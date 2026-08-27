// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/sha256.h>
#include <hash.h>

#include <algorithm>
#include <map>
#include <memory>
#include <utility>

namespace llmq::pq {
namespace {

struct ScoredMember {
    arith_uint256 score;
    CDeterministicMNCPtr dmn;
    std::optional<FrozenChildRootRecord> child_root;
};

void SetError(QuorumBuildError* error, QuorumBuildError value)
{
    if (error != nullptr) *error = value;
}

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

std::optional<std::vector<ScoredMember>> SelectRosterMembers(
    const CDeterministicMNList& snapshot,
    const uint256& modifier,
    uint32_t epoch,
    const std::map<uint256, const OperatorKeyState*>& operator_states,
    QuorumBuildError* error)
{
    std::vector<ScoredMember> candidates;
    candidates.reserve(snapshot.GetAllMNsCount());
    bool invalid_masternode_state{false};
    bool invalid_child_state{false};
    snapshot.ForEachMNShared(false, [&](const CDeterministicMNCPtr& dmn) {
        if (!dmn || !dmn->pdmnState || dmn->proTxHash.IsNull() ||
            dmn->collateralOutpoint.IsNull()) {
            invalid_masternode_state = true;
            return;
        }
        if (!CDeterministicMNList::IsMNValid(*dmn) ||
            dmn->pdmnState->confirmedHash.IsNull()) {
            return;
        }

        // Preserve the deployed deterministic score: the first SHA256 is the
        // cached confirmedHashWithProRegTxHash, followed by one SHA256 with the
        // new domain-separated modifier. This is not double-SHA256.
        uint256 score_hash;
        CSHA256 hasher;
        hasher.Write(dmn->pdmnState->confirmedHashWithProRegTxHash.begin(),
                     dmn->pdmnState->confirmedHashWithProRegTxHash.size());
        hasher.Write(modifier.begin(), modifier.size());
        hasher.Finalize(score_hash.begin());
        std::optional<FrozenChildRootRecord> child_root;
        const auto state_it{operator_states.find(dmn->proTxHash)};
        if (state_it != operator_states.end()) {
            const ChildRootResolution resolution{
                state_it->second->ResolveChildRoot(epoch)};
            if (resolution.status ==
                ChildRootResolutionStatus::FROZEN_PRESENT) {
                if (!resolution.record ||
                    resolution.record->pro_tx_hash != dmn->proTxHash ||
                    resolution.record->epoch != epoch) {
                    invalid_child_state = true;
                    return;
                }
                child_root = *resolution.record;
            } else if (resolution.status !=
                       ChildRootResolutionStatus::FROZEN_ABSENT) {
                invalid_child_state = true;
                return;
            }
        }

        candidates.push_back(
            {UintToArith256(score_hash), dmn, std::move(child_root)});
    });
    if (invalid_masternode_state) {
        SetError(error, QuorumBuildError::INVALID_MASTERNODE_STATE);
        return std::nullopt;
    }
    if (invalid_child_state) {
        SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
        return std::nullopt;
    }
    if (candidates.size() < QUORUM_SIZE) {
        SetError(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
        return std::nullopt;
    }

    const auto score_less = [](const ScoredMember& lhs,
                               const ScoredMember& rhs) {
        if (lhs.child_root.has_value() != rhs.child_root.has_value()) {
            return lhs.child_root.has_value();
        }
        if (lhs.score != rhs.score) return lhs.score > rhs.score;
        // This is the direct form of the legacy reverse-iterator tie break,
        // which places the larger outpoint first.
        return rhs.dmn->collateralOutpoint < lhs.dmn->collateralOutpoint;
    };

    std::sort(candidates.begin(), candidates.end(), score_less);
    candidates.resize(QUORUM_SIZE);
    return candidates;
}

bool AddActiveChildRootsToSet(const FrozenQuorumRoster& roster,
                              std::map<uint256,
                                       std::pair<uint256, uint32_t>>& tree_owners)
{
    for (const auto& member : roster.members) {
        if (!member.child_root) continue;
        const auto [it, inserted]{tree_owners.emplace(
            member.child_root->commitment.tree_id,
            std::pair{member.pro_tx_hash,
                      member.child_root->commitment.generation})};
        if (!inserted &&
            it->second != std::pair{member.pro_tx_hash,
                                    member.child_root->commitment.generation}) {
            return false;
        }
    }
    return true;
}

} // namespace

bool QuorumBuildConfig::IsValid() const noexcept
{
    // Keeping the snapshot within its epoch leaves at most one branch-derived
    // roster after a finalized predecessor, preserving threshold intersection.
    if (!schedule.IsValid() || roster_snapshot_lag_blocks == 0 ||
        roster_snapshot_lag_blocks > schedule.epoch_blocks ||
        registration_cutoff_blocks < roster_snapshot_lag_blocks ||
        future_horizon_epochs < ACTIVE_QUORUMS ||
        future_horizon_epochs > MAX_OPERATOR_SCHEDULE_EPOCHS) {
        return false;
    }
    const auto epoch_zero_snapshot = RegistrationCutoffHeight(
        schedule, 0, roster_snapshot_lag_blocks);
    const auto epoch_zero_cutoff = RegistrationCutoffHeight(
        schedule, 0, registration_cutoff_blocks);
    return epoch_zero_snapshot && epoch_zero_cutoff &&
           *epoch_zero_cutoff <= *epoch_zero_snapshot;
}

std::optional<uint256> GetPQQuorumModifier(const uint256& genesis_hash,
                                           uint32_t epoch,
                                           const uint256& base_hash)
{
    if (genesis_hash.IsNull() || base_hash.IsNull()) return std::nullopt;
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PQ_QUORUM_MODIFIER_DOMAIN);
    writer << genesis_hash << epoch << base_hash;
    return writer.GetHash();
}

std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || base_hash.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!config.IsValid()) {
        SetError(error, QuorumBuildError::INVALID_SCHEDULE);
        return nullptr;
    }
    const auto base_height{EpochBaseHeight(config.schedule, epoch)};
    if (!base_height || snapshot.IsNull() ||
        snapshot.GetHeight() >= *base_height || snapshot.GetBlockHash().IsNull()) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const auto modifier{GetPQQuorumModifier(genesis_hash, epoch, base_hash)};
    if (!modifier) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }

    std::map<uint256, const OperatorKeyState*> operator_states;
    for (const auto& state : operator_key_states) {
        if (!state.IsStructurallyValid() || state.schedule_initialized == 0) {
            SetError(error, QuorumBuildError::INVALID_OPERATOR_STATE);
            return nullptr;
        }
        if (!operator_states.emplace(state.pro_tx_hash, &state).second) {
            SetError(error, QuorumBuildError::DUPLICATE_OPERATOR_STATE);
            return nullptr;
        }
    }

    const auto expected_snapshot_height = RegistrationCutoffHeight(
        config.schedule, epoch, config.roster_snapshot_lag_blocks);
    if (!expected_snapshot_height || snapshot.GetHeight() != *expected_snapshot_height) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const auto schedule_view = DeriveOperatorKeyScheduleView(
        config.schedule, snapshot.GetHeight(),
        config.registration_cutoff_blocks, config.future_horizon_epochs);
    if (!schedule_view) {
        SetError(error, QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
        return nullptr;
    }
    for (const auto& [pro_tx_hash, state] : operator_states) {
        (void)pro_tx_hash;
        if (!state->IsAdvancedTo(*schedule_view)) {
            SetError(error,
                     QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
            return nullptr;
        }
    }

    auto selected{SelectRosterMembers(
        snapshot, *modifier, epoch, operator_states, error)};
    if (!selected) return nullptr;

    auto roster{std::make_unique<FrozenQuorumRoster>()};
    roster->descriptor.epoch = epoch;
    roster->descriptor.base_height = *base_height;
    roster->descriptor.base_hash = base_hash;
    roster->descriptor.snapshot_height = snapshot.GetHeight();
    roster->descriptor.snapshot_hash = snapshot.GetBlockHash();

    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        auto& member = roster->members[slot];
        member.pro_tx_hash = (*selected)[slot].dmn->proTxHash;
        member.eligible = true;
        if (!(*selected)[slot].child_root) continue;
        if (!tree_owners.emplace(
                (*selected)[slot].child_root->commitment.tree_id,
                std::pair{member.pro_tx_hash,
                          (*selected)[slot].child_root->commitment.generation}).second) {
            SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
            return nullptr;
        }
        member.child_root = std::move((*selected)[slot].child_root);
        SetBit(roster->descriptor.valid_members, slot);
    }

    roster->descriptor.valid_count =
        static_cast<uint16_t>(CountSet(roster->descriptor.valid_members));
    roster->descriptor.member_root =
        ComputeQuorumMemberRoot(genesis_hash, *roster);
    roster->descriptor.child_key_root =
        ComputeQuorumChildKeyRoot(genesis_hash, *roster);
    return roster;
}

FrozenQuorumRostersPtr BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || !snapshot_lookup) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!config.IsValid()) {
        SetError(error, QuorumBuildError::INVALID_SCHEDULE);
        return nullptr;
    }
    if (!IsEligibleChainLockTarget(config.schedule, target_height)) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    if (branch_tip.nHeight < target_height ||
        branch_tip.GetAncestor(target_height) == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const auto active_epochs{ActiveEpochsAtHeight(config.schedule, target_height)};
    if (!active_epochs) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }

    auto rosters{std::make_shared<FrozenQuorumRosters>()};
    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& identity{(*active_epochs)[slot]};
        const CBlockIndex* base_index{branch_tip.GetAncestor(identity.base_height)};
        const auto snapshot_height{
            RegistrationCutoffHeight(config.schedule, identity.epoch,
                                     config.roster_snapshot_lag_blocks)};
        if (base_index == nullptr || !snapshot_height ||
            *snapshot_height >= identity.base_height) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        const CBlockIndex* snapshot_index{base_index->GetAncestor(*snapshot_height)};
        if (snapshot_index == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        auto snapshot_state{snapshot_lookup(*snapshot_index)};
        if (!snapshot_state) {
            SetError(error, QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
            return nullptr;
        }
        if (snapshot_state->deterministic_mns.IsNull() ||
            snapshot_state->deterministic_mns.GetHeight() != *snapshot_height ||
            snapshot_state->deterministic_mns.GetBlockHash() !=
                snapshot_index->GetBlockHash() ||
            !snapshot_state->operator_key_states) {
            SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
            return nullptr;
        }
        auto roster{BuildFrozenQuorumRoster(
            genesis_hash, config, identity.epoch, base_index->GetBlockHash(),
            snapshot_state->deterministic_mns,
            std::span<const OperatorKeyState>{
                snapshot_state->operator_key_states->data(),
                snapshot_state->operator_key_states->size()}, error)};
        if (!roster) return nullptr;
        if (!AddActiveChildRootsToSet(*roster, tree_owners)) {
            SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
            return nullptr;
        }
        (*rosters)[slot] = std::move(*roster);
    }
    return rosters;
}

FrozenQuorumRosterCache::FrozenQuorumRosterCache(
    uint256 genesis_hash,
    QuorumBuildConfig config,
    QuorumSnapshotLookup snapshot_lookup,
    bool cache_results)
    : m_genesis_hash{std::move(genesis_hash)},
      m_config{config},
      m_snapshot_lookup{std::move(snapshot_lookup)},
      m_cache_results{cache_results}
{
}

std::shared_ptr<const FrozenQuorumRosterCache>
FrozenQuorumRosterCache::Create(
    uint256 genesis_hash,
    QuorumBuildConfig config,
    QuorumSnapshotLookup snapshot_lookup,
    bool cache_results)
{
    if (genesis_hash.IsNull() || !config.IsValid() || !snapshot_lookup) {
        return nullptr;
    }
    return std::shared_ptr<const FrozenQuorumRosterCache>{
        new FrozenQuorumRosterCache{
            std::move(genesis_hash), config, std::move(snapshot_lookup),
            cache_results}};
}

FrozenQuorumRostersPtr FrozenQuorumRosterCache::GetActive(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    QuorumBuildError* error) const
{
    SetError(error, QuorumBuildError::NONE);
    if (!m_cache_results) {
        return BuildActiveFrozenQuorumRosters(
            m_genesis_hash, m_config, target_height, branch_tip,
            m_snapshot_lookup, error);
    }
    if (!IsEligibleChainLockTarget(m_config.schedule, target_height)) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    if (branch_tip.nHeight < target_height) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const CBlockIndex* target{branch_tip.GetAncestor(target_height)};
    if (target == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const auto active_epochs{
        ActiveEpochsAtHeight(m_config.schedule, target_height)};
    if (!active_epochs) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    const auto& newest{active_epochs->back()};
    const CBlockIndex* newest_base{
        target->GetAncestor(newest.base_height)};
    if (newest_base == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    // A block hash commits its complete ancestry. Every other active base and
    // snapshot is an ancestor of this newest base, so this key distinguishes
    // forks exactly while allowing descendants after the base to share state.
    const Key key{newest.epoch, newest_base->GetBlockHash()};

    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.rosters && entry.key == key) {
                entry.recently_used = true;
                return entry.rosters;
            }
        }
    }

    auto built{BuildActiveFrozenQuorumRosters(
        m_genesis_hash, m_config, target_height, branch_tip,
        m_snapshot_lookup, error)};
    if (!built) return nullptr;

    FrozenQuorumRostersPtr displaced;
    FrozenQuorumRostersPtr result;
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.rosters && entry.key == key) {
                entry.recently_used = true;
                result = entry.rosters;
                break;
            }
        }
        if (!result) {
            std::optional<std::size_t> victim;
            for (std::size_t slot{0}; slot < m_entries.size(); ++slot) {
                if (!m_entries[slot].rosters) {
                    victim = slot;
                    break;
                }
            }
            while (!victim) {
                auto& candidate{m_entries[m_clock_hand]};
                if (!candidate.recently_used) {
                    victim = m_clock_hand;
                } else {
                    candidate.recently_used = false;
                }
                m_clock_hand = (m_clock_hand + 1) % m_entries.size();
            }
            auto& entry{m_entries[*victim]};
            displaced = std::move(entry.rosters);
            entry.key = key;
            entry.rosters = std::move(built);
            entry.recently_used = true;
            result = entry.rosters;
        }
    }
    return result;
}

std::optional<QuorumSnapshotState>
FrozenQuorumRosterCache::LookupSnapshot(const CBlockIndex& index) const
{
    return m_snapshot_lookup(index);
}

uint8_t GetSigningRosterAuthorizationMask(
    const FrozenQuorumRosters& rosters,
    const AuthorizationBoundaryLookup& is_boundary_ancestor)
{
    if (!is_boundary_ancestor) return 0;
    uint8_t mask{0};
    bool found_unauthorized{false};
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        const auto& roster{rosters[slot]};
        const auto& descriptor{roster.descriptor};
        const bool bootstrap{descriptor.epoch < ACTIVE_QUORUMS};
        const int32_t authorization_height{
            bootstrap ? descriptor.base_height : descriptor.snapshot_height};
        const uint256& authorization_hash{
            bootstrap ? descriptor.base_hash : descriptor.snapshot_hash};
        const bool authorized{
            authorization_height >= 0 && !authorization_hash.IsNull() &&
            is_boundary_ancestor(authorization_height,
                                 authorization_hash)};
        if (!authorized) {
            found_unauthorized = true;
            continue;
        }
        if (found_unauthorized) return 0;
        mask |= static_cast<uint8_t>(uint8_t{1} << slot);
    }
    return mask;
}

} // namespace llmq::pq
