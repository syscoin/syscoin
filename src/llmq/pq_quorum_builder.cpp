// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/sha256.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <utility>

namespace llmq::pq {
namespace {

struct ScoredMember {
    arith_uint256 score;
    CDeterministicMNCPtr dmn;
    std::optional<FrozenChildRootRecord> child_root;
};

/**
 * Registry snapshots are already strictly ordered. Preserve insertion-order
 * independence for synthetic callers without rebuilding a tree map on the
 * production path: only non-registry input pays for the pointer sort.
 */
struct OperatorStateLookup {
    std::span<const OperatorKeyState> states;
    std::vector<const OperatorKeyState*> reordered;

    [[nodiscard]] const OperatorKeyState* Find(
        const uint256& pro_tx_hash) const noexcept
    {
        if (reordered.empty()) {
            const auto position{std::lower_bound(
                states.begin(), states.end(), pro_tx_hash,
                [](const OperatorKeyState& state, const uint256& hash) {
                    return state.pro_tx_hash < hash;
                })};
            return position != states.end() &&
                    position->pro_tx_hash == pro_tx_hash
                ? &*position
                : nullptr;
        }
        const auto position{std::lower_bound(
            reordered.begin(), reordered.end(), pro_tx_hash,
            [](const OperatorKeyState* state, const uint256& hash) {
                return state->pro_tx_hash < hash;
            })};
        return position != reordered.end() &&
                (*position)->pro_tx_hash == pro_tx_hash
            ? *position
            : nullptr;
    }
};

void SetError(QuorumBuildError* error, QuorumBuildError value)
{
    if (error != nullptr) *error = value;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

std::optional<std::vector<ScoredMember>> SelectRosterMembers(
    const CDeterministicMNList& snapshot,
    const uint256& modifier,
    uint32_t epoch,
    const OperatorStateLookup& operator_states,
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
        const auto* state{operator_states.Find(dmn->proTxHash)};
        if (state != nullptr) {
            const ChildRootResolution resolution{
                state->ResolveChildRoot(epoch)};
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
        // which places the larger outpoint first. Deterministic-MN lists
        // enforce unique collateral outpoints, so valid candidates form a
        // total order even when their scores are equal.
        return rhs.dmn->collateralOutpoint < lhs.dmn->collateralOutpoint;
    };

    std::partial_sort(candidates.begin(),
                      candidates.begin() + QUORUM_SIZE,
                      candidates.end(), score_less);
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

std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const RosterBeaconSeed& beacon_seed,
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
    const auto modifier{GetPQQuorumModifier(
        genesis_hash, epoch, snapshot.GetHeight(), snapshot.GetBlockHash(),
        beacon_seed)};
    const auto beacon_hash{
        GetRosterBeaconCommitmentHash(genesis_hash, beacon_seed)};
    if (!modifier || !beacon_hash) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }

    OperatorStateLookup operator_states{operator_key_states, {}};
    bool strictly_ordered{true};
    const OperatorKeyState* previous_state{nullptr};
    for (const auto& state : operator_key_states) {
        if (!state.IsStructurallyValid() || state.schedule_initialized == 0) {
            SetError(error, QuorumBuildError::INVALID_OPERATOR_STATE);
            return nullptr;
        }
        if (previous_state != nullptr &&
            !(previous_state->pro_tx_hash < state.pro_tx_hash)) {
            strictly_ordered = false;
        }
        previous_state = &state;
    }
    if (!strictly_ordered) {
        operator_states.reordered.reserve(operator_key_states.size());
        for (const auto& state : operator_key_states) {
            operator_states.reordered.push_back(&state);
        }
        std::sort(operator_states.reordered.begin(),
                  operator_states.reordered.end(),
                  [](const OperatorKeyState* lhs,
                     const OperatorKeyState* rhs) {
                      return lhs->pro_tx_hash < rhs->pro_tx_hash;
                  });
        if (std::adjacent_find(
                operator_states.reordered.begin(),
                operator_states.reordered.end(),
                [](const OperatorKeyState* lhs,
                   const OperatorKeyState* rhs) {
                    return lhs->pro_tx_hash == rhs->pro_tx_hash;
                }) != operator_states.reordered.end()) {
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
    for (const auto& state : operator_key_states) {
        if (!state.IsAdvancedTo(*schedule_view)) {
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
    roster->descriptor.roster_beacon_hash = *beacon_hash;

    std::set<uint256> selected_members;
    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        auto& member = roster->members[slot];
        member.pro_tx_hash = (*selected)[slot].dmn->proTxHash;
        if (member.pro_tx_hash.IsNull() ||
            !selected_members.insert(member.pro_tx_hash).second) {
            SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
            return nullptr;
        }
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
    if (roster->descriptor.member_root.IsNull() ||
        roster->descriptor.child_key_root.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }
    return roster;
}

namespace {

// An exact base hash commits the branch through its snapshot. Matching both
// descriptor identities and the seed commitment lets rotations reuse already
// verified bytes without trusting a roster built for another fork, cutoff, or
// delayed-Bitcoin observation.
const FrozenQuorumRoster* FindReusableRoster(
    const uint256& genesis_hash,
    const EpochIdentity& identity,
    const CBlockIndex& base_index,
    const CBlockIndex& snapshot_index,
    const uint256& beacon_hash,
    std::span<const VerifiedRosterSetPtr> reusable_sets)
{
    for (const auto& roster_set : reusable_sets) {
        if (!roster_set || roster_set->GenesisHash() != genesis_hash) continue;
        for (const auto& roster : roster_set->Rosters()) {
            const auto& descriptor{roster.descriptor};
            if (descriptor.epoch == identity.epoch &&
                descriptor.base_height == identity.base_height &&
                descriptor.base_hash == base_index.GetBlockHash() &&
                descriptor.snapshot_height == snapshot_index.nHeight &&
                descriptor.snapshot_hash == snapshot_index.GetBlockHash() &&
                descriptor.roster_beacon_hash == beacon_hash) {
                return &roster;
            }
        }
    }
    return nullptr;
}

std::unique_ptr<FrozenQuorumRosters> BuildActiveFrozenQuorumRostersImpl(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    std::span<const VerifiedRosterSetPtr> reusable_sets,
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
    if (!beacon_bundle.IsForNewestEpoch(active_epochs->back().epoch)) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }

    auto rosters{std::make_unique<FrozenQuorumRosters>()};
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
        const auto beacon_hash{GetRosterBeaconCommitmentHash(
            genesis_hash, beacon_bundle.seeds[slot])};
        if (!beacon_hash) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
        const FrozenQuorumRoster* reusable{FindReusableRoster(
            genesis_hash, identity, *base_index, *snapshot_index,
            *beacon_hash, reusable_sets)};
        if (reusable != nullptr) {
            if (!AddActiveChildRootsToSet(*reusable, tree_owners)) {
                SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
                return nullptr;
            }
            (*rosters)[slot] = *reusable;
            continue;
        }
        std::optional<QuorumSnapshotState> snapshot_state;
        try {
            snapshot_state = snapshot_lookup(*snapshot_index);
        } catch (...) {
            // Storage lookup failures must remain local/transient rather than
            // escaping a consensus caller that already handles this result.
            SetError(error, QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
            return nullptr;
        }
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
            beacon_bundle.seeds[slot],
            snapshot_state->deterministic_mns,
            std::span<const OperatorKeyState>{
                snapshot_state->operator_key_states->data(),
                snapshot_state->operator_key_states->size()},
            error)};
        if (!roster) return nullptr;
        if (!AddActiveChildRootsToSet(*roster, tree_owners)) {
            SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
            return nullptr;
        }
        (*rosters)[slot] = std::move(*roster);
    }
    return rosters;
}

} // namespace

FrozenQuorumRostersPtr BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    auto rosters{BuildActiveFrozenQuorumRostersImpl(
        genesis_hash, config, target_height, branch_tip, beacon_bundle,
        snapshot_lookup,
        /*reusable_sets=*/{}, error)};
    if (!rosters) return nullptr;
    return FrozenQuorumRostersPtr{std::move(rosters)};
}

FrozenQuorumRosterCache::FrozenQuorumRosterCache(
    uint256 genesis_hash,
    QuorumBuildConfig config,
    QuorumSnapshotLookup snapshot_lookup,
    bool cache_results)
    : m_genesis_hash{std::move(genesis_hash)},
      m_config{config},
      m_snapshot_lookup{std::move(snapshot_lookup)},
      m_cache_results{cache_results},
      m_build_provenance{VerifiedRosterSet::NewBuildProvenance()}
{
}

std::shared_ptr<const VerifiedRosterSet>
VerifiedRosterSet::MintCanonicalBuild(
    std::unique_ptr<FrozenQuorumRosters> rosters,
    const FrozenQuorumRosterCache& cache)
{
    if (!rosters || !cache.m_build_provenance) return nullptr;
    // Exclusive transfer prevents a producer alias from changing the bytes
    // whose roots were established during canonical construction.
    FrozenQuorumRostersPtr immutable_rosters{std::move(rosters)};
    return std::shared_ptr<const VerifiedRosterSet>{
        new VerifiedRosterSet{
            cache.m_genesis_hash, std::move(immutable_rosters),
            cache.m_build_provenance}};
}

bool VerifiedRosterSet::WasBuiltBy(
    const FrozenQuorumRosterCache& cache) const noexcept
{
    return m_build_provenance &&
           m_build_provenance == cache.m_build_provenance;
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
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    const auto roster_set{GetVerifiedActive(
        target_height, branch_tip, beacon_bundle, error)};
    return roster_set ? roster_set->RostersPtr() : nullptr;
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActive(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    return GetVerifiedActiveImpl(
        target_height, branch_tip, beacon_bundle,
        /*publish=*/true, error);
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActiveNoPublish(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    return GetVerifiedActiveImpl(
        target_height, branch_tip, beacon_bundle,
        /*publish=*/false, error);
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActiveImpl(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    bool publish,
    QuorumBuildError* error) const
{
    SetError(error, QuorumBuildError::NONE);
    if (!m_cache_results) {
        auto built{BuildActiveFrozenQuorumRostersImpl(
            m_genesis_hash, m_config, target_height, branch_tip,
            beacon_bundle, m_snapshot_lookup, /*reusable_sets=*/{}, error)};
        if (!built) return nullptr;
        auto roster_set{VerifiedRosterSet::MintCanonicalBuild(
            std::move(built), *this)};
        if (!roster_set) {
            SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        }
        return roster_set;
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
    const auto beacon_bundle_hash{GetActiveRosterBeaconBundleHash(
        m_genesis_hash, beacon_bundle)};
    if (!beacon_bundle_hash ||
        !beacon_bundle.IsForNewestEpoch(newest.epoch)) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    const CBlockIndex* newest_base{
        target->GetAncestor(newest.base_height)};
    if (newest_base == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    // A block hash commits its complete ancestry. Every other active base and
    // snapshot is an ancestor of this newest base, so this key distinguishes
    // forks exactly while allowing descendants after the base to share state.
    // The bundle hash prevents a hit across different delayed-Bitcoin seeds.
    const Key key{newest.epoch, newest_base->GetBlockHash(),
                  *beacon_bundle_hash};

    std::array<VerifiedRosterSetPtr,
               FROZEN_QUORUM_ROSTER_CACHE_CAPACITY> reusable_sets;
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.roster_set && entry.key == key &&
                entry.roster_set->WasBuiltBy(*this)) {
                entry.recently_used = true;
                return entry.roster_set;
            }
        }
        for (std::size_t slot{0}; slot < m_entries.size(); ++slot) {
            if (m_entries[slot].roster_set &&
                m_entries[slot].roster_set->WasBuiltBy(*this)) {
                reusable_sets[slot] = m_entries[slot].roster_set;
            }
        }
    }

    auto built{BuildActiveFrozenQuorumRostersImpl(
        m_genesis_hash, m_config, target_height, branch_tip,
        beacon_bundle, m_snapshot_lookup, reusable_sets, error)};
    if (!built) return nullptr;
    auto verified{VerifiedRosterSet::MintCanonicalBuild(
        std::move(built), *this)};
    if (!verified) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }
    if (!publish) return verified;

    VerifiedRosterSetPtr displaced;
    VerifiedRosterSetPtr result;
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.roster_set && entry.key == key &&
                entry.roster_set->WasBuiltBy(*this)) {
                entry.recently_used = true;
                result = entry.roster_set;
                break;
            }
        }
        if (!result) {
            std::optional<std::size_t> victim;
            for (std::size_t slot{0}; slot < m_entries.size(); ++slot) {
                if (!m_entries[slot].roster_set) {
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
            displaced = std::move(entry.roster_set);
            entry.key = key;
            entry.roster_set = std::move(verified);
            entry.recently_used = true;
            result = entry.roster_set;
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
