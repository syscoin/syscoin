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

constexpr std::string_view INITIAL_RECOVERY_AUTHORITY_MODIFIER_DOMAIN{
    "SYS_PQ_INITIAL_RECOVERY_AUTHORITY_MODIFIER_V1"};

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

bool PrepareOperatorStateLookup(
    std::span<const OperatorKeyState> operator_key_states,
    OperatorStateLookup& lookup,
    QuorumBuildError* error)
{
    bool strictly_ordered{true};
    const OperatorKeyState* previous_state{nullptr};
    for (const auto& state : operator_key_states) {
        if (!state.IsStructurallyValid() || state.schedule_initialized == 0) {
            SetError(error, QuorumBuildError::INVALID_OPERATOR_STATE);
            return false;
        }
        if (previous_state != nullptr &&
            !(previous_state->pro_tx_hash < state.pro_tx_hash)) {
            strictly_ordered = false;
        }
        previous_state = &state;
    }
    if (strictly_ordered) return true;

    lookup.reordered.reserve(operator_key_states.size());
    for (const auto& state : operator_key_states) {
        lookup.reordered.push_back(&state);
    }
    std::sort(lookup.reordered.begin(), lookup.reordered.end(),
              [](const OperatorKeyState* lhs,
                 const OperatorKeyState* rhs) {
                  return lhs->pro_tx_hash < rhs->pro_tx_hash;
              });
    if (std::adjacent_find(
            lookup.reordered.begin(), lookup.reordered.end(),
            [](const OperatorKeyState* lhs,
               const OperatorKeyState* rhs) {
                return lhs->pro_tx_hash == rhs->pro_tx_hash;
            }) != lookup.reordered.end()) {
        SetError(error, QuorumBuildError::DUPLICATE_OPERATOR_STATE);
        return false;
    }
    return true;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

template <typename... Args>
uint256 AuthorityTaggedHash(std::string_view domain,
                            const uint256& genesis_hash,
                            const Args&... args)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
    writer << genesis_hash;
    (writer << ... << args);
    return writer.GetHash();
}

template <typename ResolveChildRoot>
std::optional<std::vector<ScoredMember>> SelectRosterMembers(
    const CDeterministicMNList& snapshot,
    const uint256& modifier,
    const OperatorStateLookup& operator_states,
    ResolveChildRoot&& resolve_child_root,
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
        const auto* state{operator_states.Find(dmn->proTxHash)};
        const auto child_root{resolve_child_root(state, dmn->proTxHash)};
        if (!child_root) {
            invalid_child_state = true;
            return;
        }

        candidates.push_back(
            {UintToArith256(score_hash), dmn, std::move(*child_root)});
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

namespace {

std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRosterWithModifier(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const uint256& modifier,
    const uint256& beacon_hash,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || base_hash.IsNull() || modifier.IsNull() ||
        beacon_hash.IsNull()) {
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
    OperatorStateLookup operator_states{operator_key_states, {}};
    if (!PrepareOperatorStateLookup(
            operator_key_states, operator_states, error)) return nullptr;

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
        snapshot, modifier, operator_states,
        [epoch](const OperatorKeyState* state, const uint256& pro_tx_hash)
            -> std::optional<std::optional<FrozenChildRootRecord>> {
            if (state == nullptr) {
                return std::optional<FrozenChildRootRecord>{};
            }
            const ChildRootResolution resolution{
                state->ResolveChildRoot(epoch)};
            if (resolution.status ==
                ChildRootResolutionStatus::FROZEN_ABSENT) {
                return std::optional<FrozenChildRootRecord>{};
            }
            if (resolution.status !=
                    ChildRootResolutionStatus::FROZEN_PRESENT ||
                !resolution.record ||
                resolution.record->pro_tx_hash != pro_tx_hash ||
                resolution.record->epoch != epoch) {
                return std::nullopt;
            }
            return std::move(resolution.record);
        },
        error)};
    if (!selected) return nullptr;

    auto roster{std::make_unique<FrozenQuorumRoster>()};
    roster->descriptor.epoch = epoch;
    roster->descriptor.base_height = *base_height;
    roster->descriptor.base_hash = base_hash;
    roster->descriptor.snapshot_height = snapshot.GetHeight();
    roster->descriptor.snapshot_hash = snapshot.GetBlockHash();
    roster->descriptor.roster_beacon_hash = beacon_hash;

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

} // namespace

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
    if (beacon_seed.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    if (snapshot.IsNull() || snapshot.GetBlockHash().IsNull()) {
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
    return BuildFrozenQuorumRosterWithModifier(
        genesis_hash, config, epoch, base_hash, *modifier, *beacon_hash,
        snapshot, operator_key_states, error);
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
    const RecoveryRosterAuthority* recovery_authority,
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
    const bool has_recovery_seed{std::any_of(
        beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    if (has_recovery_seed != (recovery_authority != nullptr) ||
        (recovery_authority != nullptr &&
         !recovery_authority->IsStructurallyValid())) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    if (recovery_authority != nullptr) {
        const auto authority_hash{GetRecoveryRosterAuthorityHash(
            genesis_hash, *recovery_authority)};
        if (!authority_hash ||
            *authority_hash != beacon_bundle.recovery_authority_hash) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
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
        if (beacon_bundle.seeds[slot].anchor_kind ==
            RosterBeaconAnchorKind::RECOVERY) {
            auto roster{std::make_unique<FrozenQuorumRoster>()};
            auto& descriptor{roster->descriptor};
            descriptor.epoch = identity.epoch;
            descriptor.base_height = identity.base_height;
            descriptor.base_hash = base_index->GetBlockHash();
            descriptor.snapshot_height = *snapshot_height;
            descriptor.snapshot_hash = snapshot_index->GetBlockHash();
            descriptor.roster_beacon_hash = *beacon_hash;

            const auto& authority_slot{
                recovery_authority->slots[identity.epoch % ACTIVE_QUORUMS]};
            for (std::size_t member_index{0};
                 member_index < QUORUM_SIZE; ++member_index) {
                const auto& source{authority_slot[member_index]};
                auto& member{roster->members[member_index]};
                member.pro_tx_hash = source.pro_tx_hash;
                if (!source.eligible || !source.child_root) continue;
                if (!source.child_root->commitment.CoversEpoch(
                        identity.epoch)) {
                    continue;
                }
                member.eligible = true;
                member.child_root = FrozenChildRootRecord{
                    source.pro_tx_hash,
                    source.child_root->global_key_version,
                    identity.epoch,
                    source.child_root->commitment};
                if (member.eligible) {
                    SetBit(descriptor.valid_members, member_index);
                }
            }
            descriptor.valid_count = static_cast<uint16_t>(
                CountSet(descriptor.valid_members));
            descriptor.member_root =
                ComputeQuorumMemberRoot(genesis_hash, *roster);
            descriptor.child_key_root =
                ComputeQuorumChildKeyRoot(genesis_hash, *roster);
            if (!AddActiveChildRootsToSet(*roster, tree_owners)) {
                SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
                return nullptr;
            }
            (*rosters)[slot] = std::move(*roster);
            continue;
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
    const bool complete_recovery_window{std::all_of(
        beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    if (complete_recovery_window &&
        ((*rosters)[1].descriptor.valid_count < QUORUM_MIN_VALID ||
         (*rosters)[2].descriptor.valid_count < QUORUM_MIN_VALID ||
         (*rosters)[3].descriptor.valid_count < QUORUM_MIN_VALID)) {
        SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
        return nullptr;
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
        /*recovery_authority=*/nullptr,
        snapshot_lookup,
        /*reusable_sets=*/{}, error)};
    if (!rosters) return nullptr;
    return FrozenQuorumRostersPtr{std::move(rosters)};
}

namespace {

RecoveryRosterAuthorityPtr CreateRecoveryRosterAuthorityImpl(
    const uint256& genesis_hash,
    int32_t source_height,
    const uint256& source_block_hash,
    const uint256& source_quorum_context_hash,
    const FrozenQuorumRosters& rosters)
{
    if (genesis_hash.IsNull() || source_height < 0 ||
        source_block_hash.IsNull() || source_quorum_context_hash.IsNull()) {
        return nullptr;
    }
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    if (GetQuorumContextHash(
            genesis_hash, source_height, source_block_hash, descriptors) !=
        source_quorum_context_hash) {
        return nullptr;
    }
    auto authority{std::make_shared<RecoveryRosterAuthority>()};
    std::array<bool, ACTIVE_QUORUMS> assigned{};
    for (const auto& roster : rosters) {
        const std::size_t phase{roster.descriptor.epoch % ACTIVE_QUORUMS};
        if (assigned[phase]) return nullptr;
        assigned[phase] = true;
        for (std::size_t member_index{0};
             member_index < QUORUM_SIZE; ++member_index) {
            const auto& source{roster.members[member_index]};
            auto& member{authority->slots[phase][member_index]};
            member.pro_tx_hash = source.pro_tx_hash;
            member.eligible = source.eligible;
            if (source.child_root) {
                member.child_root = RecoveryRosterChildCommitment{
                    source.child_root->global_key_version,
                    source.child_root->commitment};
            }
        }
    }
    if (std::find(assigned.begin(), assigned.end(), false) !=
            assigned.end() ||
        !authority->IsStructurallyValid()) {
        return nullptr;
    }
    return authority;
}

bool RecoveryAuthorityCoversTarget(
    const RecoveryRosterAuthority& authority,
    const ChainLockScheduleConfig& schedule,
    int32_t target_height) noexcept
{
    const auto target_epochs{ActiveEpochsAtHeight(schedule, target_height)};
    if (!target_epochs) return false;
    std::array<std::size_t, ACTIVE_QUORUMS> valid_by_phase{};
    for (const auto& identity : *target_epochs) {
        const auto& slot{authority.slots[identity.epoch % ACTIVE_QUORUMS]};
        valid_by_phase[identity.epoch % ACTIVE_QUORUMS] =
            std::count_if(slot.begin(), slot.end(),
                          [&](const RecoveryRosterMember& member) {
                              return member.eligible && member.child_root &&
                                     member.child_root->commitment.CoversEpoch(
                                         identity.epoch);
                          });
    }
    return valid_by_phase[1] >= QUORUM_MIN_VALID &&
           valid_by_phase[2] >= QUORUM_MIN_VALID &&
           valid_by_phase[3] >= QUORUM_MIN_VALID;
}

} // namespace

RecoveryRosterAuthorityPtr CreateRecoveryRosterAuthority(
    const uint256& genesis_hash,
    int32_t source_height,
    const uint256& source_block_hash,
    const uint256& source_quorum_context_hash,
    const VerifiedRosterSet& roster_set)
{
    if (roster_set.GenesisHash() != genesis_hash) return nullptr;
    return CreateRecoveryRosterAuthorityImpl(
        genesis_hash, source_height, source_block_hash,
        source_quorum_context_hash, roster_set.Rosters());
}

RecoveryRosterAuthorityPtr CreateRecoveryRosterAuthority(
    const uint256& genesis_hash,
    const ChainLockStatement& source_statement,
    const VerifiedRosterSet& roster_set)
{
    if (!source_statement.IsStructurallyValid()) return nullptr;
    return CreateRecoveryRosterAuthority(
        genesis_hash, source_statement.height, source_statement.block_hash,
        source_statement.quorum_context_hash, roster_set);
}

RecoveryRosterAuthorityPtr BuildInitialRecoveryRosterAuthority(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    int32_t activation_predecessor_height,
    const uint256& activation_predecessor_hash,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || !config.IsValid() || !snapshot_lookup ||
        activation_predecessor_height < 0 ||
        activation_predecessor_hash.IsNull() ||
        !IsEligibleChainLockTarget(config.schedule, target_height) ||
        branch_tip.nHeight < target_height ||
        activation_predecessor_height >= target_height) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    const CBlockIndex* target{branch_tip.GetAncestor(target_height)};
    const CBlockIndex* source{
        target != nullptr
            ? target->GetAncestor(activation_predecessor_height)
            : nullptr};
    if (source == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    if (source->GetBlockHash() != activation_predecessor_hash) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }

    std::optional<QuorumSnapshotState> snapshot_state;
    try {
        snapshot_state = snapshot_lookup(*source);
    } catch (...) {
        SetError(error, QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
        return nullptr;
    }
    if (!snapshot_state || snapshot_state->deterministic_mns.IsNull() ||
        snapshot_state->deterministic_mns.GetHeight() !=
            activation_predecessor_height ||
        snapshot_state->deterministic_mns.GetBlockHash() !=
                source->GetBlockHash() ||
        !snapshot_state->operator_key_states) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const auto operator_states_span{
        std::span<const OperatorKeyState>{
            snapshot_state->operator_key_states->data(),
            snapshot_state->operator_key_states->size()}};
    OperatorStateLookup operator_states{operator_states_span, {}};
    if (!PrepareOperatorStateLookup(
            operator_states_span, operator_states, error)) {
        return nullptr;
    }
    const auto schedule_view{DeriveOperatorKeyScheduleView(
        config.schedule, activation_predecessor_height,
        config.registration_cutoff_blocks,
        config.future_horizon_epochs)};
    if (!schedule_view) {
        SetError(error,
                 QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
        return nullptr;
    }
    for (const auto& state : operator_states_span) {
        if (!state.IsAdvancedTo(*schedule_view)) {
            SetError(error,
                     QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
            return nullptr;
        }
    }

    const auto authority_target{NextEligibleChainLockTargetHeight(
        config.schedule, activation_predecessor_height)};
    const auto authority_epochs{authority_target
        ? ActiveEpochsAtHeight(config.schedule, *authority_target)
        : std::optional<std::array<EpochIdentity, ACTIVE_QUORUMS>>{}};
    if (!authority_epochs) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    std::array<uint32_t, ACTIVE_QUORUMS> epoch_by_phase{};
    std::array<bool, ACTIVE_QUORUMS> phase_assigned{};
    for (const auto& identity : *authority_epochs) {
        const std::size_t phase{identity.epoch % ACTIVE_QUORUMS};
        if (phase_assigned[phase]) {
            SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
            return nullptr;
        }
        phase_assigned[phase] = true;
        epoch_by_phase[phase] = identity.epoch;
    }

    auto authority{std::make_shared<RecoveryRosterAuthority>()};
    for (std::size_t phase{0}; phase < ACTIVE_QUORUMS; ++phase) {
        const uint32_t authority_epoch{epoch_by_phase[phase]};
        // The exact durable snapshot fixes the candidate population. Its
        // child block hash is provenance only and must not become cheap
        // AuxPoW-grindable committee entropy.
        const uint256 modifier{AuthorityTaggedHash(
            INITIAL_RECOVERY_AUTHORITY_MODIFIER_DOMAIN, genesis_hash,
            activation_predecessor_height, static_cast<uint8_t>(phase))};
        auto selected{SelectRosterMembers(
            snapshot_state->deterministic_mns, modifier, operator_states,
            [authority_epoch](const OperatorKeyState* state,
                              const uint256& pro_tx_hash)
                -> std::optional<std::optional<FrozenChildRootRecord>> {
                if (state == nullptr) {
                    return std::optional<FrozenChildRootRecord>{};
                }
                const ChildRootResolution resolution{
                    state->ResolveChildRoot(authority_epoch)};
                if (resolution.status ==
                    ChildRootResolutionStatus::FROZEN_ABSENT) {
                    return std::optional<FrozenChildRootRecord>{};
                }
                if (resolution.status !=
                        ChildRootResolutionStatus::FROZEN_PRESENT ||
                    !resolution.record ||
                    resolution.record->pro_tx_hash != pro_tx_hash ||
                    resolution.record->epoch != authority_epoch) {
                    return std::nullopt;
                }
                return std::move(resolution.record);
            },
            error)};
        if (!selected) return nullptr;
        for (std::size_t member_index{0};
             member_index < QUORUM_SIZE; ++member_index) {
            const auto& source{(*selected)[member_index]};
            auto& member{authority->slots[phase][member_index]};
            member.pro_tx_hash = source.dmn->proTxHash;
            member.eligible = true;
            if (source.child_root) {
                member.child_root = RecoveryRosterChildCommitment{
                    source.child_root->global_key_version,
                    source.child_root->commitment};
            }
        }
    }
    if (!authority->IsStructurallyValid()) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }

    if (!RecoveryAuthorityCoversTarget(
            *authority, config.schedule, target_height)) {
        SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
        return nullptr;
    }
    return authority;
}

RecoveryRosterAuthorityPtr BuildRecoveryRosterAuthorityFromSource(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t recovery_target_height,
    const CBlockIndex& branch_tip,
    const RecoveryRosterAuthoritySource& source,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (!source.IsStructurallyValid() || source.IsNull() ||
        !IsEligibleChainLockTarget(config.schedule,
                                   recovery_target_height)) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (source.kind == RecoveryRosterAuthoritySourceKind::ACTIVATION) {
        return BuildInitialRecoveryRosterAuthority(
            genesis_hash, config, recovery_target_height, branch_tip,
            source.height, source.block_hash, snapshot_lookup, error);
    }
    if (source.kind !=
        RecoveryRosterAuthoritySourceKind::NORMAL_ROSTERS) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (source.height >= recovery_target_height ||
        branch_tip.nHeight < recovery_target_height) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    const CBlockIndex* source_index{branch_tip.GetAncestor(source.height)};
    if (source_index == nullptr ||
        source_index->GetBlockHash() != source.block_hash) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    ActiveRosterBeaconBundle source_bundle;
    source_bundle.seeds = source.normal_beacons;
    if (!source_bundle.IsStructurallyValid()) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    auto source_rosters{BuildActiveFrozenQuorumRosters(
        genesis_hash, config, source.height, branch_tip, source_bundle,
        snapshot_lookup, error)};
    auto authority{source_rosters
        ? CreateRecoveryRosterAuthorityImpl(
              genesis_hash, source.height, source.block_hash,
              source.quorum_context_hash, *source_rosters)
        : nullptr};
    if (!authority) {
        if (error != nullptr && *error == QuorumBuildError::NONE) {
            *error = QuorumBuildError::INVALID_FROZEN_ROSTER;
        }
        return nullptr;
    }
    if (!RecoveryAuthorityCoversTarget(
            *authority, config.schedule, recovery_target_height)) {
        SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
        return nullptr;
    }
    return authority;
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
    const FrozenQuorumRosterCache& cache,
    RecoveryRosterAuthorityPtr recovery_authority)
{
    if (!rosters || !cache.m_build_provenance) return nullptr;
    // Exclusive transfer prevents a producer alias from changing the bytes
    // whose roots were established during canonical construction.
    FrozenQuorumRostersPtr immutable_rosters{std::move(rosters)};
    return std::shared_ptr<const VerifiedRosterSet>{
        new VerifiedRosterSet{
            cache.m_genesis_hash, std::move(immutable_rosters),
            cache.m_build_provenance, std::move(recovery_authority)}};
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
        /*recovery_authority=*/nullptr,
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
        /*recovery_authority=*/nullptr,
        /*publish=*/false, error);
}

VerifiedRosterSetPtr
FrozenQuorumRosterCache::GetVerifiedActiveWithRecoveryAuthority(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    RecoveryRosterAuthorityPtr recovery_authority,
    bool publish,
    QuorumBuildError* error) const
{
    return GetVerifiedActiveImpl(
        target_height, branch_tip, beacon_bundle,
        std::move(recovery_authority), publish, error);
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActiveImpl(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    RecoveryRosterAuthorityPtr recovery_authority,
    bool publish,
    QuorumBuildError* error) const
{
    SetError(error, QuorumBuildError::NONE);
    if (!m_cache_results) {
        auto built{BuildActiveFrozenQuorumRostersImpl(
            m_genesis_hash, m_config, target_height, branch_tip,
            beacon_bundle, recovery_authority.get(), m_snapshot_lookup,
            /*reusable_sets=*/{}, error)};
        if (!built) return nullptr;
        auto roster_set{VerifiedRosterSet::MintCanonicalBuild(
            std::move(built), *this, recovery_authority)};
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
    uint256 recovery_authority_hash;
    if (recovery_authority) {
        const auto hash{GetRecoveryRosterAuthorityHash(
            m_genesis_hash, *recovery_authority)};
        if (!hash || *hash != beacon_bundle.recovery_authority_hash) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
        recovery_authority_hash = *hash;
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
                  *beacon_bundle_hash, recovery_authority_hash};

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
        beacon_bundle, recovery_authority.get(), m_snapshot_lookup,
        reusable_sets, error)};
    if (!built) return nullptr;
    auto verified{VerifiedRosterSet::MintCanonicalBuild(
        std::move(built), *this, recovery_authority)};
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
