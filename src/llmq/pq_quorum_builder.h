// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
#define SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H

#include <evo/deterministicmns.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_operator_key_state.h>
#include <llmq/pq_roster_beacon.h>
#include <sync.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

class CBlockIndex;

namespace llmq::pq {

/**
 * Fork-pinned inputs needed to reconstruct a roster at one exact branch.
 *
 * The registration cutoff and roster snapshot are deliberately independent.
 * A key must already be frozen when the snapshot is taken, so the cutoff is
 * at least as far before the epoch base as the snapshot.
 */
struct QuorumBuildConfig {
    ChainLockScheduleConfig schedule;
    uint32_t roster_snapshot_lag_blocks{0};
    uint32_t registration_cutoff_blocks{0};
    uint32_t future_horizon_epochs{0};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const QuorumBuildConfig&,
                           const QuorumBuildConfig&) = default;
};

enum class QuorumBuildError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_SCHEDULE,
    INVALID_TARGET_HEIGHT,
    INVALID_MASTERNODE_STATE,
    INSUFFICIENT_ELIGIBLE_MEMBERS,
    INVALID_OPERATOR_STATE,
    DUPLICATE_OPERATOR_STATE,
    OPERATOR_STATE_SNAPSHOT_MISMATCH,
    CHILD_KEY_NOT_FROZEN,
    DUPLICATE_CHILD_KEY,
    MISSING_BRANCH_ANCESTOR,
    SNAPSHOT_LOOKUP_FAILED,
    SNAPSHOT_MISMATCH,
    INVALID_ROSTER_BEACON,
    INVALID_FROZEN_ROSTER,
};

/**
 * State looked up at an exact block on the branch supplied by the caller.
 * The deterministic list is structurally shared internally; registry
 * operators retain the exact immutable registry allocation without also
 * pinning its potentially much larger tree-ID history.
 */
struct QuorumSnapshotState {
    CDeterministicMNList deterministic_mns;
    std::shared_ptr<const std::vector<OperatorKeyState>> operator_key_states;
};

using QuorumSnapshotLookup =
    std::function<std::optional<QuorumSnapshotState>(const CBlockIndex&)>;

using AuthorizationBoundaryLookup =
    std::function<bool(int32_t, const uint256&)>;

inline constexpr std::size_t FROZEN_QUORUM_ROSTER_CACHE_CAPACITY{16};

/**
 * Bounded success-only cache for complete branch-pinned active roster sets.
 * Retained verified sets also seed overlapping roster epochs after rotation.
 */
class FrozenQuorumRosterCache final {
public:
    [[nodiscard]] static std::shared_ptr<const FrozenQuorumRosterCache> Create(
        uint256 genesis_hash,
        QuorumBuildConfig config,
        QuorumSnapshotLookup snapshot_lookup,
        bool cache_results = true);

    [[nodiscard]] FrozenQuorumRostersPtr GetActive(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActive(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Cache hits may be reused, but a miss is not published before auth. */
    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActiveNoPublish(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActiveWithRecoveryAuthority(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        RecoveryRosterAuthorityPtr recovery_authority,
        bool publish,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Always invoke the source; independent reconstruction must not self-hit. */
    [[nodiscard]] std::optional<QuorumSnapshotState> LookupSnapshot(
        const CBlockIndex& index) const;

    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_genesis_hash;
    }
    [[nodiscard]] const QuorumBuildConfig& Config() const noexcept
    {
        return m_config;
    }

private:
    struct Key {
        uint32_t newest_epoch{0};
        uint256 branch_context_hash;
        uint256 beacon_bundle_hash;
        uint256 recovery_authority_hash;

        friend bool operator==(const Key&, const Key&) = default;
    };

    struct Entry {
        Key key;
        VerifiedRosterSetPtr roster_set;
        bool recently_used{false};
    };

    FrozenQuorumRosterCache(uint256 genesis_hash,
                            QuorumBuildConfig config,
                            QuorumSnapshotLookup snapshot_lookup,
                            bool cache_results);

    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActiveImpl(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        RecoveryRosterAuthorityPtr recovery_authority,
        bool publish,
        QuorumBuildError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    const uint256 m_genesis_hash;
    const QuorumBuildConfig m_config;
    const QuorumSnapshotLookup m_snapshot_lookup;
    const bool m_cache_results;
    // A verified set may seed unchecked roster reuse only for the immutable
    // builder configuration and snapshot source that created it.
    const VerifiedRosterSet::BuildProvenancePtr m_build_provenance;

    mutable Mutex m_mutex;
    mutable std::array<Entry, FROZEN_QUORUM_ROSTER_CACHE_CAPACITY>
        m_entries GUARDED_BY(m_mutex);
    mutable std::size_t m_clock_hand GUARDED_BY(m_mutex){0};

    friend class VerifiedRosterSet;
};

using FrozenQuorumRosterCachePtr =
    std::shared_ptr<const FrozenQuorumRosterCache>;

/**
 * Build one canonical 400-slot roster from an exact deterministic-MN snapshot.
 * The base height is derived from the fixed schedule, not accepted from a
 * caller. Payment state never enters validator selection. Root-capable
 * candidates rank ahead of keyless records, with each group ordered by the
 * epoch score derived from the exact NORMAL READY delayed-Bitcoin seed. The
 * branch base hash remains descriptor identity only and never enters that score.
 * Missing operator state or a frozen-absent key leaves an otherwise selected
 * slot without a child key.
 */
[[nodiscard]] std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const RosterBeaconSeed& beacon_seed,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error = nullptr);

/**
 * Build the four oldest-to-newest active rosters on one explicit branch from
 * the exact corresponding READY beacon bundle. The lookup is invoked only
 * with ancestors of branch_tip, then its returned height/hash and exact
 * registry schedule revision are checked.
 */
[[nodiscard]] FrozenQuorumRostersPtr
BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr);

/**
 * Select and freeze four phase-domain standby rosters from the exact pre-F
 * normal snapshot committed by source. Recovery targets reuse those positions;
 * target state may disable, but never replace or reorder, a frozen member.
 */
[[nodiscard]] RecoveryRosterAuthorityPtr
BuildRecoveryRosterAuthorityFromSource(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t recovery_target_height,
    const CBlockIndex& branch_tip,
    const RecoveryRosterAuthoritySource& source,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr);

/**
 * Derive the oldest-to-newest authorization prefix at one exact finality
 * boundary. Bootstrap rosters use their base; later rotations use their
 * snapshot. Callers reject masks with fewer than three authorized slots.
 */
[[nodiscard]] uint8_t GetSigningRosterAuthorizationMask(
    const FrozenQuorumRosters& rosters,
    const AuthorizationBoundaryLookup& is_boundary_ancestor);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
