// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
#define SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H

#include <evo/deterministicmns.h>
#include <evo/pq_payment_probation.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_operator_key_state.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

class CBlockIndex;

namespace llmq::pq {

inline constexpr std::string_view PQ_QUORUM_MODIFIER_DOMAIN{
    "SYS_PQ_QUORUM_MODIFIER_V1"};

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
    INVALID_RECOVERY_SELECTION,
};

/**
 * State looked up at an exact block on the branch supplied by the caller.
 * Values are owned so roster construction never retains aliases into a
 * mutable cache or a reorg-sensitive manager view.
 */
struct QuorumSnapshotState {
    CDeterministicMNList deterministic_mns;
    std::vector<OperatorKeyState> operator_key_states;
};

using QuorumSnapshotLookup =
    std::function<std::optional<QuorumSnapshotState>(const CBlockIndex&)>;

using FinalizedSnapshotLookup =
    std::function<bool(int32_t, const uint256&)>;

/** Domain-separated replacement for the legacy opaque DKG/base modifier. */
[[nodiscard]] std::optional<uint256> GetPQQuorumModifier(
    const uint256& genesis_hash,
    uint32_t epoch,
    const uint256& base_hash);

/**
 * Build one canonical 400-slot roster from an exact deterministic-MN snapshot.
 * The base height is derived from the fixed schedule, not accepted from a
 * caller. Payment state never enters validator selection: when more than 400
 * root-capable operators compete, 32 state-independent audit-coverage seats
 * traverse their canonical cyclic order so every such operator has a bounded
 * opportunity to demonstrate recovery. Root-capable candidates otherwise
 * rank ahead of keyless records. Missing operator state or a frozen-absent key
 * leaves an otherwise selected slot without a child key.
 */
[[nodiscard]] std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error = nullptr,
    PQPaymentRecoverySelection* recovery_selection = nullptr);

/**
 * Build the four oldest-to-newest active rosters on one explicit branch. The
 * lookup is invoked only with ancestors of branch_tip, then its returned
 * height/hash and exact registry schedule revision are checked.
 */
[[nodiscard]] FrozenQuorumRostersPtr
BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr);

/**
 * Gate validator-set rotation on finality of every newly introduced roster
 * snapshot. The four migration bootstrap epochs are fork-authorized because
 * no PQ ChainLock can precede them; every later epoch must be covered by an
 * already accepted certificate before a member may sign with it.
 */
[[nodiscard]] bool AreSigningRosterTransitionsFinalized(
    const FrozenQuorumRosters& rosters,
    const FinalizedSnapshotLookup& finalized_snapshot);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
