// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_ROSTER_BEACON_H
#define SYSCOIN_LLMQ_PQ_ROSTER_BEACON_H

#include <llmq/pq_btcc.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <string_view>

namespace llmq::pq {

inline constexpr uint16_t ROSTER_AUTHORIZATION_TRANSITION_VERSION{1};
inline constexpr uint32_t ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS{6};

inline constexpr std::string_view ROSTER_BEACON_COMMITMENT_DOMAIN{
    "SYS_PQ_ROSTER_BEACON_COMMITMENT_V1"};
inline constexpr std::string_view ROSTER_BEACON_BUNDLE_DOMAIN{
    "SYS_PQ_ROSTER_BEACON_BUNDLE_V1"};
inline constexpr std::string_view ROSTER_AUTHORIZATION_STATE_DOMAIN{
    "SYS_PQ_ROSTER_AUTHORIZATION_STATE_V1"};
inline constexpr std::string_view RECOVERY_ROSTER_ENTROPY_DOMAIN{
    "SYS_PQ_RECOVERY_ENTROPY_V1"};

/**
 * The exact prior state used by every transition except INITIALIZE. RECOVER
 * resumes from the exact durable authorization base rather than the wire
 * predecessor when finality has skipped otherwise eligible rounds.
 */
struct RosterAuthorizationPriorState {
    uint256 state_hash;
    RosterBeaconWindow window;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RosterAuthorizationPriorState&,
                           const RosterAuthorizationPriorState&) = default;
};

/** Pure state-machine input for sealing one authorization boundary. */
struct RosterAuthorizationTransition {
    uint16_t version{ROSTER_AUTHORIZATION_TRANSITION_VERSION};
    RosterAuthorizationTransitionKind kind{
        RosterAuthorizationTransitionKind::INITIALIZE};
    int32_t target_height{-1};
    uint256 target_block_hash;
    int32_t predecessor_height{-1};
    uint256 predecessor_block_hash;
    RosterAuthorizationBaseIdentity authorization_base;
    std::optional<RosterAuthorizationPriorState> previous;
    RosterBeaconWindow new_window;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RosterAuthorizationTransition&,
                           const RosterAuthorizationTransition&) = default;
};

/**
 * Exact next-epoch snapshot fact checked against the durable authorization
 * predecessor. The hash is present only after the caller has verified that
 * the cutoff is an ancestor of the certificate owning the prior state.
 */
struct RosterBeaconSnapshotCoverage {
    uint32_t epoch{0};
    int32_t height{-1};
    uint256 hash;
    bool prior_authorization_is_descendant{false};

    friend bool operator==(const RosterBeaconSnapshotCoverage&,
                           const RosterBeaconSnapshotCoverage&) = default;
};

/** Result of checking one accepted BTCC cursor against a fresh active tip. */
struct ValidatedRosterBeaconAnchor {
    BTCCursor cursor;
    int32_t btc_height{-1};
    int32_t active_tip_height{-1};
    bool is_active{false};

    friend bool operator==(const ValidatedRosterBeaconAnchor&,
                           const ValidatedRosterBeaconAnchor&) = default;
};

/** One externally validated active-chain view of an anchor and its H+37. */
struct ValidatedRosterBeaconRange {
    uint256 anchor_hash;
    int32_t anchor_height{-1};
    uint256 future_hash;
    int32_t future_height{-1};
    int32_t active_tip_height{-1};
    bool is_active{false};

    friend bool operator==(const ValidatedRosterBeaconRange&,
                           const ValidatedRosterBeaconRange&) = default;
};

/**
 * Pure normal-path input. Chain ancestry and Bitcoin active-chain lookups are
 * performed by the caller; their exact results are rebound here before a
 * transition, mask, or authorization hash can be produced.
 */
struct NormalRosterAuthorizationInput {
    uint32_t newest_epoch{0};
    int32_t target_height{-1};
    uint256 target_block_hash;
    int32_t predecessor_height{-1};
    uint256 predecessor_block_hash;
    RosterAuthorizationBaseIdentity authorization_base;
    RosterAuthorizationPriorState previous;
    BTCCursor previous_btcc_cursor;
    BTCCursor accepted_btcc_cursor;
    BTCCAdvance btcc_advance{BTCCAdvance::KEEP};
    RosterBeaconSnapshotCoverage next_snapshot;
    std::optional<ValidatedRosterBeaconAnchor> accepted_anchor;
    std::optional<ValidatedRosterBeaconRange> pending_reveal;
    std::optional<ValidatedRosterBeaconRange> ready_rotation;
    /** Exact fixed authority source/hash committed by the signed prior state. */
    RecoveryRosterAuthoritySource recovery_authority_source;
    uint256 recovery_authority_hash;
};

/** One normal-path decision; INITIALIZE and RECOVER never use this type. */
struct NormalRosterAuthorizationDecision {
    RosterAuthorizationTransition transition;
    uint8_t authorization_mask{0};
    uint256 state_hash;

    friend bool operator==(const NormalRosterAuthorizationDecision&,
                           const NormalRosterAuthorizationDecision&) = default;
};

[[nodiscard]] bool IsExactRosterBeaconObservation(
    const RosterBeaconSeed& empty,
    const RosterBeaconSeed& pending) noexcept;

[[nodiscard]] bool IsExactRosterBeaconReveal(
    const RosterBeaconSeed& pending,
    const RosterBeaconSeed& ready) noexcept;

[[nodiscard]] bool IsExactRosterBeaconRotation(
    const RosterBeaconWindow& old_window,
    const RosterBeaconWindow& new_window) noexcept;

/** ROTATE authorizes 0111; every other normal transition authorizes 1111. */
[[nodiscard]] std::optional<uint8_t> GetNormalRosterAuthorizationMask(
    RosterAuthorizationTransitionKind kind) noexcept;

/**
 * Derive the only normal-path transition admitted by these exact facts.
 * Supplying invalid or mismatched prevalidated facts fails closed. The result
 * includes the authorization hash so callers cannot hash a weaker shape-only
 * transition by mistake.
 */
[[nodiscard]] std::optional<NormalRosterAuthorizationDecision>
DeriveNormalRosterAuthorizationDecision(
    const uint256& genesis_hash,
    const NormalRosterAuthorizationInput& input) noexcept;

/** Validate wire claims and return only the policy-derived authorization mask. */
[[nodiscard]] std::optional<uint8_t>
ValidateNormalRosterAuthorizationDecision(
    const uint256& genesis_hash,
    const NormalRosterAuthorizationInput& input,
    const RosterAuthorizationTransition& claimed_transition,
    const uint256& claimed_state_hash) noexcept;

/** Canonical no-predecessor window selected by one shared delayed-Bitcoin seed. */
[[nodiscard]] bool IsInitialNormalRosterBeaconWindow(
    const RosterBeaconWindow& window) noexcept;

/** Narrow prolonged-outage exception derived from one shared raw anchor. */
[[nodiscard]] bool IsRecoveryRosterBeaconWindow(
    const RosterBeaconWindow& window) noexcept;

/** Build the sole recovery window for an authenticated source and epoch. */
[[nodiscard]] std::optional<RosterBeaconWindow>
MakeRecoveryRosterBeaconWindow(
    const RecoveryRosterAuthoritySource& source,
    const uint256& recovery_authority_hash,
    uint32_t newest_epoch) noexcept;

/** Whether any active slot was seeded by objective recovery. */
[[nodiscard]] bool HasRecoveryRosterBeacon(
    const RosterBeaconWindow& window) noexcept;

/** Commit every seed field under a roster-only, network-bound domain. */
[[nodiscard]] std::optional<uint256> GetRosterBeaconCommitmentHash(
    const uint256& genesis_hash,
    const RosterBeaconSeed& seed) noexcept;

/** Commit the complete delayed normal F source reused during recovery. */
[[nodiscard]] std::optional<uint256> GetRecoveryRosterEntropyCommitment(
    const uint256& genesis_hash,
    const RosterBeaconSeed& normal_beacon) noexcept;

[[nodiscard]] std::optional<uint256> GetActiveRosterBeaconBundleHash(
    const uint256& genesis_hash,
    const ActiveRosterBeaconBundle& bundle) noexcept;

/** Return the exact READY seed for an epoch carried by an active bundle. */
[[nodiscard]] const RosterBeaconSeed* FindRosterBeaconSeed(
    const ActiveRosterBeaconBundle& bundle,
    uint32_t epoch) noexcept;

/** Newest normal READY seed authenticated by this complete window. */
[[nodiscard]] const RosterBeaconSeed* FindNewestNormalReadySeed(
    const RosterBeaconWindow& window) noexcept;

/**
 * Miner-independent roster modifier. Base, carrier, and handoff block hashes
 * are intentionally absent; branch identity remains in the descriptor.
 */
[[nodiscard]] std::optional<uint256> GetPQQuorumModifier(
    const uint256& genesis_hash,
    uint32_t epoch,
    int32_t snapshot_height,
    const uint256& snapshot_hash,
    const RosterBeaconSeed& seed) noexcept;

/** First joint ChainLock/BTCC target in an aligned recovery epoch. */
[[nodiscard]] std::optional<int32_t>
CanonicalRosterRecoveryTargetHeight(
    const ChainLockScheduleConfig& chainlock,
    const BTCCScheduleConfig& btcc,
    uint32_t epoch) noexcept;

/**
 * Map an initialization or recovery target to its sole discontinuous
 * transition.
 * The first eligible target after activation is INITIALIZE-only. Every later
 * admissible reset is the unique joint ChainLock/BTCC target of phase 3 and is
 * RECOVER-only from a durable authorization base; all other heights return
 * null.
 */
[[nodiscard]] std::optional<RosterAuthorizationTransitionKind>
CanonicalRosterResetTransitionForTarget(
    const ChainLockScheduleConfig& chainlock,
    const BTCCScheduleConfig& btcc,
    int32_t activation_predecessor_height,
    int32_t target_height) noexcept;

/** Hash the next authorization state after validating the exact transition. */
[[nodiscard]] std::optional<uint256> GetRosterAuthorizationStateHash(
    const uint256& genesis_hash,
    const RosterAuthorizationTransition& transition) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_ROSTER_BEACON_H
