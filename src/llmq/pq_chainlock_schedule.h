// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_SCHEDULE_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_SCHEDULE_H

#include <llmq/pq_chainlock_types.h>

#include <array>
#include <cstdint>
#include <numeric>
#include <optional>

namespace llmq::pq {

inline constexpr uint32_t PQ_EPOCH_BLOCKS{288};
inline constexpr uint32_t PQ_CL_PERIOD{5};
inline constexpr uint32_t PQ_CL_SIGN_LAG{5};
inline constexpr uint32_t PQ_EPOCH_ALIGNMENT{std::lcm(PQ_EPOCH_BLOCKS, PQ_CL_PERIOD)};
inline constexpr uint32_t PQ_WARMUP_BLOCKS{
    static_cast<uint32_t>(ACTIVE_QUORUMS - 1) * PQ_EPOCH_BLOCKS};
inline constexpr uint32_t PQ_FIRST_ELIGIBLE_TARGET_OFFSET{
    ((PQ_WARMUP_BLOCKS + PQ_CL_PERIOD - 1) / PQ_CL_PERIOD) * PQ_CL_PERIOD};
inline constexpr uint32_t PQ_ACTIVE_LIFETIME_BLOCKS{
    static_cast<uint32_t>(ACTIVE_QUORUMS) * PQ_EPOCH_BLOCKS};
inline constexpr uint16_t PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD{
    static_cast<uint16_t>((PQ_ACTIVE_LIFETIME_BLOCKS + PQ_CL_PERIOD - 1) / PQ_CL_PERIOD)};

static_assert(ACTIVE_QUORUMS == 4);
static_assert(PQ_EPOCH_ALIGNMENT == 1440);
static_assert(PQ_WARMUP_BLOCKS == 864);
static_assert(PQ_FIRST_ELIGIBLE_TARGET_OFFSET == 865);
static_assert(PQ_ACTIVE_LIFETIME_BLOCKS == 1152);
static_assert(PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD == 231);
static_assert(PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD <= C11_USAGE_CAP);

/**
 * The profile fixes every field except the deployment-specific epoch origin.
 * Keeping the fixed fields in consensus parameters makes accidental profile
 * drift fail closed instead of silently changing child-key lifetime.
 */
struct ChainLockScheduleConfig {
    int32_t epoch_origin{-1};
    uint32_t epoch_blocks{PQ_EPOCH_BLOCKS};
    uint32_t chainlock_period{PQ_CL_PERIOD};
    uint32_t sign_lag{PQ_CL_SIGN_LAG};
    uint32_t active_epochs{ACTIVE_QUORUMS};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const ChainLockScheduleConfig&,
                           const ChainLockScheduleConfig&) = default;
};

/** Construct and validate the fixed profile from deployment constants. */
[[nodiscard]] std::optional<ChainLockScheduleConfig> MakeChainLockScheduleConfig(
    int32_t epoch_origin) noexcept;

struct EpochIdentity {
    uint32_t epoch{0};
    int32_t base_height{-1};

    friend bool operator==(const EpochIdentity&, const EpochIdentity&) = default;
};

using ActiveEpochIdentities = std::array<EpochIdentity, ACTIVE_QUORUMS>;

struct EligibleTargetSpan {
    int32_t first_height{-1};
    int32_t last_height{-1};
    uint16_t count{0};

    friend bool operator==(const EligibleTargetSpan&, const EligibleTargetSpan&) = default;
};

struct ChainLockSigningWindow {
    int32_t target_height{-1};
    int32_t declared_predecessor_height{-1};

    friend bool operator==(const ChainLockSigningWindow&,
                           const ChainLockSigningWindow&) = default;
};

/** Returns the fixed epoch containing height, or null before the origin. */
[[nodiscard]] std::optional<uint32_t> EpochForHeight(
    const ChainLockScheduleConfig& config, int32_t height) noexcept;

/** Returns base(e), rejecting any result outside the signed block-height domain. */
[[nodiscard]] std::optional<int32_t> EpochBaseHeight(
    const ChainLockScheduleConfig& config, uint32_t epoch) noexcept;

/** Returns base(e + 1). */
[[nodiscard]] std::optional<int32_t> EpochEndHeightExclusive(
    const ChainLockScheduleConfig& config, uint32_t epoch) noexcept;

/** Returns base(e + 4), after which epoch e cannot sign another target. */
[[nodiscard]] std::optional<int32_t> QuorumExpiryHeightExclusive(
    const ChainLockScheduleConfig& config, uint32_t epoch) noexcept;

/**
 * Returns base(e) - blocks_before_base. The deployment supplies the lag; this
 * module deliberately does not choose whether a network uses one or more
 * confirmation/snapshot epochs.
 */
[[nodiscard]] std::optional<int32_t> RegistrationCutoffHeight(
    const ChainLockScheduleConfig& config,
    uint32_t epoch,
    uint32_t blocks_before_base) noexcept;

/** Exact inverse used to identify the sparse branch snapshots a roster may consume. */
[[nodiscard]] bool IsRegistrationCutoffHeight(
    const ChainLockScheduleConfig& config,
    uint32_t blocks_before_base,
    int32_t height) noexcept;

/** The cutoff is exclusive: an entry included at the cutoff is already late. */
[[nodiscard]] bool IsBeforeRegistrationCutoff(
    const ChainLockScheduleConfig& config,
    uint32_t epoch,
    uint32_t blocks_before_base,
    int32_t commitment_inclusion_height) noexcept;

/**
 * Returns epochs [current - 3, current] in oldest-to-newest quorum-slot order.
 * The first three epochs are an explicit warmup and return null.
 */
[[nodiscard]] std::optional<ActiveEpochIdentities> ActiveEpochsAtHeight(
    const ChainLockScheduleConfig& config, int32_t target_height) noexcept;

/** Tests only the absolute five-block cadence, after the configured origin. */
[[nodiscard]] bool IsChainLockCadenceHeight(
    const ChainLockScheduleConfig& config, int32_t height) noexcept;

/** Requires only the cadence and four materialized epochs. */
[[nodiscard]] bool IsEligibleChainLockTarget(
    const ChainLockScheduleConfig& config, int32_t target_height) noexcept;

/** First eligible target strictly after the declared ChainLock predecessor. */
[[nodiscard]] std::optional<int32_t> NextEligibleChainLockTargetHeight(
    const ChainLockScheduleConfig& config,
    int32_t predecessor_height) noexcept;

/** Latest eligible target whose signing lag is satisfied by this tip. */
[[nodiscard]] std::optional<int32_t> LatestEligibleChainLockTargetHeight(
    const ChainLockScheduleConfig& config, int32_t tip_height) noexcept;

/**
 * Select the current signing round and its unique declared predecessor.
 * The durable predecessor remains the state-validation floor; after a missed
 * round the wire predecessor advances to the active block immediately before
 * the current target so recovery cannot create a second successor edge.
 */
[[nodiscard]] std::optional<ChainLockSigningWindow>
CurrentChainLockSigningWindow(
    const ChainLockScheduleConfig& config,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept;

[[nodiscard]] std::optional<int32_t> SigningHeightForTarget(
    const ChainLockScheduleConfig& config, int32_t target_height) noexcept;

[[nodiscard]] std::optional<int32_t> TargetHeightForSigningHeight(
    const ChainLockScheduleConfig& config, int32_t signing_height) noexcept;

/**
 * Returns the exact eligible target span for a child epoch. Early warmup
 * epochs have shorter spans. Arithmetic overflow returns null.
 */
[[nodiscard]] std::optional<EligibleTargetSpan> EligibleTargetsForEpoch(
    const ChainLockScheduleConfig& config, uint32_t epoch) noexcept;

[[nodiscard]] bool IsEpochActiveForTarget(
    const ChainLockScheduleConfig& config,
    uint32_t epoch,
    int32_t target_height) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_SCHEDULE_H
