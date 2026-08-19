// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_schedule.h>

#include <algorithm>
#include <cstdint>
#include <limits>

namespace llmq::pq {
namespace {

constexpr int64_t MAX_BLOCK_HEIGHT{std::numeric_limits<int32_t>::max()};

std::optional<int32_t> CheckedBaseHeight(const ChainLockScheduleConfig& config,
                                         uint64_t epoch) noexcept
{
    const int64_t height{static_cast<int64_t>(config.epoch_origin) +
                         static_cast<int64_t>(epoch) * config.epoch_blocks};
    if (height < 0 || height > MAX_BLOCK_HEIGHT) return std::nullopt;
    return static_cast<int32_t>(height);
}

std::optional<int32_t> FirstCadenceAtOrAfter(const ChainLockScheduleConfig& config,
                                             int32_t height) noexcept
{
    if (!config.IsValid() || height < config.epoch_origin) return std::nullopt;
    const int64_t offset{static_cast<int64_t>(height) - config.epoch_origin};
    const int64_t remainder{offset % config.chainlock_period};
    const int64_t adjustment{remainder == 0 ? 0 : config.chainlock_period - remainder};
    const int64_t result{static_cast<int64_t>(height) + adjustment};
    if (result > MAX_BLOCK_HEIGHT) return std::nullopt;
    return static_cast<int32_t>(result);
}

std::optional<int32_t> LastCadenceBefore(const ChainLockScheduleConfig& config,
                                         int64_t end_height_exclusive) noexcept
{
    if (!config.IsValid() || end_height_exclusive <= config.epoch_origin) {
        return std::nullopt;
    }
    const int64_t candidate{end_height_exclusive - 1};
    const int64_t offset{candidate - config.epoch_origin};
    return static_cast<int32_t>(candidate - offset % config.chainlock_period);
}

} // namespace

bool ChainLockScheduleConfig::IsValid() const noexcept
{
    if (epoch_origin < 0 || epoch_blocks != PQ_EPOCH_BLOCKS ||
        chainlock_period != PQ_CL_PERIOD || sign_lag != PQ_CL_SIGN_LAG ||
        active_epochs != ACTIVE_QUORUMS ||
        epoch_origin % static_cast<int32_t>(PQ_EPOCH_ALIGNMENT) != 0) {
        return false;
    }

    // A valid deployment must admit at least one fully warmed-up target.
    // The optional local signing delay never changes certificate validity.
    return static_cast<int64_t>(epoch_origin) +
               PQ_FIRST_ELIGIBLE_TARGET_OFFSET <=
           MAX_BLOCK_HEIGHT;
}

std::optional<ChainLockScheduleConfig> MakeChainLockScheduleConfig(
    int32_t epoch_origin) noexcept
{
    ChainLockScheduleConfig config;
    config.epoch_origin = epoch_origin;
    if (!config.IsValid()) return std::nullopt;
    return config;
}

std::optional<uint32_t> EpochForHeight(const ChainLockScheduleConfig& config,
                                       int32_t height) noexcept
{
    if (!config.IsValid() || height < config.epoch_origin) return std::nullopt;
    const uint64_t epoch{static_cast<uint64_t>(
        (static_cast<int64_t>(height) - config.epoch_origin) / config.epoch_blocks)};
    if (epoch > std::numeric_limits<uint32_t>::max()) return std::nullopt;
    return static_cast<uint32_t>(epoch);
}

std::optional<int32_t> EpochBaseHeight(const ChainLockScheduleConfig& config,
                                       uint32_t epoch) noexcept
{
    if (!config.IsValid()) return std::nullopt;
    return CheckedBaseHeight(config, epoch);
}

std::optional<int32_t> EpochEndHeightExclusive(const ChainLockScheduleConfig& config,
                                               uint32_t epoch) noexcept
{
    if (!config.IsValid() || epoch == std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    return CheckedBaseHeight(config, static_cast<uint64_t>(epoch) + 1);
}

std::optional<int32_t> QuorumExpiryHeightExclusive(const ChainLockScheduleConfig& config,
                                                   uint32_t epoch) noexcept
{
    if (!config.IsValid() || epoch > std::numeric_limits<uint32_t>::max() - ACTIVE_QUORUMS) {
        return std::nullopt;
    }
    return CheckedBaseHeight(config, static_cast<uint64_t>(epoch) + ACTIVE_QUORUMS);
}

std::optional<int32_t> RegistrationCutoffHeight(const ChainLockScheduleConfig& config,
                                                uint32_t epoch,
                                                uint32_t blocks_before_base) noexcept
{
    const auto base_height{EpochBaseHeight(config, epoch)};
    if (!base_height || blocks_before_base > static_cast<uint32_t>(*base_height)) {
        return std::nullopt;
    }
    return static_cast<int32_t>(static_cast<int64_t>(*base_height) - blocks_before_base);
}

bool IsRegistrationCutoffHeight(const ChainLockScheduleConfig& config,
                                uint32_t blocks_before_base,
                                int32_t height) noexcept
{
    if (!config.IsValid() || height < 0) return false;
    const int64_t candidate_base{
        static_cast<int64_t>(height) + blocks_before_base};
    if (candidate_base > std::numeric_limits<int32_t>::max()) return false;
    const auto epoch{
        EpochForHeight(config, static_cast<int32_t>(candidate_base))};
    if (!epoch) return false;
    const auto cutoff{
        RegistrationCutoffHeight(config, *epoch, blocks_before_base)};
    return cutoff && *cutoff == height;
}

bool IsBeforeRegistrationCutoff(const ChainLockScheduleConfig& config,
                                uint32_t epoch,
                                uint32_t blocks_before_base,
                                int32_t commitment_inclusion_height) noexcept
{
    const auto cutoff_height{
        RegistrationCutoffHeight(config, epoch, blocks_before_base)};
    return cutoff_height && commitment_inclusion_height >= 0 &&
           commitment_inclusion_height < *cutoff_height;
}

std::optional<ActiveEpochIdentities> ActiveEpochsAtHeight(
    const ChainLockScheduleConfig& config, int32_t target_height) noexcept
{
    const auto current_epoch{EpochForHeight(config, target_height)};
    if (!current_epoch || *current_epoch < ACTIVE_QUORUMS - 1) return std::nullopt;

    ActiveEpochIdentities epochs;
    const uint32_t oldest_epoch{
        *current_epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 1)};
    for (std::size_t slot{0}; slot < epochs.size(); ++slot) {
        const uint32_t epoch{oldest_epoch + static_cast<uint32_t>(slot)};
        const auto base_height{EpochBaseHeight(config, epoch)};
        if (!base_height) return std::nullopt;
        epochs[slot] = EpochIdentity{epoch, *base_height};
    }
    return epochs;
}

bool IsChainLockCadenceHeight(const ChainLockScheduleConfig& config,
                              int32_t height) noexcept
{
    if (!config.IsValid() || height < config.epoch_origin) return false;
    return (static_cast<int64_t>(height) - config.epoch_origin) %
               config.chainlock_period ==
           0;
}

bool IsEligibleChainLockTarget(const ChainLockScheduleConfig& config,
                               int32_t target_height) noexcept
{
    return IsChainLockCadenceHeight(config, target_height) &&
           ActiveEpochsAtHeight(config, target_height).has_value();
}

std::optional<int32_t> NextEligibleChainLockTargetHeight(
    const ChainLockScheduleConfig& config,
    int32_t predecessor_height) noexcept
{
    if (!config.IsValid() || predecessor_height < -1 ||
        predecessor_height == std::numeric_limits<int32_t>::max()) {
        return std::nullopt;
    }
    const auto warmup_height{
        EpochBaseHeight(config, ACTIVE_QUORUMS - 1)};
    if (!warmup_height) return std::nullopt;
    const int64_t first_height{std::max<int64_t>(
        static_cast<int64_t>(predecessor_height) + 1,
        *warmup_height)};
    if (first_height > MAX_BLOCK_HEIGHT) return std::nullopt;
    const auto target{FirstCadenceAtOrAfter(
        config, static_cast<int32_t>(first_height))};
    if (!target || !IsEligibleChainLockTarget(config, *target)) {
        return std::nullopt;
    }
    return target;
}

std::optional<int32_t> LatestEligibleChainLockTargetHeight(
    const ChainLockScheduleConfig& config, int32_t tip_height) noexcept
{
    if (!config.IsValid()) return std::nullopt;
    const int64_t available_height{
        static_cast<int64_t>(tip_height) - config.sign_lag};
    const int64_t offset{available_height - config.epoch_origin};
    if (offset < 0) return std::nullopt;
    const int64_t target_height{
        available_height - offset % config.chainlock_period};
    if (target_height < 0 || target_height > MAX_BLOCK_HEIGHT ||
        !IsEligibleChainLockTarget(
            config, static_cast<int32_t>(target_height))) {
        return std::nullopt;
    }
    return static_cast<int32_t>(target_height);
}

std::optional<ChainLockSigningWindow> CurrentChainLockSigningWindow(
    const ChainLockScheduleConfig& config,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept
{
    const auto next{NextEligibleChainLockTargetHeight(
        config, durable_predecessor_height)};
    const auto latest{LatestEligibleChainLockTargetHeight(config, tip_height)};
    if (!next || !latest || *latest < *next) return std::nullopt;

    if (*latest == *next) {
        return ChainLockSigningWindow{*latest,
                                      durable_predecessor_height};
    }
    const int64_t declared_predecessor{
        static_cast<int64_t>(*latest) - config.chainlock_period};
    if (declared_predecessor < 0 ||
        declared_predecessor > std::numeric_limits<int32_t>::max() ||
        !IsEligibleChainLockTarget(
            config, static_cast<int32_t>(declared_predecessor))) {
        return std::nullopt;
    }
    return ChainLockSigningWindow{
        *latest, static_cast<int32_t>(declared_predecessor)};
}

std::optional<int32_t> SigningHeightForTarget(const ChainLockScheduleConfig& config,
                                              int32_t target_height) noexcept
{
    if (!IsEligibleChainLockTarget(config, target_height)) return std::nullopt;
    if (static_cast<int64_t>(target_height) + config.sign_lag > MAX_BLOCK_HEIGHT) {
        return std::nullopt;
    }
    return static_cast<int32_t>(static_cast<int64_t>(target_height) + config.sign_lag);
}

std::optional<int32_t> TargetHeightForSigningHeight(const ChainLockScheduleConfig& config,
                                                    int32_t signing_height) noexcept
{
    if (!config.IsValid() || signing_height < static_cast<int32_t>(config.sign_lag)) {
        return std::nullopt;
    }
    const int32_t target_height{signing_height - static_cast<int32_t>(config.sign_lag)};
    if (!IsEligibleChainLockTarget(config, target_height)) return std::nullopt;
    return target_height;
}

std::optional<EligibleTargetSpan> EligibleTargetsForEpoch(
    const ChainLockScheduleConfig& config, uint32_t epoch) noexcept
{
    const auto epoch_base{EpochBaseHeight(config, epoch)};
    const auto warmup_height{EpochBaseHeight(config, ACTIVE_QUORUMS - 1)};
    if (!epoch_base || !warmup_height) return std::nullopt;

    const int32_t start_height{std::max(*epoch_base, *warmup_height)};
    const int64_t expiry_height{
        static_cast<int64_t>(config.epoch_origin) +
        (static_cast<int64_t>(epoch) + static_cast<int64_t>(ACTIVE_QUORUMS)) *
            static_cast<int64_t>(config.epoch_blocks)};
    const int64_t end_height_exclusive{
        std::min(expiry_height, MAX_BLOCK_HEIGHT + 1)};
    if (end_height_exclusive <= start_height) return std::nullopt;

    const auto first_height{FirstCadenceAtOrAfter(config, start_height)};
    const auto last_height{LastCadenceBefore(config, end_height_exclusive)};
    if (!first_height || !last_height || *first_height > *last_height ||
        !IsEligibleChainLockTarget(config, *first_height) ||
        !IsEligibleChainLockTarget(config, *last_height)) {
        return std::nullopt;
    }

    const int64_t count{
        (static_cast<int64_t>(*last_height) - *first_height) / config.chainlock_period + 1};
    if (count <= 0 || count > PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD) return std::nullopt;
    return EligibleTargetSpan{*first_height, *last_height, static_cast<uint16_t>(count)};
}

bool IsEpochActiveForTarget(const ChainLockScheduleConfig& config,
                            uint32_t epoch,
                            int32_t target_height) noexcept
{
    if (!IsEligibleChainLockTarget(config, target_height)) return false;
    const auto active_epochs{ActiveEpochsAtHeight(config, target_height)};
    if (!active_epochs) return false;
    return std::any_of(active_epochs->begin(), active_epochs->end(),
                       [epoch](const EpochIdentity& active) { return active.epoch == epoch; });
}

} // namespace llmq::pq
