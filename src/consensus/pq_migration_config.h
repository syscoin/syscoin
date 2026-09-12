// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
#define SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H

#include <consensus/params.h>

#include <limits>

namespace Consensus {

enum class PQActivationResult {
    DISABLED,
    VALID,
    INVALID_CONFIGURATION,
};

enum class PQLegacyReplayResult {
    ALLOWED,
    RETIRED,
    INVALID_CONFIGURATION,
};

enum class PQPaymentEligibilityResult {
    LEGACY,
    ROOT_REQUIRED,
    INVALID_CONFIGURATION,
};

// SYSCOIN: This height-only transition intentionally carries no branch hash or
// reconstructed-state commitment. Historical fork choice remains ordinary
// proof of work until PQ ChainLocks provide live finality.
inline PQActivationResult CheckPQActivationConfiguration(
    const Params& params)
{
    if (params.nPQActivationHeight == std::numeric_limits<int>::max()) {
        return PQActivationResult::DISABLED;
    }
    // The first finality statement authenticates the block at A - 1. A
    // genesis-height activation has no real predecessor to bind.
    if (params.nPQActivationHeight <= 0 ||
        params.nPQActivationHeight < params.DIP0003Height) {
        return PQActivationResult::INVALID_CONFIGURATION;
    }
    return PQActivationResult::VALID;
}

inline bool IsPQActivationHeightCompatibleWithSuperblocks(
    const Params& params) noexcept
{
    const auto activation{CheckPQActivationConfiguration(params)};
    if (activation != PQActivationResult::VALID) {
        return activation == PQActivationResult::DISABLED;
    }
    int64_t cycle{params.nSuperblockCycle};
    if (params.nPQActivationHeight < params.nNEVMStartBlock) {
        cycle = cycle * 5 / 2;
    }
    if (cycle <= 0 || cycle > std::numeric_limits<int>::max()) return false;
    return params.nPQActivationHeight < params.nSuperblockStartBlock ||
           params.nPQActivationHeight % cycle != 0;
}

inline PQLegacyReplayResult CheckPQLegacyReplay(
    const Params& params,
    int height)
{
    const auto configuration{CheckPQActivationConfiguration(params)};
    if (configuration == PQActivationResult::DISABLED) {
        return PQLegacyReplayResult::ALLOWED;
    }
    if (configuration != PQActivationResult::VALID) {
        return PQLegacyReplayResult::INVALID_CONFIGURATION;
    }
    return height < params.nPQActivationHeight
        ? PQLegacyReplayResult::ALLOWED
        : PQLegacyReplayResult::RETIRED;
}

/** The active tip after which mempool provider payloads change wire era. */
inline bool IsPQProviderMempoolTransitionTip(const Params& params,
                                             int tip_height)
{
    return CheckPQActivationConfiguration(params) ==
               PQActivationResult::VALID &&
           tip_height == params.nPQActivationHeight - 1;
}

/** Root-bearing payment eligibility starts at the first PQ-only block. */
inline PQPaymentEligibilityResult CheckPQPaymentEligibility(
    const Params& params,
    int height)
{
    const auto configuration{CheckPQActivationConfiguration(params)};
    if (configuration == PQActivationResult::DISABLED) {
        return PQPaymentEligibilityResult::LEGACY;
    }
    if (configuration != PQActivationResult::VALID) {
        return PQPaymentEligibilityResult::INVALID_CONFIGURATION;
    }
    return height < params.nPQActivationHeight
        ? PQPaymentEligibilityResult::LEGACY
        : PQPaymentEligibilityResult::ROOT_REQUIRED;
}

} // namespace Consensus

#endif // SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
