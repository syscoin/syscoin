// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
#define SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H

#include <consensus/params.h>

#include <limits>

namespace Consensus {

enum class PQAnchorResult {
    DISABLED,
    VALID,
    INVALID_CONFIGURATION,
    BLOCK_HASH_MISMATCH,
    MISSING_ANCESTOR,
    ANCESTOR_HASH_MISMATCH,
};

enum class PQLegacyReplayResult {
    ALLOWED,
    RETIRED,
    INVALID_CONFIGURATION,
};

// SYSCOIN: Configuration validation is chain-independent so parameter
// construction cannot import branch-navigation dependencies.
inline PQAnchorResult CheckPQLegacyAnchorConfiguration(
    const Params& params)
{
    const bool disabled_height{
        params.nPQLegacyAnchorHeight == std::numeric_limits<int>::max()};
    const bool null_hashes{params.hashPQLegacyAnchorBlock.IsNull() &&
                           params.hashPQLegacyMNState.IsNull() &&
                           params.hashPQLegacyPQRegistryState.IsNull()};
    if (disabled_height) {
        return null_hashes ? PQAnchorResult::DISABLED
                           : PQAnchorResult::INVALID_CONFIGURATION;
    }
    if (params.hashPQLegacyAnchorBlock.IsNull() ||
        params.hashPQLegacyMNState.IsNull() ||
        params.hashPQLegacyPQRegistryState.IsNull()) {
        return PQAnchorResult::INVALID_CONFIGURATION;
    }
    if (params.nPQLegacyAnchorHeight < params.DIP0003Height) {
        return PQAnchorResult::INVALID_CONFIGURATION;
    }
    return PQAnchorResult::VALID;
}

inline PQLegacyReplayResult CheckPQLegacyReplay(
    const Params& params,
    int height)
{
    const auto configuration{CheckPQLegacyAnchorConfiguration(params)};
    if (configuration == PQAnchorResult::DISABLED) {
        return PQLegacyReplayResult::ALLOWED;
    }
    if (configuration != PQAnchorResult::VALID) {
        return PQLegacyReplayResult::INVALID_CONFIGURATION;
    }
    return height <= params.nPQLegacyAnchorHeight
        ? PQLegacyReplayResult::ALLOWED
        : PQLegacyReplayResult::RETIRED;
}

inline PQAnchorResult CheckPQChainLockAnchorConfiguration(
    const Params& params)
{
    const bool disabled_height{
        params.nPQChainLockAnchorHeight == std::numeric_limits<int>::max()};
    if (disabled_height) {
        return params.hashPQChainLockAnchorBlock.IsNull()
            ? PQAnchorResult::DISABLED
            : PQAnchorResult::INVALID_CONFIGURATION;
    }
    if (params.hashPQChainLockAnchorBlock.IsNull() ||
        CheckPQLegacyAnchorConfiguration(params) !=
            PQAnchorResult::VALID ||
        params.nPQChainLockAnchorHeight < params.nPQLegacyAnchorHeight ||
        (params.nPQChainLockAnchorHeight == params.nPQLegacyAnchorHeight &&
         params.hashPQChainLockAnchorBlock !=
             params.hashPQLegacyAnchorBlock)) {
        return PQAnchorResult::INVALID_CONFIGURATION;
    }
    return PQAnchorResult::VALID;
}

} // namespace Consensus

#endif // SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
