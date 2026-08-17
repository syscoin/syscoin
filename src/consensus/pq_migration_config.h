// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
#define SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H

#include <consensus/params.h>

#include <limits>

namespace Consensus {

enum class PQLegacyAnchorResult {
    DISABLED,
    VALID,
    INVALID_CONFIGURATION,
    BLOCK_HASH_MISMATCH,
    MISSING_ANCESTOR,
    ANCESTOR_HASH_MISMATCH,
};

// SYSCOIN: Configuration validation is chain-independent so parameter
// construction cannot import branch-navigation dependencies.
inline PQLegacyAnchorResult CheckPQLegacyAnchorConfiguration(
    const Params& params)
{
    const bool disabled_height{
        params.nPQLegacyAnchorHeight == std::numeric_limits<int>::max()};
    const bool null_hashes{params.hashPQLegacyAnchorBlock.IsNull() &&
                           params.hashPQLegacyMNState.IsNull() &&
                           params.hashPQLegacyPQRegistryState.IsNull()};
    if (disabled_height) {
        return null_hashes ? PQLegacyAnchorResult::DISABLED
                           : PQLegacyAnchorResult::INVALID_CONFIGURATION;
    }
    if (params.hashPQLegacyAnchorBlock.IsNull() ||
        params.hashPQLegacyMNState.IsNull() ||
        params.hashPQLegacyPQRegistryState.IsNull()) {
        return PQLegacyAnchorResult::INVALID_CONFIGURATION;
    }
    if (params.nPQLegacyAnchorHeight < params.DIP0003Height) {
        return PQLegacyAnchorResult::INVALID_CONFIGURATION;
    }
    return PQLegacyAnchorResult::VALID;
}

} // namespace Consensus

#endif // SYSCOIN_CONSENSUS_PQ_MIGRATION_CONFIG_H
