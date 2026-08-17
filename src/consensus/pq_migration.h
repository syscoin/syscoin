// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PQ_MIGRATION_H
#define SYSCOIN_CONSENSUS_PQ_MIGRATION_H

#include <chain.h>
#include <consensus/pq_migration_config.h>

namespace Consensus {

/**
 * Enforce the immutable block boundary below which BLS verification is
 * replaced by byte-exact replay. This is intentionally independent of the
 * user-configurable checkpoint mechanism.
 */
inline PQLegacyAnchorResult CheckPQLegacyAnchor(
    const Params& params,
    int height,
    const uint256& block_hash,
    const CBlockIndex* previous,
    const CBlockIndex* known_anchor = nullptr)
{
    const auto configuration = CheckPQLegacyAnchorConfiguration(params);
    if (configuration != PQLegacyAnchorResult::VALID) return configuration;

    if (height < params.nPQLegacyAnchorHeight) {
        // Before the anchor is known, genesis replay must be able to discover
        // it normally. Once known, however, the prefix is immutable too: a
        // higher-work fork ending at H-1 must not disconnect across H.
        if (known_anchor == nullptr) return PQLegacyAnchorResult::VALID;
        if (known_anchor->nHeight != params.nPQLegacyAnchorHeight ||
            known_anchor->GetBlockHash() != params.hashPQLegacyAnchorBlock) {
            return PQLegacyAnchorResult::ANCESTOR_HASH_MISMATCH;
        }
        const CBlockIndex* expected = known_anchor->GetAncestor(height);
        return expected != nullptr && expected->GetBlockHash() == block_hash
            ? PQLegacyAnchorResult::VALID
            : PQLegacyAnchorResult::ANCESTOR_HASH_MISMATCH;
    }
    if (height == params.nPQLegacyAnchorHeight) {
        return block_hash == params.hashPQLegacyAnchorBlock
            ? PQLegacyAnchorResult::VALID
            : PQLegacyAnchorResult::BLOCK_HASH_MISMATCH;
    }

    if (previous == nullptr) return PQLegacyAnchorResult::MISSING_ANCESTOR;
    const CBlockIndex* anchor = previous->GetAncestor(params.nPQLegacyAnchorHeight);
    if (anchor == nullptr) return PQLegacyAnchorResult::MISSING_ANCESTOR;
    return anchor->GetBlockHash() == params.hashPQLegacyAnchorBlock
        ? PQLegacyAnchorResult::VALID
        : PQLegacyAnchorResult::ANCESTOR_HASH_MISMATCH;
}

inline bool IsPQLegacyAnchorCompatible(
    const Params& params,
    const CBlockIndex* index,
    const CBlockIndex* known_anchor = nullptr)
{
    if (index == nullptr) return false;
    const auto result = CheckPQLegacyAnchor(
        params, index->nHeight, index->GetBlockHash(), index->pprev, known_anchor);
    return result == PQLegacyAnchorResult::DISABLED ||
           result == PQLegacyAnchorResult::VALID;
}

inline bool CheckPQLegacyMNState(
    const Params& params,
    int height,
    const uint256& state_hash)
{
    if (height != params.nPQLegacyAnchorHeight) return true;
    return !params.hashPQLegacyMNState.IsNull() && state_hash == params.hashPQLegacyMNState;
}

inline bool CheckPQLegacyState(
    const Params& params,
    int height,
    const uint256& mn_state_hash,
    const uint256& pq_registry_state_hash)
{
    if (height != params.nPQLegacyAnchorHeight) return true;
    return CheckPQLegacyMNState(params, height, mn_state_hash) &&
           !params.hashPQLegacyPQRegistryState.IsNull() &&
           pq_registry_state_hash == params.hashPQLegacyPQRegistryState;
}

} // namespace Consensus

#endif // SYSCOIN_CONSENSUS_PQ_MIGRATION_H
