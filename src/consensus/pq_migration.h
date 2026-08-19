// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PQ_MIGRATION_H
#define SYSCOIN_CONSENSUS_PQ_MIGRATION_H

#include <chain.h>
#include <consensus/pq_migration_config.h>

namespace Consensus {

inline PQAnchorResult CheckPQImmutableBlockAnchor(
    PQAnchorResult configuration,
    int anchor_height,
    const uint256& anchor_hash,
    int height,
    const uint256& block_hash,
    const CBlockIndex* previous,
    const CBlockIndex* known_anchor)
{
    if (configuration != PQAnchorResult::VALID) return configuration;

    if (height < anchor_height) {
        // Before the anchor is known, genesis replay must be able to discover
        // it normally. Once known, its exact prefix is immutable too.
        if (known_anchor == nullptr) return PQAnchorResult::VALID;
        if (known_anchor->nHeight != anchor_height ||
            known_anchor->GetBlockHash() != anchor_hash) {
            return PQAnchorResult::ANCESTOR_HASH_MISMATCH;
        }
        const CBlockIndex* expected = known_anchor->GetAncestor(height);
        return expected != nullptr && expected->GetBlockHash() == block_hash
            ? PQAnchorResult::VALID
            : PQAnchorResult::ANCESTOR_HASH_MISMATCH;
    }
    if (height == anchor_height) {
        return block_hash == anchor_hash
            ? PQAnchorResult::VALID
            : PQAnchorResult::BLOCK_HASH_MISMATCH;
    }

    if (previous == nullptr) return PQAnchorResult::MISSING_ANCESTOR;
    const CBlockIndex* anchor = previous->GetAncestor(anchor_height);
    if (anchor == nullptr) return PQAnchorResult::MISSING_ANCESTOR;
    return anchor->GetBlockHash() == anchor_hash
        ? PQAnchorResult::VALID
        : PQAnchorResult::ANCESTOR_HASH_MISMATCH;
}

/**
 * Enforce the immutable block boundary below which BLS verification is
 * replaced by byte-exact replay. This is intentionally independent of the
 * user-configurable checkpoint mechanism.
 */
inline PQAnchorResult CheckPQLegacyAnchor(
    const Params& params,
    int height,
    const uint256& block_hash,
    const CBlockIndex* previous,
    const CBlockIndex* known_anchor = nullptr)
{
    return CheckPQImmutableBlockAnchor(
        CheckPQLegacyAnchorConfiguration(params),
        params.nPQLegacyAnchorHeight, params.hashPQLegacyAnchorBlock,
        height, block_hash, previous, known_anchor);
}

inline bool IsPQLegacyAnchorCompatible(
    const Params& params,
    const CBlockIndex* index,
    const CBlockIndex* known_anchor = nullptr)
{
    if (index == nullptr) return false;
    const auto result = CheckPQLegacyAnchor(
        params, index->nHeight, index->GetBlockHash(), index->pprev, known_anchor);
    return result == PQAnchorResult::DISABLED ||
           result == PQAnchorResult::VALID;
}

inline PQAnchorResult CheckPQChainLockAnchor(
    const Params& params,
    int height,
    const uint256& block_hash,
    const CBlockIndex* previous,
    const CBlockIndex* known_anchor = nullptr)
{
    return CheckPQImmutableBlockAnchor(
        CheckPQChainLockAnchorConfiguration(params),
        params.nPQChainLockAnchorHeight, params.hashPQChainLockAnchorBlock,
        height, block_hash, previous, known_anchor);
}

inline bool IsPQChainLockAnchorCompatible(
    const Params& params,
    const CBlockIndex* index,
    const CBlockIndex* known_anchor = nullptr)
{
    if (index == nullptr) return false;
    const auto result = CheckPQChainLockAnchor(
        params, index->nHeight, index->GetBlockHash(), index->pprev,
        known_anchor);
    return result == PQAnchorResult::DISABLED ||
           result == PQAnchorResult::VALID;
}

inline bool ArePQAnchorsCompatible(
    const Params& params,
    const CBlockIndex* index,
    const CBlockIndex* known_legacy_anchor = nullptr,
    const CBlockIndex* known_chainlock_anchor = nullptr)
{
    return IsPQLegacyAnchorCompatible(params, index, known_legacy_anchor) &&
           IsPQChainLockAnchorCompatible(params, index,
                                         known_chainlock_anchor);
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
