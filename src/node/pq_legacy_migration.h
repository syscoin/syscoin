// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_PQ_LEGACY_MIGRATION_H
#define SYSCOIN_NODE_PQ_LEGACY_MIGRATION_H

#include <sync.h>
#include <threadsafety.h>

class ChainstateManager;
struct bilingual_str;
extern RecursiveMutex cs_main;

namespace node {
struct CacheSizes;
struct ChainstateLoadOptions;

/**
 * Inspect legacy provenance and persist a paired-rebuild intent before any
 * chainstate or auxiliary database is opened for normal startup or wiped.
 * All previous handles to those on-disk databases must already be closed.
 */
[[nodiscard]] bool PreparePQLegacyUpgrade(
    ChainstateManager& chainman,
    ChainstateLoadOptions& options,
    const CacheSizes& cache_sizes,
    bilingual_str& error) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
} // namespace node

#endif // SYSCOIN_NODE_PQ_LEGACY_MIGRATION_H
