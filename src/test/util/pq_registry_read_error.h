// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_UTIL_PQ_REGISTRY_READ_ERROR_H
#define SYSCOIN_TEST_UTIL_PQ_REGISTRY_READ_ERROR_H

#include <evo/deterministicmns.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace llmq::pq::test {

class PQRegistryReadErrorTestAccess {
public:
    static void FailNextRead(CDeterministicMNManager& manager)
    {
        std::string error;
        auto* registry = manager.GetOrCreatePQRegistry(error);
        BOOST_REQUIRE_MESSAGE(registry != nullptr, error);
        LOCK(registry->m_mutex);
        registry->m_snapshot_cache.clear();
        registry->m_snapshot_cache_index.clear();
        // ReadCache flushes this unrelated tombstone before returning the
        // parent. Use the existing one-shot database exception seam.
        registry->m_snapshot_db->EraseCache(uint256{});
        registry->m_snapshot_db->FailNextFlushBatchForTesting();
    }
};

} // namespace llmq::pq::test

#endif // SYSCOIN_TEST_UTIL_PQ_REGISTRY_READ_ERROR_H
