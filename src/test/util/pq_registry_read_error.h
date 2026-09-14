// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_UTIL_PQ_REGISTRY_READ_ERROR_H
#define SYSCOIN_TEST_UTIL_PQ_REGISTRY_READ_ERROR_H

#include <evo/deterministicmns.h>

#include <boost/test/unit_test.hpp>

#include <exception>
#include <string>

namespace llmq::pq::test {

class PQRegistryReadErrorTestAccess {
public:
    // Remove one real disk record without changing readiness or the branch.
    // Clearing the read-view cache makes the next lookup return unavailable
    // through the normal missing-snapshot path, without throwing.
    class ScopedMissingSnapshot {
        PQRegistryManager* m_registry;
        PQRegistryDiskSnapshot m_snapshot;
        bool m_missing{false};

    public:
        ScopedMissingSnapshot(CDeterministicMNManager& manager,
                              const uint256& block_hash,
                              bool defer_removal = false)
        {
            std::string error;
            m_registry = manager.GetOrCreatePQRegistry(error);
            BOOST_REQUIRE_MESSAGE(m_registry != nullptr, error);
            {
                LOCK(m_registry->m_mutex);
                BOOST_REQUIRE(m_registry->m_snapshot_db->ReadCache(
                    block_hash, m_snapshot));
            }
            if (!defer_removal) Remove();
        }

        // Silent mutation for a synchronous test callback after an earlier
        // successful verification. Snapshot acquisition stays outside it.
        void Remove()
        {
            if (m_missing) return;
            LOCK(m_registry->m_mutex);
            m_registry->m_snapshot_cache.clear();
            m_registry->m_snapshot_cache_index.clear();
            m_registry->m_snapshot_db->EraseCache(m_snapshot.block_hash);
            m_missing = true;
        }

        ScopedMissingSnapshot(const ScopedMissingSnapshot&) = delete;
        ScopedMissingSnapshot& operator=(const ScopedMissingSnapshot&) = delete;

        bool Restore()
        {
            if (!m_missing) return true;
            if (!m_registry->WriteExactSnapshotForTesting(
                    m_snapshot.block_hash, m_snapshot)) return false;
            m_missing = false;
            return true;
        }

        ~ScopedMissingSnapshot()
        {
            try {
                BOOST_CHECK_MESSAGE(Restore(),
                    "failed to restore temporarily missing PQ registry snapshot");
            } catch (const std::exception& error) {
                BOOST_ERROR("restoring PQ registry snapshot: " << error.what());
            }
        }
    };

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
