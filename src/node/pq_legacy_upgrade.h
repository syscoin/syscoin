// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_PQ_LEGACY_UPGRADE_H
#define SYSCOIN_NODE_PQ_LEGACY_UPGRADE_H

#include <dbwrapper.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <ios>
#include <optional>

namespace node {

enum class PQLegacyUpgradePhase : uint8_t {
    REBUILD_REQUIRED = 1,
    REPLAY_READY = 2,
};

/** Legacy validation provenance captured before rebuilding Core and Geth. */
struct PQLegacyUpgradeRecord {
    static constexpr uint8_t VERSION{1};

    uint8_t version{VERSION};
    uint256 genesis_hash;
    int32_t activation_height{-1};
    int32_t legacy_tip_height{-1};
    uint256 legacy_tip_hash;
    uint256 predecessor_hash;
    PQLegacyUpgradePhase phase{PQLegacyUpgradePhase::REBUILD_REQUIRED};

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(PQLegacyUpgradeRecord, obj)
    {
        SER_WRITE(obj, if (!obj.IsValid()) {
            throw std::ios_base::failure("invalid PQ legacy upgrade record");
        });
        uint8_t phase{static_cast<uint8_t>(obj.phase)};
        READWRITE(obj.version, obj.genesis_hash, obj.activation_height,
                  obj.legacy_tip_height, obj.legacy_tip_hash,
                  obj.predecessor_hash, phase);
        SER_READ(obj, {
            obj.phase = static_cast<PQLegacyUpgradePhase>(phase);
            if (!obj.IsValid()) {
                throw std::ios_base::failure("invalid PQ legacy upgrade record");
            }
        });
    }

    friend bool operator==(const PQLegacyUpgradeRecord&,
                           const PQLegacyUpgradeRecord&) = default;
};

/**
 * Kept in the separate pq-upgrade database, never wiped by chainstate reindex.
 * Every mutation is synchronous. Corrupt present records and database read
 * errors throw; rejected transitions or unsuccessful writes return false.
 */
class PQLegacyUpgradeJournal {
    mutable Mutex m_mutex;
    // CDBWrapper's iterator factory is not const; journal reads do not mutate it.
    mutable CDBWrapper m_db;

    [[nodiscard]] std::optional<PQLegacyUpgradeRecord> ReadUpgradeLocked() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool HasBLSFreeHistoryLocked() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

protected:
    virtual bool WriteBatch(CDBBatch& batch, bool sync);

public:
    explicit PQLegacyUpgradeJournal(const DBParams& params);
    virtual ~PQLegacyUpgradeJournal() = default;

    [[nodiscard]] std::optional<PQLegacyUpgradeRecord> ReadUpgrade() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool HasBLSFreeHistory() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool MarkBLSFreeHistory() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool CaptureLegacyUpgrade(const PQLegacyUpgradeRecord& record)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool MarkReplayReady() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Preserve captured provenance across another explicit paired rebuild. */
    [[nodiscard]] bool RequireReplayRebuild() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace node

#endif // SYSCOIN_NODE_PQ_LEGACY_UPGRADE_H
