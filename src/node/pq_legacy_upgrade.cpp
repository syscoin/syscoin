// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_upgrade.h>

#include <cstddef>
#include <limits>
#include <memory>

namespace node {
namespace {
constexpr uint8_t DB_UPGRADE{'u'};
constexpr uint8_t DB_BLS_FREE_HISTORY{'o'};
constexpr uint8_t BLS_FREE_HISTORY_VERSION{1};
constexpr std::size_t UPGRADE_RECORD_SIZE{
    2 * sizeof(uint8_t) + 2 * sizeof(int32_t) + 3 * uint256::size()};

template <typename Value>
bool ReadExact(CDBWrapper& db, uint8_t key, Value& value,
               std::size_t expected_size)
{
    std::unique_ptr<CDBIterator> cursor{db.NewIterator()};
    cursor->Seek(key);
    cursor->CheckStatus();
    uint8_t stored_key{0};
    if (!cursor->Valid() || !cursor->GetKey(stored_key) || stored_key != key) {
        return false;
    }
    if (!cursor->GetKeyExact(stored_key) ||
        cursor->GetValueSize() != expected_size ||
        !cursor->GetValueExact(value)) {
        throw dbwrapper_error("Invalid PQ legacy upgrade journal record");
    }
    return true;
}
} // namespace

bool PQLegacyUpgradeRecord::IsValid() const noexcept
{
    return version == VERSION && !genesis_hash.IsNull() &&
           activation_height > 0 &&
           activation_height != std::numeric_limits<int32_t>::max() &&
           legacy_tip_height >= activation_height - 1 &&
           !legacy_tip_hash.IsNull() && !predecessor_hash.IsNull() &&
           (legacy_tip_height != activation_height - 1 ||
            legacy_tip_hash == predecessor_hash) &&
           (phase == PQLegacyUpgradePhase::REBUILD_REQUIRED ||
            phase == PQLegacyUpgradePhase::REPLAY_READY);
}

PQLegacyUpgradeJournal::PQLegacyUpgradeJournal(const DBParams& params)
    : m_db(params)
{
    LOCK(m_mutex);
    // Validate both independent records before any startup mutation.
    (void)ReadUpgradeLocked();
    (void)HasBLSFreeHistoryLocked();
}

std::optional<PQLegacyUpgradeRecord>
PQLegacyUpgradeJournal::ReadUpgradeLocked() const
{
    AssertLockHeld(m_mutex);
    PQLegacyUpgradeRecord record;
    if (!ReadExact(m_db, DB_UPGRADE, record, UPGRADE_RECORD_SIZE)) {
        return std::nullopt;
    }
    return record;
}

bool PQLegacyUpgradeJournal::HasBLSFreeHistoryLocked() const
{
    AssertLockHeld(m_mutex);
    uint8_t version{0};
    if (!ReadExact(m_db, DB_BLS_FREE_HISTORY, version, sizeof(version))) {
        return false;
    }
    if (version != BLS_FREE_HISTORY_VERSION) {
        throw dbwrapper_error("Invalid PQ BLS-free history origin marker");
    }
    return true;
}

std::optional<PQLegacyUpgradeRecord>
PQLegacyUpgradeJournal::ReadUpgrade() const
{
    LOCK(m_mutex);
    return ReadUpgradeLocked();
}

bool PQLegacyUpgradeJournal::HasBLSFreeHistory() const
{
    LOCK(m_mutex);
    return HasBLSFreeHistoryLocked();
}

bool PQLegacyUpgradeJournal::WriteBatch(CDBBatch& batch, bool sync)
{
    return m_db.WriteBatch(batch, sync);
}

bool PQLegacyUpgradeJournal::MarkBLSFreeHistory()
{
    LOCK(m_mutex);
    (void)ReadUpgradeLocked();
    if (HasBLSFreeHistoryLocked()) return true;
    CDBBatch batch{m_db};
    batch.Write(DB_BLS_FREE_HISTORY, BLS_FREE_HISTORY_VERSION);
    return WriteBatch(batch, /*sync=*/true);
}

bool PQLegacyUpgradeJournal::CaptureLegacyUpgrade(
    const PQLegacyUpgradeRecord& record)
{
    LOCK(m_mutex);
    const auto existing{ReadUpgradeLocked()};
    const bool has_bls_free_history{HasBLSFreeHistoryLocked()};
    if (!record.IsValid() ||
        record.phase != PQLegacyUpgradePhase::REBUILD_REQUIRED) {
        return false;
    }
    // A retry may observe an origin marker written after the original capture.
    // Only that identical existing anchor may survive this exception.
    if (existing) return *existing == record;
    if (has_bls_free_history) return false;
    CDBBatch batch{m_db};
    batch.Write(DB_UPGRADE, record);
    return WriteBatch(batch, /*sync=*/true);
}

bool PQLegacyUpgradeJournal::MarkReplayReady()
{
    LOCK(m_mutex);
    auto record{ReadUpgradeLocked()};
    (void)HasBLSFreeHistoryLocked();
    if (!record) return false;
    if (record->phase == PQLegacyUpgradePhase::REPLAY_READY) return true;
    record->phase = PQLegacyUpgradePhase::REPLAY_READY;
    CDBBatch batch{m_db};
    batch.Write(DB_UPGRADE, *record);
    return WriteBatch(batch, /*sync=*/true);
}

bool PQLegacyUpgradeJournal::RequireReplayRebuild()
{
    LOCK(m_mutex);
    auto record{ReadUpgradeLocked()};
    (void)HasBLSFreeHistoryLocked();
    if (!record) return false;
    if (record->phase == PQLegacyUpgradePhase::REBUILD_REQUIRED) return true;
    record->phase = PQLegacyUpgradePhase::REBUILD_REQUIRED;
    CDBBatch batch{m_db};
    batch.Write(DB_UPGRADE, *record);
    return WriteBatch(batch, /*sync=*/true);
}

} // namespace node
