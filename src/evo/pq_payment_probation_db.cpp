// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation_db.h>

#include <logging.h>
#include <util/fs.h>

#include <algorithm>
#include <ios>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace llmq::pq {
namespace {

constexpr uint32_t PAYMENT_PROBATION_GC_VERSION{1};
constexpr uint32_t PAYMENT_PROBATION_GC_GUARD{0x50504731}; // "PPG1"

const uint256& PaymentProbationGCKey()
{
    // State keys are hashes. Reserve the all-ones value for metadata and
    // reject the cryptographically-improbable collision at state admission.
    static const uint256 key{[] {
        uint256 value;
        std::fill(value.begin(), value.end(), 0xff);
        return value;
    }()};
    return key;
}

struct PaymentProbationGCRecord {
    static constexpr std::size_t WIRE_SIZE{
        5 * sizeof(uint32_t) + 5 * 32 +
        PaymentAuditReceiptState::WIRE_SIZE};

    uint32_t version{PAYMENT_PROBATION_GC_VERSION};
    PaymentAuditStoreCheckpoint checkpoint;
    uint32_t guard{PAYMENT_PROBATION_GC_GUARD};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(
            stream, version, checkpoint.prune_through_epoch,
            checkpoint.covered_through_height,
            checkpoint.covered_through_hash,
            checkpoint.authenticated_receipt_state,
            checkpoint.authenticated_probation_state_hash,
            checkpoint.authorizing_target_height,
            checkpoint.authorizing_target_hash,
            checkpoint.authorizing_chainlock_logical_id,
            checkpoint.authorizing_chainlock_witness_id, guard);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure{
                "invalid payment probation GC marker size"};
        }
        ::UnserializeMany(
            stream, version, checkpoint.prune_through_epoch,
            checkpoint.covered_through_height,
            checkpoint.covered_through_hash,
            checkpoint.authenticated_receipt_state,
            checkpoint.authenticated_probation_state_hash,
            checkpoint.authorizing_target_height,
            checkpoint.authorizing_target_hash,
            checkpoint.authorizing_chainlock_logical_id,
            checkpoint.authorizing_chainlock_witness_id, guard);
    }
};

static_assert(PaymentProbationGCRecord::WIRE_SIZE == 316);

bool IsGCRecordValid(const PaymentProbationGCRecord& record)
{
    return record.version == PAYMENT_PROBATION_GC_VERSION &&
           record.guard == PAYMENT_PROBATION_GC_GUARD &&
           record.checkpoint.IsStructurallyValid();
}

bool HasSameGCBoundary(const PaymentAuditStoreCheckpoint& left,
                       const PaymentAuditStoreCheckpoint& right)
{
    return left.IsStructurallyValid() && right.IsStructurallyValid() &&
           left.prune_through_epoch == right.prune_through_epoch &&
           left.covered_through_height == right.covered_through_height &&
           left.covered_through_hash == right.covered_through_hash &&
           left.authenticated_receipt_state ==
               right.authenticated_receipt_state &&
           left.authenticated_probation_state_hash ==
               right.authenticated_probation_state_hash;
}

enum class GCRecordStatus : uint8_t {
    ABSENT,
    VALID,
    CORRUPT,
};

GCRecordStatus ReadGCRecord(
    const CEvoDB<uint256, PQPaymentProbationState, StaticSaltedHasher>& db,
    PaymentProbationGCRecord& record)
{
    if (!db.Exists(PaymentProbationGCKey())) {
        return GCRecordStatus::ABSENT;
    }
    if (!db.Read(PaymentProbationGCKey(), record) ||
        !IsGCRecordValid(record)) {
        return GCRecordStatus::CORRUPT;
    }
    return GCRecordStatus::VALID;
}

DBParams PaymentProbationDBParams(DBParams params)
{
    if (params.path.empty()) {
        params.path = "evodb_pq_payment_probation";
    } else {
        const std::string sibling_name{
            fs::PathToString(params.path.filename()) +
            "_pq_payment_probation"};
        params.path = params.path.parent_path() / sibling_name;
    }
    params.cache_bytes = std::max<std::size_t>(1, params.cache_bytes / 4);
    return params;
}

struct ExactPaymentProbationStateKey {
    uint256 hash;

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> hash;
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing payment probation state key bytes"};
        }
    }
};

struct ExactPaymentProbationStateValue {
    PQPaymentProbationState state;

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> state;
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing payment probation state value bytes"};
        }
    }
};

} // namespace

PQPaymentProbationManager::PQPaymentProbationManager(
    const DBParams& db_params)
    : m_state_db(std::make_unique<CEvoDB<
          uint256, PQPaymentProbationState, StaticSaltedHasher>>(
          PaymentProbationDBParams(db_params),
          /*maxCacheSizeIn=*/0,
          /*maxReadCacheSizeIn=*/64))
{
    const auto empty_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_hash) {
        throw std::runtime_error{
            "failed to derive empty payment probation state"};
    }
    m_empty_state_hash = *empty_hash;
    if (m_empty_state_hash == PaymentProbationGCKey()) {
        throw std::runtime_error{
            "payment probation empty-state hash collides with metadata key"};
    }
}

bool PQPaymentProbationManager::GetState(
    const uint256& state_hash,
    PQPaymentProbationState& state) const
{
    LOCK(m_mutex);
    if (state_hash.IsNull() || state_hash == PaymentProbationGCKey()) {
        return false;
    }
    if (state_hash == m_empty_state_hash) {
        state = PQPaymentProbationState{};
        return true;
    }
    if (!m_state_db->ReadCache(state_hash, state) ||
        !state.IsStructurallyValid()) {
        return false;
    }
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    return actual_hash && *actual_hash == state_hash;
}

bool PQPaymentProbationManager::CommitState(
    const PQPaymentProbationState& state,
    const uint256& expected_hash,
    bool fJustCheck)
{
    LOCK(m_mutex);
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    if (!actual_hash || *actual_hash != expected_hash ||
        expected_hash == PaymentProbationGCKey()) {
        return false;
    }
    if (expected_hash == m_empty_state_hash || fJustCheck) return true;

    PQPaymentProbationState existing;
    if (m_state_db->ReadCache(expected_hash, existing)) {
        return existing == state;
    }
    return m_state_db->WriteThrough(expected_hash, state, /*fSync=*/false);
}

bool PQPaymentProbationManager::Flush(bool fSync)
{
    LOCK(m_mutex);
    return m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256, fSync);
}

bool PQPaymentProbationManager::IsGCCompleteForCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint) const
{
    LOCK(m_mutex);
    if (!checkpoint.IsStructurallyValid()) return false;
    try {
        PaymentProbationGCRecord record;
        return ReadGCRecord(*m_state_db, record) == GCRecordStatus::VALID &&
               HasSameGCBoundary(record.checkpoint, checkpoint);
    } catch (const std::exception& exception) {
        LogPrintf("%s -- unable to read payment probation GC marker: %s\n",
                  __func__, exception.what());
        return false;
    }
}

bool PQPaymentProbationManager::PruneStatesThroughCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes)
{
    LOCK(m_mutex);
    if (!checkpoint.IsStructurallyValid()) return false;

    PaymentProbationGCRecord previous_gc;
    const auto previous_gc_status{ReadGCRecord(*m_state_db, previous_gc)};
    if (previous_gc_status == GCRecordStatus::CORRUPT) {
        LogPrintf("%s -- corrupt payment probation GC marker\n", __func__);
        return false;
    }
    if (previous_gc_status == GCRecordStatus::VALID) {
        if (HasSameGCBoundary(previous_gc.checkpoint, checkpoint)) {
            return true;
        }
        if (checkpoint.prune_through_epoch <=
            previous_gc.checkpoint.prune_through_epoch) {
            LogPrintf("%s -- refusing non-monotonic payment probation GC "
                      "checkpoint\n",
                      __func__);
            return false;
        }
    }

    std::unordered_set<uint256, StaticSaltedHasher> retained;
    retained.reserve(retained_state_hashes.size() + 1);
    retained.insert(m_empty_state_hash);
    for (const uint256& state_hash : retained_state_hashes) {
        if (state_hash.IsNull()) {
            LogPrintf("%s -- refusing null retained payment probation "
                      "state hash\n",
                      __func__);
            return false;
        }
        retained.insert(state_hash);
    }

    // Publish every earlier state write before taking the iterator snapshot.
    // This is also the ordering barrier between the durable audit checkpoint
    // and the tombstones below.
    if (!m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256,
                                      /*fSync=*/true)) {
        return false;
    }

    std::unordered_set<uint256, StaticSaltedHasher> unresolved_retained{
        retained};
    unresolved_retained.erase(m_empty_state_hash);
    std::vector<uint256> prune_keys;
    bool found_gc_record{false};
    std::unique_ptr<CDBIterator> cursor{m_state_db->NewIterator()};
    if (!cursor) {
        LogPrintf("%s -- failed to create payment probation state iterator\n",
                  __func__);
        return false;
    }

    for (cursor->SeekToFirst(); cursor->Valid(); cursor->Next()) {
        ExactPaymentProbationStateKey decoded_key;
        if (!cursor->GetKey(decoded_key) || decoded_key.hash.IsNull()) {
            LogPrintf("%s -- invalid persisted payment probation state "
                      "key\n",
                      __func__);
            return false;
        }
        if (decoded_key.hash == PaymentProbationGCKey()) {
            PaymentProbationGCRecord record;
            if (found_gc_record || !cursor->GetValue(record) ||
                !IsGCRecordValid(record) ||
                previous_gc_status != GCRecordStatus::VALID ||
                record.checkpoint != previous_gc.checkpoint) {
                LogPrintf("%s -- invalid persisted payment probation GC "
                          "marker\n",
                          __func__);
                return false;
            }
            found_gc_record = true;
            continue;
        }

        ExactPaymentProbationStateValue decoded_value;
        if (!cursor->GetValue(decoded_value) ||
            !decoded_value.state.IsStructurallyValid()) {
            LogPrintf("%s -- invalid persisted payment probation state "
                      "record\n",
                      __func__);
            return false;
        }

        const auto actual_hash{
            GetPQPaymentProbationStateHash(decoded_value.state)};
        if (!actual_hash || *actual_hash != decoded_key.hash ||
            (decoded_key.hash == m_empty_state_hash &&
             decoded_value.state != PQPaymentProbationState{})) {
            LogPrintf("%s -- payment probation state hash mismatch for %s\n",
                      __func__, decoded_key.hash.ToString());
            return false;
        }

        unresolved_retained.erase(decoded_key.hash);
        if (retained.count(decoded_key.hash) != 0 ||
            decoded_value.state.cursor.has_receipt == 0 ||
            decoded_value.state.cursor.receipt.epoch >
                checkpoint.prune_through_epoch) {
            continue;
        }
        prune_keys.emplace_back(decoded_key.hash);
    }

    if (found_gc_record !=
        (previous_gc_status == GCRecordStatus::VALID)) {
        LogPrintf("%s -- payment probation GC marker iterator mismatch\n",
                  __func__);
        return false;
    }
    if (!unresolved_retained.empty()) {
        LogPrintf("%s -- retained payment probation state %s is missing\n",
                  __func__, unresolved_retained.begin()->ToString());
        return false;
    }

    for (const uint256& state_hash : prune_keys) {
        // EraseCache removes both dirty and read-cache copies before staging a
        // tombstone, so a later lookup cannot resurrect the deleted state.
        m_state_db->EraseCache(state_hash);
    }
    if (!m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256,
                                      /*fSync=*/true)) {
        return false;
    }

    // The marker follows durable tombstones. A crash between the two writes
    // repeats an idempotent repair pass; once this marker is durable the
    // scheduler can skip every fsync for the unchanged checkpoint.
    if (!m_state_db->Write(
            PaymentProbationGCKey(),
            PaymentProbationGCRecord{
                PAYMENT_PROBATION_GC_VERSION, checkpoint,
                PAYMENT_PROBATION_GC_GUARD},
            /*fSync=*/true)) {
        return false;
    }

    LogPrint(BCLog::SYS,
             "%s -- pruned %zu payment probation states through epoch %u; "
             "retained=%zu\n",
             __func__, prune_keys.size(), checkpoint.prune_through_epoch,
             retained.size());
    return true;
}

} // namespace llmq::pq
