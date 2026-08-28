// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_store.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <vector>

namespace llmq::pq {
namespace {

constexpr uint8_t DB_SCHEMA_KEY{0xa0};
constexpr uint8_t DB_WITNESS_PREFIX{0xa1};
constexpr uint8_t DB_EPOCH_PREFIX{0xa2};
constexpr uint8_t DB_REFERENCE_PREFIX{0xa3};
constexpr uint8_t DB_PRESENCE_PREFIX{0xa4};
constexpr uint8_t DB_CHECKPOINT_KEY{0xa5};
constexpr uint8_t DB_PRUNE_INTENT_KEY{0xa6};
// Changing the archive layout must fail closed against an old local DB.
constexpr uint32_t SCHEMA_GUARD{0x50414131}; // "PAA1"
constexpr uint32_t WITNESS_GUARD{0x50575231}; // "PWR1"
constexpr uint32_t EPOCH_GUARD{0x50455231}; // "PER1"
constexpr uint32_t REFERENCE_GUARD{0x50524631}; // "PRF1"
constexpr uint32_t PRESENCE_GUARD{0x50525031}; // "PRP1"
constexpr uint32_t CHECKPOINT_GUARD{0x50414331}; // "PAC1"
constexpr uint32_t PRUNE_INTENT_GUARD{0x50414931}; // "PAI1"

struct CorruptArchiveIndex {};

struct SchemaValue {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint32_t guard{SCHEMA_GUARD};
    uint256 genesis_hash;
    uint16_t audit_version{PAYMENT_AUDIT_VERSION};
    uint16_t receipt_version{PAYMENT_AUDIT_RECEIPT_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    uint16_t child_usage_cap{SCHEDULED_WOTS_USAGE_CAP};
    uint32_t child_signature_size{CHILD_SIGNATURE_SIZE};
    uint32_t final_audit_wire_size{FinalPaymentAudit::WIRE_SIZE};

    SERIALIZE_METHODS(SchemaValue, obj)
    {
        READWRITE(obj.version, obj.guard, obj.genesis_hash,
                  obj.audit_version, obj.receipt_version,
                  obj.child_profile, obj.child_usage_cap,
                  obj.child_signature_size, obj.final_audit_wire_size);
    }

    friend bool operator==(const SchemaValue&,
                           const SchemaValue&) = default;
};

SchemaValue MakeSchemaValue(const uint256& genesis_hash)
{
    return SchemaValue{
        PaymentAuditStore::DB_FORMAT_VERSION,
        SCHEMA_GUARD,
        genesis_hash,
        PAYMENT_AUDIT_VERSION,
        PAYMENT_AUDIT_RECEIPT_VERSION,
        CHILD_SCHEDULED_WOTS_SHAKE_128_V1,
        SCHEDULED_WOTS_USAGE_CAP,
        CHILD_SIGNATURE_SIZE,
        FinalPaymentAudit::WIRE_SIZE};
}

struct WitnessKey {
    uint8_t prefix{DB_WITNESS_PREFIX};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 witness_id;

    SERIALIZE_METHODS(WitnessKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash,
                  obj.witness_id);
    }

    friend bool operator==(const WitnessKey&, const WitnessKey&) = default;
};

struct EpochKey {
    uint8_t prefix{DB_EPOCH_PREFIX};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint32_t epoch{0};

    SERIALIZE_METHODS(EpochKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash, obj.epoch);
    }

    friend bool operator==(const EpochKey&, const EpochKey&) = default;
};

struct ReferenceKey {
    uint8_t prefix{DB_REFERENCE_PREFIX};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 witness_id;

    SERIALIZE_METHODS(ReferenceKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash,
                  obj.witness_id);
    }

    friend bool operator==(const ReferenceKey&,
                           const ReferenceKey&) = default;
};

struct PresenceKey {
    uint8_t prefix{DB_PRESENCE_PREFIX};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 witness_id;

    SERIALIZE_METHODS(PresenceKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash,
                  obj.witness_id);
    }

    friend bool operator==(const PresenceKey&, const PresenceKey&) = default;
};

struct AuditRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 logical_id;
    uint256 witness_id;
    FinalPaymentAudit audit;
    uint32_t guard{WITNESS_GUARD};

    SERIALIZE_METHODS(AuditRecord, obj)
    {
        READWRITE(obj.version, obj.logical_id, obj.witness_id, obj.audit,
                  obj.guard);
    }
};

struct EpochRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint32_t epoch{0};
    uint256 pinned_witness_id;
    std::array<uint256, PaymentAuditStore::MAX_LIVE_CANDIDATES>
        live_candidates_by_missing_quorum{};
    uint32_t guard{EPOCH_GUARD};

    SERIALIZE_METHODS(EpochRecord, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.pinned_witness_id);
        for (auto& candidate : obj.live_candidates_by_missing_quorum) {
            READWRITE(candidate);
        }
        READWRITE(obj.guard);
    }
};

struct ReferenceRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint32_t epoch{0};
    uint256 witness_id;
    uint32_t guard{REFERENCE_GUARD};

    SERIALIZE_METHODS(ReferenceRecord, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.witness_id, obj.guard);
    }
};

struct PresenceRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint32_t epoch{0};
    uint256 witness_id;
    uint32_t guard{PRESENCE_GUARD};

    SERIALIZE_METHODS(PresenceRecord, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.witness_id, obj.guard);
    }
};

struct CheckpointRecord {
    static constexpr std::size_t WIRE_SIZE{
        5 * sizeof(uint32_t) + 5 * 32 +
        PaymentAuditReceiptState::WIRE_SIZE};

    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    PaymentAuditStoreCheckpoint checkpoint;
    uint32_t guard{CHECKPOINT_GUARD};

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

static_assert(CheckpointRecord::WIRE_SIZE == 316);

struct PruneIntentRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    CheckpointRecord checkpoint;
    uint8_t phase{0};
    uint8_t has_cursor{0};
    uint32_t epoch_cursor{0};
    uint256 witness_cursor;
    uint32_t guard{PRUNE_INTENT_GUARD};

    SERIALIZE_METHODS(PruneIntentRecord, obj)
    {
        READWRITE(obj.version, obj.checkpoint, obj.phase,
                  obj.has_cursor, obj.epoch_cursor,
                  obj.witness_cursor, obj.guard);
    }
};

constexpr std::size_t AUDIT_RECORD_MAX_SIZE{
    2 * sizeof(uint32_t) + 2 * 32 + FinalPaymentAudit::WIRE_SIZE};
constexpr std::size_t SCHEMA_VALUE_SIZE{
    4 * sizeof(uint32_t) + 4 * sizeof(uint16_t) + 32};
constexpr std::size_t EPOCH_RECORD_MAX_SIZE{
    3 * sizeof(uint32_t) +
    (1 + PaymentAuditStore::MAX_LIVE_CANDIDATES) * 32};
constexpr std::size_t SMALL_INDEX_RECORD_MAX_SIZE{
    3 * sizeof(uint32_t) + 32};
constexpr std::size_t PRUNE_INTENT_MAX_SIZE{
    CheckpointRecord::WIRE_SIZE + 3 * sizeof(uint32_t) +
    2 * sizeof(uint8_t) + 32};

static_assert(EPOCH_RECORD_MAX_SIZE == 172);
static_assert(SCHEMA_VALUE_SIZE == 56);
static_assert(SMALL_INDEX_RECORD_MAX_SIZE == 44);
static_assert(PRUNE_INTENT_MAX_SIZE == 362);
static_assert(
    PaymentAuditStore::MAX_PRUNE_SCAN_RECORDS_PER_PASS >=
    1 + 4 * (PaymentAuditStore::MAX_LIVE_CANDIDATES + 1));
static_assert(
    PaymentAuditStore::MAX_PRUNE_VALUE_BYTES_PER_PASS >=
    EPOCH_RECORD_MAX_SIZE +
        (PaymentAuditStore::MAX_LIVE_CANDIDATES + 1) *
            (AUDIT_RECORD_MAX_SIZE + EPOCH_RECORD_MAX_SIZE +
             2 * SMALL_INDEX_RECORD_MAX_SIZE));

enum class BoundedReadResult : uint8_t {
    NOT_FOUND = 0,
    FOUND,
    CORRUPT,
    BUDGET_EXHAUSTED,
};

template <typename Key, typename Value>
BoundedReadResult ReadExactBounded(CDBWrapper& db,
                                   const Key& key,
                                   std::size_t maximum_value_size,
                                   Value& value)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return BoundedReadResult::NOT_FOUND;
    }
    Key found;
    if (!iterator->GetKey(found) || found != key) {
        iterator->CheckStatus();
        return BoundedReadResult::NOT_FOUND;
    }
    if (!iterator->GetKeyExact(found) ||
        iterator->GetValueSize() > maximum_value_size ||
        !iterator->GetValueExact(value)) {
        return BoundedReadResult::CORRUPT;
    }
    iterator->CheckStatus();
    return BoundedReadResult::FOUND;
}

bool HasExactSingletonRange(CDBWrapper& db, uint8_t key,
                            bool expected_present)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return !expected_present;
    }
    uint8_t prefix{0};
    if (!iterator->GetKey(prefix)) return false;
    if (prefix != key) {
        iterator->CheckStatus();
        return !expected_present;
    }
    uint8_t exact_key{0};
    if (!expected_present || !iterator->GetKeyExact(exact_key) ||
        exact_key != key) {
        return false;
    }
    iterator->Next();
    if (iterator->Valid()) {
        uint8_t next_prefix{0};
        if (!iterator->GetKey(next_prefix) || next_prefix == key) {
            return false;
        }
    }
    iterator->CheckStatus();
    return true;
}

template <typename Key, typename Value>
BoundedReadResult ReadExactForPrune(
    CDBWrapper& db, const Key& key, std::size_t maximum_value_size,
    Value& value, PaymentAuditPruneProgress& progress)
{
    if (progress.scanned_records >=
        PaymentAuditStore::MAX_PRUNE_SCAN_RECORDS_PER_PASS) {
        return BoundedReadResult::BUDGET_EXHAUSTED;
    }
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        ++progress.scanned_records;
        return BoundedReadResult::NOT_FOUND;
    }
    Key found;
    if (!iterator->GetKey(found) || found != key) {
        iterator->CheckStatus();
        ++progress.scanned_records;
        return BoundedReadResult::NOT_FOUND;
    }
    const std::size_t value_size{iterator->GetValueSize()};
    if (!iterator->GetKeyExact(found) ||
        value_size > maximum_value_size) {
        return BoundedReadResult::CORRUPT;
    }
    if (progress.scanned_value_bytes + value_size >
        PaymentAuditStore::MAX_PRUNE_VALUE_BYTES_PER_PASS) {
        return BoundedReadResult::BUDGET_EXHAUSTED;
    }
    ++progress.scanned_records;
    progress.scanned_value_bytes += value_size;
    if (!iterator->GetValueExact(value)) {
        return BoundedReadResult::CORRUPT;
    }
    iterator->CheckStatus();
    return BoundedReadResult::FOUND;
}

bool IsRecordValid(const AuditRecord& record,
                   const uint256& genesis_hash)
{
    return record.version == PaymentAuditStore::DB_FORMAT_VERSION &&
           record.guard == WITNESS_GUARD &&
           record.audit.IsStructurallyValid() &&
           record.logical_id == record.audit.GetLogicalId(genesis_hash) &&
           record.witness_id == record.audit.GetWitnessId(genesis_hash);
}

bool IsEpochRecordValid(const EpochRecord& record, uint32_t epoch)
{
    if (record.version != PaymentAuditStore::DB_FORMAT_VERSION ||
        record.guard != EPOCH_GUARD || record.epoch != epoch) {
        return false;
    }
    for (std::size_t first{0};
         first < record.live_candidates_by_missing_quorum.size(); ++first) {
        const auto& id{record.live_candidates_by_missing_quorum[first]};
        if (id.IsNull()) continue;
        if (id == record.pinned_witness_id) return false;
        for (std::size_t second{first + 1};
             second < record.live_candidates_by_missing_quorum.size();
             ++second) {
            if (id == record.live_candidates_by_missing_quorum[second]) {
                return false;
            }
        }
    }
    return true;
}

bool IsReferenceRecordValid(const ReferenceRecord& record, uint32_t epoch,
                            const uint256& witness_id)
{
    return record.version == PaymentAuditStore::DB_FORMAT_VERSION &&
           record.guard == REFERENCE_GUARD && record.epoch == epoch &&
           !record.witness_id.IsNull() &&
           record.witness_id == witness_id;
}

bool IsPresenceRecordValid(const PresenceRecord& record, uint32_t epoch,
                           const uint256& witness_id)
{
    return record.version == PaymentAuditStore::DB_FORMAT_VERSION &&
           record.guard == PRESENCE_GUARD &&
           record.epoch == epoch &&
           !record.witness_id.IsNull() &&
           record.witness_id == witness_id;
}

bool IsCheckpointRecordValid(const CheckpointRecord& record)
{
    return record.version == PaymentAuditStore::DB_FORMAT_VERSION &&
           record.guard == CHECKPOINT_GUARD &&
           record.checkpoint.IsStructurallyValid();
}

bool IsPruneIntentRecordValid(const PruneIntentRecord& record)
{
    if (record.version != PaymentAuditStore::DB_FORMAT_VERSION ||
        record.guard != PRUNE_INTENT_GUARD ||
        !IsCheckpointRecordValid(record.checkpoint) ||
        record.phase > 5 || record.has_cursor > 1) {
        return false;
    }
    if (record.has_cursor == 0) {
        return record.epoch_cursor == 0 &&
               record.witness_cursor.IsNull();
    }
    const bool epoch_phase{record.phase == 1 || record.phase == 5};
    return epoch_phase ? record.witness_cursor.IsNull()
                       : record.epoch_cursor == 0 &&
                             !record.witness_cursor.IsNull();
}

bool IsCheckpointAdvance(
    const PaymentAuditStoreCheckpoint& previous,
    const PaymentAuditStoreCheckpoint& candidate) noexcept
{
    if (candidate.prune_through_epoch < previous.prune_through_epoch ||
        candidate.covered_through_height <
            previous.covered_through_height ||
        candidate.authorizing_target_height <=
            previous.authorizing_target_height) {
        return false;
    }

    if (candidate.prune_through_epoch ==
        previous.prune_through_epoch) {
        return candidate.covered_through_height ==
                   previous.covered_through_height &&
               candidate.covered_through_hash ==
                   previous.covered_through_hash &&
               candidate.authenticated_receipt_state ==
                   previous.authenticated_receipt_state &&
               candidate.authenticated_probation_state_hash ==
                   previous.authenticated_probation_state_hash;
    }

    if (candidate.covered_through_height <=
        previous.covered_through_height) {
        return false;
    }
    const auto& old_state{previous.authenticated_receipt_state};
    const auto& new_state{candidate.authenticated_receipt_state};
    if (old_state.cursor.IsNull()) {
        return !new_state.cursor.IsNull() ||
               candidate.authenticated_probation_state_hash ==
                   previous.authenticated_probation_state_hash;
    }
    if (new_state.cursor.IsNull() ||
        new_state.cursor.epoch < old_state.cursor.epoch ||
        new_state.cursor.carrier_height <
            old_state.cursor.carrier_height) {
        return false;
    }
    if (new_state.cursor == old_state.cursor) {
        return new_state == old_state &&
               candidate.authenticated_probation_state_hash ==
                   previous.authenticated_probation_state_hash;
    }
    return true;
}

bool HasValidReference(const CDBWrapper& db, const uint256& genesis_hash,
                       uint32_t epoch, const uint256& witness_id)
{
    if (witness_id.IsNull()) return false;
    ReferenceRecord record;
    return db.Read(ReferenceKey{DB_REFERENCE_PREFIX,
                                PaymentAuditStore::DB_FORMAT_VERSION,
                                genesis_hash, witness_id},
                   record) &&
           IsReferenceRecordValid(record, epoch, witness_id);
}

bool HasValidPresence(const CDBWrapper& db, const uint256& genesis_hash,
                      uint32_t epoch, const uint256& witness_id)
{
    if (witness_id.IsNull()) return false;
    PresenceRecord record;
    return db.Read(PresenceKey{DB_PRESENCE_PREFIX,
                               PaymentAuditStore::DB_FORMAT_VERSION,
                               genesis_hash, witness_id},
                   record) &&
           IsPresenceRecordValid(record, epoch, witness_id);
}

std::optional<std::size_t> MissingQuorumSlot(
    uint8_t selected_quorum_mask)
{
    for (std::size_t missing{0}; missing < ACTIVE_QUORUMS; ++missing) {
        const uint8_t mask{static_cast<uint8_t>(
            ((uint8_t{1} << ACTIVE_QUORUMS) - 1) ^
            (uint8_t{1} << missing))};
        if (selected_quorum_mask == mask) return missing;
    }
    return std::nullopt;
}

bool ContainsLiveCandidate(const EpochRecord& record,
                           const uint256& witness_id)
{
    for (const auto& candidate :
         record.live_candidates_by_missing_quorum) {
        if (candidate == witness_id) return true;
    }
    return false;
}

struct ArchiveLinkValidation {
    BoundedReadResult result{BoundedReadResult::CORRUPT};
    bool has_reference{false};
};

ArchiveLinkValidation ValidateArchiveLinks(
    CDBWrapper& db, const uint256& genesis_hash, uint32_t epoch,
    const uint256& witness_id, bool require_witness,
    PaymentAuditPruneProgress& progress)
{
    if (witness_id.IsNull()) return {};
    if (require_witness) {
        AuditRecord witness;
        const auto witness_result{ReadExactForPrune(
            db,
            WitnessKey{DB_WITNESS_PREFIX,
                       PaymentAuditStore::DB_FORMAT_VERSION,
                       genesis_hash, witness_id},
            AUDIT_RECORD_MAX_SIZE, witness, progress)};
        if (witness_result != BoundedReadResult::FOUND) {
            return {witness_result, false};
        }
        if (!IsRecordValid(witness, genesis_hash) ||
            witness.witness_id != witness_id ||
            witness.audit.statement.commitment.seed.epoch != epoch) {
            return {};
        }
    }

    PresenceRecord presence;
    const auto presence_result{ReadExactForPrune(
            db,
            PresenceKey{DB_PRESENCE_PREFIX,
                        PaymentAuditStore::DB_FORMAT_VERSION,
                        genesis_hash, witness_id},
            SMALL_INDEX_RECORD_MAX_SIZE, presence, progress)};
    if (presence_result != BoundedReadResult::FOUND) {
        return {presence_result, false};
    }
    if (!IsPresenceRecordValid(presence, epoch, witness_id)) {
        return {};
    }

    EpochRecord epoch_record;
    const auto epoch_result{ReadExactForPrune(
            db,
            EpochKey{DB_EPOCH_PREFIX,
                     PaymentAuditStore::DB_FORMAT_VERSION,
                     genesis_hash, epoch},
            EPOCH_RECORD_MAX_SIZE, epoch_record, progress)};
    if (epoch_result != BoundedReadResult::FOUND) {
        return {epoch_result, false};
    }
    if (!IsEpochRecordValid(epoch_record, epoch)) {
        return {};
    }

    ReferenceRecord reference;
    const auto reference_result{ReadExactForPrune(
        db,
        ReferenceKey{DB_REFERENCE_PREFIX,
                     PaymentAuditStore::DB_FORMAT_VERSION,
                     genesis_hash, witness_id},
        SMALL_INDEX_RECORD_MAX_SIZE, reference, progress)};
    if (reference_result == BoundedReadResult::CORRUPT ||
        reference_result == BoundedReadResult::BUDGET_EXHAUSTED) {
        return {reference_result, false};
    }
    const bool referenced{reference_result == BoundedReadResult::FOUND};
    if (referenced &&
        !IsReferenceRecordValid(reference, epoch, witness_id)) {
        return {};
    }
    const bool live{ContainsLiveCandidate(epoch_record, witness_id)};
    const bool pinned{epoch_record.pinned_witness_id == witness_id};
    const bool valid{live ? !referenced && !pinned : referenced};
    return {valid ? BoundedReadResult::FOUND
                  : BoundedReadResult::CORRUPT,
            referenced};
}

} // namespace

PaymentAuditStore::PaymentAuditStore(fs::path path,
                                     uint256 genesis_hash,
                                     std::size_t cache_bytes,
                                     bool wipe)
    : m_genesis_hash{std::move(genesis_hash)},
      m_db{DBParams{.path = std::move(path),
                    .cache_bytes = cache_bytes,
                    .memory_only = false,
                    .wipe_data = wipe,
                    .obfuscate = false}}
{
    Initialize();
}

void PaymentAuditStore::Initialize()
{
    LOCK(m_mutex);
    if (m_genesis_hash.IsNull()) {
        m_failure = PaymentAuditStoreResult::INVALID;
        return;
    }
    try {
        const SchemaValue expected_schema{MakeSchemaValue(m_genesis_hash)};
        if (!m_db.Exists(DB_SCHEMA_KEY)) {
            if (!m_db.IsEmpty()) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            if (!m_db.Write(DB_SCHEMA_KEY, expected_schema, true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            }
            return;
        }
        SchemaValue schema;
        if (ReadExactBounded(m_db, DB_SCHEMA_KEY, SCHEMA_VALUE_SIZE,
                             schema) != BoundedReadResult::FOUND ||
            schema != expected_schema) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return;
        }
        {
            std::unique_ptr<CDBIterator> first{m_db.NewIterator()};
            first->SeekToFirst();
            uint8_t key{0};
            if (!first->Valid() || !first->GetKeyExact(key) ||
                key != DB_SCHEMA_KEY) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            first->CheckStatus();
            std::unique_ptr<CDBIterator> trailing{m_db.NewIterator()};
            trailing->Seek(static_cast<uint8_t>(DB_PRUNE_INTENT_KEY + 1));
            if (trailing->Valid()) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            trailing->CheckStatus();
        }
        const bool has_checkpoint{m_db.Exists(DB_CHECKPOINT_KEY)};
        if (!HasExactSingletonRange(m_db, DB_SCHEMA_KEY,
                                    /*expected_present=*/true) ||
            !HasExactSingletonRange(m_db, DB_CHECKPOINT_KEY,
                                    has_checkpoint)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return;
        }
        if (has_checkpoint) {
            CheckpointRecord record;
            if (ReadExactBounded(m_db, DB_CHECKPOINT_KEY,
                                 CheckpointRecord::WIRE_SIZE,
                                 record) != BoundedReadResult::FOUND ||
                !IsCheckpointRecordValid(record)) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            m_prune_checkpoint = record.checkpoint;
        }
        const bool has_intent{m_db.Exists(DB_PRUNE_INTENT_KEY)};
        if (!HasExactSingletonRange(m_db, DB_PRUNE_INTENT_KEY,
                                    has_intent)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return;
        }
        if (has_intent) {
            PruneIntentRecord record;
            if (ReadExactBounded(
                    m_db, DB_PRUNE_INTENT_KEY,
                    PRUNE_INTENT_MAX_SIZE, record) !=
                    BoundedReadResult::FOUND ||
                !IsPruneIntentRecordValid(record) ||
                (m_prune_checkpoint &&
                 !IsCheckpointAdvance(
                     *m_prune_checkpoint,
                     record.checkpoint.checkpoint))) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            m_prune_intent = PruneIntentState{
                record.checkpoint.checkpoint,
                static_cast<PrunePhase>(record.phase),
                record.has_cursor != 0,
                record.epoch_cursor,
                record.witness_cursor};
        }
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
    }
}

bool PaymentAuditStore::IsHealthy() const
{
    LOCK(m_mutex);
    return !m_failure.has_value();
}

bool PaymentAuditStore::CanAdvanceCandidateRevision() const
{
    if (m_candidate_revision != std::numeric_limits<uint64_t>::max()) {
        return true;
    }
    m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
    return false;
}

void PaymentAuditStore::AdvanceCandidateRevision() const
{
    ++m_candidate_revision;
}

const PaymentAuditStoreCheckpoint*
PaymentAuditStore::EffectivePruneCheckpointLocked() const
{
    return m_prune_intent ? &m_prune_intent->checkpoint
                          : m_prune_checkpoint
                                ? &*m_prune_checkpoint
                                : nullptr;
}

std::optional<uint64_t> PaymentAuditStore::ObserveCandidateRevision() const
{
    LOCK(m_mutex);
    if (m_failure) return std::nullopt;
    return m_candidate_revision;
}

bool PaymentAuditStore::IsCandidateRevisionCurrent(uint64_t revision) const
{
    LOCK(m_mutex);
    return !m_failure && revision == m_candidate_revision;
}

PaymentAuditStoreResult PaymentAuditStore::ProbeLiveCandidateSlot(
    uint32_t epoch, uint8_t selected_quorum_mask) const
{
    LOCK(m_mutex);
    if (m_failure) return *m_failure;
    const auto missing_quorum_slot{
        MissingQuorumSlot(selected_quorum_mask)};
    if (!missing_quorum_slot) return PaymentAuditStoreResult::INVALID;
    const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
    if (prune_checkpoint &&
        epoch <= prune_checkpoint->prune_through_epoch) {
        return PaymentAuditStoreResult::INVALID;
    }

    try {
        const EpochKey epoch_key{DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                                 m_genesis_hash, epoch};
        if (!m_db.Exists(epoch_key)) {
            return PaymentAuditStoreResult::ACCEPTED;
        }
        EpochRecord epoch_record;
        if (!m_db.Read(epoch_key, epoch_record) ||
            !IsEpochRecordValid(epoch_record, epoch) ||
            (!epoch_record.pinned_witness_id.IsNull() &&
             !HasValidReference(m_db, m_genesis_hash, epoch,
                                epoch_record.pinned_witness_id))) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }
        return epoch_record.live_candidates_by_missing_quorum[
                   *missing_quorum_slot]
                       .IsNull()
                   ? PaymentAuditStoreResult::ACCEPTED
                   : PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return *m_failure;
    }
}

PaymentAuditStoreResult PaymentAuditStore::AcceptVerified(
    const FinalPaymentAudit& audit, bool required_witness)
{
    LOCK(m_mutex);
    if (m_failure) return *m_failure;
    if (!audit.IsStructurallyValid()) return PaymentAuditStoreResult::INVALID;

    const uint256 logical_id{audit.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{audit.GetWitnessId(m_genesis_hash)};
    const uint32_t epoch{audit.statement.commitment.seed.epoch};
    const auto missing_quorum_slot{
        MissingQuorumSlot(audit.selected_quorum_mask)};
    if (logical_id.IsNull() || witness_id.IsNull() ||
        !missing_quorum_slot) {
        return PaymentAuditStoreResult::INVALID;
    }
    const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
    if (prune_checkpoint &&
        epoch <= prune_checkpoint->prune_through_epoch) {
        return PaymentAuditStoreResult::INVALID;
    }

    try {
        const WitnessKey witness_key{DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                                     m_genesis_hash, witness_id};
        const EpochKey epoch_key{DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                                 m_genesis_hash, epoch};
        const ReferenceKey reference_key{
            DB_REFERENCE_PREFIX, DB_FORMAT_VERSION, m_genesis_hash,
            witness_id};
        const PresenceKey presence_key{
            DB_PRESENCE_PREFIX, DB_FORMAT_VERSION, m_genesis_hash,
            witness_id};
        EpochRecord epoch_record;
        const bool has_epoch{m_db.Exists(epoch_key)};
        if (has_epoch &&
            (!m_db.Read(epoch_key, epoch_record) ||
             !IsEpochRecordValid(epoch_record, epoch))) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }
        if (!has_epoch) {
            epoch_record = EpochRecord{DB_FORMAT_VERSION, epoch, {}, {},
                                       EPOCH_GUARD};
        } else if (!epoch_record.pinned_witness_id.IsNull() &&
                   !HasValidReference(m_db, m_genesis_hash, epoch,
                                      epoch_record.pinned_witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }

        ReferenceRecord reference;
        const bool has_reference{m_db.Exists(reference_key)};
        if (has_reference &&
            (!m_db.Read(reference_key, reference) ||
             !IsReferenceRecordValid(reference, epoch, witness_id))) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }

        AuditRecord existing;
        if (m_db.Exists(witness_key)) {
            if (!m_db.Read(witness_key, existing) ||
                !IsRecordValid(existing, m_genesis_hash) ||
                existing.witness_id != witness_id ||
                existing.audit.statement.commitment.seed.epoch != epoch ||
                !has_epoch ||
                (has_reference &&
                 ContainsLiveCandidate(epoch_record, witness_id)) ||
                (!has_reference &&
                 (epoch_record.pinned_witness_id == witness_id ||
                  !ContainsLiveCandidate(epoch_record, witness_id)))) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return *m_failure;
            }
            if (!HasValidPresence(m_db, m_genesis_hash, epoch,
                                  witness_id)) {
                if (!CanAdvanceCandidateRevision()) return *m_failure;
                if (!m_db.Write(
                        presence_key,
                        PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                       PRESENCE_GUARD},
                        true)) {
                    m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                    return *m_failure;
                }
                AdvanceCandidateRevision();
            }
            return PaymentAuditStoreResult::DUPLICATE_WITNESS;
        }

        const AuditRecord record{DB_FORMAT_VERSION, logical_id, witness_id,
                                 audit, WITNESS_GUARD};
        // A required historical dependency can repair a missing certificate
        // record without re-entering the bounded live-candidate set. The
        // reference marker and preferred epoch pointer were committed in the
        // same batch when the carrier originally connected.
        if (has_reference) {
            if (!has_epoch || !required_witness ||
                ContainsLiveCandidate(epoch_record, witness_id)) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return *m_failure;
            }
            CDBBatch repair{m_db};
            repair.Write(witness_key, record);
            repair.Write(presence_key,
                         PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                        PRESENCE_GUARD});
            if (!CanAdvanceCandidateRevision()) return *m_failure;
            if (!m_db.WriteBatch(repair, true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                return *m_failure;
            }
            AdvanceCandidateRevision();
            return PaymentAuditStoreResult::ACCEPTED;
        }
        if (epoch_record.pinned_witness_id == witness_id) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }

        // Applied witnesses do not consume the four live candidate slots. They
        // remain available across receipt reorgs until an authenticated
        // checkpoint atomically retires their epoch.
        auto& slot{
            epoch_record.live_candidates_by_missing_quorum[
                *missing_quorum_slot]};
        if (!slot.IsNull() && !required_witness) {
            return PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL;
        }

        CDBBatch batch{m_db};
        if (!slot.IsNull() && slot != witness_id) {
            const WitnessKey victim_key{DB_WITNESS_PREFIX,
                                        DB_FORMAT_VERSION,
                                        m_genesis_hash, slot};
            const PresenceKey victim_presence_key{
                DB_PRESENCE_PREFIX, DB_FORMAT_VERSION,
                m_genesis_hash, slot};
            const ReferenceKey victim_reference_key{
                DB_REFERENCE_PREFIX, DB_FORMAT_VERSION,
                m_genesis_hash, slot};
            AuditRecord victim;
            if (!m_db.Read(victim_key, victim) ||
                !IsRecordValid(victim, m_genesis_hash) ||
                victim.witness_id != slot ||
                victim.audit.statement.commitment.seed.epoch != epoch ||
                !HasValidPresence(m_db, m_genesis_hash, epoch, slot) ||
                m_db.Exists(victim_reference_key)) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return *m_failure;
            }
            batch.Erase(victim_key);
            batch.Erase(victim_presence_key);
        }
        slot = witness_id;
        batch.Write(witness_key, record);
        batch.Write(presence_key,
                    PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                   PRESENCE_GUARD});
        batch.Write(epoch_key, epoch_record);
        if (!CanAdvanceCandidateRevision()) return *m_failure;
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            return *m_failure;
        }
        AdvanceCandidateRevision();
        return PaymentAuditStoreResult::ACCEPTED;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return *m_failure;
    }
}

std::optional<FinalPaymentAudit> PaymentAuditStore::Get(
    const uint256& witness_id) const
{
    LOCK(m_mutex);
    return GetLocked(witness_id);
}

std::optional<PaymentAuditWitnessSnapshot>
PaymentAuditStore::GetWithCandidateRevision(
    const uint256& witness_id) const
{
    LOCK(m_mutex);
    auto audit{GetLocked(witness_id)};
    if (!audit) return std::nullopt;
    return PaymentAuditWitnessSnapshot{
        std::move(*audit), m_candidate_revision};
}

std::optional<FinalPaymentAudit> PaymentAuditStore::GetLocked(
    const uint256& witness_id) const
{
    if (m_failure || witness_id.IsNull()) return std::nullopt;
    try {
        const WitnessKey key{DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                             m_genesis_hash, witness_id};
        const PresenceKey presence_key{
            DB_PRESENCE_PREFIX, DB_FORMAT_VERSION, m_genesis_hash,
            witness_id};
        PresenceRecord presence;
        const auto presence_result{ReadExactBounded(
            m_db, presence_key, SMALL_INDEX_RECORD_MAX_SIZE, presence)};
        if (presence_result == BoundedReadResult::CORRUPT) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        const bool has_presence{
            presence_result == BoundedReadResult::FOUND};
        if (has_presence &&
            !IsPresenceRecordValid(presence, presence.epoch,
                                   witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
        if (has_presence && prune_checkpoint &&
            presence.epoch <= prune_checkpoint->prune_through_epoch) {
            return std::nullopt;
        }
        AuditRecord record;
        if (!m_db.Read(key, record)) {
            // A stale tiny index must never suppress exact-witness healing.
            // Remove both sides atomically; a required response can then
            // repopulate the fully verified payload and its presence key.
            if (has_presence) {
                CDBBatch repair{m_db};
                repair.Erase(key);
                repair.Erase(presence_key);
                if (!CanAdvanceCandidateRevision()) return std::nullopt;
                if (!m_db.WriteBatch(repair, true)) {
                    m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                } else {
                    AdvanceCandidateRevision();
                }
            }
            return std::nullopt;
        }
        if (!IsRecordValid(record, m_genesis_hash) ||
            record.witness_id != witness_id) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        const uint32_t epoch{
            record.audit.statement.commitment.seed.epoch};
        if (prune_checkpoint &&
            epoch <= prune_checkpoint->prune_through_epoch) {
            return std::nullopt;
        }
        if (has_presence && presence.epoch != epoch) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        if (!has_presence) {
            if (!CanAdvanceCandidateRevision()) return std::nullopt;
            if (!m_db.Write(
                    presence_key,
                    PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                   PRESENCE_GUARD},
                    true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                return std::nullopt;
            }
            AdvanceCandidateRevision();
        }
        return record.audit;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return std::nullopt;
    }
}

std::optional<PaymentAuditCandidateSnapshot>
PaymentAuditStore::GetEpochCandidateSnapshot(uint32_t epoch) const
{
    LOCK(m_mutex);
    if (m_failure) return std::nullopt;
    PaymentAuditCandidateSnapshot snapshot{m_candidate_revision, epoch, {}};
    const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
    if (prune_checkpoint &&
        epoch <= prune_checkpoint->prune_through_epoch) {
        return snapshot;
    }
    try {
        const EpochKey epoch_key{DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                                 m_genesis_hash, epoch};
        EpochRecord epoch_record;
        if (!m_db.Exists(epoch_key)) return snapshot;
        if (!m_db.Read(epoch_key, epoch_record) ||
            !IsEpochRecordValid(epoch_record, epoch)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        if (!epoch_record.pinned_witness_id.IsNull() &&
            !HasValidReference(m_db, m_genesis_hash, epoch,
                               epoch_record.pinned_witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        std::vector<uint256> ids;
        const auto append_unique = [&](const uint256& id) {
            if (!id.IsNull() &&
                std::find(ids.begin(), ids.end(), id) == ids.end()) {
                ids.push_back(id);
            }
        };
        append_unique(epoch_record.pinned_witness_id);
        for (const auto& id :
             epoch_record.live_candidates_by_missing_quorum) {
            append_unique(id);
        }
        snapshot.ordered_candidates.reserve(ids.size());
        for (const auto& id : ids) {
            AuditRecord record;
            const WitnessKey witness_key{
                DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                m_genesis_hash, id};
            if (!m_db.Read(witness_key, record) ||
                !IsRecordValid(record, m_genesis_hash) ||
                !HasValidPresence(m_db, m_genesis_hash, epoch, id) ||
                record.witness_id != id ||
                record.audit.statement.commitment.seed.epoch != epoch) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return std::nullopt;
            }
            snapshot.ordered_candidates.push_back(
                PaymentAuditCandidateView{record.logical_id,
                                          record.witness_id,
                                          std::move(record.audit)});
        }
        return snapshot;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return std::nullopt;
    }
}

bool PaymentAuditStore::Has(const uint256& witness_id) const
{
    LOCK(m_mutex);
    if (m_failure || witness_id.IsNull()) return false;
    try {
        PresenceRecord presence;
        const PresenceKey key{DB_PRESENCE_PREFIX, DB_FORMAT_VERSION,
                              m_genesis_hash, witness_id};
        if (!m_db.Read(key, presence)) return false;
        if (!IsPresenceRecordValid(presence, presence.epoch, witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return false;
        }
        const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
        if (prune_checkpoint &&
            presence.epoch <=
                prune_checkpoint->prune_through_epoch) {
            return false;
        }
        return true;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return false;
    }
}

PaymentAuditStoreResult PaymentAuditStore::PinReferencedWitness(
    uint32_t epoch, const uint256& witness_id)
{
    LOCK(m_mutex);
    if (m_failure) return *m_failure;
    if (witness_id.IsNull()) return PaymentAuditStoreResult::INVALID;
    const auto* prune_checkpoint{EffectivePruneCheckpointLocked()};
    if (prune_checkpoint &&
        epoch <= prune_checkpoint->prune_through_epoch) {
        return PaymentAuditStoreResult::INVALID;
    }
    try {
        const EpochKey epoch_key{DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                                 m_genesis_hash, epoch};
        EpochRecord epoch_record;
        if (!m_db.Read(epoch_key, epoch_record) ||
            !IsEpochRecordValid(epoch_record, epoch)) {
            return PaymentAuditStoreResult::INVALID;
        }
        if (!epoch_record.pinned_witness_id.IsNull() &&
            !HasValidReference(m_db, m_genesis_hash, epoch,
                               epoch_record.pinned_witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }
        const ReferenceKey reference_key{
            DB_REFERENCE_PREFIX, DB_FORMAT_VERSION, m_genesis_hash,
            witness_id};
        ReferenceRecord reference;
        const bool has_reference{m_db.Exists(reference_key)};
        if (has_reference &&
            (!m_db.Read(reference_key, reference) ||
             !IsReferenceRecordValid(reference, epoch, witness_id))) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }
        const bool live_candidate{
            ContainsLiveCandidate(epoch_record, witness_id)};
        const bool already_pinned{
            epoch_record.pinned_witness_id == witness_id};
        if ((has_reference && live_candidate) ||
            (!has_reference && already_pinned)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }
        if (!has_reference && !live_candidate) {
            return PaymentAuditStoreResult::INVALID;
        }
        const WitnessKey target_key{DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                                    m_genesis_hash, witness_id};
        AuditRecord target;
        if (!m_db.Read(target_key, target) ||
            !IsRecordValid(target, m_genesis_hash) ||
            !HasValidPresence(m_db, m_genesis_hash, epoch, witness_id) ||
            target.witness_id != witness_id ||
            target.audit.statement.commitment.seed.epoch != epoch) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return *m_failure;
        }

        CDBBatch batch{m_db};
        bool removes_live_candidate{false};
        for (auto& candidate :
             epoch_record.live_candidates_by_missing_quorum) {
            if (candidate.IsNull()) continue;
            removes_live_candidate = true;
            const WitnessKey victim_key{DB_WITNESS_PREFIX,
                                        DB_FORMAT_VERSION,
                                        m_genesis_hash, candidate};
            const PresenceKey victim_presence_key{
                DB_PRESENCE_PREFIX, DB_FORMAT_VERSION,
                m_genesis_hash, candidate};
            const ReferenceKey victim_reference_key{
                DB_REFERENCE_PREFIX, DB_FORMAT_VERSION,
                m_genesis_hash, candidate};
            AuditRecord victim;
            if (!m_db.Read(victim_key, victim) ||
                !IsRecordValid(victim, m_genesis_hash) ||
                victim.witness_id != candidate ||
                victim.audit.statement.commitment.seed.epoch != epoch ||
                !HasValidPresence(m_db, m_genesis_hash, epoch, candidate) ||
                m_db.Exists(victim_reference_key)) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return *m_failure;
            }
            if (candidate != witness_id) {
                batch.Erase(victim_key);
                batch.Erase(victim_presence_key);
            }
            candidate.SetNull();
        }
        if (already_pinned && !removes_live_candidate) {
            return PaymentAuditStoreResult::DUPLICATE_WITNESS;
        }
        if (!has_reference) {
            batch.Write(reference_key,
                        ReferenceRecord{DB_FORMAT_VERSION, epoch,
                                        witness_id, REFERENCE_GUARD});
        }
        epoch_record.pinned_witness_id = witness_id;
        batch.Write(epoch_key, epoch_record);
        if (!CanAdvanceCandidateRevision()) return *m_failure;
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            return *m_failure;
        }
        AdvanceCandidateRevision();
        return already_pinned ? PaymentAuditStoreResult::DUPLICATE_WITNESS
                              : PaymentAuditStoreResult::ACCEPTED;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return *m_failure;
    }
}

bool PaymentAuditStore::PruneThroughCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint)
{
    for (;;) {
        const auto progress{PruneThroughCheckpointStep(checkpoint)};
        if (progress.status == PaymentAuditPruneStatus::COMPLETE) {
            return true;
        }
        if (progress.status != PaymentAuditPruneStatus::IN_PROGRESS) {
            return false;
        }
    }
}

PaymentAuditPruneProgress
PaymentAuditStore::PruneThroughCheckpointStep(
    const PaymentAuditStoreCheckpoint& checkpoint)
{
    LOCK(m_mutex);
    PaymentAuditPruneProgress progress;
    if (m_failure) {
        if (*m_failure == PaymentAuditStoreResult::CORRUPT) {
            progress.status = PaymentAuditPruneStatus::CORRUPT;
        } else if (*m_failure == PaymentAuditStoreResult::INVALID) {
            progress.status = PaymentAuditPruneStatus::INVALID;
        } else {
            progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
        }
        return progress;
    }
    if (!checkpoint.IsStructurallyValid()) {
        progress.status = PaymentAuditPruneStatus::INVALID;
        return progress;
    }
    if (m_prune_intent &&
        m_prune_intent->checkpoint != checkpoint) {
        progress.status = PaymentAuditPruneStatus::INVALID;
        return progress;
    }
    if (!m_prune_intent) {
        if (m_prune_checkpoint) {
            if (checkpoint == *m_prune_checkpoint) {
                progress.status = PaymentAuditPruneStatus::COMPLETE;
                return progress;
            }
            if (!IsCheckpointAdvance(*m_prune_checkpoint, checkpoint)) {
                progress.status = PaymentAuditPruneStatus::INVALID;
                return progress;
            }
        }
        PruneIntentState intent{checkpoint, PrunePhase::VALIDATE_WITNESSES,
                                false, 0, {}};
        const PruneIntentRecord disk_intent{
            DB_FORMAT_VERSION,
            CheckpointRecord{DB_FORMAT_VERSION, checkpoint,
                             CHECKPOINT_GUARD},
            static_cast<uint8_t>(intent.phase), 0, 0, {},
            PRUNE_INTENT_GUARD};
        if (!CanAdvanceCandidateRevision()) {
            progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
            return progress;
        }
        if (!m_db.Write(DB_PRUNE_INTENT_KEY, disk_intent, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
            return progress;
        }
        m_prune_intent = std::move(intent);
        AdvanceCandidateRevision();
    }

    try {
        auto& intent{*m_prune_intent};
        const auto make_disk_intent = [&] {
            return PruneIntentRecord{
                DB_FORMAT_VERSION,
                CheckpointRecord{DB_FORMAT_VERSION, intent.checkpoint,
                                 CHECKPOINT_GUARD},
                static_cast<uint8_t>(intent.phase),
                static_cast<uint8_t>(intent.has_cursor),
                intent.epoch_cursor, intent.witness_cursor,
                PRUNE_INTENT_GUARD};
        };
        const auto reset_cursor = [&] {
            intent.has_cursor = false;
            intent.epoch_cursor = 0;
            intent.witness_cursor.SetNull();
        };
        const auto can_scan = [&](std::size_t value_size) {
            if (progress.scanned_records >=
                MAX_PRUNE_SCAN_RECORDS_PER_PASS) {
                return false;
            }
            return progress.scanned_value_bytes + value_size <=
                   MAX_PRUNE_VALUE_BYTES_PER_PASS;
        };
        const auto note_scan = [&](std::size_t value_size) {
            ++progress.scanned_records;
            progress.scanned_value_bytes += value_size;
        };
        const uint32_t floor{checkpoint.prune_through_epoch};
        CDBBatch batch{m_db};
        bool phase_complete{false};
        const bool running_epoch_erase{
            intent.phase == PrunePhase::ERASE_EPOCHS};

        if (intent.phase == PrunePhase::VALIDATE_WITNESSES) {
            std::unique_ptr<CDBIterator> iterator{m_db.NewIterator()};
            if (intent.has_cursor) {
                iterator->Seek(WitnessKey{
                    DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                    m_genesis_hash, intent.witness_cursor});
            } else {
                iterator->Seek(DB_WITNESS_PREFIX);
            }
            while (iterator->Valid()) {
                uint8_t prefix{0};
                if (!iterator->GetKey(prefix)) {
                    throw CorruptArchiveIndex{};
                }
                if (prefix != DB_WITNESS_PREFIX) {
                    phase_complete = true;
                    break;
                }
                WitnessKey key;
                const std::size_t value_size{iterator->GetValueSize()};
                if (!iterator->GetKeyExact(key) ||
                    key.prefix != DB_WITNESS_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    key.witness_id.IsNull() ||
                    value_size > AUDIT_RECORD_MAX_SIZE) {
                    throw CorruptArchiveIndex{};
                }
                if (!can_scan(value_size)) {
                    intent.has_cursor = true;
                    intent.witness_cursor = key.witness_id;
                    break;
                }
                AuditRecord record;
                if (!iterator->GetValueExact(record) ||
                    !IsRecordValid(record, m_genesis_hash) ||
                    record.witness_id != key.witness_id) {
                    throw CorruptArchiveIndex{};
                }
                note_scan(value_size);
                const uint32_t epoch{
                    record.audit.statement.commitment.seed.epoch};
                if (epoch <= floor) {
                    const auto links{ValidateArchiveLinks(
                        m_db, m_genesis_hash, epoch, key.witness_id,
                        /*require_witness=*/false, progress)};
                    if (links.result ==
                        BoundedReadResult::BUDGET_EXHAUSTED) {
                        intent.has_cursor = true;
                        intent.witness_cursor = key.witness_id;
                        break;
                    }
                    if (links.result != BoundedReadResult::FOUND) {
                        throw CorruptArchiveIndex{};
                    }
                }
                iterator->Next();
            }
            iterator->CheckStatus();
            if (!iterator->Valid()) phase_complete = true;
            if (phase_complete) {
                intent.phase = PrunePhase::VALIDATE_EPOCHS;
                reset_cursor();
            }
        } else if (intent.phase == PrunePhase::VALIDATE_EPOCHS ||
                   intent.phase == PrunePhase::ERASE_EPOCHS) {
            const bool erasing{
                intent.phase == PrunePhase::ERASE_EPOCHS};
            std::unique_ptr<CDBIterator> iterator{m_db.NewIterator()};
            if (intent.has_cursor) {
                iterator->Seek(EpochKey{
                    DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                    m_genesis_hash, intent.epoch_cursor});
            } else {
                iterator->Seek(DB_EPOCH_PREFIX);
            }
            while (iterator->Valid()) {
                uint8_t prefix{0};
                if (!iterator->GetKey(prefix)) {
                    throw CorruptArchiveIndex{};
                }
                if (prefix != DB_EPOCH_PREFIX) {
                    phase_complete = true;
                    break;
                }
                EpochKey key;
                const std::size_t value_size{iterator->GetValueSize()};
                if (!iterator->GetKeyExact(key) ||
                    key.prefix != DB_EPOCH_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    value_size > EPOCH_RECORD_MAX_SIZE) {
                    throw CorruptArchiveIndex{};
                }
                if (!can_scan(value_size) ||
                    (erasing && progress.erased_records >=
                                     MAX_PRUNE_ERASE_RECORDS_PER_PASS)) {
                    intent.has_cursor = true;
                    intent.epoch_cursor = key.epoch;
                    break;
                }
                EpochRecord record;
                if (!iterator->GetValueExact(record) ||
                    !IsEpochRecordValid(record, key.epoch)) {
                    throw CorruptArchiveIndex{};
                }
                note_scan(value_size);
                // Epoch integers serialize little-endian, so their LevelDB
                // order is not numeric. Retained rows cannot terminate this
                // scan; a later physical key may still be below the floor.
                if (key.epoch > floor) {
                    iterator->Next();
                    continue;
                }
                if (!erasing) {
                    bool budget_exhausted{false};
                    const auto validate_witness = [&](
                        const uint256& witness_id) {
                        if (witness_id.IsNull()) return true;
                        const auto links{ValidateArchiveLinks(
                            m_db, m_genesis_hash, key.epoch, witness_id,
                            /*require_witness=*/true, progress)};
                        if (links.result ==
                            BoundedReadResult::BUDGET_EXHAUSTED) {
                            budget_exhausted = true;
                            return false;
                        }
                        if (links.result != BoundedReadResult::FOUND) {
                            throw CorruptArchiveIndex{};
                        }
                        return true;
                    };
                    if (!validate_witness(record.pinned_witness_id)) {
                        intent.has_cursor = true;
                        intent.epoch_cursor = key.epoch;
                        break;
                    }
                    for (const auto& witness_id :
                         record.live_candidates_by_missing_quorum) {
                        if (!validate_witness(witness_id)) {
                            break;
                        }
                    }
                    if (budget_exhausted) {
                        intent.has_cursor = true;
                        intent.epoch_cursor = key.epoch;
                        break;
                    }
                } else {
                    batch.Erase(key);
                    ++progress.erased_records;
                }
                iterator->Next();
            }
            iterator->CheckStatus();
            if (!iterator->Valid()) phase_complete = true;
            if (phase_complete && !erasing) {
                intent.phase = PrunePhase::VALIDATE_REFERENCES;
                reset_cursor();
            }
        } else {
            const uint8_t prefix{
                intent.phase == PrunePhase::VALIDATE_REFERENCES
                    ? DB_REFERENCE_PREFIX
                    : DB_PRESENCE_PREFIX};
            const bool erasing{
                intent.phase == PrunePhase::ERASE_WITNESSES};
            std::unique_ptr<CDBIterator> iterator{m_db.NewIterator()};
            if (intent.has_cursor) {
                if (prefix == DB_REFERENCE_PREFIX) {
                    iterator->Seek(ReferenceKey{
                        prefix, DB_FORMAT_VERSION, m_genesis_hash,
                        intent.witness_cursor});
                } else {
                    iterator->Seek(PresenceKey{
                        prefix, DB_FORMAT_VERSION, m_genesis_hash,
                        intent.witness_cursor});
                }
            } else {
                iterator->Seek(prefix);
            }
            while (iterator->Valid()) {
                uint8_t found_prefix{0};
                if (!iterator->GetKey(found_prefix)) {
                    throw CorruptArchiveIndex{};
                }
                if (found_prefix != prefix) {
                    phase_complete = true;
                    break;
                }
                const std::size_t value_size{iterator->GetValueSize()};
                uint256 witness_id;
                uint32_t epoch{0};
                if (prefix == DB_REFERENCE_PREFIX) {
                    ReferenceKey key;
                    if (!iterator->GetKeyExact(key) ||
                        key.prefix != prefix ||
                        key.version != DB_FORMAT_VERSION ||
                        key.genesis_hash != m_genesis_hash ||
                        key.witness_id.IsNull() ||
                        value_size > SMALL_INDEX_RECORD_MAX_SIZE) {
                        throw CorruptArchiveIndex{};
                    }
                    witness_id = key.witness_id;
                    if (!can_scan(value_size)) {
                        intent.has_cursor = true;
                        intent.witness_cursor = witness_id;
                        break;
                    }
                    ReferenceRecord record;
                    if (!iterator->GetValueExact(record) ||
                        !IsReferenceRecordValid(
                            record, record.epoch, witness_id)) {
                        throw CorruptArchiveIndex{};
                    }
                    epoch = record.epoch;
                } else {
                    PresenceKey key;
                    if (!iterator->GetKeyExact(key) ||
                        key.prefix != prefix ||
                        key.version != DB_FORMAT_VERSION ||
                        key.genesis_hash != m_genesis_hash ||
                        key.witness_id.IsNull() ||
                        value_size > SMALL_INDEX_RECORD_MAX_SIZE) {
                        throw CorruptArchiveIndex{};
                    }
                    witness_id = key.witness_id;
                    if (!can_scan(value_size)) {
                        intent.has_cursor = true;
                        intent.witness_cursor = witness_id;
                        break;
                    }
                    PresenceRecord record;
                    if (!iterator->GetValueExact(record) ||
                        !IsPresenceRecordValid(
                            record, record.epoch, witness_id)) {
                        throw CorruptArchiveIndex{};
                    }
                    epoch = record.epoch;
                }
                note_scan(value_size);
                bool has_reference{false};
                if (epoch <= floor) {
                    const auto links{ValidateArchiveLinks(
                        m_db, m_genesis_hash, epoch, witness_id,
                        /*require_witness=*/true, progress)};
                    if (links.result ==
                        BoundedReadResult::BUDGET_EXHAUSTED) {
                        intent.has_cursor = true;
                        intent.witness_cursor = witness_id;
                        break;
                    }
                    if (links.result != BoundedReadResult::FOUND) {
                        throw CorruptArchiveIndex{};
                    }
                    has_reference = links.has_reference;
                }
                const std::size_t erase_count{
                    erasing && epoch <= floor
                        ? 2 + static_cast<std::size_t>(has_reference)
                        : 0};
                if (progress.erased_records + erase_count >
                    MAX_PRUNE_ERASE_RECORDS_PER_PASS) {
                    intent.has_cursor = true;
                    intent.witness_cursor = witness_id;
                    break;
                }
                if (erasing && epoch <= floor) {
                    batch.Erase(WitnessKey{
                        DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                        m_genesis_hash, witness_id});
                    if (has_reference) {
                        batch.Erase(ReferenceKey{
                            DB_REFERENCE_PREFIX, DB_FORMAT_VERSION,
                            m_genesis_hash, witness_id});
                    }
                    batch.Erase(PresenceKey{
                        DB_PRESENCE_PREFIX, DB_FORMAT_VERSION,
                        m_genesis_hash, witness_id});
                    progress.erased_records += erase_count;
                }
                iterator->Next();
            }
            iterator->CheckStatus();
            if (!iterator->Valid()) phase_complete = true;
            if (phase_complete) {
                if (intent.phase == PrunePhase::VALIDATE_REFERENCES) {
                    intent.phase = PrunePhase::VALIDATE_PRESENCE;
                    reset_cursor();
                } else if (intent.phase ==
                           PrunePhase::VALIDATE_PRESENCE) {
                    intent.phase = PrunePhase::ERASE_WITNESSES;
                    reset_cursor();
                } else {
                    intent.phase = PrunePhase::ERASE_EPOCHS;
                    reset_cursor();
                }
            }
        }

        const bool completed_epoch_erase{
            running_epoch_erase && phase_complete};
        if (completed_epoch_erase) {
            batch.Write(DB_CHECKPOINT_KEY,
                        CheckpointRecord{DB_FORMAT_VERSION, checkpoint,
                                         CHECKPOINT_GUARD});
            batch.Erase(DB_PRUNE_INTENT_KEY);
        } else {
            batch.Write(DB_PRUNE_INTENT_KEY, make_disk_intent());
        }
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
            return progress;
        }
        if (completed_epoch_erase) {
            m_prune_checkpoint = checkpoint;
            m_prune_intent.reset();
            progress.status = PaymentAuditPruneStatus::COMPLETE;
        } else {
            progress.status = PaymentAuditPruneStatus::IN_PROGRESS;
        }
        return progress;
    } catch (const CorruptArchiveIndex&) {
        // No physical pruning occurs until every target index has passed all
        // validation phases. Restore the pre-request database shape when
        // validation itself rejects the archive; once erasure starts, the
        // durable intent must remain so restart can finish the prefix.
        if (m_prune_intent &&
            m_prune_intent->phase < PrunePhase::ERASE_WITNESSES) {
            if (!m_db.Erase(DB_PRUNE_INTENT_KEY, true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
                return progress;
            }
            m_prune_intent.reset();
        }
        m_failure = PaymentAuditStoreResult::CORRUPT;
        progress.status = PaymentAuditPruneStatus::CORRUPT;
        return progress;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        progress.status = PaymentAuditPruneStatus::DATABASE_ERROR;
        return progress;
    }
}

std::optional<PaymentAuditStoreCheckpoint>
PaymentAuditStore::GetPruneCheckpoint() const
{
    LOCK(m_mutex);
    return m_failure ? std::nullopt : m_prune_checkpoint;
}

std::optional<PaymentAuditStoreCheckpoint>
PaymentAuditStore::GetPendingPruneCheckpoint() const
{
    LOCK(m_mutex);
    return m_failure || !m_prune_intent
               ? std::nullopt
               : std::optional<PaymentAuditStoreCheckpoint>{
                     m_prune_intent->checkpoint};
}

} // namespace llmq::pq
