// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_store.h>

#include <algorithm>
#include <array>
#include <exception>
#include <ios>
#include <limits>
#include <map>
#include <set>
#include <vector>

namespace llmq::pq {
namespace {

constexpr uint8_t DB_SCHEMA_KEY{0xa0};
constexpr uint8_t DB_WITNESS_PREFIX{0xa1};
constexpr uint8_t DB_EPOCH_PREFIX{0xa2};
constexpr uint8_t DB_REFERENCE_PREFIX{0xa3};
constexpr uint8_t DB_PRESENCE_PREFIX{0xa4};
constexpr uint8_t DB_CHECKPOINT_KEY{0xa5};
// Changing the archive layout must fail closed against an old local DB.
constexpr uint32_t SCHEMA_GUARD{0x50414131}; // "PAA1"
constexpr uint32_t WITNESS_GUARD{0x50575231}; // "PWR1"
constexpr uint32_t EPOCH_GUARD{0x50455231}; // "PER1"
constexpr uint32_t REFERENCE_GUARD{0x50524631}; // "PRF1"
constexpr uint32_t PRESENCE_GUARD{0x50525031}; // "PRP1"
constexpr uint32_t CHECKPOINT_GUARD{0x50414331}; // "PAC1"

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
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid payment-audit checkpoint size");
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

static_assert(CheckpointRecord::WIRE_SIZE == 316);

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
        const SchemaValue expected_schema{
            DB_FORMAT_VERSION, SCHEMA_GUARD, m_genesis_hash,
            PAYMENT_AUDIT_VERSION,
            PAYMENT_AUDIT_RECEIPT_VERSION,
            CHILD_SCHEDULED_WOTS_SHAKE_128_V1,
            SCHEDULED_WOTS_USAGE_CAP,
            CHILD_SIGNATURE_SIZE,
            FinalPaymentAudit::WIRE_SIZE};
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
        if (!m_db.Read(DB_SCHEMA_KEY, schema) ||
            schema != expected_schema) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return;
        }
        if (m_db.Exists(DB_CHECKPOINT_KEY)) {
            CheckpointRecord record;
            if (!m_db.Read(DB_CHECKPOINT_KEY, record) ||
                !IsCheckpointRecordValid(record)) {
                m_failure = PaymentAuditStoreResult::CORRUPT;
                return;
            }
            m_prune_checkpoint = record.checkpoint;
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

PaymentAuditStoreResult PaymentAuditStore::ProbeLiveCandidateSlot(
    uint32_t epoch, uint8_t selected_quorum_mask) const
{
    LOCK(m_mutex);
    if (m_failure) return *m_failure;
    const auto missing_quorum_slot{
        MissingQuorumSlot(selected_quorum_mask)};
    if (!missing_quorum_slot) return PaymentAuditStoreResult::INVALID;
    if (m_prune_checkpoint &&
        epoch <= m_prune_checkpoint->prune_through_epoch) {
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
    if (m_prune_checkpoint &&
        epoch <= m_prune_checkpoint->prune_through_epoch) {
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
            if (!HasValidPresence(m_db, m_genesis_hash, epoch, witness_id) &&
                !m_db.Write(
                    presence_key,
                    PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                   PRESENCE_GUARD},
                    true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                return *m_failure;
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
            if (!m_db.WriteBatch(repair, true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                return *m_failure;
            }
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
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            return *m_failure;
        }
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
    if (m_failure || witness_id.IsNull()) return std::nullopt;
    try {
        const WitnessKey key{DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                             m_genesis_hash, witness_id};
        const PresenceKey presence_key{
            DB_PRESENCE_PREFIX, DB_FORMAT_VERSION, m_genesis_hash,
            witness_id};
        AuditRecord record;
        if (!m_db.Read(key, record)) {
            // A stale tiny index must never suppress exact-witness healing.
            // Remove both sides atomically; a required response can then
            // repopulate the fully verified payload and its presence key.
            if (m_db.Exists(presence_key)) {
                CDBBatch repair{m_db};
                repair.Erase(key);
                repair.Erase(presence_key);
                if (!m_db.WriteBatch(repair, true)) {
                    m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
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
        if (m_prune_checkpoint &&
            epoch <= m_prune_checkpoint->prune_through_epoch) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return std::nullopt;
        }
        if (!HasValidPresence(m_db, m_genesis_hash, epoch, witness_id)) {
            if (!m_db.Write(
                    presence_key,
                    PresenceRecord{DB_FORMAT_VERSION, epoch, witness_id,
                                   PRESENCE_GUARD},
                    true)) {
                m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
                return std::nullopt;
            }
        }
        return record.audit;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return std::nullopt;
    }
}

std::vector<FinalPaymentAudit> PaymentAuditStore::GetEpochCandidates(
    uint32_t epoch) const
{
    LOCK(m_mutex);
    std::vector<FinalPaymentAudit> result;
    if (m_failure) return result;
    if (m_prune_checkpoint &&
        epoch <= m_prune_checkpoint->prune_through_epoch) {
        return result;
    }
    try {
        const EpochKey epoch_key{DB_EPOCH_PREFIX, DB_FORMAT_VERSION,
                                 m_genesis_hash, epoch};
        EpochRecord epoch_record;
        if (!m_db.Exists(epoch_key)) return result;
        if (!m_db.Read(epoch_key, epoch_record) ||
            !IsEpochRecordValid(epoch_record, epoch)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return {};
        }
        if (!epoch_record.pinned_witness_id.IsNull() &&
            !HasValidReference(m_db, m_genesis_hash, epoch,
                               epoch_record.pinned_witness_id)) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
            return {};
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
        result.reserve(ids.size());
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
                return {};
            }
            result.push_back(std::move(record.audit));
        }
        return result;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return {};
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
        if (m_prune_checkpoint &&
            presence.epoch <=
                m_prune_checkpoint->prune_through_epoch) {
            m_failure = PaymentAuditStoreResult::CORRUPT;
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
    if (m_prune_checkpoint &&
        epoch <= m_prune_checkpoint->prune_through_epoch) {
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
        for (auto& candidate :
             epoch_record.live_candidates_by_missing_quorum) {
            if (candidate.IsNull()) continue;
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
        if (!has_reference) {
            batch.Write(reference_key,
                        ReferenceRecord{DB_FORMAT_VERSION, epoch,
                                        witness_id, REFERENCE_GUARD});
        }
        epoch_record.pinned_witness_id = witness_id;
        batch.Write(epoch_key, epoch_record);
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            return *m_failure;
        }
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
    LOCK(m_mutex);
    if (m_failure || !checkpoint.IsStructurallyValid()) return false;
    if (m_prune_checkpoint) {
        if (checkpoint == *m_prune_checkpoint) return true;
        if (!IsCheckpointAdvance(*m_prune_checkpoint, checkpoint)) {
            return false;
        }
    }

    try {
        std::map<uint256, uint32_t> witness_epochs;
        std::map<uint256, uint32_t> presence_epochs;
        std::map<uint256, uint32_t> reference_epochs;
        std::map<uint256, uint32_t> epoch_index_epochs;
        std::set<uint32_t> epoch_records;
        std::set<uint256> pinned_witnesses;
        std::set<uint256> live_candidate_witnesses;
        std::vector<EpochKey> epoch_keys_to_prune;
        bool found_schema{false};
        bool found_checkpoint{false};

        const auto note_epoch = [](auto& index, const uint256& witness_id,
                                   uint32_t epoch) {
            if (witness_id.IsNull()) return false;
            const auto [position, inserted]{index.emplace(witness_id, epoch)};
            return inserted || position->second == epoch;
        };
        std::unique_ptr<CDBIterator> iterator{m_db.NewIterator()};
        for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
            uint8_t prefix{0};
            if (!iterator->GetKey(prefix)) throw CorruptArchiveIndex{};
            if (prefix == DB_SCHEMA_KEY) {
                if (found_schema) throw CorruptArchiveIndex{};
                found_schema = true;
                continue;
            }

            if (prefix == DB_WITNESS_PREFIX) {
                WitnessKey key;
                if (!iterator->GetKey(key) ||
                    key.prefix != DB_WITNESS_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    key.witness_id.IsNull()) {
                    throw CorruptArchiveIndex{};
                }
                // Presence records carry the epoch so pruning never needs to
                // decode the multi-megabyte witness value.
                if (!witness_epochs.emplace(
                        key.witness_id,
                        std::numeric_limits<uint32_t>::max()).second) {
                    throw CorruptArchiveIndex{};
                }
                continue;
            }

            if (prefix == DB_EPOCH_PREFIX) {
                EpochKey key;
                EpochRecord record;
                if (!iterator->GetKey(key) ||
                    key.prefix != DB_EPOCH_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    !iterator->GetValue(record) ||
                    !IsEpochRecordValid(record, key.epoch) ||
                    !epoch_records.insert(key.epoch).second) {
                    throw CorruptArchiveIndex{};
                }
                if (!record.pinned_witness_id.IsNull()) {
                    if (!note_epoch(epoch_index_epochs,
                                    record.pinned_witness_id, key.epoch) ||
                        !pinned_witnesses.insert(
                            record.pinned_witness_id).second) {
                        throw CorruptArchiveIndex{};
                    }
                }
                for (const auto& witness_id :
                     record.live_candidates_by_missing_quorum) {
                    if (witness_id.IsNull()) continue;
                    if (!note_epoch(epoch_index_epochs, witness_id,
                                    key.epoch) ||
                        !live_candidate_witnesses.insert(witness_id).second) {
                        throw CorruptArchiveIndex{};
                    }
                }
                if (key.epoch <= checkpoint.prune_through_epoch) {
                    epoch_keys_to_prune.push_back(key);
                }
                continue;
            }

            if (prefix == DB_REFERENCE_PREFIX) {
                ReferenceKey key;
                ReferenceRecord record;
                if (!iterator->GetKey(key) ||
                    key.prefix != DB_REFERENCE_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    key.witness_id.IsNull() ||
                    !iterator->GetValue(record) ||
                    !IsReferenceRecordValid(record, record.epoch,
                                            key.witness_id) ||
                    !note_epoch(reference_epochs, key.witness_id,
                                record.epoch)) {
                    throw CorruptArchiveIndex{};
                }
                continue;
            }

            if (prefix == DB_PRESENCE_PREFIX) {
                PresenceKey key;
                PresenceRecord record;
                if (!iterator->GetKey(key) ||
                    key.prefix != DB_PRESENCE_PREFIX ||
                    key.version != DB_FORMAT_VERSION ||
                    key.genesis_hash != m_genesis_hash ||
                    key.witness_id.IsNull() ||
                    !iterator->GetValue(record) ||
                    !IsPresenceRecordValid(record, record.epoch,
                                           key.witness_id) ||
                    !note_epoch(presence_epochs, key.witness_id,
                                record.epoch)) {
                    throw CorruptArchiveIndex{};
                }
                continue;
            }

            if (prefix == DB_CHECKPOINT_KEY) {
                CheckpointRecord record;
                if (found_checkpoint || !iterator->GetValue(record) ||
                    !IsCheckpointRecordValid(record) ||
                    !m_prune_checkpoint ||
                    record.checkpoint != *m_prune_checkpoint) {
                    throw CorruptArchiveIndex{};
                }
                found_checkpoint = true;
                continue;
            }
            throw CorruptArchiveIndex{};
        }

        if (!found_schema ||
            found_checkpoint != m_prune_checkpoint.has_value() ||
            witness_epochs.size() != presence_epochs.size()) {
            throw CorruptArchiveIndex{};
        }
        for (auto& [witness_id, epoch] : witness_epochs) {
            const auto presence{presence_epochs.find(witness_id)};
            if (presence == presence_epochs.end()) {
                throw CorruptArchiveIndex{};
            }
            epoch = presence->second;
        }
        for (const auto& [witness_id, epoch] : presence_epochs) {
            if (!witness_epochs.contains(witness_id) ||
                !epoch_records.contains(epoch)) {
                throw CorruptArchiveIndex{};
            }
            const auto indexed{epoch_index_epochs.find(witness_id)};
            const auto referenced{reference_epochs.find(witness_id)};
            if ((indexed == epoch_index_epochs.end() ||
                 indexed->second != epoch) &&
                (referenced == reference_epochs.end() ||
                 referenced->second != epoch)) {
                throw CorruptArchiveIndex{};
            }
        }
        for (const auto& [witness_id, epoch] : epoch_index_epochs) {
            const auto presence{presence_epochs.find(witness_id)};
            if (presence == presence_epochs.end() ||
                presence->second != epoch) {
                throw CorruptArchiveIndex{};
            }
        }
        for (const auto& [witness_id, epoch] : reference_epochs) {
            const auto presence{presence_epochs.find(witness_id)};
            if (presence == presence_epochs.end() ||
                presence->second != epoch ||
                !epoch_records.contains(epoch) ||
                live_candidate_witnesses.contains(witness_id)) {
                throw CorruptArchiveIndex{};
            }
        }
        for (const auto& witness_id : pinned_witnesses) {
            if (!reference_epochs.contains(witness_id)) {
                throw CorruptArchiveIndex{};
            }
        }

        CDBBatch batch{m_db};
        for (const auto& key : epoch_keys_to_prune) batch.Erase(key);
        for (const auto& [witness_id, epoch] : presence_epochs) {
            if (epoch > checkpoint.prune_through_epoch) continue;
            batch.Erase(WitnessKey{DB_WITNESS_PREFIX, DB_FORMAT_VERSION,
                                   m_genesis_hash, witness_id});
            batch.Erase(ReferenceKey{DB_REFERENCE_PREFIX, DB_FORMAT_VERSION,
                                     m_genesis_hash, witness_id});
            batch.Erase(PresenceKey{DB_PRESENCE_PREFIX, DB_FORMAT_VERSION,
                                    m_genesis_hash, witness_id});
        }
        batch.Write(DB_CHECKPOINT_KEY,
                    CheckpointRecord{DB_FORMAT_VERSION, checkpoint,
                                     CHECKPOINT_GUARD});
        if (!m_db.WriteBatch(batch, true)) {
            m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
            return false;
        }
        m_prune_checkpoint = checkpoint;
        return true;
    } catch (const CorruptArchiveIndex&) {
        m_failure = PaymentAuditStoreResult::CORRUPT;
        return false;
    } catch (const std::exception&) {
        m_failure = PaymentAuditStoreResult::DATABASE_ERROR;
        return false;
    }
}

std::optional<PaymentAuditStoreCheckpoint>
PaymentAuditStore::GetPruneCheckpoint() const
{
    LOCK(m_mutex);
    return m_failure ? std::nullopt : m_prune_checkpoint;
}

} // namespace llmq::pq
