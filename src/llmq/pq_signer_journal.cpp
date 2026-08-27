// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_signer_journal.h>

#include <llmq/pq_chainlock_types.h>

#include <hash.h>

#include <algorithm>
#include <exception>
#include <string_view>
#include <tuple>

namespace llmq {
namespace {

constexpr std::uint8_t DB_SCHEMA_KEY{0x70};
constexpr std::uint8_t DB_SLOT_PREFIX{0x72};
constexpr std::uint8_t DB_BRANCH_LOCK_PREFIX{0x73};
constexpr std::uint8_t DB_ACCEPTED_CERTIFICATE_PREFIX{0x74};
constexpr std::uint32_t SCHEMA_GUARD{0x50514a31}; // "PQJ1"
constexpr std::uint32_t SLOT_GUARD{0x534c5431};   // "SLT1"
constexpr std::uint32_t BRANCH_LOCK_GUARD{0x42524c31}; // "BRL1"
constexpr std::uint32_t ACCEPTED_CERTIFICATE_GUARD{0x41434331}; // "ACC1"
constexpr std::uint8_t SLOT_RESERVED{1};
constexpr std::uint8_t SLOT_SIGNED{2};
constexpr std::string_view STARTUP_CONSUMED_DOMAIN{
    "SYS_PQ_SIGNER_STARTUP_CONSUMED_V1"};

struct SchemaValue
{
    std::uint32_t version{CPQSignerJournal::DB_FORMAT_VERSION};
    std::uint32_t guard{SCHEMA_GUARD};
    std::uint16_t child_profile{pq::CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    std::uint16_t usage_cap{PQ_CHILD_USAGE_CAP};
    std::uint32_t signature_size{PQ_CHILD_SIGNATURE_SIZE};

    SERIALIZE_METHODS(SchemaValue, obj)
    {
        READWRITE(obj.version, obj.guard, obj.child_profile, obj.usage_cap,
                  obj.signature_size);
    }

    friend bool operator==(const SchemaValue&, const SchemaValue&) = default;
};

struct SlotDatabaseKey
{
    std::uint8_t prefix{DB_SLOT_PREFIX};
    std::uint32_t db_version{CPQSignerJournal::DB_FORMAT_VERSION};
    PQSignerJournalLeafKey key;

    explicit SlotDatabaseKey(const PQSignerJournalKey& key_in) : key{key_in} {}

    SERIALIZE_METHODS(SlotDatabaseKey, obj)
    {
        READWRITE(obj.prefix, obj.db_version, obj.key);
    }
};

struct SlotValue
{
    std::uint32_t version{CPQSignerJournal::DB_FORMAT_VERSION};
    std::uint8_t state{SLOT_RESERVED};
    PQSignerJournalKey logical_key;
    uint256 message_hash;
    PQChildSignature signature{};
    std::uint32_t guard{SLOT_GUARD};

    SERIALIZE_METHODS(SlotValue, obj)
    {
        // Keeping this fixed-size makes truncated and state-confused records
        // fail deserialization instead of being interpreted permissively.
        READWRITE(obj.version,
                  obj.state,
                  obj.logical_key,
                  obj.message_hash,
                  obj.signature,
                  obj.guard);
    }
};

struct BranchLockDatabaseKey
{
    std::uint8_t prefix{DB_BRANCH_LOCK_PREFIX};
    std::uint32_t db_version{CPQSignerJournal::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 pro_tx_hash;

    BranchLockDatabaseKey(const uint256& genesis_hash_in,
                          const uint256& pro_tx_hash_in)
        : genesis_hash{genesis_hash_in}, pro_tx_hash{pro_tx_hash_in}
    {
    }

    SERIALIZE_METHODS(BranchLockDatabaseKey, obj)
    {
        READWRITE(obj.prefix, obj.db_version, obj.genesis_hash,
                  obj.pro_tx_hash);
    }
};

struct BranchLockValue
{
    std::uint32_t version{CPQSignerJournal::DB_FORMAT_VERSION};
    PQSignerBranchLock lock;
    std::uint32_t guard{BRANCH_LOCK_GUARD};

    SERIALIZE_METHODS(BranchLockValue, obj)
    {
        READWRITE(obj.version, obj.lock, obj.guard);
    }
};

struct AcceptedCertificateDatabaseKey
{
    std::uint8_t prefix{DB_ACCEPTED_CERTIFICATE_PREFIX};
    std::uint32_t db_version{CPQSignerJournal::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 pro_tx_hash;

    AcceptedCertificateDatabaseKey(const uint256& genesis_hash_in,
                                   const uint256& pro_tx_hash_in)
        : genesis_hash{genesis_hash_in}, pro_tx_hash{pro_tx_hash_in}
    {
    }

    SERIALIZE_METHODS(AcceptedCertificateDatabaseKey, obj)
    {
        READWRITE(obj.prefix, obj.db_version, obj.genesis_hash,
                  obj.pro_tx_hash);
    }
};

struct AcceptedCertificateValue
{
    std::uint32_t version{CPQSignerJournal::DB_FORMAT_VERSION};
    PQSignerBranchLock lock;
    uint256 logical_id;
    uint256 witness_id;
    std::uint32_t guard{ACCEPTED_CERTIFICATE_GUARD};

    SERIALIZE_METHODS(AcceptedCertificateValue, obj)
    {
        READWRITE(obj.version, obj.lock, obj.logical_id, obj.witness_id,
                  obj.guard);
    }

    bool operator==(const AcceptedCertificateValue&) const = default;
};

bool IsValidKey(const PQSignerJournalKey& key)
{
    const bool leaf_matches_purpose{
        (key.purpose == PQSignerPurpose::CHAINLOCK &&
         key.leaf_index < pq::SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE) ||
        (key.purpose == PQSignerPurpose::PAYMENT_AUDIT &&
         key.leaf_index >= pq::SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE &&
         key.leaf_index < PQ_CHILD_USAGE_CAP)};
    return !key.genesis_hash.IsNull() &&
           key.child_profile == pq::CHILD_SCHEDULED_WOTS_SHAKE_128_V1 &&
           !key.pro_tx_hash.IsNull() &&
           !key.child_key_hash.IsNull() &&
           leaf_matches_purpose &&
           key.absolute_height >= 0;
}

uint256 StartupConsumedMessageHash(const PQSignerJournalKey& key)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{STARTUP_CONSUMED_DOMAIN.data(),
                              STARTUP_CONSUMED_DOMAIN.size()}));
    writer << key;
    return writer.GetHash();
}

bool IsStartupConsumed(const SlotValue& slot)
{
    return slot.state == SLOT_RESERVED &&
           slot.message_hash == StartupConsumedMessageHash(slot.logical_key);
}

bool IsValidSlot(const SlotValue& slot)
{
    if (slot.version != CPQSignerJournal::DB_FORMAT_VERSION ||
        slot.guard != SLOT_GUARD || !IsValidKey(slot.logical_key)) {
        return false;
    }
    if (slot.state == SLOT_SIGNED) return true;
    if (slot.state != SLOT_RESERVED) return false;
    return std::all_of(slot.signature.begin(), slot.signature.end(), [](unsigned char byte) {
        return byte == 0;
    });
}

bool IsValidBranchLock(const BranchLockValue& value)
{
    return value.version == CPQSignerJournal::DB_FORMAT_VERSION &&
           value.guard == BRANCH_LOCK_GUARD &&
           value.lock.IsStructurallyValid();
}

bool IsValidAcceptedCertificate(const AcceptedCertificateValue& value)
{
    return value.version == CPQSignerJournal::DB_FORMAT_VERSION &&
           value.guard == ACCEPTED_CERTIFICATE_GUARD &&
           value.lock.IsStructurallyValid() &&
           value.lock.statement_hash == value.logical_id &&
           !value.witness_id.IsNull();
}

bool IsValidBranchIdentity(const uint256& genesis_hash,
                           const uint256& pro_tx_hash)
{
    return !genesis_hash.IsNull() && !pro_tx_hash.IsNull();
}

PQSignerJournalResult Result(PQSignerJournalOutcome outcome)
{
    return {.outcome = outcome, .signature = std::nullopt};
}

PQSignerJournalResult Replay(const PQChildSignature& signature)
{
    return {.outcome = PQSignerJournalOutcome::REPLAY, .signature = signature};
}

} // namespace

bool PQSignerJournalKey::operator<(const PQSignerJournalKey& other) const
{
    return std::tie(genesis_hash,
                    child_profile,
                    pro_tx_hash,
                    quorum_epoch,
                    child_key_hash,
                    leaf_index,
                    purpose,
                    absolute_height) <
           std::tie(other.genesis_hash,
                    other.child_profile,
                    other.pro_tx_hash,
                    other.quorum_epoch,
                    other.child_key_hash,
                    other.leaf_index,
                    other.purpose,
                    other.absolute_height);
}

bool PQSignerJournalLeafKey::operator<(
    const PQSignerJournalLeafKey& other) const
{
    return std::tie(genesis_hash, child_profile, pro_tx_hash, quorum_epoch,
                    child_key_hash, leaf_index) <
           std::tie(other.genesis_hash, other.child_profile,
                    other.pro_tx_hash, other.quorum_epoch,
                    other.child_key_hash, other.leaf_index);
}

CPQSignerJournal::CPQSignerJournal(const fs::path& path, std::size_t cache_bytes) :
    m_db{DBParams{
        .path = path,
        .cache_bytes = cache_bytes,
        .memory_only = false,
        .wipe_data = false,
        .obfuscate = false}}
{
    Initialize();
}

void CPQSignerJournal::Initialize()
{
    LOCK(m_mutex);
    try {
        if (!m_db.Exists(DB_SCHEMA_KEY)) {
            // A schema-less nonempty store is corrupt or partially restored.
            // Adopting it as empty would refund unknown signatures.
            if (!m_db.IsEmpty()) {
                m_failure = PQSignerJournalOutcome::CORRUPT;
                return;
            }
            if (!m_db.Write(DB_SCHEMA_KEY, SchemaValue{}, /*fSync=*/true)) {
                m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
            }
            return;
        }

        SchemaValue schema;
        if (!m_db.Read(DB_SCHEMA_KEY, schema) || schema != SchemaValue{}) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
        }
    } catch (const std::exception&) {
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
    }
}

PQSignerJournalResult CPQSignerJournal::Reserve(
    const PQSignerJournalKey& key,
    const uint256& message_hash,
    const PQSignerBranchLock& candidate_lock,
    const std::optional<PQSignerBranchLock>& expected_lock)
{
    LOCK(m_mutex);
    if (m_failure) return Result(*m_failure);
    if (!IsValidKey(key) || message_hash.IsNull() ||
        !candidate_lock.IsStructurallyValid() ||
        candidate_lock.height != key.absolute_height ||
        (expected_lock && !expected_lock->IsStructurallyValid())) {
        return Result(PQSignerJournalOutcome::INVALID_ARGUMENT);
    }

    try {
        const BranchLockDatabaseKey branch_key{key.genesis_hash,
                                               key.pro_tx_hash};
        BranchLockValue durable_branch;
        const bool branch_exists = m_db.Exists(branch_key);
        if (branch_exists &&
            (!m_db.Read(branch_key, durable_branch) ||
             !IsValidBranchLock(durable_branch))) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }
        if (branch_exists != expected_lock.has_value() ||
            (branch_exists && durable_branch.lock != *expected_lock)) {
            return Result(PQSignerJournalOutcome::BRANCH_CONFLICT);
        }
        if (branch_exists &&
            (candidate_lock.height < durable_branch.lock.height ||
             (candidate_lock.height == durable_branch.lock.height &&
              candidate_lock != durable_branch.lock))) {
            return Result(PQSignerJournalOutcome::BRANCH_CONFLICT);
        }

        const PQSignerJournalLeafKey leaf_key{key};
        const SlotDatabaseKey slot_key{key};
        SlotValue slot;
        const bool slot_exists = m_db.Exists(slot_key);
        if (slot_exists) {
            if (!m_db.Read(slot_key, slot) || !IsValidSlot(slot) ||
                PQSignerJournalLeafKey{slot.logical_key} != leaf_key) {
                m_failure = PQSignerJournalOutcome::CORRUPT;
                m_pending.clear();
                return Result(*m_failure);
            }
            if (slot.logical_key != key) {
                return Result(PQSignerJournalOutcome::CONFLICT);
            }
            if (IsStartupConsumed(slot)) {
                return Result(PQSignerJournalOutcome::CONSUMED);
            }
            if (slot.message_hash != message_hash) {
                return Result(PQSignerJournalOutcome::CONFLICT);
            }
            if (slot.state == SLOT_SIGNED) return Replay(slot.signature);

            // A second Reserve call cannot establish whether signing started.
            // The original live owner may still commit through StoreSignature.
            return Result(PQSignerJournalOutcome::CONSUMED);
        }

        if (m_pending.find(leaf_key) != m_pending.end()) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }

        SlotValue reserved;
        reserved.logical_key = key;
        reserved.message_hash = message_hash;

        // The physical leaf slot and operator-wide branch lock advance in one
        // atomic batch. Sync=true is the burn-before-sign boundary.
        CDBBatch batch{m_db};
        batch.Write(slot_key, reserved);
        if (!branch_exists || candidate_lock.height > durable_branch.lock.height) {
            batch.Write(branch_key, BranchLockValue{.lock = candidate_lock});
        }
        if (!m_db.WriteBatch(batch, /*fSync=*/true)) {
            m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
            m_pending.clear();
            return Result(*m_failure);
        }

        m_pending.emplace(leaf_key, PendingReservation{message_hash});
        return Result(PQSignerJournalOutcome::RESERVED);
    } catch (const std::exception&) {
        // A failed synchronous write has uncertain durability. Clearing the
        // live ownership prevents this process from attempting the signer.
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
        m_pending.clear();
        return Result(*m_failure);
    }
}

bool CPQSignerJournal::ConsumeIfAbsent(
    const std::vector<PQSignerJournalKey>& keys)
{
    LOCK(m_mutex);
    if (m_failure) return false;

    try {
        std::map<PQSignerJournalLeafKey, PQSignerJournalKey> unique;
        for (const auto& key : keys) {
            if (!IsValidKey(key)) return false;
            const PQSignerJournalLeafKey leaf_key{key};
            const auto [it, inserted]{unique.emplace(leaf_key, key)};
            if (!inserted && it->second != key) return false;
        }

        CDBBatch batch{m_db};
        bool has_writes{false};
        for (const auto& [leaf_key, key] : unique) {
            const SlotDatabaseKey slot_key{key};
            if (m_db.Exists(slot_key)) {
                SlotValue slot;
                if (!m_db.Read(slot_key, slot) || !IsValidSlot(slot) ||
                    PQSignerJournalLeafKey{slot.logical_key} != leaf_key) {
                    m_failure = PQSignerJournalOutcome::CORRUPT;
                    m_pending.clear();
                    return false;
                }
                continue;
            }
            if (m_pending.find(leaf_key) != m_pending.end()) {
                m_failure = PQSignerJournalOutcome::CORRUPT;
                m_pending.clear();
                return false;
            }

            SlotValue consumed;
            consumed.logical_key = key;
            consumed.message_hash = StartupConsumedMessageHash(key);
            batch.Write(slot_key, consumed);
            has_writes = true;
        }
        if (has_writes && !m_db.WriteBatch(batch, /*fSync=*/true)) {
            m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
            m_pending.clear();
            return false;
        }
        return true;
    } catch (const std::exception&) {
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
        m_pending.clear();
        return false;
    }
}

std::optional<PQSignerBranchLock> CPQSignerJournal::GetBranchLock(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash)
{
    LOCK(m_mutex);
    if (m_failure || !IsValidBranchIdentity(genesis_hash, pro_tx_hash)) {
        return std::nullopt;
    }
    try {
        const BranchLockDatabaseKey key{genesis_hash, pro_tx_hash};
        if (!m_db.Exists(key)) return std::nullopt;
        BranchLockValue value;
        if (!m_db.Read(key, value) || !IsValidBranchLock(value)) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return std::nullopt;
        }
        return value.lock;
    } catch (const std::exception&) {
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
        m_pending.clear();
        return std::nullopt;
    }
}

PQSignerJournalResult CPQSignerJournal::ReconcileDurableAcceptedChainLock(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const pq::FinalChainLock& chainlock)
{
    LOCK(m_mutex);
    if (m_failure) return Result(*m_failure);
    if (!IsValidBranchIdentity(genesis_hash, pro_tx_hash) ||
        !chainlock.IsStructurallyValid()) {
        return Result(PQSignerJournalOutcome::INVALID_ARGUMENT);
    }

    const uint256 logical_id{chainlock.GetLogicalId(genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(genesis_hash)};
    const AcceptedCertificateValue accepted{
        .lock = PQSignerBranchLock{
            chainlock.statement.height,
            chainlock.statement.block_hash,
            logical_id},
        .logical_id = logical_id,
        .witness_id = witness_id};
    if (!IsValidAcceptedCertificate(accepted)) {
        return Result(PQSignerJournalOutcome::INVALID_ARGUMENT);
    }

    try {
        const AcceptedCertificateDatabaseKey certificate_key{genesis_hash,
                                                             pro_tx_hash};
        AcceptedCertificateValue durable_certificate;
        const bool certificate_exists{m_db.Exists(certificate_key)};
        if (certificate_exists &&
            (!m_db.Read(certificate_key, durable_certificate) ||
             !IsValidAcceptedCertificate(durable_certificate))) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }

        const BranchLockDatabaseKey branch_key{genesis_hash, pro_tx_hash};
        BranchLockValue durable_branch;
        const bool branch_exists{m_db.Exists(branch_key)};
        if (branch_exists &&
            (!m_db.Read(branch_key, durable_branch) ||
             !IsValidBranchLock(durable_branch))) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }

        if (certificate_exists) {
            if (accepted.lock.height < durable_certificate.lock.height ||
                (accepted.lock.height == durable_certificate.lock.height &&
                 accepted != durable_certificate)) {
                // The finality persistence source supplied an older or
                // conflicting winner. Continuing could turn a restored DB
                // snapshot into authority to re-sign an adjudicated fork.
                m_failure = PQSignerJournalOutcome::CORRUPT;
                m_pending.clear();
                return Result(*m_failure);
            }
            if (accepted == durable_certificate) {
                // The certificate marker and branch lock were committed in
                // one batch. A missing/older/conflicting lock cannot be an
                // interrupted reconciliation and therefore fails closed.
                if (!branch_exists ||
                    durable_branch.lock.height < accepted.lock.height ||
                    (durable_branch.lock.height == accepted.lock.height &&
                     durable_branch.lock != accepted.lock)) {
                    m_failure = PQSignerJournalOutcome::CORRUPT;
                    m_pending.clear();
                    return Result(*m_failure);
                }
                return Result(PQSignerJournalOutcome::CERTIFICATE_REPLAY);
            }
        }

        const bool rebase_branch{
            !branch_exists || durable_branch.lock.height <= accepted.lock.height};
        CDBBatch batch{m_db};
        batch.Write(certificate_key, accepted);
        if (rebase_branch) {
            batch.Write(branch_key, BranchLockValue{.lock = accepted.lock});
        }
        if (!m_db.WriteBatch(batch, /*fSync=*/true)) {
            m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
            m_pending.clear();
            return Result(*m_failure);
        }
        return Result(rebase_branch
                          ? PQSignerJournalOutcome::CERTIFICATE_RECONCILED
                          : PQSignerJournalOutcome::CERTIFICATE_RECORDED);
    } catch (const std::exception&) {
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
        m_pending.clear();
        return Result(*m_failure);
    }
}

PQSignerJournalResult CPQSignerJournal::StoreSignature(
    const PQSignerJournalKey& key,
    const uint256& message_hash,
    const PQChildSignature& signature)
{
    LOCK(m_mutex);
    if (m_failure) return Result(*m_failure);
    if (!IsValidKey(key) || message_hash.IsNull()) {
        return Result(PQSignerJournalOutcome::INVALID_ARGUMENT);
    }

    try {
        const PQSignerJournalLeafKey leaf_key{key};
        const SlotDatabaseKey slot_key{key};
        SlotValue slot;
        const bool slot_exists = m_db.Exists(slot_key);
        if (!slot_exists) {
            if (m_pending.find(leaf_key) != m_pending.end()) {
                m_failure = PQSignerJournalOutcome::CORRUPT;
                m_pending.clear();
                return Result(*m_failure);
            }
            return Result(PQSignerJournalOutcome::NOT_RESERVED);
        }
        if (!m_db.Read(slot_key, slot) || !IsValidSlot(slot) ||
            PQSignerJournalLeafKey{slot.logical_key} != leaf_key) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }
        if (slot.logical_key != key) {
            return Result(PQSignerJournalOutcome::CONFLICT);
        }
        if (IsStartupConsumed(slot)) {
            return Result(PQSignerJournalOutcome::CONSUMED);
        }
        if (slot.message_hash != message_hash) {
            return Result(PQSignerJournalOutcome::CONFLICT);
        }
        if (slot.state == SLOT_SIGNED) return Replay(slot.signature);

        const auto pending = m_pending.find(leaf_key);
        if (pending == m_pending.end()) {
            // This includes RESERVED state loaded after a restart.
            return Result(PQSignerJournalOutcome::CONSUMED);
        }
        if (pending->second.message_hash != message_hash) {
            m_failure = PQSignerJournalOutcome::CORRUPT;
            m_pending.clear();
            return Result(*m_failure);
        }

        slot.state = SLOT_SIGNED;
        slot.signature = signature;
        if (!m_db.Write(slot_key, slot, /*fSync=*/true)) {
            m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
            m_pending.clear();
            return Result(*m_failure);
        }

        m_pending.erase(pending);
        return Result(PQSignerJournalOutcome::STORED);
    } catch (const std::exception&) {
        m_failure = PQSignerJournalOutcome::DATABASE_ERROR;
        m_pending.clear();
        return Result(*m_failure);
    }
}

bool CPQSignerJournal::IsHealthy() const
{
    LOCK(m_mutex);
    return !m_failure.has_value();
}

} // namespace llmq
