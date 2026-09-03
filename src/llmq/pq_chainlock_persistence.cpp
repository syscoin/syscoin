// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_persistence.h>

#include <llmq/pq_roster_beacon.h>

#include <hash.h>
#include <streams.h>
#include <sync.h>

#include <algorithm>
#include <array>
#include <exception>
#include <ios>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace llmq::pq {

bool RosterRecoveryPrecommit::IsStructurallyValid() const noexcept
{
    if (version != ROSTER_RECOVERY_PRECOMMIT_VERSION ||
        !pending_seed.IsStructurallyValid() ||
        (pending_seed.state != RosterBeaconState::PENDING &&
         !pending_seed.IsReady()) ||
        pending_seed.epoch % ACTIVE_QUORUMS != ACTIVE_QUORUMS - 1) {
        return false;
    }
    return pending_seed.anchor_kind == RosterBeaconAnchorKind::NORMAL;
}

bool GetRecoveryRosterRetentionDependency(
    const ChainLockStatement& statement,
    std::optional<RecoveryRosterRetentionDependency>& dependency) noexcept
{
    dependency.reset();
    std::optional<uint32_t> first_epoch;
    for (const auto& seed : statement.roster_beacons.active.seeds) {
        if (seed.anchor_kind != RosterBeaconAnchorKind::RECOVERY) continue;
        const uint32_t candidate{
            seed.epoch - seed.epoch % static_cast<uint32_t>(ACTIVE_QUORUMS)};
        if (first_epoch && *first_epoch != candidate) return false;
        first_epoch = candidate;
    }
    if (first_epoch) {
        if (statement.height < 0) return false;
        dependency = RecoveryRosterRetentionDependency{
            statement.height, *first_epoch};
    }
    return true;
}

namespace {

bool IsRecoverySourceBoundWindow(
    const RosterBeaconWindow& window) noexcept
{
    if (!window.IsStructurallyValid() ||
        !HasRecoveryRosterBeacon(window)) {
        return window.IsStructurallyValid();
    }
    const auto& source{
        window.active.recovery_authority_source.normal_beacon};
    if (!source.IsReady() ||
        source.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        return false;
    }
    bool reached_normal_suffix{false};
    for (const auto& seed : window.active.seeds) {
        if (seed.anchor_kind == RosterBeaconAnchorKind::NORMAL) {
            reached_normal_suffix = true;
            continue;
        }
        if (reached_normal_suffix ||
            seed.anchor_kind != RosterBeaconAnchorKind::RECOVERY ||
            seed.anchor_cursor != source.anchor_cursor ||
            seed.anchor_btc_height != source.anchor_btc_height ||
            seed.future_btc_hash != source.future_btc_hash) {
            return false;
        }
    }
    return true;
}

} // namespace

PaymentAuditSealContextCapsule::PaymentAuditSealContextCapsule(
    uint32_t epoch,
    int32_t carrier_end_height_exclusive,
    FinalChainLockRecordMetadata seal,
    uint8_t authorization_mask)
    : m_epoch{epoch},
      m_carrier_end_height_exclusive{carrier_end_height_exclusive},
      m_seal{std::move(seal)},
      m_authorization_mask{authorization_mask}
{
}

bool PaymentAuditSealContextCapsule::IsInternallyConsistent(
    const uint256& genesis_hash,
    const ChainLockFinalityStoreConfig& config) const noexcept
{
    if (m_version != PAYMENT_AUDIT_SEAL_CONTEXT_VERSION ||
        !config.IsValid() || !m_seal.IsInternallyConsistent(genesis_hash)) {
        return false;
    }
    const PaymentAuditScheduleConfig schedule{
        config.chainlock_schedule, config.btcc_schedule};
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(schedule, m_epoch)};
    if (!audit_schedule ||
        audit_schedule->seal_height != m_seal.statement.height ||
        audit_schedule->carrier_end_height_exclusive !=
            m_carrier_end_height_exclusive ||
        m_seal.statement.block_hash.IsNull()) {
        return false;
    }
    constexpr uint8_t all_rosters_mask{
        static_cast<uint8_t>((uint16_t{1} << ACTIVE_QUORUMS) - 1)};
    constexpr uint8_t pre_rotation_mask{
        static_cast<uint8_t>(all_rosters_mask &
                             ~(uint8_t{1} << (ACTIVE_QUORUMS - 1)))};
    const uint8_t expected_mask{
        m_seal.statement.roster_transition ==
                RosterAuthorizationTransitionKind::ROTATE
            ? pre_rotation_mask
            : all_rosters_mask};
    if (!IsSigningRosterAuthorizationMask(m_authorization_mask) ||
        m_authorization_mask != expected_mask) {
        return false;
    }
    return IsRecoverySourceBoundWindow(m_seal.statement.roster_beacons);
}

bool PaymentAuditSealContextCapsule::BuildForVerifiedDurableCandidate(
    const uint256& genesis_hash,
    const ChainLockFinalityStoreConfig& config,
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    std::optional<PaymentAuditSealContextCapsule>& capsule_out)
{
    capsule_out.reset();
    const PaymentAuditScheduleConfig schedule{
        config.chainlock_schedule, config.btcc_schedule};
    const auto seal_epoch{
        EpochForHeight(config.chainlock_schedule,
                       chainlock.statement.height)};
    if (!schedule.IsValid() || !seal_epoch || *seal_epoch == 0) {
        return schedule.IsValid();
    }
    const uint32_t subject_epoch{*seal_epoch - 1};
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(schedule, subject_epoch)};
    if (!audit_schedule ||
        audit_schedule->seal_height != chainlock.statement.height) {
        return true;
    }
    if (!context || context->GenesisHash() != genesis_hash ||
        context->Schedule() != config.chainlock_schedule ||
        context->Statement() != chainlock.statement ||
        context->AuthorizationMask() == 0) {
        return false;
    }
    const auto logical_id{chainlock.GetLogicalId(genesis_hash)};
    const auto witness_id{chainlock.GetWitnessId(genesis_hash)};
    PaymentAuditSealContextCapsule capsule{
        subject_epoch, audit_schedule->carrier_end_height_exclusive,
        FinalChainLockRecordMetadata{
            logical_id, witness_id, chainlock.statement},
        context->AuthorizationMask()};
    if (!capsule.IsInternallyConsistent(genesis_hash, config)) {
        return false;
    }
    capsule_out = std::move(capsule);
    return true;
}

namespace {

inline constexpr std::array<uint8_t, 8> SCHEMA_MAGIC{
    'S', 'Y', 'S', 'P', 'Q', 'C', 'L', '1'};
inline constexpr uint16_t SCHEMA_VERSION{1};
inline constexpr uint16_t RECORD_VERSION{1};
inline constexpr std::string_view SCHEMA_HASH_DOMAIN{
    "SYS_PQ_CHAINLOCK_PERSISTENCE_SCHEMA_V1"};
inline constexpr std::string_view RECORD_HASH_DOMAIN{
    "SYS_PQ_CHAINLOCK_PERSISTENCE_RECORD_V1"};
inline constexpr std::string_view CATCHUP_MARKER_HASH_DOMAIN{
    "SYS_PQ_CHAINLOCK_CATCHUP_MARKER_V1"};
inline constexpr std::string_view BTCC_PRESEAL_MARKER_HASH_DOMAIN{
    "SYS_PQ_BTCC_PRESEAL_MARKER_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_PRESEAL_MARKER_HASH_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_PRESEAL_MARKER_V1"};
inline constexpr std::string_view ROSTER_RECOVERY_PRECOMMIT_HASH_DOMAIN{
    "SYS_PQ_ROSTER_RECOVERY_PRECOMMIT_V1"};
inline constexpr std::string_view RECEIPT_ARCHIVE_AUTHORIZATION_HASH_DOMAIN{
    "SYS_PQ_RECEIPT_ARCHIVE_AUTHORIZATION_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_SEAL_CONTEXT_HASH_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_SEAL_CONTEXT_V1"};
inline constexpr std::string_view RECOVERY_UNIVERSE_RECORD_HASH_DOMAIN{
    "SYS_PQ_RECOVERY_UNIVERSE_RECORD_V1"};

void SetError(ChainLockPersistenceError* error,
              ChainLockPersistenceError value)
{
    if (error != nullptr) *error = value;
}

void WriteDomain(HashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

struct DiskKey {
    uint8_t type{0};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::Serialize(stream, type);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != sizeof(type)) {
            throw std::ios_base::failure("non-canonical PQ ChainLock DB key");
        }
        ::Unserialize(stream, type);
    }

    friend bool operator==(const DiskKey&, const DiskKey&) = default;
};

/** Composite namespace for the bounded exact authorization-base archive. */
struct DiskAuthorizationBaseKey {
    uint8_t type{PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY};
    uint256 logical_id;

    SERIALIZE_METHODS(DiskAuthorizationBaseKey, obj)
    {
        READWRITE(obj.type, obj.logical_id);
        SER_READ(obj, if (obj.type !=
                              PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY ||
                          obj.logical_id.IsNull()) {
            throw std::ios_base::failure(
                "non-canonical PQ authorization-base DB key");
        });
    }
};

/** Composite namespace for deduplicated local recovery universes. */
struct DiskRecoveryUniverseKey {
    uint8_t type{PQ_CHAINLOCK_PERSISTENCE_RECOVERY_UNIVERSE_KEY};
    uint256 source_id;

    SERIALIZE_METHODS(DiskRecoveryUniverseKey, obj)
    {
        READWRITE(obj.type, obj.source_id);
        SER_READ(obj, if (obj.type !=
                              PQ_CHAINLOCK_PERSISTENCE_RECOVERY_UNIVERSE_KEY ||
                          obj.source_id.IsNull()) {
            throw std::ios_base::failure(
                "non-canonical recovery-universe DB key");
        });
    }
};

struct DiskSchema {
    static constexpr std::size_t WIRE_SIZE{298};

    std::array<uint8_t, 8> magic{SCHEMA_MAGIC};
    uint16_t schema_version{SCHEMA_VERSION};
    uint256 genesis_hash;
    uint256 schema_hash;

    int32_t epoch_origin{-1};
    uint32_t epoch_blocks{0};
    uint32_t chainlock_period{0};
    uint32_t sign_lag{0};
    uint32_t active_epochs{0};

    int32_t btcc_candidate_origin{-1};
    uint32_t btcc_candidate_period{0};
    uint32_t btcc_nevm_injection_lag{0};

    int32_t activation_predecessor_height{-1};

    int32_t btcc_receipt_assumption_height{-1};
    uint256 btcc_receipt_assumption_block_hash;
    BTCCReceiptState btcc_receipt_assumption_state;

    uint32_t seen_logical_capacity{0};
    uint32_t seen_witness_capacity{0};
    uint32_t rejected_witness_capacity{0};
    uint32_t recent_chainlocks_capacity{0};

    uint16_t chainlock_version{CHAINLOCK_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    uint16_t child_usage_cap{SCHEDULED_WOTS_USAGE_CAP};
    uint32_t child_signature_size{CHILD_SIGNATURE_SIZE};
    uint16_t quorum_size{QUORUM_SIZE};
    uint16_t quorum_threshold{QUORUM_THRESHOLD};
    uint8_t active_quorums{ACTIVE_QUORUMS};
    uint8_t required_quorums{REQUIRED_QUORUMS};
    uint16_t final_signature_count{FINAL_SIGNATURE_COUNT};
    uint32_t certificate_wire_size{FinalChainLock::WIRE_SIZE};
    uint16_t payment_audit_receipt_version{
        PAYMENT_AUDIT_RECEIPT_VERSION};
    uint32_t payment_audit_receipt_wire_size{
        PaymentAuditReceipt::WIRE_SIZE};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(
            stream, magic, schema_version, genesis_hash, schema_hash,
            epoch_origin,
            epoch_blocks, chainlock_period, sign_lag, active_epochs,
            btcc_candidate_origin, btcc_candidate_period,
            btcc_nevm_injection_lag, activation_predecessor_height,
            btcc_receipt_assumption_height,
            btcc_receipt_assumption_block_hash,
            btcc_receipt_assumption_state, seen_logical_capacity,
            seen_witness_capacity,
            rejected_witness_capacity, recent_chainlocks_capacity,
            chainlock_version, child_profile, child_usage_cap,
            child_signature_size, quorum_size, quorum_threshold,
            active_quorums, required_quorums, final_signature_count,
            certificate_wire_size, payment_audit_receipt_version,
            payment_audit_receipt_wire_size);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid PQ ChainLock DB schema size");
        }
        ::UnserializeMany(
            stream, magic, schema_version, genesis_hash, schema_hash,
            epoch_origin,
            epoch_blocks, chainlock_period, sign_lag, active_epochs,
            btcc_candidate_origin, btcc_candidate_period,
            btcc_nevm_injection_lag, activation_predecessor_height,
            btcc_receipt_assumption_height,
            btcc_receipt_assumption_block_hash,
            btcc_receipt_assumption_state, seen_logical_capacity,
            seen_witness_capacity,
            rejected_witness_capacity, recent_chainlocks_capacity,
            chainlock_version, child_profile, child_usage_cap,
            child_signature_size, quorum_size, quorum_threshold,
            active_quorums, required_quorums, final_signature_count,
            certificate_wire_size, payment_audit_receipt_version,
            payment_audit_receipt_wire_size);
    }

    friend bool operator==(const DiskSchema&, const DiskSchema&) = default;
};

DiskSchema MakeSchema(const uint256& genesis_hash,
                      const ChainLockFinalityStoreConfig& config)
{
    if (genesis_hash.IsNull() || !config.IsValid() ||
        config.seen_logical_capacity > std::numeric_limits<uint32_t>::max() ||
        config.seen_witness_capacity > std::numeric_limits<uint32_t>::max() ||
        config.rejected_witness_capacity > std::numeric_limits<uint32_t>::max() ||
        config.recent_chainlocks_capacity > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(
            "invalid PQ ChainLock persistence configuration");
    }

    DiskSchema schema;
    schema.genesis_hash = genesis_hash;
    schema.epoch_origin = config.chainlock_schedule.epoch_origin;
    schema.epoch_blocks = config.chainlock_schedule.epoch_blocks;
    schema.chainlock_period = config.chainlock_schedule.chainlock_period;
    schema.sign_lag = config.chainlock_schedule.sign_lag;
    schema.active_epochs = config.chainlock_schedule.active_epochs;
    schema.btcc_candidate_origin = config.btcc_schedule.candidate_origin;
    schema.btcc_candidate_period = config.btcc_schedule.candidate_period;
    schema.btcc_nevm_injection_lag = config.btcc_schedule.nevm_injection_lag;
    schema.activation_predecessor_height =
        config.activation_predecessor_height;
    schema.btcc_receipt_assumption_height =
        config.btcc_receipt_assumption_anchor.height;
    schema.btcc_receipt_assumption_block_hash =
        config.btcc_receipt_assumption_anchor.block_hash;
    schema.btcc_receipt_assumption_state =
        config.btcc_receipt_assumption_anchor.receipt_state;
    schema.seen_logical_capacity = config.seen_logical_capacity;
    schema.seen_witness_capacity = config.seen_witness_capacity;
    schema.rejected_witness_capacity = config.rejected_witness_capacity;
    schema.recent_chainlocks_capacity = config.recent_chainlocks_capacity;
    DiskSchema hashed_schema{schema};
    hashed_schema.schema_hash.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, SCHEMA_HASH_DOMAIN);
    writer << hashed_schema;
    schema.schema_hash = writer.GetHash();
    return schema;
}

uint256 GetSchemaHash(const DiskSchema& schema)
{
    return schema.schema_hash;
}

uint256 GetRecordChecksum(const uint256& schema_hash,
                          const uint256& logical_id,
                          const uint256& witness_id,
                          const FinalChainLock& chainlock,
                          const std::vector<uint8_t>& roster_context)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECORD_HASH_DOMAIN);
    writer << schema_hash << logical_id << witness_id << chainlock
           << roster_context;
    return writer.GetHash();
}

uint256 GetRecoveryUniverseRecordChecksum(
    const uint256& schema_hash,
    const uint256& source_id,
    const std::vector<uint8_t>& encoded_capsule)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_UNIVERSE_RECORD_HASH_DOMAIN);
    writer << schema_hash << source_id << encoded_capsule;
    return writer.GetHash();
}

struct DiskRecord {
    static constexpr std::size_t FIXED_SIZE{
        sizeof(uint16_t) + 4 * 32 + FinalChainLock::WIRE_SIZE};
    static constexpr std::size_t MIN_WIRE_SIZE{
        FIXED_SIZE + GetSizeOfCompactSize(
                         DurableRosterContext::MIN_SERIALIZED_SIZE) +
        DurableRosterContext::MIN_SERIALIZED_SIZE};
    static constexpr std::size_t MAX_WIRE_SIZE{
        FIXED_SIZE + GetSizeOfCompactSize(
                         DurableRosterContext::MAX_SERIALIZED_SIZE) +
        DurableRosterContext::MAX_SERIALIZED_SIZE};

    uint16_t record_version{RECORD_VERSION};
    uint256 schema_hash;
    uint256 logical_id;
    uint256 witness_id;
    FinalChainLock chainlock;
    std::vector<uint8_t> encoded_roster_context;
    uint256 checksum;
    std::optional<DurableRosterContext> decoded_roster_context;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, record_version, schema_hash, logical_id,
                        witness_id, chainlock);
        WriteCompactSize(stream, encoded_roster_context.size());
        if (!encoded_roster_context.empty()) {
            stream.write(MakeByteSpan(encoded_roster_context));
        }
        ::Serialize(stream, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() < MIN_WIRE_SIZE ||
            stream.size() > MAX_WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid PQ ChainLock DB record size");
        }
        ::UnserializeMany(stream, record_version, schema_hash, logical_id,
                          witness_id, chainlock);
        const std::size_t context_size{ReadCompactSize(stream)};
        if (context_size < DurableRosterContext::MIN_SERIALIZED_SIZE ||
            context_size > DurableRosterContext::MAX_SERIALIZED_SIZE ||
            stream.size() != context_size + sizeof(checksum)) {
            throw std::ios_base::failure(
                "invalid durable roster-context size");
        }
        encoded_roster_context.resize(context_size);
        stream.read(MakeWritableByteSpan(encoded_roster_context));
        ::Unserialize(stream, checksum);
    }
};

struct DiskRecoveryUniverse {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t FIXED_SIZE{
        sizeof(uint16_t) + 3 * uint256::size()};
    static constexpr std::size_t MIN_WIRE_SIZE{
        FIXED_SIZE +
        GetSizeOfCompactSize(RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE) +
        RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE};
    static constexpr std::size_t MAX_WIRE_SIZE{
        FIXED_SIZE +
        GetSizeOfCompactSize(RecoveryUniverseCapsule::MAX_SERIALIZED_SIZE) +
        RecoveryUniverseCapsule::MAX_SERIALIZED_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    uint256 source_id;
    std::vector<uint8_t> encoded_capsule;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash, source_id);
        WriteCompactSize(stream, encoded_capsule.size());
        if (!encoded_capsule.empty()) {
            stream.write(MakeByteSpan(encoded_capsule));
        }
        ::Serialize(stream, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() < MIN_WIRE_SIZE ||
            stream.size() > MAX_WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid recovery-universe record size");
        }
        ::UnserializeMany(stream, version, schema_hash, source_id);
        const std::size_t capsule_size{ReadCompactSize(stream)};
        if (capsule_size <
                RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE ||
            capsule_size >
                RecoveryUniverseCapsule::MAX_SERIALIZED_SIZE ||
            stream.size() != capsule_size + sizeof(checksum)) {
            throw std::ios_base::failure(
                "invalid recovery-universe capsule size");
        }
        encoded_capsule.resize(capsule_size);
        stream.read(MakeWritableByteSpan(encoded_capsule));
        ::Unserialize(stream, checksum);
    }
};

struct DiskCatchupMarker {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t WIRE_SIZE{sizeof(uint16_t) + 4 * 32};

    uint16_t version{VERSION};
    uint256 schema_hash;
    uint256 logical_id;
    uint256 witness_id;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash, logical_id, witness_id,
                        checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure("invalid catch-up marker size");
        }
        ::UnserializeMany(stream, version, schema_hash, logical_id, witness_id,
                          checksum);
    }
};

struct DiskRosterRecoveryPrecommit {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 2 * 32 +
        RosterRecoveryPrecommit::WIRE_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    RosterRecoveryPrecommit precommit;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash, precommit, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid roster recovery precommit size");
        }
        ::UnserializeMany(stream, version, schema_hash, precommit, checksum);
    }
};

struct DiskPaymentAuditSealContext {
    static constexpr uint16_t VERSION{1};

    uint16_t version{VERSION};
    uint256 schema_hash;
    uint32_t epoch{0};
    int32_t carrier_end_height_exclusive{-1};
    uint256 seal_logical_id;
    uint256 seal_witness_id;
    ChainLockStatement seal_statement;
    uint8_t authorization_mask{0};
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash, epoch,
                        carrier_end_height_exclusive, seal_logical_id,
                        seal_witness_id, seal_statement,
                        authorization_mask, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        ::UnserializeMany(stream, version, schema_hash, epoch,
                          carrier_end_height_exclusive, seal_logical_id,
                          seal_witness_id, seal_statement,
                          authorization_mask, checksum);
    }
};

struct DiskReceiptArchiveRosterAuthorization {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 8 * 32 +
        2 * ChainLockStatement::WIRE_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    uint256 owner_logical_id;
    uint256 owner_witness_id;
    ChainLockStatement owner_statement;
    uint256 covering_logical_id;
    uint256 covering_witness_id;
    uint256 predecessor_logical_id;
    uint256 predecessor_witness_id;
    ChainLockStatement predecessor_statement;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(
            stream, version, schema_hash, owner_logical_id,
            owner_witness_id, owner_statement, covering_logical_id,
            covering_witness_id, predecessor_logical_id,
            predecessor_witness_id, predecessor_statement, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid receipt-archive authorization size");
        }
        ::UnserializeMany(
            stream, version, schema_hash, owner_logical_id,
            owner_witness_id, owner_statement, covering_logical_id,
            covering_witness_id, predecessor_logical_id,
            predecessor_witness_id, predecessor_statement, checksum);
    }
};

struct DiskBTCCPresealMarker {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 2 * sizeof(int32_t) + sizeof(uint64_t) +
        4 * 32 + 2 * BTCCReceiptState::WIRE_SIZE +
        BTCCReceipt::WIRE_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    BTCCReceiptState predecessor_receipt_state;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    BTCCReceiptState terminal_parent_receipt_state;
    BTCCReceipt terminal_receipt;
    uint64_t revision{0};
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash,
                        earliest_carrier_height, earliest_carrier_hash,
                        predecessor_receipt_state, terminal_carrier_height,
                        terminal_carrier_hash,
                        terminal_parent_receipt_state, terminal_receipt,
                        revision, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure("invalid BTCC pre-seal marker size");
        }
        ::UnserializeMany(stream, version, schema_hash,
                          earliest_carrier_height, earliest_carrier_hash,
                          predecessor_receipt_state, terminal_carrier_height,
                          terminal_carrier_hash,
                          terminal_parent_receipt_state, terminal_receipt,
                          revision, checksum);
    }
};

struct DiskPaymentAuditPresealMarker {
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 2 * sizeof(int32_t) + sizeof(uint64_t) +
        5 * 32 + PaymentAuditReceiptState::WIRE_SIZE +
        PaymentAuditReceipt::WIRE_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    PaymentAuditReceiptState predecessor_receipt_state;
    uint256 predecessor_probation_state_hash;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    PaymentAuditReceipt terminal_receipt;
    uint64_t revision{0};
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash,
                        earliest_carrier_height, earliest_carrier_hash,
                        predecessor_receipt_state,
                        predecessor_probation_state_hash,
                        terminal_carrier_height, terminal_carrier_hash,
                        terminal_receipt, revision, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid payment-audit pre-seal marker size");
        }
        ::UnserializeMany(stream, version, schema_hash,
                          earliest_carrier_height, earliest_carrier_hash,
                          predecessor_receipt_state,
                          predecessor_probation_state_hash,
                          terminal_carrier_height, terminal_carrier_hash,
                          terminal_receipt, revision, checksum);
    }
};

uint256 GetCatchupMarkerChecksum(const uint256& schema_hash,
                                 const uint256& logical_id,
                                 const uint256& witness_id)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, CATCHUP_MARKER_HASH_DOMAIN);
    writer << schema_hash << logical_id << witness_id;
    return writer.GetHash();
}

DiskCatchupMarker MakeCatchupMarker(const DiskRecord& record)
{
    DiskCatchupMarker marker;
    marker.schema_hash = record.schema_hash;
    marker.logical_id = record.logical_id;
    marker.witness_id = record.witness_id;
    marker.checksum = GetCatchupMarkerChecksum(
        marker.schema_hash, marker.logical_id, marker.witness_id);
    return marker;
}

uint256 GetRosterRecoveryPrecommitChecksum(
    const uint256& schema_hash,
    const RosterRecoveryPrecommit& precommit)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, ROSTER_RECOVERY_PRECOMMIT_HASH_DOMAIN);
    writer << schema_hash << precommit;
    return writer.GetHash();
}

DiskRosterRecoveryPrecommit MakeDiskRosterRecoveryPrecommit(
    const uint256& schema_hash,
    const RosterRecoveryPrecommit& precommit)
{
    DiskRosterRecoveryPrecommit disk;
    disk.schema_hash = schema_hash;
    disk.precommit = precommit;
    disk.checksum =
        GetRosterRecoveryPrecommitChecksum(schema_hash, precommit);
    return disk;
}

uint256 GetPaymentAuditSealContextChecksum(
    const uint256& schema_hash,
    const PaymentAuditSealContextCapsule& capsule)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PAYMENT_AUDIT_SEAL_CONTEXT_HASH_DOMAIN);
    writer << schema_hash << PAYMENT_AUDIT_SEAL_CONTEXT_VERSION
           << capsule.Epoch()
           << capsule.CarrierEndHeightExclusive()
           << capsule.Seal().logical_id
           << capsule.Seal().witness_id
           << capsule.Seal().statement
           << capsule.AuthorizationMask();
    return writer.GetHash();
}

std::unique_ptr<DiskPaymentAuditSealContext> MakeDiskPaymentAuditSealContext(
    const uint256& schema_hash,
    const PaymentAuditSealContextCapsule& capsule)
{
    auto disk{std::make_unique<DiskPaymentAuditSealContext>()};
    disk->schema_hash = schema_hash;
    disk->epoch = capsule.Epoch();
    disk->carrier_end_height_exclusive =
        capsule.CarrierEndHeightExclusive();
    disk->seal_logical_id = capsule.Seal().logical_id;
    disk->seal_witness_id = capsule.Seal().witness_id;
    disk->seal_statement = capsule.Seal().statement;
    disk->authorization_mask = capsule.AuthorizationMask();
    disk->checksum =
        GetPaymentAuditSealContextChecksum(schema_hash, capsule);
    return disk;
}

uint256 GetReceiptArchiveAuthorizationChecksum(
    const uint256& schema_hash,
    const ReceiptArchiveRosterAuthorization& authorization)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECEIPT_ARCHIVE_AUTHORIZATION_HASH_DOMAIN);
    writer << schema_hash << authorization.owner.logical_id
           << authorization.owner.witness_id
           << authorization.owner.statement
           << authorization.covering_logical_id
           << authorization.covering_witness_id
           << authorization.predecessor.logical_id
           << authorization.predecessor.witness_id
           << authorization.predecessor.statement;
    return writer.GetHash();
}

DiskReceiptArchiveRosterAuthorization
MakeDiskReceiptArchiveRosterAuthorization(
    const uint256& schema_hash,
    const ReceiptArchiveRosterAuthorization& authorization)
{
    DiskReceiptArchiveRosterAuthorization disk;
    disk.schema_hash = schema_hash;
    disk.owner_logical_id = authorization.owner.logical_id;
    disk.owner_witness_id = authorization.owner.witness_id;
    disk.owner_statement = authorization.owner.statement;
    disk.covering_logical_id = authorization.covering_logical_id;
    disk.covering_witness_id = authorization.covering_witness_id;
    disk.predecessor_logical_id = authorization.predecessor.logical_id;
    disk.predecessor_witness_id = authorization.predecessor.witness_id;
    disk.predecessor_statement = authorization.predecessor.statement;
    disk.checksum = GetReceiptArchiveAuthorizationChecksum(
        schema_hash, authorization);
    return disk;
}

ReceiptArchiveRosterAuthorization
GetReceiptArchiveRosterAuthorization(
    const DiskReceiptArchiveRosterAuthorization& disk)
{
    return ReceiptArchiveRosterAuthorization{
        FinalChainLockRecordMetadata{
            disk.owner_logical_id,
            disk.owner_witness_id,
            disk.owner_statement},
        disk.covering_logical_id,
        disk.covering_witness_id,
        FinalChainLockRecordMetadata{
            disk.predecessor_logical_id,
            disk.predecessor_witness_id,
            disk.predecessor_statement}};
}

bool ValidateDurableRecoverySources(
    const DiskRecord* best,
    const DiskRecord* unsealed,
    const std::optional<ReceiptArchiveRosterAuthorization>&
        receipt_archive_authorization)
{
    const auto validates = [](const ChainLockStatement& statement) {
        return IsRecoverySourceBoundWindow(statement.roster_beacons);
    };
    return (best == nullptr || validates(best->chainlock.statement)) &&
           (unsealed == nullptr || validates(unsealed->chainlock.statement)) &&
           (!receipt_archive_authorization ||
            (validates(receipt_archive_authorization->owner.statement) &&
             validates(receipt_archive_authorization->predecessor.statement)));
}

uint256 GetBTCCPresealMarkerChecksum(const uint256& schema_hash,
                                     const BTCCPresealMarker& marker)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, BTCC_PRESEAL_MARKER_HASH_DOMAIN);
    writer << schema_hash << marker.earliest_carrier_height
           << marker.earliest_carrier_hash
           << marker.predecessor_receipt_state
           << marker.terminal_carrier_height
           << marker.terminal_carrier_hash
           << marker.terminal_parent_receipt_state
           << marker.terminal_receipt
           << marker.revision;
    return writer.GetHash();
}

DiskBTCCPresealMarker MakeBTCCPresealMarker(
    const uint256& schema_hash, const BTCCPresealMarker& marker)
{
    DiskBTCCPresealMarker disk;
    disk.schema_hash = schema_hash;
    disk.earliest_carrier_height = marker.earliest_carrier_height;
    disk.earliest_carrier_hash = marker.earliest_carrier_hash;
    disk.predecessor_receipt_state = marker.predecessor_receipt_state;
    disk.terminal_carrier_height = marker.terminal_carrier_height;
    disk.terminal_carrier_hash = marker.terminal_carrier_hash;
    disk.terminal_parent_receipt_state =
        marker.terminal_parent_receipt_state;
    disk.terminal_receipt = marker.terminal_receipt;
    disk.revision = marker.revision;
    disk.checksum = GetBTCCPresealMarkerChecksum(schema_hash, marker);
    return disk;
}

uint256 GetPaymentAuditPresealMarkerChecksum(
    const uint256& schema_hash, const PaymentAuditPresealMarker& marker)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PAYMENT_AUDIT_PRESEAL_MARKER_HASH_DOMAIN);
    writer << schema_hash << marker.earliest_carrier_height
           << marker.earliest_carrier_hash
           << marker.predecessor_receipt_state
           << marker.predecessor_probation_state_hash
           << marker.terminal_carrier_height
           << marker.terminal_carrier_hash << marker.terminal_receipt
           << marker.revision;
    return writer.GetHash();
}

DiskPaymentAuditPresealMarker MakePaymentAuditPresealMarker(
    const uint256& schema_hash, const PaymentAuditPresealMarker& marker)
{
    DiskPaymentAuditPresealMarker disk;
    disk.schema_hash = schema_hash;
    disk.earliest_carrier_height = marker.earliest_carrier_height;
    disk.earliest_carrier_hash = marker.earliest_carrier_hash;
    disk.predecessor_receipt_state = marker.predecessor_receipt_state;
    disk.predecessor_probation_state_hash =
        marker.predecessor_probation_state_hash;
    disk.terminal_carrier_height = marker.terminal_carrier_height;
    disk.terminal_carrier_hash = marker.terminal_carrier_hash;
    disk.terminal_receipt = marker.terminal_receipt;
    disk.revision = marker.revision;
    disk.checksum =
        GetPaymentAuditPresealMarkerChecksum(schema_hash, marker);
    return disk;
}

static_assert(DiskRecord::MAX_WIRE_SIZE < MAX_SIZE);
static_assert(DiskRecoveryUniverse::MAX_WIRE_SIZE < MAX_SIZE);
static_assert(RECOVERY_UNIVERSE_DURABLE_OWNER_CAPACITY ==
              VERIFIED_AUTHORIZATION_BASE_CAPACITY + 3);
static_assert(DiskRosterRecoveryPrecommit::WIRE_SIZE == 180);
static_assert(DiskReceiptArchiveRosterAuthorization::WIRE_SIZE < MAX_SIZE);
static_assert(DiskBTCCPresealMarker::WIRE_SIZE == 500);
static_assert(DiskPaymentAuditPresealMarker::WIRE_SIZE == 683);

bool IsValidBTCCPresealMarker(
    const ChainLockFinalityStoreConfig& config,
    const BTCCPresealMarker& marker) noexcept
{
    if (!marker.IsStructurallyValid() ||
        marker.earliest_carrier_height <=
            config.btcc_receipt_assumption_anchor.height ||
        !IsBTCCReceiptCarrierHeight(
            config.btcc_schedule, marker.earliest_carrier_height) ||
        !IsBTCCReceiptCarrierHeight(
            config.btcc_schedule, marker.terminal_carrier_height)) {
        return false;
    }
    const auto& predecessor{marker.predecessor_receipt_state};
    const auto& terminal_parent{marker.terminal_parent_receipt_state};
    const bool exact_keep{IsExactBTCCReceiptTransition(
        terminal_parent, marker.terminal_receipt, BTCCAdvance::KEEP)};
    const bool exact_advance{
        IsExactBTCCReceiptTransition(
            terminal_parent, marker.terminal_receipt,
            BTCCAdvance::ADVANCE) &&
        marker.terminal_receipt.chainlock_target_hash ==
            marker.terminal_receipt.accepted_cursor.sys_hash};
    if (!IsBTCCReceiptTargetForCarrier(
            config.chainlock_schedule, config.btcc_schedule,
            config.activation_predecessor_height, terminal_parent,
            marker.terminal_carrier_height,
            marker.terminal_receipt.chainlock_target_height) ||
        marker.terminal_receipt.chainlock_target_height <=
            config.activation_predecessor_height ||
        marker.terminal_receipt.chainlock_target_height <=
            terminal_parent.latest_chainlock_target_height ||
        terminal_parent.latest_receipt_carrier_height >=
            marker.terminal_carrier_height ||
        predecessor.latest_receipt_carrier_height >=
            marker.earliest_carrier_height ||
        !IsDurableBTCCReceiptStateMonotonic(
            predecessor, terminal_parent) ||
        (marker.terminal_carrier_height ==
             marker.earliest_carrier_height &&
         terminal_parent != predecessor) ||
        (marker.terminal_carrier_height >
             marker.earliest_carrier_height &&
         terminal_parent == predecessor) ||
        (!exact_keep && !exact_advance) ||
        (marker.terminal_carrier_height ==
             marker.earliest_carrier_height &&
         marker.terminal_carrier_hash !=
             marker.earliest_carrier_hash)) {
        return false;
    }
    return predecessor.cursor.IsNull() ||
           predecessor.cursor.sys_height <
               marker.earliest_carrier_height;
}

bool HasFreshBTCCPresealRevision(const BTCCPresealState& candidate,
                                 uint64_t previous_revision) noexcept
{
    return (!candidate.active ||
            candidate.active->revision > previous_revision) &&
           (!candidate.prospective ||
            candidate.prospective->revision > previous_revision);
}

uint64_t HighestBTCCPresealRevision(const BTCCPresealState& state) noexcept
{
    uint64_t revision{0};
    if (state.active) revision = state.active->revision;
    if (state.prospective && state.prospective->revision > revision) {
        revision = state.prospective->revision;
    }
    return revision;
}

bool IsValidPaymentAuditPresealMarker(
    const ChainLockFinalityStoreConfig& config,
    const PaymentAuditPresealMarker& marker) noexcept
{
    const PaymentAuditScheduleConfig schedule{
        config.chainlock_schedule, config.btcc_schedule};
    if (!schedule.IsValid() || !marker.IsStructurallyValid()) {
        return false;
    }
    const auto earliest_epoch{PaymentAuditReceiptSlotEpoch(
        schedule, marker.earliest_carrier_height)};
    const auto terminal_epoch{PaymentAuditReceiptSlotEpoch(
        schedule, marker.terminal_carrier_height)};
    const auto earliest_schedule{
        earliest_epoch
            ? BuildPaymentAuditEpochSchedule(schedule, *earliest_epoch)
            : std::nullopt};
    const auto terminal_schedule{
        terminal_epoch
            ? BuildPaymentAuditEpochSchedule(schedule, *terminal_epoch)
            : std::nullopt};
    if (!earliest_epoch || !terminal_epoch ||
        !earliest_schedule || !terminal_schedule ||
        *terminal_epoch != marker.terminal_receipt.epoch ||
        marker.terminal_receipt.seal_height !=
            terminal_schedule->seal_height ||
        marker.terminal_receipt.carrier_height !=
            marker.terminal_carrier_height ||
        earliest_schedule->seal_height <= config.activation_predecessor_height ||
        marker.terminal_receipt.seal_height <= config.activation_predecessor_height ||
        (marker.terminal_carrier_height ==
             marker.earliest_carrier_height &&
         marker.terminal_carrier_hash !=
             marker.earliest_carrier_hash)) {
        return false;
    }
    const auto& predecessor{marker.predecessor_receipt_state.cursor};
    return predecessor.IsNull() ||
           (predecessor.epoch < *earliest_epoch &&
            predecessor.carrier_height <
                marker.earliest_carrier_height &&
            marker.terminal_receipt.epoch > predecessor.epoch);
}

bool IsValidRosterRecoveryPrecommit(
    const ChainLockFinalityStoreConfig& config,
    const RosterRecoveryPrecommit& precommit) noexcept
{
    const auto& pending_seed{precommit.pending_seed};
    const auto anchor_epoch{EpochForHeight(
        config.chainlock_schedule,
        pending_seed.anchor_cursor.sys_height)};
    const auto canonical_target{anchor_epoch
        ? CanonicalRosterRecoveryTargetHeight(
              config.chainlock_schedule, config.btcc_schedule,
              *anchor_epoch)
        : std::optional<int32_t>{}};
    const auto initial_target{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule,
        config.activation_predecessor_height)};
    return precommit.IsStructurallyValid() &&
           initial_target &&
           pending_seed.anchor_cursor.sys_height == *initial_target &&
           pending_seed.anchor_cursor.sys_height >
               config.activation_predecessor_height &&
           IsEligibleChainLockTarget(
               config.chainlock_schedule,
               pending_seed.anchor_cursor.sys_height) &&
           anchor_epoch && *anchor_epoch == pending_seed.epoch &&
           canonical_target &&
           *canonical_target == pending_seed.anchor_cursor.sys_height &&
           IsBTCCCandidateHeight(
               config.btcc_schedule,
               pending_seed.anchor_cursor.sys_height);
}

bool HasFreshPaymentAuditPresealRevision(
    const PaymentAuditPresealState& candidate,
    uint64_t previous_revision) noexcept
{
    return (!candidate.active ||
            candidate.active->revision > previous_revision) &&
           (!candidate.prospective ||
            candidate.prospective->revision > previous_revision);
}

uint64_t HighestPaymentAuditPresealRevision(
    const PaymentAuditPresealState& state) noexcept
{
    uint64_t revision{0};
    if (state.active) revision = state.active->revision;
    if (state.prospective && state.prospective->revision > revision) {
        revision = state.prospective->revision;
    }
    return revision;
}

bool IsReceiptableChainLock(const FinalChainLock& chainlock,
                            const ChainLockFinalityStoreConfig& config) noexcept
{
    const auto& statement{chainlock.statement};
    if (!IsBTCCCandidateHeight(config.btcc_schedule, statement.height)) {
        return false;
    }
    if (statement.btcc_advance == BTCCAdvance::KEEP) {
        return !statement.accepted_btcc_cursor.IsNull() &&
               statement.accepted_btcc_cursor ==
                   statement.previous_btcc_cursor;
    }
    return statement.btcc_advance == BTCCAdvance::ADVANCE &&
           statement.height == statement.accepted_btcc_cursor.sys_height;
}

bool SealsUnsealedBTCC(const FinalChainLock& seal,
                       const FinalChainLock& unsealed,
                       const ChainLockFinalityStoreConfig& config) noexcept
{
    if (!IsReceiptableChainLock(unsealed, config) ||
        !seal.statement.btcc_receipt_state.IsStructurallyValid()) {
        return false;
    }
    const int64_t carrier_height{
        static_cast<int64_t>(unsealed.statement.height) +
        config.btcc_schedule.nevm_injection_lag};
    return carrier_height <= std::numeric_limits<int32_t>::max() &&
           seal.statement.height >= carrier_height;
}

bool IsExactRecoveryStatement(const FinalChainLock& chainlock) noexcept
{
    if (!chainlock.IsStructurallyValid() ||
        chainlock.statement.btcc_advance != BTCCAdvance::ADVANCE) {
        return false;
    }
    const auto& window{chainlock.statement.roster_beacons};
    const auto& ready{
        window.active.seeds.back()};
    if (!ready.IsReady() ||
        ready.anchor_cursor.sys_height != chainlock.statement.height ||
        ready.anchor_cursor.sys_hash != chainlock.statement.block_hash ||
        chainlock.statement.accepted_btcc_cursor != ready.anchor_cursor) {
        return false;
    }
    return chainlock.statement.roster_transition ==
               RosterAuthorizationTransitionKind::INITIALIZE &&
           IsInitialNormalRosterBeaconWindow(window);
}

bool DoesRecoveryPrecommitMatchBest(
    const RosterRecoveryPrecommit& precommit,
    const std::optional<DiskRecord>& best) noexcept
{
    return precommit.IsStructurallyValid() && !best;
}

bool IsExactRosterRecoveryResolution(
    const RosterRecoveryPrecommit& pending,
    const RosterRecoveryPrecommit& ready) noexcept
{
    return pending.version == ready.version &&
           IsExactRosterBeaconReveal(
               pending.pending_seed, ready.pending_seed);
}

bool DoesRecoveryCertificateMatchPrecommit(
    const FinalChainLock& chainlock,
    const RosterRecoveryPrecommit& precommit,
    const std::optional<DiskRecord>& durable_best,
    const uint256& genesis_hash) noexcept
{
    if (!DoesRecoveryPrecommitMatchBest(precommit, durable_best) ||
        !IsExactRecoveryStatement(chainlock)) {
        return false;
    }
    const auto& next_bundle{
        chainlock.statement.roster_beacons.active};
    const auto& ready{next_bundle.seeds.back()};
    if (next_bundle.recovery_authority_source.normal_beacon != ready) {
        return false;
    }
    const bool seed_matches{
        precommit.pending_seed.state == RosterBeaconState::PENDING
            ? IsExactRosterBeaconReveal(precommit.pending_seed, ready)
            : precommit.pending_seed == ready};
    if (!seed_matches) return false;

    RosterAuthorizationTransition transition;
    transition.kind = chainlock.statement.roster_transition;
    transition.target_height = chainlock.statement.height;
    transition.target_block_hash = chainlock.statement.block_hash;
    transition.predecessor_height =
        chainlock.statement.previous_chainlock_height;
    transition.predecessor_block_hash =
        chainlock.statement.previous_chainlock_hash;
    transition.authorization_base =
        chainlock.statement.roster_authorization_base;
    transition.new_window = chainlock.statement.roster_beacons;
    if (durable_best) return false;
    const auto expected_state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    return expected_state_hash &&
           *expected_state_hash ==
               chainlock.statement.roster_authorization_state_hash;
}

template <typename Value, typename Key>
std::unique_ptr<Value> ReadExactValue(CDBWrapper& db, const Key& key)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return nullptr;
    }

    Key found_key;
    auto value{std::make_unique<Value>()};
    if (!iterator->GetKeyExact(found_key) || found_key != key ||
        !iterator->GetValueExact(*value)) {
        return nullptr;
    }
    return value;
}

} // namespace

struct PQChainLockPersistence::Impl {
    Impl(DBParams db_params,
         uint256 genesis_hash,
         ChainLockFinalityStoreConfig config)
        : genesis_hash{std::move(genesis_hash)},
          config{std::move(config)},
          schema{MakeSchema(this->genesis_hash, this->config)},
          schema_hash{GetSchemaHash(schema)},
          db{std::move(db_params)}
    {
        LOCK(mutex);
        if (::GetSerializeSize(schema) != DiskSchema::WIRE_SIZE) {
            throw std::logic_error(
                "PQ ChainLock persistence schema size drift");
        }
        InitializeOrLoad();
    }

    std::optional<DiskRecord> MakeRecord(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context) const
    {
        if (!context || context->GenesisHash() != genesis_hash ||
            context->Schedule() != config.chainlock_schedule ||
            context->Statement() != chainlock.statement ||
            context->StatementLogicalId() !=
                chainlock.GetLogicalId(genesis_hash)) {
            return std::nullopt;
        }
        DiskRecord record;
        record.schema_hash = schema_hash;
        record.logical_id = chainlock.GetLogicalId(genesis_hash);
        record.witness_id = chainlock.GetWitnessId(genesis_hash);
        record.chainlock = chainlock;
        try {
            record.decoded_roster_context =
                DurableRosterContext::Capture(*context);
            record.encoded_roster_context =
                record.decoded_roster_context->Encode();
        } catch (const std::exception&) {
            return std::nullopt;
        }
        record.checksum = GetRecordChecksum(
            schema_hash, record.logical_id, record.witness_id, chainlock,
            record.encoded_roster_context);
        return record;
    }

    bool ValidateRecord(DiskRecord& record) const
    {
        if (record.record_version != RECORD_VERSION ||
            record.schema_hash != schema_hash ||
            !record.chainlock.IsStructurallyValid() ||
            !IsEligibleChainLockTarget(config.chainlock_schedule,
                                       record.chainlock.statement.height) ||
            record.logical_id !=
                record.chainlock.GetLogicalId(genesis_hash) ||
            record.witness_id !=
                record.chainlock.GetWitnessId(genesis_hash) ||
            record.checksum != GetRecordChecksum(
                schema_hash, record.logical_id, record.witness_id,
                record.chainlock, record.encoded_roster_context)) {
            return false;
        }

        if (!record.decoded_roster_context) {
            record.decoded_roster_context =
                DurableRosterContext::DecodeTrustedPersistence(
                    record.encoded_roster_context);
        }
        if (!record.decoded_roster_context ||
            record.decoded_roster_context->GenesisHash() != genesis_hash) {
            return false;
        }

        const auto& statement{record.chainlock.statement};
        const auto next_target{NextEligibleChainLockTargetHeight(
            config.chainlock_schedule,
            statement.previous_chainlock_height)};
        const auto initializer_epoch{EpochForHeight(
            config.chainlock_schedule, statement.height)};
        const auto initializer_target{initializer_epoch
            ? CanonicalRosterRecoveryTargetHeight(
                  config.chainlock_schedule, config.btcc_schedule,
                  *initializer_epoch)
            : std::optional<int32_t>{}};
        const bool exact_initializer{
            statement.roster_transition !=
                RosterAuthorizationTransitionKind::INITIALIZE ||
            (statement.previous_chainlock_height ==
                 config.activation_predecessor_height &&
             initializer_epoch && initializer_target &&
             statement.roster_beacons.active.seeds.back().epoch ==
                 *initializer_epoch &&
             statement.height == *initializer_target &&
             IsExactRecoveryStatement(record.chainlock))};
        return exact_initializer && next_target &&
               statement.height == *next_target &&
               statement.height > config.activation_predecessor_height &&
               statement.previous_chainlock_height >= config.activation_predecessor_height &&
               (statement.previous_chainlock_height != config.activation_predecessor_height ||
                (!statement.previous_chainlock_hash.IsNull() &&
                 statement.previous_btcc_cursor.IsNull()));
    }

    DurableChainLockRecord PublicRecord(const DiskRecord& record) const
    {
        if (!record.decoded_roster_context) {
            throw std::logic_error(
                "validated durable record missing roster context");
        }
        return DurableChainLockRecord{
            record.chainlock, *record.decoded_roster_context,
            record.checksum};
    }

    FinalChainLockRecordMetadata Metadata(const DiskRecord& record) const
    {
        return FinalChainLockRecordMetadata{
            record.logical_id, record.witness_id,
            record.chainlock.statement};
    }

    static bool MatchesMetadata(
        const DiskRecord& record,
        const FinalChainLockRecordMetadata& metadata) noexcept
    {
        return record.logical_id == metadata.logical_id &&
               record.witness_id == metadata.witness_id &&
               record.chainlock.statement == metadata.statement;
    }

    const DiskRecord* FindExactRetainedRecord(
        const FinalChainLockRecordMetadata& metadata) const
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        if (best && MatchesMetadata(*best, metadata)) return &*best;
        if (unsealed && MatchesMetadata(*unsealed, metadata)) {
            return &*unsealed;
        }
        const auto retained{authorization_bases.find(metadata.logical_id)};
        return retained != authorization_bases.end() &&
                       MatchesMetadata(retained->second, metadata)
            ? &retained->second
            : nullptr;
    }

    static bool IsExactRecord(const DiskRecord& left,
                              const DiskRecord& right) noexcept
    {
        return left.logical_id == right.logical_id &&
               left.witness_id == right.witness_id &&
               left.checksum == right.checksum &&
               left.chainlock == right.chainlock &&
               left.encoded_roster_context ==
                   right.encoded_roster_context;
    }

    static bool IsOlderAuthorizationBase(const DiskRecord& left,
                                         const DiskRecord& right) noexcept
    {
        if (left.chainlock.statement.height !=
            right.chainlock.statement.height) {
            return left.chainlock.statement.height <
                   right.chainlock.statement.height;
        }
        return left.logical_id < right.logical_id;
    }

    bool ValidateRecoverySourceState(
        const DiskRecord* next_best,
        const DiskRecord* next_unsealed,
        const std::optional<ReceiptArchiveRosterAuthorization>&
            next_receipt_archive_authorization,
        ChainLockPersistenceError* error) const
    {
        if (!ValidateDurableRecoverySources(
                next_best, next_unsealed,
                next_receipt_archive_authorization)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        return true;
    }

    using AuthorizationBaseView =
        std::map<uint256, const DiskRecord*>;

    struct RecoveryUniverseMutation {
        RecoveryUniverseCapsulePtr addition;
        std::optional<DiskRecoveryUniverse> addition_record;
        std::set<uint256> erasures;
    };

    std::optional<DiskRecoveryUniverse> MakeRecoveryUniverseRecord(
        const RecoveryUniverseCapsulePtr& capsule) const
    {
        if (!capsule || !capsule->IsStructurallyValid() ||
            capsule->GenesisHash() != genesis_hash ||
            capsule->SourceId().IsNull() ||
            capsule->SourceId() != GetRecoveryUniverseSourceId(
                genesis_hash, capsule->Source())) {
            return std::nullopt;
        }
        DiskRecoveryUniverse record;
        record.schema_hash = schema_hash;
        record.source_id = capsule->SourceId();
        try {
            record.encoded_capsule = capsule->Encode();
        } catch (const std::exception&) {
            return std::nullopt;
        }
        record.checksum = GetRecoveryUniverseRecordChecksum(
            schema_hash, record.source_id, record.encoded_capsule);
        const std::size_t size{::GetSerializeSize(record)};
        if (size < DiskRecoveryUniverse::MIN_WIRE_SIZE ||
            size > DiskRecoveryUniverse::MAX_WIRE_SIZE) {
            return std::nullopt;
        }
        return record;
    }

    RecoveryUniverseCapsulePtr DecodeRecoveryUniverseRecord(
        const DiskRecoveryUniverse& record) const
    {
        if (record.version != DiskRecoveryUniverse::VERSION ||
            record.schema_hash != schema_hash || record.source_id.IsNull() ||
            record.checksum != GetRecoveryUniverseRecordChecksum(
                schema_hash, record.source_id,
                record.encoded_capsule)) {
            return nullptr;
        }
        const auto decoded{
            RecoveryUniverseCapsule::DecodeTrustedPersistence(
                record.encoded_capsule)};
        if (!decoded || decoded->GenesisHash() != genesis_hash ||
            decoded->SourceId() != record.source_id) {
            return nullptr;
        }
        return std::make_shared<const RecoveryUniverseCapsule>(*decoded);
    }

    bool CollectRecoverySource(
        const ChainLockStatement& statement,
        std::map<uint256, RecoveryRosterAuthoritySource>& required) const
    {
        if (!IsRecoverySourceBoundWindow(statement.roster_beacons)) {
            return false;
        }
        const auto& source{
            statement.roster_beacons.active.recovery_authority_source};
        if (source.IsNull()) return true;
        const uint256 source_id{
            GetRecoveryUniverseSourceId(genesis_hash, source)};
        if (source_id.IsNull()) return false;
        const auto [it, inserted]{required.emplace(source_id, source)};
        return inserted || it->second == source;
    }

    std::optional<RecoveryUniverseMutation>
    PrepareRecoveryUniverseMutation(
        const DiskRecord* next_best,
        const DiskRecord* next_unsealed,
        const AuthorizationBaseView& next_authorization_bases,
        const std::optional<ReceiptArchiveRosterAuthorization>&
            next_receipt_archive_authorization,
        const std::optional<PaymentAuditSealContextCapsule>&
            next_payment_audit_seal_context,
        RecoveryUniverseCapsulePtr supplied,
        ChainLockPersistenceError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        std::map<uint256, RecoveryRosterAuthoritySource> required;
        const auto collect_record = [&](const DiskRecord* record) {
            return record == nullptr ||
                   CollectRecoverySource(record->chainlock.statement,
                                         required);
        };
        if (!collect_record(next_best) || !collect_record(next_unsealed)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return std::nullopt;
        }
        for (const auto& [_, record] : next_authorization_bases) {
            if (record == nullptr || !collect_record(record)) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return std::nullopt;
            }
        }
        if (next_receipt_archive_authorization &&
            (!CollectRecoverySource(
                 next_receipt_archive_authorization->owner.statement,
                 required) ||
             !CollectRecoverySource(
                 next_receipt_archive_authorization->predecessor.statement,
                 required))) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return std::nullopt;
        }
        if (next_payment_audit_seal_context &&
            !CollectRecoverySource(
                next_payment_audit_seal_context->Seal().statement,
                required)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return std::nullopt;
        }
        if (required.size() > RECOVERY_UNIVERSE_DURABLE_OWNER_CAPACITY) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return std::nullopt;
        }

        RecoveryUniverseMutation mutation;
        if (supplied) {
            const auto disk{MakeRecoveryUniverseRecord(supplied)};
            const auto required_it{required.find(supplied->SourceId())};
            const auto existing{recovery_universes.find(
                supplied->SourceId())};
            if (!disk || required_it == required.end() ||
                required_it->second != supplied->Source() ||
                (existing != recovery_universes.end() &&
                 *existing->second != *supplied)) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return std::nullopt;
            }
            if (existing == recovery_universes.end()) {
                mutation.addition = std::move(supplied);
                mutation.addition_record = std::move(*disk);
            }
        }

        for (const auto& [source_id, source] : required) {
            const auto existing{recovery_universes.find(source_id)};
            if (existing != recovery_universes.end()) {
                if (!existing->second ||
                    existing->second->Source() != source) {
                    SetError(error,
                             ChainLockPersistenceError::IO_FAILURE);
                    return std::nullopt;
                }
                continue;
            }
            if (!mutation.addition ||
                mutation.addition->SourceId() != source_id ||
                mutation.addition->Source() != source) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return std::nullopt;
            }
        }
        for (const auto& [source_id, _] : recovery_universes) {
            if (!required.contains(source_id)) {
                mutation.erasures.insert(source_id);
            }
        }
        const std::size_t retained_count{
            recovery_universes.size() - mutation.erasures.size() +
            (mutation.addition ? 1U : 0U)};
        if (retained_count != required.size() ||
            retained_count > RECOVERY_UNIVERSE_DURABLE_OWNER_CAPACITY) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return std::nullopt;
        }
        return mutation;
    }

    bool ApplyRecoveryUniverseMutation(
        CDBBatch& batch,
        const RecoveryUniverseMutation& mutation,
        ChainLockPersistenceError* error) const
    {
        if (mutation.addition) {
            if (!mutation.addition_record ||
                mutation.addition_record->source_id !=
                    mutation.addition->SourceId()) {
                SetError(error,
                         ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
            batch.Write(
                DiskRecoveryUniverseKey{
                    PQ_CHAINLOCK_PERSISTENCE_RECOVERY_UNIVERSE_KEY,
                    mutation.addition->SourceId()},
                *mutation.addition_record);
        } else if (mutation.addition_record) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        for (const auto& source_id : mutation.erasures) {
            batch.Erase(DiskRecoveryUniverseKey{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_UNIVERSE_KEY,
                source_id});
        }
        return true;
    }

    void CommitRecoveryUniverseMutation(
        const RecoveryUniverseMutation& mutation)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        for (const auto& source_id : mutation.erasures) {
            recovery_universes.erase(source_id);
        }
        if (mutation.addition) {
            recovery_universes.emplace(
                mutation.addition->SourceId(), mutation.addition);
        }
    }

    bool ValidateReceiptArchiveAuthorization(
        const ReceiptArchiveRosterAuthorization& authorization,
        const DiskRecord* durable_best) const
    {
        if (!durable_best ||
            !authorization.IsInternallyConsistent(genesis_hash) ||
            authorization.covering_logical_id !=
                durable_best->logical_id ||
            authorization.covering_witness_id !=
                durable_best->witness_id ||
            authorization.owner.statement.height >
                durable_best->chainlock.statement.height) {
            return false;
        }

        const auto& predecessor{authorization.predecessor.statement};
        const auto& owner_statement{authorization.owner.statement};
        const auto predecessor_target{NextEligibleChainLockTargetHeight(
            config.chainlock_schedule,
            predecessor.previous_chainlock_height)};
        const auto owner_target{NextEligibleChainLockTargetHeight(
            config.chainlock_schedule,
            owner_statement.previous_chainlock_height)};
        const bool owner_is_cover{
            owner_statement.height ==
            durable_best->chainlock.statement.height};
        return predecessor_target &&
               predecessor.height == *predecessor_target &&
               predecessor.height > config.activation_predecessor_height &&
               predecessor.previous_chainlock_height >=
                   config.activation_predecessor_height &&
               owner_target && owner_statement.height == *owner_target &&
               (!owner_is_cover ||
                (authorization.owner.logical_id ==
                     durable_best->logical_id &&
                 authorization.owner.witness_id ==
                     durable_best->witness_id &&
                 owner_statement ==
                     durable_best->chainlock.statement));
    }

    ReceiptArchiveRosterAuthorization
    MakeReceiptArchiveAuthorization(const DiskRecord& owner,
                                    const DiskRecord& predecessor) const
    {
        return ReceiptArchiveRosterAuthorization{
            Metadata(owner),
            owner.logical_id,
            owner.witness_id,
            Metadata(predecessor)};
    }

    bool HasExactAuthorizationBase(const DiskRecord& owner) const
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        const auto& statement{owner.chainlock.statement};
        if (statement.roster_transition ==
            RosterAuthorizationTransitionKind::INITIALIZE) {
            return statement.roster_authorization_base.IsNull();
        }

        const auto& identity{statement.roster_authorization_base};
        if (identity.IsNull()) return false;
        const auto matches = [&](const DiskRecord& candidate) {
            return Metadata(candidate).AuthorizationBase() == identity;
        };
        if (best && matches(*best)) return true;
        if (unsealed && matches(*unsealed)) return true;
        const auto retained{authorization_bases.find(identity.logical_id)};
        return retained != authorization_bases.end() &&
               matches(retained->second);
    }

    void InitializeOrLoad() EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        bool any{false};
        bool found_schema{false};
        bool found_best{false};
        bool found_unsealed{false};
        bool found_catchup_marker{false};
        bool found_btcc_preseal{false};
        bool found_btcc_prospective_preseal{false};
        bool found_payment_audit_preseal{false};
        bool found_payment_audit_prospective_preseal{false};
        bool found_roster_recovery_precommit{false};
        bool found_receipt_archive_authorization{false};
        bool found_payment_audit_seal_context{false};
        std::set<uint256> authorization_base_witnesses;
        {
            std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
            for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
                any = true;
                DiskKey key;
                if (!iterator->GetKeyExact(key)) {
                    DiskAuthorizationBaseKey base_key;
                    DiskRecord record;
                    if (iterator->GetKeyExact(base_key)) {
                        if (!iterator->GetValueExact(record) ||
                            base_key.logical_id != record.logical_id ||
                            !ValidateRecord(record) ||
                            authorization_bases.contains(record.logical_id) ||
                            !authorization_base_witnesses
                                 .insert(record.witness_id).second ||
                            authorization_bases.size() >=
                                VERIFIED_AUTHORIZATION_BASE_CAPACITY) {
                            throw std::runtime_error(
                                "corrupt PQ ChainLock authorization-base record");
                        }
                        authorization_bases.emplace(
                            record.logical_id, std::move(record));
                        continue;
                    }

                    DiskRecoveryUniverseKey universe_key;
                    DiskRecoveryUniverse disk_universe;
                    if (!iterator->GetKeyExact(universe_key) ||
                        !iterator->GetValueExact(disk_universe) ||
                        universe_key.source_id != disk_universe.source_id ||
                        recovery_universes.contains(universe_key.source_id) ||
                        recovery_universes.size() >=
                            RECOVERY_UNIVERSE_DURABLE_OWNER_CAPACITY) {
                        throw std::runtime_error(
                            "corrupt recovery-universe record");
                    }
                    auto capsule{
                        DecodeRecoveryUniverseRecord(disk_universe)};
                    if (!capsule) {
                        throw std::runtime_error(
                            "corrupt recovery-universe record");
                    }
                    recovery_universes.emplace(
                        universe_key.source_id, std::move(capsule));
                    continue;
                }
                if (key.type == PQ_CHAINLOCK_PERSISTENCE_SCHEMA_KEY) {
                    if (found_schema) {
                        throw std::runtime_error(
                            "duplicate PQ ChainLock persistence schema");
                    }
                    found_schema = true;
                } else if (key.type == PQ_CHAINLOCK_PERSISTENCE_BEST_KEY) {
                    if (found_best) {
                        throw std::runtime_error(
                            "duplicate PQ ChainLock persistence record");
                    }
                    found_best = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY) {
                    if (found_unsealed) {
                        throw std::runtime_error(
                            "duplicate unsealed BTCC certificate record");
                    }
                    found_unsealed = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_CATCHUP_MARKER_KEY) {
                    if (found_catchup_marker) {
                        throw std::runtime_error(
                            "duplicate PQ catch-up marker");
                    }
                    found_catchup_marker = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY) {
                    if (found_btcc_preseal) {
                        throw std::runtime_error(
                            "duplicate BTCC pre-seal marker");
                    }
                    found_btcc_preseal = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_BTCC_PROSPECTIVE_PRESEAL_KEY) {
                    if (found_btcc_prospective_preseal) {
                        throw std::runtime_error(
                            "duplicate prospective BTCC pre-seal marker");
                    }
                    found_btcc_prospective_preseal = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PRESEAL_KEY) {
                    if (found_payment_audit_preseal) {
                        throw std::runtime_error(
                            "duplicate payment-audit pre-seal marker");
                    }
                    found_payment_audit_preseal = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PROSPECTIVE_PRESEAL_KEY) {
                    if (found_payment_audit_prospective_preseal) {
                        throw std::runtime_error(
                            "duplicate prospective payment-audit pre-seal marker");
                    }
                    found_payment_audit_prospective_preseal = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY) {
                    if (found_roster_recovery_precommit) {
                        throw std::runtime_error(
                            "duplicate roster recovery precommit");
                    }
                    found_roster_recovery_precommit = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY) {
                    if (found_receipt_archive_authorization) {
                        throw std::runtime_error(
                            "duplicate receipt-archive authorization");
                    }
                    found_receipt_archive_authorization = true;
                } else if (key.type ==
                           PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY) {
                    if (found_payment_audit_seal_context) {
                        throw std::runtime_error(
                            "duplicate payment-audit seal context");
                    }
                    found_payment_audit_seal_context = true;
                } else {
                    throw std::runtime_error(
                        "unknown PQ ChainLock persistence key");
                }
            }
            iterator->CheckStatus();
        }

        if (!any) {
            CDBBatch batch{db};
            batch.Write(DiskKey{PQ_CHAINLOCK_PERSISTENCE_SCHEMA_KEY}, schema);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                throw std::runtime_error(
                    "failed to initialize PQ ChainLock persistence schema");
            }
            return;
        }
        if (!found_schema) {
            throw std::runtime_error(
                "nonempty PQ ChainLock database has no schema");
        }

        const DiskKey schema_key{PQ_CHAINLOCK_PERSISTENCE_SCHEMA_KEY};
        const auto stored_schema{ReadExactValue<DiskSchema>(db, schema_key)};
        if (!stored_schema || *stored_schema != schema) {
            throw std::runtime_error(
                "PQ ChainLock persistence schema/configuration mismatch");
        }
        if (!found_best && found_catchup_marker) {
            throw std::runtime_error(
                "PQ catch-up marker exists without a best record");
        }
        if (!found_best && found_payment_audit_seal_context) {
            throw std::runtime_error(
                "payment-audit seal context exists without a best record");
        }

        if (found_best) {
            const DiskKey best_key{PQ_CHAINLOCK_PERSISTENCE_BEST_KEY};
            auto record{ReadExactValue<DiskRecord>(db, best_key)};
            if (!record || !ValidateRecord(*record)) {
                throw std::runtime_error(
                    "corrupt PQ ChainLock persistence record");
            }
            best = std::move(*record);
        }

        if (found_roster_recovery_precommit) {
            const DiskKey precommit_key{
                PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY};
            const auto disk{ReadExactValue<DiskRosterRecoveryPrecommit>(
                db, precommit_key)};
            if (!disk ||
                disk->version != DiskRosterRecoveryPrecommit::VERSION ||
                disk->schema_hash != schema_hash ||
                !IsValidRosterRecoveryPrecommit(config,
                                                disk->precommit) ||
                disk->checksum != GetRosterRecoveryPrecommitChecksum(
                    disk->schema_hash, disk->precommit) ||
                !DoesRecoveryPrecommitMatchBest(
                    disk->precommit, best)) {
                throw std::runtime_error(
                    "corrupt roster recovery precommit");
            }
            roster_recovery_precommit = disk->precommit;
        }

        if (found_receipt_archive_authorization) {
            const DiskKey authorization_key{
                PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY};
            const auto disk{
                ReadExactValue<DiskReceiptArchiveRosterAuthorization>(
                    db, authorization_key)};
            if (!disk ||
                disk->version !=
                    DiskReceiptArchiveRosterAuthorization::VERSION ||
                disk->schema_hash != schema_hash) {
                throw std::runtime_error(
                    "corrupt receipt-archive authorization");
            }
            const auto authorization{
                GetReceiptArchiveRosterAuthorization(*disk)};
            if (!ValidateReceiptArchiveAuthorization(
                    authorization, best ? &*best : nullptr) ||
                disk->checksum !=
                    GetReceiptArchiveAuthorizationChecksum(
                        disk->schema_hash, authorization)) {
                throw std::runtime_error(
                    "corrupt receipt-archive authorization");
            }
            receipt_archive_authorization = authorization;
        }

        if (found_catchup_marker) {
            const DiskKey marker_key{
                PQ_CHAINLOCK_PERSISTENCE_CATCHUP_MARKER_KEY};
            const auto marker{
                ReadExactValue<DiskCatchupMarker>(db, marker_key)};
            if (!marker || marker->version != DiskCatchupMarker::VERSION ||
                marker->schema_hash != schema_hash ||
                marker->logical_id.IsNull() || marker->witness_id.IsNull() ||
                marker->checksum != GetCatchupMarkerChecksum(
                    marker->schema_hash, marker->logical_id,
                    marker->witness_id)) {
                throw std::runtime_error("corrupt PQ catch-up marker");
            }
            catchup_used = true;
        }

        if (found_unsealed) {
            const DiskKey unsealed_key{
                PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY};
            auto unsealed_record{
                ReadExactValue<DiskRecord>(db, unsealed_key)};
            if (!unsealed_record || !ValidateRecord(*unsealed_record) ||
                !IsReceiptableChainLock(unsealed_record->chainlock, config) ||
                (best && unsealed_record->chainlock.statement.height >
                             best->chainlock.statement.height)) {
                throw std::runtime_error(
                    "corrupt unsealed BTCC certificate record");
            }
            unsealed = std::move(*unsealed_record);
        }
        const auto best_base{best
            ? authorization_bases.find(best->logical_id)
            : authorization_bases.end()};
        const auto unsealed_base{unsealed
            ? authorization_bases.find(unsealed->logical_id)
            : authorization_bases.end()};
        if ((best_base != authorization_bases.end() &&
             !IsExactRecord(best_base->second, *best)) ||
            (unsealed_base != authorization_bases.end() &&
             !IsExactRecord(unsealed_base->second, *unsealed))) {
            throw std::runtime_error(
                "conflicting live PQ ChainLock authorization-base record");
        }
        if (best && !HasExactAuthorizationBase(*best)) {
            throw std::runtime_error(
                "missing live PQ ChainLock authorization-base record");
        }
        if (receipt_archive_authorization) {
            const auto predecessor_base{authorization_bases.find(
                receipt_archive_authorization->predecessor.logical_id)};
            if (predecessor_base == authorization_bases.end() ||
                predecessor_base->second.witness_id !=
                    receipt_archive_authorization->predecessor.witness_id ||
                predecessor_base->second.chainlock.statement !=
                    receipt_archive_authorization->predecessor.statement) {
                throw std::runtime_error(
                    "missing receipt-archive authorization-base record");
            }
        }

        if (!ValidateDurableRecoverySources(
                best ? &*best : nullptr,
                unsealed ? &*unsealed : nullptr,
                receipt_archive_authorization)) {
            throw std::runtime_error(
                "invalid durable recovery roster source");
        }

        if (found_payment_audit_seal_context) {
            const DiskKey seal_context_key{
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY};
            const auto disk{ReadExactValue<DiskPaymentAuditSealContext>(
                db, seal_context_key)};
            if (!disk || disk->version !=
                             DiskPaymentAuditSealContext::VERSION ||
                disk->schema_hash != schema_hash) {
                throw std::runtime_error(
                    "corrupt payment-audit seal context");
            }
            PaymentAuditSealContextCapsule loaded{
                disk->epoch, disk->carrier_end_height_exclusive,
                FinalChainLockRecordMetadata{
                    disk->seal_logical_id, disk->seal_witness_id,
                    disk->seal_statement},
                disk->authorization_mask};
            if (!loaded.IsInternallyConsistent(genesis_hash, config) ||
                disk->checksum != GetPaymentAuditSealContextChecksum(
                    disk->schema_hash, loaded) || !best ||
                loaded.Seal().statement.height >
                    best->chainlock.statement.height ||
                best->chainlock.statement.height >=
                    loaded.CarrierEndHeightExclusive() ||
                (loaded.Seal().statement.height ==
                     best->chainlock.statement.height &&
                 (loaded.Seal().logical_id != best->logical_id ||
                  loaded.Seal().witness_id != best->witness_id ||
                  loaded.Seal().statement !=
                      best->chainlock.statement))) {
                throw std::runtime_error(
                    "corrupt payment-audit seal context");
            }
            const DiskRecord* const seal_record{
                FindExactRetainedRecord(loaded.Seal())};
            RosterAuthorizationVerificationContext authorization;
            authorization.admission =
                RosterAuthorizationAdmission::TRUSTED_PERSISTENCE;
            authorization.predecessor_height =
                loaded.Seal().statement.previous_chainlock_height;
            authorization.predecessor_block_hash =
                loaded.Seal().statement.previous_chainlock_hash;
            ChainLockVerificationError verification_error{
                ChainLockVerificationError::NONE};
            const auto seal_context{
                seal_record && seal_record->decoded_roster_context
                    ? PreparedChainLockContext::CreateFromTrustedPersistence(
                          config.chainlock_schedule,
                          loaded.Seal().statement,
                          *seal_record->decoded_roster_context,
                          authorization, &verification_error)
                    : PreparedChainLockContextPtr{}};
            if (!seal_context ||
                seal_context->AuthorizationMask() !=
                    loaded.AuthorizationMask()) {
                throw std::runtime_error(
                    "missing exact payment-audit seal context");
            }
            payment_audit_seal_context = std::move(loaded);
        }

        const auto load_preseal_marker = [&](uint8_t key_type,
                                             const char* description) {
            const DiskKey marker_key{key_type};
            const auto marker{
                ReadExactValue<DiskBTCCPresealMarker>(db, marker_key)};
            if (!marker ||
                marker->version != DiskBTCCPresealMarker::VERSION ||
                marker->schema_hash != schema_hash) {
                throw std::runtime_error(
                    strprintf("corrupt %s", description));
            }
            const BTCCPresealMarker loaded{
                marker->earliest_carrier_height,
                marker->earliest_carrier_hash,
                marker->predecessor_receipt_state,
                marker->terminal_carrier_height,
                marker->terminal_carrier_hash,
                marker->terminal_parent_receipt_state,
                marker->terminal_receipt,
                marker->revision};
            if (!IsValidBTCCPresealMarker(config, loaded) ||
                marker->checksum != GetBTCCPresealMarkerChecksum(
                    marker->schema_hash, loaded)) {
                throw std::runtime_error(
                    strprintf("corrupt %s", description));
            }
            return loaded;
        };
        if (found_btcc_preseal) {
            btcc_preseal_state.active = load_preseal_marker(
                PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY,
                "BTCC pre-seal marker");
        }
        if (found_btcc_prospective_preseal) {
            btcc_preseal_state.prospective = load_preseal_marker(
                PQ_CHAINLOCK_PERSISTENCE_BTCC_PROSPECTIVE_PRESEAL_KEY,
                "prospective BTCC pre-seal marker");
        }
        if (!btcc_preseal_state.IsStructurallyValid()) {
            throw std::runtime_error("corrupt BTCC pre-seal state");
        }
        highest_btcc_preseal_revision =
            HighestBTCCPresealRevision(btcc_preseal_state);

        const auto load_payment_audit_preseal_marker =
            [&](uint8_t key_type, const char* description) {
                const DiskKey marker_key{key_type};
                const auto marker{
                    ReadExactValue<DiskPaymentAuditPresealMarker>(
                        db, marker_key)};
                if (!marker ||
                    marker->version !=
                        DiskPaymentAuditPresealMarker::VERSION ||
                    marker->schema_hash != schema_hash) {
                    throw std::runtime_error(
                        strprintf("corrupt %s", description));
                }
                const PaymentAuditPresealMarker loaded{
                    marker->earliest_carrier_height,
                    marker->earliest_carrier_hash,
                    marker->predecessor_receipt_state,
                    marker->predecessor_probation_state_hash,
                    marker->terminal_carrier_height,
                    marker->terminal_carrier_hash,
                    marker->terminal_receipt,
                    marker->revision};
                if (!IsValidPaymentAuditPresealMarker(config, loaded) ||
                    marker->checksum !=
                        GetPaymentAuditPresealMarkerChecksum(
                            marker->schema_hash, loaded)) {
                    throw std::runtime_error(
                        strprintf("corrupt %s", description));
                }
                return loaded;
            };
        if (found_payment_audit_preseal) {
            payment_audit_preseal_state.active =
                load_payment_audit_preseal_marker(
                    PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PRESEAL_KEY,
                    "payment-audit pre-seal marker");
        }
        if (found_payment_audit_prospective_preseal) {
            payment_audit_preseal_state.prospective =
                load_payment_audit_preseal_marker(
                    PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PROSPECTIVE_PRESEAL_KEY,
                    "prospective payment-audit pre-seal marker");
        }
        if (!payment_audit_preseal_state.IsStructurallyValid()) {
            throw std::runtime_error(
                "corrupt payment-audit pre-seal state");
        }
        highest_payment_audit_preseal_revision =
            HighestPaymentAuditPresealRevision(
                payment_audit_preseal_state);

        AuthorizationBaseView authorization_view;
        for (const auto& [logical_id, record] : authorization_bases) {
            authorization_view.emplace(logical_id, &record);
        }
        ChainLockPersistenceError recovery_error{
            ChainLockPersistenceError::NONE};
        const auto recovery_mutation{PrepareRecoveryUniverseMutation(
            best ? &*best : nullptr, unsealed ? &*unsealed : nullptr,
            authorization_view, receipt_archive_authorization,
            payment_audit_seal_context,
            /*supplied=*/nullptr, &recovery_error)};
        if (!recovery_mutation || recovery_mutation->addition ||
            !recovery_mutation->erasures.empty()) {
            throw std::runtime_error(
                "incomplete or orphaned recovery-universe persistence");
        }
        if (best || unsealed) certificate_revision = 1;
    }

    bool PersistBest(const FinalChainLock& chainlock,
                     const PreparedChainLockContextPtr& context,
                     ChainLockPersistenceError* error,
                     std::optional<PaymentAuditSealContextCapsule>
                         supplied_payment_audit_seal_context,
                     bool catchup = false,
                     const std::optional<BTCCCursorReconciliationProof>&
                         btcc_cursor_reconciliation = std::nullopt,
                     bool consume_recovery_precommit = false,
                     const ReceiptArchiveRosterAuthorization*
                         consume_receipt_archive_authorization = nullptr,
                     bool verified_reset_convergence = false,
                     RecoveryUniverseCapsulePtr recovery_universe = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid() ||
            !IsEligibleChainLockTarget(config.chainlock_schedule,
                                       chainlock.statement.height)) {
            SetError(error, failed ? ChainLockPersistenceError::IO_FAILURE
                                   : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        if (supplied_payment_audit_seal_context &&
            (!supplied_payment_audit_seal_context->IsInternallyConsistent(
                 genesis_hash, config) ||
             supplied_payment_audit_seal_context->Seal().statement !=
                 chainlock.statement ||
             supplied_payment_audit_seal_context->Seal().logical_id !=
                 chainlock.GetLogicalId(genesis_hash) ||
             supplied_payment_audit_seal_context->Seal().witness_id !=
                 chainlock.GetWitnessId(genesis_hash))) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        const auto transition{chainlock.statement.roster_transition};
        if ((!consume_recovery_precommit &&
             transition == RosterAuthorizationTransitionKind::INITIALIZE) ||
            (!consume_recovery_precommit && roster_recovery_precommit) ||
            (consume_recovery_precommit &&
             (transition != RosterAuthorizationTransitionKind::INITIALIZE ||
              catchup))) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        auto candidate_record{MakeRecord(chainlock, context)};
        if (!candidate_record) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        DiskRecord candidate{std::move(*candidate_record)};
        const std::size_t candidate_size{::GetSerializeSize(candidate)};
        if (candidate_size < DiskRecord::MIN_WIRE_SIZE ||
            candidate_size > DiskRecord::MAX_WIRE_SIZE) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (!ValidateRecord(candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        const bool exact_best{best && IsExactRecord(candidate, *best)};

        std::optional<PaymentAuditSealContextCapsule>
            next_payment_audit_seal_context{payment_audit_seal_context};
        if (!exact_best && next_payment_audit_seal_context &&
            candidate.chainlock.statement.height >=
                next_payment_audit_seal_context
                    ->CarrierEndHeightExclusive()) {
            next_payment_audit_seal_context.reset();
        }
        if (supplied_payment_audit_seal_context) {
            if (payment_audit_seal_context &&
                (supplied_payment_audit_seal_context->Epoch() <
                     payment_audit_seal_context->Epoch() ||
                 (supplied_payment_audit_seal_context->Epoch() ==
                      payment_audit_seal_context->Epoch() &&
                  *supplied_payment_audit_seal_context !=
                      *payment_audit_seal_context) ||
                 (supplied_payment_audit_seal_context->Epoch() >
                      payment_audit_seal_context->Epoch() &&
                  supplied_payment_audit_seal_context->Seal()
                          .statement.height <
                      payment_audit_seal_context
                          ->CarrierEndHeightExclusive()))) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            next_payment_audit_seal_context =
                std::move(supplied_payment_audit_seal_context);
        }
        if (next_payment_audit_seal_context &&
            !MatchesMetadata(
                candidate, next_payment_audit_seal_context->Seal()) &&
            FindExactRetainedRecord(
                next_payment_audit_seal_context->Seal()) == nullptr) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }

        if (!ValidateDurableRecoverySources(
                best ? &*best : nullptr,
                unsealed ? &*unsealed : nullptr,
                receipt_archive_authorization)) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }

        if (exact_best) {
            if (next_payment_audit_seal_context !=
                payment_audit_seal_context) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            if (consume_receipt_archive_authorization != nullptr ||
                btcc_cursor_reconciliation.has_value() ||
                (consume_recovery_precommit &&
                 !IsExactRecoveryStatement(chainlock))) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }

            AuthorizationBaseView authorization_view;
            for (const auto& [logical_id, retained] :
                 authorization_bases) {
                authorization_view.emplace(logical_id, &retained);
            }
            const auto recovery_mutation{
                PrepareRecoveryUniverseMutation(
                    &*best, unsealed ? &*unsealed : nullptr,
                    authorization_view, receipt_archive_authorization,
                    payment_audit_seal_context,
                    std::move(recovery_universe), error)};
            if (!recovery_mutation || recovery_mutation->addition ||
                !recovery_mutation->erasures.empty()) {
                if (recovery_mutation) {
                    SetError(error,
                             ChainLockPersistenceError::IO_FAILURE);
                }
                return false;
            }

            // The predecessor needed to reconstruct a RECOVER transition is
            // intentionally discarded once its successor is durable.  Exact
            // byte-for-byte replay is therefore a no-op after the durable
            // record and embedded recovery source have been checked above. In
            // particular, replay must not consume a newer local precommit.
            return true;
        }

        RosterAuthorizationTransition authorization_transition;
        authorization_transition.kind = transition;
        authorization_transition.target_height =
            candidate.chainlock.statement.height;
        authorization_transition.target_block_hash =
            candidate.chainlock.statement.block_hash;
        authorization_transition.predecessor_height =
            candidate.chainlock.statement.previous_chainlock_height;
        authorization_transition.predecessor_block_hash =
            candidate.chainlock.statement.previous_chainlock_hash;
        authorization_transition.authorization_base =
            candidate.chainlock.statement.roster_authorization_base;
        authorization_transition.new_window =
            candidate.chainlock.statement.roster_beacons;
        if (transition != RosterAuthorizationTransitionKind::INITIALIZE) {
            const DiskRecord* authorization_base{nullptr};
            if (best &&
                Metadata(*best).AuthorizationBase() ==
                    authorization_transition.authorization_base) {
                authorization_base = &*best;
            } else if (
                unsealed &&
                Metadata(*unsealed).AuthorizationBase() ==
                    authorization_transition.authorization_base) {
                authorization_base = &*unsealed;
            } else {
                const auto retained{authorization_bases.find(
                    authorization_transition.authorization_base.logical_id)};
                if (retained != authorization_bases.end() &&
                    Metadata(retained->second).AuthorizationBase() ==
                        authorization_transition.authorization_base) {
                    authorization_base = &retained->second;
                }
            }
            if (authorization_base == nullptr) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            authorization_transition.previous =
                RosterAuthorizationPriorState{
                    authorization_base->chainlock.statement
                        .roster_authorization_state_hash,
                    authorization_base->chainlock.statement.roster_beacons};
        }
        const auto expected_authorization_hash{
            GetRosterAuthorizationStateHash(
                genesis_hash, authorization_transition)};
        if (!expected_authorization_hash ||
            *expected_authorization_hash !=
                candidate.chainlock.statement
                    .roster_authorization_state_hash) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (consume_receipt_archive_authorization != nullptr &&
            (!best || !receipt_archive_authorization ||
             *receipt_archive_authorization !=
                 *consume_receipt_archive_authorization ||
             candidate.chainlock.statement.height <=
                 best->chainlock.statement.height)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (consume_recovery_precommit) {
            if (!IsExactRecoveryStatement(chainlock) ||
                (roster_recovery_precommit && !exact_best &&
                 !verified_reset_convergence &&
                 !DoesRecoveryCertificateMatchPrecommit(
                     chainlock, *roster_recovery_precommit, best,
                     genesis_hash)) ||
                (best && !exact_best)) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
        }
        const bool advances_best{
            !best || candidate.chainlock.statement.height >
                         best->chainlock.statement.height};
        const bool erase_recovery_precommit{
            (consume_recovery_precommit &&
             roster_recovery_precommit.has_value() && advances_best)};
        const bool cursor_regresses{
            best && !IsDurableBTCCursorMonotonic(
                best->chainlock.statement.accepted_btcc_cursor,
                candidate.chainlock.statement.accepted_btcc_cursor)};
        const bool reconciles_cursor{
            cursor_regresses && catchup && btcc_cursor_reconciliation &&
            IsBTCCCursorReconciliationProof(
                best->chainlock, candidate.chainlock,
                *btcc_cursor_reconciliation, config)};
        if (btcc_cursor_reconciliation && !reconciles_cursor) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (best) {
            if (candidate.chainlock.statement.height <
                best->chainlock.statement.height) {
                SetError(error, ChainLockPersistenceError::STALE_HEIGHT);
                return false;
            }
            if (candidate.chainlock.statement.height ==
                best->chainlock.statement.height) {
                if (exact_best) {
                    if (erase_recovery_precommit &&
                        roster_recovery_precommit) {
                        try {
                            CDBBatch batch{db};
                            batch.Erase(DiskKey{
                                PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY});
                            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                                failed = true;
                                SetError(error,
                                         ChainLockPersistenceError::IO_FAILURE);
                                return false;
                            }
                        } catch (const std::exception&) {
                            failed = true;
                            SetError(error,
                                     ChainLockPersistenceError::IO_FAILURE);
                            return false;
                        }
                        roster_recovery_precommit.reset();
                    }
                    return true;
                }
                SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
                return false;
            }
            if (cursor_regresses && !reconciles_cursor) {
                SetError(error, ChainLockPersistenceError::NON_MONOTONIC_BTCC);
                return false;
            }
            if (!IsDurableBTCCReceiptStateMonotonic(
                    best->chainlock.statement.btcc_receipt_state,
                    candidate.chainlock.statement.btcc_receipt_state)) {
                SetError(error,
                         ChainLockPersistenceError::NON_MONOTONIC_RECEIPT_STATE);
                return false;
            }
            if (!IsDurablePaymentAuditStateMonotonic(
                    best->chainlock.statement.payment_audit_receipt_state,
                    best->chainlock.statement.payment_probation_state_hash,
                    candidate.chainlock.statement
                        .payment_audit_receipt_state,
                    candidate.chainlock.statement
                        .payment_probation_state_hash)) {
                SetError(error,
                         ChainLockPersistenceError::NON_MONOTONIC_RECEIPT_STATE);
                return false;
            }
        }

        std::optional<ReceiptArchiveRosterAuthorization>
            next_receipt_archive_authorization{
                receipt_archive_authorization};
        if (consume_receipt_archive_authorization != nullptr) {
            next_receipt_archive_authorization.reset();
        }
        if (catchup && best &&
            best->chainlock.statement.height <
                candidate.chainlock.statement.previous_chainlock_height) {
            if (receipt_archive_authorization &&
                consume_receipt_archive_authorization == nullptr) {
                SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
                return false;
            }
            next_receipt_archive_authorization =
                MakeReceiptArchiveAuthorization(candidate, *best);
            if (!ValidateReceiptArchiveAuthorization(
                    *next_receipt_archive_authorization, &candidate)) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
        } else if (next_receipt_archive_authorization) {
            next_receipt_archive_authorization->covering_logical_id =
                candidate.logical_id;
            next_receipt_archive_authorization->covering_witness_id =
                candidate.witness_id;
        }
        if (next_receipt_archive_authorization &&
            !ValidateReceiptArchiveAuthorization(
                *next_receipt_archive_authorization, &candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        std::optional<DiskRecord> next_unsealed{unsealed};
        if (next_unsealed &&
            SealsUnsealedBTCC(chainlock, next_unsealed->chainlock, config)) {
            next_unsealed.reset();
        }
        if (IsReceiptableChainLock(chainlock, config)) {
            next_unsealed = candidate;
        }

        if (!ValidateRecoverySourceState(
                &candidate,
                next_unsealed ? &*next_unsealed : nullptr,
                next_receipt_archive_authorization,
                error)) {
            return false;
        }

        const auto candidate_base{
            authorization_bases.find(candidate.logical_id)};
        if (candidate_base != authorization_bases.end() &&
            !IsExactRecord(candidate_base->second, candidate)) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        const DiskRecord* previous_best{best ? &*best : nullptr};
        const auto previous_base{previous_best
            ? authorization_bases.find(previous_best->logical_id)
            : authorization_bases.end()};
        if (previous_best && previous_base != authorization_bases.end() &&
            !IsExactRecord(previous_base->second, *previous_best)) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        std::size_t next_authorization_base_count{
            authorization_bases.size()};
        const bool add_previous_best{
            previous_best && previous_base == authorization_bases.end() &&
            previous_best->logical_id != candidate.logical_id};
        const DiskRecord* departing_unsealed_base{
            unsealed &&
                    (!next_unsealed ||
                     !IsExactRecord(*unsealed, *next_unsealed))
                ? &*unsealed
                : nullptr};
        const auto departing_unsealed_archive{
            departing_unsealed_base
                ? authorization_bases.find(
                      departing_unsealed_base->logical_id)
                : authorization_bases.end()};
        if (departing_unsealed_base &&
            departing_unsealed_archive != authorization_bases.end() &&
            !IsExactRecord(departing_unsealed_archive->second,
                           *departing_unsealed_base)) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        const bool add_departing_unsealed_base{
            departing_unsealed_base &&
            departing_unsealed_archive == authorization_bases.end() &&
            (!previous_best ||
             previous_best->logical_id !=
                 departing_unsealed_base->logical_id)};
        if (add_previous_best) ++next_authorization_base_count;
        if (add_departing_unsealed_base) {
            ++next_authorization_base_count;
        }

        std::set<uint256> evict_authorization_bases;
        while (next_authorization_base_count -
                   evict_authorization_bases.size() >
               VERIFIED_AUTHORIZATION_BASE_CAPACITY) {
            const DiskRecord* oldest{nullptr};
            const auto matches_referenced_base = [this](
                const DiskRecord& record, const DiskRecord& owner) {
                const auto& identity{
                    owner.chainlock.statement.roster_authorization_base};
                return !identity.IsNull() &&
                       Metadata(record).AuthorizationBase() == identity;
            };
            const auto is_protected = [&](const DiskRecord& record) {
                const bool live_role{
                    IsExactRecord(record, candidate) ||
                    matches_referenced_base(record, candidate) ||
                    (previous_best &&
                     IsExactRecord(record, *previous_best)) ||
                    (departing_unsealed_base &&
                     IsExactRecord(record, *departing_unsealed_base)) ||
                    (next_unsealed &&
                     (IsExactRecord(record, *next_unsealed) ||
                      matches_referenced_base(record, *next_unsealed)))};
                const bool archive_role{
                    next_receipt_archive_authorization &&
                    record.logical_id ==
                        next_receipt_archive_authorization->predecessor
                            .logical_id &&
                    record.witness_id ==
                        next_receipt_archive_authorization->predecessor
                            .witness_id &&
                    record.chainlock.statement ==
                        next_receipt_archive_authorization->predecessor
                            .statement};
                const bool payment_audit_seal_role{
                    next_payment_audit_seal_context &&
                    MatchesMetadata(
                        record,
                        next_payment_audit_seal_context->Seal())};
                return live_role || archive_role ||
                       payment_audit_seal_role;
            };
            const auto consider_oldest = [&](const DiskRecord& record) {
                if (!evict_authorization_bases.contains(
                        record.logical_id) &&
                    !is_protected(record) &&
                    (!oldest ||
                     IsOlderAuthorizationBase(record, *oldest))) {
                    oldest = &record;
                }
            };
            for (const auto& [logical_id, retained] :
                 authorization_bases) {
                (void)logical_id;
                consider_oldest(retained);
            }
            if (add_previous_best) consider_oldest(*previous_best);
            if (add_departing_unsealed_base) {
                consider_oldest(*departing_unsealed_base);
            }
            if (!oldest) {
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
            evict_authorization_bases.insert(oldest->logical_id);
        }

        AuthorizationBaseView next_authorization_bases;
        for (const auto& [logical_id, retained] : authorization_bases) {
            if (!evict_authorization_bases.contains(logical_id)) {
                next_authorization_bases.emplace(logical_id, &retained);
            }
        }
        if (add_previous_best &&
            !evict_authorization_bases.contains(previous_best->logical_id)) {
            next_authorization_bases[previous_best->logical_id] =
                previous_best;
        }
        if (add_departing_unsealed_base &&
            !evict_authorization_bases.contains(
                departing_unsealed_base->logical_id)) {
            next_authorization_bases[departing_unsealed_base->logical_id] =
                departing_unsealed_base;
        }
        const auto recovery_mutation{PrepareRecoveryUniverseMutation(
            &candidate, next_unsealed ? &*next_unsealed : nullptr,
            next_authorization_bases,
            next_receipt_archive_authorization,
            next_payment_audit_seal_context,
            std::move(recovery_universe), error)};
        if (!recovery_mutation) return false;

        try {
            CDBBatch batch{db};
            if (!ApplyRecoveryUniverseMutation(
                    batch, *recovery_mutation, error)) {
                return false;
            }
            batch.Write(DiskKey{PQ_CHAINLOCK_PERSISTENCE_BEST_KEY}, candidate);
            if (add_previous_best &&
                !evict_authorization_bases.contains(
                    previous_best->logical_id)) {
                batch.Write(
                    DiskAuthorizationBaseKey{
                        PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY,
                        previous_best->logical_id},
                    *previous_best);
            }
            if (add_departing_unsealed_base &&
                !evict_authorization_bases.contains(
                    departing_unsealed_base->logical_id)) {
                batch.Write(
                    DiskAuthorizationBaseKey{
                        PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY,
                        departing_unsealed_base->logical_id},
                    *departing_unsealed_base);
            }
            for (const auto& evict_authorization_base :
                 evict_authorization_bases) {
                batch.Erase(DiskAuthorizationBaseKey{
                    PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY,
                    evict_authorization_base});
            }
            const DiskKey unsealed_key{
                PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY};
            if (next_unsealed) {
                batch.Write(unsealed_key, *next_unsealed);
            } else {
                batch.Erase(unsealed_key);
            }
            if (catchup) {
                // The marker is an audit record of the highest catch-up rebase,
                // not a one-shot fuse. Candidate monotonicity above guarantees
                // each overwrite advances beyond every prior durable winner.
                batch.Write(
                    DiskKey{PQ_CHAINLOCK_PERSISTENCE_CATCHUP_MARKER_KEY},
                    MakeCatchupMarker(candidate));
            }
            if (next_receipt_archive_authorization &&
                next_receipt_archive_authorization !=
                    receipt_archive_authorization) {
                const auto disk_authorization{
                    MakeDiskReceiptArchiveRosterAuthorization(
                        schema_hash,
                        *next_receipt_archive_authorization)};
                if (::GetSerializeSize(disk_authorization) !=
                    DiskReceiptArchiveRosterAuthorization::WIRE_SIZE) {
                    SetError(error,
                             ChainLockPersistenceError::INVALID_CHAINLOCK);
                    return false;
                }
                batch.Write(
                    DiskKey{
                        PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY},
                    disk_authorization);
            } else if (!next_receipt_archive_authorization &&
                       receipt_archive_authorization) {
                batch.Erase(DiskKey{
                    PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY});
            }
            if (erase_recovery_precommit) {
                batch.Erase(DiskKey{
                    PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY});
            }
            if (next_payment_audit_seal_context !=
                payment_audit_seal_context) {
                const DiskKey seal_context_key{
                    PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY};
                if (next_payment_audit_seal_context) {
                    const auto disk_seal_context{
                        MakeDiskPaymentAuditSealContext(
                            schema_hash,
                            *next_payment_audit_seal_context)};
                    batch.Write(seal_context_key, *disk_seal_context);
                } else {
                    batch.Erase(seal_context_key);
                }
            }
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        if (add_previous_best &&
            !evict_authorization_bases.contains(
                previous_best->logical_id)) {
            authorization_bases.emplace(previous_best->logical_id,
                                        *previous_best);
        }
        if (add_departing_unsealed_base &&
            !evict_authorization_bases.contains(
                departing_unsealed_base->logical_id)) {
            authorization_bases.emplace(
                departing_unsealed_base->logical_id,
                *departing_unsealed_base);
        }
        for (const auto& evict_authorization_base :
             evict_authorization_bases) {
            authorization_bases.erase(evict_authorization_base);
        }
        best = std::move(candidate);
        unsealed = std::move(next_unsealed);
        receipt_archive_authorization =
            std::move(next_receipt_archive_authorization);
        payment_audit_seal_context =
            std::move(next_payment_audit_seal_context);
        catchup_used = catchup_used || catchup;
        if (erase_recovery_precommit) {
            roster_recovery_precommit.reset();
        }
        CommitRecoveryUniverseMutation(*recovery_mutation);
        ++certificate_revision;
        return true;
    }

    bool PersistVerifiedAuthorizationBase(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error,
        RecoveryUniverseCapsulePtr recovery_universe)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid()) {
            SetError(error, failed
                                ? ChainLockPersistenceError::IO_FAILURE
                                : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        auto candidate_record{MakeRecord(chainlock, context)};
        if (!candidate_record) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        DiskRecord candidate{std::move(*candidate_record)};
        const std::size_t candidate_size{::GetSerializeSize(candidate)};
        if (candidate_size < DiskRecord::MIN_WIRE_SIZE ||
            candidate_size > DiskRecord::MAX_WIRE_SIZE ||
            !ValidateRecord(candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        const auto validate_live_collision = [&](const auto& live) {
            return !live || live->logical_id != candidate.logical_id ||
                   IsExactRecord(*live, candidate);
        };
        if (!validate_live_collision(best) ||
            !validate_live_collision(unsealed)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if ((best && IsExactRecord(*best, candidate)) ||
            (unsealed && IsExactRecord(*unsealed, candidate))) {
            return true;
        }

        const auto existing{authorization_bases.find(candidate.logical_id)};
        if (existing != authorization_bases.end()) {
            if (!IsExactRecord(existing->second, candidate)) {
                SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            return true;
        }
        for (const auto& [logical_id, retained] : authorization_bases) {
            if (logical_id != candidate.logical_id &&
                retained.witness_id == candidate.witness_id) {
                SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
        }

        std::optional<uint256> evict;
        if (authorization_bases.size() >=
            VERIFIED_AUTHORIZATION_BASE_CAPACITY) {
            const DiskRecord* const live_best{best ? &*best : nullptr};
            const DiskRecord* const live_unsealed{
                unsealed ? &*unsealed : nullptr};
            const auto matches_referenced_base = [this](
                const DiskRecord& record, const DiskRecord* owner) {
                return owner != nullptr &&
                       !owner->chainlock.statement.roster_authorization_base
                            .IsNull() &&
                       Metadata(record).AuthorizationBase() ==
                           owner->chainlock.statement
                               .roster_authorization_base;
            };
            const FinalChainLockRecordMetadata* const archive_predecessor{
                receipt_archive_authorization
                    ? &receipt_archive_authorization->predecessor
                    : nullptr};
            const FinalChainLockRecordMetadata* const payment_audit_seal{
                payment_audit_seal_context
                    ? &payment_audit_seal_context->Seal()
                    : nullptr};
            const auto is_protected = [&](const DiskRecord& record) {
                const bool live_role{
                    (live_best && IsExactRecord(record, *live_best)) ||
                    matches_referenced_base(record, live_best) ||
                    (live_unsealed &&
                     IsExactRecord(record, *live_unsealed)) ||
                    matches_referenced_base(record, live_unsealed) ||
                    matches_referenced_base(record, &candidate)};
                const bool archive_role{
                    archive_predecessor &&
                    record.logical_id ==
                        archive_predecessor->logical_id &&
                    record.witness_id ==
                        archive_predecessor->witness_id &&
                    record.chainlock.statement ==
                        archive_predecessor->statement};
                const bool payment_audit_seal_role{
                    payment_audit_seal &&
                    MatchesMetadata(record, *payment_audit_seal)};
                return live_role || archive_role ||
                       payment_audit_seal_role;
            };
            auto oldest{authorization_bases.end()};
            for (auto it{authorization_bases.begin()};
                 it != authorization_bases.end(); ++it) {
                if (is_protected(it->second)) continue;
                if (oldest == authorization_bases.end() ||
                    IsOlderAuthorizationBase(it->second,
                                               oldest->second)) {
                    oldest = it;
                }
            }
            if (oldest == authorization_bases.end()) {
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
            evict = oldest->first;
        }

        AuthorizationBaseView next_authorization_bases;
        for (const auto& [logical_id, retained] : authorization_bases) {
            if (!evict || logical_id != *evict) {
                next_authorization_bases.emplace(logical_id, &retained);
            }
        }
        next_authorization_bases[candidate.logical_id] = &candidate;
        const auto recovery_mutation{PrepareRecoveryUniverseMutation(
            best ? &*best : nullptr, unsealed ? &*unsealed : nullptr,
            next_authorization_bases, receipt_archive_authorization,
            payment_audit_seal_context,
            std::move(recovery_universe), error)};
        if (!recovery_mutation) return false;

        try {
            CDBBatch batch{db};
            if (!ApplyRecoveryUniverseMutation(
                    batch, *recovery_mutation, error)) {
                return false;
            }
            batch.Write(
                DiskAuthorizationBaseKey{
                    PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY,
                    candidate.logical_id},
                candidate);
            if (evict) {
                batch.Erase(DiskAuthorizationBaseKey{
                    PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY,
                    *evict});
            }
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        if (evict) authorization_bases.erase(*evict);
        authorization_bases.emplace(candidate.logical_id,
                                    std::move(candidate));
        CommitRecoveryUniverseMutation(*recovery_mutation);
        return true;
    }

    bool PersistUnsealedBTCC(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error,
        RecoveryUniverseCapsulePtr recovery_universe)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid() ||
            !IsReceiptableChainLock(chainlock, config)) {
            SetError(error, failed ? ChainLockPersistenceError::IO_FAILURE
                                   : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        auto candidate_record{MakeRecord(chainlock, context)};
        if (!candidate_record) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        DiskRecord candidate{std::move(*candidate_record)};
        const std::size_t candidate_size{::GetSerializeSize(candidate)};
        if (candidate_size < DiskRecord::MIN_WIRE_SIZE ||
            candidate_size > DiskRecord::MAX_WIRE_SIZE ||
            !ValidateRecord(candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        const bool exact_unsealed{
            unsealed && IsExactRecord(candidate, *unsealed)};
        if (unsealed && !exact_unsealed) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }
        const auto candidate_base{
            authorization_bases.find(candidate.logical_id)};
        if (candidate_base != authorization_bases.end() &&
            !IsExactRecord(candidate_base->second, candidate)) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }

        if (!ValidateRecoverySourceState(
                best ? &*best : nullptr, &candidate,
                receipt_archive_authorization,
                error)) {
            return false;
        }
        if (exact_unsealed) return true;

        AuthorizationBaseView authorization_view;
        for (const auto& [logical_id, retained] : authorization_bases) {
            authorization_view.emplace(logical_id, &retained);
        }
        const auto recovery_mutation{PrepareRecoveryUniverseMutation(
            best ? &*best : nullptr, &candidate, authorization_view,
            receipt_archive_authorization, payment_audit_seal_context,
            std::move(recovery_universe), error)};
        if (!recovery_mutation) return false;

        try {
            CDBBatch batch{db};
            if (!ApplyRecoveryUniverseMutation(
                    batch, *recovery_mutation, error)) {
                return false;
            }
            batch.Write(DiskKey{PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY},
                        candidate);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        unsealed = std::move(candidate);
        CommitRecoveryUniverseMutation(*recovery_mutation);
        ++certificate_revision;
        return true;
    }

    bool PersistAuthorizedUnsealedBTCC(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        const ReceiptArchiveRosterAuthorization& expected_authorization,
        ChainLockPersistenceError* error,
        RecoveryUniverseCapsulePtr recovery_universe)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid() ||
            !IsReceiptableChainLock(chainlock, config)) {
            SetError(error, failed
                                ? ChainLockPersistenceError::IO_FAILURE
                                : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        auto candidate_record{MakeRecord(chainlock, context)};
        if (!candidate_record) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        DiskRecord candidate{std::move(*candidate_record)};
        const std::size_t candidate_size{::GetSerializeSize(candidate)};
        if (candidate_size < DiskRecord::MIN_WIRE_SIZE ||
            candidate_size > DiskRecord::MAX_WIRE_SIZE ||
            !ValidateRecord(candidate) ||
            !receipt_archive_authorization ||
            *receipt_archive_authorization != expected_authorization ||
            !ValidateReceiptArchiveAuthorization(
                expected_authorization, best ? &*best : nullptr)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        const int32_t archive_height{candidate.chainlock.statement.height};
        if (archive_height <=
                expected_authorization.predecessor.statement.height ||
            archive_height >
                expected_authorization.owner.statement
                    .previous_chainlock_height) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        if (unsealed && !IsExactRecord(*unsealed, candidate)) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }

        if (!ValidateRecoverySourceState(
                best ? &*best : nullptr, &candidate, std::nullopt,
                error)) {
            return false;
        }

        AuthorizationBaseView authorization_view;
        for (const auto& [logical_id, retained] : authorization_bases) {
            authorization_view.emplace(logical_id, &retained);
        }
        const auto recovery_mutation{PrepareRecoveryUniverseMutation(
            best ? &*best : nullptr, &candidate, authorization_view,
            /*next_receipt_archive_authorization=*/std::nullopt,
            payment_audit_seal_context,
            std::move(recovery_universe), error)};
        if (!recovery_mutation) return false;

        try {
            CDBBatch batch{db};
            if (!ApplyRecoveryUniverseMutation(
                    batch, *recovery_mutation, error)) {
                return false;
            }
            if (!unsealed) {
                batch.Write(
                    DiskKey{PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY},
                    candidate);
            }
            batch.Erase(DiskKey{
                PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY});
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }

        if (!unsealed) unsealed = std::move(candidate);
        receipt_archive_authorization.reset();
        CommitRecoveryUniverseMutation(*recovery_mutation);
        ++certificate_revision;
        return true;
    }

    bool PersistRosterRecoveryPrecommit(
        const RosterRecoveryPrecommit& precommit,
        ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !IsValidRosterRecoveryPrecommit(config, precommit) ||
            !DoesRecoveryPrecommitMatchBest(precommit, best)) {
            SetError(error, failed
                                ? ChainLockPersistenceError::IO_FAILURE
                                : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (!roster_recovery_precommit &&
            precommit.pending_seed.state != RosterBeaconState::PENDING) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (roster_recovery_precommit &&
            *roster_recovery_precommit == precommit) {
            return true;
        }
        if (roster_recovery_precommit &&
            !IsExactRosterRecoveryResolution(
                *roster_recovery_precommit, precommit)) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }

        const auto disk{
            MakeDiskRosterRecoveryPrecommit(schema_hash, precommit)};
        if (::GetSerializeSize(disk) !=
            DiskRosterRecoveryPrecommit::WIRE_SIZE) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        try {
            CDBBatch batch{db};
            batch.Write(
                DiskKey{
                    PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY},
                disk);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        roster_recovery_precommit = precommit;
        return true;
    }

    bool ReplaceRosterRecoveryPrecommit(
        const RosterRecoveryPrecommit& expected,
        const RosterRecoveryPrecommit& replacement,
        ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed) {
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        if (!roster_recovery_precommit ||
            *roster_recovery_precommit != expected) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }
        if (!IsValidRosterRecoveryPrecommit(config, replacement) ||
            !DoesRecoveryPrecommitMatchBest(replacement, best) ||
            replacement.pending_seed.state != RosterBeaconState::PENDING) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (replacement == expected) return true;

        const uint32_t old_epoch{expected.pending_seed.epoch};
        const uint32_t new_epoch{replacement.pending_seed.epoch};
        const bool same_pending_slot{
            expected.pending_seed.state == RosterBeaconState::PENDING &&
            new_epoch == old_epoch &&
            replacement.pending_seed.anchor_cursor.sys_height ==
                expected.pending_seed.anchor_cursor.sys_height};
        if (!same_pending_slot) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        const auto disk{
            MakeDiskRosterRecoveryPrecommit(schema_hash, replacement)};
        if (::GetSerializeSize(disk) !=
            DiskRosterRecoveryPrecommit::WIRE_SIZE) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        try {
            CDBBatch batch{db};
            batch.Write(
                DiskKey{
                    PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY},
                disk);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        roster_recovery_precommit = replacement;
        return true;
    }

    bool PersistBTCCPresealState(const BTCCPresealState& state,
                                 ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        const auto valid_marker = [&](const auto& marker) {
            return !marker || IsValidBTCCPresealMarker(config, *marker);
        };
        if (failed || !state.IsStructurallyValid() ||
            !valid_marker(state.active) ||
            !valid_marker(state.prospective)) {
            SetError(error, failed ? ChainLockPersistenceError::IO_FAILURE
                                   : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (btcc_preseal_state == state) return true;
        if (!state.IsEmpty() &&
            !HasFreshBTCCPresealRevision(
                state, highest_btcc_preseal_revision)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        try {
            CDBBatch batch{db};
            const auto update_marker = [&](uint8_t key_type,
                                           const auto& marker) {
                const DiskKey key{key_type};
                if (marker) {
                    batch.Write(key, MakeBTCCPresealMarker(
                                         schema_hash, *marker));
                } else {
                    batch.Erase(key);
                }
            };
            update_marker(PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY,
                          state.active);
            update_marker(
                PQ_CHAINLOCK_PERSISTENCE_BTCC_PROSPECTIVE_PRESEAL_KEY,
                state.prospective);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        btcc_preseal_state = state;
        const uint64_t next_revision{HighestBTCCPresealRevision(state)};
        if (next_revision > highest_btcc_preseal_revision) {
            highest_btcc_preseal_revision = next_revision;
        }
        return true;
    }

    bool ClearBTCCPresealState(ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        return PersistBTCCPresealState(BTCCPresealState{}, error);
    }

    bool PersistPaymentAuditPresealState(
        const PaymentAuditPresealState& state,
        ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        const auto valid_marker = [&](const auto& marker) {
            return !marker ||
                   IsValidPaymentAuditPresealMarker(config, *marker);
        };
        if (failed || !state.IsStructurallyValid() ||
            !valid_marker(state.active) ||
            !valid_marker(state.prospective)) {
            SetError(error, failed
                                ? ChainLockPersistenceError::IO_FAILURE
                                : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (payment_audit_preseal_state == state) return true;
        if (!state.IsEmpty() &&
            !HasFreshPaymentAuditPresealRevision(
                state, highest_payment_audit_preseal_revision)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        try {
            CDBBatch batch{db};
            const auto update_marker = [&](uint8_t key_type,
                                           const auto& marker) {
                const DiskKey key{key_type};
                if (marker) {
                    batch.Write(
                        key, MakePaymentAuditPresealMarker(
                                 schema_hash, *marker));
                } else {
                    batch.Erase(key);
                }
            };
            update_marker(
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PRESEAL_KEY,
                state.active);
            update_marker(
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PROSPECTIVE_PRESEAL_KEY,
                state.prospective);
            if (!db.WriteBatch(batch, /*fSync=*/true)) {
                failed = true;
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            failed = true;
            SetError(error, ChainLockPersistenceError::IO_FAILURE);
            return false;
        }
        payment_audit_preseal_state = state;
        const uint64_t next_revision{
            HighestPaymentAuditPresealRevision(state)};
        if (next_revision > highest_payment_audit_preseal_revision) {
            highest_payment_audit_preseal_revision = next_revision;
        }
        return true;
    }

    bool ClearPaymentAuditPresealState(ChainLockPersistenceError* error)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        return PersistPaymentAuditPresealState(
            PaymentAuditPresealState{}, error);
    }

    const uint256 genesis_hash;
    const ChainLockFinalityStoreConfig config;
    const DiskSchema schema;
    const uint256 schema_hash;
    CDBWrapper db;

    mutable Mutex mutex;
    std::optional<DiskRecord> best GUARDED_BY(mutex);
    std::optional<DiskRecord> unsealed GUARDED_BY(mutex);
    std::map<uint256, DiskRecord> authorization_bases GUARDED_BY(mutex);
    std::map<uint256, RecoveryUniverseCapsulePtr> recovery_universes
        GUARDED_BY(mutex);
    std::optional<ReceiptArchiveRosterAuthorization>
        receipt_archive_authorization GUARDED_BY(mutex);
    uint64_t certificate_revision GUARDED_BY(mutex){0};
    BTCCPresealState btcc_preseal_state GUARDED_BY(mutex);
    uint64_t highest_btcc_preseal_revision GUARDED_BY(mutex){0};
    PaymentAuditPresealState payment_audit_preseal_state
        GUARDED_BY(mutex);
    uint64_t highest_payment_audit_preseal_revision
        GUARDED_BY(mutex){0};
    std::optional<RosterRecoveryPrecommit> roster_recovery_precommit
        GUARDED_BY(mutex);
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context GUARDED_BY(mutex);
    bool catchup_used GUARDED_BY(mutex){false};
    bool failed GUARDED_BY(mutex){false};
};

PQChainLockPersistence::PQChainLockPersistence(
    DBParams db_params,
    uint256 genesis_hash,
    ChainLockFinalityStoreConfig config)
    : m_impl{std::make_unique<Impl>(
          std::move(db_params), std::move(genesis_hash), std::move(config))}
{
}

PQChainLockPersistence::~PQChainLockPersistence() = default;

bool PQChainLockPersistence::HasBest() const
{
    LOCK(m_impl->mutex);
    return m_impl->best.has_value();
}

DurableFinalityStateView PQChainLockPersistence::GetFinalityState() const
{
    LOCK(m_impl->mutex);
    const auto metadata = [](const DiskRecord& record) {
        return FinalChainLockRecordMetadata{
            record.logical_id, record.witness_id,
            record.chainlock.statement};
    };
    DurableFinalityStateView view;
    view.certificate_revision = m_impl->certificate_revision;
    if (m_impl->best) view.best = metadata(*m_impl->best);
    if (m_impl->unsealed) {
        view.unsealed_btcc = metadata(*m_impl->unsealed);
    }
    view.receipt_archive_authorization =
        m_impl->receipt_archive_authorization;
    view.payment_audit_seal_context =
        m_impl->payment_audit_seal_context;
    return view;
}

std::optional<DurableChainLockRecord>
PQChainLockPersistence::LoadBest() const
{
    LOCK(m_impl->mutex);
    if (!m_impl->best) return std::nullopt;
    return m_impl->PublicRecord(*m_impl->best);
}

std::optional<DurableChainLockRecord>
PQChainLockPersistence::LoadUnsealedBTCC() const
{
    LOCK(m_impl->mutex);
    if (!m_impl->unsealed) return std::nullopt;
    return m_impl->PublicRecord(*m_impl->unsealed);
}

std::vector<DurableChainLockRecord>
PQChainLockPersistence::LoadAuthorizationBases() const
{
    LOCK(m_impl->mutex);
    std::vector<DurableChainLockRecord> result;
    result.reserve(m_impl->authorization_bases.size());
    for (const auto& [_, record] : m_impl->authorization_bases) {
        result.push_back(m_impl->PublicRecord(record));
    }
    std::sort(result.begin(), result.end(), [](const auto& left,
                                               const auto& right) {
        if (left.ChainLock().statement.height !=
            right.ChainLock().statement.height) {
            return left.ChainLock().statement.height <
                   right.ChainLock().statement.height;
        }
        return left.ChainLock().statement.block_hash <
               right.ChainLock().statement.block_hash;
    });
    return result;
}

std::optional<DurableChainLockRecord>
PQChainLockPersistence::LoadAuthorizationBase(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return std::nullopt;
    LOCK(m_impl->mutex);
    const auto found{m_impl->authorization_bases.find(logical_id)};
    if (found == m_impl->authorization_bases.end()) return std::nullopt;
    return m_impl->PublicRecord(found->second);
}

std::optional<std::vector<RecoveryRosterRetentionDependency>>
PQChainLockPersistence::LoadRecoveryRosterRetentionDependencies() const
{
    LOCK(m_impl->mutex);
    std::vector<RecoveryRosterRetentionDependency> result;
    result.reserve(m_impl->authorization_bases.size() + 6);
    const auto inspect = [&](const ChainLockStatement& statement) {
        std::optional<RecoveryRosterRetentionDependency> dependency;
        if (!GetRecoveryRosterRetentionDependency(statement, dependency)) {
            return false;
        }
        if (dependency && std::find(result.begin(), result.end(),
                                    *dependency) == result.end()) {
            result.push_back(*dependency);
        }
        return true;
    };
    if ((m_impl->best &&
         !inspect(m_impl->best->chainlock.statement)) ||
        (m_impl->unsealed &&
         !inspect(m_impl->unsealed->chainlock.statement))) {
        return std::nullopt;
    }
    for (const auto& [_, record] : m_impl->authorization_bases) {
        if (!inspect(record.chainlock.statement)) return std::nullopt;
    }
    if (m_impl->receipt_archive_authorization &&
        (!inspect(m_impl->receipt_archive_authorization->owner.statement) ||
         !inspect(m_impl->receipt_archive_authorization->predecessor
                      .statement))) {
        return std::nullopt;
    }
    if (m_impl->payment_audit_seal_context &&
        !inspect(m_impl->payment_audit_seal_context->Seal().statement)) {
        return std::nullopt;
    }
    return result;
}

std::optional<int32_t>
PQChainLockPersistence::OldestAuthorizationBaseHeight() const
{
    LOCK(m_impl->mutex);
    std::optional<int32_t> oldest;
    for (const auto& [_, record] : m_impl->authorization_bases) {
        const int32_t height{record.chainlock.statement.height};
        oldest = oldest ? std::min(*oldest, height) : height;
    }
    return oldest;
}

bool PQChainLockPersistence::HasCatchupMarker() const
{
    LOCK(m_impl->mutex);
    return m_impl->catchup_used;
}

BTCCPresealState PQChainLockPersistence::LoadBTCCPresealState() const
{
    LOCK(m_impl->mutex);
    return m_impl->btcc_preseal_state;
}

PaymentAuditPresealState
PQChainLockPersistence::LoadPaymentAuditPresealState() const
{
    LOCK(m_impl->mutex);
    return m_impl->payment_audit_preseal_state;
}

std::optional<RosterRecoveryPrecommit>
PQChainLockPersistence::LoadRosterRecoveryPrecommit() const
{
    LOCK(m_impl->mutex);
    return m_impl->roster_recovery_precommit;
}

std::optional<PaymentAuditSealContextCapsule>
PQChainLockPersistence::LoadPaymentAuditSealContext() const
{
    LOCK(m_impl->mutex);
    return m_impl->payment_audit_seal_context;
}

RecoveryUniverseCapsulePtr
PQChainLockPersistence::LoadRecoveryUniverse(
    const uint256& source_id) const
{
    if (source_id.IsNull()) return nullptr;
    LOCK(m_impl->mutex);
    const auto found{m_impl->recovery_universes.find(source_id)};
    return found == m_impl->recovery_universes.end()
        ? nullptr
        : found->second;
}

bool PQChainLockPersistence::PersistBest(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, context, error,
        std::move(payment_audit_seal_context), /*catchup=*/false,
        std::nullopt, /*consume_recovery_precommit=*/false, nullptr,
        /*verified_reset_convergence=*/false,
        std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistBestCoveringReceiptArchive(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    const ReceiptArchiveRosterAuthorization& expected_authorization,
    ChainLockPersistenceError* error,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, context, error,
        std::move(payment_audit_seal_context),
        /*catchup=*/false, std::nullopt,
        /*consume_recovery_precommit=*/false,
        &expected_authorization,
        /*verified_reset_convergence=*/false,
        std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistUnsealedBTCC(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistUnsealedBTCC(
        chainlock, context, error, std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistVerifiedAuthorizationBase(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistVerifiedAuthorizationBase(
        chainlock, context, error, std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistAuthorizedUnsealedBTCC(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    const ReceiptArchiveRosterAuthorization& expected_authorization,
    ChainLockPersistenceError* error,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistAuthorizedUnsealedBTCC(
        chainlock, context, expected_authorization, error,
        std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistCatchupBest(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    const std::optional<BTCCCursorReconciliationProof>&
        btcc_cursor_reconciliation,
    const ReceiptArchiveRosterAuthorization*
        consume_receipt_archive_authorization,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, context, error,
        std::move(payment_audit_seal_context),
        /*catchup=*/true,
        btcc_cursor_reconciliation,
        /*consume_recovery_precommit=*/false,
        consume_receipt_archive_authorization,
        /*verified_reset_convergence=*/false,
        std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistInitializedBest(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    const VerifiedRecoveryResetPersistenceCapability* verified_reset,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    const bool verified_reset_convergence{
        verified_reset != nullptr &&
        (verified_reset->Authorizes(
             m_impl->genesis_hash, chainlock,
             RosterAuthorizationTransitionKind::INITIALIZE,
             ChainLockCandidateAdmission::LIVE) ||
         verified_reset->Authorizes(
             m_impl->genesis_hash, chainlock,
             RosterAuthorizationTransitionKind::INITIALIZE,
             ChainLockCandidateAdmission::CATCHUP))};
    if (verified_reset != nullptr && !verified_reset_convergence) {
        SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
        return false;
    }
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, context, error,
        std::move(payment_audit_seal_context),
        /*catchup=*/false, std::nullopt,
        /*consume_recovery_precommit=*/true, nullptr,
        verified_reset_convergence, std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistRecoveryCatchupBest(
    const FinalChainLock& chainlock,
    const PreparedChainLockContextPtr& context,
    ChainLockPersistenceError* error,
    const std::optional<BTCCCursorReconciliationProof>&
        btcc_cursor_reconciliation,
    const ReceiptArchiveRosterAuthorization*
        consume_receipt_archive_authorization,
    const VerifiedRecoveryResetPersistenceCapability* verified_reset,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    const bool verified_reset_convergence{
        verified_reset != nullptr && verified_reset->Authorizes(
            m_impl->genesis_hash, chainlock,
            RosterAuthorizationTransitionKind::RECOVER,
            ChainLockCandidateAdmission::CATCHUP)};
    if (verified_reset != nullptr && !verified_reset_convergence) {
        SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
        return false;
    }
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, context, error,
        std::move(payment_audit_seal_context),
        /*catchup=*/true,
        btcc_cursor_reconciliation,
        /*consume_recovery_precommit=*/false,
        consume_receipt_archive_authorization,
        verified_reset_convergence, std::move(recovery_universe));
}

bool PQChainLockPersistence::PersistRosterRecoveryPrecommit(
    const RosterRecoveryPrecommit& precommit,
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistRosterRecoveryPrecommit(precommit, error);
}

bool PQChainLockPersistence::ReplaceRosterRecoveryPrecommit(
    const RosterRecoveryPrecommit& expected,
    const RosterRecoveryPrecommit& replacement,
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->ReplaceRosterRecoveryPrecommit(
        expected, replacement, error);
}

bool PQChainLockPersistence::PersistBTCCPresealState(
    const BTCCPresealState& state,
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBTCCPresealState(state, error);
}

bool PQChainLockPersistence::ClearBTCCPresealState(
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->ClearBTCCPresealState(error);
}

bool PQChainLockPersistence::PersistPaymentAuditPresealState(
    const PaymentAuditPresealState& state,
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistPaymentAuditPresealState(state, error);
}

bool PQChainLockPersistence::ClearPaymentAuditPresealState(
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    return m_impl->ClearPaymentAuditPresealState(error);
}

} // namespace llmq::pq
