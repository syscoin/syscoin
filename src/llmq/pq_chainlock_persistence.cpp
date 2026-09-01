// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_persistence.h>

#include <llmq/btc_header_policy.h>
#include <llmq/pq_roster_beacon.h>

#include <hash.h>
#include <streams.h>
#include <sync.h>

#include <array>
#include <exception>
#include <ios>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace llmq::pq {

bool RosterRecoveryPrecommit::IsStructurallyValid() const noexcept
{
    if (version != ROSTER_RECOVERY_PRECOMMIT_VERSION ||
        (admission != RosterRecoveryAdmission::INITIALIZE &&
         admission != RosterRecoveryAdmission::CURRENT_CATCHUP) ||
        !pending_seed.IsStructurallyValid() ||
        (pending_seed.state != RosterBeaconState::PENDING &&
         !pending_seed.IsReady()) ||
        pending_seed.epoch % ACTIVE_QUORUMS != ACTIVE_QUORUMS - 1) {
        return false;
    }
    if (admission == RosterRecoveryAdmission::INITIALIZE) {
        return predecessor_height == -1 && predecessor_hash.IsNull() &&
               recovery_authority_hash.IsNull() &&
               recovery_authority_source.IsNull() &&
               pending_seed.anchor_kind == RosterBeaconAnchorKind::NORMAL;
    }
    return predecessor_height >= 0 && !predecessor_hash.IsNull() &&
           !recovery_authority_hash.IsNull() &&
           !recovery_authority_source.IsNull() &&
           recovery_authority_source.IsStructurallyValid() &&
           recovery_authority_source.kind ==
               RecoveryRosterAuthoritySourceKind::NORMAL_ROSTERS &&
           pending_seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY &&
           pending_seed.anchor_cursor.sys_height > predecessor_height;
}

uint256 GetRosterRecoveryPrecommitRolloverContextId(
    const uint256& genesis_hash,
    const RosterRecoveryPrecommit& expected,
    const RosterRecoveryPrecommit& replacement)
{
    if (genesis_hash.IsNull() || !expected.IsStructurallyValid() ||
        !replacement.IsStructurallyValid() ||
        expected.admission != RosterRecoveryAdmission::CURRENT_CATCHUP ||
        replacement.admission !=
            RosterRecoveryAdmission::CURRENT_CATCHUP) {
        return {};
    }
    auto normalized_replacement{replacement};
    // The paired Bitcoin-policy proof binds the observed replacement height.
    normalized_replacement.pending_seed.anchor_btc_height = -1;
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{
                  "SYS_PQ_ROSTER_RECOVERY_ROLLOVER_CONTEXT_V1"}
           << genesis_hash << expected << normalized_replacement;
    return writer.GetHash();
}

PaymentAuditSealContextCapsule::PaymentAuditSealContextCapsule(
    uint32_t epoch,
    int32_t carrier_end_height_exclusive,
    FinalChainLockRecordMetadata seal,
    uint8_t authorization_mask,
    RecoveryRosterAuthorityPtr recovery_authority)
    : m_epoch{epoch},
      m_carrier_end_height_exclusive{carrier_end_height_exclusive},
      m_seal{std::move(seal)},
      m_authorization_mask{authorization_mask},
      m_recovery_authority{std::move(recovery_authority)}
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
    const bool needs_authority{
        HasRecoveryRosterBeacon(m_seal.statement.roster_beacons)};
    if (needs_authority != static_cast<bool>(m_recovery_authority)) {
        return false;
    }
    if (!m_recovery_authority) return true;
    const auto authority_hash{
        GetRecoveryRosterAuthorityHash(genesis_hash,
                                       *m_recovery_authority)};
    return authority_hash &&
           *authority_hash == m_seal.statement.roster_beacons.active
                                  .recovery_authority_hash;
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
        context->AuthorizationMask(), context->RecoveryAuthorityPtr()};
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
inline constexpr std::string_view RECOVERY_AUTHORITY_HASH_DOMAIN{
    "SYS_PQ_RECOVERY_AUTHORITY_RECORD_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_SEAL_CONTEXT_HASH_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_SEAL_CONTEXT_V1"};

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
};

struct DiskSchema {
    static constexpr std::size_t WIRE_SIZE{290};

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
                          const FinalChainLock& chainlock)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECORD_HASH_DOMAIN);
    writer << schema_hash << logical_id << witness_id << chainlock;
    return writer.GetHash();
}

struct DiskRecord {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 4 * 32 + FinalChainLock::WIRE_SIZE};

    uint16_t record_version{RECORD_VERSION};
    uint256 schema_hash;
    uint256 logical_id;
    uint256 witness_id;
    FinalChainLock chainlock;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, record_version, schema_hash, logical_id,
                        witness_id, chainlock, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure(
                "invalid PQ ChainLock DB record size");
        }
        ::UnserializeMany(stream, record_version, schema_hash, logical_id,
                          witness_id, chainlock, checksum);
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

struct DiskRecoveryRosterAuthority {
    static constexpr uint16_t VERSION{1};

    uint16_t version{VERSION};
    uint256 schema_hash;
    uint256 owner_logical_id;
    uint256 owner_witness_id;
    uint256 authority_hash;
    RecoveryRosterAuthority authority;
    uint256 checksum;

    SERIALIZE_METHODS(DiskRecoveryRosterAuthority, obj)
    {
        READWRITE(obj.version, obj.schema_hash, obj.owner_logical_id,
                  obj.owner_witness_id, obj.authority_hash, obj.authority,
                  obj.checksum);
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
    std::optional<RecoveryRosterAuthority> recovery_authority;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        const uint8_t has_authority{recovery_authority ? uint8_t{1}
                                                       : uint8_t{0}};
        ::SerializeMany(stream, version, schema_hash, epoch,
                        carrier_end_height_exclusive, seal_logical_id,
                        seal_witness_id, seal_statement,
                        authorization_mask, has_authority);
        if (recovery_authority) {
            ::Serialize(stream, *recovery_authority);
        }
        ::Serialize(stream, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        uint8_t has_authority{0};
        ::UnserializeMany(stream, version, schema_hash, epoch,
                          carrier_end_height_exclusive, seal_logical_id,
                          seal_witness_id, seal_statement,
                          authorization_mask, has_authority);
        if (has_authority > 1) {
            throw std::ios_base::failure(
                "non-canonical payment-audit seal authority flag");
        }
        if (has_authority != 0) {
            recovery_authority.emplace();
            ::Unserialize(stream, *recovery_authority);
        } else {
            recovery_authority.reset();
        }
        ::Unserialize(stream, checksum);
    }
};

/**
 * One exact durable certificate identity owns the single retained authority.
 * Every simultaneous durable obligation must name the same authority hash.
 */
struct RecoveryAuthorityRequirement {
    uint256 owner_logical_id;
    uint256 owner_witness_id;
    uint256 authority_hash;
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
        4 * 32 + BTCCReceiptState::WIRE_SIZE + BTCCReceipt::WIRE_SIZE};

    uint16_t version{VERSION};
    uint256 schema_hash;
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    BTCCReceiptState predecessor_receipt_state;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    BTCCReceipt terminal_receipt;
    uint64_t revision{0};
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, schema_hash,
                        earliest_carrier_height, earliest_carrier_hash,
                        predecessor_receipt_state, terminal_carrier_height,
                        terminal_carrier_hash, terminal_receipt, revision,
                        checksum);
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
                          terminal_carrier_hash, terminal_receipt, revision,
                          checksum);
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

uint256 GetRecoveryAuthorityChecksum(
    const uint256& schema_hash,
    const uint256& owner_logical_id,
    const uint256& owner_witness_id,
    const uint256& authority_hash,
    const RecoveryRosterAuthority& authority)
{
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_AUTHORITY_HASH_DOMAIN);
    writer << schema_hash << owner_logical_id << owner_witness_id
           << authority_hash << authority;
    return writer.GetHash();
}

std::unique_ptr<DiskRecoveryRosterAuthority> MakeDiskRecoveryRosterAuthority(
    const uint256& schema_hash,
    const RecoveryAuthorityRequirement& requirement,
    const RecoveryRosterAuthority& authority,
    const uint256& genesis_hash)
{
    const auto authority_hash{
        GetRecoveryRosterAuthorityHash(genesis_hash, authority)};
    if (!authority_hash) return nullptr;
    auto disk{std::make_unique<DiskRecoveryRosterAuthority>()};
    disk->schema_hash = schema_hash;
    disk->owner_logical_id = requirement.owner_logical_id;
    disk->owner_witness_id = requirement.owner_witness_id;
    disk->authority_hash = *authority_hash;
    disk->authority = authority;
    disk->checksum = GetRecoveryAuthorityChecksum(
        disk->schema_hash, disk->owner_logical_id, disk->owner_witness_id,
        disk->authority_hash, disk->authority);
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
           << capsule.AuthorizationMask()
           << static_cast<bool>(capsule.RecoveryAuthority());
    if (capsule.RecoveryAuthority()) {
        writer << *capsule.RecoveryAuthority();
    }
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
    if (capsule.RecoveryAuthority()) {
        disk->recovery_authority = *capsule.RecoveryAuthority();
    }
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

bool AddRecoveryAuthorityRequirement(
    const uint256& logical_id,
    const uint256& witness_id,
    const ChainLockStatement& statement,
    std::optional<RecoveryAuthorityRequirement>& requirement)
{
    if (!HasRecoveryRosterBeacon(statement.roster_beacons)) return true;
    const uint256& authority_hash{
        statement.roster_beacons.active.recovery_authority_hash};
    if (logical_id.IsNull() || witness_id.IsNull() ||
        authority_hash.IsNull()) {
        return false;
    }
    if (requirement) return requirement->authority_hash == authority_hash;
    requirement = RecoveryAuthorityRequirement{
        logical_id, witness_id, authority_hash};
    return true;
}

bool GetRecoveryAuthorityRequirement(
    const DiskRecord* best,
    const DiskRecord* unsealed,
    const std::optional<ReceiptArchiveRosterAuthorization>&
        receipt_archive_authorization,
    std::optional<RecoveryAuthorityRequirement>& requirement)
{
    requirement.reset();
    const auto add_record = [&](const DiskRecord& record) {
        return AddRecoveryAuthorityRequirement(
            record.logical_id, record.witness_id,
            record.chainlock.statement, requirement);
    };
    const auto add_metadata = [&](const FinalChainLockRecordMetadata& record) {
        return AddRecoveryAuthorityRequirement(
            record.logical_id, record.witness_id, record.statement,
            requirement);
    };
    return (best == nullptr || add_record(*best)) &&
           (unsealed == nullptr || add_record(*unsealed)) &&
           (!receipt_archive_authorization ||
            (add_metadata(receipt_archive_authorization->owner) &&
             add_metadata(receipt_archive_authorization->predecessor)));
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
           << marker.terminal_carrier_hash << marker.terminal_receipt
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

static_assert(DiskRecord::WIRE_SIZE < MAX_SIZE);
static_assert(DiskRosterRecoveryPrecommit::WIRE_SIZE == 766);
static_assert(DiskReceiptArchiveRosterAuthorization::WIRE_SIZE < MAX_SIZE);
static_assert(DiskBTCCPresealMarker::WIRE_SIZE == 384);
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
    const auto source_height{BTCCSourceHeightForNEVMInjection(
        config.btcc_schedule, marker.terminal_carrier_height)};
    const auto signing_height{SigningHeightForTarget(
        config.chainlock_schedule,
        marker.terminal_receipt.chainlock_target_height)};
    if (!source_height || !signing_height ||
        marker.terminal_receipt.chainlock_target_height != *source_height ||
        marker.terminal_receipt.chainlock_target_height <=
            config.activation_predecessor_height ||
        marker.terminal_receipt.accepted_cursor.sys_height != *source_height ||
        marker.terminal_receipt.chainlock_target_hash !=
            marker.terminal_receipt.accepted_cursor.sys_hash ||
        (marker.terminal_carrier_height ==
             marker.earliest_carrier_height &&
         marker.terminal_carrier_hash !=
             marker.earliest_carrier_hash) ||
        static_cast<int64_t>(*signing_height) +
                PQ_BTCC_RECEIPT_PROPAGATION_BUFFER !=
            marker.terminal_carrier_height) {
        return false;
    }
    const auto& predecessor{marker.predecessor_receipt_state.cursor};
    return predecessor.IsNull() ||
           (predecessor.sys_height < marker.earliest_carrier_height &&
            marker.terminal_receipt.accepted_cursor.sys_height >
                predecessor.sys_height);
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
           (precommit.admission != RosterRecoveryAdmission::INITIALIZE ||
            (initial_target &&
             pending_seed.anchor_cursor.sys_height == *initial_target)) &&
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

bool IsReceiptableAdvance(const FinalChainLock& chainlock,
                          const ChainLockFinalityStoreConfig& config) noexcept
{
    const auto& statement{chainlock.statement};
    return statement.btcc_advance == BTCCAdvance::ADVANCE &&
           statement.height == statement.accepted_btcc_cursor.sys_height &&
           IsBTCCCandidateHeight(config.btcc_schedule, statement.height);
}

bool SealsUnsealedBTCC(const FinalChainLock& seal,
                       const FinalChainLock& unsealed,
                       const ChainLockFinalityStoreConfig& config) noexcept
{
    if (!IsReceiptableAdvance(unsealed, config) ||
        !seal.statement.btcc_receipt_state.IsStructurallyValid()) {
        return false;
    }
    const int64_t carrier_height{
        static_cast<int64_t>(unsealed.statement.height) +
        config.btcc_schedule.nevm_injection_lag};
    return carrier_height <= std::numeric_limits<int32_t>::max() &&
           seal.statement.height >= carrier_height;
}

bool IsExactRecoveryStatement(
    const FinalChainLock& chainlock,
    RosterRecoveryAdmission expected_admission) noexcept
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
    if (expected_admission == RosterRecoveryAdmission::INITIALIZE) {
        return chainlock.statement.roster_transition ==
                   RosterAuthorizationTransitionKind::INITIALIZE &&
               IsInitialNormalRosterBeaconWindow(window);
    }
    return chainlock.statement.roster_transition ==
               RosterAuthorizationTransitionKind::RECOVER &&
           IsRecoveryRosterBeaconWindow(window);
}

bool DoesRecoveryPrecommitMatchBest(
    const RosterRecoveryPrecommit& precommit,
    const std::optional<DiskRecord>& best) noexcept
{
    if (precommit.admission == RosterRecoveryAdmission::INITIALIZE) {
        return !best && precommit.predecessor_height == -1 &&
               precommit.predecessor_hash.IsNull() &&
               precommit.recovery_authority_hash.IsNull() &&
               precommit.recovery_authority_source.IsNull();
    }
    if (!best ||
        precommit.predecessor_height !=
            best->chainlock.statement.height ||
        precommit.predecessor_hash !=
            best->chainlock.statement.block_hash) {
        return false;
    }
    const auto& best_bundle{
        best->chainlock.statement.roster_beacons.active};
    if (HasRecoveryRosterBeacon(
            best->chainlock.statement.roster_beacons)) {
        return precommit.recovery_authority_hash ==
                   best_bundle.recovery_authority_hash &&
               precommit.recovery_authority_source ==
                   best_bundle.recovery_authority_source;
    }
    return precommit.recovery_authority_source.kind ==
               RecoveryRosterAuthoritySourceKind::NORMAL_ROSTERS &&
           precommit.recovery_authority_source.height ==
               best->chainlock.statement.height &&
           precommit.recovery_authority_source.block_hash ==
               best->chainlock.statement.block_hash &&
           precommit.recovery_authority_source.quorum_context_hash ==
               best->chainlock.statement.quorum_context_hash &&
           precommit.recovery_authority_source.normal_beacons ==
               best_bundle.seeds;
}

bool IsExactRosterRecoveryResolution(
    const RosterRecoveryPrecommit& pending,
    const RosterRecoveryPrecommit& ready) noexcept
{
    return pending.version == ready.version &&
           pending.admission == ready.admission &&
           pending.predecessor_height == ready.predecessor_height &&
           pending.predecessor_hash == ready.predecessor_hash &&
           pending.recovery_authority_hash ==
               ready.recovery_authority_hash &&
           pending.recovery_authority_source ==
               ready.recovery_authority_source &&
           IsExactRosterBeaconReveal(
               pending.pending_seed, ready.pending_seed);
}

bool DoesRecoveryCertificateMatchPrecommit(
    const FinalChainLock& chainlock,
    const RosterRecoveryPrecommit& precommit,
    const std::optional<DiskRecord>& durable_best,
    const uint256& genesis_hash,
    const uint256& prior_authority_hash,
    const uint256& next_authority_hash) noexcept
{
    if (!DoesRecoveryPrecommitMatchBest(precommit, durable_best) ||
        !IsExactRecoveryStatement(chainlock, precommit.admission)) {
        return false;
    }
    const auto& next_bundle{
        chainlock.statement.roster_beacons.active};
    if (precommit.admission == RosterRecoveryAdmission::INITIALIZE) {
        if (!next_authority_hash.IsNull() ||
            !precommit.recovery_authority_hash.IsNull() ||
            !precommit.recovery_authority_source.IsNull() ||
            !next_bundle.recovery_authority_hash.IsNull() ||
            !next_bundle.recovery_authority_source.IsNull()) {
            return false;
        }
    } else if (next_authority_hash.IsNull() ||
               precommit.recovery_authority_hash != next_authority_hash ||
               next_bundle.recovery_authority_hash != next_authority_hash ||
               precommit.recovery_authority_source !=
                   next_bundle.recovery_authority_source) {
        return false;
    }
    const auto& ready{
        chainlock.statement.roster_beacons.active.seeds.back()};
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
    transition.new_window = chainlock.statement.roster_beacons;
    if (precommit.admission == RosterRecoveryAdmission::CURRENT_CATCHUP) {
        if (!durable_best) return false;
        if (durable_best->chainlock.statement.roster_beacons.active
                .recovery_authority_hash != prior_authority_hash) {
            return false;
        }
        transition.previous = RosterAuthorizationPriorState{
            durable_best->chainlock.statement
                .roster_authorization_state_hash,
            durable_best->chainlock.statement.roster_beacons};
    } else if (durable_best) {
        return false;
    }
    const auto expected_state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    return expected_state_hash &&
           *expected_state_hash ==
               chainlock.statement.roster_authorization_state_hash;
}

template <typename Value>
std::unique_ptr<Value> ReadExactValue(CDBWrapper& db, const DiskKey& key)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return nullptr;
    }

    DiskKey found_key;
    auto value{std::make_unique<Value>()};
    if (!iterator->GetKeyExact(found_key) || found_key.type != key.type ||
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

    DiskRecord MakeRecord(const FinalChainLock& chainlock) const
    {
        DiskRecord record;
        record.schema_hash = schema_hash;
        record.logical_id = chainlock.GetLogicalId(genesis_hash);
        record.witness_id = chainlock.GetWitnessId(genesis_hash);
        record.chainlock = chainlock;
        record.checksum = GetRecordChecksum(
            schema_hash, record.logical_id, record.witness_id, chainlock);
        return record;
    }

    bool ValidateRecord(const DiskRecord& record) const
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
                record.chainlock)) {
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
             IsExactRecoveryStatement(
                 record.chainlock,
                 RosterRecoveryAdmission::INITIALIZE))};
        return exact_initializer && next_target &&
               statement.height == *next_target &&
               statement.height > config.activation_predecessor_height &&
               statement.previous_chainlock_height >= config.activation_predecessor_height &&
               (statement.previous_chainlock_height != config.activation_predecessor_height ||
                (!statement.previous_chainlock_hash.IsNull() &&
                 statement.previous_btcc_cursor.IsNull()));
    }

    FinalChainLockRecordMetadata Metadata(const DiskRecord& record) const
    {
        return FinalChainLockRecordMetadata{
            record.logical_id, record.witness_id,
            record.chainlock.statement};
    }

    bool PrepareRecoveryAuthorityState(
        const DiskRecord* next_best,
        const DiskRecord* next_unsealed,
        const std::optional<ReceiptArchiveRosterAuthorization>&
            next_receipt_archive_authorization,
        RecoveryRosterAuthorityPtr supplied_authority,
        const RecoveryRosterAuthorityPtr& retained_authority,
        RecoveryRosterAuthorityPtr& next_authority,
        std::unique_ptr<DiskRecoveryRosterAuthority>& next_disk_authority,
        ChainLockPersistenceError* error) const
    {
        std::optional<RecoveryAuthorityRequirement> requirement;
        if (!GetRecoveryAuthorityRequirement(
                next_best, next_unsealed,
                next_receipt_archive_authorization, requirement)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (!requirement) {
            if (supplied_authority) {
                SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            next_authority.reset();
            next_disk_authority.reset();
            return true;
        }

        next_authority = supplied_authority
            ? std::move(supplied_authority)
            : retained_authority;
        const auto authority_hash{next_authority
            ? GetRecoveryRosterAuthorityHash(genesis_hash, *next_authority)
            : std::optional<uint256>{}};
        if (!authority_hash ||
            *authority_hash != requirement->authority_hash) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        next_disk_authority = MakeDiskRecoveryRosterAuthority(
            schema_hash, *requirement, *next_authority, genesis_hash);
        if (!next_disk_authority ||
            next_disk_authority->authority_hash !=
                requirement->authority_hash) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        return true;
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
        bool found_recovery_authority{false};
        bool found_payment_audit_seal_context{false};
        {
            std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
            for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
                any = true;
                DiskKey key;
                if (!iterator->GetKeyExact(key)) {
                    throw std::runtime_error(
                        "corrupt PQ ChainLock persistence key");
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
                           PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY) {
                    if (found_recovery_authority) {
                        throw std::runtime_error(
                            "duplicate recovery roster authority");
                    }
                    found_recovery_authority = true;
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
                !IsReceiptableAdvance(unsealed_record->chainlock, config) ||
                (best && unsealed_record->chainlock.statement.height >
                             best->chainlock.statement.height)) {
                throw std::runtime_error(
                    "corrupt unsealed BTCC certificate record");
            }
            unsealed = std::move(*unsealed_record);
        }

        std::optional<RecoveryAuthorityRequirement> authority_requirement;
        if (!GetRecoveryAuthorityRequirement(
                best ? &*best : nullptr,
                unsealed ? &*unsealed : nullptr,
                receipt_archive_authorization,
                authority_requirement)) {
            throw std::runtime_error(
                "conflicting recovery roster authority obligations");
        }
        if (found_recovery_authority !=
            authority_requirement.has_value()) {
            throw std::runtime_error(
                "recovery roster authority/durable obligation mismatch");
        }
        if (found_recovery_authority) {
            const DiskKey authority_key{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY};
            const auto disk{ReadExactValue<DiskRecoveryRosterAuthority>(
                db, authority_key)};
            const auto authority_hash{disk
                ? GetRecoveryRosterAuthorityHash(
                      genesis_hash, disk->authority)
                : std::optional<uint256>{}};
            if (!disk || !authority_requirement ||
                disk->version != DiskRecoveryRosterAuthority::VERSION ||
                disk->schema_hash != schema_hash ||
                disk->owner_logical_id !=
                    authority_requirement->owner_logical_id ||
                disk->owner_witness_id !=
                    authority_requirement->owner_witness_id ||
                !authority_hash || disk->authority_hash != *authority_hash ||
                disk->authority_hash !=
                    authority_requirement->authority_hash ||
                disk->checksum != GetRecoveryAuthorityChecksum(
                    disk->schema_hash, disk->owner_logical_id,
                    disk->owner_witness_id, disk->authority_hash,
                    disk->authority)) {
                throw std::runtime_error(
                    "corrupt recovery roster authority");
            }
            recovery_authority =
                std::make_shared<const RecoveryRosterAuthority>(
                    disk->authority);
        }

        if (found_payment_audit_seal_context) {
            const DiskKey seal_context_key{
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY};
            const auto disk{ReadExactValue<DiskPaymentAuditSealContext>(
                db, seal_context_key)};
            RecoveryRosterAuthorityPtr authority;
            if (disk && disk->recovery_authority) {
                authority = std::make_shared<const RecoveryRosterAuthority>(
                    *disk->recovery_authority);
            }
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
                disk->authorization_mask, std::move(authority)};
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
        if (best || unsealed) certificate_revision = 1;
    }

    bool PersistBest(const FinalChainLock& chainlock,
                     ChainLockPersistenceError* error,
                     RecoveryRosterAuthorityPtr supplied_recovery_authority,
                     std::optional<PaymentAuditSealContextCapsule>
                         supplied_payment_audit_seal_context,
                     bool catchup = false,
                     const std::optional<BTCCCursorReconciliationProof>&
                         btcc_cursor_reconciliation = std::nullopt,
                     std::optional<RosterRecoveryAdmission>
                         consume_recovery_precommit = std::nullopt,
                     const ReceiptArchiveRosterAuthorization*
                         consume_receipt_archive_authorization = nullptr,
                     bool verified_reset_convergence = false)
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
        if ((verified_reset_convergence && !consume_recovery_precommit) ||
            (!consume_recovery_precommit &&
             (transition == RosterAuthorizationTransitionKind::INITIALIZE ||
              transition == RosterAuthorizationTransitionKind::RECOVER)) ||
            (!consume_recovery_precommit &&
             roster_recovery_precommit &&
             roster_recovery_precommit->admission ==
                 RosterRecoveryAdmission::INITIALIZE) ||
            (consume_recovery_precommit ==
                 RosterRecoveryAdmission::INITIALIZE &&
             catchup) ||
            (consume_recovery_precommit ==
                 RosterRecoveryAdmission::CURRENT_CATCHUP &&
             !catchup)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        DiskRecord candidate{MakeRecord(chainlock)};
        if (::GetSerializeSize(candidate) != DiskRecord::WIRE_SIZE) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        if (!ValidateRecord(candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        const bool exact_best{
            best && candidate.witness_id == best->witness_id &&
            candidate.logical_id == best->logical_id &&
            candidate.checksum == best->checksum &&
            candidate.chainlock == best->chainlock};

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

        const bool needs_recovery_authority{HasRecoveryRosterBeacon(
            candidate.chainlock.statement.roster_beacons)};
        RecoveryRosterAuthorityPtr candidate_recovery_authority{
            std::move(supplied_recovery_authority)};
        if (!candidate_recovery_authority && needs_recovery_authority &&
            exact_best) {
            candidate_recovery_authority = recovery_authority;
        }
        if (!candidate_recovery_authority && needs_recovery_authority &&
            transition != RosterAuthorizationTransitionKind::INITIALIZE &&
            transition != RosterAuthorizationTransitionKind::RECOVER) {
            candidate_recovery_authority = recovery_authority;
        }
        if (needs_recovery_authority !=
                static_cast<bool>(candidate_recovery_authority)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        uint256 next_recovery_authority_hash;
        if (candidate_recovery_authority) {
            const auto hash{GetRecoveryRosterAuthorityHash(
                genesis_hash, *candidate_recovery_authority)};
            if (!hash) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            next_recovery_authority_hash = *hash;
        }
        if (candidate.chainlock.statement.roster_beacons.active
                .recovery_authority_hash !=
            next_recovery_authority_hash) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        uint256 prior_recovery_authority_hash;
        if (recovery_authority) {
            const auto hash{GetRecoveryRosterAuthorityHash(
                genesis_hash, *recovery_authority)};
            if (!hash) {
                SetError(error, ChainLockPersistenceError::IO_FAILURE);
                return false;
            }
            prior_recovery_authority_hash = *hash;
        }
        std::optional<RecoveryAuthorityRequirement>
            current_authority_requirement;
        if (!GetRecoveryAuthorityRequirement(
                best ? &*best : nullptr,
                unsealed ? &*unsealed : nullptr,
                receipt_archive_authorization,
                current_authority_requirement) ||
            current_authority_requirement.has_value() !=
                static_cast<bool>(recovery_authority) ||
            (current_authority_requirement &&
             current_authority_requirement->authority_hash !=
                 prior_recovery_authority_hash)) {
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
                 !IsExactRecoveryStatement(
                     chainlock, *consume_recovery_precommit))) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }

            // The predecessor needed to reconstruct a RECOVER transition is
            // intentionally discarded once its successor is durable.  Exact
            // byte-for-byte replay is therefore a no-op after the durable
            // record and retained authority have been checked above.  In
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
        authorization_transition.new_window =
            candidate.chainlock.statement.roster_beacons;
        if (transition != RosterAuthorizationTransitionKind::INITIALIZE) {
            if (!best) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
            authorization_transition.previous =
                RosterAuthorizationPriorState{
                    best->chainlock.statement
                        .roster_authorization_state_hash,
                    best->chainlock.statement.roster_beacons};
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
            if (!IsExactRecoveryStatement(
                    chainlock, *consume_recovery_precommit) ||
                (roster_recovery_precommit && !exact_best &&
                 !verified_reset_convergence &&
                 !DoesRecoveryCertificateMatchPrecommit(
                     chainlock, *roster_recovery_precommit, best,
                     genesis_hash, prior_recovery_authority_hash,
                     next_recovery_authority_hash)) ||
                (*consume_recovery_precommit ==
                     RosterRecoveryAdmission::INITIALIZE &&
                 best && !exact_best)) {
                SetError(error,
                         ChainLockPersistenceError::INVALID_CHAINLOCK);
                return false;
            }
        }
        const bool ordinary_invalidates_current_recovery{
            !consume_recovery_precommit &&
            transition != RosterAuthorizationTransitionKind::RECOVER &&
            roster_recovery_precommit &&
            roster_recovery_precommit->admission ==
                RosterRecoveryAdmission::CURRENT_CATCHUP &&
            (candidate.chainlock.statement.height >
                 roster_recovery_precommit->predecessor_height ||
             (candidate.chainlock.statement.height ==
                  roster_recovery_precommit->predecessor_height &&
              candidate.chainlock.statement.block_hash !=
                  roster_recovery_precommit->predecessor_hash))};
        const bool advances_best{
            !best || candidate.chainlock.statement.height >
                         best->chainlock.statement.height};
        const bool erase_recovery_precommit{
            (consume_recovery_precommit.has_value() &&
             roster_recovery_precommit.has_value() && advances_best) ||
            ordinary_invalidates_current_recovery};
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
        if (IsReceiptableAdvance(chainlock, config)) {
            next_unsealed = candidate;
        }

        RecoveryRosterAuthorityPtr next_recovery_authority;
        std::unique_ptr<DiskRecoveryRosterAuthority>
            next_disk_recovery_authority;
        if (!PrepareRecoveryAuthorityState(
                &candidate,
                next_unsealed ? &*next_unsealed : nullptr,
                next_receipt_archive_authorization,
                std::move(candidate_recovery_authority),
                recovery_authority,
                next_recovery_authority,
                next_disk_recovery_authority, error)) {
            return false;
        }

        try {
            CDBBatch batch{db};
            batch.Write(DiskKey{PQ_CHAINLOCK_PERSISTENCE_BEST_KEY}, candidate);
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
            const DiskKey recovery_authority_key{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY};
            if (next_disk_recovery_authority) {
                batch.Write(recovery_authority_key,
                            *next_disk_recovery_authority);
            } else {
                batch.Erase(recovery_authority_key);
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
        best = std::move(candidate);
        unsealed = std::move(next_unsealed);
        receipt_archive_authorization =
            std::move(next_receipt_archive_authorization);
        recovery_authority = std::move(next_recovery_authority);
        payment_audit_seal_context =
            std::move(next_payment_audit_seal_context);
        catchup_used = catchup_used || catchup;
        if (erase_recovery_precommit) {
            roster_recovery_precommit.reset();
        }
        ++certificate_revision;
        return true;
    }

    bool PersistUnsealedBTCC(
        const FinalChainLock& chainlock,
        ChainLockPersistenceError* error,
        RecoveryRosterAuthorityPtr supplied_recovery_authority)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid() ||
            !IsReceiptableAdvance(chainlock, config)) {
            SetError(error, failed ? ChainLockPersistenceError::IO_FAILURE
                                   : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        DiskRecord candidate{MakeRecord(chainlock)};
        if (::GetSerializeSize(candidate) != DiskRecord::WIRE_SIZE ||
            !ValidateRecord(candidate)) {
            SetError(error, ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }
        const bool exact_unsealed{
            unsealed && unsealed->logical_id == candidate.logical_id &&
            unsealed->witness_id == candidate.witness_id &&
            unsealed->checksum == candidate.checksum &&
            unsealed->chainlock == candidate.chainlock};
        if (unsealed && !exact_unsealed) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }

        RecoveryRosterAuthorityPtr next_recovery_authority;
        std::unique_ptr<DiskRecoveryRosterAuthority>
            next_disk_recovery_authority;
        if (!PrepareRecoveryAuthorityState(
                best ? &*best : nullptr, &candidate,
                receipt_archive_authorization,
                std::move(supplied_recovery_authority),
                recovery_authority,
                next_recovery_authority,
                next_disk_recovery_authority, error)) {
            return false;
        }
        if (exact_unsealed) return true;

        try {
            CDBBatch batch{db};
            batch.Write(DiskKey{PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY},
                        candidate);
            const DiskKey recovery_authority_key{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY};
            if (next_disk_recovery_authority) {
                batch.Write(recovery_authority_key,
                            *next_disk_recovery_authority);
            } else {
                batch.Erase(recovery_authority_key);
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
        unsealed = std::move(candidate);
        recovery_authority = std::move(next_recovery_authority);
        ++certificate_revision;
        return true;
    }

    bool PersistAuthorizedUnsealedBTCC(
        const FinalChainLock& chainlock,
        const ReceiptArchiveRosterAuthorization& expected_authorization,
        ChainLockPersistenceError* error,
        RecoveryRosterAuthorityPtr supplied_recovery_authority)
        EXCLUSIVE_LOCKS_REQUIRED(mutex)
    {
        SetError(error, ChainLockPersistenceError::NONE);
        if (failed || !chainlock.IsStructurallyValid() ||
            !IsReceiptableAdvance(chainlock, config)) {
            SetError(error, failed
                                ? ChainLockPersistenceError::IO_FAILURE
                                : ChainLockPersistenceError::INVALID_CHAINLOCK);
            return false;
        }

        DiskRecord candidate{MakeRecord(chainlock)};
        if (::GetSerializeSize(candidate) != DiskRecord::WIRE_SIZE ||
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

        if (unsealed &&
            (unsealed->logical_id != candidate.logical_id ||
             unsealed->witness_id != candidate.witness_id ||
             unsealed->checksum != candidate.checksum ||
             unsealed->chainlock != candidate.chainlock)) {
            SetError(error, ChainLockPersistenceError::HEIGHT_CONFLICT);
            return false;
        }

        RecoveryRosterAuthorityPtr next_recovery_authority;
        std::unique_ptr<DiskRecoveryRosterAuthority>
            next_disk_recovery_authority;
        if (!PrepareRecoveryAuthorityState(
                best ? &*best : nullptr, &candidate, std::nullopt,
                std::move(supplied_recovery_authority),
                recovery_authority,
                next_recovery_authority,
                next_disk_recovery_authority, error)) {
            return false;
        }

        try {
            CDBBatch batch{db};
            if (!unsealed) {
                batch.Write(
                    DiskKey{PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY},
                    candidate);
            }
            batch.Erase(DiskKey{
                PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY});
            const DiskKey recovery_authority_key{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY};
            if (next_disk_recovery_authority) {
                batch.Write(recovery_authority_key,
                            *next_disk_recovery_authority);
            } else {
                batch.Erase(recovery_authority_key);
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

        if (!unsealed) unsealed = std::move(candidate);
        receipt_archive_authorization.reset();
        recovery_authority = std::move(next_recovery_authority);
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
            replacement.pending_seed.state != RosterBeaconState::PENDING ||
            replacement.admission != expected.admission ||
            replacement.predecessor_height != expected.predecessor_height ||
            replacement.predecessor_hash != expected.predecessor_hash ||
            replacement.recovery_authority_hash !=
                expected.recovery_authority_hash ||
            replacement.recovery_authority_source !=
                expected.recovery_authority_source) {
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

    bool ReplaceStablyInactiveRosterRecoveryPrecommit(
        const RosterRecoveryPrecommit& expected,
        const RosterRecoveryPrecommit& replacement,
        bool inactive_anchor_authorized,
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

        const auto& old_seed{expected.pending_seed};
        const auto& new_seed{replacement.pending_seed};
        const auto canonical_target{CanonicalRosterRecoveryTargetHeight(
            config.chainlock_schedule, config.btcc_schedule,
            new_seed.epoch)};
        const uint64_t first_disjoint_epoch{
            static_cast<uint64_t>(old_seed.epoch) + ACTIVE_QUORUMS};
        if (expected.admission !=
                RosterRecoveryAdmission::CURRENT_CATCHUP ||
            replacement.admission !=
                RosterRecoveryAdmission::CURRENT_CATCHUP ||
            old_seed.state != RosterBeaconState::PENDING ||
            new_seed.state != RosterBeaconState::PENDING ||
            !inactive_anchor_authorized ||
            !IsValidRosterRecoveryPrecommit(config, replacement) ||
            !DoesRecoveryPrecommitMatchBest(replacement, best) ||
            replacement.admission != expected.admission ||
            replacement.predecessor_height != expected.predecessor_height ||
            replacement.predecessor_hash != expected.predecessor_hash ||
            replacement.recovery_authority_hash !=
                expected.recovery_authority_hash ||
            replacement.recovery_authority_source !=
                expected.recovery_authority_source ||
            static_cast<uint64_t>(new_seed.epoch) < first_disjoint_epoch ||
            !canonical_target ||
            *canonical_target != new_seed.anchor_cursor.sys_height ||
            new_seed.anchor_cursor.sys_height <=
                old_seed.anchor_cursor.sys_height ||
            new_seed.anchor_cursor.btc_hash ==
                old_seed.anchor_cursor.btc_hash) {
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
    RecoveryRosterAuthorityPtr recovery_authority GUARDED_BY(mutex);
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

std::optional<FinalChainLock> PQChainLockPersistence::LoadBest() const
{
    LOCK(m_impl->mutex);
    if (!m_impl->best) return std::nullopt;
    return m_impl->best->chainlock;
}

std::optional<FinalChainLock> PQChainLockPersistence::LoadUnsealedBTCC() const
{
    LOCK(m_impl->mutex);
    if (!m_impl->unsealed) return std::nullopt;
    return m_impl->unsealed->chainlock;
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

RecoveryRosterAuthorityPtr
PQChainLockPersistence::LoadRecoveryRosterAuthority() const
{
    LOCK(m_impl->mutex);
    return m_impl->recovery_authority;
}

std::optional<PaymentAuditSealContextCapsule>
PQChainLockPersistence::LoadPaymentAuditSealContext() const
{
    LOCK(m_impl->mutex);
    return m_impl->payment_audit_seal_context;
}

bool PQChainLockPersistence::PersistBest(
    const FinalChainLock& chainlock,
    ChainLockPersistenceError* error,
    RecoveryRosterAuthorityPtr recovery_authority,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, error, std::move(recovery_authority),
        std::move(payment_audit_seal_context));
}

bool PQChainLockPersistence::PersistBestCoveringReceiptArchive(
    const FinalChainLock& chainlock,
    const ReceiptArchiveRosterAuthorization& expected_authorization,
    ChainLockPersistenceError* error,
    RecoveryRosterAuthorityPtr recovery_authority,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, error, std::move(recovery_authority),
        std::move(payment_audit_seal_context),
        /*catchup=*/false, std::nullopt, std::nullopt,
        &expected_authorization);
}

bool PQChainLockPersistence::PersistUnsealedBTCC(
    const FinalChainLock& chainlock,
    ChainLockPersistenceError* error,
    RecoveryRosterAuthorityPtr recovery_authority)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistUnsealedBTCC(
        chainlock, error, std::move(recovery_authority));
}

bool PQChainLockPersistence::PersistAuthorizedUnsealedBTCC(
    const FinalChainLock& chainlock,
    const ReceiptArchiveRosterAuthorization& expected_authorization,
    ChainLockPersistenceError* error,
    RecoveryRosterAuthorityPtr recovery_authority)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistAuthorizedUnsealedBTCC(
        chainlock, expected_authorization, error,
        std::move(recovery_authority));
}

bool PQChainLockPersistence::PersistCatchupBest(
    const FinalChainLock& chainlock,
    ChainLockPersistenceError* error,
    const std::optional<BTCCCursorReconciliationProof>&
        btcc_cursor_reconciliation,
    const ReceiptArchiveRosterAuthorization*
        consume_receipt_archive_authorization,
    RecoveryRosterAuthorityPtr recovery_authority,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context)
{
    LOCK(m_impl->mutex);
    return m_impl->PersistBest(
        chainlock, error, std::move(recovery_authority),
        std::move(payment_audit_seal_context),
        /*catchup=*/true,
        btcc_cursor_reconciliation, std::nullopt,
        consume_receipt_archive_authorization);
}

bool PQChainLockPersistence::PersistInitializedBest(
    const FinalChainLock& chainlock,
    ChainLockPersistenceError* error,
    RecoveryRosterAuthorityPtr recovery_authority,
    const VerifiedRecoveryResetPersistenceCapability* verified_reset,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context)
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
        chainlock, error, std::move(recovery_authority),
        std::move(payment_audit_seal_context),
        /*catchup=*/false, std::nullopt,
        RosterRecoveryAdmission::INITIALIZE, nullptr,
        verified_reset_convergence);
}

bool PQChainLockPersistence::PersistRecoveryCatchupBest(
    const FinalChainLock& chainlock,
    ChainLockPersistenceError* error,
    const std::optional<BTCCCursorReconciliationProof>&
        btcc_cursor_reconciliation,
    const ReceiptArchiveRosterAuthorization*
        consume_receipt_archive_authorization,
    RecoveryRosterAuthorityPtr recovery_authority,
    const VerifiedRecoveryResetPersistenceCapability* verified_reset,
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context)
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
        chainlock, error, std::move(recovery_authority),
        std::move(payment_audit_seal_context),
        /*catchup=*/true,
        btcc_cursor_reconciliation,
        RosterRecoveryAdmission::CURRENT_CATCHUP,
        consume_receipt_archive_authorization,
        verified_reset_convergence);
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

bool PQChainLockPersistence::
ReplaceStablyInactiveRosterRecoveryPrecommit(
    const RosterRecoveryPrecommit& expected,
    const RosterRecoveryPrecommit& replacement,
    const BTCRecoveryPrecommitRolloverProof& rollover_proof,
    ChainLockPersistenceError* error)
{
    LOCK(m_impl->mutex);
    std::optional<uint256> previous_btc_hash;
    if (m_impl->best &&
        !m_impl->best->chainlock.statement.accepted_btcc_cursor.IsNull()) {
        previous_btc_hash = m_impl->best->chainlock.statement
                                .accepted_btcc_cursor.btc_hash;
    }
    const uint256 rollover_context_id{
        GetRosterRecoveryPrecommitRolloverContextId(
            m_impl->genesis_hash, expected, replacement)};
    const bool rollover_authorized{rollover_proof.Authorizes(
        expected.pending_seed.anchor_cursor.btc_hash,
        expected.pending_seed.anchor_btc_height,
        replacement.pending_seed.anchor_cursor.btc_hash,
        replacement.pending_seed.anchor_btc_height,
        previous_btc_hash, rollover_context_id)};
    return m_impl->ReplaceStablyInactiveRosterRecoveryPrecommit(
        expected, replacement, rollover_authorized, error);
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
