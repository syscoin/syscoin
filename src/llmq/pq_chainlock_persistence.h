// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H

#include <dbwrapper.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_chainlock_store.h>
#include <llmq/pq_payment_audit.h>
#include <llmq/pq_quorum_builder.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace llmq {
class CChainLocksHandler;
}

namespace llmq::pq {

/** These one-byte keys are part of the fail-closed on-disk schema. */
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_SCHEMA_KEY{1};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BEST_KEY{2};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY{3};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_CATCHUP_MARKER_KEY{4};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY{5};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BTCC_PROSPECTIVE_PRESEAL_KEY{6};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PRESEAL_KEY{7};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PROSPECTIVE_PRESEAL_KEY{8};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY{9};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY{10};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY{12};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_AUTHORIZATION_BASE_KEY{13};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_RECOVERY_UNIVERSE_KEY{14};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_HISTORICAL_SYNC_KEY{15};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_HISTORICAL_SYNC_FALLBACK_KEY{16};

/**
 * One capsule for every independently bounded durable source owner: the
 * retained authorization rows, current best, current unsealed receipt target,
 * receipt-archive owner metadata, and both historical synchronization anchors.
 */
inline constexpr std::size_t RECOVERY_UNIVERSE_DURABLE_OWNER_CAPACITY{
    VERIFIED_AUTHORIZATION_BASE_CAPACITY + 5};

inline constexpr uint16_t ROSTER_RECOVERY_PRECOMMIT_VERSION{1};

/**
 * Local INITIALIZE signer-safety state, not network verification authority.
 * It is first fsynced as PENDING before the future Bitcoin block exists, then
 * may advance exactly once to READY before any share is produced. Normal
 * handoffs and outage recovery are authorized by durable ChainLock state and
 * never use this record.
 */
struct RosterRecoveryPrecommit {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + RosterBeaconSeed::WIRE_SIZE};

    uint16_t version{ROSTER_RECOVERY_PRECOMMIT_VERSION};
    RosterBeaconSeed pending_seed;

    SERIALIZE_METHODS(RosterRecoveryPrecommit, obj)
    {
        READWRITE(obj.version, obj.pending_seed);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical roster recovery precommit");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RosterRecoveryPrecommit&,
                           const RosterRecoveryPrecommit&) = default;
};

static_assert(RosterRecoveryPrecommit::WIRE_SIZE == 114);

/**
 * Crash-durable bounds for one deferred BTCC/NEVM replay obligation.
 *
 * The earliest carrier is the block-pruning floor. The terminal receipt is
 * the exact certificate dependency currently needed to extend the
 * authenticated prefix. The two parent states bind both ends of the replay
 * range, so its terminal KEEP cannot substitute an unrelated cursor.
 */
struct BTCCPresealMarker {
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    BTCCReceiptState predecessor_receipt_state;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    BTCCReceiptState terminal_parent_receipt_state;
    BTCCReceipt terminal_receipt;
    uint64_t revision{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return earliest_carrier_height >= 0 &&
               !earliest_carrier_hash.IsNull() &&
               predecessor_receipt_state.IsStructurallyValid() &&
               terminal_carrier_height >= earliest_carrier_height &&
               !terminal_carrier_hash.IsNull() &&
               terminal_parent_receipt_state.IsStructurallyValid() &&
               terminal_receipt.IsStructurallyValid() &&
               !terminal_receipt.IsNull() && revision > 0;
    }

    friend bool operator==(const BTCCPresealMarker&,
                           const BTCCPresealMarker&) = default;
};

/**
 * Crash-durable replay obligations for the active branch and the one
 * prospective most-work branch ActivateBestChain can be evaluating.
 *
 * Keeping both prevents a prospective carrier from erasing an earlier active
 * boundary before the prospective branch is durably activated.
 */
struct BTCCPresealState {
    std::optional<BTCCPresealMarker> active;
    std::optional<BTCCPresealMarker> prospective;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return (!active || active->IsStructurallyValid()) &&
               (!prospective || prospective->IsStructurallyValid()) &&
               (!active || !prospective ||
                active->terminal_carrier_height !=
                    prospective->terminal_carrier_height ||
                active->terminal_carrier_hash !=
                    prospective->terminal_carrier_hash);
    }

    [[nodiscard]] bool IsEmpty() const noexcept
    {
        return !active && !prospective;
    }

    friend bool operator==(const BTCCPresealState&,
                           const BTCCPresealState&) = default;
};

/**
 * Crash-durable boundary for compact historical payment-audit replay.
 *
 * The receipt carries the deterministic transition bitmap, so the exact large
 * audit witness is not needed to reconstruct state.  The reconstructed prefix
 * remains provisional until a normally verified descendant ChainLock signs
 * both the cumulative receipt state and the resulting probation-state root.
 */
struct PaymentAuditPresealMarker {
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    PaymentAuditReceiptState predecessor_receipt_state;
    uint256 predecessor_probation_state_hash;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    PaymentAuditReceipt terminal_receipt;
    uint64_t revision{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return earliest_carrier_height >= 0 &&
               !earliest_carrier_hash.IsNull() &&
               predecessor_receipt_state.IsStructurallyValid() &&
               !predecessor_probation_state_hash.IsNull() &&
               terminal_carrier_height >= earliest_carrier_height &&
               !terminal_carrier_hash.IsNull() &&
               terminal_receipt.IsStructurallyValid() &&
               !terminal_receipt.IsNull() &&
               terminal_receipt.carrier_height == terminal_carrier_height &&
               revision > 0;
    }

    friend bool operator==(const PaymentAuditPresealMarker&,
                           const PaymentAuditPresealMarker&) = default;
};

struct PaymentAuditPresealState {
    std::optional<PaymentAuditPresealMarker> active;
    std::optional<PaymentAuditPresealMarker> prospective;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return (!active || active->IsStructurallyValid()) &&
               (!prospective || prospective->IsStructurallyValid()) &&
               (!active || !prospective ||
                active->terminal_carrier_height !=
                    prospective->terminal_carrier_height ||
                active->terminal_carrier_hash !=
                    prospective->terminal_carrier_hash);
    }

    [[nodiscard]] bool IsEmpty() const noexcept
    {
        return !active && !prospective;
    }

    friend bool operator==(const PaymentAuditPresealState&,
                           const PaymentAuditPresealState&) = default;
};

inline constexpr uint16_t PAYMENT_AUDIT_SEAL_CONTEXT_VERSION{1};

/**
 * Locator and retention lease for the exact accepted seal record across the
 * bounded audit-carrier window. The record itself owns the immutable roster
 * bytes; missing or mismatched record state is a local fail-closed error.
 */
class PaymentAuditSealContextCapsule final {
public:
    [[nodiscard]] uint32_t Epoch() const noexcept { return m_epoch; }
    [[nodiscard]] int32_t CarrierEndHeightExclusive() const noexcept
    {
        return m_carrier_end_height_exclusive;
    }
    [[nodiscard]] const FinalChainLockRecordMetadata& Seal() const noexcept
    {
        return m_seal;
    }
    [[nodiscard]] uint8_t AuthorizationMask() const noexcept
    {
        return m_authorization_mask;
    }
    [[nodiscard]] bool IsInternallyConsistent(
        const uint256& genesis_hash,
        const ChainLockFinalityStoreConfig& config) const noexcept;

    friend bool operator==(const PaymentAuditSealContextCapsule&,
                           const PaymentAuditSealContextCapsule&) = default;

private:
    PaymentAuditSealContextCapsule(
        uint32_t epoch,
        int32_t carrier_end_height_exclusive,
        FinalChainLockRecordMetadata seal,
        uint8_t authorization_mask);

    static bool BuildForVerifiedDurableCandidate(
        const uint256& genesis_hash,
        const ChainLockFinalityStoreConfig& config,
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        std::optional<PaymentAuditSealContextCapsule>& capsule_out);

    uint16_t m_version{PAYMENT_AUDIT_SEAL_CONTEXT_VERSION};
    uint32_t m_epoch{0};
    int32_t m_carrier_end_height_exclusive{-1};
    FinalChainLockRecordMetadata m_seal;
    uint8_t m_authorization_mask{0};

    friend class ::llmq::CChainLocksHandler;
    friend class PaymentAuditSealContextCapsuleTestAccess;
    friend class PQChainLockPersistence;
};

enum class ChainLockPersistenceError : uint8_t {
    NONE = 0,
    INVALID_CHAINLOCK,
    STALE_HEIGHT,
    HEIGHT_CONFLICT,
    NON_MONOTONIC_BTCC,
    NON_MONOTONIC_RECEIPT_STATE,
    IO_FAILURE,
};

/**
 * Coherent small snapshot of the validated durable certificate records.
 *
 * The revision is process-local: an empty database starts at zero, a restart
 * with either record starts at one, and each successful non-idempotent
 * certificate mutation advances it once. Marker-only writes do not affect it.
 */
struct DurableFinalityStateView {
    uint64_t certificate_revision{0};
    std::optional<FinalChainLockRecordMetadata> best;
    std::optional<FinalChainLockRecordMetadata> unsealed_btcc;
    std::optional<ReceiptArchiveRosterAuthorization>
        receipt_archive_authorization;
    std::optional<PaymentAuditSealContextCapsule>
        payment_audit_seal_context;

    friend bool operator==(const DurableFinalityStateView&,
                           const DurableFinalityStateView&) = default;
};

/** Compact auxiliary snapshots still required by a retained recovery roster. */
struct RecoveryRosterRetentionDependency {
    int32_t target_height{-1};
    uint32_t first_epoch{0};

    friend bool operator==(const RecoveryRosterRetentionDependency&,
                           const RecoveryRosterRetentionDependency&) = default;
};

/** Extract one recovery group's key/target dependency; reject mixed groups. */
[[nodiscard]] bool GetRecoveryRosterRetentionDependency(
    const ChainLockStatement& statement,
    std::optional<RecoveryRosterRetentionDependency>& dependency) noexcept;

/**
 * One exact certificate and the immutable roster bytes that verified it.
 * The checksum-derived local record identity commits both values and closes
 * the startup disk-to-verification race without rebuilding old snapshots.
 */
class DurableChainLockRecord final {
public:
    DurableChainLockRecord(FinalChainLock chainlock,
                           DurableRosterContext roster_context,
                           uint256 record_identity)
        : m_chainlock{std::move(chainlock)},
          m_roster_context{std::move(roster_context)},
          m_record_identity{std::move(record_identity)}
    {
    }

    [[nodiscard]] const FinalChainLock& ChainLock() const noexcept
    {
        return m_chainlock;
    }
    [[nodiscard]] const DurableRosterContext& RosterContext() const noexcept
    {
        return m_roster_context;
    }
    [[nodiscard]] const uint256& RecordIdentity() const noexcept
    {
        return m_record_identity;
    }

    friend bool operator==(const DurableChainLockRecord& record,
                           const FinalChainLock& chainlock)
    {
        return record.m_chainlock == chainlock;
    }
    friend bool operator==(const FinalChainLock& chainlock,
                           const DurableChainLockRecord& record)
    {
        return chainlock == record.m_chainlock;
    }

private:
    FinalChainLock m_chainlock;
    DurableRosterContext m_roster_context;
    uint256 m_record_identity;
};

/** PoW-history provenance, never an assertion that its carrier is finalized. */
struct HistoricalSyncBoundary {
    static constexpr std::size_t WIRE_SIZE{
        RosterAuthorizationBaseIdentity::WIRE_SIZE + 2 * (sizeof(int32_t) + 32) +
        BTCCReceipt::WIRE_SIZE + BTCCReceiptState::WIRE_SIZE +
        PaymentAuditReceiptState::WIRE_SIZE + 32};
    RosterAuthorizationBaseIdentity durable_prior;
    int32_t carrier_height{-1};
    uint256 carrier_hash;
    BTCCReceipt receipt;
    int32_t coverage_height{-1};
    uint256 coverage_hash;
    BTCCReceiptState receipt_state;
    PaymentAuditReceiptState payment_audit_state;
    uint256 probation_state_hash;

    SERIALIZE_METHODS(HistoricalSyncBoundary, obj)
    {
        READWRITE(obj.durable_prior, obj.carrier_height, obj.carrier_hash,
                  obj.receipt, obj.coverage_height, obj.coverage_hash,
                  obj.receipt_state, obj.payment_audit_state,
                  obj.probation_state_hash);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const HistoricalSyncBoundary&,
                           const HistoricalSyncBoundary&) = default;
};

[[nodiscard]] uint256 GetHistoricalSyncBoundaryHash(
    const uint256& genesis_hash, const ChainLockFinalityStoreConfig& config,
    const HistoricalSyncBoundary& boundary);

struct DurableHistoricalSyncBoundary {
    HistoricalSyncBoundary boundary;
    DurableChainLockRecord record;
};

/** Publication-scoped proof that an ordinary successor covers imported history. */
class VerifiedHistoricalSyncSuccessor final {
public:
    const HistoricalSyncBoundary& Boundary() const noexcept { return m_boundary; }
    const uint256& CandidateLogicalId() const noexcept { return m_candidate_logical_id; }
    const RosterRecoveryPrecommit& Precommit() const noexcept { return m_precommit; }
    uint64_t SlotsRevision() const noexcept { return m_slots_revision; }

private:
    VerifiedHistoricalSyncSuccessor(HistoricalSyncBoundary boundary,
                                   uint256 candidate_logical_id,
                                   RosterRecoveryPrecommit precommit,
                                   uint64_t slots_revision)
        : m_boundary{std::move(boundary)},
          m_candidate_logical_id{std::move(candidate_logical_id)},
          m_precommit{std::move(precommit)}, m_slots_revision{slots_revision} {}
    HistoricalSyncBoundary m_boundary;
    uint256 m_candidate_logical_id;
    RosterRecoveryPrecommit m_precommit;
    uint64_t m_slots_revision;

    friend class ::llmq::CChainLocksHandler;
    friend class HistoricalSyncBoundaryPersistenceTestAccess;
};

/**
 * Durable storage for the single best post-quantum ChainLock certificate.
 *
 * The database schema binds the record to the network genesis, complete
 * finality configuration, height-only activation boundary, historical receipt
 * assumption, and fixed cryptographic profile.
 * Construction validates every database key and every byte of the record;
 * callers must still recheck branch provenance, bind the decoded roster
 * context through the trusted-persistence boundary, and reverify every
 * signature before importing LoadBest() into live finality state.
 */
class PQChainLockPersistence final {
public:
    PQChainLockPersistence(DBParams db_params,
                           uint256 genesis_hash,
                           ChainLockFinalityStoreConfig config);
    ~PQChainLockPersistence();

    PQChainLockPersistence(const PQChainLockPersistence&) = delete;
    PQChainLockPersistence& operator=(const PQChainLockPersistence&) = delete;

    [[nodiscard]] bool HasBest() const;
    [[nodiscard]] DurableFinalityStateView GetFinalityState() const;
    [[nodiscard]] std::optional<DurableChainLockRecord> LoadBest() const;
    [[nodiscard]] std::optional<DurableChainLockRecord>
    LoadUnsealedBTCC() const;
    /**
     * Certificates retained after live verification. Startup callers must
     * recheck branch and authorization provenance, decode the exact persisted
     * roster bytes, and reverify every signature before importing an in-memory
     * authorization capability.
     */
    [[nodiscard]] std::vector<DurableChainLockRecord>
    LoadAuthorizationBases() const;
    [[nodiscard]] std::optional<DurableChainLockRecord>
    LoadAuthorizationBase(const uint256& logical_id) const;
    /** Current then fallback; neither is imported as TRUSTED_PERSISTENCE. */
    [[nodiscard]] std::vector<DurableHistoricalSyncBoundary>
    LoadHistoricalSyncBoundaries(uint64_t* revision = nullptr) const;
    /** Compact coordinates needed by every durable recovery-roster owner. */
    [[nodiscard]] std::optional<
        std::vector<RecoveryRosterRetentionDependency>>
    LoadRecoveryRosterRetentionDependencies() const;
    [[nodiscard]] std::optional<int32_t>
    OldestAuthorizationBaseHeight() const;
    [[nodiscard]] bool HasCatchupMarker() const;
    [[nodiscard]] BTCCPresealState LoadBTCCPresealState() const;
    [[nodiscard]] PaymentAuditPresealState
    LoadPaymentAuditPresealState() const;
    [[nodiscard]] std::optional<RosterRecoveryPrecommit>
    LoadRosterRecoveryPrecommit() const;
    [[nodiscard]] std::optional<PaymentAuditSealContextCapsule>
    LoadPaymentAuditSealContext() const;
    /** O(1) authenticated local-persistence lookup for roster construction. */
    [[nodiscard]] RecoveryUniverseCapsulePtr LoadRecoveryUniverse(
        const uint256& source_id) const;

    /**
     * Synchronously replace the durable winner. An identical write is
     * idempotent; stale, conflicting, or BTCC-regressing records are rejected.
     */
    [[nodiscard]] bool PersistBest(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        std::optional<PaymentAuditSealContextCapsule>
            payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Atomically advance a normally verified durable winner and retire the
     * exact receipt-gap authorization that it independently covers. Recovery
     * source coordinates remain committed by each retained certificate.
     */
    [[nodiscard]] bool PersistBestCoveringReceiptArchive(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        const ReceiptArchiveRosterAuthorization& expected_authorization,
        ChainLockPersistenceError* error = nullptr,
        std::optional<PaymentAuditSealContextCapsule>
            payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Retain a fully verified stale exact-slot KEEP or ADVANCE needed by an
     * on-chain receipt without changing the finality winner.
     */
    [[nodiscard]] bool PersistUnsealedBTCC(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Durably retain one certificate only after full network authorization
     * and signature verification. This does not advance any finality or
     * receipt state.
     */
    [[nodiscard]] bool PersistVerifiedAuthorizationBase(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Atomically install the exact verified receipt archive and consume its
     * owner-bound gap authorization. Recovery source coordinates remain
     * committed by the resulting durable records.
     */
    [[nodiscard]] bool PersistAuthorizedUnsealedBTCC(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        const ReceiptArchiveRosterAuthorization& expected_authorization,
        ChainLockPersistenceError* error = nullptr,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /** Atomically advance the winner and highest catch-up audit marker. */
    [[nodiscard]] bool PersistCatchupBest(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        const std::optional<BTCCCursorReconciliationProof>&
            btcc_cursor_reconciliation = std::nullopt,
        const ReceiptArchiveRosterAuthorization*
            consume_receipt_archive_authorization = nullptr,
        std::optional<PaymentAuditSealContextCapsule>
            payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Atomically install a verified first INITIALIZE winner, consuming a
     * matching local marker when present. A conflicting marker is consumed
     * only with the exact store-minted verification capability. Plain
     * PersistBest rejects every INITIALIZE transition.
     */
    [[nodiscard]] bool PersistInitializedBest(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        const VerifiedRecoveryResetPersistenceCapability*
            verified_reset = nullptr,
        std::optional<PaymentAuditSealContextCapsule>
            payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /**
     * Atomically install a verified RECOVER winner, consuming a matching
     * local marker when present. A conflicting marker is consumed only with
     * the exact store-minted verification capability. Plain
     * PersistCatchupBest rejects every RECOVER transition.
     */
    [[nodiscard]] bool PersistRecoveryCatchupBest(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        ChainLockPersistenceError* error = nullptr,
        const std::optional<BTCCCursorReconciliationProof>&
            btcc_cursor_reconciliation = std::nullopt,
        const ReceiptArchiveRosterAuthorization*
            consume_receipt_archive_authorization = nullptr,
        const VerifiedRecoveryResetPersistenceCapability*
            verified_reset = nullptr,
        std::optional<PaymentAuditSealContextCapsule>
            payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    /** Stage PENDING first; only its exact durable record may become READY. */
    [[nodiscard]] bool PersistRosterRecoveryPrecommit(
        const RosterRecoveryPrecommit& precommit,
        ChainLockPersistenceError* error = nullptr);

    /** Atomically replace one exact attempt; never exposes a clear gap. */
    [[nodiscard]] bool ReplaceRosterRecoveryPrecommit(
        const RosterRecoveryPrecommit& expected,
        const RosterRecoveryPrecommit& replacement,
        ChainLockPersistenceError* error = nullptr);

    /** Atomically replace both deferred-NEVM branch obligations. */
    [[nodiscard]] bool PersistBTCCPresealState(
        const BTCCPresealState& state,
        ChainLockPersistenceError* error = nullptr);

    /** Synchronously clear both boundaries after authenticated replay. */
    [[nodiscard]] bool ClearBTCCPresealState(
        ChainLockPersistenceError* error = nullptr);

    /** Atomically replace both deferred payment-audit branch obligations. */
    [[nodiscard]] bool PersistPaymentAuditPresealState(
        const PaymentAuditPresealState& state,
        ChainLockPersistenceError* error = nullptr);

    /** Clear both payment-audit boundaries after a durable covering seal. */
    [[nodiscard]] bool ClearPaymentAuditPresealState(
        ChainLockPersistenceError* error = nullptr);

private:
    [[nodiscard]] bool PersistBestAfterHistoricalSync(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        const VerifiedHistoricalSyncSuccessor& proof,
        ChainLockPersistenceError* error = nullptr,
        std::optional<PaymentAuditSealContextCapsule> payment_audit_seal_context = std::nullopt,
        RecoveryUniverseCapsulePtr recovery_universe = nullptr);

    [[nodiscard]] bool PersistHistoricalSyncBoundary(
        const FinalChainLock& chainlock,
        const PreparedChainLockContextPtr& context,
        const HistoricalSyncBoundary& boundary,
        uint64_t expected_revision,
        const std::optional<FinalChainLockRecordMetadata>& covering_finality,
        RecoveryUniverseCapsulePtr recovery_universe,
        ChainLockPersistenceError* error = nullptr);

    /** Handler must revoke the supporting branch capability before removal. */
    [[nodiscard]] bool InvalidateHistoricalSyncBoundary(
        const uint256& record_identity, uint64_t expected_revision,
        ChainLockPersistenceError* error = nullptr);

    struct Impl;
    const std::unique_ptr<Impl> m_impl;

    friend class ::llmq::CChainLocksHandler;
    friend class HistoricalSyncBoundaryPersistenceTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H
