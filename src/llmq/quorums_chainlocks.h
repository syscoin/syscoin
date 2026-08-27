// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H
#define SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H

#include <util/ranges.h>
#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_chainlock_persistence.h>
#include <llmq/pq_chainlock_signer.h>
#include <llmq/pq_chainlock_store.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_signer.h>
#include <llmq/pq_payment_audit_staging_store.h>
#include <llmq/pq_payment_audit_store.h>
#include <llmq/pq_payment_audit_verify.h>
#include <llmq/pq_quorum_builder.h>
#include <protocol.h>
#include <saltedhasher.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CConnman;
class CDataStream;
class CNode;
class CScheduler;
class ChainstateManager;
class PeerManager;
typedef int64_t NodeId;

namespace Consensus {
struct Params;
}

namespace llmq {

/**
 * Linearizable admission fence for work that completes outside handler locks.
 * The complete open state is the token, so no reader can observe a partially
 * published lifecycle, health, or failure transition.
 */
class ShareAdmissionGate {
public:
    struct Observation {
        uint64_t state;

        [[nodiscard]] bool operator==(const Observation& other) const noexcept
        {
            return state == other.state;
        }
    };

    [[nodiscard]] Observation Observe() const noexcept
    {
        return Observation{m_state.load()};
    }

    /** Publish one state evaluation only if nothing changed while it ran. */
    [[nodiscard]] bool TryPublishEnabled(
        Observation observation, bool enabled) noexcept
    {
        uint64_t expected{observation.state};
        uint64_t flags{expected & FLAGS_MASK};
        flags = enabled ? flags | ENABLED : flags & ~ENABLED;
        flags = Normalize(flags);
        if (flags == (expected & FLAGS_MASK) &&
            ((flags & OPEN) != 0 || (flags & TERMINAL) != 0)) {
            return m_state.load() == expected;
        }
        return m_state.compare_exchange_strong(
            expected, Advance(expected, flags));
    }

    /** Lifecycle transitions invalidate every observation and work token. */
    void SetReady(bool ready) noexcept
    {
        uint64_t state{m_state.load()};
        while (true) {
            uint64_t flags{state & FLAGS_MASK};
            flags = ready ? flags | READY : flags & ~READY;
            if (m_state.compare_exchange_weak(
                    state, Advance(state, flags))) {
                return;
            }
        }
    }

    /** Terminal failures are sticky and invalidate work even when closed. */
    void Fail() noexcept
    {
        uint64_t state{m_state.load()};
        while (true) {
            uint64_t flags{state & FLAGS_MASK};
            flags = (flags | TERMINAL) & ~ENABLED;
            if (m_state.compare_exchange_weak(
                    state, Advance(state, flags))) {
                return;
            }
        }
    }

    [[nodiscard]] uint64_t Acquire() const noexcept
    {
        const uint64_t state{m_state.load()};
        return (state & OPEN) != 0 ? state : 0;
    }

    [[nodiscard]] bool IsCurrent(uint64_t token) const noexcept
    {
        return token != 0 && (token & OPEN) != 0 &&
               m_state.load() == token;
    }

    [[nodiscard]] bool IsOpen() const noexcept
    {
        return (m_state.load() & OPEN) != 0;
    }

    [[nodiscard]] bool IsTerminal() const noexcept
    {
        return (m_state.load() & TERMINAL) != 0;
    }

private:
    static constexpr uint64_t OPEN{uint64_t{1} << 0};
    static constexpr uint64_t READY{uint64_t{1} << 1};
    static constexpr uint64_t ENABLED{uint64_t{1} << 2};
    static constexpr uint64_t TERMINAL{uint64_t{1} << 3};
    static constexpr uint64_t REVISION_STEP{uint64_t{1} << 4};
    static constexpr uint64_t FLAGS_MASK{REVISION_STEP - 1};
    static constexpr uint64_t REVISION_MASK{~FLAGS_MASK};

    [[nodiscard]] static uint64_t Normalize(uint64_t flags) noexcept
    {
        flags &= FLAGS_MASK;
        if ((flags & TERMINAL) != 0) flags &= ~ENABLED;
        if ((flags & READY) != 0 && (flags & ENABLED) != 0 &&
            (flags & TERMINAL) == 0) {
            return flags | OPEN;
        }
        return flags & ~OPEN;
    }

    [[nodiscard]] static uint64_t Advance(
        uint64_t state, uint64_t flags) noexcept
    {
        flags = Normalize(flags);
        const uint64_t revision{state & REVISION_MASK};
        // Saturation is unreachable in practice, but wrapping could revive an
        // ancient token, so exhaustion permanently fails closed.
        if (revision == REVISION_MASK) return TERMINAL;
        return revision + REVISION_STEP + flags;
    }

    std::atomic<uint64_t> m_state{0};
};

/** Live production may stop while an exact requested historical witness heals. */
[[nodiscard]] bool IsPaymentAuditCertificateIngressAllowed(
    bool operational, bool local_certificate,
    bool required_remote_response) noexcept;

/** A required exact response must never fall through to live verification. */
[[nodiscard]] bool MustRetryPaymentAuditCertificateContext(
    bool historical_required, bool historical_resolved) noexcept;

/** Retry one immutable local aggregate without repeating scheduled-WOTS work. */
[[nodiscard]] bool IsPaymentAuditFinalizationRetryDue(
    std::chrono::microseconds now,
    std::optional<std::chrono::microseconds> last_attempt) noexcept;

/** Preserve only a collector for the exact successor view opened by a winner. */
[[nodiscard]] bool IsChainLockCollectorOnAcceptedSuccessorView(
    const pq::ChainLockScheduleConfig& schedule,
    const pq::ChainLockStatement& collector,
    const pq::ChainLockStatement& winner) noexcept;

/** A prior process could only have consumed targets signable at this tip. */
[[nodiscard]] bool ShouldConsumeChainLockStartupSlot(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t startup_tip_height,
    int32_t target_height) noexcept;

/** The live audit-signing interval starts after the seal and ends exclusively. */
[[nodiscard]] bool IsPaymentAuditSigningHeightLive(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t tip_height) noexcept;

/** A prior process could have signed once the audit window opened. */
[[nodiscard]] bool ShouldConsumePaymentAuditStartupSlot(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t startup_tip_height) noexcept;

/** Prevent delayed partition signatures from finalizing a stale or deep fork. */
[[nodiscard]] bool IsLiveChainLockCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept;

/** Recovery has the same current-round fork bound as ordinary live finality. */
[[nodiscard]] bool IsCurrentChainLockCatchupCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept;

/** A durable receipt-replay obligation cannot be orphaned by current finality. */
[[nodiscard]] bool IsCurrentChainLockCandidateBlockedByPreseal(
    bool candidate_is_active,
    bool current_round_candidate,
    bool has_btcc_preseal,
    bool has_payment_audit_preseal) noexcept;

/** Only current branch-derived recovery may revise an exact local cursor view. */
[[nodiscard]] bool IsHistoricalLocalPredecessorCursorCompatible(
    bool current_round_candidate,
    bool declared_predecessor_is_local,
    const pq::BTCCursor& declared_cursor,
    const pq::BTCCursor& local_cursor) noexcept;

struct CurrentChainLockBTCCSelection {
    pq::BTCCursor previous_cursor;
    pq::BTCCSelection selected;
    std::optional<pq::BTCCCursorReconciliationProof> cursor_reconciliation;
};

/** Select one branch-derived BTCC view without making a missed receipt permanent. */
[[nodiscard]] std::optional<CurrentChainLockBTCCSelection>
SelectCurrentChainLockBTCC(
    const uint256& genesis_hash,
    const pq::ChainLockFinalityStoreConfig& config,
    const CBlockIndex& target,
    const pq::FinalChainLock* durable_best)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// Compatibility names retain the narrow integration surface while the wire
// object and every signature are post-quantum.
class CChainLockSig : public pq::FinalChainLock {
public:
    CChainLockSig() = default;
    CChainLockSig(const pq::FinalChainLock& other) : pq::FinalChainLock{other} {}
    CChainLockSig(pq::FinalChainLock&& other)
        : pq::FinalChainLock{std::move(other)} {}

    CChainLockSig& operator=(pq::FinalChainLock other)
    {
        static_cast<pq::FinalChainLock&>(*this) = std::move(other);
        return *this;
    }

    [[nodiscard]] bool IsNull() const noexcept
    {
        return statement.height == -1 && statement.block_hash.IsNull();
    }
    [[nodiscard]] std::string ToString() const;
};
// The store owns the immutable wire object as its base type; callers do not
// need the compatibility wrapper used at deserialization boundaries.
using CChainLockSigCPtr = std::shared_ptr<const pq::FinalChainLock>;

/** Return null until every fork-pinned deployment parameter is usable. */
[[nodiscard]] std::optional<pq::ChainLockFinalityStoreConfig>
MakePQChainLockFinalityStoreConfig(const Consensus::Params& consensus);

/** Return null unless roster and registry cutoffs form one safe profile. */
[[nodiscard]] std::optional<pq::QuorumBuildConfig>
MakePQQuorumBuildConfig(const Consensus::Params& consensus);

/** Bounded worker policy used by the live fixed-profile signature verifier. */
[[nodiscard]] std::size_t GetPQChainLockVerifierThreads(
    unsigned int hardware_threads) noexcept;

/** Checkpoint GC must not strand background AssumeUTXO validation. */
[[nodiscard]] std::optional<std::vector<uint256>>
CollectChainstatePaymentProbationRoots(ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

enum class PaymentAuditContextStatus : uint8_t {
    READY = 0,
    INVALID,
    LOCAL_ERROR,
};

enum class PaymentAuditSealValidation : uint8_t {
    LIVE_EXACT = 0,
    THRESHOLD_ATTESTED_HISTORY,
};

/** Distinguish peer-invalid audit context from incomplete local indexing. */
[[nodiscard]] PaymentAuditContextStatus ClassifyPaymentAuditSealContext(
    const CBlockIndex* seal, int32_t expected_height,
    int32_t predecessor_height, const uint256& predecessor_hash,
    PaymentAuditSealValidation validation)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Distinguish a failed response block from one not locally ready yet. */
[[nodiscard]] PaymentAuditContextStatus ClassifyPaymentAuditResponseContext(
    const CBlockIndex* response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Historical audit certificates authenticate the selected response context,
 * so a fully validated pruned index remains usable without its block body.
 * Live signing additionally requires the body used to build local staging.
 */
[[nodiscard]] bool IsPaymentAuditResponseBlockUsable(
    const CBlockIndex& response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Reject a malformed carrier before an unavailable witness can defer it. */
[[nodiscard]] PaymentAuditContextStatus
ClassifyPaymentAuditReceiptCarrierContext(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier,
    const pq::PaymentAuditScheduleConfig& schedule)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Recover only the exact receipt committed by a deferred carrier block. */
[[nodiscard]] std::optional<pq::PaymentAuditReceipt>
ExtractDeferredPaymentAuditReceipt(
    const CBlock& carrier_block,
    const uint256& required_witness_id,
    const CBlockIndex& carrier,
    const CBlockIndex& best_candidate)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

using ChainLockRelayRecipients =
    std::unordered_set<uint256, StaticSaltedHasher>;

[[nodiscard]] ChainLockRelayRecipients BuildChainLockRelayRecipients(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters);

/**
 * Authenticate the transport relay independently from the share's original
 * signer. Both must be in the frozen context, but multi-hop gossip means they
 * are not required to be the same operator.
 */
[[nodiscard]] bool IsAuthorizedChainLockShareRelay(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const ChainLockRelayRecipients& relay_recipients,
    const uint256& relay_pro_tx_hash,
    const pq::ChainLockShareTranscript& transcript) noexcept;

/**
 * Live certificate and authenticated scheduled-WOTS-share handler. There is no DKG,
 * threshold-key ceremony, recovered-signature layer, or BLS state.
 */
class CChainLocksHandler final : private pq::ChainLockFinalityContext {
public:
    CChainLocksHandler(CConnman& connman,
                       PeerManager& peerman,
                       ChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    ~CChainLocksHandler();

    CChainLocksHandler(const CChainLocksHandler&) = delete;
    CChainLocksHandler& operator=(const CChainLocksHandler&) = delete;

    void Start()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lifecycle_mutex,
                                 !m_share_lifecycle_mutex,
                                 !m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_share_signing_mutex,
                                 !m_btcc_preseal_mutex);
    void Stop()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lifecycle_mutex,
                                 !m_share_lifecycle_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex);

    /**
     * Install the immutable branch-bound roster service. An absent service
     * makes incoming certificates transiently unverifiable rather than
     * trusted.
     */
    void SetQuorumRosterCache(pq::FrozenQuorumRosterCachePtr cache)
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);

    [[nodiscard]] bool AlreadyHave(const uint256& logical_id) const;
    [[nodiscard]] bool GetChainLockByHash(const uint256& logical_id,
                                          CChainLockSig& result) const;
    [[nodiscard]] CChainLockSigCPtr GetMostRecentChainLock() const;
    [[nodiscard]] CChainLockSigCPtr GetBestChainLock() const;
    [[nodiscard]] const CBlockIndex* GetBestChainLockIndex() const;
    /**
     * Resolve the active-chain floor protected by the fsynced winner before
     * Start() imports it into the live store. If the winner is on a validated
     * side branch, its active-chain fork is protected until normal finality
     * enforcement can activate it.
    */
    [[nodiscard]] bool GetDurableFinalityRecoveryFloor(
        const CBlockIndex*& active_floor,
        const CBlockIndex*& durable_target,
        std::string& error) const EXCLUSIVE_LOCKS_REQUIRED(!cs_main);
    [[nodiscard]] bool GetRecentChainLockByHeight(
        int32_t height, CChainLockSig& result) const;

    /** Exact payment-audit certificates remain independently retrievable. */
    [[nodiscard]] bool AlreadyHavePaymentAudit(
        const uint256& witness_id) const;
    [[nodiscard]] bool GetPaymentAuditByHash(
        const uint256& witness_id,
        pq::FinalPaymentAudit& result) const;

    enum class PaymentAuditReceiptCertificateStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
        UNAVAILABLE,
        LOCAL_ERROR,
    };

    /** Keep local archive failures out of peer-controlled consensus verdicts. */
    [[nodiscard]] static PaymentAuditReceiptCertificateStatus
    ClassifyPaymentAuditArchiveRead(bool store_available,
                                    bool healthy_before_read,
                                    bool witness_found,
                                    bool healthy_after_read) noexcept;
    [[nodiscard]] static PaymentAuditReceiptCertificateStatus
    ClassifyPaymentAuditArchiveMutation(
        pq::PaymentAuditStoreResult result) noexcept;
    [[nodiscard]] static bool IsPaymentAuditLocalRosterBuildError(
        pq::QuorumBuildError error) noexcept;

    /** Called only after the exact receipt transition is applied. */
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    PinPaymentAuditReceiptCertificate(
        uint32_t epoch, const uint256& witness_id);

    /** Build the canonical null-or-audit receipt for one scheduled slot. */
    [[nodiscard]] pq::PaymentAuditReceipt
    GetPaymentAuditReceiptForCarrier(
        int32_t carrier_height,
        const CBlockIndex& carrier_parent) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex);

    /** Bind a receipt to its exact archived certificate and frozen subject. */
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    CheckPaymentAuditReceiptCertificate(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier,
        pq::FinalPaymentAudit* audit = nullptr,
        pq::FrozenQuorumRoster* subject = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_lookup_mutex,
                                 !m_verification_mutex);

    /** Build the fixed-cadence carrier from a fully verified recent ADVANCE. */
    [[nodiscard]] pq::BTCCReceipt GetBTCCReceiptForCarrier(
        int32_t carrier_height,
        const CBlockIndex& carrier_parent) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    enum class BTCCReceiptCertificateStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
    };

    /** Bind a non-null receipt to the exact locally verified ADVANCE winner. */
    [[nodiscard]] BTCCReceiptCertificateStatus CheckBTCCReceiptCertificate(
        const pq::BTCCReceipt& receipt,
        const CBlockIndex& carrier) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Queue the single exact certificate blocking live carrier activation. */
    void NotePendingBTCCReceiptCertificate(
        const uint256& logical_id,
        const CBlockIndex& carrier)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_pending_btcc_receipt_mutex);
    [[nodiscard]] bool IsPendingBTCCReceiptCertificate(
        const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex);
    void NotePendingPaymentAuditReceiptCertificate(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier)
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool IsPendingPaymentAuditReceiptCertificate(
        const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex);

    /**
     * Persist the first historical non-null receipt whose certificate is not
     * locally available. Base-chain validation may continue, but NEVM delivery
     * and new signing stay deferred until catch-up authenticates the prefix.
     * The durable marker remains afterward as a separate Geth replay
     * obligation until the authenticated blocks have actually been delivered.
     */
    [[nodiscard]] bool BeginBTCCPreseal(
        const CBlockIndex& carrier,
        const pq::BTCCReceipt& missing_receipt)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsBTCCPresealActive() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool HasNEVMReplayObligation() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool ShouldDeferBTCCNEVM(
        const CBlockIndex& index) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsBTCCPrefixAuthenticated(
        const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Rebuild the payment-only transition context carried compactly by a
     * receipt. The receipt remains provisional until a descendant ChainLock
     * authenticates the resulting cumulative receipt and probation roots.
     */
    [[nodiscard]] PaymentAuditContextStatus
    BuildCompactPaymentAuditTransitionInput(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier,
        pq::PQPaymentProbationTransitionInput& input) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_lookup_mutex);
    [[nodiscard]] bool BeginPaymentAuditPreseal(
        const CBlockIndex& carrier,
        const pq::PaymentAuditReceipt& missing_receipt,
        const pq::PaymentAuditReceiptState& predecessor_receipt_state,
        const uint256& predecessor_probation_state_hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPaymentAuditPresealActive() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPaymentAuditPrefixAuthenticated(
        const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void ProcessMessage(CNode* from,
                        const std::string& command,
                        CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_signer_reconcile_mutex);

    [[nodiscard]] bool ProcessNewChainLock(
        NodeId from,
        const CChainLockSig& chainlock,
        BlockValidationState& state,
        bool* peer_fault = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);

    void NotifyHeaderTip(const CBlockIndex* new_tip)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void UpdatedBlockTip(const CBlockIndex* new_tip, bool initial_download)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void CheckActiveState()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool GetCLSIGFromPeers()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex);

    [[nodiscard]] bool HasChainLock(int32_t height,
                                    const uint256& block_hash) const;
    [[nodiscard]] bool HasConflictingChainLock(
        int32_t height, const uint256& block_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    enum class HistoricalAdmission : uint8_t {
        NONE = 0,
        CURRENT_CATCHUP,
        PRESEAL_CATCHUP,
        PRESEAL_RECEIPT,
    };

    struct HistoricalAdmissionContext {
        HistoricalAdmission admission{HistoricalAdmission::NONE};
        uint256 marker_token;

        friend bool operator==(const HistoricalAdmissionContext&,
                               const HistoricalAdmissionContext&) = default;
    };

    struct PendingPaymentAuditReceiptDependency {
        pq::PaymentAuditReceipt receipt;
        uint256 carrier_hash;
        uint256 carrier_parent_hash;

        friend bool operator==(
            const PendingPaymentAuditReceiptDependency&,
            const PendingPaymentAuditReceiptDependency&) = default;
    };

    struct PaymentAuditHistoricalContext {
        PendingPaymentAuditReceiptDependency dependency;
        uint256 best_candidate_hash;
        int32_t best_candidate_height{-1};

        friend bool operator==(const PaymentAuditHistoricalContext&,
                               const PaymentAuditHistoricalContext&) = default;
    };

    struct RuntimeVerificationContext {
        pq::FrozenQuorumRostersPtr rosters;
        uint8_t authorization_mask{0};
        HistoricalAdmissionContext historical;
    };

    struct CurrentSigningContext {
        pq::ChainLockStatement statement;
        pq::FrozenQuorumRostersPtr rosters;
        uint8_t authorization_mask{0};
    };

    struct CurrentSigningContexts {
        static constexpr std::size_t MAX_VARIANTS{2};

        std::array<pq::ChainLockStatement, MAX_VARIANTS> statements{};
        std::size_t count{0};
        pq::FrozenQuorumRostersPtr rosters;
        std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;
        uint8_t authorization_mask{0};

        [[nodiscard]] std::optional<CurrentSigningContext> Find(
            const pq::ChainLockStatement& statement) const;
    };

    // Message and scheduler threads have deliberately small stacks. Never
    // embed the roughly 500 KiB immutable roster set in a handler context.
    static_assert(sizeof(RuntimeVerificationContext) <= 64);
    static_assert(sizeof(CurrentSigningContext) <= 544);
    static_assert(sizeof(CurrentSigningContexts) <= 1088);

    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    PrepareCandidate(
        const pq::ChainLockCandidateContextRequest& request) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    RecheckCandidate(
        const pq::ChainLockCandidateContextRequest& request,
        const pq::ChainLockCandidateContext& prepared) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] pq::AcceptedBranchRelation QueryAcceptedBranch(
        int32_t height,
        const uint256& block_hash,
        int32_t accepted_tip_height,
        const uint256& accepted_tip_hash) const override;

    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    BuildCandidateContext(
        const pq::ChainLockCandidateContextRequest& request,
        const CBlockIndex** candidate = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<pq::BTCCReceiptState>
    GetCatchupHistoricalProof(const CBlockIndex& candidate,
                              HistoricalAdmission admission) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<RuntimeVerificationContext>
    BuildRuntimeVerificationContext(
        const pq::PreparedFinalChainLockCandidate& prepared,
        bool* definitively_invalid = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<RuntimeVerificationContext>
    BuildHistoricalPreVerificationContext(
        const pq::FinalChainLock& chainlock,
        const HistoricalAdmissionContext& expected,
        bool* definitively_invalid = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsConfiguredForVerification() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] pq::FrozenQuorumRosterCachePtr GetQuorumRosterCache() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    void DisableShareAdmission() noexcept;
    [[nodiscard]] uint64_t GetShareAdmissionGeneration() const noexcept;
    [[nodiscard]] bool IsShareAdmissionGenerationCurrent(
        uint64_t generation) const noexcept;
    [[nodiscard]] bool IsChainLockVerificationAvailable() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex);
    [[nodiscard]] bool ReconcileSignerJournal(const uint256& pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_signer_reconcile_mutex);
    [[nodiscard]] bool InitializeSignerStartupTip(
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex, !cs_main);
    [[nodiscard]] bool ConsumeStartupChainLockSlots(
        const CurrentSigningContext& current,
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex);
    [[nodiscard]] bool ConsumeStartupPaymentAuditSlots(
        const pq::PaymentAuditStatement& statement,
        const pq::FrozenQuorumRosters& rosters,
        uint8_t authorization_mask,
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex);
    void MaybeCreateAndSignChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_share_signing_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_btc_header_policy_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex);
    struct ChainLockShareCollectionOutcome {
        pq::ShareCollectionResult result{
            pq::ShareCollectionResult::REJECTED};
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        std::optional<pq::FinalChainLock> finalized;
        bool stale{false};
    };
    [[nodiscard]] ChainLockShareCollectionOutcome CollectChainLockShare(
        const pq::ChainLockShare& share,
        const pq::ChainLockStatement& statement,
        uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_collector_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex);
    void ProcessChainLockShare(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);
    void ProcessPaymentAuditCertificate(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex);
    void FinishPaymentAuditFinalizationAttempt(
        const std::shared_ptr<const pq::FinalPaymentAudit>& certificate,
        uint64_t runtime_generation,
        bool submit)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex);
    enum class PaymentAuditRosterBuildStatus : uint8_t {
        VALID = 0,
        INVALID,
        LOCAL_ERROR,
    };
    [[nodiscard]] pq::FrozenQuorumRostersPtr
    BuildPaymentAuditVerificationRosters(
        const pq::PaymentAuditStatement& statement,
        pq::FrozenQuorumRoster* subject = nullptr,
        uint8_t* authorization_mask = nullptr,
        bool require_live_transition_finality = false,
        PaymentAuditRosterBuildStatus* status = nullptr,
        const PaymentAuditHistoricalContext* historical = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] std::optional<PaymentAuditHistoricalContext>
    ResolvePendingPaymentAuditContext(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool RetireInvalidPendingPaymentAuditReceipt(
        const PaymentAuditHistoricalContext& expected)
        EXCLUSIVE_LOCKS_REQUIRED(
            !cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool VerifyPaymentAuditCertificateSignatures(
        const pq::FinalPaymentAudit& audit,
        const pq::FrozenQuorumRosters& rosters,
        uint8_t authorization_mask) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_verification_mutex);
    void ProcessPaymentAuditHave(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void ProcessPaymentAuditResponse(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    struct PaymentAuditShareCollectionOutcome {
        pq::ShareCollectionResult result{
            pq::ShareCollectionResult::REJECTED};
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        std::shared_ptr<const pq::FinalPaymentAudit> finalized;
        uint64_t runtime_generation{0};
        bool stale{false};
        bool closed{false};
        bool accepted_duplicate{false};
    };
    [[nodiscard]] PaymentAuditShareCollectionOutcome
    CollectPaymentAuditShare(
        const pq::PaymentAuditShare& share,
        const pq::PaymentAuditStatement& statement,
        uint64_t admission_generation,
        uint64_t expected_runtime_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void ProcessPaymentAuditShare(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeCapturePaymentAuditResponse(
        const pq::ChainLockShare& share,
        const pq::FrozenQuorumRostersPtr& rosters,
        uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void RelayPaymentAuditResponse(
        const pq::PaymentAuditResponse& response,
        NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeRelayPaymentAuditHave()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void RelayPaymentAuditShare(
        const pq::PaymentAuditShare& share,
        const std::shared_ptr<const ChainLockRelayRecipients>& recipients,
        uint64_t admission_generation,
        NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool PreparePaymentAuditSigningRuntime()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsCurrentPaymentAuditStatement(
        const pq::PaymentAuditStatement& statement) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void MaybeCreateAndSignPaymentAudit()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_share_signing_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_btc_header_policy_mutex);

    struct PaymentAuditResponseDefinition {
        pq::PaymentAuditOpenRowMetadata row;
        pq::FrozenQuorumRostersPtr rosters;
        std::vector<uint256> active_relays;
    };
    struct PaymentAuditNetworkContext {
        uint64_t generation{0};
        std::vector<PaymentAuditResponseDefinition> rows;
    };
    struct PaymentAuditResponseRuntime {
        pq::PaymentAuditRound round;
        pq::PaymentAuditFrozenRowSummary selected_row;
        std::optional<pq::PaymentAuditStatement> statement;
        std::optional<pq::FinalChainLock> seal_chainlock;
        pq::FrozenQuorumRostersPtr signing_rosters;
        std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;
        uint8_t authorization_mask{0};
        std::unique_ptr<pq::PaymentAuditCollector> collector;
        std::shared_ptr<const pq::FinalPaymentAudit> finalized_certificate;
        std::optional<std::chrono::microseconds> finalization_last_attempt;
        bool finalization_attempt_in_flight{false};
        bool local_signing_complete{false};
    };
    void ResetPaymentAuditRuntime()
        EXCLUSIVE_LOCKS_REQUIRED(m_payment_audit_mutex);
    [[nodiscard]] uint64_t PublishPaymentAuditRuntime(
        PaymentAuditResponseRuntime runtime)
        EXCLUSIVE_LOCKS_REQUIRED(m_payment_audit_mutex);
    [[nodiscard]] std::optional<PaymentAuditResponseDefinition>
    BuildPaymentAuditResponseDefinition(uint32_t epoch,
                                        uint8_t row_index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool RefreshPaymentAuditNetworkContext()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::shared_ptr<const PaymentAuditNetworkContext>
    GetPaymentAuditNetworkContext() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_payment_audit_mutex);
    [[nodiscard]] bool IsCurrentPaymentAuditNetworkRow(
        const pq::PaymentAuditOpenRowMetadata& row) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool RefreshPaymentAuditStaging()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<CurrentSigningContexts>
    BuildCurrentSigningContexts() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<CurrentSigningContexts>
    GetOrCreateCurrentSigningContexts(uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsCurrentSigningStatement(
        const pq::ChainLockStatement& statement) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool CheckBTCHeaderSigningPolicy(
        const pq::ChainLockStatement& statement)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btc_header_policy_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool CheckPaymentAuditSeedSigningPolicy(
        const pq::PaymentAuditStatement& statement)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btc_header_policy_mutex,
                                 !m_payment_audit_mutex);
    [[nodiscard]] bool AreBTCCReceiptsReadyForSigning(
        const CBlockIndex& target,
        int32_t predecessor_height) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_needed_btcc_certificate_mutex);
    void RequestNeededBTCCCertificate()
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] bool RevalidatePendingBTCCReceiptDependency()
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex);
    void RetryPendingBTCCBlock();
    void RequestNeededPaymentAuditCertificate()
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex,
            !m_btcc_preseal_mutex);
    [[nodiscard]] bool RevalidatePendingPaymentAuditReceiptDependency()
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool RevalidatePendingPaymentAuditReceiptDependencyLocked()
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] HistoricalAdmissionContext
    GetHistoricalAdmission(const pq::ChainLockStatement& statement,
                           const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] HistoricalAdmissionContext
    GetHistoricalAdmissionLocked(const pq::ChainLockStatement& statement,
                                 const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void RequestCatchupChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_catchup_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeReplayBTCCPreseal()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex);
    void MaybeReplayPaymentAuditPreseal()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool ClearBTCCPreseal(
        const pq::BTCCPresealMarker& expected)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool PersistBTCCPresealStateLocked(
        const pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex);
    [[nodiscard]] bool PersistPaymentAuditPresealStateLocked(
        const pq::PaymentAuditPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex);
    [[nodiscard]] bool FlushPaymentAuditPresealBlockFilesForDurability(
        const pq::PaymentAuditPresealState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool ClearPaymentAuditPreseal(
        const pq::PaymentAuditPresealMarker& expected)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void UpdateBTCCPresealPruneLock(const pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void UpdatePaymentAuditPresealPruneLock(
        const pq::PaymentAuditPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void UpdatePresealAuxiliaryRetention(
        const pq::BTCCPresealState& btcc_state,
        const pq::PaymentAuditPresealState& payment_audit_state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void MaybeCheckpointPaymentAuditPreseal(
        const pq::FinalChainLock& durable_winner)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void UpdateDurableChainLockAuxiliaryRetention();
    [[nodiscard]] bool FlushChainLockAuxiliarySnapshotsForDurability();
    void MaybeReleaseFinalitySnapshotPublicationRetention()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    /**
     * Fsync branch-derived BTCPREV and receipt index metadata before the
     * corresponding live/catch-up certificate can become durable.
     */
    [[nodiscard]] bool FlushBTCCIndexStateForDurableAcceptance(
        const pq::FinalChainLock& chainlock) const LOCKS_EXCLUDED(cs_main);
    void RelayChainLockShare(const pq::ChainLockShare& share,
                             uint64_t admission_generation,
                             NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_collector_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] pq::ChainLockCollector* FindCollector(
        const pq::ChainLockStatement& statement)
        EXCLUSIVE_LOCKS_REQUIRED(m_collector_mutex);
    [[nodiscard]] const pq::ChainLockCollector* FindCollector(
        const pq::ChainLockStatement& statement) const
        EXCLUSIVE_LOCKS_REQUIRED(m_collector_mutex);
    void ResetCollectors() EXCLUSIVE_LOCKS_REQUIRED(m_collector_mutex);
    enum class PersistedChainLockImport : uint8_t {
        NONE = 0,
        PENDING,
        ACCEPTED,
        INVALID,
    };
    [[nodiscard]] PersistedChainLockImport TryImportPersistedChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] PersistedChainLockImport TryImportPersistedUnsealedBTCC()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPersistedChainLockPending() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    [[nodiscard]] bool HasPendingPQHistoryAuthentication() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void RefreshPQHistoryAuthState()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void QuarantineInvalidPersistedChainLock(const std::string& reason)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    void EnforceBestChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void CompletePeerResponse(NodeId from, const uint256& logical_id);
    void FailPeerResponse(NodeId from, const uint256& logical_id);
    void ForgetAllRequests(const uint256& logical_id);

    CConnman& m_connman;
    PeerManager& m_peerman;
    ChainstateManager& m_chainman;

    const uint256 m_genesis_hash;
    const std::optional<pq::ChainLockFinalityStoreConfig> m_config;
    const std::optional<pq::QuorumBuildConfig> m_quorum_build_config;
    std::unique_ptr<pq::PQChainLockPersistence> m_persistence;
    std::unique_ptr<pq::ChainLockFinalityStore> m_store;
    std::unique_ptr<pq::PaymentAuditStore> m_payment_audit_store;
    std::unique_ptr<pq::PaymentAuditStagingStore>
        m_payment_audit_staging_store;
    mutable pq::ChainLockVerifier m_verifier;
    mutable pq::CatchupHistoricalProofCache m_catchup_proof_cache;

    mutable Mutex m_lookup_mutex;
    pq::FrozenQuorumRosterCachePtr m_quorum_roster_cache
        GUARDED_BY(m_lookup_mutex);
    // ChainLock admission may rebuild branch context and therefore acquire
    // cs_main. Keep that serialization independent from the crypto-only mutex
    // so ConnectBlock can verify an archived audit while holding cs_main.
    mutable Mutex m_chainlock_admission_mutex;
    mutable Mutex m_verification_mutex;
    mutable Mutex m_persisted_mutex;
    std::optional<pq::FinalChainLock> m_pending_persisted
        GUARDED_BY(m_persisted_mutex);
    std::optional<pq::FinalChainLock> m_pending_persisted_unsealed_btcc
        GUARDED_BY(m_persisted_mutex);
    // Exact witness which was fully reverified through the bounded
    // historical-governance path in this process. It is never a height-only
    // authorization and is reset when a different winner is accepted.
    uint256 m_threshold_attested_enforcement_witness
        GUARDED_BY(m_persisted_mutex);
    bool m_persisted_invalid GUARDED_BY(m_persisted_mutex){false};
    // A loaded best record remains an authentication obligation after its
    // in-memory import pointer is cleared, until active-chain enforcement has
    // completed. Otherwise an unrelated marker refresh could publish READY in
    // the import/enforcement gap.
    bool m_persisted_best_auth_pending GUARDED_BY(m_persisted_mutex){false};
    bool m_persisted_unsealed_auth_pending
        GUARDED_BY(m_persisted_mutex){false};

    Mutex m_collector_mutex;
    std::array<std::unique_ptr<pq::ChainLockCollector>,
               CurrentSigningContexts::MAX_VARIANTS> m_collectors
        GUARDED_BY(m_collector_mutex);
    std::size_t m_collector_count GUARDED_BY(m_collector_mutex){0};
    pq::FrozenQuorumRostersPtr m_collector_rosters
        GUARDED_BY(m_collector_mutex);
    std::shared_ptr<const ChainLockRelayRecipients>
        m_collector_relay_recipients GUARDED_BY(m_collector_mutex);
    uint8_t m_collector_authorization_mask GUARDED_BY(m_collector_mutex){0};
    uint64_t m_collector_generation GUARDED_BY(m_collector_mutex){0};
    Mutex m_context_build_mutex;
    std::unique_ptr<CPQSignerJournal> m_signer_journal;
    Mutex m_signer_reconcile_mutex;
    Mutex m_share_signing_mutex;
    uint256 m_signer_startup_pro_tx_hash GUARDED_BY(m_share_signing_mutex);
    std::optional<int32_t> m_signer_startup_tip_height
        GUARDED_BY(m_share_signing_mutex);
    mutable Mutex m_payment_audit_mutex;
    std::optional<PaymentAuditResponseRuntime> m_payment_audit_runtime
        GUARDED_BY(m_payment_audit_mutex);
    uint64_t m_payment_audit_runtime_generation
        GUARDED_BY(m_payment_audit_mutex){0};
    std::shared_ptr<const PaymentAuditNetworkContext>
        m_payment_audit_network_context GUARDED_BY(m_payment_audit_mutex);
    uint64_t m_payment_audit_network_generation
        GUARDED_BY(m_payment_audit_mutex){0};
    std::map<uint256, std::map<uint256, pq::QuorumBitmap>>
        m_payment_audit_supplied_to_peer GUARDED_BY(m_payment_audit_mutex);
    Mutex m_btc_header_policy_mutex;
    std::optional<uint256> m_btc_header_policy_last_denied
        GUARDED_BY(m_btc_header_policy_mutex);
    std::string m_btc_header_policy_last_reason
        GUARDED_BY(m_btc_header_policy_mutex);
    mutable Mutex m_needed_btcc_certificate_mutex;
    mutable std::optional<uint256> m_needed_btcc_certificate
        GUARDED_BY(m_needed_btcc_certificate_mutex);
    mutable std::chrono::microseconds m_needed_btcc_last_request
        GUARDED_BY(m_needed_btcc_certificate_mutex){0};

    struct PendingBTCCReceiptDependency {
        uint256 logical_id{};
        uint256 carrier_hash{};
    };
    mutable Mutex m_pending_btcc_receipt_mutex;
    std::optional<PendingBTCCReceiptDependency> m_pending_btcc_receipt
        GUARDED_BY(m_pending_btcc_receipt_mutex);
    std::chrono::microseconds m_pending_btcc_last_request
        GUARDED_BY(m_pending_btcc_receipt_mutex){0};
    std::atomic_bool m_retry_pending_btcc_block{false};
    mutable Mutex m_pending_payment_audit_receipt_mutex;
    std::optional<PendingPaymentAuditReceiptDependency>
        m_pending_payment_audit_receipt
            GUARDED_BY(m_pending_payment_audit_receipt_mutex);
    std::chrono::microseconds m_pending_payment_audit_last_request
        GUARDED_BY(m_pending_payment_audit_receipt_mutex){0};
    mutable Mutex m_catchup_mutex;
    std::chrono::microseconds m_catchup_last_request
        GUARDED_BY(m_catchup_mutex){0};
    std::atomic_bool m_catchup_used{false};
    mutable Mutex m_btcc_preseal_mutex;
    pq::BTCCPresealState m_btcc_preseal_state
        GUARDED_BY(m_btcc_preseal_mutex);
    uint64_t m_btcc_preseal_revision GUARDED_BY(m_btcc_preseal_mutex){0};
    pq::PaymentAuditPresealState m_payment_audit_preseal_state
        GUARDED_BY(m_btcc_preseal_mutex);
    uint64_t m_payment_audit_preseal_revision
        GUARDED_BY(m_btcc_preseal_mutex){0};


    mutable Mutex m_lifecycle_mutex;
    std::unique_ptr<CScheduler> m_scheduler GUARDED_BY(m_lifecycle_mutex);
    std::unique_ptr<std::thread> m_scheduler_thread GUARDED_BY(m_lifecycle_mutex);
    bool m_started GUARDED_BY(m_lifecycle_mutex){false};
    // Linearize lifecycle transitions with staging, relay, and local
    // certificate submission; expensive verification uses the generation.
    mutable Mutex m_share_lifecycle_mutex;
    // Lifecycle, operational state, and terminal faults publish atomically so
    // no false->true interval can revive work from an older handler state.
    ShareAdmissionGate m_share_admission_gate;
    std::atomic_bool m_persistence_failed{false};
    std::atomic_bool m_enforced{false};
};

extern CChainLocksHandler* chainLocksHandler;

/** Operational switch for producing new PQ finality material. */
[[nodiscard]] bool AreChainLocksEnabled();

/** Certificate recovery remains available while production is switched off. */
[[nodiscard]] bool ShouldVerifyChainLockCertificate(
    bool configured_and_healthy, bool persisted_import_pending,
    bool persistence_failed) noexcept;

/** Durable Syscoin finality is independent of deferred NEVM replay readiness. */
[[nodiscard]] bool ShouldEnforceDurableChainLock(
    bool configured, bool persisted_import_pending,
    bool btcc_preseal_active) noexcept;

[[nodiscard]] bool IsBTCCPresealCoveredByDurableWinner(
    int32_t marker_height, int32_t winner_height,
    bool winner_descends_marker) noexcept;

/** Immutable archive boundary equality; authorizer refresh fields are ignored. */
[[nodiscard]] bool HasSamePaymentAuditCheckpointBoundary(
    const pq::PaymentAuditStoreCheckpoint& left,
    const pq::PaymentAuditStoreCheckpoint& right) noexcept;

/** Gate the full chainstate durability barrier and both irreversible GCs. */
[[nodiscard]] bool ShouldRunPaymentAuditDurableGC(
    bool reuse_archive_checkpoint,
    bool probation_gc_complete) noexcept;

enum class BTCCCatchupRangeStatus : uint8_t {
    VALID,
    DEFINITIVE_INVALID,
    TRANSIENT_UNAVAILABLE,
};

/**
 * Require the pinned receipt-anchor identity and full post-anchor index
 * provenance before historical receipt state may replace block-body replay.
 */
[[nodiscard]] BTCCCatchupRangeStatus
GetFullyValidatedBTCCCatchupRangeStatus(
    const ChainstateManager& chainman,
    const CBlockIndex& candidate,
    const pq::BTCCReceiptAssumptionAnchor& anchor)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** An exact marker receipt newer than local finality becomes the new winner. */
[[nodiscard]] bool ShouldRouteBTCCPresealReceiptToCatchup(
    bool marker_authorized_receipt,
    int32_t receipt_target_height,
    int32_t local_finality_height) noexcept;

/** Select the earliest exact-branch marker that forces retained-body replay. */
[[nodiscard]] const pq::BTCCPresealMarker*
SelectBTCCPresealRecomputeMarker(const pq::BTCCPresealState& state,
                                const CBlockIndex& candidate) noexcept;

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H
