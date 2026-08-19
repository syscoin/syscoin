// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_STORE_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_STORE_H

#include <llmq/pq_btcc.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_types.h>
#include <sync.h>

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

namespace llmq::pq {

inline constexpr std::size_t DEFAULT_SEEN_LOGICAL_CACHE_SIZE{4096};
inline constexpr std::size_t DEFAULT_SEEN_WITNESS_CACHE_SIZE{4096};
inline constexpr std::size_t DEFAULT_REJECTED_WITNESS_CACHE_SIZE{4096};
// A certificate is exactly 3,621,236 bytes, so retaining eight is
// intentionally unlike the legacy BLS cache of 256 tiny certificates.
inline constexpr std::size_t DEFAULT_RECENT_CHAINLOCKS_SIZE{8};
inline constexpr std::size_t MAX_FINALITY_ID_CACHE_SIZE{65536};
inline constexpr std::size_t MAX_RECENT_CHAINLOCKS_SIZE{64};

/**
 * Bounded memoization for the expensive fixed-anchor catch-up proof.
 * Candidate hashes commit to their ancestry, so immutable candidate proofs
 * survive descendant tip extensions and temporary reorgs. Integration must
 * independently enforce the exact admission class and signing-window branch
 * bound, and change the validation domain token whenever anchor, configuration,
 * active-tip, marker, or validation provenance changes. Ordinary current
 * catch-up may select a shallow competing branch; marker recovery remains
 * active-branch-only.
 */
class CatchupHistoricalProofCache final {
public:
    using Clock = std::function<int64_t()>;
    struct BuildResult {
        std::optional<BTCCReceiptState> proof;
        // A definitive negative is immutable for the supplied validation
        // token. Transient storage failures are returned but never retained.
        bool definitive{true};
    };
    using Builder = std::function<BuildResult()>;

    explicit CatchupHistoricalProofCache(
        std::size_t capacity = DEFAULT_RECENT_CHAINLOCKS_SIZE,
        Clock now = {});

    [[nodiscard]] std::optional<BTCCReceiptState> GetOrCompute(
        const uint256& branch_token,
        const uint256& context_token,
        const Builder& builder)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] std::size_t ComputationsForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::size_t SizeForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Entry {
        std::optional<BTCCReceiptState> proof;
        bool transient{false};
        int64_t retry_after_ms{0};
        int64_t backoff_ms{0};
    };

    const std::size_t m_capacity;
    const Clock m_now;
    mutable Mutex m_mutex;
    uint256 m_branch_token GUARDED_BY(m_mutex);
    // Definitive negatives remain for the immutable context. Transient range
    // or storage failures use monotonic exponential backoff, preventing a
    // genuine certificate from becoming an unbounded I/O retry trigger while
    // still allowing local recovery without a tip change.
    std::map<uint256, Entry> m_proofs GUARDED_BY(m_mutex);
    std::deque<uint256> m_order GUARDED_BY(m_mutex);
    std::size_t m_computations GUARDED_BY(m_mutex){0};
};

struct ChainLockFinalityAnchor {
    int32_t height{-1};
    uint256 block_hash;
    BTCCursor btcc_cursor;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const ChainLockFinalityAnchor&,
                           const ChainLockFinalityAnchor&) = default;
};

/**
 * Release-pinned boundary for assuming only historical BTCC receipt
 * certificates. This is deliberately distinct from the immutable migration
 * anchor, which commits the reconstructed DMN and PQ-registry state.
 */
struct BTCCReceiptAssumptionAnchor {
    int32_t height{-1};
    uint256 block_hash;
    BTCCReceiptState receipt_state;

    [[nodiscard]] bool IsDisabled() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const BTCCReceiptAssumptionAnchor&,
                           const BTCCReceiptAssumptionAnchor&) = default;
};

struct ChainLockFinalityStoreConfig {
    ChainLockScheduleConfig chainlock_schedule;
    BTCCScheduleConfig btcc_schedule;
    ChainLockFinalityAnchor anchor;
    BTCCReceiptAssumptionAnchor btcc_receipt_assumption_anchor;
    std::size_t seen_logical_capacity{DEFAULT_SEEN_LOGICAL_CACHE_SIZE};
    std::size_t seen_witness_capacity{DEFAULT_SEEN_WITNESS_CACHE_SIZE};
    std::size_t rejected_witness_capacity{DEFAULT_REJECTED_WITNESS_CACHE_SIZE};
    std::size_t recent_chainlocks_capacity{DEFAULT_RECENT_CHAINLOCKS_SIZE};

    [[nodiscard]] bool IsValid() const noexcept;
};

/** Durable winner state may advance or remain exact, never regress. */
[[nodiscard]] bool IsDurableBTCCursorMonotonic(
    const BTCCursor& previous, const BTCCursor& candidate) noexcept;

struct BTCCCursorReconciliationProof {
    int32_t carrier_height{-1};
    uint256 carrier_hash;
    uint256 carrier_parent_hash;
    BTCCursor skipped_cursor;
    BTCCReceiptState previous_receipt_state;
    BTCCReceiptState current_receipt_state;
    uint256 receipt_logical_id;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const BTCCCursorReconciliationProof&,
                           const BTCCCursorReconciliationProof&) = default;
};

/** Structural half of one candidate-bound canonical-null carrier recovery. */
[[nodiscard]] bool IsBTCCCursorReconciliation(
    const FinalChainLock& best,
    const FinalChainLock& candidate,
    const ChainLockFinalityStoreConfig& config) noexcept;
/** Bind an integration-verified carrier proof to the durable transition. */
[[nodiscard]] bool IsBTCCCursorReconciliationProof(
    const FinalChainLock& best,
    const FinalChainLock& candidate,
    const BTCCCursorReconciliationProof& proof,
    const ChainLockFinalityStoreConfig& config) noexcept;
[[nodiscard]] bool IsDurableBTCCReceiptStateMonotonic(
    const BTCCReceiptState& previous,
    const BTCCReceiptState& candidate) noexcept;
[[nodiscard]] bool IsDurablePaymentAuditStateMonotonic(
    const PaymentAuditReceiptState& previous_receipt,
    const uint256& previous_probation,
    const PaymentAuditReceiptState& candidate_receipt,
    const uint256& candidate_probation) noexcept;

struct ChainLockPredecessor {
    int32_t height{-1};
    uint256 block_hash;
    BTCCursor btcc_cursor;

    friend bool operator==(const ChainLockPredecessor&,
                           const ChainLockPredecessor&) = default;
};

enum class ChainLockCandidateAdmission : uint8_t {
    LIVE = 0,
    TRUSTED_PERSISTENCE,
    RECEIPT_ARCHIVE,
    PRESEAL_RECEIPT,
    CATCHUP,
};

struct ChainLockCandidateContextRequest {
    ChainLockStatement statement;
    /** The locally accepted winner, or the immutable fork anchor before one exists. */
    ChainLockPredecessor local_best;
    bool has_local_chainlock{false};
    /** Present only when this node retained the declared predecessor certificate. */
    std::optional<BTCCursor> declared_predecessor_btcc_cursor;
    /** Trusted persistence is reserved for the locally fsynced latest winner. */
    ChainLockCandidateAdmission admission{ChainLockCandidateAdmission::LIVE};
    BTCCScheduleConfig btcc_schedule;
};

/**
 * Snapshot produced while the integration owns its chain-index lock.
 *
 * For live admission, `btcc_transition_validated` means
 * ValidateBTCCursorTransition was executed against this exact candidate
 * branch. A trusted-persistence restore may instead attest the already-fsynced
 * transition because its CBlockIndex metadata can lag the finality fsync after
 * a crash. The opaque token binds either result to a later chainstate recheck.
 */
struct ChainLockCandidateContext {
    bool block_known{false};
    bool scripts_validated{false};
    bool special_transactions_validated{false};
    bool declared_predecessor_is_ancestor{false};
    bool descends_from_local_best{false};
    bool btcc_transition_validated{false};
    int32_t block_height{-1};
    uint256 block_hash;
    uint256 context_token;
    /** Exact branch proof authorizing one canonical-null cursor reconciliation. */
    std::optional<BTCCCursorReconciliationProof> btcc_cursor_reconciliation;

    friend bool operator==(const ChainLockCandidateContext&,
                           const ChainLockCandidateContext&) = default;
};

enum class AcceptedBranchRelation : uint8_t {
    MATCH = 0,
    CONFLICT,
    UNKNOWN,
};

/**
 * Chain access is deliberately inverted so neither the finality store nor its
 * crypto path owns cs_main. Implementations must acquire the chain-index lock
 * inside each call and must not call back into ChainLockFinalityStore.
 */
class ChainLockFinalityContext {
public:
    virtual ~ChainLockFinalityContext() = default;

    [[nodiscard]] virtual std::optional<ChainLockCandidateContext> PrepareCandidate(
        const ChainLockCandidateContextRequest& request) const = 0;

    [[nodiscard]] virtual std::optional<ChainLockCandidateContext> RecheckCandidate(
        const ChainLockCandidateContextRequest& request,
        const ChainLockCandidateContext& prepared) const = 0;

    [[nodiscard]] virtual AcceptedBranchRelation QueryAcceptedBranch(
        int32_t height,
        const uint256& block_hash,
        int32_t accepted_tip_height,
        const uint256& accepted_tip_hash) const = 0;
};

enum class ChainLockFinalityError : uint8_t {
    NONE = 0,
    INVALID_CONFIG,
    INVALID_CHAINLOCK,
    INELIGIBLE_HEIGHT,
    REJECTED_WITNESS,
    DUPLICATE_WITNESS,
    DUPLICATE_LOGICAL,
    STALE_HEIGHT,
    HEIGHT_CONFLICT,
    PREDECESSOR_MISMATCH,
    CONTEXT_CHANGED,
    UNKNOWN_BLOCK,
    BLOCK_MISMATCH,
    BLOCK_NOT_FULLY_VALIDATED,
    NOT_PREDECESSOR_DESCENDANT,
    INVALID_BTCC_TRANSITION,
    INVALID_CONTEXT_TOKEN,
    INVALID_SIGNATURES,
    INVALID_PREPARATION_TOKEN,
    PERSISTED_IMPORT_NOT_EMPTY,
    PERSISTENCE_FAILURE,
};

using ChainLockDurableAccept = std::function<bool(const FinalChainLock&)>;
using ChainLockDurableArchive = std::function<bool(const FinalChainLock&)>;
using ChainLockDurableCatchup = std::function<bool(
    const FinalChainLock&,
    const std::optional<BTCCCursorReconciliationProof>&)>;
using ChainLockPreDurableCatchup = std::function<bool()>;
using ChainLockDurableAuthorization = std::function<bool(
    const std::function<bool()>&, ChainLockFinalityError*)>;

/** Small immutable token retained while the 801 independent C11 checks run. */
struct PreparedFinalChainLockCandidate {
    uint256 logical_id;
    uint256 witness_id;
    ChainLockStatement statement;
    ChainLockPredecessor predecessor;
    bool has_local_chainlock{false};
    std::optional<BTCCursor> declared_predecessor_btcc_cursor;
    ChainLockCandidateContext context;
    ChainLockCandidateAdmission admission{ChainLockCandidateAdmission::LIVE};
    uint64_t store_revision{0};
};

class ChainLockFinalityStore final {
public:
    ChainLockFinalityStore(uint256 genesis_hash,
                           ChainLockFinalityStoreConfig config,
                           const ChainLockFinalityContext& context,
                           ChainLockDurableAccept durable_accept = {},
                           ChainLockDurableArchive durable_archive = {},
                           ChainLockDurableCatchup durable_catchup = {});

    ChainLockFinalityStore(const ChainLockFinalityStore&) = delete;
    ChainLockFinalityStore& operator=(const ChainLockFinalityStore&) = delete;

    /**
     * Perform cheap/store/branch checks and reserve exact witness deduplication.
     * No callback is invoked with the store mutex held.
     */
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate> PrepareCandidate(
        const FinalChainLock& chainlock,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Prepare the single latest certificate loaded from this node's durable
     * finality database. This is not a catch-up/network admission API: it is
     * valid only while the in-memory store is empty. The caller must still
     * fully verify the target branch, frozen rosters, and all signatures.
     */
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate>
    PreparePersistedCandidate(
        const FinalChainLock& chainlock,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Prepare a requested stale ADVANCE without rebasing the live winner. */
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate>
    PrepareReceiptArchiveCandidate(
        const FinalChainLock& chainlock,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Prepare the exact ADVANCE named by a durable pre-seal marker. */
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate>
    PreparePresealReceiptCandidate(
        const FinalChainLock& chainlock,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Best-work bootstrap across a missing exact-predecessor certificate gap. */
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate>
    PrepareCatchupCandidate(
        const FinalChainLock& chainlock,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Commit a candidate only after the caller has completed every C11 check.
     * Passing false records the witness as rejected. A successful path repeats
     * all mutable predecessor and branch checks before first-winner acceptance.
     */
    [[nodiscard]] bool AcceptVerified(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Install a fully reverified token produced by PreparePersistedCandidate. */
    [[nodiscard]] bool AcceptPersistedVerified(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool AcceptReceiptArchiveVerified(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool AcceptPresealReceiptVerified(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockPreDurableCatchup pre_durable,
        ChainLockDurableAuthorization durable_authorization,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool AcceptCatchupVerified(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockPreDurableCatchup pre_durable,
        ChainLockDurableAuthorization durable_authorization,
        ChainLockFinalityError* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void RejectPrepared(const PreparedFinalChainLockCandidate& prepared)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Cache a cryptographically rejected witness before contextual prepare. */
    void RejectWitness(const FinalChainLock& chainlock)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Release a transient reservation without treating the witness as invalid. */
    void AbandonPrepared(const PreparedFinalChainLockCandidate& prepared)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool AlreadyHaveWitness(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool HasChainLock(int32_t height, const uint256& block_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool HasConflictingChainLock(int32_t height,
                                               const uint256& block_hash,
                                               bool unknown_is_conflict = true) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::shared_ptr<const FinalChainLock> GetBest() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::shared_ptr<const FinalChainLock> GetUnsealedBTCC() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::shared_ptr<const FinalChainLock> GetByWitness(
        const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::shared_ptr<const FinalChainLock> GetByHeight(
        int32_t height) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::shared_ptr<const FinalChainLock> GetByLogicalId(
        const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Oldest-to-newest bounded snapshot of fully verified winners. */
    [[nodiscard]] std::vector<std::shared_ptr<const FinalChainLock>> GetRecent() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] std::size_t RecentSizeForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::size_t SeenLogicalSizeForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::size_t SeenWitnessSizeForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::size_t RejectedWitnessSizeForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    class BoundedIdCache {
    public:
        explicit BoundedIdCache(std::size_t capacity) : m_capacity(capacity) {}

        [[nodiscard]] bool Contains(const uint256& id) const;
        void Insert(const uint256& id);
        void Erase(const uint256& id);
        [[nodiscard]] std::size_t Size() const noexcept { return m_ids.size(); }

    private:
        std::size_t m_capacity;
        std::deque<uint256> m_order;
        std::set<uint256> m_ids;
    };

    struct AcceptedRecord {
        uint256 logical_id;
        uint256 witness_id;
        std::shared_ptr<const FinalChainLock> chainlock;
    };

    [[nodiscard]] ChainLockPredecessor CurrentPredecessor() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CheckCurrentStoreState(
        const FinalChainLock& chainlock,
        const uint256& logical_id,
        const uint256& witness_id,
        ChainLockCandidateAdmission admission,
        ChainLockFinalityError* error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] std::optional<BTCCursor> FindDeclaredPredecessorCursor(
        const ChainLockStatement& statement) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] static bool ValidateContext(
        const ChainLockCandidateContext& context,
        const ChainLockCandidateContextRequest& request,
        ChainLockFinalityError* error);
    [[nodiscard]] std::optional<PreparedFinalChainLockCandidate>
    PrepareCandidateInternal(
        const FinalChainLock& chainlock,
        ChainLockCandidateAdmission admission,
        ChainLockFinalityError* error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool AcceptVerifiedInternal(
        const PreparedFinalChainLockCandidate& prepared,
        const FinalChainLock& chainlock,
        bool signatures_valid,
        ChainLockCandidateAdmission admission,
        bool persist,
        const ChainLockPreDurableCatchup& pre_durable,
        const ChainLockDurableAuthorization& durable_authorization,
        ChainLockFinalityError* error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void RememberAccepted(AcceptedRecord record) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const uint256 m_genesis_hash;
    const ChainLockFinalityStoreConfig m_config;
    const ChainLockFinalityContext& m_context;
    const ChainLockDurableAccept m_durable_accept;
    const ChainLockDurableArchive m_durable_archive;
    const ChainLockDurableCatchup m_durable_catchup;

    mutable Mutex m_mutex;
    uint64_t m_revision GUARDED_BY(m_mutex){0};
    std::optional<AcceptedRecord> m_best GUARDED_BY(m_mutex);
    std::optional<AcceptedRecord> m_unsealed_btcc GUARDED_BY(m_mutex);
    std::map<int32_t, AcceptedRecord> m_recent_by_height GUARDED_BY(m_mutex);
    std::map<uint256, std::shared_ptr<const FinalChainLock>> m_recent_by_witness
        GUARDED_BY(m_mutex);
    std::deque<int32_t> m_recent_order GUARDED_BY(m_mutex);
    BoundedIdCache m_seen_logical GUARDED_BY(m_mutex);
    BoundedIdCache m_seen_witness GUARDED_BY(m_mutex);
    BoundedIdCache m_rejected_witness GUARDED_BY(m_mutex);
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_STORE_H
