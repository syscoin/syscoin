// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_store.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace llmq::pq {
namespace {

void SetError(ChainLockFinalityError* error, ChainLockFinalityError value)
{
    if (error != nullptr) *error = value;
}

bool ValidCapacity(std::size_t value, std::size_t maximum)
{
    return value > 0 && value <= maximum;
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
    if (!IsReceiptableAdvance(unsealed, config)) return false;
    const int64_t carrier_height{
        static_cast<int64_t>(unsealed.statement.height) +
        config.btcc_schedule.nevm_injection_lag};
    return carrier_height <= std::numeric_limits<int32_t>::max() &&
           seal.statement.height >= carrier_height;
}

} // namespace

bool IsDurableBTCCursorMonotonic(
    const BTCCursor& previous, const BTCCursor& candidate) noexcept
{
    if (previous.IsNull()) return true;
    if (candidate.IsNull() || candidate.sys_height < previous.sys_height) {
        return false;
    }
    return candidate.sys_height != previous.sys_height ||
           candidate == previous;
}

bool BTCCCursorReconciliationProof::IsStructurallyValid() const noexcept
{
    return carrier_height >= 0 && !carrier_hash.IsNull() &&
           !carrier_parent_hash.IsNull() && skipped_cursor.IsStructurallyValid() &&
           !skipped_cursor.IsNull() &&
           previous_receipt_state.IsStructurallyValid() &&
           current_receipt_state.IsStructurallyValid() &&
           previous_receipt_state == current_receipt_state &&
           receipt_logical_id.IsNull();
}

bool IsBTCCCursorReconciliation(
    const FinalChainLock& best,
    const FinalChainLock& candidate,
    const ChainLockFinalityStoreConfig& config) noexcept
{
    if (!config.IsValid() || !best.IsStructurallyValid() ||
        !candidate.IsStructurallyValid()) {
        return false;
    }
    const auto& durable{best.statement};
    const auto& recovery{candidate.statement};
    const auto& skipped{durable.accepted_btcc_cursor};
    const auto& authenticated{durable.btcc_receipt_state.cursor};
    if (skipped.IsNull() ||
        !IsBTCCCandidateHeight(config.btcc_schedule,
                               skipped.sys_height) ||
        (!authenticated.IsNull() &&
         authenticated.sys_height >= skipped.sys_height)) {
        return false;
    }
    const int64_t carrier_height{
        static_cast<int64_t>(skipped.sys_height) +
        config.btcc_schedule.nevm_injection_lag};
    if (carrier_height > std::numeric_limits<int32_t>::max() ||
        recovery.height < carrier_height ||
        recovery.previous_chainlock_height < durable.height ||
        (recovery.previous_chainlock_height == durable.height &&
         recovery.previous_chainlock_hash != durable.block_hash)) {
        return false;
    }
    return recovery.previous_btcc_cursor == authenticated &&
           recovery.accepted_btcc_cursor == authenticated &&
           recovery.btcc_advance == BTCCAdvance::KEEP &&
           recovery.btcc_receipt_state == durable.btcc_receipt_state &&
           !IsDurableBTCCursorMonotonic(
               skipped,
               recovery.accepted_btcc_cursor);
}

bool IsBTCCCursorReconciliationProof(
    const FinalChainLock& best,
    const FinalChainLock& candidate,
    const BTCCCursorReconciliationProof& proof,
    const ChainLockFinalityStoreConfig& config) noexcept
{
    if (!IsBTCCCursorReconciliation(best, candidate, config) ||
        !proof.IsStructurallyValid()) {
        return false;
    }
    const auto& durable{best.statement};
    const int64_t carrier_height{
        static_cast<int64_t>(durable.accepted_btcc_cursor.sys_height) +
        config.btcc_schedule.nevm_injection_lag};
    return carrier_height == proof.carrier_height &&
           proof.skipped_cursor == durable.accepted_btcc_cursor &&
           proof.previous_receipt_state == durable.btcc_receipt_state &&
           proof.current_receipt_state == durable.btcc_receipt_state;
}

bool IsDurableBTCCReceiptStateMonotonic(
    const BTCCReceiptState& previous,
    const BTCCReceiptState& candidate) noexcept
{
    if (!previous.IsStructurallyValid() ||
        !candidate.IsStructurallyValid()) {
        return false;
    }
    if (previous.cursor.IsNull()) return true;
    if (candidate.cursor.IsNull() ||
        candidate.cursor.sys_height < previous.cursor.sys_height) {
        return false;
    }
    return candidate.cursor.sys_height != previous.cursor.sys_height ||
           candidate == previous;
}

bool IsDurablePaymentAuditStateMonotonic(
    const PaymentAuditReceiptState& previous_receipt,
    const uint256& previous_probation,
    const PaymentAuditReceiptState& candidate_receipt,
    const uint256& candidate_probation) noexcept
{
    if (!previous_receipt.IsStructurallyValid() ||
        !candidate_receipt.IsStructurallyValid() ||
        previous_probation.IsNull() || candidate_probation.IsNull()) {
        return false;
    }
    if (previous_receipt.cursor.IsNull()) return true;
    if (candidate_receipt.cursor.IsNull() ||
        candidate_receipt.cursor.epoch < previous_receipt.cursor.epoch ||
        candidate_receipt.cursor.carrier_height <
            previous_receipt.cursor.carrier_height) {
        return false;
    }
    if (candidate_receipt.cursor.epoch == previous_receipt.cursor.epoch ||
        candidate_receipt.cursor.carrier_height ==
            previous_receipt.cursor.carrier_height) {
        return candidate_receipt == previous_receipt &&
               candidate_probation == previous_probation;
    }
    return true;
}

CatchupHistoricalProofCache::CatchupHistoricalProofCache(
    std::size_t capacity, Clock now)
    : m_capacity{capacity},
      m_now{now ? std::move(now) : Clock{[] {
          return std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
              .count();
      }}}
{
    if (!ValidCapacity(capacity, MAX_RECENT_CHAINLOCKS_SIZE)) {
        throw std::invalid_argument{"invalid catch-up proof cache capacity"};
    }
}

std::optional<BTCCReceiptState> CatchupHistoricalProofCache::GetOrCompute(
    const uint256& branch_token,
    const uint256& context_token,
    const Builder& builder)
{
    if (branch_token.IsNull() || context_token.IsNull() || !builder) {
        return std::nullopt;
    }

    // The builder deliberately runs under this mutex. It is called only while
    // the integration holds cs_main, and serializing it prevents concurrent
    // copies of the same disk/ancestry scan from amplifying an untrusted CLSIG.
    LOCK(m_mutex);
    if (m_branch_token != branch_token) {
        m_branch_token = branch_token;
        m_proofs.clear();
        m_order.clear();
    }
    auto found{m_proofs.find(context_token)};
    const int64_t now_ms{m_now()};
    int64_t prior_backoff_ms{0};
    if (found != m_proofs.end()) {
        if (!found->second.transient) return found->second.proof;
        if (now_ms < found->second.retry_after_ms) return std::nullopt;
        prior_backoff_ms = found->second.backoff_ms;
    }

    ++m_computations;
    auto built{builder()};
    auto proof{std::move(built.proof)};
    if (!built.definitive) proof.reset();
    if (proof && !proof->IsStructurallyValid()) {
        proof.reset();
        built.definitive = true;
    }

    // Both outcomes are immutable for the supplied token. The integration
    // includes active-tip, validation, schedule, anchor, and indexed-state
    // facts in that token, so a real state transition invalidates this entry
    // instead of allowing each network message to retry an O(chain-age) scan.
    static constexpr int64_t INITIAL_BACKOFF_MS{1000};
    static constexpr int64_t MAX_BACKOFF_MS{60000};
    Entry entry;
    entry.proof = proof;
    if (!built.definitive) {
        entry.transient = true;
        entry.backoff_ms = prior_backoff_ms == 0
            ? INITIAL_BACKOFF_MS
            : std::min(MAX_BACKOFF_MS, prior_backoff_ms * 2);
        entry.retry_after_ms = now_ms + entry.backoff_ms;
    }
    const bool inserted{found == m_proofs.end()};
    m_proofs.insert_or_assign(context_token, std::move(entry));
    if (inserted) m_order.push_back(context_token);
    while (m_order.size() > m_capacity) {
        m_proofs.erase(m_order.front());
        m_order.pop_front();
    }
    return proof;
}

std::size_t CatchupHistoricalProofCache::ComputationsForTesting() const
{
    LOCK(m_mutex);
    return m_computations;
}

std::size_t CatchupHistoricalProofCache::SizeForTesting() const
{
    LOCK(m_mutex);
    return m_proofs.size();
}

bool ChainLockFinalityAnchor::IsStructurallyValid() const noexcept
{
    if (!btcc_cursor.IsStructurallyValid()) return false;
    if (height == -1) {
        return block_hash.IsNull() && btcc_cursor.IsNull();
    }
    return height >= 0 && !block_hash.IsNull() &&
           (btcc_cursor.IsNull() || btcc_cursor.sys_height <= height);
}

bool BTCCReceiptAssumptionAnchor::IsDisabled() const noexcept
{
    return height == -1 && block_hash.IsNull() &&
           receipt_state == BTCCReceiptState{};
}

bool BTCCReceiptAssumptionAnchor::IsStructurallyValid() const noexcept
{
    if (IsDisabled()) return true;
    return height >= 0 && !block_hash.IsNull() &&
           receipt_state.IsStructurallyValid() &&
           (receipt_state.cursor.IsNull() ||
            receipt_state.cursor.sys_height <= height);
}

bool ChainLockFinalityStoreConfig::IsValid() const noexcept
{
    const int64_t first_receipt_carrier{
        static_cast<int64_t>(btcc_schedule.candidate_origin) +
        btcc_schedule.nevm_injection_lag};
    // The receipt assumption can precede finality because it authenticates a
    // different history. Before the first carrier its only valid state is the
    // canonical empty state; later boundaries must land on an exact carrier.
    const bool valid_receipt_anchor_height{
        btcc_receipt_assumption_anchor.IsDisabled() ||
        IsBTCCReceiptCarrierHeight(
             btcc_schedule, btcc_receipt_assumption_anchor.height) ||
        (btcc_receipt_assumption_anchor.height < first_receipt_carrier &&
         btcc_receipt_assumption_anchor.receipt_state == BTCCReceiptState{})};
    return chainlock_schedule.IsValid() && btcc_schedule.IsValid() &&
           btcc_schedule.candidate_period %
                   chainlock_schedule.chainlock_period ==
               0 &&
           (static_cast<int64_t>(btcc_schedule.candidate_origin) -
            chainlock_schedule.epoch_origin) %
                   chainlock_schedule.chainlock_period ==
               0 &&
           anchor.IsStructurallyValid() &&
           anchor.height < btcc_schedule.candidate_origin &&
           anchor.btcc_cursor.IsNull() &&
           btcc_receipt_assumption_anchor.IsStructurallyValid() &&
           valid_receipt_anchor_height &&
           ValidCapacity(seen_logical_capacity, MAX_FINALITY_ID_CACHE_SIZE) &&
           ValidCapacity(seen_witness_capacity, MAX_FINALITY_ID_CACHE_SIZE) &&
           ValidCapacity(rejected_witness_capacity, MAX_FINALITY_ID_CACHE_SIZE) &&
           ValidCapacity(recent_chainlocks_capacity, MAX_RECENT_CHAINLOCKS_SIZE);
}

bool ChainLockFinalityStore::BoundedIdCache::Contains(const uint256& id) const
{
    return m_ids.find(id) != m_ids.end();
}

void ChainLockFinalityStore::BoundedIdCache::Insert(const uint256& id)
{
    if (!m_ids.insert(id).second) return;
    m_order.push_back(id);
    while (m_order.size() > m_capacity) {
        m_ids.erase(m_order.front());
        m_order.pop_front();
    }
}

void ChainLockFinalityStore::BoundedIdCache::Erase(const uint256& id)
{
    if (m_ids.erase(id) == 0) return;
    for (auto it = m_order.begin(); it != m_order.end();) {
        it = *it == id ? m_order.erase(it) : std::next(it);
    }
}

ChainLockFinalityStore::ChainLockFinalityStore(
    uint256 genesis_hash,
    ChainLockFinalityStoreConfig config,
    const ChainLockFinalityContext& context,
    ChainLockDurableAccept durable_accept,
    ChainLockDurableArchive durable_archive,
    ChainLockDurableCatchup durable_catchup)
    : m_genesis_hash(std::move(genesis_hash)),
      m_config(std::move(config)),
      m_context(context),
      m_durable_accept(std::move(durable_accept)),
      m_durable_archive(std::move(durable_archive)),
      m_durable_catchup(std::move(durable_catchup)),
      m_seen_logical(m_config.seen_logical_capacity),
      m_seen_witness(m_config.seen_witness_capacity),
      m_rejected_witness(m_config.rejected_witness_capacity)
{
    if (m_genesis_hash.IsNull() || !m_config.IsValid()) {
        throw std::invalid_argument("invalid PQ ChainLock finality configuration");
    }
}

ChainLockPredecessor ChainLockFinalityStore::CurrentPredecessor() const
{
    if (!m_best) {
        return ChainLockPredecessor{m_config.anchor.height, m_config.anchor.block_hash,
                                    m_config.anchor.btcc_cursor};
    }
    const auto& statement = m_best->chainlock->statement;
    return ChainLockPredecessor{statement.height, statement.block_hash,
                                statement.accepted_btcc_cursor};
}

bool ChainLockFinalityStore::CheckCurrentStoreState(
    const FinalChainLock& chainlock,
    const uint256& logical_id,
    const uint256& witness_id,
    ChainLockCandidateAdmission admission,
    ChainLockFinalityError* error) const
{
    if (m_rejected_witness.Contains(witness_id)) {
        SetError(error, ChainLockFinalityError::REJECTED_WITNESS);
        return false;
    }

    const auto& statement = chainlock.statement;
    const auto next_target{NextEligibleChainLockTargetHeight(
        m_config.chainlock_schedule,
        statement.previous_chainlock_height)};
    if (!next_target || statement.height != *next_target) {
        SetError(error, ChainLockFinalityError::INELIGIBLE_HEIGHT);
        return false;
    }
    const ChainLockPredecessor predecessor{CurrentPredecessor()};
    if (admission == ChainLockCandidateAdmission::LIVE) {
        // A signed, merely eligible predecessor is not evidence that the
        // preceding validator set accepted it. Exact chaining makes every
        // live roster transition depend on this node's durable winner.
        if (statement.previous_chainlock_height != predecessor.height ||
            statement.previous_chainlock_hash != predecessor.block_hash ||
            statement.previous_btcc_cursor != predecessor.btcc_cursor) {
            SetError(error, ChainLockFinalityError::PREDECESSOR_MISMATCH);
            return false;
        }
    } else if (admission == ChainLockCandidateAdmission::TRUSTED_PERSISTENCE) {
        // Only startup restoration of our own latest fsynced winner may skip
        // intermediate certificates, and only into an empty in-memory store.
        if (m_best) {
            SetError(error, ChainLockFinalityError::PERSISTED_IMPORT_NOT_EMPTY);
            return false;
        }
        if (statement.previous_chainlock_height < m_config.anchor.height ||
            (statement.previous_chainlock_height == m_config.anchor.height &&
             statement.previous_chainlock_hash != m_config.anchor.block_hash) ||
            (statement.previous_chainlock_height > m_config.anchor.height &&
             !IsEligibleChainLockTarget(m_config.chainlock_schedule,
                                        statement.previous_chainlock_height))) {
            SetError(error, ChainLockFinalityError::PREDECESSOR_MISMATCH);
            return false;
        }
    } else if (admission == ChainLockCandidateAdmission::RECEIPT_ARCHIVE) {
        if (!IsReceiptableAdvance(chainlock, m_config) ||
            statement.height <= m_config.anchor.height ||
            (m_best && statement.height >= predecessor.height)) {
            SetError(error, ChainLockFinalityError::STALE_HEIGHT);
            return false;
        }
    } else if (admission ==
               ChainLockCandidateAdmission::PRESEAL_RECEIPT) {
        // SYSCOIN: The integration's crash-durable marker authorizes this
        // special archive, but never a record above the durable winner. A newer
        // exact terminal certificate must use marker-authorized CATCHUP so the
        // persisted best/unsealed restart invariant remains coherent.
        if (!IsReceiptableAdvance(chainlock, m_config) ||
            statement.height <= m_config.anchor.height || !m_best ||
            statement.height >= predecessor.height) {
            SetError(error, ChainLockFinalityError::STALE_HEIGHT);
            return false;
        }
    } else {
        // CATCHUP is an authenticated current-quorum bootstrap across missing
        // certificates. The candidate and its declared predecessor must both
        // descend from the durable local winner; the integration rechecks that
        // active best-work relation and the full receipt accumulator.
        if (statement.previous_chainlock_height < predecessor.height ||
            (statement.previous_chainlock_height == predecessor.height &&
             statement.previous_chainlock_hash != predecessor.block_hash) ||
            statement.previous_chainlock_height <
                m_config.anchor.height ||
            (statement.previous_chainlock_height == m_config.anchor.height &&
             statement.previous_chainlock_hash !=
                 m_config.anchor.block_hash) ||
            (statement.previous_chainlock_height > m_config.anchor.height &&
             !IsEligibleChainLockTarget(
                 m_config.chainlock_schedule,
                 statement.previous_chainlock_height))) {
            SetError(error, ChainLockFinalityError::PREDECESSOR_MISMATCH);
            return false;
        }
        const bool reconciles_cursor{
            m_best && IsBTCCCursorReconciliation(
                *m_best->chainlock, chainlock, m_config)};
        if (m_best &&
            ((!IsDurableBTCCursorMonotonic(
                  m_best->chainlock->statement.accepted_btcc_cursor,
                  statement.accepted_btcc_cursor) &&
              !reconciles_cursor) ||
             !IsDurableBTCCReceiptStateMonotonic(
                 m_best->chainlock->statement.btcc_receipt_state,
                 statement.btcc_receipt_state) ||
             !IsDurablePaymentAuditStateMonotonic(
                 m_best->chainlock->statement.payment_audit_receipt_state,
                 m_best->chainlock->statement
                     .payment_probation_state_hash,
                 statement.payment_audit_receipt_state,
                 statement.payment_probation_state_hash))) {
            // Persistence repeats these checks at the fsync boundary. Reject
            // a signed but non-monotonic recovery before an expected policy
            // refusal can be mistaken for a local database failure.
            SetError(error, ChainLockFinalityError::PREDECESSOR_MISMATCH);
            return false;
        }
    }
    if (admission != ChainLockCandidateAdmission::RECEIPT_ARCHIVE &&
        admission != ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
        statement.height <= predecessor.height) {
        SetError(error, statement.height == predecessor.height
                            ? ChainLockFinalityError::HEIGHT_CONFLICT
                            : ChainLockFinalityError::STALE_HEIGHT);
        return false;
    }

    const auto same_height{m_recent_by_height.find(statement.height)};
    if (same_height != m_recent_by_height.end()) {
        SetError(error, same_height->second.logical_id == logical_id
                            ? ChainLockFinalityError::DUPLICATE_LOGICAL
                            : ChainLockFinalityError::HEIGHT_CONFLICT);
        return false;
    }
    if (m_best && m_best->logical_id == logical_id) {
        SetError(error, ChainLockFinalityError::DUPLICATE_LOGICAL);
        return false;
    }
    return true;
}

std::optional<BTCCursor> ChainLockFinalityStore::FindDeclaredPredecessorCursor(
    const ChainLockStatement& statement) const
{
    if (statement.previous_chainlock_height == m_config.anchor.height &&
        statement.previous_chainlock_hash == m_config.anchor.block_hash) {
        return m_config.anchor.btcc_cursor;
    }
    if (m_best &&
        m_best->chainlock->statement.height == statement.previous_chainlock_height &&
        m_best->chainlock->statement.block_hash == statement.previous_chainlock_hash) {
        return m_best->chainlock->statement.accepted_btcc_cursor;
    }
    const auto found{m_recent_by_height.find(statement.previous_chainlock_height)};
    if (found == m_recent_by_height.end() ||
        found->second.chainlock->statement.block_hash !=
            statement.previous_chainlock_hash) {
        return std::nullopt;
    }
    return found->second.chainlock->statement.accepted_btcc_cursor;
}

bool ChainLockFinalityStore::ValidateContext(
    const ChainLockCandidateContext& context,
    const ChainLockCandidateContextRequest& request,
    ChainLockFinalityError* error)
{
    if (!context.block_known) {
        SetError(error, ChainLockFinalityError::UNKNOWN_BLOCK);
        return false;
    }
    if (context.block_height != request.statement.height ||
        context.block_hash != request.statement.block_hash) {
        SetError(error, ChainLockFinalityError::BLOCK_MISMATCH);
        return false;
    }
    if (!context.scripts_validated || !context.special_transactions_validated) {
        SetError(error, ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED);
        return false;
    }
    if (!context.declared_predecessor_is_ancestor ||
        !context.descends_from_local_best) {
        SetError(error, ChainLockFinalityError::NOT_PREDECESSOR_DESCENDANT);
        return false;
    }
    if (!context.btcc_transition_validated) {
        SetError(error, ChainLockFinalityError::INVALID_BTCC_TRANSITION);
        return false;
    }
    if (context.context_token.IsNull()) {
        SetError(error, ChainLockFinalityError::INVALID_CONTEXT_TOKEN);
        return false;
    }
    return true;
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PrepareCandidate(const FinalChainLock& chainlock,
                                         ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock, ChainLockCandidateAdmission::LIVE, error);
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PreparePersistedCandidate(
    const FinalChainLock& chainlock,
    ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock, ChainLockCandidateAdmission::TRUSTED_PERSISTENCE, error);
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PrepareReceiptArchiveCandidate(
    const FinalChainLock& chainlock,
    ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock, ChainLockCandidateAdmission::RECEIPT_ARCHIVE, error);
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PreparePresealReceiptCandidate(
    const FinalChainLock& chainlock,
    ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock, ChainLockCandidateAdmission::PRESEAL_RECEIPT, error);
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PrepareCatchupCandidate(
    const FinalChainLock& chainlock,
    ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock, ChainLockCandidateAdmission::CATCHUP, error);
}

std::optional<PreparedFinalChainLockCandidate>
ChainLockFinalityStore::PrepareCandidateInternal(
    const FinalChainLock& chainlock,
    ChainLockCandidateAdmission admission,
    ChainLockFinalityError* error)
{
    SetError(error, ChainLockFinalityError::NONE);
    if (!chainlock.IsStructurallyValid()) {
        SetError(error, ChainLockFinalityError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (!IsEligibleChainLockTarget(m_config.chainlock_schedule,
                                   chainlock.statement.height)) {
        SetError(error, ChainLockFinalityError::INELIGIBLE_HEIGHT);
        return std::nullopt;
    }

    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    ChainLockPredecessor predecessor;
    bool has_local_chainlock{false};
    std::optional<BTCCursor> declared_predecessor_cursor;
    uint64_t revision{0};
    {
        LOCK(m_mutex);
        if (m_seen_witness.Contains(witness_id)) {
            SetError(error, ChainLockFinalityError::DUPLICATE_WITNESS);
            return std::nullopt;
        }
        if (!CheckCurrentStoreState(
                chainlock, logical_id, witness_id, admission, error)) {
            return std::nullopt;
        }
        predecessor = CurrentPredecessor();
        has_local_chainlock = m_best.has_value();
        declared_predecessor_cursor =
            admission != ChainLockCandidateAdmission::LIVE
                ? std::optional<BTCCursor>{chainlock.statement.previous_btcc_cursor}
                : FindDeclaredPredecessorCursor(chainlock.statement);
        revision = m_revision;
    }

    const ChainLockCandidateContextRequest request{
        chainlock.statement, predecessor, has_local_chainlock,
        declared_predecessor_cursor, admission, m_config.btcc_schedule};
    const auto context{m_context.PrepareCandidate(request)};
    if (!context || !ValidateContext(*context, request, error)) return std::nullopt;

    {
        LOCK(m_mutex);
        if (m_revision != revision || CurrentPredecessor() != predecessor) {
            SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
            return std::nullopt;
        }
        if (m_seen_witness.Contains(witness_id)) {
            SetError(error, ChainLockFinalityError::DUPLICATE_WITNESS);
            return std::nullopt;
        }
        if (!CheckCurrentStoreState(
                chainlock, logical_id, witness_id, admission, error)) {
            return std::nullopt;
        }
        // Logical IDs are observational here: a different witness for the same
        // unaccepted statement must remain eligible, or one bad signature bundle
        // could suppress the valid bundle before crypto is attempted.
        m_seen_logical.Insert(logical_id);
        m_seen_witness.Insert(witness_id);
    }

    return PreparedFinalChainLockCandidate{
        logical_id, witness_id, chainlock.statement, predecessor,
        has_local_chainlock, declared_predecessor_cursor, *context,
        admission, revision};
}

bool ChainLockFinalityStore::AcceptVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::LIVE, /*persist=*/true, {}, {}, error);
}

bool ChainLockFinalityStore::AcceptPersistedVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::TRUSTED_PERSISTENCE,
        /*persist=*/false, {}, {}, error);
}

bool ChainLockFinalityStore::AcceptReceiptArchiveVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::RECEIPT_ARCHIVE,
        /*persist=*/true, {}, {}, error);
}

bool ChainLockFinalityStore::AcceptPresealReceiptVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockPreDurableCatchup pre_durable,
    ChainLockDurableAuthorization durable_authorization,
    ChainLockFinalityError* error)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::PRESEAL_RECEIPT,
        /*persist=*/true, pre_durable, durable_authorization, error);
}

bool ChainLockFinalityStore::AcceptCatchupVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockPreDurableCatchup pre_durable,
    ChainLockDurableAuthorization durable_authorization,
    ChainLockFinalityError* error)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::CATCHUP,
        /*persist=*/true, pre_durable, durable_authorization, error);
}

bool ChainLockFinalityStore::AcceptVerifiedInternal(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockCandidateAdmission admission,
    bool persist,
    const ChainLockPreDurableCatchup& pre_durable,
    const ChainLockDurableAuthorization& durable_authorization,
    ChainLockFinalityError* error)
{
    SetError(error, ChainLockFinalityError::NONE);
    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (!chainlock.IsStructurallyValid() || prepared.logical_id != logical_id ||
        prepared.witness_id != witness_id || prepared.statement != chainlock.statement ||
        prepared.admission != admission) {
        SetError(error, ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
        return false;
    }
    if (!signatures_valid) {
        LOCK(m_mutex);
        m_rejected_witness.Insert(witness_id);
        SetError(error, ChainLockFinalityError::INVALID_SIGNATURES);
        return false;
    }

    const ChainLockCandidateContextRequest request{
        chainlock.statement, prepared.predecessor,
        prepared.has_local_chainlock,
        prepared.declared_predecessor_btcc_cursor,
        admission, m_config.btcc_schedule};
    ChainLockCandidateContextRequest recheck_request{request};
    bool reconciles_cursor{false};
    std::shared_ptr<const FinalChainLock> reconciliation_best;
    {
        LOCK(m_mutex);
        if (m_revision != prepared.store_revision ||
            CurrentPredecessor() != prepared.predecessor) {
            SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
            return false;
        }
        if (!CheckCurrentStoreState(
                chainlock, logical_id, witness_id, admission, error)) {
            return false;
        }
        recheck_request.has_local_chainlock = m_best.has_value();
        recheck_request.declared_predecessor_btcc_cursor =
            admission != ChainLockCandidateAdmission::LIVE
                ? prepared.declared_predecessor_btcc_cursor
                : FindDeclaredPredecessorCursor(chainlock.statement);
        reconciles_cursor =
            admission == ChainLockCandidateAdmission::CATCHUP &&
            m_best && IsBTCCCursorReconciliation(
                *m_best->chainlock, chainlock, m_config);
        if (reconciles_cursor) reconciliation_best = m_best->chainlock;
    }

    const auto rechecked{
        m_context.RecheckCandidate(recheck_request, prepared.context)};
    if (!rechecked) {
        SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
        return false;
    }
    if (!ValidateContext(*rechecked, recheck_request, error)) return false;
    if (rechecked->context_token != prepared.context.context_token ||
        rechecked->btcc_cursor_reconciliation !=
            prepared.context.btcc_cursor_reconciliation) {
        SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
        return false;
    }
    if (reconciles_cursor !=
        rechecked->btcc_cursor_reconciliation.has_value() ||
        (reconciles_cursor &&
         (!reconciliation_best || !IsBTCCCursorReconciliationProof(
             *reconciliation_best, chainlock,
             *rechecked->btcc_cursor_reconciliation, m_config)))) {
        SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
        return false;
    }

    if (admission == ChainLockCandidateAdmission::CATCHUP ||
        admission == ChainLockCandidateAdmission::PRESEAL_RECEIPT) {
        if (!pre_durable || !pre_durable()) {
            SetError(error, ChainLockFinalityError::PERSISTENCE_FAILURE);
            return false;
        }
        // The handler holds Chainstate::m_chainstate_mutex across this entire
        // path. Recheck once more after the block-index fsync so a test hook—or
        // any future caller that violates that lock contract—cannot bridge a
        // branch change into the certificate fsync below.
        const auto after_index_sync{
            m_context.RecheckCandidate(recheck_request, *rechecked)};
        if (!after_index_sync || *after_index_sync != *rechecked) {
            SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
            return false;
        }
    }

    LOCK(m_mutex);
    if (m_revision != prepared.store_revision ||
        CurrentPredecessor() != prepared.predecessor) {
        SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
        return false;
    }
    if (!CheckCurrentStoreState(
            chainlock, logical_id, witness_id, admission, error)) {
        return false;
    }
    const bool final_reconciles_cursor{
        admission == ChainLockCandidateAdmission::CATCHUP &&
        m_best && IsBTCCCursorReconciliation(
            *m_best->chainlock, chainlock, m_config)};
    if (final_reconciles_cursor !=
            rechecked->btcc_cursor_reconciliation.has_value() ||
        (final_reconciles_cursor &&
         !IsBTCCCursorReconciliationProof(
             *m_best->chainlock, chainlock,
             *rechecked->btcc_cursor_reconciliation, m_config))) {
        SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
        return false;
    }

    const bool archive_only{
        admission == ChainLockCandidateAdmission::RECEIPT_ARCHIVE ||
        admission == ChainLockCandidateAdmission::PRESEAL_RECEIPT};
    const bool catchup_accept{
        admission == ChainLockCandidateAdmission::CATCHUP};
    const bool has_durable_callback{
        archive_only ? static_cast<bool>(m_durable_archive)
                     : catchup_accept
                           ? static_cast<bool>(m_durable_catchup)
                           : static_cast<bool>(m_durable_accept)};
    const auto persist_record = [&] {
        try {
            const bool persisted{
                archive_only
                    ? m_durable_archive(chainlock)
                    : catchup_accept
                          ? m_durable_catchup(
                                chainlock,
                                rechecked->btcc_cursor_reconciliation)
                          : m_durable_accept(chainlock)};
            if (!persisted) {
                SetError(error, ChainLockFinalityError::PERSISTENCE_FAILURE);
                return false;
            }
        } catch (const std::exception&) {
            SetError(error, ChainLockFinalityError::PERSISTENCE_FAILURE);
            return false;
        }
        return true;
    };
    if (persist && has_durable_callback) {
        // Marker-authorized historical admission must remain authorized at
        // the certificate fsync linearization point. The callback may hold
        // the marker mutex while invoking persist_record; m_mutex prevents a
        // competing store winner from crossing the same seam.
        if (durable_authorization) {
            if (!durable_authorization(persist_record, error)) return false;
        } else if (!persist_record()) {
            return false;
        }
    }

    AcceptedRecord accepted{logical_id, witness_id,
                            std::make_shared<const FinalChainLock>(chainlock)};
    if (archive_only) {
        m_unsealed_btcc = accepted;
    } else {
        if (m_unsealed_btcc &&
            SealsUnsealedBTCC(chainlock, *m_unsealed_btcc->chainlock,
                              m_config)) {
            m_unsealed_btcc.reset();
        }
        if (IsReceiptableAdvance(chainlock, m_config)) {
            m_unsealed_btcc = accepted;
        }
        m_best = accepted;
    }
    RememberAccepted(std::move(accepted));
    ++m_revision;
    SetError(error, ChainLockFinalityError::NONE);
    return true;
}

void ChainLockFinalityStore::RejectPrepared(
    const PreparedFinalChainLockCandidate& prepared)
{
    LOCK(m_mutex);
    if (!prepared.witness_id.IsNull()) m_rejected_witness.Insert(prepared.witness_id);
}

void ChainLockFinalityStore::RejectWitness(const FinalChainLock& chainlock)
{
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (witness_id.IsNull()) return;
    LOCK(m_mutex);
    m_rejected_witness.Insert(witness_id);
}

void ChainLockFinalityStore::AbandonPrepared(
    const PreparedFinalChainLockCandidate& prepared)
{
    LOCK(m_mutex);
    // Accepted and explicitly rejected witnesses must remain deduplicated.
    if (m_rejected_witness.Contains(prepared.witness_id) ||
        m_recent_by_witness.find(prepared.witness_id) != m_recent_by_witness.end() ||
        (m_unsealed_btcc &&
         m_unsealed_btcc->witness_id == prepared.witness_id)) {
        return;
    }
    m_seen_witness.Erase(prepared.witness_id);
}

bool ChainLockFinalityStore::AlreadyHaveWitness(const uint256& witness_id) const
{
    if (witness_id.IsNull()) return false;
    LOCK(m_mutex);
    return m_seen_witness.Contains(witness_id) ||
           m_rejected_witness.Contains(witness_id) ||
           m_recent_by_witness.find(witness_id) != m_recent_by_witness.end() ||
           (m_unsealed_btcc &&
            m_unsealed_btcc->witness_id == witness_id);
}

void ChainLockFinalityStore::RememberAccepted(AcceptedRecord record)
{
    const int32_t height{record.chainlock->statement.height};
    m_recent_by_witness.emplace(record.witness_id, record.chainlock);
    m_recent_by_height.emplace(height, std::move(record));
    m_recent_order.push_back(height);
    while (m_recent_order.size() > m_config.recent_chainlocks_capacity) {
        const int32_t old_height{m_recent_order.front()};
        m_recent_order.pop_front();
        const auto old{m_recent_by_height.find(old_height)};
        if (old != m_recent_by_height.end()) {
            m_recent_by_witness.erase(old->second.witness_id);
            m_recent_by_height.erase(old);
        }
    }
}

bool ChainLockFinalityStore::HasChainLock(int32_t height,
                                         const uint256& block_hash) const
{
    int32_t best_height{-1};
    uint256 best_hash;
    {
        LOCK(m_mutex);
        if (height < 0 || block_hash.IsNull()) {
            return false;
        }
        best_height = m_best ? m_best->chainlock->statement.height
                             : m_config.anchor.height;
        best_hash = m_best ? m_best->chainlock->statement.block_hash
                           : m_config.anchor.block_hash;
        if (height > best_height) return false;
        if (height == best_height) return block_hash == best_hash;
        const auto recent{m_recent_by_height.find(height)};
        if (recent != m_recent_by_height.end()) {
            return block_hash == recent->second.chainlock->statement.block_hash;
        }
    }
    return m_context.QueryAcceptedBranch(height, block_hash, best_height, best_hash) ==
           AcceptedBranchRelation::MATCH;
}

bool ChainLockFinalityStore::HasConflictingChainLock(
    int32_t height,
    const uint256& block_hash,
    bool unknown_is_conflict) const
{
    int32_t best_height{-1};
    uint256 best_hash;
    {
        LOCK(m_mutex);
        best_height = m_best ? m_best->chainlock->statement.height
                             : m_config.anchor.height;
        best_hash = m_best ? m_best->chainlock->statement.block_hash
                           : m_config.anchor.block_hash;
        if (height > best_height) return false;
        if (height < 0 || block_hash.IsNull()) return true;
        if (height == best_height) return block_hash != best_hash;
        const auto recent{m_recent_by_height.find(height)};
        if (recent != m_recent_by_height.end()) {
            return block_hash != recent->second.chainlock->statement.block_hash;
        }
    }
    const AcceptedBranchRelation relation{
        m_context.QueryAcceptedBranch(height, block_hash, best_height, best_hash)};
    return relation == AcceptedBranchRelation::CONFLICT ||
           (unknown_is_conflict && relation == AcceptedBranchRelation::UNKNOWN);
}

std::shared_ptr<const FinalChainLock> ChainLockFinalityStore::GetBest() const
{
    LOCK(m_mutex);
    return m_best ? m_best->chainlock : nullptr;
}

bool FinalChainLockRecordMetadata::IsInternallyConsistent(
    const uint256& genesis_hash) const
{
    return !genesis_hash.IsNull() && !logical_id.IsNull() &&
           !witness_id.IsNull() && statement.IsStructurallyValid() &&
           logical_id == GetLogicalChainLockId(genesis_hash, statement);
}

std::optional<AcceptedFinalChainLockView>
ChainLockFinalityStore::GetBestRecord() const
{
    LOCK(m_mutex);
    if (!m_best) return std::nullopt;
    return AcceptedFinalChainLockView{
        m_revision,
        FinalChainLockRecordMetadata{
            m_best->logical_id,
            m_best->witness_id,
            m_best->chainlock->statement},
        m_best->chainlock};
}

ChainLockFinalityStateObservation
ChainLockFinalityStore::ObserveState() const
{
    LOCK(m_mutex);
    ChainLockFinalityStateObservation observation;
    observation.state_revision = m_revision;
    if (m_best) {
        observation.best = FinalChainLockRecordMetadata{
            m_best->logical_id,
            m_best->witness_id,
            m_best->chainlock->statement};
    }
    return observation;
}

std::shared_ptr<const FinalChainLock>
ChainLockFinalityStore::GetUnsealedBTCC() const
{
    LOCK(m_mutex);
    return m_unsealed_btcc ? m_unsealed_btcc->chainlock : nullptr;
}

std::shared_ptr<const FinalChainLock> ChainLockFinalityStore::GetByWitness(
    const uint256& witness_id) const
{
    LOCK(m_mutex);
    const auto found{m_recent_by_witness.find(witness_id)};
    if (found != m_recent_by_witness.end()) return found->second;
    return m_unsealed_btcc && m_unsealed_btcc->witness_id == witness_id
               ? m_unsealed_btcc->chainlock
               : nullptr;
}

std::shared_ptr<const FinalChainLock> ChainLockFinalityStore::GetByHeight(
    int32_t height) const
{
    LOCK(m_mutex);
    const auto found{m_recent_by_height.find(height)};
    if (found != m_recent_by_height.end()) return found->second.chainlock;
    return m_unsealed_btcc &&
                   m_unsealed_btcc->chainlock->statement.height == height
               ? m_unsealed_btcc->chainlock
               : nullptr;
}

std::shared_ptr<const FinalChainLock> ChainLockFinalityStore::GetByLogicalId(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return nullptr;
    LOCK(m_mutex);
    for (const auto& [height, record] : m_recent_by_height) {
        (void)height;
        if (record.logical_id == logical_id) return record.chainlock;
    }
    if (m_unsealed_btcc && m_unsealed_btcc->logical_id == logical_id) {
        return m_unsealed_btcc->chainlock;
    }
    return nullptr;
}

std::vector<std::shared_ptr<const FinalChainLock>>
ChainLockFinalityStore::GetRecent() const
{
    LOCK(m_mutex);
    std::vector<std::shared_ptr<const FinalChainLock>> result;
    result.reserve(m_recent_by_height.size());
    for (const auto& [height, record] : m_recent_by_height) {
        (void)height;
        result.push_back(record.chainlock);
    }
    return result;
}

std::size_t ChainLockFinalityStore::RecentSizeForTesting() const
{
    LOCK(m_mutex);
    return m_recent_by_height.size();
}

std::size_t ChainLockFinalityStore::SeenLogicalSizeForTesting() const
{
    LOCK(m_mutex);
    return m_seen_logical.Size();
}

std::size_t ChainLockFinalityStore::SeenWitnessSizeForTesting() const
{
    LOCK(m_mutex);
    return m_seen_witness.Size();
}

std::size_t ChainLockFinalityStore::RejectedWitnessSizeForTesting() const
{
    LOCK(m_mutex);
    return m_rejected_witness.Size();
}

} // namespace llmq::pq
