// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_store.h>

#include <llmq/pq_payment_audit.h>

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

bool IsRecoveryUniverseCapabilityForStatement(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const RecoveryUniverseCapsulePtr& capsule) noexcept
{
    if (!capsule) return true;
    const auto& source{
        statement.roster_beacons.active.recovery_authority_source};
    return !source.IsNull() && source.IsStructurallyValid() &&
           capsule->IsStructurallyValid() &&
           capsule->GenesisHash() == genesis_hash &&
           capsule->Source() == source &&
           capsule->SourceId() ==
               GetRecoveryUniverseSourceId(genesis_hash, source);
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
    if (!IsReceiptableChainLock(unsealed, config)) return false;
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
    if (candidate == previous) return true;
    if (previous.cursor.IsNull()) return !candidate.cursor.IsNull();
    if (candidate.cursor.IsNull() ||
        candidate.cursor.sys_height < previous.cursor.sys_height ||
        (candidate.cursor.sys_height == previous.cursor.sys_height &&
         candidate.cursor != previous.cursor)) {
        return false;
    }
    // A non-null KEEP receipt advances the authenticated receipt prefix while
    // retaining the exact cursor identity. Both exact-slot coordinates must
    // still move forward together.
    return candidate.latest_chainlock_target_height >
               previous.latest_chainlock_target_height &&
           candidate.latest_receipt_carrier_height >
               previous.latest_receipt_carrier_height &&
           candidate.cumulative_hash != previous.cumulative_hash;
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
    // includes active-tip, validation, schedule, activation-boundary, and
    // indexed-state facts in that token, so a real state transition invalidates this entry
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
           receipt_state.cursor.sys_height <= height &&
           receipt_state.latest_receipt_carrier_height <= height;
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
    const auto& anchor_state{
        btcc_receipt_assumption_anchor.receipt_state};
    const auto anchor_source{BTCCSourceHeightForNEVMInjection(
        btcc_schedule, anchor_state.latest_receipt_carrier_height)};
    const auto initial_target{NextEligibleChainLockTargetHeight(
        chainlock_schedule, activation_predecessor_height)};
    const auto initial_signing_height{initial_target
        ? SigningHeightForTarget(chainlock_schedule, *initial_target)
        : std::optional<int32_t>{}};
    const bool valid_receipt_position{
        (anchor_source &&
         *anchor_source == anchor_state.latest_chainlock_target_height) ||
        (initial_target && initial_signing_height &&
         IsBTCCCandidateHeight(btcc_schedule, *initial_target) &&
         anchor_state.latest_chainlock_target_height == *initial_target &&
         static_cast<int64_t>(*initial_signing_height) +
                 PQ_BTCC_RECEIPT_PROPAGATION_BUFFER <=
             anchor_state.latest_receipt_carrier_height)};
    const bool valid_receipt_anchor_state{
        btcc_receipt_assumption_anchor.IsDisabled() ||
        anchor_state == BTCCReceiptState{} ||
        (valid_receipt_position &&
         IsBTCCCandidateHeight(
             btcc_schedule, anchor_state.cursor.sys_height) &&
         IsEligibleChainLockTarget(
             chainlock_schedule,
             anchor_state.latest_chainlock_target_height))};
    return chainlock_schedule.IsValid() && btcc_schedule.IsValid() &&
           btcc_schedule.candidate_period %
                   chainlock_schedule.chainlock_period ==
               0 &&
           (static_cast<int64_t>(btcc_schedule.candidate_origin) -
            chainlock_schedule.epoch_origin) %
                   chainlock_schedule.chainlock_period ==
               0 &&
           activation_predecessor_height >= -1 &&
           activation_predecessor_height < btcc_schedule.candidate_origin &&
           btcc_receipt_assumption_anchor.IsStructurallyValid() &&
           valid_receipt_anchor_height &&
           valid_receipt_anchor_state &&
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

VerifiedRecoveryResetPersistenceCapability::
    VerifiedRecoveryResetPersistenceCapability(
        uint256 logical_id,
        uint256 witness_id,
        RosterAuthorizationTransitionKind transition,
        ChainLockCandidateAdmission candidate_admission) noexcept
    : m_logical_id(std::move(logical_id)),
      m_witness_id(std::move(witness_id)),
      m_transition(transition),
      m_candidate_admission(candidate_admission)
{
}

bool VerifiedRecoveryResetPersistenceCapability::Authorizes(
    const uint256& genesis_hash,
    const FinalChainLock& chainlock,
    RosterAuthorizationTransitionKind transition,
    ChainLockCandidateAdmission candidate_admission) const noexcept
{
    return !genesis_hash.IsNull() && chainlock.IsStructurallyValid() &&
           m_transition == transition &&
           m_candidate_admission == candidate_admission &&
           chainlock.statement.roster_transition == transition &&
           chainlock.GetLogicalId(genesis_hash) == m_logical_id &&
           chainlock.GetWitnessId(genesis_hash) == m_witness_id;
}

ChainLockFinalityStore::ChainLockFinalityStore(
    uint256 genesis_hash,
    ChainLockFinalityStoreConfig config,
    const ChainLockFinalityContext& context,
    ChainLockDurableAccept durable_accept,
    ChainLockDurableArchive durable_archive,
    ChainLockDurableCatchup durable_catchup,
    ChainLockDurableReceiptArchive durable_receipt_archive,
    ChainLockDurableCoveringAccept durable_covering_accept,
    ChainLockDurableReset durable_reset,
    ChainLockDurableAuthorizationBase durable_authorization_base)
    : m_genesis_hash(std::move(genesis_hash)),
      m_config(std::move(config)),
      m_context(context),
      m_durable_accept(std::move(durable_accept)),
      m_durable_archive(std::move(durable_archive)),
      m_durable_catchup(std::move(durable_catchup)),
      m_durable_receipt_archive(std::move(durable_receipt_archive)),
      m_durable_covering_accept(std::move(durable_covering_accept)),
      m_durable_reset(std::move(durable_reset)),
      m_durable_authorization_base(
          std::move(durable_authorization_base)),
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
        return ChainLockPredecessor{m_config.activation_predecessor_height, {}, {}};
    }
    const auto& statement = m_best->chainlock->statement;
    return ChainLockPredecessor{statement.height, statement.block_hash,
                                statement.accepted_btcc_cursor};
}

bool ChainLockFinalityStore::IsPreparedPredecessorCurrent(
    const ChainLockPredecessor& predecessor,
    bool had_local_chainlock) const
{
    if (m_best.has_value() != had_local_chainlock) return false;
    // Before the first verified winner, the candidate supplies the branch
    // hash and the integration authenticates it against that candidate's
    // ancestry. Merely preparing an invalid witness must never pin that hash.
    return !had_local_chainlock || CurrentPredecessor() == predecessor;
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
    const bool declares_activation_predecessor{
        statement.previous_chainlock_height == m_config.activation_predecessor_height &&
        !statement.previous_chainlock_hash.IsNull() &&
        statement.previous_btcc_cursor.IsNull()};
    if (admission == ChainLockCandidateAdmission::LIVE) {
        // A signed, merely eligible predecessor is not evidence that the
        // preceding validator set accepted it. Exact chaining makes every
        // live roster transition depend on this node's durable winner.
        if ((!m_best && !declares_activation_predecessor) ||
            (m_best &&
             (statement.previous_chainlock_height != predecessor.height ||
              statement.previous_chainlock_hash != predecessor.block_hash ||
              statement.previous_btcc_cursor != predecessor.btcc_cursor))) {
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
        if (statement.previous_chainlock_height < m_config.activation_predecessor_height ||
            (statement.previous_chainlock_height == m_config.activation_predecessor_height &&
             !declares_activation_predecessor) ||
            (statement.previous_chainlock_height > m_config.activation_predecessor_height &&
             !IsEligibleChainLockTarget(m_config.chainlock_schedule,
                                        statement.previous_chainlock_height))) {
            SetError(error, ChainLockFinalityError::PREDECESSOR_MISMATCH);
            return false;
        }
    } else if (admission == ChainLockCandidateAdmission::RECEIPT_ARCHIVE) {
        if (!IsReceiptableChainLock(chainlock, m_config) ||
            statement.height <= m_config.activation_predecessor_height ||
            (m_best && statement.height >= predecessor.height)) {
            SetError(error, ChainLockFinalityError::STALE_HEIGHT);
            return false;
        }
    } else if (admission ==
               ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE) {
        // The integration admits this token only after reloading and matching
        // the exact fsynced unsealed witness. Keep it archive-only and below
        // the already restored durable winner.
        if (!m_best || !IsReceiptableChainLock(chainlock, m_config) ||
            statement.height <= m_config.activation_predecessor_height ||
            statement.height >= predecessor.height) {
            SetError(error, ChainLockFinalityError::STALE_HEIGHT);
            return false;
        }
    } else if (admission ==
               ChainLockCandidateAdmission::PRESEAL_RECEIPT) {
        // SYSCOIN: The integration's crash-durable marker authorizes this
        // special archive, but never a record above the durable winner. A newer
        // exact terminal certificate must use marker-authorized CATCHUP so the
        // persisted best/unsealed restart invariant remains coherent.
        if (!IsReceiptableChainLock(chainlock, m_config) ||
            statement.height <= m_config.activation_predecessor_height || !m_best ||
            statement.height >= predecessor.height) {
            SetError(error, ChainLockFinalityError::STALE_HEIGHT);
            return false;
        }
    } else {
        // CATCHUP is an authenticated current-quorum bootstrap across missing
        // certificates. The candidate and its declared predecessor must both
        // descend from the durable local winner; the integration rechecks that
        // active best-work relation and the full receipt accumulator.
        if ((m_best &&
             (statement.previous_chainlock_height < predecessor.height ||
              (statement.previous_chainlock_height == predecessor.height &&
               statement.previous_chainlock_hash != predecessor.block_hash))) ||
            statement.previous_chainlock_height <
                m_config.activation_predecessor_height ||
            (statement.previous_chainlock_height == m_config.activation_predecessor_height &&
             !declares_activation_predecessor) ||
            (statement.previous_chainlock_height > m_config.activation_predecessor_height &&
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
        admission !=
            ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE &&
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
    if (statement.previous_chainlock_height == m_config.activation_predecessor_height) {
        return BTCCursor{};
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
ChainLockFinalityStore::PrepareTrustedUnsealedCandidate(
    const FinalChainLock& chainlock,
    ChainLockFinalityError* error)
{
    return PrepareCandidateInternal(
        chainlock,
        ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE,
        error);
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
    const auto is_exact_retained_base = [&]()
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        const auto retained_witness{
            m_authorization_base_by_witness.find(witness_id)};
        const auto retained_base{
            retained_witness != m_authorization_base_by_witness.end()
                ? m_authorization_bases.find(retained_witness->second)
                : m_authorization_bases.end()};
        return retained_base != m_authorization_bases.end() &&
               retained_base->second.logical_id == logical_id &&
               retained_base->second.witness_id == witness_id &&
               retained_base->second.chainlock &&
               *retained_base->second.chainlock == chainlock;
    };
    {
        LOCK(m_mutex);
        // An authorization-only certificate can later become locally
        // admissible. Reuse only its exact witness reservation; every branch,
        // state, and durability check below still runs again.
        if (m_seen_witness.Contains(witness_id) &&
            !is_exact_retained_base()) {
            SetError(error, ChainLockFinalityError::DUPLICATE_WITNESS);
            return std::nullopt;
        }
        if (!CheckCurrentStoreState(
                chainlock, logical_id, witness_id, admission, error)) {
            return std::nullopt;
        }
        has_local_chainlock = m_best.has_value();
        predecessor = has_local_chainlock
            ? CurrentPredecessor()
            : ChainLockPredecessor{
                  chainlock.statement.previous_chainlock_height,
                  chainlock.statement.previous_chainlock_hash,
                  chainlock.statement.previous_btcc_cursor};
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
        if (m_revision != revision ||
            !IsPreparedPredecessorCurrent(predecessor,
                                          has_local_chainlock)) {
            SetError(error, ChainLockFinalityError::CONTEXT_CHANGED);
            return std::nullopt;
        }
        if (m_seen_witness.Contains(witness_id) &&
            !is_exact_retained_base()) {
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
        logical_id, witness_id, chainlock.statement,
        chainlock.selected_quorum_mask, predecessor,
        has_local_chainlock, declared_predecessor_cursor, *context,
        admission, revision};
}

bool ChainLockFinalityStore::AcceptVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::LIVE, /*persist=*/true, {}, {}, nullptr,
        nullptr, verification_context, recovery_universe, error);
}

bool ChainLockFinalityStore::AcceptVerifiedCoveringReceiptArchive(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    const ReceiptArchiveRosterAuthorization& authorization,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::LIVE, /*persist=*/true, {}, {}, nullptr,
        &authorization, verification_context, recovery_universe, error);
}

bool ChainLockFinalityStore::AcceptPersistedVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::TRUSTED_PERSISTENCE,
        /*persist=*/false, {}, {}, nullptr, nullptr,
        verification_context, nullptr, error);
}

bool ChainLockFinalityStore::AcceptReceiptArchiveVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    const ReceiptArchiveRosterAuthorization& authorization,
    ChainLockDurableAuthorization durable_authorization,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::RECEIPT_ARCHIVE,
        /*persist=*/true, {}, durable_authorization, &authorization, nullptr,
        verification_context, recovery_universe, error);
}

bool ChainLockFinalityStore::AcceptTrustedUnsealedVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE,
        /*persist=*/false, {}, {}, nullptr, nullptr,
        verification_context, nullptr, error);
}

bool ChainLockFinalityStore::AcceptPresealReceiptVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockPreDurableCatchup pre_durable,
    ChainLockDurableAuthorization durable_authorization,
    ChainLockFinalityError* error,
    PreparedChainLockContextPtr verification_context,
    const ReceiptArchiveRosterAuthorization*
        receipt_archive_authorization,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::PRESEAL_RECEIPT,
        /*persist=*/true, pre_durable, durable_authorization,
        receipt_archive_authorization, nullptr,
        verification_context, recovery_universe, error);
}

bool ChainLockFinalityStore::AcceptCatchupVerified(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockPreDurableCatchup pre_durable,
    ChainLockDurableAuthorization durable_authorization,
    ChainLockFinalityError* error,
    const ReceiptArchiveRosterAuthorization* covering_authorization,
    PreparedChainLockContextPtr verification_context,
    RecoveryUniverseCapsulePtr recovery_universe)
{
    return AcceptVerifiedInternal(
        prepared, chainlock, signatures_valid,
        ChainLockCandidateAdmission::CATCHUP,
        /*persist=*/true, pre_durable, durable_authorization, nullptr,
        covering_authorization, verification_context, recovery_universe,
        error);
}

bool ChainLockFinalityStore::AcceptVerifiedRosterAuthorizationBase(
    const FinalChainLock& chainlock,
    bool signatures_valid,
    PreparedChainLockContextPtr verification_context,
    ChainLockFinalityError* error,
    RecoveryUniverseCapsulePtr recovery_universe,
    ChainLockDurableAuthorization durable_authorization)
{
    return AcceptRosterAuthorizationBaseInternal(
        chainlock, signatures_valid, std::move(verification_context),
        /*persisted_import=*/false, std::move(recovery_universe), error,
        std::move(durable_authorization));
}

bool ChainLockFinalityStore::AcceptPersistedRosterAuthorizationBase(
    const FinalChainLock& chainlock,
    bool signatures_valid,
    PreparedChainLockContextPtr verification_context,
    ChainLockFinalityError* error)
{
    return AcceptRosterAuthorizationBaseInternal(
        chainlock, signatures_valid, std::move(verification_context),
        /*persisted_import=*/true, nullptr, error,
        /*durable_authorization=*/{});
}

bool ChainLockFinalityStore::AcceptRosterAuthorizationBaseInternal(
    const FinalChainLock& chainlock,
    bool signatures_valid,
    PreparedChainLockContextPtr verification_context,
    bool persisted_import,
    RecoveryUniverseCapsulePtr recovery_universe,
    ChainLockFinalityError* error,
    ChainLockDurableAuthorization durable_authorization)
{
    SetError(error, ChainLockFinalityError::NONE);
    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    const bool trusted_context{
        verification_context &&
        verification_context->Authorization().admission ==
            RosterAuthorizationAdmission::TRUSTED_PERSISTENCE};
    if (!chainlock.IsStructurallyValid() || logical_id.IsNull() ||
        witness_id.IsNull() || !verification_context ||
        !IsRecoveryUniverseCapabilityForStatement(
            m_genesis_hash, chainlock.statement, recovery_universe) ||
        trusted_context != persisted_import ||
        verification_context->GenesisHash() != m_genesis_hash ||
        verification_context->Schedule() != m_config.chainlock_schedule ||
        verification_context->Statement() != chainlock.statement ||
        verification_context->StatementLogicalId() != logical_id) {
        SetError(error, ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
        return false;
    }
    if (!signatures_valid) {
        LOCK(m_mutex);
        m_rejected_witness.Insert(witness_id);
        SetError(error, ChainLockFinalityError::INVALID_SIGNATURES);
        return false;
    }

    const auto already_accepted = [&](const AcceptedRecord& record) {
        return record.chainlock && record.logical_id == logical_id &&
               record.chainlock->statement == chainlock.statement &&
               record.verification_context &&
               record.verification_context->StatementLogicalId() == logical_id;
    };
    bool retained_invalid{false};
    const auto already_retained = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        const auto recent{
            m_recent_by_height.find(chainlock.statement.height)};
        if (recent != m_recent_by_height.end() &&
            already_accepted(recent->second)) {
            RememberAuthorizationBase(
                recent->second, persisted_import);
            return true;
        }
        if (m_unsealed_btcc && already_accepted(*m_unsealed_btcc)) {
            RememberAuthorizationBase(
                *m_unsealed_btcc, persisted_import);
            return true;
        }
        const auto existing{m_authorization_bases.find(logical_id)};
        if (existing == m_authorization_bases.end()) return false;
        if (!already_accepted(existing->second)) {
            retained_invalid = true;
            SetError(error,
                     ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
        }
        return true;
    };
    {
        LOCK(m_mutex);
        if (already_retained()) {
            return !retained_invalid;
        }
    }

    if (persisted_import && durable_authorization) {
        SetError(error, ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
        return false;
    }
    if (!persisted_import && durable_authorization &&
        !m_durable_authorization_base) {
        SetError(error, ChainLockFinalityError::PERSISTENCE_FAILURE);
        return false;
    }
    if (!persisted_import && m_durable_authorization_base) {
        const auto persist_record = [&] {
            return m_durable_authorization_base(
                chainlock, verification_context, recovery_universe);
        };
        try {
            const bool persisted{durable_authorization
                ? durable_authorization(persist_record, error)
                : persist_record()};
            if (!persisted) {
                if (error != nullptr &&
                    *error == ChainLockFinalityError::NONE) {
                    SetError(error,
                             ChainLockFinalityError::PERSISTENCE_FAILURE);
                }
                return false;
            }
        } catch (const std::exception&) {
            SetError(error, ChainLockFinalityError::PERSISTENCE_FAILURE);
            return false;
        }
    }

    LOCK(m_mutex);
    if (already_retained()) {
        return !retained_invalid;
    }
    AcceptedRecord retained{
        logical_id, witness_id,
        std::make_shared<const FinalChainLock>(chainlock),
        std::move(verification_context)};
    RememberAuthorizationBase(
        std::move(retained), persisted_import);
    return true;
}

bool ChainLockFinalityStore::AcceptVerifiedInternal(
    const PreparedFinalChainLockCandidate& prepared,
    const FinalChainLock& chainlock,
    bool signatures_valid,
    ChainLockCandidateAdmission admission,
    bool persist,
    const ChainLockPreDurableCatchup& pre_durable,
    const ChainLockDurableAuthorization& durable_authorization,
    const ReceiptArchiveRosterAuthorization*
        receipt_archive_authorization,
    const ReceiptArchiveRosterAuthorization* covering_authorization,
    const PreparedChainLockContextPtr& verification_context,
    const RecoveryUniverseCapsulePtr& recovery_universe,
    ChainLockFinalityError* error)
{
    SetError(error, ChainLockFinalityError::NONE);
    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (!chainlock.IsStructurallyValid() || prepared.logical_id != logical_id ||
        prepared.witness_id != witness_id || prepared.statement != chainlock.statement ||
        prepared.selected_quorum_mask != chainlock.selected_quorum_mask ||
        prepared.admission != admission ||
        !IsRecoveryUniverseCapabilityForStatement(
            m_genesis_hash, chainlock.statement, recovery_universe) ||
        (receipt_archive_authorization != nullptr &&
         (admission != ChainLockCandidateAdmission::RECEIPT_ARCHIVE &&
          admission != ChainLockCandidateAdmission::PRESEAL_RECEIPT)) ||
        (receipt_archive_authorization != nullptr &&
         (!persist ||
          !receipt_archive_authorization->IsInternallyConsistent(
              m_genesis_hash))) ||
        (admission == ChainLockCandidateAdmission::RECEIPT_ARCHIVE &&
         persist && receipt_archive_authorization == nullptr) ||
        (admission == ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
         persist &&
         chainlock.statement.roster_transition !=
             RosterAuthorizationTransitionKind::INITIALIZE &&
         receipt_archive_authorization == nullptr) ||
        (verification_context != nullptr &&
         (verification_context->GenesisHash() != m_genesis_hash ||
          verification_context->Schedule() != m_config.chainlock_schedule ||
          verification_context->Statement() != chainlock.statement)) ||
        (covering_authorization != nullptr &&
         (admission != ChainLockCandidateAdmission::LIVE &&
          admission != ChainLockCandidateAdmission::CATCHUP)) ||
        (covering_authorization != nullptr &&
         (!persist ||
          receipt_archive_authorization != nullptr ||
          !covering_authorization->IsInternallyConsistent(
              m_genesis_hash)))) {
        SetError(error, ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
        return false;
    }
    if (!signatures_valid) {
        LOCK(m_mutex);
        m_rejected_witness.Insert(witness_id);
        SetError(error, ChainLockFinalityError::INVALID_SIGNATURES);
        return false;
    }
    const bool verified_reset_transition{
        chainlock.statement.roster_transition ==
            RosterAuthorizationTransitionKind::INITIALIZE ||
        chainlock.statement.roster_transition ==
            RosterAuthorizationTransitionKind::RECOVER};
    const bool use_durable_reset{
        persist && verified_reset_transition &&
        (admission == ChainLockCandidateAdmission::LIVE ||
         admission == ChainLockCandidateAdmission::CATCHUP) &&
        static_cast<bool>(m_durable_reset)};
    const bool requires_durable_context{
        persist &&
        (use_durable_reset ||
         ((covering_authorization != nullptr &&
          admission == ChainLockCandidateAdmission::LIVE &&
          static_cast<bool>(m_durable_covering_accept)) ||
         (admission == ChainLockCandidateAdmission::CATCHUP &&
          static_cast<bool>(m_durable_catchup)) ||
         (admission == ChainLockCandidateAdmission::RECEIPT_ARCHIVE &&
         static_cast<bool>(m_durable_receipt_archive)) ||
         (admission == ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
          (receipt_archive_authorization != nullptr
               ? static_cast<bool>(m_durable_receipt_archive)
               : static_cast<bool>(m_durable_archive))) ||
         (admission == ChainLockCandidateAdmission::LIVE &&
          covering_authorization == nullptr &&
          static_cast<bool>(m_durable_accept))))};
    if (requires_durable_context && !verification_context) {
        SetError(error, ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
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
            !IsPreparedPredecessorCurrent(
                prepared.predecessor,
                prepared.has_local_chainlock)) {
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
        !IsPreparedPredecessorCurrent(
            prepared.predecessor,
            prepared.has_local_chainlock)) {
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
        admission ==
            ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE ||
        admission == ChainLockCandidateAdmission::PRESEAL_RECEIPT};
    const bool catchup_accept{
        admission == ChainLockCandidateAdmission::CATCHUP};
    const bool has_durable_callback{
        use_durable_reset
            ? true
        : receipt_archive_authorization != nullptr
            ? static_cast<bool>(m_durable_receipt_archive)
        : covering_authorization &&
                  admission == ChainLockCandidateAdmission::LIVE
            ? static_cast<bool>(m_durable_covering_accept)
        : archive_only ? static_cast<bool>(m_durable_archive)
                     : catchup_accept
                           ? static_cast<bool>(m_durable_catchup)
                           : static_cast<bool>(m_durable_accept)};
    std::optional<VerifiedRecoveryResetPersistenceCapability>
        verified_reset_capability;
    if (use_durable_reset) {
        verified_reset_capability =
            VerifiedRecoveryResetPersistenceCapability{
                logical_id, witness_id,
                chainlock.statement.roster_transition, admission};
    }
    const auto persist_record = [&] {
        try {
            const bool persisted{
                use_durable_reset
                    ? m_durable_reset(
                          chainlock,
                          rechecked->btcc_cursor_reconciliation,
                          covering_authorization,
                          verification_context,
                          recovery_universe,
                          *verified_reset_capability)
                : receipt_archive_authorization != nullptr
                    ? m_durable_receipt_archive(
                          chainlock, *receipt_archive_authorization,
                          verification_context, recovery_universe)
                : covering_authorization &&
                          admission == ChainLockCandidateAdmission::LIVE
                    ? m_durable_covering_accept(
                          chainlock, *covering_authorization,
                          verification_context, recovery_universe)
                : archive_only
                    ? m_durable_archive(chainlock, verification_context,
                                        recovery_universe)
                    : catchup_accept
                          ? m_durable_catchup(
                                chainlock,
                                rechecked->btcc_cursor_reconciliation,
                                covering_authorization,
                                verification_context, recovery_universe)
                          : m_durable_accept(chainlock,
                                             verification_context,
                                             recovery_universe)};
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

    AcceptedRecord accepted{
        logical_id, witness_id,
        std::make_shared<const FinalChainLock>(chainlock),
        verification_context};
    // Preserve the exact verified context for archive validation and startup
    // reconstruction after the smaller relay cache expires. Retention alone
    // never authorizes a stale-base state advance; the integration must also
    // prove convergence with the current durable winner.
    RememberAuthorizationBase(accepted);
    if (archive_only) {
        m_unsealed_btcc = accepted;
    } else {
        if (m_unsealed_btcc &&
            SealsUnsealedBTCC(chainlock, *m_unsealed_btcc->chainlock,
                              m_config)) {
            m_unsealed_btcc.reset();
        }
        if (IsReceiptableChainLock(chainlock, m_config)) {
            m_unsealed_btcc = accepted;
        }
        m_best = accepted;
    }
    RememberAccepted(std::move(accepted));
    ++m_revision;
    SetError(error, ChainLockFinalityError::NONE);
    return true;
}

void ChainLockFinalityStore::RememberAuthorizationBase(
    AcceptedRecord record,
    bool unordered_startup_import)
{
    if (!record.chainlock || !record.verification_context ||
        record.logical_id.IsNull() || record.witness_id.IsNull() ||
        record.chainlock->GetLogicalId(m_genesis_hash) != record.logical_id ||
        record.chainlock->GetWitnessId(m_genesis_hash) != record.witness_id ||
        record.verification_context->GenesisHash() != m_genesis_hash ||
        record.verification_context->Schedule() != m_config.chainlock_schedule ||
        record.verification_context->Statement() != record.chainlock->statement ||
        record.verification_context->StatementLogicalId() != record.logical_id) {
        return;
    }

    const uint256 logical_id{record.logical_id};
    const uint256 witness_id{record.witness_id};
    const int32_t incoming_height{record.chainlock->statement.height};
    const RosterAuthorizationBaseIdentity referenced_base{
        record.chainlock->statement.roster_authorization_base};
    const auto existing{m_authorization_bases.find(logical_id)};
    if (existing != m_authorization_bases.end()) {
        const auto old_witness{
            m_authorization_base_by_witness.find(existing->second.witness_id)};
        if (old_witness != m_authorization_base_by_witness.end() &&
            old_witness->second == logical_id) {
            m_authorization_base_by_witness.erase(old_witness);
        }
        existing->second = std::move(record);
    } else {
        m_authorization_bases.emplace(logical_id, std::move(record));
    }
    m_authorization_base_by_witness.insert_or_assign(witness_id, logical_id);
    m_seen_logical.Insert(logical_id);
    m_seen_witness.Insert(witness_id);

    std::set<uint256> protected_ids{logical_id};
    if (!referenced_base.IsNull()) {
        protected_ids.insert(referenced_base.logical_id);
    }
    if (m_best && m_best->chainlock) {
        protected_ids.insert(m_best->logical_id);
        const auto& base{
            m_best->chainlock->statement.roster_authorization_base};
        if (!base.IsNull()) protected_ids.insert(base.logical_id);
    }
    if (m_unsealed_btcc && m_unsealed_btcc->chainlock) {
        protected_ids.insert(m_unsealed_btcc->logical_id);
        const auto& base{
            m_unsealed_btcc->chainlock->statement.roster_authorization_base};
        if (!base.IsNull()) protected_ids.insert(base.logical_id);
    }
    const std::optional<int32_t> retention_height{
        unordered_startup_import
            ? std::nullopt
            : std::optional<int32_t>{
                  m_best && m_best->chainlock
                      ? std::max(incoming_height,
                                 m_best->chainlock->statement.height)
                      : incoming_height}};
    for (const auto& [retained_id, retained] : m_authorization_bases) {
        const auto carrier_end{
            retained.chainlock
                ? PaymentAuditProtectionCarrierEnd(
                      PaymentAuditScheduleConfig{
                          m_config.chainlock_schedule,
                          m_config.btcc_schedule},
                      retained.chainlock->statement.height)
                : std::nullopt};
        if (carrier_end &&
            (!retention_height || *retention_height < *carrier_end)) {
            protected_ids.insert(retained_id);
            const auto& seal_base{
                retained.chainlock->statement.roster_authorization_base};
            if (!seal_base.IsNull()) {
                protected_ids.insert(seal_base.logical_id);
            }
        }
    }

    while (m_authorization_bases.size() >
           VERIFIED_AUTHORIZATION_BASE_CAPACITY) {
        auto old{m_authorization_bases.end()};
        for (auto it{m_authorization_bases.begin()};
             it != m_authorization_bases.end(); ++it) {
            if (protected_ids.count(it->first) != 0) continue;
            if (old == m_authorization_bases.end()) {
                old = it;
                continue;
            }
            const auto& lhs{it->second.chainlock->statement};
            const auto& rhs{old->second.chainlock->statement};
            if (lhs.height < rhs.height ||
                (lhs.height == rhs.height && it->first < old->first)) {
                old = it;
            }
        }
        if (old == m_authorization_bases.end()) break;
        const uint256 old_logical{old->first};
        const auto old_witness{
            m_authorization_base_by_witness.find(old->second.witness_id)};
        if (old_witness != m_authorization_base_by_witness.end() &&
            old_witness->second == old_logical) {
            m_authorization_base_by_witness.erase(old_witness);
        }
        m_authorization_bases.erase(old);
    }
    if (m_authorization_bases.size() >
        VERIFIED_AUTHORIZATION_BASE_CAPACITY) {
        throw std::logic_error{
            "authorization-base retention capacity invariant"};
    }
    ++m_authorization_base_revision;
}

void ChainLockFinalityStore::RejectPrepared(
    const PreparedFinalChainLockCandidate& prepared)
{
    LOCK(m_mutex);
    if (!prepared.witness_id.IsNull() &&
        !m_authorization_base_by_witness.contains(prepared.witness_id)) {
        m_rejected_witness.Insert(prepared.witness_id);
    }
}

void ChainLockFinalityStore::RejectWitness(const FinalChainLock& chainlock)
{
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (witness_id.IsNull()) return;
    LOCK(m_mutex);
    if (!m_authorization_base_by_witness.contains(witness_id)) {
        m_rejected_witness.Insert(witness_id);
    }
}

void ChainLockFinalityStore::AbandonPrepared(
    const PreparedFinalChainLockCandidate& prepared)
{
    LOCK(m_mutex);
    // Accepted and explicitly rejected witnesses must remain deduplicated.
    if (m_rejected_witness.Contains(prepared.witness_id) ||
        m_recent_by_witness.find(prepared.witness_id) != m_recent_by_witness.end() ||
        m_authorization_base_by_witness.contains(prepared.witness_id) ||
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
           m_authorization_base_by_witness.contains(witness_id) ||
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
        if (!m_best || height < 0 || block_hash.IsNull()) {
            return false;
        }
        best_height = m_best->chainlock->statement.height;
        best_hash = m_best->chainlock->statement.block_hash;
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
        // A height-only activation boundary is not a ChainLock. Until a
        // certificate is fully verified and durable, ordinary PoW fork choice
        // remains authoritative for every branch.
        if (!m_best) return false;
        best_height = m_best->chainlock->statement.height;
        best_hash = m_best->chainlock->statement.block_hash;
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

bool ReceiptArchiveRosterAuthorization::IsInternallyConsistent(
    const uint256& genesis_hash) const
{
    return owner.IsInternallyConsistent(genesis_hash) &&
           !covering_logical_id.IsNull() &&
           !covering_witness_id.IsNull() &&
           predecessor.IsInternallyConsistent(genesis_hash) &&
           owner.statement.previous_chainlock_height >
               predecessor.statement.height &&
           owner.statement.previous_chainlock_height <
               owner.statement.height;
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
        m_best->chainlock,
        m_best->verification_context};
}

std::optional<AcceptedFinalChainLockView>
ChainLockFinalityStore::GetRecordByHeight(int32_t height) const
{
    LOCK(m_mutex);
    const auto found{m_recent_by_height.find(height)};
    const AcceptedRecord* record{found != m_recent_by_height.end()
        ? &found->second
        : (m_unsealed_btcc &&
                   m_unsealed_btcc->chainlock->statement.height == height
               ? &*m_unsealed_btcc
               : nullptr)};
    if (record == nullptr) return std::nullopt;
    return AcceptedFinalChainLockView{
        m_revision,
        FinalChainLockRecordMetadata{
            record->logical_id, record->witness_id,
            record->chainlock->statement},
        record->chainlock,
        record->verification_context};
}

std::optional<VerifiedRosterAuthorizationBaseView>
ChainLockFinalityStore::GetVerifiedRosterAuthorizationBase(
    const RosterAuthorizationBaseIdentity& identity) const
{
    if (!identity.IsStructurallyValid() || identity.IsNull()) {
        return std::nullopt;
    }
    LOCK(m_mutex);
    const AcceptedRecord* record{nullptr};
    const auto retained{m_authorization_bases.find(identity.logical_id)};
    if (retained != m_authorization_bases.end()) {
        record = &retained->second;
    }
    if (record == nullptr && m_unsealed_btcc &&
        m_unsealed_btcc->logical_id == identity.logical_id) {
        record = &*m_unsealed_btcc;
    }
    if (record == nullptr) {
        const auto recent{m_recent_by_height.find(identity.height)};
        if (recent != m_recent_by_height.end() &&
            recent->second.logical_id == identity.logical_id) {
            record = &recent->second;
        }
    }
    if (record == nullptr || !record->verification_context ||
        record->logical_id != identity.logical_id ||
        record->chainlock->statement.height != identity.height ||
        record->chainlock->statement.block_hash != identity.block_hash ||
        record->verification_context->Statement() !=
            record->chainlock->statement ||
        record->verification_context->StatementLogicalId() !=
            record->logical_id) {
        return std::nullopt;
    }
    return VerifiedRosterAuthorizationBaseView{
        m_authorization_base_revision,
        FinalChainLockRecordMetadata{
            record->logical_id, record->witness_id,
            record->chainlock->statement},
        record->chainlock, record->verification_context};
}

std::optional<VerifiedRosterAuthorizationBaseView>
ChainLockFinalityStore::GetVerifiedRosterAuthorizationBaseByLogicalId(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return std::nullopt;
    LOCK(m_mutex);
    const auto retained{m_authorization_bases.find(logical_id)};
    if (retained == m_authorization_bases.end()) return std::nullopt;
    const auto& record{retained->second};
    if (!record.chainlock || !record.verification_context ||
        record.logical_id != logical_id ||
        record.verification_context->Statement() !=
            record.chainlock->statement ||
        record.verification_context->StatementLogicalId() != logical_id) {
        return std::nullopt;
    }
    return VerifiedRosterAuthorizationBaseView{
        m_authorization_base_revision,
        FinalChainLockRecordMetadata{
            record.logical_id, record.witness_id,
            record.chainlock->statement},
        record.chainlock, record.verification_context};
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

std::shared_ptr<const FinalChainLock>
ChainLockFinalityStore::GetServableByLogicalId(
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
    const auto retained{m_authorization_bases.find(logical_id)};
    if (retained != m_authorization_bases.end()) {
        return retained->second.chainlock;
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

std::size_t ChainLockFinalityStore::AuthorizationBaseSizeForTesting() const
{
    LOCK(m_mutex);
    return m_authorization_bases.size();
}

} // namespace llmq::pq
