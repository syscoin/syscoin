// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>
#include <llmq/btc_header_policy.h>
#include <llmq/pq_btcc.h>
#include <llmq/pq_quorum_overlay.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/params.h>
#include <consensus/pq_migration_config.h>
#include <consensus/validation.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <governance/governanceclasses.h>
#include <logging.h>
#include <memusage.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <protocol.h>
#include <scheduler.h>
#include <services/nevmconsensus.h>
#include <spork.h>
#include <streams.h>
#include <util/signalinterrupt.h>
#include <util/thread.h>
#include <util/time.h>
#include <validation.h>
#include <version.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmq {
namespace {

constexpr std::size_t MAX_PQ_CHAINLOCK_VERIFY_THREADS{16};
constexpr std::string_view BTCC_NEVM_REPLAY_PRUNE_LOCK{"btcc-nevm-replay"};
constexpr std::string_view PAYMENT_AUDIT_REPLAY_PRUNE_LOCK{
    "payment-audit-replay"};
constexpr std::size_t PQ_CHAINLOCK_PREFIX_SIZE{
    pq::FinalChainLock::WIRE_SIZE -
    pq::FINAL_SIGNATURE_COUNT * pq::AuthenticatedChildSignature::WIRE_SIZE};
constexpr std::chrono::seconds PAYMENT_AUDIT_FINALIZATION_RETRY_INTERVAL{30};

pq::RosterResetVerificationPolicy MakeRosterResetVerificationPolicy(
    const pq::ChainLockFinalityStoreConfig& config)
{
    return {config.chainlock_schedule, config.btcc_schedule,
            config.activation_predecessor_height};
}

uint256 GetActiveMasternodeRelayIdentity()
{
    uint256 local_pro_tx_hash;
    uint32_t local_key_version{0};
    pq::GlobalPublicKey local_public_key{};
    CService local_service;
    if (!GetActiveMasternodeIdentity(
            local_pro_tx_hash, local_key_version,
            local_public_key, local_service)) {
        return {};
    }
    return local_pro_tx_hash;
}

std::shared_ptr<const PQRelayPlan> BuildPQRelayPlanForCurrentIdentity(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters)
{
    return BuildPQRelayPlan(
        rosters, GetActiveMasternodeRelayIdentity());
}

bool IsPQRelayPlanForActiveIdentity(
    const std::shared_ptr<const PQRelayPlan>& plan)
{
    return plan && !plan->relay_members.empty() &&
           IsPQRelayPlanForIdentity(
               *plan, GetActiveMasternodeRelayIdentity());
}

bool IsPQRelayPlanForIdentityState(
    const std::shared_ptr<const PQRelayPlan>& plan,
    const uint256& active_identity)
{
    if (!plan || plan->authorized_recipients.empty()) return false;
    if (active_identity.IsNull()) {
        return plan->local_pro_tx_hash.IsNull() &&
               plan->relay_members.empty();
    }
    return IsPQRelayPlanForIdentity(*plan, active_identity) &&
           std::all_of(
               plan->relay_members.begin(),
               plan->relay_members.end(),
               [&](const uint256& member) {
                   return plan->authorized_recipients.contains(member);
               });
}

bool IsPQRelayPlanForCurrentIdentityState(
    const std::shared_ptr<const PQRelayPlan>& plan)
{
    return IsPQRelayPlanForIdentityState(
        plan, GetActiveMasternodeRelayIdentity());
}

pq::RecoveryRosterAuthorityPtr RecoveryAuthorityForDurableState(
    const uint256& genesis_hash,
    const pq::FinalChainLock& chainlock,
    const pq::PreparedChainLockContextPtr& context)
{
    if (!context || context->GenesisHash() != genesis_hash ||
        context->Statement() != chainlock.statement) {
        return nullptr;
    }
    return context->RecoveryAuthorityPtr();
}

bool IsBitmapBitSet(const pq::QuorumBitmap& bitmap,
                    std::size_t member) noexcept
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

bool HasBitmapBits(const pq::QuorumBitmap& bitmap) noexcept
{
    return std::any_of(bitmap.begin(), bitmap.end(),
                       [](uint8_t byte) { return byte != 0; });
}

pq::QuorumBitmap MissingBitmap(
    const pq::QuorumBitmap& available,
    const pq::QuorumBitmap& excluded) noexcept
{
    pq::QuorumBitmap result{};
    for (std::size_t byte{0}; byte < result.size(); ++byte) {
        result[byte] = available[byte] &
                       static_cast<uint8_t>(~excluded[byte]);
    }
    return result;
}

void AddBitmap(pq::QuorumBitmap& target,
               const pq::QuorumBitmap& added) noexcept
{
    for (std::size_t byte{0}; byte < target.size(); ++byte) {
        target[byte] |= added[byte];
    }
}

void RemoveBitmap(pq::QuorumBitmap& target,
                  const pq::QuorumBitmap& removed) noexcept
{
    for (std::size_t byte{0}; byte < target.size(); ++byte) {
        target[byte] &= static_cast<uint8_t>(~removed[byte]);
    }
}

bool SamePaymentAuditOpenRowIdentity(
    const pq::PaymentAuditOpenRowMetadata& first,
    const pq::PaymentAuditOpenRowMetadata& second) noexcept
{
    return first.expected == second.expected &&
           first.deadline_height == second.deadline_height &&
           first.response_block_hash == second.response_block_hash &&
           first.subject_valid_members == second.subject_valid_members &&
           first.response_advance == second.response_advance;
}

bool SameFrozenQuorumRoster(const pq::FrozenQuorumRoster& first,
                            const pq::FrozenQuorumRoster& second)
{
    if (first.descriptor != second.descriptor) return false;
    for (std::size_t member{0}; member < first.members.size(); ++member) {
        const auto& left{first.members[member]};
        const auto& right{second.members[member]};
        if (left.pro_tx_hash != right.pro_tx_hash ||
            left.eligible != right.eligible ||
            left.child_root != right.child_root) {
            return false;
        }
    }
    return true;
}

std::optional<pq::PQPaymentProbationTransitionView>
DerivePaymentAuditProbationTransition(
    const pq::PaymentAuditCommitment& commitment,
    const pq::FrozenQuorumRoster& subject,
    const CBlockIndex& carrier_parent,
    int32_t carrier_height,
    const uint256& result_hash,
    const pq::QuorumBitmap& observed_members,
    bool* local_error = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (local_error != nullptr) *local_error = false;
    if (deterministicMNManager == nullptr) {
        if (local_error != nullptr) *local_error = true;
        return std::nullopt;
    }
    if (carrier_parent.nHeight == std::numeric_limits<int32_t>::max() ||
        carrier_parent.nHeight + 1 != carrier_height ||
        commitment.seal_height >= carrier_height || result_hash.IsNull() ||
        commitment.previous_probation_state_hash.IsNull() ||
        carrier_parent.pqPaymentProbationStateHash !=
            commitment.previous_probation_state_hash) {
        return std::nullopt;
    }
    pq::PQPaymentProbationTransitionContext context;
    context.receipt = {
        commitment.seed.epoch, carrier_height, result_hash};
    context.roster_valid_members = commitment.subject_valid_members;
    context.observed_members = observed_members;
    for (std::size_t member{0}; member < pq::QUORUM_SIZE; ++member) {
        context.frozen_roster[member] =
            subject.members[member].pro_tx_hash;
    }
    auto outcome{deterministicMNManager->ApplyPaymentProbationTransition(
        carrier_parent, context)};
    if (outcome.status !=
            pq::PQPaymentProbationTransitionStatus::READY ||
        !outcome.transition) {
        if (local_error != nullptr) {
            *local_error = outcome.status !=
                pq::PQPaymentProbationTransitionStatus::INVALID;
        }
        return std::nullopt;
    }
    return std::move(outcome.transition);
}

class ScopedFinalitySnapshotVerificationRetention final
{
private:
    CDeterministicMNManager* const m_manager;

public:
    explicit ScopedFinalitySnapshotVerificationRetention(
        CDeterministicMNManager* manager) : m_manager{manager}
    {
        if (m_manager) {
            m_manager->BeginFinalitySnapshotVerificationRetention();
        }
    }

    ~ScopedFinalitySnapshotVerificationRetention()
    {
        if (m_manager) {
            m_manager->EndFinalitySnapshotVerificationRetention();
        }
    }

    ScopedFinalitySnapshotVerificationRetention(
        const ScopedFinalitySnapshotVerificationRetention&) = delete;
    ScopedFinalitySnapshotVerificationRetention& operator=(
        const ScopedFinalitySnapshotVerificationRetention&) = delete;
};

uint256 ReadChainLockLogicalIdPrefix(const CDataStream& payload,
                                     const uint256& genesis_hash)
{
    SpanReader reader{
        payload.GetType(), payload.GetVersion(),
        MakeUCharSpan(payload).first(PQ_CHAINLOCK_PREFIX_SIZE)};
    pq::ChainLockStatement statement;
    uint8_t selected_quorum_mask{0};
    std::array<pq::QuorumBitmap, pq::ACTIVE_QUORUMS> signer_bitmaps{};
    uint16_t signature_count{0};
    reader >> statement >> selected_quorum_mask;
    if (!statement.IsStructurallyValid() ||
        !pq::IsSelectedQuorumMask(selected_quorum_mask)) {
        throw std::ios_base::failure("invalid PQ ChainLock prefix");
    }
    for (std::size_t slot{0}; slot < signer_bitmaps.size(); ++slot) {
        reader >> signer_bitmaps[slot];
        const bool selected{
            (selected_quorum_mask & (uint8_t{1} << slot)) != 0};
        const std::size_t count{pq::CountSet(signer_bitmaps[slot])};
        if ((selected && count != pq::QUORUM_THRESHOLD) ||
            (!selected && count != 0)) {
            throw std::ios_base::failure("invalid PQ ChainLock bitmap prefix");
        }
    }
    reader >> signature_count;
    if (!reader.empty() || signature_count != pq::FINAL_SIGNATURE_COUNT) {
        throw std::ios_base::failure("invalid PQ ChainLock signature prefix");
    }
    return pq::GetLogicalChainLockId(genesis_hash, statement);
}

std::array<pq::QuorumDescriptor, pq::ACTIVE_QUORUMS> Descriptors(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters)
{
    std::array<pq::QuorumDescriptor, pq::ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < descriptors.size(); ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    return descriptors;
}

std::unique_ptr<pq::FrozenQuorumRoster> BuildHistoricalFrozenRoster(
    const uint256& genesis_hash,
    const pq::QuorumBuildConfig& config,
    const pq::FrozenQuorumRosterCache& roster_cache,
    uint32_t epoch,
    const CBlockIndex& branch_tip,
    const pq::RosterBeaconSeed& beacon_seed,
    pq::QuorumBuildError* error)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (error != nullptr) *error = pq::QuorumBuildError::NONE;
    const auto base_height{
        pq::EpochBaseHeight(config.schedule, epoch)};
    const auto snapshot_height{pq::RegistrationCutoffHeight(
        config.schedule, epoch, config.roster_snapshot_lag_blocks)};
    if (!base_height || !snapshot_height ||
        *snapshot_height >= *base_height || !beacon_seed.IsReady() ||
        beacon_seed.epoch != epoch ||
        beacon_seed.anchor_kind != pq::RosterBeaconAnchorKind::NORMAL) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::INVALID_ROSTER_BEACON;
        }
        return nullptr;
    }
    const CBlockIndex* base{branch_tip.GetAncestor(*base_height)};
    const CBlockIndex* snapshot{branch_tip.GetAncestor(*snapshot_height)};
    if (base == nullptr || snapshot == nullptr) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR;
        }
        return nullptr;
    }
    std::optional<pq::QuorumSnapshotState> snapshot_state;
    try {
        snapshot_state = roster_cache.LookupSnapshot(*snapshot);
    } catch (const std::exception&) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED;
        }
        return nullptr;
    }
    if (!snapshot_state || snapshot_state->deterministic_mns.IsNull() ||
        snapshot_state->deterministic_mns.GetHeight() != *snapshot_height ||
        snapshot_state->deterministic_mns.GetBlockHash() !=
            snapshot->GetBlockHash() ||
        !snapshot_state->operator_key_states) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::SNAPSHOT_MISMATCH;
        }
        return nullptr;
    }
    return pq::BuildFrozenQuorumRoster(
        genesis_hash, config, epoch, base->GetBlockHash(), beacon_seed,
        snapshot_state->deterministic_mns,
        std::span<const pq::OperatorKeyState>{
            snapshot_state->operator_key_states->data(),
            snapshot_state->operator_key_states->size()},
        error);
}

std::optional<pq::BTCCReceiptState> IndexedBTCCReceiptState(
    const CBlockIndex& index)
{
    pq::BTCCReceiptState state{
        pq::BTCCursor{index.pqBTCCReceiptCursorHeight,
                       index.pqBTCCReceiptCursorSysHash,
                       index.pqBTCCReceiptCursorBTCHash},
        index.pqBTCCReceiptStateHash};
    if (!state.IsStructurallyValid()) return std::nullopt;
    return state;
}

std::optional<pq::PaymentAuditReceiptState>
IndexedPaymentAuditReceiptState(const CBlockIndex& index)
{
    pq::PaymentAuditReceiptState state{
        pq::PaymentAuditReceiptCursor{
            index.pqPaymentAuditReceiptCursorHeight,
            index.pqPaymentAuditReceiptCursorEpoch,
            index.pqPaymentAuditReceiptCursorSealHash,
            index.pqPaymentAuditReceiptCursorLogicalId,
            index.pqPaymentAuditReceiptCursorWitnessId},
        index.pqPaymentAuditReceiptStateHash};
    if (!state.IsStructurallyValid()) return std::nullopt;
    return state;
}

bool HasBTCCIndexProvenance(const CBlockIndex& index) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return (index.nStatus &
            (BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
             BLOCK_PQ_BTCC_INDEX_VALIDATED)) != 0;
}

bool HasFullReceiptIndexProvenance(const CBlockIndex& index) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return (index.nStatus & BLOCK_PQ_RECEIPT_INDEX_VALIDATED) != 0;
}

struct PaymentAuditSeedReceiptContext {
    PaymentAuditContextStatus status{PaymentAuditContextStatus::LOCAL_ERROR};
    std::optional<pq::PaymentAuditSeedPoint> seed_point;
};

PaymentAuditSeedReceiptContext GetPaymentAuditSeedReceiptContext(
    const uint256& genesis_hash,
    const pq::PaymentAuditScheduleConfig& config,
    const pq::PaymentAuditEpochSchedule& schedule,
    const CBlockIndex& seal)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!schedule.IsStructurallyValid(config) ||
        seal.nHeight != schedule.seal_height) {
        return {PaymentAuditContextStatus::INVALID, std::nullopt};
    }
    const int64_t carrier_height{
        static_cast<int64_t>(schedule.anchor_height) +
        config.btcc.nevm_injection_lag};
    if (carrier_height > std::numeric_limits<int32_t>::max() ||
        carrier_height >= seal.nHeight ||
        !pq::IsBTCCReceiptCarrierHeight(
            config.btcc, static_cast<int32_t>(carrier_height))) {
        return {PaymentAuditContextStatus::INVALID, std::nullopt};
    }
    const CBlockIndex* carrier{
        seal.GetAncestor(static_cast<int32_t>(carrier_height))};
    if (carrier == nullptr || carrier->pprev == nullptr) {
        return {PaymentAuditContextStatus::LOCAL_ERROR, std::nullopt};
    }
    if ((carrier->nStatus | carrier->pprev->nStatus) & BLOCK_FAILED_MASK) {
        return {PaymentAuditContextStatus::INVALID, std::nullopt};
    }
    if (carrier->IsAssumedValid() || carrier->pprev->IsAssumedValid() ||
        !carrier->IsValid(BLOCK_VALID_SCRIPTS) ||
        !carrier->pprev->IsValid(BLOCK_VALID_SCRIPTS) ||
        !HasFullReceiptIndexProvenance(*carrier) ||
        !HasFullReceiptIndexProvenance(*carrier->pprev)) {
        return {PaymentAuditContextStatus::LOCAL_ERROR, std::nullopt};
    }
    const auto previous{IndexedBTCCReceiptState(*carrier->pprev)};
    const auto current{IndexedBTCCReceiptState(*carrier)};
    if (!previous || !current) {
        return {PaymentAuditContextStatus::LOCAL_ERROR, std::nullopt};
    }
    const auto receipt{pq::ReconstructBTCCReceipt(
        genesis_hash, config.chainlock, config.btcc, *carrier, *previous,
        *current, carrier->pqBTCCReceiptLogicalId)};
    if (!receipt) {
        return {PaymentAuditContextStatus::LOCAL_ERROR, std::nullopt};
    }
    if (receipt->IsNull()) {
        return {PaymentAuditContextStatus::READY, std::nullopt};
    }
    const auto seed_point{
        pq::PaymentAuditSeedPointFromBTCCReceipt(*receipt)};
    if (!seed_point ||
        seed_point->target_height != schedule.anchor_height) {
        return {PaymentAuditContextStatus::LOCAL_ERROR, std::nullopt};
    }
    return {PaymentAuditContextStatus::READY, seed_point};
}

PaymentAuditContextStatus ClassifyHistoricalReceiptIndexRange(
    const CBlockIndex& last, int32_t first_height,
    HistoricalIndexValidationCache& cache,
    uint64_t provenance_revocation_revision,
    std::size_t block_budget =
        HistoricalIndexValidationCache::BLOCK_BUDGET)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return cache.Validate(
        last, first_height,
        HistoricalIndexValidationMode::FULL_RECEIPT,
        provenance_revocation_revision, block_budget);
}

bool HasChainLockTargetValidation(const CBlockIndex& candidate,
                                  int32_t predecessor_height,
                                  HistoricalIndexValidationMode mode,
                                  HistoricalIndexValidationCache& cache,
                                  uint64_t provenance_revocation_revision,
                                  std::size_t block_budget =
                                      HistoricalIndexValidationCache::BLOCK_BUDGET)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    bool target_provenance{false};
    switch (mode) {
    case HistoricalIndexValidationMode::BTCC_COMPAT:
        target_provenance = HasBTCCIndexProvenance(candidate);
        break;
    case HistoricalIndexValidationMode::FULL_RECEIPT:
        target_provenance = HasFullReceiptIndexProvenance(candidate);
        break;
    case HistoricalIndexValidationMode::FULL_FINALITY: {
        constexpr uint32_t required{
            BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_PQ_RECEIPT_INDEX_VALIDATED};
        target_provenance = (candidate.nStatus & required) == required;
        break;
    }
    }
    if (predecessor_height < 0 ||
        predecessor_height >= candidate.nHeight ||
        !target_provenance ||
        cache.Validate(
            candidate, predecessor_height + 1,
            mode,
            provenance_revocation_revision, block_budget) !=
            PaymentAuditContextStatus::READY) {
        return false;
    }
    return true;
}

uint256 CandidateContextToken(const CBlockIndex& candidate,
                              const pq::ChainLockCandidateContextRequest& request,
                              const CBlockIndex* active_tip = nullptr,
                              const uint256& historical_token = {})
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_CHAINLOCK_RUNTIME_CONTEXT_V1"}
           << candidate.GetBlockHash() << candidate.nHeight
           << candidate.nStatus << candidate.nChainTx
           << request.local_best.height << request.local_best.block_hash
           << request.local_best.btcc_cursor
           << request.has_local_chainlock
           << request.statement
           << static_cast<uint8_t>(request.admission)
           << historical_token
           << request.declared_predecessor_btcc_cursor.has_value();
    if (request.declared_predecessor_btcc_cursor) {
        writer << *request.declared_predecessor_btcc_cursor;
    }
    if (request.admission == pq::ChainLockCandidateAdmission::CATCHUP ||
        request.admission ==
            pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT) {
        writer << (active_tip != nullptr);
        if (active_tip != nullptr) {
            writer << active_tip->nHeight << active_tip->GetBlockHash()
                   << ArithToUint256(active_tip->nChainWork);
        }
    }
    return writer.GetHash();
}

uint256 BTCCPresealStateToken(const pq::BTCCPresealState& state)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_BTCC_PRESEAL_ADMISSION_V1"};
    const auto write_marker = [&](const auto& marker) {
        writer << marker.has_value();
        if (!marker) return;
        writer << marker->earliest_carrier_height
               << marker->earliest_carrier_hash
               << marker->predecessor_receipt_state
               << marker->terminal_carrier_height
               << marker->terminal_carrier_hash
               << marker->terminal_receipt
               << marker->revision;
    };
    write_marker(state.active);
    write_marker(state.prospective);
    return writer.GetHash();
}

uint256 BoundedBTCCPresealSourceToken(
    const pq::BTCCPresealState& state,
    uint64_t provenance_revocation_revision)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_BTCC_BOUNDED_RECOVERY_V1"}
           << BTCCPresealStateToken(state)
           << provenance_revocation_revision;
    return writer.GetHash();
}

uint256 LiveBTCCCertificateSourceToken(
    uint64_t provenance_revocation_revision,
    const pq::ChainLockPredecessor& durable_predecessor,
    int32_t target_height,
    const uint256& target_hash)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_BTCC_LIVE_CERTIFICATE_NEED_V1"}
           << provenance_revocation_revision
           << durable_predecessor.height
           << durable_predecessor.block_hash
           << durable_predecessor.btcc_cursor
           << target_height << target_hash;
    return writer.GetHash();
}

uint256 PaymentAuditPresealStateToken(
    const pq::PaymentAuditPresealState& state)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_PAYMENT_AUDIT_PRESEAL_ADMISSION_V1"};
    const auto write_marker = [&](const auto& marker) {
        writer << marker.has_value();
        if (!marker) return;
        writer << marker->earliest_carrier_height
               << marker->earliest_carrier_hash
               << marker->predecessor_receipt_state
               << marker->predecessor_probation_state_hash
               << marker->terminal_carrier_height
               << marker->terminal_carrier_hash
               << marker->terminal_receipt
               << marker->revision;
    };
    write_marker(state.active);
    write_marker(state.prospective);
    return writer.GetHash();
}

uint256 PaymentAuditCheckpointToken(
    const std::optional<pq::PaymentAuditStoreCheckpoint>& checkpoint)
{
    if (!checkpoint) return {};
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_PAYMENT_AUDIT_CHECKPOINT_SOURCE_V1"}
           << checkpoint->prune_through_epoch
           << checkpoint->covered_through_height
           << checkpoint->covered_through_hash
           << checkpoint->authenticated_receipt_state
           << checkpoint->authenticated_probation_state_hash
           << checkpoint->authorizing_target_height
           << checkpoint->authorizing_target_hash
           << checkpoint->authorizing_chainlock_logical_id
           << checkpoint->authorizing_chainlock_witness_id;
    return writer.GetHash();
}

uint256 PresealAdmissionToken(
    const pq::BTCCPresealState& btcc_state,
    const pq::PaymentAuditPresealState& payment_audit_state)
{
    if (btcc_state.IsEmpty() && payment_audit_state.IsEmpty()) {
        return {};
    }
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_COMBINED_PRESEAL_ADMISSION_V1"}
           << !btcc_state.IsEmpty();
    if (!btcc_state.IsEmpty()) {
        writer << BTCCPresealStateToken(btcc_state);
    }
    writer << !payment_audit_state.IsEmpty();
    if (!payment_audit_state.IsEmpty()) {
        writer << PaymentAuditPresealStateToken(payment_audit_state);
    }
    return writer.GetHash();
}

std::optional<int32_t> OldestRosterSnapshotHeight(
    const pq::QuorumBuildConfig& config,
    int32_t target_height)
{
    const auto active_epochs{
        pq::ActiveEpochsAtHeight(config.schedule, target_height)};
    if (!active_epochs) return std::nullopt;
    int32_t oldest{std::numeric_limits<int32_t>::max()};
    for (const auto& identity : *active_epochs) {
        const auto snapshot{pq::RegistrationCutoffHeight(
            config.schedule, identity.epoch,
            config.roster_snapshot_lag_blocks)};
        if (!snapshot) return std::nullopt;
        oldest = std::min(oldest, *snapshot);
    }
    return oldest == std::numeric_limits<int32_t>::max()
        ? std::nullopt
        : std::optional<int32_t>{oldest};
}

std::optional<int32_t> RecoveryAuthoritySnapshotHeight(
    const pq::QuorumBuildConfig& config,
    const pq::RecoveryRosterAuthoritySource& source)
{
    if (!source.IsStructurallyValid() || source.IsNull()) {
        return std::nullopt;
    }
    return pq::RegistrationCutoffHeight(
        config.schedule, source.normal_beacon.epoch,
        config.roster_snapshot_lag_blocks);
}

bool BTCCPresealAuxiliaryRetentionFloor(
    const pq::BTCCPresealState& state,
    const pq::QuorumBuildConfig& config,
    std::optional<int32_t>& floor)
{
    floor.reset();
    const auto inspect = [&](const auto& marker) {
        if (!marker) return true;
        const auto roster_floor{OldestRosterSnapshotHeight(
            config, marker->terminal_receipt.chainlock_target_height)};
        if (!roster_floor || marker->earliest_carrier_height <= 0) {
            return false;
        }
        const int32_t marker_floor{std::min(
            static_cast<int32_t>(marker->earliest_carrier_height - 1),
            *roster_floor)};
        floor = floor ? std::min(*floor, marker_floor) : marker_floor;
        return true;
    };
    return inspect(state.active) && inspect(state.prospective) &&
           (state.IsEmpty() || floor.has_value());
}

bool PaymentAuditPresealAuxiliaryRetentionFloor(
    const pq::PaymentAuditPresealState& state,
    const pq::ChainLockFinalityStoreConfig& finality_config,
    const pq::QuorumBuildConfig& quorum_config,
    std::optional<int32_t>& floor)
{
    floor.reset();
    const pq::PaymentAuditScheduleConfig audit_schedule{
        finality_config.chainlock_schedule,
        finality_config.btcc_schedule};
    const auto inspect = [&](const auto& marker) {
        if (!marker) return true;
        const auto epoch{pq::PaymentAuditReceiptSlotEpoch(
            audit_schedule, marker->earliest_carrier_height)};
        if (!epoch || marker->earliest_carrier_height <= 0) return false;
        const auto snapshot{pq::RegistrationCutoffHeight(
            quorum_config.schedule, *epoch,
            quorum_config.roster_snapshot_lag_blocks)};
        if (!snapshot) return false;
        const int32_t marker_floor{std::min(
            marker->earliest_carrier_height - 1, *snapshot)};
        floor = floor ? std::min(*floor, marker_floor) : marker_floor;
        return true;
    };
    return inspect(state.active) && inspect(state.prospective) &&
           (state.IsEmpty() || floor.has_value());
}

std::optional<uint32_t> LatestFullyCoveredPaymentAuditEpoch(
    const pq::PaymentAuditScheduleConfig& config,
    int32_t target_height)
{
    const auto target_epoch{
        pq::EpochForHeight(config.chainlock, target_height)};
    if (!target_epoch) return std::nullopt;
    // A subject window is carried one or two epochs later. Search a small
    // schedule-derived neighborhood rather than scanning chain history.
    constexpr uint32_t SEARCH_EPOCHS{pq::ACTIVE_QUORUMS + 2};
    for (uint32_t offset{0}; offset <= SEARCH_EPOCHS; ++offset) {
        if (*target_epoch < offset) break;
        const uint32_t epoch{*target_epoch - offset};
        const auto window{pq::BuildPaymentAuditCarrierWindow(config, epoch)};
        if (window && window->end_height_exclusive > 0 &&
            static_cast<int64_t>(window->end_height_exclusive) <=
                static_cast<int64_t>(target_height) + 1) {
            return epoch;
        }
    }
    return std::nullopt;
}

uint256 CatchupValidationDomainToken(
    const ChainstateManager& chainman,
    const pq::ChainLockFinalityStoreConfig& config,
    const uint256& marker_token)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto& anchor{config.btcc_receipt_assumption_anchor};
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_CATCHUP_VALIDATION_DOMAIN_V1"}
           << anchor.height << anchor.block_hash << anchor.receipt_state
           << chainman.AssumedValidBlock()
           << chainman.IsSnapshotActive()
           << chainman.IsSnapshotValidated()
           << marker_token;
    return writer.GetHash();
}

uint256 CatchupHistoricalContextToken(
    const CBlockIndex& candidate,
    const ChainstateManager& chainman,
    const pq::ChainLockFinalityStoreConfig& config,
    const uint256& marker_token)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto indexed_state{IndexedBTCCReceiptState(candidate)};
    const auto& anchor{config.btcc_receipt_assumption_anchor};
    const auto& cl{config.chainlock_schedule};
    const auto& btcc{config.btcc_schedule};
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_CATCHUP_HISTORY_V1"}
           << candidate.nHeight << candidate.GetBlockHash()
           << candidate.nStatus << candidate.nChainTx
           << anchor.height << anchor.block_hash
           << anchor.receipt_state
           << cl.epoch_origin << cl.epoch_blocks << cl.chainlock_period
           << cl.sign_lag << cl.active_epochs
           << btcc.candidate_origin << btcc.candidate_period
           << btcc.nevm_injection_lag
           << chainman.AssumedValidBlock()
           << chainman.IsSnapshotActive()
           << chainman.IsSnapshotValidated()
           << marker_token
           << indexed_state.has_value();
    if (indexed_state) writer << *indexed_state;
    return writer.GetHash();
}

BTCCCatchupRangeStatus GetFullyValidatedBTCCCatchupRangeStatusImpl(
    const ChainstateManager& chainman,
    const CBlockIndex& candidate,
    const pq::BTCCReceiptAssumptionAnchor& anchor,
    HistoricalIndexValidationCache& cache,
    uint64_t provenance_revocation_revision,
    std::size_t block_budget =
        HistoricalIndexValidationCache::BLOCK_BUDGET)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!chainman.IsBaseBlockSyncComplete() ||
        (chainman.IsSnapshotActive() && !chainman.IsSnapshotValidated())) {
        return BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE;
    }
    // SYSCOIN: Equality is the pinned receipt boundary itself, not an
    // unvalidated earlier range. Its exact block hash and indexed receipt
    // state are still checked below; the caller separately requires the
    // marker token and all 801 signatures before reaching this disk proof.
    if (anchor.IsDisabled() || candidate.nHeight < anchor.height) {
        return BTCCCatchupRangeStatus::DEFINITIVE_INVALID;
    }
    const CBlockIndex* anchor_index{candidate.GetAncestor(anchor.height)};
    if (anchor_index == nullptr ||
        anchor_index->GetBlockHash() != anchor.block_hash) {
        return BTCCCatchupRangeStatus::DEFINITIVE_INVALID;
    }
    const auto indexed_anchor_state{IndexedBTCCReceiptState(*anchor_index)};
    if (!indexed_anchor_state ||
        *indexed_anchor_state != anchor.receipt_state) {
        return BTCCCatchupRangeStatus::DEFINITIVE_INVALID;
    }

    const uint256& assumed_hash{chainman.AssumedValidBlock()};
    if (!assumed_hash.IsNull()) {
        const CBlockIndex* assumed{
            chainman.m_blockman.LookupBlockIndex(assumed_hash)};
        if (assumed == nullptr || assumed->nHeight > anchor.height) {
            return BTCCCatchupRangeStatus::DEFINITIVE_INVALID;
        }
    }

    if (candidate.nHeight == anchor.height) {
        return BTCCCatchupRangeStatus::VALID;
    }
    const auto range_status{cache.Validate(
        candidate, anchor.height + 1,
        HistoricalIndexValidationMode::BTCC_COMPAT,
        provenance_revocation_revision, block_budget)};
    if (range_status == PaymentAuditContextStatus::INVALID) {
        return BTCCCatchupRangeStatus::DEFINITIVE_INVALID;
    }
    if (range_status != PaymentAuditContextStatus::READY) {
        // Background script/index validation and storage recovery can advance
        // without changing the candidate index token. Historical governance
        // is supplied only by the preverified 801-signature certificate.
        return BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE;
    }
    return BTCCCatchupRangeStatus::VALID;
}

const char* FinalityErrorString(pq::ChainLockFinalityError error)
{
    switch (error) {
    case pq::ChainLockFinalityError::NONE: return "none";
    case pq::ChainLockFinalityError::INVALID_CONFIG: return "invalid-config";
    case pq::ChainLockFinalityError::INVALID_CHAINLOCK: return "invalid-chainlock";
    case pq::ChainLockFinalityError::INELIGIBLE_HEIGHT: return "ineligible-height";
    case pq::ChainLockFinalityError::REJECTED_WITNESS: return "rejected-witness";
    case pq::ChainLockFinalityError::DUPLICATE_WITNESS: return "duplicate-witness";
    case pq::ChainLockFinalityError::DUPLICATE_LOGICAL: return "duplicate-logical";
    case pq::ChainLockFinalityError::STALE_HEIGHT: return "stale-height";
    case pq::ChainLockFinalityError::HEIGHT_CONFLICT: return "height-conflict";
    case pq::ChainLockFinalityError::PREDECESSOR_MISMATCH: return "predecessor-mismatch";
    case pq::ChainLockFinalityError::CONTEXT_CHANGED: return "context-changed";
    case pq::ChainLockFinalityError::UNKNOWN_BLOCK: return "unknown-block";
    case pq::ChainLockFinalityError::BLOCK_MISMATCH: return "block-mismatch";
    case pq::ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED: return "block-not-fully-validated";
    case pq::ChainLockFinalityError::NOT_PREDECESSOR_DESCENDANT: return "not-predecessor-descendant";
    case pq::ChainLockFinalityError::INVALID_BTCC_TRANSITION: return "invalid-btcc-transition";
    case pq::ChainLockFinalityError::INVALID_CONTEXT_TOKEN: return "invalid-context-token";
    case pq::ChainLockFinalityError::INVALID_SIGNATURES: return "invalid-signatures";
    case pq::ChainLockFinalityError::INVALID_PREPARATION_TOKEN: return "invalid-preparation-token";
    case pq::ChainLockFinalityError::PERSISTED_IMPORT_NOT_EMPTY: return "persisted-import-not-empty";
    case pq::ChainLockFinalityError::PERSISTENCE_FAILURE: return "persistence-failure";
    }
    return "unknown";
}

uint256 RosterRecoveryPrecommitToken(
    const uint256& genesis_hash,
    const pq::RosterRecoveryPrecommit& precommit)
{
    if (genesis_hash.IsNull() || !precommit.IsStructurallyValid()) {
        return {};
    }
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_ROSTER_RECOVERY_CAPABILITY_V1"}
           << genesis_hash << precommit;
    return writer.GetHash();
}

uint256 MutableSigningContextToken(
    const uint256& payment_audit_checkpoint_token,
    const uint256& roster_recovery_precommit_token)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_MUTABLE_SIGNING_CONTEXT_V1"}
           << payment_audit_checkpoint_token
           << roster_recovery_precommit_token;
    return writer.GetHash();
}

bool DoesStagedRosterSeedAuthorizeReady(
    const pq::RosterBeaconSeed& durable_seed,
    const pq::RosterBeaconSeed& ready_seed) noexcept
{
    return durable_seed.state == pq::RosterBeaconState::PENDING
        ? pq::IsExactRosterBeaconReveal(durable_seed, ready_seed)
        : durable_seed.IsReady() && durable_seed == ready_seed;
}

// A normal final certificate is authorized only by rosters inherited from
// the durable prior state. These facts reconstruct its signed transition;
// they are not local Bitcoin-policy results and must never authorize RESET or
// a local share. Full threshold verification is the authentication boundary.
std::optional<pq::ValidatedRosterBeaconAnchor>
ThresholdCertificateRosterBeaconAnchor(
    const pq::RosterBeaconSeed& seed) noexcept
{
    if (seed.state != pq::RosterBeaconState::PENDING ||
        !seed.IsStructurallyValid() || seed.anchor_btc_height < 0) {
        return std::nullopt;
    }
    return pq::ValidatedRosterBeaconAnchor{
        seed.anchor_cursor, seed.anchor_btc_height,
        seed.anchor_btc_height, true};
}

std::optional<pq::ValidatedRosterBeaconRange>
ThresholdCertificateRosterBeaconRange(
    const pq::RosterBeaconSeed& seed) noexcept
{
    const auto future_height{seed.FutureBTCHeight()};
    if (!seed.IsReady() || !future_height ||
        *future_height >
            std::numeric_limits<int32_t>::max() -
                static_cast<int32_t>(
                    pq::ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1)) {
        return std::nullopt;
    }
    return pq::ValidatedRosterBeaconRange{
        seed.anchor_cursor.btc_hash, seed.anchor_btc_height,
        seed.future_btc_hash, *future_height,
        *future_height + static_cast<int32_t>(
                             pq::ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1),
        true};
}

std::optional<uint32_t> LatestRosterRecoveryEpoch(
    uint32_t epoch) noexcept
{
    constexpr uint32_t FIRST{pq::ACTIVE_QUORUMS - 1};
    if (epoch < FIRST) return std::nullopt;
    return epoch - ((epoch - FIRST) % pq::ACTIVE_QUORUMS);
}

std::optional<pq::ChainLockSigningWindow> RecoverySigningWindowForTarget(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t target,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept
{
    const auto signing_height{pq::SigningHeightForTarget(schedule, target)};
    const auto next{pq::NextEligibleChainLockTargetHeight(
        schedule, durable_predecessor_height)};
    if (!signing_height || *signing_height > tip_height || !next ||
        target < *next) {
        return std::nullopt;
    }
    if (target == *next) {
        return pq::ChainLockSigningWindow{
            target, durable_predecessor_height};
    }
    const int64_t declared{
        static_cast<int64_t>(target) - schedule.chainlock_period};
    if (declared < 0 ||
        declared > std::numeric_limits<int32_t>::max() ||
        !pq::IsEligibleChainLockTarget(
            schedule, static_cast<int32_t>(declared))) {
        return std::nullopt;
    }
    return pq::ChainLockSigningWindow{
        target, static_cast<int32_t>(declared)};
}

std::optional<pq::ChainLockSigningWindow> StagedRecoverySigningWindowImpl(
    const pq::ChainLockScheduleConfig& schedule,
    const pq::BTCCScheduleConfig& btcc,
    const pq::RosterRecoveryPrecommit& precommit,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept
{
    if (!precommit.IsStructurallyValid()) return std::nullopt;
    const int32_t target{
        precommit.pending_seed.anchor_cursor.sys_height};
    const auto first_target{pq::NextEligibleChainLockTargetHeight(
        schedule, durable_predecessor_height)};
    if (!first_target || target != *first_target) {
        return std::nullopt;
    }
    const auto canonical{pq::CanonicalRosterRecoveryTargetHeight(
        schedule, btcc, precommit.pending_seed.epoch)};
    if (!canonical || *canonical != target) return std::nullopt;
    return RecoverySigningWindowForTarget(
        schedule, target, durable_predecessor_height, tip_height);
}

} // namespace

std::optional<pq::ChainLockSigningWindow> StagedRecoverySigningWindow(
    const pq::ChainLockScheduleConfig& chainlock,
    const pq::BTCCScheduleConfig& btcc,
    const pq::RosterRecoveryPrecommit& precommit,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept
{
    return StagedRecoverySigningWindowImpl(
        chainlock, btcc, precommit,
        durable_predecessor_height, tip_height);
}

CChainLocksHandler* chainLocksHandler{nullptr};

PaymentAuditContextStatus HistoricalIndexValidationCache::Validate(
    const CBlockIndex& last,
    int32_t first_height,
    HistoricalIndexValidationMode mode,
    uint64_t provenance_revocation_revision,
    std::size_t block_budget,
    std::size_t* examined_blocks)
{
    AssertLockHeld(cs_main);
    if (examined_blocks != nullptr) *examined_blocks = 0;
    if (first_height < 0 || last.nHeight < first_height ||
        last.GetBlockHash().IsNull()) {
        return PaymentAuditContextStatus::INVALID;
    }
    if (block_budget == 0) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }

    const auto classify = [&](const CBlockIndex& index)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (index.nStatus & BLOCK_FAILED_MASK) {
            return PaymentAuditContextStatus::INVALID;
        }
        const bool provenance{
            mode == HistoricalIndexValidationMode::BTCC_COMPAT
                ? HasBTCCIndexProvenance(index)
                : HasFullReceiptIndexProvenance(index)};
        if (index.IsAssumedValid() ||
            !index.IsValid(BLOCK_VALID_SCRIPTS) || !provenance ||
            (mode == HistoricalIndexValidationMode::FULL_FINALITY &&
             CSuperblock::IsValidBlockHeight(index.nHeight) &&
             !(index.nStatus & BLOCK_GOVERNANCE_VALIDATED))) {
            return PaymentAuditContextStatus::LOCAL_ERROR;
        }
        return PaymentAuditContextStatus::READY;
    };

    const uint256 last_hash{last.GetBlockHash()};
    Entry* entry{nullptr};
    for (auto& candidate : m_entries) {
        if (candidate.occupied && candidate.mode == mode &&
            candidate.provenance_revocation_revision ==
                provenance_revocation_revision &&
            candidate.last_height == last.nHeight &&
            candidate.last_hash == last_hash &&
            candidate.first_height == first_height) {
            candidate.recently_used = true;
            entry = &candidate;
            break;
        }
    }
    if (entry == nullptr) {
        std::optional<std::size_t> victim;
        for (std::size_t index{0}; index < m_entries.size(); ++index) {
            if (!m_entries[index].occupied) {
                victim = index;
                break;
            }
        }
        while (!victim) {
            const std::size_t index{m_clock};
            m_clock = (m_clock + 1) % m_entries.size();
            if (!m_entries[index].recently_used) {
                victim = index;
            } else {
                m_entries[index].recently_used = false;
            }
        }
        entry = &m_entries[*victim];
        *entry = Entry{};
        entry->occupied = true;
        entry->recently_used = true;
        entry->mode = mode;
        entry->provenance_revocation_revision =
            provenance_revocation_revision;
        entry->last_height = last.nHeight;
        entry->last_hash = last_hash;
        entry->first_height = first_height;
        entry->next_height = last.nHeight;
    }

    if (entry->next_height < first_height) {
        return classify(last);
    }
    if (entry->next_height > last.nHeight) {
        entry->next_height = last.nHeight;
    }
    const CBlockIndex* walk{last.GetAncestor(entry->next_height)};
    for (std::size_t examined{0};
         walk != nullptr && walk->nHeight >= first_height &&
         examined < block_budget;
         ++examined) {
        if (examined_blocks != nullptr) ++*examined_blocks;
        const auto status{classify(*walk)};
        if (status != PaymentAuditContextStatus::READY) return status;
        entry->next_height = walk->nHeight - 1;
        walk = walk->pprev;
    }
    return entry->next_height < first_height
        ? PaymentAuditContextStatus::READY
        : PaymentAuditContextStatus::LOCAL_ERROR;
}

BoundedActiveRangePlan BoundedActiveRangeFrontier::Plan(
    const CChain& active_chain,
    const CBlockIndex& active_tip,
    int32_t floor_height,
    const uint256& floor_hash,
    const uint256& source_token,
    std::size_t block_budget)
{
    AssertLockHeld(cs_main);
    m_plan_pending = false;
    if (source_token.IsNull() || block_budget == 0 || floor_height < -1 ||
        active_tip.nHeight < floor_height ||
        active_chain[active_tip.nHeight] != &active_tip ||
        (floor_height < 0) != floor_hash.IsNull()) {
        return {};
    }
    const CBlockIndex* floor{
        floor_height < 0 ? nullptr : active_chain[floor_height]};
    if (floor_height >= 0 &&
        (floor == nullptr || floor->GetBlockHash() != floor_hash)) {
        return {};
    }

    bool reset{!m_initialized || m_source_token != source_token ||
               m_floor_height != floor_height ||
               m_floor_hash != floor_hash ||
               m_validated_through_height < floor_height};
    if (!reset) {
        const CBlockIndex* through{
            m_validated_through_height < 0
                ? nullptr
                : active_chain[m_validated_through_height]};
        reset = (m_validated_through_height < 0) !=
                    m_validated_through_hash.IsNull() ||
                (m_validated_through_height >= 0 &&
                 (through == nullptr ||
                  through->GetBlockHash() !=
                      m_validated_through_hash));
    }
    if (reset) {
        m_initialized = true;
        m_source_token = source_token;
        m_floor_height = floor_height;
        m_floor_hash = floor_hash;
        m_validated_through_height = floor_height;
        m_validated_through_hash = floor_hash;
    }
    if (m_validated_through_height >= active_tip.nHeight) {
        return {BoundedActiveRangeStatus::COMPLETE, -1, -1, reset};
    }

    const int64_t first{
        static_cast<int64_t>(m_validated_through_height) + 1};
    const uint64_t remaining{
        static_cast<uint64_t>(active_tip.nHeight - first) + 1};
    const uint64_t span{std::min<uint64_t>(block_budget, remaining)};
    const int64_t last{first + static_cast<int64_t>(span) - 1};
    if (first < 0 || last > std::numeric_limits<int32_t>::max()) {
        return {};
    }
    m_plan_pending = true;
    m_planned_first = static_cast<int32_t>(first);
    m_planned_last = static_cast<int32_t>(last);
    return {BoundedActiveRangeStatus::WORK,
            m_planned_first, m_planned_last, reset};
}

bool BoundedActiveRangeFrontier::CommitThrough(
    const CChain& active_chain,
    int32_t through_height)
{
    AssertLockHeld(cs_main);
    if (!m_plan_pending || through_height < m_planned_first - 1 ||
        through_height > m_planned_last) {
        return false;
    }
    const CBlockIndex* through{
        through_height < 0 ? nullptr : active_chain[through_height]};
    if ((through_height < 0) != (through == nullptr) ||
        (through != nullptr && through->nHeight != through_height)) {
        return false;
    }
    m_validated_through_height = through_height;
    m_validated_through_hash =
        through == nullptr ? uint256{} : through->GetBlockHash();
    m_plan_pending = false;
    return true;
}

bool BoundedActiveRangeFrontier::IsComplete(
    const CBlockIndex& active_tip) const noexcept
{
    AssertLockHeld(cs_main);
    return m_initialized && !m_plan_pending &&
           m_validated_through_height == active_tip.nHeight &&
           m_validated_through_hash == active_tip.GetBlockHash();
}

bool PaymentAuditCandidateMetadataSnapshot::IsStructurallyValid() const noexcept
{
    if (candidate_revision == 0 ||
        ordered_candidates.size() >
            pq::PaymentAuditStore::MAX_LIVE_CANDIDATES + 1) {
        return false;
    }
    for (std::size_t index{0}; index < ordered_candidates.size(); ++index) {
        const auto& candidate{ordered_candidates[index]};
        if (!candidate.statement.IsStructurallyValid() ||
            candidate.statement.commitment.seed.epoch != epoch ||
            candidate.logical_id.IsNull() || candidate.witness_id.IsNull() ||
            candidate.commitment_hash.IsNull() ||
            candidate.result_hash.IsNull()) {
            return false;
        }
        const auto& valid_members{
            candidate.statement.commitment.subject_valid_members};
        for (std::size_t byte{0}; byte < candidate.online_members.size();
             ++byte) {
            if ((candidate.online_members[byte] &
                 static_cast<uint8_t>(~valid_members[byte])) != 0) {
                return false;
            }
        }
        for (std::size_t prior{0}; prior < index; ++prior) {
            if (ordered_candidates[prior].witness_id ==
                candidate.witness_id) {
                return false;
            }
        }
    }
    return true;
}

bool PaymentAuditCandidateMetadataSnapshot::ContainsExactStatement(
    const pq::PaymentAuditStatement& statement) const noexcept
{
    return statement.IsStructurallyValid() &&
           std::any_of(
               ordered_candidates.begin(), ordered_candidates.end(),
               [&](const auto& candidate) {
                   return candidate.statement == statement;
               });
}

PaymentAuditCandidateMetadataSnapshotPtr
PaymentAuditCandidateMetadataCache::Get(const Key& key) const
{
    LOCK(m_mutex);
    for (auto& entry : m_entries) {
        if (entry.occupied && entry.key == key) {
            entry.recently_used = true;
            ++m_hits;
            return entry.snapshot;
        }
    }
    return {};
}

PaymentAuditCandidateMetadataSnapshotPtr
PaymentAuditCandidateMetadataCache::Publish(
    const Key& key, PaymentAuditCandidateMetadataSnapshot snapshot)
{
    if (key.candidate_revision == 0 || key.epoch != snapshot.epoch ||
        key.candidate_revision != snapshot.candidate_revision ||
        !snapshot.IsStructurallyValid()) {
        return {};
    }

    LOCK(m_mutex);
    ++m_builds;
    for (auto& entry : m_entries) {
        if (!entry.occupied || entry.key != key) continue;
        entry.recently_used = true;
        if (!entry.snapshot || *entry.snapshot != snapshot) {
            ++m_conflicts;
            return {};
        }
        return entry.snapshot;
    }

    std::optional<std::size_t> victim;
    for (std::size_t index{0}; index < m_entries.size(); ++index) {
        if (!m_entries[index].occupied) {
            victim = index;
            break;
        }
    }
    while (!victim) {
        const std::size_t index{m_clock};
        m_clock = (m_clock + 1) % m_entries.size();
        auto& candidate{m_entries[index]};
        if (!candidate.recently_used) {
            victim = index;
        } else {
            candidate.recently_used = false;
        }
    }

    auto& entry{m_entries[*victim]};
    entry.key = key;
    entry.snapshot =
        std::make_shared<const PaymentAuditCandidateMetadataSnapshot>(
            std::move(snapshot));
    entry.occupied = true;
    entry.recently_used = true;
    return entry.snapshot;
}

PaymentAuditCandidateMetadataSnapshotPtr
PaymentAuditCandidateMetadataCache::GetOrBuild(
    const pq::PaymentAuditStore& store,
    const uint256& genesis_hash,
    uint32_t epoch)
{
    if (genesis_hash.IsNull()) return {};
    const auto observed_revision{store.ObserveCandidateRevision()};
    if (!observed_revision || *observed_revision == 0) return {};
    const Key observed_key{epoch, *observed_revision};
    if (const auto cached{Get(observed_key)}) {
        return store.IsCandidateRevisionCurrent(*observed_revision)
            ? cached
            : PaymentAuditCandidateMetadataSnapshotPtr{};
    }

    LOCK(m_build_mutex);
    const auto current_revision{store.ObserveCandidateRevision()};
    if (!current_revision || *current_revision == 0) return {};
    Key key{epoch, *current_revision};
    if (const auto cached{Get(key)}) {
        return store.IsCandidateRevisionCurrent(*current_revision)
            ? cached
            : PaymentAuditCandidateMetadataSnapshotPtr{};
    }

    const auto source{store.GetEpochCandidateSnapshot(epoch)};
    if (!source || source->epoch != epoch || source->revision == 0) return {};
    key.candidate_revision = source->revision;
    if (const auto cached{Get(key)}) {
        return store.IsCandidateRevisionCurrent(source->revision)
            ? cached
            : PaymentAuditCandidateMetadataSnapshotPtr{};
    }

    PaymentAuditCandidateMetadataSnapshot derived{
        source->revision, source->epoch, {}};
    derived.ordered_candidates.reserve(source->ordered_candidates.size());
    for (const auto& source_candidate : source->ordered_candidates) {
        const auto& audit{source_candidate.audit};
        if (source_candidate.logical_id.IsNull() ||
            source_candidate.witness_id.IsNull() ||
            audit.statement.commitment.seed.epoch != epoch) {
            return {};
        }
        const auto classification{pq::ClassifyPaymentAuditReports(audit)};
        if (!classification) return {};
        const uint256 commitment_hash{pq::GetPaymentAuditCommitmentHash(
            genesis_hash, audit.statement.commitment)};
        const uint256 result_hash{pq::GetPaymentAuditResultHash(
            genesis_hash, audit, *classification)};
        if (commitment_hash.IsNull() || result_hash.IsNull()) return {};
        derived.ordered_candidates.push_back(
            PaymentAuditCandidateMetadata{
                audit.statement, source_candidate.logical_id,
                source_candidate.witness_id, commitment_hash, result_hash,
                classification->online_members});
    }
    if (!derived.IsStructurallyValid() ||
        !store.IsCandidateRevisionCurrent(source->revision)) {
        return {};
    }
    const auto published{Publish(key, std::move(derived))};
    if (!published ||
        !store.IsCandidateRevisionCurrent(source->revision)) {
        return {};
    }
    return published;
}

void PaymentAuditCandidateMetadataCache::Clear()
{
    LOCK(m_build_mutex);
    LOCK(m_mutex);
    m_entries = {};
    m_clock = 0;
}

PaymentAuditCandidateMetadataCache::Stats
PaymentAuditCandidateMetadataCache::StatsForTesting() const
{
    LOCK(m_mutex);
    return Stats{
        static_cast<std::size_t>(std::count_if(
            m_entries.begin(), m_entries.end(),
            [](const Entry& entry) { return entry.occupied; })),
        m_hits,
        m_builds,
        m_conflicts};
}

std::optional<pq::PaymentAuditReceipt> PaymentAuditReceiptCache::Get(
    const Key& key) const
{
    LOCK(m_mutex);
    for (auto& entry : m_entries) {
        if (entry.occupied && entry.key == key) {
            entry.recently_used = true;
            ++m_hits;
            return entry.receipt;
        }
    }
    return std::nullopt;
}

std::optional<pq::PaymentAuditReceipt> PaymentAuditReceiptCache::Publish(
    const Key& key, const pq::PaymentAuditReceipt& receipt)
{
    if (receipt.IsNull() || !receipt.IsStructurallyValid()) {
        return std::nullopt;
    }

    LOCK(m_mutex);
    ++m_builds;
    for (auto& entry : m_entries) {
        if (!entry.occupied || entry.key != key) continue;
        entry.recently_used = true;
        if (entry.receipt != receipt) {
            ++m_conflicts;
            return std::nullopt;
        }
        return entry.receipt;
    }

    std::optional<std::size_t> victim;
    for (std::size_t index{0}; index < m_entries.size(); ++index) {
        if (!m_entries[index].occupied) {
            victim = index;
            break;
        }
    }
    while (!victim) {
        const std::size_t index{m_clock};
        m_clock = (m_clock + 1) % m_entries.size();
        auto& candidate{m_entries[index]};
        if (!candidate.recently_used) {
            victim = index;
        } else {
            candidate.recently_used = false;
        }
    }

    auto& entry{m_entries[*victim]};
    entry.key = key;
    entry.receipt = receipt;
    entry.occupied = true;
    entry.recently_used = true;
    return entry.receipt;
}

void PaymentAuditReceiptCache::Clear()
{
    LOCK(m_mutex);
    m_entries = {};
    m_clock = 0;
}

PaymentAuditReceiptCache::Stats
PaymentAuditReceiptCache::StatsForTesting() const
{
    LOCK(m_mutex);
    return Stats{
        static_cast<std::size_t>(std::count_if(
            m_entries.begin(), m_entries.end(),
            [](const Entry& entry) { return entry.occupied; })),
        m_hits,
        m_builds,
        m_conflicts};
}

class VerifiedPaymentAuditReceiptTransition final {
private:
    VerifiedPaymentAuditReceiptTransition(
        pq::PaymentAuditReceipt receipt,
        pq::PaymentAuditStatement statement,
        uint256 carrier_parent_hash,
        int32_t carrier_parent_height,
        uint256 parent_probation_state_hash,
        uint64_t archive_revision,
        uint64_t roster_source_generation,
        uint64_t probation_state_view_generation,
        int32_t reconstruction_floor,
        uint8_t authorization_mask,
        pq::PQPaymentProbationTransitionView transition);

    const pq::PaymentAuditReceipt m_receipt;
    const pq::PaymentAuditStatement m_statement;
    const uint256 m_carrier_parent_hash;
    const int32_t m_carrier_parent_height;
    const uint256 m_parent_probation_state_hash;
    const uint64_t m_archive_revision;
    const uint64_t m_roster_source_generation;
    const uint64_t m_probation_state_view_generation;
    const int32_t m_reconstruction_floor;
    const uint8_t m_authorization_mask;
    const pq::PQPaymentProbationTransitionView m_transition;

    friend class CChainLocksHandler;
    friend class VerifiedPaymentAuditReceiptTransitionCache;
    friend const pq::PQPaymentProbationTransitionView*
    GetVerifiedPaymentAuditReceiptTransition(
        const VerifiedPaymentAuditReceiptTransitionPtr&) noexcept;
};

const pq::PQPaymentProbationTransitionView*
GetVerifiedPaymentAuditReceiptTransition(
    const VerifiedPaymentAuditReceiptTransitionPtr& verified) noexcept
{
    return verified ? &verified->m_transition : nullptr;
}

VerifiedPaymentAuditReceiptTransition::
    VerifiedPaymentAuditReceiptTransition(
        pq::PaymentAuditReceipt receipt,
        pq::PaymentAuditStatement statement,
        uint256 carrier_parent_hash,
        int32_t carrier_parent_height,
        uint256 parent_probation_state_hash,
        uint64_t archive_revision,
        uint64_t roster_source_generation,
        uint64_t probation_state_view_generation,
        int32_t reconstruction_floor,
        uint8_t authorization_mask,
        pq::PQPaymentProbationTransitionView transition)
    : m_receipt{std::move(receipt)},
      m_statement{std::move(statement)},
      m_carrier_parent_hash{std::move(carrier_parent_hash)},
      m_carrier_parent_height{carrier_parent_height},
      m_parent_probation_state_hash{std::move(parent_probation_state_hash)},
      m_archive_revision{archive_revision},
      m_roster_source_generation{roster_source_generation},
      m_probation_state_view_generation{probation_state_view_generation},
      m_reconstruction_floor{reconstruction_floor},
      m_authorization_mask{authorization_mask},
      m_transition{std::move(transition)}
{
}

class VerifiedPaymentAuditReceiptTransitionCache final {
public:
    static constexpr std::size_t CAPACITY{8};

    struct Key {
        uint256 carrier_parent_hash;
        int32_t carrier_parent_height{-1};
        uint256 parent_probation_state_hash;
        int32_t carrier_height{-1};
        pq::PaymentAuditReceipt receipt;
        uint64_t archive_revision{0};
        uint64_t roster_source_generation{0};
        uint64_t probation_state_view_generation{0};

        friend bool operator==(const Key&, const Key&) = default;
    };

    [[nodiscard]] VerifiedPaymentAuditReceiptTransitionPtr Get(
        const Key& key) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.transition && entry.key == key) {
                entry.recently_used = true;
                return entry.transition;
            }
        }
        return nullptr;
    }

    [[nodiscard]] VerifiedPaymentAuditReceiptTransitionPtr Publish(
        const Key& key,
        VerifiedPaymentAuditReceiptTransitionPtr transition)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        if (!transition || !transition->m_transition.IsValid() ||
            transition->m_transition.ProvenanceGeneration() !=
                key.probation_state_view_generation ||
            transition->m_receipt != key.receipt ||
            transition->m_carrier_parent_hash != key.carrier_parent_hash ||
            transition->m_carrier_parent_height != key.carrier_parent_height ||
            transition->m_parent_probation_state_hash !=
                key.parent_probation_state_hash ||
            transition->m_receipt.carrier_height != key.carrier_height ||
            transition->m_archive_revision != key.archive_revision ||
            transition->m_roster_source_generation !=
                key.roster_source_generation ||
            transition->m_probation_state_view_generation !=
                key.probation_state_view_generation) {
            return nullptr;
        }

        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (!entry.transition || entry.key != key) continue;
            entry.recently_used = true;
            return entry.transition;
        }

        std::optional<std::size_t> victim;
        for (std::size_t index{0}; index < m_entries.size(); ++index) {
            if (!m_entries[index].transition) {
                victim = index;
                break;
            }
        }
        while (!victim) {
            const std::size_t index{m_clock};
            m_clock = (m_clock + 1) % m_entries.size();
            auto& candidate{m_entries[index]};
            if (!candidate.recently_used) {
                victim = index;
            } else {
                candidate.recently_used = false;
            }
        }

        auto& entry{m_entries[*victim]};
        entry.key = key;
        entry.transition = std::move(transition);
        entry.recently_used = true;
        return entry.transition;
    }

    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_entries = {};
        m_clock = 0;
    }

private:
    struct Entry {
        Key key;
        VerifiedPaymentAuditReceiptTransitionPtr transition;
        bool recently_used{false};
    };

    mutable Mutex m_mutex;
    mutable std::array<Entry, CAPACITY> m_entries GUARDED_BY(m_mutex);
    mutable std::size_t m_clock GUARDED_BY(m_mutex){0};
};

bool IsCurrentChainLockCatchupCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept
{
    return IsLiveChainLockCandidateAdmissible(
        schedule, active_tip, candidate);
}

bool IsCurrentChainLockCandidateBlockedByPreseal(
    bool candidate_is_active,
    bool current_round_candidate,
    bool has_btcc_preseal,
    bool has_payment_audit_preseal) noexcept
{
    return !candidate_is_active && current_round_candidate &&
           (has_btcc_preseal || has_payment_audit_preseal);
}

bool IsHistoricalLocalPredecessorCursorCompatible(
    bool current_round_candidate,
    bool declared_predecessor_is_local,
    const pq::BTCCursor& declared_cursor,
    const pq::BTCCursor& local_cursor) noexcept
{
    return current_round_candidate || !declared_predecessor_is_local ||
           declared_cursor == local_cursor;
}

bool IsLiveChainLockCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept
{
    const auto latest{pq::LatestEligibleChainLockTargetHeight(
        schedule, active_tip.nHeight)};
    if (!latest || candidate.nHeight != *latest ||
        candidate.nHeight < static_cast<int32_t>(schedule.sign_lag)) {
        return false;
    }

    // Finality may choose between branches visible during this signing round,
    // but a delayed signature must not reopen an older round or cross its
    // chain-derived boundary after peers have moved on.
    const int32_t anchor_height{
        candidate.nHeight - static_cast<int32_t>(schedule.sign_lag)};
    const CBlockIndex* active_anchor{active_tip.GetAncestor(anchor_height)};
    const CBlockIndex* candidate_anchor{candidate.GetAncestor(anchor_height)};
    return active_anchor != nullptr && candidate_anchor == active_anchor;
}

namespace {

std::optional<pq::BTCCCursorReconciliationProof>
BuildCandidateBoundNullCarrierReconciliation(
    const uint256& genesis_hash,
    const pq::ChainLockFinalityStoreConfig& config,
    const CBlockIndex& target,
    const pq::BTCCReceiptState& target_receipt_state,
    const pq::FinalChainLockRecordMetadata& durable_best)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (!config.IsValid() ||
        !durable_best.IsInternallyConsistent(genesis_hash)) {
        return std::nullopt;
    }
    const auto& durable{durable_best.statement};
    const auto& skipped{durable.accepted_btcc_cursor};
    const auto& authenticated{durable.btcc_receipt_state.cursor};
    if (skipped.IsNull() ||
        !pq::IsBTCCCandidateHeight(config.btcc_schedule,
                                   skipped.sys_height) ||
        (!authenticated.IsNull() &&
         authenticated.sys_height >= skipped.sys_height) ||
        target_receipt_state != durable.btcc_receipt_state ||
        pq::IsDurableBTCCursorMonotonic(
            skipped, target_receipt_state.cursor)) {
        return std::nullopt;
    }

    const int64_t carrier_height{
        static_cast<int64_t>(skipped.sys_height) +
        config.btcc_schedule.nevm_injection_lag};
    if (carrier_height > std::numeric_limits<int32_t>::max() ||
        target.nHeight < carrier_height) {
        return std::nullopt;
    }
    const CBlockIndex* best_index{target.GetAncestor(durable.height)};
    const CBlockIndex* source{target.GetAncestor(skipped.sys_height)};
    const CBlockIndex* carrier{
        target.GetAncestor(static_cast<int32_t>(carrier_height))};
    if (best_index == nullptr || source == nullptr || carrier == nullptr ||
        carrier->pprev == nullptr ||
        best_index->GetBlockHash() != durable.block_hash ||
        source->GetBlockHash() != skipped.sys_hash ||
        source->btcpPrevCommitment != skipped.btc_hash ||
        carrier->GetAncestor(skipped.sys_height) != source ||
        ((best_index->nStatus | source->nStatus | carrier->nStatus |
          carrier->pprev->nStatus) &
         BLOCK_FAILED_MASK) ||
        best_index->IsAssumedValid() || source->IsAssumedValid() ||
        carrier->IsAssumedValid() ||
        carrier->pprev->IsAssumedValid() ||
        !best_index->IsValid(BLOCK_VALID_SCRIPTS) ||
        !source->IsValid(BLOCK_VALID_SCRIPTS) ||
        !carrier->IsValid(BLOCK_VALID_SCRIPTS) ||
        !carrier->pprev->IsValid(BLOCK_VALID_SCRIPTS) ||
        !HasFullReceiptIndexProvenance(*best_index) ||
        !HasFullReceiptIndexProvenance(*source) ||
        !HasFullReceiptIndexProvenance(*carrier) ||
        !HasFullReceiptIndexProvenance(*carrier->pprev)) {
        return std::nullopt;
    }
    pq::BTCCValidationError transition_error{
        pq::BTCCValidationError::NONE};
    if (!pq::ValidateBTCCursorTransition(
            config.btcc_schedule, *best_index,
            durable.previous_btcc_cursor, durable.accepted_btcc_cursor,
            durable.btcc_advance, &transition_error)) {
        return std::nullopt;
    }
    const auto best_state{IndexedBTCCReceiptState(*best_index)};
    const auto previous_state{IndexedBTCCReceiptState(*carrier->pprev)};
    const auto current_state{IndexedBTCCReceiptState(*carrier)};
    if (!best_state || !previous_state || !current_state ||
        *best_state != durable.btcc_receipt_state ||
        *previous_state != durable.btcc_receipt_state ||
        *current_state != *previous_state) {
        return std::nullopt;
    }
    const auto receipt{pq::ReconstructBTCCReceipt(
        genesis_hash, config.chainlock_schedule, config.btcc_schedule,
        *carrier, *previous_state, *current_state,
        carrier->pqBTCCReceiptLogicalId)};
    if (!receipt || !receipt->IsNull()) return std::nullopt;

    pq::BTCCCursorReconciliationProof proof;
    proof.carrier_height = carrier->nHeight;
    proof.carrier_hash = carrier->GetBlockHash();
    proof.carrier_parent_hash = carrier->pprev->GetBlockHash();
    proof.skipped_cursor = skipped;
    proof.previous_receipt_state = *previous_state;
    proof.current_receipt_state = *current_state;
    proof.receipt_logical_id = carrier->pqBTCCReceiptLogicalId;
    return proof.IsStructurallyValid()
        ? std::optional<pq::BTCCCursorReconciliationProof>{proof}
        : std::nullopt;
}

bool MatchesCurrentChainLockBTCCSelection(
    const CurrentChainLockBTCCSelection& canonical,
    const pq::ChainLockStatement& statement,
    const pq::BTCCursor& durable_cursor,
    std::optional<pq::BTCCCursorReconciliationProof>* reconciliation = nullptr)
{
    if (reconciliation != nullptr) reconciliation->reset();
    if (statement.previous_btcc_cursor != canonical.previous_cursor) {
        return false;
    }
    const bool exact_selection{
        statement.accepted_btcc_cursor == canonical.selected.cursor &&
        statement.btcc_advance == canonical.selected.advance};
    const bool policy_keep{
        canonical.selected.advance == pq::BTCCAdvance::ADVANCE &&
        statement.accepted_btcc_cursor == canonical.previous_cursor &&
        statement.btcc_advance == pq::BTCCAdvance::KEEP};
    if (!exact_selection && !policy_keep) return false;

    const bool cursor_regresses{!pq::IsDurableBTCCursorMonotonic(
        durable_cursor, statement.accepted_btcc_cursor)};
    if (cursor_regresses && !canonical.cursor_reconciliation) {
        return false;
    }
    if (cursor_regresses && reconciliation != nullptr) {
        *reconciliation = canonical.cursor_reconciliation;
    }
    return true;
}

} // namespace

std::optional<CurrentChainLockBTCCSelection>
SelectCurrentChainLockBTCC(
    const uint256& genesis_hash,
    const pq::ChainLockFinalityStoreConfig& config,
    const CBlockIndex& target,
    const pq::FinalChainLockRecordMetadata* durable_best)
{
    AssertLockHeld(cs_main);
    const pq::BTCCursor durable_cursor{
        durable_best ? durable_best->statement.accepted_btcc_cursor
                     : pq::BTCCursor{}};
    if (!config.IsValid() || !durable_cursor.IsStructurallyValid()) {
        return std::nullopt;
    }
    const auto indexed_receipt_state{IndexedBTCCReceiptState(target)};
    if (!indexed_receipt_state) return std::nullopt;

    if (durable_best != nullptr) {
        if (!durable_best->IsInternallyConsistent(genesis_hash)) {
            return std::nullopt;
        }
        const CBlockIndex* best_index{
            target.GetAncestor(durable_best->statement.height)};
        const auto best_state{best_index == nullptr
            ? std::optional<pq::BTCCReceiptState>{}
            : IndexedBTCCReceiptState(*best_index)};
        if (best_index == nullptr ||
            best_index->GetBlockHash() !=
                durable_best->statement.block_hash ||
            !best_state ||
            *best_state != durable_best->statement.btcc_receipt_state) {
            return std::nullopt;
        }
    }

    const auto indexed_selection{pq::SelectBTCCForChainLock(
        config.btcc_schedule, target, indexed_receipt_state->cursor)};
    if (!indexed_selection) return std::nullopt;
    const bool indexed_cursor_is_monotonic{
        pq::IsDurableBTCCursorMonotonic(
            durable_cursor, indexed_receipt_state->cursor)};
    if (indexed_cursor_is_monotonic) {
        return CurrentChainLockBTCCSelection{
            indexed_receipt_state->cursor, *indexed_selection, std::nullopt};
    }

    if (!durable_cursor.IsNull() &&
        !indexed_receipt_state->cursor.IsNull() &&
        durable_cursor.sys_height ==
            indexed_receipt_state->cursor.sys_height) {
        return std::nullopt;
    }
    if (durable_best == nullptr ||
        *indexed_receipt_state !=
            durable_best->statement.btcc_receipt_state) {
        return std::nullopt;
    }
    const int64_t carrier_height{
        static_cast<int64_t>(durable_cursor.sys_height) +
        config.btcc_schedule.nevm_injection_lag};
    if (carrier_height > std::numeric_limits<int32_t>::max()) {
        return std::nullopt;
    }
    if (target.nHeight >= carrier_height) {
        const auto proof{BuildCandidateBoundNullCarrierReconciliation(
            genesis_hash, config, target, *indexed_receipt_state,
            *durable_best)};
        if (!proof) return std::nullopt;
        return CurrentChainLockBTCCSelection{
            indexed_receipt_state->cursor, *indexed_selection, proof};
    }

    const auto durable_selection{pq::SelectBTCCForChainLock(
        config.btcc_schedule, target, durable_cursor)};
    if (!durable_selection) return std::nullopt;
    return CurrentChainLockBTCCSelection{
        durable_cursor, *durable_selection, std::nullopt};
}

std::optional<std::vector<uint256>>
CollectChainstatePaymentProbationRoots(ChainstateManager& chainman)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> roots;
    std::string recovery_error;
    const auto recovery_indexes{
        chainman.GetAllRecoveryBlockIndexes(recovery_error)};
    if (!recovery_indexes) {
        LogPrintf("%s -- invalid chainstate recovery markers: %s\n",
                  __func__, recovery_error);
        return std::nullopt;
    }
    for (const CBlockIndex* pindex : *recovery_indexes) {
        const uint256& root{pindex->pqPaymentProbationStateHash};
        if (!root.IsNull() &&
            std::find(roots.begin(), roots.end(), root) == roots.end()) {
            roots.push_back(root);
        }
    }
    return roots;
}

bool HasSamePaymentAuditCheckpointBoundary(
    const pq::PaymentAuditStoreCheckpoint& left,
    const pq::PaymentAuditStoreCheckpoint& right) noexcept
{
    return left.IsStructurallyValid() && right.IsStructurallyValid() &&
           left.prune_through_epoch == right.prune_through_epoch &&
           left.covered_through_height == right.covered_through_height &&
           left.covered_through_hash == right.covered_through_hash &&
           left.authenticated_receipt_state ==
               right.authenticated_receipt_state &&
           left.authenticated_probation_state_hash ==
               right.authenticated_probation_state_hash;
}

bool ShouldRunPaymentAuditDurableGC(
    bool reuse_archive_checkpoint,
    bool probation_gc_complete) noexcept
{
    return !reuse_archive_checkpoint || !probation_gc_complete;
}

CChainLocksHandler::PaymentAuditGCMaintenancePlan
CChainLocksHandler::SelectPaymentAuditGCMaintenancePlan(
    const std::optional<pq::PaymentAuditStoreCheckpoint>& pending_archive,
    const std::optional<pq::PaymentAuditStoreCheckpoint>& pending_probation,
    std::span<const uint256> pending_probation_roots,
    const std::optional<pq::PaymentAuditStoreCheckpoint>& completed_archive,
    bool completed_probation) noexcept
{
    PaymentAuditGCMaintenancePlan plan;
    if (pending_archive) {
        if (pending_probation || !pending_archive->IsStructurallyValid()) {
            plan.phase = PaymentAuditGCMaintenancePhase::INVALID;
            return plan;
        }
        plan.phase = PaymentAuditGCMaintenancePhase::ARCHIVE;
        plan.checkpoint = *pending_archive;
        return plan;
    }
    if (pending_probation) {
        if (!pending_probation->IsStructurallyValid() ||
            !completed_archive ||
            !HasSamePaymentAuditCheckpointBoundary(
                *pending_probation, *completed_archive)) {
            plan.phase = PaymentAuditGCMaintenancePhase::INVALID;
            return plan;
        }
        plan.phase = PaymentAuditGCMaintenancePhase::PROBATION;
        plan.checkpoint = *pending_probation;
        plan.retained_probation_roots.assign(
            pending_probation_roots.begin(),
            pending_probation_roots.end());
        return plan;
    }
    if (completed_archive && !completed_probation) {
        if (!completed_archive->IsStructurallyValid()) {
            plan.phase = PaymentAuditGCMaintenancePhase::INVALID;
            return plan;
        }
        plan.phase = PaymentAuditGCMaintenancePhase::PROBATION;
        plan.checkpoint = *completed_archive;
        plan.derive_retained_probation_roots = true;
    }
    return plan;
}

BTCCCatchupRangeStatus GetFullyValidatedBTCCCatchupRangeStatus(
    const ChainstateManager& chainman,
    const CBlockIndex& candidate,
    const pq::BTCCReceiptAssumptionAnchor& anchor)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    HistoricalIndexValidationCache cache;
    return GetFullyValidatedBTCCCatchupRangeStatusImpl(
        chainman, candidate, anchor, cache,
        chainman.GetPQProvenanceRevocationRevision(),
        std::numeric_limits<std::size_t>::max());
}

bool ShouldRouteBTCCPresealReceiptToCatchup(
    bool marker_authorized_receipt,
    int32_t receipt_target_height,
    int32_t local_finality_height) noexcept
{
    return marker_authorized_receipt &&
           receipt_target_height > local_finality_height;
}

bool ShouldArchiveRequiredBTCCReceiptCertificate(
    bool exact_receipt_required,
    bool has_local_finality,
    int32_t receipt_target_height,
    int32_t local_finality_height) noexcept
{
    return exact_receipt_required && has_local_finality &&
           receipt_target_height < local_finality_height;
}

const pq::BTCCPresealMarker* SelectBTCCPresealRecomputeMarker(
    const pq::BTCCPresealState& state,
    const CBlockIndex& candidate) noexcept
{
    const pq::BTCCPresealMarker* first_marker{nullptr};
    const auto inspect = [&](const auto& marker) {
        if (!marker || marker->terminal_carrier_height > candidate.nHeight) {
            return;
        }
        const CBlockIndex* earliest{
            candidate.GetAncestor(marker->earliest_carrier_height)};
        const CBlockIndex* terminal{
            candidate.GetAncestor(marker->terminal_carrier_height)};
        if (earliest == nullptr || terminal == nullptr ||
            earliest->GetBlockHash() != marker->earliest_carrier_hash ||
            terminal->GetBlockHash() != marker->terminal_carrier_hash) {
            return;
        }
        if (first_marker == nullptr ||
            marker->earliest_carrier_height <
                first_marker->earliest_carrier_height) {
            first_marker = &*marker;
        }
    };
    inspect(state.active);
    inspect(state.prospective);
    return first_marker;
}

std::string CChainLockSig::ToString() const
{
    const uint256& genesis_hash{Params().GetConsensus().hashGenesisBlock};
    return strprintf(
        "CChainLockSig(PQ height=%d, blockHash=%s, logical=%s, witness=%s)",
        statement.height, statement.block_hash.ToString(),
        GetLogicalId(genesis_hash).ToString(), GetWitnessId(genesis_hash).ToString());
}

static bool IsInitialChainLockRosterSetAvailable(
    const pq::ChainLockScheduleConfig& schedule,
    const pq::BTCCScheduleConfig& btcc_schedule,
    uint32_t roster_snapshot_lag,
    int32_t predecessor_height) noexcept
{
    const auto last_bootstrap_base{
        pq::EpochBaseHeight(schedule, pq::ACTIVE_QUORUMS - 1)};
    if (!last_bootstrap_base || predecessor_height < *last_bootstrap_base ||
        predecessor_height == std::numeric_limits<int32_t>::max()) {
        return false;
    }

    std::optional<int32_t> first_target;
    for (int64_t height{static_cast<int64_t>(predecessor_height) + 1};
         height <= static_cast<int64_t>(predecessor_height) +
                       schedule.chainlock_period &&
         height <= std::numeric_limits<int32_t>::max();
         ++height) {
        if (pq::IsEligibleChainLockTarget(
                schedule, static_cast<int32_t>(height))) {
            first_target = static_cast<int32_t>(height);
            break;
        }
    }
    if (!first_target) return false;

    const auto first_epoch{
        pq::EpochForHeight(schedule, *first_target)};
    const auto canonical_target{first_epoch
        ? pq::CanonicalRosterRecoveryTargetHeight(
              schedule, btcc_schedule, *first_epoch)
        : std::optional<int32_t>{}};
    if (!canonical_target || *canonical_target != *first_target) {
        return false;
    }

    const auto active{pq::ActiveEpochsAtHeight(schedule, *first_target)};
    if (!active) return false;
    for (const auto& identity : *active) {
        const auto authorization_height{
            pq::RegistrationCutoffHeight(
                schedule, identity.epoch, roster_snapshot_lag)};
        if (!authorization_height ||
            *authorization_height > predecessor_height) {
            return false;
        }
    }
    return true;
}

std::optional<pq::ChainLockFinalityStoreConfig>
MakePQChainLockFinalityStoreConfig(const Consensus::Params& consensus)
{
    if (Consensus::CheckPQActivationConfiguration(consensus) !=
        Consensus::PQActivationResult::VALID) {
        return std::nullopt;
    }
    const int32_t predecessor_height{consensus.nPQActivationHeight - 1};
    pq::PQRegistryConfig registry_config;
    if (pq::GetPQRegistryConfig(consensus, registry_config) !=
        pq::PQRegistryDeploymentResult::VALID) {
        return std::nullopt;
    }
    const auto schedule{
        pq::MakeChainLockScheduleConfig(consensus.nPQChainLockEpochOrigin)};
    if (!schedule || *schedule != registry_config.schedule ||
        consensus.nPQRosterSnapshotLag <= 0 ||
        consensus.nPQBTCCCandidateOrigin == std::numeric_limits<int>::max() ||
        consensus.nPQBTCCCandidateOrigin <=
            predecessor_height ||
        consensus.nPQBTCCNEVMInjectionLag != static_cast<int>(pq::PQ_BTCC_NEVM_LAG)) {
        return std::nullopt;
    }

    pq::ChainLockFinalityStoreConfig config;
    config.chainlock_schedule = *schedule;
    config.btcc_schedule.candidate_origin = consensus.nPQBTCCCandidateOrigin;
    config.btcc_schedule.nevm_injection_lag =
        static_cast<uint32_t>(consensus.nPQBTCCNEVMInjectionLag);
    config.activation_predecessor_height = predecessor_height;
    if (!IsInitialChainLockRosterSetAvailable(
            *schedule, config.btcc_schedule,
            static_cast<uint32_t>(consensus.nPQRosterSnapshotLag),
            predecessor_height)) {
        return std::nullopt;
    }
    const bool receipt_anchor_disabled{
        consensus.nPQBTCCReceiptAnchorHeight ==
            std::numeric_limits<int>::max() &&
        consensus.hashPQBTCCReceiptAnchorBlock.IsNull() &&
        consensus.nPQBTCCReceiptAnchorCursorHeight == -1 &&
        consensus.hashPQBTCCReceiptAnchorCursorSysBlock.IsNull() &&
        consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.IsNull() &&
        consensus.hashPQBTCCReceiptAnchorState.IsNull()};
    // A deployed carrier schedule can create non-null receipts. Without a
    // release-pinned authenticated prefix, a fresh node can enter historical
    // preseal but can never satisfy CATCHUP after bounded cert retention.
    if (receipt_anchor_disabled ||
        consensus.nPQBTCCReceiptAnchorHeight < 0 ||
        consensus.nPQBTCCReceiptAnchorHeight ==
            std::numeric_limits<int>::max() ||
        (consensus.nDefaultAssumeValidHeight >= 0 &&
         (consensus.nDefaultAssumeValidHeight >=
              consensus.nPQActivationHeight ||
          consensus.nDefaultAssumeValidHeight >=
              consensus.nPQBTCCReceiptAnchorHeight))) {
        return std::nullopt;
    }
    config.btcc_receipt_assumption_anchor.height =
        consensus.nPQBTCCReceiptAnchorHeight;
    config.btcc_receipt_assumption_anchor.block_hash =
        consensus.hashPQBTCCReceiptAnchorBlock;
    config.btcc_receipt_assumption_anchor.receipt_state =
        pq::BTCCReceiptState{
            pq::BTCCursor{
                consensus.nPQBTCCReceiptAnchorCursorHeight,
                consensus.hashPQBTCCReceiptAnchorCursorSysBlock,
                consensus.hashPQBTCCReceiptAnchorCursorBTCBlock},
            consensus.hashPQBTCCReceiptAnchorState};
    if (!config.IsValid()) return std::nullopt;
    return config;
}

std::optional<pq::QuorumBuildConfig>
MakePQQuorumBuildConfig(const Consensus::Params& consensus)
{
    pq::PQRegistryConfig registry_config;
    if (pq::GetPQRegistryConfig(consensus, registry_config) !=
            pq::PQRegistryDeploymentResult::VALID ||
        consensus.nPQRosterSnapshotLag <= 0) {
        return std::nullopt;
    }
    pq::QuorumBuildConfig config{
        registry_config.schedule,
        static_cast<uint32_t>(consensus.nPQRosterSnapshotLag),
        registry_config.registration_cutoff_blocks,
        registry_config.future_horizon_epochs};
    if (!config.IsValid()) return std::nullopt;
    if (consensus.nPQBTCCNEVMInjectionLag < 0) return std::nullopt;
    const uint64_t current_catchup_lag{
        static_cast<uint64_t>(config.schedule.sign_lag)};
    const uint64_t historical_admission_lag{std::max<uint64_t>(
        static_cast<uint32_t>(consensus.nPQBTCCNEVMInjectionLag),
        current_catchup_lag)};
    const uint64_t preseal_snapshot_window{
        static_cast<uint64_t>(config.schedule.active_epochs) *
            config.schedule.epoch_blocks +
        config.roster_snapshot_lag_blocks +
        historical_admission_lag};
    // A first missing-certificate marker is created only at its receipt
    // carrier. Its complete four-roster snapshot set must still be present
    // in the ordinary DMN window so the durable replay floor can take over.
    if (preseal_snapshot_window >
        static_cast<uint64_t>(CDeterministicMNManager::LIST_CACHE_SIZE)) {
        return std::nullopt;
    }
    return config;
}

std::size_t GetPQChainLockVerifierThreads(unsigned int hardware_threads) noexcept
{
    if (hardware_threads <= 1) return 0;
    return std::min<std::size_t>(hardware_threads - 1,
                                 MAX_PQ_CHAINLOCK_VERIFY_THREADS);
}

bool IsPaymentAuditResponseBlockUsable(
    const CBlockIndex& response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return (!require_block_data ||
            (response.nStatus & BLOCK_HAVE_DATA) != 0) &&
           (response.nStatus & BLOCK_FAILED_MASK) == 0 &&
           !response.IsAssumedValid() &&
           response.IsValid(BLOCK_VALID_SCRIPTS);
}

PaymentAuditContextStatus ClassifyPaymentAuditReceiptCarrierContext(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier,
    const pq::PaymentAuditScheduleConfig& schedule)
{
    AssertLockHeld(cs_main);
    if (receipt.IsNull()) return PaymentAuditContextStatus::READY;
    if (!receipt.IsStructurallyValid() ||
        carrier.nHeight != receipt.carrier_height) {
        return PaymentAuditContextStatus::INVALID;
    }
    if (!schedule.IsValid()) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    const auto epoch_schedule{
        pq::BuildPaymentAuditEpochSchedule(schedule, receipt.epoch)};
    if (!epoch_schedule ||
        epoch_schedule->seal_height != receipt.seal_height ||
        receipt.carrier_height < epoch_schedule->carrier_start_height ||
        receipt.carrier_height >=
            epoch_schedule->carrier_end_height_exclusive ||
        carrier.pprev == nullptr) {
        return PaymentAuditContextStatus::INVALID;
    }
    const CBlockIndex* seal{carrier.GetAncestor(receipt.seal_height)};
    if (seal == nullptr) return PaymentAuditContextStatus::LOCAL_ERROR;
    return seal->GetBlockHash() == receipt.seal_block_hash
        ? PaymentAuditContextStatus::READY
        : PaymentAuditContextStatus::INVALID;
}

std::optional<pq::PaymentAuditReceipt>
ExtractDeferredPaymentAuditReceipt(
    const CBlock& carrier_block,
    const uint256& required_witness_id,
    const CBlockIndex& carrier,
    const CBlockIndex& best_candidate)
{
    AssertLockHeld(cs_main);
    if (required_witness_id.IsNull() || carrier.phashBlock == nullptr ||
        carrier.pprev == nullptr ||
        (carrier.nStatus & BLOCK_HAVE_DATA) == 0 ||
        (carrier.nStatus &
         (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) != 0 ||
        carrier.IsAssumedValid() ||
        !carrier.IsValid(BLOCK_VALID_TRANSACTIONS) ||
        best_candidate.nHeight < carrier.nHeight ||
        best_candidate.GetAncestor(carrier.nHeight) != &carrier ||
        (best_candidate.nStatus & BLOCK_HAVE_DATA) == 0 ||
        (best_candidate.nStatus &
         (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) != 0 ||
        best_candidate.IsAssumedValid() ||
        !best_candidate.IsValid(BLOCK_VALID_TRANSACTIONS) ||
        !best_candidate.HaveNumChainTxs() ||
        carrier_block.GetHash() != carrier.GetBlockHash()) {
        return std::nullopt;
    }
    pq::PaymentAuditReceipt receipt;
    if (!ExtractPaymentAuditReceipt(carrier_block, receipt) ||
        receipt.IsNull() || !receipt.IsStructurallyValid() ||
        receipt.carrier_height != carrier.nHeight ||
        receipt.audit_witness_id != required_witness_id) {
        return std::nullopt;
    }
    return receipt;
}

PaymentAuditContextStatus ClassifyPaymentAuditSealContextImpl(
    const CBlockIndex* seal, int32_t expected_height,
    int32_t predecessor_height, const uint256& predecessor_hash,
    PaymentAuditSealValidation validation,
    HistoricalIndexValidationCache& cache,
    uint64_t provenance_revocation_revision,
    std::size_t block_budget =
        HistoricalIndexValidationCache::BLOCK_BUDGET)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (seal == nullptr) return PaymentAuditContextStatus::LOCAL_ERROR;
    if (seal->nHeight != expected_height ||
        (seal->nStatus & BLOCK_FAILED_MASK) || predecessor_height < 0 ||
        predecessor_height >= seal->nHeight || predecessor_hash.IsNull()) {
        return PaymentAuditContextStatus::INVALID;
    }
    const CBlockIndex* predecessor{seal->GetAncestor(predecessor_height)};
    if (predecessor == nullptr) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    if (predecessor->GetBlockHash() != predecessor_hash) {
        return PaymentAuditContextStatus::INVALID;
    }
    if (validation == PaymentAuditSealValidation::LIVE_EXACT) {
        return HasChainLockTargetValidation(
                   *seal, predecessor_height,
                   HistoricalIndexValidationMode::FULL_FINALITY, cache,
                   provenance_revocation_revision, block_budget)
            ? PaymentAuditContextStatus::READY
            : PaymentAuditContextStatus::LOCAL_ERROR;
    }
    const auto predecessor_status{ClassifyHistoricalReceiptIndexRange(
        *predecessor, predecessor_height, cache,
        provenance_revocation_revision, block_budget)};
    if (predecessor_status != PaymentAuditContextStatus::READY) {
        return predecessor_status;
    }
    // The certificate attests governance only after its declared predecessor;
    // scripts and receipt accumulators remain locally reconstructed.
    return ClassifyHistoricalReceiptIndexRange(
        *seal, predecessor_height + 1, cache,
        provenance_revocation_revision, block_budget);
}

PaymentAuditContextStatus ClassifyPaymentAuditSealContext(
    const CBlockIndex* seal, int32_t expected_height,
    int32_t predecessor_height, const uint256& predecessor_hash,
    PaymentAuditSealValidation validation)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    HistoricalIndexValidationCache cache;
    return ClassifyPaymentAuditSealContextImpl(
        seal, expected_height, predecessor_height, predecessor_hash,
        validation, cache,
        /*provenance_revocation_revision=*/0,
        std::numeric_limits<std::size_t>::max());
}

PaymentAuditContextStatus ClassifyPaymentAuditResponseContext(
    const CBlockIndex* response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (response == nullptr) return PaymentAuditContextStatus::LOCAL_ERROR;
    if (response->nStatus & BLOCK_FAILED_MASK) {
        return PaymentAuditContextStatus::INVALID;
    }
    return IsPaymentAuditResponseBlockUsable(
               *response, require_block_data)
        ? PaymentAuditContextStatus::READY
        : PaymentAuditContextStatus::LOCAL_ERROR;
}

bool IsPaymentAuditCertificateIngressAllowed(
    bool operational, bool local_certificate,
    bool required_remote_response) noexcept
{
    return operational || (!local_certificate && required_remote_response);
}

bool MustRetryPaymentAuditCertificateContext(
    bool historical_required, bool historical_resolved) noexcept
{
    return historical_required && !historical_resolved;
}

bool ShouldRetryLocalChainLockShareRelay(
    bool journal_replayed, pq::ShareCollectionResult result) noexcept
{
    return journal_replayed &&
           result == pq::ShareCollectionResult::DUPLICATE;
}

FinalChainLockVerificationPath SelectFinalChainLockVerificationPath(
    const pq::CollectedChainLockFinalization* collected,
    const pq::FinalChainLock* certificate,
    const uint256& genesis_hash,
    const pq::ChainLockScheduleConfig& schedule,
    const pq::VerifiedRosterSetPtr& roster_set,
    uint8_t authorization_mask,
    bool local_live_admission,
    bool admission_generation_current,
    bool collector_generation_current) noexcept
{
    if (!collected || !certificate || !local_live_admission ||
        !admission_generation_current || !collector_generation_current ||
        certificate != &collected->Certificate()) {
        return FinalChainLockVerificationPath::FULL;
    }
    const auto& context{collected->ContextPtr()};
    if (!context || !roster_set || context->GenesisHash() != genesis_hash ||
        context->Schedule() != schedule ||
        context->Statement() != certificate->statement ||
        context->RosterSetPtr() != roster_set ||
        context->AuthorizationMask() != authorization_mask) {
        return FinalChainLockVerificationPath::FULL;
    }
    return FinalChainLockVerificationPath::COLLECTED;
}

FinalPaymentAuditVerificationPath SelectFinalPaymentAuditVerificationPath(
    const pq::CollectedPaymentAuditFinalization* collected,
    const pq::FinalPaymentAudit* certificate,
    const uint256& genesis_hash,
    const pq::PaymentAuditScheduleConfig& schedule,
    const pq::VerifiedRosterSetPtr& roster_set,
    uint8_t authorization_mask,
    bool local_live_admission,
    bool admission_generation_current,
    bool runtime_generation_current,
    bool roster_source_generation_current) noexcept
{
    if (!collected || !certificate || !local_live_admission ||
        !admission_generation_current || !runtime_generation_current ||
        !roster_source_generation_current ||
        certificate != &collected->Certificate()) {
        return FinalPaymentAuditVerificationPath::FULL;
    }
    const auto& context{collected->ContextPtr()};
    if (!context || !roster_set || context->GenesisHash() != genesis_hash ||
        context->Schedule() != schedule ||
        context->Statement() != certificate->statement ||
        context->RosterSetPtr() != roster_set ||
        context->AuthorizationMask() != authorization_mask) {
        return FinalPaymentAuditVerificationPath::FULL;
    }
    return FinalPaymentAuditVerificationPath::COLLECTED;
}

bool IsPaymentAuditVerificationPathAuthorized(
    bool local_certificate,
    FinalPaymentAuditVerificationPath path) noexcept
{
    return !local_certificate ||
           path == FinalPaymentAuditVerificationPath::COLLECTED;
}

bool IsPaymentAuditFinalizationRetryDue(
    std::chrono::microseconds now,
    std::optional<std::chrono::microseconds> last_attempt) noexcept
{
    return !last_attempt || now < *last_attempt ||
           now - *last_attempt >=
               PAYMENT_AUDIT_FINALIZATION_RETRY_INTERVAL;
}

bool ShouldResetPaymentAuditRuntime(
    bool finalized,
    uint64_t finalization_admission_generation,
    uint64_t current_admission_generation,
    uint64_t runtime_roster_source_generation,
    uint64_t current_roster_source_generation) noexcept
{
    if (runtime_roster_source_generation == 0 ||
        runtime_roster_source_generation !=
            current_roster_source_generation) {
        return true;
    }
    return finalized &&
           (current_admission_generation == 0 ||
            finalization_admission_generation !=
                current_admission_generation);
}

bool IsExactPaymentAuditRuntimeBinding(
    bool runtime_present,
    bool collector_present,
    bool generation_matches,
    bool statement_matches,
    bool prepared_context_matches,
    bool relay_recipients_match) noexcept
{
    return runtime_present && collector_present && generation_matches &&
           statement_matches && prepared_context_matches &&
           relay_recipients_match;
}

bool IsChainLockCollectorOnAcceptedSuccessorView(
    const pq::ChainLockScheduleConfig& schedule,
    const pq::ChainLockStatement& collector,
    const pq::ChainLockStatement& winner) noexcept
{
    const auto successor{
        pq::NextEligibleChainLockTargetHeight(schedule, winner.height)};
    return successor && collector.height == *successor &&
           collector.previous_chainlock_height == winner.height &&
           collector.previous_chainlock_hash == winner.block_hash &&
           collector.previous_btcc_cursor == winner.accepted_btcc_cursor;
}

bool ShouldConsumeChainLockStartupSlot(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t startup_tip_height,
    int32_t target_height) noexcept
{
    const auto latest{pq::LatestEligibleChainLockTargetHeight(
        schedule, startup_tip_height)};
    return latest && target_height <= *latest;
}

bool IsPaymentAuditSigningHeightLive(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t tip_height) noexcept
{
    const auto audit{pq::BuildPaymentAuditEpochSchedule(schedule,
                                                        subject_epoch)};
    const auto first_signing_height{
        audit ? pq::SigningHeightForTarget(schedule.chainlock,
                                           audit->seal_height)
              : std::nullopt};
    return audit && first_signing_height &&
           tip_height >= *first_signing_height &&
           tip_height < audit->carrier_end_height_exclusive;
}

bool ShouldConsumePaymentAuditStartupSlot(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t startup_tip_height) noexcept
{
    const auto audit{pq::BuildPaymentAuditEpochSchedule(schedule,
                                                        subject_epoch)};
    const auto first_signing_height{
        audit ? pq::SigningHeightForTarget(schedule.chainlock,
                                           audit->seal_height)
              : std::nullopt};
    return first_signing_height &&
           startup_tip_height >= *first_signing_height;
}

CChainLocksHandler::CChainLocksHandler(CConnman& connman,
                                       PeerManager& peerman,
                                       ChainstateManager& chainman)
    : m_connman{connman},
      m_peerman{peerman},
      m_chainman{chainman},
      m_genesis_hash{chainman.GetConsensus().hashGenesisBlock},
      m_config{MakePQChainLockFinalityStoreConfig(chainman.GetConsensus())},
      m_quorum_build_config{
          MakePQQuorumBuildConfig(chainman.GetConsensus())},
      m_verified_payment_audit_transition_cache{
          std::make_unique<
              VerifiedPaymentAuditReceiptTransitionCache>()},
      m_verifier{GetPQChainLockVerifierThreads(GetNumCores())}
{
    if (m_config) {
        bool full_reindex{false};
        if (m_chainman.m_blockman.m_block_tree_db) {
            // Full reindex may rebuild bounded block-derived audit data, but
            // it cannot rediscover the roster-authorization predecessor chain
            // from block inventory. Preserve the fsynced finality state and
            // reauthenticate it against the rebuilt branch instead.
            m_chainman.m_blockman.m_block_tree_db->ReadReindexing(
                full_reindex);
        }
        m_persistence = std::make_unique<pq::PQChainLockPersistence>(
            DBParams{
                .path = chainman.m_options.datadir / "llmq/pq-chainlocks",
                .cache_bytes = 4U << 20,
                .wipe_data = false,
            },
            m_genesis_hash, *m_config);
        m_pending_persisted = m_persistence->LoadBest();
        m_pending_persisted_unsealed_btcc =
            m_persistence->LoadUnsealedBTCC();
        m_pending_persisted_authorization_bases =
            m_persistence->LoadAuthorizationBases();
        m_persisted_best_auth_pending = m_pending_persisted.has_value();
        m_persisted_unsealed_auth_pending =
            m_pending_persisted_unsealed_btcc.has_value();
        m_catchup_used.store(m_persistence->HasCatchupMarker());
        const pq::BTCCPresealState loaded_preseal{
            m_persistence->LoadBTCCPresealState()};
        const pq::PaymentAuditPresealState loaded_payment_audit_preseal{
            m_persistence->LoadPaymentAuditPresealState()};
        uint64_t loaded_revision{0};
        const auto observe_revision = [&](const auto& marker) {
            if (marker) {
                loaded_revision = std::max(loaded_revision,
                                           marker->revision);
            }
        };
        observe_revision(loaded_preseal.active);
        observe_revision(loaded_preseal.prospective);
        uint64_t loaded_payment_audit_revision{0};
        const auto observe_payment_audit_revision = [&](const auto& marker) {
            if (marker) {
                loaded_payment_audit_revision = std::max(
                    loaded_payment_audit_revision, marker->revision);
            }
        };
        observe_payment_audit_revision(loaded_payment_audit_preseal.active);
        observe_payment_audit_revision(
            loaded_payment_audit_preseal.prospective);
        {
            LOCK(m_btcc_preseal_mutex);
            m_btcc_preseal_state = loaded_preseal;
            m_btcc_preseal_revision = loaded_revision;
            m_payment_audit_preseal_state =
                loaded_payment_audit_preseal;
            m_payment_audit_preseal_revision =
                loaded_payment_audit_revision;
        }
        m_store = std::make_unique<pq::ChainLockFinalityStore>(
            m_genesis_hash, *m_config,
            static_cast<const pq::ChainLockFinalityContext&>(*this),
            [this](const pq::FinalChainLock& chainlock,
                   const pq::PreparedChainLockContextPtr& context) {
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                std::optional<pq::PaymentAuditSealContextCapsule>
                    seal_context;
                const bool seal_context_ready{
                    pq::PaymentAuditSealContextCapsule::
                        BuildForVerifiedDurableCandidate(
                            m_genesis_hash, *m_config, chainlock,
                            context, seal_context)};
                const bool needs_recovery_authority{
                    pq::HasRecoveryRosterBeacon(
                        chainlock.statement.roster_beacons)};
                const bool persisted{
                    seal_context_ready &&
                    (!needs_recovery_authority || recovery_authority) &&
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    (chainlock.statement.roster_transition ==
                             pq::RosterAuthorizationTransitionKind::INITIALIZE
                         ? m_persistence->PersistInitializedBest(
                               chainlock, nullptr, recovery_authority,
                               /*verified_reset=*/nullptr,
                               std::move(seal_context))
                         : m_persistence->PersistBest(
                               chainlock, nullptr, recovery_authority,
                               std::move(seal_context)))};
                if (!persisted) {
                    // Stop all new signing/admission immediately. A previously
                    // durable winner, if any, remains safe to enforce.
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](const pq::FinalChainLock& chainlock,
                   const pq::PreparedChainLockContextPtr& context) {
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistUnsealedBTCC(
                        chainlock, nullptr, recovery_authority)};
                if (!persisted) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](const pq::FinalChainLock& chainlock,
                   const std::optional<pq::BTCCCursorReconciliationProof>&
                       btcc_cursor_reconciliation,
                   const pq::ReceiptArchiveRosterAuthorization*
                       covering_authorization,
                   const pq::PreparedChainLockContextPtr& context) {
                pq::ChainLockPersistenceError persistence_error{
                    pq::ChainLockPersistenceError::NONE};
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                std::optional<pq::PaymentAuditSealContextCapsule>
                    seal_context;
                const bool seal_context_ready{
                    pq::PaymentAuditSealContextCapsule::
                        BuildForVerifiedDurableCandidate(
                            m_genesis_hash, *m_config, chainlock,
                            context, seal_context)};
                const auto persist = [&] {
                    if (!seal_context_ready) return false;
                    switch (chainlock.statement.roster_transition) {
                    case pq::RosterAuthorizationTransitionKind::INITIALIZE:
                        return m_persistence->PersistInitializedBest(
                            chainlock, &persistence_error,
                            recovery_authority,
                            /*verified_reset=*/nullptr,
                            seal_context);
                    case pq::RosterAuthorizationTransitionKind::RECOVER:
                        return m_persistence->PersistRecoveryCatchupBest(
                            chainlock, &persistence_error,
                            btcc_cursor_reconciliation,
                            covering_authorization,
                            recovery_authority,
                            /*verified_reset=*/nullptr,
                            seal_context);
                    case pq::RosterAuthorizationTransitionKind::KEEP:
                    case pq::RosterAuthorizationTransitionKind::OBSERVE:
                    case pq::RosterAuthorizationTransitionKind::REVEAL:
                    case pq::RosterAuthorizationTransitionKind::ROTATE:
                        return m_persistence->PersistCatchupBest(
                            chainlock, &persistence_error,
                            btcc_cursor_reconciliation,
                            covering_authorization,
                            recovery_authority, seal_context);
                    }
                    return false;
                };
                const bool auxiliary_flushed{
                    FlushChainLockAuxiliarySnapshotsForDurability()};
                const bool persisted{auxiliary_flushed && m_persistence &&
                                     persist()};
                if (!persisted) {
                    // A stale semantic CAS is a rejected candidate, not a
                    // failed database. Only an actual durability failure may
                    // permanently close admission until restart.
                    if (!auxiliary_flushed || !m_persistence ||
                        persistence_error ==
                            pq::ChainLockPersistenceError::IO_FAILURE) {
                        m_persistence_failed.store(true);
                        DisableShareAdmission();
                    }
                } else {
                    m_catchup_used.store(true);
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](
                const pq::FinalChainLock& chainlock,
                const pq::ReceiptArchiveRosterAuthorization& authorization,
                const pq::PreparedChainLockContextPtr& context) {
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistAuthorizedUnsealedBTCC(
                        chainlock, authorization, nullptr,
                        recovery_authority)};
                if (!persisted) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](
                const pq::FinalChainLock& chainlock,
                const pq::ReceiptArchiveRosterAuthorization& authorization,
                const pq::PreparedChainLockContextPtr& context) {
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                std::optional<pq::PaymentAuditSealContextCapsule>
                    seal_context;
                const bool seal_context_ready{
                    pq::PaymentAuditSealContextCapsule::
                        BuildForVerifiedDurableCandidate(
                            m_genesis_hash, *m_config, chainlock,
                            context, seal_context)};
                const bool persisted{
                    seal_context_ready &&
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistBestCoveringReceiptArchive(
                        chainlock, authorization, nullptr,
                        recovery_authority, std::move(seal_context))};
                if (!persisted) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](
                const pq::FinalChainLock& chainlock,
                const std::optional<pq::BTCCCursorReconciliationProof>&
                    btcc_cursor_reconciliation,
                const pq::ReceiptArchiveRosterAuthorization*
                    covering_authorization,
                const pq::PreparedChainLockContextPtr& context,
                const pq::VerifiedRecoveryResetPersistenceCapability&
                    verified_reset) {
                pq::ChainLockPersistenceError persistence_error{
                    pq::ChainLockPersistenceError::NONE};
                const auto recovery_authority{
                    RecoveryAuthorityForDurableState(
                        m_genesis_hash, chainlock, context)};
                std::optional<pq::PaymentAuditSealContextCapsule>
                    seal_context;
                const bool seal_context_ready{
                    pq::PaymentAuditSealContextCapsule::
                        BuildForVerifiedDurableCandidate(
                            m_genesis_hash, *m_config, chainlock,
                            context, seal_context)};
                const bool auxiliary_flushed{
                    seal_context_ready &&
                    FlushChainLockAuxiliarySnapshotsForDurability()};
                bool persisted{false};
                const bool needs_recovery_authority{
                    pq::HasRecoveryRosterBeacon(
                        chainlock.statement.roster_beacons)};
                if (auxiliary_flushed && m_persistence &&
                    (!needs_recovery_authority || recovery_authority)) {
                    switch (chainlock.statement.roster_transition) {
                    case pq::RosterAuthorizationTransitionKind::INITIALIZE:
                        persisted = m_persistence->PersistInitializedBest(
                            chainlock, &persistence_error,
                            recovery_authority, &verified_reset,
                            seal_context);
                        break;
                    case pq::RosterAuthorizationTransitionKind::RECOVER:
                        persisted =
                            m_persistence->PersistRecoveryCatchupBest(
                                chainlock, &persistence_error,
                                btcc_cursor_reconciliation,
                                covering_authorization,
                                recovery_authority, &verified_reset,
                                seal_context);
                        break;
                    case pq::RosterAuthorizationTransitionKind::KEEP:
                    case pq::RosterAuthorizationTransitionKind::OBSERVE:
                    case pq::RosterAuthorizationTransitionKind::REVEAL:
                    case pq::RosterAuthorizationTransitionKind::ROTATE:
                        break;
                    }
                }
                if (!persisted) {
                    if (!auxiliary_flushed || !m_persistence ||
                        persistence_error ==
                            pq::ChainLockPersistenceError::IO_FAILURE) {
                        m_persistence_failed.store(true);
                        DisableShareAdmission();
                    }
                } else {
                    if (chainlock.statement.roster_transition ==
                        pq::RosterAuthorizationTransitionKind::RECOVER) {
                        m_catchup_used.store(true);
                    }
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            },
            [this](const pq::FinalChainLock& chainlock) {
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistVerifiedAuthorizationBase(
                        chainlock)};
                if (!persisted) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    UpdateDurableChainLockAuxiliaryRetention();
                }
                return persisted;
            });
        try {
            m_payment_audit_store =
                std::make_unique<pq::PaymentAuditStore>(
                    chainman.m_options.datadir /
                        "llmq/pq-payment-audits",
                    m_genesis_hash, 8U << 20, full_reindex);
            m_payment_audit_staging_store =
                std::make_unique<pq::PaymentAuditStagingStore>(
                    chainman.m_options.datadir /
                        "llmq/pq-payment-audit-staging",
                    m_genesis_hash, 8U << 20, full_reindex);
            if (!m_payment_audit_store->IsHealthy() ||
                !m_payment_audit_staging_store->IsHealthy()) {
                throw std::runtime_error{
                    "payment-audit database failed schema/health check"};
            }
        } catch (const std::exception& exception) {
            LogPrintf("CChainLocksHandler::%s -- unable to open the exact "
                      "payment-audit archive: %s\n",
                      __func__, exception.what());
            m_payment_audit_store.reset();
            m_payment_audit_staging_store.reset();
            m_persistence_failed.store(true);
            DisableShareAdmission();
        }
    }
    // SYSCOIN: InitLLMQSystem runs under cs_main before startup pruning, and it
    // can run twice during chainstate recreation. Always restore/lower or
    // erase the named retention state so a prior handler cannot leave stale
    // floors and a live marker cannot lose rollback history.
    AssertLockHeld(cs_main);
    UpdateBTCCPresealPruneLock(m_btcc_preseal_state);
    UpdatePaymentAuditPresealPruneLock(
        m_payment_audit_preseal_state);
    UpdatePresealAuxiliaryRetention(
        m_btcc_preseal_state, m_payment_audit_preseal_state);
    UpdateDurableChainLockAuxiliaryRetention();
    if (deterministicMNManager) {
        // SYSCOIN: A recreated handler must both restore a pending durable
        // publication before startup pruning and revoke any process-local GC
        // authority until this handler reproves the exact active winner or
        // authenticated historical receipt boundary.
        m_auxiliary_history_gc_auth_gate.Stop([this] {
            return RevokeAuxiliaryHistoryGCAuthorization();
        });
        deterministicMNManager->UpdateFinalitySnapshotPublicationRetention(
            IsPersistedChainLockPending());
    }

    bool loaded_preseal{false};
    {
        LOCK(m_btcc_preseal_mutex);
        loaded_preseal = !m_btcc_preseal_state.IsEmpty() ||
                         !m_payment_audit_preseal_state.IsEmpty();
    }
    const bool loaded_payment_audit_checkpoint{
        m_payment_audit_store &&
        (m_payment_audit_store->GetPendingPruneCheckpoint().has_value() ||
         m_payment_audit_store->GetPruneCheckpoint().has_value() ||
         (deterministicMNManager &&
          deterministicMNManager
              ->GetPendingPaymentProbationGCRequest().has_value()))};
    bool loaded_persisted{false};
    {
        LOCK(m_persisted_mutex);
        loaded_persisted = m_pending_persisted.has_value() ||
                           m_pending_persisted_unsealed_btcc.has_value() ||
                           !m_pending_persisted_authorization_bases.empty() ||
                           m_persisted_best_auth_pending ||
                           m_persisted_unsealed_auth_pending ||
                           m_persisted_invalid;
    }
    const bool configured_unavailable{
        m_config &&
        (!m_persistence || !m_store || !m_payment_audit_store ||
         !m_payment_audit_staging_store || m_persistence_failed.load())};
    const bool authentication_pending{
        loaded_preseal || loaded_payment_audit_checkpoint || loaded_persisted ||
        configured_unavailable};
    const PQHistoryAuthState initial_auth_state{
        !m_config
            ? PQHistoryAuthState::READY
            : (authentication_pending ? PQHistoryAuthState::PENDING
                                      : PQHistoryAuthState::READY)};
    if (!m_chainman.PublishPQHistoryAuthState(initial_auth_state)) {
        throw std::runtime_error(
            "persisted PQ history appeared after public IBD completed");
    }
}

CChainLocksHandler::~CChainLocksHandler()
{
    Stop();
}

void CChainLocksHandler::Start()
{
    {
        LOCK(m_lifecycle_mutex);
        if (m_started) return;
        m_share_admission_gate.SetReady(false);
        (void)m_auxiliary_history_gc_auth_gate.Start([this] {
            return RevokeAuxiliaryHistoryGCAuthorization();
        });
        {
            LOCK(m_share_signing_mutex);
            m_signer_startup_pro_tx_hash.SetNull();
            m_signer_startup_tip_height.reset();
        }
        if (fMasternodeMode && m_config && m_quorum_build_config) {
            try {
                m_signer_journal = std::make_unique<CPQSignerJournal>(
                    gArgs.GetDataDirNet() / "llmq/pq-signer-journal");
            } catch (const std::exception& exception) {
                LogPrintf("CChainLocksHandler::%s -- unable to open the "
                          "burn-before-sign journal: %s\n",
                          __func__, exception.what());
                m_signer_journal.reset();
            }
        }
        m_started = true;
        CheckActiveState();
        while (TryImportPersistedRosterAuthorizationBase() ==
               PersistedChainLockImport::ACCEPTED) {
        }
        (void)TryImportPersistedChainLock();
        (void)TryImportPersistedUnsealedBTCC();
        // A successful import clears the pending gate after the first state
        // check. Enforce it before publishing authentication readiness.
        CheckActiveState();
        EnforceBestChainLock();
        MaintainPaymentAuditCheckpointGC();
        m_scheduler = std::make_unique<CScheduler>();
        CScheduler* const scheduler{m_scheduler.get()};
        m_scheduler_thread = std::make_unique<std::thread>(
            &util::TraceThread, "pqcl-schdlr",
            [scheduler] { scheduler->serviceQueue(); });
        scheduler->scheduleEvery([this]() EXCLUSIVE_LOCKS_REQUIRED(
            !cs_main, !m_chainlock_admission_mutex,
            !m_share_lifecycle_mutex, !m_pending_btcc_receipt_mutex,
            !m_needed_btcc_certificate_mutex) {
            while (TryImportPersistedRosterAuthorizationBase() ==
                   PersistedChainLockImport::ACCEPTED) {
            }
            (void)TryImportPersistedChainLock();
            (void)TryImportPersistedUnsealedBTCC();
            CheckActiveState();
            ContinueVerifiedHistoricalChainLock();
            EnforceBestChainLock();
            MaintainPaymentAuditCheckpointGC();
            MaybeReplayBTCCPreseal();
            RequestNeededBTCCCertificate();
            RequestNeededPaymentAuditCertificate();
            RetryPendingBTCCBlock();
            RequestCatchupChainLock();
            RefreshPQHistoryAuthState();
            MaybeRelayPaymentAuditHave();
            const uint64_t admission_generation{
                GetShareAdmissionGeneration()};
            if (admission_generation != 0) {
                (void)RefreshCurrentSigningContexts(
                    admission_generation);
            }
            MaybeCreateAndSignChainLock();
            MaybeCreateAndSignPaymentAudit();
        }, std::chrono::seconds{5});
        {
            LOCK(m_share_lifecycle_mutex);
            m_share_admission_gate.SetReady(true);
        }
    }
    RefreshPQHistoryAuthState();
}

void CChainLocksHandler::Stop()
{
    std::unique_ptr<std::thread> thread;
    std::unique_ptr<CScheduler> scheduler;
    {
        LOCK(m_lifecycle_mutex);
        {
            LOCK(m_share_lifecycle_mutex);
            m_share_admission_gate.SetReady(false);
        }
        m_auxiliary_history_gc_auth_gate.Stop([this] {
            return RevokeAuxiliaryHistoryGCAuthorization();
        });
        m_payment_audit_candidate_metadata_cache.Clear();
        m_payment_audit_receipt_cache.Clear();
        m_verified_payment_audit_transition_cache->Clear();
        if (!m_started) return;
        m_started = false;
        scheduler = std::move(m_scheduler);
        thread = std::move(m_scheduler_thread);
        // Keep lifecycle serialization through cleanup. Otherwise a
        // concurrent Start could publish a new scheduler and journal before
        // this Stop resets the old generation's state.
        if (scheduler) scheduler->stop();
        if (thread && thread->joinable()) thread->join();
        {
            LOCK(m_context_build_mutex);
            m_live_signing_validation_frontier = {};
            m_live_signing_validation_examined_blocks = 0;
        }
        {
            LOCK(m_collector_mutex);
            ResetCollectors();
        }
        {
            LOCK(m_payment_audit_mutex);
            ResetPaymentAuditRuntime();
            m_payment_audit_network_context.reset();
        }
        m_signer_journal.reset();
        {
            LOCK(m_pending_btcc_receipt_mutex);
            m_pending_btcc_receipt.reset();
            m_pending_btcc_last_request = std::chrono::microseconds{0};
        }
        {
            LOCK(m_pending_payment_audit_receipt_mutex);
            m_pending_payment_audit_receipt.reset();
            m_pending_payment_audit_last_request =
                std::chrono::microseconds{0};
        }
        m_pending_verified_historical.store({});
        m_retry_pending_btcc_block.store(false);
    }
}

std::optional<CChainLocksHandler::CurrentSigningContext>
CChainLocksHandler::CurrentSigningContexts::Find(
    const pq::ChainLockStatement& statement) const
{
    if (!roster_set) return std::nullopt;
    for (std::size_t i{0}; i < count; ++i) {
        if (statements[i] == statement && prepared_contexts[i] &&
            prepared_contexts[i]->Statement() == statement &&
            prepared_contexts[i]->RosterSetPtr() == roster_set) {
            return CurrentSigningContext{
                static_cast<uint8_t>(i), statement,
                roster_set->RostersPtr(),
                prepared_contexts[i]->AuthorizationMask()};
        }
    }
    return std::nullopt;
}

std::optional<CChainLocksHandler::CurrentSigningContext>
CChainLocksHandler::CurrentSigningContexts::Find(
    const uint256& statement_logical_id) const
{
    if (!roster_set) return std::nullopt;
    for (std::size_t i{0}; i < count; ++i) {
        if (prepared_contexts[i] &&
            prepared_contexts[i]->StatementLogicalId() ==
                statement_logical_id &&
            prepared_contexts[i]->Statement() == statements[i] &&
            prepared_contexts[i]->RosterSetPtr() == roster_set) {
            return CurrentSigningContext{
                static_cast<uint8_t>(i), statements[i],
                roster_set->RostersPtr(),
                prepared_contexts[i]->AuthorizationMask()};
        }
    }
    return std::nullopt;
}

void CChainLocksHandler::SetQuorumRosterCache(
    pq::FrozenQuorumRosterCachePtr cache)
{
    if (cache &&
        (!m_quorum_build_config || cache->GenesisHash() != m_genesis_hash ||
         cache->Config() != *m_quorum_build_config)) {
        throw std::invalid_argument{"mismatched PQ quorum roster cache"};
    }
    {
        LOCK(m_lookup_mutex);
        if (m_quorum_roster_source_generation ==
            std::numeric_limits<uint64_t>::max()) {
            throw std::overflow_error{
                "PQ quorum roster source generation exhausted"};
        }
        m_quorum_roster_cache = std::move(cache);
        ++m_quorum_roster_source_generation;
    }
    m_payment_audit_receipt_cache.Clear();
    m_verified_payment_audit_transition_cache->Clear();
}

pq::FrozenQuorumRosterCachePtr
CChainLocksHandler::GetQuorumRosterCache(uint64_t* generation) const
{
    LOCK(m_lookup_mutex);
    if (generation != nullptr) {
        *generation = m_quorum_roster_source_generation;
    }
    return m_quorum_roster_cache;
}

bool CChainLocksHandler::IsQuorumRosterSourceGenerationCurrent(
    uint64_t generation) const
{
    LOCK(m_lookup_mutex);
    return generation != 0 &&
           generation == m_quorum_roster_source_generation &&
           static_cast<bool>(m_quorum_roster_cache);
}

bool CChainLocksHandler::RevokeAuxiliaryHistoryGCAuthorization()
{
    return deterministicMNManager == nullptr ||
           deterministicMNManager->UpdateAuxiliaryHistoryGCAuthorization(
               std::nullopt);
}

void CChainLocksHandler::DisableShareAdmission() noexcept
{
    m_share_admission_gate.Fail();
    m_auxiliary_history_gc_auth_gate.Fail([this] {
        return RevokeAuxiliaryHistoryGCAuthorization();
    });
}

uint64_t CChainLocksHandler::GetShareAdmissionGeneration() const noexcept
{
    return m_share_admission_gate.Acquire();
}

bool CChainLocksHandler::IsShareAdmissionGenerationCurrent(
    uint64_t generation) const noexcept
{
    return m_share_admission_gate.IsCurrent(generation);
}

bool CChainLocksHandler::IsConfiguredForVerification() const
{
    if (!m_store || !m_config || !m_quorum_build_config) return false;
    return static_cast<bool>(GetQuorumRosterCache());
}

bool CChainLocksHandler::IsChainLockVerificationAvailable() const
{
    if (!m_chainman.IsPQParticipationAllowed()) return false;
    const bool configured_and_healthy{
        m_persistence != nullptr && m_store != nullptr &&
        m_payment_audit_store != nullptr &&
        m_payment_audit_staging_store != nullptr &&
        m_payment_audit_store->IsHealthy() &&
        m_payment_audit_staging_store->IsHealthy() &&
        IsConfiguredForVerification()};
    return ShouldVerifyChainLockCertificate(
        configured_and_healthy, IsPersistedChainLockPending(),
        m_persistence_failed.load());
}

bool CChainLocksHandler::ReconcileSignerJournal(const uint256& pro_tx_hash)
{
    if (!m_signer_journal || !m_store) return true;
    const auto chainlock{m_store->GetBestRecord()};
    if (!chainlock) return true;
    return ReconcileSignerJournal(pro_tx_hash, chainlock->metadata);
}

bool CChainLocksHandler::ReconcileSignerJournal(
    const uint256& pro_tx_hash,
    const pq::FinalChainLockRecordMetadata& chainlock)
{
    if (!m_signer_journal) return true;
    LOCK(m_signer_reconcile_mutex);
    const PQSignerJournalResult result{
        m_signer_journal->ReconcileDurableAcceptedChainLock(
            m_genesis_hash, pro_tx_hash, chainlock)};
    switch (result.outcome) {
    case PQSignerJournalOutcome::CERTIFICATE_REPLAY:
    case PQSignerJournalOutcome::CERTIFICATE_RECORDED:
        return true;
    default:
        LogPrintf("CChainLocksHandler::%s -- durable PQ ChainLock could not "
                  "reconcile the signer journal, outcome=%u\n",
                  __func__, static_cast<uint8_t>(result.outcome));
        return false;
    }
}

bool CChainLocksHandler::InitializeSignerStartupTip(
    const uint256& local_pro_tx_hash)
{
    AssertLockHeld(m_share_signing_mutex);
    if (local_pro_tx_hash.IsNull()) return false;
    if (m_signer_startup_pro_tx_hash == local_pro_tx_hash &&
        m_signer_startup_tip_height) {
        return true;
    }
    LOCK(cs_main);
    const CBlockIndex* tip{m_chainman.ActiveTip()};
    if (tip == nullptr) return false;
    // Under the supported sequential-signer model, a target that first becomes
    // signable after this synchronized snapshot cannot have been used by the
    // prior process. Chasing later tips would burn fresh leaves indefinitely;
    // concurrent clones and rollback behind a stale/eclipsed tip still require
    // an external single-active fence.
    m_signer_startup_pro_tx_hash = local_pro_tx_hash;
    m_signer_startup_tip_height = tip->nHeight;
    return true;
}

bool CChainLocksHandler::ConsumeStartupChainLockSlots(
    const pq::PreparedChainLockContext& context,
    const CurrentSigningSource& source,
    const uint256& local_pro_tx_hash)
{
    AssertLockHeld(m_share_signing_mutex);
    if (!m_signer_journal || !m_signer_startup_tip_height || !m_config ||
        !m_persistence || !m_payment_audit_store ||
        context.GenesisHash() != m_genesis_hash ||
        context.Schedule() != m_config->chainlock_schedule) {
        return false;
    }
    const auto& statement{context.Statement()};
    const auto& rosters{context.Rosters()};
    if (source.staged_recovery) {
        const auto staged{m_persistence
            ? m_persistence->LoadRosterRecoveryPrecommit()
            : std::optional<pq::RosterRecoveryPrecommit>{}};
        const auto checkpoint{m_payment_audit_store
            ? m_payment_audit_store->GetPruneCheckpoint()
            : std::optional<pq::PaymentAuditStoreCheckpoint>{}};
        const uint256 recovery_token{staged
            ? RosterRecoveryPrecommitToken(m_genesis_hash, *staged)
            : uint256{}};
        if (!staged ||
            !m_payment_audit_store ||
            !m_payment_audit_store->IsHealthy() ||
            MutableSigningContextToken(
                PaymentAuditCheckpointToken(checkpoint),
                recovery_token) !=
                source.mutable_signing_context_token ||
            statement.height !=
                staged->pending_seed.anchor_cursor.sys_height ||
            statement.block_hash !=
                staged->pending_seed.anchor_cursor.sys_hash ||
            statement.accepted_btcc_cursor !=
                staged->pending_seed.anchor_cursor ||
            statement.btcc_advance != pq::BTCCAdvance::ADVANCE ||
            !staged->pending_seed.IsReady() ||
            staged->pending_seed !=
                statement.roster_beacons.active.seeds.back() ||
            statement.roster_transition !=
                pq::RosterAuthorizationTransitionKind::INITIALIZE) {
            return false;
        }
        return true;
    }
    if (!ShouldConsumeChainLockStartupSlot(
            m_config->chainlock_schedule, *m_signer_startup_tip_height,
            statement.height)) {
        return true;
    }

    std::vector<PQSignerJournalKey> keys;
    keys.reserve(rosters.size());
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        if ((context.AuthorizationMask() & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        const auto& roster{rosters[slot]};
        const auto leaf_index{pq::ChainLockLeafIndex(
            context.Schedule(), roster.descriptor.epoch,
            statement.height)};
        if (!leaf_index) return false;
        for (const auto& member : roster.members) {
            if (member.pro_tx_hash != local_pro_tx_hash || !member.eligible ||
                !member.child_root) {
                continue;
            }
            auto signing_material{GetActiveMasternodeChildSigningMaterial(
                m_genesis_hash, local_pro_tx_hash, *member.child_root)};
            if (!signing_material) return false;
            keys.push_back(PQSignerJournalKey{
                .genesis_hash = m_genesis_hash,
                .child_profile = statement.child_profile,
                .pro_tx_hash = local_pro_tx_hash,
                .quorum_epoch = roster.descriptor.epoch,
                .child_key_hash =
                    ::Hash(signing_material->key_proof.public_key),
                .leaf_index = *leaf_index,
                .purpose = PQSignerPurpose::CHAINLOCK,
                .absolute_height = statement.height,
            });
        }
    }
    if (!m_signer_journal->ConsumeIfAbsent(keys)) return false;
    // Repeat this for every startup-eligible context. A same-height reorg can
    // introduce a different local roster key after an earlier context had no
    // key to consume. Idempotent consumption closes that gap while allowing an
    // intact SIGNED record to replay in this scheduler pass.
    return true;
}

bool CChainLocksHandler::ConsumeStartupPaymentAuditSlots(
    const pq::PreparedPaymentAuditContext& context,
    const uint256& local_pro_tx_hash)
{
    AssertLockHeld(m_share_signing_mutex);
    if (!m_signer_journal || !m_signer_startup_tip_height || !m_config) {
        return false;
    }

    const pq::PaymentAuditScheduleConfig expected_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    if (context.GenesisHash() != m_genesis_hash ||
        context.Schedule() != expected_config) {
        return false;
    }
    const auto& config{context.Schedule()};
    const auto& statement{context.Statement()};
    const auto& rosters{context.Rosters()};
    const auto schedule{pq::BuildPaymentAuditEpochSchedule(
        config, statement.commitment.subject_epoch)};
    if (!schedule) return false;
    if (!ShouldConsumePaymentAuditStartupSlot(
            config, statement.commitment.subject_epoch,
            *m_signer_startup_tip_height)) {
        return true;
    }

    std::vector<PQSignerJournalKey> keys;
    keys.reserve(rosters.size());
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        if ((context.AuthorizationMask() & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        const auto& roster{rosters[slot]};
        const auto leaf_index{context.LeafIndex(slot)};
        if (!leaf_index) return false;
        for (const auto& member : roster.members) {
            if (member.pro_tx_hash != local_pro_tx_hash || !member.eligible ||
                !member.child_root) {
                continue;
            }
            auto signing_material{GetActiveMasternodeChildSigningMaterial(
                m_genesis_hash, local_pro_tx_hash, *member.child_root)};
            if (!signing_material) return false;
            keys.push_back(PQSignerJournalKey{
                .genesis_hash = m_genesis_hash,
                .child_profile = statement.commitment.child_profile,
                .pro_tx_hash = local_pro_tx_hash,
                .quorum_epoch = roster.descriptor.epoch,
                .child_key_hash =
                    ::Hash(signing_material->key_proof.public_key),
                .leaf_index = *leaf_index,
                .purpose = PQSignerPurpose::PAYMENT_AUDIT,
                .absolute_height = statement.commitment.seal_height,
            });
        }
    }
    if (!m_signer_journal->ConsumeIfAbsent(keys)) return false;
    // Audit roster context can likewise change without advancing the schedule;
    // do not cache successful consumption across signing candidates.
    return true;
}

bool CChainLocksHandler::IsPersistedChainLockPending() const
{
    LOCK(m_persisted_mutex);
    return m_pending_persisted.has_value() ||
           m_pending_persisted_unsealed_btcc.has_value() ||
           !m_pending_persisted_authorization_bases.empty() ||
           m_persisted_invalid;
}

bool CChainLocksHandler::HasPendingPQHistoryAuthentication() const
{
    AssertLockHeld(cs_main);
    if (!m_config) return false;
    if (!m_persistence || !m_store || !m_payment_audit_store ||
        !m_payment_audit_staging_store || m_persistence_failed.load() ||
        !m_payment_audit_store->IsHealthy() ||
        !m_payment_audit_staging_store->IsHealthy()) {
        return true;
    }
    if (m_chainman.IsSnapshotActive() &&
        !m_chainman.IsSnapshotValidated()) {
        return true;
    }
    {
        LOCK(m_persisted_mutex);
        if (m_pending_persisted || m_pending_persisted_unsealed_btcc ||
            !m_pending_persisted_authorization_bases.empty() ||
            m_persisted_best_auth_pending ||
            m_persisted_unsealed_auth_pending || m_persisted_invalid) {
            return true;
        }
    }

    // Durable acceptance alone is not public authentication readiness. The
    // installed winner must connect to the current active history; a valid
    // nonconnecting certificate stays pending and is never used here to
    // authorize a side-branch transition.
    const auto accepted_best{m_store->GetBestRecord()};
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    if (accepted_best) {
        const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
            accepted_best->metadata.statement.block_hash)};
        if (target == nullptr ||
            target->nHeight != accepted_best->metadata.statement.height ||
            active_tip == nullptr || active_tip->nHeight < target->nHeight ||
            active_tip->GetAncestor(target->nHeight) != target) {
            return true;
        }
    }

    const auto pending_archive{
        m_payment_audit_store->GetPendingPruneCheckpoint()};
    const auto pending_probation{
        deterministicMNManager
            ? deterministicMNManager
                  ->GetPendingPaymentProbationGCRequest()
            : std::nullopt};
    const auto completed_archive{
        m_payment_audit_store->GetPruneCheckpoint()};
    const std::optional<pq::PaymentAuditStoreCheckpoint> checkpoint{
        pending_archive
            ? pending_archive
            : pending_probation
                  ? std::optional<pq::PaymentAuditStoreCheckpoint>{
                        pending_probation->checkpoint}
                  : completed_archive};
    if (checkpoint) {
        // The compact archive boundary is not self-authenticating. Keep IBD
        // recoverable until a still-durable active descendant certificate
        // authenticates the exact authorizer which permitted witness pruning.
        const CBlockIndex* authorizer{
            m_chainman.m_blockman.LookupBlockIndex(
                checkpoint->authorizing_target_hash)};
        if (!checkpoint->IsStructurallyValid() || authorizer == nullptr ||
            authorizer->nHeight != checkpoint->authorizing_target_height ||
            !IsPaymentAuditCheckpointAuthenticated(
                *checkpoint, *authorizer)) {
            return true;
        }
    }

    pq::BTCCPresealState btcc;
    pq::PaymentAuditPresealState payment;
    {
        LOCK(m_btcc_preseal_mutex);
        btcc = m_btcc_preseal_state;
        payment = m_payment_audit_preseal_state;
    }
    const auto terminal_on_active = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> const CBlockIndex* {
        if (!marker || !marker->IsStructurallyValid() ||
            active_tip == nullptr) {
            return nullptr;
        }
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->terminal_carrier_hash)};
        return terminal != nullptr &&
                       terminal->nHeight == marker->terminal_carrier_height &&
                       active_tip->nHeight >= terminal->nHeight &&
                       active_tip->GetAncestor(terminal->nHeight) == terminal
                   ? terminal
                   : nullptr;
    };
    const auto btcc_unresolved = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker) return false;
        const CBlockIndex* terminal{terminal_on_active(marker)};
        if (terminal == nullptr) return true;
        return !IsBTCCPrefixAuthenticated(*terminal) &&
               CheckBTCCReceiptCertificate(marker->terminal_receipt,
                                           *terminal) !=
                   BTCCReceiptCertificateStatus::VERIFIED;
    };
    const auto payment_unresolved = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker) return false;
        const CBlockIndex* terminal{terminal_on_active(marker)};
        return terminal == nullptr ||
               !IsPaymentAuditPrefixAuthenticated(*terminal);
    };
    return btcc_unresolved(btcc.active) ||
           btcc_unresolved(btcc.prospective) ||
           payment_unresolved(payment.active) ||
           payment_unresolved(payment.prospective);
}

void CChainLocksHandler::RefreshPQHistoryAuthState()
{
    bool pending{true};
    {
        LOCK(cs_main);
        pending = HasPendingPQHistoryAuthentication();
        if (!m_chainman.PublishPQHistoryAuthState(
                pending ? PQHistoryAuthState::PENDING
                        : PQHistoryAuthState::READY)) {
            DisableShareAdmission();
            m_enforced.store(false);
            m_chainman.GetNotifications().fatalError(
                "PQ history authentication appeared after public IBD "
                "completed");
            return;
        }
    }
    if (!pending) {
        const bool completed_before{
            m_chainman.HasCompletedInitialBlockDownload()};
        m_chainman.MaybeCompleteInitialBlockDownload();
        if (completed_before) {
            (void)m_chainman.MaybeStartNEVMNetwork();
        }
    }
}

void CChainLocksHandler::QuarantineInvalidPersistedChainLock(
    const std::string& reason)
{
    bool notify{false};
    {
        LOCK(m_persisted_mutex);
        if (!m_persisted_invalid) {
            m_persisted_invalid = true;
            notify = true;
        }
    }
    DisableShareAdmission();
    m_enforced.store(false);
    if (!notify) return;

    const std::string message{strprintf(
        "Persisted PQ ChainLock is definitively invalid (%s); the node is "
        "quarantined and must not continue without resolving its durable "
        "finality state",
        reason)};
    LogPrintf("CChainLocksHandler::%s -- %s\n", __func__, message);
    m_chainman.GetNotifications().fatalError(message);
}

bool CChainLocksHandler::AlreadyHave(const uint256& logical_id) const
{
    if (!m_store || logical_id.IsNull()) return false;
    return static_cast<bool>(m_store->GetByLogicalId(logical_id));
}

bool CChainLocksHandler::GetChainLockByHash(const uint256& logical_id,
                                            CChainLockSig& result) const
{
    if (!m_store || logical_id.IsNull()) return false;
    const auto found{m_store->GetByLogicalId(logical_id)};
    if (!found) return false;
    result = *found;
    return true;
}

CChainLockSigCPtr CChainLocksHandler::GetMostRecentChainLock() const
{
    return GetBestChainLock();
}

CChainLockSigCPtr CChainLocksHandler::GetBestChainLock() const
{
    return m_chainman.IsPQParticipationAllowed() && m_store
        ? m_store->GetBest()
        : nullptr;
}

pq::VerifiedRosterSetPtr
CChainLocksHandler::GetVerifiedRosterSetForAccepted(
    const pq::FinalChainLock& accepted,
    int32_t target_height,
    const CBlockIndex& target,
    pq::QuorumBuildError* error) const
{
    if (error != nullptr) *error = pq::QuorumBuildError::NONE;
    const auto best{m_store ? m_store->GetBestRecord()
                            : std::nullopt};
    const auto context{best ? best->verification_context
                            : pq::PreparedChainLockContextPtr{}};
    if (!m_config || !best || !best->certificate ||
        *best->certificate != accepted || !context ||
        context->Statement() != accepted.statement ||
        target_height != target.nHeight ||
        target_height < accepted.statement.height) {
        if (error != nullptr) *error = pq::QuorumBuildError::INVALID_ARGUMENT;
        return nullptr;
    }
    const CBlockIndex* accepted_index{
        target.GetAncestor(accepted.statement.height)};
    const auto active_epochs{pq::ActiveEpochsAtHeight(
        m_config->chainlock_schedule, target_height)};
    if (accepted_index == nullptr ||
        accepted_index->GetBlockHash() != accepted.statement.block_hash ||
        !active_epochs ||
        !accepted.statement.roster_beacons.active.IsForNewestEpoch(
            active_epochs->back().epoch)) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR;
        }
        return nullptr;
    }
    for (std::size_t slot{0}; slot < pq::ACTIVE_QUORUMS; ++slot) {
        const auto& descriptor{context->Rosters()[slot].descriptor};
        const CBlockIndex* base{target.GetAncestor(
            (*active_epochs)[slot].base_height)};
        if (descriptor.epoch != (*active_epochs)[slot].epoch ||
            descriptor.base_height != (*active_epochs)[slot].base_height ||
            base == nullptr || descriptor.base_hash != base->GetBlockHash()) {
            if (error != nullptr) {
                *error = pq::QuorumBuildError::INVALID_FROZEN_ROSTER;
            }
            return nullptr;
        }
    }
    return context->RosterSetPtr();
}

std::size_t CChainLocksHandler::GetPaymentAuditRuntimePinnedBytes() const
{
    LOCK(m_payment_audit_mutex);
    std::size_t bytes{memusage::DynamicUsage(
        m_payment_audit_supplied_to_peer)};
    for (const auto& [peer, supplied] :
         m_payment_audit_supplied_to_peer) {
        (void)peer;
        bytes += memusage::DynamicUsage(supplied);
    }

    std::set<const pq::FrozenQuorumRosters*> counted_rosters;
    std::set<const pq::VerifiedRosterSet*> counted_roster_sets;
    std::set<const pq::PreparedChainLockContext*> counted_chain_contexts;
    std::set<const pq::PreparedPaymentAuditContext*> counted_audit_contexts;
    const auto add_roster = [&](const pq::FrozenQuorumRostersPtr& rosters) {
        if (rosters && counted_rosters.insert(rosters.get()).second) {
            bytes += sizeof(pq::FrozenQuorumRosters);
        }
    };
    const auto add_chain_context = [&](
        const pq::PreparedChainLockContextPtr& context) {
        if (!context ||
            !counted_chain_contexts.insert(context.get()).second) {
            return;
        }
        bytes += sizeof(pq::PreparedChainLockContext);
        if (counted_roster_sets.insert(context->RosterSetPtr().get()).second) {
            bytes += sizeof(pq::VerifiedRosterSet);
        }
        add_roster(context->RostersPtr());
    };
    const auto add_audit_context = [&](
        const pq::PreparedPaymentAuditContextPtr& context) {
        if (!context ||
            !counted_audit_contexts.insert(context.get()).second) {
            return;
        }
        bytes += sizeof(pq::PreparedPaymentAuditContext);
        add_chain_context(context->SealContextPtr());
    };

    if (m_payment_audit_runtime) {
        const auto& runtime{*m_payment_audit_runtime};
        bytes += sizeof(PaymentAuditResponseRuntime);
        add_roster(runtime.signing_rosters);
        if (runtime.relay_plan) {
            bytes += sizeof(PQRelayPlan) +
                     memusage::DynamicUsage(
                         runtime.relay_plan->authorized_recipients) +
                     memusage::DynamicUsage(
                         runtime.relay_plan->relay_members);
        }
        if (runtime.seal_chainlock) {
            bytes += memusage::DynamicUsage(
                runtime.seal_chainlock->signatures);
        }
        if (runtime.collector) {
            bytes += runtime.collector->MemoryUsage();
            add_audit_context(runtime.collector->GetPreparedContext());
        }
        if (runtime.finalized && runtime.finalized->proof) {
            bytes += sizeof(pq::CollectedPaymentAuditFinalization) +
                     memusage::DynamicUsage(
                         runtime.finalized->proof->Certificate()
                             .report_witnesses);
            add_audit_context(runtime.finalized->proof->ContextPtr());
        }
    }

    if (m_payment_audit_network_context) {
        bytes += sizeof(PaymentAuditNetworkContext) +
                 memusage::DynamicUsage(
                     m_payment_audit_network_context->rows);
        for (const auto& row : m_payment_audit_network_context->rows) {
            add_chain_context(row.response_context);
            bytes += memusage::DynamicUsage(row.active_relays);
            if (row.relay_plan) {
                bytes += sizeof(PQRelayPlan) +
                         memusage::DynamicUsage(
                             row.relay_plan->authorized_recipients) +
                         memusage::DynamicUsage(
                             row.relay_plan->relay_members);
            }
        }
    }
    return bytes;
}

const CBlockIndex* CChainLocksHandler::GetBestChainLockIndex() const
{
    if (!m_chainman.IsPQParticipationAllowed()) return nullptr;
    const auto best{m_store ? m_store->GetBestRecord() : std::nullopt};
    if (!best) return nullptr;
    LOCK(cs_main);
    const CBlockIndex* index{
        m_chainman.m_blockman.LookupBlockIndex(
            best->metadata.statement.block_hash)};
    return index != nullptr &&
            index->nHeight == best->metadata.statement.height
        ? index
        : nullptr;
}

std::optional<evo::AuxiliaryHistoryGCBlockIdentity>
CChainLocksHandler::GetDurableFinalityTargetForStartup() const
{
    if (!ShouldExposeDurableFinalityRecoveryMetadata(
            m_config.has_value(), m_persistence != nullptr,
            m_persistence_failed.load())) {
        return std::nullopt;
    }
    try {
        const auto best{m_persistence->GetFinalityState().best};
        if (!best || !best->IsInternallyConsistent(m_genesis_hash)) {
            return std::nullopt;
        }
        return evo::AuxiliaryHistoryGCBlockIdentity{
            best->statement.height, best->statement.block_hash};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool CChainLocksHandler::GetDurableFinalityRecoveryFloor(
    const CBlockIndex*& active_floor,
    const CBlockIndex*& durable_target,
    std::string& error,
    DurableFinalityRecoveryMode mode,
    bool* replay_target_pending) const
{
    AssertLockHeld(cs_main);
    active_floor = nullptr;
    durable_target = nullptr;
    error.clear();
    if (replay_target_pending != nullptr) {
        *replay_target_pending = false;
    }
    try {
        if (m_config &&
            (!m_persistence || !m_payment_audit_store ||
             m_persistence_failed.load())) {
            error = "configured finality persistence is unavailable while "
                    "resolving the durable recovery floor";
            return false;
        }
        if (m_payment_audit_store &&
            !m_payment_audit_store->IsHealthy()) {
            error = "payment-audit archive is unhealthy while resolving the "
                    "durable finality recovery floor";
            return false;
        }
        const auto durable{m_persistence
                               ? m_persistence->GetFinalityState().best
                               : std::nullopt};
        const auto checkpoint{m_payment_audit_store
                                  ? m_payment_audit_store->GetPruneCheckpoint()
                                  : std::nullopt};
        if (m_payment_audit_store &&
            !m_payment_audit_store->IsHealthy()) {
            error = "payment-audit archive failed while reading the durable "
                    "finality recovery floor";
            return false;
        }
        if (!durable) {
            if (checkpoint) {
                error = "payment-audit checkpoint exists without its durable "
                        "authorizing ChainLock";
                return false;
            }
            return true;
        }
        if (!durable->IsInternallyConsistent(m_genesis_hash)) {
            error = "durable ChainLock recovery floor is malformed";
            return false;
        }
        if (checkpoint && !checkpoint->IsStructurallyValid()) {
            error = "durable payment-audit checkpoint is malformed";
            return false;
        }

        const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
            durable->statement.block_hash)};
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        const bool block_index_replay{
            mode == DurableFinalityRecoveryMode::BLOCK_INDEX_REPLAY &&
            node::fReindex.load() && !checkpoint};
        if (target == nullptr) {
            if (block_index_replay && replay_target_pending != nullptr) {
                *replay_target_pending = true;
                return true;
            }
            error = "durable ChainLock recovery target is unavailable or "
                    "not fully validated";
            return false;
        }
        const bool fully_validated{
            target->IsValid(BLOCK_VALID_SCRIPTS)};
        const bool provisional_replay_target{
            block_index_replay &&
            (target->nStatus & BLOCK_HAVE_DATA) &&
            target->IsValid(BLOCK_VALID_TRANSACTIONS) &&
            target->HaveNumChainTxs()};
        if (target->nHeight != durable->statement.height ||
            (target->nStatus & BLOCK_FAILED_MASK) ||
            target->IsAssumedValid() ||
            (!fully_validated && !provisional_replay_target) ||
            active_tip == nullptr) {
            error = "durable ChainLock recovery target is unavailable or "
                    "not fully validated";
            return false;
        }
        const CBlockIndex* resolved_active_floor{
            m_chainman.ActiveChain().Contains(target)
                ? target
                : LastCommonAncestor(active_tip, target)};
        if (resolved_active_floor == nullptr ||
            !m_chainman.ActiveChain().Contains(resolved_active_floor)) {
            error = "durable ChainLock recovery target has no active-chain "
                    "fork";
            return false;
        }
        if (checkpoint) {
            const CBlockIndex* authorizer{
                m_chainman.m_blockman.LookupBlockIndex(
                    checkpoint->authorizing_target_hash)};
            const CBlockIndex* covered{
                m_chainman.m_blockman.LookupBlockIndex(
                    checkpoint->covered_through_hash)};
            const auto authorizer_receipt{
                authorizer == nullptr
                    ? std::optional<pq::PaymentAuditReceiptState>{}
                    : IndexedPaymentAuditReceiptState(*authorizer)};
            const bool durable_is_authorizer{
                target == authorizer};
            if (authorizer == nullptr ||
                authorizer->nHeight !=
                    checkpoint->authorizing_target_height ||
                (authorizer->nStatus & BLOCK_FAILED_MASK) ||
                authorizer->IsAssumedValid() ||
                !authorizer->IsValid(BLOCK_VALID_SCRIPTS) ||
                !HasFullReceiptIndexProvenance(*authorizer) ||
                !m_chainman.ActiveChain().Contains(authorizer) ||
                covered == nullptr ||
                covered->nHeight != checkpoint->covered_through_height ||
                authorizer->nHeight < covered->nHeight ||
                authorizer->GetAncestor(covered->nHeight) != covered ||
                !authorizer_receipt ||
                *authorizer_receipt !=
                    checkpoint->authenticated_receipt_state ||
                authorizer->pqPaymentProbationStateHash !=
                    checkpoint->authenticated_probation_state_hash ||
                target->nHeight < authorizer->nHeight ||
                target->GetAncestor(authorizer->nHeight) != authorizer ||
                resolved_active_floor->nHeight < authorizer->nHeight ||
                resolved_active_floor->GetAncestor(authorizer->nHeight) !=
                    authorizer ||
                (durable_is_authorizer &&
                 (durable->logical_id !=
                      checkpoint->authorizing_chainlock_logical_id ||
                  durable->witness_id !=
                      checkpoint->authorizing_chainlock_witness_id))) {
                error = "payment-audit checkpoint is not authorized by the "
                        "durable winner's active-chain ancestry";
                return false;
            }
        }
        active_floor = resolved_active_floor;
        durable_target = target;
        return true;
    } catch (const std::exception& exception) {
        error = strprintf("durable finality recovery floor unavailable: %s",
                          exception.what());
        return false;
    }
}

bool CChainLocksHandler::GetRecentChainLockByHeight(
    int32_t height, CChainLockSig& result) const
{
    if (!m_store) return false;
    const auto found{m_store->GetByHeight(height)};
    if (!found) return false;
    result = *found;
    return true;
}

bool CChainLocksHandler::AlreadyHavePaymentAudit(
    const uint256& witness_id) const
{
    return m_payment_audit_store && !witness_id.IsNull() &&
           m_payment_audit_store->Has(witness_id);
}

bool CChainLocksHandler::GetPaymentAuditByHash(
    const uint256& witness_id, pq::FinalPaymentAudit& result) const
{
    if (!m_payment_audit_store || witness_id.IsNull()) return false;
    const auto found{m_payment_audit_store->Get(witness_id)};
    if (!found) return false;
    result = *found;
    return true;
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::ClassifyPaymentAuditArchiveRead(
    bool store_available, bool healthy_before_read,
    bool witness_found, bool healthy_after_read) noexcept
{
    if (!store_available) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    if (!healthy_before_read || !healthy_after_read) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    return witness_found
        ? PaymentAuditReceiptCertificateStatus::VERIFIED
        : PaymentAuditReceiptCertificateStatus::MISSING;
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::ClassifyPaymentAuditArchiveMutation(
    pq::PaymentAuditStoreResult result) noexcept
{
    switch (result) {
    case pq::PaymentAuditStoreResult::ACCEPTED:
    case pq::PaymentAuditStoreResult::DUPLICATE_WITNESS:
        return PaymentAuditReceiptCertificateStatus::VERIFIED;
    case pq::PaymentAuditStoreResult::INVALID:
    case pq::PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL:
    case pq::PaymentAuditStoreResult::CORRUPT:
    case pq::PaymentAuditStoreResult::DATABASE_ERROR:
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
}

bool CChainLocksHandler::IsPaymentAuditLocalRosterBuildError(
    pq::QuorumBuildError error) noexcept
{
    switch (error) {
    case pq::QuorumBuildError::INVALID_MASTERNODE_STATE:
    case pq::QuorumBuildError::INVALID_OPERATOR_STATE:
    case pq::QuorumBuildError::DUPLICATE_OPERATOR_STATE:
    case pq::QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH:
    case pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED:
    case pq::QuorumBuildError::SNAPSHOT_MISMATCH:
    case pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR:
    case pq::QuorumBuildError::INVALID_FROZEN_ROSTER:
        return true;
    default:
        return false;
    }
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::PinPaymentAuditReceiptCertificate(
    uint32_t epoch, const uint256& witness_id)
{
    if (!m_chainman.IsPQParticipationAllowed()) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    if (witness_id.IsNull()) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (!m_payment_audit_store) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    if (!m_payment_audit_store->IsHealthy()) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const auto result{m_payment_audit_store->PinReferencedWitness(
        epoch, witness_id)};
    return ClassifyPaymentAuditArchiveMutation(result);
}

pq::PaymentAuditReceipt
CChainLocksHandler::GetPaymentAuditReceiptForCarrier(
    int32_t carrier_height,
    const CBlockIndex& carrier_parent) const
{
    AssertLockHeld(cs_main);
    pq::PaymentAuditReceipt null_receipt;
    if (IsPaymentAuditPresealActive()) return null_receipt;
    if (!m_payment_audit_store || !m_config ||
        carrier_parent.nHeight + 1 != carrier_height) {
        return null_receipt;
    }
    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto epoch{
        pq::PaymentAuditReceiptSlotEpoch(schedule_config, carrier_height)};
    if (!epoch) return null_receipt;
    const auto window{pq::BuildPaymentAuditCarrierWindow(
        schedule_config, *epoch)};
    if (!window || !window->Contains(carrier_height)) {
        return null_receipt;
    }

    const auto make_cache_key = [&](uint64_t archive_revision) {
        return PaymentAuditReceiptCache::Key{
            carrier_parent.GetBlockHash(), carrier_parent.nHeight,
            carrier_parent.pqPaymentProbationStateHash, carrier_height,
            *epoch, archive_revision};
    };
    const auto observed_revision{
        m_payment_audit_store->ObserveCandidateRevision()};
    if (!observed_revision) return null_receipt;
    auto cache_key{make_cache_key(*observed_revision)};
    if (const auto cached{
            m_payment_audit_receipt_cache.Get(cache_key)}) {
        return m_payment_audit_store->IsCandidateRevisionCurrent(
                   *observed_revision)
            ? *cached
            : null_receipt;
    }

    const auto candidates{
        m_payment_audit_candidate_metadata_cache.GetOrBuild(
            *m_payment_audit_store, m_genesis_hash, *epoch)};
    if (!candidates || candidates->epoch != *epoch ||
        candidates->candidate_revision == 0) {
        return null_receipt;
    }
    cache_key.archive_revision = candidates->candidate_revision;
    if (const auto cached{
            m_payment_audit_receipt_cache.Get(cache_key)}) {
        return m_payment_audit_store->IsCandidateRevisionCurrent(
                   candidates->candidate_revision)
            ? *cached
            : null_receipt;
    }

    for (const auto& candidate : candidates->ordered_candidates) {
        const auto stored{
            m_payment_audit_store->GetVerifiedWithCandidateRevision(
                candidate.witness_id)};
        if (!stored ||
            stored->Revision() != candidates->candidate_revision) {
            return null_receipt;
        }
        const auto& audit{stored->Audit()};
        const auto& statement{audit.statement};
        const auto classification{pq::ClassifyPaymentAuditReports(audit)};
        if (!classification || stored->LogicalId() != candidate.logical_id ||
            stored->WitnessId() != candidate.witness_id ||
            statement != candidate.statement ||
            pq::GetPaymentAuditCommitmentHash(
                m_genesis_hash, statement.commitment) !=
                candidate.commitment_hash ||
            pq::GetPaymentAuditResultHash(
                m_genesis_hash, audit, *classification) !=
                candidate.result_hash ||
            classification->online_members != candidate.online_members) {
            return null_receipt;
        }
        if (statement.commitment.seed.epoch != *epoch) continue;
        const CBlockIndex* seal{carrier_parent.GetAncestor(
            statement.commitment.seal_height)};
        if (seal == nullptr ||
            seal->GetBlockHash() !=
                statement.seal_statement.block_hash ||
            statement.commitment.previous_probation_state_hash !=
                carrier_parent.pqPaymentProbationStateHash) {
            continue;
        }
        if (candidate.logical_id.IsNull() || candidate.witness_id.IsNull() ||
            candidate.commitment_hash.IsNull() ||
            candidate.result_hash.IsNull()) {
            continue;
        }
        pq::FrozenQuorumRoster subject;
        uint64_t roster_source_generation{0};
        int32_t reconstruction_floor{-1};
        const auto replay_status{BuildStoredVerifiedPaymentAuditSubject(
            *stored, carrier_parent, carrier_height, subject,
            roster_source_generation, reconstruction_floor)};
        if (replay_status ==
            PaymentAuditReceiptCertificateStatus::INVALID) {
            continue;
        }
        if (replay_status !=
            PaymentAuditReceiptCertificateStatus::VERIFIED) {
            return null_receipt;
        }
        const pq::RosterBeaconSeed* subject_beacon{
            pq::FindRosterBeaconSeed(
                statement.seal_statement.roster_beacons.active,
                *epoch)};
        if (subject_beacon == nullptr) continue;
        const auto transition{DerivePaymentAuditProbationTransition(
            statement.commitment, subject, carrier_parent, carrier_height,
            candidate.result_hash, classification->online_members)};
        if (!transition ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation)) {
            continue;
        }
        const pq::PaymentAuditReceipt receipt{
            pq::PAYMENT_AUDIT_RECEIPT_VERSION,
            1,
            *epoch,
            statement.commitment.seal_height,
            statement.seal_statement.block_hash,
            carrier_height,
            candidate.logical_id,
            candidate.witness_id,
            candidate.commitment_hash,
            candidate.result_hash,
            transition->Result().StateHash(),
            *subject_beacon,
            candidate.online_members};
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation)) {
            return null_receipt;
        }
        const auto published{
            m_payment_audit_receipt_cache.Publish(cache_key, receipt)};
        if (!published ||
            !m_payment_audit_store->IsCandidateRevisionCurrent(
                candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation)) {
            return null_receipt;
        }
        return *published;
    }
    return null_receipt;
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::BuildStoredVerifiedPaymentAuditSubject(
    const pq::StoredVerifiedPaymentAudit& stored,
    const CBlockIndex& carrier_parent,
    int32_t carrier_height,
    pq::FrozenQuorumRoster& subject,
    uint64_t& roster_source_generation,
    int32_t& reconstruction_floor) const
{
    AssertLockHeld(cs_main);
    subject = {};
    roster_source_generation = 0;
    reconstruction_floor = -1;
    if (!m_config || !m_quorum_build_config) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const auto& audit{stored.Audit()};
    const auto& statement{audit.statement};
    if (stored.Revision() == 0 || stored.LogicalId().IsNull() ||
        stored.WitnessId().IsNull() || !audit.IsStructurallyValid() ||
        audit.GetLogicalId(m_genesis_hash) != stored.LogicalId() ||
        audit.GetWitnessId(m_genesis_hash) != stored.WitnessId() ||
        !pq::IsSigningRosterAuthorizationMask(
            stored.AuthorizationMask()) ||
        (audit.selected_quorum_mask &
         static_cast<uint8_t>(~stored.AuthorizationMask())) != 0) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (carrier_height < 0 || carrier_parent.nHeight < 0 ||
        static_cast<int64_t>(carrier_parent.nHeight) + 1 !=
            carrier_height ||
        (carrier_parent.nStatus & BLOCK_FAILED_MASK)) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (m_chainman.IsSnapshotActive() &&
        !m_chainman.IsSnapshotValidated()) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto slot_epoch{pq::PaymentAuditReceiptSlotEpoch(
        schedule_config, carrier_height)};
    const auto carrier_window{pq::BuildPaymentAuditCarrierWindow(
        schedule_config, statement.commitment.seed.epoch)};
    const auto epoch_schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, statement.commitment.seed.epoch)};
    const auto round{
        epoch_schedule
            ? pq::SelectPaymentAuditRound(
                  schedule_config, *epoch_schedule, m_genesis_hash,
                  statement.commitment.subject_descriptor_hash,
                  statement.commitment.seed)
            : std::nullopt};
    const auto expected_seal{pq::NextEligibleChainLockTargetHeight(
        m_config->chainlock_schedule,
        statement.seal_statement.previous_chainlock_height)};
    if (!slot_epoch || *slot_epoch != statement.commitment.seed.epoch ||
        !carrier_window || !carrier_window->Contains(carrier_height) ||
        !round || !expected_seal ||
        statement.commitment.seal_height != *expected_seal ||
        round->selected_row != statement.commitment.selected_row ||
        round->response_height != statement.commitment.response_height ||
        round->deadline_height != statement.commitment.deadline_height ||
        round->seal_height != statement.commitment.seal_height ||
        statement.seal_statement.previous_chainlock_height <
            m_config->activation_predecessor_height ||
        carrier_parent.pqPaymentProbationStateHash !=
            statement.commitment.previous_probation_state_hash) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }

    const CBlockIndex* seal{m_chainman.m_blockman.LookupBlockIndex(
        statement.seal_statement.block_hash)};
    const auto seal_status{ClassifyPaymentAuditSealContextCached(
        seal, round->seal_height,
        statement.seal_statement.previous_chainlock_height,
        statement.seal_statement.previous_chainlock_hash,
        PaymentAuditSealValidation::THRESHOLD_ATTESTED_HISTORY)};
    if (seal_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (seal_status != PaymentAuditContextStatus::READY || seal == nullptr) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (carrier_parent.GetAncestor(seal->nHeight) != seal) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }

    const CBlockIndex* response{seal->GetAncestor(round->response_height)};
    const auto response_status{ClassifyPaymentAuditResponseContext(
        response, /*require_block_data=*/false)};
    if (response_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (response_status != PaymentAuditContextStatus::READY ||
        response == nullptr) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const auto indexed_btcc{IndexedBTCCReceiptState(*seal)};
    const auto indexed_audit{IndexedPaymentAuditReceiptState(*seal)};
    const auto seed_context{GetPaymentAuditSeedReceiptContext(
        m_genesis_hash, schedule_config, *epoch_schedule, *seal)};
    if (!indexed_btcc || !indexed_audit) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (seed_context.status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (seed_context.status != PaymentAuditContextStatus::READY) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    pq::BTCCValidationError btcc_error{pq::BTCCValidationError::NONE};
    if (*indexed_btcc != statement.seal_statement.btcc_receipt_state ||
        *indexed_audit !=
            statement.seal_statement.payment_audit_receipt_state ||
        seal->pqPaymentProbationStateHash !=
            statement.seal_statement.payment_probation_state_hash ||
        !seed_context.seed_point ||
        *seed_context.seed_point != statement.commitment.seed.anchor ||
        !pq::ValidateBTCCursorTransition(
            m_config->btcc_schedule, *seal,
            statement.seal_statement.previous_btcc_cursor,
            statement.seal_statement.accepted_btcc_cursor,
            statement.seal_statement.btcc_advance, &btcc_error)) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (m_store) {
        const auto predecessor{m_store->GetByHeight(
            statement.seal_statement.previous_chainlock_height)};
        if (predecessor &&
            (predecessor->statement.block_hash !=
                 statement.seal_statement.previous_chainlock_hash ||
             predecessor->statement.accepted_btcc_cursor !=
                 statement.seal_statement.previous_btcc_cursor)) {
            return PaymentAuditReceiptCertificateStatus::INVALID;
        }
    }

    const pq::RosterBeaconSeed* subject_beacon{
        pq::FindRosterBeaconSeed(
            statement.seal_statement.roster_beacons.active,
            statement.commitment.subject_epoch)};
    if (subject_beacon == nullptr ||
        subject_beacon->anchor_kind !=
            pq::RosterBeaconAnchorKind::NORMAL) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    const auto roster_cache{GetQuorumRosterCache(
        &roster_source_generation)};
    if (!roster_cache) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    std::unique_ptr<pq::FrozenQuorumRoster> rebuilt;
    try {
        rebuilt = BuildHistoricalFrozenRoster(
            m_genesis_hash, *m_quorum_build_config, *roster_cache,
            statement.commitment.subject_epoch, *response,
            *subject_beacon, &build_error);
    } catch (const std::exception&) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (!rebuilt) {
        return IsPaymentAuditLocalRosterBuildError(build_error)
            ? PaymentAuditReceiptCertificateStatus::LOCAL_ERROR
            : PaymentAuditReceiptCertificateStatus::INVALID;
    }
    const auto& descriptor{rebuilt->descriptor};
    if (descriptor.epoch != statement.commitment.subject_epoch ||
        descriptor.base_hash !=
            statement.commitment.subject_quorum_base_hash ||
        descriptor.valid_members !=
            statement.commitment.subject_valid_members ||
        pq::GetPaymentAuditDescriptorHash(m_genesis_hash, descriptor) !=
            statement.commitment.subject_descriptor_hash) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }

    reconstruction_floor = std::min(
        statement.seal_statement.previous_chainlock_height,
        descriptor.snapshot_height);
    const auto provenance_status{ClassifyHistoricalReceiptIndexRangeCached(
        carrier_parent, reconstruction_floor)};
    if (provenance_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (provenance_status != PaymentAuditContextStatus::READY) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    subject = std::move(*rebuilt);
    return PaymentAuditReceiptCertificateStatus::VERIFIED;
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::RecheckVerifiedPaymentAuditReceiptTransition(
    const VerifiedPaymentAuditReceiptTransition& verified,
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier) const
{
    AssertLockHeld(cs_main);
    if (receipt.IsNull() || receipt != verified.m_receipt ||
        !receipt.IsStructurallyValid() ||
        !verified.m_statement.IsStructurallyValid() ||
        carrier.nHeight != receipt.carrier_height ||
        carrier.pprev == nullptr ||
        carrier.pprev->nHeight != verified.m_carrier_parent_height ||
        carrier.pprev->GetBlockHash() !=
            verified.m_carrier_parent_hash ||
        carrier.pprev->pqPaymentProbationStateHash !=
            verified.m_parent_probation_state_hash) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (!m_config || !m_quorum_build_config ||
        !m_payment_audit_store || deterministicMNManager == nullptr) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    if (!m_payment_audit_store->IsHealthy() ||
        !m_payment_audit_store->IsCandidateRevisionCurrent(
            verified.m_archive_revision) ||
        !IsQuorumRosterSourceGenerationCurrent(
            verified.m_roster_source_generation) ||
        deterministicMNManager->PaymentProbationStateViewGeneration() !=
            verified.m_probation_state_view_generation) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto carrier_status{ClassifyPaymentAuditReceiptCarrierContext(
        receipt, carrier, schedule_config)};
    if (carrier_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (carrier_status != PaymentAuditContextStatus::READY ||
        (m_chainman.IsSnapshotActive() &&
         !m_chainman.IsSnapshotValidated())) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const auto& statement{verified.m_statement};
    const auto expected_seal{pq::NextEligibleChainLockTargetHeight(
        m_config->chainlock_schedule,
        statement.seal_statement.previous_chainlock_height)};
    const auto epoch_schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, statement.commitment.seed.epoch)};
    const auto round{
        epoch_schedule
            ? pq::SelectPaymentAuditRound(
                  schedule_config, *epoch_schedule, m_genesis_hash,
                  statement.commitment.subject_descriptor_hash,
                  statement.commitment.seed)
            : std::nullopt};
    const pq::RosterBeaconSeed* receipt_subject_beacon{
        pq::FindRosterBeaconSeed(
            statement.seal_statement.roster_beacons.active,
            receipt.epoch)};
    if (!expected_seal || !round ||
        statement.commitment.seal_height != *expected_seal ||
        round->selected_row != statement.commitment.selected_row ||
        round->response_height != statement.commitment.response_height ||
        round->deadline_height != statement.commitment.deadline_height ||
        round->seal_height != statement.commitment.seal_height ||
        receipt.epoch != statement.commitment.seed.epoch ||
        receipt.seal_height != statement.commitment.seal_height ||
        receipt.seal_block_hash != statement.seal_statement.block_hash ||
        receipt.audit_logical_id != pq::GetPaymentAuditLogicalId(
            m_genesis_hash, statement) ||
        receipt.commitment_hash != pq::GetPaymentAuditCommitmentHash(
            m_genesis_hash, statement.commitment) ||
        receipt_subject_beacon == nullptr ||
        *receipt_subject_beacon != receipt.subject_roster_beacon ||
        verified.m_reconstruction_floor < 0 ||
        !pq::IsSigningRosterAuthorizationMask(
            verified.m_authorization_mask)) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }

    if (carrier.nStatus & BLOCK_FAILED_MASK) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    const CBlockIndex* seal{m_chainman.m_blockman.LookupBlockIndex(
        statement.seal_statement.block_hash)};
    const auto seal_status{ClassifyPaymentAuditSealContextCached(
        seal, round->seal_height,
        statement.seal_statement.previous_chainlock_height,
        statement.seal_statement.previous_chainlock_hash,
        PaymentAuditSealValidation::THRESHOLD_ATTESTED_HISTORY)};
    if (seal_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (seal_status != PaymentAuditContextStatus::READY || seal == nullptr) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (carrier.GetAncestor(seal->nHeight) != seal) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }

    const CBlockIndex* response{seal->GetAncestor(round->response_height)};
    const auto response_status{ClassifyPaymentAuditResponseContext(
        response, /*require_block_data=*/false)};
    if (response_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (response_status != PaymentAuditContextStatus::READY) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const auto provenance_status{ClassifyHistoricalReceiptIndexRangeCached(
        *carrier.pprev, verified.m_reconstruction_floor)};
    if (provenance_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (provenance_status != PaymentAuditContextStatus::READY) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }

    const auto indexed_btcc{IndexedBTCCReceiptState(*seal)};
    const auto indexed_audit{IndexedPaymentAuditReceiptState(*seal)};
    const auto seed_context{GetPaymentAuditSeedReceiptContext(
        m_genesis_hash, schedule_config, *epoch_schedule, *seal)};
    if (!indexed_btcc || !indexed_audit) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (seed_context.status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (seed_context.status != PaymentAuditContextStatus::READY) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    pq::BTCCValidationError btcc_error{pq::BTCCValidationError::NONE};
    if (*indexed_btcc != statement.seal_statement.btcc_receipt_state ||
        *indexed_audit !=
            statement.seal_statement.payment_audit_receipt_state ||
        seal->pqPaymentProbationStateHash !=
            statement.seal_statement.payment_probation_state_hash ||
        !seed_context.seed_point ||
        *seed_context.seed_point != statement.commitment.seed.anchor ||
        !pq::ValidateBTCCursorTransition(
            m_config->btcc_schedule, *seal,
            statement.seal_statement.previous_btcc_cursor,
            statement.seal_statement.accepted_btcc_cursor,
            statement.seal_statement.btcc_advance, &btcc_error) ||
        carrier.pprev->pqPaymentProbationStateHash !=
            statement.commitment.previous_probation_state_hash) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (m_store) {
        const auto predecessor{m_store->GetByHeight(
            statement.seal_statement.previous_chainlock_height)};
        if (predecessor &&
            (predecessor->statement.block_hash !=
                 statement.seal_statement.previous_chainlock_hash ||
             predecessor->statement.accepted_btcc_cursor !=
                 statement.seal_statement.previous_btcc_cursor)) {
            return PaymentAuditReceiptCertificateStatus::INVALID;
        }
    }

    const pq::PQPaymentAuditReceiptIdentity expected_transition_receipt{
        receipt.epoch, receipt.carrier_height, receipt.result_hash};
    const auto& transition{verified.m_transition};
    if (deterministicMNManager == nullptr ||
        deterministicMNManager->PaymentProbationStateViewGeneration() !=
            verified.m_probation_state_view_generation ||
        transition.ProvenanceGeneration() !=
            verified.m_probation_state_view_generation ||
        transition.PreviousStateHash() !=
            verified.m_parent_probation_state_hash ||
        transition.AppliedReceipt() != expected_transition_receipt ||
        transition.Result().StateHash() !=
            receipt.next_probation_state_hash) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    return PaymentAuditReceiptCertificateStatus::VERIFIED;
}

CChainLocksHandler::PaymentAuditReceiptCertificateStatus
CChainLocksHandler::CheckPaymentAuditReceiptCertificate(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier,
    VerifiedPaymentAuditReceiptTransitionPtr& transition_out) const
{
    AssertLockHeld(cs_main);
    transition_out.reset();
    if (receipt.IsNull()) {
        return PaymentAuditReceiptCertificateStatus::VERIFIED;
    }
    if (!m_chainman.IsPQParticipationAllowed()) {
        return PaymentAuditReceiptCertificateStatus::MISSING;
    }
    if (!receipt.IsStructurallyValid() ||
        carrier.nHeight != receipt.carrier_height) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (!m_config || !m_quorum_build_config) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto carrier_status{ClassifyPaymentAuditReceiptCarrierContext(
        receipt, carrier, schedule_config)};
    if (carrier_status == PaymentAuditContextStatus::INVALID) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (carrier_status == PaymentAuditContextStatus::LOCAL_ERROR) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (!m_payment_audit_store) {
        return PaymentAuditReceiptCertificateStatus::UNAVAILABLE;
    }
    if (carrier.pprev == nullptr) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    const auto make_cache_key = [&](uint64_t archive_revision,
                                    uint64_t roster_source_generation,
                                    uint64_t probation_view_generation) {
        return VerifiedPaymentAuditReceiptTransitionCache::Key{
            carrier.pprev->GetBlockHash(), carrier.pprev->nHeight,
            carrier.pprev->pqPaymentProbationStateHash,
            carrier.nHeight, receipt, archive_revision,
            roster_source_generation, probation_view_generation};
    };
    const auto try_cached = [&](uint64_t archive_revision,
                                uint64_t roster_source_generation,
                                uint64_t probation_view_generation)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
        -> std::optional<PaymentAuditReceiptCertificateStatus> {
        const auto cached{m_verified_payment_audit_transition_cache->Get(
            make_cache_key(archive_revision,
                           roster_source_generation,
                           probation_view_generation))};
        if (!cached) return std::nullopt;
        const auto status{RecheckVerifiedPaymentAuditReceiptTransition(
            *cached, receipt, carrier)};
        if (status != PaymentAuditReceiptCertificateStatus::VERIFIED) {
            return status;
        }
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                archive_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation) ||
            deterministicMNManager == nullptr ||
            deterministicMNManager->PaymentProbationStateViewGeneration() !=
                probation_view_generation) {
            return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
        }
        LogPrint(BCLog::CHAINLOCKS,
                 "reused verified PQ payment-audit receipt transition "
                 "for carrier %d\n",
                 carrier.nHeight);
        transition_out = cached;
        return PaymentAuditReceiptCertificateStatus::VERIFIED;
    };
    const auto initial_revision{
        m_payment_audit_store->ObserveCandidateRevision()};
    if (deterministicMNManager == nullptr) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const uint64_t initial_probation_generation{
        deterministicMNManager->PaymentProbationStateViewGeneration()};
    uint64_t initial_roster_generation{0};
    const auto initial_roster_cache{
        GetQuorumRosterCache(&initial_roster_generation)};
    if (!initial_revision) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (initial_roster_cache) {
        if (const auto cached_status{try_cached(
                *initial_revision, initial_roster_generation,
                initial_probation_generation)}) {
            return *cached_status;
        }
    }

    const bool healthy_before_read{m_payment_audit_store->IsHealthy()};
    if (!healthy_before_read) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const auto stored{
        m_payment_audit_store->GetVerifiedWithCandidateRevision(
            receipt.audit_witness_id)};
    const auto archive_status{ClassifyPaymentAuditArchiveRead(
        true, healthy_before_read, stored.has_value(),
        m_payment_audit_store->IsHealthy())};
    if (archive_status !=
        PaymentAuditReceiptCertificateStatus::VERIFIED) {
        return archive_status;
    }
    // The store captures this only after the exact capability read has
    // completed any presence repair under the same lock.
    const uint64_t archive_revision{stored->Revision()};
    const uint64_t probation_generation_after_read{
        deterministicMNManager->PaymentProbationStateViewGeneration()};
    uint64_t roster_generation_after_read{0};
    const auto roster_cache_after_read{
        GetQuorumRosterCache(&roster_generation_after_read)};
    if (archive_revision == 0 || !roster_cache_after_read) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    if (const auto cached_status{try_cached(
            archive_revision, roster_generation_after_read,
            probation_generation_after_read)}) {
        return *cached_status;
    }
    const auto& audit{stored->Audit()};
    const auto classification{pq::ClassifyPaymentAuditReports(audit)};
    const pq::RosterBeaconSeed* receipt_subject_beacon{
        pq::FindRosterBeaconSeed(
            audit.statement.seal_statement.roster_beacons.active,
            receipt.epoch)};
    if (stored->LogicalId() != receipt.audit_logical_id ||
        stored->WitnessId() != receipt.audit_witness_id ||
        audit.statement.commitment.seed.epoch != receipt.epoch ||
        audit.statement.commitment.seal_height != receipt.seal_height ||
        audit.statement.seal_statement.block_hash !=
            receipt.seal_block_hash ||
        !classification ||
        pq::GetPaymentAuditCommitmentHash(
            m_genesis_hash, audit.statement.commitment) !=
            receipt.commitment_hash ||
        pq::GetPaymentAuditResultHash(
            m_genesis_hash, audit, *classification) !=
            receipt.result_hash ||
        classification->online_members != receipt.online_members ||
        receipt_subject_beacon == nullptr ||
        *receipt_subject_beacon != receipt.subject_roster_beacon) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    pq::FrozenQuorumRoster subject;
    uint64_t verified_roster_generation{0};
    int32_t reconstruction_floor{-1};
    const auto replay_status{BuildStoredVerifiedPaymentAuditSubject(
        *stored, *carrier.pprev, receipt.carrier_height, subject,
        verified_roster_generation, reconstruction_floor)};
    if (replay_status !=
        PaymentAuditReceiptCertificateStatus::VERIFIED) {
        return replay_status;
    }
    bool transition_local_error{false};
    auto transition{DerivePaymentAuditProbationTransition(
        audit.statement.commitment, subject, *carrier.pprev,
        receipt.carrier_height, receipt.result_hash,
        receipt.online_members, &transition_local_error)};
    if (!transition || transition->Result().StateHash() !=
                           receipt.next_probation_state_hash) {
        return transition_local_error
            ? PaymentAuditReceiptCertificateStatus::LOCAL_ERROR
            : PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (!m_payment_audit_store->IsHealthy() ||
        !m_payment_audit_store->IsCandidateRevisionCurrent(
            archive_revision) ||
        !IsQuorumRosterSourceGenerationCurrent(
            verified_roster_generation)) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const uint64_t verified_probation_generation{
        transition->ProvenanceGeneration()};
    const uint8_t authorization_mask{stored->AuthorizationMask()};

    VerifiedPaymentAuditReceiptTransitionPtr verified{
        new VerifiedPaymentAuditReceiptTransition{
            receipt, audit.statement, carrier.pprev->GetBlockHash(),
            carrier.pprev->nHeight,
            carrier.pprev->pqPaymentProbationStateHash,
            archive_revision, verified_roster_generation,
            verified_probation_generation,
            reconstruction_floor, authorization_mask,
            std::move(*transition)}};
    const auto published{
        m_verified_payment_audit_transition_cache->Publish(
            make_cache_key(archive_revision,
                           verified_roster_generation,
                           verified_probation_generation),
            std::move(verified))};
    if (!published ||
        !m_payment_audit_store->IsCandidateRevisionCurrent(
            archive_revision) ||
        !IsQuorumRosterSourceGenerationCurrent(
            verified_roster_generation) ||
        deterministicMNManager->PaymentProbationStateViewGeneration() !=
            verified_probation_generation) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    const auto recheck_status{
        RecheckVerifiedPaymentAuditReceiptTransition(
            *published, receipt, carrier)};
    if (recheck_status !=
        PaymentAuditReceiptCertificateStatus::VERIFIED) {
        return recheck_status;
    }
    if (!m_payment_audit_store->IsCandidateRevisionCurrent(
            archive_revision) ||
        !IsQuorumRosterSourceGenerationCurrent(
            verified_roster_generation)) {
        return PaymentAuditReceiptCertificateStatus::LOCAL_ERROR;
    }
    transition_out = published;
    return PaymentAuditReceiptCertificateStatus::VERIFIED;
}

pq::BTCCReceipt CChainLocksHandler::GetBTCCReceiptForCarrier(
    int32_t carrier_height,
    const CBlockIndex& carrier_parent) const
{
    AssertLockHeld(cs_main);
    pq::BTCCReceipt null_receipt;
    if (!m_store || !m_config ||
        carrier_parent.nHeight + 1 != carrier_height ||
        !pq::IsBTCCReceiptCarrierHeight(m_config->btcc_schedule,
                                        carrier_height)) {
        return null_receipt;
    }
    const auto previous_state{IndexedBTCCReceiptState(carrier_parent)};
    if (!previous_state) return null_receipt;

    const auto source_height{pq::BTCCSourceHeightForNEVMInjection(
        m_config->btcc_schedule, carrier_height)};
    if (!source_height) return null_receipt;
    const auto chainlock{m_store->GetByHeight(*source_height)};
    if (!chainlock) return null_receipt;

    const auto& statement{chainlock->statement};
    if (statement.btcc_advance != pq::BTCCAdvance::ADVANCE ||
        statement.height != *source_height ||
        statement.accepted_btcc_cursor.sys_height != *source_height ||
        statement.accepted_btcc_cursor.IsNull() ||
        (!previous_state->cursor.IsNull() &&
         statement.accepted_btcc_cursor.sys_height <=
             previous_state->cursor.sys_height)) {
        return null_receipt;
    }
    const auto signing_height{pq::SigningHeightForTarget(
        m_config->chainlock_schedule, statement.height)};
    if (!signing_height ||
        static_cast<int64_t>(*signing_height) +
                pq::PQ_BTCC_RECEIPT_PROPAGATION_BUFFER !=
            carrier_height) {
        return null_receipt;
    }
    const CBlockIndex* target{
        carrier_parent.GetAncestor(statement.height)};
    const CBlockIndex* cursor_source{carrier_parent.GetAncestor(
        statement.accepted_btcc_cursor.sys_height)};
    if (target == nullptr || target->GetBlockHash() != statement.block_hash ||
        cursor_source == nullptr ||
        cursor_source->GetBlockHash() !=
            statement.accepted_btcc_cursor.sys_hash ||
        cursor_source->btcpPrevCommitment !=
            statement.accepted_btcc_cursor.btc_hash) {
        return null_receipt;
    }
    pq::BTCCReceipt receipt;
    receipt.chainlock_target_height = statement.height;
    receipt.chainlock_target_hash = statement.block_hash;
    receipt.chainlock_logical_id = chainlock->GetLogicalId(m_genesis_hash);
    receipt.accepted_cursor = statement.accepted_btcc_cursor;
    return receipt.IsStructurallyValid() ? receipt : null_receipt;
}

CChainLocksHandler::BTCCReceiptCertificateStatus
CChainLocksHandler::CheckBTCCReceiptCertificate(
    const pq::BTCCReceipt& receipt,
    const CBlockIndex& carrier) const
{
    AssertLockHeld(cs_main);
    if (receipt.IsNull()) return BTCCReceiptCertificateStatus::VERIFIED;
    if (!m_chainman.IsPQParticipationAllowed()) {
        return BTCCReceiptCertificateStatus::MISSING;
    }
    if (!receipt.IsStructurallyValid() || !m_store || !m_config ||
        !pq::IsBTCCReceiptCarrierHeight(m_config->btcc_schedule,
                                        carrier.nHeight)) {
        return BTCCReceiptCertificateStatus::INVALID;
    }
    const auto chainlock{
        m_store->GetByLogicalId(receipt.chainlock_logical_id)};
    if (!chainlock) return BTCCReceiptCertificateStatus::MISSING;
    const auto& statement{chainlock->statement};
    if (chainlock->GetLogicalId(m_genesis_hash) !=
            receipt.chainlock_logical_id ||
        statement.btcc_advance != pq::BTCCAdvance::ADVANCE ||
        statement.height != receipt.chainlock_target_height ||
        statement.block_hash != receipt.chainlock_target_hash ||
        statement.accepted_btcc_cursor != receipt.accepted_cursor) {
        return BTCCReceiptCertificateStatus::INVALID;
    }
    const auto signing_height{pq::SigningHeightForTarget(
        m_config->chainlock_schedule, statement.height)};
    if (!signing_height ||
        static_cast<int64_t>(*signing_height) +
                pq::PQ_BTCC_RECEIPT_PROPAGATION_BUFFER !=
            carrier.nHeight) {
        return BTCCReceiptCertificateStatus::INVALID;
    }
    const CBlockIndex* target{carrier.GetAncestor(statement.height)};
    const CBlockIndex* cursor_source{
        carrier.GetAncestor(receipt.accepted_cursor.sys_height)};
    if (target == nullptr || target->GetBlockHash() != statement.block_hash ||
        cursor_source == nullptr ||
        cursor_source->GetBlockHash() != receipt.accepted_cursor.sys_hash ||
        cursor_source->btcpPrevCommitment != receipt.accepted_cursor.btc_hash) {
        return BTCCReceiptCertificateStatus::INVALID;
    }
    return BTCCReceiptCertificateStatus::VERIFIED;
}

void CChainLocksHandler::NotePendingBTCCReceiptCertificate(
    const uint256& logical_id,
    const CBlockIndex& carrier)
{
    AssertLockHeld(cs_main);
    LOCK(m_pending_btcc_receipt_mutex);
    if (m_pending_btcc_receipt &&
        m_pending_btcc_receipt->logical_id == logical_id &&
        m_pending_btcc_receipt->carrier_hash == carrier.GetBlockHash()) {
        return;
    }

    // ActivateBestChain reaches this path only for its current best-work
    // candidate. Keeping one dependency prevents fake inventory from growing
    // an unbounded queue while allowing a better branch to replace stale work.
    m_pending_btcc_receipt = PendingBTCCReceiptDependency{
        logical_id, carrier.GetBlockHash()};
    m_pending_btcc_last_request = std::chrono::microseconds{0};
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- carrier %s waits for ADVANCE %s\n",
             __func__, carrier.GetBlockHash().ToString(),
             logical_id.ToString());
}

bool CChainLocksHandler::IsPendingBTCCReceiptCertificate(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return false;
    LOCK(m_pending_btcc_receipt_mutex);
    return m_pending_btcc_receipt &&
           m_pending_btcc_receipt->logical_id == logical_id;
}

bool CChainLocksHandler::IsRequiredBTCCReceiptCertificate(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return false;
    const auto pending_verified{
        GetPendingVerifiedHistoricalChainLock()};
    LOCK2(m_pending_btcc_receipt_mutex,
          m_needed_btcc_certificate_mutex);
    std::optional<uint256> pending;
    if (m_pending_btcc_receipt &&
        (!pending_verified ||
         pending_verified->logical_id !=
             m_pending_btcc_receipt->logical_id)) {
        pending = m_pending_btcc_receipt->logical_id;
    }
    return SelectRequiredBTCCCertificate(
               pending, m_needed_btcc_certificate) == logical_id;
}

bool CChainLocksHandler::IsNeededBTCCReceiptCertificate(
    const uint256& logical_id) const
{
    if (logical_id.IsNull()) return false;
    LOCK2(m_pending_btcc_receipt_mutex,
          m_needed_btcc_certificate_mutex);
    return (m_pending_btcc_receipt &&
            m_pending_btcc_receipt->logical_id == logical_id) ||
           (m_needed_btcc_certificate &&
            m_needed_btcc_certificate->logical_id == logical_id);
}

std::optional<CChainLocksHandler::BTCCReceiptArchiveCapability>
CChainLocksHandler::GetBTCCReceiptArchiveCapability(
    const uint256& logical_id) const
{
    if (logical_id.IsNull() || !m_persistence) return std::nullopt;
    const auto durable{m_persistence->GetFinalityState()};
    if (!durable.best || !durable.receipt_archive_authorization ||
        !durable.receipt_archive_authorization->IsInternallyConsistent(
            m_genesis_hash) ||
        durable.receipt_archive_authorization->covering_logical_id !=
            durable.best->logical_id ||
        durable.receipt_archive_authorization->covering_witness_id !=
            durable.best->witness_id ||
        durable.best->statement.height <
            durable.receipt_archive_authorization->owner.statement.height ||
        (durable.best->statement.height ==
             durable.receipt_archive_authorization->owner.statement.height &&
         (durable.receipt_archive_authorization->owner.logical_id !=
              durable.best->logical_id ||
          durable.receipt_archive_authorization->owner.witness_id !=
              durable.best->witness_id ||
          durable.receipt_archive_authorization->owner.statement.block_hash !=
              durable.best->statement.block_hash))) {
        return std::nullopt;
    }

    LOCK2(m_pending_btcc_receipt_mutex,
          m_needed_btcc_certificate_mutex);
    BTCCReceiptArchiveCapability capability;
    if (m_pending_btcc_receipt &&
        m_pending_btcc_receipt->logical_id == logical_id) {
        capability.source = BTCCReceiptArchiveSource::PENDING_CARRIER;
        capability.source_token = m_pending_btcc_receipt->carrier_hash;
    } else if (m_needed_btcc_certificate &&
               m_needed_btcc_certificate->logical_id == logical_id) {
        capability.source =
            m_needed_btcc_certificate->source ==
                    NeededBTCCCertificateSource::LIVE_FRONTIER
                ? BTCCReceiptArchiveSource::LIVE_FRONTIER
                : BTCCReceiptArchiveSource::PRESEAL_REPLAY;
        capability.source_token =
            m_needed_btcc_certificate->source_token;
    } else {
        return std::nullopt;
    }
    if (capability.source_token.IsNull()) return std::nullopt;
    capability.logical_id = logical_id;
    capability.persistence_certificate_revision =
        durable.certificate_revision;
    capability.authorization =
        *durable.receipt_archive_authorization;
    return capability;
}

bool CChainLocksHandler::IsBTCCReceiptArchiveCapabilityCurrent(
    const BTCCReceiptArchiveCapability& capability) const
{
    const auto current{
        GetBTCCReceiptArchiveCapability(capability.logical_id)};
    return current && *current == capability;
}

bool CChainLocksHandler::DoesBTCCReceiptArchiveSourceMatch(
    const BTCCReceiptArchiveCapability& capability,
    const std::optional<PendingBTCCReceiptDependency>& pending,
    const std::optional<NeededBTCCCertificate>& needed) noexcept
{
    switch (capability.source) {
    case BTCCReceiptArchiveSource::PENDING_CARRIER:
        return pending && pending->logical_id == capability.logical_id &&
            pending->carrier_hash == capability.source_token;
    case BTCCReceiptArchiveSource::LIVE_FRONTIER:
    case BTCCReceiptArchiveSource::PRESEAL_REPLAY: {
        const auto expected_source{
            capability.source == BTCCReceiptArchiveSource::LIVE_FRONTIER
                ? NeededBTCCCertificateSource::LIVE_FRONTIER
                : NeededBTCCCertificateSource::PRESEAL_REPLAY};
        return needed && needed->source == expected_source &&
            needed->logical_id == capability.logical_id &&
            needed->source_token == capability.source_token;
    }
    }
    return false;
}

bool CChainLocksHandler::AuthorizeBTCCReceiptArchivePersistence(
    const BTCCReceiptArchiveCapability& capability,
    const std::function<bool()>& persist_record,
    pq::ChainLockFinalityError* error) const
{
    if (!persist_record || !m_persistence ||
        capability.logical_id.IsNull() ||
        capability.source_token.IsNull()) {
        if (error != nullptr) {
            *error = pq::ChainLockFinalityError::CONTEXT_CHANGED;
        }
        return false;
    }

    LOCK2(m_pending_btcc_receipt_mutex,
          m_needed_btcc_certificate_mutex);
    const bool source_current{DoesBTCCReceiptArchiveSourceMatch(
        capability, m_pending_btcc_receipt,
        m_needed_btcc_certificate)};

    const auto durable{m_persistence->GetFinalityState()};
    const bool authority_current{
        durable.certificate_revision ==
                capability.persistence_certificate_revision &&
        durable.best && durable.receipt_archive_authorization &&
        durable.best->logical_id ==
            capability.authorization.covering_logical_id &&
        durable.best->witness_id ==
            capability.authorization.covering_witness_id &&
        durable.best->statement.height >=
            capability.authorization.owner.statement.height &&
        *durable.receipt_archive_authorization ==
            capability.authorization};
    if (!source_current || !authority_current) {
        if (error != nullptr) {
            *error = pq::ChainLockFinalityError::CONTEXT_CHANGED;
        }
        return false;
    }
    return persist_record();
}

std::optional<pq::ReceiptArchiveRosterAuthorization>
CChainLocksHandler::GetReceiptArchiveCoverageAuthorization(
    const pq::PreparedFinalChainLockCandidate& prepared) const
{
    if (!m_config || !m_persistence || !m_store ||
        (prepared.admission != pq::ChainLockCandidateAdmission::LIVE &&
         prepared.admission != pq::ChainLockCandidateAdmission::CATCHUP)) {
        return std::nullopt;
    }
    const auto durable{m_persistence->GetFinalityState()};
    if (!durable.best || !durable.receipt_archive_authorization ||
        !durable.receipt_archive_authorization->IsInternallyConsistent(
            m_genesis_hash) ||
        durable.best->logical_id !=
            durable.receipt_archive_authorization->covering_logical_id ||
        durable.best->witness_id !=
            durable.receipt_archive_authorization->covering_witness_id ||
        prepared.predecessor.height != durable.best->statement.height ||
        prepared.predecessor.block_hash !=
            durable.best->statement.block_hash) {
        return std::nullopt;
    }
    const auto store_best{m_store->GetBestRecord()};
    if (!store_best || store_best->metadata != *durable.best) {
        return std::nullopt;
    }

    const auto& authorization{*durable.receipt_archive_authorization};
    const int64_t coverage_height{
        static_cast<int64_t>(
            authorization.owner.statement.previous_chainlock_height) +
        m_config->btcc_schedule.nevm_injection_lag};
    if (prepared.statement.height < coverage_height) return std::nullopt;

    LOCK(cs_main);
    const CBlockIndex* candidate{
        m_chainman.m_blockman.LookupBlockIndex(
            prepared.statement.block_hash)};
    const CBlockIndex* active{
        candidate != nullptr
            ? m_chainman.ActiveChain()[prepared.statement.height]
            : nullptr};
    const CBlockIndex* owner{
        candidate != nullptr
            ? candidate->GetAncestor(authorization.owner.statement.height)
            : nullptr};
    const auto indexed_receipt{
        candidate != nullptr ? IndexedBTCCReceiptState(*candidate)
                             : std::optional<pq::BTCCReceiptState>{}};
    if (candidate == nullptr || active != candidate ||
        candidate->nHeight != prepared.statement.height ||
        owner == nullptr ||
        owner->GetBlockHash() != authorization.owner.statement.block_hash ||
        !HasChainLockTargetValidationCached(
            *candidate, authorization.owner.statement.height,
            HistoricalIndexValidationMode::FULL_FINALITY) ||
        !indexed_receipt ||
        *indexed_receipt != prepared.statement.btcc_receipt_state) {
        return std::nullopt;
    }
    return authorization;
}

bool CChainLocksHandler::PublishNeededBTCCCertificate(
    std::optional<NeededBTCCCertificate>& current,
    NeededBTCCCertificateSource source,
    const uint256& logical_id,
    const uint256& source_token)
{
    if (logical_id.IsNull() || source_token.IsNull()) return false;
    if (current) {
        if (static_cast<uint8_t>(current->source) >
            static_cast<uint8_t>(source)) {
            return false;
        }
        if (current->source == source &&
            current->logical_id == logical_id &&
            current->source_token == source_token) {
            return false;
        }
    }
    current = NeededBTCCCertificate{
        source, logical_id, source_token,
        std::chrono::microseconds{0}};
    return true;
}

bool CChainLocksHandler::EraseNeededBTCCCertificate(
    std::optional<NeededBTCCCertificate>& current,
    NeededBTCCCertificateSource source,
    const std::optional<uint256>& source_token)
{
    if (!current || current->source != source ||
        (source_token && current->source_token != *source_token)) {
        return false;
    }
    current.reset();
    return true;
}

std::optional<uint256>
CChainLocksHandler::SelectRequiredBTCCCertificate(
    const std::optional<uint256>& pending,
    const std::optional<NeededBTCCCertificate>& needed)
{
    if (pending && !pending->IsNull()) return pending;
    return needed && !needed->logical_id.IsNull()
        ? std::optional<uint256>{needed->logical_id}
        : std::nullopt;
}

void CChainLocksHandler::NoteNeededBTCCCertificate(
    NeededBTCCCertificateSource source,
    const uint256& logical_id,
    const uint256& source_token)
{
    LOCK(m_needed_btcc_certificate_mutex);
    (void)PublishNeededBTCCCertificate(
        m_needed_btcc_certificate, source, logical_id, source_token);
}

void CChainLocksHandler::ClearNeededBTCCCertificate(
    NeededBTCCCertificateSource source,
    const std::optional<uint256>& source_token)
{
    LOCK(m_needed_btcc_certificate_mutex);
    (void)EraseNeededBTCCCertificate(
        m_needed_btcc_certificate, source, source_token);
}

void CChainLocksHandler::ClearNeededBTCCCertificate(
    const uint256& logical_id)
{
    if (logical_id.IsNull()) return;
    LOCK(m_needed_btcc_certificate_mutex);
    if (m_needed_btcc_certificate &&
        m_needed_btcc_certificate->logical_id == logical_id) {
        m_needed_btcc_certificate.reset();
    }
}

void CChainLocksHandler::NotePendingPaymentAuditReceiptCertificate(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier)
{
    AssertLockHeld(cs_main);
    if (receipt.IsNull() || !receipt.IsStructurallyValid() ||
        receipt.audit_witness_id.IsNull() ||
        receipt.carrier_height != carrier.nHeight ||
        carrier.pprev == nullptr) {
        return;
    }
    LOCK(m_pending_payment_audit_receipt_mutex);
    if (m_pending_payment_audit_receipt &&
        m_pending_payment_audit_receipt->receipt == receipt &&
        m_pending_payment_audit_receipt->carrier_hash ==
            carrier.GetBlockHash() &&
        m_pending_payment_audit_receipt->carrier_parent_hash ==
            carrier.pprev->GetBlockHash()) {
        return;
    }
    m_pending_payment_audit_receipt =
        PendingPaymentAuditReceiptDependency{
            receipt, carrier.GetBlockHash(),
            carrier.pprev->GetBlockHash()};
    m_pending_payment_audit_last_request = std::chrono::microseconds{0};
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- carrier %s waits for payment "
             "audit %s\n",
             __func__, carrier.GetBlockHash().ToString(),
             receipt.audit_witness_id.ToString());
}

bool CChainLocksHandler::IsPendingPaymentAuditReceiptCertificate(
    const uint256& witness_id) const
{
    if (witness_id.IsNull()) return false;
    LOCK(m_pending_payment_audit_receipt_mutex);
    return m_pending_payment_audit_receipt &&
           m_pending_payment_audit_receipt->receipt.audit_witness_id ==
               witness_id;
}

std::optional<CChainLocksHandler::PaymentAuditHistoricalContext>
CChainLocksHandler::ResolvePendingPaymentAuditContext(
    const uint256& witness_id) const
{
    AssertLockHeld(cs_main);
    if (witness_id.IsNull()) return std::nullopt;

    std::optional<PendingPaymentAuditReceiptDependency> dependency;
    {
        LOCK(m_pending_payment_audit_receipt_mutex);
        dependency = m_pending_payment_audit_receipt;
    }
    if (!dependency ||
        dependency->receipt.audit_witness_id != witness_id) {
        return std::nullopt;
    }

    std::optional<DeferredBTCCReceiptCandidate> best_deferred;
    node::CBlockIndexWorkComparator compare;
    for (Chainstate* chainstate : m_chainman.GetAll()) {
        const auto candidate{
            chainstate->GetBestDeferredPaymentAuditReceiptCandidate()};
        if (candidate &&
            (!best_deferred ||
             compare(best_deferred->best_candidate,
                     candidate->best_candidate))) {
            best_deferred = candidate;
        }
    }
    if (!best_deferred || best_deferred->logical_id != witness_id ||
        best_deferred->carrier == nullptr ||
        best_deferred->best_candidate == nullptr ||
        best_deferred->carrier->GetBlockHash() !=
            dependency->carrier_hash ||
        best_deferred->carrier->pprev == nullptr ||
        best_deferred->carrier->pprev->GetBlockHash() !=
            dependency->carrier_parent_hash ||
        best_deferred->best_candidate->nHeight <
            best_deferred->carrier->nHeight ||
        best_deferred->best_candidate->GetAncestor(
            best_deferred->carrier->nHeight) != best_deferred->carrier ||
        (best_deferred->carrier->nStatus &
         (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) != 0 ||
        (best_deferred->carrier->nStatus & BLOCK_HAVE_DATA) == 0) {
        return std::nullopt;
    }

    CBlock carrier_block;
    if (!m_chainman.m_blockman.ReadBlockFromDisk(
            carrier_block, *best_deferred->carrier)) {
        return std::nullopt;
    }
    const auto decoded{ExtractDeferredPaymentAuditReceipt(
        carrier_block, witness_id, *best_deferred->carrier,
        *best_deferred->best_candidate)};
    if (!decoded || *decoded != dependency->receipt) {
        return std::nullopt;
    }
    return PaymentAuditHistoricalContext{
        *dependency,
        best_deferred->best_candidate->GetBlockHash(),
        best_deferred->best_candidate->nHeight};
}

bool CChainLocksHandler::RetireInvalidPendingPaymentAuditReceipt(
    const PaymentAuditHistoricalContext& expected)
{
    const bool retired{m_chainman.ActiveChainstate()
                           .RunWithStableActiveChain([&] {
        LOCK(cs_main);
        CBlockIndex* carrier{m_chainman.m_blockman.LookupBlockIndex(
            expected.dependency.carrier_hash)};
        if (carrier == nullptr || carrier->pprev == nullptr ||
            carrier->pprev->GetBlockHash() !=
                expected.dependency.carrier_parent_hash ||
            carrier->nHeight !=
                expected.dependency.receipt.carrier_height ||
            (carrier->nStatus & BLOCK_HAVE_DATA) == 0 ||
            (carrier->nStatus &
             (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) != 0 ||
            carrier->IsAssumedValid() ||
            !carrier->IsValid(BLOCK_VALID_TRANSACTIONS)) {
            return false;
        }

        CBlock carrier_block;
        pq::PaymentAuditReceipt decoded;
        if (!m_chainman.m_blockman.ReadBlockFromDisk(carrier_block, *carrier) ||
            carrier_block.GetHash() != carrier->GetBlockHash() ||
            !ExtractPaymentAuditReceipt(carrier_block, decoded) ||
            decoded != expected.dependency.receipt ||
            !m_chainman.RetireDeferredPaymentAuditReceiptCarrier(
                decoded.audit_witness_id, *carrier)) {
            return false;
        }

        // Retirement and selection of the next highest-work exact carrier are
        // one stable-chain transition across every live chainstate.
        (void)RevalidatePendingPaymentAuditReceiptDependencyLocked();
        bool witness_survives{false};
        for (Chainstate* chainstate : m_chainman.GetAll()) {
            witness_survives =
                chainstate->HasDeferredPaymentAuditReceiptCandidates(
                    decoded.audit_witness_id) ||
                witness_survives;
        }
        if (!witness_survives) {
            m_peerman.ForgetPaymentAudit(decoded.audit_witness_id);
        }
        return true;
    })};
    if (retired) m_retry_pending_btcc_block.store(true);
    return retired;
}

PaymentAuditContextStatus
CChainLocksHandler::BuildCompactPaymentAuditTransitionContext(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier,
    pq::PQPaymentProbationTransitionContext& context) const
{
    AssertLockHeld(cs_main);
    context = {};
    if (receipt.IsNull() || !receipt.IsStructurallyValid()) {
        return PaymentAuditContextStatus::INVALID;
    }
    if (!m_config || !m_quorum_build_config) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    const pq::PaymentAuditScheduleConfig audit_schedule{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto carrier_status{ClassifyPaymentAuditReceiptCarrierContext(
        receipt, carrier, audit_schedule)};
    if (carrier_status != PaymentAuditContextStatus::READY) {
        return carrier_status;
    }
    const auto slot_epoch{pq::PaymentAuditReceiptSlotEpoch(
        audit_schedule, carrier.nHeight)};
    if (!slot_epoch || *slot_epoch != receipt.epoch ||
        carrier.pprev == nullptr) {
        return PaymentAuditContextStatus::INVALID;
    }

    const auto roster_cache{GetQuorumRosterCache()};
    if (!roster_cache) return PaymentAuditContextStatus::LOCAL_ERROR;
    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    std::unique_ptr<pq::FrozenQuorumRoster> subject;
    try {
        subject = BuildHistoricalFrozenRoster(
            m_genesis_hash, *m_quorum_build_config, *roster_cache,
            receipt.epoch, carrier, receipt.subject_roster_beacon,
            &build_error);
    } catch (const std::exception&) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    if (!subject || subject->descriptor.epoch != receipt.epoch) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }

    context.receipt = {
        receipt.epoch, receipt.carrier_height, receipt.result_hash};
    context.roster_valid_members = subject->descriptor.valid_members;
    context.observed_members = receipt.online_members;
    for (std::size_t byte{0}; byte < pq::BITMAP_SIZE; ++byte) {
        if ((context.observed_members[byte] &
             static_cast<uint8_t>(~context.roster_valid_members[byte])) != 0) {
            context = {};
            return PaymentAuditContextStatus::INVALID;
        }
    }
    for (std::size_t member{0}; member < pq::QUORUM_SIZE; ++member) {
        context.frozen_roster[member] =
            subject->members[member].pro_tx_hash;
    }
    if (!context.IsStructurallyValid()) {
        context = {};
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    return PaymentAuditContextStatus::READY;
}

bool CChainLocksHandler::BeginBTCCPreseal(
    const CBlockIndex& carrier,
    const pq::BTCCReceipt& missing_receipt)
{
    AssertLockHeld(cs_main);
    if (!m_chainman.CanBeginPQHistoryAuthentication() ||
        !m_config || !m_persistence || m_persistence_failed.load() ||
        carrier.nHeight <=
            m_config->btcc_receipt_assumption_anchor.height ||
        missing_receipt.IsNull() ||
        !missing_receipt.IsStructurallyValid() ||
        missing_receipt.chainlock_target_height <= m_config->activation_predecessor_height ||
        !pq::ValidateBTCCReceiptOnBranch(m_config->btcc_schedule, carrier,
                                         missing_receipt) ||
        !pq::IsBTCCReceiptCarrierHeight(m_config->btcc_schedule,
                                        carrier.nHeight)) {
        return false;
    }
    const auto predecessor_state{
        carrier.pprev == nullptr
            ? std::optional<pq::BTCCReceiptState>{}
            : IndexedBTCCReceiptState(*carrier.pprev)};
    if (!predecessor_state) return false;

    LOCK(m_btcc_preseal_mutex);
    pq::BTCCPresealState next{m_btcc_preseal_state};
    const auto persist_pending = [&](const pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex) {
        return PersistBTCCPresealStateLocked(state) &&
               m_chainman.PublishPQHistoryAuthState(
                   PQHistoryAuthState::PENDING);
    };
    const auto fresh_marker = [&] {
        return pq::BTCCPresealMarker{
            carrier.nHeight,
            carrier.GetBlockHash(),
            *predecessor_state,
            carrier.nHeight,
            carrier.GetBlockHash(),
            missing_receipt,
            uint64_t{1}};
    };
    const auto advance_marker = [&](pq::BTCCPresealMarker& marker) {
        if (carrier.nHeight < marker.terminal_carrier_height) return true;
        if (carrier.nHeight == marker.terminal_carrier_height) {
            return carrier.GetBlockHash() == marker.terminal_carrier_hash &&
                   missing_receipt == marker.terminal_receipt;
        }
        const CBlockIndex* earliest{
            carrier.GetAncestor(marker.earliest_carrier_height)};
        if (earliest == nullptr ||
            earliest->GetBlockHash() != marker.earliest_carrier_hash) {
            return false;
        }
        marker.terminal_carrier_height = carrier.nHeight;
        marker.terminal_carrier_hash = carrier.GetBlockHash();
        marker.terminal_receipt = missing_receipt;
        return true;
    };
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    const auto marker_index = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> const CBlockIndex* {
        if (!marker) return nullptr;
        const CBlockIndex* index{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->earliest_carrier_hash)};
        return index != nullptr &&
                       index->nHeight == marker->earliest_carrier_height
                   ? index
                   : nullptr;
    };
    const auto marker_on_active = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* index{marker_index(marker)};
        return active_tip != nullptr && index != nullptr &&
               active_tip->GetAncestor(index->nHeight) == index;
    };
    const auto candidate_descends = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* index{marker_index(marker)};
        return index != nullptr && index->nHeight <= carrier.nHeight &&
               carrier.GetAncestor(index->nHeight) == index;
    };

    // A crash can leave the prospective slot pointing at the branch which is
    // now active. Promote it atomically before considering another candidate;
    // the old active marker remains durable until this branch transition is
    // known from ActiveChain.
    if (marker_on_active(next.prospective)) {
        if (!marker_on_active(next.active) ||
            next.prospective->earliest_carrier_height <
                next.active->earliest_carrier_height) {
            next.active = next.prospective;
        }
        next.prospective.reset();
    }

    // Rollforward/VerifyDB may revisit a descendant of either crash-durable
    // boundary. Persist any promotion above, then reuse it idempotently.
    if (candidate_descends(next.active)) {
        if (!advance_marker(*next.active)) return false;
        return persist_pending(next);
    }
    if (candidate_descends(next.prospective)) {
        if (!advance_marker(*next.prospective)) return false;
        return persist_pending(next);
    }

    const bool candidate_on_active{
        active_tip != nullptr &&
        active_tip->GetAncestor(carrier.nHeight) == &carrier};
    if (candidate_on_active) {
        // Recovery may move the active boundary earlier or replace a stale
        // branch marker, but it never destroys the separate prospective slot.
        next.active = fresh_marker();
    } else {
        // Only the prospective most-work branch may occupy the second slot.
        // An arbitrary side branch cannot overwrite either durable replay
        // obligation.
        if (!m_chainman.ActiveChainstate().IsCurrentMostWorkBranch(carrier)) {
            return false;
        }
        next.prospective = fresh_marker();
    }
    if (!persist_pending(next)) {
        return false;
    }
    LogPrintf("CChainLocksHandler::%s -- deferring NEVM from carrier %d:%s "
              "until a fully verified catch-up seal authenticates its "
              "receipt prefix\n",
              __func__, carrier.nHeight,
              carrier.GetBlockHash().ToString());
    return true;
}

bool CChainLocksHandler::BeginPaymentAuditPreseal(
    const CBlockIndex& carrier,
    const pq::PaymentAuditReceipt& missing_receipt,
    const pq::PaymentAuditReceiptState& predecessor_receipt_state,
    const uint256& predecessor_probation_state_hash)
{
    AssertLockHeld(cs_main);
    if (!m_chainman.CanBeginPQHistoryAuthentication() ||
        !m_config || !m_quorum_build_config || !m_persistence ||
        m_persistence_failed.load() || deterministicMNManager == nullptr ||
        carrier.pprev == nullptr || missing_receipt.IsNull() ||
        !missing_receipt.IsStructurallyValid() ||
        predecessor_probation_state_hash.IsNull() ||
        carrier.pprev->pqPaymentProbationStateHash !=
            predecessor_probation_state_hash) {
        return false;
    }
    const pq::PaymentAuditScheduleConfig schedule{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    if (ClassifyPaymentAuditReceiptCarrierContext(
            missing_receipt, carrier, schedule) !=
            PaymentAuditContextStatus::READY) {
        return false;
    }
    const auto indexed_predecessor{
        IndexedPaymentAuditReceiptState(*carrier.pprev)};
    if (!indexed_predecessor ||
        *indexed_predecessor != predecessor_receipt_state ||
        !pq::ApplyPaymentAuditReceipt(
            m_genesis_hash, predecessor_receipt_state,
            missing_receipt)) {
        return false;
    }

    LOCK(m_btcc_preseal_mutex);
    pq::PaymentAuditPresealState next{
        m_payment_audit_preseal_state};
    const auto persist_pending = [&] (
        const pq::PaymentAuditPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex) {
        return PersistPaymentAuditPresealStateLocked(state) &&
               m_chainman.PublishPQHistoryAuthState(
                   PQHistoryAuthState::PENDING);
    };
    const auto marker_index = [&](const auto& marker, bool terminal)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> const CBlockIndex* {
        if (!marker) return nullptr;
        const uint256& hash{terminal ? marker->terminal_carrier_hash
                                     : marker->earliest_carrier_hash};
        const int32_t height{terminal ? marker->terminal_carrier_height
                                      : marker->earliest_carrier_height};
        const CBlockIndex* index{
            m_chainman.m_blockman.LookupBlockIndex(hash)};
        return index != nullptr && index->nHeight == height ? index
                                                            : nullptr;
    };
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    const auto terminal_on_active = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* terminal{marker_index(marker, true)};
        return active_tip != nullptr && terminal != nullptr &&
               active_tip->GetAncestor(terminal->nHeight) == terminal;
    };
    const auto candidate_continues = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* terminal{marker_index(marker, true)};
        return terminal != nullptr && terminal->nHeight <= carrier.nHeight &&
               carrier.GetAncestor(terminal->nHeight) == terminal;
    };
    const auto candidate_already_bounded = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* earliest{marker_index(marker, false)};
        const CBlockIndex* terminal{marker_index(marker, true)};
        return earliest != nullptr && terminal != nullptr &&
               carrier.nHeight >= earliest->nHeight &&
               carrier.nHeight <= terminal->nHeight &&
               terminal->GetAncestor(carrier.nHeight) == &carrier;
    };
    const auto candidate_descends_earliest = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        const CBlockIndex* earliest{marker_index(marker, false)};
        return earliest != nullptr && earliest->nHeight <= carrier.nHeight &&
               carrier.GetAncestor(earliest->nHeight) == earliest;
    };
    const auto make_marker = [&] (
        const pq::PaymentAuditPresealMarker* shared) {
        pq::PaymentAuditPresealMarker marker;
        if (shared != nullptr) {
            marker.earliest_carrier_height =
                shared->earliest_carrier_height;
            marker.earliest_carrier_hash =
                shared->earliest_carrier_hash;
            marker.predecessor_receipt_state =
                shared->predecessor_receipt_state;
            marker.predecessor_probation_state_hash =
                shared->predecessor_probation_state_hash;
        } else {
            marker.earliest_carrier_height = carrier.nHeight;
            marker.earliest_carrier_hash = carrier.GetBlockHash();
            marker.predecessor_receipt_state =
                predecessor_receipt_state;
            marker.predecessor_probation_state_hash =
                predecessor_probation_state_hash;
        }
        marker.terminal_carrier_height = carrier.nHeight;
        marker.terminal_carrier_hash = carrier.GetBlockHash();
        marker.terminal_receipt = missing_receipt;
        marker.revision = 1;
        return marker;
    };
    const auto advance_marker = [&](pq::PaymentAuditPresealMarker& marker) {
        if (carrier.nHeight == marker.terminal_carrier_height) {
            return carrier.GetBlockHash() == marker.terminal_carrier_hash &&
                   missing_receipt == marker.terminal_receipt;
        }
        if (carrier.nHeight < marker.terminal_carrier_height) return true;
        marker.terminal_carrier_height = carrier.nHeight;
        marker.terminal_carrier_hash = carrier.GetBlockHash();
        marker.terminal_receipt = missing_receipt;
        return true;
    };
    const auto shared_prefix = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
        -> const pq::PaymentAuditPresealMarker* {
        const pq::PaymentAuditPresealMarker* selected{nullptr};
        const auto inspect = [&](const auto& marker)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            if (!marker || !candidate_descends_earliest(marker)) return;
            if (selected == nullptr ||
                marker->earliest_carrier_height <
                    selected->earliest_carrier_height) {
                selected = &*marker;
            }
        };
        inspect(next.active);
        inspect(next.prospective);
        return selected;
    };

    if (terminal_on_active(next.prospective)) {
        // Both slots can share a compact-replay prefix. When the prospective
        // branch wins, retain the earliest common predecessor but the
        // farthest terminal on the winning branch; choosing by earliest alone
        // would discard a later prospective terminal at the same boundary.
        const pq::PaymentAuditPresealMarker* terminal_source{
            &*next.prospective};
        if (terminal_on_active(next.active)) {
            if (next.active->terminal_carrier_height >
                terminal_source->terminal_carrier_height) {
                terminal_source = &*next.active;
            } else if (next.active->terminal_carrier_height ==
                           terminal_source->terminal_carrier_height &&
                       (next.active->terminal_carrier_hash !=
                            terminal_source->terminal_carrier_hash ||
                        next.active->terminal_receipt !=
                            terminal_source->terminal_receipt)) {
                return false;
            }
        }
        const CBlockIndex* winning_terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                terminal_source->terminal_carrier_hash)};
        if (winning_terminal == nullptr ||
            winning_terminal->nHeight !=
                terminal_source->terminal_carrier_height) {
            return false;
        }

        const pq::PaymentAuditPresealMarker* boundary_source{nullptr};
        const auto consider_boundary = [&](const auto& marker)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            if (!marker) return true;
            const CBlockIndex* earliest{marker_index(marker, false)};
            if (earliest == nullptr ||
                earliest->nHeight > winning_terminal->nHeight ||
                winning_terminal->GetAncestor(earliest->nHeight) !=
                    earliest) {
                return true;
            }
            if (boundary_source == nullptr ||
                marker->earliest_carrier_height <
                    boundary_source->earliest_carrier_height) {
                boundary_source = &*marker;
                return true;
            }
            if (marker->earliest_carrier_height ==
                    boundary_source->earliest_carrier_height &&
                (marker->earliest_carrier_hash !=
                     boundary_source->earliest_carrier_hash ||
                 marker->predecessor_receipt_state !=
                     boundary_source->predecessor_receipt_state ||
                 marker->predecessor_probation_state_hash !=
                     boundary_source->predecessor_probation_state_hash)) {
                return false;
            }
            return true;
        };
        if (!consider_boundary(next.active) ||
            !consider_boundary(next.prospective) ||
            boundary_source == nullptr) {
            return false;
        }
        pq::PaymentAuditPresealMarker promoted{*boundary_source};
        promoted.terminal_carrier_height =
            terminal_source->terminal_carrier_height;
        promoted.terminal_carrier_hash =
            terminal_source->terminal_carrier_hash;
        promoted.terminal_receipt = terminal_source->terminal_receipt;
        next.active = std::move(promoted);
        next.prospective.reset();
    }
    if (candidate_already_bounded(next.active) ||
        candidate_already_bounded(next.prospective)) {
        return persist_pending(next);
    }
    if (candidate_continues(next.active)) {
        if (!advance_marker(*next.active)) return false;
        return persist_pending(next);
    }
    if (candidate_continues(next.prospective)) {
        if (!advance_marker(*next.prospective)) return false;
        return persist_pending(next);
    }

    const bool candidate_on_active{
        active_tip != nullptr && active_tip->nHeight >= carrier.nHeight &&
        active_tip->GetAncestor(carrier.nHeight) == &carrier};
    const pq::PaymentAuditPresealMarker* shared{shared_prefix()};
    if (candidate_on_active) {
        next.active = make_marker(shared);
    } else {
        if (!m_chainman.ActiveChainstate().IsCurrentMostWorkBranch(carrier)) {
            return false;
        }
        next.prospective = make_marker(shared);
    }
    if (!persist_pending(next)) return false;
    LogPrintf("CChainLocksHandler::%s -- compact payment-audit replay "
              "started at carrier %d:%s; live finality and audit "
              "production remain paused until a descendant CLSIG "
              "authenticates both reconstructed roots\n",
              __func__, carrier.nHeight,
              carrier.GetBlockHash().ToString());
    return true;
}

bool CChainLocksHandler::IsBTCCPresealActive() const
{
    AssertLockHeld(cs_main);
    pq::BTCCPresealState durable;
    {
        LOCK(m_btcc_preseal_mutex);
        durable = m_btcc_preseal_state;
    }
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    if (active_tip == nullptr || !m_store) {
        return !durable.IsEmpty();
    }
    const auto best{m_store->GetBestRecord()};
    const CBlockIndex* winner{
        best ? m_chainman.m_blockman.LookupBlockIndex(
                   best->metadata.statement.block_hash)
             : nullptr};
    const auto unsealed_on_active = [&](const auto& durable)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!durable) return false;
        const CBlockIndex* marker{
            m_chainman.m_blockman.LookupBlockIndex(
                durable->earliest_carrier_hash)};
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                durable->terminal_carrier_hash)};
        if (marker == nullptr || terminal == nullptr ||
            marker->nHeight != durable->earliest_carrier_height ||
            terminal->nHeight != durable->terminal_carrier_height ||
            active_tip->GetAncestor(marker->nHeight) != marker) {
            return false;
        }
        const bool winner_descends{
            winner != nullptr && best &&
            winner->nHeight == best->metadata.statement.height &&
            winner->nHeight >= terminal->nHeight &&
            active_tip->GetAncestor(winner->nHeight) == winner &&
            winner->GetAncestor(terminal->nHeight) == terminal};
        const bool winner_covers{IsBTCCPresealCoveredByDurableWinner(
            terminal->nHeight, winner == nullptr ? -1 : winner->nHeight,
            winner_descends)};
        const bool exact_receipt_verified{
            CheckBTCCReceiptCertificate(durable->terminal_receipt,
                                        *terminal) ==
            BTCCReceiptCertificateStatus::VERIFIED};
        return !winner_covers && !exact_receipt_verified;
    };
    return unsealed_on_active(durable.active) ||
           unsealed_on_active(durable.prospective);
}

bool CChainLocksHandler::HasNEVMReplayObligation() const
{
    if (!m_chainman.IsPQParticipationAllowed()) return false;
    LOCK(m_btcc_preseal_mutex);
    return !m_btcc_preseal_state.IsEmpty() ||
           !m_payment_audit_preseal_state.IsEmpty();
}

bool CChainLocksHandler::ShouldDeferBTCCNEVM(
    const CBlockIndex& index) const
{
    AssertLockHeld(cs_main);
    if (!m_chainman.IsPQParticipationAllowed()) return false;
    pq::BTCCPresealState btcc_state;
    pq::PaymentAuditPresealState payment_audit_state;
    {
        LOCK(m_btcc_preseal_mutex);
        btcc_state = m_btcc_preseal_state;
        payment_audit_state = m_payment_audit_preseal_state;
    }
    const auto descends = [&](const auto& durable)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!durable ||
            index.nHeight < durable->earliest_carrier_height) return false;
        const CBlockIndex* marker{
            m_chainman.m_blockman.LookupBlockIndex(
                durable->earliest_carrier_hash)};
        return marker != nullptr &&
               marker->nHeight == durable->earliest_carrier_height &&
               index.GetAncestor(marker->nHeight) == marker;
    };
    const bool btcc_deferred{
        descends(btcc_state.active) ||
        descends(btcc_state.prospective)};
    const bool payment_audit_deferred{
        descends(payment_audit_state.active) ||
        descends(payment_audit_state.prospective)};
    return btcc_deferred || payment_audit_deferred;
}

bool CChainLocksHandler::IsBTCCPrefixAuthenticated(
    const CBlockIndex& index) const
{
    AssertLockHeld(cs_main);
    // A fully verified, durably accepted descendant authenticates the exact
    // cumulative receipt state it signs. Catch-up is only an admission mode;
    // it is not a separate cryptographic property of the accepted winner.
    if (!m_store) return false;
    const auto best{m_store->GetBestRecord()};
    if (!best || index.nHeight > best->metadata.statement.height) return false;
    const CBlockIndex* target{
        m_chainman.m_blockman.LookupBlockIndex(
            best->metadata.statement.block_hash)};
    return target != nullptr &&
           target->nHeight == best->metadata.statement.height &&
           target->GetAncestor(index.nHeight) == &index;
}

bool CChainLocksHandler::IsPaymentAuditPrefixAuthenticated(
    const CBlockIndex& index) const
{
    AssertLockHeld(cs_main);
    if (!m_store || !m_persistence || !m_payment_audit_store ||
        m_persistence_failed.load()) {
        return false;
    }
    const auto checkpoint{m_payment_audit_store->GetPruneCheckpoint()};
    return checkpoint &&
           IsPaymentAuditCheckpointAuthenticated(*checkpoint, index);
}

bool CChainLocksHandler::IsPaymentAuditCheckpointAuthenticated(
    const pq::PaymentAuditStoreCheckpoint& checkpoint,
    const CBlockIndex& index) const
{
    AssertLockHeld(cs_main);
    if (!m_store || !m_persistence ||
        !checkpoint.IsStructurallyValid() ||
        m_persistence_failed.load()) {
        return false;
    }
    const auto accepted{m_store->GetBestRecord()};
    const auto durable{m_persistence->GetFinalityState().best};
    if (!accepted || !durable || accepted->metadata != *durable) {
        return false;
    }
    const CBlockIndex* authorizer{m_chainman.m_blockman.LookupBlockIndex(
        checkpoint.authorizing_target_hash)};
    const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
        accepted->metadata.statement.block_hash)};
    if (authorizer == nullptr || target == nullptr ||
        authorizer->nHeight != checkpoint.authorizing_target_height ||
        target->nHeight != accepted->metadata.statement.height ||
        target->nHeight < authorizer->nHeight ||
        target->GetAncestor(authorizer->nHeight) != authorizer ||
        (authorizer->nStatus & BLOCK_FAILED_MASK) ||
        (target->nStatus & BLOCK_FAILED_MASK)) {
        return false;
    }
    const CBlockIndex* covered{m_chainman.m_blockman.LookupBlockIndex(
        checkpoint.covered_through_hash)};
    if (covered == nullptr ||
        covered->nHeight != checkpoint.covered_through_height ||
        authorizer->nHeight < covered->nHeight ||
        authorizer->GetAncestor(covered->nHeight) != covered ||
        target->nHeight < index.nHeight ||
        target->GetAncestor(index.nHeight) != &index) {
        return false;
    }
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    if (active_tip == nullptr ||
        (active_tip->nHeight >= target->nHeight
             ? active_tip->GetAncestor(target->nHeight) != target
             : target->GetAncestor(active_tip->nHeight) != active_tip)) {
        return false;
    }
    const auto indexed_authorizer{
        IndexedPaymentAuditReceiptState(*authorizer)};
    const auto indexed_target{IndexedPaymentAuditReceiptState(*target)};
    if (!indexed_authorizer ||
        *indexed_authorizer != checkpoint.authenticated_receipt_state ||
        authorizer->pqPaymentProbationStateHash !=
            checkpoint.authenticated_probation_state_hash ||
        !indexed_target ||
        *indexed_target !=
            accepted->metadata.statement.payment_audit_receipt_state ||
        target->pqPaymentProbationStateHash !=
            accepted->metadata.statement.payment_probation_state_hash) {
        return false;
    }
    const bool same_authorizer_target{
        accepted->metadata.statement.height ==
            checkpoint.authorizing_target_height &&
        accepted->metadata.statement.block_hash ==
            checkpoint.authorizing_target_hash};
    const bool exact_authorizer{
        same_authorizer_target &&
        accepted->metadata.logical_id ==
            checkpoint.authorizing_chainlock_logical_id &&
        accepted->metadata.witness_id ==
            checkpoint.authorizing_chainlock_witness_id};
    if (same_authorizer_target && !exact_authorizer) return false;
    if (!exact_authorizer) {
        const auto& previous{
            checkpoint.authenticated_receipt_state.cursor};
        const auto& current{
            accepted->metadata.statement.payment_audit_receipt_state.cursor};
        if ((!previous.IsNull() && current.IsNull()) ||
            (!previous.IsNull() &&
             (current.epoch < previous.epoch ||
              current.carrier_height < previous.carrier_height)) ||
            (target->nHeight > authorizer->nHeight &&
             ClassifyHistoricalReceiptIndexRangeCached(
                 *target, authorizer->nHeight + 1) !=
                 PaymentAuditContextStatus::READY)) {
            return false;
        }
        if (current == previous &&
            (accepted->metadata.statement.payment_audit_receipt_state !=
                 checkpoint.authenticated_receipt_state ||
             accepted->metadata.statement.payment_probation_state_hash !=
                 checkpoint.authenticated_probation_state_hash)) {
            return false;
        }
    }
    const auto indexed{IndexedPaymentAuditReceiptState(index)};
    if (!indexed) return false;
    if (indexed->cursor.IsNull()) return true;
    return indexed->cursor.epoch <= checkpoint.prune_through_epoch;
}

bool CChainLocksHandler::IsPaymentAuditPresealActive() const
{
    AssertLockHeld(cs_main);
    pq::PaymentAuditPresealState durable;
    {
        LOCK(m_btcc_preseal_mutex);
        durable = m_payment_audit_preseal_state;
    }
    if (durable.IsEmpty()) return false;
    const auto unauthenticated = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker) return false;
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->terminal_carrier_hash)};
        if (terminal == nullptr ||
            terminal->nHeight != marker->terminal_carrier_height) {
            return true;
        }
        return !IsPaymentAuditPrefixAuthenticated(*terminal);
    };
    return unauthenticated(durable.active) ||
           unauthenticated(durable.prospective);
}

bool CChainLocksHandler::ClearBTCCPreseal(
    const pq::BTCCPresealMarker& expected)
{
    LOCK(cs_main);
    LOCK(m_btcc_preseal_mutex);
    pq::BTCCPresealState next{m_btcc_preseal_state};
    if (next.active == expected) {
        next.active.reset();
    } else if (next.prospective == expected) {
        next.prospective.reset();
    } else {
        return m_btcc_preseal_state.IsEmpty();
    }
    if (!PersistBTCCPresealStateLocked(next)) {
        return false;
    }
    LogPrintf("CChainLocksHandler::%s -- authenticated deferred BTCC prefix "
              "has been replayed to NEVM\n", __func__);
    return true;
}

bool CChainLocksHandler::ClearPaymentAuditPreseal(
    const pq::PaymentAuditPresealMarker& expected)
{
    LOCK(cs_main);
    LOCK(m_btcc_preseal_mutex);
    pq::PaymentAuditPresealState next{
        m_payment_audit_preseal_state};
    if (next.active == expected) {
        next.active.reset();
    } else if (next.prospective == expected) {
        next.prospective.reset();
    } else {
        return m_payment_audit_preseal_state.IsEmpty();
    }
    if (!PersistPaymentAuditPresealStateLocked(next)) return false;
    LogPrintf("CChainLocksHandler::%s -- authenticated payment-audit "
              "prefix has been replayed to NEVM\n",
              __func__);
    return true;
}

bool CChainLocksHandler::PersistBTCCPresealStateLocked(
    const pq::BTCCPresealState& state)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_btcc_preseal_mutex);
    pq::BTCCPresealState durable{state};
    const bool changed{durable != m_btcc_preseal_state};
    uint64_t next_revision{m_btcc_preseal_revision};
    if (changed && !durable.IsEmpty()) {
        if (next_revision == std::numeric_limits<uint64_t>::max()) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return false;
        }
        ++next_revision;
        if (durable.active) durable.active->revision = next_revision;
        if (durable.prospective) {
            durable.prospective->revision = next_revision;
        }
    }
    if (!m_persistence || !durable.IsStructurallyValid()) {
        m_persistence_failed.store(true);
        DisableShareAdmission();
        return false;
    }
    if (!durable.IsEmpty()) {
        std::optional<int32_t> auxiliary_floor;
        if (!deterministicMNManager || !m_quorum_build_config ||
            !BTCCPresealAuxiliaryRetentionFloor(
                durable, *m_quorum_build_config, auxiliary_floor) ||
            !auxiliary_floor ||
            !deterministicMNManager->FlushPendingSnapshotsToDisk(
                /*fSync=*/true)) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return false;
        }
    }
    if (!m_persistence->PersistBTCCPresealState(durable)) {
        m_persistence_failed.store(true);
        DisableShareAdmission();
        return false;
    }
    if (changed) {
        ClearNeededBTCCCertificate(
            NeededBTCCCertificateSource::PRESEAL_REPLAY);
    }
    m_btcc_preseal_state = durable;
    m_btcc_preseal_revision = next_revision;
    UpdateBTCCPresealPruneLock(durable);
    UpdatePresealAuxiliaryRetention(
        durable, m_payment_audit_preseal_state);
    return true;
}

bool CChainLocksHandler::PersistPaymentAuditPresealStateLocked(
    const pq::PaymentAuditPresealState& state)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_btcc_preseal_mutex);
    pq::PaymentAuditPresealState durable{state};
    uint64_t next_revision{m_payment_audit_preseal_revision};
    if (durable != m_payment_audit_preseal_state && !durable.IsEmpty()) {
        if (next_revision == std::numeric_limits<uint64_t>::max()) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return false;
        }
        ++next_revision;
        if (durable.active) durable.active->revision = next_revision;
        if (durable.prospective) {
            durable.prospective->revision = next_revision;
        }
    }
    if (!m_persistence || !durable.IsStructurallyValid()) {
        m_persistence_failed.store(true);
        DisableShareAdmission();
        return false;
    }
    if (!durable.IsEmpty()) {
        std::optional<int32_t> auxiliary_floor;
        if (!deterministicMNManager || !m_config ||
            !m_quorum_build_config ||
            !PaymentAuditPresealAuxiliaryRetentionFloor(
                durable, *m_config, *m_quorum_build_config,
                auxiliary_floor) ||
            !auxiliary_floor ||
            // BeginPaymentAuditPreseal records the predecessor's indexed
            // receipt/probation roots before the carrier itself is committed.
            // Publish dirty block-index metadata only after its referenced
            // block and undo streams are durable, then fsync the marker.
            !deterministicMNManager->FlushPendingSnapshotsToDisk(
                /*fSync=*/true) ||
            !FlushPaymentAuditPresealBlockFilesForDurability(durable) ||
            !m_chainman.m_blockman.WriteBlockIndexDB()) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return false;
        }
    }
    if (!m_persistence->PersistPaymentAuditPresealState(durable)) {
        m_persistence_failed.store(true);
        DisableShareAdmission();
        return false;
    }
    m_payment_audit_preseal_state = durable;
    m_payment_audit_preseal_revision = next_revision;
    UpdatePaymentAuditPresealPruneLock(durable);
    UpdatePresealAuxiliaryRetention(m_btcc_preseal_state, durable);
    return true;
}

bool CChainLocksHandler::FlushPaymentAuditPresealBlockFilesForDurability(
    const pq::PaymentAuditPresealState& state) const
{
    AssertLockHeld(cs_main);
    std::array<std::optional<int32_t>, node::BlockfileType::NUM_TYPES>
        flush_heights{};
    const auto require_height = [&](int32_t height) {
        if (height < 0) return false;
        const auto type{
            m_chainman.m_blockman.m_snapshot_height &&
                    height >= *m_chainman.m_blockman.m_snapshot_height
                ? node::BlockfileType::ASSUMED
                : node::BlockfileType::NORMAL};
        flush_heights[static_cast<std::size_t>(type)] = height;
        return true;
    };
    const auto require_marker = [&](const auto& marker) {
        if (!marker) return true;
        // The marker authenticates the state immediately before its first
        // carrier and may advance across the AssumeUTXO block-file split.
        // One current-cursor flush per represented type orders every earlier
        // file, which was finalized when that cursor advanced.
        return marker->earliest_carrier_height > 0 &&
               require_height(marker->earliest_carrier_height - 1) &&
               require_height(marker->terminal_carrier_height);
    };
    if (!require_marker(state.active) ||
        !require_marker(state.prospective)) {
        return false;
    }
    for (const auto& height : flush_heights) {
        if (height &&
            !m_chainman.m_blockman.FlushChainstateBlockFile(*height)) {
            return false;
        }
    }
    return true;
}

void CChainLocksHandler::UpdateBTCCPresealPruneLock(
    const pq::BTCCPresealState& state)
{
    AssertLockHeld(cs_main);
    int32_t earliest{std::numeric_limits<int32_t>::max()};
    const auto inspect = [&](const auto& marker) {
        if (marker) {
            earliest = std::min(earliest,
                                marker->earliest_carrier_height);
        }
    };
    inspect(state.active);
    inspect(state.prospective);
    if (earliest == std::numeric_limits<int32_t>::max()) {
        m_chainman.m_blockman.RemovePruneLock(
            std::string{BTCC_NEVM_REPLAY_PRUNE_LOCK});
        return;
    }
    m_chainman.m_blockman.UpdatePruneLockLowerOnly(
        std::string{BTCC_NEVM_REPLAY_PRUNE_LOCK},
        node::PruneLockInfo{earliest});
    // SYSCOIN: A prolonged ChainLock/Geth outage intentionally permits
    // unbounded block-file growth. Retaining exact replay bodies is required
    // to keep Syscoin and the paired execution chain convergent after recovery.
    LogPrint(BCLog::PRUNE,
             "BTCC/NEVM replay locks block pruning from height %d; disk usage "
             "may grow without bound while replay remains deferred\n",
             earliest);
}

void CChainLocksHandler::UpdatePaymentAuditPresealPruneLock(
    const pq::PaymentAuditPresealState& state)
{
    AssertLockHeld(cs_main);
    int32_t earliest{std::numeric_limits<int32_t>::max()};
    const auto inspect = [&](const auto& marker) {
        if (marker) {
            earliest = std::min(earliest,
                                marker->earliest_carrier_height);
        }
    };
    inspect(state.active);
    inspect(state.prospective);
    if (earliest == std::numeric_limits<int32_t>::max()) {
        m_chainman.m_blockman.RemovePruneLock(
            std::string{PAYMENT_AUDIT_REPLAY_PRUNE_LOCK});
        return;
    }
    m_chainman.m_blockman.UpdatePruneLockLowerOnly(
        std::string{PAYMENT_AUDIT_REPLAY_PRUNE_LOCK},
        node::PruneLockInfo{earliest});
    LogPrint(BCLog::PRUNE,
             "payment-audit replay locks block pruning from height %d "
             "through exact NEVM replay and durable marker clearing\n",
             earliest);
}

void CChainLocksHandler::UpdatePresealAuxiliaryRetention(
    const pq::BTCCPresealState& btcc_state,
    const pq::PaymentAuditPresealState& payment_audit_state)
{
    AssertLockHeld(cs_main);
    if (!deterministicMNManager) {
        if (!btcc_state.IsEmpty() || !payment_audit_state.IsEmpty()) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
        }
        return;
    }

    std::optional<int32_t> btcc_floor;
    std::optional<int32_t> payment_audit_floor;
    const bool valid{
        m_quorum_build_config && m_config &&
        BTCCPresealAuxiliaryRetentionFloor(
            btcc_state, *m_quorum_build_config, btcc_floor) &&
        PaymentAuditPresealAuxiliaryRetentionFloor(
            payment_audit_state, *m_config, *m_quorum_build_config,
            payment_audit_floor)};
    std::optional<int32_t> floor;
    if (btcc_floor) floor = btcc_floor;
    if (payment_audit_floor) {
        floor = floor ? std::min(*floor, *payment_audit_floor)
                      : payment_audit_floor;
    }
    if ((!btcc_state.IsEmpty() || !payment_audit_state.IsEmpty()) &&
        (!valid || !floor)) {
        // A loaded marker is already durable. Retain every persisted snapshot
        // fail-closed if its configured roster floor cannot be reconstructed;
        // verification remains disabled until the profile is repaired.
        floor = 0;
        m_persistence_failed.store(true);
        DisableShareAdmission();
    }
    const int effective{
        deterministicMNManager->UpdateReplaySnapshotRetentionFloor(floor)};
    if (floor) {
        LogPrint(BCLog::SYS,
                 "deferred finality replay retains all DMN/PQ branch "
                 "snapshots from "
                 "logical floor %d (effective lower-only floor %d); disk "
                 "usage may grow without bound until replay clears\n",
                 *floor, effective);
    }
}

void CChainLocksHandler::UpdateDurableChainLockAuxiliaryRetention()
{
    if (!deterministicMNManager) return;

    std::optional<int32_t> floor;
    bool valid{true};
    bool found_durable{false};
    const auto inspect_height = [&](int32_t height) {
        found_durable = true;
        if (!m_quorum_build_config) {
            valid = false;
            return;
        }
        const auto candidate_floor{OldestRosterSnapshotHeight(
            *m_quorum_build_config, height)};
        if (!candidate_floor) {
            valid = false;
            return;
        }
        floor = floor ? std::min(*floor, *candidate_floor)
                      : *candidate_floor;
    };
    const auto inspect_recovery_source =
        [&](const pq::RecoveryRosterAuthoritySource& source) {
            if (source.IsNull() || !valid) return;
            if (!m_quorum_build_config || !floor) {
                valid = false;
                return;
            }
            const auto authority_floor{RecoveryAuthoritySnapshotHeight(
                *m_quorum_build_config, source)};
            if (!authority_floor) {
                valid = false;
                return;
            }
            floor = std::min(*floor, *authority_floor);
        };
    const auto inspect = [&](const auto& chainlock,
                             bool retain_recovery_source = true) {
        if (!chainlock || !valid) return;
        inspect_height(chainlock->statement.height);
        if (!valid) return;
        if (retain_recovery_source) {
            inspect_recovery_source(
                chainlock->statement.roster_beacons.active
                    .recovery_authority_source);
        }
    };
    if (m_persistence) {
        const auto durable{m_persistence->GetFinalityState()};
        inspect(durable.best);
        inspect(durable.unsealed_btcc);
        if (durable.receipt_archive_authorization) {
            inspect(std::optional<pq::FinalChainLockRecordMetadata>{
                durable.receipt_archive_authorization->predecessor});
        }
        if (durable.payment_audit_seal_context) {
            // The capsule embeds the exact fixed recovery authority. Only
            // canonical normal/mixed roster snapshots need to remain below
            // the GC floor while its carrier window can still be replayed.
            inspect(std::optional<pq::FinalChainLockRecordMetadata>{
                        durable.payment_audit_seal_context->Seal()},
                    /*retain_recovery_source=*/false);
        }
        if (const auto authorization_base_height{
                m_persistence->OldestAuthorizationBaseHeight()}) {
            inspect_height(*authorization_base_height);
        }
        for (const auto& source :
             m_persistence->LoadAuthorizationBaseRecoverySources()) {
            inspect_recovery_source(source);
        }
    }
    if (!found_durable && m_config) {
        // SYSCOIN: The activation predecessor bounds initial roster retention,
        // but it grants no finality. Only a durable verified winner may later
        // authorize destructive GC.
        const auto first_target{m_quorum_build_config
            ? pq::NextEligibleChainLockTargetHeight(
                  m_quorum_build_config->schedule,
                  m_config->activation_predecessor_height)
            : std::nullopt};
        const auto first_roster_floor{first_target && m_quorum_build_config
            ? OldestRosterSnapshotHeight(
                  *m_quorum_build_config, *first_target)
            : std::nullopt};
        if (!first_roster_floor) {
            valid = false;
        } else {
            floor = std::min(m_config->activation_predecessor_height,
                             *first_roster_floor);
        }
    }
    if (!valid) {
        // A durable certificate without reconstructible roster coordinates
        // cannot be safely imported. Preserve all snapshots and disable new
        // finality until the configured profile is repaired.
        floor = 0;
        m_persistence_failed.store(true);
        DisableShareAdmission();
    }
    deterministicMNManager->UpdateFinalitySnapshotRetentionFloor(floor);
}

bool CChainLocksHandler::FlushChainLockAuxiliarySnapshotsForDurability()
{
    if (!deterministicMNManager) return false;
    // SYSCOIN: This callback is reached only after context construction and
    // all 801 signatures (or while importing that same fsynced certificate).
    // Advance the publication generation while arming retain-all so an older
    // enforcement proof cannot release a newer certificate's barrier.
    if (!m_auxiliary_history_gc_auth_gate.ArmPublication([] {
            deterministicMNManager
                ->UpdateFinalitySnapshotPublicationRetention(true);
            return true;
        })) {
        return false;
    }
    return deterministicMNManager->FlushPendingSnapshotsToDisk(
        /*fSync=*/true);
}

void CChainLocksHandler::MaybeReleaseFinalitySnapshotPublicationRetention()
{
    const auto authorization_token{
        m_auxiliary_history_gc_auth_gate.ObserveReady()};
    if (!authorization_token) return;
    const auto revoke = [&] {
        const auto result{m_auxiliary_history_gc_auth_gate.Revoke([this] {
            return RevokeAuxiliaryHistoryGCAuthorization();
        })};
        if (result == AuxiliaryHistoryGCAuthorizationGate::
                          MutationResult::FAILED) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
        }
    };
    const bool persisted_pending{WITH_LOCK(m_persisted_mutex, return
        m_pending_persisted.has_value() ||
        m_pending_persisted_unsealed_btcc.has_value() ||
        !m_pending_persisted_authorization_bases.empty() ||
        m_persisted_best_auth_pending ||
        m_persisted_unsealed_auth_pending ||
        m_persisted_invalid;)};
    const bool healthy{
        deterministicMNManager && m_config && m_quorum_build_config &&
        m_persistence && m_store && m_payment_audit_store &&
        m_payment_audit_staging_store &&
        m_payment_audit_store->IsHealthy() &&
        m_payment_audit_staging_store->IsHealthy() &&
        !m_persistence_failed.load() && m_enforced.load() &&
        !persisted_pending};
    if (!healthy) {
        revoke();
        return;
    }

    const auto durable_state{m_persistence->GetFinalityState()};
    const auto& durable_best{durable_state.best};
    const auto accepted_best{m_store->GetBestRecord()};
    CDeterministicMNManager::AuxiliaryHistoryGCAuthorization authorization;
    if (durable_best) {
        if (!accepted_best ||
            *durable_best != accepted_best->metadata ||
            !durable_best->IsInternallyConsistent(m_genesis_hash)) {
            revoke();
            return;
        }
        authorization.source = CDeterministicMNManager::
            AuxiliaryHistoryGCAuthorizationSource::
                ENFORCED_DURABLE_CHAINLOCK;
        authorization.block = {
            durable_best->statement.height,
            durable_best->statement.block_hash};
    } else {
        // A height-only activation boundary is not finality and cannot
        // authorize destructive pruning. Wait for an enforced durable winner.
        revoke();
        return;
    }

    const bool authorizer_active{WITH_LOCK(cs_main, {
        const CBlockIndex* active{
            m_chainman.ActiveChain()[authorization.block.height]};
        return active != nullptr &&
               active->GetBlockHash() == authorization.block.block_hash;
    })};
    if (!authorizer_active) {
        revoke();
        return;
    }

    // SYSCOIN: The same barrier publishes exact finality authority and releases
    // the all-branch hold, so maintenance cannot observe one without the other.
    const auto result{m_auxiliary_history_gc_auth_gate.TryPublish(
        *authorization_token, [&authorization] {
            return deterministicMNManager
                ->UpdateAuxiliaryHistoryGCAuthorization(
                    authorization, /*release_publication=*/true);
        })};
    if (result == AuxiliaryHistoryGCAuthorizationGate::MutationResult::FAILED) {
        m_persistence_failed.store(true);
        DisableShareAdmission();
    }
}

bool CChainLocksHandler::RevalidatePendingBTCCReceiptDependency()
{
    LOCK(cs_main);
    std::optional<DeferredBTCCReceiptCandidate> best_deferred;
    node::CBlockIndexWorkComparator compare;
    for (Chainstate* chainstate : m_chainman.GetAll()) {
        const auto candidate{
            chainstate->GetBestDeferredBTCCReceiptCandidate()};
        if (candidate &&
            (!best_deferred ||
             compare(best_deferred->best_candidate,
                     candidate->best_candidate))) {
            best_deferred = candidate;
        }
    }

    LOCK(m_pending_btcc_receipt_mutex);
    if (best_deferred) {
        const PendingBTCCReceiptDependency replacement{
            best_deferred->logical_id,
            best_deferred->carrier->GetBlockHash()};
        if (!m_pending_btcc_receipt ||
            replacement.logical_id !=
                m_pending_btcc_receipt->logical_id ||
            replacement.carrier_hash !=
                m_pending_btcc_receipt->carrier_hash) {
            if (m_pending_btcc_receipt) {
                LogPrint(BCLog::CHAINLOCKS,
                         "CChainLocksHandler::%s -- replacing stale "
                         "dependency %s with highest-work ADVANCE %s\n",
                         __func__,
                         m_pending_btcc_receipt->logical_id.ToString(),
                         replacement.logical_id.ToString());
            } else {
                LogPrint(BCLog::CHAINLOCKS,
                         "CChainLocksHandler::%s -- promoting highest-work "
                         "ADVANCE %s into the empty request lane\n",
                         __func__, replacement.logical_id.ToString());
            }
            m_pending_btcc_receipt = replacement;
            m_pending_btcc_last_request = std::chrono::microseconds{0};
        }
        return true;
    }

    if (m_pending_btcc_receipt) {
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- dropping stale carrier %s "
                 "dependency %s\n",
                 __func__,
                 m_pending_btcc_receipt->carrier_hash.ToString(),
                 m_pending_btcc_receipt->logical_id.ToString());
        m_pending_btcc_receipt.reset();
        m_pending_btcc_last_request = std::chrono::microseconds{0};
    }
    return false;
}

bool CChainLocksHandler::RevalidatePendingPaymentAuditReceiptDependency()
{
    LOCK(cs_main);
    return RevalidatePendingPaymentAuditReceiptDependencyLocked();
}

bool CChainLocksHandler::RevalidatePendingPaymentAuditReceiptDependencyLocked()
{
    AssertLockHeld(cs_main);
    std::optional<DeferredBTCCReceiptCandidate> best_deferred;
    node::CBlockIndexWorkComparator compare;
    for (Chainstate* chainstate : m_chainman.GetAll()) {
        const auto candidate{
            chainstate->GetBestDeferredPaymentAuditReceiptCandidate()};
        if (candidate &&
            (!best_deferred ||
             compare(best_deferred->best_candidate,
                     candidate->best_candidate))) {
            best_deferred = candidate;
        }
    }

    std::optional<PendingPaymentAuditReceiptDependency> replacement;
    if (best_deferred && best_deferred->carrier != nullptr &&
        best_deferred->best_candidate != nullptr) {
        CBlock carrier_block;
        if (m_chainman.m_blockman.ReadBlockFromDisk(
                carrier_block, *best_deferred->carrier)) {
            const auto receipt{ExtractDeferredPaymentAuditReceipt(
                carrier_block, best_deferred->logical_id,
                *best_deferred->carrier,
                *best_deferred->best_candidate)};
            if (receipt && best_deferred->carrier->pprev != nullptr) {
                replacement = PendingPaymentAuditReceiptDependency{
                    *receipt, best_deferred->carrier->GetBlockHash(),
                    best_deferred->carrier->pprev->GetBlockHash()};
            }
        }
    }

    LOCK(m_pending_payment_audit_receipt_mutex);
    if (replacement) {
        if (m_pending_payment_audit_receipt == replacement) {
            return true;
        }
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- reconstructing highest-work "
                 "payment-audit carrier %s witness %s\n",
                 __func__, replacement->carrier_hash.ToString(),
                 replacement->receipt.audit_witness_id.ToString());
        m_pending_payment_audit_receipt = std::move(replacement);
        m_pending_payment_audit_last_request =
            std::chrono::microseconds{0};
        return true;
    }
    if (best_deferred) {
        // Disk or index readiness is a local retry condition. Preserve the
        // previously authorized exact dependency until its replacement has
        // been reconstructed completely.
        if (m_pending_payment_audit_receipt) {
            for (Chainstate* chainstate : m_chainman.GetAll()) {
                const auto dependency{
                    chainstate->m_deferred_btcc_receipt_candidates.find(
                        m_pending_payment_audit_receipt->receipt
                            .audit_witness_id)};
                if (dependency ==
                        chainstate->m_deferred_btcc_receipt_candidates.end() ||
                    dependency->second.kind !=
                        DeferredReceiptCertificateKind::PAYMENT_AUDIT) {
                    continue;
                }
                for (const auto& [carrier, candidates] :
                     dependency->second.branches) {
                    if (carrier != nullptr && carrier->pprev != nullptr &&
                        carrier->GetBlockHash() ==
                            m_pending_payment_audit_receipt->carrier_hash &&
                        carrier->pprev->GetBlockHash() ==
                            m_pending_payment_audit_receipt
                                ->carrier_parent_hash &&
                        (carrier->nStatus &
                         (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) == 0 &&
                        (carrier->nStatus & BLOCK_HAVE_DATA) != 0 &&
                        !carrier->IsAssumedValid() &&
                        carrier->IsValid(BLOCK_VALID_TRANSACTIONS)) {
                        for (const CBlockIndex* candidate : candidates) {
                            if (candidate != nullptr &&
                                (candidate->nStatus &
                                 (BLOCK_FAILED_MASK |
                                  BLOCK_CONFLICT_CHAINLOCK)) == 0 &&
                                (candidate->nStatus & BLOCK_HAVE_DATA) != 0 &&
                                !candidate->IsAssumedValid() &&
                                candidate->IsValid(
                                    BLOCK_VALID_TRANSACTIONS) &&
                                candidate->HaveNumChainTxs() &&
                                (chainstate->m_chain.Tip() == nullptr ||
                                 candidate->nChainWork >
                                     chainstate->m_chain.Tip()->nChainWork)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        m_pending_payment_audit_receipt.reset();
        m_pending_payment_audit_last_request =
            std::chrono::microseconds{0};
        return false;
    }
    // Never synthesize receipt authorization from a deferred map key. If the
    // deferred set is empty, the old singleton no longer has a carrier.
    m_pending_payment_audit_receipt.reset();
    m_pending_payment_audit_last_request = std::chrono::microseconds{0};
    return false;
}

CChainLocksHandler::HistoricalAdmissionContext
CChainLocksHandler::GetHistoricalAdmission(
    const pq::ChainLockStatement& statement,
    const uint256& logical_id) const
{
    LOCK(cs_main);
    return GetHistoricalAdmissionLocked(statement, logical_id);
}

bool CChainLocksHandler::IsExactHistoricalResetCandidate(
    const pq::ChainLockStatement& statement,
    const pq::ChainLockScheduleConfig& chainlock,
    const pq::BTCCScheduleConfig& btcc,
    int32_t activation_predecessor_height,
    const uint256& activation_predecessor_hash,
    bool has_durable_best,
    bool target_is_active,
    const uint256& target_btcp_prev) noexcept
{
    if (!target_is_active || !statement.IsStructurallyValid()) return false;
    const auto target_epoch{
        pq::EpochForHeight(chainlock, statement.height)};
    const auto reset_transition{
        pq::CanonicalRosterResetTransitionForTarget(
            chainlock, btcc, activation_predecessor_height,
            statement.height)};
    if (!target_epoch || !reset_transition ||
        *reset_transition != statement.roster_transition) {
        return false;
    }
    const auto& newest{statement.roster_beacons.active.seeds.back()};
    if (!newest.IsReady() || newest.epoch != *target_epoch) return false;

    if (*reset_transition ==
        pq::RosterAuthorizationTransitionKind::INITIALIZE) {
        return !has_durable_best &&
               pq::IsInitialNormalRosterBeaconWindow(
                   statement.roster_beacons) &&
               statement.previous_chainlock_height ==
                   activation_predecessor_height &&
               statement.previous_chainlock_hash ==
                   activation_predecessor_hash &&
               statement.previous_btcc_cursor.IsNull() &&
               newest.anchor_cursor.sys_height == statement.height &&
               newest.anchor_cursor.sys_hash == statement.block_hash &&
               target_btcp_prev == newest.anchor_cursor.btc_hash &&
               statement.accepted_btcc_cursor == newest.anchor_cursor &&
               statement.btcc_advance == pq::BTCCAdvance::ADVANCE;
    }
    return has_durable_best &&
           *reset_transition ==
               pq::RosterAuthorizationTransitionKind::RECOVER &&
           pq::IsRecoveryRosterBeaconWindow(statement.roster_beacons) &&
           statement.btcc_advance == pq::BTCCAdvance::KEEP;
}

CChainLocksHandler::HistoricalAdmissionContext
CChainLocksHandler::GetHistoricalAdmissionLocked(
    const pq::ChainLockStatement& statement,
    const uint256& logical_id) const
{
    AssertLockHeld(cs_main);
    if (!statement.IsStructurallyValid() || logical_id.IsNull() ||
        !m_config || !m_store ||
        m_persistence_failed.load() || IsPersistedChainLockPending()) {
        return {};
    }
    const auto expected_target{pq::NextEligibleChainLockTargetHeight(
        m_config->chainlock_schedule,
        statement.previous_chainlock_height)};
    if (!expected_target || statement.height != *expected_target) {
        return {};
    }

    const auto best{m_store->GetBestRecord()};
    if (!m_chainman.IsBaseBlockSyncComplete() ||
        (m_chainman.IsSnapshotActive() &&
         !m_chainman.IsSnapshotValidated())) {
        return {};
    }
    const CBlockIndex* tip{m_chainman.ActiveTip()};
    const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
        statement.block_hash)};
    const CBlockIndex* active_target{
        tip == nullptr || tip->nHeight < statement.height
            ? nullptr
            : tip->GetAncestor(statement.height)};
    if (tip == nullptr || target == nullptr ||
        target->nHeight != statement.height) {
        return {};
    }
    const CBlockIndex* activation_predecessor{
        !best && tip->nHeight >= m_config->activation_predecessor_height
            ? tip->GetAncestor(m_config->activation_predecessor_height)
            : nullptr};
    if (!best && activation_predecessor == nullptr) return {};
    const pq::ChainLockPredecessor local{
        best ? pq::ChainLockPredecessor{
                   best->metadata.statement.height,
                   best->metadata.statement.block_hash,
                   best->metadata.statement.accepted_btcc_cursor}
             : pq::ChainLockPredecessor{
                   m_config->activation_predecessor_height,
                   activation_predecessor->GetBlockHash(), {}}};
    const bool target_is_active{target == active_target};

    pq::BTCCPresealState preseal;
    pq::PaymentAuditPresealState payment_audit_preseal;
    {
        LOCK(m_btcc_preseal_mutex);
        preseal = m_btcc_preseal_state;
        payment_audit_preseal = m_payment_audit_preseal_state;
    }
    // A side-branch current certificate may adjudicate only the ordinary
    // signing round. Durable BTCC/payment replay obligations stay bound to
    // their active/prospective marker branch and revision.
    if (!target_is_active &&
        (!preseal.IsEmpty() || !payment_audit_preseal.IsEmpty())) {
        return {};
    }
    if (m_config->btcc_receipt_assumption_anchor.IsDisabled() &&
        (payment_audit_preseal.IsEmpty() ||
         !IsPaymentAuditPresealActive())) {
        return {};
    }
    const uint256 marker_token{PresealAdmissionToken(
        preseal, payment_audit_preseal)};
    bool exact_preseal_receipt{false};
    bool has_uncovered_active_marker{false};
    bool candidate_covers_active_markers{true};
    const auto inspect_marker = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker || !marker->IsStructurallyValid()) return;
        const CBlockIndex* earliest{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->earliest_carrier_hash)};
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->terminal_carrier_hash)};
        if (earliest == nullptr || terminal == nullptr ||
            earliest->nHeight != marker->earliest_carrier_height ||
            terminal->nHeight != marker->terminal_carrier_height ||
            tip->GetAncestor(terminal->nHeight) != terminal ||
            terminal->GetAncestor(earliest->nHeight) != earliest) {
            return;
        }

        const bool winner_covers{
            best && best->metadata.statement.height >= terminal->nHeight &&
            tip->GetAncestor(best->metadata.statement.height) != nullptr &&
            tip->GetAncestor(best->metadata.statement.height)->GetBlockHash() ==
                best->metadata.statement.block_hash &&
            tip->GetAncestor(best->metadata.statement.height)
                    ->GetAncestor(terminal->nHeight) == terminal};
        const auto& receipt{marker->terminal_receipt};
        const bool exact_receipt_verified{
            CheckBTCCReceiptCertificate(receipt, *terminal) ==
            BTCCReceiptCertificateStatus::VERIFIED};
        if (!winner_covers && !exact_receipt_verified) {
            has_uncovered_active_marker = true;
            candidate_covers_active_markers =
                candidate_covers_active_markers &&
                target->nHeight >= terminal->nHeight &&
                target->GetAncestor(terminal->nHeight) == terminal;
        }

        exact_preseal_receipt =
            exact_preseal_receipt ||
            (!winner_covers && !exact_receipt_verified &&
             logical_id == receipt.chainlock_logical_id &&
             statement.height > m_config->activation_predecessor_height &&
             statement.height == receipt.chainlock_target_height &&
             statement.block_hash == receipt.chainlock_target_hash &&
             statement.accepted_btcc_cursor == receipt.accepted_cursor &&
             statement.btcc_advance == pq::BTCCAdvance::ADVANCE &&
             target->GetAncestor(terminal->nHeight) == nullptr);
    };
    inspect_marker(preseal.active);
    inspect_marker(preseal.prospective);

    const auto inspect_payment_audit_marker = [&](const auto& marker,
                                                  bool active_slot)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker || !marker->IsStructurallyValid()) return;
        const CBlockIndex* earliest{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->earliest_carrier_hash)};
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->terminal_carrier_hash)};
        if (earliest == nullptr || terminal == nullptr ||
            earliest->pprev == nullptr ||
            earliest->nHeight != marker->earliest_carrier_height ||
            terminal->nHeight != marker->terminal_carrier_height) {
            if (active_slot) {
                has_uncovered_active_marker = true;
                candidate_covers_active_markers = false;
            }
            return;
        }
        if (tip->nHeight < terminal->nHeight ||
            tip->GetAncestor(terminal->nHeight) != terminal) {
            return;
        }
        const auto predecessor_state{
            IndexedPaymentAuditReceiptState(*earliest->pprev)};
        const auto terminal_state{
            IndexedPaymentAuditReceiptState(*terminal)};
        if (terminal->GetAncestor(earliest->nHeight) != earliest ||
            (terminal->nStatus & BLOCK_FAILED_MASK) ||
            terminal->IsAssumedValid() ||
            !terminal->IsValid(BLOCK_VALID_SCRIPTS) ||
            !HasFullReceiptIndexProvenance(*terminal) ||
            !predecessor_state ||
            *predecessor_state != marker->predecessor_receipt_state ||
            earliest->pprev->pqPaymentProbationStateHash !=
                marker->predecessor_probation_state_hash ||
            !terminal_state ||
            terminal_state->cursor.carrier_height !=
                marker->terminal_carrier_height ||
            terminal_state->cursor.epoch !=
                marker->terminal_receipt.epoch ||
            terminal_state->cursor.seal_block_hash !=
                marker->terminal_receipt.seal_block_hash ||
            terminal_state->cursor.audit_logical_id !=
                marker->terminal_receipt.audit_logical_id ||
            terminal_state->cursor.audit_witness_id !=
                marker->terminal_receipt.audit_witness_id ||
            terminal->pqPaymentProbationStateHash !=
                marker->terminal_receipt.next_probation_state_hash) {
            has_uncovered_active_marker = true;
            candidate_covers_active_markers = false;
            return;
        }

        const auto signed_target_covers = [&] (
            const CBlockIndex* signed_target,
            const pq::PaymentAuditReceiptState& signed_receipt_state,
            const uint256& signed_probation_state_hash)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            if (signed_target == nullptr ||
                signed_target->nHeight < terminal->nHeight ||
                signed_target->GetAncestor(terminal->nHeight) != terminal) {
                return false;
            }
            const auto indexed_target_state{
                IndexedPaymentAuditReceiptState(*signed_target)};
            if (!indexed_target_state ||
                *indexed_target_state != signed_receipt_state ||
                signed_target->pqPaymentProbationStateHash !=
                    signed_probation_state_hash) {
                return false;
            }
            const auto& terminal_cursor{terminal_state->cursor};
            const auto& target_cursor{indexed_target_state->cursor};
            if (terminal_cursor.IsNull() || target_cursor.IsNull() ||
                target_cursor.epoch < terminal_cursor.epoch ||
                target_cursor.carrier_height <
                    terminal_cursor.carrier_height) {
                return false;
            }
            if (signed_target->nHeight > terminal->nHeight &&
                ClassifyHistoricalReceiptIndexRangeCached(
                    *signed_target, terminal->nHeight + 1) !=
                    PaymentAuditContextStatus::READY) {
                return false;
            }
            return target_cursor != terminal_cursor ||
                   (*indexed_target_state == *terminal_state &&
                    signed_probation_state_hash ==
                        terminal->pqPaymentProbationStateHash);
        };

        const CBlockIndex* winner_target{
            best ? tip->GetAncestor(best->metadata.statement.height) : nullptr};
        const bool winner_covers{
            best && winner_target != nullptr &&
            winner_target->GetBlockHash() ==
                best->metadata.statement.block_hash &&
            signed_target_covers(
                winner_target,
                best->metadata.statement.payment_audit_receipt_state,
                best->metadata.statement.payment_probation_state_hash)};
        if (winner_covers) return;

        const bool candidate_covers{
            signed_target_covers(
                target, statement.payment_audit_receipt_state,
                statement.payment_probation_state_hash)};
        has_uncovered_active_marker = true;
        candidate_covers_active_markers =
            candidate_covers_active_markers && candidate_covers;
    };
    inspect_payment_audit_marker(payment_audit_preseal.active,
                                 /*active_slot=*/true);
    inspect_payment_audit_marker(payment_audit_preseal.prospective,
                                 /*active_slot=*/false);

    // SYSCOIN: The terminal T=C-10 certificate is an exact dependency of the
    // durable carrier marker. ProcessNewChainLock archives it below the local
    // winner, or installs it as marker-authorized catch-up when it is newer.
    if (target_is_active && exact_preseal_receipt) {
        return {HistoricalAdmission::PRESEAL_RECEIPT, marker_token};
    }

    if (statement.height <= local.height ||
        statement.previous_chainlock_height < local.height) {
        return {};
    }
    const bool exact_local_successor{
        statement.previous_chainlock_height == local.height &&
        statement.previous_chainlock_hash == local.block_hash &&
        statement.previous_btcc_cursor == local.btcc_cursor};
    const CBlockIndex* local_index{
        local.height >= 0 ? target->GetAncestor(local.height) : nullptr};
    if ((local.height >= 0 &&
         (local_index == nullptr ||
          local_index->GetBlockHash() != local.block_hash)) ||
        (local.height < 0 && !local.block_hash.IsNull())) {
        return {};
    }
    const CBlockIndex* declared_predecessor{
        statement.previous_chainlock_height >= 0
            ? target->GetAncestor(statement.previous_chainlock_height)
            : nullptr};
    if (statement.previous_chainlock_height < 0 ||
        declared_predecessor == nullptr ||
        declared_predecessor->GetBlockHash() !=
            statement.previous_chainlock_hash) {
        return {};
    }
    if (target_is_active && has_uncovered_active_marker &&
        candidate_covers_active_markers) {
        return {HistoricalAdmission::PRESEAL_CATCHUP, marker_token};
    }
    if (has_uncovered_active_marker) return {};

    if (IsExactHistoricalResetCandidate(
            statement, m_config->chainlock_schedule,
            m_config->btcc_schedule,
            m_config->activation_predecessor_height,
            activation_predecessor != nullptr ? activation_predecessor->GetBlockHash() : uint256{},
            best.has_value(), target_is_active,
            target->btcpPrevCommitment)) {
        return {HistoricalAdmission::RECOVERY, {}};
    }
    if (exact_local_successor) return {};
    if (!m_config->btcc_receipt_assumption_anchor.IsDisabled() &&
        IsCurrentChainLockCatchupCandidateAdmissible(
            m_config->chainlock_schedule, *tip, *target)) {
        return {HistoricalAdmission::CURRENT_CATCHUP, {}};
    }
    return {};
}

void CChainLocksHandler::RequestCatchupChainLock()
{
    if (!IsChainLockVerificationAvailable()) {
        return;
    }
    if (GetPendingVerifiedHistoricalChainLock()) return;
    if (!m_config) return;
    {
        LOCK(cs_main);
        if (m_config->btcc_receipt_assumption_anchor.IsDisabled() &&
            !IsPaymentAuditPresealActive()) {
            return;
        }
        if (!m_chainman.IsBaseBlockSyncComplete() ||
            (m_chainman.IsSnapshotActive() &&
             !m_chainman.IsSnapshotValidated())) {
            return;
        }
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const auto latest{tip == nullptr
                              ? std::nullopt
                              : pq::LatestEligibleChainLockTargetHeight(
                                    m_config->chainlock_schedule,
                                    tip->nHeight)};
        const auto best{m_store->GetBestRecord()};
        const int32_t local_height{
            best ? best->metadata.statement.height : m_config->activation_predecessor_height};
        if (!latest || *latest <= local_height) return;
    }
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(m_catchup_mutex);
        if (m_catchup_last_request.count() != 0 &&
            now - m_catchup_last_request < std::chrono::seconds{30}) {
            return;
        }
        m_catchup_last_request = now;
    }
    (void)GetCLSIGFromPeers();
}

void CChainLocksHandler::MaybeReplayPaymentAuditPreseal()
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    pq::PaymentAuditPresealState durable;
    {
        LOCK(m_btcc_preseal_mutex);
        durable = m_payment_audit_preseal_state;
    }
    if (durable.IsEmpty() || !m_config || !m_store ||
        !m_payment_audit_store) {
        return;
    }

    std::optional<pq::PaymentAuditPresealMarker> marker;
    int32_t replay_through{-1};
    uint256 replay_through_hash;
    {
        LOCK(cs_main);
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        if (active_tip == nullptr) return;
        const auto marker_index = [&](const auto& candidate, bool terminal)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> const CBlockIndex* {
            if (!candidate) return nullptr;
            const uint256& hash{
                terminal ? candidate->terminal_carrier_hash
                         : candidate->earliest_carrier_hash};
            const int32_t height{
                terminal ? candidate->terminal_carrier_height
                         : candidate->earliest_carrier_height};
            const CBlockIndex* index{
                m_chainman.m_blockman.LookupBlockIndex(hash)};
            return index != nullptr && index->nHeight == height
                ? index
                : nullptr;
        };
        const auto terminal_on_active = [&](const auto& candidate)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            const CBlockIndex* terminal{marker_index(candidate, true)};
            return terminal != nullptr &&
                   active_tip->nHeight >= terminal->nHeight &&
                   active_tip->GetAncestor(terminal->nHeight) == terminal;
        };

        pq::PaymentAuditPresealState next{durable};
        if (terminal_on_active(next.prospective)) {
            const pq::PaymentAuditPresealMarker* terminal_source{
                &*next.prospective};
            if (terminal_on_active(next.active) &&
                next.active->terminal_carrier_height >
                    terminal_source->terminal_carrier_height) {
                terminal_source = &*next.active;
            }
            const CBlockIndex* winning_terminal{
                m_chainman.m_blockman.LookupBlockIndex(
                    terminal_source->terminal_carrier_hash)};
            const pq::PaymentAuditPresealMarker* boundary_source{nullptr};
            const auto consider_boundary = [&](const auto& candidate)
                EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                const CBlockIndex* earliest{
                    marker_index(candidate, false)};
                if (!candidate || earliest == nullptr ||
                    winning_terminal == nullptr ||
                    winning_terminal->nHeight < earliest->nHeight ||
                    winning_terminal->GetAncestor(earliest->nHeight) !=
                        earliest) {
                    return;
                }
                if (boundary_source == nullptr ||
                    candidate->earliest_carrier_height <
                        boundary_source->earliest_carrier_height) {
                    boundary_source = &*candidate;
                }
            };
            consider_boundary(next.active);
            consider_boundary(next.prospective);
            if (boundary_source == nullptr || winning_terminal == nullptr) {
                return;
            }
            pq::PaymentAuditPresealMarker promoted{*boundary_source};
            promoted.terminal_carrier_height =
                terminal_source->terminal_carrier_height;
            promoted.terminal_carrier_hash =
                terminal_source->terminal_carrier_hash;
            promoted.terminal_receipt = terminal_source->terminal_receipt;
            next.active = std::move(promoted);
            next.prospective.reset();
        }

        if (next.prospective && !terminal_on_active(next.prospective)) {
            const CBlockIndex* prospective{
                marker_index(next.prospective, true)};
            if (prospective != nullptr &&
                ((prospective->nStatus & BLOCK_FAILED_MASK) ||
                 !m_chainman.ActiveChainstate().IsCurrentMostWorkBranch(
                     *prospective))) {
                next.prospective.reset();
            }
        }

        if (next.active && !terminal_on_active(next.active)) {
            const CBlockIndex* earliest{marker_index(next.active, false)};
            if (earliest != nullptr &&
                ((earliest->nStatus & BLOCK_FAILED_MASK) ||
                 active_tip->nHeight < earliest->nHeight ||
                 active_tip->GetAncestor(earliest->nHeight) != earliest)) {
                next.active.reset();
            } else if (earliest != nullptr) {
                CBlock block;
                pq::PaymentAuditReceipt receipt;
                const auto predecessor_state{
                    earliest->pprev == nullptr
                        ? std::optional<pq::PaymentAuditReceiptState>{}
                        : IndexedPaymentAuditReceiptState(*earliest->pprev)};
                const auto indexed_state{
                    IndexedPaymentAuditReceiptState(*earliest)};
                if (!m_chainman.m_blockman.ReadBlockFromDisk(
                        block, *earliest) ||
                    !ExtractPaymentAuditReceipt(block, receipt) ||
                    receipt.IsNull() || !predecessor_state ||
                    !indexed_state ||
                    *predecessor_state !=
                        next.active->predecessor_receipt_state ||
                    earliest->pprev == nullptr ||
                    earliest->pprev->pqPaymentProbationStateHash !=
                        next.active->predecessor_probation_state_hash ||
                    ClassifyPaymentAuditReceiptCarrierContext(
                        receipt, *earliest,
                        pq::PaymentAuditScheduleConfig{
                            m_config->chainlock_schedule,
                            m_config->btcc_schedule}) !=
                        PaymentAuditContextStatus::READY) {
                    return;
                }
                const auto applied{pq::ApplyPaymentAuditReceipt(
                    m_genesis_hash, *predecessor_state, receipt)};
                if (!applied || *applied != *indexed_state ||
                    receipt.next_probation_state_hash !=
                        earliest->pqPaymentProbationStateHash) {
                    return;
                }
                next.active->terminal_carrier_height = earliest->nHeight;
                next.active->terminal_carrier_hash =
                    earliest->GetBlockHash();
                next.active->terminal_receipt = std::move(receipt);
            }
        }

        if (next != durable) {
            LOCK(m_btcc_preseal_mutex);
            if (m_payment_audit_preseal_state != durable ||
                !PersistPaymentAuditPresealStateLocked(next)) {
                return;
            }
            durable = next;
        }
        if (durable.IsEmpty()) return;
        {
            LOCK(m_btcc_preseal_mutex);
            if (!m_btcc_preseal_state.IsEmpty()) return;
        }

        const auto inspect = [&](const auto& candidate)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            if (!candidate || !candidate->IsStructurallyValid()) return true;
            const CBlockIndex* earliest{
                m_chainman.m_blockman.LookupBlockIndex(
                    candidate->earliest_carrier_hash)};
            const CBlockIndex* terminal{
                m_chainman.m_blockman.LookupBlockIndex(
                    candidate->terminal_carrier_hash)};
            if (earliest == nullptr || terminal == nullptr ||
                earliest->nHeight != candidate->earliest_carrier_height ||
                terminal->nHeight != candidate->terminal_carrier_height) {
                return false;
            }
            if (active_tip->nHeight < terminal->nHeight ||
                active_tip->GetAncestor(terminal->nHeight) != terminal) {
                return true;
            }
            if (terminal->GetAncestor(earliest->nHeight) != earliest ||
                !IsPaymentAuditPrefixAuthenticated(*terminal)) {
                return false;
            }
            if (!marker || candidate->earliest_carrier_height <
                               marker->earliest_carrier_height) {
                marker = *candidate;
            }
            return true;
        };
        // Every active compact boundary through the replay target must first
        // be authenticated. Off-branch prospective markers are retained only
        // while FindMostWorkChain can still activate them.
        if (!inspect(durable.active) || !inspect(durable.prospective) ||
            !marker) {
            return;
        }
        replay_through = active_tip->nHeight;
        replay_through_hash = active_tip->GetBlockHash();
    }
    if (!marker || replay_through < marker->earliest_carrier_height ||
        replay_through_hash.IsNull() || !fNEVMConnection) {
        return;
    }

    bool complete{false};
    std::string error;
    if (!m_chainman.ActiveChainstate().ReplayDeferredBTCCNEVM(
            replay_through, replay_through_hash,
            [this, expected = *marker] {
                return ClearPaymentAuditPreseal(expected);
            },
            complete, error)) {
        LogPrintf("CChainLocksHandler::%s -- deferred payment-audit NEVM "
                  "replay paused: %s\n",
                  __func__, error);
        return;
    }
}

bool CChainLocksHandler::RecoverActiveBTCCPresealBounded(
    const CBlockIndex& active_tip,
    pq::BTCCPresealState& state)
{
    AssertLockHeld(cs_main);
    if (!m_config) return false;
    int32_t scan_from{std::numeric_limits<int32_t>::max()};
    if (state.active) {
        scan_from = std::min(
            scan_from, state.active->earliest_carrier_height);
    }
    if (state.prospective) {
        scan_from = std::min(
            scan_from, state.prospective->earliest_carrier_height);
    }
    if (scan_from == std::numeric_limits<int32_t>::max() ||
        scan_from > active_tip.nHeight) {
        m_btcc_preseal_recovery_runtime = {};
        state.active.reset();
        return true;
    }

    const CChain& active_chain{m_chainman.ActiveChain()};
    const int32_t floor_height{scan_from - 1};
    const CBlockIndex* floor{
        floor_height < 0 ? nullptr : active_chain[floor_height]};
    if (floor_height >= 0 && floor == nullptr) return false;
    const uint256 floor_hash{
        floor == nullptr ? uint256{} : floor->GetBlockHash()};
    const auto plan{
        m_btcc_preseal_recovery_runtime.frontier.Plan(
            active_chain, active_tip, floor_height, floor_hash,
            BoundedBTCCPresealSourceToken(
                state,
                m_chainman.GetPQProvenanceRevocationRevision()),
            HistoricalIndexValidationCache::BLOCK_BUDGET)};
    if (plan.reset) {
        m_btcc_preseal_recovery_runtime.recovered.reset();
    }
    if (plan.status == BoundedActiveRangeStatus::INVALID) return false;

    if (plan.status == BoundedActiveRangeStatus::WORK) {
        for (int32_t height{plan.first_height};
             height <= plan.last_height; ++height) {
            if (!pq::IsBTCCReceiptCarrierHeight(
                    m_config->btcc_schedule, height)) {
                continue;
            }
            const CBlockIndex* carrier{active_chain[height]};
            CBlock block;
            pq::BTCCReceipt receipt;
            // Keep the durable branch obligations unchanged until every
            // carrier in the exact active prefix has been inspected.
            if (carrier == nullptr ||
                !m_chainman.m_blockman.ReadBlockFromDisk(block, *carrier) ||
                !ExtractBTCCReceipt(block, receipt) ||
                !pq::ValidateBTCCReceiptOnBranch(
                    m_config->btcc_schedule, *carrier, receipt)) {
                (void)m_btcc_preseal_recovery_runtime.frontier.CommitThrough(
                    active_chain, height - 1);
                return false;
            }
            if (receipt.IsNull() ||
                IsBTCCPrefixAuthenticated(*carrier) ||
                CheckBTCCReceiptCertificate(receipt, *carrier) ==
                    BTCCReceiptCertificateStatus::VERIFIED) {
                continue;
            }
            const auto predecessor_state{
                carrier->pprev == nullptr
                    ? std::optional<pq::BTCCReceiptState>{}
                    : IndexedBTCCReceiptState(*carrier->pprev)};
            if (!predecessor_state) {
                (void)m_btcc_preseal_recovery_runtime.frontier.CommitThrough(
                    active_chain, height - 1);
                return false;
            }
            auto& recovered{m_btcc_preseal_recovery_runtime.recovered};
            if (!recovered) {
                recovered = pq::BTCCPresealMarker{
                    carrier->nHeight,
                    carrier->GetBlockHash(),
                    *predecessor_state,
                    carrier->nHeight,
                    carrier->GetBlockHash(),
                    receipt,
                    uint64_t{1}};
            } else {
                recovered->terminal_carrier_height = carrier->nHeight;
                recovered->terminal_carrier_hash = carrier->GetBlockHash();
                recovered->terminal_receipt = receipt;
            }
        }
        if (!m_btcc_preseal_recovery_runtime.frontier.CommitThrough(
                active_chain, plan.last_height)) {
            return false;
        }
    }
    if (!m_btcc_preseal_recovery_runtime.frontier.IsComplete(active_tip)) {
        return false;
    }
    if (m_btcc_preseal_recovery_runtime.recovered) {
        const auto& recovered{*m_btcc_preseal_recovery_runtime.recovered};
        const CBlockIndex* terminal{
            active_chain[recovered.terminal_carrier_height]};
        if (terminal == nullptr ||
            terminal->GetBlockHash() !=
                recovered.terminal_carrier_hash) {
            m_btcc_preseal_recovery_runtime = {};
            return false;
        }
        // Accepted winners and archived certificates only add authority.
        // Recheck the compressed terminal before publication so progress is
        // not reset by each newer winner, yet an obligation which became
        // fully authenticated during a long scan is never persisted.
        if (IsBTCCPrefixAuthenticated(*terminal) ||
            CheckBTCCReceiptCertificate(
                recovered.terminal_receipt, *terminal) ==
                BTCCReceiptCertificateStatus::VERIFIED) {
            m_btcc_preseal_recovery_runtime.recovered.reset();
        }
    }
    state.active = m_btcc_preseal_recovery_runtime.recovered;
    m_btcc_preseal_recovery_runtime = {};
    return true;
}

std::optional<int32_t>
CChainLocksHandler::AdvanceBTCCReplayValidationBounded(
    const CBlockIndex& active_tip,
    const pq::BTCCPresealState& state,
    int32_t authenticated_through)
{
    AssertLockHeld(cs_main);
    if (!m_config || authenticated_through < 0 ||
        authenticated_through > active_tip.nHeight) {
        return std::nullopt;
    }
    const CChain& active_chain{m_chainman.ActiveChain()};
    const CBlockIndex* floor{active_chain[authenticated_through]};
    if (floor == nullptr) return std::nullopt;
    const auto check = [&](const CBlockIndex& carrier)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        CBlock block;
        pq::BTCCReceipt receipt;
        if (!m_chainman.m_blockman.ReadBlockFromDisk(block, carrier) ||
            !ExtractBTCCReceipt(block, receipt)) {
            return BTCCReplayCarrierCheck{
                BTCCReplayCarrierStatus::LOCAL_ERROR, {}};
        }
        if (receipt.IsNull()) {
            return BTCCReplayCarrierCheck{
                BTCCReplayCarrierStatus::VERIFIED, {}};
        }
        switch (CheckBTCCReceiptCertificate(receipt, carrier)) {
        case BTCCReceiptCertificateStatus::VERIFIED:
            return BTCCReplayCarrierCheck{
                BTCCReplayCarrierStatus::VERIFIED, {}};
        case BTCCReceiptCertificateStatus::MISSING:
            return BTCCReplayCarrierCheck{
                BTCCReplayCarrierStatus::MISSING,
                receipt.chainlock_logical_id};
        case BTCCReceiptCertificateStatus::INVALID:
            return BTCCReplayCarrierCheck{
                BTCCReplayCarrierStatus::INVALID,
                receipt.chainlock_logical_id};
        }
        return BTCCReplayCarrierCheck{
            BTCCReplayCarrierStatus::LOCAL_ERROR, {}};
    };
    const uint256 source_token{BoundedBTCCPresealSourceToken(
        state, m_chainman.GetPQProvenanceRevocationRevision())};
    const auto step{AdvanceBTCCReplayValidationFrontier(
        m_btcc_replay_validation_frontier, active_chain, active_tip,
        authenticated_through, floor->GetBlockHash(),
        source_token,
        m_config->btcc_schedule, check)};
    if (step.missing_logical_id) {
        NoteNeededBTCCCertificate(
            NeededBTCCCertificateSource::PRESEAL_REPLAY,
            *step.missing_logical_id, source_token);
    } else if (step.validated_through &&
               step.terminal_status !=
                   BTCCReplayCarrierStatus::LOCAL_ERROR) {
        ClearNeededBTCCCertificate(
            NeededBTCCCertificateSource::PRESEAL_REPLAY,
            source_token);
    }
    if (step.terminal_status == BTCCReplayCarrierStatus::INVALID) {
        if (!m_persistence_failed.exchange(true)) {
            LogPrintf("CChainLocksHandler::%s -- invalid archived BTCC "
                      "authority %s for active replay carrier %s at %d; "
                      "disabling ChainLock share admission\n",
                      __func__, step.blocked_logical_id.ToString(),
                      step.blocked_carrier_hash.ToString(),
                      step.blocked_carrier_height);
        }
        DisableShareAdmission();
    }
    return step.validated_through;
}

CChainLocksHandler::BTCCReplayValidationStep
CChainLocksHandler::AdvanceBTCCReplayValidationFrontier(
    BoundedActiveRangeFrontier& frontier,
    const CChain& active_chain,
    const CBlockIndex& active_tip,
    int32_t authenticated_through,
    const uint256& authenticated_hash,
    const uint256& source_token,
    const pq::BTCCScheduleConfig& schedule,
    const std::function<BTCCReplayCarrierCheck(
        const CBlockIndex&)>& check,
    std::size_t block_budget)
{
    AssertLockHeld(cs_main);
    if (authenticated_through < 0 ||
        authenticated_through > active_tip.nHeight ||
        authenticated_hash.IsNull() || source_token.IsNull() ||
        !check || block_budget == 0) {
        return {};
    }
    const auto plan{frontier.Plan(
        active_chain, active_tip, authenticated_through,
        authenticated_hash, source_token, block_budget)};
    if (plan.status == BoundedActiveRangeStatus::INVALID) {
        return {};
    }
    if (plan.status == BoundedActiveRangeStatus::WORK) {
        for (int32_t height{plan.first_height};
             height <= plan.last_height; ++height) {
            if (!pq::IsBTCCReceiptCarrierHeight(
                    schedule, height)) {
                continue;
            }
            const CBlockIndex* carrier{active_chain[height]};
            const BTCCReplayCarrierCheck result{
                carrier == nullptr
                    ? BTCCReplayCarrierCheck{}
                    : check(*carrier)};
            if (result.status !=
                BTCCReplayCarrierStatus::VERIFIED) {
                if (!frontier.CommitThrough(
                        active_chain, height - 1)) {
                    return {};
                }
                BTCCReplayValidationStep step;
                step.validated_through = height - 1;
                step.terminal_status = result.status;
                step.blocked_carrier_height = height;
                step.blocked_carrier_hash =
                    carrier == nullptr ? uint256{}
                                       : carrier->GetBlockHash();
                step.blocked_logical_id = result.logical_id;
                if (result.status ==
                        BTCCReplayCarrierStatus::MISSING &&
                    !result.logical_id.IsNull()) {
                    step.missing_logical_id = result.logical_id;
                }
                return step;
            }
        }
        if (!frontier.CommitThrough(
                active_chain, plan.last_height)) {
            return {};
        }
    }
    return BTCCReplayValidationStep{
        frontier.ValidatedThroughHeight(), std::nullopt,
        BTCCReplayCarrierStatus::VERIFIED, -1, {}, {}};
}

void CChainLocksHandler::MaybeReplayBTCCPreseal()
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    pq::BTCCPresealState durable;
    pq::PaymentAuditPresealState payment_audit_durable;
    {
        LOCK(m_btcc_preseal_mutex);
        durable = m_btcc_preseal_state;
        payment_audit_durable = m_payment_audit_preseal_state;
    }
    if (durable.IsEmpty()) {
        ClearNeededBTCCCertificate(
            NeededBTCCCertificateSource::PRESEAL_REPLAY);
        MaybeReplayPaymentAuditPreseal();
        return;
    }
    // Payment marker maintenance is independent of Geth progress. In
    // particular, discard a failed prospective block promptly even while a
    // separate BTCC replay obligation remains durable.
    MaybeReplayPaymentAuditPreseal();
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_durable = m_payment_audit_preseal_state;
    }
    if (!m_config || !m_store) return;

    std::optional<pq::BTCCPresealMarker> marker;
    int32_t replay_through{-1};
    uint256 replay_through_hash;
    {
        LOCK(cs_main);
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        if (active_tip == nullptr) return;

        const auto marker_index = [&](const auto& candidate)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> const CBlockIndex* {
            if (!candidate) return nullptr;
            const CBlockIndex* index{
                m_chainman.m_blockman.LookupBlockIndex(
                    candidate->earliest_carrier_hash)};
            return index != nullptr &&
                           index->nHeight ==
                               candidate->earliest_carrier_height
                       ? index
                       : nullptr;
        };
        const auto marker_on_active = [&](const auto& candidate)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            const CBlockIndex* index{marker_index(candidate)};
            return index != nullptr &&
                   active_tip->GetAncestor(index->nHeight) == index;
        };

        pq::BTCCPresealState next{durable};
        // Promotion happens only after ActiveChain proves that the prospective
        // branch won. Until this fsynced transition, the prior active boundary
        // remains alongside it and survives every crash cut.
        if (marker_on_active(next.prospective)) {
            if (!marker_on_active(next.active) ||
                next.prospective->earliest_carrier_height <
                    next.active->earliest_carrier_height) {
                next.active = next.prospective;
            }
            next.prospective.reset();
        }

        if (!marker_on_active(next.active)) {
            // A marker can become stale only after a branch transition. Scan
            // from the earliest still-durable boundary before retiring it, so
            // an earlier active B@1100 is never lost to prospective A@1110.
            if (!RecoverActiveBTCCPresealBounded(*active_tip, next)) return;
        }

        // A losing prospective branch is no longer a replay obligation once
        // the active branch has been recovered. A still-current most-work
        // candidate remains durable until activation or replacement.
        if (next.prospective && !marker_on_active(next.prospective)) {
            const CBlockIndex* prospective{marker_index(next.prospective)};
            if (prospective == nullptr ||
                !m_chainman.ActiveChainstate().IsCurrentMostWorkBranch(
                    *prospective)) {
                next.prospective.reset();
            }
        }

        if (next != durable) {
            LOCK(m_btcc_preseal_mutex);
            if (m_btcc_preseal_state != durable ||
                !PersistBTCCPresealStateLocked(next)) {
                return;
            }
            durable = next;
        }
        marker = durable.active;
        if (!marker || !marker_on_active(marker)) {
            ClearNeededBTCCCertificate(
                NeededBTCCCertificateSource::PRESEAL_REPLAY);
            return;
        }

        const auto best{m_store->GetBestRecord()};
        const CBlockIndex* authenticated{
            best ? m_chainman.m_blockman.LookupBlockIndex(
                   best->metadata.statement.block_hash)
                 : nullptr};
        int32_t authenticated_through{-1};
        if (authenticated != nullptr &&
            authenticated->nHeight == best->metadata.statement.height &&
            authenticated->nHeight >= marker->terminal_carrier_height &&
            active_tip->GetAncestor(authenticated->nHeight) ==
                authenticated &&
            authenticated->GetAncestor(marker->terminal_carrier_height)
                    ->GetBlockHash() == marker->terminal_carrier_hash) {
            authenticated_through = authenticated->nHeight;
        } else {
            const CBlockIndex* terminal{active_tip->GetAncestor(
                marker->terminal_carrier_height)};
            if (terminal != nullptr &&
                terminal->GetBlockHash() == marker->terminal_carrier_hash &&
                CheckBTCCReceiptCertificate(marker->terminal_receipt,
                                            *terminal) ==
                    BTCCReceiptCertificateStatus::VERIFIED) {
                // SYSCOIN: The T=C-10 certificate verifies its exact carrier
                // receipt whether it was archived below the prior winner or
                // installed as the newer marker-authorized catch-up winner.
                authenticated_through = terminal->nHeight;
            }
        }
        if (authenticated_through >= marker->terminal_carrier_height) {
            const auto validated_through{
                AdvanceBTCCReplayValidationBounded(
                    *active_tip, durable, authenticated_through)};
            if (!validated_through) return;
            replay_through = *validated_through;
            const CBlockIndex* replay_index{
                active_tip->GetAncestor(replay_through)};
            if (replay_index != nullptr) {
                replay_through_hash = replay_index->GetBlockHash();
            }
        } else {
            NoteNeededBTCCCertificate(
                NeededBTCCCertificateSource::PRESEAL_REPLAY,
                marker->terminal_receipt.chainlock_logical_id,
                BoundedBTCCPresealSourceToken(
                    durable,
                    m_chainman.GetPQProvenanceRevocationRevision()));
        }

        // A BTCC-authenticated prefix must not replay across an intersecting
        // compact payment-audit boundary that has not yet been authenticated.
        // Geth's cursor still permits safe progress up to the block before
        // that boundary; both durable markers remain until replay reaches the
        // active tip.
        const auto cap_at_unauthenticated_payment =
            [&](const auto& payment_marker)
                EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                if (!payment_marker || replay_through < 0) return;
                const CBlockIndex* earliest{
                    m_chainman.m_blockman.LookupBlockIndex(
                        payment_marker->earliest_carrier_hash)};
                const CBlockIndex* terminal{
                    m_chainman.m_blockman.LookupBlockIndex(
                        payment_marker->terminal_carrier_hash)};
                if (earliest == nullptr || terminal == nullptr ||
                    earliest->nHeight !=
                        payment_marker->earliest_carrier_height ||
                    terminal->nHeight !=
                        payment_marker->terminal_carrier_height ||
                    active_tip->nHeight < earliest->nHeight ||
                    active_tip->GetAncestor(earliest->nHeight) != earliest ||
                    replay_through < earliest->nHeight) {
                    return;
                }
                const bool terminal_authenticated{
                    active_tip->nHeight >= terminal->nHeight &&
                    active_tip->GetAncestor(terminal->nHeight) == terminal &&
                    terminal->GetAncestor(earliest->nHeight) == earliest &&
                    IsPaymentAuditPrefixAuthenticated(*terminal)};
                if (terminal_authenticated) return;
                replay_through = earliest->nHeight - 1;
                const CBlockIndex* capped{
                    active_tip->GetAncestor(replay_through)};
                replay_through_hash = capped == nullptr
                    ? uint256{}
                    : capped->GetBlockHash();
            };
        cap_at_unauthenticated_payment(payment_audit_durable.active);
        cap_at_unauthenticated_payment(
            payment_audit_durable.prospective);
    }

    if (!marker || replay_through < marker->earliest_carrier_height ||
        replay_through_hash.IsNull()) {
        return;
    }

    // The replay obligation is durable even while Geth is unavailable. This
    // prevents a later reconnect from exposing a history that skipped the
    // authenticated Bitcoin checkpoints.
    if (!fNEVMConnection) return;

    bool complete{false};
    std::string error;
    if (!m_chainman.ActiveChainstate().ReplayDeferredBTCCNEVM(
            replay_through, replay_through_hash,
            [this, expected = *marker] {
                return ClearBTCCPreseal(expected);
            },
            complete, error)) {
        LogPrintf("CChainLocksHandler::%s -- deferred NEVM replay paused: %s\n",
                  __func__, error);
        return;
    }
}

void CChainLocksHandler::RequestNeededBTCCCertificate()
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    (void)RevalidatePendingBTCCReceiptDependency();
    const auto pending_verified{
        GetPendingVerifiedHistoricalChainLock()};
    std::optional<uint256> logical_id;
    bool pending_blocks_lower_priority{false};
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(m_pending_btcc_receipt_mutex);
        if (m_pending_btcc_receipt &&
            (!pending_verified ||
             pending_verified->logical_id !=
                 m_pending_btcc_receipt->logical_id)) {
            pending_blocks_lower_priority = true;
            if (m_pending_btcc_last_request.count() == 0 ||
                now - m_pending_btcc_last_request >=
                    std::chrono::seconds{5}) {
                logical_id = m_pending_btcc_receipt->logical_id;
                m_pending_btcc_last_request = now;
            }
        }
    }
    // A best-work block dependency outranks signing/readiness lookups. It is
    // still a single deduplicated ID and therefore cannot expand the ordinary
    // CLSIG download lanes.
    if (pending_blocks_lower_priority && !logical_id) return;
    if (!logical_id) {
        LOCK(m_needed_btcc_certificate_mutex);
        if (!m_needed_btcc_certificate ||
            (pending_verified &&
             pending_verified->logical_id ==
                 m_needed_btcc_certificate->logical_id) ||
            (m_needed_btcc_certificate->last_request.count() != 0 &&
             now - m_needed_btcc_certificate->last_request <
                 std::chrono::seconds{30})) {
            return;
        }
        logical_id = m_needed_btcc_certificate->logical_id;
        m_needed_btcc_certificate->last_request = now;
    }
    m_connman.ForEachNode([&](CNode* node) {
        if (!SupportsPQChainLocks(node->GetCommonVersion())) return;
        CNetMsgMaker maker{node->GetCommonVersion()};
        m_connman.PushMessage(
            node, maker.Make(NetMsgType::GETCLSIG, *logical_id));
    });
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- requesting receipt ADVANCE %s\n",
             __func__, logical_id->ToString());
}

void CChainLocksHandler::RequestNeededPaymentAuditCertificate()
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    (void)RevalidatePendingPaymentAuditReceiptDependency();
    std::optional<uint256> witness_id;
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(m_pending_payment_audit_receipt_mutex);
        if (m_pending_payment_audit_receipt &&
            (m_pending_payment_audit_last_request.count() == 0 ||
             now - m_pending_payment_audit_last_request >=
                 std::chrono::seconds{5})) {
            witness_id = m_pending_payment_audit_receipt
                             ->receipt.audit_witness_id;
            m_pending_payment_audit_last_request = now;
        }
    }
    if (!witness_id) return;
    m_connman.ForEachNode([&](CNode* node) {
        if (!SupportsPQChainLocks(node->GetCommonVersion())) return;
        CNetMsgMaker maker{node->GetCommonVersion()};
        m_connman.PushMessage(
            node, maker.Make(NetMsgType::GETPQPOSE, *witness_id));
    });
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- requesting receipt payment audit "
             "%s\n",
             __func__, witness_id->ToString());
}

void CChainLocksHandler::RetryPendingBTCCBlock()
{
    if (!m_retry_pending_btcc_block.exchange(false)) return;

    BlockValidationState state;
    if (!m_chainman.ActiveChainstate().ActivateBestChain(state)) {
        LogPrintf("CChainLocksHandler::%s -- failed to retry BTCC receipt "
                  "dependency: %s\n",
                  __func__, state.ToString());
        if (!static_cast<bool>(m_chainman.m_interrupt)) {
            m_retry_pending_btcc_block.store(true);
        }
    }
}

PaymentAuditContextStatus
CChainLocksHandler::ClassifyHistoricalReceiptIndexRangeCached(
    const CBlockIndex& last, int32_t first_height) const
{
    AssertLockHeld(cs_main);
    return ClassifyHistoricalReceiptIndexRange(
        last, first_height, m_historical_index_validation_cache,
        m_chainman.GetPQProvenanceRevocationRevision());
}

bool CChainLocksHandler::HasChainLockTargetValidationCached(
    const CBlockIndex& candidate, int32_t predecessor_height,
    HistoricalIndexValidationMode mode) const
{
    AssertLockHeld(cs_main);
    return HasChainLockTargetValidation(
        candidate, predecessor_height, mode,
        m_historical_index_validation_cache,
        m_chainman.GetPQProvenanceRevocationRevision());
}

BTCCCatchupRangeStatus
CChainLocksHandler::GetFullyValidatedBTCCCatchupRangeStatusCached(
    const CBlockIndex& candidate,
    const pq::BTCCReceiptAssumptionAnchor& anchor) const
{
    AssertLockHeld(cs_main);
    return GetFullyValidatedBTCCCatchupRangeStatusImpl(
        m_chainman, candidate, anchor,
        m_historical_index_validation_cache,
        m_chainman.GetPQProvenanceRevocationRevision());
}

PaymentAuditContextStatus
CChainLocksHandler::ClassifyPaymentAuditSealContextCached(
    const CBlockIndex* seal, int32_t expected_height,
    int32_t predecessor_height, const uint256& predecessor_hash,
    PaymentAuditSealValidation validation) const
{
    AssertLockHeld(cs_main);
    return ClassifyPaymentAuditSealContextImpl(
        seal, expected_height, predecessor_height, predecessor_hash,
        validation, m_historical_index_validation_cache,
        m_chainman.GetPQProvenanceRevocationRevision());
}

std::optional<pq::BTCCReceiptState>
CChainLocksHandler::RecomputeBTCCReceiptStateCached(
    const CBlockIndex& target,
    int32_t first_carrier_height,
    const pq::BTCCReceiptState& initial_state,
    const uint256& context_token,
    bool* transient_failure,
    std::size_t* examined_carriers) const
{
    AssertLockHeld(cs_main);
    if (transient_failure != nullptr) *transient_failure = false;
    if (examined_carriers != nullptr) *examined_carriers = 0;
    if (!m_config || context_token.IsNull() ||
        !initial_state.IsStructurallyValid() || first_carrier_height < 0 ||
        target.nHeight < first_carrier_height ||
        !pq::IsBTCCReceiptCarrierHeight(
            m_config->btcc_schedule, first_carrier_height)) {
        return std::nullopt;
    }

    auto& frontier{m_btcc_receipt_recompute_frontier};
    const uint64_t provenance_revocation_revision{
        m_chainman.GetPQProvenanceRevocationRevision()};
    if (!frontier.initialized ||
        frontier.context_token != context_token ||
        frontier.provenance_revocation_revision !=
            provenance_revocation_revision ||
        frontier.target_height != target.nHeight ||
        frontier.target_hash != target.GetBlockHash() ||
        frontier.first_carrier_height != first_carrier_height ||
        frontier.initial_state != initial_state) {
        frontier = {};
        frontier.initialized = true;
        frontier.context_token = context_token;
        frontier.provenance_revocation_revision =
            provenance_revocation_revision;
        frontier.target_height = target.nHeight;
        frontier.target_hash = target.GetBlockHash();
        frontier.first_carrier_height = first_carrier_height;
        frontier.next_carrier_height = first_carrier_height;
        frontier.initial_state = initial_state;
        frontier.state = initial_state;
    }

    static constexpr std::size_t CARRIER_BUDGET{64};
    std::size_t examined{0};
    while (frontier.next_carrier_height <= target.nHeight &&
           examined < CARRIER_BUDGET) {
        const CBlockIndex* carrier{
            target.GetAncestor(
                static_cast<int32_t>(frontier.next_carrier_height))};
        if (carrier == nullptr) return std::nullopt;
        CBlock block;
        if (!m_chainman.m_blockman.ReadBlockFromDisk(block, *carrier)) {
            if (transient_failure != nullptr) *transient_failure = true;
            return std::nullopt;
        }
        ++examined;
        if (examined_carriers != nullptr) ++*examined_carriers;
        pq::BTCCReceipt receipt;
        if (!ExtractBTCCReceipt(block, receipt) ||
            !pq::ValidateBTCCReceiptOnBranch(
                m_config->btcc_schedule, *carrier, receipt)) {
            return std::nullopt;
        }
        const auto next{pq::ApplyBTCCReceiptState(
            m_chainman.GetConsensus().hashGenesisBlock,
            m_config->chainlock_schedule, m_config->btcc_schedule,
            carrier->nHeight, carrier->GetBlockHash(), frontier.state,
            receipt)};
        if (!next) return std::nullopt;
        frontier.state = *next;
        frontier.next_carrier_height +=
            m_config->btcc_schedule.candidate_period;
    }
    if (frontier.next_carrier_height <= target.nHeight) {
        if (transient_failure != nullptr) *transient_failure = true;
        return std::nullopt;
    }
    return frontier.state;
}

std::optional<pq::BTCCReceiptState>
CChainLocksHandler::GetCatchupHistoricalProof(
    const CBlockIndex& candidate,
    HistoricalAdmission admission) const
{
    AssertLockHeld(cs_main);
    if (!m_config) return std::nullopt;
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    const bool current_candidate{
        admission == HistoricalAdmission::CURRENT_CATCHUP &&
        active_tip != nullptr &&
        IsCurrentChainLockCatchupCandidateAdmissible(
            m_config->chainlock_schedule, *active_tip, candidate)};
    const bool active_marker_candidate{
        admission != HistoricalAdmission::CURRENT_CATCHUP &&
        admission != HistoricalAdmission::NONE &&
        active_tip != nullptr &&
        active_tip->GetAncestor(candidate.nHeight) == &candidate};
    if (!current_candidate && !active_marker_candidate) {
        return std::nullopt;
    }
    // Derive the marker token directly from durable state so every mutation
    // invalidates both successful and backed-off proof entries.
    pq::BTCCPresealState preseal;
    pq::PaymentAuditPresealState payment_audit_preseal;
    {
        LOCK(m_btcc_preseal_mutex);
        preseal = m_btcc_preseal_state;
        payment_audit_preseal = m_payment_audit_preseal_state;
    }
    const uint256 marker_token{PresealAdmissionToken(
        preseal, payment_audit_preseal)};
    // The candidate hash itself commits to its ancestry. Keep proofs cached
    // across ordinary descendant tip extensions; admission excludes expired
    // or deep-fork candidates without forcing one historical scan per newly
    // connected block.
    const uint256 branch_token{
        CatchupValidationDomainToken(m_chainman, *m_config,
                                     marker_token)};
    const uint256 context_token{
        CatchupHistoricalContextToken(candidate, m_chainman, *m_config,
                                      marker_token)};
    return m_catchup_proof_cache.GetOrCompute(
        branch_token, context_token,
        [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
            -> pq::CatchupHistoricalProofCache::BuildResult {
            const auto range_status{GetFullyValidatedBTCCCatchupRangeStatusCached(
                candidate,
                m_config->btcc_receipt_assumption_anchor)};
            if (range_status != BTCCCatchupRangeStatus::VALID) {
                return {std::nullopt,
                        range_status ==
                            BTCCCatchupRangeStatus::DEFINITIVE_INVALID};
            }
            const auto indexed{IndexedBTCCReceiptState(candidate)};
            if (!indexed) return {std::nullopt, true};

            // SYSCOIN: Ordinary current catch-up trusts the branch-local state
            // only after every post-receipt-anchor index proves full non-assumed
            // validation. A pre-seal candidate additionally recomputes the
            // retained marker-to-target carrier range, never pruned anchor
            // history.
            const pq::BTCCPresealMarker* first_marker{
                SelectBTCCPresealRecomputeMarker(preseal, candidate)};
            if (first_marker == nullptr) return {*indexed, true};

            const CBlockIndex* earliest{candidate.GetAncestor(
                first_marker->earliest_carrier_height)};
            const CBlockIndex* predecessor{
                earliest == nullptr ? nullptr : earliest->pprev};
            const auto predecessor_state{
                predecessor == nullptr
                    ? std::optional<pq::BTCCReceiptState>{}
                    : IndexedBTCCReceiptState(*predecessor)};
            if (predecessor == nullptr ||
                !HasBTCCIndexProvenance(*predecessor) ||
                predecessor->IsAssumedValid() ||
                !predecessor->IsValid(BLOCK_VALID_SCRIPTS)) {
                return {std::nullopt, false};
            }
            if (!predecessor_state ||
                *predecessor_state !=
                    first_marker->predecessor_receipt_state) {
                return {std::nullopt, true};
            }
            bool transient_failure{false};
            auto proof{RecomputeBTCCReceiptStateCached(
                candidate,
                first_marker->earliest_carrier_height,
                first_marker->predecessor_receipt_state,
                context_token,
                &transient_failure)};
            if (proof && *proof != *indexed) proof.reset();
            return {std::move(proof), !transient_failure};
        });
}

int32_t CChainLocksHandler::CandidateFullValidationFloor(
    const pq::ChainLockCandidateContextRequest& request,
    int32_t activation_predecessor_height) noexcept
{
    if (request.admission ==
            pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE ||
        request.admission ==
            pq::ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE) {
        return request.statement.previous_chainlock_height;
    }
    return request.has_local_chainlock ? request.local_best.height
                                       : activation_predecessor_height;
}

HistoricalIndexValidationMode
CChainLocksHandler::CandidateTargetValidationMode(
    pq::ChainLockCandidateAdmission admission) noexcept
{
    // Exact fsynced winners and unsealed advances were already admitted with
    // live governance provenance. Reindex can reproduce scripts and both
    // receipt accumulators, but not historical governance vote availability.
    return admission ==
                pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE ||
            admission == pq::ChainLockCandidateAdmission::
                             TRUSTED_UNSEALED_PERSISTENCE
        ? HistoricalIndexValidationMode::FULL_RECEIPT
        : HistoricalIndexValidationMode::FULL_FINALITY;
}

bool CChainLocksHandler::IsCandidateTargetValidationSufficient(
    pq::ChainLockCandidateAdmission admission,
    bool has_local_chainlock,
    bool marker_authorized_catchup,
    bool exact_local_target,
    bool historical_receipt_range_ready) noexcept
{
    if (exact_local_target) return true;
    // SYSCOIN: An ordinary first winner must prove full finality provenance
    // from the activation predecessor. Marker-authorized preseal catch-up is
    // the sole exception: its durable replay obligation and authenticated
    // retained-range proof are what allow a covering CLSIG to restore the
    // first local winner after reindex.
    return admission == pq::ChainLockCandidateAdmission::CATCHUP &&
        (has_local_chainlock || marker_authorized_catchup) &&
        historical_receipt_range_ready;
}

std::optional<pq::ChainLockCandidateContext>
CChainLocksHandler::BuildCandidateContext(
    const pq::ChainLockCandidateContextRequest& request,
    const CBlockIndex** candidate_out) const
{
    if (!m_config || request.btcc_schedule != m_config->btcc_schedule) {
        return std::nullopt;
    }

    LOCK(cs_main);
    const CBlockIndex* candidate{
        m_chainman.m_blockman.LookupBlockIndex(request.statement.block_hash)};
    if (candidate == nullptr || candidate->nHeight != request.statement.height) {
        return pq::ChainLockCandidateContext{};
    }
    if (m_chainman.IsSnapshotActive() &&
        !m_chainman.IsSnapshotValidated()) {
        if (candidate_out != nullptr) *candidate_out = candidate;
        pq::ChainLockCandidateContext unavailable;
        unavailable.block_known = true;
        return unavailable;
    }

    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    const bool active_candidate{
        active_tip != nullptr && active_tip->nHeight >= candidate->nHeight &&
        active_tip->GetAncestor(candidate->nHeight) == candidate};
    const bool live_candidate_admissible{
        request.admission != pq::ChainLockCandidateAdmission::LIVE ||
        (active_tip != nullptr && IsLiveChainLockCandidateAdmissible(
                                      m_config->chainlock_schedule,
                                      *active_tip, *candidate))};
    const bool catchup{
        request.admission == pq::ChainLockCandidateAdmission::CATCHUP};
    const bool preseal_receipt{
        request.admission ==
        pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT};
    const auto historical{(catchup || preseal_receipt)
        ? GetHistoricalAdmissionLocked(
              request.statement,
              pq::GetLogicalChainLockId(m_genesis_hash, request.statement))
        : HistoricalAdmissionContext{}};
    const bool current_round_candidate{
        request.admission == pq::ChainLockCandidateAdmission::LIVE ||
        (catchup &&
         (historical.admission == HistoricalAdmission::CURRENT_CATCHUP ||
          historical.admission == HistoricalAdmission::RECOVERY))};
    const bool declared_predecessor_is_local{
        request.statement.previous_chainlock_height ==
            request.local_best.height &&
        request.statement.previous_chainlock_hash ==
            request.local_best.block_hash};
    const bool historical_local_cursor_matches{
        !(catchup || preseal_receipt) ||
        IsHistoricalLocalPredecessorCursorCompatible(
            current_round_candidate, declared_predecessor_is_local,
            request.statement.previous_btcc_cursor,
            request.local_best.btcc_cursor)};
    pq::BTCCPresealState preseal;
    pq::PaymentAuditPresealState payment_audit_preseal;
    {
        LOCK(m_btcc_preseal_mutex);
        preseal = m_btcc_preseal_state;
        payment_audit_preseal = m_payment_audit_preseal_state;
    }
    const uint256 marker_token{
        PresealAdmissionToken(preseal, payment_audit_preseal)};
    const bool marker_authorized_historical{
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP ||
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const bool marker_snapshot_matches_historical{
        !marker_authorized_historical ||
        marker_token == historical.marker_token};
    const bool side_candidate_blocked_by_preseal{
        IsCurrentChainLockCandidateBlockedByPreseal(
            active_candidate, current_round_candidate,
            !preseal.IsEmpty(), !payment_audit_preseal.IsEmpty())};
    const bool exact_catchup_target{
        !catchup ||
        historical.admission == HistoricalAdmission::CURRENT_CATCHUP ||
        historical.admission == HistoricalAdmission::RECOVERY ||
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP ||
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const bool exact_preseal_receipt{
        !preseal_receipt ||
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    // SYSCOIN: Before the first durable winner, a catch-up or restored
    // certificate's declared predecessor is only part of its signed chain.
    // It cannot narrow full validation of the branch segment from A-1.
    const int32_t validation_floor{CandidateFullValidationFloor(
        request, m_config->activation_predecessor_height)};
    const bool exact_local_target{HasChainLockTargetValidationCached(
        *candidate, validation_floor,
        CandidateTargetValidationMode(request.admission))};
    const bool payment_only_catchup{
        catchup && exact_local_target &&
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP &&
        m_config->btcc_receipt_assumption_anchor.IsDisabled()};
    const bool staged_recovery_catchup{
        catchup && exact_local_target &&
        historical.admission == HistoricalAdmission::RECOVERY};
    const auto catchup_proof{
        (catchup || preseal_receipt) && exact_catchup_target &&
                exact_preseal_receipt && active_tip != nullptr
            ? (payment_only_catchup || staged_recovery_catchup
                   ? IndexedBTCCReceiptState(*candidate)
                   : GetCatchupHistoricalProof(
                         *candidate, historical.admission))
            : std::optional<pq::BTCCReceiptState>{}};
    const bool trusted_persistence{
        request.admission ==
            pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE ||
        request.admission == pq::ChainLockCandidateAdmission::
                                 TRUSTED_UNSEALED_PERSISTENCE};
    const bool catchup_historical_receipt_range{
        catchup && !exact_local_target && validation_floor >= 0 &&
        ClassifyHistoricalReceiptIndexRangeCached(
            *candidate, validation_floor) ==
            PaymentAuditContextStatus::READY};
    const bool target_validation_sufficient{
        IsCandidateTargetValidationSufficient(
            request.admission, request.has_local_chainlock,
            historical.admission == HistoricalAdmission::PRESEAL_CATCHUP,
            exact_local_target, catchup_historical_receipt_range)};
    const bool validated{
        live_candidate_admissible && exact_catchup_target &&
        exact_preseal_receipt && marker_snapshot_matches_historical &&
        !side_candidate_blocked_by_preseal &&
        (trusted_persistence
             ? target_validation_sufficient
             : (catchup ? (catchup_proof.has_value() &&
                           target_validation_sufficient)
                        : (preseal_receipt
                               ? (exact_local_target ||
                                  catchup_proof.has_value())
                               : exact_local_target)))};
    bool declared_predecessor_is_ancestor{false};
    if (request.statement.previous_chainlock_height >= 0 &&
        request.statement.previous_chainlock_height < candidate->nHeight) {
        const CBlockIndex* declared_predecessor{candidate->GetAncestor(
            request.statement.previous_chainlock_height)};
        declared_predecessor_is_ancestor =
            declared_predecessor != nullptr &&
            declared_predecessor->GetBlockHash() ==
                request.statement.previous_chainlock_hash;
    }

    bool descends_from_local_best{false};
    if (request.admission ==
            pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE ||
        request.admission ==
            pq::ChainLockCandidateAdmission::TRUSTED_UNSEALED_PERSISTENCE) {
        const CBlockIndex* local_best{
            m_chainman.m_blockman.LookupBlockIndex(
                request.local_best.block_hash)};
        const CBlockIndex* historical_target{
            local_best != nullptr &&
                    local_best->nHeight == request.local_best.height
                ? local_best->GetAncestor(candidate->nHeight)
                : nullptr};
        descends_from_local_best =
            historical_target == candidate;
    } else if (preseal_receipt) {
        const CBlockIndex* local_best{
            m_chainman.m_blockman.LookupBlockIndex(
                request.local_best.block_hash)};
        if (local_best != nullptr &&
            local_best->nHeight == request.local_best.height) {
            descends_from_local_best =
                candidate->nHeight >= local_best->nHeight
                    ? candidate->GetAncestor(local_best->nHeight) == local_best
                    : local_best->GetAncestor(candidate->nHeight) == candidate;
        }
    } else if (catchup) {
        const CBlockIndex* anchor{
            candidate->GetAncestor(request.local_best.height)};
        descends_from_local_best =
            anchor != nullptr &&
            anchor->GetBlockHash() == request.local_best.block_hash;
    } else if (request.local_best.height >= 0 &&
               request.local_best.height < candidate->nHeight) {
        const CBlockIndex* local_best{
            candidate->GetAncestor(request.local_best.height)};
        descends_from_local_best =
            local_best != nullptr &&
            local_best->GetBlockHash() == request.local_best.block_hash;
    }

    pq::BTCCValidationError btcc_error{pq::BTCCValidationError::NONE};
    const bool known_predecessor_matches =
        !request.declared_predecessor_btcc_cursor ||
        *request.declared_predecessor_btcc_cursor ==
            request.statement.previous_btcc_cursor;
    const auto indexed_receipt_state{IndexedBTCCReceiptState(*candidate)};
    const auto indexed_payment_audit_state{
        IndexedPaymentAuditReceiptState(*candidate)};
    const auto durable_best{m_store ? m_store->GetBestRecord()
                                    : std::nullopt};
    const bool durable_snapshot_matches{
        request.has_local_chainlock
            ? (durable_best &&
               durable_best->metadata.statement.height == request.local_best.height &&
               durable_best->metadata.statement.block_hash ==
                   request.local_best.block_hash &&
               durable_best->metadata.statement.accepted_btcc_cursor ==
                   request.local_best.btcc_cursor)
            : !durable_best};
    std::optional<pq::BTCCCursorReconciliationProof>
        btcc_cursor_reconciliation;
    bool current_btcc_valid{true};
    if (current_round_candidate) {
        const auto canonical{durable_snapshot_matches
            ? SelectCurrentChainLockBTCC(
                  m_genesis_hash, *m_config, *candidate,
                  durable_best ? &durable_best->metadata : nullptr)
            : std::optional<CurrentChainLockBTCCSelection>{}};
        current_btcc_valid = canonical &&
            MatchesCurrentChainLockBTCCSelection(
                *canonical, request.statement,
                request.local_best.btcc_cursor,
                &btcc_cursor_reconciliation) &&
            (!btcc_cursor_reconciliation ||
             (catchup &&
              (historical.admission ==
                   HistoricalAdmission::CURRENT_CATCHUP ||
               historical.admission ==
                   HistoricalAdmission::RECOVERY)));
    }
    // The durable record exists only after live validation and fsync. On a
    // crash, that fsync can precede persistence of CBlockIndex BTCPREV metadata,
    // so startup restoration trusts only that previously attested transition.
    // Network admission can never select this mode.
    const bool btcc_valid = known_predecessor_matches &&
        historical_local_cursor_matches && current_btcc_valid &&
        indexed_receipt_state &&
        indexed_payment_audit_state &&
        *indexed_receipt_state == request.statement.btcc_receipt_state &&
        *indexed_payment_audit_state ==
            request.statement.payment_audit_receipt_state &&
        candidate->pqPaymentProbationStateHash ==
            request.statement.payment_probation_state_hash &&
        (!(catchup || (preseal_receipt && !exact_local_target)) ||
         (catchup_proof && *catchup_proof == *indexed_receipt_state)) &&
        ((request.admission ==
              pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE ||
          request.admission == pq::ChainLockCandidateAdmission::
                                   TRUSTED_UNSEALED_PERSISTENCE) ||
         pq::ValidateBTCCursorTransition(
             request.btcc_schedule, *candidate,
             request.statement.previous_btcc_cursor,
             request.statement.accepted_btcc_cursor,
             request.statement.btcc_advance, &btcc_error));
    if (candidate_out != nullptr) *candidate_out = candidate;
    return pq::ChainLockCandidateContext{
        true,
        validated,
        validated,
        declared_predecessor_is_ancestor,
        descends_from_local_best,
        btcc_valid,
        candidate->nHeight,
        candidate->GetBlockHash(),
        CandidateContextToken(*candidate, request,
                              (catchup || preseal_receipt) ? active_tip
                                                          : nullptr,
                              (marker_authorized_historical ||
                               (current_round_candidate && !active_candidate))
                                  ? marker_token
                                  : uint256{}),
        btcc_cursor_reconciliation};
}

bool CChainLocksHandler::FlushBTCCIndexStateForDurableAcceptance(
    const pq::FinalChainLock& chainlock) const
{
    LOCK(cs_main);
    CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
        chainlock.statement.block_hash)};
    if (target == nullptr ||
        target->nHeight != chainlock.statement.height) {
        return false;
    }

    const auto indexed_state{IndexedBTCCReceiptState(*target)};
    const auto indexed_payment_audit_state{
        IndexedPaymentAuditReceiptState(*target)};
    if (!indexed_state || !indexed_payment_audit_state ||
        *indexed_state != chainlock.statement.btcc_receipt_state ||
        *indexed_payment_audit_state !=
            chainlock.statement.payment_audit_receipt_state ||
        target->pqPaymentProbationStateHash !=
            chainlock.statement.payment_probation_state_hash) {
        return false;
    }
    if (!indexed_state->cursor.IsNull()) {
        const CBlockIndex* source{
            target->GetAncestor(indexed_state->cursor.sys_height)};
        if (source == nullptr ||
            source->GetBlockHash() != indexed_state->cursor.sys_hash ||
            source->btcpPrevCommitment != indexed_state->cursor.btc_hash) {
            return false;
        }
    }

    // Block connection marks every derived BTCPREV/receipt index mutation
    // dirty. Make the target's block and undo stream durable before publishing
    // that metadata, then fsync the certificate record. A crash before the
    // latter leaves no winner; one after it can reverify the durable branch.
    return m_chainman.m_blockman.FlushChainstateBlockFile(target->nHeight) &&
           m_chainman.m_blockman.WriteBlockIndexDB();
}

void CChainLocksHandler::MaintainPaymentAuditCheckpointGC()
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    bool expected{false};
    if (!m_payment_audit_gc_active.compare_exchange_strong(
            expected, true, std::memory_order_acquire,
            std::memory_order_relaxed)) {
        return;
    }
    struct MaintenanceGuard final {
        std::atomic_bool& active;
        ~MaintenanceGuard()
        {
            active.store(false, std::memory_order_release);
        }
    } maintenance_guard{m_payment_audit_gc_active};
    if (ContinuePaymentAuditCheckpointGC() || !m_store) return;
    const auto record{m_store->GetBestRecord()};
    if (record) MaybeCheckpointPaymentAuditPreseal(record->metadata);
}

bool CChainLocksHandler::ContinuePaymentAuditCheckpointGC()
{
    if (!m_payment_audit_store || !deterministicMNManager ||
        m_persistence_failed.load()) {
        return false;
    }

    const auto pending_archive{
        m_payment_audit_store->GetPendingPruneCheckpoint()};
    const auto pending_probation{
        deterministicMNManager->GetPendingPaymentProbationGCRequest()};
    const auto completed_archive{
        m_payment_audit_store->GetPruneCheckpoint()};
    const bool completed_probation{
        completed_archive &&
        deterministicMNManager
            ->IsPaymentProbationGCCompleteForCheckpoint(
                *completed_archive)};
    const auto plan{SelectPaymentAuditGCMaintenancePlan(
        pending_archive,
        pending_probation
            ? std::optional<pq::PaymentAuditStoreCheckpoint>{
                  pending_probation->checkpoint}
            : std::nullopt,
        pending_probation
            ? std::span<const uint256>{
                  pending_probation->retained_state_hashes}
            : std::span<const uint256>{},
        completed_archive, completed_probation)};
    if (plan.phase == PaymentAuditGCMaintenancePhase::NONE) {
        return false;
    }
    const auto fail = [&](const char* reason, uint8_t status = 0) {
        LogPrintf("CChainLocksHandler::%s -- payment-audit GC %s "
                  "(status=%u, checkpoint=%s); disabling ChainLock "
                  "share admission\n",
                  __func__, reason, status,
                  plan.checkpoint.authorizing_chainlock_witness_id
                      .ToString());
        m_persistence_failed.store(true);
        DisableShareAdmission();
    };
    if (plan.phase == PaymentAuditGCMaintenancePhase::INVALID) {
        fail("has conflicting durable intents");
        return true;
    }

    LOCK(cs_main);
    const CBlockIndex* authorizer{
        m_chainman.m_blockman.LookupBlockIndex(
            plan.checkpoint.authorizing_target_hash)};
    if (authorizer == nullptr ||
        authorizer->nHeight !=
            plan.checkpoint.authorizing_target_height ||
        !IsPaymentAuditCheckpointAuthenticated(
            plan.checkpoint, *authorizer)) {
        // Import/enforcement and active-chain connection may still be
        // converging. The durable intent remains authoritative and is retried
        // without allowing a newer checkpoint to pass it.
        return true;
    }

    if (plan.phase == PaymentAuditGCMaintenancePhase::ARCHIVE) {
        const auto progress{
            m_payment_audit_store->PruneThroughCheckpointStep(
                plan.checkpoint)};
        if (progress.status == pq::PaymentAuditPruneStatus::IN_PROGRESS) {
            return true;
        }
        if (progress.status != pq::PaymentAuditPruneStatus::COMPLETE) {
            fail("archive step failed",
                 static_cast<uint8_t>(progress.status));
            return true;
        }
        // SYSCOIN: Keep each scheduler invocation to one bounded database
        // phase while cs_main pins the authorizing branch. The completed
        // archive checkpoint durably selects probation work on the next pass.
        return true;
    }

    std::vector<uint256> retained_probation_roots{
        plan.retained_probation_roots};
    const auto pending_probation_request{
        deterministicMNManager->GetPendingPaymentProbationGCRequest()};
    if (pending_probation_request) {
        if (!HasSamePaymentAuditCheckpointBoundary(
                pending_probation_request->checkpoint,
                plan.checkpoint)) {
            fail("probation intent does not match completed archive");
            return true;
        }
        retained_probation_roots =
            pending_probation_request->retained_state_hashes;
    } else if (plan.derive_retained_probation_roots) {
        pq::PaymentAuditPresealState retained_markers;
        {
            LOCK(m_btcc_preseal_mutex);
            retained_markers = m_payment_audit_preseal_state;
        }
        const auto retain_probation_root = [&](const uint256& root) {
            if (!root.IsNull() &&
                std::find(retained_probation_roots.begin(),
                          retained_probation_roots.end(), root) ==
                    retained_probation_roots.end()) {
                retained_probation_roots.push_back(root);
            }
        };
        retain_probation_root(
            plan.checkpoint.authenticated_probation_state_hash);
        retain_probation_root(authorizer->pqPaymentProbationStateHash);
        const auto chainstate_probation_roots{
            CollectChainstatePaymentProbationRoots(m_chainman)};
        if (!chainstate_probation_roots) {
            fail("could not collect retained probation roots");
            return true;
        }
        for (const uint256& root : *chainstate_probation_roots) {
            retain_probation_root(root);
        }
        if (retained_markers.active) {
            retain_probation_root(
                retained_markers.active
                    ->predecessor_probation_state_hash);
        }
        if (retained_markers.prospective) {
            retain_probation_root(
                retained_markers.prospective
                    ->predecessor_probation_state_hash);
        }
    }

    const auto probation_progress{
        deterministicMNManager
            ->PrunePaymentProbationStatesThroughCheckpointStep(
                plan.checkpoint,
                std::span<const uint256>{retained_probation_roots})};
    if (probation_progress.status ==
            pq::PQPaymentProbationPruneStatus::IN_PROGRESS) {
        return true;
    }
    if (probation_progress.status ==
            pq::PQPaymentProbationPruneStatus::COMPLETE) {
        // The bounded archive and probation stores are now both durable. The
        // next maintenance pass observes NONE, so this transition is the
        // single completion notification for asynchronous checkpoint GC.
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- authenticated payment-audit "
                 "archive through epoch %u with durable CLSIG %s at %d\n",
                 __func__, plan.checkpoint.prune_through_epoch,
                 plan.checkpoint.authorizing_chainlock_witness_id.ToString(),
                 plan.checkpoint.authorizing_target_height);
        return true;
    }
    fail("probation step failed",
         static_cast<uint8_t>(probation_progress.status));
    return true;
}

void CChainLocksHandler::MaybeCheckpointPaymentAuditPreseal(
    const pq::FinalChainLockRecordMetadata& durable_winner)
{
    if (!m_store || !m_persistence || !m_payment_audit_store ||
        !m_config || m_persistence_failed.load() ||
        !durable_winner.IsInternallyConsistent(m_genesis_hash)) {
        return;
    }
    const auto accepted{m_store->GetBestRecord()};
    const auto persisted{m_persistence->GetFinalityState().best};
    if (!accepted || !persisted || accepted->metadata != durable_winner ||
        *persisted != durable_winner) {
        return;
    }

    LOCK(cs_main);
    CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
        durable_winner.statement.block_hash)};
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    if (target == nullptr || active_tip == nullptr ||
        target->nHeight != durable_winner.statement.height ||
        active_tip->nHeight < target->nHeight ||
        active_tip->GetAncestor(target->nHeight) != target ||
        (target->nStatus & BLOCK_FAILED_MASK) ||
        target->IsAssumedValid() ||
        !target->IsValid(BLOCK_VALID_SCRIPTS) ||
        !HasFullReceiptIndexProvenance(*target)) {
        return;
    }
    const auto target_receipt_state{
        IndexedPaymentAuditReceiptState(*target)};
    if (!target_receipt_state ||
        *target_receipt_state !=
            durable_winner.statement.payment_audit_receipt_state ||
        target->pqPaymentProbationStateHash !=
            durable_winner.statement.payment_probation_state_hash) {
        return;
    }

    const pq::PaymentAuditScheduleConfig schedule{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    std::optional<uint32_t> prune_through{
        LatestFullyCoveredPaymentAuditEpoch(schedule, target->nHeight)};
    if (!target_receipt_state->cursor.IsNull()) {
        prune_through = prune_through
            ? std::max(*prune_through,
                       target_receipt_state->cursor.epoch)
            : std::optional<uint32_t>{
                  target_receipt_state->cursor.epoch};
    }
    if (!prune_through) return;

    const auto previous_checkpoint{
        m_payment_audit_store->GetPruneCheckpoint()};
    if (previous_checkpoint &&
        *prune_through < previous_checkpoint->prune_through_epoch) {
        return;
    }
    pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = *prune_through;
    checkpoint.covered_through_height = target->nHeight;
    checkpoint.covered_through_hash = target->GetBlockHash();
    checkpoint.authenticated_receipt_state = *target_receipt_state;
    checkpoint.authenticated_probation_state_hash =
        target->pqPaymentProbationStateHash;
    if (previous_checkpoint &&
        checkpoint.prune_through_epoch ==
            previous_checkpoint->prune_through_epoch) {
        if (checkpoint.authenticated_receipt_state !=
                previous_checkpoint->authenticated_receipt_state ||
            checkpoint.authenticated_probation_state_hash !=
                previous_checkpoint->authenticated_probation_state_hash) {
            // The current winner still authenticates the old prefix by
            // ancestry, but the store boundary cannot advance until the new
            // receipt epoch is itself safe to prune.
            return;
        }
        checkpoint.covered_through_height =
            previous_checkpoint->covered_through_height;
        checkpoint.covered_through_hash =
            previous_checkpoint->covered_through_hash;
    }
    checkpoint.authorizing_target_height =
        durable_winner.statement.height;
    checkpoint.authorizing_target_hash =
        durable_winner.statement.block_hash;
    checkpoint.authorizing_chainlock_logical_id =
        durable_winner.logical_id;
    checkpoint.authorizing_chainlock_witness_id =
        durable_winner.witness_id;
    if (!checkpoint.IsStructurallyValid()) return;

    // A later durable descendant already authenticates an unchanged archive
    // boundary, so the multi-megabyte archive needs no rewrite or rescan.
    const bool reuse_archive_checkpoint{
        previous_checkpoint &&
        HasSamePaymentAuditCheckpointBoundary(
            *previous_checkpoint, checkpoint) &&
        IsPaymentAuditPrefixAuthenticated(*target)};
    const pq::PaymentAuditStoreCheckpoint committed_checkpoint{
        reuse_archive_checkpoint ? *previous_checkpoint : checkpoint};
    const CBlockIndex* checkpoint_target{target};

    // The state-owned completion marker is removed by -reindex-chainstate.
    // Thus an unchanged winner is a zero-fsync no-op during steady state, but
    // a crash between the archive and state commits (or a rebuild that
    // recreated covered roots) performs one repair pass.
    const bool probation_gc_complete{
        deterministicMNManager != nullptr &&
        deterministicMNManager
            ->IsPaymentProbationGCCompleteForCheckpoint(
                committed_checkpoint)};
    const bool requires_durable_gc{ShouldRunPaymentAuditDurableGC(
        reuse_archive_checkpoint, probation_gc_complete)};
    if (requires_durable_gc) {
        // Pruning either store is irreversible across a crash. First publish
        // the active chainstate marker after the DMN, PQ-registry, and
        // probation-state durability barriers, so restart can never land
        // below a root removed by this checkpoint. Holding cs_main keeps the
        // authenticated target active across the flush and both GC commits.
        if (reuse_archive_checkpoint) {
            // A completed archive with unfinished probation state is resumed
            // by the exact durable-request path on the next bounded pass.
            return;
        }
        BlockValidationState flush_state;
        if (!m_chainman.ActiveChainstate().FlushStateToDisk(
                flush_state, FlushStateMode::ALWAYS)) {
            LogPrintf("CChainLocksHandler::%s -- chainstate flush before "
                      "payment-audit GC failed: %s\n",
                      __func__, flush_state.ToString());
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return;
        }

        // The checkpoint batch follows index/probation fsync, durable
        // certificate installation, active-chain enforcement, and the
        // chainstate marker. Only one bounded archive slice runs here; exact
        // durable intent recovery owns every continuation and probation pass.
        const auto archive_progress{
            m_payment_audit_store->PruneThroughCheckpointStep(checkpoint)};
        if (archive_progress.status !=
                pq::PaymentAuditPruneStatus::IN_PROGRESS &&
            archive_progress.status !=
                pq::PaymentAuditPruneStatus::COMPLETE) {
            LogPrintf("CChainLocksHandler::%s -- payment-audit archive GC "
                      "failed with status %u\n",
                      __func__,
                      static_cast<unsigned>(archive_progress.status));
            m_persistence_failed.store(true);
            DisableShareAdmission();
        }
        return;
    }

    LOCK(m_btcc_preseal_mutex);
    pq::PaymentAuditPresealState next{
        m_payment_audit_preseal_state};
    const auto marker_conflicts_with_winner = [&](const auto& marker)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        if (!marker || !marker->IsStructurallyValid()) return false;
        const CBlockIndex* earliest{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->earliest_carrier_hash)};
        const CBlockIndex* terminal{
            m_chainman.m_blockman.LookupBlockIndex(
                marker->terminal_carrier_hash)};
        return (earliest != nullptr &&
                earliest->nHeight <= checkpoint_target->nHeight &&
                checkpoint_target->GetAncestor(earliest->nHeight) !=
                    earliest) ||
               (terminal != nullptr &&
                terminal->nHeight <= checkpoint_target->nHeight &&
                checkpoint_target->GetAncestor(terminal->nHeight) !=
                    terminal);
    };
    const bool clear_active{marker_conflicts_with_winner(next.active)};
    const bool clear_prospective{
        marker_conflicts_with_winner(next.prospective)};
    if (clear_active) next.active.reset();
    if (clear_prospective) next.prospective.reset();
    if (next != m_payment_audit_preseal_state &&
        !PersistPaymentAuditPresealStateLocked(next)) {
        return;
    }
    if (!previous_checkpoint ||
        *previous_checkpoint != committed_checkpoint) {
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- authenticated payment-audit "
                 "archive through epoch %u with durable CLSIG %s at %d\n",
                 __func__, committed_checkpoint.prune_through_epoch,
                 committed_checkpoint.authorizing_chainlock_witness_id
                     .ToString(),
                 committed_checkpoint.authorizing_target_height);
    }
}

std::optional<pq::ChainLockCandidateContext>
CChainLocksHandler::PrepareCandidate(
    const pq::ChainLockCandidateContextRequest& request) const
{
    return BuildCandidateContext(request);
}

std::optional<pq::ChainLockCandidateContext>
CChainLocksHandler::RecheckCandidate(
    const pq::ChainLockCandidateContextRequest& request,
    const pq::ChainLockCandidateContext& prepared) const
{
    const auto current{BuildCandidateContext(request)};
    if (!current || *current != prepared) return std::nullopt;
    return current;
}

pq::AcceptedBranchRelation CChainLocksHandler::QueryAcceptedBranch(
    int32_t height,
    const uint256& block_hash,
    int32_t accepted_tip_height,
    const uint256& accepted_tip_hash) const
{
    if (height < 0 || block_hash.IsNull() || accepted_tip_height < height ||
        accepted_tip_hash.IsNull()) {
        return pq::AcceptedBranchRelation::UNKNOWN;
    }
    LOCK(cs_main);
    const CBlockIndex* accepted_tip{
        m_chainman.m_blockman.LookupBlockIndex(accepted_tip_hash)};
    if (accepted_tip == nullptr || accepted_tip->nHeight != accepted_tip_height) {
        return pq::AcceptedBranchRelation::UNKNOWN;
    }
    const CBlockIndex* ancestor{accepted_tip->GetAncestor(height)};
    if (ancestor == nullptr) return pq::AcceptedBranchRelation::UNKNOWN;
    return ancestor->GetBlockHash() == block_hash
               ? pq::AcceptedBranchRelation::MATCH
               : pq::AcceptedBranchRelation::CONFLICT;
}

std::optional<pq::NormalRosterAuthorizationInput>
CChainLocksHandler::BuildNormalRosterAuthorizationInput(
    const pq::ChainLockStatement& statement,
    const pq::FinalChainLockRecordMetadata& prior,
    pq::RosterAuthorizationTransitionKind requested_transition,
    RosterBeaconEvidence evidence) const
{
    AssertLockNotHeld(cs_main);
    if (!m_config || !m_quorum_build_config ||
        !prior.IsInternallyConsistent(m_genesis_hash) ||
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::INITIALIZE ||
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::RECOVER) {
        return std::nullopt;
    }

    pq::NormalRosterAuthorizationInput input;
    input.target_height = statement.height;
    input.target_block_hash = statement.block_hash;
    input.predecessor_height = statement.previous_chainlock_height;
    input.predecessor_block_hash = statement.previous_chainlock_hash;
    input.authorization_base = prior.AuthorizationBase();
    input.previous = pq::RosterAuthorizationPriorState{
        prior.statement.roster_authorization_state_hash,
        prior.statement.roster_beacons};
    input.previous_btcc_cursor = statement.previous_btcc_cursor;
    input.accepted_btcc_cursor = statement.accepted_btcc_cursor;
    input.btcc_advance = statement.btcc_advance;
    input.recovery_authority_source =
        statement.roster_beacons.active.recovery_authority_source;
    input.recovery_authority_hash =
        statement.roster_beacons.active.recovery_authority_hash;

    {
        LOCK(cs_main);
        const CBlockIndex* candidate{
            m_chainman.m_blockman.LookupBlockIndex(statement.block_hash)};
        if (candidate == nullptr || candidate->nHeight != statement.height) {
            return std::nullopt;
        }
        const CBlockIndex* wire_predecessor{
            candidate->GetAncestor(statement.previous_chainlock_height)};
        const CBlockIndex* authorization_predecessor{
            candidate->GetAncestor(prior.statement.height)};
        if (wire_predecessor == nullptr ||
            wire_predecessor->GetBlockHash() !=
                statement.previous_chainlock_hash ||
            authorization_predecessor == nullptr ||
            authorization_predecessor->GetBlockHash() !=
                prior.statement.block_hash) {
            return std::nullopt;
        }
        const auto newest_epoch{pq::EpochForHeight(
            m_config->chainlock_schedule, statement.height)};
        if (!newest_epoch ||
            *newest_epoch == std::numeric_limits<uint32_t>::max()) {
            return std::nullopt;
        }
        input.newest_epoch = *newest_epoch;
        input.next_snapshot.epoch = *newest_epoch + 1;
        const auto snapshot_height{pq::RegistrationCutoffHeight(
            m_config->chainlock_schedule, input.next_snapshot.epoch,
            m_quorum_build_config->roster_snapshot_lag_blocks)};
        if (!snapshot_height) return std::nullopt;
        input.next_snapshot.height = *snapshot_height;
        if (prior.statement.height >= *snapshot_height) {
            const CBlockIndex* snapshot{
                authorization_predecessor->GetAncestor(*snapshot_height)};
            if (snapshot == nullptr) return std::nullopt;
            input.next_snapshot.hash = snapshot->GetBlockHash();
            input.next_snapshot.prior_authorization_is_descendant = true;
        }

        const auto check_cursor = [&](const pq::BTCCursor& cursor) {
            if (cursor.IsNull()) return true;
            const CBlockIndex* source{
                candidate->GetAncestor(cursor.sys_height)};
            return source != nullptr &&
                   source->GetBlockHash() == cursor.sys_hash &&
                   source->btcpPrevCommitment == cursor.btc_hash;
        };
        if (!check_cursor(statement.previous_btcc_cursor) ||
            !check_cursor(statement.accepted_btcc_cursor)) {
            return std::nullopt;
        }
    }

    const uint32_t prior_newest_epoch{
        input.previous.window.active.seeds.back().epoch};
    const bool rotates{prior_newest_epoch != input.newest_epoch};
    const bool request_observation{
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::OBSERVE ||
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::ROTATE};
    const bool observation_required{
        request_observation &&
        statement.btcc_advance == pq::BTCCAdvance::ADVANCE &&
        input.next_snapshot.prior_authorization_is_descendant &&
        ((rotates && requested_transition ==
                         pq::RosterAuthorizationTransitionKind::ROTATE) ||
         (!rotates && input.previous.window.next.state ==
                          pq::RosterBeaconState::EMPTY))};
    const bool range_required{
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::REVEAL ||
        requested_transition ==
            pq::RosterAuthorizationTransitionKind::ROTATE};
    if (!observation_required && !range_required) return input;

    if (evidence == RosterBeaconEvidence::THRESHOLD_CERTIFICATE) {
        if (range_required) {
            const pq::RosterBeaconSeed* claimed_ready{nullptr};
            if (requested_transition ==
                pq::RosterAuthorizationTransitionKind::REVEAL) {
                claimed_ready = &statement.roster_beacons.next;
            } else if (input.previous.window.next.IsReady()) {
                claimed_ready = &input.previous.window.next;
            } else {
                claimed_ready =
                    &statement.roster_beacons.active.seeds.back();
            }
            const auto range{
                ThresholdCertificateRosterBeaconRange(*claimed_ready)};
            if (!range) return std::nullopt;
            if (input.previous.window.next.IsReady()) {
                input.ready_rotation = *range;
            } else {
                input.pending_reveal = *range;
            }
        }
        if (observation_required) {
            const auto anchor{ThresholdCertificateRosterBeaconAnchor(
                statement.roster_beacons.next)};
            if (!anchor) return std::nullopt;
            input.accepted_anchor = *anchor;
        }
        return input;
    }

    std::string reason;
    if (!pq::IsBTCHeaderPolicyEnabled() ||
        !m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
            /*recover=*/true, reason)) {
        return std::nullopt;
    }
    auto config{pq::GetConfiguredBTCHeaderPolicy(reason)};
    if (!config) return std::nullopt;
    const auto policy{pq::MakeConfiguredBTCHeaderPolicy()};

    if (observation_required) {
        config->max_lag_blocks = pq::ROSTER_BEACON_MAX_ANCHOR_BTC_LAG;
        if (!config->IsValid()) return std::nullopt;
        std::optional<uint256> previous_hash;
        if (!statement.previous_btcc_cursor.IsNull()) {
            previous_hash = statement.previous_btcc_cursor.btc_hash;
        }
        const auto checked{policy.CheckCandidate(
            *config, statement.accepted_btcc_cursor.btc_hash,
            previous_hash, GetTime(), reason)};
        if (!checked || checked->btc_hash !=
                            statement.accepted_btcc_cursor.btc_hash ||
            checked->btc_height < 0 || checked->confirmations <= 0 ||
            static_cast<int64_t>(checked->btc_height) +
                    checked->confirmations - 1 >
                std::numeric_limits<int32_t>::max()) {
            return std::nullopt;
        }
        input.accepted_anchor = pq::ValidatedRosterBeaconAnchor{
            statement.accepted_btcc_cursor, checked->btc_height,
            static_cast<int32_t>(
                static_cast<int64_t>(checked->btc_height) +
                checked->confirmations - 1),
            true};
    }

    if (range_required) {
        const auto& seed{input.previous.window.next};
        if (seed.state == pq::RosterBeaconState::EMPTY) {
            return std::nullopt;
        }
        const auto checked{policy.CheckPaymentAuditActiveRange(
            *config, seed.anchor_cursor.btc_hash, GetTime(), reason)};
        const auto future_height{seed.FutureBTCHeight()};
        if (!checked || !future_height ||
            checked->anchor_hash != seed.anchor_cursor.btc_hash ||
            checked->anchor_height != seed.anchor_btc_height ||
            checked->future_height != *future_height ||
            checked->future_hash.IsNull() ||
            checked->future_height >
                std::numeric_limits<int32_t>::max() -
                    static_cast<int32_t>(
                        pq::ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1)) {
            return std::nullopt;
        }
        pq::ValidatedRosterBeaconRange range{
            checked->anchor_hash, checked->anchor_height,
            checked->future_hash, checked->future_height,
            checked->future_height +
                static_cast<int32_t>(
                    pq::ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1),
            true};
        if (seed.state == pq::RosterBeaconState::PENDING) {
            input.pending_reveal = std::move(range);
        } else if (seed.state == pq::RosterBeaconState::READY) {
            input.ready_rotation = std::move(range);
        } else {
            return std::nullopt;
        }
    }
    return input;
}

std::optional<pq::RosterAuthorizationVerificationContext>
CChainLocksHandler::BuildNetworkRosterAuthorizationContext(
    const pq::ChainLockStatement& statement,
    const CBlockIndex& candidate,
    const pq::VerifiedRosterAuthorizationBaseView* prior) const
{
    if (!m_config || candidate.nHeight != statement.height ||
        candidate.GetBlockHash() != statement.block_hash) {
        return std::nullopt;
    }

    pq::RosterAuthorizationVerificationContext authorization;
    authorization.reset_policy =
        MakeRosterResetVerificationPolicy(*m_config);
    authorization.predecessor_height =
        statement.previous_chainlock_height;
    authorization.predecessor_block_hash =
        statement.previous_chainlock_hash;
    authorization.authorization_base =
        statement.roster_authorization_base;
    if (prior != nullptr &&
        (!prior->metadata.IsInternallyConsistent(m_genesis_hash) ||
         prior->metadata.AuthorizationBase() !=
             statement.roster_authorization_base ||
         !prior->certificate || !prior->verification_context ||
         prior->certificate->statement != prior->metadata.statement ||
         prior->verification_context->Statement() !=
             prior->metadata.statement ||
         prior->verification_context->StatementLogicalId() !=
             prior->metadata.logical_id)) {
        return std::nullopt;
    }

    const auto transition{statement.roster_transition};
    if (transition ==
        pq::RosterAuthorizationTransitionKind::INITIALIZE) {
        if (prior != nullptr ||
            !pq::IsInitialNormalRosterBeaconWindow(
                statement.roster_beacons) ||
            statement.btcc_advance != pq::BTCCAdvance::ADVANCE) {
            return std::nullopt;
        }
        const auto initial_target{
            pq::NextEligibleChainLockTargetHeight(
                m_config->chainlock_schedule,
                m_config->activation_predecessor_height)};
        const CBlockIndex* activation_predecessor{
            candidate.GetAncestor(
                m_config->activation_predecessor_height)};
        if (!initial_target || candidate.nHeight != *initial_target ||
            statement.previous_chainlock_height !=
                m_config->activation_predecessor_height ||
            activation_predecessor == nullptr ||
            statement.previous_chainlock_hash !=
                activation_predecessor->GetBlockHash() ||
            !statement.previous_btcc_cursor.IsNull()) {
            return std::nullopt;
        }
        const auto& ready{
            statement.roster_beacons.active.seeds.back()};
        const auto target_epoch{pq::EpochForHeight(
            m_config->chainlock_schedule, candidate.nHeight)};
        const auto canonical{target_epoch
            ? pq::CanonicalRosterRecoveryTargetHeight(
                  m_config->chainlock_schedule,
                  m_config->btcc_schedule, *target_epoch)
            : std::optional<int32_t>{}};
        if (!ready.IsReady() || !target_epoch || !canonical ||
            ready.epoch != *target_epoch || *canonical != candidate.nHeight ||
            statement.accepted_btcc_cursor != ready.anchor_cursor) {
            return std::nullopt;
        }

        {
            LOCK(cs_main);
            if (candidate.nHeight !=
                    ready.anchor_cursor.sys_height ||
                candidate.GetBlockHash() !=
                    ready.anchor_cursor.sys_hash ||
                candidate.btcpPrevCommitment !=
                    ready.anchor_cursor.btc_hash) {
                return std::nullopt;
            }
        }

        // Bitcoin active-chain/range checks are signer policy. Network
        // admission must remain deterministic for ordinary full nodes, which
        // authenticate these exact bytes through the threshold certificate.
        authorization.admission =
            pq::RosterAuthorizationAdmission::INITIALIZE;
        return authorization;
    }

    if (transition == pq::RosterAuthorizationTransitionKind::RECOVER) {
        if (prior == nullptr ||
            statement.btcc_advance != pq::BTCCAdvance::KEEP) {
            return std::nullopt;
        }
        const auto target_epoch{pq::EpochForHeight(
            m_config->chainlock_schedule, candidate.nHeight)};
        const auto canonical{target_epoch
            ? pq::CanonicalRosterRecoveryTargetHeight(
                  m_config->chainlock_schedule,
                  m_config->btcc_schedule, *target_epoch)
            : std::optional<int32_t>{}};
        const auto& source{
            statement.roster_beacons.active.recovery_authority_source};
        const auto& authority_hash{
            statement.roster_beacons.active.recovery_authority_hash};
        const auto& prior_bundle{
            prior->metadata.statement.roster_beacons.active};
        const auto expected_window{target_epoch
            ? pq::MakeRecoveryRosterBeaconWindow(
                  source, authority_hash,
                  *target_epoch)
            : std::optional<pq::RosterBeaconWindow>{}};
        if (!target_epoch || !canonical ||
            *canonical != candidate.nHeight || source.IsNull() ||
            authority_hash.IsNull() ||
            source != prior_bundle.recovery_authority_source ||
            authority_hash != prior_bundle.recovery_authority_hash ||
            !expected_window || *expected_window != statement.roster_beacons) {
            return std::nullopt;
        }
        authorization.admission =
            pq::RosterAuthorizationAdmission::RECOVER;
        authorization.previous = pq::RosterAuthorizationPriorState{
            prior->metadata.statement.roster_authorization_state_hash,
            prior->metadata.statement.roster_beacons};
        return authorization;
    }

    if (prior == nullptr) return std::nullopt;
    authorization.previous = pq::RosterAuthorizationPriorState{
        prior->metadata.statement.roster_authorization_state_hash,
        prior->metadata.statement.roster_beacons};
    authorization.admission = pq::RosterAuthorizationAdmission::LIVE;
    authorization.normal_input = BuildNormalRosterAuthorizationInput(
        statement, prior->metadata, transition,
        RosterBeaconEvidence::THRESHOLD_CERTIFICATE);
    if (!authorization.normal_input) return std::nullopt;
    return authorization;
}

pq::RecoveryRosterAuthorityPtr
CChainLocksHandler::DeriveRecoveryRosterAuthority(
    const CBlockIndex& candidate,
    const pq::RecoveryRosterAuthoritySource& source,
    const pq::FrozenQuorumRosterCachePtr& roster_cache,
    pq::QuorumBuildError* error) const
{
    if (error != nullptr) *error = pq::QuorumBuildError::NONE;
    if (!m_config || !m_quorum_build_config || !roster_cache ||
        !source.IsStructurallyValid() || source.IsNull()) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::INVALID_ARGUMENT;
        }
        return nullptr;
    }
    const auto& normal{source.normal_beacon};
    const CBlockIndex* source_anchor{
        candidate.GetAncestor(normal.anchor_cursor.sys_height)};
    if (source_anchor == nullptr ||
        source_anchor->GetBlockHash() != normal.anchor_cursor.sys_hash) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR;
        }
        return nullptr;
    }
    return pq::BuildRecoveryRosterAuthorityFromSource(
        m_genesis_hash, *m_quorum_build_config, candidate.nHeight,
        candidate, source,
        [roster_cache](const CBlockIndex& index) {
            return roster_cache->LookupSnapshot(index);
        },
        error);
}

pq::RecoveryRosterAuthorityPtr
CChainLocksHandler::ResolveRecoveryRosterAuthority(
    const pq::ChainLockStatement& statement,
    const CBlockIndex& candidate,
    const pq::FinalChainLockRecordMetadata* prior,
    const pq::FrozenQuorumRosterCachePtr& roster_cache,
    pq::QuorumBuildError* error) const
{
    if (error != nullptr) *error = pq::QuorumBuildError::NONE;
    const auto& bundle{statement.roster_beacons.active};
    const auto& source{bundle.recovery_authority_source};
    const uint256& expected_hash{bundle.recovery_authority_hash};
    if (!m_config || !m_quorum_build_config || !m_persistence ||
        !roster_cache || !source.IsStructurallyValid() ||
        source.IsNull() || expected_hash.IsNull() ||
        (statement.roster_transition ==
             pq::RosterAuthorizationTransitionKind::RECOVER &&
         prior == nullptr)) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::INVALID_ARGUMENT;
        }
        return nullptr;
    }
    const CBlockIndex* source_anchor{candidate.GetAncestor(
        source.normal_beacon.anchor_cursor.sys_height)};
    if (source_anchor == nullptr ||
        source_anchor->GetBlockHash() !=
            source.normal_beacon.anchor_cursor.sys_hash) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR;
        }
        return nullptr;
    }
    const auto exact_persisted_authority = [&]
        (const uint256& hash) -> pq::RecoveryRosterAuthorityPtr {
        const auto authority{m_persistence->LoadRecoveryRosterAuthority()};
        const auto authority_hash{authority
            ? pq::GetRecoveryRosterAuthorityHash(
                  m_genesis_hash, *authority)
            : std::optional<uint256>{}};
        return authority_hash && *authority_hash == hash
            ? authority
            : nullptr;
    };

    if (prior != nullptr &&
        (!prior->IsInternallyConsistent(m_genesis_hash) ||
         (statement.roster_transition ==
              pq::RosterAuthorizationTransitionKind::RECOVER &&
          (source != prior->statement.roster_beacons.active
                         .recovery_authority_source ||
           expected_hash != prior->statement.roster_beacons.active
                                .recovery_authority_hash)))) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::INVALID_ARGUMENT;
        }
        return nullptr;
    }

    if (auto authority{exact_persisted_authority(expected_hash)};
        authority && authority->normal_beacon == source.normal_beacon) {
        return authority;
    }
    auto authority{pq::BuildRecoveryRosterAuthorityFromSource(
        m_genesis_hash, *m_quorum_build_config, statement.height,
        candidate, source,
        [roster_cache](const CBlockIndex& index) {
            return roster_cache->LookupSnapshot(index);
        },
        error)};
    const auto authority_hash{authority
        ? pq::GetRecoveryRosterAuthorityHash(
              m_genesis_hash, *authority)
        : std::optional<uint256>{}};
    if (!authority_hash || *authority_hash != expected_hash ||
        authority->normal_beacon != source.normal_beacon) {
        if (error != nullptr) {
            *error = pq::QuorumBuildError::INVALID_ROSTER_BEACON;
        }
        return nullptr;
    }
    return authority;
}

std::optional<CChainLocksHandler::RuntimeVerificationContext>
CChainLocksHandler::BuildRuntimeVerificationContext(
    const pq::PreparedFinalChainLockCandidate& prepared,
    bool* definitively_invalid,
    bool publish_roster,
    const BTCCReceiptArchiveCapability*
        receipt_archive_capability) const
{
    if (definitively_invalid != nullptr) *definitively_invalid = false;
    if (!m_config || !m_quorum_build_config) return std::nullopt;
    uint64_t roster_source_generation{0};
    const auto roster_cache{
        GetQuorumRosterCache(&roster_source_generation)};
    if (!roster_cache) return std::nullopt;

    const CBlockIndex* candidate{nullptr};
    const pq::ChainLockCandidateContextRequest request{
        prepared.statement, prepared.predecessor,
        prepared.has_local_chainlock,
        prepared.declared_predecessor_btcc_cursor,
        prepared.admission, m_config->btcc_schedule};
    const auto current{
        BuildCandidateContext(request, &candidate)};
    if (!current || *current != prepared.context || candidate == nullptr) {
        return std::nullopt;
    }

    HistoricalAdmissionContext historical;
    if (prepared.admission == pq::ChainLockCandidateAdmission::CATCHUP ||
        prepared.admission ==
            pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT) {
        historical = GetHistoricalAdmission(prepared.statement,
                                             prepared.logical_id);
        const bool expected_catchup{
            prepared.admission == pq::ChainLockCandidateAdmission::CATCHUP &&
            (historical.admission ==
                 HistoricalAdmission::CURRENT_CATCHUP ||
             historical.admission ==
                 HistoricalAdmission::RECOVERY ||
             historical.admission ==
                 HistoricalAdmission::PRESEAL_CATCHUP ||
             historical.admission ==
                 HistoricalAdmission::PRESEAL_RECEIPT)};
        const bool expected_receipt{
            prepared.admission ==
                pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
            historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
        if (!expected_catchup && !expected_receipt) return std::nullopt;
    }

    pq::RosterAuthorizationVerificationContext authorization;
    std::optional<pq::VerifiedRosterAuthorizationBaseView>
        exact_authorization_prior;
    authorization.predecessor_height =
        prepared.statement.previous_chainlock_height;
    authorization.predecessor_block_hash =
        prepared.statement.previous_chainlock_hash;
    const bool trusted_persistence{
        prepared.admission ==
        pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE};
    std::optional<pq::FinalChainLock> exact_persisted_record;
    if (trusted_persistence && !m_persistence) return std::nullopt;
    if (trusted_persistence && m_persistence) {
        const auto matches_prepared = [&](const pq::FinalChainLock& record) {
            return record.statement == prepared.statement &&
                   record.GetLogicalId(m_genesis_hash) ==
                       prepared.logical_id &&
                   record.GetWitnessId(m_genesis_hash) ==
                       prepared.witness_id;
        };
        const auto persisted_best{m_persistence->LoadBest()};
        if (persisted_best && matches_prepared(*persisted_best)) {
            exact_persisted_record = persisted_best;
        } else {
            const auto base{m_persistence->LoadAuthorizationBase(
                prepared.logical_id)};
            if (base && matches_prepared(*base)) {
                exact_persisted_record = base;
            }
        }
        if (!exact_persisted_record) return std::nullopt;
    }
    const bool trusted_unsealed{
        prepared.admission == pq::ChainLockCandidateAdmission::
                                  TRUSTED_UNSEALED_PERSISTENCE};
    const auto persisted_unsealed{
        trusted_unsealed && m_persistence
            ? m_persistence->LoadUnsealedBTCC()
            : std::optional<pq::FinalChainLock>{}};
    const bool exact_persisted_unsealed{
        persisted_unsealed &&
        persisted_unsealed->statement == prepared.statement &&
        persisted_unsealed->GetLogicalId(m_genesis_hash) ==
            prepared.logical_id &&
        persisted_unsealed->GetWitnessId(m_genesis_hash) ==
            prepared.witness_id};
    const bool network_receipt_archive{
        prepared.admission ==
            pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE};
    const bool preseal_receipt_archive{
        prepared.admission ==
                pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
        prepared.statement.roster_transition !=
            pq::RosterAuthorizationTransitionKind::INITIALIZE};
    const bool authorized_receipt_archive{
        network_receipt_archive || preseal_receipt_archive};
    if (trusted_unsealed && !exact_persisted_unsealed) {
        return std::nullopt;
    }
    if (authorized_receipt_archive &&
        (receipt_archive_capability == nullptr ||
         receipt_archive_capability->logical_id != prepared.logical_id ||
         !IsBTCCReceiptArchiveCapabilityCurrent(
             *receipt_archive_capability))) {
        return std::nullopt;
    }
    if (prepared.admission ==
            pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE ||
        trusted_unsealed) {
        authorization.admission =
            pq::RosterAuthorizationAdmission::TRUSTED_PERSISTENCE;
    } else {
        const auto best{m_store ? m_store->GetBestRecord()
                                : std::nullopt};
        if (prepared.has_local_chainlock != best.has_value() ||
            (best &&
             (best->metadata.statement.height !=
                  prepared.predecessor.height ||
              best->metadata.statement.block_hash !=
                  prepared.predecessor.block_hash))) {
            return std::nullopt;
        }
        if (authorized_receipt_archive) {
            if (!best || best->metadata.statement.height <
                             receipt_archive_capability->authorization
                                 .owner.statement.height ||
                prepared.statement.height <=
                    receipt_archive_capability->authorization.predecessor
                        .statement.height ||
                prepared.statement.height >
                    receipt_archive_capability->authorization
                        .owner.statement.previous_chainlock_height) {
                return std::nullopt;
            }
            if (best->metadata.logical_id !=
                    receipt_archive_capability->authorization
                        .covering_logical_id ||
                best->metadata.witness_id !=
                    receipt_archive_capability->authorization
                        .covering_witness_id) {
                return std::nullopt;
            }
            LOCK(cs_main);
            const CBlockIndex* best_index{
                m_chainman.m_blockman.LookupBlockIndex(
                    best->metadata.statement.block_hash)};
            const CBlockIndex* owner_index{
                best_index != nullptr &&
                        best_index->nHeight ==
                            best->metadata.statement.height
                    ? best_index->GetAncestor(
                          receipt_archive_capability->authorization
                              .owner.statement.height)
                    : nullptr};
            if (owner_index == nullptr ||
                owner_index->GetBlockHash() !=
                    receipt_archive_capability->authorization
                        .owner.statement.block_hash ||
                owner_index->GetAncestor(prepared.statement.height) !=
                    candidate) {
                return std::nullopt;
            }
        }
        const auto authorization_route{
            SelectHistoricalRosterAuthorization(
                prepared.admission, historical.admission,
                prepared.statement.roster_transition)};
        if (authorization_route ==
            HistoricalRosterAuthorization::EXACT_NETWORK) {
            if (!prepared.statement.roster_authorization_base.IsNull()) {
                exact_authorization_prior =
                    m_store->GetVerifiedRosterAuthorizationBase(
                        prepared.statement.roster_authorization_base);
                if (!exact_authorization_prior) return std::nullopt;
            }
            const auto derived{BuildNetworkRosterAuthorizationContext(
                prepared.statement, *candidate,
                exact_authorization_prior
                    ? &*exact_authorization_prior
                    : nullptr)};
            if (!derived) return std::nullopt;
            authorization = *derived;
            if (!IsStateAdvancingAuthorizationBaseAdmissible(
                    prepared.admission,
                    prepared.selected_quorum_mask,
                    prepared.statement, *candidate, best,
                    exact_authorization_prior
                        ? &*exact_authorization_prior
                        : nullptr,
                    authorization,
                    prepared.context.btcc_cursor_reconciliation)) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    const pq::FinalChainLockRecordMetadata* recovery_prior{
        prepared.statement.roster_transition ==
                    pq::RosterAuthorizationTransitionKind::RECOVER &&
                exact_authorization_prior
            ? &exact_authorization_prior->metadata
            : nullptr};
    pq::RecoveryRosterAuthorityPtr recovery_authority;
    if (!prepared.statement.roster_beacons.active
             .recovery_authority_source.IsNull()) {
        if (trusted_persistence || trusted_unsealed) {
            const auto persisted{trusted_persistence
                ? exact_persisted_record
                : m_persistence->LoadUnsealedBTCC()};
            recovery_authority =
                persisted && persisted->statement == prepared.statement &&
                        persisted->GetLogicalId(m_genesis_hash) ==
                            prepared.logical_id &&
                        persisted->GetWitnessId(m_genesis_hash) ==
                            prepared.witness_id
                    ? m_persistence->LoadRecoveryRosterAuthority()
                    : nullptr;
            const auto authority_hash{recovery_authority
                ? pq::GetRecoveryRosterAuthorityHash(
                      m_genesis_hash, *recovery_authority)
                : std::optional<uint256>{}};
            if (!authority_hash ||
                *authority_hash != prepared.statement.roster_beacons.active
                                       .recovery_authority_hash) {
                recovery_authority.reset();
            }
            // Persistence keeps one current authority blob. An older retained
            // authorization base can name an earlier E/S pair, so rebuild
            // that exact authority from its separately retained source
            // snapshot instead of trusting statement metadata or discarding
            // the base after restart.
            if (!recovery_authority &&
                (trusted_persistence || trusted_unsealed)) {
                recovery_authority = DeriveRecoveryRosterAuthority(
                    *candidate,
                    prepared.statement.roster_beacons.active
                        .recovery_authority_source,
                    roster_cache, &build_error);
                const auto rebuilt_hash{recovery_authority
                    ? pq::GetRecoveryRosterAuthorityHash(
                          m_genesis_hash, *recovery_authority)
                    : std::optional<uint256>{}};
                if (!rebuilt_hash ||
                    *rebuilt_hash !=
                        prepared.statement.roster_beacons.active
                            .recovery_authority_hash) {
                    recovery_authority.reset();
                }
            }
        } else {
            recovery_authority = ResolveRecoveryRosterAuthority(
                prepared.statement, *candidate, recovery_prior,
                roster_cache, &build_error);
        }
        if (!recovery_authority) {
            if (definitively_invalid != nullptr) {
                *definitively_invalid =
                    build_error !=
                        pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED &&
                    build_error !=
                        pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR;
            }
            return std::nullopt;
        }
    }
    const auto roster_set{recovery_authority
        ? roster_cache->GetVerifiedActiveWithRecoveryAuthority(
              prepared.statement.height, *candidate,
              prepared.statement.roster_beacons.active,
              recovery_authority, publish_roster, &build_error)
        : publish_roster
            ? roster_cache->GetVerifiedActive(
                  prepared.statement.height, *candidate,
                  prepared.statement.roster_beacons.active, &build_error)
            : roster_cache->GetVerifiedActiveNoPublish(
                  prepared.statement.height, *candidate,
                  prepared.statement.roster_beacons.active, &build_error)};
    if (!roster_set) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid =
                build_error != pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR &&
                build_error != pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED &&
                build_error != pq::QuorumBuildError::INVALID_FROZEN_ROSTER;
        }
        return std::nullopt;
    }
    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    auto prepared_context{pq::PreparedChainLockContext::Create(
        m_config->chainlock_schedule, prepared.statement, roster_set,
        authorization, &verification_error, recovery_authority)};
    if (!prepared_context) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid = true;
        }
        return std::nullopt;
    }
    return RuntimeVerificationContext{
        std::move(prepared_context), historical,
        roster_source_generation};
}

std::optional<CChainLocksHandler::RuntimeVerificationContext>
CChainLocksHandler::BuildHistoricalPreVerificationContext(
    const pq::FinalChainLock& chainlock,
    const HistoricalAdmissionContext& expected,
    const BTCCReceiptArchiveCapability* receipt_archive_capability,
    bool* definitively_invalid) const
{
    if (definitively_invalid != nullptr) *definitively_invalid = false;
    if (!m_config || !m_quorum_build_config || !m_store ||
        expected.admission == HistoricalAdmission::NONE) {
        return std::nullopt;
    }
    uint64_t roster_source_generation{0};
    const auto roster_cache{
        GetQuorumRosterCache(&roster_source_generation)};
    if (!roster_cache) return std::nullopt;

    const CBlockIndex* candidate{nullptr};
    pq::VerifiedRosterSetPtr roster_set;
    {
        LOCK(cs_main);
        if (GetHistoricalAdmissionLocked(
                chainlock.statement,
                chainlock.GetLogicalId(m_genesis_hash)) != expected ||
            !m_chainman.IsBaseBlockSyncComplete() ||
            (m_chainman.IsSnapshotActive() &&
             !m_chainman.IsSnapshotValidated())) {
            return std::nullopt;
        }
        candidate = m_chainman.m_blockman.LookupBlockIndex(
            chainlock.statement.block_hash);
        if (candidate == nullptr ||
            candidate->nHeight != chainlock.statement.height) {
            return std::nullopt;
        }
        if (candidate->nStatus & BLOCK_FAILED_MASK) {
            if (definitively_invalid != nullptr) {
                *definitively_invalid = true;
            }
            return std::nullopt;
        }
        if (candidate->IsAssumedValid() ||
            !candidate->IsValid(BLOCK_VALID_SCRIPTS) ||
            !HasFullReceiptIndexProvenance(*candidate)) {
            return std::nullopt;
        }
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        const bool active_candidate{
            active_tip != nullptr &&
            active_tip->nHeight >= candidate->nHeight &&
            active_tip->GetAncestor(candidate->nHeight) == candidate};
        if ((expected.admission ==
                 HistoricalAdmission::CURRENT_CATCHUP ||
             expected.admission ==
                 HistoricalAdmission::RECOVERY) &&
            !active_candidate &&
            !(candidate->nStatus & BLOCK_HAVE_DATA)) {
            return std::nullopt;
        }

    }

    const auto best{m_store->GetBestRecord()};
    std::optional<pq::RosterAuthorizationVerificationContext>
        authorization;
    const auto candidate_admission{
        SelectHistoricalPreVerificationAdmission(
            expected.admission, chainlock.statement.height,
            best ? std::optional<int32_t>{best->metadata.statement.height}
                 : std::nullopt)};
    std::optional<pq::BTCCCursorReconciliationProof>
        preverification_reconciliation;
    if (candidate_admission ==
            pq::ChainLockCandidateAdmission::CATCHUP &&
        best) {
        LOCK(cs_main);
        const auto canonical{SelectCurrentChainLockBTCC(
            m_genesis_hash, *m_config, *candidate, &best->metadata)};
        if (canonical) {
            (void)MatchesCurrentChainLockBTCCSelection(
                *canonical, chainlock.statement,
                best->metadata.statement.accepted_btcc_cursor,
                &preverification_reconciliation);
        }
    }
    const bool authorized_preseal_receipt{
        candidate_admission ==
            pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
        chainlock.statement.roster_transition !=
            pq::RosterAuthorizationTransitionKind::INITIALIZE};
    if (authorized_preseal_receipt &&
        (receipt_archive_capability == nullptr ||
         receipt_archive_capability->logical_id !=
             chainlock.GetLogicalId(m_genesis_hash) ||
         !IsBTCCReceiptArchiveCapabilityCurrent(
             *receipt_archive_capability) ||
         !best ||
         best->metadata.logical_id !=
             receipt_archive_capability->authorization
                 .covering_logical_id ||
         best->metadata.witness_id !=
             receipt_archive_capability->authorization
                 .covering_witness_id ||
         chainlock.statement.height <=
             receipt_archive_capability->authorization.predecessor
                 .statement.height ||
         chainlock.statement.height >
             receipt_archive_capability->authorization.owner.statement
                 .previous_chainlock_height)) {
        return std::nullopt;
    }
    if (authorized_preseal_receipt) {
        LOCK(cs_main);
        const CBlockIndex* best_index{
            m_chainman.m_blockman.LookupBlockIndex(
                best->metadata.statement.block_hash)};
        const CBlockIndex* owner_index{
            best_index != nullptr &&
                    best_index->nHeight == best->metadata.statement.height
                ? best_index->GetAncestor(
                      receipt_archive_capability->authorization.owner
                          .statement.height)
                : nullptr};
        if (owner_index == nullptr ||
            owner_index->GetBlockHash() !=
                receipt_archive_capability->authorization.owner
                    .statement.block_hash ||
            owner_index->GetAncestor(chainlock.statement.height) !=
                candidate) {
            return std::nullopt;
        }
    }
    std::optional<pq::VerifiedRosterAuthorizationBaseView>
        exact_authorization_prior;
    const auto authorization_route{SelectHistoricalRosterAuthorization(
        candidate_admission, expected.admission,
        chainlock.statement.roster_transition)};
    if (authorization_route ==
        HistoricalRosterAuthorization::EXACT_NETWORK) {
        if (!chainlock.statement.roster_authorization_base.IsNull()) {
            exact_authorization_prior =
                m_store->GetVerifiedRosterAuthorizationBase(
                    chainlock.statement.roster_authorization_base);
            if (!exact_authorization_prior) return std::nullopt;
        }
        authorization = BuildNetworkRosterAuthorizationContext(
            chainlock.statement, *candidate,
            exact_authorization_prior ? &*exact_authorization_prior
                                      : nullptr);
    }
    if (!authorization) return std::nullopt;
    if (!IsStateAdvancingAuthorizationBaseAdmissible(
            candidate_admission, chainlock.selected_quorum_mask,
            chainlock.statement, *candidate, best,
            exact_authorization_prior ? &*exact_authorization_prior
                                      : nullptr,
            *authorization, preverification_reconciliation)) {
        return std::nullopt;
    }
    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    pq::RecoveryRosterAuthorityPtr recovery_authority;
    if (!chainlock.statement.roster_beacons.active
             .recovery_authority_source.IsNull()) {
        recovery_authority = ResolveRecoveryRosterAuthority(
            chainlock.statement, *candidate,
                chainlock.statement.roster_transition ==
                        pq::RosterAuthorizationTransitionKind::RECOVER &&
                    exact_authorization_prior
                ? &exact_authorization_prior->metadata
                : nullptr,
            roster_cache, &build_error);
        if (!recovery_authority) return std::nullopt;
    }
    roster_set = recovery_authority
        ? roster_cache->GetVerifiedActiveWithRecoveryAuthority(
              chainlock.statement.height, *candidate,
              chainlock.statement.roster_beacons.active,
              recovery_authority, /*publish=*/false, &build_error)
        : roster_cache->GetVerifiedActiveNoPublish(
              chainlock.statement.height, *candidate,
              chainlock.statement.roster_beacons.active, &build_error);
    if (!roster_set) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid =
                build_error !=
                    pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR &&
                build_error !=
                    pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED &&
                build_error !=
                    pq::QuorumBuildError::INVALID_FROZEN_ROSTER;
        }
        return std::nullopt;
    }
    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    auto prepared_context{pq::PreparedChainLockContext::Create(
        m_config->chainlock_schedule, chainlock.statement,
        std::move(roster_set), *authorization, &verification_error,
        recovery_authority)};
    if (!prepared_context) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid = true;
        }
        return std::nullopt;
    }
    return RuntimeVerificationContext{
        std::move(prepared_context), expected,
        roster_source_generation};
}

CChainLocksHandler::HistoricalRosterAuthorization
CChainLocksHandler::SelectHistoricalRosterAuthorization(
    pq::ChainLockCandidateAdmission candidate_admission,
    HistoricalAdmission historical_admission,
    pq::RosterAuthorizationTransitionKind transition) noexcept
{
    const bool reset_transition{
        transition ==
            pq::RosterAuthorizationTransitionKind::INITIALIZE ||
        transition == pq::RosterAuthorizationTransitionKind::RECOVER};
    switch (historical_admission) {
    case HistoricalAdmission::RECOVERY:
        return reset_transition
            ? HistoricalRosterAuthorization::EXACT_NETWORK
            : HistoricalRosterAuthorization::INVALID;
    case HistoricalAdmission::CURRENT_CATCHUP:
        return reset_transition
            ? HistoricalRosterAuthorization::INVALID
            : HistoricalRosterAuthorization::EXACT_NETWORK;
    case HistoricalAdmission::PRESEAL_CATCHUP:
        return HistoricalRosterAuthorization::EXACT_NETWORK;
    case HistoricalAdmission::PRESEAL_RECEIPT:
        return HistoricalRosterAuthorization::EXACT_NETWORK;
    case HistoricalAdmission::NONE:
        (void)candidate_admission;
        return HistoricalRosterAuthorization::EXACT_NETWORK;
    }
    return HistoricalRosterAuthorization::INVALID;
}

pq::ChainLockCandidateAdmission
CChainLocksHandler::SelectHistoricalPreVerificationAdmission(
    HistoricalAdmission historical_admission,
    int32_t statement_height,
    std::optional<int32_t> best_height) noexcept
{
    return historical_admission == HistoricalAdmission::PRESEAL_RECEIPT &&
                   best_height && statement_height < *best_height
        ? pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT
        : pq::ChainLockCandidateAdmission::CATCHUP;
}

bool CChainLocksHandler::IsHistoricalArchiveIdentity(
    pq::ChainLockCandidateAdmission candidate_admission) noexcept
{
    return candidate_admission ==
               pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT ||
           candidate_admission ==
               pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE ||
           candidate_admission == pq::ChainLockCandidateAdmission::
                                      TRUSTED_UNSEALED_PERSISTENCE;
}

bool CChainLocksHandler::IsStateAdvancingAuthorizationBaseAdmissible(
    pq::ChainLockCandidateAdmission candidate_admission,
    uint8_t selected_quorum_mask,
    const pq::ChainLockStatement& statement,
    const CBlockIndex& candidate,
    const std::optional<pq::AcceptedFinalChainLockView>& current,
    const pq::VerifiedRosterAuthorizationBaseView* exact_prior,
    const pq::RosterAuthorizationVerificationContext&
        exact_authorization,
    const std::optional<pq::BTCCCursorReconciliationProof>&
        btcc_cursor_reconciliation) const
{
    if (candidate_admission != pq::ChainLockCandidateAdmission::LIVE &&
        candidate_admission != pq::ChainLockCandidateAdmission::CATCHUP) {
        return true;
    }
    if (!current) {
        return statement.roster_transition ==
                   pq::RosterAuthorizationTransitionKind::INITIALIZE &&
               statement.roster_authorization_base.IsNull();
    }
    if (statement.roster_authorization_base ==
        current->metadata.AuthorizationBase()) {
        return true;
    }
    if (!exact_prior || !m_config ||
        statement.roster_transition ==
            pq::RosterAuthorizationTransitionKind::INITIALIZE ||
        !current->metadata.IsInternallyConsistent(m_genesis_hash) ||
        !exact_prior->metadata.IsInternallyConsistent(m_genesis_hash) ||
        exact_prior->metadata.AuthorizationBase() !=
            statement.roster_authorization_base ||
        exact_prior->metadata.statement.height >=
            current->metadata.statement.height ||
        current->metadata.statement.height >= statement.height) {
        return false;
    }

    {
        LOCK(cs_main);
        const CBlockIndex* current_ancestor{
            candidate.GetAncestor(current->metadata.statement.height)};
        const CBlockIndex* base_ancestor{
            candidate.GetAncestor(exact_prior->metadata.statement.height)};
        if (current_ancestor == nullptr ||
            current_ancestor->GetBlockHash() !=
                current->metadata.statement.block_hash ||
            base_ancestor == nullptr ||
            base_ancestor->GetBlockHash() !=
                exact_prior->metadata.statement.block_hash) {
            return false;
        }
    }

    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    const auto exact_mask{pq::ValidateRosterAuthorizationState(
        m_genesis_hash, statement, exact_authorization,
        &verification_error)};
    if (!exact_mask ||
        (selected_quorum_mask & ~*exact_mask) != 0) {
        return false;
    }

    if (statement.roster_transition ==
        pq::RosterAuthorizationTransitionKind::RECOVER) {
        if (candidate_admission !=
            pq::ChainLockCandidateAdmission::CATCHUP) {
            return false;
        }
        const auto target_epoch{pq::EpochForHeight(
            m_config->chainlock_schedule, statement.height)};
        const auto canonical{target_epoch
            ? pq::CanonicalRosterRecoveryTargetHeight(
                  m_config->chainlock_schedule,
                  m_config->btcc_schedule, *target_epoch)
            : std::optional<int32_t>{}};
        const auto& candidate_bundle{
            statement.roster_beacons.active};
        const auto& current_bundle{
            current->metadata.statement.roster_beacons.active};
        if (!target_epoch || !canonical ||
            *canonical != statement.height ||
            candidate_bundle.recovery_authority_source.IsNull() ||
            candidate_bundle.recovery_authority_hash.IsNull() ||
            candidate_bundle.recovery_authority_source !=
                current_bundle.recovery_authority_source ||
            candidate_bundle.recovery_authority_hash !=
                current_bundle.recovery_authority_hash) {
            return false;
        }
        const auto expected_window{pq::MakeRecoveryRosterBeaconWindow(
            current_bundle.recovery_authority_source,
            current_bundle.recovery_authority_hash, *target_epoch)};
        if (!expected_window ||
            *expected_window != statement.roster_beacons) {
            return false;
        }

        auto projected_statement{statement};
        projected_statement.roster_authorization_base =
            current->metadata.AuthorizationBase();
        pq::RosterAuthorizationTransition projected_transition;
        projected_transition.kind =
            pq::RosterAuthorizationTransitionKind::RECOVER;
        projected_transition.target_height = statement.height;
        projected_transition.target_block_hash = statement.block_hash;
        projected_transition.predecessor_height =
            statement.previous_chainlock_height;
        projected_transition.predecessor_block_hash =
            statement.previous_chainlock_hash;
        projected_transition.authorization_base =
            projected_statement.roster_authorization_base;
        projected_transition.previous =
            pq::RosterAuthorizationPriorState{
                current->metadata.statement
                    .roster_authorization_state_hash,
                current->metadata.statement.roster_beacons};
        projected_transition.new_window = statement.roster_beacons;
        const auto projected_state_hash{
            pq::GetRosterAuthorizationStateHash(
                m_genesis_hash, projected_transition)};
        if (!projected_state_hash) return false;
        projected_statement.roster_authorization_state_hash =
            *projected_state_hash;

        pq::RosterAuthorizationVerificationContext projected;
        projected.admission =
            pq::RosterAuthorizationAdmission::RECOVER;
        projected.predecessor_height =
            statement.previous_chainlock_height;
        projected.predecessor_block_hash =
            statement.previous_chainlock_hash;
        projected.authorization_base =
            projected_statement.roster_authorization_base;
        projected.reset_policy =
            MakeRosterResetVerificationPolicy(*m_config);
        projected.previous = projected_transition.previous;
        const auto projected_mask{pq::ValidateRosterAuthorizationState(
            m_genesis_hash, projected_statement, projected,
            &verification_error)};
        return projected_mask &&
               (selected_quorum_mask & ~*projected_mask) == 0;
    }

    constexpr std::array<pq::RosterAuthorizationTransitionKind, 4>
        normal_transitions{
            pq::RosterAuthorizationTransitionKind::KEEP,
            pq::RosterAuthorizationTransitionKind::OBSERVE,
            pq::RosterAuthorizationTransitionKind::REVEAL,
            pq::RosterAuthorizationTransitionKind::ROTATE};
    for (const auto requested : normal_transitions) {
        const auto input{BuildNormalRosterAuthorizationInput(
            statement, current->metadata, requested,
            RosterBeaconEvidence::THRESHOLD_CERTIFICATE)};
        const auto decision{input
            ? pq::DeriveNormalRosterAuthorizationDecision(
                  m_genesis_hash, *input)
            : std::optional<pq::NormalRosterAuthorizationDecision>{}};
        if (!decision ||
            decision->transition.new_window.active !=
                statement.roster_beacons.active ||
            (selected_quorum_mask &
             ~decision->authorization_mask) != 0) {
            continue;
        }
        if (decision->transition.new_window.next ==
            statement.roster_beacons.next) {
            return true;
        }
        const auto& projected_next{
            decision->transition.new_window.next};
        const auto& candidate_next{statement.roster_beacons.next};
        const bool inverse_observation{
            candidate_admission ==
                pq::ChainLockCandidateAdmission::CATCHUP &&
            btcc_cursor_reconciliation &&
            btcc_cursor_reconciliation->IsStructurallyValid() &&
            candidate_next.anchor_kind ==
                pq::RosterBeaconAnchorKind::NORMAL &&
            candidate_next.state == pq::RosterBeaconState::EMPTY &&
            projected_next.anchor_kind ==
                pq::RosterBeaconAnchorKind::NORMAL &&
            (projected_next.state == pq::RosterBeaconState::PENDING ||
             projected_next.state == pq::RosterBeaconState::READY) &&
            candidate_next.epoch == projected_next.epoch &&
            projected_next.anchor_cursor ==
                btcc_cursor_reconciliation->skipped_cursor &&
            btcc_cursor_reconciliation->skipped_cursor ==
                current->metadata.statement.accepted_btcc_cursor &&
            btcc_cursor_reconciliation->previous_receipt_state ==
                current->metadata.statement.btcc_receipt_state &&
            statement.btcc_receipt_state ==
                btcc_cursor_reconciliation->current_receipt_state &&
            statement.height >=
                btcc_cursor_reconciliation->carrier_height &&
            statement.accepted_btcc_cursor ==
                btcc_cursor_reconciliation->current_receipt_state.cursor &&
            statement.btcc_advance == pq::BTCCAdvance::KEEP};
        if (inverse_observation) return true;
    }
    return false;
}

bool CChainLocksHandler::IsHistoricalVerificationCapabilityCurrent(
    const RuntimeVerificationContext& verification,
    const HistoricalAdmissionContext& expected) const
{
    uint64_t current_roster_generation{0};
    (void)GetQuorumRosterCache(&current_roster_generation);
    return verification.prepared_context != nullptr &&
           DoesHistoricalVerificationCapabilityMatch(
               verification.historical,
               verification.roster_source_generation, expected,
               current_roster_generation);
}

bool CChainLocksHandler::DoesHistoricalVerificationCapabilityMatch(
    const HistoricalAdmissionContext& verified,
    uint64_t verified_roster_generation,
    const HistoricalAdmissionContext& expected,
    uint64_t current_roster_generation) noexcept
{
    return verified == expected && verified_roster_generation != 0 &&
           verified_roster_generation == current_roster_generation;
}

std::shared_ptr<const CChainLocksHandler::PendingVerifiedHistoricalChainLock>
CChainLocksHandler::GetPendingVerifiedHistoricalChainLock() const
{
    return m_pending_verified_historical.load();
}

bool CChainLocksHandler::RetainVerifiedHistoricalChainLock(
    const pq::FinalChainLock& chainlock,
    const RuntimeVerificationContext& verification)
{
    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    auto pending{std::make_shared<PendingVerifiedHistoricalChainLock>()};
    pending->chainlock = chainlock;
    pending->verification = verification;
    pending->logical_id = logical_id;
    pending->witness_id = witness_id;
    std::shared_ptr<const PendingVerifiedHistoricalChainLock> desired{
        std::move(pending)};
    std::shared_ptr<const PendingVerifiedHistoricalChainLock> empty;
    if (m_pending_verified_historical.compare_exchange_strong(
            empty, desired)) {
        return true;
    }
    return empty && empty->logical_id == logical_id &&
           empty->witness_id == witness_id;
}

void CChainLocksHandler::ContinueVerifiedHistoricalChainLock()
{
    const auto pending{GetPendingVerifiedHistoricalChainLock()};
    if (!pending) return;

    BlockValidationState state;
    bool retain{false};
    const bool accepted{ProcessNewChainLockInternal(
        /*from=*/-1, pending->chainlock, state,
        /*peer_fault=*/nullptr, /*local_finalization=*/nullptr,
        pending.get(), &retain)};
    if (accepted || !retain) {
        auto expected{pending};
        (void)m_pending_verified_historical.compare_exchange_strong(
            expected, {});
    }
    if (!accepted && !retain) {
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s dropped stale verified historical "
                 "certificate %s: %s\n",
                 __func__, pending->witness_id.ToString(),
                 state.ToString());
    }
}

bool CChainLocksHandler::HasExactLiveSigningTargetEndpoint(
    const CBlockIndex& target)
{
    AssertLockHeld(cs_main);
    constexpr uint32_t target_provenance{
        BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_PQ_RECEIPT_INDEX_VALIDATED};
    return target.nHeight >= 0 &&
           (target.nStatus & BLOCK_HAVE_DATA) &&
           !(target.nStatus & BLOCK_FAILED_MASK) &&
           !target.IsAssumedValid() &&
           target.IsValid(BLOCK_VALID_SCRIPTS) &&
           (target.nStatus & target_provenance) == target_provenance &&
           (!CSuperblock::IsValidBlockHeight(target.nHeight) ||
            (target.nStatus & BLOCK_GOVERNANCE_VALIDATED));
}

bool CChainLocksHandler::AdvanceLiveSigningValidationFrontier(
    LiveSigningValidationFrontier& frontier,
    const CChain& active_chain,
    const CBlockIndex& target,
    const pq::ChainLockPredecessor& durable_predecessor,
    const pq::ChainLockFinalityStoreConfig& config,
    const uint256& genesis_hash,
    uint64_t provenance_revocation_revision,
    const std::function<BTCCReceiptCertificateStatus(
        const pq::BTCCReceipt&, const CBlockIndex&)>&
        certificate_status,
    uint64_t& examined_blocks,
    std::size_t block_budget)
{
    AssertLockHeld(cs_main);
    if (!config.IsValid() || genesis_hash.IsNull() ||
        durable_predecessor.height < 0 ||
        durable_predecessor.height >= target.nHeight ||
        durable_predecessor.block_hash.IsNull() ||
        !durable_predecessor.btcc_cursor.IsStructurallyValid()) {
        return false;
    }
    const CBlockIndex* active_floor{
        active_chain[durable_predecessor.height]};
    const CBlockIndex* active_target{active_chain[target.nHeight]};
    if (active_floor == nullptr ||
        active_floor->GetBlockHash() !=
            durable_predecessor.block_hash ||
        active_target != &target) {
        return false;
    }

    const auto reset_to_floor = [&] {
        frontier.initialized = true;
        frontier.provenance_revocation_revision =
            provenance_revocation_revision;
        frontier.durable_predecessor = durable_predecessor;
        frontier.validated_through_height =
            durable_predecessor.height;
        frontier.validated_through_hash =
            durable_predecessor.block_hash;
    };
    if (!frontier.initialized) {
        reset_to_floor();
    } else {
        const bool shape_valid{
            frontier.durable_predecessor.height >= 0 &&
            frontier.validated_through_height >=
                frontier.durable_predecessor.height &&
            !frontier.durable_predecessor.block_hash.IsNull() &&
            !frontier.validated_through_hash.IsNull()};
        const CBlockIndex* active_through{
            shape_valid
                ? active_chain[frontier.validated_through_height]
                : nullptr};
        const bool through_current{
            active_through != nullptr &&
            active_through->GetBlockHash() ==
                frontier.validated_through_hash};
        const bool exact_floor{
            frontier.durable_predecessor == durable_predecessor};
        const bool same_branch_floor_advance{
            shape_valid && through_current &&
            durable_predecessor.height >
                frontier.durable_predecessor.height &&
            active_chain[frontier.durable_predecessor.height] != nullptr &&
            active_chain[frontier.durable_predecessor.height]
                    ->GetBlockHash() ==
                frontier.durable_predecessor.block_hash};
        if (!shape_valid || !through_current ||
            frontier.provenance_revocation_revision !=
                provenance_revocation_revision ||
            target.nHeight < frontier.validated_through_height ||
            (!exact_floor && !same_branch_floor_advance)) {
            reset_to_floor();
        } else if (same_branch_floor_advance) {
            frontier.durable_predecessor = durable_predecessor;
            if (frontier.validated_through_height <
                durable_predecessor.height) {
                frontier.validated_through_height =
                    durable_predecessor.height;
                frontier.validated_through_hash =
                    durable_predecessor.block_hash;
            }
        }
    }

    std::size_t examined_this_call{0};
    for (int32_t height{frontier.validated_through_height + 1};
         height <= target.nHeight; ++height) {
        if (examined_this_call == block_budget) return false;
        ++examined_this_call;
        if (examined_blocks != std::numeric_limits<uint64_t>::max()) {
            ++examined_blocks;
        }
        const CBlockIndex* index{active_chain[height]};
        if (index == nullptr || index->nHeight != height ||
            (index->nStatus & BLOCK_FAILED_MASK) ||
            index->IsAssumedValid() ||
            !index->IsValid(BLOCK_VALID_SCRIPTS) ||
            !HasFullReceiptIndexProvenance(*index) ||
            (CSuperblock::IsValidBlockHeight(height) &&
             !(index->nStatus & BLOCK_GOVERNANCE_VALIDATED))) {
            return false;
        }

        if (pq::IsBTCCReceiptCarrierHeight(config.btcc_schedule,
                                           height)) {
            if (index->pprev == nullptr) return false;
            const auto previous_state{
                IndexedBTCCReceiptState(*index->pprev)};
            const auto current_state{IndexedBTCCReceiptState(*index)};
            const auto receipt{
                previous_state && current_state
                    ? pq::ReconstructBTCCReceipt(
                          genesis_hash, config.chainlock_schedule,
                          config.btcc_schedule, *index,
                          *previous_state, *current_state,
                          index->pqBTCCReceiptLogicalId)
                    : std::optional<pq::BTCCReceipt>{}};
            if (!receipt ||
                (!receipt->IsNull() &&
                 (!certificate_status ||
                  certificate_status(*receipt, *index) !=
                      BTCCReceiptCertificateStatus::VERIFIED))) {
                return false;
            }
        }

        frontier.validated_through_height = height;
        frontier.validated_through_hash = index->GetBlockHash();
    }
    return frontier.validated_through_height == target.nHeight &&
           frontier.validated_through_hash == target.GetBlockHash();
}

bool CChainLocksHandler::IsLiveSigningValidationRevisionCurrent(
    const CurrentSigningSource& source,
    uint64_t provenance_revocation_revision) noexcept
{
    return source.provenance_revocation_revision ==
           provenance_revocation_revision;
}

std::optional<pq::ChainLockSigningWindow>
CChainLocksHandler::OutageRecoverySigningWindow(
    const pq::ChainLockScheduleConfig& chainlock,
    const pq::BTCCScheduleConfig& btcc,
    uint32_t durable_authorization_epoch,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept
{
    const auto latest_window{pq::CurrentChainLockSigningWindow(
        chainlock, durable_predecessor_height, tip_height)};
    const auto latest_epoch{latest_window
        ? pq::EpochForHeight(chainlock, latest_window->target_height)
        : std::optional<uint32_t>{}};
    if (!latest_window || !latest_epoch ||
        durable_authorization_epoch > *latest_epoch ||
        static_cast<uint64_t>(*latest_epoch) -
                durable_authorization_epoch <=
            1) {
        return std::nullopt;
    }
    const auto recovery_epoch{LatestRosterRecoveryEpoch(*latest_epoch)};
    const auto canonical{recovery_epoch
        ? pq::CanonicalRosterRecoveryTargetHeight(
              chainlock, btcc, *recovery_epoch)
        : std::optional<int32_t>{}};
    if (!canonical || latest_window->target_height < *canonical) {
        return std::nullopt;
    }
    return RecoverySigningWindowForTarget(
        chainlock, *canonical, durable_predecessor_height, tip_height);
}

std::optional<CChainLocksHandler::CurrentSigningContexts>
CChainLocksHandler::BuildCurrentSigningContexts(
    uint64_t admission_generation)
{
    if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
        !m_config || !m_quorum_build_config || !m_store ||
        !m_persistence || !m_payment_audit_store) {
        return std::nullopt;
    }

    uint64_t roster_source_generation{0};
    const auto roster_cache{
        GetQuorumRosterCache(&roster_source_generation)};
    if (!roster_cache) return std::nullopt;

    const pq::ChainLockFinalityStateObservation finality{
        m_store->ObserveState()};
    const pq::DurableFinalityStateView persistence{
        m_persistence->GetFinalityState()};
    if (persistence.best != finality.best) return std::nullopt;
    if (!m_payment_audit_store->IsHealthy()) return std::nullopt;
    const auto payment_audit_checkpoint{
        m_payment_audit_store->GetPruneCheckpoint()};
    if (!m_payment_audit_store->IsHealthy()) return std::nullopt;
    const auto staged_recovery{
        m_persistence->LoadRosterRecoveryPrecommit()};
    if (staged_recovery && finality.best) return std::nullopt;
    if (!staged_recovery &&
        !RequestActiveMasternodeRecoveryChildKeyTrees(
            m_genesis_hash, {})) {
        return std::nullopt;
    }

    uint256 payment_audit_preseal_token;
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_preseal_token = PaymentAuditPresealStateToken(
            m_payment_audit_preseal_state);
    }

    pq::ChainLockPredecessor durable_predecessor;
    CurrentChainLockBTCCSelection btcc;
    CurrentSigningSource source;
    std::optional<uint32_t> target_epoch;
    bool reset_path{false};
    bool staged_pending_target_mismatch{false};
    pq::RecoveryRosterAuthorityPtr recovery_authority;
    pq::RecoveryRosterAuthoritySource recovery_authority_source;
    uint256 recovery_authority_hash;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive() ||
            (m_chainman.IsSnapshotActive() &&
             !m_chainman.IsSnapshotValidated())) {
            return std::nullopt;
        }
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const CChain& active_chain{m_chainman.ActiveChain()};
        if (finality.best) {
            durable_predecessor = pq::ChainLockPredecessor{
                finality.best->statement.height,
                finality.best->statement.block_hash,
                finality.best->statement.accepted_btcc_cursor};
        } else {
            const CBlockIndex* activation_predecessor{
                active_chain[m_config->activation_predecessor_height]};
            if (activation_predecessor == nullptr) return std::nullopt;
            durable_predecessor = pq::ChainLockPredecessor{
                m_config->activation_predecessor_height,
                activation_predecessor->GetBlockHash(), {}};
        }
        if (tip == nullptr) return std::nullopt;
        const auto latest_window{pq::CurrentChainLockSigningWindow(
            m_config->chainlock_schedule,
            durable_predecessor.height, tip->nHeight)};
        if (!latest_window) return std::nullopt;
        const auto latest_epoch{pq::EpochForHeight(
            m_config->chainlock_schedule,
            latest_window->target_height)};
        if (!latest_epoch) return std::nullopt;
        const bool continuous_at_latest{
            finality.best &&
            finality.best->statement.roster_beacons.active.seeds.back()
                    .epoch <= *latest_epoch &&
            static_cast<uint64_t>(*latest_epoch) -
                    finality.best->statement.roster_beacons.active.seeds
                        .back()
                        .epoch <=
                1};
        std::optional<pq::ChainLockSigningWindow> window;
        if (staged_recovery) {
            if (finality.best) {
                return std::nullopt;
            }
            window = StagedRecoverySigningWindow(
                m_config->chainlock_schedule,
                m_config->btcc_schedule, *staged_recovery,
                durable_predecessor.height, tip->nHeight);
            reset_path = true;
        } else if (continuous_at_latest) {
            window = latest_window;
        } else if (!finality.best) {
            const auto initial_target{
                pq::NextEligibleChainLockTargetHeight(
                    m_config->chainlock_schedule,
                    m_config->activation_predecessor_height)};
            const auto initial_epoch{initial_target
                ? pq::EpochForHeight(
                      m_config->chainlock_schedule, *initial_target)
                : std::optional<uint32_t>{}};
            const auto canonical{initial_epoch
                ? pq::CanonicalRosterRecoveryTargetHeight(
                      m_config->chainlock_schedule,
                      m_config->btcc_schedule, *initial_epoch)
                : std::optional<int32_t>{}};
            if (!initial_target || !canonical ||
                *canonical != *initial_target) {
                return std::nullopt;
            }
            window = RecoverySigningWindowForTarget(
                m_config->chainlock_schedule, *initial_target,
                durable_predecessor.height, tip->nHeight);
            reset_path = true;
        } else {
            window = OutageRecoverySigningWindow(
                m_config->chainlock_schedule, m_config->btcc_schedule,
                finality.best->statement.roster_beacons.active.seeds.back()
                    .epoch,
                durable_predecessor.height, tip->nHeight);
            reset_path = true;
        }
        if (!window) return std::nullopt;
        const CBlockIndex* indexed_target{
            active_chain[window->target_height]};
        const CBlockIndex* declared_predecessor{
            active_chain[window->declared_predecessor_height]};
        if (indexed_target == nullptr || declared_predecessor == nullptr) {
            return std::nullopt;
        }
        if (staged_recovery &&
            (staged_recovery->pending_seed.anchor_cursor.sys_height !=
                 indexed_target->nHeight ||
             staged_recovery->pending_seed.anchor_cursor.sys_hash !=
                 indexed_target->GetBlockHash() ||
             staged_recovery->pending_seed.anchor_cursor.btc_hash !=
                 indexed_target->btcpPrevCommitment)) {
            if (staged_recovery->pending_seed.state !=
                    pq::RosterBeaconState::PENDING ||
                staged_recovery->pending_seed.anchor_cursor.sys_height !=
                    indexed_target->nHeight) {
                return std::nullopt;
            }
            staged_pending_target_mismatch = true;
        }
        if (durable_predecessor.height >= 0) {
            const CBlockIndex* predecessor_index{
                active_chain[durable_predecessor.height]};
            if (predecessor_index == nullptr ||
                predecessor_index->GetBlockHash() !=
                    durable_predecessor.block_hash) {
                return std::nullopt;
            }
        } else if (!durable_predecessor.block_hash.IsNull()) {
            return std::nullopt;
        }
        const uint64_t provenance_revocation_revision{
            m_chainman.GetPQProvenanceRevocationRevision()};
        const uint256 live_source_token{LiveBTCCCertificateSourceToken(
            provenance_revocation_revision, durable_predecessor,
            indexed_target->nHeight, indexed_target->GetBlockHash())};
        const auto certificate_status = [this, live_source_token](
            const pq::BTCCReceipt& receipt,
            const CBlockIndex& carrier)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            const auto status{
                CheckBTCCReceiptCertificate(receipt, carrier)};
            if (status == BTCCReceiptCertificateStatus::VERIFIED) {
                ClearNeededBTCCCertificate(
                    receipt.chainlock_logical_id);
            } else if (status ==
                       BTCCReceiptCertificateStatus::MISSING) {
                NoteNeededBTCCCertificate(
                    NeededBTCCCertificateSource::LIVE_FRONTIER,
                    receipt.chainlock_logical_id, live_source_token);
            }
            return status;
        };
        if (!AdvanceLiveSigningValidationFrontier(
                m_live_signing_validation_frontier, active_chain,
                *indexed_target, durable_predecessor, *m_config,
                m_genesis_hash, provenance_revocation_revision,
                certificate_status,
                m_live_signing_validation_examined_blocks)) {
            return std::nullopt;
        }
        ClearNeededBTCCCertificate(
            NeededBTCCCertificateSource::LIVE_FRONTIER,
            live_source_token);
        if (!HasExactLiveSigningTargetEndpoint(*indexed_target)) {
            return std::nullopt;
        }
        const auto selected{SelectCurrentChainLockBTCC(
            m_genesis_hash, *m_config, *indexed_target,
            finality.best ? &*finality.best : nullptr)};
        if (!selected) return std::nullopt;
        btcc = *selected;
        const auto indexed_receipt_state{
            IndexedBTCCReceiptState(*indexed_target)};
        if (!indexed_receipt_state) return std::nullopt;
        const auto indexed_payment_audit_state{
            IndexedPaymentAuditReceiptState(*indexed_target)};
        if (!indexed_payment_audit_state ||
            indexed_target->pqPaymentProbationStateHash.IsNull()) {
            return std::nullopt;
        }
        target_epoch = pq::EpochForHeight(
            m_config->chainlock_schedule, indexed_target->nHeight);
        if (!target_epoch) return std::nullopt;

        source.admission_generation = admission_generation;
        source.finality_store_revision = finality.state_revision;
        source.roster_source_generation = roster_source_generation;
        source.persistence_certificate_revision =
            persistence.certificate_revision;
        source.provenance_revocation_revision =
            provenance_revocation_revision;
        const uint256 recovery_token{staged_recovery
            ? RosterRecoveryPrecommitToken(
                  m_genesis_hash, *staged_recovery)
            : uint256{}};
        if (staged_recovery && recovery_token.IsNull()) {
            return std::nullopt;
        }
        source.mutable_signing_context_token =
            MutableSigningContextToken(
                PaymentAuditCheckpointToken(payment_audit_checkpoint),
                recovery_token);
        source.staged_recovery = staged_recovery.has_value();
        source.durable_predecessor = durable_predecessor;
        source.window = *window;
        source.target_hash = indexed_target->GetBlockHash();
        source.declared_predecessor_hash =
            declared_predecessor->GetBlockHash();
        source.payment_audit_preseal_token =
            payment_audit_preseal_token;
        source.btcc_receipt_state = *indexed_receipt_state;
        source.payment_audit_receipt_state =
            *indexed_payment_audit_state;
        source.payment_probation_state_hash =
            indexed_target->pqPaymentProbationStateHash;
        source.has_durable_chainlock = finality.best.has_value();
        source.outage_recovery = finality.best.has_value() && reset_path;
    }

    const auto resolve_recovery_state = [&]() {
        pq::RecoveryRosterAuthoritySource desired_source;
        uint256 committed_hash;
        if (finality.best) {
            const auto& prior_window{
                finality.best->statement.roster_beacons};
            desired_source =
                prior_window.active.recovery_authority_source;
            committed_hash =
                prior_window.active.recovery_authority_hash;
            if (!reset_path &&
                !pq::HasRecoveryRosterBeacon(prior_window)) {
                const auto* newest_normal{
                    pq::FindNewestNormalReadySeed(prior_window)};
                if (newest_normal == nullptr) return false;
                pq::RecoveryRosterAuthoritySource refreshed;
                refreshed.normal_beacon = *newest_normal;
                if (refreshed != desired_source) {
                    desired_source = std::move(refreshed);
                    committed_hash.SetNull();
                }
            }
        } else {
            if (!staged_recovery ||
                !staged_recovery->pending_seed.IsReady()) {
                return true;
            }
            desired_source.normal_beacon =
                staged_recovery->pending_seed;
        }
        if (!desired_source.IsStructurallyValid() ||
            desired_source.IsNull()) {
            return false;
        }

        const auto persisted{
            m_persistence->LoadRecoveryRosterAuthority()};
        if (persisted &&
            persisted->normal_beacon == desired_source.normal_beacon) {
            const auto hash{pq::GetRecoveryRosterAuthorityHash(
                m_genesis_hash, *persisted)};
            if (!hash ||
                (!committed_hash.IsNull() && *hash != committed_hash)) {
                return false;
            }
            recovery_authority = persisted;
            recovery_authority_source = std::move(desired_source);
            recovery_authority_hash = *hash;
            return true;
        }

        const CBlockIndex* target{nullptr};
        {
            LOCK(cs_main);
            target = m_chainman.m_blockman.LookupBlockIndex(
                source.target_hash);
            if (target == nullptr ||
                target->nHeight != source.window.target_height) {
                return false;
            }
        }
        auto authority{DeriveRecoveryRosterAuthority(
            *target, desired_source, roster_cache)};
        const auto hash{authority
            ? pq::GetRecoveryRosterAuthorityHash(
                  m_genesis_hash, *authority)
            : std::optional<uint256>{}};
        if (!hash ||
            (!committed_hash.IsNull() && *hash != committed_hash)) {
            return false;
        }
        recovery_authority = std::move(authority);
        recovery_authority_source = std::move(desired_source);
        recovery_authority_hash = *hash;
        return true;
    };
    if (!resolve_recovery_state()) return std::nullopt;

    CurrentSigningContexts contexts;
    contexts.source = std::move(source);
    std::array<pq::RosterAuthorizationVerificationContext,
               CurrentSigningContexts::MAX_VARIANTS> authorizations;
    for (auto& authorization : authorizations) {
        authorization.reset_policy =
            MakeRosterResetVerificationPolicy(*m_config);
    }
    const auto make_statement = [&](const pq::BTCCursor& accepted,
                                    pq::BTCCAdvance advance) {
        pq::ChainLockStatement statement;
        statement.height = contexts.source.window.target_height;
        statement.block_hash = contexts.source.target_hash;
        statement.previous_chainlock_height =
            contexts.source.window.declared_predecessor_height;
        statement.previous_chainlock_hash =
            contexts.source.declared_predecessor_hash;
        statement.previous_btcc_cursor = btcc.previous_cursor;
        statement.accepted_btcc_cursor = accepted;
        statement.btcc_advance = advance;
        statement.btcc_receipt_state = contexts.source.btcc_receipt_state;
        statement.payment_audit_receipt_state =
            contexts.source.payment_audit_receipt_state;
        statement.payment_probation_state_hash =
            contexts.source.payment_probation_state_hash;
        if (!recovery_authority_source.IsNull()) {
            statement.roster_beacons.active
                .recovery_authority_source =
                recovery_authority_source;
            statement.roster_beacons.active
                .recovery_authority_hash =
                recovery_authority_hash;
        }
        return statement;
    };

    const auto append_normal = [&](pq::ChainLockStatement statement) {
        if (!finality.best ||
            contexts.count >= CurrentSigningContexts::MAX_VARIANTS) {
            return false;
        }
        statement.roster_authorization_base =
            finality.best->AuthorizationBase();
        const auto& previous_window{
            finality.best->statement.roster_beacons};
        const uint32_t previous_epoch{
            previous_window.active.seeds.back().epoch};
        pq::RosterAuthorizationTransitionKind requested{
            pq::RosterAuthorizationTransitionKind::KEEP};
        if (previous_epoch != *target_epoch) {
            requested = pq::RosterAuthorizationTransitionKind::ROTATE;
        } else if (previous_window.next.state ==
                   pq::RosterBeaconState::PENDING) {
            requested = pq::RosterAuthorizationTransitionKind::REVEAL;
        } else if (previous_window.next.state ==
                       pq::RosterBeaconState::EMPTY &&
                   statement.btcc_advance == pq::BTCCAdvance::ADVANCE) {
            requested = pq::RosterAuthorizationTransitionKind::OBSERVE;
        }

        auto input{BuildNormalRosterAuthorizationInput(
            statement, *finality.best, requested,
            RosterBeaconEvidence::SIGNER_POLICY)};
        auto decision{input
            ? pq::DeriveNormalRosterAuthorizationDecision(
                  m_genesis_hash, *input)
            : std::optional<pq::NormalRosterAuthorizationDecision>{}};
        if ((!decision || decision->transition.kind != requested) &&
            requested ==
                pq::RosterAuthorizationTransitionKind::REVEAL) {
            requested = pq::RosterAuthorizationTransitionKind::KEEP;
            input = BuildNormalRosterAuthorizationInput(
                statement, *finality.best, requested,
                RosterBeaconEvidence::SIGNER_POLICY);
            decision = input
                ? pq::DeriveNormalRosterAuthorizationDecision(
                      m_genesis_hash, *input)
                : std::optional<
                      pq::NormalRosterAuthorizationDecision>{};
        }
        if (!input || !decision) return false;
        statement.roster_transition = decision->transition.kind;
        statement.roster_beacons = decision->transition.new_window;
        statement.roster_authorization_state_hash =
            decision->state_hash;

        auto& authorization{authorizations[contexts.count]};
        authorization.admission =
            pq::RosterAuthorizationAdmission::LIVE;
        authorization.predecessor_height =
            statement.previous_chainlock_height;
        authorization.predecessor_block_hash =
            statement.previous_chainlock_hash;
        authorization.authorization_base =
            statement.roster_authorization_base;
        authorization.previous = input->previous;
        authorization.normal_input = std::move(*input);
        contexts.statements[contexts.count++] = std::move(statement);
        return true;
    };

    if (!reset_path) {
        (void)append_normal(make_statement(btcc.selected.cursor,
                                           btcc.selected.advance));
    }

    const bool allow_keep_variant{
        btcc.selected.advance == pq::BTCCAdvance::ADVANCE &&
        (pq::IsDurableBTCCursorMonotonic(
             durable_predecessor.btcc_cursor,
             btcc.previous_cursor) ||
         btcc.cursor_reconciliation.has_value())};
    if (!reset_path && allow_keep_variant) {
        (void)append_normal(make_statement(
            btcc.previous_cursor, pq::BTCCAdvance::KEEP));
    }

    if (reset_path) {
        const CBlockIndex* recovery_target{nullptr};
        {
            LOCK(cs_main);
            recovery_target = m_chainman.m_blockman.LookupBlockIndex(
                contexts.source.target_hash);
            if (recovery_target == nullptr ||
                recovery_target->nHeight !=
                    contexts.source.window.target_height) {
                return std::nullopt;
            }
        }
        if (*target_epoch < pq::ACTIVE_QUORUMS - 1 ||
            *target_epoch % pq::ACTIVE_QUORUMS !=
                pq::ACTIVE_QUORUMS - 1) {
            return std::nullopt;
        }
        const bool outage_recovery{finality.best.has_value()};
        if (outage_recovery) {
            if (staged_recovery || !recovery_authority ||
                recovery_authority_source.IsNull() ||
                recovery_authority_hash.IsNull()) {
                return std::nullopt;
            }
            const auto reset_window{pq::MakeRecoveryRosterBeaconWindow(
                recovery_authority_source,
                recovery_authority_hash,
                *target_epoch)};
            if (!reset_window) return std::nullopt;

            pq::RosterAuthorizationTransition transition;
            transition.kind =
                pq::RosterAuthorizationTransitionKind::RECOVER;
            transition.target_height =
                contexts.source.window.target_height;
            transition.target_block_hash = contexts.source.target_hash;
            transition.predecessor_height =
                contexts.source.window.declared_predecessor_height;
            transition.predecessor_block_hash =
                contexts.source.declared_predecessor_hash;
            transition.authorization_base =
                finality.best->AuthorizationBase();
            transition.previous = pq::RosterAuthorizationPriorState{
                finality.best->statement
                    .roster_authorization_state_hash,
                finality.best->statement.roster_beacons};
            transition.new_window = *reset_window;
            const auto state_hash{pq::GetRosterAuthorizationStateHash(
                m_genesis_hash, transition)};
            if (!state_hash) return std::nullopt;

            auto statement{make_statement(
                btcc.previous_cursor, pq::BTCCAdvance::KEEP)};
            statement.roster_transition = transition.kind;
            statement.roster_beacons = transition.new_window;
            statement.roster_authorization_state_hash = *state_hash;
            statement.roster_authorization_base =
                transition.authorization_base;
            auto& authorization{authorizations[contexts.count]};
            authorization.admission =
                pq::RosterAuthorizationAdmission::RECOVER;
            authorization.predecessor_height =
                statement.previous_chainlock_height;
            authorization.predecessor_block_hash =
                statement.previous_chainlock_hash;
            authorization.authorization_base =
                statement.roster_authorization_base;
            authorization.previous = transition.previous;
            contexts.statements[contexts.count++] =
                std::move(statement);
        } else {
        if (!staged_recovery) {
            const pq::BTCCursor anchor_cursor{btcc.selected.cursor};
            if (btcc.selected.advance != pq::BTCCAdvance::ADVANCE ||
                anchor_cursor.IsNull() ||
                anchor_cursor.sys_height !=
                    contexts.source.window.target_height ||
                anchor_cursor.sys_hash != contexts.source.target_hash) {
                return std::nullopt;
            }
            std::string reason;
            if (!pq::IsBTCHeaderPolicyEnabled() ||
                !m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
                    /*recover=*/true, reason)) {
                return std::nullopt;
            }
            auto btc_config{pq::GetConfiguredBTCHeaderPolicy(reason)};
            if (!btc_config) return std::nullopt;
            btc_config->max_lag_blocks =
                pq::ROSTER_BEACON_MAX_ANCHOR_BTC_LAG;
            std::optional<uint256> previous_btc_hash;
            if (!durable_predecessor.btcc_cursor.IsNull()) {
                previous_btc_hash =
                    durable_predecessor.btcc_cursor.btc_hash;
            }
            const auto anchor{btc_config->IsValid()
                ? pq::MakeConfiguredBTCHeaderPolicy().CheckCandidate(
                      *btc_config, anchor_cursor.btc_hash,
                      previous_btc_hash,
                      GetTime(), reason)
                : std::optional<pq::BTCHeaderPolicyResult>{}};
            if (!anchor || anchor->btc_hash != anchor_cursor.btc_hash ||
                anchor->btc_height < 0) {
                return std::nullopt;
            }
            pq::RosterBeaconSeed pending;
            pending.anchor_kind = pq::RosterBeaconAnchorKind::NORMAL;
            pending.state = pq::RosterBeaconState::PENDING;
            pending.epoch = *target_epoch;
            pending.anchor_cursor = anchor_cursor;
            pending.anchor_btc_height = anchor->btc_height;
            pq::RosterRecoveryPrecommit precommit;
            precommit.pending_seed = std::move(pending);
            const bool persisted{
                m_persistence->PersistRosterRecoveryPrecommit(precommit)};
            if (!persisted) {
                return std::nullopt;
            }
            (void)RequestActiveMasternodeRecoveryChildKeyTrees(
                m_genesis_hash, {});
            return std::nullopt;
        }
        const auto& staged{*staged_recovery};
        if (staged_pending_target_mismatch) {
            const pq::BTCCursor replacement_cursor{btcc.selected.cursor};
            if (staged.pending_seed.state !=
                    pq::RosterBeaconState::PENDING ||
                btcc.selected.advance != pq::BTCCAdvance::ADVANCE ||
                replacement_cursor.IsNull() ||
                replacement_cursor.sys_height !=
                    contexts.source.window.target_height ||
                replacement_cursor.sys_hash != contexts.source.target_hash) {
                return std::nullopt;
            }

            std::string reason;
            if (!pq::IsBTCHeaderPolicyEnabled() ||
                !m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
                    /*recover=*/true, reason)) {
                return std::nullopt;
            }
            auto btc_config{pq::GetConfiguredBTCHeaderPolicy(reason)};
            if (!btc_config) return std::nullopt;
            btc_config->max_lag_blocks =
                pq::ROSTER_BEACON_MAX_ANCHOR_BTC_LAG;
            std::optional<uint256> previous_btc_hash;
            if (!durable_predecessor.btcc_cursor.IsNull()) {
                previous_btc_hash =
                    durable_predecessor.btcc_cursor.btc_hash;
            }
            auto replacement{staged};
            replacement.pending_seed.epoch = *target_epoch;
            replacement.pending_seed.anchor_cursor = replacement_cursor;
            const auto anchor{btc_config->IsValid()
                ? pq::MakeConfiguredBTCHeaderPolicy().CheckCandidate(
                      *btc_config, replacement_cursor.btc_hash,
                      previous_btc_hash, GetTime(), reason)
                : std::optional<pq::BTCHeaderPolicyResult>{}};
            if (!anchor ||
                anchor->btc_hash != replacement_cursor.btc_hash ||
                anchor->btc_height < 0) {
                return std::nullopt;
            }

            replacement.pending_seed.anchor_btc_height =
                anchor->btc_height;
            const bool replaced{
                m_chainman.ActiveChainstate().RunWithStableActiveChain(
                    [&] {
                        {
                            LOCK(cs_main);
                            const CBlockIndex* active_target{
                                m_chainman.ActiveChain()[
                                    replacement_cursor.sys_height]};
                            if (active_target == nullptr ||
                                active_target->GetBlockHash() !=
                                    replacement_cursor.sys_hash ||
                                active_target->btcpPrevCommitment !=
                                    replacement_cursor.btc_hash) {
                                return false;
                            }
                        }
                        return m_persistence
                            ->ReplaceRosterRecoveryPrecommit(
                                staged, replacement);
                    })};
            if (!replaced) return std::nullopt;
            (void)RequestActiveMasternodeRecoveryChildKeyTrees(
                m_genesis_hash, {});
            // Rebuild from the newly fsynced source generation before any
            // one-time signing leaf can be consumed.
            return std::nullopt;
        }
        if (staged.pending_seed.epoch != *target_epoch ||
            btcc.selected.advance != pq::BTCCAdvance::ADVANCE ||
            btcc.selected.cursor != staged.pending_seed.anchor_cursor) {
            return std::nullopt;
        }
        {
            LOCK(cs_main);
            const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
                contexts.source.target_hash)};
            if (target == nullptr ||
                target->nHeight != contexts.source.window.target_height ||
                target->nHeight !=
                    staged.pending_seed.anchor_cursor.sys_height ||
                target->GetBlockHash() !=
                    staged.pending_seed.anchor_cursor.sys_hash ||
                target->btcpPrevCommitment !=
                    staged.pending_seed.anchor_cursor.btc_hash) {
                return std::nullopt;
            }
        }
        std::string reason;
        if (!pq::IsBTCHeaderPolicyEnabled() ||
            !m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
                /*recover=*/true, reason)) {
            return std::nullopt;
        }
        const auto btc_config{pq::GetConfiguredBTCHeaderPolicy(reason)};
        const auto range{btc_config
            ? pq::MakeConfiguredBTCHeaderPolicy()
                  .CheckPaymentAuditActiveRange(
                      *btc_config,
                      staged.pending_seed.anchor_cursor.btc_hash,
                      GetTime(), reason)
            : std::optional<pq::BTCHeaderActiveRange>{}};
        const auto future_height{staged.pending_seed.FutureBTCHeight()};
        if (!range || !future_height ||
            range->anchor_hash !=
                staged.pending_seed.anchor_cursor.btc_hash ||
            range->anchor_height != staged.pending_seed.anchor_btc_height ||
            range->future_height != *future_height ||
            range->future_hash.IsNull()) {
            return std::nullopt;
        }

        if (staged.pending_seed.state ==
            pq::RosterBeaconState::PENDING) {
            auto resolved{staged};
            resolved.pending_seed.state = pq::RosterBeaconState::READY;
            resolved.pending_seed.future_btc_hash = range->future_hash;
            if (!DoesStagedRosterSeedAuthorizeReady(
                    staged.pending_seed, resolved.pending_seed)) {
                return std::nullopt;
            }
            const bool persisted_ready{
                m_chainman.ActiveChainstate().RunWithStableActiveChain(
                    [&] {
                        {
                            LOCK(cs_main);
                            const CBlockIndex* active_target{
                                m_chainman.ActiveChain()[
                                    staged.pending_seed.anchor_cursor
                                        .sys_height]};
                            if (active_target == nullptr ||
                                active_target->GetBlockHash() !=
                                    staged.pending_seed.anchor_cursor
                                        .sys_hash ||
                                active_target->btcpPrevCommitment !=
                                    staged.pending_seed.anchor_cursor
                                        .btc_hash) {
                                return false;
                            }
                        }
                        return m_persistence
                            ->PersistRosterRecoveryPrecommit(resolved);
                    })};
            if (!persisted_ready) return std::nullopt;
            // The READY hash must be a distinct fsynced source generation.
            // A later pass rebuilds every roster and source token from it
            // before any one-time leaf can be consumed.
            return std::nullopt;
        }
        if (!staged.pending_seed.IsReady() ||
            staged.pending_seed.future_btc_hash != range->future_hash) {
            return std::nullopt;
        }
        if (!recovery_authority || recovery_authority_source.IsNull() ||
            recovery_authority_hash.IsNull()) {
            return std::nullopt;
        }

        pq::RosterBeaconWindow reset_window;
        const uint32_t oldest_epoch{
            *target_epoch - static_cast<uint32_t>(
                                pq::ACTIVE_QUORUMS - 1)};
        for (std::size_t slot{0}; slot < pq::ACTIVE_QUORUMS; ++slot) {
            auto seed{staged.pending_seed};
            seed.epoch = oldest_epoch + static_cast<uint32_t>(slot);
            reset_window.active.seeds[slot] = std::move(seed);
        }
        reset_window.active.recovery_authority_source =
            recovery_authority_source;
        reset_window.active.recovery_authority_hash =
            recovery_authority_hash;
        reset_window.next.epoch = *target_epoch + 1;
        if (!pq::IsInitialNormalRosterBeaconWindow(reset_window)) {
            return std::nullopt;
        }
        pq::RosterAuthorizationTransition transition;
        transition.kind =
            pq::RosterAuthorizationTransitionKind::INITIALIZE;
        transition.target_height = contexts.source.window.target_height;
        transition.target_block_hash = contexts.source.target_hash;
        transition.predecessor_height =
            contexts.source.window.declared_predecessor_height;
        transition.predecessor_block_hash =
            contexts.source.declared_predecessor_hash;
        transition.new_window = reset_window;
        const auto state_hash{pq::GetRosterAuthorizationStateHash(
            m_genesis_hash, transition)};
        if (!state_hash) return std::nullopt;

        const auto append_reset = [&](pq::ChainLockStatement statement) {
            if (contexts.count >= CurrentSigningContexts::MAX_VARIANTS) {
                return false;
            }
            statement.roster_transition = transition.kind;
            statement.roster_beacons = transition.new_window;
            statement.roster_authorization_state_hash = *state_hash;
            statement.roster_authorization_base =
                transition.authorization_base;
            auto& authorization{authorizations[contexts.count]};
            authorization.admission =
                pq::RosterAuthorizationAdmission::INITIALIZE;
            authorization.predecessor_height =
                statement.previous_chainlock_height;
            authorization.predecessor_block_hash =
                statement.previous_chainlock_hash;
            authorization.authorization_base =
                statement.roster_authorization_base;
            contexts.statements[contexts.count++] =
                std::move(statement);
            return true;
        };
        (void)append_reset(make_statement(btcc.selected.cursor,
                                          btcc.selected.advance));
        }
    }

    if (contexts.count == 0) return std::nullopt;
    const auto& active_beacons{
        contexts.statements[0].roster_beacons.active};
    for (std::size_t i{1}; i < contexts.count; ++i) {
        if (contexts.statements[i].roster_beacons.active !=
            active_beacons) {
            return std::nullopt;
        }
    }
    if (!recovery_authority &&
        !active_beacons.recovery_authority_source.IsNull()) {
        recovery_authority =
            m_persistence->LoadRecoveryRosterAuthority();
        const auto authority_hash{recovery_authority
            ? pq::GetRecoveryRosterAuthorityHash(
                  m_genesis_hash, *recovery_authority)
            : std::optional<uint256>{}};
        if (!authority_hash ||
            *authority_hash != active_beacons.recovery_authority_hash) {
            return std::nullopt;
        }
    }
    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    {
        LOCK(cs_main);
        const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
            contexts.source.target_hash)};
        if (target == nullptr ||
            target->nHeight != contexts.source.window.target_height) {
            return std::nullopt;
        }
        contexts.roster_set = recovery_authority
            ? roster_cache->GetVerifiedActiveWithRecoveryAuthority(
                  target->nHeight, *target, active_beacons,
                  recovery_authority, /*publish=*/true, &build_error)
            : roster_cache->GetVerifiedActive(
                  target->nHeight, *target, active_beacons, &build_error);
    }
    if (!contexts.roster_set) return std::nullopt;
    std::vector<pq::FrozenChildRootRecord> reset_child_roots;
    if (reset_path) {
        uint256 local_pro_tx_hash;
        uint32_t local_key_version{0};
        pq::GlobalPublicKey local_global_key{};
        CService local_service;
        if (GetActiveMasternodeIdentity(
                local_pro_tx_hash, local_key_version,
                local_global_key, local_service)) {
            reset_child_roots.reserve(pq::ACTIVE_QUORUMS);
            for (const auto& roster : contexts.roster_set->Rosters()) {
                for (const auto& member : roster.members) {
                    if (member.pro_tx_hash == local_pro_tx_hash &&
                        member.eligible && member.child_root) {
                        reset_child_roots.push_back(*member.child_root);
                        break;
                    }
                }
            }
        }
    }
    if (!RequestActiveMasternodeRecoveryChildKeyTrees(
            m_genesis_hash, reset_child_roots)) {
        return std::nullopt;
    }
    const auto descriptors{Descriptors(contexts.roster_set->Rosters())};
    for (std::size_t i{0}; i < contexts.count; ++i) {
        auto& statement{contexts.statements[i]};
        statement.quorum_context_hash = pq::GetQuorumContextHash(
            m_genesis_hash, statement.height, statement.block_hash,
            descriptors);
        if (!statement.IsStructurallyValid()) return std::nullopt;
        pq::ChainLockVerificationError verification_error{
            pq::ChainLockVerificationError::NONE};
        contexts.prepared_contexts[i] =
            pq::PreparedChainLockContext::Create(
                m_config->chainlock_schedule, statement,
                contexts.roster_set, authorizations[i],
                &verification_error, recovery_authority);
        if (!contexts.prepared_contexts[i]) return std::nullopt;
    }
    if (!IsCurrentSigningSource(contexts.source)) return std::nullopt;
    return contexts;
}

bool CChainLocksHandler::IsCurrentSigningSource(
    const CurrentSigningSource& source) const
{
    if (!IsShareAdmissionGenerationCurrent(source.admission_generation) ||
        !m_config || !m_store || !m_persistence ||
        !m_payment_audit_store ||
        source.window.target_height < 0 || source.target_hash.IsNull()) {
        return false;
    }

    const auto finality{m_store->ObserveState()};
    const auto durable{m_persistence->GetFinalityState()};
    if (!m_payment_audit_store->IsHealthy()) return false;
    const auto payment_audit_checkpoint{
        m_payment_audit_store->GetPruneCheckpoint()};
    if (!m_payment_audit_store->IsHealthy()) return false;
    const auto recovery_precommit{
        m_persistence->LoadRosterRecoveryPrecommit()};
    const uint256 recovery_precommit_token{recovery_precommit
        ? RosterRecoveryPrecommitToken(
              m_genesis_hash, *recovery_precommit)
        : uint256{}};
    const uint256 mutable_signing_context_token{
        MutableSigningContextToken(
            PaymentAuditCheckpointToken(payment_audit_checkpoint),
            recovery_precommit_token)};
    uint256 payment_audit_preseal_token;
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_preseal_token = PaymentAuditPresealStateToken(
            m_payment_audit_preseal_state);
    }
    const bool predecessor_shape_valid{
        finality.best
            ? source.durable_predecessor == pq::ChainLockPredecessor{
                  finality.best->statement.height,
                  finality.best->statement.block_hash,
                  finality.best->statement.accepted_btcc_cursor}
            : source.durable_predecessor.height ==
                      m_config->activation_predecessor_height &&
                  !source.durable_predecessor.block_hash.IsNull() &&
                  source.durable_predecessor.btcc_cursor.IsNull()};
    if (finality.state_revision != source.finality_store_revision ||
        durable.certificate_revision !=
            source.persistence_certificate_revision ||
        durable.best != finality.best || !predecessor_shape_valid ||
        source.has_durable_chainlock != finality.best.has_value() ||
        (source.outage_recovery &&
         (source.staged_recovery || !source.has_durable_chainlock)) ||
        mutable_signing_context_token !=
            source.mutable_signing_context_token ||
        source.staged_recovery != recovery_precommit.has_value() ||
        payment_audit_preseal_token !=
            source.payment_audit_preseal_token ||
        !IsQuorumRosterSourceGenerationCurrent(
            source.roster_source_generation)) {
        return false;
    }

    const auto branch_is_current = [&]() {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const auto window = [&]() {
            if (tip == nullptr) {
                return std::optional<pq::ChainLockSigningWindow>{};
            }
            if (source.outage_recovery) {
                if (!finality.best || source.staged_recovery) {
                    return std::optional<pq::ChainLockSigningWindow>{};
                }
                return OutageRecoverySigningWindow(
                    m_config->chainlock_schedule,
                    m_config->btcc_schedule,
                    finality.best->statement.roster_beacons.active.seeds
                        .back()
                        .epoch,
                    source.durable_predecessor.height, tip->nHeight);
            }
            if (!source.staged_recovery) {
                return pq::CurrentChainLockSigningWindow(
                    m_config->chainlock_schedule,
                    source.durable_predecessor.height, tip->nHeight);
            }
            return recovery_precommit ? StagedRecoverySigningWindow(
                                            m_config->chainlock_schedule,
                                            m_config->btcc_schedule, *recovery_precommit,
                                            source.durable_predecessor.height, tip->nHeight) :
                                        std::optional<pq::ChainLockSigningWindow>{};
        }();
        const CChain& active_chain{m_chainman.ActiveChain()};
        const CBlockIndex* target{
            tip != nullptr && tip->nHeight >= source.window.target_height
                ? active_chain[source.window.target_height]
                : nullptr};
        const CBlockIndex* declared_predecessor{
            target == nullptr
                ? nullptr
                : active_chain[
                      source.window.declared_predecessor_height]};
        const CBlockIndex* durable_index{
            target != nullptr && source.durable_predecessor.height >= 0
                ? active_chain[source.durable_predecessor.height]
                : nullptr};
        const auto receipt_state{target == nullptr
            ? std::optional<pq::BTCCReceiptState>{}
            : IndexedBTCCReceiptState(*target)};
        const auto payment_audit_state{target == nullptr
            ? std::optional<pq::PaymentAuditReceiptState>{}
            : IndexedPaymentAuditReceiptState(*target)};
        const bool durable_branch{
            source.durable_predecessor.height >= 0
                ? durable_index != nullptr &&
                      durable_index->GetBlockHash() ==
                          source.durable_predecessor.block_hash
                : source.durable_predecessor.block_hash.IsNull()};
        return
            !(m_chainman.IsSnapshotActive() &&
              !m_chainman.IsSnapshotValidated()) &&
            !IsPaymentAuditPresealActive() &&
            IsLiveSigningValidationRevisionCurrent(
                source,
                m_chainman.GetPQProvenanceRevocationRevision()) &&
            window && *window == source.window && target != nullptr &&
            target->GetBlockHash() == source.target_hash &&
            declared_predecessor != nullptr &&
            declared_predecessor->GetBlockHash() ==
                source.declared_predecessor_hash &&
            durable_branch &&
            HasExactLiveSigningTargetEndpoint(*target) &&
            receipt_state &&
            *receipt_state == source.btcc_receipt_state &&
            payment_audit_state &&
            *payment_audit_state ==
                source.payment_audit_receipt_state &&
            target->pqPaymentProbationStateHash ==
                source.payment_probation_state_hash;
    };
    if (!branch_is_current()) return false;

    // These observations bracket the chain-index check. A source is usable
    // only when every independently synchronized input remained unchanged.
    const auto finality_after{m_store->ObserveState()};
    const auto durable_after{m_persistence->GetFinalityState()};
    if (!m_payment_audit_store->IsHealthy()) return false;
    const auto payment_audit_checkpoint_after{
        m_payment_audit_store->GetPruneCheckpoint()};
    const auto recovery_precommit_after{
        m_persistence->LoadRosterRecoveryPrecommit()};
    const uint256 recovery_precommit_token_after{
        recovery_precommit_after
            ? RosterRecoveryPrecommitToken(
                  m_genesis_hash, *recovery_precommit_after)
            : uint256{}};
    const uint256 mutable_signing_context_token_after{
        MutableSigningContextToken(
            PaymentAuditCheckpointToken(
                payment_audit_checkpoint_after),
            recovery_precommit_token_after)};
    uint256 payment_audit_preseal_after;
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_preseal_after = PaymentAuditPresealStateToken(
            m_payment_audit_preseal_state);
    }
    return IsShareAdmissionGenerationCurrent(source.admission_generation) &&
           finality_after == finality && durable_after == durable &&
           m_payment_audit_store->IsHealthy() &&
           payment_audit_checkpoint_after ==
               payment_audit_checkpoint &&
           mutable_signing_context_token_after ==
               mutable_signing_context_token &&
           payment_audit_preseal_after ==
               payment_audit_preseal_token &&
           IsQuorumRosterSourceGenerationCurrent(
               source.roster_source_generation);
}

bool CChainLocksHandler::CheckBTCHeaderSigningPolicy(
    const pq::ChainLockStatement& statement)
{
    if (!m_config || !statement.IsStructurallyValid()) return false;
    if (!pq::IsBTCHeaderPolicyEnabled()) {
        return true;
    }
    if (statement.btcc_advance != pq::BTCCAdvance::KEEP &&
        statement.btcc_advance != pq::BTCCAdvance::ADVANCE) {
        return false;
    }

    const uint256 statement_id{
        pq::GetLogicalChainLockId(m_genesis_hash, statement)};
    const auto deny = [&](const std::string& reason) {
        bool log_rejection{false};
        {
            LOCK(m_btc_header_policy_mutex);
            log_rejection = m_btc_header_policy_last_denied != statement_id ||
                            m_btc_header_policy_last_reason != reason;
            m_btc_header_policy_last_denied = statement_id;
            m_btc_header_policy_last_reason = reason;
        }
        if (log_rejection) {
            LogPrint(BCLog::CHAINLOCKS,
                     "CChainLocksHandler::%s -- refusing roster/BTCC share "
                     "at height %d: %s\n",
                     __func__, statement.height, reason);
        }
        return false;
    };
    const auto accept = [&] {
        LOCK(m_btc_header_policy_mutex);
        m_btc_header_policy_last_denied.reset();
        m_btc_header_policy_last_reason.clear();
        return true;
    };

    if (statement.btcc_advance == pq::BTCCAdvance::ADVANCE) {
        if (statement.accepted_btcc_cursor.IsNull()) return false;
        // Do not trust the statement's serialized cursor in isolation.
        // Re-derive the source and exact indexed BTCPREV before consulting
        // this sentry's independent Bitcoin view.
        LOCK(cs_main);
        const CChain& active_chain{m_chainman.ActiveChain()};
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const CBlockIndex* target{
            tip != nullptr && tip->nHeight >= statement.height
                ? active_chain[statement.height]
                : nullptr};
        const auto selected{
            target != nullptr &&
                    target->GetBlockHash() == statement.block_hash
                ? pq::SelectBTCCForChainLock(
                      m_config->btcc_schedule, *target,
                      statement.previous_btcc_cursor)
                : std::nullopt};
        const CBlockIndex* source{
            selected && selected->advance == pq::BTCCAdvance::ADVANCE
                ? active_chain[selected->cursor.sys_height]
                : nullptr};
        if (!selected || selected->cursor != statement.accepted_btcc_cursor ||
            selected->advance != statement.btcc_advance || source == nullptr ||
            source->GetBlockHash() !=
                statement.accepted_btcc_cursor.sys_hash ||
            source->btcpPrevCommitment !=
                statement.accepted_btcc_cursor.btc_hash) {
            return false;
        }
    }

    std::string reason;
    if (statement.roster_transition ==
        pq::RosterAuthorizationTransitionKind::RECOVER) {
        if (statement.btcc_advance != pq::BTCCAdvance::KEEP ||
            !pq::IsRecoveryRosterBeaconWindow(
                statement.roster_beacons)) {
            return deny("btc-recovery-state-mismatch");
        }
        return accept();
    }

    if (statement.roster_transition ==
            pq::RosterAuthorizationTransitionKind::INITIALIZE &&
        pq::IsInitialNormalRosterBeaconWindow(
            statement.roster_beacons)) {
        const bool backend_healthy{
            m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
                /*recover=*/true, reason)};
        const auto config{backend_healthy
            ? pq::GetConfiguredBTCHeaderPolicy(reason)
            : std::nullopt};
        if (statement.btcc_advance != pq::BTCCAdvance::ADVANCE ||
            !config) {
            return deny(reason.empty() ? "btc-recovery-policy-unavailable"
                                       : reason);
        }
        const auto& ready{
            statement.roster_beacons.active.seeds.back()};
        const auto range{
            pq::MakeConfiguredBTCHeaderPolicy()
                .CheckPaymentAuditActiveRange(
                    *config, ready.anchor_cursor.btc_hash,
                    GetTime(), reason)};
        const auto future_height{ready.FutureBTCHeight()};
        if (!range || !future_height ||
            statement.accepted_btcc_cursor != ready.anchor_cursor ||
            ready.anchor_cursor.sys_height != statement.height ||
            ready.anchor_cursor.sys_hash != statement.block_hash ||
            range->anchor_hash != ready.anchor_cursor.btc_hash ||
            range->anchor_height != ready.anchor_btc_height ||
            range->future_height != *future_height ||
            range->future_hash != ready.future_btc_hash) {
            return deny(reason.empty() ? "btc-recovery-range-mismatch"
                                       : reason);
        }
        return accept();
    }

    if (statement.roster_transition !=
        pq::RosterAuthorizationTransitionKind::KEEP) {
        const auto best{m_store ? m_store->GetBestRecord()
                                : std::nullopt};
        const auto input{best
            ? BuildNormalRosterAuthorizationInput(
                  statement, best->metadata,
                  statement.roster_transition,
                  RosterBeaconEvidence::SIGNER_POLICY)
            : std::optional<pq::NormalRosterAuthorizationInput>{}};
        if (!input) {
            return deny(reason.empty() ? "btc-roster-evidence-mismatch"
                                       : reason);
        }
        pq::RosterAuthorizationTransition transition;
        transition.kind = statement.roster_transition;
        transition.target_height = statement.height;
        transition.target_block_hash = statement.block_hash;
        transition.predecessor_height =
            statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            statement.previous_chainlock_hash;
        transition.authorization_base =
            statement.roster_authorization_base;
        transition.previous = pq::RosterAuthorizationPriorState{
            best->metadata.statement.roster_authorization_state_hash,
            best->metadata.statement.roster_beacons};
        transition.new_window = statement.roster_beacons;
        if (!pq::ValidateNormalRosterAuthorizationDecision(
                m_genesis_hash, *input, transition,
                statement.roster_authorization_state_hash)) {
            return deny("btc-roster-transition-mismatch");
        }
    }

    if (statement.btcc_advance == pq::BTCCAdvance::KEEP) {
        return accept();
    }

    const bool backend_healthy{
        m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
            /*recover=*/true, reason)};
    auto config{backend_healthy
        ? pq::GetConfiguredBTCHeaderPolicy(reason)
        : std::nullopt};
    if (config) {
        const auto epoch{pq::EpochForHeight(
            m_config->chainlock_schedule, statement.height)};
        const pq::PaymentAuditScheduleConfig audit_config{
            m_config->chainlock_schedule, m_config->btcc_schedule};
        const auto audit_schedule{
            epoch ? pq::BuildPaymentAuditEpochSchedule(audit_config, *epoch)
                  : std::nullopt};
        if (audit_schedule &&
            audit_schedule->anchor_height == statement.height) {
            // K proves the anchor was recent before H+37 could be known.
            // At delayed B it is rechecked only for active-chain membership.
            config->max_lag_blocks =
                config->max_lag_blocks == 0
                    ? pq::DEFAULT_BTC_HEADER_MAX_LAG_BLOCKS
                    : std::min<int64_t>(
                          config->max_lag_blocks,
                          pq::DEFAULT_BTC_HEADER_MAX_LAG_BLOCKS);
        }
    }
    std::optional<uint256> previous_hash;
    if (!statement.previous_btcc_cursor.IsNull()) {
        previous_hash = statement.previous_btcc_cursor.btc_hash;
    }
    const auto checked{
        config ? pq::MakeConfiguredBTCHeaderPolicy().CheckCandidate(
                     *config, statement.accepted_btcc_cursor.btc_hash,
                     previous_hash, GetTime(), reason)
               : std::nullopt};
    if (!checked) {
        return deny(reason);
    }

    // This result is Bitcoin policy only. External calls hold no Syscoin
    // authority; the caller must capture the exact published collector and
    // recheck its source and both local pre-seals before any signer-journal
    // state is consumed.
    if (checked->previous_was_reorged) {
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- Bitcoin reorg recovery accepted "
                 "for BTCC ADVANCE at height %d after recent-fork policy "
                 "cleared\n",
                 __func__, statement.height);
    }
    return accept();
}

bool CChainLocksHandler::CheckPaymentAuditSeedSigningPolicy(
    const pq::PaymentAuditStatement& statement)
{
    if (!statement.IsStructurallyValid() || !m_config ||
        !pq::IsBTCHeaderPolicyEnabled()) {
        return false;
    }
    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, statement.commitment.seed.epoch)};
    if (!schedule) return false;
    const auto syscoin_context_current = [&] {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const CBlockIndex* seal{
            tip != nullptr && tip->nHeight >= statement.commitment.seal_height
                ? tip->GetAncestor(statement.commitment.seal_height)
                : nullptr};
        if (seal == nullptr || seal->GetBlockHash() !=
                                   statement.seal_statement.block_hash) {
            return false;
        }
        const auto seed_context{GetPaymentAuditSeedReceiptContext(
            m_genesis_hash, schedule_config, *schedule, *seal)};
        return seed_context.status == PaymentAuditContextStatus::READY &&
               seed_context.seed_point &&
               *seed_context.seed_point == statement.commitment.seed.anchor;
    };
    if (!syscoin_context_current()) return false;

    std::string reason;
    const bool backend_healthy{
        m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
            /*recover=*/true, reason)};
    const auto config{
        backend_healthy ? pq::GetConfiguredBTCHeaderPolicy(reason)
                        : std::optional<pq::BTCHeaderPolicyConfig>{}};
    const auto checked{
        config ? pq::MakeConfiguredBTCHeaderPolicy()
                     .CheckPaymentAuditActiveRange(
                         *config,
                         statement.commitment.seed.anchor
                             .accepted_cursor.btc_hash,
                         GetTime(), reason)
               : std::optional<pq::BTCHeaderActiveRange>{}};
    const bool exact{
        checked &&
        checked->anchor_hash ==
            statement.commitment.seed.anchor.accepted_cursor.btc_hash &&
        checked->anchor_height ==
            statement.commitment.seed.anchor_btc_height &&
        checked->future_height ==
            statement.commitment.seed.future_btc_height &&
        checked->future_hash ==
            statement.commitment.seed.future_btc_hash};
    if (!exact || !syscoin_context_current()) {
        const uint256 statement_id{pq::GetPaymentAuditLogicalId(
            m_genesis_hash, statement)};
        bool log_rejection{false};
        {
            LOCK(m_btc_header_policy_mutex);
            log_rejection =
                m_btc_header_policy_last_denied != statement_id ||
                m_btc_header_policy_last_reason != reason;
            m_btc_header_policy_last_denied = statement_id;
            m_btc_header_policy_last_reason = reason;
        }
        if (log_rejection) {
            LogPrint(BCLog::CHAINLOCKS,
                     "CChainLocksHandler::%s -- refusing payment-audit "
                     "share for epoch %u: %s\n",
                     __func__, statement.commitment.seed.epoch, reason);
        }
        return false;
    }
    {
        LOCK(m_btc_header_policy_mutex);
        m_btc_header_policy_last_denied.reset();
        m_btc_header_policy_last_reason.clear();
    }
    return true;
}

CChainLocksHandler::CurrentSigningContextsPtr
CChainLocksHandler::GetPublishedCurrentSigningContexts(
    uint64_t admission_generation) const
{
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return {};
    LOCK(m_collector_mutex);
    const auto& current{m_current_signing_contexts};
    if (!current ||
        current->source.admission_generation != admission_generation ||
        current->count == 0 ||
        current->count > CurrentSigningContexts::MAX_VARIANTS ||
        !current->roster_set || !current->relay_plan) {
        return {};
    }
    for (std::size_t i{0}; i < current->count; ++i) {
        if (!current->prepared_contexts[i] || !m_collectors[i] ||
            m_collectors[i]->GetStatement() != current->statements[i] ||
            m_collectors[i]->GetPreparedContext() !=
                current->prepared_contexts[i] ||
            current->prepared_contexts[i]->RosterSetPtr() !=
                current->roster_set ||
            !pq::IsSigningRosterAuthorizationMask(
                current->prepared_contexts[i]->AuthorizationMask())) {
            return {};
        }
    }
    return IsShareAdmissionGenerationCurrent(admission_generation)
        ? current
        : CurrentSigningContextsPtr{};
}

bool CChainLocksHandler::RefreshCurrentSigningContexts(
    uint64_t admission_generation)
{
    // The synthetic regtest fixture exercises collector admission without a
    // live operator key. Production nodes build these contexts only when they
    // are actually capable of signing and relaying as a masternode.
    const bool synthetic_regtest_collector{
        Params().MineBlocksOnDemand() &&
        gArgs.IsArgSet("-pqchainlocktestfixture")};
    if ((!fMasternodeMode && !synthetic_regtest_collector) ||
        !IsShareAdmissionGenerationCurrent(admission_generation)) {
        return false;
    }
    const auto is_current = [this](
                                const CurrentSigningContextsPtr& contexts) {
        return contexts &&
               IsPQRelayPlanForCurrentIdentityState(
                   contexts->relay_plan) &&
               IsCurrentSigningSource(contexts->source);
    };
    const auto apply_relay_plan = [](
                                      const CurrentSigningContextsPtr& contexts) {
        if (pqQuorumConnectionOverlay == nullptr || !contexts ||
            !IsPQRelayPlanForActiveIdentity(contexts->relay_plan)) {
            return;
        }
        const std::optional<PQQuorumOverlayPredecessor> accepted_predecessor{
            contexts->source.has_durable_chainlock
                ? std::optional<PQQuorumOverlayPredecessor>{
                      PQQuorumOverlayPredecessor{
                          contexts->source.durable_predecessor.height,
                          contexts->source.durable_predecessor.block_hash}}
                : std::nullopt};
        (void)pqQuorumConnectionOverlay->ApplyPreparedContext(
            contexts->statements[0].quorum_context_hash,
            contexts->relay_plan->relay_members,
            accepted_predecessor);
    };
    auto cached{GetPublishedCurrentSigningContexts(admission_generation)};
    const bool initial_current{is_current(cached)};
    if (initial_current) {
        apply_relay_plan(cached);
        return true;
    }

    LOCK(m_context_build_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
        return false;
    }
    cached = GetPublishedCurrentSigningContexts(admission_generation);
    const bool cached_current{is_current(cached)};
    if (cached_current) {
        apply_relay_plan(cached);
        return true;
    }

    uint64_t build_generation{0};
    CurrentSigningContextsPtr replaced;
    {
        LOCK(m_collector_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
            return false;
        }
        build_generation = m_collector_generation;
        replaced = m_current_signing_contexts;
    }
    const auto retire_replaced_if_exact = [&]() {
        if (!replaced) return;
        LOCK(m_collector_mutex);
        if (m_collector_generation == build_generation &&
            m_current_signing_contexts == replaced) {
            ResetCollectors();
        }
    };
    auto built{BuildCurrentSigningContexts(admission_generation)};
    if (!built) {
        retire_replaced_if_exact();
        return false;
    }
    built->relay_plan = BuildPQRelayPlanForCurrentIdentity(
        built->roster_set->Rosters());
    if (!built->relay_plan) {
        retire_replaced_if_exact();
        return false;
    }

    std::array<std::unique_ptr<pq::ChainLockCollector>,
               CurrentSigningContexts::MAX_VARIANTS> collectors;
    for (std::size_t i{0}; i < built->count; ++i) {
        if (!built->prepared_contexts[i] ||
            built->prepared_contexts[i]->Statement() !=
                built->statements[i] ||
            built->prepared_contexts[i]->RosterSetPtr() !=
                built->roster_set) {
            retire_replaced_if_exact();
            return false;
        }
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        collectors[i] = pq::ChainLockCollector::Create(
            built->prepared_contexts[i], &error);
        if (!collectors[i]) {
            retire_replaced_if_exact();
            return false;
        }
    }
    auto published{std::make_shared<const CurrentSigningContexts>(
        std::move(*built))};

    uint64_t published_generation{0};
    {
        LOCK(m_collector_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_collector_generation != build_generation ||
            m_current_signing_contexts != replaced) {
            return false;
        }
        m_collectors = std::move(collectors);
        m_current_signing_contexts = published;
        published_generation = ++m_collector_generation;
    }
    // Source inputs are not serialized by the publication mutex. Retire only
    // this exact pointer/generation if the post-publication safety check loses
    // a race; never tear down a replacement installed by another transition.
    if (!is_current(published)) {
        LOCK(m_collector_mutex);
        if (m_collector_generation == published_generation &&
            m_current_signing_contexts == published) {
            ResetCollectors();
        }
        return false;
    }
    // The first INITIALIZE context has no accepted predecessor for the
    // tip-driven overlay path. Reapplying cached contexts also repairs a plan
    // cleared by IBD or a racing tip callback before any share announcement.
    apply_relay_plan(published);
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- published PQ ChainLock signing "
             "context height=%d variants=%u\n",
             __func__, published->source.window.target_height,
             static_cast<unsigned int>(published->count));
    return true;
}

std::optional<CChainLocksHandler::PaymentAuditResponseDefinition>
CChainLocksHandler::BuildPaymentAuditResponseDefinition(
    uint32_t epoch,
    uint8_t row_index) const
{
    if (!m_share_admission_gate.IsOpen() || !m_config ||
        !m_quorum_build_config ||
        !m_store || !m_payment_audit_staging_store ||
        row_index >= pq::PAYMENT_AUDIT_ROW_COUNT) {
        return std::nullopt;
    }
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return std::nullopt;
    }
    const auto row{m_payment_audit_staging_store->GetOpenRowMetadata(
        epoch, row_index)};
    if (!row) return std::nullopt;

    const auto finalized_record{
        m_store->GetRecordByHeight(row->expected.response_height)};
    const auto finalized{finalized_record
        ? finalized_record->certificate
        : CChainLockSigCPtr{}};
    const std::optional<pq::ChainLockStatement> response_statement{
        finalized
            ? std::optional<pq::ChainLockStatement>{finalized->statement}
            : std::nullopt};
    if (!response_statement ||
        response_statement->height != row->expected.response_height ||
        response_statement->block_hash != row->response_block_hash ||
        response_statement->btcc_advance != row->response_advance ||
        response_statement->accepted_btcc_cursor.sys_height !=
            row->expected.response_height ||
        pq::GetLogicalChainLockId(m_genesis_hash, *response_statement) !=
            row->expected.response_chainlock_logical_id) {
        return std::nullopt;
    }

    {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const CBlockIndex* response_index{
            tip != nullptr &&
                    tip->nHeight >= row->expected.response_height
                ? tip->GetAncestor(row->expected.response_height)
                : nullptr};
        if (tip == nullptr || response_index == nullptr ||
            tip->nHeight >= row->deadline_height ||
            response_index->GetBlockHash() != row->response_block_hash ||
            !(response_index->nStatus & BLOCK_HAVE_DATA) ||
            (response_index->nStatus & BLOCK_FAILED_MASK) ||
            response_index->IsAssumedValid() ||
            !response_index->IsValid(BLOCK_VALID_SCRIPTS)) {
            return std::nullopt;
        }
    }
    const auto response_context{finalized_record
        ? finalized_record->verification_context
        : pq::PreparedChainLockContextPtr{}};
    const auto roster_set{response_context
        ? response_context->RosterSetPtr()
        : pq::VerifiedRosterSetPtr{}};
    if (!roster_set || roster_set->Rosters().back().descriptor.epoch != epoch ||
        response_statement->roster_beacons.active.seeds.back().anchor_kind ==
            pq::RosterBeaconAnchorKind::RECOVERY ||
        roster_set->Rosters().back().descriptor.valid_members !=
            row->subject_valid_members ||
        pq::GetPaymentAuditDescriptorHash(
            m_genesis_hash, roster_set->Rosters().back().descriptor) !=
            row->expected.subject_descriptor_hash ||
        !response_context ||
        response_context->Statement() != *response_statement ||
        !pq::IsSigningRosterAuthorizationMask(
            response_context->AuthorizationMask()) ||
        (response_context->AuthorizationMask() &
         (uint8_t{1} << (pq::ACTIVE_QUORUMS - 1))) == 0) {
        return std::nullopt;
    }
    const auto current{m_payment_audit_staging_store->GetOpenRowMetadata(
        row->expected.epoch, row->expected.row_index)};
    if (!current || !SamePaymentAuditOpenRowIdentity(*current, *row) ||
        !IsCurrentPaymentAuditNetworkRow(*row)) {
        return std::nullopt;
    }
    std::vector<uint256> active_relays;
    active_relays.reserve(
        response_context->Rosters().size() * pq::QUORUM_SIZE);
    for (const auto& roster : response_context->Rosters()) {
        for (const auto& member : roster.members) {
            if (member.eligible && member.child_root) {
                active_relays.push_back(member.pro_tx_hash);
            }
        }
    }
    std::sort(active_relays.begin(), active_relays.end());
    active_relays.erase(
        std::unique(active_relays.begin(), active_relays.end()),
        active_relays.end());
    auto relay_plan{BuildPQRelayPlanForCurrentIdentity(
        response_context->Rosters())};
    if (!relay_plan) return std::nullopt;
    return PaymentAuditResponseDefinition{
        *row, std::move(response_context), std::move(active_relays),
        std::move(relay_plan)};
}

bool CChainLocksHandler::IsPaymentAuditResponseDefinitionSourceCurrent(
    const PaymentAuditResponseDefinition& definition) const
{
    if (!m_store || !definition.response_context ||
        !IsPQRelayPlanForCurrentIdentityState(
            definition.relay_plan)) {
        return false;
    }
    const auto finalized{m_store->GetRecordByHeight(
        definition.row.expected.response_height)};
    if (!finalized || !finalized->certificate ||
        finalized->verification_context != definition.response_context) {
        return false;
    }
    return pq::MatchesPaymentAuditResponseContext(
        definition.row.expected, *definition.response_context,
        finalized->certificate->statement);
}

std::shared_ptr<const CChainLocksHandler::PaymentAuditNetworkContext>
CChainLocksHandler::GetPaymentAuditNetworkContext() const
{
    LOCK(m_payment_audit_mutex);
    return m_payment_audit_network_context;
}

bool CChainLocksHandler::IsCurrentPaymentAuditNetworkRow(
    const pq::PaymentAuditOpenRowMetadata& row) const
{
    if (!m_share_admission_gate.IsOpen() ||
        !m_payment_audit_staging_store) {
        return false;
    }
    const auto current{
        m_payment_audit_staging_store->GetOpenRowMetadata(
            row.expected.epoch, row.expected.row_index)};
    if (!current || !SamePaymentAuditOpenRowIdentity(*current, row)) {
        return false;
    }
    LOCK(cs_main);
    if (IsPaymentAuditPresealActive()) return false;
    const CBlockIndex* tip{m_chainman.ActiveTip()};
    const CBlockIndex* response{
        tip != nullptr && tip->nHeight >= row.expected.response_height
            ? tip->GetAncestor(row.expected.response_height)
            : nullptr};
    return tip != nullptr && response != nullptr &&
           tip->nHeight < row.deadline_height &&
           response->GetBlockHash() == row.response_block_hash &&
           (response->nStatus & BLOCK_HAVE_DATA) &&
           !(response->nStatus & BLOCK_FAILED_MASK) &&
           !response->IsAssumedValid() &&
           response->IsValid(BLOCK_VALID_SCRIPTS);
}

bool CChainLocksHandler::RefreshPaymentAuditNetworkContext()
{
    if (!RefreshPaymentAuditStaging() ||
        !m_payment_audit_staging_store) {
        LOCK(m_payment_audit_mutex);
        m_payment_audit_network_context.reset();
        return false;
    }

    // Only the scheduler builds branch/roster context. Network messages may
    // consume this immutable snapshot but never trigger a rebuild.
    std::vector<pq::PaymentAuditOpenRowMetadata> rows;
    const auto epoch{m_payment_audit_staging_store->ActiveEpoch()};
    if (epoch) {
        rows = m_payment_audit_staging_store->GetOpenRowsMetadata(*epoch);
    }
    const auto current{GetPaymentAuditNetworkContext()};
    const auto find_current = [&](const auto& row)
        -> const PaymentAuditResponseDefinition* {
        if (!current) return nullptr;
        const auto found{std::find_if(
            current->rows.begin(), current->rows.end(),
            [&](const auto& definition) {
                return SamePaymentAuditOpenRowIdentity(
                           definition.row, row) &&
                       IsPaymentAuditResponseDefinitionSourceCurrent(
                           definition);
            })};
        return found != current->rows.end() ? &*found : nullptr;
    };
    const bool removed{current && std::any_of(
        current->rows.begin(), current->rows.end(),
        [&](const auto& definition) {
            return !IsPaymentAuditResponseDefinitionSourceCurrent(
                       definition) ||
                   std::none_of(rows.begin(), rows.end(),
                                [&](const auto& row) {
                       return SamePaymentAuditOpenRowIdentity(
                           definition.row, row);
                   });
        })};
    std::vector<PaymentAuditResponseDefinition> built;
    built.reserve(rows.size());
    for (const auto& row : rows) {
        if (find_current(row) != nullptr) continue;
        auto definition{BuildPaymentAuditResponseDefinition(
            row.expected.epoch, row.expected.row_index)};
        if (definition &&
            SamePaymentAuditOpenRowIdentity(definition->row, row)) {
            built.push_back(std::move(*definition));
        }
    }
    if (current && !removed && built.empty()) return true;

    auto next{std::make_shared<PaymentAuditNetworkContext>()};
    next->rows.reserve(rows.size());
    for (const auto& row : rows) {
        if (const auto* existing{find_current(row)}) {
            next->rows.push_back(*existing);
            continue;
        }
        const auto created{std::find_if(
            built.begin(), built.end(), [&](const auto& definition) {
                return SamePaymentAuditOpenRowIdentity(
                    definition.row, row);
            })};
        if (created != built.end()) {
            next->rows.push_back(std::move(*created));
        }
    }
    {
        LOCK(m_payment_audit_mutex);
        m_payment_audit_network_context = std::move(next);
    }
    return true;
}

bool CChainLocksHandler::RefreshPaymentAuditStaging()
{
    if (!m_share_admission_gate.IsOpen() || !m_config ||
        !m_quorum_build_config ||
        !m_store || !m_payment_audit_staging_store ||
        !m_payment_audit_staging_store->IsHealthy()) {
        return false;
    }
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return false;
    }

    int32_t tip_height{-1};
    uint256 tip_hash;
    std::optional<uint32_t> epoch;
    {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        if (tip == nullptr) return false;
        tip_height = tip->nHeight;
        tip_hash = tip->GetBlockHash();
        epoch = pq::EpochForHeight(m_config->chainlock_schedule,
                                   tip_height);
    }
    if (!epoch) return false;

    const auto active_epoch{m_payment_audit_staging_store->ActiveEpoch()};
    if (!active_epoch || *active_epoch != *epoch) {
        const auto activated{
            m_payment_audit_staging_store->ActivateEpoch(*epoch)};
        if (activated != pq::PaymentAuditStagingResult::ACCEPTED &&
            activated != pq::PaymentAuditStagingResult::DUPLICATE) {
            return false;
        }
    }

    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, *epoch)};
    if (!schedule) return false;

    // Deadline equality is already frozen: stop admission before opening the
    // next overlapping row at the same height.
    for (const auto& row :
         m_payment_audit_staging_store->GetOpenRowsMetadata(*epoch)) {
        if (tip_height < row.deadline_height) continue;

        uint256 active_response_hash;
        uint256 active_deadline_hash;
        bool tip_consistent{false};
        bool active_branch{false};
        {
            LOCK(cs_main);
            const CBlockIndex* tip{m_chainman.ActiveTip()};
            const CBlockIndex* response_index{
                tip != nullptr &&
                        tip->nHeight >= row.expected.response_height
                    ? tip->GetAncestor(row.expected.response_height)
                    : nullptr};
            const CBlockIndex* deadline_index{
                tip != nullptr && tip->nHeight >= row.deadline_height
                    ? tip->GetAncestor(row.deadline_height)
                    : nullptr};
            tip_consistent = tip != nullptr && tip->nHeight == tip_height &&
                             tip->GetBlockHash() == tip_hash;
            if (tip_consistent &&
                response_index != nullptr && deadline_index != nullptr &&
                (response_index->nStatus & BLOCK_HAVE_DATA) &&
                !(response_index->nStatus & BLOCK_FAILED_MASK) &&
                !response_index->IsAssumedValid() &&
                response_index->IsValid(BLOCK_VALID_SCRIPTS) &&
                (deadline_index->nStatus & BLOCK_HAVE_DATA) &&
                !(deadline_index->nStatus & BLOCK_FAILED_MASK) &&
                !deadline_index->IsAssumedValid() &&
                deadline_index->IsValid(BLOCK_VALID_SCRIPTS)) {
                active_response_hash = response_index->GetBlockHash();
                active_deadline_hash = deadline_index->GetBlockHash();
                active_branch = true;
            }
        }
        if (!tip_consistent) return false;
        const auto final_response{
            m_store->GetByHeight(row.expected.response_height)};
        if (!active_branch ||
            active_response_hash != row.response_block_hash ||
            !final_response ||
            final_response->statement.block_hash !=
                row.response_block_hash ||
            final_response->statement.btcc_advance !=
                pq::BTCCAdvance::ADVANCE ||
            final_response->statement.accepted_btcc_cursor.sys_height !=
                row.expected.response_height ||
            final_response->GetLogicalId(m_genesis_hash) !=
                row.expected.response_chainlock_logical_id) {
            (void)m_payment_audit_staging_store->DiscardOpenRow(
                row.expected.epoch, row.expected.row_index);
            continue;
        }
        if (m_payment_audit_staging_store->FreezeRow(
                row.expected.epoch, row.expected.row_index,
                active_response_hash, active_deadline_hash) !=
            pq::PaymentAuditStagingResult::ACCEPTED) {
            return false;
        }
    }

    for (uint8_t row_index{0};
         row_index < pq::PAYMENT_AUDIT_ROW_COUNT; ++row_index) {
        const auto& row_schedule{schedule->rows[row_index]};
        if (tip_height < row_schedule.response_height ||
            tip_height >= row_schedule.deadline_height ||
            m_payment_audit_staging_store->GetSummary(
                *epoch, row_index)) {
            continue;
        }
        const auto response_record{
            m_store->GetRecordByHeight(row_schedule.response_height)};
        const auto response_chainlock{response_record
            ? response_record->certificate
            : CChainLockSigCPtr{}};
        if (!response_chainlock ||
            !response_record->verification_context ||
            response_record->verification_context->Statement() !=
                response_chainlock->statement ||
            response_chainlock->statement.roster_beacons.active.seeds.back()
                    .anchor_kind ==
                pq::RosterBeaconAnchorKind::RECOVERY ||
            response_chainlock->statement.height !=
                row_schedule.response_height ||
            response_chainlock->statement.btcc_advance !=
                pq::BTCCAdvance::ADVANCE ||
            response_chainlock->statement.accepted_btcc_cursor.sys_height !=
                row_schedule.response_height) {
            continue;
        }

        pq::FrozenQuorumRostersPtr rosters;
        uint256 response_block_hash;
        {
            LOCK(cs_main);
            const CBlockIndex* tip{m_chainman.ActiveTip()};
            const CBlockIndex* response_index{
                tip != nullptr &&
                        tip->nHeight >= row_schedule.response_height
                    ? tip->GetAncestor(row_schedule.response_height)
                    : nullptr};
            if (tip == nullptr || tip->nHeight != tip_height ||
                tip->GetBlockHash() != tip_hash ||
                response_index == nullptr ||
                response_index->GetBlockHash() !=
                    response_chainlock->statement.block_hash ||
                !(response_index->nStatus & BLOCK_HAVE_DATA) ||
                (response_index->nStatus & BLOCK_FAILED_MASK) ||
                response_index->IsAssumedValid() ||
                !response_index->IsValid(BLOCK_VALID_SCRIPTS)) {
                continue;
            }
            response_block_hash = response_index->GetBlockHash();
            rosters = response_record->verification_context->RostersPtr();
        }
        if (!rosters || rosters->back().descriptor.epoch != *epoch) {
            continue;
        }
        const auto& subject{rosters->back().descriptor};
        pq::PaymentAuditStagingRow row;
        row.expected.epoch = *epoch;
        row.expected.row_index = row_index;
        row.expected.response_height = row_schedule.response_height;
        row.expected.response_chainlock_logical_id =
            response_chainlock->GetLogicalId(m_genesis_hash);
        row.expected.subject_descriptor_hash =
            pq::GetPaymentAuditDescriptorHash(m_genesis_hash, subject);
        row.deadline_height = row_schedule.deadline_height;
        row.response_block_hash = response_block_hash;
        row.subject_valid_members = subject.valid_members;
        if (!row.IsStructurallyValid(m_genesis_hash)) continue;

        auto result{m_payment_audit_staging_store->EnsureRow(row)};
        if (result == pq::PaymentAuditStagingResult::BRANCH_CONFLICT) {
            result =
                m_payment_audit_staging_store->ReplaceRowBranch(row);
        }
        if (result != pq::PaymentAuditStagingResult::ACCEPTED &&
            result != pq::PaymentAuditStagingResult::DUPLICATE) {
            return false;
        }
    }

    std::set<uint256> active_logical_ids;
    for (const auto& row :
         m_payment_audit_staging_store->GetOpenRowsMetadata(*epoch)) {
        active_logical_ids.insert(
            row.expected.response_chainlock_logical_id);
    }
    {
        LOCK(m_payment_audit_mutex);
        for (auto peer{m_payment_audit_supplied_to_peer.begin()};
             peer != m_payment_audit_supplied_to_peer.end();) {
            std::erase_if(peer->second, [&](const auto& supplied) {
                return !active_logical_ids.contains(supplied.first);
            });
            if (peer->second.empty()) {
                peer = m_payment_audit_supplied_to_peer.erase(peer);
            } else {
                ++peer;
            }
        }
    }
    return m_payment_audit_staging_store->IsHealthy();
}

void CChainLocksHandler::MaybeCapturePaymentAuditResponse(
    const pq::ChainLockShare& share,
    const pq::FrozenQuorumRostersPtr& rosters,
    uint64_t admission_generation)
{
    LOCK(m_share_lifecycle_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    if (!rosters || !m_config || !m_payment_audit_staging_store ||
        !m_payment_audit_staging_store->IsHealthy() ||
        share.GetStatement().btcc_advance != pq::BTCCAdvance::ADVANCE ||
        share.GetStatement().accepted_btcc_cursor.sys_height !=
            share.transcript.height) {
        return;
    }
    const auto epoch{pq::EpochForHeight(
        m_config->chainlock_schedule, share.transcript.height)};
    if (!epoch) return;
    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, *epoch)};
    if (!schedule) return;
    std::optional<uint8_t> row_index;
    for (uint8_t index{0}; index < pq::PAYMENT_AUDIT_ROW_COUNT; ++index) {
        if (schedule->rows[index].response_height ==
            share.transcript.height) {
            row_index = index;
            break;
        }
    }
    if (!row_index) return;
    const auto& row_schedule{schedule->rows[*row_index]};

    int32_t tip_height{-1};
    {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const CBlockIndex* response_index{
            tip != nullptr && tip->nHeight >= share.transcript.height
                ? tip->GetAncestor(share.transcript.height)
                : nullptr};
        if (tip == nullptr || response_index == nullptr ||
            tip->nHeight >= row_schedule.deadline_height ||
            response_index->GetBlockHash() !=
                share.GetStatement().block_hash ||
            !(response_index->nStatus & BLOCK_HAVE_DATA) ||
            (response_index->nStatus & BLOCK_FAILED_MASK) ||
            response_index->IsAssumedValid() ||
            !response_index->IsValid(BLOCK_VALID_SCRIPTS)) {
            return;
        }
        tip_height = tip->nHeight;
    }

    const auto& subject{rosters->back()};
    if (subject.descriptor.epoch != *epoch ||
        share.transcript.quorum_epoch != subject.descriptor.epoch ||
        share.transcript.quorum_base_hash != subject.descriptor.base_hash ||
        share.transcript.member_index >= pq::QUORUM_SIZE) {
        return;
    }
    pq::PaymentAuditResponse response;
    response.epoch = subject.descriptor.epoch;
    response.row_index = *row_index;
    response.subject_descriptor_hash =
        pq::GetPaymentAuditDescriptorHash(m_genesis_hash,
                                          subject.descriptor);
    response.response = share;
    if (!response.IsStructurallyValid()) return;
    pq::PaymentAuditHave expected;
    expected.epoch = *epoch;
    expected.row_index = *row_index;
    expected.response_height = row_schedule.response_height;
    expected.response_chainlock_logical_id =
        pq::GetLogicalChainLockId(m_genesis_hash, share.GetStatement());
    expected.subject_descriptor_hash =
        response.subject_descriptor_hash;
    pq::PaymentAuditStagingRow row;
    row.expected = expected;
    row.deadline_height = row_schedule.deadline_height;
    row.response_block_hash = share.GetStatement().block_hash;
    row.subject_valid_members = subject.descriptor.valid_members;
    if (!row.IsStructurallyValid(m_genesis_hash)) return;

    const auto active_epoch{m_payment_audit_staging_store->ActiveEpoch()};
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    if (!active_epoch || *active_epoch != *epoch) {
        const auto activated{
            m_payment_audit_staging_store->ActivateEpoch(*epoch)};
        if (activated != pq::PaymentAuditStagingResult::ACCEPTED &&
            activated != pq::PaymentAuditStagingResult::DUPLICATE) {
            return;
        }
    }
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    auto ensured{m_payment_audit_staging_store->EnsureRow(row)};
    if (ensured == pq::PaymentAuditStagingResult::BRANCH_CONFLICT) {
        ensured = m_payment_audit_staging_store->ReplaceRowBranch(row);
    }
    if (ensured != pq::PaymentAuditStagingResult::ACCEPTED &&
        ensured != pq::PaymentAuditStagingResult::DUPLICATE) {
        return;
    }
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    if (m_payment_audit_staging_store->AddVerifiedResponse(
            *epoch, *row_index, tip_height, response) ==
        pq::PaymentAuditStagingResult::ACCEPTED) {
        if (IsShareAdmissionGenerationCurrent(admission_generation)) {
            RelayPaymentAuditResponse(response);
        }
    }
}

void CChainLocksHandler::RelayPaymentAuditResponse(
    const pq::PaymentAuditResponse& response, uint256 excluded_identity)
{
    const auto context{GetPaymentAuditNetworkContext()};
    if (!context) return;
    const PaymentAuditResponseDefinition* definition{nullptr};
    for (const auto& candidate : context->rows) {
        if (candidate.row.expected.epoch == response.epoch &&
            candidate.row.expected.row_index == response.row_index) {
            definition = &candidate;
            break;
        }
    }
    if (definition == nullptr || !definition->relay_plan ||
        definition->row.expected.subject_descriptor_hash !=
            response.subject_descriptor_hash ||
        !IsPaymentAuditResponseDefinitionSourceCurrent(*definition) ||
        !IsCurrentPaymentAuditNetworkRow(definition->row)) {
        return;
    }
    PQRelayIdentityGate relay_gate{excluded_identity};
    m_connman.ForEachNode([&](CNode* node) {
        if (node == nullptr || node->fDisconnect ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
            return;
        }
        const uint256 identity{node->GetVerifiedProRegTxHash()};
        if (!relay_gate.Admit(
                identity,
                std::binary_search(
                    definition->active_relays.begin(),
                    definition->active_relays.end(), identity),
                definition->relay_plan->relay_members.contains(identity))) {
            return;
        }
        m_connman.PushMessage(
            node, CNetMsgMaker(node->GetCommonVersion())
                      .Make(NetMsgType::PQPOSERESP, response));
    });
}

void CChainLocksHandler::MaybeRelayPaymentAuditHave()
{
    if (!m_chainman.IsPQParticipationAllowed() ||
        !RefreshPaymentAuditNetworkContext() ||
        !m_payment_audit_staging_store) {
        return;
    }
    const auto context{GetPaymentAuditNetworkContext()};
    if (!context) return;
    for (const auto& definition : context->rows) {
        if (!definition.relay_plan) continue;
        const auto row{m_payment_audit_staging_store->GetOpenRowMetadata(
            definition.row.expected.epoch,
            definition.row.expected.row_index)};
        if (!row ||
            !SamePaymentAuditOpenRowIdentity(*row, definition.row) ||
            !IsPaymentAuditResponseDefinitionSourceCurrent(definition) ||
            !IsCurrentPaymentAuditNetworkRow(definition.row)) {
            continue;
        }
        pq::PaymentAuditHave have{definition.row.expected};
        have.available_members = row->available_members;
        PQRelayIdentityGate relay_gate;
        m_connman.ForEachNode([&](CNode* node) {
            if (node == nullptr || node->fDisconnect ||
                node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
                return;
            }
            const uint256 identity{node->GetVerifiedProRegTxHash()};
            if (!relay_gate.Admit(
                    identity,
                    std::binary_search(
                        definition.active_relays.begin(),
                        definition.active_relays.end(), identity),
                    definition.relay_plan->relay_members.contains(identity))) {
                return;
            }
            m_connman.PushMessage(
                node, CNetMsgMaker(node->GetCommonVersion())
                          .Make(NetMsgType::PQPOSEHAVE, have));
        });
    }
}

void CChainLocksHandler::ResetPaymentAuditRuntime()
{
    ReleasePaymentAuditOverlay();
    m_payment_audit_runtime.reset();
    ++m_payment_audit_runtime_generation;
}

void CChainLocksHandler::ReleasePaymentAuditOverlay()
{
    if (pqQuorumConnectionOverlay == nullptr ||
        !m_payment_audit_runtime ||
        m_payment_audit_runtime->relay_group_id.IsNull()) {
        return;
    }
    (void)pqQuorumConnectionOverlay->RemovePaymentAuditContext(
        m_payment_audit_runtime->relay_group_id,
        m_payment_audit_runtime_generation);
}

bool CChainLocksHandler::ApplyPaymentAuditOverlay(
    uint64_t expected_runtime_generation)
{
    std::optional<pq::PaymentAuditStatement> statement;
    std::shared_ptr<const PQRelayPlan> relay_plan;
    uint256 relay_group_id;
    uint64_t roster_source_generation{0};
    bool already_finalized{false};
    {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime_generation !=
                expected_runtime_generation ||
            !m_payment_audit_runtime ||
            !m_payment_audit_runtime->statement ||
            !m_payment_audit_runtime->relay_plan) {
            return false;
        }
        statement = m_payment_audit_runtime->statement;
        relay_plan = m_payment_audit_runtime->relay_plan;
        relay_group_id = m_payment_audit_runtime->relay_group_id;
        roster_source_generation =
            m_payment_audit_runtime->roster_source_generation;
        already_finalized =
            m_payment_audit_runtime->finalized.has_value();
    }
    if (already_finalized) {
        if (pqQuorumConnectionOverlay != nullptr &&
            !relay_group_id.IsNull()) {
            (void)pqQuorumConnectionOverlay->RemovePaymentAuditContext(
                relay_group_id, expected_runtime_generation);
        }
        return true;
    }
    if (!statement || relay_group_id.IsNull() ||
        relay_group_id !=
            pq::GetPaymentAuditLogicalId(m_genesis_hash, *statement) ||
        !IsPQRelayPlanForCurrentIdentityState(relay_plan) ||
        !IsQuorumRosterSourceGenerationCurrent(
            roster_source_generation) ||
        !IsCurrentPaymentAuditStatement(*statement)) {
        return false;
    }
    const bool has_relay_identity{
        IsPQRelayPlanForActiveIdentity(relay_plan)};
    if (pqQuorumConnectionOverlay != nullptr &&
        has_relay_identity &&
        !pqQuorumConnectionOverlay->ApplyPaymentAuditContext(
            relay_group_id, relay_plan->relay_members,
            expected_runtime_generation)) {
        return false;
    }

    bool exact{false};
    bool finalized{false};
    {
        LOCK(m_payment_audit_mutex);
        exact = m_payment_audit_runtime_generation ==
                    expected_runtime_generation &&
                m_payment_audit_runtime &&
                m_payment_audit_runtime->statement == statement &&
                m_payment_audit_runtime->relay_plan == relay_plan &&
                m_payment_audit_runtime->relay_group_id ==
                    relay_group_id &&
                m_payment_audit_runtime->roster_source_generation ==
                    roster_source_generation;
        finalized = exact &&
                    m_payment_audit_runtime->finalized.has_value();
    }
    if (finalized) {
        if (pqQuorumConnectionOverlay != nullptr) {
            (void)pqQuorumConnectionOverlay->RemovePaymentAuditContext(
                relay_group_id, expected_runtime_generation);
        }
        return true;
    }
    exact = exact &&
            IsPQRelayPlanForCurrentIdentityState(relay_plan) &&
            IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation) &&
            IsCurrentPaymentAuditStatement(*statement);
    if (!exact && pqQuorumConnectionOverlay != nullptr) {
        (void)pqQuorumConnectionOverlay->RemovePaymentAuditContext(
            relay_group_id, expected_runtime_generation);
    }
    return exact;
}

uint64_t CChainLocksHandler::PublishPaymentAuditRuntime(
    PaymentAuditResponseRuntime runtime)
{
    ReleasePaymentAuditOverlay();
    ++m_payment_audit_runtime_generation;
    m_payment_audit_runtime.emplace(std::move(runtime));
    return m_payment_audit_runtime_generation;
}

std::optional<pq::VerifiedRosterAuthorizationBaseView>
CChainLocksHandler::ResolvePaymentAuditSealRecord(
    const pq::ChainLockFinalityStore& store,
    const uint256& genesis_hash,
    const pq::ChainLockStatement& seal_statement)
{
    const uint256 logical_id{
        pq::GetLogicalChainLockId(genesis_hash, seal_statement)};
    const auto retained{
        store.GetVerifiedRosterAuthorizationBaseByLogicalId(logical_id)};
    if (!retained || logical_id.IsNull() || !retained->certificate ||
        !retained->verification_context ||
        retained->metadata.logical_id != logical_id ||
        retained->metadata.statement != seal_statement ||
        retained->certificate->statement != seal_statement ||
        retained->verification_context->Statement() != seal_statement ||
        retained->verification_context->StatementLogicalId() != logical_id) {
        return std::nullopt;
    }
    return retained;
}

bool CChainLocksHandler::PreparePaymentAuditSigningRuntime()
{
    if (!RefreshPaymentAuditStaging() || !m_store ||
        !m_payment_audit_store || !m_config ||
        !m_payment_audit_staging_store ||
        !pq::IsBTCHeaderPolicyEnabled()) {
        return false;
    }
    uint64_t current_roster_source_generation{0};
    const auto roster_cache{
        GetQuorumRosterCache(&current_roster_source_generation)};
    const uint64_t current_admission_generation{
        GetShareAdmissionGeneration()};
    if (!roster_cache || current_admission_generation == 0) return false;
    const uint256 current_relay_identity{
        GetActiveMasternodeRelayIdentity()};

    std::optional<pq::PaymentAuditStatement> cached_statement;
    uint64_t cached_runtime_generation{0};
    {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime &&
            (!m_payment_audit_runtime->relay_plan ||
             !IsPQRelayPlanForIdentityState(
                 m_payment_audit_runtime->relay_plan,
                 current_relay_identity) ||
             ShouldResetPaymentAuditRuntime(
                 m_payment_audit_runtime->finalized.has_value(),
                 m_payment_audit_runtime->finalized
                     ? m_payment_audit_runtime->finalized
                           ->admission_generation
                     : 0,
                 current_admission_generation,
                 m_payment_audit_runtime->roster_source_generation,
                 current_roster_source_generation))) {
            ResetPaymentAuditRuntime();
        }
        if (m_payment_audit_runtime &&
            m_payment_audit_runtime->collector &&
            m_payment_audit_runtime->statement &&
            m_payment_audit_runtime->seal_chainlock &&
            m_payment_audit_runtime->signing_rosters &&
            m_payment_audit_runtime->relay_plan &&
            pq::IsSigningRosterAuthorizationMask(
                m_payment_audit_runtime->authorization_mask)) {
            cached_statement = m_payment_audit_runtime->statement;
            cached_runtime_generation =
                m_payment_audit_runtime_generation;
        }
    }
    if (cached_statement &&
        IsCurrentPaymentAuditStatement(*cached_statement)) {
        const auto candidates{
            m_payment_audit_candidate_metadata_cache.GetOrBuild(
                *m_payment_audit_store, m_genesis_hash,
                cached_statement->commitment.seed.epoch)};
        if (!candidates) return false;
        if (!candidates->ContainsExactStatement(*cached_statement)) {
            if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                    candidates->candidate_revision)) {
                return false;
            }
            if (!ApplyPaymentAuditOverlay(
                    cached_runtime_generation) ||
                !m_payment_audit_store->IsCandidateRevisionCurrent(
                    candidates->candidate_revision)) {
                LOCK(m_payment_audit_mutex);
                if (m_payment_audit_runtime_generation ==
                    cached_runtime_generation) {
                    ResetPaymentAuditRuntime();
                }
                return false;
            }
            return true;
        }
    }

    std::vector<uint32_t> candidate_epochs;
    if (const auto active{
            m_payment_audit_staging_store->ActiveEpoch()}) {
        candidate_epochs.push_back(*active);
    }
    for (const uint32_t retained :
         m_payment_audit_staging_store->RetainedEpochs()) {
        if (std::find(candidate_epochs.begin(), candidate_epochs.end(),
                      retained) == candidate_epochs.end()) {
            candidate_epochs.push_back(retained);
        }
    }
    std::sort(candidate_epochs.begin(), candidate_epochs.end(),
              std::greater<uint32_t>{});

    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    for (const uint32_t epoch : candidate_epochs) {
        const auto schedule{pq::BuildPaymentAuditEpochSchedule(
            schedule_config, epoch)};
        if (!schedule) continue;
        const auto summaries{
            m_payment_audit_staging_store->GetEpochSummaries(epoch)};
        if (summaries.size() != pq::PAYMENT_AUDIT_ROW_COUNT) continue;

        std::array<std::optional<pq::PaymentAuditFrozenRowSummary>,
                   pq::PAYMENT_AUDIT_ROW_COUNT> rows;
        bool complete{true};
        uint256 subject_descriptor_hash;
        pq::QuorumBitmap subject_valid_members{};
        for (const auto& summary : summaries) {
            const std::size_t row{summary.identity.row_index};
            if (row >= rows.size() || rows[row] ||
                summary.identity.epoch != epoch ||
                summary.identity.response_height !=
                    schedule->rows[row].response_height ||
                summary.deadline_height !=
                    schedule->rows[row].deadline_height ||
                summary.response_advance != pq::BTCCAdvance::ADVANCE) {
                complete = false;
                break;
            }
            if (subject_descriptor_hash.IsNull()) {
                subject_descriptor_hash =
                    summary.identity.subject_descriptor_hash;
                subject_valid_members = summary.subject_valid_members;
            } else if (summary.identity.subject_descriptor_hash !=
                           subject_descriptor_hash ||
                       summary.subject_valid_members !=
                           subject_valid_members) {
                complete = false;
                break;
            }
            rows[row] = summary;
        }
        if (!complete || subject_descriptor_hash.IsNull() ||
            std::any_of(rows.begin(), rows.end(),
                        [](const auto& row) { return !row.has_value(); })) {
            continue;
        }

        std::optional<pq::FinalChainLockRecordMetadata> seal_metadata;
        if (const auto recent{
                m_store->GetRecordByHeight(schedule->seal_height)}) {
            seal_metadata = recent->metadata;
        } else if (const auto capsule{
                       m_persistence
                           ? m_persistence->LoadPaymentAuditSealContext()
                           : std::optional<
                                 pq::PaymentAuditSealContextCapsule>{}};
                   capsule && capsule->IsInternallyConsistent(
                                  m_genesis_hash, *m_config) &&
                   capsule->Epoch() == epoch &&
                   capsule->Seal().statement.height ==
                       schedule->seal_height &&
                   capsule->CarrierEndHeightExclusive() ==
                       schedule->carrier_end_height_exclusive) {
            seal_metadata = capsule->Seal();
        }
        auto seal_record{seal_metadata
            ? ResolvePaymentAuditSealRecord(
                  *m_store, m_genesis_hash,
                  seal_metadata->statement)
            : std::optional<
                  pq::VerifiedRosterAuthorizationBaseView>{}};
        if (seal_record && seal_record->metadata != *seal_metadata) {
            seal_record.reset();
        }
        const auto seal_chainlock{seal_record
            ? seal_record->certificate
            : CChainLockSigCPtr{}};
        if (!seal_chainlock ||
            seal_chainlock->statement.height != schedule->seal_height) {
            continue;
        }

        bool active_context{true};
        std::optional<pq::PaymentAuditSeedPoint> anchor_seed_point;
        {
            LOCK(cs_main);
            const CBlockIndex* tip{m_chainman.ActiveTip()};
            const CBlockIndex* seal{
                tip != nullptr && tip->nHeight >= schedule->seal_height
                    ? tip->GetAncestor(schedule->seal_height)
                    : nullptr};
            const auto seed_context{
                seal != nullptr
                    ? GetPaymentAuditSeedReceiptContext(
                          m_genesis_hash, schedule_config, *schedule, *seal)
                    : PaymentAuditSeedReceiptContext{}};
            active_context =
                tip != nullptr &&
                tip->nHeight < schedule->carrier_end_height_exclusive &&
                seal != nullptr &&
                seal->GetBlockHash() ==
                    seal_chainlock->statement.block_hash &&
                seed_context.status == PaymentAuditContextStatus::READY &&
                seed_context.seed_point.has_value();
            if (active_context) {
                anchor_seed_point = seed_context.seed_point;
            }
            for (const auto& row : rows) {
                if (!active_context) break;
                const auto& summary{*row};
                const CBlockIndex* response{tip->GetAncestor(
                    summary.identity.response_height)};
                const CBlockIndex* deadline{tip->GetAncestor(
                    summary.deadline_height)};
                active_context =
                    response != nullptr && deadline != nullptr &&
                    response->GetBlockHash() ==
                        summary.response_block_hash &&
                    deadline->GetBlockHash() ==
                        summary.deadline_block_hash;
            }
        }
        if (!active_context) continue;

        std::string reason;
        const bool backend_healthy{
            m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
                /*recover=*/true, reason)};
        const auto btc_config{
            backend_healthy
                ? pq::GetConfiguredBTCHeaderPolicy(reason)
                : std::optional<pq::BTCHeaderPolicyConfig>{}};
        const auto active_range{
            btc_config
                ? pq::MakeConfiguredBTCHeaderPolicy()
                      .CheckPaymentAuditActiveRange(
                          *btc_config,
                          anchor_seed_point->accepted_cursor.btc_hash,
                          GetTime(), reason)
                : std::optional<pq::BTCHeaderActiveRange>{}};
        if (!active_range) {
            LogPrint(BCLog::CHAINLOCKS,
                     "CChainLocksHandler::%s -- abstaining from payment "
                     "audit epoch %u: %s\n",
                     __func__, epoch, reason);
            continue;
        }

        pq::PaymentAuditSeed seed;
        seed.epoch = epoch;
        seed.anchor = *anchor_seed_point;
        seed.anchor_btc_height = active_range->anchor_height;
        seed.future_btc_height = active_range->future_height;
        seed.future_btc_hash = active_range->future_hash;
        const auto round{pq::SelectPaymentAuditRound(
            schedule_config, *schedule, m_genesis_hash,
            subject_descriptor_hash, seed)};
        if (!round) continue;
        const auto& selected{*rows[round->selected_row]};

        pq::PaymentAuditCommitment commitment;
        commitment.seed = seed;
        commitment.selected_row = round->selected_row;
        commitment.response_height = round->response_height;
        commitment.deadline_height = round->deadline_height;
        commitment.response_chainlock_logical_id =
            selected.identity.response_chainlock_logical_id;
        commitment.response_advance = selected.response_advance;
        commitment.seal_height = round->seal_height;
        commitment.subject_epoch = epoch;
        commitment.subject_quorum_base_hash.SetNull();
        commitment.subject_descriptor_hash = subject_descriptor_hash;
        commitment.subject_valid_members = subject_valid_members;
        commitment.previous_probation_state_hash =
            seal_chainlock->statement.payment_probation_state_hash;

        // Rebuilding the historical selected-row roster fills the one field
        // not carried by the compact staging summary and rejects any branch
        // or snapshot discontinuity before an audit key can be consumed.
        const pq::RosterBeaconSeed* subject_beacon{
            pq::FindRosterBeaconSeed(
                seal_chainlock->statement.roster_beacons.active,
                epoch)};
        std::unique_ptr<pq::FrozenQuorumRoster> response_subject;
        {
            LOCK(cs_main);
            const CBlockIndex* tip{m_chainman.ActiveTip()};
            const CBlockIndex* response{
                tip != nullptr && tip->nHeight >= round->response_height
                    ? tip->GetAncestor(round->response_height)
                    : nullptr};
            if (response == nullptr || response->GetBlockHash() !=
                                           selected.response_block_hash) {
                continue;
            }
            pq::QuorumBuildError build_error{
                pq::QuorumBuildError::NONE};
            if (subject_beacon != nullptr) {
                response_subject = BuildHistoricalFrozenRoster(
                    m_genesis_hash, *m_quorum_build_config,
                    *roster_cache, epoch, *response, *subject_beacon,
                    &build_error);
            }
        }
        if (!response_subject ||
            response_subject->descriptor.epoch != epoch ||
            response_subject->descriptor.valid_members !=
                subject_valid_members ||
            pq::GetPaymentAuditDescriptorHash(
                m_genesis_hash,
                response_subject->descriptor) !=
                subject_descriptor_hash) {
            continue;
        }
        commitment.subject_quorum_base_hash =
            response_subject->descriptor.base_hash;

        pq::PaymentAuditStatement statement{
            commitment, seal_chainlock->statement};
        if (!statement.IsStructurallyValid() ||
            !IsCurrentPaymentAuditStatement(statement)) {
            continue;
        }
        pq::RosterAuthorizationVerificationContext authorization;
        uint64_t roster_source_generation{0};
        auto signing_rosters{
            BuildPaymentAuditVerificationRosters(
                statement, nullptr, &authorization,
                /*require_live_transition_finality=*/true,
                /*status=*/nullptr, /*historical=*/nullptr,
                &roster_source_generation,
                /*reconstruction_floor=*/nullptr,
                /*defer_historical_provenance=*/false)};
        if (!signing_rosters) continue;
        const auto existing_candidates{
            m_payment_audit_candidate_metadata_cache.GetOrBuild(
                *m_payment_audit_store, m_genesis_hash, epoch)};
        if (!existing_candidates) return false;
        if (existing_candidates->ContainsExactStatement(statement)) {
            continue;
        }
        pq::ShareCollectionError collection_error{
            pq::ShareCollectionError::NONE};
        pq::PaymentAuditVerificationError audit_error{
            pq::PaymentAuditVerificationError::NONE};
        auto prepared_context{pq::PreparedPaymentAuditContext::Create(
            pq::PaymentAuditScheduleConfig{m_config->chainlock_schedule,
                                           m_config->btcc_schedule},
            statement, *seal_chainlock, signing_rosters,
            authorization,
            &audit_error)};
        if (!prepared_context) continue;
        const uint8_t authorization_mask{
            prepared_context->AuthorizationMask()};
        auto collector{pq::PaymentAuditCollector::Create(
            std::move(prepared_context), &collection_error)};
        if (!collector) continue;
        const auto signing_rosters_ptr{signing_rosters->RostersPtr()};

        const auto durable_selected{
            m_payment_audit_staging_store->GetSummary(
                epoch, round->selected_row)};
        if (!durable_selected || *durable_selected != selected ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation) ||
            !IsCurrentPaymentAuditStatement(statement)) {
            continue;
        }
        auto relay_plan{BuildPQRelayPlanForCurrentIdentity(
            *signing_rosters_ptr)};
        if (!relay_plan) continue;
        const uint256 relay_group_id{
            pq::GetPaymentAuditLogicalId(m_genesis_hash, statement)};
        if (relay_group_id.IsNull()) continue;

        // Bind publication to both immutable sources. If either changes
        // across publication, retire only the runtime installed by this pass.
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                existing_candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation) ||
            !IsPQRelayPlanForCurrentIdentityState(relay_plan)) {
            return false;
        }
        uint64_t published_generation{0};
        {
            LOCK(m_payment_audit_mutex);
            published_generation = PublishPaymentAuditRuntime(
                PaymentAuditResponseRuntime{
                    *round, selected, statement, *seal_chainlock,
                    signing_rosters_ptr, relay_plan, relay_group_id,
                    authorization_mask, roster_source_generation,
                    std::move(collector), std::nullopt, std::nullopt,
                    false, false});
        }
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                existing_candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation) ||
            !IsPQRelayPlanForCurrentIdentityState(relay_plan) ||
            !ApplyPaymentAuditOverlay(published_generation) ||
            !m_payment_audit_store->IsCandidateRevisionCurrent(
                existing_candidates->candidate_revision)) {
            LOCK(m_payment_audit_mutex);
            if (m_payment_audit_runtime_generation ==
                published_generation) {
                ResetPaymentAuditRuntime();
            }
            return false;
        }
        return true;
    }

    LOCK(m_payment_audit_mutex);
    ResetPaymentAuditRuntime();
    return false;
}

bool CChainLocksHandler::IsCurrentPaymentAuditStatement(
    const pq::PaymentAuditStatement& statement) const
{
    if (!statement.IsStructurallyValid() || !m_store || !m_config) {
        return false;
    }
    const auto seal_record{ResolvePaymentAuditSealRecord(
        *m_store, m_genesis_hash, statement.seal_statement)};
    const auto seal{seal_record ? seal_record->certificate
                                : CChainLockSigCPtr{}};
    if (!seal || seal->statement != statement.seal_statement) {
        return false;
    }
    LOCK(cs_main);
    if (IsPaymentAuditPresealActive()) return false;
    if (m_chainman.IsSnapshotActive() &&
        !m_chainman.IsSnapshotValidated()) {
        return false;
    }
    const CBlockIndex* tip{m_chainman.ActiveTip()};
    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, statement.commitment.subject_epoch)};
    if (tip == nullptr || !schedule ||
        !IsPaymentAuditSigningHeightLive(
            schedule_config, statement.commitment.subject_epoch,
            tip->nHeight)) {
        return false;
    }
    const CBlockIndex* active{
        m_chainman.ActiveChain()[statement.commitment.seal_height]};
    if (active == nullptr ||
        active->GetBlockHash() != statement.seal_statement.block_hash ||
        ClassifyPaymentAuditSealContextCached(
            active, statement.commitment.seal_height,
            statement.seal_statement.previous_chainlock_height,
            statement.seal_statement.previous_chainlock_hash,
            PaymentAuditSealValidation::LIVE_EXACT) !=
            PaymentAuditContextStatus::READY) {
        return false;
    }
    const auto indexed_btcc{IndexedBTCCReceiptState(*active)};
    const auto indexed_audit{IndexedPaymentAuditReceiptState(*active)};
    const auto seed_context{
        GetPaymentAuditSeedReceiptContext(
            m_genesis_hash, schedule_config, *schedule, *active)};
    pq::BTCCValidationError btcc_error{pq::BTCCValidationError::NONE};
    return indexed_btcc &&
           *indexed_btcc == statement.seal_statement.btcc_receipt_state &&
           indexed_audit &&
           *indexed_audit ==
               statement.seal_statement.payment_audit_receipt_state &&
           active->pqPaymentProbationStateHash ==
               statement.seal_statement.payment_probation_state_hash &&
           active->pqPaymentProbationStateHash ==
               statement.commitment.previous_probation_state_hash &&
           seed_context.status == PaymentAuditContextStatus::READY &&
           seed_context.seed_point &&
           *seed_context.seed_point == statement.commitment.seed.anchor &&
           pq::ValidateBTCCursorTransition(
               m_config->btcc_schedule, *active,
               statement.seal_statement.previous_btcc_cursor,
               statement.seal_statement.accepted_btcc_cursor,
               statement.seal_statement.btcc_advance, &btcc_error);
}

bool CChainLocksHandler::HasExactPaymentAuditRuntime(
    uint64_t expected_runtime_generation,
    const pq::PaymentAuditStatement& statement,
    const pq::PreparedPaymentAuditContextPtr& prepared_context,
    const std::shared_ptr<const PQRelayPlan>& relay_plan) const
{
    if (!prepared_context ||
        !IsPQRelayPlanForCurrentIdentityState(relay_plan)) {
        return false;
    }
    LOCK(m_payment_audit_mutex);
    const bool runtime_present{m_payment_audit_runtime.has_value()};
    const bool collector_present{
        runtime_present && m_payment_audit_runtime->collector != nullptr};
    const auto current_context{
        collector_present
            ? m_payment_audit_runtime->collector->GetPreparedContext()
            : nullptr};
    return IsExactPaymentAuditRuntimeBinding(
        runtime_present,
        collector_present,
        m_payment_audit_runtime_generation == expected_runtime_generation,
        runtime_present && m_payment_audit_runtime->statement &&
            *m_payment_audit_runtime->statement == statement &&
            prepared_context->Statement() == statement,
        current_context == prepared_context &&
            m_payment_audit_runtime->signing_rosters ==
                prepared_context->RostersPtr() &&
            m_payment_audit_runtime->authorization_mask ==
                prepared_context->AuthorizationMask(),
        runtime_present && m_payment_audit_runtime->relay_plan &&
            m_payment_audit_runtime->relay_plan == relay_plan);
}

bool CChainLocksHandler::HasExactPaymentAuditFinalization(
    const LocalPaymentAuditFinalization& finalized) const
{
    if (!finalized.proof) return false;
    LOCK(m_payment_audit_mutex);
    return m_payment_audit_runtime_generation ==
               finalized.runtime_generation &&
           m_payment_audit_runtime &&
           m_payment_audit_runtime->finalization_attempt_in_flight &&
           m_payment_audit_runtime->finalized &&
           m_payment_audit_runtime->finalized->proof == finalized.proof &&
           m_payment_audit_runtime->finalized->admission_generation ==
               finalized.admission_generation &&
           m_payment_audit_runtime->finalized->runtime_generation ==
               finalized.runtime_generation &&
           m_payment_audit_runtime->finalized->roster_source_generation ==
               finalized.roster_source_generation &&
           m_payment_audit_runtime->roster_source_generation ==
               finalized.roster_source_generation &&
           m_payment_audit_runtime->collector &&
           m_payment_audit_runtime->collector->GetPreparedContext() ==
               finalized.proof->ContextPtr() &&
           m_payment_audit_runtime->statement &&
           *m_payment_audit_runtime->statement ==
               finalized.proof->Certificate().statement;
}

void CChainLocksHandler::RelayPaymentAuditShare(
    const pq::PaymentAuditShare& share,
    const pq::PreparedPaymentAuditContextPtr& prepared_context,
    const std::shared_ptr<const PQRelayPlan>& relay_plan,
    uint64_t runtime_generation,
    uint64_t admission_generation,
    uint256 excluded_identity)
{
    LOCK(m_share_lifecycle_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    if (!HasExactPaymentAuditRuntime(
            runtime_generation, share.transcript.statement,
            prepared_context, relay_plan) ||
        !IsCurrentPaymentAuditStatement(share.transcript.statement)) {
        return;
    }
    PQRelayIdentityGate relay_gate{excluded_identity};
    m_connman.ForEachNode([&](CNode* node) {
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        if (node == nullptr || node->fDisconnect ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
            return;
        }
        const uint256 identity{node->GetVerifiedProRegTxHash()};
        if (!relay_gate.Admit(
                identity,
                relay_plan->authorized_recipients.contains(identity),
                relay_plan->relay_members.contains(identity))) {
            return;
        }
        m_connman.PushMessage(
            node, CNetMsgMaker(node->GetCommonVersion())
                      .Make(NetMsgType::PQPOSESHARE, share));
    });
}

CChainLocksHandler::PaymentAuditShareCollectionOutcome
CChainLocksHandler::CollectPaymentAuditShare(
    const pq::PaymentAuditShare& share,
    const pq::PaymentAuditStatement& statement,
    uint64_t admission_generation,
    uint64_t expected_runtime_generation)
{
    PaymentAuditShareCollectionOutcome outcome;
    std::optional<
        pq::PaymentAuditCollector::ShareVerificationReservation> reservation;
    {
        LOCK(m_payment_audit_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_payment_audit_runtime_generation !=
                expected_runtime_generation ||
            !m_payment_audit_runtime ||
            !m_payment_audit_runtime->collector ||
            !m_payment_audit_runtime->statement ||
            *m_payment_audit_runtime->statement != statement) {
            if (m_payment_audit_runtime_generation ==
                expected_runtime_generation) {
                ResetPaymentAuditRuntime();
            }
            outcome.stale = true;
            return outcome;
        }
        if (m_payment_audit_runtime->finalized) {
            outcome.closed = true;
            return outcome;
        }
        auto pending{
            m_payment_audit_runtime->collector->ReserveShareVerification(
                share, &outcome.error)};
        if (pending) {
            reservation.emplace(std::move(*pending));
        } else {
            outcome.result = outcome.error ==
                    pq::ShareCollectionError::DUPLICATE
                ? pq::ShareCollectionResult::DUPLICATE
                : pq::ShareCollectionResult::REJECTED;
            outcome.accepted_duplicate =
                outcome.result == pq::ShareCollectionResult::DUPLICATE &&
                m_payment_audit_runtime->collector->HasAcceptedShare(
                    share.transcript);
        }
    }

    const auto retire_if_exact = [&]() {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime_generation ==
            expected_runtime_generation) {
            ResetPaymentAuditRuntime();
        }
    };
    const auto is_current = [&]() {
        return IsShareAdmissionGenerationCurrent(admission_generation) &&
               IsCurrentPaymentAuditStatement(statement);
    };

    if (!reservation) {
        if (outcome.result == pq::ShareCollectionResult::DUPLICATE) {
            return outcome;
        }
        if (!is_current()) {
            retire_if_exact();
            outcome.stale = true;
        }
        return outcome;
    }

    if (!is_current()) {
        retire_if_exact();
        outcome.stale = true;
        return outcome;
    }

    try {
        pq::PaymentAuditCollector::VerifyReservedShare(*reservation);
    } catch (const std::exception&) {
        // Completion below releases the exact pending slot as a local error.
    }

    if (!is_current()) {
        retire_if_exact();
        outcome.stale = true;
        return outcome;
    }

    {
        LOCK(m_payment_audit_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_payment_audit_runtime_generation !=
                expected_runtime_generation ||
            !m_payment_audit_runtime ||
            !m_payment_audit_runtime->collector ||
            !m_payment_audit_runtime->statement ||
            *m_payment_audit_runtime->statement != statement) {
            if (m_payment_audit_runtime_generation ==
                expected_runtime_generation) {
                ResetPaymentAuditRuntime();
            }
            outcome.stale = true;
            return outcome;
        }
        outcome.closed = static_cast<bool>(
            m_payment_audit_runtime->finalized);
        outcome.result =
            m_payment_audit_runtime->collector->CompleteShareVerification(
                std::move(*reservation), &outcome.error);
        if (!outcome.closed &&
            outcome.result == pq::ShareCollectionResult::ACCEPTED) {
            auto proof{
                m_payment_audit_runtime->collector->FinalizeCollection()};
            if (proof) {
                LocalPaymentAuditFinalization finalized{
                    std::move(proof), admission_generation,
                    expected_runtime_generation,
                    m_payment_audit_runtime->roster_source_generation};
                outcome.finalized = finalized;
                m_payment_audit_runtime->finalized =
                    std::move(finalized);
                ReleasePaymentAuditOverlay();
                m_payment_audit_runtime->finalization_last_attempt =
                    GetTime<std::chrono::microseconds>();
                m_payment_audit_runtime->finalization_attempt_in_flight =
                    true;
            }
        }
    }

    if (!is_current()) {
        retire_if_exact();
        outcome.finalized.reset();
        outcome.stale = true;
    }
    return outcome;
}

void CChainLocksHandler::ProcessPaymentAuditShare(
    CNode* from, CDataStream& payload)
{
    const uint64_t admission_generation{GetShareAdmissionGeneration()};
    if (admission_generation == 0) return;
    if (from == nullptr ||
        from->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        if (from != nullptr) from->fDisconnect = true;
        return;
    }
    const NodeId node_id{from->GetId()};
    const auto punish = [&](const char* reason) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, reason);
        }
    };
    const uint256 peer_identity{from->GetVerifiedProRegTxHash()};
    if (peer_identity.IsNull()) {
        punish("unauthenticated-pq-payment-audit-share");
        return;
    }
    if (payload.size() != pq::PaymentAuditShare::WIRE_SIZE) {
        punish("bad-pq-payment-audit-share-size");
        return;
    }
    pq::PaymentAuditShare share;
    try {
        payload >> share;
        if (!payload.empty()) {
            throw std::ios_base::failure(
                "trailing payment-audit share bytes");
        }
    } catch (const std::exception&) {
        punish("bad-pq-payment-audit-share-encoding");
        return;
    }
    std::shared_ptr<const PQRelayPlan> relay_plan;
    pq::PreparedPaymentAuditContextPtr prepared_context;
    uint64_t runtime_generation{0};
    {
        // Runtime construction belongs to the scheduler. This lock admits a
        // share only to an already-authenticated, generation-bound collector.
        LOCK(m_payment_audit_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        if (!m_payment_audit_runtime ||
            !m_payment_audit_runtime->collector ||
            !m_payment_audit_runtime->statement ||
            !m_payment_audit_runtime->signing_rosters ||
            !m_payment_audit_runtime->relay_plan) {
            return;
        }
        relay_plan = m_payment_audit_runtime->relay_plan;
        if (!relay_plan->authorized_recipients.contains(peer_identity) ||
            share.transcript.statement !=
                *m_payment_audit_runtime->statement) {
            return;
        }
        if (m_payment_audit_runtime->finalized) return;
        prepared_context =
            m_payment_audit_runtime->collector->GetPreparedContext();
        if (!prepared_context) return;
        runtime_generation = m_payment_audit_runtime_generation;
    }

    auto collection{CollectPaymentAuditShare(
        share, share.transcript.statement, admission_generation,
        runtime_generation)};
    if (collection.stale || collection.closed) return;
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
        if (collection.finalized) {
            FinishPaymentAuditFinalizationAttempt(
                *collection.finalized);
        }
        return;
    }
    if (collection.result != pq::ShareCollectionResult::ACCEPTED) {
        if (collection.error ==
            pq::ShareCollectionError::INVALID_SIGNATURE) {
            punish("bad-pq-payment-audit-share-signature");
        }
        return;
    }
    if (!HasExactPaymentAuditRuntime(
            runtime_generation, share.transcript.statement,
            prepared_context, relay_plan) ||
        !IsCurrentPaymentAuditStatement(share.transcript.statement)) {
        if (collection.finalized) {
            FinishPaymentAuditFinalizationAttempt(
                *collection.finalized);
        }
        return;
    }
    RelayPaymentAuditShare(
        share, prepared_context, relay_plan,
        runtime_generation, admission_generation, peer_identity);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
        if (collection.finalized) {
            FinishPaymentAuditFinalizationAttempt(
                *collection.finalized);
        }
        return;
    }
    if (collection.finalized) {
        LOCK(m_share_lifecycle_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
            FinishPaymentAuditFinalizationAttempt(
                *collection.finalized);
            return;
        }
        SubmitPaymentAuditFinalizationAttempt(*collection.finalized);
    }
}

CChainLocksHandler::ChainLockShareCollectionOutcome
CChainLocksHandler::CollectChainLockShare(
    const pq::ChainLockShare& share,
    CurrentSigningContextsPtr signing_contexts,
    std::size_t variant_index,
    uint64_t admission_generation)
{
    ChainLockShareCollectionOutcome outcome;
    if (!signing_contexts ||
        variant_index >= signing_contexts->count ||
        share.GetStatement() !=
            signing_contexts->statements[variant_index]) {
        outcome.stale = true;
        return outcome;
    }
    const pq::ChainLockStatement& statement{
        signing_contexts->statements[variant_index]};
    uint64_t collector_generation{0};
    std::optional<
        pq::ChainLockCollector::ShareVerificationReservation> reservation;
    {
        LOCK(m_collector_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_current_signing_contexts != signing_contexts ||
            variant_index >= signing_contexts->count) {
            outcome.stale = true;
            return outcome;
        }
        if (!m_collectors[variant_index]) {
            outcome.stale = true;
            return outcome;
        }
        collector_generation = m_collector_generation;
        outcome.collector_generation = collector_generation;
    }

    const auto retire_if_exact = [&]() {
        LOCK(m_collector_mutex);
        if (m_collector_generation == collector_generation &&
            m_current_signing_contexts == signing_contexts) {
            ResetCollectors();
        }
    };
    const auto has_exact_collector = [&]() {
        LOCK(m_collector_mutex);
        return m_collector_generation == collector_generation &&
               m_current_signing_contexts == signing_contexts &&
               variant_index < signing_contexts->count &&
               m_collectors[variant_index] != nullptr &&
               m_collectors[variant_index]->GetStatement() == statement;
    };
    const auto is_current = [&]() {
        return IsShareAdmissionGenerationCurrent(admission_generation) &&
               IsCurrentSigningSource(signing_contexts->source) &&
               has_exact_collector();
    };
    if (!is_current()) {
        retire_if_exact();
        outcome.stale = true;
        return outcome;
    }

    {
        LOCK(m_collector_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_collector_generation != collector_generation ||
            m_current_signing_contexts != signing_contexts ||
            !m_collectors[variant_index]) {
            outcome.stale = true;
            return outcome;
        }
        pq::ChainLockCollector* collector{
            m_collectors[variant_index].get()};
        auto pending{collector->ReserveShareVerification(
            share, &outcome.error)};
        if (pending) {
            reservation.emplace(std::move(*pending));
        } else {
            outcome.result = outcome.error ==
                    pq::ShareCollectionError::DUPLICATE
                ? pq::ShareCollectionResult::DUPLICATE
                : pq::ShareCollectionResult::REJECTED;
        }
    }
    if (!reservation) {
        if (outcome.result == pq::ShareCollectionResult::DUPLICATE) {
            return outcome;
        }
        if (!is_current()) {
            retire_if_exact();
            outcome.stale = true;
        }
        return outcome;
    }

    try {
        pq::ChainLockCollector::VerifyReservedShare(*reservation);
    } catch (const std::exception&) {
        // Completion below classifies an unverified reservation as local and
        // releases its exact pending slot.
    }

    if (!is_current()) {
        retire_if_exact();
        outcome.stale = true;
        return outcome;
    }

    {
        LOCK(m_collector_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            m_collector_generation != collector_generation ||
            m_current_signing_contexts != signing_contexts) {
            if (m_collector_generation == collector_generation &&
                m_current_signing_contexts == signing_contexts) {
                ResetCollectors();
            }
            outcome.stale = true;
            return outcome;
        }
        pq::ChainLockCollector* collector{
            m_collectors[variant_index].get()};
        if (collector == nullptr) {
            ResetCollectors();
            outcome.stale = true;
            return outcome;
        }
        outcome.result = collector->CompleteShareVerification(
            std::move(*reservation), &outcome.error);
        if (outcome.result == pq::ShareCollectionResult::ACCEPTED) {
            auto proof{collector->FinalizeCollection()};
            if (proof) {
                outcome.finalized.emplace(LocalChainLockFinalization{
                    std::move(proof), signing_contexts, variant_index,
                    admission_generation,
                    collector_generation});
            }
        }
    }

    if (!is_current()) {
        retire_if_exact();
        outcome.finalized.reset();
        outcome.stale = true;
    }
    return outcome;
}

void CChainLocksHandler::ProcessChainLockShare(CNode* from,
                                               CDataStream& payload)
{
    const uint64_t admission_generation{GetShareAdmissionGeneration()};
    if (admission_generation == 0) return;
    if (from == nullptr || from->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        if (from != nullptr) from->fDisconnect = true;
        return;
    }
    const NodeId node_id{from->GetId()};
    const auto punish = [&](int score, const char* reason) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, score, reason);
        }
    };
    const uint256 peer_identity{from->GetVerifiedProRegTxHash()};
    if (peer_identity.IsNull()) {
        punish(100, "unauthenticated-pq-clshare");
        return;
    }
    if (payload.size() != pq::CompactChainLockShare::WIRE_SIZE) {
        punish(100, "bad-pq-clshare-size");
        return;
    }

    pq::CompactChainLockShare compact;
    try {
        payload >> compact;
        if (!payload.empty()) {
            throw std::ios_base::failure("trailing PQ ChainLock share bytes");
        }
    } catch (const std::exception&) {
        punish(100, "bad-pq-clshare-encoding");
        return;
    }
    // Network ingress may consume scheduler-minted immutable state but never
    // build chain, receipt, roster, or collector context on a peer's behalf.
    auto contexts{GetPublishedCurrentSigningContexts(
        admission_generation)};
    const auto current{contexts ? contexts->Find(
                                      compact.statement_logical_id)
                                : std::nullopt};
    if (!current || !current->rosters || !contexts->relay_plan) {
        // An envelope can race publication of its exact immutable context.
        // Local deterministic journal replay will announce it again.
        return;
    }
    const auto& prepared_context{
        contexts->prepared_contexts[current->variant_index]};
    const auto expanded{prepared_context
        ? pq::ExpandCompactChainLockShare(compact, *prepared_context)
        : std::nullopt};
    if (!expanded) return;
    const pq::ChainLockShare& share{*expanded};
    if (!IsAuthorizedChainLockShareRelay(
            *current->rosters,
            contexts->relay_plan->authorized_recipients,
            peer_identity, share.transcript)) {
        // Shares are multi-hop gossip. The authenticated transport peer must
        // belong to an active roster, while the signed transcript identifies
        // the original member and is checked by the collector below. A share
        // can race a tip/predecessor change, which is not misbehavior.
        return;
    }

    auto collection{CollectChainLockShare(
        share, contexts, current->variant_index,
        admission_generation)};
    if (collection.stale ||
        !IsShareAdmissionGenerationCurrent(admission_generation)) {
        return;
    }
    if (collection.result != pq::ShareCollectionResult::ACCEPTED) {
        if (collection.error == pq::ShareCollectionError::LOCAL_ERROR) {
            return;
        }
        if (collection.error ==
            pq::ShareCollectionError::INVALID_SIGNATURE) {
            punish(100, "bad-pq-clshare-signature");
        } else if (collection.result ==
                   pq::ShareCollectionResult::REJECTED) {
            punish(100, "bad-pq-clshare-context");
        }
        return;
    }
    const auto collection_is_current = [&]() {
        if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
            !IsCurrentSigningSource(contexts->source)) {
            return false;
        }
        LOCK(m_collector_mutex);
        return m_collector_generation ==
                   collection.collector_generation &&
               m_current_signing_contexts == contexts &&
               current->variant_index < contexts->count &&
               m_collectors[current->variant_index] != nullptr &&
               m_collectors[current->variant_index]->GetStatement() ==
                   share.GetStatement();
    };
    // Verification runs outside the collector lock. Bind both subsequent
    // side effects to the exact capability generation that accepted it.
    if (!collection_is_current()) return;
    MaybeCapturePaymentAuditResponse(
        share, current->rosters, admission_generation);
    if (!collection_is_current()) return;
    RelayChainLockShare(share, contexts, current->variant_index,
                        admission_generation, peer_identity);

    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    if (collection.finalized) {
        LOCK(m_share_lifecycle_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        BlockValidationState state;
        if (!ProcessCollectedChainLock(*collection.finalized, state)) {
            LogPrint(BCLog::CHAINLOCKS,
                     "CChainLocksHandler::%s -- locally collected PQ "
                     "ChainLock was rejected: %s\n",
                     __func__, state.ToString());
        }
    }
}

pq::VerifiedRosterSetPtr
CChainLocksHandler::BuildPaymentAuditVerificationRosters(
    const pq::PaymentAuditStatement& statement,
    pq::FrozenQuorumRoster* subject_out,
    pq::RosterAuthorizationVerificationContext* authorization_out,
    bool require_live_transition_finality,
    PaymentAuditRosterBuildStatus* status,
    const PaymentAuditHistoricalContext* historical,
    uint64_t* roster_source_generation_out,
    int32_t* reconstruction_floor_out,
    bool defer_historical_provenance) const
{
    if (status != nullptr) {
        *status = PaymentAuditRosterBuildStatus::INVALID;
    }
    if (authorization_out != nullptr) {
        *authorization_out = {};
    }
    if (roster_source_generation_out != nullptr) {
        *roster_source_generation_out = 0;
    }
    if (reconstruction_floor_out != nullptr) {
        *reconstruction_floor_out = -1;
    }
    if (!statement.IsStructurallyValid() ||
        (historical != nullptr && require_live_transition_finality)) {
        return nullptr;
    }
    if (!m_config || !m_quorum_build_config) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    const auto expected_seal{pq::NextEligibleChainLockTargetHeight(
        m_config->chainlock_schedule,
        statement.seal_statement.previous_chainlock_height)};
    if (!expected_seal || statement.commitment.seal_height !=
                              *expected_seal) {
        return nullptr;
    }
    uint64_t roster_source_generation{0};
    const auto roster_cache{
        GetQuorumRosterCache(&roster_source_generation)};
    if (!roster_cache) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }

    const pq::PaymentAuditScheduleConfig schedule_config{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const auto epoch_schedule{pq::BuildPaymentAuditEpochSchedule(
        schedule_config, statement.commitment.seed.epoch)};
    const auto round{
        epoch_schedule
            ? pq::SelectPaymentAuditRound(
                  schedule_config, *epoch_schedule, m_genesis_hash,
                  statement.commitment.subject_descriptor_hash,
                  statement.commitment.seed)
            : std::nullopt};
    if (!round || round->selected_row !=
                      statement.commitment.selected_row ||
        round->response_height != statement.commitment.response_height ||
        round->deadline_height != statement.commitment.deadline_height ||
        round->seal_height != statement.commitment.seal_height) {
        return nullptr;
    }

    LOCK(cs_main);
    if (m_chainman.IsSnapshotActive() &&
        !m_chainman.IsSnapshotValidated()) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    const CBlockIndex* seal{
        m_chainman.m_blockman.LookupBlockIndex(
            statement.seal_statement.block_hash)};
    const auto seal_status{ClassifyPaymentAuditSealContextCached(
        seal, round->seal_height,
        statement.seal_statement.previous_chainlock_height,
        statement.seal_statement.previous_chainlock_hash,
        historical == nullptr
            ? PaymentAuditSealValidation::LIVE_EXACT
            : PaymentAuditSealValidation::THRESHOLD_ATTESTED_HISTORY)};
    if (seal_status != PaymentAuditContextStatus::READY) {
        if (status != nullptr &&
            seal_status == PaymentAuditContextStatus::LOCAL_ERROR) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (statement.seal_statement.previous_chainlock_height <
            m_config->activation_predecessor_height) {
        return nullptr;
    }
    const auto indexed_btcc{IndexedBTCCReceiptState(*seal)};
    const auto indexed_audit{IndexedPaymentAuditReceiptState(*seal)};
    pq::BTCCValidationError btcc_error{pq::BTCCValidationError::NONE};
    if (!indexed_btcc || !indexed_audit) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (*indexed_btcc != statement.seal_statement.btcc_receipt_state ||
        *indexed_audit !=
            statement.seal_statement.payment_audit_receipt_state ||
        seal->pqPaymentProbationStateHash !=
            statement.seal_statement.payment_probation_state_hash ||
        !pq::ValidateBTCCursorTransition(
            m_config->btcc_schedule, *seal,
            statement.seal_statement.previous_btcc_cursor,
            statement.seal_statement.accepted_btcc_cursor,
            statement.seal_statement.btcc_advance, &btcc_error)) {
        return nullptr;
    }
    const auto seed_context{GetPaymentAuditSeedReceiptContext(
        m_genesis_hash, schedule_config, *epoch_schedule, *seal)};
    if (seed_context.status != PaymentAuditContextStatus::READY) {
        if (status != nullptr &&
            seed_context.status == PaymentAuditContextStatus::LOCAL_ERROR) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (!seed_context.seed_point ||
        *seed_context.seed_point != statement.commitment.seed.anchor) {
        return nullptr;
    }
    if (m_store) {
        const auto predecessor{m_store->GetByHeight(
            statement.seal_statement.previous_chainlock_height)};
        if (predecessor &&
            (predecessor->statement.block_hash !=
                 statement.seal_statement.previous_chainlock_hash ||
             predecessor->statement.accepted_btcc_cursor !=
                 statement.seal_statement.previous_btcc_cursor)) {
            return nullptr;
        }
    }

    const CBlockIndex* historical_carrier{nullptr};
    if (historical != nullptr) {
        const auto& receipt{historical->dependency.receipt};
        historical_carrier = m_chainman.m_blockman.LookupBlockIndex(
            historical->dependency.carrier_hash);
        if (historical_carrier == nullptr) {
            if (status != nullptr) {
                *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
            }
            return nullptr;
        }
        if (historical_carrier->nHeight != receipt.carrier_height ||
            historical_carrier->pprev == nullptr ||
            historical_carrier->pprev->GetBlockHash() !=
                historical->dependency.carrier_parent_hash ||
            (historical_carrier->nStatus & BLOCK_FAILED_MASK) ||
            receipt.epoch != statement.commitment.seed.epoch ||
            receipt.seal_height != statement.commitment.seal_height ||
            receipt.seal_block_hash !=
                statement.seal_statement.block_hash ||
            receipt.audit_logical_id != pq::GetPaymentAuditLogicalId(
                m_genesis_hash, statement) ||
            receipt.commitment_hash != pq::GetPaymentAuditCommitmentHash(
                m_genesis_hash, statement.commitment) ||
            historical_carrier->GetAncestor(seal->nHeight) != seal) {
            return nullptr;
        }
    }
    const auto accepted_seal_record{m_store
        ? ResolvePaymentAuditSealRecord(
              *m_store, m_genesis_hash, statement.seal_statement)
        : std::optional<pq::VerifiedRosterAuthorizationBaseView>{}};
    const auto accepted_seal{accepted_seal_record
        ? accepted_seal_record->certificate
        : CChainLockSigCPtr{}};
    const bool exact_accepted_seal{
        accepted_seal &&
        accepted_seal->statement == statement.seal_statement};
    pq::PreparedChainLockContextPtr seal_context{
        exact_accepted_seal && accepted_seal_record &&
                accepted_seal_record->verification_context &&
                accepted_seal_record->verification_context->Statement() ==
                    statement.seal_statement
            ? accepted_seal_record->verification_context
            : pq::PreparedChainLockContextPtr{}};
    const bool independently_covered_history{
        historical_carrier != nullptr &&
        IsPaymentAuditPrefixAuthenticated(*historical_carrier)};
    if (!exact_accepted_seal && !independently_covered_history) {
        return nullptr;
    }
    const CBlockIndex* response{
        seal->GetAncestor(round->response_height)};
    const auto response_status{ClassifyPaymentAuditResponseContext(
        response, require_live_transition_finality)};
    if (response_status != PaymentAuditContextStatus::READY) {
        if (status != nullptr &&
            response_status == PaymentAuditContextStatus::LOCAL_ERROR) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }

    if (!seal_context && independently_covered_history && m_persistence) {
        const auto capsule{
            m_persistence->LoadPaymentAuditSealContext()};
        if (capsule &&
            capsule->IsInternallyConsistent(m_genesis_hash, *m_config) &&
            capsule->Epoch() == statement.commitment.seed.epoch &&
            capsule->CarrierEndHeightExclusive() ==
                epoch_schedule->carrier_end_height_exclusive &&
            historical_carrier->nHeight >=
                epoch_schedule->carrier_start_height &&
            historical_carrier->nHeight <
                capsule->CarrierEndHeightExclusive() &&
            capsule->Seal().statement == statement.seal_statement) {
            pq::QuorumBuildError build_error{
                pq::QuorumBuildError::NONE};
            const auto& recovery_authority{
                capsule->RecoveryAuthority()};
            const auto roster_set{recovery_authority
                ? roster_cache->GetVerifiedActiveWithRecoveryAuthority(
                      statement.seal_statement.height, *seal,
                      statement.seal_statement.roster_beacons.active,
                      recovery_authority, /*publish=*/false,
                      &build_error)
                : roster_cache->GetVerifiedActiveNoPublish(
                      statement.seal_statement.height, *seal,
                      statement.seal_statement.roster_beacons.active,
                      &build_error)};
            if (roster_set) {
                pq::RosterAuthorizationVerificationContext
                    trusted_authorization;
                trusted_authorization.admission =
                    pq::RosterAuthorizationAdmission::
                        TRUSTED_PERSISTENCE;
                trusted_authorization.predecessor_height =
                    statement.seal_statement
                        .previous_chainlock_height;
                trusted_authorization.predecessor_block_hash =
                    statement.seal_statement
                        .previous_chainlock_hash;
                pq::ChainLockVerificationError verification_error{
                    pq::ChainLockVerificationError::NONE};
                auto rebuilt{pq::PreparedChainLockContext::Create(
                    m_config->chainlock_schedule,
                    statement.seal_statement, roster_set,
                    trusted_authorization, &verification_error,
                    recovery_authority)};
                if (rebuilt && rebuilt->AuthorizationMask() ==
                                   capsule->AuthorizationMask()) {
                    seal_context = std::move(rebuilt);
                }
            }
        }
    }
    if (!seal_context) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    const auto seal_rosters{seal_context->RosterSetPtr()};
    if (!seal_rosters) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    const std::optional<uint8_t> authorization_mask{
        seal_context->AuthorizationMask()};
    if (!authorization_mask ||
        !pq::IsSigningRosterAuthorizationMask(*authorization_mask)) {
        return nullptr;
    }
    const auto& authorization{seal_context->Authorization()};
    const pq::RosterBeaconSeed* subject_beacon{pq::FindRosterBeaconSeed(
        statement.seal_statement.roster_beacons.active,
        statement.commitment.subject_epoch)};
    if (subject_beacon == nullptr ||
        subject_beacon->anchor_kind !=
            pq::RosterBeaconAnchorKind::NORMAL) {
        return nullptr;
    }
    const auto subject_it{std::find_if(
        seal_rosters->Rosters().begin(),
        seal_rosters->Rosters().end(),
        [&](const pq::FrozenQuorumRoster& roster) {
            return roster.descriptor.epoch ==
                statement.commitment.subject_epoch;
        })};
    if (subject_it == seal_rosters->Rosters().end()) {
        return nullptr;
    }
    const auto& subject{subject_it->descriptor};
    if (subject.epoch != statement.commitment.subject_epoch ||
        subject.base_hash !=
            statement.commitment.subject_quorum_base_hash ||
        subject.valid_members !=
            statement.commitment.subject_valid_members ||
        pq::GetPaymentAuditDescriptorHash(m_genesis_hash, subject) !=
            statement.commitment.subject_descriptor_hash) {
        return nullptr;
    }
    if (statement.seal_statement.payment_probation_state_hash !=
            seal->pqPaymentProbationStateHash) {
        return nullptr;
    }
    const CBlockIndex* subject_snapshot{
        response->GetAncestor(subject.snapshot_height)};
    if (subject_snapshot == nullptr ||
        subject_snapshot->GetBlockHash() != subject.snapshot_hash) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    int32_t reconstruction_floor{-1};
    if (historical_carrier != nullptr) {
        reconstruction_floor =
            statement.seal_statement.previous_chainlock_height;
        const auto include_snapshots = [&](const pq::FrozenQuorumRosters& rosters) {
            for (const auto& roster : rosters) {
                reconstruction_floor = std::min(
                    reconstruction_floor,
                    roster.descriptor.snapshot_height);
            }
        };
        include_snapshots(seal_rosters->Rosters());
        reconstruction_floor = std::min(
            reconstruction_floor, subject.snapshot_height);
        if (!defer_historical_provenance) {
            const auto provenance_status{
                ClassifyHistoricalReceiptIndexRangeCached(
                    *historical_carrier->pprev, reconstruction_floor)};
            if (provenance_status != PaymentAuditContextStatus::READY) {
                if (status != nullptr &&
                    provenance_status ==
                        PaymentAuditContextStatus::LOCAL_ERROR) {
                    *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
                }
                return nullptr;
            }
        }
    }
    if (subject_out != nullptr) {
        *subject_out = *subject_it;
    }
    if (authorization_out != nullptr) {
        *authorization_out = authorization;
    }
    if (status != nullptr) {
        *status = PaymentAuditRosterBuildStatus::VALID;
    }
    if (roster_source_generation_out != nullptr) {
        *roster_source_generation_out = roster_source_generation;
    }
    if (reconstruction_floor_out != nullptr) {
        *reconstruction_floor_out = reconstruction_floor;
    }
    return seal_rosters;
}

void CChainLocksHandler::ProcessPaymentAuditCertificate(
    CNode* from, CDataStream& payload)
{
    if (from == nullptr) return;
    const NodeId node_id{from->GetId()};
    const auto punish = [&](const char* reason) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, reason);
        }
    };
    PaymentAuditRemoteRequestContext remote;
    {
        LOCK(cs_main);
        remote.requested = m_peerman.GetRequestedPaymentAudit(node_id);
        remote.may_be_cancelled_response =
            m_peerman.HasCancelledPaymentAuditResponse(node_id);
        remote.required_response = remote.requested &&
                                   IsPendingPaymentAuditReceiptCertificate(*remote.requested);
    }
    const bool authorized_remote_response{
        remote.requested.has_value() ||
        remote.may_be_cancelled_response};
    const auto payment_audit_operational = [&] {
        if (!m_share_admission_gate.IsOpen()) return false;
        LOCK(cs_main);
        return !IsPaymentAuditPresealActive();
    };
    if (!IsPaymentAuditCertificateIngressAllowed(
            payment_audit_operational(),
            /*local_certificate=*/false,
            remote.required_response)) {
        if (remote.requested) {
            LOCK(cs_main);
            m_peerman.ReceivedPaymentAuditFailure(
                node_id, *remote.requested);
        }
        return;
    }
    if (!authorized_remote_response) {
        punish("unsolicited-pq-payment-audit");
        return;
    }
    if (payload.size() != pq::FinalPaymentAudit::WIRE_SIZE) {
        punish("bad-pq-payment-audit-size");
        if (remote.requested) {
            LOCK(cs_main);
            m_peerman.ReceivedPaymentAuditFailure(
                node_id, *remote.requested);
        }
        return;
    }

    pq::FinalPaymentAudit audit;
    try {
        payload >> audit;
        if (!payload.empty()) {
            throw std::ios_base::failure(
                "trailing PQ payment-audit bytes");
        }
    } catch (const std::exception&) {
        punish("bad-pq-payment-audit-encoding");
        if (remote.requested) {
            LOCK(cs_main);
            m_peerman.ReceivedPaymentAuditFailure(
                node_id, *remote.requested);
        }
        return;
    }
    ProcessPaymentAuditCertificateInternal(
        from, audit, remote, /*local_finalization=*/nullptr);
}

void CChainLocksHandler::ProcessCollectedPaymentAudit(
    const LocalPaymentAuditFinalization& finalized)
{
    if (!finalized.proof) return;
    ProcessPaymentAuditCertificateInternal(
        /*from=*/nullptr, finalized.proof->Certificate(),
        PaymentAuditRemoteRequestContext{}, &finalized);
}

void CChainLocksHandler::ProcessPaymentAuditCertificateInternal(
    CNode* from,
    const pq::FinalPaymentAudit& audit,
    const PaymentAuditRemoteRequestContext& remote,
    const LocalPaymentAuditFinalization* local_finalization)
{
    const bool local_certificate{local_finalization != nullptr};
    if ((from == nullptr) != local_certificate) return;
    if (local_certificate && !local_finalization->proof) return;

    const NodeId node_id{from != nullptr ? from->GetId() : -1};
    const auto punish = [&](const char* reason) {
        if (from == nullptr) return;
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, reason);
        }
    };
    const auto& requested{remote.requested};
    const auto fail_request = [&] {
        if (from == nullptr || !requested) return;
        LOCK(cs_main);
        m_peerman.ReceivedPaymentAuditFailure(node_id, *requested);
    };
    const auto complete_request = [&](const uint256& witness_id) {
        if (from == nullptr) return;
        LOCK(cs_main);
        m_peerman.ReceivedPaymentAuditResponse(node_id, witness_id);
    };
    const auto payment_audit_operational = [&] {
        if (!m_share_admission_gate.IsOpen()) return false;
        LOCK(cs_main);
        return !IsPaymentAuditPresealActive();
    };
    if (local_certificate &&
        !IsPaymentAuditCertificateIngressAllowed(
            payment_audit_operational(),
            /*local_certificate=*/true,
            /*required_remote_response=*/false)) {
        fail_request();
        return;
    }
    if (!local_certificate &&
        !requested && !remote.may_be_cancelled_response) {
        punish("unsolicited-pq-payment-audit");
        return;
    }

    const uint256 logical_id{audit.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{audit.GetWitnessId(m_genesis_hash)};
    if (logical_id.IsNull() || witness_id.IsNull()) {
        punish("wrong-pq-payment-audit-response");
        fail_request();
        return;
    }

    // A required dependency can replace a speculative or prior-fork request
    // while its multi-megabyte response is already in flight. Consume exactly
    // one bounded cancellation token for the matching witness and leave any
    // current request untouched.
    if (from != nullptr &&
        (!requested || *requested != witness_id)) {
        bool cancelled_response{false};
        {
            LOCK(cs_main);
            cancelled_response =
                m_peerman.TakeCancelledPaymentAuditResponse(
                    node_id, witness_id);
        }
        if (cancelled_response) return;
    }
    if (from != nullptr && !requested) {
        punish("unsolicited-pq-payment-audit");
        return;
    }
    if (requested && *requested != witness_id) {
        punish("wrong-pq-payment-audit-response");
        fail_request();
        return;
    }
    if (!m_payment_audit_store ||
        !m_payment_audit_store->IsHealthy()) {
        fail_request();
        return;
    }
    // Read the payload itself before treating the response as a duplicate.
    // Get() removes a stale presence record, allowing the fully verified
    // requested response below to atomically heal the exact witness.
    const auto archived{m_payment_audit_store->Get(witness_id)};
    const auto archive_status{ClassifyPaymentAuditArchiveRead(
        /*store_available=*/true, /*healthy_before_read=*/true,
        archived.has_value(), m_payment_audit_store->IsHealthy())};
    if (archive_status == PaymentAuditReceiptCertificateStatus::VERIFIED) {
        complete_request(witness_id);
        return;
    }
    if (archive_status != PaymentAuditReceiptCertificateStatus::MISSING) {
        fail_request();
        return;
    }

    bool historical_required{remote.required_response};
    std::optional<PaymentAuditHistoricalContext> historical;
    if (from != nullptr && requested && *requested == witness_id) {
        LOCK(cs_main);
        historical_required = historical_required ||
            IsPendingPaymentAuditReceiptCertificate(witness_id);
        historical = ResolvePendingPaymentAuditContext(witness_id);
    }
    if (MustRetryPaymentAuditCertificateContext(
            historical_required, historical.has_value())) {
        fail_request();
        return;
    }
    if (historical) {
        const auto classification{pq::ClassifyPaymentAuditReports(audit)};
        const auto& receipt{historical->dependency.receipt};
        const pq::RosterBeaconSeed* subject_beacon{
            pq::FindRosterBeaconSeed(
                audit.statement.seal_statement.roster_beacons.active,
                receipt.epoch)};
        if (!classification || receipt.epoch !=
                                   audit.statement.commitment.seed.epoch ||
            receipt.seal_height !=
                audit.statement.commitment.seal_height ||
            receipt.seal_block_hash !=
                audit.statement.seal_statement.block_hash ||
            receipt.audit_logical_id != logical_id ||
            receipt.audit_witness_id != witness_id ||
            receipt.commitment_hash != pq::GetPaymentAuditCommitmentHash(
                m_genesis_hash, audit.statement.commitment) ||
            receipt.result_hash != pq::GetPaymentAuditResultHash(
                m_genesis_hash, audit, *classification) ||
            classification->online_members != receipt.online_members ||
            subject_beacon == nullptr ||
            *subject_beacon != receipt.subject_roster_beacon) {
            (void)RetireInvalidPendingPaymentAuditReceipt(*historical);
            fail_request();
            return;
        }
    }
    if (!historical) {
        const auto slot_status{
            m_payment_audit_store->ProbeLiveCandidateSlot(
                audit.statement.commitment.seed.epoch,
                audit.selected_quorum_mask)};
        if (slot_status ==
            pq::PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL) {
            complete_request(witness_id);
            return;
        }
        if (slot_status != pq::PaymentAuditStoreResult::ACCEPTED &&
            slot_status != pq::PaymentAuditStoreResult::INVALID) {
            fail_request();
            return;
        }
    }
    const auto is_exact_local_runtime = [&] {
        return local_finalization && local_finalization->proof &&
               HasExactPaymentAuditFinalization(*local_finalization) &&
               local_finalization->proof->Certificate().statement ==
                   audit.statement;
    };
    PaymentAuditRosterBuildStatus roster_status{
        PaymentAuditRosterBuildStatus::INVALID};
    uint8_t authorization_mask{0};
    pq::RosterAuthorizationVerificationContext authorization;
    uint64_t roster_source_generation{0};
    pq::VerifiedRosterSetPtr rosters;
    if (local_certificate) {
        if (!local_finalization || historical ||
            !is_exact_local_runtime() ||
            !IsShareAdmissionGenerationCurrent(
                local_finalization->admission_generation) ||
            !IsQuorumRosterSourceGenerationCurrent(
                local_finalization->roster_source_generation) ||
            !IsCurrentPaymentAuditStatement(audit.statement)) {
            return;
        }
        const auto& context{local_finalization->proof->ContextPtr()};
        if (!context || context->Statement() != audit.statement) return;
        rosters = context->RosterSetPtr();
        authorization_mask = context->AuthorizationMask();
        const auto& seal_context{context->SealContextPtr()};
        if (!seal_context) return;
        authorization = seal_context->Authorization();
        roster_source_generation =
            local_finalization->roster_source_generation;
        roster_status = PaymentAuditRosterBuildStatus::VALID;
    } else {
        // Defer the potentially long historical-prefix walk until after the
        // remote certificate takes the mandatory FULL signature path below.
        // The stable-chain rederivation retains the fail-safe default.
        rosters = BuildPaymentAuditVerificationRosters(
            audit.statement, nullptr, &authorization,
            /*require_live_transition_finality=*/false, &roster_status,
            historical ? &*historical : nullptr,
            &roster_source_generation,
            /*reconstruction_floor=*/nullptr,
            /*defer_historical_provenance=*/historical.has_value());
        const auto derived_mask{rosters
            ? pq::ValidateRosterAuthorizationState(
                  m_genesis_hash, audit.statement.seal_statement,
                  authorization)
            : std::optional<uint8_t>{}};
        if (rosters && !derived_mask) {
            rosters.reset();
            roster_status = PaymentAuditRosterBuildStatus::INVALID;
        } else if (derived_mask) {
            authorization_mask = *derived_mask;
        }
    }
    if (historical) {
        LOCK(cs_main);
        const auto current{ResolvePendingPaymentAuditContext(witness_id)};
        if (!current || *current != *historical) {
            fail_request();
            return;
        }
    }
    if (!rosters) {
        if (roster_status == PaymentAuditRosterBuildStatus::LOCAL_ERROR) {
            fail_request();
            return;
        }
        if (historical &&
            !RetireInvalidPendingPaymentAuditReceipt(*historical)) {
            fail_request();
            return;
        }
        punish("bad-pq-payment-audit-context");
        fail_request();
        return;
    }
    const bool runtime_generation_current{is_exact_local_runtime()};
    const pq::PaymentAuditScheduleConfig schedule{
        m_config->chainlock_schedule, m_config->btcc_schedule};
    const bool roster_source_generation_current{
        local_finalization &&
        roster_source_generation ==
            local_finalization->roster_source_generation &&
        IsQuorumRosterSourceGenerationCurrent(
            roster_source_generation)};
    const auto verification_path{
        SelectFinalPaymentAuditVerificationPath(
            local_finalization && local_finalization->proof ? local_finalization->proof.get() : nullptr,
            &audit, m_genesis_hash, schedule, rosters,
            authorization_mask,
            /*local_live_admission=*/local_finalization && !historical,
            local_finalization &&
                IsShareAdmissionGenerationCurrent(
                    local_finalization->admission_generation),
            runtime_generation_current,
            roster_source_generation_current)};
    if (!IsPaymentAuditVerificationPathAuthorized(
            local_certificate, verification_path)) {
        return;
    }
    if (verification_path == FinalPaymentAuditVerificationPath::FULL) {
        pq::PaymentAuditVerificationError verification_error{
            pq::PaymentAuditVerificationError::NONE};
        auto prepared{pq::PrepareFinalPaymentAuditVerification(
            schedule, audit, rosters, authorization,
            &verification_error)};
        if (!prepared) {
            if (historical &&
                !RetireInvalidPendingPaymentAuditReceipt(*historical)) {
                fail_request();
                return;
            }
            punish("bad-pq-payment-audit-context");
            fail_request();
            return;
        }
        bool signatures_valid{false};
        {
            LOCK(m_verification_mutex);
            signatures_valid =
                m_verifier.VerifyChecks(std::move(prepared->checks));
        }
        if (!signatures_valid) {
            if (historical &&
                !RetireInvalidPendingPaymentAuditReceipt(*historical)) {
                fail_request();
                return;
            }
            punish("bad-pq-payment-audit-signatures");
            fail_request();
            return;
        }
    }
    if ((verification_path !=
             FinalPaymentAuditVerificationPath::COLLECTED &&
         verification_path !=
             FinalPaymentAuditVerificationPath::FULL) ||
        !pq::IsSigningRosterAuthorizationMask(authorization_mask) ||
        (audit.selected_quorum_mask &
         static_cast<uint8_t>(~authorization_mask)) != 0) {
        return;
    }
    pq::VerifiedPaymentAuditAdmission verified_admission{
        audit, authorization_mask};

    // The historical exception is two phase: signatures are checked without
    // chain locks, then the exact highest-work deferred carrier and every
    // branch-derived roster input are rederived while activation is frozen.
    std::optional<pq::PaymentAuditStoreResult> stored_result;
    if (historical) {
        const bool stable{m_chainman.ActiveChainstate()
                              .RunWithStableActiveChain([&] {
            std::optional<PaymentAuditHistoricalContext> current;
            {
                LOCK(cs_main);
                current = ResolvePendingPaymentAuditContext(witness_id);
                if (!current || *current != *historical ||
                    m_peerman.GetRequestedPaymentAudit(node_id) !=
                        witness_id) {
                    return false;
                }
            }
            PaymentAuditRosterBuildStatus current_status{
                PaymentAuditRosterBuildStatus::INVALID};
            pq::RosterAuthorizationVerificationContext
                current_authorization;
            const auto current_rosters{BuildPaymentAuditVerificationRosters(
                audit.statement, nullptr, &current_authorization,
                /*require_live_transition_finality=*/false,
                &current_status, &*current,
                /*roster_source_generation=*/nullptr,
                /*reconstruction_floor=*/nullptr,
                /*defer_historical_provenance=*/false)};
            const auto current_authorization_mask{current_rosters
                ? pq::ValidateRosterAuthorizationState(
                      m_genesis_hash,
                      audit.statement.seal_statement,
                      current_authorization)
                : std::optional<uint8_t>{}};
            if (!current_rosters ||
                !current_authorization_mask ||
                *current_authorization_mask != authorization_mask) {
                return false;
            }
            for (std::size_t slot{0};
                 slot < current_rosters->Rosters().size(); ++slot) {
                if (!SameFrozenQuorumRoster(
                        current_rosters->Rosters()[slot],
                        rosters->Rosters()[slot])) {
                    return false;
                }
            }
            {
                LOCK(cs_main);
                const auto latest{
                    ResolvePendingPaymentAuditContext(witness_id)};
                if (!latest || *latest != *historical ||
                    m_peerman.GetRequestedPaymentAudit(node_id) !=
                        witness_id) {
                    return false;
                }
            }
            if (!IsPaymentAuditCertificateIngressAllowed(
                    payment_audit_operational(),
                    /*local_certificate=*/false,
                    /*required_remote_response=*/true)) {
                return false;
            }
            stored_result = m_payment_audit_store->AcceptVerified(
                std::move(verified_admission),
                /*required_witness=*/true);
            return true;
        })};
        if (!stable || !stored_result) {
            fail_request();
            return;
        }
    } else {
        if (!IsPaymentAuditCertificateIngressAllowed(
                payment_audit_operational(),
                local_certificate,
                /*required_remote_response=*/false)) {
            fail_request();
            return;
        }
        if (!m_payment_audit_store->IsHealthy()) {
            fail_request();
            return;
        }
        if (local_certificate &&
            (!local_finalization ||
             verification_path !=
                 FinalPaymentAuditVerificationPath::COLLECTED ||
             !IsShareAdmissionGenerationCurrent(
                 local_finalization->admission_generation) ||
             !is_exact_local_runtime() ||
             roster_source_generation !=
                 local_finalization->roster_source_generation ||
             !IsQuorumRosterSourceGenerationCurrent(
                 roster_source_generation) ||
             !IsCurrentPaymentAuditStatement(audit.statement))) {
            return;
        }
        stored_result = m_payment_audit_store->AcceptVerified(
            std::move(verified_admission),
            /*required_witness=*/false);
    }

    const auto result{*stored_result};
    if (result == pq::PaymentAuditStoreResult::ACCEPTED) {
        if (payment_audit_operational()) {
            m_peerman.RelayInv(CInv{MSG_PQPOSECERT, witness_id});
        }
    } else if (result ==
               pq::PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL) {
        // A concurrent live winner satisfies request accounting even though
        // this alternate witness cannot consume the same bounded slot.
        complete_request(witness_id);
        return;
    } else if (result != pq::PaymentAuditStoreResult::DUPLICATE_WITNESS) {
        fail_request();
        return;
    }
    const bool reconsidered{WITH_LOCK(cs_main, {
        bool restored{false};
        for (Chainstate* chainstate : m_chainman.GetAll()) {
            restored = chainstate
                           ->ReconsiderPaymentAuditReceiptCandidates(
                               witness_id) ||
                       restored;
        }
        return restored;
    })};
    {
        LOCK(m_pending_payment_audit_receipt_mutex);
        if (m_pending_payment_audit_receipt &&
            m_pending_payment_audit_receipt
                    ->receipt.audit_witness_id == witness_id &&
            (!historical ||
             m_pending_payment_audit_receipt->carrier_hash ==
                 historical->dependency.carrier_hash)) {
            m_pending_payment_audit_receipt.reset();
            m_pending_payment_audit_last_request =
                std::chrono::microseconds{0};
            m_retry_pending_btcc_block.store(true);
        }
    }
    if (reconsidered) m_retry_pending_btcc_block.store(true);
    complete_request(witness_id);
    {
        LOCK(cs_main);
        m_peerman.ForgetPaymentAudit(witness_id);
    }
}

void CChainLocksHandler::FinishPaymentAuditFinalizationAttempt(
    const LocalPaymentAuditFinalization& finalized)
{
    LOCK(m_payment_audit_mutex);
    if (m_payment_audit_runtime_generation ==
            finalized.runtime_generation &&
        m_payment_audit_runtime &&
        m_payment_audit_runtime->finalized &&
        m_payment_audit_runtime->finalized->proof == finalized.proof &&
        m_payment_audit_runtime->finalized->admission_generation ==
            finalized.admission_generation &&
        m_payment_audit_runtime->finalized->runtime_generation ==
            finalized.runtime_generation &&
        m_payment_audit_runtime->finalized->roster_source_generation ==
            finalized.roster_source_generation) {
        m_payment_audit_runtime->finalization_attempt_in_flight = false;
    }
}

void CChainLocksHandler::SubmitPaymentAuditFinalizationAttempt(
    const LocalPaymentAuditFinalization& finalized)
{
    if (!finalized.proof ||
        !IsShareAdmissionGenerationCurrent(
            finalized.admission_generation) ||
        !HasExactPaymentAuditFinalization(finalized) ||
        !IsCurrentPaymentAuditStatement(
            finalized.proof->Certificate().statement)) {
        FinishPaymentAuditFinalizationAttempt(finalized);
        return;
    }
    ProcessCollectedPaymentAudit(finalized);
    FinishPaymentAuditFinalizationAttempt(finalized);
}

void CChainLocksHandler::ProcessPaymentAuditHave(
    CNode* from, CDataStream& payload)
{
    if (from == nullptr ||
        from->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        if (from != nullptr) from->fDisconnect = true;
        return;
    }
    const NodeId node_id{from->GetId()};
    const auto punish = [&](const char* reason) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, reason);
        }
    };
    const uint256 peer_identity{from->GetVerifiedProRegTxHash()};
    if (peer_identity.IsNull()) {
        punish("unauthenticated-pq-payment-audit-have");
        return;
    }
    if (payload.size() != pq::PaymentAuditHave::WIRE_SIZE) {
        punish("bad-pq-payment-audit-have-size");
        return;
    }
    pq::PaymentAuditHave have;
    try {
        payload >> have;
        if (!payload.empty()) {
            throw std::ios_base::failure(
                "trailing PQ payment-audit HAVE bytes");
        }
    } catch (const std::exception&) {
        punish("bad-pq-payment-audit-have-encoding");
        return;
    }
    if (!m_share_admission_gate.IsOpen() ||
        !m_payment_audit_staging_store) {
        return;
    }
    const auto context{GetPaymentAuditNetworkContext()};
    if (!context) return;
    const PaymentAuditResponseDefinition* definition{nullptr};
    for (const auto& candidate : context->rows) {
        if (candidate.row.expected.epoch == have.epoch &&
            candidate.row.expected.row_index == have.row_index) {
            definition = &candidate;
            break;
        }
    }
    if (definition == nullptr ||
        !IsPaymentAuditResponseDefinitionSourceCurrent(*definition) ||
        !std::binary_search(definition->active_relays.begin(),
                            definition->active_relays.end(),
                            peer_identity) ||
        have.epoch != definition->row.expected.epoch ||
        have.row_index != definition->row.expected.row_index ||
        have.response_height !=
            definition->row.expected.response_height ||
        have.response_chainlock_logical_id !=
            definition->row.expected.response_chainlock_logical_id ||
        have.subject_descriptor_hash !=
            definition->row.expected.subject_descriptor_hash) {
        return;
    }
    for (std::size_t member{0}; member < pq::QUORUM_SIZE; ++member) {
        if (IsBitmapBitSet(have.available_members, member) &&
            !IsBitmapBitSet(definition->row.subject_valid_members,
                            member)) {
            punish("bad-pq-payment-audit-have-bitmap");
            return;
        }
    }

    const auto current{m_payment_audit_staging_store->GetOpenRowMetadata(
        have.epoch, have.row_index)};
    if (!current ||
        !SamePaymentAuditOpenRowIdentity(*current, definition->row) ||
        !IsCurrentPaymentAuditNetworkRow(definition->row)) {
        return;
    }
    pq::QuorumBitmap excluded{have.available_members};
    pq::QuorumBitmap claimed{};
    {
        // Claim slots before copying 5 KiB responses so repeated or
        // concurrent HAVEs cannot rematerialize an already-served burst.
        LOCK(m_payment_audit_mutex);
        const auto peer{m_payment_audit_supplied_to_peer.find(
            peer_identity)};
        if (peer != m_payment_audit_supplied_to_peer.end()) {
            const auto supplied{peer->second.find(
                have.response_chainlock_logical_id)};
            if (supplied != peer->second.end()) {
                AddBitmap(excluded, supplied->second);
            }
        }
        claimed = MissingBitmap(current->available_members, excluded);
        if (HasBitmapBits(claimed)) {
            auto& supplied{
                m_payment_audit_supplied_to_peer[peer_identity]
                                                [have.response_chainlock_logical_id]};
            AddBitmap(supplied, claimed);
        }
    }
    if (!HasBitmapBits(claimed)) return;

    const auto responses{m_payment_audit_staging_store->GetVerifiedResponses(
        definition->row.expected, claimed)};
    if (!responses ||
        !IsPaymentAuditResponseDefinitionSourceCurrent(*definition) ||
        !IsCurrentPaymentAuditNetworkRow(definition->row)) {
        LOCK(m_payment_audit_mutex);
        const auto peer{m_payment_audit_supplied_to_peer.find(
            peer_identity)};
        if (peer != m_payment_audit_supplied_to_peer.end()) {
            const auto supplied{peer->second.find(
                have.response_chainlock_logical_id)};
            if (supplied != peer->second.end()) {
                RemoveBitmap(supplied->second, claimed);
                if (!HasBitmapBits(supplied->second)) {
                    peer->second.erase(supplied);
                }
            }
            if (peer->second.empty()) {
                m_payment_audit_supplied_to_peer.erase(peer);
            }
        }
        return;
    }
    for (const auto& response : *responses) {
        m_connman.PushMessage(
            from, CNetMsgMaker(from->GetCommonVersion())
                      .Make(NetMsgType::PQPOSERESP, response));
    }
}

void CChainLocksHandler::ProcessPaymentAuditResponse(
    CNode* from, CDataStream& payload)
{
    if (from == nullptr ||
        from->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        if (from != nullptr) from->fDisconnect = true;
        return;
    }
    const NodeId node_id{from->GetId()};
    const auto punish = [&](const char* reason) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, reason);
        }
    };
    const uint256 peer_identity{from->GetVerifiedProRegTxHash()};
    if (peer_identity.IsNull()) {
        punish("unauthenticated-pq-payment-audit-response");
        return;
    }
    if (payload.size() != pq::PaymentAuditResponse::WIRE_SIZE) {
        punish("bad-pq-payment-audit-response-size");
        return;
    }
    pq::PaymentAuditResponse response;
    try {
        payload >> response;
        if (!payload.empty()) {
            throw std::ios_base::failure(
                "trailing PQ payment-audit response bytes");
        }
    } catch (const std::exception&) {
        punish("bad-pq-payment-audit-response-encoding");
        return;
    }
    const uint64_t admission_generation{GetShareAdmissionGeneration()};
    if (admission_generation == 0 || !m_payment_audit_staging_store) {
        return;
    }
    const auto context{GetPaymentAuditNetworkContext()};
    if (!context) return;
    const PaymentAuditResponseDefinition* definition{nullptr};
    for (const auto& candidate : context->rows) {
        if (candidate.row.expected.epoch == response.epoch &&
            candidate.row.expected.row_index == response.row_index) {
            definition = &candidate;
            break;
        }
    }
    if (definition == nullptr ||
        !IsPaymentAuditResponseDefinitionSourceCurrent(*definition) ||
        !std::binary_search(definition->active_relays.begin(),
                            definition->active_relays.end(),
                            peer_identity) ||
        response.epoch != definition->row.expected.epoch ||
        response.row_index != definition->row.expected.row_index ||
        response.subject_descriptor_hash !=
            definition->row.expected.subject_descriptor_hash ||
        response.response.transcript.member_index >= pq::QUORUM_SIZE) {
        return;
    }
    const auto& statement{response.response.GetStatement()};
    const auto expected_target{
        m_config ? pq::NextEligibleChainLockTargetHeight(
                       m_config->chainlock_schedule,
                       statement.previous_chainlock_height)
                 : std::nullopt};
    if (response.response.transcript.height !=
            definition->row.expected.response_height ||
        !expected_target || statement.height != *expected_target ||
        statement.block_hash != definition->row.response_block_hash ||
        statement.btcc_advance != definition->row.response_advance ||
        pq::GetLogicalChainLockId(m_genesis_hash, statement) !=
            definition->row.expected.response_chainlock_logical_id) {
        return;
    }
    const auto& subject{definition->response_context->Rosters().back()};
    const std::size_t member{response.response.transcript.member_index};
    if (response.response.transcript.quorum_epoch !=
            subject.descriptor.epoch ||
        response.response.transcript.quorum_base_hash !=
            subject.descriptor.base_hash ||
        subject.members[member].pro_tx_hash !=
            response.response.transcript.member_pro_tx_hash) {
        return;
    }
    const auto current{m_payment_audit_staging_store->GetOpenRowMetadata(
        response.epoch, response.row_index)};
    if (!current ||
        !SamePaymentAuditOpenRowIdentity(*current, definition->row) ||
        IsBitmapBitSet(current->available_members, member) ||
        !IsCurrentPaymentAuditNetworkRow(definition->row)) {
        return;
    }
    pq::PaymentAuditVerificationError error{
        pq::PaymentAuditVerificationError::NONE};
    auto check{pq::PreparePaymentAuditResponseVerification(
        response, definition->row.expected,
        *definition->response_context, &error)};
    const bool verified{check && (*check)()};
    const bool peer_fault{
        (!check &&
         (error == pq::PaymentAuditVerificationError::INVALID_SIGNER ||
          error ==
              pq::PaymentAuditVerificationError::INVALID_CHILD_PROOF ||
          error == pq::PaymentAuditVerificationError::INVALID_PUBLIC_KEY)) ||
        (check && !verified)};
    if (!check && !peer_fault) return;

    bool punish_response{false};
    {
        LOCK(m_share_lifecycle_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
            return;
        }
        const auto latest_context{GetPaymentAuditNetworkContext()};
        const PaymentAuditResponseDefinition* latest_definition{nullptr};
        if (latest_context) {
            for (const auto& candidate : latest_context->rows) {
                if (candidate.row.expected.epoch == response.epoch &&
                    candidate.row.expected.row_index == response.row_index) {
                    latest_definition = &candidate;
                    break;
                }
            }
        }
        if (latest_definition == nullptr ||
            !IsPaymentAuditResponseDefinitionSourceCurrent(
                *latest_definition) ||
            latest_definition->response_context !=
                definition->response_context ||
            !SamePaymentAuditOpenRowIdentity(
                latest_definition->row, definition->row)) {
            return;
        }
        const auto latest{
            m_payment_audit_staging_store->GetOpenRowMetadata(
                response.epoch, response.row_index)};
        if (!latest ||
            !SamePaymentAuditOpenRowIdentity(*latest, definition->row) ||
            !IsCurrentPaymentAuditNetworkRow(definition->row)) {
            return;
        }
        if (peer_fault) {
            punish_response = true;
        } else {
            if (IsBitmapBitSet(latest->available_members, member)) return;
            pq::PaymentAuditStagingResult result{
                pq::PaymentAuditStagingResult::NOT_FOUND};
            {
                LOCK(cs_main);
                const CBlockIndex* tip{m_chainman.ActiveTip()};
                const CBlockIndex* response_index{
                    tip != nullptr &&
                            tip->nHeight >=
                                definition->row.expected.response_height
                        ? tip->GetAncestor(
                              definition->row.expected.response_height)
                        : nullptr};
                if (tip == nullptr || response_index == nullptr ||
                    response_index->GetBlockHash() !=
                        definition->row.response_block_hash) {
                    return;
                }
                result = m_payment_audit_staging_store->AddVerifiedResponse(
                    response.epoch, response.row_index, tip->nHeight,
                    response);
            }
            if (result == pq::PaymentAuditStagingResult::ACCEPTED) {
                // The WAL append precedes fan-out, while the lifecycle fence
                // prevents Stop from splitting those two publications.
                RelayPaymentAuditResponse(response, peer_identity);
            }
        }
    }
    if (punish_response) {
        punish("bad-pq-payment-audit-response-signature");
    }
}

void CChainLocksHandler::ProcessMessage(CNode* from,
                                        const std::string& command,
                                        CDataStream& payload)
{
    if (!m_chainman.IsPQParticipationAllowed()) return;
    if (!m_store) {
        if (command == NetMsgType::CLSIG && from != nullptr) {
            std::optional<uint256> requested;
            {
                LOCK(cs_main);
                requested = m_peerman.GetRequestedChainLock(from->GetId());
            }
            if (requested) CompletePeerResponse(from->GetId(), *requested);
        }
        return;
    }
    if (command == NetMsgType::PQCLSHARE) {
        if (!m_share_admission_gate.IsOpen()) return;
        ProcessChainLockShare(from, payload);
        return;
    }
    if (command == NetMsgType::PQPOSECERT) {
        ProcessPaymentAuditCertificate(from, payload);
        return;
    }
    if (command == NetMsgType::PQPOSEHAVE) {
        ProcessPaymentAuditHave(from, payload);
        return;
    }
    if (command == NetMsgType::PQPOSERESP) {
        ProcessPaymentAuditResponse(from, payload);
        return;
    }
    if (command == NetMsgType::PQPOSESHARE) {
        if (!m_share_admission_gate.IsOpen()) return;
        ProcessPaymentAuditShare(from, payload);
        return;
    }
    if (command != NetMsgType::CLSIG) return;
    const NodeId node_id{from != nullptr ? from->GetId() : -1};
    std::optional<uint256> requested_logical_id;
    if (from != nullptr) {
        LOCK(cs_main);
        requested_logical_id = m_peerman.GetRequestedChainLock(node_id);
    }
    if (!IsChainLockVerificationAvailable()) {
        if (requested_logical_id) {
            CompletePeerResponse(node_id, *requested_logical_id);
        }
        return;
    }
    if (payload.size() != pq::FinalChainLockSerializedSize()) {
        if (from != nullptr) {
            if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
                m_peerman.Misbehaving(*peer, 100, "bad-pq-clsig-size");
            }
        }
        if (requested_logical_id) {
            FailPeerResponse(node_id, *requested_logical_id);
        }
        return;
    }

    uint256 prefix_logical_id;
    try {
        prefix_logical_id = ReadChainLockLogicalIdPrefix(payload, m_genesis_hash);
    } catch (const std::exception&) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, "bad-pq-clsig-prefix");
        }
        if (requested_logical_id) {
            FailPeerResponse(node_id, *requested_logical_id);
        }
        return;
    }

    // A required receipt dependency may replace an earlier speculative
    // request on the same connection. Route the current response first; one
    // exact late response for the canceled ID is then consumed and discarded
    // without blocking or punishing the only honest required provider.
    if (!requested_logical_id ||
        prefix_logical_id != *requested_logical_id) {
        bool cancelled_response{false};
        if (from != nullptr) {
            LOCK(cs_main);
            cancelled_response =
                m_peerman.TakeCancelledChainLockResponse(
                    node_id, prefix_logical_id);
        }
        if (cancelled_response) return;
    }
    if (!requested_logical_id) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, "unsolicited-pq-clsig");
        }
        return;
    }
    if (prefix_logical_id != *requested_logical_id) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, "wrong-pq-clsig-response");
        }
        FailPeerResponse(node_id, *requested_logical_id);
        return;
    }

    CChainLockSig chainlock;
    try {
        chainlock = pq::ReadFinalChainLock(
            payload, pq::FinalChainLockSerializedSize());
        if (!payload.empty()) throw std::ios_base::failure("trailing PQ CLSIG bytes");
    } catch (const std::exception&) {
        if (from != nullptr) {
            if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
                m_peerman.Misbehaving(*peer, 100, "bad-pq-clsig-encoding");
            }
        }
        FailPeerResponse(node_id, *requested_logical_id);
        return;
    }

    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    if (logical_id != prefix_logical_id) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, "noncanonical-pq-clsig-id");
        }
        FailPeerResponse(node_id, *requested_logical_id);
        return;
    }

    BlockValidationState state;
    bool peer_fault{false};
    if (!ProcessNewChainLock(node_id, chainlock, state, &peer_fault) &&
        peer_fault && state.IsInvalid()) {
        if (PeerRef peer{m_peerman.GetPeerRef(node_id)}) {
            m_peerman.Misbehaving(*peer, 100, state.GetRejectReason());
        }
    }
}

bool CChainLocksHandler::ProcessNewChainLock(
    NodeId from,
    const CChainLockSig& chainlock,
    BlockValidationState& state,
    bool* peer_fault)
{
    return ProcessNewChainLockInternal(
        from, chainlock, state, peer_fault,
        /*local_finalization=*/nullptr);
}

bool CChainLocksHandler::ProcessCollectedChainLock(
    const LocalChainLockFinalization& finalized,
    BlockValidationState& state)
{
    if (!finalized.proof) {
        return state.Error("missing collected ChainLock finalization proof");
    }
    return ProcessNewChainLockInternal(
        /*from=*/-1, finalized.proof->Certificate(), state,
        /*peer_fault=*/nullptr, &finalized);
}

bool CChainLocksHandler::ProcessNewChainLockInternal(
    NodeId from,
    const pq::FinalChainLock& chainlock,
    BlockValidationState& state,
    bool* peer_fault,
    const LocalChainLockFinalization* local_finalization,
    const PendingVerifiedHistoricalChainLock* continuation,
    bool* retain_continuation)
{
    if (peer_fault != nullptr) *peer_fault = false;
    if (retain_continuation != nullptr) *retain_continuation = false;
    if (!IsChainLockVerificationAvailable()) {
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             "pq-clsig-not-configured");
    }

    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (continuation != nullptr &&
        (from != -1 || local_finalization != nullptr ||
         continuation->logical_id != logical_id ||
         continuation->witness_id != witness_id ||
         continuation->chainlock != chainlock)) {
        return state.Error("pq-clsig-invalid-local-continuation");
    }
    if (continuation == nullptr) {
        const auto pending{GetPendingVerifiedHistoricalChainLock()};
        if (pending && pending->logical_id == logical_id) {
            CompletePeerResponse(from, logical_id);
            return state.Error("pq-clsig-verified-continuation-pending");
        }
    }
    if (from != -1) {
        if (PeerRef peer{m_peerman.GetPeerRef(from)}) {
            m_peerman.AddKnownTx(*peer, logical_id);
        }
    }

    // Bound every candidate-context lookup, including historical marker
    // range classification, before any peer can begin a second job.
    TRY_LOCK(m_chainlock_admission_mutex, admission_lock);
    if (!admission_lock) {
        CompletePeerResponse(from, logical_id);
        if (continuation != nullptr && retain_continuation != nullptr) {
            *retain_continuation = true;
        }
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             "pq-clsig-verifier-busy");
    }

    const auto current_best{m_store->GetBestRecord()};
    const auto historical{
        GetHistoricalAdmission(chainlock.statement, logical_id)};
    const bool preseal_receipt{
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const int32_t local_finality_height{
        current_best ? current_best->metadata.statement.height
                     : m_config->activation_predecessor_height};
    const bool preseal_receipt_rebase{
        ShouldRouteBTCCPresealReceiptToCatchup(
            preseal_receipt, chainlock.statement.height,
            local_finality_height)};
    const bool needed_receipt_certificate{
        IsNeededBTCCReceiptCertificate(logical_id)};
    const bool archive_only{
        (preseal_receipt && !preseal_receipt_rebase) ||
        ShouldArchiveRequiredBTCCReceiptCertificate(
            needed_receipt_certificate,
            current_best.has_value(), chainlock.statement.height,
            local_finality_height)};
    const bool preseal_receipt_requires_authorization{
        preseal_receipt &&
        chainlock.statement.roster_transition !=
            pq::RosterAuthorizationTransitionKind::INITIALIZE};
    const bool requires_receipt_archive_capability{
        (archive_only && !preseal_receipt) ||
        preseal_receipt_requires_authorization};
    const auto receipt_archive_capability{
        requires_receipt_archive_capability
            ? GetBTCCReceiptArchiveCapability(logical_id)
            : std::optional<BTCCReceiptArchiveCapability>{}};
    if (requires_receipt_archive_capability &&
        !receipt_archive_capability) {
        CompletePeerResponse(from, logical_id);
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             "pq-clsig-archive-authority-unavailable");
    }
    const bool catchup{
        historical.admission == HistoricalAdmission::CURRENT_CATCHUP ||
        historical.admission == HistoricalAdmission::RECOVERY ||
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP ||
        preseal_receipt_rebase};
    const bool historical_admission{catchup || preseal_receipt};
    if (continuation != nullptr && !historical_admission) {
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             "pq-clsig-stale-local-continuation");
    }
    pq::ChainLockFinalityError finality_error{pq::ChainLockFinalityError::NONE};
    std::optional<pq::PreparedFinalChainLockCandidate> prepared;
    std::optional<RuntimeVerificationContext> verification_context;
    bool index_persistence_failed{false};
    bool accepted{false};
    bool historical_acceptance_complete{false};
    bool historical_capability_reusable{false};
    std::optional<RuntimeVerificationContext> historical_preverification;
    std::optional<ScopedFinalitySnapshotVerificationRetention>
        snapshot_verification_retention;

    if (!historical_admission) {
        prepared = archive_only
            ? m_store->PrepareReceiptArchiveCandidate(chainlock,
                                                       &finality_error)
            : m_store->PrepareCandidate(chainlock, &finality_error);
        if (!prepared) {
            FailPeerResponse(from, logical_id);
            return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                 strprintf("pq-clsig-%s",
                                           FinalityErrorString(finality_error)));
        }
    }

    {
        // Do not queue multi-megabyte certificates behind the CCheckQueue
        // master. This is a strict global admission bound and therefore also
        // limits each peer to one admitted verification job.
        // SYSCOIN: Synchronize behind any active maintenance pass before the
        // first roster lookup. The admission mutex bounds this transient
        // retain-all state to one network candidate without participating in
        // the cs_main-to-crypto lock order.
        snapshot_verification_retention.emplace(deterministicMNManager.get());

        // SYSCOIN: The early admission gate bounds marker-range
        // classification to one candidate. Authenticate the exact roster and
        // all 801 signatures before retained disk/carrier replay work; the
        // statement cannot choose its own beacon authorization.
        if (historical_admission) {
            if (continuation != nullptr) {
                historical_preverification = continuation->verification;
                if (!IsHistoricalVerificationCapabilityCurrent(
                        *historical_preverification, historical)) {
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-stale-verification-capability");
                }
                historical_capability_reusable = true;
            } else if (m_store->AlreadyHaveWitness(witness_id)) {
                CompletePeerResponse(from, logical_id);
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                     "pq-clsig-duplicate-witness");
            } else {
                historical_preverification =
                    BuildHistoricalPreVerificationContext(chainlock,
                        historical,
                        receipt_archive_capability
                            ? &*receipt_archive_capability
                            : nullptr);
                if (!historical_preverification) {
                    CompletePeerResponse(from, logical_id);
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-context-unavailable");
                }
                pq::ChainLockVerificationError verification_error{
                    pq::ChainLockVerificationError::NONE};
                auto signature_checks{pq::PrepareFinalChainLockVerification(
                    chainlock,
                    *historical_preverification->prepared_context,
                    &verification_error)};
                if (!signature_checks) {
                    m_store->RejectWitness(chainlock);
                    if (peer_fault != nullptr) *peer_fault = true;
                    FailPeerResponse(from, logical_id);
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-invalid-context");
                }
                if (peer_fault != nullptr) *peer_fault = true;
                bool signatures_valid{false};
                {
                    LOCK(m_verification_mutex);
                    signatures_valid = m_verifier.VerifyChecks(
                        std::move(signature_checks->checks));
                }
                if (!signatures_valid) {
                    m_store->RejectWitness(chainlock);
                    FailPeerResponse(from, logical_id);
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-invalid-signatures");
                }
                historical_capability_reusable = true;
                if (peer_fault != nullptr) {
                    // Everything below is local historical state, storage, or
                    // a concurrent active/store context. A fully authenticated
                    // peer response must never be punished for those failures.
                    *peer_fault = false;
                }
            }

            // SYSCOIN: Marker catch-up derives authority from current best work
            // plus the current quorum. An exact terminal receipt newer than
            // the local winner follows the same fully verified catch-up path;
            // an older one is archived without rebasing. Keep ActivateBestChain
            // excluded through context rederivation and durable publication.
            accepted = m_chainman.ActiveChainstate().RunWithStableActiveChain(
                [&] {
                    if (GetHistoricalAdmission(chainlock.statement,
                                               logical_id) != historical) {
                        finality_error =
                            pq::ChainLockFinalityError::CONTEXT_CHANGED;
                        return false;
                    }
                    prepared = catchup
                        ? m_store->PrepareCatchupCandidate(
                              chainlock, &finality_error)
                        : m_store->PreparePresealReceiptCandidate(
                              chainlock, &finality_error);
                    if (!prepared) return false;
                    bool definitively_invalid{false};
                    verification_context = BuildRuntimeVerificationContext(
                        *prepared, &definitively_invalid,
                        /*publish_roster=*/true,
                        receipt_archive_capability
                            ? &*receipt_archive_capability
                            : nullptr);
                    if (!verification_context ||
                        Descriptors(verification_context->prepared_context
                                        ->Rosters()) !=
                            Descriptors(historical_preverification
                                            ->prepared_context->Rosters()) ||
                        verification_context->prepared_context
                                ->AuthorizationMask() !=
                            historical_preverification->prepared_context
                                ->AuthorizationMask() ||
                        verification_context->historical != historical ||
                        verification_context->roster_source_generation !=
                            historical_preverification
                                ->roster_source_generation) {
                        if (definitively_invalid || verification_context) {
                            historical_capability_reusable = false;
                        }
                        finality_error =
                            pq::ChainLockFinalityError::CONTEXT_CHANGED;
                        m_store->AbandonPrepared(*prepared);
                        return false;
                    }
                    if (!IsHistoricalVerificationCapabilityCurrent(
                            *historical_preverification, historical)) {
                        historical_capability_reusable = false;
                        finality_error =
                            pq::ChainLockFinalityError::CONTEXT_CHANGED;
                        m_store->AbandonPrepared(*prepared);
                        return false;
                    }
                    const auto sync_index = [&] {
                        const bool flushed{
                            FlushBTCCIndexStateForDurableAcceptance(
                                chainlock)};
                        index_persistence_failed = !flushed;
                        return flushed;
                    };
                    const auto authorize_durable =
                        [&](const std::function<bool()>& persist_record,
                            pq::ChainLockFinalityError* error) {
                            const bool preseal_authorized{
                                historical.admission ==
                                    HistoricalAdmission::PRESEAL_CATCHUP ||
                                historical.admission ==
                                    HistoricalAdmission::PRESEAL_RECEIPT};
                            if (!preseal_authorized) {
                                return persist_record();
                            }
                            // SYSCOIN: The store holds its winner mutex while
                            // this callback holds the marker mutex across the
                            // certificate fsync. This is the authorization
                            // linearization point: promotion, terminal advance,
                            // replay-clear, and a competing winner cannot turn
                            // a stale proof into durable finality.
                            LOCK(m_btcc_preseal_mutex);
                            if (PresealAdmissionToken(
                                    m_btcc_preseal_state,
                                    m_payment_audit_preseal_state) !=
                                    historical.marker_token) {
                                if (error != nullptr) {
                                    *error = pq::ChainLockFinalityError::
                                        CONTEXT_CHANGED;
                                }
                                return false;
                            }
                            return persist_record();
                    };
                    if (catchup) {
                        const auto coverage_authorization{
                            GetReceiptArchiveCoverageAuthorization(
                                *prepared)};
                        return m_store->AcceptCatchupVerified(
                            *prepared, chainlock, /*signatures_valid=*/true,
                            sync_index, authorize_durable,
                            &finality_error,
                            coverage_authorization
                                ? &*coverage_authorization
                                : nullptr,
                            verification_context->prepared_context);
                    }
                    return m_store->AcceptPresealReceiptVerified(
                        *prepared, chainlock, /*signatures_valid=*/true,
                        sync_index, authorize_durable,
                        &finality_error,
                        verification_context->prepared_context,
                        receipt_archive_capability
                            ? &receipt_archive_capability->authorization
                            : nullptr);
                });
            historical_acceptance_complete = true;
            // Retained disk/carrier replay cannot escape globally serialized
            // admission and requires a valid certificate.
        } else {
            verification_context = BuildRuntimeVerificationContext(
                *prepared, /*definitively_invalid=*/nullptr,
                /*publish_roster=*/false,
                receipt_archive_capability
                    ? &*receipt_archive_capability
                    : nullptr);
            if (!verification_context) {
                m_store->AbandonPrepared(*prepared);
                CompletePeerResponse(from, logical_id);
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                     "pq-clsig-context-unavailable");
            }

            bool collector_generation_current{false};
            if (local_finalization && local_finalization->proof &&
                local_finalization->signing_contexts &&
                local_finalization->variant_index <
                    local_finalization->signing_contexts->count) {
                LOCK(m_collector_mutex);
                const pq::ChainLockCollector* collector{
                    m_collectors[local_finalization->variant_index].get()};
                collector_generation_current =
                    m_collector_generation ==
                        local_finalization->collector_generation &&
                    m_current_signing_contexts ==
                        local_finalization->signing_contexts &&
                    local_finalization->signing_contexts
                            ->statements[local_finalization->variant_index] ==
                        chainlock.statement &&
                    collector != nullptr &&
                    collector->GetPreparedContext() ==
                        local_finalization->proof->ContextPtr();
            }
            const bool local_live_admission{
                local_finalization != nullptr && from == -1 &&
                !historical_admission && !archive_only &&
                prepared->admission == pq::ChainLockCandidateAdmission::LIVE};
            const auto verification_path{
                SelectFinalChainLockVerificationPath(
                    local_finalization && local_finalization->proof
                        ? local_finalization->proof.get()
                        : nullptr,
                    &chainlock, m_genesis_hash,
                    m_config->chainlock_schedule,
                    verification_context->prepared_context->RosterSetPtr(),
                    verification_context->prepared_context
                        ->AuthorizationMask(),
                    local_live_admission,
                    local_finalization &&
                        IsShareAdmissionGenerationCurrent(
                            local_finalization->admission_generation),
                    collector_generation_current)};
            if (verification_path ==
                FinalChainLockVerificationPath::FULL) {
                pq::ChainLockVerificationError verification_error{
                    pq::ChainLockVerificationError::NONE};
                auto signature_checks{pq::PrepareFinalChainLockVerification(
                    chainlock, *verification_context->prepared_context,
                    &verification_error)};
                if (!signature_checks) {
                    m_store->RejectPrepared(*prepared);
                    if (peer_fault != nullptr) *peer_fault = true;
                    FailPeerResponse(from, logical_id);
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-invalid-context");
                }
                if (peer_fault != nullptr) *peer_fault = true;
                bool signatures_valid{false};
                {
                    LOCK(m_verification_mutex);
                    signatures_valid = m_verifier.VerifyChecks(
                        std::move(signature_checks->checks));
                }
                if (!signatures_valid) {
                    if (archive_only) {
                        m_store->RejectPrepared(*prepared);
                    } else {
                        (void)m_store->AcceptVerified(
                            *prepared, chainlock,
                            /*signatures_valid=*/false, &finality_error);
                    }
                    FailPeerResponse(from, logical_id);
                    return state.Invalid(
                        BlockValidationResult::BLOCK_CHAINLOCK,
                        "pq-clsig-invalid-signatures");
                }
            }
            if (peer_fault != nullptr) *peer_fault = false;
        }
    }
    admission_lock.unlock();

    const auto accept_verified = [&] {
        const auto publication_context{
            prepared ? BuildRuntimeVerificationContext(
                           *prepared,
                           /*definitively_invalid=*/nullptr,
                           /*publish_roster=*/true,
                           receipt_archive_capability
                               ? &*receipt_archive_capability
                               : nullptr)
                     : std::nullopt};
        if (!verification_context || !publication_context ||
            publication_context->prepared_context->AuthorizationMask() !=
                verification_context->prepared_context
                    ->AuthorizationMask() ||
            Descriptors(publication_context->prepared_context->Rosters()) !=
                Descriptors(
                    verification_context->prepared_context->Rosters())) {
            finality_error = pq::ChainLockFinalityError::CONTEXT_CHANGED;
            return false;
        }
        const auto coverage_authorization{
            archive_only
                ? std::optional<
                      pq::ReceiptArchiveRosterAuthorization>{}
                : GetReceiptArchiveCoverageAuthorization(*prepared)};
        if (!FlushBTCCIndexStateForDurableAcceptance(chainlock)) {
            index_persistence_failed = true;
            return false;
        }
        if (archive_only) {
            const auto authorize_durable =
                [&](const std::function<bool()>& persist_record,
                    pq::ChainLockFinalityError* error) {
                    return AuthorizeBTCCReceiptArchivePersistence(
                        *receipt_archive_capability, persist_record, error);
                };
            return m_store->AcceptReceiptArchiveVerified(
                *prepared, chainlock, /*signatures_valid=*/true,
                receipt_archive_capability->authorization,
                authorize_durable, &finality_error,
                verification_context->prepared_context);
        }
        return coverage_authorization
            ? m_store->AcceptVerifiedCoveringReceiptArchive(
                  *prepared, chainlock, /*signatures_valid=*/true,
                  *coverage_authorization, &finality_error,
                  verification_context->prepared_context)
            : m_store->AcceptVerified(
                  *prepared, chainlock, /*signatures_valid=*/true,
                  &finality_error,
                  verification_context->prepared_context);
    };
    if (!historical_acceptance_complete) {
        accepted = m_chainman.ActiveChainstate().RunWithStableActiveChain(
            accept_verified);
    }
    if (index_persistence_failed) {
        // This is a local durability failure, never peer misbehavior. Refuse
        // the winner and all subsequent signing/admission until restart so a
        // certificate cannot outrun the branch state that authenticates it.
        if (prepared) m_store->AbandonPrepared(*prepared);
        CompletePeerResponse(from, logical_id);
        m_persistence_failed.store(true);
        DisableShareAdmission();
        return state.Error("pq-clsig-btcc-index-persistence-failed");
    }
    if (!accepted) {
        if (prepared) m_store->AbandonPrepared(*prepared);
        const bool retain_verified_historical{
            historical_preverification &&
            historical_capability_reusable &&
            finality_error ==
                pq::ChainLockFinalityError::CONTEXT_CHANGED &&
            IsHistoricalVerificationCapabilityCurrent(
                *historical_preverification, historical) &&
            GetHistoricalAdmission(chainlock.statement, logical_id) ==
                historical};
        if (retain_verified_historical) {
            const bool retained{
                continuation != nullptr ||
                RetainVerifiedHistoricalChainLock(
                    chainlock, *historical_preverification)};
            if (continuation != nullptr && retain_continuation != nullptr) {
                *retain_continuation = true;
            }
            CompletePeerResponse(from, logical_id);
            return retained
                ? state.Error("pq-clsig-historical-continuation-pending")
                : state.Error("pq-clsig-historical-continuation-occupied");
        }
        CompletePeerResponse(from, logical_id);
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             strprintf("pq-clsig-%s",
                                       FinalityErrorString(finality_error)));
    }
    const bool reconsider_deferred_candidates{WITH_LOCK(cs_main, {
        bool reconsidered{false};
        for (Chainstate* chainstate : m_chainman.GetAll()) {
            reconsidered =
                chainstate->ReconsiderBTCCReceiptCandidates(logical_id) ||
                reconsidered;
        }
        return reconsidered;
    })};
    ClearNeededBTCCCertificate(logical_id);
    {
        LOCK(m_pending_btcc_receipt_mutex);
        if (m_pending_btcc_receipt &&
            m_pending_btcc_receipt->logical_id == logical_id) {
            m_pending_btcc_receipt.reset();
            m_pending_btcc_last_request = std::chrono::microseconds{0};
            m_retry_pending_btcc_block.store(true);
        }
    }
    if (reconsider_deferred_candidates) {
        m_retry_pending_btcc_block.store(true);
    }

    if (archive_only) {
        const CInv inventory{MSG_CLSIG, logical_id};
        m_peerman.RelayInv(inventory);
        CompletePeerResponse(from, logical_id);
        ForgetAllRequests(logical_id);
        RefreshPQHistoryAuthState();
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s accepted archived receipt ADVANCE "
                 "%s at height %d without rebasing finality\n",
                 __func__, witness_id.ToString(),
                 chainlock.statement.height);
        return true;
    }

    {
        LOCK(m_persisted_mutex);
        const auto accepted_best{m_store->GetBestRecord()};
        if (accepted_best &&
            accepted_best->metadata.witness_id == witness_id) {
            m_threshold_attested_enforcement_witness =
                historical_admission ? witness_id : uint256{};
        }
    }

    // Only a fully verified certificate that crossed the durable-accept fsync
    // may create the immutable accepted row used by payment-audit signing. A
    // crash before this call is recovered from the persisted winner at startup.
    uint256 local_pro_tx_hash;
    uint32_t local_key_version{0};
    pq::GlobalPublicKey local_public_key{};
    CService local_service;
    if (GetActiveMasternodeIdentity(local_pro_tx_hash, local_key_version,
                                    local_public_key, local_service)) {
        (void)ReconcileSignerJournal(local_pro_tx_hash);
    }

    const CInv inventory{MSG_CLSIG, logical_id};
    m_peerman.RelayInv(inventory);
    CompletePeerResponse(from, logical_id);
    ForgetAllRequests(logical_id);
    EnforceBestChainLock();
    MaintainPaymentAuditCheckpointGC();
    RefreshPQHistoryAuthState();
    if (pnevmdatadb) {
        const CBlockIndex* accepted_index{GetBestChainLockIndex()};
        if (accepted_index != nullptr &&
            !pnevmdatadb->PruneStandalone(accepted_index->GetMedianTimePast())) {
            LogPrintf("CChainLocksHandler::%s -- CNEVMDataDB::Prune failed\n",
                      __func__);
        }
    }
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s accepted PQ ChainLock %s at height %d\n",
             __func__, witness_id.ToString(), chainlock.statement.height);
    {
        LOCK(m_collector_mutex);
        const bool collector_follows_winner{
            m_current_signing_contexts &&
            m_current_signing_contexts->count != 0 &&
            m_collectors[0] &&
            IsChainLockCollectorOnAcceptedSuccessorView(
                m_config->chainlock_schedule,
                m_collectors[0]->GetStatement(), chainlock.statement)};
        if (!collector_follows_winner) {
            // AcceptVerified is the atomic first-winner boundary. Discard the
            // losing KEEP/ADVANCE view together with the winner so late shares
            // cannot revive it. Preserve only a next-view collector that a
            // concurrent share created after the durable acceptance.
            ResetCollectors();
        }
    }
    // A delayed winner can make the following sequential target immediately
    // signable. Move relay connectivity to that new durable view without
    // waiting for another block-tip notification.
    if (pqQuorumConnectionOverlay != nullptr) {
        const CBlockIndex* tip{WITH_LOCK(cs_main, return m_chainman.ActiveTip())};
        pqQuorumConnectionOverlay->UpdatedBlockTip(
            tip, /*initial_download=*/false);
    }
    return true;
}

CChainLocksHandler::PersistedChainLockImport
CChainLocksHandler::TryImportPersistedRosterAuthorizationBase()
{
    pq::FinalChainLock persisted;
    {
        LOCK(m_persisted_mutex);
        if (m_persisted_invalid) return PersistedChainLockImport::INVALID;
        if (m_pending_persisted_authorization_bases.empty()) {
            return PersistedChainLockImport::NONE;
        }
        persisted = m_pending_persisted_authorization_bases.front();
    }
    if (!ShouldAttemptPersistedChainLockImport(
            m_chainman.IsPQParticipationAllowed(),
            IsConfiguredForVerification())) {
        return PersistedChainLockImport::PENDING;
    }

    TRY_LOCK(m_chainlock_admission_mutex, admission_lock);
    if (!admission_lock) return PersistedChainLockImport::PENDING;
    ScopedFinalitySnapshotVerificationRetention snapshot_retention{
        deterministicMNManager.get()};

    const auto exact_record_is_still_durable = [&] {
        if (!m_persistence) return false;
        const uint256 logical_id{persisted.GetLogicalId(m_genesis_hash)};
        const uint256 witness_id{persisted.GetWitnessId(m_genesis_hash)};
        const auto durable{
            m_persistence->LoadAuthorizationBase(logical_id)};
        return durable && *durable == persisted &&
               durable->GetWitnessId(m_genesis_hash) == witness_id;
    };
    if (!exact_record_is_still_durable()) {
        QuarantineInvalidPersistedChainLock(
            "authorization-base record changed during startup import");
        return PersistedChainLockImport::INVALID;
    }

    pq::ChainLockFinalityError finality_error{
        pq::ChainLockFinalityError::NONE};
    auto prepared{
        m_store->PreparePersistedCandidate(persisted, &finality_error)};
    if (!prepared) {
        if (finality_error == pq::ChainLockFinalityError::UNKNOWN_BLOCK ||
            finality_error ==
                pq::ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED ||
            finality_error == pq::ChainLockFinalityError::CONTEXT_CHANGED) {
            return PersistedChainLockImport::PENDING;
        }
        QuarantineInvalidPersistedChainLock(strprintf(
            "authorization-base preparation: %s",
            FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }

    bool context_definitively_invalid{false};
    const auto verification_context{BuildRuntimeVerificationContext(
        *prepared, &context_definitively_invalid,
        /*publish_roster=*/false)};
    if (!verification_context) {
        m_store->AbandonPrepared(*prepared);
        if (context_definitively_invalid) {
            QuarantineInvalidPersistedChainLock(
                "invalid authorization-base roster context");
            return PersistedChainLockImport::INVALID;
        }
        return PersistedChainLockImport::PENDING;
    }

    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    auto signature_checks{pq::PrepareFinalChainLockVerification(
        persisted, *verification_context->prepared_context,
        &verification_error)};
    bool signatures_valid{false};
    if (signature_checks) {
        LOCK(m_verification_mutex);
        signatures_valid =
            m_verifier.VerifyChecks(std::move(signature_checks->checks));
    }
    if (!signature_checks || !signatures_valid) {
        m_store->RejectPrepared(*prepared);
        QuarantineInvalidPersistedChainLock(
            "failed authorization-base roster/signature verification");
        return PersistedChainLockImport::INVALID;
    }

    // Close the disk-to-context race without rewriting the already fsynced
    // row. Only the exact persisted witness may mint the in-memory capability.
    if (!exact_record_is_still_durable()) {
        m_store->AbandonPrepared(*prepared);
        QuarantineInvalidPersistedChainLock(
            "authorization-base record changed after verification");
        return PersistedChainLockImport::INVALID;
    }
    if (!m_store->AcceptPersistedRosterAuthorizationBase(
            persisted, /*signatures_valid=*/true,
            verification_context->prepared_context, &finality_error)) {
        m_store->AbandonPrepared(*prepared);
        QuarantineInvalidPersistedChainLock(strprintf(
            "authorization-base acceptance: %s",
            FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }

    bool queue_mismatch{false};
    {
        LOCK(m_persisted_mutex);
        if (m_pending_persisted_authorization_bases.empty() ||
            m_pending_persisted_authorization_bases.front() != persisted) {
            queue_mismatch = true;
        } else {
            m_pending_persisted_authorization_bases.erase(
                m_pending_persisted_authorization_bases.begin());
        }
    }
    if (queue_mismatch) {
        QuarantineInvalidPersistedChainLock(
            "authorization-base startup queue changed unexpectedly");
        return PersistedChainLockImport::INVALID;
    }
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- fully reverified persisted roster "
             "authorization base at height %d\n",
             __func__, persisted.statement.height);
    return PersistedChainLockImport::ACCEPTED;
}

CChainLocksHandler::PersistedChainLockImport
CChainLocksHandler::TryImportPersistedChainLock()
{
    pq::FinalChainLock persisted;
    {
        LOCK(m_persisted_mutex);
        if (m_persisted_invalid) return PersistedChainLockImport::INVALID;
        // Authorization-only rows are imported first while the in-memory
        // store is empty. That lets them cross the same branch/context seam as
        // the latest fsynced winner without weakening trusted persistence into
        // a general post-startup admission path.
        if (!m_pending_persisted_authorization_bases.empty()) {
            return PersistedChainLockImport::PENDING;
        }
        if (!m_pending_persisted) return PersistedChainLockImport::NONE;
        persisted = *m_pending_persisted;
    }
    if (!ShouldAttemptPersistedChainLockImport(
            m_chainman.IsPQParticipationAllowed(),
            IsConfiguredForVerification())) {
        return PersistedChainLockImport::PENDING;
    }

    TRY_LOCK(m_chainlock_admission_mutex, admission_lock);
    if (!admission_lock) return PersistedChainLockImport::PENDING;
    ScopedFinalitySnapshotVerificationRetention snapshot_retention{
        deterministicMNManager.get()};

    pq::ChainLockFinalityError finality_error{
        pq::ChainLockFinalityError::NONE};
    auto prepared{
        m_store->PreparePersistedCandidate(persisted, &finality_error)};
    if (!prepared) {
        // Unknown block/validation state can be transient during IBD/reindex.
        if (finality_error == pq::ChainLockFinalityError::UNKNOWN_BLOCK ||
            finality_error ==
                pq::ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED ||
            finality_error == pq::ChainLockFinalityError::CONTEXT_CHANGED) {
            return PersistedChainLockImport::PENDING;
        }
        QuarantineInvalidPersistedChainLock(strprintf(
            "finality preparation: %s", FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }

    bool context_definitively_invalid{false};
    const auto verification_context{BuildRuntimeVerificationContext(
        *prepared, &context_definitively_invalid)};
    if (!verification_context) {
        m_store->AbandonPrepared(*prepared);
        if (context_definitively_invalid) {
            QuarantineInvalidPersistedChainLock("invalid roster context");
            return PersistedChainLockImport::INVALID;
        }
        return PersistedChainLockImport::PENDING;
    }

    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    auto signature_checks{pq::PrepareFinalChainLockVerification(
        persisted, *verification_context->prepared_context,
        &verification_error)};
    bool signatures_valid{false};
    if (signature_checks) {
        LOCK(m_verification_mutex);
        signatures_valid =
            m_verifier.VerifyChecks(std::move(signature_checks->checks));
    }
    if (!signature_checks || !signatures_valid) {
        m_store->RejectPrepared(*prepared);
        QuarantineInvalidPersistedChainLock(
            "failed full roster/signature verification");
        return PersistedChainLockImport::INVALID;
    }
    const bool persisted_requires_historical_enforcement{
        WITH_LOCK(cs_main, {
            const CBlockIndex* target{
                m_chainman.m_blockman.LookupBlockIndex(
                    persisted.statement.block_hash)};
            return target != nullptr &&
                target->nHeight == persisted.statement.height &&
                !HasChainLockTargetValidationCached(
                    *target,
                    persisted.statement.previous_chainlock_height,
                    HistoricalIndexValidationMode::FULL_FINALITY);
        })};

    if (!FlushChainLockAuxiliarySnapshotsForDurability()) {
        m_store->AbandonPrepared(*prepared);
        return PersistedChainLockImport::PENDING;
    }

    if (!m_store->AcceptPersistedVerified(
            *prepared, persisted, /*signatures_valid=*/true,
            &finality_error,
            verification_context->prepared_context)) {
        m_store->AbandonPrepared(*prepared);
        if (finality_error == pq::ChainLockFinalityError::CONTEXT_CHANGED) {
            return PersistedChainLockImport::PENDING;
        }
        QuarantineInvalidPersistedChainLock(strprintf(
            "final acceptance: %s", FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }


    // The record was loaded from the fsynced certificate DB and has now been
    // fully reverified and accepted. Repeating this after a crash is exact and
    // idempotent; transient pending and invalid records never reach this call.
    uint256 local_pro_tx_hash;
    uint32_t local_key_version{0};
    pq::GlobalPublicKey local_public_key{};
    CService local_service;
    if (GetActiveMasternodeIdentity(local_pro_tx_hash, local_key_version,
                                    local_public_key, local_service)) {
        (void)ReconcileSignerJournal(local_pro_tx_hash);
    }

    {
        LOCK(m_persisted_mutex);
        const uint256 persisted_witness{
            persisted.GetWitnessId(m_genesis_hash)};
        const auto accepted_best{m_store->GetBestRecord()};
        if (accepted_best &&
            accepted_best->metadata.witness_id ==
                persisted_witness) {
            m_threshold_attested_enforcement_witness =
                persisted_requires_historical_enforcement
                    ? persisted_witness
                    : uint256{};
        }
        if (m_pending_persisted &&
            m_pending_persisted->GetWitnessId(m_genesis_hash) ==
                persisted_witness) {
            m_pending_persisted.reset();
        }
    }
    {
        LOCK(m_collector_mutex);
        const bool collector_follows_winner{
            m_current_signing_contexts &&
            m_current_signing_contexts->count != 0 &&
            m_collectors[0] &&
            IsChainLockCollectorOnAcceptedSuccessorView(
                m_config->chainlock_schedule,
                m_collectors[0]->GetStatement(), persisted.statement)};
        if (!collector_follows_winner) {
            ResetCollectors();
        }
    }
    if (pqQuorumConnectionOverlay != nullptr) {
        const CBlockIndex* tip{WITH_LOCK(cs_main, return m_chainman.ActiveTip())};
        pqQuorumConnectionOverlay->UpdatedBlockTip(
            tip, /*initial_download=*/false);
    }
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- fully reverified persisted PQ "
             "ChainLock at height %d\n",
             __func__, persisted.statement.height);
    return PersistedChainLockImport::ACCEPTED;
}

CChainLocksHandler::PersistedChainLockImport
CChainLocksHandler::TryImportPersistedUnsealedBTCC()
{
    pq::FinalChainLock persisted;
    {
        LOCK(m_persisted_mutex);
        if (m_persisted_invalid) return PersistedChainLockImport::INVALID;
        if (!m_pending_persisted_unsealed_btcc) {
            return PersistedChainLockImport::NONE;
        }
        if (m_pending_persisted ||
            !m_pending_persisted_authorization_bases.empty()) {
            return PersistedChainLockImport::PENDING;
        }
        persisted = *m_pending_persisted_unsealed_btcc;
    }
    if (!ShouldAttemptPersistedChainLockImport(
            m_chainman.IsPQParticipationAllowed(),
            IsConfiguredForVerification())) {
        return PersistedChainLockImport::PENDING;
    }

    const uint256 logical_id{persisted.GetLogicalId(m_genesis_hash)};
    if (m_store->GetByLogicalId(logical_id)) {
        if (!FlushChainLockAuxiliarySnapshotsForDurability()) {
            return PersistedChainLockImport::PENDING;
        }
        LOCK(m_persisted_mutex);
        m_pending_persisted_unsealed_btcc.reset();
        m_persisted_unsealed_auth_pending = false;
        return PersistedChainLockImport::ACCEPTED;
    }

    TRY_LOCK(m_chainlock_admission_mutex, admission_lock);
    if (!admission_lock) return PersistedChainLockImport::PENDING;
    ScopedFinalitySnapshotVerificationRetention snapshot_retention{
        deterministicMNManager.get()};

    // SYSCOIN: This admission is stronger than a network receipt archive.
    // Re-read the durable row under global certificate admission and require
    // exact witness identity before selecting reduced historical provenance.
    const auto exact_unsealed{
        m_persistence ? m_persistence->LoadUnsealedBTCC()
                      : std::optional<pq::FinalChainLock>{}};
    if (!exact_unsealed || *exact_unsealed != persisted) {
        return PersistedChainLockImport::PENDING;
    }

    pq::ChainLockFinalityError finality_error{
        pq::ChainLockFinalityError::NONE};
    auto prepared{
        m_store->PrepareTrustedUnsealedCandidate(persisted,
                                                 &finality_error)};
    if (!prepared) {
        if (finality_error == pq::ChainLockFinalityError::UNKNOWN_BLOCK ||
            finality_error ==
                pq::ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED ||
            finality_error == pq::ChainLockFinalityError::CONTEXT_CHANGED) {
            return PersistedChainLockImport::PENDING;
        }
        QuarantineInvalidPersistedChainLock(strprintf(
            "unsealed BTCC preparation: %s",
            FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }

    bool context_definitively_invalid{false};
    const auto verification_context{BuildRuntimeVerificationContext(
        *prepared, &context_definitively_invalid)};
    if (!verification_context) {
        m_store->AbandonPrepared(*prepared);
        if (context_definitively_invalid) {
            QuarantineInvalidPersistedChainLock(
                "invalid unsealed BTCC roster context");
            return PersistedChainLockImport::INVALID;
        }
        return PersistedChainLockImport::PENDING;
    }

    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    auto signature_checks{pq::PrepareFinalChainLockVerification(
        persisted, *verification_context->prepared_context,
        &verification_error)};
    bool signatures_valid{false};
    if (signature_checks) {
        LOCK(m_verification_mutex);
        signatures_valid =
            m_verifier.VerifyChecks(std::move(signature_checks->checks));
    }
    if (!signature_checks || !signatures_valid) {
        m_store->RejectPrepared(*prepared);
        QuarantineInvalidPersistedChainLock(
            "failed unsealed BTCC roster/signature verification");
        return PersistedChainLockImport::INVALID;
    }

    if (!FlushChainLockAuxiliarySnapshotsForDurability()) {
        m_store->AbandonPrepared(*prepared);
        return PersistedChainLockImport::PENDING;
    }

    const auto rechecked_unsealed{
        m_persistence ? m_persistence->LoadUnsealedBTCC()
                      : std::optional<pq::FinalChainLock>{}};
    if (!rechecked_unsealed || *rechecked_unsealed != persisted) {
        m_store->AbandonPrepared(*prepared);
        return PersistedChainLockImport::PENDING;
    }

    if (!m_store->AcceptTrustedUnsealedVerified(
            *prepared, persisted, /*signatures_valid=*/true,
            &finality_error,
            verification_context->prepared_context)) {
        m_store->AbandonPrepared(*prepared);
        if (finality_error == pq::ChainLockFinalityError::CONTEXT_CHANGED) {
            return PersistedChainLockImport::PENDING;
        }
        QuarantineInvalidPersistedChainLock(strprintf(
            "unsealed BTCC acceptance: %s",
            FinalityErrorString(finality_error)));
        return PersistedChainLockImport::INVALID;
    }

    {
        LOCK(m_persisted_mutex);
        if (m_pending_persisted_unsealed_btcc &&
            m_pending_persisted_unsealed_btcc->GetWitnessId(m_genesis_hash) ==
                persisted.GetWitnessId(m_genesis_hash)) {
            m_pending_persisted_unsealed_btcc.reset();
            m_persisted_unsealed_auth_pending = false;
        }
    }
    LogPrint(BCLog::CHAINLOCKS,
             "CChainLocksHandler::%s -- fully reverified persisted unsealed "
             "BTCC ADVANCE at height %d\n",
             __func__, persisted.statement.height);
    return PersistedChainLockImport::ACCEPTED;
}

void CChainLocksHandler::CompletePeerResponse(NodeId from,
                                              const uint256& logical_id)
{
    if (from == -1) return;
    LOCK(cs_main);
    m_peerman.ReceivedResponse(from, logical_id);
}

void CChainLocksHandler::FailPeerResponse(NodeId from,
                                         const uint256& logical_id)
{
    if (from == -1) return;
    LOCK(cs_main);
    m_peerman.ReceivedChainLockFailure(from, logical_id);
}

void CChainLocksHandler::ForgetAllRequests(const uint256& logical_id)
{
    LOCK(cs_main);
    m_peerman.ForgetTxHash(-1, logical_id);
}

ChainLockRelayRecipients BuildChainLockRelayRecipients(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters)
{
    ChainLockRelayRecipients recipients;
    recipients.reserve(pq::ACTIVE_QUORUMS * pq::QUORUM_SIZE);
    for (const auto& roster : rosters) {
        for (const auto& member : roster.members) {
            if (!member.pro_tx_hash.IsNull() && member.eligible &&
                member.child_root) {
                recipients.insert(member.pro_tx_hash);
            }
        }
    }
    return recipients;
}

std::shared_ptr<const PQRelayPlan> BuildPQRelayPlan(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash)
{
    PQRelayPlan plan;
    plan.authorized_recipients = BuildChainLockRelayRecipients(rosters);
    if (plan.authorized_recipients.empty()) return {};

    if (local_pro_tx_hash.IsNull()) {
        // Verification authority is roster-derived; absent local identity
        // deliberately yields no connection or gossip capability.
        return std::make_shared<const PQRelayPlan>(std::move(plan));
    }
    plan.local_pro_tx_hash = local_pro_tx_hash;
    plan.relay_members = GetPQQuorumUnionRelayConnections(
        rosters, local_pro_tx_hash);
    if (!std::all_of(
            plan.relay_members.begin(), plan.relay_members.end(),
            [&](const uint256& member) {
                return plan.authorized_recipients.contains(member);
            })) {
        return {};
    }
    return std::make_shared<const PQRelayPlan>(std::move(plan));
}

bool IsPQRelayPlanForIdentity(
    const PQRelayPlan& plan, const uint256& local_pro_tx_hash) noexcept
{
    return !plan.local_pro_tx_hash.IsNull() &&
           plan.local_pro_tx_hash == local_pro_tx_hash;
}

PQRelayIdentityGate::PQRelayIdentityGate(
    const uint256& excluded_identity)
    : m_excluded_identity{excluded_identity}
{
}

bool PQRelayIdentityGate::Admit(
    const uint256& identity, bool authorized_recipient,
    bool current_relay_member)
{
    if (identity.IsNull() || !authorized_recipient ||
        !current_relay_member ||
        identity == m_excluded_identity) {
        return false;
    }
    return m_admitted_identities.insert(identity).second;
}

bool IsAuthorizedChainLockShareRelay(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const ChainLockRelayRecipients& relay_recipients,
    const uint256& relay_pro_tx_hash,
    const pq::ChainLockShareTranscript& transcript) noexcept
{
    if (relay_pro_tx_hash.IsNull() ||
        transcript.member_index >= pq::QUORUM_SIZE ||
        transcript.member_pro_tx_hash.IsNull()) {
        return false;
    }
    if (!relay_recipients.contains(relay_pro_tx_hash)) return false;

    bool signer_matches_transcript{false};
    for (const auto& roster : rosters) {
        if (roster.descriptor.epoch == transcript.quorum_epoch &&
            roster.descriptor.base_hash == transcript.quorum_base_hash) {
            const auto& signer{roster.members[transcript.member_index]};
            signer_matches_transcript =
                signer.eligible && signer.child_root &&
                signer.pro_tx_hash == transcript.member_pro_tx_hash;
        }
    }
    return signer_matches_transcript;
}

void CChainLocksHandler::ResetCollectors()
{
    for (auto& collector : m_collectors) collector.reset();
    m_current_signing_contexts.reset();
    ++m_collector_generation;
}

void CChainLocksHandler::RelayChainLockShare(
    const pq::ChainLockShare& share,
    CurrentSigningContextsPtr signing_contexts,
    std::size_t variant_index,
    uint64_t admission_generation,
    uint256 excluded_identity)
{
    if (!signing_contexts ||
        !IsCurrentSigningSource(signing_contexts->source)) {
        return;
    }
    LOCK(m_share_lifecycle_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    if (variant_index >= signing_contexts->count ||
        share.GetStatement() !=
            signing_contexts->statements[variant_index]) {
        return;
    }
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    {
        LOCK(m_collector_mutex);
        if (m_current_signing_contexts != signing_contexts ||
            !m_collectors[variant_index] ||
            m_collectors[variant_index]->GetStatement() !=
                share.GetStatement()) {
            return;
        }
    }
    const auto& relay_plan{signing_contexts->relay_plan};
    if (!IsPQRelayPlanForActiveIdentity(relay_plan)) return;
    const auto& prepared_context{
        signing_contexts->prepared_contexts[variant_index]};
    const auto compact{prepared_context
        ? pq::BuildCompactChainLockShare(share, *prepared_context)
        : std::nullopt};
    if (!compact) return;

    PQRelayIdentityGate relay_gate{excluded_identity};
    m_connman.ForEachNode([&](CNode* node) {
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        if (node == nullptr || node->fDisconnect ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
            return;
        }
        const uint256 identity{node->GetVerifiedProRegTxHash()};
        if (!relay_gate.Admit(
                identity,
                relay_plan->authorized_recipients.contains(identity),
                relay_plan->relay_members.contains(identity))) {
            return;
        }
        m_connman.PushMessage(
            node, CNetMsgMaker(node->GetCommonVersion())
                      .Make(NetMsgType::PQCLSHARE, *compact));
    });
}

void CChainLocksHandler::MaybeCreateAndSignChainLock()
{
    const uint64_t admission_generation{GetShareAdmissionGeneration()};
    if (admission_generation == 0 || !fMasternodeMode ||
        !m_signer_journal ||
        !m_signer_journal->IsHealthy() || !masternodeSync.IsSynced()) {
        return;
    }
    {
        LOCK(cs_main);
        // A durable descendant CLSIG closes the consensus pre-seal
        // immediately. Geth may remain offline with a separate replay marker
        // without preventing the sentry from signing the next live target.
        if (IsBTCCPresealActive() ||
            IsPaymentAuditPresealActive()) return;
    }
    TRY_LOCK(m_share_signing_mutex, signing_lock);
    if (!signing_lock) return;

    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    pq::GlobalPublicKey global_public_key{};
    CService service;
    if (!GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                     global_public_key, service)) {
        return;
    }

    // Identity initialization can lag persisted-certificate restoration. Do
    // not sign until the current durable winner has populated its independent
    // accepted row, closing the fsync-before-journal-record crash window.
    if (!ReconcileSignerJournal(local_pro_tx_hash) ||
        !InitializeSignerStartupTip(local_pro_tx_hash)) {
        return;
    }

    auto contexts{GetPublishedCurrentSigningContexts(
        admission_generation)};
    if (!contexts) return;

    std::optional<CurrentSigningContext> current;
    const auto existing_branch_lock{m_signer_journal->GetBranchLock(
        m_genesis_hash, local_pro_tx_hash,
        contexts->statements[0].height)};
    if (!m_signer_journal->IsHealthy()) return;
    if (existing_branch_lock) {
        for (std::size_t i{0}; i < contexts->count; ++i) {
            const auto& statement{contexts->statements[i]};
            if (existing_branch_lock->block_hash == statement.block_hash &&
                existing_branch_lock->statement_hash ==
                    pq::GetLogicalChainLockId(m_genesis_hash, statement)) {
                current = contexts->Find(contexts->statements[i]);
                break;
            }
        }
        // A same-height durable vote may only resume its exact canonical
        // variant. Backend recovery must never turn an earlier KEEP into a
        // second ADVANCE vote (or vice versa).
        if (!current) return;
    } else {
        for (std::size_t i{0}; i < contexts->count; ++i) {
            if (contexts->statements[i].btcc_advance ==
                pq::BTCCAdvance::ADVANCE) {
                if (CheckBTCHeaderSigningPolicy(contexts->statements[i])) {
                    current = contexts->Find(contexts->statements[i]);
                }
                break;
            }
        }
    }
    if (!current) {
        for (std::size_t i{0}; i < contexts->count; ++i) {
            if (contexts->statements[i].btcc_advance ==
                pq::BTCCAdvance::KEEP) {
                current = contexts->Find(contexts->statements[i]);
                break;
            }
        }
    }
    if (!current) return;

    pq::PreparedChainLockContextPtr signing_context;
    uint64_t collector_generation{0};
    {
        LOCK(m_collector_mutex);
        if (m_current_signing_contexts != contexts ||
            current->variant_index >= contexts->count) {
            return;
        }
        pq::ChainLockCollector* collector{
            m_collectors[current->variant_index].get()};
        if (collector == nullptr) return;
        signing_context = collector->GetPreparedContext();
        collector_generation = m_collector_generation;
    }
    if (!signing_context ||
        signing_context->Statement() != current->statement) {
        return;
    }
    const auto& statement{signing_context->Statement()};
    const auto& rosters{signing_context->Rosters()};
    const uint8_t authorization_mask{
        signing_context->AuthorizationMask()};
    const auto has_exact_collector = [&]() {
        LOCK(m_collector_mutex);
        return m_collector_generation == collector_generation &&
               m_current_signing_contexts == contexts &&
               current->variant_index < contexts->count &&
               m_collectors[current->variant_index] != nullptr &&
               m_collectors[current->variant_index]->GetStatement() ==
                   statement &&
               m_collectors[current->variant_index]
                       ->GetPreparedContext() == signing_context;
    };
    const auto local_preseals_clear = [this]() {
        LOCK(cs_main);
        return !IsBTCCPresealActive() &&
               !IsPaymentAuditPresealActive();
    };
    const auto exact_signing_capability_is_current = [&]() {
        return IsShareAdmissionGenerationCurrent(admission_generation) &&
               has_exact_collector() &&
               local_preseals_clear() &&
               IsCurrentSigningSource(contexts->source);
    };

    // Bitcoin policy checks deliberately run without cs_main and can span
    // several bounded RPC calls. A concurrent Syscoin reorg invalidates both
    // approval and fallback; never let either path reserve a stale key slot.
    if (!exact_signing_capability_is_current()) return;
    if (!ConsumeStartupChainLockSlots(
            *signing_context, contexts->source,
            local_pro_tx_hash)) {
        return;
    }

    bool local_member{false};
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        if ((authorization_mask & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        local_member = std::any_of(
            rosters[slot].members.begin(),
            rosters[slot].members.end(),
            [&](const pq::FrozenQuorumMember& member) {
                return member.pro_tx_hash == local_pro_tx_hash &&
                       member.eligible && member.child_root.has_value();
            });
        if (local_member) break;
    }
    if (!local_member) return;

    pq::ChainLockShareSigner signer{
        m_genesis_hash, local_pro_tx_hash,
        m_config->chainlock_schedule, *m_signer_journal};
    const PQSignerBranchLock candidate_branch_lock{
        statement.height,
        statement.block_hash,
        pq::GetLogicalChainLockId(m_genesis_hash, statement)};
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        if ((authorization_mask & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        const auto& roster{rosters[slot]};
        for (std::size_t member_index{0};
             member_index < roster.members.size(); ++member_index) {
            const auto& member{roster.members[member_index]};
            if (member.pro_tx_hash != local_pro_tx_hash || !member.eligible ||
                !member.child_root) {
                continue;
            }
            if (!exact_signing_capability_is_current()) return;
            auto signing_material{GetActiveMasternodeChildSigningMaterial(
                m_genesis_hash, local_pro_tx_hash, *member.child_root)};
            if (!signing_material) {
                LogPrint(BCLog::CHAINLOCKS,
                         "CChainLocksHandler::%s -- committed scheduled-WOTS child "
                         "key cache is unavailable for epoch %u\n",
                         __func__, roster.descriptor.epoch);
                continue;
            }
            // Material derivation can span a capability transition. Recheck
            // before consulting or consuming durable signer-journal state.
            if (!exact_signing_capability_is_current()) return;
            const auto expected_branch_lock{m_signer_journal->GetBranchLock(
                m_genesis_hash, local_pro_tx_hash,
                candidate_branch_lock.height)};
            if (!m_signer_journal->IsHealthy()) return;
            if (expected_branch_lock &&
                candidate_branch_lock != *expected_branch_lock) {
                return;
            }
            pq::ChainLockSigningError signing_error{
                pq::ChainLockSigningError::NONE};
            // Roster reveals and recovery ranges are signer policy, not a
            // verifier dependency. Recheck them after material derivation and
            // immediately before the one-time journal reservation.
            if (!CheckBTCHeaderSigningPolicy(statement)) return;
            if (!exact_signing_capability_is_current() ||
                !IsActiveMasternodeChildSigningMaterialCurrent(
                    local_pro_tx_hash, *signing_material)) {
                return;
            }
            auto signed_share{signer.Sign(
                *signing_context,
                static_cast<uint8_t>(slot),
                static_cast<uint16_t>(member_index),
                *signing_material->secret_key,
                signing_material->key_proof,
                expected_branch_lock,
                &signing_error)};
            if (!signed_share.share) {
                if (signing_error !=
                        pq::ChainLockSigningError::JOURNAL_CONSUMED &&
                    signing_error !=
                        pq::ChainLockSigningError::JOURNAL_CONFLICT) {
                    LogPrint(BCLog::CHAINLOCKS,
                             "CChainLocksHandler::%s -- scheduled-WOTS share signing "
                             "failed for epoch %u, error=%u\n",
                             __func__, roster.descriptor.epoch,
                             static_cast<uint8_t>(signing_error));
                }
                continue;
            }

            // The expensive signing operation may span a reorg. Burned slots
            // are never refunded, but stale signatures are never announced.
            if (!exact_signing_capability_is_current() ||
                !IsActiveMasternodeChildSigningMaterialCurrent(
                    local_pro_tx_hash, *signing_material)) {
                return;
            }

            auto collection{CollectChainLockShare(
                *signed_share.share, contexts,
                current->variant_index,
                admission_generation)};
            if (collection.stale) return;
            if (collection.result !=
                pq::ShareCollectionResult::ACCEPTED) {
                // A peer can receive our first share before its private
                // scheduler has published the matching capability. Journal
                // replay is deterministic, so periodically re-announce only
                // our own exact duplicate; remote duplicates never relay.
                if (ShouldRetryLocalChainLockShareRelay(
                        signed_share.replayed, collection.result)) {
                    if (!exact_signing_capability_is_current()) return;
                    RelayChainLockShare(
                        *signed_share.share, contexts,
                        current->variant_index,
                        admission_generation);
                }
                continue;
            }
            // Collection verifies outside the collector lock. Authorize the
            // local announcement at the exact still-published capability and
            // preseal state, rather than relying on the pre-collection fence.
            if (!exact_signing_capability_is_current()) return;
            MaybeCapturePaymentAuditResponse(
                *signed_share.share, signing_context->RostersPtr(),
                admission_generation);
            if (!exact_signing_capability_is_current()) return;
            RelayChainLockShare(
                *signed_share.share, contexts,
                current->variant_index, admission_generation);
            if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
                return;
            }
            if (collection.finalized) {
                LOCK(m_share_lifecycle_mutex);
                if (!IsShareAdmissionGenerationCurrent(
                        admission_generation)) {
                    return;
                }
                BlockValidationState state;
                (void)ProcessCollectedChainLock(
                    *collection.finalized, state);
                return;
            }
        }
    }
}

void CChainLocksHandler::MaybeCreateAndSignPaymentAudit()
{
    const uint64_t admission_generation{GetShareAdmissionGeneration()};
    if (admission_generation == 0 || !fMasternodeMode ||
        !m_signer_journal ||
        !m_signer_journal->IsHealthy() || !masternodeSync.IsSynced()) {
        return;
    }
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    TRY_LOCK(m_share_signing_mutex, signing_lock);
    if (!signing_lock) return;

    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    pq::GlobalPublicKey global_public_key{};
    CService service;
    if (!GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                     global_public_key, service) ||
        !ReconcileSignerJournal(local_pro_tx_hash) ||
        !InitializeSignerStartupTip(local_pro_tx_hash) ||
        !PreparePaymentAuditSigningRuntime()) {
        return;
    }

    std::optional<pq::PaymentAuditStatement> statement;
    pq::PreparedPaymentAuditContextPtr signing_context;
    pq::QuorumBitmap reporter_observed_members{};
    pq::FrozenQuorumRostersPtr rosters;
    std::shared_ptr<const PQRelayPlan> relay_plan;
    std::optional<LocalPaymentAuditFinalization> finalization_to_process;
    uint64_t runtime_generation{0};
    uint8_t authorization_mask{0};
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(m_payment_audit_mutex);
        if (!m_payment_audit_runtime ||
            !m_payment_audit_runtime->collector ||
            !m_payment_audit_runtime->statement ||
            !m_payment_audit_runtime->seal_chainlock ||
            !m_payment_audit_runtime->signing_rosters ||
            !m_payment_audit_runtime->relay_plan) {
            return;
        }
        runtime_generation = m_payment_audit_runtime_generation;
        if (m_payment_audit_runtime->finalized) {
            if (m_payment_audit_runtime
                    ->finalization_attempt_in_flight ||
                !IsPaymentAuditFinalizationRetryDue(
                    now, m_payment_audit_runtime
                             ->finalization_last_attempt)) {
                return;
            }
            m_payment_audit_runtime->finalization_last_attempt = now;
            m_payment_audit_runtime->finalization_attempt_in_flight = true;
            finalization_to_process =
                m_payment_audit_runtime->finalized;
        } else {
            if (m_payment_audit_runtime->local_signing_complete) return;
            signing_context = m_payment_audit_runtime->collector
                                  ->GetPreparedContext();
            if (!signing_context) return;
            statement = signing_context->Statement();
            reporter_observed_members =
                m_payment_audit_runtime->selected_row
                    .locally_observed_members;
            rosters = signing_context->RostersPtr();
            relay_plan = m_payment_audit_runtime->relay_plan;
            authorization_mask =
                signing_context->AuthorizationMask();
        }
    }
    if (finalization_to_process) {
        LOCK(m_share_lifecycle_mutex);
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
            FinishPaymentAuditFinalizationAttempt(
                *finalization_to_process);
            return;
        }
        if (!IsCurrentPaymentAuditStatement(
                finalization_to_process->proof->Certificate().statement)) {
            FinishPaymentAuditFinalizationAttempt(
                *finalization_to_process);
            return;
        }
        SubmitPaymentAuditFinalizationAttempt(*finalization_to_process);
        return;
    }
    if (!statement || !signing_context || !rosters || !relay_plan ||
        !pq::IsSigningRosterAuthorizationMask(authorization_mask) ||
        !IsCurrentPaymentAuditStatement(*statement)) {
        return;
    }

    bool local_member{false};
    for (std::size_t slot{0}; slot < rosters->size(); ++slot) {
        if ((authorization_mask & (uint8_t{1} << slot)) == 0) continue;
        local_member = std::any_of(
            (*rosters)[slot].members.begin(),
            (*rosters)[slot].members.end(),
            [&](const pq::FrozenQuorumMember& member) {
                return member.pro_tx_hash == local_pro_tx_hash &&
                       member.eligible && member.child_root.has_value();
            });
        if (local_member) break;
    }
    if (!local_member) {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime_generation == runtime_generation &&
            m_payment_audit_runtime &&
            m_payment_audit_runtime->collector &&
            m_payment_audit_runtime->collector->GetPreparedContext() ==
                signing_context &&
            m_payment_audit_runtime->statement == statement) {
            m_payment_audit_runtime->local_signing_complete = true;
        }
        return;
    }

    const auto& seal_statement{statement->seal_statement};
    const PQSignerBranchLock seal_lock{
        seal_statement.height,
        seal_statement.block_hash,
        pq::GetLogicalChainLockId(m_genesis_hash, seal_statement)};
    const auto retained_seal{ResolvePaymentAuditSealRecord(
        *m_store, m_genesis_hash, seal_statement)};
    if (!retained_seal ||
        retained_seal->metadata.logical_id != seal_lock.statement_hash ||
        retained_seal->metadata.statement != seal_statement ||
        !ReconcileSignerJournal(local_pro_tx_hash,
                                retained_seal->metadata)) {
        return;
    }
    const auto expected_accepted_certificate{
        m_signer_journal->GetAcceptedCertificate(
            m_genesis_hash, local_pro_tx_hash, seal_lock.height)};
    if (!m_signer_journal->IsHealthy() ||
        !expected_accepted_certificate ||
        *expected_accepted_certificate != seal_lock) {
        return;
    }
    const auto has_exact_open_runtime = [&]() {
        LOCK(m_payment_audit_mutex);
        return m_payment_audit_runtime_generation == runtime_generation &&
               m_payment_audit_runtime &&
               m_payment_audit_runtime->collector &&
               m_payment_audit_runtime->collector->GetPreparedContext() ==
                   signing_context &&
               m_payment_audit_runtime->statement == statement &&
               !m_payment_audit_runtime->finalized;
    };
    if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
        !has_exact_open_runtime() ||
        !ConsumeStartupPaymentAuditSlots(
            *signing_context, local_pro_tx_hash)) {
        return;
    }

    pq::PaymentAuditShareSigner signer{
        m_genesis_hash, local_pro_tx_hash,
        pq::PaymentAuditScheduleConfig{m_config->chainlock_schedule,
                                       m_config->btcc_schedule},
        *m_signer_journal};
    bool signing_material_missing{false};
    bool collection_incomplete{false};
    for (std::size_t slot{0}; slot < rosters->size(); ++slot) {
        if ((authorization_mask & (uint8_t{1} << slot)) == 0) continue;
        const auto& roster{(*rosters)[slot]};
        for (std::size_t member_index{0};
             member_index < roster.members.size(); ++member_index) {
            const auto& member{roster.members[member_index]};
            if (member.pro_tx_hash != local_pro_tx_hash || !member.eligible ||
                !member.child_root) {
                continue;
            }
            auto signing_material{GetActiveMasternodeChildSigningMaterial(
                m_genesis_hash, local_pro_tx_hash, *member.child_root)};
            if (!signing_material) {
                signing_material_missing = true;
                LogPrint(BCLog::CHAINLOCKS,
                         "CChainLocksHandler::%s -- committed scheduled-WOTS child "
                         "key cache is unavailable for payment-audit epoch "
                         "%u\n",
                         __func__, roster.descriptor.epoch);
                continue;
            }
            if (!IsCurrentPaymentAuditStatement(*statement)) return;
            // Each child signature is expensive enough for Bitcoin to reorg
            // between local roster slots. Recheck the exact K/H+37 view
            // immediately before consuming every audit key use.
            if (!CheckPaymentAuditSeedSigningPolicy(*statement)) return;

            pq::ChainLockSigningError signing_error{
                pq::ChainLockSigningError::NONE};
            if (!IsShareAdmissionGenerationCurrent(admission_generation) ||
                !has_exact_open_runtime() ||
                !IsActiveMasternodeChildSigningMaterialCurrent(
                    local_pro_tx_hash, *signing_material)) {
                return;
            }
            auto signed_share{signer.Sign(
                *signing_context, reporter_observed_members,
                static_cast<uint8_t>(slot),
                static_cast<uint16_t>(member_index),
                *signing_material->secret_key,
                signing_material->key_proof,
                expected_accepted_certificate, &signing_error)};
            if (!signed_share.share) {
                if (signing_error !=
                        pq::ChainLockSigningError::JOURNAL_CONSUMED &&
                    signing_error !=
                        pq::ChainLockSigningError::JOURNAL_CONFLICT) {
                    LogPrint(BCLog::CHAINLOCKS,
                             "CChainLocksHandler::%s -- payment-audit scheduled-WOTS "
                             "share signing failed for epoch %u, error=%u\n",
                             __func__, roster.descriptor.epoch,
                             static_cast<uint8_t>(signing_error));
                }
                continue;
            }
            if (!IsCurrentPaymentAuditStatement(*statement) ||
                !IsActiveMasternodeChildSigningMaterialCurrent(
                    local_pro_tx_hash, *signing_material)) {
                return;
            }

            auto collection{CollectPaymentAuditShare(
                *signed_share.share, *statement, admission_generation,
                runtime_generation)};
            if (collection.stale || collection.closed) return;
            if (collection.result !=
                pq::ShareCollectionResult::ACCEPTED) {
                collection_incomplete =
                    collection_incomplete ||
                    !collection.accepted_duplicate;
                continue;
            }
            if (!HasExactPaymentAuditRuntime(
                    runtime_generation, *statement, signing_context,
                    relay_plan) ||
                !IsCurrentPaymentAuditStatement(*statement)) {
                if (collection.finalized) {
                    FinishPaymentAuditFinalizationAttempt(
                        *collection.finalized);
                }
                return;
            }
            RelayPaymentAuditShare(
                *signed_share.share, signing_context, relay_plan,
                runtime_generation, admission_generation);
            if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
                if (collection.finalized) {
                    FinishPaymentAuditFinalizationAttempt(
                        *collection.finalized);
                }
                return;
            }
            if (collection.finalized) {
                LOCK(m_share_lifecycle_mutex);
                if (!IsShareAdmissionGenerationCurrent(
                        admission_generation)) {
                    FinishPaymentAuditFinalizationAttempt(
                        *collection.finalized);
                    return;
                }
                SubmitPaymentAuditFinalizationAttempt(
                    *collection.finalized);
                return;
            }
        }
    }

    if (!signing_material_missing && !collection_incomplete) {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime_generation == runtime_generation &&
            m_payment_audit_runtime &&
            m_payment_audit_runtime->collector &&
            m_payment_audit_runtime->collector->GetPreparedContext() ==
                signing_context &&
            m_payment_audit_runtime->statement == statement) {
            m_payment_audit_runtime->local_signing_complete = true;
        }
    }
}

void CChainLocksHandler::EnforceBestChainLock()
{
    if (!m_enforced.load()) return;
    if (!m_store || !m_config) return;
    const auto record{m_store->GetBestRecord()};
    if (!record) {
        // No PQ finality exists before the first durable winner. Ordinary PoW
        // still selects the active branch; only refresh snapshot retention.
        MaybeReleaseFinalitySnapshotPublicationRetention();
        return;
    }
    uint256 threshold_attested_witness;
    {
        LOCK(m_persisted_mutex);
        threshold_attested_witness =
            m_threshold_attested_enforcement_witness;
    }
    const CBlockIndex* best{nullptr};
    const CBlockIndex* finalized_predecessor{nullptr};
    ChainLockEnforcementProvenance provenance{
        ChainLockEnforcementProvenance::EXACT_LOCAL};
    {
        LOCK(cs_main);
        const auto& statement{record->metadata.statement};
        best = m_chainman.m_blockman.LookupBlockIndex(statement.block_hash);
        if (best == nullptr || best->nHeight != statement.height) return;
        finalized_predecessor = best->GetAncestor(
            statement.previous_chainlock_height);
        if (finalized_predecessor == nullptr ||
            finalized_predecessor->GetBlockHash() !=
                statement.previous_chainlock_hash) {
            return;
        }
        if (m_chainman.IsSnapshotActive() &&
            !m_chainman.IsSnapshotValidated()) {
            return;
        }
        if (!HasChainLockTargetValidationCached(
                *best, statement.previous_chainlock_height,
                HistoricalIndexValidationMode::FULL_FINALITY)) {
            const uint256 witness_id{record->metadata.witness_id};
            if (witness_id.IsNull() ||
                threshold_attested_witness != witness_id ||
                !m_chainman.IsBaseBlockSyncComplete() ||
                (m_chainman.IsSnapshotActive() &&
                 !m_chainman.IsSnapshotValidated()) ||
                statement.previous_chainlock_height <
                    m_config->activation_predecessor_height ||
                statement.previous_chainlock_height >= statement.height ||
                (best->nStatus & BLOCK_FAILED_MASK) ||
                (best->nStatus & BLOCK_HAVE_DATA) == 0 ||
                best->IsAssumedValid() ||
                !best->IsValid(BLOCK_VALID_SCRIPTS) ||
                !HasFullReceiptIndexProvenance(*best)) {
                return;
            }
            const auto indexed_btcc{IndexedBTCCReceiptState(*best)};
            const auto indexed_audit{IndexedPaymentAuditReceiptState(*best)};
            pq::BTCCValidationError btcc_error{
                pq::BTCCValidationError::NONE};
            if (ClassifyHistoricalReceiptIndexRangeCached(
                    *finalized_predecessor,
                    statement.previous_chainlock_height) !=
                    PaymentAuditContextStatus::READY ||
                ClassifyHistoricalReceiptIndexRangeCached(
                    *best, statement.previous_chainlock_height + 1) !=
                    PaymentAuditContextStatus::READY ||
                !indexed_btcc ||
                *indexed_btcc != statement.btcc_receipt_state ||
                !indexed_audit ||
                *indexed_audit != statement.payment_audit_receipt_state ||
                best->pqPaymentProbationStateHash !=
                    statement.payment_probation_state_hash ||
                !pq::ValidateBTCCursorTransition(
                    m_config->btcc_schedule, *best,
                    statement.previous_btcc_cursor,
                    statement.accepted_btcc_cursor,
                    statement.btcc_advance, &btcc_error)) {
                return;
            }
            const auto retained_predecessor{m_store->GetByHeight(
                statement.previous_chainlock_height)};
            if (retained_predecessor &&
                (retained_predecessor->statement.block_hash !=
                     statement.previous_chainlock_hash ||
                 retained_predecessor->statement.accepted_btcc_cursor !=
                     statement.previous_btcc_cursor)) {
                return;
            }
            provenance = ChainLockEnforcementProvenance::
                VERIFIED_DURABLE_CERTIFICATE;
        }
    }
    if (!m_chainman.ActiveChainstate().EnforceBestChainLock(
            best, finalized_predecessor, provenance)) {
        return;
    }
    const bool enforced_on_active{WITH_LOCK(cs_main, {
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        return tip != nullptr && tip->nHeight >= best->nHeight &&
               tip->GetAncestor(best->nHeight) == best;
    })};
    if (enforced_on_active) {
        LOCK(m_persisted_mutex);
        m_persisted_best_auth_pending = false;
    }
    MaybeReleaseFinalitySnapshotPublicationRetention();
}

void CChainLocksHandler::NotifyHeaderTip(const CBlockIndex*)
{
    // Validation callbacks must not import or enforce finality synchronously:
    // ActivateBestChain can wait for this queue while holding its chainstate
    // mutex. The private PQ scheduler performs both operations every five
    // seconds without participating in that lock cycle.
    CheckActiveState();
    (void)RevalidatePendingBTCCReceiptDependency();
    (void)RevalidatePendingPaymentAuditReceiptDependency();
}

void CChainLocksHandler::UpdatedBlockTip(const CBlockIndex*, bool)
{
    CheckActiveState();
    (void)RevalidatePendingBTCCReceiptDependency();
    (void)RevalidatePendingPaymentAuditReceiptDependency();
}

void CChainLocksHandler::CheckActiveState()
{
    bool configured{false};
    bool pending{false};
    bool verification_available{false};
    while (true) {
        const ShareAdmissionGate::Observation observation{
            m_share_admission_gate.Observe()};
        configured =
            m_store != nullptr && m_payment_audit_store != nullptr &&
            m_payment_audit_staging_store != nullptr &&
            m_payment_audit_store->IsHealthy() &&
            m_payment_audit_staging_store->IsHealthy();
        const bool operational{AreChainLocksEnabled()};
        pending = IsPersistedChainLockPending();
        verification_available = IsChainLockVerificationAvailable();
        if (m_share_admission_gate.TryPublishEnabled(
                observation, verification_available && operational)) {
            break;
        }
    }

    // A kill switch or deferred NEVM replay may stop producing new finality,
    // but neither may make an already durable Syscoin decision reversible.
    // The pre-seal gates signing and Geth delivery above; base ChainLock
    // enforcement starts immediately so a PoW fork cannot strand the seal on
    // an incompatible branch while Geth is offline.
    const bool enforce{m_chainman.IsPQParticipationAllowed() &&
        ShouldEnforceDurableChainLock(
            configured, pending, HasNEVMReplayObligation())};
    m_enforced.store(enforce);
    // SYSCOIN: Backend health can fail without passing through the share
    // gate's permanent-failure path. Publish that transition through the same
    // generation gate as certificate durability and handler lifecycle.
    (void)m_auxiliary_history_gc_auth_gate.SetHealthy(
        deterministicMNManager && configured && verification_available &&
            enforce,
        [this] { return RevokeAuxiliaryHistoryGCAuthorization(); });
}

bool CChainLocksHandler::GetCLSIGFromPeers()
{
    if (!IsChainLockVerificationAvailable()) return false;
    const CNetMsgMaker maker{PROTOCOL_VERSION};
    const CConnman::NodesSnapshot nodes{m_connman, FullyConnectedOnly};
    for (CNode* node : nodes.Nodes()) {
        m_connman.PushMessage(node, maker.Make(NetMsgType::GETCLSIG));
    }
    return true;
}

bool CChainLocksHandler::HasChainLock(int32_t height,
                                      const uint256& block_hash) const
{
    return m_enforced.load() && m_store &&
           m_store->HasChainLock(height, block_hash);
}

bool CChainLocksHandler::HasConflictingChainLock(
    int32_t height, const uint256& block_hash) const
{
    return m_enforced.load() && m_store &&
           m_store->HasConflictingChainLock(height, block_hash);
}

bool AreChainLocksEnabled()
{
    return sporkManager != nullptr &&
           sporkManager->IsSporkActive(SPORK_19_CHAINLOCKS_ENABLED);
}

bool ShouldVerifyChainLockCertificate(
    bool configured_and_healthy, bool persisted_import_pending,
    bool persistence_failed) noexcept
{
    // The operational spork controls production, not recovery of an exact
    // certificate already required to authenticate locally indexed history.
    return configured_and_healthy && !persisted_import_pending &&
           !persistence_failed;
}

bool ShouldAttemptPersistedChainLockImport(
    bool participation_allowed, bool configured_for_verification) noexcept
{
    // Import is what clears the pending state, so it cannot use the normal
    // verification-availability gate that pending import intentionally closes.
    return participation_allowed && configured_for_verification;
}

bool ShouldExposeDurableFinalityRecoveryMetadata(
    bool configured, bool persistence_available,
    bool persistence_failed) noexcept
{
    // PreparePQActivationHandoff deliberately quarantines a persisted pin
    // before ReplayBlocks. Recovery of journal-authorizing metadata must not
    // depend on the live participation flag that replay itself precedes.
    return configured && persistence_available && !persistence_failed;
}

bool ShouldEnforceDurableChainLock(
    bool configured, bool persisted_import_pending,
    bool btcc_preseal_active) noexcept
{
    // A pre-seal is an execution/readiness obligation, not permission to
    // reverse a fully verified and fsynced Syscoin finality decision.
    (void)btcc_preseal_active;
    return configured && !persisted_import_pending;
}

bool DisconnectCrossesDurableChainLockFloor(
    int32_t disconnect_height, int32_t active_floor_height,
    bool floor_descends_from_disconnect) noexcept
{
    return disconnect_height >= 0 &&
           active_floor_height >= disconnect_height &&
           floor_descends_from_disconnect;
}

bool IsDurableChainLockCandidateCompatible(
    int32_t candidate_height, int32_t durable_target_height,
    bool candidate_descends_target,
    bool target_descends_candidate) noexcept
{
    if (candidate_height < 0 || durable_target_height < 0) return false;
    return candidate_height >= durable_target_height
        ? candidate_descends_target
        : target_descends_candidate;
}

bool IsBTCCPresealCoveredByDurableWinner(
    int32_t marker_height, int32_t winner_height,
    bool winner_descends_marker) noexcept
{
    return marker_height >= 0 && winner_height >= marker_height &&
           winner_descends_marker;
}

} // namespace llmq
