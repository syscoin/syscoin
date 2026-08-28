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
#include <consensus/pq_migration.h>
#include <consensus/validation.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <governance/governanceclasses.h>
#include <logging.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
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

uint8_t DeriveSigningRosterAuthorizationMask(
    const pq::FrozenQuorumRosters& rosters,
    const CBlockIndex& candidate,
    int32_t boundary_height,
    const uint256& boundary_hash)
{
    if (boundary_height < 0 || boundary_height > candidate.nHeight ||
        boundary_hash.IsNull()) {
        return 0;
    }
    const CBlockIndex* boundary{candidate.GetAncestor(boundary_height)};
    if (boundary == nullptr || boundary->GetBlockHash() != boundary_hash) {
        return 0;
    }
    return pq::GetSigningRosterAuthorizationMask(
        rosters, [boundary](int32_t height, const uint256& hash) {
            const CBlockIndex* ancestor{
                height >= 0 && height <= boundary->nHeight
                    ? boundary->GetAncestor(height)
                    : nullptr};
            return ancestor != nullptr && ancestor->GetBlockHash() == hash;
        });
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

bool HasFullChainLockTargetValidation(const CBlockIndex& candidate,
                                      int32_t predecessor_height,
                                      HistoricalIndexValidationCache& cache,
                                      uint64_t provenance_revocation_revision,
                                      std::size_t block_budget =
                                          HistoricalIndexValidationCache::BLOCK_BUDGET)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    constexpr uint32_t target_provenance{
        BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_PQ_RECEIPT_INDEX_VALIDATED};
    if (predecessor_height < 0 ||
        predecessor_height >= candidate.nHeight ||
        (candidate.nStatus & target_provenance) != target_provenance ||
        cache.Validate(
            candidate, predecessor_height + 1,
            HistoricalIndexValidationMode::FULL_FINALITY,
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
           << request.statement.previous_chainlock_height
           << request.statement.previous_chainlock_hash
           << request.statement.previous_btcc_cursor
           << request.statement.btcc_receipt_state
           << request.statement.payment_audit_receipt_state
           << request.statement.payment_probation_state_hash
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
    // unvalidated pre-anchor range. Its exact block hash and indexed receipt
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

std::optional<pq::BTCCReceiptState> RecomputeBTCCReceiptState(
    const ChainstateManager& chainman,
    const CBlockIndex& target,
    const pq::ChainLockFinalityStoreConfig& config,
    int32_t first_carrier_height,
    pq::BTCCReceiptState state,
    bool* transient_failure = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (transient_failure != nullptr) *transient_failure = false;
    if (!state.IsStructurallyValid() || first_carrier_height < 0 ||
        target.nHeight < first_carrier_height ||
        !pq::IsBTCCReceiptCarrierHeight(config.btcc_schedule,
                                        first_carrier_height)) {
        return std::nullopt;
    }
    for (int64_t height{first_carrier_height}; height <= target.nHeight;
         height += config.btcc_schedule.candidate_period) {
        const CBlockIndex* carrier{
            target.GetAncestor(static_cast<int32_t>(height))};
        if (carrier == nullptr) return std::nullopt;
        CBlock block;
        if (!chainman.m_blockman.ReadBlockFromDisk(block, *carrier)) {
            if (transient_failure != nullptr) *transient_failure = true;
            return std::nullopt;
        }
        pq::BTCCReceipt receipt;
        if (!ExtractBTCCReceipt(block, receipt) ||
            !pq::ValidateBTCCReceiptOnBranch(
                config.btcc_schedule, *carrier, receipt)) {
            return std::nullopt;
        }
        const auto next{pq::ApplyBTCCReceiptState(
            chainman.GetConsensus().hashGenesisBlock,
            config.chainlock_schedule, config.btcc_schedule,
            carrier->nHeight, carrier->GetBlockHash(), state, receipt)};
        if (!next) return std::nullopt;
        state = *next;
    }
    return state;
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

} // namespace

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
                     : config.anchor.btcc_cursor};
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

static bool IsInitialChainLockRosterSetAnchored(
    const pq::ChainLockScheduleConfig& schedule,
    uint32_t roster_snapshot_lag,
    int32_t anchor_height) noexcept
{
    const auto last_bootstrap_base{
        pq::EpochBaseHeight(schedule, pq::ACTIVE_QUORUMS - 1)};
    if (!last_bootstrap_base || anchor_height < *last_bootstrap_base ||
        anchor_height == std::numeric_limits<int32_t>::max()) {
        return false;
    }

    std::optional<int32_t> first_target;
    for (int64_t height{static_cast<int64_t>(anchor_height) + 1};
         height <= static_cast<int64_t>(anchor_height) +
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

    const auto active{pq::ActiveEpochsAtHeight(schedule, *first_target)};
    if (!active) return false;
    for (const auto& identity : *active) {
        const auto authorization_height{
            identity.epoch < pq::ACTIVE_QUORUMS
                ? std::optional<int32_t>{identity.base_height}
                : pq::RegistrationCutoffHeight(
                      schedule, identity.epoch, roster_snapshot_lag)};
        if (!authorization_height || *authorization_height > anchor_height) {
            return false;
        }
    }
    return true;
}

std::optional<pq::ChainLockFinalityStoreConfig>
MakePQChainLockFinalityStoreConfig(const Consensus::Params& consensus)
{
    if (Consensus::CheckPQLegacyAnchorConfiguration(consensus) !=
            Consensus::PQAnchorResult::VALID ||
        Consensus::CheckPQChainLockAnchorConfiguration(consensus) !=
            Consensus::PQAnchorResult::VALID) {
        return std::nullopt;
    }
    pq::PQRegistryConfig registry_config;
    if (pq::GetPQRegistryConfig(consensus, registry_config) !=
        pq::PQRegistryDeploymentResult::VALID) {
        return std::nullopt;
    }
    const auto schedule{
        pq::MakeChainLockScheduleConfig(consensus.nPQChainLockEpochOrigin)};
    if (!schedule || *schedule != registry_config.schedule ||
        consensus.nPQRosterSnapshotLag <= 0 ||
        !IsInitialChainLockRosterSetAnchored(
            *schedule, static_cast<uint32_t>(consensus.nPQRosterSnapshotLag),
            consensus.nPQChainLockAnchorHeight) ||
        consensus.nPQBTCCCandidateOrigin == std::numeric_limits<int>::max() ||
        consensus.nPQBTCCCandidateOrigin <=
            consensus.nPQChainLockAnchorHeight ||
        consensus.nPQBTCCNEVMInjectionLag != static_cast<int>(pq::PQ_BTCC_NEVM_LAG)) {
        return std::nullopt;
    }

    pq::ChainLockFinalityStoreConfig config;
    config.chainlock_schedule = *schedule;
    config.btcc_schedule.candidate_origin = consensus.nPQBTCCCandidateOrigin;
    config.btcc_schedule.nevm_injection_lag =
        static_cast<uint32_t>(consensus.nPQBTCCNEVMInjectionLag);
    config.anchor.height = consensus.nPQChainLockAnchorHeight;
    config.anchor.block_hash = consensus.hashPQChainLockAnchorBlock;
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
         (consensus.nDefaultAssumeValidHeight >
              consensus.nPQLegacyAnchorHeight ||
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
        return HasFullChainLockTargetValidation(
                   *seal, predecessor_height, cache,
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
            // The persisted block-index marker distinguishes a full reindex
            // (which can deterministically refetch exact witnesses) from
            // -reindex-chainstate and ordinary restart. Only the former may
            // discard a corrupt archive instead of failing closed.
            m_chainman.m_blockman.m_block_tree_db->ReadReindexing(
                full_reindex);
        }
        m_persistence = std::make_unique<pq::PQChainLockPersistence>(
            DBParams{
                .path = chainman.m_options.datadir / "llmq/pq-chainlocks",
                .cache_bytes = 4U << 20,
                .wipe_data = full_reindex,
            },
            m_genesis_hash, *m_config);
        m_pending_persisted = m_persistence->LoadBest();
        m_pending_persisted_unsealed_btcc =
            m_persistence->LoadUnsealedBTCC();
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
            [this](const pq::FinalChainLock& chainlock) {
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence && m_persistence->PersistBest(chainlock)};
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
            [this](const pq::FinalChainLock& chainlock) {
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistUnsealedBTCC(chainlock)};
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
                       btcc_cursor_reconciliation) {
                const bool persisted{
                    FlushChainLockAuxiliarySnapshotsForDurability() &&
                    m_persistence &&
                    m_persistence->PersistCatchupBest(
                        chainlock, nullptr,
                        btcc_cursor_reconciliation)};
                if (!persisted) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                } else {
                    m_catchup_used.store(true);
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
        // immutable anchor.
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
        m_payment_audit_store->GetPruneCheckpoint().has_value()};
    bool loaded_persisted{false};
    {
        LOCK(m_persisted_mutex);
        loaded_persisted = m_pending_persisted.has_value() ||
                           m_pending_persisted_unsealed_btcc.has_value() ||
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
        (void)TryImportPersistedChainLock();
        (void)TryImportPersistedUnsealedBTCC();
        // A successful import clears the pending gate after the first state
        // check. Enforce it before publishing authentication readiness.
        CheckActiveState();
        EnforceBestChainLock();
        m_scheduler = std::make_unique<CScheduler>();
        CScheduler* const scheduler{m_scheduler.get()};
        m_scheduler_thread = std::make_unique<std::thread>(
            &util::TraceThread, "pqcl-schdlr",
            [scheduler] { scheduler->serviceQueue(); });
        scheduler->scheduleEvery([this]() EXCLUSIVE_LOCKS_REQUIRED(
            !cs_main, !m_chainlock_admission_mutex,
            !m_share_lifecycle_mutex) {
            (void)TryImportPersistedChainLock();
            (void)TryImportPersistedUnsealedBTCC();
            CheckActiveState();
            EnforceBestChainLock();
            RequestNeededBTCCCertificate();
            RequestNeededPaymentAuditCertificate();
            RetryPendingBTCCBlock();
            RequestCatchupChainLock();
            MaybeReplayBTCCPreseal();
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
        m_retry_pending_btcc_block.store(false);
    }
}

std::optional<CChainLocksHandler::CurrentSigningContext>
CChainLocksHandler::CurrentSigningContexts::Find(
    const pq::ChainLockStatement& statement) const
{
    if (!roster_set) return std::nullopt;
    for (std::size_t i{0}; i < count; ++i) {
        if (statements[i] == statement) {
            return CurrentSigningContext{
                static_cast<uint8_t>(i), statement,
                roster_set->RostersPtr(), authorization_mask};
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
    LOCK(m_signer_reconcile_mutex);
    const auto chainlock{m_store->GetBestRecord()};
    if (!chainlock) return true;
    const PQSignerJournalResult result{
        m_signer_journal->ReconcileDurableAcceptedChainLock(
            m_genesis_hash, pro_tx_hash, chainlock->metadata)};
    switch (result.outcome) {
    case PQSignerJournalOutcome::CERTIFICATE_RECONCILED:
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
    const uint256& local_pro_tx_hash)
{
    AssertLockHeld(m_share_signing_mutex);
    if (!m_signer_journal || !m_signer_startup_tip_height || !m_config ||
        context.GenesisHash() != m_genesis_hash ||
        context.Schedule() != m_config->chainlock_schedule) {
        return false;
    }
    const auto& statement{context.Statement()};
    const auto& rosters{context.Rosters()};
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

    const auto checkpoint{m_payment_audit_store->GetPruneCheckpoint()};
    if (checkpoint) {
        // The compact archive boundary is not self-authenticating. Keep IBD
        // recoverable until a still-durable active descendant certificate
        // authenticates the exact authorizer which permitted witness pruning.
        const CBlockIndex* authorizer{
            m_chainman.m_blockman.LookupBlockIndex(
                checkpoint->authorizing_target_hash)};
        if (!checkpoint->IsStructurallyValid() || authorizer == nullptr ||
            authorizer->nHeight != checkpoint->authorizing_target_height ||
            !IsPaymentAuditPrefixAuthenticated(*authorizer)) {
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
    return m_store ? m_store->GetBest() : nullptr;
}

const CBlockIndex* CChainLocksHandler::GetBestChainLockIndex() const
{
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

bool CChainLocksHandler::GetDurableFinalityRecoveryFloor(
    const CBlockIndex*& active_floor,
    const CBlockIndex*& durable_target,
    std::string& error) const
{
    active_floor = nullptr;
    durable_target = nullptr;
    error.clear();
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

        LOCK(cs_main);
        const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
            durable->statement.block_hash)};
        const CBlockIndex* active_tip{m_chainman.ActiveTip()};
        if (target == nullptr ||
            target->nHeight != durable->statement.height ||
            (target->nStatus & BLOCK_FAILED_MASK) ||
            target->IsAssumedValid() ||
            !target->IsValid(BLOCK_VALID_SCRIPTS) ||
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
        const auto& statement{candidate.statement};
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
        if (!BuildPaymentAuditVerificationRosters(
                statement, &subject)) {
            continue;
        }
        const auto transition{DerivePaymentAuditProbationTransition(
            statement.commitment, subject, carrier_parent, carrier_height,
            candidate.result_hash, candidate.online_members)};
        if (!transition) continue;
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
            candidate.online_members};
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                candidates->candidate_revision)) {
            return null_receipt;
        }
        const auto published{
            m_payment_audit_receipt_cache.Publish(cache_key, receipt)};
        if (!published ||
            !m_payment_audit_store->IsCandidateRevisionCurrent(
                candidates->candidate_revision)) {
            return null_receipt;
        }
        return *published;
    }
    return null_receipt;
}

bool CChainLocksHandler::VerifyPaymentAuditCertificateSignatures(
    const pq::FinalPaymentAudit& audit,
    const pq::VerifiedRosterSetPtr& roster_set,
    uint8_t authorization_mask) const
{
    pq::PaymentAuditVerificationError error{
        pq::PaymentAuditVerificationError::NONE};
    auto prepared{pq::PrepareFinalPaymentAuditVerification(
        pq::PaymentAuditScheduleConfig{m_config->chainlock_schedule,
                                       m_config->btcc_schedule},
        audit, roster_set, authorization_mask, &error)};
    if (!prepared) return false;
    LOCK(m_verification_mutex);
    return m_verifier.VerifyChecks(std::move(prepared->checks));
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
    const auto audit_snapshot{
        m_payment_audit_store->GetWithCandidateRevision(
            receipt.audit_witness_id)};
    const pq::FinalPaymentAudit* const audit{
        audit_snapshot ? &audit_snapshot->audit : nullptr};
    const auto archive_status{ClassifyPaymentAuditArchiveRead(
        true, healthy_before_read, audit != nullptr,
        m_payment_audit_store->IsHealthy())};
    if (archive_status !=
        PaymentAuditReceiptCertificateStatus::VERIFIED) {
        return archive_status;
    }
    // The store captures this only after Get() has completed any presence
    // repair, under the same lock as the exact witness read.
    const uint64_t archive_revision{audit_snapshot->revision};
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
    const auto classification{pq::ClassifyPaymentAuditReports(*audit)};
    if (audit->statement.commitment.seed.epoch != receipt.epoch ||
        audit->statement.commitment.seal_height != receipt.seal_height ||
        audit->statement.seal_statement.block_hash !=
            receipt.seal_block_hash ||
        !classification ||
        audit->GetLogicalId(m_genesis_hash) != receipt.audit_logical_id ||
        audit->GetWitnessId(m_genesis_hash) != receipt.audit_witness_id ||
        pq::GetPaymentAuditCommitmentHash(
            m_genesis_hash, audit->statement.commitment) !=
            receipt.commitment_hash ||
        pq::GetPaymentAuditResultHash(
            m_genesis_hash, *audit, *classification) !=
            receipt.result_hash ||
        classification->online_members != receipt.online_members) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    const PaymentAuditHistoricalContext historical{
        PendingPaymentAuditReceiptDependency{
            receipt, carrier.GetBlockHash(),
            carrier.pprev->GetBlockHash()},
        {}, -1};
    pq::FrozenQuorumRoster subject;
    PaymentAuditRosterBuildStatus roster_status{
        PaymentAuditRosterBuildStatus::INVALID};
    uint8_t authorization_mask{0};
    uint64_t verified_roster_generation{0};
    int32_t reconstruction_floor{-1};
    const auto rosters{BuildPaymentAuditVerificationRosters(
        audit->statement, &subject,
        &authorization_mask,
        /*require_live_transition_finality=*/false,
        &roster_status, &historical, &verified_roster_generation,
        &reconstruction_floor)};
    if (!rosters) {
        return roster_status == PaymentAuditRosterBuildStatus::LOCAL_ERROR
            ? PaymentAuditReceiptCertificateStatus::LOCAL_ERROR
            : PaymentAuditReceiptCertificateStatus::INVALID;
    }
    if (!VerifyPaymentAuditCertificateSignatures(
            *audit, rosters, authorization_mask)) {
        return PaymentAuditReceiptCertificateStatus::INVALID;
    }
    bool transition_local_error{false};
    auto transition{DerivePaymentAuditProbationTransition(
        audit->statement.commitment, subject, *carrier.pprev,
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

    VerifiedPaymentAuditReceiptTransitionPtr verified{
        new VerifiedPaymentAuditReceiptTransition{
            receipt, audit->statement, carrier.pprev->GetBlockHash(),
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
    const auto base_height{pq::EpochBaseHeight(
        m_quorum_build_config->schedule, receipt.epoch)};
    const auto snapshot_height{pq::RegistrationCutoffHeight(
        m_quorum_build_config->schedule, receipt.epoch,
        m_quorum_build_config->roster_snapshot_lag_blocks)};
    if (!slot_epoch || *slot_epoch != receipt.epoch || !base_height ||
        !snapshot_height || *snapshot_height >= *base_height ||
        carrier.pprev == nullptr) {
        return PaymentAuditContextStatus::INVALID;
    }
    const CBlockIndex* base{carrier.GetAncestor(*base_height)};
    const CBlockIndex* snapshot{carrier.GetAncestor(*snapshot_height)};
    if (base == nullptr || snapshot == nullptr) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }

    const auto roster_cache{GetQuorumRosterCache()};
    if (!roster_cache) return PaymentAuditContextStatus::LOCAL_ERROR;
    std::optional<pq::QuorumSnapshotState> snapshot_state;
    try {
        snapshot_state = roster_cache->LookupSnapshot(*snapshot);
    } catch (const std::exception&) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    if (!snapshot_state || snapshot_state->deterministic_mns.IsNull() ||
        snapshot_state->deterministic_mns.GetHeight() != *snapshot_height ||
        snapshot_state->deterministic_mns.GetBlockHash() !=
            snapshot->GetBlockHash() ||
        !snapshot_state->operator_key_states) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    std::unique_ptr<pq::FrozenQuorumRoster> subject;
    try {
        subject = pq::BuildFrozenQuorumRoster(
            m_genesis_hash, *m_quorum_build_config, receipt.epoch,
            base->GetBlockHash(), snapshot_state->deterministic_mns,
            std::span<const pq::OperatorKeyState>{
                snapshot_state->operator_key_states->data(),
                snapshot_state->operator_key_states->size()},
            &build_error);
    } catch (const std::exception&) {
        return PaymentAuditContextStatus::LOCAL_ERROR;
    }
    if (!subject || subject->descriptor.epoch != receipt.epoch ||
        subject->descriptor.base_height != *base_height ||
        subject->descriptor.base_hash != base->GetBlockHash() ||
        subject->descriptor.snapshot_height != *snapshot_height ||
        subject->descriptor.snapshot_hash != snapshot->GetBlockHash()) {
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
        missing_receipt.chainlock_target_height <= m_config->anchor.height ||
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
    LOCK(m_btcc_preseal_mutex);
    return !m_btcc_preseal_state.IsEmpty() ||
           !m_payment_audit_preseal_state.IsEmpty();
}

bool CChainLocksHandler::ShouldDeferBTCCNEVM(
    const CBlockIndex& index) const
{
    AssertLockHeld(cs_main);
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
    const auto accepted{m_store->GetBestRecord()};
    const auto durable{m_persistence->GetFinalityState().best};
    if (!checkpoint || !checkpoint->IsStructurallyValid() || !accepted ||
        !durable || accepted->metadata != *durable) {
        return false;
    }
    const CBlockIndex* authorizer{m_chainman.m_blockman.LookupBlockIndex(
        checkpoint->authorizing_target_hash)};
    const CBlockIndex* target{m_chainman.m_blockman.LookupBlockIndex(
        accepted->metadata.statement.block_hash)};
    if (authorizer == nullptr || target == nullptr ||
        authorizer->nHeight != checkpoint->authorizing_target_height ||
        target->nHeight != accepted->metadata.statement.height ||
        target->nHeight < authorizer->nHeight ||
        target->GetAncestor(authorizer->nHeight) != authorizer ||
        (authorizer->nStatus & BLOCK_FAILED_MASK) ||
        (target->nStatus & BLOCK_FAILED_MASK)) {
        return false;
    }
    const CBlockIndex* covered{m_chainman.m_blockman.LookupBlockIndex(
        checkpoint->covered_through_hash)};
    if (covered == nullptr ||
        covered->nHeight != checkpoint->covered_through_height ||
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
        *indexed_authorizer != checkpoint->authenticated_receipt_state ||
        authorizer->pqPaymentProbationStateHash !=
            checkpoint->authenticated_probation_state_hash ||
        !indexed_target ||
        *indexed_target !=
            accepted->metadata.statement.payment_audit_receipt_state ||
        target->pqPaymentProbationStateHash !=
            accepted->metadata.statement.payment_probation_state_hash) {
        return false;
    }
    const bool same_authorizer_target{
        accepted->metadata.statement.height ==
            checkpoint->authorizing_target_height &&
        accepted->metadata.statement.block_hash ==
            checkpoint->authorizing_target_hash};
    const bool exact_authorizer{
        same_authorizer_target &&
        accepted->metadata.logical_id ==
            checkpoint->authorizing_chainlock_logical_id &&
        accepted->metadata.witness_id ==
            checkpoint->authorizing_chainlock_witness_id};
    if (same_authorizer_target && !exact_authorizer) return false;
    if (!exact_authorizer) {
        const auto& previous{
            checkpoint->authenticated_receipt_state.cursor};
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
                 checkpoint->authenticated_receipt_state ||
             accepted->metadata.statement.payment_probation_state_hash !=
                 checkpoint->authenticated_probation_state_hash)) {
            return false;
        }
    }
    const auto indexed{IndexedPaymentAuditReceiptState(index)};
    if (!indexed) return false;
    if (indexed->cursor.IsNull()) return true;
    return indexed->cursor.epoch <= checkpoint->prune_through_epoch;
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
    uint64_t next_revision{m_btcc_preseal_revision};
    if (durable != m_btcc_preseal_state && !durable.IsEmpty()) {
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
    const auto inspect = [&](const auto& chainlock) {
        if (!chainlock || !valid) return;
        found_durable = true;
        if (!m_quorum_build_config) {
            valid = false;
            return;
        }
        const auto candidate_floor{OldestRosterSnapshotHeight(
            *m_quorum_build_config, chainlock->statement.height)};
        if (!candidate_floor) {
            valid = false;
            return;
        }
        floor = floor ? std::min(*floor, *candidate_floor)
                      : *candidate_floor;
    };
    if (m_persistence) {
        const auto durable{m_persistence->GetFinalityState()};
        inspect(durable.best);
        inspect(durable.unsealed_btcc);
    }
    if (!found_durable && m_config) {
        // SYSCOIN: The anchor authorizes finality, but the first admissible
        // winner authenticates older registration cutoffs. Keep that roster
        // requirement separate from the future destructive-GC authority.
        const auto first_target{m_quorum_build_config
            ? pq::NextEligibleChainLockTargetHeight(
                  m_quorum_build_config->schedule,
                  m_config->anchor.height)
            : std::nullopt};
        const auto first_roster_floor{first_target && m_quorum_build_config
            ? OldestRosterSnapshotHeight(
                  *m_quorum_build_config, *first_target)
            : std::nullopt};
        if (!first_roster_floor) {
            valid = false;
        } else {
            floor = std::min(m_config->anchor.height,
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
        // An unsealed BTCC record affects roster retention only. Before the
        // first enforced winner, destruction is authorized solely by the
        // release-pinned ChainLock anchor.
        if (accepted_best || !m_config->anchor.IsStructurallyValid()) {
            revoke();
            return;
        }
        authorization.source = CDeterministicMNManager::
            AuxiliaryHistoryGCAuthorizationSource::
                IMMUTABLE_CHAINLOCK_ANCHOR;
        authorization.block = {
            m_config->anchor.height,
            m_config->anchor.block_hash};
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
    const pq::ChainLockPredecessor local{
        best ? pq::ChainLockPredecessor{
                   best->metadata.statement.height,
                   best->metadata.statement.block_hash,
                   best->metadata.statement.accepted_btcc_cursor}
             : pq::ChainLockPredecessor{
                   m_config->anchor.height, m_config->anchor.block_hash,
                   m_config->anchor.btcc_cursor}};
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
             statement.height > m_config->anchor.height &&
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
            best ? best->metadata.statement.height : m_config->anchor.height};
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

void CChainLocksHandler::MaybeReplayBTCCPreseal()
{
    pq::BTCCPresealState durable;
    pq::PaymentAuditPresealState payment_audit_durable;
    {
        LOCK(m_btcc_preseal_mutex);
        durable = m_btcc_preseal_state;
        payment_audit_durable = m_payment_audit_preseal_state;
    }
    if (durable.IsEmpty()) {
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
            int32_t scan_from{std::numeric_limits<int32_t>::max()};
            if (next.active) {
                scan_from = std::min(scan_from,
                                     next.active->earliest_carrier_height);
            }
            if (next.prospective) {
                scan_from = std::min(scan_from,
                                     next.prospective->earliest_carrier_height);
            }
            std::optional<pq::BTCCPresealMarker> recovered;
            if (scan_from != std::numeric_limits<int32_t>::max() &&
                scan_from <= active_tip->nHeight) {
                for (int32_t height{scan_from};
                     height <= active_tip->nHeight; ++height) {
                    if (!pq::IsBTCCReceiptCarrierHeight(
                            m_config->btcc_schedule, height)) {
                        continue;
                    }
                    const CBlockIndex* carrier{
                        active_tip->GetAncestor(height)};
                    CBlock block;
                    pq::BTCCReceipt receipt;
                    // Disk/transient failures retain both old obligations and
                    // retry later; they never authorize clearing the boundary.
                    if (carrier == nullptr ||
                        !m_chainman.m_blockman.ReadBlockFromDisk(
                            block, *carrier) ||
                        !ExtractBTCCReceipt(block, receipt) ||
                        !pq::ValidateBTCCReceiptOnBranch(
                            m_config->btcc_schedule, *carrier, receipt)) {
                        return;
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
                    if (!predecessor_state) return;
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
                        recovered->terminal_carrier_hash =
                            carrier->GetBlockHash();
                        recovered->terminal_receipt = receipt;
                    }
                }
            }
            next.active = recovered;
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
        if (!marker || !marker_on_active(marker)) return;

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
            replay_through = active_tip->nHeight;
            for (int32_t height{authenticated_through + 1};
                 height <= active_tip->nHeight; ++height) {
                if (!pq::IsBTCCReceiptCarrierHeight(
                        m_config->btcc_schedule, height)) {
                    continue;
                }
                const CBlockIndex* carrier{
                    active_tip->GetAncestor(height)};
                CBlock block;
                pq::BTCCReceipt receipt;
                if (carrier == nullptr ||
                    !m_chainman.m_blockman.ReadBlockFromDisk(
                        block, *carrier) ||
                    !ExtractBTCCReceipt(block, receipt) ||
                    (!receipt.IsNull() &&
                     CheckBTCCReceiptCertificate(receipt, *carrier) !=
                         BTCCReceiptCertificateStatus::VERIFIED)) {
                    replay_through = height - 1;
                    break;
                }
            }
            const CBlockIndex* replay_index{
                active_tip->GetAncestor(replay_through)};
            if (replay_index != nullptr) {
                replay_through_hash = replay_index->GetBlockHash();
            }
        } else {
            LOCK(m_needed_btcc_certificate_mutex);
            if (m_needed_btcc_certificate !=
                marker->terminal_receipt.chainlock_logical_id) {
                m_needed_btcc_certificate =
                    marker->terminal_receipt.chainlock_logical_id;
                m_needed_btcc_last_request = std::chrono::microseconds{0};
            }
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
    (void)RevalidatePendingBTCCReceiptDependency();
    std::optional<uint256> logical_id;
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(m_pending_btcc_receipt_mutex);
        if (m_pending_btcc_receipt &&
            (m_pending_btcc_last_request.count() == 0 ||
             now - m_pending_btcc_last_request >= std::chrono::seconds{5})) {
            logical_id = m_pending_btcc_receipt->logical_id;
            m_pending_btcc_last_request = now;
        }
    }
    // A best-work block dependency outranks signing/readiness lookups. It is
    // still a single deduplicated ID and therefore cannot expand the ordinary
    // CLSIG download lanes.
    if (!logical_id) {
    {
        LOCK(m_needed_btcc_certificate_mutex);
        if (!m_needed_btcc_certificate ||
            (m_needed_btcc_last_request.count() != 0 &&
             now - m_needed_btcc_last_request < std::chrono::seconds{30})) {
            return;
        }
        logical_id = m_needed_btcc_certificate;
        m_needed_btcc_last_request = now;
    }
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

bool CChainLocksHandler::HasFullChainLockTargetValidationCached(
    const CBlockIndex& candidate, int32_t predecessor_height) const
{
    AssertLockHeld(cs_main);
    return HasFullChainLockTargetValidation(
        candidate, predecessor_height,
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
            // only after every post-anchor index proves full non-assumed
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
            auto proof{RecomputeBTCCReceiptState(
                m_chainman, candidate, *m_config,
                first_marker->earliest_carrier_height,
                first_marker->predecessor_receipt_state,
                &transient_failure)};
            if (proof && *proof != *indexed) proof.reset();
            return {std::move(proof), !transient_failure};
        });
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
         historical.admission == HistoricalAdmission::CURRENT_CATCHUP)};
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
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP ||
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const bool exact_preseal_receipt{
        !preseal_receipt ||
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const int32_t validation_floor{
        request.admission == pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE
            ? request.statement.previous_chainlock_height
            : request.local_best.height};
    const bool exact_local_target{HasFullChainLockTargetValidationCached(
        *candidate, validation_floor)};
    const bool payment_only_catchup{
        catchup && exact_local_target &&
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP &&
        m_config->btcc_receipt_assumption_anchor.IsDisabled()};
    const auto catchup_proof{
        (catchup || preseal_receipt) && exact_catchup_target &&
                exact_preseal_receipt && active_tip != nullptr
            ? (payment_only_catchup
                   ? IndexedBTCCReceiptState(*candidate)
                   : GetCatchupHistoricalProof(
                         *candidate, historical.admission))
            : std::optional<pq::BTCCReceiptState>{}};
    const bool trusted_persistence{
        request.admission ==
        pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE};
    const bool catchup_historical_receipt_range{
        catchup && !exact_local_target && validation_floor >= 0 &&
        ClassifyHistoricalReceiptIndexRangeCached(
            *candidate, validation_floor) ==
            PaymentAuditContextStatus::READY};
    const bool trusted_historical_range{
        trusted_persistence && !exact_local_target &&
        GetFullyValidatedBTCCCatchupRangeStatusCached(
            *candidate,
            m_config->btcc_receipt_assumption_anchor) ==
            BTCCCatchupRangeStatus::VALID &&
        ClassifyHistoricalReceiptIndexRangeCached(
            *candidate,
            m_config->btcc_receipt_assumption_anchor.height) ==
            PaymentAuditContextStatus::READY};
    const bool validated{
        live_candidate_admissible && exact_catchup_target &&
        exact_preseal_receipt && marker_snapshot_matches_historical &&
        !side_candidate_blocked_by_preseal &&
        (trusted_persistence
             ? (exact_local_target || trusted_historical_range)
             : (catchup ? (catchup_proof.has_value() &&
                           (exact_local_target ||
                            catchup_historical_receipt_range))
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
        pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE) {
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
             (catchup && historical.admission ==
                              HistoricalAdmission::CURRENT_CATCHUP));
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
        (request.admission == pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE ||
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
    pq::PaymentAuditStoreCheckpoint committed_checkpoint{
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

        // The checkpoint batch follows index/probation fsync, durable certificate
        // installation, active-chain enforcement, and the chainstate marker. A
        // crash before this write keeps every audit; a crash after it can
        // authenticate the pruned prefix even if marker clearing lags.
        if (!reuse_archive_checkpoint &&
            !m_payment_audit_store->PruneThroughCheckpoint(checkpoint)) {
            const auto observed{
                m_payment_audit_store->GetPruneCheckpoint()};
            if (!m_payment_audit_store->IsHealthy() || !observed ||
                !observed->IsStructurallyValid()) {
                m_persistence_failed.store(true);
                DisableShareAdmission();
                return;
            }
            if (*observed != checkpoint) {
                // A later enforced winner can win the checkpoint race. Accept it
                // only when the current durable winner cryptographically matches
                // the observed authorizer and extends this exact active target.
                const auto accepted_now{m_store->GetBestRecord()};
                const auto persisted_now{
                    m_persistence->GetFinalityState().best};
                const CBlockIndex* observed_authorizer{
                    m_chainman.m_blockman.LookupBlockIndex(
                        observed->authorizing_target_hash)};
                const CBlockIndex* observed_covered{
                    m_chainman.m_blockman.LookupBlockIndex(
                        observed->covered_through_hash)};
                const auto observed_state{
                    observed_authorizer == nullptr
                        ? std::optional<pq::PaymentAuditReceiptState>{}
                        : IndexedPaymentAuditReceiptState(
                              *observed_authorizer)};
                const bool same_boundary_refresh{
                    observed->prune_through_epoch ==
                        checkpoint.prune_through_epoch &&
                    observed->covered_through_height ==
                        checkpoint.covered_through_height &&
                    observed->covered_through_hash ==
                        checkpoint.covered_through_hash &&
                    observed->authenticated_receipt_state ==
                        checkpoint.authenticated_receipt_state &&
                    observed->authenticated_probation_state_hash ==
                        checkpoint.authenticated_probation_state_hash &&
                    observed->authorizing_target_height >
                        checkpoint.authorizing_target_height};
                const bool boundary_advance{
                    observed->prune_through_epoch >
                        checkpoint.prune_through_epoch &&
                    observed->covered_through_height >
                        checkpoint.covered_through_height &&
                    observed->authorizing_target_height >=
                        observed->covered_through_height};
                const bool durable_dominates{
                    accepted_now && persisted_now &&
                    accepted_now->metadata == *persisted_now &&
                    observed_authorizer != nullptr &&
                    observed_covered != nullptr && observed_state &&
                    observed_authorizer->nHeight ==
                        observed->authorizing_target_height &&
                    observed_covered->nHeight ==
                        observed->covered_through_height &&
                    observed_authorizer->GetAncestor(
                        observed_covered->nHeight) == observed_covered &&
                    observed_authorizer->nHeight >= target->nHeight &&
                    observed_authorizer->GetAncestor(target->nHeight) ==
                        target &&
                    active_tip->nHeight >= observed_authorizer->nHeight &&
                    active_tip->GetAncestor(observed_authorizer->nHeight) ==
                        observed_authorizer &&
                    !(observed_authorizer->nStatus & BLOCK_FAILED_MASK) &&
                    !observed_authorizer->IsAssumedValid() &&
                    observed_authorizer->IsValid(BLOCK_VALID_SCRIPTS) &&
                    HasFullReceiptIndexProvenance(*observed_authorizer) &&
                    *observed_state ==
                        observed->authenticated_receipt_state &&
                    observed_authorizer->pqPaymentProbationStateHash ==
                        observed->authenticated_probation_state_hash &&
                    accepted_now->metadata.statement.height ==
                        observed->authorizing_target_height &&
                    accepted_now->metadata.statement.block_hash ==
                        observed->authorizing_target_hash &&
                    accepted_now->metadata.logical_id ==
                        observed->authorizing_chainlock_logical_id &&
                    accepted_now->metadata.witness_id ==
                        observed->authorizing_chainlock_witness_id &&
                    accepted_now->metadata.statement.payment_audit_receipt_state ==
                        *observed_state &&
                    accepted_now->metadata.statement.payment_probation_state_hash ==
                        observed_authorizer->pqPaymentProbationStateHash &&
                    (observed_authorizer->nHeight == target->nHeight ||
                     ClassifyHistoricalReceiptIndexRangeCached(
                         *observed_authorizer, target->nHeight + 1) ==
                         PaymentAuditContextStatus::READY) &&
                    (same_boundary_refresh || boundary_advance)};
                if (!durable_dominates) {
                    m_persistence_failed.store(true);
                    DisableShareAdmission();
                    return;
                }
                committed_checkpoint = *observed;
                checkpoint_target = observed_authorizer;
            }
        }

        pq::PaymentAuditPresealState retained_markers;
        {
            LOCK(m_btcc_preseal_mutex);
            retained_markers = m_payment_audit_preseal_state;
        }
        std::vector<uint256> retained_probation_roots;
        const auto retain_probation_root = [&](const uint256& root) {
            if (!root.IsNull() &&
                std::find(retained_probation_roots.begin(),
                          retained_probation_roots.end(), root) ==
                    retained_probation_roots.end()) {
                retained_probation_roots.push_back(root);
            }
        };
        retain_probation_root(
            committed_checkpoint.authenticated_probation_state_hash);
        retain_probation_root(
            checkpoint_target->pqPaymentProbationStateHash);
        const auto chainstate_probation_roots{
            CollectChainstatePaymentProbationRoots(m_chainman)};
        if (!chainstate_probation_roots) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return;
        }
        for (const uint256& root : *chainstate_probation_roots) {
            retain_probation_root(root);
        }
        if (retained_markers.active) {
            retain_probation_root(
                retained_markers.active->predecessor_probation_state_hash);
        }
        if (retained_markers.prospective) {
            retain_probation_root(
                retained_markers.prospective
                    ->predecessor_probation_state_hash);
        }
        bool probation_gc_succeeded{false};
        try {
            probation_gc_succeeded =
                deterministicMNManager &&
                deterministicMNManager
                    ->PrunePaymentProbationStatesThroughCheckpoint(
                        committed_checkpoint,
                        std::span<const uint256>{
                            retained_probation_roots});
        } catch (const std::exception& exception) {
            LogPrintf("CChainLocksHandler::%s -- payment probation state GC "
                      "failed: %s\n",
                      __func__, exception.what());
        }
        if (!probation_gc_succeeded) {
            m_persistence_failed.store(true);
            DisableShareAdmission();
            return;
        }
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

std::optional<CChainLocksHandler::RuntimeVerificationContext>
CChainLocksHandler::BuildRuntimeVerificationContext(
    const pq::PreparedFinalChainLockCandidate& prepared,
    bool* definitively_invalid) const
{
    if (definitively_invalid != nullptr) *definitively_invalid = false;
    if (!m_config || !m_quorum_build_config) return std::nullopt;
    const auto roster_cache{GetQuorumRosterCache()};
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

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    const auto roster_set{roster_cache->GetVerifiedActive(
        prepared.statement.height, *candidate, &build_error)};
    if (!roster_set) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid =
                build_error != pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR &&
                build_error != pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED &&
                build_error != pq::QuorumBuildError::INVALID_FROZEN_ROSTER;
        }
        return std::nullopt;
    }
    const auto& rosters{roster_set->Rosters()};
    const uint8_t authorization_mask{
        DeriveSigningRosterAuthorizationMask(
            rosters, *candidate,
            prepared.statement.previous_chainlock_height,
            prepared.statement.previous_chainlock_hash)};
    if (!pq::IsSigningRosterAuthorizationMask(authorization_mask)) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid = true;
        }
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
                 HistoricalAdmission::PRESEAL_CATCHUP ||
             historical.admission ==
                 HistoricalAdmission::PRESEAL_RECEIPT)};
        const bool expected_receipt{
            prepared.admission ==
                pq::ChainLockCandidateAdmission::PRESEAL_RECEIPT &&
            historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
        if (!expected_catchup && !expected_receipt) return std::nullopt;
    }
    return RuntimeVerificationContext{
        roster_set, authorization_mask, historical};
}

std::optional<CChainLocksHandler::RuntimeVerificationContext>
CChainLocksHandler::BuildHistoricalPreVerificationContext(
    const pq::FinalChainLock& chainlock,
    const HistoricalAdmissionContext& expected,
    bool* definitively_invalid) const
{
    if (definitively_invalid != nullptr) *definitively_invalid = false;
    if (!m_config || !m_quorum_build_config ||
        expected.admission == HistoricalAdmission::NONE) {
        return std::nullopt;
    }
    const auto roster_cache{GetQuorumRosterCache()};
    if (!roster_cache) return std::nullopt;

    LOCK(cs_main);
    if (GetHistoricalAdmissionLocked(
            chainlock.statement,
            chainlock.GetLogicalId(m_genesis_hash)) != expected) {
        return std::nullopt;
    }
    if (!m_chainman.IsBaseBlockSyncComplete() ||
        (m_chainman.IsSnapshotActive() &&
         !m_chainman.IsSnapshotValidated())) {
        return std::nullopt;
    }
    const CBlockIndex* candidate{m_chainman.m_blockman.LookupBlockIndex(
        chainlock.statement.block_hash)};
    if (candidate == nullptr ||
        candidate->nHeight != chainlock.statement.height) {
        return std::nullopt;
    }
    if (candidate->nStatus & BLOCK_FAILED_MASK) {
        if (definitively_invalid != nullptr) *definitively_invalid = true;
        return std::nullopt;
    }
    if (candidate->IsAssumedValid() ||
        !candidate->IsValid(BLOCK_VALID_SCRIPTS) ||
        !HasFullReceiptIndexProvenance(*candidate)) {
        return std::nullopt;
    }
    const CBlockIndex* active_tip{m_chainman.ActiveTip()};
    const bool active_candidate{
        active_tip != nullptr && active_tip->nHeight >= candidate->nHeight &&
        active_tip->GetAncestor(candidate->nHeight) == candidate};
    if (expected.admission == HistoricalAdmission::CURRENT_CATCHUP &&
        !active_candidate && !(candidate->nStatus & BLOCK_HAVE_DATA)) {
        return std::nullopt;
    }

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    const auto roster_set{roster_cache->GetVerifiedActive(
        chainlock.statement.height, *candidate, &build_error)};
    if (!roster_set) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid =
                build_error != pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR &&
                build_error != pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED &&
                build_error != pq::QuorumBuildError::INVALID_FROZEN_ROSTER;
        }
        return std::nullopt;
    }
    const auto& rosters{roster_set->Rosters()};
    const uint8_t authorization_mask{
        DeriveSigningRosterAuthorizationMask(
            rosters, *candidate,
            chainlock.statement.previous_chainlock_height,
            chainlock.statement.previous_chainlock_hash)};
    if (!pq::IsSigningRosterAuthorizationMask(authorization_mask)) {
        if (definitively_invalid != nullptr) {
            *definitively_invalid = true;
        }
        return std::nullopt;
    }
    return RuntimeVerificationContext{
        roster_set, authorization_mask, expected};
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

    uint256 payment_audit_preseal_token;
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_preseal_token = PaymentAuditPresealStateToken(
            m_payment_audit_preseal_state);
    }

    const pq::ChainLockPredecessor durable_predecessor{
        finality.best ? pq::ChainLockPredecessor{
                   finality.best->statement.height,
                   finality.best->statement.block_hash,
                   finality.best->statement.accepted_btcc_cursor}
             : pq::ChainLockPredecessor{
                   m_config->anchor.height, m_config->anchor.block_hash,
                   m_config->anchor.btcc_cursor}};

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    pq::VerifiedRosterSetPtr roster_set;
    pq::FrozenQuorumRostersPtr rosters;
    CurrentChainLockBTCCSelection btcc;
    uint8_t authorization_mask{0};
    CurrentSigningSource source;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive() ||
            (m_chainman.IsSnapshotActive() &&
             !m_chainman.IsSnapshotValidated())) {
            return std::nullopt;
        }
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const auto window{tip == nullptr
            ? std::optional<pq::ChainLockSigningWindow>{}
            : pq::CurrentChainLockSigningWindow(
                  m_config->chainlock_schedule,
                  durable_predecessor.height, tip->nHeight)};
        if (tip == nullptr || !window) return std::nullopt;
        const CChain& active_chain{m_chainman.ActiveChain()};
        const CBlockIndex* indexed_target{
            active_chain[window->target_height]};
        const CBlockIndex* declared_predecessor{
            active_chain[window->declared_predecessor_height]};
        if (indexed_target == nullptr || declared_predecessor == nullptr) {
            return std::nullopt;
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
        const auto certificate_status = [this](
            const pq::BTCCReceipt& receipt,
            const CBlockIndex& carrier)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            const auto status{
                CheckBTCCReceiptCertificate(receipt, carrier)};
            if (status == BTCCReceiptCertificateStatus::VERIFIED) {
                LOCK(m_needed_btcc_certificate_mutex);
                if (m_needed_btcc_certificate ==
                    receipt.chainlock_logical_id) {
                    m_needed_btcc_certificate.reset();
                    m_needed_btcc_last_request =
                        std::chrono::microseconds{0};
                }
            } else if (status ==
                       BTCCReceiptCertificateStatus::MISSING) {
                LOCK(m_needed_btcc_certificate_mutex);
                m_needed_btcc_certificate =
                    receipt.chainlock_logical_id;
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
        roster_set = roster_cache->GetVerifiedActive(
            indexed_target->nHeight, *indexed_target, &build_error);
        if (roster_set) {
            rosters = roster_set->RostersPtr();
            authorization_mask = DeriveSigningRosterAuthorizationMask(
                *rosters, *indexed_target,
                window->declared_predecessor_height,
                declared_predecessor->GetBlockHash());
        }

        source.admission_generation = admission_generation;
        source.finality_store_revision = finality.state_revision;
        source.roster_source_generation = roster_source_generation;
        source.persistence_certificate_revision =
            persistence.certificate_revision;
        source.provenance_revocation_revision =
            provenance_revocation_revision;
        source.payment_audit_checkpoint_token =
            PaymentAuditCheckpointToken(payment_audit_checkpoint);
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
    }
    if (!rosters ||
        !pq::IsSigningRosterAuthorizationMask(authorization_mask)) {
        // One newest roster may wait while the older three keep signing; a
        // shorter or gapped predecessor-authorized prefix fails closed.
        return std::nullopt;
    }

    CurrentSigningContexts contexts;
    contexts.source = std::move(source);
    pq::ChainLockStatement& selected{contexts.statements[contexts.count++]};
    selected.height = contexts.source.window.target_height;
    selected.block_hash = contexts.source.target_hash;
    selected.previous_chainlock_height =
        contexts.source.window.declared_predecessor_height;
    selected.previous_chainlock_hash =
        contexts.source.declared_predecessor_hash;
    selected.previous_btcc_cursor = btcc.previous_cursor;
    selected.accepted_btcc_cursor = btcc.selected.cursor;
    selected.btcc_advance = btcc.selected.advance;
    selected.btcc_receipt_state = contexts.source.btcc_receipt_state;
    selected.payment_audit_receipt_state =
        contexts.source.payment_audit_receipt_state;
    selected.payment_probation_state_hash =
        contexts.source.payment_probation_state_hash;
    selected.quorum_context_hash = pq::GetQuorumContextHash(
        m_genesis_hash, selected.height, selected.block_hash,
        Descriptors(*rosters));
    if (!selected.IsStructurallyValid()) return std::nullopt;

    if (selected.btcc_advance == pq::BTCCAdvance::ADVANCE &&
        (pq::IsDurableBTCCursorMonotonic(
             durable_predecessor.btcc_cursor,
             selected.previous_btcc_cursor) ||
         btcc.cursor_reconciliation)) {
        // BTCPREV availability is an independent sentry policy decision, not
        // a prerequisite for base ChainLock liveness. The only permitted
        // alternative keeps the exact predecessor cursor; both variants bind
        // the same target, predecessor, and frozen rosters.
        pq::ChainLockStatement& keep{contexts.statements[contexts.count++]};
        keep = selected;
        keep.accepted_btcc_cursor = keep.previous_btcc_cursor;
        keep.btcc_advance = pq::BTCCAdvance::KEEP;
        if (!keep.IsStructurallyValid()) return std::nullopt;
    }
    contexts.roster_set = std::move(roster_set);
    contexts.authorization_mask = authorization_mask;
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
    uint256 payment_audit_preseal_token;
    {
        LOCK(m_btcc_preseal_mutex);
        payment_audit_preseal_token = PaymentAuditPresealStateToken(
            m_payment_audit_preseal_state);
    }
    const pq::ChainLockPredecessor durable_predecessor{
        finality.best
            ? pq::ChainLockPredecessor{
                  finality.best->statement.height,
                  finality.best->statement.block_hash,
                  finality.best->statement.accepted_btcc_cursor}
            : pq::ChainLockPredecessor{
                  m_config->anchor.height, m_config->anchor.block_hash,
                  m_config->anchor.btcc_cursor}};
    if (finality.state_revision != source.finality_store_revision ||
        durable.certificate_revision !=
            source.persistence_certificate_revision ||
        durable.best != finality.best ||
        durable_predecessor != source.durable_predecessor ||
        PaymentAuditCheckpointToken(payment_audit_checkpoint) !=
            source.payment_audit_checkpoint_token ||
        payment_audit_preseal_token !=
            source.payment_audit_preseal_token ||
        !IsQuorumRosterSourceGenerationCurrent(
            source.roster_source_generation)) {
        return false;
    }

    bool branch_current{false};
    {
        LOCK(cs_main);
        const CBlockIndex* tip{m_chainman.ActiveTip()};
        const auto window{tip == nullptr
            ? std::optional<pq::ChainLockSigningWindow>{}
            : pq::CurrentChainLockSigningWindow(
                  m_config->chainlock_schedule,
                  source.durable_predecessor.height, tip->nHeight)};
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
        branch_current =
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
    }
    if (!branch_current) return false;

    // These observations bracket the chain-index check. A source is usable
    // only when every independently synchronized input remained unchanged.
    const auto finality_after{m_store->ObserveState()};
    const auto durable_after{m_persistence->GetFinalityState()};
    if (!m_payment_audit_store->IsHealthy()) return false;
    const auto payment_audit_checkpoint_after{
        m_payment_audit_store->GetPruneCheckpoint()};
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
           payment_audit_preseal_after ==
               payment_audit_preseal_token &&
           IsQuorumRosterSourceGenerationCurrent(
               source.roster_source_generation);
}

bool CChainLocksHandler::CheckBTCHeaderSigningPolicy(
    const pq::ChainLockStatement& statement)
{
    if (statement.btcc_advance == pq::BTCCAdvance::KEEP ||
        !pq::IsBTCHeaderPolicyEnabled()) {
        return true;
    }
    if (statement.btcc_advance != pq::BTCCAdvance::ADVANCE ||
        statement.accepted_btcc_cursor.IsNull()) {
        return false;
    }

    const uint256 statement_id{
        pq::GetLogicalChainLockId(m_genesis_hash, statement)};

    // Do not trust the statement's serialized cursor in isolation. Re-derive
    // the scheduled source and exact indexed BTCPREV before consulting this
    // sentry's independent Bitcoin view.
    {
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
    const bool backend_healthy{
        m_chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
            /*recover=*/true, reason)};
    auto config{backend_healthy
                    ? pq::GetConfiguredBTCHeaderPolicy(reason)
                    : std::nullopt};
    if (config && m_config) {
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
                     "CChainLocksHandler::%s -- refusing BTCC ADVANCE share "
                     "at height %d: %s\n",
                     __func__, statement.height, reason);
        }
        return false;
    }

    // This result is Bitcoin policy only. External calls hold no Syscoin
    // authority; the caller must capture the exact published collector and
    // recheck its source and both local pre-seals before any signer-journal
    // state is consumed.
    {
        LOCK(m_btc_header_policy_mutex);
        m_btc_header_policy_last_denied.reset();
        m_btc_header_policy_last_reason.clear();
    }
    if (checked->previous_was_reorged) {
        LogPrint(BCLog::CHAINLOCKS,
                 "CChainLocksHandler::%s -- Bitcoin reorg recovery accepted "
                 "for BTCC ADVANCE at height %d after recent-fork policy "
                 "cleared\n",
                 __func__, statement.height);
    }
    return true;
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
        !current->roster_set || !current->relay_recipients ||
        !pq::IsSigningRosterAuthorizationMask(
            current->authorization_mask)) {
        return {};
    }
    for (std::size_t i{0}; i < current->count; ++i) {
        if (!m_collectors[i] ||
            m_collectors[i]->GetStatement() != current->statements[i] ||
            m_collectors[i]->GetPreparedContext()->RosterSetPtr() !=
                current->roster_set ||
            m_collectors[i]->GetPreparedContext()->AuthorizationMask() !=
                current->authorization_mask) {
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
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
        return false;
    }
    const auto is_current = [this](
        const CurrentSigningContextsPtr& contexts) {
        return contexts && IsCurrentSigningSource(contexts->source);
    };

    auto cached{GetPublishedCurrentSigningContexts(admission_generation)};
    if (is_current(cached)) return true;

    LOCK(m_context_build_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) {
        return false;
    }
    cached = GetPublishedCurrentSigningContexts(admission_generation);
    if (is_current(cached)) return true;

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
    built->relay_recipients =
        std::make_shared<const ChainLockRelayRecipients>(
            BuildChainLockRelayRecipients(
                built->roster_set->Rosters()));

    pq::ChainLockVerificationError verification_error{
        pq::ChainLockVerificationError::NONE};
    std::array<std::unique_ptr<pq::ChainLockCollector>,
               CurrentSigningContexts::MAX_VARIANTS> collectors;
    for (std::size_t i{0}; i < built->count; ++i) {
        auto prepared{pq::PreparedChainLockContext::Create(
            m_config->chainlock_schedule, built->statements[i],
            built->roster_set, built->authorization_mask,
            &verification_error)};
        if (!prepared) {
            retire_replaced_if_exact();
            return false;
        }
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        collectors[i] = pq::ChainLockCollector::Create(
            std::move(prepared), &error);
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

    const auto roster_cache{GetQuorumRosterCache()};
    if (!roster_cache) return std::nullopt;

    const auto finalized{
        m_store->GetByHeight(row->expected.response_height)};
    std::optional<pq::ChainLockStatement> response_statement;
    if (finalized) {
        response_statement = finalized->statement;
    } else {
        response_statement =
            m_payment_audit_staging_store->GetVerifiedResponseStatement(
                row->expected);
    }
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

    pq::VerifiedRosterSetPtr roster_set;
    uint8_t authorization_mask{0};
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
        pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
        roster_set = roster_cache->GetVerifiedActive(
            response_index->nHeight, *response_index, &build_error);
        if (roster_set) {
            authorization_mask = DeriveSigningRosterAuthorizationMask(
                roster_set->Rosters(), *response_index,
                response_statement->previous_chainlock_height,
                response_statement->previous_chainlock_hash);
        }
    }
    if (!roster_set || roster_set->Rosters().back().descriptor.epoch != epoch ||
        roster_set->Rosters().back().descriptor.valid_members !=
            row->subject_valid_members ||
        pq::GetPaymentAuditDescriptorHash(
            m_genesis_hash, roster_set->Rosters().back().descriptor) !=
            row->expected.subject_descriptor_hash ||
        !pq::IsSigningRosterAuthorizationMask(authorization_mask) ||
        (authorization_mask &
         (uint8_t{1} << (pq::ACTIVE_QUORUMS - 1))) == 0) {
        return std::nullopt;
    }
    auto response_context{pq::PreparedChainLockContext::Create(
        m_config->chainlock_schedule, std::move(*response_statement),
        std::move(roster_set),
        authorization_mask)};
    if (!response_context) {
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
    return PaymentAuditResponseDefinition{
        *row, std::move(response_context), std::move(active_relays)};
}

bool CChainLocksHandler::IsPaymentAuditResponseDefinitionSourceCurrent(
    const PaymentAuditResponseDefinition& definition) const
{
    if (!m_store || !definition.response_context) return false;
    const auto finalized{m_store->GetByHeight(
        definition.row.expected.response_height)};
    if (!finalized) return true;
    return pq::MatchesPaymentAuditResponseContext(
        definition.row.expected, *definition.response_context,
        finalized->statement);
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

    const auto roster_cache{GetQuorumRosterCache()};
    if (!roster_cache) return false;

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
        const auto response_chainlock{
            m_store->GetByHeight(row_schedule.response_height)};
        if (!response_chainlock ||
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
            pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
            rosters = roster_cache->GetActive(
                response_index->nHeight, *response_index, &build_error);
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
    const pq::PaymentAuditResponse& response, NodeId except_peer)
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
    if (definition == nullptr ||
        definition->row.expected.subject_descriptor_hash !=
            response.subject_descriptor_hash ||
        !IsPaymentAuditResponseDefinitionSourceCurrent(*definition) ||
        !IsCurrentPaymentAuditNetworkRow(definition->row)) {
        return;
    }
    m_connman.ForEachNode([&](CNode* node) {
        if (node == nullptr || node->GetId() == except_peer ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION ||
            !std::binary_search(
                definition->active_relays.begin(),
                definition->active_relays.end(),
                node->GetVerifiedProRegTxHash())) {
            return;
        }
        m_connman.PushMessage(
            node, CNetMsgMaker(node->GetCommonVersion())
                      .Make(NetMsgType::PQPOSERESP, response));
    });
}

void CChainLocksHandler::MaybeRelayPaymentAuditHave()
{
    if (!RefreshPaymentAuditNetworkContext() ||
        !m_payment_audit_staging_store) {
        return;
    }
    const auto context{GetPaymentAuditNetworkContext()};
    if (!context) return;
    for (const auto& definition : context->rows) {
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
        m_connman.ForEachNode([&](CNode* node) {
            if (node == nullptr ||
                node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION ||
                !std::binary_search(
                    definition.active_relays.begin(),
                    definition.active_relays.end(),
                    node->GetVerifiedProRegTxHash())) {
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
    m_payment_audit_runtime.reset();
    ++m_payment_audit_runtime_generation;
}

uint64_t CChainLocksHandler::PublishPaymentAuditRuntime(
    PaymentAuditResponseRuntime runtime)
{
    ++m_payment_audit_runtime_generation;
    m_payment_audit_runtime.emplace(std::move(runtime));
    return m_payment_audit_runtime_generation;
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

    std::optional<pq::PaymentAuditStatement> cached_statement;
    {
        LOCK(m_payment_audit_mutex);
        if (m_payment_audit_runtime &&
            ShouldResetPaymentAuditRuntime(
                m_payment_audit_runtime->finalized.has_value(),
                m_payment_audit_runtime->finalized
                    ? m_payment_audit_runtime->finalized
                          ->admission_generation
                    : 0,
                current_admission_generation,
                m_payment_audit_runtime->roster_source_generation,
                current_roster_source_generation)) {
            ResetPaymentAuditRuntime();
        }
        if (m_payment_audit_runtime &&
            m_payment_audit_runtime->collector &&
            m_payment_audit_runtime->statement &&
            m_payment_audit_runtime->seal_chainlock &&
            m_payment_audit_runtime->signing_rosters &&
            m_payment_audit_runtime->relay_recipients &&
            pq::IsSigningRosterAuthorizationMask(
                m_payment_audit_runtime->authorization_mask)) {
            cached_statement = m_payment_audit_runtime->statement;
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
            return true;
        }
    }

    std::vector<uint32_t> candidate_epochs;
    if (const auto active{
            m_payment_audit_staging_store->ActiveEpoch()}) {
        candidate_epochs.push_back(*active);
    }
    if (const auto retained{
            m_payment_audit_staging_store->RetainedEpoch()};
        retained &&
        std::find(candidate_epochs.begin(), candidate_epochs.end(),
                  *retained) == candidate_epochs.end()) {
        candidate_epochs.push_back(*retained);
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

        const auto seal_chainlock{
            m_store->GetByHeight(schedule->seal_height)};
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
        pq::FrozenQuorumRostersPtr response_rosters;
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
            response_rosters = roster_cache->GetActive(
                response->nHeight, *response, &build_error);
        }
        if (!response_rosters ||
            response_rosters->back().descriptor.epoch != epoch ||
            response_rosters->back().descriptor.valid_members !=
                subject_valid_members ||
            pq::GetPaymentAuditDescriptorHash(
                m_genesis_hash,
                response_rosters->back().descriptor) !=
                subject_descriptor_hash) {
            continue;
        }
        commitment.subject_quorum_base_hash =
            response_rosters->back().descriptor.base_hash;

        pq::PaymentAuditStatement statement{
            commitment, seal_chainlock->statement};
        if (!statement.IsStructurallyValid() ||
            !IsCurrentPaymentAuditStatement(statement)) {
            continue;
        }
        uint8_t authorization_mask{0};
        uint64_t roster_source_generation{0};
        auto signing_rosters{
            BuildPaymentAuditVerificationRosters(
                statement, nullptr, &authorization_mask,
                /*require_live_transition_finality=*/true,
                /*status=*/nullptr, /*historical=*/nullptr,
                &roster_source_generation)};
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
            authorization_mask,
            &audit_error)};
        if (!prepared_context) continue;
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
        auto relay_recipients{
            std::make_shared<const ChainLockRelayRecipients>(
                BuildChainLockRelayRecipients(*signing_rosters_ptr))};

        // Bind publication to both immutable sources. If either changes
        // across publication, retire only the runtime installed by this pass.
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                existing_candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation)) {
            return false;
        }
        uint64_t published_generation{0};
        {
            LOCK(m_payment_audit_mutex);
            published_generation = PublishPaymentAuditRuntime(
                PaymentAuditResponseRuntime{
                    *round, selected, statement, *seal_chainlock,
                    signing_rosters_ptr, relay_recipients,
                    authorization_mask, roster_source_generation,
                    std::move(collector), std::nullopt, std::nullopt,
                    false, false});
        }
        if (!m_payment_audit_store->IsCandidateRevisionCurrent(
                existing_candidates->candidate_revision) ||
            !IsQuorumRosterSourceGenerationCurrent(
                roster_source_generation)) {
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
    const auto seal{m_store->GetByHeight(
        statement.commitment.seal_height)};
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
    const std::shared_ptr<const ChainLockRelayRecipients>& recipients) const
{
    if (!prepared_context || !recipients) return false;
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
        runtime_present && m_payment_audit_runtime->relay_recipients &&
            m_payment_audit_runtime->relay_recipients == recipients);
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
    const std::shared_ptr<const ChainLockRelayRecipients>& recipients,
    uint64_t runtime_generation,
    uint64_t admission_generation,
    NodeId except_peer)
{
    LOCK(m_share_lifecycle_mutex);
    if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
    {
        LOCK(cs_main);
        if (IsPaymentAuditPresealActive()) return;
    }
    if (!HasExactPaymentAuditRuntime(
            runtime_generation, share.transcript.statement,
            prepared_context, recipients) ||
        !IsCurrentPaymentAuditStatement(share.transcript.statement)) {
        return;
    }
    m_connman.ForEachNode([&](CNode* node) {
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        if (node == nullptr || node->GetId() == except_peer ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
            return;
        }
        const uint256 identity{node->GetVerifiedProRegTxHash()};
        if (identity.IsNull() || !recipients->contains(identity)) return;
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
    std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;
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
            !m_payment_audit_runtime->relay_recipients) {
            return;
        }
        relay_recipients = m_payment_audit_runtime->relay_recipients;
        if (!relay_recipients->contains(peer_identity) ||
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
            prepared_context, relay_recipients) ||
        !IsCurrentPaymentAuditStatement(share.transcript.statement)) {
        if (collection.finalized) {
            FinishPaymentAuditFinalizationAttempt(
                *collection.finalized);
        }
        return;
    }
    RelayPaymentAuditShare(
        share, prepared_context, relay_recipients,
        runtime_generation, admission_generation, node_id);
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
    if (payload.size() != pq::ChainLockShare::WIRE_SIZE) {
        punish(100, "bad-pq-clshare-size");
        return;
    }

    pq::ChainLockShare share;
    try {
        payload >> share;
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
    const auto current{contexts ? contexts->Find(share.GetStatement())
                                : std::nullopt};
    if (!current || !current->rosters || !contexts->relay_recipients ||
        !IsAuthorizedChainLockShareRelay(
            *current->rosters, *contexts->relay_recipients,
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
                        admission_generation, node_id);

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
    uint8_t* authorization_mask_out,
    bool require_live_transition_finality,
    PaymentAuditRosterBuildStatus* status,
    const PaymentAuditHistoricalContext* historical,
    uint64_t* roster_source_generation_out,
    int32_t* reconstruction_floor_out) const
{
    if (status != nullptr) {
        *status = PaymentAuditRosterBuildStatus::INVALID;
    }
    if (authorization_mask_out != nullptr) {
        *authorization_mask_out = 0;
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
            m_config->anchor.height) {
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

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    pq::VerifiedRosterSetPtr seal_rosters;
    try {
        seal_rosters = roster_cache->GetVerifiedActive(
            seal->nHeight, *seal, &build_error);
    } catch (const std::exception&) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (!seal_rosters) {
        if (status != nullptr &&
            IsPaymentAuditLocalRosterBuildError(build_error)) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    const uint8_t authorization_mask{
        DeriveSigningRosterAuthorizationMask(
            seal_rosters->Rosters(), *seal,
            statement.seal_statement.previous_chainlock_height,
            statement.seal_statement.previous_chainlock_hash)};
    if (!pq::IsSigningRosterAuthorizationMask(authorization_mask)) {
        return nullptr;
    }
    pq::VerifiedRosterSetPtr response_rosters;
    try {
        response_rosters = roster_cache->GetVerifiedActive(
            response->nHeight, *response, &build_error);
    } catch (const std::exception&) {
        if (status != nullptr) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (!response_rosters) {
        if (status != nullptr &&
            IsPaymentAuditLocalRosterBuildError(build_error)) {
            *status = PaymentAuditRosterBuildStatus::LOCAL_ERROR;
        }
        return nullptr;
    }
    if (!pq::MatchesVerifiedPaymentAuditSubject(
            statement.commitment, *response_rosters)) {
        return nullptr;
    }
    if (statement.seal_statement.payment_probation_state_hash !=
            seal->pqPaymentProbationStateHash) {
        return nullptr;
    }
    const auto& subject{
        response_rosters->Rosters().back().descriptor};
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
        include_snapshots(response_rosters->Rosters());
        const auto provenance_status{ClassifyHistoricalReceiptIndexRangeCached(
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
    if (subject_out != nullptr) {
        *subject_out = response_rosters->Rosters().back();
    }
    if (authorization_mask_out != nullptr) {
        *authorization_mask_out = authorization_mask;
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
                m_genesis_hash, audit, *classification)) {
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
        roster_source_generation =
            local_finalization->roster_source_generation;
        roster_status = PaymentAuditRosterBuildStatus::VALID;
    } else {
        rosters = BuildPaymentAuditVerificationRosters(
            audit.statement, nullptr, &authorization_mask,
            /*require_live_transition_finality=*/false, &roster_status,
            historical ? &*historical : nullptr,
            &roster_source_generation);
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
            schedule, audit, rosters, authorization_mask,
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
            uint8_t current_authorization_mask{0};
            const auto current_rosters{BuildPaymentAuditVerificationRosters(
                audit.statement, nullptr, &current_authorization_mask,
                /*require_live_transition_finality=*/false,
                &current_status, &*current)};
            if (!current_rosters ||
                current_authorization_mask != authorization_mask) {
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
                audit, /*required_witness=*/true);
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
            audit, /*required_witness=*/false);
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
                RelayPaymentAuditResponse(response, node_id);
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
    const LocalChainLockFinalization* local_finalization)
{
    if (peer_fault != nullptr) *peer_fault = false;
    if (!IsChainLockVerificationAvailable()) {
        return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                             "pq-clsig-not-configured");
    }

    const uint256 logical_id{chainlock.GetLogicalId(m_genesis_hash)};
    const uint256 witness_id{chainlock.GetWitnessId(m_genesis_hash)};
    if (from != -1) {
        if (PeerRef peer{m_peerman.GetPeerRef(from)}) {
            m_peerman.AddKnownTx(*peer, logical_id);
        }
    }

    const auto current_best{m_store->GetBestRecord()};
    const auto historical{
        GetHistoricalAdmission(chainlock.statement, logical_id)};
    const bool preseal_receipt{
        historical.admission == HistoricalAdmission::PRESEAL_RECEIPT};
    const int32_t local_finality_height{
        current_best ? current_best->metadata.statement.height
                     : m_config->anchor.height};
    const bool preseal_receipt_rebase{
        ShouldRouteBTCCPresealReceiptToCatchup(
            preseal_receipt, chainlock.statement.height,
            local_finality_height)};
    const bool archive_only{
        (preseal_receipt && !preseal_receipt_rebase) ||
        (IsPendingBTCCReceiptCertificate(logical_id) && current_best &&
         chainlock.statement.height <
             current_best->metadata.statement.height)};
    const bool catchup{
        historical.admission == HistoricalAdmission::CURRENT_CATCHUP ||
        historical.admission == HistoricalAdmission::PRESEAL_CATCHUP ||
        preseal_receipt_rebase};
    const bool historical_admission{catchup || preseal_receipt};
    pq::ChainLockFinalityError finality_error{pq::ChainLockFinalityError::NONE};
    std::optional<pq::PreparedFinalChainLockCandidate> prepared;
    std::optional<RuntimeVerificationContext> verification_context;
    bool index_persistence_failed{false};
    bool accepted{false};
    bool historical_acceptance_complete{false};
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
        TRY_LOCK(m_chainlock_admission_mutex, admission_lock);
        if (!admission_lock) {
            if (prepared) m_store->AbandonPrepared(*prepared);
            CompletePeerResponse(from, logical_id);
            return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                 "pq-clsig-verifier-busy");
        }
        // SYSCOIN: Synchronize behind any active maintenance pass before the
        // first roster lookup. The admission mutex bounds this transient
        // retain-all state to one network candidate without participating in
        // the cs_main-to-crypto lock order.
        snapshot_verification_retention.emplace(deterministicMNManager.get());

        // SYSCOIN: Historical marker admission is the only path that can
        // trigger retained-range receipt work. First rebuild the exact active-branch
        // rosters and authenticate all 801 witness signatures. Random network
        // bytes can therefore consume bounded crypto, never O(chain-age) disk
        // work under cs_main.
        std::optional<RuntimeVerificationContext> historical_preverification;
        if (historical_admission) {
            if (m_store->AlreadyHaveWitness(witness_id)) {
                CompletePeerResponse(from, logical_id);
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                     "pq-clsig-duplicate-witness");
            }
            historical_preverification =
                BuildHistoricalPreVerificationContext(chainlock, historical);
            if (!historical_preverification) {
                CompletePeerResponse(from, logical_id);
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                     "pq-clsig-context-unavailable");
            }
            pq::ChainLockVerificationError verification_error{
                pq::ChainLockVerificationError::NONE};
            auto signature_checks{pq::PrepareFinalChainLockVerification(
                m_config->chainlock_schedule, chainlock,
                *historical_preverification->roster_set,
                historical_preverification->authorization_mask,
                &verification_error)};
            if (!signature_checks) {
                m_store->RejectWitness(chainlock);
                if (peer_fault != nullptr) *peer_fault = true;
                FailPeerResponse(from, logical_id);
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
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
                return state.Invalid(BlockValidationResult::BLOCK_CHAINLOCK,
                                     "pq-clsig-invalid-signatures");
            }
            if (peer_fault != nullptr) {
                // Everything below is local historical state, storage, or a
                // concurrent active/store context. A fully authenticated peer
                // response must never be punished for those local failures.
                *peer_fault = false;
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
                    verification_context =
                        BuildRuntimeVerificationContext(*prepared);
                    if (!verification_context ||
                        Descriptors(
                            verification_context->roster_set->Rosters()) !=
                            Descriptors(historical_preverification
                                            ->roster_set->Rosters()) ||
                        verification_context->authorization_mask !=
                            historical_preverification->authorization_mask ||
                        verification_context->historical != historical) {
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
                            if (historical.marker_token.IsNull()) {
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
                        return m_store->AcceptCatchupVerified(
                            *prepared, chainlock, /*signatures_valid=*/true,
                            sync_index, authorize_durable,
                            &finality_error);
                    }
                    return m_store->AcceptPresealReceiptVerified(
                        *prepared, chainlock, /*signatures_valid=*/true,
                        sync_index, authorize_durable,
                        &finality_error);
                });
            historical_acceptance_complete = true;
            // No historical work may escape the globally serialized admission
            // section; a valid certificate is the sole permission to scan.
        } else {
            verification_context = BuildRuntimeVerificationContext(*prepared);
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
                    verification_context->roster_set,
                    verification_context->authorization_mask,
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
                    m_config->chainlock_schedule, chainlock,
                    *verification_context->roster_set,
                    verification_context->authorization_mask,
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
                        (void)m_store->AcceptReceiptArchiveVerified(
                            *prepared, chainlock,
                            /*signatures_valid=*/false, &finality_error);
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

    const auto accept_verified = [&] {
        const auto publication_context{
            prepared ? BuildRuntimeVerificationContext(*prepared)
                     : std::nullopt};
        if (!verification_context || !publication_context ||
            publication_context->authorization_mask !=
                verification_context->authorization_mask ||
            Descriptors(publication_context->roster_set->Rosters()) !=
                Descriptors(verification_context->roster_set->Rosters())) {
            finality_error = pq::ChainLockFinalityError::CONTEXT_CHANGED;
            return false;
        }
        if (!FlushBTCCIndexStateForDurableAcceptance(chainlock)) {
            index_persistence_failed = true;
            return false;
        }
        return archive_only
                   ? m_store->AcceptReceiptArchiveVerified(
                         *prepared, chainlock, /*signatures_valid=*/true,
                         &finality_error)
                   : m_store->AcceptVerified(
                               *prepared, chainlock,
                               /*signatures_valid=*/true, &finality_error);
    };
    if (!historical_acceptance_complete) {
        accepted = archive_only
            ? accept_verified()
            : m_chainman.ActiveChainstate().RunWithStableActiveChain(
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
    {
        LOCK(m_needed_btcc_certificate_mutex);
        if (m_needed_btcc_certificate == logical_id) {
            m_needed_btcc_certificate.reset();
            m_needed_btcc_last_request = std::chrono::microseconds{0};
        }
    }
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

    // This is the only live rebase authority: AcceptVerified returned only
    // after full signature verification and the durable-accept fsync. A crash
    // before this call is recovered from the persisted winner on startup.
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
CChainLocksHandler::TryImportPersistedChainLock()
{
    pq::FinalChainLock persisted;
    {
        LOCK(m_persisted_mutex);
        if (m_persisted_invalid) return PersistedChainLockImport::INVALID;
        if (!m_pending_persisted) return PersistedChainLockImport::NONE;
        persisted = *m_pending_persisted;
    }
    if (!IsConfiguredForVerification()) return PersistedChainLockImport::PENDING;

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
        m_config->chainlock_schedule, persisted,
        *verification_context->roster_set,
        verification_context->authorization_mask,
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
                !HasFullChainLockTargetValidationCached(
                    *target,
                    persisted.statement.previous_chainlock_height);
        })};

    if (!FlushChainLockAuxiliarySnapshotsForDurability()) {
        m_store->AbandonPrepared(*prepared);
        return PersistedChainLockImport::PENDING;
    }

    if (!m_store->AcceptPersistedVerified(
            *prepared, persisted, /*signatures_valid=*/true,
            &finality_error)) {
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
        if (m_pending_persisted) return PersistedChainLockImport::PENDING;
        persisted = *m_pending_persisted_unsealed_btcc;
    }
    if (!IsConfiguredForVerification()) return PersistedChainLockImport::PENDING;

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

    pq::ChainLockFinalityError finality_error{
        pq::ChainLockFinalityError::NONE};
    auto prepared{
        m_store->PrepareReceiptArchiveCandidate(persisted, &finality_error)};
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
        m_config->chainlock_schedule, persisted,
        *verification_context->roster_set,
        verification_context->authorization_mask,
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

    if (!m_store->AcceptReceiptArchiveVerified(
            *prepared, persisted, /*signatures_valid=*/true,
            &finality_error)) {
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
    NodeId except_peer)
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
    const auto& recipients{signing_contexts->relay_recipients};
    if (!recipients) return;

    m_connman.ForEachNode([&](CNode* node) {
        if (!IsShareAdmissionGenerationCurrent(admission_generation)) return;
        if (node == nullptr || node->GetId() == except_peer ||
            node->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
            return;
        }
        const uint256 identity{node->GetVerifiedProRegTxHash()};
        if (identity.IsNull() || !recipients->contains(identity)) return;
        m_connman.PushMessage(
            node, CNetMsgMaker(node->GetCommonVersion())
                      .Make(NetMsgType::PQCLSHARE, share));
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

    // Identity initialization can lag persisted-certificate restoration. No
    // signing is possible until the current durable winner has reconciled the
    // operator lock, closing the fsync-before-journal-rebase crash window.
    if (!ReconcileSignerJournal(local_pro_tx_hash) ||
        !InitializeSignerStartupTip(local_pro_tx_hash)) {
        return;
    }

    auto contexts{GetPublishedCurrentSigningContexts(
        admission_generation)};
    if (!contexts) return;

    std::optional<CurrentSigningContext> current;
    const auto existing_branch_lock{m_signer_journal->GetBranchLock(
        m_genesis_hash, local_pro_tx_hash)};
    if (!m_signer_journal->IsHealthy()) return;
    if (existing_branch_lock &&
        existing_branch_lock->height == contexts->statements[0].height) {
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
            *signing_context, local_pro_tx_hash)) {
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
                m_genesis_hash, local_pro_tx_hash)};
            if (!m_signer_journal->IsHealthy()) return;
            if (expected_branch_lock) {
                if (candidate_branch_lock.height < expected_branch_lock->height ||
                    (candidate_branch_lock.height == expected_branch_lock->height &&
                     candidate_branch_lock != *expected_branch_lock)) {
                    return;
                }
                if (candidate_branch_lock.height > expected_branch_lock->height) {
                    LOCK(cs_main);
                    const CChain& active_chain{m_chainman.ActiveChain()};
                    const CBlockIndex* target{
                        active_chain[candidate_branch_lock.height]};
                    const CBlockIndex* locked_ancestor{
                        target == nullptr || expected_branch_lock->height < 0
                            ? nullptr
                            : active_chain[expected_branch_lock->height]};
                    if (target == nullptr ||
                        target->GetBlockHash() !=
                            candidate_branch_lock.block_hash ||
                        target->nHeight != candidate_branch_lock.height ||
                        locked_ancestor == nullptr ||
                        locked_ancestor->GetBlockHash() !=
                            expected_branch_lock->block_hash) {
                        // A prior local signature is a durable finality vote.
                        // Never follow a PoW reorg across it, even when the
                        // aggregate certificate was withheld or not received.
                        return;
                    }
                }
            }
            pq::ChainLockSigningError signing_error{
                pq::ChainLockSigningError::NONE};
            if (!exact_signing_capability_is_current()) return;
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
            if (!exact_signing_capability_is_current()) return;

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
    std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;
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
            !m_payment_audit_runtime->relay_recipients) {
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
            relay_recipients =
                m_payment_audit_runtime->relay_recipients;
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
    if (!statement || !signing_context || !rosters || !relay_recipients ||
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
    const auto expected_branch_lock{m_signer_journal->GetBranchLock(
        m_genesis_hash, local_pro_tx_hash)};
    if (!m_signer_journal->IsHealthy() || !expected_branch_lock ||
        *expected_branch_lock != seal_lock) {
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
                !has_exact_open_runtime()) {
                return;
            }
            auto signed_share{signer.Sign(
                *signing_context, reporter_observed_members,
                static_cast<uint8_t>(slot),
                static_cast<uint16_t>(member_index),
                *signing_material->secret_key,
                signing_material->key_proof,
                expected_branch_lock, &signing_error)};
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
            if (!IsCurrentPaymentAuditStatement(*statement)) return;

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
                    relay_recipients) ||
                !IsCurrentPaymentAuditStatement(*statement)) {
                if (collection.finalized) {
                    FinishPaymentAuditFinalizationAttempt(
                        *collection.finalized);
                }
                return;
            }
            RelayPaymentAuditShare(
                *signed_share.share, signing_context, relay_recipients,
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
        // The immutable anchor is already the enforced finality reference
        // before the first accepted winner.
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
    ChainLockEnforcementProvenance provenance{
        ChainLockEnforcementProvenance::EXACT_LOCAL};
    {
        LOCK(cs_main);
        const auto& statement{record->metadata.statement};
        best = m_chainman.m_blockman.LookupBlockIndex(statement.block_hash);
        if (best == nullptr || best->nHeight != statement.height) return;
        if (m_chainman.IsSnapshotActive() &&
            !m_chainman.IsSnapshotValidated()) {
            return;
        }
        if (!HasFullChainLockTargetValidationCached(
                *best, statement.previous_chainlock_height)) {
            const uint256 witness_id{record->metadata.witness_id};
            if (witness_id.IsNull() ||
                threshold_attested_witness != witness_id ||
                !m_chainman.IsBaseBlockSyncComplete() ||
                (m_chainman.IsSnapshotActive() &&
                 !m_chainman.IsSnapshotValidated()) ||
                statement.previous_chainlock_height <
                    m_config->anchor.height ||
                statement.previous_chainlock_height >= statement.height ||
                (best->nStatus & BLOCK_FAILED_MASK) ||
                (best->nStatus & BLOCK_HAVE_DATA) == 0 ||
                best->IsAssumedValid() ||
                !best->IsValid(BLOCK_VALID_SCRIPTS) ||
                !HasFullReceiptIndexProvenance(*best)) {
                return;
            }
            const CBlockIndex* predecessor{best->GetAncestor(
                statement.previous_chainlock_height)};
            const auto indexed_btcc{IndexedBTCCReceiptState(*best)};
            const auto indexed_audit{IndexedPaymentAuditReceiptState(*best)};
            pq::BTCCValidationError btcc_error{
                pq::BTCCValidationError::NONE};
            if (predecessor == nullptr ||
                predecessor->GetBlockHash() !=
                    statement.previous_chainlock_hash ||
                ClassifyHistoricalReceiptIndexRangeCached(
                    *predecessor,
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
            best, provenance)) {
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
    MaybeCheckpointPaymentAuditPreseal(record->metadata);
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
    const bool enforce{ShouldEnforceDurableChainLock(
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
    bool unknown_is_conflict{true};
    if (m_store && m_config && !m_store->GetBestRecord()) {
        AssertLockHeld(cs_main);
        const CBlockIndex* const anchor{
            m_chainman.m_blockman.LookupBlockIndex(
                m_config->anchor.block_hash)};
        // SYSCOIN: Before the first winner, the immutable finality anchor is
        // the store's finality reference. Its prefix cannot be classified
        // until that exact header is discovered. Contextual anchor validation
        // pins F meanwhile; after discovery, UNKNOWN again fails closed.
        unknown_is_conflict =
            anchor != nullptr && anchor->nHeight == m_config->anchor.height;
    }
    return m_enforced.load() && m_store &&
           m_store->HasConflictingChainLock(
               height, block_hash,
               /*unknown_is_conflict=*/unknown_is_conflict);
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

bool ShouldEnforceDurableChainLock(
    bool configured, bool persisted_import_pending,
    bool btcc_preseal_active) noexcept
{
    // A pre-seal is an execution/readiness obligation, not permission to
    // reverse a fully verified and fsynced Syscoin finality decision.
    (void)btcc_preseal_active;
    return configured && !persisted_import_pending;
}

bool IsBTCCPresealCoveredByDurableWinner(
    int32_t marker_height, int32_t winner_height,
    bool winner_descends_marker) noexcept
{
    return marker_height >= 0 && winner_height >= marker_height &&
           winner_descends_marker;
}

} // namespace llmq
