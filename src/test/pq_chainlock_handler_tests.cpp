// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>

#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/scheduled_wots/scheduled_wots.h>
#include <evo/deterministicmns.h>
#include <governance/governanceclasses.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <node/miner.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <script/script.h>
#include <streams.h>
#include <test/pq_test_util.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/time.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

llmq::pq::RosterBeaconSeed SubjectBeacon(uint32_t epoch)
{
    llmq::pq::RosterBeaconSeed seed;
    seed.state = llmq::pq::RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = llmq::pq::BTCCursor{
        10'000 + static_cast<int32_t>(epoch),
        NonNullHash(100'000 + epoch), NonNullHash(200'000 + epoch)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(300'000 + epoch);
    return seed;
}

llmq::pq::PaymentAuditReceipt NonNullPaymentAuditReceipt(uint64_t salt)
{
    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = static_cast<uint32_t>(100 + salt);
    receipt.seal_height = static_cast<int32_t>(1'000 + salt);
    receipt.seal_block_hash = NonNullHash(10'000 + salt);
    receipt.carrier_height = receipt.seal_height +
                             llmq::pq::PAYMENT_AUDIT_RECEIPT_DELAY;
    receipt.audit_logical_id = NonNullHash(20'000 + salt);
    receipt.audit_witness_id = NonNullHash(30'000 + salt);
    receipt.commitment_hash = NonNullHash(40'000 + salt);
    receipt.result_hash = NonNullHash(50'000 + salt);
    receipt.next_probation_state_hash = NonNullHash(60'000 + salt);
    receipt.subject_roster_beacon = SubjectBeacon(receipt.epoch);
    receipt.online_members[0] = 1;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    return receipt;
}

llmq::PaymentAuditReceiptCache::Key PaymentAuditReceiptCacheKey(
    uint64_t salt)
{
    return llmq::PaymentAuditReceiptCache::Key{
        NonNullHash(70'000 + salt),
        static_cast<int32_t>(2'000 + salt),
        NonNullHash(80'000 + salt),
        static_cast<int32_t>(2'001 + salt),
        static_cast<uint32_t>(100 + salt),
        1 + salt};
}

CBlock PaymentAuditCarrierBlock(
    const llmq::pq::PaymentAuditReceipt& receipt)
{
    const llmq::pq::BTCCReceipt btcc;
    DataStream tail;
    tail << PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES << receipt
         << BTCC_RECEIPT_MAGIC_BYTES << btcc;
    const auto bytes{MakeUCharSpan(tail)};
    const std::vector<unsigned char> payload{bytes.begin(), bytes.end()};

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

Consensus::Params ValidConsensus()
{
    Consensus::Params consensus;
    consensus.hashGenesisBlock = NonNullHash(1);
    consensus.DIP0003Height = 1;
    consensus.nPQActivationHeight = 2305;
    consensus.nPQPreparationHeight = 1000;
    consensus.nPQChainLockEpochOrigin = 1440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = 2305;
    consensus.nPQBTCCNEVMInjectionLag = llmq::pq::PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1000;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(2);
    return consensus;
}

void SetFirstMembers(llmq::pq::QuorumBitmap& bitmap, std::size_t count)
{
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

llmq::pq::FinalPaymentAudit MakePaymentAuditCandidate(
    uint32_t epoch, uint8_t mask, uint64_t salt,
    std::size_t observed_count = llmq::pq::QUORUM_MIN_VALID)
{
    using namespace llmq::pq;
    FinalPaymentAudit audit;
    auto& commitment{audit.statement.commitment};
    const int32_t anchor_height{
        static_cast<int32_t>(10'000 + epoch * 1'000)};
    commitment.seed.epoch = epoch;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        anchor_height, NonNullHash(100 + salt),
        BTCCursor{anchor_height, NonNullHash(200 + salt),
                  NonNullHash(300 + salt)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(400 + salt);
    commitment.selected_row = 3;
    commitment.response_height = anchor_height - 30;
    commitment.deadline_height = anchor_height - 10;
    commitment.response_chainlock_logical_id = NonNullHash(500 + salt);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = anchor_height + PAYMENT_AUDIT_SEAL_DELAY;
    commitment.subject_epoch = epoch;
    commitment.subject_quorum_base_hash = NonNullHash(600 + salt);
    commitment.subject_descriptor_hash = NonNullHash(700 + salt);
    SetFirstMembers(commitment.subject_valid_members, QUORUM_SIZE);
    commitment.previous_probation_state_hash = NonNullHash(800 + salt);

    auto& seal{audit.statement.seal_statement};
    seal.height = commitment.seal_height;
    seal.block_hash = NonNullHash(900 + salt);
    seal.previous_chainlock_height = commitment.seal_height - 5;
    seal.previous_chainlock_hash = NonNullHash(1'000 + salt);
    seal.quorum_context_hash = NonNullHash(1'100 + salt);
    seal.payment_probation_state_hash =
        commitment.previous_probation_state_hash;
    const uint32_t first_active_epoch{
        epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 2)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        seal.roster_beacons.active.seeds[slot] = SubjectBeacon(
            first_active_epoch + static_cast<uint32_t>(slot));
    }
    seal.roster_beacons.next.epoch =
        first_active_epoch + ACTIVE_QUORUMS;
    seal.roster_beacons.active.recovery_authority_source.normal_beacon =
        seal.roster_beacons.active.seeds.back();
    seal.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    seal.roster_authorization_state_hash = NonNullHash(1'200 + salt);
    seal.roster_authorization_base = {
        seal.previous_chainlock_height, seal.previous_chainlock_hash,
        NonNullHash(1'250 + salt)};

    audit.selected_quorum_mask = mask;
    audit.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((mask & (uint8_t{1} << slot)) == 0) continue;
        SetFirstMembers(audit.signer_bitmaps[slot], QUORUM_THRESHOLD);
        for (std::size_t reporter{0}; reporter < QUORUM_THRESHOLD;
             ++reporter) {
            PaymentAuditReportWitness witness;
            SetFirstMembers(witness.observed_members, observed_count);
            witness.authenticated_signature.key_proof.public_key[0] = 1;
            witness.authenticated_signature.signature[0] =
                static_cast<uint8_t>(salt + slot + reporter);
            audit.report_witnesses.push_back(std::move(witness));
        }
    }
    BOOST_REQUIRE(audit.IsStructurallyValid());
    return audit;
}

llmq::pq::PaymentAuditStoreCheckpoint MakePaymentAuditCheckpoint(
    uint32_t epoch, uint64_t salt, int32_t target_height)
{
    using namespace llmq::pq;
    const int32_t covered_height{target_height - 2};
    PaymentAuditReceiptState receipt_state;
    receipt_state.cursor = {
        covered_height - 1,
        epoch,
        NonNullHash(1'200 + salt),
        NonNullHash(1'300 + salt),
        NonNullHash(1'400 + salt)};
    receipt_state.cumulative_hash = NonNullHash(1'500 + salt);
    PaymentAuditStoreCheckpoint checkpoint{
        epoch,
        covered_height,
        NonNullHash(1'600 + salt),
        receipt_state,
        NonNullHash(1'700 + salt),
        target_height,
        NonNullHash(1'800 + salt),
        NonNullHash(1'900 + salt),
        NonNullHash(2'000 + salt)};
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    return checkpoint;
}

llmq::pq::FinalChainLock MakeCatchupChainLock(
    int32_t height, int32_t previous_height,
    const uint256& previous_hash, uint64_t salt)
{
    llmq::pq::FinalChainLock chainlock;
    chainlock.statement.height = height;
    chainlock.statement.block_hash = NonNullHash(10'000 + salt);
    chainlock.statement.previous_chainlock_height = previous_height;
    chainlock.statement.previous_chainlock_hash = previous_hash;
    chainlock.statement.quorum_context_hash = NonNullHash(20'000 + salt);
    chainlock.statement.payment_probation_state_hash = NonNullHash(30'000);
    const auto schedule{
        llmq::pq::MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);
    const auto active_epochs{
        llmq::pq::ActiveEpochsAtHeight(*schedule, height)};
    BOOST_REQUIRE(active_epochs);
    for (std::size_t slot{0}; slot < llmq::pq::ACTIVE_QUORUMS; ++slot) {
        chainlock.statement.roster_beacons.active.seeds[slot] =
            SubjectBeacon((*active_epochs)[slot].epoch);
    }
    chainlock.statement.roster_beacons.next.epoch =
        active_epochs->back().epoch + 1;
    chainlock.statement.roster_beacons.active
        .recovery_authority_source.normal_beacon =
        chainlock.statement.roster_beacons.active.seeds.back();
    chainlock.statement.roster_transition =
        llmq::pq::RosterAuthorizationTransitionKind::KEEP;
    chainlock.statement.roster_authorization_state_hash =
        NonNullHash(25'000 + salt);
    chainlock.statement.roster_authorization_base = {
        previous_height, previous_hash, NonNullHash(26'000 + salt)};
    chainlock.selected_quorum_mask = 0b0111;
    chainlock.signatures.resize(llmq::pq::FINAL_SIGNATURE_COUNT);
    for (auto& authenticated : chainlock.signatures) {
        authenticated.key_proof.public_key[0] = 1;
    }
    for (std::size_t slot{0}; slot < llmq::pq::REQUIRED_QUORUMS; ++slot) {
        SetFirstMembers(chainlock.signer_bitmaps[slot],
                        llmq::pq::QUORUM_THRESHOLD);
    }
    chainlock.signatures.front().signature.front() =
        static_cast<uint8_t>(salt);
    return chainlock;
}

llmq::pq::ChainLockFinalityStoreConfig CatchupStoreConfig()
{
    llmq::pq::ChainLockFinalityStoreConfig config;
    config.chainlock_schedule =
        *llmq::pq::MakeChainLockScheduleConfig(/*epoch_origin=*/0);
    config.btcc_schedule.candidate_origin = 870;
    config.activation_predecessor_height = 864;
    return config;
}

class FullReceiptCatchupContext final
    : public llmq::pq::ChainLockFinalityContext
{
public:
    bool full_receipt_history{false};

    std::optional<llmq::pq::ChainLockCandidateContext> PrepareCandidate(
        const llmq::pq::ChainLockCandidateContextRequest& request)
        const override
    {
        return MakeContext(request);
    }

    std::optional<llmq::pq::ChainLockCandidateContext> RecheckCandidate(
        const llmq::pq::ChainLockCandidateContextRequest& request,
        const llmq::pq::ChainLockCandidateContext& prepared) const override
    {
        const auto current{MakeContext(request)};
        return current == prepared
            ? std::optional<llmq::pq::ChainLockCandidateContext>{current}
            : std::nullopt;
    }

    llmq::pq::AcceptedBranchRelation QueryAcceptedBranch(
        int32_t, const uint256&, int32_t, const uint256&) const override
    {
        return llmq::pq::AcceptedBranchRelation::MATCH;
    }

private:
    llmq::pq::ChainLockCandidateContext MakeContext(
        const llmq::pq::ChainLockCandidateContextRequest& request) const
    {
        return llmq::pq::ChainLockCandidateContext{
            /*block_known=*/true,
            /*scripts_validated=*/true,
            /*special_transactions_validated=*/full_receipt_history,
            /*declared_predecessor_is_ancestor=*/true,
            /*descends_from_local_best=*/true,
            /*btcc_transition_validated=*/true,
            request.statement.height,
            request.statement.block_hash,
            NonNullHash(40'000),
            std::nullopt};
    }
};

} // namespace

namespace llmq::test {

class CChainLocksHandlerTestAccess {
public:
    static const pq::ChainLockFinalityStoreConfig* Config(
        const CChainLocksHandler& handler)
    {
        return handler.m_config ? &*handler.m_config : nullptr;
    }

    static const pq::QuorumBuildConfig* QuorumConfig(
        const CChainLocksHandler& handler)
    {
        return handler.m_quorum_build_config
            ? &*handler.m_quorum_build_config
            : nullptr;
    }

    static void ResetFinalityStore(CChainLocksHandler& handler)
    {
        if (!handler.m_config) {
            handler.m_store.reset();
            return;
        }
        handler.m_store = std::make_unique<pq::ChainLockFinalityStore>(
            handler.m_genesis_hash, *handler.m_config,
            static_cast<const pq::ChainLockFinalityContext&>(handler));
    }

    static void ResetFinalityStoreWithContext(
        CChainLocksHandler& handler,
        const pq::ChainLockFinalityContext& context)
    {
        if (!handler.m_config) {
            handler.m_store.reset();
            return;
        }
        handler.m_store = std::make_unique<pq::ChainLockFinalityStore>(
            handler.m_genesis_hash, *handler.m_config, context);
    }

    static pq::ChainLockFinalityStore* Store(CChainLocksHandler& handler)
    {
        return handler.m_store.get();
    }

    static void SetServableHistoricalCertificate(
        CChainLocksHandler& handler,
        std::shared_ptr<const pq::FinalChainLock> certificate)
    {
        LOCK(::cs_main);
        handler.m_historical_sync_servable[0] = std::move(certificate);
    }

    static pq::BTCCReceipt BTCCReceiptForCarrier(
        const CChainLocksHandler& handler,
        int32_t carrier_height,
        const CBlockIndex& carrier_parent)
    {
        LOCK(::cs_main);
        return handler.GetBTCCReceiptForCarrier(
            carrier_height, carrier_parent);
    }

    static bool IsVerifiedBTCCReceipt(
        const CChainLocksHandler& handler,
        const pq::BTCCReceipt& receipt,
        const CBlockIndex& carrier)
    {
        LOCK(::cs_main);
        return handler.CheckBTCCReceiptCertificate(receipt, carrier) ==
               CChainLocksHandler::BTCCReceiptCertificateStatus::VERIFIED;
    }

    struct ObjectiveRosterAuthorizationSummary {
        pq::ObjectiveRosterAuthorizationMode mode{
            pq::ObjectiveRosterAuthorizationMode::PAUSE};
        std::optional<pq::RosterAuthorizationBaseIdentity> base;
        std::optional<pq::RecoveryRosterAuthoritySource> recovery_source;
    };

    static std::optional<ObjectiveRosterAuthorizationSummary>
    ObjectiveRosterAuthorization(
        const CChainLocksHandler& handler,
        const CBlockIndex& candidate)
    {
        LOCK(::cs_main);
        const auto context{
            handler.ResolveObjectiveRosterAuthorizationContext(candidate)};
        if (!context) return std::nullopt;
        return ObjectiveRosterAuthorizationSummary{
            context->mode,
            context->base
                ? std::optional<pq::RosterAuthorizationBaseIdentity>{
                      context->base->metadata.AuthorizationBase()}
                : std::nullopt,
            context->recovery_source};
    }

    static bool HasRuntimeVerificationContext(
        const CChainLocksHandler& handler,
        const pq::PreparedFinalChainLockCandidate& prepared)
    {
        return handler.BuildRuntimeVerificationContext(prepared).has_value();
    }

    static std::optional<pq::RosterAuthorizationBaseIdentity>
    SelectedObjectiveRosterBase(const CChainLocksHandler& handler,
                               const CBlockIndex& candidate)
    {
        LOCK(::cs_main);
        std::optional<pq::RosterAuthorizationBaseIdentity> selected;
        (void)handler.ResolveObjectiveRosterAuthorizationContext(candidate, nullptr, &selected);
        return selected;
    }

    static std::optional<pq::PreparedFinalChainLockCandidate>
    PrepareRuntimeCandidateWithoutStoreAdmission(
        const CChainLocksHandler& handler,
        const pq::FinalChainLock& chainlock,
        pq::ChainLockCandidateAdmission admission)
    {
        const auto best{handler.m_store
                            ? handler.m_store->GetBestRecord()
                            : std::nullopt};
        if (!best) return std::nullopt;
        const pq::ChainLockPredecessor predecessor{
            best->metadata.statement.height,
            best->metadata.statement.block_hash,
            best->metadata.statement.accepted_btcc_cursor};
        const std::optional<pq::BTCCursor> declared_predecessor_cursor{
            chainlock.statement.previous_chainlock_height ==
                        best->metadata.statement.height &&
                    chainlock.statement.previous_chainlock_hash ==
                        best->metadata.statement.block_hash
                ? std::optional<pq::BTCCursor>{
                      best->metadata.statement.accepted_btcc_cursor}
                : std::nullopt};
        const pq::ChainLockCandidateContextRequest request{
            chainlock.statement, predecessor,
            /*has_local_chainlock=*/true,
            declared_predecessor_cursor, admission,
            handler.m_config->btcc_schedule};
        const auto context{handler.BuildCandidateContext(request)};
        if (!context) return std::nullopt;
        return pq::PreparedFinalChainLockCandidate{
            chainlock.GetLogicalId(handler.m_genesis_hash),
            chainlock.GetWitnessId(handler.m_genesis_hash),
            chainlock.statement, chainlock.selected_quorum_mask,
            predecessor,
            /*has_local_chainlock=*/true,
            declared_predecessor_cursor, *context, admission,
            /*store_revision=*/0};
    }

    static bool HasCurrentCatchupHistoricalVerificationContext(
        const CChainLocksHandler& handler,
        const pq::FinalChainLock& chainlock)
    {
        return handler.BuildHistoricalPreVerificationContext(
            chainlock,
            CChainLocksHandler::HistoricalAdmissionContext{
                CChainLocksHandler::HistoricalAdmission::CURRENT_CATCHUP,
                {}}).has_value();
    }

    static uint8_t HistoricalAdmissionFor(
        const CChainLocksHandler& handler,
        const pq::FinalChainLock& chainlock)
    {
        LOCK(::cs_main);
        return static_cast<uint8_t>(handler.GetHistoricalAdmissionLocked(
            chainlock.statement,
            chainlock.GetLogicalId(handler.m_genesis_hash)).admission);
    }

    static std::unique_ptr<pq::ChainLockFinalityStore> ExchangeFinalityStore(
        CChainLocksHandler& handler,
        std::unique_ptr<pq::ChainLockFinalityStore> store)
    {
        return std::exchange(handler.m_store, std::move(store));
    }

    static void SetHistoricalSyncAuthorization(
        CChainLocksHandler& handler,
        const std::optional<pq::HistoricalSyncBoundary>& boundary,
        const pq::VerifiedRosterAuthorizationBaseView& base,
        std::optional<uint64_t> provenance_revision = std::nullopt,
        uint256 record_identity = {})
    {
        LOCK(::cs_main);
        handler.m_historical_sync = boundary
            ? std::make_shared<const CChainLocksHandler::HistoricalSyncAuthorization>(
                  CChainLocksHandler::HistoricalSyncAuthorization{
                      *boundary, base, provenance_revision.value_or(
                          handler.m_chainman.GetPQProvenanceRevocationRevision()), record_identity})
            : nullptr;
    }

    static uint256 PersistHistoricalBootstrap(
        CChainLocksHandler& handler, const pq::FinalChainLock& base,
        const pq::PreparedChainLockContextPtr& context,
        const pq::HistoricalSyncBoundary& boundary)
    {
        uint64_t revision{0};
        (void)handler.m_persistence->LoadHistoricalSyncBootstrap(&revision);
        BOOST_REQUIRE(handler.m_persistence->PersistHistoricalSyncBootstrap(
            base, context, boundary, revision, nullptr));
        return handler.m_persistence->LoadHistoricalSyncBootstrap()->record.RecordIdentity();
    }

    static void MaintainHistoricalRetention(CChainLocksHandler& handler)
        EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        handler.MaintainHistoricalSyncRetention();
    }

    static void SetHistoricalRequest(CChainLocksHandler& handler, const uint256& logical_id)
    {
        LOCK(::cs_main);
        handler.m_historical_sync_requested = logical_id;
        handler.m_historical_sync_last_request = std::chrono::microseconds{1};
    }

    static bool HasHistoricalRequest(const CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        return !handler.m_historical_sync_requested.IsNull() || handler.m_historical_sync_last_request.count() != 0;
    }

    static void SetReplayMarkers(CChainLocksHandler& handler,
                                const pq::BTCCPresealState& btcc,
                                const pq::PaymentAuditPresealState& payment)
    {
        LOCK(::cs_main);
        LOCK(handler.m_btcc_preseal_mutex);
        BOOST_REQUIRE(handler.m_persistence->PersistBTCCPresealState(btcc));
        BOOST_REQUIRE(handler.m_persistence->PersistPaymentAuditPresealState(payment));
        handler.m_btcc_preseal_state = btcc;
        handler.m_payment_audit_preseal_state = payment;
    }

    static bool ClearReplayMarker(CChainLocksHandler& handler,
                                  const pq::BTCCPresealMarker& marker)
    {
        return handler.ClearBTCCPreseal(marker);
    }

    static bool ClearReplayMarker(CChainLocksHandler& handler,
                                  const pq::PaymentAuditPresealMarker& marker)
    {
        return handler.ClearPaymentAuditPreseal(marker);
    }

    static void ReplayPaymentPreseal(CChainLocksHandler& handler)
    {
        handler.MaybeReplayPaymentAuditPreseal();
    }

    static int32_t PaymentReplayValidatedHeight(const CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        return handler.m_payment_audit_replay_validation.frontier.ValidatedThroughHeight();
    }

    static std::optional<pq::PaymentAuditReceipt> PaymentReplayDependency(
        const CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        const auto dependency{handler.GetPaymentAuditReplayDependency()};
        return dependency ? std::make_optional(dependency->receipt) : std::nullopt;
    }

    static bool PaymentReplayAuthenticated(const CChainLocksHandler& handler,
                                           const CBlockIndex& index)
    {
        LOCK(::cs_main);
        return handler.IsPaymentAuditReplayAuthenticated(index);
    }

    static std::optional<CChainLocksHandler::PaymentAuditHistoricalContext>
    PaymentAuditHistoricalContext(const CChainLocksHandler& handler,
                                 const uint256& witness_id)
    {
        LOCK(::cs_main);
        return handler.ResolvePendingPaymentAuditContext(witness_id);
    }

    static std::optional<bool> TryHistoricalPaymentAudit(
        CChainLocksHandler& handler, const pq::FinalPaymentAudit& audit,
        const CChainLocksHandler::PaymentAuditHistoricalContext& context)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main)
    {
        AssertLockNotHeld(::cs_main);
        return handler.TryProcessPaymentAuditHistoricalReplay(audit, context);
    }

    static void RequestPaymentAuditDependency(CChainLocksHandler& handler)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main)
    {
        handler.RequestNeededPaymentAuditCertificate();
    }

    static std::chrono::microseconds PaymentAuditLastRequest(
        const CChainLocksHandler& handler)
    {
        LOCK(handler.m_pending_payment_audit_receipt_mutex);
        return handler.m_pending_payment_audit_last_request;
    }

    static VerifiedPaymentAuditReceiptTransitionPtr HistoricalPaymentAuditTransition(
        const CChainLocksHandler& handler, const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier)
    {
        LOCK(::cs_main);
        return handler.GetPaymentAuditHistoricalReplayTransition(receipt, carrier);
    }

    static pq::PQChainLockPersistence& Persistence(CChainLocksHandler& handler)
    {
        return *Assert(handler.m_persistence);
    }

    static std::optional<pq::PaymentAuditPresealMarker> RecoverPaymentPreseal(
        const CChain& active_chain, const CBlockIndex& old_terminal,
        const pq::PaymentAuditPresealMarker& marker,
        const uint256& genesis_hash,
        const pq::PaymentAuditScheduleConfig& schedule,
        const std::function<bool(CBlock&, const CBlockIndex&)>& read_block)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return CChainLocksHandler::RecoverPaymentAuditPresealMarker(
            active_chain, old_terminal, marker, genesis_hash, schedule, read_block);
    }

    static bool PendingHistory(const CChainLocksHandler& handler, bool allow_prefix = true)
    {
        LOCK(::cs_main);
        return handler.HasPendingPQHistoryAuthentication(allow_prefix);
    }

    static void SetRestoredEnforcementWitness(
        CChainLocksHandler& handler, const uint256& witness_id)
    {
        LOCK(handler.m_persisted_mutex);
        handler.m_threshold_attested_enforcement_witness = witness_id;
        handler.m_persisted_best_auth_pending = true;
        handler.m_enforced.store(true);
    }

    static bool BestAuthenticationPending(const CChainLocksHandler& handler)
    {
        LOCK(handler.m_persisted_mutex);
        return handler.m_persisted_best_auth_pending;
    }

    static void EnforceBestChainLock(CChainLocksHandler& handler)
    {
        handler.EnforceBestChainLock();
    }

    static void RefreshHistory(CChainLocksHandler& handler)
    {
        handler.RefreshPQHistoryAuthState();
    }

    static std::optional<pq::BTCCPresealMarker> RecoverBTCCPresealMarker(
        const CChain& active_chain, const CBlockIndex& old_terminal,
        const pq::BTCCPresealMarker& marker, const uint256& genesis_hash,
        const pq::ChainLockFinalityStoreConfig& config)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return CChainLocksHandler::RecoverBTCCPresealMarker(
            active_chain, old_terminal, marker, genesis_hash, config);
    }

    static void SetBTCCPresealRevision(CChainLocksHandler& handler,
                                      uint64_t revision)
    {
        LOCK(handler.m_btcc_preseal_mutex);
        handler.m_btcc_preseal_revision = revision;
    }

    static void RevokeHistoricalAuthorization(CChainLocksHandler& handler)
    {
        const CBlockIndex* tip{WITH_LOCK(::cs_main, return handler.m_chainman.ActiveTip())};
        handler.UpdatedBlockTip(tip, /*initial_download=*/false);
    }

    static bool TryReenterWithMalformedPaymentMarker(CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        if (!handler.m_historical_sync) return false;
        std::optional<pq::PaymentAuditPresealMarker> original;
        {
            LOCK(handler.m_btcc_preseal_mutex);
            original = std::exchange(handler.m_payment_audit_preseal_state.prospective,
                                     pq::PaymentAuditPresealMarker{});
        }
        const bool recognized{
            handler.TryReenterHistoricalSyncAuthentication(*handler.m_historical_sync)};
        {
            LOCK(handler.m_btcc_preseal_mutex);
            handler.m_payment_audit_preseal_state.prospective = std::move(original);
        }
        return recognized;
    }

    static bool TryReenterWithBTCCReceiptId(CChainLocksHandler& handler, const uint256& logical_id)
    {
        LOCK(::cs_main);
        if (!handler.m_historical_sync) return false;
        uint256 original;
        {
            LOCK(handler.m_btcc_preseal_mutex);
            original = std::exchange(handler.m_btcc_preseal_state.active->terminal_receipt.chainlock_logical_id,
                                     logical_id);
        }
        const bool recognized{
            handler.TryReenterHistoricalSyncAuthentication(*handler.m_historical_sync)};
        {
            LOCK(handler.m_btcc_preseal_mutex);
            handler.m_btcc_preseal_state.active->terminal_receipt.chainlock_logical_id = original;
        }
        return recognized;
    }

    static std::shared_ptr<const pq::FinalChainLock> HistoricalRevalidationCertificate(
        const CChainLocksHandler& handler)
    {
        const auto input{handler.m_historical_sync_revalidation_input.load()};
        return input ? input->certificate : nullptr;
    }

    static pq::RecoveryUniverseCapsulePtr HistoricalRevalidationUniverse(
        const CChainLocksHandler& handler)
    {
        const auto input{handler.m_historical_sync_revalidation_input.load()};
        return input ? input->recovery_universe : nullptr;
    }

    static void SetHistoricalRevalidationInput(
        CChainLocksHandler& handler,
        std::shared_ptr<const pq::FinalChainLock> certificate,
        pq::RecoveryUniverseCapsulePtr recovery_universe)
    {
        handler.m_historical_sync_revalidation_input.store(
            std::make_shared<const CChainLocksHandler::HistoricalSyncRevalidationInput>(
                CChainLocksHandler::HistoricalSyncRevalidationInput{
                    std::move(certificate), std::move(recovery_universe)}));
    }

    static pq::RecoveryUniverseLookup RecoveryUniverseLookup(
        const CChainLocksHandler& handler)
    {
        return handler.GetRecoveryUniversePersistenceLookup();
    }

    static bool RevalidationInputIsPeerServable(
        CChainLocksHandler& handler, const uint256& logical_id)
    {
        LOCK(::cs_main);
        auto ordinary{std::move(handler.m_store)};
        handler.m_store = std::make_unique<pq::ChainLockFinalityStore>(
            handler.m_genesis_hash, *handler.m_config,
            static_cast<const pq::ChainLockFinalityContext&>(handler));
        auto protected_records{std::exchange(handler.m_historical_sync_servable, {})};
        auto bootstrap{std::exchange(handler.m_historical_sync_bootstrap_servable, {})};
        CChainLockSig certificate;
        const bool servable{handler.AlreadyHave(logical_id) ||
            handler.GetChainLockByHash(logical_id, certificate)};
        handler.m_historical_sync_bootstrap_servable = std::move(bootstrap);
        handler.m_historical_sync_servable = std::move(protected_records);
        handler.m_store = std::move(ordinary);
        return servable;
    }

    static bool RefreshHistoricalBoundary(CChainLocksHandler& handler)
        EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        return handler.RefreshPoWHistoricalSyncBoundary();
    }

    static uint64_t OpenShareAdmissionForTest(CChainLocksHandler& handler)
    {
        handler.m_share_admission_gate.SetReady(true);
        while (!handler.m_share_admission_gate.TryPublishEnabled(
            handler.m_share_admission_gate.Observe(), true)) {}
        return handler.GetShareAdmissionGeneration();
    }

    static bool HasShareAdmission(const CChainLocksHandler& handler)
    {
        return handler.GetShareAdmissionGeneration() != 0;
    }

    static bool IsShareAdmissionCurrent(const CChainLocksHandler& handler, uint64_t generation)
    {
        return handler.IsShareAdmissionGenerationCurrent(generation);
    }

    static bool IsShareAdmissionTerminal(const CChainLocksHandler& handler)
    {
        return handler.m_share_admission_gate.IsTerminal();
    }

    static std::unique_ptr<CPQSignerJournal> ExchangeSignerJournal(
        CChainLocksHandler& handler, std::unique_ptr<CPQSignerJournal> journal)
    {
        return std::exchange(handler.m_signer_journal, std::move(journal));
    }

    static pq::PaymentAuditStore& AuditStore(CChainLocksHandler& handler)
    {
        return *Assert(handler.m_payment_audit_store);
    }

    static bool HasHistoricalSyncAuthorization(const CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        return static_cast<bool>(handler.GetPoWHistoricalSyncAuthorization());
    }

    static std::optional<pq::HistoricalSyncBoundary> SelectHistoricalSyncBoundary(
        CChainLocksHandler& handler, std::optional<int32_t> coverage_height = std::nullopt)
    {
        LOCK(::cs_main);
        return handler.SelectPoWHistoricalSyncBoundary(coverage_height);
    }

    static bool ValidateHistoricalSyncBoundary(
        const CChainLocksHandler& handler, const pq::HistoricalSyncBoundary& boundary,
        const pq::FinalChainLock& certificate)
    {
        LOCK(::cs_main);
        return handler.ValidatePoWHistoricalSyncBoundary(boundary, certificate).has_value();
    }

    static void ClearHistoricalIndexTestCache(CChainLocksHandler& handler)
    {
        LOCK(::cs_main);
        handler.m_historical_index_validation_cache = {};
    }

    static std::unique_ptr<pq::PQChainLockPersistence> ExchangePersistence(
        CChainLocksHandler& handler,
        std::unique_ptr<pq::PQChainLockPersistence> persistence)
    {
        return std::exchange(handler.m_persistence, std::move(persistence));
    }

    static std::optional<pq::VerifiedHistoricalSyncSuccessor>
    PrepareHistoricalSyncSuccessor(
        const CChainLocksHandler& handler, const pq::FinalChainLock& chainlock)
    {
        LOCK(::cs_main);
        std::optional<pq::VerifiedHistoricalSyncSuccessor> proof;
        if (!handler.PrepareHistoricalSyncSuccessor(chainlock, proof)) {
            return std::nullopt;
        }
        return proof;
    }

    static bool HasNoFinalityWinner(const CChainLocksHandler& handler)
    {
        return handler.m_store && !handler.m_store->GetBestRecord() &&
               handler.m_persistence && !handler.m_persistence->HasBest();
    }

    static std::optional<uint8_t> FindCurrentSigningVariant(
        const std::array<pq::PreparedChainLockContextPtr, 2>& variants,
        pq::VerifiedRosterSetPtr roster_set,
        const uint256& statement_logical_id)
    {
        CChainLocksHandler::CurrentSigningContexts contexts;
        contexts.count = variants.size();
        contexts.roster_set = std::move(roster_set);
        for (std::size_t index{0}; index < variants.size(); ++index) {
            if (!variants[index]) return std::nullopt;
            contexts.statements[index] = variants[index]->Statement();
            contexts.prepared_contexts[index] = variants[index];
        }
        const auto found{contexts.Find(statement_logical_id)};
        return found
            ? std::optional<uint8_t>{found->variant_index}
            : std::nullopt;
    }

    struct ChainLockFinalizationRetryState {
        CChainLocksHandler::CurrentSigningContextsPtr expected_contexts;
        CChainLocksHandler::CurrentSigningContextsPtr current_contexts;
        std::unique_ptr<pq::ChainLockCollector> collector;
        uint64_t expected_collector_generation{7};
        uint64_t current_collector_generation{7};
        uint64_t admission_generation{11};
    };

    static ChainLockFinalizationRetryState FinalizationRetryState(
        const pq::PreparedChainLockContextPtr& context)
    {
        ChainLockFinalizationRetryState state;
        CChainLocksHandler::CurrentSigningContexts contexts;
        contexts.count = 1;
        contexts.source.admission_generation = state.admission_generation;
        contexts.statements[0] = context->Statement();
        contexts.prepared_contexts[0] = context;
        contexts.roster_set = context->RosterSetPtr();
        state.expected_contexts =
            std::make_shared<const CChainLocksHandler::CurrentSigningContexts>(
                std::move(contexts));
        state.current_contexts = state.expected_contexts;
        state.collector = pq::ChainLockCollector::Create(context);
        return state;
    }

    static pq::CollectedChainLockFinalizationPtr FinalizationRetryProof(
        ChainLockFinalizationRetryState& state)
    {
        const auto finalized{CChainLocksHandler::GetChainLockFinalizationForRetry(
            state.expected_contexts, state.expected_collector_generation,
            state.current_contexts, state.current_collector_generation,
            state.admission_generation, 0, state.collector.get())};
        return finalized ? finalized->proof : nullptr;
    }

    static void ReplaceFinalizationRetryContexts(
        ChainLockFinalizationRetryState& state)
    {
        state.current_contexts =
            std::make_shared<const CChainLocksHandler::CurrentSigningContexts>(
                *state.expected_contexts);
    }

    static bool PublishFinalizationRetry(
        CChainLocksHandler& handler,
        ChainLockFinalizationRetryState& retry)
    {
        if (!handler.m_config || !handler.m_store || !handler.m_persistence ||
            !handler.m_payment_audit_store ||
            handler.m_payment_audit_store->GetPruneCheckpoint() ||
            handler.m_persistence->LoadRosterRecoveryPrecommit()) {
            return false;
        }
        {
            LOCK(handler.m_btcc_preseal_mutex);
            if (!handler.m_payment_audit_preseal_state.IsEmpty()) return false;
        }
        handler.m_share_admission_gate.SetReady(true);
        if (!handler.m_share_admission_gate.TryPublishEnabled(
                handler.m_share_admission_gate.Observe(), true)) {
            return false;
        }
        auto contexts{*retry.expected_contexts};
        auto& source{contexts.source};
        const auto& statement{contexts.statements[0]};
        source.admission_generation = handler.GetShareAdmissionGeneration();
        source.finality_store_revision = handler.m_store->ObserveState().state_revision;
        source.persistence_certificate_revision =
            handler.m_persistence->GetFinalityState().certificate_revision;
        (void)handler.GetQuorumRosterCache(&source.roster_source_generation);
        // This fixture has no checkpoint, recovery precommit, or preseal.
        CHashWriter mutable_token{SER_GETHASH, 0};
        mutable_token << std::string{"SYS_PQ_MUTABLE_SIGNING_CONTEXT_V1"}
                      << uint256{} << uint256{};
        source.mutable_signing_context_token = mutable_token.GetHash();
        CHashWriter preseal_token{SER_GETHASH, 0};
        preseal_token << std::string{"SYS_PQ_PAYMENT_AUDIT_PRESEAL_ADMISSION_V1"}
                      << false << false;
        source.payment_audit_preseal_token = preseal_token.GetHash();
        source.durable_predecessor = {
            statement.previous_chainlock_height,
            statement.previous_chainlock_hash, statement.previous_btcc_cursor};
        {
            LOCK(::cs_main);
            const auto* tip{handler.m_chainman.ActiveTip()};
            const auto window{tip ? pq::CurrentChainLockSigningWindow(
                handler.m_config->chainlock_schedule,
                source.durable_predecessor.height, tip->nHeight) : std::nullopt};
            if (!window) return false;
            source.window = *window;
            source.provenance_revocation_revision =
                handler.m_chainman.GetPQProvenanceRevocationRevision();
        }
        source.target_hash = statement.block_hash;
        source.declared_predecessor_hash = statement.previous_chainlock_hash;
        source.btcc_receipt_state = statement.btcc_receipt_state;
        source.payment_audit_receipt_state = statement.payment_audit_receipt_state;
        source.payment_probation_state_hash = statement.payment_probation_state_hash;
        contexts.relay_plan = std::make_shared<const PQRelayPlan>();
        if (!handler.IsCurrentSigningSource(source)) return false;
        const auto published{
            std::make_shared<const CChainLocksHandler::CurrentSigningContexts>(
                std::move(contexts))};
        {
            LOCK(handler.m_collector_mutex);
            handler.m_current_signing_contexts = published;
            handler.m_collectors[0] = std::move(retry.collector);
            ++handler.m_collector_generation;
        }
        return handler.IsChainLockVerificationAvailable() &&
               handler.GetPublishedCurrentSigningContexts(
                   published->source.admission_generation) == published;
    }

    static Mutex& ChainLockAdmissionMutex(CChainLocksHandler& handler)
    {
        return handler.m_chainlock_admission_mutex;
    }

    static void RetryChainLockFinalization(CChainLocksHandler& handler)
        EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        handler.MaybeRetryChainLockFinalization();
    }

    static pq::VerifiedPaymentAuditAdmission VerifiedPaymentAudit(
        pq::FinalPaymentAudit audit,
        uint8_t authorization_mask = 0x0f)
    {
        return pq::VerifiedPaymentAuditAdmission{
            std::move(audit), authorization_mask};
    }

    static std::optional<pq::VerifiedRosterAuthorizationBaseView>
    ResolvePaymentAuditSealRecord(
        const pq::ChainLockFinalityStore& store,
        const uint256& genesis_hash,
        const pq::ChainLockStatement& seal_statement)
    {
        return CChainLocksHandler::ResolvePaymentAuditSealRecord(
            store, genesis_hash, seal_statement);
    }

    enum class CertificateStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
        LOCAL_ERROR,
    };

    struct LiveSigningFrontier {
        CChainLocksHandler::LiveSigningValidationFrontier frontier;
        uint64_t examined_blocks{0};
    };

    using CertificateCheck = std::function<CertificateStatus(
        const pq::BTCCReceipt&, const CBlockIndex&)>;

    struct ReplayStep {
        std::optional<int32_t> validated_through;
        std::optional<uint256> missing_logical_id;
        CertificateStatus terminal_status{CertificateStatus::VERIFIED};
        int32_t blocked_carrier_height{-1};
        uint256 blocked_carrier_hash;
        uint256 blocked_logical_id;
    };

    enum class PaymentAuditGCPhase : uint8_t {
        NONE = 0,
        ARCHIVE,
        PROBATION,
        INVALID,
    };

    enum class NeededCertificateSource : uint8_t {
        LIVE_FRONTIER = 0,
        PRESEAL_REPLAY = 1,
        PAYMENT_AUDIT_SEAL = 2,
    };

    class NeededCertificateState {
        friend class CChainLocksHandlerTestAccess;
        std::optional<CChainLocksHandler::NeededBTCCCertificate> current;
    };

    class PaymentAuditSealDependencyState {
        friend class CChainLocksHandlerTestAccess;
        std::optional<CChainLocksHandler::PendingPaymentAuditSealDependency>
            current;
        std::optional<CChainLocksHandler::NeededBTCCCertificate> needed;
    };

    class LivePaymentAuditSealCapability {
        friend class CChainLocksHandlerTestAccess;
        std::optional<CChainLocksHandler::PaymentAuditSealFetchCapability>
            capability;
    };

    struct PaymentAuditSealRequest {
        pq::RosterAuthorizationBaseIdentity target;
        uint256 source_token;
        uint64_t revision;

        friend bool operator==(const PaymentAuditSealRequest&,
                               const PaymentAuditSealRequest&) = default;
    };

    static std::optional<PaymentAuditSealRequest> PaymentAuditSealRequestState(
        const CChainLocksHandler& handler)
    {
        LOCK(handler.m_pending_payment_audit_receipt_mutex);
        const auto& dependency{handler.m_pending_payment_audit_seal};
        return dependency ? std::make_optional(PaymentAuditSealRequest{
            dependency->RequestedIdentity(), dependency->source_token,
            dependency->request_revision}) : std::nullopt;
    }

    static std::optional<PaymentAuditSealRequest> PaymentAuditSealRequestState(
        const PaymentAuditSealDependencyState& state)
    {
        return state.current ? std::make_optional(PaymentAuditSealRequest{
            state.current->RequestedIdentity(), state.current->source_token,
            state.current->request_revision}) : std::nullopt;
    }

    static LivePaymentAuditSealCapability PaymentAuditSealCapability(
        const PaymentAuditSealDependencyState& state,
        const std::optional<pq::VerifiedRosterAuthorizationBaseView>& base = std::nullopt)
    {
        LivePaymentAuditSealCapability result;
        if (state.current) result.capability = CChainLocksHandler::PaymentAuditSealFetchCapability{*state.current, base};
        return result;
    }

    static bool PaymentAuditSealCapabilityMatches(
        const PaymentAuditSealDependencyState& state,
        const LivePaymentAuditSealCapability& capability)
    {
        return state.current && capability.capability &&
            CChainLocksHandler::DoesPaymentAuditSealSourceMatch(
                *capability.capability, state.current->owner, state.current, state.needed);
    }

    static bool AdvancePaymentAuditSealDependency(
        CChainLocksHandler& handler,
        const LivePaymentAuditSealCapability& capability,
        const pq::RosterAuthorizationBaseIdentity& missing)
    {
        return capability.capability &&
            handler.AdvancePaymentAuditSealDependency(*capability.capability, missing);
    }

    static bool BuildPaymentAuditSealVerificationContext(
        const CChainLocksHandler& handler,
        const LivePaymentAuditSealCapability& capability,
        const pq::ChainLockStatement& statement,
        std::optional<pq::RosterAuthorizationBaseIdentity>& missing)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main)
    {
        AssertLockNotHeld(::cs_main);
        return capability.capability && handler.BuildPaymentAuditSealVerificationContext(
            *capability.capability, statement, /*publish_roster=*/false, &missing).has_value();
    }

    static void SetPendingPaymentAuditReceipt(
        CChainLocksHandler& handler,
        const pq::PaymentAuditReceipt& receipt,
        const uint256& carrier_hash,
        const uint256& carrier_parent_hash)
    {
        LOCK(handler.m_pending_payment_audit_receipt_mutex);
        LOCK(handler.m_needed_btcc_certificate_mutex);
        handler.m_pending_payment_audit_seal.reset();
        handler.m_needed_btcc_certificate.reset();
        handler.m_pending_payment_audit_receipt =
            CChainLocksHandler::PendingPaymentAuditReceiptDependency{
                receipt, carrier_hash, carrier_parent_hash};
    }

    static bool StagePaymentAuditSealDependency(
        CChainLocksHandler& handler,
        const pq::ChainLockStatement& statement,
        const std::optional<pq::RosterAuthorizationBaseIdentity>&
            objective_base)
    {
        std::optional<CChainLocksHandler::
            PendingPaymentAuditReceiptDependency> owner;
        {
            LOCK(handler.m_pending_payment_audit_receipt_mutex);
            owner = handler.m_pending_payment_audit_receipt;
        }
        if (!owner) return false;
        const auto dependency{
            CChainLocksHandler::MakePendingPaymentAuditSealDependency(
                handler.m_genesis_hash, *owner, statement,
                objective_base)};
        return dependency &&
            handler.StagePendingPaymentAuditSealDependency(*dependency);
    }

    static LivePaymentAuditSealCapability PaymentAuditSealCapability(
        const CChainLocksHandler& handler,
        const uint256& logical_id)
    {
        LivePaymentAuditSealCapability result;
        result.capability =
            handler.GetPaymentAuditSealFetchCapability(logical_id);
        return result;
    }

    static bool HasPaymentAuditSealCapability(
        const LivePaymentAuditSealCapability& capability)
    {
        return capability.capability.has_value();
    }

    static bool AuthorizePaymentAuditSealPersistence(
        const CChainLocksHandler& handler,
        const LivePaymentAuditSealCapability& capability,
        const std::function<bool()>& persist_record,
        pq::ChainLockFinalityError* error)
    {
        return capability.capability &&
            handler.AuthorizePaymentAuditSealPersistence(
                *capability.capability, persist_record, error);
    }

    static void CompletePaymentAuditSealFetch(
        CChainLocksHandler& handler,
        const LivePaymentAuditSealCapability& capability)
    {
        if (capability.capability) {
            handler.CompletePaymentAuditSealFetch(
                *capability.capability);
        }
    }

    static bool HasPendingPaymentAuditSeal(
        const CChainLocksHandler& handler)
    {
        LOCK(handler.m_pending_payment_audit_receipt_mutex);
        return handler.m_pending_payment_audit_seal.has_value();
    }

    static bool HasPendingPaymentAuditReceipt(
        const CChainLocksHandler& handler)
    {
        LOCK(handler.m_pending_payment_audit_receipt_mutex);
        return handler.m_pending_payment_audit_receipt.has_value();
    }

    static bool HasNeededPaymentAuditSeal(
        const CChainLocksHandler& handler)
    {
        LOCK(handler.m_needed_btcc_certificate_mutex);
        return handler.m_needed_btcc_certificate &&
            handler.m_needed_btcc_certificate->source ==
                CChainLocksHandler::NeededBTCCCertificateSource::
                    PAYMENT_AUDIT_SEAL;
    }

    static void ClearPaymentAuditDependenciesForStop(
        CChainLocksHandler& handler)
    {
        handler.ClearPendingPaymentAuditDependenciesForStop();
    }

    static bool PublishPaymentAuditSealDependency(
        PaymentAuditSealDependencyState& state,
        const uint256& genesis_hash,
        const pq::PaymentAuditReceipt& receipt,
        const uint256& carrier_hash,
        const uint256& carrier_parent_hash,
        const pq::ChainLockStatement& statement,
        const std::optional<pq::RosterAuthorizationBaseIdentity>& objective_base,
        const std::optional<pq::RosterAuthorizationBaseIdentity>& requested_base = std::nullopt,
        uint64_t request_revision = 0,
        const std::optional<uint256>& replay_source = std::nullopt)
    {
        const CChainLocksHandler::PendingPaymentAuditReceiptDependency owner{
            receipt, carrier_hash, carrier_parent_hash,
            replay_source ? CChainLocksHandler::PaymentAuditReceiptDependencySource::PRESEAL_REPLAY
                          : CChainLocksHandler::PaymentAuditReceiptDependencySource::DEFERRED_CANDIDATE,
            replay_source.value_or(uint256{})};
        const auto dependency{
            CChainLocksHandler::MakePendingPaymentAuditSealDependency(
                genesis_hash, owner, statement, objective_base, requested_base, request_revision)};
        if (!dependency) return false;
        const bool changed{
            CChainLocksHandler::PublishPendingPaymentAuditSealDependency(
                state.current, *dependency)};
        (void)CChainLocksHandler::PublishNeededBTCCCertificate(
            state.needed,
            CChainLocksHandler::NeededBTCCCertificateSource::
                PAYMENT_AUDIT_SEAL,
            dependency->RequestedIdentity().logical_id, dependency->source_token);
        return changed;
    }

    static bool PaymentAuditSealSourceMatches(
        const PaymentAuditSealDependencyState& state,
        const pq::PaymentAuditReceipt& receipt,
        const uint256& carrier_hash,
        const uint256& carrier_parent_hash,
        const std::optional<pq::VerifiedRosterAuthorizationBaseView>& base,
        const std::optional<uint256>& replay_source = std::nullopt)
    {
        if (!state.current) return false;
        return CChainLocksHandler::DoesPaymentAuditSealSourceMatch(
            CChainLocksHandler::PaymentAuditSealFetchCapability{
                *state.current, base},
            CChainLocksHandler::PendingPaymentAuditReceiptDependency{
                receipt, carrier_hash, carrier_parent_hash,
                replay_source ? CChainLocksHandler::PaymentAuditReceiptDependencySource::PRESEAL_REPLAY
                              : CChainLocksHandler::PaymentAuditReceiptDependencySource::DEFERRED_CANDIDATE,
                replay_source.value_or(uint256{})},
            state.current, state.needed);
    }

    static std::optional<uint256> PaymentAuditSealLogicalId(
        const PaymentAuditSealDependencyState& state)
    {
        return state.current
            ? std::optional<uint256>{state.current->logical_id}
            : std::nullopt;
    }

    static bool PublishNeededCertificate(
        NeededCertificateState& state,
        NeededCertificateSource source,
        const uint256& logical_id,
        const uint256& source_token)
    {
        return CChainLocksHandler::PublishNeededBTCCCertificate(
            state.current,
            static_cast<CChainLocksHandler::NeededBTCCCertificateSource>(
                source),
            logical_id, source_token);
    }

    static bool EraseNeededCertificate(
        NeededCertificateState& state,
        NeededCertificateSource source,
        const std::optional<uint256>& source_token = std::nullopt)
    {
        return CChainLocksHandler::EraseNeededBTCCCertificate(
            state.current,
            static_cast<CChainLocksHandler::NeededBTCCCertificateSource>(
                source),
            source_token);
    }

    static bool EraseNeededCertificateByLogicalId(
        NeededCertificateState& state,
        const uint256& logical_id)
    {
        return CChainLocksHandler::
            EraseNeededBTCCCertificateByLogicalId(
                state.current, logical_id);
    }

    static std::optional<uint256> SelectRequiredCertificate(
        const std::optional<uint256>& pending,
        const NeededCertificateState& state)
    {
        return CChainLocksHandler::SelectRequiredBTCCCertificate(
            pending, state.current);
    }

    static void MarkNeededCertificateRequested(
        NeededCertificateState& state)
    {
        BOOST_REQUIRE(state.current);
        state.current->last_request = std::chrono::microseconds{1};
    }

    static bool NeededCertificateRequestTimerIsClear(
        const NeededCertificateState& state)
    {
        return state.current && state.current->last_request.count() == 0;
    }

    struct PaymentAuditGCPlan {
        PaymentAuditGCPhase phase{PaymentAuditGCPhase::NONE};
        pq::PaymentAuditStoreCheckpoint checkpoint;
        std::vector<uint256> retained_roots;
        bool derive_retained_roots{false};
    };

    using ReplayCheck = std::function<std::pair<CertificateStatus, uint256>(
        const CBlockIndex&)>;

    static bool Advance(
        LiveSigningFrontier& state,
        const CChain& active_chain,
        const CBlockIndex& target,
        const pq::ChainLockPredecessor& durable_predecessor,
        const pq::ChainLockFinalityStoreConfig& config,
        const uint256& genesis_hash,
        uint64_t provenance_revocation_revision,
        const CertificateCheck& check,
        std::size_t block_budget =
            HistoricalIndexValidationCache::BLOCK_BUDGET)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        const auto adapter = [&](const pq::BTCCReceipt& receipt,
                                 const CBlockIndex& carrier) {
            if (!check) {
                return CChainLocksHandler::
                    BTCCReceiptCertificateStatus::INVALID;
            }
            switch (check(receipt, carrier)) {
            case CertificateStatus::VERIFIED:
                return CChainLocksHandler::
                    BTCCReceiptCertificateStatus::VERIFIED;
            case CertificateStatus::MISSING:
                return CChainLocksHandler::
                    BTCCReceiptCertificateStatus::MISSING;
            case CertificateStatus::INVALID:
                return CChainLocksHandler::
                    BTCCReceiptCertificateStatus::INVALID;
            case CertificateStatus::LOCAL_ERROR:
                return CChainLocksHandler::
                    BTCCReceiptCertificateStatus::INVALID;
            }
            return CChainLocksHandler::
                BTCCReceiptCertificateStatus::INVALID;
        };
        return CChainLocksHandler::
            AdvanceLiveSigningValidationFrontier(
                state.frontier, active_chain, target,
                durable_predecessor, config, genesis_hash,
                provenance_revocation_revision, adapter,
                state.examined_blocks, block_budget);
    }

    static bool HasExactTargetEndpoint(const CBlockIndex& target)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return CChainLocksHandler::
            HasExactLiveSigningTargetEndpoint(target);
    }

    static int32_t ValidatedThrough(
        const LiveSigningFrontier& state) noexcept
    {
        return state.frontier.validated_through_height;
    }

    static uint256 ValidatedThroughHash(
        const LiveSigningFrontier& state)
    {
        return state.frontier.validated_through_hash;
    }

    static pq::ChainLockPredecessor DurablePredecessor(
        const LiveSigningFrontier& state)
    {
        return state.frontier.durable_predecessor;
    }

    static bool SourceRevisionCurrent(uint64_t source_revision,
                                      uint64_t current_revision)
    {
        CChainLocksHandler::CurrentSigningSource source;
        source.provenance_revocation_revision = source_revision;
        return CChainLocksHandler::
            IsLiveSigningValidationRevisionCurrent(
                source, current_revision);
    }

    static bool ExactHistoricalResetCandidate(
        const pq::ChainLockStatement& statement,
        const pq::ChainLockScheduleConfig& chainlock,
        const pq::BTCCScheduleConfig& btcc,
        int32_t activation_predecessor_height,
        const uint256& activation_predecessor_hash,
        bool has_durable_best,
        bool target_is_active,
        const uint256& target_btcp_prev,
        bool has_verified_historical_recovery = false)
    {
        return CChainLocksHandler::IsExactHistoricalResetCandidate(
            statement, chainlock, btcc,
            activation_predecessor_height,
            activation_predecessor_hash, has_durable_best,
            target_is_active, target_btcp_prev,
            has_verified_historical_recovery);
    }

    static const CBlockIndex* HistoricalSelectionTip(
        const CBlockIndex& active_tip,
        const pq::ChainLockScheduleConfig& schedule,
        std::optional<int32_t> coverage_height)
    {
        return CChainLocksHandler::ResolvePoWHistoricalSelectionTip(
            active_tip, schedule, coverage_height);
    }

    static bool HistoricalCapabilityMatches(
        uint8_t verified_admission,
        const uint256& verified_marker,
        uint64_t verified_roster_generation,
        uint8_t expected_admission,
        const uint256& expected_marker,
        uint64_t current_roster_generation)
    {
        const CChainLocksHandler::HistoricalAdmissionContext verified{
            static_cast<CChainLocksHandler::HistoricalAdmission>(
                verified_admission),
            verified_marker};
        const CChainLocksHandler::HistoricalAdmissionContext expected{
            static_cast<CChainLocksHandler::HistoricalAdmission>(
                expected_admission),
            expected_marker};
        return CChainLocksHandler::
            DoesHistoricalVerificationCapabilityMatch(
                verified, verified_roster_generation, expected,
                current_roster_generation);
    }

    static uint8_t HistoricalRosterAuthorization(
        pq::ChainLockCandidateAdmission candidate_admission,
        uint8_t historical_admission,
        pq::RosterAuthorizationTransitionKind transition)
    {
        return static_cast<uint8_t>(CChainLocksHandler::
            SelectHistoricalRosterAuthorization(
                candidate_admission,
                static_cast<CChainLocksHandler::HistoricalAdmission>(
                    historical_admission),
                transition));
    }

    static pq::ChainLockCandidateAdmission
    HistoricalPreVerificationAdmission(
        uint8_t historical_admission,
        int32_t statement_height,
        std::optional<int32_t> best_height)
    {
        return CChainLocksHandler::
            SelectHistoricalPreVerificationAdmission(
                static_cast<CChainLocksHandler::HistoricalAdmission>(
                    historical_admission),
                statement_height, best_height);
    }

    static bool HistoricalArchiveIdentity(
        pq::ChainLockCandidateAdmission admission)
    {
        return CChainLocksHandler::IsHistoricalArchiveIdentity(admission);
    }

    static bool StateAdvancingAuthorizationBaseAdmissible(
        const CChainLocksHandler& handler,
        pq::ChainLockCandidateAdmission admission,
        const pq::FinalChainLock& chainlock,
        const std::optional<pq::BTCCCursorReconciliationProof>&
            btcc_cursor_reconciliation = std::nullopt)
    {
        if (!handler.m_store) return false;
        const auto current{handler.m_store->GetBestRecord()};
        const CBlockIndex* candidate{nullptr};
        std::optional<
            CChainLocksHandler::ObjectiveRosterAuthorizationContext>
            objective;
        {
            LOCK(::cs_main);
            candidate = handler.m_chainman.m_blockman.LookupBlockIndex(
                chainlock.statement.block_hash);
            if (candidate != nullptr &&
                chainlock.statement.roster_transition !=
                    pq::RosterAuthorizationTransitionKind::INITIALIZE) {
                objective = handler
                    .ResolveObjectiveRosterAuthorizationContext(*candidate);
            }
        }
        if (candidate == nullptr) return false;
        const auto exact_prior{
            objective && objective->base
                ? objective->base
                : std::optional<pq::VerifiedRosterAuthorizationBaseView>{}};
        const auto authorization{
            handler.BuildNetworkRosterAuthorizationContext(
                chainlock.statement, *candidate,
                objective ? &*objective : nullptr)};
        return authorization &&
               handler.IsStateAdvancingAuthorizationBaseAdmissible(
                   admission, chainlock.selected_quorum_mask,
                   chainlock.statement, *candidate, current,
                   exact_prior ? &*exact_prior : nullptr,
                   *authorization, btcc_cursor_reconciliation);
    }

    static std::optional<pq::RosterAuthorizationVerificationContext>
    NetworkRosterAuthorization(
        const CChainLocksHandler& handler,
        const pq::ChainLockStatement& statement)
    {
        const CBlockIndex* candidate{nullptr};
        std::optional<CChainLocksHandler::ObjectiveRosterAuthorizationContext> objective;
        {
            LOCK(::cs_main);
            candidate = handler.m_chainman.m_blockman.LookupBlockIndex(statement.block_hash);
            if (candidate != nullptr) {
                objective = handler.ResolveObjectiveRosterAuthorizationContext(*candidate);
            }
        }
        return candidate != nullptr && objective
            ? handler.BuildNetworkRosterAuthorizationContext(statement, *candidate, &*objective)
            : std::nullopt;
    }

    static bool ReceiptArchiveSourceMatches(
        uint8_t capability_source,
        const uint256& logical_id,
        const uint256& source_token,
        std::optional<std::pair<uint256, uint256>> pending,
        std::optional<std::tuple<uint8_t, uint256, uint256>> needed)
    {
        CChainLocksHandler::BTCCReceiptArchiveCapability capability;
        capability.source = static_cast<
            CChainLocksHandler::BTCCReceiptArchiveSource>(
                capability_source);
        capability.logical_id = logical_id;
        capability.source_token = source_token;
        std::optional<CChainLocksHandler::PendingBTCCReceiptDependency>
            pending_dependency;
        if (pending) {
            pending_dependency =
                CChainLocksHandler::PendingBTCCReceiptDependency{
                    pending->first, pending->second};
        }
        std::optional<CChainLocksHandler::NeededBTCCCertificate>
            needed_certificate;
        if (needed) {
            needed_certificate = CChainLocksHandler::NeededBTCCCertificate{
                static_cast<CChainLocksHandler::NeededBTCCCertificateSource>(
                    std::get<0>(*needed)),
                std::get<1>(*needed), std::get<2>(*needed), {}};
        }
        return CChainLocksHandler::DoesBTCCReceiptArchiveSourceMatch(
            capability, pending_dependency, needed_certificate);
    }

    static int32_t CandidateFullValidationFloor(
        const pq::ChainLockCandidateContextRequest& request,
        int32_t activation_predecessor_height)
    {
        return CChainLocksHandler::CandidateFullValidationFloor(
            request, activation_predecessor_height);
    }

    static HistoricalIndexValidationMode CandidateTargetValidationMode(
        pq::ChainLockCandidateAdmission admission)
    {
        return CChainLocksHandler::CandidateTargetValidationMode(admission);
    }

    static bool CandidateTargetValidationSufficient(
        pq::ChainLockCandidateAdmission admission,
        bool has_local_chainlock,
        bool marker_authorized_catchup,
        bool exact_local_target,
        bool historical_receipt_range_ready)
    {
        return CChainLocksHandler::IsCandidateTargetValidationSufficient(
            admission, has_local_chainlock, marker_authorized_catchup,
            exact_local_target,
            historical_receipt_range_ready);
    }

    static ReplayStep AdvanceReplay(
        BoundedActiveRangeFrontier& frontier,
        const CChain& active_chain,
        const CBlockIndex& active_tip,
        int32_t authenticated_through,
        const uint256& authenticated_hash,
        const uint256& source_token,
        const pq::BTCCScheduleConfig& schedule,
        const ReplayCheck& check,
        std::size_t block_budget =
            HistoricalIndexValidationCache::BLOCK_BUDGET)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        const auto adapter = [&](const CBlockIndex& carrier) {
            const auto [status, logical_id]{check(carrier)};
            CChainLocksHandler::BTCCReplayCarrierStatus translated{
                CChainLocksHandler::BTCCReplayCarrierStatus::LOCAL_ERROR};
            switch (status) {
            case CertificateStatus::VERIFIED:
                translated = CChainLocksHandler::
                    BTCCReplayCarrierStatus::VERIFIED;
                break;
            case CertificateStatus::MISSING:
                translated = CChainLocksHandler::
                    BTCCReplayCarrierStatus::MISSING;
                break;
            case CertificateStatus::INVALID:
                translated = CChainLocksHandler::
                    BTCCReplayCarrierStatus::INVALID;
                break;
            case CertificateStatus::LOCAL_ERROR:
                break;
            }
            return CChainLocksHandler::BTCCReplayCarrierCheck{
                translated, logical_id};
        };
        const auto result{CChainLocksHandler::
            AdvanceBTCCReplayValidationFrontier(
                frontier, active_chain, active_tip,
                authenticated_through, authenticated_hash,
                source_token, schedule, adapter, block_budget)};
        CertificateStatus terminal_status{CertificateStatus::LOCAL_ERROR};
        switch (result.terminal_status) {
        case CChainLocksHandler::BTCCReplayCarrierStatus::VERIFIED:
            terminal_status = CertificateStatus::VERIFIED;
            break;
        case CChainLocksHandler::BTCCReplayCarrierStatus::MISSING:
            terminal_status = CertificateStatus::MISSING;
            break;
        case CChainLocksHandler::BTCCReplayCarrierStatus::INVALID:
            terminal_status = CertificateStatus::INVALID;
            break;
        case CChainLocksHandler::BTCCReplayCarrierStatus::LOCAL_ERROR:
            terminal_status = CertificateStatus::LOCAL_ERROR;
            break;
        }
        return {result.validated_through,
                result.missing_logical_id,
                terminal_status,
                result.blocked_carrier_height,
                result.blocked_carrier_hash,
                result.blocked_logical_id};
    }

    static PaymentAuditGCPlan SelectPaymentAuditGCPlan(
        const std::optional<pq::PaymentAuditStoreCheckpoint>&
            pending_archive,
        const std::optional<pq::PQPaymentProbationGCRequest>&
            pending_probation,
        const std::optional<pq::PaymentAuditStoreCheckpoint>&
            completed_archive,
        bool completed_probation)
    {
        const auto selected{
            CChainLocksHandler::SelectPaymentAuditGCMaintenancePlan(
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
        return {static_cast<PaymentAuditGCPhase>(selected.phase),
                selected.checkpoint,
                selected.retained_probation_roots,
                selected.derive_retained_probation_roots};
    }
};

} // namespace llmq::test

namespace {

struct LiveSigningIndexChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;
    CChain active;

    explicit LiveSigningIndexChain(std::size_t count)
        : hashes(count), indices(count)
    {
        for (std::size_t height{0}; height < count; ++height) {
            hashes[height] = NonNullHash(100'000 + height);
            CBlockIndex& index{indices[height]};
            index.nHeight = static_cast<int32_t>(height);
            index.phashBlock = &hashes[height];
            index.pprev = height == 0 ? nullptr : &indices[height - 1];
            index.nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_BTCC_INDEX_VALIDATED |
                BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                (CSuperblock::IsValidBlockHeight(index.nHeight)
                     ? BLOCK_GOVERNANCE_VALIDATED
                     : 0));
            index.BuildSkip();
        }
        active.SetTip(indices.back());
    }

    CBlockIndex& At(int32_t height)
    {
        return indices.at(static_cast<std::size_t>(height));
    }

    const CBlockIndex& At(int32_t height) const
    {
        return indices.at(static_cast<std::size_t>(height));
    }

    llmq::pq::ChainLockPredecessor Predecessor(int32_t height) const
    {
        return llmq::pq::ChainLockPredecessor{
            height, At(height).GetBlockHash(), {}};
    }

    void SetReceiptStateFrom(int32_t height,
                             const llmq::pq::BTCCReceiptState& state)
    {
        for (std::size_t offset{static_cast<std::size_t>(height)};
             offset < indices.size(); ++offset) {
            CBlockIndex& index{indices[offset]};
            index.pqBTCCReceiptCursorHeight = state.cursor.sys_height;
            index.pqBTCCReceiptCursorSysHash = state.cursor.sys_hash;
            index.pqBTCCReceiptCursorBTCHash = state.cursor.btc_hash;
            index.pqBTCCReceiptStateHash = state.cumulative_hash;
            index.pqBTCCReceiptLatestTargetHeight =
                state.latest_chainlock_target_height;
            index.pqBTCCReceiptLatestCarrierHeight =
                state.latest_receipt_carrier_height;
        }
    }

    void ClearStatus(int32_t height, uint32_t status)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        CBlockIndex& index{At(height)};
        index.nStatus = static_cast<BlockStatus>(index.nStatus & ~status);
    }

    void SetStatus(int32_t height, uint32_t status)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        CBlockIndex& index{At(height)};
        index.nStatus = static_cast<BlockStatus>(index.nStatus | status);
    }

    void RehashFrom(int32_t height, uint64_t salt)
    {
        for (std::size_t offset{static_cast<std::size_t>(height)};
             offset < hashes.size(); ++offset) {
            hashes[offset] = NonNullHash(salt + offset);
        }
    }
};

struct PaymentPresealReorgFixture {
    static constexpr std::array<int32_t, 3> CARRIERS{1'385, 1'725, 1'965};
    const uint256 genesis{NonNullHash(850'000)};
    const uint256 predecessor_probation{NonNullHash(850'001)};
    const llmq::pq::PaymentAuditScheduleConfig schedule{
        *llmq::pq::MakeChainLockScheduleConfig(0),
        llmq::pq::BTCCScheduleConfig{.candidate_origin = 865}};
    LiveSigningIndexChain chain{2'001};
    std::array<llmq::pq::PaymentAuditReceipt, 3> receipts;
    std::array<CBlock, 3> blocks;
    llmq::pq::PaymentAuditPresealMarker marker;
    std::vector<uint256> fork_hashes;
    std::vector<CBlockIndex> fork;
    std::vector<int32_t> reads;
    std::optional<int32_t> unavailable_height;

    PaymentPresealReorgFixture()
    {
        // Give the exact block-read callback ordinary matching header hashes.
        for (auto& index : chain.indices) {
            index.nVersion = 1;
            index.hashMerkleRoot = NonNullHash(851'000 + index.nHeight);
            chain.hashes[index.nHeight] = index.GetBlockHeader().GetHash();
            index.pqPaymentProbationStateHash = predecessor_probation;
        }
        llmq::pq::PaymentAuditReceiptState state;
        for (std::size_t i{0}; i < receipts.size(); ++i) {
            auto& receipt{receipts[i]};
            const auto epoch{static_cast<uint32_t>(3 + i)};
            const auto epoch_schedule{
                llmq::pq::BuildPaymentAuditEpochSchedule(schedule, epoch)};
            BOOST_REQUIRE(epoch_schedule);
            receipt = NonNullPaymentAuditReceipt(i);
            receipt.epoch = epoch;
            receipt.seal_height = epoch_schedule->seal_height;
            receipt.seal_block_hash = chain.At(receipt.seal_height).GetBlockHash();
            receipt.carrier_height = CARRIERS[i];
            receipt.subject_roster_beacon = SubjectBeacon(epoch);
            const auto next{llmq::pq::ApplyPaymentAuditReceipt(genesis, state, receipt)};
            BOOST_REQUIRE(next);
            state = *next;
            for (int32_t height{receipt.carrier_height};
                 height <= chain.active.Height(); ++height) {
                auto& index{chain.At(height)};
                index.pqPaymentAuditReceiptCursorHeight = state.cursor.carrier_height;
                index.pqPaymentAuditReceiptCursorEpoch = state.cursor.epoch;
                index.pqPaymentAuditReceiptCursorSealHash = state.cursor.seal_block_hash;
                index.pqPaymentAuditReceiptCursorLogicalId = state.cursor.audit_logical_id;
                index.pqPaymentAuditReceiptCursorWitnessId = state.cursor.audit_witness_id;
                index.pqPaymentAuditReceiptStateHash = state.cumulative_hash;
                index.pqPaymentProbationStateHash = receipt.next_probation_state_hash;
            }
            blocks[i] = PaymentAuditCarrierBlock(receipt);
            static_cast<CBlockHeader&>(blocks[i]) =
                chain.At(receipt.carrier_height).GetBlockHeader();
        }
        marker = llmq::pq::PaymentAuditPresealMarker{
            CARRIERS.front(), chain.At(CARRIERS.front()).GetBlockHash(),
            {}, predecessor_probation, CARRIERS.back(),
            chain.At(CARRIERS.back()).GetBlockHash(), receipts.back(), 7};
        BOOST_REQUIRE(marker.IsStructurallyValid());
    }

    void ReorgAfter(int32_t shared_height)
    {
        LOCK(cs_main);
        fork = std::vector<CBlockIndex>(chain.active.Height() - shared_height);
        fork_hashes.resize(fork.size());
        CBlockIndex* previous{&chain.At(shared_height)};
        for (std::size_t i{0}; i < fork.size(); ++i) {
            auto& index{fork[i]};
            // The replacement suffix has null audit receipts and inherits
            // the common ancestor's exact receipt and probation states.
            index.nHeight = shared_height + 1 + static_cast<int32_t>(i);
            index.nVersion = 1;
            index.nStatus = chain.At(index.nHeight).nStatus;
            const auto& shared{chain.At(shared_height)};
            index.pqPaymentAuditReceiptCursorHeight = shared.pqPaymentAuditReceiptCursorHeight;
            index.pqPaymentAuditReceiptCursorEpoch = shared.pqPaymentAuditReceiptCursorEpoch;
            index.pqPaymentAuditReceiptCursorSealHash = shared.pqPaymentAuditReceiptCursorSealHash;
            index.pqPaymentAuditReceiptCursorLogicalId = shared.pqPaymentAuditReceiptCursorLogicalId;
            index.pqPaymentAuditReceiptCursorWitnessId = shared.pqPaymentAuditReceiptCursorWitnessId;
            index.pqPaymentAuditReceiptStateHash = shared.pqPaymentAuditReceiptStateHash;
            index.pqPaymentProbationStateHash = shared.pqPaymentProbationStateHash;
            index.nNonce = static_cast<uint32_t>(index.nHeight);
            index.pprev = previous;
            index.phashBlock = &fork_hashes[i];
            fork_hashes[i] = index.GetBlockHeader().GetHash();
            index.BuildSkip();
            previous = &index;
        }
        chain.active.SetTip(*previous);
    }

    std::optional<llmq::pq::PaymentAuditPresealMarker> Recover()
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return llmq::test::CChainLocksHandlerTestAccess::RecoverPaymentPreseal(
            chain.active, chain.At(CARRIERS.back()), marker, genesis, schedule,
            [this](CBlock& block, const CBlockIndex& index) {
                reads.push_back(index.nHeight);
                if (unavailable_height == index.nHeight) return false;
                for (std::size_t i{0}; i < CARRIERS.size(); ++i) {
                    if (CARRIERS[i] != index.nHeight) continue;
                    block = blocks[i];
                    return true;
                }
                return false;
            });
    }

    void CheckBoundary(const llmq::pq::PaymentAuditPresealMarker& recovered,
                       std::size_t receipt_index) const
    {
        auto expected{marker};
        expected.terminal_carrier_height = CARRIERS[receipt_index];
        expected.terminal_carrier_hash = chain.At(CARRIERS[receipt_index]).GetBlockHash();
        expected.terminal_receipt = receipts[receipt_index];
        BOOST_CHECK(recovered == expected);
    }
};

llmq::pq::ChainLockFinalityStoreConfig LiveSigningFrontierConfig()
{
    auto config{CatchupStoreConfig()};
    BOOST_REQUIRE(config.IsValid());
    return config;
}

const auto ACCEPT_LIVE_SIGNING_CERTIFICATE = [](
                                                 const llmq::pq::BTCCReceipt&, const CBlockIndex&) {
    return llmq::test::CChainLocksHandlerTestAccess::
        CertificateStatus::VERIFIED;
};

struct BTCCPresealRecoveryChain {
    static constexpr int32_t FIRST_CARRIER{2'315};
    static constexpr int32_t MIDDLE_CARRIER{2'325};
    static constexpr int32_t OLD_TERMINAL{2'405};
    static constexpr int32_t TIP_HEIGHT{2'410};

    const uint256 genesis{NonNullHash(985'000)};
    const llmq::pq::ChainLockFinalityStoreConfig config{[] {
        const auto selected{llmq::MakePQChainLockFinalityStoreConfig(ValidConsensus())};
        BOOST_REQUIRE(selected);
        return *selected;
    }()};
    LiveSigningIndexChain original{TIP_HEIGHT + 1};
    LiveSigningIndexChain replacement{TIP_HEIGHT + 1};
    llmq::pq::BTCCReceiptState first_state;
    llmq::pq::BTCCReceiptState middle_state;
    llmq::pq::BTCCReceipt first_receipt;
    llmq::pq::BTCCReceipt middle_receipt;
    llmq::pq::BTCCPresealMarker marker;

    BTCCPresealRecoveryChain()
    {
        const llmq::pq::BTCCursor cursor{
            2'305, original.At(2'305).GetBlockHash(), NonNullHash(985'001)};
        original.At(cursor.sys_height).btcpPrevCommitment = cursor.btc_hash;
        const auto append = [&](int32_t height,
                                const llmq::pq::BTCCReceiptState& previous,
                                llmq::pq::BTCCReceipt& receipt) {
            receipt.chainlock_target_height = height - llmq::pq::PQ_BTCC_NEVM_LAG;
            receipt.chainlock_target_hash = original.At(receipt.chainlock_target_height).GetBlockHash();
            receipt.chainlock_logical_id = NonNullHash(985'100 + height);
            receipt.accepted_cursor = cursor;
            const auto state{llmq::pq::ApplyBTCCReceiptState(
                genesis, config.chainlock_schedule, config.btcc_schedule,
                config.activation_predecessor_height, height,
                original.At(height).GetBlockHash(), previous, receipt)};
            BOOST_REQUIRE(state);
            original.SetReceiptStateFrom(height, *state);
            original.At(height).pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
            return *state;
        };
        first_state = append(FIRST_CARRIER, {}, first_receipt);
        middle_state = append(MIDDLE_CARRIER, first_state, middle_receipt);
        llmq::pq::BTCCReceipt terminal_receipt;
        (void)append(OLD_TERMINAL, middle_state, terminal_receipt);
        marker = {FIRST_CARRIER, original.At(FIRST_CARRIER).GetBlockHash(), {},
                  OLD_TERMINAL, original.At(OLD_TERMINAL).GetBlockHash(),
                  middle_state, terminal_receipt, 7};
        BOOST_REQUIRE(marker.IsStructurallyValid());
    }

    void ForkAfter(int32_t common_height)
    {
        replacement.At(common_height + 1).pprev = &original.At(common_height);
        replacement.RehashFrom(common_height + 1, 986'000);
        for (int32_t height{common_height + 1}; height <= TIP_HEIGHT; ++height) {
            replacement.At(height).BuildSkip();
        }
        replacement.SetReceiptStateFrom(common_height + 1,
            common_height < MIDDLE_CARRIER ? first_state : middle_state);
        replacement.active.SetTip(original.At(common_height));
        replacement.active.SetTip(replacement.At(TIP_HEIGHT));
        BOOST_REQUIRE(replacement.active.FindFork(&original.At(OLD_TERMINAL)) ==
                      &original.At(common_height));
    }
};

// SYSCOIN: Observe actual mining entry points after public IBD has latched.
struct ReplayMiningNEVMSubscriber final : CValidationInterface {
    std::size_t template_requests{0};
    std::string template_error;

    void NotifyGetNEVMBlock(CNEVMBlock& block, std::string& error) override
    {
        ++template_requests;
        error = template_error;
        block.nBlockHash = NonNullHash(1'100'000 + template_requests);
        block.nTxRoot = block.nBlockHash;
        block.nReceiptRoot = block.nBlockHash;
        block.vchNEVMBlockData = {1};
    }

    void NotifyNEVMBlockConnect(
        const CNEVMHeader&, const CBlock&, std::string& error,
        const uint256&, NEVMDataVec&, const uint32_t&, bool, const uint256&,
        const CDeterministicMNListNEVMAddressDiff&,
        std::optional<NEVMBlockReject>* rejection = nullptr) override
    {
        error.clear();
        if (rejection) rejection->reset();
    }
};

struct PresealMiningSetup : TestChain100Setup {
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    static constexpr int32_t TIP_HEIGHT{1'385};
    static constexpr int32_t BTCC_CARRIER_HEIGHT{875};
    const bool previous_nevm_connection{fNEVMConnection};
    std::shared_ptr<ReplayMiningNEVMSubscriber> nevm{
        std::make_shared<ReplayMiningNEVMSubscriber>()};
    const llmq::pq::ChainLockFinalityStoreConfig marker_config{[] {
        auto config{CatchupStoreConfig()};
        config.btcc_schedule.candidate_origin = 865;
        return config;
    }()};
    std::unique_ptr<llmq::pq::PQChainLockPersistence> original_persistence;
    llmq::pq::PQChainLockPersistence* durable{nullptr};
    uint64_t marker_revision{0};

    PresealMiningSetup()
        : TestChain100Setup{ChainType::REGTEST, {"-nevmstartheight=101"}}
    {
        fNEVMConnection = false;
        mineBlocks(TIP_HEIGHT - 100);
        SyncWithValidationInterfaceQueue();
        auto& chainman{static_cast<TestChainstateManager&>(*Assert(m_node.chainman))};
        BOOST_REQUIRE_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), TIP_HEIGHT);
        BOOST_REQUIRE(llmq::chainLocksHandler);
        BOOST_REQUIRE(marker_config.IsValid());
        auto persistence{std::make_unique<llmq::pq::PQChainLockPersistence>(
            DBParams{.path = m_path_root / "mining-replay-markers", .cache_bytes = 4U << 20},
            chainman.GetConsensus().hashGenesisBlock, marker_config)};
        durable = persistence.get();
        original_persistence = Access::ExchangePersistence(
            *llmq::chainLocksHandler, std::move(persistence));
        BOOST_REQUIRE(!durable->HasBest());
        chainman.ResetIbd(PQHistoryAuthState::READY);
        BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
        BOOST_REQUIRE(!chainman.HasPendingNEVMStartupPair());
        RegisterSharedValidationInterface(nevm);
        fNEVMConnection = true;
    }

    ~PresealMiningSetup()
    {
        UnregisterValidationInterface(nevm.get());
        SyncWithValidationInterfaceQueue();
        fNEVMConnection = previous_nevm_connection;
        if (durable) Access::SetReplayMarkers(*llmq::chainLocksHandler, {}, {});
        Access::ExchangePersistence(
            *llmq::chainLocksHandler, std::move(original_persistence)).reset();
    }

    llmq::pq::BTCCPresealMarker BTCCMarker(bool unrelated = false)
    {
        LOCK(::cs_main);
        auto& chainman{*Assert(m_node.chainman)};
        const CBlockIndex* carrier{chainman.ActiveChain()[BTCC_CARRIER_HEIGHT]};
        BOOST_REQUIRE(carrier);
        if (unrelated) {
            auto header{carrier->GetBlockHeader()};
            header.hashMerkleRoot = NonNullHash(1'101'000 + marker_revision);
            carrier = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(carrier);
            BOOST_REQUIRE(!chainman.ActiveChain().Contains(carrier));
        }
        const CBlockIndex* target{carrier->GetAncestor(865)};
        BOOST_REQUIRE(target);
        llmq::pq::BTCCReceipt receipt;
        receipt.chainlock_target_height = target->nHeight;
        receipt.chainlock_target_hash = target->GetBlockHash();
        receipt.chainlock_logical_id = NonNullHash(1'102'000);
        receipt.accepted_cursor = {target->nHeight, target->GetBlockHash(), NonNullHash(1'102'001)};
        llmq::pq::BTCCPresealMarker marker{
            carrier->nHeight, carrier->GetBlockHash(), {},
            carrier->nHeight, carrier->GetBlockHash(), {}, receipt, ++marker_revision};
        BOOST_REQUIRE(marker.IsStructurallyValid());
        return marker;
    }

    llmq::pq::PaymentAuditPresealMarker PaymentMarker(bool unrelated = false)
    {
        LOCK(::cs_main);
        auto& chainman{*Assert(m_node.chainman)};
        const llmq::pq::PaymentAuditScheduleConfig schedule{
            marker_config.chainlock_schedule, marker_config.btcc_schedule};
        const auto epoch{llmq::pq::BuildPaymentAuditEpochSchedule(schedule, 3)};
        BOOST_REQUIRE(epoch);
        BOOST_REQUIRE_EQUAL(epoch->carrier_start_height, TIP_HEIGHT);
        const CBlockIndex* carrier{chainman.ActiveChain()[epoch->carrier_start_height]};
        BOOST_REQUIRE(carrier);
        if (unrelated) {
            auto header{carrier->GetBlockHeader()};
            header.hashMerkleRoot = NonNullHash(1'103'000 + marker_revision);
            carrier = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(carrier);
            BOOST_REQUIRE(!chainman.ActiveChain().Contains(carrier));
        }
        auto receipt{NonNullPaymentAuditReceipt(3)};
        receipt.epoch = 3;
        receipt.seal_height = epoch->seal_height;
        receipt.seal_block_hash = carrier->GetAncestor(receipt.seal_height)->GetBlockHash();
        receipt.carrier_height = carrier->nHeight;
        receipt.subject_roster_beacon = SubjectBeacon(receipt.epoch);
        llmq::pq::PaymentAuditPresealMarker marker{
            carrier->nHeight, carrier->GetBlockHash(), {}, NonNullHash(1'104'000),
            carrier->nHeight, carrier->GetBlockHash(), receipt, ++marker_revision};
        BOOST_REQUIRE(marker.IsStructurallyValid());
        return marker;
    }

    void CheckDurableMarkers(const llmq::pq::BTCCPresealState& btcc,
                             const llmq::pq::PaymentAuditPresealState& payment)
    {
        // Reopen the database so this observes the synchronous disk write,
        // including erasure, independently of persistence's in-memory cache.
        SyncWithValidationInterfaceQueue();
        durable = nullptr;
        Access::ExchangePersistence(*llmq::chainLocksHandler, nullptr).reset();
        auto persistence{std::make_unique<llmq::pq::PQChainLockPersistence>(
            DBParams{.path = m_path_root / "mining-replay-markers", .cache_bytes = 4U << 20},
            m_node.chainman->GetConsensus().hashGenesisBlock, marker_config)};
        durable = persistence.get();
        Access::ExchangePersistence(*llmq::chainLocksHandler, std::move(persistence));
        BOOST_REQUIRE(durable->LoadBTCCPresealState() == btcc);
        BOOST_REQUIRE(durable->LoadPaymentAuditPresealState() == payment);
        BOOST_REQUIRE(!durable->HasBest());
    }

    UniValue MiningRPC(const std::string& method)
    {
        node::JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = UniValue{UniValue::VARR};
        if (method == "getblocktemplate") {
            UniValue options{UniValue::VOBJ};
            UniValue rules{UniValue::VARR};
            rules.push_back("segwit");
            options.pushKV("rules", rules);
            request.params.push_back(options);
        } else {
            request.params.push_back(EncodeDestination(PKHash(coinbaseKey.GetPubKey())));
        }
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
        return tableRPC.execute(request);
    }

    void CheckMiningCachesAllowed()
    {
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        for (const auto* method : {"getblocktemplate", "createauxblock"}) {
            BOOST_TEST_CONTEXT(method) {
                const auto first{MiningRPC(method)};
                BOOST_REQUIRE(first.isObject());
                BOOST_CHECK_EQUAL(first["height"].getInt<int>(), TIP_HEIGHT + 1);
                BOOST_CHECK_EQUAL(first["previousblockhash"].get_str(),
                    WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip()->GetBlockHash().ToString()));
                const auto requests{nevm->template_requests};
                const auto cached{MiningRPC(method)};
                BOOST_CHECK_EQUAL(cached.write(), first.write());
                BOOST_CHECK_EQUAL(nevm->template_requests, requests);
            }
        }
    }

    void CheckMiningCachesBlocked()
    {
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        const auto requests{nevm->template_requests};
        for (const auto* method : {"getblocktemplate", "createauxblock"}) {
            BOOST_TEST_CONTEXT(method) {
                BOOST_CHECK_EXCEPTION(MiningRPC(method), UniValue,
                    [](const UniValue& error) {
                        return error["code"].getInt<int>() == RPC_CLIENT_IN_INITIAL_DOWNLOAD &&
                               error["message"].get_str() ==
                                   "NEVM block production is waiting for execution recovery";
                    });
                BOOST_CHECK_EQUAL(nevm->template_requests, requests);
            }
        }
    }

    void CheckAssemblerAllowed()
    {
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        const auto requests{nevm->template_requests};
        const auto block{node::BlockAssembler{m_node.chainman->ActiveChainstate(), nullptr}
                             .CreateNewBlock(CScript{} << OP_TRUE)};
        BOOST_REQUIRE(block);
        BOOST_CHECK_EQUAL(nevm->template_requests, requests + 1);
    }

    void CheckAssemblerBlocked()
    {
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        BOOST_REQUIRE(!m_node.chainman->HasPendingNEVMStartupPair());
        const auto requests{nevm->template_requests};
        BOOST_CHECK_EXCEPTION(
            (node::BlockAssembler{m_node.chainman->ActiveChainstate(), nullptr}
                 .CreateNewBlock(CScript{} << OP_TRUE)),
            std::runtime_error, [](const std::runtime_error& error) {
                return std::string{error.what()} ==
                    "NEVM block production is waiting for execution recovery";
            });
        BOOST_CHECK_EQUAL(nevm->template_requests, requests);
    }
};

// SYSCOIN: Start at the already-connected compact-receipt boundary. Ordinary
// archive cases model prior signature verification. The opt-in historical
// cases sign their terminal audit and invoke the complete verifier. The chain
// indexes and canonical roster snapshots model an already-connected history;
// these tests do not claim cold synchronization from public peers.
struct LatePaymentAuditPresealSetup : TestingSetup {
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using Status = llmq::CChainLocksHandler::PaymentAuditReceiptCertificateStatus;
    static constexpr int32_t FIRST_CARRIER{2'825};
    static constexpr int32_t TIP_HEIGHT{3'407};
    static constexpr std::array<int32_t, 3> CARRIERS{FIRST_CARRIER, 3'115, 3'405};

    struct Engine final : CValidationInterface {
        uint64_t count{0};
        uint256 hash;
        std::vector<uint256> connected;
        std::size_t template_requests{0};
        std::size_t queries{0};
        std::size_t flushes{0};
        bool flush_available{true};
        bool wrong_final_tip{false};
        uint64_t expected_final_count{TIP_HEIGHT - FIRST_CARRIER + 1};
        std::optional<uint256> reported_hash;
        std::function<void()> on_query;

        void NotifyGetNEVMBlock(CNEVMBlock&, std::string& error) override
        {
            ++template_requests;
            error = "late-payment-preseal-template-probe";
        }
        void NotifyNEVMBlockConnect(
            const CNEVMHeader&, const CBlock& block, std::string& error,
            const uint256& incoming, NEVMDataVec&, const uint32_t& height,
            bool, const uint256&, const CDeterministicMNListNEVMAddressDiff&,
            std::optional<NEVMBlockReject>* rejection = nullptr) override
        {
            error.clear();
            if (rejection) rejection->reset();
            if (incoming.IsNull()) return;
            BOOST_REQUIRE_EQUAL(height, FIRST_CARRIER + count);
            if (count != 0) BOOST_REQUIRE(block.hashPrevBlock == hash);
            ++count;
            hash = incoming;
            connected.push_back(hash);
        }
        void NotifyNEVMComms(const std::string& command, bool& response,
                             std::optional<NEVMBlockReject>* rejection = nullptr) override
        {
            if (rejection) rejection->reset();
            if (command == "flush") ++flushes;
            response = command == "flush" ? flush_available : true;
        }
        void NotifyGetNEVMBlockInfo(uint64_t& reported_count, uint256& reported,
                                 std::string& error) override
        {
            ++queries;
            if (auto callback{std::exchange(on_query, {})}) callback();
            error.clear();
            reported_count = count;
            reported = wrong_final_tip && count == expected_final_count
                ? NonNullHash(1'250'000) : reported_hash.value_or(hash);
        }
    };

    struct AuditPeer {
        ConnmanTestMsg& connman;
        PeerManager& peerman;
        CNode* node;
        const std::chrono::seconds previous_mock_time{GetMockTime()};
        std::atomic<bool> interrupt{false};

        explicit AuditPeer(node::NodeContext& context)
            : connman{static_cast<ConnmanTestMsg&>(*context.connman)},
              peerman{*context.peerman},
              node{new CNode{/*id=*/925, /*sock=*/nullptr,
                  CAddress{CService{in_addr{0xa0b0c00d}, 7785}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/13, /*nLocalHostNonceIn=*/925, CAddress{},
                  /*addrNameIn=*/std::string{}, ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false}}
        {
            connman.AddTestNode(*node);
        }
        ~AuditPeer()
        {
            peerman.FinalizeNode(*node);
            connman.ClearTestNodes();
            SetMockTime(previous_mock_time);
        }
        void Handshake() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex, !::cs_main)
        {
            connman.Handshake(*node, /*successfully_connected=*/true,
                ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                ServiceFlags(NODE_NETWORK | NODE_WITNESS), PROTOCOL_VERSION, /*relay_txs=*/true);
            TestOnlyResetTimeData();
            BOOST_REQUIRE(!node->fDisconnect);
            connman.FlushSendBuffer(*node);
            node->fPauseSend = false;
        }
        template <typename T>
        void Dispatch(const char* command, const T& value)
            EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex, !::cs_main)
        {
            CDataStream payload{SER_NETWORK, node->GetCommonVersion()};
            payload << value;
            peerman.ProcessMessage(*node, command, payload,
                GetTime<std::chrono::microseconds>(), interrupt);
        }
        void Request(const uint256& witness_id)
            EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex, !::cs_main)
        {
            Dispatch(NetMsgType::INV, std::vector<CInv>{{MSG_PQPOSECERT, witness_id}});
            peerman.SendMessages(node);
            BOOST_REQUIRE(WITH_LOCK(::cs_main,
                return peerman.GetRequestedPaymentAudit(node->GetId())) == witness_id);
            connman.FlushSendBuffer(*node);
            node->fPauseSend = false;
        }
        void Deliver(const llmq::pq::FinalPaymentAudit& audit)
            EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex, !::cs_main)
        {
            Dispatch(NetMsgType::PQPOSECERT, audit);
            BOOST_CHECK(!WITH_LOCK(::cs_main,
                return peerman.GetRequestedPaymentAudit(node->GetId())));
        }
        std::size_t Queued(const std::string& command) const
        {
            LOCK(node->cs_vSend);
            const auto& [bytes, more, current]{node->m_transport->GetBytesToSend(false)};
            (void)more;
            return (!bytes.empty() && current == command ? 1U : 0U) +
                std::count_if(node->vSendMsg.begin(), node->vSendMsg.end(),
                    [&](const CSerializedNetMsg& message) { return message.m_type == command; });
        }
    };

    const bool previous_nevm{fNEVMConnection};
    llmq::CChainLocksHandler* const previous_handler{llmq::chainLocksHandler};
    std::shared_ptr<Engine> engine{std::make_shared<Engine>()};
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    std::vector<CBlockIndex*> chain;
    std::vector<uint256> replay_hashes;
    std::array<llmq::pq::FinalPaymentAudit, 3> audits;
    std::array<llmq::pq::PaymentAuditReceipt, 3> receipts;
    llmq::pq::PaymentAuditPresealState markers;
    llmq::pq::BTCCReceiptState btcc_state;
    llmq::pq::PaymentAuditReceiptState payment_state;
    uint256 probation_hash;
    llmq::pq::ChainLockFinalityStoreConfig config;
    llmq::pq::QuorumBuildConfig quorum_config;
    llmq::pq::FrozenQuorumRosterCachePtr signing_roster_cache;
    std::vector<std::optional<scheduled_wots::SecretKey>> signing_keys;
    std::vector<scheduled_wots::PublicKey> signing_public_keys;
    const bool signed_terminal;
    const bool invalid_terminal_signature;
    const int32_t tip_height;
    std::size_t roster_lookups{0};
    const uint256 genesis{m_node.chainman->GetConsensus().hashGenesisBlock};

    struct ActiveDIP {
        Consensus::Params& consensus;
        const int previous;
        explicit ActiveDIP(Consensus::Params& params)
            : consensus{params}, previous{params.DIP0003Height}
        {
            consensus.DIP0003Height = 1;
        }
        ~ActiveDIP() { consensus.DIP0003Height = previous; }
    };

    explicit LatePaymentAuditPresealSetup(bool sign_terminal = false, bool invalid_signature = false)
        : TestingSetup{ChainType::REGTEST, {"-nevmstartheight=2825"}},
          chain(static_cast<std::size_t>((sign_terminal ? 3'420 : TIP_HEIGHT) + 1)),
          signed_terminal{sign_terminal}, invalid_terminal_signature{invalid_signature},
          tip_height{sign_terminal ? 3'420 : TIP_HEIGHT}
    {
        fNEVMConnection = false;
        CreateHandler();
        config = *Assert(Access::Config(*handler));
        quorum_config = *Assert(Access::QuorumConfig(*handler));
        if (signed_terminal) PrepareSigningKeys();
        InstallRosterCache();
        BOOST_REQUIRE(deterministicMNManager);
        probation_hash = deterministicMNManager->EmptyPaymentProbationStateHash();
        const llmq::pq::PaymentAuditScheduleConfig schedule{
            config.chainlock_schedule, config.btcc_schedule};
        std::array<llmq::pq::PaymentAuditEpochSchedule, 3> epochs;
        for (std::size_t i{0}; i < epochs.size(); ++i) {
            const auto epoch{llmq::pq::BuildPaymentAuditEpochSchedule(schedule, 3 + i)};
            BOOST_REQUIRE(epoch);
            epochs[i] = *epoch;
            BOOST_REQUIRE_EQUAL(epochs[i].carrier_start_height, CARRIERS[i]);
        }
        LOCK(::cs_main);
        chain[0] = m_node.chainman->ActiveTip();
        BOOST_REQUIRE(chain[0]);
        chain[0]->pqPaymentProbationStateHash = probation_hash;
        const int64_t first_time{GetTime() - tip_height};
        for (int32_t height{1}; height <= tip_height; ++height) {
            llmq::pq::BTCCReceipt btcc;
            if (height == 2'315) btcc = MakeBTCCReceipt(2'305);
            for (const auto& epoch : epochs) {
                if (int64_t{height} == int64_t{epoch.anchor_height} +
                        config.btcc_schedule.nevm_injection_lag) {
                    btcc = MakeBTCCReceipt(epoch.anchor_height);
                }
            }
            llmq::pq::PaymentAuditReceipt payment;
            for (std::size_t i{0}; i < CARRIERS.size(); ++i) {
                if (height == CARRIERS[i]) payment = PrepareAudit(i, epochs[i]);
            }
            CBlock block;
            block.SetBaseVersion(4, m_node.chainman->GetConsensus().nAuxpowChainId);
            block.hashPrevBlock = chain[height - 1]->GetBlockHash();
            block.nTime = static_cast<uint32_t>(first_time + height);
            block.nBits = chain[0]->nBits;
            CMutableTransaction coinbase;
            coinbase.vin.resize(1);
            coinbase.vin.front().prevout.SetNull();
            coinbase.vin.front().scriptSig = CScript{} << height << OP_0;
            coinbase.vout.emplace_back(0, CScript{} << OP_TRUE);
            DataStream data{SER_NETWORK};
            if (height >= FIRST_CARRIER) {
                block.SetNEVMVersion();
                CNEVMHeader nevm;
                nevm.nBlockHash = NonNullHash(1'210'000 + height);
                nevm.nTxRoot = nevm.nBlockHash;
                nevm.nReceiptRoot = nevm.nBlockHash;
                data << NEVM_MAGIC_BYTES << nevm;
                block.vchNEVMBlockData = {1};
            }
            if (llmq::pq::PaymentAuditReceiptSlotEpoch(schedule, height)) {
                data << PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES << payment;
            }
            if (llmq::pq::IsBTCCReceiptCarrierHeight(config.btcc_schedule, height)) {
                data << BTCC_RECEIPT_MAGIC_BYTES << btcc;
            }
            if (!data.empty()) {
                const auto bytes{MakeUCharSpan(data)};
                coinbase.vout.emplace_back(0, CScript{} << OP_RETURN <<
                    std::vector<unsigned char>{bytes.begin(), bytes.end()});
            }
            block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
            block.hashMerkleRoot = BlockMerkleRoot(block);
            while (!CheckProofOfWork(block.GetHash(), block.nBits,
                                    m_node.chainman->GetConsensus())) ++block.nNonce;
            auto& blockman{m_node.chainman->m_blockman};
            const auto position{blockman.SaveBlockToDisk(block, height, nullptr)};
            BOOST_REQUIRE(!position.IsNull());
            auto* index{blockman.AddToBlockIndex(block, m_node.chainman->m_best_header)};
            BOOST_REQUIRE(index);
            chain[height] = index;
            m_node.chainman->ReceivedBlockTransactions(block, index, position);
            index->nStatus = (index->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS |
                BLOCK_PQ_RECEIPT_INDEX_VALIDATED | BLOCK_GOVERNANCE_VALIDATED;
            if (!btcc.IsNull()) {
                const auto next{llmq::pq::ApplyBTCCReceiptState(
                    genesis, config.chainlock_schedule, config.btcc_schedule,
                    config.activation_predecessor_height, height, block.GetHash(), btcc_state, btcc)};
                BOOST_REQUIRE(next);
                btcc_state = *next;
                index->pqBTCCReceiptLogicalId = btcc.chainlock_logical_id;
            }
            if (!payment.IsNull()) {
                const auto next{llmq::pq::ApplyPaymentAuditReceipt(genesis, payment_state, payment)};
                BOOST_REQUIRE(next);
                payment_state = *next;
                probation_hash = payment.next_probation_state_hash;
            }
            Stamp(*index);
            m_node.chainman->ActiveChainstate().m_chain.SetTip(*index);
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(index->GetBlockHash());
            // Exact manager snapshots support the real probation verifier and
            // native NEVM diff reader; no registration validation is implied.
            BOOST_REQUIRE(deterministicMNManager->m_evoDb->WriteThrough(
                index->GetBlockHash(), CDeterministicMNList{index->GetBlockHash(), height, 0}, false));
            if (height >= FIRST_CARRIER) replay_hashes.push_back(block.GetHash());
        }
        BOOST_REQUIRE(m_node.chainman->m_blockman.FlushChainstateBlockFile(tip_height));
        engine->expected_final_count = replay_hashes.size();
        markers.active = llmq::pq::PaymentAuditPresealMarker{
            FIRST_CARRIER, chain[FIRST_CARRIER]->GetBlockHash(), {},
            deterministicMNManager->EmptyPaymentProbationStateHash(),
            CARRIERS.back(), chain[CARRIERS.back()]->GetBlockHash(), receipts.back(), 1};
        BOOST_REQUIRE(markers.active->IsStructurallyValid());
        Access::SetReplayMarkers(*handler, {}, markers);
        BOOST_REQUIRE(!Access::Store(*handler)->GetBest());
        BOOST_REQUIRE(!Access::AuditStore(*handler).GetPruneCheckpoint());
        llmq::chainLocksHandler = handler.get();
        RegisterSharedValidationInterface(engine);
        fNEVMConnection = true;
        LatchMiningReady();
    }

    ~LatePaymentAuditPresealSetup()
    {
        UnregisterValidationInterface(engine.get());
        SyncWithValidationInterfaceQueue();
        llmq::chainLocksHandler = previous_handler;
        handler.reset();
        fNEVMConnection = previous_nevm;
    }

    void CreateHandler()
    {
        auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
        chainman.ResetIbd(PQHistoryAuthState::PENDING);
        auto& consensus{const_cast<Consensus::Params&>(chainman.GetConsensus())};
        struct Restore {
            Consensus::Params& target;
            Consensus::Params saved;
            ~Restore() { target = saved; }
        } restore{consensus, consensus};
        consensus.DIP0003Height = 1;
        consensus.nPQActivationHeight = 2'305;
        consensus.nPQPreparationHeight = 1'000;
        consensus.nPQChainLockEpochOrigin = 1'440;
        consensus.nPQRegistrationCutoffBlocks = 288;
        consensus.nPQRosterSnapshotLag = 288;
        consensus.nPQFutureHorizonEpochs = 8;
        consensus.nPQBTCCCandidateOrigin = 2'305;
        consensus.nPQBTCCNEVMInjectionLag = llmq::pq::PQ_BTCC_NEVM_LAG;
        consensus.nPQBTCCReceiptAnchorHeight = 0;
        consensus.hashPQBTCCReceiptAnchorBlock = genesis;
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *m_node.connman, *m_node.peerman, chainman);
        BOOST_REQUIRE(Access::Config(*handler));
        BOOST_REQUIRE(Access::QuorumConfig(*handler));
    }

    void PrepareSigningKeys()
    {
        signing_keys.resize(llmq::pq::QUORUM_SIZE);
        signing_public_keys.resize(signing_keys.size());
        std::vector<std::future<bool>> workers;
        constexpr std::size_t WORKERS{8};
        for (std::size_t worker{0}; worker < WORKERS; ++worker) {
            workers.push_back(std::async(std::launch::async, [&, worker] {
                for (std::size_t tag{worker}; tag < signing_keys.size(); tag += WORKERS) {
                    scheduled_wots::KeyGenerationSeed seed{};
                    for (std::size_t byte{0}; byte < seed.size(); ++byte) {
                        seed[byte] = static_cast<uint8_t>(
                            ((uint64_t{tag + 1} >> ((byte % 8) * 8)) ^ (0x63U + 29U * byte)));
                    }
                    auto key{scheduled_wots::GenerateSecretKey(seed)};
                    if (!key || !key->GetPublicKey(signing_public_keys[tag])) return false;
                    signing_keys[tag] = std::move(*key);
                }
                return true;
            }));
        }
        for (auto& worker : workers) BOOST_REQUIRE(worker.get());
    }

    llmq::pq::test::SyntheticChildAuthorization SignedChildAuthorization(
        std::size_t tag, uint32_t epoch) const
    {
        return llmq::pq::test::MakeSyntheticChildAuthorization(
            genesis, NonNullHash(1'220'000 + tag), epoch,
            signing_public_keys.at(tag), (uint64_t{epoch} << 32) | (tag + 1));
    }

    void SignTerminalAudit(llmq::pq::FinalPaymentAudit& audit)
    {
        using namespace llmq::pq;
        auto& seal{audit.statement.seal_statement};
        QuorumBuildError error{QuorumBuildError::NONE};
        const auto verified_rosters{signing_roster_cache->GetVerifiedActiveNoPublish(
            seal.height, *chain[seal.height], seal.roster_beacons.active, &error)};
        BOOST_REQUIRE_MESSAGE(verified_rosters, static_cast<int>(error));
        const auto& rosters{verified_rosters->Rosters()};
        std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            descriptors[slot] = rosters[slot].descriptor;
        }
        seal.quorum_context_hash = GetQuorumContextHash(
            genesis, seal.height, seal.block_hash, descriptors);
        BOOST_REQUIRE(audit.statement.commitment.subject_descriptor_hash ==
            GetPaymentAuditDescriptorHash(genesis, descriptors[REQUIRED_QUORUMS - 1]));
        std::size_t offset{0};
        const PaymentAuditScheduleConfig schedule{config.chainlock_schedule, config.btcc_schedule};
        for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
            const auto& roster{rosters[slot]};
            const auto leaf{PaymentAuditLeafIndex(schedule, audit.statement.commitment.subject_epoch,
                seal.height, roster.descriptor.epoch)};
            BOOST_REQUIRE(leaf);
            for (uint16_t member{0}; member < QUORUM_THRESHOLD; ++member) {
                const auto& frozen{roster.members[member]};
                std::size_t tag{0};
                while (tag < signing_keys.size() && NonNullHash(1'220'000 + tag) != frozen.pro_tx_hash) ++tag;
                BOOST_REQUIRE_LT(tag, signing_keys.size());
                const auto child{SignedChildAuthorization(tag, roster.descriptor.epoch)};
                BOOST_REQUIRE(frozen.child_root && *frozen.child_root == child.record);
                auto& witness{audit.report_witnesses.at(offset++)};
                witness.authenticated_signature.key_proof = child.proof;
                const auto transcript{BuildPaymentAuditShareTranscript(audit.statement,
                    witness.observed_members, roster.descriptor, member, frozen.pro_tx_hash)};
                const auto hash{GetPaymentAuditShareHash(genesis, transcript)};
                scheduled_wots::Message message;
                std::copy(hash.begin(), hash.end(), message.begin());
                // Each operator signs a distinct scheduled audit leaf in
                // each selected slot; every one of the 801 signatures is real.
                BOOST_REQUIRE(scheduled_wots::SignDeterministic(
                    *signing_keys[tag], *leaf, message, witness.authenticated_signature.signature));
            }
        }
        BOOST_REQUIRE_EQUAL(offset, PAYMENT_AUDIT_SIGNATURE_COUNT);
    }

    llmq::pq::QuorumSnapshotState Snapshot(const CBlockIndex& index) const
    {
        using namespace llmq::pq;
        QuorumSnapshotState snapshot;
        snapshot.deterministic_mns = CDeterministicMNList{index.GetBlockHash(), index.nHeight, QUORUM_SIZE};
        const auto view{DeriveOperatorKeyScheduleView(config.chainlock_schedule, index.nHeight,
            quorum_config.registration_cutoff_blocks, quorum_config.future_horizon_epochs)};
        BOOST_REQUIRE(view);
        std::vector<OperatorKeyState> keys;
        for (uint32_t tag{0}; tag < QUORUM_SIZE; ++tag) {
            auto dmn{std::make_shared<CDeterministicMN>(tag + 1)};
            dmn->proTxHash = NonNullHash(1'220'000 + tag);
            dmn->collateralOutpoint = COutPoint{NonNullHash(1'221'000 + tag), tag};
            auto state{std::make_shared<CDeterministicMNState>()};
            const auto owner{NonNullHash(1'222'000 + tag)};
            std::copy_n(owner.begin(), state->keyIDOwner.size(), state->keyIDOwner.begin());
            state->nRegisteredHeight = 1;
            state->UpdateConfirmedHash(dmn->proTxHash, NonNullHash(1'223'000 + tag));
            dmn->pdmnState = state;
            snapshot.deterministic_mns.AddMN(dmn, false);
            auto key{OperatorKeyState::ForOperator(dmn->proTxHash)};
            key.has_global_key = key.global_key_active = 1;
            key.global_key.key_version = 1;
            key.global_key.public_key[0] = static_cast<uint8_t>((tag & 0x7fU) | 0x80U);
            key.global_key.activated_height = 1;
            key.global_key.child_key_commitment.tree_id = NonNullHash(1'224'000 + tag);
            key.global_key.child_key_commitment.generation = 1;
            key.global_key.child_key_commitment.first_epoch = 0;
            key.global_key.child_key_commitment.root = NonNullHash(1'225'000 + tag);
            key.schedule_initialized = 1;
            key.schedule = OperatorKeyScheduleState::FromView(*view);
            if (signed_terminal) {
                key.global_key.child_key_commitment =
                    SignedChildAuthorization(tag, key.schedule.first_mutable_epoch).record.commitment;
            }
            for (uint32_t epoch{key.schedule.first_retained_frozen_epoch};
                 epoch < key.schedule.first_mutable_epoch; ++epoch) {
                key.frozen_child_roots.push_back(signed_terminal
                    ? SignedChildAuthorization(tag, epoch).record
                    : FrozenChildRootRecord{key.pro_tx_hash, 1, epoch, key.global_key.child_key_commitment});
            }
            BOOST_REQUIRE(key.IsStructurallyValid());
            keys.push_back(std::move(key));
        }
        snapshot.operator_key_states = std::make_shared<const std::vector<OperatorKeyState>>(std::move(keys));
        return snapshot;
    }

    void InstallRosterCache(bool available = true)
    {
        const auto cache{llmq::pq::FrozenQuorumRosterCache::Create(
            genesis, quorum_config, [this, available](const CBlockIndex& index)
                -> std::optional<llmq::pq::QuorumSnapshotState> {
                ++roster_lookups;
                if (!available) return std::nullopt;
                return std::optional<llmq::pq::QuorumSnapshotState>{Snapshot(index)};
            })};
        BOOST_REQUIRE(cache);
        signing_roster_cache = cache;
        handler->SetQuorumRosterCache(cache);
    }

    llmq::pq::BTCCReceipt MakeBTCCReceipt(int32_t target_height)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        auto* target{chain[target_height]};
        BOOST_REQUIRE(target);
        llmq::pq::BTCCReceipt receipt;
        receipt.chainlock_target_height = target_height;
        receipt.chainlock_target_hash = target->GetBlockHash();
        receipt.chainlock_logical_id = NonNullHash(1'230'000 + target_height);
        receipt.accepted_cursor = {target_height, target->GetBlockHash(), NonNullHash(1'231'000 + target_height)};
        target->btcpPrevCommitment = receipt.accepted_cursor.btc_hash;
        return receipt;
    }

    void Stamp(CBlockIndex& index)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        index.pqBTCCReceiptCursorHeight = btcc_state.cursor.sys_height;
        index.pqBTCCReceiptCursorSysHash = btcc_state.cursor.sys_hash;
        index.pqBTCCReceiptCursorBTCHash = btcc_state.cursor.btc_hash;
        index.pqBTCCReceiptStateHash = btcc_state.cumulative_hash;
        index.pqBTCCReceiptLatestTargetHeight = btcc_state.latest_chainlock_target_height;
        index.pqBTCCReceiptLatestCarrierHeight = btcc_state.latest_receipt_carrier_height;
        index.pqPaymentAuditReceiptCursorHeight = payment_state.cursor.carrier_height;
        index.pqPaymentAuditReceiptCursorEpoch = payment_state.cursor.epoch;
        index.pqPaymentAuditReceiptCursorSealHash = payment_state.cursor.seal_block_hash;
        index.pqPaymentAuditReceiptCursorLogicalId = payment_state.cursor.audit_logical_id;
        index.pqPaymentAuditReceiptCursorWitnessId = payment_state.cursor.audit_witness_id;
        index.pqPaymentAuditReceiptStateHash = payment_state.cumulative_hash;
        index.pqPaymentProbationStateHash = probation_hash;
    }

    llmq::pq::PaymentAuditReceipt PrepareAudit(
        std::size_t ordinal, const llmq::pq::PaymentAuditEpochSchedule& epoch)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        using namespace llmq::pq;
        auto& audit{audits[ordinal]};
        audit = MakePaymentAuditCandidate(epoch.epoch, 0x07, 1'240'000 + ordinal);
        auto& commitment{audit.statement.commitment};
        auto& seal{audit.statement.seal_statement};
        const auto beacon{SubjectBeacon(epoch.epoch)};
        const auto base{EpochBaseHeight(config.chainlock_schedule, epoch.epoch)};
        const auto snapshot_height{RegistrationCutoffHeight(config.chainlock_schedule, epoch.epoch,
                                                           quorum_config.roster_snapshot_lag_blocks)};
        BOOST_REQUIRE(base && snapshot_height);
        const auto snapshot{Snapshot(*chain[*snapshot_height])};
        QuorumBuildError build_error{QuorumBuildError::NONE};
        const auto subject{BuildFrozenQuorumRoster(genesis, quorum_config, epoch.epoch,
            chain[*base]->GetBlockHash(), beacon, snapshot.deterministic_mns,
            *snapshot.operator_key_states, &build_error, chain[*snapshot_height])};
        BOOST_REQUIRE_MESSAGE(subject, static_cast<int>(build_error));
        commitment.subject_quorum_base_hash = subject->descriptor.base_hash;
        commitment.subject_descriptor_hash = GetPaymentAuditDescriptorHash(genesis, subject->descriptor);
        commitment.subject_valid_members = subject->descriptor.valid_members;
        const auto anchor_receipt{MakeBTCCReceipt(epoch.anchor_height)};
        const auto seed_point{PaymentAuditSeedPointFromBTCCReceipt(anchor_receipt)};
        BOOST_REQUIRE(seed_point);
        commitment.seed.anchor = *seed_point;
        const PaymentAuditScheduleConfig schedule{config.chainlock_schedule, config.btcc_schedule};
        const auto round{SelectPaymentAuditRound(schedule, epoch, genesis,
            commitment.subject_descriptor_hash, commitment.seed)};
        BOOST_REQUIRE(round);
        commitment.selected_row = round->selected_row;
        commitment.response_height = round->response_height;
        commitment.deadline_height = round->deadline_height;
        commitment.seal_height = round->seal_height;
        commitment.previous_probation_state_hash = probation_hash;
        seal.height = epoch.seal_height;
        seal.block_hash = chain[seal.height]->GetBlockHash();
        seal.previous_chainlock_height = seal.height - PQ_CL_PERIOD;
        seal.previous_chainlock_hash = chain[seal.previous_chainlock_height]->GetBlockHash();
        seal.previous_btcc_cursor = btcc_state.cursor;
        seal.accepted_btcc_cursor = btcc_state.cursor;
        seal.btcc_advance = BTCCAdvance::KEEP;
        seal.btcc_receipt_state = btcc_state;
        seal.payment_audit_receipt_state = payment_state;
        seal.payment_probation_state_hash = probation_hash;
        seal.roster_authorization_base = {seal.previous_chainlock_height,
            seal.previous_chainlock_hash, NonNullHash(1'241'000 + ordinal)};
        if (signed_terminal && ordinal + 1 == audits.size()) {
            // The near-tip ingress case must reach the real missing-seal
            // graph using the branch's selected ordinary base identity.
            const auto selected{Access::SelectedObjectiveRosterBase(*handler, *chain[seal.height])};
            BOOST_REQUIRE(selected);
            seal.roster_authorization_base = *selected;
            SignTerminalAudit(audit);
            if (invalid_terminal_signature) {
                // Commit the corrupted witness ID into the carrier below,
                // so rejection cannot be explained by a mismatching ID.
                audit.report_witnesses.front().authenticated_signature.signature[0] ^= 1;
            }
        }
        BOOST_REQUIRE(audit.IsStructurallyValid());
        const auto classification{ClassifyPaymentAuditReports(audit)};
        BOOST_REQUIRE(classification);
        auto& receipt{receipts[ordinal]};
        receipt.has_audit = 1;
        receipt.epoch = epoch.epoch;
        receipt.seal_height = seal.height;
        receipt.seal_block_hash = seal.block_hash;
        receipt.carrier_height = epoch.carrier_start_height;
        receipt.audit_logical_id = audit.GetLogicalId(genesis);
        receipt.audit_witness_id = audit.GetWitnessId(genesis);
        receipt.commitment_hash = GetPaymentAuditCommitmentHash(genesis, commitment);
        receipt.result_hash = GetPaymentAuditResultHash(genesis, audit, *classification);
        receipt.subject_roster_beacon = beacon;
        receipt.online_members = classification->online_members;
        auto& parent{*chain[receipt.carrier_height - 1]};
        const auto parent_snapshot{Snapshot(parent)};
        BOOST_REQUIRE(deterministicMNManager->m_evoDb->WriteThrough(
            parent.GetBlockHash(), parent_snapshot.deterministic_mns, false));
        PQPaymentProbationTransitionContext context;
        context.receipt = {receipt.epoch, receipt.carrier_height, receipt.result_hash};
        context.roster_valid_members = subject->descriptor.valid_members;
        context.observed_members = receipt.online_members;
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            context.frozen_roster[member] = subject->members[member].pro_tx_hash;
        }
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        auto outcome{deterministicMNManager->ApplyPaymentProbationTransition(parent, context)};
        BOOST_REQUIRE(outcome.status == PQPaymentProbationTransitionStatus::READY);
        BOOST_REQUIRE(outcome.transition);
        receipt.next_probation_state_hash = outcome.transition->Result().StateHash();
        BOOST_REQUIRE(receipt.next_probation_state_hash != probation_hash);
        BOOST_REQUIRE(deterministicMNManager->CommitPaymentProbationTransition(*outcome.transition, false));
        BOOST_REQUIRE(receipt.IsStructurallyValid());
        return receipt;
    }

    void ReopenHandler()
    {
        SyncWithValidationInterfaceQueue();
        llmq::chainLocksHandler = previous_handler;
        handler.reset();
        CreateHandler();
        InstallRosterCache();
        llmq::chainLocksHandler = handler.get();
        BOOST_REQUIRE(Access::Persistence(*handler).LoadPaymentAuditPresealState() == markers);
        BOOST_REQUIRE(!Access::Persistence(*handler).HasBest());
        LatchMiningReady();
    }

    void Admit(std::size_t ordinal)
    {
        // This capability models already-completed archive signature checks.
        BOOST_REQUIRE(Access::AuditStore(*handler).AcceptVerified(
            Access::VerifiedPaymentAudit(audits[ordinal]),
            /*required_witness=*/true) == llmq::pq::PaymentAuditStoreResult::ACCEPTED);
        LOCK(::cs_main);
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        llmq::VerifiedPaymentAuditReceiptTransitionPtr transition;
        BOOST_REQUIRE(handler->CheckPaymentAuditReceiptCertificate(
            receipts[ordinal], *chain[CARRIERS[ordinal]], transition) == Status::VERIFIED);
        const auto* applied{llmq::GetVerifiedPaymentAuditReceiptTransition(transition)};
        BOOST_REQUIRE(applied);
        BOOST_CHECK(applied->Result().StateHash() == receipts[ordinal].next_probation_state_hash);
    }

    void Replay()
    {
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        Access::ReplayPaymentPreseal(*handler);
    }

    void LatchMiningReady()
    {
        static_cast<TestChainstateManager&>(*m_node.chainman).ResetIbd(PQHistoryAuthState::READY);
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
    }

    void CheckAssemblerGate(bool allowed)
    {
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        BOOST_REQUIRE(!m_node.chainman->HasPendingNEVMStartupPair());
        const auto requests{engine->template_requests};
        // This fixture starts after historical connection, without replaying
        // the UTXO set. A distinct fetch error proves the real assembler gate
        // opens without treating that boundary as a fresh-block validity test.
        BOOST_CHECK_EXCEPTION(
            (node::BlockAssembler{m_node.chainman->ActiveChainstate(), nullptr}
                 .CreateNewBlock(CScript{} << OP_TRUE)),
            std::runtime_error, [allowed](const std::runtime_error& error) {
                return std::string{error.what()} == (allowed
                    ? "Could not fetch NEVM block late-payment-preseal-template-probe"
                    : "NEVM block production is waiting for execution recovery");
            });
        BOOST_CHECK_EQUAL(engine->template_requests, requests + (allowed ? 1 : 0));
    }

    void CheckBlocked(std::size_t applied = 0)
    {
        {
            LOCK(::cs_main);
            BOOST_CHECK(handler->HasNEVMReplayObligation());
            BOOST_CHECK(handler->IsPaymentAuditPresealActive());
            BOOST_CHECK(!m_node.chainman->IsNEVMBlockProductionAllowed());
            BOOST_CHECK(Access::Persistence(*handler).LoadPaymentAuditPresealState() == markers);
            BOOST_CHECK_EQUAL(engine->count, applied);
            BOOST_REQUIRE_LE(applied, replay_hashes.size());
            BOOST_CHECK(engine->connected == std::vector<uint256>(
                replay_hashes.begin(), replay_hashes.begin() + applied));
        }
        CheckAssemblerGate(false);
    }

    void ReplayUntilMissing(std::size_t ordinal)
    {
        for (std::size_t attempt{0}; attempt < 32; ++attempt) {
            if (Access::PaymentReplayValidatedHeight(*handler) == CARRIERS[ordinal] - 1 &&
                Access::PaymentReplayDependency(*handler) == receipts.back()) break;
            Replay();
        }
        // The newest terminal proof owns downloads while local evidence may
        // independently advance the sequential verification frontier.
        BOOST_REQUIRE(Access::PaymentReplayDependency(*handler) == receipts.back());
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), CARRIERS[ordinal] - 1);
        CheckBlocked();
    }

    void AdmitAll()
    {
        for (std::size_t ordinal{0}; ordinal < audits.size(); ++ordinal) Admit(ordinal);
    }

    void CheckCompleted()
    {
        {
            LOCK(::cs_main);
            BOOST_CHECK(!handler->HasNEVMReplayObligation());
            BOOST_CHECK(!handler->IsPaymentAuditPresealActive());
            BOOST_CHECK(m_node.chainman->IsNEVMBlockProductionAllowed());
            BOOST_CHECK(Access::Persistence(*handler).LoadPaymentAuditPresealState().IsEmpty());
            BOOST_CHECK(!Access::Store(*handler)->GetBest());
            BOOST_CHECK(!Access::AuditStore(*handler).GetPruneCheckpoint());
            BOOST_CHECK_EQUAL(engine->count, replay_hashes.size());
            BOOST_CHECK(engine->hash == chain.back()->GetBlockHash());
            BOOST_CHECK(engine->connected == replay_hashes);
        }
        CheckAssemblerGate(true);
    }

    void CompleteReplay()
    {
        for (std::size_t attempt{0}; attempt < 32 && handler->HasNEVMReplayObligation(); ++attempt) Replay();
        CheckCompleted();
    }

    void CheckReplayRetention(int expected)
    {
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        // A maximum request cannot raise the lower-only replay floor.
        BOOST_CHECK_EQUAL(deterministicMNManager->UpdateReplaySnapshotRetentionFloor(
            std::numeric_limits<int32_t>::max()), expected);
    }

    void CheckLateEvidence()
    {
        ReopenHandler();
        const auto first_roster{llmq::pq::RegistrationCutoffHeight(
            config.chainlock_schedule, 0, quorum_config.roster_snapshot_lag_blocks)};
        const auto audit_roster{llmq::pq::RegistrationCutoffHeight(
            config.chainlock_schedule, receipts.front().epoch,
            quorum_config.roster_snapshot_lag_blocks)};
        BOOST_REQUIRE(first_roster && audit_roster);
        BOOST_REQUIRE_EQUAL(*first_roster, 1'152);
        BOOST_REQUIRE_GT(*audit_roster, *first_roster);
        CheckReplayRetention(*first_roster);
        CheckBlocked();
        ReplayUntilMissing(0);
        Admit(0);
        ReplayUntilMissing(1);
        Admit(1);
        ReplayUntilMissing(2);
        CheckReplayRetention(*first_roster);
        Admit(2);
        CompleteReplay();
        CheckReplayRetention(std::numeric_limits<int>::max());
    }

    void CheckWrongBranchEvidence()
    {
        auto wrong_branch{audits.back()};
        wrong_branch.statement.seal_statement.block_hash = NonNullHash(1'250'001);
        BOOST_REQUIRE(wrong_branch.IsStructurallyValid());
        BOOST_REQUIRE(wrong_branch.GetWitnessId(genesis) != receipts.back().audit_witness_id);
        BOOST_REQUIRE(Access::AuditStore(*handler).AcceptVerified(
            Access::VerifiedPaymentAudit(wrong_branch)) == llmq::pq::PaymentAuditStoreResult::ACCEPTED);
        Admit(0);
        Admit(1);
        {
            LOCK(::cs_main);
            ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
            llmq::VerifiedPaymentAuditReceiptTransitionPtr transition;
            BOOST_CHECK(handler->CheckPaymentAuditReceiptCertificate(
                receipts.back(), *chain[CARRIERS.back()], transition) == Status::MISSING);
            BOOST_CHECK(!transition);
        }
        ReplayUntilMissing(2);
        // The exact old witness bypasses the unrelated live candidate slot.
        Admit(2);
        CompleteReplay();
    }

    void CheckCoveredPrefix(bool ordinary_seal)
    {
        using namespace llmq::pq;
        ReopenHandler();
        for (const auto& receipt : receipts) {
            BOOST_REQUIRE(!handler->AlreadyHavePaymentAudit(receipt.audit_witness_id));
        }
        if (ordinary_seal) {
            const auto& statement{audits.back().statement.seal_statement};
            auto certificate{MakeCatchupChainLock(statement.height,
                statement.previous_chainlock_height, statement.previous_chainlock_hash, 1'250'006)};
            certificate.statement = statement;
            BOOST_REQUIRE(certificate.IsStructurallyValid());
            // Model the verified import boundary with a matching typed
            // context. Signature verification is supplied at that boundary.
            const auto context{ChainLockStoreTestContextFactory::CreateTrustedPersistence(
                genesis, config.chainlock_schedule, statement)};
            BOOST_REQUIRE(context);
            ChainLockFinalityError error{ChainLockFinalityError::NONE};
            BOOST_REQUIRE(Access::Store(*handler)->AcceptPersistedRosterAuthorizationBase(
                certificate, /*signatures_valid=*/true, context, &error));
            BOOST_REQUIRE(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBasesForTarget(
                statement.height, statement.block_hash).empty());
            BOOST_CHECK(!Access::Store(*handler)->GetBest());
            // The ordinary seal covers audits 0 and 1, but not its later
            // terminal receipt. That last exact witness remains necessary.
            ReplayUntilMissing(2);
        }
        Admit(2);
        engine->flush_available = false;
        Replay();
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), TIP_HEIGHT);
        BOOST_REQUIRE_LT(FIRST_CARRIER, audits.back().statement.seal_statement.height);
        BOOST_CHECK(Access::PaymentReplayAuthenticated(*handler, *chain[FIRST_CARRIER]));
        CheckBlocked();
        for (std::size_t ordinal{0}; ordinal < 2; ++ordinal) {
            BOOST_CHECK(!handler->AlreadyHavePaymentAudit(receipts[ordinal].audit_witness_id));
        }
        engine->flush_available = true;
        CompleteReplay();
        for (std::size_t ordinal{0}; ordinal < 2; ++ordinal) {
            BOOST_CHECK(!handler->AlreadyHavePaymentAudit(receipts[ordinal].audit_witness_id));
        }
    }

    void CheckNoHistoricalOrdinaryAuthority()
    {
        BOOST_CHECK(Access::Persistence(*handler).LoadAuthorizationBases().empty());
        BOOST_CHECK(!Access::Persistence(*handler).HasBest());
        BOOST_CHECK(!Access::Persistence(*handler).LoadPaymentAuditSealContext());
        BOOST_CHECK_EQUAL(Access::Store(*handler)->AuthorizationBaseSizeForTesting(), 0U);
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(
            audits.back().statement.seal_statement.roster_authorization_base));
        BOOST_CHECK(Access::Store(*handler)->GetVerifiedRosterAuthorizationBasesForTarget(
            receipts.back().seal_height, receipts.back().seal_block_hash).empty());
        BOOST_CHECK(!Access::Store(*handler)->GetBest());
        BOOST_CHECK(!Access::AuditStore(*handler).GetPruneCheckpoint());
    }

    void CheckNoHistoricalArchives()
    {
        for (const auto& receipt : receipts) {
            BOOST_CHECK(!Access::AuditStore(*handler).Get(receipt.audit_witness_id));
        }
        CheckNoHistoricalOrdinaryAuthority();
    }

    auto RequestHistoricalReplay()
    {
        ReplayUntilMissing(0);
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(m_node.chainman->IsBaseBlockSyncComplete());
            handler->NotePendingPaymentAuditReceiptCertificate(
                receipts.back(), *chain[CARRIERS.back()]);
        }
        const auto context{Access::PaymentAuditHistoricalContext(
            *handler, receipts.back().audit_witness_id)};
        BOOST_REQUIRE(context);
        return *context;
    }

    auto HistoricalTransition() const
    {
        return Access::HistoricalPaymentAuditTransition(
            *handler, receipts.back(), *chain[CARRIERS.back()]);
    }

    void CheckHistoricalSignedReplay() EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        BOOST_REQUIRE(signed_terminal);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        AuditPeer peer{m_node};
        peer.Handshake();
        engine->flush_available = false;
        auto context{RequestHistoricalReplay()};
        CheckNoHistoricalArchives();
        std::optional<Access::PaymentAuditSealRequest> stalled;
        {
            auto& active{m_node.chainman->ActiveChainstate()};
            struct RestoreTip {
                Chainstate& active;
                CBlockIndex& tip;
                ~RestoreTip() { LOCK(::cs_main); active.m_chain.SetTip(tip); active.CoinsTip().SetBestBlock(tip.GetBlockHash()); }
            } restore{active, *chain.back()};
            WITH_LOCK(::cs_main, active.m_chain.SetTip(*chain[TIP_HEIGHT]);
                active.CoinsTip().SetBestBlock(chain[TIP_HEIGHT]->GetBlockHash()));
            // At tip 3407 the independently selected E is 3395, below the
            // exact terminal receipt at 3405. Its seal alone cannot open E.
            BOOST_CHECK(!Access::TryHistoricalPaymentAudit(*handler, audits.back(), context).has_value());
            BOOST_CHECK(!HistoricalTransition());
            Access::RequestPaymentAuditDependency(*handler);
            BOOST_REQUIRE_GT(Access::PaymentAuditLastRequest(*handler).count(), 0);
            peer.Request(receipts.back().audit_witness_id);
            peer.Deliver(audits.back());
            stalled = Access::PaymentAuditSealRequestState(*handler);
            BOOST_REQUIRE(stalled);
            BOOST_CHECK(Access::HasNeededPaymentAuditSeal(*handler));
            BOOST_CHECK(!HistoricalTransition());
            peer.connman.FlushSendBuffer(*peer.node);
            Access::RequestPaymentAuditDependency(*handler);
            BOOST_CHECK(Access::PaymentAuditSealRequestState(*handler) == stalled);
            BOOST_CHECK_EQUAL(peer.Queued(NetMsgType::GETPQPOSE), 0U);
        }
        // Only the null tail advanced. The actual scheduler must relinquish
        // this exact ordinary-seal graph and request the audit once it is deep.
        Access::RequestPaymentAuditDependency(*handler);
        BOOST_CHECK(!Access::HasPendingPaymentAuditSeal(*handler));
        BOOST_CHECK(!Access::HasNeededPaymentAuditSeal(*handler));
        BOOST_CHECK_EQUAL(peer.Queued(NetMsgType::GETPQPOSE), 1U);
        const auto retry_time{Access::PaymentAuditLastRequest(*handler)};
        Access::RequestPaymentAuditDependency(*handler);
        BOOST_CHECK(Access::PaymentAuditLastRequest(*handler) == retry_time);
        BOOST_CHECK_EQUAL(peer.Queued(NetMsgType::GETPQPOSE), 1U);
        SetMockTime(GetTime<std::chrono::seconds>() +
            ChainLockRequestTracker::SOURCE_FAILURE_COOLDOWN + std::chrono::seconds{1});
        auto wrong_branch{audits.back()};
        wrong_branch.statement.seal_statement.block_hash = NonNullHash(1'250'101);
        BOOST_CHECK(!Access::TryHistoricalPaymentAudit(*handler, wrong_branch, context).value_or(false));
        BOOST_CHECK(!HistoricalTransition());
        ++markers.active->revision;
        Access::SetReplayMarkers(*handler, {}, markers);
        BOOST_CHECK(!Access::TryHistoricalPaymentAudit(*handler, audits.back(), context).value_or(false));
        context = RequestHistoricalReplay();
        peer.Request(receipts.back().audit_witness_id);
        peer.Deliver(audits.back());
        const auto proof{HistoricalTransition()};
        BOOST_REQUIRE(proof);
        const auto* transition{llmq::GetVerifiedPaymentAuditReceiptTransition(proof)};
        BOOST_REQUIRE(transition);
        BOOST_CHECK(transition->Result().StateHash() == receipts.back().next_probation_state_hash);
        BOOST_CHECK(Access::HasPendingPaymentAuditReceipt(*handler));
        CheckNoHistoricalArchives();
        Replay();
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), tip_height);
        BOOST_CHECK(Access::PaymentReplayAuthenticated(*handler, *chain[FIRST_CARRIER]));
        CheckBlocked();

        // The signed capability is deliberately absent from every durable
        // archive. Restart must discover and verify the terminal proof again.
        ReopenHandler();
        BOOST_CHECK(!HistoricalTransition());
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), -1);
        CheckNoHistoricalArchives();
        context = RequestHistoricalReplay();
        peer.Request(receipts.back().audit_witness_id);
        peer.Deliver(audits.back());
        const auto held_proof{HistoricalTransition()};
        BOOST_REQUIRE(held_proof);
        Replay();
        BOOST_REQUIRE_EQUAL(Access::PaymentReplayValidatedHeight(*handler), tip_height);
        bool source_changed{false};
        engine->on_query = [&] {
            source_changed = true;
            ++markers.active->revision;
            Access::SetReplayMarkers(*handler, {}, markers);
        };
        engine->flush_available = true;
        Replay();
        BOOST_REQUIRE(source_changed);
        BOOST_CHECK(!HistoricalTransition());
        BOOST_CHECK(!Access::PaymentReplayAuthenticated(*handler, *chain[FIRST_CARRIER]));
        Replay();
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), FIRST_CARRIER - 1);
        CheckBlocked();
        context = RequestHistoricalReplay();
        peer.Request(receipts.back().audit_witness_id);
        peer.Deliver(audits.back());
        BOOST_REQUIRE(HistoricalTransition());
        engine->reported_hash = NonNullHash(1'250'102);
        Replay();
        CheckBlocked();
        engine->reported_hash.reset();
        engine->wrong_final_tip = true;
        for (std::size_t attempt{0}; attempt < 32 && engine->count < replay_hashes.size(); ++attempt) Replay();
        BOOST_REQUIRE_EQUAL(engine->count, replay_hashes.size());
        CheckBlocked(replay_hashes.size());
        engine->wrong_final_tip = false;
        CompleteReplay();
        CheckNoHistoricalArchives();
    }

    void CheckHistoricalInvalidSignature() EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        BOOST_REQUIRE(signed_terminal && invalid_terminal_signature);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        AuditPeer peer{m_node};
        peer.Handshake();
        const auto context{RequestHistoricalReplay()};
        BOOST_REQUIRE(audits.back().IsStructurallyValid());
        BOOST_REQUIRE(audits.back().GetWitnessId(genesis) == receipts.back().audit_witness_id);
        const auto attempted{Access::TryHistoricalPaymentAudit(*handler, audits.back(), context)};
        BOOST_REQUIRE(attempted.has_value());
        BOOST_CHECK(!*attempted);
        peer.Request(receipts.back().audit_witness_id);
        peer.Deliver(audits.back());
        BOOST_CHECK(!HistoricalTransition());
        BOOST_CHECK(!Access::HasPendingPaymentAuditSeal(*handler));
        CheckNoHistoricalArchives();
        CheckBlocked();
    }

    void CheckHistoricalIngressBeforeArchiveDuplicate() EXCLUSIVE_LOCKS_REQUIRED(!::cs_main)
    {
        BOOST_REQUIRE(signed_terminal && !invalid_terminal_signature);
        LOCK(NetEventsInterface::g_msgproc_mutex);
        ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
        AuditPeer peer{m_node};
        peer.Handshake();
        (void)RequestHistoricalReplay();
        peer.Request(receipts.back().audit_witness_id);
        // Model an already-verified ordinary archive appearing while the
        // exact response is in flight. Duplicate accounting must not bypass
        // creation of the separately needed replay capability.
        BOOST_REQUIRE(Access::AuditStore(*handler).AcceptVerified(
            Access::VerifiedPaymentAudit(audits.back()), /*required_witness=*/true) ==
            llmq::pq::PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(!HistoricalTransition());
        peer.Deliver(audits.back());
        BOOST_REQUIRE(HistoricalTransition());
        BOOST_REQUIRE(Access::AuditStore(*handler).Get(receipts.back().audit_witness_id));
        CheckNoHistoricalOrdinaryAuthority();
    }

    void CheckIntermediateRoots()
    {
        AdmitAll();
        const int32_t corrupted_height{audits.back().statement.seal_statement.height + 1};
        for (const bool probation : {false, true}) {
            BOOST_TEST_CONTEXT("probation=" << probation) {
                auto& index{*chain[corrupted_height]};
                uint256* const target{WITH_LOCK(::cs_main, return probation
                    ? &index.pqPaymentProbationStateHash : &index.pqPaymentAuditReceiptStateHash)};
                uint256& field{*target};
                struct Restore {
                    uint256& field;
                    const uint256 saved;
                    ~Restore() { LOCK(::cs_main); field = saved; }
                } restore{field, WITH_LOCK(::cs_main, return field)};
                WITH_LOCK(::cs_main, field = NonNullHash(1'250'002));
                for (std::size_t attempt{0}; attempt < 8; ++attempt) Replay();
                BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), corrupted_height - 1);
                CheckBlocked();
            }
        }
        CompleteReplay();
    }

    void CheckRestartRescansEarlierProof()
    {
        Admit(0);
        Admit(1);
        engine->flush_available = false;
        Replay();
        BOOST_REQUIRE_GE(Access::PaymentReplayValidatedHeight(*handler), FIRST_CARRIER);
        BOOST_REQUIRE_LT(Access::PaymentReplayValidatedHeight(*handler), CARRIERS[1]);
        CheckBlocked();
        ReopenHandler();
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), -1);
        InstallRosterCache(false);
        const auto lookups{roster_lookups};
        for (std::size_t attempt{0}; attempt < 8; ++attempt) Replay();
        BOOST_CHECK_GT(roster_lookups, lookups);
        BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), FIRST_CARRIER - 1);
        BOOST_CHECK(Access::PaymentReplayDependency(*handler) == receipts.back());
        CheckBlocked();
        InstallRosterCache();
        engine->flush_available = true;
        Admit(2);
        CompleteReplay();
    }

    void CheckSourceChangesBeforeSend(bool revise_marker)
    {
        AdmitAll();
        bool changed{false};
        engine->on_query = [&] {
            BOOST_REQUIRE_EQUAL(engine->count, 0U);
            changed = true;
            if (revise_marker) {
                BOOST_REQUIRE(markers.active);
                ++markers.active->revision;
                Access::SetReplayMarkers(*handler, {}, markers);
            } else {
                InstallRosterCache(false);
            }
        };
        for (std::size_t attempt{0}; attempt < 32 && !changed; ++attempt) Replay();
        BOOST_REQUIRE(changed);
        CheckBlocked();
        if (!revise_marker) {
            const auto lookups{roster_lookups};
            for (std::size_t attempt{0}; attempt < 8; ++attempt) Replay();
            BOOST_CHECK_GT(roster_lookups, lookups);
            BOOST_CHECK_EQUAL(Access::PaymentReplayValidatedHeight(*handler), FIRST_CARRIER - 1);
            CheckBlocked();
            InstallRosterCache();
        }
        CompleteReplay();
    }

    void CheckEngineFailures()
    {
        AdmitAll();
        engine->flush_available = false;
        for (std::size_t attempt{0}; attempt < 32 && engine->flushes == 0; ++attempt) Replay();
        BOOST_REQUIRE_GT(engine->flushes, 0U);
        CheckBlocked();
        engine->flush_available = true;
        engine->reported_hash = NonNullHash(1'250'003);
        const auto queries{engine->queries};
        Replay();
        BOOST_CHECK_GT(engine->queries, queries);
        CheckBlocked();
        engine->reported_hash.reset();
        engine->wrong_final_tip = true;
        for (std::size_t attempt{0}; attempt < 32 && engine->count < replay_hashes.size(); ++attempt) Replay();
        BOOST_REQUIRE_EQUAL(engine->count, replay_hashes.size());
        CheckBlocked(replay_hashes.size());
        engine->wrong_final_tip = false;
        CompleteReplay();
    }

    void CheckMissingBaseRequestGraph()
    {
        using namespace llmq::pq;
        Admit(0);
        Admit(1);
        ReplayUntilMissing(2);
        auto seal{audits.back().statement.seal_statement};
        auto ancestor{seal};
        ancestor.height = seal.height - PQ_CL_PERIOD;
        auto& target{*chain[ancestor.height]};
        const auto selected_parent{Access::SelectedObjectiveRosterBase(*handler, target)};
        BOOST_REQUIRE(selected_parent);
        BOOST_REQUIRE_LT(selected_parent->height, ancestor.height);
        {
            LOCK(::cs_main);
            ancestor.block_hash = target.GetBlockHash();
            ancestor.previous_chainlock_height = ancestor.height - PQ_CL_PERIOD;
            ancestor.previous_chainlock_hash = chain[ancestor.previous_chainlock_height]->GetBlockHash();
            ancestor.btcc_receipt_state = BTCCReceiptState{
                {target.pqBTCCReceiptCursorHeight, target.pqBTCCReceiptCursorSysHash,
                 target.pqBTCCReceiptCursorBTCHash},
                target.pqBTCCReceiptStateHash, target.pqBTCCReceiptLatestTargetHeight,
                target.pqBTCCReceiptLatestCarrierHeight};
            ancestor.previous_btcc_cursor = ancestor.accepted_btcc_cursor = ancestor.btcc_receipt_state.cursor;
            ancestor.btcc_advance = BTCCAdvance::KEEP;
            ancestor.payment_audit_receipt_state = PaymentAuditReceiptState{
                {target.pqPaymentAuditReceiptCursorHeight, target.pqPaymentAuditReceiptCursorEpoch,
                 target.pqPaymentAuditReceiptCursorSealHash, target.pqPaymentAuditReceiptCursorLogicalId,
                 target.pqPaymentAuditReceiptCursorWitnessId}, target.pqPaymentAuditReceiptStateHash};
            ancestor.payment_probation_state_hash = target.pqPaymentProbationStateHash;
            ancestor.roster_authorization_base = *selected_parent;
            handler->NotePendingPaymentAuditReceiptCertificate(receipts.back(), *chain[CARRIERS.back()]);
        }
        BOOST_REQUIRE(ancestor.IsStructurallyValid());
        const RosterAuthorizationBaseIdentity objective{
            ancestor.height, ancestor.block_hash, GetLogicalChainLockId(genesis, ancestor)};
        seal.roster_authorization_base = objective;
        BOOST_REQUIRE(seal.IsStructurallyValid());
        // These statements exercise request metadata. They never receive a
        // signature-verification capability or ordinary store admission.
        BOOST_REQUIRE(Access::StagePaymentAuditSealDependency(*handler, seal, objective));
        const auto first{Access::PaymentAuditSealRequestState(*handler)};
        const auto first_capability{Access::PaymentAuditSealCapability(*handler, objective.logical_id)};
        BOOST_REQUIRE(first);
        BOOST_REQUIRE(Access::HasPaymentAuditSealCapability(first_capability));
        BOOST_CHECK(first->target == objective);
        BOOST_CHECK_EQUAL(first->revision, 0U);
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(objective));
        BOOST_CHECK(!Access::HasPaymentAuditSealCapability(Access::PaymentAuditSealCapability(
            *handler, GetLogicalChainLockId(genesis, seal))));
        BOOST_CHECK(Access::StagePaymentAuditSealDependency(*handler, seal, objective));
        BOOST_CHECK(Access::PaymentAuditSealRequestState(*handler) == first);

        std::size_t authorized_callbacks{0};
        ChainLockFinalityError source_error{ChainLockFinalityError::NONE};
        BOOST_CHECK(Access::AuthorizePaymentAuditSealPersistence(*handler, first_capability,
            [&] { ++authorized_callbacks; return true; }, &source_error));
        BOOST_CHECK_EQUAL(authorized_callbacks, 1U);
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(objective));

        std::optional<RosterAuthorizationBaseIdentity> missing;
        {
            ActiveDIP active_dip{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())};
            BOOST_CHECK(!Access::BuildPaymentAuditSealVerificationContext(
                *handler, first_capability, ancestor, missing));
        }
        BOOST_REQUIRE(missing == selected_parent);
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(*missing));
        auto wrong_branch{*missing};
        wrong_branch.block_hash = NonNullHash(1'250'004);
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, first_capability, wrong_branch));
        auto wrong_logical{*missing};
        wrong_logical.logical_id = NonNullHash(1'250'005);
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, first_capability, wrong_logical));
        BOOST_CHECK(Access::PaymentAuditSealRequestState(*handler) == first);
        BOOST_REQUIRE(Access::AdvancePaymentAuditSealDependency(*handler, first_capability, *missing));
        const auto second{Access::PaymentAuditSealRequestState(*handler)};
        const auto second_capability{Access::PaymentAuditSealCapability(*handler, missing->logical_id)};
        BOOST_REQUIRE(second);
        BOOST_REQUIRE(Access::HasPaymentAuditSealCapability(second_capability));
        BOOST_CHECK(second->target == *missing);
        BOOST_CHECK_EQUAL(second->revision, first->revision + 1);
        BOOST_CHECK(second->source_token != first->source_token);
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, first_capability, *missing));
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, second_capability, objective));
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, second_capability, *missing));
        BOOST_CHECK(Access::PaymentAuditSealRequestState(*handler) == second);

        // A completion notification cannot manufacture ordinary authority.
        // With the original base still absent, the graph requests it again.
        Access::CompletePaymentAuditSealFetch(*handler, second_capability);
        const auto third{Access::PaymentAuditSealRequestState(*handler)};
        BOOST_REQUIRE(third);
        BOOST_CHECK(third->target == objective);
        BOOST_CHECK_EQUAL(third->revision, second->revision + 1);
        BOOST_CHECK(third->source_token != first->source_token);
        BOOST_CHECK(third->source_token != second->source_token);
        std::size_t stale_writes{0};
        ChainLockFinalityError error{ChainLockFinalityError::NONE};
        BOOST_CHECK(!Access::AuthorizePaymentAuditSealPersistence(*handler, first_capability,
            [&] { ++stale_writes; return true; }, &error));
        BOOST_CHECK_EQUAL(stale_writes, 0U);
        BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(objective));
        BOOST_CHECK(!Access::Store(*handler)->GetBest());

        const auto current_capability{Access::PaymentAuditSealCapability(*handler, objective.logical_id)};
        BOOST_REQUIRE(Access::HasPaymentAuditSealCapability(current_capability));
        ++markers.active->revision;
        Access::SetReplayMarkers(*handler, {}, markers);
        BOOST_CHECK(!Access::AdvancePaymentAuditSealDependency(*handler, current_capability, *missing));
        BOOST_CHECK(!Access::AuthorizePaymentAuditSealPersistence(*handler, current_capability,
            [&] { ++stale_writes; return true; }, &error));
        BOOST_CHECK_EQUAL(stale_writes, 0U);
        BOOST_CHECK(Access::PaymentAuditSealRequestState(*handler) == third);
        CheckBlocked();
    }
};

struct SignedLatePaymentAuditPresealSetup : LatePaymentAuditPresealSetup {
    SignedLatePaymentAuditPresealSetup() : LatePaymentAuditPresealSetup{true} {}
};

struct InvalidSignedLatePaymentAuditPresealSetup : LatePaymentAuditPresealSetup {
    InvalidSignedLatePaymentAuditPresealSetup() : LatePaymentAuditPresealSetup{true, true} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_handler_tests, BasicTestingSetup)

BOOST_FIXTURE_TEST_CASE(payment_preseal_late_terminal_archive_replays_without_new_finality,
                        LatePaymentAuditPresealSetup)
{
    CheckLateEvidence();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_wrong_branch_terminal_archive_cannot_authorize_replay,
                        LatePaymentAuditPresealSetup)
{
    CheckWrongBranchEvidence();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_terminal_archive_skips_pruned_audit_prefix,
                        LatePaymentAuditPresealSetup)
{
    CheckCoveredPrefix(/*ordinary_seal=*/false);
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_ordinary_terminal_seal_skips_pruned_audit_prefix,
                        LatePaymentAuditPresealSetup)
{
    CheckCoveredPrefix(/*ordinary_seal=*/true);
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_signed_historical_terminal_replays_without_ordinary_archives,
                        SignedLatePaymentAuditPresealSetup)
{
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(m_node.chainman->IsBaseBlockSyncComplete());
    }
    CheckHistoricalSignedReplay();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_historical_terminal_rejects_matching_invalid_signature,
                        InvalidSignedLatePaymentAuditPresealSetup)
{
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(m_node.chainman->IsBaseBlockSyncComplete());
    }
    CheckHistoricalInvalidSignature();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_historical_ingress_precedes_ordinary_archive_duplicate,
                        SignedLatePaymentAuditPresealSetup)
{
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(m_node.chainman->IsBaseBlockSyncComplete());
    }
    CheckHistoricalIngressBeforeArchiveDuplicate();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_tail_indexed_roots_must_match_authenticated_seal,
                        LatePaymentAuditPresealSetup)
{
    CheckIntermediateRoots();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_restart_discards_partial_scan_and_rechecks_earlier_rosters,
                        LatePaymentAuditPresealSetup)
{
    CheckRestartRescansEarlierProof();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_marker_revision_during_engine_query_revokes_replay,
                        LatePaymentAuditPresealSetup)
{
    CheckSourceChangesBeforeSend(/*revise_marker=*/true);
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_roster_replacement_during_engine_query_revokes_replay,
                        LatePaymentAuditPresealSetup)
{
    CheckSourceChangesBeforeSend(/*revise_marker=*/false);
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_engine_failures_preserve_marker_until_exact_tip,
                        LatePaymentAuditPresealSetup)
{
    CheckEngineFailures();
}

BOOST_FIXTURE_TEST_CASE(payment_preseal_missing_base_graph_requires_exact_older_branch_authority,
                        LatePaymentAuditPresealSetup)
{
    CheckMissingBaseRequestGraph();
}

BOOST_FIXTURE_TEST_CASE(nevm_mining_active_btcc_preseal_blocks_before_template_request,
                        PresealMiningSetup)
{
    CheckAssemblerAllowed();
    CheckMiningCachesAllowed();
    const auto marker{BTCCMarker()};
    Access::SetReplayMarkers(*llmq::chainLocksHandler, {marker, std::nullopt}, {});
    CheckDurableMarkers({marker, std::nullopt}, {});
    CheckAssemblerBlocked();
    CheckMiningCachesBlocked();
    BOOST_REQUIRE(Access::ClearReplayMarker(*llmq::chainLocksHandler, marker));
    CheckDurableMarkers({}, {});
    CheckAssemblerAllowed();
    CheckMiningCachesAllowed();
}

BOOST_FIXTURE_TEST_CASE(nevm_mining_active_payment_preseal_blocks_fresh_and_cached_templates,
                        PresealMiningSetup)
{
    CheckAssemblerAllowed();
    CheckMiningCachesAllowed();
    const auto marker{PaymentMarker()};
    Access::SetReplayMarkers(*llmq::chainLocksHandler, {}, {marker, std::nullopt});
    CheckDurableMarkers({}, {marker, std::nullopt});
    CheckAssemblerBlocked();
    CheckMiningCachesBlocked();
    BOOST_REQUIRE(Access::ClearReplayMarker(*llmq::chainLocksHandler, marker));
    CheckDurableMarkers({}, {});
    CheckAssemblerAllowed();
    CheckMiningCachesAllowed();
}

BOOST_FIXTURE_TEST_CASE(nevm_mining_prospective_markers_follow_the_active_branch,
                        PresealMiningSetup)
{
    for (const bool unrelated : {false, true}) {
        for (const bool payment : {false, true}) {
            BOOST_TEST_CONTEXT("unrelated=" << unrelated << ", payment=" << payment) {
                CheckAssemblerAllowed();
                CheckMiningCachesAllowed();
                llmq::pq::BTCCPresealState btcc_state;
                llmq::pq::PaymentAuditPresealState payment_state;
                if (payment) payment_state.prospective = PaymentMarker(unrelated);
                else btcc_state.prospective = BTCCMarker(unrelated);
                Access::SetReplayMarkers(*llmq::chainLocksHandler, btcc_state, payment_state);
                CheckDurableMarkers(btcc_state, payment_state);
                BOOST_REQUIRE(llmq::chainLocksHandler->HasNEVMReplayObligation());
                if (unrelated) {
                    CheckAssemblerAllowed();
                    CheckMiningCachesAllowed();
                } else {
                    CheckAssemblerBlocked();
                    CheckMiningCachesBlocked();
                }
                if (payment) {
                    BOOST_REQUIRE(Access::ClearReplayMarker(
                        *llmq::chainLocksHandler, *payment_state.prospective));
                } else {
                    BOOST_REQUIRE(Access::ClearReplayMarker(
                        *llmq::chainLocksHandler, *btcc_state.prospective));
                }
                CheckDurableMarkers({}, {});
                CheckAssemblerAllowed();
                CheckMiningCachesAllowed();
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(btcc_preseal_terminal_reorg_preserves_single_carrier)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    BTCCPresealRecoveryChain chain;
    chain.ForkAfter(BTCCPresealRecoveryChain::FIRST_CARRIER + 5);
    const auto before{chain.marker};

    LOCK(cs_main);
    const auto recovered{Access::RecoverBTCCPresealMarker(
        chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
        chain.marker, chain.genesis, chain.config)};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK_EQUAL(recovered->terminal_carrier_height, chain.FIRST_CARRIER);
    BOOST_CHECK(recovered->terminal_carrier_hash == before.earliest_carrier_hash);
    BOOST_CHECK(recovered->terminal_receipt == chain.first_receipt);
    BOOST_CHECK(recovered->terminal_parent_receipt_state == before.predecessor_receipt_state);
    BOOST_CHECK_EQUAL(recovered->earliest_carrier_height, before.earliest_carrier_height);
    BOOST_CHECK(recovered->earliest_carrier_hash == before.earliest_carrier_hash);
    BOOST_CHECK(recovered->predecessor_receipt_state == before.predecessor_receipt_state);
    BOOST_CHECK_EQUAL(recovered->revision, before.revision);
    BOOST_CHECK(chain.marker == before);
}

BOOST_AUTO_TEST_CASE(btcc_preseal_terminal_reorg_retains_intermediate_receipt)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    BTCCPresealRecoveryChain chain;
    chain.ForkAfter(BTCCPresealRecoveryChain::MIDDLE_CARRIER + 5);

    LOCK(cs_main);
    const auto recovered{Access::RecoverBTCCPresealMarker(
        chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
        chain.marker, chain.genesis, chain.config)};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK_EQUAL(recovered->terminal_carrier_height, chain.MIDDLE_CARRIER);
    BOOST_CHECK(recovered->terminal_carrier_hash ==
                chain.original.At(chain.MIDDLE_CARRIER).GetBlockHash());
    BOOST_CHECK(recovered->terminal_receipt == chain.middle_receipt);
    BOOST_CHECK(recovered->terminal_parent_receipt_state == chain.first_state);
    BOOST_CHECK_EQUAL(recovered->earliest_carrier_height, chain.FIRST_CARRIER);
    BOOST_CHECK(recovered->predecessor_receipt_state == chain.marker.predecessor_receipt_state);
}

BOOST_AUTO_TEST_CASE(btcc_preseal_terminal_reorg_null_tail_uses_common_prefix)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    BTCCPresealRecoveryChain chain;
    chain.ForkAfter(BTCCPresealRecoveryChain::OLD_TERMINAL - 6);
    auto replacement_receipt{chain.marker.terminal_receipt};
    replacement_receipt.chainlock_logical_id = NonNullHash(987'001);
    const auto replacement_state{llmq::pq::ApplyBTCCReceiptState(
        chain.genesis, chain.config.chainlock_schedule, chain.config.btcc_schedule,
        chain.config.activation_predecessor_height, chain.OLD_TERMINAL,
        chain.replacement.At(chain.OLD_TERMINAL).GetBlockHash(),
        chain.middle_state, replacement_receipt)};
    BOOST_REQUIRE(replacement_state);
    chain.replacement.SetReceiptStateFrom(chain.OLD_TERMINAL, *replacement_state);
    chain.replacement.At(chain.OLD_TERMINAL).pqBTCCReceiptLogicalId =
        replacement_receipt.chainlock_logical_id;

    LOCK(cs_main);
    const auto recovered{Access::RecoverBTCCPresealMarker(
        chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
        chain.marker, chain.genesis, chain.config)};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK_EQUAL(recovered->terminal_carrier_height, chain.MIDDLE_CARRIER);
    BOOST_CHECK(recovered->terminal_receipt == chain.middle_receipt);
    BOOST_CHECK_EQUAL(recovered->earliest_carrier_height, chain.FIRST_CARRIER);
}

BOOST_AUTO_TEST_CASE(btcc_preseal_terminal_reorg_unavailable_index_preserves_marker)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    BTCCPresealRecoveryChain chain;
    const int32_t common_height{chain.MIDDLE_CARRIER + 5};
    chain.ForkAfter(common_height);
    const auto before{chain.marker};

    LOCK(cs_main);
    for (const int32_t height : {chain.FIRST_CARRIER - 1,
                                chain.MIDDLE_CARRIER - 1,
                                chain.MIDDLE_CARRIER, common_height}) {
        for (const uint32_t remove : {uint32_t{BLOCK_PQ_RECEIPT_INDEX_VALIDATED},
                                      uint32_t{BLOCK_VALID_SCRIPTS}}) {
            BOOST_TEST_CONTEXT("height " << height << ", missing status " << remove) {
                auto& index{chain.original.At(height)};
                const auto original_status{index.nStatus};
                index.nStatus &= ~remove;
                BOOST_CHECK(!Access::RecoverBTCCPresealMarker(
                    chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
                    chain.marker, chain.genesis, chain.config));
                BOOST_CHECK(chain.marker == before);
                index.nStatus = original_status;
            }
        }
    }
    auto& common{chain.original.At(common_height)};
    const auto original_state_hash{common.pqBTCCReceiptStateHash};
    common.pqBTCCReceiptStateHash = NonNullHash(987'002);
    BOOST_CHECK(!Access::RecoverBTCCPresealMarker(
        chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
        chain.marker, chain.genesis, chain.config));
    BOOST_CHECK(chain.marker == before);
    common.pqBTCCReceiptStateHash = original_state_hash;
    BOOST_REQUIRE(Access::RecoverBTCCPresealMarker(
        chain.replacement.active, chain.original.At(chain.OLD_TERMINAL),
        chain.marker, chain.genesis, chain.config));
}

BOOST_AUTO_TEST_CASE(historical_selection_keeps_frozen_active_ancestry)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const auto schedule{llmq::pq::MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    LiveSigningIndexChain chain{2'101};
    constexpr int32_t COVERAGE{2'000};
    const auto* selected{Access::HistoricalSelectionTip(
        chain.At(2'010), *schedule, COVERAGE)};
    BOOST_REQUIRE(selected);
    BOOST_CHECK(selected == &chain.At(2'010));
    BOOST_CHECK(Access::HistoricalSelectionTip(
        chain.At(2'100), *schedule, COVERAGE) == selected);
    BOOST_CHECK(Access::HistoricalSelectionTip(
        chain.At(2'100), *schedule, std::nullopt) == &chain.At(2'100));
    BOOST_CHECK(!Access::HistoricalSelectionTip(
        chain.At(2'009), *schedule, COVERAGE));
    BOOST_CHECK(!Access::HistoricalSelectionTip(
        chain.At(2'100), *schedule, COVERAGE + 1));
    BOOST_CHECK(!Access::HistoricalSelectionTip(
        chain.At(2'100), *schedule, -1));
    BOOST_CHECK(!Access::HistoricalSelectionTip(
        chain.At(2'100), *schedule, std::numeric_limits<int32_t>::max()));

    LiveSigningIndexChain sibling{2'101};
    sibling.RehashFrom(COVERAGE, 200'000);
    const auto* replaced{Access::HistoricalSelectionTip(
        sibling.At(2'100), *schedule, COVERAGE)};
    BOOST_REQUIRE(replaced);
    // The selector must rederive from the current branch, so the validator's
    // exact frozen-boundary comparison rejects a replaced supporting prefix.
    BOOST_CHECK(replaced->GetAncestor(COVERAGE)->GetBlockHash() !=
                selected->GetAncestor(COVERAGE)->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(historical_reset_admission_distinguishes_initialize_and_recover)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;

    const auto chainlock{MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(chainlock);
    const BTCCScheduleConfig btcc{.candidate_origin = 865};
    constexpr int32_t ACTIVATION_PREDECESSOR{864};
    const uint256 activation_hash{NonNullHash(89'000)};
    const uint256 initial_hash{NonNullHash(89'001)};
    const uint256 initial_btcp{NonNullHash(89'002)};

    RosterBeaconSeed normal;
    normal.state = RosterBeaconState::READY;
    normal.epoch = ACTIVE_QUORUMS - 1;
    normal.anchor_cursor = BTCCursor{
        865, initial_hash, initial_btcp};
    normal.anchor_btc_height = 800'000;
    normal.future_btc_hash = NonNullHash(89'003);
    BOOST_REQUIRE(normal.IsReady());

    RosterBeaconWindow initial_window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        initial_window.active.seeds[slot] = normal;
        initial_window.active.seeds[slot].epoch =
            static_cast<uint32_t>(slot);
    }
    initial_window.active.recovery_authority_source.normal_beacon = normal;
    initial_window.next.epoch = ACTIVE_QUORUMS;
    BOOST_REQUIRE(IsInitialNormalRosterBeaconWindow(initial_window));

    auto initialize{
        MakeCatchupChainLock(865, ACTIVATION_PREDECESSOR,
                             activation_hash, 89'005)
            .statement};
    initialize.block_hash = initial_hash;
    initialize.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    initialize.roster_authorization_base = {};
    initialize.roster_beacons = initial_window;
    initialize.previous_btcc_cursor = {};
    initialize.accepted_btcc_cursor = normal.anchor_cursor;
    initialize.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(initialize.IsStructurallyValid());
    BOOST_CHECK(Access::ExactHistoricalResetCandidate(
        initialize, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, initial_btcp));
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        initialize, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/true,
        /*target_is_active=*/true, initial_btcp));
    BOOST_CHECK(Access::ExactHistoricalResetCandidate(
        initialize, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, initial_btcp,
        /*has_verified_historical_recovery=*/true));
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        initialize, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/true,
        /*target_is_active=*/true, initial_btcp,
        /*has_verified_historical_recovery=*/true));

    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        *chainlock, btcc, /*epoch=*/7)};
    BOOST_REQUIRE(recovery_target);
    auto recover{initialize};
    recover.height = *recovery_target;
    recover.block_hash = NonNullHash(89'006);
    recover.previous_chainlock_height =
        *recovery_target - static_cast<int32_t>(PQ_CL_PERIOD);
    recover.previous_chainlock_hash = NonNullHash(89'007);
    recover.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    recover.roster_authorization_base = RosterAuthorizationBaseIdentity{
        initialize.height, initialize.block_hash, NonNullHash(89'008)};
    const auto recovery_window{MakeRecoveryRosterBeaconWindow(
        initial_window.active.recovery_authority_source,
        /*newest_epoch=*/7)};
    BOOST_REQUIRE(recovery_window);
    recover.roster_beacons = *recovery_window;
    recover.previous_btcc_cursor = initialize.accepted_btcc_cursor;
    recover.accepted_btcc_cursor = recover.previous_btcc_cursor;
    recover.btcc_advance = BTCCAdvance::KEEP;
    recover.roster_authorization_state_hash = NonNullHash(89'009);
    BOOST_REQUIRE(recover.IsStructurallyValid());
    BOOST_CHECK_NE(
        recover.roster_beacons.active.seeds.back().anchor_cursor.sys_height,
        recover.height);
    BOOST_CHECK(Access::ExactHistoricalResetCandidate(
        recover, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/true,
        /*target_is_active=*/true, NonNullHash(89'010)));
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        recover, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, NonNullHash(89'010)));

    BOOST_CHECK(Access::ExactHistoricalResetCandidate(
        recover, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, NonNullHash(89'010),
        /*has_verified_historical_recovery=*/true));
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        recover, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/false, NonNullHash(89'010),
        /*has_verified_historical_recovery=*/true));
    auto noncanonical_recovery{recover};
    noncanonical_recovery.height += static_cast<int32_t>(PQ_CL_PERIOD);
    BOOST_REQUIRE(noncanonical_recovery.IsStructurallyValid());
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        noncanonical_recovery, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, NonNullHash(89'010),
        /*has_verified_historical_recovery=*/true));
    auto wrong_window{recover};
    wrong_window.roster_beacons = initial_window;
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        wrong_window, *chainlock, btcc, ACTIVATION_PREDECESSOR,
        activation_hash, /*has_durable_best=*/false,
        /*target_is_active=*/true, NonNullHash(89'010),
        /*has_verified_historical_recovery=*/true));

    auto advancing_recovery{recover};
    advancing_recovery.accepted_btcc_cursor = BTCCursor{
        advancing_recovery.height, advancing_recovery.block_hash,
        NonNullHash(89'011)};
    advancing_recovery.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(advancing_recovery.IsStructurallyValid());
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        advancing_recovery, *chainlock, btcc,
        ACTIVATION_PREDECESSOR, activation_hash,
        /*has_durable_best=*/true, /*target_is_active=*/true,
        NonNullHash(89'010)));
    BOOST_CHECK(!Access::ExactHistoricalResetCandidate(
        advancing_recovery, *chainlock, btcc,
        ACTIVATION_PREDECESSOR, activation_hash,
        /*has_durable_best=*/false, /*target_is_active=*/true,
        NonNullHash(89'010), /*has_verified_historical_recovery=*/true));
}

BOOST_AUTO_TEST_CASE(objective_recovery_mode_is_mutually_exclusive_at_one_target)
{
    using namespace llmq::pq;

    const auto chainlock{MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(chainlock);
    const BTCCScheduleConfig btcc{.candidate_origin = 865};
    const auto canonical{CanonicalRosterRecoveryTargetHeight(
        *chainlock, btcc, /*epoch=*/7)};
    BOOST_REQUIRE(canonical);
    const auto old_epoch_base{EpochBaseHeight(*chainlock, /*epoch=*/3)};
    const auto fresh_epoch_base{EpochBaseHeight(*chainlock, /*epoch=*/6)};
    BOOST_REQUIRE(old_epoch_base);
    BOOST_REQUIRE(fresh_epoch_base);
    const auto old_receipt{NextEligibleChainLockTargetHeight(
        *chainlock, *old_epoch_base - 1)};
    const auto fresh_receipt{NextEligibleChainLockTargetHeight(
        *chainlock, *fresh_epoch_base - 1)};
    BOOST_REQUIRE(old_receipt);
    BOOST_REQUIRE(fresh_receipt);

    const auto recover{GetObjectiveRosterAuthorizationMode(
        *chainlock, btcc, /*target_epoch=*/7, *canonical,
        *old_receipt)};
    const auto normal{GetObjectiveRosterAuthorizationMode(
        *chainlock, btcc, /*target_epoch=*/7, *canonical,
        *fresh_receipt)};
    BOOST_REQUIRE(recover);
    BOOST_REQUIRE(normal);
    BOOST_CHECK(*recover == ObjectiveRosterAuthorizationMode::RECOVER);
    BOOST_CHECK(*normal == ObjectiveRosterAuthorizationMode::NORMAL);

    const int32_t noncanonical{
        *canonical - static_cast<int32_t>(chainlock->chainlock_period)};
    const auto paused{GetObjectiveRosterAuthorizationMode(
        *chainlock, btcc, /*target_epoch=*/7, noncanonical,
        *old_receipt)};
    BOOST_REQUIRE(paused);
    BOOST_CHECK(*paused == ObjectiveRosterAuthorizationMode::PAUSE);
}

BOOST_AUTO_TEST_CASE(current_signing_context_routes_advance_and_keep_ids)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;

    const uint256 genesis_hash{NonNullHash(90'000)};
    const auto schedule{MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);
    auto advance_statement{
        MakeCatchupChainLock(2'000, 1'995, NonNullHash(90'001), 1)
            .statement};
    advance_statement.previous_btcc_cursor =
        BTCCursor{1'900, NonNullHash(90'002), NonNullHash(90'003)};
    advance_statement.accepted_btcc_cursor =
        BTCCursor{1'905, NonNullHash(90'004), NonNullHash(90'005)};
    advance_statement.btcc_advance = BTCCAdvance::ADVANCE;

    auto keep_statement{advance_statement};
    keep_statement.accepted_btcc_cursor =
        keep_statement.previous_btcc_cursor;
    keep_statement.btcc_advance = BTCCAdvance::KEEP;

    const auto roster_set{
        ChainLockStoreTestContextFactory::CreateRosterSet(genesis_hash)};
    BOOST_REQUIRE(roster_set);
    const std::array<PreparedChainLockContextPtr, 2> variants{
        ChainLockStoreTestContextFactory::Create(
            *schedule, advance_statement, roster_set),
        ChainLockStoreTestContextFactory::Create(
            *schedule, keep_statement, roster_set)};
    BOOST_REQUIRE(variants[0]);
    BOOST_REQUIRE(variants[1]);
    BOOST_REQUIRE(variants[0]->StatementLogicalId() !=
                  variants[1]->StatementLogicalId());

    const auto advance_variant{Access::FindCurrentSigningVariant(
        variants, roster_set, variants[0]->StatementLogicalId())};
    const auto keep_variant{Access::FindCurrentSigningVariant(
        variants, roster_set, variants[1]->StatementLogicalId())};
    BOOST_REQUIRE(advance_variant);
    BOOST_REQUIRE(keep_variant);
    BOOST_CHECK_EQUAL(*advance_variant, 0U);
    BOOST_CHECK_EQUAL(*keep_variant, 1U);
    BOOST_CHECK(!Access::FindCurrentSigningVariant(
        variants, roster_set, NonNullHash(90'006)));
    BOOST_CHECK(!Access::FindCurrentSigningVariant(
        variants, roster_set, uint256{}));
}

BOOST_AUTO_TEST_CASE(
    historical_index_validation_resumes_long_ranges_in_bounded_steps)
{
    constexpr std::size_t BLOCK_BUDGET{127};
    constexpr int32_t FIRST_HEIGHT{7};
    constexpr int32_t LAST_HEIGHT{10'007};
    constexpr std::size_t RANGE_SIZE{
        static_cast<std::size_t>(LAST_HEIGHT - FIRST_HEIGHT + 1)};
    LiveSigningIndexChain chain{
        static_cast<std::size_t>(LAST_HEIGHT + 1)};
    llmq::HistoricalIndexValidationCache cache;

    LOCK(cs_main);
    llmq::PaymentAuditContextStatus status{
        llmq::PaymentAuditContextStatus::LOCAL_ERROR};
    std::size_t calls{0};
    std::size_t total_examined{0};
    while (status != llmq::PaymentAuditContextStatus::READY) {
        std::size_t examined{0};
        status = cache.Validate(
            chain.At(LAST_HEIGHT), FIRST_HEIGHT,
            llmq::HistoricalIndexValidationMode::FULL_FINALITY,
            /*provenance_revocation_revision=*/1, BLOCK_BUDGET,
            &examined);
        BOOST_REQUIRE(status ==
                          llmq::PaymentAuditContextStatus::LOCAL_ERROR ||
                      status == llmq::PaymentAuditContextStatus::READY);
        BOOST_CHECK_LE(examined, BLOCK_BUDGET);
        BOOST_REQUIRE_GT(examined, 0U);
        total_examined += examined;
        ++calls;
    }
    BOOST_CHECK_EQUAL(total_examined, RANGE_SIZE);
    BOOST_CHECK_EQUAL(calls,
                      (RANGE_SIZE + BLOCK_BUDGET - 1) / BLOCK_BUDGET);

    std::size_t examined{1};
    BOOST_CHECK(cache.Validate(
                    chain.At(LAST_HEIGHT), FIRST_HEIGHT,
                    llmq::HistoricalIndexValidationMode::FULL_FINALITY,
                    /*provenance_revocation_revision=*/1, BLOCK_BUDGET,
                    &examined) ==
                llmq::PaymentAuditContextStatus::READY);
    BOOST_CHECK_EQUAL(examined, 0U);

    BOOST_CHECK(cache.Validate(
                    chain.At(LAST_HEIGHT), FIRST_HEIGHT,
                    llmq::HistoricalIndexValidationMode::FULL_FINALITY,
                    /*provenance_revocation_revision=*/2, BLOCK_BUDGET,
                    &examined) ==
                llmq::PaymentAuditContextStatus::LOCAL_ERROR);
    BOOST_CHECK_EQUAL(examined, BLOCK_BUDGET);
}

BOOST_AUTO_TEST_CASE(
    first_winner_catchup_cannot_narrow_full_validation_to_its_predecessor)
{
    int32_t previous_superblock{0};
    int32_t superblock_height{0};
    CSuperblock::GetNearestSuperblocksHeights(
        /*nBlockHeight=*/1, previous_superblock, superblock_height);
    BOOST_REQUIRE_GT(superblock_height, 1);
    const int32_t activation_predecessor{superblock_height - 1};
    const int32_t declared_predecessor{superblock_height + 1};
    const int32_t target_height{superblock_height + 2};
    llmq::pq::ChainLockCandidateContextRequest request;
    request.admission = llmq::pq::ChainLockCandidateAdmission::CATCHUP;
    request.has_local_chainlock = false;
    request.local_best.height = declared_predecessor;
    request.statement.previous_chainlock_height = declared_predecessor;

    const int32_t first_winner_floor{
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateFullValidationFloor(
                request, activation_predecessor)};
    BOOST_CHECK_EQUAL(first_winner_floor, activation_predecessor);
    BOOST_CHECK(!llmq::test::CChainLocksHandlerTestAccess::
                    CandidateTargetValidationSufficient(
                        llmq::pq::ChainLockCandidateAdmission::CATCHUP,
                        /*has_local_chainlock=*/false,
                        /*marker_authorized_catchup=*/false,
                        /*exact_local_target=*/false,
                        /*historical_receipt_range_ready=*/true));
    BOOST_CHECK(llmq::test::CChainLocksHandlerTestAccess::
                    CandidateTargetValidationSufficient(
                        llmq::pq::ChainLockCandidateAdmission::CATCHUP,
                        /*has_local_chainlock=*/false,
                        /*marker_authorized_catchup=*/true,
                        /*exact_local_target=*/false,
                        /*historical_receipt_range_ready=*/true));
    BOOST_CHECK(llmq::test::CChainLocksHandlerTestAccess::
                    CandidateTargetValidationSufficient(
                        llmq::pq::ChainLockCandidateAdmission::CATCHUP,
                        /*has_local_chainlock=*/true,
                        /*marker_authorized_catchup=*/false,
                        /*exact_local_target=*/false,
                        /*historical_receipt_range_ready=*/true));

    request.has_local_chainlock = true;
    BOOST_CHECK_EQUAL(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateFullValidationFloor(
                request, activation_predecessor),
        declared_predecessor);

    request.has_local_chainlock = false;
    request.admission =
        llmq::pq::ChainLockCandidateAdmission::TRUSTED_PERSISTENCE;
    BOOST_CHECK_EQUAL(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateFullValidationFloor(
                request, activation_predecessor),
        activation_predecessor);
    BOOST_CHECK(!llmq::test::CChainLocksHandlerTestAccess::
                    CandidateTargetValidationSufficient(
                        llmq::pq::ChainLockCandidateAdmission::
                            TRUSTED_PERSISTENCE,
                        /*has_local_chainlock=*/false,
                        /*marker_authorized_catchup=*/false,
                        /*exact_local_target=*/false,
                        /*historical_receipt_range_ready=*/true));
    BOOST_CHECK(llmq::test::CChainLocksHandlerTestAccess::
                    CandidateTargetValidationSufficient(
                        llmq::pq::ChainLockCandidateAdmission::
                            TRUSTED_PERSISTENCE,
                        /*has_local_chainlock=*/false,
                        /*marker_authorized_catchup=*/false,
                        /*exact_local_target=*/true,
                        /*historical_receipt_range_ready=*/false));

    request.admission =
        llmq::pq::ChainLockCandidateAdmission::RECEIPT_ARCHIVE;
    BOOST_CHECK_EQUAL(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateFullValidationFloor(
                request, activation_predecessor),
        declared_predecessor);
    request.admission = llmq::pq::ChainLockCandidateAdmission::
                            TRUSTED_UNSEALED_PERSISTENCE;
    BOOST_CHECK_EQUAL(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateFullValidationFloor(
                request, activation_predecessor),
        declared_predecessor);

    // The skipped interval contains a superblock whose governance provenance
    // is absent. A floor derived from the unsigned local declaration would
    // miss it; the activation predecessor correctly keeps it in scope.
    LiveSigningIndexChain chain{
        static_cast<std::size_t>(target_height + 1)};
    llmq::HistoricalIndexValidationCache full_cache;
    llmq::HistoricalIndexValidationCache narrowed_cache;
    LOCK(cs_main);
    chain.ClearStatus(superblock_height, BLOCK_GOVERNANCE_VALIDATED);
    chain.ClearStatus(target_height, BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateTargetValidationMode(
                llmq::pq::ChainLockCandidateAdmission::
                    TRUSTED_PERSISTENCE) ==
        llmq::HistoricalIndexValidationMode::FULL_RECEIPT);
    BOOST_CHECK(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateTargetValidationMode(
                llmq::pq::ChainLockCandidateAdmission::
                    TRUSTED_UNSEALED_PERSISTENCE) ==
        llmq::HistoricalIndexValidationMode::FULL_RECEIPT);
    BOOST_CHECK(
        llmq::test::CChainLocksHandlerTestAccess::
            CandidateTargetValidationMode(
                llmq::pq::ChainLockCandidateAdmission::LIVE) ==
        llmq::HistoricalIndexValidationMode::FULL_FINALITY);
    llmq::HistoricalIndexValidationCache persisted_cache;
    BOOST_CHECK(persisted_cache.Validate(
                    chain.At(target_height), first_winner_floor + 1,
                    llmq::HistoricalIndexValidationMode::FULL_RECEIPT,
                    /*provenance_revocation_revision=*/1) ==
                llmq::PaymentAuditContextStatus::READY);
    BOOST_CHECK(full_cache.Validate(
                    chain.At(target_height), first_winner_floor + 1,
                    llmq::HistoricalIndexValidationMode::FULL_FINALITY,
                    /*provenance_revocation_revision=*/1) ==
                llmq::PaymentAuditContextStatus::LOCAL_ERROR);
    BOOST_CHECK(narrowed_cache.Validate(
                    chain.At(target_height), declared_predecessor + 1,
                    llmq::HistoricalIndexValidationMode::FULL_FINALITY,
                    /*provenance_revocation_revision=*/1) ==
                llmq::PaymentAuditContextStatus::READY);
}

BOOST_AUTO_TEST_CASE(
    bounded_active_range_frontier_is_branch_and_source_bound)
{
    constexpr std::size_t BLOCK_BUDGET{127};
    constexpr int32_t FLOOR_HEIGHT{7};
    constexpr int32_t LAST_HEIGHT{10'007};
    constexpr std::size_t RANGE_SIZE{
        static_cast<std::size_t>(LAST_HEIGHT - FLOOR_HEIGHT)};
    LiveSigningIndexChain chain{
        static_cast<std::size_t>(LAST_HEIGHT + 1)};
    llmq::BoundedActiveRangeFrontier frontier;
    const uint256 source{NonNullHash(199'000)};

    LOCK(cs_main);
    std::size_t calls{0};
    for (;;) {
        const auto plan{frontier.Plan(
            chain.active, chain.At(LAST_HEIGHT), FLOOR_HEIGHT,
            chain.At(FLOOR_HEIGHT).GetBlockHash(), source,
            BLOCK_BUDGET)};
        if (plan.status ==
            llmq::BoundedActiveRangeStatus::COMPLETE) {
            break;
        }
        BOOST_REQUIRE(plan.status ==
                      llmq::BoundedActiveRangeStatus::WORK);
        BOOST_CHECK_LE(
            plan.last_height - plan.first_height + 1,
            static_cast<int32_t>(BLOCK_BUDGET));
        BOOST_REQUIRE(frontier.CommitThrough(
            chain.active, plan.last_height));
        ++calls;
    }
    BOOST_CHECK(frontier.IsComplete(chain.At(LAST_HEIGHT)));
    BOOST_CHECK_EQUAL(calls,
                      (RANGE_SIZE + BLOCK_BUDGET - 1) / BLOCK_BUDGET);

    chain.RehashFrom(LAST_HEIGHT, 299'000);
    const auto reorg_plan{frontier.Plan(
        chain.active, chain.At(LAST_HEIGHT), FLOOR_HEIGHT,
        chain.At(FLOOR_HEIGHT).GetBlockHash(), source, BLOCK_BUDGET)};
    BOOST_REQUIRE(reorg_plan.status ==
                  llmq::BoundedActiveRangeStatus::WORK);
    BOOST_CHECK(reorg_plan.reset);
    BOOST_CHECK_EQUAL(reorg_plan.first_height, FLOOR_HEIGHT + 1);
    BOOST_CHECK(!frontier.CommitThrough(
        chain.active, reorg_plan.last_height + 1));
    BOOST_REQUIRE(frontier.CommitThrough(
        chain.active, reorg_plan.last_height));

    const auto new_source_plan{frontier.Plan(
        chain.active, chain.At(LAST_HEIGHT), FLOOR_HEIGHT,
        chain.At(FLOOR_HEIGHT).GetBlockHash(), NonNullHash(199'001),
        BLOCK_BUDGET)};
    BOOST_REQUIRE(new_source_plan.status ==
                  llmq::BoundedActiveRangeStatus::WORK);
    BOOST_CHECK(new_source_plan.reset);
    BOOST_CHECK_EQUAL(new_source_plan.first_height, FLOOR_HEIGHT + 1);
    const int32_t partial_through{new_source_plan.first_height + 20};
    BOOST_REQUIRE(frontier.CommitThrough(
        chain.active, partial_through));
    const auto resumed_plan{frontier.Plan(
        chain.active, chain.At(LAST_HEIGHT), FLOOR_HEIGHT,
        chain.At(FLOOR_HEIGHT).GetBlockHash(), NonNullHash(199'001),
        BLOCK_BUDGET)};
    BOOST_REQUIRE(resumed_plan.status ==
                  llmq::BoundedActiveRangeStatus::WORK);
    BOOST_CHECK(!resumed_plan.reset);
    BOOST_CHECK_EQUAL(resumed_plan.first_height, partial_through + 1);

    const auto revoked_plan{frontier.Plan(
        chain.active, chain.At(LAST_HEIGHT), FLOOR_HEIGHT,
        chain.At(FLOOR_HEIGHT).GetBlockHash(), NonNullHash(199'002),
        BLOCK_BUDGET)};
    BOOST_REQUIRE(revoked_plan.status ==
                  llmq::BoundedActiveRangeStatus::WORK);
    BOOST_CHECK(revoked_plan.reset);
    BOOST_CHECK_EQUAL(revoked_plan.first_height, FLOOR_HEIGHT + 1);
}

BOOST_AUTO_TEST_CASE(
    historical_verification_capability_is_exact_source_bound)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    constexpr uint8_t PRESEAL_CATCHUP{4};
    const uint256 marker{NonNullHash(199'500)};

    BOOST_CHECK(Access::HistoricalCapabilityMatches(
        PRESEAL_CATCHUP, marker, /*verified_roster_generation=*/7,
        PRESEAL_CATCHUP, marker, /*current_roster_generation=*/7));
    BOOST_CHECK(!Access::HistoricalCapabilityMatches(
        PRESEAL_CATCHUP, marker, /*verified_roster_generation=*/7,
        PRESEAL_CATCHUP, marker, /*current_roster_generation=*/8));
    BOOST_CHECK(!Access::HistoricalCapabilityMatches(
        PRESEAL_CATCHUP, marker, /*verified_roster_generation=*/7,
        PRESEAL_CATCHUP, NonNullHash(199'501),
        /*current_roster_generation=*/7));
    BOOST_CHECK(!Access::HistoricalCapabilityMatches(
        PRESEAL_CATCHUP, marker, /*verified_roster_generation=*/0,
        PRESEAL_CATCHUP, marker, /*current_roster_generation=*/0));
}

BOOST_AUTO_TEST_CASE(historical_roster_authorization_routes_are_explicit)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using Admission = llmq::pq::ChainLockCandidateAdmission;
    using Transition = llmq::pq::RosterAuthorizationTransitionKind;
    constexpr uint8_t INVALID{0};
    constexpr uint8_t EXACT_NETWORK{1};
    constexpr uint8_t NONE{0};
    constexpr uint8_t CURRENT_CATCHUP{1};
    constexpr uint8_t RETAINED_SUCCESSOR{2};
    constexpr uint8_t RECOVERY{3};
    constexpr uint8_t PRESEAL_CATCHUP{4};
    constexpr uint8_t PRESEAL_RECEIPT{5};
    const std::array transitions{
        Transition::INITIALIZE, Transition::KEEP, Transition::OBSERVE,
        Transition::REVEAL, Transition::ROTATE, Transition::RECOVER};

    for (const auto transition : transitions) {
        const bool reset{transition == Transition::INITIALIZE ||
                         transition == Transition::RECOVER};
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::LIVE, NONE, transition),
                          EXACT_NETWORK);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::RECEIPT_ARCHIVE, NONE,
                              transition),
                          EXACT_NETWORK);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::CATCHUP, CURRENT_CATCHUP,
                              transition),
                          reset ? INVALID : EXACT_NETWORK);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::CATCHUP, RETAINED_SUCCESSOR,
                              transition),
                          reset ? INVALID : EXACT_NETWORK);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::CATCHUP, RECOVERY, transition),
                          reset ? EXACT_NETWORK : INVALID);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::CATCHUP, PRESEAL_CATCHUP,
                              transition),
                          EXACT_NETWORK);
        BOOST_CHECK_EQUAL(Access::HistoricalRosterAuthorization(
                              Admission::PRESEAL_RECEIPT,
                              PRESEAL_RECEIPT, transition),
                          EXACT_NETWORK);
    }

    const auto old_receipt{Access::HistoricalPreVerificationAdmission(
        PRESEAL_RECEIPT, /*statement_height=*/90,
        /*best_height=*/100)};
    const auto newer_receipt{Access::HistoricalPreVerificationAdmission(
        PRESEAL_RECEIPT, /*statement_height=*/110,
        /*best_height=*/100)};
    const auto first_receipt{Access::HistoricalPreVerificationAdmission(
        PRESEAL_RECEIPT, /*statement_height=*/90, std::nullopt)};
    BOOST_CHECK(old_receipt == Admission::PRESEAL_RECEIPT);
    BOOST_CHECK(newer_receipt == Admission::CATCHUP);
    BOOST_CHECK(first_receipt == Admission::CATCHUP);
    BOOST_CHECK(Access::HistoricalArchiveIdentity(old_receipt));
    BOOST_CHECK(!Access::HistoricalArchiveIdentity(newer_receipt));
    BOOST_CHECK(Access::HistoricalArchiveIdentity(
        Admission::RECEIPT_ARCHIVE));
    BOOST_CHECK(Access::HistoricalArchiveIdentity(
        Admission::TRUSTED_UNSEALED_PERSISTENCE));
}

BOOST_AUTO_TEST_CASE(receipt_archive_source_capability_is_exact)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const uint256 logical_id{NonNullHash(199'600)};
    const uint256 carrier_hash{NonNullHash(199'601)};
    const uint256 source_token{NonNullHash(199'602)};

    BOOST_CHECK(Access::ReceiptArchiveSourceMatches(
        /*PENDING_CARRIER=*/0, logical_id, carrier_hash,
        std::pair{logical_id, carrier_hash}, std::nullopt));
    BOOST_CHECK(!Access::ReceiptArchiveSourceMatches(
        /*PENDING_CARRIER=*/0, logical_id, carrier_hash,
        std::pair{logical_id, NonNullHash(199'603)}, std::nullopt));
    BOOST_CHECK(!Access::ReceiptArchiveSourceMatches(
        /*PENDING_CARRIER=*/0, logical_id, carrier_hash,
        std::pair{NonNullHash(199'604), carrier_hash}, std::nullopt));

    BOOST_CHECK(Access::ReceiptArchiveSourceMatches(
        /*LIVE_FRONTIER=*/1, logical_id, source_token, std::nullopt,
        std::tuple{/*LIVE_FRONTIER=*/0, logical_id, source_token}));
    BOOST_CHECK(!Access::ReceiptArchiveSourceMatches(
        /*LIVE_FRONTIER=*/1, logical_id, source_token, std::nullopt,
        std::tuple{/*PRESEAL_REPLAY=*/1, logical_id, source_token}));
    BOOST_CHECK(!Access::ReceiptArchiveSourceMatches(
        /*LIVE_FRONTIER=*/1, logical_id, source_token, std::nullopt,
        std::tuple{/*LIVE_FRONTIER=*/0, logical_id,
                   NonNullHash(199'605)}));
}

BOOST_AUTO_TEST_CASE(
    btcc_replay_requests_missing_carriers_sequentially)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    BOOST_CHECK(llmq::ShouldArchiveRequiredBTCCReceiptCertificate(
        /*exact_receipt_required=*/true,
        /*has_local_finality=*/true,
        /*receipt_target_height=*/880,
        /*local_finality_height=*/900));
    BOOST_CHECK(!llmq::ShouldArchiveRequiredBTCCReceiptCertificate(
        /*exact_receipt_required=*/false,
        /*has_local_finality=*/true,
        /*receipt_target_height=*/880,
        /*local_finality_height=*/900));
    BOOST_CHECK(!llmq::ShouldArchiveRequiredBTCCReceiptCertificate(
        /*exact_receipt_required=*/true,
        /*has_local_finality=*/true,
        /*receipt_target_height=*/900,
        /*local_finality_height=*/900));
    const auto config{LiveSigningFrontierConfig()};
    constexpr int32_t AUTHENTICATED_THROUGH{864};
    constexpr int32_t TIP_HEIGHT{1'100};
    LiveSigningIndexChain chain{
        static_cast<std::size_t>(TIP_HEIGHT + 1)};
    std::vector<int32_t> carriers;
    for (int32_t height{AUTHENTICATED_THROUGH + 1};
         height <= TIP_HEIGHT && carriers.size() < 2; ++height) {
        if (llmq::pq::IsBTCCReceiptCarrierHeight(
                config.btcc_schedule, height)) {
            carriers.push_back(height);
        }
    }
    BOOST_REQUIRE_EQUAL(carriers.size(), 2U);
    const uint256 first_id{NonNullHash(199'600)};
    const uint256 second_id{NonNullHash(199'601)};
    const uint256 source{NonNullHash(199'602)};
    llmq::BoundedActiveRangeFrontier frontier;
    unsigned int phase{0};
    const auto check = [&](const CBlockIndex& carrier) {
        if (phase == 0 && carrier.nHeight == carriers[0]) {
            return std::pair{Access::CertificateStatus::MISSING,
                             first_id};
        }
        if (phase == 1 && carrier.nHeight == carriers[1]) {
            return std::pair{Access::CertificateStatus::MISSING,
                             second_id};
        }
        return std::pair{Access::CertificateStatus::VERIFIED,
                         uint256{}};
    };

    LOCK(cs_main);
    auto step{Access::AdvanceReplay(
        frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, check)};
    BOOST_REQUIRE(step.validated_through);
    BOOST_REQUIRE(step.missing_logical_id);
    BOOST_CHECK_EQUAL(*step.validated_through, carriers[0] - 1);
    BOOST_CHECK(*step.missing_logical_id == first_id);

    phase = 1;
    step = Access::AdvanceReplay(
        frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, check);
    BOOST_REQUIRE(step.validated_through);
    BOOST_REQUIRE(step.missing_logical_id);
    BOOST_CHECK_EQUAL(*step.validated_through, carriers[1] - 1);
    BOOST_CHECK(*step.missing_logical_id == second_id);

    phase = 2;
    step = Access::AdvanceReplay(
        frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, check);
    BOOST_REQUIRE(step.validated_through);
    BOOST_CHECK_EQUAL(*step.validated_through, TIP_HEIGHT);
    BOOST_CHECK(!step.missing_logical_id);

    llmq::BoundedActiveRangeFrontier invalid_frontier;
    const auto invalid = [&](const CBlockIndex& carrier) {
        return carrier.nHeight == carriers[0]
            ? std::pair{Access::CertificateStatus::INVALID,
                        first_id}
            : std::pair{Access::CertificateStatus::VERIFIED,
                        uint256{}};
    };
    const auto invalid_step{Access::AdvanceReplay(
        invalid_frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, invalid)};
    BOOST_REQUIRE(invalid_step.validated_through);
    BOOST_CHECK_EQUAL(*invalid_step.validated_through,
                      carriers[0] - 1);
    BOOST_CHECK(!invalid_step.missing_logical_id);
    BOOST_CHECK(invalid_step.terminal_status ==
                Access::CertificateStatus::INVALID);
    BOOST_CHECK_EQUAL(invalid_step.blocked_carrier_height,
                      carriers[0]);
    BOOST_CHECK(invalid_step.blocked_carrier_hash ==
                chain.At(carriers[0]).GetBlockHash());
    BOOST_CHECK(invalid_step.blocked_logical_id == first_id);

    const auto invalid_retry{Access::AdvanceReplay(
        invalid_frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, invalid)};
    BOOST_REQUIRE(invalid_retry.validated_through);
    BOOST_CHECK_EQUAL(*invalid_retry.validated_through,
                      carriers[0] - 1);
    BOOST_CHECK(!invalid_retry.missing_logical_id);
    BOOST_CHECK(invalid_retry.terminal_status ==
                Access::CertificateStatus::INVALID);

    llmq::BoundedActiveRangeFrontier local_error_frontier;
    const auto local_error = [&](const CBlockIndex& carrier) {
        return carrier.nHeight == carriers[0]
            ? std::pair{Access::CertificateStatus::LOCAL_ERROR,
                        first_id}
            : std::pair{Access::CertificateStatus::VERIFIED,
                        uint256{}};
    };
    const auto local_error_step{Access::AdvanceReplay(
        local_error_frontier, chain.active, chain.At(TIP_HEIGHT),
        AUTHENTICATED_THROUGH,
        chain.At(AUTHENTICATED_THROUGH).GetBlockHash(), source,
        config.btcc_schedule, local_error)};
    BOOST_REQUIRE(local_error_step.validated_through);
    BOOST_CHECK_EQUAL(*local_error_step.validated_through,
                      carriers[0] - 1);
    BOOST_CHECK(!local_error_step.missing_logical_id);
    BOOST_CHECK(local_error_step.terminal_status ==
                Access::CertificateStatus::LOCAL_ERROR);
}

BOOST_AUTO_TEST_CASE(
    live_signing_frontier_retains_long_prefix_and_extends_only_delta)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const auto config{LiveSigningFrontierConfig()};
    const uint256 genesis{NonNullHash(200'000)};
    LiveSigningIndexChain chain{1'886};
    Access::LiveSigningFrontier state;
    const auto floor{chain.Predecessor(864)};

    LOCK(cs_main);
    chain.ClearStatus(1'880, BLOCK_HAVE_DATA);
    chain.ClearStatus(1'880, BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(1'880), floor, config, genesis,
        /*provenance_revocation_revision=*/1,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 1'016U);
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(state), 1'880);
    BOOST_CHECK(!Access::HasExactTargetEndpoint(chain.At(1'880)));

    const uint64_t after_initial{state.examined_blocks};
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(1'880), floor, config, genesis, 1,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, after_initial);

    chain.SetStatus(1'880, BLOCK_HAVE_DATA);
    BOOST_CHECK(!Access::HasExactTargetEndpoint(chain.At(1'880)));
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(1'880), floor, config, genesis, 1,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, after_initial);
    chain.SetStatus(1'880, BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(Access::HasExactTargetEndpoint(chain.At(1'880)));

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(1'885), floor, config, genesis, 1,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, after_initial + 5);
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(state), 1'885);
}

BOOST_AUTO_TEST_CASE(live_signing_frontier_caps_each_recovery_step)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    constexpr std::size_t BLOCK_BUDGET{127};
    const auto config{LiveSigningFrontierConfig()};
    const uint256 genesis{NonNullHash(200'500)};
    LiveSigningIndexChain chain{1'881};
    Access::LiveSigningFrontier state;
    const auto floor{chain.Predecessor(864)};

    LOCK(cs_main);
    bool ready{false};
    std::size_t calls{0};
    while (!ready) {
        const uint64_t before{state.examined_blocks};
        ready = Access::Advance(
            state, chain.active, chain.At(1'880), floor, config, genesis,
            /*provenance_revocation_revision=*/1,
            ACCEPT_LIVE_SIGNING_CERTIFICATE, BLOCK_BUDGET);
        BOOST_CHECK_LE(state.examined_blocks - before, BLOCK_BUDGET);
        BOOST_REQUIRE_GT(state.examined_blocks - before, 0U);
        ++calls;
    }
    BOOST_CHECK_EQUAL(state.examined_blocks, 1'016U);
    BOOST_CHECK_EQUAL(calls, (1'016U + BLOCK_BUDGET - 1) / BLOCK_BUDGET);
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(state), 1'880);
}

BOOST_AUTO_TEST_CASE(
    live_signing_frontier_resumes_after_partial_provenance_and_governance)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const auto config{LiveSigningFrontierConfig()};
    const uint256 genesis{NonNullHash(201'000)};

    {
        LiveSigningIndexChain chain{1'011};
        Access::LiveSigningFrontier state;
        const auto floor{chain.Predecessor(864)};

        LOCK(cs_main);
        chain.ClearStatus(1'001, BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        BOOST_CHECK(!Access::Advance(
            state, chain.active, chain.At(1'010), floor, config, genesis,
            /*provenance_revocation_revision=*/1,
            ACCEPT_LIVE_SIGNING_CERTIFICATE));
        BOOST_CHECK_EQUAL(Access::ValidatedThrough(state), 1'000);
        const uint64_t after_wait{state.examined_blocks};

        chain.SetStatus(1'001, BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        BOOST_REQUIRE(Access::Advance(
            state, chain.active, chain.At(1'010), floor, config, genesis,
            1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
        BOOST_CHECK_EQUAL(state.examined_blocks, after_wait + 10);
    }

    {
        int32_t governance_height{865};
        while (!CSuperblock::IsValidBlockHeight(governance_height)) {
            ++governance_height;
        }
        LiveSigningIndexChain chain{
            static_cast<std::size_t>(governance_height + 6)};
        Access::LiveSigningFrontier state;
        const auto floor{chain.Predecessor(864)};

        LOCK(cs_main);
        chain.ClearStatus(governance_height,
                          BLOCK_GOVERNANCE_VALIDATED);
        do {
            BOOST_CHECK(!Access::Advance(
                state, chain.active, chain.At(governance_height + 5),
                floor, config, genesis, 1,
                ACCEPT_LIVE_SIGNING_CERTIFICATE));
        } while (Access::ValidatedThrough(state) <
                 governance_height - 1);
        BOOST_CHECK_EQUAL(Access::ValidatedThrough(state),
                          governance_height - 1);
        const uint64_t after_wait{state.examined_blocks};

        chain.SetStatus(governance_height,
                        BLOCK_GOVERNANCE_VALIDATED);
        BOOST_REQUIRE(Access::Advance(
            state, chain.active, chain.At(governance_height + 5), floor,
            config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
        BOOST_CHECK_EQUAL(state.examined_blocks, after_wait + 6);
    }
}

BOOST_AUTO_TEST_CASE(
    live_signing_frontier_resumes_at_exact_missing_btcc_certificate)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    auto config{LiveSigningFrontierConfig()};
    config.activation_predecessor_height = 869;
    BOOST_REQUIRE(config.IsValid());
    const uint256 genesis{NonNullHash(202'000)};
    LiveSigningIndexChain chain{891};
    const auto floor{chain.Predecessor(864)};
    CBlockIndex& source{chain.At(870)};
    CBlockIndex& carrier{chain.At(880)};
    source.btcpPrevCommitment = NonNullHash(202'100);

    llmq::pq::BTCCReceipt receipt;
    receipt.chainlock_target_height = source.nHeight;
    receipt.chainlock_target_hash = source.GetBlockHash();
    receipt.chainlock_logical_id = NonNullHash(202'200);
    receipt.accepted_cursor = llmq::pq::BTCCursor{
        source.nHeight, source.GetBlockHash(), source.btcpPrevCommitment};
    const auto applied{llmq::pq::ApplyBTCCReceiptState(
        genesis, config.chainlock_schedule, config.btcc_schedule,
        config.activation_predecessor_height, carrier.nHeight,
        carrier.GetBlockHash(), {}, receipt)};
    BOOST_REQUIRE(applied);
    chain.SetReceiptStateFrom(carrier.nHeight, *applied);
    carrier.pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;

    Access::LiveSigningFrontier state;
    uint256 requested;
    const auto missing = [&](const llmq::pq::BTCCReceipt& candidate,
                             const CBlockIndex&) {
        requested = candidate.chainlock_logical_id;
        return Access::CertificateStatus::MISSING;
    };

    LOCK(cs_main);
    BOOST_CHECK(!Access::Advance(
        state, chain.active, chain.At(890), floor, config, genesis, 1,
        missing));
    BOOST_CHECK(requested == receipt.chainlock_logical_id);
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(state), 879);
    const uint64_t after_missing{state.examined_blocks};

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(890), floor, config, genesis, 1,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, after_missing + 11);
    const uint64_t after_verified{state.examined_blocks};

    unsigned int unexpected_callbacks{0};
    const auto evicted = [&](const llmq::pq::BTCCReceipt&,
                             const CBlockIndex&) {
        ++unexpected_callbacks;
        return Access::CertificateStatus::MISSING;
    };
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(890), floor, config, genesis, 1,
        evicted));
    BOOST_CHECK_EQUAL(unexpected_callbacks, 0U);
    BOOST_CHECK_EQUAL(state.examined_blocks, after_verified);

    Access::LiveSigningFrontier invalid_state;
    const auto invalid = [](const llmq::pq::BTCCReceipt&,
                            const CBlockIndex&) {
        return Access::CertificateStatus::INVALID;
    };
    BOOST_CHECK(!Access::Advance(
        invalid_state, chain.active, chain.At(890), floor, config,
        genesis, 1, invalid));
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(invalid_state), 879);
}

BOOST_AUTO_TEST_CASE(
    live_signing_frontier_rebases_and_resets_on_branch_or_floor_change)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const auto config{LiveSigningFrontierConfig()};
    const uint256 genesis{NonNullHash(203'000)};
    LiveSigningIndexChain chain{996};
    Access::LiveSigningFrontier state;

    LOCK(cs_main);
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(990), chain.Predecessor(864),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 126U);

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(990), chain.Predecessor(870),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 126U);
    BOOST_CHECK(Access::DurablePredecessor(state) ==
                chain.Predecessor(870));

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(995), chain.Predecessor(870),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 131U);

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(995), chain.Predecessor(865),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 261U);

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(990), chain.Predecessor(865),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 386U);

    LiveSigningIndexChain fork{996};
    fork.RehashFrom(950, 300'000);
    BOOST_REQUIRE(Access::Advance(
        state, fork.active, fork.At(990), fork.Predecessor(865), config,
        genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 511U);
    BOOST_CHECK(Access::ValidatedThroughHash(state) ==
                fork.At(990).GetBlockHash());

    Access::LiveSigningFrontier rebased;
    chain.ClearStatus(900, BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(!Access::Advance(
        rebased, chain.active, chain.At(995), chain.Predecessor(864),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(rebased), 899);
    const uint64_t before_rebase{rebased.examined_blocks};
    BOOST_REQUIRE(Access::Advance(
        rebased, chain.active, chain.At(995), chain.Predecessor(920),
        config, genesis, 1, ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(Access::ValidatedThrough(rebased), 995);
    BOOST_CHECK(Access::DurablePredecessor(rebased) ==
                chain.Predecessor(920));
    BOOST_CHECK_EQUAL(rebased.examined_blocks, before_rebase + 75);
}

BOOST_AUTO_TEST_CASE(
    live_signing_frontier_revision_revokes_same_hash_proof_and_source)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    const auto config{LiveSigningFrontierConfig()};
    const uint256 genesis{NonNullHash(204'000)};
    LiveSigningIndexChain chain{981};
    Access::LiveSigningFrontier state;
    const auto floor{chain.Predecessor(864)};

    LOCK(cs_main);
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(980), floor, config, genesis,
        /*provenance_revocation_revision=*/7,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 116U);
    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(980), floor, config, genesis, 7,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 116U);

    BOOST_REQUIRE(Access::Advance(
        state, chain.active, chain.At(980), floor, config, genesis,
        /*provenance_revocation_revision=*/8,
        ACCEPT_LIVE_SIGNING_CERTIFICATE));
    BOOST_CHECK_EQUAL(state.examined_blocks, 232U);
    BOOST_CHECK(Access::SourceRevisionCurrent(8, 8));
    BOOST_CHECK(!Access::SourceRevisionCurrent(8, 9));
}

BOOST_AUTO_TEST_CASE(share_admission_gate_linearizes_lifecycle_and_health)
{
    llmq::ShareAdmissionGate gate;
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    gate.SetReady(true);
    const uint64_t first_token{gate.Acquire()};
    BOOST_REQUIRE_NE(first_token, 0U);
    BOOST_CHECK(gate.IsCurrent(first_token));

    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    BOOST_CHECK(!gate.IsCurrent(first_token));
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    const uint64_t second_token{gate.Acquire()};
    BOOST_REQUIRE_NE(second_token, 0U);
    BOOST_CHECK_NE(second_token, first_token);

    gate.SetReady(false);
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    gate.SetReady(true);
    const uint64_t restarted_token{gate.Acquire()};
    BOOST_REQUIRE_NE(restarted_token, 0U);
    BOOST_CHECK_NE(restarted_token, second_token);
    BOOST_CHECK(!gate.IsCurrent(second_token));
}

BOOST_AUTO_TEST_CASE(share_admission_gate_terminal_failure_is_sticky)
{
    llmq::ShareAdmissionGate gate;
    gate.SetReady(true);
    const auto stale_enable{gate.Observe()};
    const auto before_failure{gate.Observe()};
    gate.Fail();
    BOOST_CHECK_NE(gate.Observe().state, before_failure.state);
    BOOST_CHECK(gate.IsTerminal());
    BOOST_CHECK(!gate.TryPublishEnabled(stale_enable, true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    const auto closed_failure{gate.Observe()};
    gate.Fail();
    BOOST_CHECK_NE(gate.Observe().state, closed_failure.state);
    gate.SetReady(false);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    gate.SetReady(true);
    BOOST_CHECK(gate.IsTerminal());
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    llmq::ShareAdmissionGate open_gate;
    open_gate.SetReady(true);
    BOOST_CHECK(open_gate.TryPublishEnabled(open_gate.Observe(), true));
    const uint64_t open_token{open_gate.Acquire()};
    BOOST_REQUIRE_NE(open_token, 0U);
    open_gate.Fail();
    open_gate.SetReady(false);
    BOOST_CHECK(open_gate.TryPublishEnabled(open_gate.Observe(), true));
    open_gate.SetReady(true);
    BOOST_CHECK(!open_gate.IsCurrent(open_token));
    BOOST_CHECK_EQUAL(open_gate.Acquire(), 0U);
}

BOOST_AUTO_TEST_CASE(auxiliary_gc_authority_rejects_stale_lifecycle_proofs)
{
    using Gate = llmq::AuxiliaryHistoryGCAuthorizationGate;
    Gate gate;
    bool authority{true};
    bool publication_hold{false};
    std::size_t publishes{0};
    std::size_t revocations{0};
    const auto revoke = [&] {
        ++revocations;
        authority = false;
        return true;
    };

    BOOST_REQUIRE(gate.Start(revoke));
    BOOST_CHECK_EQUAL(revocations, 1U);
    BOOST_CHECK(!gate.SetHealthy(false, revoke));
    BOOST_CHECK_EQUAL(revocations, 1U);
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto running{gate.ObserveReady()};
    BOOST_REQUIRE(running);

    gate.Stop(revoke);
    BOOST_CHECK_EQUAL(revocations, 2U);
    BOOST_CHECK(!authority);
    BOOST_CHECK(gate.TryPublish(*running, [&] {
        ++publishes;
        authority = true;
        return true;
    }) == Gate::MutationResult::STALE);
    BOOST_CHECK_EQUAL(publishes, 0U);
    BOOST_CHECK(!authority);

    // A certificate already crossing its durability seam during shutdown
    // must retain history, but it cannot revive destructive authority.
    const auto stopped_publication{gate.ArmPublication([&] {
        publication_hold = true;
        return true;
    })};
    BOOST_REQUIRE(stopped_publication);
    BOOST_CHECK(publication_hold);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.CompletePublication(*stopped_publication) ==
                Gate::MutationResult::APPLIED);
    BOOST_CHECK(!gate.ObserveReady());

    BOOST_REQUIRE(gate.Start(revoke));
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto restarted{gate.ObserveReady()};
    BOOST_REQUIRE(restarted);
    BOOST_CHECK_NE(*restarted, *running);
    BOOST_CHECK(gate.TryPublish(*restarted, [&] {
        ++publishes;
        authority = true;
        publication_hold = false;
        return true;
    }) == Gate::MutationResult::APPLIED);
    BOOST_CHECK(authority);
    BOOST_CHECK(!publication_hold);
    BOOST_CHECK_EQUAL(publishes, 1U);

    BOOST_CHECK(!gate.SetHealthy(false, revoke));
    BOOST_CHECK_EQUAL(revocations, 4U);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(!gate.SetHealthy(false, revoke));
    BOOST_CHECK_EQUAL(revocations, 4U);
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto revalidated{gate.ObserveReady()};
    BOOST_REQUIRE(revalidated);
    BOOST_CHECK_NE(*revalidated, *restarted);
}

BOOST_AUTO_TEST_CASE(auxiliary_gc_authority_newer_barrier_invalidates_proof)
{
    using Gate = llmq::AuxiliaryHistoryGCAuthorizationGate;
    Gate gate;
    bool authority{false};
    bool publication_hold{false};
    const auto revoke = [&] {
        authority = false;
        return true;
    };

    BOOST_REQUIRE(gate.Start(revoke));
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto before_barrier{gate.ObserveReady()};
    BOOST_REQUIRE(before_barrier);
    const auto publication{gate.ArmPublication([&] {
        publication_hold = true;
        return true;
    })};
    BOOST_REQUIRE(publication);

    BOOST_CHECK(gate.TryPublish(*before_barrier, [&] {
        authority = true;
        publication_hold = false;
        return true;
    }) == Gate::MutationResult::STALE);
    BOOST_CHECK(!authority);
    BOOST_CHECK(publication_hold);

    // A negative proof observed before the barrier may revoke old authority,
    // but it cannot invalidate the in-flight writer's completion capability.
    BOOST_CHECK(gate.Revoke(revoke) == Gate::MutationResult::APPLIED);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.CompletePublication(*publication) ==
                Gate::MutationResult::APPLIED);
    const auto after_barrier{gate.ObserveReady()};
    BOOST_REQUIRE(after_barrier);
    const auto competing_proof{after_barrier};
    BOOST_CHECK(gate.TryPublish(*after_barrier, [&] {
        authority = true;
        publication_hold = false;
        return true;
    }) == Gate::MutationResult::APPLIED);
    BOOST_CHECK(authority);
    BOOST_CHECK(!publication_hold);
    std::size_t duplicate_publishes{0};
    BOOST_CHECK(gate.TryPublish(*competing_proof, [&] {
        ++duplicate_publishes;
        return true;
    }) == Gate::MutationResult::STALE);
    BOOST_CHECK_EQUAL(duplicate_publishes, 0U);

    const auto before_revoke{gate.ObserveReady()};
    BOOST_REQUIRE(before_revoke);
    BOOST_CHECK(gate.Revoke(revoke) == Gate::MutationResult::APPLIED);
    BOOST_CHECK(!authority);
    BOOST_CHECK(gate.TryPublish(*before_revoke, [&] {
        ++duplicate_publishes;
        return true;
    }) == Gate::MutationResult::STALE);
    BOOST_CHECK_EQUAL(duplicate_publishes, 0U);

    // A failure observation is conservative even when it was built beside a
    // successful proof; it must invalidate the published erase authority.
    const auto after_revoke{gate.ObserveReady()};
    BOOST_REQUIRE(after_revoke);
    BOOST_CHECK_NE(*after_revoke, *competing_proof);
}

BOOST_AUTO_TEST_CASE(auxiliary_gc_authority_overlapping_publications_complete_last)
{
    using Gate = llmq::AuxiliaryHistoryGCAuthorizationGate;
    Gate gate;
    bool authority{true};
    std::size_t arms{0};
    std::size_t revocations{0};
    const auto revoke = [&] {
        ++revocations;
        authority = false;
        return true;
    };
    const auto arm = [&] {
        ++arms;
        return true;
    };

    BOOST_REQUIRE(gate.Start(revoke));
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto stale_proof{gate.ObserveReady()};
    BOOST_REQUIRE(stale_proof);

    const auto first{gate.ArmPublication(arm)};
    const auto second{gate.ArmPublication(arm)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);
    BOOST_CHECK_EQUAL(*first, *second);
    BOOST_CHECK_EQUAL(arms, 2U);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.TryPublish(*stale_proof, [] { return true; }) ==
                Gate::MutationResult::STALE);

    BOOST_CHECK(!gate.SetHealthy(false, revoke));
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.CompletePublication(*first) ==
                Gate::MutationResult::APPLIED);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.CompletePublication(*second) ==
                Gate::MutationResult::APPLIED);
    BOOST_CHECK(gate.ObserveReady());
    BOOST_CHECK_EQUAL(revocations, 2U);
}

BOOST_AUTO_TEST_CASE(auxiliary_gc_authority_failure_is_sticky)
{
    using Gate = llmq::AuxiliaryHistoryGCAuthorizationGate;
    Gate gate;
    bool authority{false};
    bool publication_hold{false};
    const auto revoke = [&] {
        authority = false;
        return true;
    };

    BOOST_REQUIRE(gate.Start(revoke));
    BOOST_REQUIRE(gate.SetHealthy(true, revoke));
    const auto before_failure{gate.ObserveReady()};
    BOOST_REQUIRE(before_failure);
    authority = true;
    gate.Fail(revoke);
    BOOST_CHECK(!authority);
    BOOST_CHECK(!gate.ObserveReady());
    BOOST_CHECK(gate.TryPublish(*before_failure, [&] {
        authority = true;
        return true;
    }) == Gate::MutationResult::STALE);
    BOOST_CHECK(!gate.Start(revoke));
    BOOST_CHECK(!gate.SetHealthy(true, revoke));

    // Late certificate ingress may only strengthen retention after failure.
    BOOST_CHECK(!gate.ArmPublication([&] {
        publication_hold = true;
        return true;
    }));
    BOOST_CHECK(publication_hold);
    BOOST_CHECK(!authority);

    Gate rejected_publication;
    BOOST_REQUIRE(rejected_publication.Start([] { return true; }));
    BOOST_REQUIRE(rejected_publication.SetHealthy(
        true, [] { return true; }));
    const auto rejected_token{rejected_publication.ObserveReady()};
    BOOST_REQUIRE(rejected_token);
    BOOST_CHECK(rejected_publication.TryPublish(
                    *rejected_token, [] { return false; }) ==
                Gate::MutationResult::FAILED);
    BOOST_CHECK(!rejected_publication.ObserveReady());
    BOOST_CHECK(!rejected_publication.Start([] { return true; }));
}

BOOST_AUTO_TEST_CASE(payment_audit_receipt_cache_is_exact_context_bound)
{
    llmq::PaymentAuditReceiptCache cache;
    const auto key{PaymentAuditReceiptCacheKey(1)};
    const auto receipt{NonNullPaymentAuditReceipt(1)};

    const auto published{cache.Publish(key, receipt)};
    BOOST_REQUIRE(published);
    BOOST_CHECK(*published == receipt);
    const auto cached{cache.Get(key)};
    BOOST_REQUIRE(cached);
    BOOST_CHECK(*cached == receipt);

    const auto expect_miss = [&](auto mutate) {
        auto different{key};
        mutate(different);
        BOOST_CHECK(!cache.Get(different));
    };
    expect_miss([](auto& different) {
        different.carrier_parent_hash = NonNullHash(90'001);
    });
    expect_miss([](auto& different) {
        ++different.carrier_parent_height;
    });
    expect_miss([](auto& different) {
        different.parent_probation_state_hash = NonNullHash(90'002);
    });
    expect_miss([](auto& different) { ++different.carrier_height; });
    expect_miss([](auto& different) { ++different.epoch; });
    expect_miss([](auto& different) { ++different.archive_revision; });

    const auto duplicate{cache.Publish(key, receipt)};
    BOOST_REQUIRE(duplicate);
    BOOST_CHECK(*duplicate == receipt);

    auto conflicting{receipt};
    conflicting.result_hash = NonNullHash(90'003);
    BOOST_REQUIRE(conflicting.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, conflicting));
    const auto retained{cache.Get(key)};
    BOOST_REQUIRE(retained);
    BOOST_CHECK(*retained == receipt);

    const auto before_null{cache.StatsForTesting()};
    BOOST_CHECK(!cache.Publish(PaymentAuditReceiptCacheKey(2), {}));
    const auto after_null{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(after_null.entries, before_null.entries);
    BOOST_CHECK_EQUAL(after_null.builds, before_null.builds);
    BOOST_CHECK_EQUAL(after_null.conflicts, before_null.conflicts);

    BOOST_CHECK_EQUAL(after_null.entries, 1U);
    BOOST_CHECK_EQUAL(after_null.hits, 2U);
    BOOST_CHECK_EQUAL(after_null.builds, 3U);
    BOOST_CHECK_EQUAL(after_null.conflicts, 1U);
}

BOOST_AUTO_TEST_CASE(payment_audit_receipt_cache_is_bounded_and_clearable)
{
    llmq::PaymentAuditReceiptCache cache;
    std::array<llmq::PaymentAuditReceiptCache::Key,
               llmq::PaymentAuditReceiptCache::CAPACITY + 1> keys;
    const auto receipt{NonNullPaymentAuditReceipt(3)};
    for (std::size_t index{0}; index < keys.size(); ++index) {
        keys[index] = PaymentAuditReceiptCacheKey(100 + index);
        BOOST_REQUIRE(cache.Publish(keys[index], receipt));
    }

    auto stats{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(stats.entries,
                      llmq::PaymentAuditReceiptCache::CAPACITY);
    BOOST_CHECK_EQUAL(stats.builds, keys.size());
    BOOST_CHECK(!cache.Get(keys.front()));
    BOOST_REQUIRE(cache.Get(keys.back()));

    cache.Clear();
    stats = cache.StatsForTesting();
    BOOST_CHECK_EQUAL(stats.entries, 0U);
    BOOST_CHECK(!cache.Get(keys.back()));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_preserves_order_and_receipt_fields)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_parity"};
    const uint256 genesis_hash{NonNullHash(91'000)};
    constexpr uint32_t epoch{21};
    const auto pinned{MakePaymentAuditCandidate(epoch, 0x0b, 10)};
    const auto late_slot{MakePaymentAuditCandidate(epoch, 0x07, 11)};
    const auto early_slot{MakePaymentAuditCandidate(epoch, 0x0e, 12)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          pinned)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.PinReferencedWitness(
                      epoch, pinned.GetWitnessId(genesis_hash)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          late_slot)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          early_slot)) ==
                  PaymentAuditStoreResult::ACCEPTED);

    PaymentAuditCandidateMetadataCache cache;
    const auto compact{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(compact);
    BOOST_CHECK(compact->IsStructurallyValid());
    const auto full{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(full);
    BOOST_CHECK_EQUAL(compact->candidate_revision, full->revision);
    BOOST_REQUIRE_EQUAL(compact->ordered_candidates.size(),
                        full->ordered_candidates.size());

    for (std::size_t index{0};
         index < full->ordered_candidates.size(); ++index) {
        const auto& source{full->ordered_candidates[index]};
        const auto& metadata{compact->ordered_candidates[index]};
        const auto classification{ClassifyPaymentAuditReports(source.audit)};
        BOOST_REQUIRE(classification);
        BOOST_CHECK(metadata.statement == source.audit.statement);
        BOOST_CHECK(metadata.logical_id == source.logical_id);
        BOOST_CHECK(metadata.witness_id == source.witness_id);
        BOOST_CHECK(metadata.commitment_hash ==
                    GetPaymentAuditCommitmentHash(
                        genesis_hash, source.audit.statement.commitment));
        BOOST_CHECK(metadata.result_hash == GetPaymentAuditResultHash(
                        genesis_hash, source.audit, *classification));
        BOOST_CHECK(metadata.online_members ==
                    classification->online_members);

        const int32_t carrier_height{
            source.audit.statement.commitment.seal_height +
            static_cast<int32_t>(PAYMENT_AUDIT_RECEIPT_DELAY)};
        const uint256 next_state_hash{NonNullHash(92'000 + index)};
        const RosterBeaconSeed* subject_beacon{nullptr};
        for (const auto& seed : source.audit.statement.seal_statement
                                    .roster_beacons.active.seeds) {
            if (seed.epoch == epoch) subject_beacon = &seed;
        }
        BOOST_REQUIRE(subject_beacon);
        const PaymentAuditReceipt direct{
            PAYMENT_AUDIT_RECEIPT_VERSION,
            1,
            epoch,
            source.audit.statement.commitment.seal_height,
            source.audit.statement.seal_statement.block_hash,
            carrier_height,
            source.logical_id,
            source.witness_id,
            GetPaymentAuditCommitmentHash(
                genesis_hash, source.audit.statement.commitment),
            GetPaymentAuditResultHash(
                genesis_hash, source.audit, *classification),
            next_state_hash,
            *subject_beacon,
            classification->online_members};
        const PaymentAuditReceipt from_metadata{
            PAYMENT_AUDIT_RECEIPT_VERSION,
            1,
            epoch,
            metadata.statement.commitment.seal_height,
            metadata.statement.seal_statement.block_hash,
            carrier_height,
            metadata.logical_id,
            metadata.witness_id,
            metadata.commitment_hash,
            metadata.result_hash,
            next_state_hash,
            *subject_beacon,
            metadata.online_members};
        BOOST_REQUIRE(direct.IsStructurallyValid());
        BOOST_REQUIRE(from_metadata.IsStructurallyValid());
        BOOST_CHECK(from_metadata == direct);
    }

    const auto repeated{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated);
    BOOST_CHECK(repeated == compact);
    auto stats{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(stats.builds, 1U);
    BOOST_CHECK_EQUAL(stats.hits, 1U);

    const auto empty{cache.GetOrBuild(store, genesis_hash, epoch + 1)};
    BOOST_REQUIRE(empty);
    BOOST_CHECK(empty->IsStructurallyValid());
    BOOST_CHECK(empty->ordered_candidates.empty());
    const auto repeated_empty{
        cache.GetOrBuild(store, genesis_hash, epoch + 1)};
    BOOST_REQUIRE(repeated_empty);
    BOOST_CHECK(repeated_empty == empty);
    stats = cache.StatsForTesting();
    BOOST_CHECK_EQUAL(stats.builds, 2U);
    BOOST_CHECK_EQUAL(stats.hits, 2U);
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_tracks_archive_revision_and_health)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_revision"};
    const uint256 genesis_hash{NonNullHash(93'000)};
    constexpr uint32_t epoch{22};
    const auto first{MakePaymentAuditCandidate(epoch, 0x07, 20)};
    const auto second{MakePaymentAuditCandidate(epoch, 0x0b, 21)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          first)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    PaymentAuditCandidateMetadataCache cache;
    const auto initial{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(initial);
    BOOST_REQUIRE_EQUAL(initial->ordered_candidates.size(), 1U);
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        initial->candidate_revision));

    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          second)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        initial->candidate_revision));
    const auto advanced{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(advanced);
    BOOST_CHECK_NE(advanced->candidate_revision,
                   initial->candidate_revision);
    BOOST_REQUIRE_EQUAL(advanced->ordered_candidates.size(), 2U);

    const uint256 second_id{second.GetWitnessId(genesis_hash)};
    BOOST_REQUIRE(store.PinReferencedWitness(epoch, second_id) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        advanced->candidate_revision));
    const auto pinned{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(pinned);
    BOOST_REQUIRE_EQUAL(pinned->ordered_candidates.size(), 1U);
    BOOST_CHECK(pinned->ordered_candidates.front().witness_id == second_id);

    BOOST_REQUIRE(store.PruneThroughCheckpoint(
        MakePaymentAuditCheckpoint(epoch, 22, 100'000)));
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        pinned->candidate_revision));
    const auto pruned{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(pruned);
    BOOST_CHECK(pruned->ordered_candidates.empty());
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        pruned->candidate_revision));
    const auto repeated{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated);
    BOOST_CHECK(repeated == pruned);

    const auto before_failures{cache.StatsForTesting()};
    BOOST_CHECK(!cache.GetOrBuild(store, uint256{}, epoch));
    BOOST_CHECK(!cache.GetOrBuild(store, uint256{}, epoch));
    const auto after_failures{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(after_failures.entries, before_failures.entries);
    BOOST_CHECK_EQUAL(after_failures.builds, before_failures.builds);

    PaymentAuditStore unhealthy{
        m_path_root / "pq_payment_audit_candidate_metadata_unhealthy",
        uint256{}};
    BOOST_CHECK(!unhealthy.IsHealthy());
    BOOST_CHECK(!cache.GetOrBuild(unhealthy, genesis_hash, epoch));
    BOOST_CHECK_EQUAL(cache.StatsForTesting().builds,
                      before_failures.builds);
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_exact_compatibility_fences_stale_negative)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_compatibility"};
    const uint256 genesis_hash{NonNullHash(93'500)};
    constexpr uint32_t epoch{24};
    const auto completed{MakePaymentAuditCandidate(epoch, 0x07, 25)};
    const auto incompatible{MakePaymentAuditCandidate(epoch, 0x0b, 26)};

    PaymentAuditStore store{path, genesis_hash};
    PaymentAuditCandidateMetadataCache cache;
    const auto healthy_empty{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(healthy_empty);
    BOOST_CHECK(healthy_empty->ordered_candidates.empty());
    BOOST_CHECK(!healthy_empty->ContainsExactStatement(
        completed.statement));
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        healthy_empty->candidate_revision));

    const auto repeated_empty{
        cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated_empty);
    BOOST_CHECK(repeated_empty == healthy_empty);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().builds, 1U);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().hits, 1U);

    // A negative decision is usable only while its exact archive revision is
    // still current. Installing the matching witness invalidates it before a
    // runtime can be retained or published.
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          completed)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        healthy_empty->candidate_revision));
    BOOST_CHECK(!healthy_empty->ContainsExactStatement(
        completed.statement));

    const auto refreshed{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(refreshed);
    BOOST_CHECK_NE(refreshed->candidate_revision,
                   healthy_empty->candidate_revision);
    BOOST_CHECK(refreshed->ContainsExactStatement(completed.statement));
    BOOST_CHECK(!refreshed->ContainsExactStatement(incompatible.statement));
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        refreshed->candidate_revision));

    const auto full{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(full);
    const auto matches_full = [&](const PaymentAuditStatement& statement) {
        return std::any_of(
            full->ordered_candidates.begin(),
            full->ordered_candidates.end(),
            [&](const auto& candidate) {
                return IsPaymentAuditCandidateCompatible(
                    candidate.audit, statement);
            });
    };
    BOOST_CHECK_EQUAL(
        refreshed->ContainsExactStatement(completed.statement),
        matches_full(completed.statement));
    BOOST_CHECK_EQUAL(
        refreshed->ContainsExactStatement(incompatible.statement),
        matches_full(incompatible.statement));

    PaymentAuditStatement invalid_statement;
    BOOST_CHECK(!refreshed->ContainsExactStatement(invalid_statement));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_cache_is_exact_bounded_and_clearable)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_conflict"};
    const uint256 genesis_hash{NonNullHash(94'000)};
    constexpr uint32_t epoch{23};
    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          MakePaymentAuditCandidate(epoch, 0x07, 30))) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(
                      llmq::test::CChainLocksHandlerTestAccess::VerifiedPaymentAudit(
                          MakePaymentAuditCandidate(epoch, 0x0b, 31))) ==
                  PaymentAuditStoreResult::ACCEPTED);

    PaymentAuditCandidateMetadataCache source_cache;
    const auto source{source_cache.GetOrBuild(
        store, genesis_hash, epoch)};
    BOOST_REQUIRE(source);
    const PaymentAuditCandidateMetadataCache::Key key{
        epoch, source->candidate_revision};

    auto duplicate_logical_ids{*source};
    duplicate_logical_ids.ordered_candidates[1].logical_id =
        duplicate_logical_ids.ordered_candidates[0].logical_id;
    BOOST_CHECK(duplicate_logical_ids.IsStructurallyValid());
    auto duplicate_witness_ids{duplicate_logical_ids};
    duplicate_witness_ids.ordered_candidates[1].witness_id =
        duplicate_witness_ids.ordered_candidates[0].witness_id;
    BOOST_CHECK(!duplicate_witness_ids.IsStructurallyValid());
    auto invalid_online_subset{*source};
    invalid_online_subset.ordered_candidates[0]
        .statement.commitment.subject_valid_members[0] &=
        static_cast<uint8_t>(~uint8_t{1});
    BOOST_CHECK(!invalid_online_subset.IsStructurallyValid());

    PaymentAuditCandidateMetadataCache cache;
    const auto published{cache.Publish(key, *source)};
    BOOST_REQUIRE(published);
    BOOST_CHECK(cache.Get(key) == published);
    BOOST_CHECK(!cache.Get({epoch + 1, key.candidate_revision}));
    BOOST_CHECK(!cache.Get({epoch, key.candidate_revision + 1}));

    auto reordered{*source};
    std::reverse(reordered.ordered_candidates.begin(),
                 reordered.ordered_candidates.end());
    BOOST_REQUIRE(reordered.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, std::move(reordered)));
    BOOST_CHECK(cache.Get(key) == published);

    auto changed_statement{*source};
    changed_statement.ordered_candidates.front()
        .statement.commitment.seed.future_btc_hash = NonNullHash(95'000);
    BOOST_REQUIRE(changed_statement.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, std::move(changed_statement)));
    BOOST_CHECK(cache.Get(key) == published);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().conflicts, 2U);

    PaymentAuditCandidateMetadataSnapshot invalid;
    BOOST_CHECK(!cache.Publish({}, std::move(invalid)));
    const auto before_fill{cache.StatsForTesting()};

    std::array<PaymentAuditCandidateMetadataCache::Key,
               PaymentAuditCandidateMetadataCache::CAPACITY + 1> keys;
    PaymentAuditCandidateMetadataSnapshotPtr held;
    for (std::size_t index{0}; index < keys.size(); ++index) {
        keys[index] = {epoch + 1,
                       static_cast<uint64_t>(1'000 + index)};
        auto value{cache.Publish(
            keys[index],
            PaymentAuditCandidateMetadataSnapshot{
                keys[index].candidate_revision,
                keys[index].epoch,
                {}})};
        BOOST_REQUIRE(value);
        if (index == 0) held = std::move(value);
    }
    BOOST_REQUIRE(held);
    BOOST_CHECK(held->ordered_candidates.empty());
    BOOST_CHECK_EQUAL(cache.StatsForTesting().entries,
                      PaymentAuditCandidateMetadataCache::CAPACITY);
    BOOST_CHECK(!cache.Get(key));
    BOOST_CHECK(cache.Get(keys.back()));

    cache.Clear();
    BOOST_CHECK_EQUAL(cache.StatsForTesting().entries, 0U);
    BOOST_CHECK(!cache.Get(keys.back()));
    BOOST_CHECK(held->IsStructurallyValid());
    BOOST_CHECK_EQUAL(before_fill.conflicts, 2U);
}

BOOST_AUTO_TEST_CASE(share_admission_gate_rejects_competing_observations)
{
    llmq::ShareAdmissionGate gate;
    gate.SetReady(true);
    const auto stale_enable{gate.Observe()};
    const auto newer_disable{stale_enable};
    BOOST_CHECK(gate.TryPublishEnabled(newer_disable, false));
    BOOST_CHECK(!gate.TryPublishEnabled(stale_enable, true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    const auto enable{gate.Observe()};
    const auto stale_disable{enable};
    BOOST_CHECK(gate.TryPublishEnabled(enable, true));
    const uint64_t token{gate.Acquire()};
    BOOST_REQUIRE_NE(token, 0U);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    BOOST_CHECK_EQUAL(gate.Acquire(), token);
    BOOST_CHECK(!gate.TryPublishEnabled(stale_disable, false));
    BOOST_CHECK(gate.IsCurrent(token));
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK(!gate.IsCurrent(token));

    gate.SetReady(false);
    const auto stopped_enable{gate.Observe()};
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK(!gate.TryPublishEnabled(stopped_enable, true));
    gate.SetReady(true);
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
}

BOOST_AUTO_TEST_CASE(startup_slot_consumption_is_limited_to_live_rounds)
{
    const llmq::pq::ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    BOOST_REQUIRE(chainlock.IsValid());
    BOOST_CHECK(llmq::ShouldConsumeChainLockStartupSlot(
        chainlock, /*startup_tip_height=*/885, /*target_height=*/880));
    BOOST_CHECK(!llmq::ShouldConsumeChainLockStartupSlot(
        chainlock, /*startup_tip_height=*/885, /*target_height=*/885));
}

BOOST_AUTO_TEST_CASE(staged_initialization_keeps_one_fixed_signing_window)
{
    const llmq::pq::ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    const llmq::pq::BTCCScheduleConfig btcc{.candidate_origin = 865};
    BOOST_REQUIRE(chainlock.IsValid());
    BOOST_REQUIRE(btcc.IsValid());

    const auto target{llmq::pq::CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, /*epoch=*/3)};
    BOOST_REQUIRE(target);
    BOOST_CHECK_EQUAL(*target, 865);
    BOOST_CHECK(!llmq::pq::CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, /*epoch=*/4));

    llmq::pq::RosterRecoveryPrecommit precommit;
    precommit.pending_seed.anchor_kind =
        llmq::pq::RosterBeaconAnchorKind::NORMAL;
    precommit.pending_seed.state =
        llmq::pq::RosterBeaconState::PENDING;
    precommit.pending_seed.epoch = 3;
    precommit.pending_seed.anchor_cursor = llmq::pq::BTCCursor{
        *target, NonNullHash(210'000), NonNullHash(210'001)};
    precommit.pending_seed.anchor_btc_height = 800'000;
    BOOST_REQUIRE(precommit.IsStructurallyValid());

    const auto first{llmq::StagedRecoverySigningWindow(
        chainlock, btcc, precommit,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/870)};
    const auto much_later{llmq::StagedRecoverySigningWindow(
        chainlock, btcc, precommit,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/5'000)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(much_later);
    BOOST_CHECK(*first == *much_later);
    BOOST_CHECK_EQUAL(first->target_height, *target);
    BOOST_CHECK_EQUAL(first->declared_predecessor_height, 864);
    BOOST_CHECK(!llmq::StagedRecoverySigningWindow(
        chainlock, btcc, precommit,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/869));

    auto wrong_target{precommit};
    wrong_target.pending_seed.anchor_cursor.sys_height +=
        static_cast<int32_t>(chainlock.chainlock_period);
    BOOST_CHECK(!llmq::StagedRecoverySigningWindow(
        chainlock, btcc, wrong_target,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/5'000));

    auto later_initialization{precommit};
    later_initialization.pending_seed.epoch = 7;
    later_initialization.pending_seed.anchor_cursor.sys_height = 2'017;
    BOOST_REQUIRE(later_initialization.IsStructurallyValid());
    BOOST_CHECK(!llmq::StagedRecoverySigningWindow(
        chainlock, btcc, later_initialization,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/5'000));

    auto ready{precommit};
    ready.pending_seed.state = llmq::pq::RosterBeaconState::READY;
    ready.pending_seed.future_btc_hash = NonNullHash(210'002);
    BOOST_REQUIRE(ready.IsStructurallyValid());
    const auto ready_window{llmq::StagedRecoverySigningWindow(
        chainlock, btcc, ready,
        /*durable_predecessor_height=*/864,
        /*tip_height=*/5'000)};
    BOOST_REQUIRE(ready_window);
    BOOST_CHECK(*ready_window == *first);
}

BOOST_AUTO_TEST_CASE(payment_audit_signing_height_is_exactly_window_bounded)
{
    const llmq::pq::ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    BOOST_REQUIRE(chainlock.IsValid());
    const llmq::pq::PaymentAuditScheduleConfig audit{
        chainlock,
        llmq::pq::BTCCScheduleConfig{.candidate_origin = 865},
    };
    BOOST_REQUIRE(audit.IsValid());
    const auto round{llmq::pq::BuildPaymentAuditEpochSchedule(
        audit, /*epoch=*/3)};
    BOOST_REQUIRE(round);
    const auto first_signing{llmq::pq::SigningHeightForTarget(
        chainlock, round->seal_height)};
    BOOST_REQUIRE(first_signing);
    BOOST_CHECK(!llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, *first_signing - 1));
    BOOST_CHECK(llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, *first_signing));
    BOOST_CHECK(llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, round->carrier_end_height_exclusive - 1));
    BOOST_CHECK(!llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, round->carrier_end_height_exclusive));
    BOOST_CHECK(!llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, *first_signing - 1));
    BOOST_CHECK(llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, *first_signing));
    // SYSCOIN: A deep reorg can revive an old carrier window, so a startup
    // floor beyond that window must still retire an absent old leaf.
    BOOST_CHECK(llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, round->carrier_end_height_exclusive));
}

BOOST_AUTO_TEST_CASE(
    btcc_certificate_history_expiry_includes_signing_lag)
{
    using namespace llmq::pq;

    auto config{CatchupStoreConfig()};
    config.recent_chainlocks_capacity = DEFAULT_RECENT_CHAINLOCKS_SIZE;
    BOOST_REQUIRE(config.IsValid());
    constexpr int32_t TARGET{870};
    BTCCReceipt receipt;
    receipt.chainlock_target_height = TARGET;
    receipt.chainlock_target_hash = NonNullHash(210'400);
    receipt.chainlock_logical_id = NonNullHash(210'401);
    receipt.accepted_cursor = {
        TARGET, receipt.chainlock_target_hash, NonNullHash(210'402)};
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    const auto serve_until{
        llmq::BTCCCertificateServeUntilHeight(config, receipt)};
    BOOST_REQUIRE(serve_until);
    BOOST_CHECK_EQUAL(
        *serve_until,
        TARGET +
            static_cast<int32_t>(config.recent_chainlocks_capacity) *
                config.chainlock_schedule.chainlock_period +
            config.chainlock_schedule.sign_lag);
    BOOST_CHECK_EQUAL(*serve_until, TARGET + 45);

    config.recent_chainlocks_capacity = 1;
    BOOST_REQUIRE(config.IsValid());
    const auto single_slot{
        llmq::BTCCCertificateServeUntilHeight(config, receipt)};
    BOOST_REQUIRE(single_slot);
    BOOST_CHECK_EQUAL(*single_slot, TARGET + 10);

    receipt.chainlock_target_height =
        std::numeric_limits<int32_t>::max() - 9;
    receipt.accepted_cursor.sys_height =
        receipt.chainlock_target_height;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    BOOST_CHECK(!llmq::BTCCCertificateServeUntilHeight(config, receipt));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_seal_resolution_survives_eviction_and_restart)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;

    const uint256 genesis{NonNullHash(210'500)};
    auto config{CatchupStoreConfig()};
    config.recent_chainlocks_capacity =
        DEFAULT_RECENT_CHAINLOCKS_SIZE;
    FullReceiptCatchupContext context;
    context.full_receipt_history = true;
    ChainLockFinalityStore store{genesis, config, context};

    auto seal{MakeCatchupChainLock(
        /*height=*/865,
        config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 210'501)};
    auto accept = [&](const FinalChainLock& chainlock) {
        const auto prepared{store.PrepareCandidate(chainlock)};
        BOOST_REQUIRE_MESSAGE(
            prepared,
            "failed to prepare fixture CLSIG at height " <<
                chainlock.statement.height);
        const auto verified{ChainLockStoreTestContextFactory::Create(
            genesis, config.chainlock_schedule, chainlock.statement)};
        BOOST_REQUIRE(verified);
        BOOST_REQUIRE(store.AcceptVerified(
            *prepared, chainlock, /*signatures_valid=*/true,
            /*error=*/nullptr, verified));
    };
    accept(seal);

    auto previous{seal};
    for (std::size_t offset{1};
         offset <= DEFAULT_RECENT_CHAINLOCKS_SIZE + 1; ++offset) {
        auto next{MakeCatchupChainLock(
            seal.statement.height +
                static_cast<int32_t>(offset * PQ_CL_PERIOD),
            previous.statement.height, previous.statement.block_hash,
            210'501 + offset)};
        next.statement.previous_btcc_cursor =
            previous.statement.accepted_btcc_cursor;
        next.statement.accepted_btcc_cursor =
            previous.statement.accepted_btcc_cursor;
        accept(next);
        previous = std::move(next);
    }

    BOOST_CHECK(!store.GetRecordByHeight(seal.statement.height));
    const auto retained{Access::ResolvePaymentAuditSealRecord(
        store, genesis, seal.statement)};
    BOOST_REQUIRE(retained);
    BOOST_CHECK(retained->certificate &&
                retained->certificate->statement == seal.statement);
    BOOST_CHECK(retained->verification_context &&
                retained->verification_context->Statement() ==
                    seal.statement);

    auto wrong_seal{seal.statement};
    wrong_seal.block_hash = NonNullHash(210'999);
    BOOST_CHECK(!Access::ResolvePaymentAuditSealRecord(
        store, genesis, wrong_seal));

    ChainLockFinalityStore restarted{genesis, config, context};
    const auto trusted{
        ChainLockStoreTestContextFactory::CreateTrustedPersistence(
            genesis, config.chainlock_schedule, seal.statement)};
    BOOST_REQUIRE(trusted);
    BOOST_REQUIRE(restarted.AcceptPersistedRosterAuthorizationBase(
        seal, /*signatures_valid=*/true, trusted));
    BOOST_CHECK(!restarted.GetRecordByHeight(seal.statement.height));
    const auto restored{Access::ResolvePaymentAuditSealRecord(
        restarted, genesis, seal.statement)};
    BOOST_REQUIRE(restored);
    BOOST_CHECK(restored->certificate &&
                restored->certificate->statement == seal.statement);
    BOOST_CHECK(restored->verification_context &&
                restored->verification_context->Authorization().admission ==
                    RosterAuthorizationAdmission::TRUSTED_PERSISTENCE);
}

BOOST_AUTO_TEST_CASE(deployment_configuration_is_fail_closed)
{
    auto consensus{ValidConsensus()};
    const auto config{llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_CHECK_EQUAL(config->activation_predecessor_height,
                      consensus.nPQActivationHeight - 1);
    BOOST_CHECK_EQUAL(config->chainlock_schedule.epoch_origin,
                      consensus.nPQChainLockEpochOrigin);
    BOOST_CHECK_EQUAL(config->btcc_schedule.candidate_origin,
                      consensus.nPQBTCCCandidateOrigin);
    BOOST_CHECK_EQUAL(config->btcc_receipt_assumption_anchor.height, 1000);
    const auto first_target{llmq::pq::NextEligibleChainLockTargetHeight(
        config->chainlock_schedule, config->activation_predecessor_height)};
    BOOST_REQUIRE(first_target);
    BOOST_CHECK_EQUAL(*first_target, 2305);
    BOOST_CHECK_EQUAL(
        *llmq::pq::SigningHeightForTarget(
            config->chainlock_schedule, *first_target),
        2310);
    const auto quorum_config{llmq::MakePQQuorumBuildConfig(consensus)};
    BOOST_REQUIRE(quorum_config);
    BOOST_CHECK_EQUAL(quorum_config->registration_cutoff_blocks, 288U);
    BOOST_CHECK_EQUAL(quorum_config->roster_snapshot_lag_blocks, 288U);

    consensus = ValidConsensus();
    consensus.nPQChainLockEpochOrigin = 2880;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQRosterSnapshotLag = 288;
    BOOST_CHECK(llmq::MakePQQuorumBuildConfig(consensus));
    consensus.nPQRegistrationCutoffBlocks = 289;
    consensus.nPQRosterSnapshotLag = 289;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQRosterSnapshotLag = llmq::pq::PQ_CL_SIGN_LAG - 1;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));
    consensus.nPQRosterSnapshotLag = llmq::pq::PQ_CL_SIGN_LAG;
    BOOST_CHECK(llmq::MakePQQuorumBuildConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQPreparationHeight = 500;
    consensus.nPQRegistrationCutoffBlocks = 844;
    BOOST_CHECK(llmq::MakePQQuorumBuildConfig(consensus));
    consensus.nPQRegistrationCutoffBlocks = 845;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQActivationHeight = consensus.DIP0003Height - 1;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQActivationHeight =
        consensus.nPQBTCCCandidateOrigin + 1;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQChainLockEpochOrigin++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQFutureHorizonEpochs = 0;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQRegistrationCutoffBlocks = 144;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCNEVMInjectionLag++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCCandidateOrigin++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQBTCCReceiptAnchorBlock.SetNull();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 1001;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 1000;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 999;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = 2321;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = 2325;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus.nDefaultAssumeValidHeight = 1000;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 1001;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 2325;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));
}

BOOST_AUTO_TEST_CASE(btcc_preseal_recovery_floor_is_lower_only)
{
    auto expanded_consensus{ValidConsensus()};
    expanded_consensus.nPQPreparationHeight = 500;
    expanded_consensus.nPQRegistrationCutoffBlocks = 844;
    const auto quorum_config{
        llmq::MakePQQuorumBuildConfig(expanded_consensus)};
    const auto finality_config{
        llmq::MakePQChainLockFinalityStoreConfig(ValidConsensus())};
    BOOST_REQUIRE(quorum_config);
    BOOST_REQUIRE(finality_config);

    constexpr int32_t first_target{2305};
    constexpr int32_t first_carrier{
        first_target + static_cast<int32_t>(
                           llmq::pq::PQ_BTCC_NEVM_LAG)};
    const llmq::pq::BTCCursor cursor{
        first_target - 10, NonNullHash(3'100'001),
        NonNullHash(3'100'002)};
    const llmq::pq::BTCCReceiptState predecessor{
        cursor, NonNullHash(3'100'003), first_target - 10,
        first_carrier - 10};
    BOOST_REQUIRE(predecessor.IsStructurallyValid());
    llmq::pq::BTCCReceipt first_receipt;
    first_receipt.chainlock_target_height = first_target;
    first_receipt.chainlock_target_hash = NonNullHash(3'100'004);
    first_receipt.chainlock_logical_id = NonNullHash(3'100'005);
    first_receipt.accepted_cursor = cursor;
    BOOST_REQUIRE(first_receipt.IsStructurallyValid());
    llmq::pq::BTCCPresealMarker marker{
        first_carrier, NonNullHash(3'100'006), predecessor,
        first_carrier, NonNullHash(3'100'006), predecessor,
        first_receipt, 1};
    const auto initial_floor{
        llmq::GetBTCCPresealAuxiliaryRetentionFloor(
            llmq::pq::BTCCPresealState{marker, std::nullopt},
            *quorum_config, *finality_config)};
    BOOST_REQUIRE(initial_floor);
    BOOST_CHECK_EQUAL(*initial_floor, 1152);

    const llmq::pq::BTCCReceiptState terminal_parent{
        cursor, NonNullHash(3'100'007), first_target, first_carrier};
    BOOST_REQUIRE(terminal_parent.IsStructurallyValid());
    marker.terminal_carrier_height = first_carrier + 10;
    marker.terminal_carrier_hash = NonNullHash(3'100'008);
    marker.terminal_parent_receipt_state = terminal_parent;
    marker.terminal_receipt.chainlock_target_height = first_target + 10;
    marker.terminal_receipt.chainlock_target_hash =
        NonNullHash(3'100'009);
    marker.terminal_receipt.chainlock_logical_id =
        NonNullHash(3'100'010);
    BOOST_REQUIRE(marker.IsStructurallyValid());
    const auto advanced_floor{
        llmq::GetBTCCPresealAuxiliaryRetentionFloor(
            llmq::pq::BTCCPresealState{marker, std::nullopt},
            *quorum_config, *finality_config)};
    BOOST_REQUIRE(advanced_floor);
    BOOST_CHECK_EQUAL(*advanced_floor, *initial_floor);

    // INITIALIZE may use a later carrier, but its roster dependency remains
    // the one fixed activation target rather than carrier-lag arithmetic.
    marker.predecessor_receipt_state = {};
    marker.terminal_parent_receipt_state = {};
    marker.earliest_carrier_height = first_carrier + 10;
    marker.earliest_carrier_hash = NonNullHash(3'100'011);
    marker.terminal_carrier_height = marker.earliest_carrier_height;
    marker.terminal_carrier_hash = marker.earliest_carrier_hash;
    marker.terminal_receipt = first_receipt;
    BOOST_REQUIRE(marker.IsStructurallyValid());
    const auto late_initial_floor{
        llmq::GetBTCCPresealAuxiliaryRetentionFloor(
            llmq::pq::BTCCPresealState{marker, std::nullopt},
            *quorum_config, *finality_config)};
    BOOST_REQUIRE(late_initial_floor);
    BOOST_CHECK_EQUAL(*late_initial_floor, *initial_floor);

    // The first recovery group must cover the carrier C itself, not merely
    // its ordinary receipt source E=C-10. Equality uses the current group;
    // once C passes that canonical target, the next four-epoch group owns R.
    const auto canonical{llmq::pq::CanonicalRosterRecoveryTargetHeight(
        finality_config->chainlock_schedule,
        finality_config->btcc_schedule, /*epoch=*/7)};
    BOOST_REQUIRE(canonical);
    const auto current_recovery_floor{llmq::pq::RegistrationCutoffHeight(
        quorum_config->schedule, /*epoch=*/4,
        quorum_config->registration_cutoff_blocks)};
    BOOST_REQUIRE(current_recovery_floor);
    marker.predecessor_receipt_state = predecessor;
    const auto set_carrier = [&](int32_t carrier_height) {
        marker.earliest_carrier_height = carrier_height;
        marker.earliest_carrier_hash =
            NonNullHash(3'200'000 + carrier_height);
        marker.terminal_carrier_height = carrier_height;
        marker.terminal_carrier_hash = marker.earliest_carrier_hash;
        marker.terminal_parent_receipt_state = predecessor;
        marker.terminal_receipt = first_receipt;
        BOOST_REQUIRE(marker.IsStructurallyValid());
        return llmq::GetBTCCPresealAuxiliaryRetentionFloor(
            llmq::pq::BTCCPresealState{marker, std::nullopt},
            *quorum_config, *finality_config);
    };
    const auto before_recovery{set_carrier(*canonical - 10)};
    const auto exact_recovery{set_carrier(*canonical)};
    const auto after_recovery{set_carrier(*canonical + 10)};
    BOOST_REQUIRE(before_recovery);
    BOOST_REQUIRE(exact_recovery);
    BOOST_REQUIRE(after_recovery);
    BOOST_CHECK_EQUAL(*before_recovery, *current_recovery_floor);
    BOOST_CHECK_EQUAL(*exact_recovery, *current_recovery_floor);
    BOOST_CHECK_EQUAL(*after_recovery, 2304);

    // All four receipt-epoch phases map to the first phase-3 epoch at least
    // two epochs later. The chosen carrier equals that canonical target, so
    // R belongs to the current recovery group in every case.
    for (uint32_t phase{0}; phase < llmq::pq::ACTIVE_QUORUMS; ++phase) {
        const uint32_t receipt_epoch{8 + phase};
        const auto receipt_base{llmq::pq::EpochBaseHeight(
            quorum_config->schedule, receipt_epoch)};
        BOOST_REQUIRE(receipt_base);
        const int32_t receipt_target{*receipt_base + 5};
        marker.predecessor_receipt_state = llmq::pq::BTCCReceiptState{
            llmq::pq::BTCCursor{
                receipt_target, NonNullHash(3'300'000 + phase),
                NonNullHash(3'310'000 + phase)},
            NonNullHash(3'320'000 + phase), receipt_target,
            receipt_target + 10};
        BOOST_REQUIRE(marker.predecessor_receipt_state.IsStructurallyValid());
        const uint32_t minimum_epoch{receipt_epoch + 2};
        const uint32_t recovery_epoch{static_cast<uint32_t>(
            minimum_epoch +
            (llmq::pq::ACTIVE_QUORUMS - 1 +
             llmq::pq::ACTIVE_QUORUMS -
             minimum_epoch % llmq::pq::ACTIVE_QUORUMS) %
                llmq::pq::ACTIVE_QUORUMS)};
        const auto recovery_target{
            llmq::pq::CanonicalRosterRecoveryTargetHeight(
                finality_config->chainlock_schedule,
                finality_config->btcc_schedule, recovery_epoch)};
        const auto recovery_floor{llmq::pq::RegistrationCutoffHeight(
            quorum_config->schedule,
            recovery_epoch - (llmq::pq::ACTIVE_QUORUMS - 1),
            quorum_config->registration_cutoff_blocks)};
        BOOST_REQUIRE(recovery_target);
        BOOST_REQUIRE(recovery_floor);
        const auto phase_floor{set_carrier(*recovery_target)};
        BOOST_REQUIRE(phase_floor);
        BOOST_CHECK_EQUAL(*phase_floor, *recovery_floor);
    }
}

BOOST_AUTO_TEST_CASE(live_chainlock_candidates_are_current_and_one_window_bound)
{
    const auto schedule{
        llmq::pq::MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);

    std::array<CBlockIndex, 21> active;
    std::array<uint256, 21> active_hashes;
    for (std::size_t offset{0}; offset < active.size(); ++offset) {
        active_hashes[offset] = NonNullHash(50'000 + offset);
        active[offset].nHeight = 870 + static_cast<int32_t>(offset);
        active[offset].phashBlock = &active_hashes[offset];
        active[offset].pprev = offset == 0 ? nullptr : &active[offset - 1];
    }

    std::array<CBlockIndex, 5> shallow_fork;
    std::array<uint256, 5> shallow_hashes;
    for (std::size_t offset{0}; offset < shallow_fork.size(); ++offset) {
        shallow_hashes[offset] = NonNullHash(51'000 + offset);
        shallow_fork[offset].nHeight = 871 + static_cast<int32_t>(offset);
        shallow_fork[offset].phashBlock = &shallow_hashes[offset];
        shallow_fork[offset].pprev =
            offset == 0 ? &active[0] : &shallow_fork[offset - 1];
    }

    // At tip 880, target 875 is the current signable round. A competing
    // target that shares its height-870 boundary remains admissible.
    BOOST_CHECK(llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[10], shallow_fork.back()));

    // Advancing one round makes the same certificate stale even though its
    // target is now an ancestor of one known branch.
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], shallow_fork.back()));
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], active[5]));
    BOOST_CHECK(llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], active[10]));

    std::array<CBlockIndex, 6> deep_fork;
    std::array<uint256, 6> deep_hashes;
    for (std::size_t offset{0}; offset < deep_fork.size(); ++offset) {
        deep_hashes[offset] = NonNullHash(52'000 + offset);
        deep_fork[offset].nHeight = 870 + static_cast<int32_t>(offset);
        deep_fork[offset].phashBlock = &deep_hashes[offset];
        deep_fork[offset].pprev =
            offset == 0 ? nullptr : &deep_fork[offset - 1];
    }
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[10], deep_fork.back()));

    std::array<CBlockIndex, 5> current_side_fork;
    std::array<uint256, 5> current_side_hashes;
    for (std::size_t offset{0}; offset < current_side_fork.size(); ++offset) {
        current_side_hashes[offset] = NonNullHash(53'000 + offset);
        current_side_fork[offset].nHeight =
            876 + static_cast<int32_t>(offset);
        current_side_fork[offset].phashBlock =
            &current_side_hashes[offset];
        current_side_fork[offset].pprev =
            offset == 0 ? &active[5] : &current_side_fork[offset - 1];
    }

    // Recovery uses the same current-round fork bound as LIVE: a competing
    // target may win while it shares the H-5 boundary, but expires with the
    // round and a deeper fork is never admissible.
    BOOST_CHECK(llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], active[10]));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], active[5]));
    BOOST_CHECK(llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], current_side_fork.back()));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[20], active[10]));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[20], current_side_fork.back()));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[10], deep_fork.back()));
}

BOOST_AUTO_TEST_CASE(
    current_btcc_selection_waits_for_and_then_obeys_the_exact_carrier)
{
    const uint256 genesis{NonNullHash(54'000)};
    const auto config{CatchupStoreConfig()};
    std::array<CBlockIndex, 17> chain;
    std::array<uint256, 17> hashes;
    LOCK(cs_main);
    for (std::size_t offset{0}; offset < chain.size(); ++offset) {
        hashes[offset] = offset == 0
            ? NonNullHash(config.activation_predecessor_height)
            : NonNullHash(54'100 + offset);
        chain[offset].nHeight = 864 + static_cast<int32_t>(offset);
        chain[offset].phashBlock = &hashes[offset];
        chain[offset].pprev = offset == 0 ? nullptr : &chain[offset - 1];
        chain[offset].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    }
    CBlockIndex& source{chain[6]};
    CBlockIndex& pre_carrier_target{chain[11]};
    CBlockIndex& carrier_target{chain[16]};
    source.btcpPrevCommitment = NonNullHash(54'200);
    carrier_target.btcpPrevCommitment = NonNullHash(54'201);

    auto advance{MakeCatchupChainLock(
        870, 865, chain[1].GetBlockHash(), 54'300)};
    advance.statement.block_hash = source.GetBlockHash();
    advance.statement.accepted_btcc_cursor = llmq::pq::BTCCursor{
        source.nHeight, source.GetBlockHash(), source.btcpPrevCommitment};
    advance.statement.btcc_advance = llmq::pq::BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(advance.IsStructurallyValid());
    const llmq::pq::FinalChainLockRecordMetadata advance_metadata{
        advance.GetLogicalId(genesis), advance.GetWitnessId(genesis),
        advance.statement};

    const auto before_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, pre_carrier_target, &advance_metadata)};
    BOOST_REQUIRE(before_carrier);
    BOOST_CHECK(before_carrier->previous_cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(before_carrier->selected.cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(before_carrier->selected.advance ==
                llmq::pq::BTCCAdvance::KEEP);
    BOOST_CHECK(!before_carrier->cursor_reconciliation);
    auto inconsistent_metadata{advance_metadata};
    inconsistent_metadata.logical_id = NonNullHash(54'302);
    BOOST_CHECK(!llmq::SelectCurrentChainLockBTCC(
        genesis, config, pre_carrier_target, &inconsistent_metadata));

    const auto at_null_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &advance_metadata)};
    BOOST_REQUIRE(at_null_carrier);
    BOOST_CHECK(at_null_carrier->previous_cursor.IsNull());
    BOOST_CHECK(at_null_carrier->selected.advance ==
                llmq::pq::BTCCAdvance::ADVANCE);
    BOOST_CHECK_EQUAL(at_null_carrier->selected.cursor.sys_height, 880);
    BOOST_REQUIRE(at_null_carrier->cursor_reconciliation);
    BOOST_CHECK_EQUAL(
        at_null_carrier->cursor_reconciliation->carrier_height, 880);

    // Catching up directly to KEEP(C) retains no ADVANCE archive, but its
    // signed cursor-vs-receipt gap yields the identical objective proof.
    auto keep{MakeCatchupChainLock(
        875, 870, source.GetBlockHash(), 54'301)};
    keep.statement.block_hash = pre_carrier_target.GetBlockHash();
    keep.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    keep.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    const llmq::pq::FinalChainLockRecordMetadata keep_metadata{
        keep.GetLogicalId(genesis), keep.GetWitnessId(genesis), keep.statement};
    const auto caught_up_at_null_carrier{
        llmq::SelectCurrentChainLockBTCC(
            genesis, config, carrier_target, &keep_metadata)};
    BOOST_REQUIRE(caught_up_at_null_carrier);
    BOOST_REQUIRE(caught_up_at_null_carrier->cursor_reconciliation);
    BOOST_CHECK(caught_up_at_null_carrier->previous_cursor.IsNull());

    // A non-null carrier advances the indexed receipt cursor to C, so there is
    // no rollback proof and both durable/indexed views select from C.
    llmq::pq::BTCCReceipt receipt;
    receipt.chainlock_target_height = advance.statement.height;
    receipt.chainlock_target_hash = advance.statement.block_hash;
    receipt.chainlock_logical_id = advance.GetLogicalId(genesis);
    receipt.accepted_cursor = advance.statement.accepted_btcc_cursor;
    const auto applied{llmq::pq::ApplyBTCCReceiptState(
        genesis, config.chainlock_schedule, config.btcc_schedule,
        /*activation_predecessor_height=*/869, carrier_target.nHeight,
        carrier_target.GetBlockHash(), {}, receipt)};
    BOOST_REQUIRE(applied);
    carrier_target.pqBTCCReceiptCursorHeight = applied->cursor.sys_height;
    carrier_target.pqBTCCReceiptCursorSysHash = applied->cursor.sys_hash;
    carrier_target.pqBTCCReceiptCursorBTCHash = applied->cursor.btc_hash;
    carrier_target.pqBTCCReceiptStateHash = applied->cumulative_hash;
    carrier_target.pqBTCCReceiptLatestTargetHeight =
        applied->latest_chainlock_target_height;
    carrier_target.pqBTCCReceiptLatestCarrierHeight =
        applied->latest_receipt_carrier_height;
    carrier_target.pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
    const auto at_nonnull_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &keep_metadata)};
    BOOST_REQUIRE(at_nonnull_carrier);
    BOOST_CHECK(at_nonnull_carrier->previous_cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(!at_nonnull_carrier->cursor_reconciliation);

    // Equal heights with a different cursor identity are never ordered.
    carrier_target.pqBTCCReceiptCursorSysHash = NonNullHash(54'999);
    BOOST_CHECK(!llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &keep_metadata));
}

BOOST_AUTO_TEST_CASE(
    current_side_candidates_cannot_orphan_durable_preseal_state)
{
    // Exact-successor LIVE and ordinary current catch-up share this publication
    // guard. Active candidates and non-current marker recovery are unchanged.
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/false,
        /*has_payment_audit_preseal=*/false));
    BOOST_CHECK(llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/false));
    BOOST_CHECK(llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/false,
        /*has_payment_audit_preseal=*/true));
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/true,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/true));
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/false,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/true));
}

BOOST_AUTO_TEST_CASE(
    marker_recovery_cannot_self_choose_an_exact_local_cursor)
{
    const llmq::pq::BTCCursor local{
        870, NonNullHash(55'000), NonNullHash(55'001)};
    const llmq::pq::BTCCursor alternate{
        865, NonNullHash(55'002), NonNullHash(55'003)};

    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/true,
        local, local));
    BOOST_CHECK(!llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/true,
        alternate, local));

    // P>S has no locally retained predecessor certificate, while CURRENT
    // derives its exceptional cursor transition from the candidate branch.
    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/false,
        alternate, local));
    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/true,
        /*declared_predecessor_is_local=*/true,
        alternate, local));
}

BOOST_AUTO_TEST_CASE(verification_worker_count_is_bounded)
{
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(0), 0U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(1), 0U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(2), 1U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(8), 7U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(256), 16U);
}

BOOST_AUTO_TEST_CASE(pruned_response_index_is_usable_only_for_history)
{
    LOCK(cs_main);
    CBlockIndex response;
    response.nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);

    BOOST_CHECK(llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/false));
    BOOST_CHECK(!llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/true));

    response.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    BOOST_CHECK(llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/true));

    response.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_VALID);
    BOOST_CHECK(!llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/false));
}

BOOST_AUTO_TEST_CASE(payment_audit_carrier_context_precedes_archive_lookup)
{
    using Status = llmq::PaymentAuditContextStatus;
    const auto chainlock{llmq::pq::MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock);
    const llmq::pq::PaymentAuditScheduleConfig config{
        *chainlock,
        llmq::pq::BTCCScheduleConfig{.candidate_origin = 865}};
    const auto schedule{
        llmq::pq::BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);

    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = schedule->epoch;
    receipt.seal_height = schedule->seal_height;
    receipt.seal_block_hash = NonNullHash(500);
    receipt.carrier_height = schedule->carrier_start_height;
    receipt.audit_logical_id = NonNullHash(501);
    receipt.audit_witness_id = NonNullHash(502);
    receipt.commitment_hash = NonNullHash(503);
    receipt.result_hash = NonNullHash(504);
    receipt.next_probation_state_hash = NonNullHash(505);
    receipt.subject_roster_beacon = SubjectBeacon(receipt.epoch);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    constexpr std::size_t PATH_CAPACITY{32};
    const auto path_size{static_cast<std::size_t>(
        receipt.carrier_height - receipt.seal_height + 1)};
    BOOST_REQUIRE(path_size <= PATH_CAPACITY);
    std::array<uint256, PATH_CAPACITY> hashes;
    std::array<CBlockIndex, PATH_CAPACITY> indexes;
    for (std::size_t i{0}; i < path_size; ++i) {
        hashes[i] = NonNullHash(600 + i);
        indexes[i].phashBlock = &hashes[i];
        indexes[i].nHeight = receipt.seal_height +
                             static_cast<int32_t>(i);
        if (i != 0) indexes[i].pprev = &indexes[i - 1];
    }
    receipt.seal_block_hash = hashes[0];

    LOCK(cs_main);
    const CBlockIndex& carrier{indexes[path_size - 1]};
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    receipt, carrier, config) == Status::READY);

    auto wrong_height{receipt};
    ++wrong_height.seal_height;
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    wrong_height, carrier, config) == Status::INVALID);
    auto wrong_hash{receipt};
    wrong_hash.seal_block_hash = NonNullHash(700);
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    wrong_hash, carrier, config) == Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    receipt, carrier,
                    llmq::pq::PaymentAuditScheduleConfig{}) ==
                Status::LOCAL_ERROR);
}

BOOST_AUTO_TEST_CASE(payment_preseal_reorg_preserves_intermediate_receipt)
{
    PaymentPresealReorgFixture fixture;
    fixture.ReorgAfter(fixture.CARRIERS[1]);
    LOCK(cs_main);
    const auto recovered{fixture.Recover()};
    BOOST_REQUIRE(recovered);
    fixture.CheckBoundary(*recovered, 1);
    BOOST_CHECK(fixture.reads == std::vector<int32_t>({1'385, 1'725}));
    // The old covering winner at 1720 cannot cover this surviving receipt.
    BOOST_CHECK_GT(recovered->terminal_carrier_height, 1'720);
}

BOOST_AUTO_TEST_CASE(payment_preseal_reorg_uses_cursor_across_null_tail)
{
    PaymentPresealReorgFixture fixture;
    fixture.ReorgAfter(1'964);
    LOCK(cs_main);
    const auto recovered{fixture.Recover()};
    BOOST_REQUIRE(recovered);
    fixture.CheckBoundary(*recovered, 1);
    BOOST_CHECK(fixture.reads == std::vector<int32_t>({1'385, 1'725}));
}

BOOST_AUTO_TEST_CASE(payment_preseal_reorg_first_receipt_is_last_survivor)
{
    PaymentPresealReorgFixture fixture;
    fixture.ReorgAfter(1'724);
    LOCK(cs_main);
    const auto recovered{fixture.Recover()};
    BOOST_REQUIRE(recovered);
    fixture.CheckBoundary(*recovered, 0);
    BOOST_CHECK(fixture.reads == std::vector<int32_t>({1'385}));
}

BOOST_AUTO_TEST_CASE(payment_preseal_reorg_waits_for_exact_carrier_data)
{
    PaymentPresealReorgFixture fixture;
    fixture.ReorgAfter(1'964);
    const auto original{fixture.marker};
    LOCK(cs_main);
    fixture.unavailable_height = fixture.CARRIERS[1];
    BOOST_CHECK(!fixture.Recover());
    BOOST_CHECK(fixture.marker == original);
    BOOST_CHECK(fixture.reads == std::vector<int32_t>({1'385, 1'725}));

    fixture.unavailable_height.reset();
    fixture.reads.clear();
    const auto recovered{fixture.Recover()};
    BOOST_REQUIRE(recovered);
    fixture.CheckBoundary(*recovered, 1);
    BOOST_CHECK(fixture.reads == std::vector<int32_t>({1'385, 1'725}));
}

BOOST_AUTO_TEST_CASE(payment_preseal_reorg_waits_for_parent_provenance)
{
    PaymentPresealReorgFixture fixture;
    fixture.ReorgAfter(1'964);
    const auto original{fixture.marker};
    LOCK(cs_main);
    for (const int32_t height : {fixture.CARRIERS[0] - 1, fixture.CARRIERS[1] - 1}) {
        auto& parent{fixture.chain.At(height)};
        const auto status{parent.nStatus};
        parent.nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
        BOOST_CHECK(!fixture.Recover());
        BOOST_CHECK(fixture.marker == original);
        parent.nStatus = status;
        const auto recovered{fixture.Recover()};
        BOOST_REQUIRE(recovered);
        fixture.CheckBoundary(*recovered, 1);
    }
}

BOOST_AUTO_TEST_CASE(deferred_payment_audit_receipt_is_exactly_carrier_bound)
{
    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = 4;
    receipt.seal_height = 1'000;
    receipt.seal_block_hash = NonNullHash(801);
    receipt.carrier_height = 1'010;
    receipt.audit_logical_id = NonNullHash(802);
    receipt.audit_witness_id = NonNullHash(803);
    receipt.commitment_hash = NonNullHash(804);
    receipt.result_hash = NonNullHash(805);
    receipt.next_probation_state_hash = NonNullHash(806);
    receipt.subject_roster_beacon = SubjectBeacon(receipt.epoch);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    CBlock block{PaymentAuditCarrierBlock(receipt)};
    const uint256 parent_hash{NonNullHash(807)};
    block.hashPrevBlock = parent_hash;
    const uint256 carrier_hash{block.GetHash()};
    const uint256 best_hash{NonNullHash(808)};
    const uint256 sibling_hash{NonNullHash(809)};

    LOCK(cs_main);
    CBlockIndex parent;
    parent.phashBlock = &parent_hash;
    parent.nHeight = receipt.carrier_height - 1;
    CBlockIndex carrier;
    carrier.phashBlock = &carrier_hash;
    carrier.pprev = &parent;
    carrier.nHeight = receipt.carrier_height;
    carrier.nTx = 1;
    carrier.nChainTx = 1;
    carrier.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    CBlockIndex best;
    best.phashBlock = &best_hash;
    best.pprev = &carrier;
    best.nHeight = carrier.nHeight + 1;
    best.nTx = 1;
    best.nChainTx = 2;
    best.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    CBlockIndex sibling;
    sibling.phashBlock = &sibling_hash;
    sibling.pprev = &parent;
    sibling.nHeight = carrier.nHeight;
    sibling.nTx = 1;
    sibling.nChainTx = 1;
    sibling.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    const auto exact{llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK(*exact == receipt);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, NonNullHash(900), carrier, best));
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, sibling));

    carrier.nStatus = static_cast<BlockStatus>(
        carrier.nStatus | BLOCK_FAILED_VALID);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
    carrier.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    best.nStatus = static_cast<BlockStatus>(BLOCK_VALID_TRANSACTIONS);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
    best.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA | BLOCK_ASSUMED_VALID);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
}

BOOST_AUTO_TEST_CASE(payment_audit_context_waits_for_local_validation)
{
    using Status = llmq::PaymentAuditContextStatus;
    using SealValidation = llmq::PaymentAuditSealValidation;

    LOCK(cs_main);
    int32_t last_superblock{0};
    int32_t superblock_height{0};
    CSuperblock::GetNearestSuperblocksHeights(
        /*nBlockHeight=*/0, last_superblock, superblock_height);
    BOOST_REQUIRE_EQUAL(last_superblock, 0);
    BOOST_REQUIRE(superblock_height > 1);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(superblock_height));
    const uint256 predecessor_hash{NonNullHash(100)};
    const uint256 seal_hash{NonNullHash(101)};
    CBlockIndex predecessor;
    predecessor.nHeight = superblock_height - 1;
    predecessor.phashBlock = &predecessor_hash;
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    CBlockIndex seal;
    seal.nHeight = superblock_height;
    seal.phashBlock = &seal_hash;
    seal.pprev = &predecessor;
    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    nullptr, /*expected_height=*/seal.nHeight,
                    predecessor.nHeight, predecessor_hash,
                    SealValidation::LIVE_EXACT) == Status::LOCAL_ERROR);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::READY);

    // Old BTCC-only provenance cannot authenticate the payment-audit and
    // probation roots used by historical audit verification.
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::LOCAL_ERROR);
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::LOCAL_ERROR);
    seal.nStatus = static_cast<BlockStatus>(
        seal.nStatus | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::READY);

    // The predecessor is the authenticated checkpoint and need not carry the
    // new receipt bit. Every later block does, and every superblock in that
    // suffix independently retains exact governance provenance.
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    const uint256 middle_hash{NonNullHash(103)};
    CBlockIndex middle;
    middle.nHeight = predecessor.nHeight + 1;
    middle.phashBlock = &middle_hash;
    middle.pprev = &predecessor;
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    const uint256 target_hash{NonNullHash(104)};
    CBlockIndex target;
    target.nHeight = middle.nHeight + 1;
    target.phashBlock = &target_hash;
    target.pprev = &middle;
    constexpr uint32_t target_ready{
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_PQ_RECEIPT_INDEX_VALIDATED};
    target.nStatus = static_cast<BlockStatus>(target_ready);
    const auto classify_target = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        return llmq::ClassifyPaymentAuditSealContext(
            &target, target.nHeight, predecessor.nHeight,
            predecessor_hash, SealValidation::LIVE_EXACT);
    };
    BOOST_CHECK(classify_target() == Status::READY);

    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        middle.nStatus | BLOCK_GOVERNANCE_VALIDATED);
    target.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    target.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    target.nStatus = static_cast<BlockStatus>(target_ready);
    BOOST_CHECK(classify_target() == Status::READY);

    middle.nStatus = static_cast<BlockStatus>(
        middle.nStatus | BLOCK_ASSUMED_VALID);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        (middle.nStatus & ~BLOCK_ASSUMED_VALID) | BLOCK_FAILED_VALID);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight + 1, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, seal.nHeight, seal_hash,
                    SealValidation::LIVE_EXACT) == Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    NonNullHash(102), SealValidation::LIVE_EXACT) ==
                Status::INVALID);

    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_ASSUMED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::LOCAL_ERROR);
    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_FAILED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::INVALID);

    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    nullptr, /*require_block_data=*/false) ==
                Status::LOCAL_ERROR);
    CBlockIndex response;
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::LOCAL_ERROR);
    response.nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::READY);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/true) ==
                Status::LOCAL_ERROR);
    response.nStatus = static_cast<BlockStatus>(
        response.nStatus | BLOCK_FAILED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::INVALID);
}

BOOST_AUTO_TEST_CASE(old_only_catchup_cannot_promote_store_best)
{
    using AuditStatus = llmq::PaymentAuditContextStatus;
    using SealValidation = llmq::PaymentAuditSealValidation;
    using FinalityError = llmq::pq::ChainLockFinalityError;

    const uint256 predecessor_hash{NonNullHash(110)};
    const uint256 seal_hash{NonNullHash(111)};
    CBlockIndex predecessor;
    predecessor.nHeight = 17519;
    predecessor.phashBlock = &predecessor_hash;
    CBlockIndex seal;
    seal.nHeight = 17520;
    seal.phashBlock = &seal_hash;
    seal.pprev = &predecessor;
    {
        LOCK(cs_main);
        predecessor.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        seal.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    }

    const auto classify_history = [&] {
        LOCK(cs_main);
        return llmq::ClassifyPaymentAuditSealContext(
            &seal, seal.nHeight, predecessor.nHeight, predecessor_hash,
            SealValidation::THRESHOLD_ATTESTED_HISTORY);
    };

    // Legacy 2048 is sufficient for the BTCC recomputation half, but it does
    // not attest the payment-audit and probation state required to promote a
    // historical certificate into durable finality.
    BOOST_REQUIRE(classify_history() == AuditStatus::LOCAL_ERROR);

    FullReceiptCatchupContext context;
    context.full_receipt_history =
        classify_history() == AuditStatus::READY;
    llmq::pq::ChainLockFinalityStore store{
        NonNullHash(112), CatchupStoreConfig(), context};
    const auto candidate{
        MakeCatchupChainLock(885, 880, NonNullHash(880), 113)};
    FinalityError error{FinalityError::NONE};
    BOOST_CHECK(!store.PrepareCatchupCandidate(candidate, &error));
    BOOST_CHECK(error == FinalityError::BLOCK_NOT_FULLY_VALIDATED);
    BOOST_CHECK(!store.GetBest());

    // A locally reconstructed 4096 range unlocks the same catch-up candidate;
    // the finality store still performs its ordinary recheck before promotion.
    {
        LOCK(cs_main);
        seal.nStatus = static_cast<BlockStatus>(
            seal.nStatus | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    }
    BOOST_REQUIRE(classify_history() == AuditStatus::READY);
    context.full_receipt_history = true;
    auto prepared{store.PrepareCatchupCandidate(candidate, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, candidate, /*signatures_valid=*/true,
        [] { return true; }, {}, &error));
    const auto best{store.GetBest()};
    BOOST_REQUIRE(best);
    BOOST_CHECK(*best == candidate);
}

BOOST_AUTO_TEST_CASE(payment_audit_archive_failures_are_not_invalid_certs)
{
    using Status = llmq::CChainLocksHandler::
        PaymentAuditReceiptCertificateStatus;
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/false,
                        /*healthy_before_read=*/false,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/false) ==
                Status::UNAVAILABLE);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/true,
                        /*healthy_before_read=*/true,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/true) ==
                Status::MISSING);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/true,
                        /*healthy_before_read=*/true,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/false) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveMutation(
                        llmq::pq::PaymentAuditStoreResult::DATABASE_ERROR) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveMutation(
                        llmq::pq::PaymentAuditStoreResult::INVALID) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED));
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::SNAPSHOT_MISMATCH));
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR));
    BOOST_CHECK(!llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::INVALID_TARGET_HEIGHT));
}

BOOST_AUTO_TEST_CASE(payment_audit_required_history_ingress_survives_kill_switch)
{
    BOOST_CHECK(llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/true, /*local_certificate=*/true,
        /*authorized_remote_response=*/false));
    BOOST_CHECK(llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/false,
        /*authorized_remote_response=*/true));
    BOOST_CHECK(!llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/true,
        /*authorized_remote_response=*/false));
    BOOST_CHECK(!llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/false,
        /*required_remote_response=*/false));

    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/true,
        /*historical_resolved=*/true));
    BOOST_CHECK(llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/true,
        /*historical_resolved=*/false));
    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/false,
        /*historical_resolved=*/false));
    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/false,
        /*historical_resolved=*/true));
}

BOOST_AUTO_TEST_CASE(local_chainlock_share_retry_is_journal_replay_only)
{
    using llmq::pq::ShareCollectionResult;
    BOOST_CHECK(llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::DUPLICATE));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/false, ShareCollectionResult::DUPLICATE));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::ACCEPTED));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::REJECTED));
}

BOOST_AUTO_TEST_CASE(chainlock_finalization_retry_retires_exact_context)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    const uint256 genesis{NonNullHash(921'000)};
    const auto schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    const auto certificate{MakeCatchupChainLock(2'000, 1'995, NonNullHash(921'001), 43)};
    const auto context{ChainLockStoreTestContextFactory::Create(
        genesis, *schedule, certificate.statement)};
    auto retry{Access::FinalizationRetryState(context)};
    BOOST_REQUIRE(retry.collector);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        llmq_tests::ChainLockCollectorTestAccess::Insert(
            *retry.collector, slot, QUORUM_THRESHOLD,
            static_cast<uint8_t>(slot + 1));
    }
    const auto completed{Access::FinalizationRetryProof(retry)};
    BOOST_REQUIRE(completed);

    // Equal statement bytes do not revive a retired publication, collector
    // generation, or share-admission generation.
    Access::ReplaceFinalizationRetryContexts(retry);
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    retry.current_contexts = retry.expected_contexts;
    ++retry.current_collector_generation;
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    retry.current_collector_generation = retry.expected_collector_generation;
    const uint64_t admission_generation{retry.admission_generation};
    retry.admission_generation = 0;
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    retry.admission_generation = admission_generation + 1;
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    retry.admission_generation = admission_generation;
    BOOST_CHECK(Access::FinalizationRetryProof(retry) == completed);

    // Replacing the collector with another prepared capability for the same
    // statement is also retirement, even before its generation is published.
    auto original_collector{std::move(retry.collector)};
    retry.collector = ChainLockCollector::Create(
        ChainLockStoreTestContextFactory::Create(
            *schedule, certificate.statement, context->RosterSetPtr()));
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    retry.collector = std::move(original_collector);
    BOOST_CHECK(Access::FinalizationRetryProof(retry) == completed);
    retry.current_contexts.reset();
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
}

BOOST_AUTO_TEST_CASE(local_payment_audit_share_retry_requires_accepted_journal_replay)
{
    using llmq::pq::ShareCollectionResult;
    for (const bool journal_replayed : {false, true}) {
        for (const bool accepted_duplicate : {false, true}) {
            BOOST_CHECK(llmq::ShouldRelayLocalPaymentAuditShare(
                journal_replayed, ShareCollectionResult::ACCEPTED,
                accepted_duplicate));
            BOOST_CHECK(!llmq::ShouldRelayLocalPaymentAuditShare(
                journal_replayed, ShareCollectionResult::REJECTED,
                accepted_duplicate));
            BOOST_CHECK_EQUAL(llmq::ShouldRelayLocalPaymentAuditShare(
                                  journal_replayed,
                                  ShareCollectionResult::DUPLICATE,
                                  accepted_duplicate),
                              journal_replayed && accepted_duplicate);
        }
    }
}

BOOST_AUTO_TEST_CASE(payment_audit_finalization_retry_is_rate_limited)
{
    using Microseconds = std::chrono::microseconds;
    const Microseconds first_attempt{100'000'000};

    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt, std::nullopt));
    BOOST_CHECK(!llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt + std::chrono::seconds{29}, first_attempt));
    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt + std::chrono::seconds{30}, first_attempt));
    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt - std::chrono::seconds{1}, first_attempt));
}

BOOST_AUTO_TEST_CASE(payment_audit_runtime_retires_revoked_capabilities)
{
    llmq::ShareAdmissionGate gate;
    gate.SetReady(true);
    BOOST_REQUIRE(gate.TryPublishEnabled(gate.Observe(), true));
    const uint64_t first_token{gate.Acquire()};
    BOOST_REQUIRE_NE(first_token, 0U);

    constexpr uint64_t roster_generation{7};
    BOOST_CHECK(!llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/false, /*finalization_admission_generation=*/0,
        first_token, roster_generation, roster_generation));
    BOOST_CHECK(!llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/true, first_token, first_token,
        roster_generation, roster_generation));

    BOOST_REQUIRE(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK(llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/true, first_token, gate.Acquire(),
        roster_generation, roster_generation));
    BOOST_REQUIRE(gate.TryPublishEnabled(gate.Observe(), true));
    const uint64_t reopened_token{gate.Acquire()};
    BOOST_REQUIRE_NE(reopened_token, 0U);
    BOOST_CHECK_NE(reopened_token, first_token);
    BOOST_CHECK(llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/true, first_token, reopened_token,
        roster_generation, roster_generation));

    BOOST_CHECK(llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/false, /*finalization_admission_generation=*/0,
        reopened_token, roster_generation, roster_generation + 1));
    BOOST_CHECK(llmq::ShouldResetPaymentAuditRuntime(
        /*finalized=*/true, reopened_token, reopened_token,
        roster_generation, roster_generation + 1));
}

BOOST_AUTO_TEST_CASE(payment_audit_side_effects_require_exact_runtime_binding)
{
    const auto allowed = [](const std::array<bool, 6>& checks) {
        return llmq::IsExactPaymentAuditRuntimeBinding(
            checks[0], checks[1], checks[2], checks[3], checks[4],
            checks[5]);
    };
    std::array<bool, 6> checks;
    checks.fill(true);
    BOOST_CHECK(allowed(checks));
    for (std::size_t mismatch{0}; mismatch < checks.size(); ++mismatch) {
        checks[mismatch] = false;
        BOOST_CHECK(!allowed(checks));
        checks[mismatch] = true;
    }
}

BOOST_AUTO_TEST_CASE(preseal_never_disables_durable_base_finality)
{
    BOOST_CHECK(llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/false));
    BOOST_CHECK(llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/true));
    BOOST_CHECK(!llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/true,
        /*btcc_preseal_active=*/true));
    BOOST_CHECK(!llmq::ShouldEnforceDurableChainLock(
        /*configured=*/false, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/false));
}

BOOST_AUTO_TEST_CASE(durable_finality_floor_blocks_only_crossing_disconnects)
{
    // The active winner itself is the normal recovery floor.
    BOOST_CHECK(llmq::DisconnectCrossesDurableChainLockFloor(
        /*disconnect_height=*/10, /*active_floor_height=*/10,
        /*floor_descends_from_disconnect=*/true));
    // Reorganizations above the winner remain ordinary PoW fork choice.
    BOOST_CHECK(!llmq::DisconnectCrossesDurableChainLockFloor(
        /*disconnect_height=*/11, /*active_floor_height=*/10,
        /*floor_descends_from_disconnect=*/false));
    // A side winner protects the active common ancestor, not the losing
    // branch above it; enforcement may disconnect that branch and repin A-1.
    BOOST_CHECK(!llmq::DisconnectCrossesDurableChainLockFloor(
        /*disconnect_height=*/8, /*active_floor_height=*/7,
        /*floor_descends_from_disconnect=*/false));
    BOOST_CHECK(!llmq::DisconnectCrossesDurableChainLockFloor(
        /*disconnect_height=*/7, /*active_floor_height=*/10,
        /*floor_descends_from_disconnect=*/false));

    // Best-chain activation compares the complete candidate and winner
    // branches before any disconnect. Descendants and winner prefixes are
    // usable; a competing branch is retired for clean reselection.
    BOOST_CHECK(llmq::IsDurableChainLockCandidateCompatible(
        /*candidate_height=*/12, /*durable_target_height=*/10,
        /*candidate_descends_target=*/true,
        /*target_descends_candidate=*/false));
    BOOST_CHECK(llmq::IsDurableChainLockCandidateCompatible(
        /*candidate_height=*/8, /*durable_target_height=*/10,
        /*candidate_descends_target=*/false,
        /*target_descends_candidate=*/true));
    BOOST_CHECK(!llmq::IsDurableChainLockCandidateCompatible(
        /*candidate_height=*/12, /*durable_target_height=*/10,
        /*candidate_descends_target=*/false,
        /*target_descends_candidate=*/false));
    BOOST_CHECK(!llmq::IsDurableChainLockCandidateCompatible(
        /*candidate_height=*/-1, /*durable_target_height=*/10,
        /*candidate_descends_target=*/true,
        /*target_descends_candidate=*/true));
}

BOOST_AUTO_TEST_CASE(chainlock_recovery_survives_operational_kill_switch)
{
    BOOST_CHECK(llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/false,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/true,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/true));

    // Startup import owns the pending state it must clear. A configured,
    // participating node must therefore attempt import even though ordinary
    // certificate verification is intentionally unavailable while pending.
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/true,
        /*persistence_failed=*/false));
    BOOST_CHECK(llmq::ShouldAttemptPersistedChainLockImport(
        /*participation_allowed=*/true,
        /*configured_for_verification=*/true));
    BOOST_CHECK(!llmq::ShouldAttemptPersistedChainLockImport(
        /*participation_allowed=*/false,
        /*configured_for_verification=*/true));
    BOOST_CHECK(!llmq::ShouldAttemptPersistedChainLockImport(
        /*participation_allowed=*/true,
        /*configured_for_verification=*/false));

    // ReplayBlocks runs while the activation handoff is still quarantined.
    // Recovery metadata intentionally has no live-participation input.
    BOOST_CHECK(llmq::ShouldExposeDurableFinalityRecoveryMetadata(
        /*configured=*/true, /*persistence_available=*/true,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldExposeDurableFinalityRecoveryMetadata(
        /*configured=*/false, /*persistence_available=*/true,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldExposeDurableFinalityRecoveryMetadata(
        /*configured=*/true, /*persistence_available=*/false,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldExposeDurableFinalityRecoveryMetadata(
        /*configured=*/true, /*persistence_available=*/true,
        /*persistence_failed=*/true));
}

BOOST_AUTO_TEST_CASE(updated_receipt_anchor_routes_exact_target_to_catchup)
{
    constexpr int32_t local_best{2305};
    constexpr int32_t receipt_anchor{2315};
    constexpr int32_t carrier{receipt_anchor +
                              static_cast<int32_t>(
                                  llmq::pq::PQ_BTCC_NEVM_LAG)};
    auto consensus{ValidConsensus()};
    consensus.nPQBTCCReceiptAnchorHeight = receipt_anchor;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(30);
    const auto config{llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_CHECK(llmq::pq::IsBTCCReceiptCarrierHeight(
        config->btcc_schedule, carrier));

    // The first post-anchor carrier C=A+10 may carry the exact ADVANCE T=A.
    // Because A is newer than the local winner S, marker authorization must
    // publish it through CATCHUP rather than the archive-only path.
    BOOST_CHECK(llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/true, receipt_anchor, local_best));
    BOOST_CHECK(!llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/false, receipt_anchor, local_best));
    BOOST_CHECK(!llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/true, receipt_anchor, receipt_anchor));
}

BOOST_AUTO_TEST_CASE(durable_seal_closes_consensus_preseal_without_geth)
{
    // Geth availability is deliberately absent from this predicate. Once a
    // fully verified descendant winner is fsynced on the same branch, signing
    // may resume while the separate replay obligation remains durable.
    BOOST_CHECK(llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1115,
        /*winner_descends_marker=*/true));
    BOOST_CHECK(!llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1095,
        /*winner_descends_marker=*/true));
    BOOST_CHECK(!llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1115,
        /*winner_descends_marker=*/false));
}

BOOST_AUTO_TEST_CASE(btcc_certificate_need_is_source_bound_and_prioritized)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using Source = Access::NeededCertificateSource;
    Access::NeededCertificateState state;
    const uint256 live_id{NonNullHash(1)};
    const uint256 newer_live_id{NonNullHash(2)};
    const uint256 replay_id{NonNullHash(3)};
    const uint256 pending_id{NonNullHash(4)};
    const uint256 live_token{NonNullHash(10)};
    const uint256 newer_live_token{NonNullHash(11)};
    const uint256 replay_token{NonNullHash(12)};

    BOOST_CHECK(Access::PublishNeededCertificate(
        state, Source::LIVE_FRONTIER, live_id, live_token));
    Access::MarkNeededCertificateRequested(state);
    BOOST_CHECK(!Access::NeededCertificateRequestTimerIsClear(state));
    BOOST_CHECK(!Access::PublishNeededCertificate(
        state, Source::LIVE_FRONTIER, live_id, live_token));
    BOOST_CHECK(!Access::NeededCertificateRequestTimerIsClear(state));

    BOOST_CHECK(Access::PublishNeededCertificate(
        state, Source::LIVE_FRONTIER, newer_live_id, newer_live_token));
    BOOST_CHECK(Access::NeededCertificateRequestTimerIsClear(state));
    BOOST_REQUIRE(Access::SelectRequiredCertificate(std::nullopt, state));
    BOOST_CHECK(*Access::SelectRequiredCertificate(
                    std::nullopt, state) == newer_live_id);

    BOOST_CHECK(Access::PublishNeededCertificate(
        state, Source::PRESEAL_REPLAY, replay_id, replay_token));
    BOOST_CHECK(!Access::PublishNeededCertificate(
        state, Source::LIVE_FRONTIER, live_id, live_token));
    BOOST_REQUIRE(Access::SelectRequiredCertificate(
        pending_id, state));
    BOOST_CHECK(*Access::SelectRequiredCertificate(
                    pending_id, state) == pending_id);
    BOOST_CHECK(*Access::SelectRequiredCertificate(
                    std::nullopt, state) == replay_id);

    BOOST_CHECK(!Access::EraseNeededCertificate(
        state, Source::LIVE_FRONTIER, live_token));
    BOOST_CHECK(!Access::EraseNeededCertificate(
        state, Source::PRESEAL_REPLAY, live_token));
    BOOST_CHECK(Access::EraseNeededCertificate(
        state, Source::PRESEAL_REPLAY, replay_token));
    BOOST_CHECK(!Access::SelectRequiredCertificate(std::nullopt, state));

    const uint256 payment_seal_id{NonNullHash(5)};
    const uint256 payment_seal_token{NonNullHash(13)};
    BOOST_CHECK(Access::PublishNeededCertificate(
        state, Source::PAYMENT_AUDIT_SEAL,
        payment_seal_id, payment_seal_token));
    BOOST_CHECK(!Access::EraseNeededCertificateByLogicalId(
        state, payment_seal_id));
    BOOST_REQUIRE(Access::SelectRequiredCertificate(
        std::nullopt, state));
    BOOST_CHECK(*Access::SelectRequiredCertificate(
                    std::nullopt, state) == payment_seal_id);
    BOOST_CHECK(Access::EraseNeededCertificate(
        state, Source::PAYMENT_AUDIT_SEAL,
        payment_seal_token));
    BOOST_CHECK(!Access::SelectRequiredCertificate(std::nullopt, state));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_seal_dependency_is_base_gated_exact_and_single_lane)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;

    const uint256 genesis{NonNullHash(215'000)};
    const auto schedule{MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);
    const auto base{MakeCatchupChainLock(
        /*height=*/865, /*previous_height=*/864,
        NonNullHash(864), 215'001)};
    const RosterAuthorizationBaseIdentity base_identity{
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    const auto base_context{ChainLockStoreTestContextFactory::Create(
        genesis, *schedule, base.statement)};
    BOOST_REQUIRE(base_context);
    const VerifiedRosterAuthorizationBaseView base_view{
        /*base_revision=*/1,
        FinalChainLockRecordMetadata{
            base.GetLogicalId(genesis), base.GetWitnessId(genesis),
            base.statement},
        std::make_shared<const FinalChainLock>(base), base_context};

    auto audit{MakePaymentAuditCandidate(
        /*epoch=*/7, /*mask=*/0b0111, 215'002)};
    audit.statement.seal_statement.roster_authorization_base =
        base_identity;
    BOOST_REQUIRE(audit.statement.seal_statement.IsStructurallyValid());
    auto receipt{NonNullPaymentAuditReceipt(215'003)};
    receipt.seal_height = audit.statement.seal_statement.height;
    receipt.seal_block_hash =
        audit.statement.seal_statement.block_hash;
    receipt.carrier_height =
        receipt.seal_height + PAYMENT_AUDIT_RECEIPT_DELAY;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    const uint256 carrier_hash{NonNullHash(215'004)};
    const uint256 carrier_parent_hash{NonNullHash(215'005)};

    Access::PaymentAuditSealDependencyState state;
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(
        state, genesis, receipt, carrier_hash, carrier_parent_hash,
        audit.statement.seal_statement, std::nullopt));
    BOOST_CHECK(!Access::PaymentAuditSealLogicalId(state));

    auto wrong_receipt{receipt};
    wrong_receipt.seal_block_hash = NonNullHash(215'006);
    BOOST_REQUIRE(wrong_receipt.IsStructurallyValid());
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(
        state, genesis, wrong_receipt, carrier_hash,
        carrier_parent_hash, audit.statement.seal_statement,
        base_identity));
    auto wrong_base{base_identity};
    wrong_base.logical_id = NonNullHash(215'007);
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(
        state, genesis, receipt, carrier_hash, carrier_parent_hash,
        audit.statement.seal_statement, wrong_base));

    BOOST_CHECK(Access::PublishPaymentAuditSealDependency(
        state, genesis, receipt, carrier_hash, carrier_parent_hash,
        audit.statement.seal_statement, base_identity));
    const auto first_id{Access::PaymentAuditSealLogicalId(state)};
    BOOST_REQUIRE(first_id);
    BOOST_CHECK(Access::PaymentAuditSealSourceMatches(
        state, receipt, carrier_hash, carrier_parent_hash, base_view));
    BOOST_CHECK(!Access::PaymentAuditSealSourceMatches(
        state, receipt, NonNullHash(215'008), carrier_parent_hash,
        base_view));

    auto replacement{MakePaymentAuditCandidate(
        /*epoch=*/8, /*mask=*/0b0111, 215'009)};
    replacement.statement.seal_statement.roster_authorization_base =
        base_identity;
    BOOST_REQUIRE(
        replacement.statement.seal_statement.IsStructurallyValid());
    auto replacement_receipt{receipt};
    replacement_receipt.seal_height =
        replacement.statement.seal_statement.height;
    replacement_receipt.seal_block_hash =
        replacement.statement.seal_statement.block_hash;
    replacement_receipt.carrier_height =
        replacement_receipt.seal_height +
        PAYMENT_AUDIT_RECEIPT_DELAY;
    BOOST_REQUIRE(replacement_receipt.IsStructurallyValid());
    const uint256 replacement_carrier{NonNullHash(215'010)};
    const uint256 replacement_parent{NonNullHash(215'011)};
    BOOST_CHECK(Access::PublishPaymentAuditSealDependency(
        state, genesis, replacement_receipt, replacement_carrier,
        replacement_parent, replacement.statement.seal_statement,
        base_identity));
    const auto replacement_id{Access::PaymentAuditSealLogicalId(state)};
    BOOST_REQUIRE(replacement_id);
    BOOST_CHECK(*replacement_id != *first_id);
    BOOST_CHECK(!Access::PaymentAuditSealSourceMatches(
        state, receipt, carrier_hash, carrier_parent_hash, base_view));
    BOOST_CHECK(Access::PaymentAuditSealSourceMatches(
        state, replacement_receipt, replacement_carrier,
        replacement_parent, base_view));
}

BOOST_AUTO_TEST_CASE(payment_audit_base_request_metadata_binds_cursor_revision_and_owner)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    const uint256 genesis{NonNullHash(215'100)};
    const RosterAuthorizationBaseIdentity objective{865, NonNullHash(215'101), NonNullHash(215'102)};
    const RosterAuthorizationBaseIdentity older{860, NonNullHash(215'103), NonNullHash(215'104)};
    auto seal{MakePaymentAuditCandidate(7, 0b0111, 215'105).statement.seal_statement};
    seal.roster_authorization_base = objective;
    BOOST_REQUIRE(seal.IsStructurallyValid());
    auto receipt{NonNullPaymentAuditReceipt(215'106)};
    receipt.seal_height = seal.height;
    receipt.seal_block_hash = seal.block_hash;
    receipt.carrier_height = seal.height + PAYMENT_AUDIT_RECEIPT_DELAY;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    const uint256 carrier{NonNullHash(215'107)};
    const uint256 parent{NonNullHash(215'108)};
    const uint256 replay_source{NonNullHash(215'109)};
    Access::PaymentAuditSealDependencyState state;
    const auto publish = [&](const std::optional<RosterAuthorizationBaseIdentity>& requested,
                             uint64_t revision) {
        return Access::PublishPaymentAuditSealDependency(state, genesis, receipt, carrier, parent,
            seal, objective, requested, revision, replay_source);
    };

    BOOST_CHECK(!publish(RosterAuthorizationBaseIdentity{}, 1));
    auto same_height_other_branch{objective};
    same_height_other_branch.block_hash = NonNullHash(215'110);
    BOOST_CHECK(!publish(same_height_other_branch, 1));
    auto newer{objective};
    ++newer.height;
    BOOST_CHECK(!publish(newer, 1));
    newer.height = seal.height;
    BOOST_CHECK(!publish(newer, 1));
    BOOST_CHECK(!Access::PaymentAuditSealRequestState(state));

    BOOST_REQUIRE(publish(objective, 1));
    const auto first{Access::PaymentAuditSealRequestState(state)};
    const auto first_capability{Access::PaymentAuditSealCapability(state)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->target == objective);
    BOOST_CHECK_EQUAL(first->revision, 1U);
    // Download ownership exists while the ordinary objective proof is absent.
    BOOST_CHECK(Access::PaymentAuditSealCapabilityMatches(state, first_capability));
    BOOST_CHECK(Access::PaymentAuditSealSourceMatches(
        state, receipt, carrier, parent, std::nullopt, replay_source));
    BOOST_CHECK(!Access::PaymentAuditSealSourceMatches(
        state, receipt, NonNullHash(215'111), parent, std::nullopt, replay_source));
    BOOST_CHECK(!Access::PaymentAuditSealSourceMatches(
        state, receipt, carrier, parent, std::nullopt, NonNullHash(215'112)));
    BOOST_CHECK(!Access::PaymentAuditSealSourceMatches(
        state, receipt, carrier, parent, std::nullopt));

    BOOST_REQUIRE(publish(older, 2));
    const auto second{Access::PaymentAuditSealRequestState(state)};
    const auto second_capability{Access::PaymentAuditSealCapability(state)};
    BOOST_REQUIRE(second);
    BOOST_CHECK(second->target == older);
    BOOST_CHECK(second->source_token != first->source_token);
    BOOST_CHECK(!Access::PaymentAuditSealCapabilityMatches(state, first_capability));
    BOOST_CHECK(Access::PaymentAuditSealCapabilityMatches(state, second_capability));
    auto wrong_receipt{receipt};
    wrong_receipt.seal_block_hash = NonNullHash(215'113);
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(state, genesis, wrong_receipt, carrier,
        parent, seal, objective, older, 3, replay_source));
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(state, genesis, receipt, carrier,
        parent, seal, objective, older, 3, uint256{}));
    BOOST_CHECK(Access::PaymentAuditSealRequestState(state) == second);

    // Returning to the same requested identity cannot revive an old reply.
    BOOST_REQUIRE(publish(objective, 3));
    const auto third{Access::PaymentAuditSealRequestState(state)};
    BOOST_REQUIRE(third);
    BOOST_CHECK(third->target == first->target);
    BOOST_CHECK(third->source_token != first->source_token);
    BOOST_CHECK(third->source_token != second->source_token);
    BOOST_CHECK_EQUAL(third->revision, 3U);
    BOOST_CHECK(!Access::PaymentAuditSealCapabilityMatches(state, first_capability));
    BOOST_CHECK(!Access::PaymentAuditSealCapabilityMatches(state, second_capability));

    auto initialize{seal};
    initialize.roster_transition = RosterAuthorizationTransitionKind::INITIALIZE;
    initialize.roster_authorization_base = {};
    BOOST_REQUIRE(initialize.IsStructurallyValid());
    BOOST_CHECK(!Access::PublishPaymentAuditSealDependency(state, genesis, receipt, carrier,
        parent, initialize, std::nullopt, older, 4, replay_source));
    BOOST_CHECK(Access::PaymentAuditSealRequestState(state) == third);
}

BOOST_AUTO_TEST_CASE(payment_audit_checkpoint_boundary_ignores_authorizer_refresh)
{
    llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = 7;
    checkpoint.covered_through_height = 100;
    checkpoint.covered_through_hash = NonNullHash(100);
    checkpoint.authenticated_receipt_state.cursor = {
        99, 7, NonNullHash(101), NonNullHash(102), NonNullHash(103)};
    checkpoint.authenticated_receipt_state.cumulative_hash =
        NonNullHash(104);
    checkpoint.authenticated_probation_state_hash = NonNullHash(105);
    checkpoint.authorizing_target_height = 110;
    checkpoint.authorizing_target_hash = NonNullHash(106);
    checkpoint.authorizing_chainlock_logical_id = NonNullHash(107);
    checkpoint.authorizing_chainlock_witness_id = NonNullHash(108);
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    BOOST_CHECK(llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, checkpoint));
    BOOST_CHECK(!llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/true,
        /*probation_gc_complete=*/true));
    BOOST_CHECK(llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/false,
        /*probation_gc_complete=*/true));
    BOOST_CHECK(llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/true,
        /*probation_gc_complete=*/false));

    auto refreshed{checkpoint};
    // Authorizer-only changes permit archive and completed state-GC reuse;
    // the five-second enforcement pass therefore performs no full flush.
    refreshed.authorizing_target_height = 120;
    refreshed.authorizing_target_hash = NonNullHash(109);
    refreshed.authorizing_chainlock_logical_id = NonNullHash(110);
    refreshed.authorizing_chainlock_witness_id = NonNullHash(111);
    BOOST_REQUIRE(refreshed.IsStructurallyValid());
    BOOST_CHECK(llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, refreshed));

    const auto boundary_differs = [&](const auto& mutate) {
        auto changed{refreshed};
        mutate(changed);
        BOOST_REQUIRE(changed.IsStructurallyValid());
        BOOST_CHECK(!llmq::HasSamePaymentAuditCheckpointBoundary(
            checkpoint, changed));
    };
    boundary_differs([](auto& changed) {
        ++changed.prune_through_epoch;
    });
    boundary_differs([](auto& changed) {
        ++changed.covered_through_height;
    });
    boundary_differs([](auto& changed) {
        changed.covered_through_hash = NonNullHash(112);
    });
    boundary_differs([](auto& changed) {
        changed.authenticated_receipt_state.cumulative_hash =
            NonNullHash(113);
    });
    boundary_differs([](auto& changed) {
        changed.authenticated_probation_state_hash = NonNullHash(114);
    });

    auto malformed{refreshed};
    malformed.authorizing_target_hash.SetNull();
    BOOST_CHECK(!llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, malformed));
}

BOOST_AUTO_TEST_CASE(payment_audit_gc_resumes_exact_durable_phase_first)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using Phase = Access::PaymentAuditGCPhase;

    llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = 7;
    checkpoint.covered_through_height = 100;
    checkpoint.covered_through_hash = NonNullHash(200);
    checkpoint.authenticated_receipt_state.cursor = {
        99, 7, NonNullHash(201), NonNullHash(202), NonNullHash(203)};
    checkpoint.authenticated_receipt_state.cumulative_hash =
        NonNullHash(204);
    checkpoint.authenticated_probation_state_hash = NonNullHash(205);
    checkpoint.authorizing_target_height = 110;
    checkpoint.authorizing_target_hash = NonNullHash(206);
    checkpoint.authorizing_chainlock_logical_id = NonNullHash(207);
    checkpoint.authorizing_chainlock_witness_id = NonNullHash(208);
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());

    auto plan{Access::SelectPaymentAuditGCPlan(
        std::nullopt, std::nullopt, std::nullopt,
        /*completed_probation=*/false)};
    BOOST_CHECK(plan.phase == Phase::NONE);

    plan = Access::SelectPaymentAuditGCPlan(
        checkpoint, std::nullopt, std::nullopt,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::ARCHIVE);
    BOOST_CHECK(plan.checkpoint == checkpoint);
    BOOST_CHECK(plan.retained_roots.empty());
    BOOST_CHECK(!plan.derive_retained_roots);

    const llmq::pq::PQPaymentProbationGCRequest probation{
        checkpoint, {NonNullHash(209), NonNullHash(210)}};
    plan = Access::SelectPaymentAuditGCPlan(
        checkpoint, probation, std::nullopt,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::INVALID);

    plan = Access::SelectPaymentAuditGCPlan(
        std::nullopt, probation, std::nullopt,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::INVALID);

    plan = Access::SelectPaymentAuditGCPlan(
        std::nullopt, probation, checkpoint,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::PROBATION);
    BOOST_CHECK(plan.checkpoint == checkpoint);
    BOOST_CHECK(plan.retained_roots == probation.retained_state_hashes);
    BOOST_CHECK(!plan.derive_retained_roots);

    auto different_boundary{checkpoint};
    ++different_boundary.prune_through_epoch;
    ++different_boundary.covered_through_height;
    different_boundary.covered_through_hash = NonNullHash(211);
    ++different_boundary.authorizing_target_height;
    different_boundary.authorizing_target_hash = NonNullHash(212);
    different_boundary.authorizing_chainlock_logical_id = NonNullHash(213);
    different_boundary.authorizing_chainlock_witness_id = NonNullHash(214);
    BOOST_REQUIRE(different_boundary.IsStructurallyValid());
    plan = Access::SelectPaymentAuditGCPlan(
        std::nullopt, probation, different_boundary,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::INVALID);

    plan = Access::SelectPaymentAuditGCPlan(
        std::nullopt, std::nullopt, checkpoint,
        /*completed_probation=*/false);
    BOOST_CHECK(plan.phase == Phase::PROBATION);
    BOOST_CHECK(plan.checkpoint == checkpoint);
    BOOST_CHECK(plan.retained_roots.empty());
    BOOST_CHECK(plan.derive_retained_roots);

    plan = Access::SelectPaymentAuditGCPlan(
        std::nullopt, std::nullopt, checkpoint,
        /*completed_probation=*/true);
    BOOST_CHECK(plan.phase == Phase::NONE);
}

BOOST_AUTO_TEST_CASE(preseal_marker_forces_retained_body_recomputation)
{
    LOCK(::cs_main);
    std::vector<uint256> hashes(6);
    std::vector<CBlockIndex> chain(6);
    for (int height{0}; height < static_cast<int>(chain.size()); ++height) {
        hashes[height] = NonNullHash(100 + height);
        chain[height].nHeight = height;
        chain[height].phashBlock = &hashes[height];
        chain[height].pprev = height == 0 ? nullptr : &chain[height - 1];
    }
    chain.back().nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);

    llmq::pq::BTCCPresealState state;
    state.active.emplace();
    state.active->earliest_carrier_height = 2;
    state.active->earliest_carrier_hash = hashes[2];
    state.active->terminal_carrier_height = 4;
    state.active->terminal_carrier_hash = hashes[4];

    // The persisted full-validation bit may authorize pruned ordinary
    // catch-up, but an exact marker branch still selects its retained range.
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(state, chain.back()) ==
                &*state.active);
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(state, chain[3]) ==
                nullptr);

    std::array<uint256, 4> fork_hashes{};
    std::array<CBlockIndex, 4> fork_indices{};
    for (int offset{0}; offset < static_cast<int>(fork_indices.size());
         ++offset) {
        fork_hashes[offset] = NonNullHash(200 + offset);
        fork_indices[offset].nHeight = 2 + offset;
        fork_indices[offset].phashBlock = &fork_hashes[offset];
        fork_indices[offset].pprev =
            offset == 0 ? &chain[1] : &fork_indices[offset - 1];
    }
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(
                    state, fork_indices.back()) ==
                nullptr);
}

BOOST_AUTO_TEST_CASE(compatibility_object_contains_no_legacy_signature_state)
{
    llmq::CChainLockSig chainlock;
    BOOST_CHECK(chainlock.IsNull());

    llmq::pq::FinalChainLock pq_chainlock;
    pq_chainlock.statement.height = 864;
    pq_chainlock.statement.block_hash = NonNullHash(10);
    chainlock = std::move(pq_chainlock);
    BOOST_CHECK(!chainlock.IsNull());
    BOOST_CHECK_EQUAL(chainlock.statement.height, 864);
    BOOST_CHECK(chainlock.statement.block_hash == NonNullHash(10));
}

BOOST_AUTO_TEST_CASE(accepted_winner_preserves_only_its_exact_successor_view)
{
    const auto schedule{llmq::pq::MakeChainLockScheduleConfig(
        /*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);

    llmq::pq::ChainLockStatement winner;
    winner.height = 865;
    winner.block_hash = NonNullHash(11);
    winner.accepted_btcc_cursor.sys_height = 42;
    winner.accepted_btcc_cursor.sys_hash = NonNullHash(13);
    winner.accepted_btcc_cursor.btc_hash = NonNullHash(14);

    llmq::pq::ChainLockStatement collector;
    collector.height = 870;
    collector.previous_chainlock_height = winner.height;
    collector.previous_chainlock_hash = winner.block_hash;
    collector.previous_btcc_cursor = winner.accepted_btcc_cursor;
    BOOST_CHECK(llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, collector, winner));

    auto stale{collector};
    stale.previous_chainlock_height = 864;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, stale, winner));

    auto skipped{collector};
    skipped.height = 875;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, skipped, winner));

    auto wrong_hash{collector};
    wrong_hash.previous_chainlock_hash = NonNullHash(12);
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, wrong_hash, winner));

    auto wrong_cursor{collector};
    ++wrong_cursor.previous_btcc_cursor.sys_height;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, wrong_cursor, winner));
}

BOOST_AUTO_TEST_CASE(share_relay_identity_is_independent_from_original_signer)
{
    std::array<llmq::pq::FrozenQuorumRoster, llmq::pq::ACTIVE_QUORUMS>
        rosters{};
    auto& roster{rosters[0]};
    roster.descriptor.epoch = 7;
    roster.descriptor.base_hash = NonNullHash(20);

    const uint256 original_signer{NonNullHash(21)};
    const uint256 authenticated_relay{NonNullHash(22)};
    roster.members[3].eligible = true;
    roster.members[3].pro_tx_hash = original_signer;
    roster.members[3].child_root.emplace();
    auto& relay_member{rosters[1].members[9]};
    relay_member.eligible = true;
    relay_member.pro_tx_hash = authenticated_relay;
    relay_member.child_root.emplace();
    const uint256 ineligible_relay{NonNullHash(24)};
    auto& ineligible_member{rosters[2].members[10]};
    ineligible_member.pro_tx_hash = ineligible_relay;
    ineligible_member.child_root.emplace();
    const uint256 rootless_relay{NonNullHash(25)};
    auto& rootless_member{rosters[3].members[11]};
    rootless_member.eligible = true;
    rootless_member.pro_tx_hash = rootless_relay;
    auto& null_member{rosters[3].members[12]};
    null_member.eligible = true;
    null_member.child_root.emplace();

    llmq::pq::ChainLockShareTranscript transcript;
    transcript.quorum_epoch = roster.descriptor.epoch;
    transcript.quorum_base_hash = roster.descriptor.base_hash;
    transcript.member_index = 3;
    transcript.member_pro_tx_hash = original_signer;
    const auto relay_recipients{
        llmq::BuildChainLockRelayRecipients(rosters)};
    BOOST_CHECK(!relay_recipients.contains(uint256{}));

    const auto observer_plan{
        llmq::BuildPQRelayPlan(rosters, uint256{})};
    BOOST_REQUIRE(observer_plan);
    BOOST_CHECK(observer_plan->local_pro_tx_hash.IsNull());
    BOOST_CHECK(observer_plan->relay_members.empty());
    BOOST_CHECK(observer_plan->authorized_recipients ==
                relay_recipients);
    const uint256 unselected_identity{NonNullHash(27)};
    const auto unselected_plan{
        llmq::BuildPQRelayPlan(rosters, unselected_identity)};
    BOOST_REQUIRE(unselected_plan);
    BOOST_CHECK(llmq::IsPQRelayPlanForIdentity(
        *unselected_plan, unselected_identity));
    BOOST_CHECK(unselected_plan->relay_members.empty());
    BOOST_CHECK(unselected_plan->authorized_recipients ==
                relay_recipients);

    BOOST_CHECK(original_signer != authenticated_relay);
    BOOST_CHECK(llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, authenticated_relay, transcript));

    transcript.member_pro_tx_hash = NonNullHash(23);
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, authenticated_relay, transcript));
    transcript.member_pro_tx_hash = original_signer;
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, NonNullHash(26), transcript));
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, ineligible_relay, transcript));
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, rootless_relay, transcript));
}

BOOST_AUTO_TEST_CASE(
    share_relay_egress_is_overlay_bounded_and_identity_deduplicated)
{
    const uint256 sender{NonNullHash(31)};
    const uint256 planned_recipient{NonNullHash(32)};
    const uint256 unplanned_recipient{NonNullHash(33)};
    const uint256 unauthorized_identity{NonNullHash(34)};
    const uint256 local_identity{NonNullHash(35)};
    llmq::PQRelayPlan plan;
    plan.local_pro_tx_hash = local_identity;
    BOOST_CHECK(llmq::IsPQRelayPlanForIdentity(
        plan, local_identity));
    BOOST_CHECK(!llmq::IsPQRelayPlanForIdentity(
        plan, NonNullHash(36)));
    BOOST_CHECK(!llmq::IsPQRelayPlanForIdentity(plan, uint256{}));
    plan.local_pro_tx_hash.SetNull();
    BOOST_CHECK(!llmq::IsPQRelayPlanForIdentity(
        plan, local_identity));

    llmq::PQRelayIdentityGate gate{sender};

    BOOST_CHECK(!gate.Admit(
        uint256{}, /*authorized_recipient=*/true,
        /*current_relay_member=*/true));
    BOOST_CHECK(!gate.Admit(
        sender, /*authorized_recipient=*/true,
        /*current_relay_member=*/true));
    BOOST_CHECK(!gate.Admit(
        unplanned_recipient, /*authorized_recipient=*/true,
        /*current_relay_member=*/false));
    BOOST_CHECK(!gate.Admit(
        unauthorized_identity, /*authorized_recipient=*/false,
        /*current_relay_member=*/true));
    BOOST_CHECK(gate.Admit(
        planned_recipient, /*authorized_recipient=*/true,
        /*current_relay_member=*/true));
    BOOST_CHECK(!gate.Admit(
        planned_recipient, /*authorized_recipient=*/true,
        /*current_relay_member=*/true));
}

BOOST_FIXTURE_TEST_CASE(
    updated_receipt_anchor_is_a_valid_historical_range_boundary,
    TestChain100Setup)
{
    constexpr int32_t receipt_anchor_height{1010};
    constexpr std::size_t range_size{11};
    std::array<uint256, range_size> hashes;
    std::array<CBlockIndex, range_size> indices;
    {
        LOCK(::cs_main);
        for (std::size_t offset{0}; offset < range_size; ++offset) {
            hashes[offset] = NonNullHash(31 + offset);
            indices[offset].nHeight = receipt_anchor_height + offset;
            indices[offset].phashBlock = &hashes[offset];
            indices[offset].pprev =
                offset == 0 ? nullptr : &indices[offset - 1];
            indices[offset].nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        }
    }
    CBlockIndex& candidate{indices.back()};

    llmq::pq::BTCCReceiptAssumptionAnchor anchor;
    anchor.height = receipt_anchor_height;
    anchor.block_hash = hashes.front();

    auto& chainman{
        static_cast<TestChainstateManager&>(*Assert(m_node.chainman))};
    chainman.ResetIbd(PQHistoryAuthState::PENDING);
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsBaseBlockSyncComplete());
        candidate.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::VALID);

        for (std::size_t offset{1}; offset < range_size; ++offset) {
            indices[offset].nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
        }
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::VALID);

        indices[5].nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_ASSUMED_VALID);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_FAILED_VALID);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

        CBlockIndex below_anchor;
        const uint256 below_hash{NonNullHash(32)};
        below_anchor.nHeight = receipt_anchor_height - 1;
        below_anchor.phashBlock = &below_hash;
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, below_anchor, anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);

        auto wrong_anchor{anchor};
        wrong_anchor.block_hash = NonNullHash(33);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, wrong_anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);
    }
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

struct PQAuthorizationBasePathSetup : TestingSetup {
    PQAuthorizationBasePathSetup() : TestingSetup{ChainType::REGTEST} {}
    void CheckHistoricalPrefix(bool reauthorize_after_ready, bool mixed_markers = false,
                               bool btcc_terminal_reorg = false,
                               bool btcc_coalesce_markers = false,
                               bool mining_guard = false);
};

llmq::pq::RecoveryUniverseCapsulePtr SelectorRecoveryUniverse(
    const uint256& genesis, const llmq::pq::RecoveryRosterAuthoritySource& source,
    const uint256& snapshot_hash)
{
    using namespace llmq::pq;
    std::vector<RecoveryUniverseMember> members;
    for (std::size_t index{0}; index < QUORUM_SIZE; ++index) {
        members.push_back({NonNullHash(940'000 + index), NonNullHash(941'000 + index),
                          COutPoint{NonNullHash(942'000 + index), static_cast<uint32_t>(index)}});
    }
    std::sort(members.begin(), members.end(), [](const auto& left, const auto& right) {
        return left.pro_tx_hash < right.pro_tx_hash;
    });
    const int32_t snapshot_height{source.normal_beacon.anchor_cursor.sys_height - 1};
    const auto source_id{GetRecoveryUniverseSourceId(genesis, source)};
    const auto members_hash{GetRecoveryUniverseMembersHash(genesis, members)};
    const auto capsule_id{GetRecoveryUniverseCapsuleId(
        genesis, source, snapshot_height, snapshot_hash, members_hash, members.size())};
    DataStream stream{SER_DISK};
    stream << RECOVERY_UNIVERSE_CAPSULE_VERSION << genesis << source << snapshot_height
           << snapshot_hash << source_id << static_cast<uint32_t>(members.size());
    for (const auto& member : members) stream << member;
    stream << members_hash << capsule_id;
    const std::vector<uint8_t> encoded{
        UCharCast(stream.data()), UCharCast(stream.data() + stream.size())};
    const auto capsule{RecoveryUniverseCapsule::DecodeTrustedPersistence(encoded)};
    BOOST_REQUIRE(capsule);
    return std::make_shared<const RecoveryUniverseCapsule>(*capsule);
}

} // namespace

BOOST_FIXTURE_TEST_CASE(
    chainlock_targeted_polls_preserve_standby_peers_and_upload_limits,
    PQAuthorizationBasePathSetup)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& chainman{*Assert(m_node.chainman)};
    auto& peerman{*Assert(m_node.peerman)};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    FullReceiptCatchupContext store_context;
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            connman, peerman, chainman);
    }
    Access::ExchangeFinalityStore(*handler,
        std::make_unique<ChainLockFinalityStore>(
            genesis, CatchupStoreConfig(), store_context));
    // Install already-servable bytes at the handler's normal serving seam.
    // Certificate admission and signature verification have separate tests.
    auto certificate{std::make_shared<const FinalChainLock>(
        MakeCatchupChainLock(2'000, 1'995, NonNullHash(921'100), 44))};
    BOOST_REQUIRE(certificate->IsStructurallyValid());
    Access::SetServableHistoricalCertificate(*handler, certificate);
    const uint256 logical_id{certificate->GetLogicalId(genesis)};
    BOOST_REQUIRE(handler->AlreadyHave(logical_id));
    const std::vector<CInv> inventory{{MSG_CLSIG, logical_id}};

    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c009;
    const CAddress address{CService{ipv4_addr, 7785}, NODE_NETWORK};
    CNode node{
        /*id=*/902, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/9, /*nLocalHostNonceIn=*/902, CAddress{},
        /*addrNameIn=*/std::string{}, ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    connman.Handshake(
        node, /*successfully_connected=*/true,
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        PROTOCOL_VERSION, /*relay_txs=*/true);
    TestOnlyResetTimeData();
    struct RestoreNetworkState {
        PeerManager& peerman;
        CNode& node;
        llmq::CChainLocksHandler* previous_handler;
        std::chrono::seconds previous_mock_time;
        ~RestoreNetworkState()
        {
            peerman.FinalizeNode(node);
            llmq::chainLocksHandler = previous_handler;
            SetMockTime(previous_mock_time);
        }
    } restore{peerman, node,
              std::exchange(llmq::chainLocksHandler, handler.get()),
              GetMockTime()};
    BOOST_REQUIRE(!node.fDisconnect);
    const PeerRef peer{peerman.GetPeerRef(node.GetId())};
    BOOST_REQUIRE(peer);
    connman.FlushSendBuffer(node);
    node.fPauseSend = false;

    std::atomic<bool> interrupt{false};
    const auto start{GetTime<std::chrono::seconds>()};
    const auto dispatch = [&](const char* command, const auto& argument)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        CDataStream request{SER_NETWORK, node.GetCommonVersion()};
        request << argument;
        peerman.ProcessMessage(node, command, request,
                               GetTime<std::chrono::microseconds>(), interrupt);
    };
    const auto drain_reply = [&](const char* expected_command) {
        LOCK(node.cs_vSend);
        // With a null socket the one response is left in the V1 transport.
        BOOST_REQUIRE(node.vSendMsg.empty());
        std::size_t total_bytes{0};
        while (true) {
            const auto& [bytes, more, command]{
                node.m_transport->GetBytesToSend(false)};
            (void)more;
            if (bytes.empty()) break;
            BOOST_CHECK_EQUAL(command, expected_command);
            total_bytes += bytes.size();
            node.m_transport->MarkBytesSent(bytes.size());
        }
        node.fPauseSend = false;
        return total_bytes;
    };
    const auto check_score = [&](int expected) {
        LOCK(peer->m_misbehavior_mutex);
        BOOST_CHECK_EQUAL(peer->m_misbehavior_score, expected);
        BOOST_CHECK(!peer->m_should_discourage);
        BOOST_CHECK(!node.fDisconnect);
    };
    const std::size_t inventory_bytes{
        CMessageHeader::HEADER_SIZE + GetSerializeSize(inventory)};
    const std::size_t certificate_bytes{
        CMessageHeader::HEADER_SIZE + FinalChainLockSerializedSize()};

    // Two other providers may occupy the required download lanes for sixty
    // seconds. This honest standby receives the scheduler's five-second
    // GETCLSIG polls but no GETDATA throughout that interval.
    for (int seconds{0}; seconds <= 65; seconds += 5) {
        SetMockTime(start + std::chrono::seconds{seconds});
        dispatch(NetMsgType::GETCLSIG, logical_id);
        BOOST_CHECK_EQUAL(drain_reply(NetMsgType::INV), inventory_bytes);
        check_score(0);
        LOCK(peer->m_pq_certificate_mutex);
        BOOST_CHECK(peer->m_clsig_uploads
                        .HasActiveTargetedAuthorization(logical_id));
    }

    // Repeated polls left exactly one consumable payload grant.
    dispatch(NetMsgType::GETDATA, inventory);
    BOOST_CHECK_EQUAL(drain_reply(NetMsgType::CLSIG), certificate_bytes);
    check_score(0);
    dispatch(NetMsgType::GETDATA, inventory);
    BOOST_CHECK_EQUAL(drain_reply(""), 0U);
    check_score(20); // Ungranted GETDATA remains a protocol violation.

    // An explicit retry can grant the second and final payload.
    dispatch(NetMsgType::GETCLSIG, logical_id);
    BOOST_CHECK_EQUAL(drain_reply(NetMsgType::INV), inventory_bytes);
    dispatch(NetMsgType::GETDATA, inventory);
    BOOST_CHECK_EQUAL(drain_reply(NetMsgType::CLSIG), certificate_bytes);
    check_score(20);

    // The requester may still be waiting for local verification or another
    // provider. Exhausted polls neither punish it nor mint a third payload.
    for (int seconds{70}; seconds <= 105; seconds += 5) {
        SetMockTime(start + std::chrono::seconds{seconds});
        dispatch(NetMsgType::GETCLSIG, logical_id);
        BOOST_CHECK_EQUAL(drain_reply(""), 0U);
        check_score(20);
        LOCK(peer->m_pq_certificate_mutex);
        BOOST_CHECK(!peer->m_clsig_uploads
                         .HasActiveTargetedAuthorization(logical_id));
    }
    dispatch(NetMsgType::GETDATA, inventory);
    BOOST_CHECK_EQUAL(drain_reply(""), 0U);
    check_score(40);
}

BOOST_FIXTURE_TEST_CASE(
    restored_chainlock_enforcement_accepts_only_pruned_active_winners,
    PQAuthorizationBasePathSetup)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    constexpr int32_t TARGET_HEIGHT{2'330};
    constexpr int32_t PREDECESSOR_HEIGHT{TARGET_HEIGHT - PQ_CL_PERIOD};
    constexpr int32_t TIP_HEIGHT{TARGET_HEIGHT + PQ_CL_SIGN_LAG};
    const uint256 probation_root{NonNullHash(986'000)};
    auto& chainman{*Assert(m_node.chainman)};
    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    std::vector<CBlockIndex*> chain(static_cast<std::size_t>(TIP_HEIGHT + 1));
    CBlockIndex* sibling{nullptr};
    {
        LOCK(::cs_main);
        chain[0] = chainman.ActiveTip();
        BOOST_REQUIRE(chain[0]);
        const int64_t first_time{GetTime<std::chrono::seconds>().count() - TIP_HEIGHT};
        for (int32_t height{1}; height <= TIP_HEIGHT; ++height) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = chain[height - 1]->GetBlockHash();
            header.hashMerkleRoot = NonNullHash(987'000 + height);
            header.nTime = static_cast<uint32_t>(first_time + height);
            header.nBits = chain[height - 1]->nBits;
            header.nNonce = static_cast<uint32_t>(height);
            chain[height] = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(chain[height]);
            chain[height]->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_BTCC_INDEX_VALIDATED | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                BLOCK_GOVERNANCE_VALIDATED;
            chain[height]->nTx = 1;
            chain[height]->nChainTx = static_cast<unsigned int>(height + 1);
            chain[height]->pqPaymentProbationStateHash = probation_root;
        }
        CBlockHeader header{chain[TARGET_HEIGHT]->GetBlockHeader()};
        header.hashMerkleRoot = NonNullHash(990'000);
        sibling = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
        BOOST_REQUIRE(sibling);
        sibling->nStatus = chain[TARGET_HEIGHT]->nStatus;
        sibling->nTx = 1;
        sibling->nChainTx = static_cast<unsigned int>(TARGET_HEIGHT + 1);
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
        BOOST_REQUIRE(chainman.IsBaseBlockSyncComplete());
        BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(TARGET_HEIGHT));
        // Historical governance replay preserves full receipt validation but
        // lacks exact local governance provenance. Pruning later removes data.
        chain[TARGET_HEIGHT]->nStatus &=
            ~(BLOCK_GOVERNANCE_VALIDATED | BLOCK_HAVE_DATA);
    }

    auto& consensus{const_cast<Consensus::Params&>(chainman.GetConsensus())};
    const auto original_consensus{consensus};
    consensus.nPQActivationHeight = 2'305;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = 2'305;
    consensus.nPQBTCCNEVMInjectionLag = PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1'000;
    consensus.hashPQBTCCReceiptAnchorBlock = chain[1'000]->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nDefaultAssumeValidHeight = -1;
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *Assert(m_node.connman), *Assert(m_node.peerman), chainman);
    }
    consensus = original_consensus;
    const auto* config{Access::Config(*handler)};
    BOOST_REQUIRE(config);
    FullReceiptCatchupContext store_context;
    store_context.full_receipt_history = true;
    Access::ResetFinalityStoreWithContext(*handler, store_context);
    auto* store{Access::Store(*handler)};
    BOOST_REQUIRE(store);
    auto certificate{MakeCatchupChainLock(
        TARGET_HEIGHT, PREDECESSOR_HEIGHT,
        chain[PREDECESSOR_HEIGHT]->GetBlockHash(), 986'001)};
    certificate.statement.block_hash = chain[TARGET_HEIGHT]->GetBlockHash();
    certificate.statement.payment_probation_state_hash = probation_root;
    BOOST_REQUIRE(certificate.IsStructurallyValid());
    // Enter at the post-verification startup seam, then exercise the complete
    // production handler and lower-chainstate enforcement path.
    const auto prepared{store->PreparePersistedCandidate(certificate)};
    BOOST_REQUIRE(prepared);
    const auto verified{ChainLockStoreTestContextFactory::CreateTrustedPersistence(
        genesis, config->chainlock_schedule, certificate.statement)};
    BOOST_REQUIRE(store->AcceptPersistedVerified(
        *prepared, certificate, /*signatures_valid=*/true, nullptr, verified));
    const uint256 witness_id{certificate.GetWitnessId(genesis)};
    const auto check_rejected = [&] {
        Access::ClearHistoricalIndexTestCache(*handler);
        Access::EnforceBestChainLock(*handler);
        BOOST_CHECK(Access::BestAuthenticationPending(*handler));
        BOOST_CHECK(Access::PendingHistory(*handler));
        LOCK(::cs_main);
        BOOST_CHECK(!(sibling->nStatus & BLOCK_CONFLICT_CHAINLOCK));
        BOOST_CHECK(!(chain[TARGET_HEIGHT]->nStatus & BLOCK_CONFLICT_CHAINLOCK));
    };

    Access::SetRestoredEnforcementWitness(*handler, {});
    check_rejected();
    Access::SetRestoredEnforcementWitness(*handler, NonNullHash(986'002));
    check_rejected();
    Access::SetRestoredEnforcementWitness(*handler, witness_id);
    for (const int32_t height : {PREDECESSOR_HEIGHT, TARGET_HEIGHT}) {
        {
            LOCK(::cs_main);
            chain[height]->nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
        }
        check_rejected();
        {
            LOCK(::cs_main);
            chain[height]->nStatus |= BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
        }
    }
    {
        LOCK(::cs_main);
        chain[TARGET_HEIGHT]->pqPaymentProbationStateHash = NonNullHash(986'003);
    }
    check_rejected();
    {
        LOCK(::cs_main);
        chain[TARGET_HEIGHT]->pqPaymentProbationStateHash = probation_root;
        chainman.ActiveChainstate().m_chain.SetTip(*sibling);
        BOOST_REQUIRE(chainman.IsBaseBlockSyncComplete());
    }
    check_rejected();
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == sibling);
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
    }

    Access::ClearHistoricalIndexTestCache(*handler);
    Access::EnforceBestChainLock(*handler);
    BOOST_CHECK(!Access::BestAuthenticationPending(*handler));
    BOOST_CHECK(!Access::PendingHistory(*handler));
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == chain[TIP_HEIGHT]);
        BOOST_CHECK(!(chain[TARGET_HEIGHT]->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK(!(chain[TARGET_HEIGHT]->nStatus & BLOCK_GOVERNANCE_VALIDATED));
        BOOST_CHECK(sibling->nStatus & BLOCK_CONFLICT_CHAINLOCK);
    }
}

BOOST_FIXTURE_TEST_CASE(
    chainlock_finalization_retry_reuses_complete_proof_after_contention,
    PQAuthorizationBasePathSetup)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    constexpr int32_t TARGET_HEIGHT{2'305};
    constexpr int32_t TIP_HEIGHT{TARGET_HEIGHT + PQ_CL_SIGN_LAG};
    auto& chainman{*Assert(m_node.chainman)};
    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    std::vector<CBlockIndex*> chain(static_cast<std::size_t>(TIP_HEIGHT + 1));
    {
        LOCK(::cs_main);
        chain[0] = chainman.ActiveTip();
        BOOST_REQUIRE(chain[0]);
        for (int32_t height{1}; height <= TIP_HEIGHT; ++height) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = chain[height - 1]->GetBlockHash();
            header.hashMerkleRoot = NonNullHash(920'000 + height);
            header.nTime = static_cast<uint32_t>(GetTime<std::chrono::seconds>().count());
            header.nBits = 0x207fffff;
            header.nNonce = static_cast<uint32_t>(height);
            chain[height] = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(chain[height]);
            chain[height]->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_BTCC_INDEX_VALIDATED | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                BLOCK_GOVERNANCE_VALIDATED;
            chain[height]->pqPaymentProbationStateHash = NonNullHash(30'000);
        }
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
    }
    auto& consensus{const_cast<Consensus::Params&>(chainman.GetConsensus())};
    const auto original_consensus{consensus};
    consensus.nPQActivationHeight = TARGET_HEIGHT;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = TARGET_HEIGHT;
    consensus.nPQBTCCNEVMInjectionLag = PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1'000;
    consensus.hashPQBTCCReceiptAnchorBlock = chain[1'000]->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nDefaultAssumeValidHeight = -1;

    class RecordingAdmissionContext final : public ChainLockFinalityContext {
    public:
        mutable std::vector<ChainLockStatement> submitted;
        std::optional<ChainLockCandidateContext> PrepareCandidate(
            const ChainLockCandidateContextRequest& request) const override
        {
            submitted.push_back(request.statement);
            // End at the ordinary store-admission seam. This regression tests
            // scheduler delivery; signature and persistence have separate tests.
            return std::nullopt;
        }
        std::optional<ChainLockCandidateContext> RecheckCandidate(
            const ChainLockCandidateContextRequest&,
            const ChainLockCandidateContext&) const override
        {
            return std::nullopt;
        }
        AcceptedBranchRelation QueryAcceptedBranch(
            int32_t, const uint256&, int32_t, const uint256&) const override
        {
            return AcceptedBranchRelation::MATCH;
        }
    } store_context;
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *Assert(m_node.connman), *Assert(m_node.peerman), chainman);
    }
    consensus = original_consensus;
    const auto* config{Access::Config(*handler)};
    const auto* quorum_config{Access::QuorumConfig(*handler)};
    BOOST_REQUIRE(config);
    BOOST_REQUIRE(quorum_config);
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, *quorum_config, [](const CBlockIndex&) {
            return std::optional<QuorumSnapshotState>{};
        })};
    BOOST_REQUIRE(cache);
    handler->SetQuorumRosterCache(cache);
    Access::ResetFinalityStoreWithContext(*handler, store_context);

    auto certificate{MakeCatchupChainLock(TARGET_HEIGHT, TARGET_HEIGHT - 1,
        chain[TARGET_HEIGHT - 1]->GetBlockHash(), 42)};
    certificate.statement.block_hash = chain[TARGET_HEIGHT]->GetBlockHash();
    BOOST_REQUIRE(certificate.IsStructurallyValid());
    const auto context{ChainLockStoreTestContextFactory::Create(
        genesis, config->chainlock_schedule, certificate.statement)};
    auto retry{Access::FinalizationRetryState(context)};
    BOOST_REQUIRE(retry.collector);
    BOOST_CHECK(!Access::FinalizationRetryProof(retry));
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        llmq_tests::ChainLockCollectorTestAccess::Insert(
            *retry.collector, slot, QUORUM_THRESHOLD,
            static_cast<uint8_t>(slot + 1));
    }
    auto* collector{retry.collector.get()};
    const auto completed{collector->FinalizeCollection()};
    BOOST_REQUIRE(completed);
    const auto original_counts{collector->ShareCounts()};
    BOOST_REQUIRE(Access::PublishFinalizationRetry(*handler, retry));

    std::promise<void> entered;
    std::promise<void> release;
    auto released{release.get_future()};
    std::thread maintenance{[&] {
        LOCK(Access::ChainLockAdmissionMutex(*handler));
        entered.set_value();
        released.wait();
    }};
    entered.get_future().wait();
    // Exercise the actual scheduler method while ordinary admission is busy.
    Access::RetryChainLockFinalization(*handler);
    const auto submissions_while_busy{store_context.submitted.size()};
    release.set_value();
    maintenance.join();
    BOOST_CHECK_EQUAL(submissions_while_busy, 0U);

    // No unique or duplicate share arrives. A later scheduler pass alone must
    // submit the completed certificate to the production store-admission path.
    Access::RetryChainLockFinalization(*handler);
    BOOST_REQUIRE_EQUAL(store_context.submitted.size(), 1U);
    BOOST_CHECK(store_context.submitted.front() == completed->Certificate().statement);
    BOOST_CHECK(collector->FinalizeCollection() == completed);
    BOOST_CHECK(collector->ShareCounts() == original_counts);
    BOOST_CHECK(llmq::SelectFinalChainLockVerificationPath(
        completed.get(), &completed->Certificate(), genesis,
        config->chainlock_schedule, context->RosterSetPtr(),
        context->AuthorizationMask(), /*local_live_admission=*/true,
        /*admission_generation_current=*/true,
        /*collector_generation_current=*/true) ==
        llmq::FinalChainLockVerificationPath::COLLECTED);
}

BOOST_FIXTURE_TEST_CASE(
    pow_refresh_handler_requires_objective_capability_and_receipt_before_normal,
    PQAuthorizationBasePathSetup)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    constexpr int32_t BASE_HEIGHT{2'305};
    constexpr int32_t TIP_HEIGHT{4'950};
    constexpr uint32_t GROUP{2};
    const uint256 probation_root{NonNullHash(950'000)};
    auto& chainman{*Assert(m_node.chainman)};
    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    std::vector<CBlockIndex*> chain(static_cast<std::size_t>(TIP_HEIGHT + 1));
    {
        LOCK(::cs_main);
        chain[0] = chainman.ActiveTip();
        BOOST_REQUIRE(chain[0]);
        const int64_t first_time{GetTime<std::chrono::seconds>().count() - TIP_HEIGHT};
        for (int32_t height{1}; height <= TIP_HEIGHT; ++height) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = chain[height - 1]->GetBlockHash();
            header.hashMerkleRoot = NonNullHash(951'000 + height);
            header.nTime = static_cast<uint32_t>(first_time + height);
            header.nBits = 0x207fffff;
            header.nNonce = static_cast<uint32_t>(height);
            chain[height] = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(chain[height]);
            chain[height]->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_BTCC_INDEX_VALIDATED | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                BLOCK_GOVERNANCE_VALIDATED;
            chain[height]->nChainWork = GetBlockProof(*chain[height]) * (height + 1);
            chain[height]->nTx = 1;
            chain[height]->nChainTx = static_cast<unsigned int>(height + 1);
            chain[height]->pqPaymentProbationStateHash = probation_root;
        }
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
    }
    auto& consensus{const_cast<Consensus::Params&>(chainman.GetConsensus())};
    const auto original_consensus{consensus};
    consensus.nPQActivationHeight = BASE_HEIGHT;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = BASE_HEIGHT;
    consensus.nPQBTCCNEVMInjectionLag = PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1'000;
    consensus.hashPQBTCCReceiptAnchorBlock = chain[1'000]->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nDefaultAssumeValidHeight = -1;
    consensus.nPQRecoveryRefreshActivationHeight = BASE_HEIGHT;
    consensus.nPQRecoveryRefreshGraceGroups = 1;
    consensus.nPQRecoveryRefreshSnapshotLagBlocks = 144;
    consensus.nPQRecoveryRefreshEntropyDelayBlocks = 60;
    consensus.nPQRecoveryRefreshCarrierDelayBlocks = 60;
    consensus.nPQRecoveryRefreshCarrierMinDepthBlocks = 5;
    consensus.nPQRecoveryRefreshSnapshotMinWorkBlocks = 60;
    consensus.nPQRecoveryRefreshCarrierMinWorkBlocks = 5;
    consensus.nPQRecoveryReadinessWindowBlocks = 128;
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *Assert(m_node.connman), *Assert(m_node.peerman), chainman);
    }
    consensus = original_consensus;
    const auto* config{Access::Config(*handler)};
    const auto* quorum_config{Access::QuorumConfig(*handler)};
    BOOST_REQUIRE(config);
    BOOST_REQUIRE(quorum_config);
    const auto coordinates{DeriveRecoveryRefreshCoordinates(
        config->chainlock_schedule, config->btcc_schedule,
        quorum_config->recovery_refresh, GROUP)};
    BOOST_REQUIRE(coordinates);
    const int32_t recovery_height{coordinates->target_height};
    BOOST_REQUIRE_LT(recovery_height + 30, TIP_HEIGHT);

    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState snapshot;
        snapshot.deterministic_mns = CDeterministicMNList{
            index.GetBlockHash(), index.nHeight, QUORUM_SIZE};
        const auto view{DeriveOperatorKeyScheduleView(
            config->chainlock_schedule, index.nHeight,
            quorum_config->registration_cutoff_blocks, quorum_config->future_horizon_epochs)};
        BOOST_REQUIRE(view);
        std::vector<OperatorKeyState> keys;
        keys.reserve(QUORUM_SIZE);
        for (uint32_t tag{0}; tag < QUORUM_SIZE; ++tag) {
            auto dmn{std::make_shared<CDeterministicMN>(tag + 1)};
            dmn->proTxHash = NonNullHash(960'000 + tag);
            dmn->collateralOutpoint = COutPoint{NonNullHash(961'000 + tag), tag};
            auto state{std::make_shared<CDeterministicMNState>()};
            const auto owner{NonNullHash(962'000 + tag)};
            std::copy_n(owner.begin(), state->keyIDOwner.size(), state->keyIDOwner.begin());
            state->nRegisteredHeight = 100;
            state->UpdateConfirmedHash(dmn->proTxHash, NonNullHash(963'000 + tag));
            dmn->pdmnState = std::move(state);
            snapshot.deterministic_mns.AddMN(dmn, /*fBumpTotalCount=*/false);
            auto key{OperatorKeyState::ForOperator(dmn->proTxHash)};
            key.has_global_key = 1;
            key.global_key_active = 1;
            key.global_key.key_version = 1;
            key.global_key.public_key[0] = static_cast<uint8_t>((tag & 0x7fU) | 0x80U);
            key.global_key.activated_height = 1;
            key.global_key.child_key_commitment.generation = 1;
            key.global_key.child_key_commitment.first_epoch = 0;
            key.global_key.child_key_commitment.tree_id = NonNullHash(964'000 + tag);
            key.global_key.child_key_commitment.root = NonNullHash(965'000 + tag);
            key.schedule_initialized = 1;
            key.schedule = OperatorKeyScheduleState::FromView(*view);
            for (uint32_t epoch{key.schedule.first_retained_frozen_epoch};
                 epoch < key.schedule.first_mutable_epoch; ++epoch) {
                key.frozen_child_roots.push_back(FrozenChildRootRecord{
                    key.pro_tx_hash, 1, epoch, key.global_key.child_key_commitment});
            }
            if (index.nHeight >= coordinates->snapshot_height) {
                key.recovery_readiness = RecoveryReadinessRecord{
                    GROUP, 1, coordinates->readiness_reference_height,
                    chain[coordinates->readiness_reference_height]->GetBlockHash(),
                    coordinates->snapshot_height};
            }
            BOOST_REQUIRE(key.IsStructurallyValid());
            keys.push_back(std::move(key));
        }
        snapshot.operator_key_states =
            std::make_shared<const std::vector<OperatorKeyState>>(std::move(keys));
        return std::optional<QuorumSnapshotState>{std::move(snapshot)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(genesis, *quorum_config, lookup)};
    BOOST_REQUIRE(cache);
    handler->SetQuorumRosterCache(cache);
    auto& work_carrier{*chain[coordinates->carrier_height]};
    // Raw merged-work validation has separate consensus tests. This fixture
    // begins at its immutable, script-validated block-index boundary.
    work_carrier.pqRecoveryRefreshGroup = GROUP;
    work_carrier.pqRecoveryRefreshEntropyBlockHash =
        chain[coordinates->entropy_height]->GetBlockHash();
    work_carrier.pqRecoveryRefreshParentWorkHash = NonNullHash(966'000);
    work_carrier.pqRecoveryRefreshCommitmentHash = NonNullHash(966'001);

    FullReceiptCatchupContext store_context;
    store_context.full_receipt_history = true;
    Access::ResetFinalityStoreWithContext(*handler, store_context);
    auto* store{Access::Store(*handler)};
    BOOST_REQUIRE(store);
    const auto bind_transition = [&](FinalChainLock& candidate, const FinalChainLock* prior) {
        RosterAuthorizationTransition transition;
        transition.kind = candidate.statement.roster_transition;
        transition.target_height = candidate.statement.height;
        transition.target_block_hash = candidate.statement.block_hash;
        transition.predecessor_height = candidate.statement.previous_chainlock_height;
        transition.predecessor_block_hash = candidate.statement.previous_chainlock_hash;
        if (prior != nullptr) {
            candidate.statement.roster_authorization_base = {
                prior->statement.height, prior->statement.block_hash, prior->GetLogicalId(genesis)};
            transition.previous = RosterAuthorizationPriorState{
                prior->statement.roster_authorization_state_hash, prior->statement.roster_beacons};
        }
        transition.authorization_base = candidate.statement.roster_authorization_base;
        transition.new_window = candidate.statement.roster_beacons;
        const auto hash{GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(hash);
        candidate.statement.roster_authorization_state_hash = *hash;
        BOOST_REQUIRE(candidate.IsStructurallyValid());
    };
    auto base{MakeCatchupChainLock(BASE_HEIGHT, BASE_HEIGHT - 1,
        chain[BASE_HEIGHT - 1]->GetBlockHash(), 966'002)};
    base.statement.block_hash = chain[BASE_HEIGHT]->GetBlockHash();
    base.statement.payment_probation_state_hash = probation_root;
    base.statement.accepted_btcc_cursor = {BASE_HEIGHT, base.statement.block_hash, NonNullHash(966'003)};
    base.statement.btcc_advance = BTCCAdvance::ADVANCE;
    base.statement.roster_transition = RosterAuthorizationTransitionKind::INITIALIZE;
    base.statement.roster_authorization_base = {};
    chain[BASE_HEIGHT]->btcpPrevCommitment = base.statement.accepted_btcc_cursor.btc_hash;
    const auto base_epoch{EpochForHeight(config->chainlock_schedule, BASE_HEIGHT)};
    BOOST_REQUIRE(base_epoch);
    auto ready{SubjectBeacon(*base_epoch)};
    ready.anchor_cursor = base.statement.accepted_btcc_cursor;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        base.statement.roster_beacons.active.seeds[slot] = ready;
        base.statement.roster_beacons.active.seeds[slot].epoch =
            *base_epoch - (ACTIVE_QUORUMS - 1) + slot;
    }
    base.statement.roster_beacons.active.recovery_authority_source.normal_beacon = ready;
    base.statement.roster_beacons.next = {};
    base.statement.roster_beacons.next.epoch = *base_epoch + 1;
    bind_transition(base, nullptr);
    const auto install_base = [&](const FinalChainLock& value) {
        const auto prepared{store->PrepareCandidate(value)};
        BOOST_REQUIRE(prepared);
        const auto context{ChainLockStoreTestContextFactory::Create(
            genesis, config->chainlock_schedule, value.statement)};
        BOOST_REQUIRE(store->AcceptVerified(*prepared, value, true, nullptr, context));
    };
    install_base(base);
    auto current{base};
    current.statement.height += PQ_CL_PERIOD;
    current.statement.block_hash = chain[current.statement.height]->GetBlockHash();
    current.statement.previous_chainlock_height = BASE_HEIGHT;
    current.statement.previous_chainlock_hash = base.statement.block_hash;
    current.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
    current.statement.btcc_advance = BTCCAdvance::KEEP;
    current.statement.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    bind_transition(current, &base);
    install_base(current);

    const auto receipt_for = [&](const FinalChainLock& value, const BTCCReceiptState& previous) {
        const int32_t carrier{value.statement.height + static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
        BTCCReceipt receipt;
        receipt.chainlock_target_height = value.statement.height;
        receipt.chainlock_target_hash = value.statement.block_hash;
        receipt.chainlock_logical_id = value.GetLogicalId(genesis);
        receipt.accepted_cursor = value.statement.accepted_btcc_cursor;
        const auto state{ApplyBTCCReceiptState(genesis, config->chainlock_schedule,
            config->btcc_schedule, config->activation_predecessor_height,
            carrier, chain[carrier]->GetBlockHash(), previous, receipt)};
        BOOST_REQUIRE(state);
        for (int32_t height{carrier}; height <= TIP_HEIGHT; ++height) {
            auto& index{*chain[height]};
            index.pqBTCCReceiptCursorHeight = state->cursor.sys_height;
            index.pqBTCCReceiptCursorSysHash = state->cursor.sys_hash;
            index.pqBTCCReceiptCursorBTCHash = state->cursor.btc_hash;
            index.pqBTCCReceiptStateHash = state->cumulative_hash;
            index.pqBTCCReceiptLatestTargetHeight = state->latest_chainlock_target_height;
            index.pqBTCCReceiptLatestCarrierHeight = state->latest_receipt_carrier_height;
        }
        chain[carrier]->pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
        return *state;
    };
    const auto base_receipt_state{receipt_for(base, BTCCReceiptState{})};
    const auto grace_height{CanonicalRosterRecoveryTargetHeight(
        config->chainlock_schedule, config->btcc_schedule, GROUP * ACTIVE_QUORUMS - 1)};
    BOOST_REQUIRE(grace_height);
    const auto grace{Access::ObjectiveRosterAuthorization(*handler, *chain[*grace_height])};
    BOOST_REQUIRE(grace);
    BOOST_CHECK(grace->mode == ObjectiveRosterAuthorizationMode::RECOVER);
    BOOST_CHECK(grace->recovery_source == base.statement.roster_beacons.active.recovery_authority_source);
    BOOST_CHECK(!Access::ObjectiveRosterAuthorization(*handler, *chain[recovery_height]));
    work_carrier.pqRecoveryRefreshWorkValidated = true;
    const auto objective{Access::ObjectiveRosterAuthorization(*handler, *chain[recovery_height])};
    BOOST_REQUIRE(objective);
    BOOST_REQUIRE(objective->base);
    BOOST_REQUIRE(objective->recovery_source);
    BOOST_CHECK(objective->mode == ObjectiveRosterAuthorizationMode::RECOVER);
    BOOST_CHECK_EQUAL(objective->base->height, BASE_HEIGHT);
    BOOST_CHECK(objective->recovery_source->kind == RecoveryRosterSourceKind::POW_REFRESH);
    BOOST_CHECK_EQUAL(objective->recovery_source->refresh.group, GROUP);
    const auto recovery_epoch{EpochForHeight(config->chainlock_schedule, recovery_height)};
    BOOST_REQUIRE(recovery_epoch);
    const auto window{MakeRecoveryRosterBeaconWindow(*objective->recovery_source, *recovery_epoch)};
    BOOST_REQUIRE(window);
    BOOST_CHECK_EQUAL(window->active.seeds.front().readiness_group_floor_plus_one, GROUP + 1);
    BOOST_CHECK_EQUAL(window->next.readiness_group_floor_plus_one, GROUP + 1);
    auto recovery{MakeCatchupChainLock(recovery_height, recovery_height - PQ_CL_PERIOD,
        chain[recovery_height - PQ_CL_PERIOD]->GetBlockHash(), 966'004)};
    recovery.statement.block_hash = chain[recovery_height]->GetBlockHash();
    recovery.statement.payment_probation_state_hash = probation_root;
    recovery.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
    recovery.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
    recovery.statement.btcc_advance = BTCCAdvance::KEEP;
    recovery.statement.btcc_receipt_state = base_receipt_state;
    recovery.statement.roster_transition = RosterAuthorizationTransitionKind::RECOVER;
    recovery.statement.roster_beacons = *window;
    bind_transition(recovery, &base);
    const auto authorization{Access::NetworkRosterAuthorization(*handler, recovery.statement)};
    BOOST_REQUIRE(authorization);
    BOOST_CHECK(authorization->HasPoWRefreshAuthority(genesis, recovery.statement));
    auto wrong_target{recovery.statement};
    wrong_target.block_hash = NonNullHash(966'008);
    BOOST_CHECK(!authorization->HasPoWRefreshAuthority(genesis, wrong_target));
    const auto mask{ValidateRosterAuthorizationState(genesis, recovery.statement, *authorization)};
    BOOST_REQUIRE(mask);
    BOOST_CHECK_EQUAL(*mask, 0b1111);

    RosterAuthorizationVerificationContext unproven;
    unproven.admission = authorization->admission;
    unproven.predecessor_height = authorization->predecessor_height;
    unproven.predecessor_block_hash = authorization->predecessor_block_hash;
    unproven.authorization_base = authorization->authorization_base;
    unproven.reset_policy = authorization->reset_policy;
    unproven.previous = authorization->previous;
    BOOST_CHECK(!unproven.HasPoWRefreshAuthority(genesis, recovery.statement));
    BOOST_CHECK(!ValidateRosterAuthorizationState(genesis, recovery.statement, unproven));
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, recovery));
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, recovery));
    for (const bool old_source : {true, false}) {
        auto forged{recovery};
        auto source{old_source ? base.statement.roster_beacons.active.recovery_authority_source
                              : *objective->recovery_source};
        if (!old_source) source.refresh.seed = NonNullHash(966'005);
        const auto forged_window{MakeRecoveryRosterBeaconWindow(source, *recovery_epoch)};
        BOOST_REQUIRE(forged_window);
        forged.statement.roster_beacons = *forged_window;
        bind_transition(forged, &base);
        BOOST_CHECK(!Access::NetworkRosterAuthorization(*handler, forged.statement));
        BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
            *handler, ChainLockCandidateAdmission::CATCHUP, forged));
        BOOST_CHECK(!authorization->HasPoWRefreshAuthority(genesis, forged.statement));
    }
    work_carrier.pqRecoveryRefreshWorkValidated = false;
    BOOST_CHECK(!Access::NetworkRosterAuthorization(*handler, recovery.statement));
    work_carrier.pqRecoveryRefreshWorkValidated = true;

    const auto install_verified = [&](FinalChainLock& value) {
        QuorumBuildError build_error{QuorumBuildError::NONE};
        const auto rosters{cache->GetVerifiedActive(value.statement.height, *chain[TIP_HEIGHT],
            value.statement.roster_beacons.active, &build_error)};
        BOOST_REQUIRE_MESSAGE(rosters, "quorum build error=" << static_cast<int>(build_error));
        std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            descriptors[slot] = rosters->Rosters()[slot].descriptor;
        }
        value.statement.quorum_context_hash = GetQuorumContextHash(
            genesis, value.statement.height, value.statement.block_hash, descriptors);
        const auto auth{Access::NetworkRosterAuthorization(*handler, value.statement)};
        BOOST_REQUIRE(auth);
        ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
        const auto context{PreparedChainLockContext::Create(config->chainlock_schedule,
            value.statement, rosters, *auth, &verification_error)};
        BOOST_REQUIRE_MESSAGE(context, "verification error=" << static_cast<int>(verification_error));
        ChainLockFinalityError finality_error{ChainLockFinalityError::NONE};
        const auto prepared{store->PrepareCatchupCandidate(value, &finality_error)};
        BOOST_REQUIRE_MESSAGE(prepared, "preparation error=" << static_cast<int>(finality_error));
        const auto universe{cache->BuildPoWRefreshUniverse(GROUP, *chain[recovery_height])};
        BOOST_REQUIRE(universe);
        BOOST_REQUIRE_MESSAGE(store->AcceptCatchupVerified(*prepared, value, true, [] { return true; }, {},
            &finality_error, nullptr, context, universe),
            "acceptance error=" << static_cast<int>(finality_error));
    };
    install_verified(recovery);
    const int32_t carrier_height{recovery_height + static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    const auto before_receipt{Access::ObjectiveRosterAuthorization(*handler, *chain[carrier_height])};
    BOOST_REQUIRE(before_receipt);
    BOOST_CHECK(before_receipt->mode == ObjectiveRosterAuthorizationMode::PAUSE);
    const auto recovery_receipt_state{receipt_for(recovery, base_receipt_state)};
    const auto same_round{Access::ObjectiveRosterAuthorization(*handler, *chain[carrier_height])};
    BOOST_REQUIRE(same_round);
    BOOST_CHECK(same_round->mode == ObjectiveRosterAuthorizationMode::PAUSE);
    const int32_t normal_height{carrier_height + static_cast<int32_t>(PQ_CL_SIGN_LAG)};
    const auto resumed{Access::ObjectiveRosterAuthorization(*handler, *chain[normal_height])};
    BOOST_REQUIRE(resumed);
    BOOST_CHECK(resumed->mode == ObjectiveRosterAuthorizationMode::NORMAL);
    BOOST_REQUIRE(resumed->base);
    BOOST_CHECK(resumed->base->logical_id == recovery.GetLogicalId(genesis));
    BOOST_CHECK(resumed->recovery_source == objective->recovery_source);
    auto normal{recovery};
    normal.statement.height = normal_height;
    normal.statement.block_hash = chain[normal_height]->GetBlockHash();
    normal.statement.previous_chainlock_height = normal_height - PQ_CL_PERIOD;
    normal.statement.previous_chainlock_hash = chain[normal_height - PQ_CL_PERIOD]->GetBlockHash();
    normal.statement.btcc_receipt_state = recovery_receipt_state;
    normal.statement.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    bind_transition(normal, &recovery);
    install_verified(normal);
    BOOST_CHECK(store->GetBestRecord()->metadata.logical_id == normal.GetLogicalId(genesis));
    BOOST_CHECK(HasRecoveryRosterBeacon(normal.statement.roster_beacons));

    auto observe{normal};
    observe.statement.height = normal_height + PQ_CL_PERIOD;
    observe.statement.block_hash = chain[observe.statement.height]->GetBlockHash();
    observe.statement.previous_chainlock_height = normal_height;
    observe.statement.previous_chainlock_hash = normal.statement.block_hash;
    observe.statement.accepted_btcc_cursor = {
        observe.statement.height, observe.statement.block_hash, NonNullHash(966'006)};
    chain[observe.statement.height]->btcpPrevCommitment = observe.statement.accepted_btcc_cursor.btc_hash;
    observe.statement.btcc_advance = BTCCAdvance::ADVANCE;
    observe.statement.roster_transition = RosterAuthorizationTransitionKind::OBSERVE;
    auto& pending{observe.statement.roster_beacons.next};
    pending.state = RosterBeaconState::PENDING;
    pending.anchor_cursor = observe.statement.accepted_btcc_cursor;
    pending.anchor_btc_height = ready.anchor_btc_height + 100;
    bind_transition(observe, &recovery);
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, observe));
    install_verified(observe);
    const auto observation_receipt_state{receipt_for(observe, recovery_receipt_state)};

    auto reveal{observe};
    reveal.statement.height = observe.statement.height + 2 * PQ_BTCC_NEVM_LAG;
    reveal.statement.block_hash = chain[reveal.statement.height]->GetBlockHash();
    reveal.statement.previous_chainlock_height = reveal.statement.height - PQ_CL_PERIOD;
    reveal.statement.previous_chainlock_hash = chain[reveal.statement.previous_chainlock_height]->GetBlockHash();
    reveal.statement.previous_btcc_cursor = observe.statement.accepted_btcc_cursor;
    reveal.statement.btcc_advance = BTCCAdvance::KEEP;
    reveal.statement.btcc_receipt_state = observation_receipt_state;
    reveal.statement.roster_transition = RosterAuthorizationTransitionKind::REVEAL;
    reveal.statement.roster_beacons.next.state = RosterBeaconState::READY;
    reveal.statement.roster_beacons.next.future_btc_hash = NonNullHash(966'007);
    bind_transition(reveal, &observe);
    install_verified(reveal);
    const auto reveal_receipt_state{receipt_for(reveal, observation_receipt_state)};
    const auto next_base{EpochBaseHeight(config->chainlock_schedule, *recovery_epoch + 1)};
    BOOST_REQUIRE(next_base);
    const auto rotation_height{NextEligibleChainLockTargetHeight(config->chainlock_schedule, *next_base - 1)};
    BOOST_REQUIRE(rotation_height);
    BOOST_REQUIRE_LT(*rotation_height, TIP_HEIGHT);
    auto rotate{reveal};
    rotate.statement.height = *rotation_height;
    rotate.statement.block_hash = chain[*rotation_height]->GetBlockHash();
    rotate.statement.previous_chainlock_height = *rotation_height - PQ_CL_PERIOD;
    rotate.statement.previous_chainlock_hash = chain[rotate.statement.previous_chainlock_height]->GetBlockHash();
    rotate.statement.btcc_receipt_state = reveal_receipt_state;
    rotate.statement.roster_transition = RosterAuthorizationTransitionKind::ROTATE;
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        rotate.statement.roster_beacons.active.seeds[slot] = reveal.statement.roster_beacons.active.seeds[slot + 1];
    }
    rotate.statement.roster_beacons.active.seeds.back() = reveal.statement.roster_beacons.next;
    rotate.statement.roster_beacons.next = {};
    rotate.statement.roster_beacons.next.epoch = *recovery_epoch + 2;
    rotate.statement.roster_beacons.next.readiness_group_floor_plus_one =
        rotate.statement.roster_beacons.active.seeds.back().readiness_group_floor_plus_one;
    bind_transition(rotate, &reveal);
    const auto rotation_authorization{Access::NetworkRosterAuthorization(*handler, rotate.statement)};
    BOOST_REQUIRE(rotation_authorization);
    const auto rotation_mask{ValidateRosterAuthorizationState(genesis, rotate.statement, *rotation_authorization)};
    BOOST_REQUIRE(rotation_mask);
    BOOST_CHECK_EQUAL(*rotation_mask, 0b0111);
    install_verified(rotate);
    BOOST_CHECK_EQUAL(std::count_if(rotate.statement.roster_beacons.active.seeds.begin(),
        rotate.statement.roster_beacons.active.seeds.end(),
        [](const RosterBeaconSeed& seed) { return seed.IsRecovery(); }), 3);
    BOOST_CHECK(rotate.statement.roster_beacons.active.recovery_authority_source == *objective->recovery_source);
    BOOST_CHECK_EQUAL(rotate.statement.roster_beacons.next.readiness_group_floor_plus_one, GROUP + 1);
}

void PQAuthorizationBasePathSetup::CheckHistoricalPrefix(bool reauthorize_after_ready, bool mixed_markers,
                                                        bool btcc_terminal_reorg,
                                                        bool btcc_coalesce_markers,
                                                        bool mining_guard)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;
    constexpr int32_t BASE_HEIGHT{2'305};
    constexpr int32_t CARRIER_HEIGHT{2'315};
    constexpr int32_t TIP_HEIGHT{2'840};
    const uint256 probation_root{NonNullHash(943'000)};
    auto& chainman{*Assert(m_node.chainman)};
    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    std::vector<CBlockIndex*> chain(static_cast<std::size_t>(TIP_HEIGHT + 1));
    {
        LOCK(::cs_main);
        chain[0] = chainman.ActiveTip();
        BOOST_REQUIRE(chain[0]);
        const int64_t first_time{GetTime<std::chrono::seconds>().count() - TIP_HEIGHT};
        for (int32_t height{1}; height <= TIP_HEIGHT; ++height) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = chain[height - 1]->GetBlockHash();
            header.hashMerkleRoot = NonNullHash(944'000 + height);
            header.nTime = static_cast<uint32_t>(first_time + height);
            header.nBits = chain[height - 1]->nBits;
            header.nNonce = static_cast<uint32_t>(height);
            chain[height] = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(chain[height]);
            chain[height]->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_RECEIPT_INDEX_VALIDATED | BLOCK_GOVERNANCE_VALIDATED;
            chain[height]->nTx = 1;
            chain[height]->nChainTx = static_cast<unsigned int>(height + 1);
            chain[height]->pqPaymentProbationStateHash = probation_root;
        }
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
        BOOST_REQUIRE(chainman.IsBaseBlockSyncComplete());
        BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(2'330));
        chain[2'330]->nStatus &= ~BLOCK_GOVERNANCE_VALIDATED;
    }
    auto& consensus{const_cast<Consensus::Params&>(chainman.GetConsensus())};
    const auto original_consensus{consensus};
    consensus.nPQActivationHeight = BASE_HEIGHT;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = BASE_HEIGHT;
    consensus.nPQBTCCNEVMInjectionLag = PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1'000;
    consensus.hashPQBTCCReceiptAnchorBlock = chain[1'000]->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nDefaultAssumeValidHeight = -1;
    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *Assert(m_node.connman), *Assert(m_node.peerman), chainman);
    }
    consensus = original_consensus;
    const auto* config{Access::Config(*handler)};
    BOOST_REQUIRE(config);
    FullReceiptCatchupContext store_context;
    store_context.full_receipt_history = true;
    Access::ResetFinalityStoreWithContext(*handler, store_context);
    auto* store{Access::Store(*handler)};
    BOOST_REQUIRE(store);
    auto persistence{std::make_unique<PQChainLockPersistence>(
        DBParams{.path = m_path_root / "historical-prefix-selector", .cache_bytes = 4U << 20,
                 .memory_only = !reauthorize_after_ready && !mining_guard}, genesis, *config)};
    auto* durable{persistence.get()};
    const auto original_persistence{Access::ExchangePersistence(*handler, std::move(persistence))};

    auto base{MakeCatchupChainLock(BASE_HEIGHT, BASE_HEIGHT - 1,
                                  chain[BASE_HEIGHT - 1]->GetBlockHash(), 945'000)};
    base.statement.block_hash = chain[BASE_HEIGHT]->GetBlockHash();
    base.statement.payment_probation_state_hash = probation_root;
    base.statement.accepted_btcc_cursor = {BASE_HEIGHT, base.statement.block_hash, NonNullHash(945'001)};
    base.statement.btcc_advance = BTCCAdvance::ADVANCE;
    chain[BASE_HEIGHT]->btcpPrevCommitment = base.statement.accepted_btcc_cursor.btc_hash;
    base.statement.roster_transition = RosterAuthorizationTransitionKind::INITIALIZE;
    base.statement.roster_authorization_base = {};
    const auto epoch{EpochForHeight(config->chainlock_schedule, BASE_HEIGHT)};
    BOOST_REQUIRE(epoch);
    auto ready{SubjectBeacon(*epoch)};
    ready.anchor_cursor = base.statement.accepted_btcc_cursor;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& seed{base.statement.roster_beacons.active.seeds[slot]};
        seed = ready;
        seed.epoch = *epoch - (ACTIVE_QUORUMS - 1) + slot;
    }
    base.statement.roster_beacons.active.recovery_authority_source.normal_beacon = ready;
    base.statement.roster_beacons.next = {};
    base.statement.roster_beacons.next.epoch = *epoch + 1;
    BOOST_REQUIRE(IsInitialNormalRosterBeaconWindow(base.statement.roster_beacons));
    const auto bind_transition = [&](FinalChainLock& candidate, const FinalChainLock* prior) {
        RosterAuthorizationTransition transition;
        transition.kind = candidate.statement.roster_transition;
        transition.target_height = candidate.statement.height;
        transition.target_block_hash = candidate.statement.block_hash;
        transition.predecessor_height = candidate.statement.previous_chainlock_height;
        transition.predecessor_block_hash = candidate.statement.previous_chainlock_hash;
        if (prior) {
            candidate.statement.roster_authorization_base = {
                prior->statement.height, prior->statement.block_hash, prior->GetLogicalId(genesis)};
            transition.previous = RosterAuthorizationPriorState{
                prior->statement.roster_authorization_state_hash, prior->statement.roster_beacons};
        }
        transition.authorization_base = candidate.statement.roster_authorization_base;
        transition.new_window = candidate.statement.roster_beacons;
        const auto state_hash{GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(state_hash);
        candidate.statement.roster_authorization_state_hash = *state_hash;
        BOOST_REQUIRE(candidate.IsStructurallyValid());
    };
    bind_transition(base, nullptr);
    const auto universe{SelectorRecoveryUniverse(genesis,
        base.statement.roster_beacons.active.recovery_authority_source,
        chain[BASE_HEIGHT - 1]->GetBlockHash())};
    const auto install = [&](const FinalChainLock& candidate, bool persist) {
        const auto context{ChainLockStoreTestContextFactory::CreateDurable(
            genesis, config->chainlock_schedule, candidate.statement)};
        BOOST_REQUIRE(context);
        const auto prepared{store->PrepareCandidate(candidate)};
        BOOST_REQUIRE(prepared);
        BOOST_REQUIRE(store->AcceptVerified(*prepared, candidate, true, nullptr, context));
        if (persist) {
            if (candidate.statement.roster_transition == RosterAuthorizationTransitionKind::INITIALIZE) {
                BOOST_REQUIRE(durable->PersistInitializedBest(
                    candidate, context, nullptr, nullptr, std::nullopt, universe));
            } else {
                const auto& source{candidate.statement.roster_beacons.active.recovery_authority_source};
                BOOST_REQUIRE(durable->PersistBest(candidate, context, nullptr, std::nullopt,
                    SelectorRecoveryUniverse(genesis, source, chain[source.normal_beacon.anchor_cursor.sys_height - 1]->GetBlockHash())));
            }
        }
    };
    install(base, true);
    BTCCReceipt receipt;
    receipt.chainlock_target_height = BASE_HEIGHT;
    receipt.chainlock_target_hash = base.statement.block_hash;
    receipt.chainlock_logical_id = base.GetLogicalId(genesis);
    receipt.accepted_cursor = base.statement.accepted_btcc_cursor;
    auto payment_receipt{NonNullPaymentAuditReceipt(1)};
    const auto payment_schedule{BuildPaymentAuditEpochSchedule(
        PaymentAuditScheduleConfig{config->chainlock_schedule, config->btcc_schedule}, *epoch)};
    BOOST_REQUIRE(payment_schedule);
    BOOST_REQUIRE_LT(payment_schedule->carrier_start_height, TIP_HEIGHT - 5);
    payment_receipt.epoch = *epoch;
    payment_receipt.seal_height = payment_schedule->seal_height;
    payment_receipt.seal_block_hash = chain[payment_receipt.seal_height]->GetBlockHash();
    payment_receipt.carrier_height = payment_schedule->carrier_start_height;
    payment_receipt.subject_roster_beacon = SubjectBeacon(*epoch);
    payment_receipt.next_probation_state_hash = probation_root;
    BOOST_REQUIRE(payment_receipt.IsStructurallyValid());
    const PaymentAuditReceiptState payment_state{
        {payment_receipt.carrier_height, payment_receipt.epoch, payment_receipt.seal_block_hash,
         payment_receipt.audit_logical_id, payment_receipt.audit_witness_id}, NonNullHash(945'002)};
    BOOST_REQUIRE(payment_state.IsStructurallyValid());
    const auto stamp_receipt = [&](const BTCCReceipt& opening) {
        const auto state{ApplyBTCCReceiptState(genesis, config->chainlock_schedule,
            config->btcc_schedule, config->activation_predecessor_height, CARRIER_HEIGHT,
            chain[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{}, opening)};
        BOOST_REQUIRE(state);
        for (int32_t height{CARRIER_HEIGHT}; height <= TIP_HEIGHT; ++height) {
            auto& index{*chain[height]};
            index.pqBTCCReceiptCursorHeight = state->cursor.sys_height;
            index.pqBTCCReceiptCursorSysHash = state->cursor.sys_hash;
            index.pqBTCCReceiptCursorBTCHash = state->cursor.btc_hash;
            index.pqBTCCReceiptStateHash = state->cumulative_hash;
            index.pqBTCCReceiptLatestTargetHeight = state->latest_chainlock_target_height;
            index.pqBTCCReceiptLatestCarrierHeight = state->latest_receipt_carrier_height;
            if (height >= payment_receipt.carrier_height) {
                index.pqPaymentAuditReceiptCursorHeight = payment_state.cursor.carrier_height;
                index.pqPaymentAuditReceiptCursorEpoch = payment_state.cursor.epoch;
                index.pqPaymentAuditReceiptCursorSealHash = payment_state.cursor.seal_block_hash;
                index.pqPaymentAuditReceiptCursorLogicalId = payment_state.cursor.audit_logical_id;
                index.pqPaymentAuditReceiptCursorWitnessId = payment_state.cursor.audit_witness_id;
                index.pqPaymentAuditReceiptStateHash = payment_state.cumulative_hash;
            }
        }
        chain[CARRIER_HEIGHT]->pqBTCCReceiptLogicalId = opening.chainlock_logical_id;
        return *state;
    };
    const auto receipt_state{stamp_receipt(receipt)};
    if (btcc_terminal_reorg) {
        struct RestoreNEVMConnection {
            const bool previous{fNEVMConnection};
            ~RestoreNEVMConnection() { fNEVMConnection = previous; }
        } restore_nevm;
        fNEVMConnection = false;
        constexpr int32_t DURABLE_HEIGHT{2'325};
        constexpr int32_t TERMINAL_HEIGHT{DURABLE_HEIGHT + PQ_BTCC_NEVM_LAG};
        const auto stamp_later_receipt = [&](int32_t carrier_height,
                                              const BTCCReceiptState& previous,
                                              const BTCCReceipt& opening) {
            const auto state{ApplyBTCCReceiptState(
                genesis, config->chainlock_schedule, config->btcc_schedule,
                config->activation_predecessor_height, carrier_height,
                chain[carrier_height]->GetBlockHash(), previous, opening)};
            BOOST_REQUIRE(state);
            for (int32_t height{carrier_height}; height <= TIP_HEIGHT; ++height) {
                auto& index{*chain[height]};
                index.pqBTCCReceiptCursorHeight = state->cursor.sys_height;
                index.pqBTCCReceiptCursorSysHash = state->cursor.sys_hash;
                index.pqBTCCReceiptCursorBTCHash = state->cursor.btc_hash;
                index.pqBTCCReceiptStateHash = state->cumulative_hash;
                index.pqBTCCReceiptLatestTargetHeight = state->latest_chainlock_target_height;
                index.pqBTCCReceiptLatestCarrierHeight = state->latest_receipt_carrier_height;
            }
            chain[carrier_height]->pqBTCCReceiptLogicalId = opening.chainlock_logical_id;
            return *state;
        };
        auto current{base};
        auto current_receipt_state{receipt_state};
        BTCCReceipt middle_receipt;
        for (int32_t height{BASE_HEIGHT + static_cast<int32_t>(PQ_CL_PERIOD)};
             height <= DURABLE_HEIGHT; height += static_cast<int32_t>(PQ_CL_PERIOD)) {
            auto next{MakeCatchupChainLock(height, current.statement.height,
                                          current.statement.block_hash, 988'000 + height)};
            next.statement.block_hash = chain[height]->GetBlockHash();
            next.statement.payment_probation_state_hash = probation_root;
            next.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
            next.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
            next.statement.btcc_receipt_state = height >= DURABLE_HEIGHT
                ? current_receipt_state : receipt_state;
            next.statement.roster_beacons = current.statement.roster_beacons;
            bind_transition(next, &current);
            install(next, true);
            current = std::move(next);
            if (height == CARRIER_HEIGHT) {
                middle_receipt.chainlock_target_height = height;
                middle_receipt.chainlock_target_hash = current.statement.block_hash;
                middle_receipt.chainlock_logical_id = current.GetLogicalId(genesis);
                middle_receipt.accepted_cursor = current.statement.accepted_btcc_cursor;
                current_receipt_state = stamp_later_receipt(
                    DURABLE_HEIGHT, receipt_state, middle_receipt);
            }
        }
        BTCCReceipt terminal_receipt;
        terminal_receipt.chainlock_target_height = DURABLE_HEIGHT;
        terminal_receipt.chainlock_target_hash = current.statement.block_hash;
        terminal_receipt.chainlock_logical_id = current.GetLogicalId(genesis);
        terminal_receipt.accepted_cursor = current.statement.accepted_btcc_cursor;
        (void)stamp_later_receipt(TERMINAL_HEIGHT, current_receipt_state, terminal_receipt);
        BOOST_REQUIRE(Access::IsVerifiedBTCCReceipt(*handler, terminal_receipt,
                                                   *chain[TERMINAL_HEIGHT]));
        BTCCPresealState markers;
        markers.active = BTCCPresealMarker{
            CARRIER_HEIGHT, chain[CARRIER_HEIGHT]->GetBlockHash(), {},
            TERMINAL_HEIGHT, chain[TERMINAL_HEIGHT]->GetBlockHash(),
            current_receipt_state, terminal_receipt, 7};
        if (btcc_coalesce_markers) {
            LOCK(::cs_main);
            auto header{chain[TERMINAL_HEIGHT]->GetBlockHeader()};
            header.hashMerkleRoot = NonNullHash(989'900);
            auto* prospective{chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header)};
            BOOST_REQUIRE(prospective);
            prospective->nStatus = chain[TERMINAL_HEIGHT]->nStatus;
            prospective->nTx = chain[TERMINAL_HEIGHT]->nTx;
            prospective->nChainTx = chain[TERMINAL_HEIGHT]->nChainTx;
            markers.prospective = markers.active;
            markers.prospective->terminal_carrier_hash = prospective->GetBlockHash();
            // The earlier replay floor belongs to the prospective slot. Both
            // terminals will project onto the common receipt at D.
            markers.active->earliest_carrier_height = DURABLE_HEIGHT;
            markers.active->earliest_carrier_hash = current.statement.block_hash;
            markers.active->predecessor_receipt_state = receipt_state;
            BOOST_REQUIRE(chainman.PublishPQHistoryAuthState(PQHistoryAuthState::PENDING));
        }
        Access::SetReplayMarkers(*handler, markers, {});
        Access::SetBTCCPresealRevision(*handler, 7);
        BOOST_REQUIRE(!Access::HasHistoricalSyncAuthorization(*handler));
        if (!btcc_coalesce_markers) {
            BOOST_REQUIRE(!Access::PendingHistory(*handler));
            Access::RefreshHistory(*handler);
            BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
        } else {
            BOOST_REQUIRE(Access::PendingHistory(*handler));
        }
        BOOST_REQUIRE(handler->HasNEVMReplayObligation());
        handler->CheckActiveState();
        BOOST_REQUIRE(handler->HasChainLock(DURABLE_HEIGHT, current.statement.block_hash));
        BOOST_REQUIRE_NE(Access::OpenShareAdmissionForTest(*handler), 0U);
        const auto finality{durable->GetFinalityState()};
        std::vector<CBlockIndex*> fork{chain};
        {
            LOCK(::cs_main);
            for (int32_t height{TERMINAL_HEIGHT}; height <= TIP_HEIGHT; ++height) {
                auto header{chain[height]->GetBlockHeader()};
                header.hashPrevBlock = fork[height - 1]->GetBlockHash();
                header.hashMerkleRoot = NonNullHash(989'000 + height);
                auto* index{chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header)};
                BOOST_REQUIRE(index);
                index->nStatus = chain[height]->nStatus;
                index->nTx = chain[height]->nTx;
                index->nChainTx = chain[height]->nChainTx;
                index->pqPaymentProbationStateHash = probation_root;
                fork[height] = index;
            }
            const auto replacement_state{ApplyBTCCReceiptState(
                genesis, config->chainlock_schedule, config->btcc_schedule,
                config->activation_predecessor_height, TERMINAL_HEIGHT,
                fork[TERMINAL_HEIGHT]->GetBlockHash(), current_receipt_state, terminal_receipt)};
            BOOST_REQUIRE(replacement_state);
            for (int32_t height{TERMINAL_HEIGHT}; height <= TIP_HEIGHT; ++height) {
                auto& index{*fork[height]};
                index.pqBTCCReceiptCursorHeight = replacement_state->cursor.sys_height;
                index.pqBTCCReceiptCursorSysHash = replacement_state->cursor.sys_hash;
                index.pqBTCCReceiptCursorBTCHash = replacement_state->cursor.btc_hash;
                index.pqBTCCReceiptStateHash = replacement_state->cumulative_hash;
                index.pqBTCCReceiptLatestTargetHeight = replacement_state->latest_chainlock_target_height;
                index.pqBTCCReceiptLatestCarrierHeight = replacement_state->latest_receipt_carrier_height;
            }
            fork[TERMINAL_HEIGHT]->pqBTCCReceiptLogicalId = terminal_receipt.chainlock_logical_id;
            chainman.ActiveChainstate().m_chain.SetTip(*fork[TIP_HEIGHT]);
        }
        BOOST_REQUIRE(Access::IsVerifiedBTCCReceipt(*handler, terminal_receipt,
                                                   *fork[TERMINAL_HEIGHT]));
        BOOST_REQUIRE(Access::PendingHistory(*handler));
        if (!btcc_coalesce_markers) {
            auto& common{*chain[TERMINAL_HEIGHT - 1]};
            const auto status{WITH_LOCK(::cs_main, return common.nStatus)};
            {
                LOCK(::cs_main);
                common.nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
            }
            Access::RefreshHistory(*handler);
            BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
            BOOST_CHECK(!Access::IsShareAdmissionTerminal(*handler));
            BOOST_CHECK(!Access::HasShareAdmission(*handler));
            BOOST_CHECK(durable->LoadBTCCPresealState() == markers);
            BOOST_CHECK(durable->GetFinalityState().best == finality.best);
            BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
            {
                LOCK(::cs_main);
                common.nStatus = status;
            }
        }
        // Exercise the certificate/validation callback ordering directly: no
        // scheduler replay pass or new historical capability repairs this first.
        Access::RefreshHistory(*handler);
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
        BOOST_CHECK(!chainman.IsInitialBlockDownload());
        BOOST_CHECK(!Access::PendingHistory(*handler));
        BOOST_CHECK(!Access::IsShareAdmissionTerminal(*handler));
        BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
        BOOST_CHECK(handler->HasChainLock(DURABLE_HEIGHT, current.statement.block_hash));
        BOOST_CHECK(durable->GetFinalityState().best == finality.best);
        BOOST_CHECK(durable->GetFinalityState().unsealed_btcc == finality.unsealed_btcc);
        const auto repaired{durable->LoadBTCCPresealState()};
        BOOST_REQUIRE(repaired.active);
        BOOST_CHECK(!repaired.prospective);
        BOOST_CHECK_EQUAL(repaired.active->earliest_carrier_height, CARRIER_HEIGHT);
        BOOST_CHECK(repaired.active->earliest_carrier_hash == chain[CARRIER_HEIGHT]->GetBlockHash());
        BOOST_CHECK(repaired.active->predecessor_receipt_state == BTCCReceiptState{});
        BOOST_CHECK_EQUAL(repaired.active->terminal_carrier_height, DURABLE_HEIGHT);
        BOOST_CHECK(repaired.active->terminal_carrier_hash == current.statement.block_hash);
        BOOST_CHECK(repaired.active->terminal_receipt == middle_receipt);
        BOOST_CHECK(repaired.active->terminal_parent_receipt_state == receipt_state);
        BOOST_CHECK_GT(repaired.active->revision, markers.active->revision);
        BOOST_CHECK(handler->HasNEVMReplayObligation());
        Access::RefreshHistory(*handler);
        BOOST_CHECK(durable->LoadBTCCPresealState() == repaired);
        Access::ExchangePersistence(*handler, nullptr).reset();
        persistence = std::make_unique<PQChainLockPersistence>(
            DBParams{.path = m_path_root / "historical-prefix-selector", .cache_bytes = 4U << 20},
            genesis, *config);
        BOOST_CHECK(persistence->LoadBTCCPresealState() == repaired);
        BOOST_CHECK(persistence->GetFinalityState().best == finality.best);
        Access::ExchangePersistence(*handler, std::move(persistence));
        return;
    }
    if (mixed_markers) {
        constexpr int32_t DURABLE_HEIGHT{2'825};
        constexpr int32_t COVERAGE_HEIGHT{2'830};
        constexpr int32_t LATE_CARRIER_HEIGHT{2'835};
        auto current{base};
        for (int32_t height{BASE_HEIGHT + static_cast<int32_t>(PQ_CL_PERIOD)};
             height <= DURABLE_HEIGHT; height += static_cast<int32_t>(PQ_CL_PERIOD)) {
            auto next{MakeCatchupChainLock(height, current.statement.height,
                                          current.statement.block_hash, 982'000 + height)};
            next.statement.block_hash = chain[height]->GetBlockHash();
            next.statement.payment_probation_state_hash = probation_root;
            next.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
            next.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
            next.statement.roster_beacons = current.statement.roster_beacons;
            if (height >= CARRIER_HEIGHT) next.statement.btcc_receipt_state = receipt_state;
            if (height >= payment_receipt.carrier_height) next.statement.payment_audit_receipt_state = payment_state;
            auto& window{next.statement.roster_beacons};
            const auto target_epoch{EpochForHeight(config->chainlock_schedule, height)};
            BOOST_REQUIRE(target_epoch);
            if (*target_epoch > window.active.seeds.back().epoch) {
                BOOST_REQUIRE(window.next.IsReady());
                for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
                    window.active.seeds[slot] = window.active.seeds[slot + 1];
                }
                window.active.seeds.back() = window.next;
                window.active.recovery_authority_source.normal_beacon = window.next;
                window.next = {};
                window.next.epoch = *target_epoch + 1;
                window.next.readiness_group_floor_plus_one =
                    window.active.seeds.back().readiness_group_floor_plus_one;
                next.statement.roster_transition = RosterAuthorizationTransitionKind::ROTATE;
            } else if (window.next.state == RosterBeaconState::EMPTY) {
                window.next.state = RosterBeaconState::PENDING;
                window.next.anchor_cursor = base.statement.accepted_btcc_cursor;
                window.next.anchor_btc_height = 800'000;
                next.statement.roster_transition = RosterAuthorizationTransitionKind::OBSERVE;
            } else if (window.next.state == RosterBeaconState::PENDING) {
                window.next.state = RosterBeaconState::READY;
                window.next.future_btc_hash = NonNullHash(982'001);
                next.statement.roster_transition = RosterAuthorizationTransitionKind::REVEAL;
            }
            bind_transition(next, &current);
            install(next, true);
            current = std::move(next);
        }
        const auto boundary{Access::SelectHistoricalSyncBoundary(*handler)};
        BOOST_REQUIRE(boundary);
        BOOST_REQUIRE_EQUAL(boundary->coverage_height, COVERAGE_HEIGHT);
        BOOST_REQUIRE_EQUAL(payment_receipt.carrier_height, 2'825);
        BOOST_REQUIRE_LT(DURABLE_HEIGHT, boundary->coverage_height);
        const auto base_view{store->GetVerifiedRosterAuthorizationBaseByLogicalId(base.GetLogicalId(genesis))};
        BOOST_REQUIRE(base_view);
        const auto identity{Access::PersistHistoricalBootstrap(*handler, base,
            ChainLockStoreTestContextFactory::CreateDurable(genesis, config->chainlock_schedule, base.statement),
            *boundary)};
        Access::SetHistoricalSyncAuthorization(*handler, *boundary, *base_view, std::nullopt, identity);

        BTCCReceipt late_receipt{receipt};
        late_receipt.chainlock_target_height = current.statement.height;
        late_receipt.chainlock_target_hash = current.statement.block_hash;
        late_receipt.chainlock_logical_id = current.GetLogicalId(genesis);
        const auto late_state{ApplyBTCCReceiptState(genesis, config->chainlock_schedule,
            config->btcc_schedule, config->activation_predecessor_height, LATE_CARRIER_HEIGHT,
            chain[LATE_CARRIER_HEIGHT]->GetBlockHash(), receipt_state, late_receipt)};
        BOOST_REQUIRE(late_state);
        for (int32_t height{LATE_CARRIER_HEIGHT}; height <= TIP_HEIGHT; ++height) {
            auto& index{*chain[height]};
            index.pqBTCCReceiptCursorHeight = late_state->cursor.sys_height;
            index.pqBTCCReceiptCursorSysHash = late_state->cursor.sys_hash;
            index.pqBTCCReceiptCursorBTCHash = late_state->cursor.btc_hash;
            index.pqBTCCReceiptStateHash = late_state->cumulative_hash;
            index.pqBTCCReceiptLatestTargetHeight = late_state->latest_chainlock_target_height;
            index.pqBTCCReceiptLatestCarrierHeight = late_state->latest_receipt_carrier_height;
        }
        chain[LATE_CARRIER_HEIGHT]->pqBTCCReceiptLogicalId = late_receipt.chainlock_logical_id;
        BOOST_REQUIRE(Access::IsVerifiedBTCCReceipt(*handler, late_receipt, *chain[LATE_CARRIER_HEIGHT]));
        BTCCPresealState btcc_markers;
        btcc_markers.active = BTCCPresealMarker{
            LATE_CARRIER_HEIGHT, chain[LATE_CARRIER_HEIGHT]->GetBlockHash(), receipt_state,
            LATE_CARRIER_HEIGHT, chain[LATE_CARRIER_HEIGHT]->GetBlockHash(), receipt_state, late_receipt, 1};
        PaymentAuditPresealState payment_markers;
        payment_markers.active = PaymentAuditPresealMarker{
            payment_receipt.carrier_height, chain[payment_receipt.carrier_height]->GetBlockHash(),
            PaymentAuditReceiptState{}, probation_root, payment_receipt.carrier_height,
            chain[payment_receipt.carrier_height]->GetBlockHash(), payment_receipt, 1};
        Access::SetReplayMarkers(*handler, btcc_markers, payment_markers);
        BOOST_REQUIRE(!Access::PendingHistory(*handler));
        BOOST_REQUIRE(Access::PendingHistory(*handler, /*allow_prefix=*/false));
        Access::RefreshHistory(*handler);
        BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
        handler->CheckActiveState();
        BOOST_REQUIRE(handler->HasChainLock(DURABLE_HEIGHT, current.statement.block_hash));
        const auto finality{durable->GetFinalityState()};
        {
            LOCK(::cs_main);
            CBlockIndex* parent{chain[COVERAGE_HEIGHT - 1]};
            for (int32_t height{COVERAGE_HEIGHT}; height <= TIP_HEIGHT; ++height) {
                auto header{chain[height]->GetBlockHeader()};
                header.hashPrevBlock = parent->GetBlockHash();
                header.hashMerkleRoot = NonNullHash(983'000 + height);
                auto* index{chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header)};
                BOOST_REQUIRE(index);
                index->nStatus = chain[height]->nStatus;
                index->nTx = chain[height]->nTx;
                index->nChainTx = chain[height]->nChainTx;
                parent = index;
            }
            chainman.ActiveChainstate().m_chain.SetTip(*parent);
        }
        BOOST_REQUIRE(!Access::HasHistoricalSyncAuthorization(*handler));
        BOOST_REQUIRE(Access::IsVerifiedBTCCReceipt(*handler, late_receipt, *chain[LATE_CARRIER_HEIGHT]));
        const auto missing_id{NonNullHash(983'999)};
        BOOST_CHECK(!Access::TryReenterWithBTCCReceiptId(*handler, missing_id));
        {
            LOCK(::cs_main);
            chain[LATE_CARRIER_HEIGHT]->pqBTCCReceiptLogicalId = missing_id;
        }
        BOOST_CHECK(!Access::TryReenterWithBTCCReceiptId(*handler, missing_id));
        {
            LOCK(::cs_main);
            chain[LATE_CARRIER_HEIGHT]->pqBTCCReceiptLogicalId = late_receipt.chainlock_logical_id;
        }
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
        Access::RevokeHistoricalAuthorization(*handler);
        Access::RefreshHistory(*handler);
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::PENDING);
        BOOST_CHECK(!chainman.IsInitialBlockDownload());
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK(handler->HasChainLock(DURABLE_HEIGHT, current.statement.block_hash));
        BOOST_CHECK(durable->GetFinalityState().best == finality.best);
        BOOST_CHECK(durable->LoadBTCCPresealState() == btcc_markers);
        BOOST_CHECK(durable->LoadPaymentAuditPresealState() == payment_markers);
        return;
    }
    const auto equal_boundary{Access::SelectHistoricalSyncBoundary(*handler)};
    BOOST_REQUIRE(equal_boundary);
    BOOST_CHECK(equal_boundary->receipt == receipt);
    BOOST_CHECK(equal_boundary->durable_prior == durable->GetFinalityState().best->AuthorizationBase());
    BOOST_CHECK_GT(equal_boundary->coverage_height, BASE_HEIGHT);
    BOOST_CHECK(Access::ValidateHistoricalSyncBoundary(*handler, *equal_boundary, base));
    const auto local{store->GetServableByLogicalId(equal_boundary->receipt.chainlock_logical_id)};
    BOOST_REQUIRE(local);
    BOOST_CHECK(*local == base);
    BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
    const auto bootstrap_identity{Access::PersistHistoricalBootstrap(*handler, base,
        ChainLockStoreTestContextFactory::CreateDurable(genesis, config->chainlock_schedule, base.statement), *equal_boundary)};
    Access::MaintainHistoricalRetention(*handler);
    BOOST_REQUIRE(durable->LoadHistoricalSyncBootstrap());
    auto wrong_opening{receipt};
    wrong_opening.chainlock_logical_id = NonNullHash(946'000);
    stamp_receipt(wrong_opening);
    BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler));
    stamp_receipt(receipt);

    if (reauthorize_after_ready) {
        const auto* quorum_config{Access::QuorumConfig(*handler)};
        BOOST_REQUIRE(quorum_config);
        const auto roster_lookups{std::make_shared<std::size_t>(0)};
        const auto unavailable_rosters{FrozenQuorumRosterCache::Create(
            genesis, *quorum_config,
            [roster_lookups](const CBlockIndex&) -> std::optional<QuorumSnapshotState> {
                ++*roster_lookups;
                return std::nullopt;
            }, /*cache_results=*/false, Access::RecoveryUniverseLookup(*handler))};
        BOOST_REQUIRE(unavailable_rosters);
        handler->SetQuorumRosterCache(unavailable_rosters);
        // Keep D below E: the payment marker has no independent checkpoint,
        // so revoking only E must reopen authentication without undoing D.
        BOOST_REQUIRE_LT(BASE_HEIGHT, payment_receipt.carrier_height);
        BOOST_REQUIRE_LT(payment_receipt.carrier_height, equal_boundary->coverage_height);
        const auto initial_finality{durable->GetFinalityState()};
        const auto base_view{store->GetVerifiedRosterAuthorizationBaseByLogicalId(base.GetLogicalId(genesis))};
        BOOST_REQUIRE(base_view);
        Access::SetHistoricalSyncAuthorization(*handler, *equal_boundary, *base_view,
                                               std::nullopt, bootstrap_identity);
        BTCCPresealState btcc_markers;
        btcc_markers.active = BTCCPresealMarker{
            CARRIER_HEIGHT, chain[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{},
            CARRIER_HEIGHT, chain[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{}, receipt, 1};
        PaymentAuditPresealState payment_markers;
        payment_markers.active = PaymentAuditPresealMarker{
            payment_receipt.carrier_height, chain[payment_receipt.carrier_height]->GetBlockHash(),
            PaymentAuditReceiptState{}, probation_root, payment_receipt.carrier_height,
            chain[payment_receipt.carrier_height]->GetBlockHash(), payment_receipt, 1};
        Access::SetReplayMarkers(*handler, btcc_markers, payment_markers);
        BOOST_REQUIRE(!Access::PendingHistory(*handler));
        BOOST_REQUIRE(Access::PendingHistory(*handler, /*allow_prefix=*/false));
        Access::RefreshHistory(*handler);
        BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
        handler->CheckActiveState();
        BOOST_REQUIRE(handler->HasChainLock(BASE_HEIGHT, base.statement.block_hash));
        // This fixture does not Start the handler; own the gate independently
        // of its scheduler lifecycle and the test network's spork setting.
        uint64_t signing_generation{Access::OpenShareAdmissionForTest(*handler)};
        BOOST_REQUIRE_NE(signing_generation, 0U);

        const fs::path journal_path{m_path_root / "historical-prefix-signer"};
        auto journal{std::make_unique<llmq::CPQSignerJournal>(journal_path)};
        auto* journal_ptr{journal.get()};
        const auto original_journal{Access::ExchangeSignerJournal(*handler, std::move(journal))};
        const llmq::PQSignerJournalKey key{
            .genesis_hash = genesis,
            .child_profile = CHILD_SCHEDULED_WOTS_SHAKE_128_V1,
            .pro_tx_hash = NonNullHash(949'100),
            .quorum_epoch = *epoch,
            .child_key_hash = NonNullHash(949'101),
            .leaf_index = 0,
            .absolute_height = BASE_HEIGHT + 5,
        };
        const uint256 message{NonNullHash(949'102)};
        const llmq::PQSignerBranchLock vote{
            key.absolute_height, chain[key.absolute_height]->GetBlockHash(), message};
        BOOST_REQUIRE(journal_ptr->Reserve(key, message, vote, std::nullopt).outcome ==
                      llmq::PQSignerJournalOutcome::RESERVED);

        const auto fork_after = [&](int32_t height, uint64_t salt) {
            std::vector<CBlockIndex*> fork{chain};
            LOCK(::cs_main);
            for (int32_t next{height + 1}; next <= TIP_HEIGHT; ++next) {
                auto header{chain[next]->GetBlockHeader()};
                header.hashPrevBlock = fork[next - 1]->GetBlockHash();
                header.hashMerkleRoot = NonNullHash(salt + next);
                auto* index{chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header)};
                BOOST_REQUIRE(index);
                const auto* original{chain[next]};
                index->nStatus = original->nStatus;
                index->nTx = original->nTx;
                index->nChainTx = original->nChainTx;
                index->btcpPrevCommitment = original->btcpPrevCommitment;
                index->pqBTCCReceiptCursorHeight = original->pqBTCCReceiptCursorHeight;
                index->pqBTCCReceiptCursorSysHash = original->pqBTCCReceiptCursorSysHash;
                index->pqBTCCReceiptCursorBTCHash = original->pqBTCCReceiptCursorBTCHash;
                index->pqBTCCReceiptStateHash = original->pqBTCCReceiptStateHash;
                index->pqBTCCReceiptLatestTargetHeight = original->pqBTCCReceiptLatestTargetHeight;
                index->pqBTCCReceiptLatestCarrierHeight = original->pqBTCCReceiptLatestCarrierHeight;
                index->pqBTCCReceiptLogicalId = original->pqBTCCReceiptLogicalId;
                index->pqPaymentAuditReceiptCursorHeight = original->pqPaymentAuditReceiptCursorHeight;
                index->pqPaymentAuditReceiptCursorEpoch = original->pqPaymentAuditReceiptCursorEpoch;
                index->pqPaymentAuditReceiptCursorSealHash = original->pqPaymentAuditReceiptCursorSealHash;
                index->pqPaymentAuditReceiptCursorLogicalId = original->pqPaymentAuditReceiptCursorLogicalId;
                index->pqPaymentAuditReceiptCursorWitnessId = original->pqPaymentAuditReceiptCursorWitnessId;
                index->pqPaymentAuditReceiptStateHash = original->pqPaymentAuditReceiptStateHash;
                index->pqPaymentProbationStateHash = original->pqPaymentProbationStateHash;
                fork[next] = index;
            }
            chainman.ActiveChainstate().m_chain.SetTip(*fork[TIP_HEIGHT]);
            return fork;
        };
        const auto conflicting{fork_after(BASE_HEIGHT - 1, 959'000)};
        BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler));
        BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, *equal_boundary, base));
        BOOST_CHECK(WITH_LOCK(::cs_main, return handler->HasConflictingChainLock(
            BASE_HEIGHT, conflicting[BASE_HEIGHT]->GetBlockHash())));
        {
            LOCK(::cs_main);
            chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
        }
        Access::ClearHistoricalIndexTestCache(*handler);
        BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
        auto previous_boundary{*equal_boundary};
        uint256 previous_identity{bootstrap_identity};
        std::shared_ptr<const FinalChainLock> retained_certificate;
        RecoveryUniverseCapsulePtr retained_universe;
        for (const bool different_base : {false, true}) {
            BOOST_TEST_CONTEXT("replacement names " << (different_base ? "different B" : "same B")) {
                auto fork{fork_after(different_base ? BASE_HEIGHT : previous_boundary.coverage_height - 1,
                                     different_base ? 970'000 : 960'000)};
                BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
                BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, previous_boundary, base));
                BOOST_CHECK(!Access::TryReenterWithMalformedPaymentMarker(*handler));
                BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
                Access::SetHistoricalRequest(*handler, previous_boundary.receipt.chainlock_logical_id);
                if (different_base) Access::MaintainHistoricalRetention(*handler);
                else Access::RevokeHistoricalAuthorization(*handler);
                Access::RefreshHistory(*handler);
                Access::RefreshHistory(*handler);
                BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::PENDING);
                BOOST_CHECK(!chainman.IsInitialBlockDownload());
                BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
                BOOST_CHECK(!Access::HasShareAdmission(*handler));
                BOOST_CHECK(!Access::IsShareAdmissionCurrent(*handler, signing_generation));
                BOOST_CHECK(!Access::IsShareAdmissionTerminal(*handler));
                handler->CheckActiveState();
                BOOST_CHECK(!Access::HasShareAdmission(*handler));
                BOOST_CHECK(handler->HasChainLock(BASE_HEIGHT, base.statement.block_hash));
                BOOST_CHECK(WITH_LOCK(::cs_main, return handler->HasConflictingChainLock(
                    BASE_HEIGHT, NonNullHash(949'103))));
                BOOST_CHECK(durable->GetFinalityState().best == initial_finality.best);
                BOOST_CHECK(durable->GetFinalityState().unsealed_btcc == initial_finality.unsealed_btcc);
                BOOST_CHECK(durable->LoadBTCCPresealState() == btcc_markers);
                BOOST_CHECK(durable->LoadPaymentAuditPresealState() == payment_markers);
                Access::MaintainHistoricalRetention(*handler);
                BOOST_CHECK(!durable->IsHistoricalSyncRecordCurrent(previous_boundary, previous_identity));
                BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
                if (!different_base) {
                    Access::ExchangePersistence(*handler, nullptr).reset();
                    persistence = std::make_unique<PQChainLockPersistence>(
                        DBParams{.path = m_path_root / "historical-prefix-selector", .cache_bytes = 4U << 20},
                        genesis, *config);
                    durable = persistence.get();
                    BOOST_CHECK(durable->GetFinalityState().best == initial_finality.best);
                    BOOST_CHECK(durable->GetFinalityState().unsealed_btcc == initial_finality.unsealed_btcc);
                    BOOST_CHECK(durable->LoadBTCCPresealState() == btcc_markers);
                    BOOST_CHECK(durable->LoadPaymentAuditPresealState() == payment_markers);
                    BOOST_CHECK(!durable->LoadHistoricalSyncBootstrap());
                    Access::ExchangePersistence(*handler, std::move(persistence));
                    Access::ExchangeSignerJournal(*handler, nullptr).reset();
                    journal = std::make_unique<llmq::CPQSignerJournal>(journal_path);
                    BOOST_CHECK(journal->GetBranchLock(genesis, key.pro_tx_hash, key.absolute_height) == vote);
                    BOOST_CHECK(journal->Reserve(key, message, vote, vote).outcome ==
                                llmq::PQSignerJournalOutcome::CONSUMED);
                    Access::ExchangeSignerJournal(*handler, std::move(journal));
                    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::PENDING);
                    retained_certificate = Access::HistoricalRevalidationCertificate(*handler);
                    retained_universe = Access::HistoricalRevalidationUniverse(*handler);
                    BOOST_REQUIRE(retained_certificate);
                    BOOST_REQUIRE(retained_universe);
                    BOOST_CHECK(*retained_certificate == base);
                    BOOST_CHECK(*retained_universe == *universe);
                    BOOST_CHECK(!Access::RevalidationInputIsPeerServable(*handler, base.GetLogicalId(genesis)));
                    const auto lookup{Access::RecoveryUniverseLookup(*handler)};
                    auto held_persistence{Access::ExchangePersistence(*handler, nullptr)};
                    const auto cached_universe{lookup(universe->SourceId())};
                    const auto unrelated_universe{lookup(NonNullHash(949'104))};
                    Access::ExchangePersistence(*handler, std::move(held_persistence));
                    BOOST_CHECK(cached_universe == retained_universe);
                    BOOST_CHECK(!unrelated_universe);
                } else {
                    BOOST_CHECK(!Access::HistoricalRevalidationCertificate(*handler));
                    BOOST_CHECK(!Access::HistoricalRevalidationUniverse(*handler));
                }

                FinalChainLock replacement{base};
                if (different_base) {
                    const int32_t candidate_period{static_cast<int32_t>(config->btcc_schedule.candidate_period)};
                    const auto preceding_state{ApplyBTCCReceiptState(
                        genesis, config->chainlock_schedule, config->btcc_schedule,
                        config->activation_predecessor_height, CARRIER_HEIGHT,
                        fork[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{}, receipt)};
                    BOOST_REQUIRE(preceding_state);
                    replacement.statement.height = BASE_HEIGHT + candidate_period;
                    replacement.statement.block_hash = fork[replacement.statement.height]->GetBlockHash();
                    replacement.statement.previous_chainlock_height = replacement.statement.height -
                        static_cast<int32_t>(config->chainlock_schedule.chainlock_period);
                    replacement.statement.previous_chainlock_hash =
                        fork[replacement.statement.previous_chainlock_height]->GetBlockHash();
                    replacement.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
                    replacement.statement.btcc_receipt_state = *preceding_state;
                    replacement.statement.btcc_advance = BTCCAdvance::KEEP;
                    replacement.statement.roster_transition = RosterAuthorizationTransitionKind::KEEP;
                    bind_transition(replacement, &base);
                    BTCCReceipt opening{receipt};
                    opening.chainlock_target_height = replacement.statement.height;
                    opening.chainlock_target_hash = replacement.statement.block_hash;
                    opening.chainlock_logical_id = replacement.GetLogicalId(genesis);
                    const int32_t carrier_height{CARRIER_HEIGHT + candidate_period};
                    const auto state{ApplyBTCCReceiptState(genesis, config->chainlock_schedule,
                        config->btcc_schedule, config->activation_predecessor_height, carrier_height,
                        fork[carrier_height]->GetBlockHash(), *preceding_state, opening)};
                    BOOST_REQUIRE(state);
                    for (int32_t height{CARRIER_HEIGHT}; height <= TIP_HEIGHT; ++height) {
                        auto& index{*fork[height]};
                        const auto indexed{height >= carrier_height ? *state : *preceding_state};
                        index.pqBTCCReceiptCursorHeight = indexed.cursor.sys_height;
                        index.pqBTCCReceiptCursorSysHash = indexed.cursor.sys_hash;
                        index.pqBTCCReceiptCursorBTCHash = indexed.cursor.btc_hash;
                        index.pqBTCCReceiptStateHash = indexed.cumulative_hash;
                        index.pqBTCCReceiptLatestTargetHeight = indexed.latest_chainlock_target_height;
                        index.pqBTCCReceiptLatestCarrierHeight = indexed.latest_receipt_carrier_height;
                        index.pqBTCCReceiptLogicalId.SetNull();
                    }
                    fork[CARRIER_HEIGHT]->pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
                    fork[carrier_height]->pqBTCCReceiptLogicalId = opening.chainlock_logical_id;
                    btcc_markers.active = BTCCPresealMarker{
                        carrier_height, fork[carrier_height]->GetBlockHash(), *preceding_state,
                        carrier_height, fork[carrier_height]->GetBlockHash(), *preceding_state, opening, 2};
                    payment_markers.active->earliest_carrier_hash = fork[payment_receipt.carrier_height]->GetBlockHash();
                    payment_markers.active->terminal_carrier_hash = fork[payment_receipt.carrier_height]->GetBlockHash();
                    ++payment_markers.active->revision;
                    Access::SetReplayMarkers(*handler, btcc_markers, payment_markers);
                }
                Access::ClearHistoricalIndexTestCache(*handler);
                const auto selected{Access::SelectHistoricalSyncBoundary(*handler)};
                BOOST_REQUIRE(selected);
                BOOST_CHECK(selected->receipt.chainlock_logical_id == replacement.GetLogicalId(genesis));
                BOOST_REQUIRE(Access::ValidateHistoricalSyncBoundary(*handler, *selected, replacement));
                if (!different_base) {
                    const auto lookups_before{*roster_lookups};
                    BlockValidationState state;
                    BOOST_CHECK(!handler->ProcessNewChainLock(-1, *retained_certificate, state));
                    BOOST_CHECK_EQUAL(state.GetRejectReason(), "pq-clsig-historical-rosters-unavailable");
                    BOOST_CHECK_GT(*roster_lookups, lookups_before);
                    const auto refresh_lookups_before{*roster_lookups};
                    BOOST_CHECK(Access::RefreshHistoricalBoundary(*handler));
                    BOOST_CHECK_GT(*roster_lookups, refresh_lookups_before);
                } else {
                    // A second branch change can select another B before a
                    // previous byte-only cache has successfully revalidated.
                    Access::SetHistoricalRevalidationInput(*handler, retained_certificate, retained_universe);
                    const auto lookups_before{*roster_lookups};
                    BOOST_CHECK(Access::RefreshHistoricalBoundary(*handler));
                    BOOST_CHECK_EQUAL(*roster_lookups, lookups_before);
                }
                BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
                BOOST_CHECK(Access::HistoricalRevalidationCertificate(*handler) == retained_certificate);
                BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::PENDING);
                BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
                {
                    LOCK(::cs_main);
                    fork[selected->coverage_height]->nStatus |= BLOCK_FAILED_VALID;
                }
                Access::ClearHistoricalIndexTestCache(*handler);
                BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler));
                BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, *selected, replacement));
                {
                    LOCK(::cs_main);
                    fork[selected->coverage_height]->nStatus &= ~BLOCK_FAILED_VALID;
                }
                Access::ClearHistoricalIndexTestCache(*handler);
                const auto context{ChainLockStoreTestContextFactory::CreateDurable(
                    genesis, config->chainlock_schedule, replacement.statement)};
                if (different_base) {
                    BOOST_REQUIRE(durable->PersistVerifiedAuthorizationBase(replacement, context, nullptr, universe));
                }
                previous_identity = Access::PersistHistoricalBootstrap(*handler, replacement, context, *selected);
                const VerifiedRosterAuthorizationBaseView replacement_view{
                    base_view->base_revision,
                    {replacement.GetLogicalId(genesis), replacement.GetWitnessId(genesis), replacement.statement},
                    std::make_shared<const FinalChainLock>(replacement), context};
                Access::SetHistoricalSyncAuthorization(*handler, *selected, replacement_view,
                                                       std::nullopt, previous_identity);
                BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
                BOOST_CHECK(!Access::RefreshHistoricalBoundary(*handler));
                BOOST_CHECK(!Access::HistoricalRevalidationCertificate(*handler));
                BOOST_CHECK(!Access::HistoricalRevalidationUniverse(*handler));
                BOOST_CHECK(Access::PendingHistory(*handler, /*allow_prefix=*/false));
                Access::RefreshHistory(*handler);
                BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
                BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
                BOOST_CHECK(handler->HasChainLock(BASE_HEIGHT, base.statement.block_hash));
                const uint64_t resumed_generation{Access::OpenShareAdmissionForTest(*handler)};
                BOOST_CHECK_NE(resumed_generation, 0U);
                BOOST_CHECK(resumed_generation != signing_generation);
                BOOST_CHECK(!Access::IsShareAdmissionCurrent(*handler, signing_generation));
                BOOST_CHECK(!Access::IsShareAdmissionTerminal(*handler));
                signing_generation = resumed_generation;
                previous_boundary = *selected;
            }
        }
        // Durable markers and one-time reservations survive reopening; neither
        // transient authorization loss nor replacement may refund a leaf.
        Access::ExchangePersistence(*handler, nullptr).reset();
        persistence = std::make_unique<PQChainLockPersistence>(
            DBParams{.path = m_path_root / "historical-prefix-selector", .cache_bytes = 4U << 20}, genesis, *config);
        BOOST_CHECK(persistence->GetFinalityState().best == initial_finality.best);
        BOOST_CHECK(persistence->LoadBTCCPresealState() == btcc_markers);
        BOOST_CHECK(persistence->LoadPaymentAuditPresealState() == payment_markers);
        BOOST_REQUIRE(persistence->LoadHistoricalSyncBootstrap());
        Access::ExchangePersistence(*handler, std::move(persistence));
        Access::ExchangeSignerJournal(*handler, nullptr).reset();
        journal = std::make_unique<llmq::CPQSignerJournal>(journal_path);
        BOOST_CHECK(journal->GetBranchLock(genesis, key.pro_tx_hash, key.absolute_height) == vote);
        BOOST_CHECK(journal->Reserve(key, message, vote, vote).outcome == llmq::PQSignerJournalOutcome::CONSUMED);
        Access::ExchangeSignerJournal(*handler, std::move(journal));
        return;
    }

    auto current{base};
    for (int32_t height{BASE_HEIGHT + static_cast<int32_t>(PQ_CL_PERIOD)}; height <= 2'325;
         height += static_cast<int32_t>(PQ_CL_PERIOD)) {
        auto next{MakeCatchupChainLock(height, current.statement.height,
                                      current.statement.block_hash, 947'000 + height)};
        next.statement.block_hash = chain[height]->GetBlockHash();
        next.statement.payment_probation_state_hash = probation_root;
        next.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
        next.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
        next.statement.roster_beacons = current.statement.roster_beacons;
        if (height >= CARRIER_HEIGHT) {
            next.statement.btcc_receipt_state = receipt_state;
        }
        bind_transition(next, &current);
        install(next, true);
        current = std::move(next);
    }
    const auto older_boundary{Access::SelectHistoricalSyncBoundary(*handler)};
    BOOST_REQUIRE(older_boundary);
    BOOST_CHECK(older_boundary->receipt == receipt);
    BOOST_CHECK(older_boundary->durable_prior == durable->GetFinalityState().best->AuthorizationBase());
    BOOST_CHECK_LT(older_boundary->carrier_height, older_boundary->durable_prior.height);
    BOOST_CHECK_GT(older_boundary->coverage_height, older_boundary->durable_prior.height);
    BOOST_CHECK(Access::ValidateHistoricalSyncBoundary(*handler, *older_boundary, base));
    const auto retained_base{store->GetServableByLogicalId(older_boundary->receipt.chainlock_logical_id)};
    BOOST_REQUIRE(retained_base);
    BOOST_CHECK(*retained_base == base);
    BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, *equal_boundary, base));
    BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, *older_boundary, current));
    BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler, current.statement.height));
    BOOST_CHECK(store->GetBestRecord()->metadata.statement == current.statement);

    const std::vector<std::function<uint32_t(uint32_t)>> corruptions{
        [](uint32_t status) { return status & ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED; },
        [](uint32_t status) { return status | BLOCK_ASSUMED_VALID; },
        [](uint32_t status) { return status | BLOCK_FAILED_VALID; },
        [](uint32_t status) { return (status & ~BLOCK_VALID_MASK) | BLOCK_VALID_CHAIN; },
    };
    for (const int32_t height : {BASE_HEIGHT, CARRIER_HEIGHT - 1, CARRIER_HEIGHT,
                                  older_boundary->coverage_height}) {
        for (std::size_t i{0}; i < corruptions.size(); ++i) {
            BOOST_TEST_CONTEXT("selector anchor " << height << ", corruption " << i) {
                const auto status{WITH_LOCK(::cs_main, return chain[height]->nStatus)};
                {
                    LOCK(::cs_main);
                    chain[height]->nStatus = corruptions[i](status);
                }
                Access::ClearHistoricalIndexTestCache(*handler);
                BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler));
                BOOST_CHECK(!Access::ValidateHistoricalSyncBoundary(*handler, *older_boundary, base));
                {
                    LOCK(::cs_main);
                    chain[height]->nStatus = status;
                }
                Access::ClearHistoricalIndexTestCache(*handler);
                BOOST_REQUIRE(Access::SelectHistoricalSyncBoundary(*handler));
            }
        }
    }
    auto unpublished{MakeCatchupChainLock(2'330, current.statement.height,
                                        current.statement.block_hash, 948'000)};
    unpublished.statement.block_hash = chain[2'330]->GetBlockHash();
    unpublished.statement.payment_probation_state_hash = probation_root;
    unpublished.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
    unpublished.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
    unpublished.statement.btcc_receipt_state = receipt_state;
    unpublished.statement.roster_beacons = current.statement.roster_beacons;
    bind_transition(unpublished, &current);
    install(unpublished, false);
    BOOST_CHECK(!Access::SelectHistoricalSyncBoundary(*handler));
    BOOST_CHECK(durable->GetFinalityState().best->statement == current.statement);
    BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
    {
        LOCK(::cs_main);
        BOOST_CHECK(!(chain[2'330]->nStatus & BLOCK_GOVERNANCE_VALIDATED));
    }

    BOOST_REQUIRE(durable->PersistBest(unpublished,
        ChainLockStoreTestContextFactory::CreateDurable(genesis, config->chainlock_schedule, unpublished.statement)));
    current = unpublished;
    for (int32_t height{2'335}; height <= equal_boundary->coverage_height + 5;
         height += static_cast<int32_t>(PQ_CL_PERIOD)) {
        auto next{MakeCatchupChainLock(height, current.statement.height,
                                      current.statement.block_hash, 949'000 + height)};
        next.statement.block_hash = chain[height]->GetBlockHash();
        next.statement.payment_probation_state_hash = probation_root;
        next.statement.previous_btcc_cursor = base.statement.accepted_btcc_cursor;
        next.statement.accepted_btcc_cursor = base.statement.accepted_btcc_cursor;
        next.statement.btcc_receipt_state = receipt_state;
        if (height >= payment_receipt.carrier_height) next.statement.payment_audit_receipt_state = payment_state;
        next.statement.roster_beacons = current.statement.roster_beacons;
        auto& window{next.statement.roster_beacons};
        const auto target_epoch{EpochForHeight(config->chainlock_schedule, height)};
        BOOST_REQUIRE(target_epoch);
        if (*target_epoch > window.active.seeds.back().epoch) {
            BOOST_REQUIRE(window.next.IsReady());
            for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) window.active.seeds[slot] = window.active.seeds[slot + 1];
            window.active.seeds.back() = window.next;
            window.active.recovery_authority_source.normal_beacon = window.next;
            window.next = {};
            window.next.epoch = *target_epoch + 1;
            window.next.readiness_group_floor_plus_one =
                window.active.seeds.back().readiness_group_floor_plus_one;
            next.statement.roster_transition = RosterAuthorizationTransitionKind::ROTATE;
        } else if (window.next.state == RosterBeaconState::EMPTY) {
            window.next.state = RosterBeaconState::PENDING;
            window.next.anchor_cursor = base.statement.accepted_btcc_cursor;
            window.next.anchor_btc_height = 800'000;
            next.statement.roster_transition = RosterAuthorizationTransitionKind::OBSERVE;
        } else if (window.next.state == RosterBeaconState::PENDING) {
            window.next.state = RosterBeaconState::READY;
            window.next.future_btc_hash = NonNullHash(949'001);
            next.statement.roster_transition = RosterAuthorizationTransitionKind::REVEAL;
        }
        bind_transition(next, &current);
        install(next, true);
        current = std::move(next);
    }
    const auto base_view{store->GetVerifiedRosterAuthorizationBaseByLogicalId(base.GetLogicalId(genesis))};
    BOOST_REQUIRE(base_view);
    Access::SetHistoricalSyncAuthorization(*handler, *equal_boundary, *base_view, std::nullopt, bootstrap_identity);
    Access::SetHistoricalRequest(*handler, base.GetLogicalId(genesis));
    BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
    BTCCPresealState btcc_markers;
    btcc_markers.active = BTCCPresealMarker{
        CARRIER_HEIGHT, chain[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{},
        CARRIER_HEIGHT, chain[CARRIER_HEIGHT]->GetBlockHash(), BTCCReceiptState{}, receipt, 1};
    PaymentAuditPresealState payment_markers;
    payment_markers.active = PaymentAuditPresealMarker{
        payment_receipt.carrier_height, chain[payment_receipt.carrier_height]->GetBlockHash(), PaymentAuditReceiptState{}, probation_root,
        payment_receipt.carrier_height, chain[payment_receipt.carrier_height]->GetBlockHash(), payment_receipt, 1};
    Access::SetReplayMarkers(*handler, btcc_markers, payment_markers);
    BOOST_CHECK(!Access::PendingHistory(*handler));
    BOOST_CHECK(Access::PendingHistory(*handler, /*allow_prefix=*/false));
    Access::RefreshHistory(*handler);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
    Access::MaintainHistoricalRetention(*handler);
    BOOST_REQUIRE(durable->LoadHistoricalSyncBootstrap());
    BOOST_CHECK(Access::HasHistoricalSyncAuthorization(*handler));
    BOOST_CHECK(Access::HasHistoricalRequest(*handler));

    const auto before_retirement{durable->GetFinalityState()};
    const PaymentAuditStoreCheckpoint checkpoint{
        payment_receipt.epoch, current.statement.height, current.statement.block_hash,
        payment_state, probation_root, current.statement.height, current.statement.block_hash,
        current.GetLogicalId(genesis), current.GetWitnessId(genesis)};
    auto& audit_store{Access::AuditStore(*handler)};
    BOOST_REQUIRE(audit_store.PruneThroughCheckpointStep(checkpoint).status == PaymentAuditPruneStatus::IN_PROGRESS);
    BOOST_REQUIRE(audit_store.GetPendingPruneCheckpoint());
    BOOST_CHECK(!audit_store.GetPruneCheckpoint());
    Access::MaintainHistoricalRetention(*handler);
    BOOST_REQUIRE(durable->LoadHistoricalSyncBootstrap());
    BOOST_CHECK(Access::PendingHistory(*handler, /*allow_prefix=*/false));
    BOOST_REQUIRE(audit_store.PruneThroughCheckpoint(checkpoint));
    BOOST_CHECK(!Access::PendingHistory(*handler, /*allow_prefix=*/false));
    Access::MaintainHistoricalRetention(*handler);
    BOOST_CHECK(!durable->LoadHistoricalSyncBootstrap());
    BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
    BOOST_CHECK(!Access::HasHistoricalRequest(*handler));
    BOOST_CHECK(!durable->IsHistoricalSyncRecordCurrent(*equal_boundary, bootstrap_identity));
    BOOST_CHECK(durable->GetFinalityState().best == before_retirement.best);
    BOOST_CHECK(durable->GetFinalityState().unsealed_btcc == before_retirement.unsealed_btcc);
    BOOST_CHECK(durable->LoadBTCCPresealState() == btcc_markers);
    BOOST_CHECK(durable->LoadPaymentAuditPresealState() == payment_markers);
    Access::RefreshHistory(*handler);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetPQHistoryAuthState()) == PQHistoryAuthState::READY);
    if (mining_guard) {
        // Both exact prefixes are already authenticated. The remaining
        // durable obligations still require execution replay before mining.
        BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
        BOOST_REQUIRE(chainman.IsPQBlockProductionAllowed());
        BOOST_REQUIRE(!chainman.HasPendingNEVMStartupPair());
        BOOST_REQUIRE(!WITH_LOCK(::cs_main, return handler->IsBTCCPresealActive()));
        BOOST_REQUIRE(!WITH_LOCK(::cs_main, return handler->IsPaymentAuditPresealActive()));
        BOOST_REQUIRE(handler->HasNEVMReplayObligation());

        struct RestoreMiningContext {
            Consensus::Params& consensus;
            const int dip_height;
            const int nevm_height;
            const bool nevm_connection;
            llmq::CChainLocksHandler* original_handler;
            const std::shared_ptr<ReplayMiningNEVMSubscriber> subscriber{
                std::make_shared<ReplayMiningNEVMSubscriber>()};

            ~RestoreMiningContext()
            {
                UnregisterValidationInterface(subscriber.get());
                SyncWithValidationInterfaceQueue();
                LOCK(::cs_main);
                consensus.DIP0003Height = dip_height;
                consensus.nNEVMStartBlock = nevm_height;
                fNEVMConnection = nevm_connection;
                llmq::chainLocksHandler = original_handler;
            }
        } restore{consensus, consensus.DIP0003Height, consensus.nNEVMStartBlock,
                  fNEVMConnection, llmq::chainLocksHandler};
        restore.subscriber->template_error = "mining-replay-template-probe";
        RegisterSharedValidationInterface(restore.subscriber);
        {
            LOCK(::cs_main);
            consensus.DIP0003Height = std::numeric_limits<int>::max();
            consensus.nNEVMStartBlock = 1;
            fNEVMConnection = true;
            llmq::chainLocksHandler = handler.get();
        }
        const auto check_blocked = [&] {
            BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
            BOOST_CHECK_EXCEPTION(
                (node::BlockAssembler{chainman.ActiveChainstate(), nullptr}
                     .CreateNewBlock(CScript{} << OP_TRUE)),
                std::runtime_error, [](const std::runtime_error& error) {
                    return std::string{error.what()} ==
                        "NEVM block production is waiting for execution recovery";
                });
            BOOST_CHECK_EQUAL(restore.subscriber->template_requests, 0U);
        };
        check_blocked();
        BOOST_REQUIRE(Access::ClearReplayMarker(*handler, *btcc_markers.active));
        BOOST_REQUIRE(durable->LoadBTCCPresealState().IsEmpty());
        BOOST_REQUIRE(durable->LoadPaymentAuditPresealState() == payment_markers);
        check_blocked();
        BOOST_REQUIRE(Access::ClearReplayMarker(*handler, *payment_markers.active));
        BOOST_REQUIRE(durable->LoadPaymentAuditPresealState().IsEmpty());
        BOOST_REQUIRE(!handler->HasNEVMReplayObligation());
        // The callback sentinel stops before synthetic block bodies or coins
        // could affect the result, and proves clearing releases the same gate.
        BOOST_CHECK_EXCEPTION(
            (node::BlockAssembler{chainman.ActiveChainstate(), nullptr}
                 .CreateNewBlock(CScript{} << OP_TRUE)),
            std::runtime_error, [](const std::runtime_error& error) {
                return std::string{error.what()} ==
                    "Could not fetch NEVM block mining-replay-template-probe";
            });
        BOOST_CHECK_EQUAL(restore.subscriber->template_requests, 1U);
    }
}

BOOST_FIXTURE_TEST_CASE(nevm_mining_authenticated_markers_wait_for_execution_replay,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/false, /*mixed_markers=*/false,
                          /*btcc_terminal_reorg=*/false, /*btcc_coalesce_markers=*/false,
                          /*mining_guard=*/true);
}

BOOST_FIXTURE_TEST_CASE(historical_prefix_selector_uses_durably_known_receipt_base,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/false);
}

BOOST_FIXTURE_TEST_CASE(historical_prefix_reorg_after_ready_reauthenticates_without_reopening_finality,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/true);
}

BOOST_FIXTURE_TEST_CASE(historical_prefix_reorg_accepts_independent_receipt_beyond_coverage,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/true, /*mixed_markers=*/true);
}

BOOST_FIXTURE_TEST_CASE(btcc_preseal_terminal_reorg_refreshes_ready_before_replay,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/true, /*mixed_markers=*/false,
                          /*btcc_terminal_reorg=*/true);
}

BOOST_FIXTURE_TEST_CASE(btcc_preseal_terminal_reorg_coalesces_common_terminal,
                        PQAuthorizationBasePathSetup)
{
    CheckHistoricalPrefix(/*reauthorize_after_ready=*/true, /*mixed_markers=*/false,
                          /*btcc_terminal_reorg=*/true, /*btcc_coalesce_markers=*/true);
}

BOOST_FIXTURE_TEST_CASE(
    state_advancing_paths_rebase_to_the_current_active_roster_bundle,
    PQAuthorizationBasePathSetup)
{
    using Access = llmq::test::CChainLocksHandlerTestAccess;
    using namespace llmq::pq;

    constexpr int32_t RECEIPT_ANCHOR_HEIGHT{1'000};
    constexpr int32_t ACTIVATION_HEIGHT{2'305};
    constexpr int32_t BASE_HEIGHT{2'305};
    constexpr int32_t CURRENT_HEIGHT{2'310};
    constexpr int32_t CANDIDATE_HEIGHT{2'315};
    constexpr int32_t RECOVERY_HEIGHT{3'465};
    constexpr int32_t TIP_HEIGHT{3'480};
    const uint256 probation_root{NonNullHash(920'000)};

    auto& chainman{*Assert(m_node.chainman)};
    std::vector<CBlockIndex*> chain(
        static_cast<std::size_t>(TIP_HEIGHT) + 1);
    {
        LOCK(::cs_main);
        chain[0] = chainman.ActiveTip();
        BOOST_REQUIRE(chain[0]);
        const int64_t first_time{
            GetTime<std::chrono::seconds>().count() - TIP_HEIGHT};
        for (int32_t height{1}; height <= TIP_HEIGHT; ++height) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = chain[height - 1]->GetBlockHash();
            header.hashMerkleRoot = NonNullHash(921'000 + height);
            header.nTime = static_cast<uint32_t>(first_time + height);
            header.nBits = chain[height - 1]->nBits;
            header.nNonce = static_cast<uint32_t>(height);
            chain[height] = chainman.m_blockman.AddToBlockIndex(
                header, chainman.m_best_header);
            BOOST_REQUIRE(chain[height]);
            chain[height]->nStatus = static_cast<BlockStatus>(
                chain[height]->nStatus | BLOCK_VALID_SCRIPTS |
                BLOCK_HAVE_DATA | BLOCK_PQ_BTCC_INDEX_VALIDATED |
                BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                BLOCK_GOVERNANCE_VALIDATED);
            chain[height]->nTx = 1;
            chain[height]->nChainTx =
                static_cast<unsigned int>(height + 1);
            chain[height]->pqPaymentProbationStateHash = probation_root;
        }
        chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
    }

    auto& consensus{
        const_cast<Consensus::Params&>(chainman.GetConsensus())};
    const Consensus::Params original_consensus{consensus};
    consensus.nPQActivationHeight = ACTIVATION_HEIGHT;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = ACTIVATION_HEIGHT;
    consensus.nPQBTCCNEVMInjectionLag = PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = RECEIPT_ANCHOR_HEIGHT;
    consensus.hashPQBTCCReceiptAnchorBlock =
        chain[RECEIPT_ANCHOR_HEIGHT]->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nDefaultAssumeValidHeight = -1;

    std::unique_ptr<llmq::CChainLocksHandler> handler;
    {
        LOCK(::cs_main);
        handler = std::make_unique<llmq::CChainLocksHandler>(
            *Assert(m_node.connman), *Assert(m_node.peerman), chainman);
    }
    consensus = original_consensus;
    BOOST_REQUIRE(handler);
    const auto* config{Access::Config(*handler)};
    BOOST_REQUIRE(config);

    const auto active_epochs{
        ActiveEpochsAtHeight(config->chainlock_schedule, BASE_HEIGHT)};
    BOOST_REQUIRE(active_epochs);
    RosterBeaconWindow base_window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        base_window.active.seeds[slot] =
            SubjectBeacon((*active_epochs)[slot].epoch);
    }
    base_window.next.epoch = active_epochs->back().epoch + 1;
    base_window.active.recovery_authority_source.normal_beacon =
        base_window.active.seeds.back();
    BOOST_REQUIRE(base_window.IsStructurallyValid());

    const uint256 genesis{chainman.GetConsensus().hashGenesisBlock};
    const auto set_exact_continuation = [&](FinalChainLock& child,
                                            const FinalChainLock& prior) {
        child.statement.roster_transition =
            RosterAuthorizationTransitionKind::KEEP;
        child.statement.roster_beacons = prior.statement.roster_beacons;
        child.statement.roster_authorization_base = {
            prior.statement.height, prior.statement.block_hash,
            prior.GetLogicalId(genesis)};
        RosterAuthorizationTransition transition;
        transition.kind = child.statement.roster_transition;
        transition.target_height = child.statement.height;
        transition.target_block_hash = child.statement.block_hash;
        transition.predecessor_height =
            child.statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            child.statement.previous_chainlock_hash;
        transition.authorization_base =
            child.statement.roster_authorization_base;
        transition.previous = RosterAuthorizationPriorState{
            prior.statement.roster_authorization_state_hash,
            prior.statement.roster_beacons};
        transition.new_window = child.statement.roster_beacons;
        const auto state_hash{
            GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(state_hash);
        child.statement.roster_authorization_state_hash = *state_hash;
        BOOST_REQUIRE(child.IsStructurallyValid());
    };
    const auto context_for = [&](const FinalChainLock& chainlock) {
        return ChainLockStoreTestContextFactory::Create(
            genesis, config->chainlock_schedule, chainlock.statement);
    };
    const auto install = [&](ChainLockFinalityStore& store,
                             const FinalChainLock& chainlock) {
        ChainLockFinalityError prepare_error{ChainLockFinalityError::NONE};
        const auto prepared{
            store.PrepareCandidate(chainlock, &prepare_error)};
        BOOST_REQUIRE_MESSAGE(
            prepared,
            "failed to prepare fixture CLSIG at height " <<
                chainlock.statement.height << " with error " <<
                static_cast<int>(prepare_error));
        const auto context{context_for(chainlock)};
        BOOST_REQUIRE(context);
        BOOST_REQUIRE(store.AcceptVerified(
            *prepared, chainlock, /*signatures_valid=*/true,
            /*error=*/nullptr, context));
    };

    auto base{MakeCatchupChainLock(
        BASE_HEIGHT, ACTIVATION_HEIGHT - 1,
        chain[ACTIVATION_HEIGHT - 1]->GetBlockHash(), 923'000)};
    base.statement.block_hash = chain[BASE_HEIGHT]->GetBlockHash();
    base.statement.roster_beacons = base_window;
    base.statement.payment_probation_state_hash = probation_root;
    const BTCCursor base_cursor{
        BASE_HEIGHT, base.statement.block_hash, NonNullHash(923'500)};
    chain[BASE_HEIGHT]->btcpPrevCommitment = base_cursor.btc_hash;
    base.statement.previous_btcc_cursor = {};
    base.statement.accepted_btcc_cursor = base_cursor;
    base.statement.btcc_advance = BTCCAdvance::ADVANCE;
    base.statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    base.statement.roster_authorization_base = {};
    BOOST_REQUIRE(base.IsStructurallyValid());

    BTCCReceipt base_receipt;
    base_receipt.chainlock_target_height = BASE_HEIGHT;
    base_receipt.chainlock_target_hash = base.statement.block_hash;
    base_receipt.chainlock_logical_id = base.GetLogicalId(genesis);
    base_receipt.accepted_cursor = base_cursor;
    BOOST_REQUIRE(base_receipt.IsStructurallyValid());
    const auto receipted_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        config->activation_predecessor_height, CANDIDATE_HEIGHT,
        chain[CANDIDATE_HEIGHT]->GetBlockHash(),
        BTCCReceiptState{}, base_receipt)};
    BOOST_REQUIRE(receipted_state);
    for (int32_t height{CANDIDATE_HEIGHT}; height <= TIP_HEIGHT; ++height) {
        chain[height]->pqBTCCReceiptCursorHeight =
            receipted_state->cursor.sys_height;
        chain[height]->pqBTCCReceiptCursorSysHash =
            receipted_state->cursor.sys_hash;
        chain[height]->pqBTCCReceiptCursorBTCHash =
            receipted_state->cursor.btc_hash;
        chain[height]->pqBTCCReceiptStateHash =
            receipted_state->cumulative_hash;
        chain[height]->pqBTCCReceiptLatestTargetHeight =
            receipted_state->latest_chainlock_target_height;
        chain[height]->pqBTCCReceiptLatestCarrierHeight =
            receipted_state->latest_receipt_carrier_height;
    }
    chain[CANDIDATE_HEIGHT]->pqBTCCReceiptLogicalId =
        base_receipt.chainlock_logical_id;

    auto current{MakeCatchupChainLock(
        CURRENT_HEIGHT, BASE_HEIGHT, base.statement.block_hash,
        924'000)};
    current.statement.block_hash = chain[CURRENT_HEIGHT]->GetBlockHash();
    current.statement.payment_probation_state_hash = probation_root;
    current.statement.previous_btcc_cursor = base_cursor;
    current.statement.accepted_btcc_cursor = base_cursor;
    current.statement.btcc_advance = BTCCAdvance::KEEP;
    set_exact_continuation(current, base);

    auto candidate{MakeCatchupChainLock(
        CANDIDATE_HEIGHT, CURRENT_HEIGHT,
        current.statement.block_hash, 925'000)};
    candidate.statement.block_hash =
        chain[CANDIDATE_HEIGHT]->GetBlockHash();
    candidate.statement.payment_probation_state_hash = probation_root;
    candidate.statement.previous_btcc_cursor = base_cursor;
    candidate.statement.accepted_btcc_cursor = base_cursor;
    candidate.statement.btcc_advance = BTCCAdvance::KEEP;
    candidate.statement.btcc_receipt_state = *receipted_state;
    set_exact_continuation(candidate, base);

    FullReceiptCatchupContext store_context;
    store_context.full_receipt_history = true;
    Access::ResetFinalityStoreWithContext(*handler, store_context);
    auto* store{Access::Store(*handler)};
    BOOST_REQUIRE(store);
    install(*store, base);

    constexpr int32_t LATE_INITIAL_CARRIER{
        BASE_HEIGHT + 2 * static_cast<int32_t>(PQ_BTCC_CANDIDATE_PERIOD)};
    CBlockIndex& late_parent{*chain[LATE_INITIAL_CARRIER - 1]};
    const auto saved_cursor_height{late_parent.pqBTCCReceiptCursorHeight};
    const auto saved_cursor_sys_hash{late_parent.pqBTCCReceiptCursorSysHash};
    const auto saved_cursor_btc_hash{late_parent.pqBTCCReceiptCursorBTCHash};
    const auto saved_state_hash{late_parent.pqBTCCReceiptStateHash};
    const auto saved_target_height{
        late_parent.pqBTCCReceiptLatestTargetHeight};
    const auto saved_carrier_height{
        late_parent.pqBTCCReceiptLatestCarrierHeight};
    late_parent.pqBTCCReceiptCursorHeight = -1;
    late_parent.pqBTCCReceiptCursorSysHash.SetNull();
    late_parent.pqBTCCReceiptCursorBTCHash.SetNull();
    late_parent.pqBTCCReceiptStateHash.SetNull();
    late_parent.pqBTCCReceiptLatestTargetHeight = -1;
    late_parent.pqBTCCReceiptLatestCarrierHeight = -1;

    const auto late_initial_receipt{Access::BTCCReceiptForCarrier(
        *handler, LATE_INITIAL_CARRIER, late_parent)};
    BOOST_REQUIRE(late_initial_receipt == base_receipt);
    BOOST_CHECK(Access::IsVerifiedBTCCReceipt(
        *handler, late_initial_receipt, *chain[LATE_INITIAL_CARRIER]));

    late_parent.pqBTCCReceiptCursorHeight = saved_cursor_height;
    late_parent.pqBTCCReceiptCursorSysHash = saved_cursor_sys_hash;
    late_parent.pqBTCCReceiptCursorBTCHash = saved_cursor_btc_hash;
    late_parent.pqBTCCReceiptStateHash = saved_state_hash;
    late_parent.pqBTCCReceiptLatestTargetHeight = saved_target_height;
    late_parent.pqBTCCReceiptLatestCarrierHeight = saved_carrier_height;

    install(*store, current);
    BOOST_REQUIRE(store->GetVerifiedRosterAuthorizationBase(
        RosterAuthorizationBaseIdentity{
            base.statement.height, base.statement.block_hash,
            base.GetLogicalId(genesis)}));
    const auto at_initial_receipt_carrier{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[CANDIDATE_HEIGHT])};
    BOOST_REQUIRE(at_initial_receipt_carrier);
    BOOST_CHECK(at_initial_receipt_carrier->mode ==
                ObjectiveRosterAuthorizationMode::PAUSE);
    BOOST_CHECK(!at_initial_receipt_carrier->base);
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, candidate));
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, candidate));

    // The active tip is far past this exact next edge. Before the locally
    // verified authorization record exists it is no longer generic catch-up;
    // afterwards only the retained capability opens the dedicated path.
    BOOST_CHECK_EQUAL(Access::HistoricalAdmissionFor(*handler, candidate),
                      0U);
    const auto candidate_context{context_for(candidate)};
    BOOST_REQUIRE(candidate_context);
    BOOST_REQUIRE(store->AcceptVerifiedRosterAuthorizationBase(
        candidate, /*signatures_valid=*/true, candidate_context));
    constexpr uint8_t RETAINED_SUCCESSOR_ADMISSION{2};
    BOOST_CHECK_EQUAL(Access::HistoricalAdmissionFor(*handler, candidate),
                      RETAINED_SUCCESSOR_ADMISSION);
    const auto retained_catchup{
        Access::PrepareRuntimeCandidateWithoutStoreAdmission(
            *handler, candidate, ChainLockCandidateAdmission::CATCHUP)};
    BOOST_REQUIRE(retained_catchup);
    BOOST_CHECK(retained_catchup->context.block_known);
    BOOST_CHECK(retained_catchup->context.scripts_validated);
    BOOST_CHECK(retained_catchup->context.special_transactions_validated);
    BOOST_CHECK(retained_catchup->context.btcc_transition_validated);

    // Diagnostic: the receipt-selected authorization base is fully verified
    // locally, but is one state edge ahead of the durable winner. The same
    // otherwise-valid catch-up is rejected until that base itself becomes the
    // durable winner.
    constexpr int32_t KEEP_CARRIER{CANDIDATE_HEIGHT +
        static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    BTCCReceipt candidate_receipt;
    candidate_receipt.chainlock_target_height = CANDIDATE_HEIGHT;
    candidate_receipt.chainlock_target_hash =
        candidate.statement.block_hash;
    candidate_receipt.chainlock_logical_id =
        candidate.GetLogicalId(genesis);
    candidate_receipt.accepted_cursor = base_cursor;
    BOOST_REQUIRE(candidate_receipt.IsStructurallyValid());
    const auto candidate_receipted_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        config->activation_predecessor_height, KEEP_CARRIER,
        chain[KEEP_CARRIER]->GetBlockHash(), *receipted_state,
        candidate_receipt)};
    BOOST_REQUIRE(candidate_receipted_state);
    for (int32_t height{KEEP_CARRIER}; height <= TIP_HEIGHT; ++height) {
        chain[height]->pqBTCCReceiptCursorHeight =
            candidate_receipted_state->cursor.sys_height;
        chain[height]->pqBTCCReceiptCursorSysHash =
            candidate_receipted_state->cursor.sys_hash;
        chain[height]->pqBTCCReceiptCursorBTCHash =
            candidate_receipted_state->cursor.btc_hash;
        chain[height]->pqBTCCReceiptStateHash =
            candidate_receipted_state->cumulative_hash;
        chain[height]->pqBTCCReceiptLatestTargetHeight =
            candidate_receipted_state->latest_chainlock_target_height;
        chain[height]->pqBTCCReceiptLatestCarrierHeight =
            candidate_receipted_state->latest_receipt_carrier_height;
    }
    chain[KEEP_CARRIER]->pqBTCCReceiptLogicalId =
        candidate_receipt.chainlock_logical_id;

    const int32_t forward_height{KEEP_CARRIER +
        static_cast<int32_t>(config->chainlock_schedule.sign_lag)};
    auto forward{MakeCatchupChainLock(
        forward_height,
        forward_height - static_cast<int32_t>(PQ_CL_PERIOD),
        chain[forward_height - static_cast<int32_t>(PQ_CL_PERIOD)]
            ->GetBlockHash(),
        925'050)};
    forward.statement.block_hash = chain[forward_height]->GetBlockHash();
    forward.statement.payment_probation_state_hash = probation_root;
    forward.statement.previous_btcc_cursor = base_cursor;
    forward.statement.accepted_btcc_cursor = base_cursor;
    forward.statement.btcc_advance = BTCCAdvance::KEEP;
    forward.statement.btcc_receipt_state = *candidate_receipted_state;
    set_exact_continuation(forward, candidate);
    BOOST_REQUIRE(forward.IsStructurallyValid());

    const auto forward_objective{Access::ObjectiveRosterAuthorization(
        *handler, *chain[forward_height])};
    BOOST_REQUIRE(forward_objective);
    BOOST_REQUIRE(forward_objective->base);
    BOOST_CHECK(forward_objective->mode ==
                ObjectiveRosterAuthorizationMode::NORMAL);
    const RosterAuthorizationBaseIdentity candidate_base{
        candidate.statement.height, candidate.statement.block_hash,
        candidate.GetLogicalId(genesis)};
    BOOST_CHECK(*forward_objective->base == candidate_base);
    const auto old_durable{store->GetBestRecord()};
    BOOST_REQUIRE(old_durable);
    BOOST_CHECK_EQUAL(old_durable->metadata.statement.height, CURRENT_HEIGHT);
    BOOST_CHECK(candidate.statement.height >
                old_durable->metadata.statement.height);
    BOOST_CHECK(candidate.statement.height < forward.statement.height);
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, forward));

    // A scheduled receipt may carry an exact KEEP certificate. Its statement
    // is bound to the carrier-parent receipt state just like ADVANCE.
    install(*store, candidate);
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, forward));
    const auto keep_receipt{Access::BTCCReceiptForCarrier(
        *handler, KEEP_CARRIER, *chain[KEEP_CARRIER - 1])};
    BOOST_REQUIRE(!keep_receipt.IsNull());
    BOOST_CHECK_EQUAL(keep_receipt.chainlock_target_height,
                      CANDIDATE_HEIGHT);
    BOOST_CHECK(keep_receipt.accepted_cursor == base_cursor);
    BOOST_CHECK(Access::IsVerifiedBTCCReceipt(
        *handler, keep_receipt, *chain[KEEP_CARRIER]));

    for (int32_t height{KEEP_CARRIER}; height <= TIP_HEIGHT; ++height) {
        chain[height]->pqBTCCReceiptCursorHeight =
            receipted_state->cursor.sys_height;
        chain[height]->pqBTCCReceiptCursorSysHash =
            receipted_state->cursor.sys_hash;
        chain[height]->pqBTCCReceiptCursorBTCHash =
            receipted_state->cursor.btc_hash;
        chain[height]->pqBTCCReceiptStateHash =
            receipted_state->cumulative_hash;
        chain[height]->pqBTCCReceiptLatestTargetHeight =
            receipted_state->latest_chainlock_target_height;
        chain[height]->pqBTCCReceiptLatestCarrierHeight =
            receipted_state->latest_receipt_carrier_height;
    }
    chain[KEEP_CARRIER]->pqBTCCReceiptLogicalId.SetNull();

    Access::ResetFinalityStoreWithContext(*handler, store_context);
    store = Access::Store(*handler);
    BOOST_REQUIRE(store);
    install(*store, base);
    install(*store, current);

    // A receipt carried by only one target sibling must not change roster
    // authority until that carrier reaches the next round's shared boundary.
    constexpr int32_t RECENT_HEIGHT{
        RECOVERY_HEIGHT - static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    auto recent{MakeCatchupChainLock(
        RECENT_HEIGHT, CURRENT_HEIGHT,
        current.statement.block_hash, 925'250)};
    recent.statement.block_hash = chain[RECENT_HEIGHT]->GetBlockHash();
    recent.statement.payment_probation_state_hash = probation_root;
    recent.statement.previous_btcc_cursor = base_cursor;
    recent.statement.accepted_btcc_cursor = base_cursor;
    recent.statement.btcc_advance = BTCCAdvance::KEEP;
    recent.statement.btcc_receipt_state = *receipted_state;
    set_exact_continuation(recent, base);
    const auto recent_context{context_for(recent)};
    BOOST_REQUIRE(recent_context);
    BOOST_REQUIRE(store->AcceptVerifiedRosterAuthorizationBase(
        recent, /*signatures_valid=*/true, recent_context));

    uint256 receipt_sibling_hash{NonNullHash(925'251)};
    CBlockIndex receipt_sibling;
    receipt_sibling.nHeight = RECOVERY_HEIGHT;
    receipt_sibling.phashBlock = &receipt_sibling_hash;
    receipt_sibling.pprev = chain[RECOVERY_HEIGHT - 1];
    receipt_sibling.BuildSkip();
    {
        LOCK(::cs_main);
        receipt_sibling.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
            BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED);
    }

    BTCCReceipt recent_receipt;
    recent_receipt.chainlock_target_height = RECENT_HEIGHT;
    recent_receipt.chainlock_target_hash = recent.statement.block_hash;
    recent_receipt.chainlock_logical_id = recent.GetLogicalId(genesis);
    recent_receipt.accepted_cursor = base_cursor;
    const auto recent_receipted_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        config->activation_predecessor_height, RECOVERY_HEIGHT,
        receipt_sibling.GetBlockHash(), *receipted_state, recent_receipt)};
    BOOST_REQUIRE(recent_receipted_state);
    receipt_sibling.pqBTCCReceiptCursorHeight =
        recent_receipted_state->cursor.sys_height;
    receipt_sibling.pqBTCCReceiptCursorSysHash =
        recent_receipted_state->cursor.sys_hash;
    receipt_sibling.pqBTCCReceiptCursorBTCHash =
        recent_receipted_state->cursor.btc_hash;
    receipt_sibling.pqBTCCReceiptStateHash =
        recent_receipted_state->cumulative_hash;
    receipt_sibling.pqBTCCReceiptLatestTargetHeight =
        recent_receipted_state->latest_chainlock_target_height;
    receipt_sibling.pqBTCCReceiptLatestCarrierHeight =
        recent_receipted_state->latest_receipt_carrier_height;
    receipt_sibling.pqBTCCReceiptLogicalId =
        recent_receipt.chainlock_logical_id;

    BOOST_CHECK(chain[RECOVERY_HEIGHT]
                    ->pqBTCCReceiptLogicalId.IsNull());
    BOOST_CHECK(!receipt_sibling.pqBTCCReceiptLogicalId.IsNull());
    BOOST_CHECK(chain[RECOVERY_HEIGHT]->pqBTCCReceiptStateHash !=
                receipt_sibling.pqBTCCReceiptStateHash);
    const auto plain_target_objective{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[RECOVERY_HEIGHT])};
    const auto receipt_target_objective{
        Access::ObjectiveRosterAuthorization(*handler, receipt_sibling)};
    BOOST_REQUIRE(plain_target_objective);
    BOOST_REQUIRE(receipt_target_objective);
    BOOST_REQUIRE(plain_target_objective->base);
    BOOST_REQUIRE(receipt_target_objective->base);
    const RosterAuthorizationBaseIdentity expected_base{
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    BOOST_CHECK(plain_target_objective->mode ==
                ObjectiveRosterAuthorizationMode::RECOVER);
    BOOST_CHECK(receipt_target_objective->mode ==
                plain_target_objective->mode);
    BOOST_CHECK(receipt_target_objective->base ==
                plain_target_objective->base);
    BOOST_CHECK(*receipt_target_objective->base == expected_base);
    BOOST_CHECK(receipt_target_objective->recovery_source ==
                plain_target_objective->recovery_source);

    const auto recovery_epoch{EpochForHeight(
        config->chainlock_schedule, RECOVERY_HEIGHT)};
    BOOST_REQUIRE(recovery_epoch);
    BOOST_REQUIRE(plain_target_objective->recovery_source);
    BOOST_REQUIRE(receipt_target_objective->recovery_source);
    const auto plain_target_window{MakeRecoveryRosterBeaconWindow(
        *plain_target_objective->recovery_source, *recovery_epoch)};
    const auto receipt_target_window{MakeRecoveryRosterBeaconWindow(
        *receipt_target_objective->recovery_source, *recovery_epoch)};
    BOOST_REQUIRE(plain_target_window);
    BOOST_REQUIRE(receipt_target_window);
    BOOST_CHECK(plain_target_window->active ==
                receipt_target_window->active);

    const auto canonical_recovery{CanonicalRosterRecoveryTargetHeight(
        config->chainlock_schedule, config->btcc_schedule,
        *recovery_epoch)};
    BOOST_REQUIRE(canonical_recovery);
    BOOST_REQUIRE_EQUAL(*canonical_recovery, RECOVERY_HEIGHT);
    const auto recovery_window{MakeRecoveryRosterBeaconWindow(
        base_window.active.recovery_authority_source,
        *recovery_epoch)};
    BOOST_REQUIRE(recovery_window);
    auto recovery{MakeCatchupChainLock(
        RECOVERY_HEIGHT, CURRENT_HEIGHT,
        current.statement.block_hash, 925'500)};
    recovery.statement.block_hash =
        chain[RECOVERY_HEIGHT]->GetBlockHash();
    recovery.statement.payment_probation_state_hash = probation_root;
    recovery.statement.previous_btcc_cursor = base_cursor;
    recovery.statement.accepted_btcc_cursor = base_cursor;
    recovery.statement.btcc_advance = BTCCAdvance::KEEP;
    recovery.statement.btcc_receipt_state = *receipted_state;
    recovery.statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    recovery.statement.roster_beacons = *recovery_window;
    recovery.statement.roster_authorization_base = {
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    {
        RosterAuthorizationTransition transition;
        transition.kind = RosterAuthorizationTransitionKind::RECOVER;
        transition.target_height = recovery.statement.height;
        transition.target_block_hash = recovery.statement.block_hash;
        transition.predecessor_height =
            recovery.statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            recovery.statement.previous_chainlock_hash;
        transition.authorization_base =
            recovery.statement.roster_authorization_base;
        transition.previous = RosterAuthorizationPriorState{
            base.statement.roster_authorization_state_hash,
            base.statement.roster_beacons};
        transition.new_window = recovery.statement.roster_beacons;
        const auto state_hash{
            GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(state_hash);
        recovery.statement.roster_authorization_state_hash = *state_hash;
    }
    BOOST_REQUIRE(recovery.IsStructurallyValid());
    const auto recovery_objective{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[RECOVERY_HEIGHT])};
    BOOST_REQUIRE(recovery_objective);
    BOOST_CHECK(recovery_objective->mode ==
                ObjectiveRosterAuthorizationMode::RECOVER);
    BOOST_REQUIRE(recovery_objective->base);
    BOOST_CHECK(*recovery_objective->base == expected_base);
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, recovery));
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, recovery));

    auto wrong_recovery_source{recovery};
    auto& wrong_bundle{
        wrong_recovery_source.statement.roster_beacons.active};
    wrong_bundle.recovery_authority_source.normal_beacon.future_btc_hash =
        NonNullHash(925'501);
    const auto wrong_window{MakeRecoveryRosterBeaconWindow(
        wrong_bundle.recovery_authority_source,
        *recovery_epoch)};
    BOOST_REQUIRE(wrong_window);
    wrong_recovery_source.statement.roster_beacons = *wrong_window;
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP,
        wrong_recovery_source));

    auto missing_base{candidate};
    missing_base.statement.roster_authorization_base.logical_id =
        NonNullHash(926'000);
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, missing_base));

    const auto hidden_recovery_next_round{
        Access::ObjectiveRosterAuthorization(
            *handler,
            *chain[RECOVERY_HEIGHT +
                   static_cast<int32_t>(PQ_CL_PERIOD)])};
    BOOST_REQUIRE(hidden_recovery_next_round);
    BOOST_CHECK(hidden_recovery_next_round->mode ==
                ObjectiveRosterAuthorizationMode::PAUSE);
    BOOST_CHECK(!hidden_recovery_next_round->base);

    {
        // Keep B's verified capability, but remove every ordinary winner and
        // archive view so only the imported historical edge can authorize C.
        const auto historical_base{store->GetVerifiedRosterAuthorizationBase(expected_base)};
        BOOST_REQUIRE(historical_base);
        auto original_store{Access::ExchangeFinalityStore(*handler, nullptr)};
        Access::ResetFinalityStoreWithContext(*handler, store_context);
        BOOST_REQUIRE(Access::HasNoFinalityWinner(*handler));
        BOOST_CHECK(!Access::Store(*handler)->GetVerifiedRosterAuthorizationBase(expected_base));

        const auto set_recovery_base = [&](FinalChainLock& child, const FinalChainLock& prior) {
            child.statement.roster_authorization_base = {
                prior.statement.height, prior.statement.block_hash, prior.GetLogicalId(genesis)};
            RosterAuthorizationTransition transition;
            transition.kind = RosterAuthorizationTransitionKind::RECOVER;
            transition.target_height = child.statement.height;
            transition.target_block_hash = child.statement.block_hash;
            transition.predecessor_height = child.statement.previous_chainlock_height;
            transition.predecessor_block_hash = child.statement.previous_chainlock_hash;
            transition.authorization_base = child.statement.roster_authorization_base;
            transition.previous = RosterAuthorizationPriorState{
                prior.statement.roster_authorization_state_hash, prior.statement.roster_beacons};
            transition.new_window = child.statement.roster_beacons;
            const auto state_hash{GetRosterAuthorizationStateHash(genesis, transition)};
            BOOST_REQUIRE(state_hash);
            child.statement.roster_authorization_state_hash = *state_hash;
            BOOST_REQUIRE(child.IsStructurallyValid());
        };
        auto fresh_recovery{recovery};
        fresh_recovery.statement.previous_chainlock_height =
            RECOVERY_HEIGHT - static_cast<int32_t>(PQ_CL_PERIOD);
        fresh_recovery.statement.previous_chainlock_hash =
            chain[fresh_recovery.statement.previous_chainlock_height]->GetBlockHash();
        set_recovery_base(fresh_recovery, base);

        constexpr int32_t COVERAGE_HEIGHT{
            RECOVERY_HEIGHT - 2 * static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
        HistoricalSyncBoundary boundary;
        boundary.carrier_height = CANDIDATE_HEIGHT;
        boundary.carrier_hash = chain[CANDIDATE_HEIGHT]->GetBlockHash();
        boundary.receipt = base_receipt;
        boundary.coverage_height = COVERAGE_HEIGHT;
        boundary.coverage_hash = chain[COVERAGE_HEIGHT]->GetBlockHash();
        boundary.receipt_state = *receipted_state;
        boundary.probation_state_hash = probation_root;
        BOOST_REQUIRE(boundary.IsStructurallyValid());
        BOOST_REQUIRE(boundary.durable_prior.IsNull());
        constexpr uint8_t RECOVERY_ADMISSION{3};
        const auto check_rejected = [&](const FinalChainLock& child) {
            BOOST_CHECK_NE(Access::HistoricalAdmissionFor(*handler, child), RECOVERY_ADMISSION);
            BOOST_CHECK(Access::HasNoFinalityWinner(*handler));
        };
        const auto check_recovery = [&] {
            BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
            BOOST_CHECK_EQUAL(Access::HistoricalAdmissionFor(*handler, fresh_recovery), RECOVERY_ADMISSION);
            BOOST_CHECK(Access::HasNoFinalityWinner(*handler));
        };

        check_rejected(fresh_recovery);
        Access::SetHistoricalSyncAuthorization(*handler, boundary, *historical_base);
        const auto imported_objective{Access::ObjectiveRosterAuthorization(
            *handler, *chain[RECOVERY_HEIGHT])};
        BOOST_REQUIRE(imported_objective);
        BOOST_CHECK(imported_objective->mode == ObjectiveRosterAuthorizationMode::RECOVER);
        BOOST_REQUIRE(imported_objective->base);
        BOOST_CHECK(*imported_objective->base == expected_base);
        check_recovery();

        Access::SetHistoricalSyncAuthorization(*handler, std::nullopt, *historical_base);
        BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(fresh_recovery);
        const uint64_t wrong_revision{WITH_LOCK(::cs_main,
            return chainman.GetPQProvenanceRevocationRevision() + 1)};
        Access::SetHistoricalSyncAuthorization(*handler, boundary, *historical_base, wrong_revision);
        BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(fresh_recovery);
        Access::SetHistoricalSyncAuthorization(*handler, boundary, *historical_base);

        const uint32_t coverage_status{WITH_LOCK(::cs_main, return chain[COVERAGE_HEIGHT]->nStatus)};
        {
            LOCK(::cs_main);
            chain[COVERAGE_HEIGHT]->nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
        }
        BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(fresh_recovery);
        {
            LOCK(::cs_main);
            chain[COVERAGE_HEIGHT]->nStatus = coverage_status;
        }
        check_recovery();

        auto wrong_base{fresh_recovery};
        wrong_base.statement.roster_authorization_base.logical_id = NonNullHash(925'600);
        BOOST_REQUIRE(wrong_base.IsStructurallyValid());
        check_rejected(wrong_base);
        for (const int32_t height : {RECOVERY_HEIGHT, RECOVERY_HEIGHT + static_cast<int32_t>(PQ_CL_PERIOD)}) {
            auto overlapping{boundary};
            overlapping.coverage_height = height;
            overlapping.coverage_hash = chain[height]->GetBlockHash();
            BOOST_REQUIRE(overlapping.IsStructurallyValid());
            Access::SetHistoricalSyncAuthorization(*handler, overlapping, *historical_base);
            BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
            check_rejected(fresh_recovery);
        }
        Access::SetHistoricalSyncAuthorization(*handler, boundary, *historical_base);

        const auto set_indexed_receipt = [](CBlockIndex& index, const BTCCReceiptState& state) {
            index.pqBTCCReceiptCursorHeight = state.cursor.sys_height;
            index.pqBTCCReceiptCursorSysHash = state.cursor.sys_hash;
            index.pqBTCCReceiptCursorBTCHash = state.cursor.btc_hash;
            index.pqBTCCReceiptStateHash = state.cumulative_hash;
            index.pqBTCCReceiptLatestTargetHeight = state.latest_chainlock_target_height;
            index.pqBTCCReceiptLatestCarrierHeight = state.latest_receipt_carrier_height;
        };
        CBlockIndex* sibling{nullptr};
        {
            LOCK(::cs_main);
            auto header{chain[RECOVERY_HEIGHT]->GetBlockHeader()};
            header.nNonce += 1'000'000;
            sibling = chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header);
            BOOST_REQUIRE(sibling);
            sibling->nStatus = chain[RECOVERY_HEIGHT]->nStatus;
            sibling->pqPaymentProbationStateHash = probation_root;
            set_indexed_receipt(*sibling, *receipted_state);
        }
        auto off_branch{fresh_recovery};
        off_branch.statement.block_hash = sibling->GetBlockHash();
        set_recovery_base(off_branch, base);
        BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(off_branch);

        std::vector<CBlockIndex*> replacement{chain[COVERAGE_HEIGHT - 1]};
        {
            LOCK(::cs_main);
            for (int32_t height{COVERAGE_HEIGHT}; height <= TIP_HEIGHT; ++height) {
                auto header{chain[height]->GetBlockHeader()};
                header.hashPrevBlock = replacement.back()->GetBlockHash();
                header.nNonce += 2'000'000;
                auto* index{chainman.m_blockman.AddToBlockIndex(header, chainman.m_best_header)};
                BOOST_REQUIRE(index);
                index->nStatus = chain[height]->nStatus;
                index->nTx = chain[height]->nTx;
                index->nChainTx = chain[height]->nChainTx;
                index->pqPaymentProbationStateHash = probation_root;
                set_indexed_receipt(*index, *receipted_state);
                replacement.push_back(index);
            }
            chainman.ActiveChainstate().m_chain.SetTip(*replacement.back());
        }
        auto reorged{fresh_recovery};
        reorged.statement.block_hash =
            replacement[RECOVERY_HEIGHT - COVERAGE_HEIGHT + 1]->GetBlockHash();
        reorged.statement.previous_chainlock_hash =
            replacement[reorged.statement.previous_chainlock_height - COVERAGE_HEIGHT + 1]->GetBlockHash();
        set_recovery_base(reorged, base);
        BOOST_CHECK(!Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(reorged);
        {
            LOCK(::cs_main);
            chainman.ActiveChainstate().m_chain.SetTip(*chain[TIP_HEIGHT]);
        }
        check_recovery();

        const auto other_context{context_for(base)};
        BOOST_REQUIRE(other_context != historical_base->verification_context);
        BOOST_REQUIRE(Access::Store(*handler)->AcceptVerifiedRosterAuthorizationBase(
            base, /*signatures_valid=*/true, other_context));
        BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
        check_rejected(fresh_recovery);
        Access::ResetFinalityStoreWithContext(*handler, store_context);
        check_recovery();

        // A recent receipt selects NORMAL even at the canonical reset target.
        // Matching a verified B and its branch cannot override that decision.
        constexpr int32_t NORMAL_BASE_HEIGHT{COVERAGE_HEIGHT};
        constexpr int32_t NORMAL_CARRIER{
            NORMAL_BASE_HEIGHT + static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
        auto normal_base{MakeCatchupChainLock(
            NORMAL_BASE_HEIGHT, NORMAL_BASE_HEIGHT - static_cast<int32_t>(PQ_CL_PERIOD),
            chain[NORMAL_BASE_HEIGHT - static_cast<int32_t>(PQ_CL_PERIOD)]->GetBlockHash(), 925'601)};
        normal_base.statement.block_hash = chain[NORMAL_BASE_HEIGHT]->GetBlockHash();
        normal_base.statement.previous_btcc_cursor = base_cursor;
        normal_base.statement.accepted_btcc_cursor = base_cursor;
        normal_base.statement.btcc_receipt_state = *receipted_state;
        normal_base.statement.payment_probation_state_hash = probation_root;
        set_exact_continuation(normal_base, base);
        BOOST_REQUIRE(Access::Store(*handler)->AcceptVerifiedRosterAuthorizationBase(
            normal_base, /*signatures_valid=*/true, context_for(normal_base)));
        const auto normal_view{Access::Store(*handler)->GetVerifiedRosterAuthorizationBaseByLogicalId(
            normal_base.GetLogicalId(genesis))};
        BOOST_REQUIRE(normal_view);
        Access::ResetFinalityStoreWithContext(*handler, store_context);
        BTCCReceipt normal_receipt;
        normal_receipt.chainlock_target_height = NORMAL_BASE_HEIGHT;
        normal_receipt.chainlock_target_hash = normal_base.statement.block_hash;
        normal_receipt.chainlock_logical_id = normal_base.GetLogicalId(genesis);
        normal_receipt.accepted_cursor = base_cursor;
        const auto normal_state{ApplyBTCCReceiptState(
            genesis, config->chainlock_schedule, config->btcc_schedule,
            config->activation_predecessor_height, NORMAL_CARRIER,
            chain[NORMAL_CARRIER]->GetBlockHash(), *receipted_state, normal_receipt)};
        BOOST_REQUIRE(normal_state);
        const uint256 old_carrier_id{chain[NORMAL_CARRIER]->pqBTCCReceiptLogicalId};
        for (int32_t height{NORMAL_CARRIER}; height <= TIP_HEIGHT; ++height) {
            set_indexed_receipt(*chain[height], *normal_state);
        }
        chain[NORMAL_CARRIER]->pqBTCCReceiptLogicalId = normal_receipt.chainlock_logical_id;
        auto normal_boundary{boundary};
        normal_boundary.carrier_height = NORMAL_CARRIER;
        normal_boundary.carrier_hash = chain[NORMAL_CARRIER]->GetBlockHash();
        normal_boundary.receipt = normal_receipt;
        normal_boundary.coverage_height = NORMAL_CARRIER;
        normal_boundary.coverage_hash = normal_boundary.carrier_hash;
        normal_boundary.receipt_state = *normal_state;
        BOOST_REQUIRE(normal_boundary.IsStructurallyValid());
        Access::SetHistoricalSyncAuthorization(*handler, normal_boundary, *normal_view);
        BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));
        const auto normal_objective{Access::ObjectiveRosterAuthorization(*handler, *chain[RECOVERY_HEIGHT])};
        BOOST_REQUIRE(normal_objective);
        BOOST_CHECK(normal_objective->mode == ObjectiveRosterAuthorizationMode::NORMAL);
        BOOST_REQUIRE(normal_objective->base);
        BOOST_CHECK(*normal_objective->base == normal_view->metadata.AuthorizationBase());

        {
            // Use the existing initializer-convergence proof path to exercise
            // exact candidate resolution without fabricating a promotion token.
            auto persistence{std::make_unique<PQChainLockPersistence>(
                DBParams{.path = m_path_root / "historical-successor-proof",
                         .cache_bytes = 4U << 20,
                         .memory_only = true},
                genesis, *config)};
            RosterRecoveryPrecommit precommit;
            precommit.pending_seed = base_window.active.seeds.back();
            precommit.pending_seed.state = RosterBeaconState::PENDING;
            precommit.pending_seed.anchor_cursor = base_cursor;
            precommit.pending_seed.future_btc_hash.SetNull();
            BOOST_REQUIRE(precommit.IsStructurallyValid());
            BOOST_REQUIRE(persistence->PersistRosterRecoveryPrecommit(precommit));
            auto original_persistence{
                Access::ExchangePersistence(*handler, std::move(persistence))};
            BOOST_REQUIRE(Access::HasHistoricalSyncAuthorization(*handler));

            const auto current_target{LatestEligibleChainLockTargetHeight(
                config->chainlock_schedule, TIP_HEIGHT)};
            BOOST_REQUIRE(current_target);
            BOOST_REQUIRE_GT(*current_target, normal_boundary.coverage_height);
            CBlockIndex* competing{nullptr};
            {
                LOCK(::cs_main);
                auto header{chain[*current_target]->GetBlockHeader()};
                header.nNonce += 4'000'000;
                competing = chainman.m_blockman.AddToBlockIndex(
                    header, chainman.m_best_header);
                BOOST_REQUIRE(competing);
                competing->nStatus = chain[*current_target]->nStatus;
                competing->pqPaymentProbationStateHash = probation_root;
                set_indexed_receipt(*competing, *normal_state);
                BOOST_CHECK(!chainman.ActiveChain().Contains(competing));
                BOOST_REQUIRE(llmq::IsCurrentChainLockCatchupCandidateAdmissible(
                    config->chainlock_schedule, *chainman.ActiveTip(), *competing));
            }
            const int32_t previous_height{
                *current_target - static_cast<int32_t>(PQ_CL_PERIOD)};
            auto successor{MakeCatchupChainLock(
                *current_target, previous_height,
                chain[previous_height]->GetBlockHash(), 925'602)};
            successor.statement.block_hash = competing->GetBlockHash();
            successor.statement.payment_probation_state_hash = probation_root;
            successor.statement.previous_btcc_cursor = base_cursor;
            successor.statement.accepted_btcc_cursor = base_cursor;
            successor.statement.btcc_receipt_state = *normal_state;
            set_exact_continuation(successor, normal_base);
            const auto successor_proof{
                Access::PrepareHistoricalSyncSuccessor(*handler, successor)};
            BOOST_REQUIRE(successor_proof);
            BOOST_CHECK(successor_proof->Boundary() == normal_boundary);
            BOOST_CHECK(successor_proof->CandidateLogicalId() ==
                        successor.GetLogicalId(genesis));
            BOOST_CHECK(successor_proof->Precommit() == precommit);
            BOOST_CHECK(Access::HasNoFinalityWinner(*handler));

            auto mismatched_height{successor};
            mismatched_height.statement.height += static_cast<int32_t>(PQ_CL_PERIOD);
            BOOST_CHECK(!Access::PrepareHistoricalSyncSuccessor(
                *handler, mismatched_height));
            auto unknown_target{successor};
            unknown_target.statement.block_hash = NonNullHash(925'603);
            BOOST_CHECK(!Access::PrepareHistoricalSyncSuccessor(*handler, unknown_target));
            auto unrelated_base{successor};
            unrelated_base.statement.roster_authorization_base.logical_id = NonNullHash(925'604);
            BOOST_CHECK(!Access::PrepareHistoricalSyncSuccessor(*handler, unrelated_base));

            const uint32_t competing_status{WITH_LOCK(::cs_main,
                return competing->nStatus)};
            {
                LOCK(::cs_main);
                competing->nStatus |= BLOCK_FAILED_VALID;
            }
            BOOST_CHECK(!Access::PrepareHistoricalSyncSuccessor(*handler, successor));
            {
                LOCK(::cs_main);
                competing->nStatus = competing_status;
            }
            Access::SetHistoricalSyncAuthorization(
                *handler, normal_boundary, *normal_view, wrong_revision);
            BOOST_CHECK(!Access::PrepareHistoricalSyncSuccessor(*handler, successor));
            Access::SetHistoricalSyncAuthorization(*handler, normal_boundary, *normal_view);
            BOOST_REQUIRE(Access::PrepareHistoricalSyncSuccessor(*handler, successor));
            Access::ExchangePersistence(*handler, std::move(original_persistence));
        }

        auto unnecessary_recovery{fresh_recovery};
        unnecessary_recovery.statement.btcc_receipt_state = *normal_state;
        set_recovery_base(unnecessary_recovery, normal_base);
        check_rejected(unnecessary_recovery);

        for (int32_t height{NORMAL_CARRIER}; height <= TIP_HEIGHT; ++height) {
            set_indexed_receipt(*chain[height], *receipted_state);
        }
        chain[NORMAL_CARRIER]->pqBTCCReceiptLogicalId = old_carrier_id;
        Access::SetHistoricalSyncAuthorization(*handler, boundary, *historical_base);
        check_recovery();
        Access::SetHistoricalSyncAuthorization(*handler, std::nullopt, *historical_base);
        Access::ExchangeFinalityStore(*handler, std::move(original_store));
    }

    const auto recovery_context{context_for(recovery)};
    BOOST_REQUIRE(recovery_context);
    BOOST_REQUIRE(store->AcceptVerifiedRosterAuthorizationBase(
        recovery, /*signatures_valid=*/true, recovery_context));
    constexpr int32_t RECOVERY_CARRIER{RECOVERY_HEIGHT +
        static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    BTCCReceipt recovery_receipt;
    recovery_receipt.chainlock_target_height = RECOVERY_HEIGHT;
    recovery_receipt.chainlock_target_hash =
        recovery.statement.block_hash;
    recovery_receipt.chainlock_logical_id =
        recovery.GetLogicalId(genesis);
    recovery_receipt.accepted_cursor = base_cursor;
    const auto recovery_receipted_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        config->activation_predecessor_height, RECOVERY_CARRIER,
        chain[RECOVERY_CARRIER]->GetBlockHash(),
        *receipted_state, recovery_receipt)};
    BOOST_REQUIRE(recovery_receipted_state);
    for (int32_t height{RECOVERY_CARRIER};
         height <= TIP_HEIGHT; ++height) {
        chain[height]->pqBTCCReceiptCursorHeight =
            recovery_receipted_state->cursor.sys_height;
        chain[height]->pqBTCCReceiptCursorSysHash =
            recovery_receipted_state->cursor.sys_hash;
        chain[height]->pqBTCCReceiptCursorBTCHash =
            recovery_receipted_state->cursor.btc_hash;
        chain[height]->pqBTCCReceiptStateHash =
            recovery_receipted_state->cumulative_hash;
        chain[height]->pqBTCCReceiptLatestTargetHeight =
            recovery_receipted_state->latest_chainlock_target_height;
        chain[height]->pqBTCCReceiptLatestCarrierHeight =
            recovery_receipted_state->latest_receipt_carrier_height;
    }
    chain[RECOVERY_CARRIER]->pqBTCCReceiptLogicalId =
        recovery_receipt.chainlock_logical_id;

    const auto at_recovery_receipt_carrier{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[RECOVERY_CARRIER])};
    BOOST_REQUIRE(at_recovery_receipt_carrier);
    BOOST_CHECK(at_recovery_receipt_carrier->mode ==
                ObjectiveRosterAuthorizationMode::PAUSE);
    BOOST_CHECK(!at_recovery_receipt_carrier->base);

    constexpr int32_t NORMAL_RESUME_TARGET{
        RECOVERY_CARRIER + static_cast<int32_t>(PQ_CL_PERIOD)};
    const auto after_recovery_receipt_boundary{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[NORMAL_RESUME_TARGET])};
    BOOST_REQUIRE(after_recovery_receipt_boundary);
    BOOST_CHECK(after_recovery_receipt_boundary->mode ==
                ObjectiveRosterAuthorizationMode::NORMAL);
    BOOST_REQUIRE(after_recovery_receipt_boundary->base);
    const RosterAuthorizationBaseIdentity expected_recovery_base{
        recovery.statement.height, recovery.statement.block_hash,
        recovery.GetLogicalId(genesis)};
    BOOST_CHECK(*after_recovery_receipt_boundary->base ==
                expected_recovery_base);
    BOOST_REQUIRE(after_recovery_receipt_boundary->recovery_source);
    BOOST_CHECK(*after_recovery_receipt_boundary->recovery_source ==
                base_window.active.recovery_authority_source);

    // A stale-base certificate cannot discard an unconsumed observation just
    // because both histories still have the same active signer authority.
    auto observed_current{MakeCatchupChainLock(
        CANDIDATE_HEIGHT, CURRENT_HEIGHT, current.statement.block_hash,
        926'500)};
    observed_current.statement.block_hash =
        chain[CANDIDATE_HEIGHT]->GetBlockHash();
    observed_current.statement.payment_probation_state_hash = probation_root;
    observed_current.statement.btcc_receipt_state = *receipted_state;
    observed_current.statement.roster_authorization_base = {
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    observed_current.statement.roster_beacons = base_window;
    auto& observed_next{observed_current.statement.roster_beacons.next};
    observed_next.state = RosterBeaconState::PENDING;
    observed_next.anchor_cursor = {
        CANDIDATE_HEIGHT, observed_current.statement.block_hash,
        NonNullHash(927'000)};
    observed_next.anchor_btc_height = 800'000;
    observed_current.statement.previous_btcc_cursor = base_cursor;
    observed_current.statement.accepted_btcc_cursor =
        observed_next.anchor_cursor;
    observed_current.statement.btcc_advance = BTCCAdvance::ADVANCE;
    {
        RosterAuthorizationTransition transition;
        transition.kind = RosterAuthorizationTransitionKind::OBSERVE;
        transition.target_height = observed_current.statement.height;
        transition.target_block_hash =
            observed_current.statement.block_hash;
        transition.predecessor_height =
            observed_current.statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            observed_current.statement.previous_chainlock_hash;
        transition.authorization_base =
            observed_current.statement.roster_authorization_base;
        transition.previous = RosterAuthorizationPriorState{
            base.statement.roster_authorization_state_hash,
            base.statement.roster_beacons};
        transition.new_window = observed_current.statement.roster_beacons;
        observed_current.statement.roster_transition = transition.kind;
        const auto state_hash{
            GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(state_hash);
        observed_current.statement.roster_authorization_state_hash =
            *state_hash;
    }
    BOOST_REQUIRE(observed_current.IsStructurallyValid());
    chain[CANDIDATE_HEIGHT]->btcpPrevCommitment =
        observed_next.anchor_cursor.btc_hash;

    constexpr int32_t RECONCILIATION_HEIGHT{CANDIDATE_HEIGHT + 2 *
        static_cast<int32_t>(PQ_CL_PERIOD)};
    auto superseding{MakeCatchupChainLock(
        RECONCILIATION_HEIGHT,
        RECONCILIATION_HEIGHT - static_cast<int32_t>(PQ_CL_PERIOD),
        chain[RECONCILIATION_HEIGHT -
              static_cast<int32_t>(PQ_CL_PERIOD)]->GetBlockHash(),
        925'100)};
    superseding.statement.block_hash =
        chain[RECONCILIATION_HEIGHT]->GetBlockHash();
    superseding.statement.payment_probation_state_hash = probation_root;
    superseding.statement.previous_btcc_cursor = base_cursor;
    superseding.statement.accepted_btcc_cursor = base_cursor;
    superseding.statement.btcc_advance = BTCCAdvance::KEEP;
    superseding.statement.btcc_receipt_state = *receipted_state;
    set_exact_continuation(superseding, base);

    Access::ResetFinalityStoreWithContext(*handler, store_context);
    store = Access::Store(*handler);
    BOOST_REQUIRE(store);
    install(*store, base);
    install(*store, current);
    BOOST_REQUIRE(IsEligibleChainLockTarget(
        config->chainlock_schedule, observed_current.statement.height));
    install(*store, observed_current);
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, superseding));

    // The existing candidate-bound null-carrier proof is the sole exception:
    // it authenticates rollback of the provisional cursor and its next seed.
    BTCCCursorReconciliationProof reconciliation;
    reconciliation.carrier_height = RECONCILIATION_HEIGHT;
    reconciliation.carrier_hash = superseding.statement.block_hash;
    reconciliation.carrier_parent_hash =
        chain[RECONCILIATION_HEIGHT - 1]->GetBlockHash();
    reconciliation.skipped_cursor =
        observed_current.statement.accepted_btcc_cursor;
    reconciliation.previous_receipt_state = *receipted_state;
    reconciliation.current_receipt_state = *receipted_state;
    BOOST_REQUIRE(reconciliation.IsStructurallyValid());
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, superseding,
        reconciliation));
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, superseding,
        reconciliation));

    // A structurally valid recovery state has a different signed source and
    // therefore cannot use the stale-base convergence exception.
    auto incompatible_current{current};
    const auto incompatible_recovery_window{MakeRecoveryRosterBeaconWindow(
        base_window.active.recovery_authority_source,
        base_window.active.seeds.back().epoch)};
    BOOST_REQUIRE(incompatible_recovery_window);
    incompatible_current.statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    incompatible_current.statement.roster_beacons =
        *incompatible_recovery_window;
    {
        RosterAuthorizationTransition transition;
        transition.kind = RosterAuthorizationTransitionKind::RECOVER;
        transition.target_height = incompatible_current.statement.height;
        transition.target_block_hash =
            incompatible_current.statement.block_hash;
        transition.predecessor_height =
            incompatible_current.statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            incompatible_current.statement.previous_chainlock_hash;
        transition.authorization_base =
            incompatible_current.statement.roster_authorization_base;
        transition.previous = RosterAuthorizationPriorState{
            base.statement.roster_authorization_state_hash,
            base.statement.roster_beacons};
        transition.new_window = incompatible_current.statement.roster_beacons;
        const auto state_hash{
            GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(state_hash);
        incompatible_current.statement.roster_authorization_state_hash =
            *state_hash;
    }
    BOOST_REQUIRE(incompatible_current.IsStructurallyValid());
    Access::ResetFinalityStoreWithContext(*handler, store_context);
    store = Access::Store(*handler);
    BOOST_REQUIRE(store);
    install(*store, base);
    install(*store, incompatible_current);
    BOOST_CHECK(!Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, superseding,
        reconciliation));

    // A REVEAL may retain the older authenticated recovery source when the
    // newly READY source has fewer than 400 rooted members. Once receipted,
    // that exact signed choice remains the objective source once its carrier
    // reaches the next round boundary; it must not be replaced by the rejected
    // newest seed.
    RosterBeaconWindow pending_source_window{base_window};
    auto& pending_source{pending_source_window.next};
    pending_source.state = RosterBeaconState::PENDING;
    pending_source.anchor_cursor = base_cursor;
    pending_source.anchor_btc_height = 800'000;
    BOOST_REQUIRE(pending_source_window.IsStructurallyValid());

    const int32_t retained_height{CANDIDATE_HEIGHT};
    const int32_t retained_predecessor_height{CURRENT_HEIGHT};
    const RosterAuthorizationBaseIdentity retained_authorization_base{
        retained_predecessor_height,
        chain[retained_predecessor_height]->GetBlockHash(),
        NonNullHash(927'500)};
    NormalRosterAuthorizationInput retained_input;
    const auto retained_epoch{EpochForHeight(
        config->chainlock_schedule, retained_height)};
    BOOST_REQUIRE(retained_epoch);
    retained_input.newest_epoch = *retained_epoch;
    retained_input.target_height = retained_height;
    retained_input.target_block_hash = chain[retained_height]->GetBlockHash();
    retained_input.predecessor_height = retained_predecessor_height;
    retained_input.predecessor_block_hash =
        chain[retained_predecessor_height]->GetBlockHash();
    retained_input.authorization_base = retained_authorization_base;
    retained_input.previous = RosterAuthorizationPriorState{
        NonNullHash(927'501), pending_source_window};
    retained_input.previous_btcc_cursor = base_cursor;
    retained_input.accepted_btcc_cursor = base_cursor;
    retained_input.btcc_advance = BTCCAdvance::KEEP;
    retained_input.next_snapshot.epoch = *retained_epoch + 1;
    const auto* quorum_config{Access::QuorumConfig(*handler)};
    BOOST_REQUIRE(quorum_config);
    const auto retained_snapshot_height{RegistrationCutoffHeight(
        config->chainlock_schedule, retained_input.next_snapshot.epoch,
        quorum_config->roster_snapshot_lag_blocks)};
    BOOST_REQUIRE(retained_snapshot_height);
    BOOST_REQUIRE(retained_authorization_base.height >=
                  *retained_snapshot_height);
    retained_input.next_snapshot.height = *retained_snapshot_height;
    retained_input.next_snapshot.hash =
        chain[*retained_snapshot_height]->GetBlockHash();
    retained_input.next_snapshot.prior_authorization_is_descendant = true;
    const auto future_height{pending_source.FutureBTCHeight()};
    BOOST_REQUIRE(future_height);
    retained_input.pending_reveal = ValidatedRosterBeaconRange{
        pending_source.anchor_cursor.btc_hash,
        pending_source.anchor_btc_height,
        NonNullHash(927'502),
        *future_height,
        *future_height +
            static_cast<int32_t>(ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1),
        true};
    auto rejected_source{pending_source};
    rejected_source.state = RosterBeaconState::READY;
    rejected_source.future_btc_hash =
        retained_input.pending_reveal->future_hash;
    retained_input.recovery_source_evaluation =
        NormalRosterAuthorizationInput::RecoverySourceEvaluation{
            RecoveryRosterAuthoritySource{rejected_source}, false};
    retained_input.recovery_authority_source =
        base_window.active.recovery_authority_source;
    const auto retained_decision{DeriveNormalRosterAuthorizationDecision(
        genesis, retained_input)};
    BOOST_REQUIRE(retained_decision);
    BOOST_REQUIRE(retained_decision->transition.kind ==
                  RosterAuthorizationTransitionKind::REVEAL);
    BOOST_REQUIRE(retained_decision->transition.new_window.active
                      .recovery_authority_source ==
                  base_window.active.recovery_authority_source);
    BOOST_REQUIRE(FindNewestNormalReadySeed(
                      retained_decision->transition.new_window) != nullptr);
    BOOST_REQUIRE(FindNewestNormalReadySeed(
                      retained_decision->transition.new_window)->epoch ==
                  rejected_source.epoch);

    auto retained_source_base{MakeCatchupChainLock(
        retained_height, retained_predecessor_height,
        chain[retained_predecessor_height]->GetBlockHash(), 927'503)};
    retained_source_base.statement.block_hash =
        chain[retained_height]->GetBlockHash();
    retained_source_base.statement.previous_btcc_cursor = base_cursor;
    retained_source_base.statement.accepted_btcc_cursor = base_cursor;
    retained_source_base.statement.btcc_advance = BTCCAdvance::KEEP;
    retained_source_base.statement.btcc_receipt_state = *receipted_state;
    retained_source_base.statement.payment_probation_state_hash =
        probation_root;
    retained_source_base.statement.roster_transition =
        retained_decision->transition.kind;
    retained_source_base.statement.roster_beacons =
        retained_decision->transition.new_window;
    retained_source_base.statement.roster_authorization_state_hash =
        retained_decision->state_hash;
    retained_source_base.statement.roster_authorization_base =
        retained_authorization_base;
    BOOST_REQUIRE(retained_source_base.IsStructurallyValid());

    Access::ResetFinalityStoreWithContext(*handler, store_context);
    store = Access::Store(*handler);
    BOOST_REQUIRE(store);
    const auto retained_context{context_for(retained_source_base)};
    BOOST_REQUIRE(retained_context);
    BOOST_REQUIRE(store->AcceptVerifiedRosterAuthorizationBase(
        retained_source_base, /*signatures_valid=*/true,
        retained_context));

    constexpr int32_t RETAINED_SOURCE_CARRIER{
        CANDIDATE_HEIGHT + static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    BTCCReceipt retained_source_receipt;
    retained_source_receipt.chainlock_target_height = retained_height;
    retained_source_receipt.chainlock_target_hash =
        retained_source_base.statement.block_hash;
    retained_source_receipt.chainlock_logical_id =
        retained_source_base.GetLogicalId(genesis);
    retained_source_receipt.accepted_cursor = base_cursor;
    const auto retained_source_receipt_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        config->activation_predecessor_height, RETAINED_SOURCE_CARRIER,
        chain[RETAINED_SOURCE_CARRIER]->GetBlockHash(), *receipted_state,
        retained_source_receipt)};
    BOOST_REQUIRE(retained_source_receipt_state);
    constexpr int32_t RETAINED_SOURCE_AUTHORITY_TARGET{
        RETAINED_SOURCE_CARRIER + static_cast<int32_t>(PQ_CL_PERIOD)};
    for (int32_t height{RETAINED_SOURCE_CARRIER};
         height <= RETAINED_SOURCE_AUTHORITY_TARGET; ++height) {
        chain[height]->pqBTCCReceiptCursorHeight =
            retained_source_receipt_state->cursor.sys_height;
        chain[height]->pqBTCCReceiptCursorSysHash =
            retained_source_receipt_state->cursor.sys_hash;
        chain[height]->pqBTCCReceiptCursorBTCHash =
            retained_source_receipt_state->cursor.btc_hash;
        chain[height]->pqBTCCReceiptStateHash =
            retained_source_receipt_state->cumulative_hash;
        chain[height]->pqBTCCReceiptLatestTargetHeight =
            retained_source_receipt_state->latest_chainlock_target_height;
        chain[height]->pqBTCCReceiptLatestCarrierHeight =
            retained_source_receipt_state->latest_receipt_carrier_height;
    }
    chain[RETAINED_SOURCE_CARRIER]->pqBTCCReceiptLogicalId =
        retained_source_receipt.chainlock_logical_id;

    const auto retained_objective{Access::ObjectiveRosterAuthorization(
        *handler, *chain[RETAINED_SOURCE_AUTHORITY_TARGET])};
    BOOST_REQUIRE(retained_objective);
    BOOST_REQUIRE(retained_objective->recovery_source);
    BOOST_CHECK(*retained_objective->recovery_source ==
                base_window.active.recovery_authority_source);

    // A historical audit missing only its exact seal owns one bounded CLSIG
    // lane. Replacing the carrier invalidates the old capability before its
    // durable write; an accepted seal is retained as authorization only and
    // makes the same audit dependency resolvable without rebasing finality.
    auto audit_seal{MakeCatchupChainLock(
        retained_height + static_cast<int32_t>(PQ_CL_PERIOD),
        retained_height, retained_source_base.statement.block_hash,
        927'504)};
    audit_seal.statement.block_hash =
        chain[audit_seal.statement.height]->GetBlockHash();
    audit_seal.statement.previous_btcc_cursor = base_cursor;
    audit_seal.statement.accepted_btcc_cursor = base_cursor;
    audit_seal.statement.btcc_advance = BTCCAdvance::KEEP;
    audit_seal.statement.btcc_receipt_state = *receipted_state;
    audit_seal.statement.payment_probation_state_hash = probation_root;
    set_exact_continuation(audit_seal, retained_source_base);
    BOOST_REQUIRE(audit_seal.IsStructurallyValid());

    auto audit_receipt{NonNullPaymentAuditReceipt(927'505)};
    audit_receipt.seal_height = audit_seal.statement.height;
    audit_receipt.seal_block_hash = audit_seal.statement.block_hash;
    audit_receipt.carrier_height =
        audit_receipt.seal_height + PAYMENT_AUDIT_RECEIPT_DELAY;
    BOOST_REQUIRE(audit_receipt.IsStructurallyValid());
    const uint256 audit_carrier_hash{NonNullHash(927'506)};
    const uint256 audit_carrier_parent_hash{NonNullHash(927'507)};
    const RosterAuthorizationBaseIdentity audit_objective_base{
        retained_source_base.statement.height,
        retained_source_base.statement.block_hash,
        retained_source_base.GetLogicalId(genesis)};

    Access::SetPendingPaymentAuditReceipt(
        *handler, audit_receipt, audit_carrier_hash,
        audit_carrier_parent_hash);
    BOOST_REQUIRE(Access::StagePaymentAuditSealDependency(
        *handler, audit_seal.statement, audit_objective_base));
    BOOST_CHECK(Access::HasPendingPaymentAuditSeal(*handler));
    BOOST_CHECK(Access::HasPendingPaymentAuditReceipt(*handler));
    BOOST_CHECK(Access::HasNeededPaymentAuditSeal(*handler));
    const auto stale_capability{Access::PaymentAuditSealCapability(
        *handler, audit_seal.GetLogicalId(genesis))};
    BOOST_REQUIRE(
        Access::HasPaymentAuditSealCapability(stale_capability));
    BOOST_CHECK(!Access::HasPaymentAuditSealCapability(
        Access::PaymentAuditSealCapability(
            *handler, NonNullHash(927'508))));

    Access::ClearPaymentAuditDependenciesForStop(*handler);
    BOOST_CHECK(!Access::HasPendingPaymentAuditSeal(*handler));
    BOOST_CHECK(!Access::HasPendingPaymentAuditReceipt(*handler));
    BOOST_CHECK(!Access::HasNeededPaymentAuditSeal(*handler));

    auto replacement_receipt{audit_receipt};
    replacement_receipt.audit_witness_id = NonNullHash(927'509);
    BOOST_REQUIRE(replacement_receipt.IsStructurallyValid());
    Access::SetPendingPaymentAuditReceipt(
        *handler, replacement_receipt, NonNullHash(927'510),
        NonNullHash(927'511));
    std::size_t stale_persist_calls{0};
    ChainLockFinalityError finality_error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!Access::AuthorizePaymentAuditSealPersistence(
        *handler, stale_capability,
        [&] {
            ++stale_persist_calls;
            return true;
        },
        &finality_error));
    BOOST_CHECK_EQUAL(stale_persist_calls, 0U);
    BOOST_CHECK(finality_error == ChainLockFinalityError::CONTEXT_CHANGED);

    Access::SetPendingPaymentAuditReceipt(
        *handler, audit_receipt, audit_carrier_hash,
        audit_carrier_parent_hash);
    BOOST_REQUIRE(Access::StagePaymentAuditSealDependency(
        *handler, audit_seal.statement, audit_objective_base));
    const auto capability{Access::PaymentAuditSealCapability(
        *handler, audit_seal.GetLogicalId(genesis))};
    BOOST_REQUIRE(Access::HasPaymentAuditSealCapability(capability));

    std::size_t durable_authorization_calls{0};
    // This synthetic carrier exercises dependency metadata only. The durable
    // write guard now also requires a real current carrier and source owner.
    BOOST_CHECK(!Access::AuthorizePaymentAuditSealPersistence(
        *handler, capability,
        [&] {
            ++durable_authorization_calls;
            return true;
        },
        &finality_error));
    BOOST_CHECK_EQUAL(durable_authorization_calls, 0U);
    BOOST_CHECK(finality_error == ChainLockFinalityError::CONTEXT_CHANGED);

    const auto audit_seal_context{context_for(audit_seal)};
    BOOST_REQUIRE(audit_seal_context);
    BOOST_REQUIRE(store->AcceptVerifiedRosterAuthorizationBase(
        audit_seal, /*signatures_valid=*/true, audit_seal_context,
        &finality_error));
    BOOST_CHECK(!store->GetBest());
    BOOST_REQUIRE(Access::ResolvePaymentAuditSealRecord(
        *store, genesis, audit_seal.statement));
    BOOST_CHECK(handler->AlreadyHave(audit_seal.GetLogicalId(genesis)));
    llmq::CChainLockSig served_seal;
    BOOST_REQUIRE(handler->GetChainLockByHash(
        audit_seal.GetLogicalId(genesis), served_seal));
    BOOST_CHECK(served_seal == audit_seal);

    Access::CompletePaymentAuditSealFetch(*handler, capability);
    BOOST_CHECK(!Access::HasPendingPaymentAuditSeal(*handler));
    BOOST_CHECK(handler->AlreadyHave(audit_seal.GetLogicalId(genesis)));

    // If the exact seal wins the race between roster lookup and dependency
    // staging, the audit response remains successful and no stale GETCLSIG
    // lane is published.
    Access::SetPendingPaymentAuditReceipt(
        *handler, audit_receipt, audit_carrier_hash,
        audit_carrier_parent_hash);
    BOOST_REQUIRE(Access::StagePaymentAuditSealDependency(
        *handler, audit_seal.statement, audit_objective_base));
    BOOST_CHECK(!Access::HasPendingPaymentAuditSeal(*handler));
    BOOST_CHECK(!Access::HasNeededPaymentAuditSeal(*handler));
}
