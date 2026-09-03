// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>

#include <chain.h>
#include <consensus/params.h>
#include <governance/governanceclasses.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
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
    };

    class NeededCertificateState {
        friend class CChainLocksHandlerTestAccess;
        std::optional<CChainLocksHandler::NeededBTCCCertificate> current;
    };

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
        const uint256& target_btcp_prev)
    {
        return CChainLocksHandler::IsExactHistoricalResetCandidate(
            statement, chainlock, btcc,
            activation_predecessor_height,
            activation_predecessor_hash, has_durable_best,
            target_is_active, target_btcp_prev);
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_handler_tests, BasicTestingSetup)

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
    constexpr uint8_t PRESEAL_CATCHUP{3};
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
    constexpr uint8_t RECOVERY{2};
    constexpr uint8_t PRESEAL_CATCHUP{3};
    constexpr uint8_t PRESEAL_RECEIPT{4};
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
    const auto config{LiveSigningFrontierConfig()};
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
        carrier.nHeight, carrier.GetBlockHash(), {}, receipt)};
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
        carrier_target.nHeight, carrier_target.GetBlockHash(), {}, receipt)};
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
};

} // namespace

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
    constexpr int32_t TIP_HEIGHT{3'475};
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
    BOOST_REQUIRE(base.IsStructurallyValid());

    BTCCReceipt base_receipt;
    base_receipt.chainlock_target_height = BASE_HEIGHT;
    base_receipt.chainlock_target_hash = base.statement.block_hash;
    base_receipt.chainlock_logical_id = base.GetLogicalId(genesis);
    base_receipt.accepted_cursor = base_cursor;
    BOOST_REQUIRE(base_receipt.IsStructurallyValid());
    const auto receipted_state{ApplyBTCCReceiptState(
        genesis, config->chainlock_schedule, config->btcc_schedule,
        CANDIDATE_HEIGHT, chain[CANDIDATE_HEIGHT]->GetBlockHash(),
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
    install(*store, current);
    BOOST_REQUIRE(store->GetVerifiedRosterAuthorizationBase(
        RosterAuthorizationBaseIdentity{
            base.statement.height, base.statement.block_hash,
            base.GetLogicalId(genesis)}));
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::LIVE, candidate));
    BOOST_CHECK(Access::StateAdvancingAuthorizationBaseAdmissible(
        *handler, ChainLockCandidateAdmission::CATCHUP, candidate));

    // A scheduled receipt may carry an exact KEEP certificate. Its statement
    // is bound to the carrier-parent receipt state just like ADVANCE.
    install(*store, candidate);
    constexpr int32_t KEEP_CARRIER{CANDIDATE_HEIGHT +
        static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    const auto keep_receipt{Access::BTCCReceiptForCarrier(
        *handler, KEEP_CARRIER, *chain[KEEP_CARRIER - 1])};
    BOOST_REQUIRE(!keep_receipt.IsNull());
    BOOST_CHECK_EQUAL(keep_receipt.chainlock_target_height,
                      CANDIDATE_HEIGHT);
    BOOST_CHECK(keep_receipt.accepted_cursor == base_cursor);
    BOOST_CHECK(Access::IsVerifiedBTCCReceipt(
        *handler, keep_receipt, *chain[KEEP_CARRIER]));

    Access::ResetFinalityStoreWithContext(*handler, store_context);
    store = Access::Store(*handler);
    BOOST_REQUIRE(store);
    install(*store, base);
    install(*store, current);

    const auto recovery_epoch{EpochForHeight(
        config->chainlock_schedule, RECOVERY_HEIGHT)};
    BOOST_REQUIRE(recovery_epoch);
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
    const RosterAuthorizationBaseIdentity expected_base{
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
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
        RECOVERY_CARRIER, chain[RECOVERY_CARRIER]->GetBlockHash(),
        *receipted_state, recovery_receipt)};
    BOOST_REQUIRE(recovery_receipted_state);
    chain[RECOVERY_CARRIER]->pqBTCCReceiptCursorHeight =
        recovery_receipted_state->cursor.sys_height;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptCursorSysHash =
        recovery_receipted_state->cursor.sys_hash;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptCursorBTCHash =
        recovery_receipted_state->cursor.btc_hash;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptStateHash =
        recovery_receipted_state->cumulative_hash;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptLatestTargetHeight =
        recovery_receipted_state->latest_chainlock_target_height;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptLatestCarrierHeight =
        recovery_receipted_state->latest_receipt_carrier_height;
    chain[RECOVERY_CARRIER]->pqBTCCReceiptLogicalId =
        recovery_receipt.chainlock_logical_id;

    const auto receipted_recovery{
        Access::ObjectiveRosterAuthorization(
            *handler, *chain[RECOVERY_CARRIER])};
    BOOST_REQUIRE(receipted_recovery);
    BOOST_CHECK(receipted_recovery->mode ==
                ObjectiveRosterAuthorizationMode::NORMAL);
    BOOST_REQUIRE(receipted_recovery->base);
    const RosterAuthorizationBaseIdentity expected_recovery_base{
        recovery.statement.height, recovery.statement.block_hash,
        recovery.GetLogicalId(genesis)};
    BOOST_CHECK(*receipted_recovery->base == expected_recovery_base);
    BOOST_REQUIRE(receipted_recovery->recovery_source);
    BOOST_CHECK(*receipted_recovery->recovery_source ==
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
}
