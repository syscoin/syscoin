// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <evo/deterministicmns.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <llmq/quorums_commitment.h>
#include <key.h>
#include <messagesigner.h>
#include <netbase.h>
#include <primitives/block.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace {

uint256 NonNullHash(uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = value & 0xff;
    hash.begin()[1] = (value >> 8) & 0xff;
    hash.begin()[2] = (value >> 16) & 0xff;
    hash.begin()[3] = (value >> 24) & 0xff;
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

CKeyID NonNullKeyID(uint8_t value)
{
    CKeyID key_id;
    key_id.begin()[0] = value == 0 ? 1 : value;
    return key_id;
}

class PostPQProviderAuthSetup : public BasicTestingSetup
{
private:
    Consensus::Params& m_consensus;
    const int m_old_dip3_height;
    const int m_old_activation_height;
    const int m_old_preparation_height;
    const int m_old_epoch_origin;
    const uint32_t m_old_registration_cutoff;
    const uint32_t m_old_future_horizon;
    std::unique_ptr<CDeterministicMNManager> m_previous_manager;

public:
    static constexpr int ACTIVATION_HEIGHT{1000};

    const uint256 pro_tx_hash{NonNullHash(1)};
    uint256 parent_hash{NonNullHash(2)};
    const uint256 previous_hash{NonNullHash(6)};
    CBlockIndex previous_index;
    CBlockIndex parent_index;
    CService replacement_service;

    PostPQProviderAuthSetup()
        : BasicTestingSetup{ChainType::REGTEST},
          m_consensus{const_cast<Consensus::Params&>(Params().GetConsensus())},
          m_old_dip3_height{m_consensus.DIP0003Height},
          m_old_activation_height{m_consensus.nPQActivationHeight},
          m_old_preparation_height{m_consensus.nPQPreparationHeight},
          m_old_epoch_origin{m_consensus.nPQChainLockEpochOrigin},
          m_old_registration_cutoff{m_consensus.nPQRegistrationCutoffBlocks},
          m_old_future_horizon{m_consensus.nPQFutureHorizonEpochs},
          m_previous_manager{std::move(deterministicMNManager)}
    {
        // Keep the two-block fixture's inverse-history base available.
        m_consensus.DIP0003Height = ACTIVATION_HEIGHT - 2;
        m_consensus.nPQActivationHeight = ACTIVATION_HEIGHT;
        m_consensus.nPQPreparationHeight = ACTIVATION_HEIGHT - 1;
        m_consensus.nPQChainLockEpochOrigin = 1440;
        m_consensus.nPQRegistrationCutoffBlocks = 144;
        m_consensus.nPQFutureHorizonEpochs = 8;

        previous_index.nHeight = ACTIVATION_HEIGHT - 2;
        previous_index.phashBlock = &previous_hash;
        parent_index.nHeight = ACTIVATION_HEIGHT - 1;
        parent_index.pprev = &previous_index;
        parent_index.phashBlock = &parent_hash;

        const auto network_address = LookupHost("1.2.3.4", false);
        assert(network_address);
        replacement_service = CService{*network_address, 12345};

        auto db_params = DBParams{
            .path = m_path_root / "provider_auth_evo",
            .cache_bytes = static_cast<std::size_t>(1 << 20),
            .memory_only = true,
            .wipe_data = true,
        };
        deterministicMNManager =
            std::make_unique<CDeterministicMNManager>(db_params);

        CDeterministicMNList parent_list{
            parent_hash, ACTIVATION_HEIGHT - 1, 1};
        auto member = std::make_shared<CDeterministicMN>(0);
        member->proTxHash = pro_tx_hash;
        member->collateralOutpoint = COutPoint{NonNullHash(5), 0};
        auto state = std::make_shared<CDeterministicMNState>();
        state->nVersion = CProRegTx::PQ_VERSION;
        state->nRegisteredHeight = ACTIVATION_HEIGHT - 100;
        state->nCollateralHeight = ACTIVATION_HEIGHT - 200;
        state->keyIDOwner = NonNullKeyID(1);
        state->keyIDVoting = NonNullKeyID(2);
        member->pdmnState = std::move(state);
        parent_list.AddMN(member, /*fBumpTotalCount=*/false);
        deterministicMNManager->m_evoDb->WriteCache(parent_hash,
                                                     std::move(parent_list));
    }

    ~PostPQProviderAuthSetup()
    {
        deterministicMNManager.reset();
        deterministicMNManager = std::move(m_previous_manager);
        m_consensus.DIP0003Height = m_old_dip3_height;
        m_consensus.nPQActivationHeight = m_old_activation_height;
        m_consensus.nPQPreparationHeight = m_old_preparation_height;
        m_consensus.nPQChainLockEpochOrigin = m_old_epoch_origin;
        m_consensus.nPQRegistrationCutoffBlocks =
            m_old_registration_cutoff;
        m_consensus.nPQFutureHorizonEpochs = m_old_future_horizon;
    }

    void UseDisabledPQActivation()
    {
        m_consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    }

    void LoadEmptyParentRegistry()
    {
        LOCK(cs_main);
        auto previous_list{deterministicMNManager->GetListForBlock(&parent_index)};
        previous_list.SetBlockHash(previous_hash);
        previous_list.SetHeight(previous_index.nHeight);
        deterministicMNManager->m_evoDb->WriteCache(
            previous_hash, std::move(previous_list));

        CBlock preparation;
        preparation.hashPrevBlock = previous_hash;
        preparation.nTime = parent_index.nHeight;
        preparation.nNonce = parent_index.nHeight;
        preparation.vtx.emplace_back(MakeTransactionRef(CMutableTransaction{}));
        parent_hash = preparation.GetHash();
        CCoinsView base_view;
        CCoinsViewCache view{&base_view};
        const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
        BlockValidationState state;
        CDeterministicMNListNEVMAddressDiff diff;
        BOOST_REQUIRE_MESSAGE(deterministicMNManager->ProcessBlock(
            preparation, &parent_index, state, view, no_legacy_commitment,
            diff, /*fJustCheck=*/false, /*ibd=*/true), state.ToString());

        llmq::pq::PQRegistryReadView registry;
        std::string error;
        BOOST_REQUIRE_MESSAGE(deterministicMNManager->GetPQRegistryReadView(
            &parent_index, registry, error), error);
        BOOST_CHECK_EQUAL(registry.OperatorCount(), 0U);
        BOOST_REQUIRE(deterministicMNManager->GetListForBlock(
            &parent_index).GetMN(pro_tx_hash));
    }

    CTransaction ServiceMutation() const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE;
        transaction.vin.emplace_back(COutPoint{NonNullHash(10), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpServTx payload;
        payload.nVersion = CProUpServTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.addr = replacement_service;
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        payload.globalKeyVersion = 1;
        payload.pqSig[0] = 1;
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    CTransaction RevokeMutation() const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE;
        transaction.vin.emplace_back(COutPoint{NonNullHash(11), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpRevTx payload;
        payload.nVersion = CProUpRevTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        payload.globalKeyVersion = 1;
        payload.pqSig[0] = 1;
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    CTransaction LegacyServiceMutation() const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE;
        transaction.vin.emplace_back(COutPoint{NonNullHash(12), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpServTx payload;
        payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.addr = replacement_service;
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        std::array<uint8_t, CLegacyBLSSignature::SERIALIZED_SIZE> signature{};
        signature[0] = 1;
        assert(payload.legacySig.SetBytes(signature));
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    CTransaction LegacyRevokeMutation() const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE;
        transaction.vin.emplace_back(COutPoint{NonNullHash(13), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpRevTx payload;
        payload.nVersion = CProUpRevTx::BASIC_BLS_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        std::array<uint8_t, CLegacyBLSSignature::SERIALIZED_SIZE> signature{};
        signature[0] = 1;
        assert(payload.legacySig.SetBytes(signature));
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    CTransaction Registration(bool legacy) const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
        transaction.vin.emplace_back(COutPoint{NonNullHash(14), 0});
        transaction.vout.emplace_back(nMNCollateralRequired,
            GetScriptForDestination(WitnessV0KeyHash{NonNullKeyID(70)}));

        CProRegTx payload;
        payload.nVersion = legacy ? CProRegTx::LEGACY_BLS_VERSION
                                 : CProRegTx::PQ_VERSION;
        payload.collateralOutpoint = COutPoint{uint256{}, 0};
        payload.keyIDOwner = NonNullKeyID(20);
        payload.keyIDVoting = NonNullKeyID(21);
        payload.scriptPayout =
            GetScriptForDestination(WitnessV0KeyHash{NonNullKeyID(72)});
        if (legacy) {
            std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> key{};
            key.fill(1);
            assert(payload.pubKeyOperator.SetBytes(key));
        } else {
            payload.pqVotingPublicKey.fill(0x31);
        }
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    CTransaction RegistrarMutation(bool legacy) const
    {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
        transaction.vin.emplace_back(COutPoint{NonNullHash(15), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpRegTx payload;
        payload.nVersion = legacy ? CProUpRegTx::LEGACY_BLS_VERSION
                                 : CProUpRegTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.keyIDVoting = NonNullKeyID(21);
        payload.scriptPayout =
            GetScriptForDestination(WitnessV0KeyHash{NonNullKeyID(72)});
        if (legacy) {
            std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> key{};
            key.fill(2);
            assert(payload.pubKeyOperator.SetBytes(key));
        } else {
            payload.pqVotingPublicKey.fill(0x41);
        }
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        SetTxPayload(transaction, payload);
        return CTransaction{transaction};
    }

    std::array<CTransaction, 4> ProviderTransactions(bool legacy) const
    {
        return {Registration(legacy),
                legacy ? LegacyServiceMutation() : ServiceMutation(),
                RegistrarMutation(legacy),
                legacy ? LegacyRevokeMutation() : RevokeMutation()};
    }

    bool CheckProvider(const CTransaction& transaction,
                       const CBlockIndex* parent,
                       TxValidationState& state,
                       bool just_check,
                       bool check_sigs,
                       SpecialTxValidationContext context =
                           SpecialTxValidationContext::MEMPOOL_PRECHECK) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        CCoinsView base_view;
        CCoinsViewCache view{&base_view};
        view.AddCoin(COutPoint{NonNullHash(5), 0},
            Coin{CTxOut{nMNCollateralRequired, GetScriptForDestination(
                WitnessV0KeyHash{NonNullKeyID(70)})},
                ACTIVATION_HEIGHT - 200, false}, false);
        switch (transaction.nVersion) {
        case SYSCOIN_TX_VERSION_MN_REGISTER:
            return CheckProRegTx(transaction, parent, state, view,
                                 just_check, check_sigs);
        case SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE:
            return CheckProUpServTx(transaction, parent, state,
                                    just_check, check_sigs, context);
        case SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR:
            return CheckProUpRegTx(transaction, parent, state, view,
                                   just_check, check_sigs);
        case SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE:
            return CheckProUpRevTx(transaction, parent, state,
                                   just_check, check_sigs, context);
        default:
            assert(false);
            return false;
        }
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_provider_auth_tests, PostPQProviderAuthSetup)

BOOST_AUTO_TEST_CASE(disabled_activation_replays_legacy_provider_versions)
{
    UseDisabledPQActivation();
    const CTransaction service{LegacyServiceMutation()};
    const CTransaction revoke{LegacyRevokeMutation()};

    LOCK(cs_main);

    TxValidationState service_state;
    BOOST_CHECK(CheckProUpServTx(
        service, &parent_index, service_state, /*fJustCheck=*/false,
        /*check_sigs=*/true, SpecialTxValidationContext::NORMAL));

    TxValidationState revoke_state;
    BOOST_CHECK(CheckProUpRevTx(
        revoke, &parent_index, revoke_state, /*fJustCheck=*/false,
        /*check_sigs=*/true, SpecialTxValidationContext::NORMAL));

    TxValidationState pq_state;
    BOOST_CHECK(!CheckProUpServTx(
        ServiceMutation(), &parent_index, pq_state, /*fJustCheck=*/false,
        /*check_sigs=*/true, SpecialTxValidationContext::NORMAL));
    BOOST_CHECK_EQUAL(pq_state.GetRejectReason(), "bad-protx-version");
}

BOOST_AUTO_TEST_CASE(post_pq_auth_is_independent_of_script_checks)
{
    LoadEmptyParentRegistry();
    const CTransaction service{ServiceMutation()};
    const CTransaction revoke{RevokeMutation()};

    LOCK(cs_main);

    TxValidationState service_precheck;
    BOOST_CHECK(CheckProUpServTx(
        service, &parent_index, service_precheck, /*fJustCheck=*/true,
        /*check_sigs=*/false,
        SpecialTxValidationContext::MEMPOOL_PRECHECK));

    TxValidationState revoke_precheck;
    BOOST_CHECK(CheckProUpRevTx(
        revoke, &parent_index, revoke_precheck, /*fJustCheck=*/true,
        /*check_sigs=*/false,
        SpecialTxValidationContext::MEMPOOL_PRECHECK));

    // The post-script mempool pass and every normal ConnectBlock call use this
    // context, so check_sigs=false must not suppress post-quantum authorization.
    TxValidationState service_normal;
    BOOST_CHECK(!CheckProUpServTx(
        service, &parent_index, service_normal, /*fJustCheck=*/false,
        /*check_sigs=*/false, SpecialTxValidationContext::NORMAL));
    BOOST_CHECK_EQUAL(service_normal.GetRejectReason(), "bad-protx-pq-key");
    BOOST_CHECK(service_normal.IsInvalid());

    TxValidationState revoke_normal;
    BOOST_CHECK(!CheckProUpRevTx(
        revoke, &parent_index, revoke_normal, /*fJustCheck=*/false,
        /*check_sigs=*/false, SpecialTxValidationContext::NORMAL));
    BOOST_CHECK_EQUAL(revoke_normal.GetRejectReason(), "bad-protx-pq-key");
    BOOST_CHECK(revoke_normal.IsInvalid());

    // Block connection delegates only PQ revocation authorization to the
    // registry state transition. Service updates are not registry-owned and
    // must still authenticate in this context.
    TxValidationState revoke_registry_precheck;
    BOOST_CHECK(CheckProUpRevTx(
        revoke, &parent_index, revoke_registry_precheck,
        /*fJustCheck=*/false, /*check_sigs=*/true,
        SpecialTxValidationContext::PQ_REGISTRY_PRECHECK));

    TxValidationState service_registry_precheck;
    BOOST_CHECK(!CheckProUpServTx(
        service, &parent_index, service_registry_precheck,
        /*fJustCheck=*/false, /*check_sigs=*/true,
        SpecialTxValidationContext::PQ_REGISTRY_PRECHECK));
    BOOST_CHECK_EQUAL(service_registry_precheck.GetRejectReason(),
                      "bad-protx-pq-key");
    BOOST_CHECK(service_registry_precheck.IsInvalid());

    // Roll-forward is not a second validation path. It only reapplies effects
    // from a block which passed full validation before the interrupted flush.
    TxValidationState service_rollforward;
    BOOST_CHECK(CheckProUpServTx(
        service, &parent_index, service_rollforward, /*fJustCheck=*/false,
        /*check_sigs=*/false,
        SpecialTxValidationContext::ALREADY_VALIDATED_ROLLFORWARD));

    TxValidationState revoke_rollforward;
    BOOST_CHECK(CheckProUpRevTx(
        revoke, &parent_index, revoke_rollforward, /*fJustCheck=*/false,
        /*check_sigs=*/false,
        SpecialTxValidationContext::ALREADY_VALIDATED_ROLLFORWARD));
}

BOOST_AUTO_TEST_CASE(unavailable_parent_registry_is_a_local_error)
{
    LOCK(cs_main);
    // The fixture has a DMN list but has not processed its preparation block.
    // Missing local registry state must not be classified as an invalid key.
    for (const bool just_check : {false, true}) {
        for (const bool check_sigs : {false, true}) {
            for (const auto& [transaction, check_provider] : {
                     std::pair{ServiceMutation(), &CheckProUpServTx},
                     std::pair{RevokeMutation(), &CheckProUpRevTx}}) {
                TxValidationState state;
                BOOST_CHECK(!check_provider(transaction, &parent_index, state,
                    just_check, check_sigs, SpecialTxValidationContext::NORMAL));
                BOOST_CHECK(state.IsError());
                BOOST_CHECK(!state.IsInvalid());
                BOOST_CHECK_EQUAL(state.GetRejectReason(), "failed-protx-pq-registry");
            }
        }
    }
    TxValidationState service_precheck;
    BOOST_CHECK(!CheckProUpServTx(ServiceMutation(), &parent_index,
        service_precheck, /*fJustCheck=*/false, /*check_sigs=*/true,
        SpecialTxValidationContext::PQ_REGISTRY_PRECHECK));
    BOOST_CHECK(service_precheck.IsError());
}

BOOST_AUTO_TEST_CASE(provider_parent_snapshot_failures_are_local_errors)
{
    LOCK(cs_main);
    auto& db{*deterministicMNManager->m_evoDb};
    const auto parent_list{deterministicMNManager->GetListForBlock(&parent_index)};
    enum class Failure { MISSING, HEIGHT, HASH, DATABASE };
    for (const bool legacy : {false, true}) {
        if (legacy) UseDisabledPQActivation();
        for (const auto& transaction : ProviderTransactions(legacy)) {
            for (const bool just_check : {false, true}) {
                for (const bool check_sigs : {false, true}) {
                    for (const auto failure : {Failure::MISSING, Failure::HEIGHT,
                                               Failure::HASH, Failure::DATABASE}) {
                        BOOST_TEST_CONTEXT("version=" << transaction.nVersion
                            << " legacy=" << legacy << " just_check=" << just_check
                            << " check_sigs=" << check_sigs
                            << " failure=" << static_cast<int>(failure)) {
                            auto snapshot{parent_list};
                            if (failure == Failure::HEIGHT) {
                                snapshot.SetHeight(parent_index.nHeight + 1);
                            } else if (failure == Failure::HASH) {
                                snapshot.SetBlockHash(NonNullHash(90));
                            }
                            db.WriteCache(parent_hash, snapshot);
                            if (failure == Failure::MISSING) {
                                db.EraseCache(parent_hash);
                            } else if (failure == Failure::DATABASE) {
                                // ReadCache must flush this unrelated tombstone
                                // before returning even a cached parent snapshot.
                                db.EraseCache(NonNullHash(91));
                                db.FailNextFlushBatchForTesting();
                            }
                            TxValidationState failed;
                            BOOST_CHECK(!CheckProvider(transaction, &parent_index,
                                failed, just_check, check_sigs,
                                SpecialTxValidationContext::NORMAL));
                            BOOST_CHECK(failed.IsError());
                            BOOST_CHECK(!failed.IsInvalid());
                            BOOST_CHECK_EQUAL(failed.GetRejectReason(),
                                              "failed-protx-parent-state");

                            db.WriteCache(parent_hash, parent_list);
                            // These fixtures check the structural admission
                            // pass; their placeholder PQ signatures do not
                            // claim successful normal operator authorization.
                            TxValidationState restored;
                            BOOST_REQUIRE_MESSAGE(CheckProvider(transaction,
                                &parent_index, restored, just_check,
                                /*check_sigs=*/false), restored.ToString());
                            BOOST_CHECK(restored.IsValid());
                        }
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(provider_parent_lookup_preserves_consensus_checks)
{
    LOCK(cs_main);
    auto& db{*deterministicMNManager->m_evoDb};
    const auto parent_list{deterministicMNManager->GetListForBlock(&parent_index)};
    for (const bool legacy : {false, true}) {
        if (legacy) UseDisabledPQActivation();
        for (const auto& transaction : ProviderTransactions(legacy)) {
            BOOST_TEST_CONTEXT("version=" << transaction.nVersion
                               << " legacy=" << legacy) {
                TxValidationState valid;
                BOOST_REQUIRE_MESSAGE(CheckProvider(transaction, &parent_index,
                    valid, false, false), valid.ToString());

                CMutableTransaction changed_inputs{transaction};
                ++changed_inputs.vin.front().prevout.n;
                TxValidationState inputs_state;
                BOOST_CHECK(!CheckProvider(CTransaction{changed_inputs},
                    &parent_index, inputs_state, false, false));
                BOOST_CHECK(inputs_state.IsInvalid());
                BOOST_CHECK_EQUAL(inputs_state.GetRejectReason(),
                                  "bad-protx-inputs-hash");

                CMutableTransaction no_payload{transaction};
                no_payload.vout.clear();
                no_payload.vout.emplace_back(1, CScript{} << OP_TRUE);
                TxValidationState payload_state;
                BOOST_CHECK(!CheckProvider(CTransaction{no_payload},
                    &parent_index, payload_state, false, false));
                BOOST_CHECK(payload_state.IsInvalid());
                BOOST_CHECK_EQUAL(payload_state.GetRejectReason(),
                                  "bad-protx-payload");

                TxValidationState null_parent;
                BOOST_CHECK(!CheckProvider(transaction, nullptr,
                    null_parent, false, false));
                BOOST_CHECK(null_parent.IsInvalid());
                BOOST_CHECK_EQUAL(null_parent.GetRejectReason(),
                                  "bad-protx-version");

                auto altered_list{parent_list};
                const bool registration{
                    transaction.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER};
                if (registration) {
                    auto member_state{std::make_shared<CDeterministicMNState>(
                        *altered_list.GetMN(pro_tx_hash)->pdmnState)};
                    member_state->keyIDOwner = NonNullKeyID(20);
                    altered_list.UpdateMN(pro_tx_hash, member_state);
                } else {
                    altered_list.RemoveMN(pro_tx_hash);
                }
                db.WriteCache(parent_hash, altered_list);
                TxValidationState membership_state;
                BOOST_CHECK(!CheckProvider(transaction, &parent_index,
                    membership_state, false, false));
                BOOST_CHECK(membership_state.IsInvalid());
                BOOST_CHECK_EQUAL(membership_state.GetRejectReason(),
                    registration ? "bad-protx-dup-key" : "bad-protx-hash");
                db.WriteCache(parent_hash, parent_list);
            }
        }
    }

    // Before DIP3, the manager legitimately returns an empty list without
    // consulting persistent snapshots. Keep that registration contract.
    CBlockIndex pre_dip3;
    pre_dip3.nHeight = ACTIVATION_HEIGHT - 3;
    pre_dip3.phashBlock = &previous_hash;
    TxValidationState pre_dip3_state;
    BOOST_REQUIRE_MESSAGE(CheckProvider(Registration(/*legacy=*/true),
        &pre_dip3, pre_dip3_state, false, true), pre_dip3_state.ToString());
}

BOOST_AUTO_TEST_CASE(unavailable_provider_parent_manager_is_a_local_error)
{
    LOCK(cs_main);
    struct RestoreManager {
        std::unique_ptr<CDeterministicMNManager> manager{
            std::move(deterministicMNManager)};
        ~RestoreManager() { deterministicMNManager = std::move(manager); }
    } restore;
    for (const auto& transaction : ProviderTransactions(/*legacy=*/false)) {
        TxValidationState state;
        BOOST_CHECK(!CheckProvider(transaction, &parent_index, state,
                                   false, false));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "failed-protx-parent-state");
    }
}

BOOST_AUTO_TEST_CASE(pq_voting_registrar_remains_owner_authorized)
{
    LOCK(cs_main);
    CKey owner;
    owner.MakeNewKey(true);
    CKey non_owner;
    non_owner.MakeNewKey(true);
    auto parent_list{deterministicMNManager->GetListForBlock(&parent_index)};
    const auto member{parent_list.GetMN(pro_tx_hash)};
    BOOST_REQUIRE(member);
    auto original{std::make_shared<CDeterministicMNState>(*member->pdmnState)};
    original->keyIDOwner = owner.GetPubKey().GetID();
    original->keyIDVoting = non_owner.GetPubKey().GetID();
    llmq::pq::GlobalPublicKey original_key{};
    original_key.fill(0x31);
    BOOST_REQUIRE(original->pqVotingKey.UpdatePublicKey(original_key, parent_index.nHeight - 1));
    parent_list.UpdateMN(pro_tx_hash, original);
    deterministicMNManager->m_evoDb->WriteCache(parent_hash, parent_list);
    LoadEmptyParentRegistry();

    CCoinsView base_view;
    CCoinsViewCache view{&base_view};
    view.AddCoin(member->collateralOutpoint,
        Coin{CTxOut{nMNCollateralRequired, GetScriptForDestination(
            WitnessV0KeyHash{NonNullKeyID(70)})}, parent_index.nHeight - 100, false}, false);

    for (bool revoke : {false, true}) {
        CMutableTransaction transaction;
        transaction.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
        transaction.vin.emplace_back(COutPoint{NonNullHash(71), 0});
        transaction.vout.emplace_back(1, CScript{} << OP_TRUE);
        CProUpRegTx payload;
        payload.nVersion = CProUpRegTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.keyIDVoting = original->keyIDVoting;
        if (!revoke) payload.pqVotingPublicKey.fill(0x41);
        payload.scriptPayout = GetScriptForDestination(WitnessV0KeyHash{NonNullKeyID(72)});
        payload.inputsHash = CalcTxInputsHash(CTransaction{transaction});
        BOOST_REQUIRE(CHashSigner::SignHash(::SerializeHash(payload), owner, payload.vchSig));
        SetTxPayload(transaction, payload);
        TxValidationState valid;
        BOOST_REQUIRE_MESSAGE(CheckProUpRegTx(CTransaction{transaction}, &parent_index,
            valid, view, false, true), valid.ToString());

        payload.pqVotingPublicKey.back() ^= 1;
        SetTxPayload(transaction, payload);
        TxValidationState changed_key;
        BOOST_CHECK(!CheckProUpRegTx(CTransaction{transaction}, &parent_index,
            changed_key, view, false, true));
        BOOST_CHECK(changed_key.IsInvalid());
        BOOST_CHECK_EQUAL(changed_key.GetRejectReason(), "bad-protx-hash-sig");
        BOOST_REQUIRE(CHashSigner::SignHash(::SerializeHash(payload), non_owner, payload.vchSig));
        SetTxPayload(transaction, payload);
        TxValidationState wrong_owner;
        BOOST_CHECK(!CheckProUpRegTx(CTransaction{transaction}, &parent_index,
            wrong_owner, view, false, true));
        BOOST_CHECK(wrong_owner.IsInvalid());
        BOOST_CHECK_EQUAL(wrong_owner.GetRejectReason(), "bad-protx-hash-sig");
    }
}

BOOST_AUTO_TEST_SUITE_END()
