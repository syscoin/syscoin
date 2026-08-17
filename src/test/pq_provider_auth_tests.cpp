// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <evo/deterministicmns.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <netbase.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
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
    const int m_old_anchor_height;
    const uint256 m_old_anchor_block;
    const uint256 m_old_anchor_dmn_state;
    const uint256 m_old_anchor_registry_state;
    const int m_old_preparation_height;
    const int m_old_epoch_origin;
    const uint32_t m_old_registration_cutoff;
    const uint32_t m_old_future_horizon;
    std::unique_ptr<CDeterministicMNManager> m_previous_manager;

public:
    static constexpr int ANCHOR_HEIGHT{1000};

    const uint256 pro_tx_hash{NonNullHash(1)};
    const uint256 parent_hash{NonNullHash(2)};
    const uint256 previous_hash{NonNullHash(6)};
    CBlockIndex previous_index;
    CBlockIndex parent_index;
    CService replacement_service;

    PostPQProviderAuthSetup()
        : BasicTestingSetup{ChainType::REGTEST},
          m_consensus{const_cast<Consensus::Params&>(Params().GetConsensus())},
          m_old_anchor_height{m_consensus.nPQLegacyAnchorHeight},
          m_old_anchor_block{m_consensus.hashPQLegacyAnchorBlock},
          m_old_anchor_dmn_state{m_consensus.hashPQLegacyMNState},
          m_old_anchor_registry_state{m_consensus.hashPQLegacyPQRegistryState},
          m_old_preparation_height{m_consensus.nPQPreparationHeight},
          m_old_epoch_origin{m_consensus.nPQChainLockEpochOrigin},
          m_old_registration_cutoff{m_consensus.nPQRegistrationCutoffBlocks},
          m_old_future_horizon{m_consensus.nPQFutureHorizonEpochs},
          m_previous_manager{std::move(deterministicMNManager)}
    {
        m_consensus.nPQLegacyAnchorHeight = ANCHOR_HEIGHT;
        m_consensus.hashPQLegacyAnchorBlock = parent_hash;
        m_consensus.hashPQLegacyMNState = NonNullHash(3);
        m_consensus.hashPQLegacyPQRegistryState = NonNullHash(4);
        m_consensus.nPQPreparationHeight = ANCHOR_HEIGHT;
        m_consensus.nPQChainLockEpochOrigin = 1440;
        m_consensus.nPQRegistrationCutoffBlocks = 144;
        m_consensus.nPQFutureHorizonEpochs = 8;

        previous_index.nHeight = ANCHOR_HEIGHT - 1;
        previous_index.phashBlock = &previous_hash;
        parent_index.nHeight = ANCHOR_HEIGHT;
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

        CDeterministicMNList parent_list{parent_hash, ANCHOR_HEIGHT, 1};
        auto member = std::make_shared<CDeterministicMN>(0);
        member->proTxHash = pro_tx_hash;
        member->collateralOutpoint = COutPoint{NonNullHash(5), 0};
        auto state = std::make_shared<CDeterministicMNState>();
        state->nVersion = CProRegTx::PQ_VERSION;
        state->nRegisteredHeight = ANCHOR_HEIGHT - 100;
        state->nCollateralHeight = ANCHOR_HEIGHT - 200;
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
        m_consensus.nPQLegacyAnchorHeight = m_old_anchor_height;
        m_consensus.hashPQLegacyAnchorBlock = m_old_anchor_block;
        m_consensus.hashPQLegacyMNState = m_old_anchor_dmn_state;
        m_consensus.hashPQLegacyPQRegistryState =
            m_old_anchor_registry_state;
        m_consensus.nPQPreparationHeight = m_old_preparation_height;
        m_consensus.nPQChainLockEpochOrigin = m_old_epoch_origin;
        m_consensus.nPQRegistrationCutoffBlocks =
            m_old_registration_cutoff;
        m_consensus.nPQFutureHorizonEpochs = m_old_future_horizon;
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
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_provider_auth_tests, PostPQProviderAuthSetup)

BOOST_AUTO_TEST_CASE(post_pq_auth_is_independent_of_script_checks)
{
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

    TxValidationState revoke_normal;
    BOOST_CHECK(!CheckProUpRevTx(
        revoke, &parent_index, revoke_normal, /*fJustCheck=*/false,
        /*check_sigs=*/false, SpecialTxValidationContext::NORMAL));
    BOOST_CHECK_EQUAL(revoke_normal.GetRejectReason(), "bad-protx-pq-key");

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

BOOST_AUTO_TEST_SUITE_END()
