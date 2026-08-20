// Copyright (c) 2022-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_dkgsession.h>
#include <llmq/quorums_dkgsessionmgr.h>
#include <protocol.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <stdexcept>

BOOST_AUTO_TEST_SUITE(llmq_dkg_tests)

namespace {

template <typename Message>
Message WireRoundTrip(const Message& message)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << message;

    Message decoded;
    stream >> decoded;
    if (!stream.empty()) {
        throw std::runtime_error{"DKG message wire round-trip left trailing data"};
    }
    return decoded;
}

} // namespace

BOOST_AUTO_TEST_CASE(llmq_dkgerror)
{
    using namespace llmq;
    for (auto i = 0; i< llmq::DKGError::type::_COUNT;i++) {
        BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type(i)) == 0.0);
        SetSimulatedDKGErrorRate(llmq::DKGError::type(i), 1.0);
        BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type(i)) == 1.0);
    }
    BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type::_COUNT) == 0.0);
    SetSimulatedDKGErrorRate(llmq::DKGError::type::_COUNT, 1.0);
    BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type::_COUNT) == 0.0);
}

BOOST_FIXTURE_TEST_CASE(preverify_rejects_invalid_member_signatures, TestChain100Setup)
{
    using namespace llmq;

    BOOST_REQUIRE(quorumDKGSessionManager != nullptr);
    const CBlockIndex* quorum_base_block{WITH_LOCK(
        cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(quorum_base_block != nullptr);

    const auto& params{Params().GetConsensus().llmqTypeChainLocks};
    BOOST_REQUIRE(params.size <= std::numeric_limits<uint8_t>::max());
    CBLSSecretKey signing_key;
    signing_key.MakeNewKey();
    const bool use_legacy_bls{bls::bls_legacy_scheme.load()};

    std::vector<CDeterministicMNCPtr> members;
    members.reserve(params.size);
    for (int i = 0; i < params.size; ++i) {
        auto member{std::make_shared<CDeterministicMN>(i + 1)};
        member->proTxHash = uint256{static_cast<uint8_t>(i + 1)};
        auto state{std::make_shared<CDeterministicMNState>()};
        if (i == 0) {
            state->pubKeyOperator.Set(signing_key.GetPublicKey(), use_legacy_bls);
        }
        member->pdmnState = std::move(state);
        members.emplace_back(std::move(member));
    }

    CBLSWorker bls_worker;
    CDKGSession session{bls_worker, *quorumDKGSessionManager};
    BOOST_REQUIRE(session.Init(quorum_base_block, members, uint256{}));

    const auto sign = [&](auto& message) {
        message.sig = signing_key.Sign(message.GetSignHash(), use_legacy_bls);
        BOOST_REQUIRE(message.sig.IsValid());
    };
    const auto check_preverification = [&](const auto& message) {
        static_assert(CBLSSignature::SerSize == 96);
        const auto invalid_signature_bytes{message.sig.ToBytes(use_legacy_bls)};
        BOOST_REQUIRE(std::all_of(
            invalid_signature_bytes.begin(), invalid_signature_bytes.end(),
            [](uint8_t byte) { return byte == 0; }));
        const auto invalid_message{WireRoundTrip(message)};
        BOOST_REQUIRE(!invalid_message.sig.IsValid());
        bool ban{false};
        BOOST_CHECK(!session.PreVerifyMessage(invalid_message, ban));
        BOOST_CHECK(ban);

        auto valid_message{message};
        sign(valid_message);
        valid_message = WireRoundTrip(valid_message);
        BOOST_REQUIRE(valid_message.sig.IsValid());
        BOOST_REQUIRE(valid_message.sig.VerifyInsecure(
            members.front()->pdmnState->pubKeyOperator.Get(),
            valid_message.GetSignHash(), use_legacy_bls));
        ban = false;
        BOOST_CHECK(session.PreVerifyMessage(valid_message, ban));
        BOOST_CHECK(!ban);
    };

    CDKGContribution contribution;
    contribution.quorumHash = quorum_base_block->GetBlockHash();
    contribution.proTxHash = members.front()->proTxHash;
    contribution.vvec = std::make_shared<std::vector<CBLSPublicKey>>();
    for (int i = 0; i < params.threshold; ++i) {
        CBLSSecretKey key;
        key.MakeNewKey();
        contribution.vvec->emplace_back(key.GetPublicKey());
    }
    contribution.contributions =
        std::make_shared<CBLSIESMultiRecipientObjects<CBLSSecretKey>>();
    contribution.contributions->blobs.resize(params.size);
    check_preverification(contribution);

    CDKGComplaint complaint{static_cast<size_t>(params.size)};
    complaint.quorumHash = quorum_base_block->GetBlockHash();
    complaint.proTxHash = members.front()->proTxHash;
    check_preverification(complaint);

    CDKGJustification justification;
    justification.quorumHash = quorum_base_block->GetBlockHash();
    justification.proTxHash = members.front()->proTxHash;
    justification.contributions.push_back({0, signing_key});
    check_preverification(justification);
}



BOOST_AUTO_TEST_SUITE_END()
