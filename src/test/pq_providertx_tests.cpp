// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_providertx.h>

#include <llmq/pq_global_auth.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint32_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<uint8_t>(value >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

ChildKeyTreeCommitment Commitment(uint32_t generation = 1)
{
    ChildKeyTreeCommitment commitment;
    commitment.generation = generation;
    commitment.first_epoch = 7;
    commitment.tree_id = NonNullHash(100 + generation);
    commitment.root = NonNullHash(200 + generation);
    return commitment;
}

GlobalKeyTxPayload ValidGlobal(GlobalKeyOperation operation)
{
    GlobalKeyTxPayload payload;
    payload.operation = operation;
    payload.pro_tx_hash = NonNullHash(1);
    payload.candidate.key_version =
        operation == GlobalKeyOperation::INITIAL ? 1 : 2;
    payload.candidate.public_key[0] = 2;
    payload.candidate.child_key_commitment = Commitment();
    payload.transaction_inputs_hash = NonNullHash(3);
    if (operation == GlobalKeyOperation::INITIAL) {
        payload.owner_authorization[0] = 27;
        payload.owner_authorization[1] = 1;
        payload.owner_authorization.back() = 1;
    }
    payload.authorization[0] = 4;
    return payload;
}

std::vector<unsigned char> Encode(const GlobalKeyTxPayload& value)
{
    DataStream stream;
    stream << value;
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_providertx_tests)

BOOST_AUTO_TEST_CASE(global_payload_is_fixed_and_canonical)
{
    for (const auto operation : {GlobalKeyOperation::INITIAL,
                                 GlobalKeyOperation::ROTATE}) {
        const auto payload = ValidGlobal(operation);
        BOOST_REQUIRE(payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
        const auto encoded = Encode(payload);
        BOOST_CHECK_EQUAL(encoded.size(), GlobalKeyTxPayload::WIRE_SIZE);
        GlobalKeyTxPayload decoded;
        BOOST_REQUIRE(DecodeGlobalKeyTxPayload(encoded, decoded));
        BOOST_CHECK(decoded == payload);

        auto truncated = encoded;
        truncated.pop_back();
        BOOST_CHECK(!DecodeGlobalKeyTxPayload(truncated, decoded));
        auto suffixed = encoded;
        suffixed.push_back(0);
        BOOST_CHECK(!DecodeGlobalKeyTxPayload(suffixed, decoded));
    }

    auto payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION + 1));
    payload.version++;
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
    payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    payload.candidate.child_key_commitment.root.SetNull();
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
    payload = ValidGlobal(GlobalKeyOperation::ROTATE);
    payload.candidate.activated_height = 1;
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
    payload = ValidGlobal(GlobalKeyOperation::ROTATE);
    payload.authorization.fill(0);
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));

    payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    payload.owner_authorization.fill(0);
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
    payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    payload.owner_authorization[0] = 26;
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
    payload = ValidGlobal(GlobalKeyOperation::ROTATE);
    payload.owner_authorization[0] = 27;
    payload.owner_authorization[1] = 1;
    BOOST_CHECK(!payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
}

BOOST_AUTO_TEST_CASE(owner_registration_digest_binds_child_root_metadata)
{
    const uint256 genesis = NonNullHash(9);
    const auto payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    const auto digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis, payload);
    BOOST_REQUIRE(digest);

    auto changed = payload;
    changed.pro_tx_hash = NonNullHash(10);
    auto changed_digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis, changed);
    BOOST_REQUIRE(changed_digest);
    BOOST_CHECK(*digest != *changed_digest);
    changed = payload;
    changed.candidate.child_key_commitment.root = NonNullHash(11);
    changed_digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis, changed);
    BOOST_REQUIRE(changed_digest);
    BOOST_CHECK(*digest != *changed_digest);
    changed = payload;
    changed.candidate.child_key_commitment.tree_id = NonNullHash(12);
    changed_digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis, changed);
    BOOST_REQUIRE(changed_digest);
    BOOST_CHECK(*digest != *changed_digest);
    changed = payload;
    changed.transaction_inputs_hash = NonNullHash(13);
    changed_digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis, changed);
    BOOST_REQUIRE(changed_digest);
    BOOST_CHECK(*digest != *changed_digest);
}

BOOST_AUTO_TEST_CASE(global_transcript_binds_complete_candidate)
{
    const uint256 genesis = NonNullHash(20);
    auto payload = ValidGlobal(GlobalKeyOperation::INITIAL);
    const uint256 registration = GetGlobalRegistrationHash(
        genesis, payload.pro_tx_hash, payload.candidate,
        payload.transaction_inputs_hash);

    auto changed = payload;
    changed.candidate.child_key_commitment.first_epoch++;
    BOOST_CHECK(registration != GetGlobalRegistrationHash(
                                    genesis, changed.pro_tx_hash,
                                    changed.candidate,
                                    changed.transaction_inputs_hash));
    changed = payload;
    changed.candidate.public_key[1] = 1;
    BOOST_CHECK(registration != GetGlobalRegistrationHash(
                                    genesis, changed.pro_tx_hash,
                                    changed.candidate,
                                    changed.transaction_inputs_hash));
    changed = payload;
    changed.transaction_inputs_hash = NonNullHash(21);
    BOOST_CHECK(registration != GetGlobalRegistrationHash(
                                    genesis, changed.pro_tx_hash,
                                    changed.candidate,
                                    changed.transaction_inputs_hash));
}

BOOST_AUTO_TEST_SUITE_END()
