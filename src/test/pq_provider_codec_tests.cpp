// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/providertx.h>
#include <evo/dmnstate.h>
#include <llmq/pq_global_auth.h>

#include <clientversion.h>
#include <hash.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace {

uint256 NonNullHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value == 0 ? 1 : value;
    return hash;
}

CKeyID NonNullKeyID(uint8_t value)
{
    CKeyID key_id;
    key_id.begin()[0] = value == 0 ? 1 : value;
    return key_id;
}

template <typename Payload>
std::size_t WireSize(const Payload& payload)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << payload;
    return stream.size();
}

template <typename Payload>
std::vector<std::byte> Encoded(const Payload& payload)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << payload;
    return {stream.begin(), stream.end()};
}

std::vector<std::byte> LegacyStateBytes(const CDeterministicMNState& state)
{
    CDataStream stream{SER_DISK, PROTOCOL_VERSION};
    stream << state.nVersion << state.nRegisteredHeight << state.nLastPaidHeight
           << state.nPoSePenalty << state.nPoSeRevivedHeight << state.GetBannedHeight()
           << state.nRevocationReason << state.confirmedHash
           << state.confirmedHashWithProRegTxHash << state.keyIDOwner
           << state.pubKeyOperator << state.keyIDVoting << state.addr
           << state.scriptPayout << state.scriptOperatorPayout
           << state.nCollateralHeight << state.vchNEVMAddress;
    return {stream.begin(), stream.end()};
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_provider_codec_tests)

BOOST_AUTO_TEST_CASE(post_anchor_registrar_codecs_omit_legacy_operator_key)
{
    CProRegTx pq_registration;
    pq_registration.nVersion = CProRegTx::PQ_VERSION;
    pq_registration.collateralOutpoint.hash = NonNullHash(1);
    pq_registration.keyIDOwner = NonNullKeyID(2);
    pq_registration.keyIDVoting = NonNullKeyID(3);
    pq_registration.pqVotingPublicKey[0] = 1;
    pq_registration.inputsHash = NonNullHash(4);

    CProRegTx legacy_registration = pq_registration;
    legacy_registration.nVersion = CProRegTx::BASIC_BLS_VERSION;
    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key{};
    operator_key[0] = 1;
    BOOST_REQUIRE(legacy_registration.pubKeyOperator.SetBytes(operator_key));
    BOOST_CHECK_EQUAL(WireSize(legacy_registration) - WireSize(pq_registration),
                      CLegacyBLSPublicKey::SERIALIZED_SIZE -
                          llmq::pq::GLOBAL_PUBLIC_KEY_SIZE);

    CProUpRegTx pq_update;
    pq_update.nVersion = CProUpRegTx::PQ_VERSION;
    pq_update.proTxHash = NonNullHash(5);
    pq_update.keyIDVoting = NonNullKeyID(6);
    pq_update.pqVotingPublicKey[0] = 2;
    pq_update.inputsHash = NonNullHash(7);
    CProUpRegTx legacy_update = pq_update;
    legacy_update.nVersion = CProUpRegTx::BASIC_BLS_VERSION;
    BOOST_REQUIRE(legacy_update.pubKeyOperator.SetBytes(operator_key));
    BOOST_CHECK_EQUAL(WireSize(legacy_update) - WireSize(pq_update),
                      CLegacyBLSPublicKey::SERIALIZED_SIZE -
                          llmq::pq::GLOBAL_PUBLIC_KEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pq_voting_provider_fields_preserve_legacy_bytes_and_bind_authorization)
{
    CProRegTx registration;
    registration.keyIDOwner = NonNullKeyID(1);
    registration.keyIDVoting = NonNullKeyID(2);
    registration.inputsHash = NonNullHash(3);
    registration.scriptPayout = GetScriptForDestination(WitnessV0KeyHash(NonNullKeyID(4)));
    registration.pqVotingPublicKey.fill(0x31);
    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key{};
    operator_key[0] = 1;
    BOOST_REQUIRE(registration.pubKeyOperator.SetBytes(operator_key));
    CProUpRegTx update;
    update.proTxHash = NonNullHash(5);
    update.keyIDVoting = registration.keyIDVoting;
    update.pubKeyOperator = registration.pubKeyOperator;
    update.scriptPayout = registration.scriptPayout;
    update.pqVotingPublicKey = registration.pqVotingPublicKey;

    for (uint16_t version : {uint16_t{1}, uint16_t{2}}) {
        registration.nVersion = version;
        update.nVersion = version;
        CDataStream expected_registration{SER_NETWORK, PROTOCOL_VERSION};
        expected_registration << registration.nVersion << registration.nType
            << registration.nMode << registration.collateralOutpoint
            << registration.addr << registration.keyIDOwner << registration.pubKeyOperator
            << registration.keyIDVoting << registration.nOperatorReward
            << registration.scriptPayout << registration.inputsHash << registration.vchSig;
        BOOST_CHECK(Encoded(registration) == std::vector<std::byte>(
            expected_registration.begin(), expected_registration.end()));
        CProRegTx decoded_registration = registration;
        expected_registration >> decoded_registration;
        BOOST_CHECK(llmq::pq::IsNullVotingPublicKey(decoded_registration.pqVotingPublicKey));

        CDataStream expected_update{SER_NETWORK, PROTOCOL_VERSION};
        expected_update << update.nVersion << update.proTxHash << update.nMode
            << update.pubKeyOperator << update.keyIDVoting << update.scriptPayout
            << update.inputsHash << update.vchSig;
        BOOST_CHECK(Encoded(update) == std::vector<std::byte>(
            expected_update.begin(), expected_update.end()));
        CProUpRegTx decoded_update = update;
        expected_update >> decoded_update;
        BOOST_CHECK(llmq::pq::IsNullVotingPublicKey(decoded_update.pqVotingPublicKey));
    }

    registration.nVersion = CProRegTx::PQ_VERSION;
    registration.pubKeyOperator.SetNull();
    update.nVersion = CProUpRegTx::PQ_VERSION;
    update.pubKeyOperator.SetNull();
    const uint256 registration_hash{::SerializeHash(registration)};
    const uint256 update_hash{::SerializeHash(update)};
    registration.pqVotingPublicKey.back() ^= 1;
    update.pqVotingPublicKey.back() ^= 1;
    BOOST_CHECK(::SerializeHash(registration) != registration_hash);
    BOOST_CHECK(::SerializeHash(update) != update_hash);
    registration.pqVotingPublicKey.back() ^= 1;
    update.pqVotingPublicKey.back() ^= 1;
    registration.vchSig.assign(65, 1);
    update.vchSig.assign(65, 2);
    BOOST_CHECK(::SerializeHash(registration) == registration_hash);
    BOOST_CHECK(::SerializeHash(update) == update_hash);

    TxValidationState valid_registration;
    BOOST_CHECK(registration.IsTriviallyValid(valid_registration, true));
    registration.pqVotingPublicKey = {};
    TxValidationState null_registration;
    BOOST_CHECK(!registration.IsTriviallyValid(null_registration, true));
    BOOST_CHECK_EQUAL(null_registration.GetRejectReason(), "bad-protx-pq-voting-key");
    update.pqVotingPublicKey = {};
    TxValidationState revoked_update;
    BOOST_CHECK(update.IsTriviallyValid(revoked_update, true));
}

BOOST_AUTO_TEST_CASE(pq_voting_provider_roundtrip_and_truncation)
{
    CProRegTx registration;
    registration.nVersion = CProRegTx::PQ_VERSION;
    registration.pqVotingPublicKey.fill(0x51);
    CProUpRegTx update;
    update.nVersion = CProUpRegTx::PQ_VERSION;
    update.pqVotingPublicKey.fill(0x61);
    const auto check = []<typename Payload>(const Payload& payload) {
        const auto bytes{Encoded(payload)};
        CDataStream full{bytes, SER_NETWORK, PROTOCOL_VERSION};
        Payload decoded;
        full >> decoded;
        BOOST_CHECK(full.empty());
        BOOST_CHECK(decoded.pqVotingPublicKey == payload.pqVotingPublicKey);
        for (std::size_t size = 0; size < bytes.size(); ++size) {
            CDataStream truncated{std::vector<std::byte>(bytes.begin(), bytes.begin() + size),
                                  SER_NETWORK, PROTOCOL_VERSION};
            BOOST_CHECK_THROW(truncated >> decoded, std::ios_base::failure);
        }
    };
    check(registration);
    check(update);
}

BOOST_AUTO_TEST_CASE(pq_voting_record_lifecycle_and_overflow)
{
    llmq::pq::VotingKeyRecord record;
    llmq::pq::GlobalPublicKey first{};
    first.fill(0x41);
    llmq::pq::GlobalPublicKey second{};
    second.fill(0x42);
    BOOST_CHECK(record.IsStructurallyValid());
    BOOST_CHECK(!record.HasActiveKey());
    BOOST_REQUIRE(record.UpdatePublicKey({}, 100));
    BOOST_CHECK_EQUAL(record.key_version, 0);
    BOOST_CHECK_EQUAL(record.activated_height, -1);
    BOOST_REQUIRE(record.UpdatePublicKey(first, 101));
    BOOST_CHECK(record.HasActiveKey());
    BOOST_CHECK_EQUAL(record.key_version, 1);
    BOOST_REQUIRE(record.UpdatePublicKey(first, 102));
    BOOST_CHECK_EQUAL(record.activated_height, 101);
    BOOST_REQUIRE(record.UpdatePublicKey(second, 103));
    BOOST_REQUIRE(record.UpdatePublicKey(first, 104));
    BOOST_CHECK_EQUAL(record.key_version, 3);
    BOOST_CHECK_EQUAL(record.activated_height, 104);
    BOOST_REQUIRE(record.UpdatePublicKey({}, 105));
    BOOST_CHECK(record.IsStructurallyValid());
    BOOST_CHECK(!record.HasActiveKey());
    BOOST_CHECK_EQUAL(record.key_version, 4);
    BOOST_REQUIRE(record.UpdatePublicKey({}, 106));
    BOOST_CHECK_EQUAL(record.activated_height, 105);
    BOOST_REQUIRE(record.UpdatePublicKey(first, 107));
    BOOST_CHECK_EQUAL(record.key_version, 5);
    record.key_version = std::numeric_limits<uint32_t>::max();
    const auto exhausted{record};
    BOOST_REQUIRE(record.UpdatePublicKey(first, 108));
    BOOST_CHECK(!record.UpdatePublicKey(second, 108));
    BOOST_CHECK(!record.UpdatePublicKey({}, 108));
    BOOST_CHECK(!record.UpdatePublicKey(first, -1));
    BOOST_CHECK(record == exhausted);
}

BOOST_AUTO_TEST_CASE(pq_voting_dmn_encoding_preserves_legacy_and_operator_reset)
{
    CDeterministicMNState state;
    state.nRegisteredHeight = 10;
    state.nCollateralHeight = 9;
    state.keyIDOwner = NonNullKeyID(1);
    state.keyIDVoting = NonNullKeyID(2);
    state.vchNEVMAddress = {1, 2, 3};
    for (int version : {1, 2, 3, 4}) {
        state.nVersion = version;
        const auto legacy_bytes{LegacyStateBytes(state)};
        BOOST_CHECK(Encoded(state) == legacy_bytes);
        CDataStream diagnostic{SER_DISK, PROTOCOL_VERSION};
        state.SerializePQStateDiagnosticV1(diagnostic);
        BOOST_CHECK(std::vector<std::byte>(diagnostic.begin(), diagnostic.end()) == legacy_bytes);
        CDeterministicMNState decoded;
        decoded.pqVotingKey.public_key[0] = 1;
        decoded.pqVotingKey.key_version = 1;
        decoded.pqVotingKey.activated_height = 1;
        CDataStream stream{legacy_bytes, SER_DISK, PROTOCOL_VERSION};
        stream >> decoded;
        BOOST_CHECK(stream.empty());
        BOOST_CHECK(decoded.pqVotingKey == llmq::pq::VotingKeyRecord{});
        BOOST_CHECK(Encoded(decoded) == legacy_bytes);
    }

    const auto legacy{state};
    llmq::pq::GlobalPublicKey key{};
    key.fill(0x73);
    BOOST_REQUIRE(state.pqVotingKey.UpdatePublicKey(key, 20));
    const auto active{state};
    state.ResetOperatorFields();
    BOOST_CHECK(state.pqVotingKey == active.pqVotingKey);
    BOOST_CHECK_EQUAL(state.nVersion, CProUpServTx::LEGACY_BLS_VERSION);
    for (bool revoke : {false, true}) {
        if (revoke) BOOST_REQUIRE(state.pqVotingKey.UpdatePublicKey({}, 21));
        CDataStream stream{SER_DISK, PROTOCOL_VERSION};
        stream << state;
        int32_t marker;
        uint16_t schema;
        stream >> marker >> schema;
        BOOST_CHECK_EQUAL(marker, -1);
        BOOST_CHECK_EQUAL(schema, 1);
        CDataStream roundtrip{Encoded(state), SER_DISK, PROTOCOL_VERSION};
        CDeterministicMNState decoded;
        roundtrip >> decoded;
        BOOST_CHECK(roundtrip.empty());
        BOOST_CHECK(Encoded(decoded) == Encoded(state));
        BOOST_CHECK(decoded.pqVotingKey == state.pqVotingKey);
        BOOST_CHECK_EQUAL(decoded.pqVotingKey.HasActiveKey(), !revoke);
    }

    CDeterministicMNStateDiff forward{legacy, active};
    BOOST_CHECK_EQUAL(forward.fields, CDeterministicMNStateDiff::Field_pqVotingKey);
    CDataStream diff_stream{SER_DISK, PROTOCOL_VERSION};
    diff_stream << forward;
    CDeterministicMNStateDiff decoded_diff;
    diff_stream >> decoded_diff;
    auto restored{legacy};
    decoded_diff.ApplyToState(restored);
    BOOST_CHECK(Encoded(restored) == Encoded(active));
    CDeterministicMNStateDiff inverse{active, legacy};
    CDataStream inverse_stream{SER_DISK, PROTOCOL_VERSION};
    inverse_stream << inverse;
    inverse_stream >> decoded_diff;
    decoded_diff.ApplyToState(restored);
    BOOST_CHECK(Encoded(restored) == LegacyStateBytes(legacy));
}

BOOST_AUTO_TEST_CASE(pq_voting_dmn_encoding_rejects_noncanonical_records)
{
    CDeterministicMNState state;
    state.pqVotingKey.public_key[0] = 1;
    BOOST_CHECK(!state.pqVotingKey.IsStructurallyValid());
    BOOST_CHECK_THROW(Encoded(state), std::ios_base::failure);
    state.pqVotingKey.key_version = 1;
    BOOST_CHECK_THROW(Encoded(state), std::ios_base::failure);
    state.pqVotingKey.activated_height = 10;
    const auto bytes{Encoded(state)};
    for (std::size_t size = 0; size < bytes.size(); ++size) {
        CDataStream truncated{std::vector<std::byte>(bytes.begin(), bytes.begin() + size),
                              SER_DISK, PROTOCOL_VERSION};
        CDeterministicMNState decoded;
        BOOST_CHECK_THROW(truncated >> decoded, std::ios_base::failure);
    }
    auto unknown_schema{bytes};
    unknown_schema[4] = std::byte{2};
    CDataStream unknown{unknown_schema, SER_DISK, PROTOCOL_VERSION};
    CDeterministicMNState decoded;
    BOOST_CHECK_THROW(unknown >> decoded, std::ios_base::failure);
    CDataStream empty_extended{SER_DISK, PROTOCOL_VERSION};
    empty_extended << int32_t{-1} << uint16_t{1};
    state.pqVotingKey = {};
    empty_extended << state << state.pqVotingKey;
    BOOST_CHECK_THROW(empty_extended >> decoded, std::ios_base::failure);
    auto negative_version{LegacyStateBytes(state)};
    negative_version[0] = std::byte{0xfe};
    negative_version[1] = std::byte{0xff};
    negative_version[2] = std::byte{0xff};
    negative_version[3] = std::byte{0xff};
    CDataStream invalid_version{negative_version, SER_DISK, PROTOCOL_VERSION};
    BOOST_CHECK_THROW(invalid_version >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(pq_service_round_trip_and_hash_excludes_signature)
{
    CProUpServTx payload;
    payload.nVersion = CProUpServTx::PQ_VERSION;
    payload.proTxHash = NonNullHash(8);
    payload.inputsHash = NonNullHash(9);
    payload.globalKeyVersion = 7;
    payload.pqSig[0] = 1;
    payload.vchNEVMAddress.assign(llmq::pq::NEVM_ADDRESS_SIZE, 0x42);

    const uint256 hash = ::SerializeHash(payload);
    payload.pqSig.back() = 2;
    BOOST_CHECK(::SerializeHash(payload) == hash);
    payload.globalKeyVersion++;
    BOOST_CHECK(::SerializeHash(payload) != hash);
    payload.globalKeyVersion--;

    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << payload;
    CProUpServTx decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(decoded.nVersion, CProUpServTx::PQ_VERSION);
    BOOST_CHECK_EQUAL(decoded.globalKeyVersion, payload.globalKeyVersion);
    BOOST_CHECK(decoded.pqSig == payload.pqSig);
    BOOST_CHECK(decoded.vchNEVMAddress == payload.vchNEVMAddress);
}

BOOST_AUTO_TEST_CASE(pq_revocation_round_trip_and_legacy_width)
{
    CProUpRevTx pq;
    pq.nVersion = CProUpRevTx::PQ_VERSION;
    pq.proTxHash = NonNullHash(10);
    pq.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
    pq.inputsHash = NonNullHash(11);
    pq.globalKeyVersion = 3;
    pq.pqSig[0] = 1;

    CProUpRevTx legacy = pq;
    legacy.nVersion = CProUpRevTx::BASIC_BLS_VERSION;
    std::array<uint8_t, CLegacyBLSSignature::SERIALIZED_SIZE> signature{};
    signature[0] = 1;
    BOOST_REQUIRE(legacy.legacySig.SetBytes(signature));

    const std::size_t common_size = sizeof(uint16_t) + 32 + sizeof(uint16_t) + 32;
    BOOST_CHECK_EQUAL(WireSize(legacy),
                      common_size + CLegacyBLSSignature::SERIALIZED_SIZE);
    BOOST_CHECK_EQUAL(WireSize(pq),
                      common_size + sizeof(uint32_t) +
                          llmq::pq::GLOBAL_SIGNATURE_SIZE);

    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << pq;
    CProUpRevTx decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(decoded.globalKeyVersion, pq.globalKeyVersion);
    BOOST_CHECK(decoded.pqSig == pq.pqSig);
}

BOOST_AUTO_TEST_SUITE_END()
