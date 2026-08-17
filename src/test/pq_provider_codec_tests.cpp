// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/providertx.h>
#include <llmq/pq_global_auth.h>

#include <clientversion.h>
#include <hash.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>

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

} // namespace

BOOST_AUTO_TEST_SUITE(pq_provider_codec_tests)

BOOST_AUTO_TEST_CASE(post_anchor_registrar_codecs_omit_legacy_operator_key)
{
    CProRegTx pq_registration;
    pq_registration.nVersion = CProRegTx::PQ_VERSION;
    pq_registration.collateralOutpoint.hash = NonNullHash(1);
    pq_registration.keyIDOwner = NonNullKeyID(2);
    pq_registration.keyIDVoting = NonNullKeyID(3);
    pq_registration.inputsHash = NonNullHash(4);

    CProRegTx legacy_registration = pq_registration;
    legacy_registration.nVersion = CProRegTx::BASIC_BLS_VERSION;
    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key{};
    operator_key[0] = 1;
    BOOST_REQUIRE(legacy_registration.pubKeyOperator.SetBytes(operator_key));
    BOOST_CHECK_EQUAL(WireSize(legacy_registration) - WireSize(pq_registration),
                      CLegacyBLSPublicKey::SERIALIZED_SIZE);

    CProUpRegTx pq_update;
    pq_update.nVersion = CProUpRegTx::PQ_VERSION;
    pq_update.proTxHash = NonNullHash(5);
    pq_update.keyIDVoting = NonNullKeyID(6);
    pq_update.inputsHash = NonNullHash(7);
    CProUpRegTx legacy_update = pq_update;
    legacy_update.nVersion = CProUpRegTx::BASIC_BLS_VERSION;
    BOOST_REQUIRE(legacy_update.pubKeyOperator.SetBytes(operator_key));
    BOOST_CHECK_EQUAL(WireSize(legacy_update) - WireSize(pq_update),
                      CLegacyBLSPublicKey::SERIALIZED_SIZE);
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
