// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_providertx.h>

#include <llmq/pq_global_auth.h>
#include <hash.h>
#include <messagesigner.h>
#include <span.h>
#include <streams.h>
#include <version.h>

#include <algorithm>
#include <utility>

namespace llmq::pq {
namespace {

bool HasAuthorization(const GlobalSignature& signature) noexcept
{
    return std::any_of(signature.begin(), signature.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool IsAllZero(const CompactECDSAOwnerSignature& signature) noexcept
{
    return std::all_of(signature.begin(), signature.end(),
                       [](uint8_t byte) { return byte == 0; });
}

bool IsStructurallyCanonicalCompactSignature(
    const CompactECDSAOwnerSignature& signature) noexcept
{
    static constexpr std::array<uint8_t, 32> SECP256K1_ORDER{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    static constexpr std::array<uint8_t, 32> SECP256K1_HALF_ORDER{
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};
    const auto r_begin = signature.begin() + 1;
    const auto s_begin = r_begin + 32;
    const bool r_nonzero = std::any_of(
        r_begin, s_begin, [](uint8_t byte) { return byte != 0; });
    const bool s_nonzero = std::any_of(
        s_begin, signature.end(), [](uint8_t byte) { return byte != 0; });
    const bool r_below_order = std::lexicographical_compare(
        r_begin, s_begin, SECP256K1_ORDER.begin(), SECP256K1_ORDER.end());
    const bool s_above_half_order = std::lexicographical_compare(
        SECP256K1_HALF_ORDER.begin(), SECP256K1_HALF_ORDER.end(),
        s_begin, signature.end());
    // Bitcoin compact signatures encode recovery/compression in 27..34.
    // Rejecting high-S prevents an otherwise valid owner authorization from
    // giving the same registration two transaction IDs.
    return signature[0] >= 27 && signature[0] <= 34 && r_nonzero &&
           s_nonzero && r_below_order && !s_above_half_order;
}

template <typename Payload>
bool DecodeStrict(const std::vector<unsigned char>& encoded,
                  std::size_t minimum_size,
                  std::size_t maximum_size,
                  Payload& output) noexcept
{
    if (encoded.size() < minimum_size || encoded.size() > maximum_size) return false;
    try {
        CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
        Payload candidate;
        stream >> candidate;
        // Generic special-tx extraction does not reject suffix bytes. Consensus
        // must use this decoder so a payload has exactly one wire encoding.
        if (!stream.empty()) return false;
        output = std::move(candidate);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace

bool GlobalKeyTxPayload::IsTriviallyValid(int32_t transaction_version) const noexcept
{
    if (transaction_version != SPECIALTX_TYPE ||
        version != PQ_GLOBAL_KEY_PAYLOAD_VERSION || pro_tx_hash.IsNull() ||
        transaction_inputs_hash.IsNull() ||
        !IsGlobalKeyCandidateStructurallyValid(candidate) ||
        !HasAuthorization(authorization)) {
        return false;
    }
    if (operation == GlobalKeyOperation::INITIAL) {
        // Version one is first registration. Higher versions are the same
        // owner + new-key-PoP transcript used to recover a revoked operator;
        // registry state decides whether that recovery is currently allowed.
        return IsStructurallyCanonicalCompactSignature(owner_authorization);
    }
    if (operation == GlobalKeyOperation::ROTATE) {
        return candidate.key_version > 1 && IsAllZero(owner_authorization);
    }
    return false;
}

std::optional<uint256> GetGlobalOwnerRegistrationAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyTxPayload& payload)
{
    if (genesis_hash.IsNull() ||
        payload.version != PQ_GLOBAL_KEY_PAYLOAD_VERSION ||
        payload.operation != GlobalKeyOperation::INITIAL ||
        payload.pro_tx_hash.IsNull() ||
        payload.transaction_inputs_hash.IsNull() ||
        !IsGlobalKeyCandidateStructurallyValid(payload.candidate)) {
        return std::nullopt;
    }

    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PQ_GLOBAL_OWNER_REGISTER_DOMAIN);
    writer << genesis_hash << PQ_GLOBAL_KEY_TX_VERSION << payload.version
           << static_cast<uint8_t>(payload.operation) << payload.pro_tx_hash
           << payload.candidate.version << payload.candidate.profile
           << payload.candidate.key_version << payload.candidate.public_key
           << payload.candidate.child_key_commitment
           << payload.candidate.activated_height
           << payload.transaction_inputs_hash;
    return writer.GetHash();
}

bool VerifyGlobalOwnerRegistrationAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyTxPayload& payload,
    const CKeyID& previous_owner_key_id)
{
    const auto digest = GetGlobalOwnerRegistrationAuthorizationHash(
        genesis_hash, payload);
    if (!digest || !payload.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION)) {
        return false;
    }
    const std::vector<unsigned char> signature{
        payload.owner_authorization.begin(),
        payload.owner_authorization.end()};
    return CHashSigner::VerifyHash(*digest, previous_owner_key_id, signature);
}

bool DecodeGlobalKeyTxPayload(const std::vector<unsigned char>& encoded,
                              GlobalKeyTxPayload& payload) noexcept
{
    return DecodeStrict(encoded, GlobalKeyTxPayload::WIRE_SIZE,
                        GlobalKeyTxPayload::WIRE_SIZE, payload);
}

} // namespace llmq::pq
