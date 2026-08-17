// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_PROVIDERTX_H
#define SYSCOIN_EVO_PQ_PROVIDERTX_H

#include <llmq/pq_chainlock_types.h>

#include <primitives/transaction.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <array>
#include <ios>
#include <optional>
#include <string_view>
#include <vector>

namespace llmq::pq {

inline constexpr int32_t PQ_GLOBAL_KEY_TX_VERSION{SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY};
inline constexpr uint16_t PQ_GLOBAL_KEY_PAYLOAD_VERSION{1};
inline constexpr std::size_t COMPACT_ECDSA_SIGNATURE_SIZE{65};
inline constexpr std::string_view PQ_GLOBAL_OWNER_REGISTER_DOMAIN{
    "SYS_PQ_GLOBAL_OWNER_REGISTER_V1"};

using CompactECDSAOwnerSignature =
    std::array<uint8_t, COMPACT_ECDSA_SIGNATURE_SIZE>;

enum class GlobalKeyOperation : uint8_t {
    INITIAL = 1,
    ROTATE = 2,
};

/**
 * Register, recover, or rotate the long-lived FIPS 205 operator key.
 *
 * The candidate always has activated_height == 0. Consensus derives the
 * activation height from the containing block, preventing a signer from
 * choosing state-transition metadata outside the signed transaction.
 */
struct GlobalKeyTxPayload {
    static constexpr int32_t SPECIALTX_TYPE{PQ_GLOBAL_KEY_TX_VERSION};
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(uint8_t) + 32 +
        sizeof(uint16_t) * 2 + sizeof(uint32_t) * 2 + GLOBAL_PUBLIC_KEY_SIZE +
        ChildKeyTreeCommitment::WIRE_SIZE + 32 +
        COMPACT_ECDSA_SIGNATURE_SIZE + GLOBAL_SIGNATURE_SIZE};

    uint16_t version{PQ_GLOBAL_KEY_PAYLOAD_VERSION};
    GlobalKeyOperation operation{GlobalKeyOperation::INITIAL};
    uint256 pro_tx_hash;
    GlobalKeyRecord candidate;
    uint256 transaction_inputs_hash;
    /** Required for INITIAL registration/recovery; verified against the owner. */
    CompactECDSAOwnerSignature owner_authorization{};
    /** New-key PoP for INITIAL/recovery, current-key auth for ROTATE. */
    GlobalSignature authorization{};

    SERIALIZE_METHODS(GlobalKeyTxPayload, obj)
    {
        SER_WRITE(obj, if (!obj.IsTriviallyValid(SPECIALTX_TYPE)) {
            throw std::ios_base::failure("non-canonical PQ global-key payload");
        });
        uint8_t operation{static_cast<uint8_t>(obj.operation)};
        READWRITE(obj.version, operation, obj.pro_tx_hash, obj.candidate,
                  obj.transaction_inputs_hash, obj.owner_authorization,
                  obj.authorization);
        SER_READ(obj, obj.operation = static_cast<GlobalKeyOperation>(operation));
        SER_READ(obj, if (!obj.IsTriviallyValid(SPECIALTX_TYPE)) {
            throw std::ios_base::failure("non-canonical PQ global-key payload");
        });
    }

    [[nodiscard]] bool IsTriviallyValid(int32_t transaction_version) const noexcept;
    friend bool operator==(const GlobalKeyTxPayload&, const GlobalKeyTxPayload&) = default;
};

/**
 * Digest for the compact ECDSA signature in an INITIAL tx86.
 *
 * The signature bytes are excluded to avoid recursion. Consensus must first
 * check transaction_inputs_hash against CalcTxInputsHash, then verify this
 * digest against keyIDOwner from the previous deterministic-MN snapshot.
 */
[[nodiscard]] std::optional<uint256>
GetGlobalOwnerRegistrationAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyTxPayload& payload);
[[nodiscard]] bool VerifyGlobalOwnerRegistrationAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyTxPayload& payload,
    const CKeyID& previous_owner_key_id);

static_assert(GlobalKeyTxPayload::WIRE_SIZE == 8'112);

/** Strict decoders reject truncation, oversize input, and trailing bytes. */
[[nodiscard]] bool DecodeGlobalKeyTxPayload(
    const std::vector<unsigned char>& encoded,
    GlobalKeyTxPayload& payload) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_PROVIDERTX_H
