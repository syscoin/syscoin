// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_GLOBAL_AUTH_H
#define SYSCOIN_LLMQ_PQ_GLOBAL_AUTH_H

#include <llmq/pq_chainlock_types.h>

#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

class CService;

namespace llmq::pq {

inline constexpr uint16_t PROVIDER_SERVICE_AUTH_VERSION{1};
inline constexpr uint16_t PROVIDER_REVOKE_AUTH_VERSION{1};
inline constexpr uint16_t MNAUTH_TRANSCRIPT_VERSION{1};
inline constexpr uint16_t GOVERNANCE_AUTHORIZATION_VERSION{1};
inline constexpr uint16_t MAX_PROVIDER_REVOCATION_REASON{3};
inline constexpr std::size_t MAX_PROVIDER_PAYOUT_SCRIPT_SIZE{10'000};
inline constexpr std::size_t NEVM_ADDRESS_SIZE{20};

inline constexpr std::string_view PROVIDER_SERVICE_DOMAIN{"SYS_PQ_PROVIDER_SERVICE_V1"};
inline constexpr std::string_view PROVIDER_REVOKE_DOMAIN{"SYS_PQ_PROVIDER_REVOKE_V1"};
inline constexpr std::string_view MNAUTH_DOMAIN{"SYS_PQ_MNAUTH_V1"};
inline constexpr std::string_view GOVERNANCE_TRIGGER_DOMAIN{
    "SYS_PQ_GOV_TRIGGER_V1"};
inline constexpr std::string_view GOVERNANCE_VOTE_DOMAIN{
    "SYS_PQ_GOV_VOTE_V1"};
inline constexpr std::string_view GOVERNANCE_PROPOSAL_VOTE_DOMAIN{
    "SYS_PQ_GOV_PROPOSAL_VOTE_V1"};

enum class GlobalAuthPurpose : uint8_t {
    GLOBAL_REGISTRATION = 0,
    GLOBAL_ROTATION = 1,
    PROVIDER_SERVICE = 2,
    PROVIDER_REVOKE = 3,
    MNAUTH = 4,
    GOVERNANCE_TRIGGER = 5,
    GOVERNANCE_VOTE = 6,
    GOVERNANCE_PROPOSAL_VOTE = 8,
};

enum class GovernanceAuthPurpose : uint8_t {
    TRIGGER = 0,
    TRIGGER_VOTE = 1,
    PROPOSAL_VOTE = 2,
};

/**
 * Fixed authorization carried in the existing governance signature field.
 *
 * The signed block identifies the immutable PQ-registry snapshot containing
 * the exact historical global key. Branch validation also requires this key
 * version to remain current because an off-chain signature has no immutable
 * evidence that it was produced before a later rotation or revocation.
 */
struct GovernanceAuthorization {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(int32_t) + 32 * 2 +
        sizeof(uint32_t) + GLOBAL_SIGNATURE_SIZE};

    uint16_t version{GOVERNANCE_AUTHORIZATION_VERSION};
    int32_t signed_height{-1};
    uint256 signed_block_hash;
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    GlobalSignature signature{};

    SERIALIZE_METHODS(GovernanceAuthorization, obj)
    {
        READWRITE(obj.version, obj.signed_height, obj.signed_block_hash,
                  obj.pro_tx_hash, obj.global_key_version, obj.signature);
    }

    [[nodiscard]] bool IsHeaderStructurallyValid() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const GovernanceAuthorization&,
                           const GovernanceAuthorization&) = default;
};

static_assert(GovernanceAuthorization::WIRE_SIZE == 7'930);

/** Exact fixed-size codec for the legacy vector-valued signature field. */
[[nodiscard]] bool EncodeGovernanceAuthorization(
    const GovernanceAuthorization& authorization,
    std::vector<unsigned char>& encoded) noexcept;
[[nodiscard]] bool DecodeGovernanceAuthorization(
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization) noexcept;

[[nodiscard]] std::optional<uint256> GetGovernanceAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& historical_key,
    const GovernanceAuthorization& authorization,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash);
[[nodiscard]] bool VerifyGovernanceAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& historical_key,
    const GovernanceAuthorization& authorization,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash);

/** Off-chain authorization is valid only while its signing key is current. */
[[nodiscard]] bool GovernanceAuthorizationMatchesCurrentKey(
    const GovernanceAuthorization& authorization,
    const GlobalKeyRecord& current_key) noexcept;

/**
 * Return the exact FIPS 205 context for a global-key authorization purpose.
 *
 * The context is deliberately the same versioned ASCII tag used by the
 * canonical hash transcript. Callers must use this helper when signing and
 * must not construct a context from user-provided text.
 */
[[nodiscard]] std::span<const uint8_t> GetGlobalAuthContext(
    GlobalAuthPurpose purpose) noexcept;

/**
 * A provider payload carries an unactivated candidate. Consensus derives the
 * activation height from the containing block only after authorization.
 */
[[nodiscard]] bool IsGlobalKeyCandidateStructurallyValid(
    const GlobalKeyRecord& candidate) noexcept;

/** A current authorization key must already be part of deterministic MN state. */
[[nodiscard]] bool IsStoredGlobalKeyRecordStructurallyValid(
    const GlobalKeyRecord& record) noexcept;

/**
 * Initial-key proof of possession. It supplements, but never replaces, the
 * existing collateral/owner authorization for provider registration.
 */
[[nodiscard]] std::optional<uint256> GetGlobalRegistrationAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash);
[[nodiscard]] bool VerifyGlobalKeyRegistration(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& signature);

/** Recovery uses the registration transcript but requires exact +1 version. */
[[nodiscard]] std::optional<uint256> GetGlobalRecoveryAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash);
[[nodiscard]] bool VerifyGlobalKeyRecovery(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& signature);

/** Rotation is authorized by the currently stored global key. */
[[nodiscard]] std::optional<uint256> GetGlobalRotationAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash);
[[nodiscard]] bool VerifyGlobalKeyRotation(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& signature);

enum class EndpointNetwork : uint8_t {
    IPV4 = 1,
    IPV6 = 2,
    TOR_V3 = 3,
    I2P = 4,
    CJDNS = 5,
};

/** Fixed, serialization-version-independent service identity. */
struct NetworkEndpoint {
    EndpointNetwork network{EndpointNetwork::IPV4};
    uint8_t address_size{0};
    std::array<uint8_t, 32> address{};
    uint16_t port{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const NetworkEndpoint&, const NetworkEndpoint&) = default;
};

/** Convert CService to fixed network bytes; no DNS or text formatting is used. */
[[nodiscard]] std::optional<NetworkEndpoint> MakeNetworkEndpoint(
    const CService& service) noexcept;

struct ProviderServiceAuthorization {
    uint16_t version{PROVIDER_SERVICE_AUTH_VERSION};
    uint16_t payload_version{0};
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    NetworkEndpoint service;
    std::vector<uint8_t> operator_payout_script;
    std::optional<std::array<uint8_t, NEVM_ADDRESS_SIZE>> nevm_address;
    uint256 transaction_inputs_hash;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const ProviderServiceAuthorization&,
                           const ProviderServiceAuthorization&) = default;
};

[[nodiscard]] std::optional<uint256> GetProviderServiceAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderServiceAuthorization& authorization);
[[nodiscard]] bool VerifyProviderServiceAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderServiceAuthorization& authorization,
    const GlobalSignature& signature);

struct ProviderRevokeAuthorization {
    uint16_t version{PROVIDER_REVOKE_AUTH_VERSION};
    uint16_t payload_version{0};
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    uint16_t reason{0};
    uint256 transaction_inputs_hash;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const ProviderRevokeAuthorization&,
                           const ProviderRevokeAuthorization&) = default;
};

[[nodiscard]] std::optional<uint256> GetProviderRevokeAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderRevokeAuthorization& authorization);
[[nodiscard]] bool VerifyProviderRevokeAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderRevokeAuthorization& authorization,
    const GlobalSignature& signature);

enum class MNAUTHSignerRole : uint8_t {
    INITIATOR = 0,
    RESPONDER = 1,
};

/**
 * Canonical peer-authentication transcript.
 *
 * Endpoints are the deterministic masternode service identities, not an
 * observer's potentially NAT-rewritten socket address. Cookies are admission
 * tokens, challenges are the per-connection VERSION challenges, and nonces are
 * the VERSION nonces. Naming by connection role makes both peers serialize the
 * same bytes despite having opposite local/inbound views.
 */
struct MNAUTHTranscript {
    uint16_t version{MNAUTH_TRANSCRIPT_VERSION};
    std::array<uint8_t, 4> network_magic{};
    uint256 initiator_pro_tx_hash;
    uint256 responder_pro_tx_hash;
    uint32_t initiator_global_key_version{0};
    uint32_t responder_global_key_version{0};
    uint256 initiator_cookie;
    uint256 responder_cookie;
    uint256 initiator_challenge;
    uint256 responder_challenge;
    uint64_t initiator_version_nonce{0};
    uint64_t responder_version_nonce{0};
    uint32_t initiator_protocol_version{0};
    uint32_t responder_protocol_version{0};
    uint64_t initiator_service_flags{0};
    uint64_t responder_service_flags{0};
    NetworkEndpoint initiator_endpoint;
    NetworkEndpoint responder_endpoint;
    MNAUTHSignerRole signer_role{MNAUTHSignerRole::INITIATOR};

    [[nodiscard]] bool IsStructurallyValid(uint64_t required_service_flags) const noexcept;
    friend bool operator==(const MNAUTHTranscript&, const MNAUTHTranscript&) = default;
};

[[nodiscard]] std::optional<uint256> GetMNAUTHAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    const MNAUTHTranscript& transcript,
    uint64_t required_service_flags);
[[nodiscard]] bool VerifyMNAUTHAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    const MNAUTHTranscript& transcript,
    uint64_t required_service_flags,
    const GlobalSignature& signature);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_GLOBAL_AUTH_H
