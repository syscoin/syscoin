// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_global_auth.h>

#include <crypto/slhdsa/slhdsa.h>
#include <hash.h>
#include <netaddress.h>
#include <span.h>
#include <streams.h>
#include <version.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

template <typename Range>
bool HasNonZeroByte(const Range& range) noexcept
{
    return std::any_of(range.begin(), range.end(), [](uint8_t byte) { return byte != 0; });
}

std::size_t ExpectedAddressSize(EndpointNetwork network) noexcept
{
    switch (network) {
    case EndpointNetwork::IPV4:
        return 4;
    case EndpointNetwork::IPV6:
    case EndpointNetwork::CJDNS:
        return 16;
    case EndpointNetwork::TOR_V3:
    case EndpointNetwork::I2P:
        return 32;
    }
    return 0;
}

void WriteEndpoint(CHashWriter& writer, const NetworkEndpoint& endpoint)
{
    writer << static_cast<uint8_t>(endpoint.network) << endpoint.address_size
           << endpoint.address << endpoint.port;
}

uint256 PublicKeyHash(const GlobalKeyRecord& record)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << record.version << record.profile << record.key_version
           << record.public_key << record.child_key_commitment
           << record.activated_height;
    return writer.GetHash();
}

bool VerifyDigest(const GlobalKeyRecord& key,
                  GlobalAuthPurpose purpose,
                  const uint256& digest,
                  const GlobalSignature& signature) noexcept
{
    if (!HasNonZeroByte(signature)) return false;
    return slhdsa::Verify(key.public_key,
                         std::span<const uint8_t>{digest.begin(), digest.size()},
                         GetGlobalAuthContext(purpose), signature);
}

bool RecordsMatchMNAUTH(const GlobalKeyRecord& initiator_key,
                        const GlobalKeyRecord& responder_key,
                        const MNAUTHTranscript& transcript) noexcept
{
    return IsStoredGlobalKeyRecordStructurallyValid(initiator_key) &&
           IsStoredGlobalKeyRecordStructurallyValid(responder_key) &&
           transcript.initiator_global_key_version == initiator_key.key_version &&
           transcript.responder_global_key_version == responder_key.key_version;
}

bool IsAuthorizedCommitmentSuccessor(
    const ChildKeyTreeCommitment& current,
    const ChildKeyTreeCommitment& candidate) noexcept
{
    if (candidate == current) return true;
    return CanAdvanceChildKeyTreeGeneration(current.generation) &&
           candidate.generation == current.generation + 1 &&
           candidate.tree_id != current.tree_id &&
           candidate.root != current.root;
}

} // namespace

std::span<const uint8_t> GetGlobalAuthContext(GlobalAuthPurpose purpose) noexcept
{
    std::string_view context;
    switch (purpose) {
    case GlobalAuthPurpose::GLOBAL_REGISTRATION:
        context = GLOBAL_REGISTER_DOMAIN;
        break;
    case GlobalAuthPurpose::GLOBAL_ROTATION:
        context = GLOBAL_ROTATE_DOMAIN;
        break;
    case GlobalAuthPurpose::PROVIDER_SERVICE:
        context = PROVIDER_SERVICE_DOMAIN;
        break;
    case GlobalAuthPurpose::PROVIDER_REVOKE:
        context = PROVIDER_REVOKE_DOMAIN;
        break;
    case GlobalAuthPurpose::MNAUTH:
        context = MNAUTH_DOMAIN;
        break;
    case GlobalAuthPurpose::GOVERNANCE_TRIGGER:
        context = GOVERNANCE_TRIGGER_DOMAIN;
        break;
    case GlobalAuthPurpose::GOVERNANCE_VOTE:
        context = GOVERNANCE_VOTE_DOMAIN;
        break;
    case GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE:
        context = GOVERNANCE_PROPOSAL_VOTE_DOMAIN;
        break;
    }
    return {reinterpret_cast<const uint8_t*>(context.data()), context.size()};
}

static_assert(GLOBAL_REGISTER_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(GLOBAL_ROTATE_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(PROVIDER_SERVICE_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(PROVIDER_REVOKE_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(MNAUTH_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(GOVERNANCE_TRIGGER_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(GOVERNANCE_VOTE_DOMAIN.size() <= slhdsa::MAX_CONTEXT_SIZE);
static_assert(GOVERNANCE_PROPOSAL_VOTE_DOMAIN.size() <=
              slhdsa::MAX_CONTEXT_SIZE);

bool GovernanceAuthorization::IsHeaderStructurallyValid() const noexcept
{
    return version == GOVERNANCE_AUTHORIZATION_VERSION &&
           signed_height >= 0 && !signed_block_hash.IsNull() &&
           !pro_tx_hash.IsNull() && global_key_version != 0;
}

bool GovernanceAuthorization::IsStructurallyValid() const noexcept
{
    return IsHeaderStructurallyValid() && HasNonZeroByte(signature);
}

bool EncodeGovernanceAuthorization(
    const GovernanceAuthorization& authorization,
    std::vector<unsigned char>& encoded) noexcept
{
    encoded.clear();
    if (!authorization.IsStructurallyValid()) return false;
    try {
        CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
        stream << authorization;
        if (stream.size() != GovernanceAuthorization::WIRE_SIZE) return false;
        encoded.resize(stream.size());
        std::memcpy(encoded.data(), stream.data(), stream.size());
        return true;
    } catch (const std::exception&) {
        encoded.clear();
        return false;
    }
}

bool DecodeGovernanceAuthorization(
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization) noexcept
{
    if (encoded.size() != GovernanceAuthorization::WIRE_SIZE) return false;
    try {
        SpanReader stream{SER_NETWORK, PROTOCOL_VERSION,
                          Span<const unsigned char>{encoded.data(),
                                                    encoded.size()}};
        GovernanceAuthorization candidate;
        stream >> candidate;
        if (!stream.empty() || !candidate.IsStructurallyValid()) return false;
        authorization = std::move(candidate);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::optional<uint256> GetGovernanceAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& signing_key,
    const GovernanceAuthorization& authorization,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash)
{
    if (genesis_hash.IsNull() || unsigned_payload_hash.IsNull() ||
        !IsStoredGlobalKeyRecordStructurallyValid(signing_key) ||
        !authorization.IsHeaderStructurallyValid() ||
        authorization.global_key_version != signing_key.key_version ||
        signing_key.activated_height >
            static_cast<uint32_t>(authorization.signed_height)) {
        return std::nullopt;
    }

    std::string_view domain;
    switch (purpose) {
    case GovernanceAuthPurpose::TRIGGER:
        domain = GOVERNANCE_TRIGGER_DOMAIN;
        break;
    case GovernanceAuthPurpose::TRIGGER_VOTE:
        domain = GOVERNANCE_VOTE_DOMAIN;
        break;
    case GovernanceAuthPurpose::PROPOSAL_VOTE:
        domain = GOVERNANCE_PROPOSAL_VOTE_DOMAIN;
        break;
    default:
        return std::nullopt;
    }
    return TaggedHash(domain, genesis_hash, authorization.version,
                      authorization.signed_height,
                      authorization.signed_block_hash,
                      authorization.pro_tx_hash,
                      authorization.global_key_version,
                      signing_key.version, signing_key.profile,
                      signing_key.activated_height,
                      PublicKeyHash(signing_key), unsigned_payload_hash);
}

bool VerifyGovernanceAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& signing_key,
    const GovernanceAuthorization& authorization,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash)
{
    const auto digest = GetGovernanceAuthorizationHash(
        genesis_hash, signing_key, authorization, purpose,
        unsigned_payload_hash);
    if (!digest || !authorization.IsStructurallyValid()) return false;
    GlobalAuthPurpose global_purpose;
    switch (purpose) {
    case GovernanceAuthPurpose::TRIGGER:
        global_purpose = GlobalAuthPurpose::GOVERNANCE_TRIGGER;
        break;
    case GovernanceAuthPurpose::TRIGGER_VOTE:
        global_purpose = GlobalAuthPurpose::GOVERNANCE_VOTE;
        break;
    case GovernanceAuthPurpose::PROPOSAL_VOTE:
        global_purpose = GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE;
        break;
    default:
        return false;
    }
    return VerifyDigest(signing_key, global_purpose, *digest,
                        authorization.signature);
}

bool GovernanceAuthorizationMatchesCurrentKey(
    const GovernanceAuthorization& authorization,
    const GlobalKeyRecord& current_key) noexcept
{
    return authorization.IsHeaderStructurallyValid() &&
           IsStoredGlobalKeyRecordStructurallyValid(current_key) &&
           authorization.global_key_version == current_key.key_version &&
           current_key.activated_height <=
               static_cast<uint32_t>(authorization.signed_height);
}

bool IsGlobalKeyCandidateStructurallyValid(const GlobalKeyRecord& candidate) noexcept
{
    return candidate.version == GLOBAL_KEY_RECORD_VERSION &&
           candidate.profile == GLOBAL_SLH_DSA_SHAKE_128S_V1 &&
           candidate.key_version != 0 && candidate.activated_height == 0 &&
           candidate.child_key_commitment.IsStructurallyValid() &&
           HasNonZeroByte(candidate.public_key);
}

bool IsStoredGlobalKeyRecordStructurallyValid(const GlobalKeyRecord& record) noexcept
{
    return record.IsStructurallyValid();
}

std::optional<uint256> GetGlobalRegistrationAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash)
{
    if (genesis_hash.IsNull() || pro_tx_hash.IsNull() || transaction_inputs_hash.IsNull() ||
        !IsGlobalKeyCandidateStructurallyValid(candidate) ||
        candidate.key_version != 1 ||
        candidate.child_key_commitment.generation != 1) {
        return std::nullopt;
    }
    return GetGlobalRegistrationHash(genesis_hash, pro_tx_hash, candidate,
                                     transaction_inputs_hash);
}

bool VerifyGlobalKeyRegistration(const uint256& genesis_hash,
                                 const uint256& pro_tx_hash,
                                 const GlobalKeyRecord& candidate,
                                 const uint256& transaction_inputs_hash,
                                 const GlobalSignature& signature)
{
    const auto digest = GetGlobalRegistrationAuthorizationHash(
        genesis_hash, pro_tx_hash, candidate, transaction_inputs_hash);
    return digest && VerifyDigest(candidate, GlobalAuthPurpose::GLOBAL_REGISTRATION,
                                  *digest, signature);
}

std::optional<uint256> GetGlobalRecoveryAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash)
{
    if (genesis_hash.IsNull() || pro_tx_hash.IsNull() ||
        transaction_inputs_hash.IsNull() ||
        !IsStoredGlobalKeyRecordStructurallyValid(current) ||
        !IsGlobalKeyCandidateStructurallyValid(candidate) ||
        current.key_version == std::numeric_limits<uint32_t>::max() ||
        candidate.key_version != current.key_version + 1 ||
        candidate.public_key == current.public_key ||
        candidate.child_key_commitment == current.child_key_commitment ||
        !IsAuthorizedCommitmentSuccessor(
            current.child_key_commitment,
            candidate.child_key_commitment)) {
        return std::nullopt;
    }
    return GetGlobalRegistrationHash(genesis_hash, pro_tx_hash, candidate,
                                     transaction_inputs_hash);
}

bool VerifyGlobalKeyRecovery(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& signature)
{
    const auto digest = GetGlobalRecoveryAuthorizationHash(
        genesis_hash, pro_tx_hash, current, candidate,
        transaction_inputs_hash);
    return digest && VerifyDigest(candidate,
                                  GlobalAuthPurpose::GLOBAL_REGISTRATION,
                                  *digest, signature);
}

std::optional<uint256> GetGlobalRotationAuthorizationHash(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const GlobalKeyRecord& current,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash)
{
    if (genesis_hash.IsNull() || pro_tx_hash.IsNull() || transaction_inputs_hash.IsNull() ||
        !IsStoredGlobalKeyRecordStructurallyValid(current) ||
        !IsGlobalKeyCandidateStructurallyValid(candidate) ||
        current.key_version == std::numeric_limits<uint32_t>::max() ||
        candidate.key_version != current.key_version + 1 ||
        candidate.public_key == current.public_key ||
        !IsAuthorizedCommitmentSuccessor(
            current.child_key_commitment,
            candidate.child_key_commitment)) {
        return std::nullopt;
    }
    return GetGlobalRotationHash(genesis_hash, pro_tx_hash, current, candidate,
                                 transaction_inputs_hash);
}

bool VerifyGlobalKeyRotation(const uint256& genesis_hash,
                             const uint256& pro_tx_hash,
                             const GlobalKeyRecord& current,
                             const GlobalKeyRecord& candidate,
                             const uint256& transaction_inputs_hash,
                             const GlobalSignature& signature)
{
    const auto digest = GetGlobalRotationAuthorizationHash(
        genesis_hash, pro_tx_hash, current, candidate, transaction_inputs_hash);
    return digest && VerifyDigest(current, GlobalAuthPurpose::GLOBAL_ROTATION,
                                  *digest, signature);
}

bool NetworkEndpoint::IsStructurallyValid() const noexcept
{
    const std::size_t expected_size = ExpectedAddressSize(network);
    if (expected_size == 0 || address_size != expected_size || port == 0 ||
        !std::any_of(address.begin(), address.begin() + expected_size,
                     [](uint8_t byte) { return byte != 0; })) {
        return false;
    }
    return std::all_of(address.begin() + expected_size, address.end(),
                       [](uint8_t byte) { return byte == 0; });
}

std::optional<NetworkEndpoint> MakeNetworkEndpoint(const CService& service) noexcept
{
    if (!service.IsValid() || service.GetPort() == 0) return std::nullopt;

    NetworkEndpoint endpoint;
    endpoint.port = service.GetPort();
    if (service.IsIPv4()) {
        in_addr address{};
        if (!service.GetInAddr(&address)) return std::nullopt;
        endpoint.network = EndpointNetwork::IPV4;
        endpoint.address_size = 4;
        std::memcpy(endpoint.address.data(), &address, endpoint.address_size);
    } else if (service.IsIPv6()) {
        in6_addr address{};
        if (!service.GetIn6Addr(&address)) return std::nullopt;
        endpoint.network = EndpointNetwork::IPV6;
        endpoint.address_size = 16;
        std::memcpy(endpoint.address.data(), &address, endpoint.address_size);
    } else if (service.IsCJDNS()) {
        in6_addr address{};
        if (!service.GetIn6Addr(&address)) return std::nullopt;
        endpoint.network = EndpointNetwork::CJDNS;
        endpoint.address_size = 16;
        std::memcpy(endpoint.address.data(), &address, endpoint.address_size);
    } else if (service.IsTor() || service.IsI2P()) {
        const auto address = service.GetAddrBytes();
        if (address.size() != endpoint.address.size()) return std::nullopt;
        endpoint.network = service.IsTor() ? EndpointNetwork::TOR_V3 : EndpointNetwork::I2P;
        endpoint.address_size = 32;
        std::copy(address.begin(), address.end(), endpoint.address.begin());
    } else {
        return std::nullopt;
    }
    if (!endpoint.IsStructurallyValid()) return std::nullopt;
    return endpoint;
}

bool ProviderServiceAuthorization::IsStructurallyValid() const noexcept
{
    return version == PROVIDER_SERVICE_AUTH_VERSION && payload_version != 0 &&
           !pro_tx_hash.IsNull() && global_key_version != 0 &&
           service.IsStructurallyValid() &&
           operator_payout_script.size() <= MAX_PROVIDER_PAYOUT_SCRIPT_SIZE &&
           !transaction_inputs_hash.IsNull();
}

std::optional<uint256> GetProviderServiceAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderServiceAuthorization& authorization)
{
    if (genesis_hash.IsNull() || !IsStoredGlobalKeyRecordStructurallyValid(current) ||
        !authorization.IsStructurallyValid() ||
        authorization.global_key_version != current.key_version) {
        return std::nullopt;
    }

    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PROVIDER_SERVICE_DOMAIN);
    writer << genesis_hash << authorization.version << authorization.payload_version
           << authorization.pro_tx_hash << authorization.global_key_version
           << current.version << current.profile << PublicKeyHash(current);
    WriteEndpoint(writer, authorization.service);
    writer << authorization.operator_payout_script;
    const bool has_nevm_address = authorization.nevm_address.has_value();
    writer << has_nevm_address;
    if (has_nevm_address) writer << *authorization.nevm_address;
    writer << authorization.transaction_inputs_hash;
    return writer.GetHash();
}

bool VerifyProviderServiceAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderServiceAuthorization& authorization,
    const GlobalSignature& signature)
{
    const auto digest = GetProviderServiceAuthorizationHash(genesis_hash, current,
                                                            authorization);
    return digest && VerifyDigest(current, GlobalAuthPurpose::PROVIDER_SERVICE,
                                  *digest, signature);
}

bool ProviderRevokeAuthorization::IsStructurallyValid() const noexcept
{
    return version == PROVIDER_REVOKE_AUTH_VERSION && payload_version != 0 &&
           !pro_tx_hash.IsNull() && global_key_version != 0 &&
           reason <= MAX_PROVIDER_REVOCATION_REASON && !transaction_inputs_hash.IsNull();
}

std::optional<uint256> GetProviderRevokeAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderRevokeAuthorization& authorization)
{
    if (genesis_hash.IsNull() || !IsStoredGlobalKeyRecordStructurallyValid(current) ||
        !authorization.IsStructurallyValid() ||
        authorization.global_key_version != current.key_version) {
        return std::nullopt;
    }
    return TaggedHash(PROVIDER_REVOKE_DOMAIN, genesis_hash, authorization.version,
                      authorization.payload_version, authorization.pro_tx_hash,
                      authorization.global_key_version, current.version, current.profile,
                      PublicKeyHash(current), authorization.reason,
                      authorization.transaction_inputs_hash);
}

bool VerifyProviderRevokeAuthorization(
    const uint256& genesis_hash,
    const GlobalKeyRecord& current,
    const ProviderRevokeAuthorization& authorization,
    const GlobalSignature& signature)
{
    const auto digest = GetProviderRevokeAuthorizationHash(genesis_hash, current,
                                                           authorization);
    return digest && VerifyDigest(current, GlobalAuthPurpose::PROVIDER_REVOKE,
                                  *digest, signature);
}

bool MNAUTHTranscript::IsStructurallyValid(uint64_t required_service_flags) const noexcept
{
    const bool known_role = signer_role == MNAUTHSignerRole::INITIATOR ||
                            signer_role == MNAUTHSignerRole::RESPONDER;
    return version == MNAUTH_TRANSCRIPT_VERSION && HasNonZeroByte(network_magic) &&
           !initiator_pro_tx_hash.IsNull() && !responder_pro_tx_hash.IsNull() &&
           initiator_pro_tx_hash != responder_pro_tx_hash &&
           initiator_global_key_version != 0 && responder_global_key_version != 0 &&
           !initiator_cookie.IsNull() && !responder_cookie.IsNull() &&
           initiator_cookie != responder_cookie && !initiator_challenge.IsNull() &&
           !responder_challenge.IsNull() &&
           initiator_challenge != responder_challenge &&
           initiator_version_nonce != 0 && responder_version_nonce != 0 &&
           initiator_version_nonce != responder_version_nonce &&
           initiator_protocol_version != 0 && responder_protocol_version != 0 &&
           required_service_flags != 0 &&
           (initiator_service_flags & required_service_flags) == required_service_flags &&
           (responder_service_flags & required_service_flags) == required_service_flags &&
           initiator_endpoint.IsStructurallyValid() &&
           responder_endpoint.IsStructurallyValid() && known_role;
}

std::optional<uint256> GetMNAUTHAuthorizationHash(
    const uint256& genesis_hash,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    const MNAUTHTranscript& transcript,
    uint64_t required_service_flags)
{
    if (genesis_hash.IsNull() || !transcript.IsStructurallyValid(required_service_flags) ||
        !RecordsMatchMNAUTH(initiator_key, responder_key, transcript)) {
        return std::nullopt;
    }

    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, MNAUTH_DOMAIN);
    writer << genesis_hash << transcript.version << transcript.network_magic
           << transcript.initiator_pro_tx_hash << transcript.responder_pro_tx_hash
           << initiator_key.version << initiator_key.profile << initiator_key.key_version
           << PublicKeyHash(initiator_key) << responder_key.version << responder_key.profile
           << responder_key.key_version << PublicKeyHash(responder_key)
           << transcript.initiator_cookie << transcript.responder_cookie
           << transcript.initiator_challenge << transcript.responder_challenge
           << transcript.initiator_version_nonce << transcript.responder_version_nonce
           << transcript.initiator_protocol_version << transcript.responder_protocol_version
           << transcript.initiator_service_flags << transcript.responder_service_flags;
    WriteEndpoint(writer, transcript.initiator_endpoint);
    WriteEndpoint(writer, transcript.responder_endpoint);
    writer << static_cast<uint8_t>(transcript.signer_role);
    return writer.GetHash();
}

bool VerifyMNAUTHAuthorization(const uint256& genesis_hash,
                               const GlobalKeyRecord& initiator_key,
                               const GlobalKeyRecord& responder_key,
                               const MNAUTHTranscript& transcript,
                               uint64_t required_service_flags,
                               const GlobalSignature& signature)
{
    const auto digest = GetMNAUTHAuthorizationHash(
        genesis_hash, initiator_key, responder_key, transcript, required_service_flags);
    if (!digest) return false;
    const GlobalKeyRecord& signer = transcript.signer_role == MNAUTHSignerRole::INITIATOR
        ? initiator_key
        : responder_key;
    return VerifyDigest(signer, GlobalAuthPurpose::MNAUTH, *digest, signature);
}

} // namespace llmq::pq
