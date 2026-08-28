// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_global_auth.h>

#include <crypto/slhdsa/slhdsa.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

using namespace llmq::pq;

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

slhdsa::SecretKey DeterministicKey()
{
    slhdsa::KeyGenerationSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i);
    auto key = slhdsa::GenerateSecretKey(seed);
    BOOST_REQUIRE(key.has_value());
    return std::move(*key);
}

GlobalKeyRecord CandidateFor(const slhdsa::SecretKey& key, uint32_t key_version)
{
    GlobalKeyRecord candidate;
    candidate.key_version = key_version;
    BOOST_REQUIRE(key.GetPublicKey(candidate.public_key));
    candidate.child_key_commitment.generation = 1;
    candidate.child_key_commitment.first_epoch = 7;
    candidate.child_key_commitment.tree_id =
        NonNullHash(100 + key_version);
    candidate.child_key_commitment.root =
        NonNullHash(200 + key_version);
    return candidate;
}

GlobalSignature Sign(const slhdsa::SecretKey& key,
                     GlobalAuthPurpose purpose,
                     const uint256& digest)
{
    GlobalSignature signature;
    BOOST_REQUIRE(slhdsa::SignDeterministic(
        key, std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(purpose), signature));
    return signature;
}

NetworkEndpoint Endpoint(uint8_t last_byte, uint16_t port)
{
    NetworkEndpoint endpoint;
    endpoint.network = EndpointNetwork::IPV4;
    endpoint.address_size = 4;
    endpoint.address[0] = 192;
    endpoint.address[1] = 0;
    endpoint.address[2] = 2;
    endpoint.address[3] = last_byte;
    endpoint.port = port;
    return endpoint;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_global_auth_tests)

BOOST_AUTO_TEST_CASE(canonical_global_authorizations_and_domain_separation)
{
    const uint256 genesis = NonNullHash(1);
    const uint256 pro_tx_hash = NonNullHash(2);
    const uint256 inputs_hash = NonNullHash(3);
    auto key = DeterministicKey();

    GlobalKeyRecord candidate = CandidateFor(key, 1);
    BOOST_CHECK(IsGlobalKeyCandidateStructurallyValid(candidate));
    BOOST_CHECK(!IsStoredGlobalKeyRecordStructurallyValid(candidate));
    const auto registration_hash = GetGlobalRegistrationAuthorizationHash(
        genesis, pro_tx_hash, candidate, inputs_hash);
    BOOST_REQUIRE(registration_hash);
    const GlobalSignature registration_signature = Sign(
        key, GlobalAuthPurpose::GLOBAL_REGISTRATION, *registration_hash);
    BOOST_CHECK(VerifyGlobalKeyRegistration(genesis, pro_tx_hash, candidate,
                                            inputs_hash, registration_signature));

    GlobalKeyRecord stored = candidate;
    stored.activated_height = 1440;
    BOOST_CHECK(!IsGlobalKeyCandidateStructurallyValid(stored));
    BOOST_CHECK(IsStoredGlobalKeyRecordStructurallyValid(stored));
    BOOST_CHECK(!GetGlobalRegistrationAuthorizationHash(
        genesis, pro_tx_hash, stored, inputs_hash));

    auto candidate_with_height = candidate;
    candidate_with_height.activated_height = 7;
    BOOST_CHECK(!VerifyGlobalKeyRegistration(genesis, pro_tx_hash, candidate_with_height,
                                             inputs_hash, registration_signature));
    BOOST_CHECK(!VerifyGlobalKeyRegistration(genesis, pro_tx_hash, candidate,
                                             NonNullHash(4), registration_signature));

    GlobalKeyRecord replacement = candidate;
    replacement.key_version = 2;
    replacement.public_key[0] ^= 0x80;
    const auto rotation_hash = GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, stored, replacement, inputs_hash);
    BOOST_REQUIRE(rotation_hash);
    BOOST_CHECK(*registration_hash != *rotation_hash);
    BOOST_CHECK(!VerifyGlobalKeyRotation(genesis, pro_tx_hash, stored, replacement,
                                         inputs_hash, registration_signature));
    const GlobalSignature rotation_signature = Sign(
        key, GlobalAuthPurpose::GLOBAL_ROTATION, *rotation_hash);
    BOOST_CHECK(VerifyGlobalKeyRotation(genesis, pro_tx_hash, stored, replacement,
                                        inputs_hash, rotation_signature));

    // Recovery always installs a fresh generation/root and the candidate key,
    // not the revoked current key, must prove possession.
    slhdsa::KeyGenerationSeed recovery_seed;
    for (std::size_t i{0}; i < recovery_seed.size(); ++i) {
        recovery_seed[i] = static_cast<uint8_t>(i + 91);
    }
    auto generated_recovery_key = slhdsa::GenerateSecretKey(recovery_seed);
    BOOST_REQUIRE(generated_recovery_key);
    auto recovery_key = std::move(*generated_recovery_key);
    auto recovery_candidate = CandidateFor(recovery_key, 2);
    recovery_candidate.child_key_commitment.generation = 2;
    const auto recovery_hash = GetGlobalRecoveryAuthorizationHash(
        genesis, pro_tx_hash, stored, recovery_candidate, inputs_hash);
    BOOST_REQUIRE(recovery_hash);
    BOOST_CHECK(*recovery_hash != *rotation_hash);
    const GlobalSignature wrong_recovery_signature = Sign(
        key, GlobalAuthPurpose::GLOBAL_REGISTRATION, *recovery_hash);
    BOOST_CHECK(!VerifyGlobalKeyRecovery(
        genesis, pro_tx_hash, stored, recovery_candidate, inputs_hash,
        wrong_recovery_signature));
    const auto recovery_signature = Sign(
        recovery_key, GlobalAuthPurpose::GLOBAL_REGISTRATION, *recovery_hash);
    BOOST_CHECK(VerifyGlobalKeyRecovery(
        genesis, pro_tx_hash, stored, recovery_candidate, inputs_hash,
        recovery_signature));

    auto skipped_version = replacement;
    skipped_version.key_version++;
    BOOST_CHECK(!GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, stored, skipped_version, inputs_hash));
    replacement.activated_height = 1441;
    BOOST_CHECK(!GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, stored, replacement, inputs_hash));
}

BOOST_AUTO_TEST_CASE(child_root_generation_cap_allows_final_successor_only)
{
    const uint256 genesis{NonNullHash(30)};
    const uint256 pro_tx_hash{NonNullHash(31)};
    const uint256 inputs_hash{NonNullHash(32)};
    auto key{DeterministicKey()};

    auto penultimate{CandidateFor(key, 1)};
    penultimate.activated_height = 1440;
    penultimate.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION - 1;
    penultimate.child_key_commitment.tree_id = NonNullHash(33);
    penultimate.child_key_commitment.root = NonNullHash(34);
    BOOST_REQUIRE(IsStoredGlobalKeyRecordStructurallyValid(penultimate));

    auto final_root{CandidateFor(key, 2)};
    final_root.public_key[0] ^= 0x80;
    final_root.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION;
    final_root.child_key_commitment.tree_id = NonNullHash(35);
    final_root.child_key_commitment.root = NonNullHash(36);
    BOOST_CHECK(GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, penultimate, final_root, inputs_hash));
    BOOST_CHECK(GetGlobalRecoveryAuthorizationHash(
        genesis, pro_tx_hash, penultimate, final_root, inputs_hash));

    auto exhausted{penultimate};
    exhausted.child_key_commitment = final_root.child_key_commitment;
    auto key_only{final_root};
    key_only.child_key_commitment = exhausted.child_key_commitment;
    BOOST_CHECK(GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, exhausted, key_only, inputs_hash));

    auto seventeenth{final_root};
    seventeenth.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION + 1;
    seventeenth.child_key_commitment.tree_id = NonNullHash(37);
    seventeenth.child_key_commitment.root = NonNullHash(38);
    BOOST_CHECK(!IsGlobalKeyCandidateStructurallyValid(seventeenth));
    BOOST_CHECK(!GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, exhausted, seventeenth, inputs_hash));
    BOOST_CHECK(!GetGlobalRecoveryAuthorizationHash(
        genesis, pro_tx_hash, exhausted, seventeenth, inputs_hash));
}

BOOST_AUTO_TEST_CASE(provider_transcripts_bind_every_operation)
{
    const uint256 genesis = NonNullHash(10);
    const uint256 pro_tx_hash = NonNullHash(11);
    auto key = DeterministicKey();
    GlobalKeyRecord stored = CandidateFor(key, 1);
    stored.activated_height = 1440;

    ProviderServiceAuthorization service;
    service.payload_version = 4;
    service.pro_tx_hash = pro_tx_hash;
    service.global_key_version = stored.key_version;
    service.service = Endpoint(1, 8369);
    service.operator_payout_script = {0x00, 0x14, 0x01, 0x02};
    service.nevm_address.emplace();
    (*service.nevm_address)[19] = 1;
    service.transaction_inputs_hash = NonNullHash(12);
    const auto service_hash = GetProviderServiceAuthorizationHash(genesis, stored, service);
    BOOST_REQUIRE(service_hash);
    const GlobalSignature service_signature = Sign(
        key, GlobalAuthPurpose::PROVIDER_SERVICE, *service_hash);
    BOOST_CHECK(VerifyProviderServiceAuthorization(genesis, stored, service,
                                                   service_signature));
    auto changed_service = service;
    changed_service.service.port++;
    const auto changed_service_hash = GetProviderServiceAuthorizationHash(
        genesis, stored, changed_service);
    BOOST_REQUIRE(changed_service_hash);
    BOOST_CHECK(*service_hash != *changed_service_hash);
    changed_service = service;
    changed_service.service.address[31] = 1;
    BOOST_CHECK(!GetProviderServiceAuthorizationHash(genesis, stored, changed_service));

    ProviderRevokeAuthorization revoke;
    revoke.payload_version = 4;
    revoke.pro_tx_hash = pro_tx_hash;
    revoke.global_key_version = stored.key_version;
    revoke.reason = 2;
    revoke.transaction_inputs_hash = NonNullHash(13);
    const auto revoke_hash = GetProviderRevokeAuthorizationHash(genesis, stored, revoke);
    BOOST_REQUIRE(revoke_hash);
    BOOST_CHECK(*service_hash != *revoke_hash);
    BOOST_CHECK(!VerifyProviderRevokeAuthorization(genesis, stored, revoke,
                                                   service_signature));
    const GlobalSignature revoke_signature = Sign(
        key, GlobalAuthPurpose::PROVIDER_REVOKE, *revoke_hash);
    BOOST_CHECK(VerifyProviderRevokeAuthorization(genesis, stored, revoke,
                                                  revoke_signature));
    revoke.reason = MAX_PROVIDER_REVOCATION_REASON + 1;
    BOOST_CHECK(!GetProviderRevokeAuthorizationHash(genesis, stored, revoke));
}

BOOST_AUTO_TEST_CASE(mnauth_binds_both_peers_and_connection_roles)
{
    const uint256 genesis = NonNullHash(20);
    auto key = DeterministicKey();
    GlobalKeyRecord initiator_key = CandidateFor(key, 1);
    initiator_key.activated_height = 1440;
    GlobalKeyRecord responder_key = initiator_key;
    responder_key.key_version = 3;
    responder_key.public_key[0] ^= 0x40;
    responder_key.activated_height = 1728;

    MNAUTHTranscript transcript;
    transcript.network_magic = {0xfa, 0xbf, 0xb5, 0xda};
    transcript.initiator_pro_tx_hash = NonNullHash(21);
    transcript.responder_pro_tx_hash = NonNullHash(22);
    transcript.initiator_global_key_version = initiator_key.key_version;
    transcript.responder_global_key_version = responder_key.key_version;
    transcript.initiator_cookie = NonNullHash(23);
    transcript.responder_cookie = NonNullHash(24);
    transcript.initiator_challenge = NonNullHash(25);
    transcript.responder_challenge = NonNullHash(26);
    transcript.initiator_version_nonce = 27;
    transcript.responder_version_nonce = 28;
    transcript.initiator_protocol_version = 70016;
    transcript.responder_protocol_version = 70017;
    transcript.initiator_service_flags = 9;
    transcript.responder_service_flags = 9;
    transcript.initiator_endpoint = Endpoint(10, 8369);
    transcript.responder_endpoint = Endpoint(11, 8369);
    transcript.signer_role = MNAUTHSignerRole::INITIATOR;
    constexpr uint64_t REQUIRED_SERVICES{1};

    BOOST_REQUIRE(transcript.IsStructurallyValid(REQUIRED_SERVICES));
    const auto digest = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, transcript, REQUIRED_SERVICES);
    BOOST_REQUIRE(digest);
    const GlobalSignature signature = Sign(key, GlobalAuthPurpose::MNAUTH, *digest);
    BOOST_CHECK(VerifyMNAUTHAuthorization(genesis, initiator_key, responder_key,
                                         transcript, REQUIRED_SERVICES, signature));

    auto changed = transcript;
    changed.signer_role = MNAUTHSignerRole::RESPONDER;
    const auto role_hash = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, changed, REQUIRED_SERVICES);
    BOOST_REQUIRE(role_hash);
    BOOST_CHECK(*digest != *role_hash);
    BOOST_CHECK(!VerifyMNAUTHAuthorization(genesis, initiator_key, responder_key,
                                          changed, REQUIRED_SERVICES, signature));

    changed = transcript;
    changed.responder_challenge = NonNullHash(29);
    const auto challenge_hash = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, changed, REQUIRED_SERVICES);
    BOOST_REQUIRE(challenge_hash);
    BOOST_CHECK(*digest != *challenge_hash);

    changed = transcript;
    changed.initiator_cookie.SetNull();
    BOOST_CHECK(!changed.IsStructurallyValid(REQUIRED_SERVICES));
    BOOST_CHECK(!GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, changed, REQUIRED_SERVICES));
    changed = transcript;
    changed.responder_service_flags = 8;
    BOOST_CHECK(!changed.IsStructurallyValid(REQUIRED_SERVICES));
    changed = transcript;
    changed.initiator_protocol_version++;
    const auto version_hash = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, changed, REQUIRED_SERVICES);
    BOOST_REQUIRE(version_hash);
    BOOST_CHECK(*digest != *version_hash);
    BOOST_CHECK(!GetMNAUTHAuthorizationHash(
        NonNullHash(30), initiator_key, responder_key, transcript, 0));
}

BOOST_AUTO_TEST_CASE(governance_envelope_is_fixed_domain_separated_and_current_key_bound)
{
    const uint256 genesis{NonNullHash(40)};
    const uint256 pro_tx_hash{NonNullHash(41)};
    const uint256 payload_hash{NonNullHash(42)};
    auto current_secret{DeterministicKey()};
    GlobalKeyRecord current_key{CandidateFor(current_secret, 3)};
    current_key.activated_height = 100;

    GovernanceAuthorization authorization;
    authorization.signed_height = 120;
    authorization.signed_block_hash = NonNullHash(43);
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = current_key.key_version;
    BOOST_CHECK(authorization.IsHeaderStructurallyValid());
    BOOST_CHECK(!authorization.IsStructurallyValid());

    const auto digest{GetGovernanceAuthorizationHash(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER, payload_hash)};
    BOOST_REQUIRE(digest);
    authorization.signature = Sign(
        current_secret, GlobalAuthPurpose::GOVERNANCE_TRIGGER, *digest);
    BOOST_REQUIRE(authorization.IsStructurallyValid());
    BOOST_CHECK(VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER, payload_hash));
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER_VOTE, payload_hash));
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::PROPOSAL_VOTE, payload_hash));
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER, NonNullHash(44)));

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(authorization, encoded));
    BOOST_CHECK_EQUAL(encoded.size(), GovernanceAuthorization::WIRE_SIZE);
    GovernanceAuthorization decoded;
    BOOST_REQUIRE(DecodeGovernanceAuthorization(encoded, decoded));
    BOOST_CHECK(decoded == authorization);
    encoded.push_back(0);
    BOOST_CHECK(!DecodeGovernanceAuthorization(encoded, decoded));
    encoded.pop_back();
    encoded.pop_back();
    BOOST_CHECK(!DecodeGovernanceAuthorization(encoded, decoded));

    slhdsa::KeyGenerationSeed replacement_seed{};
    for (std::size_t i{0}; i < replacement_seed.size(); ++i) {
        replacement_seed[i] = static_cast<uint8_t>(0x90 + i);
    }
    auto replacement_secret{slhdsa::GenerateSecretKey(replacement_seed)};
    BOOST_REQUIRE(replacement_secret);
    GlobalKeyRecord replacement_key{CandidateFor(*replacement_secret, 4)};
    replacement_key.activated_height = 130;
    // Live off-chain governance must reject the authorization as soon as the
    // branch-current key rotates.
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, replacement_key, authorization,
        GovernanceAuthPurpose::TRIGGER, payload_hash));
    BOOST_CHECK(VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER, payload_hash));

    const auto proposal_digest{GetGovernanceAuthorizationHash(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::PROPOSAL_VOTE, payload_hash)};
    BOOST_REQUIRE(proposal_digest);
    authorization.signature = Sign(
        current_secret,
        GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE,
        *proposal_digest);
    BOOST_CHECK(VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::PROPOSAL_VOTE, payload_hash));
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, current_key, authorization,
        GovernanceAuthPurpose::TRIGGER_VOTE, payload_hash));
    BOOST_CHECK(GovernanceAuthorizationMatchesCurrentKey(
        authorization, current_key));
    BOOST_CHECK(!GovernanceAuthorizationMatchesCurrentKey(
        authorization, replacement_key));
    auto not_yet_active{current_key};
    not_yet_active.activated_height =
        static_cast<uint32_t>(authorization.signed_height + 1);
    BOOST_CHECK(!GovernanceAuthorizationMatchesCurrentKey(
        authorization, not_yet_active));

    auto changed_anchor{authorization};
    changed_anchor.signed_block_hash = NonNullHash(45);
    BOOST_CHECK(!VerifyGovernanceAuthorization(
        genesis, current_key, changed_anchor,
        GovernanceAuthPurpose::PROPOSAL_VOTE, payload_hash));
}

BOOST_AUTO_TEST_SUITE_END()
