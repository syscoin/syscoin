// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/mnauth.h>

#include <crypto/slhdsa/slhdsa.h>
#include <evo/deterministicmns.h>
#include <masternode/activemasternode.h>
#include <netbase.h>
#include <net_processing.h>
#include <streams.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <utility>
#include <vector>

using namespace llmq::pq;

namespace {

constexpr uint64_t REQUIRED_SERVICES{1};

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

slhdsa::SecretKey DeterministicKey(uint8_t offset)
{
    slhdsa::KeyGenerationSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i + offset);
    }
    auto key = slhdsa::GenerateSecretKey(seed);
    BOOST_REQUIRE(key);
    return std::move(*key);
}

GlobalKeyRecord StoredKey(const slhdsa::SecretKey& key,
                          uint32_t key_version,
                          uint32_t height)
{
    GlobalKeyRecord record;
    record.key_version = key_version;
    record.activated_height = height;
    record.child_key_commitment.generation = 1;
    record.child_key_commitment.tree_id =
        NonNullHash(1'000 + key_version);
    record.child_key_commitment.root =
        NonNullHash(2'000 + key_version);
    BOOST_REQUIRE(key.GetPublicKey(record.public_key));
    BOOST_REQUIRE(record.IsStructurallyValid());
    return record;
}

NetworkEndpoint Endpoint(uint8_t last_byte)
{
    NetworkEndpoint endpoint;
    endpoint.network = EndpointNetwork::IPV4;
    endpoint.address_size = 4;
    endpoint.address[0] = 192;
    endpoint.address[1] = 0;
    endpoint.address[2] = 2;
    endpoint.address[3] = last_byte;
    endpoint.port = 8369;
    return endpoint;
}

MNAUTHTranscript Transcript(const GlobalKeyRecord& initiator_key,
                            const GlobalKeyRecord& responder_key,
                            uint32_t discriminator = 0)
{
    MNAUTHTranscript transcript;
    transcript.network_magic = {0xfa, 0xbf, 0xb5, 0xda};
    transcript.initiator_pro_tx_hash = NonNullHash(10);
    transcript.responder_pro_tx_hash = NonNullHash(11);
    transcript.initiator_global_key_version = initiator_key.key_version;
    transcript.responder_global_key_version = responder_key.key_version;
    transcript.initiator_cookie = NonNullHash(20 + discriminator * 10);
    transcript.responder_cookie = NonNullHash(21 + discriminator * 10);
    transcript.initiator_challenge = NonNullHash(22 + discriminator * 10);
    transcript.responder_challenge = NonNullHash(23 + discriminator * 10);
    transcript.initiator_version_nonce = 100 + discriminator * 10;
    transcript.responder_version_nonce = 101 + discriminator * 10;
    transcript.initiator_protocol_version = 70016;
    transcript.responder_protocol_version = 70017;
    transcript.initiator_service_flags = 9;
    transcript.responder_service_flags = 9;
    transcript.initiator_endpoint = Endpoint(1);
    transcript.responder_endpoint = Endpoint(2);
    transcript.signer_role = MNAUTHSignerRole::INITIATOR;
    return transcript;
}

PQMNAUTHMessage SignMessage(const uint256& genesis,
                            const slhdsa::SecretKey& signer,
                            const GlobalKeyRecord& initiator_key,
                            const GlobalKeyRecord& responder_key,
                            const MNAUTHTranscript& transcript)
{
    const auto digest = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, transcript, REQUIRED_SERVICES);
    BOOST_REQUIRE(digest);

    PQMNAUTHMessage message;
    message.signer_role = transcript.signer_role;
    if (message.signer_role == MNAUTHSignerRole::INITIATOR) {
        message.signer_pro_tx_hash = transcript.initiator_pro_tx_hash;
        message.signer_global_key_version = transcript.initiator_global_key_version;
    } else {
        message.signer_pro_tx_hash = transcript.responder_pro_tx_hash;
        message.signer_global_key_version = transcript.responder_global_key_version;
    }
    BOOST_REQUIRE(slhdsa::SignDeterministic(
        signer, std::span<const uint8_t>{digest->begin(), digest->size()},
        GetGlobalAuthContext(GlobalAuthPurpose::MNAUTH), message.signature));
    return message;
}

std::vector<unsigned char> Encode(const PQMNAUTHMessage& message)
{
    DataStream stream;
    stream << message;
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

bool VerifyOne(std::optional<MNAUTHVerificationTask>& task)
{
    BOOST_REQUIRE(task);
    std::vector<MNAUTHVerificationTask> tasks;
    tasks.push_back(std::move(*task));
    task.reset();
    return VerifyMNAUTHTasks(std::move(tasks));
}

CService Service(uint8_t last_byte, uint16_t port = 8369)
{
    return LookupNumeric(
        strprintf("192.0.2.%u", last_byte), port);
}

CMNAuth::ContextToken AsyncContext(
    int64_t peer_id,
    uint64_t source_key,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    const MNAUTHTranscript& transcript,
    bool local_is_initiator,
    bool authenticated_remote = false)
{
    CMNAuth::ContextToken context;
    context.peer_id = peer_id;
    context.tip_hash = NonNullHash(9'000);
    context.local_is_initiator = local_is_initiator;
    context.keyed_net_group = source_key;
    context.common_version = PQ_MNAUTH_PROTO_VERSION;
    context.masternode_connection = true;

    const auto& local_key{
        local_is_initiator ? initiator_key : responder_key};
    const auto& remote_key{
        local_is_initiator ? responder_key : initiator_key};
    const uint256& local_pro_tx{
        local_is_initiator ? transcript.initiator_pro_tx_hash
                           : transcript.responder_pro_tx_hash};
    const uint256& remote_pro_tx{
        local_is_initiator ? transcript.responder_pro_tx_hash
                           : transcript.initiator_pro_tx_hash};
    context.local_key = local_key;
    context.remote_key = remote_key;
    context.local_endpoint = local_is_initiator
        ? transcript.initiator_endpoint
        : transcript.responder_endpoint;
    context.remote_endpoint = local_is_initiator
        ? transcript.responder_endpoint
        : transcript.initiator_endpoint;
    context.local_service = Service(
        context.local_endpoint.address[3], context.local_endpoint.port);
    context.remote_service = Service(
        context.remote_endpoint.address[3], context.remote_endpoint.port);
    context.connected_service = local_is_initiator
        ? context.remote_service
        : Service(99, 40'000);
    if (authenticated_remote) {
        context.authenticated_remote_pro_tx_hash = remote_pro_tx;
    }

    context.connection.local.pro_tx_hash = local_pro_tx;
    context.connection.local.global_key_version = local_key.key_version;
    context.connection.local.cookie = local_is_initiator
        ? transcript.initiator_cookie
        : transcript.responder_cookie;
    context.connection.remote.pro_tx_hash = remote_pro_tx;
    context.connection.remote.global_key_version = remote_key.key_version;
    context.connection.remote.cookie = local_is_initiator
        ? transcript.responder_cookie
        : transcript.initiator_cookie;
    context.connection.local_challenge = local_is_initiator
        ? transcript.initiator_challenge
        : transcript.responder_challenge;
    context.connection.remote_challenge = local_is_initiator
        ? transcript.responder_challenge
        : transcript.initiator_challenge;
    context.connection.local_version_nonce = local_is_initiator
        ? transcript.initiator_version_nonce
        : transcript.responder_version_nonce;
    context.connection.remote_version_nonce = local_is_initiator
        ? transcript.responder_version_nonce
        : transcript.initiator_version_nonce;
    context.connection.local_protocol_version = local_is_initiator
        ? transcript.initiator_protocol_version
        : transcript.responder_protocol_version;
    context.connection.remote_protocol_version = local_is_initiator
        ? transcript.responder_protocol_version
        : transcript.initiator_protocol_version;
    context.connection.local_service_flags = local_is_initiator
        ? transcript.initiator_service_flags
        : transcript.responder_service_flags;
    context.connection.remote_service_flags = local_is_initiator
        ? transcript.responder_service_flags
        : transcript.initiator_service_flags;
    context.connection.has_local = true;
    context.connection.has_remote = true;
    BOOST_REQUIRE(context.IsStructurallyValid());
    return context;
}

CMNAuth::VerifyRequest AsyncVerifyRequest(
    int64_t peer_id,
    uint64_t source_key,
    const uint256& genesis,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    MNAUTHTranscript transcript)
{
    CMNAuth::VerifyRequest request;
    request.context = AsyncContext(
        peer_id, source_key, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/false);
    request.genesis_hash = genesis;
    request.expected_signer_role = MNAUTHSignerRole::INITIATOR;
    request.required_service_flags = REQUIRED_SERVICES;
    request.transcript = std::move(transcript);
    request.message.signer_pro_tx_hash =
        request.transcript.initiator_pro_tx_hash;
    request.message.signer_global_key_version =
        request.transcript.initiator_global_key_version;
    request.message.signer_role = MNAUTHSignerRole::INITIATOR;
    request.message.signature[0] = 1;
    BOOST_REQUIRE(request.message.IsStructurallyValid());
    return request;
}

CMNAuth::SignRequest AsyncSignRequest(CMNAuth::ContextToken context)
{
    CMNAuth::SignRequest request;
    request.authorization_hash = NonNullHash(
        10'000 + static_cast<uint32_t>(context.peer_id));
    request.attributed_pro_tx_hash =
        context.connection.remote.pro_tx_hash;
    request.signer_role = context.local_is_initiator
        ? MNAUTHSignerRole::INITIATOR
        : MNAUTHSignerRole::RESPONDER;
    request.context = std::move(context);
    return request;
}

class ActiveMasternodeInfoGuard final {
public:
    ActiveMasternodeInfoGuard()
    {
        LOCK(activeMasternodeInfoCs);
        m_previous_mode = fMasternodeMode;
        m_previous = std::move(activeMasternodeInfo);
        activeMasternodeInfo = {};
        activeMasternodeInfo.identityGeneration =
            m_previous.identityGeneration + 1;
        fMasternodeMode = false;
    }

    ~ActiveMasternodeInfoGuard()
    {
        LOCK(activeMasternodeInfoCs);
        const uint64_t next_generation{
            activeMasternodeInfo.identityGeneration + 1};
        activeMasternodeInfo = std::move(m_previous);
        activeMasternodeInfo.identityGeneration = next_generation;
        fMasternodeMode = m_previous_mode;
    }

    ActiveMasternodeInfoGuard(const ActiveMasternodeInfoGuard&) = delete;
    ActiveMasternodeInfoGuard& operator=(
        const ActiveMasternodeInfoGuard&) = delete;

private:
    bool m_previous_mode{false};
    CActiveMasternodeInfo m_previous;
};

} // namespace

BOOST_AUTO_TEST_SUITE(pq_mnauth_tests)

BOOST_AUTO_TEST_CASE(
    deterministic_duplicate_policy_selects_one_stable_connection)
{
    using Candidate = MNAUTHConnectionSelectionCandidate;
    const auto select = [](
        bool local_is_initiator,
        std::initializer_list<Candidate> candidates) {
        return SelectPreferredMNAUTHConnection(
            local_is_initiator,
            std::span<const Candidate>{
                candidates.begin(), candidates.size()});
    };

    // The expected direction wins even when the wrong-direction socket is
    // older, then the lowest NodeId wins within that direction.
    BOOST_CHECK_EQUAL(*select(true, {{10, true}, {50, false}}), 50);
    BOOST_CHECK_EQUAL(*select(true, {{41, true}, {19, true}}), 19);
    BOOST_CHECK_EQUAL(*select(true, {{41, false}, {19, false}}), 19);
    BOOST_CHECK_EQUAL(*select(false, {{10, false}, {50, true}}), 50);
    BOOST_CHECK_EQUAL(*select(false, {{41, true}, {19, true}}), 19);
    BOOST_CHECK_EQUAL(*select(false, {{41, false}, {19, false}}), 19);

    // Disconnecting sockets cannot win, and input order has no effect.
    BOOST_CHECK_EQUAL(
        *select(true, {{5, false, true}, {20, false}, {3, true}}),
        20);
    BOOST_CHECK_EQUAL(
        *select(true, {{3, true}, {20, false}, {5, false, true}}),
        20);
    BOOST_CHECK_EQUAL(
        *select(false, {{5, true, true}, {20, true}, {3, false}}),
        20);
    BOOST_CHECK_EQUAL(
        *select(false, {{3, false}, {20, true}, {5, true, true}}),
        20);
    BOOST_CHECK(!select(true, {}));
}

BOOST_AUTO_TEST_CASE(version_claim_and_connection_role_mapping_are_canonical)
{
    CMNAuthVersionData regular;
    regular.cookie = NonNullHash(1);
    BOOST_CHECK(regular.IsStructurallyValid());
    BOOST_CHECK(!regular.HasMasternodeIdentity());
    regular.global_key_version = 1;
    BOOST_CHECK(!regular.IsStructurallyValid());

    CMNAuthConnectionData initiator_view;
    initiator_view.local.pro_tx_hash = NonNullHash(10);
    initiator_view.local.global_key_version = 2;
    initiator_view.local.cookie = NonNullHash(11);
    initiator_view.remote.pro_tx_hash = NonNullHash(20);
    initiator_view.remote.global_key_version = 3;
    initiator_view.remote.cookie = NonNullHash(21);
    initiator_view.local_challenge = NonNullHash(12);
    initiator_view.remote_challenge = NonNullHash(22);
    initiator_view.local_version_nonce = 13;
    initiator_view.remote_version_nonce = 23;
    initiator_view.local_protocol_version = 70018;
    initiator_view.remote_protocol_version = 70018;
    initiator_view.local_service_flags = 9;
    initiator_view.remote_service_flags = 9;
    initiator_view.has_local = true;
    initiator_view.has_remote = true;
    BOOST_REQUIRE(initiator_view.IsComplete());

    const auto initiator_transcript = BuildMNAUTHTranscript(
        initiator_view, /*local_is_initiator=*/true, Endpoint(1), Endpoint(2),
        MNAUTHSignerRole::INITIATOR, {0xfa, 0xbf, 0xb5, 0xda},
        REQUIRED_SERVICES);
    BOOST_REQUIRE(initiator_transcript);

    CMNAuthConnectionData responder_view;
    responder_view.local = initiator_view.remote;
    responder_view.remote = initiator_view.local;
    responder_view.local_challenge = initiator_view.remote_challenge;
    responder_view.remote_challenge = initiator_view.local_challenge;
    responder_view.local_version_nonce = initiator_view.remote_version_nonce;
    responder_view.remote_version_nonce = initiator_view.local_version_nonce;
    responder_view.local_protocol_version =
        initiator_view.remote_protocol_version;
    responder_view.remote_protocol_version =
        initiator_view.local_protocol_version;
    responder_view.local_service_flags =
        initiator_view.remote_service_flags;
    responder_view.remote_service_flags =
        initiator_view.local_service_flags;
    responder_view.has_local = true;
    responder_view.has_remote = true;
    const auto responder_transcript = BuildMNAUTHTranscript(
        responder_view, /*local_is_initiator=*/false, Endpoint(2), Endpoint(1),
        MNAUTHSignerRole::INITIATOR, {0xfa, 0xbf, 0xb5, 0xda},
        REQUIRED_SERVICES);
    BOOST_REQUIRE(responder_transcript);
    BOOST_CHECK(*initiator_transcript == *responder_transcript);

    responder_view.remote.cookie = responder_view.local.cookie;
    BOOST_CHECK(!responder_view.IsComplete());
    BOOST_CHECK(!BuildMNAUTHTranscript(
        responder_view, /*local_is_initiator=*/false, Endpoint(2), Endpoint(1),
        MNAUTHSignerRole::INITIATOR, {0xfa, 0xbf, 0xb5, 0xda},
        REQUIRED_SERVICES));
}

BOOST_AUTO_TEST_CASE(version_identity_is_scoped_to_masternode_transport)
{
    ActiveMasternodeInfoGuard active_info_guard;
    auto secret{DeterministicKey(0)};
    ChainLockMasterSeed master_seed{};
    for (std::size_t i{0}; i < master_seed.size(); ++i) {
        master_seed[i] = static_cast<uint8_t>(0xd0 + i);
    }
    auto manager = std::make_shared<LocalOperatorKeyManager>(
        std::move(secret), std::move(master_seed));
    BOOST_REQUIRE(manager->IsValid());
    const uint256 pro_tx_hash{NonNullHash(100)};
    constexpr uint32_t key_version{1};
    {
        LOCK(activeMasternodeInfoCs);
        activeMasternodeInfo.operatorKeyManager = manager;
        activeMasternodeInfo.proTxHash = pro_tx_hash;
        activeMasternodeInfo.globalKeyVersion = key_version;
        ++activeMasternodeInfo.identityGeneration;
        fMasternodeMode = true;
    }

    const auto ordinary{CMNAuth::MakeVersionData(false)};
    BOOST_CHECK(ordinary.IsStructurallyValid());
    BOOST_CHECK(!ordinary.cookie.IsNull());
    BOOST_CHECK(!ordinary.HasMasternodeIdentity());
    BOOST_CHECK(ordinary.pro_tx_hash.IsNull());
    BOOST_CHECK_EQUAL(ordinary.global_key_version, 0U);

    const auto dedicated{CMNAuth::MakeVersionData(true)};
    BOOST_CHECK(dedicated.IsStructurallyValid());
    BOOST_CHECK(!dedicated.cookie.IsNull());
    BOOST_CHECK(dedicated.HasMasternodeIdentity());
    BOOST_CHECK(dedicated.pro_tx_hash == pro_tx_hash);
    BOOST_CHECK_EQUAL(dedicated.global_key_version, key_version);

    BOOST_CHECK(ShouldClassifyRemoteMasternodeIdentity(
        /*participation_allowed=*/true,
        /*identity_advertised=*/true));
    BOOST_CHECK(!ShouldClassifyRemoteMasternodeIdentity(
        /*participation_allowed=*/false,
        /*identity_advertised=*/true));
    BOOST_CHECK(!ShouldClassifyRemoteMasternodeIdentity(
        /*participation_allowed=*/true,
        /*identity_advertised=*/false));
}

BOOST_AUTO_TEST_CASE(wire_encoding_is_fixed_and_strict)
{
    PQMNAUTHMessage message;
    message.signer_pro_tx_hash = NonNullHash(1);
    message.signer_global_key_version = 2;
    message.signature[0] = 3;

    const auto encoded = Encode(message);
    BOOST_CHECK_EQUAL(encoded.size(), PQMNAUTHMessage::WIRE_SIZE);
    PQMNAUTHMessage decoded;
    BOOST_REQUIRE(DecodePQMNAUTHMessage(encoded, decoded));
    BOOST_CHECK(decoded == message);

    CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_REQUIRE(DecodePQMNAUTHMessage(stream, decoded));
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(decoded == message);

    auto truncated = encoded;
    truncated.pop_back();
    BOOST_CHECK(!DecodePQMNAUTHMessage(truncated, decoded));
    CDataStream truncated_stream(truncated, SER_NETWORK, PROTOCOL_VERSION);
    const auto truncated_size = truncated_stream.size();
    BOOST_CHECK(!DecodePQMNAUTHMessage(truncated_stream, decoded));
    BOOST_CHECK_EQUAL(truncated_stream.size(), truncated_size);
    auto suffixed = encoded;
    suffixed.push_back(0);
    BOOST_CHECK(!DecodePQMNAUTHMessage(suffixed, decoded));
    CDataStream suffixed_stream(suffixed, SER_NETWORK, PROTOCOL_VERSION);
    const auto suffixed_size = suffixed_stream.size();
    BOOST_CHECK(!DecodePQMNAUTHMessage(suffixed_stream, decoded));
    BOOST_CHECK_EQUAL(suffixed_stream.size(), suffixed_size);
    auto unknown_role = encoded;
    unknown_role[sizeof(uint16_t) + 32 + sizeof(uint32_t)] = 0xff;
    BOOST_CHECK(!DecodePQMNAUTHMessage(unknown_role, decoded));

    message.signature.fill(0);
    BOOST_CHECK(!message.IsStructurallyValid());
    DataStream output;
    BOOST_CHECK_THROW(output << message, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(valid_queue_verification_replay_and_transcript_cache)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    const auto transcript = Transcript(initiator_key, responder_key);
    const auto message = SignMessage(genesis, initiator_secret, initiator_key,
                                     responder_key, transcript);
    const auto authorization_hash = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, transcript, REQUIRED_SERVICES);
    BOOST_REQUIRE(authorization_hash);

    MNAUTHVerificationManager manager;
    MNAUTHVerificationError error{MNAUTHVerificationError::INVALID_MESSAGE};
    auto task = manager.Prepare(7, 70, genesis, initiator_key, responder_key,
                                transcript, MNAUTHSignerRole::INITIATOR,
                                REQUIRED_SERVICES, message, 100,
                                &error);
    BOOST_REQUIRE(task);
    BOOST_CHECK(error == MNAUTHVerificationError::NONE);
    BOOST_CHECK_EQUAL(manager.GetStats().inflight, 1U);

    MNAUTHCheckQueue queue{1};
    queue.StartWorkerThreads(2);
    std::vector<MNAUTHVerificationTask> tasks;
    tasks.push_back(std::move(*task));
    task.reset();
    BOOST_CHECK(VerifyMNAUTHTasks(std::move(tasks), &queue));
    queue.StopWorkerThreads();

    const auto stats = manager.GetStats();
    BOOST_CHECK_EQUAL(stats.inflight, 0U);
    BOOST_CHECK_EQUAL(stats.peer_sessions, 1U);
    BOOST_CHECK_EQUAL(stats.replay_entries, 1U);
    BOOST_CHECK_EQUAL(stats.success_cache_entries, 1U);
    BOOST_CHECK(manager.HasCachedSuccess(*authorization_hash, message.signature));

    auto changed_signature = message.signature;
    changed_signature[0] ^= 1;
    BOOST_CHECK(!manager.HasCachedSuccess(*authorization_hash, changed_signature));
    auto changed_transcript = transcript;
    changed_transcript.initiator_challenge = NonNullHash(99);
    const auto changed_hash = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, changed_transcript,
        REQUIRED_SERVICES);
    BOOST_REQUIRE(changed_hash);
    BOOST_CHECK(!manager.HasCachedSuccess(*changed_hash, message.signature));

    BOOST_CHECK(!manager.Prepare(7, 70, genesis, initiator_key, responder_key,
                                 transcript, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message, 101,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::DUPLICATE_PEER);
    manager.ForgetPeer(7);
    BOOST_CHECK(!manager.Prepare(8, 80, genesis, initiator_key, responder_key,
                                 transcript, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message, 101,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::REPLAY);
}

BOOST_AUTO_TEST_CASE(responder_direction_uses_the_responder_global_key)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    auto transcript = Transcript(initiator_key, responder_key);
    transcript.signer_role = MNAUTHSignerRole::RESPONDER;
    const auto message = SignMessage(genesis, responder_secret, initiator_key,
                                     responder_key, transcript);

    MNAUTHVerificationManager manager;
    MNAUTHVerificationError error;
    auto task = manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                transcript, MNAUTHSignerRole::RESPONDER,
                                REQUIRED_SERVICES, message, 1, &error);
    BOOST_REQUIRE(task);
    BOOST_CHECK(VerifyOne(task));

    MNAUTHVerificationManager wrong_direction_manager;
    BOOST_CHECK(!wrong_direction_manager.Prepare(
        2, 20, genesis, initiator_key, responder_key, transcript,
        MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES, message, 1, &error));
    BOOST_CHECK(error == MNAUTHVerificationError::WRONG_SIGNER_ROLE);
}

BOOST_AUTO_TEST_CASE(direction_identity_and_transcript_header_fail_cheaply)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    const auto transcript = Transcript(initiator_key, responder_key);
    const auto message = SignMessage(genesis, initiator_secret, initiator_key,
                                     responder_key, transcript);
    MNAUTHVerificationManager manager;
    MNAUTHVerificationError error;

    auto wrong_direction = message;
    wrong_direction.signer_role = MNAUTHSignerRole::RESPONDER;
    wrong_direction.signer_pro_tx_hash = transcript.responder_pro_tx_hash;
    wrong_direction.signer_global_key_version =
        transcript.responder_global_key_version;
    BOOST_CHECK(!manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 transcript, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES,
                                 wrong_direction, 1, &error));
    BOOST_CHECK(error == MNAUTHVerificationError::WRONG_SIGNER_ROLE);

    auto wrong_identity = message;
    wrong_identity.signer_pro_tx_hash = NonNullHash(80);
    BOOST_CHECK(!manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 transcript, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES,
                                 wrong_identity, 1, &error));
    BOOST_CHECK(error == MNAUTHVerificationError::WRONG_SIGNER_IDENTITY);
    wrong_identity = message;
    ++wrong_identity.signer_global_key_version;
    BOOST_CHECK(!manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 transcript, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES,
                                 wrong_identity, 1, &error));
    BOOST_CHECK(error == MNAUTHVerificationError::WRONG_SIGNER_IDENTITY);

    auto missing_cookie = transcript;
    missing_cookie.responder_cookie.SetNull();
    BOOST_CHECK(!manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 missing_cookie, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message, 1,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::INVALID_TRANSCRIPT);
    BOOST_CHECK_EQUAL(manager.GetStats().inflight, 0U);
    BOOST_CHECK_EQUAL(manager.GetStats().replay_entries, 0U);
}

BOOST_AUTO_TEST_CASE(signature_binds_network_genesis_cookies_versions_and_keys)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    const auto transcript = Transcript(initiator_key, responder_key);
    const auto message = SignMessage(genesis, initiator_secret, initiator_key,
                                     responder_key, transcript);
    MNAUTHVerificationManager manager;
    MNAUTHVerificationError error;
    int64_t peer_id{10};
    uint64_t now{10};

    auto expect_bad = [&](const uint256& candidate_genesis,
                          const GlobalKeyRecord& candidate_initiator_key,
                          const MNAUTHTranscript& candidate_transcript) {
        auto task = manager.Prepare(peer_id,
                                    static_cast<uint64_t>(peer_id),
                                    candidate_genesis,
                                    candidate_initiator_key, responder_key,
                                    candidate_transcript,
                                    MNAUTHSignerRole::INITIATOR,
                                    REQUIRED_SERVICES,
                                    message, now, &error);
        BOOST_REQUIRE(task);
        BOOST_CHECK(error == MNAUTHVerificationError::NONE);
        BOOST_CHECK(!VerifyOne(task));
        manager.ForgetPeer(peer_id);
        ++peer_id;
        ++now;
    };

    auto changed = transcript;
    changed.network_magic[0] ^= 1;
    expect_bad(genesis, initiator_key, changed);
    expect_bad(NonNullHash(90), initiator_key, transcript);
    changed = transcript;
    changed.responder_cookie = NonNullHash(91);
    expect_bad(genesis, initiator_key, changed);
    changed = transcript;
    ++changed.initiator_protocol_version;
    expect_bad(genesis, initiator_key, changed);
    auto wrong_key = initiator_key;
    wrong_key.public_key[0] ^= 0x80;
    expect_bad(genesis, wrong_key, transcript);
}

BOOST_AUTO_TEST_CASE(admission_bounds_clock_and_abandonment_fail_closed)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    const auto transcript1 = Transcript(initiator_key, responder_key, 0);
    const auto message1 = SignMessage(genesis, initiator_secret, initiator_key,
                                      responder_key, transcript1);
    auto transcript2 = Transcript(initiator_key, responder_key, 1);
    auto message2 = message1;

    MNAUTHRuntimeConfig config;
    config.max_inflight = 1;
    config.max_peer_sessions = 3;
    config.max_rate_sources = 2;
    config.max_replay_entries = 3;
    config.max_success_cache_entries = 1;
    config.global_attempts_per_window = 2;
    config.source_attempts_per_window = 1;
    config.rate_window_seconds = 10;
    config.replay_retention_seconds = 10;
    BOOST_REQUIRE(config.IsValid());
    MNAUTHVerificationManager manager{config};
    MNAUTHVerificationError error;

    auto task1 = manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 transcript1, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message1, 100,
                                 &error);
    BOOST_REQUIRE(task1);
    BOOST_CHECK(!manager.Prepare(2, 20, genesis, initiator_key, responder_key,
                                 transcript2, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message2, 100,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::INFLIGHT_LIMIT);
    task1.reset();
    BOOST_CHECK_EQUAL(manager.GetStats().inflight, 0U);

    auto task2 = manager.Prepare(2, 20, genesis, initiator_key, responder_key,
                                 transcript2, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message2, 100,
                                 &error);
    BOOST_REQUIRE(task2);
    BOOST_CHECK(!VerifyOne(task2));
    manager.ForgetPeer(2);

    auto transcript3 = Transcript(initiator_key, responder_key, 2);
    BOOST_CHECK(!manager.Prepare(2, 20, genesis, initiator_key, responder_key,
                                 transcript3, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message2, 100,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::RATE_LIMIT);
    BOOST_CHECK(!manager.Prepare(3, 30, genesis, initiator_key, responder_key,
                                 transcript3, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message2, 99,
                                 &error));
    BOOST_CHECK(error == MNAUTHVerificationError::INVALID_TIME);

    auto invalid_config = config;
    invalid_config.max_inflight = 0;
    BOOST_CHECK(!invalid_config.IsValid());
    MNAUTHVerificationManager invalid_manager{invalid_config};
    BOOST_CHECK(!invalid_manager.Prepare(
        4, 40, genesis, initiator_key, responder_key, transcript3,
        MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES, message2, 100, &error));
    BOOST_CHECK(error == MNAUTHVerificationError::INVALID_CONFIGURATION);
}

BOOST_AUTO_TEST_CASE(global_rate_exhaustion_does_not_poison_peer_state)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);
    const auto initial_transcript = Transcript(initiator_key, responder_key);
    const auto message = SignMessage(genesis, initiator_secret, initiator_key,
                                     responder_key, initial_transcript);

    MNAUTHRuntimeConfig config;
    config.max_inflight = 1;
    config.max_peer_sessions = 4;
    config.max_rate_sources = 4;
    config.max_replay_entries = 4;
    config.max_success_cache_entries = 1;
    config.global_attempts_per_window = 2;
    config.source_attempts_per_window = 1;
    config.rate_window_seconds = 10;
    config.replay_retention_seconds = 10;
    BOOST_REQUIRE(config.IsValid());
    MNAUTHVerificationManager manager{config};
    MNAUTHVerificationError error;

    for (int64_t peer_id{1}; peer_id <= 2; ++peer_id) {
        const auto transcript = Transcript(
            initiator_key, responder_key, static_cast<uint32_t>(peer_id));
        auto task = manager.Prepare(
            peer_id, static_cast<uint64_t>(peer_id), genesis,
            initiator_key, responder_key, transcript,
            MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES, message, 100,
            &error);
        BOOST_REQUIRE(task);
        task.reset();
        manager.ForgetPeer(peer_id);
    }
    BOOST_CHECK_EQUAL(manager.GetStats().rate_sources, 2U);

    for (int64_t peer_id{3}; peer_id <= 12; ++peer_id) {
        const auto transcript = Transcript(
            initiator_key, responder_key, static_cast<uint32_t>(peer_id));
        BOOST_CHECK(!manager.Prepare(
            peer_id, static_cast<uint64_t>(peer_id), genesis,
            initiator_key, responder_key, transcript,
            MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES, message, 100,
            &error));
        BOOST_CHECK(error == MNAUTHVerificationError::RATE_LIMIT);
    }
    BOOST_CHECK_EQUAL(manager.GetStats().rate_sources, 2U);

    const auto recovered_transcript = Transcript(initiator_key, responder_key, 13);
    auto recovered = manager.Prepare(
        13, 13, genesis, initiator_key, responder_key, recovered_transcript,
        MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES, message, 110, &error);
    BOOST_REQUIRE(recovered);
    BOOST_CHECK_EQUAL(manager.GetStats().rate_sources, 1U);
}

BOOST_AUTO_TEST_CASE(success_cache_is_strictly_bounded)
{
    const uint256 genesis = NonNullHash(1);
    auto initiator_secret = DeterministicKey(0);
    auto responder_secret = DeterministicKey(64);
    const auto initiator_key = StoredKey(initiator_secret, 1, 100);
    const auto responder_key = StoredKey(responder_secret, 2, 101);

    MNAUTHRuntimeConfig config;
    config.max_success_cache_entries = 1;
    MNAUTHVerificationManager manager{config};

    const auto transcript1 = Transcript(initiator_key, responder_key, 0);
    const auto message1 = SignMessage(genesis, initiator_secret, initiator_key,
                                      responder_key, transcript1);
    const auto hash1 = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, transcript1, REQUIRED_SERVICES);
    BOOST_REQUIRE(hash1);
    auto task1 = manager.Prepare(1, 10, genesis, initiator_key, responder_key,
                                 transcript1, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message1, 1);
    BOOST_CHECK(VerifyOne(task1));

    const auto transcript2 = Transcript(initiator_key, responder_key, 1);
    const auto message2 = SignMessage(genesis, initiator_secret, initiator_key,
                                      responder_key, transcript2);
    const auto hash2 = GetMNAUTHAuthorizationHash(
        genesis, initiator_key, responder_key, transcript2, REQUIRED_SERVICES);
    BOOST_REQUIRE(hash2);
    auto task2 = manager.Prepare(2, 20, genesis, initiator_key, responder_key,
                                 transcript2, MNAUTHSignerRole::INITIATOR,
                                 REQUIRED_SERVICES, message2, 2);
    BOOST_CHECK(VerifyOne(task2));

    BOOST_CHECK_EQUAL(manager.GetStats().success_cache_entries, 1U);
    BOOST_CHECK(!manager.HasCachedSuccess(*hash1, message1.signature));
    BOOST_CHECK(manager.HasCachedSuccess(*hash2, message2.signature));
}

BOOST_AUTO_TEST_CASE(async_config_rejects_unserviceable_lane_and_completion_bounds)
{
    CMNAuth::AsyncConfig config;
    BOOST_REQUIRE(config.IsValid());

    auto invalid_lane = config;
    invalid_lane.signing_admission.source_attempts_per_window = 3;
    invalid_lane.signing_admission.identity_attempts_per_window = 3;
    BOOST_CHECK(invalid_lane.signing_admission.IsValid());
    BOOST_CHECK(!invalid_lane.IsValid());

    auto undersized_completions = config;
    undersized_completions.max_completion_queue = 26;
    BOOST_CHECK(!undersized_completions.IsValid());

    auto multiple_signers = config;
    multiple_signers.sign_threads = 2;
    BOOST_CHECK(!multiple_signers.IsValid());
}

BOOST_AUTO_TEST_CASE(shared_netgroup_admits_small_quorum_verification_burst)
{
    const uint256 genesis{NonNullHash(1)};
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    MNAUTHVerificationManager manager;

    constexpr uint64_t shared_source{777};
    for (int64_t peer_id{1}; peer_id <= 5; ++peer_id) {
        auto transcript = Transcript(
            initiator_key, responder_key,
            static_cast<uint32_t>(peer_id));
        PQMNAUTHMessage message;
        message.signer_pro_tx_hash = transcript.initiator_pro_tx_hash;
        message.signer_global_key_version =
            transcript.initiator_global_key_version;
        message.signer_role = MNAUTHSignerRole::INITIATOR;
        message.signature[0] = 1;
        MNAUTHVerificationError error;
        auto task = manager.Prepare(
            peer_id, shared_source, genesis, initiator_key, responder_key,
            transcript, MNAUTHSignerRole::INITIATOR, REQUIRED_SERVICES,
            message, 1, &error);
        BOOST_REQUIRE(task);
        BOOST_CHECK(error == MNAUTHVerificationError::NONE);
        task.reset();
        manager.ForgetPeer(peer_id);
    }
    BOOST_CHECK_EQUAL(manager.GetStats().rate_sources, 1U);
}

BOOST_AUTO_TEST_CASE(pending_deadline_is_live_only_strictly_before_boundary)
{
    const CMNAuthPendingState pending{
        CMNAuthPendingPhase::AWAITING_REMOTE, 100};
    BOOST_CHECK(!pending.IsLiveAt(-1));
    BOOST_CHECK(pending.IsLiveAt(99));
    BOOST_CHECK(!pending.IsLiveAt(100));
    BOOST_CHECK(!pending.IsLiveAt(101));
    BOOST_CHECK(!CMNAuthPendingState{}.IsLiveAt(0));
}

BOOST_AUTO_TEST_CASE(async_deadline_skips_queued_crypto_and_expires_late_result)
{
    const uint256 genesis{NonNullHash(1)};
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};

    std::atomic<int64_t> now_micros{100};
    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    bool first_entered{false};
    bool release_first{false};
    std::atomic<int> verify_calls{0};

    CMNAuth::AsyncConfig config;
    config.verify_threads = 1;
    config.max_verify_queue = 2;
    config.verify_timeout = std::chrono::microseconds{10};
    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [&] { return now_micros.load(); };
    hooks.verify = [&](MNAUTHVerificationTask&) {
        const int call{++verify_calls};
        if (call == 1) {
            std::unique_lock lock{mutex};
            first_entered = true;
            entered_cv.notify_all();
            release_cv.wait(lock, [&] { return release_first; });
        }
        return true;
    };
    hooks.sign = [](const uint256&, uint32_t, const uint256&,
                    GlobalSignature& signature) {
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncProcessor async{config, std::move(hooks)};
    BOOST_REQUIRE(async.RegisterPeer(1));
    BOOST_REQUIRE(async.RegisterPeer(2));

    auto first = async.EnqueueVerify(AsyncVerifyRequest(
        1, 101, genesis, initiator_key, responder_key,
        Transcript(initiator_key, responder_key, 0)));
    BOOST_REQUIRE(first.Accepted());
    {
        std::unique_lock lock{mutex};
        BOOST_REQUIRE(entered_cv.wait_for(
            lock, std::chrono::seconds{2}, [&] { return first_entered; }));
    }
    auto second = async.EnqueueVerify(AsyncVerifyRequest(
        2, 102, genesis, initiator_key, responder_key,
        Transcript(initiator_key, responder_key, 1)));
    BOOST_REQUIRE(second.Accepted());
    BOOST_CHECK_EQUAL(first.deadline_micros, 110);
    BOOST_CHECK_EQUAL(second.deadline_micros, 110);

    now_micros = 110;
    {
        std::lock_guard lock{mutex};
        release_first = true;
    }
    release_cv.notify_all();

    std::vector<CMNAuth::Completion> completions;
    while (completions.size() < 2) {
        auto batch = async.WaitForCompletions(std::chrono::seconds{2});
        completions.insert(completions.end(),
                           std::make_move_iterator(batch.begin()),
                           std::make_move_iterator(batch.end()));
        BOOST_REQUIRE(!batch.empty() || completions.size() == 2);
    }
    BOOST_CHECK_EQUAL(verify_calls.load(), 1);
    BOOST_CHECK(completions[0].error ==
                CMNAuth::CompletionError::EXPIRED);
    BOOST_CHECK(completions[1].error ==
                CMNAuth::CompletionError::EXPIRED);
    const auto stats{async.GetStats()};
    BOOST_CHECK_EQUAL(stats.verify_expired_before_execution, 1U);
    BOOST_CHECK_EQUAL(stats.verify_failed, 2U);
}

BOOST_AUTO_TEST_CASE(async_cancel_and_nodeid_reuse_do_not_leak_verifier_session)
{
    const uint256 genesis{NonNullHash(1)};
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};

    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    bool entered{false};
    bool release{false};
    std::atomic<int> calls{0};
    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [] { return int64_t{1'000'000}; };
    hooks.verify = [&](MNAUTHVerificationTask&) {
        if (++calls == 1) {
            std::unique_lock lock{mutex};
            entered = true;
            entered_cv.notify_all();
            release_cv.wait(lock, [&] { return release; });
        }
        return true;
    };
    hooks.sign = [](const uint256&, uint32_t, const uint256&,
                    GlobalSignature& signature) {
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{},
                                  std::move(hooks)};
    BOOST_REQUIRE(async.RegisterPeer(7));
    BOOST_REQUIRE(async.EnqueueVerify(AsyncVerifyRequest(
        7, 70, genesis, initiator_key, responder_key,
        Transcript(initiator_key, responder_key, 0))).Accepted());
    {
        std::unique_lock lock{mutex};
        BOOST_REQUIRE(entered_cv.wait_for(
            lock, std::chrono::seconds{2}, [&] { return entered; }));
    }

    async.CancelPeer(7);
    BOOST_REQUIRE(async.RegisterPeer(7));
    const auto replacement = async.EnqueueVerify(AsyncVerifyRequest(
        7, 71, genesis, initiator_key, responder_key,
        Transcript(initiator_key, responder_key, 1)));
    BOOST_REQUIRE(replacement.Accepted());
    {
        std::lock_guard lock{mutex};
        release = true;
    }
    release_cv.notify_all();

    const auto completions{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(completions.size(), 1U);
    BOOST_CHECK(completions.front().Success());
    BOOST_CHECK_EQUAL(calls.load(), 2);
}

BOOST_AUTO_TEST_CASE(async_sign_lanes_reserve_and_prioritize_local_initiator)
{
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};

    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    bool first_entered{false};
    bool release_first{false};
    std::atomic<int> sign_calls{0};
    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [] { return int64_t{1'000'000}; };
    hooks.verify = [](MNAUTHVerificationTask&) { return true; };
    hooks.sign = [&](const uint256&, uint32_t, const uint256&,
                     GlobalSignature& signature) {
        const int call{++sign_calls};
        if (call == 1) {
            std::unique_lock lock{mutex};
            first_entered = true;
            entered_cv.notify_all();
            release_cv.wait(lock, [&] { return release_first; });
        }
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{},
                                  std::move(hooks)};
    for (int64_t peer_id : {1, 2, 3, 4}) {
        BOOST_REQUIRE(async.RegisterPeer(peer_id));
    }

    auto responder_one = AsyncContext(
        1, 500, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/false,
        /*authenticated_remote=*/true);
    BOOST_REQUIRE(async.EnqueueSign(
        AsyncSignRequest(std::move(responder_one))).Accepted());
    {
        std::unique_lock lock{mutex};
        BOOST_REQUIRE(entered_cv.wait_for(
            lock, std::chrono::seconds{2}, [&] { return first_entered; }));
    }
    auto responder_two = AsyncContext(
        2, 500, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/false,
        /*authenticated_remote=*/true);
    BOOST_REQUIRE(async.EnqueueSign(
        AsyncSignRequest(std::move(responder_two))).Accepted());
    auto initiator = AsyncContext(
        3, 500, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true);
    BOOST_REQUIRE(async.EnqueueSign(
        AsyncSignRequest(std::move(initiator))).Accepted());
    auto responder_over_quota = AsyncContext(
        4, 500, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/false,
        /*authenticated_remote=*/true);
    const auto rejected_responder{async.EnqueueSign(
        AsyncSignRequest(std::move(responder_over_quota)))};
    BOOST_CHECK(rejected_responder.error ==
                CMNAuth::AsyncError::SIGN_ADMISSION);
    BOOST_CHECK(rejected_responder.signing_error ==
                MNAUTHSigningAdmissionError::RATE_LIMIT);

    {
        std::lock_guard lock{mutex};
        release_first = true;
    }
    release_cv.notify_all();
    auto first_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(first_batch.size(), 1U);
    BOOST_CHECK(first_batch.front().message.signer_role ==
                MNAUTHSignerRole::RESPONDER);

    // Taking a completion is not enough to release the signer; full
    // main-thread processing must acknowledge it explicitly.
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    BOOST_CHECK_EQUAL(sign_calls.load(), 1);
    async.AcknowledgeSignCompletion(
        first_batch.front().context.peer_id,
        first_batch.front().registration_generation,
        first_batch.front().deadline_micros);

    auto second_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(second_batch.size(), 1U);
    BOOST_CHECK(second_batch.front().message.signer_role ==
                MNAUTHSignerRole::INITIATOR);
    async.AcknowledgeSignCompletion(
        second_batch.front().context.peer_id,
        second_batch.front().registration_generation,
        second_batch.front().deadline_micros);

    auto third_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(third_batch.size(), 1U);
    BOOST_CHECK(third_batch.front().message.signer_role ==
                MNAUTHSignerRole::RESPONDER);
    async.AcknowledgeSignCompletion(
        third_batch.front().context.peer_id,
        third_batch.front().registration_generation,
        third_batch.front().deadline_micros);
}

BOOST_AUTO_TEST_CASE(async_sign_backlog_precedes_governance_across_ack_gap)
{
    ActiveMasternodeInfoGuard active_info_guard;
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};
    ChainLockMasterSeed master_seed{};
    for (std::size_t i{0}; i < master_seed.size(); ++i) {
        master_seed[i] = static_cast<uint8_t>(0xd0 + i);
    }
    auto manager = std::make_shared<LocalOperatorKeyManager>(
        std::move(initiator_secret), std::move(master_seed));
    BOOST_REQUIRE(manager->IsValid());
    {
        LOCK(activeMasternodeInfoCs);
        activeMasternodeInfo.operatorKeyManager = manager;
        activeMasternodeInfo.proTxHash =
            transcript.initiator_pro_tx_hash;
        activeMasternodeInfo.globalKeyVersion = initiator_key.key_version;
        ++activeMasternodeInfo.identityGeneration;
        fMasternodeMode = true;
    }

    std::mutex hook_mutex;
    std::condition_variable hook_entered_cv;
    std::condition_variable hook_release_cv;
    bool first_hook_entered{false};
    bool release_first_hook{false};
    std::atomic<int> sequence{0};
    std::atomic<int> mnauth_calls{0};
    std::atomic<int> first_mnauth_order{0};
    std::atomic<int> second_mnauth_order{0};
    std::atomic<int> governance_order{0};

    CMNAuth::AsyncHooks hooks;
    hooks.verify = [](MNAUTHVerificationTask&) { return true; };
    hooks.sign = [&](const uint256& pro_tx_hash, uint32_t key_version,
                     const uint256& authorization_hash,
                     GlobalSignature& signature) {
        const int call{mnauth_calls.fetch_add(
                           1, std::memory_order_acq_rel)};
        if (call == 0) {
            std::unique_lock lock{hook_mutex};
            first_hook_entered = true;
            hook_entered_cv.notify_all();
            hook_release_cv.wait(
                lock, [&] { return release_first_hook; });
        }
        const bool result{SignActiveMasternodeMNAUTH(
            pro_tx_hash, key_version, authorization_hash, signature)};
        const int order{sequence.fetch_add(
                            1, std::memory_order_acq_rel) +
                        1};
        (call == 0 ? first_mnauth_order : second_mnauth_order)
            .store(order, std::memory_order_release);
        return result;
    };
    CMNAuth::AsyncConfig config;
    config.sign_timeout = std::chrono::seconds{45};
    CMNAuth::AsyncProcessor async{config, std::move(hooks)};
    BOOST_REQUIRE(async.RegisterPeer(1));
    BOOST_REQUIRE(async.RegisterPeer(2));
    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        1, 500, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true))).Accepted());

    bool entered{false};
    {
        std::unique_lock lock{hook_mutex};
        entered = hook_entered_cv.wait_for(
            lock, std::chrono::seconds{10},
            [&] { return first_hook_entered; });
    }
    if (!entered) {
        {
            std::lock_guard lock{hook_mutex};
            release_first_hook = true;
        }
        hook_release_cv.notify_all();
    }
    BOOST_REQUIRE(entered);

    const auto second_enqueue{async.EnqueueSign(
        AsyncSignRequest(AsyncContext(
            2, 500, initiator_key, responder_key, transcript,
            /*local_is_initiator=*/true)))};
    if (!second_enqueue.Accepted()) {
        {
            std::lock_guard lock{hook_mutex};
            release_first_hook = true;
        }
        hook_release_cv.notify_all();
        async.Stop();
    }
    BOOST_REQUIRE(second_enqueue.Accepted());

    bool governance_result{false};
    GlobalSignature governance_signature{};
    std::thread governance{[&] {
        governance_result = SignActiveMasternodeGovernanceVote(
            transcript.initiator_pro_tx_hash, initiator_key.key_version,
            NonNullHash(30'000), governance_signature);
        governance_order.store(
            sequence.fetch_add(1, std::memory_order_acq_rel) + 1,
            std::memory_order_release);
    }};

    const auto waiter_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{10}};
    ActiveMasternodeGlobalSigningStats pre_release_stats;
    do {
        pre_release_stats = GetActiveMasternodeGlobalSigningStats();
        if (pre_release_stats.governance_waiters == 1 &&
            pre_release_stats.mnauth_demands == 2) {
            break;
        }
        std::this_thread::yield();
    } while (std::chrono::steady_clock::now() < waiter_deadline);

    {
        std::lock_guard lock{hook_mutex};
        release_first_hook = true;
    }
    hook_release_cv.notify_all();

    auto first_completion{
        async.WaitForCompletions(std::chrono::seconds{40})};
    ActiveMasternodeGlobalSigningStats ack_gap_stats;
    if (first_completion.size() == 1) {
        ack_gap_stats = GetActiveMasternodeGlobalSigningStats();
        async.AcknowledgeSignCompletion(
            first_completion.front().context.peer_id,
            first_completion.front().registration_generation,
            first_completion.front().deadline_micros);
    } else {
        async.CancelPeer(1);
        async.CancelPeer(2);
    }

    std::vector<CMNAuth::Completion> second_completion;
    int64_t second_deadline_headroom{0};
    if (first_completion.size() == 1) {
        second_completion =
            async.WaitForCompletions(std::chrono::seconds{40});
        if (second_completion.size() == 1) {
            second_deadline_headroom =
                second_completion.front().deadline_micros -
                TicksSinceEpoch<std::chrono::microseconds>(
                    SteadyClock::now());
            async.AcknowledgeSignCompletion(
                second_completion.front().context.peer_id,
                second_completion.front().registration_generation,
                second_completion.front().deadline_micros);
        } else {
            async.CancelPeer(2);
        }
    }
    governance.join();

    BOOST_REQUIRE_EQUAL(pre_release_stats.governance_waiters, 1U);
    BOOST_REQUIRE_EQUAL(pre_release_stats.mnauth_demands, 2U);
    BOOST_REQUIRE_EQUAL(first_completion.size(), 1U);
    BOOST_REQUIRE(first_completion.front().Success());
    BOOST_CHECK_EQUAL(ack_gap_stats.active_operations, 0U);
    BOOST_CHECK_EQUAL(ack_gap_stats.governance_waiters, 1U);
    BOOST_CHECK_EQUAL(ack_gap_stats.mnauth_demands, 1U);
    BOOST_REQUIRE_EQUAL(second_completion.size(), 1U);
    BOOST_REQUIRE(second_completion.front().Success());
    BOOST_REQUIRE(governance_result);
    BOOST_CHECK_EQUAL(mnauth_calls.load(std::memory_order_acquire), 2);
    BOOST_CHECK_EQUAL(first_mnauth_order.load(std::memory_order_acquire), 1);
    BOOST_CHECK_EQUAL(second_mnauth_order.load(std::memory_order_acquire), 2);
    BOOST_CHECK_EQUAL(governance_order.load(std::memory_order_acquire), 3);
    BOOST_CHECK_GT(second_deadline_headroom,
                   std::chrono::duration_cast<std::chrono::microseconds>(
                       std::chrono::seconds{10}).count());
    BOOST_CHECK_EQUAL(
        GetActiveMasternodeGlobalSigningStats().mnauth_demands, 0U);
}

BOOST_AUTO_TEST_CASE(async_hook_exception_is_local_not_peer_crypto_failure)
{
    const uint256 genesis{NonNullHash(1)};
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};

    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [] { return int64_t{1'000'000}; };
    hooks.verify = [](MNAUTHVerificationTask&) -> bool {
        throw std::runtime_error{"injected verifier failure"};
    };
    hooks.sign = [](const uint256&, uint32_t, const uint256&,
                    GlobalSignature&) -> bool {
        throw std::runtime_error{"injected signer failure"};
    };
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{},
                                  std::move(hooks)};
    BOOST_REQUIRE(async.RegisterPeer(1));
    BOOST_REQUIRE(async.EnqueueVerify(AsyncVerifyRequest(
        1, 1, genesis, initiator_key, responder_key,
        transcript)).Accepted());
    const auto verify_completions{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(verify_completions.size(), 1U);
    BOOST_CHECK(verify_completions.front().error ==
                CMNAuth::CompletionError::LOCAL_ERROR);

    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        1, 1, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true))).Accepted());
    const auto sign_completions{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(sign_completions.size(), 1U);
    BOOST_CHECK(sign_completions.front().error ==
                CMNAuth::CompletionError::LOCAL_ERROR);
    BOOST_CHECK_EQUAL(
        GetActiveMasternodeGlobalSigningStats().mnauth_demands, 0U);
}

BOOST_AUTO_TEST_CASE(async_sign_demand_releases_on_cancel_and_stop)
{
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};

    std::mutex mutex;
    std::condition_variable entered_cv;
    std::condition_variable release_cv;
    bool entered{false};
    bool release{false};
    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [] { return int64_t{1'000'000}; };
    hooks.verify = [](MNAUTHVerificationTask&) { return true; };
    hooks.sign = [&](const uint256&, uint32_t, const uint256&,
                     GlobalSignature& signature) {
        std::unique_lock lock{mutex};
        entered = true;
        entered_cv.notify_all();
        release_cv.wait(lock, [&] { return release; });
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{},
                                  std::move(hooks)};
    for (int64_t peer_id : {1, 2, 3}) {
        BOOST_REQUIRE(async.RegisterPeer(peer_id));
    }
    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        1, 1, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true))).Accepted());
    bool hook_entered{false};
    {
        std::unique_lock lock{mutex};
        hook_entered = entered_cv.wait_for(
            lock, std::chrono::seconds{2}, [&] { return entered; });
    }
    if (!hook_entered) {
        {
            std::lock_guard lock{mutex};
            release = true;
        }
        release_cv.notify_all();
    }
    BOOST_REQUIRE(hook_entered);

    const auto second_enqueue{async.EnqueueSign(
        AsyncSignRequest(AsyncContext(
            2, 1, initiator_key, responder_key, transcript,
            /*local_is_initiator=*/true)))};
    if (!second_enqueue.Accepted()) {
        {
            std::lock_guard lock{mutex};
            release = true;
        }
        release_cv.notify_all();
        async.Stop();
    }
    BOOST_REQUIRE(second_enqueue.Accepted());
    auto third_transcript{transcript};
    third_transcript.responder_pro_tx_hash = NonNullHash(99);
    const auto third_enqueue{async.EnqueueSign(
        AsyncSignRequest(AsyncContext(
            3, 1, initiator_key, responder_key, third_transcript,
            /*local_is_initiator=*/true)))};
    if (!third_enqueue.Accepted()) {
        {
            std::lock_guard lock{mutex};
            release = true;
        }
        release_cv.notify_all();
        async.Stop();
    }
    BOOST_REQUIRE(third_enqueue.Accepted());
    BOOST_CHECK_EQUAL(
        GetActiveMasternodeGlobalSigningStats().mnauth_demands, 3U);

    // Erasing the first of two queued move-only jobs must release exactly one
    // reservation while preserving the job moved over it.
    async.CancelPeer(2);
    BOOST_CHECK_EQUAL(
        GetActiveMasternodeGlobalSigningStats().mnauth_demands, 2U);

    std::atomic_bool stop_returned{false};
    std::thread stopper{[&] {
        async.Stop();
        stop_returned.store(true, std::memory_order_release);
    }};
    const auto stop_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{2}};
    bool queued_demand_released{false};
    while (std::chrono::steady_clock::now() < stop_deadline) {
        if (GetActiveMasternodeGlobalSigningStats().mnauth_demands == 1) {
            queued_demand_released = true;
            break;
        }
        std::this_thread::yield();
    }
    {
        std::lock_guard lock{mutex};
        release = true;
    }
    release_cv.notify_all();
    stopper.join();

    BOOST_REQUIRE(queued_demand_released);
    BOOST_CHECK(stop_returned.load(std::memory_order_acquire));
    BOOST_CHECK_EQUAL(
        GetActiveMasternodeGlobalSigningStats().mnauth_demands, 0U);
}

BOOST_AUTO_TEST_CASE(stale_sign_ack_cannot_release_reused_node_generation)
{
    auto initiator_secret{DeterministicKey(0)};
    auto responder_secret{DeterministicKey(64)};
    const auto initiator_key{StoredKey(initiator_secret, 1, 100)};
    const auto responder_key{StoredKey(responder_secret, 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};
    std::atomic<int> sign_calls{0};

    CMNAuth::AsyncHooks hooks;
    hooks.now_micros = [] { return int64_t{1'000'000}; };
    hooks.verify = [](MNAUTHVerificationTask&) { return true; };
    hooks.sign = [&](const uint256&, uint32_t, const uint256&,
                     GlobalSignature& signature) {
        ++sign_calls;
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{},
                                  std::move(hooks)};
    BOOST_REQUIRE(async.RegisterPeer(1));
    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        1, 1, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true))).Accepted());
    auto old_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(old_batch.size(), 1U);

    async.CancelPeer(1);
    BOOST_REQUIRE(async.RegisterPeer(1));
    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        1, 1, initiator_key, responder_key, transcript,
        /*local_is_initiator=*/true))).Accepted());
    auto current_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(current_batch.size(), 1U);
    BOOST_CHECK_EQUAL(old_batch.front().deadline_micros,
                      current_batch.front().deadline_micros);
    BOOST_CHECK_NE(old_batch.front().registration_generation,
                   current_batch.front().registration_generation);

    BOOST_REQUIRE(async.RegisterPeer(2));
    auto next_transcript{transcript};
    next_transcript.responder_pro_tx_hash = NonNullHash(99);
    BOOST_REQUIRE(async.EnqueueSign(AsyncSignRequest(AsyncContext(
        2, 2, initiator_key, responder_key, next_transcript,
        /*local_is_initiator=*/true))).Accepted());

    async.AcknowledgeSignCompletion(
        old_batch.front().context.peer_id,
        old_batch.front().registration_generation,
        old_batch.front().deadline_micros);
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    BOOST_CHECK_EQUAL(sign_calls.load(), 2);

    async.AcknowledgeSignCompletion(
        current_batch.front().context.peer_id,
        current_batch.front().registration_generation,
        current_batch.front().deadline_micros);
    auto next_batch{
        async.WaitForCompletions(std::chrono::seconds{2})};
    BOOST_REQUIRE_EQUAL(next_batch.size(), 1U);
    BOOST_CHECK_EQUAL(sign_calls.load(), 3);
    async.AcknowledgeSignCompletion(
        next_batch.front().context.peer_id,
        next_batch.front().registration_generation,
        next_batch.front().deadline_micros);
}

BOOST_AUTO_TEST_SUITE_END()
