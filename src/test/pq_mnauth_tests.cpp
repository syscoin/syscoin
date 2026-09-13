// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/mnauth.h>

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/slhdsa/slhdsa.h>
#include <dsnotificationinterface.h>
#include <evo/deterministicmns.h>
#include <hash.h>
#include <init.h>
#include <llmq/pq_quorum_overlay.h>
#include <llmq/quorums_chainlocks.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <netbase.h>
#include <net_processing.h>
#include <node/transaction.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/pq_registry_read_error.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace llmq::pq;

namespace mnauth_tests {
class CMNAuthTestAccess {
public:
    static void Process(CMNAuth::AsyncProcessor& async,
                        ChainstateManager& chainman,
                        CConnman& connman,
                        PeerManager& peerman,
                        const std::function<void()>& context_validated)
    {
        CMNAuth::ProcessAsyncCompletionsImpl(
            async, chainman, connman, peerman, context_validated);
    }
};
} // namespace mnauth_tests

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

// Exercise the live completion handler against authenticated persisted registry
// records. The successor changes only the remote key or its advertised service.
class CompletionPublicationFixture {
    static constexpr int PREPARATION_HEIGHT{1295};
    static constexpr int CURRENT_HEIGHT{1296};

    ActiveMasternodeInfoGuard m_active_info_guard;
    const int m_current_height;
    const int m_next_height;
    std::vector<uint256> m_hashes;
    std::vector<CBlockIndex> m_indices;
    struct RestoreState {
        ChainstateManager& chainman;
        ConnmanTestMsg& connman;
        Consensus::Params& consensus;
        Consensus::Params original_consensus;
        CBlockIndex* original_tip;
        std::unique_ptr<CDeterministicMNManager> original_manager;
        ~RestoreState()
        {
            LOCK(cs_main);
            connman.ClearTestNodes();
            chainman.ActiveChain().SetTip(*original_tip);
            deterministicMNManager = std::move(original_manager);
            consensus = original_consensus;
        }
    } m_restore;

    std::mutex m_wake_mutex;
    std::condition_variable m_wake_cv;
    unsigned m_wakes{0};
    unsigned m_consumed_wakes{0};

public:
    ChainstateManager& chainman;
    ConnmanTestMsg& connman;
    PeerManager& peerman;
    CMNAuth::ContextToken context;
    GlobalKeyRecord next_remote_key;
    CService next_remote_service;

    CompletionPublicationFixture(TestingSetup& fixture,
                                 bool outbound, bool rotate_key,
                                 bool active_manager_setup = false)
        : m_current_height{active_manager_setup ? 2310 : CURRENT_HEIGHT},
          m_next_height{m_current_height + 1},
          m_hashes(m_next_height + 1),
          m_indices(m_next_height + 1),
          m_restore{*fixture.m_node.chainman,
                    static_cast<ConnmanTestMsg&>(*fixture.m_node.connman),
                    const_cast<Consensus::Params&>(Params().GetConsensus()),
                    Params().GetConsensus(),
                    WITH_LOCK(cs_main, return fixture.m_node.chainman->ActiveTip()),
                    std::move(deterministicMNManager)},
          chainman{m_restore.chainman}, connman{m_restore.connman},
          peerman{*fixture.m_node.peerman}
    {
        auto& consensus{m_restore.consensus};
        consensus.DIP0003Height = PREPARATION_HEIGHT - 1;
        consensus.DIP0003EnforcementHeight = PREPARATION_HEIGHT - 1;
        consensus.nPQPreparationHeight = PREPARATION_HEIGHT;
        consensus.nPQActivationHeight = CURRENT_HEIGHT;
        consensus.nPQChainLockEpochOrigin = 1440;
        consensus.nPQRegistrationCutoffBlocks = 144;
        consensus.nPQFutureHorizonEpochs = 8;
        PQRegistryConfig config;
        BOOST_REQUIRE(GetPQRegistryConfig(consensus, config) ==
                      PQRegistryDeploymentResult::VALID);
        for (int height{0}; height <= m_next_height; ++height) {
            m_hashes[height] = NonNullHash(80'000 + height);
            auto& index{m_indices[height]};
            index.nHeight = height;
            index.pprev = height == 0 ? nullptr : &m_indices[height - 1];
            index.phashBlock = &m_hashes[height];
            index.BuildSkip();
        }

        const auto key_for = [&](uint8_t offset, uint32_t version,
                                 const uint256& pro_tx_hash) {
            auto key{StoredKey(DeterministicKey(offset), version,
                               PREPARATION_HEIGHT)};
            const auto tree_id{GetChildKeyTreeId(
                consensus.hashGenesisBlock, pro_tx_hash,
                key.child_key_commitment.generation,
                key.child_key_commitment.first_epoch)};
            BOOST_REQUIRE(tree_id);
            key.child_key_commitment.tree_id = *tree_id;
            if (active_manager_setup) {
                const auto& commitment{key.child_key_commitment};
                CHashWriter writer{SER_GETHASH, 0};
                writer << std::string{"SYS_PQ_OPERATOR_TEST_STUB_V1"}
                       << consensus.hashGenesisBlock << commitment.tree_id
                       << commitment.generation << commitment.first_epoch
                       << commitment.depth;
                key.child_key_commitment.root = writer.GetHash();
            }
            return key;
        };
        const auto initiator_key{key_for(0, 1, NonNullHash(10))};
        const auto responder_key{key_for(1, 1, NonNullHash(11))};
        context = AsyncContext(100, 42, initiator_key, responder_key,
                               Transcript(initiator_key, responder_key), outbound);
        if (active_manager_setup) {
            const auto local_service{Lookup("127.0.0.1", GetListenPort(), false)};
            BOOST_REQUIRE(local_service);
            context.local_service = *local_service;
        }
        context.tip_hash = m_hashes[m_current_height];
        const auto& remote_pro_tx{context.connection.remote.pro_tx_hash};
        next_remote_key = rotate_key ? key_for(2, 2, remote_pro_tx)
                                     : context.remote_key;
        if (rotate_key) next_remote_key.activated_height = m_next_height;
        next_remote_service = rotate_key ? context.remote_service : Service(3);

        const DBParams dmn_params{
            .path = fixture.m_path_root / fs::PathFromString(
                strprintf("mnauth_publication_%d_%d", outbound, rotate_key)),
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
        };
        DBParams registry_params{dmn_params};
        registry_params.path += "_pq_registry";
        registry_params.cache_bytes /= 2;
        {
            PQRegistryManager writer{
                registry_params, consensus.hashGenesisBlock, config,
                evo::MakeAuxiliaryHistoryGCDeployment(consensus).configuration_id};
            const auto empty_root{PQRegistrySnapshot{}.RecomputeConsensusStateRoot(
                consensus.hashGenesisBlock)};
            BOOST_REQUIRE(empty_root);
            uint256 previous_root{*empty_root};
            std::vector<OperatorKeyState> previous_states;
            for (int height{PREPARATION_HEIGHT}; height <= m_next_height; ++height) {
                const auto schedule{DeriveOperatorKeyScheduleView(
                    config.schedule, height, config.registration_cutoff_blocks,
                    config.future_horizon_epochs)};
                BOOST_REQUIRE(schedule);
                PQRegistrySnapshot snapshot;
                for (const bool local : {true, false}) {
                    const auto& pro_tx{local ? context.connection.local.pro_tx_hash
                                             : remote_pro_tx};
                    auto state{OperatorKeyState::ForOperator(pro_tx)};
                    state.schedule_initialized = 1;
                    state.schedule = OperatorKeyScheduleState::FromView(*schedule);
                    state.has_global_key = 1;
                    state.global_key_active = 1;
                    state.global_key = local ? context.local_key
                        : height == m_next_height ? next_remote_key : context.remote_key;
                    BOOST_REQUIRE(state.IsStructurallyValid());
                    snapshot.operator_states.push_back(state);
                }
                std::sort(snapshot.operator_states.begin(), snapshot.operator_states.end(),
                          [](const auto& lhs, const auto& rhs) {
                              return lhs.pro_tx_hash < rhs.pro_tx_hash;
                          });
                const auto root{snapshot.RecomputeConsensusStateRoot(consensus.hashGenesisBlock)};
                BOOST_REQUIRE(root);
                PQRegistryDiskSnapshot disk;
                disk.is_checkpoint =
                    (height - PREPARATION_HEIGHT) % PQ_REGISTRY_CHECKPOINT_INTERVAL == 0;
                disk.height = height;
                disk.block_hash = m_hashes[height];
                disk.previous_block_hash = m_hashes[height - 1];
                disk.previous_consensus_state_root = previous_root;
                for (const auto& state : snapshot.operator_states) {
                    if (std::find(previous_states.begin(), previous_states.end(), state) ==
                        previous_states.end()) {
                        disk.operator_states.push_back(state);
                    }
                }
                if (disk.is_checkpoint) disk.checkpoint_operator_states = snapshot.operator_states;
                disk.consensus_state_root = *root;
                BOOST_REQUIRE(writer.WriteExactSnapshotForTesting(disk.block_hash, disk));
                previous_root = *root;
                previous_states = std::move(snapshot.operator_states);
            }
        }
        deterministicMNManager = std::make_unique<CDeterministicMNManager>(dmn_params);
        for (int height{m_current_height}; height <= m_next_height; ++height) {
            CDeterministicMNList list{m_hashes[height], height, 2};
            for (const bool local : {true, false}) {
                auto member{std::make_shared<CDeterministicMN>(local ? 0 : 1)};
                member->proTxHash = local ? context.connection.local.pro_tx_hash : remote_pro_tx;
                member->collateralOutpoint = COutPoint{NonNullHash(local ? 300 : 301), 0};
                auto state{std::make_shared<CDeterministicMNState>()};
                state->keyIDOwner.begin()[0] = local ? 1 : 2;
                state->addr = local ? context.local_service
                    : height == m_next_height ? next_remote_service : context.remote_service;
                state->nRegisteredHeight = PREPARATION_HEIGHT - 1;
                member->pdmnState = state;
                list.AddMN(member, /*fBumpTotalCount=*/false);
            }
            deterministicMNManager->m_evoDb->WriteCache(m_hashes[height], list);
        }
        {
            ChainLockMasterSeed master_seed{};
            master_seed[0] = 1;
            LOCK(activeMasternodeInfoCs);
            activeMasternodeInfo.operatorKeyManager = std::make_shared<LocalOperatorKeyManager>(
                DeterministicKey(outbound ? 0 : 1), std::move(master_seed));
            BOOST_REQUIRE(activeMasternodeInfo.operatorKeyManager->IsValid());
            activeMasternodeInfo.proTxHash = context.connection.local.pro_tx_hash;
            activeMasternodeInfo.globalKeyVersion = context.local_key.key_version;
            activeMasternodeInfo.service = context.local_service;
            ++activeMasternodeInfo.identityGeneration;
            fMasternodeMode = true;
        }
        LOCK(cs_main);
        chainman.ActiveChain().SetTip(m_indices[m_current_height]);
        for (int height{m_current_height}; height <= m_next_height; ++height) {
            PQRegistryReadView view;
            std::string error;
            BOOST_REQUIRE_MESSAGE(deterministicMNManager->GetPQRegistryReadView(
                &m_indices[height], view, error), error);
            BOOST_REQUIRE(view.FindOperator(remote_pro_tx));
        }
    }

    CNode& AddNode(int64_t peer_id)
    {
        auto* node = new CNode{
            peer_id, nullptr, CAddress{context.connected_service, NODE_NETWORK},
            context.keyed_net_group, 1, CAddress{}, std::string{},
            context.local_is_initiator ? ConnectionType::OUTBOUND_FULL_RELAY
                                       : ConnectionType::INBOUND,
            false};
        connman.AddTestNode(*node);
        node->fSuccessfullyConnected = true;
        node->m_masternode_connection = true;
        node->SetCommonVersion(context.common_version);
        auto connection{context.connection};
        if (peer_id != context.peer_id) {
            connection.remote.cookie = NonNullHash(50'000 + static_cast<uint32_t>(peer_id));
        }
        BOOST_REQUIRE(node->SetLocalMNAuthConnectionData(
            connection.local, connection.local_challenge,
            connection.local_version_nonce, connection.local_protocol_version,
            connection.local_service_flags));
        BOOST_REQUIRE(node->SetRemoteMNAuthConnectionData(
            connection.remote, connection.remote_challenge,
            connection.remote_version_nonce, connection.remote_protocol_version,
            connection.remote_service_flags));
        return *node;
    }

    CMNAuth::AsyncHooks Hooks()
    {
        CMNAuth::AsyncHooks hooks;
        // Cryptography is covered by the transcript tests. These hooks isolate
        // publication ordering while retaining production admission/completions.
        hooks.verify = [](MNAUTHVerificationTask&) { return true; };
        hooks.sign = [](const uint256&, uint32_t, const uint256&, GlobalSignature& signature) {
            signature[0] = 1;
            return true;
        };
        hooks.wake = [this] {
            std::lock_guard lock{m_wake_mutex};
            ++m_wakes;
            m_wake_cv.notify_all();
        };
        return hooks;
    }

    void WaitForCompletion()
    {
        std::unique_lock lock{m_wake_mutex};
        BOOST_REQUIRE(m_wake_cv.wait_for(lock, std::chrono::seconds{5},
            [&] { return m_wakes > m_consumed_wakes; }));
        ++m_consumed_wakes;
    }

    void QueueVerify(CNode& node, CMNAuth::AsyncProcessor& async)
    {
        CMNAuth::VerifyRequest request;
        request.context = context;
        request.context.peer_id = node.GetId();
        request.context.connection = node.GetMNAuthConnectionData();
        request.genesis_hash = Params().GetConsensus().hashGenesisBlock;
        request.required_service_flags = REQUIRED_SERVICES;
        request.expected_signer_role = context.local_is_initiator
            ? MNAUTHSignerRole::RESPONDER : MNAUTHSignerRole::INITIATOR;
        const auto transcript{BuildMNAUTHTranscript(
            request.context.connection, context.local_is_initiator,
            context.local_endpoint, context.remote_endpoint,
            request.expected_signer_role, Params().MessageStart(), REQUIRED_SERVICES)};
        BOOST_REQUIRE(transcript);
        request.transcript = *transcript;
        request.message.signer_role = request.expected_signer_role;
        request.message.signer_pro_tx_hash = context.connection.remote.pro_tx_hash;
        request.message.signer_global_key_version = context.remote_key.key_version;
        request.message.signature[0] = 1;
        const auto result{async.EnqueueVerify(std::move(request))};
        BOOST_REQUIRE(result.Accepted());
        node.SetMNAuthPending(CMNAuthPendingPhase::VERIFY_PENDING, result.deadline_micros);
        WaitForCompletion();
    }

    void QueueSign(CNode& node, CMNAuth::AsyncProcessor& async)
    {
        auto peer_context{context};
        peer_context.peer_id = node.GetId();
        peer_context.connection = node.GetMNAuthConnectionData();
        const auto result{async.EnqueueSign(AsyncSignRequest(std::move(peer_context)))};
        BOOST_REQUIRE(result.Accepted());
        node.SetMNAuthPending(CMNAuthPendingPhase::SIGN_PENDING, result.deadline_micros);
        WaitForCompletion();
    }

    void AdvanceTip()
    {
        {
            LOCK(cs_main);
            chainman.ActiveChain().SetTip(m_indices[m_next_height]);
        }
        CMNAuth::UpdatedBlockTip(chainman, connman);
    }

    void ProcessGuarded(CMNAuth::AsyncProcessor& async,
                        const std::function<bool()>& published,
                        bool advance_tip = false)
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool attempted{false};
        bool acquired_during_validation{false};
        bool observed_publication{false};
        unsigned callbacks{0};
        std::thread transition;
        struct ThreadJoinGuard {
            std::thread& thread;
            ~ThreadJoinGuard()
            {
                if (thread.joinable()) thread.join();
            }
        } join_guard{transition};
        mnauth_tests::CMNAuthTestAccess::Process(
            async, chainman, connman, peerman, [&] {
                ++callbacks;
                transition = std::thread{[&] {
                    {
                        TRY_LOCK(cs_main, lock);
                        acquired_during_validation = bool(lock);
                    }
                    {
                        std::lock_guard lock{mutex};
                        attempted = true;
                        cv.notify_all();
                    }
                    {
                        LOCK(cs_main);
                        observed_publication = published();
                    }
                    if (advance_tip) AdvanceTip();
                }};
                std::unique_lock lock{mutex};
                cv.wait(lock, [&] { return attempted; });
            });
        if (transition.joinable()) transition.join();
        BOOST_CHECK_EQUAL(callbacks, 1U);
        BOOST_CHECK(!acquired_during_validation);
        BOOST_CHECK(observed_publication);
    }
};

// The chain and UTXO undo are genuinely mined by TestChain100Setup. Only the
// completed authentication and its branch-local authority records are seeded;
// handshake verification and registration transaction processing have separate
// tests. In particular, cleanup must come from the registered PeerManager.
class RollbackNotificationFixture {
    Consensus::Params& m_consensus;
    struct RestoreState {
        Consensus::Params& consensus;
        Consensus::Params original_consensus;
        std::unique_ptr<CDeterministicMNManager> original_manager;
        ConnmanTestMsg& connman;
        ~RestoreState()
        {
            SyncWithValidationInterfaceQueue();
            connman.ClearTestNodes();
            LOCK(cs_main);
            deterministicMNManager = std::move(original_manager);
            consensus = original_consensus;
        }
    } m_restore;
    std::array<GlobalKeyRecord, 3> m_parent_keys;
    std::array<GlobalKeyRecord, 3> m_tip_keys;
    std::array<CService, 3> m_parent_services;
    std::array<CService, 3> m_tip_services;

    static uint256 Provider(std::size_t member)
    {
        return NonNullHash(500 + member);
    }

public:
    static constexpr std::size_t KEY_CHANGED{0};
    static constexpr std::size_t SERVICE_CHANGED{1};
    static constexpr std::size_t UNCHANGED{2};
    ChainstateManager& chainman;
    ConnmanTestMsg& connman;
    PeerManager& peerman;
    CBlockIndex* const tip;

    explicit RollbackNotificationFixture(TestChain100Setup& fixture)
        : m_consensus{const_cast<Consensus::Params&>(Params().GetConsensus())},
          m_restore{m_consensus, m_consensus, std::move(deterministicMNManager),
                    static_cast<ConnmanTestMsg&>(*fixture.m_node.connman)},
          chainman{*fixture.m_node.chainman},
          connman{static_cast<ConnmanTestMsg&>(*fixture.m_node.connman)},
          peerman{*fixture.m_node.peerman},
          tip{WITH_LOCK(cs_main, return chainman.ActiveTip())}
    {
        const int preparation_height{tip->nHeight - 2};
        m_consensus.DIP0003Height = preparation_height - 1;
        m_consensus.DIP0003EnforcementHeight = preparation_height - 1;
        m_consensus.nPQPreparationHeight = preparation_height;
        m_consensus.nPQActivationHeight = preparation_height + 1;
        m_consensus.nPQChainLockEpochOrigin = 1440;
        m_consensus.nPQRegistrationCutoffBlocks = 144;
        m_consensus.nPQFutureHorizonEpochs = 8;
        PQRegistryConfig config;
        BOOST_REQUIRE(GetPQRegistryConfig(m_consensus, config) ==
                      PQRegistryDeploymentResult::VALID);
        const auto key_for = [&](uint8_t seed, uint32_t version,
                                 std::size_t member, int height) {
            auto key{StoredKey(DeterministicKey(seed), version, height)};
            const auto tree_id{GetChildKeyTreeId(
                m_consensus.hashGenesisBlock, Provider(member),
                key.child_key_commitment.generation,
                key.child_key_commitment.first_epoch)};
            BOOST_REQUIRE(tree_id);
            key.child_key_commitment.tree_id = *tree_id;
            return key;
        };
        for (std::size_t member{0}; member < m_parent_keys.size(); ++member) {
            m_parent_keys[member] = key_for(member, 1, member, preparation_height);
            m_tip_keys[member] = m_parent_keys[member];
            m_parent_services[member] = Service(10 + member);
            m_tip_services[member] = m_parent_services[member];
        }
        m_tip_keys[KEY_CHANGED] = key_for(4, 2, KEY_CHANGED, tip->nHeight);
        m_tip_services[SERVICE_CHANGED] = Service(20);

        const DBParams dmn_params{
            .path = fixture.m_path_root / "mnauth_rollback",
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
        };
        DBParams registry_params{dmn_params};
        registry_params.path += "_pq_registry";
        registry_params.cache_bytes /= 2;
        {
            PQRegistryManager writer{
                registry_params, m_consensus.hashGenesisBlock, config,
                evo::MakeAuxiliaryHistoryGCDeployment(m_consensus).configuration_id};
            const auto empty_root{PQRegistrySnapshot{}.RecomputeConsensusStateRoot(
                m_consensus.hashGenesisBlock)};
            BOOST_REQUIRE(empty_root);
            uint256 previous_root{*empty_root};
            std::vector<OperatorKeyState> previous_states;
            for (int height{preparation_height}; height <= tip->nHeight; ++height) {
                const auto schedule{DeriveOperatorKeyScheduleView(
                    config.schedule, height, config.registration_cutoff_blocks,
                    config.future_horizon_epochs)};
                BOOST_REQUIRE(schedule);
                PQRegistrySnapshot snapshot;
                for (std::size_t member{0}; member < m_parent_keys.size(); ++member) {
                    auto state{OperatorKeyState::ForOperator(Provider(member))};
                    state.schedule_initialized = 1;
                    state.schedule = OperatorKeyScheduleState::FromView(*schedule);
                    state.has_global_key = 1;
                    state.global_key_active = 1;
                    state.global_key = height == tip->nHeight
                        ? m_tip_keys[member] : m_parent_keys[member];
                    BOOST_REQUIRE(state.IsStructurallyValid());
                    snapshot.operator_states.push_back(state);
                }
                std::sort(snapshot.operator_states.begin(), snapshot.operator_states.end(),
                          [](const auto& lhs, const auto& rhs) {
                              return lhs.pro_tx_hash < rhs.pro_tx_hash;
                          });
                const auto root{snapshot.RecomputeConsensusStateRoot(
                    m_consensus.hashGenesisBlock)};
                BOOST_REQUIRE(root);
                const auto* index{tip->GetAncestor(height)};
                PQRegistryDiskSnapshot disk;
                disk.is_checkpoint = height == preparation_height;
                disk.height = height;
                disk.block_hash = index->GetBlockHash();
                disk.previous_block_hash = index->pprev->GetBlockHash();
                disk.previous_consensus_state_root = previous_root;
                for (const auto& state : snapshot.operator_states) {
                    if (std::find(previous_states.begin(), previous_states.end(), state) ==
                        previous_states.end()) {
                        disk.operator_states.push_back(state);
                    }
                }
                if (disk.is_checkpoint) disk.checkpoint_operator_states = snapshot.operator_states;
                disk.consensus_state_root = *root;
                BOOST_REQUIRE(writer.WriteExactSnapshotForTesting(disk.block_hash, disk));
                previous_root = *root;
                previous_states = std::move(snapshot.operator_states);
            }
        }
        // Seed the public V1 inverse schema before opening the manager. Both
        // endpoints and the history chain are verified again by real undo.
        DBParams inverse_params{dmn_params};
        inverse_params.path += "_inverse";
        inverse_params.cache_bytes /= 8;
        {
            CEvoDB<uint256, CDeterministicMNList, StaticSaltedHasher> lists{dmn_params, 0};
            CEvoDB<uint256, CDeterministicMNListInverse, StaticSaltedHasher>
                inverses{inverse_params, 0};
            CDeterministicMNList previous;
            uint256 previous_history;
            for (int height{m_consensus.DIP0003Height}; height <= tip->nHeight; ++height) {
                const auto* index{tip->GetAncestor(height)};
                CDeterministicMNList list{index->GetBlockHash(), height, 3};
                for (std::size_t member{0}; member < m_parent_keys.size(); ++member) {
                    auto dmn{std::make_shared<CDeterministicMN>(member)};
                    dmn->proTxHash = Provider(member);
                    dmn->collateralOutpoint = COutPoint{NonNullHash(600 + member), 0};
                    auto state{std::make_shared<CDeterministicMNState>()};
                    state->keyIDOwner.begin()[0] = member + 1;
                    state->addr = height == tip->nHeight
                        ? m_tip_services[member] : m_parent_services[member];
                    state->nRegisteredHeight = m_consensus.DIP0003Height;
                    dmn->pdmnState = state;
                    list.AddMN(dmn, /*fBumpTotalCount=*/false);
                }
                const uint256 state_hash{list.GetOrComputePQLegacyStateHash(
                    m_consensus.hashGenesisBlock)};
                BOOST_REQUIRE(lists.WriteThrough(index->GetBlockHash(), list));
                if (height == m_consensus.DIP0003Height) {
                    static constexpr std::string_view domain{"SYS_DMN_INVERSE_BASE_V1"};
                    CHashWriter writer{SER_GETHASH, 0};
                    writer.write(AsBytes(Span{domain.data(), domain.size()}));
                    writer << m_consensus.hashGenesisBlock << int32_t{height}
                           << index->GetBlockHash() << state_hash;
                    previous_history = writer.GetHash();
                } else {
                    CDeterministicMNListInverse inverse;
                    inverse.genesis_hash = m_consensus.hashGenesisBlock;
                    inverse.coverage_base_height = m_consensus.DIP0003Height;
                    inverse.parent_history_commitment = previous_history;
                    inverse.child_height = height;
                    inverse.child_hash = index->GetBlockHash();
                    inverse.child_state_hash = state_hash;
                    inverse.parent_height = height - 1;
                    inverse.parent_hash = index->pprev->GetBlockHash();
                    inverse.parent_state_hash = previous.GetOrComputePQLegacyStateHash(
                        m_consensus.hashGenesisBlock);
                    inverse.parent_total_registered_count = previous.GetTotalRegisteredCount();
                    CDeterministicMNListNEVMAddressDiff nevm_diff;
                    list.BuildDiff(previous, inverse.inverse_diff, nevm_diff);
                    static constexpr std::string_view domain{"SYS_DMN_INVERSE_HISTORY_V1"};
                    CHashWriter writer{SER_GETHASH, 0};
                    writer.write(AsBytes(Span{domain.data(), domain.size()}));
                    writer << inverse.version << inverse.genesis_hash
                           << inverse.coverage_base_height << inverse.parent_history_commitment
                           << inverse.child_height << inverse.child_hash << inverse.child_state_hash
                           << inverse.parent_height << inverse.parent_hash << inverse.parent_state_hash
                           << inverse.parent_total_registered_count << ::SerializeHash(inverse.inverse_diff);
                    inverse.history_commitment = writer.GetHash();
                    BOOST_REQUIRE(inverse.IsStructurallyValid());
                    BOOST_REQUIRE(inverses.WriteThrough(inverse.child_hash, inverse));
                    previous_history = inverse.history_commitment;
                }
                previous = std::move(list);
            }
        }
        deterministicMNManager = std::make_unique<CDeterministicMNManager>(dmn_params);
        LOCK(cs_main);
        BOOST_REQUIRE(deterministicMNManager->VerifyInverseJournalTipSeal(tip));
        for (const auto* index : {tip->pprev, tip}) {
            PQRegistryReadView view;
            std::string error;
            BOOST_REQUIRE_MESSAGE(deterministicMNManager->GetPQRegistryReadView(
                index, view, error), error);
            BOOST_REQUIRE(view.FindOperator(Provider(UNCHANGED)));
        }
        deterministicMNManager->UpdatedBlockTip(tip);
    }

    CNode& AddCompletedPeer(std::size_t member, bool parent_authority = false)
    {
        const auto& key{parent_authority ? m_parent_keys[member] : m_tip_keys[member]};
        const auto& service{parent_authority ? m_parent_services[member] : m_tip_services[member]};
        auto* node = new CNode{
            static_cast<NodeId>(100 + member + (parent_authority ? 10 : 0)),
            nullptr, CAddress{service, NODE_NETWORK}, 42, 1, CAddress{},
            std::string{}, ConnectionType::OUTBOUND_FULL_RELAY, false};
        connman.AddTestNode(*node);
        node->fSuccessfullyConnected = true;
        node->m_masternode_connection = true;
        node->SetCommonVersion(PQ_MNAUTH_PROTO_VERSION);
        node->SetVerifiedMasternode(Provider(member), ::Hash(key.public_key),
                                   key.key_version, service);
        node->SetMNAuthPending(CMNAuthPendingPhase::COMPLETE, 0);
        return *node;
    }

    CNode& AddUnverifiedPeer()
    {
        auto* node = new CNode{
            200, nullptr, CAddress{Service(99), NODE_NETWORK}, 42, 1,
            CAddress{}, std::string{}, ConnectionType::INBOUND, false};
        connman.AddTestNode(*node);
        node->fSuccessfullyConnected = true;
        node->SetCommonVersion(PQ_MNAUTH_PROTO_VERSION);
        return *node;
    }

    std::shared_ptr<CBlock> ReadBlock(const CBlockIndex* index)
    {
        auto block{std::make_shared<CBlock>()};
        BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(*block, *index));
        return block;
    }
};

class ValidationRegistration {
    CValidationInterface& m_subscriber;

public:
    explicit ValidationRegistration(CValidationInterface& subscriber)
        : m_subscriber{subscriber}
    {
        SyncWithValidationInterfaceQueue();
        RegisterValidationInterface(&m_subscriber);
    }
    ~ValidationRegistration()
    {
        UnregisterValidationInterface(&m_subscriber);
        SyncWithValidationInterfaceQueue();
    }
};

class InboundPeerRegistration {
    PeerManager& m_peerman;
    CNode& m_node;

public:
    InboundPeerRegistration(PeerManager& peerman, CNode& node)
        : m_peerman{peerman}, m_node{node}
    {
        BOOST_REQUIRE(node.IsInboundConn());
        peerman.InitializeNode(node, NODE_NETWORK);
        BOOST_REQUIRE(peerman.GetPeerRef(node.GetId()));
    }
    ~InboundPeerRegistration() { m_peerman.FinalizeNode(m_node); }

    void CheckNoPenalty() const
    {
        const auto peer{m_peerman.GetPeerRef(m_node.GetId())};
        BOOST_REQUIRE(peer);
        LOCK(peer->m_misbehavior_mutex);
        BOOST_CHECK_EQUAL(peer->m_misbehavior_score, 0);
        BOOST_CHECK(!peer->m_should_discourage);
    }
};

enum class AuthorityReadFailure { REGISTRY, DETERMINISTIC_LIST };

void FailNextAuthorityRead(AuthorityReadFailure failure)
{
    if (failure == AuthorityReadFailure::REGISTRY) {
        llmq::pq::test::PQRegistryReadErrorTestAccess::FailNextRead(
            *deterministicMNManager);
    } else {
        // Exercise the same pending-flush dbwrapper_error on the second
        // authority source, even when its requested list is cached.
        deterministicMNManager->m_evoDb->EraseCache(uint256{});
        deterministicMNManager->m_evoDb->FailNextFlushBatchForTesting();
    }
}

class RollbackNotifications final : public CValidationInterface {
public:
    unsigned disconnected{0};
    unsigned connected{0};
    unsigned updated_tips{0};

    void BlockDisconnected(const std::shared_ptr<const CBlock>&,
                           const CBlockIndex*) override { ++disconnected; }
    void BlockConnected(ChainstateRole, const std::shared_ptr<const CBlock>&,
                        const CBlockIndex*) override { ++connected; }
    void UpdatedBlockTip(const CBlockIndex*, const CBlockIndex*,
                         ChainstateManager&, bool) override { ++updated_tips; }
};

// Keep the actual Init path inexpensive: regtest accepts the loopback service,
// and its existing commitment stub avoids requesting a full child-key tree.
class ActiveOperatorTipFixture {
    struct RuntimeOptions {
        const bool original_listen{fListen};
        const std::string original_stub{
            gArgs.GetArg("-pqoperatorcommitmentteststub", "0")};
        RuntimeOptions()
        {
            fListen = false;
            gArgs.ForceSetArg("-pqoperatorcommitmentteststub", "1");
        }
        ~RuntimeOptions()
        {
            fListen = original_listen;
            gArgs.ForceSetArg("-pqoperatorcommitmentteststub", original_stub);
        }
    } m_options;

public:
    CompletionPublicationFixture publication;
    CActiveMasternodeManager active;
    const CBlockIndex* const tip;
    const std::shared_ptr<LocalOperatorKeyManager> key_manager;
    const ActiveChildKeyCache* const child_cache;

    explicit ActiveOperatorTipFixture(TestingSetup& fixture)
        : publication{fixture, /*outbound=*/true, /*rotate_key=*/false,
                      /*active_manager_setup=*/true},
          active{publication.connman},
          tip{WITH_LOCK(cs_main, return publication.chainman.ActiveTip())},
          key_manager{WITH_LOCK(activeMasternodeInfoCs,
              return activeMasternodeInfo.operatorKeyManager)},
          child_cache{[&] {
              LOCK(activeMasternodeInfoCs);
              activeMasternodeInfo.proTxHash.SetNull();
              activeMasternodeInfo.globalKeyVersion = 0;
              activeMasternodeInfo.outpoint.SetNull();
              ++activeMasternodeInfo.identityGeneration;
              activeMasternodeInfo.childKeyCache =
                  std::make_unique<ActiveChildKeyCache>(
                      *key_manager, fixture.m_path_root / "tip-child-cache");
              return activeMasternodeInfo.childKeyCache.get();
          }()}
    {
    }

    ~ActiveOperatorTipFixture() { SyncWithValidationInterfaceQueue(); }

    void InitReady()
    {
        BOOST_CHECK_NO_THROW(active.Init(tip));
        BOOST_REQUIRE_EQUAL(active.GetStateString(), "READY");
        CheckRetained();
    }

    void Notify()
    {
        GetMainSignals().UpdatedBlockTip(
            tip, tip->pprev, publication.chainman, /*fInitialDownload=*/false);
        SyncWithValidationInterfaceQueue();
    }

    ActiveChildSigningMaterial Lease() const
    {
        LOCK(activeMasternodeInfoCs);
        ActiveChildSigningMaterial lease;
        lease.active_key_manager = activeMasternodeInfo.operatorKeyManager;
        lease.active_global_key_version = activeMasternodeInfo.globalKeyVersion;
        lease.active_identity_generation = activeMasternodeInfo.identityGeneration;
        return lease;
    }

    void CheckRetained() const
    {
        LOCK(activeMasternodeInfoCs);
        BOOST_CHECK(activeMasternodeInfo.operatorKeyManager == key_manager);
        BOOST_CHECK(activeMasternodeInfo.childKeyCache.get() == child_cache);
        BOOST_CHECK(key_manager->IsValid());
    }

    void CheckInactive() const
    {
        uint256 provider;
        uint32_t version{0};
        GlobalPublicKey public_key{};
        CService service;
        BOOST_CHECK(!GetActiveMasternodeIdentity(provider, version, public_key, service));
        GlobalSignature signature;
        signature.fill(1);
        BOOST_CHECK(!SignActiveMasternodeMNAUTH(
            publication.context.connection.local.pro_tx_hash,
            publication.context.local_key.key_version, NonNullHash(70'006), signature));
        BOOST_CHECK(std::all_of(signature.begin(), signature.end(),
                                [](uint8_t value) { return value == 0; }));
        LOCK(activeMasternodeInfoCs);
        BOOST_CHECK(activeMasternodeInfo.proTxHash.IsNull());
        BOOST_CHECK_EQUAL(activeMasternodeInfo.globalKeyVersion, 0U);
        BOOST_CHECK(activeMasternodeInfo.outpoint.IsNull());
        CheckRetained();
    }
};

class TipReadFault final : public CValidationInterface {
public:
    std::optional<AuthorityReadFailure> next_failure;
    unsigned injected{0};

    void UpdatedBlockTip(const CBlockIndex*, const CBlockIndex*,
                         ChainstateManager&, bool) override
    {
        if (const auto failure{std::exchange(next_failure, std::nullopt)}) {
            FailNextAuthorityRead(*failure);
            ++injected;
        }
    }
};

// The default fixture initializes a disabled global overlay. Supply a real
// overlay with an eligible schedule so queued CDS notifications reach its
// registry read, without starting the unrelated finality worker.
class TipOverlayGuard {
    static FrozenQuorumRosterCachePtr Cache()
    {
        QuorumBuildConfig config;
        const auto schedule{MakeChainLockScheduleConfig(
            Params().GetConsensus().nPQChainLockEpochOrigin)};
        BOOST_REQUIRE(schedule);
        config.schedule = *schedule;
        config.roster_snapshot_lag_blocks = 144;
        config.registration_cutoff_blocks = 144;
        config.future_horizon_epochs = 8;
        auto cache{FrozenQuorumRosterCache::Create(
            Params().GetConsensus().hashGenesisBlock, config,
            [](const CBlockIndex&) -> std::optional<QuorumSnapshotState> {
                return std::nullopt;
            })};
        BOOST_REQUIRE(cache);
        return cache;
    }

public:
    llmq::CPQQuorumConnectionOverlay overlay;

private:
    llmq::CPQQuorumConnectionOverlay* const m_original;

public:
    explicit TipOverlayGuard(CConnman& connman)
        : overlay{connman, Cache(), [] { return std::optional<int32_t>{2304}; }},
          m_original{llmq::pqQuorumConnectionOverlay}
    {
        BOOST_REQUIRE(m_original);
        BOOST_REQUIRE(llmq::chainLocksHandler);
        BOOST_REQUIRE(!llmq::chainLocksHandler->GetBestChainLock());
        llmq::pqQuorumConnectionOverlay = &overlay;
    }

    ~TipOverlayGuard()
    {
        SyncWithValidationInterfaceQueue();
        llmq::pqQuorumConnectionOverlay = m_original;
    }
};

bool HasQueuedMNAUTH(CNode& node)
{
    LOCK(node.cs_vSend);
    if (!node.vSendMsg.empty()) return node.vSendMsg.front().m_type == NetMsgType::MNAUTH;
    const auto& [bytes, more, command]{node.m_transport->GetBytesToSend(false)};
    return !bytes.empty() && command == NetMsgType::MNAUTH;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_mnauth_tests)

BOOST_FIXTURE_TEST_CASE(queued_tip_authority_errors_preserve_overlay_and_revoke_leases,
                        RegTestingSetup)
{
    ActiveOperatorTipFixture fixture{*this};
    fixture.InitReady();
    TipOverlayGuard overlay{fixture.publication.connman};
    const uint256 relay_member{NonNullHash(70'001)};
    const uint256 audit_member{NonNullHash(70'002)};
    BOOST_REQUIRE(overlay.overlay.ApplyPreparedContext(
        NonNullHash(70'003), {relay_member}, std::nullopt));
    BOOST_REQUIRE(overlay.overlay.ApplyPaymentAuditContext(
        NonNullHash(70'004), {audit_member}, 1));

    TipReadFault overlay_fault;
    CDSNotificationInterface ds{fixture.publication.connman,
                                fixture.publication.peerman};
    TipReadFault active_fault;
    RollbackNotifications notifications;
    ValidationRegistration arm_overlay{overlay_fault};
    ValidationRegistration register_ds{ds};
    ValidationRegistration arm_active{active_fault};
    ValidationRegistration register_active{fixture.active};
    ValidationRegistration observe{notifications};
    const auto& provider{fixture.publication.context.connection.local.pro_tx_hash};
    const auto original_lease{fixture.Lease()};
    BOOST_REQUIRE(IsActiveMasternodeChildSigningMaterialCurrent(provider, original_lease));

    // The active subscriber must keep its identity unchanged: this proves the
    // overlay consumed the throwing read before any later authority consumer.
    overlay_fault.next_failure = AuthorityReadFailure::REGISTRY;
    {
        ASSERT_DEBUG_LOG("PQ overlay local authority read failed:");
        BOOST_CHECK_NO_THROW(fixture.Notify());
    }
    BOOST_CHECK_EQUAL(overlay_fault.injected, 1U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 1U);
    BOOST_CHECK(IsActiveMasternodeChildSigningMaterialCurrent(provider, original_lease));
    BOOST_CHECK(fixture.publication.connman.IsMasternodeQuorumRelayMember(relay_member));
    BOOST_CHECK(fixture.publication.connman.IsMasternodeQuorumRelayMember(audit_member));

    for (const auto failure : {AuthorityReadFailure::REGISTRY,
                               AuthorityReadFailure::DETERMINISTIC_LIST}) {
        const auto lease{fixture.Lease()};
        BOOST_REQUIRE(IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        active_fault.next_failure = failure;
        BOOST_CHECK_NO_THROW(fixture.Notify());
        // READY intentionally retries Init in the same notification. A
        // readable retry can restore the same identity, but never its lease.
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "READY");
        BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        BOOST_CHECK(IsActiveMasternodeChildSigningMaterialCurrent(provider, fixture.Lease()));
        fixture.CheckRetained();
        BOOST_CHECK(fixture.publication.connman.IsMasternodeQuorumRelayMember(relay_member));
        BOOST_CHECK(fixture.publication.connman.IsMasternodeQuorumRelayMember(audit_member));
    }
    BOOST_CHECK_EQUAL(active_fault.injected, 2U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 3U);
    BOOST_CHECK_NO_THROW(fixture.Notify());
    BOOST_CHECK_EQUAL(notifications.updated_tips, 4U);
    BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "READY");
}

BOOST_FIXTURE_TEST_CASE(active_operator_init_authority_errors_clear_identity_and_recover,
                        RegTestingSetup)
{
    ActiveOperatorTipFixture fixture{*this};
    TipReadFault fault;
    RollbackNotifications notifications;
    ValidationRegistration arm{fault};
    ValidationRegistration register_active{fixture.active};
    ValidationRegistration observe{notifications};
    const auto& provider{fixture.publication.context.connection.local.pro_tx_hash};

    for (const auto failure : {AuthorityReadFailure::REGISTRY,
                               AuthorityReadFailure::DETERMINISTIC_LIST}) {
        // A failed direct re-init also revokes an already published identity.
        fixture.InitReady();
        const auto lease{fixture.Lease()};
        BOOST_REQUIRE(IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        FailNextAuthorityRead(failure);
        BOOST_CHECK_NO_THROW(fixture.active.Init(fixture.tip));
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "ERROR");
        fixture.CheckInactive();
        BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));

        // The non-READY notification branch shares Init's exception boundary.
        fault.next_failure = failure;
        BOOST_CHECK_NO_THROW(fixture.Notify());
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "ERROR");
        fixture.CheckInactive();
        BOOST_CHECK_NO_THROW(fixture.Notify());
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "READY");
        fixture.CheckRetained();
        BOOST_CHECK(IsActiveMasternodeChildSigningMaterialCurrent(provider, fixture.Lease()));
        BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
    }
    BOOST_CHECK_EQUAL(fault.injected, 2U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 4U);
}

BOOST_FIXTURE_TEST_CASE(active_operator_missing_or_invalid_dmn_snapshot_recovers,
                        RegTestingSetup)
{
    ActiveOperatorTipFixture fixture{*this};
    fixture.InitReady();
    RollbackNotifications notifications;
    ValidationRegistration register_active{fixture.active};
    ValidationRegistration observe{notifications};
    const auto& provider{fixture.publication.context.connection.local.pro_tx_hash};
    const auto saved_list{deterministicMNManager->GetListForBlock(fixture.tip)};

    for (const bool missing : {true, false}) {
        const auto lease{fixture.Lease()};
        BOOST_REQUIRE(IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        if (missing) {
            deterministicMNManager->m_evoDb->EraseCache(fixture.tip->GetBlockHash());
        } else {
            deterministicMNManager->m_evoDb->WriteCache(fixture.tip->GetBlockHash(),
                CDeterministicMNList{NonNullHash(70'005), fixture.tip->nHeight, 0});
        }
        BOOST_CHECK_NO_THROW(fixture.Notify());
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "ERROR");
        fixture.CheckInactive();
        BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        deterministicMNManager->m_evoDb->WriteCache(fixture.tip->GetBlockHash(), saved_list);
        BOOST_CHECK_NO_THROW(fixture.Notify());
        BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "READY");
        BOOST_CHECK(IsActiveMasternodeChildSigningMaterialCurrent(provider, fixture.Lease()));
        BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
        fixture.CheckRetained();
    }
    BOOST_CHECK_EQUAL(notifications.updated_tips, 4U);
}

BOOST_FIXTURE_TEST_CASE(active_operator_dmn_removal_survives_registry_read_failure,
                        RegTestingSetup)
{
    ActiveOperatorTipFixture fixture{*this};
    fixture.InitReady();
    TipReadFault fault;
    RollbackNotifications notifications;
    ValidationRegistration arm{fault};
    ValidationRegistration register_active{fixture.active};
    ValidationRegistration observe{notifications};
    const auto& provider{fixture.publication.context.connection.local.pro_tx_hash};
    const auto saved_list{deterministicMNManager->GetListForBlock(fixture.tip)};
    const auto lease{fixture.Lease()};
    BOOST_REQUIRE(IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
    auto removed_list{saved_list};
    removed_list.RemoveMN(provider);
    deterministicMNManager->m_evoDb->WriteCache(fixture.tip->GetBlockHash(), removed_list);
    fault.next_failure = AuthorityReadFailure::REGISTRY;
    BOOST_CHECK_NO_THROW(fixture.Notify());
    // The successful DMN read remains authoritative despite the later failed
    // registry read; Init's readable retry cannot restore a removed operator.
    BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "REMOVED");
    fixture.CheckInactive();
    BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
    BOOST_CHECK_EQUAL(fault.injected, 1U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 1U);

    deterministicMNManager->m_evoDb->WriteCache(fixture.tip->GetBlockHash(), saved_list);
    BOOST_CHECK_NO_THROW(fixture.Notify());
    BOOST_CHECK_EQUAL(fixture.active.GetStateString(), "READY");
    BOOST_CHECK(IsActiveMasternodeChildSigningMaterialCurrent(provider, fixture.Lease()));
    BOOST_CHECK(!IsActiveMasternodeChildSigningMaterialCurrent(provider, lease));
    fixture.CheckRetained();
    BOOST_CHECK_EQUAL(notifications.updated_tips, 2U);
}

BOOST_FIXTURE_TEST_CASE(rollback_only_notifications_retire_completed_authentication,
                        TestChain100Setup)
{
    RollbackNotificationFixture fixture{*this};
    CNode& rotated{fixture.AddCompletedPeer(RollbackNotificationFixture::KEY_CHANGED)};
    CNode& moved{fixture.AddCompletedPeer(RollbackNotificationFixture::SERVICE_CHANGED)};
    CNode& unchanged{fixture.AddCompletedPeer(RollbackNotificationFixture::UNCHANGED)};
    RollbackNotifications notifications;
    ValidationRegistration observe{notifications};
    ValidationRegistration register_peerman{fixture.peerman};

    BlockValidationState invalidate_state;
    BOOST_REQUIRE_MESSAGE(fixture.chainman.ActiveChainstate().InvalidateBlock(
        invalidate_state, fixture.tip), invalidate_state.ToString());
    BlockValidationState activate_state;
    BOOST_REQUIRE_MESSAGE(fixture.chainman.ActiveChainstate().ActivateBestChain(
        activate_state), activate_state.ToString());
    SyncWithValidationInterfaceQueue();

    BOOST_CHECK(WITH_LOCK(cs_main, return fixture.chainman.ActiveTip()) == fixture.tip->pprev);
    BOOST_CHECK_EQUAL(notifications.disconnected, 1U);
    BOOST_CHECK_EQUAL(notifications.connected, 0U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 0U);
    BOOST_CHECK(rotated.fDisconnect);
    BOOST_CHECK(moved.fDisconnect);
    BOOST_CHECK(!unchanged.fDisconnect);
    BOOST_CHECK(unchanged.GetMNAuthPending().phase == CMNAuthPendingPhase::COMPLETE);
}

BOOST_FIXTURE_TEST_CASE(historical_disconnect_notification_uses_current_authentication_authority,
                        TestChain100Setup)
{
    RollbackNotificationFixture fixture{*this};
    CNode& rotated{fixture.AddCompletedPeer(RollbackNotificationFixture::KEY_CHANGED)};
    CNode& moved{fixture.AddCompletedPeer(RollbackNotificationFixture::SERVICE_CHANGED)};
    CNode& unchanged{fixture.AddCompletedPeer(RollbackNotificationFixture::UNCHANGED)};
    CNode& old_key{fixture.AddCompletedPeer(RollbackNotificationFixture::KEY_CHANGED,
                                          /*parent_authority=*/true)};
    CNode& old_service{fixture.AddCompletedPeer(RollbackNotificationFixture::SERVICE_CHANGED,
                                              /*parent_authority=*/true)};
    ValidationRegistration register_peerman{fixture.peerman};

    // Deliver an older event after the actual active tip already names the
    // successor. The production subscriber must resolve authority at that tip.
    GetMainSignals().BlockDisconnected(fixture.ReadBlock(fixture.tip->pprev),
                                       fixture.tip->pprev);
    SyncWithValidationInterfaceQueue();

    BOOST_CHECK(WITH_LOCK(cs_main, return fixture.chainman.ActiveTip()) == fixture.tip);
    BOOST_CHECK(!rotated.fDisconnect);
    BOOST_CHECK(!moved.fDisconnect);
    BOOST_CHECK(!unchanged.fDisconnect);
    BOOST_CHECK(old_key.fDisconnect);
    BOOST_CHECK(old_service.fDisconnect);
}

BOOST_FIXTURE_TEST_CASE(private_and_failed_undo_preserve_current_authentication,
                        TestChain100Setup)
{
    RollbackNotificationFixture fixture{*this};
    CNode& rotated{fixture.AddCompletedPeer(RollbackNotificationFixture::KEY_CHANGED)};
    CNode& moved{fixture.AddCompletedPeer(RollbackNotificationFixture::SERVICE_CHANGED)};
    CNode& unchanged{fixture.AddCompletedPeer(RollbackNotificationFixture::UNCHANGED)};
    RollbackNotifications notifications;
    ValidationRegistration observe{notifications};
    ValidationRegistration register_peerman{fixture.peerman};
    const auto block{fixture.ReadBlock(fixture.tip)};
    {
        LOCK(cs_main);
        CCoinsViewCache private_view{&fixture.chainman.ActiveChainstate().CoinsTip()};
        NEVMMintTxSet mint_txs;
        std::vector<uint256> nevm_blocks;
        std::vector<std::pair<uint256, uint32_t>> txid_pairs;
        BOOST_REQUIRE(fixture.chainman.ActiveChainstate().DisconnectBlock(
            *block, fixture.tip, private_view, mint_txs, nevm_blocks, txid_pairs) == DISCONNECT_OK);
        BOOST_CHECK(private_view.GetBestBlock() == fixture.tip->pprev->GetBlockHash());
        BOOST_CHECK(fixture.chainman.ActiveChainstate().CoinsTip().GetBestBlock() ==
                    fixture.tip->GetBlockHash());
    }
    SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!rotated.fDisconnect);
    BOOST_CHECK(!moved.fDisconnect);
    BOOST_CHECK(!unchanged.fDisconnect);
    BOOST_REQUIRE(deterministicMNManager->CorruptInverseJournalForTesting(
        fixture.tip->GetBlockHash()));
    BlockValidationState state;
    BOOST_CHECK(!fixture.chainman.ActiveChainstate().InvalidateBlock(state, fixture.tip));
    SyncWithValidationInterfaceQueue();

    BOOST_CHECK(WITH_LOCK(cs_main, return fixture.chainman.ActiveTip()) == fixture.tip);
    BOOST_CHECK_EQUAL(notifications.disconnected, 0U);
    BOOST_CHECK_EQUAL(notifications.connected, 0U);
    BOOST_CHECK_EQUAL(notifications.updated_tips, 0U);
    BOOST_CHECK(!rotated.fDisconnect);
    BOOST_CHECK(!moved.fDisconnect);
    BOOST_CHECK(!unchanged.fDisconnect);
}


BOOST_FIXTURE_TEST_CASE(completions_after_tip_change_do_not_publish_or_retire_duplicates,
                        RegTestingSetup)
{
    for (const bool sign : {false, true}) {
        CompletionPublicationFixture fixture{*this, /*outbound=*/true, /*rotate_key=*/!sign};
        CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{}, fixture.Hooks()};
        CNode& node{fixture.AddNode(100)};
        CNode& duplicate{fixture.AddNode(200)};
        duplicate.SetVerifiedMasternode(
            fixture.context.connection.remote.pro_tx_hash,
            ::Hash(fixture.next_remote_key.public_key),
            fixture.next_remote_key.key_version, fixture.next_remote_service);
        BOOST_REQUIRE(async.RegisterPeer(node.GetId()));
        if (sign) fixture.QueueSign(node, async);
        else fixture.QueueVerify(node, async);

        fixture.AdvanceTip();
        BOOST_REQUIRE(!duplicate.fDisconnect);
        CMNAuth::ProcessAsyncCompletions(
            async, fixture.chainman, fixture.connman, fixture.peerman);
        BOOST_CHECK(node.fDisconnect);
        BOOST_CHECK(!duplicate.fDisconnect);
        BOOST_CHECK(node.GetVerifiedProRegTxHash().IsNull());
        BOOST_CHECK(!HasQueuedMNAUTH(node));
        BOOST_CHECK(node.GetMNAuthPending().phase != CMNAuthPendingPhase::COMPLETE);
        BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops, 1U);
    }
}

BOOST_FIXTURE_TEST_CASE(current_completions_publish_before_tip_cleanup,
                        RegTestingSetup)
{
    for (const bool outbound : {false, true}) {
        CompletionPublicationFixture fixture{*this, outbound, /*rotate_key=*/outbound};
        CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{}, fixture.Hooks()};
        CNode& node{fixture.AddNode(100)};
        CNode& duplicate{fixture.AddNode(200)};
        duplicate.SetVerifiedMasternode(
            fixture.context.connection.remote.pro_tx_hash,
            ::Hash(fixture.context.remote_key.public_key),
            fixture.context.remote_key.key_version, fixture.context.remote_service);
        BOOST_REQUIRE(async.RegisterPeer(node.GetId()));
        if (outbound) {
            fixture.QueueSign(node, async);
            fixture.ProcessGuarded(async, [&] {
                return !node.fDisconnect && HasQueuedMNAUTH(node) &&
                    node.GetMNAuthPending().phase == CMNAuthPendingPhase::AWAITING_REMOTE;
            });
        }
        fixture.QueueVerify(node, async);
        const auto published = [&] {
            return !node.fDisconnect && duplicate.fDisconnect &&
                node.GetVerifiedProRegTxHash() == fixture.context.connection.remote.pro_tx_hash &&
                node.GetVerifiedGlobalKeyVersion() == fixture.context.remote_key.key_version &&
                node.GetVerifiedMasternodeService() == fixture.context.remote_service;
        };
        fixture.ProcessGuarded(async, [&] {
            return published() && node.GetMNAuthPending().phase ==
                (outbound ? CMNAuthPendingPhase::COMPLETE : CMNAuthPendingPhase::SIGN_PENDING);
        }, /*advance_tip=*/outbound);
        if (!outbound) {
            fixture.WaitForCompletion();
            fixture.ProcessGuarded(async, [&] {
                return published() && HasQueuedMNAUTH(node) &&
                    node.GetMNAuthPending().phase == CMNAuthPendingPhase::COMPLETE;
            }, /*advance_tip=*/true);
        }
        // The serialized tip transition sees the published remote identity and
        // retires it on either key rotation or service replacement.
        BOOST_CHECK(node.fDisconnect);
        BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops, 0U);
        BOOST_CHECK_EQUAL(async.GetStats().verify_completed, 1U);
        BOOST_CHECK_EQUAL(async.GetStats().sign_completed, 1U);
    }
}

BOOST_FIXTURE_TEST_CASE(authority_read_errors_drop_one_completion_and_preserve_batch_progress,
                        RegTestingSetup)
{
    for (const auto failure : {AuthorityReadFailure::REGISTRY,
                               AuthorityReadFailure::DETERMINISTIC_LIST}) {
        for (const bool sign : {false, true}) {
            CompletionPublicationFixture fixture{*this, /*outbound=*/true, /*rotate_key=*/false};
            CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{}, fixture.Hooks()};
            CNode& rejected{fixture.AddNode(100)};
            CNode& sibling{fixture.AddNode(50)};
            CNode& duplicate{fixture.AddNode(200)};
            duplicate.SetVerifiedMasternode(
                fixture.context.connection.remote.pro_tx_hash,
                ::Hash(fixture.context.remote_key.public_key),
                fixture.context.remote_key.key_version, fixture.context.remote_service);
            BOOST_REQUIRE(async.RegisterPeer(rejected.GetId()));
            BOOST_REQUIRE(async.RegisterPeer(sibling.GetId()));
            // Waiting for each completion fixes the mixed batch order while
            // retaining the real queues, registrations and signer latch.
            if (sign) {
                fixture.QueueSign(rejected, async);
                fixture.QueueVerify(sibling, async);
            } else {
                fixture.QueueVerify(rejected, async);
                fixture.QueueSign(sibling, async);
            }
            BOOST_REQUIRE_EQUAL(async.GetStats().completion_queue_depth, 2U);
            FailNextAuthorityRead(failure);
            unsigned validated{0};
            BOOST_CHECK_NO_THROW(mnauth_tests::CMNAuthTestAccess::Process(
                async, fixture.chainman, fixture.connman, fixture.peerman, [&] {
                    ++validated;
                    // Observe the rejected attempt before its readable
                    // sibling can legitimately publish or retire a duplicate.
                    BOOST_CHECK(rejected.fDisconnect);
                    BOOST_CHECK(rejected.GetVerifiedProRegTxHash().IsNull());
                    BOOST_CHECK(!HasQueuedMNAUTH(rejected));
                    BOOST_CHECK(!duplicate.fDisconnect);
                }));
            BOOST_CHECK_EQUAL(validated, 1U);
            BOOST_CHECK(rejected.fDisconnect);
            BOOST_CHECK(rejected.GetVerifiedProRegTxHash().IsNull());
            BOOST_CHECK(!HasQueuedMNAUTH(rejected));
            BOOST_CHECK(rejected.GetMNAuthPending().phase != CMNAuthPendingPhase::COMPLETE);
            BOOST_CHECK(!sibling.fDisconnect);
            if (sign) {
                BOOST_CHECK(sibling.GetVerifiedProRegTxHash() ==
                            fixture.context.connection.remote.pro_tx_hash);
                BOOST_CHECK(sibling.GetMNAuthPending().phase == CMNAuthPendingPhase::COMPLETE);
                BOOST_CHECK(duplicate.fDisconnect);
            } else {
                BOOST_CHECK(HasQueuedMNAUTH(sibling));
                BOOST_CHECK(sibling.GetMNAuthPending().phase == CMNAuthPendingPhase::AWAITING_REMOTE);
                BOOST_CHECK(!duplicate.fDisconnect);
            }
            const auto stats{async.GetStats()};
            BOOST_CHECK_EQUAL(stats.verify_completed, 1U);
            BOOST_CHECK_EQUAL(stats.sign_completed, 1U);
            BOOST_CHECK_EQUAL(stats.verify_failed, 0U);
            BOOST_CHECK_EQUAL(stats.sign_failed, 0U);
            BOOST_CHECK_EQUAL(stats.stale_completion_drops, 1U);
            BOOST_CHECK_EQUAL(stats.completion_queue_depth, 0U);
            BOOST_CHECK_EQUAL(stats.verify_inflight, 0U);
            BOOST_CHECK_EQUAL(stats.sign_inflight, 0U);

            // No cancellation or manual acknowledgement releases the first
            // SIGN. A new private-key job can finish only after its exact
            // completion was acknowledged by the production drain.
            CNode& recovered{fixture.AddNode(75)};
            BOOST_REQUIRE(async.RegisterPeer(recovered.GetId()));
            fixture.QueueSign(recovered, async);
            BOOST_CHECK_NO_THROW(CMNAuth::ProcessAsyncCompletions(
                async, fixture.chainman, fixture.connman, fixture.peerman));
            BOOST_CHECK(!recovered.fDisconnect);
            BOOST_CHECK(HasQueuedMNAUTH(recovered));
            BOOST_CHECK(recovered.GetMNAuthPending().phase == CMNAuthPendingPhase::AWAITING_REMOTE);
            BOOST_CHECK_EQUAL(async.GetStats().sign_completed, 2U);
            BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops, 1U);
            BOOST_CHECK_EQUAL(async.GetStats().completion_queue_depth, 0U);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(inbound_authority_read_errors_do_not_punish_or_schedule_response,
                        RegTestingSetup)
{
    for (const auto failure : {AuthorityReadFailure::REGISTRY,
                               AuthorityReadFailure::DETERMINISTIC_LIST}) {
        for (const bool after_validation : {false, true}) {
            CompletionPublicationFixture fixture{*this, /*outbound=*/false, /*rotate_key=*/false};
            CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{}, fixture.Hooks()};
            CNode& rejected{fixture.AddNode(100)};
            InboundPeerRegistration registration{fixture.peerman, rejected};
            CNode& duplicate{fixture.AddNode(200)};
            duplicate.SetVerifiedMasternode(
                fixture.context.connection.remote.pro_tx_hash,
                ::Hash(fixture.context.remote_key.public_key),
                fixture.context.remote_key.key_version, fixture.context.remote_service);
            BOOST_REQUIRE(async.RegisterPeer(rejected.GetId()));
            fixture.QueueVerify(rejected, async);
            unsigned validated{0};
            if (!after_validation) FailNextAuthorityRead(failure);
            BOOST_CHECK_NO_THROW(mnauth_tests::CMNAuthTestAccess::Process(
                async, fixture.chainman, fixture.connman, fixture.peerman, [&] {
                    ++validated;
                    // Arm the actual database read after initial revalidation
                    // to exercise the inbound authenticated-context rebuild.
                    BOOST_REQUIRE(after_validation);
                    FailNextAuthorityRead(failure);
                }));
            BOOST_CHECK_EQUAL(validated, after_validation ? 1U : 0U);
            BOOST_CHECK(rejected.fDisconnect);
            BOOST_CHECK(!HasQueuedMNAUTH(rejected));
            BOOST_CHECK(rejected.GetMNAuthPending().phase != CMNAuthPendingPhase::COMPLETE);
            registration.CheckNoPenalty();
            if (after_validation) {
                // The first read authorized publication. The second local
                // read must fail closed before any responder signing work.
                BOOST_CHECK(rejected.GetVerifiedProRegTxHash() ==
                            fixture.context.connection.remote.pro_tx_hash);
                BOOST_CHECK(duplicate.fDisconnect);
            } else {
                BOOST_CHECK(rejected.GetVerifiedProRegTxHash().IsNull());
                BOOST_CHECK(!duplicate.fDisconnect);
            }
            BOOST_CHECK_EQUAL(async.GetStats().verify_completed, 1U);
            BOOST_CHECK_EQUAL(async.GetStats().verify_failed, 0U);
            BOOST_CHECK_EQUAL(async.GetStats().sign_completed, 0U);
            BOOST_CHECK_EQUAL(async.GetStats().sign_queue_depth, 0U);
            BOOST_CHECK_EQUAL(async.GetStats().sign_inflight, 0U);
            BOOST_CHECK_EQUAL(async.GetStats().completion_queue_depth, 0U);
            BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops,
                              after_validation ? 0U : 1U);

            CNode& recovered{fixture.AddNode(50)};
            InboundPeerRegistration recovered_registration{fixture.peerman, recovered};
            BOOST_REQUIRE(async.RegisterPeer(recovered.GetId()));
            fixture.QueueVerify(recovered, async);
            BOOST_CHECK_NO_THROW(CMNAuth::ProcessAsyncCompletions(
                async, fixture.chainman, fixture.connman, fixture.peerman));
            BOOST_REQUIRE(!recovered.fDisconnect);
            BOOST_CHECK(recovered.GetVerifiedProRegTxHash() ==
                        fixture.context.connection.remote.pro_tx_hash);
            BOOST_CHECK(recovered.GetMNAuthPending().phase == CMNAuthPendingPhase::SIGN_PENDING);
            fixture.WaitForCompletion();
            BOOST_CHECK_NO_THROW(CMNAuth::ProcessAsyncCompletions(
                async, fixture.chainman, fixture.connman, fixture.peerman));
            BOOST_CHECK(!recovered.fDisconnect);
            BOOST_CHECK(HasQueuedMNAUTH(recovered));
            BOOST_CHECK(recovered.GetMNAuthPending().phase == CMNAuthPendingPhase::COMPLETE);
            recovered_registration.CheckNoPenalty();
            BOOST_CHECK_EQUAL(async.GetStats().verify_completed, 2U);
            BOOST_CHECK_EQUAL(async.GetStats().sign_completed, 1U);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(missing_deterministic_authority_drops_sign_and_recovers_after_restore,
                        RegTestingSetup)
{
    CompletionPublicationFixture fixture{*this, /*outbound=*/true, /*rotate_key=*/false};
    CMNAuth::AsyncProcessor async{CMNAuth::AsyncConfig{}, fixture.Hooks()};
    CNode& rejected{fixture.AddNode(100)};
    BOOST_REQUIRE(async.RegisterPeer(rejected.GetId()));
    fixture.QueueSign(rejected, async);
    const auto* tip{WITH_LOCK(cs_main, return fixture.chainman.ActiveTip())};
    const auto saved_list{deterministicMNManager->GetListForBlock(tip)};
    // An absent persisted snapshot throws std::runtime_error rather than
    // dbwrapper_error. Keep the known list for a subsequent readable attempt.
    deterministicMNManager->m_evoDb->EraseCache(tip->GetBlockHash());
    BOOST_CHECK_NO_THROW(CMNAuth::ProcessAsyncCompletions(
        async, fixture.chainman, fixture.connman, fixture.peerman));
    deterministicMNManager->m_evoDb->WriteCache(tip->GetBlockHash(), saved_list);
    BOOST_CHECK(rejected.fDisconnect);
    BOOST_CHECK(rejected.GetVerifiedProRegTxHash().IsNull());
    BOOST_CHECK(!HasQueuedMNAUTH(rejected));
    BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops, 1U);
    BOOST_CHECK_EQUAL(async.GetStats().completion_queue_depth, 0U);

    CNode& recovered{fixture.AddNode(50)};
    BOOST_REQUIRE(async.RegisterPeer(recovered.GetId()));
    fixture.QueueSign(recovered, async);
    BOOST_CHECK_NO_THROW(CMNAuth::ProcessAsyncCompletions(
        async, fixture.chainman, fixture.connman, fixture.peerman));
    BOOST_CHECK(!recovered.fDisconnect);
    BOOST_CHECK(HasQueuedMNAUTH(recovered));
    BOOST_CHECK_EQUAL(async.GetStats().sign_completed, 2U);
    BOOST_CHECK_EQUAL(async.GetStats().sign_failed, 0U);
    BOOST_CHECK_EQUAL(async.GetStats().stale_completion_drops, 1U);
}

BOOST_FIXTURE_TEST_CASE(notification_authority_read_errors_retire_verified_peers_and_recover,
                        TestChain100Setup)
{
    for (const auto failure : {AuthorityReadFailure::REGISTRY,
                               AuthorityReadFailure::DETERMINISTIC_LIST}) {
        RollbackNotificationFixture fixture{*this};
        CNode& rotated{fixture.AddCompletedPeer(RollbackNotificationFixture::KEY_CHANGED)};
        CNode& moved{fixture.AddCompletedPeer(RollbackNotificationFixture::SERVICE_CHANGED)};
        CNode& unchanged{fixture.AddCompletedPeer(RollbackNotificationFixture::UNCHANGED)};
        CNode& unverified{fixture.AddUnverifiedPeer()};
        RollbackNotifications notifications;
        ValidationRegistration observe{notifications};
        ValidationRegistration register_peerman{fixture.peerman};
        const auto block{fixture.ReadBlock(fixture.tip->pprev)};
        const auto notify = [&] {
            // An already committed historical notification reaches the real
            // PeerManager subscriber without an undo consuming the read fault.
            GetMainSignals().BlockDisconnected(block, fixture.tip->pprev);
            SyncWithValidationInterfaceQueue();
        };
        FailNextAuthorityRead(failure);
        BOOST_CHECK_NO_THROW(notify());
        BOOST_CHECK_EQUAL(notifications.disconnected, 1U);
        BOOST_CHECK(rotated.fDisconnect);
        BOOST_CHECK(moved.fDisconnect);
        BOOST_CHECK(unchanged.fDisconnect);
        BOOST_CHECK(!unverified.fDisconnect);
        BOOST_CHECK(unverified.GetVerifiedProRegTxHash().IsNull());
        BOOST_CHECK(unverified.GetMNAuthPending().phase == CMNAuthPendingPhase::NONE);

        CNode& recovered{fixture.AddCompletedPeer(
            RollbackNotificationFixture::UNCHANGED, /*parent_authority=*/true)};
        BOOST_CHECK_NO_THROW(notify());
        BOOST_CHECK_EQUAL(notifications.disconnected, 2U);
        BOOST_CHECK(!recovered.fDisconnect);
        BOOST_CHECK(recovered.GetMNAuthPending().phase == CMNAuthPendingPhase::COMPLETE);
        BOOST_CHECK(!unverified.fDisconnect);
        BOOST_CHECK(WITH_LOCK(cs_main, return fixture.chainman.ActiveTip()) == fixture.tip);
    }
}

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

BOOST_AUTO_TEST_CASE(async_interrupt_cancels_queues_without_joining_active_hooks)
{
    const auto initiator_key{StoredKey(DeterministicKey(0), 1, 100)};
    const auto responder_key{StoredKey(DeterministicKey(64), 2, 101)};
    const auto transcript{Transcript(initiator_key, responder_key)};
    const auto sign_request = [&](int64_t peer, bool initiator) {
        return AsyncSignRequest(AsyncContext(
            peer, peer, initiator_key, responder_key, transcript,
            initiator, /*authenticated_remote=*/!initiator));
    };
    const auto verify_request = [&](int64_t peer) {
        return AsyncVerifyRequest(
            peer, peer, NonNullHash(1), initiator_key, responder_key,
            Transcript(initiator_key, responder_key, peer));
    };

    std::mutex mutex;
    std::condition_variable cv;
    bool release{false};
    bool hooks_timed_out{false};
    unsigned sign_calls{0};
    unsigned verify_calls{0};
    const auto enter_hook = [&](unsigned& calls) {
        std::unique_lock lock{mutex};
        ++calls;
        cv.notify_all();
        const bool released{cv.wait_for(lock, std::chrono::seconds{30},
                                       [&] { return release; })};
        hooks_timed_out |= !released;
        return released;
    };
    CMNAuth::AsyncHooks hooks;
    hooks.verify = [&](MNAUTHVerificationTask&) { return enter_hook(verify_calls); };
    hooks.sign = [&](const uint256&, uint32_t, const uint256&,
                     GlobalSignature& signature) {
        if (!enter_hook(sign_calls)) return false;
        signature[0] = 1;
        return true;
    };
    CMNAuth::AsyncConfig config;
    config.verify_threads = 1;
    CMNAuth::AsyncProcessor async{config, std::move(hooks)};
    std::promise<void> interrupted;
    auto interrupt_result{interrupted.get_future()};
    std::thread interrupter;
    struct Cleanup {
        CMNAuth::AsyncProcessor& async;
        std::mutex& mutex;
        std::condition_variable& cv;
        bool& release;
        std::thread& interrupter;
        ~Cleanup()
        {
            {
                std::lock_guard lock{mutex};
                release = true;
            }
            cv.notify_all();
            if (interrupter.joinable()) interrupter.join();
            async.Stop();
        }
    } cleanup{async, mutex, cv, release, interrupter};

    for (int64_t peer : {1, 2, 3, 4, 5}) BOOST_REQUIRE(async.RegisterPeer(peer));
    BOOST_REQUIRE(async.EnqueueSign(sign_request(1, true)).Accepted());
    BOOST_REQUIRE(async.EnqueueVerify(verify_request(4)).Accepted());
    {
        std::unique_lock lock{mutex};
        BOOST_REQUIRE(cv.wait_for(lock, std::chrono::seconds{5}, [&] {
            return sign_calls == 1 && verify_calls == 1;
        }));
    }
    BOOST_REQUIRE(async.EnqueueSign(sign_request(2, true)).Accepted());
    BOOST_REQUIRE(async.EnqueueSign(sign_request(3, false)).Accepted());
    BOOST_REQUIRE(async.EnqueueVerify(verify_request(5)).Accepted());
    BOOST_REQUIRE_EQUAL(GetActiveMasternodeGlobalSigningStats().mnauth_demands, 3U);

    interrupter = std::thread{[&] {
        async.Interrupt();
        async.Interrupt();
        interrupted.set_value();
    }};
    // The hooks remain held until after this assertion. Cleanup releases them
    // even if Interrupt regresses into a joining operation.
    BOOST_REQUIRE(interrupt_result.wait_for(std::chrono::seconds{5}) ==
                  std::future_status::ready);
    interrupter.join();
    const auto interrupted_stats{async.GetStats()};
    BOOST_CHECK_EQUAL(interrupted_stats.verify_queue_depth, 0U);
    BOOST_CHECK_EQUAL(interrupted_stats.initiator_sign_queue_depth, 0U);
    BOOST_CHECK_EQUAL(interrupted_stats.responder_sign_queue_depth, 0U);
    BOOST_CHECK_EQUAL(interrupted_stats.verify_inflight, 1U);
    BOOST_CHECK_EQUAL(interrupted_stats.sign_inflight, 1U);
    BOOST_CHECK_EQUAL(interrupted_stats.cancelled_jobs, 3U);
    BOOST_CHECK_EQUAL(GetActiveMasternodeGlobalSigningStats().mnauth_demands, 1U);
    BOOST_CHECK(!async.RegisterPeer(6));
    BOOST_CHECK(async.EnqueueSign(sign_request(6, true)).error == CMNAuth::AsyncError::STOPPED);
    BOOST_CHECK(async.EnqueueVerify(verify_request(6)).error == CMNAuth::AsyncError::STOPPED);
    BOOST_CHECK(async.WaitForCompletions(std::chrono::milliseconds{0}).empty());

    {
        std::lock_guard lock{mutex};
        release = true;
    }
    cv.notify_all();
    async.Stop();
    async.Stop();
    const auto stopped_stats{async.GetStats()};
    BOOST_CHECK_EQUAL(stopped_stats.verify_inflight, 0U);
    BOOST_CHECK_EQUAL(stopped_stats.sign_inflight, 0U);
    BOOST_CHECK_EQUAL(stopped_stats.cancelled_jobs, 5U);
    BOOST_CHECK_EQUAL(sign_calls, 1U);
    BOOST_CHECK_EQUAL(verify_calls, 1U);
    BOOST_CHECK(!hooks_timed_out);
    BOOST_CHECK(async.TakeCompletions().empty());
    BOOST_CHECK_EQUAL(GetActiveMasternodeGlobalSigningStats().mnauth_demands, 0U);
}

BOOST_FIXTURE_TEST_CASE(node_interrupt_releases_validation_and_transaction_waiters,
                        TestChain100Setup)
{
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns.front(), 0, 1, coinbaseKey,
        GetScriptForDestination(PKHash{coinbaseKey.GetPubKey()}),
        m_coinbase_txns.front()->vout[0].nValue - 10'000,
        /*submit=*/false))};
    const auto original_consensus{Params().GetConsensus()};
    CBlockIndex* const original_tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveTip())};
    {
        LOCK(cs_main);
        BOOST_REQUIRE(m_node.chainman->ProcessTransaction(tx, /*test_accept=*/true).
            m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    SyncWithValidationInterfaceQueue();
    CompletionPublicationFixture fixture{*this, /*outbound=*/true, /*rotate_key=*/false};
    const int original_sync_mode{masternodeSync.GetAssetID()};
    std::vector<CNode*> registered_nodes;
    std::thread broadcaster;
    std::promise<bool> governance_signed;
    auto governance_result{governance_signed.get_future()};
    std::promise<TransactionError> broadcast_finished;
    auto broadcast_result{broadcast_finished.get_future()};
    GlobalSignature governance_signature{};
    std::string broadcast_error;
    struct Cleanup {
        PeerManager& peerman;
        std::vector<CNode*>& nodes;
        std::thread& broadcaster;
        int original_sync_mode;
        ~Cleanup()
        {
            // Failure cleanup cancels queued peers first, so a failed bounded
            // wait cannot leave a signer reservation blocking fixture teardown.
            for (auto it{nodes.rbegin()}; it != nodes.rend(); ++it) peerman.FinalizeNode(**it);
            if (broadcaster.joinable()) broadcaster.join();
            SyncWithValidationInterfaceQueue();
            masternodeSync.SetSyncMode(original_sync_mode);
        }
    } cleanup{fixture.peerman, registered_nodes, broadcaster, original_sync_mode};
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
    const auto wait_until = [](const auto& predicate) {
        const auto deadline{std::chrono::steady_clock::now() + std::chrono::seconds{30}};
        while (!predicate()) {
            if (std::chrono::steady_clock::now() >= deadline) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return true;
    };
    const auto begin_handshake = [&](NodeId id) {
        auto* node = new CNode{
            id, nullptr, CAddress{fixture.context.connected_service, NODE_NETWORK},
            fixture.context.keyed_net_group, 1, CAddress{}, std::string{},
            ConnectionType::OUTBOUND_FULL_RELAY, false};
        fixture.connman.AddTestNode(*node);
        node->m_masternode_connection = true;
        fixture.peerman.InitializeNode(*node, NODE_NETWORK);
        registered_nodes.push_back(node);
        BOOST_REQUIRE(!node->fDisconnect);
        auto remote{fixture.context.connection.remote};
        remote.cookie = NonNullHash(50'000 + id);
        BOOST_REQUIRE(node->SetRemoteMNAuthConnectionData(
            remote, fixture.context.connection.remote_challenge,
            fixture.context.connection.remote_version_nonce,
            PQ_MNAUTH_PROTO_VERSION, NODE_NETWORK));
        node->nVersion = PQ_MNAUTH_PROTO_VERSION;
        node->SetCommonVersion(PQ_MNAUTH_PROTO_VERSION);
        CDataStream verack{SER_NETWORK, PROTOCOL_VERSION};
        const std::atomic_bool interrupt{false};
        {
            LOCK(NetEventsInterface::g_msgproc_mutex);
            fixture.peerman.ProcessMessage(*node, NetMsgType::VERACK,
                                          verack, GetTime<std::chrono::microseconds>(), interrupt);
        }
        BOOST_REQUIRE(!node->fDisconnect);
        BOOST_REQUIRE(node->GetMNAuthPending().phase == CMNAuthPendingPhase::SIGN_PENDING);
    };
    begin_handshake(100);
    BOOST_REQUIRE(wait_until([&] {
        const auto stats{fixture.peerman.GetMNAuthAsyncStats()};
        return stats.sign_completed == 1 && stats.completion_queue_depth == 1;
    }));
    begin_handshake(101);
    BOOST_REQUIRE_EQUAL(fixture.peerman.GetMNAuthAsyncStats().sign_queue_depth, 1U);
    BOOST_REQUIRE_EQUAL(GetActiveMasternodeGlobalSigningStats().mnauth_demands, 1U);

    // Admission above needs the fixture's authenticated registry tip. Return
    // to the mined chain for real mempool validation; the executor still owns
    // its admitted work and no completion has been acknowledged or cancelled.
    {
        LOCK(cs_main);
        m_node.chainman->ActiveChain().SetTip(*original_tip);
        const_cast<Consensus::Params&>(Params().GetConsensus()) = original_consensus;
    }
    const uint256 governance_digest{NonNullHash(90'001)};
    CallFunctionInValidationInterfaceQueue([&, governance_digest] {
        try {
            governance_signed.set_value(SignActiveMasternodeGovernanceTrigger(
                fixture.context.connection.local.pro_tx_hash,
                fixture.context.local_key.key_version, governance_digest,
                governance_signature));
        } catch (...) {
            governance_signed.set_exception(std::current_exception());
        }
    });
    BOOST_REQUIRE(wait_until([] {
        return GetActiveMasternodeGlobalSigningStats().governance_waiters == 1;
    }));
    broadcaster = std::thread{[&] {
        try {
            broadcast_finished.set_value(node::BroadcastTransaction(
                m_node, tx, broadcast_error, /*max_tx_fee=*/0,
                /*relay=*/false, /*wait_callback=*/true));
        } catch (...) {
            broadcast_finished.set_exception(std::current_exception());
        }
    }};
    BOOST_REQUIRE(wait_until([&] {
        // Taking cs_main also waits for BroadcastTransaction to enqueue its
        // ordered callback after successful admission and release the lock.
        LOCK(cs_main);
        return m_node.mempool->exists(GenTxid::Txid(tx->GetHash()));
    }));
    BOOST_REQUIRE(broadcast_result.wait_for(std::chrono::milliseconds{0}) == std::future_status::timeout);

    ::Interrupt(m_node);
    const auto interrupted_stats{fixture.peerman.GetMNAuthAsyncStats()};
    BOOST_CHECK_EQUAL(interrupted_stats.sign_queue_depth, 0U);
    BOOST_CHECK_EQUAL(interrupted_stats.completion_queue_depth, 0U);
    BOOST_CHECK_EQUAL(GetActiveMasternodeGlobalSigningStats().mnauth_demands, 0U);
    BOOST_REQUIRE(broadcast_result.wait_for(std::chrono::seconds{30}) == std::future_status::ready);
    BOOST_CHECK(broadcast_result.get() == TransactionError::OK);
    BOOST_CHECK(broadcast_error.empty());
    broadcaster.join();
    BOOST_REQUIRE(governance_result.wait_for(std::chrono::milliseconds{0}) == std::future_status::ready);
    BOOST_CHECK(governance_result.get());
    BOOST_CHECK(slhdsa::Verify(fixture.context.local_key.public_key,
        std::span<const uint8_t>{governance_digest.begin(), governance_digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_TRIGGER), governance_signature));
    BOOST_CHECK_EQUAL(fixture.peerman.GetMNAuthAsyncStats().sign_completed, 1U);
    BOOST_CHECK_EQUAL(fixture.peerman.GetMNAuthAsyncStats().cancelled_jobs, 2U);
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
