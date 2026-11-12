// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/mnauth.h>
#include <crypto/slhdsa/slhdsa.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_quorum_overlay.h>
#include <netbase.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <queue>
#include <random>
#include <set>
#include <vector>

namespace {
using namespace llmq;
using namespace llmq::pq;

uint256 Identity(uint32_t value)
{
    uint256 hash;
    // SYSCOIN: Extract each fixture-identity byte without implicit integer truncation.
    for (unsigned i{0}; i < 4; ++i) {
        hash.begin()[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xffU);
    }
    return hash;
}

GlobalKeyRecord Key()
{
    slhdsa::KeyGenerationSeed seed{};
    const auto secret{slhdsa::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret);
    GlobalKeyRecord key;
    key.key_version = 1;
    key.activated_height = 1;
    key.child_key_commitment.generation = 1;
    key.child_key_commitment.tree_id = Identity(1001);
    key.child_key_commitment.root = Identity(1002);
    BOOST_REQUIRE(secret->GetPublicKey(key.public_key));
    BOOST_REQUIRE(key.IsStructurallyValid());
    return key;
}

// The test executes the real asynchronous queues and admission managers with
// production defaults. Crypto is substituted with an explicit service model:
// eight seconds per SLH signature (slower than the nine/minute reference rate)
// and ten milliseconds per verification. No elapsed-time sleeps are needed.
struct Authentication {
    static constexpr int64_t SIGN_MICROS{8'000'000};
    static constexpr int64_t VERIFY_MICROS{10'000};
    std::atomic<int64_t> now{0};
    const GlobalKeyRecord key{Key()};
    int64_t next_peer{1};
    unsigned rate_refusals{0};
    struct Node {
        CMNAuth::AsyncProcessor processor;
        explicit Node(Authentication& owner) : processor(CMNAuth::AsyncConfig{}, [&] {
            CMNAuth::AsyncHooks hooks;
            hooks.now_micros = [&owner] { return owner.now.load(); };
            hooks.sign = [&owner](const uint256&, uint32_t, const uint256&, GlobalSignature& signature) {
                owner.now.fetch_add(SIGN_MICROS);
                signature[0] = 1;
                return true;
            };
            hooks.verify = [&owner](MNAUTHVerificationTask&) {
                owner.now.fetch_add(VERIFY_MICROS);
                return true;
            };
            return hooks;
        }()) {}
    };
    std::map<uint32_t, std::unique_ptr<Node>> nodes;

    Node& Get(uint32_t id)
    {
        auto& node{nodes[id]};
        if (!node) node = std::make_unique<Node>(*this);
        return *node;
    }

    CMNAuth::ContextToken Context(uint32_t initiator, uint32_t responder,
                                 int64_t peer, bool local_initiator, bool authenticated = false)
    {
        CMNAuth::ContextToken context;
        context.peer_id = peer;
        context.tip_hash = Identity(9000);
        context.local_is_initiator = local_initiator;
        context.keyed_net_group = 1; // All fixture addresses share one source group.
        context.common_version = PQ_MNAUTH_PROTO_VERSION;
        context.masternode_connection = true;
        context.local_key = context.remote_key = key;
        NetworkEndpoint a, b;
        a.network = b.network = EndpointNetwork::IPV4;
        a.address_size = b.address_size = 4;
        a.address[0] = b.address[0] = 192;
        a.address[2] = b.address[2] = 2;
        a.address[3] = 1; b.address[3] = 2;
        a.port = b.port = 8369;
        context.local_endpoint = local_initiator ? a : b;
        context.remote_endpoint = local_initiator ? b : a;
        const auto service_a{LookupNumeric("192.0.2.1", 8369)};
        const auto service_b{LookupNumeric("192.0.2.2", 8369)};
        context.local_service = local_initiator ? service_a : service_b;
        context.remote_service = local_initiator ? service_b : service_a;
        context.connected_service = local_initiator ? context.remote_service : LookupNumeric("192.0.2.1", 40000);
        auto& c{context.connection};
        c.local.pro_tx_hash = Identity(local_initiator ? initiator : responder);
        c.remote.pro_tx_hash = Identity(local_initiator ? responder : initiator);
        c.local.global_key_version = c.remote.global_key_version = key.key_version;
        c.local.cookie = Identity(10000 + peer * 10 + (local_initiator ? 1 : 2));
        c.remote.cookie = Identity(10000 + peer * 10 + (local_initiator ? 2 : 1));
        c.local_challenge = Identity(10000 + peer * 10 + (local_initiator ? 3 : 4));
        c.remote_challenge = Identity(10000 + peer * 10 + (local_initiator ? 4 : 3));
        c.local_version_nonce = peer * 10 + (local_initiator ? 5 : 6);
        c.remote_version_nonce = peer * 10 + (local_initiator ? 6 : 5);
        c.local_protocol_version = c.remote_protocol_version = PQ_MNAUTH_PROTO_VERSION;
        c.local_service_flags = c.remote_service_flags = 9;
        c.has_local = c.has_remote = true;
        if (authenticated) context.authenticated_remote_pro_tx_hash = c.remote.pro_tx_hash;
        BOOST_REQUIRE(context.IsStructurallyValid());
        return context;
    }

    MNAUTHTranscript Transcript(const CMNAuth::ContextToken& context, MNAUTHSignerRole role)
    {
        const auto transcript{BuildMNAUTHTranscript(context.connection, context.local_is_initiator,
            context.local_endpoint, context.remote_endpoint, role, {0xfa, 0xbf, 0xb5, 0xda}, 1)};
        BOOST_REQUIRE(transcript);
        return *transcript;
    }

    bool Sign(Node& node, const CMNAuth::ContextToken& context, CMNAuth::Completion& completion)
    {
        const auto role{context.local_is_initiator ? MNAUTHSignerRole::INITIATOR : MNAUTHSignerRole::RESPONDER};
        const auto digest{GetMNAUTHAuthorizationHash(Identity(9001), key, key, Transcript(context, role), 1)};
        BOOST_REQUIRE(digest);
        CMNAuth::SignRequest request;
        request.context = context;
        request.authorization_hash = *digest;
        request.attributed_pro_tx_hash = context.connection.remote.pro_tx_hash;
        request.signer_role = role;
        const auto admitted{node.processor.EnqueueSign(std::move(request))};
        if (!admitted.Accepted()) {
            BOOST_CHECK(admitted.error == CMNAuth::AsyncError::SIGN_ADMISSION);
            BOOST_CHECK(admitted.signing_error == MNAUTHSigningAdmissionError::RATE_LIMIT);
            ++rate_refusals;
            return false;
        }
        const auto results{node.processor.WaitForCompletions(std::chrono::seconds{2})};
        BOOST_REQUIRE_EQUAL(results.size(), 1U);
        completion = results.front();
        BOOST_REQUIRE(completion.Success());
        BOOST_CHECK_LT(now.load(), completion.deadline_micros);
        node.processor.AcknowledgeSignCompletion(context.peer_id, completion.registration_generation, completion.deadline_micros);
        return true;
    }

    void Verify(Node& node, const CMNAuth::ContextToken& context, const CMNAuth::Completion& signed_message)
    {
        CMNAuth::VerifyRequest request;
        request.context = context;
        request.genesis_hash = Identity(9001);
        request.expected_signer_role = signed_message.message.signer_role;
        request.transcript = Transcript(context, request.expected_signer_role);
        request.required_service_flags = 1;
        request.message = signed_message.message;
        BOOST_REQUIRE(node.processor.EnqueueVerify(std::move(request)).Accepted());
        const auto results{node.processor.WaitForCompletions(std::chrono::seconds{2})};
        BOOST_REQUIRE_EQUAL(results.size(), 1U);
        BOOST_REQUIRE(results.front().Success());
        BOOST_CHECK_LT(now.load(), results.front().deadline_micros);
    }

    bool Connect(uint32_t a, uint32_t b)
    {
        auto& initiator{Get(a)};
        auto& responder{Get(b)};
        const auto peer{next_peer++};
        BOOST_REQUIRE(initiator.processor.RegisterPeer(peer));
        BOOST_REQUIRE(responder.processor.RegisterPeer(peer));
        auto local{Context(a, b, peer, true)};
        auto remote{Context(a, b, peer, false)};
        CMNAuth::Completion proof;
        bool success{Sign(initiator, local, proof)};
        if (success) {
            Verify(responder, remote, proof);
            remote.authenticated_remote_pro_tx_hash = Identity(a);
            success = Sign(responder, remote, proof);
            if (success) Verify(initiator, local, proof);
        }
        initiator.processor.CancelPeer(peer);
        responder.processor.CancelPeer(peer);
        return success;
    }

    void ConsumeResponderWindow(uint32_t b)
    {
        auto& responder{Get(b)};
        for (uint32_t a : {8001U, 8002U}) {
            const auto peer{next_peer++};
            BOOST_REQUIRE(responder.processor.RegisterPeer(peer));
            CMNAuth::Completion proof;
            BOOST_REQUIRE(Sign(responder, Context(a, b, peer, false, true), proof));
            responder.processor.CancelPeer(peer);
        }
    }
};

struct RelayCut {
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    std::map<uint256, std::size_t> positions;
    std::vector<std::vector<std::size_t>> graph{QUORUM_SIZE};
    std::set<std::size_t> faulty;
    std::vector<std::size_t> stranded;

    explicit RelayCut(bool isolate_one) : stranded(isolate_one ? std::vector<std::size_t>{0} : std::vector<std::size_t>{0, 3})
    {
        for (std::size_t i{0}; i < QUORUM_SIZE; ++i) {
            positions.emplace(Identity(i + 1), i);
            for (auto& roster : rosters) {
                roster.members[i].pro_tx_hash = Identity(i + 1);
                roster.members[i].eligible = true;
                roster.members[i].child_root.emplace();
            }
        }
        for (std::size_t i{0}; i < QUORUM_SIZE; ++i) {
            for (const auto& hash : GetPQQuorumUnionRelayConnections(rosters, Identity(i + 1))) {
                graph[i].push_back(positions.at(hash));
            }
        }
        for (const auto origin : stranded) faulty.insert(graph[origin].begin(), graph[origin].end());
        if (isolate_one) {
            for (std::size_t i{0}; i < graph.size(); ++i) {
                if (std::find(graph[i].begin(), graph[i].end(), 0) != graph[i].end()) faulty.insert(i);
            }
            BOOST_REQUIRE_EQUAL(faulty.size(), 16U);
        }
        for (std::size_t i{0}; faulty.size() < QUORUM_MAX_BYZANTINE; ++i) {
            if (std::find(stranded.begin(), stranded.end(), i) == stranded.end()) faulty.insert(i);
        }
        for (const auto origin : stranded) BOOST_REQUIRE(!faulty.contains(origin));
    }

    std::size_t LargestCollector(const std::map<std::size_t, std::set<std::size_t>>& extra) const
    {
        std::vector<std::size_t> counts(QUORUM_SIZE);
        for (std::size_t origin{0}; origin < QUORUM_SIZE; ++origin) {
            if (faulty.contains(origin)) continue;
            std::set<std::size_t> reached{origin};
            std::queue<std::size_t> pending;
            pending.push(origin);
            // The fallback retransmits only the local origin's own shares.
            // Each recipient then uses its existing normal relay connections.
            if (auto it{extra.find(origin)}; it != extra.end()) {
                for (const auto peer : it->second) {
                    if (!faulty.contains(peer) && reached.insert(peer).second) pending.push(peer);
                }
            }
            while (!pending.empty()) {
                const auto at{pending.front()}; pending.pop();
                for (const auto peer : graph[at]) {
                    if (!faulty.contains(peer) && reached.insert(peer).second) pending.push(peer);
                }
            }
            for (const auto peer : reached) ++counts[peer];
        }
        return *std::max_element(counts.begin(), counts.end());
    }

    void RecoverWithAdmission(uint64_t seed = 0xC0DEC0DE)
    {
        BOOST_REQUIRE_EQUAL(faulty.size(), QUORUM_MAX_BYZANTINE);
        BOOST_REQUIRE_LT(LargestCollector({}), QUORUM_THRESHOLD);
        Authentication auth;
        std::map<std::size_t, PQShareRelayFallback> selectors;
        std::map<std::size_t, std::vector<uint256>> orders;
        // Seed is fixed before constructing the fault set and is never searched
        // for a successful outcome. This checks scenarios, not all placements.
        std::mt19937_64 rng{seed};
        for (const auto origin : stranded) {
            auto candidates{BuildPQShareRelayFallbackCandidates(rosters, Identity(origin + 1))};
            // Explicit Fisher-Yates keeps the test ordering portable across
            // standard-library implementations of std::shuffle.
            for (std::size_t remaining{candidates.size()}; remaining > 1; --remaining) {
                std::swap(candidates[remaining - 1], candidates[rng() % remaining]);
            }
            BOOST_REQUIRE(!candidates.empty());
            orders.emplace(origin, candidates);
            // Competing previously authenticated peers consumed this endpoint's
            // two responder slots. The fallback must wait for real rate expiry.
            auth.ConsumeResponderWindow(positions.at(candidates.front()) + 1);
        }
        const int64_t start{auth.now.load()};
        const auto schedule{MakeChainLockScheduleConfig(0)};
        BOOST_REQUIRE(schedule);
        const auto initial{CurrentChainLockSigningWindow(*schedule, 864, 870)};
        BOOST_REQUIRE(initial);
        BOOST_REQUIRE_EQUAL(initial->target_height, 865);
        for (const auto origin : stranded) {
            BOOST_REQUIRE(selectors[origin].Start(
                {Identity(9002), Identity(origin + 1), 1, 1}, orders.at(origin), start / 1'000'000));
        }
        std::map<std::size_t, std::set<std::size_t>> authenticated;
        std::map<std::pair<std::size_t, std::size_t>, int64_t> retry_at;
        bool threshold{false};
        unsigned attempted{0};
        // A five-block window at the post-NEVM target spacing is 300 seconds.
        // Height is the actual cutoff: faster block arrival can retire this
        // context earlier, and the separate rollover test enforces that case.
        constexpr int64_t BLOCK_SECONDS{60};
        const int64_t end{start + PQ_CL_PERIOD * BLOCK_SECONDS * 1'000'000};
        while (auth.now.load() < end) {
            const auto elapsed{(auth.now.load() - start) / 1'000'000};
            const auto window{CurrentChainLockSigningWindow(*schedule, 864, 870 + elapsed / BLOCK_SECONDS)};
            BOOST_REQUIRE(window);
            BOOST_REQUIRE(*window == *initial);
            for (const auto origin : stranded) {
                auto& selector{selectors.at(origin)};
                selector.Advance(auth.now.load() / 1'000'000, false);
                BOOST_REQUIRE_LE(selector.Members().size(), PQShareRelayFallback::MAX_EXTRA_CONNECTIONS);
                for (const auto& hash : selector.Members()) {
                    const auto peer{positions.at(hash)};
                    const auto edge{std::make_pair(origin, peer)};
                    if (authenticated[origin].contains(peer) || auth.now.load() < retry_at[edge]) continue;
                    ++attempted;
                    if (auth.Connect(origin + 1, peer + 1)) authenticated[origin].insert(peer);
                    // Public-network LLMQ connector retry delay is 60 seconds.
                    retry_at[edge] = auth.now.load() + 60'000'000;
                }
            }
            // Include one second for bounded delivery on established links.
            auth.now.fetch_add(1'000'000);
            if (LargestCollector(authenticated) >= QUORUM_THRESHOLD) {
                threshold = true;
                break;
            }
        }
        BOOST_CHECK(threshold);
        BOOST_CHECK_LT(auth.now.load(), end);
        if (stranded.size() == 1) BOOST_CHECK_GT(auth.rate_refusals, 0U);
        BOOST_CHECK_LE(attempted, 4U * stranded.size());
        BOOST_TEST_MESSAGE("Authenticated fallback collected threshold after " <<
            (auth.now.load() - start) / 1'000'000 << "s with " << attempted << " admission attempts");
        for (auto& [origin, selector] : selectors) {
            selector.Advance(auth.now.load() / 1'000'000, true);
            BOOST_CHECK(selector.Members().empty());
        }
    }
};


// A network-wide capacity model complements the real AsyncProcessor pipeline
// above without creating three operating-system threads for each of 400 nodes.
// Each node owns the production role-specific admission managers and shares one
// eight-second signing worker between its initiator and responder queues.
void RecoverConcurrentFallback(bool isolate_one)
{
    RelayCut cut{isolate_one};
    CMNAuth::AsyncConfig config;
    BOOST_REQUIRE(config.IsValid());
    auto initiator_config{config.signing_admission};
    initiator_config.global_attempts_per_window = config.initiator_sign_attempts_per_window;
    initiator_config.source_attempts_per_window = config.initiator_sign_source_attempts_per_window;
    auto responder_config{config.signing_admission};
    responder_config.global_attempts_per_window = config.responder_sign_attempts_per_window;
    responder_config.source_attempts_per_window = config.responder_sign_source_attempts_per_window;
    responder_config.identity_attempts_per_window = config.responder_sign_identity_attempts_per_window;
    enum Kind { TICK, START, INIT_DONE, RESP_START, RESP_DONE, AUTH_DONE };
    struct Event {
        int64_t time;
        uint64_t sequence;
        Kind kind;
        std::size_t a{0}, b{0};
        int64_t deadline{0};
        bool operator<(const Event& other) const {
            return time > other.time || (time == other.time && sequence > other.sequence);
        }
    };
    struct Job { Event event; };
    struct Endpoint {
        MNAUTHSigningAdmissionManager initiator;
        MNAUTHSigningAdmissionManager responder;
        std::deque<Job> initiator_queue, responder_queue;
        bool busy{false};
        Endpoint(MNAUTHSigningRuntimeConfig i, MNAUTHSigningRuntimeConfig r) : initiator(i), responder(r) {}
    };
    std::vector<std::unique_ptr<Endpoint>> endpoints;
    std::vector<PQShareRelayFallback> selectors(QUORUM_SIZE);
    std::mt19937_64 rng{0xC0DEC0DE};
    for (std::size_t i{0}; i < QUORUM_SIZE; ++i) {
        endpoints.push_back(std::make_unique<Endpoint>(initiator_config, responder_config));
        if (cut.faulty.contains(i)) continue;
        auto candidates{BuildPQShareRelayFallbackCandidates(cut.rosters, Identity(i + 1))};
        for (std::size_t remaining{candidates.size()}; remaining > 1; --remaining) {
            std::swap(candidates[remaining - 1], candidates[rng() % remaining]);
        }
        BOOST_REQUIRE(selectors[i].Start({Identity(9002), Identity(i + 1), 1, 1}, std::move(candidates), 0));
    }
    std::vector<std::set<std::size_t>> normal_reach(QUORUM_SIZE), delivered(QUORUM_SIZE);
    std::vector<unsigned> collector_counts(QUORUM_SIZE);
    for (std::size_t origin{0}; origin < QUORUM_SIZE; ++origin) {
        if (cut.faulty.contains(origin)) continue;
        std::queue<std::size_t> q;
        normal_reach[origin].insert(origin);
        q.push(origin);
        while (!q.empty()) {
            const auto at{q.front()}; q.pop();
            for (const auto peer : cut.graph[at]) {
                if (!cut.faulty.contains(peer) && normal_reach[origin].insert(peer).second) q.push(peer);
            }
        }
        delivered[origin] = normal_reach[origin];
        for (const auto peer : delivered[origin]) ++collector_counts[peer];
    }
    BOOST_REQUIRE_LT(*std::max_element(collector_counts.begin(), collector_counts.end()), QUORUM_THRESHOLD);
    std::priority_queue<Event> events;
    uint64_t sequence{0};
    events.push({0, ++sequence, TICK});
    std::set<std::pair<std::size_t, std::size_t>> pending, authenticated;
    unsigned attempts{0}, rate_refusals{0}, completed{0};
    int64_t finished{-1};
    constexpr int64_t SECOND{1'000'000};
    constexpr int64_t END{PQ_CL_PERIOD * 60 * SECOND};
    const auto schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    const auto context{CurrentChainLockSigningWindow(*schedule, 864, 870)};
    BOOST_REQUIRE(context);
    const auto retry = [&](Event event) {
        pending.erase({event.a, event.b});
        event.kind = START;
        // Public-network LLMQ connector retries an identity after 60 seconds.
        event.time += 60 * SECOND;
        event.sequence = ++sequence;
        events.push(event);
    };
    const auto enqueue = [&](Event event, Endpoint& endpoint, bool initiating) {
        auto& queue{initiating ? endpoint.initiator_queue : endpoint.responder_queue};
        const auto cap{initiating ? config.max_initiator_sign_queue : config.max_responder_sign_queue};
        BOOST_REQUIRE_LT(queue.size(), cap);
        event.deadline = event.time + config.sign_timeout.count();
        if (endpoint.busy) queue.push_back({event});
        else {
            endpoint.busy = true;
            event.time += Authentication::SIGN_MICROS;
            event.sequence = ++sequence;
            events.push(event);
        }
    };
    const auto release = [&](Endpoint& endpoint, int64_t now) {
        endpoint.busy = false;
        auto* queue{!endpoint.initiator_queue.empty() ? &endpoint.initiator_queue : &endpoint.responder_queue};
        if (queue->empty()) return;
        auto job{queue->front()}; queue->pop_front();
        endpoint.busy = true;
        job.event.time = now + Authentication::SIGN_MICROS;
        job.event.sequence = ++sequence;
        events.push(job.event);
    };
    while (!events.empty() && events.top().time < END && finished < 0) {
        auto event{events.top()}; events.pop();
        if (event.kind == TICK) {
            BOOST_REQUIRE(CurrentChainLockSigningWindow(*schedule, 864, 870 + event.time / (60 * SECOND)) == context);
            for (std::size_t a{0}; a < QUORUM_SIZE; ++a) {
                if (cut.faulty.contains(a)) continue;
                if (selectors[a].Advance(event.time / SECOND, false)) {
                    BOOST_REQUIRE_LE(selectors[a].Members().size(), PQShareRelayFallback::MAX_EXTRA_CONNECTIONS);
                    for (const auto& hash : selectors[a].Members()) {
                        const auto b{cut.positions.at(hash)};
                        if (!authenticated.contains({a, b}) && !pending.contains({a, b})) events.push({event.time, ++sequence, START, a, b});
                    }
                }
            }
            events.push({event.time + SECOND, ++sequence, TICK});
            continue;
        }
        const auto edge{std::make_pair(event.a, event.b)};
        const bool current{selectors[event.a].Members().contains(Identity(event.b + 1))};
        if (event.kind == INIT_DONE || event.kind == RESP_DONE) {
            release(*endpoints[event.kind == INIT_DONE ? event.a : event.b], event.time);
            if (event.time >= event.deadline) { retry(event); continue; }
        }
        if (!current) { pending.erase(edge); continue; }
        if (event.kind == START) {
            if (authenticated.contains(edge) || pending.contains(edge)) continue;
            ++attempts;
            MNAUTHSigningAdmissionError error;
            if (!endpoints[event.a]->initiator.Admit(event.b + 1, Identity(event.b + 1), event.time / SECOND, &error)) {
                BOOST_CHECK(error == MNAUTHSigningAdmissionError::RATE_LIMIT);
                ++rate_refusals;
                retry(event);
                continue;
            }
            pending.insert(edge);
            event.kind = INIT_DONE;
            enqueue(event, *endpoints[event.a], true);
        } else if (event.kind == INIT_DONE) {
            event.kind = RESP_START;
            event.time += Authentication::VERIFY_MICROS;
            event.sequence = ++sequence;
            events.push(event);
        } else if (event.kind == RESP_START) {
            MNAUTHSigningAdmissionError error;
            if (!endpoints[event.b]->responder.Admit(event.a + 1, Identity(event.a + 1), event.time / SECOND, &error)) {
                BOOST_CHECK(error == MNAUTHSigningAdmissionError::RATE_LIMIT);
                ++rate_refusals;
                retry(event);
                continue;
            }
            event.kind = RESP_DONE;
            enqueue(event, *endpoints[event.b], false);
        } else if (event.kind == RESP_DONE) {
            event.kind = AUTH_DONE;
            event.time += Authentication::VERIFY_MICROS + SECOND; // Verification, then relay delivery.
            event.sequence = ++sequence;
            events.push(event);
        } else if (event.kind == AUTH_DONE) {
            authenticated.insert(edge);
            pending.erase(edge);
            ++completed;
            if (!cut.faulty.contains(event.b)) {
                for (const auto peer : normal_reach[event.b]) {
                    if (delivered[event.a].insert(peer).second && ++collector_counts[peer] >= QUORUM_THRESHOLD) finished = event.time;
                }
            }
        }
    }
    BOOST_CHECK_GE(finished, 0);
    BOOST_CHECK_LT(finished, END);
    BOOST_CHECK_GT(rate_refusals, 0U);
    BOOST_TEST_MESSAGE("All-honest concurrent fallback (" << (isolate_one ? "isolated" : "two senders") <<
        ") threshold at " << finished / SECOND << "s; " << attempts << " attempts, " <<
        completed << " authenticated, " << rate_refusals << " rate-limit refusals");
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_relay_fallback_tests)

BOOST_AUTO_TEST_CASE(authentication_retry_honors_existing_responder_budget)
{
    Authentication auth;
    auth.ConsumeResponderWindow(2);
    auth.now = 30'000'000;
    BOOST_CHECK(!auth.Connect(1, 2));
    BOOST_CHECK_EQUAL(auth.rate_refusals, 1U);
    auth.now = 98'000'000;
    BOOST_REQUIRE(auth.Connect(1, 2));
    BOOST_CHECK_GT(auth.now.load(), 80'000'000);
    BOOST_CHECK_LT(auth.now.load(), 120'000'000);
}


BOOST_AUTO_TEST_CASE(isolated_honest_member_reaches_threshold_after_bounded_authenticated_fallback)
{
    RelayCut{true}.RecoverWithAdmission();
}

BOOST_AUTO_TEST_CASE(two_senders_with_blocked_outgoing_edges_reach_threshold_after_fallback)
{
    RelayCut{false}.RecoverWithAdmission();
}

BOOST_AUTO_TEST_CASE(independent_seed_rotations_respect_authentication_budget)
{
    RelayCut{true}.RecoverWithAdmission(1);
    RelayCut{false}.RecoverWithAdmission(1);
}

BOOST_AUTO_TEST_CASE(concurrent_honest_fallback_preserves_capacity_for_isolated_member)
{
    RecoverConcurrentFallback(true);
}

BOOST_AUTO_TEST_CASE(concurrent_honest_fallback_preserves_capacity_for_two_stranded_senders)
{
    RecoverConcurrentFallback(false);
}

BOOST_AUTO_TEST_CASE(changing_height_context_discards_pending_fallback_destinations)
{
    RelayCut cut{true};
    PQShareRelayFallback selector;
    const PQShareRelayFallbackKey key{Identity(9002), Identity(1), 1, 1};
    BOOST_REQUIRE(selector.Start(key, BuildPQShareRelayFallbackCandidates(cut.rosters, Identity(1)), 0));
    BOOST_REQUIRE(selector.Advance(30, false));
    BOOST_REQUIRE_EQUAL(selector.Members().size(), 1U);
    const auto old_peer{*selector.Members().begin()};
    const auto schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    const auto old_window{CurrentChainLockSigningWindow(*schedule, 864, 870)};
    // A cold handshake can finish after five fast-arriving/remaining blocks.
    // It may authenticate the transport, but cannot extend an expired share context.
    Authentication auth;
    auth.now = 290'000'000;
    BOOST_REQUIRE(auth.Connect(1, cut.positions.at(old_peer) + 1));
    BOOST_REQUIRE_GT(auth.now.load(), 300'000'000);
    const auto new_window{CurrentChainLockSigningWindow(*schedule, 864,
        870 + auth.now.load() / 60'000'000)};
    BOOST_REQUIRE(old_window && new_window);
    BOOST_REQUIRE(old_window->target_height != new_window->target_height);
    selector.Reset();
    BOOST_CHECK(!selector.Key());
    BOOST_CHECK(selector.Members().empty());
    // Late authentication of old_peer must not regain old-context membership.
    BOOST_CHECK(!selector.Members().contains(old_peer));
    BOOST_REQUIRE(selector.Start({Identity(9003), Identity(1), 2, 2},
        BuildPQShareRelayFallbackCandidates(cut.rosters, Identity(1)), 31));
    BOOST_CHECK(!selector.Advance(60, false));
    BOOST_CHECK(selector.Members().empty());
    BOOST_REQUIRE(selector.Advance(61, false));
    BOOST_CHECK(selector.Key()->context_hash == Identity(9003));
}

BOOST_AUTO_TEST_SUITE_END()
