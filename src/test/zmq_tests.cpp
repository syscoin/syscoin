// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/common.h>
#include <primitives/transaction.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validationinterface.h>
#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqpublishnotifier.h>

#include <boost/test/unit_test.hpp>
#include <zmq.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

class CZMQNotificationInterfaceTestAccess
{
public:
    static std::shared_ptr<CZMQNotificationInterface> Create(std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers)
    {
        std::shared_ptr<CZMQNotificationInterface> interface{new CZMQNotificationInterface()};
        interface->notifiers = std::move(notifiers);
        if (!interface->Initialize()) throw std::runtime_error{"ZMQ test interface initialization failed"};
        return interface;
    }

    static void* Context(const CZMQNotificationInterface& interface) { return interface.pcontext; }
};

namespace {
using Bytes = std::vector<unsigned char>;

struct ZMQTestingSetup : BasicTestingSetup {
    CScheduler scheduler;

    ZMQTestingSetup()
    {
        GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);
        scheduler.m_service_thread = std::thread{[this] { scheduler.serviceQueue(); }};
    }

    ~ZMQTestingSetup()
    {
        SyncWithValidationInterfaceQueue();
        scheduler.stop();
        GetMainSignals().UnregisterBackgroundSignalScheduler();
    }
};

struct RegisteredInterface {
    std::shared_ptr<CValidationInterface> interface;

    explicit RegisteredInterface(std::shared_ptr<CValidationInterface> value) : interface{std::move(value)}
    {
        RegisterSharedValidationInterface(interface);
    }

    ~RegisteredInterface()
    {
        SyncWithValidationInterfaceQueue();
        UnregisterSharedValidationInterface(interface);
    }
};

// Hold the real validation queue without relying on scheduling sleeps. The
// destructor also releases it if a test assertion throws.
class PausedQueue
{
    std::promise<void> release;
    bool released{false};

public:
    PausedQueue()
    {
        auto entered = std::make_shared<std::promise<void>>();
        auto ready = entered->get_future();
        auto resume = release.get_future().share();
        CallFunctionInValidationInterfaceQueue([entered, resume] {
            entered->set_value();
            resume.wait();
        });
        if (ready.wait_for(5s) != std::future_status::ready) {
            release.set_value();
            throw std::runtime_error{"Validation queue did not reach test gate"};
        }
    }

    void Resume()
    {
        if (!released) {
            released = true;
            release.set_value();
        }
        SyncWithValidationInterfaceQueue();
    }

    ~PausedQueue() { Resume(); }
};

uint256 TestHash(uint32_t value)
{
    uint256 hash;
    WriteLE32(hash.begin(), value);
    return hash;
}

Bytes HashBytes(const uint256& hash)
{
    Bytes bytes{hash.begin(), hash.end()};
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

CTransactionRef TestTransaction(uint32_t value)
{
    CMutableTransaction tx;
    tx.nLockTime = value;
    tx.vout.emplace_back(value, CScript{});
    return MakeTransactionRef(tx);
}

struct NotificationState {
    std::vector<uint256> votes;
    std::vector<uint256> objects;
    size_t transactions{0};
    size_t shutdowns{0};
    size_t destroyed{0};
    size_t requests{0};
};

class RecordingNotifier final : public CZMQAbstractNotifier
{
    const std::shared_ptr<NotificationState> state;
    const bool fail_vote;

public:
    RecordingNotifier(std::shared_ptr<NotificationState> value, bool fail = false)
        : state{std::move(value)}, fail_vote{fail} {}
    ~RecordingNotifier() override { ++state->destroyed; }
    bool Initialize(void*, void*) override { return true; }
    void Shutdown() override { ++state->shutdowns; }
    bool NotifyGovernanceVote(const uint256& hash) override
    {
        state->votes.push_back(hash);
        return !fail_vote;
    }
    bool NotifyGovernanceObject(const uint256& hash) override
    {
        state->objects.push_back(hash);
        return true;
    }
    bool NotifyTransaction(const CTransaction&) override
    {
        ++state->transactions;
        return true;
    }
    bool NotifyNEVMComms(const std::string&, bool& response, std::optional<NEVMBlockReject>*) override
    {
        response = ++state->requests > 1;
        return response;
    }
    bool NotifyGetNEVMBlockInfo(uint64_t& height, uint256& hash, std::string& status) override
    {
        height = 123;
        hash = TestHash(456);
        status = "synchronous-response";
        return true;
    }
};

struct SynchronousObserver final : CValidationInterface {
    uint256 vote;
    uint256 object;
    void NotifyGovernanceVote(const uint256& hash) override { vote = hash; }
    void NotifyGovernanceObject(const uint256& hash) override { object = hash; }
};

template <typename Notifier>
std::unique_ptr<Notifier> Publisher(const std::string& type, const std::string& address)
{
    auto notifier = std::make_unique<Notifier>();
    notifier->SetType(type);
    notifier->SetAddress(address);
    notifier->SetOutboundMessageHighWaterMark(4096);
    return notifier;
}

class Subscriber
{
    void* socket{nullptr};

public:
    Subscriber(void* context, const std::string& address)
    {
        socket = zmq_socket(context, ZMQ_SUB);
        if (!socket) throw std::runtime_error{"Unable to create test subscriber"};
        const int hwm{4096};
        const int timeout{100};
        if (zmq_setsockopt(socket, ZMQ_RCVHWM, &hwm, sizeof(hwm)) != 0 ||
            zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
            zmq_setsockopt(socket, ZMQ_SUBSCRIBE, "", 0) != 0 ||
            zmq_connect(socket, address.c_str()) != 0) {
            zmq_close(socket);
            socket = nullptr;
            throw std::runtime_error{"Unable to configure test subscriber"};
        }
    }

    ~Subscriber() { if (socket) zmq_close(socket); }

    std::vector<Bytes> Receive()
    {
        std::vector<Bytes> frames;
        int more{0};
        do {
            zmq_msg_t message;
            if (zmq_msg_init(&message) != 0) throw std::runtime_error{"Unable to initialize test message"};
            const int result = zmq_msg_recv(&message, socket, 0);
            if (result < 0) {
                zmq_msg_close(&message);
                if (frames.empty() && errno == EAGAIN) return {};
                throw std::runtime_error{"Unable to receive complete test message"};
            }
            const auto* data = static_cast<const unsigned char*>(zmq_msg_data(&message));
            frames.emplace_back(data, data + zmq_msg_size(&message));
            zmq_msg_close(&message);
            size_t size{sizeof(more)};
            if (zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &size) != 0) throw std::runtime_error{"Unable to read test message boundary"};
        } while (more);
        return frames;
    }
};

using Sequences = std::map<std::string, uint32_t>;

std::string CheckMessage(const std::vector<Bytes>& frames, Sequences& sequences)
{
    BOOST_REQUIRE_EQUAL(frames.size(), 3U);
    BOOST_REQUIRE_EQUAL(frames[2].size(), 4U);
    const std::string topic{frames[0].begin(), frames[0].end()};
    const uint32_t sequence = ReadLE32(frames[2].data());
    const auto previous = sequences.find(topic);
    if (previous != sequences.end()) BOOST_CHECK_EQUAL(sequence, previous->second + 1);
    sequences[topic] = sequence;
    return topic;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(zmq_tests, ZMQTestingSetup)

BOOST_AUTO_TEST_CASE(governance_publication_is_queued_but_observers_and_nevm_remain_synchronous)
{
    auto state = std::make_shared<NotificationState>();
    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;
    notifiers.emplace_back(std::make_unique<RecordingNotifier>(state));
    auto interface = CZMQNotificationInterfaceTestAccess::Create(std::move(notifiers));
    RegisteredInterface registered{interface};
    auto observer = std::make_shared<SynchronousObserver>();
    RegisteredInterface registered_observer{observer};
    PausedQueue paused;

    auto vote = TestHash(1);
    auto object = TestHash(2);
    GetMainSignals().NotifyGovernanceVote(vote);
    GetMainSignals().NotifyGovernanceObject(object);
    BOOST_CHECK(observer->vote == vote);
    BOOST_CHECK(observer->object == object);
    BOOST_CHECK(state->votes.empty());
    BOOST_CHECK(state->objects.empty());
    vote.SetNull();
    object.SetNull();

    bool response{true};
    GetMainSignals().NotifyNEVMComms("status", response);
    BOOST_CHECK(!response);
    BOOST_REQUIRE_EQUAL(interface->GetActiveNotifiers().size(), 1U);
    GetMainSignals().NotifyNEVMComms("status", response);
    BOOST_CHECK(response);
    BOOST_CHECK_EQUAL(state->requests, 2U);
    uint64_t height{0};
    uint256 hash;
    std::string status;
    GetMainSignals().NotifyGetNEVMBlockInfo(height, hash, status);
    BOOST_CHECK_EQUAL(height, 123U);
    BOOST_CHECK(hash == TestHash(456));
    BOOST_CHECK_EQUAL(status, "synchronous-response");

    paused.Resume();
    BOOST_REQUIRE_EQUAL(state->votes.size(), 1U);
    BOOST_REQUIRE_EQUAL(state->objects.size(), 1U);
    BOOST_CHECK(state->votes.front() == TestHash(1));
    BOOST_CHECK(state->objects.front() == TestHash(2));
}

BOOST_AUTO_TEST_CASE(concurrent_governance_and_mempool_publications_share_complete_messages)
{
    const std::string shared_address{"inproc://governance-shared"};
    const std::string separate_address{"inproc://governance-separate"};
    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;
    notifiers.push_back(Publisher<CZMQPublishHashGovernanceVoteNotifier>("pubhashgovernancevote", shared_address));
    notifiers.push_back(Publisher<CZMQPublishHashGovernanceObjectNotifier>("pubhashgovernanceobject", shared_address));
    notifiers.push_back(Publisher<CZMQPublishHashTransactionNotifier>("pubhashtx", shared_address));
    notifiers.push_back(Publisher<CZMQPublishSequenceNotifier>("pubsequence", shared_address));
    notifiers.push_back(Publisher<CZMQPublishHashGovernanceVoteNotifier>("pubhashgovernancevote", separate_address));
    auto interface = CZMQNotificationInterfaceTestAccess::Create(std::move(notifiers));
    Subscriber shared{CZMQNotificationInterfaceTestAccess::Context(*interface), shared_address};
    Subscriber separate{CZMQNotificationInterfaceTestAccess::Context(*interface), separate_address};
    RegisteredInterface registered{interface};
    Sequences shared_sequences;
    Sequences separate_sequences;

    // Verify subscription delivery before counting concurrent publications.
    for (int attempt = 0; attempt < 10 && (shared_sequences.size() != 4 || separate_sequences.size() != 1); ++attempt) {
        GetMainSignals().NotifyGovernanceVote(TestHash(0));
        GetMainSignals().NotifyGovernanceObject(TestHash(0));
        GetMainSignals().TransactionAddedToMempool(TestTransaction(0), 1);
        SyncWithValidationInterfaceQueue();
        for (auto frames = shared.Receive(); !frames.empty(); frames = shared.Receive()) CheckMessage(frames, shared_sequences);
        for (auto frames = separate.Receive(); !frames.empty(); frames = separate.Receive()) CheckMessage(frames, separate_sequences);
    }
    BOOST_REQUIRE_EQUAL(shared_sequences.size(), 4U);
    BOOST_REQUIRE_EQUAL(separate_sequences.size(), 1U);

    constexpr uint32_t COUNT{100};
    std::map<std::string, std::set<Bytes>> expected;
    for (uint32_t i = 1; i <= COUNT; ++i) {
        expected["hashgovernancevote"].insert(HashBytes(TestHash(i)));
        expected["hashgovernancevote"].insert(HashBytes(TestHash(COUNT + i)));
        expected["hashgovernanceobject"].insert(HashBytes(TestHash(i)));
        const Bytes tx_hash = HashBytes(TestTransaction(i)->GetHash());
        expected["hashtx"].insert(tx_hash);
        Bytes sequence = tx_hash;
        sequence.resize(41);
        sequence[32] = 'A';
        WriteLE64(sequence.data() + 33, i);
        expected["sequence"].insert(sequence);
    }
    auto separate_expected = expected.at("hashgovernancevote");
    std::promise<void> start;
    auto ready = start.get_future().share();
    std::atomic<bool> done{false};
    std::atomic<bool> metadata_valid{true};
    std::thread metadata{[&] {
        ready.wait();
        while (!done) {
            const auto active = interface->GetActiveNotifiers();
            if (active.size() != 5) metadata_valid = false;
            for (const auto* notifier : active) {
                if (notifier->GetType().empty() || notifier->GetOutboundMessageHighWaterMark() != 4096) metadata_valid = false;
            }
        }
    }};
    std::thread first_votes{[&] {
        ready.wait();
        for (uint32_t i = 1; i <= COUNT; ++i) GetMainSignals().NotifyGovernanceVote(TestHash(i));
    }};
    std::thread governance{[&] {
        ready.wait();
        for (uint32_t i = 1; i <= COUNT; ++i) {
            GetMainSignals().NotifyGovernanceVote(TestHash(COUNT + i));
            GetMainSignals().NotifyGovernanceObject(TestHash(i));
        }
    }};
    std::thread ordinary{[&] {
        ready.wait();
        for (uint32_t i = 1; i <= COUNT; ++i) GetMainSignals().TransactionAddedToMempool(TestTransaction(i), i);
    }};
    start.set_value();
    first_votes.join();
    governance.join();
    ordinary.join();
    SyncWithValidationInterfaceQueue();
    done = true;
    metadata.join();
    BOOST_CHECK(metadata_valid);

    for (uint32_t i = 0; i < 5 * COUNT; ++i) {
        const auto frames = shared.Receive();
        const auto topic = CheckMessage(frames, shared_sequences);
        BOOST_REQUIRE(expected.count(topic));
        BOOST_CHECK_EQUAL(expected.at(topic).erase(frames[1]), 1U);
    }
    for (const auto& [topic, messages] : expected) BOOST_CHECK_MESSAGE(messages.empty(), topic);
    for (uint32_t i = 0; i < 2 * COUNT; ++i) {
        const auto frames = separate.Receive();
        BOOST_CHECK_EQUAL(CheckMessage(frames, separate_sequences), "hashgovernancevote");
        BOOST_CHECK_EQUAL(separate_expected.erase(frames[1]), 1U);
    }
    BOOST_CHECK(separate_expected.empty());
    BOOST_CHECK(shared.Receive().empty());
    BOOST_CHECK(separate.Receive().empty());
}

BOOST_AUTO_TEST_CASE(failed_publication_retires_once_and_preserves_metadata_lifetime)
{
    auto failed = std::make_shared<NotificationState>();
    auto healthy = std::make_shared<NotificationState>();
    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;
    auto failing_notifier = std::make_unique<RecordingNotifier>(failed, true);
    failing_notifier->SetType("pub-failing");
    failing_notifier->SetAddress("inproc://retired");
    notifiers.push_back(std::move(failing_notifier));
    auto healthy_notifier = std::make_unique<RecordingNotifier>(healthy);
    healthy_notifier->SetType("pub-healthy");
    notifiers.push_back(std::move(healthy_notifier));
    auto interface = CZMQNotificationInterfaceTestAccess::Create(std::move(notifiers));
    {
        RegisteredInterface registered{interface};
        const auto snapshot = interface->GetActiveNotifiers();
        BOOST_REQUIRE_EQUAL(snapshot.size(), 2U);
        PausedQueue paused;
        GetMainSignals().NotifyGovernanceVote(TestHash(1));
        GetMainSignals().NotifyGovernanceVote(TestHash(2));
        GetMainSignals().NotifyGovernanceObject(TestHash(3));
        GetMainSignals().TransactionAddedToMempool(TestTransaction(4), 4);
        std::atomic<bool> done{false};
        std::atomic<bool> metadata_valid{true};
        std::thread metadata{[&] {
            while (!done) {
                for (const auto* notifier : interface->GetActiveNotifiers()) {
                    if (notifier->GetType() != "pub-failing" && notifier->GetType() != "pub-healthy") metadata_valid = false;
                }
                if (snapshot.front()->GetAddress() != "inproc://retired") metadata_valid = false;
            }
        }};
        paused.Resume();
        done = true;
        metadata.join();
        BOOST_CHECK(metadata_valid);
        BOOST_CHECK_EQUAL(failed->votes.size(), 1U);
        BOOST_CHECK(failed->objects.empty());
        BOOST_CHECK_EQUAL(failed->transactions, 0U);
        BOOST_CHECK_EQUAL(failed->shutdowns, 1U);
        BOOST_CHECK_EQUAL(failed->destroyed, 0U);
        BOOST_REQUIRE_EQUAL(interface->GetActiveNotifiers().size(), 1U);
        BOOST_CHECK_EQUAL(snapshot.front()->GetType(), "pub-failing");
        BOOST_CHECK(!snapshot.front()->IsActive());
        BOOST_CHECK_EQUAL(healthy->votes.size(), 2U);
        BOOST_CHECK_EQUAL(healthy->objects.size(), 1U);
        BOOST_CHECK_EQUAL(healthy->transactions, 1U);
    }
    interface.reset();
    BOOST_CHECK_EQUAL(failed->shutdowns, 1U);
    BOOST_CHECK_EQUAL(failed->destroyed, 1U);
    BOOST_CHECK_EQUAL(healthy->shutdowns, 1U);
    BOOST_CHECK_EQUAL(healthy->destroyed, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
