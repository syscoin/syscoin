// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <compat/compat.h>
#include <test/util/setup_common.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <memory>
#include <thread>

#ifdef USE_POLL
#include <poll.h>
#endif

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(sock_tests, BasicTestingSetup)

static bool SocketIsClosed(const SOCKET& s)
{
    // Notice that if another thread is running and creates its own socket after `s` has been
    // closed, it may be assigned the same file descriptor number. In this case, our test will
    // wrongly pretend that the socket is not closed.
    int type;
    socklen_t len = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (sockopt_arg_type)&type, &len) == SOCKET_ERROR;
}

static SOCKET CreateSocket()
{
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(s != static_cast<SOCKET>(SOCKET_ERROR));
    return s;
}

BOOST_AUTO_TEST_CASE(constructor_and_destructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock = new Sock(s);
    BOOST_CHECK(*sock == s);
    BOOST_CHECK(!SocketIsClosed(s));
    delete sock;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_constructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock1 = new Sock(s);
    Sock* sock2 = new Sock(std::move(*sock1));
    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s));
    BOOST_CHECK(*sock2 == s);
    delete sock2;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_assignment)
{
    const SOCKET s1 = CreateSocket();
    const SOCKET s2 = CreateSocket();
    Sock* sock1 = new Sock(s1);
    Sock* sock2 = new Sock(s2);

    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(!SocketIsClosed(s2));

    *sock2 = std::move(*sock1);
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock2;
    BOOST_CHECK(SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
}

BOOST_AUTO_TEST_CASE(wait_many_urgent_data_respects_receive_interest)
{
    Sock listener{CreateSocket()};
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)), 0);
    BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
    socklen_t endpoint_len{sizeof(endpoint)};
    BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&endpoint), &endpoint_len), 0);

    auto sender{std::make_shared<Sock>(CreateSocket())};
    BOOST_REQUIRE_EQUAL(sender->Connect(reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)), 0);
    std::shared_ptr<Sock> receiver{listener.Accept(nullptr, nullptr)};
    BOOST_REQUIRE(receiver);
    BOOST_REQUIRE(receiver->IsSelectable());
    BOOST_REQUIRE(sender->IsSelectable());
    const int inline_urgent{0};
    BOOST_REQUIRE_EQUAL(receiver->SetSockOpt(SOL_SOCKET, SO_OOBINLINE, &inline_urgent, sizeof(inline_urgent)), 0);
    BOOST_REQUIRE_EQUAL(sender->Send("!", 1, MSG_OOB), 1);

    // Wait for a real TCP exception before checking that a paused receiver
    // cannot turn it into another read, even while its socket is writable.
#ifdef USE_POLL
    pollfd urgent_poll{static_cast<int>(receiver->Get()), POLLPRI, 0};
    BOOST_REQUIRE_EQUAL(poll(&urgent_poll, 1, 5000), 1);
    BOOST_REQUIRE(urgent_poll.revents & POLLPRI);
#else
    fd_set exceptional;
    FD_ZERO(&exceptional);
    FD_SET(receiver->Get(), &exceptional);
    timeval timeout{5, 0};
    BOOST_REQUIRE_EQUAL(select(static_cast<int>(receiver->Get() + 1), nullptr, nullptr, &exceptional, &timeout), 1);
    BOOST_REQUIRE(FD_ISSET(receiver->Get(), &exceptional));
#endif

    Sock::EventsPerSock interests{
        {receiver, Sock::Events{Sock::SEND}},
        {sender, Sock::Events{Sock::SEND}},
    };
    BOOST_REQUIRE(receiver->WaitMany(0ms, interests));
    BOOST_CHECK_EQUAL(interests.at(receiver).occurred, Sock::SEND);

    // Keep a writable socket in the set: Windows select rejects empty sets.
    interests.at(receiver).requested = 0;
    BOOST_REQUIRE(receiver->WaitMany(0ms, interests));
    BOOST_CHECK_EQUAL(interests.at(receiver).occurred, 0);

    interests.at(receiver).requested = Sock::RECV | Sock::SEND;
    BOOST_REQUIRE(receiver->WaitMany(0ms, interests));
    BOOST_CHECK(interests.at(receiver).occurred & Sock::SEND);
#ifdef USE_POLL
    // The poll backend does not subscribe to urgent-data events (POLLPRI).
    BOOST_CHECK(!(interests.at(receiver).occurred & Sock::ERR));
#else
    // Receive-enabled select sockets must still report exceptions.
    BOOST_CHECK(interests.at(receiver).occurred & Sock::ERR);
#endif
    char urgent{};
    BOOST_REQUIRE_EQUAL(receiver->Recv(&urgent, 1, MSG_OOB), 1);
    BOOST_CHECK_EQUAL(urgent, '!');
}

#ifndef WIN32 // Windows does not have socketpair(2).

static void CreateSocketPair(int s[2])
{
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, s), 0);
}

static void SendAndRecvMessage(const Sock& sender, const Sock& receiver)
{
    const char* msg = "abcd";
    constexpr ssize_t msg_len = 4;
    char recv_buf[10];

    BOOST_CHECK_EQUAL(sender.Send(msg, msg_len, 0), msg_len);
    BOOST_CHECK_EQUAL(receiver.Recv(recv_buf, sizeof(recv_buf), 0), msg_len);
    BOOST_CHECK_EQUAL(strncmp(msg, recv_buf, msg_len), 0);
}

BOOST_AUTO_TEST_CASE(send_and_receive)
{
    int s[2];
    CreateSocketPair(s);

    Sock* sock0 = new Sock(s[0]);
    Sock* sock1 = new Sock(s[1]);

    SendAndRecvMessage(*sock0, *sock1);

    Sock* sock0moved = new Sock(std::move(*sock0));
    Sock* sock1moved = new Sock(INVALID_SOCKET);
    *sock1moved = std::move(*sock1);

    delete sock0;
    delete sock1;

    SendAndRecvMessage(*sock1moved, *sock0moved);

    delete sock0moved;
    delete sock1moved;

    BOOST_CHECK(SocketIsClosed(s[0]));
    BOOST_CHECK(SocketIsClosed(s[1]));
}

BOOST_AUTO_TEST_CASE(wait)
{
    int s[2];
    CreateSocketPair(s);

    Sock sock0(s[0]);
    Sock sock1(s[1]);

    std::thread waiter([&sock0]() { (void)sock0.Wait(24h, Sock::RECV); });

    BOOST_REQUIRE_EQUAL(sock1.Send("a", 1, 0), 1);

    waiter.join();
}

BOOST_AUTO_TEST_CASE(recv_until_terminator_limit)
{
    constexpr auto timeout = 1min; // High enough so that it is never hit.
    CThreadInterrupt interrupt;
    int s[2];
    CreateSocketPair(s);

    Sock sock_send(s[0]);
    Sock sock_recv(s[1]);

    std::thread receiver([&sock_recv, &timeout, &interrupt]() {
        constexpr size_t max_data{10};
        bool threw_as_expected{false};
        // BOOST_CHECK_EXCEPTION() writes to some variables shared with the main thread which
        // creates a data race. So mimic it manually.
        try {
            (void)sock_recv.RecvUntilTerminator('\n', timeout, interrupt, max_data);
        } catch (const std::runtime_error& e) {
            threw_as_expected = HasReason("too many bytes without a terminator")(e);
        }
        assert(threw_as_expected);
    });

    BOOST_REQUIRE_NO_THROW(sock_send.SendComplete("1234567", timeout, interrupt));
    BOOST_REQUIRE_NO_THROW(sock_send.SendComplete("89a\n", timeout, interrupt));

    receiver.join();
}

#endif /* WIN32 */

BOOST_AUTO_TEST_SUITE_END()
