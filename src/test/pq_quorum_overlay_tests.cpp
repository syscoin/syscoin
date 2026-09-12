// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_overlay.h>

#include <net.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <queue>
#include <set>
#include <vector>

using namespace llmq;

namespace {

uint256 NonNullHash(uint64_t value, uint64_t salt = 0)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<uint8_t>(value >> (8 * i));
        hash.begin()[8 + i] = static_cast<uint8_t>(salt >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

pq::FrozenQuorumRoster Roster(uint64_t group_tag,
                              const std::vector<uint256>& participants)
{
    BOOST_REQUIRE_LE(participants.size(), pq::QUORUM_SIZE);
    pq::FrozenQuorumRoster roster;
    roster.descriptor.epoch = static_cast<uint32_t>(group_tag);
    roster.descriptor.base_hash = NonNullHash(group_tag, 0xb453);
    for (std::size_t slot{0}; slot < participants.size(); ++slot) {
        auto& member = roster.members[slot];
        member.pro_tx_hash = participants[slot];
        member.eligible = true;
        member.child_root.emplace();
    }
    return roster;
}

PQQuorumConnectionSet Connections(std::initializer_list<uint256> members)
{
    return PQQuorumConnectionSet{members};
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_quorum_overlay_tests)

BOOST_AUTO_TEST_CASE(relay_target_tracks_the_current_recovery_window)
{
    const auto schedule{pq::MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);

    BOOST_CHECK(!GetPQQuorumOverlayTargetHeight(
        *schedule, /*predecessor_height=*/864, /*tip_height=*/869));
    BOOST_CHECK_EQUAL(
        *GetPQQuorumOverlayTargetHeight(
            *schedule, /*predecessor_height=*/864, /*tip_height=*/870),
        865);
    BOOST_CHECK_EQUAL(
        *GetPQQuorumOverlayTargetHeight(
            *schedule, /*predecessor_height=*/864, /*tip_height=*/1400),
        1395);
    BOOST_CHECK_EQUAL(
        *GetPQQuorumOverlayTargetHeight(
            *schedule, /*predecessor_height=*/865, /*tip_height=*/1400),
        1395);
}

BOOST_AUTO_TEST_CASE(topology_is_deterministic_bounded_and_connected)
{
    std::vector<uint256> participants;
    participants.reserve(pq::QUORUM_SIZE);
    for (std::size_t i{0}; i < pq::QUORUM_SIZE; ++i) {
        participants.push_back(NonNullHash(10'000 + i));
    }
    const auto roster{Roster(7, participants)};

    std::map<uint256, std::size_t> positions;
    for (std::size_t i{0}; i < participants.size(); ++i) {
        positions.emplace(participants[i], i);
    }
    std::vector<std::vector<std::size_t>> graph(participants.size());
    for (std::size_t i{0}; i < participants.size(); ++i) {
        const auto first{
            GetPQQuorumRelayConnections(roster, participants[i])};
        const auto second{
            GetPQQuorumRelayConnections(roster, participants[i])};
        BOOST_CHECK(first == second);
        BOOST_CHECK_EQUAL(first.size(), 8U);
        BOOST_CHECK_EQUAL(first.count(participants[i]), 0U);
        BOOST_CHECK_EQUAL(
            first.count(participants[(i + 1) % participants.size()]), 1U);
        for (const auto& peer : first) {
            const auto position{positions.find(peer)};
            BOOST_REQUIRE(position != positions.end());
            graph[i].push_back(position->second);
        }
    }

    std::vector<bool> reached(participants.size());
    std::queue<std::size_t> pending;
    reached[0] = true;
    pending.push(0);
    while (!pending.empty()) {
        const auto current{pending.front()};
        pending.pop();
        for (const auto peer : graph[current]) {
            if (reached[peer]) continue;
            reached[peer] = true;
            pending.push(peer);
        }
    }
    BOOST_CHECK_EQUAL(
        static_cast<std::size_t>(std::count(reached.begin(), reached.end(), true)),
        participants.size());
}

BOOST_AUTO_TEST_CASE(disjoint_rosters_form_one_bounded_connected_union)
{
    std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS> rosters;
    std::vector<uint256> participants;
    participants.reserve(pq::ACTIVE_QUORUMS * pq::QUORUM_SIZE);
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        std::vector<uint256> roster_members;
        roster_members.reserve(pq::QUORUM_SIZE);
        for (std::size_t member{0}; member < pq::QUORUM_SIZE; ++member) {
            const uint256 identity{
                NonNullHash(100'000 + slot * pq::QUORUM_SIZE + member)};
            roster_members.push_back(identity);
            participants.push_back(identity);
        }
        rosters[slot] = Roster(20 + slot, roster_members);
    }

    std::map<uint256, std::size_t> positions;
    for (std::size_t i{0}; i < participants.size(); ++i) {
        positions.emplace(participants[i], i);
    }
    std::vector<std::vector<std::size_t>> graph(participants.size());
    for (std::size_t i{0}; i < participants.size(); ++i) {
        const auto peers{
            GetPQQuorumUnionRelayConnections(rosters, participants[i])};
        BOOST_CHECK_EQUAL(peers.size(), 10U);
        BOOST_CHECK_EQUAL(peers.count(participants[i]), 0U);
        for (const auto& peer : peers) {
            const auto position{positions.find(peer)};
            BOOST_REQUIRE(position != positions.end());
            graph[i].push_back(position->second);
        }
    }

    std::vector<bool> reached(participants.size());
    std::queue<std::size_t> pending;
    reached[0] = true;
    pending.push(0);
    while (!pending.empty()) {
        const auto current{pending.front()};
        pending.pop();
        for (const auto peer : graph[current]) {
            if (reached[peer]) continue;
            reached[peer] = true;
            pending.push(peer);
        }
    }
    BOOST_CHECK_EQUAL(
        static_cast<std::size_t>(
            std::count(reached.begin(), reached.end(), true)),
        participants.size());
}

BOOST_AUTO_TEST_CASE(plan_is_one_union_group_for_any_participating_signer)
{
    const uint256 local{NonNullHash(1)};
    const uint256 peer_a{NonNullHash(2)};
    const uint256 peer_b{NonNullHash(3)};
    const uint256 outsider{NonNullHash(4)};
    std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS> rosters{
        Roster(10, {local, peer_a, peer_b}),
        Roster(11, {local, peer_a, outsider}),
        Roster(12, {peer_b, local, outsider}),
        Roster(13, {outsider})};
    // Selection alone is insufficient: only a frozen registered child key
    // makes this operator a ChainLock signer and overlay participant.
    rosters[1].members[0].child_root.reset();

    const auto plan{BuildPQQuorumOverlayPlan(
        NonNullHash(50), 100, NonNullHash(51), rosters, local)};
    BOOST_REQUIRE_EQUAL(plan.size(), 1U);
    for (const auto& [group, peers] : plan) {
        BOOST_CHECK(!group.IsNull());
        BOOST_CHECK_EQUAL(peers.count(local), 0U);
        BOOST_CHECK_LE(peers.size(), 2U);
    }

    rosters[0].members[0].child_root.reset();
    rosters[2].members[1].child_root.reset();
    BOOST_CHECK(BuildPQQuorumOverlayPlan(
        NonNullHash(50), 100, NonNullHash(51), rosters, local).empty());
}

BOOST_AUTO_TEST_CASE(prepared_context_plan_bootstraps_without_a_winner)
{
    const uint256 context_hash{NonNullHash(60)};
    PQQuorumConnectionSet relay_members;
    for (std::size_t member{0}; member < 10; ++member) {
        relay_members.insert(NonNullHash(61 + member));
    }

    const auto plan{BuildPreparedPQQuorumOverlayPlan(
        context_hash, relay_members)};
    BOOST_REQUIRE_EQUAL(plan.size(), 1U);
    BOOST_CHECK(plan.at(context_hash) == relay_members);
    BOOST_CHECK(BuildPreparedPQQuorumOverlayPlan(
        uint256{}, relay_members).empty());
    BOOST_CHECK(BuildPreparedPQQuorumOverlayPlan(
        context_hash, {}).empty());

    const PQQuorumOverlayPredecessor predecessor{
        59, NonNullHash(59)};
    BOOST_CHECK(IsPreparedPQQuorumOverlaySourceCurrent(
        std::nullopt, std::nullopt));
    BOOST_CHECK(!IsPreparedPQQuorumOverlaySourceCurrent(
        predecessor, std::nullopt));
    BOOST_CHECK(!IsPreparedPQQuorumOverlaySourceCurrent(
        std::nullopt, predecessor));
    BOOST_CHECK(IsPreparedPQQuorumOverlaySourceCurrent(
        predecessor, predecessor));
    auto stale_predecessor{predecessor};
    stale_predecessor.block_hash = NonNullHash(58);
    BOOST_CHECK(!IsPreparedPQQuorumOverlaySourceCurrent(
        predecessor, stale_predecessor));
}

BOOST_FIXTURE_TEST_CASE(
    prepared_context_plan_retries_after_a_clear, TestingSetup)
{
    const uint256 context_hash{NonNullHash(80)};
    const uint256 relay_member{NonNullHash(81)};
    const PQQuorumConnectionSet relay_members{relay_member};
    CPQQuorumConnectionOverlay overlay{
        *Assert(m_node.connman), {}, [] { return std::nullopt; }};

    BOOST_REQUIRE(overlay.ApplyPreparedContext(
        context_hash, relay_members, std::nullopt));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        relay_member));

    const PQQuorumOverlayPredecessor stale_predecessor{
        79, NonNullHash(79)};
    BOOST_CHECK(!overlay.ApplyPreparedContext(
        context_hash, relay_members, stale_predecessor));
    BOOST_CHECK(!overlay.ApplyPreparedContext(
        context_hash, {}, std::nullopt));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        relay_member));

    overlay.Clear();
    BOOST_CHECK(!m_node.connman->IsMasternodeQuorumRelayMember(
        relay_member));
    BOOST_REQUIRE(overlay.ApplyPreparedContext(
        context_hash, relay_members, std::nullopt));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        relay_member));
}

BOOST_FIXTURE_TEST_CASE(
    payment_audit_plan_is_bounded_and_independent, TestingSetup)
{
    const uint256 chainlock_group_a{NonNullHash(90)};
    const uint256 chainlock_group_b{NonNullHash(91)};
    const uint256 chainlock_member_a{NonNullHash(92)};
    const uint256 chainlock_member_b{NonNullHash(93)};
    const uint256 audit_group_a{NonNullHash(94)};
    const uint256 audit_group_b{NonNullHash(95)};
    const uint256 audit_member_a{NonNullHash(96)};
    const uint256 audit_member_b{NonNullHash(97)};
    CPQQuorumConnectionOverlay overlay{
        *Assert(m_node.connman), {}, [] { return std::nullopt; }};

    BOOST_REQUIRE(overlay.ApplyPreparedContext(
        chainlock_group_a, {chainlock_member_a}, std::nullopt));
    BOOST_REQUIRE(overlay.ApplyPaymentAuditContext(
        audit_group_a, {audit_member_a}, 7));
    BOOST_REQUIRE(overlay.ApplyPreparedContext(
        chainlock_group_b, {chainlock_member_b}, std::nullopt));
    BOOST_CHECK(!m_node.connman->IsMasternodeQuorumRelayMember(
        chainlock_member_a));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        chainlock_member_b));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        audit_member_a));

    BOOST_CHECK(!overlay.RemovePaymentAuditContext(
        audit_group_a, 6));
    BOOST_REQUIRE(overlay.ApplyPaymentAuditContext(
        audit_group_b, {audit_member_b}, 8));
    BOOST_CHECK(!m_node.connman->IsMasternodeQuorumRelayMember(
        audit_member_a));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        audit_member_b));
    BOOST_CHECK(!overlay.RemovePaymentAuditContext(
        audit_group_a, 7));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        audit_member_b));

    BOOST_REQUIRE(overlay.RemovePaymentAuditContext(
        audit_group_b, 8));
    BOOST_CHECK(!m_node.connman->IsMasternodeQuorumRelayMember(
        audit_member_b));
    BOOST_CHECK(m_node.connman->IsMasternodeQuorumRelayMember(
        chainlock_member_b));
    BOOST_CHECK(!overlay.ApplyPaymentAuditContext(
        audit_group_b, {audit_member_b}, 8));
    BOOST_CHECK(!overlay.ApplyPaymentAuditContext(
        audit_group_b, {}, 9));
}

BOOST_AUTO_TEST_CASE(reconciler_rolls_over_and_preserves_retry_groups)
{
    const uint256 group_a{NonNullHash(100)};
    const uint256 group_b{NonNullHash(101)};
    const uint256 group_c{NonNullHash(102)};
    const uint256 peer_a{NonNullHash(200)};
    const uint256 peer_b{NonNullHash(201)};
    const uint256 peer_c{NonNullHash(202)};

    std::vector<uint256> installed;
    std::vector<uint256> removed;
    PQQuorumOverlayReconciler reconciler{
        [&](const uint256& group, const PQQuorumConnectionSet&) {
            installed.push_back(group);
        },
        [&](const uint256& group) { removed.push_back(group); }};

    const PQQuorumOverlayPlan first{
        {group_a, Connections({peer_a})},
        {group_b, Connections({peer_b})}};
    reconciler.Apply(first);
    BOOST_CHECK_EQUAL(installed.size(), 2U);
    BOOST_CHECK(removed.empty());

    // The connector retains these groups and retries disconnected peers, so
    // an unchanged tip does not need to reinstall anything.
    reconciler.Apply(first);
    BOOST_CHECK_EQUAL(installed.size(), 2U);
    BOOST_CHECK(removed.empty());

    const PQQuorumOverlayPlan rollover{
        {group_b, Connections({peer_b})},
        {group_c, Connections({peer_c})}};
    reconciler.Apply(rollover);
    BOOST_CHECK_EQUAL(installed.size(), 3U);
    BOOST_REQUIRE_EQUAL(removed.size(), 1U);
    BOOST_CHECK(removed.front() == group_a);
    BOOST_CHECK(reconciler.GetInstalledPlan() == rollover);

    const PQQuorumOverlayPlan changed{
        {group_b, Connections({peer_a, peer_b})},
        {group_c, Connections({peer_c})}};
    reconciler.Apply(changed);
    BOOST_CHECK_EQUAL(installed.size(), 4U);
    BOOST_CHECK_EQUAL(removed.size(), 1U);

    reconciler.Clear();
    BOOST_CHECK(reconciler.GetInstalledPlan().empty());
    BOOST_CHECK_EQUAL(removed.size(), 3U);
    const std::set<uint256> final_removed{removed.begin() + 1, removed.end()};
    const std::set<uint256> expected_removed{group_b, group_c};
    BOOST_CHECK(final_removed == expected_removed);
}

BOOST_AUTO_TEST_SUITE_END()
