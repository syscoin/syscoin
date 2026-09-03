// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <compat/compat.h>
#include <cstdint>
#include <governance/governancepages.h> // SYSCOIN: fork relay tests.
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/net.h> // SYSCOIN: fork connection-role test hooks.
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ios>
#include <memory>
#include <optional>
#include <string>
#include <vector> // SYSCOIN: bounded fork inventory tests.

using namespace std::literals;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)
// SYSCOIN: BEGIN fork-only bounded admission and failover tests for PQ
// certificates, paged governance relay, and masternode connection roles.
BOOST_AUTO_TEST_CASE(masternode_connection_status_is_role_exact)
{
    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c0ff;
    const CAddress address{CService{ipv4_addr, 7799}, NODE_NETWORK};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    BOOST_REQUIRE(connman.ReserveTestOutboundAddress(address));
    BOOST_CHECK(!connman.ReserveTestOutboundAddress(address));
    connman.ReleaseTestOutboundAddress(address);

    auto* node = new CNode{
        /*id=*/1000, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/1, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    connman.AddTestNode(*node);
    BOOST_CHECK(!connman.ReserveTestOutboundAddress(address));

    BOOST_CHECK(connman.GetMasternodeConnectionStatus(address) ==
                CConnman::MasternodeConnectionStatus::ORDINARY);
    node->m_masternode_connection = true;
    BOOST_CHECK(connman.GetMasternodeConnectionStatus(address) ==
                CConnman::MasternodeConnectionStatus::DEDICATED);
    node->fDisconnect = true;
    BOOST_CHECK(connman.GetMasternodeConnectionStatus(address) ==
                CConnman::MasternodeConnectionStatus::DISCONNECTING);
    node->fDisconnect = false;

    // Exact-address uniqueness is a security invariant. If another caller
    // violates it, fail closed instead of selecting an arbitrary role.
    auto* duplicate = new CNode{
        /*id=*/1001, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/2, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::MANUAL,
        /*inbound_onion=*/false};
    connman.AddTestNode(*duplicate);
    BOOST_CHECK(connman.GetMasternodeConnectionStatus(address) ==
                CConnman::MasternodeConnectionStatus::DISCONNECTING);

    connman.ClearTestNodes();
    BOOST_CHECK(connman.GetMasternodeConnectionStatus(address) ==
                CConnman::MasternodeConnectionStatus::NONE);
}

BOOST_AUTO_TEST_CASE(cinv_pq_chainlock_command)
{
    const CInv inv(MSG_CLSIG, uint256::ONEV);
    BOOST_CHECK_EQUAL(inv.GetCommand(), NetMsgType::CLSIG);
    BOOST_CHECK_EQUAL(
        inv.ToString(),
        strprintf("%s %s", NetMsgType::CLSIG, uint256::ONEV.ToString()));
    const CInv audit_inv(MSG_PQPOSECERT, uint256::ONEV);
    BOOST_CHECK_EQUAL(audit_inv.GetCommand(), NetMsgType::PQPOSECERT);
    BOOST_CHECK_EQUAL(
        audit_inv.ToString(),
        strprintf("%s %s", NetMsgType::PQPOSECERT,
                  uint256::ONEV.ToString()));
    BOOST_CHECK(audit_inv.IsGenTxMsg());
    BOOST_CHECK(!IsActualTransactionInv(inv));
    BOOST_CHECK(IsActualTransactionInv(CInv{MSG_TX, uint256::ONEV}));
    BOOST_CHECK(IsActualTransactionInv(CInv{MSG_WTX, uint256::ONEV}));
    BOOST_CHECK(IsActualTransactionInv(CInv{MSG_WITNESS_TX, uint256::ONEV}));
    BOOST_CHECK(!SupportsPQChainLocks(PQ_MNAUTH_PROTO_VERSION - 1));
    BOOST_CHECK(SupportsPQChainLocks(PQ_MNAUTH_PROTO_VERSION));
}

BOOST_AUTO_TEST_CASE(pq_certificate_inv_batch_is_bounded)
{
    std::vector<CInv> inventory{
        {MSG_CLSIG, uint256{1}},
        {MSG_CLSIG, uint256{2}},
        {MSG_PQPOSECERT, uint256{3}},
        {MSG_PQPOSECERT, uint256{4}},
        {MSG_TX, uint256{5}},
    };
    BOOST_CHECK(!HasTooManyPQCertificateInvs(inventory));

    // The two certificate families use independent request trackers, but no
    // peer may turn either one into a MAX_INV_SZ batch of database probes.
    inventory.emplace_back(MSG_CLSIG, uint256{6});
    BOOST_CHECK(HasTooManyPQCertificateInvs(inventory));
    inventory.back() = CInv{MSG_PQPOSECERT, uint256{6}};
    BOOST_CHECK(HasTooManyPQCertificateInvs(inventory));

    std::vector<CInv> duplicate_flood(
        GetMaxInv(), CInv{MSG_PQPOSECERT, uint256{7}});
    BOOST_CHECK(HasTooManyPQCertificateInvs(duplicate_flood));
}

BOOST_AUTO_TEST_CASE(payment_audit_kill_switch_allows_only_required_fetch)
{
    BOOST_CHECK(ShouldRequestPaymentAuditCertificate(
        /*operational=*/true, /*required_dependency=*/false,
        /*initial_block_download=*/false));
    BOOST_CHECK(ShouldRequestPaymentAuditCertificate(
        /*operational=*/false, /*required_dependency=*/true,
        /*initial_block_download=*/true));
    BOOST_CHECK(!ShouldRequestPaymentAuditCertificate(
        /*operational=*/false, /*required_dependency=*/false,
        /*initial_block_download=*/false));
    BOOST_CHECK(!ShouldRequestPaymentAuditCertificate(
        /*operational=*/true, /*required_dependency=*/false,
        /*initial_block_download=*/true));
    BOOST_CHECK(!ShouldProcessPQCertificateAnnouncement(
        /*peer_already_knows=*/true, /*required_dependency=*/false));
    BOOST_CHECK(ShouldProcessPQCertificateAnnouncement(
        /*peer_already_knows=*/true, /*required_dependency=*/true));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_request_admission_is_bounded)
{
    ChainLockRequestTracker tracker;
    const NodeId first_peer{10};
    const NodeId second_peer{11};
    const uint256 first{1};
    const uint256 second{2};
    const uint256 excess{3};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_CHECK(tracker.Announce(first_peer, first));
    BOOST_CHECK(tracker.Announce(first_peer, first));
    BOOST_CHECK(tracker.Announce(first_peer, second));
    BOOST_CHECK(!tracker.Announce(first_peer, excess));
    BOOST_CHECK_EQUAL(tracker.Count(first_peer), 2U);
    BOOST_CHECK(tracker.Announce(second_peer, first));

    const auto requested{tracker.Request(first_peer, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == first);
    BOOST_CHECK(tracker.IsRequested(first_peer, first));
    BOOST_CHECK(!tracker.Request(second_peer, now, expiry));

    tracker.ReceivedResponse(first_peer, first);
    BOOST_CHECK(!tracker.IsRequested(first_peer, first));

    // A response rotates this logical ID behind other unattempted IDs at the
    // same trust level. This prevents one Sybil-corroborated fake ID from
    // retaining the public lane forever.
    const auto next{tracker.Request(first_peer, now, expiry)};
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == second);
    tracker.ReceivedResponse(first_peer, second);

    const auto alternate{tracker.Request(second_peer, now, expiry)};
    BOOST_REQUIRE(alternate);
    BOOST_CHECK(*alternate == first);
    tracker.Forget(first);
    BOOST_CHECK_EQUAL(tracker.Count(second_peer), 0U);
    BOOST_CHECK(!tracker.RequestedBy(second_peer));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_local_dependency_does_not_cooldown_exact_provider)
{
    const NodeId peer{12};
    const uint256 audit_id{uint256S("12")};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    ChainLockRequestTracker deferred;
    BOOST_REQUIRE(deferred.Announce(
        peer, audit_id,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true));
    BOOST_REQUIRE(deferred.Request(peer, now, expiry));
    deferred.ReceivedResponse(peer, audit_id);
    BOOST_REQUIRE(deferred.Announce(
        peer, audit_id,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true));
    BOOST_CHECK(deferred.Request(peer, now, expiry));

    ChainLockRequestTracker failed;
    BOOST_REQUIRE(failed.Announce(
        peer, audit_id,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true));
    BOOST_REQUIRE(failed.Request(peer, now, expiry));
    BOOST_REQUIRE(failed.ReceivedFailure(peer, audit_id, now));
    BOOST_REQUIRE(failed.Announce(
        peer, audit_id,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true));
    BOOST_CHECK(!failed.Request(peer, now, expiry));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_request_timeout_and_disconnect_cleanup)
{
    ChainLockRequestTracker tracker;
    const NodeId stale_peer{20};
    const NodeId fallback_peer{21};
    const uint256 logical_id{9};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(stale_peer, logical_id));
    BOOST_REQUIRE(tracker.Announce(fallback_peer, logical_id));
    BOOST_REQUIRE(tracker.Request(stale_peer, now, expiry));

    std::vector<ChainLockRequestTracker::InFlight> expired;
    const auto fallback{tracker.Request(
        fallback_peer, expiry, std::chrono::microseconds{300}, &expired)};
    BOOST_REQUIRE_EQUAL(expired.size(), 1U);
    BOOST_CHECK_EQUAL(expired.front().peer, stale_peer);
    BOOST_CHECK(expired.front().logical_id == logical_id);
    BOOST_REQUIRE(fallback);
    BOOST_CHECK(*fallback == logical_id);
    BOOST_CHECK_EQUAL(tracker.Count(stale_peer), 0U);

    BOOST_REQUIRE(tracker.Announce(stale_peer, logical_id));
    BOOST_CHECK(!tracker.Request(
        stale_peer, expiry, std::chrono::microseconds{400}));

    tracker.DisconnectedPeer(fallback_peer, expiry);
    tracker.DisconnectedPeer(stale_peer, expiry);
    BOOST_CHECK_EQUAL(tracker.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_higher_trust_source_gets_reserved_lane)
{
    ChainLockRequestTracker tracker;
    const NodeId inbound_attacker{30};
    const NodeId second_inbound{31};
    const NodeId honest_outbound{32};
    const uint256 fake_first{10};
    const uint256 fake_second{11};
    const uint256 real_chainlock{12};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(inbound_attacker, fake_first));
    BOOST_REQUIRE(tracker.Request(inbound_attacker, now, expiry));

    BOOST_REQUIRE(tracker.Announce(second_inbound, fake_second));
    BOOST_CHECK(!tracker.Request(second_inbound, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, real_chainlock,
        ChainLockRequestTracker::SourcePriority::OUTBOUND));
    const auto preferred{
        tracker.Request(honest_outbound, now, expiry)};
    BOOST_REQUIRE(preferred);
    BOOST_CHECK(*preferred == real_chainlock);
    BOOST_CHECK(tracker.IsRequested(inbound_attacker, fake_first));
    BOOST_CHECK(tracker.IsRequested(honest_outbound, real_chainlock));
    BOOST_CHECK(!tracker.RequestedBy(second_inbound));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_untrusted_sybil_cannot_consume_reserved_lane)
{
    ChainLockRequestTracker tracker;
    const NodeId first_attacker{33};
    const NodeId second_attacker{34};
    const NodeId corroborating_attacker{35};
    const NodeId honest_outbound{36};
    const uint256 first_fake{13};
    const uint256 corroborated_fake{14};
    const uint256 real_chainlock{15};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(first_attacker, first_fake));
    BOOST_REQUIRE(tracker.Request(first_attacker, now, expiry));

    // Independent inbound identities are not independent trust. A Sybil must
    // not consume the lane reserved for a node-selected or authenticated peer.
    BOOST_REQUIRE(tracker.Announce(second_attacker, corroborated_fake));
    BOOST_REQUIRE(tracker.Announce(corroborating_attacker,
                                   corroborated_fake));
    BOOST_CHECK(!tracker.Request(second_attacker, now, expiry));
    BOOST_CHECK(!tracker.Request(corroborating_attacker, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, real_chainlock,
        ChainLockRequestTracker::SourcePriority::OUTBOUND));
    const auto requested{tracker.Request(honest_outbound, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == real_chainlock);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_withholding_rotates_logical_ids_fairly)
{
    ChainLockRequestTracker tracker;
    const NodeId first_attacker{37};
    const NodeId honest_inbound{100};
    const uint256 fake{18};
    const uint256 real_chainlock{19};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    for (std::size_t i{0};
         i < ChainLockRequestTracker::MAX_ANNOUNCERS_PER_LOGICAL_ID;
         ++i) {
        BOOST_REQUIRE(tracker.Announce(
            first_attacker + static_cast<NodeId>(i), fake));
    }
    BOOST_CHECK(!tracker.Announce(honest_inbound - 1, fake));
    BOOST_REQUIRE(tracker.Announce(honest_inbound, real_chainlock));

    const auto first_request{tracker.Request(first_attacker, now, expiry)};
    BOOST_REQUIRE(first_request);
    BOOST_CHECK(*first_request == fake);

    std::vector<ChainLockRequestTracker::InFlight> expired;
    const auto rotated{tracker.Request(
        honest_inbound, expiry, std::chrono::microseconds{300}, &expired)};
    BOOST_REQUIRE_EQUAL(expired.size(), 1U);
    BOOST_REQUIRE(rotated);
    BOOST_CHECK(*rotated == real_chainlock);

    // The fake remains eligible later through a different advertiser; fair
    // rotation does not break honest multi-peer retry.
    tracker.ReceivedResponse(honest_inbound, real_chainlock);
    const auto fake_retry{tracker.Request(
        first_attacker + 1, expiry, std::chrono::microseconds{300})};
    BOOST_REQUIRE(fake_retry);
    BOOST_CHECK(*fake_retry == fake);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_same_id_cap_preserves_trusted_source)
{
    ChainLockRequestTracker tracker;
    const NodeId first_attacker{110};
    const NodeId honest_outbound{120};
    const uint256 logical_id{22};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    for (std::size_t i{0};
         i < ChainLockRequestTracker::MAX_ANNOUNCERS_PER_LOGICAL_ID;
         ++i) {
        BOOST_REQUIRE(tracker.Announce(
            first_attacker + static_cast<NodeId>(i), logical_id));
    }
    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, logical_id,
        ChainLockRequestTracker::SourcePriority::OUTBOUND));
    BOOST_CHECK_EQUAL(tracker.Size(),
                      ChainLockRequestTracker::MAX_ANNOUNCERS_PER_LOGICAL_ID);

    const auto requested{tracker.Request(honest_outbound, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == logical_id);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_unsolicited_notfound_cannot_reorder)
{
    ChainLockRequestTracker tracker;
    const NodeId honest_inbound{41};
    const NodeId attacker{42};
    const uint256 real_chainlock{20};
    const uint256 fake{21};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(honest_inbound, real_chainlock));
    BOOST_REQUIRE(tracker.Announce(attacker, fake));

    // A peer may only complete the exact request assigned to it. Otherwise an
    // unsolicited NOTFOUND could rotate an honest peer's ID behind fake IDs.
    tracker.ReceivedResponse(attacker, real_chainlock);
    const auto requested{tracker.Request(honest_inbound, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == real_chainlock);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_untrusted_inventory_cannot_block_trusted_admission)
{
    ChainLockRequestTracker tracker;
    uint64_t next_id{1000};
    for (NodeId peer{100};
         tracker.Size() + 1 < ChainLockRequestTracker::MAX_ANNOUNCEMENTS;
         ++peer) {
        BOOST_REQUIRE(tracker.Announce(
            peer, uint256S(strprintf("%x", next_id++))));
        if (tracker.Size() + 1 <
            ChainLockRequestTracker::MAX_ANNOUNCEMENTS) {
            BOOST_REQUIRE(tracker.Announce(
                peer, uint256S(strprintf("%x", next_id++))));
        }
    }

    const NodeId honest_outbound{1000};
    const uint256 stale_inbound{uint256S("07cf")};
    const uint256 real_chainlock{uint256S("07d0")};
    BOOST_REQUIRE(tracker.Announce(honest_outbound, stale_inbound));
    BOOST_CHECK_EQUAL(tracker.Size(),
                      ChainLockRequestTracker::MAX_ANNOUNCEMENTS);

    // A connection may authenticate after its first announcement. Admission
    // must remain safe even when eviction removes that peer's old entry.
    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, real_chainlock,
        ChainLockRequestTracker::SourcePriority::OUTBOUND));
    BOOST_CHECK_EQUAL(tracker.Size(),
                      ChainLockRequestTracker::MAX_ANNOUNCEMENTS);
    BOOST_CHECK_EQUAL(tracker.Count(honest_outbound), 1U);
    const auto requested{tracker.Request(
        honest_outbound, std::chrono::microseconds{100},
        std::chrono::microseconds{200})};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == real_chainlock);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_dependency_displaces_full_table)
{
    ChainLockRequestTracker tracker;
    uint64_t next_id{3000};
    NodeId peer{200};
    while (tracker.Size() < ChainLockRequestTracker::MAX_ANNOUNCEMENTS) {
        BOOST_REQUIRE(tracker.Announce(
            peer, uint256S(strprintf("%x", next_id++)),
            ChainLockRequestTracker::SourcePriority::AUTHENTICATED));
        if (tracker.Size() < ChainLockRequestTracker::MAX_ANNOUNCEMENTS) {
            BOOST_REQUIRE(tracker.Announce(
                peer, uint256S(strprintf("%x", next_id++)),
                ChainLockRequestTracker::SourcePriority::AUTHENTICATED));
        }
        ++peer;
    }

    const NodeId receipt_source{999};
    const uint256 required_receipt{uint256S("0badc0de")};
    BOOST_REQUIRE(tracker.Announce(
        receipt_source, required_receipt,
        ChainLockRequestTracker::SourcePriority::INBOUND,
        /*required=*/true));
    BOOST_CHECK_EQUAL(tracker.Size(),
                      ChainLockRequestTracker::MAX_ANNOUNCEMENTS + 1);

    // Local validation chose this exact logical ID. Its source trust still
    // matters among alternate providers, but generic authenticated traffic
    // cannot keep it out of the bounded table or ahead of it in scheduling.
    const auto requested{tracker.Request(
        receipt_source, std::chrono::microseconds{100},
        std::chrono::microseconds{200})};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == required_receipt);
    BOOST_REQUIRE(tracker.RequestedBy(receipt_source));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_dependency_replaces_peer_entry)
{
    ChainLockRequestTracker tracker;
    const NodeId peer{1001};
    const uint256 generic_one{31};
    const uint256 generic_two{32};
    const uint256 required_receipt{33};

    BOOST_REQUIRE(tracker.Announce(
        peer, generic_one,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED));
    BOOST_REQUIRE(tracker.Announce(
        peer, generic_two,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED));
    BOOST_REQUIRE(tracker.Announce(
        peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::INBOUND,
        /*required=*/true));
    BOOST_CHECK_EQUAL(tracker.Count(peer), 2U);

    const auto requested{tracker.Request(
        peer, std::chrono::microseconds{100},
        std::chrono::microseconds{200})};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == required_receipt);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_dependency_keeps_all_providers)
{
    ChainLockRequestTracker tracker;
    const uint256 required_receipt{34};
    const NodeId first_withholder{1100};
    for (std::size_t i{0};
         i < ChainLockRequestTracker::MAX_ANNOUNCERS_PER_LOGICAL_ID;
         ++i) {
        BOOST_REQUIRE(tracker.Announce(
            first_withholder + static_cast<NodeId>(i), required_receipt,
            ChainLockRequestTracker::SourcePriority::AUTHENTICATED,
            /*required=*/true));
    }

    // The ordinary eight-advertiser cap protects arbitrary IDs. It must not
    // exclude an honest ninth provider for the one ID selected by validation.
    const NodeId honest_provider{1200};
    BOOST_REQUIRE(tracker.Announce(
        honest_provider, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED,
        /*required=*/true));
    BOOST_CHECK_EQUAL(
        tracker.Size(),
        ChainLockRequestTracker::MAX_ANNOUNCERS_PER_LOGICAL_ID + 1);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_notfound_rotates_source)
{
    ChainLockRequestTracker tracker;
    const uint256 required_receipt{uint256S("24")};
    const NodeId authenticated_withholder{1250};
    const NodeId reconnected_withholder{1252};
    const NodeId honest_outbound{1251};
    const uint256 authenticated_identity{uint256S("a11ce")};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(
        authenticated_withholder, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, authenticated_identity));
    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true));
    BOOST_REQUIRE(tracker.Request(authenticated_withholder, now, expiry));

    // An authenticated advertiser that denies the object it offered must not
    // immediately outrank an honest lower-priority provider again.
    BOOST_REQUIRE(tracker.ReceivedFailure(
        authenticated_withholder, required_receipt, now));
    tracker.DisconnectedPeer(authenticated_withholder, now);
    BOOST_REQUIRE(tracker.Announce(
        reconnected_withholder, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, authenticated_identity));
    BOOST_CHECK(!tracker.Request(reconnected_withholder, now, expiry));

    const auto fallback{tracker.Request(honest_outbound, now, expiry)};
    BOOST_REQUIRE(fallback);
    BOOST_CHECK(*fallback == required_receipt);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_disconnect_preserves_identity_cooldown)
{
    ChainLockRequestTracker tracker;
    const uint256 required_receipt{uint256S("25")};
    const uint256 authenticated_identity{uint256S("b0b")};
    const NodeId initial_peer{1260};
    const NodeId reconnected_peer{1261};
    const NodeId honest_outbound{1262};
    constexpr uint64_t keyed_net_group{77};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    // The request begins before MNAUTH and is then migrated to the stable
    // operator identity. Disconnecting before a response must cool that
    // identity, not merely the obsolete connection or netgroup.
    BOOST_REQUIRE(tracker.Announce(
        initial_peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::INBOUND,
        /*required=*/true, /*authenticated_pro_tx=*/{}, keyed_net_group));
    BOOST_REQUIRE(tracker.Request(initial_peer, now, expiry));
    tracker.UpdateSourceIdentity(
        initial_peer, authenticated_identity, keyed_net_group,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED);
    tracker.DisconnectedPeer(initial_peer, now);

    BOOST_REQUIRE(tracker.Announce(
        honest_outbound, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true));

    BOOST_REQUIRE(tracker.Announce(
        reconnected_peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED,
        /*required=*/true, authenticated_identity, keyed_net_group));
    BOOST_CHECK(!tracker.Request(reconnected_peer, now, expiry));
    const auto fallback{tracker.Request(honest_outbound, now, expiry)};
    BOOST_REQUIRE(fallback);
    BOOST_CHECK(*fallback == required_receipt);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_hedge_uses_distinct_sources)
{
    ChainLockRequestTracker tracker;
    const uint256 required_receipt{uint256S("26")};
    const uint256 first_identity{uint256S("cafe")};
    const NodeId first_peer{1270};
    const NodeId duplicate_identity_peer{1271};
    const NodeId second_peer{1272};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(
        first_peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, first_identity));
    BOOST_REQUIRE(tracker.Announce(
        duplicate_identity_peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, first_identity));
    BOOST_REQUIRE(tracker.Announce(
        second_peer, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true, /*authenticated_pro_tx=*/{},
        /*keyed_net_group=*/88));

    BOOST_REQUIRE(tracker.Request(first_peer, now, expiry));
    BOOST_CHECK(!tracker.Request(duplicate_identity_peer, now, expiry));
    BOOST_REQUIRE(tracker.Request(second_peer, now, expiry));

    // Durable acceptance completes the winner first. Forget then cancels only
    // the losing hedge, whose one late exact payload is recognizable once.
    tracker.ReceivedResponse(first_peer, required_receipt);
    tracker.Forget(required_receipt);
    BOOST_CHECK(!tracker.HasCancelled(first_peer, now));
    BOOST_CHECK(tracker.HasCancelled(second_peer, now));
    BOOST_CHECK(!tracker.TakeCancelled(first_peer, required_receipt, now));
    BOOST_CHECK(tracker.TakeCancelled(second_peer, required_receipt, now));
    BOOST_CHECK(!tracker.HasCancelled(second_peer, now));
    BOOST_CHECK(!tracker.TakeCancelled(second_peer, required_receipt, now));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_dependency_preempts_generic_lanes)
{
    ChainLockRequestTracker tracker;
    const uint256 generic_one{uint256S("27")};
    const uint256 generic_two{uint256S("28")};
    const uint256 required_receipt{uint256S("29")};
    const NodeId generic_peer_one{1280};
    const NodeId generic_peer_two{1281};
    const NodeId required_peer_one{1282};
    const NodeId required_peer_two{1283};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(
        generic_peer_one, generic_one,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, uint256S("d001")));
    BOOST_REQUIRE(tracker.Request(generic_peer_one, now, expiry));
    BOOST_REQUIRE(tracker.Announce(
        generic_peer_two, generic_two,
        ChainLockRequestTracker::SourcePriority::OUTBOUND));
    BOOST_REQUIRE(tracker.Request(generic_peer_two, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        required_peer_one, required_receipt,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, uint256S("d002")));
    BOOST_REQUIRE(tracker.Request(required_peer_one, now, expiry));

    // Once an exact block dependency exists, a newly advertised generic ID
    // cannot refill the second lane ahead of an honest hedge.
    const NodeId late_generic_peer{1284};
    BOOST_REQUIRE(tracker.Announce(
        late_generic_peer, uint256S("2a"),
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, uint256S("d003")));
    BOOST_CHECK(!tracker.Request(late_generic_peer, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        required_peer_two, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true, /*authenticated_pro_tx=*/{},
        /*keyed_net_group=*/99));
    BOOST_CHECK(!tracker.IsRequested(generic_peer_one, generic_one));
    BOOST_CHECK(!tracker.IsRequested(generic_peer_two, generic_two));
    BOOST_REQUIRE(tracker.TakeCancelled(
        generic_peer_one, generic_one, now));
    BOOST_REQUIRE(tracker.TakeCancelled(
        generic_peer_two, generic_two, now));

    BOOST_REQUIRE(tracker.Request(required_peer_two, now, expiry));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_required_reuses_cancelled_provider_immediately)
{
    ChainLockRequestTracker tracker;
    const NodeId only_provider{1290};
    const uint256 generic{uint256S("2b")};
    const uint256 required{uint256S("2c")};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(
        only_provider, generic,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, uint256S("d004")));
    BOOST_REQUIRE(tracker.Request(only_provider, now, expiry));

    // The future dependency may already be known as generic inventory. Its
    // later promotion to the selected required ID must still displace the
    // in-flight generic request immediately.
    BOOST_REQUIRE(tracker.Announce(
        only_provider, required,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, uint256S("d004")));
    BOOST_REQUIRE(tracker.Announce(
        only_provider, required,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, uint256S("d004")));
    const auto current{tracker.Request(only_provider, now, expiry)};
    BOOST_REQUIRE(current);
    BOOST_CHECK(*current == required);

    // The current response remains requested while one exact late generic
    // response is independently consumed.
    BOOST_CHECK(tracker.IsRequested(only_provider, required));
    BOOST_CHECK(tracker.TakeCancelled(only_provider, generic, now));
    BOOST_CHECK(tracker.IsRequested(only_provider, required));
    BOOST_CHECK(!tracker.TakeCancelled(only_provider, generic, now));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_multiple_replacements_preserve_late_responses)
{
    ChainLockRequestTracker tracker;
    const NodeId provider{1291};
    const uint256 first{uint256S("2d")};
    const uint256 second{uint256S("2e")};
    const uint256 current{uint256S("2f")};
    const uint256 identity{uint256S("d005")};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};

    BOOST_REQUIRE(tracker.Announce(
        provider, first,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, identity));
    BOOST_REQUIRE(tracker.Request(provider, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        provider, second,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, identity));
    BOOST_REQUIRE(tracker.Request(provider, now, expiry));

    BOOST_REQUIRE(tracker.Announce(
        provider, current,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, identity));
    const auto requested{tracker.Request(provider, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == current);

    BOOST_CHECK(tracker.TakeCancelled(provider, first, now));
    BOOST_CHECK(tracker.TakeCancelled(provider, second, now));
    BOOST_CHECK(tracker.IsRequested(provider, current));
    BOOST_CHECK(!tracker.TakeCancelled(provider, first, now));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_cancellation_backlog_never_forgets_honest_response)
{
    ChainLockRequestTracker tracker;
    const NodeId provider{1292};
    const uint256 identity{uint256S("d006")};
    const auto now{std::chrono::microseconds{100}};
    const auto expiry{std::chrono::microseconds{200}};
    std::vector<uint256> requested_ids;

    const uint256 first{uint256S("30")};
    BOOST_REQUIRE(tracker.Announce(
        provider, first,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/false, identity));
    BOOST_REQUIRE(tracker.Request(provider, now, expiry));
    requested_ids.push_back(first);

    // Four dependency replacements leave four legitimate multi-megabyte
    // responses outstanding on this connection. The tracker must retain all
    // four cancellation identities and stop reusing the peer before a fifth
    // response can become ambiguous.
    for (uint8_t value = 0x31; value <= 0x34; ++value) {
        const uint256 next{value};
        BOOST_REQUIRE(tracker.Announce(
            provider, next,
            ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
            /*required=*/true, identity));
        const auto requested{tracker.Request(provider, now, expiry)};
        if (value < 0x34) {
            BOOST_REQUIRE(requested);
            BOOST_CHECK(*requested == next);
            requested_ids.push_back(next);
        } else {
            BOOST_CHECK(!requested);
        }
    }

    const uint256 newest{uint256S("35")};
    BOOST_REQUIRE(tracker.Announce(
        provider, newest,
        ChainLockRequestTracker::SourcePriority::AUTHENTICATED_OUTBOUND,
        /*required=*/true, identity));
    BOOST_CHECK(!tracker.Request(provider, now, expiry));

    // Consuming one exact late response frees capacity; the newest required
    // dependency can then use this otherwise-only provider without losing
    // accounting for the other three responses.
    BOOST_REQUIRE(tracker.TakeCancelled(provider, requested_ids.front(), now));
    const auto current{tracker.Request(provider, now, expiry)};
    BOOST_REQUIRE(current);
    BOOST_CHECK(*current == newest);
    for (std::size_t i = 1; i < requested_ids.size(); ++i) {
        BOOST_CHECK(tracker.TakeCancelled(provider, requested_ids[i], now));
    }
    BOOST_CHECK(tracker.IsRequested(provider, newest));
}

BOOST_AUTO_TEST_CASE(pq_chainlock_retired_dependency_drops_stale_sources)
{
    ChainLockRequestTracker tracker;
    const uint256 required_receipt{35};
    const NodeId active_source{1300};
    const NodeId alternate_source{1301};
    BOOST_REQUIRE(tracker.Announce(
        active_source, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true));
    BOOST_REQUIRE(tracker.Announce(
        alternate_source, required_receipt,
        ChainLockRequestTracker::SourcePriority::OUTBOUND,
        /*required=*/true));
    BOOST_REQUIRE(tracker.Request(
        active_source, std::chrono::microseconds{100},
        std::chrono::microseconds{200}));

    tracker.ClearRequired(required_receipt);
    BOOST_CHECK(!tracker.RequiredLogicalId());
    BOOST_CHECK_EQUAL(tracker.Count(alternate_source), 0U);
    BOOST_CHECK(!tracker.IsRequested(active_source, required_receipt));
    BOOST_CHECK(tracker.TakeCancelled(
        active_source, required_receipt,
        std::chrono::microseconds{100}));
    BOOST_CHECK_EQUAL(tracker.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_upload_authorization_is_consume_once)
{
    ChainLockUploadTracker tracker;
    const uint256 first{16};
    const uint256 second{17};

    BOOST_CHECK(!tracker.Consume(first));
    tracker.Announce(first);
    BOOST_CHECK(tracker.Consume(first));
    BOOST_CHECK(!tracker.Consume(first));

    // Repeating the same INV must not mint another multi-megabyte response.
    tracker.Announce(first);
    BOOST_CHECK(!tracker.Consume(first));

    // Only an explicit targeted GETCLSIG retry renews one response budget.
    BOOST_CHECK(tracker.Reauthorize(
        first, /*upload_budget_reserved=*/true));
    // Repeating GETPQPOSE before its GETDATA is consumed must not renew the
    // targeted authorization or trigger another archive lookup.
    BOOST_CHECK(!tracker.Reauthorize(
        first, /*upload_budget_reserved=*/true));
    bool upload_budget_reserved{false};
    BOOST_CHECK(tracker.Consume(first, &upload_budget_reserved));
    BOOST_CHECK(upload_budget_reserved);
    BOOST_CHECK(!tracker.Consume(first));
    BOOST_CHECK(!tracker.Reauthorize(first));

    // A newly announced winner remains independently requestable.
    tracker.Announce(second);
    BOOST_CHECK(tracker.Consume(second));

    // Evicting and re-announcing an old ID cannot reset its two-upload cap.
    const uint256 third{18};
    tracker.Announce(third);
    tracker.Announce(first);
    BOOST_CHECK(!tracker.Consume(first));
    BOOST_CHECK(!tracker.Reauthorize(first));

    // A lookup which finds no archive row revokes its pending GETDATA grant;
    // the process-wide lookup limiter, not an indefinitely resettable upload
    // authorization, governs any later retry.
    const uint256 missing{19};
    BOOST_REQUIRE(tracker.Reauthorize(
        missing, /*upload_budget_reserved=*/true));
    BOOST_CHECK(tracker.HasActiveTargetedAuthorization(missing));
    tracker.CancelTargetedAuthorization(missing);
    BOOST_CHECK(!tracker.HasActiveTargetedAuthorization(missing));
    BOOST_CHECK(!tracker.Consume(missing));
}

BOOST_AUTO_TEST_CASE(pq_consensus_certificate_state_needs_no_tx_relay)
{
    Peer peer{/*id=*/901, NODE_NETWORK};
    BOOST_CHECK(peer.GetTxRelay() == nullptr);
    peer.m_common_version.store(PQ_MNAUTH_PROTO_VERSION);

    const uint256 witness{uint256S("a901")};
    const CInv current_chainlock{MSG_CLSIG, uint256S("c901")};
    BOOST_REQUIRE(QueuePQCertificateInventory(peer, current_chainlock));
    BOOST_CHECK(!QueuePQCertificateInventory(peer, current_chainlock));
    {
        LOCK(peer.m_pq_certificate_mutex);
        BOOST_REQUIRE_EQUAL(peer.m_pq_certificates_to_send.size(), 1U);
        BOOST_CHECK(peer.m_pq_certificates_to_send.front().type == MSG_CLSIG);
        BOOST_CHECK(peer.m_pq_certificates_to_send.front().hash ==
                    current_chainlock.hash);
        BOOST_REQUIRE(peer.m_payment_audit_uploads.Reauthorize(
            witness, /*upload_budget_reserved=*/true));
        BOOST_CHECK(!peer.m_payment_audit_uploads.Reauthorize(
            witness, /*upload_budget_reserved=*/true));
        bool upload_budget_reserved{false};
        BOOST_REQUIRE(peer.m_payment_audit_uploads.Consume(
            witness, &upload_budget_reserved));
        BOOST_CHECK(upload_budget_reserved);
    }
    BOOST_CHECK(peer.GetTxRelay() == nullptr);
}

BOOST_AUTO_TEST_CASE(pq_chainlock_upload_budget_survives_reconnect)
{
    ChainLockUploadRateLimiter limiter;
    const uint64_t keyed_net_group{0xabc};
    const auto now{std::chrono::microseconds{100}};

    BOOST_CHECK(limiter.Consume({}, keyed_net_group, now));
    BOOST_CHECK(limiter.Consume({}, keyed_net_group, now));
    BOOST_CHECK(!limiter.Consume({}, keyed_net_group, now));

    // A new CNode/Peer object has no effect: the process-wide key is the
    // deterministic network group, not the ephemeral NodeId.
    BOOST_CHECK(!limiter.Consume(
        {}, keyed_net_group,
        now + ChainLockUploadRateLimiter::REFILL_INTERVAL -
            std::chrono::microseconds{1}));
    BOOST_CHECK(limiter.Consume(
        {}, keyed_net_group,
        now + ChainLockUploadRateLimiter::REFILL_INTERVAL));

    // Authentication is even stronger: one proTx identity shares a bucket
    // across addresses/netgroups, while an unrelated source remains live.
    const uint256 pro_tx{uint256S("d007")};
    BOOST_CHECK(limiter.Consume(pro_tx, 1, now));
    BOOST_CHECK(limiter.Consume(pro_tx, 2, now));
    BOOST_CHECK(!limiter.Consume(pro_tx, 3, now));
    BOOST_CHECK(limiter.Consume({}, keyed_net_group + 1, now));
    BOOST_CHECK(!limiter.Consume({}, 0, now));
    BOOST_CHECK_EQUAL(limiter.Size(), 3U);
}

BOOST_AUTO_TEST_CASE(pq_payment_audit_archive_probe_budget_is_independent)
{
    ChainLockUploadRateLimiter upload_budget;
    ChainLockUploadRateLimiter archive_probe_budget;
    const uint64_t keyed_net_group{0xabc};
    const auto now{std::chrono::microseconds{100}};

    BOOST_CHECK(archive_probe_budget.Consume({}, keyed_net_group, now));
    BOOST_CHECK(archive_probe_budget.Consume({}, keyed_net_group, now));
    BOOST_CHECK(!archive_probe_budget.Consume({}, keyed_net_group, now));

    // Speculative INV presence checks must not spend either of the two
    // full-certificate upload tokens reserved for an authorized GETDATA.
    BOOST_CHECK(upload_budget.Consume({}, keyed_net_group, now));
    BOOST_CHECK(upload_budget.Consume({}, keyed_net_group, now));
    BOOST_CHECK(!upload_budget.Consume({}, keyed_net_group, now));

    // Both buckets key reconnects to the same deterministic source identity.
    BOOST_CHECK(!archive_probe_budget.Consume(
        {}, keyed_net_group,
        now + ChainLockUploadRateLimiter::REFILL_INTERVAL -
            std::chrono::microseconds{1}));
    BOOST_CHECK(archive_probe_budget.Consume(
        {}, keyed_net_group,
        now + ChainLockUploadRateLimiter::REFILL_INTERVAL));
}

namespace {

CGovernancePageRequest MakeGovernancePageRequest(
    const uint256& scope = {}, const uint256& cursor = {},
    const uint256& view = {}, uint64_t nonce = 1)
{
    return CGovernancePageRequest{scope, cursor, view, nonce};
}

CGovernancePageResponse MakeGovernancePageResponse(
    const CGovernancePageRequest& request,
    std::vector<CInv> inventory, bool done, const uint256& view,
    uint32_t total_count,
    uint8_t status = GOVERNANCE_PAGE_OK)
{
    return CGovernancePageResponse{
        request.scope_hash,
        request.cursor,
        request.view_id,
        request.nonce,
        status,
        view,
        total_count,
        inventory.empty() ? request.cursor : inventory.back().hash,
        done,
        std::move(inventory)};
}

std::shared_ptr<const GovernancePageImmutableSnapshot>
MakeGovernancePageSnapshot(
    const uint256& scope, const uint256& view,
    const std::vector<CInv>& inventory,
    uint64_t instance_id = 1)
{
    auto budget{std::make_shared<GovernancePageSnapshotBudget>()};
    GovernancePageSnapshotReservation reservation{budget};
    std::vector<GovernancePageSnapshotEntry> entries;
    entries.reserve(inventory.size());
    for (const CInv& inv : inventory) {
        entries.push_back(GovernancePageSnapshotEntry{
            inv, std::vector<unsigned char>{0}});
    }
    std::size_t retained{
        sizeof(GovernancePageImmutableSnapshot) +
        entries.capacity() * sizeof(GovernancePageSnapshotEntry)};
    for (const auto& entry : entries) {
        retained += entry.payload.capacity();
    }
    if (!reservation.Reserve(retained)) return {};
    return GovernancePageImmutableSnapshot::Create(
        std::move(reservation), instance_id,
        /*validation_context_epoch=*/1, scope, view,
        std::move(entries));
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_governance_request_is_source_and_type_bound)
{
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source first_source{40, 100, {}};
    const GovernanceRequestTracker::Source relay_source{41, 101, {}};
    const CInv object{MSG_GOVERNANCE_OBJECT, uint256{20}};
    const CInv second{MSG_GOVERNANCE_OBJECT, uint256{21}};
    const CInv rejected{MSG_GOVERNANCE_OBJECT, uint256{22}};
    const CInv wrong_type{MSG_GOVERNANCE_OBJECT_VOTE, object.hash};
    const auto now{std::chrono::seconds{10}};
    const auto expiry{now + std::chrono::seconds{30}};

    BOOST_CHECK_LE(GovernanceRequestTracker::MAX_ANNOUNCEMENTS, 32U);
    BOOST_CHECK(tracker.Announce(first_source, object));
    BOOST_CHECK(tracker.Announce(first_source, second));
    BOOST_CHECK(!tracker.Announce(first_source, rejected));
    BOOST_CHECK(tracker.Announce(relay_source, object));

    const auto requested{tracker.Request(first_source.peer, now, expiry)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK_EQUAL(requested->type, object.type);
    BOOST_CHECK(requested->hash == object.hash);
    BOOST_CHECK(!tracker.ReceivedResponse(relay_source.peer, object, now));
    BOOST_CHECK(!tracker.ReceivedResponse(first_source.peer, wrong_type, now));
    BOOST_CHECK(!tracker.ReceivedResponse(first_source.peer, rejected, now));
    BOOST_CHECK(tracker.IsRequested(first_source.peer, object));
    BOOST_CHECK(tracker.ReceivedResponse(first_source.peer, object, now));

    BOOST_CHECK(!tracker.Request(relay_source.peer, now, expiry));
    const auto after_cadence{now +
        GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto relayed{
        tracker.Request(relay_source.peer, after_cadence, expiry)};
    BOOST_REQUIRE(relayed);
    BOOST_CHECK_EQUAL(relayed->type, object.type);
    BOOST_CHECK(relayed->hash == object.hash);
}

BOOST_AUTO_TEST_CASE(pq_governance_source_budget_survives_reconnect)
{
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source first_connection{50, 200, {}};
    const GovernanceRequestTracker::Source reconnected{51, 200, {}};
    const CInv first{MSG_GOVERNANCE_OBJECT_VOTE, uint256{30}};
    const CInv second{MSG_GOVERNANCE_OBJECT_VOTE, uint256{31}};
    const CInv third{MSG_GOVERNANCE_OBJECT_VOTE, uint256{32}};
    const auto now{std::chrono::seconds{20}};
    const auto expiry{now + std::chrono::seconds{30}};

    BOOST_REQUIRE(tracker.Announce(first_connection, first));
    BOOST_REQUIRE(tracker.Request(first_connection.peer, now, expiry));
    tracker.Forget(first);
    BOOST_REQUIRE(tracker.Announce(first_connection, second));
    BOOST_REQUIRE(tracker.Request(first_connection.peer, now, expiry));
    tracker.Forget(second);

    tracker.DisconnectedPeer(first_connection.peer, now);
    BOOST_REQUIRE(tracker.Announce(reconnected, third));
    BOOST_CHECK(!tracker.Request(reconnected.peer, now, expiry));
    const auto refilled{now +
        GovernanceRequestTracker::SOURCE_REFILL_INTERVAL};
    BOOST_REQUIRE(tracker.Request(reconnected.peer, refilled,
                                  refilled + std::chrono::seconds{30}));

    GovernanceRequestTracker authenticated_tracker;
    const uint256 authenticated_id{99};
    const GovernanceRequestTracker::Source authenticated_first{
        60, 300, authenticated_id};
    const GovernanceRequestTracker::Source authenticated_reconnect{
        61, 301, authenticated_id};
    BOOST_REQUIRE(authenticated_tracker.Announce(authenticated_first, first));
    BOOST_REQUIRE(authenticated_tracker.Request(authenticated_first.peer, now,
                                                expiry));
    authenticated_tracker.Forget(first);
    BOOST_REQUIRE(authenticated_tracker.Announce(authenticated_first, second));
    BOOST_REQUIRE(authenticated_tracker.Request(authenticated_first.peer, now,
                                                expiry));
    authenticated_tracker.Forget(second);
    authenticated_tracker.DisconnectedPeer(authenticated_first.peer, now);
    BOOST_REQUIRE(authenticated_tracker.Announce(authenticated_reconnect,
                                                 third));
    BOOST_CHECK(!authenticated_tracker.Request(authenticated_reconnect.peer,
                                               now, expiry));
    BOOST_REQUIRE(authenticated_tracker.Request(
        authenticated_reconnect.peer, refilled,
        refilled + std::chrono::seconds{30}));
}

BOOST_AUTO_TEST_CASE(pq_governance_withhold_rotates_stable_source)
{
    const auto now{std::chrono::seconds{30}};
    const auto timeout{now + std::chrono::seconds{30}};

    // SYSCOIN: a newly connected inbound source cannot preempt an outbound
    // source merely by having its SendMessages turn run first.
    GovernanceRequestTracker priority_tracker;
    const GovernanceRequestTracker::Source inbound{70, 400, {}, false};
    const GovernanceRequestTracker::Source outbound{71, 401, {}, true};
    const CInv inbound_inv{MSG_GOVERNANCE_OBJECT, uint256{40}};
    const CInv outbound_inv{MSG_GOVERNANCE_OBJECT, uint256{41}};
    BOOST_REQUIRE(priority_tracker.Announce(inbound, inbound_inv));
    BOOST_REQUIRE(priority_tracker.Announce(outbound, outbound_inv));
    BOOST_CHECK(!priority_tracker.Request(inbound.peer, now, timeout));
    const auto preferred{
        priority_tracker.Request(outbound.peer, now, timeout)};
    BOOST_REQUIRE(preferred);
    BOOST_CHECK(preferred->hash == outbound_inv.hash);

    // SYSCOIN: withholding cools the stable netgroup and immediately rotates
    // the one global verification lane to a distinct source.
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source withholder{72, 500, {}, true};
    const GovernanceRequestTracker::Source honest{73, 501, {}, true};
    const CInv fake{MSG_GOVERNANCE_OBJECT_VOTE, uint256{42}};
    const CInv real{MSG_GOVERNANCE_OBJECT_VOTE, uint256{43}};
    BOOST_REQUIRE(tracker.Announce(withholder, fake));
    BOOST_REQUIRE(tracker.Announce(honest, real));
    const auto requested{tracker.Request(withholder.peer, now, timeout)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(requested->hash == fake.hash);

    std::optional<GovernanceRequestTracker::InFlight> expired;
    const auto rotated{tracker.Request(
        honest.peer, timeout, timeout + std::chrono::seconds{30}, &expired)};
    BOOST_REQUIRE(expired);
    BOOST_CHECK_EQUAL(expired->source.peer, withholder.peer);
    BOOST_CHECK(expired->inv.hash == fake.hash);
    BOOST_REQUIRE(rotated);
    BOOST_CHECK(rotated->hash == real.hash);
    tracker.Forget(real);

    const GovernanceRequestTracker::Source reconnected{
        74, withholder.keyed_net_group, {}, true};
    const CInv next_fake{MSG_GOVERNANCE_OBJECT_VOTE, uint256{44}};
    BOOST_REQUIRE(tracker.Announce(reconnected, next_fake));
    const auto before_cooldown{
        timeout + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN -
        std::chrono::microseconds{1}};
    BOOST_CHECK(!tracker.Request(
        reconnected.peer, before_cooldown,
        before_cooldown + std::chrono::seconds{30}));
    const auto after_cooldown{
        timeout + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN};
    BOOST_REQUIRE(tracker.Request(
        reconnected.peer, after_cooldown,
        after_cooldown + std::chrono::seconds{30}));
}

BOOST_AUTO_TEST_CASE(pq_governance_mnauth_migrates_failure_history)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{40}};
    const auto expiry{now + std::chrono::seconds{30}};
    const uint256 pro_tx{uint256S("a11ce")};
    const GovernanceRequestTracker::Source unauthenticated{
        80, 600, {}, true};
    const CInv fake{MSG_GOVERNANCE_OBJECT, uint256{50}};

    BOOST_REQUIRE(tracker.Announce(unauthenticated, fake));
    BOOST_REQUIRE(tracker.Request(unauthenticated.peer, now, expiry));
    BOOST_REQUIRE(tracker.ReceivedFailure(
        unauthenticated.peer, fake, now));
    tracker.UpdateSourceIdentity(
        unauthenticated.peer, pro_tx,
        unauthenticated.keyed_net_group, true);
    tracker.DisconnectedPeer(unauthenticated.peer, now);

    // SYSCOIN: reconnecting on another network group with the authenticated
    // identity cannot discard the pre-authentication failure cooldown.
    const GovernanceRequestTracker::Source authenticated_reconnect{
        81, 601, pro_tx, true};
    const CInv retry{MSG_GOVERNANCE_OBJECT, uint256{51}};
    BOOST_REQUIRE(tracker.Announce(authenticated_reconnect, retry));
    BOOST_CHECK(!tracker.Request(
        authenticated_reconnect.peer, now, expiry));
    const auto after_cooldown{
        now + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN};
    BOOST_REQUIRE(tracker.Request(
        authenticated_reconnect.peer, after_cooldown,
        after_cooldown + std::chrono::seconds{30}));

    GovernanceRequestTracker reverse_tracker;
    const GovernanceRequestTracker::Source reverse_connection{
        82, 700, {}, true};
    const CInv reverse_fake{MSG_GOVERNANCE_OBJECT, uint256{52}};
    BOOST_REQUIRE(reverse_tracker.Announce(
        reverse_connection, reverse_fake));
    BOOST_REQUIRE(reverse_tracker.Request(
        reverse_connection.peer, now, expiry));
    reverse_tracker.UpdateSourceIdentity(
        reverse_connection.peer, pro_tx,
        reverse_connection.keyed_net_group, true);
    BOOST_REQUIRE(reverse_tracker.ReceivedFailure(
        reverse_connection.peer, reverse_fake, now));
    reverse_tracker.DisconnectedPeer(reverse_connection.peer, now);

    // A failure after authentication is mirrored back to the network-group
    // key, so reconnecting without MNAUTH cannot recover a fresh burst.
    const GovernanceRequestTracker::Source unauthenticated_reconnect{
        83, reverse_connection.keyed_net_group, {}, true};
    const CInv reverse_retry{MSG_GOVERNANCE_OBJECT, uint256{53}};
    BOOST_REQUIRE(reverse_tracker.Announce(
        unauthenticated_reconnect, reverse_retry));
    BOOST_CHECK(!reverse_tracker.Request(
        unauthenticated_reconnect.peer, now, expiry));
    BOOST_REQUIRE(reverse_tracker.Request(
        unauthenticated_reconnect.peer, after_cooldown,
        after_cooldown + std::chrono::seconds{30}));
}

BOOST_AUTO_TEST_CASE(
    pq_governance_metadata_timeout_cools_only_exact_unauthenticated_connection)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{100}};
    const auto timeout{now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT};
    const auto transfer_deadline{
        timeout + GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const uint64_t shared_netgroup{750};
    const GovernanceRequestTracker::Source silent{
        84, shared_netgroup, {}, true};
    const GovernanceRequestTracker::Source sibling{
        85, shared_netgroup, {}, true};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 7)};

    BOOST_REQUIRE(tracker.BeginPageSession(silent, now));
    BOOST_REQUIRE(tracker.BeginPage(request, now, transfer_deadline));
    const auto result{tracker.TakePageResult(timeout)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(!result->success);
    tracker.EndPageSession();

    BOOST_CHECK(!tracker.CanUsePageSource(silent, timeout));
    BOOST_CHECK(tracker.CanUsePageSource(sibling, timeout));

    const CInv silent_inv{MSG_GOVERNANCE_OBJECT, uint256{57}};
    const CInv sibling_inv{MSG_GOVERNANCE_OBJECT, uint256{58}};
    BOOST_REQUIRE(tracker.Announce(silent, silent_inv));
    BOOST_REQUIRE(tracker.Announce(sibling, sibling_inv));
    BOOST_CHECK(!tracker.Request(
        silent.peer, timeout, timeout + std::chrono::seconds{30}));
    const auto sibling_request{tracker.Request(
        sibling.peer, timeout, timeout + std::chrono::seconds{30})};
    BOOST_REQUIRE(sibling_request);
    BOOST_CHECK(sibling_request->hash == sibling_inv.hash);
    BOOST_REQUIRE(tracker.ReceivedResponse(
        sibling.peer, sibling_inv, timeout));

    BOOST_CHECK(!tracker.BeginPageSession(silent, timeout));
    BOOST_REQUIRE(tracker.BeginPageSession(sibling, timeout));
    tracker.EndPageSession();

    const auto cooldown_boundary{
        timeout + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN};
    const auto recovered{tracker.Request(
        silent.peer, cooldown_boundary,
        cooldown_boundary + std::chrono::seconds{30})};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(recovered->hash == silent_inv.hash);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_late_valid_metadata_is_a_local_timeout)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{110}};
    const auto response_deadline{now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT};
    const auto transfer_deadline{
        response_deadline + GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const uint256 pro_tx{uint256S("b101")};
    const GovernanceRequestTracker::Source source{
        93, 755, pro_tx, true};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 71)};
    const std::vector<CInv> inventory;
    const auto view{ComputeGovernancePageViewHash({}, inventory)};
    BOOST_REQUIRE(view);
    const auto response{MakeGovernancePageResponse(
        request, inventory, true, *view, 0)};

    BOOST_REQUIRE(tracker.BeginPageSession(source, now));
    BOOST_REQUIRE(tracker.BeginPage(request, now, transfer_deadline));
    BOOST_CHECK(!tracker.ReceivedPage(
        source.peer, response, {}, response_deadline));
    const auto result{tracker.TakePageResult(response_deadline)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(!result->success);
    tracker.EndPageSession();

    // The canonical response proves delivery. A local clock discontinuity
    // must not suppress a later live governance object from this ProTx.
    BOOST_CHECK(tracker.CanUsePageSource(source, response_deadline));
    const CInv live_object{MSG_GOVERNANCE_OBJECT, uint256{64}};
    BOOST_REQUIRE(tracker.Announce(source, live_object));
    const auto live_request{tracker.Request(
        source.peer, response_deadline,
        response_deadline + std::chrono::seconds{30})};
    BOOST_REQUIRE(live_request);
    BOOST_CHECK(*live_request == live_object);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_malformed_bound_metadata_is_strongly_attributed)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{115}};
    const auto transfer_deadline{
        now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT +
        GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const uint64_t shared_netgroup{757};
    const GovernanceRequestTracker::Source malformed_source{
        94, shared_netgroup, {}, true};
    const GovernanceRequestTracker::Source sibling{
        95, shared_netgroup, {}, true};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 72)};
    const std::vector<CInv> inventory;
    const auto view{ComputeGovernancePageViewHash({}, inventory)};
    BOOST_REQUIRE(view);
    auto response{MakeGovernancePageResponse(
        request, inventory, true, *view, 0)};
    response.status = std::numeric_limits<uint8_t>::max();

    BOOST_REQUIRE(tracker.BeginPageSession(malformed_source, now));
    BOOST_REQUIRE(tracker.BeginPage(request, now, transfer_deadline));
    BOOST_CHECK(!tracker.ReceivedPage(
        malformed_source.peer, response, {}, now));
    const auto result{tracker.TakePageResult(now)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(!result->success);
    tracker.EndPageSession();

    BOOST_CHECK(!tracker.CanUsePageSource(malformed_source, now));
    BOOST_CHECK(!tracker.CanUsePageSource(sibling, now));
    const auto cooldown_boundary{
        now + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN};
    BOOST_CHECK(tracker.CanUsePageSource(sibling, cooldown_boundary));
}

BOOST_AUTO_TEST_CASE(
    pq_governance_metadata_timeout_migrates_on_mnauth)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{120}};
    const auto timeout{now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT};
    const auto transfer_deadline{
        timeout + GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const uint64_t shared_netgroup{760};
    const uint256 pro_tx{uint256S("b201")};
    const GovernanceRequestTracker::Source before_auth{
        86, shared_netgroup, {}, true};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 8)};

    // No ordinary request precedes the timeout. MNAUTH must therefore create
    // the ProTx rate record from exact pre-authentication history alone.
    BOOST_REQUIRE(tracker.BeginPageSession(before_auth, now));
    BOOST_REQUIRE(tracker.BeginPage(request, now, transfer_deadline));
    BOOST_REQUIRE(tracker.TakePageResult(timeout));
    tracker.EndPageSession();
    tracker.UpdateSourceIdentity(
        before_auth.peer, pro_tx, shared_netgroup, true);
    tracker.DisconnectedPeer(before_auth.peer, timeout);

    const GovernanceRequestTracker::Source authenticated_reconnect{
        87, shared_netgroup + 1, pro_tx, true};
    const GovernanceRequestTracker::Source sibling{
        88, shared_netgroup, {}, true};
    const CInv cooled_inv{MSG_GOVERNANCE_OBJECT, uint256{59}};
    const CInv sibling_inv{MSG_GOVERNANCE_OBJECT, uint256{60}};
    BOOST_REQUIRE(tracker.Announce(
        authenticated_reconnect, cooled_inv));
    BOOST_REQUIRE(tracker.Announce(sibling, sibling_inv));
    BOOST_CHECK(!tracker.Request(
        authenticated_reconnect.peer, timeout,
        timeout + std::chrono::seconds{30}));
    const auto sibling_request{tracker.Request(
        sibling.peer, timeout, timeout + std::chrono::seconds{30})};
    BOOST_REQUIRE(sibling_request);
    BOOST_CHECK(sibling_request->hash == sibling_inv.hash);
    BOOST_REQUIRE(tracker.ReceivedResponse(
        sibling.peer, sibling_inv, timeout));
    BOOST_CHECK(!tracker.BeginPageSession(
        authenticated_reconnect, timeout));

    const auto cooldown_boundary{
        timeout + GovernanceRequestTracker::SOURCE_FAILURE_COOLDOWN};
    const auto recovered{tracker.Request(
        authenticated_reconnect.peer, cooldown_boundary,
        cooldown_boundary + std::chrono::seconds{30})};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(recovered->hash == cooled_inv.hash);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_authenticated_metadata_timeout_does_not_cool_shared_nat)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{140}};
    const auto timeout{now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT};
    const auto transfer_deadline{
        timeout + GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const uint64_t shared_netgroup{770};
    const uint256 failed_identity{uint256S("b301")};
    const uint256 sibling_identity{uint256S("b302")};
    const GovernanceRequestTracker::Source failed{
        89, shared_netgroup, failed_identity, true};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 9)};

    BOOST_REQUIRE(tracker.BeginPageSession(failed, now));
    BOOST_REQUIRE(tracker.BeginPage(request, now, transfer_deadline));
    BOOST_REQUIRE(tracker.TakePageResult(timeout));
    tracker.EndPageSession();

    const GovernanceRequestTracker::Source failed_reconnect{
        90, shared_netgroup + 1, failed_identity, true};
    const GovernanceRequestTracker::Source authenticated_sibling{
        91, shared_netgroup, sibling_identity, true};
    const CInv failed_inv{MSG_GOVERNANCE_OBJECT, uint256{61}};
    const CInv authenticated_inv{MSG_GOVERNANCE_OBJECT, uint256{62}};
    BOOST_REQUIRE(tracker.Announce(failed_reconnect, failed_inv));
    BOOST_REQUIRE(tracker.Announce(
        authenticated_sibling, authenticated_inv));
    BOOST_CHECK(!tracker.Request(
        failed_reconnect.peer, timeout,
        timeout + std::chrono::seconds{30}));
    const auto authenticated_request{tracker.Request(
        authenticated_sibling.peer, timeout,
        timeout + std::chrono::seconds{30})};
    BOOST_REQUIRE(authenticated_request);
    BOOST_CHECK(authenticated_request->hash == authenticated_inv.hash);
    BOOST_REQUIRE(tracker.ReceivedResponse(
        authenticated_sibling.peer, authenticated_inv, timeout));

    const GovernanceRequestTracker::Source unauthenticated_sibling{
        92, shared_netgroup, {}, true};
    const CInv unauthenticated_inv{
        MSG_GOVERNANCE_OBJECT, uint256{63}};
    const auto next_request_time{
        timeout + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_REQUIRE(tracker.Announce(
        unauthenticated_sibling, unauthenticated_inv));
    const auto unauthenticated_request{tracker.Request(
        unauthenticated_sibling.peer, next_request_time,
        next_request_time + std::chrono::seconds{30})};
    BOOST_REQUIRE(unauthenticated_request);
    BOOST_CHECK(unauthenticated_request->hash == unauthenticated_inv.hash);
    BOOST_REQUIRE(tracker.ReceivedResponse(
        unauthenticated_sibling.peer, unauthenticated_inv,
        next_request_time));

    BOOST_CHECK(!tracker.BeginPageSession(
        failed_reconnect, next_request_time));
    BOOST_REQUIRE(tracker.BeginPageSession(
        authenticated_sibling, next_request_time));
    tracker.EndPageSession();
}

BOOST_AUTO_TEST_CASE(
    pq_governance_authenticated_failures_do_not_cool_shared_nat_peers)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{50}};
    const uint64_t shared_netgroup{800};
    const uint256 first_identity{uint256S("b001")};
    const uint256 second_identity{uint256S("b002")};
    const GovernanceRequestTracker::Source failed{
        90, shared_netgroup, first_identity, true};
    const GovernanceRequestTracker::Source same_nat_honest{
        91, shared_netgroup, second_identity, true};

    BOOST_REQUIRE(tracker.BeginPageSession(failed, now));
    BOOST_REQUIRE(tracker.FailPageSource(failed.peer, now));
    tracker.EndPageSession();

    // The authenticated identity is the blame key. A second masternode behind
    // the same NAT remains usable, while either identity downgrade still
    // inherits the mirrored netgroup cooldown.
    BOOST_REQUIRE(tracker.BeginPageSession(same_nat_honest, now));
    tracker.EndPageSession();
    const GovernanceRequestTracker::Source failed_reconnect{
        92, shared_netgroup + 1, first_identity, true};
    BOOST_CHECK(!tracker.BeginPageSession(failed_reconnect, now));
    const GovernanceRequestTracker::Source unauthenticated_reconnect{
        93, shared_netgroup, {}, true};
    BOOST_CHECK(!tracker.BeginPageSession(
        unauthenticated_reconnect, now));
}

BOOST_AUTO_TEST_CASE(
    pq_governance_mnauth_ignores_unrelated_shared_nat_cooldown)
{
    GovernanceRequestTracker tracker;
    const auto now{std::chrono::seconds{60}};
    const auto expiry{now + std::chrono::seconds{30}};
    const uint64_t shared_netgroup{810};
    const uint256 failed_identity{uint256S("b101")};
    const uint256 migrating_identity{uint256S("b102")};
    const GovernanceRequestTracker::Source before_auth{
        94, shared_netgroup, {}, true};
    const CInv first{MSG_GOVERNANCE_OBJECT, uint256{54}};
    const CInv second{MSG_GOVERNANCE_OBJECT, uint256{55}};
    const CInv retry{MSG_GOVERNANCE_OBJECT, uint256{56}};

    // Consume the shared burst before MNAUTH so identity migration must carry
    // the restrictive token state rather than minting a new ProTx budget.
    BOOST_REQUIRE(tracker.Announce(before_auth, first));
    BOOST_REQUIRE(tracker.Request(before_auth.peer, now, expiry));
    BOOST_REQUIRE(tracker.ReceivedResponse(before_auth.peer, first, now));
    const auto second_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_REQUIRE(tracker.Announce(before_auth, second));
    BOOST_REQUIRE(tracker.Request(
        before_auth.peer, second_time, expiry));
    BOOST_REQUIRE(tracker.ReceivedResponse(
        before_auth.peer, second, second_time));

    const GovernanceRequestTracker::Source failed{
        95, shared_netgroup, failed_identity, true};
    BOOST_REQUIRE(tracker.BeginPageSession(failed, second_time));
    BOOST_REQUIRE(tracker.FailPageSource(failed.peer, second_time));
    tracker.EndPageSession();

    // The authenticated failure still blocks an unauthenticated reconnect on
    // this netgroup, but it must not become the newly authenticated peer's
    // ProTx cooldown merely because both peers share a NAT.
    const GovernanceRequestTracker::Source unauthenticated_reconnect{
        96, shared_netgroup, {}, true};
    BOOST_CHECK(!tracker.BeginPageSession(
        unauthenticated_reconnect, second_time));
    BOOST_REQUIRE(tracker.Announce(before_auth, retry));
    tracker.UpdateSourceIdentity(
        before_auth.peer, migrating_identity, shared_netgroup, true);

    const auto before_refill{
        second_time + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_CHECK(!tracker.Request(before_auth.peer, before_refill, expiry));
    const auto refilled{
        now + GovernanceRequestTracker::SOURCE_REFILL_INTERVAL};
    BOOST_REQUIRE(tracker.Request(before_auth.peer, refilled, expiry));
}

BOOST_AUTO_TEST_CASE(
    pq_governance_ordinary_stale_transport_is_nonpunitive)
{
    const GovernanceRequestTracker::Source source{
        96, 819, uint256S("b101"), true};
    const CInv local_context{
        MSG_GOVERNANCE_OBJECT_VOTE, uint256S("b102")};
    const CInv newer{
        MSG_GOVERNANCE_OBJECT_VOTE, uint256S("b103")};
    const CInv followup{
        MSG_GOVERNANCE_OBJECT, uint256S("b104")};
    const auto now{std::chrono::seconds{60}};
    const auto deadline{now + std::chrono::seconds{30}};

    GovernanceRequestTracker tracker;
    BOOST_REQUIRE(tracker.Announce(source, local_context));
    BOOST_REQUIRE(tracker.Announce(source, newer));
    const auto local_request{tracker.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(local_request);
    const auto local_authorization{
        tracker.BeginResponse(source.peer, *local_request, now)};
    BOOST_REQUIRE(local_authorization);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *local_authorization,
        GovernanceRequestTracker::ResponseOutcome::LOCAL_CONTEXT_CHANGED,
        now));
    BOOST_CHECK_EQUAL(tracker.Count(source.peer), 2U);

    const auto second_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto newer_request{
        tracker.Request(source.peer, second_time, deadline)};
    BOOST_REQUIRE(newer_request);
    BOOST_CHECK(*newer_request == newer);
    BOOST_REQUIRE(tracker.ReceivedResponse(
        source.peer, *newer_request, second_time));

    const auto retry_time{
        now + GovernanceRequestTracker::SOURCE_REFILL_INTERVAL};
    const auto missing_request{
        tracker.Request(source.peer, retry_time, deadline)};
    BOOST_REQUIRE(missing_request);
    BOOST_CHECK(*missing_request == local_context);
    const auto missing_authorization{
        tracker.BeginResponse(source.peer, *missing_request, retry_time)};
    BOOST_REQUIRE(missing_authorization);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *missing_authorization,
        GovernanceRequestTracker::ResponseOutcome::NOT_FOUND,
        retry_time));
    BOOST_CHECK_EQUAL(tracker.Count(source.peer), 0U);

    // The semantic retry consumed a mutable ordinary relay promise. Its
    // subsequent disappearance must not impose the exact-page source
    // cooldown when the advertised object changed before GETDATA arrived.
    const auto third_time{
        now + 2 * GovernanceRequestTracker::SOURCE_REFILL_INTERVAL};
    BOOST_REQUIRE(tracker.Announce(source, followup));
    const auto followup_request{
        tracker.Request(source.peer, third_time, deadline)};
    BOOST_REQUIRE(followup_request);
    BOOST_CHECK(*followup_request == followup);

    GovernanceRequestTracker capacity_tracker;
    BOOST_REQUIRE(capacity_tracker.Announce(source, local_context));
    BOOST_REQUIRE(capacity_tracker.Announce(source, newer));
    const auto deferred_request{
        capacity_tracker.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(deferred_request);
    const auto deferred_authorization{capacity_tracker.BeginResponse(
        source.peer, *deferred_request, now)};
    BOOST_REQUIRE(deferred_authorization);
    BOOST_REQUIRE(capacity_tracker.CompleteResponse(
        *deferred_authorization,
        GovernanceRequestTracker::ResponseOutcome::LOCAL_CONTEXT_CHANGED,
        now));
    // A tried, locally deferred item must not occupy one of the peer's two
    // ordinary slots forever and suppress a newly announced object.
    BOOST_REQUIRE(capacity_tracker.Announce(source, followup));
    BOOST_CHECK_EQUAL(capacity_tracker.Count(source.peer), 2U);
    const auto capacity_next{
        capacity_tracker.Request(source.peer, second_time, deadline)};
    BOOST_REQUIRE(capacity_next);
    BOOST_CHECK(*capacity_next == followup);
    BOOST_REQUIRE(capacity_tracker.ReceivedResponse(
        source.peer, *capacity_next, second_time));
    const auto capacity_followup{
        capacity_tracker.Request(source.peer, retry_time, deadline)};
    BOOST_REQUIRE(capacity_followup);
    BOOST_CHECK(*capacity_followup == newer);

    GovernanceRequestTracker full_tracker;
    BOOST_REQUIRE(full_tracker.Announce(source, local_context));
    BOOST_REQUIRE(full_tracker.Announce(source, newer));
    // Parent objects take precedence even if both bounded vote slots have not
    // yet been attempted; exact vote paging repairs the displaced vote.
    BOOST_REQUIRE(full_tracker.Announce(source, followup));
    BOOST_CHECK_EQUAL(full_tracker.Count(source.peer), 2U);
    const auto full_next{full_tracker.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(full_next);
    BOOST_CHECK(*full_next == followup);

    const GovernanceRequestTracker::Source lower_priority{
        98, 821, {}, false};
    const CInv lower_fresh{
        MSG_GOVERNANCE_OBJECT, uint256S("b105")};
    GovernanceRequestTracker priority_tracker;
    BOOST_REQUIRE(priority_tracker.Announce(source, local_context));
    BOOST_REQUIRE(priority_tracker.Announce(source, newer));
    BOOST_REQUIRE(priority_tracker.Announce(lower_priority, lower_fresh));
    const auto first_deferred{
        priority_tracker.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(first_deferred);
    auto deferred_auth{priority_tracker.BeginResponse(
        source.peer, *first_deferred, now)};
    BOOST_REQUIRE(deferred_auth);
    BOOST_REQUIRE(priority_tracker.CompleteResponse(
        *deferred_auth,
        GovernanceRequestTracker::ResponseOutcome::LOCAL_CONTEXT_CHANGED,
        now));
    const auto second_deferred{
        priority_tracker.Request(source.peer, second_time, deadline)};
    BOOST_REQUIRE(second_deferred);
    deferred_auth = priority_tracker.BeginResponse(
        source.peer, *second_deferred, second_time);
    BOOST_REQUIRE(deferred_auth);
    BOOST_REQUIRE(priority_tracker.CompleteResponse(
        *deferred_auth,
        GovernanceRequestTracker::ResponseOutcome::LOCAL_CONTEXT_CHANGED,
        second_time));
    const auto lower_time{
        second_time +
        GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto lower_request{priority_tracker.Request(
        lower_priority.peer, lower_time, deadline)};
    BOOST_REQUIRE(lower_request);
    BOOST_CHECK(*lower_request == lower_fresh);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_global_cap_admits_fresh_page_source_objects)
{
    const auto now{std::chrono::seconds{65}};
    const auto deadline{now + std::chrono::seconds{30}};
    const auto second_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    uint64_t next_hash{0xc100};
    uint64_t next_nonce{51};
    const auto fill_to_capacity =
        [&](GovernanceRequestTracker& tracker, NodeId first_peer) {
            while (tracker.Size() <
                   GovernanceRequestTracker::MAX_ANNOUNCEMENTS) {
                const GovernanceRequestTracker::Source filler{
                    first_peer, static_cast<uint64_t>(first_peer + 5000),
                    {}, false};
                for (std::size_t slot{0};
                     slot <
                         GovernanceRequestTracker::MAX_ANNOUNCEMENTS_PER_PEER &&
                     tracker.Size() <
                         GovernanceRequestTracker::MAX_ANNOUNCEMENTS;
                     ++slot) {
                    if (!tracker.Announce(
                            filler,
                            CInv{MSG_GOVERNANCE_OBJECT,
                                 uint256S(strprintf(
                                     "%016x", next_hash++))})) {
                        return false;
                    }
                }
                ++first_peer;
            }
            return true;
        };
    const auto begin_page =
        [&](GovernanceRequestTracker& tracker,
            const GovernanceRequestTracker::Source& page_source) {
            if (!tracker.BeginPageSession(page_source, now)) return false;
            const auto request{MakeGovernancePageRequest(
                {}, {}, {}, next_nonce++)};
            return tracker.BeginPage(request, now, deadline);
        };

    {
        GovernanceRequestTracker tracker;
        const GovernanceRequestTracker::Source page_source{
            300, 5300, uint256S("c101"), true};
        const GovernanceRequestTracker::Source deferred_source{
            301, 5301, uint256S("c102"), true};
        const GovernanceRequestTracker::Source queued_vote_source{
            302, 5302, uint256S("c103"), true};
        const CInv deferred_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c104")};
        const CInv companion_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c105")};
        const CInv queued_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c106")};
        const CInv fresh_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c107")};

        BOOST_REQUIRE(begin_page(tracker, page_source));
        BOOST_REQUIRE(tracker.Announce(deferred_source, deferred_vote));
        const auto attempted{
            tracker.Request(deferred_source.peer, now, deadline)};
        BOOST_REQUIRE(attempted);
        const auto authorization{tracker.BeginResponse(
            deferred_source.peer, *attempted, now)};
        BOOST_REQUIRE(authorization);
        BOOST_REQUIRE(tracker.CompleteResponse(
            *authorization,
            GovernanceRequestTracker::ResponseOutcome::
                LOCAL_CONTEXT_CHANGED,
            now));
        BOOST_REQUIRE(tracker.Announce(
            deferred_source, companion_object));
        BOOST_REQUIRE(tracker.Announce(
            queued_vote_source, queued_vote));
        BOOST_REQUIRE(fill_to_capacity(tracker, 1000));

        BOOST_REQUIRE(tracker.Announce(page_source, fresh_object));
        BOOST_CHECK_EQUAL(tracker.Count(deferred_source.peer), 1U);
        BOOST_CHECK_EQUAL(tracker.Count(queued_vote_source.peer), 1U);
        BOOST_CHECK_EQUAL(
            tracker.Size(),
            GovernanceRequestTracker::MAX_ANNOUNCEMENTS);
        tracker.EndPageSession();
        const auto survivor{
            tracker.Request(deferred_source.peer, second_time, deadline)};
        BOOST_REQUIRE(survivor);
        BOOST_CHECK(*survivor == companion_object);
    }

    {
        GovernanceRequestTracker tracker;
        const GovernanceRequestTracker::Source page_source{
            310, 5310, uint256S("c111"), true};
        const GovernanceRequestTracker::Source deferred_source{
            311, 5311, uint256S("c112"), true};
        const GovernanceRequestTracker::Source queued_vote_source{
            312, 5312, uint256S("c113"), true};
        const CInv deferred_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c114")};
        const CInv queued_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c115")};
        const CInv fresh_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c116")};

        BOOST_REQUIRE(begin_page(tracker, page_source));
        BOOST_REQUIRE(tracker.Announce(
            deferred_source, deferred_object));
        const auto attempted{
            tracker.Request(deferred_source.peer, now, deadline)};
        BOOST_REQUIRE(attempted);
        const auto authorization{tracker.BeginResponse(
            deferred_source.peer, *attempted, now)};
        BOOST_REQUIRE(authorization);
        BOOST_REQUIRE(tracker.CompleteResponse(
            *authorization,
            GovernanceRequestTracker::ResponseOutcome::
                LOCAL_CONTEXT_CHANGED,
            now));
        BOOST_REQUIRE(tracker.Announce(
            queued_vote_source, queued_vote));
        BOOST_REQUIRE(fill_to_capacity(tracker, 1100));

        BOOST_REQUIRE(tracker.Announce(page_source, fresh_object));
        BOOST_CHECK_EQUAL(tracker.Count(deferred_source.peer), 1U);
        BOOST_CHECK_EQUAL(tracker.Count(queued_vote_source.peer), 0U);
        BOOST_CHECK_EQUAL(
            tracker.Size(),
            GovernanceRequestTracker::MAX_ANNOUNCEMENTS);
    }

    {
        GovernanceRequestTracker tracker;
        const GovernanceRequestTracker::Source page_source{
            320, 5320, uint256S("c121"), true};
        const GovernanceRequestTracker::Source deferred_source{
            321, 5321, uint256S("c122"), true};
        const CInv deferred_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c123")};
        const CInv rejected_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c124")};
        const CInv fresh_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c125")};

        BOOST_REQUIRE(begin_page(tracker, page_source));
        BOOST_REQUIRE(tracker.Announce(
            deferred_source, deferred_object));
        const auto attempted{
            tracker.Request(deferred_source.peer, now, deadline)};
        BOOST_REQUIRE(attempted);
        const auto authorization{tracker.BeginResponse(
            deferred_source.peer, *attempted, now)};
        BOOST_REQUIRE(authorization);
        BOOST_REQUIRE(tracker.CompleteResponse(
            *authorization,
            GovernanceRequestTracker::ResponseOutcome::
                LOCAL_CONTEXT_CHANGED,
            now));
        BOOST_REQUIRE(fill_to_capacity(tracker, 1200));

        BOOST_CHECK(!tracker.Announce(page_source, rejected_vote));
        BOOST_CHECK_EQUAL(tracker.Count(deferred_source.peer), 1U);
        BOOST_CHECK_EQUAL(
            tracker.Count(page_source.peer),
            MAX_GOVERNANCE_PAGE_INVENTORY);
        BOOST_REQUIRE(tracker.Announce(page_source, fresh_object));
        BOOST_CHECK_EQUAL(tracker.Count(deferred_source.peer), 0U);
        BOOST_CHECK_EQUAL(
            tracker.Count(page_source.peer),
            MAX_GOVERNANCE_PAGE_INVENTORY + 1U);
        BOOST_CHECK_EQUAL(
            tracker.Size(),
            GovernanceRequestTracker::MAX_ANNOUNCEMENTS);
    }

    {
        GovernanceRequestTracker tracker;
        const GovernanceRequestTracker::Source page_source{
            330, 5330, uint256S("c131"), true};
        const GovernanceRequestTracker::Source protected_source{
            331, 5331, uint256S("c132"), true};
        const GovernanceRequestTracker::Source queued_vote_source{
            332, 5332, uint256S("c133"), true};
        const CInv protected_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c134")};
        const CInv queued_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c135")};
        const CInv fresh_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c136")};

        BOOST_REQUIRE(begin_page(tracker, page_source));
        BOOST_REQUIRE(tracker.Announce(
            protected_source, protected_vote));
        const auto requested{
            tracker.Request(protected_source.peer, now, deadline)};
        BOOST_REQUIRE(requested);
        const auto authorization{tracker.BeginResponse(
            protected_source.peer, *requested, now)};
        BOOST_REQUIRE(authorization);
        BOOST_REQUIRE(tracker.Announce(
            queued_vote_source, queued_vote));
        BOOST_REQUIRE(fill_to_capacity(tracker, 1300));

        // Global admission must not evict an ordinary item whose delivered
        // response is still being verified; a local-context result needs the
        // retained entry so it can be deferred and retried fairly.
        BOOST_REQUIRE(tracker.Announce(page_source, fresh_object));
        BOOST_CHECK_EQUAL(tracker.Count(protected_source.peer), 1U);
        BOOST_CHECK_EQUAL(tracker.Count(queued_vote_source.peer), 0U);
        BOOST_CHECK(tracker.IsRequested(
            protected_source.peer, protected_vote));
        BOOST_REQUIRE(tracker.CompleteResponse(
            *authorization,
            GovernanceRequestTracker::ResponseOutcome::
                LOCAL_CONTEXT_CHANGED,
            now));
        BOOST_CHECK_EQUAL(tracker.Count(protected_source.peer), 1U);
        BOOST_CHECK_EQUAL(
            tracker.Size(),
            GovernanceRequestTracker::MAX_ANNOUNCEMENTS);
    }

    {
        GovernanceRequestTracker tracker;
        const GovernanceRequestTracker::Source page_source{
            340, 5340, uint256S("c141"), true};
        const GovernanceRequestTracker::Source protected_source{
            341, 5341, uint256S("c142"), true};
        const CInv protected_vote{
            MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c143")};
        const CInv fresh_object{
            MSG_GOVERNANCE_OBJECT, uint256S("c144")};

        BOOST_REQUIRE(begin_page(tracker, page_source));
        BOOST_REQUIRE(tracker.Announce(
            protected_source, protected_vote));
        const auto requested{
            tracker.Request(protected_source.peer, now, deadline)};
        BOOST_REQUIRE(requested);
        const auto authorization{tracker.BeginResponse(
            protected_source.peer, *requested, now)};
        BOOST_REQUIRE(authorization);
        BOOST_REQUIRE(fill_to_capacity(tracker, 1400));

        // When every other slot contains a fresh parent object, admission
        // fails instead of consuming the only delivered ordinary request.
        BOOST_CHECK(!tracker.Announce(page_source, fresh_object));
        BOOST_CHECK(tracker.IsRequested(
            protected_source.peer, protected_vote));
        BOOST_CHECK_EQUAL(
            tracker.Size(),
            GovernanceRequestTracker::MAX_ANNOUNCEMENTS);
    }
}

BOOST_AUTO_TEST_CASE(
    pq_governance_verified_orphan_transport_semantics)
{
    const GovernanceRequestTracker::Source source{
        97, 820, uint256S("b201"), true};
    const uint256 parent_hash{uint256S("b202")};
    const CInv orphan_vote{
        MSG_GOVERNANCE_OBJECT_VOTE, uint256S("b203")};
    const CInv parent{MSG_GOVERNANCE_OBJECT, parent_hash};
    const auto now{std::chrono::seconds{70}};
    const auto deadline{now + std::chrono::seconds{30}};

    GovernanceRequestTracker ordinary;
    BOOST_REQUIRE(ordinary.Announce(source, orphan_vote));
    const auto requested{
        ordinary.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(requested);
    BOOST_CHECK(*requested == orphan_vote);
    const auto authorization{
        ordinary.BeginResponse(source.peer, *requested, now)};
    BOOST_REQUIRE(authorization);
    BOOST_REQUIRE(ordinary.CompleteResponse(
        *authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_ORPHAN_STORED,
        now));
    BOOST_CHECK(!ordinary.CompleteResponse(
        *authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_ORPHAN_STORED,
        now));
    BOOST_CHECK_EQUAL(ordinary.Count(source.peer), 0U);

    BOOST_REQUIRE(ordinary.Announce(source, parent));
    BOOST_CHECK(!ordinary.Request(source.peer, now, deadline));
    const auto after_cadence{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto parent_request{
        ordinary.Request(source.peer, after_cadence, deadline)};
    BOOST_REQUIRE(parent_request);
    BOOST_CHECK(*parent_request == parent);

    GovernanceRequestTracker exact_page;
    const std::vector<CInv> inventory{orphan_vote};
    const auto view{
        ComputeGovernancePageViewHash(parent_hash, inventory)};
    BOOST_REQUIRE(view);
    auto page_request{
        MakeGovernancePageRequest(parent_hash, {}, {}, 61)};
    const auto page_response{MakeGovernancePageResponse(
        page_request, inventory, /*done=*/true, *view,
        /*total_count=*/1)};
    BOOST_REQUIRE(exact_page.BeginPageSession(source, now));
    BOOST_REQUIRE(exact_page.BeginPage(
        page_request, now, deadline));
    BOOST_REQUIRE(exact_page.ReceivedPage(
        source.peer, page_response, inventory, now));
    const auto page_item{
        exact_page.Request(source.peer, now, deadline)};
    BOOST_REQUIRE(page_item);
    const auto page_authorization{
        exact_page.BeginResponse(source.peer, *page_item, now)};
    BOOST_REQUIRE(page_authorization);
    BOOST_CHECK(page_authorization->page_required);
    BOOST_REQUIRE(exact_page.CompleteResponse(
        *page_authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_ORPHAN_STORED,
        now));
    const auto failed_page{exact_page.TakePageResult(now)};
    BOOST_REQUIRE(failed_page);
    BOOST_CHECK(!failed_page->success);
    BOOST_CHECK(failed_page->request.cursor.IsNull());

    ++page_request.nonce;
    BOOST_CHECK(exact_page.BeginPage(
        page_request, after_cadence, deadline));
}

BOOST_AUTO_TEST_CASE(pq_governance_page_protocol_and_codec_are_canonical)
{
    BOOST_CHECK(!SupportsGovernancePages(
        GOVERNANCE_PAGE_PROTO_VERSION - 1));
    BOOST_CHECK(SupportsGovernancePages(GOVERNANCE_PAGE_PROTO_VERSION));
    BOOST_CHECK_LE(GOVERNANCE_PAGE_PROTO_VERSION, PROTOCOL_VERSION);

    const std::vector<CInv> complete{
        {MSG_GOVERNANCE_OBJECT, uint256{1}},
        {MSG_GOVERNANCE_OBJECT, uint256{2}},
        {MSG_GOVERNANCE_OBJECT, uint256{3}}};
    const auto view{ComputeGovernancePageViewHash({}, complete)};
    BOOST_REQUIRE(view);
    const auto request{MakeGovernancePageRequest()};
    const auto first{MakeGovernancePageResponse(
        request, {complete[0], complete[1]}, false, *view, 3)};
    BOOST_CHECK(IsValidGovernancePageResponse(request, first));

    auto malformed{first};
    malformed.nonce++;
    BOOST_CHECK(!IsValidGovernancePageResponse(request, malformed));
    malformed = first;
    malformed.status = 255;
    BOOST_CHECK(!IsValidGovernancePageResponse(request, malformed));
    malformed = first;
    malformed.inventory[1] = malformed.inventory[0];
    BOOST_CHECK(!IsValidGovernancePageResponse(request, malformed));
    malformed = first;
    malformed.total_count = 2;
    BOOST_CHECK(!IsValidGovernancePageResponse(request, malformed));

    const auto noncanonical_restart{
        MakeGovernancePageRequest({}, {}, *view, 2)};
    BOOST_CHECK(!IsValidGovernancePageResponse(
        noncanonical_restart,
        MakeGovernancePageResponse(
            noncanonical_restart, {}, true, *view, 0)));

    const auto continuation{
        MakeGovernancePageRequest({}, complete[1].hash, *view, 3)};
    const auto terminal{MakeGovernancePageResponse(
        continuation, {complete[2]}, true, *view, 3)};
    BOOST_CHECK(IsValidGovernancePageResponse(continuation, terminal));

    auto changed{MakeGovernancePageResponse(
        continuation, {}, false, uint256{99}, 4,
        GOVERNANCE_PAGE_VIEW_CHANGED)};
    BOOST_CHECK(IsValidGovernancePageResponse(continuation, changed));
    auto restart{MakeGovernancePageResponse(
        continuation, {}, false, {}, 0,
        GOVERNANCE_PAGE_RESTART_REQUIRED)};
    BOOST_CHECK(IsValidGovernancePageResponse(continuation, restart));
    auto unavailable{MakeGovernancePageResponse(
        continuation, {}, false, {}, 0,
        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE)};
    BOOST_CHECK(IsValidGovernancePageResponse(
        continuation, unavailable));
    auto scope_too_large{MakeGovernancePageResponse(
        continuation, {}, false, {}, 0,
        GOVERNANCE_PAGE_SCOPE_TOO_LARGE)};
    BOOST_CHECK(IsValidGovernancePageResponse(
        continuation, scope_too_large));
    scope_too_large.total_count = 1;
    BOOST_CHECK(!IsValidGovernancePageResponse(
        continuation, scope_too_large));

    CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
    encoded << terminal;
    CGovernancePageResponse decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded.scope_hash == terminal.scope_hash);
    BOOST_CHECK(decoded.cursor == terminal.cursor);
    BOOST_CHECK(decoded.request_view_id == terminal.request_view_id);
    BOOST_CHECK_EQUAL(decoded.nonce, terminal.nonce);
    BOOST_CHECK_EQUAL(decoded.status, terminal.status);
    BOOST_CHECK(decoded.view_id == terminal.view_id);
    BOOST_CHECK_EQUAL(decoded.total_count, terminal.total_count);
    BOOST_CHECK(decoded.next_cursor == terminal.next_cursor);
    BOOST_CHECK_EQUAL(decoded.done, terminal.done);
    BOOST_REQUIRE_EQUAL(decoded.inventory.size(), 1U);
    BOOST_CHECK(decoded.inventory[0].hash == complete[2].hash);

    auto oversized{first};
    oversized.inventory.push_back(complete[2]);
    CDataStream oversized_encoding{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK_THROW(oversized_encoding << oversized,
                      std::ios_base::failure);

    CDataStream oversized_wire{SER_NETWORK, PROTOCOL_VERSION};
    oversized_wire << first.scope_hash << first.cursor
                   << first.request_view_id << first.nonce
                   << first.status << first.view_id << first.total_count
                   << first.next_cursor << first.done;
    WriteCompactSize(oversized_wire, 3);
    for (const CInv& inv : complete) oversized_wire << inv;
    CGovernancePageResponse rejected;
    BOOST_CHECK_THROW(oversized_wire >> rejected,
                      std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_page_accepts_bounded_masternode_transport)
{
    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c001;
    const CAddress address{CService{ipv4_addr, 7777}, NODE_NETWORK};
    const std::string destination;
    CNode inbound{
        /*id=*/1, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/1, CAddress{},
        destination, ConnectionType::INBOUND,
        /*inbound_onion=*/false};
    inbound.SetCommonVersion(GOVERNANCE_PAGE_PROTO_VERSION);
    BOOST_CHECK(CanUseGovernancePageProtocol(inbound));

    inbound.m_masternode_connection = true;
    BOOST_CHECK(!inbound.CanRelay());
    // An unauthenticated ordinary peer can already request bounded pages. A
    // VERSION-level masternode claim must not remove that bootstrap path while
    // MNAUTH is deferred during blockchain sync; it remains netgroup-limited.
    BOOST_CHECK(inbound.GetVerifiedProRegTxHash().IsNull());
    BOOST_CHECK(CanUseGovernancePageProtocol(inbound));
    inbound.SetVerifiedMasternode(
        uint256::ONEV, uint256::ONEV, /*global_key_version=*/1);
    BOOST_CHECK(CanUseGovernancePageProtocol(inbound));
    inbound.m_masternode_probe_connection = true;
    BOOST_CHECK(!CanUseGovernancePageProtocol(inbound));
    inbound.m_masternode_probe_connection = false;

    CNode block_only{
        /*id=*/2, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/2, CAddress{},
        destination, ConnectionType::BLOCK_RELAY,
        /*inbound_onion=*/false};
    block_only.SetCommonVersion(GOVERNANCE_PAGE_PROTO_VERSION);
    block_only.SetVerifiedMasternode(
        uint256::ONEV, uint256::ONEV, /*global_key_version=*/1);
    BOOST_CHECK(!CanUseGovernancePageProtocol(block_only));

    inbound.SetCommonVersion(GOVERNANCE_PAGE_PROTO_VERSION - 1);
    BOOST_CHECK(!CanUseGovernancePageProtocol(inbound));
}

BOOST_AUTO_TEST_CASE(
    pq_governance_page_busy_response_preserves_serve_phase)
{
    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c002;
    const CAddress address{CService{ipv4_addr, 7778}, NODE_NETWORK};
    CNode node{
        /*id=*/3, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/2, /*nLocalHostNonceIn=*/3, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    node.SetCommonVersion(GOVERNANCE_PAGE_PROTO_VERSION);
    m_node.peerman->InitializeNode(node, NODE_NETWORK);

    const PeerRef peer{m_node.peerman->GetPeerRef(node.GetId())};
    BOOST_REQUIRE(peer);
    const uint256 scope{uint256{20}};
    const uint256 prior_scope{uint256{19}};
    const uint256 view{uint256{21}};
    const uint256 cursor{uint256{22}};
    const CInv upload{MSG_GOVERNANCE_OBJECT_VOTE, uint256{23}};
    const auto now{GetTime<std::chrono::microseconds>()};
    {
        LOCK(peer->m_governance_page_upload_mutex);
        peer->m_governance_page_serve_phase =
            Peer::GovernancePageServePhase{
                /*object_done=*/true, prior_scope,
                now + std::chrono::hours{1}};
        peer->m_governance_page_serve_session =
            Peer::GovernancePageServeSession{
                /*generation=*/1, /*snapshot=*/nullptr, scope, view,
                cursor, /*last_nonce=*/10,
                /*cursor_zero_restarts=*/0,
                now + std::chrono::hours{1},
                now + std::chrono::hours{2}};
        peer->m_governance_page_uploads.emplace(
            upload, Peer::GovernancePageUpload{
                        scope, now + std::chrono::hours{1},
                        /*exact_page=*/true, /*snapshot=*/nullptr,
                        /*entry_index=*/0});
        peer->m_last_governance_page_serve_nonce = 10;
    }

    CGovernancePageRequest continuation;
    continuation.scope_hash = scope;
    continuation.cursor = cursor;
    continuation.view_id = view;
    continuation.nonce = 11;
    const auto prepared{
        m_node.peerman->PrepareGovernancePageRequest(node, continuation)};
    BOOST_REQUIRE(prepared.has_value());

    GovernancePageBuildResult busy;
    busy.response.scope_hash = scope;
    busy.response.cursor = cursor;
    busy.response.request_view_id = view;
    busy.response.nonce = continuation.nonce;
    busy.response.status = GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE;
    busy.response.next_cursor = cursor;
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        continuation, busy.response));
    BOOST_REQUIRE(m_node.peerman->SendGovernancePage(node, busy));

    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK(peer->m_governance_page_uploads.empty());
        BOOST_CHECK(!peer->m_governance_page_serve_session);
        BOOST_REQUIRE(peer->m_governance_page_serve_phase);
        BOOST_CHECK(peer->m_governance_page_serve_phase->object_done);
        BOOST_CHECK(peer->m_governance_page_serve_phase->last_vote_scope ==
                    prior_scope);
        BOOST_CHECK_EQUAL(peer->m_last_governance_page_serve_nonce, 11U);
    }
    BOOST_CHECK(!m_node.peerman->SendGovernancePage(node, busy));

    CGovernancePageRequest retry;
    retry.scope_hash = scope;
    retry.nonce = 12;
    BOOST_CHECK(m_node.peerman
                    ->PrepareGovernancePageRequest(node, retry)
                    .has_value());

    m_node.peerman->FinalizeNode(node);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_page_upload_lanes_are_isolated)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c003;
    const CAddress address{CService{ipv4_addr, 7779}, NODE_NETWORK};
    CNode node{
        /*id=*/4, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/3, /*nLocalHostNonceIn=*/4, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    connman.Handshake(
        node, /*successfully_connected=*/true,
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        PROTOCOL_VERSION, /*relay_txs=*/true);
    TestOnlyResetTimeData();

    const PeerRef peer{m_node.peerman->GetPeerRef(node.GetId())};
    BOOST_REQUIRE(peer);
    Peer::TxRelay* const tx_relay{peer->GetTxRelay()};
    BOOST_REQUIRE(tx_relay);

    const uint256 view{uint256{30}};
    const std::vector<CInv> inventory{
        {MSG_GOVERNANCE_OBJECT, uint256{10}},
        {MSG_GOVERNANCE_OBJECT, uint256{20}},
        {MSG_GOVERNANCE_OBJECT, uint256{30}},
        {MSG_GOVERNANCE_OBJECT, uint256{40}},
    };
    const auto snapshot{
        MakeGovernancePageSnapshot({}, view, inventory)};
    BOOST_REQUIRE(snapshot);

    const auto first_request{MakeGovernancePageRequest()};
    GovernancePageBuildResult first_page{
        MakeGovernancePageResponse(
            first_request, {inventory[0], inventory[1]},
            /*done=*/false, view,
            static_cast<uint32_t>(inventory.size())),
        snapshot, {0, 1}};
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        first_request, first_page.response));
    BOOST_REQUIRE(m_node.peerman->SendGovernancePage(
        node, first_page));

    // Model an all-known page by leaving both exact credits unconsumed. A
    // newly accepted live object must still receive the independent ordinary
    // relay credit.
    const CInv live{
        MSG_GOVERNANCE_OBJECT, uint256{50}};
    m_node.peerman->PushTxInventoryOther(*peer, live);
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        tx_relay->m_next_inv_send_time = 1us;
    }
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_CHECK(!tx_relay->m_tx_inventory_to_send_other.count(live));
    }
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE_EQUAL(
            peer->m_governance_page_uploads.size(),
            Peer::MAX_GOVERNANCE_UPLOADS);
        BOOST_CHECK_EQUAL(
            std::count_if(
                peer->m_governance_page_uploads.begin(),
                peer->m_governance_page_uploads.end(),
                [](const auto& upload) {
                    return upload.second.exact_page;
                }),
            MAX_GOVERNANCE_PAGE_INVENTORY);
        const auto ordinary{
            peer->m_governance_page_uploads.find(live)};
        BOOST_REQUIRE(ordinary !=
                      peer->m_governance_page_uploads.end());
        BOOST_CHECK(!ordinary->second.exact_page);
    }

    const auto continuation_request{MakeGovernancePageRequest(
        {}, first_page.response.next_cursor, view, /*nonce=*/2)};
    const auto prepared{m_node.peerman->PrepareGovernancePageRequest(
        node, continuation_request)};
    BOOST_REQUIRE(prepared.has_value());
    BOOST_CHECK(*prepared == snapshot);
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE_EQUAL(
            peer->m_governance_page_uploads.size(), 1U);
        BOOST_REQUIRE(peer->m_governance_page_uploads.count(live));
        BOOST_CHECK(!peer->m_governance_page_uploads.at(live).exact_page);
    }

    GovernancePageBuildResult terminal_page{
        MakeGovernancePageResponse(
            continuation_request, {inventory[2], inventory[3]},
            /*done=*/true, view,
            static_cast<uint32_t>(inventory.size())),
        snapshot, {2, 3}};
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        continuation_request, terminal_page.response));
    BOOST_REQUIRE(m_node.peerman->SendGovernancePage(
        node, terminal_page));
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE_EQUAL(
            peer->m_governance_page_uploads.size(),
            Peer::MAX_GOVERNANCE_UPLOADS);
        BOOST_REQUIRE(peer->m_governance_page_uploads.count(live));
        BOOST_CHECK(!peer->m_governance_page_uploads.at(live).exact_page);
        for (std::size_t i{2}; i < inventory.size(); ++i) {
            const auto exact{
                peer->m_governance_page_uploads.find(inventory[i])};
            BOOST_REQUIRE(exact !=
                          peer->m_governance_page_uploads.end());
            BOOST_CHECK(exact->second.exact_page);
            BOOST_CHECK(exact->second.snapshot == snapshot);
            BOOST_CHECK_EQUAL(exact->second.entry_index, i);
        }
    }

    const CInv blocked_live{
        MSG_GOVERNANCE_OBJECT, uint256{60}};
    m_node.peerman->PushTxInventoryOther(*peer, blocked_live);
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        tx_relay->m_next_inv_send_time = 1us;
    }
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK_EQUAL(
            peer->m_governance_page_uploads.size(),
            Peer::MAX_GOVERNANCE_UPLOADS);
        BOOST_CHECK(!peer->m_governance_page_uploads.count(
            blocked_live));
    }
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_CHECK(tx_relay->m_tx_inventory_to_send_other.count(
            blocked_live));
    }

    // A later exact page commitment for the live hash replaces the weaker
    // ordinary authorization instead of increasing the bounded capacity.
    const uint256 replacement_view{uint256{31}};
    const std::vector<CInv> replacement_inventory{
        live, {MSG_GOVERNANCE_OBJECT, uint256{70}}};
    const auto replacement_snapshot{MakeGovernancePageSnapshot(
        {}, replacement_view, replacement_inventory,
        /*instance_id=*/2)};
    BOOST_REQUIRE(replacement_snapshot);
    const auto restart_request{MakeGovernancePageRequest(
        {}, {}, {}, /*nonce=*/3)};
    const auto restarted{m_node.peerman->PrepareGovernancePageRequest(
        node, restart_request)};
    BOOST_REQUIRE(restarted.has_value());
    GovernancePageBuildResult replacement_page{
        MakeGovernancePageResponse(
            restart_request, replacement_inventory,
            /*done=*/true, replacement_view,
            static_cast<uint32_t>(replacement_inventory.size())),
        replacement_snapshot, {0, 1}};
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        restart_request, replacement_page.response));
    BOOST_REQUIRE(m_node.peerman->SendGovernancePage(
        node, replacement_page));
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE_EQUAL(
            peer->m_governance_page_uploads.size(),
            MAX_GOVERNANCE_PAGE_INVENTORY);
        for (const CInv& inv : replacement_inventory) {
            const auto exact{
                peer->m_governance_page_uploads.find(inv)};
            BOOST_REQUIRE(exact !=
                          peer->m_governance_page_uploads.end());
            BOOST_CHECK(exact->second.exact_page);
            BOOST_CHECK(exact->second.snapshot ==
                        replacement_snapshot);
        }
    }

    m_node.peerman->FinalizeNode(node);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_exact_upload_suppresses_redundant_ordinary_inv)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c005;
    const CAddress address{CService{ipv4_addr, 7781}, NODE_NETWORK};
    CNode node{
        /*id=*/6, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/5, /*nLocalHostNonceIn=*/6, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    connman.Handshake(
        node, /*successfully_connected=*/true,
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        PROTOCOL_VERSION, /*relay_txs=*/true);
    TestOnlyResetTimeData();

    const PeerRef peer{m_node.peerman->GetPeerRef(node.GetId())};
    BOOST_REQUIRE(peer);
    Peer::TxRelay* const tx_relay{peer->GetTxRelay()};
    BOOST_REQUIRE(tx_relay);

    const CInv exact{MSG_GOVERNANCE_OBJECT, uint256S("d101")};
    const CInv later{MSG_GOVERNANCE_OBJECT, uint256S("d102")};
    const uint256 view{uint256S("d103")};
    const auto snapshot{MakeGovernancePageSnapshot({}, view, {exact})};
    BOOST_REQUIRE(snapshot);
    const auto exact_expiry{
        GetTime<std::chrono::microseconds>() + std::chrono::seconds{10}};
    {
        LOCK(peer->m_governance_page_upload_mutex);
        peer->m_governance_page_uploads.emplace(
            exact, Peer::GovernancePageUpload{
                       {}, exact_expiry, /*exact_page=*/true, snapshot, 0});
    }

    m_node.peerman->PushTxInventoryOther(*peer, exact);
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_REQUIRE(tx_relay->m_tx_inventory_to_send_other.count(exact));
        BOOST_CHECK(!tx_relay->m_tx_inventory_known_filter.contains(
            exact.hash));
        tx_relay->m_next_inv_send_time = 1us;
    }
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));

    // GOVPAGE already announced this hash. The generic queue entry is
    // redundant and must not create a second, shorter authorization or mark
    // the hash known as though an ordinary INV had been emitted.
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_CHECK(!tx_relay->m_tx_inventory_to_send_other.count(exact));
        BOOST_CHECK(!tx_relay->m_tx_inventory_known_filter.contains(
            exact.hash));
    }
    {
        LOCK(peer->m_governance_page_upload_mutex);
        const auto upload{peer->m_governance_page_uploads.find(exact)};
        BOOST_REQUIRE(upload != peer->m_governance_page_uploads.end());
        BOOST_CHECK(upload->second.exact_page);
        BOOST_CHECK(upload->second.snapshot == snapshot);
        BOOST_CHECK(upload->second.expiry == exact_expiry);
        upload->second.expiry =
            GetTime<std::chrono::microseconds>() - 1us;
    }

    // Once the exact credit is actually gone, an unrelated live item still
    // uses the independent ordinary lane and receives a fresh authorization.
    m_node.peerman->PushTxInventoryOther(*peer, later);
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        tx_relay->m_next_inv_send_time = 1us;
    }
    const auto before_later{GetTime<std::chrono::microseconds>()};
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_CHECK(!tx_relay->m_tx_inventory_to_send_other.count(later));
        BOOST_CHECK(tx_relay->m_tx_inventory_known_filter.contains(
            later.hash));
    }
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK(!peer->m_governance_page_uploads.count(exact));
        BOOST_CHECK(!peer->m_retired_governance_ordinary_uploads.count(
            exact));
        const auto upload{peer->m_governance_page_uploads.find(later)};
        BOOST_REQUIRE(upload != peer->m_governance_page_uploads.end());
        BOOST_CHECK(!upload->second.exact_page);
        BOOST_CHECK(upload->second.expiry >=
                    before_later +
                        Peer::GOVERNANCE_ORDINARY_UPLOAD_LIFETIME);
    }

    m_node.peerman->FinalizeNode(node);
}

BOOST_AUTO_TEST_CASE(
    pq_governance_retired_ordinary_uploads_are_bounded_and_one_shot)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c004;
    const CAddress address{CService{ipv4_addr, 7780}, NODE_NETWORK};
    CNode node{
        /*id=*/5, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/4, /*nLocalHostNonceIn=*/5, CAddress{},
        /*addrNameIn=*/std::string{},
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false};
    auto& connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
    connman.Handshake(
        node, /*successfully_connected=*/true,
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        PROTOCOL_VERSION, /*relay_txs=*/true);
    TestOnlyResetTimeData();

    const PeerRef peer{m_node.peerman->GetPeerRef(node.GetId())};
    BOOST_REQUIRE(peer);
    Peer::TxRelay* const tx_relay{peer->GetTxRelay()};
    BOOST_REQUIRE(tx_relay);
    BOOST_REQUIRE_GT(
        Peer::MAX_RETIRED_GOVERNANCE_ORDINARY_UPLOADS, 1U);

    const auto now{GetTime<std::chrono::microseconds>()};
    const CInv retiring{
        MSG_GOVERNANCE_OBJECT, uint256S("d001")};
    const CInv next_live{
        MSG_GOVERNANCE_OBJECT, uint256S("d002")};
    std::vector<CInv> seeded_retired;
    seeded_retired.reserve(
        Peer::MAX_RETIRED_GOVERNANCE_ORDINARY_UPLOADS);
    {
        LOCK(peer->m_governance_page_upload_mutex);
        peer->m_governance_page_uploads.emplace(
            retiring, Peer::GovernancePageUpload{
                          {}, now - 1us, /*exact_page=*/false, {}});
        for (std::size_t i{0};
             i < Peer::MAX_RETIRED_GOVERNANCE_ORDINARY_UPLOADS;
             ++i) {
            const CInv filler{
                MSG_GOVERNANCE_OBJECT,
                uint256{static_cast<uint8_t>(100 + i)}};
            seeded_retired.push_back(filler);
            peer->m_retired_governance_ordinary_uploads.emplace(
                filler, now + std::chrono::seconds{
                                  static_cast<int64_t>(i + 1)});
        }
    }
    m_node.peerman->PushTxInventoryOther(*peer, next_live);
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        tx_relay->m_next_inv_send_time = 1us;
    }
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));

    // Expiry moves the old exact CInv into a bounded grace set while freeing
    // the independent active lane for the next INV in the same send pass.
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE_EQUAL(
            peer->m_retired_governance_ordinary_uploads.size(),
            Peer::MAX_RETIRED_GOVERNANCE_ORDINARY_UPLOADS);
        BOOST_CHECK(
            peer->m_retired_governance_ordinary_uploads.count(retiring));
        BOOST_CHECK(!peer->m_retired_governance_ordinary_uploads.count(
            seeded_retired.front()));
        BOOST_REQUIRE(peer->m_governance_page_uploads.count(next_live));
        BOOST_CHECK(!peer->m_governance_page_uploads.at(next_live).exact_page);
    }
    {
        LOCK(tx_relay->m_tx_inventory_mutex);
        BOOST_CHECK(!tx_relay->m_tx_inventory_to_send_other.count(next_live));
    }

    // Dead grace entries are removed independently of active INV traffic.
    const CInv purged{seeded_retired[1]};
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_REQUIRE(peer->m_retired_governance_ordinary_uploads.count(
            purged));
        peer->m_retired_governance_ordinary_uploads.at(purged) = now - 1us;
    }
    BOOST_REQUIRE(m_node.peerman->SendMessages(&node));
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK(!peer->m_retired_governance_ordinary_uploads.count(
            purged));
    }

    // A stronger page commitment for the same hash removes the retired relay
    // grant instead of leaving a second way to consume the payload.
    const auto replacement_view{ComputeGovernancePageViewHash(
        {}, std::vector<CInv>{retiring})};
    BOOST_REQUIRE(replacement_view);
    const auto replacement_snapshot{MakeGovernancePageSnapshot(
        {}, *replacement_view, {retiring}, /*instance_id=*/3)};
    BOOST_REQUIRE(replacement_snapshot);
    const auto replacement_request{MakeGovernancePageRequest(
        {}, {}, {}, /*nonce=*/40)};
    GovernancePageBuildResult replacement_page{
        MakeGovernancePageResponse(
            replacement_request, {retiring}, /*done=*/true,
            *replacement_view, /*total_count=*/1),
        replacement_snapshot, {0}};
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        replacement_request, replacement_page.response));
    BOOST_REQUIRE(m_node.peerman->SendGovernancePage(
        node, replacement_page));
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK(!peer->m_retired_governance_ordinary_uploads.count(
            retiring));
        const auto exact{peer->m_governance_page_uploads.find(retiring)};
        BOOST_REQUIRE(exact != peer->m_governance_page_uploads.end());
        BOOST_CHECK(exact->second.exact_page);
        BOOST_CHECK(exact->second.snapshot == replacement_snapshot);
    }

    // Retired ordinary credits are consumed before lookup or serialization,
    // so even a now-missing payload cannot reuse the one-shot authorization.
    const CInv one_shot{
        MSG_GOVERNANCE_OBJECT_VOTE, uint256S("d003")};
    {
        LOCK(peer->m_governance_page_upload_mutex);
        peer->m_retired_governance_ordinary_uploads.emplace(
            one_shot, now + GOVERNANCE_PAGE_TRANSFER_TIMEOUT);
    }
    connman.FlushSendBuffer(node);
    node.fPauseSend = false;
    std::atomic<bool> interrupt{false};
    CDataStream getdata{SER_NETWORK, node.GetCommonVersion()};
    getdata << std::vector<CInv>{one_shot};
    BOOST_REQUIRE(!node.fDisconnect);
    m_node.peerman->ProcessMessage(
        node, NetMsgType::GETDATA, getdata, now, interrupt);
    BOOST_CHECK(!node.fDisconnect);
    {
        LOCK(peer->m_getdata_requests_mutex);
        BOOST_CHECK(peer->m_getdata_requests.empty());
    }
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK(!peer->m_retired_governance_ordinary_uploads.count(
            one_shot));
    }
    std::size_t retired_after_first{0};
    {
        LOCK(peer->m_governance_page_upload_mutex);
        retired_after_first =
            peer->m_retired_governance_ordinary_uploads.size();
    }
    CDataStream repeated_getdata{SER_NETWORK, node.GetCommonVersion()};
    repeated_getdata << std::vector<CInv>{one_shot};
    connman.FlushSendBuffer(node);
    node.fPauseSend = false;
    m_node.peerman->ProcessMessage(
        node, NetMsgType::GETDATA, repeated_getdata, now, interrupt);
    {
        LOCK(peer->m_getdata_requests_mutex);
        BOOST_CHECK(peer->m_getdata_requests.empty());
    }
    {
        LOCK(peer->m_governance_page_upload_mutex);
        BOOST_CHECK_EQUAL(
            peer->m_retired_governance_ordinary_uploads.size(),
            retired_after_first);
    }

    m_node.peerman->FinalizeNode(node);
}

BOOST_AUTO_TEST_CASE(pq_governance_page_session_reservation_is_atomic)
{
    GovernanceRequestTracker tracker;
    std::vector<GovernanceRequestTracker::Source> sources;
    for (int i{0}; i < 15; ++i) {
        sources.push_back(GovernanceRequestTracker::Source{
            100 + i, static_cast<uint64_t>(1000 + i), {}, i % 2 == 0});
        BOOST_REQUIRE(tracker.Announce(
            sources.back(),
            CInv{MSG_GOVERNANCE_OBJECT,
                 uint256{static_cast<uint8_t>(100 + 2 * i)}}));
        BOOST_REQUIRE(tracker.Announce(
            sources.back(),
            CInv{MSG_GOVERNANCE_OBJECT,
                 uint256{static_cast<uint8_t>(101 + 2 * i)}}));
    }
    BOOST_REQUIRE_EQUAL(tracker.Size(), 30U);

    const auto page_source{sources.front()};
    const auto now{std::chrono::seconds{100}};
    BOOST_REQUIRE(tracker.BeginPageSession(page_source, now));
    BOOST_CHECK(tracker.HasActivePageSession());
    BOOST_CHECK_EQUAL(tracker.Size(), 30U);
    BOOST_CHECK_EQUAL(tracker.Count(page_source.peer), 2U);
    BOOST_REQUIRE(tracker.Announce(
        page_source,
        CInv{MSG_GOVERNANCE_OBJECT, uint256{250}}));
    BOOST_CHECK_EQUAL(tracker.Size(), 31U);

    const auto deadline{now + std::chrono::seconds{30}};
    BOOST_CHECK(!tracker.Request(sources[1].peer, now, deadline));

    const std::vector<CInv> complete{
        {MSG_GOVERNANCE_OBJECT, uint256{104}},
        {MSG_GOVERNANCE_OBJECT, uint256{201}},
        {MSG_GOVERNANCE_OBJECT, uint256{202}}};
    const auto view{ComputeGovernancePageViewHash({}, complete)};
    BOOST_REQUIRE(view);
    const auto request{MakeGovernancePageRequest({}, {}, {}, 11)};
    BOOST_REQUIRE(tracker.BeginPage(request, now, deadline));

    const auto relayed_while_waiting{
        tracker.Request(sources[2].peer, now, deadline)};
    BOOST_REQUIRE(relayed_while_waiting);
    BOOST_CHECK(relayed_while_waiting->hash == uint256{104});
    const auto page_now{now};
    const auto response{MakeGovernancePageResponse(
        request, {complete[0], complete[1]}, false, *view, 3)};
    BOOST_CHECK(!tracker.ReceivedPage(
        page_source.peer, response,
        {complete[0], CInv{MSG_GOVERNANCE_OBJECT, uint256{249}}},
        page_now));
    BOOST_CHECK(tracker.IsPageRequested(page_source.peer, response));
    BOOST_REQUIRE(tracker.ReceivedPage(
        page_source.peer, response, {complete[0], complete[1]},
        page_now));

    const auto ordinary_authorization{tracker.BeginResponse(
        sources[2].peer, *relayed_while_waiting, page_now)};
    BOOST_REQUIRE(ordinary_authorization);
    BOOST_CHECK(!ordinary_authorization->page_required);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *ordinary_authorization,
        GovernanceRequestTracker::ResponseOutcome::NOT_FOUND,
        page_now));
    BOOST_CHECK(!tracker.TakePageResult(page_now));
    BOOST_REQUIRE(tracker.Announce(
        sources[2],
        CInv{MSG_GOVERNANCE_OBJECT, uint256{249}}));

    const auto first{tracker.Request(page_source.peer, page_now, deadline)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->hash == complete[0].hash);
    BOOST_CHECK(!tracker.ReceivedResponse(
        page_source.peer, *first, page_now));
    BOOST_CHECK(tracker.IsRequested(page_source.peer, *first));
    const auto authorization{
        tracker.BeginResponse(page_source.peer, *first, page_now)};
    BOOST_REQUIRE(authorization);
    BOOST_CHECK(authorization->page_required);
    BOOST_CHECK(authorization->page_scope.IsNull());
    tracker.Forget(*first);
    BOOST_CHECK(!tracker.BeginResponse(
        page_source.peer, *first, now).has_value());
    BOOST_REQUIRE(tracker.CompleteResponse(
        *authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        page_now));

    const auto after_cadence{
        page_now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto second{
        tracker.Request(page_source.peer, after_cadence, deadline)};
    BOOST_REQUIRE(second);
    BOOST_CHECK(second->hash == complete[1].hash);
    const auto second_authorization{
        tracker.BeginResponse(page_source.peer, *second, after_cadence)};
    BOOST_REQUIRE(second_authorization);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *second_authorization,
        GovernanceRequestTracker::ResponseOutcome::VALID_SUPERSEDED,
        after_cadence));

    const auto result{tracker.TakePageResult(after_cadence)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->success);
    BOOST_REQUIRE(result->response);
    BOOST_CHECK_EQUAL(result->response->status, GOVERNANCE_PAGE_OK);
    BOOST_CHECK_EQUAL(result->response->total_count, 3U);
    BOOST_REQUIRE_EQUAL(result->response->inventory.size(), 2U);
    BOOST_CHECK(tracker.HasActivePageSession());
    BOOST_CHECK_EQUAL(tracker.Size(), 31U);
    BOOST_CHECK(!tracker.Request(sources[1].peer, after_cadence, deadline));

    const auto reused_nonce{MakeGovernancePageRequest(
        {}, complete[1].hash, *view, request.nonce)};
    BOOST_CHECK(!tracker.BeginPage(
        reused_nonce, after_cadence, deadline));
    const auto continuation{MakeGovernancePageRequest(
        {}, complete[1].hash, *view, 12)};
    BOOST_CHECK(tracker.BeginPage(
        continuation, after_cadence, deadline));
    tracker.EndPageSession();
    BOOST_CHECK(!tracker.HasActivePageSession());
    BOOST_CHECK_EQUAL(tracker.Size(), 29U);
    BOOST_CHECK(tracker.Announce(
        page_source,
        CInv{MSG_GOVERNANCE_OBJECT, uint256{250}}));

    GovernanceRequestTracker malformed;
    BOOST_REQUIRE(malformed.BeginPageSession(page_source, now));
    BOOST_REQUIRE(malformed.BeginPage(request, now, deadline));
    auto wrong_scope{response};
    wrong_scope.scope_hash = uint256{1};
    BOOST_CHECK(!malformed.ReceivedPage(
        page_source.peer, wrong_scope, {}, now));
    BOOST_CHECK(malformed.RejectPage(
        page_source.peer, wrong_scope, now));
    const auto malformed_result{malformed.TakePageResult(now)};
    BOOST_REQUIRE(malformed_result);
    BOOST_CHECK(!malformed_result->success);
    BOOST_CHECK(!malformed.BeginPage(request, now, deadline));
}

BOOST_AUTO_TEST_CASE(pq_governance_page_semantics_retry_and_deadline)
{
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source source_a{200, 2000, {}, true};
    const GovernanceRequestTracker::Source source_b{201, 2001, {}, true};
    const uint256 parent{uint256S("5000")};
    const std::vector<CInv> inventory{
        {MSG_GOVERNANCE_OBJECT_VOTE, uint256S("5001")},
        {MSG_GOVERNANCE_OBJECT_VOTE, uint256S("5002")}};
    const auto view{ComputeGovernancePageViewHash(parent, inventory)};
    BOOST_REQUIRE(view);
    const auto now{std::chrono::seconds{200}};
    const auto deadline{now + std::chrono::seconds{30}};

    BOOST_REQUIRE(tracker.BeginPageSession(source_a, now));
    auto request{MakeGovernancePageRequest(parent, {}, {}, 21)};
    BOOST_REQUIRE(tracker.BeginPage(request, now, deadline));
    auto response{MakeGovernancePageResponse(
        request, inventory, true, *view, 2)};
    BOOST_REQUIRE(tracker.ReceivedPage(
        source_a.peer, response, inventory, now));
    const auto first{tracker.Request(source_a.peer, now, deadline)};
    BOOST_REQUIRE(first);
    const auto authorization{
        tracker.BeginResponse(source_a.peer, *first, now)};
    BOOST_REQUIRE(authorization);
    BOOST_CHECK(authorization->page_required);
    BOOST_CHECK(authorization->page_scope == parent);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *authorization,
        GovernanceRequestTracker::ResponseOutcome::PAYLOAD_INVALID,
        now));
    const auto failed{tracker.TakePageResult(now)};
    BOOST_REQUIRE(failed);
    BOOST_CHECK(!failed->success);
    BOOST_REQUIRE(failed->response);
    BOOST_CHECK(failed->request.cursor.IsNull());
    BOOST_CHECK(!tracker.SetPageSessionSource(
        source_a,
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL));

    const auto retry_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_REQUIRE(tracker.SetPageSessionSource(source_b, retry_time));
    request.nonce++;
    response = MakeGovernancePageResponse(
        request, inventory, true, *view, 2);
    BOOST_REQUIRE(tracker.BeginPage(request, retry_time, deadline));
    BOOST_REQUIRE(tracker.ReceivedPage(
        source_b.peer, response, inventory, retry_time));
    const uint256 authenticated{uint256S("b001")};
    tracker.UpdateSourceIdentity(
        source_b.peer, authenticated, source_b.keyed_net_group, true);
    const auto retry_first{
        tracker.Request(source_b.peer, retry_time, deadline)};
    BOOST_REQUIRE(retry_first);
    const auto migrated{
        tracker.BeginResponse(source_b.peer, *retry_first, retry_time)};
    BOOST_REQUIRE(migrated);
    BOOST_CHECK(migrated->page_source.authenticated_pro_tx == authenticated);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *migrated,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        retry_time));
    const auto second_time{
        retry_time + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto retry_second{
        tracker.Request(source_b.peer, second_time, deadline)};
    BOOST_REQUIRE(retry_second);
    const auto migrated_second{
        tracker.BeginResponse(source_b.peer, *retry_second, second_time)};
    BOOST_REQUIRE(migrated_second);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *migrated_second,
        GovernanceRequestTracker::ResponseOutcome::VALID_SUPERSEDED,
        second_time));
    const auto succeeded{tracker.TakePageResult(second_time)};
    BOOST_REQUIRE(succeeded);
    BOOST_CHECK(succeeded->success);
    BOOST_CHECK(succeeded->source.authenticated_pro_tx == authenticated);
    tracker.EndPageSession();

    GovernanceRequestTracker deadline_tracker;
    BOOST_REQUIRE(deadline_tracker.BeginPageSession(source_a, now));
    const auto short_deadline{now + std::chrono::seconds{1}};
    request = MakeGovernancePageRequest(parent, {}, {}, 31);
    response = MakeGovernancePageResponse(
        request, inventory, true, *view, 2);
    BOOST_REQUIRE(deadline_tracker.BeginPage(
        request, now, short_deadline));
    BOOST_REQUIRE(deadline_tracker.ReceivedPage(
        source_a.peer, response, inventory, now));
    BOOST_REQUIRE(deadline_tracker.Request(
        source_a.peer, now, now + std::chrono::seconds{30}));
    const auto expired{deadline_tracker.TakePageResult(short_deadline)};
    BOOST_REQUIRE(expired);
    BOOST_CHECK(!expired->success);
    BOOST_CHECK(deadline_tracker.HasActivePageSession());
}

BOOST_AUTO_TEST_CASE(
    pq_governance_page_session_live_relay_escape_is_bounded)
{
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source page_source{
        205, 2050, uint256S("c001"), true};
    const GovernanceRequestTracker::Source first_relay{
        206, 2060, uint256S("c002"), true};
    const GovernanceRequestTracker::Source second_relay{
        207, 2070, uint256S("c003"), true};
    const GovernanceRequestTracker::Source third_relay{
        208, 2080, uint256S("c004"), true};
    const CInv known_object{
        MSG_GOVERNANCE_OBJECT, uint256S("c010")};
    const CInv live_trigger{
        MSG_GOVERNANCE_OBJECT, uint256S("c011")};
    const CInv queued_vote{
        MSG_GOVERNANCE_OBJECT_VOTE, uint256S("c012")};
    const CInv exact_object{
        MSG_GOVERNANCE_OBJECT, uint256S("c013")};
    const CInv priority_object{
        MSG_GOVERNANCE_OBJECT, uint256S("c014")};
    const CInv competing_trigger{
        MSG_GOVERNANCE_OBJECT, uint256S("c015")};
    const auto now{std::chrono::seconds{250}};
    const auto deadline{now + std::chrono::seconds{30}};

    BOOST_REQUIRE(tracker.BeginPageSession(page_source, now));
    auto request{MakeGovernancePageRequest({}, {}, {}, 35)};
    BOOST_REQUIRE(tracker.BeginPage(request, now, deadline));
    const auto known_view{ComputeGovernancePageViewHash(
        {}, std::vector<CInv>{known_object})};
    BOOST_REQUIRE(known_view);
    const auto all_known{MakeGovernancePageResponse(
        request, {known_object}, /*done=*/true, *known_view,
        /*total_count=*/1)};
    BOOST_REQUIRE(tracker.ReceivedPage(
        page_source.peer, all_known, {}, now));
    const auto first_result{tracker.TakePageResult(now)};
    BOOST_REQUIRE(first_result);
    BOOST_CHECK(first_result->success);

    // An all-known terminal page must not suppress a trigger announced while
    // the session waits for its next cursor request.
    BOOST_REQUIRE(tracker.Announce(first_relay, live_trigger));
    const auto terminal_escape{
        tracker.Request(first_relay.peer, now, deadline)};
    BOOST_REQUIRE(terminal_escape);
    BOOST_CHECK(*terminal_escape == live_trigger);
    const auto terminal_authorization{tracker.BeginResponse(
        first_relay.peer, *terminal_escape, now)};
    BOOST_REQUIRE(terminal_authorization);
    BOOST_CHECK(!terminal_authorization->page_required);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *terminal_authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        now));

    const auto second_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_REQUIRE(tracker.Announce(second_relay, queued_vote));
    BOOST_CHECK(!tracker.Request(
        second_relay.peer, second_time, deadline));

    // A successfully begun continuation replenishes exactly one escape. Its
    // immutable ordinary attribution must survive a GOVPAGE arriving before
    // semantic validation completes.
    ++request.nonce;
    BOOST_REQUIRE(tracker.BeginPage(request, second_time, deadline));
    const auto metadata_escape{
        tracker.Request(second_relay.peer, second_time, deadline)};
    BOOST_REQUIRE(metadata_escape);
    BOOST_CHECK(*metadata_escape == queued_vote);

    const auto exact_view{ComputeGovernancePageViewHash(
        {}, std::vector<CInv>{exact_object})};
    BOOST_REQUIRE(exact_view);
    const auto exact_response{MakeGovernancePageResponse(
        request, {exact_object}, /*done=*/true, *exact_view,
        /*total_count=*/1)};
    BOOST_REQUIRE(tracker.ReceivedPage(
        page_source.peer, exact_response, {exact_object}, second_time));
    const auto ordinary_authorization{tracker.BeginResponse(
        second_relay.peer, *metadata_escape, second_time)};
    BOOST_REQUIRE(ordinary_authorization);
    BOOST_CHECK(!ordinary_authorization->page_required);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *ordinary_authorization,
        GovernanceRequestTracker::ResponseOutcome::PAYLOAD_INVALID,
        second_time));
    BOOST_CHECK(!tracker.TakePageResult(second_time));

    const auto exact_time{
        second_time + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto exact_request{
        tracker.Request(page_source.peer, exact_time, deadline)};
    BOOST_REQUIRE(exact_request);
    BOOST_CHECK(*exact_request == exact_object);
    const auto exact_authorization{tracker.BeginResponse(
        page_source.peer, *exact_request, exact_time)};
    BOOST_REQUIRE(exact_authorization);
    BOOST_CHECK(exact_authorization->page_required);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *exact_authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        exact_time));
    const auto exact_result{tracker.TakePageResult(exact_time)};
    BOOST_REQUIRE(exact_result);
    BOOST_CHECK(exact_result->success);

    // With a fresh credit still available, a required page payload must win
    // over ordinary inventory. The untouched credit becomes usable as soon as
    // the terminal page is committed.
    const auto priority_time{
        exact_time + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    ++request.nonce;
    BOOST_REQUIRE(tracker.BeginPage(request, priority_time, deadline));
    const auto priority_view{ComputeGovernancePageViewHash(
        {}, std::vector<CInv>{priority_object})};
    BOOST_REQUIRE(priority_view);
    const auto priority_response{MakeGovernancePageResponse(
        request, {priority_object}, /*done=*/true, *priority_view,
        /*total_count=*/1)};
    BOOST_REQUIRE(tracker.ReceivedPage(
        page_source.peer, priority_response, {priority_object},
        priority_time));
    BOOST_REQUIRE(tracker.Announce(third_relay, competing_trigger));
    BOOST_CHECK(!tracker.Request(
        third_relay.peer, priority_time, deadline));
    const auto priority_request{
        tracker.Request(page_source.peer, priority_time, deadline)};
    BOOST_REQUIRE(priority_request);
    BOOST_CHECK(*priority_request == priority_object);
    const auto priority_authorization{tracker.BeginResponse(
        page_source.peer, *priority_request, priority_time)};
    BOOST_REQUIRE(priority_authorization);
    BOOST_CHECK(priority_authorization->page_required);
    BOOST_REQUIRE(tracker.CompleteResponse(
        *priority_authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        priority_time));
    const auto priority_result{tracker.TakePageResult(priority_time)};
    BOOST_REQUIRE(priority_result);
    BOOST_CHECK(priority_result->success);

    const auto post_terminal_time{
        priority_time +
        GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    const auto post_terminal_escape{tracker.Request(
        third_relay.peer, post_terminal_time, deadline)};
    BOOST_REQUIRE(post_terminal_escape);
    BOOST_CHECK(*post_terminal_escape == competing_trigger);
    tracker.EndPageSession();

    GovernanceRequestTracker current_source_tracker;
    BOOST_REQUIRE(current_source_tracker.BeginPageSession(
        page_source, now));
    BOOST_REQUIRE(current_source_tracker.BeginPage(
        request, now, deadline));
    BOOST_REQUIRE(current_source_tracker.Announce(
        page_source, live_trigger));
    const auto current_source_escape{current_source_tracker.Request(
        page_source.peer, now, deadline)};
    BOOST_REQUIRE(current_source_escape);
    BOOST_CHECK(*current_source_escape == live_trigger);
    const auto current_source_authorization{
        current_source_tracker.BeginResponse(
            page_source.peer, *current_source_escape, now)};
    BOOST_REQUIRE(current_source_authorization);
    BOOST_CHECK(!current_source_authorization->page_required);
    BOOST_REQUIRE(current_source_tracker.CompleteResponse(
        *current_source_authorization,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        now));
    current_source_tracker.EndPageSession();
}

BOOST_AUTO_TEST_CASE(pq_governance_page_response_attempt_is_aba_safe)
{
    GovernanceRequestTracker tracker;
    const GovernanceRequestTracker::Source source{210, 2100, {}, true};
    const CInv object{MSG_GOVERNANCE_OBJECT, uint256S("6001")};
    const std::vector<CInv> inventory{object};
    const auto view{ComputeGovernancePageViewHash({}, inventory)};
    BOOST_REQUIRE(view);
    const auto now{std::chrono::seconds{300}};
    const auto deadline{now + std::chrono::seconds{30}};

    BOOST_REQUIRE(tracker.BeginPageSession(source, now));
    auto request{MakeGovernancePageRequest({}, {}, {}, 41)};
    auto response{MakeGovernancePageResponse(
        request, inventory, true, *view, 1)};
    BOOST_REQUIRE(tracker.BeginPage(request, now, deadline));
    BOOST_REQUIRE(tracker.ReceivedPage(
        source.peer, response, inventory, now));
    BOOST_REQUIRE(tracker.Request(source.peer, now, deadline));
    const auto stale{
        tracker.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(stale);

    tracker.EndPageSession();
    const auto retry_time{
        now + GovernanceRequestTracker::MIN_VERIFICATION_INTERVAL};
    BOOST_REQUIRE(tracker.BeginPageSession(source, retry_time));
    request.nonce++;
    response = MakeGovernancePageResponse(
        request, inventory, true, *view, 1);
    BOOST_REQUIRE(tracker.BeginPage(request, retry_time, deadline));
    BOOST_REQUIRE(tracker.ReceivedPage(
        source.peer, response, inventory, retry_time));
    BOOST_REQUIRE(tracker.Request(source.peer, retry_time, deadline));
    const auto current{
        tracker.BeginResponse(source.peer, object, retry_time)};
    BOOST_REQUIRE(current);
    BOOST_CHECK_NE(stale->request_id, current->request_id);
    BOOST_CHECK(!tracker.CompleteResponse(
        *stale,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        retry_time));
    BOOST_CHECK(tracker.IsRequested(source.peer, object));
    BOOST_REQUIRE(tracker.CompleteResponse(
        *current,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        retry_time));
    const auto result{tracker.TakePageResult(retry_time)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->success);
    tracker.EndPageSession();
}

BOOST_AUTO_TEST_CASE(pq_governance_page_deadline_and_disconnect_are_terminal)
{
    const GovernanceRequestTracker::Source source{220, 2200, {}, true};
    const CInv object{MSG_GOVERNANCE_OBJECT, uint256S("7001")};
    const std::vector<CInv> inventory{object};
    const auto view{ComputeGovernancePageViewHash({}, inventory)};
    BOOST_REQUIRE(view);
    const auto now{std::chrono::seconds{400}};
    const auto deadline{now + std::chrono::seconds{1}};
    const auto request{MakeGovernancePageRequest({}, {}, {}, 51)};
    const auto response{MakeGovernancePageResponse(
        request, inventory, true, *view, 1)};

    GovernanceRequestTracker completed;
    BOOST_REQUIRE(completed.BeginPageSession(source, now));
    BOOST_REQUIRE(completed.BeginPage(request, now, deadline));
    BOOST_REQUIRE(completed.ReceivedPage(
        source.peer, response, inventory, now));
    BOOST_REQUIRE(completed.Request(source.peer, now, deadline));
    const auto accepted{completed.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(accepted);
    BOOST_REQUIRE(completed.CompleteResponse(
        *accepted,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        now));
    const auto polled_late{
        completed.TakePageResult(deadline + std::chrono::seconds{1})};
    BOOST_REQUIRE(polled_late);
    BOOST_CHECK(polled_late->success);

    GovernanceRequestTracker late;
    BOOST_REQUIRE(late.BeginPageSession(source, now));
    BOOST_REQUIRE(late.BeginPage(request, now, deadline));
    BOOST_REQUIRE(late.ReceivedPage(
        source.peer, response, inventory, now));
    BOOST_REQUIRE(late.Request(source.peer, now, deadline));
    const auto delivered{late.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(delivered);
    BOOST_REQUIRE(late.CompleteResponse(
        *delivered,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        deadline));
    const auto rejected_late{late.TakePageResult(deadline)};
    BOOST_REQUIRE(rejected_late);
    BOOST_CHECK(!rejected_late->success);

    GovernanceRequestTracker late_invalid;
    BOOST_REQUIRE(late_invalid.BeginPageSession(source, now));
    BOOST_REQUIRE(late_invalid.BeginPage(request, now, deadline));
    BOOST_REQUIRE(late_invalid.ReceivedPage(
        source.peer, response, inventory, now));
    BOOST_REQUIRE(late_invalid.Request(source.peer, now, deadline));
    const auto invalid_delivery{
        late_invalid.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(invalid_delivery);
    BOOST_REQUIRE(late_invalid.CompleteResponse(
        *invalid_delivery,
        GovernanceRequestTracker::ResponseOutcome::PAYLOAD_INVALID,
        deadline));
    const auto invalid_late_result{
        late_invalid.TakePageResult(deadline)};
    BOOST_REQUIRE(invalid_late_result);
    BOOST_CHECK(!invalid_late_result->success);
    late_invalid.EndPageSession();
    BOOST_CHECK(!late_invalid.BeginPageSession(source, deadline));

    GovernanceRequestTracker disconnected;
    BOOST_REQUIRE(disconnected.BeginPageSession(source, now));
    BOOST_CHECK_EQUAL(disconnected.Size(), 2U);
    disconnected.DisconnectedPeer(source.peer, now);
    BOOST_CHECK_EQUAL(disconnected.Size(), 0U);
    BOOST_CHECK(disconnected.HasActivePageSession());
    disconnected.EndPageSession();

    GovernanceRequestTracker disconnected_metadata;
    const uint256 disconnected_identity{uint256S("7003")};
    const GovernanceRequestTracker::Source authenticated_source{
        221, source.keyed_net_group, disconnected_identity, true};
    BOOST_REQUIRE(disconnected_metadata.BeginPageSession(
        authenticated_source, now));
    BOOST_REQUIRE(disconnected_metadata.BeginPage(
        request, now, deadline));
    disconnected_metadata.DisconnectedPeer(
        authenticated_source.peer, now);
    const auto disconnected_result{
        disconnected_metadata.TakePageResult(now)};
    BOOST_REQUIRE(disconnected_result);
    BOOST_CHECK(!disconnected_result->success);
    disconnected_metadata.EndPageSession();

    const GovernanceRequestTracker::Source authenticated_reconnect{
        222, source.keyed_net_group + 1, disconnected_identity, true};
    const GovernanceRequestTracker::Source disconnected_sibling{
        223, source.keyed_net_group, {}, true};
    const CInv disconnected_retry{
        MSG_GOVERNANCE_OBJECT, uint256S("7004")};
    const CInv disconnected_sibling_inv{
        MSG_GOVERNANCE_OBJECT, uint256S("7005")};
    BOOST_REQUIRE(disconnected_metadata.Announce(
        authenticated_reconnect, disconnected_retry));
    BOOST_REQUIRE(disconnected_metadata.Announce(
        disconnected_sibling, disconnected_sibling_inv));
    BOOST_CHECK(!disconnected_metadata.Request(
        authenticated_reconnect.peer, now, deadline));
    const auto disconnected_sibling_request{
        disconnected_metadata.Request(
            disconnected_sibling.peer, now, deadline)};
    BOOST_REQUIRE(disconnected_sibling_request);
    BOOST_CHECK(
        disconnected_sibling_request->hash ==
        disconnected_sibling_inv.hash);

    GovernanceRequestTracker interrupted;
    const std::vector<CInv> two_items{
        object,
        {MSG_GOVERNANCE_OBJECT, uint256S("7002")}};
    const auto two_view{ComputeGovernancePageViewHash({}, two_items)};
    BOOST_REQUIRE(two_view);
    const auto two_response{MakeGovernancePageResponse(
        request, two_items, true, *two_view, 2)};
    BOOST_REQUIRE(interrupted.BeginPageSession(source, now));
    BOOST_REQUIRE(interrupted.BeginPage(request, now, deadline));
    BOOST_REQUIRE(interrupted.ReceivedPage(
        source.peer, two_response, two_items, now));
    BOOST_REQUIRE(interrupted.Request(source.peer, now, deadline));
    const auto interrupted_delivery{
        interrupted.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(interrupted_delivery);
    interrupted.DisconnectedPeer(source.peer, now);
    BOOST_REQUIRE(interrupted.CompleteResponse(
        *interrupted_delivery,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        now));
    const auto interrupted_result{interrupted.TakePageResult(now)};
    BOOST_REQUIRE(interrupted_result);
    BOOST_CHECK(!interrupted_result->success);
    interrupted.EndPageSession();
    const GovernanceRequestTracker::Source reconnected{
        source.peer + 1, source.keyed_net_group, {}, true};
    BOOST_CHECK(!interrupted.BeginPageSession(reconnected, now));

    GovernanceRequestTracker final_item;
    BOOST_REQUIRE(final_item.BeginPageSession(source, now));
    BOOST_REQUIRE(final_item.BeginPage(request, now, deadline));
    BOOST_REQUIRE(final_item.ReceivedPage(
        source.peer, response, inventory, now));
    BOOST_REQUIRE(final_item.Request(source.peer, now, deadline));
    const auto final_delivery{
        final_item.BeginResponse(source.peer, object, now)};
    BOOST_REQUIRE(final_delivery);
    final_item.DisconnectedPeer(source.peer, now);
    BOOST_REQUIRE(final_item.CompleteResponse(
        *final_delivery,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        now));
    const auto final_result{final_item.TakePageResult(now)};
    BOOST_REQUIRE(final_result);
    BOOST_CHECK(final_result->success);
    final_item.EndPageSession();
    BOOST_CHECK(final_item.BeginPageSession(reconnected, now));

    GovernanceRequestTracker slow_transfer;
    const auto transfer_deadline{
        now + GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    GovernanceRequestTracker silent_response;
    BOOST_REQUIRE(silent_response.BeginPageSession(source, now));
    BOOST_REQUIRE(silent_response.BeginPage(
        request, now, transfer_deadline));
    const auto silent_result{silent_response.TakePageResult(
        now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT)};
    BOOST_REQUIRE(silent_result);
    BOOST_CHECK(!silent_result->success);

    BOOST_REQUIRE(slow_transfer.BeginPageSession(source, now));
    BOOST_REQUIRE(slow_transfer.BeginPage(
        request, now, transfer_deadline));
    BOOST_REQUIRE(slow_transfer.ReceivedPage(
        source.peer, response, inventory, now));
    std::optional<GovernanceRequestTracker::InFlight> expired;
    BOOST_REQUIRE(slow_transfer.Request(
        source.peer, now, now + std::chrono::seconds{30}, &expired));
    const auto after_legacy_timeout{
        now + std::chrono::seconds{31}};
    BOOST_CHECK(!slow_transfer.Request(
        source.peer, after_legacy_timeout,
        after_legacy_timeout + std::chrono::seconds{30}, &expired));
    BOOST_CHECK(!expired);
    const auto slow_delivery{slow_transfer.BeginResponse(
        source.peer, object, after_legacy_timeout)};
    BOOST_REQUIRE(slow_delivery);
    BOOST_REQUIRE(slow_transfer.CompleteResponse(
        *slow_delivery,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        after_legacy_timeout));
    const auto slow_result{
        slow_transfer.TakePageResult(after_legacy_timeout)};
    BOOST_REQUIRE(slow_result);
    BOOST_CHECK(slow_result->success);
    slow_transfer.EndPageSession();

    GovernanceRequestTracker delayed_response;
    const auto full_request_deadline{
        now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT +
        GOVERNANCE_PAGE_TRANSFER_TIMEOUT};
    const auto response_arrival{
        now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT - std::chrono::seconds{1}};
    const auto payload_arrival{
        full_request_deadline - std::chrono::seconds{2}};
    BOOST_REQUIRE(delayed_response.BeginPageSession(source, now));
    BOOST_REQUIRE(delayed_response.BeginPage(
        request, now, full_request_deadline));
    BOOST_REQUIRE(delayed_response.ReceivedPage(
        source.peer, response, inventory, response_arrival));
    BOOST_REQUIRE(delayed_response.Request(
        source.peer, response_arrival, full_request_deadline));
    const auto delayed_delivery{delayed_response.BeginResponse(
        source.peer, object, payload_arrival)};
    BOOST_REQUIRE(delayed_delivery);
    BOOST_REQUIRE(delayed_response.CompleteResponse(
        *delayed_delivery,
        GovernanceRequestTracker::ResponseOutcome::
            VALID_OR_EXACT_KNOWN,
        payload_arrival));
    const auto delayed_result{
        delayed_response.TakePageResult(payload_arrival)};
    BOOST_REQUIRE(delayed_result);
    BOOST_CHECK(delayed_result->success);
    delayed_response.EndPageSession();
}

// SYSCOIN: end bounded PQ ChainLock and governance relay admission tests.

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    addr = LookupHost("0.0.0.0", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "0.0.0.0");

    // IPv4, INADDR_NONE
    addr = LookupHost("255.255.255.255", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "255.255.255.255");

    // IPv4, casual
    addr = LookupHost("12.34.56.78", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "12.34.56.78");

    // IPv6, in6addr_any
    addr = LookupHost("::", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "::");

    // IPv6, casual
    addr = LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    addr = LookupHost(scoped_addr, false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
    addr = LookupHost(link_local + "%0", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), link_local);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        const std::optional<CNetAddr> net_addr{LookupHost(input_address, false)};
        BOOST_REQUIRE(net_addr.value().IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.value().ToStringAddr(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V1_NETWORK};

    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << WithParams(ser_params, addr);
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{ParseHex(
        "02"                                  // network type (IPv6)
        "10"                                  // address length
        "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd + sha256("bitcoin")[0:5] +
                                              // sha256(name)[0:10]
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << Span{ParseHex("04"                               // network type (TORv3)
                       "20"                               // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f"
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"             // network type (unknown)
                       "fe00000002"     // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> WithParams(ser_params, addr), std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> WithParams(ser_params, addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CAddress{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(g_reachable_nets.Contains(NET_CJDNS));

    g_reachable_nets.Remove(NET_IPV4);
    g_reachable_nets.Remove(NET_IPV6);
    g_reachable_nets.Remove(NET_ONION);
    g_reachable_nets.Remove(NET_I2P);
    g_reachable_nets.Remove(NET_CJDNS);

    BOOST_CHECK(!g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_CJDNS));

    g_reachable_nets.Add(NET_IPV4);
    g_reachable_nets.Add(NET_IPV6);
    g_reachable_nets.Add(NET_ONION);
    g_reachable_nets.Add(NET_I2P);
    g_reachable_nets.Add(NET_CJDNS);

    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(g_reachable_nets.Contains(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    // Should be reachable by default.
    BOOST_CHECK(g_reachable_nets.Contains(NET_UNROUTABLE));
    BOOST_CHECK(g_reachable_nets.Contains(NET_INTERNAL));

    g_reachable_nets.RemoveAll();

    BOOST_CHECK(!g_reachable_nets.Contains(NET_UNROUTABLE));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_INTERNAL));

    g_reachable_nets.Add(NET_IPV4);
    g_reachable_nets.Add(NET_IPV6);
    g_reachable_nets.Add(NET_ONION);
    g_reachable_nets.Add(NET_I2P);
    g_reachable_nets.Add(NET_CJDNS);
    g_reachable_nets.Add(NET_UNROUTABLE);
    g_reachable_nets.Add(NET_INTERNAL);
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    g_reachable_nets.Add(NET_IPV4);
    BOOST_CHECK(g_reachable_nets.Contains(addr));

    g_reachable_nets.Remove(NET_IPV4);
    BOOST_CHECK(!g_reachable_nets.Contains(addr));

    g_reachable_nets.Add(NET_IPV4); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    g_reachable_nets.Add(NET_IPV4);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    // SYSCOIN: begin PQ VERSION transcript fixture state.
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/3,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};
    // SYSCOIN: end PQ VERSION transcript fixture state.

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};
    const CNetMsgMaker msg_maker{PROTOCOL_VERSION};

    // Force ChainstateManager::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    auto& chainman = static_cast<TestChainstateManager&>(*m_node.chainman);
    chainman.JumpOutOfIbd();

    m_node.peerman->InitializeNode(peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    // SYSCOIN: begin PQ VERSION transcript adaptation.
    CMNAuthVersionData mnauth_version;
    mnauth_version.cookie = uint256::ONEV;
    const uint256 mnauth_challenge{uint256::TWOV};
    const auto msg_version = msg_maker.Make(
        NetMsgType::VERSION, PROTOCOL_VERSION, services, time,
        services, CNetAddr::V1(peer_us),
        services, CNetAddr::V1(CService{}),
        uint64_t{1}, std::string{}, int32_t{0}, true,
        mnauth_challenge, false, mnauth_version);
    CDataStream msg_version_stream{msg_version.data, SER_NETWORK, PROTOCOL_VERSION};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);
    BOOST_REQUIRE(!peer.fDisconnect);
    BOOST_CHECK_EQUAL(peer.nVersion.load(), PROTOCOL_VERSION);
    BOOST_CHECK(peer.GetMNAuthConnectionData().has_remote);
    // SYSCOIN: end PQ VERSION transcript adaptation.

    const auto msg_verack = msg_maker.Make(NetMsgType::VERACK);
    CDataStream msg_verack_stream{msg_verack.data, SER_NETWORK, PROTOCOL_VERSION};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);
    // SYSCOIN: PQ MNAUTH setup must not break the Bitcoin handshake fixture.
    BOOST_REQUIRE(peer.fSuccessfullyConnected);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        Span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            DataStream s{data};
            std::vector<CAddress> addresses;

            s >> CAddress::V1_NETWORK(addresses);

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    m_node.peerman->SendMessages(&peer);

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainman.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the internal state
    // in timedata.cpp and later confuses the test "timedata_tests/addtimedata". Thus reset
    // that state as it was before our test was run.
    TestOnlyResetTimeData();
}


BOOST_AUTO_TEST_CASE(advertise_local_address)
{
    auto CreatePeer = [](const CAddress& addr) {
        return std::make_unique<CNode>(/*id=*/0,
                                       /*sock=*/nullptr,
                                       addr,
                                       /*nKeyedNetGroupIn=*/0,
                                       /*nLocalHostNonceIn=*/0,
                                       CAddress{},
                                       /*pszDest=*/std::string{},
                                       ConnectionType::OUTBOUND_FULL_RELAY,
                                       /*inbound_onion=*/false);
    };
    g_reachable_nets.Add(NET_CJDNS);

    CAddress addr_ipv4{Lookup("1.2.3.4", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv4.IsValid());
    BOOST_REQUIRE(addr_ipv4.IsIPv4());

    CAddress addr_ipv6{Lookup("1122:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv6.IsValid());
    BOOST_REQUIRE(addr_ipv6.IsIPv6());

    CAddress addr_ipv6_tunnel{Lookup("2002:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv6_tunnel.IsValid());
    BOOST_REQUIRE(addr_ipv6_tunnel.IsIPv6());
    BOOST_REQUIRE(addr_ipv6_tunnel.IsRFC3964());

    CAddress addr_teredo{Lookup("2001:0000:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_teredo.IsValid());
    BOOST_REQUIRE(addr_teredo.IsIPv6());
    BOOST_REQUIRE(addr_teredo.IsRFC4380());

    CAddress addr_onion;
    BOOST_REQUIRE(addr_onion.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    BOOST_REQUIRE(addr_onion.IsValid());
    BOOST_REQUIRE(addr_onion.IsTor());

    CAddress addr_i2p;
    BOOST_REQUIRE(addr_i2p.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p"));
    BOOST_REQUIRE(addr_i2p.IsValid());
    BOOST_REQUIRE(addr_i2p.IsI2P());

    CService service_cjdns{Lookup("fc00:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    CAddress addr_cjdns{MaybeFlipIPv6toCJDNS(service_cjdns), NODE_NONE};
    BOOST_REQUIRE(addr_cjdns.IsValid());
    BOOST_REQUIRE(addr_cjdns.IsCJDNS());

    const auto peer_ipv4{CreatePeer(addr_ipv4)};
    const auto peer_ipv6{CreatePeer(addr_ipv6)};
    const auto peer_ipv6_tunnel{CreatePeer(addr_ipv6_tunnel)};
    const auto peer_teredo{CreatePeer(addr_teredo)};
    const auto peer_onion{CreatePeer(addr_onion)};
    const auto peer_i2p{CreatePeer(addr_i2p)};
    const auto peer_cjdns{CreatePeer(addr_cjdns)};

    // one local clearnet address - advertise to all but privacy peers
    AddLocal(addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv4) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6_tunnel) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_teredo) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_cjdns) == addr_ipv4);
    BOOST_CHECK(!GetLocalAddress(*peer_onion).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_i2p).IsValid());
    RemoveLocal(addr_ipv4);

    // local privacy addresses - don't advertise to clearnet peers
    AddLocal(addr_onion);
    AddLocal(addr_i2p);
    BOOST_CHECK(!GetLocalAddress(*peer_ipv4).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_ipv6).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_ipv6_tunnel).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_teredo).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_cjdns).IsValid());
    BOOST_CHECK(GetLocalAddress(*peer_onion) == addr_onion);
    BOOST_CHECK(GetLocalAddress(*peer_i2p) == addr_i2p);
    RemoveLocal(addr_onion);
    RemoveLocal(addr_i2p);

    // local addresses from all networks
    AddLocal(addr_ipv4);
    AddLocal(addr_ipv6);
    AddLocal(addr_ipv6_tunnel);
    AddLocal(addr_teredo);
    AddLocal(addr_onion);
    AddLocal(addr_i2p);
    AddLocal(addr_cjdns);
    BOOST_CHECK(GetLocalAddress(*peer_ipv4) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6) == addr_ipv6);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6_tunnel) == addr_ipv6);
    BOOST_CHECK(GetLocalAddress(*peer_teredo) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_onion) == addr_onion);
    BOOST_CHECK(GetLocalAddress(*peer_i2p) == addr_i2p);
    BOOST_CHECK(GetLocalAddress(*peer_cjdns) == addr_cjdns);
    RemoveLocal(addr_ipv4);
    RemoveLocal(addr_ipv6);
    RemoveLocal(addr_ipv6_tunnel);
    RemoveLocal(addr_teredo);
    RemoveLocal(addr_onion);
    RemoveLocal(addr_i2p);
    RemoveLocal(addr_cjdns);
}

namespace {

CKey GenerateRandomTestKey() noexcept
{
    CKey key;
    uint256 key_data = InsecureRand256();
    key.Set(key_data.begin(), key_data.end(), true);
    return key;
}

/** A class for scenario-based tests of V2Transport
 *
 * Each V2TransportTester encapsulates a V2Transport (the one being tested), and can be told to
 * interact with it. To do so, it also encapsulates a BIP324Cipher to act as the other side. A
 * second V2Transport is not used, as doing so would not permit scenarios that involve sending
 * invalid data, or ones using BIP324 features that are not implemented on the sending
 * side (like decoy packets).
 */
class V2TransportTester
{
    V2Transport m_transport; //!< V2Transport being tested
    BIP324Cipher m_cipher; //!< Cipher to help with the other side
    bool m_test_initiator; //!< Whether m_transport is the initiator (true) or responder (false)

    std::vector<uint8_t> m_sent_garbage; //!< The garbage we've sent to m_transport.
    std::vector<uint8_t> m_recv_garbage; //!< The garbage we've received from m_transport.
    std::vector<uint8_t> m_to_send; //!< Bytes we have queued up to send to m_transport.
    std::vector<uint8_t> m_received; //!< Bytes we have received from m_transport.
    std::deque<CSerializedNetMsg> m_msg_to_send; //!< Messages to be sent *by* m_transport to us.
    bool m_sent_aad{false};

public:
    /** Construct a tester object. test_initiator: whether the tested transport is initiator. */
    V2TransportTester(bool test_initiator) :
        m_transport(0, test_initiator, SER_NETWORK, INIT_PROTO_VERSION),
        m_cipher{GenerateRandomTestKey(), MakeByteSpan(InsecureRand256())},
        m_test_initiator(test_initiator) {}

    /** Data type returned by Interact:
     *
     * - std::nullopt: transport error occurred
     * - otherwise: a vector of
     *   - std::nullopt: invalid message received
     *   - otherwise: a CNetMessage retrieved
     */
    using InteractResult = std::optional<std::vector<std::optional<CNetMessage>>>;

    /** Send/receive scheduled/available bytes and messages.
     *
     * This is the only function that interacts with the transport being tested; everything else is
     * scheduling things done by Interact(), or processing things learned by it.
     */
    InteractResult Interact()
    {
        std::vector<std::optional<CNetMessage>> ret;
        while (true) {
            bool progress{false};
            // Send bytes from m_to_send to the transport.
            if (!m_to_send.empty()) {
                Span<const uint8_t> to_send = Span{m_to_send}.first(1 + InsecureRandRange(m_to_send.size()));
                size_t old_len = to_send.size();
                if (!m_transport.ReceivedBytes(to_send)) {
                    return std::nullopt; // transport error occurred
                }
                if (old_len != to_send.size()) {
                    progress = true;
                    m_to_send.erase(m_to_send.begin(), m_to_send.begin() + (old_len - to_send.size()));
                }
            }
            // Retrieve messages received by the transport.
            if (m_transport.ReceivedMessageComplete() && (!progress || InsecureRandBool())) {
                bool reject{false};
                auto msg = m_transport.GetReceivedMessage({}, reject);
                if (reject) {
                    ret.emplace_back(std::nullopt);
                } else {
                    ret.emplace_back(std::move(msg));
                }
                progress = true;
            }
            // Enqueue a message to be sent by the transport to us.
            if (!m_msg_to_send.empty() && (!progress || InsecureRandBool())) {
                if (m_transport.SetMessageToSend(m_msg_to_send.front())) {
                    m_msg_to_send.pop_front();
                    progress = true;
                }
            }
            // Receive bytes from the transport.
            const auto& [recv_bytes, _more, _msg_type] = m_transport.GetBytesToSend(!m_msg_to_send.empty());
            if (!recv_bytes.empty() && (!progress || InsecureRandBool())) {
                size_t to_receive = 1 + InsecureRandRange(recv_bytes.size());
                m_received.insert(m_received.end(), recv_bytes.begin(), recv_bytes.begin() + to_receive);
                progress = true;
                m_transport.MarkBytesSent(to_receive);
            }
            if (!progress) break;
        }
        return ret;
    }

    /** Expose the cipher. */
    BIP324Cipher& GetCipher() { return m_cipher; }

    /** Schedule bytes to be sent to the transport. */
    void Send(Span<const uint8_t> data)
    {
        m_to_send.insert(m_to_send.end(), data.begin(), data.end());
    }

    /** Send V1 version message header to the transport. */
    void SendV1Version(const MessageStartChars& magic)
    {
        CMessageHeader hdr(magic, "version", 126 + InsecureRandRange(11));
        CDataStream ser(SER_NETWORK, CLIENT_VERSION);
        ser << hdr;
        m_to_send.insert(m_to_send.end(), UCharCast(ser.data()), UCharCast(ser.data() + ser.size()));
    }

    /** Schedule bytes to be sent to the transport. */
    void Send(Span<const std::byte> data) { Send(MakeUCharSpan(data)); }

    /** Schedule our ellswift key to be sent to the transport. */
    void SendKey() { Send(m_cipher.GetOurPubKey()); }

    /** Schedule specified garbage to be sent to the transport. */
    void SendGarbage(Span<const uint8_t> garbage)
    {
        // Remember the specified garbage (so we can use it as AAD).
        m_sent_garbage.assign(garbage.begin(), garbage.end());
        // Schedule it for sending.
        Send(m_sent_garbage);
    }

    /** Schedule garbage (of specified length) to be sent to the transport. */
    void SendGarbage(size_t garbage_len)
    {
        // Generate random garbage and send it.
        SendGarbage(g_insecure_rand_ctx.randbytes<uint8_t>(garbage_len));
    }

    /** Schedule garbage (with valid random length) to be sent to the transport. */
    void SendGarbage()
    {
         SendGarbage(InsecureRandRange(V2Transport::MAX_GARBAGE_LEN + 1));
    }

    /** Schedule a message to be sent to us by the transport. */
    void AddMessage(std::string m_type, std::vector<uint8_t> payload)
    {
        CSerializedNetMsg msg;
        msg.m_type = std::move(m_type);
        msg.data = std::move(payload);
        m_msg_to_send.push_back(std::move(msg));
    }

    /** Expect ellswift key to have been received from transport and process it.
     *
     * Many other V2TransportTester functions cannot be called until after ReceiveKey() has been
     * called, as no encryption keys are set up before that point.
     */
    void ReceiveKey()
    {
        // When processing a key, enough bytes need to have been received already.
        BOOST_REQUIRE(m_received.size() >= EllSwiftPubKey::size());
        // Initialize the cipher using it (acting as the opposite side of the tested transport).
        m_cipher.Initialize(MakeByteSpan(m_received).first(EllSwiftPubKey::size()), !m_test_initiator);
        // Strip the processed bytes off the front of the receive buffer.
        m_received.erase(m_received.begin(), m_received.begin() + EllSwiftPubKey::size());
    }

    /** Schedule an encrypted packet with specified content/aad/ignore to be sent to transport
     *  (only after ReceiveKey). */
    void SendPacket(Span<const uint8_t> content, Span<const uint8_t> aad = {}, bool ignore = false)
    {
        // Use cipher to construct ciphertext.
        std::vector<std::byte> ciphertext;
        ciphertext.resize(content.size() + BIP324Cipher::EXPANSION);
        m_cipher.Encrypt(
            /*contents=*/MakeByteSpan(content),
            /*aad=*/MakeByteSpan(aad),
            /*ignore=*/ignore,
            /*output=*/ciphertext);
        // Schedule it for sending.
        Send(ciphertext);
    }

    /** Schedule garbage terminator to be sent to the transport (only after ReceiveKey). */
    void SendGarbageTerm()
    {
        // Schedule the garbage terminator to be sent.
        Send(m_cipher.GetSendGarbageTerminator());
    }

    /** Schedule version packet to be sent to the transport (only after ReceiveKey). */
    void SendVersion(Span<const uint8_t> version_data = {}, bool vers_ignore = false)
    {
        Span<const std::uint8_t> aad;
        // Set AAD to garbage only for first packet.
        if (!m_sent_aad) aad = m_sent_garbage;
        SendPacket(/*content=*/version_data, /*aad=*/aad, /*ignore=*/vers_ignore);
        m_sent_aad = true;
    }

    /** Expect a packet to have been received from transport, process it, and return its contents
     *  (only after ReceiveKey). Decoys are skipped. Optional associated authenticated data (AAD) is
     *  expected in the first received packet, no matter if that is a decoy or not. */
    std::vector<uint8_t> ReceivePacket(Span<const std::byte> aad = {})
    {
        std::vector<uint8_t> contents;
        // Loop as long as there are ignored packets that are to be skipped.
        while (true) {
            // When processing a packet, at least enough bytes for its length descriptor must be received.
            BOOST_REQUIRE(m_received.size() >= BIP324Cipher::LENGTH_LEN);
            // Decrypt the content length.
            size_t size = m_cipher.DecryptLength(MakeByteSpan(Span{m_received}.first(BIP324Cipher::LENGTH_LEN)));
            // Check that the full packet is in the receive buffer.
            BOOST_REQUIRE(m_received.size() >= size + BIP324Cipher::EXPANSION);
            // Decrypt the packet contents.
            contents.resize(size);
            bool ignore{false};
            bool ret = m_cipher.Decrypt(
                /*input=*/MakeByteSpan(
                    Span{m_received}.first(size + BIP324Cipher::EXPANSION).subspan(BIP324Cipher::LENGTH_LEN)),
                /*aad=*/aad,
                /*ignore=*/ignore,
                /*contents=*/MakeWritableByteSpan(contents));
            BOOST_CHECK(ret);
            // Don't expect AAD in further packets.
            aad = {};
            // Strip the processed packet's bytes off the front of the receive buffer.
            m_received.erase(m_received.begin(), m_received.begin() + size + BIP324Cipher::EXPANSION);
            // Stop if the ignore bit is not set on this packet.
            if (!ignore) break;
        }
        return contents;
    }

    /** Expect garbage and garbage terminator to have been received, and process them (only after
     *  ReceiveKey). */
    void ReceiveGarbage()
    {
        // Figure out the garbage length.
        size_t garblen;
        for (garblen = 0; garblen <= V2Transport::MAX_GARBAGE_LEN; ++garblen) {
            BOOST_REQUIRE(m_received.size() >= garblen + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
            auto term_span = MakeByteSpan(Span{m_received}.subspan(garblen, BIP324Cipher::GARBAGE_TERMINATOR_LEN));
            if (term_span == m_cipher.GetReceiveGarbageTerminator()) break;
        }
        // Copy the garbage to a buffer.
        m_recv_garbage.assign(m_received.begin(), m_received.begin() + garblen);
        // Strip garbage + garbage terminator off the front of the receive buffer.
        m_received.erase(m_received.begin(), m_received.begin() + garblen + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
    }

    /** Expect version packet to have been received, and process it (only after ReceiveKey). */
    void ReceiveVersion()
    {
        auto contents = ReceivePacket(/*aad=*/MakeByteSpan(m_recv_garbage));
        // Version packets from real BIP324 peers are expected to be empty, despite the fact that
        // this class supports *sending* non-empty version packets (to test that BIP324 peers
        // correctly ignore version packet contents).
        BOOST_CHECK(contents.empty());
    }

    /** Expect application packet to have been received, with specified short id and payload.
     *  (only after ReceiveKey). */
    void ReceiveMessage(uint8_t short_id, Span<const uint8_t> payload)
    {
        auto ret = ReceivePacket();
        BOOST_CHECK(ret.size() == payload.size() + 1);
        BOOST_CHECK(ret[0] == short_id);
        BOOST_CHECK(Span{ret}.subspan(1) == payload);
    }

    /** Expect application packet to have been received, with specified 12-char message type and
     *  payload (only after ReceiveKey). */
    void ReceiveMessage(const std::string& m_type, Span<const uint8_t> payload)
    {
        auto ret = ReceivePacket();
        BOOST_REQUIRE(ret.size() == payload.size() + 1 + CMessageHeader::COMMAND_SIZE);
        BOOST_CHECK(ret[0] == 0);
        for (unsigned i = 0; i < 12; ++i) {
            if (i < m_type.size()) {
                BOOST_CHECK(ret[1 + i] == m_type[i]);
            } else {
                BOOST_CHECK(ret[1 + i] == 0);
            }
        }
        BOOST_CHECK(Span{ret}.subspan(1 + CMessageHeader::COMMAND_SIZE) == payload);
    }

    /** Schedule an encrypted packet with specified message type and payload to be sent to
     *  transport (only after ReceiveKey). */
    void SendMessage(std::string mtype, Span<const uint8_t> payload)
    {
        // Construct contents consisting of 0x00 + 12-byte message type + payload.
        std::vector<uint8_t> contents(1 + CMessageHeader::COMMAND_SIZE + payload.size());
        std::copy(mtype.begin(), mtype.end(), reinterpret_cast<char*>(contents.data() + 1));
        std::copy(payload.begin(), payload.end(), contents.begin() + 1 + CMessageHeader::COMMAND_SIZE);
        // Send a packet with that as contents.
        SendPacket(contents);
    }

    /** Schedule an encrypted packet with specified short message id and payload to be sent to
     *  transport (only after ReceiveKey). */
    void SendMessage(uint8_t short_id, Span<const uint8_t> payload)
    {
        // Construct contents consisting of short_id + payload.
        std::vector<uint8_t> contents(1 + payload.size());
        contents[0] = short_id;
        std::copy(payload.begin(), payload.end(), contents.begin() + 1);
        // Send a packet with that as contents.
        SendPacket(contents);
    }

    /** Test whether the transport's session ID matches the session ID we expect. */
    void CompareSessionIDs() const
    {
        auto info = m_transport.GetInfo();
        BOOST_CHECK(info.session_id);
        BOOST_CHECK(uint256(MakeUCharSpan(m_cipher.GetSessionID())) == *info.session_id);
    }

    /** Introduce a bit error in the data scheduled to be sent. */
    void Damage()
    {
        m_to_send[InsecureRandRange(m_to_send.size())] ^= (uint8_t{1} << InsecureRandRange(8));
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(v2transport_test)
{
    // A mostly normal scenario, testing a transport in initiator mode.
    for (int i = 0; i < 10; ++i) {
        V2TransportTester tester(true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.SendGarbage();
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(100000));
        auto msg_data_2 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(1000));
        tester.SendMessage(uint8_t(4), msg_data_1); // cmpctblock short id
        tester.SendMessage(0, {}); // Invalidly encoded message
        tester.SendMessage("tx", msg_data_2); // 12-character encoded message type
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 3);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "cmpctblock" && Span{(*ret)[0]->m_recv} == MakeByteSpan(msg_data_1));
        BOOST_CHECK(!(*ret)[1]);
        BOOST_CHECK((*ret)[2] && (*ret)[2]->m_type == "tx" && Span{(*ret)[2]->m_recv} == MakeByteSpan(msg_data_2));

        // Then send a message with a bit error, expecting failure. It's possible this failure does
        // not occur immediately (when the length descriptor was modified), but it should come
        // eventually, and no messages can be delivered anymore.
        tester.SendMessage("bad", msg_data_1);
        tester.Damage();
        while (true) {
            ret = tester.Interact();
            if (!ret) break; // failure
            BOOST_CHECK(ret->size() == 0); // no message can be delivered
            // Send another message.
            auto msg_data_3 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(10000));
            tester.SendMessage(uint8_t(12), msg_data_3); // getheaders short id
        }
    }

    // Normal scenario, with a transport in responder node.
    for (int i = 0; i < 10; ++i) {
        V2TransportTester tester(false);
        tester.SendKey();
        tester.SendGarbage();
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(100000));
        auto msg_data_2 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(1000));
        tester.SendMessage(uint8_t(14), msg_data_1); // inv short id
        tester.SendMessage(uint8_t(19), msg_data_2); // pong short id
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 2);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "inv" && Span{(*ret)[0]->m_recv} == MakeByteSpan(msg_data_1));
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "pong" && Span{(*ret)[1]->m_recv} == MakeByteSpan(msg_data_2));

        // Then send a too-large message.

        // The maximum permitted contents length for a packet, consisting of:
        // - 0x00 byte: indicating long message type encoding
        // - 12 bytes of message type
        // - payload
        // SYSCOIN
        static constexpr size_t MAX_CONTENTS_LEN =
            1 + CMessageHeader::COMMAND_SIZE +
            MAX_PROTOCOL_MESSAGE_LENGTH;
        auto msg_data_3 = g_insecure_rand_ctx.randbytes<uint8_t>(MAX_CONTENTS_LEN+1);
        tester.SendMessage(uint8_t(11), msg_data_3); // getdata short id
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Various valid but unusual scenarios.
    for (int i = 0; i < 50; ++i) {
        /** Whether an initiator or responder is being tested. */
        bool initiator = InsecureRandBool();
        /** Use either 0 bytes or the maximum possible (4095 bytes) garbage length. */
        size_t garb_len = InsecureRandBool() ? 0 : V2Transport::MAX_GARBAGE_LEN;
        /** How many decoy packets to send before the version packet. */
        unsigned num_ignore_version = InsecureRandRange(10);
        /** What data to send in the version packet (ignored by BIP324 peers, but reserved for future extensions). */
        auto ver_data = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandBool() ? 0 : InsecureRandRange(1000));
        /** Whether to immediately send key and garbage out (required for responders, optional otherwise). */
        bool send_immediately = !initiator || InsecureRandBool();
        /** How many decoy packets to send before the first and second real message. */
        unsigned num_decoys_1 = InsecureRandRange(1000), num_decoys_2 = InsecureRandRange(1000);
        V2TransportTester tester(initiator);
        if (send_immediately) {
            tester.SendKey();
            tester.SendGarbage(garb_len);
        }
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        if (!send_immediately) {
            tester.SendKey();
            tester.SendGarbage(garb_len);
        }
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        for (unsigned v = 0; v < num_ignore_version; ++v) {
            size_t ver_ign_data_len = InsecureRandBool() ? 0 : InsecureRandRange(1000);
            auto ver_ign_data = g_insecure_rand_ctx.randbytes<uint8_t>(ver_ign_data_len);
            tester.SendVersion(ver_ign_data, true);
        }
        tester.SendVersion(ver_data, false);
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        for (unsigned d = 0; d < num_decoys_1; ++d) {
            auto decoy_data = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(1000));
            tester.SendPacket(/*content=*/decoy_data, /*aad=*/{}, /*ignore=*/true);
        }
        auto msg_data_1 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(4000000));
        tester.SendMessage(uint8_t(28), msg_data_1);
        for (unsigned d = 0; d < num_decoys_2; ++d) {
            auto decoy_data = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(1000));
            tester.SendPacket(/*content=*/decoy_data, /*aad=*/{}, /*ignore=*/true);
        }
        auto msg_data_2 = g_insecure_rand_ctx.randbytes<uint8_t>(InsecureRandRange(1000));
        tester.SendMessage(uint8_t(13), msg_data_2); // headers short id
        // Send invalidly-encoded message
        tester.SendMessage(std::string("blocktxn\x00\x00\x00a", CMessageHeader::COMMAND_SIZE), {});
        tester.SendMessage("foobar", {}); // test receiving unknown message type
        tester.AddMessage("barfoo", {}); // test sending unknown message type
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 4);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "addrv2" && Span{(*ret)[0]->m_recv} == MakeByteSpan(msg_data_1));
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "headers" && Span{(*ret)[1]->m_recv} == MakeByteSpan(msg_data_2));
        BOOST_CHECK(!(*ret)[2]);
        BOOST_CHECK((*ret)[3] && (*ret)[3]->m_type == "foobar" && (*ret)[3]->m_recv.empty());
        tester.ReceiveMessage("barfoo", {});
    }

    // Too long garbage (initiator).
    {
        V2TransportTester tester(true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.SendGarbage(V2Transport::MAX_GARBAGE_LEN + 1);
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Too long garbage (responder).
    {
        V2TransportTester tester(false);
        tester.SendKey();
        tester.SendGarbage(V2Transport::MAX_GARBAGE_LEN + 1);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Send garbage that includes the first 15 garbage terminator bytes somewhere.
    {
        V2TransportTester tester(true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.ReceiveKey();
        /** The number of random garbage bytes before the included first 15 bytes of terminator. */
        size_t len_before = InsecureRandRange(V2Transport::MAX_GARBAGE_LEN - 16 + 1);
        /** The number of random garbage bytes after it. */
        size_t len_after = InsecureRandRange(V2Transport::MAX_GARBAGE_LEN - 16 - len_before + 1);
        // Construct len_before + 16 + len_after random bytes.
        auto garbage = g_insecure_rand_ctx.randbytes<uint8_t>(len_before + 16 + len_after);
        // Replace the designed 16 bytes in the middle with the to-be-sent garbage terminator.
        auto garb_term = MakeUCharSpan(tester.GetCipher().GetSendGarbageTerminator());
        std::copy(garb_term.begin(), garb_term.begin() + 16, garbage.begin() + len_before);
        // Introduce a bit error in the last byte of that copied garbage terminator, making only
        // the first 15 of them match.
        garbage[len_before + 15] ^= (uint8_t(1) << InsecureRandRange(8));
        tester.SendGarbage(garbage);
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = g_insecure_rand_ctx.randbytes<uint8_t>(4000000); // test that receiving 4M payload works
        auto msg_data_2 = g_insecure_rand_ctx.randbytes<uint8_t>(4000000); // test that sending 4M payload works
        tester.SendMessage(uint8_t(InsecureRandRange(223) + 33), {}); // unknown short id
        tester.SendMessage(uint8_t(2), msg_data_1); // "block" short id
        tester.AddMessage("blocktxn", msg_data_2); // schedule blocktxn to be sent to us
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 2);
        BOOST_CHECK(!(*ret)[0]);
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "block" && Span{(*ret)[1]->m_recv} == MakeByteSpan(msg_data_1));
        tester.ReceiveMessage(uint8_t(3), msg_data_2); // "blocktxn" short id
    }

    // Send correct network's V1 header
    {
        V2TransportTester tester(false);
        tester.SendV1Version(Params().MessageStart());
        auto ret = tester.Interact();
        BOOST_CHECK(ret);
    }

    // Send wrong network's V1 header
    {
        V2TransportTester tester(false);
        tester.SendV1Version(CChainParams::Main(CChainParams::MainNetOptions{})->MessageStart());
        auto ret = tester.Interact();
        BOOST_CHECK(!ret);
    }
}
BOOST_AUTO_TEST_SUITE_END()
