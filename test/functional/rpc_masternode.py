#!/usr/bin/env python3
# Copyright (c) 2020 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import time

from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    MASTERNODE_COLLATERAL,
    p2p_port,
)
'''
rpc_masternode.py

Test "masternode" rpc subcommands
'''

class RPCMasternodeTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(4, 3, fast_dip3_enforcement=True)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def authenticated_peer(node, protx_hash, inbound):
        return next((
            peer for peer in node.getpeerinfo()
            if peer["masternode"]
            and peer["inbound"] == inbound
            and peer.get("verified_proregtx_hash") == protx_hash
        ), None)

    def test_wire_pq_mnauth(self):
        initiator = self.mninfo[0]
        responder = self.mninfo[1]
        initiator_node = initiator.node
        responder_node = responder.node
        initiator_stats_before = initiator_node.getnetworkinfo()["mnauth"]
        responder_stats_before = responder_node.getnetworkinfo()["mnauth"]
        unexpected_logs = [
            "deadline expired",
            "MNAUTH phase ",
            "missing MNAUTH state",
            "PQ verification admission failed",
            "MNAUTH signing admission failed",
            "pq mnauth signature verification failed",
        ]

        with initiator_node.assert_debug_log(
                [
                    "sending PQ MNAUTH, role=0",
                    "valid PQ MNAUTH for %s" % responder.proTxHash,
                ],
                unexpected_msgs=unexpected_logs,
                timeout=180):
            with responder_node.assert_debug_log(
                    [
                        "valid PQ MNAUTH for %s" % initiator.proTxHash,
                        "sending PQ MNAUTH, role=1",
                    ],
                    unexpected_msgs=unexpected_logs,
                    timeout=180):
                assert_equal(
                    initiator_node.masternode_connect(
                        "127.0.0.1:%d" % p2p_port(responder.nodeIdx)),
                    "successfully connected",
                )
                self.wait_until(
                    lambda: (
                        self.authenticated_peer(
                            initiator_node, responder.proTxHash, False)
                        is not None
                        and self.authenticated_peer(
                            responder_node, initiator.proTxHash, True)
                        is not None
                    ),
                    timeout=180,
                )

                initiator_peer = self.authenticated_peer(
                    initiator_node, responder.proTxHash, False)
                responder_peer = self.authenticated_peer(
                    responder_node, initiator.proTxHash, True)
                initiator_peer_id = initiator_peer["id"]
                responder_peer_id = responder_peer["id"]
                for peer in (initiator_peer, responder_peer):
                    assert peer["bytessent_per_msg"].get("mnauth", 0) > 0
                    assert peer["bytesrecv_per_msg"].get("mnauth", 0) > 0

                # Survive the former fixed five-second transport grace on the
                # same authenticated connection in both directions.
                time.sleep(6)
                assert_equal(
                    self.authenticated_peer(
                        initiator_node, responder.proTxHash, False)["id"],
                    initiator_peer_id,
                )
                assert_equal(
                    self.authenticated_peer(
                        responder_node, initiator.proTxHash, True)["id"],
                    responder_peer_id,
                )

        for node, before in (
                (initiator_node, initiator_stats_before),
                (responder_node, responder_stats_before)):
            after = node.getnetworkinfo()["mnauth"]
            assert after["verify_completed"] >= before["verify_completed"] + 1
            assert after["sign_completed"] >= before["sign_completed"] + 1
            assert after["verify_latency_max_us"] > 0
            assert after["sign_latency_max_us"] > 0
            for field in (
                    "verify_queue",
                    "sign_queue",
                    "initiator_sign_queue",
                    "responder_sign_queue",
                    "completion_queue",
                    "verify_inflight",
                    "sign_inflight"):
                assert_equal(after[field], 0)
            for field in (
                    "verify_failed",
                    "sign_failed",
                    "verify_saturation_drops",
                    "sign_saturation_drops",
                    "initiator_sign_saturation_drops",
                    "responder_sign_saturation_drops",
                    "verify_expired_before_execution",
                    "sign_expired_before_execution",
                    "preverify_rate_drops",
                    "sign_rate_drops",
                    "cancelled_jobs",
                    "stale_completions",
                    "completion_backpressure"):
                assert_equal(after[field], before[field])

    def test_ordinary_manual_connection_does_not_mnauth(self):
        initiator = self.mninfo[1]
        responder = self.mninfo[2]
        initiator_node = initiator.node
        responder_node = responder.node
        responder_service = "127.0.0.1:%d" % p2p_port(responder.nodeIdx)

        # Exercise the ordinary addnode path independently of any connection
        # the masternode connector might already have established.
        self.disconnect_nodes(initiator.nodeIdx, responder.nodeIdx)
        initiator_stats_before = initiator_node.getnetworkinfo()["mnauth"]
        responder_stats_before = responder_node.getnetworkinfo()["mnauth"]
        unexpected_logs = [
            "deadline expired",
            "MNAUTH phase ",
            "missing MNAUTH state",
            "claims an inbound PQ masternode connection",
            "sending PQ MNAUTH",
            "valid PQ MNAUTH",
            "PQ verification admission failed",
            "MNAUTH signing admission failed",
            "pq mnauth signature verification failed",
        ]

        def ordinary_manual_peer(node, remote_addr, inbound):
            return next((
                peer for peer in node.getpeerinfo()
                if peer["inbound"] == inbound
                and not peer["masternode"]
                and peer["connection_type"] == (
                    "inbound" if inbound else "manual")
                and peer["addr"] == remote_addr
            ), None)

        def exact_manual_pair():
            outbound = ordinary_manual_peer(
                initiator_node, responder_service, False)
            return (
                outbound,
                None if outbound is None else ordinary_manual_peer(
                    responder_node, outbound["addrbind"], True),
            )

        with initiator_node.assert_debug_log(
                ["New manual v1 peer connected"],
                unexpected_msgs=unexpected_logs,
                timeout=180):
            with responder_node.assert_debug_log(
                    ["New inbound v1 peer connected"],
                    unexpected_msgs=unexpected_logs,
                    timeout=180):
                initiator_node.addnode(responder_service, "onetry")
                self.wait_until(
                    lambda: all(peer is not None
                                for peer in exact_manual_pair()),
                    timeout=180,
                )

                initiator_peer, responder_peer = exact_manual_pair()
                assert_equal(initiator_peer["addr"], responder_service)
                initiator_addrbind = initiator_peer["addrbind"]
                assert_equal(responder_peer["addr"], initiator_addrbind)
                initiator_peer_id = initiator_peer["id"]
                responder_peer_id = responder_peer["id"]
                for peer in (initiator_peer, responder_peer):
                    assert_equal(peer["masternode"], False)
                    assert "verified_proregtx_hash" not in peer
                    assert_equal(
                        peer["bytessent_per_msg"].get("mnauth", 0), 0)
                    assert_equal(
                        peer["bytesrecv_per_msg"].get("mnauth", 0), 0)

                # The old identity leak put the inbound side into a 60-second
                # MNAUTH wait. Prove this ordinary socket is never enrolled.
                time.sleep(61)
                initiator_peer = ordinary_manual_peer(
                    initiator_node, responder_service, False)
                responder_peer = ordinary_manual_peer(
                    responder_node, initiator_addrbind, True)
                assert initiator_peer is not None
                assert responder_peer is not None
                assert_equal(initiator_peer["id"], initiator_peer_id)
                assert_equal(responder_peer["id"], responder_peer_id)
                for peer in (initiator_peer, responder_peer):
                    assert_equal(
                        peer["bytessent_per_msg"].get("mnauth", 0), 0)
                    assert_equal(
                        peer["bytesrecv_per_msg"].get("mnauth", 0), 0)

                assert_raises_rpc_error(
                    -32603,
                    "Existing ordinary connection",
                    initiator_node.masternode_connect,
                    responder_service,
                )
                initiator_peer = ordinary_manual_peer(
                    initiator_node, responder_service, False)
                responder_peer = ordinary_manual_peer(
                    responder_node, initiator_addrbind, True)
                assert initiator_peer is not None
                assert responder_peer is not None
                assert_equal(initiator_peer["id"], initiator_peer_id)
                assert_equal(responder_peer["id"], responder_peer_id)

        for node, before in (
                (initiator_node, initiator_stats_before),
                (responder_node, responder_stats_before)):
            assert_equal(node.getnetworkinfo()["mnauth"], before)

        initiator_node.disconnectnode(nodeid=initiator_peer_id)
        self.wait_until(
            lambda: (
                ordinary_manual_peer(
                    initiator_node, responder_service, False) is None
                and ordinary_manual_peer(
                    responder_node, initiator_addrbind, True) is None
            ),
            timeout=5,
        )

        dedicated_unexpected_logs = [
            "deadline expired",
            "MNAUTH phase ",
            "missing MNAUTH state",
            "PQ verification admission failed",
            "MNAUTH signing admission failed",
            "pq mnauth signature verification failed",
        ]
        with initiator_node.assert_debug_log(
                [
                    "sending PQ MNAUTH, role=0",
                    "valid PQ MNAUTH for %s" % responder.proTxHash,
                ],
                unexpected_msgs=dedicated_unexpected_logs,
                timeout=180):
            with responder_node.assert_debug_log(
                    [
                        "valid PQ MNAUTH for %s" % initiator.proTxHash,
                        "sending PQ MNAUTH, role=1",
                    ],
                    unexpected_msgs=dedicated_unexpected_logs,
                    timeout=180):
                assert_equal(
                    initiator_node.masternode_connect(responder_service),
                    "successfully connected",
                )
                self.wait_until(
                    lambda: (
                        self.authenticated_peer(
                            initiator_node, responder.proTxHash, False)
                        is not None
                        and self.authenticated_peer(
                            responder_node, initiator.proTxHash, True)
                        is not None
                    ),
                    timeout=180,
                )

                dedicated_initiator = self.authenticated_peer(
                    initiator_node, responder.proTxHash, False)
                dedicated_responder = self.authenticated_peer(
                    responder_node, initiator.proTxHash, True)
                assert_equal(dedicated_initiator["addr"], responder_service)
                assert dedicated_initiator["id"] != initiator_peer_id
                assert dedicated_responder["id"] != responder_peer_id
                for peer in (dedicated_initiator, dedicated_responder):
                    assert peer["bytessent_per_msg"].get("mnauth", 0) > 0
                    assert peer["bytesrecv_per_msg"].get("mnauth", 0) > 0

        for node, before in (
                (initiator_node, initiator_stats_before),
                (responder_node, responder_stats_before)):
            after = node.getnetworkinfo()["mnauth"]
            assert after["verify_completed"] >= before["verify_completed"] + 1
            assert after["sign_completed"] >= before["sign_completed"] + 1

    def run_test(self):
        self.test_wire_pq_mnauth()
        self.test_ordinary_manual_connection_does_not_mnauth()
        self.log.info("test that results from `winners` and `payments` RPCs match")
        blockhash = ""
        payments = []
        # we expect some masternodes to have 0 operator reward and some to have non-0 operator reward
        checked_0_operator_reward = False
        checked_non_0_operator_reward = False
        while not checked_0_operator_reward or not checked_non_0_operator_reward:
            self.generate(self.nodes[0], 1)
            bi = self.nodes[0].getblockchaininfo()
            height = bi["blocks"]
            blockhash = bi["bestblockhash"]
            winners_payee = self.nodes[0].masternode_winners()[str(height)]
            payments = self.nodes[0].masternode_payments(blockhash)
            assert_equal(len(payments), 1)
            payments_block = payments[0]
            payments_block_payees = payments_block["masternodes"][0]["payees"]
            payments_payee = ""
            for i in range(0, len(payments_block_payees)):
                payments_payee += payments_block_payees[i]["address"]
                if i < len(payments_block_payees) - 1:
                    payments_payee += ", "
            assert_equal(payments_block["height"], height)
            assert_equal(payments_block["blockhash"], blockhash)
            assert_equal(winners_payee, payments_payee)
            if len(payments_block_payees) == 1:
                checked_0_operator_reward = True
            if len(payments_block_payees) > 1:
                checked_non_0_operator_reward = True

        self.log.info("test various `payments` RPC options")
        payments1 = self.nodes[0].masternode_payments(blockhash, -1)
        assert_equal(payments, payments1)
        payments2_1 = self.nodes[0].masternode_payments(blockhash, 2)
        # using chaintip as a start block should return 1 block only
        assert_equal(len(payments2_1), 1)
        assert_equal(payments[0], payments2_1[0])
        payments2_2 = self.nodes[0].masternode_payments(blockhash, -2)
        # using chaintip as a start block should return 2 blocks now, with the tip being the last one
        assert_equal(len(payments2_2), 2)
        assert_equal(payments[0], payments2_2[-1])

        self.log.info("test that `masternode payments` results at chaintip match `getblocktemplate` results for that block")
        gbt_masternode = self.nodes[0].getblocktemplate({"rules": ["segwit"]})["masternode"]
        self.generate(self.nodes[0], 1)
        payments_masternode = self.nodes[0].masternode_payments()[0]["masternodes"][0]
        for i in range(0, len(gbt_masternode)):
            assert_equal(gbt_masternode[i]["payee"], payments_masternode["payees"][i]["address"])
            assert_equal(gbt_masternode[i]["script"], payments_masternode["payees"][i]["script"])
            assert_equal(gbt_masternode[i]["amount"], payments_masternode["payees"][i]["amount"])

        self.log.info("test that `masternode payments` results and `protx info` results match")
        # we expect some masternodes to have 0 operator reward and some to have non-0 operator reward
        checked_0_operator_reward = False
        checked_non_0_operator_reward = False
        while not checked_0_operator_reward or not checked_non_0_operator_reward:
            payments_masternode = self.nodes[0].masternode_payments()[0]["masternodes"][0]
            protx_info = self.nodes[0].protx_info(payments_masternode["proTxHash"])
            if len(payments_masternode["payees"]) == 1:
                assert_equal(protx_info["state"]["payoutAddress"], payments_masternode["payees"][0]["address"])
                checked_0_operator_reward = True
            else:
                assert_equal(len(payments_masternode["payees"]), 2)
                option1 = protx_info["state"]["payoutAddress"] == payments_masternode["payees"][0]["address"] and \
                    protx_info["state"]["operatorPayoutAddress"] == payments_masternode["payees"][1]["address"]
                option2 = protx_info["state"]["payoutAddress"] == payments_masternode["payees"][1]["address"] and \
                    protx_info["state"]["operatorPayoutAddress"] == payments_masternode["payees"][0]["address"]
                assert option1 or option2
                checked_non_0_operator_reward = True
            self.generate(self.nodes[0], 1)

        self.log.info("test that `masternode outputs` show correct list")
        addr1 = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()
        # SYSCOIN
        self.nodes[0].sendmany('', {addr1: MASTERNODE_COLLATERAL, addr2: MASTERNODE_COLLATERAL})
        self.generate(self.nodes[0], 1)
        # we have 3 masternodes that are running already and 2 new outputs we just created
        assert_equal(len(self.nodes[0].masternode_outputs()), 5)

if __name__ == '__main__':
    RPCMasternodeTest().main()
