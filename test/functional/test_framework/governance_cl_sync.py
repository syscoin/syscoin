#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for the governance ChainLock bootstrap fixture."""

from types import SimpleNamespace
import unittest

from feature_governance_cl import SyscoinGovernanceTest


class TestGovernanceChainlockSync(unittest.TestCase):
    def test_controller_connection_requires_outbound_relay_and_handshake(self):
        for inbound, masternode in [(True, False), (False, True)]:
            with self.subTest(inbound=inbound, masternode=masternode):
                case = object.__new__(SyscoinGovernanceTest)
                peers = [{"subver": "controller", "inbound": inbound,
                          "masternode": masternode, "bytesrecv_per_msg": {"pong": 32}}]
                node = SimpleNamespace(index=5, getpeerinfo=lambda: peers)
                case.nodes = [SimpleNamespace(getnetworkinfo=lambda: {"subversion": "controller"})]
                calls = []

                def disconnect(a, b):
                    self.assertEqual((a, b), (5, 0))
                    peers.clear()
                    calls.append("disconnect")

                def connect(a, b):
                    self.assertEqual((a, b), (5, 0))
                    peers.append({"subver": "controller", "inbound": False,
                                  "masternode": False, "bytesrecv_per_msg": {}})
                    calls.append("connect")

                def wait_until(predicate, *, timeout):
                    self.assertEqual(timeout, 5)
                    self.assertFalse(predicate(), "handshake must finish before bootstrap")
                    peers[0]["bytesrecv_per_msg"]["pong"] = 32
                    self.assertTrue(predicate())

                case.disconnect_nodes = disconnect
                case.connect_nodes = connect
                case.wait_until = wait_until
                case.ensure_controller_connection(node)
                self.assertEqual(calls, ["disconnect", "connect"])

                case.wait_until = lambda predicate, **_: self.assertTrue(predicate())
                case.ensure_controller_connection(node)
                self.assertEqual(calls, ["disconnect", "connect"])

    def test_target_chainlock_wait_advances_clock_and_requires_exact_hash(self):
        case = object.__new__(SyscoinGovernanceTest)
        clock_steps = []

        def advance_clock(key, *, step):
            self.assertEqual(key, "feature_governance_cl_hash_sync")
            self.assertEqual(step, 1)
            clock_steps.append(step)

        case._throttled_bump_mocktime = advance_clock
        node = SimpleNamespace(getbestchainlock=lambda: {
            "height": 330,
            "blockhash": "target" if sum(clock_steps) >= 2 else "another-block",
        })

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 60)
            self.assertFalse(predicate(), "matching height must not substitute for the target hash")
            self.assertTrue(predicate(), "mock time must release the delayed request")

        case.wait_until = wait_until
        case.wait_for_chainlock_hash(node, "target")
        self.assertEqual(clock_steps, [1, 1])
