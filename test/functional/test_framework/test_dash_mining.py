#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise shared fixture mining without an expensive masternode deployment."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from .authproxy import JSONRPCException
from .auxpow_testing import NON_NULL_BTCPREV_HASH_HEX
from .test_framework import DashTestFramework


class RecordingMiningNode:
    def __init__(self, *, args=(), candidates=(), height=0, max_ordinary_batch=None):
        self.process = SimpleNamespace(args=["syscoind", *args])
        self.extra_args = []
        self.candidates = set(candidates)
        self.height = height
        self.calls = []
        self.payouts = {}
        self.template = None
        self.max_ordinary_batch = max_ordinary_batch

    def getblockcount(self):
        return self.height

    def get_deterministic_priv_key(self):
        return SimpleNamespace(address="deterministic-mining-address")

    def generate(self, nblocks, *, invalid_call):
        return self.generatetoaddress(
            nblocks, self.get_deterministic_priv_key().address,
            invalid_call=invalid_call)

    def generatetoaddress(self, nblocks, address, *, invalid_call):
        assert invalid_call is False
        if self.max_ordinary_batch is not None and nblocks > self.max_ordinary_batch:
            raise JSONRPCException({"code": -344, "message": "mining RPC timed out"})
        heights = range(self.height + 1, self.height + nblocks + 1)
        assert self.candidates.isdisjoint(heights), "ordinary batch crossed a candidate"
        self.calls.append(("ordinary", self.height + 1, nblocks, address))
        hashes = [f"{height:064x}" for height in heights]
        self.payouts.update((block_hash, address) for block_hash in hashes)
        self.height += nblocks
        return hashes

    def createauxblock(self, address, btcprev=None):
        assert self.height + 1 in self.candidates, "unscheduled AuxPoW block"
        if btcprev is None:
            raise JSONRPCException({
                "code": -8,
                "message": "btcprevhash is required at this height",
            })
        assert btcprev == NON_NULL_BTCPREV_HASH_HEX
        self.template = (f"{self.height + 1:064x}", address)
        return {"hash": self.template[0]}

    def submitauxblock(self, block_hash, auxpow):
        assert self.template is not None
        assert block_hash == self.template[0]
        assert auxpow == "test-auxpow"
        self.height += 1
        self.calls.append(("auxpow", self.height, 1, self.template[1]))
        self.payouts[block_hash] = self.template[1]
        self.template = None
        return True


class TestDashMining(unittest.TestCase):
    def setUp(self):
        # Framework construction parses command-line options and starts test
        # lifecycle state; these helpers only need the mining/sync methods.
        self.framework = object.__new__(DashTestFramework)
        self.framework.sync_all = Mock()
        self.auxpow = patch(
            "test_framework.test_framework.mineAuxpowBlockWithMethods",
            side_effect=self.mine_auxpow,
        )
        self.auxpow.start()
        self.addCleanup(self.auxpow.stop)

    @staticmethod
    def mine_auxpow(create, submit):
        template = create()
        assert template["_btcprevhash"] == NON_NULL_BTCPREV_HASH_HEX
        assert submit(template["hash"], "test-auxpow")
        return template["hash"]

    def assert_hashes_and_payouts(self, node, hashes, first_height, count, address):
        expected = [f"{height:064x}" for height in range(first_height, first_height + count)]
        self.assertEqual(hashes, expected)
        self.assertEqual([node.payouts[block_hash] for block_hash in hashes], [address] * count)

    def test_explicit_address_batches_stop_at_each_candidate(self):
        node = RecordingMiningNode(
            args=["-pqbtcccandidateorigin=5"], candidates=[5, 15, 25])
        sync = Mock()
        prefix = self.framework.generatetoaddress(node, 4, "first-address", sync_fun=sync)
        self.assert_hashes_and_payouts(node, prefix, 1, 4, "first-address")
        sync.assert_called_once_with()
        self.framework.sync_all.assert_not_called()

        sync.reset_mock()
        hashes = self.framework.generatetoaddress(
            node, nblocks=23, address="second-address", sync_fun=sync)
        self.assert_hashes_and_payouts(node, hashes, 5, 23, "second-address")
        self.assertEqual(node.calls, [
            ("ordinary", 1, 4, "first-address"),
            ("auxpow", 5, 1, "second-address"),
            ("ordinary", 6, 9, "second-address"),
            ("auxpow", 15, 1, "second-address"),
            ("ordinary", 16, 9, "second-address"),
            ("auxpow", 25, 1, "second-address"),
            ("ordinary", 26, 2, "second-address"),
        ])
        self.assertEqual(node.height, 27)
        sync.assert_called_once_with()
        self.framework.sync_all.assert_not_called()

    def test_generate_preserves_default_payout_and_one_default_sync(self):
        node = RecordingMiningNode(
            args=["-pqbtcccandidateorigin=5"], candidates=[5, 15])
        hashes = self.framework.generate(node, nblocks=16)
        address = node.get_deterministic_priv_key().address
        self.assert_hashes_and_payouts(node, hashes, 1, 16, address)
        self.assertEqual([(kind, height, count) for kind, height, count, _ in node.calls], [
            ("ordinary", 1, 4), ("auxpow", 5, 1),
            ("ordinary", 6, 9), ("auxpow", 15, 1), ("ordinary", 16, 1),
        ])
        self.framework.sync_all.assert_called_once_with()

    def test_deterministic_masternode_fixture_mines_activation_and_later_candidates(self):
        # Check the actual independent fixture's wiring: testing Dash alone
        # cannot detect a consumer still using the generic direct-mining path.
        from feature_deterministicmns import DIP3Test

        framework = object.__new__(DIP3Test)
        framework.sync_all = Mock()
        node = RecordingMiningNode(
            args=["-pqbtcccandidateorigin=2305"],
            candidates=[2305, 2315], height=2304)
        hashes = framework.generate(node, 12)
        self.assert_hashes_and_payouts(
            node, hashes, 2305, 12, node.get_deterministic_priv_key().address)
        self.assertEqual([(kind, height, count) for kind, height, count, _ in node.calls], [
            ("auxpow", 2305, 1), ("ordinary", 2306, 9),
            ("auxpow", 2315, 1), ("ordinary", 2316, 1),
        ])
        framework.sync_all.assert_called_once_with()

    def test_no_op_sync_and_origin_zero_skip_genesis(self):
        node = RecordingMiningNode(
            args=["-pqbtcccandidateorigin=0"], candidates=[10, 20])
        hashes = self.framework.generate(node, 21, sync_fun=self.framework.no_op)
        self.assert_hashes_and_payouts(
            node, hashes, 1, 21, node.get_deterministic_priv_key().address)
        self.assertEqual([(kind, height, count) for kind, height, count, _ in node.calls], [
            ("ordinary", 1, 9), ("auxpow", 10, 1),
            ("ordinary", 11, 9), ("auxpow", 20, 1), ("ordinary", 21, 1),
        ])
        self.framework.sync_all.assert_not_called()

    def test_launched_restart_override_wins_over_stale_extra_args(self):
        node = RecordingMiningNode(
            args=["-pqbtcccandidateorigin=5", "-pqbtcccandidateorigin=0"],
            candidates=[10], height=8)
        node.extra_args = ["-pqbtcccandidateorigin=5"]
        hashes = self.framework.generatetoaddress(node, 3, "restart-address")
        self.assert_hashes_and_payouts(node, hashes, 9, 3, "restart-address")
        self.assertEqual(node.calls, [
            ("ordinary", 9, 1, "restart-address"),
            ("auxpow", 10, 1, "restart-address"),
            ("ordinary", 11, 1, "restart-address"),
        ])
        self.framework.sync_all.assert_called_once_with()

    def test_disabled_and_unconfigured_schedules_use_only_ordinary_batches(self):
        for args in ([], ["-pqbtcccandidateorigin=-1"],
                     ["-pqbtcccandidateorigin=2147483647"]):
            with self.subTest(args=args):
                node = RecordingMiningNode(args=args)
                node.extra_args = ["-pqbtcccandidateorigin=5"]
                sync = Mock()
                hashes = self.framework.generatetoaddress(
                    node, 27, "ordinary-address", sync_fun=sync)
                self.assert_hashes_and_payouts(node, hashes, 1, 27, "ordinary-address")
                self.assertTrue(all(kind == "ordinary" for kind, *_ in node.calls))
                sync.assert_called_once_with()
        self.framework.sync_all.assert_not_called()

    def test_large_preparation_mining_stays_within_each_rpc_budget(self):
        from feature_deterministicmns import DIP3Test
        from feature_pq_operator_lifecycle import PQOperatorLifecycleTest

        # Both an unconfigured preparation chain and a distant first
        # candidate used to dispatch the entire catch-up through one RPC.
        for fixture in (DashTestFramework, DIP3Test, PQOperatorLifecycleTest):
            for args in ([], ["-pqbtcccandidateorigin=2305"]):
                with self.subTest(fixture=fixture.__name__, args=args):
                    framework = object.__new__(fixture)
                    framework.sync_all = Mock()
                    node = RecordingMiningNode(
                        args=args, height=111, max_ordinary_batch=10)
                    hashes = framework.generate(node, 2304 - node.height)
                    self.assert_hashes_and_payouts(
                        node, hashes, 112, 2193,
                        node.get_deterministic_priv_key().address)
                    self.assertEqual(node.height, 2304)
                    self.assertGreater(len(node.calls), 1)
                    framework.sync_all.assert_called_once_with()

    def test_short_rpc_result_returns_without_retrying(self):
        node = RecordingMiningNode()
        ordinary_rpc = node.generatetoaddress
        with patch.object(node, "generatetoaddress", side_effect=lambda nblocks, address, **kwargs:
                          ordinary_rpc(3, address, **kwargs)) as limited_rpc:
            hashes = self.framework.generate(node, 30)
        self.assert_hashes_and_payouts(
            node, hashes, 1, 3, node.get_deterministic_priv_key().address)
        limited_rpc.assert_called_once()
        self.framework.sync_all.assert_called_once_with()

    def test_zero_blocks_preserves_empty_result_and_sync(self):
        node = RecordingMiningNode(args=["-pqbtcccandidateorigin=5"], candidates=[5])
        self.assertEqual(self.framework.generate(node, 0), [])
        self.assertEqual(node.height, 0)
        self.assertEqual(node.calls, [("ordinary", 1, 0, "deterministic-mining-address")])
        self.framework.sync_all.assert_called_once_with()

    def test_unexpected_rpc_errors_propagate_without_sync(self):
        for method, height in (("generatetoaddress", 0), ("createauxblock", 4)):
            with self.subTest(method=method):
                node = RecordingMiningNode(
                    args=["-pqbtcccandidateorigin=5"], candidates=[5], height=height)
                error = JSONRPCException({"code": -1, "message": "unrelated mining failure"})
                with patch.object(node, method, side_effect=error) as failing_rpc:
                    with self.assertRaises(JSONRPCException) as raised:
                        self.framework.generate(node, 1)
                    self.assertIs(raised.exception, error)
                    failing_rpc.assert_called_once()
                self.assertEqual(node.height, height)
                self.assertEqual(node.calls, [])
        self.framework.sync_all.assert_not_called()


if __name__ == "__main__":
    unittest.main()
