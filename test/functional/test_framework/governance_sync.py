#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for governance functional-test relay barriers."""

from types import SimpleNamespace
import json
import unittest

from feature_governance import SyscoinGovernanceTest as TriggerTest
from feature_governance_dynamic import SyscoinGovernanceTest as DynamicTest


class TestGovernanceSync(unittest.TestCase):
    def test_initial_trigger_vote_advances_clock_and_requires_exact_count(self):
        case = object.__new__(TriggerTest)
        vote_count = {"target": 1}
        clock_steps = []

        def advance_clock(key, *, step):
            self.assertEqual(key, "feature_governance_initial_vote_sync")
            self.assertEqual(step, 1)
            clock_steps.append(step)

        case._throttled_bump_mocktime = advance_clock

        def list_triggers(*_):
            triggers = {"other": {"YesCount": 1}}
            # Model a vote whose GETDATA request is not due until mock time advances.
            if sum(clock_steps) >= 2:
                triggers["target"] = {"YesCount": vote_count["target"]}
            return triggers

        node = SimpleNamespace(gobject_list=list_triggers)

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 5)
            self.assertFalse(predicate(), "another trigger's vote must not satisfy this wait")
            self.assertTrue(predicate(), "mock time must release the delayed vote request")
            vote_count["target"] = 2
            self.assertFalse(predicate(), "extra votes must not satisfy the exact-count assertion")

        case.wait_until = wait_until
        case.wait_for_initial_trigger_vote(node, "target")
        self.assertEqual(clock_steps, [1, 1, 1])

    def test_controller_link_must_be_outbound_relay_and_handshaken(self):
        for inbound, masternode in [(True, False), (False, True)]:
            with self.subTest(inbound=inbound, masternode=masternode):
                case = object.__new__(TriggerTest)
                controller_subver = "controller"
                peers = [{"subver": controller_subver, "inbound": inbound,
                          "masternode": masternode, "bytesrecv_per_msg": {"pong": 32}}]
                node = SimpleNamespace(index=3, getpeerinfo=lambda: peers)
                case.nodes = [SimpleNamespace(getnetworkinfo=lambda: {"subversion": controller_subver})]
                calls = []

                def disconnect(a, b):
                    self.assertEqual((a, b), (3, 0))
                    peers.clear()
                    calls.append("disconnect")

                def connect(a, b):
                    self.assertEqual((a, b), (3, 0))
                    peers.append({"subver": controller_subver, "inbound": False,
                                  "masternode": False, "bytesrecv_per_msg": {}})
                    calls.append("connect")

                def wait_until(predicate, *, timeout):
                    self.assertEqual(timeout, 5)
                    self.assertFalse(predicate(), "an unfinished handshake must not pass")
                    peers[0]["bytesrecv_per_msg"]["pong"] = 32
                    self.assertTrue(predicate())

                case.disconnect_nodes = disconnect
                case.connect_nodes = connect
                case.wait_until = wait_until
                case.connect_masternode_to_controller(node)
                self.assertEqual(calls, ["disconnect", "connect"])

                # The established fixture link should not be disconnected again.
                case.wait_until = lambda predicate, **_: self.assertTrue(predicate())
                case.connect_masternode_to_controller(node)
                self.assertEqual(calls, ["disconnect", "connect"])

    def test_superblock_waits_for_matching_dominant_winner_votes(self):
        height = 175
        case = object.__new__(TriggerTest)
        case.mn_count = 5
        case._throttled_bump_mocktime = lambda *_args, **_kwargs: None
        winner = {
            "DataString": json.dumps({"event_block_height": height}),
            "Hash": "winning-data", "YesCount": 4, "NoCount": 1,
            "AbstainCount": 0, "AbsoluteYesCount": 3,
            "fCachedFunding": False,
        }
        # A late rival may have no NO votes until another block arrives. Its
        # incomplete tally must not deadlock a winner that cannot be overtaken.
        rival = dict(winner, Hash="rival-data", YesCount=1, NoCount=0, AbsoluteYesCount=1)
        expected_votes = {str(i): f"voter{i}:1:{'yes' if i < 4 else 'no'}:funding" for i in range(5)}
        votes = [dict(expected_votes) for _ in range(6)]
        triggers = [{"winner": dict(winner), "rival": dict(rival)} for _ in range(6)]
        case.nodes = [SimpleNamespace(
            getgovernanceinfo=lambda: {"governanceminquorum": 1},
            gobject_list=lambda *_args, i=i: triggers[i],
            gobject_getcurrentvotes=lambda _hash, i=i: votes[i],
        ) for i in range(6)]

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 30)
            votes[-1].pop("0")
            self.assertFalse(predicate(), "a missing winner vote must block mining")
            votes[-1] = dict(expected_votes)
            votes[-1]["0"] = "voter0:2:yes:funding"
            self.assertFalse(predicate(), "equal tallies must not hide different current votes")
            votes[-1] = dict(expected_votes)
            self.assertTrue(predicate(), "incomplete rival votes and stale cache flags must not block a dominant winner")

        case.wait_until = wait_until
        case.wait_for_superblock_votes(height)

    def test_superblock_three_two_split_waits_only_for_irreversible_rival_bound(self):
        height = 200
        case = object.__new__(TriggerTest)
        case.mn_count = 5
        case._throttled_bump_mocktime = lambda *_args, **_kwargs: None
        winner = {
            "DataString": json.dumps({"event_block_height": height}),
            "Hash": "winning-data", "YesCount": 3, "NoCount": 2,
            "AbstainCount": 0, "AbsoluteYesCount": 1,
        }
        rival = dict(winner, Hash="rival-data", YesCount=2, NoCount=0, AbsoluteYesCount=2)
        winner_votes = {str(i): f"voter{i}:1:{'yes' if i < 3 else 'no'}:funding" for i in range(5)}
        rival_votes = {str(i): f"voter{i}:1:yes:funding" for i in (3, 4)}
        votes = [{"winner": dict(winner_votes), "rival": dict(rival_votes)} for _ in range(6)]
        triggers = [{"winner": dict(winner), "rival": dict(rival)} for _ in range(6)]
        case.nodes = [SimpleNamespace(
            getgovernanceinfo=lambda: {"governanceminquorum": 1},
            gobject_list=lambda *_args, i=i: triggers[i],
            gobject_getcurrentvotes=lambda trigger_hash, i=i: votes[i][trigger_hash],
        ) for i in range(6)]

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 30)
            self.assertFalse(predicate(), "a rival which can overtake the winner is not ready")
            for node_votes in votes:
                node_votes["rival"]["0"] = "voter0:2:no:funding"
            self.assertFalse(predicate(), "a possible tie must still block mining")
            for node_votes in votes[:-1]:
                node_votes["rival"]["1"] = "voter1:2:no:funding"
            self.assertFalse(predicate(), "every node must have the same irreversible winner")
            votes[-1]["rival"]["1"] = "voter1:2:no:funding"
            self.assertTrue(predicate(), "the rival's fifth vote is unnecessary once it cannot catch the winner")
            for node_votes in votes:
                node_votes["rival"].pop("3")
                node_votes["rival"].pop("4")
            self.assertFalse(predicate(), "unseen YES voters could still make another trigger win")
            for node_votes in votes:
                node_votes["rival"].update(rival_votes)
            self.assertTrue(predicate())
            votes[-1]["rival"]["0"] = "voter0:2:yes:funding"
            self.assertFalse(predicate(), "a voter apparently supporting two triggers is not settled")

        case.wait_until = wait_until
        case.wait_for_superblock_votes(height)

    def test_trigger_barrier_checks_every_voter_and_exact_hashes(self):
        expected = {"isolated", "winning"}
        late_hashes = {"other", "winning"}
        case = object.__new__(TriggerTest)
        case.nodes = [
            SimpleNamespace(gobject_list=lambda *_: dict.fromkeys(expected)),
            SimpleNamespace(gobject_list=lambda *_: dict.fromkeys(late_hashes)),
            SimpleNamespace(gobject_list=lambda *_: dict.fromkeys(expected)),
        ]
        case._throttled_bump_mocktime = lambda *_args, **_kwargs: None
        checked = []

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 5)
            self.assertFalse(predicate(), "matching counts must not substitute for matching hashes")
            late_hashes.clear()
            self.assertFalse(predicate(), "a lagging voter must keep the barrier closed")
            late_hashes.update(expected)
            self.assertTrue(predicate())
            checked.append(True)

        case.wait_until = wait_until
        case.wait_for_trigger_convergence(expected)
        self.assertEqual(checked, [True])

    def test_proposal_vote_barrier_waits_for_every_proposal_on_every_node(self):
        proposal_hashes = ["first", "second"]
        votes = [{proposal_hash: 0 for proposal_hash in proposal_hashes} for _ in range(3)]
        case = object.__new__(DynamicTest)
        case.mn_count = 5
        case.log = SimpleNamespace(info=lambda *_: None)
        case._throttled_bump_mocktime = lambda *_args, **_kwargs: None
        case.sync_gobject_list = lambda count: self.assertEqual(count, 2)

        def vote_many(proposal_hash, signal, outcome):
            self.assertEqual((signal, outcome), ("funding", "yes"))
            votes[0][proposal_hash] = case.mn_count

        case.nodes = [
            SimpleNamespace(
                gobject_vote_many=vote_many,
                gobject_get=lambda proposal_hash, index=index: {
                    "FundingResult": {"YesCount": votes[index][proposal_hash]}
                },
            ) for index in range(3)
        ]
        checked = []

        def wait_until(predicate, *, timeout):
            self.assertEqual(timeout, 10)
            self.assertFalse(predicate(), "controller acceptance is not network convergence")
            votes[1].update(votes[0])
            votes[2]["first"] = case.mn_count
            self.assertFalse(predicate(), "one missing proposal must keep the barrier closed")
            votes[2]["second"] = case.mn_count
            self.assertTrue(predicate())
            checked.append(True)

        case.wait_until = wait_until
        case.vote_on_proposals(proposal_hashes, {1: "funding"}, {1: "yes"})
        self.assertEqual(checked, [True])
