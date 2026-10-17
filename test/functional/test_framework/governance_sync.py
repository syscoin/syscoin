#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for governance functional-test relay barriers."""

from types import SimpleNamespace
import unittest

from feature_governance import SyscoinGovernanceTest as TriggerTest
from feature_governance_dynamic import SyscoinGovernanceTest as DynamicTest


class TestGovernanceSync(unittest.TestCase):
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
