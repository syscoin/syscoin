#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for the functional DKG connection barrier."""

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from .test_framework import DashTestFramework


class TestQuorumConnections(unittest.TestCase):
    QUORUM = "current-quorum"

    def member(self, protx_hash, connections, *, quorum=QUORUM):
        status = {
            "session": [{"status": {"quorumHash": quorum}}],
            "quorumConnections": [{"quorumHash": quorum, "quorumConnections": connections}],
        }
        member = SimpleNamespace(proTxHash=protx_hash, node=SimpleNamespace(quorum_dkgstatus=lambda: status))
        return member, status

    @staticmethod
    def connection(protx_hash, *, connected=True, outbound=True):
        return {"proTxHash": protx_hash, "connected": connected, "outbound": outbound}

    def check_barrier(self, members, assertions, *, count, expected_connections=1, require_outbound_ready=False):
        case = object.__new__(DashTestFramework)
        retries = []

        def wait(predicate, *, timeout):
            self.assertEqual(timeout, 7)
            assertions(predicate, retries)

        with patch("test_framework.test_framework.wait_until_helper_internal", side_effect=wait):
            case.wait_for_quorum_connections(self.QUORUM, expected_connections, members, timeout=7,
                                             wait_proc=lambda: retries.append(True), expected_member_count=count,
                                             require_outbound_ready=require_outbound_ready)

    def test_later_member_must_be_connected(self):
        first, _ = self.member("first", [self.connection("second")])
        second, status = self.member("second", [self.connection("first", connected=False)])

        def assertions(predicate, retries):
            self.assertFalse(predicate(), "the first ready member must not release the barrier")
            self.assertEqual(retries, [True])
            status["quorumConnections"][0]["quorumConnections"][0]["connected"] = True
            self.assertTrue(predicate())

        self.check_barrier([first, second], assertions, count=2)

    def test_session_and_connections_must_match_current_quorum(self):
        first, _ = self.member("first", [self.connection("second")])
        second, status = self.member("second", [self.connection("first")], quorum="old-quorum")

        def assertions(predicate, _):
            self.assertFalse(predicate(), "an old session must not count as a current participant")
            status["session"][0]["status"]["quorumHash"] = self.QUORUM
            self.assertFalse(predicate(), "a current session with old connections is not ready")
            status["quorumConnections"][0]["quorumHash"] = self.QUORUM
            self.assertTrue(predicate())

        self.check_barrier([first, second], assertions, count=2)

    def test_nonmembers_are_skipped_but_expected_member_count_is_required(self):
        first, _ = self.member("first", [self.connection("second")])
        second, status = self.member("second", [self.connection("first")])
        observer, _ = self.member("observer", [], quorum="old-quorum")

        def assertions(predicate, _):
            self.assertTrue(predicate(), "online MNs outside this quorum must not block its members")
            status["session"] = []
            self.assertFalse(predicate(), "the remaining ready member cannot hide a missing participant")

        self.check_barrier([first, second, observer], assertions, count=2)

    def test_inbound_count_cannot_hide_an_unready_outbound_relay(self):
        first, status = self.member("first", [
            self.connection("second", outbound=False),
            self.connection("third", outbound=False),
            self.connection("fourth", connected=False),
        ])
        second, _ = self.member("second", [self.connection("first"), self.connection("third")])
        third, _ = self.member("third", [self.connection("first"), self.connection("second")])

        fourth, _ = self.member("fourth", [self.connection("first"), self.connection("second")])

        def assertions(predicate, _):
            self.assertFalse(predicate(), "two inbound connections cannot replace an outgoing relay")
            status["quorumConnections"][0]["quorumConnections"][2]["connected"] = True
            self.assertTrue(predicate())

        self.check_barrier([first, second, third, fourth], assertions, count=4,
                           expected_connections=2, require_outbound_ready=True)

    def test_explicit_reduced_connection_expectation_is_preserved(self):
        first, _ = self.member("first", [self.connection("second", connected=False)])
        second, _ = self.member("second", [])
        self.check_barrier([first, second], lambda predicate, _: self.assertTrue(predicate()),
                           count=2, expected_connections=0)

    def test_no_current_sessions_cannot_pass(self):
        observer, _ = self.member("observer", [], quorum="old-quorum")
        self.check_barrier([observer], lambda predicate, _: self.assertFalse(predicate()),
                           count=1, expected_connections=0)
