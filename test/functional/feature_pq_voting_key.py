#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent PQ funding authority, wallet recovery, rotation, and rollback."""

import json

from test_framework.test_framework import DashTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQVotingKeyTest(DashTestFramework):
    def set_test_params(self):
        self.set_dash_test_params(
            2, 1, extra_args=[["-nevmstartheight=10000"] for _ in range(2)],
            fast_dip3_enforcement=True)
        # Production operators disable wallets by default. Enable an empty
        # one here to distinguish missing voting authority from a missing RPC.
        self.extra_args[1].append("-disablewallet=0")

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def state(self, node=None):
        return (node or self.nodes[0]).protx_info(self.mn.proTxHash)["state"]

    def assert_tally(self, yes, no):
        def matches(node):
            self._throttled_bump_mocktime("pq_voting_key_sync", step=1)
            tally = node.gobject_get(self.proposal)["FundingResult"]
            return tally["YesCount"] == yes and tally["NoCount"] == no

        for node in self.nodes:
            self.wait_until(lambda node=node: matches(node), timeout=120)

    def vote(self, wallet, outcome):
        result = wallet.gobject_vote_alias(
            self.proposal, "funding", outcome, self.mn.proTxHash)
        assert_equal(result["detail"][self.mn.proTxHash]["result"], "success")

    def rotate(self, public_key):
        self.nodes[0].protx_update_registrar(
            self.mn.proTxHash, "", public_key, "", self.mn.collateral_address)
        self.bump_mocktime(1)
        self.generate(self.nodes[0], 1)
        return self.nodes[0].getbestblockhash()

    def advance_vote_time(self):
        # The one-hour vote interval also trips the controller's scheduler-
        # sleep detector. Complete that resync before testing vote relay.
        with self.nodes[0].assert_debug_log([
                "WARNING: no actions for too long, restarting sync..."]):
            self.bump_mocktime(3601)
            self.nodes[0].mockscheduler(1)
        assert self.sync_mnsync(self.nodes)

    def mature_key(self):
        self.advance_vote_time()
        self.generate(self.nodes[0], 6)

    def run_test(self):
        owner, operator = self.nodes
        if not operator.listwallets():
            operator.createwallet("voting-delegate", descriptors=True)
        self.mn = self.mninfo[0]
        public_a = self.mn.pqVotingPublicKey
        assert_equal(len(public_a), 64)
        assert_equal(self.state()["pqVotingPublicKey"], public_a)
        assert_equal(self.state()["pqVotingKeyVersion"], 1)
        details = owner.protx_list_wallet(1)
        assert_equal(len(details), 1)
        assert_equal(details[0]["pqVotingPublicKey"], public_a)
        assert_equal(details[0]["hasVotingKey"], True)
        assert "votingKey" not in details[0]
        initial_key_height = self.state()["pqVotingKeyActivationHeight"]
        self.rotate("")
        assert_equal(self.state()["pqVotingKeyVersion"], 1)
        assert_equal(self.state()["pqVotingKeyActivationHeight"], initial_key_height)

        # Keep automatic trigger votes outside this funding-authority fixture.
        owner.spork("SPORK_9_SUPERBLOCKS_ENABLED", 4070908800)
        self.wait_for_sporks_same(timeout=120)
        proposal_time = self.mocktime
        data = json.dumps({
            "type": 1,
            "name": "PQ_voting_authority",
            "start_epoch": proposal_time,
            "end_epoch": proposal_time + 86400,
            "payment_amount": 1,
            "payment_address": owner.getnewaddress(),
            "url": "https://syscoin.org",
        }).encode().hex()
        collateral = owner.gobject_prepare("0", 1, proposal_time, data)
        self.generate(owner, 6)
        self.bump_mocktime(6)
        self.proposal = owner.gobject_submit("0", 1, proposal_time, data, collateral)
        for node in self.nodes:
            self.wait_until(
                lambda node=node: self.proposal in node.gobject_list(), timeout=120)

        self.log.info("An operator key alone cannot cast an owner's funding vote")
        assert_raises_rpc_error(
            -8, "Private SLH voting key not known by wallet",
            operator.gobject_vote_alias,
            self.proposal, "funding", "yes", self.mn.proTxHash)
        assert_raises_rpc_error(
            -8, "online masternode SLH operator key",
            owner.gobject_vote_alias,
            self.proposal, "valid", "yes", self.mn.proTxHash)

        self.log.info("Encrypt, reload, and restore the wallet's independent voting key")
        passphrase = "pq-voting-regtest-passphrase"
        owner.encryptwallet(passphrase)
        assert_raises_rpc_error(
            -13, "walletpassphrase", owner.protx_generate_voting_key)
        assert_raises_rpc_error(
            -13, "walletpassphrase", owner.gobject_vote_alias,
            self.proposal, "funding", "yes", self.mn.proTxHash)
        owner.unloadwallet(self.default_wallet_name)
        owner.loadwallet(self.default_wallet_name)
        # Live wallet reload does not rerun startup's collateral auto-locking.
        owner.lockunspent(False, [{
            "txid": self.mn.collateral_txid,
            "vout": self.mn.collateral_vout,
        }])
        owner.walletpassphrase(passphrase, 3600)
        self.vote(owner, "yes")
        self.assert_tally(1, 0)

        backup = owner.datadir_path / "pq-voting-wallet.bak"
        owner.backupwallet(backup)
        owner.restorewallet("pq-voting-restored", backup)
        restored = owner.get_wallet_rpc("pq-voting-restored")
        assert_raises_rpc_error(
            -13, "walletpassphrase", restored.gobject_vote_alias,
            self.proposal, "funding", "yes", self.mn.proTxHash)
        self.advance_vote_time()
        restored.walletpassphrase(passphrase, 3600)
        self.vote(restored, "yes")
        self.assert_tally(1, 0)
        owner.unloadwallet("pq-voting-restored")
        owner.walletpassphrase(passphrase, 3600)

        # Delegation is explicit: only after the owner registers B may this
        # operator wallet, which generated B, vote on the owner's behalf.
        public_b = operator.protx_generate_voting_key()
        assert public_b != public_a
        rotation_block = self.rotate(public_b)
        assert_equal(self.state()["pqVotingKeyVersion"], 2)
        self.assert_tally(0, 0)
        assert_raises_rpc_error(
            -8, "Private SLH voting key not known by wallet",
            owner.gobject_vote_alias,
            self.proposal, "funding", "yes", self.mn.proTxHash)
        self.mature_key()
        self.vote(operator, "no")
        self.assert_tally(0, 1)

        self.log.info("Rollback restores A authority and its retained signed vote")
        for node in self.nodes:
            node.invalidateblock(rotation_block)
        self.sync_blocks()
        assert_equal(self.state()["pqVotingPublicKey"], public_a)
        assert_equal(self.state()["pqVotingKeyVersion"], 1)
        self.assert_tally(1, 0)
        for node in self.nodes:
            node.reconsiderblock(rotation_block)
        self.sync_blocks()
        assert_equal(self.state()["pqVotingPublicKey"], public_b)
        assert_equal(self.state()["pqVotingKeyVersion"], 2)
        self.assert_tally(0, 1)

        self.log.info("Returning to A creates version 3, not authority for old A votes")
        owner.walletpassphrase(passphrase, 3600)
        self.rotate(public_a)
        assert_equal(self.state()["pqVotingKeyVersion"], 3)
        self.assert_tally(0, 0)
        self.mature_key()
        owner.walletpassphrase(passphrase, 3600)
        self.vote(owner, "yes")
        self.assert_tally(1, 0)

        self.rotate("00" * 32)
        assert_equal(self.state()["pqVotingKeyVersion"], 4)
        assert_equal(self.state()["pqVotingPublicKey"], "00" * 32)
        self.assert_tally(0, 0)
        assert_raises_rpc_error(
            -8, "Masternode has no active SLH voting key",
            owner.gobject_vote_alias,
            self.proposal, "funding", "yes", self.mn.proTxHash)


if __name__ == "__main__":
    PQVotingKeyTest().main()
