#!/usr/bin/env python3
# Copyright (c) 2018-2024 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests around Syscoin governance."""

import json
import shutil
from test_framework.test_framework import DashTestFramework, initialize_datadir
from test_framework.util import assert_equal, satoshi_round, force_finish_mnsync
from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
)
GOVERNANCE_DELETION_DELAY = 10 * 60
SUPERBLOCK_PAYMENT_LIMIT_UP = 10
SUPERBLOCK_PAYMENT_LIMIT_DOWN = -10
SUPERBLOCK_PAYMENT_LIMIT_SAME = 0
GOVERNANCE_FEE_CONFIRMATIONS = 6
MASTERNODE_SYNC_TICK_SECONDS = 6
PROPOSAL_END_EPOCH = 60
class SyscoinGovernanceTest(DashTestFramework):
    def set_test_params(self):
        # Using adjusted v20 deployment params to test an edge case where superblock maturity window is equal to deployment window size
        self.set_dash_test_params(6, 5, fast_dip3_enforcement=True)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def prepare_object(self, object_type, parent_hash, creation_time, revision, name, amount, payment_address):
        proposal_rev = revision
        proposal_time = int(creation_time)
        proposal_template = {
            "type": object_type,
            "name": name,
            "start_epoch": proposal_time,
            "end_epoch": proposal_time + PROPOSAL_END_EPOCH,
            "payment_amount": float(amount),
            "payment_address": payment_address,
            "url": "https://syscoin.org"
        }
        proposal_hex = ''.join(format(x, '02x') for x in json.dumps(proposal_template).encode())
        collateral_hash = self.nodes[0].gobject_prepare(parent_hash, proposal_rev, proposal_time, proposal_hex)
        return {
            "parentHash": parent_hash,
            "collateralHash": collateral_hash,
            "createdAt": proposal_time,
            "revision": proposal_rev,
            "hex": proposal_hex,
            "data": proposal_template,
        }

    def check_superblockbudget(self, expected_budget):
        self.log.info(f"Check budget node {self.nodes[0].getsuperblockbudget()} vs expected {satoshi_round(expected_budget)}")
        assert_equal(self.nodes[0].getsuperblockbudget(), satoshi_round(expected_budget))

    def have_trigger_for_height(self, sb_block_height):
        count = 0
        self.bump_mocktime(1)
        for node in self.nodes:
            valid_triggers = node.gobject_list("valid", "triggers")
            for trigger in list(valid_triggers.values()):
                if json.loads(trigger["DataString"])["event_block_height"] != sb_block_height:
                    continue
                if trigger['AbsoluteYesCount'] > 0:
                    count = count + 1
                    break
        return count == len(self.nodes)

    def run_test(self):
        
        map_vote_outcomes = {
            0: "none",
            1: "yes",
            2: "no",
            3: "abstain"
        }
        map_vote_signals = {
            0: "none",
            1: "funding",
            2: "valid",
            3: "delete",
            4: "endorsed"
        }
        self.p0_payout_address = self.nodes[0].getnewaddress()
        self.p1_payout_address = self.nodes[0].getnewaddress()
        self.p2_payout_address = self.nodes[0].getnewaddress()
        self.p3_payout_address = self.nodes[0].getnewaddress()
        self.initial_budget = float(1500000.00000000)
        self.expected_budget = self.initial_budget

        # Ensure nodes are connected at the beginning
        for idx, node_outer in enumerate(self.nodes):
            for idx, node_inner in enumerate(self.nodes):
                if node_inner.index != node_outer.index:
                    self.connect_nodes(node_inner.index, node_outer.index, wait_for_connect=False)

        # Step 1: SB1 - Proposals to push budget up by 10%
        self.log.info("SB1 - Proposals to increase budget by 10%")
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.5, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.3, "address": self.p1_payout_address},
            {"amount": self.expected_budget * 0.3, "address": self.p2_payout_address}  # Total: 1.1 times the budget
        ])
        
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.expected_budget *= 1.10
        self.mine_superblock_and_check_budget(self.expected_budget)

        # Step 1: SB2 - Proposals to push budget up by 5%
        self.log.info("SB2 - Proposals to increase budget by 5%")
        # expire previous proposals
        self.bump_mocktime(int(PROPOSAL_END_EPOCH))
        self.generate(self.nodes[0], 5)
        self.bump_mocktime(int(GOVERNANCE_DELETION_DELAY + MASTERNODE_SYNC_TICK_SECONDS))  # delete prev proposals and advance ProcessTick
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.51, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.32, "address": self.p1_payout_address},
            {"amount": self.expected_budget * 0.22, "address": self.p2_payout_address}  # Total: 1.05 times the budget
        ])
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.expected_budget *= 1.10
        self.mine_superblock_and_check_budget(self.expected_budget)
        
        # Step 3: SB3 - Proposals to change proposals budget up by 4% and not see a change in the limit 
        self.log.info("SB3 - Proposals to increase budget by 4%")
        # expire previous proposals
        self.bump_mocktime(int(PROPOSAL_END_EPOCH))
        self.generate(self.nodes[0], 5)
        self.bump_mocktime(int(GOVERNANCE_DELETION_DELAY + MASTERNODE_SYNC_TICK_SECONDS))  # delete prev proposals and advance ProcessTick
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.52, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.29, "address": self.p1_payout_address},
            {"amount": self.expected_budget * 0.23, "address": self.p2_payout_address}  # Total: 1.04 times the budget
        ])
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.mine_superblock_and_check_budget(self.expected_budget)
        
        # Step 4: SB4 - Proposals to decrease budget by 10%
        self.log.info("SB4 - Proposals to decrease budget by 10%")
        # expire previous proposals
        self.bump_mocktime(int(PROPOSAL_END_EPOCH))
        self.generate(self.nodes[0], 5)
        self.bump_mocktime(int(GOVERNANCE_DELETION_DELAY + MASTERNODE_SYNC_TICK_SECONDS))  # delete prev proposals and advance ProcessTick
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.45, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.45, "address": self.p1_payout_address}  # Total: 0.9 times the budget
        ])
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.expected_budget *= 0.90
        self.mine_superblock_and_check_budget(self.expected_budget)

        # Step 5: SB5 - Proposals to change proposals budget down by 4% and not see a change in the limit
        self.log.info("SB5 - Proposals to decrease budget by 4%")
        # expire previous proposals
        self.bump_mocktime(int(PROPOSAL_END_EPOCH))
        self.generate(self.nodes[0], 5)
        self.bump_mocktime(int(GOVERNANCE_DELETION_DELAY + MASTERNODE_SYNC_TICK_SECONDS))  # delete prev proposals and advance ProcessTick
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.43, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.53, "address": self.p1_payout_address}  # Total: 0.96 times the budget
        ])
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.mine_superblock_and_check_budget(self.expected_budget)

        # Step 6: SB6 - Proposals to decrease budget by 5%
        self.log.info("SB6 - Proposals to decrease budget by 5%")
        # expire previous proposals
        self.bump_mocktime(int(PROPOSAL_END_EPOCH))
        self.generate(self.nodes[0], 5)
        self.bump_mocktime(int(GOVERNANCE_DELETION_DELAY + MASTERNODE_SYNC_TICK_SECONDS))  # delete prev proposals and advance ProcessTick
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        proposals = self.prepare_and_submit_proposals([
            {"amount": self.expected_budget * 0.1, "address": self.p0_payout_address},
            {"amount": self.expected_budget * 0.7, "address": self.p1_payout_address},
            {"amount": self.expected_budget * 0.15, "address": self.p3_payout_address}  # Total: 0.95 times the budget
        ])
        self.vote_on_proposals(proposals, map_vote_signals, map_vote_outcomes)
        self.expected_budget *= 0.90
        self.mine_superblock_and_check_budget(self.expected_budget)

        # Step 7: SB7 - Reindex and verify budget after reindex
        self.log.info("SB7 - Reindex and check budget")
        # previous proposals were against the higher budget so the limit should increase again with the same proposals
        self.expected_budget *= 1.1
        self.reindex_node_and_check_budget(self.expected_budget)

        # Step 8: SB8 - Resync from scratch and verify budget after resync
        self.log.info("SB8 - Resync and check budget")
        self.resync_node_and_check_budget(self.expected_budget)

    def prepare_and_submit_proposals(self, proposals):
        proposal_time = self.mocktime
        proposal_hashes = []
        proposal_datas = []
        for i, proposal in enumerate(proposals):
            amount = satoshi_round(proposal["amount"])
            address = proposal["address"]
            proposal_data = self.prepare_object(1, "%064x" % 0, proposal_time, 1, f"Proposal_{i}", amount, address)
            proposal_datas.append(proposal_data)
        self.generate(self.nodes[0], GOVERNANCE_FEE_CONFIRMATIONS)  # Generate 6 blocks to ensure proposal is processed
        self.bump_mocktime(6)
        self.sync_blocks()
        for i, proposal in enumerate(proposals):
            proposal_hash = self.nodes[0].gobject_submit("0", 1, proposal_time, proposal_datas[i]["hex"], proposal_datas[i]["collateralHash"])
            proposal_hashes.append(proposal_hash)
            self.log.info(f"Submitted proposal {i} with hash {proposal_hash}")  # Debug statement to confirm proposal creation
        return proposal_hashes

    def vote_on_proposals(self, proposal_hashes, map_vote_signals, map_vote_outcomes):
        self.log.info(f"Voting on proposals: {proposal_hashes}")  # Debug statement
        self.sync_gobject_list(len(proposal_hashes))  # Ensure all nodes have the proposals
        for proposal_hash in proposal_hashes:
            self.nodes[0].gobject_vote_many(proposal_hash, map_vote_signals[1], map_vote_outcomes[1])

    def sync_gobject_list(self, expected_count=4):
        # Ensures that each node has processed all governance objects
        def check_each_node_has_gobjects(node, expected_count=expected_count):
            self.bump_mocktime(1)
            return len(node.gobject_list("valid", "proposals")) == expected_count

        # Check for each node individually
        for i in range(len(self.nodes)):
            self.wait_until(lambda: check_each_node_has_gobjects(self.nodes[i]), timeout=10)
        
        # Double-check that all nodes are synchronized
        self.wait_until(lambda: all(len(node.gobject_list("valid", "proposals")) > 0 for node in self.nodes), timeout=10)


    def mine_superblock_and_check_budget(self, expected_budget):
        self.bump_mocktime(1)
        block_count = self.nodes[0].getblockcount()
        sb_cycle = self.nodes[0].getgovernanceinfo()['superblockcycle']
        n = sb_cycle - block_count % sb_cycle
        for _ in range(n - 1):
            self.generate(self.nodes[0], 1)
            self.bump_mocktime(1)
            self.sync_blocks()
        sb_block_height = self.nodes[0].getblockcount() + 1
        self.wait_until(lambda: self.have_trigger_for_height(sb_block_height), timeout=15)
        self.generate(self.nodes[0], 1)
        self.log.info(f"Mined superblock at block {self.nodes[0].getblockcount()}")
        self.sync_blocks()
        self.check_superblockbudget(expected_budget)

    def reindex_node_and_check_budget(self, expected_budget):
        self.bump_mocktime(1)
        block_count = self.nodes[0].getblockcount()
        sb_cycle = self.nodes[0].getgovernanceinfo()['superblockcycle']
        n = sb_cycle - block_count % sb_cycle
        for _ in range(n - 1):
            self.generate(self.nodes[0], 1)
            self.bump_mocktime(1)
            self.sync_blocks()
        sb_block_height = self.nodes[0].getblockcount() + 1
        self.stop_node(1)
        self.start_node(1, extra_args=['-reindex', *self.extra_args[1]])
        self.nodes[1].setnetworkactive(True)
        for idx, node_outer in enumerate(self.nodes):
            for idx, node_inner in enumerate(self.nodes):
                if node_inner.index != node_outer.index:
                    self.connect_nodes(node_inner.index, node_outer.index, wait_for_connect=False)

        self.sync_mnsync([self.nodes[1]])
        self.wait_until(lambda: self.have_trigger_for_height(sb_block_height), timeout=15)
        self.generate(self.nodes[0], 1)
        self.log.info(f"Mined superblock at block {self.nodes[0].getblockcount()}")
        self.bump_mocktime(1)
        self.sync_blocks()
        self.log.info(f"Check budget node {self.nodes[1].getsuperblockbudget()} vs expected {satoshi_round(expected_budget)}")
        assert_equal(self.nodes[1].getsuperblockbudget(), satoshi_round(expected_budget))

    def resync_node_and_check_budget(self, expected_budget):
        self.bump_mocktime(1)
        block_count = self.nodes[0].getblockcount()
        sb_cycle = self.nodes[0].getgovernanceinfo()['superblockcycle']
        n = sb_cycle - block_count % sb_cycle
        for _ in range(n - 1):
            self.generate(self.nodes[0], 1)
            self.bump_mocktime(1)
            self.sync_blocks()
        sb_block_height = self.nodes[0].getblockcount() + 1
        self.stop_node(1)
        shutil.rmtree(self.nodes[1].datadir_path)
        initialize_datadir(self.options.tmpdir, 1, self.chain)
        self.start_node(1, extra_args=['-networkactive=0', *self.extra_args[1]])
        # always starts at initial budget before sync
        assert_equal(self.nodes[1].getsuperblockbudget(), satoshi_round(self.initial_budget))
        self.nodes[1].setnetworkactive(True)
        for idx, node_outer in enumerate(self.nodes):
            for idx, node_inner in enumerate(self.nodes):
                if node_inner.index != node_outer.index:
                    self.connect_nodes(node_inner.index, node_outer.index, wait_for_connect=False)

        self.sync_mnsync([self.nodes[1]])
        self.wait_until(lambda: self.have_trigger_for_height(sb_block_height), timeout=15)
        self.generate(self.nodes[0], 1)
        self.log.info(f"Mined superblock at block {self.nodes[0].getblockcount()}")
        self.bump_mocktime(1)
        self.sync_blocks()
        self.log.info(f"Check budget node {self.nodes[1].getsuperblockbudget()} vs expected {satoshi_round(expected_budget)}")
        assert_equal(self.nodes[1].getsuperblockbudget(), satoshi_round(expected_budget))
if __name__ == '__main__':
    SyscoinGovernanceTest().main()
