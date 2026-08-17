#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Focused post-quantum deterministic-masternode operator lifecycle coverage."""

from test_framework.messages import CTransaction, from_hex
from test_framework.script import OP_RETURN
from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import (
    Decimal,
    assert_equal,
    assert_raises_rpc_error,
    force_finish_mnsync,
    get_rpc_proxy,
    p2p_port,
)


class PQOperatorLifecycleTest(SyscoinTestFramework):
    REGTEST_GENESIS = "28a2c2d251f46fac05ade79085cbcb2ae4ec67ea24f1f1c7b40a348c00521194"
    FIXTURE_C11_SEED = "11" * 32
    FIXTURE_C11_SEED_HASH = "3fd852825ad83c1d655939d69cbe8afbbfc94c46ca22585aed5303b8360d4259"
    FIXTURE_TREE_ID = "2ed3eab46dd542daf231ad8519f0e81c9d45aeec9904ade4272befd99c9b0b18"
    FIXTURE_ROOT = "3e7d12bd5e7fc0bd4b7aa2201263c6e95c36cf1bdbca2ade72326682732201d2"

    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)
        parser.add_argument(
            "--real-pq-tree",
            action="store_true",
            help="regenerate the full 65,536-leaf C11 operator tree",
        )

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            "-dip3params=1:1",
            "-mncollateral=100",
            "-sporkkey=cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW",
        ]
        # The commitment was generated once by the production builder for this
        # exact regtest genesis, seed, tree ID, generation, and first epoch.
        self.extra_args.append(
            "-pqoperatorcommitmenttestfixture=%s:%s:%s:1:0:%s" % (
                self.REGTEST_GENESIS,
                self.FIXTURE_C11_SEED_HASH,
                self.FIXTURE_TREE_ID,
                self.FIXTURE_ROOT,
            )
        )
        if self.options.real_pq_tree:
            self.extra_args.append("-pqoperatorcommitmenttestfixtureverify=1")

    def skip_test_if_missing_module(self):
        if self.options.descriptors is not True:
            self.log.info("PQ operator lifecycle test forces descriptor wallets")
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(1)
        self.start_node(0, extra_args=self.extra_args)
        force_finish_mnsync(self.nodes[0])
        # The migration anchor is discovered from this bootstrap chain, so no
        # exact PQ governance registry exists yet. Keep superblocks off only
        # until that anchor is installed; otherwise the first superblock must
        # correctly fail closed on unavailable governance state.
        self.nodes[0].spork("SPORK_9_SUPERBLOCKS_ENABLED", 4070908800)

    def ensure_controller_wallet(self):
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)

    @staticmethod
    def consensus_protx_info(info):
        result = dict(info)
        result.pop("metaInfo", None)
        return result

    @staticmethod
    def assert_payment_audit_clear(info):
        assert_equal(info["paymentAudit"], {
            "consecutiveMisses": 0,
            "paymentWithheld": False,
            "paymentEligibleSinceHeight": -1,
        })

    def configure_pq_migration_anchor(self):
        node = self.nodes[0]
        anchor = node.protx_migration_info()
        assert_equal(anchor["height"], node.getblockcount())
        registration_cutoff_blocks = 288
        roster_snapshot_lag = 288
        assert registration_cutoff_blocks >= roster_snapshot_lag
        self.extra_args += [
            "-pqlegacyanchorheight=%d" % anchor["height"],
            "-pqlegacyanchorblockhash=%s" % anchor["blockHash"],
            "-pqlegacydmnstatehash=%s" % anchor["dmnStateHash"],
            "-pqlegacypqregistrystatehash=%s" % anchor["pqRegistryStateHash"],
            "-pqpreparationheight=%d" % anchor["height"],
            "-pqchainlockepochorigin=1440",
            "-pqregistrationcutoffblocks=%d" % registration_cutoff_blocks,
            "-pqrostersnapshotlag=%d" % roster_snapshot_lag,
            "-pqfuturehorizonepochs=8",
            "-pqbtcccandidateorigin=1000000",
            "-pqbtccreceiptanchorheight=%d" % anchor["height"],
            "-pqbtccreceiptanchorblockhash=%s" % anchor["blockHash"],
            "-pqbtccreceiptanchorcursorheight=-1",
            "-pqbtccreceiptanchorcursorsyshash=%s" % ("0" * 64),
            "-pqbtccreceiptanchorcursorbtchash=%s" % ("0" * 64),
            "-pqbtccreceiptanchorstatehash=%s" % ("0" * 64),
        ]
        self.stop_node(0)
        node.extra_args = list(self.extra_args)
        self.start_node(0, extra_args=self.extra_args + ["-reindex"])
        self.ensure_controller_wallet()
        force_finish_mnsync(node)
        assert_equal(node.protx_migration_info(), anchor)
        # From this point onward the configured PQ registry can publish exact
        # governance readiness, so exercise the normal fail-closed path.
        node.spork("SPORK_9_SUPERBLOCKS_ENABLED", 0)

    def create_masternode(self):
        node = self.nodes[0]
        operator_keys = node.protx_generate_operator_keypair()
        # Keep the precomputed commitment bound to a known independent seed;
        # --real-pq-tree regenerates the same configuration from scratch.
        operator_keys["c11Seed"] = self.FIXTURE_C11_SEED
        funds_address = node.getnewaddress()
        owner_address = node.getnewaddress()
        payout_address = node.getnewaddress()
        node.sendtoaddress(funds_address, Decimal("100.001"))
        protx_hash = node.protx_register_fund(
            node.getnewaddress(),
            "127.0.0.1:%d" % p2p_port(2),
            owner_address,
            "",
            owner_address,
            0,
            payout_address,
            funds_address,
        )
        self.generate(node, 1)
        info = node.protx_info(protx_hash)
        assert info["state"]["PoSeBanHeight"] != -1
        self.assert_payment_audit_clear(info)
        listed = [
            entry for entry in node.protx_list("registered", True)
            if entry["proTxHash"] == protx_hash
        ]
        assert_equal(len(listed), 1)
        self.assert_payment_audit_clear(listed[0])
        return {
            "protx_hash": protx_hash,
            "funds_address": funds_address,
            "operator_key": operator_keys["operatorKey"],
            "c11_seed": operator_keys["c11Seed"],
            "service": "127.0.0.1:%d" % p2p_port(2),
        }

    def create_independent_mempool_tx(self):
        node = self.nodes[0]
        fixture_key = node.get_deterministic_priv_key()
        fixture_amount = Decimal("0.01000000")
        fixture_fee = Decimal("0.00001000")
        funding_txid = node.sendtoaddress(fixture_key.address, fixture_amount)
        funding_tx = node.getrawtransaction(funding_txid, 1)
        fixture_script = node.getaddressinfo(
            fixture_key.address)["scriptPubKey"]
        fixture_outputs = [
            output for output in funding_tx["vout"]
            if output["value"] == fixture_amount
            and output["scriptPubKey"]["hex"] == fixture_script
        ]
        assert_equal(len(fixture_outputs), 1)
        fixture_output = fixture_outputs[0]
        self.generate(node, 1)

        prevout = {
            "txid": funding_txid,
            "vout": fixture_output["n"],
            "scriptPubKey": fixture_output["scriptPubKey"]["hex"],
            "amount": fixture_amount,
        }
        unsigned = node.createrawtransaction(
            [{"txid": funding_txid, "vout": fixture_output["n"]}],
            {node.getnewaddress(): fixture_amount - fixture_fee},
        )
        signed = node.signrawtransactionwithkey(
            unsigned, [fixture_key.key], [prevout])
        assert_equal(signed["complete"], True)
        assert "errors" not in signed
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        return signed["hex"]

    @staticmethod
    def resign_with_wallet(node, transaction_hex):
        transaction = from_hex(CTransaction(), transaction_hex)
        for tx_input in transaction.vin:
            tx_input.scriptSig = b""
        for witness in transaction.wit.vtxinwit:
            witness.scriptWitness.stack = []
        signed = node.signrawtransactionwithwallet(transaction.serialize().hex())
        assert_equal(signed["complete"], True)
        assert "errors" not in signed
        return signed["hex"]

    @staticmethod
    def assert_script_rejection(result):
        assert_equal(result["allowed"], False)
        reject_reason = result["reject-reason"]
        assert reject_reason.startswith((
            "mandatory-script-verify-flag-failed",
            "non-mandatory-script-verify-flag",
        )), reject_reason
        assert not reject_reason.startswith("bad-pq-"), reject_reason

    def check_mempool_auth_order(self, raw_registration, independent_tx):
        node = self.nodes[0]
        assert_equal(
            node.testmempoolaccept([raw_registration])[0]["allowed"], True)

        transaction = from_hex(CTransaction(), raw_registration)
        payload_outputs = [
            output for output in transaction.vout
            if output.scriptPubKey and output.scriptPubKey[0] == OP_RETURN
        ]
        assert_equal(len(payload_outputs), 1)
        corrupted_payload = bytearray(payload_outputs[0].scriptPubKey)
        corrupted_payload[-1] ^= 1
        payload_outputs[0].scriptPubKey = bytes(corrupted_payload)

        corrupted_hex = transaction.serialize().hex()
        self.assert_script_rejection(
            node.testmempoolaccept([corrupted_hex])[0])

        resigned_hex = self.resign_with_wallet(node, corrupted_hex)
        pq_result = node.testmempoolaccept([resigned_hex])[0]
        assert_equal(pq_result["allowed"], False)
        assert pq_result["reject-reason"].startswith("bad-pq-"), pq_result

        package_results = node.testmempoolaccept(
            [independent_tx, corrupted_hex])
        assert_equal(len(package_results), 2)
        assert_equal(package_results[0]["allowed"], True)
        self.assert_script_rejection(package_results[1])

    def register_initial_root(self, masternode, independent_tx):
        node = self.nodes[0]
        # Rotation deliberately omits newC11Seed so it preserves this
        # commitment. --real-pq-tree is the production builder oracle.
        operator_rpc = get_rpc_proxy(
            node.url,
            node.index,
            timeout=1200 if self.options.real_pq_tree else 120,
            coveragedir=node.coverage_dir,
        )
        if not self.options.real_pq_tree:
            assert_raises_rpc_error(
                -8,
                "test fixture does not match the requested seed or schedule",
                operator_rpc.protx_register_operator_key,
                masternode["protx_hash"],
                masternode["operator_key"],
                "22" * 32,
                masternode["funds_address"],
                False,
            )
        raw_registration = operator_rpc.protx_register_operator_key(
            masternode["protx_hash"],
            masternode["operator_key"],
            masternode["c11_seed"],
            masternode["funds_address"],
            False,
        )
        self.check_mempool_auth_order(raw_registration, independent_tx)
        node.sendrawtransaction(raw_registration)
        self.generate(node, 1)
        initial_key = node.protx_operator_key_info(masternode["protx_hash"])
        assert_equal(initial_key["keyVersion"], 1)
        return operator_rpc, initial_key

    def rotate_operator_on_same_root(self, operator_rpc, masternode,
                                     initial_key):
        node = self.nodes[0]
        replacement = node.protx_generate_operator_keypair()
        raw_rotation = operator_rpc.protx_rotate_operator_key(
            masternode["protx_hash"],
            masternode["operator_key"],
            replacement["operatorKey"],
            masternode["funds_address"],
            False,
        )
        assert_equal(node.testmempoolaccept([raw_rotation])[0]["allowed"], True)
        node.sendrawtransaction(raw_rotation)
        self.generate(node, 1)

        rotated_key = node.protx_operator_key_info(masternode["protx_hash"])
        assert_equal(rotated_key["keyVersion"], 2)
        assert rotated_key["publicKey"] != initial_key["publicKey"]
        masternode["operator_key"] = replacement["operatorKey"]
        return rotated_key

    def update_service(self, masternode):
        node = self.nodes[0]
        node.protx_update_service(
            masternode["protx_hash"],
            masternode["service"],
            masternode["operator_key"],
            "",
            "",
            masternode["funds_address"],
        )
        self.generate(node, 1)
        info = node.protx_info(masternode["protx_hash"])
        assert_equal(info["state"]["service"], masternode["service"])
        assert_equal(info["state"]["PoSeBanHeight"], -1)
        self.assert_payment_audit_clear(info)
        return self.consensus_protx_info(info)

    def check_restart_and_fresh_replay(self, masternode, expected_info,
                                       expected_operator_info):
        node = self.nodes[0]
        expected_tip = node.getbestblockhash()
        expected_migration = node.protx_migration_info()

        self.restart_node(0, extra_args=self.extra_args)
        self.ensure_controller_wallet()
        force_finish_mnsync(node)
        assert_equal(node.getbestblockhash(), expected_tip)
        assert_equal(
            self.consensus_protx_info(
                node.protx_info(masternode["protx_hash"])),
            expected_info,
        )
        assert_equal(
            node.protx_operator_key_info(masternode["protx_hash"]),
            expected_operator_info,
        )

        self.add_nodes(1, offset=1, extra_args=[self.extra_args])
        self.start_node(1)
        self.connect_nodes(1, 0)
        self.sync_blocks(self.nodes[:2], timeout=180)
        force_finish_mnsync(self.nodes[1])
        assert_equal(self.nodes[1].getbestblockhash(), expected_tip)
        assert_equal(
            self.consensus_protx_info(
                self.nodes[1].protx_info(masternode["protx_hash"])),
            expected_info,
        )
        assert_equal(
            self.nodes[1].protx_operator_key_info(masternode["protx_hash"]),
            expected_operator_info,
        )
        assert_equal(self.nodes[1].protx_migration_info(), expected_migration)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        while node.getbalance() < Decimal("101"):
            self.generatetoaddress(node, 10, node.getnewaddress())

        self.configure_pq_migration_anchor()
        masternode = self.create_masternode()
        independent_tx = self.create_independent_mempool_tx()
        operator_rpc, initial_key = self.register_initial_root(
            masternode, independent_tx)
        rotated_key = self.rotate_operator_on_same_root(
            operator_rpc, masternode, initial_key)
        expected_info = self.update_service(masternode)
        self.check_restart_and_fresh_replay(
            masternode, expected_info, rotated_key)


if __name__ == "__main__":
    PQOperatorLifecycleTest().main()
