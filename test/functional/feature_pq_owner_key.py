#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PQ ownership at activation, late enrollment, and hosted operator setup."""

from io import BytesIO

from feature_pq_operator_lifecycle import PQOperatorLifecycleTest
from test_framework.messages import CTransaction, deser_string
from test_framework.util import (
    Decimal,
    assert_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    p2p_port,
)


class PQOwnerKeyTest(PQOperatorLifecycleTest):
    def set_test_params(self):
        super().set_test_params()

    def wallets(self):
        node = self.nodes[0]
        for name in (self.default_wallet_name, "customer", "provider"):
            if name not in node.listwallets():
                node.loadwallet(name)
        self.controller = node.get_wallet_rpc(self.default_wallet_name)
        self.customer = node.get_wallet_rpc("customer")
        self.provider = get_rpc_proxy(
            node.url + "/wallet/provider", node.index, timeout=1200,
            coveragedir=node.coverage_dir)

    def create_owned_masternode(self, service_index):
        node = self.nodes[0]
        owner_address = self.customer.getnewaddress()
        funds_address = self.controller.getnewaddress()
        fee_address = self.provider.getnewaddress()
        self.controller.sendtoaddress(funds_address, Decimal("100.001"))
        self.controller.sendtoaddress(fee_address, 1)
        self.generate(node, 1)
        keys = self.provider.protx_generate_operator_keypair()
        protx_hash = self.controller.protx_register_fund(
            self.controller.getnewaddress(),
            "127.0.0.1:%d" % p2p_port(service_index),
            owner_address, "", owner_address, 0,
            self.controller.getnewaddress(), funds_address)
        self.generate(node, 1)
        return {
            "protx_hash": protx_hash,
            "operator_key": keys["operatorKey"],
            "chainlock_seed": keys["chainlockSeed"],
            "fee_address": fee_address,
        }

    def prepare(self, mn):
        result = self.provider.protx_register_operator_prepare(
            mn["protx_hash"], mn["operator_key"], mn["chainlock_seed"],
            mn["fee_address"])
        request = result["request"]
        # Public handoff data must never carry the provider's private material.
        assert mn["operator_key"] not in request
        assert mn["chainlock_seed"] not in request
        decoded = self.customer.protx_decode_operator_request(request)
        assert_equal(decoded["proTxHash"], mn["protx_hash"])
        assert_equal(decoded["genesisHash"], self.nodes[0].getblockhash(0))
        assert_equal(decoded["ownerType"], self.state(mn)["ownerKeyType"])
        assert_equal(decoded["ownerKeyVersion"], self.state(mn).get("pqOwnerKeyVersion", 0))
        assert_equal(len(decoded["operatorPublicKey"]), 64)
        assert_equal(len(decoded["chainlockRoot"]), 64)
        return request

    def handoff(self, mn, *, request=None):
        node = self.nodes[0]
        request = request or self.prepare(mn)
        assert_equal(self.customer.getbalance(), 0)
        assert_raises_rpc_error(
            None, None, self.provider.protx_register_operator_sign, request)
        corrupt_request = request[:-2] + ("00" if request[-2:] != "00" else "01")
        assert_raises_rpc_error(
            None, None, self.customer.protx_register_operator_sign,
            corrupt_request)
        # Owner authority binds the provider's complete funded transaction,
        # including change. Keep the original seal and alter only that output.
        stream = BytesIO(bytes.fromhex(request))
        deser_string(stream)  # envelope domain
        stream.read(32)  # genesis hash
        prefix = stream.getvalue()[:stream.tell()]
        transaction = CTransaction()
        transaction.deserialize(stream)
        seal = stream.read()
        change = next(output for output in transaction.vout if output.nValue > 0)
        change.nValue -= 1
        changed_output_request = (prefix + transaction.serialize() + seal).hex()
        assert_raises_rpc_error(
            None, None, self.customer.protx_decode_operator_request,
            changed_output_request)
        assert_raises_rpc_error(
            None, None, self.customer.protx_register_operator_sign,
            changed_output_request)
        signature = self.customer.protx_register_operator_sign(request)
        corrupt_signature = ("00" if signature[:2] != "00" else "01") + signature[2:]
        assert_raises_rpc_error(
            None, None, self.provider.protx_register_operator_submit,
            request, corrupt_signature, False)
        rawtx = self.provider.protx_register_operator_submit(
            request, signature, False)
        admission = node.testmempoolaccept([rawtx])[0]
        assert admission["allowed"], admission
        txid = self.provider.protx_register_operator_submit(request, signature)
        assert_equal(node.decoderawtransaction(rawtx)["txid"], txid)
        self.generate(node, 1)
        assert_equal(node.protx_operator_key_info(mn["protx_hash"])["keyVersion"], 1)

    def fund_customer(self):
        address = self.customer.getnewaddress()
        self.controller.sendtoaddress(address, 1)
        self.generate(self.nodes[0], 1)
        return address

    def empty_customer(self):
        amount = self.customer.getbalance()
        if amount:
            self.customer.sendtoaddress(
                self.controller.getnewaddress(), amount, "", "", True)
            self.generate(self.nodes[0], 1)
        assert_equal(self.customer.getbalance(), 0)

    def state(self, mn):
        return self.nodes[0].protx_info(mn["protx_hash"])["state"]

    def migrate(self, mn, *, enroll_voting=True):
        before = self.state(mn)
        new_owner = self.customer.protx_generate_owner_key()
        fee_address = self.fund_customer()
        # The wallet has the voting secret, but it is not an owner secret.
        voting_only = self.customer.protx_generate_voting_key()
        assert_raises_rpc_error(
            None, None, self.customer.protx_update_owner,
            mn["protx_hash"], voting_only, fee_address)
        self.customer.protx_update_owner(
            mn["protx_hash"], new_owner, fee_address,
            voting_only if enroll_voting else "")
        self.generate(self.nodes[0], 1)
        migration_block = self.nodes[0].getbestblockhash()
        after = self.state(mn)
        assert_equal(after["pqOwnerPublicKey"], new_owner)
        assert_equal(after["pqOwnerKeyVersion"], 1)
        if enroll_voting:
            assert_equal(after["pqVotingPublicKey"], voting_only)
        preserved_fields = ["payoutAddress", "operatorPayoutAddress", "service"]
        if not enroll_voting:
            preserved_fields.extend(["pqVotingPublicKey", "pqVotingKeyVersion"])
        if self.nodes[0].getblockcount() < self.BTCC_CANDIDATE_ORIGIN:
            preserved_fields.extend(["pubKeyOperator", "version"])
        for field in preserved_fields:
            if field in before:
                assert_equal(after[field], before[field])
        self.empty_customer()
        return migration_block, new_owner

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        while node.getbalance() < Decimal("210"):
            self.generatetoaddress(node, 10, node.getnewaddress())
        self.configure_pq_preparation()
        node.createwallet("customer", descriptors=True)
        node.createwallet("provider", descriptors=True)
        self.wallets()
        legacy_mn = self.create_owned_masternode(2)
        pq_mn = self.create_owned_masternode(3)

        self.log.info("The customer signs a provider-funded bootstrap without fee funds")
        self.handoff(legacy_mn)
        self.log.info("A request signed before ownership migration cannot be submitted afterward")
        stale_request = self.prepare(pq_mn)
        stale_signature = self.customer.protx_register_operator_sign(stale_request)
        migration_block, pq_owner = self.migrate(pq_mn)
        assert_raises_rpc_error(
            None, None, self.provider.protx_register_operator_submit,
            stale_request, stale_signature, False)

        self.log.info("Preparation rollback restores the old owner and exact PQ version")
        expected = self.state(pq_mn)
        node.invalidateblock(migration_block)
        assert_equal(self.state(pq_mn).get("pqOwnerKeyVersion", 0), 0)
        node.reconsiderblock(migration_block)
        assert_equal(self.state(pq_mn)["pqOwnerPublicKey"], pq_owner)
        assert_equal(self.state(pq_mn), expected)

        self.log.info("A migrated owner authorizes the same hosted workflow with SLH")
        self.handoff(pq_mn)
        # Owner and operator alone do not qualify once the voting-key gate
        # activates. Complete this owner's remaining voting enrollment later.
        operator_before = node.protx_operator_key_info(legacy_mn["protx_hash"])
        self.migrate(legacy_mn, enroll_voting=False)
        self.activate_pq()
        self.wallets()
        self.generate(node, 1)
        assert_equal(self.state(legacy_mn)["pqOwnerKeyVersion"], 1)
        assert "pqVotingPublicKey" not in self.state(legacy_mn)
        assert_equal(node.protx_operator_key_info(legacy_mn["protx_hash"])["keyVersion"], 1)
        # Both operators have valid pre-activation commitments, but only the
        # node with both an owner and voting key qualifies for PQ-era payments.
        assert_equal(node.masternode_current()["proTxHash"], pq_mn["protx_hash"])

        self.log.info("Late voting enrollment preserves the active operator and restores payment eligibility")
        owner_before = self.state(legacy_mn)["pqOwnerPublicKey"]
        fee_address = self.fund_customer()
        voting_public = self.customer.protx_generate_voting_key()
        self.customer.protx_update_owner(
            legacy_mn["protx_hash"], owner_before, fee_address, voting_public)
        self.generate(node, 1)
        enrolled = self.state(legacy_mn)
        assert_equal(enrolled["pqOwnerPublicKey"], owner_before)
        assert_equal(enrolled["pqOwnerKeyVersion"], 1)
        assert_equal(enrolled["pqVotingPublicKey"], voting_public)
        assert_equal(node.masternode_current()["proTxHash"], legacy_mn["protx_hash"])
        self.log.info("An ordinary SLH registrar update rotates voting and payout independently")
        fee_address = self.fund_customer()
        voting_public = self.customer.protx_generate_voting_key()
        payout_address = self.controller.getnewaddress()
        self.customer.protx_update_registrar(
            legacy_mn["protx_hash"], "", voting_public, payout_address, fee_address)
        self.generate(node, 1)
        updated = self.state(legacy_mn)
        assert_equal(updated["pqOwnerPublicKey"], owner_before)
        assert_equal(updated["pqOwnerKeyVersion"], 1)
        assert_equal(updated["pqVotingPublicKey"], voting_public)
        assert_equal(updated["payoutAddress"], payout_address)
        assert_equal(node.protx_operator_key_info(legacy_mn["protx_hash"]), operator_before)

        expected_operator = node.protx_operator_key_info(pq_mn["protx_hash"])
        self.check_restart_and_fresh_replay(
            pq_mn, self.consensus_protx_info(node.protx_info(pq_mn["protx_hash"])),
            expected_operator)


if __name__ == "__main__":
    PQOwnerKeyTest().main()
