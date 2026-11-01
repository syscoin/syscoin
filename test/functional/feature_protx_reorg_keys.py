#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Refresh cached provider key-change classification after a reorg."""

from decimal import Decimal

from feature_protx_conflicts import ProTxConflictTest
from test_framework.messages import CTransaction, from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error


class ProTxReorgKeysTest(ProTxConflictTest):
    def set_test_params(self):
        super().set_test_params()

    def check_key_change_classification(self, becomes_key_change):
        node = self.nodes[0]
        target, _ = self.prepare_replacement()
        control, _ = self.prepare_replacement()
        original_key = target.operatorAddr
        intermediate_key = node.bls_generate()['public']
        final_key = node.bls_generate()['public']
        change_funds, pending_funds, next_funds, control_funds = [node.getnewaddress() for _ in range(4)]
        funding_ids = {address: node.sendtoaddress(address, Decimal('0.02'))
                       for address in (change_funds, pending_funds, next_funds, control_funds)}
        self.generate(node, 1)

        changed = node.protx_update_registrar(
            target.protx_hash, intermediate_key, '', '', change_funds)
        changed_inputs = node.getrawtransaction(changed, True)['vin']
        self.generate(node, 1)
        change_block = node.getbestblockhash()
        assert_equal(node.protx_info(target.protx_hash)['state']['pubKeyOperator'], intermediate_key)

        # Before rollback, target=intermediate is not a key change, whereas
        # target=original is one. Rollback reverses those classifications.
        pending_key = intermediate_key if becomes_key_change else original_key
        pending = node.protx_update_registrar(
            target.protx_hash, pending_key, '', node.getnewaddress(), pending_funds)
        pending_tx = node.getrawtransaction(pending, True)
        assert all(txin['txid'] == funding_ids[pending_funds] for txin in pending_tx['vin'])
        assert_equal(node.getmempoolentry(pending)['depends'], [])
        control_id = node.protx_update_registrar(
            control.protx_hash, '', '', node.getnewaddress(), control_funds)

        node.invalidateblock(change_block)
        assert_equal(node.protx_info(target.protx_hash)['state']['pubKeyOperator'], original_key)
        assert {pending, control_id} <= set(node.getrawmempool())
        if not becomes_key_change:
            # The disconnected key change may itself be resurrected. Mine a
            # conflicting spend of its independently funded input, leaving the
            # pending registrar untouched, so it cannot mask this test's result.
            value = sum(node.gettxout(txin['txid'], txin['vout'], False)['value']
                        for txin in changed_inputs)
            spend_raw = node.createrawtransaction(
                [{'txid': txin['txid'], 'vout': txin['vout']} for txin in changed_inputs],
                {node.getnewaddress(): value - Decimal('0.001')})
            spend_signed = node.signrawtransactionwithwallet(spend_raw)
            assert_equal(spend_signed['complete'], True)
            self.mine_block(node, [from_hex(CTransaction(), spend_signed['hex'])])
        assert_equal(set(node.getrawmempool()), {pending, control_id})

        args = (target.protx_hash, final_key, '', node.getnewaddress(), next_funds)
        expected = {pending, control_id}
        if becomes_key_change:
            # The surviving registrar now changes the key. A second change
            # must be rejected even though it was not a change at admission.
            assert_raises_rpc_error(-4, 'protx-dup', node.protx_update_registrar, *args)
        else:
            # The surviving registrar now keeps the key. Its old cached flag
            # must not prevent a new, genuine key change from being admitted.
            expected.add(node.protx_update_registrar(*args))
        assert_equal(set(node.getrawmempool()), expected)
        # Revisiting a prior tip can reuse its template until the normal
        # five-second mempool-change cache window expires.
        self.wait_until(lambda: expected <= {
            tx['txid'] for tx in node.getblocktemplate({'rules': ['segwit']})['transactions']}, timeout=10)
        self.generate(node, 1)
        assert expected <= set(node.getblock(node.getbestblockhash())['tx'][1:])
        assert_equal(node.getrawmempool(), [])

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0
        for becomes_key_change in (True, False):
            self.log.info('Registrar becomes key change after rollback: %s', becomes_key_change)
            self.check_key_change_classification(becomes_key_change)


if __name__ == '__main__':
    ProTxReorgKeysTest().main()
