#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Evict pending external registrations when their collateral is spent."""

from decimal import Decimal

from feature_protx_conflicts import ProTxConflictTest
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CTransaction, from_hex
from test_framework.util import assert_equal, p2p_port


class ProTxCollateralSpendTest(ProTxConflictTest):
    def set_test_params(self):
        super().set_test_params()

    def record_result(self, result):
        self.log.info('Collateral-spend cleanup: %s', result)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0

        old, registration_raw = self.prepare_replacement()
        registration_service = f'127.0.0.3:{p2p_port(2) + self.mn_index}'
        registration = node.decoderawtransaction(registration_raw)
        payload = registration['proRegTx']
        control, _ = self.prepare_replacement()
        control_id = self.submit_update(control, 'service')

        registration_id = node.sendrawtransaction(registration_raw)
        change = next(output for output in registration['vout'] if output['value'] > 0)
        child_raw = node.createrawtransaction(
            [{'txid': registration_id, 'vout': change['n']}],
            {node.getnewaddress(): change['value'] - Decimal('0.0001')})
        child_signed = node.signrawtransactionwithwallet(child_raw)
        assert_equal(child_signed['complete'], True)
        child_id = node.sendrawtransaction(child_signed['hex'])
        assert_equal(set(node.getrawmempool()), {registration_id, child_id, control_id})

        collateral = {'txid': old.collateral_txid, 'vout': old.collateral_vout}
        assert all((txin['txid'], txin['vout']) != (collateral['txid'], collateral['vout'])
                   for txin in registration['vin'])
        assert_equal(node.lockunspent(True, [collateral]), True)
        spend_raw = node.createrawtransaction([collateral], {node.getnewaddress(): Decimal('99.999')})
        spend_signed = node.signrawtransactionwithwallet(spend_raw)
        assert_equal(spend_signed['complete'], True)
        spend = from_hex(CTransaction(), spend_signed['hex'])
        spend.rehash()

        # A peer's block may spend collateral without including the pending
        # registration. Use the normal MN-payment helper, keeping its fee input
        # and the registration's fee input independent.
        self.mine_block(node, [spend])
        block = node.getblock(node.getbestblockhash())
        assert_equal(block['tx'][1:], [spend.hash])
        assert_equal(node.gettxout(old.collateral_txid, old.collateral_vout, False), None)

        template = None
        template_error = None
        try:
            template = node.getblocktemplate({'rules': ['segwit']})
        except JSONRPCException as error:
            template_error = error.error
        after = set(node.getrawmempool())
        self.record_result({
            'registration': registration_id,
            'child': child_id,
            'control': control_id,
            'collateral_spend': spend.hash,
            'mempool_after': sorted(after),
            'template_error': template_error,
        })
        assert_equal(after, {control_id})
        assert_equal(template_error, None)
        assert control_id in {tx['txid'] for tx in template['transactions']}

        # Reuse all of the evicted registration's unique properties with fresh
        # collateral, proving that cleanup releases the property indexes too.
        new_collateral_address = node.getnewaddress()
        new_collateral_id = node.sendtoaddress(new_collateral_address, Decimal(100))
        node.sendtoaddress(payload['payoutAddress'], Decimal('0.001'))
        self.generate(node, 1)
        new_collateral = node.getrawtransaction(new_collateral_id, True)
        new_collateral_vout = next(output['n'] for output in new_collateral['vout']
                                   if output['value'] == Decimal(100))
        renewed = node.protx_register(
            new_collateral_id, new_collateral_vout, registration_service,
            payload['ownerAddress'], payload['pubKeyOperator'], payload['votingAddress'],
            payload['operatorReward'], payload['payoutAddress'], payload['payoutAddress'])
        assert_equal(node.getrawmempool(), [renewed])
        self.generate(node, 1)
        assert_equal(node.protx_info(renewed)['proTxHash'], renewed)


if __name__ == '__main__':
    ProTxCollateralSpendTest().main()
