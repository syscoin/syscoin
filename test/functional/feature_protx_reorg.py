#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Revalidate pending provider updates when a reorg removes their registration."""

from decimal import Decimal

from feature_deterministicmns import DIP3Test
from test_framework.util import assert_equal


class ProTxReorgTest(DIP3Test):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1
        self.num_initial_mn = 1
        self.extra_args.append('-persistmempool=0')

    def prepare_registered_mn(self):
        node = self.nodes[0]
        self.mn_index += 1
        mn = self.prepare_mn(node, 1, 'reorg-%d' % self.mn_index)
        mn.p2p_port += self.mn_index
        self.create_mn_collateral(node, mn)
        self.register_mn(node, mn)
        return mn

    def update(self, mn, kind, fee_address):
        node = self.nodes[0]
        if kind == 'service':
            return node.protx_update_service(
                mn.protx_hash, '127.0.0.2:%d' % mn.p2p_port,
                mn.blsMnkey, '', '', fee_address)
        if kind == 'registrar':
            return node.protx_update_registrar(mn.protx_hash, '', '', node.getnewaddress(), fee_address)
        return node.protx_revoke(mn.protx_hash, mn.blsMnkey, 0, fee_address)

    def check_disconnected_registration(self, kind):
        node = self.nodes[0]
        control = self.prepare_registered_mn()
        self.mn_index += 1
        target = self.prepare_mn(node, 1, 'disconnected-%d' % self.mn_index)
        target.p2p_port += self.mn_index
        self.create_mn_collateral(node, target)
        update_funds = node.getnewaddress()
        control_funds = node.getnewaddress()
        for address in (target.fundsAddr, update_funds, control_funds):
            node.sendtoaddress(address, Decimal('0.02'))
        self.generate(node, 1)

        # All update fee inputs predate the registration block, so disconnecting
        # it does not remove the update through ordinary input dependencies.
        target.rewards_address = node.getnewaddress()
        target.protx_hash = node.protx_register(
            target.collateral_txid, target.collateral_vout,
            '127.0.0.1:%d' % target.p2p_port, target.ownerAddr,
            target.operatorAddr, target.votingAddr, 0,
            target.rewards_address, target.fundsAddr)
        self.generate(node, 1)
        registration_block = node.getbestblockhash()
        update_id = self.update(target, kind, update_funds)
        assert_equal(node.getmempoolentry(update_id)['depends'], [])
        control_id = self.update(control, kind, control_funds)
        raw_update = node.getrawtransaction(update_id, True)
        change = next(output for output in raw_update['vout'] if output['value'] > 0)
        child_raw = node.createrawtransaction(
            [{'txid': update_id, 'vout': change['n']}],
            {node.getnewaddress(): change['value'] - Decimal('0.0001')})
        child_signed = node.signrawtransactionwithwallet(child_raw)
        assert_equal(child_signed['complete'], True)
        child_id = node.sendrawtransaction(child_signed['hex'])
        assert_equal(set(node.getrawmempool()), {update_id, child_id, control_id})

        node.invalidateblock(registration_block)
        assert target.protx_hash not in node.protx_list('registered')
        remaining = set(node.getrawmempool())
        self.log.info('%s update=%s child=%s control=%s after reorg=%s',
                      kind, update_id, child_id, control_id, sorted(remaining))
        assert update_id not in remaining
        assert child_id not in remaining
        assert control_id in remaining
        # Clear stale provider indexes before replay, so they cannot block this
        # still-valid registration from returning to the mempool.
        assert target.protx_hash in remaining
        template_ids = {tx['txid'] for tx in node.getblocktemplate({'rules': ['segwit']})['transactions']}
        assert control_id in template_ids
        assert update_id not in template_ids
        assert child_id not in template_ids

        # The still-valid control remains mineable after returning to the old
        # branch, while neither the evicted update nor its child is resurrected.
        node.reconsiderblock(registration_block)
        assert_equal(node.getbestblockhash(), registration_block)
        assert_equal(set(node.getrawmempool()), {control_id})
        self.generate(node, 1)
        assert_equal(node.getblock(node.getbestblockhash())['tx'][1:], [control_id])

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0
        for kind in ('service', 'registrar', 'revoke'):
            self.log.info('Disconnect a registration while its %s update remains pending', kind)
            self.check_disconnected_registration(kind)


if __name__ == '__main__':
    ProTxReorgTest().main()
