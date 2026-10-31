#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep replacement registrations and updates of the old MN out of one mempool."""

from decimal import Decimal

from feature_deterministicmns import DIP3Test
from test_framework.messages import CTransaction, from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error, force_finish_mnsync


class ProTxConflictTest(DIP3Test):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1
        self.num_initial_mn = 1
        self.extra_args.append('-persistmempool=0')

    def restart_wallet(self, *, broadcast, persist=False, expected_mempool=()):
        args = [arg for arg in self.extra_args if not arg.startswith('-persistmempool=')]
        args += ['-persistmempool=%d' % persist, '-walletbroadcast=%d' % broadcast]
        self.restart_node(0, extra_args=args)
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)
        force_finish_mnsync(self.nodes[0])
        assert_equal(set(self.nodes[0].getrawmempool()), set(expected_mempool))

    def restart_without_mempool(self):
        # Keep the signing wallet available without reaccepting the prepared
        # update before this test deliberately submits its first transaction.
        self.restart_wallet(broadcast=False)

    def prepare_replacement(self):
        node = self.nodes[0]
        self.mn_index += 2
        old = self.prepare_mn(node, 1, 'old')
        # These are registered identities, not running test nodes. Give each
        # identity a distinct advertised port without consuming node indices.
        old.p2p_port += self.mn_index
        self.create_mn_collateral(node, old)
        self.register_mn(node, old)
        replacement = self.prepare_mn(node, 2, 'replacement')
        replacement.p2p_port += self.mn_index
        replacement.rewards_address = node.getnewaddress()
        node.sendtoaddress(old.fundsAddr, Decimal('0.02'))
        node.sendtoaddress(replacement.fundsAddr, Decimal('0.02'))
        self.generate(node, 1)
        # Separate confirmed fee inputs prevent ordinary transaction ancestry or
        # double spends from masking the semantic ProTx conflict.
        raw = node.protx_register(
            old.collateral_txid, old.collateral_vout,
            '127.0.0.3:%d' % replacement.p2p_port,
            replacement.ownerAddr, replacement.operatorAddr,
            replacement.votingAddr, 0, replacement.rewards_address,
            replacement.fundsAddr, False)
        reserved = [{'txid': txin['txid'], 'vout': txin['vout']}
                    for txin in node.decoderawtransaction(raw)['vin']]
        node.lockunspent(False, reserved, True)
        old.fee_inputs = [{'txid': coin['txid'], 'vout': coin['vout']}
                          for coin in node.listunspent(1, 9999999, [old.fundsAddr])]
        node.lockunspent(False, old.fee_inputs, True)
        return old, raw

    def submit_update(self, old, kind):
        node = self.nodes[0]
        node.lockunspent(True, old.fee_inputs)
        if kind == 'service':
            return node.protx_update_service(
                old.protx_hash, '127.0.0.2:%d' % old.p2p_port,
                old.blsMnkey, '', '', old.fundsAddr)
        if kind == 'registrar':
            # Keep the operator key: replacement conflict handling must not be
            # accidentally covered by the existing key-change conflict rules.
            return node.protx_update_registrar(
                old.protx_hash, '', '', node.getnewaddress(), old.fundsAddr)
        return node.protx_revoke(old.protx_hash, old.blsMnkey, 0, old.fundsAddr)

    def check_first_seen(self, kind, replacement_first):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, kind)
        update_raw = node.getrawtransaction(update_id)
        replacement_id = node.decoderawtransaction(replacement_raw)['txid']
        # Wallet RPCs sign and submit updates. Keep their raw transaction and
        # restart this isolated node to test either arrival order from empty.
        self.restart_without_mempool()
        node = self.nodes[0]
        first_raw, second_raw = ((replacement_raw, update_raw) if replacement_first
                                 else (update_raw, replacement_raw))
        first_id = replacement_id if replacement_first else update_id
        assert_equal(node.sendrawtransaction(first_raw), first_id)
        assert_raises_rpc_error(-26, 'protx-dup', node.sendrawtransaction, second_raw)
        assert_equal(node.getrawmempool(), [first_id])
        self.generate(node, 1)
        self.restart_wallet(broadcast=True)

    def check_confirmed_replacement(self, kind):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        control, _ = self.prepare_replacement()
        second_fee_address = None
        if kind == 'service':
            second_fee_address = node.getnewaddress()
            node.sendtoaddress(second_fee_address, Decimal('0.02'))
            self.generate(node, 1)
        update_id = self.submit_update(old, kind)
        control_id = self.submit_update(control, 'service')
        old_references = {update_id}
        if second_fee_address is not None:
            # Exercise repeated removal from the same reference-index key,
            # not just removal of one update and its ordinary descendants.
            old_references.add(node.protx_update_service(
                old.protx_hash, '127.0.0.4:%d' % old.p2p_port,
                old.blsMnkey, '', '', second_fee_address))
        update = node.getrawtransaction(update_id, True)
        change = next(output for output in update['vout'] if output['value'] > 0)
        child_raw = node.createrawtransaction(
            [{'txid': update_id, 'vout': change['n']}],
            {node.getnewaddress(): change['value'] - Decimal('0.0001')})
        child_raw = node.signrawtransactionwithwallet(child_raw)['hex']
        child_id = node.sendrawtransaction(child_raw)
        assert_equal(set(node.getrawmempool()), old_references | {child_id, control_id})

        # A peer can mine a replacement that local policy would not admit.
        # Use the existing raw-block helper to pay the correct MN fee share.
        self.mine_block(node, [from_hex(CTransaction(), replacement_raw)])
        assert_equal(set(node.getrawmempool()), {control_id})
        self.generate(node, 1)

    def check_consensus_order(self, kind):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, kind)
        update_raw = node.getrawtransaction(update_id)
        replacement_id = node.decoderawtransaction(replacement_raw)['txid']
        self.restart_without_mempool()
        node = self.nodes[0]
        # The first-seen rule is policy only. Consensus still accepts an update
        # followed by the replacement, even though the pair cannot coexist in
        # the local mempool.
        self.mine_block(node, [from_hex(CTransaction(), update_raw),
                               from_hex(CTransaction(), replacement_raw)])
        block = node.getblock(node.getbestblockhash())
        assert_equal(block['tx'][1:], [update_id, replacement_id])
        assert_equal(node.protx_info(replacement_id)['proTxHash'], replacement_id)
        self.restart_wallet(broadcast=True)

    def check_persisted_first_seen(self, replacement_first):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, 'service')
        update_raw = node.getrawtransaction(update_id)
        replacement_id = node.decoderawtransaction(replacement_raw)['txid']
        self.restart_without_mempool()
        node = self.nodes[0]
        first_raw, second_raw = ((replacement_raw, update_raw) if replacement_first
                                 else (update_raw, replacement_raw))
        first_id = replacement_id if replacement_first else update_id
        assert_equal(node.sendrawtransaction(first_raw), first_id)
        node.savemempool()
        self.restart_wallet(broadcast=False, persist=True, expected_mempool={first_id})
        node = self.nodes[0]
        # The reference/collateral indices must be reconstructed on reload,
        # so the persisted transaction still wins the same semantic conflict.
        assert_raises_rpc_error(-26, 'protx-dup', node.sendrawtransaction, second_raw)
        assert_equal(node.getrawmempool(), [first_id])
        self.generate(node, 1)
        self.restart_wallet(broadcast=True)

    def check_reorg_replay(self):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, 'service')
        update_raw = node.getrawtransaction(update_id)
        replacement_id = node.decoderawtransaction(replacement_raw)['txid']
        self.restart_without_mempool()
        node = self.nodes[0]
        self.mine_block(node, [from_hex(CTransaction(), update_raw),
                               from_hex(CTransaction(), replacement_raw)])
        block_hash = node.getbestblockhash()
        node.invalidateblock(block_hash)
        assert_equal(node.protx_info(old.protx_hash)['proTxHash'], old.protx_hash)
        # Reorg resurrection replays the block in order. It must retain only
        # the first transaction, not recreate an unmineable conflicting pair.
        assert_equal(node.getrawmempool(), [update_id])
        self.wait_for_replayed_template(update_id, replacement_id)
        node.reconsiderblock(block_hash)
        assert_equal(node.getbestblockhash(), block_hash)
        assert_equal(node.getrawmempool(), [])
        self.restart_wallet(broadcast=True)

    def check_longer_branch_replay(self):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, 'service')
        update_raw = node.getrawtransaction(update_id)
        replacement_id = node.decoderawtransaction(replacement_raw)['txid']
        self.restart_without_mempool()
        node = self.nodes[0]
        self.mine_block(node, [from_hex(CTransaction(), update_raw),
                               from_hex(CTransaction(), replacement_raw)])
        replaced_branch = node.getbestblockhash()

        # Prepare a longer competing branch that never replaces the old MN.
        # Its eventual activation must revalidate disconnected transactions
        # against that branch, not the MN list at the tip being disconnected.
        node.invalidateblock(replaced_branch)
        self.mine_block(node)
        competing_first = node.getbestblockhash()
        self.mine_block(node)
        competing_tip = node.getbestblockhash()
        node.invalidateblock(competing_first)
        node.reconsiderblock(replaced_branch)
        assert_equal(node.getbestblockhash(), replaced_branch)
        assert_equal(node.protx_info(replacement_id)['proTxHash'], replacement_id)
        assert_equal(node.getrawmempool(), [])

        node.reconsiderblock(competing_first)
        assert_equal(node.getbestblockhash(), competing_tip)
        assert_equal(node.protx_info(old.protx_hash)['proTxHash'], old.protx_hash)
        self.log.info('Longer-branch replay: update=%s replacement=%s mempool=%s',
                      update_id, replacement_id, node.getrawmempool())
        assert_equal(node.getrawmempool(), [update_id])
        self.wait_for_replayed_template(update_id, replacement_id)
        self.generate(node, 1)
        # Confirming the retained update must release its reference index so
        # the replacement can be admitted normally afterward.
        assert_equal(node.sendrawtransaction(replacement_raw), replacement_id)
        assert_equal(node.getrawmempool(), [replacement_id])
        self.generate(node, 1)
        assert_equal(node.protx_info(replacement_id)['proTxHash'], replacement_id)
        self.restart_wallet(broadcast=True)

    def wait_for_replayed_template(self, update_id, replacement_id):
        def has_replayed_update():
            template_ids = [tx['txid'] for tx in self.nodes[0].getblocktemplate({'rules': ['segwit']})['transactions']]
            return update_id in template_ids and replacement_id not in template_ids

        # Returning to a prior tip can reuse its successful template until the
        # normal five-second mempool-change cache window expires.
        self.wait_until(has_replayed_update, timeout=10)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0
        for kind in ('service', 'registrar', 'revoke'):
            for replacement_first in (False, True):
                self.log.info('First-seen %s conflict, replacement first: %s', kind, replacement_first)
                self.check_first_seen(kind, replacement_first)
            self.log.info('Confirmed replacement removes %s update and descendant', kind)
            self.check_confirmed_replacement(kind)
            self.log.info('Consensus accepts %s update before replacement', kind)
            self.check_consensus_order(kind)
        for replacement_first in (False, True):
            self.log.info('First-seen conflict survives mempool reload, replacement first: %s', replacement_first)
            self.check_persisted_first_seen(replacement_first)
        self.log.info('Reorg replay keeps only the first-seen update and produces a valid template')
        self.check_reorg_replay()
        self.log.info('Longer-branch activation uses the new branch for replay conflicts')
        self.check_longer_branch_replay()


if __name__ == '__main__':
    ProTxConflictTest().main()
