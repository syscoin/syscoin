#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Apply provider-conflict policy to package members before insertion."""

from decimal import Decimal

from feature_protx_conflicts import ProTxConflictTest
from test_framework.messages import CTransaction, from_hex
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    create_lots_of_big_transactions,
    gen_return_txouts,
)
from test_framework.wallet import MiniWallet


class ProTxPackageTest(ProTxConflictTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args += ['-maxmempool=5', '-datacarriersize=100000']

    def check_dry_run(self, kind, replacement_first):
        node = self.nodes[0]
        old, replacement_raw = self.prepare_replacement()
        update_id = self.submit_update(old, kind)
        update_raw = node.getrawtransaction(update_id)
        self.restart_without_mempool()
        node = self.nodes[0]
        package = [replacement_raw, update_raw] if replacement_first else [update_raw, replacement_raw]
        # Independently valid transactions must not become mutually valid just
        # because package prechecks precede all mempool insertions.
        for raw in package:
            assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)
        result = node.testmempoolaccept(package)
        assert_equal(result[1]['allowed'], False)
        assert_equal(result[1]['reject-reason'], 'protx-dup')
        assert_equal(node.getrawmempool(), [])
        # Package policy must not change consensus acceptance of this order.
        self.mine_block(node, [from_hex(CTransaction(), update_raw),
                               from_hex(CTransaction(), replacement_raw)])
        self.restart_wallet(broadcast=True)

    def make_service_update(self, old, service, fee_address):
        node = self.nodes[0]
        update_id = node.protx_update_service(old.protx_hash, service, old.blsMnkey, '', '', fee_address)
        return node.getrawtransaction(update_id)

    def check_service_properties(self, duplicate):
        node = self.nodes[0]
        first, _ = self.prepare_replacement()
        second = first
        if duplicate:
            second, _ = self.prepare_replacement()
        fee_address = node.getnewaddress()
        node.sendtoaddress(fee_address, Decimal('0.02'))
        self.generate(node, 1)
        port = 19000 + self.mn_index
        node.lockunspent(True, first.fee_inputs)
        first_raw = self.make_service_update(first, f'127.0.0.9:{port}', first.fundsAddr)
        self.restart_without_mempool()
        node = self.nodes[0]
        second_service = f'127.0.0.9:{port if duplicate else port + 1}'
        second_raw = self.make_service_update(second, second_service, fee_address)
        self.restart_without_mempool()
        node = self.nodes[0]
        for raw in (first_raw, second_raw):
            assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)
        result = node.testmempoolaccept([first_raw, second_raw])
        if duplicate:
            assert_equal(result[1]['reject-reason'], 'protx-dup')
            assert_equal(result[1]['allowed'], False)
            self.mine_block(node, [from_hex(CTransaction(), first_raw)])
        else:
            # Existing policy permits separate service updates for one MN
            # when their advertised endpoints differ.
            assert all(item['allowed'] for item in result)
            self.mine_block(node, [from_hex(CTransaction(), first_raw),
                                   from_hex(CTransaction(), second_raw)])
        assert_equal(node.getrawmempool(), [])
        self.restart_wallet(broadcast=True)

    def check_duplicate_collateral(self):
        node = self.nodes[0]
        old, first_raw = self.prepare_replacement()
        other = self.prepare_mn(node, 2, 'package-replacement')
        node.sendtoaddress(other.fundsAddr, Decimal('0.02'))
        self.generate(node, 1)
        second_raw = node.protx_register(
            old.collateral_txid, old.collateral_vout,
            f'127.0.0.8:{21000 + self.mn_index}',
            other.ownerAddr, other.operatorAddr, other.votingAddr,
            0, node.getnewaddress(), other.fundsAddr, False)
        for raw in (first_raw, second_raw):
            assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)
        result = node.testmempoolaccept([first_raw, second_raw])
        assert_equal(result[1]['allowed'], False)
        assert_equal(result[1]['reject-reason'], 'protx-dup')
        assert_equal(node.getrawmempool(), [])
        self.mine_block(node, [from_hex(CTransaction(), first_raw)])
        self.restart_wallet(broadcast=True)

    def low_fee_parent(self, raw):
        node = self.nodes[0]
        tx = from_hex(CTransaction(), raw)
        input_value = sum(int(node.gettxout(f'{txin.prevout.hash:064x}', txin.prevout.n)['value'] * 100000000)
                          for txin in tx.vin)
        change = next(out for out in tx.vout if out.nValue > 0)
        change.nValue = input_value - sum(out.nValue for out in tx.vout if out is not change) - 1000
        signed = node.signrawtransactionwithwallet(tx.serialize().hex())
        assert_equal(signed['complete'], True)
        return signed['hex']

    def make_child(self, parents):
        node = self.nodes[0]
        inputs, prevtxs = [], []
        amount = Decimal(0)
        for raw in parents:
            tx = from_hex(CTransaction(), raw)
            tx.rehash()
            index, output = next((i, out) for i, out in enumerate(tx.vout) if out.nValue > 0)
            inputs.append({'txid': tx.hash, 'vout': index})
            value = Decimal(output.nValue) / 100000000
            prevtxs.append(dict(inputs[-1], scriptPubKey=output.scriptPubKey.hex(), amount=value))
            amount += value
        raw = node.createrawtransaction(inputs, {node.getnewaddress(): amount - Decimal('0.002')})
        signed = node.signrawtransactionwithwallet(raw, prevtxs)
        assert_equal(signed['complete'], True)
        return signed['hex']

    def check_submission(self, kind):
        node = self.nodes[0]
        miniwallet = MiniWallet(node)
        self.generate(miniwallet, 180)
        old, replacement_raw = self.prepare_replacement()
        control, _ = self.prepare_replacement()
        update_id = self.submit_update(old, kind)
        update_raw = node.getrawtransaction(update_id)
        control_id = self.submit_update(control, kind)
        control_raw = node.getrawtransaction(control_id)
        self.restart_without_mempool()
        node = self.nodes[0]
        replacement_raw, update_raw, control_raw = [self.low_fee_parent(raw)
                                                   for raw in (replacement_raw, update_raw, control_raw)]
        # Rewriting the ordinary change output must preserve the signed
        # provider payload; a later fee rejection would otherwise mask it.
        for raw in (replacement_raw, update_raw, control_raw):
            assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)
        child_raw = self.make_child([replacement_raw, update_raw])
        control_child = self.make_child([replacement_raw, control_raw])

        # Force deferred package validation: neither provider parent may be
        # admitted by submitpackage's preliminary individual-admission pass.
        miniwallet = MiniWallet(node)
        txouts = gen_return_txouts()
        for count in range(75):
            create_lots_of_big_transactions(miniwallet, node, Decimal('0.02') + Decimal(count) / 10000, 1, txouts)
            if node.getmempoolinfo()['mempoolminfee'] > Decimal('0.00004'):
                break
        assert node.getmempoolinfo()['mempoolminfee'] > Decimal('0.00004')
        for raw in (replacement_raw, update_raw, control_raw):
            assert_equal(node.testmempoolaccept([raw])[0]['reject-reason'], 'mempool min fee not met')
        assert_equal(node.testmempoolaccept([child_raw])[0]['reject-reason'], 'missing-inputs')
        before = set(node.getrawmempool())
        for parents in ([replacement_raw, update_raw], [update_raw, replacement_raw]):
            # The RPC reports the earliest individual failure, even though the
            # deferred package itself fails the provider-conflict check.
            assert_raises_rpc_error(-26, 'mempool min fee not met', node.submitpackage, parents + [child_raw])
            assert_equal(set(node.getrawmempool()), before)

        # Reusing the rejected package's replacement with an unrelated update
        # must succeed: failed attempts must not leak provider reservations.
        package = [replacement_raw, control_raw, control_child]
        result = node.submitpackage(package)
        package_ids = set()
        for raw in package:
            tx = from_hex(CTransaction(), raw)
            tx.rehash()
            package_ids.add(tx.hash)
            assert_equal(result['tx-results'][tx.getwtxid()]['txid'], tx.hash)
        assert package_ids <= set(node.getrawmempool())
        rejected = from_hex(CTransaction(), update_raw)
        rejected.rehash()
        assert rejected.hash not in node.getrawmempool()
        template = node.getblocktemplate({'rules': ['segwit']})
        assert package_ids <= {tx['txid'] for tx in template['transactions']}
        self.generate(node, 1)
        self.restart_wallet(broadcast=True)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0
        for kind in ('service', 'registrar', 'revoke'):
            for replacement_first in (False, True):
                self.log.info('Package dry run: %s, replacement first: %s', kind, replacement_first)
                self.check_dry_run(kind, replacement_first)
        self.log.info('Package rejects duplicate service endpoints')
        self.check_service_properties(duplicate=True)
        self.log.info('Package permits distinct service updates for the same MN')
        self.check_service_properties(duplicate=False)
        self.log.info('Package rejects duplicate external collateral')
        self.check_duplicate_collateral()
        for kind in ('service', 'registrar', 'revoke'):
            self.log.info('Package submission checks %s conflicts before deferred insertion', kind)
            self.check_submission(kind)


if __name__ == '__main__':
    ProTxPackageTest().main()
