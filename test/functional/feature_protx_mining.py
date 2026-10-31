#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Select provider updates against the MN state produced by earlier block entries."""

from decimal import Decimal

from feature_deterministicmns import DIP3Test
from test_framework.util import assert_equal


class ProTxMiningTest(DIP3Test):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1
        self.num_initial_mn = 1
        self.extra_args.append('-persistmempool=0')

    def prepare_masternode(self):
        node = self.nodes[0]
        self.mn_index += 1
        mn = self.prepare_mn(node, 1, 'mining-%d' % self.mn_index)
        mn.p2p_port += self.mn_index
        self.create_mn_collateral(node, mn)
        self.register_mn(node, mn)
        # NEVM changes require a confirmed MN, independently of transaction confirmations.
        self.generate(node, 2 * len(node.protx_list('registered')) + 2)
        assert node.protx_info(mn.protx_hash)['state']['confirmedHash'] != '00' * 32
        return mn

    def fund_addresses(self, count):
        node = self.nodes[0]
        addresses = [node.getnewaddress() for _ in range(count)]
        for address in addresses:
            node.sendtoaddress(address, Decimal('0.05'))
        self.generate(node, 1)
        return addresses

    def key_update(self, mn, kind, fee_address):
        node = self.nodes[0]
        if kind == 'revoke':
            return node.protx_revoke(mn.protx_hash, mn.blsMnkey, 0, fee_address)
        return node.protx_update_registrar(
            mn.protx_hash, node.bls_generate()['public'], '', '', fee_address)

    def service_update(self, mn, fee_address, nevm_byte, port_offset):
        return self.nodes[0].protx_update_service(
            mn.protx_hash, '127.0.0.2:%d' % (mn.p2p_port + port_offset),
            mn.blsMnkey, '0x' + nevm_byte * 20, '', fee_address)

    def check_order(self, kind, service_first):
        node = self.nodes[0]
        mn = self.prepare_masternode()
        service_funds, key_funds = self.fund_addresses(2)
        service_id = self.service_update(mn, service_funds, '11', 100)
        key_id = self.key_update(mn, kind, key_funds)
        assert_equal(set(node.getrawmempool()), {service_id, key_id})
        first = service_id if service_first else key_id
        node.prioritisetransaction(first, 0, 100000000)

        template_ids = [tx['txid'] for tx in node.getblocktemplate({'rules': ['segwit']})['transactions']]
        expected = [service_id, key_id] if service_first else [key_id]
        assert_equal(template_ids, expected)
        self.generate(node, 1)
        assert_equal(node.getblock(node.getbestblockhash())['tx'][1:], expected)
        assert_equal(node.getrawmempool(), [])

    def check_rejected_package_does_not_change_context(self):
        node = self.nodes[0]
        mn = self.prepare_masternode()
        key_funds, valid_service_funds = self.fund_addresses(2)
        key_id = self.key_update(mn, 'registrar', key_funds)
        # Spending the registrar's change makes the invalid order mandatory
        # when this service update is considered with its ancestor package.
        invalid_service_id = self.service_update(mn, key_funds, '22', 101)
        assert any(txin['txid'] == key_id for txin in node.getrawtransaction(invalid_service_id, True)['vin'])
        valid_service_id = self.service_update(mn, valid_service_funds, '33', 102)
        assert_equal(set(node.getrawmempool()), {key_id, invalid_service_id, valid_service_id})
        node.prioritisetransaction(invalid_service_id, 0, 300000000)
        node.prioritisetransaction(valid_service_id, 0, 100000000)

        # The high-fee invalid package is examined first. Its rejected key
        # change must not leak into the context of this valid service update.
        template_ids = [tx['txid'] for tx in node.getblocktemplate({'rules': ['segwit']})['transactions']]
        assert_equal(template_ids, [valid_service_id, key_id])
        self.generate(node, 1)
        assert_equal(node.getblock(node.getbestblockhash())['tx'][1:], template_ids)
        assert_equal(node.getrawmempool(), [])

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(self.default_wallet_name, descriptors=True)
        self.generatetoaddress(node, 200, node.getnewaddress())
        self.generate(node, 433 - node.getblockcount())
        self.mn_index = 0
        for kind in ('registrar', 'revoke'):
            for service_first in (False, True):
                self.log.info('Check %s with service first=%s', kind, service_first)
                self.check_order(kind, service_first)
        self.check_rejected_package_does_not_change_context()


if __name__ == '__main__':
    ProTxMiningTest().main()
