#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test GETDATA processing behavior"""
from collections import defaultdict

from test_framework.messages import (
    CInv,
    MSG_CLSIG,  # SYSCOIN: final PQ ChainLock inventory.
    msg_getdata,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import SyscoinTestFramework


class P2PStoreBlock(P2PInterface):
    def __init__(self):
        super().__init__()
        self.blocks = defaultdict(int)

    def on_block(self, message):
        message.block.calc_sha256()
        self.blocks[message.block.sha256] += 1


class GetdataTest(SyscoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        p2p_block_store = self.nodes[0].add_p2p_connection(P2PStoreBlock())

        self.log.info("test that an invalid GETDATA doesn't prevent processing of future messages")

        # Send invalid message and verify that node responds to later ping
        invalid_getdata = msg_getdata()
        invalid_getdata.inv.append(CInv(t=0, h=0))  # INV type 0 is invalid.
        p2p_block_store.send_and_ping(invalid_getdata)

        # Check getdata still works by fetching tip block
        best_block = int(self.nodes[0].getbestblockhash(), 16)
        good_getdata = msg_getdata()
        good_getdata.inv.append(CInv(t=2, h=best_block))
        p2p_block_store.send_and_ping(good_getdata)
        p2p_block_store.wait_until(lambda: p2p_block_store.blocks[best_block] == 1)

        # SYSCOIN: Duplicate large-certificate requests are rejected before
        # they can consume a bounded upload slot.
        self.log.info("test that duplicate PQ ChainLock requests are disconnected before queuing")
        duplicate_peer = self.nodes[0].add_p2p_connection(P2PInterface())
        duplicate_getdata = msg_getdata(inv=[
            CInv(MSG_CLSIG, 1),
            CInv(MSG_CLSIG, 1),
        ])
        with self.nodes[0].assert_debug_log(["duplicate-pq-certificate-getdata"]):
            duplicate_peer.send_message(duplicate_getdata)
            duplicate_peer.wait_for_disconnect(timeout=10)


if __name__ == '__main__':
    GetdataTest().main()
