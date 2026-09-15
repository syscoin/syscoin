#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test syscoind aborts if can't disconnect a block.

- Start a single node and generate 3 blocks.
- Delete the undo data.
- Mine a fork that requires disconnecting the tip.
- Verify that syscoind AbortNode's.
"""
from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import assert_equal


class AbortNodeTest(SyscoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        # We'll connect the nodes later

    def run_test(self):
        self.generate(self.nodes[0], 3, sync_fun=self.no_op)

        # SYSCOIN: Persist the chain before damaging it. The durability fence
        # rejects later index writes with missing undo, so shutdown cannot be
        # relied on to publish the chain needed by the final restart check.
        tip = self.nodes[0].getbestblockhash()
        self.restart_node(0)
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        assert_equal(self.nodes[0].getblockcount(), 3)

        # Deleting the undo file will result in reorg failure
        (self.nodes[0].blocks_path / "rev00000.dat").unlink()

        # Connecting to a node with a more work chain will trigger a reorg
        # attempt.
        self.generate(self.nodes[1], 3, sync_fun=self.no_op)
        with self.nodes[0].assert_debug_log(["Failed to disconnect block"]):
            self.connect_nodes(0, 1)
            self.generate(self.nodes[1], 1, sync_fun=self.no_op)

            # Check that node0 aborted
            self.log.info("Waiting for crash")
            # SYSCOIN: Shutdown rechecks the damaged undo stream and can emit
            # the same fatal diagnostic again. Keep other stderr forbidden.
            self.nodes[0].wait_until_stopped(timeout=5, expect_error=True,
                expected_stderr="Error: A fatal internal error occurred, see debug.log for details",
                allow_repeated_stderr=True)
        self.log.info("Node crashed - now verifying restart fails")
        self.nodes[0].assert_start_raises_init_error()


if __name__ == '__main__':
    AbortNodeTest().main()
