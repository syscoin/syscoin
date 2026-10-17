#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Public Sentry signing capabilities are coherent and wallet independent."""

from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import assert_equal


class ProTxCapabilitiesTest(SyscoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-mncollateral=100"]]

    def check_capabilities(self, collateral):
        node = self.nodes[0]
        result = node.protx_capabilities()
        assert_equal(result["version"], 1)
        assert_equal(result["network"], "regtest")
        assert_equal(result["genesisHash"], node.getblockhash(0))
        assert_equal(result["height"], node.getblockcount())
        assert_equal(result["blockHash"], node.getbestblockhash())
        assert_equal(result["nextBlockHeight"], node.getblockcount() + 1)
        assert_equal(result["requiredCollateralSatoshis"], str(collateral * 100000000))
        assert_equal(result["pqActive"], False)
        assert_equal(result["preparationActive"], False)
        assert_equal(result["era"], "legacy-v3" if result["servicePayloadVersion"] == 3 else "legacy-v1")
        assert_equal(result["preparationHeight"], None)
        assert_equal(result["activationHeight"], None)
        return result

    def run_test(self):
        before = self.check_capabilities(100)
        self.generatetoaddress(self.nodes[0], 1, "mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ")
        after = self.check_capabilities(100)
        assert_equal(after["height"], before["height"] + 1)
        self.restart_node(0, extra_args=["-mncollateral=200"])
        self.check_capabilities(200)


if __name__ == "__main__":
    ProTxCapabilitiesTest().main()

