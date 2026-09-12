#!/usr/bin/env python3
# Copyright (c) 2021 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import DashTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, bytes_to_hex_str
from test_framework.p2p import P2PInterface
from test_framework.messages import hash256
'''
rpc_mnauth.py

Tests mnauth RPC command
'''


class FakeMNAUTHTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(2, 1, fast_dip3_enforcement=True)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        masternode = self.mninfo[0]
        # SYSCOIN: exercise the regtest MNAUTH override with the active SLH
        # operator identity and assert that no retired BLS peer fields survive.
        marker = "pq-mnauth-rpc"
        p2p_masternode = masternode.node.add_p2p_connection(
            P2PInterface(), uacomment=marker)
        p2p_masternode.wait_for_verack()

        protx_hash = masternode.proTxHash
        operator_identity = masternode.node.protx_operator_key_info(protx_hash)
        public_key = operator_identity["publicKey"]
        key_version = operator_identity["keyVersion"]

        # SYSCOIN: select the explicit Python peer instead of relying on
        # getpeerinfo ordering among the live deterministic-node connections.
        peerinfo = next(
            peer for peer in masternode.node.getpeerinfo()
            if marker in peer.get("subver", ""))
        # The peerinfo should not yet contain a verified PQ identity.
        assert "verified_proregtx_hash" not in peerinfo
        assert "verified_global_pubkey_hash" not in peerinfo
        assert "verified_pubkey_hash" not in peerinfo
        # SYSCOIN: fake-authenticate the P2P connection to the masternode.
        node_id = peerinfo["id"]
        assert masternode.node.mnauth(node_id, protx_hash, public_key, key_version)
        # The peerinfo should now contain the exact global-key identity.
        peerinfo = next(
            peer for peer in masternode.node.getpeerinfo()
            if peer["id"] == node_id)
        assert "verified_proregtx_hash" in peerinfo
        assert "verified_global_pubkey_hash" in peerinfo
        assert "verified_global_key_version" in peerinfo
        assert_equal(peerinfo["verified_proregtx_hash"], protx_hash)
        expected_key_hash = bytes_to_hex_str(
            hash256(bytes.fromhex(public_key))[::-1])
        assert_equal(peerinfo["verified_global_pubkey_hash"], expected_key_hash)
        assert_equal(peerinfo["verified_global_key_version"], key_version)
        # Test some error cases
        null_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert_raises_rpc_error(-8, "proTxHash invalid", masternode.node.mnauth,
                                                         node_id,
                                                         null_hash,
                                                         public_key,
                                                         key_version)
        assert_raises_rpc_error(-8, "globalPublicKey must be a nonzero 32-byte key", masternode.node.mnauth,
                                                         node_id,
                                                         protx_hash,
                                                         null_hash,
                                                         key_version)
        assert_raises_rpc_error(-8, "globalPublicKey must be a nonzero 32-byte key", masternode.node.mnauth,
                                                         node_id,
                                                         protx_hash,
                                                         "01",
                                                         key_version)
        assert_raises_rpc_error(-8, "globalKeyVersion must be nonzero", masternode.node.mnauth,
                                                         node_id,
                                                         protx_hash,
                                                         public_key,
                                                         0)
        assert not masternode.node.mnauth(-1, protx_hash, public_key, key_version)


if __name__ == '__main__':
    FakeMNAUTHTest().main()
