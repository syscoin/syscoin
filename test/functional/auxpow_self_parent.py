#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test rejection of a direct Syscoin block reused as its own AuxPoW parent."""

import copy
import struct

from test_framework.messages import (
    CAuxPow,
    CBlock,
    CBlockHeader,
    CTxOut,
    CHAIN_ID,
    VERSION_AUXPOW,
    VERSION_START_BIT,
    from_hex,
)
from test_framework.script import CScript
from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import assert_equal


CHAIN_ID_MASK = 0x1F << VERSION_START_BIT


class AuxpowSelfParentTest(SyscoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-dip3params=1:1", "-bridgev2startheight=1"],
            ["-dip3params=1:1", "-bridgev2startheight=2"],
        ]

    def build_pair(self, node, parent_chain_id=CHAIN_ID):
        address = node.get_deterministic_priv_key().address
        aux_template = node.createauxblock(address)

        generated = node.generateblock(address, [], False, invalid_call=False)
        parent = from_hex(CBlock(), generated["hex"])
        assert_equal(len(parent.vtx), 1)
        assert_equal(parent.hashPrevBlock, int(aux_template["previousblockhash"], 16))
        if parent_chain_id == 0:
            parent.nVersion &= ~CHAIN_ID_MASK
        assert_equal((parent.nVersion >> VERSION_START_BIT) & 0x1F, parent_chain_id)
        assert_equal(parent.nVersion & VERSION_AUXPOW, 0)

        merged_mining_tag = (
            bytes.fromhex("fabe6d6d")
            + bytes.fromhex(aux_template["hash"])
            + struct.pack("<II", 1, 0)
        )
        old_script = bytes(parent.vtx[0].vin[0].scriptSig)
        parent.vtx[0].vin[0].scriptSig = CScript(old_script + merged_mining_tag)
        assert len(parent.vtx[0].vin[0].scriptSig) <= 100

        # Post-Nexus AuxPoW requires this parent-coinbase output. It is also a
        # valid zero-value OP_RETURN in the independently submitted parent.
        parent.vtx[0].vout.append(
            CTxOut(0, CScript(bytes.fromhex(aux_template["coinbasescript"])))
        )

        parent.vtx[0].rehash()
        parent.hashMerkleRoot = parent.calc_merkle_root()
        parent.nNonce = 0
        parent.solve()

        auxpow = CAuxPow()
        auxpow.nVersion = parent.vtx[0].nVersion
        auxpow.vin = copy.deepcopy(parent.vtx[0].vin)
        auxpow.vout = copy.deepcopy(parent.vtx[0].vout)
        auxpow.wit = copy.deepcopy(parent.vtx[0].wit)
        auxpow.nLockTime = parent.vtx[0].nLockTime
        auxpow.extraData = parent.vtx[0].extraData
        auxpow.hashBlock = 0
        auxpow.vMerkleBranch = []
        auxpow.nIndex = 0
        auxpow.vChainMerkleBranch = []
        auxpow.nChainIndex = 0
        auxpow.parentBlock = CBlockHeader(parent)

        return aux_template, parent, auxpow

    def run_test(self):
        for node in self.nodes:
            node.setnetworkactive(False)

        self.log.info("Rejecting the direct parent at the Bridge V2 activation")
        aux_template, parent, auxpow = self.build_pair(self.nodes[0])
        assert_equal(
            self.nodes[0].submitblock(parent.serialize().hex()),
            "bad-direct-auxpow-parent",
        )

        self.log.info("Keeping the AuxPoW child valid")
        assert_equal(
            self.nodes[0].submitauxblock(aux_template["hash"], auxpow.serialize().hex()),
            True,
        )
        aux_info = self.nodes[0].getblock(aux_template["hash"])
        assert_equal(aux_info["height"], 1)
        assert "auxpow" in aux_info

        self.log.info("Keeping ordinary direct blocks valid after activation")
        address = self.nodes[0].get_deterministic_priv_key().address
        direct = self.nodes[0].generateblock(address, [], False, invalid_call=False)
        assert_equal(self.nodes[0].submitblock(direct["hex"]), None)

        self.log.info("Rejecting the same construction with parent Chain ID zero")
        zero_template, zero_parent, zero_auxpow = self.build_pair(
            self.nodes[0], parent_chain_id=0
        )
        assert_equal(
            self.nodes[0].submitblock(zero_parent.serialize().hex()),
            "bad-direct-auxpow-parent",
        )
        assert_equal(
            self.nodes[0].submitauxblock(
                zero_template["hash"], zero_auxpow.serialize().hex()
            ),
            True,
        )

        self.log.info("Preserving historical consensus before activation")
        old_template, old_parent, old_auxpow = self.build_pair(self.nodes[1])
        assert_equal(self.nodes[1].submitblock(old_parent.serialize().hex()), None)
        assert_equal(
            self.nodes[1].submitauxblock(old_template["hash"], old_auxpow.serialize().hex()),
            True,
        )
        parent_info = self.nodes[1].getblock(old_parent.hash)
        old_aux_info = self.nodes[1].getblock(old_template["hash"])
        assert_equal(parent_info["height"], 1)
        assert_equal(parent_info["height"], old_aux_info["height"])
        assert_equal(parent_info["chainwork"], old_aux_info["chainwork"])


if __name__ == "__main__":
    AuxpowSelfParentTest().main()
