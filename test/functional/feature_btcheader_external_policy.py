#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the minimal external Bitcoin policy backend on AuxPoW templates."""

import json
import os
from pathlib import Path
import sys
import time

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.auxpow import reverseHex
from test_framework.auxpow_testing import computeAuxpow, mineAuxpowBlock
from test_framework.messages import CBlock, from_hex
from test_framework.test_framework import SkipTest, SyscoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    force_finish_mnsync,
)


FAKE_BACKEND = r'''#!/usr/bin/env python3
import json
import subprocess
import sys
import time

with open(sys.argv[1], "r", encoding="utf8") as handle:
    state = json.load(handle)

if not state.get("online", True):
    print("backend down", file=sys.stderr)
    sys.exit(1)
delay = state.get("sleep", 0)
if delay:
    time.sleep(delay)
if state.get("spawn_descendant", False):
    # Inherit stdout/stderr so this catches leaked descendants retaining the
    # backend pipes after the direct CLI process exits.
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

method = sys.argv[2]
args = sys.argv[3:]
if method == "getblockchaininfo" and not args:
    result = {
        "chain": state["chain"],
        "initialblockdownload": state.get("ibd", False),
        "bestblockhash": state["best_hash"],
        "headers": state["headers"][state["best_hash"]]["height"],
    }
elif method == "getblockheader" and len(args) == 2 and args[1] == "true":
    if args[0] not in state["headers"]:
        print("header-not-found", file=sys.stderr)
        sys.exit(1)
    result = dict(state["headers"][args[0]])
    result["hash"] = args[0]
elif method == "getblockhash" and len(args) == 1:
    print(state["active"][args[0]])
    sys.exit(0)
elif method == "getchaintips" and not args:
    result = state["tips"]
else:
    print("unsupported method", file=sys.stderr)
    sys.exit(2)

json.dump(result, sys.stdout)
'''


class BTCHeaderPolicyAuxpowTest(SyscoinTestFramework):
    # SYSCOIN: non-palindromic hashes make RPC/display byte-order mistakes
    # observable in both the parent header and raw coinbase commitment.
    TIP = bytes(range(1, 33)).hex()
    NEXT_TIP = bytes(range(33, 65)).hex()
    OLD = "cc" * 32
    FORK = "dd" * 32
    PQ_EPOCH_BLOCKS = 288
    ACTIVE_QUORUMS = 4
    CHAINLOCK_EPOCH_ORIGIN = 1440
    FIRST_ELIGIBLE_TARGET_OFFSET = (
        (ACTIVE_QUORUMS - 1) * PQ_EPOCH_BLOCKS + 1)
    BTC_CANDIDATE_PERIOD = 10
    BTC_CANDIDATE_ORIGIN = (
        CHAINLOCK_EPOCH_ORIGIN + FIRST_ELIGIBLE_TARGET_OFFSET)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            # SYSCOIN: mine the immutable migration boundary first, then
            # restart with its exact hashes and the complete PQ schedule.
            "-dip3params=1:1",
            "-btcheaderpolicyondemand=1",
            "-btcheadermanaged=0",
            "-btcheadercmdtimeout=1",
        ]]

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.config["components"].getboolean(
                "ENABLE_BTC_HEADER_COMMAND", fallback=False):
            raise SkipTest("Boost.Process Bitcoin header backend unavailable")

    def setup_chain(self):
        super().setup_chain()
        root = Path(self.options.tmpdir)
        self.backend_script = root / "fake-bitcoin-cli.py"
        self.backend_state = root / "fake-bitcoin-state.json"
        self.backend_script.write_text(FAKE_BACKEND, encoding="utf8")
        self.backend_script.chmod(0o700)
        self.state = {
            "online": True,
            "sleep": 0,
            "spawn_descendant": False,
            "chain": "regtest",
            "ibd": False,
            "best_hash": self.TIP,
            "headers": {
                self.TIP: {
                    "height": 100,
                    "confirmations": 1,
                    "time": int(time.time()),
                },
                self.OLD: {
                    "height": 50,
                    "confirmations": 51,
                    "time": int(time.time()) - 600,
                },
            },
            "active": {"50": self.OLD, "100": self.TIP},
            "tips": [{"hash": self.TIP, "height": 100, "status": "active"}],
        }
        self._write_state()
        self.extra_args[0] += [
            f"-btcheadercmd={sys.executable}",
            f"-btcheaderarg={self.backend_script}",
            f"-btcheaderarg={self.backend_state}",
        ]

    def _write_state(self):
        replacement = self.backend_state.with_suffix(".tmp")
        replacement.write_text(json.dumps(self.state), encoding="utf8")
        os.replace(replacement, self.backend_state)

    def _mine_template(self, template):
        target = reverseHex(template["_target"])
        btcprev = template.get("_btcprevhash", "00" * 32)
        auxpow = computeAuxpow(
            template["hash"], target, True,
            template["coinbasescript"], btcprev)
        assert self.nodes[0].submitauxblock(template["hash"], auxpow)

    def _candidate_at_or_after(self, height):
        if height <= self.BTC_CANDIDATE_ORIGIN:
            return self.BTC_CANDIDATE_ORIGIN
        offset = height - self.BTC_CANDIDATE_ORIGIN
        return height + (-offset % self.BTC_CANDIDATE_PERIOD)

    def _configure_pq_migration(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        mineAuxpowBlock(node, None)
        anchor = node.protx_migration_info()
        assert_equal(anchor["height"], 1)

        # SYSCOIN: finality deployment is all-or-none. The first block pins the
        # exact legacy state; reindex proves the same boundary before enabling
        # the first production-valid joint BTCC and ChainLock target.
        pq_args = [
            f'-pqlegacyanchorheight={anchor["height"]}',
            f'-pqlegacyanchorblockhash={anchor["blockHash"]}',
            f'-pqlegacydmnstatehash={anchor["dmnStateHash"]}',
            f'-pqlegacypqregistrystatehash={anchor["pqRegistryStateHash"]}',
            "-pqpreparationheight=1",
            f"-pqchainlockepochorigin={self.CHAINLOCK_EPOCH_ORIGIN}",
            f"-pqregistrationcutoffblocks={self.PQ_EPOCH_BLOCKS}",
            f"-pqrostersnapshotlag={self.PQ_EPOCH_BLOCKS}",
            "-pqfuturehorizonepochs=8",
            f"-pqbtcccandidateorigin={self.BTC_CANDIDATE_ORIGIN}",
            # SYSCOIN: Before the first carrier, the separate receipt
            # assumption record commits the empty state at migration.
            f'-pqbtccreceiptanchorheight={anchor["height"]}',
            f'-pqbtccreceiptanchorblockhash={anchor["blockHash"]}',
            "-pqbtccreceiptanchorcursorheight=-1",
            f'-pqbtccreceiptanchorcursorsyshash={"0" * 64}',
            f'-pqbtccreceiptanchorcursorbtchash={"0" * 64}',
            f'-pqbtccreceiptanchorstatehash={"0" * 64}',
        ]
        # SYSCOIN: a configured migration must not start with finality silently
        # disabled. Without the receipt boundary a fresh node could enter
        # historical preseal and remain unable to catch up after cert pruning.
        incomplete_pq_args = [
            arg for arg in pq_args
            if not arg.startswith("-pqbtccreceiptanchor")
        ]
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=self.extra_args[0] + [
                f"-pqbtcccandidateorigin={self.BTC_CANDIDATE_ORIGIN}"],
            expected_msg="incomplete PQ deployment",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=self.extra_args[0] + incomplete_pq_args,
            expected_msg="BTCC receipt assumption anchor",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.extra_args[0].extend(pq_args)
        self.nodes[0].extra_args = list(self.extra_args[0])
        self.start_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        force_finish_mnsync(node)
        assert_equal(node.protx_migration_info(), anchor)
        return anchor

    def _assert_raw_btcprev_binding(self, block_hash, expected_btcprev):
        node = self.nodes[0]
        raw_block = node.getblock(block_hash, 0)
        block = from_hex(CBlock(), raw_block)
        assert block.auxpow is not None
        assert_equal(
            block.auxpow.parentBlock.hashPrevBlock,
            int(expected_btcprev, 16),
        )

        # uint256 is serialized little-endian after the literal `btcp` tag.
        commitment = b"btcp" + bytes.fromhex(expected_btcprev)[::-1]
        commitment_count = sum(
            bytes(output.scriptPubKey).count(commitment)
            for output in block.vtx[0].vout
        )
        assert_equal(commitment_count, 1)
        return raw_block

    def run_test(self):
        node = self.nodes[0]
        anchor = self._configure_pq_migration()
        address = node.get_deterministic_priv_key().address
        first_candidate = self._candidate_at_or_after(anchor["height"] + 1)
        second_candidate = first_candidate + self.BTC_CANDIDATE_PERIOD
        while node.getblockcount() < first_candidate - 1:
            mineAuxpowBlock(node, None)

        # The address-less createauxblock form remains invalid; the scheduled
        # address form below must auto-source the independent Bitcoin view.
        assert_raises_rpc_error(-1, None, node.createauxblock)
        assert_raises_rpc_error(
            -1, "header-not-found", node.createauxblock,
            address, "bb" * 32)

        # SYSCOIN: wallet-based getauxblock and address-based createauxblock
        # share the same scheduled policy selection and submission checks.
        wrong_parent_template = node.getauxblock()
        assert_equal(wrong_parent_template["height"], first_candidate)
        assert_equal(wrong_parent_template["_btcprevhash"], self.TIP)
        wrong_parent_auxpow = computeAuxpow(
            wrong_parent_template["hash"],
            reverseHex(wrong_parent_template["_target"]),
            True,
            wrong_parent_template["coinbasescript"],
            self.OLD,
        )
        assert_equal(
            node.getauxblock(
                wrong_parent_template["hash"], wrong_parent_auxpow),
            False,
        )
        assert_equal(node.getblockcount(), first_candidate - 1)

        template = node.createauxblock(ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(template["height"], first_candidate)
        assert_equal(template["_btcprevhash"], self.TIP)
        # Reusing the cached candidate exercises the AuxPoW-version header
        # while its proof slot is deliberately still null.
        assert_equal(node.createauxblock(ADDRESS_BCRT1_UNSPENDABLE), template)

        # The Syscoin tip and payout remain unchanged. Advancing only the
        # independent Bitcoin view must invalidate the cached work, embed the
        # new BTCPREV, and then cache that replacement for subsequent polls.
        initial_template_hash = template["hash"]
        self.state["headers"][self.TIP]["confirmations"] = 2
        self.state["headers"][self.NEXT_TIP] = {
            "height": 101,
            "confirmations": 1,
            "time": int(time.time()),
        }
        self.state["active"]["101"] = self.NEXT_TIP
        self.state["best_hash"] = self.NEXT_TIP
        self.state["tips"] = [{
            "hash": self.NEXT_TIP,
            "height": 101,
            "status": "active",
        }]
        self._write_state()

        template = node.createauxblock(ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(template["height"], first_candidate)
        assert_equal(template["_btcprevhash"], self.NEXT_TIP)
        assert template["hash"] != initial_template_hash
        assert_equal(node.createauxblock(ADDRESS_BCRT1_UNSPENDABLE), template)
        self._mine_template(template)
        raw_candidate = self._assert_raw_btcprev_binding(
            template["hash"], self.NEXT_TIP)

        # Reindex must revalidate and reproduce the exact raw candidate. This
        # covers historical replay without exposing a test-only block-index RPC.
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        force_finish_mnsync(node)
        assert_equal(node.getblockhash(anchor["height"]), anchor["blockHash"])
        assert_equal(node.getblock(template["hash"], 0), raw_candidate)
        self._assert_raw_btcprev_binding(template["hash"], self.NEXT_TIP)

        while node.getblockcount() < second_candidate - 1:
            mineAuxpowBlock(node, None)

        self.state["headers"][self.NEXT_TIP]["time"] = int(time.time()) - 7201
        self._write_state()
        assert_raises_rpc_error(
            -1, "btc-tip-stale", node.createauxblock, address)

        self.state["headers"][self.NEXT_TIP]["time"] = int(time.time())
        self._write_state()
        assert_raises_rpc_error(
            -1, "btc-candidate-too-old", node.createauxblock,
            address, self.OLD)

        self.state["tips"].append(
            {"hash": self.FORK, "height": 99, "status": "valid-fork"})
        self._write_state()
        assert_raises_rpc_error(
            -1, "btc-recent-fork", node.createauxblock, address)

        self.state["tips"] = self.state["tips"][:1]
        self.state["online"] = False
        self._write_state()
        assert_raises_rpc_error(
            -1, "btcheadercmd-exit-1", node.createauxblock, address)

        self.state["online"] = True
        self.state["sleep"] = 2
        self._write_state()
        assert_raises_rpc_error(
            -1, "btcheadercmd-timeout", node.createauxblock, address)

        self.state["sleep"] = 0
        self.state["spawn_descendant"] = True
        self._write_state()
        recovered = node.createauxblock(address)
        assert_equal(recovered["height"], second_candidate)
        assert_equal(recovered["_btcprevhash"], self.NEXT_TIP)
        self._mine_template(recovered)

        self.state["spawn_descendant"] = False
        self._write_state()


if __name__ == "__main__":
    BTCHeaderPolicyAuxpowTest().main()
