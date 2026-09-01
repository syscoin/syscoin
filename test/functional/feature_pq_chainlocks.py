#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Live P2P coverage for post-quantum ChainLock admission and finality.

The test prepares a private registry and activates PQ rules at a runtime-mined
height. It never changes the production 400-member, 267-threshold, four-roster
profile. A non-installed C++ helper derives four snapshots from the mined
branch and signs 801 real scheduled-WOTS shares; syscoind receives them only through the
production P2P collector.
"""

import json
import os
import struct
import subprocess
import sys
import time
from copy import deepcopy
from io import BytesIO
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.auxpow import reverseHex
from test_framework.auxpow_testing import computeAuxpow
from test_framework.blocktools import script_BIP34_coinbase_height
from test_framework.messages import (
    CAuxPow,
    CBlock,
    CInv,
    MSG_CLSIG,
    MSG_PQPOSECERT,
    hash256,
    msg_clsig,
    msg_generic,
    msg_getclsig,
    msg_getpqpose,
    msg_inv,
    msg_pqclshare,
    msg_pqposecert,
    ser_uint256,
    uint256_from_compact,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface, P2P_VERSION
from test_framework.script import CScript, OP_RETURN
from test_framework.test_node import ErrorMatch
from test_framework.test_framework import SkipTest, SyscoinTestFramework
from test_framework.util import (
    Decimal,
    assert_equal,
    assert_raises_rpc_error,
    force_finish_mnsync,
    p2p_port,
)


CHAINLOCK_VERSION = 1
CHILD_PROFILE = 1
QUORUM_SIZE = 400
QUORUM_THRESHOLD = 267
QUORUM_MIN_VALID = 300
ACTIVE_QUORUMS = 4
REQUIRED_QUORUMS = 3
CHILD_SIGNATURE_SIZE = 704
CHILD_KEY_TREE_DEPTH = 16
CHILD_KEY_PROOF_SIZE = 32 + CHILD_KEY_TREE_DEPTH * 32
AUTHENTICATED_CHILD_SIGNATURE_SIZE = CHILD_KEY_PROOF_SIZE + CHILD_SIGNATURE_SIZE
FINAL_SIGNATURE_COUNT = REQUIRED_QUORUMS * QUORUM_THRESHOLD
BITMAP_SIZE = QUORUM_SIZE // 8
BTCC_RECEIPT_STATE_SIZE = 100
BTCC_RECEIPT_WIRE_SIZE = 138
PAYMENT_AUDIT_RECEIPT_STATE_SIZE = 136
ROSTER_BEACON_SEED_WIRE_SIZE = 112
RECOVERY_ROSTER_AUTHORITY_SOURCE_WIRE_SIZE = 517
CHAINLOCK_STATEMENT_WIRE_SIZE = 1_657
FINAL_CHAINLOCK_FIXED_WIRE_SIZE = (
    CHAINLOCK_STATEMENT_WIRE_SIZE + 1 + ACTIVE_QUORUMS * BITMAP_SIZE + 2
)
PQCLSHARE_WIRE_SIZE = 1_282
SELF_CONTAINED_CHAINLOCK_SHARE_WIRE_SIZE = 2_975
FINAL_CHAINLOCK_WIRE_SIZE = 1_001_508
FINAL_PAYMENT_AUDIT_WIRE_SIZE = 1_041_907
PAYMENT_AUDIT_RECEIPT_WIRE_SIZE = 369
PAYMENT_AUDIT_RECEIPT_VERSION = 1
PAYMENT_PROBATION_STATE_VERSION = 1
CHAINLOCK_PERIOD = 5
FIRST_ELIGIBLE_TARGET_HEIGHT = 2315
ACTIVATION_PREDECESSOR_HEIGHT = FIRST_ELIGIBLE_TARGET_HEIGHT - 1
SIGN_LAG = 5
EPOCH_ORIGIN = 1440
EPOCH_BLOCKS = 288
REGISTRATION_CUTOFF_BLOCKS = 288
ROSTER_SNAPSHOT_LAG = 288
FUTURE_HORIZON_EPOCHS = 8
BTCC_CANDIDATE_ORIGIN = 2315
BTCC_CANDIDATE_PERIOD = 10
PAYMENT_AUDIT_PREP_EPOCH = 3
PAYMENT_AUDIT_PREP_RESPONSE_HEIGHT = 2545
PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT = 2575
PAYMENT_AUDIT_PREP_CARRIER_HEIGHT = PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT + 10
PAYMENT_AUDIT_EPOCH = 4
PAYMENT_AUDIT_RESPONSE_HEIGHT = 2825
PAYMENT_AUDIT_RESPONSE_PREDECESSOR_HEIGHT = \
    PAYMENT_AUDIT_RESPONSE_HEIGHT - CHAINLOCK_PERIOD
PAYMENT_AUDIT_ANCHOR_HEIGHT = 2855
PAYMENT_AUDIT_ANCHOR_PREDECESSOR_HEIGHT = \
    PAYMENT_AUDIT_ANCHOR_HEIGHT - CHAINLOCK_PERIOD
PAYMENT_AUDIT_SEED_CARRIER_HEIGHT = PAYMENT_AUDIT_ANCHOR_HEIGHT + 10
PAYMENT_AUDIT_SEAL_HEIGHT = 3100
PAYMENT_AUDIT_SEAL_PREDECESSOR_HEIGHT = \
    PAYMENT_AUDIT_SEAL_HEIGHT - CHAINLOCK_PERIOD
PAYMENT_AUDIT_CARRIER_HEIGHT = 3115
PAYMENT_AUDIT_POST_TARGET_HEIGHT = 3120
PAYMENT_AUDIT_POST_PREDECESSOR_HEIGHT = \
    PAYMENT_AUDIT_POST_TARGET_HEIGHT - CHAINLOCK_PERIOD
PAYMENT_AUDIT_POST_SIGNING_HEIGHT = 3125
CURRENT_CATCHUP_PREDECESSOR_HEIGHT = \
    FIRST_ELIGIBLE_TARGET_HEIGHT + CHAINLOCK_PERIOD
CURRENT_CATCHUP_TARGET_HEIGHT = \
    CURRENT_CATCHUP_PREDECESSOR_HEIGHT + CHAINLOCK_PERIOD
CURRENT_CATCHUP_TIP_HEIGHT = CURRENT_CATCHUP_TARGET_HEIGHT + SIGN_LAG
RECOVERY_ANCHOR_BTC_HEIGHT = 800_000
RECOVERY_FUTURE_BTC_HEIGHT = RECOVERY_ANCHOR_BTC_HEIGHT + 37
RECOVERY_READY_TIP_BTC_HEIGHT = RECOVERY_FUTURE_BTC_HEIGHT + 5
RECOVERY_FUTURE_BTC_HASH = "%064x" % 0xb8000000
RECOVERY_READY_TIP_BTC_HASH = "%064x" % 0xb9000000
LOGICAL_ID_DOMAIN = b"SYS_PQ_CHAINLOCK_LOGICAL_ID_V1"
SHARE_BUNDLE_MAGIC = 0x315246534C435150
SHARE_BUNDLE_VERSION = 1
SHARE_BUNDLE_MAX_SIZE = 8 << 20
SHARE_BUNDLE_CHECKSUM_DOMAIN = b"SYS_PQ_CHAINLOCK_SHARE_FIXTURE_V1"
PAYMENT_PROBATION_STATE_HASH_DOMAIN = b"SYS_PQ_PAYMENT_PROBATION_STATE_V1"
PAYMENT_AUDIT_BUNDLE_MAGIC = 0x3154414550505153
PAYMENT_AUDIT_BUNDLE_VERSION = 1
PAYMENT_AUDIT_BUNDLE_MAX_SIZE = 24 << 20
PAYMENT_AUDIT_BUNDLE_CHECKSUM_DOMAIN = \
    b"SYS_PQ_PAYMENT_AUDIT_FUNCTIONAL_FIXTURE_V1"
PAYMENT_AUDIT_PREFIX_BUNDLE_MAGIC = 0x3158465250505153
PAYMENT_AUDIT_PREFIX_BUNDLE_VERSION = 1
PAYMENT_AUDIT_PREFIX_BUNDLE_MAX_SIZE = 8 << 20
PAYMENT_AUDIT_PREFIX_BUNDLE_CHECKSUM_DOMAIN = \
    b"SYS_PQ_PAYMENT_AUDIT_PREFIX_FUNCTIONAL_FIXTURE_V1"
POST_CHAINLOCK_BUNDLE_MAGIC = 0x3154534F50435153
POST_CHAINLOCK_BUNDLE_VERSION = 1
POST_CHAINLOCK_BUNDLE_CHECKSUM_DOMAIN = \
    b"SYS_PQ_PAYMENT_AUDIT_POST_CHAINLOCK_V1"


FAKE_BTC_HEADER_BACKEND = r'''#!/usr/bin/env python3
import json
import os
import sys

state_path = sys.argv[1]
with open(state_path, "r", encoding="utf8") as handle:
    state = json.load(handle)

view = state["ready" if state["ready_phase"] else "anchor"]
method = sys.argv[2]
args = sys.argv[3:]
if method == "getblockchaininfo" and not args:
    result = {
        "chain": "regtest",
        "initialblockdownload": False,
        "bestblockhash": view["best_hash"],
        "headers": view["headers"][view["best_hash"]]["height"],
    }
elif method == "getblockheader" and len(args) == 2 and args[1] == "true":
    if args[0] not in view["headers"]:
        print("header-not-found", file=sys.stderr)
        sys.exit(1)
    result = dict(view["headers"][args[0]])
    result["hash"] = args[0]
elif method == "getblockhash" and len(args) == 1:
    if args[0] not in view["active"]:
        print("height-not-found", file=sys.stderr)
        sys.exit(1)
    print(view["active"][args[0]])
    if (not state["ready_phase"] and
            args[0] == str(state["anchor_height"])):
        state["ready_phase"] = True
        replacement = state_path + ".tmp"
        with open(replacement, "w", encoding="utf8") as handle:
            json.dump(state, handle)
        os.replace(replacement, state_path)
    sys.exit(0)
elif method == "getchaintips" and not args:
    result = [{
        "hash": view["best_hash"],
        "height": view["headers"][view["best_hash"]]["height"],
        "status": "active",
    }]
else:
    print("unsupported method", file=sys.stderr)
    sys.exit(2)

json.dump(result, sys.stdout)
'''


def serialize_cursor(sys_height=-1, sys_hash=0, btc_hash=0):
    return (
        struct.pack("<i", sys_height)
        + ser_uint256(sys_hash)
        + ser_uint256(btc_hash)
    )


def serialize_receipt_state():
    payload = serialize_cursor() + ser_uint256(0)
    assert_equal(len(payload), BTCC_RECEIPT_STATE_SIZE)
    return payload


def serialize_payment_audit_receipt_state():
    payload = (
        struct.pack("<iI", -1, 0)
        + ser_uint256(0)
        + ser_uint256(0)
        + ser_uint256(0)
        + ser_uint256(0)
    )
    assert_equal(len(payload), PAYMENT_AUDIT_RECEIPT_STATE_SIZE)
    return payload


def serialize_roster_beacon_seed(epoch, state=2):
    if state == 0:
        return (
            struct.pack("<HBBI", 1, 1, state, epoch)
            + serialize_cursor()
            + struct.pack("<i", -1)
            + ser_uint256(0)
        )
    return (
        struct.pack("<HBBI", 1, 1, state, epoch)
        + serialize_cursor(
            10_000 + epoch, 100_000 + epoch, 200_000 + epoch)
        + struct.pack("<i", 800_000 + epoch)
        + ser_uint256(300_000 + epoch if state == 2 else 0)
    )


def serialize_null_recovery_roster_authority_source():
    payload = (
        struct.pack("<Bi", 0, -1)
        + ser_uint256(0)
        + ser_uint256(0)
        + serialize_roster_beacon_seed(0, state=0) * ACTIVE_QUORUMS
    )
    assert_equal(len(payload), RECOVERY_ROSTER_AUTHORITY_SOURCE_WIRE_SIZE)
    return payload


def serialize_roster_beacon_window(newest_epoch=3):
    first_epoch = newest_epoch - ACTIVE_QUORUMS + 1
    return (
        struct.pack("<H", 1)
        + b"".join(
            serialize_roster_beacon_seed(first_epoch + slot)
            for slot in range(ACTIVE_QUORUMS)
        )
        + ser_uint256(0)
        + serialize_null_recovery_roster_authority_source()
        + serialize_roster_beacon_seed(newest_epoch + 1, state=0)
    )


def empty_payment_probation_state_hash():
    # version, null cursor (including its canonical null identity), count=0
    state = (
        struct.pack("<HB", PAYMENT_PROBATION_STATE_VERSION, 0)
        + struct.pack("<Ii", 0, -1)
        + ser_uint256(0)
        + struct.pack("<H", 0)
    )
    return uint256_from_str(
        hash256(PAYMENT_PROBATION_STATE_HASH_DOMAIN + state)
    )


def serialize_authenticated_child_signature(signature_byte=0):
    # A non-zero public key is the only structural proof requirement. The
    # private-anchor fixture intentionally reaches context-unavailable before
    # cryptographic verification, so zero siblings/signature are sufficient.
    return (
        b"\x01" + bytes(31)
        + bytes(CHILD_KEY_TREE_DEPTH * 32)
        + bytes([signature_byte]) * CHILD_SIGNATURE_SIZE
    )


def serialize_statement(height, block_hash, previous_height, previous_hash,
                        quorum_context_hash):
    payload = (
        struct.pack("<HHi", CHAINLOCK_VERSION, CHILD_PROFILE, height)
        + ser_uint256(block_hash)
        + struct.pack("<i", previous_height)
        + ser_uint256(previous_hash)
        + ser_uint256(quorum_context_hash)
        + struct.pack("<B", 1)  # RosterAuthorizationTransitionKind::KEEP
        + serialize_roster_beacon_window()
        + ser_uint256(0x41555448)
        + serialize_cursor()
        + serialize_cursor()
        + struct.pack("<B", 0)  # BTCCAdvance::KEEP
        + serialize_receipt_state()
        + serialize_payment_audit_receipt_state()
        + ser_uint256(empty_payment_probation_state_hash())
    )
    assert_equal(len(payload), CHAINLOCK_STATEMENT_WIRE_SIZE)
    return payload


def logical_id(genesis_hash, statement):
    return uint256_from_str(
        hash256(LOGICAL_ID_DOMAIN + ser_uint256(genesis_hash) + statement)
    )


def serialize_share(statement_logical_id, quorum_slot, member_index):
    assert 0 <= quorum_slot < ACTIVE_QUORUMS
    assert 0 <= member_index < QUORUM_SIZE
    payload = (
        ser_uint256(statement_logical_id)
        + struct.pack("<H", quorum_slot * QUORUM_SIZE + member_index)
        + serialize_authenticated_child_signature()
    )
    assert_equal(len(payload), PQCLSHARE_WIRE_SIZE)
    return payload


def serialize_final_chainlock(statement, signature_byte=0):
    full_bytes, residual_bits = divmod(QUORUM_THRESHOLD, 8)
    selected_bitmap = (
        bytes([0xff] * full_bytes)
        + (bytes([(1 << residual_bits) - 1]) if residual_bits else b"")
        + bytes(BITMAP_SIZE - full_bytes - (1 if residual_bits else 0))
    )
    empty_bitmap = bytes(BITMAP_SIZE)
    payload = (
        statement
        + struct.pack("<B", 0b1011)
        + selected_bitmap
        + selected_bitmap
        + empty_bitmap
        + selected_bitmap
        + struct.pack("<H", FINAL_SIGNATURE_COUNT)
        + serialize_authenticated_child_signature(signature_byte) * FINAL_SIGNATURE_COUNT
    )
    signature_count_offset = (
        CHAINLOCK_STATEMENT_WIRE_SIZE + 1 + ACTIVE_QUORUMS * BITMAP_SIZE
    )
    assert_equal(len(statement), CHAINLOCK_STATEMENT_WIRE_SIZE)
    assert_equal(payload[CHAINLOCK_STATEMENT_WIRE_SIZE], 0b1011)
    assert_equal(
        struct.unpack_from("<H", payload, signature_count_offset)[0],
        FINAL_SIGNATURE_COUNT,
    )
    assert_equal(
        len(payload),
        FINAL_CHAINLOCK_FIXED_WIRE_SIZE
        + FINAL_SIGNATURE_COUNT * AUTHENTICATED_CHILD_SIGNATURE_SIZE,
    )
    assert_equal(len(payload), FINAL_CHAINLOCK_WIRE_SIZE)
    return payload


class PQChainLocksTest(SyscoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 1200
        self.base_args = [
            "-debug=chainlocks",
            "-debug=net",
            "-dip3params=1:1",
            "-mncollateral=100",
            "-sporkkey=cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW",
        ]
        self.extra_args = [list(self.base_args)]

    def setup_chain(self):
        super().setup_chain()
        root = Path(self.options.tmpdir)
        self.btc_backend_script = root / "pq-fake-bitcoin-cli.py"
        self.btc_backend_state = root / "pq-fake-bitcoin-state.json"
        self.btc_backend_script.write_text(
            FAKE_BTC_HEADER_BACKEND, encoding="utf8")
        self.btc_backend_script.chmod(0o700)

        anchor_hash = self.payment_btcprev(
            FIRST_ELIGIBLE_TARGET_HEIGHT)
        now = int(time.time())
        anchor_header = {
            "height": RECOVERY_ANCHOR_BTC_HEIGHT,
            "confirmations": 1,
            "time": now,
        }
        ready_anchor = dict(anchor_header)
        ready_anchor["confirmations"] = (
            RECOVERY_READY_TIP_BTC_HEIGHT
            - RECOVERY_ANCHOR_BTC_HEIGHT + 1
        )
        state = {
            "ready_phase": False,
            "anchor_height": RECOVERY_ANCHOR_BTC_HEIGHT,
            "anchor": {
                "best_hash": anchor_hash,
                "headers": {anchor_hash: anchor_header},
                "active": {
                    str(RECOVERY_ANCHOR_BTC_HEIGHT): anchor_hash,
                },
            },
            "ready": {
                "best_hash": RECOVERY_READY_TIP_BTC_HASH,
                "headers": {
                    anchor_hash: ready_anchor,
                    RECOVERY_FUTURE_BTC_HASH: {
                        "height": RECOVERY_FUTURE_BTC_HEIGHT,
                        "confirmations": 6,
                        "time": now,
                    },
                    RECOVERY_READY_TIP_BTC_HASH: {
                        "height": RECOVERY_READY_TIP_BTC_HEIGHT,
                        "confirmations": 1,
                        "time": now,
                    },
                },
                "active": {
                    str(RECOVERY_ANCHOR_BTC_HEIGHT): anchor_hash,
                    str(RECOVERY_FUTURE_BTC_HEIGHT):
                        RECOVERY_FUTURE_BTC_HASH,
                    str(RECOVERY_READY_TIP_BTC_HEIGHT):
                        RECOVERY_READY_TIP_BTC_HASH,
                },
            },
        }
        self.btc_backend_state.write_text(
            json.dumps(state), encoding="utf8")
        self.btc_backend_args = [
            "-btcheaderpolicyondemand=1",
            "-btcheadermanaged=0",
            "-btcheadercmdtimeout=2",
            "-btcheadertipmaxage=0",
            "-btcheadercmd=%s" % sys.executable,
            "-btcheaderarg=%s" % self.btc_backend_script,
            "-btcheaderarg=%s" % self.btc_backend_state,
        ]

    def skip_test_if_missing_module(self):
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.skip_if_no_wallet()
        if not self.config["components"].getboolean(
                "ENABLE_BTC_HEADER_COMMAND", fallback=False):
            raise SkipTest(
                "Boost.Process Bitcoin header backend unavailable")

    @staticmethod
    def peer_id(node, marker):
        matches = [
            peer["id"]
            for peer in node.getpeerinfo()
            if marker in peer.get("subver", "")
        ]
        assert_equal(len(matches), 1)
        return matches[0]

    @staticmethod
    def assert_no_chainlock_rpcs(node):
        assert_raises_rpc_error(
            -32603, "Unable to find any ChainLock", node.getbestchainlock)
        assert_raises_rpc_error(
            -32603, "Unable to find any chainlock", node.getchainlocks)

    def connect_peer(self, marker):
        peer = self.nodes[0].add_p2p_connection(
            P2PInterface(), uacomment=marker
        )
        peer.wait_for_verack()
        peer_info = next(
            info
            for info in self.nodes[0].getpeerinfo()
            if info["id"] == self.peer_id(self.nodes[0], marker)
        )
        assert_equal(peer_info["version"], P2P_VERSION)
        return peer

    def authenticate_peer(self, peer, marker, protx_hash):
        assert self.nodes[0].mnauth(
            self.peer_id(self.nodes[0], marker),
            "%064x" % protx_hash,
            "%064x" % 0x22,
            1,
        )
        peer_info = next(
            info for info in self.nodes[0].getpeerinfo()
            if info["id"] == self.peer_id(self.nodes[0], marker)
        )
        assert_equal(
            peer_info["verified_proregtx_hash"], "%064x" % protx_hash)
        return peer

    def install_payment_masternode(self, node, mining_address):
        while node.getbalance() < Decimal("101"):
            self.generatetoaddress(
                node, 10, mining_address, sync_fun=self.no_op)

        operator_keys = node.protx_generate_operator_keypair()
        funds_address = node.getnewaddress()
        owner_address = node.getnewaddress()
        payout_address = node.getnewaddress()
        service = "127.0.0.1:%d" % p2p_port(2)
        node.sendtoaddress(funds_address, Decimal("100.001"))
        protx_hash = node.protx_register_fund(
            node.getnewaddress(),
            service,
            owner_address,
            "",
            owner_address,
            0,
            payout_address,
            funds_address,
        )
        self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        node.protx_register_operator_key(
            protx_hash,
            operator_keys["operatorKey"],
            operator_keys["chainlockSeed"],
            funds_address,
        )
        self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        info = node.protx_info(protx_hash)
        assert_equal(info["state"]["PoSeBanHeight"], -1)
        assert_equal(
            node.protx_operator_key_info(protx_hash)["keyVersion"], 1)
        self.payment_masternode_protx_hash = protx_hash

    def configure_private_migration(self):
        node = self.nodes[0]
        address = node.getnewaddress()
        self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
        preparation_state = node.protx_migration_info()
        assert_equal(preparation_state["height"], 1)

        registration_cutoff_blocks = 288
        # SYSCOIN: roster membership is sampled only after root registration closes.
        roster_snapshot_lag = 288
        assert registration_cutoff_blocks >= roster_snapshot_lag
        profile_args = self.base_args + [
            "-pqpreparationheight=1",
            "-pqchainlockepochorigin=1440",
            "-pqregistrationcutoffblocks=%d" % registration_cutoff_blocks,
            "-pqrostersnapshotlag=%d" % roster_snapshot_lag,
            "-pqfuturehorizonepochs=8",
        ]
        preparation_args = profile_args + [
            "-pqfinalitypreparation=1",
            "-pqoperatorcommitmentteststub=1",
        ]
        self.stop_node(0)
        node.extra_args = list(preparation_args)
        with node.assert_debug_log([
                "PQ registry/quorum preparation is active on regtest; no "
                "PQ finality service will start"]):
            self.start_node(0, extra_args=preparation_args + ["-reindex"])
        force_finish_mnsync(node)
        assert_equal(node.protx_migration_info(), preparation_state)
        self.assert_no_chainlock_rpcs(node)

        # Post-activation payment consensus requires at least one valid
        # operator whose child root was frozen before activation. The
        # synthetic quorum fixture does not replace the on-chain payment set.
        self.install_payment_masternode(node, address)

        self.generatetoaddress(
            node, ACTIVATION_PREDECESSOR_HEIGHT - node.getblockcount(), address,
            sync_fun=self.no_op)
        assert_equal(node.getblockcount(), ACTIVATION_PREDECESSOR_HEIGHT)
        activation_predecessor = {
            "height": ACTIVATION_PREDECESSOR_HEIGHT,
            "blockHash": node.getblockhash(ACTIVATION_PREDECESSOR_HEIGHT),
        }
        pq_args = profile_args + [
            "-pqactivationheight=%d" % (activation_predecessor["height"] + 1),
            "-pqbtcccandidateorigin=%d" % BTCC_CANDIDATE_ORIGIN,
            "-pqbtccreceiptanchorheight=%d" % activation_predecessor["height"],
            "-pqbtccreceiptanchorblockhash=%s" % activation_predecessor["blockHash"],
            "-pqbtccreceiptanchorcursorheight=-1",
            "-pqbtccreceiptanchorcursorsyshash=%s" % ("0" * 64),
            "-pqbtccreceiptanchorcursorbtchash=%s" % ("0" * 64),
            "-pqbtccreceiptanchorstatehash=%s" % ("0" * 64),
        ]
        self.stop_node(0)
        self.extra_args[0] = pq_args
        node.extra_args = list(pq_args)
        self.start_node(0, extra_args=pq_args + ["-reindex"])
        tip_state = node.protx_migration_info()
        assert_equal(tip_state["height"], activation_predecessor["height"])
        assert_equal(tip_state["blockHash"], activation_predecessor["blockHash"])
        assert_equal(node.getblockhash(activation_predecessor["height"]),
                     activation_predecessor["blockHash"])

        node.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        assert_equal(self.mine_one_pq_block(),
                     node.getblockhash(FIRST_ELIGIBLE_TARGET_HEIGHT))
        self.assert_no_chainlock_rpcs(node)
        return preparation_state, activation_predecessor

    def test_rpc_compatibility_without_winner(self, preparation_state):
        node = self.nodes[0]
        self.assert_no_chainlock_rpcs(node)
        assert_equal(node.gettxchainlocks([]), [])
        assert_equal(
            node.gettxchainlocks(["01".zfill(64)]),
            [{"height": 0, "chainlock": False, "mempool": False}],
        )

        preparation_coinbase = node.getblock(
            preparation_state["blockHash"], 2)["tx"][0]["txid"]
        # A height-only cutover does not manufacture finality. Until the first
        # valid certificate is durably accepted, ordinary PoW fork choice
        # remains authoritative for every historical block.
        assert_equal(
            node.gettxchainlocks([preparation_coinbase]),
            [{"height": preparation_state["height"], "chainlock": False,
              "mempool": False}],
        )
        genesis_coinbase = node.getblock(node.getblockhash(0), 2)["tx"][0]["txid"]
        assert_raises_rpc_error(
            -5, "genesis block coinbase is not an ordinary transaction",
            node.gettxchainlocks, [genesis_coinbase])
        assert_raises_rpc_error(
            -8, "Up to 100 txids only", node.gettxchainlocks,
            ["%064x" % (index + 1) for index in range(101)])

    def test_share_admission(self, activation_predecessor):
        node = self.nodes[0]
        dmn_state_before = node.protx_migration_info()["dmnStateHash"]
        identity = 0x11
        statement_fields = (
            FIRST_ELIGIBLE_TARGET_HEIGHT,
            0x41,
            activation_predecessor["height"],
            int(activation_predecessor["blockHash"], 16),
            0x42,
        )

        statement_id = logical_id(
            int(node.getblockhash(0), 16),
            serialize_statement(*statement_fields),
        )
        canonical_share = serialize_share(statement_id, 0, 0)
        public_peer = self.connect_peer("pq-share-public")
        with node.assert_debug_log(["unauthenticated-pq-clshare"]):
            public_peer.send_message(msg_pqclshare(canonical_share))
            public_peer.wait_for_disconnect(timeout=10)

        oversized_marker = "pq-share-full-width"
        oversized_peer = self.authenticate_peer(
            self.connect_peer(oversized_marker), oversized_marker, identity
        )
        former_full_width = canonical_share + bytes(
            SELF_CONTAINED_CHAINLOCK_SHARE_WIRE_SIZE - PQCLSHARE_WIRE_SIZE
        )
        with node.assert_debug_log(["bad-pq-clshare-size"]):
            oversized_peer.send_message(msg_pqclshare(former_full_width))
            oversized_peer.wait_for_disconnect(timeout=10)

        # The transport peer is a relay, not necessarily the original signer.
        # This private-anchor test has no 400-operator active roster, so use a
        # stale statement to cover the multi-hop-safe no-punishment path. The
        # fork-pinned live fixture additionally exercises active-roster ingress
        # and collector verification of the original signer. Selected-sentry
        # overlay relay is covered by the relay-plan and overlay unit tests.
        relay_marker = "pq-share-relay"
        relay_peer = self.authenticate_peer(
            self.connect_peer(relay_marker), relay_marker, identity
        )
        relayed_share = serialize_share(statement_id, 0, 1)
        relay_peer.send_and_ping(msg_pqclshare(relayed_share))
        assert relay_peer.is_connected
        assert_equal(
            node.protx_migration_info()["dmnStateHash"], dmn_state_before)
        self.assert_no_chainlock_rpcs(node)

    def test_getclsig_requests(self):
        node = self.nodes[0]

        # An empty request asks for the current winner. With no winner it is a
        # valid no-op and must not fabricate or announce a certificate.
        best_peer = self.connect_peer("pq-getclsig-best")
        best_peer.send_and_ping(msg_getclsig())
        assert best_peer.is_connected
        assert "inv" not in best_peer.last_message
        self.assert_no_chainlock_rpcs(node)

        unknown_peer = self.connect_peer("pq-getclsig-unknown")
        unknown_peer.send_and_ping(msg_getclsig(1))
        assert unknown_peer.is_connected
        assert "inv" not in unknown_peer.last_message

        null_peer = self.connect_peer("pq-getclsig-null")
        with node.assert_debug_log(["bad-getclsig-id"]):
            null_peer.send_message(msg_getclsig(0))
            null_peer.wait_for_disconnect(timeout=10)

        trailing_peer = self.connect_peer("pq-getclsig-trailing")
        with node.assert_debug_log(["bad-getclsig-size"]):
            trailing_peer.send_message(msg_generic(
                b"getclsig", ser_uint256(1) + b"\x00"))
            trailing_peer.wait_for_disconnect(timeout=10)

    def request_chainlock(self, peer, logical_hash):
        peer.send_message(msg_inv([CInv(MSG_CLSIG, logical_hash)]))
        peer.wait_for_getdata([logical_hash], timeout=15)
        assert_equal(peer.last_message["getdata"].inv[0].type, MSG_CLSIG)

    def test_final_chainlock_admission(self, activation_predecessor):
        node = self.nodes[0]
        genesis_hash = int(node.getblockhash(0), 16)
        previous_hash = int(activation_predecessor["blockHash"], 16)

        requested_statement = serialize_statement(
            FIRST_ELIGIBLE_TARGET_HEIGHT,
            0x51,
            activation_predecessor["height"],
            previous_hash,
            0x52,
        )
        requested_id = logical_id(genesis_hash, requested_statement)
        requested_certificate = serialize_final_chainlock(requested_statement)

        # Size checks precede request matching. Cover both independently so a
        # short unsolicited payload cannot masquerade as request-boundary
        # coverage.
        short_marker = "pq-clsig-short"
        short_peer = self.authenticate_peer(
            self.connect_peer(short_marker), short_marker, 0x101)
        self.request_chainlock(short_peer, requested_id)
        with node.assert_debug_log(["bad-pq-clsig-size"]):
            short_peer.send_message(msg_clsig(b"\x00"))
            short_peer.wait_for_disconnect(timeout=10)

        unsolicited_peer = self.connect_peer("pq-clsig-unsolicited")
        with node.assert_debug_log(["unsolicited-pq-clsig"]):
            unsolicited_peer.send_message(msg_clsig(requested_certificate))
            unsolicited_peer.wait_for_disconnect(timeout=30)

        wrong_statement = serialize_statement(
            FIRST_ELIGIBLE_TARGET_HEIGHT,
            0x53,
            activation_predecessor["height"],
            previous_hash,
            0x52,
        )
        wrong_response = serialize_final_chainlock(wrong_statement)

        wrong_marker = "pq-clsig-wrong-response"
        wrong_peer = self.authenticate_peer(
            self.connect_peer(wrong_marker), wrong_marker, 0x102)
        self.request_chainlock(wrong_peer, requested_id)
        with node.assert_debug_log(["wrong-pq-clsig-response"]):
            wrong_peer.send_message(msg_clsig(wrong_response))
            wrong_peer.wait_for_disconnect(timeout=30)

        requested_marker = "pq-clsig-requested"
        requested_peer = self.authenticate_peer(
            self.connect_peer(requested_marker), requested_marker, 0x103)
        self.request_chainlock(requested_peer, requested_id)
        requested_peer.send_and_ping(msg_clsig(requested_certificate))
        assert requested_peer.is_connected
        self.assert_no_chainlock_rpcs(node)

        # The logical ID excludes signatures. A different exact-size witness
        # for the same statement must pass request matching but still fail
        # closed when no production roster context exists.
        alternate_marker = "pq-clsig-alternate-witness"
        alternate_peer = self.authenticate_peer(
            self.connect_peer(alternate_marker), alternate_marker, 0x104)
        self.request_chainlock(alternate_peer, requested_id)
        alternate_peer.send_and_ping(
            msg_clsig(serialize_final_chainlock(
                requested_statement, signature_byte=1)))
        assert alternate_peer.is_connected
        self.assert_no_chainlock_rpcs(node)

    def test_no_winner_survives_restart(self, preparation_state):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        tip_migration_state = node.protx_migration_info()
        self.restart_node(0, extra_args=self.extra_args[0])
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.protx_migration_info(), tip_migration_state)
        self.test_rpc_compatibility_without_winner(preparation_state)

    @staticmethod
    def read_full_dimension_bundle(path):
        data = Path(path).read_bytes()
        assert len(data) <= SHARE_BUNDLE_MAX_SIZE
        assert len(data) > 32
        body, checksum = data[:-32], data[-32:]
        assert_equal(hash256(SHARE_BUNDLE_CHECKSUM_DOMAIN + body), checksum)

        header_size = struct.calcsize("<QHIII")
        magic, version, share_count, share_size, certificate_size = \
            struct.unpack_from("<QHIII", body, 0)
        assert_equal(magic, SHARE_BUNDLE_MAGIC)
        assert_equal(version, SHARE_BUNDLE_VERSION)
        assert_equal(share_count, FINAL_SIGNATURE_COUNT)
        assert_equal(share_size, PQCLSHARE_WIRE_SIZE)
        assert_equal(certificate_size, FINAL_CHAINLOCK_WIRE_SIZE)

        offset = header_size
        values = []
        for _ in range(4):
            values.append(uint256_from_str(body[offset:offset + 32]))
            offset += 32
        sender_identity, observer_identity, logical_hash, witness_hash = values
        shares = []
        for _ in range(share_count):
            shares.append(body[offset:offset + share_size])
            offset += share_size
        certificate = body[offset:offset + certificate_size]
        offset += certificate_size
        assert_equal(offset, len(body))
        assert_equal(len(certificate), FINAL_CHAINLOCK_WIRE_SIZE)
        return {
            "sender_identity": sender_identity,
            "observer_identity": observer_identity,
            "logical_hash": logical_hash,
            "witness_hash": witness_hash,
            "shares": shares,
            "certificate": certificate,
        }

    @staticmethod
    def _read_uint256(body, offset):
        end = offset + 32
        assert end <= len(body)
        return uint256_from_str(body[offset:end]), end

    @classmethod
    def _read_chainlock_artifact(cls, body, offset):
        logical_hash, offset = cls._read_uint256(body, offset)
        witness_hash, offset = cls._read_uint256(body, offset)
        certificate_size = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        assert_equal(certificate_size, FINAL_CHAINLOCK_WIRE_SIZE)
        certificate = body[offset:offset + certificate_size]
        assert_equal(len(certificate), certificate_size)
        return {
            "logical_hash": logical_hash,
            "witness_hash": witness_hash,
            "certificate": certificate,
        }, offset + certificate_size

    @staticmethod
    def _decode_payment_audit_receipt(receipt):
        assert_equal(len(receipt), PAYMENT_AUDIT_RECEIPT_WIRE_SIZE)
        version, has_audit, epoch, seal_height = struct.unpack_from(
            "<HBIi", receipt, 0)
        offset = struct.calcsize("<HBIi")
        seal_hash = uint256_from_str(receipt[offset:offset + 32])
        offset += 32
        carrier_height = struct.unpack_from("<i", receipt, offset)[0]
        offset += 4
        values = []
        for _ in range(5):
            values.append(uint256_from_str(receipt[offset:offset + 32]))
            offset += 32
        subject_roster_beacon = receipt[
            offset:offset + ROSTER_BEACON_SEED_WIRE_SIZE]
        assert_equal(len(subject_roster_beacon),
                     ROSTER_BEACON_SEED_WIRE_SIZE)
        offset += ROSTER_BEACON_SEED_WIRE_SIZE
        online_members = receipt[offset:offset + BITMAP_SIZE]
        assert_equal(len(online_members), BITMAP_SIZE)
        offset += BITMAP_SIZE
        assert_equal(offset, len(receipt))
        return {
            "version": version,
            "has_audit": has_audit,
            "epoch": epoch,
            "seal_height": seal_height,
            "seal_hash": seal_hash,
            "carrier_height": carrier_height,
            "audit_logical_hash": values[0],
            "audit_witness_hash": values[1],
            "commitment_hash": values[2],
            "result_hash": values[3],
            "next_probation_state_hash": values[4],
            "subject_roster_beacon": subject_roster_beacon,
            "online_members": online_members,
        }

    @staticmethod
    def _decode_btcc_receipt(receipt):
        assert_equal(len(receipt), BTCC_RECEIPT_WIRE_SIZE)
        version, target_height = struct.unpack_from("<Hi", receipt, 0)
        offset = struct.calcsize("<Hi")
        target_hash = uint256_from_str(receipt[offset:offset + 32])
        offset += 32
        logical_hash = uint256_from_str(receipt[offset:offset + 32])
        offset += 32
        cursor_height = struct.unpack_from("<i", receipt, offset)[0]
        offset += 4
        cursor_sys_hash = uint256_from_str(receipt[offset:offset + 32])
        offset += 32
        cursor_btc_hash = uint256_from_str(receipt[offset:offset + 32])
        offset += 32
        assert_equal(offset, len(receipt))
        return {
            "version": version,
            "target_height": target_height,
            "target_hash": target_hash,
            "logical_hash": logical_hash,
            "cursor_height": cursor_height,
            "cursor_sys_hash": cursor_sys_hash,
            "cursor_btc_hash": cursor_btc_hash,
        }

    @staticmethod
    def _decode_btcc_receipt_state(receipt_state):
        assert_equal(len(receipt_state), BTCC_RECEIPT_STATE_SIZE)
        cursor_height = struct.unpack_from("<i", receipt_state, 0)[0]
        offset = 4
        cursor_sys_hash = uint256_from_str(
            receipt_state[offset:offset + 32])
        offset += 32
        cursor_btc_hash = uint256_from_str(
            receipt_state[offset:offset + 32])
        offset += 32
        cumulative_hash = uint256_from_str(
            receipt_state[offset:offset + 32])
        offset += 32
        assert_equal(offset, len(receipt_state))
        return {
            "cursor_height": cursor_height,
            "cursor_sys_hash": cursor_sys_hash,
            "cursor_btc_hash": cursor_btc_hash,
            "cumulative_hash": cumulative_hash,
        }

    @staticmethod
    def _decode_payment_audit_receipt_state(receipt_state):
        assert_equal(len(receipt_state), PAYMENT_AUDIT_RECEIPT_STATE_SIZE)
        carrier_height, epoch = struct.unpack_from("<iI", receipt_state, 0)
        offset = struct.calcsize("<iI")
        values = []
        for _ in range(4):
            values.append(uint256_from_str(
                receipt_state[offset:offset + 32]))
            offset += 32
        assert_equal(offset, len(receipt_state))
        return {
            "carrier_height": carrier_height,
            "epoch": epoch,
            "seal_hash": values[0],
            "audit_logical_hash": values[1],
            "audit_witness_hash": values[2],
            "cumulative_hash": values[3],
        }

    @classmethod
    def read_payment_audit_bundle(cls, path):
        data = Path(path).read_bytes()
        assert len(data) <= PAYMENT_AUDIT_BUNDLE_MAX_SIZE
        assert len(data) > 32
        body, checksum = data[:-32], data[-32:]
        assert_equal(
            hash256(PAYMENT_AUDIT_BUNDLE_CHECKSUM_DOMAIN + body),
            checksum,
        )

        header_format = "<QHIBHB"
        (magic, version, epoch, selected_row, online_count,
         conclusive) = struct.unpack_from(header_format, body, 0)
        assert_equal(magic, PAYMENT_AUDIT_BUNDLE_MAGIC)
        assert_equal(version, PAYMENT_AUDIT_BUNDLE_VERSION)
        offset = struct.calcsize(header_format)
        unobserved_member, offset = cls._read_uint256(body, offset)
        unobserved_member_misses = body[offset]
        offset += 1
        (response_height, anchor_height, seal_height,
         carrier_height) = struct.unpack_from("<iiii", body, offset)
        offset += struct.calcsize("<iiii")

        chainlocks = []
        for _ in range(3):
            artifact, offset = cls._read_chainlock_artifact(body, offset)
            chainlocks.append(artifact)

        audit_logical_hash, offset = cls._read_uint256(body, offset)
        audit_witness_hash, offset = cls._read_uint256(body, offset)
        audit_size = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        assert_equal(audit_size, FINAL_PAYMENT_AUDIT_WIRE_SIZE)
        audit_certificate = body[offset:offset + audit_size]
        assert_equal(len(audit_certificate), audit_size)
        offset += audit_size
        receipt = body[offset:offset + PAYMENT_AUDIT_RECEIPT_WIRE_SIZE]
        assert_equal(len(receipt), PAYMENT_AUDIT_RECEIPT_WIRE_SIZE)
        offset += PAYMENT_AUDIT_RECEIPT_WIRE_SIZE
        btcc_receipt_state = body[
            offset:offset + BTCC_RECEIPT_STATE_SIZE]
        assert_equal(len(btcc_receipt_state), BTCC_RECEIPT_STATE_SIZE)
        offset += BTCC_RECEIPT_STATE_SIZE
        receipt_state = body[
            offset:offset + PAYMENT_AUDIT_RECEIPT_STATE_SIZE]
        assert_equal(len(receipt_state), PAYMENT_AUDIT_RECEIPT_STATE_SIZE)
        offset += PAYMENT_AUDIT_RECEIPT_STATE_SIZE
        probation_state_hash, offset = cls._read_uint256(body, offset)
        assert_equal(offset, len(body))

        decoded_receipt = cls._decode_payment_audit_receipt(receipt)
        decoded_btcc_state = cls._decode_btcc_receipt_state(
            btcc_receipt_state)
        decoded_state = cls._decode_payment_audit_receipt_state(
            receipt_state)
        assert_equal(decoded_receipt["audit_logical_hash"],
                     audit_logical_hash)
        assert_equal(decoded_receipt["audit_witness_hash"],
                     audit_witness_hash)
        assert_equal(decoded_receipt["next_probation_state_hash"],
                     probation_state_hash)
        assert_equal(
            sum(bin(byte).count("1") for byte in
                decoded_receipt["online_members"]),
            online_count,
        )
        assert_equal(decoded_state["audit_logical_hash"],
                     audit_logical_hash)
        assert_equal(decoded_state["audit_witness_hash"],
                     audit_witness_hash)
        return {
            "epoch": epoch,
            "selected_row": selected_row,
            "online_count": online_count,
            "conclusive": conclusive,
            "unobserved_member": unobserved_member,
            "unobserved_member_misses": unobserved_member_misses,
            "response_height": response_height,
            "anchor_height": anchor_height,
            "seal_height": seal_height,
            "carrier_height": carrier_height,
            "response": chainlocks[0],
            "anchor": chainlocks[1],
            "seal": chainlocks[2],
            "audit_logical_hash": audit_logical_hash,
            "audit_witness_hash": audit_witness_hash,
            "audit_certificate": audit_certificate,
            "receipt": receipt,
            "btcc_receipt_state": btcc_receipt_state,
            "decoded_btcc_receipt_state": decoded_btcc_state,
            "receipt_state": receipt_state,
            "decoded_receipt": decoded_receipt,
            "decoded_receipt_state": decoded_state,
            "probation_state_hash": probation_state_hash,
        }

    @classmethod
    def read_payment_audit_prefix_bundle(cls, path):
        data = Path(path).read_bytes()
        assert len(data) <= PAYMENT_AUDIT_PREFIX_BUNDLE_MAX_SIZE
        assert len(data) > 32
        body, checksum = data[:-32], data[-32:]
        assert_equal(
            hash256(PAYMENT_AUDIT_PREFIX_BUNDLE_CHECKSUM_DOMAIN + body),
            checksum,
        )
        magic, version = struct.unpack_from("<QH", body, 0)
        assert_equal(magic, PAYMENT_AUDIT_PREFIX_BUNDLE_MAGIC)
        assert_equal(version, PAYMENT_AUDIT_PREFIX_BUNDLE_VERSION)
        offset = struct.calcsize("<QH")
        response, offset = cls._read_chainlock_artifact(body, offset)
        anchor, offset = cls._read_chainlock_artifact(body, offset)
        assert_equal(offset, len(body))
        return {"response": response, "anchor": anchor}

    @classmethod
    def read_post_chainlock_bundle(cls, path):
        data = Path(path).read_bytes()
        assert len(data) > 32
        body, checksum = data[:-32], data[-32:]
        assert_equal(
            hash256(POST_CHAINLOCK_BUNDLE_CHECKSUM_DOMAIN + body),
            checksum,
        )
        magic, version, target_height = struct.unpack_from("<QHi", body, 0)
        assert_equal(magic, POST_CHAINLOCK_BUNDLE_MAGIC)
        assert_equal(version, POST_CHAINLOCK_BUNDLE_VERSION)
        offset = struct.calcsize("<QHi")
        target_hash, offset = cls._read_uint256(body, offset)
        logical_hash, offset = cls._read_uint256(body, offset)
        witness_hash, offset = cls._read_uint256(body, offset)
        certificate_size = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        assert_equal(certificate_size, FINAL_CHAINLOCK_WIRE_SIZE)
        certificate = body[offset:offset + certificate_size]
        assert_equal(len(certificate), certificate_size)
        offset += certificate_size
        receipt_state = body[
            offset:offset + PAYMENT_AUDIT_RECEIPT_STATE_SIZE]
        assert_equal(len(receipt_state), PAYMENT_AUDIT_RECEIPT_STATE_SIZE)
        offset += PAYMENT_AUDIT_RECEIPT_STATE_SIZE
        probation_state_hash, offset = cls._read_uint256(body, offset)
        assert_equal(offset, len(body))
        return {
            "target_height": target_height,
            "target_hash": target_hash,
            "logical_hash": logical_hash,
            "witness_hash": witness_hash,
            "certificate": certificate,
            "receipt_state": receipt_state,
            "decoded_receipt_state":
                cls._decode_payment_audit_receipt_state(receipt_state),
            "probation_state_hash": probation_state_hash,
        }

    def generate_full_dimension_fixture(self, activation_predecessor):
        node = self.nodes[0]
        address = node.get_deterministic_priv_key().address
        # ChainLock targets require exact governance provenance. Rapid mining
        # while mnsync is incomplete intentionally records only budget bounds.
        force_finish_mnsync(node)
        signing_height = FIRST_ELIGIBLE_TARGET_HEIGHT + SIGN_LAG
        blocks_needed = signing_height - node.getblockcount()
        assert blocks_needed >= 0
        if blocks_needed:
            self.generatetoaddress(
                node, blocks_needed, address, sync_fun=self.no_op)

        genesis_hash = node.getblockhash(0)
        target_hash = node.getblockhash(FIRST_ELIGIBLE_TARGET_HEIGHT)
        base_heights = [
            EPOCH_ORIGIN + slot * EPOCH_BLOCKS
            for slot in range(ACTIVE_QUORUMS)
        ]
        snapshot_heights = [
            height - ROSTER_SNAPSHOT_LAG for height in base_heights
        ]
        base_hashes = [node.getblockhash(height) for height in base_heights]
        snapshot_hashes = [
            node.getblockhash(height) for height in snapshot_heights
        ]
        canonical_tip, competing_blocks = self.prepare_competing_work()
        assert_equal(node.getbestblockhash(), canonical_tip)
        # Prevent an equal-work preference from changing across restart before
        # the fixture can publish its exact branch-bound INITIALIZE context.
        node.invalidateblock(competing_blocks[-1].hash)
        assert_equal(node.getbestblockhash(), canonical_tip)

        snapshot_path = os.path.join(
            self.options.tmpdir, "pq-chainlock-snapshots.dat")
        shares_path = os.path.join(
            self.options.tmpdir, "pq-chainlock-shares.dat")
        helper = os.path.join(
            self.config["environment"]["BUILDDIR"], "src", "test",
            "pq_chainlock_fixture" +
            self.config["environment"]["EXEEXT"])
        assert os.path.isfile(helper), "missing pq_chainlock_fixture test helper"

        self.stop_node(0)
        command = [
            helper,
            snapshot_path,
            shares_path,
            genesis_hash,
            str(FIRST_ELIGIBLE_TARGET_HEIGHT),
            target_hash,
            str(activation_predecessor["height"]),
            activation_predecessor["blockHash"],
            self.payment_btcprev(FIRST_ELIGIBLE_TARGET_HEIGHT),
            str(RECOVERY_ANCHOR_BTC_HEIGHT),
            RECOVERY_FUTURE_BTC_HASH,
            str(EPOCH_ORIGIN),
            str(REGISTRATION_CUTOFF_BLOCKS),
            str(ROSTER_SNAPSHOT_LAG),
            str(FUTURE_HORIZON_EPOCHS),
            *base_hashes,
            *snapshot_hashes,
        ]
        subprocess.run(
            command, check=True, capture_output=True, text=True,
            timeout=900 * self.options.timeout_factor)

        corrupt_snapshot_path = os.path.join(
            self.options.tmpdir, "pq-chainlock-snapshots-corrupt.dat")
        corrupt_snapshot = bytearray(Path(snapshot_path).read_bytes())
        corrupt_snapshot[len(corrupt_snapshot) // 2] ^= 1
        Path(corrupt_snapshot_path).write_bytes(corrupt_snapshot)
        with node.assert_debug_log([
                "invalid PQ ChainLock test fixture: PQ ChainLock snapshot "
                "fixture checksum mismatch",
        ]):
            node.assert_start_raises_init_error(
                extra_args=self.extra_args[0] + [
                    "-pqchainlocktestfixture=%s" % corrupt_snapshot_path,
                ],
                expected_msg="Error opening block database",
                match=ErrorMatch.PARTIAL_REGEX,
            )

        fixture_args = self.extra_args[0] + self.btc_backend_args + [
            "-pqchainlocktestfixture=%s" % snapshot_path,
        ]
        self.extra_args[0] = fixture_args
        node.extra_args = list(fixture_args)
        with node.assert_debug_log(
                ["Loaded branch-bound PQ ChainLock regtest fixture"]):
            self.start_node(0, extra_args=fixture_args)
        # preciousblock preference is not durable. Restore the exact branch
        # used by the fixture before publishing any collection capability.
        node.preciousblock(canonical_tip)
        self.wait_until(
            lambda: node.getbestblockhash() == canonical_tip,
            timeout=30,
        )
        assert_equal(node.getblockhash(FIRST_ELIGIBLE_TARGET_HEIGHT),
                     target_hash)
        assert_equal(node.getbestblockhash(), canonical_tip)
        with node.assert_debug_log([
                "published PQ ChainLock signing context height=%d" %
                FIRST_ELIGIBLE_TARGET_HEIGHT,
        ], timeout=180):
            node.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
            force_finish_mnsync(node)
        self.assert_no_chainlock_rpcs(node)
        return (
            target_hash,
            fixture_args,
            self.read_full_dimension_bundle(shares_path),
            canonical_tip,
            competing_blocks,
        )

    @staticmethod
    def payment_btcprev(height):
        return "%064x" % (0xb7000000 + height)

    @staticmethod
    def is_btcc_candidate(height):
        return (
            height >= BTCC_CANDIDATE_ORIGIN
            and (height - BTCC_CANDIDATE_ORIGIN)
            % BTCC_CANDIDATE_PERIOD == 0
        )

    def mine_one_pq_block(self):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        address = node.get_deterministic_priv_key().address
        if not self.is_btcc_candidate(height):
            return self.generatetoaddress(
                node, 1, address, sync_fun=self.no_op)[0]

        btcprev = self.payment_btcprev(height)
        template = node.createauxblock(address, btcprev)
        assert_equal(template["height"], height)
        assert_equal(template["_btcprevhash"], btcprev)
        auxpow = computeAuxpow(
            template["hash"], reverseHex(template["_target"]), True,
            template["coinbasescript"], btcprev,
        )
        assert node.submitauxblock(template["hash"], auxpow)
        return template["hash"]

    def mine_pq_to_height(self, target_height):
        node = self.nodes[0]
        assert target_height >= node.getblockcount()
        while node.getblockcount() < target_height:
            self.mine_one_pq_block()
        assert_equal(node.getblockcount(), target_height)

    @staticmethod
    def coinbase_commitment_data(block):
        for output in block.vtx[0].vout:
            operations = list(CScript(output.scriptPubKey).raw_iter())
            if not operations or operations[0][0] != OP_RETURN:
                continue
            pushes = [data for _, data, _ in operations[1:]]
            if pushes and all(data is not None for data in pushes):
                return output, pushes
        raise AssertionError("coinbase commitment output not found")

    def read_btcc_receipt(self, block_hash):
        raw = bytes.fromhex(self.nodes[0].getblock(block_hash, 0))
        stream = BytesIO(raw)
        block = CBlock()
        block.deserialize(stream)
        _, pushes = self.coinbase_commitment_data(block)
        extra = pushes[-1]
        btcc_offset = extra.rfind(b"btcr")
        btcprev_offset = extra.rfind(b"btcp")
        assert btcc_offset >= 0
        assert_equal(
            btcc_offset + 4 + BTCC_RECEIPT_WIRE_SIZE,
            btcprev_offset,
        )
        receipt = extra[
            btcc_offset + 4:btcc_offset + 4 + BTCC_RECEIPT_WIRE_SIZE]
        assert_equal(len(receipt), BTCC_RECEIPT_WIRE_SIZE)
        return receipt, self._decode_btcc_receipt(receipt)

    def attach_auxpow(self, block, previous_height, btcprev_hash=None):
        node = self.nodes[0]
        block.mark_auxpow()
        block.auxpow = None
        block.rehash()
        target = ("%064x" % uint256_from_compact(block.nBits)).encode()
        auxpow_height = previous_height - 5
        auxpow_height -= auxpow_height % 10
        auxpow_tag_hash = node.getblockhash(auxpow_height)
        auxpow_script = CScript([
            OP_RETURN,
            b"sys" + bytes.fromhex(auxpow_tag_hash)[::-1]
            + struct.pack("<I", auxpow_height),
        ])
        if btcprev_hash is None:
            encoded = computeAuxpow(
                block.hash, target, True, auxpow_script.hex())
        else:
            encoded = computeAuxpow(
                block.hash, target, True, auxpow_script.hex(),
                btcprev_hash)
        block.auxpow = CAuxPow()
        block.auxpow.deserialize(BytesIO(bytes.fromhex(encoded)))

    def prepare_competing_work(
            self, fork_base_height=FIRST_ELIGIBLE_TARGET_HEIGHT - 1):
        """Admit and fully validate a fork before it is quarantined."""
        node = self.nodes[0]
        canonical_tip = node.getbestblockhash()
        canonical_height = node.getblockcount()
        previous_hash = int(node.getblockhash(fork_base_height), 16)
        competing_blocks = []

        for height in range(fork_base_height + 1,
                            canonical_height + 1):
            stream = BytesIO(bytes.fromhex(
                node.getblock(node.getblockhash(height), 0)))
            block = CBlock()
            block.deserialize(stream)
            sidecar = stream.read()
            block.hashPrevBlock = previous_hash
            block.nNonce = (block.nNonce + height + 1) & 0xffffffff
            btcprev = self.payment_btcprev(height) \
                if self.is_btcc_candidate(height) else None
            self.attach_auxpow(block, height - 1, btcprev)
            assert block.hash != node.getblockhash(height)
            result = node.submitblock((block.serialize() + sidecar).hex())
            assert result in (None, "inconclusive"), result
            previous_hash = block.sha256
            competing_blocks.append(block)

        competing_tip = competing_blocks[-1].hash
        # Activate both branches before finality so a later rejection cannot
        # be attributed to ordinary deferred validation.
        node.preciousblock(competing_tip)
        assert_equal(node.getbestblockhash(), competing_tip)
        node.preciousblock(canonical_tip)
        assert_equal(node.getbestblockhash(), canonical_tip)
        side_tip = next(
            tip for tip in node.getchaintips()
            if tip["hash"] == competing_tip
        )
        assert_equal(side_tip["status"], "valid-fork")
        return canonical_tip, competing_blocks

    def assert_competing_work_rejected(self, canonical_tip,
                                       competing_blocks):
        """Try to activate and extend a proven-valid fork after finality."""
        node = self.nodes[0]
        competing_tip = competing_blocks[-1].hash
        competing_height = node.getblockheader(competing_tip)["height"]

        # Restore the pre-finality-proven branch, then force its activation.
        # EnforceBestChainLock may already have marked the branch conflicting
        # when the certificate was accepted, in which case preciousblock is a
        # no-op and there is no second bad-chainlock validation log.
        node.reconsiderblock(competing_tip)
        side_tip = next(
            tip for tip in node.getchaintips()
            if tip["hash"] == competing_tip
        )
        assert_equal(side_tip["status"], "conflicting")
        node.preciousblock(competing_tip)
        assert_equal(node.getbestblockhash(), canonical_tip)
        side_tip = next(
            tip for tip in node.getchaintips()
            if tip["hash"] == competing_tip
        )
        assert_equal(side_tip["status"], "conflicting")

        # Build the next otherwise-valid AuxPoW block on the quarantined tip.
        # The reorg attempt above has already marked the fork's locked target
        # conflicting, so its greater-work child must hit the ChainLock parent
        # rejection path.
        extension = deepcopy(competing_blocks[-1])
        extension.hashPrevBlock = competing_blocks[-1].sha256
        extension.nTime += 1
        extension.nNonce = (extension.nNonce + 1) & 0xffffffff
        extension.vtx[0].vin[0].scriptSig = \
            script_BIP34_coinbase_height(competing_height + 1)
        extension.vtx[0].sha256 = None
        extension.vtx[0].hash = None
        extension.vtx[0].rehash()
        extension.hashMerkleRoot = extension.calc_merkle_root()
        self.attach_auxpow(extension, competing_height)
        assert_equal(
            node.submitblock(extension.serialize().hex()),
            "bad-prevblk-chainlock",
        )
        assert_equal(node.getbestblockhash(), canonical_tip)
        side_tip = next(
            tip for tip in node.getchaintips()
            if tip["hash"] == competing_tip
        )
        assert_equal(side_tip["status"], "conflicting")

    def test_full_dimension_collection(self, activation_predecessor):
        node = self.nodes[0]
        (target_hash, fixture_args, bundle,
         canonical_tip, competing_blocks) = \
            self.generate_full_dimension_fixture(activation_predecessor)
        dmn_state_before = node.protx_migration_info()["dmnStateHash"]

        sender_marker = "pq-full-sender"
        sender = self.authenticate_peer(
            self.connect_peer(sender_marker), sender_marker,
            bundle["sender_identity"])
        observer_marker = "pq-full-observer"
        observer = self.authenticate_peer(
            self.connect_peer(observer_marker), observer_marker,
            bundle["observer_identity"])

        observer_share_count = observer.message_count["pqclshare"]
        sender.send_and_ping(
            msg_pqclshare(bundle["shares"][0]), timeout=180)
        observer.sync_with_ping(timeout=180)
        # This fixture is an authenticated collector without a local roster
        # identity. Collection remains enabled, but only selected sentries may
        # install the overlay and relay shares.
        assert_equal(
            observer.message_count["pqclshare"], observer_share_count)

        # A member slot is the vote identity. Later bytes cannot add weight
        # after the slot is verified, so discard them without blaming the
        # authenticated transport relay.
        sender_relay_count = sender.message_count["pqclshare"]
        alternate_witness = (
            bundle["shares"][0][:-1]
            + bytes([bundle["shares"][0][-1] ^ 1])
        )
        observer.send_and_ping(
            msg_pqclshare(alternate_witness), timeout=180)
        assert observer.is_connected
        assert_equal(sender.message_count["pqclshare"], sender_relay_count)

        # Canonical fixture order is 267 + 267 + 267. Exactly 800 leaves the
        # third selected quorum one share short and must not publish a winner.
        for start in range(1, FINAL_SIGNATURE_COUNT - 1, 100):
            end = min(start + 100, FINAL_SIGNATURE_COUNT - 1)
            for share in bundle["shares"][start:end]:
                sender.send_message(msg_pqclshare(share))
            sender.sync_with_ping(timeout=240)
        assert sender.is_connected
        assert observer.is_connected
        assert_equal(
            node.protx_migration_info()["dmnStateHash"], dmn_state_before)
        self.assert_no_chainlock_rpcs(node)

        with node.assert_debug_log(
                ["accepted PQ ChainLock"], timeout=1200):
            sender.send_message(msg_pqclshare(bundle["shares"][-1]))
        # Finality changes the active identity view and deliberately retires
        # stale authenticated test peers. Exact post-restart retrieval below
        # proves certificate serving without depending on that connection.

        expected_logical = "%064x" % bundle["logical_hash"]
        expected_witness = "%064x" % bundle["witness_hash"]
        best = node.getbestchainlock()
        assert_equal(best["height"], FIRST_ELIGIBLE_TARGET_HEIGHT)
        assert_equal(best["blockhash"], target_hash)
        assert_equal(best["logicalid"], expected_logical)
        assert_equal(best["witnessid"], expected_witness)
        assert_equal(best["selected_quorum_mask"], 0b0111)
        assert_equal(best["signature_count"], FINAL_SIGNATURE_COUNT)
        assert best["known_block"]
        assert_equal(
            node.protx_migration_info()["dmnStateHash"], dmn_state_before)

        compatible = node.getchainlocks()
        assert_equal(compatible["recent_chainlock"]["logicalid"],
                     expected_logical)
        assert_equal(compatible["active_chainlock"]["witnessid"],
                     expected_witness)
        target_coinbase = node.getblock(target_hash, 2)["tx"][0]["txid"]
        assert_equal(
            node.gettxchainlocks([target_coinbase]),
            [{"height": FIRST_ELIGIBLE_TARGET_HEIGHT,
              "chainlock": True, "mempool": False}],
        )
        self.assert_competing_work_rejected(
            canonical_tip, competing_blocks)

        # Certificate verification/restoration is portable consensus and must
        # not inherit the collector's local Bitcoin-header policy dependency.
        rpc_free_args = [
            arg for arg in fixture_args
            if not arg.startswith("-btcheader")
        ]
        self.extra_args[0] = rpc_free_args
        node.extra_args = list(rpc_free_args)
        self.restart_node(0, extra_args=rpc_free_args)
        restored = node.getbestchainlock()
        assert_equal(restored["logicalid"], expected_logical)
        assert_equal(restored["witnessid"], expected_witness)
        assert_equal(
            node.gettxchainlocks([target_coinbase]),
            [{"height": FIRST_ELIGIBLE_TARGET_HEIGHT,
              "chainlock": True, "mempool": False}],
        )

        retrieval = self.connect_peer("pq-full-restart-retrieval")
        retrieval.send_and_ping(msg_getclsig(), timeout=60)
        retrieval.wait_until(
            lambda: retrieval.message_count["clsig"] >= 1,
            timeout=600)
        assert_equal(
            retrieval.last_message["clsig"].payload,
            bundle["certificate"])
        return bundle["certificate"]

    def generate_payment_audit_fixture(self, authorizer):
        node = self.nodes[0]
        assert node.getblockcount() >= FIRST_ELIGIBLE_TARGET_HEIGHT + 6
        # The preceding persistence check restarts the daemon. Finish MN sync
        # before mining so every superblock in the attested range receives
        # exact governance provenance, not only script validity.
        force_finish_mnsync(node)
        genesis_hash = node.getblockhash(0)
        branch_anchor_hash = node.getblockhash(
            FIRST_ELIGIBLE_TARGET_HEIGHT)
        helper = os.path.join(
            self.config["environment"]["BUILDDIR"], "src", "test",
            "pq_chainlock_fixture" + self.config["environment"]["EXEEXT"],
        )
        assert os.path.isfile(helper), "missing pq_chainlock_fixture test helper"
        original_authorizer_path = os.path.join(
            self.options.tmpdir, "pq-payment-audit-catchup-authorizer.dat")
        transition_authorizer_path = os.path.join(
            self.options.tmpdir, "pq-payment-audit-authorizer.dat")
        Path(original_authorizer_path).write_bytes(authorizer)

        def build_and_admit_prefix(
                label, audit_epoch, response_height, anchor_height,
                authorizer_path, authorizer_carrier_height):
            response_predecessor_height = response_height - CHAINLOCK_PERIOD
            response_expiry_height = \
                response_height + SIGN_LAG + CHAINLOCK_PERIOD
            anchor_predecessor_height = anchor_height - CHAINLOCK_PERIOD
            self.mine_pq_to_height(anchor_height + SIGN_LAG)
            response_predecessor_hash = node.getblockhash(
                response_predecessor_height)
            response_hash = node.getblockhash(response_height)
            anchor_predecessor_hash = node.getblockhash(
                anchor_predecessor_height)
            anchor_hash = node.getblockhash(anchor_height)
            authorizer_carrier_hash = (
                node.getblockhash(authorizer_carrier_height)
                if authorizer_carrier_height is not None
                else "%064x" % 0
            )
            base_heights = [
                EPOCH_ORIGIN + epoch * EPOCH_BLOCKS
                for epoch in range(audit_epoch + 1)
            ]
            snapshot_heights = [
                height - ROSTER_SNAPSHOT_LAG for height in base_heights
            ]
            base_hashes = [
                node.getblockhash(height) for height in base_heights
            ]
            snapshot_hashes = [
                node.getblockhash(height) for height in snapshot_heights
            ]
            snapshot_path = os.path.join(
                self.options.tmpdir,
                "pq-payment-audit-%s-prefix-snapshots.dat" % label,
            )
            bundle_path = os.path.join(
                self.options.tmpdir,
                "pq-payment-audit-%s-prefix-bundle.dat" % label,
            )
            self.stop_node(0)
            subprocess.run([
                helper,
                "payment-audit-prefix",
                snapshot_path,
                bundle_path,
                genesis_hash,
                str(FIRST_ELIGIBLE_TARGET_HEIGHT),
                branch_anchor_hash,
                str(EPOCH_ORIGIN),
                str(REGISTRATION_CUTOFF_BLOCKS),
                str(ROSTER_SNAPSHOT_LAG),
                str(FUTURE_HORIZON_EPOCHS),
                str(BTCC_CANDIDATE_ORIGIN),
                str(audit_epoch),
                str(response_predecessor_height),
                response_predecessor_hash,
                response_hash,
                self.payment_btcprev(response_height),
                str(anchor_predecessor_height),
                anchor_predecessor_hash,
                anchor_hash,
                self.payment_btcprev(anchor_height),
                authorizer_carrier_hash,
                *base_hashes,
                *snapshot_hashes,
                authorizer_path,
            ], check=True, capture_output=True, text=True,
                timeout=3600 * self.options.timeout_factor)
            prefix = self.read_payment_audit_prefix_bundle(bundle_path)
            fixture_args = [
                arg for arg in self.extra_args[0]
                if not arg.startswith("-pqchainlocktestfixture=")
            ] + ["-pqchainlocktestfixture=%s" % snapshot_path]
            self.extra_args[0] = fixture_args
            node.extra_args = list(fixture_args)
            with node.assert_debug_log(
                    ["Loaded branch-bound PQ ChainLock regtest fixture"]):
                self.start_node(0, extra_args=fixture_args)
            assert_equal(node.getblockcount(), anchor_height + SIGN_LAG)
            node.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
            force_finish_mnsync(node)
            prefix_tip = node.getbestblockhash()
            response_expiry_hash = node.getblockhash(response_expiry_height)
            # Each response was absent when its fixed carrier was mined. The
            # rewind publishes it within the live window without rewriting
            # that already-validated null carrier.
            node.invalidateblock(response_expiry_hash)
            assert_equal(node.getblockcount(), response_expiry_height - 1)
            self.admit_chainlock_artifact(
                prefix["response"], response_height, response_hash,
                "pq-audit-%s-response" % label)
            node.reconsiderblock(response_expiry_hash)
            self.wait_until(
                lambda: node.getbestblockhash() == prefix_tip,
                timeout=1200,
            )
            assert_equal(node.getblockcount(), anchor_height + SIGN_LAG)
            _, response_carrier = self.read_btcc_receipt(
                response_expiry_hash)
            assert_equal(response_carrier["version"], 1)
            assert_equal(response_carrier["target_height"], -1)
            assert_equal(response_carrier["target_hash"], 0)
            assert_equal(response_carrier["logical_hash"], 0)
            assert_equal(response_carrier["cursor_height"], -1)
            assert_equal(response_carrier["cursor_sys_hash"], 0)
            assert_equal(response_carrier["cursor_btc_hash"], 0)
            self.admit_chainlock_artifact(
                prefix["anchor"], anchor_height, anchor_hash,
                "pq-audit-%s-anchor" % label)
            return {
                "prefix": prefix,
                "fixture_args": fixture_args,
                "response_predecessor_hash": response_predecessor_hash,
                "response_hash": response_hash,
                "anchor_predecessor_hash": anchor_predecessor_hash,
                "anchor_hash": anchor_hash,
            }

        prep = build_and_admit_prefix(
            "prep", PAYMENT_AUDIT_PREP_EPOCH,
            PAYMENT_AUDIT_PREP_RESPONSE_HEIGHT,
            PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT,
            original_authorizer_path,
            None,
        )
        Path(transition_authorizer_path).write_bytes(
            prep["prefix"]["anchor"]["certificate"])
        self.mine_pq_to_height(PAYMENT_AUDIT_PREP_CARRIER_HEIGHT)
        transition_carrier_hash = node.getblockhash(
            PAYMENT_AUDIT_PREP_CARRIER_HEIGHT)
        _, transition_receipt = self.read_btcc_receipt(
            transition_carrier_hash)
        assert_equal(
            transition_receipt["target_height"],
            PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT,
        )
        assert_equal(
            transition_receipt["target_hash"],
            int(prep["anchor_hash"], 16),
        )
        assert_equal(
            transition_receipt["logical_hash"],
            prep["prefix"]["anchor"]["logical_hash"],
        )
        assert_equal(
            transition_receipt["cursor_height"],
            PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT,
        )
        assert_equal(
            transition_receipt["cursor_sys_hash"],
            int(prep["anchor_hash"], 16),
        )
        assert_equal(
            transition_receipt["cursor_btc_hash"],
            int(self.payment_btcprev(
                PAYMENT_AUDIT_PREP_ANCHOR_HEIGHT), 16),
        )

        current = build_and_admit_prefix(
            "current", PAYMENT_AUDIT_EPOCH,
            PAYMENT_AUDIT_RESPONSE_HEIGHT,
            PAYMENT_AUDIT_ANCHOR_HEIGHT,
            transition_authorizer_path,
            PAYMENT_AUDIT_PREP_CARRIER_HEIGHT,
        )
        prefix = current["prefix"]
        prefix_fixture_args = current["fixture_args"]
        response_predecessor_hash = current["response_predecessor_hash"]
        response_hash = current["response_hash"]
        anchor_predecessor_hash = current["anchor_predecessor_hash"]
        anchor_hash = current["anchor_hash"]

        self.mine_pq_to_height(PAYMENT_AUDIT_SEED_CARRIER_HEIGHT)
        seed_carrier_hash = node.getblockhash(
            PAYMENT_AUDIT_SEED_CARRIER_HEIGHT)
        seed_receipt, decoded_seed_receipt = self.read_btcc_receipt(
            seed_carrier_hash)
        assert_equal(decoded_seed_receipt["version"], 1)
        assert_equal(
            decoded_seed_receipt["target_height"],
            PAYMENT_AUDIT_ANCHOR_HEIGHT,
        )
        assert_equal(
            decoded_seed_receipt["target_hash"], int(anchor_hash, 16))
        assert_equal(
            decoded_seed_receipt["logical_hash"],
            prefix["anchor"]["logical_hash"],
        )
        assert_equal(
            decoded_seed_receipt["cursor_height"],
            PAYMENT_AUDIT_ANCHOR_HEIGHT,
        )
        assert_equal(
            decoded_seed_receipt["cursor_sys_hash"], int(anchor_hash, 16))
        assert_equal(
            decoded_seed_receipt["cursor_btc_hash"],
            int(self.payment_btcprev(PAYMENT_AUDIT_ANCHOR_HEIGHT), 16),
        )

        self.mine_pq_to_height(PAYMENT_AUDIT_SEAL_HEIGHT + SIGN_LAG)
        seal_predecessor_hash = node.getblockhash(
            PAYMENT_AUDIT_SEAL_PREDECESSOR_HEIGHT)
        seal_hash = node.getblockhash(PAYMENT_AUDIT_SEAL_HEIGHT)
        base_heights = [
            EPOCH_ORIGIN + epoch * EPOCH_BLOCKS
            for epoch in range(PAYMENT_AUDIT_EPOCH + 2)
        ]
        snapshot_heights = [
            height - ROSTER_SNAPSHOT_LAG for height in base_heights
        ]
        base_hashes = [node.getblockhash(height) for height in base_heights]
        snapshot_hashes = [
            node.getblockhash(height) for height in snapshot_heights
        ]
        snapshot_path = os.path.join(
            self.options.tmpdir, "pq-payment-audit-snapshots.dat")
        bundle_path = os.path.join(
            self.options.tmpdir, "pq-payment-audit-bundle.dat")

        self.stop_node(0)
        command = [
            helper,
            "payment-audit",
            snapshot_path,
            bundle_path,
            genesis_hash,
            str(FIRST_ELIGIBLE_TARGET_HEIGHT),
            branch_anchor_hash,
            str(EPOCH_ORIGIN),
            str(REGISTRATION_CUTOFF_BLOCKS),
            str(ROSTER_SNAPSHOT_LAG),
            str(FUTURE_HORIZON_EPOCHS),
            str(BTCC_CANDIDATE_ORIGIN),
            str(PAYMENT_AUDIT_EPOCH),
            str(PAYMENT_AUDIT_RESPONSE_PREDECESSOR_HEIGHT),
            response_predecessor_hash,
            response_hash,
            self.payment_btcprev(PAYMENT_AUDIT_RESPONSE_HEIGHT),
            str(PAYMENT_AUDIT_ANCHOR_PREDECESSOR_HEIGHT),
            anchor_predecessor_hash,
            anchor_hash,
            self.payment_btcprev(PAYMENT_AUDIT_ANCHOR_HEIGHT),
            str(PAYMENT_AUDIT_SEAL_PREDECESSOR_HEIGHT),
            seal_predecessor_hash,
            seal_hash,
            seed_carrier_hash,
            seed_receipt.hex(),
            transition_carrier_hash,
            *base_hashes,
            *snapshot_hashes,
            transition_authorizer_path,
        ]
        subprocess.run(
            command, check=True, capture_output=True, text=True,
            timeout=7200 * self.options.timeout_factor,
        )
        bundle = self.read_payment_audit_bundle(bundle_path)
        seal_authorizer_path = os.path.join(
            self.options.tmpdir, "pq-payment-audit-seal-authorizer.dat")
        Path(seal_authorizer_path).write_bytes(
            bundle["seal"]["certificate"])
        assert_equal(
            bundle["response"]["logical_hash"],
            prefix["response"]["logical_hash"],
        )
        assert_equal(
            bundle["anchor"]["logical_hash"],
            prefix["anchor"]["logical_hash"],
        )
        assert_equal(bundle["epoch"], PAYMENT_AUDIT_EPOCH)
        assert_equal(bundle["selected_row"], 23)
        assert_equal(bundle["online_count"], QUORUM_MIN_VALID - 1)
        assert_equal(bundle["conclusive"], 0)
        assert_equal(bundle["unobserved_member_misses"], 0)
        assert_equal(bundle["response_height"],
                     PAYMENT_AUDIT_RESPONSE_HEIGHT)
        assert_equal(bundle["anchor_height"], PAYMENT_AUDIT_ANCHOR_HEIGHT)
        assert_equal(bundle["seal_height"], PAYMENT_AUDIT_SEAL_HEIGHT)
        assert_equal(bundle["carrier_height"], PAYMENT_AUDIT_CARRIER_HEIGHT)
        assert_equal(
            bundle["decoded_receipt"]["version"],
            PAYMENT_AUDIT_RECEIPT_VERSION,
        )
        assert_equal(bundle["decoded_receipt"]["has_audit"], 1)
        assert_equal(bundle["decoded_receipt"]["carrier_height"],
                     PAYMENT_AUDIT_CARRIER_HEIGHT)
        indexed_btcc = bundle["decoded_btcc_receipt_state"]
        assert_equal(
            indexed_btcc["cursor_height"], PAYMENT_AUDIT_ANCHOR_HEIGHT)
        assert_equal(indexed_btcc["cursor_sys_hash"], int(anchor_hash, 16))
        assert_equal(
            indexed_btcc["cursor_btc_hash"],
            int(self.payment_btcprev(PAYMENT_AUDIT_ANCHOR_HEIGHT), 16),
        )
        assert indexed_btcc["cumulative_hash"] != 0

        fixture_args = [
            arg for arg in prefix_fixture_args
            if not arg.startswith("-pqchainlocktestfixture=")
        ] + ["-pqchainlocktestfixture=%s" % snapshot_path]
        self.extra_args[0] = fixture_args
        node.extra_args = list(fixture_args)
        with node.assert_debug_log(
                ["Loaded branch-bound PQ ChainLock regtest fixture"]):
            self.start_node(0, extra_args=fixture_args)
        assert_equal(node.getblockcount(), PAYMENT_AUDIT_SEAL_HEIGHT + SIGN_LAG)
        node.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        force_finish_mnsync(node)
        # Match the full-dimension fixture path: the spork update becomes
        # operational on the next tip notification without crossing another
        # scheduled BTCC candidate or audit carrier.
        self.mine_one_pq_block()
        assert_equal(node.getblockcount(), PAYMENT_AUDIT_SEAL_HEIGHT + 6)
        return {
            "helper": helper,
            "fixture_args": fixture_args,
            "bundle": bundle,
            "genesis_hash": genesis_hash,
            "response_hash": response_hash,
            "anchor_hash": anchor_hash,
            "seal_hash": seal_hash,
            "seed_carrier_hash": seed_carrier_hash,
            "seed_receipt": seed_receipt,
            "base_hashes": base_hashes,
            "snapshot_hashes": snapshot_hashes,
            "seal_authorizer_path": seal_authorizer_path,
        }

    def admit_chainlock_artifact(self, artifact, height, block_hash, marker):
        node = self.nodes[0]
        peer = self.authenticate_peer(
            self.connect_peer(marker), marker, 0xc100 + height)
        self.request_chainlock(peer, artifact["logical_hash"])
        with node.assert_debug_log(
                ["accepted PQ ChainLock"], timeout=1200):
            # Accepting a winner can immediately invalidate the sender's
            # authenticated PQ identity, so acceptance cannot depend on a
            # subsequent pong from that connection.
            peer.send_message(msg_clsig(artifact["certificate"]))
        expected_logical = "%064x" % artifact["logical_hash"]
        expected_witness = "%064x" % artifact["witness_hash"]
        self.wait_until(
            lambda: node.getbestchainlock()["logicalid"] ==
                    expected_logical,
            timeout=1200,
        )
        best = node.getbestchainlock()
        assert_equal(best["height"], height)
        assert_equal(best["blockhash"], block_hash)
        assert_equal(best["logicalid"], expected_logical)
        assert_equal(best["witnessid"], expected_witness)

    def admit_payment_audit_chainlocks(self, context):
        bundle = context["bundle"]
        best = self.nodes[0].getbestchainlock()
        assert_equal(best["height"], PAYMENT_AUDIT_ANCHOR_HEIGHT)
        assert_equal(
            best["logicalid"], "%064x" % bundle["anchor"]["logical_hash"])
        for artifact, height, block_hash, marker in [
            (bundle["seal"], PAYMENT_AUDIT_SEAL_HEIGHT,
             context["seal_hash"], "pq-audit-seal"),
        ]:
            self.admit_chainlock_artifact(
                artifact, height, block_hash, marker)

    def build_pending_payment_audit_carrier(self, bundle):
        node = self.nodes[0]
        self.mine_pq_to_height(PAYMENT_AUDIT_CARRIER_HEIGHT - 1)
        provider_marker = "pq-audit-required-provider"

        canonical_hash = self.mine_one_pq_block()
        assert_equal(node.getblockcount(), PAYMENT_AUDIT_CARRIER_HEIGHT)
        canonical_raw = bytes.fromhex(node.getblock(canonical_hash, 0))
        stream = BytesIO(canonical_raw)
        carrier = CBlock()
        carrier.deserialize(stream)
        sidecar = stream.read()
        commitment_output, pushes = self.coinbase_commitment_data(carrier)
        extra = pushes[-1]
        audit_offset = extra.rfind(b"pqar")
        btcc_offset = extra.rfind(b"btcr")
        btcprev_offset = extra.rfind(b"btcp")
        assert audit_offset >= 0
        assert_equal(
            audit_offset + 4 + PAYMENT_AUDIT_RECEIPT_WIRE_SIZE,
            btcc_offset,
        )
        assert_equal(
            btcc_offset + 4 + BTCC_RECEIPT_WIRE_SIZE,
            btcprev_offset,
        )
        null_receipt = extra[
            audit_offset + 4:
            audit_offset + 4 + PAYMENT_AUDIT_RECEIPT_WIRE_SIZE
        ]
        decoded_null = self._decode_payment_audit_receipt(null_receipt)
        assert_equal(
            decoded_null["version"], PAYMENT_AUDIT_RECEIPT_VERSION)
        assert_equal(decoded_null["has_audit"], 0)
        assert_equal(decoded_null["online_members"], bytes(BITMAP_SIZE))
        assert_equal(
            extra[btcprev_offset + 4:],
            ser_uint256(int(self.payment_btcprev(
                PAYMENT_AUDIT_CARRIER_HEIGHT), 16)),
        )

        modified_extra = (
            extra[:audit_offset + 4]
            + bundle["receipt"]
            + extra[audit_offset + 4 + PAYMENT_AUDIT_RECEIPT_WIRE_SIZE:]
        )
        commitment_output.scriptPubKey = CScript(
            [OP_RETURN, *pushes[:-1], modified_extra])
        carrier.vtx[0].rehash()
        carrier.hashMerkleRoot = carrier.calc_merkle_root()
        carrier.nNonce = (carrier.nNonce + 1) & 0xffffffff
        self.attach_auxpow(
            carrier,
            PAYMENT_AUDIT_CARRIER_HEIGHT - 1,
            self.payment_btcprev(PAYMENT_AUDIT_CARRIER_HEIGHT),
        )
        assert carrier.hash != canonical_hash

        node.invalidateblock(canonical_hash)
        parent_hash = "%064x" % carrier.hashPrevBlock
        assert_equal(node.getbestblockhash(), parent_hash)
        # Test-only MNAUTH identities are deliberately absent from the live
        # DML and are disconnected on a tip change. Connect the provider only
        # after returning to the stable parent; the pending carrier cannot
        # advance that tip until this exact witness arrives.
        provider = self.authenticate_peer(
            self.connect_peer(provider_marker), provider_marker, 0xc200)
        with node.assert_debug_log([
                "pq-payment-audit-certificate-pending"]):
            assert_raises_rpc_error(
                -25,
                "pq-payment-audit-certificate-pending",
                node.submitblock,
                (carrier.serialize() + sidecar).hex(),
            )
        assert_equal(node.getbestblockhash(), parent_hash)

        provider.wait_until(
            lambda: (
                "getpqpose" in provider.last_message
                and provider.last_message["getpqpose"].witness_id ==
                    bundle["audit_witness_hash"]
            ),
            timeout=60,
        )
        provider.last_message.pop("getdata", None)
        provider.send_message(msg_inv([
            CInv(MSG_PQPOSECERT, bundle["audit_witness_hash"]),
        ]))
        provider.wait_for_getdata(
            [bundle["audit_witness_hash"]], timeout=60)
        assert_equal(
            provider.last_message["getdata"].inv[0].type,
            MSG_PQPOSECERT,
        )
        provider.send_and_ping(
            msg_pqposecert(bundle["audit_certificate"]), timeout=1200)
        self.wait_until(
            lambda: node.getbestblockhash() == carrier.hash,
            timeout=1200,
        )
        assert_equal(node.getblockcount(), PAYMENT_AUDIT_CARRIER_HEIGHT)
        return carrier.hash, canonical_hash

    def generate_payment_state_chainlock(
            self, context, mode, output_name, target_height, target_hash,
            predecessor_height, predecessor_hash):
        bundle = context["bundle"]
        post_path = os.path.join(
            self.options.tmpdir, output_name)
        command = [
            context["helper"],
            mode,
            post_path,
            context["genesis_hash"],
            str(target_height),
            target_hash,
            str(predecessor_height),
            predecessor_hash,
            str(PAYMENT_AUDIT_ANCHOR_HEIGHT),
            context["anchor_hash"],
            self.payment_btcprev(PAYMENT_AUDIT_ANCHOR_HEIGHT),
            str(EPOCH_ORIGIN),
            str(REGISTRATION_CUTOFF_BLOCKS),
            str(ROSTER_SNAPSHOT_LAG),
            str(FUTURE_HORIZON_EPOCHS),
            str(BTCC_CANDIDATE_ORIGIN),
            bundle["btcc_receipt_state"].hex(),
            bundle["receipt_state"].hex(),
            "%064x" % bundle["probation_state_hash"],
            *context["base_hashes"],
            *context["snapshot_hashes"],
            context["seal_authorizer_path"],
        ]
        subprocess.run(
            command, check=True, capture_output=True, text=True,
            timeout=3600 * self.options.timeout_factor,
        )
        post = self.read_post_chainlock_bundle(post_path)
        assert_equal(post["target_height"], target_height)
        assert_equal(post["target_hash"], int(target_hash, 16))
        assert_equal(post["receipt_state"], bundle["receipt_state"])
        assert_equal(post["probation_state_hash"],
                     bundle["probation_state_hash"])
        return post

    def generate_post_audit_chainlock(self, context):
        node = self.nodes[0]
        self.mine_pq_to_height(PAYMENT_AUDIT_POST_SIGNING_HEIGHT)
        predecessor_hash = node.getblockhash(
            PAYMENT_AUDIT_POST_PREDECESSOR_HEIGHT)
        target_hash = node.getblockhash(PAYMENT_AUDIT_POST_TARGET_HEIGHT)
        post = self.generate_payment_state_chainlock(
            context,
            "payment-audit-post",
            "pq-payment-audit-post-chainlock.dat",
            PAYMENT_AUDIT_POST_TARGET_HEIGHT,
            target_hash,
            PAYMENT_AUDIT_POST_PREDECESSOR_HEIGHT,
            predecessor_hash,
        )
        # The post-audit winner synchronously authorizes the compact archive
        # checkpoint. Wait for that durability boundary before testing that
        # the exact multi-megabyte witness has been retired.
        with node.assert_debug_log([
                "authenticated payment-audit archive through epoch"],
                timeout=1200):
            self.admit_chainlock_artifact(
                post,
                PAYMENT_AUDIT_POST_TARGET_HEIGHT,
                target_hash,
                "pq-audit-post",
            )
        return post

    def assert_payment_audit_state(self, context, post, expected_tip):
        node = self.nodes[0]
        bundle = context["bundle"]
        expected_state = bundle["decoded_receipt_state"]
        expected_logical = "%064x" % post["logical_hash"]
        expected_witness = "%064x" % post["witness_hash"]

        def has_expected_chainlock():
            try:
                return node.getbestchainlock()["logicalid"] == \
                    expected_logical
            except JSONRPCException as exception:
                if (exception.error["code"] == -32603 and
                        "Unable to find any ChainLock" in
                        exception.error["message"]):
                    return False
                raise

        self.wait_until(
            has_expected_chainlock,
            timeout=1200,
        )
        assert_equal(node.getbestblockhash(), expected_tip)
        assert_equal(node.getblockcount(),
                     PAYMENT_AUDIT_POST_SIGNING_HEIGHT)
        active = node.getchainlocks()["active_chainlock"]
        assert_equal(active["height"], PAYMENT_AUDIT_POST_TARGET_HEIGHT)
        assert_equal(active["logicalid"], expected_logical)
        assert_equal(active["witnessid"], expected_witness)
        receipt_state = active["payment_audit_receipt_state"]
        assert_equal(receipt_state["carrier_height"],
                     PAYMENT_AUDIT_CARRIER_HEIGHT)
        assert_equal(receipt_state["epoch"], PAYMENT_AUDIT_EPOCH)
        assert_equal(receipt_state["seal_blockhash"],
                     "%064x" % expected_state["seal_hash"])
        assert_equal(receipt_state["audit_logicalid"],
                     "%064x" % bundle["audit_logical_hash"])
        assert_equal(receipt_state["audit_witnessid"],
                     "%064x" % bundle["audit_witness_hash"])
        assert_equal(receipt_state["cumulative_hash"],
                     "%064x" % expected_state["cumulative_hash"])
        assert_equal(active["payment_probation_state_hash"],
                     "%064x" % bundle["probation_state_hash"])
        assert_equal(bundle["online_count"], QUORUM_MIN_VALID - 1)
        assert_equal(bundle["conclusive"], 0)
        assert_equal(bundle["unobserved_member_misses"], 0)
        # The synthetic historical roster is intentionally not injected into
        # the live deterministic-MN set. The real transition is therefore
        # inconclusive: its receipt cursor advances without penalizing the
        # independent root-bearing payment masternode.
        registered = node.protx_list("registered", True)
        assert_equal(len(registered), 1)
        assert_equal(
            registered[0]["proTxHash"],
            self.payment_masternode_protx_hash,
        )
        assert_equal(registered[0]["paymentAudit"], {
            "consecutiveMisses": 0,
            "paymentWithheld": False,
            "paymentEligibleSinceHeight": -1,
        })

    def retrieve_payment_audit(self, bundle, marker, identity):
        peer = self.authenticate_peer(
            self.connect_peer(marker), marker, identity)
        before = peer.message_count["pqposecert"]
        peer.send_message(msg_getpqpose(bundle["audit_witness_hash"]))
        peer.wait_until(
            lambda: peer.message_count["pqposecert"] > before,
            timeout=1200,
        )
        assert_equal(
            peer.last_message["pqposecert"].payload,
            bundle["audit_certificate"],
        )

    def assert_payment_audit_retired(self, bundle, marker, identity):
        peer = self.authenticate_peer(
            self.connect_peer(marker), marker, identity)
        before = peer.message_count["pqposecert"]
        # A response would be queued before the pong, so this checks absence
        # without relying on an arbitrary sleep.
        peer.send_and_ping(
            msg_getpqpose(bundle["audit_witness_hash"]), timeout=60)
        assert_equal(peer.message_count["pqposecert"], before)

    def restore_reindexed_payment_audit(
            self, context, post, expected_tip, carrier_hash,
            canonical_hash):
        node = self.nodes[0]
        bundle = context["bundle"]
        fixture_args = context["fixture_args"]
        with node.assert_debug_log([
                "fully reverified persisted PQ ChainLock at height %d" %
                PAYMENT_AUDIT_POST_TARGET_HEIGHT,
                "authenticated payment-audit archive through epoch",
                ], timeout=1200):
            self.restart_node(0, extra_args=fixture_args + ["-reindex"])
            # Full reindex rebuilds bounded block-derived audit data but
            # preserves the exact fsynced finality certificate. It is imported
            # only after branch, index, roster, and signature revalidation;
            # block inventory cannot name omitted authorization predecessors.
            assert_equal(
                node.getblockcount(), PAYMENT_AUDIT_POST_SIGNING_HEIGHT)
            assert_equal(node.getbestblockhash(), expected_tip)
            assert node.getblock(carrier_hash)["confirmations"] > 0
            assert_equal(node.getblock(canonical_hash)["confirmations"], -1)
            force_finish_mnsync(node)
            self.assert_payment_audit_state(context, post, expected_tip)
        self.assert_payment_audit_retired(
            bundle, "pq-audit-reindex-retired", 0xc301)

    def test_payment_audit_receipt(self, authorizer):
        node = self.nodes[0]
        context = self.generate_payment_audit_fixture(authorizer)
        bundle = context["bundle"]
        self.admit_payment_audit_chainlocks(context)
        carrier_hash, canonical_hash = \
            self.build_pending_payment_audit_carrier(bundle)
        # Initial activation pins the witness and advances the archive
        # revision. The first reconnect must miss and republish under that
        # stable revision; only the next reconnect may reuse it.
        cache_hit_marker = (
            "reused verified PQ payment-audit receipt transition "
            "for carrier %d" % PAYMENT_AUDIT_CARRIER_HEIGHT)
        with node.assert_debug_log(
                [], unexpected_msgs=[cache_hit_marker], timeout=1200):
            node.invalidateblock(carrier_hash)
            assert_equal(
                node.getblockcount(), PAYMENT_AUDIT_CARRIER_HEIGHT - 1)
            node.reconsiderblock(carrier_hash)
            self.wait_until(
                lambda: node.getbestblockhash() == carrier_hash,
                timeout=1200,
            )
        with node.assert_debug_log([cache_hit_marker], timeout=1200):
            node.invalidateblock(carrier_hash)
            assert_equal(
                node.getblockcount(), PAYMENT_AUDIT_CARRIER_HEIGHT - 1)
            node.reconsiderblock(carrier_hash)
            self.wait_until(
                lambda: node.getbestblockhash() == carrier_hash,
                timeout=1200,
            )
        assert_equal(node.getblockcount(), PAYMENT_AUDIT_CARRIER_HEIGHT)
        # Before a covering CLSIG creates the compact checkpoint, the exact
        # audit is still live and independently retrievable.
        self.retrieve_payment_audit(
            bundle, "pq-audit-live-retrieval", 0xc400)
        post = self.generate_post_audit_chainlock(context)
        expected_tip = node.getbestblockhash()
        self.assert_payment_audit_state(context, post, expected_tip)
        self.assert_payment_audit_retired(
            bundle, "pq-audit-live-retired", 0xc401)

        self.restart_node(0, extra_args=context["fixture_args"])
        force_finish_mnsync(node)
        self.assert_payment_audit_state(context, post, expected_tip)
        self.assert_payment_audit_retired(
            bundle, "pq-audit-restart-retired", 0xc402)

        self.restore_reindexed_payment_audit(
            context, post, expected_tip, carrier_hash, canonical_hash)

    def test_current_catchup_side_branch_reorg(self, authorizer):
        node = self.nodes[0]
        local_best = node.getbestchainlock()
        assert_equal(local_best["height"], FIRST_ELIGIBLE_TARGET_HEIGHT)
        assert FIRST_ELIGIBLE_TARGET_HEIGHT < \
            CURRENT_CATCHUP_PREDECESSOR_HEIGHT

        self.mine_pq_to_height(CURRENT_CATCHUP_TIP_HEIGHT)
        canonical_tip = node.getbestblockhash()
        canonical_target = node.getblockhash(CURRENT_CATCHUP_TARGET_HEIGHT)
        expected_canonical_tip, competing_blocks = \
            self.prepare_competing_work(CURRENT_CATCHUP_PREDECESSOR_HEIGHT)
        assert_equal(expected_canonical_tip, canonical_tip)
        assert_equal(node.getbestblockhash(), canonical_tip)
        assert_equal(node.getblockcount(), CURRENT_CATCHUP_TIP_HEIGHT)

        side_target = competing_blocks[
            CURRENT_CATCHUP_TARGET_HEIGHT
            - CURRENT_CATCHUP_PREDECESSOR_HEIGHT - 1
        ].hash
        side_tip = competing_blocks[-1].hash
        assert side_target != canonical_target
        assert side_tip != canonical_tip
        assert_equal(
            node.getblockheader(side_target)["height"],
            CURRENT_CATCHUP_TARGET_HEIGHT,
        )
        # Restart below both versions of the fixed receipt carrier. The
        # durable authorizer is then imported before either branch reconnects
        # height 2325, so neither valid carrier is mistaken for missing proof.
        node.invalidateblock(canonical_target)
        node.invalidateblock(side_target)
        assert_equal(node.getblockcount(), CURRENT_CATCHUP_TARGET_HEIGHT - 1)
        predecessor_hash = node.getblockhash(
            CURRENT_CATCHUP_PREDECESSOR_HEIGHT)
        genesis_hash = node.getblockhash(0)

        base_heights = [
            EPOCH_ORIGIN + slot * EPOCH_BLOCKS
            for slot in range(ACTIVE_QUORUMS)
        ]
        snapshot_heights = [
            height - ROSTER_SNAPSHOT_LAG for height in base_heights
        ]
        base_hashes = [node.getblockhash(height) for height in base_heights]
        snapshot_hashes = [
            node.getblockhash(height) for height in snapshot_heights
        ]
        snapshot_path = os.path.join(
            self.options.tmpdir, "pq-current-catchup-side-snapshots.dat")
        shares_path = os.path.join(
            self.options.tmpdir, "pq-current-catchup-side-shares.dat")
        authorizer_path = os.path.join(
            self.options.tmpdir, "pq-current-catchup-authorizer.dat")
        Path(authorizer_path).write_bytes(authorizer)
        helper = os.path.join(
            self.config["environment"]["BUILDDIR"], "src", "test",
            "pq_chainlock_fixture" +
            self.config["environment"]["EXEEXT"])
        assert os.path.isfile(helper), \
            "missing pq_chainlock_fixture test helper"

        self.stop_node(0)
        subprocess.run([
            helper,
            snapshot_path,
            shares_path,
            genesis_hash,
            str(CURRENT_CATCHUP_TARGET_HEIGHT),
            side_target,
            str(CURRENT_CATCHUP_PREDECESSOR_HEIGHT),
            predecessor_hash,
            self.payment_btcprev(CURRENT_CATCHUP_TARGET_HEIGHT),
            str(RECOVERY_ANCHOR_BTC_HEIGHT),
            RECOVERY_FUTURE_BTC_HASH,
            str(EPOCH_ORIGIN),
            str(REGISTRATION_CUTOFF_BLOCKS),
            str(ROSTER_SNAPSHOT_LAG),
            str(FUTURE_HORIZON_EPOCHS),
            *base_hashes,
            *snapshot_hashes,
            authorizer_path,
        ], check=True, capture_output=True, text=True,
            timeout=900 * self.options.timeout_factor)
        catchup = self.read_full_dimension_bundle(shares_path)
        fixture_args = [
            arg for arg in self.extra_args[0]
            if not arg.startswith("-pqchainlocktestfixture=")
        ] + ["-pqchainlocktestfixture=%s" % snapshot_path]
        self.extra_args[0] = fixture_args
        node.extra_args = list(fixture_args)
        with node.assert_debug_log(
                ["Loaded branch-bound PQ ChainLock regtest fixture"]):
            self.start_node(0, extra_args=fixture_args)
        node.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        force_finish_mnsync(node)
        node.reconsiderblock(canonical_tip)
        assert_equal(node.getbestblockhash(), canonical_tip)
        node.reconsiderblock(side_tip)
        node.preciousblock(canonical_tip)

        # The certificate names a fully validated side block in the current
        # signing round. Its shared H-sign_lag boundary makes it admissible,
        # while durable finality is still the older 2305 winner.
        assert_equal(node.getbestblockhash(), canonical_tip)
        assert_equal(node.getbestchainlock()["height"],
                     FIRST_ELIGIBLE_TARGET_HEIGHT)
        marker = "pq-current-catchup-side"
        provider = self.authenticate_peer(
            self.connect_peer(marker), marker, 0xc500)
        self.request_chainlock(provider, catchup["logical_hash"])
        with node.assert_debug_log(["accepted PQ ChainLock"], timeout=1200):
            # Enforcing the side winner can disconnect the synthetic MNAUTH
            # identity before a ping response, so submit without a round trip.
            provider.send_message(msg_clsig(catchup["certificate"]))

        expected_logical = "%064x" % catchup["logical_hash"]
        self.wait_until(
            lambda: node.getbestchainlock()["logicalid"] == expected_logical
                    and node.getbestblockhash() == side_tip,
            timeout=1200,
        )
        best = node.getbestchainlock()
        assert_equal(best["height"], CURRENT_CATCHUP_TARGET_HEIGHT)
        assert_equal(best["blockhash"], side_target)
        assert_equal(node.getblockcount(), CURRENT_CATCHUP_TIP_HEIGHT)
        assert node.getblock(side_target)["confirmations"] > 0
        assert_equal(node.getblock(canonical_target)["confirmations"], -1)
        return catchup["certificate"]

    def run_test(self):
        preparation_state, activation_predecessor = self.configure_private_migration()
        self.test_rpc_compatibility_without_winner(preparation_state)
        self.test_getclsig_requests()
        self.test_share_admission(activation_predecessor)
        self.test_final_chainlock_admission(activation_predecessor)
        self.test_no_winner_survives_restart(preparation_state)
        authorizer = self.test_full_dimension_collection(
            activation_predecessor)
        catchup_authorizer = self.test_current_catchup_side_branch_reorg(
            authorizer)
        self.test_payment_audit_receipt(catchup_authorizer)


if __name__ == "__main__":
    PQChainLocksTest().main()
