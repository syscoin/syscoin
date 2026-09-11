#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""NEVM connects preserve invalidity and recover lost acknowledged predecessors."""

from copy import deepcopy
from io import BytesIO
from threading import Thread
import hashlib
import random
import struct
import time

from test_framework.test_framework import SyscoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_raises_rpc_error, force_finish_mnsync
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import (
    COIN,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    CNEVMBlock,
    CNEVMBlockConnect,
    CNEVMBlockDisconnect,
    CNEVMHeader,
    CTxOut,
    hash256,
    msg_generic,
    ser_string,
    ser_uint256,
    ser_vector,
    tx_from_hex,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface, p2p_lock

try:
    import zmq
except ImportError:
    pass


class NEVMPayloadRepairPeer(P2PInterface):
    def on_inv(self, message):
        # This fixture only answers Core's explicit repair request.
        pass


class FeatureNEVMConnectAfterConsensus(SyscoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-whitelist=noban@127.0.0.1",
            "-nevmstartheight=1",
            "-mncollateral=100",
            "-dip3params=1000:1000",
            "-par=2",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_syscoind_zmq()
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.skip_if_no_wallet()

    def _start_zmq_responder(self, address):
        self._zmq_ctx = zmq.Context()
        self._zmq_sock = self._zmq_ctx.socket(zmq.REP)
        self._zmq_sock.bind(address)
        self._zmq_sock.setsockopt(zmq.RCVTIMEO, 1000)
        self._zmq_running = True
        self._connect_syshashes = []
        self._disconnect_syshashes = []
        self._last_nevm_block_data = b"nevmblock"
        self._connect_response = b"connected"
        self._connect_protocol_response = b"connect-v1"
        self._connect_negotiations = 0
        self._payload_negotiations = 0
        self._payload_checks = []
        self._payload_check_response = b"payload-valid"
        self._applied_syshashes = []
        self._buffer_connects = False
        self._buffered_syshashes = []
        self._expected_connect_syshashes = None
        self._nevm_events = []
        self._block_info_available = True

        def _loop():
            while self._zmq_running:
                try:
                    parts = self._zmq_sock.recv_multipart()
                except zmq.Again:
                    continue
                except zmq.ContextTerminated:
                    break
                except zmq.ZMQError:
                    if not self._zmq_running:
                        break
                    continue
                if not parts:
                    continue
                topic = parts[0]
                payload = parts[1] if len(parts) > 1 else b""
                if topic == b"nevmcomms":
                    response = b"ack"
                    if payload == ser_string(b"connect-v1"):
                        self._connect_negotiations += 1
                        response = self._connect_protocol_response
                    elif payload == ser_string(b"payload-v1"):
                        self._payload_negotiations += 1
                        response = b"payload-v1"
                    elif payload == ser_string(b"flush"):
                        self._flush_mock_buffer()
                        self._nevm_events.append(("flush", len(self._applied_syshashes)))
                        response = b"flushed"
                    self._zmq_sock.send_multipart([b"nevmcomms", response])
                elif topic == b"nevmblock":
                    h = hash256(str(random.randint(-0x80000000, 0x7FFFFFFF)).encode())
                    u = uint256_from_str(h)
                    nevm_block = CNEVMBlock()
                    nevm_block.nBlockHash = u
                    nevm_block.nTxRoot = u
                    nevm_block.nReceiptRoot = u
                    nevm_block.vchNEVMBlockData = self._last_nevm_block_data
                    self._zmq_sock.send_multipart([b"nevmblock", nevm_block.serialize()])
                elif topic == b"nevmblockinfo":
                    # Report the applied pair without calling Core while it
                    # may be waiting for this reply with cs_main held.
                    self._nevm_events.append((
                        "blockinfo", len(self._applied_syshashes),
                        self._applied_syshashes[-1] if self._applied_syshashes else 0,
                    ))
                    self._zmq_sock.send_multipart(
                        [
                            b"nevmblockinfo",
                            str(len(self._applied_syshashes)).encode() if self._block_info_available else b"unavailable",
                            f"{self._applied_syshashes[-1] if self._applied_syshashes else 0:064x}".encode(),
                        ]
                    )
                elif topic == b"nevmconnect":
                    response = b"connected"
                    try:
                        nevm_connect = CNEVMBlockConnect()
                        nevm_connect.deserialize(BytesIO(payload))
                        self._connect_syshashes.append(nevm_connect.sysblockhash)
                        if nevm_connect.sysblockhash != 0:
                            response = self._connect_response
                            if callable(response):
                                response = response(nevm_connect)
                            acknowledged = self._applied_syshashes + self._buffered_syshashes
                            exact_retry = acknowledged and acknowledged[-1] == nevm_connect.sysblockhash
                            if response == b"connected" and not exact_retry:
                                if self._expected_connect_syshashes is not None and (
                                    len(acknowledged) >= len(self._expected_connect_syshashes)
                                    or nevm_connect.sysblockhash != self._expected_connect_syshashes[len(acknowledged)]
                                ):
                                    response = b"error:non contiguous insert"
                                elif self._buffer_connects:
                                    self._buffered_syshashes.append(nevm_connect.sysblockhash)
                                else:
                                    self._applied_syshashes.append(nevm_connect.sysblockhash)
                        self._nevm_events.append(("connect", nevm_connect.sysblockhash, response))
                    except Exception as e:
                        self.log.warning("failed to decode nevmconnect: %s", e)
                        self._connect_syshashes.append(-1)
                    self._zmq_sock.send_multipart([b"nevmconnect", response])
                elif topic == b"nevmvalidate":
                    response = b"error:mock-payload-decode"
                    try:
                        request = CNEVMBlockConnect()
                        request.deserialize(BytesIO(payload))
                        self._payload_checks.append(request)
                        response = self._payload_check_response
                        if callable(response):
                            response = response(request)
                        self._nevm_events.append(("payloadcheck", request.sysblockhash, response))
                    except Exception as e:
                        self.log.warning("failed to decode nevmvalidate: %s", e)
                    self._zmq_sock.send_multipart([b"nevmvalidate", response])
                elif topic == b"nevmdisconnect":
                    try:
                        nevm_disconnect = CNEVMBlockDisconnect()
                        nevm_disconnect.deserialize(BytesIO(payload))
                        self._disconnect_syshashes.append(nevm_disconnect.sysblockhash)
                        if self._applied_syshashes and self._applied_syshashes[-1] == nevm_disconnect.sysblockhash:
                            self._applied_syshashes.pop()
                    except Exception:
                        self._disconnect_syshashes.append(-1)
                    self._zmq_sock.send_multipart([b"nevmdisconnect", b"disconnected"])
                else:
                    self._zmq_sock.send_multipart([topic, b"ack"])

        self._zmq_thread = Thread(target=_loop, daemon=True)
        self._zmq_thread.start()

    def _flush_mock_buffer(self):
        self._applied_syshashes.extend(self._buffered_syshashes)
        self._buffered_syshashes.clear()

    def _stop_zmq_responder(self):
        if not self._zmq_running:
            return
        self._zmq_running = False
        if hasattr(self, "_zmq_thread"):
            self._zmq_thread.join(timeout=5)
        if hasattr(self, "_zmq_sock"):
            self._zmq_sock.close(linger=0)
        if hasattr(self, "_zmq_ctx"):
            self._zmq_ctx.destroy(linger=0)

    def _nonzero_connects_since(self, start_len):
        return [h for h in self._connect_syshashes[start_len:] if h not in (0, -1)]

    def _serialize_nevm_block(self, block, nevm_data):
        # Core CBlockHeader does not emit an extra NEVM byte; encode explicitly.
        assert block.is_nevm()
        r = b""
        r += struct.pack("<i", block.nVersion)
        r += ser_uint256(block.hashPrevBlock)
        r += ser_uint256(block.hashMerkleRoot)
        r += struct.pack("<I", block.nTime)
        r += struct.pack("<I", block.nBits)
        r += struct.pack("<I", block.nNonce)
        r += ser_vector(block.vtx, "serialize_with_witness")
        r += ser_string(nevm_data)
        return r

    def _build_block(self, node, *, coinbase_excess=0):
        # Rollback arms the mining gate. Its scheduler owns the recovery,
        # so a miner retries until the resulting active prefix is verified.
        templates = []

        def ready():
            try:
                templates.append(node.getblocktemplate({"rules": ["segwit"]}))
                return True
            except JSONRPCException as error:
                if error.error["code"] == -10 and "execution recovery" in error.error["message"]:
                    return False
                raise

        self.wait_until(ready)
        tmpl = templates[0]
        base_extra = bytes.fromhex(tmpl.get("default_witness_commitment_extra", ""))
        if base_extra == b"":
            raise AssertionError("getblocktemplate missing default_witness_commitment_extra")
        if b"nevm" not in base_extra:
            raise AssertionError("getblocktemplate extra missing NEVM tag")
        if (tmpl.get("version", 0) & (1 << 7)) == 0:
            raise AssertionError("getblocktemplate version missing VERSION_NEVM")

        coinbase = create_coinbase(height=tmpl["height"])
        coinbase.nVersion = tmpl.get("version_coinbase", coinbase.nVersion)
        coinbase.vout[0].nValue = tmpl["coinbasevalue"] + coinbase_excess
        for mn_out in tmpl.get("masternode", []):
            coinbase.vout.append(CTxOut(mn_out["amount"], bytes.fromhex(mn_out["script"])))
        for sb_out in tmpl.get("superblock", []):
            coinbase.vout.append(CTxOut(sb_out["amount"], bytes.fromhex(sb_out["script"])))
        coinbase.extraData = base_extra
        coinbase.rehash()

        txlist = [tx_from_hex(e["data"]) for e in tmpl.get("transactions", [])]
        block = create_block(tmpl=tmpl, coinbase=coinbase, txlist=txlist)
        add_witness_commitment(block, nonce=0)
        block.solve()
        return block

    @staticmethod
    def _invalid_response(request, *, nevm_delta=0, sys_delta=0):
        return (
            f"invalid:{request.evmBlock.nBlockHash ^ nevm_delta:064x}:"
            f"{request.sysblockhash ^ sys_delta:064x}"
        ).encode()

    @staticmethod
    def _payload_invalid_response(request):
        digest = hashlib.sha256(
            b"syscoin-nevm-payload-v1\x00"
            + ser_uint256(request.evmBlock.nBlockHash)
            + ser_uint256(request.evmBlock.nTxRoot)
            + ser_uint256(request.evmBlock.nReceiptRoot)
            + ser_uint256(request.sysblockhash)
            + request.evmBlock.vchNEVMBlockData
        ).digest()
        return (
            f"payload-invalid:{request.evmBlock.nBlockHash:064x}:"
            f"{request.sysblockhash:064x}:{uint256_from_str(digest):064x}"
        ).encode()

    def _check_payload_repair_from_requested_peer(self, *, commitment_invalid=False):
        node = self.nodes[0]
        block = self._build_block(node)
        # Keep this repaired-and-cleaned-up fixture distinct if later cases
        # reuse the cached template for the same parent.
        block.nNonce += 1 + (1 << 16 if commitment_invalid else 0)
        block.solve()
        original_payload = self._last_nevm_block_data
        replacement_payload = b"approved-nevm-fixture"
        original_raw = self._serialize_nevm_block(block, original_payload)
        replacement_raw = self._serialize_nevm_block(block, replacement_payload)
        previous_tip = node.getbestblockhash()
        applied = self._applied_syshashes[:]
        connect_len = len(self._connect_syshashes)
        checks = len(self._payload_checks)
        negotiations = self._payload_negotiations
        previous_mocktime = node.mocktime
        rejected = []

        def connect_response(request):
            if request.sysblockhash == block.sha256 and request.evmBlock.vchNEVMBlockData == original_payload:
                rejected.append(request)
                return self._payload_invalid_response(request)
            if commitment_invalid and request.sysblockhash == block.sha256:
                return self._invalid_response(request)
            return b"connected"

        self._connect_response = connect_response
        self._payload_check_response = lambda request: (
            (self._invalid_response(request) if commitment_invalid else b"payload-valid")
            if request.sysblockhash == block.sha256
            and request.evmBlock.vchNEVMBlockData == replacement_payload
            else self._payload_invalid_response(request)
        )
        try:
            assert_raises_rpc_error(-25, "nevm-connect-payload-invalid", node.submitblock, original_raw.hex())
            assert_equal(len(rejected), 1)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.getblock(block.hash, 0), original_raw.hex())
            stored_header = node.getblockheader(block.hash, False)
            branch = next(tip for tip in node.getchaintips() if tip["hash"] == block.hash)
            assert branch["status"] != "invalid"
            for _ in range(2):
                # Pending repair stops before BlockChecked, so BIP22 has no
                # new validation result for an already indexed submission.
                assert_equal(node.submitblock(original_raw.hex()), "inconclusive")
            assert_equal(self._nonzero_connects_since(connect_len), [block.sha256])
            assert_equal(len(self._payload_checks), checks)
            assert_equal(self._payload_negotiations, negotiations)
            assert_equal(self._applied_syshashes, applied)

            # A connected peer may not yet have this block and remain silent.
            # Timeout must retire the connection, allowing a fresh connection
            # to receive the same request without accepting a delayed reply.
            node.setmocktime(previous_mocktime or int(time.time()))
            silent_peer = node.add_p2p_connection(NEVMPayloadRepairPeer())
            silent_peer.wait_for_getdata([block.sha256])
            node.bumpmocktime(61)
            silent_peer.wait_for_disconnect()
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.getblock(block.hash, 0), original_raw.hex())
            assert_equal(self._nonzero_connects_since(connect_len), [block.sha256])
            assert_equal(len(self._payload_checks), checks)
            node.bumpmocktime(6)

            peer = node.add_p2p_connection(NEVMPayloadRepairPeer())
            peer.wait_for_getdata([block.sha256])
            with p2p_lock:
                assert_equal(peer.last_message["getdata"].inv[0].type, MSG_BLOCK | MSG_WITNESS_FLAG)
            # Reuse the legitimately mined wrapper. Only the opaque mock
            # engine payload differs in the requested full-block response.
            peer.send_message(msg_generic(b"block", replacement_raw))
            if commitment_invalid:
                self.wait_until(lambda: any(tip["hash"] == block.hash and tip["status"] == "invalid"
                                           for tip in node.getchaintips()))
                assert_equal(node.getbestblockhash(), previous_tip)
            else:
                self.wait_until(lambda: node.getbestblockhash() == block.hash)
            peer.sync_with_ping()
            assert_equal(node.getblockheader(block.hash, False), stored_header)
            assert_equal(node.getblock(block.hash, 0), replacement_raw.hex())
            assert_equal(self._applied_syshashes, applied if commitment_invalid else applied + [block.sha256])
            assert_equal(self._nonzero_connects_since(connect_len), [block.sha256, block.sha256])
            assert_equal(len(self._payload_checks), checks + 1)
            assert_equal(self._payload_negotiations, negotiations + 1)
            validated = self._payload_checks[-1]
            assert_equal(validated.sysblockhash, block.sha256)
            assert_equal(validated.evmBlock.nBlockHash, rejected[0].evmBlock.nBlockHash)
            assert_equal(validated.evmBlock.nTxRoot, rejected[0].evmBlock.nTxRoot)
            assert_equal(validated.evmBlock.nReceiptRoot, rejected[0].evmBlock.nReceiptRoot)
            assert_equal(validated.evmBlock.vchNEVMBlockData, replacement_payload)
            assert_equal(node.submitblock(replacement_raw.hex()), "duplicate-invalid" if commitment_invalid else "duplicate")
            # Administrative test cleanup after successful repair exercises
            # ordinary undo and keeps later cases below the first superblock.
            if not commitment_invalid:
                node.invalidateblock(block.hash)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(self._applied_syshashes, applied)
        finally:
            node.disconnect_p2ps()
            node.setmocktime(previous_mocktime or 0)
            self._connect_response = b"connected"
            self._payload_check_response = b"payload-valid"

    def _check_payload_repair_retargets_requested_peer(self):
        node = self.nodes[0]
        previous_tip = node.getbestblockhash()
        previous_height = node.getblockcount()
        previous_coinbase = node.getblock(previous_tip)["tx"][0]
        previous_coin = node.gettxout(previous_coinbase, 0)
        previous_mocktime = node.mocktime
        applied = self._applied_syshashes[:]
        connect_len = len(self._connect_syshashes)
        checks = len(self._payload_checks)

        def build_branch_block(label, parent_hash, height):
            # These coinbase-only branches precede DIP3 and the first
            # superblock. Reuse template payments, but commit a distinct mock
            # NEVM identity even if getblocktemplate returns its cached block.
            assert height < 1000
            block = self._build_block(node)
            assert_equal(len(block.vtx), 1)
            coinbase = block.vtx[0]
            coinbase.vin[0].scriptSig = create_coinbase(height).vin[0].scriptSig
            nevm_header = CNEVMHeader()
            for field in ("nBlockHash", "nTxRoot", "nReceiptRoot"):
                setattr(nevm_header, field, uint256_from_str(hash256(
                    label + field.encode() + ser_uint256(parent_hash)
                )))
            offset = coinbase.extraData.index(b"nevm") + len(b"nevm")
            coinbase.extraData = (
                coinbase.extraData[:offset] + nevm_header.serialize()
                + coinbase.extraData[offset + len(nevm_header.serialize()):]
            )
            coinbase.vout.pop()  # Replace the template's witness commitment.
            block.hashPrevBlock = parent_hash
            block.nTime += height - previous_height - 1
            block.nNonce = 0
            add_witness_commitment(block, nonce=0)
            block.solve()
            return block

        block_a = build_branch_block(b"payload-retarget-A", int(previous_tip, 16), previous_height + 1)
        block_b = build_branch_block(b"payload-retarget-B", int(previous_tip, 16), previous_height + 1)
        block_b2 = build_branch_block(b"payload-retarget-B2", block_b.sha256, previous_height + 2)
        blocks = (block_a, block_b, block_b2)
        original_payload = self._last_nevm_block_data
        original_raws = [self._serialize_nevm_block(block, original_payload) for block in blocks]
        stale_a_raw = self._serialize_nevm_block(block_a, b"stale-nevm-A")
        replacement_payload = b"approved-nevm-B"
        replacement_b_raw = self._serialize_nevm_block(block_b, replacement_payload)
        rejected = []

        def connect_response(request):
            if request.sysblockhash in (block_a.sha256, block_b.sha256) and request.evmBlock.vchNEVMBlockData == original_payload:
                rejected.append(request)
                return self._payload_invalid_response(request)
            return b"connected"

        def assert_pending_b():
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.gettxout(previous_coinbase, 0), previous_coin)
            for block, raw in zip(blocks, original_raws):
                assert_equal(node.getblock(block.hash, 0), raw.hex())
                assert_equal(node.gettxout(block.vtx[0].hash, 0), None)
            tips = {tip["hash"]: tip["status"] for tip in node.getchaintips()}
            assert tips[block_a.hash] != "invalid"
            assert tips[block_b2.hash] != "invalid"
            assert_equal(self._nonzero_connects_since(connect_len), [block_a.sha256, block_b.sha256])
            assert_equal(len(self._payload_checks), checks)
            assert_equal(self._applied_syshashes, applied)

        self._connect_response = connect_response
        self._payload_check_response = lambda request: (
            b"payload-valid" if request.sysblockhash == block_b.sha256
            and request.evmBlock.vchNEVMBlockData == replacement_payload
            else self._payload_invalid_response(request)
        )
        try:
            # Freeze time throughout retargeting so A's peer cannot retire
            # because its request timed out.
            node.setmocktime(previous_mocktime or int(time.time()))
            assert_raises_rpc_error(-25, "nevm-connect-payload-invalid", node.submitblock, original_raws[0].hex())
            peer_a = node.add_p2p_connection(NEVMPayloadRepairPeer())
            peer_a.wait_for_getdata([block_a.sha256])

            assert_equal(node.submitblock(original_raws[1].hex()), "inconclusive")
            # B2 makes B's branch strictly better while A's response is held.
            assert_equal(node.submitblock(original_raws[2].hex()), "inconclusive")
            peer_a.wait_for_disconnect()
            assert_pending_b()
            assert_equal([request.sysblockhash for request in rejected], [block_a.sha256, block_b.sha256])
            stored_header_b = node.getblockheader(block_b.hash, False)

            peer_b = node.add_p2p_connection(NEVMPayloadRepairPeer())
            peer_b.wait_for_getdata([block_b.sha256])
            with p2p_lock:
                assert_equal(peer_b.last_message["getdata"].inv[0].type, MSG_BLOCK | MSG_WITNESS_FLAG)
            # The old connection is retired. Deliver its stale A bytes on
            # B's designated connection and prove they cannot satisfy or
            # disturb B's repair before the actual B response arrives.
            peer_b.send_and_ping(msg_generic(b"block", stale_a_raw))
            assert peer_b.is_connected
            assert_pending_b()

            peer_b.send_message(msg_generic(b"block", replacement_b_raw))
            self.wait_until(lambda: node.getbestblockhash() == block_b2.hash)
            peer_b.sync_with_ping()
            assert_equal(node.getblockheader(block_b.hash, False), stored_header_b)
            assert_equal(node.getblock(block_b.hash, 0), replacement_b_raw.hex())
            assert_equal(node.getblock(block_a.hash, 0), original_raws[0].hex())
            assert_equal(node.getblock(block_b2.hash, 0), original_raws[2].hex())
            assert_equal(self._applied_syshashes, applied + [block_b.sha256, block_b2.sha256])
            assert_equal(self._nonzero_connects_since(connect_len), [
                block_a.sha256, block_b.sha256, block_b.sha256, block_b2.sha256,
            ])
            assert_equal(len(self._payload_checks), checks + 1)
            validated = self._payload_checks[-1]
            assert_equal(validated.sysblockhash, block_b.sha256)
            for field in ("nBlockHash", "nTxRoot", "nReceiptRoot"):
                assert_equal(getattr(validated.evmBlock, field), getattr(rejected[-1].evmBlock, field))
            assert_equal(validated.evmBlock.vchNEVMBlockData, replacement_payload)
            assert node.gettxout(block_b.vtx[0].hash, 0) is not None
            assert node.gettxout(block_b2.vtx[0].hash, 0) is not None

            # Remove A before undoing B so fixture cleanup cannot select the
            # deliberately unrepaired old branch. Keep later cases' height.
            node.invalidateblock(block_a.hash)
            node.invalidateblock(block_b.hash)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.getblockcount(), previous_height)
            assert_equal(self._applied_syshashes, applied)
        finally:
            node.disconnect_p2ps()
            node.setmocktime(previous_mocktime or 0)
            self._connect_response = b"connected"
            self._payload_check_response = b"payload-valid"

    def _check_lost_acknowledged_predecessors(self):
        node = self.nodes[0]
        core_pid = node.process.pid
        applied = self._applied_syshashes[:]
        self._buffer_connects = True
        missing = [int(block_hash, 16) for block_hash in self.generate(node, 2)]
        assert_equal(self._applied_syshashes, applied)
        assert_equal(self._buffered_syshashes, missing)

        # Prepare the successor while the mock engine is still available.
        # Then lose only acknowledged entries, keeping Core and its chain live.
        block = self._build_block(node)
        raw = self._serialize_nevm_block(block, self._last_nevm_block_data).hex()
        parent = applied + missing
        self._expected_connect_syshashes = parent + [block.sha256]
        self._buffered_syshashes.clear()
        connect_len = len(self._connect_syshashes)
        disconnect_len = len(self._disconnect_syshashes)
        event_len = len(self._nevm_events)
        parent_tip = node.getbestblockhash()
        parent_coinbase = node.getblock(parent_tip)["tx"][0]
        parent_coin = node.gettxout(parent_coinbase, 0)

        assert_equal(node.submitblock(raw), None)
        assert_equal(node.process.pid, core_pid)
        assert_equal(node.process.poll(), None)
        assert_equal(node.getbestblockhash(), block.hash)
        assert_equal(node.gettxout(parent_coinbase, 0), {
            **parent_coin,
            "bestblock": block.hash,
            "confirmations": parent_coin["confirmations"] + 1,
        })
        assert node.gettxout(block.vtx[0].hash, 0) is not None
        assert_equal(self._disconnect_syshashes[disconnect_len:], [])
        assert_equal(self._nonzero_connects_since(connect_len), [block.sha256, *missing, block.sha256])

        events = self._nevm_events[event_len:]
        connects = [event for event in events if event[0] == "connect"]
        assert_equal(connects[0], ("connect", block.sha256, b"error:non contiguous insert"))
        assert_equal(connects[-1], ("connect", block.sha256, b"connected"))
        statuses = [(index, event) for index, event in enumerate(events) if event[0] == "blockinfo"]
        assert statuses
        assert_equal(statuses[0][1], ("blockinfo", len(applied), applied[-1]))
        assert_equal(statuses[-1][1], ("blockinfo", len(parent), parent[-1]))
        for index, _ in statuses:
            assert index > 0 and events[index - 1][0] == "flush"
        # The missing prefix must be applied before the current pair is retried.
        assert statuses[-1][0] < len(events) - 1
        assert_equal(self._applied_syshashes[:len(parent)], parent)
        assert_equal(self._applied_syshashes + self._buffered_syshashes, parent + [block.sha256])

        # Complete the mock's final acknowledged batch before the other cases.
        self._flush_mock_buffer()
        self._buffer_connects = False
        self._expected_connect_syshashes = None

    def _check_mining_prefix_scheduler(self):
        node = self.nodes[0]
        assert_equal(node.getconnectioncount(), 0)
        cached = node.getblocktemplate({"rules": ["segwit"]})
        tip = node.getbestblockhash()
        applied = self._applied_syshashes[:]
        assert len(applied) > 1
        connect_len = len(self._connect_syshashes)
        disconnect_len = len(self._disconnect_syshashes)

        # Simulate a lost execution suffix. Failed invalidation preflight
        # arms recovery without changing Core or introducing a new block.
        self._applied_syshashes = applied[:-1]
        self._expected_connect_syshashes = applied
        self._block_info_available = False
        try:
            assert_raises_rpc_error(-20, "nevm-reorg-status:", node.invalidateblock, tip)
            assert_raises_rpc_error(
                -10, "execution recovery", node.getblocktemplate, {"rules": ["segwit"]},
            )
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(self._nonzero_connects_since(connect_len), [])

            # No mining call or peer drives this retry: the private scheduler
            # must replay the retained block and verify its final applied pair.
            self._block_info_available = True
            self.wait_until(lambda: self._applied_syshashes == applied)
            recovered = node.getblocktemplate({"rules": ["segwit"]})
            assert_equal(recovered["previousblockhash"], cached["previousblockhash"])
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(self._nonzero_connects_since(connect_len), [applied[-1]])
            assert_equal(self._disconnect_syshashes[disconnect_len:], [])
        finally:
            self._block_info_available = True
            self._expected_connect_syshashes = None

    def _check_applied_pending_child_scheduler(self):
        node = self.nodes[0]
        assert_equal(node.getconnectioncount(), 0)
        core_pid = node.process.pid
        block = self._build_block(node)
        # Give this later-invalidated fixture its own identity even when the
        # next case reuses the cached template for the same parent.
        block.nNonce += 1 << 17
        block.solve()
        raw = self._serialize_nevm_block(block, self._last_nevm_block_data).hex()
        previous_tip = node.getbestblockhash()
        previous_coinbase = node.getblock(previous_tip)["tx"][0]
        previous_coin = node.gettxout(previous_coinbase, 0)

        # Build the descendant offline while C is still pending. These early
        # coinbase-only blocks use the same payments below DIP3/superblocks.
        assert_equal(len(block.vtx), 1)
        descendant = deepcopy(block)
        coinbase = descendant.vtx[0]
        coinbase.vin[0].scriptSig = create_coinbase(node.getblockcount() + 2).vin[0].scriptSig
        nevm_header = CNEVMHeader()
        for field in ("nBlockHash", "nTxRoot", "nReceiptRoot"):
            setattr(nevm_header, field, uint256_from_str(hash256(
                b"pending-child-descendant" + field.encode() + ser_uint256(block.sha256)
            )))
        offset = coinbase.extraData.index(b"nevm") + len(b"nevm")
        coinbase.extraData = (
            coinbase.extraData[:offset] + nevm_header.serialize()
            + coinbase.extraData[offset + len(nevm_header.serialize()):]
        )
        coinbase.vout.pop()
        descendant.hashPrevBlock = block.sha256
        descendant.nTime += 1
        descendant.nNonce = 0
        add_witness_commitment(descendant, nonce=0)
        descendant.solve()
        descendant_raw = self._serialize_nevm_block(descendant, self._last_nevm_block_data).hex()

        applied = self._applied_syshashes[:]
        connect_len = len(self._connect_syshashes)
        disconnect_len = len(self._disconnect_syshashes)
        event_len = len(self._nevm_events)

        def apply_without_acknowledgement(request):
            if request.sysblockhash != block.sha256:
                return b"error:mock-unexpected-connect"
            if self._applied_syshashes == applied:
                self._applied_syshashes.append(block.sha256)
            # Apply the request, but make its acknowledgement unusable. The
            # subsequent unavailable status prevents the bounded live recovery
            # from proving that the child has already reached the engine.
            return b"error:mock-lost-ack"

        self._connect_response = apply_without_acknowledgement
        self._expected_connect_syshashes = applied + [block.sha256, descendant.sha256]
        self._block_info_available = False
        try:
            assert_raises_rpc_error(-25, "nevm-response-unserialize", node.submitblock, raw)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.gettxout(previous_coinbase, 0), previous_coin)
            assert_equal(node.gettxout(block.vtx[0].hash, 0), None)
            assert_equal(node.getblock(block.hash, 0), raw)
            branch = next(tip for tip in node.getchaintips() if tip["hash"] == block.hash)
            assert branch["status"] != "invalid"
            assert_equal(self._applied_syshashes, applied + [block.sha256])
            assert_equal(self._nonzero_connects_since(connect_len), [block.sha256])

            # Download D before communication recovers. Its public submission
            # retries C, whose unavailable acknowledgement still keeps Core at
            # P; D remains an eligible stored descendant of that same branch.
            assert_equal(node.submitblock(descendant_raw), "inconclusive")
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.getblock(descendant.hash, 0), descendant_raw)
            assert_equal(node.gettxout(descendant.vtx[0].hash, 0), None)
            branch = next(tip for tip in node.getchaintips() if tip["hash"] == descendant.hash)
            assert branch["status"] != "invalid"
            assert_equal(self._applied_syshashes, applied + [block.sha256])
            assert_equal(self._nonzero_connects_since(connect_len), [block.sha256, block.sha256])
            assert_raises_rpc_error(
                -10, "execution recovery", node.getblocktemplate, {"rules": ["segwit"]},
            )

            # Restore replies without submitting any block or requesting a
            # template. Only the private scheduler can finish Core's retained
            # pending child and reopen mining against the engine's exact pair.
            self._connect_response = b"connected"
            self._block_info_available = True
            self.wait_until(lambda: node.getbestblockhash() == block.hash)
            assert_equal(node.process.pid, core_pid)
            assert_equal(node.process.poll(), None)
            assert_equal(node.getblock(block.hash, 0), raw)
            assert_equal(node.gettxout(previous_coinbase, 0), {
                **previous_coin,
                "bestblock": block.hash,
                "confirmations": previous_coin["confirmations"] + 1,
            })
            assert node.gettxout(block.vtx[0].hash, 0) is not None
            assert_equal(self._applied_syshashes, applied + [block.sha256])
            assert_raises_rpc_error(
                -10, "execution recovery", node.getblocktemplate, {"rules": ["segwit"]},
            )

            # The next scheduler pass must resume ordinary candidate selection
            # after verifying C. No new block submission or peer may drive D.
            self.wait_until(lambda: node.getbestblockhash() == descendant.hash)
            assert_equal(node.getblock(descendant.hash, 0), descendant_raw)
            assert_equal(node.gettxout(previous_coinbase, 0), {
                **previous_coin,
                "bestblock": descendant.hash,
                "confirmations": previous_coin["confirmations"] + 2,
            })
            assert_equal(node.gettxout(block.vtx[0].hash, 0)["confirmations"], 2)
            assert node.gettxout(descendant.vtx[0].hash, 0) is not None
            assert_equal(self._applied_syshashes, applied + [block.sha256, descendant.sha256])

            # A final scheduler pass verifies D before mining reopens. These
            # template retries only observe readiness, never select candidates.
            templates = []

            def ready():
                try:
                    templates.append(node.getblocktemplate({"rules": ["segwit"]}))
                    return True
                except JSONRPCException as error:
                    if error.error["code"] == -10 and "execution recovery" in error.error["message"]:
                        return False
                    raise

            self.wait_until(ready)
            assert_equal(templates[0]["previousblockhash"], descendant.hash)
            assert_equal(self._nonzero_connects_since(connect_len), [
                block.sha256, block.sha256, block.sha256, descendant.sha256,
            ])
            assert_equal(self._disconnect_syshashes[disconnect_len:], [])
            events = self._nevm_events[event_len:]
            statuses = [event for event in events if event[0] == "blockinfo"]
            assert len(statuses) >= 3
            assert_equal(statuses[-1], ("blockinfo", len(applied) + 2, descendant.sha256))
            descendant_connect_index = events.index(("connect", descendant.sha256, b"connected"))
            parent_status_index = max(
                index for index, event in enumerate(events)
                if event == ("blockinfo", len(applied) + 1, block.sha256)
            )
            assert parent_status_index < descendant_connect_index
            assert_equal(events[parent_status_index - 1], ("flush", len(applied) + 1))
            last_status_index = max(index for index, event in enumerate(events) if event[0] == "blockinfo")
            assert last_status_index > descendant_connect_index
            assert_equal(events[last_status_index - 1], ("flush", len(applied) + 2))

            # Administrative cleanup keeps subsequent response cases below
            # the first superblock after scheduler completion is established.
            node.invalidateblock(block.hash)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(self._applied_syshashes, applied)
        finally:
            self._connect_response = b"connected"
            self._block_info_available = True
            self._expected_connect_syshashes = None

    def _check_applied_pending_child_reselected(self):
        node = self.nodes[0]
        assert_equal(node.getconnectioncount(), 0)
        core_pid = node.process.pid
        previous_tip = node.getbestblockhash()
        previous_height = node.getblockcount()
        previous_coinbase = node.getblock(previous_tip)["tx"][0]
        previous_coin = node.gettxout(previous_coinbase, 0)
        applied = self._applied_syshashes[:]

        def build_branch_block(label, parent_hash, height):
            # Reuse pre-DIP3 payments while committing distinct mock NEVM
            # identities for these coinbase-only branches below superblocks.
            block = self._build_block(node)
            assert_equal(len(block.vtx), 1)
            coinbase = block.vtx[0]
            coinbase.vin[0].scriptSig = create_coinbase(height).vin[0].scriptSig
            nevm_header = CNEVMHeader()
            for field in ("nBlockHash", "nTxRoot", "nReceiptRoot"):
                setattr(nevm_header, field, uint256_from_str(hash256(
                    label + field.encode() + ser_uint256(parent_hash)
                )))
            offset = coinbase.extraData.index(b"nevm") + len(b"nevm")
            coinbase.extraData = (
                coinbase.extraData[:offset] + nevm_header.serialize()
                + coinbase.extraData[offset + len(nevm_header.serialize()):]
            )
            coinbase.vout.pop()
            block.hashPrevBlock = parent_hash
            block.nTime += height - previous_height - 1
            block.nNonce = 1 << 18
            add_witness_commitment(block, nonce=0)
            block.solve()
            return block

        block_c = build_branch_block(b"applied-reselection-C", int(previous_tip, 16), previous_height + 1)
        block_b = build_branch_block(b"applied-reselection-B", int(previous_tip, 16), previous_height + 1)
        block_b2 = build_branch_block(b"applied-reselection-B2", block_b.sha256, previous_height + 2)
        blocks = (block_c, block_b, block_b2)
        raws = [self._serialize_nevm_block(block, self._last_nevm_block_data).hex() for block in blocks]
        connect_len = len(self._connect_syshashes)
        disconnect_len = len(self._disconnect_syshashes)

        def apply_without_acknowledgement(request):
            if request.sysblockhash == block_c.sha256:
                if self._applied_syshashes == applied:
                    self._applied_syshashes.append(block_c.sha256)
                return b"error:mock-lost-ack"
            return b"error:non contiguous insert"

        self._connect_response = apply_without_acknowledgement
        self._block_info_available = False
        try:
            assert_raises_rpc_error(-25, "nevm-response-unserialize", node.submitblock, raws[0])
            assert_equal(node.submitblock(raws[1]), "inconclusive")
            assert_equal(node.submitblock(raws[2]), "inconclusive")
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.gettxout(previous_coinbase, 0), previous_coin)
            for block, raw in zip(blocks, raws):
                assert_equal(node.getblock(block.hash, 0), raw)
                assert_equal(node.gettxout(block.vtx[0].hash, 0), None)
            tips = {tip["hash"]: tip["status"] for tip in node.getchaintips()}
            assert tips[block_c.hash] != "invalid"
            assert tips[block_b2.hash] != "invalid"
            assert_equal(self._applied_syshashes, applied + [block_c.sha256])
            # B's ordinary activation attempt must wait before external
            # delivery while C's earlier applied identity remains unresolved.
            assert_equal(self._nonzero_connects_since(connect_len), [block_c.sha256, block_c.sha256])
            assert_equal(self._disconnect_syshashes[disconnect_len:], [])
            assert_raises_rpc_error(
                -10, "execution recovery", node.getblocktemplate, {"rules": ["segwit"]},
            )
            recovery_connect_len = len(self._connect_syshashes)

            # Only the scheduler may reconcile engine-only C and select the
            # already-downloaded better branch; Core must never publish C.
            with node.assert_debug_log(
                [f"UpdateTip: new best={block_b2.hash}"],
                unexpected_msgs=[f"UpdateTip: new best={block_c.hash}"],
            ):
                self._expected_connect_syshashes = applied + [block_b.sha256, block_b2.sha256]
                self._connect_response = b"connected"
                self._block_info_available = True
                self.wait_until(lambda: node.getbestblockhash() == block_b2.hash)

                templates = []

                def ready():
                    try:
                        templates.append(node.getblocktemplate({"rules": ["segwit"]}))
                        return True
                    except JSONRPCException as error:
                        if error.error["code"] == -10 and "execution recovery" in error.error["message"]:
                            return False
                        raise

                self.wait_until(ready)
                assert_equal(templates[0]["previousblockhash"], block_b2.hash)

            assert_equal(node.process.pid, core_pid)
            assert_equal(node.process.poll(), None)
            assert_equal(node.gettxout(block_c.vtx[0].hash, 0), None)
            assert_equal(node.gettxout(previous_coinbase, 0), {
                **previous_coin,
                "bestblock": block_b2.hash,
                "confirmations": previous_coin["confirmations"] + 2,
            })
            assert_equal(node.gettxout(block_b.vtx[0].hash, 0)["confirmations"], 2)
            assert node.gettxout(block_b2.vtx[0].hash, 0) is not None
            for block, raw in zip(blocks, raws):
                assert_equal(node.getblock(block.hash, 0), raw)
            tips = {tip["hash"]: tip["status"] for tip in node.getchaintips()}
            assert tips[block_c.hash] != "invalid"
            assert_equal(tips[block_b2.hash], "active")
            assert_equal(self._applied_syshashes, applied + [block_b.sha256, block_b2.sha256])
            assert_equal(self._nonzero_connects_since(recovery_connect_len), [block_b.sha256, block_b2.sha256])
            assert_equal(self._disconnect_syshashes[disconnect_len:], [block_c.sha256])

            # Remove C before undoing B so fixture cleanup cannot select it.
            node.invalidateblock(block_c.hash)
            node.invalidateblock(block_b.hash)
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.getblockcount(), previous_height)
            assert_equal(self._applied_syshashes, applied)
        finally:
            self._connect_response = b"connected"
            self._block_info_available = True
            self._expected_connect_syshashes = None

    def _check_connect_responses(self, responses, *, protocol_response=b"connect-v1", consensus_invalid=False, connects_per_attempt=None):
        node = self.nodes[0]
        block = self._build_block(node)
        raw = self._serialize_nevm_block(block, self._last_nevm_block_data).hex()
        previous_tip = node.getbestblockhash()
        previous_coinbase = node.getblock(previous_tip)["tx"][0]
        previous_coin = node.gettxout(previous_coinbase, 0)

        # Index a descendant before the failed connection to verify that an
        # operational response does not invalidate the candidate's branch.
        descendant = create_block(
            hashprev=block.sha256, coinbase=create_coinbase(node.getblockcount() + 2),
            ntime=block.nTime + 1, version=block.nVersion,
        )
        descendant.solve()
        assert_equal(node.submitheader(bytes.fromhex(raw)[:80].hex()), None)
        assert_equal(node.submitheader(self._serialize_nevm_block(descendant, b"")[:80].hex()), None)
        connect_len = len(self._connect_syshashes)
        negotiations = self._connect_negotiations
        applied = self._applied_syshashes[:]
        self._connect_protocol_response = protocol_response
        expected_connects = []
        if connects_per_attempt is None:
            connects_per_attempt = 1 if consensus_invalid or protocol_response != b"connect-v1" else 2
        for attempt, response in enumerate(responses, start=1):
            self._connect_response = response
            if consensus_invalid:
                assert_equal(node.submitblock(raw), "nevm-connect-consensus-invalid")
            else:
                error = "nevm-connect-response-invalid-data" if protocol_response == b"connect-v1" else "nevm-connect-protocol-unsupported"
                assert_raises_rpc_error(-25, error, node.submitblock, raw)
                branch_tip = next(tip for tip in node.getchaintips() if tip["hash"] == descendant.hash)
                assert_equal(branch_tip["status"], "headers-only")
            assert_equal(node.getbestblockhash(), previous_tip)
            assert_equal(node.gettxout(previous_coinbase, 0), previous_coin)
            assert_equal(node.gettxout(block.vtx[0].hash, 0), None)
            assert_equal(self._applied_syshashes, applied)
            assert_equal(self._connect_negotiations, negotiations + attempt * connects_per_attempt)
            if protocol_response == b"connect-v1":
                expected_connects.extend([block.sha256] * connects_per_attempt)
            assert_equal(self._nonzero_connects_since(connect_len), expected_connects)

        self._connect_response = b"connected"
        self._connect_protocol_response = b"connect-v1"
        if consensus_invalid:
            assert_equal(node.submitblock(raw), "duplicate-invalid")
            assert_equal(self._nonzero_connects_since(connect_len), expected_connects)
            return
        # Resubmit the exact indexed block, with no reconsiderblock call.
        assert_equal(node.submitblock(raw), "duplicate")
        assert_equal(node.getbestblockhash(), block.hash)
        assert node.gettxout(block.vtx[0].hash, 0) is not None
        assert_equal(self._applied_syshashes, applied + [block.sha256])
        assert_equal(self._connect_negotiations, negotiations + len(responses) * connects_per_attempt + 1)
        assert_equal(self._nonzero_connects_since(connect_len), expected_connects + [block.sha256])

    def run_test(self):
        address = "tcp://127.0.0.1:29601"
        self._start_zmq_responder(address)
        try:
            self.extra_args[0].append(f"-zmqpubnevm={address}")
            self.extra_args[0].append("-debug=zmq")
            self.restart_node(0, self.extra_args[0])
            force_finish_mnsync(self.nodes[0])

            # Leave room for each response group below the first superblock.
            self.generate(self.nodes[0], 1)
            tip_before = self.nodes[0].getbestblockhash()
            height_before = self.nodes[0].getblockcount()

            # Rejected late (coinbase value) must not emit a nonzero nevmconnect.
            bad_block = self._build_block(self.nodes[0], coinbase_excess=COIN)
            time.sleep(0.2)
            connect_len = len(self._connect_syshashes)
            disconnect_len = len(self._disconnect_syshashes)

            raw = self._serialize_nevm_block(bad_block, self._last_nevm_block_data)
            result = self.nodes[0].submitblock(hexdata=raw.hex())
            time.sleep(0.5)

            assert_equal(self.nodes[0].getbestblockhash(), tip_before)
            assert_equal(self.nodes[0].getblockcount(), height_before)
            assert_equal(result, "bad-cb-amount")
            assert_equal(self._nonzero_connects_since(connect_len), [])
            assert_equal(self._disconnect_syshashes[disconnect_len:], [])

            self.log.info("Live Core replays only predecessors lost from the engine's acknowledged buffer")
            self._check_lost_acknowledged_predecessors()
            assert_equal(self._payload_checks, [])
            assert_equal(self._payload_negotiations, 0)

            self.log.info("Mining recovery runs without peers, new blocks, or a mining request")
            self._check_mining_prefix_scheduler()

            self.log.info("Scheduled recovery finishes an already-applied child after its acknowledgement fails")
            self._check_applied_pending_child_scheduler()

            self.log.info("Scheduled recovery rolls back an engine-only child after a better branch arrives")
            self._check_applied_pending_child_reselected()

            self.log.info("A requested full block repairs only the engine-approved NEVM payload")
            self._check_payload_repair_from_requested_peer()

            self.log.info("A requested payload can prove an immutable commitment contradiction")
            self._check_payload_repair_from_requested_peer(commitment_invalid=True)

            self.log.info("A better branch retargets repair and retires the old designated peer")
            self._check_payload_repair_retargets_requested_peer()

            self.log.info("Operational and unmatched responses preserve the exact block for retry")
            # Keep the focused pre-DIP3 fixture below its first superblock;
            # every failed attempt must preserve this same indexed branch.
            self._check_connect_responses((
                b"error:queue-full", b"not connected", b"unknown", b"invalid", b"invalid:malformed",
                lambda request: self._invalid_response(request) + b":extra",
            ))

            # Typed but unbound identities are refused before transport recovery.
            self._check_connect_responses((
                lambda request: self._invalid_response(request, nevm_delta=1),
                lambda request: self._invalid_response(request, sys_delta=1),
            ), connects_per_attempt=1)

            self.log.info("A generic ack cannot negotiate typed connect results")
            self._check_connect_responses((b"connected",), protocol_response=b"ack")
            self.log.info("Only an invalid result bound to both requested hashes rejects the block")
            self._check_connect_responses((self._invalid_response,), consensus_invalid=True)

            # Managed Geth shutdown remains a clean daemon exit even though
            # Core now reports the unfinished connection as an operational error.
            self.extra_args[0].append("-gethcommandline=--exitwhensynced")
            self.restart_node(0, self.extra_args[0])
            force_finish_mnsync(self.nodes[0])
            address = self.nodes[0].getnewaddress()
            self._connect_response = b"not connected"
            assert_raises_rpc_error(
                -32603, "ProcessNewBlock, block not accepted",
                self.nodes[0].generatetoaddress, 1, address, invalid_call=False,
            )
            self.nodes[0].wait_until_stopped()

            self.log.info("Managed shutdown also exits when the connected engine disappears")
            self._connect_response = b"connected"
            self.restart_node(0, self.extra_args[0])
            node = self.nodes[0]
            force_finish_mnsync(node)
            # Prepare while the engine is available, then remove the actual
            # transport endpoint before submitting the valid candidate.
            block = self._build_block(node)
            raw = self._serialize_nevm_block(block, self._last_nevm_block_data).hex()
            self._stop_zmq_responder()
            with node.assert_debug_log(
                ["nevm-connect-not-sent", "Shutdown: done"],
                unexpected_msgs=["RestartGethNode:", "StartGethNode:", "Geth Started with pid"],
            ):
                assert_raises_rpc_error(-25, "nevm-connect-not-sent", node.submitblock, raw)
                node.wait_until_stopped()
        finally:
            self._stop_zmq_responder()


if __name__ == "__main__":
    FeatureNEVMConnectAfterConsensus().main()
