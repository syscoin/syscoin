#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise real external/managed Bitcoin-header policy under the PQ profile.

The production profile fixes each active roster at 400 members and finalizes at
267 shares. This four-node functional deliberately does not weaken those
constants or inject certificates. It covers miner policy, Bitcoin fork/reorg
handling, backend lifecycle, raw BTCPREV binding, restart continuity, and the
fail-closed NEVM/null-receipt path. Sentry ADVANCE/KEEP policy decisions are
covered with full contexts by the C++ BTC policy and ChainLock handler tests.
"""

import json
import os
from io import BytesIO
from pathlib import Path
import shutil
import struct
import subprocess
import time
from threading import Event, Thread

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.auxpow import reverseHex
from test_framework.auxpow_testing import computeAuxpow
from test_framework.messages import (
    CAuxPow,
    CBlock,
    CNEVMBlock,
    CNEVMBlockConnect,
    from_hex,
    ser_uint256,
    uint256_from_compact,
)
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import DashTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    force_finish_mnsync,
)

try:
    import zmq
except ImportError:
    pass


class ExternalBitcoinRegtestNode:
    def __init__(self, *, name, bitcoind, bitcoin_cli, datadir,
                 p2p_port, rpc_port, addnode_port=None):
        self.name = name
        self.bitcoind = bitcoind
        self.bitcoin_cli = bitcoin_cli
        self.datadir = Path(datadir)
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.addnode_port = addnode_port
        self.proc = None

    def _cli(self, *args, timeout_s=30):
        command = [
            self.bitcoin_cli,
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcport={self.rpc_port}",
            *[str(arg) for arg in args],
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout_s)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"{self.name}: bitcoin-cli timed out: {error}") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(
                f"{self.name}: bitcoin-cli failed: {detail}")
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def _debug_log_tail(self, lines=40):
        log_path = self.datadir / "regtest" / "debug.log"
        if not log_path.exists():
            return "<debug.log not found>"
        with log_path.open("r", encoding="utf8", errors="replace") as log:
            return "".join(log.readlines()[-lines:]).strip()

    def start(self):
        self.datadir.mkdir(parents=True, exist_ok=True)
        command = [
            self.bitcoind,
            "-regtest",
            "-server=1",
            "-discover=0",
            "-dnsseed=0",
            "-listen=1",
            "-fallbackfee=0.0001",
            f"-datadir={self.datadir}",
            f"-bind=127.0.0.1:{self.p2p_port}",
            f"-port={self.p2p_port}",
            f"-rpcport={self.rpc_port}",
        ]
        if self.addnode_port is not None:
            command.append(f"-addnode=127.0.0.1:{self.addnode_port}")
        self.proc = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        deadline = time.time() + 30
        last_error = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name}: bitcoind exited {self.proc.returncode}\n"
                    f"{self._debug_log_tail()}")
            try:
                self._cli("getblockchaininfo", timeout_s=2)
                return
            except RuntimeError as error:
                last_error = error
                time.sleep(0.2)
        raise RuntimeError(
            f"{self.name}: Bitcoin RPC startup timed out: {last_error}\n"
            f"{self._debug_log_tail()}")

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self._cli("stop")
            except Exception:
                pass
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.proc = None

    def mine(self, blocks, descriptor="raw(51)"):
        # SYSCOIN: the bundled headers-only helper intentionally has no wallet.
        return self._cli("generatetodescriptor", blocks, descriptor)

    def set_network_active(self, active):
        return self._cli("setnetworkactive", "true" if active else "false")

    def rpc(self, *args):
        return self._cli(*args)


class ZMQNEVMResponder:
    def __init__(self, log, context, address):
        self.log = log
        self.context = context
        self.address = address
        self.btcprev_by_sys_hash = {}
        self.running = True
        self.ready = Event()
        self.error = None
        self.counter = 1
        self.thread = Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(timeout=10):
            raise RuntimeError("Timed out starting NEVM ZMQ responder")
        if self.error is not None:
            raise RuntimeError("Failed to start NEVM ZMQ responder") from self.error

    def stop(self):
        self.running = False
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("Timed out stopping NEVM ZMQ responder")
        if self.error is not None:
            raise RuntimeError("NEVM ZMQ responder failed") from self.error

    def _loop(self):
        socket = None
        try:
            # SYSCOIN: ZeroMQ sockets are thread-affine; bind and use this REP
            # socket exclusively in the worker.
            socket = self.context.socket(zmq.REP)
            socket.setsockopt(zmq.RCVTIMEO, 1000)
            socket.setsockopt(zmq.SNDTIMEO, 1000)
            socket.bind(self.address)
            self.ready.set()
            while self.running:
                try:
                    message = socket.recv_multipart()
                except zmq.Again:
                    continue
                if not message:
                    continue
                topic = message[0]
                payload = message[1] if len(message) > 1 else b""
                if topic == b"nevmcomms":
                    socket.send_multipart([topic, b"ack"])
                elif topic == b"nevmblock":
                    value = self.counter
                    self.counter += 1
                    block = CNEVMBlock()
                    block.nBlockHash = value
                    block.nTxRoot = value
                    block.nReceiptRoot = value
                    block.vchNEVMBlockData = b"feature_btcheader_policy_auxpow"
                    socket.send_multipart([topic, block.serialize()])
                elif topic == b"nevmblockinfo":
                    # No external child chain is attached in this fixture.
                    # The paired Syscoin hash is null when the applied count is 0.
                    socket.send_multipart([topic, b"0", b"0" * 64])
                elif topic == b"nevmconnect":
                    connect = CNEVMBlockConnect()
                    connect.deserialize(BytesIO(payload))
                    self.btcprev_by_sys_hash[connect.sysblockhash] = (
                        connect.btcprevhash)
                    socket.send_multipart([topic, b"connected"])
                elif topic == b"nevmdisconnect":
                    socket.send_multipart([topic, b"disconnected"])
                else:
                    self.log.info("Unknown NEVM ZMQ topic: %s", topic)
                    socket.send_multipart([topic, b"ack"])
        except Exception as error:
            self.error = error
            self.ready.set()
        finally:
            if socket is not None:
                socket.close(linger=0)


class BTCHeaderPolicyAuxpowTest(DashTestFramework):
    # SYSCOIN: The random-receipt quarantine case needs an eligible ChainLock
    # target; pre-warmup BTCPREV candidates can only carry null receipts.
    BTC_CANDIDATE_ORIGIN = 2305
    FINALITY_ANCHOR_HEIGHT = 2304
    BTC_CANDIDATE_PERIOD = 10
    BTCC_NEVM_LAG = 10
    BTC_MINE_DESC_NODE0 = "raw(51)"
    BTC_MINE_DESC_NODE1 = "raw(52)"

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # Mining through the four-epoch ChainLock warmup can exceed the default
        # per-request timeout on slower functional-test hosts.
        self.rpc_timeout = 240
        self.set_dash_test_params(4, 3, fast_dip3_enforcement=True)
        self.btc_nodes = []
        self.bitcoind_path = None
        self.bitcoin_cli_path = None
        self.external_btc_p2p_ports = None
        self.external_btc_rpc_ports = None
        self.zmq_context = None
        self.nevm_responder = None
        self.zmq_address = None
        self.managed_node_cfg = {}
        self.allocated_ports = set()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py3_zmq()
        self.skip_if_no_syscoind_zmq()
        self.bitcoind_path, self.bitcoin_cli_path = (
            self._resolve_bitcoin_binaries())
        if self.bitcoind_path is None or self.bitcoin_cli_path is None:
            raise SkipTest(
                "bitcoind and bitcoin-cli are required for "
                "feature_btcheader_policy_auxpow.py")

    def _resolve_bitcoin_binaries(self):
        build_dir = self.config["environment"]["BUILDDIR"]
        node_candidates = [
            # SYSCOIN: This functional exercises the patched managed contract;
            # prefer the bundled helper over an unrelated PATH bitcoind.
            os.path.join(
                build_dir, "src", "bin", "btcheadernode", "bin", "bitcoind"),
            os.getenv("BITCOIND"),
            shutil.which("bitcoind"),
        ]
        cli_candidates = [
            os.path.join(
                build_dir, "src", "bin", "btcheadernode", "bin", "bitcoin-cli"),
            os.getenv("BITCOINCLI"),
            shutil.which("bitcoin-cli"),
        ]
        executable = lambda path: (
            path and os.path.isfile(path) and os.access(path, os.X_OK))
        for node_path in node_candidates:
            if not executable(node_path):
                continue
            try:
                help_result = subprocess.run(
                    [node_path, "-help"], capture_output=True, text=True,
                    timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if help_result.returncode != 0 or "-headersonly" not in help_result.stdout:
                continue
            cli_path = next(
                (path for path in cli_candidates if executable(path)), None)
            if cli_path is not None:
                return node_path, cli_path
        return None, None

    def _alloc_free_port(self):
        import socket
        # SYSCOIN: macOS can immediately recycle the same ephemeral port after
        # a probe socket closes. Keep allocations unique within this fixture.
        for _ in range(64):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            if port not in self.allocated_ports:
                self.allocated_ports.add(port)
                return port
        raise RuntimeError("Unable to allocate a unique loopback port")

    def _start_external_btc_network(self):
        base = Path(self.options.tmpdir) / "external_btc"
        base.mkdir(parents=True, exist_ok=True)
        if self.external_btc_p2p_ports is None:
            self.external_btc_p2p_ports = [
                self._alloc_free_port(), self._alloc_free_port()]
        if self.external_btc_rpc_ports is None:
            self.external_btc_rpc_ports = [
                self._alloc_free_port(), self._alloc_free_port()]
        p2p0, p2p1 = self.external_btc_p2p_ports
        rpc0, rpc1 = self.external_btc_rpc_ports
        self.btc_nodes = [
            ExternalBitcoinRegtestNode(
                name="btc0", bitcoind=self.bitcoind_path,
                bitcoin_cli=self.bitcoin_cli_path, datadir=base / "node0",
                p2p_port=p2p0, rpc_port=rpc0, addnode_port=p2p1),
            ExternalBitcoinRegtestNode(
                name="btc1", bitcoind=self.bitcoind_path,
                bitcoin_cli=self.bitcoin_cli_path, datadir=base / "node1",
                p2p_port=p2p1, rpc_port=rpc1, addnode_port=p2p0),
        ]
        for node in self.btc_nodes:
            node.start()
        self._wait_for_btc_sync()

    def _stop_external_btc_network(self):
        for node in reversed(self.btc_nodes):
            node.stop()
        self.btc_nodes = []

    def _start_nevm_responder(self):
        self.zmq_address = f"tcp://127.0.0.1:{self._alloc_free_port()}"
        self.zmq_context = zmq.Context()
        self.nevm_responder = ZMQNEVMResponder(
            self.log, self.zmq_context, self.zmq_address)
        self.nevm_responder.start()

    def _stop_nevm_responder(self):
        if self.nevm_responder is not None:
            self.nevm_responder.stop()
            self.nevm_responder = None
        if self.zmq_context is not None:
            self.zmq_context.destroy(linger=0)
            self.zmq_context = None

    def configure_pq_migration_anchor(self):
        assert_equal(self.nodes[0].getblockcount(), 0)
        self.bump_mocktime(1, nodes=[self.nodes[0]])
        self.generatetoaddress(
            self.nodes[0], 1, self.nodes[0].getnewaddress(),
            sync_fun=self.no_op)
        migration_anchor = self.nodes[0].protx_migration_info()
        assert_equal(migration_anchor["height"], 1)
        profile_args = [
            f'-pqlegacyanchorheight={migration_anchor["height"]}',
            f'-pqlegacyanchorblockhash={migration_anchor["blockHash"]}',
            f'-pqlegacydmnstatehash={migration_anchor["dmnStateHash"]}',
            f'-pqlegacypqregistrystatehash={migration_anchor["pqRegistryStateHash"]}',
            "-pqpreparationheight=1",
            "-pqchainlockepochorigin=1440",
            "-pqregistrationcutoffblocks=288",
            "-pqrostersnapshotlag=288",
            "-pqfuturehorizonepochs=8",
        ]

        # SYSCOIN: build the provider/roster history first. No finality store
        # exists in this explicit preparation state, so the exact bootstrap
        # predecessor can be learned without circular quorum authorization.
        preparation_args = (
            self.extra_args[0] + profile_args + ["-pqfinalitypreparation=1"])
        self.stop_node(0)
        self.nodes[0].extra_args = list(preparation_args)
        self.start_node(0, extra_args=preparation_args + ["-reindex"])
        force_finish_mnsync(self.nodes[0])
        self.generatetoaddress(
            self.nodes[0],
            self.FINALITY_ANCHOR_HEIGHT - self.nodes[0].getblockcount(),
            self.nodes[0].getnewaddress(), sync_fun=self.no_op)
        finality_anchor = {
            "height": self.FINALITY_ANCHOR_HEIGHT,
            "blockHash": self.nodes[0].getblockhash(
                self.FINALITY_ANCHOR_HEIGHT),
        }

        pq_args = profile_args + [
            f'-pqchainlockanchorheight={finality_anchor["height"]}',
            f'-pqchainlockanchorblockhash={finality_anchor["blockHash"]}',
            f"-pqbtcccandidateorigin={self.BTC_CANDIDATE_ORIGIN}",
            # SYSCOIN: This independent boundary is before the first carrier,
            # so the authenticated receipt state is canonically empty.
            f'-pqbtccreceiptanchorheight={finality_anchor["height"]}',
            f'-pqbtccreceiptanchorblockhash={finality_anchor["blockHash"]}',
            "-pqbtccreceiptanchorcursorheight=-1",
            f'-pqbtccreceiptanchorcursorsyshash={"0" * 64}',
            f'-pqbtccreceiptanchorcursorbtchash={"0" * 64}',
            f'-pqbtccreceiptanchorstatehash={"0" * 64}',
        ]
        for args in self.extra_args:
            args.extend(pq_args)
        self.stop_node(0)
        self.nodes[0].extra_args = list(self.extra_args[0])
        self.start_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        force_finish_mnsync(self.nodes[0])
        assert_equal(
            self.nodes[0].getblockhash(migration_anchor["height"]),
            migration_anchor["blockHash"])
        tip_state = self.nodes[0].protx_migration_info()
        assert_equal(tip_state["height"], finality_anchor["height"])
        assert_equal(tip_state["blockHash"], finality_anchor["blockHash"])
        assert_equal(
            self.nodes[0].getblockhash(finality_anchor["height"]),
            finality_anchor["blockHash"])

    def setup_network(self):
        self._start_nevm_responder()
        self._start_external_btc_network()
        btc0 = self.btc_nodes[0]
        for args in self.extra_args:
            args.extend([
                # SYSCOIN: pass a fixed executable and literal argv entries;
                # the policy runner never invokes a shell.
                "-btcheadermanaged=0",
                f"-btcheadercmd={self.bitcoin_cli_path}",
                "-btcheaderarg=-regtest",
                f"-btcheaderarg=-datadir={btc0.datadir}",
                f"-btcheaderarg=-rpcport={btc0.rpc_port}",
                "-btcheaderpolicyondemand=1",
                "-btcheaderwatchdog=1",
                "-btcheaderwatchdogprobeinterval=1",
                "-btcheaderwatchdogstalltimeout=300",
                "-btcheaderwatchdogreindexafter=2",
                "-btcheadertipmaxage=0",
                "-btcheadermaxlagblocks=36",
                "-btcheaderrecentforkdepth=2",
                "-debug=chainlocks",
                "-nevmstartheight=1",
                "-gethcommandline=--miner.pendingfeerecipient="
                "0x00000000000000000000000000000000000000aa",
            ])
        self.extra_args[0].append(f"-zmqpubnevm={self.zmq_address}")
        super().setup_network()

    def wait_for_sporks_same(self, timeout=180):
        # SYSCOIN: this fixture starts three depth-16 child-key cache builders
        # concurrently. On bounded CI hosts their initial public-cache builds
        # can outlive the framework's ordinary 30-second spork deadline even
        # though P2P remains healthy; retain a finite deadline without reducing
        # production tree geometry.
        return super().wait_for_sporks_same(timeout=timeout)

    def shutdown(self):
        try:
            return super().shutdown()
        finally:
            self._stop_external_btc_network()
            self._stop_nevm_responder()

    def _strip_btcheader_args(self, args):
        prefixes = (
            "-btcheadermanaged", "-btcheadercmd", "-btcheaderarg",
            "-btcheaderbinary", "-btcheaderclibinary",
            "-btcheaderdatadir", "-btcheaderport", "-btcheaderrpcport",
            "-btcheadercommandline", "-btcheaderpolicyondemand",
            "-btcheaderwatchdog", "-btcheaderwatchdogprobeinterval",
            "-btcheaderwatchdogrestartcooldown",
            "-btcheaderwatchdogstalltimeout",
            "-btcheaderwatchdogreindexafter",
            "-btcheadertipmaxage", "-btcheadertipmaxnoprogress",
            "-btcheadermaxlagblocks", "-btcheaderrecentforkdepth",
            "-mocktime",
        )
        return [
            arg for arg in args
            if not any(arg.startswith(prefix) for prefix in prefixes)]

    def _enable_managed_btcheader_on_node(self, node_index):
        p2p_port = self._alloc_free_port()
        rpc_port = self._alloc_free_port()
        data_dir = (Path(self.nodes[node_index].chain_path) /
                    "btcheader managed test")
        data_dir.mkdir(parents=True, exist_ok=True)
        args = self._strip_btcheader_args(self.extra_args[node_index])
        args.extend([
            "-btcheadermanaged=1",
            f"-btcheaderbinary={self.bitcoind_path}",
            f"-btcheaderclibinary={self.bitcoin_cli_path}",
            f"-btcheaderdatadir={data_dir}",
            f"-btcheaderport={p2p_port}",
            f"-btcheaderrpcport={rpc_port}",
            f"-btcheadercommandline=-bind=127.0.0.1:{p2p_port}",
            f"-btcheadercommandline=-connect=127.0.0.1:"
            f"{self.btc_nodes[0].p2p_port}",
            "-btcheaderpolicyondemand=1",
            "-btcheaderwatchdog=1",
            "-btcheaderwatchdogprobeinterval=1",
            "-btcheaderwatchdogrestartcooldown=4",
            "-btcheaderwatchdogstalltimeout=8",
            "-btcheaderwatchdogreindexafter=2",
            "-btcheadertipmaxnoprogress=60",
            "-btcheadertipmaxage=0",
            "-btcheadermaxlagblocks=36",
            "-btcheaderrecentforkdepth=2",
        ])
        self.extra_args[node_index] = args
        self.restart_node(node_index, extra_args=args)
        # SYSCOIN: the controller initiates toward the sentry so its identity
        # is authenticated on the controller's outbound connection.
        self.connect_nodes(0, node_index, wait_for_connect=False)
        for peer_index in range(1, self.num_nodes):
            if peer_index != node_index:
                self.connect_nodes(node_index, peer_index,
                                   wait_for_connect=False)
        self.sync_all()
        force_finish_mnsync(self.nodes[node_index])
        self.managed_node_cfg[node_index] = {
            "rpc_port": rpc_port,
            "datadir": data_dir,
        }
        return self._wait_for_managed_chaininfo(node_index)

    def _managed_cli(self, node_index, *args, timeout=20):
        config = self.managed_node_cfg[node_index]
        command = [
            self.bitcoin_cli_path,
            "-regtest",
            f'-datadir={config["datadir"]}',
            f'-rpcport={config["rpc_port"]}',
            *[str(arg) for arg in args],
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(
                "managed bitcoin-cli failed: " +
                (result.stderr.strip() or result.stdout.strip()))
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def _wait_for_managed_chaininfo(self, node_index, timeout=60):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                info = self._managed_cli(
                    node_index, "getblockchaininfo", timeout=2)
                if (isinstance(info, dict)
                        and info.get("headersonly") is True
                        and info.get("bestblockhash")
                        == self.btc_nodes[0].rpc("getbestblockhash")
                        and info.get("initialblockdownload") is False):
                    return info
            except Exception as error:
                last_error = error
            time.sleep(0.25)
        raise RuntimeError(
            f"Managed Bitcoin RPC did not become ready: {last_error}")

    def _wait_for_btc_sync(self):
        self.wait_until(
            lambda: self.btc_nodes[0].rpc("getbestblockhash") ==
                    self.btc_nodes[1].rpc("getbestblockhash"),
            timeout=60)

    def _set_btc_network_active(self, active):
        for node in self.btc_nodes:
            node.set_network_active(active)

    def _btc_active_confirmed_hash(self):
        height = self.btc_nodes[0].rpc("getblockcount")
        block_hash = self.btc_nodes[0].rpc(
            "getblockhash", max(0, height - 1))
        header = self.btc_nodes[0].rpc(
            "getblockheader", block_hash, "true")
        assert header["confirmations"] >= 2
        return block_hash

    def _btc_far_older_confirmed_hash(self):
        height = self.btc_nodes[0].rpc("getblockcount")
        block_hash = self.btc_nodes[0].rpc(
            "getblockhash", max(0, height - 50))
        header = self.btc_nodes[0].rpc(
            "getblockheader", block_hash, "true")
        assert header["confirmations"] >= 50
        return block_hash

    def _btc_has_recent_fork(self):
        height = self.btc_nodes[0].rpc("getblockcount")
        return any(
            tip.get("status") in ("valid-fork", "valid-headers", "headers-only")
            and tip.get("height", -1) >= height - 2
            for tip in self.btc_nodes[0].rpc("getchaintips"))

    def _create_recent_fork(self):
        self._wait_for_btc_sync()
        self._set_btc_network_active(False)
        self.wait_until(
            lambda: all(node.rpc("getconnectioncount") == 0
                        for node in self.btc_nodes),
            timeout=30)
        self.btc_nodes[0].mine(2, self.BTC_MINE_DESC_NODE0)
        self.btc_nodes[1].mine(2, self.BTC_MINE_DESC_NODE1)
        self._set_btc_network_active(True)
        self.btc_nodes[0].rpc(
            "addnode", f"127.0.0.1:{self.btc_nodes[1].p2p_port}", "onetry")
        self.wait_until(self._btc_has_recent_fork, timeout=60)

    def _cool_down_recent_fork(self):
        self.btc_nodes[0].mine(3)
        self._wait_for_btc_sync()
        self.wait_until(lambda: not self._btc_has_recent_fork(), timeout=60)

    def _create_stale_hash(self):
        self._wait_for_btc_sync()
        self._set_btc_network_active(False)
        self.wait_until(
            lambda: all(node.rpc("getconnectioncount") == 0
                        for node in self.btc_nodes),
            timeout=30)
        self.btc_nodes[0].mine(2, self.BTC_MINE_DESC_NODE0)
        stale_hash = self.btc_nodes[0].rpc("getbestblockhash")
        self.btc_nodes[1].mine(5, self.BTC_MINE_DESC_NODE1)
        self._set_btc_network_active(True)
        self.btc_nodes[0].rpc(
            "addnode", f"127.0.0.1:{self.btc_nodes[1].p2p_port}", "onetry")
        self._wait_for_btc_sync()
        header = self.btc_nodes[0].rpc(
            "getblockheader", stale_hash, "true")
        assert header["confirmations"] < 1
        return stale_hash

    def _next_candidate_height(self):
        height = self.nodes[0].getblockcount() + 1
        if height <= self.BTC_CANDIDATE_ORIGIN:
            return self.BTC_CANDIDATE_ORIGIN
        offset = height - self.BTC_CANDIDATE_ORIGIN
        return height + (-offset % self.BTC_CANDIDATE_PERIOD)

    def _mine_to_candidate_parent(self):
        candidate_height = self._next_candidate_height()
        count = candidate_height - 1 - self.nodes[0].getblockcount()
        if count > 0:
            self.generatetoaddress(
                self.nodes[0], count,
                self.nodes[0].get_deterministic_priv_key().address)
            self.sync_blocks()
        assert_equal(self.nodes[0].getblockcount(), candidate_height - 1)
        return candidate_height

    def _mine_candidate(self, requested_btcprev=None):
        candidate_height = self._mine_to_candidate_parent()
        address = self.nodes[0].get_deterministic_priv_key().address
        template = (
            self.nodes[0].createauxblock(address)
            if requested_btcprev is None
            else self.nodes[0].createauxblock(address, requested_btcprev))
        assert_equal(template["height"], candidate_height)
        expected = (self.btc_nodes[0].rpc("getbestblockhash")
                    if requested_btcprev is None else requested_btcprev)
        assert_equal(template["_btcprevhash"], expected)
        auxpow = computeAuxpow(
            template["hash"], reverseHex(template["_target"]), True,
            template["coinbasescript"], expected)
        assert_equal(
            self.nodes[0].submitauxblock(template["hash"], auxpow), True)
        self.sync_blocks()
        return template

    def _assert_raw_btcprev_binding(self, block_hash, expected_btcprev):
        raw_block = self.nodes[0].getblock(block_hash, 0)
        block = from_hex(CBlock(), raw_block)
        assert block.auxpow is not None
        assert_equal(
            block.auxpow.parentBlock.hashPrevBlock,
            int(expected_btcprev, 16))
        commitment = b"btcp" + bytes.fromhex(expected_btcprev)[::-1]
        assert_equal(sum(
            bytes(output.scriptPubKey).count(commitment)
            for output in block.vtx[0].vout), 1)
        return raw_block

    @staticmethod
    def _coinbase_commitment_data(block):
        for output in block.vtx[0].vout:
            operations = list(CScript(output.scriptPubKey).raw_iter())
            if not operations or operations[0][0] != OP_RETURN:
                continue
            pushes = [data for _, data, _ in operations[1:]]
            if pushes and all(data is not None for data in pushes):
                return output, pushes
        raise AssertionError("coinbase commitment output not found")

    def _attach_auxpow(self, block, previous_height, btcprev_hash):
        block.mark_auxpow()
        block.auxpow = None
        block.rehash()
        target = ("%064x" % uint256_from_compact(block.nBits)).encode()
        auxpow_height = previous_height - 5
        auxpow_height -= auxpow_height % 10
        auxpow_tag_hash = self.nodes[0].getblockhash(auxpow_height)
        auxpow_script = CScript([
            OP_RETURN,
            b"sys" + bytes.fromhex(auxpow_tag_hash)[::-1]
            + struct.pack("<I", auxpow_height),
        ])
        encoded = computeAuxpow(
            block.hash, target, True, auxpow_script.hex(), btcprev_hash)
        block.auxpow = CAuxPow()
        block.auxpow.deserialize(BytesIO(bytes.fromhex(encoded)))

    def _exercise_missing_receipt_candidate_yield(self, source, canonical):
        """A random receipt ID must not pin an already-known valid sibling."""
        node = self.nodes[0]
        carrier_height = canonical["height"]
        assert_equal(carrier_height, source["height"] + self.BTCC_NEVM_LAG)
        canonical_hash = canonical["hash"]
        canonical_raw = bytes.fromhex(node.getblock(canonical_hash, 0))
        canonical_stream = BytesIO(canonical_raw)
        canonical_block = CBlock()
        canonical_block.deserialize(canonical_stream)
        assert canonical_block.is_nevm()
        nevm_sidecar_wire = canonical_stream.read()
        assert nevm_sidecar_wire
        malicious_stream = BytesIO(canonical_raw)
        malicious = CBlock()
        malicious.deserialize(malicious_stream)
        assert_equal(malicious_stream.read(), nevm_sidecar_wire)
        commitment_output, pushes = self._coinbase_commitment_data(malicious)
        extra = pushes[-1]
        btcp_offset = extra.rfind(b"btcp")
        receipt_offset = btcp_offset - (4 + 138)
        assert btcp_offset >= 0
        assert receipt_offset >= 0
        assert_equal(extra[receipt_offset:receipt_offset + 4], b"btcr")
        assert_equal(extra[btcp_offset + 4:],
                     ser_uint256(int(canonical["_btcprevhash"], 16)))

        source_height = source["height"]
        source_hash = int(source["hash"], 16)
        source_btcprev = int(source["_btcprevhash"], 16)
        arbitrary_logical_id = int("a5" * 32, 16)
        receipt = (
            struct.pack("<Hi", 1, source_height)
            + ser_uint256(source_hash)
            + ser_uint256(arbitrary_logical_id)
            + struct.pack("<i", source_height)
            + ser_uint256(source_hash)
            + ser_uint256(source_btcprev)
        )
        assert_equal(len(receipt), 138)
        modified_extra = (
            extra[:receipt_offset] + b"btcr" + receipt
            + extra[btcp_offset:]
        )
        commitment_output.scriptPubKey = CScript(
            [OP_RETURN, *pushes[:-1], modified_extra])
        malicious.vtx[0].rehash()
        malicious.hashMerkleRoot = malicious.calc_merkle_root()
        malicious.nNonce = (malicious.nNonce + 1) & 0xffffffff
        self._attach_auxpow(
            malicious, carrier_height - 1, canonical["_btcprevhash"])
        assert malicious.hash != canonical_hash

        node.invalidateblock(canonical_hash)
        parent_hash = "%064x" % canonical_block.hashPrevBlock
        assert_equal(node.getbestblockhash(), parent_hash)
        with node.assert_debug_log([
                "pq-btcc-receipt-certificate-pending",
                "deferred 1 candidate(s)",
        ]):
            assert_raises_rpc_error(
                -25, "pq-btcc-receipt-certificate-pending",
                node.submitblock,
                (malicious.serialize() + nevm_sidecar_wire).hex())
        assert_equal(node.getbestblockhash(), parent_hash)

        # reconsiderblock repopulates both candidates. The production work
        # selector must skip the quarantined random-ID branch and activate the
        # equally worked canonical null-receipt sibling immediately.
        node.reconsiderblock(canonical_hash)
        assert_equal(node.getbestblockhash(), canonical_hash)
        self.sync_blocks()

    def _wait_for_zmq_btcprev(self, height):
        sys_hash = int(self.nodes[0].getblockhash(height), 16)
        self.wait_until(
            lambda: sys_hash in self.nevm_responder.btcprev_by_sys_hash,
            timeout=60)
        return self.nevm_responder.btcprev_by_sys_hash[sys_hash]

    def _assert_no_chainlock_winner(self):
        assert_equal(len(self.nodes[0].masternode_list("status")), 3)
        for node in self.nodes:
            assert_raises_rpc_error(
                -32603, "Unable to find any ChainLock",
                node.getbestchainlock)
            assert_raises_rpc_error(
                -32603, "Unable to find any chainlock",
                node.getchainlocks)

    def _exercise_managed_lifecycle(self):
        node_index = 1
        info = self._enable_managed_btcheader_on_node(node_index)
        assert info.get("headersonly") is True

        status = self.nodes[node_index].syscoinbtcheaderstatus()
        assert status["process_running"]
        assert status["policy_healthy"]
        assert status["ready"]
        owner_path = (
            self.managed_node_cfg[node_index]["datadir"] /
            ".syscoin-btcheader-owner.json")
        with owner_path.open("r", encoding="utf8") as owner_file:
            owner_before = json.load(owner_file)
        progress_before = (
            owner_before["last_tip_height"],
            owner_before["last_tip_hash"],
            owner_before["last_progress_time"],
        )
        assert progress_before[0] >= 0
        assert progress_before[1] != "0" * 64
        assert progress_before[2] > 0

        self.nodes[node_index].syscoinstopbtcheadernode()
        with owner_path.open("r", encoding="utf8") as owner_file:
            stopped_owner = json.load(owner_file)
        assert_equal(stopped_owner["pid"], -1)
        assert_equal(
            (stopped_owner["last_tip_height"],
             stopped_owner["last_tip_hash"],
             stopped_owner["last_progress_time"]),
            progress_before)
        time.sleep(0.5)
        self.nodes[node_index].syscoinstartbtcheadernode()
        restarted = self._wait_for_managed_chaininfo(node_index)
        assert restarted.get("headersonly") is True
        assert self.nodes[node_index].syscoinbtcheaderstatus()["ready"]
        with owner_path.open("r", encoding="utf8") as owner_file:
            owner_after_child_restart = json.load(owner_file)
        assert_equal(
            (owner_after_child_restart["last_tip_height"],
             owner_after_child_restart["last_tip_hash"],
             owner_after_child_restart["last_progress_time"]),
            progress_before)

        # SYSCOIN: A full syscoind restart at an expired wall time must restore
        # the same observation and remain fail-closed; process restart is not a
        # new eclipse/no-progress allowance.
        expired_time = progress_before[2] + 61
        restart_args = [
            arg for arg in self.extra_args[node_index]
            if not arg.startswith("-mocktime=")
        ]
        restart_args.append(f"-mocktime={expired_time}")
        self.extra_args[node_index] = restart_args
        self.restart_node(node_index, extra_args=restart_args)
        expired_status = self.nodes[node_index].syscoinbtcheaderstatus()
        assert not expired_status["policy_healthy"]
        assert not expired_status["ready"]
        assert "btcheader-tip-no-progress" in expired_status["reason"]
        with owner_path.open("r", encoding="utf8") as owner_file:
            owner_after_syscoin_restart = json.load(owner_file)
        assert_equal(
            (owner_after_syscoin_restart["last_tip_height"],
             owner_after_syscoin_restart["last_tip_hash"],
             owner_after_syscoin_restart["last_progress_time"]),
            progress_before)

        self.btc_nodes[0].mine(1)
        self._wait_for_btc_sync()
        self._wait_for_managed_chaininfo(node_index)
        self.wait_until(
            lambda: self.nodes[node_index].syscoinbtcheaderstatus()["ready"],
            timeout=60)

    def run_test(self):
        for node in self.nodes:
            force_finish_mnsync(node)

        self.log.info("Bootstrap a real Bitcoin regtest header chain")
        self.btc_nodes[0].mine(60)
        self._wait_for_btc_sync()

        self.log.info("Auto-select and bind the first scheduled BTCPREV")
        first = self._mine_candidate()
        first_btcprev = first["_btcprevhash"]
        raw_first = self._assert_raw_btcprev_binding(
            first["hash"], first_btcprev)

        self.log.info("Restart preserves the accepted raw candidate and policy")
        self.restart_node(0, extra_args=self.extra_args[0])
        for peer_index in range(1, self.num_nodes):
            self.connect_nodes(0, peer_index, wait_for_connect=False)
        self.sync_all()
        force_finish_mnsync(self.nodes[0])
        assert_equal(self.nodes[0].getblock(first["hash"], 0), raw_first)
        self._assert_raw_btcprev_binding(first["hash"], first_btcprev)

        self.log.info("External backend outage fails closed, then recovers")
        outage_height = self._mine_to_candidate_parent()
        self._stop_external_btc_network()
        assert_raises_rpc_error(
            -1, "BTCPREV unavailable", self.nodes[0].createauxblock,
            self.nodes[0].get_deterministic_priv_key().address)
        self._start_external_btc_network()
        recovered = self._mine_candidate()
        assert_equal(recovered["height"], outage_height)

        self.log.info(
            "A first-seen random-ID BTCC carrier yields to its valid sibling")
        self._exercise_missing_receipt_candidate_yield(first, recovered)

        # The candidate at H is receipted at H+10. With only three registered
        # operators there is no 400-member roster or 267-share CLSIG, so the
        # carrier is canonically null and NEVM must see no unauthenticated BTC hash.
        assert_equal(
            self._wait_for_zmq_btcprev(
                first["height"] + self.BTCC_NEVM_LAG),
            0)
        self._assert_no_chainlock_winner()

        self.log.info("Reject a policy-stale but active Bitcoin hash")
        old_hash = self._btc_far_older_confirmed_hash()
        self._mine_to_candidate_parent()
        assert_raises_rpc_error(
            -1, "btc-candidate-too-old", self.nodes[0].createauxblock,
            ADDRESS_BCRT1_UNSPENDABLE, old_hash)
        self._mine_candidate(self._btc_active_confirmed_hash())

        self.log.info("Pause on a recent Bitcoin fork, then recover")
        self._mine_to_candidate_parent()
        self._create_recent_fork()
        assert_raises_rpc_error(
            -1, "btc-recent-fork", self.nodes[0].createauxblock,
            ADDRESS_BCRT1_UNSPENDABLE)
        self._cool_down_recent_fork()
        self._mine_candidate()

        self.log.info("Reject an orphaned Bitcoin hash after a real reorg")
        self._mine_to_candidate_parent()
        stale_hash = self._create_stale_hash()
        assert_raises_rpc_error(
            -1, "btc-candidate-unconfirmed", self.nodes[0].createauxblock,
            ADDRESS_BCRT1_UNSPENDABLE, stale_hash)
        self._mine_candidate()

        self.log.info("Exercise bundled managed headers-only stop/start")
        self._exercise_managed_lifecycle()
        self._assert_no_chainlock_winner()


if __name__ == "__main__":
    BTCHeaderPolicyAuxpowTest().main()
