#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Black-box contract test for the pinned managed Bitcoin header helper."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sha256d(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def compact_target(bits):
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        raise AssertionError("negative compact target")
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def mine_header(previous_hash, previous_time, bits, marker):
    timestamp = max(previous_time + 1, int(time.time()))
    target = compact_target(bits)
    merkle_root = hashlib.sha256(f"syscoin-btcheader-{marker}".encode()).digest()
    for nonce in range(0x100000000):
        header = (
            struct.pack("<I", 4)
            + bytes.fromhex(previous_hash)[::-1]
            + merkle_root
            + struct.pack("<III", timestamp, bits, nonce)
        )
        digest = sha256d(header)
        if int.from_bytes(digest, "little") <= target:
            return header.hex(), digest[::-1].hex(), timestamp
    raise AssertionError("regtest header nonce space exhausted")


class HeaderNode:
    def __init__(self, bitcoind, bitcoin_cli, datadir):
        self.bitcoind = str(bitcoind)
        self.bitcoin_cli = str(bitcoin_cli)
        self.datadir = Path(datadir)
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        self.process = None
        self.stderr = None

    def command(self, *args, timeout=10):
        command = [
            self.bitcoin_cli,
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcport={self.rpc_port}",
            *map(str, args),
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def start(self):
        self.datadir.mkdir(parents=True, exist_ok=True)
        stderr_path = self.datadir / "child-stderr.log"
        self.stderr = stderr_path.open("ab")
        self.process = subprocess.Popen(
            [
                self.bitcoind,
                "-regtest",
                "-headersonly=1",
                # The patch must override this hostile later value.
                "-blocksonly=0",
                "-server=1",
                "-daemon=0",
                "-listen=0",
                "-dnsseed=0",
                "-discover=0",
                f"-datadir={self.datadir}",
                f"-port={self.p2p_port}",
                f"-rpcport={self.rpc_port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self.stderr,
        )
        deadline = time.monotonic() + 30
        last_error = "RPC unavailable"
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"bitcoind exited with {self.process.returncode}")
            try:
                self.command("getblockchaininfo", timeout=2)
                return
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                last_error = str(error)
                time.sleep(0.1)
        raise RuntimeError(f"timed out waiting for helper RPC: {last_error}")

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.command("stop")
            except (RuntimeError, subprocess.TimeoutExpired):
                self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.process = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None


def run_contract(bitcoind, bitcoin_cli):
    with tempfile.TemporaryDirectory(prefix="syscoin-btcheader-contract-") as root:
        node = HeaderNode(bitcoind, bitcoin_cli, root)
        try:
            node.start()
            chain_info = node.command("getblockchaininfo")
            assert chain_info["chain"] == "regtest"
            assert chain_info["headersonly"] is True

            network_info = node.command("getnetworkinfo")
            assert "NETWORK" not in network_info["localservicesnames"]
            assert "NETWORK_LIMITED" not in network_info["localservicesnames"]

            genesis_hash = node.command("getblockhash", 0)
            previous_hash = genesis_hash
            previous_header = node.command("getblockheader", previous_hash, "true")
            previous_time = previous_header["time"]
            bits = int(previous_header["bits"], 16)
            submitted = []
            for marker in range(1, 7):
                raw, block_hash, previous_time = mine_header(
                    previous_hash, previous_time, bits, marker
                )
                node.command("submitheader", raw)
                submitted.append(block_hash)
                previous_hash = block_hash

            chain_info = node.command("getblockchaininfo")
            assert chain_info["headers"] == 6
            assert chain_info["blocks"] == 6
            assert chain_info["bestblockhash"] == submitted[-1]
            assert chain_info["initialblockdownload"] is False
            assert node.command("getblockhash", 3) == submitted[2]

            ancestor = node.command("getblockheader", submitted[2], "true")
            assert ancestor["height"] == 3
            assert ancestor["confirmations"] == 4
            tip = node.command("getblockheader", submitted[-1], "true")
            assert tip["height"] == 6
            assert tip["confirmations"] == 1
            chain_tips = node.command("getchaintips")
            assert any(
                entry["hash"] == submitted[-1]
                and entry["height"] == 6
                and entry["status"] == "active"
                for entry in chain_tips
            )

            # A shorter competing header branch must remain visible but never
            # gain optimistic active-chain confirmations.
            fork_parent = node.command("getblockheader", submitted[2], "true")
            fork_previous = submitted[2]
            fork_time = fork_parent["time"]
            fork_hashes = []
            for marker in (101, 102):
                raw, fork_hash, fork_time = mine_header(
                    fork_previous, fork_time, bits, marker
                )
                node.command("submitheader", raw)
                fork_hashes.append(fork_hash)
                fork_previous = fork_hash
            fork_header = node.command("getblockheader", fork_hashes[-1], "true")
            assert fork_header["height"] == 5
            assert fork_header["confirmations"] < 0
            assert any(
                entry["hash"] == fork_hashes[-1]
                and entry["height"] == 5
                and entry["status"] != "active"
                for entry in node.command("getchaintips")
            )

            node.stop()
            node.start()
            assert node.command("getblockhash", 3) == submitted[2]
            assert node.command("getblockchaininfo")["bestblockhash"] == submitted[-1]

            debug_log = (Path(root) / "regtest" / "debug.log").read_text(
                encoding="utf8", errors="replace"
            )
            assert "enforcing -blocksonly=1 (override=1)" in debug_log
        finally:
            node.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoind", required=True, type=Path)
    parser.add_argument("--bitcoin-cli", required=True, type=Path)
    args = parser.parse_args()
    if not args.bitcoind.is_file() or not args.bitcoin_cli.is_file():
        parser.error("both helper binaries must exist")
    run_contract(args.bitcoind, args.bitcoin_cli)
    print("btcheadernode headers-only RPC contract: PASS")


if __name__ == "__main__":
    main()
