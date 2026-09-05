#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Catch up after real PQ authorization-certificate eviction.

The branch-bound snapshot helper supplies the same 400-member test population
as feature_pq_chainlocks.py. It does not supply accepted authorization state.
Every certificate has 801 real signatures and reaches the daemon through P2P.
The final assertions require successful catch-up, not rejection of the peer.
"""

import json
from pathlib import Path
import selectors
import shutil
import struct
import subprocess
import time

from feature_pq_chainlocks import (
    ACTIVE_QUORUMS,
    BTCC_CANDIDATE_ORIGIN,
    BTCC_CANDIDATE_PERIOD,
    CHAINLOCK_PERIOD,
    CHAINLOCK_STATEMENT_WIRE_SIZE,
    EPOCH_BLOCKS,
    EPOCH_ORIGIN,
    FIRST_ELIGIBLE_TARGET_HEIGHT,
    FUTURE_HORIZON_EPOCHS,
    PQChainLocksTest,
    QUORUM_SIZE,
    RECOVERY_ANCHOR_BTC_HEIGHT,
    RECOVERY_FUTURE_BTC_HASH,
    REQUIRED_QUORUMS,
    REGISTRATION_CUTOFF_BLOCKS,
    ROSTER_SNAPSHOT_LAG,
    SIGN_LAG,
)
from test_framework.authproxy import JSONRPCException
from test_framework.messages import MSG_CLSIG, msg_clsig, msg_getclsig
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.util import assert_equal, force_finish_mnsync, p2p_port


AUTHORIZATION_BASE_CAPACITY = 128
OUTAGE_RECOVERY_TARGET = 4615  # First usable recovery window here is epochs 8..11.
OUTAGE_STARTUP_HEIGHT = OUTAGE_RECOVERY_TARGET - SIGN_LAG
POST_RECOVERY_NORMAL_TARGET = OUTAGE_RECOVERY_TARGET + BTCC_CANDIDATE_PERIOD + SIGN_LAG
ROSTER_TRANSITION_OFFSET = struct.calcsize("<HHi32si32s32s")
ROSTER_CHANGING_TRANSITIONS = (2, 3, 4)  # OBSERVE, REVEAL, ROTATE


class CertificateProbe(P2PInterface):
    def __init__(self):
        super().__init__()
        self.certificate_inventory = set()

    def on_inv(self, message):
        self.certificate_inventory.update(
            inv.hash for inv in message.inv if inv.type == MSG_CLSIG)
        super().on_inv(message)


class PQPrunedSyncTest(PQChainLocksTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 4
        # Local peers share one two-upload network-group bucket. This test
        # exercises retained-authority validation, not bandwidth throttling.
        self.base_args.append("-whitelist=download@127.0.0.1")
        self.extra_args = [list(self.base_args) for _ in range(self.num_nodes)]

    def setup_network(self):
        # The other datadirs start empty; neither learns finality during setup.
        self.add_nodes(1, extra_args=[self.extra_args[0]])
        self.start_node(0)
        count = self.num_nodes
        self.num_nodes = 1
        self.import_deterministic_coinbase_privkeys()
        self.num_nodes = count

    def fixture_command(self, arguments):
        self.signer.stdin.write(" ".join(
            json.dumps(str(arg), ensure_ascii=False) for arg in arguments) + "\n")
        self.signer.stdin.flush()
        with selectors.DefaultSelector() as ready:
            ready.register(self.signer.stdout, selectors.EVENT_READ)
            assert ready.select(900 * self.options.timeout_factor), \
                "timed out generating real certificate fixture"
        result = self.signer.stdout.readline().strip()
        assert_equal(result, "OK")

    def fixture_args(self):
        return [arg for arg in self.extra_args[0]
                if not arg.startswith("-pqchainlocktestfixture=")]

    def install_snapshot(self, path):
        self.extra_args[0] = self.fixture_args() + [
            "-pqchainlocktestfixture=%s" % path]
        self.nodes[0].extra_args = list(self.extra_args[0])
        self.restart_node(0, extra_args=self.extra_args[0])
        self.nodes[0].spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        force_finish_mnsync(self.nodes[0])
        self.loaded_epoch = (self.nodes[0].getblockcount() - EPOCH_ORIGIN) // EPOCH_BLOCKS

    def remember(self, artifact, height):
        path = self.root / ("certificate-%d.dat" % height)
        path.write_bytes(artifact["certificate"])
        self.certificates[artifact["logical_hash"]] = (artifact, path)
        marker = "pruned-sync-%d" % height
        self.submit_expected_certificate(self.nodes[0], artifact, height, marker, 0xc100 + height)
        best = self.nodes[0].getbestchainlock()
        assert_equal(best["height"], height)
        assert_equal(best["blockhash"], self.nodes[0].getblockhash(height))
        assert_equal(best["witnessid"], "%064x" % artifact["witness_hash"])
        self.latest_certificate_path = path
        self.nodes[0].disconnect_p2ps()

    def receipt_at(self, height):
        # Authorization is anchored at target-sign_lag, whereas the statement
        # also commits receipt state at target. These can name different CLSIGs.
        carrier = height - (height - BTCC_CANDIDATE_ORIGIN) % BTCC_CANDIDATE_PERIOD
        while carrier >= FIRST_ELIGIBLE_TARGET_HEIGHT + BTCC_CANDIDATE_PERIOD:
            block_hash = self.nodes[0].getblockhash(carrier)
            _, receipt = self.read_btcc_receipt(block_hash)
            if receipt["logical_hash"]:
                return self.certificates[receipt["logical_hash"]][1], block_hash
            carrier -= BTCC_CANDIDATE_PERIOD
        raise AssertionError("missing non-null receipt at height %d" % height)

    def generate_initial(self, activation_predecessor):
        node = self.nodes[0]
        force_finish_mnsync(node)
        self.mine_pq_to_height(FIRST_ELIGIBLE_TARGET_HEIGHT + SIGN_LAG)
        self.genesis = node.getblockhash(0)
        self.branch_anchor = node.getblockhash(FIRST_ELIGIBLE_TARGET_HEIGHT)
        snapshot = self.root / "snapshots-initial.dat"
        bundle = self.root / "initial-bundle.dat"
        bases = [EPOCH_ORIGIN + epoch * EPOCH_BLOCKS for epoch in range(ACTIVE_QUORUMS)]
        self.log.info("Generating initial real 801-signature certificate")
        self.fixture_command([
            snapshot, bundle, self.genesis,
            FIRST_ELIGIBLE_TARGET_HEIGHT, self.branch_anchor,
            activation_predecessor["height"], activation_predecessor["blockHash"],
            self.payment_btcprev(FIRST_ELIGIBLE_TARGET_HEIGHT),
            RECOVERY_ANCHOR_BTC_HEIGHT, RECOVERY_FUTURE_BTC_HASH,
            EPOCH_ORIGIN, REGISTRATION_CUTOFF_BLOCKS,
            ROSTER_SNAPSHOT_LAG, FUTURE_HORIZON_EPOCHS,
            *[node.getblockhash(height) for height in bases],
            *[node.getblockhash(height - ROSTER_SNAPSHOT_LAG) for height in bases],
        ])
        self.install_snapshot(snapshot)
        artifact = self.read_full_dimension_bundle(bundle)
        self.remember(artifact, FIRST_ELIGIBLE_TARGET_HEIGHT)
        return artifact

    def generate_step(self, target):
        node = self.nodes[0]
        self.mine_pq_to_height(target + SIGN_LAG)
        epoch = (target + SIGN_LAG - EPOCH_ORIGIN) // EPOCH_BLOCKS
        bases = [EPOCH_ORIGIN + value * EPOCH_BLOCKS for value in range(epoch + 1)]
        authorizer, authorization_carrier = self.receipt_at(target - SIGN_LAG)
        state, state_carrier = self.receipt_at(target)
        snapshot = self.root / ("snapshots-%d.dat" % target)
        bundle = self.root / ("bundle-%d.dat" % target)
        self.fixture_command([
            "chainlock-step", snapshot, bundle, self.genesis,
            FIRST_ELIGIBLE_TARGET_HEIGHT, self.branch_anchor,
            EPOCH_ORIGIN, REGISTRATION_CUTOFF_BLOCKS,
            ROSTER_SNAPSHOT_LAG, FUTURE_HORIZON_EPOCHS,
            BTCC_CANDIDATE_ORIGIN, epoch, target - CHAINLOCK_PERIOD,
            node.getblockhash(target - CHAINLOCK_PERIOD), node.getblockhash(target),
            self.payment_btcprev(target), authorization_carrier,
            *[node.getblockhash(height) for height in bases],
            *[node.getblockhash(height - ROSTER_SNAPSHOT_LAG) for height in bases],
            authorizer, state, state_carrier, self.latest_certificate_path,
        ])
        if epoch != self.loaded_epoch:
            self.install_snapshot(snapshot)
        self.latest_snapshot = snapshot
        artifact = self.read_payment_audit_prefix_bundle(bundle)
        if (artifact["certificate"][ROSTER_TRANSITION_OFFSET]
                in ROSTER_CHANGING_TRANSITIONS and not self.is_btcc_candidate(target)):
            return None
        self.remember(artifact, target)
        return artifact

    def start_receiver(self, index, args):
        self.add_nodes(1, offset=index, extra_args=[args])
        self.start_node(index)
        receiver = self.nodes[index]
        receiver.spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        force_finish_mnsync(receiver)
        self.connect_nodes(index, 0)
        self.sync_blocks([self.nodes[0], receiver], timeout=180)
        force_finish_mnsync(receiver)
        # A certificate may arrive before its target block during replay.
        # Retry on a fresh connection so peer inventory suppression cannot
        # mask the authorization-retention case this test isolates.
        # The failed early fetch also has a two-minute source cooldown.
        receiver.setmocktime(int(time.time()) + 180)
        self.disconnect_nodes(index, 0)
        self.connect_nodes(index, 0)

    @staticmethod
    def best_id(node):
        try:
            return node.getbestchainlock()["logicalid"]
        except JSONRPCException as error:
            if error.error["code"] != -32603:
                raise
            return None

    def fetch_from_source(self, logical_hash=None):
        peer = self.nodes[0].add_p2p_connection(CertificateProbe())
        peer.send_and_ping(msg_getclsig(logical_hash), timeout=60)
        return peer

    def tick_receivers(self, receivers):
        now = int(time.time()) + 180
        for node in receivers:
            node.setmocktime(now)

    def generate_outage_snapshots(self):
        node = self.nodes[0]
        tip = OUTAGE_RECOVERY_TARGET + SIGN_LAG
        # The first recovery slot must open after synchronized signer startup;
        # starting at tip would correctly tombstone that already-open slot.
        self.mine_pq_to_height(OUTAGE_STARTUP_HEIGHT)
        epoch = (tip - EPOCH_ORIGIN) // EPOCH_BLOCKS
        assert_equal(epoch, 11)
        bases = [EPOCH_ORIGIN + value * EPOCH_BLOCKS for value in range(epoch + 1)]
        snapshot = self.root / "snapshots-outage.dat"
        self.operator_path = self.root / "outage-operator.json"
        self.fixture_command([
            "catchup-operator", snapshot, self.operator_path,
            "127.0.0.1:%d" % p2p_port(1), self.genesis,
            FIRST_ELIGIBLE_TARGET_HEIGHT, self.branch_anchor,
            EPOCH_ORIGIN, REGISTRATION_CUTOFF_BLOCKS,
            ROSTER_SNAPSHOT_LAG, FUTURE_HORIZON_EPOCHS, tip,
            node.getblockhash(OUTAGE_RECOVERY_TARGET - SIGN_LAG),
            *[node.getblockhash(height) for height in bases],
            *[node.getblockhash(height - ROSTER_SNAPSHOT_LAG) for height in bases],
        ])
        self.operator = json.loads(self.operator_path.read_text(encoding="utf8"))
        self.install_snapshot(snapshot)
        return list(self.extra_args[0])

    def assert_isolated_historical_restart(self, receiver_args, expected_id):
        fresh = self.nodes[2]
        target = fresh.getbestchainlock()["height"]
        coverage = target - SIGN_LAG
        _, carrier_hash = self.receipt_at(coverage)
        _, receipt = self.read_btcc_receipt(carrier_hash)
        self.log.info("Restart caught-up receiver without peers or a later receipt carrier")
        self.disconnect_nodes(2, 0)
        self.stop_node(2)
        with fresh.assert_debug_log([
                "imported PoW historical authority %064x" % receipt["logical_hash"],
                "through %d without advancing finality" % coverage,
        ], timeout=120):
            self.start_node(2, extra_args=receiver_args + ["-connect=0"])
            assert_equal(fresh.getpeerinfo(), [])
            force_finish_mnsync(fresh)
        assert_equal(fresh.getpeerinfo(), [])
        assert_equal(self.best_id(fresh), expected_id)
        assert_equal(fresh.getblockcount(), target + SIGN_LAG)

    def assert_outage_signing(self, initial_id, latest_id):
        self.log.info("No new certificates: roll to recovery epochs 8..11 and target %d",
                      OUTAGE_RECOVERY_TARGET)
        receiver_args = self.generate_outage_snapshots()
        assert_equal(self.best_id(self.nodes[0]), latest_id)
        self.log.info("Stale participant resumes; fresh receiver joins during the long outage")
        stale = self.nodes[1]
        cache_dir = stale.chain_path / "llmq" / "pq-child-key-trees"
        cache_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.operator["cache_path"], cache_dir / self.operator["cache_filename"])
        operator_args = receiver_args + self.btc_backend_args + [
            "-masternodeslhprivkey=%s" % self.operator["global_secret_key"],
            "-masternodechainlockseed=%s" % self.operator["chainlock_seed"],
        ]
        stale.extra_args = list(receiver_args)
        self.start_node(1, extra_args=receiver_args)
        assert_equal(self.best_id(stale), initial_id)
        self.connect_nodes(1, 0)
        self.sync_blocks([self.nodes[0], stale], timeout=180)
        force_finish_mnsync(stale)
        self.tick_receivers([stale])
        self.disconnect_nodes(1, 0)
        self.connect_nodes(1, 0)
        self.start_receiver(3, receiver_args)
        receivers = [stale, self.nodes[3]]
        # Regtest can finish mnsync automatically during block download.
        # Enable the local signer only at the fixed synchronized height so
        # its one-time startup floor cannot race an intermediate download tip.
        self.disconnect_nodes(1, 0)
        self.stop_node(1)
        stale.extra_args = list(operator_args)
        self.start_node(1, extra_args=operator_args)
        force_finish_mnsync(stale)
        self.connect_nodes(1, 0)
        startup_marker = "captured PQ signer startup tip height=%d proTxHash=%s" % (
            OUTAGE_STARTUP_HEIGHT, self.operator["pro_tx_hash"])

        def startup_captured():
            self.tick_receivers(receivers)
            return startup_marker in stale.debug_log_path.read_text(encoding="utf8")

        self.wait_until(startup_captured, timeout=180)
        assert_equal(stale.masternode_status()["state"], "READY")
        assert_equal(self.best_id(stale), initial_id)
        assert_equal(self.best_id(self.nodes[3]), None)
        self.log.info("Returning signer captured startup at %d; opening future recovery slot",
                      OUTAGE_STARTUP_HEIGHT)
        signature_offset = stale.debug_log_size(encoding="utf8")
        self.mine_pq_to_height(OUTAGE_RECOVERY_TARGET + SIGN_LAG)
        self.sync_blocks([self.nodes[0], *receivers], timeout=180)
        expected = "published PQ ChainLock signing context height=%d" % OUTAGE_RECOVERY_TARGET
        offsets = {node.index: 0 for node in receivers}
        published = set()

        def contexts_ready():
            self.tick_receivers(receivers)
            for node in receivers:
                if node.index in published:
                    continue
                with node.debug_log_path.open(encoding="utf8", errors="replace") as log:
                    log.seek(offsets[node.index])
                    if expected in log.read():
                        published.add(node.index)
                    offsets[node.index] = log.tell()
            return len(published) == len(receivers)

        try:
            self.wait_until(contexts_ready, timeout=180)
        finally:
            for node in receivers:
                self.log.info("Outage receiver %d: tip=%d finality=%s context_ready=%s",
                              node.index, node.getblockcount(), self.best_id(node),
                              node.index in published)
        shares = {}
        share_marker = "PQ fixture collected local share="

        def signatures_ready():
            nonlocal signature_offset
            self.tick_receivers(receivers)
            with stale.debug_log_path.open(encoding="utf8") as log:
                log.seek(signature_offset)
                for line in log.read().splitlines():
                    if share_marker not in line:
                        continue
                    payload = bytes.fromhex(line.split(share_marker, 1)[1].strip())
                    if struct.unpack_from("<i", payload, 4)[0] != OUTAGE_RECOVERY_TARGET:
                        continue
                    epoch = struct.unpack_from("<I", payload, CHAINLOCK_STATEMENT_WIRE_SIZE)[0]
                    previous = shares.setdefault(epoch, payload.hex())
                    assert_equal(previous, payload.hex())
                signature_offset = log.tell()
            return len(shares) == ACTIVE_QUORUMS

        self.wait_until(signatures_ready, timeout=180)
        assert_equal(sorted(shares), [8, 9, 10, 11])
        # These are public shares emitted only after real daemon signing and
        # collector verification, not signatures supplied by the helper.
        shares_path = self.root / "outage-local-shares.json"
        shares_path.write_text(json.dumps(list(shares.values())), encoding="utf8")
        assert_equal(self.best_id(stale), initial_id)
        assert_equal(self.best_id(self.nodes[3]), None)
        assert_equal(self.best_id(self.nodes[0]), latest_id)
        for node in receivers:
            assert_equal(node.getblockcount(), OUTAGE_RECOVERY_TARGET + SIGN_LAG)
            assert not node.getblockchaininfo()["initialblockdownload"]
        target_hash = stale.getblockhash(OUTAGE_RECOVERY_TARGET)
        self.disconnect_nodes(1, 0)
        self.stop_node(1)
        report_path = self.root / "outage-journal-verification.json"
        journal_args = [
            "verify-operator-journal", stale.chain_path / "llmq" / "pq-signer-journal",
            self.operator_path, self.genesis, OUTAGE_RECOVERY_TARGET, target_hash,
        ]
        self.fixture_command([*journal_args, shares_path, report_path])
        report = json.loads(report_path.read_text(encoding="utf8"))
        assert_equal(report["signed_slots"], ACTIVE_QUORUMS)
        assert_equal(report["epochs"], [8, 9, 10, 11])
        assert_equal(report["height"], OUTAGE_RECOVERY_TARGET)
        assert_equal(report["block_hash"], target_hash)
        assert_equal(report["pro_tx_hash"], self.operator["pro_tx_hash"])

        protected_report = stale.chain_path / "llmq" / "pq-signer-journal" / "CURRENT"
        current_contents = protected_report.read_bytes()
        rejected = subprocess.run(
            [str(self.helper), *map(str, journal_args), str(shares_path), str(protected_report)],
            capture_output=True, text=True, timeout=60)
        assert rejected.returncode != 0, "journal audit accepted a destructive report path"
        assert_equal(protected_report.read_bytes(), current_contents)

        # The audit must bind the signature to the exact public transcript,
        # not merely find some valid signature next to the target vote row.
        for label, offset in (("statement", 8), ("signature", -1)):
            changed = [bytes.fromhex(share) for share in shares.values()]
            corrupted = bytearray(changed[0])
            corrupted[offset] ^= 1
            changed[0] = bytes(corrupted)
            bad_path = self.root / ("outage-tampered-%s.json" % label)
            bad_path.write_text(json.dumps([share.hex() for share in changed]), encoding="utf8")
            rejected = subprocess.run(
                [str(self.helper), *map(str, journal_args), str(bad_path), str(report_path)],
                capture_output=True, text=True, timeout=60)
            assert rejected.returncode != 0, "journal audit accepted tampered %s" % label
        self.fixture_command([*journal_args, shares_path, report_path])
        self.log.info("Verified %d durable recovery signatures for target %d without a newer CLSIG",
                      report["signed_slots"], OUTAGE_RECOVERY_TARGET)
        self.assert_first_recovery_acceptance(
            shares_path, receiver_args, operator_args, journal_args, report_path, initial_id)

    def certificate_provider(self, node, marker, identity):
        peer = node.add_p2p_connection(P2PInterface(), uacomment=marker)
        peer.wait_for_verack()
        assert node.mnauth(self.peer_id(node, marker), "%064x" % identity,
                           "%064x" % 0x22, 1)
        return peer

    def submit_expected_certificate(self, node, artifact, target, marker, identity):
        expected = "%064x" % artifact["logical_hash"]
        busy = "CLSIG %s at %d deferred/rejected: pq-clsig-verifier-busy" % (expected, target)
        for attempt in range(4):
            offset = node.debug_log_size(encoding="utf8")
            peer = self.certificate_provider(node, "%s-%d" % (marker, attempt), identity + attempt)
            self.request_chainlock(peer, artifact["logical_hash"])
            peer.send_message(msg_clsig(artifact["certificate"]))

            def accepted_or_busy():
                if self.best_id(node) == expected:
                    return True
                with node.debug_log_path.open(encoding="utf8") as log:
                    log.seek(offset)
                    return busy in log.read()

            self.wait_until(accepted_or_busy, timeout=120)
            if self.best_id(node) == expected:
                return
            # Historical maintenance shares the bounded verifier. Only this
            # exact transient permits retry; a new peer avoids INV suppression.
            node.disconnect_p2ps()
        raise AssertionError("certificate verifier stayed busy for %s" % expected)

    def assert_exact_winner(self, node, artifact, target):
        best = node.getbestchainlock()
        assert_equal(best["logicalid"], "%064x" % artifact["logical_hash"])
        assert_equal(best["witnessid"], "%064x" % artifact["witness_hash"])
        assert_equal(best["height"], target)
        assert_equal(best["blockhash"], node.getblockhash(target))

    def assert_captured_shares_preserved(self, artifact, shares_path):
        captured = [bytes.fromhex(share) for share in
                    json.loads(shares_path.read_text(encoding="utf8"))]
        positions = [struct.unpack_from("<I32sH32s", share, CHAINLOCK_STATEMENT_WIRE_SIZE)
                     for share in captured]
        first_epoch = min(position[0] for position in positions)
        included = 0
        for share, (epoch, _, member, _) in zip(captured, positions):
            assert_equal(share[:CHAINLOCK_STATEMENT_WIRE_SIZE],
                         artifact["certificate"][:CHAINLOCK_STATEMENT_WIRE_SIZE])
            compact = (artifact["logical_hash"].to_bytes(32, "little")
                       + struct.pack("<H", (epoch - first_epoch) * QUORUM_SIZE + member)
                       + share[CHAINLOCK_STATEMENT_WIRE_SIZE + struct.calcsize("<I32sH32s"):])
            included += compact in artifact["shares"]
        # The helper verifies all four transcripts. The wire certificate
        # selects three quorum thresholds, preserving their three local shares.
        assert_equal(included, REQUIRED_QUORUMS)

    def assert_first_recovery_acceptance(
            self, shares_path, receiver_args, operator_args, journal_args, report_path, initial_id):
        fresh = self.nodes[3]
        authorizer, _ = self.receipt_at(OUTAGE_RECOVERY_TARGET - SIGN_LAG)
        bundle = self.root / "outage-complete-bundle.dat"
        self.log.info("Completing the four daemon recovery shares into a real 801-signature certificate")
        self.fixture_command([
            "catchup-complete", shares_path, authorizer, BTCC_CANDIDATE_ORIGIN, bundle])
        recovery = self.read_full_dimension_bundle(bundle)
        assert_equal(recovery["certificate"][ROSTER_TRANSITION_OFFSET], 5)
        self.assert_captured_shares_preserved(recovery, shares_path)
        assert_equal(self.best_id(fresh), None)
        self.disconnect_nodes(3, 0)

        # A bad witness for the exact authorized statement must neither install
        # finality nor undo the returning operator's durable one-time burns.
        bad = bytearray(recovery["certificate"])
        bad[-1] ^= 1
        provider = self.certificate_provider(fresh, "first-recovery-invalid", 0xc901)
        self.request_chainlock(provider, recovery["logical_hash"])
        with fresh.assert_debug_log(["pq-clsig-invalid-signatures"], timeout=120):
            provider.send_message(msg_clsig(bytes(bad)))
        assert_equal(self.best_id(fresh), None)
        self.fixture_command([*journal_args, shares_path, report_path])
        assert_equal(json.loads(report_path.read_text(encoding="utf8"))["signed_slots"],
                     ACTIVE_QUORUMS)
        fresh.disconnect_p2ps()

        self.log.info("Fresh receiver accepts RECOVER as its first durable winner, not the imported base")
        self.submit_expected_certificate(
            fresh, recovery, OUTAGE_RECOVERY_TARGET, "first-recovery-valid", 0xc902)
        self.assert_exact_winner(fresh, recovery, OUTAGE_RECOVERY_TARGET)
        fresh.disconnect_p2ps()
        self.stop_node(3)
        self.start_node(3, extra_args=receiver_args + ["-connect=0"])
        assert_equal(fresh.getpeerinfo(), [])
        force_finish_mnsync(fresh)
        self.wait_until(lambda: self.best_id(fresh) == "%064x" % recovery["logical_hash"],
                        timeout=120)
        self.assert_exact_winner(fresh, recovery, OUTAGE_RECOVERY_TARGET)
        assert_equal(fresh.getblockcount(), OUTAGE_RECOVERY_TARGET + SIGN_LAG)
        assert_equal(fresh.getpeerinfo(), [])

        self.remember(recovery, OUTAGE_RECOVERY_TARGET)
        # Deliver the state edge while it is still above the returning node's
        # frozen prefix. A later historical import cannot stand in for D.
        stale = self.nodes[1]
        with stale.assert_debug_log(["imported PoW historical authority"], timeout=120):
            self.start_node(1, extra_args=receiver_args + ["-connect=0"])
            force_finish_mnsync(stale)
            self.tick_receivers([stale])
        assert_equal(stale.getpeerinfo(), [])
        assert_equal(self.best_id(stale), initial_id)
        self.submit_expected_certificate(
            stale, recovery, OUTAGE_RECOVERY_TARGET, "returning-recovery-valid", 0xc910)
        self.assert_exact_winner(stale, recovery, OUTAGE_RECOVERY_TARGET)
        stale.disconnect_p2ps()
        self.stop_node(1)
        self.assert_post_recovery_normal_round(recovery, operator_args)

    def assert_post_recovery_normal_round(self, recovery, operator_args):
        target = POST_RECOVERY_NORMAL_TARGET
        self.mine_pq_to_height(target - SIGN_LAG)
        authorizer, carrier = self.receipt_at(target - SIGN_LAG)
        _, receipt = self.read_btcc_receipt(carrier)
        assert_equal(receipt["logical_hash"], recovery["logical_hash"])
        snapshot = self.root / "snapshots-post-recovery.dat"
        self.fixture_command([
            "catchup-extend", snapshot, target + SIGN_LAG,
            self.nodes[0].getblockhash(target - SIGN_LAG)])
        self.install_snapshot(snapshot)
        receiver_args = list(self.extra_args[0])
        operator_args = [arg for arg in operator_args
                         if not arg.startswith("-pqchainlocktestfixture=")] + [
                             "-pqchainlocktestfixture=%s" % snapshot]
        fresh, stale = self.nodes[3], self.nodes[1]
        self.stop_node(3)
        self.start_node(3, extra_args=receiver_args)
        self.start_node(1, extra_args=receiver_args)
        for index in (1, 3):
            self.connect_nodes(index, 0)
        receivers = [stale, fresh]
        self.sync_blocks([self.nodes[0], *receivers], timeout=180)
        for node in receivers:
            force_finish_mnsync(node)
        self.disconnect_nodes(1, 0)
        self.stop_node(1)
        self.start_node(1, extra_args=operator_args)
        force_finish_mnsync(stale)
        self.connect_nodes(1, 0)
        startup_marker = "captured PQ signer startup tip height=%d proTxHash=%s" % (
            target - SIGN_LAG, self.operator["pro_tx_hash"])

        def startup_ready():
            self.tick_receivers(receivers)
            return startup_marker in stale.debug_log_path.read_text(encoding="utf8")

        self.wait_until(startup_ready, timeout=180)
        self.wait_until(lambda: self.best_id(stale) == "%064x" % recovery["logical_hash"],
                        timeout=120)
        offset = stale.debug_log_size(encoding="utf8")
        self.log.info("Recovery receipt selects ordinary signing for target %d", target)
        self.mine_pq_to_height(target + SIGN_LAG)
        self.sync_blocks([self.nodes[0], *receivers], timeout=180)
        shares = {}
        marker = "PQ fixture collected local share="

        def normal_shares_ready():
            nonlocal offset
            self.tick_receivers(receivers)
            with stale.debug_log_path.open(encoding="utf8") as log:
                log.seek(offset)
                for line in log.read().splitlines():
                    if marker not in line:
                        continue
                    payload = bytes.fromhex(line.split(marker, 1)[1].strip())
                    if struct.unpack_from("<i", payload, 4)[0] != target:
                        continue
                    assert payload[ROSTER_TRANSITION_OFFSET] not in (0, 5)
                    epoch = struct.unpack_from("<I", payload, CHAINLOCK_STATEMENT_WIRE_SIZE)[0]
                    assert_equal(shares.setdefault(epoch, payload.hex()), payload.hex())
                offset = log.tell()
            return len(shares) == ACTIVE_QUORUMS

        self.wait_until(normal_shares_ready, timeout=180)
        assert_equal(sorted(shares), [8, 9, 10, 11])
        shares_path = self.root / "post-recovery-local-shares.json"
        shares_path.write_text(json.dumps(list(shares.values())), encoding="utf8")
        bundle = self.root / "post-recovery-complete-bundle.dat"
        self.fixture_command([
            "catchup-complete", shares_path, authorizer, BTCC_CANDIDATE_ORIGIN, bundle])
        normal = self.read_full_dimension_bundle(bundle)
        assert normal["certificate"][ROSTER_TRANSITION_OFFSET] not in (0, 5)
        self.assert_captured_shares_preserved(normal, shares_path)
        self.remember(normal, target)
        for node in receivers:
            self.wait_until(lambda: self.best_id(node) == "%064x" % normal["logical_hash"],
                            timeout=120)
            self.assert_exact_winner(node, normal, target)

    def run_scenario(self):
        _, predecessor = self.configure_private_migration()
        initial = self.generate_initial(predecessor)

        self.log.info("Positive control: fresh receiver authenticates available initial certificate")
        receiver_args = list(self.extra_args[0])
        self.start_receiver(1, receiver_args)
        self.wait_until(lambda: self.best_id(self.nodes[1]) == "%064x" % initial["logical_hash"],
                        timeout=120)
        self.stop_node(1)

        # Wait until the first receipt is visible at the authorization lookback.
        target = FIRST_ELIGIBLE_TARGET_HEIGHT + 3 * CHAINLOCK_PERIOD
        count = 1
        while count < AUTHORIZATION_BASE_CAPACITY + 9:
            assert target + SIGN_LAG < EPOCH_ORIGIN + 6 * EPOCH_BLOCKS
            artifact = self.generate_step(target)
            if artifact is None:
                target += CHAINLOCK_PERIOD
                continue
            latest = artifact
            count += 1
            if count % 16 == 0:
                self.log.info("Accepted %d distinct certificates; latest target %d", count, target)
            # A new roster decision must reach its receipt-selected authority
            # anchor before the next statement can build on that decision.
            # These deliberately unpublished rounds do not alter the wire cadence.
            if artifact["certificate"][ROSTER_TRANSITION_OFFSET] in ROSTER_CHANGING_TRANSITIONS:
                target += BTCC_CANDIDATE_PERIOD + SIGN_LAG
            else:
                target += CHAINLOCK_PERIOD

        self.log.info("Checking actual GETCLSIG eviction, including the authorization archive")
        old = self.fetch_from_source(initial["logical_hash"])
        with p2p_lock:
            assert initial["logical_hash"] not in old.certificate_inventory, \
                "initial certificate has not actually been evicted"
            assert "clsig" not in old.last_message
        newest = self.fetch_from_source(latest["logical_hash"])
        newest.wait_until(lambda: newest.message_count["clsig"] > 0, timeout=120)
        assert_equal(newest.last_message["clsig"].payload, latest["certificate"])
        self.nodes[0].disconnect_p2ps()

        self.log.info("Fresh receiver joins after eviction; no finality DB or verified base is supplied")
        receiver_args = self.fixture_args() + ["-pqchainlocktestfixture=%s" % self.latest_snapshot]
        self.start_receiver(2, receiver_args)
        expected = "%064x" % latest["logical_hash"]
        self.log.info("Base blocks synced to %s; expecting authenticated finality %s",
                      self.nodes[2].getbestblockhash(), expected)

        fresh = self.nodes[2]
        self.wait_until(lambda: self.best_id(fresh) == expected or any(
            peer.get("bytesrecv_per_msg", {}).get("clsig", 0)
            >= len(latest["certificate"]) for peer in fresh.getpeerinfo()), timeout=60)
        last_clock_update = 0

        def finality_caught_up():
            nonlocal last_clock_update
            now = int(time.time())
            if now != last_clock_update:
                # Expiring the early-fetch cooldown must not freeze later
                # ordinary retry deadlines while waiting for authentication.
                self.tick_receivers([self.nodes[2]])
                last_clock_update = now
            return self.best_id(self.nodes[2]) == expected

        try:
            self.wait_until(finality_caught_up, timeout=180)
        finally:
            self.log.info("Receiver %d: tip=%d finality=%s IBD=%s", fresh.index,
                          fresh.getblockcount(), self.best_id(fresh),
                          fresh.getblockchaininfo()["initialblockdownload"])
        assert not self.nodes[2].getblockchaininfo()["initialblockdownload"]
        self.assert_isolated_historical_restart(receiver_args, expected)
        self.stop_node(2)
        self.assert_outage_signing("%064x" % initial["logical_hash"], expected)

    def run_test(self):
        self.root = Path(self.options.tmpdir)
        self.certificates = {}
        helper = Path(self.config["environment"]["BUILDDIR"]) / "src/test" / (
            "pq_chainlock_fixture" + self.config["environment"]["EXEEXT"])
        self.helper = helper
        with (self.root / "fixture-stream.log").open("w", encoding="utf8") as errors:
            self.signer = subprocess.Popen([str(helper), "stream"], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=errors,
                                           text=True, bufsize=1)
            try:
                self.run_scenario()
            finally:
                self.signer.stdin.close()
                self.signer.wait(timeout=30)
                self.signer.stdout.close()


if __name__ == "__main__":
    PQPrunedSyncTest().main()
