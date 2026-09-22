#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise managed Bitcoin watchdog escalation without a Bitcoin installation."""

import json
import os
from pathlib import Path
import signal
import time

from test_framework.test_framework import SkipTest, SyscoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port


# Both executables use the managed argv/cookie contract. Only the transport is
# replaced: the daemon still owns, authenticates, stops, and reaps real children.
BACKEND = r'''#!/usr/bin/env python3
import fcntl
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import time


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp." + str(os.getpid()))
    temporary.write_text(json.dumps(value), encoding="utf8")
    os.replace(temporary, path)


def record(value):
    encoded = (json.dumps(value) + "\n").encode("utf8")
    descriptor = os.open(data_dir / "events.jsonl",
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        assert os.write(descriptor, encoded) == len(encoded)
    finally:
        os.close(descriptor)


options = {}
positional = []
for argument in sys.argv[1:]:
    if argument.startswith("-"):
        name, separator, value = argument.partition("=")
        assert name not in options
        options[name] = value if separator else "1"
    else:
        positional.append(argument)
assert options["-regtest"] == "1"
data_dir = Path(options["-datadir"])
network_dir = data_dir / "regtest"
endpoint_path = network_dir / "endpoint.json"
cookie_path = network_dir / ".cookie"

if Path(sys.argv[0]).name == "bitcoin-cli":
    assert set(options) == {"-datadir", "-rpcport", "-regtest"}
    assert len(positional) == 1
    try:
        endpoint = json.loads(endpoint_path.read_text(encoding="utf8"))
        assert endpoint["rpc_port"] == options["-rpcport"]
        assert cookie_path.read_text(encoding="utf8") == endpoint["cookie"]
        os.kill(endpoint["pid"], 0)
    except (OSError, ValueError, AssertionError):
        sys.exit("managed endpoint is not available")

    method = positional[0]
    if method == "getblockchaininfo":
        state = json.loads((data_dir / "state.json").read_text(encoding="utf8"))
        now = time.monotonic()
        delay = endpoint["first_probe_delay"]
        if delay and "first_probe_time" not in endpoint:
            # Managed startup already waits for the process to survive. Arm
            # warmup on its first RPC probe so this exercises the later retry.
            endpoint["first_probe_time"] = now
            write_json(endpoint_path, endpoint)
        ready = (not state.get("rpc_unavailable", False) and
                 now >= endpoint.get("first_probe_time", now) + delay)
        if state.get("record_probes", False):
            record({"event": "probe", "pid": endpoint["pid"],
                    "comment": endpoint["comment"], "ready": ready,
                    "time": now})
        if not ready:
            sys.exit("managed endpoint is not ready")
        result = {
            "chain": "regtest",
            "headersonly": True,
            "initialblockdownload": state["ibd"],
            "headers": state["height"],
            "blocks": state["height"],
            "bestblockhash": state["hash"],
        }
    elif method == "getnetworkinfo":
        result = {"subversion": "/watchdog-test:" + endpoint["comment"] + "/"}
        record({"event": "authenticated", "pid": endpoint["pid"],
                "comment": endpoint["comment"]})
    elif method == "stop":
        write_json(network_dir / "stop.json", {
            "pid": endpoint["pid"], "cookie": endpoint["cookie"],
            "comment": endpoint["comment"],
        })
        record({"event": "stop-request", "pid": endpoint["pid"],
                "comment": endpoint["comment"]})
        result = "stopping"
    else:
        sys.exit("unsupported method: " + method)
    print(json.dumps(result))
    sys.exit(0)

assert not positional
assert options["-headersonly"] == "1"
assert options["-blocksonly"] == "1"
assert options["-server"] == "1"
assert options["-daemon"] == "0"
assert options["-uacomment"].startswith("syscoinbtcc_")
network_dir.mkdir(exist_ok=True)
lock_file = (network_dir / ".lock").open("a", encoding="utf8")
fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
cookie = "__cookie__:" + secrets.token_hex(32)
cookie_path.write_text(cookie, encoding="utf8")
cookie_path.chmod(0o600)
state = json.loads((data_dir / "state.json").read_text(encoding="utf8"))
endpoint = {
    "pid": os.getpid(), "rpc_port": options["-rpcport"],
    "comment": options["-uacomment"], "cookie": cookie,
    "first_probe_delay": state.get("first_probe_delay", 0),
}
write_json(endpoint_path, endpoint)
record({"event": "start", "pid": os.getpid(), "argv": sys.argv[1:],
        "comment": endpoint["comment"],
        "reindex": options.get("-reindex") == "1"})
stop_reason = None


def on_signal(signum, frame):
    global stop_reason
    stop_reason = "signal:" + str(signum)


signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)
try:
    while stop_reason is None:
        try:
            request = json.loads((network_dir / "stop.json").read_text(encoding="utf8"))
            if request == {"pid": os.getpid(), "cookie": cookie,
                           "comment": endpoint["comment"]}:
                stop_reason = "authenticated-stop"
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
finally:
    # A stopped endpoint must disappear before the parent can try adoption.
    endpoint_path.unlink()
    cookie_path.unlink()
    record({"event": "exit", "pid": os.getpid(), "reason": stop_reason})
'''


class BTCHeaderWatchdogTest(SyscoinTestFramework):
    PROBE_INTERVAL = 3600
    STALL_TIMEOUT = 20
    RESTART_COOLDOWN = 10
    STARTUP_GRACE = 30
    REINDEX_AFTER = 2

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The key-generation RPC needs the wallet module, but no loaded wallet.
        self.extra_args = [["-disablewallet=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if not self.is_wallet_compiled():
            raise SkipTest("PQ operator key-generation RPC requires wallet support")
        if not self.config["components"].getboolean(
                "ENABLE_BTC_HEADER_COMMAND", fallback=False):
            raise SkipTest("Boost.Process Bitcoin header backend unavailable")

    def setup_chain(self):
        super().setup_chain()
        self.backend_dir = Path(self.options.tmpdir) / "managed Bitcoin watchdog"
        self.backend_dir.mkdir(mode=0o700)
        for name in ("bitcoind", "bitcoin-cli"):
            executable = self.backend_dir / name
            executable.write_text(BACKEND, encoding="utf8")
            executable.chmod(0o700)
        self.state = {"ibd": False, "height": 100, "hash": "11" * 32}
        self.write_state()
        self.now = int(time.time())
        self.extra_args[0].append(f"-mocktime={self.now}")

    def write_state(self):
        replacement = self.backend_dir / "state.tmp"
        replacement.write_text(json.dumps(self.state), encoding="utf8")
        os.replace(replacement, self.backend_dir / "state.json")

    def events(self, event=None):
        with (self.backend_dir / "events.jsonl").open(encoding="utf8") as source:
            entries = [json.loads(line) for line in source]
        return [entry for entry in entries
                if event is None or entry["event"] == event]

    def assert_owner_progress(self, expected):
        with (self.backend_dir / ".syscoin-btcheader-owner.json").open(
                encoding="utf8") as source:
            owner = json.load(source)
        assert_equal((owner["last_tip_height"], owner["last_tip_hash"],
                      owner["last_progress_time"]), expected)
        launches = self.events("start")
        assert_equal(owner["pid"], launches[-1]["pid"])
        assert all(entry["comment"] == owner["comment"] for entry in launches)

    def advance_time(self, seconds):
        self.now += seconds
        self.nodes[0].setmocktime(self.now)

    def assert_stalled_status(self):
        status = self.nodes[0].syscoinbtcheaderstatus()
        assert status["managed"]
        assert status["process_running"]
        assert not status["policy_healthy"]
        assert not status["ready"]
        assert "ibd-stalled" in status["reason"]

    def scheduler_probe(self, expected_reason):
        node = self.nodes[0]
        with node.assert_debug_log([
                "Bitcoin header policy backend is not ready;",
                expected_reason,
        ], unexpected_msgs=[
                "btcheader-watchdog-restart-failed",
                "btcheader-watchdog-rpc-unreachable-after-restart",
                "refusing RPC stop for an unauthenticated managed endpoint",
                "forcing owned Bitcoin header pid",
        ], timeout=30):
            node.mockscheduler(self.PROBE_INTERVAL)
        # The callback must finish and requeue its next probe before advancing
        # the scheduler again; a child launch alone does not provide that fence.
        node.syncwithvalidationinterfacequeue()

    def restart_stalled_backend(self, expected_reindexes, progress):
        self.scheduler_probe("btcheader-watchdog-restarted-stalled-backend")
        assert_equal([entry["reindex"] for entry in self.events("start")],
                     expected_reindexes)
        self.assert_stalled_status()
        self.assert_owner_progress(progress)
        assert all(entry["reason"] == "authenticated-stop"
                   for entry in self.events("exit"))

    def check_restarted_child_warmup(self):
        node = self.nodes[0]
        self.log.info("One stopped-child restart retries through brief RPC warmup")
        self.advance_time(self.RESTART_COOLDOWN)
        self.state.update(ibd=False, height=102, hash="33" * 32,
                          first_probe_delay=0.7, rpc_unavailable=False,
                          record_probes=True)
        self.write_state()
        starts = len(self.events("start"))
        stops = len(self.events("stop-request"))
        exits = len(self.events("exit"))
        probes_before = len(self.events("probe"))
        with node.assert_debug_log([
                "Bitcoin header watchdog restarted managed child",
        ], unexpected_msgs=[
                "btcheader-watchdog-restart-cooldown",
                "btcheader-watchdog-rpc-unreachable-after-restart",
                "btcheader-watchdog-restart-failed",
                "forcing owned Bitcoin header pid",
        ], timeout=30):
            node.mockscheduler(self.PROBE_INTERVAL)
            node.syncwithvalidationinterfacequeue()

        # Inspect this scheduler invocation before status can supply a later
        # successful probe and conceal a skipped retry in the watchdog.
        launch = self.events("start")[-1]
        probes = self.events("probe")[probes_before:]
        assert_equal(len(self.events("start")), starts + 1)
        assert_equal(len(self.events("stop-request")), stops)
        assert_equal(len(self.events("exit")), exits)
        assert not launch["reindex"]
        assert 2 <= len(probes) <= 11, probes
        assert all(probe["pid"] == launch["pid"] and
                   probe["comment"] == launch["comment"] for probe in probes)
        assert all(not probe["ready"] for probe in probes[:-1]), probes
        assert probes[-1]["ready"], probes
        assert probes[-1]["time"] - probes[0]["time"] >= 0.7, probes
        status = node.syscoinbtcheaderstatus()
        assert status["process_running"]
        assert status["policy_healthy"]
        assert status["ready"]
        self.assert_owner_progress((self.state["height"], self.state["hash"], self.now))
        node.syscoinstopbtcheadernode()
        assert_equal(self.events("exit")[-1]["pid"], launch["pid"])
        assert_equal(self.events("exit")[-1]["reason"], "authenticated-stop")

    def assert_unready_status(self):
        status = self.nodes[0].syscoinbtcheaderstatus()
        assert status["process_running"]
        assert not status["policy_healthy"]
        assert not status["ready"]
        assert "chaininfo" not in status
        assert "btcheader-watchdog-startup-pending" in status["reason"]

    def restart_unready_backend(self, previous_launch=None):
        node = self.nodes[0]
        self.state.update(first_probe_delay=0, rpc_unavailable=True,
                          record_probes=True)
        self.write_state()
        starts = len(self.events("start"))
        stops = len(self.events("stop-request"))
        exits = len(self.events("exit"))
        probes_before = len(self.events("probe"))
        started = time.monotonic()
        with node.assert_debug_log([
                "Bitcoin header watchdog restarted managed child",
                "btcheader-watchdog-rpc-unreachable-after-restart",
        ], unexpected_msgs=[
                "btcheader-watchdog-restart-cooldown",
                "btcheader-watchdog-startup-pending",
                "btcheader-watchdog-restart-failed",
                "forcing owned Bitcoin header pid",
        ], timeout=30):
            node.mockscheduler(self.PROBE_INTERVAL)
            node.syncwithvalidationinterfacequeue()
        elapsed = time.monotonic() - started
        assert elapsed < 30, f"Unavailable replacement blocked watchdog for {elapsed:.2f}s"
        launch = self.events("start")[-1]
        probes = self.events("probe")[probes_before:]
        assert_equal(len(self.events("start")), starts + 1)
        assert_equal(len(self.events("stop-request")), stops)
        assert not launch["reindex"]
        if previous_launch is None:
            assert_equal(len(self.events("exit")), exits)
            # A stopped-child restart probes the new child once, then retries
            # exactly ten times before recording the failed recovery cycle.
            assert_equal(len(probes), 11)
        else:
            assert launch["pid"] != previous_launch["pid"]
            assert_equal(len(self.events("exit")), exits + 1)
            assert_equal(self.events("exit")[-1]["pid"], previous_launch["pid"])
            assert_equal(self.events("exit")[-1]["reason"],
                         f"signal:{signal.SIGTERM}")
            # The old owned child gets a health probe and one authentication
            # probe before its controlled stop. Only the ten retries target
            # the new child on this live-process restart path.
            assert_equal(len(probes), 12)
            assert all(probe["pid"] == previous_launch["pid"] and
                       probe["comment"] == previous_launch["comment"] and
                       not probe["ready"] for probe in probes[:2])
            probes = probes[2:]
            lifecycle = [entry for entry in self.events()
                         if entry["event"] in ("start", "exit")]
            assert_equal([(entry["event"], entry["pid"])
                          for entry in lifecycle[-2:]],
                         [("exit", previous_launch["pid"]),
                          ("start", launch["pid"])])
        assert all(not probe["ready"] and probe["pid"] == launch["pid"] and
                   probe["comment"] == launch["comment"] for probe in probes)
        self.assert_unready_status()
        return launch

    def assert_startup_pending(self, launch, progress):
        starts = len(self.events("start"))
        stops = len(self.events("stop-request"))
        exits = len(self.events("exit"))
        probes_before = len(self.events("probe"))
        self.scheduler_probe("btcheader-watchdog-startup-pending")
        assert_equal(len(self.events("start")), starts)
        assert_equal(len(self.events("stop-request")), stops)
        assert_equal(len(self.events("exit")), exits)
        probes = self.events("probe")[probes_before:]
        assert_equal(len(probes), 1)
        assert_equal(probes[0]["pid"], launch["pid"])
        assert_equal(probes[0]["comment"], launch["comment"])
        assert not probes[0]["ready"]
        self.assert_unready_status()
        self.assert_owner_progress(progress)

    def check_restarted_child_startup_grace(self):
        node = self.nodes[0]
        self.log.info("Startup grace retains an unready child beyond restart cooldown")
        progress = (self.state["height"], self.state["hash"], self.now)
        self.advance_time(self.RESTART_COOLDOWN)
        launch = self.restart_unready_backend()
        self.assert_owner_progress(progress)
        for _ in range(2):
            self.advance_time(self.RESTART_COOLDOWN + 1)
            self.assert_startup_pending(launch, progress)

        self.log.info("Readiness during startup grace recovers without another launch")
        self.state.update(height=103, hash="44" * 32, rpc_unavailable=False)
        self.write_state()
        starts = len(self.events("start"))
        stops = len(self.events("stop-request"))
        exits = len(self.events("exit"))
        probes_before = len(self.events("probe"))
        with node.assert_debug_log([], unexpected_msgs=[
                "Bitcoin header watchdog restarted managed child",
                "Bitcoin header policy backend is not ready;",
        ], timeout=30):
            node.mockscheduler(self.PROBE_INTERVAL)
            node.syncwithvalidationinterfacequeue()
        assert_equal(len(self.events("start")), starts)
        assert_equal(len(self.events("stop-request")), stops)
        assert_equal(len(self.events("exit")), exits)
        probes = self.events("probe")[probes_before:]
        assert_equal(len(probes), 1)
        assert_equal(probes[0]["pid"], launch["pid"])
        assert probes[0]["ready"]
        status = node.syscoinbtcheaderstatus()
        assert status["process_running"]
        assert status["policy_healthy"]
        assert status["ready"]
        progress = (self.state["height"], self.state["hash"], self.now)
        self.assert_owner_progress(progress)
        return launch, progress

    def check_restarted_child_unavailable(self, healthy_launch, progress):
        node = self.nodes[0]
        self.log.info("Readiness clears startup grace before a later live RPC outage")
        # No time advances after readiness: normal cooldown has expired, but
        # the old launch would still be inside its startup grace if not cleared.
        launch = self.restart_unready_backend(healthy_launch)
        self.assert_owner_progress(progress)
        elapsed = 0
        for seconds in (1, self.RESTART_COOLDOWN, self.RESTART_COOLDOWN + 1):
            self.advance_time(seconds)
            elapsed += seconds
            self.assert_startup_pending(launch, progress)

        self.log.info("Grace expiry permits one bounded replacement of an unready child")
        self.advance_time(self.STARTUP_GRACE - elapsed)
        # With REINDEX_AFTER=2, this second failed recovery cycle must still
        # launch without reindex. The first cycle and repeated pending probes
        # must not have consumed multiple escalation attempts.
        launch = self.restart_unready_backend(launch)
        self.assert_owner_progress(progress)
        self.advance_time(1)
        self.assert_startup_pending(launch, progress)

        # Restore only the owned fake's RPC response for authenticated cleanup.
        self.state["rpc_unavailable"] = False
        self.write_state()
        node.syscoinstopbtcheadernode()
        assert_equal(self.events("exit")[-1]["pid"], launch["pid"])
        assert_equal(self.events("exit")[-1]["reason"], "authenticated-stop")

    def run_test(self):
        node = self.nodes[0]
        operator = node.protx_generate_operator_keypair()
        genesis = node.getblockhash(0)
        self.extra_args[0] = [
            "-disablewallet=1",
            f"-mocktime={self.now}",
            f'-masternodeslhprivkey={operator["operatorKey"]}',
            f'-masternodechainlockseed={operator["chainlockSeed"]}',
            "-dip3params=1:1",
            "-pqpreparationheight=1",
            "-pqchainlockepochorigin=1440",
            "-pqregistrationcutoffblocks=288",
            "-pqrostersnapshotlag=288",
            "-pqfuturehorizonepochs=8",
            "-pqactivationheight=2315",
            "-pqbtcccandidateorigin=2315",
            "-pqbtccreceiptanchorheight=0",
            f"-pqbtccreceiptanchorblockhash={genesis}",
            "-pqbtccreceiptanchorcursorheight=-1",
            f'-pqbtccreceiptanchorcursorsyshash={"0" * 64}',
            f'-pqbtccreceiptanchorcursorbtchash={"0" * 64}',
            f'-pqbtccreceiptanchorstatehash={"0" * 64}',
            "-pqbtccreceiptanchorlatesttargetheight=-1",
            "-pqbtccreceiptanchorlatestcarrierheight=-1",
            "-btcheadermanaged=1",
            f'-btcheaderbinary={self.backend_dir / "bitcoind"}',
            f'-btcheaderclibinary={self.backend_dir / "bitcoin-cli"}',
            f"-btcheaderdatadir={self.backend_dir}",
            f"-btcheaderport={p2p_port(1)}",
            f"-btcheaderrpcport={rpc_port(1)}",
            "-btcheaderpolicyondemand=1",
            "-btcheaderwatchdog=1",
            f"-btcheaderwatchdogprobeinterval={self.PROBE_INTERVAL}",
            f"-btcheaderwatchdogrestartcooldown={self.RESTART_COOLDOWN}",
            f"-btcheaderwatchdogstartupgrace={self.STARTUP_GRACE}",
            f"-btcheaderwatchdogstalltimeout={self.STALL_TIMEOUT}",
            f"-btcheaderwatchdogreindexafter={self.REINDEX_AFTER}",
            "-btcheadercmdtimeout=5",
        ]
        self.restart_node(0, extra_args=self.extra_args[0])
        assert node.syscoinbtcheaderstatus()["ready"]
        progress = (self.state["height"], self.state["hash"], self.now)
        self.assert_owner_progress(progress)

        self.log.info("Status-only stalled probes do not consume restart attempts")
        self.state["ibd"] = True
        self.write_state()
        self.advance_time(self.STALL_TIMEOUT)
        for _ in range(self.REINDEX_AFTER + 1):
            self.assert_stalled_status()
        assert_equal(len(self.events("start")), 1)
        reindexes = [False, False]
        self.restart_stalled_backend(reindexes, progress)

        self.log.info("Cooldown probes do not advance the escalation threshold")
        self.advance_time(1)
        for _ in range(self.REINDEX_AFTER + 1):
            self.scheduler_probe("btcheader-watchdog-restart-cooldown(9)")
            self.assert_stalled_status()
        assert_equal(len(self.events("start")), len(reindexes))
        self.advance_time(self.RESTART_COOLDOWN - 1)
        reindexes.append(False)
        self.restart_stalled_backend(reindexes, progress)

        self.log.info("Repeated successful launches with no progress trigger one reindex")
        self.advance_time(self.RESTART_COOLDOWN)
        reindexes.append(True)
        self.restart_stalled_backend(reindexes, progress)
        self.advance_time(self.RESTART_COOLDOWN)
        reindexes.append(False)
        self.restart_stalled_backend(reindexes, progress)

        self.log.info("Genuine header progress resets both escalation counters")
        self.advance_time(1)
        self.state.update(ibd=False, height=101, hash="22" * 32)
        self.write_state()
        status = node.syscoinbtcheaderstatus()
        assert status["policy_healthy"]
        assert status["ready"]
        progress = (self.state["height"], self.state["hash"], self.now)
        self.assert_owner_progress(progress)
        assert_equal(len(self.events("start")), len(reindexes))

        self.state["ibd"] = True
        self.write_state()
        self.advance_time(self.STALL_TIMEOUT)
        for reindex in (False, False, True):
            reindexes.append(reindex)
            self.restart_stalled_backend(reindexes, progress)
            self.advance_time(self.RESTART_COOLDOWN)

        node.syscoinstopbtcheadernode()
        launches = self.events("start")
        exits = self.events("exit")
        assert_equal([entry["pid"] for entry in exits],
                     [entry["pid"] for entry in launches])
        assert all(entry["reason"] == "authenticated-stop" for entry in exits)
        assert_equal([entry["pid"] for entry in self.events("stop-request")],
                     [entry["pid"] for entry in launches])
        authenticated = set()
        for entry in self.events():
            identity = (entry["pid"], entry.get("comment"))
            if entry["event"] == "authenticated":
                authenticated.add(identity)
            elif entry["event"] == "stop-request":
                assert identity in authenticated
        assert_equal(sum(entry["reindex"] for entry in launches), 2)

        self.check_restarted_child_warmup()
        launch, progress = self.check_restarted_child_startup_grace()
        self.check_restarted_child_unavailable(launch, progress)


if __name__ == "__main__":
    BTCHeaderWatchdogTest().main()
