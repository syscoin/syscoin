#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the real external Bitcoin-header command runner on every platform."""

import json
import os
from pathlib import Path
import sys
import time

from test_framework.test_framework import SkipTest, SyscoinTestFramework
from test_framework.util import assert_equal


BACKEND = r'''import json
from pathlib import Path
import subprocess
import sys
import time

with open(sys.argv[1], encoding="utf8") as source:
    state = json.load(source)
if sys.argv[2:] != ["getblockchaininfo"]:
    sys.exit("unexpected backend arguments: " + repr(sys.argv[2:]))

mode = state["mode"]
if mode == "exit":
    print("external backend failed", file=sys.stderr)
    sys.exit(7)
if mode == "invalid-json":
    print("not JSON")
    sys.exit(0)
if mode == "timeout":
    # A leaked descendant keeps both captured pipes open after its parent is
    # terminated. The finite lifetime also bounds a failing regression test.
    descendant = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdout=sys.stdout, stderr=sys.stderr)
    Path(state["descendant_marker"]).write_text(
        str(descendant.pid), encoding="utf8")
    time.sleep(20)

print(json.dumps(state["chaininfo"]))
'''


class BTCHeaderExternalCommandTest(SyscoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.supports_cli = False
        self.extra_args = [[
            "-btcheadermanaged=0",
            "-btcheaderwatchdog=0",
            "-btcheadercmdtimeout=3",
        ]]

    def add_options(self, parser):
        parser.add_argument(
            "--require-backend", action="store_true",
            help="Fail instead of skipping when external command support is unavailable")

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean(
                "ENABLE_BTC_HEADER_COMMAND", fallback=False):
            if self.options.require_backend:
                raise AssertionError("Required Boost.Process Bitcoin header backend unavailable")
            raise SkipTest("Boost.Process Bitcoin header backend unavailable")

    def setup_chain(self):
        super().setup_chain()
        backend_dir = Path(self.options.tmpdir) / "external backend with spaces ₿_🏃"
        backend_dir.mkdir()
        backend_script = backend_dir / "bitcoin cli.py"
        backend_script.write_text(BACKEND, encoding="utf8")
        self.backend_state = backend_dir / "backend state.json"
        self.descendant_marker = backend_dir / "descendant pid"
        self.state = {
            "mode": "ready",
            "descendant_marker": str(self.descendant_marker),
            "chaininfo": {
                "chain": "regtest",
                "initialblockdownload": False,
                "headers": 100,
                "blocks": 100,
                "bestblockhash": "12" * 32,
            },
        }
        self.write_state("ready")
        # Use the interpreter executable directly: neither shell quoting nor
        # executable script/shebang support may hide an argv regression on Windows.
        self.extra_args[0] += [
            f"-btcheadercmd={sys.executable}",
            f"-btcheaderarg={backend_script}",
            f"-btcheaderarg={self.backend_state}",
        ]

    def write_state(self, mode):
        self.state["mode"] = mode
        replacement = self.backend_state.with_suffix(".tmp")
        replacement.write_text(json.dumps(self.state), encoding="utf8")
        os.replace(replacement, self.backend_state)

    def assert_ready(self):
        status = self.nodes[0].syscoinbtcheaderstatus()
        assert_equal(status["managed"], False)
        assert_equal(status["process_running"], True)
        assert_equal(status["policy_healthy"], True)
        assert_equal(status["ready"], True)
        assert_equal(status["chaininfo"], self.state["chaininfo"])
        assert "reason" not in status, status

    def assert_failure(self, reason):
        status = self.nodes[0].syscoinbtcheaderstatus()
        assert_equal(status["managed"], False)
        assert_equal(status["ready"], False)
        assert reason in status["reason"], status
        assert "chaininfo" not in status, status

    def run_test(self):
        self.log.info("Check external command support and literal argv paths")
        assert_equal(self.nodes[0].getblockcount(), 0)
        # Native MSVC CI uses --require-backend so an absent feature cannot
        # silently skip the real command test; optional Autoconf builds may skip.
        self.assert_ready()

        self.log.info("Check nonzero exit and malformed JSON fail closed")
        self.write_state("exit")
        self.assert_failure("btcheadercmd-exit-7: external backend failed")
        self.write_state("invalid-json")
        self.assert_failure("btc-rpc-invalid-json")

        self.log.info("Check timeout terminates descendants holding RPC pipes")
        self.write_state("timeout")
        started = time.monotonic()
        self.assert_failure("btcheadercmd-timeout")
        elapsed = time.monotonic() - started
        assert self.descendant_marker.exists(), "Backend did not spawn its descendant"
        assert int(self.descendant_marker.read_text(encoding="utf8")) > 0
        # This allowance exceeds the three-second command deadline but stays
        # below the descendant's 20-second fallback lifetime, even on Windows CI.
        assert elapsed < 10, f"Timed-out backend retained captured pipes for {elapsed:.2f}s"

        self.log.info("Check command recovery without restarting or mining")
        self.state["chaininfo"].update(
            headers=101, blocks=101, bestblockhash="34" * 32)
        self.write_state("ready")
        self.assert_ready()
        assert_equal(self.nodes[0].getblockcount(), 0)


if __name__ == "__main__":
    BTCHeaderExternalCommandTest().main()
