#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline progress-reader and real-make lifecycle checks, without Syscoin."""

import importlib.util
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'test/util/ci-test-progress.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROGRESS = load('ci_test_progress', HELPER)
LEGACY = load('test_ci_test_log', ROOT / 'test/util/test-ci-test-log.py')
ENTER = b'test/pq_registry_tests.cpp(830): Entering test case "population"\n'
LEAVE = b'test/pq_registry_tests.cpp(830): Leaving test case "population"; testing time: 123us\n'
PHASE = b'PQ population key generation: 801 jobs, 4 workers\n'
INFO = b'2026-10-01T00:00:00.000Z TestFramework (INFO): Create superblock\n'


class TestRecords(unittest.TestCase):
    def test_native_markers_and_noise(self):
        for raw in (ENTER, LEAVE, PHASE, b'PQ integration member key generation: through 2000 keys\n',
                    b'PQ integration full-dimension scenario: complete\n'):
            result = PROGRESS.progress_record('native', 12.34, raw)
            self.assertTrue(result.startswith(b'CI progress native +12.3s | '))
        for raw in (b'', b'ordinary debug line', INFO, b'Entering test suite "pq_registry_tests"'):
            self.assertIsNone(PROGRESS.progress_record('native', 0, raw))

    def test_functional_levels(self):
        for level in (b'INFO', b'WARNING', b'ERROR'):
            self.assertIsNotNone(PROGRESS.progress_record('functional', 0, INFO.replace(b'INFO', level)))
        self.assertIsNone(PROGRESS.progress_record('functional', 0, INFO.replace(b'INFO', b'DEBUG')))
        self.assertIsNone(PROGRESS.progress_record('functional', 0, PHASE))

    def test_control_characters_and_invalid_utf8(self):
        result = PROGRESS.progress_record('native', 0,
            b'\x1b[32mPQ population phase\x1b[0m\r::error::not-a-command\n\x00\xff')
        self.assertEqual(result.count(b'\n'), 1)
        self.assertNotIn(b'\r', result)
        self.assertNotIn(b'\x1b', result)
        self.assertNotIn(b'\x00', result)
        self.assertFalse(result.startswith(b'::'))
        result.decode('utf-8', errors='strict')

    def test_record_byte_bound(self):
        result = PROGRESS.progress_record('native', 1, ('PQ population ' + '\U0001f642' * 5000).encode())
        self.assertLessEqual(len(result), 4000)
        self.assertEqual(result.count(b'\n'), 1)
        result.decode('utf-8', errors='strict')


class TestReader(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'native.log'
        self.output = []

    def follower(self, mode='native', path=None):
        follower = PROGRESS.Follower(mode, path or self.path, self.output.append)
        self.addCleanup(follower.close)
        return follower

    def append(self, value):
        with self.path.open('ab') as log:
            log.write(value)

    def test_missing_file_slow_partial_writer_and_exactly_once(self):
        follower = self.follower()
        follower.poll()
        self.append(PHASE[:20])
        follower.poll()
        self.assertEqual(self.output, [])
        self.append(PHASE[20:])
        follower.poll()
        follower.poll()
        self.assertEqual(len(self.output), 1)
        self.assertIn(PHASE.strip(), self.output[0])

    def test_oversized_line_is_discarded_without_losing_next_record(self):
        follower = self.follower()
        self.append(b'PQ population ' + b'x' * 20000)
        follower.poll()
        self.assertEqual(self.output, [])
        self.append(b'\n' + ENTER)
        follower.poll()
        self.assertEqual(len(self.output), 1)
        self.assertIn(b'Entering test case', self.output[0])
        self.assertLessEqual(len(follower.readers[self.path].pending), PROGRESS.MAX_LINE_BYTES)

    def test_truncation_resets_independent_handle(self):
        follower = self.follower()
        self.append(PHASE)
        follower.poll()
        self.path.write_bytes(b'')
        follower.poll()
        self.append(LEAVE)
        follower.poll()
        self.assertEqual(len(self.output), 2)

    def test_read_budget_and_original_writer_position(self):
        follower = self.follower()
        self.path.write_bytes(b'noise\n' * 30000)
        with self.path.open('ab') as writer:
            position = writer.tell()
            follower.poll()
            self.assertEqual(writer.tell(), position)
        reader = follower.readers[self.path]
        self.assertEqual(os.lseek(reader.fd, 0, os.SEEK_CUR), PROGRESS.READ_BUDGET)

    def test_fifo_and_symlink_are_not_read(self):
        os.mkfifo(self.path)
        follower = self.follower()
        follower.poll()
        self.assertIsNone(follower.readers[self.path].fd)
        self.path.unlink()
        real = self.root / 'real.log'
        real.write_bytes(PHASE)
        self.path.symlink_to(real)
        follower.poll()
        self.assertEqual(self.output, [])

    def test_functional_snapshot_and_strict_path(self):
        old = self.root / 'test_runner_old/feature_governance_dynamic_0/test_framework.log'
        old.parent.mkdir(parents=True)
        old.write_bytes(INFO.replace(b'Create', b'Old'))
        follower = self.follower('functional', self.root)
        new = self.root / 'test_runner_new/feature_governance_dynamic_0/test_framework.log'
        new.parent.mkdir(parents=True)
        new.write_bytes(INFO)
        other = self.root / 'test_runner_new/feature_governance_0/test_framework.log'
        other.parent.mkdir(parents=True)
        other.write_bytes(INFO.replace(b'Create', b'Other'))
        follower.poll()
        self.assertEqual(len(self.output), 1)
        self.assertIn(b'Create superblock', self.output[0])


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def start(self, mode='native', parent=None):
        path = self.root / 'native.log' if mode == 'native' else self.root
        if mode == 'native':
            path.touch()
        ready = self.root / 'ready'
        process = subprocess.Popen([sys.executable, '-B', str(HELPER), '--mode', mode,
            '--path', str(path), '--parent-pid', str(parent or os.getpid()),
            '--ready-file', str(ready)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 3
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), 'follower did not acknowledge initial snapshot')
        return process, path

    def test_sigterm_final_drain_complete_records_only(self):
        process, path = self.start()
        path.write_bytes(PHASE + b'PQ population incomplete')
        process.terminate()
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, error)
        self.assertIn(PHASE.strip(), output)
        self.assertNotIn(b'incomplete', output)

    def test_record_is_forwarded_while_writer_and_follower_are_alive(self):
        process, path = self.start()
        with path.open('ab') as writer:
            writer.write(ENTER)
            writer.flush()
            self.assertTrue(select.select([process.stdout], [], [], 2)[0])
            self.assertIn(b'Entering test case', process.stdout.readline())
            self.assertIsNone(process.poll())
            writer.write(LEAVE)
            writer.flush()
        process.terminate()
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, error)
        self.assertIn(b'Leaving test case', output)

    def test_functional_ready_handshake_does_not_skip_immediate_new_log(self):
        old = self.root / 'test_runner_old/feature_governance_dynamic_0/test_framework.log'
        old.parent.mkdir(parents=True)
        old.write_bytes(INFO.replace(b'Create', b'Old'))
        process, root = self.start('functional')
        new = root / 'test_runner_new/feature_governance_dynamic_0/test_framework.log'
        new.parent.mkdir(parents=True)
        new.write_bytes(INFO)
        process.terminate()
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, error)
        self.assertIn(b'Create superblock', output)
        self.assertNotIn(b'Old superblock', output)

    def test_parent_disappearance(self):
        parent = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(lambda: parent.poll() is None and parent.kill())
        process, path = self.start(parent=parent.pid)
        path.write_bytes(PHASE)
        parent.terminate()
        parent.wait(timeout=3)
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, error)
        self.assertIn(PHASE.strip(), output)


class TestNativeRecipe(unittest.TestCase):
    def setUp(self):
        self.recipe = LEGACY.TestRecipe()
        self.recipe.setUp()
        self.addCleanup(self.recipe.doCleanups)
        (self.recipe.src / 'test/pq_registry_tests.cpp').write_text('BOOST_AUTO_TEST_SUITE(pq_registry_tests)\n')
        self.recipe.payload = ENTER + b'app debug noise\n' + PHASE + LEAVE
        self.recipe.payload_file.write_bytes(self.recipe.payload)
        self.recipe.binary.write_text('#!/usr/bin/env python3\nimport json, os, pathlib, sys, time\n'
            'pathlib.Path(os.environ["ARGS_CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n'
            'os.write(1, pathlib.Path(os.environ["PAYLOAD"]).read_bytes())\n'
            'time.sleep(0.4)\n'
            'sys.exit(int(os.environ["TEST_STATUS"]))\n')
        self.recipe.env['ARGS_CAPTURE'] = str(self.recipe.directory / 'args.json')
        self.target = 'test/pq_registry_tests.cpp.test'

    def run_recipe(self, **kwargs):
        return self.recipe.run_recipe(target=self.target, **kwargs)

    def test_live_progress_log_and_arguments_preserved_dash_and_bash(self):
        for shell in ('/bin/dash', '/bin/bash'):
            baseline = self.run_recipe(original=True, github='true', status=0, shell=shell)
            arguments = Path(self.recipe.env['ARGS_CAPTURE']).read_bytes()
            new = self.run_recipe(github='true', status=0, shell=shell,
                extra_env={'CI_UNIT_TESTS_SHARD': '2'})
            self.assertEqual(new.returncode, baseline.returncode, new.stderr)
            self.assertEqual(Path(self.recipe.env['ARGS_CAPTURE']).read_bytes(), arguments)
            self.assertEqual(new.stdout.count(b'CI progress native '), 3)
            self.assertIn(b'Completed tests from src/test/pq_registry_tests.cpp', new.stdout)
            self.assertNotIn(b'app debug noise', new.stdout)

    def test_failures_still_annotate_and_replay_entire_log(self):
        for status in (1, 9, 134):
            result = self.run_recipe(github='true', status=status,
                extra_env={'CI_UNIT_TESTS_SHARD': '2'})
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'::error file=src/test/pq_registry_tests.cpp::', result.stdout)
            self.assertIn(self.recipe.payload, result.stdout)
            self.assertNotIn(b'Completed tests from', result.stdout)

    def test_inactive_conditions_do_not_start_helper(self):
        for github, shard in ((None, '2'), ('false', '2'), ('true', '')):
            result = self.run_recipe(github=github, status=0, python='/no-such-python',
                extra_env={'CI_UNIT_TESTS_SHARD': shard})
            self.assertEqual(result.returncode, 0)
            self.assertNotIn(b'CI progress', result.stdout)
            self.assertEqual(result.stderr, b'')

    def test_stale_native_log_is_not_replayed(self):
        (self.recipe.src / 'test/pq_registry_tests.log').write_bytes(b'PQ population STALE\n')
        result = self.run_recipe(github='true', status=0,
            extra_env={'CI_UNIT_TESTS_SHARD': '2'})
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b'STALE', result.stdout)

    def test_failed_logfile_export_never_runs_test_or_watcher(self):
        shell = self.recipe.directory / 'failed-export-shell'
        shell.write_text('#!/bin/bash\n'
            'export() { case "$1" in TEST_LOGFILE=*) TEST_LOGFILE="${1#*=}"; return 17;; '
            '*) builtin export "$@";; esac; }\n'
            'test "$1" = -c || exit 98\neval "$2"\n')
        shell.chmod(0o755)
        log = self.recipe.src / 'test/pq_registry_tests.log'
        log.write_bytes(self.recipe.payload)
        old = self.run_recipe(original=True, shell=shell)
        new = self.run_recipe(shell=shell)
        self.assertEqual(new.returncode, old.returncode)
        self.assertEqual(new.stdout, old.stdout)
        self.assertEqual(new.stderr, old.stderr)
        self.assertFalse(Path(self.recipe.env['ARGS_CAPTURE']).exists())

    def test_missing_helper_interpreter_cannot_change_test_status(self):
        for status in (0, 9):
            result = self.run_recipe(github='true', status=status, python='/no-such-python',
                extra_env={'CI_UNIT_TESTS_SHARD': '2'})
            self.assertEqual(result.returncode, 0 if status == 0 else 2)
            if status:
                self.assertIn(self.recipe.payload, result.stdout)

    def test_cleanup_is_bounded_for_helper_ignoring_sigterm(self):
        shim = self.recipe.directory / 'stubborn-python'
        pidfile = self.recipe.directory / 'helper.pid'
        shim.write_text('#!' + sys.executable + '\nimport os, pathlib, signal, sys, time\n'
            'if sys.argv[1].endswith("ci-test-progress.py"):\n'
            '    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            '    pathlib.Path(os.environ["HELPER_PIDFILE"]).write_text(str(os.getpid()))\n'
            '    while True: time.sleep(10)\n'
            'os.execv(' + repr(sys.executable) + ', [' + repr(sys.executable) + '] + sys.argv[1:])\n')
        shim.chmod(0o755)
        start = time.monotonic()
        result = self.run_recipe(github='true', status=0, python=shim,
            extra_env={'CI_UNIT_TESTS_SHARD': '2', 'HELPER_PIDFILE': str(pidfile)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - start, 4)
        self.assertTrue(pidfile.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
