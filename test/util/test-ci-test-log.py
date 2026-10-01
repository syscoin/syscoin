#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline annotation and real-make recipe tests; no Syscoin binary is needed."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'test/util/ci-test-log.py'
SPEC = importlib.util.spec_from_file_location('ci_test_log', HELPER)
LOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOG)


def decode(value, property_value=False):
    replacements = [('%0D', '\r'), ('%0A', '\n')]
    if property_value:
        replacements += [('%3A', ':'), ('%2C', ',')]
    for escaped, literal in replacements + [('%25', '%')]:
        value = value.replace(escaped, literal)
    return value


class TestAnnotation(unittest.TestCase):
    def summary(self, data):
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / 'test.log'
            logfile.write_bytes(data)
            return LOG.failure_summary(logfile)

    def test_data_and_property_escaping(self):
        value = '%0A%,:\r\n::warning::injected ##[error]legacy'
        self.assertEqual(LOG.escape(value), '%250A%25,:%0D%0A::warning::injected ##[error]legacy')
        self.assertEqual(decode(LOG.escape(value)), value)
        self.assertEqual(decode(LOG.escape(value, True), True), value)
        self.assertNotIn(',', LOG.escape(value, True))
        self.assertNotIn(':', LOG.escape(value, True))

    def test_untrusted_annotation_stays_one_command(self):
        source = 'src/test/a,b:%0A\r\n::warning::fake.cpp'
        summary = 'error: 100%\r::add-mask::fake\n##[error]legacy %0A'
        result = LOG.annotation(source, summary).decode()
        self.assertEqual(result.count('\n'), 1)
        self.assertNotIn('\r', result)
        header, message = result[:-1].split('::', 2)[1:]
        self.assertTrue(header.startswith('error file='))
        self.assertNotIn(',', header)
        self.assertEqual(decode(header.removeprefix('error file='), True), source)
        self.assertEqual(decode(message), summary)

    def test_first_boost_failure_ignores_routine_error_text(self):
        diagnostic = 'test/a.cpp(42): error: in "a/first": check x == y has failed'
        data = ('Entering test suite "a"\napplication error: deliberately tested\n'
                + diagnostic + '\ntest/a.cpp(51): fatal error: in "a/second": bad\n')
        self.assertEqual(self.summary(data.encode()), diagnostic)

    def test_sanitizer_and_boost_markers(self):
        for line in (
            'unknown location(0): fatal error: in "a": memory access violation',
            '==123==ERROR: AddressSanitizer: heap-use-after-free',
            '==123==ERROR: LeakSanitizer: detected memory leaks',
            'WARNING: ThreadSanitizer: data race',
            'WARNING: MemorySanitizer: use-of-uninitialized-value',
            'SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior test.cpp:2:3',
            'AddressSanitizer:DEADLYSIGNAL',
            'test/a.cpp:123:4: runtime error: signed integer overflow',
            '*** 1 failure is detected in the test module "Syscoin Test Suite"',
            '*** 2 failures are detected in the test module "Syscoin Test Suite"',
        ):
            with self.subTest(line=line):
                self.assertEqual(self.summary(('before\n' + line + '\nafter\n').encode()), line)

    def test_ansi_crlf_and_invalid_utf8(self):
        line = b'\x1b[1;31;49mtest/a.cpp(7): error: in "a": bad \xff\x1b[0;39;49m\r\n'
        self.assertEqual(self.summary(line), 'test/a.cpp(7): error: in "a": bad \ufffd')

    def test_no_marker_uses_last_nonempty_line(self):
        self.assertEqual(self.summary(b'first\n\nlast useful line\n \r\n'),
                         'No recognized failure marker; last log line: last useful line')

    def test_empty_and_missing_log(self):
        self.assertEqual(self.summary(b' \n\t\r\n'), 'Test process failed; log is empty.')
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(LOG.failure_summary(Path(directory) / 'missing'),
                             'Test process failed; log could not be read.')

    def test_bound_preserves_utf8_and_escape_sequences(self):
        for source, summary in (
            ('src/test/a.cpp', '%\r\n\U0001f642' * 5000),
            ('x,:%\r\n\U0001f642' * 5000, 'error: huge source'),
        ):
            result = LOG.annotation(source, summary)
            self.assertLessEqual(len(result), 4000)
            self.assertEqual(result.count(b'\n'), 1)
            result.decode('utf-8', errors='strict')
            self.assertNotRegex(result[:-1].decode(), r'%(?:[0-9A-F]?)$')
            self.assertTrue(result.endswith(b'...\n'))


class TestRecipe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.src = self.directory / 'src'
        (self.src / 'test').mkdir(parents=True)
        (self.src / 'test/example.cpp').write_text('BOOST_AUTO_TEST_SUITE(example)\n')
        self.payload = b'Entering test suite\ntest/example.cpp(23): error: in "example": expected 100%\ntail\n'
        self.payload_file = self.directory / 'payload'
        self.payload_file.write_bytes(self.payload)
        self.binary = self.directory / 'mock-test'
        self.binary.write_text('#!/usr/bin/env python3\nimport os, pathlib, sys\n'
                               'os.write(1, pathlib.Path(os.environ["PAYLOAD"]).read_bytes())\n'
                               'sys.exit(int(os.environ["TEST_STATUS"]))\n')
        self.binary.chmod(0o755)
        fragment = (ROOT / 'src/Makefile.test.include').read_text()
        self.recipe = fragment[fragment.index('%.cpp.test: %.cpp'):fragment.index('\ntest/data/%.json.h:')]
        redirect = ' > "$$TEST_LOGFILE" 2>&1'
        end = self.recipe.index(redirect) + len(redirect)
        self.original = self.recipe[:end] + ' || (cat "$$TEST_LOGFILE" && false)\n'
        self.env = {**os.environ, 'PAYLOAD': str(self.payload_file)}
        for name in ('MAKEFLAGS', 'MFLAGS', 'GITHUB_ACTIONS'):
            self.env.pop(name, None)

    def run_recipe(self, original=False, github=None, status=9, python=None, extra_env=None,
                   target='test/example.cpp.test', vpath=None, shell=None):
        preamble = (f'TEST_BINARY = {self.binary}\nabs_builddir = {self.src}\nSED = sed\n'
                    f'PYTHON = {python or sys.executable}\ntop_srcdir = {ROOT}\nAM_V_at = @\n')
        if vpath:
            preamble += f'vpath %.cpp {vpath}\n'
        if shell:
            preamble += f'SHELL = {shell}\n'
        (self.src / 'Makefile').write_text(preamble + (self.original if original else self.recipe))
        env = {**self.env, 'TEST_STATUS': str(status), **(extra_env or {})}
        if github is not None:
            env['GITHUB_ACTIONS'] = github
        result = subprocess.run(['make', '--no-print-directory', '-s', target],
                                cwd=self.src, env=env, capture_output=True)
        self.assertEqual((self.src / target.replace('.cpp.test', '.log')).read_bytes(), self.payload)
        return result

    def test_local_failure_output_and_result_unchanged(self):
        for github in (None, '', 'false', 'TRUE'):
            old = self.run_recipe(original=True, github=github)
            new = self.run_recipe(github=github, python='/no-such-python')
            self.assertEqual(new.returncode, old.returncode)
            self.assertEqual(new.stdout, old.stdout)
            self.assertEqual(new.returncode, 2)
            self.assertIn(b'Error 1', new.stderr)
            self.assertNotIn(b'Completed tests from ', new.stdout)

    def test_github_failure_annotation_then_complete_original_output(self):
        old = self.run_recipe(original=True, github='true')
        for status in (1, 2, 9, 99, 134):
            new = self.run_recipe(github='true', status=status)
            lines = new.stdout.splitlines(keepends=True)
            annotations = [line for line in lines if line.startswith(b'::error ')]
            self.assertEqual(len(annotations), 1)
            self.assertIn(b'file=src/test/example.cpp::test/example.cpp(23): error:', annotations[0])
            self.assertIn(b'100%25', annotations[0])
            self.assertEqual(new.stdout.replace(annotations[0], b'', 1), old.stdout)
            self.assertEqual(new.returncode, 2)
            self.assertIn(b'Error 1', new.stderr)
            self.assertNotIn(b'Completed tests from ', new.stdout)

    def test_local_success_output_unchanged(self):
        for github in (None, '', 'false', 'TRUE'):
            old = self.run_recipe(original=True, github=github, status=0)
            new = self.run_recipe(github=github, status=0, python='/no-such-python')
            self.assertEqual(new.returncode, 0)
            self.assertEqual(new.stdout, old.stdout)
            self.assertEqual(new.stderr, old.stderr)

    def test_github_success_emits_one_completion_without_annotation_helper(self):
        old = self.run_recipe(original=True, github='true', status=0)
        new = self.run_recipe(github='true', status=0, python='/no-such-python')
        marker = b'Completed tests from src/test/example.cpp\n'
        self.assertEqual(new.returncode, 0)
        self.assertEqual(new.stdout, old.stdout + marker)
        self.assertEqual(new.stdout.count(marker), 1)
        self.assertEqual(new.stderr, old.stderr)
        self.assertNotIn(b'::error', new.stdout)

    def test_failed_completion_print_cannot_fail_successful_test(self):
        shell = self.directory / 'shell-with-failed-printf'
        shell.write_text('#!/bin/sh\nprintf() { echo "simulated diagnostic failure" >&2; return 7; }\n'
                         'test "$1" = -c || exit 98\neval "$2"\n')
        shell.chmod(0o755)
        old = self.run_recipe(original=True, github='true', status=0, shell=shell)
        new = self.run_recipe(github='true', status=0, shell=shell, python='/no-such-python')
        self.assertEqual(new.returncode, 0)
        self.assertEqual(new.stdout, old.stdout)
        self.assertEqual(new.stderr, b'simulated diagnostic failure\n')
        self.assertNotIn(self.payload, new.stdout)
        self.assertNotIn(b'::error', new.stdout)

    def test_out_of_tree_wallet_annotation_uses_repository_path(self):
        source_root = self.directory / 'source-tree/src'
        (source_root / 'wallet/test').mkdir(parents=True)
        (source_root / 'wallet/test/example.cpp').write_text('BOOST_AUTO_TEST_SUITE(example)\n')
        (self.src / 'wallet/test').mkdir(parents=True)
        result = self.run_recipe(github='true', target='wallet/test/example.cpp.test', vpath=source_root)
        self.assertIn(b'::error file=src/wallet/test/example.cpp::', result.stdout)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'Completed tests from ', result.stdout)
        success = self.run_recipe(github='true', status=0, target='wallet/test/example.cpp.test',
                                  vpath=source_root, python='/no-such-python')
        self.assertEqual(success.returncode, 0)
        self.assertEqual(success.stdout.count(b'Completed tests from src/wallet/test/example.cpp\n'), 1)
        self.assertNotIn(b'::error', success.stdout)

    def test_annotation_failure_keeps_log_and_failure(self):
        old = self.run_recipe(original=True, github='true')
        new = self.run_recipe(github='true', python='/no-such-python')
        self.assertEqual(new.stdout, old.stdout)
        self.assertEqual(new.returncode, old.returncode)
        self.assertIn(b'Error 1', new.stderr)
        self.assertNotIn(b'Completed tests from ', new.stdout)

    def test_cat_failure_status_is_preserved(self):
        bindir = self.directory / 'bin'
        bindir.mkdir()
        cat = bindir / 'cat'
        cat.write_text('#!/bin/sh\n/bin/cat "$@"\ncase "$1" in *.log) exit 7;; esac\n')
        cat.chmod(0o755)
        env = {'PATH': str(bindir) + os.pathsep + self.env['PATH']}
        for github in (None, 'true'):
            old = self.run_recipe(original=True, github=github, extra_env=env)
            new = self.run_recipe(github=github, extra_env=env)
            self.assertEqual(new.returncode, old.returncode)
            self.assertIn(b'Error 7', old.stderr)
            self.assertIn(b'Error 7', new.stderr)
            self.assertNotIn(b'Completed tests from ', new.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
