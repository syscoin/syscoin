#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline source-inventory and real-recipe checks for the registry case split.

These tests inspect the exact source and mock only the test executable. They do
not claim to replace the compiled Boost --list_content inventory or execute any
registry/cryptographic test. Boost's documented colon-separated selector and
disabler semantics are used below:
https://www.boost.org/doc/libs/latest/libs/test/doc/html/boost_test/utf_reference/rt_param_reference/run_test.html
https://www.boost.org/doc/libs/latest/libs/test/doc/html/boost_test/runtime_config/test_unit_filtering.html
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/test/pq_registry_tests.cpp'
SUITE = 'pq_registry_tests'
POPULATION = 'authenticated_new_population_replaces_only_refreshed_recovery_source'
CASE_FILTER = SUITE + '/' + POPULATION
REMAINING_FILTER = SUITE + ':!' + CASE_FILTER
spec = importlib.util.spec_from_file_location('test_ci_test_log', ROOT / 'test/util/test-ci-test-log.py')
LEGACY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LEGACY)


def source_cases(text):
    """Fail closed if this direct-case inventory gains unsupported test forms."""
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.DOTALL)
    suites = re.findall(r'BOOST_FIXTURE_TEST_SUITE\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', text)
    if suites != [(SUITE, 'BasicTestingSetup')]:
        raise ValueError('unexpected registry suite/fixture declaration')
    names = re.findall(r'^\s*BOOST_AUTO_TEST_CASE\s*\(\s*(\w+)\s*\)\s*$', text, re.MULTILINE)
    declarations = re.findall(r'\bBOOST_[A-Z_]*TEST_CASE(?:_TEMPLATE)?\b', text)
    if len(names) != len(declarations) or len(names) != len(set(names)):
        raise ValueError('unsupported or duplicate registry test declaration')
    if re.search(r'\bBOOST_TEST_DECORATOR\b|\b(?:boost::unit_test|utf)::(?:depends_on|precondition|disabled|enable_if)\s*\(', text):
        raise ValueError('registry selection requires dependency/decorator review')
    if names.count(POPULATION) != 1:
        raise ValueError('population case must exist exactly once')
    return names


def modeled_selection(expression, names):
    """Set proof for these three exact documented filters, not a Boost parser."""
    if expression == SUITE:
        return set(names)
    if expression == CASE_FILTER:
        return {POPULATION}
    if expression == REMAINING_FILTER:
        return set(names) - {POPULATION}
    raise ValueError(expression)


class TestInventory(unittest.TestCase):
    def test_exact_source_partition_is_disjoint_complete_and_single_population(self):
        names = source_cases(SOURCE.read_text())
        population = modeled_selection(CASE_FILTER, names)
        remaining = modeled_selection(REMAINING_FILTER, names)
        self.assertEqual(len(population), 1)
        self.assertTrue(remaining)
        self.assertFalse(population & remaining)
        self.assertEqual(population | remaining, set(names))

    def test_future_independent_cases_remain_in_complement(self):
        text = SOURCE.read_text().replace('BOOST_AUTO_TEST_SUITE_END()',
            'BOOST_AUTO_TEST_CASE(future_added_registry_case)\n{}\nBOOST_AUTO_TEST_SUITE_END()')
        names = source_cases(text)
        self.assertIn('future_added_registry_case', modeled_selection(REMAINING_FILTER, names))
        self.assertNotIn('future_added_registry_case', modeled_selection(CASE_FILTER, names))

    def test_missing_duplicate_or_dependent_population_is_rejected(self):
        original = SOURCE.read_text()
        variants = [original.replace(POPULATION, 'renamed_population'),
                    original.replace('BOOST_AUTO_TEST_SUITE_END()',
                        f'BOOST_AUTO_TEST_CASE({POPULATION})\n{{}}\nBOOST_AUTO_TEST_SUITE_END()'),
                    original.replace(f'BOOST_AUTO_TEST_CASE({POPULATION})',
                        f'BOOST_AUTO_TEST_CASE({POPULATION}, * depends_on("other"))')]
        for text in variants:
            with self.assertRaises(ValueError):
                source_cases(text)


class TestRegistryRecipe(unittest.TestCase):
    def setUp(self):
        self.recipe = LEGACY.TestRecipe()
        self.recipe.setUp()
        self.addCleanup(self.recipe.doCleanups)
        (self.recipe.src / 'test/pq_registry_tests.cpp').write_bytes(SOURCE.read_bytes())
        self.capture = self.recipe.directory / 'args.json'
        self.recipe.env['ARGS_CAPTURE'] = str(self.capture)
        self.recipe.binary.write_text('#!' + sys.executable + '\n'
            'import json, os, pathlib, sys, time\n'
            'pathlib.Path(os.environ["ARGS_CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n'
            'os.write(1, pathlib.Path(os.environ["PAYLOAD"]).read_bytes())\n'
            'time.sleep(float(os.getenv("MOCK_DELAY", "0")))\n'
            'sys.exit(int(os.environ["TEST_STATUS"]))\n')
        self.target = 'test/pq_registry_tests.cpp.test'

    def run_mode(self, mode='', **kwargs):
        extra = {'SYSCOIN_PQ_REGISTRY_CASES': mode}
        extra.update(kwargs.pop('extra_env', {}))
        return self.recipe.run_recipe(target=kwargs.pop('target', self.target),
            extra_env=extra, **kwargs)

    def arguments(self):
        return json.loads(self.capture.read_text())

    def test_default_arguments_are_identical_and_complete(self):
        result = self.run_mode(status=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments(), ['--catch_system_errors=no', '-l', 'test_suite',
            '-t', SUITE, '--', 'DEBUG_LOG_OUT'])

    def test_case_selection_is_outside_command_substitution(self):
        # Older macOS /bin/sh cannot parse this case form inside $(...).
        recipe = self.recipe.recipe.replace('\\\n', '')
        self.assertNotRegex(recipe, r'\$\$\(\s*case\b')
        self.assertIn('-t "$$ci_test_filter" -- DEBUG_LOG_OUT', recipe)

    def test_failed_logfile_export_does_not_run_binary(self):
        logfile = self.recipe.src / 'test/pq_registry_tests.log'
        logfile.write_bytes(self.recipe.payload)
        shell = self.recipe.directory / 'shell-with-failed-export'
        shell.write_text('#!/bin/bash\nexport() { return 7; }\n'
                         'test "$1" = -c || exit 98\neval "$2"\n')
        shell.chmod(0o755)
        result = self.run_mode('population', status=0, shell=shell,
                               extra_env={'TEST_LOGFILE': str(logfile)})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())
        self.assertNotIn(b'Completed tests from', result.stdout)

    def test_exact_partition_filters_in_dash_and_bash(self):
        for shell in ('/bin/dash', '/bin/bash'):
            for mode, expected in (('population', CASE_FILTER), ('remaining', REMAINING_FILTER)):
                result = self.run_mode(mode, status=0, shell=shell)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.arguments(), ['--catch_system_errors=no', '-l', 'test_suite',
                    '-t', expected, '--', 'DEBUG_LOG_OUT'])

    def test_nonregistry_and_multiple_suites_are_not_filtered(self):
        (self.recipe.src / 'test/example.cpp').write_text(
            'BOOST_AUTO_TEST_SUITE(first)\nBOOST_AUTO_TEST_SUITE(second)\n')
        for mode in ('', 'population', 'remaining'):
            result = self.run_mode(mode, target='test/example.cpp.test', status=0)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.arguments()[4], 'first,second')

    def test_out_of_tree_registry_filter_uses_target_identity(self):
        source_root = self.recipe.directory / 'out-of-tree/src'
        (source_root / 'test').mkdir(parents=True)
        (source_root / 'test/pq_registry_tests.cpp').write_bytes(SOURCE.read_bytes())
        (self.recipe.src / 'test/pq_registry_tests.cpp').unlink()
        result = self.run_mode('remaining', status=0, vpath=source_root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments()[4], REMAINING_FILTER)

    def test_invalid_mode_fails_before_binary(self):
        (self.recipe.src / 'test/pq_registry_tests.log').write_bytes(self.recipe.payload)
        for mode in ('other', 'all', 'population remaining'):
            result = self.run_mode(mode, status=0)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'SYSCOIN_PQ_REGISTRY_CASES must be', result.stderr)
            self.assertFalse(self.capture.exists())

    def test_failures_replay_original_log_for_both_partitions(self):
        for mode in ('population', 'remaining'):
            result = self.run_mode(mode, status=9, github='true')
            self.assertEqual(result.returncode, 2)
            self.assertIn(self.recipe.payload, result.stdout)
            self.assertIn(b'::error file=src/test/pq_registry_tests.cpp::', result.stdout)
            self.assertNotIn(b'Completed tests from', result.stdout)

    def test_population_lane_retains_live_progress(self):
        self.recipe.payload = b'PQ population key generation: 801 jobs, 4 workers\n'
        self.recipe.payload_file.write_bytes(self.recipe.payload)
        result = self.run_mode('population', status=0, github='true',
            extra_env={'CI_UNIT_TESTS_SHARD': 'registry-population', 'MOCK_DELAY': '0.4'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'CI progress native ', result.stdout)
        self.assertIn(b'Completed tests from src/test/pq_registry_tests.cpp', result.stdout)

    def test_integration_lane_retains_unfiltered_suite_and_live_progress(self):
        source = self.recipe.src / 'test/pq_chainlock_integration_tests.cpp'
        source.write_text('BOOST_AUTO_TEST_SUITE(pq_chainlock_integration_tests)\n')
        self.recipe.payload = b'test/pq_chainlock_integration_tests.cpp(10): Entering test case "integration"\n'
        self.recipe.payload_file.write_bytes(self.recipe.payload)
        result = self.run_mode('', target='test/pq_chainlock_integration_tests.cpp.test',
            status=0, github='true', extra_env={'CI_UNIT_TESTS_SHARD': 'chainlock-integration', 'MOCK_DELAY': '0.4'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments()[4], 'pq_chainlock_integration_tests')
        self.assertIn(b'CI progress native ', result.stdout)


class TestCIDispatch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / 'make.json'
        make = self.root / 'make'
        make.write_text('#!' + sys.executable + '\n'
            'import json, os, pathlib, sys\n'
            'if "print-unit-test-sources" in sys.argv:\n'
            '    print(os.environ["INVENTORY"], end="")\n'
            '    raise SystemExit(int(os.getenv("INVENTORY_STATUS", "0")))\n'
            'pathlib.Path(os.environ["MAKE_CAPTURE"]).write_text(json.dumps({"args": sys.argv[1:], '
            '"marker": os.getenv("DISPATCH_MARKER"), "data": os.getenv("DIR_UNIT_TEST_DATA"), '
            '"library": os.getenv("LD_LIBRARY_PATH")}))\n'
            'raise SystemExit(int(os.getenv("MAKE_STATUS", "0")))\n')
        make.chmod(0o755)
        text = (ROOT / 'ci/test/06_script_b.sh').read_text()
        start = text.index('if [ "$RUN_UNIT_TESTS" = "true" ]; then')
        end = text.index('if [ "$RUN_UNIT_TESTS_SEQUENTIAL"', start)
        self.block = 'set -e\n' + text[start:end]
        self.inventory = sorted([f'test/a{i}.cpp' for i in range(8)] +
            ['test/pq_chainlock_integration_tests.cpp', 'test/pq_registry_tests.cpp',
             'wallet/test/first.cpp', 'wallet/test/second.cpp'])

    def dispatch(self, shard, inventory=None, **extra):
        self.capture.unlink(missing_ok=True)
        env = {**os.environ, 'PATH': str(self.root) + os.pathsep + os.environ['PATH'],
            'MAKE_CAPTURE': str(self.capture), 'INVENTORY': '\n'.join(self.inventory if inventory is None else inventory) + '\n',
            'RUN_UNIT_TESTS': 'true', 'CI_UNIT_TESTS_SHARD': shard,
            'TEST_RUNNER_ENV': 'DISPATCH_MARKER=preserved', 'DIR_UNIT_TEST_DATA': '/unit-data',
            'DEPENDS_DIR': '/depends', 'HOST': 'host', 'MAKEJOBS': '-j4', **extra}
        result = subprocess.run(['bash', '-c', self.block], cwd=self.root, env=env, capture_output=True)
        record = json.loads(self.capture.read_text()) if self.capture.exists() else None
        return result, record

    def test_default_make_check_is_unchanged(self):
        result, record = self.dispatch('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record['args'], ['-j4', 'check', 'VERBOSE=1'])

    def test_numeric_assignment_is_unchanged_before_integration_removal(self):
        for shard in range(1, 5):
            result, record = self.dispatch(str(shard))
            self.assertEqual(result.returncode, 0, result.stderr)
            settings = dict(arg.split('=', 1) for arg in record['args'] if '=' in arg)
            self.assertEqual(settings['SYSCOIN_TESTS_TO_RUN'].split(),
                [path for path in self.inventory[shard - 1::4] if path != 'test/pq_chainlock_integration_tests.cpp'])
            self.assertEqual(settings['SYSCOIN_PQ_REGISTRY_CASES'], 'remaining')

    def test_dedicated_lanes_retain_make_check_and_environment(self):
        for lane, source, mode in [('registry-population', 'test/pq_registry_tests.cpp', 'population'),
                                   ('chainlock-integration', 'test/pq_chainlock_integration_tests.cpp', '')]:
            result, record = self.dispatch(lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            settings = dict(arg.split('=', 1) for arg in record['args'] if '=' in arg)
            self.assertEqual(settings['SYSCOIN_TESTS_TO_RUN'], source)
            self.assertEqual(settings['SYSCOIN_PQ_REGISTRY_CASES'], mode)
            self.assertIn('check', record['args'])
            self.assertEqual((record['marker'], record['data'], record['library']),
                ('preserved', '/unit-data', '/depends/host/lib'))

    def test_missing_sources_invalid_lanes_and_inventory_errors_fail_closed(self):
        for lane, inventory, extra in [
            ('registry-population', ['test/other.cpp'], {}),
            ('chainlock-integration', ['test/other.cpp'], {}),
            ('wrong-lane', self.inventory, {}),
            ('1;false', self.inventory, {}),
            ('registry-population', self.inventory, {'INVENTORY_STATUS': '7'}),
        ]:
            result, record = self.dispatch(lane, inventory, **extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(record)

    def test_make_failure_and_disabled_unit_phase_are_preserved(self):
        result, record = self.dispatch('registry-population', MAKE_STATUS='9')
        self.assertEqual(result.returncode, 9)
        self.assertIsNotNone(record)
        result, record = self.dispatch('registry-population', RUN_UNIT_TESTS='false')
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(record)


if __name__ == '__main__':
    unittest.main(verbosity=2)
