#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Small regressions for platform-specific functional-test inputs."""

import socket
import unittest
from unittest.mock import patch

from feature_discover import is_valid_ipv6_address
from feature_pruning import PruneTest


class TestPortability(unittest.TestCase):
    def test_scoped_ipv6_uses_portable_parser_input(self):
        # Windows inet_pton rejects the zone suffix even when other platforms
        # accept it. Always supply the unscoped address to the system parser.
        with patch('feature_discover.socket.inet_pton', wraps=socket.inet_pton) as parse:
            self.assertTrue(is_valid_ipv6_address('fe80::1%10'))
            parse.assert_called_once_with(socket.AF_INET6, 'fe80::1')

    def test_scoped_ipv6_discovery(self):
        for address in ('::1', '2001:db8::1', 'fe80::1%10', 'fe80::1%eth0'):
            with self.subTest(address=address):
                self.assertTrue(is_valid_ipv6_address(address))
        for address in ('invalid%10', '127.0.0.1%10', 'fe80::1%', 'fe80::1%1%2'):
            with self.subTest(address=address):
                self.assertFalse(is_valid_ipv6_address(address))

    def test_pruning_transitions_preserve_chain_parameters(self):
        # No node processes or datadirs are needed to validate argument binding.
        test = object.__new__(PruneTest)
        test.set_test_params()
        for node_number in range(test.num_nodes):
            original = list(test.extra_args[node_number])
            for overrides in (('-prune=1',), ('-prune=550',), ('-prune=550', '-blockfilterindex=1')):
                with self.subTest(node=node_number, overrides=overrides):
                    result = test.pruning_args(node_number, *overrides)
                    self.assertEqual(result[:len(original)], original)
                    self.assertEqual(result[len(original):], list(overrides))
                    self.assertIn('-dip3params=2000:2000', result)
                    self.assertEqual(test.extra_args[node_number], original)


if __name__ == '__main__':
    unittest.main()
