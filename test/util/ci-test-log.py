#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Print a bounded GitHub Actions annotation for a failed Boost source."""

import os
import re
import sys


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FAILURE = re.compile(
    r'^.+\([0-9]+\): (?:fatal )?error: in "'
    r'|^(?:==[0-9]+==)?(?:ERROR|WARNING|SUMMARY): (?:Address|Leak|Thread|Memory|UndefinedBehavior)Sanitizer:'
    r'|^AddressSanitizer:DEADLYSIGNAL'
    r'|^.+:[0-9]+:[0-9]+: runtime error:'
    r'|^\*\*\* [0-9]+ failures? (?:is|are) detected'
)


def escape(value, property_value=False):
    """Match actions/toolkit's workflow-command escaping (percent first)."""
    value = value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    if property_value:
        value = value.replace(':', '%3A').replace(',', '%2C')
    return value


def failure_summary(logfile):
    """Select the first Boost/sanitizer diagnostic, otherwise show the last line."""
    last_line = ''
    try:
        with open(logfile, 'rb') as log:
            for raw in log:
                line = ANSI_ESCAPE.sub('', raw.decode('utf-8', errors='replace')).strip()
                if line:
                    last_line = line[:2000]
                    if FAILURE.search(line):
                        return last_line
    except OSError:
        return 'Test process failed; log could not be read.'
    if last_line:
        return 'No recognized failure marker; last log line: ' + last_line
    return 'Test process failed; log is empty.'


def annotation(source, summary):
    prefix = f'::error file={escape(source, True)}::'
    # One write below Linux PIPE_BUF keeps annotations from interleaving under
    # make -j. Truncate before escaping so UTF-8 and escape sequences stay whole.
    if len(prefix.encode('utf-8')) > 2000:
        prefix = '::error::'
        summary = source + ': ' + summary
    while len((prefix + escape(summary) + '\n').encode('utf-8')) > 4000:
        summary = summary[:len(summary) // 2] + '...'
    return (prefix + escape(summary) + '\n').encode('utf-8')


if __name__ == '__main__':
    source, logfile = sys.argv[1:]
    os.write(sys.stdout.fileno(), annotation(source, failure_summary(logfile)))
