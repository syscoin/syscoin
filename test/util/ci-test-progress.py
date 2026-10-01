#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Best-effort, bounded progress from independent CI logfile read handles."""

import argparse
import errno
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import time


POLL_SECONDS = 0.25
READ_BUDGET = 65536
MAX_LINE_BYTES = 8192
MAX_FILES = 16
FUNCTIONAL_GLOB = 'test_runner_*/feature_governance_dynamic_*/test_framework.log'
ANSI_ESCAPE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
NATIVE = re.compile(r'(?:^|: )(?:(?:Entering|Leaving) test case "[A-Za-z0-9_]+"|PQ population )')
FUNCTIONAL = re.compile(r'\((?:INFO|WARNING|ERROR)\):')


class StopRequested(Exception):
    pass


def parent_exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError as error:
        return error.errno == errno.EPERM


def progress_record(mode, elapsed, raw):
    line = ANSI_ESCAPE.sub('', raw.decode('utf-8', errors='replace'))
    line = ''.join(char if char.isprintable() else ' ' for char in line).strip()
    if not (NATIVE if mode == 'native' else FUNCTIONAL).search(line):
        return None
    # The fixed prefix and removal of every control character prevent log
    # contents from becoming a separate terminal/workflow command.
    prefix = f'CI progress {mode} +{elapsed:.1f}s | '
    body = line.encode('utf-8')[:3500].decode('utf-8', errors='ignore')
    return (prefix + body + '\n').encode('utf-8')


class LogReader:
    def __init__(self, path):
        self.path = path
        self.fd = None
        self.pending = bytearray()
        self.discarding = False

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read(self, emit):
        """Read at most one budget, keeping only bounded complete records."""
        try:
            if self.fd is None:
                self.fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                    self.close()
                    return
            if os.fstat(self.fd).st_size < os.lseek(self.fd, 0, os.SEEK_CUR):
                os.lseek(self.fd, 0, os.SEEK_SET)
                self.pending.clear()
                self.discarding = False
            remaining = READ_BUDGET
            while remaining:
                chunk = os.read(self.fd, min(4096, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                parts = chunk.split(b'\n')
                for index, part in enumerate(parts):
                    complete = index + 1 < len(parts)
                    if not self.discarding:
                        if len(self.pending) + len(part) > MAX_LINE_BYTES:
                            self.pending.clear()
                            self.discarding = True
                        else:
                            self.pending.extend(part)
                    if complete:
                        if not self.discarding:
                            emit(bytes(self.pending))
                        self.pending.clear()
                        self.discarding = False
        except OSError:
            self.close()


class Follower:
    def __init__(self, mode, path, output=None):
        self.mode = mode
        self.path = Path(path)
        self.started = time.monotonic()
        self.output = output or self.write
        self.readers = {}
        self.existing = set(self.path.glob(FUNCTIONAL_GLOB)) if mode == 'functional' else set()
        if mode == 'native':
            self.readers[self.path] = LogReader(self.path)

    @staticmethod
    def write(record):
        # Never change flags or seek on the inherited stdout descriptor.
        # A busy output sink may lose diagnostic lines; the full log is intact.
        try:
            if select.select([], [sys.stdout.fileno()], [], 0)[1]:
                os.write(sys.stdout.fileno(), record)
        except (OSError, ValueError):
            pass

    def poll(self):
        if self.mode == 'functional':
            for path in sorted(self.path.glob(FUNCTIONAL_GLOB)):
                if path not in self.existing and path not in self.readers and len(self.readers) < MAX_FILES:
                    self.readers[path] = LogReader(path)
        for reader in self.readers.values():
            reader.read(self.emit)

    def emit(self, raw):
        record = progress_record(self.mode, time.monotonic() - self.started, raw)
        if record is not None:
            self.output(record)

    def close(self):
        for reader in self.readers.values():
            reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('native', 'functional'), required=True)
    parser.add_argument('--path', type=Path, required=True)
    parser.add_argument('--parent-pid', type=int, required=True)
    parser.add_argument('--ready-file', type=Path)
    args = parser.parse_args()
    if args.parent_pid <= 1:
        parser.error('--parent-pid must be greater than one')

    def stop(_signum, _frame):
        raise StopRequested

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    follower = Follower(args.mode, args.path)
    try:
        # Functional callers wait briefly for this snapshot acknowledgement
        # before starting a new runner, so a new log cannot be mistaken for old.
        if args.ready_file is not None:
            args.ready_file.touch(exist_ok=False)
        while parent_exists(args.parent_pid):
            follower.poll()
            time.sleep(POLL_SECONDS)
    except StopRequested:
        pass
    finally:
        # One final bounded pass, not a wait for EOF or a partial line.
        try:
            follower.poll()
        except StopRequested:
            pass
        finally:
            follower.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
