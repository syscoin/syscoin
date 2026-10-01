#!/usr/bin/env python3
"""Bound one diagnostic process and sample Linux CPU, scheduler and memory data."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def read_text(path):
    try:
        return {"value": path.read_text().strip()}
    except (OSError, UnicodeError) as error:
        return {"unavailable": type(error).__name__}


def sample(pid, proc_root=Path("/proc")):
    process = proc_root / str(pid)
    result = {"pid": pid, "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}
    status = read_text(process / "status")
    if "value" in status:
        result["memory"] = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in status["value"].splitlines()
            if line.startswith(("VmRSS:", "VmHWM:", "Threads:"))
        }
    else:
        result["memory"] = status
    result["threads"] = []
    try:
        tasks = sorted((process / "task").iterdir(), key=lambda path: int(path.name))
    except OSError as error:
        result["tasks_unavailable"] = type(error).__name__
        return result
    result["threads_truncated"] = len(tasks) > 32
    for task in tasks[:32]:
        record = {"tid": int(task.name), "wchan": read_text(task / "wchan"),
                  "schedstat": read_text(task / "schedstat")}
        stat = read_text(task / "stat")
        if "value" in stat:
            # Fields after the final ')' begin with field 3 (state).
            fields = stat["value"].rsplit(")", 1)[-1].split()
            try:
                record.update(state=fields[0], user_ticks=int(fields[11]),
                              system_ticks=int(fields[12]))
            except (IndexError, ValueError):
                record["stat_unavailable"] = "malformed"
        else:
            record["stat_unavailable"] = stat["unavailable"]
        result["threads"].append(record)
    return result


def stop(process):
    """Bound cleanup of the entire diagnostic process group, including children."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait(timeout=5)


def observe(command, seconds, output, interval=5):
    start = time.monotonic()
    process = subprocess.Popen(command, start_new_session=True)
    timed_out = False
    try:
        while process.poll() is None:
            record = sample(process.pid)
            record.update(event="sample", elapsed_s=time.monotonic() - start)
            output.write(json.dumps(record, sort_keys=True) + "\n")
            output.flush()
            remaining = seconds - (time.monotonic() - start)
            if remaining <= 0:
                timed_out = True
                stop(process)
                break
            try:
                process.wait(timeout=min(interval, remaining))
            except subprocess.TimeoutExpired:
                pass
    finally:
        if process.poll() is None:
            stop(process)
    exit_code = 124 if timed_out else process.returncode
    if exit_code < 0:
        exit_code = 128 - exit_code
    output.write(json.dumps({"event": "process_exit", "returncode": process.returncode,
                             "exit_code": exit_code, "timed_out": timed_out,
                             "elapsed_s": time.monotonic() - start}) + "\n")
    output.flush()
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not 1 <= args.seconds <= 1200 or not command:
        parser.error("require a command and a duration between 1 and 1200 seconds")
    with args.output.open("w", encoding="utf-8") as output:
        return observe(command, args.seconds, output)


if __name__ == "__main__":
    raise SystemExit(main())
