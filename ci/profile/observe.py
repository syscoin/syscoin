#!/usr/bin/env python3
"""Bound equal-work signing comparisons and sample Linux CPU/memory evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


class Failure(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


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
            fields = stat["value"].rsplit(")", 1)[-1].split()
            try:
                record.update(state=fields[0], user_ticks=int(fields[11]),
                              system_ticks=int(fields[12]))
            except (IndexError, ValueError):
                record["stat_unavailable"] = "malformed"
        else:
            record["stat_unavailable"] = stat["unavailable"]
        status = read_text(task / "status")
        record["allowed_cpus"] = next(
            (line.split(":", 1)[1].strip() for line in status.get("value", "").splitlines()
             if line.startswith("Cpus_allowed_list:")), "unavailable")
        result["threads"].append(record)
    return result


def platform_state():
    return {
        "cpu_max": read_text(Path("/sys/fs/cgroup/cpu.max")),
        "cpu_stat": read_text(Path("/sys/fs/cgroup/cpu.stat")),
        "cpuset_effective": read_text(Path("/sys/fs/cgroup/cpuset.cpus.effective")),
        "cgroup_membership": read_text(Path("/proc/self/cgroup")),
        # Field 9 on each cpu line is steal time in clock ticks.
        "cpu_lines": [line for line in Path("/proc/stat").read_text().splitlines()
                      if line.startswith("cpu")],
    }


def topology(allowed=None, cpu_root=Path("/sys/devices/system/cpu")):
    allowed = sorted(os.sched_getaffinity(0) if allowed is None else allowed)
    if len(allowed) < 4:
        raise Failure("need four allowed logical CPUs; refusing a different comparison")
    entries = []
    for cpu in allowed:
        directory = cpu_root / f"cpu{cpu}/topology"
        try:
            entries.append({"cpu": cpu,
                            "package": int((directory / "physical_package_id").read_text()),
                            "core": int((directory / "core_id").read_text()),
                            "siblings": (directory / "thread_siblings_list").read_text().strip()})
        except (OSError, ValueError):
            raise Failure("CPU topology unavailable; no affinity assumptions made")
    selected_four = allowed[:4]
    selected_two = []
    seen = set()
    for entry in entries:
        identity = (entry["package"], entry["core"])
        if entry["cpu"] in selected_four and identity not in seen:
            seen.add(identity)
            selected_two.append(entry["cpu"])
    if len(selected_two) < 2:
        raise Failure("selected logical CPUs do not expose two distinct cores")
    return {"allowed_cpus": allowed, "topology": entries,
            "selected_four": selected_four, "selected_two": selected_two[:2]}


def emit(stream, record, console=False):
    line = json.dumps(record, sort_keys=True)
    stream.write(line + "\n")
    stream.flush()
    if console:
        print(line, flush=True)


def stop_all(processes):
    """TERM all groups together, then KILL stragglers, with two shared 5s caps."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        pending = [process for process in processes if process.poll() is None]
        # A child leader may have exited while a descendant still owns a pipe.
        # These groups were created exclusively for this diagnostic invocation.
        for process in processes:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 5
        for process in pending:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
    if any(process.poll() is None for process in processes):
        raise Failure("diagnostic child did not terminate within cleanup cap")


def run_mode(mode, commands, deadline, metrics, events, interval=5):
    """Each command emits ready, awaits newline, then emits a sign batch result."""
    start = time.monotonic()
    children = []
    records = []
    release_time = None
    verification_released = False
    sign_end_times = []
    selector = selectors.DefaultSelector()
    next_sample = start
    try:
        for label, command, expected_count in commands:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       start_new_session=True)
            child = {"label": label, "process": process, "ready": False, "buffer": b"",
                     "expected_count": expected_count, "complete": False, "sign_complete": False}
            children.append(child)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, child)
        while selector.get_map() or any(child["process"].poll() is None for child in children):
            now = time.monotonic()
            if now >= deadline:
                raise Failure(f"{mode}: global comparison deadline expired", 124)
            if now >= next_sample:
                emit(metrics, {"mode": mode, "event": "sample", "elapsed_s": now - start,
                               "processes": [sample(child["process"].pid) for child in children
                                             if child["process"].poll() is None],
                               "platform": platform_state()})
                next_sample = now + interval
            for key, _ in selector.select(timeout=min(0.1, max(0, deadline - now))):
                child = key.data
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    if child["buffer"]:
                        raise Failure(f"{mode}: truncated child event")
                    continue
                child["buffer"] += data
                if len(child["buffer"]) > 65536:
                    raise Failure(f"{mode}: child output exceeded line buffer")
                while b"\n" in child["buffer"]:
                    line, child["buffer"] = child["buffer"].split(b"\n", 1)
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        raise Failure(f"{mode}: malformed child event")
                    if not isinstance(event, dict):
                        raise Failure(f"{mode}: child event is not an object")
                    observed = time.monotonic()
                    record = {"mode": mode, "child": child["label"], "pid": child["process"].pid,
                              "observed_elapsed_s": observed - start, "data": event}
                    records.append(record)
                    if len(records) > 256:
                        raise Failure(f"{mode}: child event count exceeded diagnostic cap")
                    emit(events, record, console=True)
                    if event.get("event") == "ready":
                        if child["ready"] or event.get("member_count") != child["expected_count"]:
                            raise Failure(f"{mode}: unexpected ready event")
                        child["ready"] = True
                    elif event.get("phase") == "sign" and event.get("event") == "batch_complete":
                        if release_time is None or child["sign_complete"]:
                            raise Failure(f"{mode}: signing before release or duplicate completion")
                        if event.get("operations") != child["expected_count"]:
                            raise Failure(f"{mode}: unequal signing work")
                        child["sign_complete"] = True
                        sign_end_times.append(observed)
                    elif event.get("event") == "profile_complete":
                        if not verification_released or event.get("signatures_verified") != child["expected_count"]:
                            raise Failure(f"{mode}: missing signature verification")
                        child["complete"] = True
            if release_time is None and all(child["ready"] for child in children):
                release_time = time.monotonic()
                emit(events, {"mode": mode, "event": "barrier_release",
                              "elapsed_s": release_time - start}, console=True)
                for child in children:
                    child["process"].stdin.write(b"\n")
                    child["process"].stdin.flush()
            if not verification_released and all(child["sign_complete"] for child in children):
                verification_released = True
                emit(events, {"mode": mode, "event": "verification_release",
                              "elapsed_s": time.monotonic() - start}, console=True)
                for child in children:
                    child["process"].stdin.write(b"\n")
                    child["process"].stdin.flush()
                    child["process"].stdin.close()
            for child in children:
                code = child["process"].poll()
                if code is not None and code != 0:
                    raise Failure(f"{mode}: child {child['label']} exited {code}",
                                  code if code > 0 else 128 - code)
        if release_time is None or not all(child["complete"] and child["sign_complete"]
                                           for child in children):
            raise Failure(f"{mode}: child exited without completing signing and verification")
        batches = [record["data"] for record in records
                   if record["data"].get("phase") == "sign"
                   and record["data"].get("event") == "batch_complete"]
        summary = {"mode": mode, "event": "mode_complete",
                   "signatures_verified": sum(child["expected_count"] for child in children),
                   "controller_sign_wall_s": max(sign_end_times) - release_time,
                   "sign_user_s": sum(batch["user_s"] for batch in batches),
                   "sign_system_s": sum(batch["system_s"] for batch in batches),
                   "sum_process_peak_rss_kib": sum(batch["peak_rss_kib"] for batch in batches)}
        emit(events, summary, console=True)
        return summary
    finally:
        try:
            stop_all([child["process"] for child in children])
        finally:
            selector.close()
            for child in children:
                for pipe in (child["process"].stdin, child["process"].stdout):
                    if pipe is not None:
                        pipe.close()


def verify_signatures(directory):
    result = {}
    for member in range(4):
        contents = [(directory / mode / f"member-{member}.sig").read_bytes()
                    for mode in ("threads2", "threads4", "processes4")]
        if any(len(item) != 7856 for item in contents) or any(item != contents[0] for item in contents):
            raise Failure(f"member {member}: signature length or cross-mode equality failed")
        result[str(member)] = hashlib.sha256(contents[0]).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 1200:
        parser.error("duration must be between 1 and 1200 seconds")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.seconds
    cpu = topology()
    with (args.output_dir / "metrics.jsonl").open("w", encoding="utf-8") as metrics, \
         (args.output_dir / "events.jsonl").open("w", encoding="utf-8") as events:
        emit(events, {"event": "platform", **cpu, **platform_state()}, console=True)
        results = []
        for mode, cpus in (("threads2", cpu["selected_two"]), ("threads4", cpu["selected_four"]),
                           ("processes4", cpu["selected_four"])):
            directory = args.output_dir / mode
            directory.mkdir()
            common = [str(args.binary.resolve()), "--output-dir", str(directory)]
            if mode == "processes4":
                commands = [(str(member), common + ["--workers", "1", "--cpus", str(core),
                             "--member", str(member)], 1) for member, core in enumerate(cpus)]
            else:
                commands = [("all", common + ["--workers", str(len(cpus)), "--cpus",
                             ",".join(map(str, cpus))], 4)]
            results.append(run_mode(mode, commands, deadline, metrics, events))
        summary = {"event": "comparison_complete", "modes": results,
                   "signature_sha256": verify_signatures(args.output_dir)}
        emit(events, summary, console=True)
        (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Failure as error:
        print(f"comparison failed: {error}", flush=True)
        raise SystemExit(error.code)
