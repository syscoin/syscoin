# Bounded signing scaling comparison

This diagnostic branch is based on PR609 at
67ddd5e05a8f63af0d8dd46ae0ab3ef317515145. Do not merge its workflow exclusions.
The inherited workflows exclude only codex/diagnostics/pq-scaling-67ddd5e0;
the new workflow runs only on that branch. PR609 and full-suite coverage remain
unchanged. The diagnostic does not invoke the full population test.

The same Ubuntu 24.04 runner class and container, Clang 18 Autotools configuration,
six production crypto objects, sanitizer flags, runtime options and suppression
files are used. V=1 records actual compile/link commands. Production inputs are
checked against the pinned parent before execution. No crypto implementation,
population size, assertion or suppression is changed.

Each mode performs exactly four registration signatures using the same fixed
member identities, population key seeds, registration domain and synthetic
32-byte digests. The modes run sequentially on one runner:

1. Two threads, one on each of two distinct reported cores; each signs two members
2. Four threads with fixed member-to-logical-CPU assignment
3. Four separate processes with the identical member-to-logical-CPU assignment

Every process finishes key generation before a controller barrier releases
signing. A second barrier prevents verification and file writes until every
process finishes signing. All twelve signatures are verified, and each member's
signature bytes must match across all three modes. Process startup, key generation
and verification are excluded from the controller signing interval. The interval
includes bounded barrier release and event-delivery overhead; individual worker
intervals exclude progress output.

The allowed affinity set, reported package/core/SMT topology, visible cgroup CPU
quota/counters and guest CPU counters (including steal time) are recorded. Two
reported cores and four allowed logical CPUs are required; missing/incompatible
topology fails rather than silently changing the comparison. Every worker pins
itself inside the existing allowed set and verifies its observed CPU ID. Host
settings, privileges and quotas are not changed. Guest topology and visible
cgroup limits cannot establish all host-side resource constraints.

Per-operation wall time, thread CPU and context switches are recorded. A separate
controller samples each process's RSS, thread state, CPU affinity, wait channel,
CPU ticks and scheduler statistics every five seconds. Summed per-process peak
RSS is an upper bound, not a simultaneous memory peak; raw samples permit a
separate aggregate-RSS calculation. Unavailable fields are explicitly marked.

All three modes share one 20-minute process deadline, including their setup.
Cleanup sends TERM to all diagnostic process groups and then KILL to stragglers,
with two shared five-second limits. The container has a 25-minute deadline and
removal trap; the job has a 30-minute maximum. Build, sanitizer, affinity, protocol,
signature and deadline failures remain failures. Logs, events, metrics and the
summary are uploaded for seven days even on failure.

These four samples are a controlled primitive comparison, not the full registry
case or its exact transaction transcripts. Mode order is fixed, so cache,
frequency and time-dependent host effects remain limitations. Separate-process
improvement can support investigating shared-process runtime effects; two-thread
improvement can support avoiding SMT contention. Neither proves a particular
runtime call stack or justifies suppressing sanitizer checks. No paid resource
or full-population rerun is included.
