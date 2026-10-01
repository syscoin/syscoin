# Bounded registration signing diagnostic

This branch-only diagnostic is based on PR609 at
`67ddd5e05a8f63af0d8dd46ae0ab3ef317515145`. Do not merge its workflow exclusions
into the PR. The three inherited workflows exclude only
`codex/diagnostics/pq-signing-67ddd5e0`; the new workflow runs only on that branch.
It does not rerun or replace the full population test.

The job uses the same `ubuntu-24.04` runner class and Ubuntu 24.04 container,
Clang 18 configuration, ASan/LSan/UBSan/integer/float-divide instrumentation,
runtime options and suppression files as the failing native lane. It generates
the real Autotools makefiles and builds only the four SLH C objects, two C++
wrapper objects and diagnostic driver. `V=1` records actual compile and link
commands. No production source or sanitizer setting is changed. The standalone
executable omits the full node/Boost fixture and its other libraries.

Four keys use the exact population seed formula for members 0, 267, 400 and 800.
The unchanged production `slhdsa::SignDeterministic` receives the registration
domain `SYS_PQ_GLOBAL_REGISTER_V1` and distinct deterministic 32-byte sample
digests. These are synthetic inputs, not the full registry transaction hashes.
The same four inputs are signed with one worker and then four workers, verified,
and checked for byte-identical deterministic signatures. Verification and
progress output are outside individual signing measurements. The serial-first
order may warm runtime caches; four samples do not establish production latency
or predict the complete stateful population case.

Each operation records wall time, thread user/system CPU and context switches.
A separate Python process samples `/proc` every five seconds for thread CPU
ticks, state, wait channel and scheduler statistics plus process RSS/high-water
memory. `schedstat` fields are runtime ns, runnable-queue wait ns and timeslices;
zeros can mean scheduler accounting is disabled. Unavailable fields are marked,
not treated as zero work. Samples and CPU clocks can distinguish sustained CPU
work, descheduling and observed waits, but do not identify a call stack or prove
the cause of an earlier full-test timeout.

The diagnostic process has a 20-minute deadline with bounded TERM/KILL cleanup;
the container has a 25-minute deadline and removal trap, and the whole job has a
30-minute maximum. Build/setup time consumes part of that overall budget. Any
sanitizer, build, verification or deadline failure remains a failing job. Full
logs and metrics are uploaded for seven days even on failure. No stronger runner,
new suppression, reduced population or full-suite invocation is part of this run.
