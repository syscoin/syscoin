# BTC header-node helper build

This directory builds the pinned Bitcoin Core binaries used by the managed
BTC-header policy backend. Managed mode is the runtime default for miners and
sentries that participate in BTCC. Official supported Linux and macOS release
packages bundle the helper. Ordinary developer source builds may opt out.

## What it does

- Pins both the upstream Bitcoin Git commit and source-archive SHA-256 in
  `bitcoin.lock`.
- Applies the audited headers-only patch.
- Auto-detects Bitcoin build system (Autotools for older releases, CMake for newer releases).
- Generates an explicit CMake cross-toolchain from the complete outer
  `HOST`/compiler/sysroot/depends environment instead of reducing `CC` and
  `CXX` to their first argv element.
- Builds `bitcoind` and `bitcoin-cli`.
- Writes outputs to:
  - `<build-root>/src/bin/btcheadernode/bin/bitcoind`
  - `<build-root>/src/bin/btcheadernode/bin/bitcoin-cli`

## Configure / build

From the Syscoin root:

```bash
./autogen.sh
./configure --enable-btcheadernode-build
make -j$(nproc)
```

If the option is not enabled, this build path is skipped. A source build that
omits the helper can still run an ordinary full node. A configured miner or
sentry must either rebuild with the helper or explicitly select external mode
with `-btcheadermanaged=0 -btcheadercmd=<path>`; startup otherwise fails.

When enabled for Linux or macOS release builds, the produced `bitcoind` and
`bitcoin-cli` are installed into the final package `bin/` directory so sentry
operators can use the shipped binaries directly. The macOS application bundle
also contains both executables below
`Contents/Resources/btcheadernode/bin`, where managed runtime discovery looks
for them before startup.

The exact Bitcoin notice is installed as
`share/doc/syscoin/btcheadernode/COPYING.bitcoin-core` on Linux and as
`Contents/Resources/btcheadernode/COPYING.bitcoin-core` in the macOS app. The
build verifies that it is byte-identical to `COPYING` from the pinned Bitcoin
commit before compilation, so source or packaging drift fails closed. Refresh
and verify the notice whenever `bitcoin.lock` changes.

Guix release builds download the pinned HTTPS source archive before entering
the network-isolated container, verify its SHA-256 even when a same-named cache
file already exists, and pass that authenticated file to the helper. A digest
mismatch aborts the release build.

## Lock file

`bitcoin.lock` controls the pinned upstream source:

- `BITCOIN_REPO`: upstream Git URL
- `BITCOIN_REF`: human-readable tag/branch (optional validation anchor)
- `BITCOIN_COMMIT`: immutable commit to build
- `BITCOIN_SOURCE_ARCHIVE_URL`: pinned HTTPS archive location
- `BITCOIN_SOURCE_ARCHIVE_SHA256`: required archive content digest
- `BITCOIN_PATCH`: optional path (relative to `contrib/btcheadernode/`) to apply with `git apply`
- `BITCOIN_PATCH_FORK_REPO`: optional fork repo for patch generation workflow
- `BITCOIN_PATCH_FORK_REF`: optional fork ref for patch generation workflow

Clone mode validates that `BITCOIN_REF` resolves to `BITCOIN_COMMIT`. Archive
mode accepts only content matching `BITCOIN_SOURCE_ARCHIVE_SHA256`; a filename
or locally recomputed but unpinned digest is never sufficient provenance.

## Patch workflow

`HEADERS_ONLY_PATCH_SPEC.md` describes the expected runtime/RPC contract for header-only mode.

To generate `patches/headers-only.diff` from your Bitcoin fork branch:

```bash
contrib/btcheadernode/generate-headers-only-patch.sh \
  --src-root "$(pwd)" \
  --fork-repo https://github.com/syscoin/bitcoin.git \
  --fork-ref headers-only-v30.2
```

If `BITCOIN_PATCH_FORK_REPO` (and optionally `BITCOIN_PATCH_FORK_REF`) are set in
`bitcoin.lock`, you can omit `--fork-repo/--fork-ref`.

Then set `BITCOIN_PATCH` in `bitcoin.lock`:

- `BITCOIN_PATCH=patches/headers-only.diff`

Re-run `make` (or call the build script directly).

## Direct invocation

```bash
contrib/btcheadernode/build-bitcoin-header-node.sh \
  --src-root "$(pwd)" \
  --build-root "$(pwd)"
```

Use `--force-clean` if you want to discard the cached Bitcoin source/build workdirs before rebuilding.

Optional environment variables for direct invocation:

- `BTCHEADERNODE_SOURCE_ARCHIVE`: local copy of the exact pinned archive. Its
  SHA-256 is always verified before extraction.
- `BTCHEADERNODE_STATIC_LINK_FLAGS`: linker flags for `bitcoind`/`bitcoin-cli`
  (defaults to `-static-libstdc++` on non-macOS hosts and empty on macOS).
- `LDFLAGS`: optional base linker flags inherited from the outer build (for Guix alignment).

## Security contract tests

The lightweight cross-matrix smoke test verifies that Darwin and Linux target,
SDK/sysroot, compiler, linker, and depends settings survive toolchain
generation:

```bash
contrib/btcheadernode/test-toolchain-generation.sh
```

Given a downloaded copy of the pinned archive, the provenance regression also
proves that a same-named cache artifact with modified content is rejected
before extraction or compilation:

```bash
contrib/btcheadernode/test-source-provenance.sh /path/to/bitcoin-v30.2.tar.gz
```

After building the pinned helper, run the black-box contract test:

```bash
python3 contrib/btcheadernode/test-headers-only.py \
  --bitcoind ./src/bin/btcheadernode/bin/bitcoind \
  --bitcoin-cli ./src/bin/btcheadernode/bin/bitcoin-cli
```

It starts the real patched binary, submits valid competing regtest header
branches beyond genesis, checks canonical `getblockhash`, confirmation and
`getchaintips` semantics, proves `-blocksonly=0` cannot defeat the managed
profile, and repeats the checks after restart. CI downloads only the pinned
archive digest and runs the same native build and contract.

Managed signet is intentionally not supported: header proof of work cannot
authenticate the required signet coinbase solution. Use external mode with a
fully validating Bitcoin signet node instead.
