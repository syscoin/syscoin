# Porting ledger: removed, relocated, and unmatched paths

Bitcoin `e4fef4ae65c68ebd34774700dc4801c24313d469` → Syscoin `d5fc88adc9992a25f26641ddb174a76e7bf64407`.

This records integration context and review inventory. A missing path or removed hunk does not prove deleted functionality: code may have moved, been replaced, or arrived from another upstream. Before/after text for shared C/C++ changes is preserved in `audit.json.gz`.

## Verified moves and removed-code context

| Area | What a future merge must reconcile |
| --- | --- |
| Reindex completion | Bitcoin cleared `WriteReindexing(false)`, `fReindex`, and logged completion immediately after file scanning. The target removes that early block near `src/node/blockstorage.cpp:1613` and finalizes after best-chain activation at `1654–1667`, with persistence checks and a pending-NEVM-repair exception. The old location needs an explicit move note; see network/storage finding 11. |
| Block-index dirty sets | `src/node/blockstorage.cpp:713–729` collects dirty entries before writing, then clears them only after successful `WriteBatchSync`. The original erases inside the collection loops were removed. The current post-write SYSCOIN comment covers only part of this change; preserve the ordering on a port. Local provenance is `486933e22fffbabb07d5f10bb7ebcd20adeae9b7`. |
| BIP30 | Bitcoin-chain historical exceptions and optimization guards were removed/disabled in `src/validation.cpp:4942–4966,5347–5432`. A future merge must preserve the intended fork behavior rather than restoring Bitcoin-specific chain history merely to resolve a diff. See C01. |
| AuxPoW header split | Bitcoin header fields/helpers moved out of the original `CBlockHeader` shape into the pure-header/AuxPoW representation. Treat the apparent deletions as a representation change; see C02. |
| Compression files | The removed `src/compressor.cpp` and `.h` were changed under Syscoin commit `9b0d1a2e223757a8ce7d77d4fb8923ceed916779` (SPTs). Compression support is present in `src/primitives/transaction.h`, including `TxOutCompression` near line 567, used by `src/coins.h:64,73`. Reconcile the relocated/customized implementation instead of restoring old files wholesale. |
| Peer state | The former `Peer` structure in `src/net_processing.cpp` is substantially relocated to `src/net_processing.h:576–852`. `CanServeBlocks` still exists at `src/net_processing.cpp:3623`. The old bodies are not evidence those features disappeared. |
| Node snapshots/callbacks | `NodesSnapshot` still exists at `src/net.h:1570`; callback and filtering changes need review at their current definitions. `NodeFullyConnected` is already preserved as a commented declaration near line 1710. |
| Pruned-file cleanup | The latest patch already retains the old Bitcoin cleanup call as commented code plus a SYSCOIN relocation explanation near `src/validation.cpp:10306`. It is not another confirmed missing-tag finding. |
| Generic utility changes | The removed `src/util/getuniquepath.cpp/.h` files and the changed implementation of the still-present `src/compat/endian.h` need separate provenance/replacement review. Do not classify generic maintenance changes as fork rules solely because they differ from rc3. |

## Whole upstream paths without a target match

40 paths. Matching handles exact paths and Bitcoin/Syscoin product renames, not arbitrary moves.

| Upstream path | Category |
| --- | --- |
| `build-aux/m4/bitcoin_runtime_lib.m4` | build_config_other |
| `contrib/devtools/gen-bitcoin-conf.sh` | build_config_other |
| `contrib/devtools/headerssync-params.py` | build_config_other |
| `contrib/devtools/test_utxo_snapshots.sh` | build_config_other |
| `contrib/guix/patches/glibc-2.27-fcommon.patch` | build_config_other |
| `contrib/guix/patches/glibc-2.27-guix-prefix.patch` | build_config_other |
| `contrib/guix/patches/glibc-2.27-no-librt.patch` | build_config_other |
| `contrib/guix/patches/glibc-2.27-powerpc-ldbrx.patch` | build_config_other |
| `contrib/guix/patches/glibc-2.27-riscv64-Use-__has_include-to-include-asm-syscalls.h.patch` | build_config_other |
| `contrib/guix/patches/vmov-alignment.patch` | build_config_other |
| `contrib/seeds/.gitignore` | build_config_other |
| `contrib/seeds/asmap.py` | build_config_other |
| `contrib/seeds/nodes_main_manual.txt` | documentation_or_asset |
| `contrib/signet/README.md` | documentation_or_asset |
| `contrib/signet/getcoins.py` | build_config_other |
| `contrib/signet/miner` | build_config_other |
| `contrib/tracing/mempool_monitor.py` | build_config_other |
| `contrib/verify-binaries/README.md` | documentation_or_asset |
| `contrib/verify-binaries/test.py` | build_config_other |
| `contrib/verify-binaries/verify.py` | build_config_other |
| `depends/packages/native_cctools.mk` | build_config_other |
| `depends/packages/native_clang.mk` | build_config_other |
| `depends/packages/native_libtapi.mk` | build_config_other |
| `depends/patches/native_libtapi/disable_zlib.patch` | build_config_other |
| `depends/patches/qt/fast_fixed_dtoa_no_optimize.patch` | build_config_other |
| `depends/patches/qt/use_android_ndk23.patch` | build_config_other |
| `depends/patches/zeromq/netbsd_kevent_void.patch` | build_config_other |
| `src/compressor.cpp` | production |
| `src/compressor.h` | production |
| `src/util/getuniquepath.cpp` | production |
| `src/util/getuniquepath.h` | production |
| `test/functional/feature_signet.py` | test |
| `test/functional/feature_txindex_compatibility.py` | test |
| `test/functional/feature_unsupported_utxo_db.py` | test |
| `test/functional/mempool_compatibility.py` | test |
| `test/functional/tool_signet_miner.py` | test |
| `test/functional/wallet_backwards_compatibility.py` | test |
| `test/functional/wallet_inactive_hdchains.py` | test |
| `test/functional/wallet_upgradewallet.py` | test |
| `test/lint/lint-files.py` | test |

## Pure code-removal hunks and annotated removal context

These are the hunks with no remaining executable tokens on the target side. Other replacement hunks can also remove upstream statements; inspect their before/after text in the JSON.

| Target path | Bitcoin start/count | Syscoin anchor/count | Classification |
| --- | --- | --- | --- |
| `src/bench/checkblock.cpp` | 32 / 2 | 32 / 2 | local_removal_context |
| `src/bench/checkblock.cpp` | 51 / 1 | 51 / 0 | removed_upstream_code |
| `src/bench/checkblock.cpp` | 55 / 1 | 55 / 2 | local_removal_context |
| `src/chainparamsseeds.h` | 901 / 88 | 36 / 2 | removed_upstream_code |
| `src/coins.h` | 12 / 1 | 12 / 0 | removed_upstream_code |
| `src/common/run_command.cpp` | 39 / 1 | 138 / 0 | removed_upstream_code |
| `src/compat/assumptions.h` | 13 / 14 | 13 / 0 | removed_upstream_code |
| `src/compat/byteswap.h` | 12 / 1 | 13 / 0 | removed_upstream_code |
| `src/compat/byteswap.h` | 18 / 1 | 36 / 1 | removed_upstream_code |
| `src/compat/byteswap.h` | 41 / 1 | 62 / 0 | removed_upstream_code |
| `src/compat/byteswap.h` | 55 / 3 | 78 / 0 | removed_upstream_code |
| `src/compat/endian.h` | 8 / 4 | 8 / 0 | removed_upstream_code |
| `src/compat/endian.h` | 151 / 89 | 73 / 0 | removed_upstream_code |
| `src/consensus/params.h` | 11 / 1 | 11 / 0 | removed_upstream_code |
| `src/crypto/common.h` | 89 / 21 | 85 / 0 | removed_upstream_code |
| `src/dbwrapper.cpp` | 249 / 1 | 249 / 1 | removed_upstream_code |
| `src/dummywallet.cpp` | 33 / 1 | 35 / 0 | removed_upstream_code |
| `src/headerssync.cpp` | 24 / 1 | 26 / 1 | removed_upstream_code |
| `src/kernel/chainparams.cpp` | 258 / 1 | 387 / 1 | removed_upstream_code |
| `src/kernel/chainparams.cpp` | 270 / 6 | 419 / 1 | removed_upstream_code |
| `src/kernel/chainparams.cpp` | 378 / 9 | 521 / 0 | removed_upstream_code |
| `src/kernel/chainparams.cpp` | 504 / 4 | 740 / 4 | removed_upstream_code |
| `src/net.cpp` | 3475 / 2 | 4100 / 0 | local_removal_context |
| `src/net.h` | 958 / 1 | 1023 / 0 | removed_upstream_code |
| `src/net.h` | 1382 / 2 | 1723 / 0 | removed_upstream_code |
| `src/net.h` | 1585 / 7 | 1938 / 0 | removed_upstream_code |
| `src/net.h` | 1593 / 29 | 1939 / 0 | removed_upstream_code |
| `src/net_processing.cpp` | 17 / 1 | 17 / 1 | removed_upstream_code |
| `src/net_processing.cpp` | 190 / 215 | 2378 / 0 | removed_upstream_code |
| `src/net_processing.cpp` | 532 / 3 | 2610 / 0 | removed_upstream_code |
| `src/net_processing.cpp` | 544 / 1 | 2619 / 1 | removed_upstream_code |
| `src/net_processing.cpp` | 1116 / 5 | 3216 / 0 | removed_upstream_code |
| `src/node/blockstorage.cpp` | 1034 / 1 | 1322 / 0 | removed_upstream_code |
| `src/node/blockstorage.cpp` | 1166 / 3 | 1613 / 0 | local_removal_context |
| `src/node/blockstorage.h` | 159 / 1 | 204 / 0 | removed_upstream_code |
| `src/primitives/block.h` | 48 / 7 | 64 / 0 | removed_upstream_code |
| `src/primitives/transaction.h` | 147 / 43 | 207 / 0 | removed_upstream_code |
| `src/qt/clientmodel.h` | 13 / 1 | 15 / 0 | removed_upstream_code |
| `src/qt/signverifymessagedialog.cpp` | 128 / 1 | 130 / 1 | removed_upstream_code |
| `src/qt/syscoingui.cpp` | 395 / 67 | 416 / 0 | removed_upstream_code |
| `src/qt/syscoingui.cpp` | 1187 / 15 | 1277 / 0 | removed_upstream_code |
| `src/qt/walletcontroller.cpp` | 253 / 2 | 253 / 0 | removed_upstream_code |
| `src/qt/walletmodel.cpp` | 614 / 2 | 614 / 2 | local_removal_context |
| `src/qt/walletmodel.cpp` | 624 / 1 | 624 / 1 | removed_upstream_code |
| `src/rest.cpp` | 223 / 1 | 223 / 0 | removed_upstream_code |
| `src/rest.cpp` | 715 / 1 | 729 / 0 | removed_upstream_code |
| `src/rpc/blockchain.cpp` | 108 / 1 | 115 / 0 | removed_upstream_code |
| `src/rpc/blockchain.cpp` | 556 / 1 | 750 / 0 | removed_upstream_code |
| `src/rpc/mining.cpp` | 11 / 1 | 11 / 0 | removed_upstream_code |
| `src/rpc/net.cpp` | 38 / 1 | 38 / 0 | removed_upstream_code |
| `src/rpc/rawtransaction.cpp` | 52 / 1 | 52 / 0 | removed_upstream_code |
| `src/rpc/server.cpp` | 597 / 8 | 598 / 8 | local_removal_context |
| `src/rpc/server.h` | 19 / 1 | 18 / 0 | removed_upstream_code |
| `src/rpc/server.h` | 186 / 2 | 184 / 2 | local_removal_context |
| `src/script/interpreter.cpp` | 15 / 1 | 15 / 0 | removed_upstream_code |
| `src/streams.h` | 331 / 1 | 392 / 0 | removed_upstream_code |
| `src/test/blockfilter_index_tests.cpp` | 8 / 1 | 8 / 0 | removed_upstream_code |
| `src/test/crypto_tests.cpp` | 1061 / 22 | 1061 / 0 | removed_upstream_code |
| `src/test/fs_tests.cpp` | 8 / 1 | 8 / 0 | removed_upstream_code |
| `src/test/fs_tests.cpp` | 104 / 15 | 103 / 0 | removed_upstream_code |
| `src/test/fuzz/deserialize.cpp` | 13 / 1 | 14 / 0 | removed_upstream_code |
| `src/test/fuzz/integer.cpp` | 8 / 1 | 10 / 0 | removed_upstream_code |
| `src/test/fuzz/integer.cpp` | 84 / 1 | 85 / 0 | removed_upstream_code |
| `src/test/mempool_tests.cpp` | 15 / 2 | 22 / 0 | removed_upstream_code |
| `src/test/pow_tests.cpp` | 32 / 1 | 32 / 1 | removed_upstream_code |
| `src/test/pow_tests.cpp` | 46 / 1 | 47 / 1 | removed_upstream_code |
| `src/test/pow_tests.cpp` | 60 / 1 | 62 / 1 | removed_upstream_code |
| `src/test/pow_tests.cpp` | 77 / 1 | 79 / 1 | removed_upstream_code |
| `src/test/sighash_tests.cpp` | 163 / 1 | 163 / 2 | local_removal_context |
| `src/test/sighash_tests.cpp` | 208 / 1 | 209 / 1 | removed_upstream_code |
| `src/test/util/mining.cpp` | 21 / 1 | 21 / 0 | removed_upstream_code |
| `src/test/util/setup_common.cpp` | 249 / 2 | 327 / 1 | local_removal_context |
| `src/test/util_tests.cpp` | 15 / 1 | 15 / 0 | removed_upstream_code |
| `src/test/util_tests.cpp` | 1109 / 5 | 1115 / 0 | removed_upstream_code |
| `src/test/util_tests.cpp` | 1190 / 1 | 1210 / 0 | removed_upstream_code |
| `src/test/util_tests.cpp` | 1233 / 16 | 1255 / 0 | removed_upstream_code |
| `src/test/util_tests.cpp` | 1668 / 1 | 1676 / 1 | removed_upstream_code |
| `src/txmempool.cpp` | 456 / 1 | 583 / 0 | local_removal_context |
| `src/txmempool.h` | 41 / 2 | 55 / 0 | removed_upstream_code |
| `src/uint256.h` | 9 / 1 | 9 / 0 | removed_upstream_code |
| `src/undo.h` | 10 / 1 | 10 / 0 | removed_upstream_code |
| `src/undo.h` | 28 / 1 | 27 / 1 | removed_upstream_code |
| `src/undo.h` | 31 / 1 | 30 / 1 | removed_upstream_code |
| `src/undo.h` | 41 / 1 | 40 / 1 | removed_upstream_code |
| `src/undo.h` | 47 / 1 | 46 / 1 | removed_upstream_code |
| `src/util/check.h` | 23 / 2 | 24 / 0 | removed_upstream_code |
| `src/util/check.h` | 34 / 14 | 33 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 14 / 1 | 12 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 16 / 1 | 13 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 20 / 1 | 16 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 93 / 13 | 93 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 264 / 10 | 252 / 0 | removed_upstream_code |
| `src/util/fs_helpers.cpp` | 277 / 1 | 255 / 0 | removed_upstream_code |
| `src/util/fs_helpers.h` | 40 / 1 | 48 / 0 | removed_upstream_code |
| `src/util/strencodings.cpp` | 9 / 1 | 10 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1030 / 2 | 1275 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1058 / 2 | 1312 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1542 / 1 | 1843 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1556 / 1 | 1857 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1657 / 1 | 2735 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1701 / 1 | 2778 / 0 | removed_upstream_code |
| `src/validation.cpp` | 1760 / 1 | 3359 / 0 | removed_upstream_code |
| `src/validation.cpp` | 2007 / 2 | 4948 / 2 | local_removal_context |
| `src/validation.cpp` | 2025 / 1 | 4966 / 0 | local_removal_context |
| `src/validation.cpp` | 2246 / 1 | 5357 / 2 | removed_upstream_code |
| `src/validation.cpp` | 2274 / 1 | 5386 / 1 | removed_upstream_code |
| `src/validation.cpp` | 2304 / 1 | 5416 / 1 | removed_upstream_code |
| `src/validation.cpp` | 2306 / 1 | 5418 / 1 | removed_upstream_code |
| `src/validation.cpp` | 2311 / 1 | 5423 / 1 | removed_upstream_code |
| `src/validation.cpp` | 2320 / 1 | 5432 / 1 | removed_upstream_code |
| `src/validation.cpp` | 2346 / 1 | 5459 / 0 | removed_upstream_code |
| `src/validation.cpp` | 2489 / 1 | 5771 / 0 | removed_upstream_code |
| `src/validation.cpp` | 2499 / 1 | 5780 / 0 | removed_upstream_code |
| `src/validation.cpp` | 2714 / 1 | 6134 / 0 | removed_upstream_code |
| `src/validation.cpp` | 2900 / 1 | 6522 / 0 | local_removal_context |
| `src/validation.cpp` | 3334 / 2 | 7812 / 0 | removed_upstream_code |
| `src/validation.cpp` | 3573 / 1 | 8592 / 0 | removed_upstream_code |
| `src/validation.cpp` | 3764 / 1 | 8892 / 0 | removed_upstream_code |
| `src/validation.cpp` | 4434 / 1 | 9820 / 0 | local_removal_context |
| `src/validation.cpp` | 4554 / 2 | 10306 / 4 | explicit_removal_context |
| `src/validation.cpp` | 4700 / 1 | 10533 / 0 | removed_upstream_code |
| `src/validation.cpp` | 5056 / 1 | 10999 / 0 | removed_upstream_code |
| `src/validation.cpp` | 5065 / 1 | 11007 / 0 | removed_upstream_code |
| `src/validation.cpp` | 5299 / 1 | 11359 / 1 | removed_upstream_code |
| `src/validation.cpp` | 5806 / 1 | 13742 / 1 | removed_upstream_code |
| `src/validation.h` | 1057 / 1 | 1530 / 0 | removed_upstream_code |
| `src/wallet/rpc/signmessage.cpp` | 52 / 2 | 52 / 2 | local_removal_context |
| `src/wallet/rpc/signmessage.cpp` | 56 / 1 | 56 / 1 | removed_upstream_code |
| `src/wallet/rpc/wallet.cpp` | 397 / 5 | 397 / 0 | removed_upstream_code |
| `src/wallet/salvage.cpp` | 88 / 18 | 88 / 0 | removed_upstream_code |
| `src/wallet/walletdb.cpp` | 595 / 2 | 623 / 2 | local_removal_context |

## No matching upstream path

All target paths in this category are listed below. This is a path inventory, not an authorship claim or a declaration that the files need line-by-line markers. Fork-only subsystems should retain their existing attribution; integration points in shared Bitcoin files are the first annotation priority.

### build_config_other (76)

- `.github/workflows/guix-build.yml`
- `.github/workflows/sanitizers.yml`
- `REVIEWERS`
- `build_msvc/libsecp256k1_config.h`
- `build_msvc/pq_chainlock_fixture/pq_chainlock_fixture.vcxproj`
- `build_msvc/test_msvc_config.py`
- `ci/test/00_setup_env_native_multiprocess.sh`
- `ci/test/05_before_script.sh`
- `ci/test/06_script_a.sh`
- `contrib/auxpow/getwork-wrapper.py`
- `contrib/auxpow/getwork-wrapper.sh`
- `contrib/btcheadernode/COPYING.bitcoin-core`
- `contrib/btcheadernode/bitcoin.lock`
- `contrib/btcheadernode/build-bitcoin-header-node.sh`
- `contrib/btcheadernode/generate-headers-only-patch.sh`
- `contrib/btcheadernode/patches/headers-only.diff`
- `contrib/btcheadernode/test-headers-only.py`
- `contrib/btcheadernode/test-source-provenance.sh`
- `contrib/btcheadernode/test-toolchain-generation.sh`
- `contrib/containers/guix/Dockerfile`
- `contrib/containers/guix/docker-compose.yml`
- `contrib/containers/guix/scripts/entrypoint`
- `contrib/containers/guix/scripts/guix-start`
- `contrib/containers/guix/scripts/setup-sdk`
- `contrib/devtools/github-merge.py`
- `contrib/devtools/optimize-pngs.py`
- `contrib/devtools/update-css-files.py`
- `contrib/devtools/update-translations.py`
- `contrib/guix/Dockerfile`
- `contrib/guix/patches/binutils-unaligned-default.patch`
- `contrib/guix/patches/glibc-guix-prefix.patch`
- `contrib/install_db4.sh`
- `contrib/notarization/.gitignore`
- `contrib/notarization/create-detached-macos-sigs.sh`
- `contrib/notarization/notarize-all.sh`
- `contrib/notarization/notarize-mac-binaries.sh`
- `contrib/notarization/sign-mac-binaries.sh`
- `contrib/notarization/staple-notarization.sh`
- `contrib/syscoin-cli.bash-completion`
- `contrib/syscoin-tx.bash-completion`
- `contrib/syscoind.bash-completion`
- `contrib/testgen/base58.py`
- `contrib/verifybinaries/verify.py`
- `depends/patches/boost/process_macos_sdk.patch`
- `depends/patches/expat/cmake_minimum.patch`
- `depends/patches/libevent/cmake_fixups.patch`
- `depends/patches/libevent/fix_mingw_link.patch`
- `depends/patches/libnatpmp/no_libtool.patch`
- `depends/patches/miniupnpc/no_libtool.patch`
- `depends/patches/qrencode/cmake_fixups.patch`
- `depends/patches/qt/clang_18_libpng.patch`
- `depends/patches/qt/darwin_no_libm.patch`
- `depends/patches/qt/fix_qt_configure.patch`
- `depends/patches/qt/no_warnings_for_symbols.patch`
- `depends/patches/qt/utc_from_string_no_optimize.patch`
- `depends/patches/qt/zlib-timebits64.patch`
- `depends/patches/zeromq/builtin_sha1.patch`
- `depends/patches/zeromq/cacheline_undefined.patch`
- `depends/patches/zeromq/cmake_minimum.patch`
- `depends/patches/zeromq/fix_have_windows.patch`
- `depends/patches/zeromq/fix_mingw_link.patch`
- `depends/patches/zeromq/macos_mktemp_check.patch`
- `depends/patches/zeromq/no_librt.patch`
- `depends/patches/zeromq/openbsd_kqueue_headers.patch`
- `dip-0022/quorum_attack.py`
- `src/assetbalances.json`
- `src/bin/darwin/arm64/placeholder`
- `src/bin/darwin/x86_64/placeholder`
- `src/bin/linux/aarch64/placeholder`
- `src/bin/linux/arm/placeholder`
- `src/bin/linux/x86_64/sysgeth`
- `src/bin/windows/placeholder`
- `src/crypto/slhdsa/LICENSE.upstream`
- `src/mine.sh`
- `src/qt/forms/masternodelist.ui`
- `syscoin.code-workspace`

### documentation_or_asset (58)

- `.github/ISSUE_TEMPLATE.md`
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/good_first_issue.md`
- `.github/ISSUE_TEMPLATE/gui_issue.md`
- `contrib/btcheadernode/HEADERS_ONLY_PATCH_SPEC.md`
- `contrib/btcheadernode/README.md`
- `contrib/containers/guix/motd.txt`
- `contrib/notarization/DETACHED-SIGNATURES.md`
- `contrib/notarization/README.md`
- `contrib/seeds/suspicious_hosts.txt`
- `contrib/verifybinaries/README.md`
- `dip-0022/README.md`
- `doc/BTC-header-backend.md`
- `doc/nevm-zmq.md`
- `doc/pq-chainlocks.md`
- `doc/release-notes-123.md`
- `doc/release-notes-14054.md`
- `doc/release-notes-15566.md`
- `doc/release-notes-15637.md`
- `doc/release-notes-24914.md`
- `doc/release-notes-25158.md`
- `doc/release-notes-26076.md`
- `doc/release-notes-26094.md`
- `doc/release-notes-26485.md`
- `doc/release-notes-27213.md`
- `doc/release-notes-27302.md`
- `doc/release-notes-27460.md`
- `doc/release-notes-27501.md`
- `doc/release-notes-27596.md`
- `doc/release-notes-27609.md`
- `doc/release-notes-27632.md`
- `doc/release-notes-27757.md`
- `doc/release-notes-28113.md`
- `doc/release-notes-28354.md`
- `doc/release-notes-28414.md`
- `doc/release-notes-28448.md`
- `doc/release-notes-28685.md`
- `doc/release-notes-empty-template.md`
- `doc/release-notes/release-notes-4.1.0.md`
- `doc/release-notes/release-notes-4.1.1.md`
- `doc/release-notes/release-notes-4.1.2.md`
- `doc/release-notes/release-notes-4.1.3.md`
- `doc/release-notes/release-notes-4.2.0.md`
- `doc/release-notes/release-notes-4.2.1.md`
- `doc/release-notes/release-notes-4.2.2.md`
- `doc/release-notes/release-notes-4.3.0.md`
- `doc/release-notes/release-notes-4.4.0.md`
- `doc/release-notes/release-notes-5.0.0.md`
- `doc/release-notes/release-notes-5.1.0.md`
- `doc/release-notes/release-notes-5.1.1.md`
- `doc/release-notes/release-notes-5.1.2.md`
- `share/pixmaps/syscoin20.png`
- `share/pixmaps/syscoin24.png`
- `share/pixmaps/syscoin48.png`
- `share/pixmaps/syscoin96.png`
- `src/crypto/slhdsa/README.md`
- `src/qt/res/icons/about.png`
- `src/qt/res/icons/masternodes.png`

### production (216)

- `src/auxpow.cpp`
- `src/auxpow.h`
- `src/batchedlogger.cpp`
- `src/batchedlogger.h`
- `src/cachemap.h`
- `src/cachemultimap.h`
- `src/consensus/pq_migration_config.h`
- `src/crypto/chacha_poly_aead.cpp`
- `src/crypto/chacha_poly_aead.h`
- `src/crypto/legacy_bls.h`
- `src/crypto/scheduled_wots/scheduled_wots.cpp`
- `src/crypto/scheduled_wots/scheduled_wots.h`
- `src/crypto/slhdsa/secure.cpp`
- `src/crypto/slhdsa/secure.h`
- `src/crypto/slhdsa/selftest.cpp`
- `src/crypto/slhdsa/selftest.h`
- `src/crypto/slhdsa/slhdsa.cpp`
- `src/crypto/slhdsa/slhdsa.h`
- `src/crypto/slhdsa/vendor/cbmc.h`
- `src/crypto/slhdsa/vendor/plat_local.h`
- `src/crypto/slhdsa/vendor/sha3_api.c`
- `src/crypto/slhdsa/vendor/sha3_api.h`
- `src/crypto/slhdsa/vendor/sha3_f1600.c`
- `src/crypto/slhdsa/vendor/slh_adrs.h`
- `src/crypto/slhdsa/vendor/slh_dsa.c`
- `src/crypto/slhdsa/vendor/slh_dsa.h`
- `src/crypto/slhdsa/vendor/slh_param.h`
- `src/crypto/slhdsa/vendor/slh_shake.c`
- `src/crypto/slhdsa/vendor/slh_sys.h`
- `src/crypto/slhdsa/vendor/slh_var.h`
- `src/crypto/slhdsa/vendor/slh_wots_internal.h`
- `src/ctpl_stl.h`
- `src/cxxtimer.hpp`
- `src/dsnotificationinterface.cpp`
- `src/dsnotificationinterface.h`
- `src/evo/auxiliary_history_gc.cpp`
- `src/evo/auxiliary_history_gc.h`
- `src/evo/deterministicmns.cpp`
- `src/evo/deterministicmns.h`
- `src/evo/dmnstate.cpp`
- `src/evo/dmnstate.h`
- `src/evo/evodb.h`
- `src/evo/mnauth.cpp`
- `src/evo/mnauth.h`
- `src/evo/mnauth_types.h`
- `src/evo/pq_payment_probation.cpp`
- `src/evo/pq_payment_probation.h`
- `src/evo/pq_payment_probation_db.cpp`
- `src/evo/pq_payment_probation_db.h`
- `src/evo/pq_providertx.cpp`
- `src/evo/pq_providertx.h`
- `src/evo/pq_registry.cpp`
- `src/evo/pq_registry.h`
- `src/evo/pq_voting_key.h`
- `src/evo/provider_revoke_payload.h`
- `src/evo/providertx.cpp`
- `src/evo/providertx.h`
- `src/evo/specialtx.cpp`
- `src/evo/specialtx.h`
- `src/evo/specialtx_payload.h`
- `src/flatdatabase.h`
- `src/governance/governance.cpp`
- `src/governance/governance.h`
- `src/governance/governanceclasses.cpp`
- `src/governance/governanceclasses.h`
- `src/governance/governancecommon.cpp`
- `src/governance/governancecommon.h`
- `src/governance/governanceexceptions.cpp`
- `src/governance/governanceexceptions.h`
- `src/governance/governanceobject.cpp`
- `src/governance/governanceobject.h`
- `src/governance/governancepages.h`
- `src/governance/governancevalidators.cpp`
- `src/governance/governancevalidators.h`
- `src/governance/governancevote.cpp`
- `src/governance/governancevote.h`
- `src/governance/governancevotedb.cpp`
- `src/governance/governancevotedb.h`
- `src/governance/pq_governance_auth.cpp`
- `src/governance/pq_governance_auth.h`
- `src/governance/pq_governance_auth_interface.h`
- `src/limitedmap.h`
- `src/llmq/btc_header_policy.cpp`
- `src/llmq/btc_header_policy.h`
- `src/llmq/legacy_quorum_commitment.cpp`
- `src/llmq/legacy_quorum_commitment.h`
- `src/llmq/pq_btcc.cpp`
- `src/llmq/pq_btcc.h`
- `src/llmq/pq_chainlock_collector.cpp`
- `src/llmq/pq_chainlock_collector.h`
- `src/llmq/pq_chainlock_persistence.cpp`
- `src/llmq/pq_chainlock_persistence.h`
- `src/llmq/pq_chainlock_schedule.cpp`
- `src/llmq/pq_chainlock_schedule.h`
- `src/llmq/pq_chainlock_signer.cpp`
- `src/llmq/pq_chainlock_signer.h`
- `src/llmq/pq_chainlock_store.cpp`
- `src/llmq/pq_chainlock_store.h`
- `src/llmq/pq_chainlock_test_fixture.cpp`
- `src/llmq/pq_chainlock_test_fixture.h`
- `src/llmq/pq_chainlock_types.cpp`
- `src/llmq/pq_chainlock_types.h`
- `src/llmq/pq_chainlock_verify.cpp`
- `src/llmq/pq_chainlock_verify.h`
- `src/llmq/pq_child_key_derivation.h`
- `src/llmq/pq_child_key_tree.cpp`
- `src/llmq/pq_child_key_tree.h`
- `src/llmq/pq_global_auth.cpp`
- `src/llmq/pq_global_auth.h`
- `src/llmq/pq_mnauth.cpp`
- `src/llmq/pq_mnauth.h`
- `src/llmq/pq_operator_key_state.cpp`
- `src/llmq/pq_operator_key_state.h`
- `src/llmq/pq_payment_audit.cpp`
- `src/llmq/pq_payment_audit.h`
- `src/llmq/pq_payment_audit_collector.cpp`
- `src/llmq/pq_payment_audit_collector.h`
- `src/llmq/pq_payment_audit_signer.cpp`
- `src/llmq/pq_payment_audit_signer.h`
- `src/llmq/pq_payment_audit_staging_store.cpp`
- `src/llmq/pq_payment_audit_staging_store.h`
- `src/llmq/pq_payment_audit_store.cpp`
- `src/llmq/pq_payment_audit_store.h`
- `src/llmq/pq_payment_audit_verify.cpp`
- `src/llmq/pq_payment_audit_verify.h`
- `src/llmq/pq_quorum_builder.cpp`
- `src/llmq/pq_quorum_builder.h`
- `src/llmq/pq_quorum_overlay.cpp`
- `src/llmq/pq_quorum_overlay.h`
- `src/llmq/pq_recovery_refresh.cpp`
- `src/llmq/pq_recovery_refresh.h`
- `src/llmq/pq_roster_beacon.cpp`
- `src/llmq/pq_roster_beacon.h`
- `src/llmq/pq_signer_journal.cpp`
- `src/llmq/pq_signer_journal.h`
- `src/llmq/quorums_blockprocessor.cpp`
- `src/llmq/quorums_blockprocessor.h`
- `src/llmq/quorums_chainlocks.cpp`
- `src/llmq/quorums_chainlocks.h`
- `src/llmq/quorums_commitment.cpp`
- `src/llmq/quorums_commitment.h`
- `src/llmq/quorums_init.cpp`
- `src/llmq/quorums_init.h`
- `src/llmq/quorums_utils.cpp`
- `src/llmq/quorums_utils.h`
- `src/masternode/activemasternode.cpp`
- `src/masternode/activemasternode.h`
- `src/masternode/masternodemeta.cpp`
- `src/masternode/masternodemeta.h`
- `src/masternode/masternodepayments.cpp`
- `src/masternode/masternodepayments.h`
- `src/masternode/masternodesync.cpp`
- `src/masternode/masternodesync.h`
- `src/masternode/masternodeutils.cpp`
- `src/masternode/masternodeutils.h`
- `src/masternode/pq_operatorkeys.cpp`
- `src/masternode/pq_operatorkeys.h`
- `src/messagesigner.cpp`
- `src/messagesigner.h`
- `src/netfulfilledman.cpp`
- `src/netfulfilledman.h`
- `src/nevm/address.cpp`
- `src/nevm/address.h`
- `src/nevm/common.cpp`
- `src/nevm/common.h`
- `src/nevm/commondata.cpp`
- `src/nevm/commondata.h`
- `src/nevm/exceptions.h`
- `src/nevm/fixedhash.cpp`
- `src/nevm/fixedhash.h`
- `src/nevm/nevm.cpp`
- `src/nevm/nevm.h`
- `src/nevm/response.h`
- `src/nevm/rlp.cpp`
- `src/nevm/rlp.h`
- `src/nevm/sha3.cpp`
- `src/nevm/sha3.h`
- `src/nevm/vector_ref.h`
- `src/node/blockconnection.h`
- `src/node/btcheader_state.h`
- `src/node/geth_startup.h`
- `src/node/pq_activation_handoff.h`
- `src/primitives/pureheader.cpp`
- `src/primitives/pureheader.h`
- `src/qt/masternodelist.cpp`
- `src/qt/masternodelist.h`
- `src/rpc/auxpow_miner.cpp`
- `src/rpc/auxpow_miner.h`
- `src/rpc/governance.cpp`
- `src/rpc/masternode.cpp`
- `src/rpc/rpcevo.cpp`
- `src/rpc/rpcquorums.cpp`
- `src/saltedhasher.cpp`
- `src/saltedhasher.h`
- `src/services/assetconsensus.cpp`
- `src/services/assetconsensus.h`
- `src/services/nevmconsensus.cpp`
- `src/services/nevmconsensus.h`
- `src/services/rpc/assetrpc.cpp`
- `src/services/rpc/assetrpc.h`
- `src/services/rpc/nevmrpc.cpp`
- `src/services/rpc/wallet/nevmwalletrpc.cpp`
- `src/spork.cpp`
- `src/spork.h`
- `src/support/allocators/mt_pooled_secure.h`
- `src/support/allocators/pooled_secure.h`
- `src/unordered_lru_cache.h`
- `src/util/ranges.h`
- `src/util/syscall_sandbox.cpp`
- `src/util/syscall_sandbox.h`
- `src/util/system.h`
- `src/wallet/pq_key_schedule.h`
- `src/wallet/rpc/spend.h`
- `src/wallet/rpcevo.cpp`
- `src/wallet/rpcgovernance.cpp`
- `src/wallet/rpcmasternode.cpp`

### test (95)

- `src/bench/pq_crypto.cpp`
- `src/bench/pq_registry.cpp`
- `src/test/auxiliary_history_gc_tests.cpp`
- `src/test/auxpow_tests.cpp`
- `src/test/btc_header_policy_tests.cpp`
- `src/test/data/nevmspv_invalid.json`
- `src/test/data/nevmspv_valid.json`
- `src/test/data/proposals_invalid.json`
- `src/test/data/proposals_valid.json`
- `src/test/data/utxo.json`
- `src/test/evo_deterministicmns_tests.cpp`
- `src/test/evodb_tests.cpp`
- `src/test/fuzz/pq_chainlock_types.cpp`
- `src/test/fuzz/pq_governance_auth.cpp`
- `src/test/fuzz/pq_providertx.cpp`
- `src/test/fuzz/pq_scheduled_wots.cpp`
- `src/test/fuzz/pq_slhdsa.cpp`
- `src/test/fuzz/syscoin_mint.cpp`
- `src/test/fuzz/syscoin_spt.cpp`
- `src/test/geth_startup_tests.cpp`
- `src/test/governance_validators_tests.cpp`
- `src/test/legacy_bls_tests.cpp`
- `src/test/legacy_quorum_commitment_tests.cpp`
- `src/test/nevm_auxiliary_tests.cpp`
- `src/test/nevm_cache_writeback_tests.cpp`
- `src/test/nevm_ownership_tests.cpp`
- `src/test/nevm_tests.cpp`
- `src/test/pq_btcc_tests.cpp`
- `src/test/pq_chainlock_collector_tests.cpp`
- `src/test/pq_chainlock_fixture.cpp`
- `src/test/pq_chainlock_handler_tests.cpp`
- `src/test/pq_chainlock_integration_tests.cpp`
- `src/test/pq_chainlock_persistence_tests.cpp`
- `src/test/pq_chainlock_schedule_tests.cpp`
- `src/test/pq_chainlock_signer_tests.cpp`
- `src/test/pq_chainlock_store_tests.cpp`
- `src/test/pq_chainlock_types_tests.cpp`
- `src/test/pq_chainlock_verify_tests.cpp`
- `src/test/pq_child_key_tree_tests.cpp`
- `src/test/pq_crypto_tests.cpp`
- `src/test/pq_global_auth_tests.cpp`
- `src/test/pq_governance_auth_tests.cpp`
- `src/test/pq_historical_sync_frontier_tests.cpp`
- `src/test/pq_migration_tests.cpp`
- `src/test/pq_mnauth_tests.cpp`
- `src/test/pq_operator_key_state_tests.cpp`
- `src/test/pq_operator_keys_tests.cpp`
- `src/test/pq_payment_audit_staging_store_tests.cpp`
- `src/test/pq_payment_audit_store_tests.cpp`
- `src/test/pq_payment_audit_tests.cpp`
- `src/test/pq_payment_audit_verify_tests.cpp`
- `src/test/pq_payment_probation_db_tests.cpp`
- `src/test/pq_payment_probation_tests.cpp`
- `src/test/pq_provider_auth_tests.cpp`
- `src/test/pq_provider_codec_tests.cpp`
- `src/test/pq_providertx_tests.cpp`
- `src/test/pq_quorum_builder_tests.cpp`
- `src/test/pq_quorum_overlay_tests.cpp`
- `src/test/pq_recovery_refresh_tests.cpp`
- `src/test/pq_registry_tests.cpp`
- `src/test/pq_roster_beacon_tests.cpp`
- `src/test/pq_signer_journal_tests.cpp`
- `src/test/pq_test_util.h`
- `src/test/util/nevm_mint.h`
- `test/functional/allocation_mint_testnet.py`
- `test/functional/auxpow_invalidpow.py`
- `test/functional/auxpow_mining.py`
- `test/functional/auxpow_self_parent.py`
- `test/functional/auxpow_zerohash.py`
- `test/functional/feature_assets.py`
- `test/functional/feature_btcheader_external_command.py`
- `test/functional/feature_btcheader_external_policy.py`
- `test/functional/feature_btcheader_policy_auxpow.py`
- `test/functional/feature_btcheader_watchdog.py`
- `test/functional/feature_deterministicmns.py`
- `test/functional/feature_governance.py`
- `test/functional/feature_governance_dynamic.py`
- `test/functional/feature_governance_objects.py`
- `test/functional/feature_multikeysporks.py`
- `test/functional/feature_nevm_connect_after_consensus.py`
- `test/functional/feature_nevm_data.py`
- `test/functional/feature_pq_chainlocks.py`
- `test/functional/feature_pq_chainlocks_pruned_sync.py`
- `test/functional/feature_pq_operator_lifecycle.py`
- `test/functional/feature_pq_voting_key.py`
- `test/functional/feature_sporks.py`
- `test/functional/interface_zmq_nevm.py`
- `test/functional/rpc_masternode.py`
- `test/functional/rpc_mnauth.py`
- `test/functional/test_framework/asset_helpers.py`
- `test/functional/test_framework/auxpow.py`
- `test/functional/test_framework/auxpow_testing.py`
- `test/functional/test_framework/bignum.py`
- `test/functional/test_framework/masternodes.py`
- `test/functional/test_framework/test_dash_mining.py`

### translation (1)

- `src/qt/locale/syscoin_pt@qtfiletype.ts`

### vendor (410)

- `src/immer/.clang-format`
- `src/immer/.dir-locals.el`
- `src/immer/.gdbinit`
- `src/immer/.github/FUNDING.yml`
- `src/immer/.github/workflows/cifuzz.yml`
- `src/immer/.github/workflows/test.yml`
- `src/immer/.gitignore`
- `src/immer/.gitmodules`
- `src/immer/CMakeLists.txt`
- `src/immer/LICENSE`
- `src/immer/Package.swift`
- `src/immer/README.rst`
- `src/immer/WORKSPACE`
- `src/immer/benchmark/CMakeLists.txt`
- `src/immer/benchmark/config.hpp`
- `src/immer/benchmark/extra/refcounting.cpp`
- `src/immer/benchmark/set/access.hpp`
- `src/immer/benchmark/set/access.ipp`
- `src/immer/benchmark/set/erase.hpp`
- `src/immer/benchmark/set/erase.ipp`
- `src/immer/benchmark/set/insert.hpp`
- `src/immer/benchmark/set/insert.ipp`
- `src/immer/benchmark/set/iter.hpp`
- `src/immer/benchmark/set/iter.ipp`
- `src/immer/benchmark/set/memory/basic-string-long.cpp`
- `src/immer/benchmark/set/memory/basic-string-short.cpp`
- `src/immer/benchmark/set/memory/basic-unsigned.cpp`
- `src/immer/benchmark/set/memory/exp-string-long.cpp`
- `src/immer/benchmark/set/memory/exp-string-short.cpp`
- `src/immer/benchmark/set/memory/exp-unsigned.cpp`
- `src/immer/benchmark/set/memory/lin-string-long.cpp`
- `src/immer/benchmark/set/memory/lin-string-short.cpp`
- `src/immer/benchmark/set/memory/lin-unsigned.cpp`
- `src/immer/benchmark/set/memory/memory.hpp`
- `src/immer/benchmark/set/string-box/access.cpp`
- `src/immer/benchmark/set/string-box/erase.cpp`
- `src/immer/benchmark/set/string-box/generator.ipp`
- `src/immer/benchmark/set/string-box/insert.cpp`
- `src/immer/benchmark/set/string-box/iter.cpp`
- `src/immer/benchmark/set/string-long/access.cpp`
- `src/immer/benchmark/set/string-long/erase.cpp`
- `src/immer/benchmark/set/string-long/generator.ipp`
- `src/immer/benchmark/set/string-long/insert.cpp`
- `src/immer/benchmark/set/string-long/iter.cpp`
- `src/immer/benchmark/set/string-short/access.cpp`
- `src/immer/benchmark/set/string-short/erase.cpp`
- `src/immer/benchmark/set/string-short/generator.ipp`
- `src/immer/benchmark/set/string-short/insert.cpp`
- `src/immer/benchmark/set/string-short/iter.cpp`
- `src/immer/benchmark/set/unsigned/access.cpp`
- `src/immer/benchmark/set/unsigned/erase.cpp`
- `src/immer/benchmark/set/unsigned/generator.ipp`
- `src/immer/benchmark/set/unsigned/insert.cpp`
- `src/immer/benchmark/set/unsigned/iter.cpp`
- `src/immer/benchmark/vector/access.hpp`
- `src/immer/benchmark/vector/assoc.hpp`
- `src/immer/benchmark/vector/branching/access.ipp`
- `src/immer/benchmark/vector/branching/assoc.ipp`
- `src/immer/benchmark/vector/branching/basic/access.cpp`
- `src/immer/benchmark/vector/branching/basic/assoc.cpp`
- `src/immer/benchmark/vector/branching/basic/concat.cpp`
- `src/immer/benchmark/vector/branching/basic/push.cpp`
- `src/immer/benchmark/vector/branching/concat.ipp`
- `src/immer/benchmark/vector/branching/gc/access.cpp`
- `src/immer/benchmark/vector/branching/gc/assoc.cpp`
- `src/immer/benchmark/vector/branching/gc/concat.cpp`
- `src/immer/benchmark/vector/branching/gc/push.cpp`
- `src/immer/benchmark/vector/branching/push.ipp`
- `src/immer/benchmark/vector/branching/safe/access.cpp`
- `src/immer/benchmark/vector/branching/safe/assoc.cpp`
- `src/immer/benchmark/vector/branching/safe/concat.cpp`
- `src/immer/benchmark/vector/branching/safe/push.cpp`
- `src/immer/benchmark/vector/branching/unsafe/access.cpp`
- `src/immer/benchmark/vector/branching/unsafe/assoc.cpp`
- `src/immer/benchmark/vector/branching/unsafe/concat.cpp`
- `src/immer/benchmark/vector/branching/unsafe/push.cpp`
- `src/immer/benchmark/vector/common.hpp`
- `src/immer/benchmark/vector/concat.hpp`
- `src/immer/benchmark/vector/drop.hpp`
- `src/immer/benchmark/vector/misc/access.cpp`
- `src/immer/benchmark/vector/misc/assoc.cpp`
- `src/immer/benchmark/vector/misc/concat.cpp`
- `src/immer/benchmark/vector/misc/drop.cpp`
- `src/immer/benchmark/vector/misc/push-front.cpp`
- `src/immer/benchmark/vector/misc/push.cpp`
- `src/immer/benchmark/vector/misc/take.cpp`
- `src/immer/benchmark/vector/paper/access.cpp`
- `src/immer/benchmark/vector/paper/assoc-random.cpp`
- `src/immer/benchmark/vector/paper/assoc.cpp`
- `src/immer/benchmark/vector/paper/concat.cpp`
- `src/immer/benchmark/vector/paper/push.cpp`
- `src/immer/benchmark/vector/push.hpp`
- `src/immer/benchmark/vector/push_front.hpp`
- `src/immer/benchmark/vector/take.hpp`
- `src/immer/cmake/FindBoehmGC.cmake`
- `src/immer/cmake/FindRRB.cmake`
- `src/immer/cmake/ImmerUtils.cmake`
- `src/immer/codecov.yml`
- `src/immer/default.nix`
- `src/immer/doc/CMakeLists.txt`
- `src/immer/doc/_static/logo-black.svg`
- `src/immer/doc/_static/logo-front.svg`
- `src/immer/doc/_static/logo.svg`
- `src/immer/doc/_static/patreon.svg`
- `src/immer/doc/_static/sinusoidal-badge.svg`
- `src/immer/doc/algorithms.rst`
- `src/immer/doc/conf.py`
- `src/immer/doc/containers.rst`
- `src/immer/doc/design.rst`
- `src/immer/doc/doxygen.config`
- `src/immer/doc/implementation.rst`
- `src/immer/doc/index.rst`
- `src/immer/doc/introduction.rst`
- `src/immer/doc/memory.rst`
- `src/immer/doc/requirements.txt`
- `src/immer/doc/sphinx-html-hack.bash`
- `src/immer/doc/transients.rst`
- `src/immer/doc/utilities.rst`
- `src/immer/example/CMakeLists.txt`
- `src/immer/example/array/array.cpp`
- `src/immer/example/box/box.cpp`
- `src/immer/example/flex-vector/flex-vector.cpp`
- `src/immer/example/map/intro.cpp`
- `src/immer/example/set/intro.cpp`
- `src/immer/example/table/intro.cpp`
- `src/immer/example/vector/fizzbuzz.cpp`
- `src/immer/example/vector/gc.cpp`
- `src/immer/example/vector/intro.cpp`
- `src/immer/example/vector/iota-move.cpp`
- `src/immer/example/vector/iota-slow.cpp`
- `src/immer/example/vector/iota-transient-std.cpp`
- `src/immer/example/vector/iota-transient.cpp`
- `src/immer/example/vector/move.cpp`
- `src/immer/example/vector/vector.cpp`
- `src/immer/extra/fuzzer/CMakeLists.txt`
- `src/immer/extra/fuzzer/array-gc.cpp`
- `src/immer/extra/fuzzer/array.cpp`
- `src/immer/extra/fuzzer/flex-vector-bo.cpp`
- `src/immer/extra/fuzzer/flex-vector-gc.cpp`
- `src/immer/extra/fuzzer/flex-vector-st.cpp`
- `src/immer/extra/fuzzer/flex-vector.cpp`
- `src/immer/extra/fuzzer/fuzzer_gc_guard.hpp`
- `src/immer/extra/fuzzer/fuzzer_input.hpp`
- `src/immer/extra/fuzzer/load_input.hpp`
- `src/immer/extra/fuzzer/map-gc.cpp`
- `src/immer/extra/fuzzer/map-st-str-conflict.cpp`
- `src/immer/extra/fuzzer/map-st-str.cpp`
- `src/immer/extra/fuzzer/map-st.cpp`
- `src/immer/extra/fuzzer/map.cpp`
- `src/immer/extra/fuzzer/set-gc.cpp`
- `src/immer/extra/fuzzer/set-st-str-conflict.cpp`
- `src/immer/extra/fuzzer/set-st-str.cpp`
- `src/immer/extra/fuzzer/set-st.cpp`
- `src/immer/extra/fuzzer/set.cpp`
- `src/immer/extra/fuzzer/vector-gc.cpp`
- `src/immer/extra/fuzzer/vector-st.cpp`
- `src/immer/extra/fuzzer/vector.cpp`
- `src/immer/extra/guile/CMakeLists.txt`
- `src/immer/extra/guile/README.rst`
- `src/immer/extra/guile/benchmark.scm`
- `src/immer/extra/guile/example.scm`
- `src/immer/extra/guile/immer.scm.in`
- `src/immer/extra/guile/scm/detail/convert.hpp`
- `src/immer/extra/guile/scm/detail/define.hpp`
- `src/immer/extra/guile/scm/detail/finalizer_wrapper.hpp`
- `src/immer/extra/guile/scm/detail/function_args.hpp`
- `src/immer/extra/guile/scm/detail/invoke.hpp`
- `src/immer/extra/guile/scm/detail/pack.hpp`
- `src/immer/extra/guile/scm/detail/subr_wrapper.hpp`
- `src/immer/extra/guile/scm/detail/util.hpp`
- `src/immer/extra/guile/scm/group.hpp`
- `src/immer/extra/guile/scm/list.hpp`
- `src/immer/extra/guile/scm/scm.hpp`
- `src/immer/extra/guile/scm/type.hpp`
- `src/immer/extra/guile/scm/val.hpp`
- `src/immer/extra/guile/src/immer.cpp`
- `src/immer/extra/js/immer.cpp`
- `src/immer/extra/js/index.js`
- `src/immer/extra/js/index.tpl.html`
- `src/immer/extra/js/lib/benchmark.js`
- `src/immer/extra/js/lib/immutable.min.js`
- `src/immer/extra/js/lib/lodash.js`
- `src/immer/extra/js/lib/mori.js`
- `src/immer/extra/js/lib/platform.js`
- `src/immer/extra/python/CMakeLists.txt`
- `src/immer/extra/python/README.rst`
- `src/immer/extra/python/benchmark/test_benchmarks.py`
- `src/immer/extra/python/example.py`
- `src/immer/extra/python/immer/__init__.py`
- `src/immer/extra/python/src/immer-boost.cpp`
- `src/immer/extra/python/src/immer-pybind.cpp`
- `src/immer/extra/python/src/immer-raw.cpp`
- `src/immer/immer/algorithm.hpp`
- `src/immer/immer/array.hpp`
- `src/immer/immer/array_transient.hpp`
- `src/immer/immer/atom.hpp`
- `src/immer/immer/box.hpp`
- `src/immer/immer/config.hpp`
- `src/immer/immer/detail/arrays/no_capacity.hpp`
- `src/immer/immer/detail/arrays/node.hpp`
- `src/immer/immer/detail/arrays/with_capacity.hpp`
- `src/immer/immer/detail/combine_standard_layout.hpp`
- `src/immer/immer/detail/hamts/bits.hpp`
- `src/immer/immer/detail/hamts/champ.hpp`
- `src/immer/immer/detail/hamts/champ_iterator.hpp`
- `src/immer/immer/detail/hamts/node.hpp`
- `src/immer/immer/detail/iterator_facade.hpp`
- `src/immer/immer/detail/rbts/bits.hpp`
- `src/immer/immer/detail/rbts/node.hpp`
- `src/immer/immer/detail/rbts/operations.hpp`
- `src/immer/immer/detail/rbts/position.hpp`
- `src/immer/immer/detail/rbts/rbtree.hpp`
- `src/immer/immer/detail/rbts/rbtree_iterator.hpp`
- `src/immer/immer/detail/rbts/rrbtree.hpp`
- `src/immer/immer/detail/rbts/rrbtree_iterator.hpp`
- `src/immer/immer/detail/rbts/visitor.hpp`
- `src/immer/immer/detail/ref_count_base.hpp`
- `src/immer/immer/detail/type_traits.hpp`
- `src/immer/immer/detail/util.hpp`
- `src/immer/immer/experimental/detail/dvektor_impl.hpp`
- `src/immer/immer/experimental/dvektor.hpp`
- `src/immer/immer/flex_vector.hpp`
- `src/immer/immer/flex_vector_transient.hpp`
- `src/immer/immer/heap/cpp_heap.hpp`
- `src/immer/immer/heap/debug_size_heap.hpp`
- `src/immer/immer/heap/free_list_heap.hpp`
- `src/immer/immer/heap/free_list_node.hpp`
- `src/immer/immer/heap/gc_heap.hpp`
- `src/immer/immer/heap/heap_policy.hpp`
- `src/immer/immer/heap/identity_heap.hpp`
- `src/immer/immer/heap/malloc_heap.hpp`
- `src/immer/immer/heap/split_heap.hpp`
- `src/immer/immer/heap/tags.hpp`
- `src/immer/immer/heap/thread_local_free_list_heap.hpp`
- `src/immer/immer/heap/unsafe_free_list_heap.hpp`
- `src/immer/immer/heap/with_data.hpp`
- `src/immer/immer/lock/no_lock_policy.hpp`
- `src/immer/immer/lock/spinlock_policy.hpp`
- `src/immer/immer/map.hpp`
- `src/immer/immer/map_transient.hpp`
- `src/immer/immer/memory_policy.hpp`
- `src/immer/immer/refcount/enable_intrusive_ptr.hpp`
- `src/immer/immer/refcount/no_refcount_policy.hpp`
- `src/immer/immer/refcount/refcount_policy.hpp`
- `src/immer/immer/refcount/unsafe_refcount_policy.hpp`
- `src/immer/immer/set.hpp`
- `src/immer/immer/set_transient.hpp`
- `src/immer/immer/table.hpp`
- `src/immer/immer/table_transient.hpp`
- `src/immer/immer/transience/gc_transience_policy.hpp`
- `src/immer/immer/transience/no_transience_policy.hpp`
- `src/immer/immer/vector.hpp`
- `src/immer/immer/vector_transient.hpp`
- `src/immer/nix/benchmarks.nix`
- `src/immer/nix/docs.nix`
- `src/immer/setup.py`
- `src/immer/shell.nix`
- `src/immer/spm.cpp`
- `src/immer/test/CMakeLists.txt`
- `src/immer/test/algorithm.cpp`
- `src/immer/test/array/default.cpp`
- `src/immer/test/array/gc.cpp`
- `src/immer/test/array_transient/default.cpp`
- `src/immer/test/array_transient/gc.cpp`
- `src/immer/test/atom/default.cpp`
- `src/immer/test/atom/gc.cpp`
- `src/immer/test/atom/generic.ipp`
- `src/immer/test/box/default.cpp`
- `src/immer/test/box/gc.cpp`
- `src/immer/test/box/generic.ipp`
- `src/immer/test/box/recursive.cpp`
- `src/immer/test/box/vector-of-boxes-transient.cpp`
- `src/immer/test/dada.hpp`
- `src/immer/test/detail/type_traits.cpp`
- `src/immer/test/experimental/dvektor.cpp`
- `src/immer/test/flex_vector/B3-BL0.cpp`
- `src/immer/test/flex_vector/B3-BL3.cpp`
- `src/immer/test/flex_vector/default.cpp`
- `src/immer/test/flex_vector/fuzzed-0.cpp`
- `src/immer/test/flex_vector/fuzzed-1.cpp`
- `src/immer/test/flex_vector/fuzzed-2.cpp`
- `src/immer/test/flex_vector/fuzzed-3.cpp`
- `src/immer/test/flex_vector/fuzzed-4.cpp`
- `src/immer/test/flex_vector/gc.cpp`
- `src/immer/test/flex_vector/generic.ipp`
- `src/immer/test/flex_vector/issue-45.cpp`
- `src/immer/test/flex_vector/issue-47.cpp`
- `src/immer/test/flex_vector/regular-B3-BL3.cpp`
- `src/immer/test/flex_vector/regular-default.cpp`
- `src/immer/test/flex_vector_transient/B3-BL0.cpp`
- `src/immer/test/flex_vector_transient/default.cpp`
- `src/immer/test/flex_vector_transient/gc.cpp`
- `src/immer/test/flex_vector_transient/generic.ipp`
- `src/immer/test/flex_vector_transient/regular-default.cpp`
- `src/immer/test/flex_vector_transient/regular-gc.cpp`
- `src/immer/test/map/B3.cpp`
- `src/immer/test/map/B6.cpp`
- `src/immer/test/map/default.cpp`
- `src/immer/test/map/gc.cpp`
- `src/immer/test/map/generic.ipp`
- `src/immer/test/map/issue-56.cpp`
- `src/immer/test/map_transient/B3.cpp`
- `src/immer/test/map_transient/B6.cpp`
- `src/immer/test/map_transient/default.cpp`
- `src/immer/test/map_transient/gc.cpp`
- `src/immer/test/map_transient/generic.ipp`
- `src/immer/test/memory/heaps.cpp`
- `src/immer/test/memory/refcounts.cpp`
- `src/immer/test/oss-fuzz/array-0.cpp`
- `src/immer/test/oss-fuzz/array-gc-0.cpp`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-array-5722369596063744`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-array-gc-5983642523009024`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-4806287339290624.fuzz`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-5068547731226624`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-5078027885871104.fuzz`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-5682145239236608`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-6237969917411328`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-bo-6038320384311296`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-4787718039797760`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-4855756386729984`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-4872518268354560`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5120685673021440`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5123086366801920`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5127731734642688`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5151861104181248`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5194423089233920`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5428967461617664`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5635385259196416`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5651513180160000`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5660697665732608`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-5676111456108544`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-6017886557306880`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-6265466893631488`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-6299398922043392`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-flex-vector-gc-6595824679911424`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-map-6457979420934144`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-map-gc-5748495613689856`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-map-st-5193157168594944`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-map-st-5313188008165376`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-map-st-6242663155761152`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-set-gc-5193673156067328`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-set-gc-5709797958352896`
- `src/immer/test/oss-fuzz/data/clusterfuzz-testcase-minimized-set-st-4717454829420544`
- `src/immer/test/oss-fuzz/data/crash-2838943da19b47c02dcff313e523eead0e2e8635`
- `src/immer/test/oss-fuzz/data/crash-dc9dad6beae69a6bb8ffd6d203b95032f445ec9b`
- `src/immer/test/oss-fuzz/flex-vector-0.cpp`
- `src/immer/test/oss-fuzz/flex-vector-bo-0.cpp`
- `src/immer/test/oss-fuzz/flex-vector-gc-0.cpp`
- `src/immer/test/oss-fuzz/input.hpp`
- `src/immer/test/oss-fuzz/map-gc-0.cpp`
- `src/immer/test/oss-fuzz/map-st-0.cpp`
- `src/immer/test/oss-fuzz/map-st-1.cpp`
- `src/immer/test/oss-fuzz/map-st-2.cpp`
- `src/immer/test/oss-fuzz/map-st-str-0.cpp`
- `src/immer/test/oss-fuzz/set-gc-0.cpp`
- `src/immer/test/oss-fuzz/set-gc-1.cpp`
- `src/immer/test/oss-fuzz/set-st-0.cpp`
- `src/immer/test/oss-fuzz/set-st-str-0.cpp`
- `src/immer/test/set/B3.cpp`
- `src/immer/test/set/B6.cpp`
- `src/immer/test/set/default.cpp`
- `src/immer/test/set/gc.cpp`
- `src/immer/test/set/generic.ipp`
- `src/immer/test/set_transient/B3.cpp`
- `src/immer/test/set_transient/B6.cpp`
- `src/immer/test/set_transient/default.cpp`
- `src/immer/test/set_transient/gc.cpp`
- `src/immer/test/set_transient/generic.ipp`
- `src/immer/test/table/B3.cpp`
- `src/immer/test/table/B6.cpp`
- `src/immer/test/table/default.cpp`
- `src/immer/test/table/gc.cpp`
- `src/immer/test/table/generic.ipp`
- `src/immer/test/table_transient/B3.cpp`
- `src/immer/test/table_transient/B6.cpp`
- `src/immer/test/table_transient/default.cpp`
- `src/immer/test/table_transient/gc.cpp`
- `src/immer/test/table_transient/generic.ipp`
- `src/immer/test/transient_tester.hpp`
- `src/immer/test/util.hpp`
- `src/immer/test/vector/B3-BL0.cpp`
- `src/immer/test/vector/B3-BL2.cpp`
- `src/immer/test/vector/B3-BL3.cpp`
- `src/immer/test/vector/B3-BL4.cpp`
- `src/immer/test/vector/default.cpp`
- `src/immer/test/vector/gc.cpp`
- `src/immer/test/vector/generic.ipp`
- `src/immer/test/vector/issue-16.cpp`
- `src/immer/test/vector/issue-177.cpp`
- `src/immer/test/vector/issue-46.cpp`
- `src/immer/test/vector/issue-74.cpp`
- `src/immer/test/vector_transient/B3-BL0.cpp`
- `src/immer/test/vector_transient/default.cpp`
- `src/immer/test/vector_transient/gc.cpp`
- `src/immer/test/vector_transient/generic.ipp`
- `src/immer/tools/clojure/README.md`
- `src/immer/tools/clojure/project.clj`
- `src/immer/tools/clojure/src/immer_benchmark.clj`
- `src/immer/tools/docker/icfp17/Dockerfile`
- `src/immer/tools/gdb_pretty_printers/__init__.py`
- `src/immer/tools/gdb_pretty_printers/autoload.py`
- `src/immer/tools/gdb_pretty_printers/printers.py`
- `src/immer/tools/include/nonius.h++`
- `src/immer/tools/include/prettyprint.hpp`
- `src/immer/tools/reproduce-paper-results.bash`
- `src/immer/tools/scala/README.md`
- `src/immer/tools/scala/build.sbt`
- `src/immer/tools/scala/src/test/scala/org/immer/benchmarks.scala`
- `src/immer/tools/scala/version.sbt`
- `src/immer/tools/with-tee.bash`

## Shared changed files requiring separate non-C++ review

These files were content-compared but excluded from automatic C/C++ marker analysis. Python tests, build scripts, configuration, documentation, translations, and vendor code need appropriate provenance conventions rather than C++ comment insertion.

| Target path | Category | Upstream path |
| --- | --- | --- |
| `.cirrus.yml` | build_config_other | `.cirrus.yml` |
| `.github/workflows/ci.yml` | build_config_other | `.github/workflows/ci.yml` |
| `.gitignore` | build_config_other | `.gitignore` |
| `.tx/config` | build_config_other | `.tx/config` |
| `CONTRIBUTING.md` | documentation_or_asset | `CONTRIBUTING.md` |
| `Makefile.am` | build_config_other | `Makefile.am` |
| `README.md` | documentation_or_asset | `README.md` |
| `SECURITY.md` | documentation_or_asset | `SECURITY.md` |
| `autogen.sh` | build_config_other | `autogen.sh` |
| `build-aux/m4/l_atomic.m4` | build_config_other | `build-aux/m4/l_atomic.m4` |
| `build-aux/m4/syscoin_qt.m4` | build_config_other | `build-aux/m4/bitcoin_qt.m4` |
| `build_msvc/.gitignore` | build_config_other | `build_msvc/.gitignore` |
| `build_msvc/README.md` | documentation_or_asset | `build_msvc/README.md` |
| `build_msvc/bench_syscoin/bench_syscoin.vcxproj.in` | build_config_other | `build_msvc/bench_bitcoin/bench_bitcoin.vcxproj.in` |
| `build_msvc/common.init.vcxproj.in` | build_config_other | `build_msvc/common.init.vcxproj.in` |
| `build_msvc/libsyscoin_common/libsyscoin_common.vcxproj.in` | build_config_other | `build_msvc/libbitcoin_common/libbitcoin_common.vcxproj.in` |
| `build_msvc/libsyscoin_consensus/libsyscoin_consensus.vcxproj` | build_config_other | `build_msvc/libbitcoin_consensus/libbitcoin_consensus.vcxproj` |
| `build_msvc/msbuild/tasks/hexdump.targets` | build_config_other | `build_msvc/msbuild/tasks/hexdump.targets` |
| `build_msvc/msvc-autogen.py` | build_config_other | `build_msvc/msvc-autogen.py` |
| `build_msvc/syscoin-tx/syscoin-tx.vcxproj` | build_config_other | `build_msvc/bitcoin-tx/bitcoin-tx.vcxproj` |
| `build_msvc/syscoin-wallet/syscoin-wallet.vcxproj` | build_config_other | `build_msvc/bitcoin-wallet/bitcoin-wallet.vcxproj` |
| `build_msvc/syscoin.sln` | build_config_other | `build_msvc/bitcoin.sln` |
| `build_msvc/syscoin_config.h.in` | build_config_other | `build_msvc/bitcoin_config.h.in` |
| `build_msvc/syscoind/syscoind.vcxproj` | build_config_other | `build_msvc/bitcoind/bitcoind.vcxproj` |
| `build_msvc/test_syscoin/test_syscoin.vcxproj` | build_config_other | `build_msvc/test_bitcoin/test_bitcoin.vcxproj` |
| `build_msvc/vcpkg.json` | build_config_other | `build_msvc/vcpkg.json` |
| `ci/lint/06_script.sh` | build_config_other | `ci/lint/06_script.sh` |
| `ci/test/00_setup_env_android.sh` | build_config_other | `ci/test/00_setup_env_android.sh` |
| `ci/test/00_setup_env_arm.sh` | build_config_other | `ci/test/00_setup_env_arm.sh` |
| `ci/test/00_setup_env_mac.sh` | build_config_other | `ci/test/00_setup_env_mac.sh` |
| `ci/test/00_setup_env_mac_native.sh` | build_config_other | `ci/test/00_setup_env_mac_native.sh` |
| `ci/test/00_setup_env_native_asan.sh` | build_config_other | `ci/test/00_setup_env_native_asan.sh` |
| `ci/test/00_setup_env_native_fuzz.sh` | build_config_other | `ci/test/00_setup_env_native_fuzz.sh` |
| `ci/test/00_setup_env_native_fuzz_with_valgrind.sh` | build_config_other | `ci/test/00_setup_env_native_fuzz_with_valgrind.sh` |
| `ci/test/00_setup_env_native_msan.sh` | build_config_other | `ci/test/00_setup_env_native_msan.sh` |
| `ci/test/00_setup_env_native_qt5.sh` | build_config_other | `ci/test/00_setup_env_native_qt5.sh` |
| `ci/test/00_setup_env_native_tidy.sh` | build_config_other | `ci/test/00_setup_env_native_tidy.sh` |
| `ci/test/00_setup_env_native_tsan.sh` | build_config_other | `ci/test/00_setup_env_native_tsan.sh` |
| `ci/test/00_setup_env_native_valgrind.sh` | build_config_other | `ci/test/00_setup_env_native_valgrind.sh` |
| `ci/test/00_setup_env_win64.sh` | build_config_other | `ci/test/00_setup_env_win64.sh` |
| `ci/test/01_base_install.sh` | build_config_other | `ci/test/01_base_install.sh` |
| `ci/test/06_script_b.sh` | build_config_other | `ci/test/06_script_b.sh` |
| `configure.ac` | build_config_other | `configure.ac` |
| `contrib/README.md` | documentation_or_asset | `contrib/README.md` |
| `contrib/debian/copyright` | build_config_other | `contrib/debian/copyright` |
| `contrib/devtools/README.md` | documentation_or_asset | `contrib/devtools/README.md` |
| `contrib/devtools/circular-dependencies.py` | build_config_other | `contrib/devtools/circular-dependencies.py` |
| `contrib/devtools/clang-format-diff.py` | build_config_other | `contrib/devtools/clang-format-diff.py` |
| `contrib/devtools/copyright_header.py` | build_config_other | `contrib/devtools/copyright_header.py` |
| `contrib/devtools/gen-manpages.py` | build_config_other | `contrib/devtools/gen-manpages.py` |
| `contrib/devtools/security-check.py` | build_config_other | `contrib/devtools/security-check.py` |
| `contrib/devtools/symbol-check.py` | build_config_other | `contrib/devtools/symbol-check.py` |
| `contrib/devtools/test-security-check.py` | build_config_other | `contrib/devtools/test-security-check.py` |
| `contrib/devtools/test-symbol-check.py` | build_config_other | `contrib/devtools/test-symbol-check.py` |
| `contrib/devtools/utxo_snapshot.sh` | build_config_other | `contrib/devtools/utxo_snapshot.sh` |
| `contrib/guix/INSTALL.md` | documentation_or_asset | `contrib/guix/INSTALL.md` |
| `contrib/guix/README.md` | documentation_or_asset | `contrib/guix/README.md` |
| `contrib/guix/guix-attest` | build_config_other | `contrib/guix/guix-attest` |
| `contrib/guix/guix-build` | build_config_other | `contrib/guix/guix-build` |
| `contrib/guix/guix-codesign` | build_config_other | `contrib/guix/guix-codesign` |
| `contrib/guix/libexec/build.sh` | build_config_other | `contrib/guix/libexec/build.sh` |
| `contrib/guix/libexec/codesign.sh` | build_config_other | `contrib/guix/libexec/codesign.sh` |
| `contrib/guix/libexec/prelude.bash` | build_config_other | `contrib/guix/libexec/prelude.bash` |
| `contrib/guix/manifest.scm` | build_config_other | `contrib/guix/manifest.scm` |
| `contrib/linearize/README.md` | documentation_or_asset | `contrib/linearize/README.md` |
| `contrib/linearize/example-linearize.cfg` | build_config_other | `contrib/linearize/example-linearize.cfg` |
| `contrib/linearize/linearize-hashes.py` | build_config_other | `contrib/linearize/linearize-hashes.py` |
| `contrib/macdeploy/README.md` | documentation_or_asset | `contrib/macdeploy/README.md` |
| `contrib/macdeploy/detached-sig-create.sh` | build_config_other | `contrib/macdeploy/detached-sig-create.sh` |
| `contrib/macdeploy/gen-sdk` | build_config_other | `contrib/macdeploy/gen-sdk` |
| `contrib/macdeploy/macdeployqtplus` | build_config_other | `contrib/macdeploy/macdeployqtplus` |
| `contrib/message-capture/message-capture-parser.py` | build_config_other | `contrib/message-capture/message-capture-parser.py` |
| `contrib/qos/README.md` | documentation_or_asset | `contrib/qos/README.md` |
| `contrib/qos/tc.sh` | build_config_other | `contrib/qos/tc.sh` |
| `contrib/seeds/README.md` | documentation_or_asset | `contrib/seeds/README.md` |
| `contrib/seeds/generate-seeds.py` | build_config_other | `contrib/seeds/generate-seeds.py` |
| `contrib/seeds/makeseeds.py` | build_config_other | `contrib/seeds/makeseeds.py` |
| `contrib/seeds/nodes_main.txt` | documentation_or_asset | `contrib/seeds/nodes_main.txt` |
| `contrib/seeds/nodes_test.txt` | documentation_or_asset | `contrib/seeds/nodes_test.txt` |
| `contrib/shell/git-utils.bash` | build_config_other | `contrib/shell/git-utils.bash` |
| `contrib/testgen/README.md` | documentation_or_asset | `contrib/testgen/README.md` |
| `contrib/testgen/gen_key_io_test_vectors.py` | build_config_other | `contrib/testgen/gen_key_io_test_vectors.py` |
| `contrib/tracing/README.md` | documentation_or_asset | `contrib/tracing/README.md` |
| `contrib/tracing/log_utxocache_flush.py` | build_config_other | `contrib/tracing/log_utxocache_flush.py` |
| `contrib/valgrind.supp` | build_config_other | `contrib/valgrind.supp` |
| `contrib/verify-commits/README.md` | documentation_or_asset | `contrib/verify-commits/README.md` |
| `contrib/verify-commits/gpg.sh` | build_config_other | `contrib/verify-commits/gpg.sh` |
| `contrib/verify-commits/trusted-git-root` | build_config_other | `contrib/verify-commits/trusted-git-root` |
| `contrib/verify-commits/trusted-keys` | build_config_other | `contrib/verify-commits/trusted-keys` |
| `contrib/verify-commits/trusted-sha512-root-commit` | build_config_other | `contrib/verify-commits/trusted-sha512-root-commit` |
| `contrib/verify-commits/verify-commits.py` | build_config_other | `contrib/verify-commits/verify-commits.py` |
| `contrib/windeploy/win-codesign.cert` | build_config_other | `contrib/windeploy/win-codesign.cert` |
| `contrib/zmq/zmq_sub.py` | build_config_other | `contrib/zmq/zmq_sub.py` |
| `depends/Makefile` | build_config_other | `depends/Makefile` |
| `depends/README.md` | documentation_or_asset | `depends/README.md` |
| `depends/builders/darwin.mk` | build_config_other | `depends/builders/darwin.mk` |
| `depends/builders/default.mk` | build_config_other | `depends/builders/default.mk` |
| `depends/builders/openbsd.mk` | build_config_other | `depends/builders/openbsd.mk` |
| `depends/config.guess` | build_config_other | `depends/config.guess` |
| `depends/config.site.in` | build_config_other | `depends/config.site.in` |
| `depends/config.sub` | build_config_other | `depends/config.sub` |
| `depends/description.md` | documentation_or_asset | `depends/description.md` |
| `depends/funcs.mk` | build_config_other | `depends/funcs.mk` |
| `depends/gen_id` | build_config_other | `depends/gen_id` |
| `depends/hosts/android.mk` | build_config_other | `depends/hosts/android.mk` |
| `depends/hosts/darwin.mk` | build_config_other | `depends/hosts/darwin.mk` |
| `depends/hosts/default.mk` | build_config_other | `depends/hosts/default.mk` |
| `depends/hosts/freebsd.mk` | build_config_other | `depends/hosts/freebsd.mk` |
| `depends/hosts/linux.mk` | build_config_other | `depends/hosts/linux.mk` |
| `depends/hosts/mingw32.mk` | build_config_other | `depends/hosts/mingw32.mk` |
| `depends/hosts/netbsd.mk` | build_config_other | `depends/hosts/netbsd.mk` |
| `depends/hosts/openbsd.mk` | build_config_other | `depends/hosts/openbsd.mk` |
| `depends/packages.md` | documentation_or_asset | `depends/packages.md` |
| `depends/packages/bdb.mk` | build_config_other | `depends/packages/bdb.mk` |
| `depends/packages/boost.mk` | build_config_other | `depends/packages/boost.mk` |
| `depends/packages/capnp.mk` | build_config_other | `depends/packages/capnp.mk` |
| `depends/packages/expat.mk` | build_config_other | `depends/packages/expat.mk` |
| `depends/packages/freetype.mk` | build_config_other | `depends/packages/freetype.mk` |
| `depends/packages/libXau.mk` | build_config_other | `depends/packages/libXau.mk` |
| `depends/packages/libevent.mk` | build_config_other | `depends/packages/libevent.mk` |
| `depends/packages/libmultiprocess.mk` | build_config_other | `depends/packages/libmultiprocess.mk` |
| `depends/packages/libnatpmp.mk` | build_config_other | `depends/packages/libnatpmp.mk` |
| `depends/packages/libxcb_util.mk` | build_config_other | `depends/packages/libxcb_util.mk` |
| `depends/packages/miniupnpc.mk` | build_config_other | `depends/packages/miniupnpc.mk` |
| `depends/packages/native_capnp.mk` | build_config_other | `depends/packages/native_capnp.mk` |
| `depends/packages/native_libmultiprocess.mk` | build_config_other | `depends/packages/native_libmultiprocess.mk` |
| `depends/packages/packages.mk` | build_config_other | `depends/packages/packages.mk` |
| `depends/packages/qrencode.mk` | build_config_other | `depends/packages/qrencode.mk` |
| `depends/packages/qt.mk` | build_config_other | `depends/packages/qt.mk` |
| `depends/packages/sqlite.mk` | build_config_other | `depends/packages/sqlite.mk` |
| `depends/packages/zeromq.mk` | build_config_other | `depends/packages/zeromq.mk` |
| `depends/patches/qt/dont_hardcode_pwd.patch` | build_config_other | `depends/patches/qt/dont_hardcode_pwd.patch` |
| `depends/patches/qt/fix_android_jni_static.patch` | build_config_other | `depends/patches/qt/fix_android_jni_static.patch` |
| `depends/patches/qt/mac-qmake.conf` | build_config_other | `depends/patches/qt/mac-qmake.conf` |
| `depends/patches/qt/memory_resource.patch` | build_config_other | `depends/patches/qt/memory_resource.patch` |
| `doc/JSON-RPC-interface.md` | documentation_or_asset | `doc/JSON-RPC-interface.md` |
| `doc/README.md` | documentation_or_asset | `doc/README.md` |
| `doc/README_windows.txt` | documentation_or_asset | `doc/README_windows.txt` |
| `doc/REST-interface.md` | documentation_or_asset | `doc/REST-interface.md` |
| `doc/build-osx.md` | documentation_or_asset | `doc/build-osx.md` |
| `doc/build-unix.md` | documentation_or_asset | `doc/build-unix.md` |
| `doc/dependencies.md` | documentation_or_asset | `doc/dependencies.md` |
| `doc/descriptors.md` | documentation_or_asset | `doc/descriptors.md` |
| `doc/developer-notes.md` | documentation_or_asset | `doc/developer-notes.md` |
| `doc/files.md` | documentation_or_asset | `doc/files.md` |
| `doc/fuzzing.md` | documentation_or_asset | `doc/fuzzing.md` |
| `doc/man/Makefile.am` | documentation_or_asset | `doc/man/Makefile.am` |
| `doc/man/syscoin-cli.1` | documentation_or_asset | `doc/man/bitcoin-cli.1` |
| `doc/man/syscoin-qt.1` | documentation_or_asset | `doc/man/bitcoin-qt.1` |
| `doc/man/syscoin-tx.1` | documentation_or_asset | `doc/man/bitcoin-tx.1` |
| `doc/man/syscoin-util.1` | documentation_or_asset | `doc/man/bitcoin-util.1` |
| `doc/man/syscoin-wallet.1` | documentation_or_asset | `doc/man/bitcoin-wallet.1` |
| `doc/man/syscoind.1` | documentation_or_asset | `doc/man/bitcoind.1` |
| `doc/managing-wallets.md` | documentation_or_asset | `doc/managing-wallets.md` |
| `doc/policy/mempool-replacements.md` | documentation_or_asset | `doc/policy/mempool-replacements.md` |
| `doc/psbt.md` | documentation_or_asset | `doc/psbt.md` |
| `doc/release-notes.md` | documentation_or_asset | `doc/release-notes.md` |
| `doc/release-notes/release-notes-0.10.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.10.0.md` |
| `doc/release-notes/release-notes-0.11.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.11.0.md` |
| `doc/release-notes/release-notes-0.12.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.12.0.md` |
| `doc/release-notes/release-notes-0.12.1.md` | documentation_or_asset | `doc/release-notes/release-notes-0.12.1.md` |
| `doc/release-notes/release-notes-0.13.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.13.0.md` |
| `doc/release-notes/release-notes-0.13.1.md` | documentation_or_asset | `doc/release-notes/release-notes-0.13.1.md` |
| `doc/release-notes/release-notes-0.13.2.md` | documentation_or_asset | `doc/release-notes/release-notes-0.13.2.md` |
| `doc/release-notes/release-notes-0.14.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.14.0.md` |
| `doc/release-notes/release-notes-0.15.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.15.0.md` |
| `doc/release-notes/release-notes-0.16.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.16.0.md` |
| `doc/release-notes/release-notes-0.17.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.17.0.md` |
| `doc/release-notes/release-notes-0.17.1.md` | documentation_or_asset | `doc/release-notes/release-notes-0.17.1.md` |
| `doc/release-notes/release-notes-0.3.22.md` | documentation_or_asset | `doc/release-notes/release-notes-0.3.22.md` |
| `doc/release-notes/release-notes-0.3.23.md` | documentation_or_asset | `doc/release-notes/release-notes-0.3.23.md` |
| `doc/release-notes/release-notes-0.4.3.md` | documentation_or_asset | `doc/release-notes/release-notes-0.4.3.md` |
| `doc/release-notes/release-notes-0.5.2.md` | documentation_or_asset | `doc/release-notes/release-notes-0.5.2.md` |
| `doc/release-notes/release-notes-0.7.1.md` | documentation_or_asset | `doc/release-notes/release-notes-0.7.1.md` |
| `doc/release-notes/release-notes-0.8.2.md` | documentation_or_asset | `doc/release-notes/release-notes-0.8.2.md` |
| `doc/release-notes/release-notes-0.9.0.md` | documentation_or_asset | `doc/release-notes/release-notes-0.9.0.md` |
| `doc/release-notes/release-notes-0.9.2.1.md` | documentation_or_asset | `doc/release-notes/release-notes-0.9.2.1.md` |
| `doc/release-notes/release-notes-0.9.2.md` | documentation_or_asset | `doc/release-notes/release-notes-0.9.2.md` |
| `doc/release-process.md` | documentation_or_asset | `doc/release-process.md` |
| `doc/tor.md` | documentation_or_asset | `doc/tor.md` |
| `doc/zmq.md` | documentation_or_asset | `doc/zmq.md` |
| `share/examples/syscoin.conf` | documentation_or_asset | `share/examples/bitcoin.conf` |
| `share/pixmaps/syscoin128.xpm` | documentation_or_asset | `share/pixmaps/bitcoin128.xpm` |
| `share/pixmaps/syscoin16.xpm` | documentation_or_asset | `share/pixmaps/bitcoin16.xpm` |
| `share/pixmaps/syscoin256.xpm` | documentation_or_asset | `share/pixmaps/bitcoin256.xpm` |
| `share/pixmaps/syscoin32.xpm` | documentation_or_asset | `share/pixmaps/bitcoin32.xpm` |
| `share/pixmaps/syscoin64.xpm` | documentation_or_asset | `share/pixmaps/bitcoin64.xpm` |
| `share/setup.nsi.in` | documentation_or_asset | `share/setup.nsi.in` |
| `src/Makefile.am` | build_config_other | `src/Makefile.am` |
| `src/Makefile.bench.include` | build_config_other | `src/Makefile.bench.include` |
| `src/Makefile.minisketch.include` | build_config_other | `src/Makefile.minisketch.include` |
| `src/Makefile.qt.include` | build_config_other | `src/Makefile.qt.include` |
| `src/Makefile.qttest.include` | build_config_other | `src/Makefile.qttest.include` |
| `src/Makefile.test.include` | build_config_other | `src/Makefile.test.include` |
| `src/Makefile.test_fuzz.include` | build_config_other | `src/Makefile.test_fuzz.include` |
| `src/Makefile.test_util.include` | build_config_other | `src/Makefile.test_util.include` |
| `src/crc32c/src/crc32c_arm64.cc` | vendor | `src/crc32c/src/crc32c_arm64.cc` |
| `src/leveldb/db/db_impl.cc` | vendor | `src/leveldb/db/db_impl.cc` |
| `src/leveldb/db/db_impl.h` | vendor | `src/leveldb/db/db_impl.h` |
| `src/leveldb/db/fault_injection_test.cc` | vendor | `src/leveldb/db/fault_injection_test.cc` |
| `src/leveldb/include/leveldb/db.h` | vendor | `src/leveldb/include/leveldb/db.h` |
| `src/leveldb/include/leveldb/status.h` | vendor | `src/leveldb/include/leveldb/status.h` |
| `src/minisketch/.cirrus.yml` | vendor | `src/minisketch/.cirrus.yml` |
| `src/minisketch/ci/cirrus.sh` | vendor | `src/minisketch/ci/cirrus.sh` |
| `src/minisketch/ci/linux-debian.Dockerfile` | vendor | `src/minisketch/ci/linux-debian.Dockerfile` |
| `src/minisketch/configure.ac` | vendor | `src/minisketch/configure.ac` |
| `src/minisketch/include/minisketch.h` | vendor | `src/minisketch/include/minisketch.h` |
| `src/minisketch/src/false_positives.h` | vendor | `src/minisketch/src/false_positives.h` |
| `src/minisketch/src/int_utils.h` | vendor | `src/minisketch/src/int_utils.h` |
| `src/minisketch/src/minisketch.cpp` | vendor | `src/minisketch/src/minisketch.cpp` |
| `src/minisketch/src/sketch.h` | vendor | `src/minisketch/src/sketch.h` |
| `src/minisketch/src/sketch_impl.h` | vendor | `src/minisketch/src/sketch_impl.h` |
| `src/qt/README.md` | documentation_or_asset | `src/qt/README.md` |
| `src/qt/forms/coincontroldialog.ui` | build_config_other | `src/qt/forms/coincontroldialog.ui` |
| `src/qt/forms/createwalletdialog.ui` | build_config_other | `src/qt/forms/createwalletdialog.ui` |
| `src/qt/forms/debugwindow.ui` | build_config_other | `src/qt/forms/debugwindow.ui` |
| `src/qt/forms/optionsdialog.ui` | build_config_other | `src/qt/forms/optionsdialog.ui` |
| `src/qt/forms/overviewpage.ui` | build_config_other | `src/qt/forms/overviewpage.ui` |
| `src/qt/forms/receiverequestdialog.ui` | build_config_other | `src/qt/forms/receiverequestdialog.ui` |
| `src/qt/forms/sendcoinsdialog.ui` | build_config_other | `src/qt/forms/sendcoinsdialog.ui` |
| `src/qt/locale/syscoin_ca.ts` | translation | `src/qt/locale/bitcoin_ca.ts` |
| `src/qt/locale/syscoin_cs.ts` | translation | `src/qt/locale/bitcoin_cs.ts` |
| `src/qt/locale/syscoin_de.ts` | translation | `src/qt/locale/bitcoin_de.ts` |
| `src/qt/locale/syscoin_de_AT.ts` | translation | `src/qt/locale/bitcoin_de_AT.ts` |
| `src/qt/locale/syscoin_de_CH.ts` | translation | `src/qt/locale/bitcoin_de_CH.ts` |
| `src/qt/locale/syscoin_el.ts` | translation | `src/qt/locale/bitcoin_el.ts` |
| `src/qt/locale/syscoin_es.ts` | translation | `src/qt/locale/bitcoin_es.ts` |
| `src/qt/locale/syscoin_es_CL.ts` | translation | `src/qt/locale/bitcoin_es_CL.ts` |
| `src/qt/locale/syscoin_es_CO.ts` | translation | `src/qt/locale/bitcoin_es_CO.ts` |
| `src/qt/locale/syscoin_es_DO.ts` | translation | `src/qt/locale/bitcoin_es_DO.ts` |
| `src/qt/locale/syscoin_es_SV.ts` | translation | `src/qt/locale/bitcoin_es_SV.ts` |
| `src/qt/locale/syscoin_es_VE.ts` | translation | `src/qt/locale/bitcoin_es_VE.ts` |
| `src/qt/locale/syscoin_fa.ts` | translation | `src/qt/locale/bitcoin_fa.ts` |
| `src/qt/locale/syscoin_hu.ts` | translation | `src/qt/locale/bitcoin_hu.ts` |
| `src/qt/locale/syscoin_km.ts` | translation | `src/qt/locale/bitcoin_km.ts` |
| `src/qt/locale/syscoin_kn.ts` | translation | `src/qt/locale/bitcoin_kn.ts` |
| `src/qt/locale/syscoin_ko.ts` | translation | `src/qt/locale/bitcoin_ko.ts` |
| `src/qt/locale/syscoin_lb.ts` | translation | `src/qt/locale/bitcoin_lb.ts` |
| `src/qt/locale/syscoin_ml.ts` | translation | `src/qt/locale/bitcoin_ml.ts` |
| `src/qt/locale/syscoin_nb.ts` | translation | `src/qt/locale/bitcoin_nb.ts` |
| `src/qt/locale/syscoin_nl.ts` | translation | `src/qt/locale/bitcoin_nl.ts` |
| `src/qt/locale/syscoin_pl.ts` | translation | `src/qt/locale/bitcoin_pl.ts` |
| `src/qt/locale/syscoin_sr.ts` | translation | `src/qt/locale/bitcoin_sr.ts` |
| `src/qt/locale/syscoin_sr@ijekavianlatin.ts` | translation | `src/qt/locale/bitcoin_sr@ijekavianlatin.ts` |
| `src/qt/locale/syscoin_sr@latin.ts` | translation | `src/qt/locale/bitcoin_sr@latin.ts` |
| `src/qt/locale/syscoin_te.ts` | translation | `src/qt/locale/bitcoin_te.ts` |
| `src/qt/locale/syscoin_uk.ts` | translation | `src/qt/locale/bitcoin_uk.ts` |
| `src/qt/locale/syscoin_uz@Cyrl.ts` | translation | `src/qt/locale/bitcoin_uz@Cyrl.ts` |
| `src/qt/res/src/syscoin.svg` | documentation_or_asset | `src/qt/res/src/bitcoin.svg` |
| `src/qt/syscoin.qrc` | build_config_other | `src/qt/bitcoin.qrc` |
| `src/test/data/bip341_wallet_vectors.json` | test | `src/test/data/bip341_wallet_vectors.json` |
| `src/test/data/key_io_invalid.json` | test | `src/test/data/key_io_invalid.json` |
| `src/test/data/key_io_valid.json` | test | `src/test/data/key_io_valid.json` |
| `src/test/data/tx_invalid.json` | test | `src/test/data/tx_invalid.json` |
| `src/test/data/tx_valid.json` | test | `src/test/data/tx_valid.json` |
| `src/univalue/include/univalue.h` | vendor | `src/univalue/include/univalue.h` |
| `src/univalue/lib/univalue.cpp` | vendor | `src/univalue/lib/univalue.cpp` |
| `test/config.ini.in` | test | `test/config.ini.in` |
| `test/functional/README.md` | test | `test/functional/README.md` |
| `test/functional/feature_assumeutxo.py` | test | `test/functional/feature_assumeutxo.py` |
| `test/functional/feature_assumevalid.py` | test | `test/functional/feature_assumevalid.py` |
| `test/functional/feature_block.py` | test | `test/functional/feature_block.py` |
| `test/functional/feature_coinstatsindex.py` | test | `test/functional/feature_coinstatsindex.py` |
| `test/functional/feature_index_prune.py` | test | `test/functional/feature_index_prune.py` |
| `test/functional/feature_init.py` | test | `test/functional/feature_init.py` |
| `test/functional/feature_maxuploadtarget.py` | test | `test/functional/feature_maxuploadtarget.py` |
| `test/functional/feature_pruning.py` | test | `test/functional/feature_pruning.py` |
| `test/functional/feature_rbf.py` | test | `test/functional/feature_rbf.py` |
| `test/functional/feature_remove_pruned_files_on_startup.py` | test | `test/functional/feature_remove_pruned_files_on_startup.py` |
| `test/functional/feature_segwit.py` | test | `test/functional/feature_segwit.py` |
| `test/functional/feature_taproot.py` | test | `test/functional/feature_taproot.py` |
| `test/functional/feature_utxo_set_hash.py` | test | `test/functional/feature_utxo_set_hash.py` |
| `test/functional/feature_versionbits_warning.py` | test | `test/functional/feature_versionbits_warning.py` |
| `test/functional/interface_rest.py` | test | `test/functional/interface_rest.py` |
| `test/functional/interface_syscoin_cli.py` | test | `test/functional/interface_bitcoin_cli.py` |
| `test/functional/mempool_accept.py` | test | `test/functional/mempool_accept.py` |
| `test/functional/mempool_limit.py` | test | `test/functional/mempool_limit.py` |
| `test/functional/mining_basic.py` | test | `test/functional/mining_basic.py` |
| `test/functional/mining_prioritisetransaction.py` | test | `test/functional/mining_prioritisetransaction.py` |
| `test/functional/p2p_addr_relay.py` | test | `test/functional/p2p_addr_relay.py` |
| `test/functional/p2p_blockfilters.py` | test | `test/functional/p2p_blockfilters.py` |
| `test/functional/p2p_filter.py` | test | `test/functional/p2p_filter.py` |
| `test/functional/p2p_getdata.py` | test | `test/functional/p2p_getdata.py` |
| `test/functional/p2p_headers_sync_with_minchainwork.py` | test | `test/functional/p2p_headers_sync_with_minchainwork.py` |
| `test/functional/p2p_ibd_stalling.py` | test | `test/functional/p2p_ibd_stalling.py` |
| `test/functional/p2p_invalid_messages.py` | test | `test/functional/p2p_invalid_messages.py` |
| `test/functional/p2p_segwit.py` | test | `test/functional/p2p_segwit.py` |
| `test/functional/rpc_dumptxoutset.py` | test | `test/functional/rpc_dumptxoutset.py` |
| `test/functional/rpc_getblockfrompeer.py` | test | `test/functional/rpc_getblockfrompeer.py` |
| `test/functional/rpc_getblockstats.py` | test | `test/functional/rpc_getblockstats.py` |
| `test/functional/rpc_help.py` | test | `test/functional/rpc_help.py` |
| `test/functional/rpc_misc.py` | test | `test/functional/rpc_misc.py` |
| `test/functional/rpc_net.py` | test | `test/functional/rpc_net.py` |
| `test/functional/rpc_psbt.py` | test | `test/functional/rpc_psbt.py` |
| `test/functional/rpc_rawtransaction.py` | test | `test/functional/rpc_rawtransaction.py` |
| `test/functional/rpc_scanblocks.py` | test | `test/functional/rpc_scanblocks.py` |
| `test/functional/rpc_scantxoutset.py` | test | `test/functional/rpc_scantxoutset.py` |
| `test/functional/rpc_signmessagewithprivkey.py` | test | `test/functional/rpc_signmessagewithprivkey.py` |
| `test/functional/rpc_validateaddress.py` | test | `test/functional/rpc_validateaddress.py` |
| `test/functional/test_framework/address.py` | test | `test/functional/test_framework/address.py` |
| `test/functional/test_framework/blocktools.py` | test | `test/functional/test_framework/blocktools.py` |
| `test/functional/test_framework/messages.py` | test | `test/functional/test_framework/messages.py` |
| `test/functional/test_framework/p2p.py` | test | `test/functional/test_framework/p2p.py` |
| `test/functional/test_framework/test_framework.py` | test | `test/functional/test_framework/test_framework.py` |
| `test/functional/test_framework/test_node.py` | test | `test/functional/test_framework/test_node.py` |
| `test/functional/test_framework/util.py` | test | `test/functional/test_framework/util.py` |
| `test/functional/test_runner.py` | test | `test/functional/test_runner.py` |
| `test/functional/wallet_abandonconflict.py` | test | `test/functional/wallet_abandonconflict.py` |
| `test/functional/wallet_avoid_mixing_output_types.py` | test | `test/functional/wallet_avoid_mixing_output_types.py` |
| `test/functional/wallet_avoidreuse.py` | test | `test/functional/wallet_avoidreuse.py` |
| `test/functional/wallet_balance.py` | test | `test/functional/wallet_balance.py` |
| `test/functional/wallet_basic.py` | test | `test/functional/wallet_basic.py` |
| `test/functional/wallet_bumpfee.py` | test | `test/functional/wallet_bumpfee.py` |
| `test/functional/wallet_crosschain.py` | test | `test/functional/wallet_crosschain.py` |
| `test/functional/wallet_fundrawtransaction.py` | test | `test/functional/wallet_fundrawtransaction.py` |
| `test/functional/wallet_groups.py` | test | `test/functional/wallet_groups.py` |
| `test/functional/wallet_import_rescan.py` | test | `test/functional/wallet_import_rescan.py` |
| `test/functional/wallet_importdescriptors.py` | test | `test/functional/wallet_importdescriptors.py` |
| `test/functional/wallet_keypool.py` | test | `test/functional/wallet_keypool.py` |
| `test/functional/wallet_listsinceblock.py` | test | `test/functional/wallet_listsinceblock.py` |
| `test/functional/wallet_pruning.py` | test | `test/functional/wallet_pruning.py` |
| `test/functional/wallet_send.py` | test | `test/functional/wallet_send.py` |
| `test/functional/wallet_simulaterawtx.py` | test | `test/functional/wallet_simulaterawtx.py` |
| `test/functional/wallet_transactiontime_rescan.py` | test | `test/functional/wallet_transactiontime_rescan.py` |
| `test/functional/wallet_txn_clone.py` | test | `test/functional/wallet_txn_clone.py` |
| `test/functional/wallet_txn_doublespend.py` | test | `test/functional/wallet_txn_doublespend.py` |
| `test/functional/wallet_watchonly.py` | test | `test/functional/wallet_watchonly.py` |
| `test/fuzz/test_runner.py` | test | `test/fuzz/test_runner.py` |
| `test/get_previous_releases.py` | test | `test/get_previous_releases.py` |
| `test/lint/git-subtree-check.sh` | test | `test/lint/git-subtree-check.sh` |
| `test/lint/lint-circular-dependencies.py` | test | `test/lint/lint-circular-dependencies.py` |
| `test/lint/lint-format-strings.py` | test | `test/lint/lint-format-strings.py` |
| `test/lint/lint-git-commit-check.py` | test | `test/lint/lint-git-commit-check.py` |
| `test/lint/lint-include-guards.py` | test | `test/lint/lint-include-guards.py` |
| `test/lint/lint-includes.py` | test | `test/lint/lint-includes.py` |
| `test/lint/lint-locale-dependence.py` | test | `test/lint/lint-locale-dependence.py` |
| `test/lint/lint-python.py` | test | `test/lint/lint-python.py` |
| `test/lint/lint-shell-locale.py` | test | `test/lint/lint-shell-locale.py` |
| `test/lint/lint-spelling.py` | test | `test/lint/lint-spelling.py` |
| `test/lint/lint-whitespace.py` | test | `test/lint/lint-whitespace.py` |
| `test/lint/run-lint-format-strings.py` | test | `test/lint/run-lint-format-strings.py` |
| `test/sanitizer_suppressions/tsan` | test | `test/sanitizer_suppressions/tsan` |
| `test/sanitizer_suppressions/ubsan` | test | `test/sanitizer_suppressions/ubsan` |
| `test/util/data/syscoin-util-test.json` | test | `test/util/data/bitcoin-util-test.json` |
| `test/util/data/tt-delin1-out.json` | test | `test/util/data/tt-delin1-out.json` |
| `test/util/data/tt-delout1-out.json` | test | `test/util/data/tt-delout1-out.json` |
| `test/util/data/tt-locktime317000-out.json` | test | `test/util/data/tt-locktime317000-out.json` |
| `test/util/data/txcreate1.hex` | test | `test/util/data/txcreate1.hex` |
| `test/util/data/txcreate1.json` | test | `test/util/data/txcreate1.json` |
| `test/util/data/txcreatedata1.json` | test | `test/util/data/txcreatedata1.json` |
| `test/util/data/txcreatedata2.json` | test | `test/util/data/txcreatedata2.json` |
| `test/util/data/txcreatedata_seq0.json` | test | `test/util/data/txcreatedata_seq0.json` |
| `test/util/data/txcreatedata_seq1.json` | test | `test/util/data/txcreatedata_seq1.json` |
| `test/util/data/txcreatemultisig3.json` | test | `test/util/data/txcreatemultisig3.json` |
| `test/util/data/txcreateoutpubkey2.json` | test | `test/util/data/txcreateoutpubkey2.json` |
| `test/util/data/txcreatescript3.json` | test | `test/util/data/txcreatescript3.json` |
| `test/util/data/txcreatesignv1.hex` | test | `test/util/data/txcreatesignv1.hex` |
| `test/util/data/txcreatesignv1.json` | test | `test/util/data/txcreatesignv1.json` |
| `test/util/data/txcreatesignv2.hex` | test | `test/util/data/txcreatesignv2.hex` |
