#!/usr/bin/env bash
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
export LC_ALL=C
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_SCRIPT="$SCRIPT_DIR/build-bitcoin-header-node.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/syscoin-btcheader-toolchain.XXXXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

CC_BIN="$(command -v clang || command -v cc)"
CXX_BIN="$(command -v clang++ || command -v c++)"

DARWIN_TOOLCHAIN="$TMP_ROOT/darwin.cmake"
HOST=aarch64-apple-darwin \
CC="$CC_BIN --target=aarch64-apple-darwin -isysroot/fake/MacOSX.sdk -nostdlibinc" \
CXX="$CXX_BIN --target=aarch64-apple-darwin -isysroot/fake/MacOSX.sdk -nostdlibinc" \
CFLAGS="-mmacos-version-min=13.0" \
CXXFLAGS="-mmacos-version-min=13.0 -stdlib=libc++" \
LDFLAGS="-Wl,-platform_version,macos,13.0,15.0" \
BTCHEADERNODE_DEPENDS_PREFIX="/fake/depends/aarch64-apple-darwin" \
    "$BUILD_SCRIPT" --emit-toolchain "$DARWIN_TOOLCHAIN"

grep -F 'set(CMAKE_SYSTEM_NAME "Darwin")' "$DARWIN_TOOLCHAIN"
grep -F 'set(CMAKE_SYSTEM_PROCESSOR "arm64")' "$DARWIN_TOOLCHAIN"
grep -F 'set(CMAKE_C_COMPILER_TARGET "aarch64-apple-darwin")' "$DARWIN_TOOLCHAIN"
grep -F -- '--target=aarch64-apple-darwin -isysroot/fake/MacOSX.sdk -nostdlibinc -mmacos-version-min=13.0' "$DARWIN_TOOLCHAIN"
grep -F 'set(CMAKE_OSX_SYSROOT "/fake/MacOSX.sdk")' "$DARWIN_TOOLCHAIN"
grep -F 'set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0")' "$DARWIN_TOOLCHAIN"
grep -F 'set(CMAKE_FIND_ROOT_PATH "/fake/depends/aarch64-apple-darwin")' "$DARWIN_TOOLCHAIN"

# LLVM tool names can be multicall symlinks. Exercise CMake's actual static
# archive create/finish rules so a canonicalized llvm-ranlib fails as it does
# in the Guix Darwin build, instead of checking only the emitted text.
ARCHIVE_TEST_ROOT="$TMP_ROOT/archive-test"
ARCHIVE_TOOL_DIR="$ARCHIVE_TEST_ROOT/tools"
ARCHIVE_SOURCE_DIR="$ARCHIVE_TEST_ROOT/source"
ARCHIVE_BUILD_DIR="$ARCHIVE_TEST_ROOT/build"
ARCHIVE_LOG="$ARCHIVE_TEST_ROOT/archive.log"
ARCHIVE_AR="$ARCHIVE_TOOL_DIR/llvm-ar"
ARCHIVE_RANLIB="$ARCHIVE_TOOL_DIR/llvm-ranlib"
REAL_AR="$(command -v ar)"

mkdir -p "$ARCHIVE_TOOL_DIR" "$ARCHIVE_SOURCE_DIR"
cat > "$ARCHIVE_AR" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "${0##*/}" "$*" >> "$BTCHEADERNODE_ARCHIVE_LOG"
case "${0##*/}" in
    llvm-ar)
        exec "$BTCHEADERNODE_REAL_AR" "$@"
        ;;
    llvm-ranlib)
        # The archive create step above already produced the artifact. The
        # regression is that this finish step retains its multicall basename.
        exit 0
        ;;
    *)
        echo "Unexpected archive tool entry point: ${0##*/}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "$ARCHIVE_AR"
ln -s llvm-ar "$ARCHIVE_RANLIB"

cat > "$ARCHIVE_SOURCE_DIR/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(btcheader_archive_probe C)
add_library(btcheader_archive_probe STATIC archive_probe.c)
EOF
cat > "$ARCHIVE_SOURCE_DIR/archive_probe.c" <<'EOF'
int btcheader_archive_probe(void) { return 0; }
EOF

ARCHIVE_TOOLCHAIN="$ARCHIVE_TEST_ROOT/toolchain.cmake"
HOST=aarch64-apple-darwin \
CC="$CC_BIN" \
CXX="$CXX_BIN" \
AR="$ARCHIVE_AR" \
RANLIB="$ARCHIVE_RANLIB" \
    "$BUILD_SCRIPT" --emit-toolchain "$ARCHIVE_TOOLCHAIN"

grep -F "set(CMAKE_AR \"$ARCHIVE_AR\")" "$ARCHIVE_TOOLCHAIN"
grep -F "set(CMAKE_RANLIB \"$ARCHIVE_RANLIB\")" "$ARCHIVE_TOOLCHAIN"

RELATIVE_ARCHIVE_TOOLCHAIN="$ARCHIVE_TEST_ROOT/relative-toolchain.cmake"
ARCHIVE_TOOL_DIR_PHYSICAL="$(cd "$ARCHIVE_TOOL_DIR" && pwd -P)"
(
    cd "$ARCHIVE_TEST_ROOT"
    HOST=aarch64-apple-darwin \
    CC="$CC_BIN" \
    CXX="$CXX_BIN" \
    AR="tools/llvm-ar" \
    RANLIB="tools/llvm-ranlib" \
        "$BUILD_SCRIPT" --emit-toolchain "$RELATIVE_ARCHIVE_TOOLCHAIN"
)
grep -F "set(CMAKE_AR \"$ARCHIVE_TOOL_DIR_PHYSICAL/llvm-ar\")" \
    "$RELATIVE_ARCHIVE_TOOLCHAIN"
grep -F "set(CMAKE_RANLIB \"$ARCHIVE_TOOL_DIR_PHYSICAL/llvm-ranlib\")" \
    "$RELATIVE_ARCHIVE_TOOLCHAIN"

BTCHEADERNODE_ARCHIVE_LOG="$ARCHIVE_LOG" \
BTCHEADERNODE_REAL_AR="$REAL_AR" \
    cmake -S "$ARCHIVE_SOURCE_DIR" -B "$ARCHIVE_BUILD_DIR" \
        -DCMAKE_TOOLCHAIN_FILE="$ARCHIVE_TOOLCHAIN" \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
BTCHEADERNODE_ARCHIVE_LOG="$ARCHIVE_LOG" \
BTCHEADERNODE_REAL_AR="$REAL_AR" \
    cmake --build "$ARCHIVE_BUILD_DIR"

test -f "$ARCHIVE_BUILD_DIR/libbtcheader_archive_probe.a"
grep -E '^llvm-ar .*[qr].*libbtcheader_archive_probe\.a' "$ARCHIVE_LOG"
grep -F 'llvm-ranlib libbtcheader_archive_probe.a' "$ARCHIVE_LOG"

LINUX_TOOLCHAIN="$TMP_ROOT/linux.cmake"
HOST=aarch64-linux-gnu \
CC="$CC_BIN --target=aarch64-linux-gnu --sysroot=/fake/linux-sysroot" \
CXX="$CXX_BIN --target=aarch64-linux-gnu --sysroot=/fake/linux-sysroot" \
CPPFLAGS="-I/fake/depends/aarch64-linux-gnu/include" \
LDFLAGS="-Wl,--as-needed" \
BTCHEADERNODE_DEPENDS_PREFIX="/fake/depends/aarch64-linux-gnu" \
    "$BUILD_SCRIPT" --emit-toolchain "$LINUX_TOOLCHAIN"

grep -F 'set(CMAKE_SYSTEM_NAME "Linux")' "$LINUX_TOOLCHAIN"
grep -F 'set(CMAKE_SYSTEM_PROCESSOR "aarch64")' "$LINUX_TOOLCHAIN"
grep -F -- '--target=aarch64-linux-gnu --sysroot=/fake/linux-sysroot -I/fake/depends/aarch64-linux-gnu/include' "$LINUX_TOOLCHAIN"
grep -F 'set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--as-needed")' "$LINUX_TOOLCHAIN"

echo "btcheadernode cross-toolchain generation: PASS"
