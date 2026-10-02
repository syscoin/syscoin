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

# A compiler's entry-point name can select both the dispatcher and C++ link
# semantics. A real mixed-language executable catches more than path text.
COMPILER_TEST_ROOT="$TMP_ROOT/compiler-test"
COMPILER_TOOL_DIR="$COMPILER_TEST_ROOT/tools"
COMPILER_SOURCE_DIR="$COMPILER_TEST_ROOT/source"
COMPILER_BUILD_DIR="$COMPILER_TEST_ROOT/build"
COMPILER_LOG="$COMPILER_TEST_ROOT/compiler.log"
case "$(uname -s)" in
    Darwin) COMPILER_HOST="$(uname -m)-apple-darwin" ;;
    Linux) COMPILER_HOST="$(uname -m)-linux-gnu" ;;
    *) echo "Unsupported compiler-probe host" >&2; exit 1 ;;
esac
mkdir -p "$COMPILER_TOOL_DIR" "$COMPILER_SOURCE_DIR"
COMPILER_TOOL_DIR="$(cd "$COMPILER_TOOL_DIR" && pwd -P)"
COMPILER_CC="$COMPILER_TOOL_DIR/cc-probe"
COMPILER_CXX="$COMPILER_TOOL_DIR/cxx-probe"
cat > "$COMPILER_TOOL_DIR/compiler-dispatch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "${0##*/}" "$*" >> "$BTCHEADERNODE_COMPILER_LOG"
case "${0##*/}" in
    cc-probe|*-gcc) exec "$BTCHEADERNODE_REAL_CC" "$@" ;;
    cxx-probe|*-g++) exec "$BTCHEADERNODE_REAL_CXX" "$@" ;;
    *) echo "Compiler entry point was canonicalized: ${0##*/}" >&2; exit 1 ;;
esac
EOF
chmod +x "$COMPILER_TOOL_DIR/compiler-dispatch"
for alias in cc-probe cxx-probe "$COMPILER_HOST-gcc" "$COMPILER_HOST-g++"; do
    ln -s compiler-dispatch "$COMPILER_TOOL_DIR/$alias"
done

emit_compiler_alias_toolchain() {
    HOST="$COMPILER_HOST" \
    CC="$2 -DBTCHEADERNODE_ALIAS_C=1" \
    CXX="$3 -DBTCHEADERNODE_ALIAS_CXX=1" \
    CFLAGS= CXXFLAGS= LDFLAGS= \
    CPPFLAGS="-DBTCHEADERNODE_ALIAS_SHARED=1" \
    AR= RANLIB= NM= STRIP= BTCHEADERNODE_DEPENDS_PREFIX= \
        "$BUILD_SCRIPT" --emit-toolchain "$1"
}

COMPILER_TOOLCHAIN="$COMPILER_TEST_ROOT/toolchain.cmake"
emit_compiler_alias_toolchain "$COMPILER_TOOLCHAIN" "$COMPILER_CC" "$COMPILER_CXX"
grep -E '^set\(CMAKE_(C|CXX)_COMPILER ' "$COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_C_COMPILER \"$COMPILER_CC\")" "$COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_CXX_COMPILER \"$COMPILER_CXX\")" "$COMPILER_TOOLCHAIN"
grep -F 'set(CMAKE_C_FLAGS_INIT "-DBTCHEADERNODE_ALIAS_C=1 -DBTCHEADERNODE_ALIAS_SHARED=1")' \
    "$COMPILER_TOOLCHAIN"
grep -F 'set(CMAKE_CXX_FLAGS_INIT "-DBTCHEADERNODE_ALIAS_CXX=1 -DBTCHEADERNODE_ALIAS_SHARED=1")' \
    "$COMPILER_TOOLCHAIN"

RELATIVE_COMPILER_TOOLCHAIN="$COMPILER_TEST_ROOT/relative-toolchain.cmake"
(
    cd "$COMPILER_TEST_ROOT"
    emit_compiler_alias_toolchain "$RELATIVE_COMPILER_TOOLCHAIN" tools/cc-probe tools/cxx-probe
)
grep -F "set(CMAKE_C_COMPILER \"$COMPILER_CC\")" "$RELATIVE_COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_CXX_COMPILER \"$COMPILER_CXX\")" "$RELATIVE_COMPILER_TOOLCHAIN"

PATH_COMPILER_TOOLCHAIN="$COMPILER_TEST_ROOT/path-toolchain.cmake"
PATH="$COMPILER_TOOL_DIR:$PATH" \
    emit_compiler_alias_toolchain "$PATH_COMPILER_TOOLCHAIN" cc-probe cxx-probe
grep -F "set(CMAKE_C_COMPILER \"$COMPILER_CC\")" "$PATH_COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_CXX_COMPILER \"$COMPILER_CXX\")" "$PATH_COMPILER_TOOLCHAIN"

FALLBACK_COMPILER_TOOLCHAIN="$COMPILER_TEST_ROOT/fallback-toolchain.cmake"
PATH="$COMPILER_TOOL_DIR:$PATH" HOST="$COMPILER_HOST" CC= CXX= \
CFLAGS= CXXFLAGS= CPPFLAGS= LDFLAGS= AR= RANLIB= NM= STRIP= BTCHEADERNODE_DEPENDS_PREFIX= \
    "$BUILD_SCRIPT" --emit-toolchain "$FALLBACK_COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_C_COMPILER \"$COMPILER_TOOL_DIR/$COMPILER_HOST-gcc\")" "$FALLBACK_COMPILER_TOOLCHAIN"
grep -F "set(CMAKE_CXX_COMPILER \"$COMPILER_TOOL_DIR/$COMPILER_HOST-g++\")" "$FALLBACK_COMPILER_TOOLCHAIN"

if (
    cd "$COMPILER_TEST_ROOT"
    emit_compiler_alias_toolchain "$COMPILER_TEST_ROOT/invalid-c.cmake" printf "$COMPILER_CXX"
) > "$COMPILER_TEST_ROOT/invalid-c.log" 2>&1; then
    echo "Expected the shell builtin CC to be rejected" >&2
    exit 1
fi
grep -Fx 'Could not locate the configured C compiler.' "$COMPILER_TEST_ROOT/invalid-c.log"

if (
    cd "$COMPILER_TEST_ROOT"
    emit_compiler_alias_toolchain "$COMPILER_TEST_ROOT/invalid-cxx.cmake" "$COMPILER_CC" printf
) > "$COMPILER_TEST_ROOT/invalid-cxx.log" 2>&1; then
    echo "Expected the shell builtin CXX to be rejected" >&2
    exit 1
fi
grep -Fx 'Could not locate the configured C++ compiler.' "$COMPILER_TEST_ROOT/invalid-cxx.log"

cat > "$COMPILER_SOURCE_DIR/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(btcheader_compiler_probe C CXX)
add_executable(compiler_probe probe.c probe.cpp)
EOF
cat > "$COMPILER_SOURCE_DIR/probe.c" <<'EOF'
#if !defined(BTCHEADERNODE_ALIAS_C) || !defined(BTCHEADERNODE_ALIAS_SHARED)
#error Missing C compiler command flags
#endif
int compiler_probe_value(void) { return 42; }
EOF
cat > "$COMPILER_SOURCE_DIR/probe.cpp" <<'EOF'
#include <iostream>
#if !defined(BTCHEADERNODE_ALIAS_CXX) || !defined(BTCHEADERNODE_ALIAS_SHARED)
#error Missing C++ compiler command flags
#endif
extern "C" int compiler_probe_value(void);
int main() { std::cout << "compiler alias: " << compiler_probe_value() << '\n'; }
EOF

BTCHEADERNODE_COMPILER_LOG="$COMPILER_LOG" \
BTCHEADERNODE_REAL_CC="$CC_BIN" BTCHEADERNODE_REAL_CXX="$CXX_BIN" \
    cmake -S "$COMPILER_SOURCE_DIR" -B "$COMPILER_BUILD_DIR" \
        -DCMAKE_TOOLCHAIN_FILE="$COMPILER_TOOLCHAIN"
BTCHEADERNODE_COMPILER_LOG="$COMPILER_LOG" \
BTCHEADERNODE_REAL_CC="$CC_BIN" BTCHEADERNODE_REAL_CXX="$CXX_BIN" \
    cmake --build "$COMPILER_BUILD_DIR"
test "$("$COMPILER_BUILD_DIR/compiler_probe")" = "compiler alias: 42"
grep -F 'cc-probe ' "$COMPILER_LOG"
grep -F 'cxx-probe ' "$COMPILER_LOG"

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
