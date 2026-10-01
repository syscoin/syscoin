#!/usr/bin/env bash
# Bounded diagnostic only. Never invoke the full test suite from here.
set -eo pipefail
export LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive
exec > >(tee /output/driver.log) 2>&1
set -x

# Use the same package set, compiler selection and image as native ASan CI.
source /source/ci/test/00_setup_env_native_asan.sh
apt-get update
# PACKAGES is the repository's whitespace-separated Debian package list.
# shellcheck disable=SC2086
apt-get install --no-install-recommends --no-upgrade -y ${PACKAGES} \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  curl ca-certificates ccache python3 rsync git procps bison e2fsprogs
clang-18 --version
clang++-18 --version
uname -a
lscpu
free -m

mkdir -p /ci_container_base /output/build
rsync -a --exclude=.git /source/ /ci_container_base/
cd /ci_container_base
./autogen.sh
cd /output/build
/ci_container_base/configure --disable-dependency-tracking --enable-werror \
  --enable-external-signer --prefix=/output/install --enable-c++20 --enable-usdt \
  --enable-zmq --with-incompatible-bdb --with-gui=qt5 \
  CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER' \
  --with-sanitizers=address,float-divide-by-zero,integer,undefined \
  CC='clang-18 -ftrivial-auto-var-init=pattern' \
  CXX='clang++-18 -ftrivial-auto-var-init=pattern'
make -C src -f Makefile -f /ci_container_base/ci/profile/profile.mk \
  V=1 -j4 pq-signing-profile

# Identical runtime options and suppression contents to ci/test/06_script_b.sh.
export ASAN_OPTIONS='detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1'
export LSAN_OPTIONS='suppressions=/ci_container_base/test/sanitizer_suppressions/lsan'
export UBSAN_OPTIONS='suppressions=/ci_container_base/test/sanitizer_suppressions/ubsan:print_stacktrace=1:halt_on_error=1:report_error_type=1'
sha256sum /ci_container_base/test/sanitizer_suppressions/{lsan,ubsan}
python3 /ci_container_base/ci/profile/observe.py \
  --seconds 1200 --output /output/metrics.jsonl -- ./src/pq-signing-profile
