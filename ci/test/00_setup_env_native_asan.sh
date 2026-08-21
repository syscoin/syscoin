#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# BCC needs access to host kernel facilities that are not available in every
# container runtime. Opt in on a suitably configured runner.
if [[ "${INSTALL_BCC_TRACING_TOOLS}" == "true" ]]; then
  BPFCC_PACKAGE="bpfcc-tools linux-headers-$(uname --kernel-release)"
  export CI_CONTAINER_CAP="--privileged -v /sys/kernel:/sys/kernel:rw"
else
  BPFCC_PACKAGE=""
  # ASan + LSan needs access to ptrace.
  # See https://github.com/google/sanitizers/issues/764.
  export CI_CONTAINER_CAP="--cap-add SYS_PTRACE"
fi

export CONTAINER_NAME=ci_native_asan
# SYSCOIN: The post-BLS sanitizer image no longer installs GMP.
export PACKAGES="systemtap-sdt-dev clang-18 llvm-18 libclang-rt-18-dev python3-zmq qtbase5-dev qttools5-dev qttools5-dev-tools libevent-dev libboost-dev libdb5.3++-dev libminiupnpc-dev libnatpmp-dev libzmq3-dev libqrencode-dev libsqlite3-dev ${BPFCC_PACKAGE}"
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export NO_DEPENDS=1
export GOAL="install"
export CCACHE_MAXSIZE=300M
# SYSCOIN: Docker's network can expose AF_INET6 to Python while libevent cannot resolve
# or bind ::1. Keep the bind tests in normal CI and skip them in this lane.
# SYSCOIN: Full 65,536-leaf C11 fixtures take multiple hours when instrumented.
# Exclude the remaining full-tree masternode setups; the focused lifecycle uses
# a bound regtest commitment while shallow units cover the real worker/crypto path.
PQ_FULL_TREE_TESTS="feature_deterministicmns,feature_nevm_data"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},rpc_masternode,rpc_mnauth"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_objects,feature_governance"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_dynamic,feature_btcheader_policy_auxpow"
# SYSCOIN: The full-dimension ChainLocks functional prevents this lane from
# completing under AddressSanitizer; native macOS and TSan retain the test.
export TEST_RUNNER_EXTRA="--exclude interface_zmq_nevm,rpc_bind,feature_bind_extra,feature_proxy,${PQ_FULL_TREE_TESTS},feature_pq_chainlocks"
export SYSCOIN_CONFIG="--enable-c++20 --enable-usdt --enable-zmq --with-incompatible-bdb --with-gui=qt5 \
CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER' \
--with-sanitizers=address,float-divide-by-zero,integer,undefined \
CC='clang-18 -ftrivial-auto-var-init=pattern' CXX='clang++-18 -ftrivial-auto-var-init=pattern'"
