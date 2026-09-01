#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_tsan
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export PACKAGES="cmake clang-18 llvm-18 libclang-rt-18-dev libc++abi-18-dev libc++-18-dev python3-zmq"
export DEP_OPTS="NO_QT=1 CC=clang-18 CXX='clang++-18 -stdlib=libc++'"
export GOAL="install"
export SYSCOIN_CONFIG="--enable-zmq --with-gui=no --with-sanitizers=thread --with-boost-process \
CC=clang-18 CXX='clang++-18 -stdlib=libc++' CXXFLAGS='-g' \
CPPFLAGS='-DARENA_DEBUG -DDEBUG_LOCKORDER -DDEBUG_LOCKCONTENTION -D_LIBCPP_REMOVE_TRANSITIVE_INCLUDES'"
# SYSCOIN: Docker's network can expose AF_INET6 to Python while libevent cannot resolve
# or bind ::1. Keep the bind tests in normal CI and skip them in this lane.
# SYSCOIN: Full 65,536-leaf scheduled-WOTS fixtures take multiple hours when instrumented.
# Exclude the remaining full-tree masternode setups; focused crypto and
# ChainLock tests cover the real worker/signing paths.
PQ_FULL_TREE_TESTS="feature_deterministicmns,feature_nevm_data"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},rpc_masternode,rpc_mnauth"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_objects,feature_governance"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_dynamic,feature_btcheader_policy_auxpow"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_pq_chainlocks"
export TEST_RUNNER_EXTRA="--exclude interface_zmq_nevm,rpc_bind,feature_bind_extra,feature_proxy,${PQ_FULL_TREE_TESTS}"
export PYZMQ=true
export NO_WERROR=1
