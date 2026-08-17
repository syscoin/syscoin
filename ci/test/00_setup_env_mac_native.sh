#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export HOST=x86_64-apple-darwin
export PIP_PACKAGES="zmq"
export PIP_INSTALL_FLAGS="--break-system-packages"
export GOAL="install"
export SYSCOIN_CONFIG="--with-gui --with-miniupnpc --with-natpmp --enable-reduce-exports"
# SYSCOIN: Each full PQ operator tree saturates all four hosted macOS CPUs, so
# running several masternode fixtures under -j10 can starve registration RPCs.
# Exclude the remaining full-tree fixtures; the focused lifecycle uses its
# production-generated regtest commitment and stays in the parallel batch.
PQ_FULL_TREE_TESTS="feature_deterministicmns,feature_nevm_data"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},rpc_masternode,rpc_mnauth"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_objects,feature_governance"
PQ_FULL_TREE_TESTS="${PQ_FULL_TREE_TESTS},feature_governance_dynamic,feature_btcheader_policy_auxpow"
export TEST_RUNNER_EXTRA="--exclude interface_zmq_nevm,${PQ_FULL_TREE_TESTS}"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
export CCACHE_MAXSIZE=400M
export CPATH="/opt/homebrew/include"
export LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt $LDFLAGS"
export RUN_FUZZ_TESTS=true
export FUZZ_TESTS_CONFIG="--exclude banman"  # https://github.com/bitcoin/bitcoin/issues/27924
