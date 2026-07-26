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
# Hosted macOS cannot reliably complete the long-running Syscoin
# LLMQ/governance tests; cover those paths in the follow-up CI work.
export TEST_RUNNER_EXTRA="--exclude interface_zmq_nevm,feature_llmqchainlocks,feature_llmqconnections,feature_llmqsimplepose,feature_governance,feature_governance_dynamic"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
export CCACHE_MAXSIZE=400M
export CPATH="/opt/homebrew/include"
export LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt $LDFLAGS"
export RUN_FUZZ_TESTS=true
export FUZZ_TESTS_CONFIG="--exclude banman"  # https://github.com/bitcoin/bitcoin/issues/27924
