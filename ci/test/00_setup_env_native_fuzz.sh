#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export CONTAINER_NAME=ci_native_fuzz
export PACKAGES="cmake clang-18 llvm-18 libclang-rt-18-dev python3 libevent-dev bsdmainutils libboost-dev"
export DEP_OPTS="NO_UPNP=1 DEBUG=1"
export CPPFLAGS="-DDEBUG_LOCKORDER -DARENA_DEBUG"
export CI_CONTAINER_CAP="--cap-add SYS_PTRACE"
export LLVM_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-18"
export PYZMQ=true
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export RUN_FUZZ_TESTS=true
export GOAL="install"
export SYSCOIN_CONFIG="--enable-zmq --disable-ccache --enable-fuzz --with-sanitizers=fuzzer,address,undefined,integer CC='clang-18 -ftrivial-auto-var-init=pattern' CXX='clang++-18 -ftrivial-auto-var-init=pattern' --with-boost-process"
export NO_WERROR=1
export CCACHE_MAXSIZE=200M
