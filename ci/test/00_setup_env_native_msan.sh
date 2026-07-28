#!/usr/bin/env bash
#
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
LIBCXX_DIR="/msan/cxx_build/"
export MSAN_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O1 -fno-optimize-sibling-calls"
LIBCXX_FLAGS="-nostdinc++ -nostdlib++ -isystem ${LIBCXX_DIR}include/c++/v1 -L${LIBCXX_DIR}lib -Wl,-rpath,${LIBCXX_DIR}lib -lc++ -lc++abi -lpthread -Wno-unused-command-line-argument"
export MSAN_AND_LIBCXX_FLAGS="${MSAN_FLAGS} ${LIBCXX_FLAGS}"

export CONTAINER_NAME="ci_native_msan"
export PACKAGES="cmake ninja-build clang-18 llvm-18 llvm-18-dev libclang-18-dev libclang-rt-18-dev"
# BDB generates false positives and will be removed in future.
export DEP_OPTS="NO_BDB=1 NO_QT=1 DEBUG=1 CC=clang CXX=clang++ CFLAGS='${MSAN_FLAGS}' CXXFLAGS='${MSAN_AND_LIBCXX_FLAGS}' gmp_config_opts='--disable-shared --enable-cxx --disable-fat --disable-assembly'"
export GOAL="install"
export SYSCOIN_CONFIG="--with-sanitizers=memory --disable-hardening --with-asm=no CPPFLAGS='-U_FORTIFY_SOURCE' CFLAGS='${MSAN_FLAGS}' CXXFLAGS='${MSAN_AND_LIBCXX_FLAGS}'"
export USE_MEMORY_SANITIZER="true"
export RUN_FUNCTIONAL_TESTS="false"
# GMP's fat-build CPU dispatcher intentionally probes an uninitialized stack
# buffer, while uninstrumented assembly writes are invisible to MSan. Use the
# instrumented generic-C implementation so the complete unit suite can run.
export RUN_UNIT_TESTS="false"
export RUN_UNIT_TESTS_SEQUENTIAL="true"
export CCACHE_MAXSIZE=250M
