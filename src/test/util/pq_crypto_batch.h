// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license; see COPYING.
#ifndef SYSCOIN_TEST_UTIL_PQ_CRYPTO_BATCH_H
#define SYSCOIN_TEST_UTIL_PQ_CRYPTO_BATCH_H

#include <test/util/pq_crypto_worker.h>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <vector>

namespace pq_test_crypto {
// Empty/unset means the existing in-process test path. A requested but unsupported
// subprocess mode is an error, never an implicit fallback or test omission.
std::size_t RequestedWorkerCount();
std::vector<Result> RunBatches(const std::filesystem::path& executable,
                              const std::filesystem::path& new_directory,
                              const Request& request, std::size_t workers,
                              std::chrono::seconds timeout = std::chrono::hours{3});
} // namespace pq_test_crypto
#endif
