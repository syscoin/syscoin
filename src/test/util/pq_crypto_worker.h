// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_UTIL_PQ_CRYPTO_WORKER_H
#define SYSCOIN_TEST_UTIL_PQ_CRYPTO_WORKER_H

#include <crypto/slhdsa/slhdsa.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

/** Test-only preparation protocol. Seeds are public deterministic fixture data. */
namespace pq_test_crypto {

inline constexpr std::size_t MAX_JOBS{801};
inline constexpr std::uint32_t MAX_MEMBER{800};
inline constexpr char WORKER_FLAG[]{"--pq-test-crypto-worker"};

enum class Operation : std::uint32_t { Keygen = 1, Sign = 2 };

struct Job {
    std::uint32_t member{};
    slhdsa::KeyGenerationSeed seed{};
    std::array<std::uint8_t, 32> digest{};
};

struct Request {
    Operation operation{Operation::Keygen};
    std::vector<std::uint8_t> context;
    std::vector<Job> jobs;
};

struct Result {
    std::uint32_t member{};
    slhdsa::PublicKey public_key{};
    slhdsa::Signature signature{};
};

/** All protocol and crypto failures throw std::runtime_error. */
void WriteRequest(const std::filesystem::path& path, const Request& request);
Request ReadRequest(const std::filesystem::path& path);
std::vector<Result> Execute(const Request& request);
void WriteResponse(const std::filesystem::path& path, const Request& request,
                   const std::vector<Result>& results);
std::vector<Result> ReadResponse(const std::filesystem::path& path,
                                 const Request& expected_request);

/** Handle the reserved argv[1] mode before Boost or node initialization. */
std::optional<int> TryWorkerMain(int argc, char* argv[]);

} // namespace pq_test_crypto

#endif // SYSCOIN_TEST_UTIL_PQ_CRYPTO_WORKER_H
