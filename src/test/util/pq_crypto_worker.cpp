// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/pq_crypto_worker.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string_view>

namespace pq_test_crypto {
namespace {

constexpr std::array<std::uint8_t, 8> REQUEST_MAGIC{'P', 'Q', 'T', 'R', 'E', 'Q', '0', '1'};
constexpr std::array<std::uint8_t, 8> RESPONSE_MAGIC{'P', 'Q', 'T', 'R', 'S', 'P', '0', '1'};
constexpr std::uint32_t VERSION{1};
// All integers are little-endian uint32_t. No native struct representation is sent.
constexpr std::size_t MAX_REQUEST_BYTES{8 + 4 * 4 + slhdsa::MAX_CONTEXT_SIZE + MAX_JOBS * (4 + slhdsa::KEY_GENERATION_SEED_SIZE + 32)};
constexpr std::size_t MAX_RESPONSE_BYTES{8 + 4 + MAX_REQUEST_BYTES + 4 + MAX_JOBS * (4 + slhdsa::PUBLIC_KEY_SIZE + slhdsa::SIGNATURE_SIZE)};

[[noreturn]] void Fail(const char* message)
{
    throw std::runtime_error(message);
}

bool IsZero(std::span<const std::uint8_t> bytes)
{
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte == 0; });
}

void ValidateRequest(const Request& request)
{
    if (request.operation != Operation::Keygen && request.operation != Operation::Sign) Fail("unknown crypto operation");
    if (request.context.size() > slhdsa::MAX_CONTEXT_SIZE) Fail("crypto context too large");
    if (request.jobs.empty() || request.jobs.size() > MAX_JOBS) Fail("invalid crypto job count");
    if (request.operation == Operation::Keygen && !request.context.empty()) Fail("keygen context must be empty");
    std::array<bool, MAX_JOBS> seen{};
    for (const auto& job : request.jobs) {
        if (job.member > MAX_MEMBER) Fail("crypto member out of range");
        if (seen[job.member]) Fail("duplicate crypto member");
        seen[job.member] = true;
        if (request.operation == Operation::Keygen && !IsZero(job.digest)) Fail("keygen digest must be zero");
    }
}

void ValidateResults(const Request& request, const std::vector<Result>& results)
{
    if (results.size() != request.jobs.size()) Fail("crypto result count mismatch");
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (results[i].member != request.jobs[i].member) Fail("crypto result member mismatch");
        if (request.operation == Operation::Keygen && !IsZero(results[i].signature)) Fail("keygen signature must be zero");
    }
}

class Reader {
    std::ifstream m_file;
    std::size_t m_remaining;

public:
    Reader(const std::filesystem::path& path, std::size_t limit) : m_file(path, std::ios::binary), m_remaining(limit)
    {
        if (!m_file) Fail("cannot open crypto input");
    }

    void Bytes(std::span<std::uint8_t> bytes)
    {
        if (bytes.size() > m_remaining) Fail("crypto input exceeds size limit");
        if (!bytes.empty() && !m_file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) Fail("truncated crypto input");
        m_remaining -= bytes.size();
    }

    std::uint32_t U32()
    {
        std::array<std::uint8_t, 4> bytes{};
        Bytes(bytes);
        return std::uint32_t{bytes[0]} | (std::uint32_t{bytes[1]} << 8) |
               (std::uint32_t{bytes[2]} << 16) | (std::uint32_t{bytes[3]} << 24);
    }

    void Header(const std::array<std::uint8_t, 8>& expected)
    {
        std::array<std::uint8_t, 8> magic{};
        Bytes(magic);
        if (magic != expected) Fail("invalid crypto protocol magic");
        if (U32() != VERSION) Fail("unsupported crypto protocol version");
    }

    void Finish()
    {
        char extra{};
        if (m_file.get(extra)) Fail("trailing crypto input");
        if (!m_file.eof() || m_file.bad()) Fail("cannot finish reading crypto input");
    }
};

class Writer {
    std::ofstream m_file;
    std::size_t m_remaining;

public:
    Writer(const std::filesystem::path& path, std::size_t limit) : m_file(path, std::ios::binary | std::ios::trunc), m_remaining(limit)
    {
        if (!m_file) Fail("cannot open crypto output");
    }

    void Bytes(std::span<const std::uint8_t> bytes)
    {
        if (bytes.size() > m_remaining) Fail("crypto output exceeds size limit");
        if (!bytes.empty() && !m_file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) Fail("cannot write crypto output");
        m_remaining -= bytes.size();
    }

    void U32(std::uint32_t value)
    {
        const std::array<std::uint8_t, 4> bytes{static_cast<std::uint8_t>(value), static_cast<std::uint8_t>(value >> 8),
                                                static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)};
        Bytes(bytes);
    }

    void Header(const std::array<std::uint8_t, 8>& magic)
    {
        Bytes(magic);
        U32(VERSION);
    }

    void Finish()
    {
        m_file.close();
        if (!m_file) Fail("cannot finish writing crypto output");
    }
};

void WriteRequestBody(Writer& writer, const Request& request)
{
    writer.Header(REQUEST_MAGIC);
    writer.U32(static_cast<std::uint32_t>(request.operation));
    writer.U32(static_cast<std::uint32_t>(request.jobs.size()));
    writer.U32(static_cast<std::uint32_t>(request.context.size()));
    writer.Bytes(request.context);
    for (const auto& job : request.jobs) {
        writer.U32(job.member);
        writer.Bytes(job.seed);
        writer.Bytes(job.digest);
    }
}

Request ReadRequestBody(Reader& reader)
{
    reader.Header(REQUEST_MAGIC);
    Request request;
    request.operation = static_cast<Operation>(reader.U32());
    if (request.operation != Operation::Keygen && request.operation != Operation::Sign) Fail("unknown crypto operation");
    const auto count = reader.U32();
    const auto context_size = reader.U32();
    if (count == 0 || count > MAX_JOBS) Fail("invalid crypto job count");
    if (context_size > slhdsa::MAX_CONTEXT_SIZE) Fail("crypto context too large");
    if (request.operation == Operation::Keygen && context_size != 0) Fail("keygen context must be empty");
    request.context.resize(context_size);
    reader.Bytes(request.context);
    request.jobs.resize(count);
    for (auto& job : request.jobs) {
        job.member = reader.U32();
        reader.Bytes(job.seed);
        reader.Bytes(job.digest);
    }
    ValidateRequest(request);
    return request;
}

bool SameRequest(const Request& left, const Request& right)
{
    if (left.operation != right.operation || left.context != right.context || left.jobs.size() != right.jobs.size()) return false;
    for (std::size_t i = 0; i < left.jobs.size(); ++i) {
        if (left.jobs[i].member != right.jobs[i].member || left.jobs[i].seed != right.jobs[i].seed || left.jobs[i].digest != right.jobs[i].digest) return false;
    }
    return true;
}

} // namespace

void WriteRequest(const std::filesystem::path& path, const Request& request)
{
    ValidateRequest(request);
    Writer writer(path, MAX_REQUEST_BYTES);
    WriteRequestBody(writer, request);
    writer.Finish();
}

Request ReadRequest(const std::filesystem::path& path)
{
    Reader reader(path, MAX_REQUEST_BYTES);
    auto request = ReadRequestBody(reader);
    reader.Finish();
    return request;
}

std::vector<Result> Execute(const Request& request)
{
    ValidateRequest(request);
    std::vector<Result> results;
    results.reserve(request.jobs.size());
    for (const auto& job : request.jobs) {
        auto secret = slhdsa::GenerateSecretKey(job.seed);
        if (!secret) Fail("crypto worker key generation failed");
        Result result;
        result.member = job.member;
        if (!secret->GetPublicKey(result.public_key)) Fail("crypto worker public key extraction failed");
        if (request.operation == Operation::Sign) {
            if (!slhdsa::SignDeterministic(*secret, job.digest, request.context, result.signature)) Fail("crypto worker signing failed");
            if (!slhdsa::Verify(result.public_key, job.digest, request.context, result.signature)) Fail("crypto worker verification failed");
        }
        results.push_back(result);
        if (results.size() % 32 == 0 || results.size() == request.jobs.size()) {
            std::fprintf(stderr, "PQ population crypto worker: %zu/%zu %s jobs complete\n", results.size(), request.jobs.size(),
                         request.operation == Operation::Keygen ? "keygen" : "sign");
        }
    }
    return results;
}

void WriteResponse(const std::filesystem::path& path, const Request& request, const std::vector<Result>& results)
{
    ValidateRequest(request);
    ValidateResults(request, results);
    Writer writer(path, MAX_RESPONSE_BYTES);
    writer.Header(RESPONSE_MAGIC);
    // Echo the complete public fixture request; a response cannot be reused for
    // a different seed, digest, context, operation, or ordered set of members.
    WriteRequestBody(writer, request);
    writer.U32(static_cast<std::uint32_t>(results.size()));
    for (const auto& result : results) {
        writer.U32(result.member);
        writer.Bytes(result.public_key);
        writer.Bytes(result.signature);
    }
    writer.Finish();
}

std::vector<Result> ReadResponse(const std::filesystem::path& path, const Request& expected_request)
{
    ValidateRequest(expected_request);
    Reader reader(path, MAX_RESPONSE_BYTES);
    reader.Header(RESPONSE_MAGIC);
    if (!SameRequest(ReadRequestBody(reader), expected_request)) Fail("crypto response request mismatch");
    const auto count = reader.U32();
    if (count != expected_request.jobs.size()) Fail("crypto result count mismatch");
    std::vector<Result> results(count);
    for (auto& result : results) {
        result.member = reader.U32();
        reader.Bytes(result.public_key);
        reader.Bytes(result.signature);
    }
    ValidateResults(expected_request, results);
    reader.Finish();
    return results;
}

std::optional<int> TryWorkerMain(int argc, char* argv[])
{
    if (argc < 2 || std::string_view{argv[1]} != WORKER_FLAG) return std::nullopt;
    try {
        if (argc != 4) Fail("usage: --pq-test-crypto-worker INPUT OUTPUT");
        const auto request = ReadRequest(std::filesystem::path{argv[2]});
        WriteResponse(std::filesystem::path{argv[3]}, request, Execute(request));
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "PQ test crypto worker: %s\n", e.what());
    } catch (...) {
        std::fprintf(stderr, "PQ test crypto worker: unknown failure\n");
    }
    return EXIT_FAILURE;
}

} // namespace pq_test_crypto
