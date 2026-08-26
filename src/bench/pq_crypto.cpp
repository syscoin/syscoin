// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <checkqueue.h>
#include <common/system.h>
#include <crypto/slhdsa/slhdsa.h>
#include <crypto/sphincs_c11/sphincs_c11.h>
#include <llmq/pq_child_key_tree.h>
#include <masternode/pq_operatorkeys.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::size_t CHAINLOCK_SIGNATURES{
    llmq::pq::FINAL_SIGNATURE_COUNT};
constexpr std::size_t CHAINLOCK_SIGNING_JOBS{3};
constexpr std::size_t SIGNING_SCALE_JOBS{16};
constexpr std::size_t VERIFY_SAMPLE_COUNT{16};
constexpr unsigned int VERIFY_QUEUE_BATCH_SIZE{8};
constexpr std::size_t TREE_PARALLEL_THREADS{16};

void Require(bool condition, const char* operation)
{
    if (!condition) throw std::runtime_error{std::string{"PQ benchmark failed: "} + operation};
}

sphincs_c11::SecretSeed C11SecretSeed(std::size_t index)
{
    sphincs_c11::SecretSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>((17 * index + i) & 0xff);
    }
    return seed;
}

sphincs_c11::PublicSeed C11PublicSeed(std::size_t index)
{
    sphincs_c11::PublicSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>((0xa0 + 29 * index + i) & 0xff);
    }
    return seed;
}

sphincs_c11::Message C11Message(std::size_t index)
{
    sphincs_c11::Message message;
    for (std::size_t i{0}; i < message.size(); ++i) {
        message[i] = static_cast<unsigned char>((3 + 31 * index + 7 * i) & 0xff);
    }
    return message;
}

slhdsa::KeyGenerationSeed SLHKeySeed()
{
    slhdsa::KeyGenerationSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
    }
    return seed;
}

std::array<std::uint8_t, 32> SLHMessage()
{
    std::array<std::uint8_t, 32> message;
    for (std::size_t i{0}; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>(0x80 + i);
    }
    return message;
}

const std::array<std::uint8_t, 21> SLH_DOMAIN{
    'S', 'Y', 'S', 'C', 'O', 'I', 'N', '_', 'P', 'Q', '_', 'B', 'E', 'N', 'C', 'H', '_', 'V', '1', '_', '1'};

struct C11SigningFixture {
    std::vector<sphincs_c11::PublicKey> public_keys;
    std::vector<sphincs_c11::SecretKey> secret_keys;
    std::vector<sphincs_c11::Message> messages;
    std::vector<sphincs_c11::Signature> signatures;

    explicit C11SigningFixture(std::size_t count)
        : public_keys(count), secret_keys(count), messages(count), signatures(count)
    {
        for (std::size_t i{0}; i < count; ++i) {
            messages[i] = C11Message(i);
            Require(sphincs_c11::GenerateKeyPair(C11SecretSeed(i), C11PublicSeed(i),
                                                 public_keys[i], secret_keys[i]),
                    "C11 key generation");
            Require(sphincs_c11::Sign(secret_keys[i], messages[i], signatures[i]),
                    "C11 signing setup");
        }
    }
};

struct C11SigningJob {
    const sphincs_c11::SecretKey* secret_key;
    const sphincs_c11::Message* message;
    sphincs_c11::Signature* signature;

    bool operator()() const
    {
        return sphincs_c11::Sign(*secret_key, *message, *signature);
    }
};

std::vector<C11SigningJob> MakeSigningJobs(C11SigningFixture& fixture)
{
    std::vector<C11SigningJob> jobs;
    jobs.reserve(fixture.secret_keys.size());
    for (std::size_t i{0}; i < fixture.secret_keys.size(); ++i) {
        jobs.push_back(C11SigningJob{
            &fixture.secret_keys[i], &fixture.messages[i], &fixture.signatures[i]});
    }
    return jobs;
}

C11SigningFixture& GetC11SigningScaleFixture()
{
    static C11SigningFixture fixture{SIGNING_SCALE_JOBS};
    return fixture;
}

bool HasCores(std::size_t count)
{
    const int cores{GetNumCores()};
    return cores > 0 && static_cast<std::size_t>(cores) >= count;
}

llmq::pq::ChildKeyTreeConfig ChildTreeConfig(uint16_t depth)
{
    llmq::pq::ChildKeyTreeConfig config;
    config.genesis_hash = uint256::ONEV;
    config.tree_id = uint256::ONEV;
    config.tree_id.begin()[0] = 0x42;
    config.generation = 1;
    config.first_epoch = 1024;
    config.depth = depth;
    Require(config.IsValid(), "child tree configuration");
    return config;
}

llmq::pq::ChainLockMasterSeed ChildTreeSeed()
{
    llmq::pq::ChainLockMasterSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>(0x51 + i);
    }
    return seed;
}

void C11ChildTreeBuild(benchmark::Bench& bench, uint16_t depth,
                       std::size_t workers)
{
    if (workers > 1 && !HasCores(workers)) return;
    const auto seed{ChildTreeSeed()};
    const auto config{ChildTreeConfig(depth)};
    bench.epochs(1).epochIterations(1).batch(1).unit("tree").run([&] {
        auto tree{llmq::pq::ChildKeyTree::Build(seed, config, workers)};
        Require(tree.has_value(), "child tree build");
        ankerl::nanobench::doNotOptimizeAway(tree->GetRoot());
        ankerl::nanobench::doNotOptimizeAway(tree->CacheBytes());
    });
}

void C11ChildTreeBuildDepth14Serial(benchmark::Bench& bench)
{
    C11ChildTreeBuild(bench, 14, 1);
}

void C11ChildTreeBuildDepth14Parallel16(benchmark::Bench& bench)
{
    C11ChildTreeBuild(bench, 14, TREE_PARALLEL_THREADS);
}

void C11ChildTreeBuildDepth16Serial(benchmark::Bench& bench)
{
    C11ChildTreeBuild(bench, 16, 1);
}

void C11ChildTreeBuildDepth16Parallel16(benchmark::Bench& bench)
{
    C11ChildTreeBuild(bench, 16, TREE_PARALLEL_THREADS);
}

llmq::pq::ChildKeyTree BuildChildTree(
    const llmq::pq::ChainLockMasterSeed& seed,
    const llmq::pq::ChildKeyTreeConfig& config)
{
    auto tree{llmq::pq::ChildKeyTree::Build(
        seed, config,
        HasCores(TREE_PARALLEL_THREADS) ? TREE_PARALLEL_THREADS : 1)};
    Require(tree.has_value(), "child tree fixture build");
    return std::move(*tree);
}

struct ChildTreeFixture {
    llmq::pq::ChainLockMasterSeed seed{ChildTreeSeed()};
    llmq::pq::ChildKeyTreeConfig config;
    llmq::pq::ChildKeyTree tree;
    uint32_t epoch{0};
    llmq::pq::ChildPublicKey public_key{};
    llmq::pq::ChildKeyTreeProof proof;

    explicit ChildTreeFixture(uint16_t depth)
        : config{ChildTreeConfig(depth)},
          tree{BuildChildTree(seed, config)},
          epoch{static_cast<uint32_t>(config.first_epoch +
                                      config.LeafCount() / 2)}
    {
        const auto generated_public_key{
            llmq::pq::DeriveCommittedChildPublicKey(
                seed, config.genesis_hash, config.tree_id,
                config.generation, epoch)};
        Require(generated_public_key.has_value(), "child public key derivation");
        public_key = *generated_public_key;
        auto generated{tree.GetProof(public_key, epoch)};
        Require(generated.has_value(), "child tree proof generation");
        proof = std::move(*generated);
        Require(llmq::pq::VerifyChildKeyTreeProof(
                    config, tree.GetRoot(), epoch, proof),
                "child tree proof verification");
    }
};

ChildTreeFixture& GetChildTreeFixture14()
{
    static ChildTreeFixture fixture{14};
    return fixture;
}

ChildTreeFixture& GetChildTreeFixture16()
{
    static ChildTreeFixture fixture{16};
    return fixture;
}

void C11ChildTreeProofGeneration(benchmark::Bench& bench,
                                 ChildTreeFixture& fixture)
{
    bench.batch(1).unit("proof").run([&] {
        auto proof{fixture.tree.GetProof(fixture.public_key, fixture.epoch)};
        Require(proof.has_value(), "child tree proof generation");
        ankerl::nanobench::doNotOptimizeAway(proof->public_key);
        ankerl::nanobench::doNotOptimizeAway(proof->siblings);
    });
}

void C11ChildTreeProofGenerationDepth14(benchmark::Bench& bench)
{
    C11ChildTreeProofGeneration(bench, GetChildTreeFixture14());
}

void C11ChildTreeProofGenerationDepth16(benchmark::Bench& bench)
{
    C11ChildTreeProofGeneration(bench, GetChildTreeFixture16());
}

struct ChildTreeVerificationJob {
    const ChildTreeFixture* fixture{nullptr};

    bool operator()() const
    {
        return llmq::pq::VerifyChildKeyTreeProof(
            fixture->config, fixture->tree.GetRoot(), fixture->epoch,
            fixture->proof);
    }
};

void C11ChildTreeVerify801(benchmark::Bench& bench,
                           ChildTreeFixture& fixture,
                           std::size_t total_threads)
{
    if (total_threads > 1 && !HasCores(total_threads)) return;
    const std::vector<ChildTreeVerificationJob> job_template(
        CHAINLOCK_SIGNATURES, ChildTreeVerificationJob{&fixture});
    if (total_threads == 1) {
        bench.batch(job_template.size()).unit("proof").run([&] {
            bool success{true};
            for (const auto& job : job_template) success &= job();
            ankerl::nanobench::doNotOptimizeAway(success);
        });
        return;
    }

    std::vector<ChildTreeVerificationJob> jobs;
    jobs.reserve(job_template.size());
    CCheckQueue<ChildTreeVerificationJob> queue{VERIFY_QUEUE_BATCH_SIZE};
    queue.StartWorkerThreads(static_cast<int>(total_threads - 1));
    bench.batch(job_template.size()).unit("proof").run([&] {
        jobs.assign(job_template.begin(), job_template.end());
        CCheckQueueControl<ChildTreeVerificationJob> control{&queue};
        control.Add(std::move(jobs));
        const bool success{control.Wait()};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    queue.StopWorkerThreads();
}

void C11ChildTreeVerify801Depth14Serial(benchmark::Bench& bench)
{
    C11ChildTreeVerify801(bench, GetChildTreeFixture14(), 1);
}

void C11ChildTreeVerify801Depth14Parallel16(benchmark::Bench& bench)
{
    C11ChildTreeVerify801(bench, GetChildTreeFixture14(),
                          TREE_PARALLEL_THREADS);
}

void C11ChildTreeVerify801Depth16Serial(benchmark::Bench& bench)
{
    C11ChildTreeVerify801(bench, GetChildTreeFixture16(), 1);
}

void C11ChildTreeVerify801Depth16Parallel16(benchmark::Bench& bench)
{
    C11ChildTreeVerify801(bench, GetChildTreeFixture16(),
                          TREE_PARALLEL_THREADS);
}

struct C11VerificationJob {
    const sphincs_c11::PublicKey* public_key;
    const sphincs_c11::Message* message;
    const sphincs_c11::Signature* signature;

    bool operator()() const
    {
        return sphincs_c11::Verify(*public_key, *message, *signature);
    }
};

struct C11VerificationFixture {
    std::vector<sphincs_c11::PublicKey> public_keys;
    std::vector<sphincs_c11::Message> messages;
    std::vector<sphincs_c11::Signature> signatures;
    std::vector<C11VerificationJob> jobs;

    C11VerificationFixture()
        : public_keys(CHAINLOCK_SIGNATURES),
          messages(CHAINLOCK_SIGNATURES),
          signatures(CHAINLOCK_SIGNATURES)
    {
        sphincs_c11::PublicKey sample_public_key;
        sphincs_c11::SecretKey sample_secret_key;
        Require(sphincs_c11::GenerateKeyPair(C11SecretSeed(100), C11PublicSeed(100),
                                             sample_public_key, sample_secret_key),
                "C11 verification key generation");

        std::array<sphincs_c11::Message, VERIFY_SAMPLE_COUNT> sample_messages;
        std::array<sphincs_c11::Signature, VERIFY_SAMPLE_COUNT> sample_signatures;
        for (std::size_t i{0}; i < VERIFY_SAMPLE_COUNT; ++i) {
            sample_messages[i] = C11Message(100 + i);
            Require(sphincs_c11::Sign(sample_secret_key, sample_messages[i],
                                      sample_signatures[i]),
                    "C11 verification signing setup");
        }

        jobs.reserve(CHAINLOCK_SIGNATURES);
        for (std::size_t i{0}; i < CHAINLOCK_SIGNATURES; ++i) {
            const std::size_t sample{i % VERIFY_SAMPLE_COUNT};
            public_keys[i] = sample_public_key;
            messages[i] = sample_messages[sample];
            signatures[i] = sample_signatures[sample];
            jobs.push_back(C11VerificationJob{
                &public_keys[i], &messages[i], &signatures[i]});
        }
    }
};

const C11VerificationFixture& GetC11VerificationFixture()
{
    static const C11VerificationFixture fixture;
    return fixture;
}

struct SLHFixture {
    slhdsa::KeyGenerationSeed seed{SLHKeySeed()};
    std::array<std::uint8_t, 32> message{SLHMessage()};
    std::optional<slhdsa::SecretKey> secret_key{slhdsa::GenerateSecretKey(seed)};
    slhdsa::PublicKey public_key{};
    slhdsa::Signature signature{};

    SLHFixture()
    {
        Require(secret_key.has_value(), "SLH-DSA key generation");
        Require(secret_key->GetPublicKey(public_key), "SLH-DSA public key export");
        Require(slhdsa::SignDeterministic(*secret_key, message, SLH_DOMAIN, signature),
                "SLH-DSA signing setup");
        Require(slhdsa::Verify(public_key, message, SLH_DOMAIN, signature),
                "SLH-DSA verification setup");
    }
};

void C11KeyGeneration(benchmark::Bench& bench)
{
    const auto secret_seed{C11SecretSeed(0)};
    const auto public_seed{C11PublicSeed(0)};
    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    Require(sphincs_c11::GenerateKeyPair(secret_seed, public_seed, public_key, secret_key),
            "C11 key generation setup");

    bench.batch(1).unit("keypair").run([&] {
        const bool success{sphincs_c11::GenerateKeyPair(
            secret_seed, public_seed, public_key, secret_key)};
        ankerl::nanobench::doNotOptimizeAway(success);
        ankerl::nanobench::doNotOptimizeAway(public_key.GetBytes());
    });
}

void C11Sign(benchmark::Bench& bench)
{
    C11SigningFixture fixture{1};
    bench.batch(1).unit("signature").run([&] {
        const bool success{sphincs_c11::Sign(
            fixture.secret_keys[0], fixture.messages[0], fixture.signatures[0])};
        ankerl::nanobench::doNotOptimizeAway(success);
        ankerl::nanobench::doNotOptimizeAway(fixture.signatures[0]);
    });
}

void C11Verify(benchmark::Bench& bench)
{
    const auto& fixture{GetC11VerificationFixture()};
    bench.batch(1).unit("signature").run([&] {
        const bool success{fixture.jobs[0]()};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

void C11SignThreeSerial(benchmark::Bench& bench)
{
    C11SigningFixture fixture{CHAINLOCK_SIGNING_JOBS};
    const auto jobs{MakeSigningJobs(fixture)};
    bench.batch(jobs.size()).unit("signature").run([&] {
        bool success{true};
        for (const auto& job : jobs) success &= job();
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

void C11SignThreeParallel(benchmark::Bench& bench)
{
    if (!HasCores(CHAINLOCK_SIGNING_JOBS)) return;

    C11SigningFixture fixture{CHAINLOCK_SIGNING_JOBS};
    const auto job_template{MakeSigningJobs(fixture)};
    std::vector<C11SigningJob> jobs;
    jobs.reserve(job_template.size());
    CCheckQueue<C11SigningJob> queue{/*batch_size=*/1};
    queue.StartWorkerThreads(static_cast<int>(CHAINLOCK_SIGNING_JOBS - 1));

    bench.batch(job_template.size()).unit("signature").run([&] {
        jobs.assign(job_template.begin(), job_template.end());
        CCheckQueueControl<C11SigningJob> control{&queue};
        control.Add(std::move(jobs));
        const bool success{control.Wait()};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    queue.StopWorkerThreads();
}

void C11Sign16Serial(benchmark::Bench& bench)
{
    auto& fixture{GetC11SigningScaleFixture()};
    const auto jobs{MakeSigningJobs(fixture)};
    bench.epochs(5).batch(jobs.size()).unit("signature").run([&] {
        bool success{true};
        for (const auto& job : jobs) success &= job();
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

void C11Sign16Parallel(benchmark::Bench& bench, std::size_t total_threads)
{
    if (!HasCores(total_threads)) return;

    auto& fixture{GetC11SigningScaleFixture()};
    const auto job_template{MakeSigningJobs(fixture)};
    std::vector<C11SigningJob> jobs;
    jobs.reserve(job_template.size());
    CCheckQueue<C11SigningJob> queue{/*batch_size=*/1};
    queue.StartWorkerThreads(static_cast<int>(total_threads - 1));

    bench.epochs(5).batch(job_template.size()).unit("signature").run([&] {
        jobs.assign(job_template.begin(), job_template.end());
        CCheckQueueControl<C11SigningJob> control{&queue};
        control.Add(std::move(jobs));
        const bool success{control.Wait()};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    queue.StopWorkerThreads();
}

void C11Sign16Parallel2(benchmark::Bench& bench)
{
    C11Sign16Parallel(bench, 2);
}

void C11Sign16Parallel4(benchmark::Bench& bench)
{
    C11Sign16Parallel(bench, 4);
}

void C11Sign16Parallel8(benchmark::Bench& bench)
{
    C11Sign16Parallel(bench, 8);
}

void C11Sign16Parallel16(benchmark::Bench& bench)
{
    C11Sign16Parallel(bench, 16);
}

void C11Verify801Serial(benchmark::Bench& bench)
{
    const auto& fixture{GetC11VerificationFixture()};
    bench.batch(fixture.jobs.size()).unit("signature").run([&] {
        bool success{true};
        for (const auto& job : fixture.jobs) success &= job();
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

void C11Verify801Parallel(benchmark::Bench& bench, std::size_t total_threads)
{
    if (!HasCores(total_threads)) return;

    const auto& fixture{GetC11VerificationFixture()};
    std::vector<C11VerificationJob> jobs;
    jobs.reserve(fixture.jobs.size());
    CCheckQueue<C11VerificationJob> queue{VERIFY_QUEUE_BATCH_SIZE};
    queue.StartWorkerThreads(static_cast<int>(total_threads - 1));

    bench.batch(fixture.jobs.size()).unit("signature").run([&] {
        jobs.assign(fixture.jobs.begin(), fixture.jobs.end());
        CCheckQueueControl<C11VerificationJob> control{&queue};
        control.Add(std::move(jobs));
        const bool success{control.Wait()};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    queue.StopWorkerThreads();
}

void C11Verify801Parallel2(benchmark::Bench& bench)
{
    C11Verify801Parallel(bench, 2);
}

void C11Verify801Parallel4(benchmark::Bench& bench)
{
    C11Verify801Parallel(bench, 4);
}

void C11Verify801Parallel8(benchmark::Bench& bench)
{
    C11Verify801Parallel(bench, 8);
}

void C11Verify801Parallel16(benchmark::Bench& bench)
{
    C11Verify801Parallel(bench, 16);
}

void SLHKeyGeneration(benchmark::Bench& bench)
{
    const auto seed{SLHKeySeed()};
    auto secret_key{slhdsa::GenerateSecretKey(seed)};
    Require(secret_key.has_value(), "SLH-DSA key generation setup");

    bench.batch(1).unit("keypair").run([&] {
        secret_key = slhdsa::GenerateSecretKey(seed);
        ankerl::nanobench::doNotOptimizeAway(secret_key.has_value());
    });
}

void SLHSign(benchmark::Bench& bench)
{
    SLHFixture fixture;
    bench.batch(1).unit("signature").run([&] {
        const bool success{slhdsa::SignDeterministic(
            *fixture.secret_key, fixture.message, SLH_DOMAIN, fixture.signature)};
        ankerl::nanobench::doNotOptimizeAway(success);
        ankerl::nanobench::doNotOptimizeAway(fixture.signature);
    });
}

void SLHVerify(benchmark::Bench& bench)
{
    SLHFixture fixture;
    bench.batch(1).unit("signature").run([&] {
        const bool success{slhdsa::Verify(
            fixture.public_key, fixture.message, SLH_DOMAIN, fixture.signature)};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

} // namespace

BENCHMARK(C11KeyGeneration, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign, benchmark::PriorityLevel::LOW);
BENCHMARK(C11SignThreeSerial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11SignThreeParallel, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign16Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign16Parallel2, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign16Parallel4, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign16Parallel8, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Sign16Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(C11Verify801Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Verify801Parallel2, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Verify801Parallel4, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Verify801Parallel8, benchmark::PriorityLevel::LOW);
BENCHMARK(C11Verify801Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeBuildDepth14Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeBuildDepth14Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeBuildDepth16Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeBuildDepth16Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeProofGenerationDepth14, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeProofGenerationDepth16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeVerify801Depth14Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeVerify801Depth14Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeVerify801Depth16Serial, benchmark::PriorityLevel::LOW);
BENCHMARK(C11ChildTreeVerify801Depth16Parallel16, benchmark::PriorityLevel::LOW);
BENCHMARK(SLHKeyGeneration, benchmark::PriorityLevel::LOW);
BENCHMARK(SLHSign, benchmark::PriorityLevel::LOW);
BENCHMARK(SLHVerify, benchmark::PriorityLevel::LOW);
