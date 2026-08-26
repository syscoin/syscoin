// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/pq_operatorkeys.h>

#include <crypto/hmac_sha256.h>
#include <hash.h>
#include <llmq/pq_global_auth.h>
#include <span.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

constexpr std::string_view COMMITTED_CHILD_ID_DOMAIN{
    "SYS_PQ_SWOTS_CHILD_ID_V1"};
constexpr std::string_view COMMITTED_CHILD_KDF_DOMAIN{
    "SYS_PQ_SWOTS_CHILD_KDF_V1"};
constexpr uint8_t SECRET_SEED_LABEL{0};
constexpr uint8_t SECRET_PRF_LABEL{1};
constexpr uint8_t PUBLIC_SEED_LABEL{2};

class CleanseGuard final {
public:
    CleanseGuard(void* data, std::size_t size) noexcept : m_data{data}, m_size{size} {}
    ~CleanseGuard() { memory_cleanse(m_data, m_size); }

    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;

private:
    void* m_data;
    std::size_t m_size;
};

uint256 GetCommittedChildKDFIdentity(const uint256& genesis_hash,
                                     const uint256& tree_id,
                                     uint32_t generation,
                                     uint32_t epoch)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{COMMITTED_CHILD_ID_DOMAIN.data(),
                              COMMITTED_CHILD_ID_DOMAIN.size()}));
    writer << genesis_hash << tree_id << generation << epoch
           << CHILD_SCHEDULED_WOTS_SHAKE_128_V1;
    return writer.GetHash();
}

std::array<uint8_t, CHMAC_SHA256::OUTPUT_SIZE> DeriveSeed(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& identity,
    std::string_view domain,
    uint8_t label) noexcept
{
    std::array<uint8_t, CHMAC_SHA256::OUTPUT_SIZE> output{};
    CHMAC_SHA256 hmac{chainlock_master_seed.data(),
                      chainlock_master_seed.size()};
    CleanseGuard hmac_guard{&hmac, sizeof(hmac)};
    hmac.Write(reinterpret_cast<const uint8_t*>(domain.data()),
               domain.size());
    hmac.Write(identity.begin(), identity.size());
    hmac.Write(&label, sizeof(label));
    hmac.Finalize(output.data());
    return output;
}

std::optional<scheduled_wots::SecretKey> DeriveChildSecretKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& identity,
    std::string_view domain) noexcept
{
    if (chainlock_master_seed.size() != CHAINLOCK_MASTER_SEED_SIZE ||
        std::all_of(chainlock_master_seed.begin(),
                    chainlock_master_seed.end(),
                    [](uint8_t byte) { return byte == 0; }) ||
        identity.IsNull()) {
        return std::nullopt;
    }
    auto secret_material{DeriveSeed(chainlock_master_seed, identity, domain,
                                    SECRET_SEED_LABEL)};
    CleanseGuard secret_material_guard{secret_material.data(),
                                       secret_material.size()};
    auto prf_material{DeriveSeed(chainlock_master_seed, identity, domain,
                                 SECRET_PRF_LABEL)};
    CleanseGuard prf_material_guard{prf_material.data(),
                                    prf_material.size()};
    auto public_material{DeriveSeed(chainlock_master_seed, identity, domain,
                                    PUBLIC_SEED_LABEL)};
    CleanseGuard public_material_guard{public_material.data(),
                                       public_material.size()};

    scheduled_wots::KeyGenerationSeed seed{};
    CleanseGuard seed_guard{seed.data(), seed.size()};
    std::copy_n(secret_material.begin(), scheduled_wots::N, seed.begin());
    std::copy_n(prf_material.begin(), scheduled_wots::N,
                seed.begin() + scheduled_wots::N);
    std::copy_n(public_material.begin(), scheduled_wots::N,
                seed.begin() + 2 * scheduled_wots::N);
    return scheduled_wots::GenerateSecretKey(seed);
}

std::optional<scheduled_wots::SecretKey> DeriveCommittedChildSecretKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& genesis_hash,
    const uint256& tree_id,
    uint32_t generation,
    uint32_t epoch) noexcept
{
    if (genesis_hash.IsNull() || tree_id.IsNull() ||
        !IsValidChildKeyTreeGeneration(generation)) {
        return std::nullopt;
    }
    return DeriveChildSecretKey(
        chainlock_master_seed,
        GetCommittedChildKDFIdentity(genesis_hash, tree_id, generation,
                                     epoch),
        COMMITTED_CHILD_KDF_DOMAIN);
}

} // namespace

bool ImportChainLockMasterSeed(std::span<const uint8_t> encoded,
                               ChainLockMasterSeed& output) noexcept
{
    output.fill(0);
    if (encoded.size() != CHAINLOCK_MASTER_SEED_SIZE ||
        std::all_of(encoded.begin(), encoded.end(),
                    [](uint8_t byte) { return byte == 0; })) {
        return false;
    }
    std::copy(encoded.begin(), encoded.end(), output.begin());
    return true;
}

std::optional<ChildPublicKey> DeriveCommittedChildPublicKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& genesis_hash,
    const uint256& tree_id,
    uint32_t generation,
    uint32_t epoch) noexcept
{
    auto secret_key{DeriveCommittedChildSecretKey(
        chainlock_master_seed, genesis_hash, tree_id, generation, epoch)};
    if (!secret_key) return std::nullopt;
    ChildPublicKey public_key{};
    if (!secret_key->GetPublicKey(public_key)) return std::nullopt;
    return public_key;
}

LocalOperatorKeyManager::LocalOperatorKeyManager(
    slhdsa::SecretKey&& global_secret_key,
    ChainLockMasterSeed&& chainlock_master_seed)
    : m_global_secret_key{std::move(global_secret_key)},
      m_chainlock_master_seed{chainlock_master_seed}
{
    memory_cleanse(chainlock_master_seed.data(), chainlock_master_seed.size());
    if (!m_global_secret_key.GetPublicKey(m_global_public_key)) {
        m_global_public_key.fill(0);
    }
}

LocalOperatorKeyManager::~LocalOperatorKeyManager()
{
    memory_cleanse(m_chainlock_master_seed.data(),
                   m_chainlock_master_seed.size());
}

LocalOperatorKeyManager::LocalOperatorKeyManager(
    LocalOperatorKeyManager&& other) noexcept
    : m_global_secret_key{std::move(other.m_global_secret_key)},
      m_global_public_key{other.m_global_public_key},
      m_chainlock_master_seed{other.m_chainlock_master_seed}
{
    other.m_global_public_key.fill(0);
    memory_cleanse(other.m_chainlock_master_seed.data(),
                   other.m_chainlock_master_seed.size());
}

LocalOperatorKeyManager& LocalOperatorKeyManager::operator=(
    LocalOperatorKeyManager&& other) noexcept
{
    if (this == &other) return *this;
    memory_cleanse(m_chainlock_master_seed.data(),
                   m_chainlock_master_seed.size());
    m_global_secret_key = std::move(other.m_global_secret_key);
    m_global_public_key = other.m_global_public_key;
    m_chainlock_master_seed = other.m_chainlock_master_seed;
    other.m_global_public_key.fill(0);
    memory_cleanse(other.m_chainlock_master_seed.data(),
                   other.m_chainlock_master_seed.size());
    return *this;
}

bool LocalOperatorKeyManager::IsValid() const noexcept
{
    return m_global_secret_key.IsValid() &&
           std::any_of(m_global_public_key.begin(), m_global_public_key.end(),
                       [](uint8_t byte) { return byte != 0; }) &&
           std::any_of(m_chainlock_master_seed.begin(),
                       m_chainlock_master_seed.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool LocalOperatorKeyManager::Matches(const GlobalKeyRecord& record) const noexcept
{
    return IsStoredGlobalKeyRecordStructurallyValid(record) &&
           record.public_key == m_global_public_key;
}

bool LocalOperatorKeyManager::SignMNAUTH(
    const uint256& authorization_hash,
    GlobalSignature& signature) const noexcept
{
    if (!IsValid() || authorization_hash.IsNull()) {
        signature.fill(0);
        return false;
    }
    return slhdsa::SignDeterministic(
        m_global_secret_key,
        std::span<const uint8_t>{authorization_hash.begin(),
                                 authorization_hash.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::MNAUTH), signature);
}

bool LocalOperatorKeyManager::SignGovernanceTrigger(
    const uint256& authorization_hash,
    GlobalSignature& signature) const noexcept
{
    if (!IsValid() || authorization_hash.IsNull()) {
        signature.fill(0);
        return false;
    }
    return slhdsa::SignDeterministic(
        m_global_secret_key,
        std::span<const uint8_t>{authorization_hash.begin(),
                                 authorization_hash.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_TRIGGER),
        signature);
}

bool LocalOperatorKeyManager::SignGovernanceVote(
    const uint256& authorization_hash,
    GlobalSignature& signature) const noexcept
{
    if (!IsValid() || authorization_hash.IsNull()) {
        signature.fill(0);
        return false;
    }
    return slhdsa::SignDeterministic(
        m_global_secret_key,
        std::span<const uint8_t>{authorization_hash.begin(),
                                 authorization_hash.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_VOTE), signature);
}

bool LocalOperatorKeyManager::SignGovernanceProposalVote(
    const uint256& authorization_hash,
    GlobalSignature& signature) const noexcept
{
    if (!IsValid() || authorization_hash.IsNull()) {
        signature.fill(0);
        return false;
    }
    return slhdsa::SignDeterministic(
        m_global_secret_key,
        std::span<const uint8_t>{authorization_hash.begin(),
                                 authorization_hash.size()},
        GetGlobalAuthContext(
            GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE),
        signature);
}

std::optional<scheduled_wots::SecretKey>
LocalOperatorKeyManager::DeriveCommittedChildKey(
    const uint256& genesis_hash,
    const uint256& tree_id,
    uint32_t generation,
    uint32_t epoch) const noexcept
{
    if (!IsValid()) return std::nullopt;
    return DeriveCommittedChildSecretKey(
        m_chainlock_master_seed, genesis_hash, tree_id, generation, epoch);
}

std::optional<ChildKeyTree>
LocalOperatorKeyManager::BuildCommittedChildKeyTree(
    const ChildKeyTreeConfig& config,
    std::size_t worker_count) const
{
    if (!IsValid()) return std::nullopt;
    return ChildKeyTree::Build(m_chainlock_master_seed, config, worker_count);
}

} // namespace llmq::pq
