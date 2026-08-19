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

constexpr std::string_view COMMITTED_CHILD_KDF_DOMAIN{
    "SYS_PQ_CHAINLOCK_CHILD_KDF_V1"};
constexpr uint8_t SECRET_SEED_LABEL{0};
constexpr uint8_t PUBLIC_SEED_LABEL{1};

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
    writer.write(AsBytes(Span{COMMITTED_CHILD_KDF_DOMAIN.data(),
                              COMMITTED_CHILD_KDF_DOMAIN.size()}));
    writer << genesis_hash << tree_id << generation << epoch
           << CHILD_C11_SHA_V1;
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

std::optional<sphincs_c11::SecretKey> DeriveChildSecretKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& identity,
    std::string_view domain) noexcept
{
    if (chainlock_master_seed.size() != sphincs_c11::SECRET_SEED_SIZE ||
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
    auto public_material{DeriveSeed(chainlock_master_seed, identity, domain,
                                    PUBLIC_SEED_LABEL)};
    CleanseGuard public_material_guard{public_material.data(),
                                       public_material.size()};

    sphincs_c11::SecretSeed secret_seed{};
    CleanseGuard secret_seed_guard{secret_seed.data(), secret_seed.size()};
    std::copy(secret_material.begin(), secret_material.end(),
              secret_seed.begin());
    sphincs_c11::PublicSeed public_seed{};
    std::copy_n(public_material.begin(), public_seed.size(),
                public_seed.begin());
    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    if (!sphincs_c11::GenerateKeyPair(secret_seed, public_seed, public_key,
                                      secret_key)) {
        return std::nullopt;
    }
    return secret_key;
}

std::optional<sphincs_c11::SecretKey> DeriveCommittedChildSecretKey(
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
    if (encoded.size() != sphincs_c11::SECRET_SEED_SIZE ||
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
    return sphincs_c11::SerializePublicKey(secret_key->GetPublicKey());
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

std::optional<sphincs_c11::SecretKey>
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

std::optional<ChildKeyProof>
LocalOperatorKeyManager::GetCommittedChildKeyProof(
    const ChildKeyTree& tree,
    uint32_t epoch) const
{
    if (!IsValid()) return std::nullopt;
    return tree.GetConsensusProof(m_chainlock_master_seed, epoch);
}

} // namespace llmq::pq
