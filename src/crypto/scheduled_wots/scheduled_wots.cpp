// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/scheduled_wots/scheduled_wots.h>

#include <crypto/slhdsa/secure.h>
#include <crypto/slhdsa/vendor/sha3_api.h>
#include <crypto/slhdsa/vendor/slh_wots_internal.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace scheduled_wots {
namespace {

using Node = std::array<std::uint8_t, N>;
using TreeNodes = std::array<Node, TREE_NODE_COUNT>;

constexpr std::size_t SK_SEED_OFFSET{0};
constexpr std::size_t SK_PRF_OFFSET{N};
constexpr std::size_t PK_SEED_OFFSET{2 * N};
constexpr std::size_t PK_ROOT_OFFSET{3 * N};
constexpr std::size_t RANDOMIZER_OFFSET{0};
constexpr std::size_t WOTS_OFFSET{N};
constexpr std::size_t AUTH_OFFSET{N + WOTS_SIGNATURE_SIZE};

constexpr std::string_view PURE_CONTEXT_DOMAIN{
    "SYS_PQ_SWOTS_SHAKE_N16_W16_H8_V1"};
constexpr std::size_t PURE_CONTEXT_SIZE{PURE_CONTEXT_DOMAIN.size() + 1};
constexpr std::array<std::uint8_t, 2> PURE_PREFIX{
    0, static_cast<std::uint8_t>(PURE_CONTEXT_SIZE)};

static_assert(PURE_CONTEXT_DOMAIN.size() == 32);
static_assert(PURE_CONTEXT_SIZE == 33);
static_assert(SYSCOIN_SLH_WOTS_N == N);
static_assert(SYSCOIN_SLH_WOTS_LEN == WOTS_LENGTH);
static_assert(SYSCOIN_SLH_WOTS_SIGNATURE_SIZE == WOTS_SIGNATURE_SIZE);
static_assert(SYSCOIN_SLH_WOTS_TREE_HEIGHT == TREE_HEIGHT);
static_assert(SYSCOIN_SLH_WOTS_TREE_LEAVES == TREE_LEAF_COUNT);
static_assert(AUTH_OFFSET + TREE_HEIGHT * N == SIGNATURE_SIZE);

class CleanseGuard final
{
public:
    CleanseGuard(void* data, std::size_t size) noexcept : m_data{data}, m_size{size} {}
    ~CleanseGuard() { syscoin_slhdsa_secure_zero(m_data, m_size); }

    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;

private:
    void* m_data;
    std::size_t m_size;
};

class Shake256State final
{
public:
    Shake256State() noexcept { shake256_init(&m_state); }
    ~Shake256State() { syscoin_slhdsa_secure_zero(&m_state, sizeof(m_state)); }

    Shake256State(const Shake256State&) = delete;
    Shake256State& operator=(const Shake256State&) = delete;

    void Update(const void* data, std::size_t size) noexcept
    {
        shake_update(&m_state, data, size);
    }

    void Final(std::span<std::uint8_t> output) noexcept
    {
        shake_out(&m_state, output.data(), output.size());
    }

private:
    sha3_var_t m_state{};
};

constexpr std::size_t TreeOffset(std::size_t height) noexcept
{
    return 2 * TREE_LEAF_COUNT -
           (std::size_t{1} << (TREE_HEIGHT + 1 - height));
}

bool ConstantTimeEqual(std::span<const std::uint8_t> lhs,
                       std::span<const std::uint8_t> rhs) noexcept
{
    if (lhs.size() != rhs.size()) return false;
    std::uint8_t difference{0};
    for (std::size_t i{0}; i < lhs.size(); ++i) {
        difference |= lhs[i] ^ rhs[i];
    }
    return difference == 0;
}

void Cleanse(std::span<std::uint8_t> bytes) noexcept
{
    syscoin_slhdsa_secure_zero(bytes.data(), bytes.size());
}

void UpdatePureTranscript(Shake256State& state, std::uint8_t leaf,
                          std::span<const std::uint8_t> message) noexcept
{
    state.Update(PURE_PREFIX.data(), PURE_PREFIX.size());
    state.Update(PURE_CONTEXT_DOMAIN.data(), PURE_CONTEXT_DOMAIN.size());
    state.Update(&leaf, sizeof(leaf));
    state.Update(message.data(), message.size());
}

void ComputeRandomizer(const std::uint8_t* sk_prf,
                       const std::uint8_t* pk_seed,
                       std::uint8_t leaf,
                       std::span<const std::uint8_t> message,
                       Node& randomizer) noexcept
{
    Shake256State state;
    state.Update(sk_prf, N);
    state.Update(pk_seed, N);
    UpdatePureTranscript(state, leaf, message);
    state.Final(randomizer);
}

void ComputeMessageDigest(const std::uint8_t* randomizer,
                          const std::uint8_t* pk_seed,
                          const std::uint8_t* pk_root,
                          std::uint8_t leaf,
                          std::span<const std::uint8_t> message,
                          Node& digest) noexcept
{
    Shake256State state;
    state.Update(randomizer, N);
    state.Update(pk_seed, N);
    state.Update(pk_root, N);
    UpdatePureTranscript(state, leaf, message);
    state.Final(digest);
}

} // namespace

class SecretKey::SigningCache final
{
public:
    [[nodiscard]] static std::unique_ptr<SigningCache> Build(
        const std::uint8_t* sk_seed,
        const std::uint8_t* pk_seed) noexcept
    {
        try {
            auto cache{std::make_unique<SigningCache>()};
            for (std::uint32_t leaf{0}; leaf < TREE_LEAF_COUNT; ++leaf) {
                Node& node{cache->m_nodes[TreeOffset(0) + leaf]};
                if (syscoin_slhdsa_vendor_wots_128s_pkgen(
                        node.data(), sk_seed, pk_seed, leaf) != 1) {
                    return nullptr;
                }
            }

            for (std::uint32_t height{1}; height <= TREE_HEIGHT; ++height) {
                const std::size_t node_count{TREE_LEAF_COUNT >> height};
                const std::size_t child_offset{TreeOffset(height - 1)};
                const std::size_t parent_offset{TreeOffset(height)};
                for (std::uint32_t index{0}; index < node_count; ++index) {
                    Node& parent{cache->m_nodes[parent_offset + index]};
                    const Node& left{cache->m_nodes[child_offset + 2 * index]};
                    const Node& right{cache->m_nodes[child_offset + 2 * index + 1]};
                    if (syscoin_slhdsa_vendor_wots_128s_tree_hash(
                            parent.data(), pk_seed, height, index,
                            left.data(), right.data()) != 1) {
                        return nullptr;
                    }
                }
            }

            std::copy_n(pk_seed, N, cache->m_public_key.begin());
            std::copy(cache->m_nodes[TreeOffset(TREE_HEIGHT)].begin(),
                      cache->m_nodes[TreeOffset(TREE_HEIGHT)].end(),
                      cache->m_public_key.begin() + N);
            return cache;
        } catch (...) {
            return nullptr;
        }
    }

    [[nodiscard]] const PublicKey& GetPublicKey() const noexcept
    {
        return m_public_key;
    }

    [[nodiscard]] const Node& AuthenticationNode(
        std::uint32_t leaf, std::size_t height) const noexcept
    {
        return m_nodes[TreeOffset(height) + ((leaf >> height) ^ 1U)];
    }

private:
    TreeNodes m_nodes{};
    PublicKey m_public_key{};
};

SecretKey::SecretKey(Encoding&& encoding,
                     std::unique_ptr<SigningCache>&& cache) noexcept :
    m_encoding{encoding},
    m_cache{std::move(cache)},
    m_valid{m_cache != nullptr}
{
    Cleanse(encoding);
}

SecretKey::SecretKey(SecretKey&& other) noexcept :
    m_encoding{other.m_encoding},
    m_cache{std::move(other.m_cache)},
    m_valid{other.m_valid && m_cache != nullptr}
{
    Cleanse(other.m_encoding);
    other.m_valid = false;
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept
{
    if (this == &other) return *this;

    Cleanse(m_encoding);
    m_cache.reset();
    m_encoding = other.m_encoding;
    m_cache = std::move(other.m_cache);
    m_valid = other.m_valid && m_cache != nullptr;
    Cleanse(other.m_encoding);
    other.m_valid = false;
    return *this;
}

SecretKey::~SecretKey() noexcept
{
    m_cache.reset();
    Cleanse(m_encoding);
    m_valid = false;
}

bool SecretKey::Export(std::span<std::uint8_t> out) const noexcept
{
    if (!m_valid || !m_cache || out.size() != SECRET_KEY_SIZE) return false;
    std::copy(m_encoding.begin(), m_encoding.end(), out.begin());
    return true;
}

bool SecretKey::GetPublicKey(std::span<std::uint8_t> out) const noexcept
{
    if (!m_valid || !m_cache || out.size() != PUBLIC_KEY_SIZE) return false;
    std::copy(m_cache->GetPublicKey().begin(), m_cache->GetPublicKey().end(),
              out.begin());
    return true;
}

std::size_t SecretKey::CacheBytes() const noexcept
{
    return m_valid && m_cache ? TREE_CACHE_BYTES : 0;
}

std::optional<SecretKey> GenerateSecretKey(
    std::span<const std::uint8_t> seed) noexcept
{
    if (seed.size() != KEY_GENERATION_SEED_SIZE) return std::nullopt;

    SecretKey::Encoding encoding{};
    CleanseGuard encoding_guard{encoding.data(), encoding.size()};
    std::copy(seed.begin(), seed.end(), encoding.begin());

    auto cache{SecretKey::SigningCache::Build(
        encoding.data() + SK_SEED_OFFSET,
        encoding.data() + PK_SEED_OFFSET)};
    if (!cache) return std::nullopt;
    std::copy(cache->GetPublicKey().begin(), cache->GetPublicKey().end(),
              encoding.begin() + PK_SEED_OFFSET);
    return SecretKey{std::move(encoding), std::move(cache)};
}

std::optional<SecretKey> ImportSecretKey(
    std::span<const std::uint8_t> encoded) noexcept
{
    if (encoded.size() != SECRET_KEY_SIZE) return std::nullopt;

    SecretKey::Encoding candidate{};
    CleanseGuard candidate_guard{candidate.data(), candidate.size()};
    std::copy(encoded.begin(), encoded.end(), candidate.begin());
    auto cache{SecretKey::SigningCache::Build(
        candidate.data() + SK_SEED_OFFSET,
        candidate.data() + PK_SEED_OFFSET)};
    if (!cache || !ConstantTimeEqual(
            cache->GetPublicKey(),
            std::span<const std::uint8_t>{candidate}.subspan(PK_SEED_OFFSET))) {
        return std::nullopt;
    }
    return SecretKey{std::move(candidate), std::move(cache)};
}

bool SignDeterministic(const SecretKey& secret_key,
                       std::uint32_t leaf,
                       std::span<const std::uint8_t> message,
                       std::span<std::uint8_t> signature_out) noexcept
{
    Message message_copy{};
    if (message.size() == MESSAGE_SIZE) {
        std::copy(message.begin(), message.end(), message_copy.begin());
    }
    if (signature_out.size() != SIGNATURE_SIZE) return false;
    Cleanse(signature_out);
    if (!secret_key.m_valid || !secret_key.m_cache ||
        leaf >= AUTHORIZED_LEAF_COUNT || message.size() != MESSAGE_SIZE ||
        !ConstantTimeEqual(
            secret_key.m_cache->GetPublicKey(),
            std::span<const std::uint8_t>{secret_key.m_encoding}.subspan(
                PK_SEED_OFFSET))) {
        return false;
    }

    Node randomizer{};
    Node digest{};
    CleanseGuard randomizer_guard{randomizer.data(), randomizer.size()};
    CleanseGuard digest_guard{digest.data(), digest.size()};
    const std::uint8_t leaf_byte{static_cast<std::uint8_t>(leaf)};
    ComputeRandomizer(secret_key.m_encoding.data() + SK_PRF_OFFSET,
                      secret_key.m_encoding.data() + PK_SEED_OFFSET,
                      leaf_byte, message_copy, randomizer);
    ComputeMessageDigest(randomizer.data(),
                         secret_key.m_encoding.data() + PK_SEED_OFFSET,
                         secret_key.m_encoding.data() + PK_ROOT_OFFSET,
                         leaf_byte, message_copy, digest);

    std::copy(randomizer.begin(), randomizer.end(),
              signature_out.begin() + RANDOMIZER_OFFSET);
    if (syscoin_slhdsa_vendor_wots_128s_sign(
            signature_out.data() + WOTS_OFFSET, digest.data(),
            secret_key.m_encoding.data() + SK_SEED_OFFSET,
            secret_key.m_encoding.data() + PK_SEED_OFFSET, leaf) != 1) {
        Cleanse(signature_out);
        return false;
    }
    for (std::size_t height{0}; height < TREE_HEIGHT; ++height) {
        const Node& sibling{
            secret_key.m_cache->AuthenticationNode(leaf, height)};
        std::copy(sibling.begin(), sibling.end(),
                  signature_out.begin() + AUTH_OFFSET + height * N);
    }
    return true;
}

bool Verify(std::span<const std::uint8_t> public_key,
            std::uint32_t leaf,
            std::span<const std::uint8_t> message,
            std::span<const std::uint8_t> signature) noexcept
{
    if (public_key.size() != PUBLIC_KEY_SIZE ||
        signature.size() != SIGNATURE_SIZE || message.size() != MESSAGE_SIZE ||
        leaf >= AUTHORIZED_LEAF_COUNT) {
        return false;
    }

    Node digest{};
    Node node{};
    Node parent{};
    CleanseGuard digest_guard{digest.data(), digest.size()};
    const std::uint8_t leaf_byte{static_cast<std::uint8_t>(leaf)};
    ComputeMessageDigest(signature.data() + RANDOMIZER_OFFSET,
                         public_key.data(), public_key.data() + N,
                         leaf_byte, message, digest);
    if (syscoin_slhdsa_vendor_wots_128s_pk_from_sig(
            node.data(), signature.data() + WOTS_OFFSET, digest.data(),
            public_key.data(), leaf) != 1) {
        return false;
    }

    for (std::uint32_t height{0}; height < TREE_HEIGHT; ++height) {
        const std::uint8_t* sibling{
            signature.data() + AUTH_OFFSET + height * N};
        const bool node_is_right{((leaf >> height) & 1U) != 0};
        const std::uint8_t* left{node_is_right ? sibling : node.data()};
        const std::uint8_t* right{node_is_right ? node.data() : sibling};
        if (syscoin_slhdsa_vendor_wots_128s_tree_hash(
                parent.data(), public_key.data(), height + 1,
                leaf >> (height + 1), left, right) != 1) {
            return false;
        }
        node = parent;
    }
    return ConstantTimeEqual(node,
                             public_key.subspan(N, N));
}

} // namespace scheduled_wots
