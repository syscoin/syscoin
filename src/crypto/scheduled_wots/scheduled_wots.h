// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CRYPTO_SCHEDULED_WOTS_SCHEDULED_WOTS_H
#define SYSCOIN_CRYPTO_SCHEDULED_WOTS_SCHEDULED_WOTS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace scheduled_wots {

inline constexpr char ALGORITHM[]{"SYS-SCHEDULED-WOTS+-SHAKE-N16-W16-H8-V1"};
inline constexpr std::size_t N{16};
inline constexpr std::size_t MESSAGE_SIZE{32};
inline constexpr std::size_t KEY_GENERATION_SEED_SIZE{48};
inline constexpr std::size_t SECRET_KEY_SIZE{64};
inline constexpr std::size_t PUBLIC_KEY_SIZE{32};
inline constexpr std::size_t WOTS_LENGTH{35};
inline constexpr std::size_t WOTS_SIGNATURE_SIZE{WOTS_LENGTH * N};
inline constexpr std::size_t TREE_HEIGHT{8};
inline constexpr std::size_t TREE_LEAF_COUNT{std::size_t{1} << TREE_HEIGHT};
inline constexpr std::size_t TREE_NODE_COUNT{2 * TREE_LEAF_COUNT - 1};
inline constexpr std::size_t TREE_CACHE_BYTES{TREE_NODE_COUNT * N};
inline constexpr std::uint32_t AUTHORIZED_LEAF_COUNT{235};
inline constexpr std::size_t SIGNATURE_SIZE{
    N + WOTS_SIGNATURE_SIZE + TREE_HEIGHT * N};

static_assert(SIGNATURE_SIZE == 704);
static_assert(TREE_CACHE_BYTES == 8176);
static_assert(AUTHORIZED_LEAF_COUNT <= TREE_LEAF_COUNT);

using KeyGenerationSeed =
    std::array<std::uint8_t, KEY_GENERATION_SEED_SIZE>;
using PublicKey = std::array<std::uint8_t, PUBLIC_KEY_SIZE>;
using Message = std::array<std::uint8_t, MESSAGE_SIZE>;
/** Wire layout: R[16] || WOTS[35][16] || authentication_path[8][16]. */
using Signature = std::array<std::uint8_t, SIGNATURE_SIZE>;

/**
 * Move-only owner of one scheduled WOTS+ key and its immutable public tree.
 *
 * The encoded secret-key layout is
 * SK.seed[16] || SK.prf[16] || PK.seed[16] || PK.root[16]. The cached tree is
 * public data, is never serialized by this API, and is rebuilt on import.
 */
class SecretKey final
{
public:
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;
    ~SecretKey() noexcept;

    [[nodiscard]] bool IsValid() const noexcept { return m_valid; }
    [[nodiscard]] bool Export(std::span<std::uint8_t> out) const noexcept;
    [[nodiscard]] bool GetPublicKey(std::span<std::uint8_t> out) const noexcept;
    [[nodiscard]] std::size_t CacheBytes() const noexcept;

private:
    using Encoding = std::array<std::uint8_t, SECRET_KEY_SIZE>;
    class SigningCache;

    SecretKey(Encoding&& encoding,
              std::unique_ptr<SigningCache>&& cache) noexcept;

    Encoding m_encoding{};
    std::unique_ptr<const SigningCache> m_cache;
    bool m_valid{false};

    friend std::optional<SecretKey> GenerateSecretKey(
        std::span<const std::uint8_t>) noexcept;
    friend std::optional<SecretKey> ImportSecretKey(
        std::span<const std::uint8_t>) noexcept;
    friend bool SignDeterministic(const SecretKey&, std::uint32_t,
                                  std::span<const std::uint8_t>,
                                  std::span<std::uint8_t>) noexcept;
};

/** Generate and cache a key from SK.seed || SK.prf || PK.seed. */
[[nodiscard]] std::optional<SecretKey> GenerateSecretKey(
    std::span<const std::uint8_t> seed) noexcept;

/** Import exactly 64 bytes, rebuilding the tree and validating PK.root. */
[[nodiscard]] std::optional<SecretKey> ImportSecretKey(
    std::span<const std::uint8_t> encoded) noexcept;

/**
 * Deterministically sign a 32-byte prepared message at an authorized leaf.
 * leaf is implicit protocol state and is not included in the 704-byte output.
 */
[[nodiscard]] bool SignDeterministic(
    const SecretKey& secret_key,
    std::uint32_t leaf,
    std::span<const std::uint8_t> message,
    std::span<std::uint8_t> signature_out) noexcept;

/** Verify an exact 704-byte signature at an authorized schedule leaf. */
[[nodiscard]] bool Verify(
    std::span<const std::uint8_t> public_key,
    std::uint32_t leaf,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> signature) noexcept;

} // namespace scheduled_wots

#endif // SYSCOIN_CRYPTO_SCHEDULED_WOTS_SCHEDULED_WOTS_H
