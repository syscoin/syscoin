// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CRYPTO_SLHDSA_SLHDSA_H
#define SYSCOIN_CRYPTO_SLHDSA_SLHDSA_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace slhdsa {

inline constexpr char ALGORITHM[] = "SLH-DSA-SHAKE-128s";
inline constexpr std::size_t PUBLIC_KEY_SIZE{32};
inline constexpr std::size_t SECRET_KEY_SIZE{64};
inline constexpr std::size_t SIGNATURE_SIZE{7856};
inline constexpr std::size_t KEY_GENERATION_SEED_SIZE{48};
inline constexpr std::size_t HEDGED_RANDOMIZER_SIZE{16};
inline constexpr std::size_t MAX_CONTEXT_SIZE{255};

using PublicKey = std::array<std::uint8_t, PUBLIC_KEY_SIZE>;
using Signature = std::array<std::uint8_t, SIGNATURE_SIZE>;
using KeyGenerationSeed = std::array<std::uint8_t, KEY_GENERATION_SEED_SIZE>;
using HedgedRandomizer = std::array<std::uint8_t, HEDGED_RANDOMIZER_SIZE>;

/**
 * Move-only owner of an encoded FIPS 205 SLH-DSA-SHAKE-128s secret key.
 *
 * Destruction and moves cleanse the relinquished storage. Import validates the
 * embedded public root before constructing this type, so a live instance has a
 * valid internal key encoding unless memory has been corrupted.
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

    /** Export into exactly 64 bytes. The caller owns cleansing the destination. */
    [[nodiscard]] bool Export(std::span<std::uint8_t> out) const noexcept;

    /** Copy the non-secret verification key into exactly 32 bytes. */
    [[nodiscard]] bool GetPublicKey(std::span<std::uint8_t> out) const noexcept;

private:
    using Encoding = std::array<std::uint8_t, SECRET_KEY_SIZE>;

    explicit SecretKey(Encoding&& encoding) noexcept;

    Encoding m_encoding{};
    bool m_valid{false};

    friend std::optional<SecretKey> GenerateSecretKey(std::span<const std::uint8_t>) noexcept;
    friend std::optional<SecretKey> ImportSecretKey(std::span<const std::uint8_t>) noexcept;
    friend bool SignDeterministic(const SecretKey&, std::span<const std::uint8_t>,
                                  std::span<const std::uint8_t>, std::span<std::uint8_t>) noexcept;
    friend bool SignHedged(const SecretKey&, std::span<const std::uint8_t>,
                           std::span<const std::uint8_t>, std::span<const std::uint8_t>,
                           std::span<std::uint8_t>) noexcept;
};

/** Generate a key from exactly SK.seed || SK.prf || PK.seed (48 bytes). */
[[nodiscard]] std::optional<SecretKey> GenerateSecretKey(
    std::span<const std::uint8_t> seed) noexcept;

/** Import exactly 64 bytes and recompute the public root before accepting it. */
[[nodiscard]] std::optional<SecretKey> ImportSecretKey(
    std::span<const std::uint8_t> encoded) noexcept;

/**
 * Produce a deterministic FIPS 205 pure signature.
 *
 * domain_context is the FIPS 205 context field and must be at most 255 bytes.
 * Consensus callers should always supply a stable, protocol-specific domain.
 * signature_out must be exactly 7,856 bytes.
 */
[[nodiscard]] bool SignDeterministic(
    const SecretKey& secret_key,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> domain_context,
    std::span<std::uint8_t> signature_out) noexcept;

/**
 * Produce a hedged FIPS 205 pure signature using exactly 16 fresh random bytes.
 * All other size and domain requirements match SignDeterministic().
 */
[[nodiscard]] bool SignHedged(
    const SecretKey& secret_key,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> domain_context,
    std::span<const std::uint8_t> randomizer,
    std::span<std::uint8_t> signature_out) noexcept;

/** Fail-closed verification with exact public-key and signature sizes. */
[[nodiscard]] bool Verify(
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> domain_context,
    std::span<const std::uint8_t> signature) noexcept;

} // namespace slhdsa

#endif // SYSCOIN_CRYPTO_SLHDSA_SLHDSA_H
