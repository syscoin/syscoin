// Copyright (c) 2026 The Syscoin Core developers
// Copyright (c) 2026 Nicolas Consigny
// Distributed under the MIT software license, see the accompanying LICENSE file.

#ifndef SYSCOIN_CRYPTO_SPHINCS_C11_SPHINCS_C11_H
#define SYSCOIN_CRYPTO_SPHINCS_C11_SPHINCS_C11_H

#include <span.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace sphincs_c11 {

static constexpr std::size_t SECRET_SEED_SIZE = 32;
static constexpr std::size_t PUBLIC_SEED_SIZE = 16;
static constexpr std::size_t MESSAGE_SIZE = 32;
static constexpr std::size_t PUBLIC_KEY_SIZE = 32;
static constexpr std::size_t SECRET_KEY_SIZE = 64;
static constexpr std::size_t SIGNATURE_SIZE = 3976;
/** Exclusive bound for deterministic R grinding and serialized WOTS counters. */
static constexpr std::uint32_t GRIND_LIMIT = 10'000'000;

using SecretSeed = std::array<unsigned char, SECRET_SEED_SIZE>;
using PublicSeed = std::array<unsigned char, PUBLIC_SEED_SIZE>;
using Message = std::array<unsigned char, MESSAGE_SIZE>;
using Signature = std::array<unsigned char, SIGNATURE_SIZE>;
using SerializedPublicKey = std::array<unsigned char, PUBLIC_KEY_SIZE>;
using SerializedSecretKey = std::array<unsigned char, SECRET_KEY_SIZE>;

class PublicKey
{
public:
    PublicKey() = default;

    const SerializedPublicKey& GetBytes() const noexcept { return m_bytes; }

private:
    SerializedPublicKey m_bytes{};

    friend bool GenerateKeyPair(const SecretSeed&, const PublicSeed&, PublicKey&, class SecretKey&);
    friend bool ParsePublicKey(Span<const unsigned char>, PublicKey&);
    friend bool ParseSecretKey(Span<const unsigned char>, class SecretKey&);
    friend bool Verify(const PublicKey&, const Message&, Span<const unsigned char>);
    friend class SecretKey;
};

/**
 * An owning secret key. Copies are forbidden and every destruction, move, and
 * replacement securely overwrites the previous bytes.
 *
 * Serialized layout: SK.seed[32] || PK.seed[16] || PK.root[16].
 */
class SecretKey
{
public:
    SecretKey() noexcept;
    ~SecretKey();

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&& other) noexcept;
    SecretKey& operator=(SecretKey&& other) noexcept;

    bool IsInitialized() const noexcept { return m_initialized; }
    PublicKey GetPublicKey() const noexcept;
    void Clear() noexcept;

private:
    class SigningCache;

    SerializedSecretKey m_bytes{};
    bool m_initialized{false};
    // This immutable public tree reuses work already required to validate the
    // key; it contains no secret material and is never serialized.
    std::unique_ptr<SigningCache> m_signing_cache;

    friend bool GenerateKeyPair(const SecretSeed&, const PublicSeed&, PublicKey&, SecretKey&);
    friend bool ParseSecretKey(Span<const unsigned char>, SecretKey&);
    friend bool Sign(const SecretKey&, const Message&, Signature&);
    friend SerializedSecretKey SerializeSecretKey(const SecretKey&);
};

/** Build a deterministic key pair from caller-supplied uniformly random seeds. */
bool GenerateKeyPair(const SecretSeed& secret_seed, const PublicSeed& public_seed,
                     PublicKey& public_key, SecretKey& secret_key);

/** Parse a canonical 32-byte public key. */
bool ParsePublicKey(Span<const unsigned char> bytes, PublicKey& public_key);

/**
 * Parse and validate a canonical 64-byte secret key. This recomputes the public
 * root and is intentionally as expensive as key generation.
 */
bool ParseSecretKey(Span<const unsigned char> bytes, SecretKey& secret_key);

SerializedPublicKey SerializePublicKey(const PublicKey& public_key) noexcept;
SerializedSecretKey SerializeSecretKey(const SecretKey& secret_key);

/** Deterministically sign exactly 32 message bytes. */
bool Sign(const SecretKey& secret_key, const Message& message, Signature& signature);

/** Verify an exact, canonical 3976-byte signature. */
bool Verify(const PublicKey& public_key, const Message& message,
            Span<const unsigned char> signature);

/**
 * Non-owning input for independent verification jobs. Inputs and pointed-to
 * objects must outlive VerifyBatch().
 */
struct VerificationInput {
    const PublicKey* public_key{nullptr};
    const Message* message{nullptr};
    Span<const unsigned char> signature{};
};

/**
 * Convenience batch verifier. Each item is independent and the implementation
 * has no mutable global state, so callers may shard the same inputs across
 * their existing worker pool. One byte (0 or 1) is returned per input.
 */
std::vector<unsigned char> VerifyBatch(Span<const VerificationInput> inputs);

} // namespace sphincs_c11

#endif // SYSCOIN_CRYPTO_SPHINCS_C11_SPHINCS_C11_H
