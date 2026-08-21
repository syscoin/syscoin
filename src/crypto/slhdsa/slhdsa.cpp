// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa/slhdsa.h>

#include <crypto/slhdsa/secure.h>
#include <crypto/slhdsa/vendor/slh_dsa.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace slhdsa {
namespace {

bool VendorParametersMatch() noexcept
{
    return slh_pk_sz(&slh_dsa_shake_128s) == PUBLIC_KEY_SIZE &&
           slh_sk_sz(&slh_dsa_shake_128s) == SECRET_KEY_SIZE &&
           slh_sig_sz(&slh_dsa_shake_128s) == SIGNATURE_SIZE;
}

bool ConstantTimeEqual(std::span<const std::uint8_t> lhs,
                       std::span<const std::uint8_t> rhs) noexcept
{
    if (lhs.size() != rhs.size()) return false;

    std::uint8_t difference{0};
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        difference |= lhs[i] ^ rhs[i];
    }
    return difference == 0;
}

void Cleanse(std::span<std::uint8_t> bytes) noexcept
{
    syscoin_slhdsa_secure_zero(bytes.data(), bytes.size());
}

bool CanSign(const SecretKey& secret_key,
             std::span<const std::uint8_t> domain_context,
             std::span<std::uint8_t> signature_out) noexcept
{
    if (signature_out.size() != SIGNATURE_SIZE) return false;
    Cleanse(signature_out);
    return secret_key.IsValid() && domain_context.size() <= MAX_CONTEXT_SIZE &&
           VendorParametersMatch();
}

} // namespace

SecretKey::SecretKey(Encoding&& encoding) noexcept :
    m_encoding{encoding},
    m_valid{true}
{
    Cleanse(encoding);
}

SecretKey::SecretKey(SecretKey&& other) noexcept :
    m_encoding{other.m_encoding},
    m_valid{other.m_valid}
{
    Cleanse(other.m_encoding);
    other.m_valid = false;
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept
{
    if (this == &other) return *this;

    Cleanse(m_encoding);
    m_encoding = other.m_encoding;
    m_valid = other.m_valid;
    Cleanse(other.m_encoding);
    other.m_valid = false;
    return *this;
}

SecretKey::~SecretKey() noexcept
{
    Cleanse(m_encoding);
    m_valid = false;
}

bool SecretKey::Export(std::span<std::uint8_t> out) const noexcept
{
    if (!m_valid || out.size() != m_encoding.size()) return false;
    std::copy(m_encoding.begin(), m_encoding.end(), out.begin());
    return true;
}

bool SecretKey::GetPublicKey(std::span<std::uint8_t> out) const noexcept
{
    if (!m_valid || out.size() != PUBLIC_KEY_SIZE) return false;
    std::copy_n(m_encoding.begin() + 2 * HEDGED_RANDOMIZER_SIZE,
                PUBLIC_KEY_SIZE, out.begin());
    return true;
}

std::optional<SecretKey> GenerateSecretKey(std::span<const std::uint8_t> seed) noexcept
{
    if (seed.size() != KEY_GENERATION_SEED_SIZE || !VendorParametersMatch()) {
        return std::nullopt;
    }

    SecretKey::Encoding encoded{};
    PublicKey public_key{};
    const int result = slh_keygen_internal(encoded.data(), public_key.data(),
                                           seed.data(), seed.data() + HEDGED_RANDOMIZER_SIZE,
                                           seed.data() + 2 * HEDGED_RANDOMIZER_SIZE,
                                           &slh_dsa_shake_128s);
    const bool consistent = result == 0 &&
        ConstantTimeEqual(public_key,
                          std::span<const std::uint8_t>{encoded}.subspan(2 * HEDGED_RANDOMIZER_SIZE));
    if (!consistent) {
        Cleanse(encoded);
        return std::nullopt;
    }
    return SecretKey{std::move(encoded)};
}

std::optional<SecretKey> ImportSecretKey(std::span<const std::uint8_t> encoded) noexcept
{
    if (encoded.size() != SECRET_KEY_SIZE || !VendorParametersMatch()) {
        return std::nullopt;
    }

    KeyGenerationSeed seed{};
    std::copy_n(encoded.begin(), seed.size(), seed.begin());
    auto regenerated = GenerateSecretKey(seed);
    Cleanse(seed);
    if (!regenerated.has_value()) return std::nullopt;

    SecretKey::Encoding canonical{};
    if (!regenerated->Export(canonical) || !ConstantTimeEqual(canonical, encoded)) {
        Cleanse(canonical);
        return std::nullopt;
    }
    Cleanse(canonical);
    return regenerated;
}

bool SignDeterministic(const SecretKey& secret_key,
                       std::span<const std::uint8_t> message,
                       std::span<const std::uint8_t> domain_context,
                       std::span<std::uint8_t> signature_out) noexcept
{
    if (!CanSign(secret_key, domain_context, signature_out)) return false;

    const size_t written = slh_sign(signature_out.data(), message.data(), message.size(),
                                    domain_context.data(), domain_context.size(),
                                    secret_key.m_encoding.data(), nullptr,
                                    &slh_dsa_shake_128s);
    if (written != SIGNATURE_SIZE) {
        Cleanse(signature_out);
        return false;
    }
    return true;
}

bool SignHedged(const SecretKey& secret_key,
                std::span<const std::uint8_t> message,
                std::span<const std::uint8_t> domain_context,
                std::span<const std::uint8_t> randomizer,
                std::span<std::uint8_t> signature_out) noexcept
{
    if (!CanSign(secret_key, domain_context, signature_out)) {
        return false;
    }
    if (randomizer.size() != HEDGED_RANDOMIZER_SIZE) {
        Cleanse(signature_out);
        return false;
    }

    const size_t written = slh_sign(signature_out.data(), message.data(), message.size(),
                                    domain_context.data(), domain_context.size(),
                                    secret_key.m_encoding.data(), randomizer.data(),
                                    &slh_dsa_shake_128s);
    if (written != SIGNATURE_SIZE) {
        Cleanse(signature_out);
        return false;
    }
    return true;
}

bool Verify(std::span<const std::uint8_t> public_key,
            std::span<const std::uint8_t> message,
            std::span<const std::uint8_t> domain_context,
            std::span<const std::uint8_t> signature) noexcept
{
    if (public_key.size() != PUBLIC_KEY_SIZE || signature.size() != SIGNATURE_SIZE ||
        domain_context.size() > MAX_CONTEXT_SIZE || !VendorParametersMatch()) {
        return false;
    }

    return slh_verify(message.data(), message.size(), signature.data(), signature.size(),
                      domain_context.data(), domain_context.size(), public_key.data(),
                      &slh_dsa_shake_128s) == 1;
}

} // namespace slhdsa
