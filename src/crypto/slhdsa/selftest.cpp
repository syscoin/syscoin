// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa/selftest.h>

#include <crypto/slhdsa/secure.h>
#include <crypto/slhdsa/slhdsa.h>
#include <crypto/slhdsa/vendor/sha3_api.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace slhdsa {
namespace {

constexpr std::array<std::uint8_t, 21> KAT_CONTEXT{
    'S', 'Y', 'S', 'C', 'O', 'I', 'N', '-', 'S', 'L', 'H', 'D', 'S', 'A', '-',
    'K', 'A', 'T', '-', 'V', '1'};

constexpr PublicKey KAT_PUBLIC_KEY{
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x89, 0xfd, 0x81, 0xfd, 0xbb, 0x5b, 0x94, 0x12,
    0x9b, 0x14, 0x76, 0x1b, 0xdc, 0x6b, 0xf6, 0x82};

constexpr std::array<std::uint8_t, 32> KAT_SIGNATURE_SHAKE256{
    0x4a, 0xe7, 0x70, 0x42, 0xf4, 0xe1, 0x02, 0xd0,
    0xfb, 0x95, 0x4a, 0x8b, 0x12, 0x29, 0xf1, 0xa1,
    0xa8, 0xa4, 0x63, 0x5b, 0x1f, 0x9a, 0xb3, 0xc5,
    0x88, 0x25, 0xfe, 0x3a, 0x88, 0x6f, 0x39, 0x45};

bool IsAllZero(std::span<const std::uint8_t> bytes) noexcept
{
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte == 0; });
}

} // namespace

bool RunSelfTest() noexcept
{
    KeyGenerationSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
    }
    if (GenerateSecretKey(std::span<const std::uint8_t>{seed}.first(seed.size() - 1)).has_value()) {
        return false;
    }

    std::array<std::uint8_t, 32> message{};
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>(0xa0 + i);
    }

    auto secret_key = GenerateSecretKey(seed);
    syscoin_slhdsa_secure_zero(seed.data(), seed.size());
    if (!secret_key.has_value()) return false;

    PublicKey public_key{};
    if (!secret_key->GetPublicKey(public_key) || public_key != KAT_PUBLIC_KEY ||
        secret_key->GetPublicKey(std::span<std::uint8_t>{public_key}.first(PUBLIC_KEY_SIZE - 1))) {
        return false;
    }

    Signature signature{};
    if (SignDeterministic(*secret_key, message, KAT_CONTEXT,
                          std::span<std::uint8_t>{signature}.first(SIGNATURE_SIZE - 1))) {
        return false;
    }
    if (!SignDeterministic(*secret_key, message, KAT_CONTEXT, signature)) return false;

    std::array<std::uint8_t, 32> signature_digest{};
    shake256(signature_digest.data(), signature_digest.size(), signature.data(), signature.size());
    if (signature_digest != KAT_SIGNATURE_SHAKE256 ||
        !Verify(public_key, message, KAT_CONTEXT, signature)) {
        return false;
    }

    signature[SIGNATURE_SIZE / 2] ^= 0x01;
    if (Verify(public_key, message, KAT_CONTEXT, signature)) return false;
    signature[SIGNATURE_SIZE / 2] ^= 0x01;

    auto wrong_context = KAT_CONTEXT;
    wrong_context[0] ^= 0x01;
    if (Verify(public_key, message, wrong_context, signature) ||
        Verify(std::span<const std::uint8_t>{public_key}.first(PUBLIC_KEY_SIZE - 1),
               message, KAT_CONTEXT, signature) ||
        Verify(public_key, message, KAT_CONTEXT,
               std::span<const std::uint8_t>{signature}.first(SIGNATURE_SIZE - 1))) {
        return false;
    }

    std::array<std::uint8_t, MAX_CONTEXT_SIZE + 1> oversized_context{};
    std::fill(signature.begin(), signature.end(), 0xa5);
    if (SignDeterministic(*secret_key, message, oversized_context, signature) ||
        !IsAllZero(signature) || Verify(public_key, message, oversized_context, signature)) {
        return false;
    }

    HedgedRandomizer randomizer{};
    for (std::size_t i = 0; i < randomizer.size(); ++i) {
        randomizer[i] = static_cast<std::uint8_t>(0xf0 + i);
    }
    std::fill(signature.begin(), signature.end(), 0xa5);
    if (SignHedged(*secret_key, message, KAT_CONTEXT,
                   std::span<const std::uint8_t>{randomizer}.first(randomizer.size() - 1),
                   signature) || !IsAllZero(signature)) {
        return false;
    }
    if (!SignHedged(*secret_key, message, KAT_CONTEXT, randomizer, signature) ||
        !Verify(public_key, message, KAT_CONTEXT, signature)) {
        return false;
    }

    std::array<std::uint8_t, SECRET_KEY_SIZE> encoded{};
    if (!secret_key->Export(encoded)) return false;
    if (ImportSecretKey(std::span<const std::uint8_t>{encoded}.first(SECRET_KEY_SIZE - 1)).has_value() ||
        secret_key->Export(std::span<std::uint8_t>{encoded}.first(SECRET_KEY_SIZE - 1))) {
        return false;
    }
    auto imported = ImportSecretKey(encoded);
    encoded.back() ^= 0x01;
    const bool rejected_corrupt_key = !ImportSecretKey(encoded).has_value();
    syscoin_slhdsa_secure_zero(encoded.data(), encoded.size());
    if (!imported.has_value() || !rejected_corrupt_key) return false;

    PublicKey imported_public_key{};
    SecretKey moved_key{std::move(*imported)};
    return !imported->IsValid() && moved_key.IsValid() &&
           moved_key.GetPublicKey(imported_public_key) && imported_public_key == public_key;
}

} // namespace slhdsa
