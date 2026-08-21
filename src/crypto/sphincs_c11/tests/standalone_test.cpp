// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying ../LICENSE file.

#include <crypto/sha256.h>
#include <crypto/sphincs_c11/sphincs_c11.h>
#include <support/cleanse.h>

#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

template <typename Bytes>
std::string Hex(const Bytes& bytes)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

[[noreturn]] void Fail(const char* reason)
{
    std::cerr << "FAIL: " << reason << '\n';
    std::exit(1);
}

void Require(bool condition, const char* reason)
{
    if (!condition) Fail(reason);
}

} // namespace

int main(int argc, char** argv)
{
    using namespace sphincs_c11;

    SecretSeed secret_seed;
    PublicSeed public_seed;
    Message message;
    for (std::size_t i = 0; i < secret_seed.size(); ++i) secret_seed[i] = i;
    for (std::size_t i = 0; i < public_seed.size(); ++i) public_seed[i] = 0xa0 + i;
    for (std::size_t i = 0; i < message.size(); ++i) message[i] = (3 + 7 * i) & 0xff;

    PublicKey public_key;
    SecretKey secret_key;
    Require(GenerateKeyPair(secret_seed, public_seed, public_key, secret_key), "key generation");
    Require(secret_key.IsInitialized(), "secret key initialization");
    Require(SerializePublicKey(secret_key.GetPublicKey()) == SerializePublicKey(public_key),
            "public key embedded in secret key");

    Signature signature;
    Require(Sign(secret_key, message, signature), "signing");
    Require(Verify(public_key, message, signature), "valid signature rejected");

    Signature second_signature;
    Require(Sign(secret_key, message, second_signature), "second signing");
    Require(signature == second_signature, "signing is not deterministic");

    Message wrong_message = message;
    wrong_message[0] ^= 1;
    Require(!Verify(public_key, wrong_message, signature), "wrong message accepted");
    Require(!Verify(public_key, message,
                    Span<const unsigned char>(signature.data(), signature.size() - 1)),
            "short signature accepted");

    for (std::size_t offset : {std::size_t{0}, std::size_t{16}, std::size_t{224},
                               std::size_t{2336}, SIGNATURE_SIZE - 1}) {
        Signature corrupted = signature;
        corrupted[offset] ^= 1;
        Require(!Verify(public_key, message, corrupted), "corrupted signature accepted");
    }

    SerializedPublicKey public_bytes = SerializePublicKey(public_key);
    PublicKey parsed_public_key;
    Require(ParsePublicKey(public_bytes, parsed_public_key), "public key parsing");
    Require(Verify(parsed_public_key, message, signature), "parsed public key rejected signature");
    SerializedPublicKey wrong_public_bytes = public_bytes;
    wrong_public_bytes.back() ^= 1;
    PublicKey wrong_public_key;
    Require(ParsePublicKey(wrong_public_bytes, wrong_public_key), "wrong public key parsing");
    Require(!Verify(wrong_public_key, message, signature), "wrong public key accepted signature");
    Require(!ParsePublicKey(Span<const unsigned char>(public_bytes.data(), public_bytes.size() - 1),
                            parsed_public_key),
            "short public key accepted");

    SerializedSecretKey secret_bytes = SerializeSecretKey(secret_key);
    SecretKey parsed_secret_key;
    Require(ParseSecretKey(secret_bytes, parsed_secret_key), "secret key parsing/root validation");
    secret_bytes.back() ^= 1;
    SecretKey corrupted_secret_key;
    Require(!ParseSecretKey(secret_bytes, corrupted_secret_key), "invalid secret key root accepted");
    memory_cleanse(secret_bytes.data(), secret_bytes.size());

    Signature batch_corrupted = signature;
    batch_corrupted[100] ^= 1;
    const std::array<VerificationInput, 3> batch{{
        {&public_key, &message, signature},
        {&public_key, &wrong_message, signature},
        {&public_key, &message, batch_corrupted},
    }};
    const std::vector<unsigned char> results = VerifyBatch(batch);
    Require(results == std::vector<unsigned char>({1, 0, 0}), "batch verification");

    std::array<unsigned char, CSHA256::OUTPUT_SIZE> signature_digest;
    CSHA256().Write(signature.data(), signature.size()).Finalize(signature_digest.data());
    static constexpr const char* EXPECTED_PUBLIC_KEY =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafa3d1b4ec763f8be45e4a56375774efe9";
    static constexpr const char* EXPECTED_SIGNATURE_SHA256 =
        "99c0656fccd9353d4b68db3f4d09afc1485c9cc59381ff5603208a25be026886";
    Require(Hex(public_bytes) == EXPECTED_PUBLIC_KEY, "pinned Python public-key vector mismatch");
    Require(Hex(signature_digest) == EXPECTED_SIGNATURE_SHA256,
            "pinned Python signature vector mismatch");
    if (argc == 2 && std::string(argv[1]) == "--dump-signature") {
        std::cout << "signature=" << Hex(signature) << '\n';
    } else if (argc != 1) {
        Fail("unknown argument");
    }
    std::cout << "public_key=" << Hex(public_bytes) << '\n';
    std::cout << "signature_sha256=" << Hex(signature_digest) << '\n';
    std::cout << "PASS\n";

    memory_cleanse(secret_seed.data(), secret_seed.size());
    return 0;
}
