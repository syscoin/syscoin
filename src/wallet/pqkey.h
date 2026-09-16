// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_WALLET_PQKEY_H
#define SYSCOIN_WALLET_PQKEY_H

#include <crypto/slhdsa/slhdsa.h>
#include <wallet/crypter.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace wallet {

enum class PQKeyRole : uint8_t {
    VOTING = 1,
    OWNER = 2,
};

struct PQKeyInfo {
    slhdsa::PublicKey public_key{};
    uint8_t roles{0};
};

/** Selective plaintext export. Roles describe wallet use, not on-chain authority. */
struct PQKeyExport {
    slhdsa::PublicKey public_key{};
    CKeyingMaterial secret;
    uint8_t roles{0};
};

/** Network-independent, versioned checksummed hex record for SLH-DSA-SHAKE-128s. */
[[nodiscard]] std::optional<std::string> EncodePQKey(
    const PQKeyExport& record, std::string& error);

/** Bounded fixed-size decoding; validates the complete secret and matching public key. */
[[nodiscard]] std::optional<PQKeyExport> DecodePQKey(
    std::string_view encoded, std::string& error);

} // namespace wallet

#endif // SYSCOIN_WALLET_PQKEY_H
