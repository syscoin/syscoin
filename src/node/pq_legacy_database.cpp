// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_database.h>

#include <dbwrapper.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace node {
namespace {

constexpr uint8_t ROOT_SCHEMA_KEY{'V'};
constexpr uint32_t ROOT_SCHEMA_VERSION{1};
// CDBWrapper serializes the string "\0obfuscate_key" with a length prefix.
constexpr std::array<uint8_t, 15> OBFUSCATE_METADATA_KEY{
    14, 0, 'o', 'b', 'f', 'u', 's', 'c', 'a', 't', 'e', '_', 'k', 'e', 'y'};

bool IsObfuscationMetadata(CDBIterator& it, const CDBWrapper& db)
{
    std::array<uint8_t, OBFUSCATE_METADATA_KEY.size()> key;
    if (!it.GetKeyExact(key) || key != OBFUSCATE_METADATA_KEY) return false;

    // The wrapper writes this one value unobfuscated, then loads its eight
    // bytes as the obfuscation key. Iterator decoding XORs all values, so
    // undo that XOR here before checking the original fixed-size encoding.
    const auto& obfuscate_key{dbwrapper_private::GetObfuscateKey(db)};
    std::array<uint8_t, 9> encoded;
    if (obfuscate_key.size() != 8 || it.GetValueSize() != encoded.size() ||
        !it.GetValueExact(encoded)) return false;
    for (std::size_t i{0}; i < encoded.size(); ++i) {
        encoded[i] ^= obfuscate_key[i % obfuscate_key.size()];
    }
    if (encoded[0] != obfuscate_key.size()) return false;
    for (std::size_t i{0}; i < obfuscate_key.size(); ++i) {
        if (encoded[i + 1] != obfuscate_key[i]) return false;
    }
    return true;
}

} // namespace

NEVMRootSchema InspectNEVMRootSchema(CDBWrapper& db)
{
    try {
        std::unique_ptr<CDBIterator> it{db.NewIterator()};
        it->Seek(ROOT_SCHEMA_KEY);
        it->CheckStatus();
        uint8_t schema_key;
        if (it->Valid() && it->GetKeyExact(schema_key) &&
            schema_key == ROOT_SCHEMA_KEY) {
            uint32_t version{0};
            return it->GetValueSize() == sizeof(version) &&
                           it->GetValueExact(version) &&
                           version == ROOT_SCHEMA_VERSION
                       ? NEVMRootSchema::CURRENT
                       : NEVMRootSchema::CORRUPT;
        }

        bool has_roots{false};
        it->SeekToFirst();
        it->CheckStatus();
        while (it->Valid()) {
            uint256 root_key;
            if (it->GetKeyExact(root_key)) {
                // Fixed-size decoding keeps malformed database values from
                // allocating memory based on an untrusted length prefix.
                std::array<uint8_t, 2 * uint256::size()> roots;
                if (it->GetValueSize() != 2 * uint256::size() ||
                    !it->GetValueExact(roots)) return NEVMRootSchema::CORRUPT;
                has_roots = true;
            } else if (!IsObfuscationMetadata(*it, db)) {
                return NEVMRootSchema::CORRUPT;
            }
            it->Next();
            it->CheckStatus();
        }
        return has_roots ? NEVMRootSchema::LEGACY : NEVMRootSchema::EMPTY;
    } catch (const dbwrapper_error&) {
        return NEVMRootSchema::CORRUPT;
    }
}

} // namespace node
