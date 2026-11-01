// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PROVIDERTX_SIGNATURECACHE_H
#define SYSCOIN_EVO_PROVIDERTX_SIGNATURECACHE_H

#include <uint256.h>

#include <cstdint>
#include <optional>

class CBLSPublicKey;
class CBLSSignature;

/** One positive BLS verification result, owned by a mempool entry.
 *
 * The complete cryptographic inputs are checked on every use. This does not
 * cache provider validity, and is neither serialized nor populated by policy
 * metadata. Callers must hold the mempool lock while accessing an entry's cache.
 */
class CProTxBLSCache
{
public:
    enum class Result : uint8_t { UNVERIFIED, INVALID, VERIFIED, CACHED };

private:
    std::optional<uint256> m_verified;
    Result m_last_result{Result::UNVERIFIED};

public:
    bool Verify(const CBLSSignature& signature, const CBLSPublicKey& pubkey,
                const uint256& message, bool legacy);
    Result GetLastResult() const { return m_last_result; }
};

#endif // SYSCOIN_EVO_PROVIDERTX_SIGNATURECACHE_H
