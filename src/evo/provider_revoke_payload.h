// Copyright (c) 2018-2020 The Dash Core developers
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PROVIDER_REVOKE_PAYLOAD_H
#define SYSCOIN_EVO_PROVIDER_REVOKE_PAYLOAD_H

#include <crypto/legacy_bls.h>
#include <llmq/pq_chainlock_types.h>
#include <primitives/transaction.h>
#include <univalue.h>

#include <cstdint>
#include <string>

class TxValidationState;

// SYSCOIN: the registry needs the neutral revoke wire payload but must not
// depend on provider validation, which in turn consumes registry snapshots.
class CProUpRevTx
{
public:
    static constexpr auto SPECIALTX_TYPE =
        SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;
    static constexpr uint16_t PQ_VERSION = 3;

    [[nodiscard]] static constexpr auto GetVersion(
        const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION
                                      : LEGACY_BLS_VERSION;
    }
    // These values are informational and do not alter revocation semantics.
    enum {
        REASON_NOT_SPECIFIED = 0,
        REASON_TERMINATION_OF_SERVICE = 1,
        REASON_COMPROMISED_KEYS = 2,
        REASON_CHANGE_OF_KEYS = 3,
        REASON_LAST = REASON_CHANGE_OF_KEYS,
    };

    uint16_t nVersion{LEGACY_BLS_VERSION};
    uint256 proTxHash;
    uint16_t nReason{REASON_NOT_SPECIFIED};
    uint256 inputsHash;
    CLegacyBLSSignature legacySig;
    uint32_t globalKeyVersion{0};
    llmq::pq::GlobalSignature pqSig{};

    SERIALIZE_METHODS(CProUpRevTx, obj)
    {
        READWRITE(obj.nVersion);
        if (obj.nVersion == 0 || obj.nVersion > PQ_VERSION) return;
        READWRITE(obj.proTxHash, obj.nReason, obj.inputsHash);
        if (obj.nVersion <= BASIC_BLS_VERSION) {
            if (!(s.GetType() & SER_GETHASH)) READWRITE(obj.legacySig);
        } else {
            READWRITE(obj.globalKeyVersion);
            if (!(s.GetType() & SER_GETHASH)) READWRITE(obj.pqSig);
        }
    }

    std::string ToString() const;
    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("reason", static_cast<int>(nReason));
        obj.pushKV("inputsHash", inputsHash.ToString());
    }
    bool IsTriviallyValid(TxValidationState& state,
                          bool is_basic_scheme_active) const;
};

#endif // SYSCOIN_EVO_PROVIDER_REVOKE_PAYLOAD_H
