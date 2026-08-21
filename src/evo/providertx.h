// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PROVIDERTX_H
#define SYSCOIN_EVO_PROVIDERTX_H

#include <crypto/legacy_bls.h>
#include <consensus/validation.h>
#include <evo/provider_revoke_payload.h>
#include <llmq/pq_chainlock_types.h>
#include <primitives/transaction.h>

#include <base58.h>
#include <netaddress.h>
#include <pubkey.h>
#include <univalue.h>
#include <script/script.h>
#include <key_io.h>
#include <kernel/cs_main.h>

#include <cstdint>
#include <optional>

class CBlockIndex;
class CCoinsViewCache;
enum class SpecialTxValidationContext : uint8_t;

struct ProviderMutationIdentity {
    uint256 pro_tx_hash;
    bool is_pq_revocation{false};
};

/** Strict, non-throwing decoding for provider-update conflict detection. */
[[nodiscard]] std::optional<ProviderMutationIdentity>
DecodeProviderMutationIdentity(const CTransaction& tx) noexcept;

class CProRegTx
{
public:
    static constexpr auto SPECIALTX_TYPE = SYSCOIN_TX_VERSION_MN_REGISTER;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;
    static constexpr uint16_t PQ_VERSION = 3;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }
    uint16_t nVersion{LEGACY_BLS_VERSION};                 // message version
    uint16_t nType{0};                                     // only 0 supported for now
    uint16_t nMode{0};                                     // only 0 supported for now
    COutPoint collateralOutpoint{uint256(), (uint32_t)-1}; // if hash is null, we refer to a ProRegTx output
    CService addr;
    CKeyID keyIDOwner;
    CLegacyBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    uint16_t nOperatorReward{0};
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

    SERIALIZE_METHODS(CProRegTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > PQ_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.nType,
                obj.nMode,
                obj.collateralOutpoint,
                obj.addr,
                obj.keyIDOwner);
        if (obj.nVersion <= BASIC_BLS_VERSION) {
            READWRITE(obj.pubKeyOperator);
        }
        READWRITE(
                obj.keyIDVoting,
                obj.nOperatorReward,
                obj.scriptPayout,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(obj.vchSig);
        }
    }

    // When signing with the collateral key, we don't sign the hash but a generated message instead
    // This is needed for HW wallet support which can only sign text messages as of now
    std::string MakeSignString() const;

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
        obj.pushKV("collateralIndex", (int)collateralOutpoint.n);
        obj.pushKV("service", addr.ToStringAddr());
        obj.pushKV("ownerAddress", EncodeDestination(WitnessV0KeyHash(keyIDOwner)));
        obj.pushKV("votingAddress", EncodeDestination(WitnessV0KeyHash(keyIDVoting)));

        CTxDestination dest;
        if (ExtractDestination(scriptPayout, dest)) {
            obj.pushKV("payoutAddress", EncodeDestination(dest));
        }
        if (nVersion <= BASIC_BLS_VERSION) {
            obj.pushKV("legacyPubKeyOperator", pubKeyOperator.ToString());
        }
        obj.pushKV("operatorReward", (double)nOperatorReward / 100);

        obj.pushKV("inputsHash", inputsHash.ToString());
    }
    bool IsTriviallyValid(TxValidationState& state, bool is_basic_scheme_active) const;
};
class CProUpServTx
{
public:
    static constexpr auto SPECIALTX_TYPE = SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;
    static constexpr uint16_t UPDATE_NEVM_VERSION = 3;
    static constexpr uint16_t PQ_VERSION = 4;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? UPDATE_NEVM_VERSION : LEGACY_BLS_VERSION;
    }
    uint16_t nVersion{LEGACY_BLS_VERSION}; // message version
    uint256 proTxHash;
    CService addr;
    CScript scriptOperatorPayout;
    uint256 inputsHash; // replay protection
    CLegacyBLSSignature legacySig;
    uint32_t globalKeyVersion{0};
    llmq::pq::GlobalSignature pqSig{};
    std::vector<unsigned char> vchNEVMAddress;

    SERIALIZE_METHODS(CProUpServTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > PQ_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.proTxHash,
                obj.addr,
                obj.scriptOperatorPayout,
                obj.inputsHash
        );
        if (obj.nVersion <= UPDATE_NEVM_VERSION) {
            if (!(s.GetType() & SER_GETHASH)) READWRITE(obj.legacySig);
        } else {
            READWRITE(obj.globalKeyVersion);
            if (!(s.GetType() & SER_GETHASH)) READWRITE(obj.pqSig);
        }
        if (obj.nVersion >= UPDATE_NEVM_VERSION) {
            READWRITE(obj.vchNEVMAddress);
       }
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("service", addr.ToStringAddr());
        CTxDestination dest;
        if (ExtractDestination(scriptOperatorPayout, dest)) {
            obj.pushKV("operatorPayoutAddress", EncodeDestination(dest));
        }
        obj.pushKV("inputsHash", inputsHash.ToString());
        obj.pushKV("nevmAddress", vchNEVMAddress.empty()? "" :"0x"+HexStr(vchNEVMAddress));
    }

    bool IsTriviallyValid(TxValidationState& state, bool is_basic_scheme_active) const;
};

class CProUpRegTx
{
public:
    static constexpr auto SPECIALTX_TYPE = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;
    static constexpr uint16_t PQ_VERSION = 3;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }
    uint16_t nVersion{LEGACY_BLS_VERSION}; // message version
    uint256 proTxHash;
    uint16_t nMode{0}; // only 0 supported for now
    CLegacyBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

    SERIALIZE_METHODS(CProUpRegTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > PQ_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.proTxHash,
                obj.nMode);
        if (obj.nVersion <= BASIC_BLS_VERSION) {
            READWRITE(obj.pubKeyOperator);
        }
        READWRITE(
                obj.keyIDVoting,
                obj.scriptPayout,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(
                    obj.vchSig
            );
        }
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("votingAddress", EncodeDestination(WitnessV0KeyHash(keyIDVoting)));
        CTxDestination dest;
        if (ExtractDestination(scriptPayout, dest)) {
            obj.pushKV("payoutAddress", EncodeDestination(dest));
        }
        if (nVersion <= BASIC_BLS_VERSION) {
            obj.pushKV("legacyPubKeyOperator", pubKeyOperator.ToString());
        }
        obj.pushKV("inputsHash", inputsHash.ToString());
    }

    bool IsTriviallyValid(TxValidationState& state, bool is_basic_scheme_active) const;
};

bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool CheckProUpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool CheckProUpRevTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

#endif // SYSCOIN_EVO_PROVIDERTX_H
