// Copyright (c) 2018-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_DMNSTATE_H
#define SYSCOIN_EVO_DMNSTATE_H

#include <crypto/common.h>
#include <bls/bls.h>
#include <pubkey.h>
#include <netaddress.h>
#include <script/script.h>
#include <evo/providertx.h>

#include <memory>
#include <utility>
class CProRegTx;
class UniValue;

namespace llmq
{
    class CFinalCommitment;
} // namespace llmq

class CDeterministicMNState
{
private:
    int nPoSeBanHeight{-1};

    friend class CDeterministicMNStateDiff;
public:
    int nVersion{CProUpServTx::LEGACY_BLS_VERSION};

    int nRegisteredHeight{-1};
    int nCollateralHeight{-1};
    int nLastPaidHeight{0};
    int nPoSePenalty{0};
    int nPoSeRevivedHeight{-1};
    uint16_t nRevocationReason{CProUpRevTx::REASON_NOT_SPECIFIED};

    // the block hash X blocks after registration, used in quorum calculations
    uint256 confirmedHash;
    // sha256(proTxHash, confirmedHash) to speed up quorum calculations
    // please note that this is NOT a double-sha256 hash
    uint256 confirmedHashWithProRegTxHash;

    CKeyID keyIDOwner;
    CBLSLazyPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    CService addr;
    CScript scriptPayout;
    CScript scriptOperatorPayout;
    std::vector<unsigned char> vchNEVMAddress;
    bool m_changed_nevm_address{false};

public:
    CDeterministicMNState() = default;
    explicit CDeterministicMNState(const CProRegTx& proTx) :
        nVersion(proTx.nVersion),
        keyIDOwner(proTx.keyIDOwner),
        pubKeyOperator(proTx.pubKeyOperator),
        keyIDVoting(proTx.keyIDVoting),
        addr(proTx.addr),
        scriptPayout(proTx.scriptPayout)
    {
    }

    template <typename Stream>
    CDeterministicMNState(deserialize_type, Stream& s)
    {
        s >> *this;
    }

    SERIALIZE_METHODS(CDeterministicMNState, obj)
    {
        READWRITE(
            obj.nVersion,
            obj.nRegisteredHeight,
            obj.nLastPaidHeight,
            obj.nPoSePenalty,
            obj.nPoSeRevivedHeight,
            obj.nPoSeBanHeight,
            obj.nRevocationReason,
            obj.confirmedHash,
            obj.confirmedHashWithProRegTxHash,
            obj.keyIDOwner);
        READWRITE(CBLSLazyPublicKeyVersionWrapper(const_cast<CBLSLazyPublicKey&>(obj.pubKeyOperator), obj.nVersion == CProRegTx::LEGACY_BLS_VERSION));
        READWRITE(
            obj.keyIDVoting,
            obj.addr,
            obj.scriptPayout,
            obj.scriptOperatorPayout,
            obj.nCollateralHeight,
            obj.vchNEVMAddress);
    }

    void ResetOperatorFields()
    {
        nVersion = CProUpServTx::LEGACY_BLS_VERSION;
        pubKeyOperator = CBLSLazyPublicKey();
        addr = CService();
        scriptOperatorPayout = CScript();
        nRevocationReason = CProUpRevTx::REASON_NOT_SPECIFIED;
        vchNEVMAddress.clear();
    }
    void BanIfNotBanned(int height)
    {
        if (!IsBanned()) {
            nPoSeBanHeight = height;
            vchNEVMAddress.clear();

        }
    }
    int GetBannedHeight() const
    {
        return nPoSeBanHeight;
    }
    bool IsBanned() const
    {
        return nPoSeBanHeight != -1;
    }
    void Revive(int nRevivedHeight)
    {
        nPoSePenalty = 0;
        nPoSeBanHeight = -1;
        nPoSeRevivedHeight = nRevivedHeight;
    }
    void UpdateConfirmedHash(const uint256& _proTxHash, const uint256& _confirmedHash)
    {
        confirmedHash = _confirmedHash;
        CSHA256 h;
        h.Write(_proTxHash.begin(), _proTxHash.size());
        h.Write(_confirmedHash.begin(), _confirmedHash.size());
        h.Finalize(confirmedHashWithProRegTxHash.begin());
    }

public:
    std::string ToString() const;
    void ToJson(UniValue& obj) const;
};

class CDeterministicMNStateDiff
{
public:
    enum Field : uint64_t {
        Field_nRegisteredHeight = 0x0001,
        Field_nLastPaidHeight = 0x0002,
        Field_nPoSePenalty = 0x0004,
        Field_nPoSeRevivedHeight = 0x0008,
        Field_nPoSeBanHeight = 0x0010,
        Field_nRevocationReason = 0x0020,
        Field_confirmedHash = 0x0040,
        Field_confirmedHashWithProRegTxHash = 0x0080,
        Field_keyIDOwner = 0x0100,
        Field_pubKeyOperator = 0x0200,
        Field_keyIDVoting = 0x0400,
        Field_addr = 0x0800,
        Field_scriptPayout = 0x1000,
        Field_scriptOperatorPayout = 0x2000,
        Field_nCollateralHeight = 0x4000,
        Field_nVersion = 0x8000,
        Field_vchNEVMAddress = 0x10000,
    };

#define DMN_STATE_DIFF_ALL_FIELDS                      \
    DMN_STATE_DIFF_LINE(nRegisteredHeight)             \
    DMN_STATE_DIFF_LINE(nLastPaidHeight)               \
    DMN_STATE_DIFF_LINE(nPoSePenalty)                  \
    DMN_STATE_DIFF_LINE(nPoSeRevivedHeight)            \
    DMN_STATE_DIFF_LINE(nPoSeBanHeight)                \
    DMN_STATE_DIFF_LINE(nRevocationReason)             \
    DMN_STATE_DIFF_LINE(confirmedHash)                 \
    DMN_STATE_DIFF_LINE(confirmedHashWithProRegTxHash) \
    DMN_STATE_DIFF_LINE(keyIDOwner)                    \
    DMN_STATE_DIFF_LINE(pubKeyOperator)                \
    DMN_STATE_DIFF_LINE(keyIDVoting)                   \
    DMN_STATE_DIFF_LINE(addr)                          \
    DMN_STATE_DIFF_LINE(scriptPayout)                  \
    DMN_STATE_DIFF_LINE(scriptOperatorPayout)          \
    DMN_STATE_DIFF_LINE(nCollateralHeight)             \
    DMN_STATE_DIFF_LINE(nVersion)                      \
    DMN_STATE_DIFF_LINE(vchNEVMAddress)

public:
    uint32_t fields{0};
    // we reuse the state class, but only the members as noted by fields are valid
    CDeterministicMNState state;

public:
    CDeterministicMNStateDiff() = default;
    CDeterministicMNStateDiff(const CDeterministicMNState& a, const CDeterministicMNState& b)
    {
#define DMN_STATE_DIFF_LINE(f) if (a.f != b.f) { state.f = b.f; fields |= Field_##f; }
        DMN_STATE_DIFF_ALL_FIELDS
#undef DMN_STATE_DIFF_LINE
        if (fields & Field_pubKeyOperator) { state.nVersion = b.nVersion; fields |= Field_nVersion; }
    }

    [[nodiscard]] UniValue ToJson() const;

    SERIALIZE_METHODS(CDeterministicMNStateDiff, obj)
    {
        // NOTE: reading pubKeyOperator requires nVersion
        bool read_pubkey{false};
        READWRITE(VARINT(obj.fields));
#define DMN_STATE_DIFF_LINE(f) \
        if (strcmp(#f, "pubKeyOperator") == 0 && (obj.fields & Field_pubKeyOperator)) {\
            SER_READ(obj, read_pubkey = true); \
            READWRITE(CBLSLazyPublicKeyVersionWrapper(const_cast<CBLSLazyPublicKey&>(obj.state.pubKeyOperator), obj.state.nVersion == CProRegTx::LEGACY_BLS_VERSION)); \
        } else if (obj.fields & Field_##f) READWRITE(obj.state.f);

        DMN_STATE_DIFF_ALL_FIELDS
#undef DMN_STATE_DIFF_LINE
        if (read_pubkey) {
            SER_READ(obj, obj.fields |= Field_nVersion);
            SER_READ(obj, obj.state.pubKeyOperator.SetLegacy(obj.state.nVersion == CProRegTx::LEGACY_BLS_VERSION));
        }
    }

    void ApplyToState(CDeterministicMNState& target) const
    {
#define DMN_STATE_DIFF_LINE(f) if (fields & Field_##f) target.f = state.f;
        DMN_STATE_DIFF_ALL_FIELDS
#undef DMN_STATE_DIFF_LINE
    }
};


#endif // SYSCOIN_EVO_DMNSTATE_H
