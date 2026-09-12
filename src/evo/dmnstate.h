// Copyright (c) 2018-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_DMNSTATE_H
#define SYSCOIN_EVO_DMNSTATE_H

#include <crypto/common.h>
#include <crypto/legacy_bls.h>
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
    // SYSCOIN: retained as bytes only for historical DMN replay and branch
    // diagnostics. It is never a live post-activation authentication key.
    CLegacyBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    llmq::pq::VotingKeyRecord pqVotingKey;
    CService addr;
    CScript scriptPayout;
    CScript scriptOperatorPayout;
    std::vector<unsigned char> vchNEVMAddress;

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
        // The provider version changes on operator reset, so it cannot also
        // select the persistent owner-delegated voting-key schema.
        static constexpr int32_t PQ_STATE_SENTINEL{-1};
        static constexpr uint16_t PQ_STATE_SCHEMA{1};
        SER_WRITE(obj, if (obj.nVersion < 0 || !obj.pqVotingKey.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical DMN voting-key state");
        });
        int32_t encoded_version{obj.pqVotingKey.key_version == 0
            ? obj.nVersion : PQ_STATE_SENTINEL};
        READWRITE(encoded_version);
        if (encoded_version < PQ_STATE_SENTINEL) {
            throw std::ios_base::failure("invalid DMN state encoding");
        }
        const bool has_voting_record{encoded_version == PQ_STATE_SENTINEL};
        if (has_voting_record) {
            uint16_t schema{PQ_STATE_SCHEMA};
            READWRITE(schema);
            if (schema != PQ_STATE_SCHEMA) {
                throw std::ios_base::failure("unknown DMN voting-key schema");
            }
            READWRITE(obj.nVersion);
            if (obj.nVersion < 0) {
                throw std::ios_base::failure("invalid DMN provider version");
            }
        } else {
            SER_READ(obj, obj.nVersion = encoded_version; obj.pqVotingKey = {});
        }
        READWRITE(
            obj.nRegisteredHeight,
            obj.nLastPaidHeight,
            obj.nPoSePenalty,
            obj.nPoSeRevivedHeight,
            obj.nPoSeBanHeight,
            obj.nRevocationReason,
            obj.confirmedHash,
            obj.confirmedHashWithProRegTxHash,
            obj.keyIDOwner);
        READWRITE(obj.pubKeyOperator);
        READWRITE(
            obj.keyIDVoting,
            obj.addr,
            obj.scriptPayout,
            obj.scriptOperatorPayout,
            obj.nCollateralHeight,
            obj.vchNEVMAddress);
        if (has_voting_record) {
            READWRITE(obj.pqVotingKey);
            if (obj.pqVotingKey.key_version == 0) {
                throw std::ios_base::failure("empty extended DMN voting-key state");
            }
        }
    }

    void ResetOperatorFields()
    {
        nVersion = CProUpServTx::LEGACY_BLS_VERSION;
        pubKeyOperator.SetNull();
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

    /** SYSCOIN: Fixed field encoding for branch-local deterministic-state diagnostics. */
    template <typename Stream>
    void SerializePQStateDiagnosticV1(Stream& stream) const
    {
        stream << static_cast<int32_t>(nVersion)
               << static_cast<int32_t>(nRegisteredHeight)
               << static_cast<int32_t>(nLastPaidHeight)
               << static_cast<int32_t>(nPoSePenalty)
               << static_cast<int32_t>(nPoSeRevivedHeight)
               << static_cast<int32_t>(nPoSeBanHeight)
               << nRevocationReason << confirmedHash << confirmedHashWithProRegTxHash
               << keyIDOwner;
        pubKeyOperator.Serialize(stream);
        stream << keyIDVoting << addr << scriptPayout << scriptOperatorPayout
               << static_cast<int32_t>(nCollateralHeight) << vchNEVMAddress;
        llmq::pq::SerializeVotingKeyCommitment(stream, pqVotingKey);
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
        Field_pqVotingKey = 0x20000,
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
    DMN_STATE_DIFF_LINE(vchNEVMAddress)                \
    DMN_STATE_DIFF_LINE(pqVotingKey)

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
        bool read_pubkey{false};
        READWRITE(VARINT(obj.fields));
#define DMN_STATE_DIFF_LINE(f) \
        if (strcmp(#f, "pubKeyOperator") == 0 && (obj.fields & Field_pubKeyOperator)) {\
            SER_READ(obj, read_pubkey = true); \
            READWRITE(obj.state.pubKeyOperator); \
        } else if (obj.fields & Field_##f) READWRITE(obj.state.f);

        DMN_STATE_DIFF_ALL_FIELDS
#undef DMN_STATE_DIFF_LINE
        if (read_pubkey) {
            SER_READ(obj, obj.fields |= Field_nVersion);
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
