// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_PRIMITIVES_TRANSACTION_H
#define SYSCOIN_PRIMITIVES_TRANSACTION_H

#include <consensus/amount.h>
#include <prevector.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <consensus/consensus.h>
#include <saltedhasher.h>
// SYSCOIN
class TxValidationState;
class CHashWriter;
class UniValue;

/**
 * This saves us from making many heap allocations when serializing
 * and deserializing compressed scripts.
 *
 * This prevector size is determined by the largest .resize() in the
 * CompressScript function. The largest compressed script format is a
 * compressed public key, which is 33 bytes.
 */
using CompressedScript = prevector<33, unsigned char>;
/**
 * A flag that is ORed into the protocol version to designate that a transaction
 * should be (un)serialized without witness data.
 * Make sure that this does not collide with any of the values in `version.h`
 * or with `ADDRV2_FORMAT`.
 */
static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;
// SYSCOIN
static const int SERIALIZE_TRANSACTION_PODA = 0x04000000;
static const float NEVM_DATA_SCALE_FACTOR = 0.01;


const int SYSCOIN_TX_VERSION_MN_REGISTER = 80;
const int SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE = 81;
const int SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR = 82;
const int SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE = 83;
const int SYSCOIN_TX_VERSION_MN_QUORUM_COMMITMENT = 85;

const int SYSCOIN_TX_VERSION_NEVM_DATA_SHA3 = 137;
const int SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN = 138;
const int SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION = 139;
const int SYSCOIN_TX_VERSION_ALLOCATION_MINT = 140;
const int SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM = 141;
const int SYSCOIN_TX_VERSION_ALLOCATION_SEND = 142;

const int SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN_LEGACY = 0x7400;
const int SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN_LEGACY1 = 128;
const int MAX_MEMO = 256;
const int MAX_NEVM_DATA_BLOB = 2097152; // 2MB
const int MAX_DATA_BLOBS = 32;
const int MAX_NEVM_DATA_BLOCK = MAX_NEVM_DATA_BLOB * MAX_DATA_BLOBS; // 64MB
const int NEVM_DATA_EXPIRE_TIME = 21600; // 6 hour
const int NEVM_DATA_ENFORCE_TIME_HAVE_DATA = 7200; // 2 hour
const int NEVM_DATA_ENFORCE_TIME_NOT_HAVE_DATA = NEVM_DATA_ENFORCE_TIME_HAVE_DATA*4; // 8 hour
enum {
	ZDAG_NOT_FOUND = -1,
	ZDAG_STATUS_OK = 0,
	ZDAG_WARNING_RBF,
    ZDAG_WARNING_NOT_ZDAG_TX,
    ZDAG_WARNING_SIZE_OVER_POLICY,
	ZDAG_MAJOR_CONFLICT
};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const uint256& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        int cmp = a.hash.Compare(b.hash);
        return cmp < 0 || (cmp == 0 && a.n < b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    // SYSCOIN
    std::string ToStringShort() const;
};
// SYSCOIN
static CScript emptyScript;
/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static const uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }
    // SYSCOIN
    explicit CTxIn(const COutPoint &prevoutIn, const CScript &scriptSigIn=emptyScript, uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(const uint256 &hashPrevTx, uint32_t nOut, const CScript &scriptSigIn=emptyScript, uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s) {
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);
    s >> tx.nVersion;
    s.SetTxVersion(tx.nVersion);
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
    // SYSCOIN
    tx.LoadAssets();
}
template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s) {
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);
    s.SetTxVersion(tx.nVersion);
    s << tx.nVersion;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}
// SYSCOIN

bool CompressScript(const CScript& script, CompressedScript &out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript &out);

/**
 * Compress amount.
 *
 * nAmount is of type uint64_t and thus cannot be negative. If you're passing in
 * a CAmount (int64_t), make sure to properly handle the case where the amount
 * is negative before calling CompressAmount(...).
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(uint64_t nAmount);

uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression
{
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template<typename Stream>
    void Ser(Stream &s, const CScript& script) {
        CompressedScript compr;
        if (CompressScript(script, compr)) {
            s << Span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << Span{script};
    }

    template<typename Stream>
    void Unser(Stream &s, CScript& script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
            s >> Span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> Span{script};
        }
    }
};

struct AmountCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(CompressAmount(val));
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

struct AssetCoinInfoCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(val.nAsset);
        if(val.nAsset > 0) {
            s << VARINT(CompressAmount(val.nValue));
        }
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        s >> VARINT(val.nAsset);
        if(val.nAsset > 0) {
            uint64_t v;
            s >> VARINT(v);
            val.nValue = DecompressAmount(v);
        }
    }
};

class CAssetCoinInfo {
public:
	uint64_t nAsset;
	CAmount nValue;
	CAssetCoinInfo() {
		SetNull();
        nValue = 0;
	}
    CAssetCoinInfo(const uint64_t &nAssetIn, const CAmount& nValueIn): nAsset(nAssetIn), nValue(nValueIn) {}
 
    friend bool operator==(const CAssetCoinInfo& a, const CAssetCoinInfo& b)
    {
        return (a.nAsset == b.nAsset &&
                a.nValue == b.nValue);
    }

    SERIALIZE_METHODS(CAssetCoinInfo, obj) {
        READWRITE(Using<AssetCoinInfoCompression>(obj));
    }

	inline void SetNull() { nAsset = 0;}
    inline bool IsNull() const { return nAsset == 0;}
};
class CTransaction;
bool IsSyscoinNEVMDataTx(const int &nVersion);
class CNEVMData {
public:
    std::vector<uint8_t> vchVersionHash;
    uint256 txid;
    std::shared_ptr<const std::vector<uint8_t>> vchNEVMData;
    CNEVMData() {
        SetNull();
    }
    explicit CNEVMData(const CScript &script);
    explicit CNEVMData(const CTransaction &tx, const int nVersion);
    explicit CNEVMData(const CTransaction &tx);
    inline void ClearData() {
        vchVersionHash.clear();
        if(vchNEVMData) {
            vchNEVMData.reset();
        }
    }
    template<typename Stream>
    void Ser(Stream &s) {
        s << vchVersionHash;
    }

    template<typename Stream>
    void Unser(Stream &s) {
        s >> vchVersionHash;
        const bool fAllowPoDA = (s.GetVersion() & SERIALIZE_TRANSACTION_PODA);
        if(fAllowPoDA) {
            std::vector<uint8_t> vchNEVMDataIn;
            s >> vchNEVMDataIn;
            vchNEVMData = std::make_shared<const std::vector<uint8_t>>(vchNEVMDataIn);
        }
    }
    inline void SetNull() { ClearData(); }
    inline bool IsNull() const { return (vchVersionHash.empty()); }
    bool UnserializeFromTx(const CTransaction &tx, const int nVersion);
    bool UnserializeFromScript(const CScript& script);
    int UnserializeFromData(const std::vector<unsigned char> &vchData, const int nVersion);
    void SerializeData(std::vector<unsigned char>& vchData);
};
class MapPoDAPayloadMeta {
    public:
        uint256 txid;
        uint32_t nSize{0};
        int64_t nMedianTime{0};
        std::shared_ptr<const std::vector<uint8_t>> vchNEVMData;
        MapPoDAPayloadMeta(){}
        MapPoDAPayloadMeta(const uint256 &txidIn, const uint32_t &nSizeIn, const int64_t &nMedianTimeIn): txid(txidIn), nSize(nSizeIn), nMedianTime(nMedianTimeIn) {}
        explicit MapPoDAPayloadMeta(const CNEVMData &data, const int64_t &nMedianTimeIn): txid(data.txid), nMedianTime(nMedianTimeIn) {
            if(data.vchNEVMData) {
                nSize = data.vchNEVMData->size();
                vchNEVMData = data.vchNEVMData;
            }
        }
        SERIALIZE_METHODS(MapPoDAPayloadMeta, obj) {
            READWRITE(obj.txid, obj.nSize, obj.nMedianTime);
        }
    };
/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;
    // SYSCOIN
    CAssetCoinInfo assetInfo;
    std::vector<uint8_t> vchNEVMData;
    CTxOut()
    {
        SetNull();
    }
    // SYSCOIN
    CTxOut(const CAmount& nValueIn, const CScript &scriptPubKeyIn);
    CTxOut(const CAmount& nValueIn, const CScript &scriptPubKeyIn, const CAssetCoinInfo &assetInfoIn) : nValue(nValueIn), scriptPubKey(scriptPubKeyIn), assetInfo(assetInfoIn) {}
    CTxOut(const CAmount& nValueIn, const CScript &scriptPubKeyIn, const std::vector<uint8_t> &vchNEVMDataIn)  : nValue(nValueIn), scriptPubKey(scriptPubKeyIn), vchNEVMData(vchNEVMDataIn) {}
    SERIALIZE_METHODS(CTxOut, obj)
    {
        READWRITE(obj.nValue, obj.scriptPubKey);
        if (obj.scriptPubKey.IsUnspendable() && IsSyscoinNEVMDataTx(s.GetTxVersion())) {
            if (!(s.GetType() & SER_NO_PODA) && s.GetType() & SER_NETWORK) {
                READWRITE(obj.vchNEVMData);
            } else if(s.GetType() == SER_SIZE) {
                s.seek(obj.vchNEVMData.size() * NEVM_DATA_SCALE_FACTOR);
            }
        }
    }

    void SetNull()
    {
        assetInfo.SetNull();
        nValue = -1;
        scriptPubKey.clear();
        vchNEVMData.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey &&
                a.assetInfo    == b.assetInfo &&
                a.vchNEVMData  == b.vchNEVMData);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }
    std::string ToString() const;
};


/** wrapper for CTxOut that provides a more compact serialization */
struct TxOutCompression
{
    FORMATTER_METHODS(CTxOut, obj) { READWRITE(Using<AmountCompression>(obj.nValue), Using<ScriptCompression>(obj.scriptPubKey), Using<AssetCoinInfoCompression>(obj.assetInfo)); }
};

class CAssetOutValue {
public:
    uint32_t n;
    CAmount nValue;
    SERIALIZE_METHODS(CAssetOutValue, obj) {
        READWRITE(COMPACTSIZE(obj.n), Using<AmountCompression>(obj.nValue));
    }
    CAssetOutValue(const uint32_t &nIn, const uint64_t& nAmountIn): n(nIn), nValue(nAmountIn) {}
    CAssetOutValue() {
        SetNull();
    }
    inline void SetNull() {
        nValue = 0;
        n = 0;
    }
    inline friend bool operator==(const CAssetOutValue &a, const CAssetOutValue &b) {
		return (a.n == b.n && a.nValue == b.nValue);
	}
    inline friend bool operator!=(const CAssetOutValue &a, const CAssetOutValue &b) {
		return !(a == b);
	}
};
class CAssetOut {
public:
    uint64_t key;
    std::vector<CAssetOutValue> values;
    
    SERIALIZE_METHODS(CAssetOut, obj) {
        READWRITE(VARINT(obj.key), obj.values);
    }

    CAssetOut(const uint64_t &keyIn, const std::vector<CAssetOutValue>& valuesIn): key(keyIn), values(valuesIn) {}
    CAssetOut() {
		SetNull();
	}
    inline void SetNull() {
        key = 0;
        values.clear();
    }
    inline friend bool operator==(const CAssetOut &a, const CAssetOut &b) {
		return (a.key == b.key && a.values == b.values);
	}
    inline friend bool operator!=(const CAssetOut &a, const CAssetOut &b) {
		return !(a == b);
	}
};

template<typename TxType>
inline CAmount CalculateOutputValue(const TxType& tx)
{
    return std::accumulate(tx.vout.cbegin(), tx.vout.cend(), CAmount{0}, [](CAmount sum, const auto& txout) { return sum + txout.nValue; });
}


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const int32_t nVersion;
    const uint32_t nLockTime;

private:
    /** Memory only. */
    const uint256 hash;
    const uint256 m_witness_hash;

    uint256 ComputeHash() const;
    uint256 ComputeWitnessHash() const;

public:
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction& tx);
    explicit CTransaction(CMutableTransaction&& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }
    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const { return hash; }
    const uint256& GetWitnessHash() const { return m_witness_hash; };

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // SYSCOIN
    CAmount GetAssetValueOut(const std::vector<CAssetOutValue> &vecVout) const;
    bool GetAssetValueOut(CAssetsMap &mapAssetOut, std::string& err) const;
    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
    // SYSCOIN
    bool HasAssets() const;
    bool IsNEVMData() const;
    bool IsMnTx() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int32_t nVersion;
    uint32_t nLockTime;

    explicit CMutableTransaction();
    explicit CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
    // SYSCOIN
    bool HasAssets() const;
    bool IsNEVMData() const;
    bool IsMnTx() const;
    void LoadAssets();
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

class CAssetAllocation {
public:
    std::vector<CAssetOut> voutAssets;
    SERIALIZE_METHODS(CAssetAllocation, obj) {
        READWRITE(obj.voutAssets);
    }

	CAssetAllocation() {
		SetNull();
	}
    explicit CAssetAllocation(const CTransaction &tx);
    explicit CAssetAllocation(const CMutableTransaction &mtx);

	inline friend bool operator==(const CAssetAllocation &a, const CAssetAllocation &b) {
		return (a.voutAssets == b.voutAssets
			);
	}
    CAssetAllocation(const CAssetAllocation&) = delete;
    CAssetAllocation(CAssetAllocation && other) = default;
    CAssetAllocation& operator=( CAssetAllocation& a ) = delete;
	CAssetAllocation& operator=( CAssetAllocation&& a ) = default;
 
	inline friend bool operator!=(const CAssetAllocation &a, const CAssetAllocation &b) {
		return !(a == b);
	}
	inline void SetNull() { voutAssets.clear();}
    inline bool IsNull() const { return voutAssets.empty();}
    bool UnserializeFromTx(const CTransaction &tx);
    bool UnserializeFromTx(const CMutableTransaction &mtx);
	int UnserializeFromData(const std::vector<unsigned char> &vchData);
	void SerializeData(std::vector<unsigned char>& vchData);
};

class CMintSyscoin: public CAssetAllocation {
public:
    // where in vchTxParentNodes the vchTxValue can be found as an offset
    uint16_t posTx;
    std::vector<unsigned char> vchTxParentNodes;
    uint256 nTxRoot;
    std::vector<unsigned char> vchTxPath;
    // where in vchReceiptParentNodes the vchReceiptValue can be found as an offset
    uint16_t posReceipt;
    std::vector<unsigned char> vchReceiptParentNodes;
    uint256 nReceiptRoot;
    uint256 nTxHash;
    uint256 nBlockHash;

    CMintSyscoin() {
        SetNull();
    }
    explicit CMintSyscoin(const CTransaction &tx);
    explicit CMintSyscoin(const CMutableTransaction &mtx);

    SERIALIZE_METHODS(CMintSyscoin, obj) {
        READWRITE(AsBase<CAssetAllocation>(obj));
        READWRITE(obj.nTxHash, obj.nBlockHash, obj.posTx,
        obj.vchTxParentNodes, obj.vchTxPath, obj.posReceipt,
        obj.vchReceiptParentNodes, obj.nTxRoot, obj.nReceiptRoot);
    }

    inline void SetNull() { voutAssets.clear(); posTx = 0; nTxRoot.SetNull(); nReceiptRoot.SetNull(); vchTxParentNodes.clear(); vchTxPath.clear(); posReceipt = 0; vchReceiptParentNodes.clear(); nTxHash.SetNull(); nBlockHash.SetNull();  }
    inline bool IsNull() const { return (voutAssets.empty() && posTx == 0 && posReceipt == 0); }
    int UnserializeFromData(const std::vector<unsigned char> &vchData);
    bool UnserializeFromTx(const CTransaction &tx);
    bool UnserializeFromTx(const CMutableTransaction &mtx);
    void SerializeData(std::vector<unsigned char>& vchData);
};

class CBurnSyscoin: public CAssetAllocation {
public:
    std::vector<unsigned char> vchNEVMAddress;
    CBurnSyscoin() {
        SetNull();
    }
    explicit CBurnSyscoin(const CTransaction &tx);
    explicit CBurnSyscoin(const CMutableTransaction &mtx);

    SERIALIZE_METHODS(CBurnSyscoin, obj) {
        
        READWRITE(AsBase<CAssetAllocation>(obj));
        READWRITE(obj.vchNEVMAddress);
    }

    inline void SetNull() { voutAssets.clear(); vchNEVMAddress.clear();  }
    inline bool IsNull() const { return (vchNEVMAddress.empty() && voutAssets.empty()); }
    int UnserializeFromData(const std::vector<unsigned char> &vchData);
    bool UnserializeFromTx(const CTransaction &tx);
    bool UnserializeFromTx(const CMutableTransaction &mtx);
    void SerializeData(std::vector<unsigned char>& vchData);
};
class NEVMTxRoot {
    public:
    uint256 nTxRoot;
    uint256 nReceiptRoot;
    SERIALIZE_METHODS(NEVMTxRoot, obj)
    {
        READWRITE(obj.nTxRoot, obj.nReceiptRoot);
    }
};
class CNEVMHeader {
    public:
    uint256 nBlockHash;
    uint256 nTxRoot;
    uint256 nReceiptRoot;
    CNEVMHeader(){
        SetNull();
    };
    CNEVMHeader(CNEVMHeader&& evmBlock){
        nBlockHash = std::move(evmBlock.nBlockHash);
        nTxRoot = std::move(evmBlock.nTxRoot);
        nReceiptRoot = std::move(evmBlock.nReceiptRoot);
    }
    SERIALIZE_METHODS(CNEVMHeader, obj)
    {
        READWRITE(obj.nBlockHash, obj.nTxRoot, obj.nReceiptRoot);
    }
    inline void SetNull() { nBlockHash.SetNull(); nTxRoot.SetNull(); nReceiptRoot.SetNull(); }
};

class CNEVMBlock: public CNEVMHeader {
    public:
    std::vector<unsigned char>  vchNEVMBlockData;
    SERIALIZE_METHODS(CNEVMBlock, obj)
    {
        READWRITE(AsBase<CNEVMHeader>(obj), obj.vchNEVMBlockData);
    }
};

bool IsSyscoinTx(const int &nVersion);
bool IsMasternodeTx(const int &nVersion);
bool IsAssetAllocationTx(const int &nVersion);
bool IsZdagTx(const int &nVersion);
bool IsSyscoinMintTx(const int &nVersion);
int GetSyscoinDataOutput(const CTransaction& tx);
int GetSyscoinDataOutput(const CMutableTransaction& mtx);
bool GetSyscoinData(const CTransaction &tx, std::vector<unsigned char> &vchData, int& nOut);
bool GetSyscoinData(const CMutableTransaction &mtx, std::vector<unsigned char> &vchData, int& nOut);
bool GetSyscoinData(const CScript &scriptPubKey, std::vector<unsigned char> &vchData);
typedef std::vector<std::vector<uint8_t> > NEVMDataVec;
typedef std::unordered_map<uint256, NEVMTxRoot, StaticSaltedHasher> NEVMTxRootMap;
typedef std::map<std::vector<uint8_t>, MapPoDAPayloadMeta > PoDAMAPMemory;
/** A generic txid reference (txid or wtxid). */
// SYSCOIN
class GenTxid
{
    bool m_is_wtxid;
    uint256 m_hash;
    uint32_t m_type;
    GenTxid(bool is_wtxid, const uint256& hash, const uint32_t& type) : m_is_wtxid(is_wtxid), m_hash(hash), m_type(type) {}
    GenTxid(bool is_wtxid, const uint256& hash) : m_is_wtxid(is_wtxid), m_hash(hash), m_type(0) {}

public:
    static GenTxid Txid(const uint256& hash) { return GenTxid{false, hash}; }
    static GenTxid Wtxid(const uint256& hash) { return GenTxid{true, hash}; }
    // SYSCOIN
    static GenTxid Txid(const uint256& hash, const uint32_t& type) { return GenTxid{false, hash, type}; }
    static GenTxid Wtxid(const uint256& hash, const uint32_t& type) { return GenTxid{true, hash, type}; }
    bool IsWtxid() const { return m_is_wtxid; }
    const uint256& GetHash() const { return m_hash; }
    const uint32_t& GetType() const { return m_type; }
    friend bool operator==(const GenTxid& a, const GenTxid& b) { return a.m_is_wtxid == b.m_is_wtxid && a.m_hash == b.m_hash; }
    friend bool operator<(const GenTxid& a, const GenTxid& b) { return std::tie(a.m_is_wtxid, a.m_hash) < std::tie(b.m_is_wtxid, b.m_hash); }
};
extern bool fTestNet;
#endif // SYSCOIN_PRIMITIVES_TRANSACTION_H
