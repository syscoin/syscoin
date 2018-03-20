#ifndef NAMEDB_H
#define NAMEDB_H

#include "bitcoinrpc.h"
#include "leveldb.h"

class CAliasIndex {
public:
    uint256 txHash;
    int64 nHeight;
    COutPoint txPrevOut;
    std::vector<unsigned char> vValue;

    CAliasIndex() { 
        SetNull();
    }

    CAliasIndex(uint256 txHashIn, COutPoint txPrevOutIn, uint64 nHeightIn, std::vector<unsigned char> vValueIn) {
        txHash = txHashIn;
        txPrevOut = txPrevOutIn;
        nHeight = nHeightIn;
        vValue = vValueIn;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(txHash);
        READWRITE(VARINT(nHeight));
        READWRITE(txPrevOut);
    	READWRITE(vValue);
    )

    friend bool operator==(const CAliasIndex &a, const CAliasIndex &b) {
        return (a.nHeight == b.nHeight && a.txHash == b.txHash);
    }

    friend bool operator!=(const CAliasIndex &a, const CAliasIndex &b) {
        return !(a == b);
    }
    
    void SetNull() { txHash.SetHex("0x0"); nHeight = -1; vValue.clear(); }
    bool IsNull() const { return (nHeight == -1 && txHash == 0); }
};

class CAliasFee {
public:
	uint64 nBlockTime;
	uint64 nHeight;
	uint256 hash;
	uint64 nValue;

	CAliasFee() {
        SetNull();
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(nBlockTime);
        READWRITE(nHeight);
        READWRITE(hash);
    	READWRITE(nValue);
    )

    void SetNull() { hash = 0; nHeight = 0; nValue = 0; nBlockTime = 0; }
    bool IsNull() const { return (nHeight == 0 && hash == 0 && nValue == 0 && nBlockTime == 0); }

	CAliasFee(uint256 s, uint64 t, uint64 h, uint64 v) {
		hash = s;
		nBlockTime = t;
		nHeight = h;
		nValue = v;
	}
	bool operator()(uint256 s, uint64 t, uint64 h, uint64 v) {
		hash = s;
		nBlockTime = t;
		nHeight = h;
		nValue = v;
		return true;
	}
    friend bool operator==(const CAliasFee &a, const CAliasFee &b) {
        return (a.hash == b.hash && a.nBlockTime == b.nBlockTime && a.nHeight == b.nHeight && a.nValue == b.nValue);
    }

    friend bool operator!=(const CAliasFee &a, const CAliasFee &b) {
        return !(a == b);
    }
};
extern std::list<CAliasFee> lstAliasFees;

class CAliasDB : public CLevelDB {
public:
    CAliasDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "aliases", nCacheSize, fMemory, fWipe) {
    }

	bool WriteName(const std::vector<unsigned char>& name, std::vector<CAliasIndex>& vtxPos) {
		return Write(make_pair(std::string("namei"), name), vtxPos);
	}

	bool EraseName(const std::vector<unsigned char>& name) {
	    return Erase(make_pair(std::string("namei"), name));
	}
	bool ReadAlias(const std::vector<unsigned char>& name, std::vector<CAliasIndex>& vtxPos) {
		return Read(make_pair(std::string("namei"), name), vtxPos);
	}
	bool ExistsAlias(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namei"), name));
	}

	bool WriteAliasTxFees(std::vector<CAliasFee>& vtxPos) {
		return Write(std::string("nametxf"), vtxPos);
	}
	bool ReadAliasTxFees(std::vector<CAliasFee>& vtxPos) {
		return Read(std::string("nametxf"), vtxPos);
	}

    bool WriteAliasIndex(std::vector<std::vector<unsigned char> >& vtxIndex) {
        return Write(std::string("namendx"), vtxIndex);
    }
    bool ReadAliasIndex(std::vector<std::vector<unsigned char> >& vtxIndex) {
        return Read(std::string("namendx"), vtxIndex);
    }

    bool ScanNames(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CAliasIndex> >& nameScan);

    bool ReconstructNameIndex(CBlockIndex *pindexRescan);
};



extern std::map<std::vector<unsigned char>, uint256> mapMyAliases;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapAliasesPending;

std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const json_spirit::Value& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const json_spirit::Value& value);

static const int SYSCOIN_TX_VERSION = 0x7400;
static const int64 MIN_AMOUNT = COIN;
static const unsigned int MAX_NAME_LENGTH = 255;
static const unsigned int MAX_VALUE_LENGTH = 1023;
static const unsigned int MIN_ACTIVATE_DEPTH = 120;
static const unsigned int MIN_ACTIVATE_DEPTH_CAKENET = 1;

bool CheckAliasInputs(
    CBlockIndex *pindex, const CTransaction &tx, CValidationState &state,
	CCoinsViewCache &inputs, std::map<std::vector<unsigned char>,uint256> &mapTestPool, 
    bool fBlock, bool fMiner, bool fJustCheck);
bool ExtractAliasAddress(const CScript& script, std::string& address);
bool IsAliasMine(const CTransaction& tx);
bool IsAliasMine2(const CTransaction& tx);
void RemoveAliasTxnFromMemoryPool(const CTransaction& tx);
bool IsAliasMine(const CTransaction& tx, const CTxOut& txout, bool ignore_aliasnew = false);
bool IsAliasOp(int op);

int GetNameTxPosHeight(const CAliasIndex& txPos);
int GetNameTxPosHeight(const CDiskTxPos& txPos);
int GetNameTxPosHeight2(const CDiskTxPos& txPos, int nHeight);

bool GetTxOfAlias(CAliasDB& dbName, const std::vector<unsigned char> &vchName, CTransaction& tx);
int IndexOfNameOutput(const CTransaction& tx);
bool GetValueOfNameTxHash(const uint256& txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
bool GetAliasOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool GetValueOfAliasTx(const CTransaction& tx, std::vector<unsigned char>& value);
bool DecodeAliasTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool GetValueOfAliasTx(const CCoins& tx, std::vector<unsigned char>& value);
bool DecodeAliasTx(const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeAliasScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool GetAliasAddress(const CTransaction& tx, std::string& strAddress);
bool GetAliasAddress(const CDiskTxPos& txPos, std::string& strAddress);
extern void GetAliasValue(const std::string& strName, std::string& strAddress);
std::string SendMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee, const std::string& txData = "");
bool CreateTransactionWithInputTx(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const std::string& txData = "");
int64 GetAliasNetworkFee(int nType, int nHeight);
uint64 GetAliasFeeSubsidy(const unsigned int nTime);
int64 GetAliasNetFee(const CTransaction& tx);
bool InsertAliasFee(CBlockIndex *pindex, uint256 hash, uint64 nValue);
std::string aliasFromOp(int op);
bool IsAliasOp(int op);
int GetAliasDisplayExpirationDepth(int nHeight);
void UnspendInputs(CWalletTx& wtx);
bool RemoveAliasFee(CAliasFee &txnVal);

#endif // NAMEDB_H
