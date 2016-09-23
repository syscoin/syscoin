#ifndef ALIAS_H
#define ALIAS_H

#include "rpcserver.h"
#include "dbwrapper.h"
#include "script/script.h"
#include "serialize.h"
#include "consensus/params.h"
#include "sync.h"
class CWalletTx;
class CTransaction;
class CTxOut;
class COutPoint;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;
struct CRecipient;
class CSyscoinAddress;
static const unsigned int MAX_GUID_LENGTH = 70;
static const unsigned int MAX_NAME_LENGTH = 255;
static const unsigned int MAX_VALUE_LENGTH = 1023;
static const unsigned int MAX_ID_LENGTH = 20;
static const unsigned int MAX_ENCRYPTED_VALUE_LENGTH = 1108;

static const unsigned int SAFETY_LEVEL1 = 1;
static const unsigned int SAFETY_LEVEL2 = 2;
static const unsigned int SYSCOIN_FORK1 = 50000;


bool IsSys21Fork(const uint64_t& nHeight);
class CAliasIndex {
public:
	 std::vector<unsigned char> vchAlias;
	 std::vector<unsigned char> vchGUID;
    uint256 txHash;
    int64_t nHeight;
    std::vector<unsigned char> vchPublicValue;
	std::vector<unsigned char> vchPrivateValue;
	std::vector<unsigned char> vchPrivateKey;
	std::vector<unsigned char> vchPubKey;
	unsigned char safetyLevel;
	unsigned char nRenewal;
	int nRatingAsBuyer;
	int nRatingCountAsBuyer;
	int nRatingAsSeller;
	int nRatingCountAsSeller;
	int nRatingAsArbiter;
	int nRatingCountAsArbiter;
	bool safeSearch;
    CAliasIndex() { 
        SetNull();
    }
    CAliasIndex(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
	void ClearAlias()
	{
		vchPublicValue.clear();
		vchPrivateKey.clear();
		vchPrivateValue.clear();
		vchGUID.clear();
	}
    bool GetAliasFromList(std::vector<CAliasIndex> &aliasList) {
        if(aliasList.size() == 0) return false;
		CAliasIndex myAlias = aliasList.front();
		if(nHeight <= 0)
		{
			*this = myAlias;
			return true;
		}
			
		// find the closest alias without going over in height, assuming aliasList orders entries by nHeight ascending
        for(std::vector<CAliasIndex>::reverse_iterator it = aliasList.rbegin(); it != aliasList.rend(); ++it) {
            const CAliasIndex &a = *it;
			// skip if this height is greater than our alias height
			if(a.nHeight > nHeight)
				continue;
            myAlias = a;
			break;
        }
        *this = myAlias;
        return true;
    }
	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {        
		READWRITE(txHash);
		READWRITE(VARINT(nHeight));
		READWRITE(vchPublicValue);
		READWRITE(vchPrivateValue);
		READWRITE(vchPrivateKey);
		READWRITE(vchPubKey);
		READWRITE(vchAlias);
		READWRITE(vchGUID);
		READWRITE(safetyLevel);
		READWRITE(nRenewal);
		READWRITE(safeSearch);
		READWRITE(VARINT(nRatingAsBuyer));
		READWRITE(VARINT(nRatingCountAsBuyer));
		READWRITE(VARINT(nRatingAsSeller));
		READWRITE(VARINT(nRatingCountAsSeller));
		READWRITE(VARINT(nRatingAsArbiter));
		READWRITE(VARINT(nRatingCountAsArbiter));
	}
    friend bool operator==(const CAliasIndex &a, const CAliasIndex &b) {
		return (a.vchPrivateKey == b.vchPrivateKey && a.nRenewal == b.nRenewal && a.vchGUID == b.vchGUID && a.vchAlias == b.vchAlias && a.nRatingCountAsArbiter == b.nRatingCountAsArbiter && a.nRatingAsArbiter == b.nRatingAsArbiter && a.nRatingCountAsSeller == b.nRatingCountAsSeller && a.nRatingAsSeller == b.nRatingAsSeller && a.nRatingCountAsBuyer == b.nRatingCountAsBuyer && a.nRatingAsBuyer == b.nRatingAsBuyer && a.safetyLevel == b.safetyLevel && a.safeSearch == b.safeSearch && a.nHeight == b.nHeight && a.txHash == b.txHash && a.vchPublicValue == b.vchPublicValue && a.vchPrivateValue == b.vchPrivateValue && a.vchPubKey == b.vchPubKey);
    }

    friend bool operator!=(const CAliasIndex &a, const CAliasIndex &b) {
        return !(a == b);
    }
    CAliasIndex operator=(const CAliasIndex &b) {
		vchGUID = b.vchGUID;
		nRenewal = b.nRenewal;
		vchAlias = b.vchAlias;
        txHash = b.txHash;
        nHeight = b.nHeight;
        vchPublicValue = b.vchPublicValue;
        vchPrivateValue = b.vchPrivateValue;
		vchPrivateKey = b.vchPrivateKey;
        vchPubKey = b.vchPubKey;
		safetyLevel = b.safetyLevel;
		safeSearch = b.safeSearch;
		nRatingAsBuyer = b.nRatingAsBuyer;
		nRatingCountAsBuyer = b.nRatingCountAsBuyer;
		nRatingAsSeller = b.nRatingAsSeller;
		nRatingCountAsSeller = b.nRatingCountAsSeller;
		nRatingAsArbiter = b.nRatingAsArbiter;
		nRatingCountAsArbiter = b.nRatingCountAsArbiter;
        return *this;
    }   
    void SetNull() {vchPrivateKey.clear(); nRenewal = 0; vchGUID.clear(); vchAlias.clear(); nRatingCountAsBuyer = 0; nRatingAsBuyer = 0; nRatingCountAsSeller = 0; nRatingAsSeller = 0; nRatingCountAsArbiter = 0; nRatingAsArbiter = 0; safetyLevel = 0; safeSearch = true; txHash.SetNull(); nHeight = 0; vchPublicValue.clear(); vchPrivateValue.clear(); vchPubKey.clear(); }
    bool IsNull() const { return (vchPrivateKey.empty() && nRenewal == 0 && vchGUID.empty() && vchAlias.empty() && nRatingCountAsBuyer == 0 && nRatingAsBuyer == 0 && nRatingCountAsArbiter == 0 && nRatingAsArbiter == 0 && nRatingCountAsSeller == 0 && nRatingAsSeller == 0 && safetyLevel == 0 && safeSearch && nHeight == 0 && txHash.IsNull() && vchPublicValue.empty() && vchPrivateValue.empty() && vchPubKey.empty()); }
	bool UnserializeFromTx(const CTransaction &tx);
	bool UnserializeFromData(const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash);
	const std::vector<unsigned char> Serialize();
};

class CAliasDB : public CDBWrapper {
public:
    CAliasDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "aliases", nCacheSize, fMemory, fWipe) {
    }

	bool WriteAlias(const std::vector<unsigned char>& name, const std::vector<unsigned char>& address, std::vector<CAliasIndex>& vtxPos) {
		return Write(make_pair(std::string("namei"), name), vtxPos) && Write(make_pair(std::string("namea"), address), name);
	}

	bool EraseAlias(const std::vector<unsigned char>& name) {
	    return Erase(make_pair(std::string("namei"), name));
	}
	bool ReadAlias(const std::vector<unsigned char>& name, std::vector<CAliasIndex>& vtxPos) {
		return Read(make_pair(std::string("namei"), name), vtxPos);
	}
	bool ReadAddress(const std::vector<unsigned char>& address, std::vector<unsigned char>& name) {
		return Read(make_pair(std::string("namea"), address), name);
	}
	bool ExistsAlias(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namei"), name));
	}
	bool ExistsAddress(const std::vector<unsigned char>& address) {
	    return Exists(make_pair(std::string("namea"), address));
	}
    bool ScanNames(
		const std::vector<unsigned char>& vchAlias, const std::string& strRegExp, bool safeSearch,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CAliasIndex> >& nameScan);

};

class COfferDB;
class CCertDB;
class CEscrowDB;
class CMessageDB;
extern CAliasDB *paliasdb;
extern COfferDB *pofferdb;
extern CCertDB *pcertdb;
extern CEscrowDB *pescrowdb;
extern CMessageDB *pmessagedb;



std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const UniValue& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const UniValue& value);
int GetSyscoinTxVersion();
const int SYSCOIN_TX_VERSION = 0x7400;
bool IsValidAliasName(const std::vector<unsigned char> &vchAlias);
bool CheckAliasInputs(const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, std::string &errorMessage, const CBlock* block = NULL, bool dontaddtodb=false);
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient);
void CreateFeeRecipient(CScript& scriptPubKey, const std::vector<unsigned char>& data, CRecipient& recipient);
bool IsSyscoinTxMine(const CTransaction& tx,const std::string &type);
bool IsAliasOp(int op);
bool getCategoryList(std::vector<std::string>& categoryList);
bool getBanList(const std::vector<unsigned char> &banData, std::map<std::string, unsigned char> &banAliasList,  std::map<std::string, unsigned char>& banCertList,  std::map<std::string, unsigned char>& banOfferList);
bool GetTxOfAlias(const std::vector<unsigned char> &vchAlias, CAliasIndex& alias, CTransaction& tx, bool skipExpiresCheck=false);
bool GetTxAndVtxOfAlias(const std::vector<unsigned char> &vchAlias, CAliasIndex& alias, CTransaction& tx, std::vector<CAliasIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck=false);
int IndexOfAliasOutput(const CTransaction& tx);
bool GetAliasOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool DecodeAliasTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseAliasTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseSyscoinTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAliasScript(const CScript& script, int& op,
		std::vector<std::vector<unsigned char> > &vvch);
void GetAddressFromAlias(const std::string& strAlias, std::string& strAddress, unsigned char& safetyLevel, bool& safeSearch, int64_t& nHeight);
void GetAliasFromAddress(const std::string& strAddress, std::string& strAlias, unsigned char& safetyLevel, bool& safeSearch, int64_t& nHeight);
CAmount convertCurrencyCodeToSyscoin(const std::vector<unsigned char> &vchAliasPeg, const std::vector<unsigned char> &vchCurrencyCode, const float &nPrice, const unsigned int &nHeight, int &precision);
CAmount convertSyscoinToCurrencyCode(const std::vector<unsigned char> &vchAliasPeg, const std::vector<unsigned char> &vchCurrencyCode, const CAmount &nPrice, const unsigned int &nHeight, int &precision);
unsigned int QtyOfPendingAcceptsInMempool(const std::vector<unsigned char>& vchToFind);
std::string getCurrencyToSYSFromAlias(const std::vector<unsigned char> &vchAliasPeg, const std::vector<unsigned char> &vchCurrency, float &nFee, const unsigned int &nHeightToFind, std::vector<std::string>& rateList, int &precision);
std::string aliasFromOp(int op);
std::string GenerateSyscoinGuid();
bool IsAliasOp(int op);
int GetAliasExpirationDepth();
CScript RemoveAliasScriptPrefix(const CScript& scriptIn);
int GetSyscoinDataOutput(const CTransaction& tx);
bool IsSyscoinDataOutput(const CTxOut& out);
bool GetSyscoinData(const CTransaction &tx, std::vector<unsigned char> &vchData, std::vector<unsigned char> &vchHash, int& nOut);
bool GetSyscoinData(const CScript &scriptPubKey, std::vector<unsigned char> &vchData, std::vector<unsigned char> &vchHash);
bool IsSysServiceExpired(const uint64_t &nHeight);
bool IsInSys21Fork(CScript& scriptPubKey, uint64_t &nHeight);
bool GetSyscoinTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams);
bool IsSyscoinScript(const CScript& scriptPubKey, int &op, std::vector<std::vector<unsigned char> > &vvchArgs);
void RemoveSyscoinScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut);
bool GetPreviousInput(const COutPoint * outpoint, int &op, std::vector<std::vector<unsigned char> > &vvchArgs);
void PutToAliasList(std::vector<CAliasIndex> &aliasList, CAliasIndex& index);
#endif // ALIAS_H
