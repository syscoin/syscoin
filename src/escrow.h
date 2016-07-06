#ifndef ESCROW_H
#define ESCROW_H

#include "rpcserver.h"
#include "dbwrapper.h"
#include "script/script.h"
#include "serialize.h"
class CWalletTx;
class CTransaction;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;

bool CheckEscrowInputs(const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock *block = NULL);
bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeMyEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeEscrowScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsEscrowOp(int op);
int IndexOfEscrowOutput(const CTransaction& tx);
int IndexOfMyEscrowOutput(const CTransaction& tx);
int GetEscrowExpirationDepth();

std::string escrowFromOp(int op);
CScript RemoveEscrowScriptPrefix(const CScript& scriptIn);
extern bool IsSys21Fork(const uint64_t& nHeight);
enum EscrowUser {
    BUYER=1,
	SELLER=2,
	ARBITER=3
};
class CEscrowFeedback {
public:
	std::vector<unsigned char> vchFeedback;
	unsigned char nRating;
	unsigned char nFeedbackUser;
	uint64_t nHeight;
	
    CEscrowFeedback() {
        SetNull();
    }
    CEscrowFeedback(unsigned char nEscrowFeedbackUser) {
        SetNull();
		nFeedbackUser = nEscrowFeedbackUser;
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchFeedback);
		READWRITE(nRating);
		READWRITE(nFeedbackUser);
		READWRITE(nHeight);
	}

    friend bool operator==(const CEscrowFeedback &a, const CEscrowFeedback &b) {
        return (
        a.vchFeedback == b.vchFeedback
		&& a.nRating == b.nRating
		&& a.nFeedbackUser == b.nFeedbackUser
		&& a.nHeight == b.nHeight
        );
    }

    CEscrowFeedback operator=(const CEscrowFeedback &b) {
        vchFeedback = b.vchFeedback;
		nRating = b.nRating;
		nFeedbackUser = b.nFeedbackUser;
		nHeight = b.nHeight;
        return *this;
    }

    friend bool operator!=(const CEscrowFeedback &a, const CEscrowFeedback &b) {
        return !(a == b);
    }

    void SetNull() { nHeight = 0; nRating = 0; nFeedbackUser = 0; vchFeedback.clear();}
    bool IsNull() const { return (nHeight == 0 && nRating == 0 && nFeedbackUser == 0 && vchFeedback.empty()); }
};
struct escrowfeedbacksort {
    bool operator ()(const CEscrowFeedback& a, const CEscrowFeedback& b) {
        return a.nHeight < b.nHeight;
    }
};
class CEscrow {
public:
	std::vector<unsigned char> vchEscrow;
	std::vector<unsigned char> vchSellerKey;
	std::vector<unsigned char> vchArbiterKey;
	std::vector<unsigned char> vchRedeemScript;
	std::vector<unsigned char> vchOffer;
	std::vector<unsigned char> vchPaymentMessage;
	std::vector<unsigned char> rawTx;
	std::vector<unsigned char> vchOfferAcceptLink;
	std::vector<unsigned char> vchBuyerKey;
	std::vector<unsigned char> vchWhitelistAlias;
	CEscrowFeedback buyerFeedback;
	CEscrowFeedback sellerFeedback;
	CEscrowFeedback arbiterFeedback;
	
	
    uint256 txHash;
	uint256 escrowInputTxHash;
    uint64_t nHeight;
	unsigned int nQty;
	unsigned int op;
	int64_t nPricePerUnit;
	void ClearEscrow()
	{
		vchEscrow.clear();
		vchSellerKey.clear();
		vchArbiterKey.clear();
		vchRedeemScript.clear();
		vchOffer.clear();
		vchPaymentMessage.clear();
		vchWhitelistAlias.clear();
		vchOfferAcceptLink.clear();
		buyerFeedback.SetNull();
		sellerFeedback.SetNull();
		arbiterFeedback.SetNull();
	}
    CEscrow() {
        SetNull();
    }
    CEscrow(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchSellerKey);
		READWRITE(vchArbiterKey);
		READWRITE(vchRedeemScript);
        READWRITE(vchOffer);
		READWRITE(vchWhitelistAlias);
		READWRITE(vchPaymentMessage);
		READWRITE(rawTx);
		READWRITE(vchOfferAcceptLink);
		READWRITE(txHash);
		READWRITE(escrowInputTxHash);
		READWRITE(VARINT(nHeight));
		READWRITE(VARINT(nQty));
		READWRITE(VARINT(nPricePerUnit));
        READWRITE(vchBuyerKey);	
		if(IsSys21Fork(nHeight))
		{
			READWRITE(vchEscrow);
			READWRITE(buyerFeedback);	
			READWRITE(sellerFeedback);	
			READWRITE(arbiterFeedback);	
			READWRITE(VARINT(op));
		}
	}

    friend bool operator==(const CEscrow &a, const CEscrow &b) {
        return (
        a.vchBuyerKey == b.vchBuyerKey
		&& a.vchSellerKey == b.vchSellerKey
		&& a.vchArbiterKey == b.vchArbiterKey
		&& a.vchRedeemScript == b.vchRedeemScript
        && a.vchOffer == b.vchOffer
		&& a.vchWhitelistAlias == b.vchWhitelistAlias
		&& a.vchPaymentMessage == b.vchPaymentMessage
		&& a.rawTx == b.rawTx
		&& a.vchOfferAcceptLink == b.vchOfferAcceptLink
		&& a.txHash == b.txHash
		&& a.escrowInputTxHash == b.escrowInputTxHash
		&& a.nHeight == b.nHeight
		&& a.nQty == b.nQty
		&& a.nPricePerUnit == b.nPricePerUnit
		&& a.buyerFeedback == b.buyerFeedback
		&& a.sellerFeedback == b.sellerFeedback
		&& a.arbiterFeedback == b.arbiterFeedback
		&& a.vchEscrow == b.vchEscrow
		&& a.op == b.op
        );
    }

    CEscrow operator=(const CEscrow &b) {
        vchBuyerKey = b.vchBuyerKey;
		vchSellerKey = b.vchSellerKey;
		vchArbiterKey = b.vchArbiterKey;
		vchRedeemScript = b.vchRedeemScript;
        vchOffer = b.vchOffer;
		vchWhitelistAlias = b.vchWhitelistAlias;
		vchPaymentMessage = b.vchPaymentMessage;
		rawTx = b.rawTx;
		vchOfferAcceptLink = b.vchOfferAcceptLink;
		txHash = b.txHash;
		escrowInputTxHash = b.escrowInputTxHash;
		nHeight = b.nHeight;
		nQty = b.nQty;
		nPricePerUnit = b.nPricePerUnit;
		buyerFeedback = b.buyerFeedback;
		sellerFeedback = b.sellerFeedback;
		arbiterFeedback = b.arbiterFeedback;
		vchEscrow = b.vchEscrow;
		op = b.op;
        return *this;
    }

    friend bool operator!=(const CEscrow &a, const CEscrow &b) {
        return !(a == b);
    }

    void SetNull() { op = 0; vchEscrow.clear(); buyerFeedback.SetNull();sellerFeedback.SetNull();arbiterFeedback.SetNull(); nHeight = 0; txHash.SetNull(); escrowInputTxHash.SetNull(); nQty = 0; nPricePerUnit = 0; vchBuyerKey.clear(); vchArbiterKey.clear(); vchSellerKey.clear(); vchRedeemScript.clear(); vchOffer.clear(); vchWhitelistAlias.clear(); rawTx.clear(); vchOfferAcceptLink.clear(); vchPaymentMessage.clear();}
    bool IsNull() const { return (op == 0 && vchEscrow.empty() && txHash.IsNull() && escrowInputTxHash.IsNull() && buyerFeedback.IsNull() && sellerFeedback.IsNull() && arbiterFeedback.IsNull() && nHeight == 0 && nQty == 0 && nPricePerUnit == 0 && vchBuyerKey.empty() && vchArbiterKey.empty() && vchSellerKey.empty()); }
    bool UnserializeFromTx(const CTransaction &tx);
	bool UnserializeFromData(const std::vector<unsigned char> &vchData);
	const std::vector<unsigned char> Serialize();
};


class CEscrowDB : public CDBWrapper {
public:
    CEscrowDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "escrow", nCacheSize, fMemory, fWipe) {}

    bool WriteEscrow(const std::vector<unsigned char>& name, std::vector<CEscrow>& vtxPos) {
        return Write(make_pair(std::string("escrowi"), name), vtxPos);
    }

    bool EraseEscrow(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("escrowi"), name));
    }

    bool ReadEscrow(const std::vector<unsigned char>& name, std::vector<CEscrow>& vtxPos) {
        return Read(make_pair(std::string("escrowi"), name), vtxPos);
    }

    bool ExistsEscrow(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("escrowi"), name));
    }

    bool ScanEscrows(
		const std::vector<unsigned char>& vchName, const std::string& strRegExp, 
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan);
   bool ScanEscrowFeedbacks(
		const std::vector<unsigned char>& vchName, const std::string& strRegExp, 
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan);
};

bool GetTxOfEscrow(const std::vector<unsigned char> &vchEscrow, CEscrow& txPos, CTransaction& tx);
void HandleEscrowFeedback(const CEscrow& escrow);
int FindFeedbackInEscrow(const unsigned char nFeedbackUser, const EscrowUser type, const std::vector<CEscrow> &vtxPos);
void GetFeedbackInEscrow(std::vector<CEscrowFeedback> &feedBack, int &avgRating, const EscrowUser type, std::vector<CEscrow> &vtxPos);
#endif // ESCROW_H
