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
class CEscrowFeedback {
public:
    enum UserType {
        BUYER,
		SELLER,
		ARBITER
    };
	std::vector<unsigned char> vchFeedback;
	unsigned char nRating;
	unsigned char nFeedbackUser;
	
	
	void ClearFeedback()
	{
		vchFeedback.clear();
	}
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
	}

    friend bool operator==(const CEscrowFeedback &a, const CEscrowFeedback &b) {
        return (
        a.vchFeedback == b.vchBuyerKey
		&& a.nRating == b.nRating
		&& a.nFeedbackUser == b.nFeedbackUser
        );
    }

    CEscrow operator=(const CEscrowFeedback &b) {
        vchFeedback = b.vchFeedback;
		nRating = b.nRating;
		nFeedbackUser = b.nFeedbackUser;
        return *this;
    }

    friend bool operator!=(const CEscrowFeedback &a, const CEscrowFeedback &b) {
        return !(a == b);
    }

    void SetNull() { nRating = 0; nFeedbackUser = 0; vchFeedback.clear();}
    bool IsNull() const { return (nRating == 0 && nFeedbackUser == 0 && nArbiterRating == 0 && vchFeedback.empty()); }
};

class CEscrow {
public:
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
	int64_t nPricePerUnit;
	void ClearEscrow()
	{
		vchSellerKey.clear();
		vchArbiterKey.clear();
		vchRedeemScript.clear();
		vchOffer.clear();
		vchPaymentMessage.clear();
		vchWhitelistAlias.clear();
		vchOfferAcceptLink.clear();
		buyerFeedback.ClearFeedback();
		sellerFeedback.ClearFeedback();
		arbiterFeedback.ClearFeedback();
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
			READWRITE(buyerFeedback);	
			READWRITE(sellerFeedback);	
			READWRITE(arbiterFeedback);	
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
		buyerFeedback = b.buyerFeedback;
		sellerFeedback = b.sellerFeedback;
		arbiterFeedback = b.arbiterFeedback;
        return *this;
    }

    friend bool operator!=(const CEscrow &a, const CEscrow &b) {
        return !(a == b);
    }

    void SetNull() { buyerFeedback.SetNull();sellerFeedback.SetNull();arbiterFeedback.SetNull(); nHeight = 0; txHash.SetNull(); escrowInputTxHash.SetNull(); nQty = 0; nPricePerUnit = 0; vchBuyerKey.clear(); vchArbiterKey.clear(); vchSellerKey.clear(); vchRedeemScript.clear(); vchOffer.clear(); vchWhitelistAlias.clear(); rawTx.clear(); vchOfferAcceptLink.clear(); vchPaymentMessage.clear();}
    bool IsNull() const { return (txHash.IsNull() && escrowInputTxHash.IsNull() && buyerFeedback.IsNull() == 0 && sellerFeedback.IsNull() && arbiterFeedback.IsNull() && nHeight == 0 && nQty == 0 && nPricePerUnit == 0 && vchBuyerKey.empty() && vchArbiterKey.empty() && vchSellerKey.empty()); }
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

    bool ReconstructEscrowIndex(CBlockIndex *pindexRescan);
};

bool GetTxOfEscrow(const std::vector<unsigned char> &vchEscrow, CEscrow& txPos, CTransaction& tx);

#endif // ESCROW_H
