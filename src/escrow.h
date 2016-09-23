#ifndef ESCROW_H
#define ESCROW_H

#include "rpc/server.h"
#include "dbwrapper.h"
#include "feedback.h"
class CWalletTx;
class CTransaction;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;
bool CheckEscrowInputs(const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, std::string &errorMessage, const CBlock* block = NULL, bool dontaddtodb=false);
bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeEscrowScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsEscrowOp(int op);
int IndexOfEscrowOutput(const CTransaction& tx);
int GetEscrowExpirationDepth();

std::string escrowFromOp(int op);
CScript RemoveEscrowScriptPrefix(const CScript& scriptIn);
extern bool IsSys21Fork(const uint64_t& nHeight);
class CEscrow {
public:
	std::vector<unsigned char> vchEscrow;
	std::vector<unsigned char> vchSellerAlias;
	std::vector<unsigned char> vchArbiterAlias;
	std::vector<unsigned char> vchRedeemScript;
	std::vector<unsigned char> vchOffer;
	std::vector<unsigned char> vchPaymentMessage;
	std::vector<unsigned char> rawTx;
	std::vector<unsigned char> vchBuyerAlias;
	std::vector<unsigned char> vchLinkAlias;
	std::vector<CFeedback> feedback;
    uint256 txHash;
	std::string escrowInputTx;
    uint64_t nHeight;
	uint64_t nAcceptHeight;
	unsigned int nQty;
	unsigned int op;
	void ClearEscrow()
	{
		feedback.clear();
		vchSellerAlias.clear();
		vchArbiterAlias.clear();
		vchLinkAlias.clear();
		vchRedeemScript.clear();
		vchLinkAlias.clear();
		vchOffer.clear();
		rawTx.clear();
		vchPaymentMessage.clear();
		escrowInputTx.clear();
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
		READWRITE(vchSellerAlias);
		READWRITE(vchArbiterAlias);
		READWRITE(vchRedeemScript);
        READWRITE(vchOffer);
		READWRITE(vchPaymentMessage);
		READWRITE(rawTx);
		READWRITE(txHash);
		READWRITE(escrowInputTx);
		READWRITE(VARINT(nHeight));
		READWRITE(VARINT(nAcceptHeight));
		READWRITE(VARINT(nQty));
		READWRITE(VARINT(op));
        READWRITE(vchBuyerAlias);	
		READWRITE(vchEscrow);
		READWRITE(vchLinkAlias);
		READWRITE(feedback);
	}

    friend bool operator==(const CEscrow &a, const CEscrow &b) {
        return (
        a.vchBuyerAlias == b.vchBuyerAlias
		&& a.vchSellerAlias == b.vchSellerAlias
		&& a.vchArbiterAlias == b.vchArbiterAlias
		&& a.vchRedeemScript == b.vchRedeemScript
        && a.vchOffer == b.vchOffer
		&& a.vchPaymentMessage == b.vchPaymentMessage
		&& a.rawTx == b.rawTx
		&& a.txHash == b.txHash
		&& a.escrowInputTx == b.escrowInputTx
		&& a.nHeight == b.nHeight
		&& a.nAcceptHeight == b.nAcceptHeight
		&& a.nQty == b.nQty
		&& a.vchLinkAlias == b.vchLinkAlias
		&& a.vchEscrow == b.vchEscrow
		&& a.op == b.op
		&& a.feedback == b.feedback
        );
    }

    CEscrow operator=(const CEscrow &b) {
        vchBuyerAlias = b.vchBuyerAlias;
		vchSellerAlias = b.vchSellerAlias;
		vchArbiterAlias = b.vchArbiterAlias;
		vchRedeemScript = b.vchRedeemScript;
        vchOffer = b.vchOffer;
		vchPaymentMessage = b.vchPaymentMessage;
		rawTx = b.rawTx;
		txHash = b.txHash;
		vchLinkAlias = b.vchLinkAlias;
		escrowInputTx = b.escrowInputTx;
		nHeight = b.nHeight;
		nAcceptHeight = b.nAcceptHeight;
		nQty = b.nQty;
		vchEscrow = b.vchEscrow;
		op = b.op;
		feedback = b.feedback;
        return *this;
    }

    friend bool operator!=(const CEscrow &a, const CEscrow &b) {
        return !(a == b);
    }

    void SetNull() { op = 0; vchLinkAlias.clear(); feedback.clear(); vchEscrow.clear(); nHeight = nAcceptHeight = 0; txHash.SetNull(); escrowInputTx.clear(); nQty = 0; vchBuyerAlias.clear(); vchArbiterAlias.clear(); vchSellerAlias.clear(); vchRedeemScript.clear(); vchOffer.clear(); rawTx.clear(); vchPaymentMessage.clear();}
    bool IsNull() const { return (vchLinkAlias.empty() && feedback.empty() && op == 0 && vchEscrow.empty() && txHash.IsNull() && escrowInputTx.empty() && nHeight == 0 && nAcceptHeight == 0 && nQty == 0 && vchBuyerAlias.empty() && vchArbiterAlias.empty() && vchSellerAlias.empty() && vchRedeemScript.empty() && vchOffer.empty() && rawTx.empty() && vchPaymentMessage.empty()); }
    bool UnserializeFromTx(const CTransaction &tx);
	bool UnserializeFromData(const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash);
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
		const std::vector<unsigned char>& vchEscrow, const std::string& strRegExp, 
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan);
   bool ScanEscrowFeedbacks(
		const std::vector<unsigned char>& vchEscrow, const std::string& strRegExp, 
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan);
};

bool GetTxOfEscrow(const std::vector<unsigned char> &vchEscrow, CEscrow& txPos, CTransaction& tx);
bool GetTxAndVtxOfEscrow(const std::vector<unsigned char> &vchEscrow, CEscrow& txPos, CTransaction& tx, std::vector<CEscrow> &vtxPos);
void HandleEscrowFeedback(const CEscrow& serializedEscrow, CEscrow& dbEscrow, std::vector<CEscrow> &vtxPos);
#endif // ESCROW_H
