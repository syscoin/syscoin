#include "escrow.h"
#include "offer.h"
#include "alias.h"
#include "cert.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "base58.h"
#include "rpcserver.h"
#include "wallet/wallet.h"
#include "policy/policy.h"
#include "script/script.h"
#include "chainparams.h"
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
using namespace std;
extern void SendMoney(const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew);
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInOffer=NULL, const CWalletTx* wtxInCert=NULL, const CWalletTx* wtxInAlias=NULL, const CWalletTx* wtxInEscrow=NULL, bool syscoinTx=true);
void PutToEscrowList(std::vector<CEscrow> &escrowList, CEscrow& index) {
	int i = escrowList.size() - 1;
	BOOST_REVERSE_FOREACH(CEscrow &o, escrowList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	escrowList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	escrowList[i] = index;
            return;
        }
        i--;
	}
    escrowList.push_back(index);
}
bool IsEscrowOp(int op) {
    return op == OP_ESCROW_ACTIVATE
        || op == OP_ESCROW_RELEASE
        || op == OP_ESCROW_REFUND
		|| op == OP_ESCROW_COMPLETE;
}
// 0.05% fee on escrow value for arbiter
int64_t GetEscrowArbiterFee(int64_t escrowValue) {

	int64_t nFee = escrowValue*0.005;
	if(nFee < DEFAULT_MIN_RELAY_TX_FEE)
		nFee = DEFAULT_MIN_RELAY_TX_FEE;
	return nFee;
}
int GetEscrowExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 100;
  #else
    return 525600;
  #endif
}


string escrowFromOp(int op) {
    switch (op) {
    case OP_ESCROW_ACTIVATE:
        return "escrowactivate";
    case OP_ESCROW_RELEASE:
        return "escrowrelease";
    case OP_ESCROW_REFUND:
        return "escrowrefund";
	case OP_ESCROW_COMPLETE:
		return "escrowcomplete";
    default:
        return "<unknown escrow op>";
    }
}
bool CEscrow::UnserializeFromData(const vector<unsigned char> &vchData) {
    try {
        CDataStream dsEscrow(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsEscrow >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	// extra check to ensure data was parsed correctly
	if(!IsSysCompressedOrUncompressedPubKey(vchBuyerKey))
	{
		SetNull();
		return false;
	}
	return true;
}
bool CEscrow::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	if(!GetSyscoinData(tx, vchData))
	{
		SetNull();
		return false;
	}
	if(!UnserializeFromData(vchData))
	{
		return false;
	}
    return true;
}
const vector<unsigned char> CEscrow::Serialize() {
    CDataStream dsEscrow(SER_NETWORK, PROTOCOL_VERSION);
    dsEscrow << *this;
    const vector<unsigned char> vchData(dsEscrow.begin(), dsEscrow.end());
    return vchData;

}
bool CEscrowDB::ScanEscrows(const std::vector<unsigned char>& vchEscrow, const string& strRegexp, unsigned int nMax,
        std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan) {
	string strSearchLower = strRegexp;
	boost::algorithm::to_lower(strSearchLower);
	int nMaxAge  = GetEscrowExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("escrowi"), vchEscrow));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "escrowi") {
            	vector<unsigned char> vchEscrow = key.second;
                vector<CEscrow> vtxPos;
				pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CEscrow &txPos = vtxPos.back();
  				if (chainActive.Tip()->nHeight - txPos.nHeight >= nMaxAge && txPos.op == OP_ESCROW_COMPLETE)
				{
					pcursor->Next();
					continue;
				}   
				const string &escrow = stringFromVch(vchEscrow);
				const string &offerstr = stringFromVch(txPos.vchOffer);
				CPubKey SellerPubKey(txPos.vchSellerKey);
				CSyscoinAddress selleraddy(SellerPubKey.GetID());
				selleraddy = CSyscoinAddress(selleraddy.ToString());

				CPubKey ArbiterPubKey(txPos.vchArbiterKey);
				CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
				arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());

				CPubKey BuyerPubKey(txPos.vchBuyerKey);
				CSyscoinAddress buyeraddy(BuyerPubKey.GetID());
				buyeraddy = CSyscoinAddress(buyeraddy.ToString());
				string buyerAliasLower = buyeraddy.aliasName;
				string sellerAliasLower = selleraddy.aliasName;
				string arbiterAliasLower = arbiteraddy.aliasName;
				boost::algorithm::to_lower(buyerAliasLower);
				boost::algorithm::to_lower(sellerAliasLower);
				boost::algorithm::to_lower(arbiterAliasLower);

				if (strRegexp != "" && strRegexp != offerstr && strRegexp != escrow && strSearchLower != buyerAliasLower && strSearchLower != sellerAliasLower && strSearchLower != arbiterAliasLower)
				{
					pcursor->Next();
					continue;
				}  
                escrowScan.push_back(make_pair(vchEscrow, txPos));
            }
            if (escrowScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}
int IndexOfEscrowOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
    int op, nOut;
	bool good = DecodeEscrowTx(tx, op, nOut, vvch);
	if (!good)
		return -1;
    return nOut;
}
int IndexOfMyEscrowOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
    int op, nOut;
	bool good = DecodeMyEscrowTx(tx, op, nOut, vvch);
	if (!good)
		return -1;
    return nOut;
}
bool GetTxOfEscrow(const vector<unsigned char> &vchEscrow,
        CEscrow& txPos, CTransaction& tx) {
    vector<CEscrow> vtxPos;
    if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if ((nHeight + GetEscrowExpirationDepth()
            < chainActive.Tip()->nHeight) && txPos.op == OP_ESCROW_COMPLETE) {
        string escrow = stringFromVch(vchEscrow);
        LogPrintf("GetTxOfEscrow(%s) : expired", escrow.c_str());
        return false;
    }
    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfEscrow() : could not read tx from disk");

    return true;
}
bool DecodeAndParseEscrowTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CEscrow escrow;
	bool decode = DecodeEscrowTx(tx, op, nOut, vvch);
	bool parse = escrow.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeMyEscrowTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;
	if(!pwalletMain)
		return false;

    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (pwalletMain->IsMine(out) && DecodeEscrowScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found && IsEscrowOp(op);
}
bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeEscrowScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found && IsEscrowOp(op);
}

bool DecodeEscrowScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
    opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode)) return false;
	if (opcode < OP_1 || opcode > OP_16) return false;
    op = CScript::DecodeOP_N(opcode);
    for (;;) {
        vector<unsigned char> vch;
        if (!script.GetOp(pc, opcode, vch))
            return false;

        if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
            break;
        if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
            return false;
        vvch.push_back(vch);
    }

    // move the pc to after any DROP or NOP
    while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
        if (!script.GetOp(pc, opcode))
            break;
    }
	
    pc--;

    if ((op == OP_ESCROW_ACTIVATE && vvch.size() == 1)
        || (op == OP_ESCROW_RELEASE && vvch.size() == 1)
        || (op == OP_ESCROW_REFUND && vvch.size() <= 2)
		|| (op == OP_ESCROW_COMPLETE && vvch.size() <= 2))
        return true;

    return false;
}
bool DecodeEscrowScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeEscrowScript(script, op, vvch, pc);
}

CScript RemoveEscrowScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeEscrowScript(scriptIn, op, vvch, pc))
	{
        throw runtime_error("RemoveEscrowScriptPrefix() : could not decode escrow script");
	}
	
    return CScript(pc, scriptIn.end());
}
bool CheckEscrowInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock* block) {
		
	if (tx.IsCoinBase())
		return true;
	const COutPoint *prevOutput = NULL;
	CCoins prevCoins;
	int prevOp = 0;
	int prevAliasOp = 0;
	bool foundAlias = false;
	bool foundEscrow = false;
	vector<vector<unsigned char> > vvchPrevArgs, vvchPrevAliasArgs;
	if(fJustCheck)
	{
		// Strict check - bug disallowed
		for (unsigned int i = 0; i < tx.vin.size(); i++) {
			vector<vector<unsigned char> > vvch;
			int pop;
			prevOutput = &tx.vin[i].prevout;	
			if(!prevOutput)
				continue;
			// ensure inputs are unspent when doing consensus check to add to block
			if(!inputs.GetCoins(prevOutput->hash, prevCoins))
				continue;
			if(prevCoins.vout.size() <= prevOutput->n || !IsSyscoinScript(prevCoins.vout[prevOutput->n].scriptPubKey, pop, vvch))
				continue;
			if(foundEscrow && foundAlias)
				break;

			if (!foundEscrow && IsEscrowOp(pop)) {
				foundEscrow = true; 
				prevOp = pop;
				vvchPrevArgs = vvch;
			}
			else if (!foundAlias && IsAliasOp(pop))
			{
				foundAlias = true; 
				prevAliasOp = pop;
				vvchPrevAliasArgs = vvch;
			}
		}
	}
		LogPrintf("*** %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
    // Make sure escrow outputs are not spent by a regular transaction, or the escrow would be lost
    if (tx.nVersion != SYSCOIN_TX_VERSION) {
		LogPrintf("CheckEscrowInputs() : non-syscoin transaction\n");
        return true;
    }

    // unserialize escrow UniValue from txn, check for valid
    CEscrow theEscrow;
    theEscrow.UnserializeFromTx(tx);
    COffer theOffer;
	string retError = "";
    
	if(theEscrow.IsNull() && op != OP_ESCROW_COMPLETE && vvchArgs.size() == 1)
		return true;
    if (vvchArgs[0].size() > MAX_NAME_LENGTH)
        return error("escrow tx GUID too big");
	if(!theEscrow.vchBuyerKey.empty() && !IsSysCompressedOrUncompressedPubKey(theEscrow.vchBuyerKey))
	{
		return error("escrow buyer pub key invalid length");
	}
	if(!theEscrow.vchSellerKey.empty() && !IsSysCompressedOrUncompressedPubKey(theEscrow.vchSellerKey))
	{
		return error("escrow seller pub key invalid length");
	}
	if(!theEscrow.vchArbiterKey.empty() && !IsSysCompressedOrUncompressedPubKey(theEscrow.vchArbiterKey))
	{
		return error("escrow arbiter pub key invalid length");
	}
	if(theEscrow.vchRedeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
	{
		return error("escrow redeem script too long");
	}
	if(theEscrow.buyerFeedback.vchFeedback.size() > MAX_VALUE_LENGTH)
	{
		return error("buyer feedback too long");
	}
	if(theEscrow.sellerFeedback.vchFeedback.size() > MAX_VALUE_LENGTH)
	{
		return error("seller feedback too long");
	}
	if(theEscrow.arbiterFeedback.vchFeedback.size() > MAX_VALUE_LENGTH)
	{
		return error("arbiter feedback too long");
	}
	if(theEscrow.vchOffer.size() > MAX_ID_LENGTH)
	{
		return error("escrow offer guid too long");
	}
	if(theEscrow.vchWhitelistAlias.size() > MAX_ID_LENGTH)
	{
		return error("escrow alias guid too long");
	}
	if(theEscrow.rawTx.size() > MAX_STANDARD_TX_SIZE)
	{
		return error("escrow message tx too long");
	}
	if(theEscrow.vchOfferAcceptLink.size() > 0)
	{
		return error("escrow offeraccept guid not allowed");
	}
	if(!theEscrow.vchEscrow.empty() && theEscrow.vchEscrow != vvchArgs[0])
	{
		return error("guid in data output doesn't match guid in tx");
	}
	if(fJustCheck)
	{
		switch (op) {
			case OP_ESCROW_ACTIVATE:
				if(!theEscrow.vchWhitelistAlias.empty() && !IsAliasOp(prevAliasOp))
					return error("CheckEscrowInputs() : an escrow offer accept using an alias must attach the alias as an input");
				if(IsAliasOp(prevAliasOp) && vvchPrevAliasArgs[0] != theEscrow.vchWhitelistAlias)
					return error("CheckEscrowInputs() : escrow alias guid and alias input guid mismatch");
				if(!theEscrow.buyerFeedback.IsNull() || !theEscrow.sellerFeedback.IsNull() || !theEscrow.arbiterFeedback.IsNull())
				{
					return error("CheckEscrowInputs() :cannot leave feedback in activate tx");
				}
				if((retError = CheckForAliasExpiryAndSafety(theEscrow.vchBuyerKey, nHeight)) != "")
				{
					retError = string("CheckEscrowInputs(): ") + retError;
					return error(retError.c_str());
				}
				if((retError = CheckForAliasExpiryAndSafety(theEscrow.vchSellerKey, nHeight)) != "")
				{
					retError = string("CheckEscrowInputs(): ") + retError;
					return error(retError.c_str());
				}	
				if((retError = CheckForAliasExpiryAndSafety(theEscrow.vchArbiterKey, nHeight)) != "")
				{
					retError = string("CheckEscrowInputs(): ") + retError;
					return error(retError.c_str());
				}
				if(theEscrow.op != OP_ESCROW_ACTIVATE)
					return error("CheckEscrowInputs() :  invalid op, should be escrow activate");
				break;
			case OP_ESCROW_RELEASE:
				if(prevOp != OP_ESCROW_ACTIVATE)
					return error("CheckEscrowInputs() : can only release an activated escrow");
				// Check input
				if (vvchPrevArgs[0] != vvchArgs[0])
					return error("CheckEscrowInputs() : escrow input guid mismatch");
				if(!theEscrow.buyerFeedback.IsNull() || !theEscrow.sellerFeedback.IsNull() || !theEscrow.arbiterFeedback.IsNull())
				{
					return error("CheckEscrowInputs() :cannot leave feedback in release tx");
				}
				if(theEscrow.op != OP_ESCROW_RELEASE)
					return error("CheckEscrowInputs() :  invalid op, should be escrow release");
				break;
			case OP_ESCROW_COMPLETE:
				// Check input
				if (vvchArgs.size() > 1 && vvchArgs[1].size() > 1)
					return error("CheckEscrowInputs() : escrow complete status too large");
				if (vvchPrevArgs[0] != vvchArgs[0])
					return error("CheckEscrowInputs() : escrow input guid mismatch");
				if(vvchArgs.size() > 1 && vvchArgs[1] == vchFromString("1"))
				{
					if(prevOp != OP_ESCROW_COMPLETE && prevOp != OP_ESCROW_REFUND)
						return error("CheckEscrowInputs() : can only leave feedback for a completed escrow");
					if(!theEscrow.IsNull() && theEscrow.buyerFeedback.IsNull() && theEscrow.sellerFeedback.IsNull() && theEscrow.arbiterFeedback.IsNull())
					{
						return error("CheckEscrowInputs() :cannot leave empty feedback");
					}
					if(prevOp == OP_ESCROW_COMPLETE && vvchPrevArgs.size() > 1 && vvchPrevArgs[1] == vchFromString("1") && theEscrow.buyerFeedback.vchFeedback.size() <= 0 && theEscrow.sellerFeedback.vchFeedback.size() <= 0 && theEscrow.arbiterFeedback.vchFeedback.size() <= 0)
					{
						return error("CheckEscrowInputs() :feedback reply must leave a message, rating is not used.");
					}
				}
				else
				{
					if(prevOp != OP_ESCROW_RELEASE)
						return error("CheckEscrowInputs() : can only complete a released escrow");

					if(!theEscrow.buyerFeedback.IsNull() || !theEscrow.sellerFeedback.IsNull() || !theEscrow.arbiterFeedback.IsNull())
					{
						return error("CheckEscrowInputs() :cannot leave feedback in complete tx");
					}
				}
				break;			
			case OP_ESCROW_REFUND:
				if (vvchArgs.size() > 1 && vvchArgs[1].size() > 1)
					return error("CheckEscrowInputs() : escrow refund status too large");
				if (vvchPrevArgs[0] != vvchArgs[0])
					return error("CheckEscrowInputs() : escrow input guid mismatch");
				if(vvchArgs.size() > 1 && vvchArgs[1] == vchFromString("1"))
				{
					if(prevOp != OP_ESCROW_REFUND)
						return error("CheckEscrowInputs() :  can only complete refund on a refunded escrow");
					if(theEscrow.op != OP_ESCROW_COMPLETE)
						return error("CheckEscrowInputs() :  invalid op, should be escrow complete");

				}
				else
				{
					if(prevOp != OP_ESCROW_ACTIVATE)
						return error("CheckEscrowInputs() : can only refund an activated escrow");
					if(theEscrow.op != OP_ESCROW_REFUND)
						return error("CheckEscrowInputs() :  invalid op, should be escrow refund");
				}
				// Check input
				if(!theEscrow.buyerFeedback.IsNull() || !theEscrow.sellerFeedback.IsNull() || !theEscrow.arbiterFeedback.IsNull())
				{
					return error("CheckEscrowInputs() :cannot leave feedback in refund tx");
				}
				


				break;
			default:
				return error( "CheckEscrowInputs() : escrow transaction has unknown op");
		}
	}



    if (!fJustCheck ) {
		vector<CEscrow> vtxPos;
		// make sure escrow settings don't change (besides rawTx) outside of activation
		if(op != OP_ESCROW_ACTIVATE) 
		{
			// save serialized escrow for later use
			CEscrow serializedEscrow = theEscrow;
			if (pescrowdb->ExistsEscrow(vvchArgs[0])) {
				if (!pescrowdb->ReadEscrow(vvchArgs[0], vtxPos))
					return error(
							"CheckEscrowInputs() : failed to read from escrow DB");
			}
			// make sure we have found this escrow in db
			if(!vtxPos.empty())
			{
				// if escrow is refunded or claimed and its expired
				// if not refunded or claimed it cannot expire
				if(vtxPos.back().op == OP_ESCROW_COMPLETE && (vtxPos.back().nHeight + GetEscrowExpirationDepth()) < nHeight)
				{
					if(fDebug)
						LogPrintf("CheckEscrowInputs(): Trying to update an expired service");
					return true;
				}
				theEscrow = vtxPos.back();					
				// these are the only settings allowed to change outside of activate
				if(!serializedEscrow.rawTx.empty())
					theEscrow.rawTx = serializedEscrow.rawTx;
				if(op == OP_ESCROW_REFUND && vvchArgs.size() == 1)
				{
					vector<COffer> myVtxPos;
					if (vvchArgs.size() > 2 && dbOffer.qty != -1 && pofferdb->ExistsOffer(theEscrow.vchOffer)) {
						if (pofferdb->ReadOffer(theEscrow.vchOffer, myVtxPos) && !myVtxPos.empty())
						{
							COffer &dbOffer = myVtxPos.back();
							if((dbOffer.nHeight + GetOfferExpirationDepth()) < nHeight)
							{
								if(fDebug)
									LogPrintf("CheckEscrowInputs() : OP_ESCROW_ACTIVATE trying to refund an expired offer");	
							}
							else
							{
								dbOffer.nQty += theEscrow.nQty;
								if(dbOffer.nQty < 0)
									dbOffer.nQty = 0;
								dbOffer.PutToOfferList(myVtxPos);
								if (!pofferdb->WriteOffer(theEscrow.vchOffer, myVtxPos))
									return error( "CheckEscrowInputs() : failed to write to offer to DB");
							}
						}

					}
				}
				if(op == OP_ESCROW_COMPLETE)
				{
					if(vvchArgs.size() > 1 && vvchArgs[1] == vchFromString("1"))
					{
						int count = 0;
						// ensure we don't add same feedback twice (feedback in db should be older than current height)
						// ensure feedback is valid
						// ensure you aren't leaving feedback for yourself
						if(!serializedEscrow.buyerFeedback.IsNull()  && serializedEscrow.buyerFeedback.nFeedbackUser != BUYER && theEscrow.buyerFeedback.nHeight < nHeight)
						{
							theEscrow.buyerFeedback = serializedEscrow.buyerFeedback;
							theEscrow.buyerFeedback.nHeight = nHeight;
							count++;
						}
						else
							theEscrow.buyerFeedback.SetNull();

						if(!serializedEscrow.sellerFeedback.IsNull() && serializedEscrow.sellerFeedback.nFeedbackUser != SELLER && theEscrow.sellerFeedback.nHeight < nHeight)
						{
							theEscrow.sellerFeedback = serializedEscrow.sellerFeedback;
							theEscrow.sellerFeedback.nHeight = nHeight;
							count++;
						}
						else
							theEscrow.sellerFeedback.SetNull();


						if(!serializedEscrow.arbiterFeedback.IsNull() && serializedEscrow.arbiterFeedback.nFeedbackUser != ARBITER && theEscrow.arbiterFeedback.nHeight < nHeight)
						{
							theEscrow.arbiterFeedback = serializedEscrow.arbiterFeedback;
							theEscrow.arbiterFeedback.nHeight = nHeight;
							count++;
						}
						else
							theEscrow.arbiterFeedback.SetNull();

						// can't leave more than 2 feedbacks at once
						if(count > 2)
						{
							if(fDebug)
								LogPrintf("CheckEscrowInputs() : Trying to leave more than 2 feedbacks in the same transaction, skipping...");
							return true;
						}

						// has this user (nFeedbackUser) already left feedback (BUYER/SELLER/ARBITER) by checking escrow history of tx's (vtxPos)
						if(FindFeedbackInEscrow(theEscrow.buyerFeedback.nFeedbackUser, BUYER, vtxPos))
							theEscrow.buyerFeedback.nRating = 0;
						if(FindFeedbackInEscrow(theEscrow.sellerFeedback.nFeedbackUser, SELLER, vtxPos))
							theEscrow.sellerFeedback.nRating = 0;
						if(FindFeedbackInEscrow(theEscrow.arbiterFeedback.nFeedbackUser, ARBITER, vtxPos))
							theEscrow.arbiterFeedback.nRating = 0;

						HandleEscrowFeedback(theEscrow);	
					
					}
					else
					{
						theOffer.UnserializeFromTx(tx);
						theEscrow.vchOfferAcceptLink = theOffer.accept.vchAcceptRand;
					}
				}
				
			}
			else
				return true;
					
		}
		else
		{
			vector<COffer> myVtxPos;
			if (vvchArgs.size() > 2 && theEscrow.qty != -1 && pofferdb->ExistsOffer(theEscrow.vchOffer)) {
				if (pofferdb->ReadOffer(theEscrow.vchOffer, myVtxPos) && !myVtxPos.empty())
				{
					COffer &dbOffer = myVtxPos.back();
					if((dbOffer.nHeight + GetOfferExpirationDepth()) < nHeight)
					{
						if(fDebug)
							LogPrintf("CheckEscrowInputs() : OP_ESCROW_ACTIVATE trying to purchase an expired offer");	
					}
					else
					{
						dbOffer.nQty -= theEscrow.nQty;
						if(dbOffer.nQty < 0)
							dbOffer.nQty = 0;
						dbOffer.PutToOfferList(myVtxPos);
						if (!pofferdb->WriteOffer(theEscrow.vchOffer, myVtxPos))
							return error( "CheckEscrowInputs() : failed to write to offer to DB");
					}
				}

			}

		}
        // set the escrow's txn-dependent values
		if(op == OP_ESCROW_COMPLETE)
			theEscrow.op = op;
		theEscrow.txHash = tx.GetHash();
		theEscrow.nHeight = nHeight;
		PutToEscrowList(vtxPos, theEscrow);
        // write escrow  

        if (!pescrowdb->WriteEscrow(vvchArgs[0], vtxPos))
            return error( "CheckEscrowInputs() : failed to write to escrow DB");
		

      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED ESCROW: op=%s escrow=%s hash=%s height=%d\n",
                escrowFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
	}
    return true;
}
void HandleEscrowFeedback(const CEscrow& escrow)
{
	if(escrow.buyerFeedback.nRating > 0)
	{
		CPubKey key(escrow.vchBuyerKey);
		CSyscoinAddress address(key.GetID());
		address = CSyscoinAddress(address.ToString());
		if(address.IsValid() && address.isAlias)
		{
			vector<CAliasIndex> vtxPos;
			const vector<unsigned char> &vchAlias = vchFromString(address.aliasName);
			if (paliasdb->ReadAlias(vchAlias, vtxPos) && !vtxPos.empty())
			{
				
				CAliasIndex alias = vtxPos.back();
				alias.nRatingCount++;
				alias.nRating += escrow.buyerFeedback.nRating;
				PutToAliasList(vtxPos, alias);
				paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vtxPos);
			}
		}
			
	}
	if(escrow.sellerFeedback.nRating > 0)
	{
		CPubKey key(escrow.vchSellerKey);
		CSyscoinAddress address(key.GetID());
		address = CSyscoinAddress(address.ToString());
		if(address.IsValid() && address.isAlias)
		{
			vector<CAliasIndex> vtxPos;
			const vector<unsigned char> &vchAlias = vchFromString(address.aliasName);
			if (paliasdb->ReadAlias(vchAlias, vtxPos) && !vtxPos.empty())
			{
				CAliasIndex alias = vtxPos.back();
				alias.nRatingCount++;
				alias.nRating += escrow.sellerFeedback.nRating;
				PutToAliasList(vtxPos, alias);
				paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vtxPos);
			}
		}
	}
	if(escrow.arbiterFeedback.nRating > 0)
	{
		CPubKey key(escrow.vchArbiterKey);
		CSyscoinAddress address(key.GetID());
		address = CSyscoinAddress(address.ToString());
		if(address.IsValid() && address.isAlias)
		{
			vector<CAliasIndex> vtxPos;
			const vector<unsigned char> &vchAlias = vchFromString(address.aliasName);
			if (paliasdb->ReadAlias(vchAlias, vtxPos) && !vtxPos.empty())
			{
				CAliasIndex alias = vtxPos.back();
				alias.nRatingCount++;
				alias.nRating += escrow.arbiterFeedback.nRating;
				PutToAliasList(vtxPos, alias);
				paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vtxPos);
			}
		}
	}
}
bool FindFeedbackInEscrow(const unsigned char nFeedbackUser, const EscrowUser type, const vector<CEscrow> &vtxPos)
{
	for(unsigned int i =0;i<vtxPos.size();i++)
	{
		if(type == BUYER)
		{
			if(vtxPos[i].buyerFeedback.nFeedbackUser == nFeedbackUser)
				return true;
		}
		else if(type == SELLER)
		{
			if(vtxPos[i].sellerFeedback.nFeedbackUser == nFeedbackUser)
				return true;
		}
		else if(type == ARBITER)
		{
			if(vtxPos[i].arbiterFeedback.nFeedbackUser == nFeedbackUser)
				return true;
		}
	}
	return false;
}
void GetFeedbackInEscrow(vector<CEscrowFeedback> &feedBack, int &avgRating, const EscrowUser type, vector<CEscrow> &vtxPos)
{
	float nRating = 0;
	int nRatingCount = 0;
	for(unsigned int i =0;i<vtxPos.size();i++)
	{
		if(type == BUYER)
		{
			if(!vtxPos[i].buyerFeedback.IsNull())
			{
				if(vtxPos[i].buyerFeedback.nRating > 0)
				{
					nRating += vtxPos[i].buyerFeedback.nRating;
					nRatingCount++;
				}
				feedBack.push_back(vtxPos[i].buyerFeedback);
			}
		}
		else if(type == SELLER)
		{
			if(!vtxPos[i].sellerFeedback.IsNull())
			{
				if(vtxPos[i].sellerFeedback.nRating > 0)
				{
					nRating += vtxPos[i].sellerFeedback.nRating;
					nRatingCount++;
				}
				feedBack.push_back(vtxPos[i].sellerFeedback);
			}
		}
		else if(type == ARBITER)
		{
			if(!vtxPos[i].arbiterFeedback.IsNull())
			{
				if(vtxPos[i].arbiterFeedback.nRating > 0)
				{
					nRating += vtxPos[i].arbiterFeedback.nRating;
					nRatingCount++;
				}
				feedBack.push_back(vtxPos[i].arbiterFeedback);
			}
		}
	}
	if(nRatingCount > 0)
	{
		nRating /= nRatingCount;
	}
	avgRating = (int)roundf(nRating);
	if(feedBack.size() > 0)
		sort(feedBack.begin(), feedBack.end(), escrowfeedbacksort());
	
}
UniValue escrownew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 5 )
        throw runtime_error(
		"escrownew <alias> <offer> <quantity> <message> <arbiter alias>\n"
						"<alias> An alias you own.\n"
                        "<offer> GUID of offer that this escrow is managing.\n"
                        "<quantity> Quantity of items to buy of offer.\n"
						"<message> Delivery details to seller.\n"
						"<arbiter alias> Alias of Arbiter.\n"
                        + HelpRequiringPassphrase());
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	string strArbiter = params[4].get_str();
	CSyscoinAddress arbiterAddress = CSyscoinAddress(strArbiter);
	if (!arbiterAddress.IsValid())
		throw runtime_error("Invalid arbiter syscoin address");
	if (!arbiterAddress.isAlias)
		throw runtime_error("Arbiter must be a valid alias");
	if(IsMine(*pwalletMain, arbiterAddress.Get()))
		throw runtime_error("Arbiter alias must not be yours");
	// check for alias existence in DB
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchFromString(arbiterAddress.aliasName), vtxPos))
		throw runtime_error("failed to read alias from alias DB");
	if (vtxPos.size() < 1)
		throw runtime_error("no result returned");
	CAliasIndex arbiteralias = vtxPos.back();

	vector<unsigned char> vchMessage = vchFromValue(params[3]);
	unsigned int nQty = 1;
	if(atof(params[2].get_str().c_str()) < 0)
		throw runtime_error("invalid quantity value, must be greator than 0");

	try {
		nQty = boost::lexical_cast<unsigned int>(params[2].get_str());
	} catch (std::exception &e) {
		throw runtime_error("invalid quantity value. Quantity must be less than 4294967296.");
	}

    if (vchMessage.size() <= 0)
        vchMessage = vchFromString("ESCROW");

	CSyscoinAddress aliasAddress = CSyscoinAddress(stringFromVch(vchAlias));
	if (!aliasAddress.IsValid())
		throw runtime_error("Invalid syscoin address");
	if (!aliasAddress.isAlias)
		throw runtime_error("Offer must be a valid alias");

	CAliasIndex buyeralias;
	CTransaction aliastx;
	if (!GetTxOfAlias(vchAlias, buyeralias, aliastx))
		throw runtime_error("could not find an alias with this name");

    if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("This alias is not yours.");
    }
	if (pwalletMain->GetWalletTx(aliastx.GetHash()) == NULL)
		throw runtime_error("this alias is not in your wallet");

	COffer theOffer, linkedOffer;
	CTransaction txOffer;
	vector<unsigned char> vchSellerPubKey;
	if (!GetTxOfOffer( vchOffer, theOffer, txOffer, true))
		throw runtime_error("could not find an offer with this identifier");
	unsigned int memPoolQty = QtyOfPendingAcceptsInMempool(vchOffer);
	if(theOffer.nQty != -1 && theOffer.nQty < (nQty+memPoolQty))
		throw runtime_error(strprintf("not enough remaining quantity to fulfill this escrow, qty remaining %u, qty desired %u,  qty waiting to be accepted by the network %d", theOffer.nQty, nQty, memPoolQty));


	vchSellerPubKey = theOffer.vchPubKey;
	if(!theOffer.vchLinkOffer.empty())
	{
		if(pofferdb->ExistsOffer(theOffer.vchLinkOffer))
		{
			CTransaction tmpTx;
			if (!GetTxOfOffer( theOffer.vchLinkOffer, linkedOffer, tmpTx, true))
				throw runtime_error("Trying to accept a linked offer but could not find parent offer");
			if (linkedOffer.bOnlyAcceptBTC)
				throw runtime_error("Linked offer only accepts Bitcoins, linked offers currently only work with Syscoin payments");
			vchSellerPubKey = linkedOffer.vchPubKey;
		}
	}
	COfferLinkWhitelistEntry foundAlias;
	CAliasIndex theAlias;
	const CWalletTx *wtxAliasIn = NULL;
	vector<unsigned char> vchWhitelistAlias;
	CScript scriptPubKeyAlias, scriptPubKeyAliasOrig;
	// go through the whitelist and see if you own any of the aliases to apply to this offer for a discount
	for(unsigned int i=0;i<theOffer.linkWhitelist.entries.size();i++) {
		CTransaction txAlias;	
		vector<vector<unsigned char> > vvch;
		COfferLinkWhitelistEntry& entry = theOffer.linkWhitelist.entries[i];
		// make sure this alias is still valid
		if (GetTxOfAlias(entry.aliasLinkVchRand, theAlias, txAlias))
		{
			// check for existing alias updates/transfers
			if (ExistsInMempool(entry.aliasLinkVchRand, OP_ALIAS_UPDATE)) {
				throw runtime_error("there is are pending operations on that alias");
			}
			// make sure its in your wallet (you control this alias)
			wtxAliasIn = pwalletMain->GetWalletTx(txAlias.GetHash());		
			if (IsSyscoinTxMine(txAlias, "alias") && wtxAliasIn != NULL) 
			{
				foundAlias = entry;
				vchWhitelistAlias = entry.aliasLinkVchRand;
				CPubKey currentKey(theAlias.vchPubKey);
				scriptPubKeyAliasOrig = GetScriptForDestination(currentKey.GetID());
			}		
		}
	}
	scriptPubKeyAlias << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << vchWhitelistAlias << theAlias.vchGUID << OP_2DROP << OP_DROP;
	scriptPubKeyAlias += scriptPubKeyAliasOrig;

	if (ExistsInMempool(vchOffer, OP_OFFER_ACTIVATE) || ExistsInMempool(vchOffer, OP_OFFER_UPDATE)) {
		throw runtime_error("there are pending operations on that offer");
	}
	
    // gather inputs
	int64_t rand = GetRand(std::numeric_limits<int64_t>::max());
	vector<unsigned char> vchRand = CScriptNum(rand).getvch();
    vector<unsigned char> vchEscrow = vchFromValue(HexStr(vchRand));

    // this is a syscoin transaction
    CWalletTx wtx;
	EnsureWalletIsUnlocked();
    CScript scriptPubKey, scriptPubKeyBuyer, scriptPubKeySeller, scriptPubKeyArbiter,scriptBuyer, scriptSeller,scriptArbiter;

	string strCipherText = "";
	// encrypt to offer owner
	if(!EncryptMessage(vchSellerPubKey, vchMessage, strCipherText))
		throw runtime_error("could not encrypt message to seller");
	
	if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		throw runtime_error("offeraccept message length cannot exceed 1023 bytes!");

	CPubKey ArbiterPubKey(arbiteralias.vchPubKey);
	CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
	arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());
	if(!arbiteraddy.IsValid() || !arbiteraddy.isAlias)
		throw runtime_error("Invalid arbiter alias or address");

	CPubKey SellerPubKey(vchSellerPubKey);
	CSyscoinAddress selleraddy(SellerPubKey.GetID());
	selleraddy = CSyscoinAddress(selleraddy.ToString());
	if(!selleraddy.IsValid() || !selleraddy.isAlias)
		throw runtime_error("Invalid seller alias or address");

	CPubKey BuyerPubKey(buyeralias.vchPubKey);
	scriptArbiter= GetScriptForDestination(ArbiterPubKey.GetID());
	scriptSeller= GetScriptForDestination(SellerPubKey.GetID());
	scriptBuyer= GetScriptForDestination(BuyerPubKey.GetID());
	scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << OP_2DROP;
	scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow  << OP_2DROP;
	scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow << OP_2DROP;
	scriptPubKeySeller += scriptSeller;
	scriptPubKeyArbiter += scriptArbiter;
	scriptPubKeyBuyer += scriptBuyer;

	UniValue arrayParams(UniValue::VARR);
	UniValue arrayOfKeys(UniValue::VARR);

	// standard 2 of 3 multisig
	arrayParams.push_back(2);
	arrayOfKeys.push_back(HexStr(arbiteralias.vchPubKey));
	arrayOfKeys.push_back(HexStr(vchSellerPubKey));
	arrayOfKeys.push_back(HexStr(buyeralias.vchPubKey));
	arrayParams.push_back(arrayOfKeys);
	UniValue resCreate;
	try
	{
		resCreate = tableRPC.execute("createmultisig", arrayParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resCreate.isObject())
		throw runtime_error("Could not create escrow transaction: Invalid response from createescrow!");
	const UniValue &o = resCreate.get_obj();
	vector<unsigned char> redeemScript;
	const UniValue& redeemScript_value = find_value(o, "redeemScript");
	if (redeemScript_value.isStr())
	{
		redeemScript = ParseHex(redeemScript_value.get_str());
		scriptPubKey = CScript(redeemScript.begin(), redeemScript.end());
	}
	else
		throw runtime_error("Could not create escrow transaction: could not find redeem script in response!");
	// send to escrow address

	int precision = 2;
	CAmount nPricePerUnit = convertCurrencyCodeToSyscoin(theOffer.vchAliasPeg, theOffer.sCurrencyCode, theOffer.GetPrice(foundAlias), chainActive.Tip()->nHeight, precision);
	CAmount nTotal = nPricePerUnit*nQty;

	CAmount nEscrowFee = GetEscrowArbiterFee(nTotal);
	CRecipient recipientFee;
	CreateRecipient(scriptPubKey, recipientFee);
	CAmount nAmountWithFee = nTotal+nEscrowFee+recipientFee.nAmount;

	CWalletTx escrowWtx;
	vector<CRecipient> vecSendEscrow;
	CRecipient recipientEscrow  = {scriptPubKey, nAmountWithFee, false};
	vecSendEscrow.push_back(recipientEscrow);
	
	SendMoneySyscoin(vecSendEscrow, recipientEscrow.nAmount, false, escrowWtx, NULL, NULL, NULL, NULL, false);
	
	// send to seller/arbiter so they can track the escrow through GUI
    // build escrow
    CEscrow newEscrow;
	newEscrow.op = OP_ESCROW_ACTIVATE;
	newEscrow.vchEscrow = vchEscrow;
	newEscrow.vchBuyerKey = buyeralias.vchPubKey;
	newEscrow.vchArbiterKey = arbiteralias.vchPubKey;
	newEscrow.vchWhitelistAlias = vchWhitelistAlias;
	newEscrow.vchRedeemScript = redeemScript;
	newEscrow.vchOffer = vchOffer;
	newEscrow.vchSellerKey = vchSellerPubKey;
	newEscrow.vchPaymentMessage = vchFromString(strCipherText);
	newEscrow.nQty = nQty;
	newEscrow.escrowInputTxHash = escrowWtx.GetHash();
	newEscrow.nPricePerUnit = nPricePerUnit;
	newEscrow.nHeight = chainActive.Tip()->nHeight;
	// send the tranasction
	vector<CRecipient> vecSend;
	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	CRecipient recipientSeller;
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	vecSend.push_back(recipientSeller);
	CRecipient aliasRecipient;
	CreateRecipient(scriptPubKeyAlias, aliasRecipient);
	// if we use an alias as input to this escrow tx, we need another utxo for further alias transactions on this alias, so we create one here
	if(wtxAliasIn != NULL)
		vecSend.push_back(aliasRecipient);

	CRecipient recipientBuyer;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);

	const vector<unsigned char> &data = newEscrow.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	SendMoneySyscoin(vecSend,recipientBuyer.nAmount+ recipientArbiter.nAmount+recipientSeller.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxAliasIn, wtxInEscrow);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchRand));
	return res;
}
UniValue escrowrelease(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowrelease <escrow guid>\n"
                        "Releases escrow funds to seller, seller needs to sign the output transaction and send to the network.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch) 
    	|| !IsEscrowOp(op))
        throw runtime_error("could not decode escrow tx");
	const CWalletTx *wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this escrow is not in your wallet");

    // unserialize escrow UniValue from txn
    CEscrow theEscrow;
    if(!theEscrow.UnserializeFromTx(tx))
        throw runtime_error("cannot unserialize escrow from txn");
	vector<CEscrow> vtxPos;
	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, escrow.escrowInputTxHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("failed to find escrow transaction");

	CPubKey arbiterKey(escrow.vchArbiterKey);
	CSyscoinAddress arbiterAddress(arbiterKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	CPubKey buyerKey(escrow.vchBuyerKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");
	
	CPubKey sellerKey(escrow.vchSellerKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");
	bool foundSellerKey = false;
	try
	{
		// if this is the seller calling release, try to claim the release
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw runtime_error("Seller address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for seller address " + sellerAddress.ToString() + " is not known");
		foundSellerKey = true;
		
	}
	catch(...)
	{
		foundSellerKey = false;
	}
	if(foundSellerKey)
		return tableRPC.execute("escrowclaimrelease", params);
    if (op != OP_ESCROW_ACTIVATE)
        throw runtime_error("Release can only happen on an activated escrow");
	int nOutMultiSig = 0;
	CScript redeemScriptPubKey = CScript(escrow.vchRedeemScript.begin(), escrow.vchRedeemScript.end());
	CRecipient recipientFee;
	CreateRecipient(redeemScriptPubKey, recipientFee);
	int64_t nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64_t nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64_t nExpectedAmountWithFee = nExpectedAmount+nEscrowFee+recipientFee.nAmount;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64_t nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");

	string strPrivateKey ;
	bool arbiterSigning = false;
	// who is initiating release arbiter or buyer?
	try
	{
		arbiterSigning = true;
		// try arbiter
		CKeyID keyID;
		if (!arbiterAddress.GetKeyID(keyID))
			throw runtime_error("Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for arbiter address " + arbiterAddress.ToString() + " is not known");
		strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	}
	catch(...)
	{
		arbiterSigning = false;
		// otherwise try buyer
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw runtime_error("Buyer or Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Buyer or Arbiter private keys not known");
		strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	}
     	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)) {
		throw runtime_error("there are pending operations on that escrow");
	}
	// create a raw tx that sends escrow amount to seller and collateral to buyer
    // inputs buyer txHash
	UniValue arrayCreateParams(UniValue::VARR);
	UniValue createTxInputsArray(UniValue::VARR);
	UniValue createTxInputUniValue(UniValue::VOBJ);
	UniValue createAddressUniValue(UniValue::VOBJ);
	createTxInputUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	createTxInputUniValue.push_back(Pair("vout", nOutMultiSig));
	createTxInputsArray.push_back(createTxInputUniValue);
	if(arbiterSigning)
	{
		createAddressUniValue.push_back(Pair(sellerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(arbiterAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else
	{
		createAddressUniValue.push_back(Pair(sellerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}

	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressUniValue);
	UniValue resCreate;
	try
	{
		resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}	
	if (!resCreate.isStr())
		throw runtime_error("Could not create escrow transaction: Invalid response from createrawtransaction!");
	string createEscrowSpendingTx = resCreate.get_str();

	// Buyer/Arbiter signs it
	UniValue arraySignParams(UniValue::VARR);
	UniValue arraySignInputs(UniValue::VARR);
	UniValue arrayPrivateKeys(UniValue::VARR);

	UniValue signUniValue(UniValue::VOBJ);
	signUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signUniValue.push_back(Pair("vout", nOutMultiSig));
	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
	arraySignParams.push_back(createEscrowSpendingTx);
	arraySignInputs.push_back(signUniValue);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	UniValue res;
	try
	{
		res = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error("Could not sign escrow transaction: " + find_value(objError, "message").get_str());
	}	
	if (!res.isObject())
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	const UniValue& o = res.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();


	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_RELEASE;
	escrow.rawTx = ParseHex(hex_str);
	escrow.nHeight = chainActive.Tip()->nHeight;

    CScript scriptPubKey, scriptPubKeySeller;
	scriptPubKeySeller= GetScriptForDestination(sellerKey.GetID());
    scriptPubKey << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << OP_2DROP;
    scriptPubKey += scriptPubKeySeller;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	const vector<unsigned char> &data = escrow.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInAlias=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxInAlias, wtxIn);
	UniValue ret(UniValue::VARR);
	ret.push_back(wtx.GetHash().GetHex());
	return ret;
}
UniValue escrowclaimrelease(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrelease <escrow guid>\n"
                        "Claim escrow funds released from buyer or arbiter using escrowrelease.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);


	EnsureWalletIsUnlocked();
    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
	vector<CEscrow> vtxPos;
	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, escrow.escrowInputTxHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("failed to find escrow transaction");

 	int nOutMultiSig = 0;
	CScript redeemScriptPubKey = CScript(escrow.vchRedeemScript.begin(), escrow.vchRedeemScript.end());
	CRecipient recipientFee;
	CreateRecipient(redeemScriptPubKey, recipientFee);
	int64_t nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64_t nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64_t nExpectedAmountWithFee = nExpectedAmount+nEscrowFee+recipientFee.nAmount;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64_t nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");
	// decode rawTx and check it pays enough and it pays to buyer/seller appropriately
	// check that right amount is going to be sent to seller
	bool foundSellerPayment = false;
	bool foundFeePayment = false;
	UniValue arrayDecodeParams(UniValue::VARR);
	arrayDecodeParams.push_back(HexStr(escrow.rawTx));
	UniValue decodeRes;
	try
	{
		decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!decodeRes.isObject())
		throw runtime_error("Could not decode escrow transaction: Invalid response from decoderawtransaction!");
	const UniValue& decodeo = decodeRes.get_obj();
	const UniValue& vout_value = find_value(decodeo, "vout");
	if (!vout_value.isArray())
		throw runtime_error("Could not decode escrow transaction: Can't find vout's from transaction!");	
	const UniValue &vouts = vout_value.get_array();
    for (unsigned int idx = 0; idx < vouts.size(); idx++) {
        const UniValue& vout = vouts[idx];					
		const UniValue &voutObj = vout.get_obj();					
		const UniValue &voutValue = find_value(voutObj, "value");
		if(!voutValue.isNum())
			throw runtime_error("Could not decode escrow transaction: Invalid vout value!");
		int64_t iVout = AmountFromValue(voutValue);
		UniValue scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(!scriptPubKeyValue.isObject())
			throw runtime_error("Could not decode escrow transaction: Invalid scriptPubKey UniValue!");
		const UniValue &scriptPubKeyValueObj = scriptPubKeyValue.get_obj();	
		const UniValue &addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(!addressesValue.isArray())
			throw runtime_error("Could not decode escrow transaction: Invalid addresses UniValue!");

		const UniValue &addresses = addressesValue.get_array();
		for (unsigned int idx = 0; idx < addresses.size(); idx++) {
			const UniValue& address = addresses[idx];
			if(!address.isStr())
				throw runtime_error("Could not decode escrow transaction: Invalid address UniValue!");
			const string &strAddress = address.get_str();
			CSyscoinAddress payoutAddress(strAddress);
			// check arb fee is paid to arbiter or buyer
			if(!foundFeePayment)
			{
				CPubKey arbiterKey(escrow.vchArbiterKey);
				CSyscoinAddress arbiterAddress(arbiterKey.GetID());
				if(arbiterAddress == payoutAddress && iVout == nEscrowFee)
					foundFeePayment = true;
			}
			if(!foundFeePayment)
			{
				CPubKey buyerKey(escrow.vchBuyerKey);
				CSyscoinAddress buyerAddress(buyerKey.GetID());
				if(buyerAddress == payoutAddress && iVout == nEscrowFee)
					foundFeePayment = true;
			}	
			if(IsMine(*pwalletMain, payoutAddress.Get()))
			{
				if(!foundSellerPayment)
				{
					if(iVout == nExpectedAmount)
					{
						foundSellerPayment = true;
					}
				}
			}
		}
	}


	CKeyID keyID;
	CPubKey sellerKey(escrow.vchSellerKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");

	if (!sellerAddress.GetKeyID(keyID))
		throw runtime_error("Seller address does not refer to a key");
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw runtime_error("Private key for seller address " + sellerAddress.ToString() + " is not known");
	const string &strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	if(!foundSellerPayment)
		throw runtime_error("Expected payment amount from escrow does not match what was expected by the seller!");	
	if(!foundFeePayment)    
		throw runtime_error("Expected fee payment to arbiter or buyer from escrow does not match what was expected!");	
	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE) ) {
		throw runtime_error("there are pending operations on that escrow");
	}
    // Seller signs it
	UniValue arraySignParams(UniValue::VARR);
	UniValue arraySignInputs(UniValue::VARR);
	UniValue arrayPrivateKeys(UniValue::VARR);
	UniValue signUniValue(UniValue::VOBJ);
	signUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signUniValue.push_back(Pair("vout", nOutMultiSig));
	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
	arraySignParams.push_back(HexStr(escrow.rawTx));
	arraySignInputs.push_back(signUniValue);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	UniValue res;
	try
	{
		res = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error("Could not sign escrow transaction: " + find_value(objError, "message").get_str());
	}	
	if (!res.isObject())
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	const UniValue& o = res.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();

	const UniValue& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.isBool())
		bComplete = complete_value.get_bool();

	if(!bComplete)
		throw runtime_error("Could not sign escrow transaction. It is showing as incomplete, you may not allowed to complete this request at this time.");

	// broadcast the payment transaction
	UniValue arraySendParams(UniValue::VARR);
	arraySendParams.push_back(hex_str);
	try
	{
		res = tableRPC.execute("sendrawtransaction", arraySendParams);
	}
	catch (UniValue& objError)
	{
		string rawtxError = find_value(objError, "message").get_str();
		UniValue arrayAcceptParams(UniValue::VARR);
		arrayAcceptParams.push_back(stringFromVch(vchEscrow));
		try
		{
			res = tableRPC.execute("escrowcomplete", arrayAcceptParams);
		}
		catch (UniValue& objError)
		{
			throw runtime_error(rawtxError);
		}
		if (!res.isArray())
			throw runtime_error("Could not complete escrow: Invalid response from escrowcomplete!");
		return res;
	}
	if (!res.isStr())
		throw runtime_error("Could not send escrow transaction: Invalid response from sendrawtransaction!");


	UniValue arrayAcceptParams(UniValue::VARR);
	arrayAcceptParams.push_back(stringFromVch(vchEscrow));
	try
	{
		res = tableRPC.execute("escrowcomplete", arrayAcceptParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!res.isArray())
		throw runtime_error("Could not complete escrow: Invalid response from escrowcomplete!");
	return res;

	
	
}
UniValue escrowcomplete(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowcomplete <escrow guid>\n"
                         "Accepts an offer that's in escrow, to complete the escrow process.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
	CWalletTx wtx;
	CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
	uint256 hash;
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch) 
    	|| !IsEscrowOp(op) 
    	|| (op != OP_ESCROW_RELEASE))
        throw runtime_error("Can only complete an escrow that has been released to you");
	const CWalletTx *wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this escrow is not in your wallet");
	
      	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE) ) {
		throw runtime_error("there are pending operations on that escrow");
	}
	CPubKey buyerKey(escrow.vchBuyerKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());
	buyerAddress = CSyscoinAddress(buyerAddress.ToString());
	if(!buyerAddress.IsValid() || !buyerAddress.isAlias )
		throw runtime_error("Buyer address is invalid!");

	UniValue acceptParams(UniValue::VARR);
	acceptParams.push_back(buyerAddress.aliasName);
	acceptParams.push_back(stringFromVch(escrow.vchOffer));
	acceptParams.push_back(static_cast<ostringstream*>( &(ostringstream() << escrow.nQty) )->str());
	acceptParams.push_back(stringFromVch(escrow.vchPaymentMessage));
	acceptParams.push_back("");
	acceptParams.push_back("");
	acceptParams.push_back(tx.GetHash().GetHex());

	UniValue res;
	try
	{
		res = tableRPC.execute("offeraccept", acceptParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}	
	if (!res.isArray())
		throw runtime_error("Could not complete escrow transaction: Invalid response from offeraccept!");

	const UniValue &arr = res.get_array();
	uint256 acceptTxHash(uint256S(arr[0].get_str()));
	const string &acceptGUID = arr[1].get_str();
	const CWalletTx *wtxAcceptIn;
	wtxAcceptIn = pwalletMain->GetWalletTx(acceptTxHash);
	if (wtxAcceptIn == NULL)
		throw runtime_error("offer accept is not in your wallet");
	UniValue ret(UniValue::VARR);
	ret.push_back(wtxAcceptIn->GetHash().GetHex());
	return ret;
}
UniValue escrowrefund(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowrefund <escrow guid>\n"
                         "Refunds escrow funds back to buyer, buyer needs to sign the output transaction and send to the network.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch) 
    	|| !IsEscrowOp(op))
        throw runtime_error("could not decode escrow tx");
	const CWalletTx *wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this escrow is not in your wallet");
    // unserialize escrow from txn
    CEscrow theEscrow;
    if(!theEscrow.UnserializeFromTx(tx))
        throw runtime_error("cannot unserialize escrow from txn");
	vector<CEscrow> vtxPos;
	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, escrow.escrowInputTxHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("failed to find escrow transaction");

	CPubKey arbiterKey(escrow.vchArbiterKey);
	CSyscoinAddress arbiterAddress(arbiterKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	CPubKey buyerKey(escrow.vchBuyerKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");
	
	CPubKey sellerKey(escrow.vchSellerKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");
	bool foundBuyerKey = false;
	try
	{
		// if this is the buyer calling refund, try to claim the refund
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw runtime_error("Buyer address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for buyer address " + buyerAddress.ToString() + " is not known");
		foundBuyerKey = true;
	}
	catch(...)
	{
		foundBuyerKey = false;
	}
	if(foundBuyerKey)
		return tableRPC.execute("escrowclaimrefund", params);
	if(op != OP_ESCROW_ACTIVATE)
		 throw runtime_error("Refund can only happen on an activated escrow");
	int nOutMultiSig = 0;
	CScript redeemScriptPubKey = CScript(escrow.vchRedeemScript.begin(), escrow.vchRedeemScript.end());
	CRecipient recipientFee;
	CreateRecipient(redeemScriptPubKey, recipientFee);
	int64_t nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64_t nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64_t nExpectedAmountWithFee = nExpectedAmount+nEscrowFee+recipientFee.nAmount;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64_t nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");
	string strPrivateKey ;
	bool arbiterSigning = false;
	// who is initiating release arbiter or seller?
	try
	{
		arbiterSigning = true;
		// try arbiter
		CKeyID keyID;
		if (!arbiterAddress.GetKeyID(keyID))
			throw runtime_error("Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for arbiter address " + arbiterAddress.ToString() + " is not known");
		strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	}
	catch(...)
	{
		arbiterSigning = false;
		// otherwise try seller
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw runtime_error("Seller or Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Seller or Arbiter private keys not known");
		strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	}
     	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE) ) {
		throw runtime_error("there are pending operations on that escrow");
	}
	// refunds buyer from escrow
	UniValue arrayCreateParams(UniValue::VARR);
	UniValue createTxInputsArray(UniValue::VARR);
	UniValue createTxInputUniValue(UniValue::VOBJ);
	UniValue createAddressUniValue(UniValue::VOBJ);
	createTxInputUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	createTxInputUniValue.push_back(Pair("vout", nOutMultiSig));
	createTxInputsArray.push_back(createTxInputUniValue);
	if(arbiterSigning)
	{
		createAddressUniValue.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressUniValue.push_back(Pair(arbiterAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else
	{
		createAddressUniValue.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nExpectedAmount+nEscrowFee)));
	}	
	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressUniValue);
	UniValue resCreate;
	try
	{
		resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!resCreate.isStr())
		throw runtime_error("Could not create escrow transaction: Invalid response from createrawtransaction!");
	string createEscrowSpendingTx = resCreate.get_str();

	// Buyer/Arbiter signs it
	UniValue arraySignParams(UniValue::VARR);
	UniValue arraySignInputs(UniValue::VARR);
	UniValue arrayPrivateKeys(UniValue::VARR);

	UniValue signUniValue(UniValue::VOBJ);
	signUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signUniValue.push_back(Pair("vout", nOutMultiSig));
	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
	arraySignParams.push_back(createEscrowSpendingTx);
	arraySignInputs.push_back(signUniValue);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	UniValue res;
	try
	{
		res = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error("Could not sign escrow transaction: " + find_value(objError, "message").get_str());
	}
	
	if (!res.isObject())
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	const UniValue& o = res.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();

	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_REFUND;
	escrow.rawTx = ParseHex(hex_str);
	escrow.nHeight = chainActive.Tip()->nHeight;


    CScript scriptPubKey, scriptPubKeyBuyer;
	scriptPubKeyBuyer= GetScriptForDestination(buyerKey.GetID());
    scriptPubKey << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << OP_2DROP;
    scriptPubKey += scriptPubKeyBuyer;
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	const vector<unsigned char> &data = escrow.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInAlias=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxInAlias, wtxIn);
	UniValue ret(UniValue::VARR);
	ret.push_back(wtx.GetHash().GetHex());
	return ret;
}
UniValue escrowclaimrefund(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrefund <escrow guid>\n"
                        "Claim escrow funds released from seller or arbiter using escrowrefund.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);


	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
	CWalletTx wtx;
	const CWalletTx *wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this escrow is not in your wallet");

	vector<CEscrow> vtxPos;
	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
    CTransaction fundingTx;
	if (!GetSyscoinTransaction(vtxPos.front().nHeight, escrow.escrowInputTxHash, fundingTx, Params().GetConsensus()))
		throw runtime_error("failed to find escrow transaction");

 	int nOutMultiSig = 0;
	// 0.5% escrow fee
	CScript redeemScriptPubKey = CScript(escrow.vchRedeemScript.begin(), escrow.vchRedeemScript.end());
	CRecipient recipientFee;
	CreateRecipient(redeemScriptPubKey, recipientFee);
	int64_t nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64_t nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64_t nExpectedAmountWithFee = nExpectedAmount+nEscrowFee+recipientFee.nAmount;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64_t nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");
	// decode rawTx and check it pays enough and it pays to buyer appropriately
	// check that right amount is going to be sent to buyer
	bool foundBuyerPayment = false;
	UniValue arrayDecodeParams(UniValue::VARR);

	arrayDecodeParams.push_back(HexStr(escrow.rawTx));
	UniValue decodeRes;
	try
	{
		decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!decodeRes.isObject())
		throw runtime_error("Could not decode escrow transaction: Invalid response from decoderawtransaction!");
	const UniValue& decodeo = decodeRes.get_obj();
	const UniValue& vout_value = find_value(decodeo, "vout");
	if (!vout_value.isArray())
		throw runtime_error("Could not decode escrow transaction: Can't find vout's from transaction!");	
	UniValue vouts = vout_value.get_array();
    for (unsigned int idx = 0; idx < vouts.size(); idx++) {
        const UniValue& vout = vouts[idx];					
		const UniValue &voutObj = vout.get_obj();					
		const UniValue &voutValue = find_value(voutObj, "value");
		if(!voutValue.isNum())
			throw runtime_error("Could not decode escrow transaction: Invalid vout value!");
		int64_t iVout = AmountFromValue(voutValue);
		UniValue scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(!scriptPubKeyValue.isObject())
			throw runtime_error("Could not decode escrow transaction: Invalid scriptPubKey UniValue!");
		const UniValue &scriptPubKeyValueObj = scriptPubKeyValue.get_obj();	
		const UniValue &addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(!addressesValue.isArray())
			throw runtime_error("Could not decode escrow transaction: Invalid addresses UniValue!");

		UniValue addresses = addressesValue.get_array();
		for (unsigned int idx = 0; idx < addresses.size(); idx++) {
			const UniValue& address = addresses[idx];
			if(!address.isStr())
				throw runtime_error("Could not decode escrow transaction: Invalid address UniValue!");
			string strAddress = address.get_str();
			CSyscoinAddress payoutAddress(strAddress);
			if(IsMine(*pwalletMain, payoutAddress.Get()))
			{
				if(!foundBuyerPayment)
				{
					if(iVout == (nExpectedAmount+nEscrowFee) || iVout == nExpectedAmount)
					{
						foundBuyerPayment = true;
						break;
					}
				}
			}
		}
	}

	// get buyer's private key for signing
	CKeyID keyID;
	CPubKey buyerKey(escrow.vchBuyerKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");
	if (!buyerAddress.GetKeyID(keyID))
		throw runtime_error("Buyer address does not refer to a key");
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw runtime_error("Private key for buyer address " + buyerAddress.ToString() + " is not known");
	string strPrivateKey = CSyscoinSecret(vchSecret).ToString();
	if(!foundBuyerPayment)
		throw runtime_error("Expected payment amount from escrow does not match what was expected by the buyer!");
      	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)  ) {
		throw runtime_error("there are pending operations on that escrow");
	}
    // Seller signs it
	UniValue arraySignParams(UniValue::VARR);
	UniValue arraySignInputs(UniValue::VARR);
	UniValue arrayPrivateKeys(UniValue::VARR);
	UniValue signUniValue(UniValue::VOBJ);
	signUniValue.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signUniValue.push_back(Pair("vout", nOutMultiSig));
	signUniValue.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signUniValue.push_back(Pair("redeemScript", HexStr(escrow.vchRedeemScript)));
	arraySignParams.push_back(HexStr(escrow.rawTx));
	arraySignInputs.push_back(signUniValue);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	UniValue res;
	try
	{
		res = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error("Could not sign escrow transaction: " + find_value(objError, "message").get_str());
	}
	if (!res.isObject())
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	const UniValue& o = res.get_obj();
	string hex_str = "";

	const UniValue& hex_value = find_value(o, "hex");
	if (hex_value.isStr())
		hex_str = hex_value.get_str();
	const UniValue& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.isBool())
		bComplete = complete_value.get_bool();

	if(!bComplete)
		throw runtime_error("Could not sign escrow transaction. It is showing as incomplete, you may not allowed to complete this request at this time.");

	// broadcast the payment transaction
	UniValue arraySendParams(UniValue::VARR);
	arraySendParams.push_back(hex_str);
	UniValue ret(UniValue::VARR);
	UniValue returnRes;
	try
	{
		returnRes = tableRPC.execute("sendrawtransaction", arraySendParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error(find_value(objError, "message").get_str());
	}
	if (!returnRes.isStr())
		throw runtime_error("Could not send escrow transaction: Invalid response from sendrawtransaction!");

	CPubKey sellerKey(escrow.vchSellerKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");

	CPubKey arbiterKey(escrow.vchArbiterKey);
	CSyscoinAddress arbiterAddress(sellerKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	escrow.ClearEscrow();
	escrow.op = OP_ESCROW_COMPLETE;
	escrow.nHeight = chainActive.Tip()->nHeight;
    CScript scriptPubKeyBuyer, scriptPubKeySeller,scriptPubKeyArbiter, scriptPubKeyBuyerDestination, scriptPubKeySellerDestination, scriptPubKeyArbiterDestination;
	scriptPubKeyBuyerDestination= GetScriptForDestination(buyerKey.GetID());
    scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
    scriptPubKeyBuyer += scriptPubKeyBuyerDestination;
 
	scriptPubKeySellerDestination= GetScriptForDestination(sellerKey.GetID());
    scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
    scriptPubKeySeller += scriptPubKeySellerDestination;

	scriptPubKeyArbiterDestination= GetScriptForDestination(arbiterKey.GetID());
    scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
    scriptPubKeyArbiter += scriptPubKeyArbiterDestination;

	vector<CRecipient> vecSend;
	CRecipient recipientBuyer;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	vecSend.push_back(recipientBuyer);
	CRecipient recipientSeller;
	CreateRecipient(scriptPubKeySeller, recipientSeller);
	vecSend.push_back(recipientSeller);
	CRecipient recipientArbiter;
	CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
	vecSend.push_back(recipientArbiter);

	const vector<unsigned char> &data = escrow.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInAlias=NULL;
	if(IsSys21Fork(chainActive.Tip()->nHeight))
		SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxInAlias, wtxIn);
	ret.push_back(wtx.GetHash().GetHex());
	return ret;
}
UniValue escrowfeedback(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 5)
        throw runtime_error(
		"escrowfeedback <escrow guid> [feedbackprimary] [ratingprimary] [feedbacksecondary] [ratingasecondary]\n"
                        "Send feedback for primary and secondary users in escrow, depending on who you are. Ratings are numbers from 1 to 5\n"
						"If you are the buyer, feedbackprimary is for seller and feedbacksecondary is for arbiter.\n"
						"If you are the seller, feedbackprimary is for buyer and feedbacksecondary is for arbiter.\n"
						"If you are the arbiter, feedbackprimary is for buyer and feedbacksecondary is for seller.\n"
						"If arbiter didn't do any work for this escrow you can leave his feedback empty and rating as a 0.\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
	int nRatingPrimary = 0;
	int nRatingSecondary = 0;
	vector<unsigned char> vchFeedbackPrimary;
	vector<unsigned char> vchFeedbackSecondary;
	if(params.size() > 1)
		vchFeedbackPrimary = vchFromValue(params[1]);
	if(params.size() > 2)
	{
		try {
			nRatingPrimary = atoi(params[2].get_str());
			if(nRatingPrimary < 0 || nRatingPrimary > 5)
				throw runtime_error("invalid primary rating value, must be less than or equal to 5 and greater than or equal to 0");

		} catch (std::exception &e) {
			throw runtime_error("invalid primary rating value");
		}
	}
	if(params.size() > 3)
		vchFeedbackSecondary = vchFromValue(params[3]);
	if(params.size() > 4)
	{
		try {
			nRatingSecondary = atoi(params[4].get_str());
			if(nRatingSecondary < 0 || nRatingSecondary > 5)
				throw runtime_error("invalid secondary rating value, must be less than or equal to 5 and greater than or equal to 0");

		} catch (std::exception &e) {
			throw runtime_error("invalid secondary rating value");
		}
	}
    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow( vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch) 
    	|| !IsEscrowOp(op))
        throw runtime_error("could not decode escrow tx");
	const CWalletTx *wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this escrow is not in your wallet");
	if(vvch.size() > 1 && vvch[1] == vchFromString("1") && vchFeedbackPrimary.size() <= 0 && vchFeedbackSecondary.size() <= 0)
		throw runtime_error("Feedback reply cannot be empty");
	CPubKey arbiterKey(escrow.vchArbiterKey);
	CSyscoinAddress arbiterAddress(arbiterKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	CPubKey buyerKey(escrow.vchBuyerKey);
	CSyscoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");
	
	CPubKey sellerKey(escrow.vchSellerKey);
	CSyscoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");
	bool foundBuyerKey = false;
	try
	{
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw runtime_error("Buyer address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for buyer address " + buyerAddress.ToString() + " is not known");
		foundBuyerKey = true;
	}
	catch(...)
	{
		foundBuyerKey = false;
	}
	bool foundSellerKey = false;
	try
	{
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw runtime_error("Seller address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for seller address " + sellerAddress.ToString() + " is not known");
		foundSellerKey = true;
	}
	catch(...)
	{
		foundSellerKey = false;
	}
	bool foundArbiterKey = false;
	try
	{
		CKeyID keyID;
		if (!arbiterAddress.GetKeyID(keyID))
			throw runtime_error("Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("Private key for arbiter address " + arbiterAddress.ToString() + " is not known");
		foundArbiterKey = true;
	}
	catch(...)
	{
		foundArbiterKey = false;
	}
     	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE) ) {
		throw runtime_error("there are pending operations on that escrow");
	}
	escrow.ClearEscrow();


	CScript scriptPubKeyBuyer, scriptPubKeySeller,scriptPubKeyArbiter, scriptPubKeyBuyerDestination, scriptPubKeySellerDestination, scriptPubKeyArbiterDestination;
	scriptPubKeyBuyerDestination= GetScriptForDestination(buyerKey.GetID());
	scriptPubKeySellerDestination= GetScriptForDestination(sellerKey.GetID());
	scriptPubKeyArbiterDestination= GetScriptForDestination(arbiterKey.GetID());
	vector<CRecipient> vecSend;
	CRecipient recipientBuyer, recipientSeller, recipientArbiter;

	// buyer
	if(foundBuyerKey)
	{
		CEscrowFeedback sellerFeedback(BUYER);
		sellerFeedback.vchFeedback = vchFeedbackPrimary;
		sellerFeedback.nRating = nRatingPrimary;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		CEscrowFeedback arbiterFeedback(BUYER);
		arbiterFeedback.vchFeedback = vchFeedbackSecondary;
		arbiterFeedback.nRating = nRatingSecondary;
		arbiterFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.arbiterFeedback = arbiterFeedback;
		escrow.sellerFeedback = sellerFeedback;

		scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeySeller += scriptPubKeySellerDestination;
		scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeyArbiter += scriptPubKeyArbiterDestination;   
		CreateRecipient(scriptPubKeySeller, recipientSeller);
		vecSend.push_back(recipientSeller);
		CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
		vecSend.push_back(recipientArbiter);
	}
	// seller
	else if(foundSellerKey)
	{
		CEscrowFeedback buyerFeedback(SELLER);
		buyerFeedback.vchFeedback = vchFeedbackPrimary;
		buyerFeedback.nRating = nRatingPrimary;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		CEscrowFeedback arbiterFeedback(SELLER);
		arbiterFeedback.vchFeedback = vchFeedbackSecondary;
		arbiterFeedback.nRating = nRatingSecondary;
		arbiterFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.buyerFeedback = buyerFeedback;
		escrow.arbiterFeedback = arbiterFeedback;
		scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeyBuyer += scriptPubKeyBuyerDestination;
		scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeyArbiter += scriptPubKeyArbiterDestination; 
		CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
		vecSend.push_back(recipientBuyer);
		CreateRecipient(scriptPubKeyArbiter, recipientArbiter);
		vecSend.push_back(recipientArbiter);
	}
	// arbiter
	else if(foundArbiterKey)
	{
		CEscrowFeedback buyerFeedback(ARBITER);
		buyerFeedback.vchFeedback = vchFeedbackPrimary;
		buyerFeedback.nRating = nRatingPrimary;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		CEscrowFeedback sellerFeedback(ARBITER);
		sellerFeedback.vchFeedback = vchFeedbackSecondary;
		sellerFeedback.nRating = nRatingSecondary;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		escrow.buyerFeedback = buyerFeedback;
		escrow.sellerFeedback = sellerFeedback;
		scriptPubKeyBuyer << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeyBuyer += scriptPubKeyBuyerDestination;
		scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << vchFromString("1") << OP_2DROP << OP_DROP;
		scriptPubKeySeller += scriptPubKeySellerDestination;
		CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
		vecSend.push_back(recipientBuyer);
		CreateRecipient(scriptPubKeySeller, recipientSeller);
		vecSend.push_back(recipientSeller);
	}
	else
	{
		throw runtime_error("You must be either the arbiter, buyer or seller to leave feedback on this escrow");
	}
	escrow.op = OP_ESCROW_COMPLETE;
	escrow.nHeight = chainActive.Tip()->nHeight;


	const vector<unsigned char> &data = escrow.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInAlias=NULL;
	if(IsSys21Fork(chainActive.Tip()->nHeight))
		SendMoneySyscoin(vecSend, recipientBuyer.nAmount+recipientSeller.nAmount+recipientArbiter.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxInAlias, wtxIn);
	UniValue ret(UniValue::VARR);
	ret.push_back(wtx.GetHash().GetHex());
	return ret;
}
UniValue escrowinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowinfo <guid>\n"
                "Show stored values of a single escrow and its .\n");

    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an escrow UniValue if it is found
    CTransaction tx;

	vector<CEscrow> vtxPos;

    UniValue oEscrow(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw runtime_error("failed to read from escrow DB");
	CEscrow ca = vtxPos.back();
	CTransaction offertx;
	COffer offer;
	if (!GetTxOfOffer(ca.vchOffer, offer, offertx, true))
		throw runtime_error("failed to read from offer DB");
	
    string sHeight = strprintf("%llu", ca.nHeight);
    oEscrow.push_back(Pair("escrow", stringFromVch(vchEscrow)));
	string sTime;
	CBlockIndex *pindex = chainActive[ca.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	int avgBuyerRating, avgSellerRating, avgArbiterRating;
	vector<CEscrowFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
	GetFeedbackInEscrow(buyerFeedBacks, avgBuyerRating, BUYER, vtxPos);
	GetFeedbackInEscrow(sellerFeedBacks, avgSellerRating, SELLER, vtxPos);
	GetFeedbackInEscrow(arbiterFeedBacks, avgArbiterRating, ARBITER, vtxPos);
		
	CPubKey SellerPubKey(ca.vchSellerKey);
	CSyscoinAddress selleraddy(SellerPubKey.GetID());
	selleraddy = CSyscoinAddress(selleraddy.ToString());

	CPubKey ArbiterPubKey(ca.vchArbiterKey);
	CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
	arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());

	CPubKey BuyerPubKey(ca.vchBuyerKey);
	CSyscoinAddress buyeraddy(BuyerPubKey.GetID());
	buyeraddy = CSyscoinAddress(buyeraddy.ToString());

	oEscrow.push_back(Pair("time", sTime));
	oEscrow.push_back(Pair("seller", selleraddy.aliasName));
	oEscrow.push_back(Pair("arbiter", arbiteraddy.aliasName));
	oEscrow.push_back(Pair("buyer", buyeraddy.aliasName));
	oEscrow.push_back(Pair("offer", stringFromVch(ca.vchOffer)));
	oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
	oEscrow.push_back(Pair("offeracceptlink", stringFromVch(ca.vchOfferAcceptLink)));
	oEscrow.push_back(Pair("systotal", ValueFromAmount(ca.nPricePerUnit * ca.nQty)));
	int64_t nEscrowFee = GetEscrowArbiterFee(ca.nPricePerUnit * ca.nQty);
	oEscrow.push_back(Pair("sysfee", ValueFromAmount(nEscrowFee)));
	string sTotal = strprintf("%" PRIu64" SYS", ((nEscrowFee+ca.nPricePerUnit)*ca.nQty)/COIN);
	oEscrow.push_back(Pair("total", sTotal));
    oEscrow.push_back(Pair("txid", ca.txHash.GetHex()));
    oEscrow.push_back(Pair("height", sHeight));
	string strMessage = string("");
	if(!DecryptMessage(ca.vchSellerKey, ca.vchPaymentMessage, strMessage))
		strMessage = string("Encrypted for owner of offer");
	oEscrow.push_back(Pair("pay_message", strMessage));
	oEscrow.push_back(Pair("rawpay_message", stringFromVch(ca.vchPaymentMessage)));
	int expired_block = ca.nHeight + GetEscrowExpirationDepth();
	int expired = 0;
    if(expired_block < chainActive.Tip()->nHeight && ca.op == OP_ESCROW_COMPLETE)
	{
		expired = 1;
	}  
	oEscrow.push_back(Pair("expired", expired));
	UniValue oBuyerFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<buyerFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUser));
		oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
		oBuyerFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("buyer_feedback", oBuyerFeedBack));
	oEscrow.push_back(Pair("avg_buyer_rating", avgBuyerRating));
	UniValue oSellerFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<sellerFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUser));
		oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
		oSellerFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("seller_feedback", oSellerFeedBack));
	oEscrow.push_back(Pair("avg_seller_rating", avgSellerRating));
	UniValue oArbiterFeedBack(UniValue::VARR);
	for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
		oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUser));
		oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
		oArbiterFeedBack.push_back(oFeedback);
	}
	oEscrow.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
	oEscrow.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
	unsigned int ratingCount = 0;
	if(avgArbiterRating > 0)
		ratingCount++;
	if(avgSellerRating > 0)
		ratingCount++;
	if(avgBuyerRating > 0)
		ratingCount++;
	if(ratingCount == 0)
		ratingCount = 1;
	float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
	oEscrow.push_back(Pair("avg_rating", (int)totalAvgRating));	
    return oEscrow;
}

UniValue escrowcipher(const UniValue& params, bool fHelp) {
    if (fHelp || 2 < params.size())
        throw runtime_error("escrowlist <alias> <message>\n"
                "calculate a cipher based on an alias and a message");
	vector<unsigned char> vchName = vchFromString(params[0].get_str());
	vector<unsigned char> vchMessage = vchFromString(params[1].get_str());
	EnsureWalletIsUnlocked();
	CTransaction tx;
	CAliasIndex theAlias;
	if (!GetTxOfAlias(vchName, theAlias, tx))
		throw runtime_error("could not find an alias with this name");
	string strCipherText;
	
	// encrypt using alias pub key
	if(!EncryptMessage(theAlias.vchPubKey, vchMessage, strCipherText))
	{
		throw runtime_error("Could not encrypt message!");
	}
	if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		throw runtime_error("data length cannot exceed 1023 bytes!");

	UniValue res(UniValue::VARR);
	res.push_back(strCipherText);
	return res;
}
UniValue escrowlist(const UniValue& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("escrowlist [<escrow>]\n"
                "list my own escrows");
	vector<unsigned char> vchName;

	if (params.size() == 1)
		vchName = vchFromValue(params[0]);
    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    UniValue oRes(UniValue::VARR);
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, UniValue > vNamesO;

    uint256 hash;
    CTransaction tx, dbtx;

    vector<unsigned char> vchValue;
    uint64_t nHeight;
	int pending = 0;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
    {
		int expired_block;
		int expired = 0;
		pending = 0;
        // get txn hash, read txn index
        hash = item.second.GetHash();
		const CWalletTx &wtx = item.second;        // skip non-syscoin txns
		CTransaction tx;
        if (wtx.nVersion != SYSCOIN_TX_VERSION)
            continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		if (!DecodeEscrowTx(wtx, op, nOut, vvch) || !IsEscrowOp(op))
			continue;
		vchName = vvch[0];
		vector<CEscrow> vtxPos;
		CEscrow escrow;
		if (!pescrowdb->ReadEscrow(vchName, vtxPos) || vtxPos.empty())
		{
			pending = 1;
			escrow = CEscrow(wtx);
		}
		else
		{
			escrow = vtxPos.back();
			CTransaction tx;
			if (!GetSyscoinTransaction(escrow.nHeight, escrow.txHash, tx, Params().GetConsensus()))
			{
				pending = 1;
			}
			else{
				if (!DecodeEscrowTx(tx, op, nOut, vvch) || !IsEscrowOp(op))
					continue;
			}
		}
		COffer offer;
		CTransaction offertx;
		if (!GetTxOfOffer(escrow.vchOffer, offer, offertx, true))
			continue;
		// skip this escrow if it doesn't match the given filter value
		if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
			continue;
		// get last active name only
		if (vNamesI.find(vchName) != vNamesI.end() && (escrow.nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
			continue;

		nHeight = escrow.nHeight;
        // build the output
        UniValue oName(UniValue::VOBJ);
        oName.push_back(Pair("escrow", stringFromVch(vchName)));
		string sTime;
		CBlockIndex *pindex = chainActive[escrow.nHeight];
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		int avgBuyerRating, avgSellerRating, avgArbiterRating;
		vector<CEscrowFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
		GetFeedbackInEscrow(buyerFeedBacks, avgBuyerRating, BUYER, vtxPos);
		GetFeedbackInEscrow(sellerFeedBacks, avgSellerRating, SELLER, vtxPos);
		GetFeedbackInEscrow(arbiterFeedBacks, avgArbiterRating, ARBITER, vtxPos);
		
		CPubKey SellerPubKey(escrow.vchSellerKey);
		CSyscoinAddress selleraddy(SellerPubKey.GetID());
		selleraddy = CSyscoinAddress(selleraddy.ToString());

		CPubKey ArbiterPubKey(escrow.vchArbiterKey);
		CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
		arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());

		CPubKey BuyerPubKey(escrow.vchBuyerKey);
		CSyscoinAddress buyeraddy(BuyerPubKey.GetID());
		buyeraddy = CSyscoinAddress(buyeraddy.ToString());

		oName.push_back(Pair("time", sTime));
		oName.push_back(Pair("seller", selleraddy.aliasName));
		oName.push_back(Pair("arbiter", arbiteraddy.aliasName));
		oName.push_back(Pair("buyer", buyeraddy.aliasName));
		oName.push_back(Pair("offer", stringFromVch(escrow.vchOffer)));
		oName.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
		oName.push_back(Pair("offeracceptlink", stringFromVch(escrow.vchOfferAcceptLink)));
		int64_t nEscrowFee = GetEscrowArbiterFee(escrow.nPricePerUnit * escrow.nQty);
		oName.push_back(Pair("sysfee", ValueFromAmount(nEscrowFee)));
		string sTotal = strprintf("%" PRIu64" SYS", ((nEscrowFee+escrow.nPricePerUnit)*escrow.nQty)/COIN);
		oName.push_back(Pair("total", sTotal));

		expired_block = nHeight + GetEscrowExpirationDepth();
        if(expired_block < chainActive.Tip()->nHeight && escrow.op == OP_ESCROW_COMPLETE)
		{
			expired = 1;
		} 
	
		string status = "unknown";
		if(pending == 0)
		{
			if(op == OP_ESCROW_ACTIVATE)
				status = "in-escrow";
			else if(op == OP_ESCROW_RELEASE)
				status = "escrow released";
			else if(op == OP_ESCROW_REFUND && vvch.size() == 1)
				status = "escrow refunded";
			else if(op == OP_ESCROW_REFUND && vvch.size() == 2 && vvch[1] == vchFromString("1"))
				status = "escrow refund complete";
			else if(op == OP_ESCROW_COMPLETE )
				status = "complete";
		}
		else
			status = "pending";
		UniValue oBuyerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<buyerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
			oBuyerFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("buyer_feedback", oBuyerFeedBack));
		oName.push_back(Pair("avg_buyer_rating", avgBuyerRating));
		UniValue oSellerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<sellerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
			oSellerFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("seller_feedback", oSellerFeedBack));
		oName.push_back(Pair("avg_seller_rating", avgSellerRating));
		UniValue oArbiterFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
			oArbiterFeedBack.push_back(oFeedback);
		}
		oName.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
		oName.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
		unsigned int ratingCount = 0;
		if(avgArbiterRating > 0)
			ratingCount++;
		if(avgSellerRating > 0)
			ratingCount++;
		if(avgBuyerRating > 0)
			ratingCount++;
		if(ratingCount == 0)
			ratingCount = 1;
		float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
		oName.push_back(Pair("avg_rating", (int)totalAvgRating));	
		oName.push_back(Pair("status", status));
		oName.push_back(Pair("expired", expired));
 
		vNamesI[vchName] = nHeight;
		vNamesO[vchName] = oName;	
		
    
	}
    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
        oRes.push_back(item.second);
    return oRes;
}


UniValue escrowhistory(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowhistory <escrow>\n"
                "List all stored values of an escrow.\n");

    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
    string escrow = stringFromVch(vchEscrow);

    {
        vector<CEscrow> vtxPos;
        if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
            throw runtime_error("failed to read from escrow DB");

        CEscrow txPos2;
        uint256 txHash;
        uint256 blockHash;
        BOOST_FOREACH(txPos2, vtxPos) {
            txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetSyscoinTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus())) {
				error("could not read txpos");
				continue;
			}
			COffer offer;
			CTransaction offertx;
			if (!GetTxOfOffer(txPos2.vchOffer, offer, offertx, true))
				continue;
            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeEscrowTx(tx, op, nOut, vvch) 
            	|| !IsEscrowOp(op) )
                continue;
			int expired = 0;
            UniValue oEscrow(UniValue::VOBJ);
            uint64_t nHeight;
			nHeight = txPos2.nHeight;
			oEscrow.push_back(Pair("escrow", escrow));
			string opName = escrowFromOp(op);
			oEscrow.push_back(Pair("escrowtype", opName));
			CPubKey SellerPubKey(txPos2.vchSellerKey);
			CSyscoinAddress selleraddy(SellerPubKey.GetID());
			selleraddy = CSyscoinAddress(selleraddy.ToString());

			CPubKey ArbiterPubKey(txPos2.vchArbiterKey);
			CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
			arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());

			CPubKey BuyerPubKey(txPos2.vchBuyerKey);
			CSyscoinAddress buyeraddy(BuyerPubKey.GetID());
			buyeraddy = CSyscoinAddress(buyeraddy.ToString());

			oEscrow.push_back(Pair("txid", tx.GetHash().GetHex()));
			oEscrow.push_back(Pair("seller", selleraddy.aliasName));
			oEscrow.push_back(Pair("arbiter", arbiteraddy.aliasName));
			oEscrow.push_back(Pair("buyer", buyeraddy.aliasName));
			oEscrow.push_back(Pair("offer", stringFromVch(txPos2.vchOffer)));
			oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
			oEscrow.push_back(Pair("offeracceptlink", stringFromVch(txPos2.vchOfferAcceptLink)));

			int64_t nEscrowFee = GetEscrowArbiterFee(txPos2.nPricePerUnit * txPos2.nQty);
			oEscrow.push_back(Pair("sysfee", ValueFromAmount(nEscrowFee)));
			string sTotal = strprintf("%" PRIu64" SYS", ((nEscrowFee+txPos2.nPricePerUnit)*txPos2.nQty)/COIN);
			oEscrow.push_back(Pair("total", sTotal));
			if(nHeight + GetEscrowExpirationDepth() - chainActive.Tip()->nHeight <= 0  && txPos2.op == OP_ESCROW_COMPLETE)
			{
				expired = 1;
			}  
	
			string status = "unknown";

			if(op == OP_ESCROW_ACTIVATE)
				status = "in-escrow";
			else if(op == OP_ESCROW_RELEASE)
				status = "escrow released";
			else if(op == OP_ESCROW_REFUND && vvch.size() == 1)
				status = "escrow refunded";
			else if(op == OP_ESCROW_REFUND && vvch.size() == 2 && vvch[1] == vchFromString("1"))
				status = "escrow refund complete";
			else if(op == OP_ESCROW_COMPLETE)
				status = "complete";

			oEscrow.push_back(Pair("status", status));
			oEscrow.push_back(Pair("expired", expired));
			oEscrow.push_back(Pair("height", strprintf("%d", nHeight)));
			oRes.push_back(oEscrow);
        }
        
    }
    return oRes;
}
UniValue escrowfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 2)
		throw runtime_error(
				"escrowfilter [[[[[regexp]] from=0]}\n"
						"scan and filter escrows\n"
						"[regexp] : apply [regexp] on escrows, empty means all escrows\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[escrowfilter] : shows all escrows that are safe to display (not on the ban list)\n"
						"escrowfilter \"\" 5 # list escrows updated in last 5 blocks\n"
						"escrowfilter \"^escrow\" # list all excrows starting with \"escrow\"\n"
						"escrowfilter 36000 0 0 stat # display stats (number of escrows) on active escrows\n");

	vector<unsigned char> vchEscrow;
	string strRegexp;

	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchEscrow = vchFromValue(params[1]);

	UniValue oRes(UniValue::VARR);

   
    vector<pair<vector<unsigned char>, CEscrow> > escrowScan;
    if (!pescrowdb->ScanEscrows(vchEscrow, strRegexp, 25, escrowScan))
        throw runtime_error("scan failed");
    pair<vector<unsigned char>, CEscrow> pairScan;
    BOOST_FOREACH(pairScan, escrowScan) {
		const CEscrow &txEscrow = pairScan.second;  
		const string &escrow = stringFromVch(pairScan.first);
		vector<COffer> vtxOfferPos;
		vector<CEscrow> vtxPos;
		COffer offer;
		if (pofferdb->ReadOffer(txEscrow.vchOffer, vtxOfferPos) && !vtxOfferPos.empty())
		{
			offer = vtxOfferPos.back();
		}
        int nHeight = txEscrow.nHeight;
		CTransaction tx;
		if (!GetSyscoinTransaction(nHeight, txEscrow.txHash, tx, Params().GetConsensus())) {
			continue;
		}
        // decode txn, skip non-alias txns
        vector<vector<unsigned char> > vvch;
        int op, nOut;
        if (!DecodeEscrowTx(tx, op, nOut, vvch) 
        	|| !IsEscrowOp(op) )
            continue; 
		int avgBuyerRating, avgSellerRating, avgArbiterRating;
		vector<CEscrowFeedback> buyerFeedBacks, sellerFeedBacks, arbiterFeedBacks;
		if (!pescrowdb->ReadEscrow(pairScan.first, vtxPos) || vtxPos.empty())
			continue;
		GetFeedbackInEscrow(buyerFeedBacks, avgBuyerRating, BUYER, vtxPos);
		GetFeedbackInEscrow(sellerFeedBacks, avgSellerRating, SELLER, vtxPos);
		GetFeedbackInEscrow(arbiterFeedBacks, avgArbiterRating, ARBITER, vtxPos);
		
		CPubKey SellerPubKey(txEscrow.vchSellerKey);
		CSyscoinAddress selleraddy(SellerPubKey.GetID());
		selleraddy = CSyscoinAddress(selleraddy.ToString());

		CPubKey ArbiterPubKey(txEscrow.vchArbiterKey);
		CSyscoinAddress arbiteraddy(ArbiterPubKey.GetID());
		arbiteraddy = CSyscoinAddress(arbiteraddy.ToString());

		CPubKey BuyerPubKey(txEscrow.vchBuyerKey);
		CSyscoinAddress buyeraddy(BuyerPubKey.GetID());
		buyeraddy = CSyscoinAddress(buyeraddy.ToString());
		int expired = 0;

        UniValue oEscrow(UniValue::VOBJ);
        oEscrow.push_back(Pair("escrow", escrow));
		if(nHeight + GetEscrowExpirationDepth() - chainActive.Tip()->nHeight <= 0 && txEscrow.op == OP_ESCROW_COMPLETE)
		{
			expired = 1;
		} 
		string sTime;
		CBlockIndex *pindex = chainActive[txEscrow.nHeight];
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		oEscrow.push_back(Pair("time", sTime));
		oEscrow.push_back(Pair("expired", expired));
		oEscrow.push_back(Pair("seller", selleraddy.aliasName));
		oEscrow.push_back(Pair("arbiter", arbiteraddy.aliasName));
		oEscrow.push_back(Pair("buyer", buyeraddy.aliasName));
		oEscrow.push_back(Pair("offer", stringFromVch(txEscrow.vchOffer)));
		oEscrow.push_back(Pair("offertitle", stringFromVch(offer.sTitle)));
		oEscrow.push_back(Pair("offeracceptlink", stringFromVch(txEscrow.vchOfferAcceptLink)));
	
		string status = "unknown";

		if(op == OP_ESCROW_ACTIVATE)
			status = "in-escrow";
		else if(op == OP_ESCROW_RELEASE)
			status = "escrow released";
		else if(op == OP_ESCROW_REFUND && vvch.size() == 1)
			status = "escrow refunded";
		else if(op == OP_ESCROW_REFUND && vvch.size() == 2 && vvch[1] == vchFromString("1"))
			status = "escrow refund complete";
		else if(op == OP_ESCROW_COMPLETE)
			status = "complete";
		

		oEscrow.push_back(Pair("status", status));
		int64_t nEscrowFee = GetEscrowArbiterFee(txEscrow.nPricePerUnit * txEscrow.nQty);
		oEscrow.push_back(Pair("sysfee", ValueFromAmount(nEscrowFee)));
		string sTotal = strprintf("%" PRIu64" SYS", ((nEscrowFee+txEscrow.nPricePerUnit)*txEscrow.nQty)/COIN);
		oEscrow.push_back(Pair("total", sTotal));
		UniValue oBuyerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<buyerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", buyerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[i].vchFeedback)));
			oBuyerFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("buyer_feedback", oBuyerFeedBack));
		oEscrow.push_back(Pair("avg_buyer_rating", avgBuyerRating));
		UniValue oSellerFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<sellerFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", sellerFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[i].vchFeedback)));
			oSellerFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("seller_feedback", oSellerFeedBack));
		oEscrow.push_back(Pair("avg_seller_rating", avgSellerRating));
		UniValue oArbiterFeedBack(UniValue::VARR);
		for(unsigned int i =0;i<arbiterFeedBacks.size();i++)
		{
			UniValue oFeedback(UniValue::VOBJ);
			string sFeedbackTime;
			CBlockIndex *pindex = chainActive[buyerFeedBacks[i].nHeight];
			if (pindex) {
				sFeedbackTime = strprintf("%llu", pindex->nTime);
			}
			oFeedback.push_back(Pair("time", sFeedbackTime));
			oFeedback.push_back(Pair("rating", arbiterFeedBacks[i].nRating));
			oFeedback.push_back(Pair("feedbackuser", arbiterFeedBacks[i].nFeedbackUser));
			oFeedback.push_back(Pair("feedback", stringFromVch(arbiterFeedBacks[i].vchFeedback)));
			oArbiterFeedBack.push_back(oFeedback);
		}
		oEscrow.push_back(Pair("arbiter_feedback", oArbiterFeedBack));
		oEscrow.push_back(Pair("avg_arbiter_rating", avgArbiterRating));
		unsigned int ratingCount = 0;
		if(avgArbiterRating > 0)
			ratingCount++;
		if(avgSellerRating > 0)
			ratingCount++;
		if(avgBuyerRating > 0)
			ratingCount++;
		if(ratingCount == 0)
			ratingCount = 1;
		float totalAvgRating = roundf((avgArbiterRating+avgSellerRating+avgBuyerRating)/(float)ratingCount);
		oEscrow.push_back(Pair("avg_rating", (int)totalAvgRating));	

        oRes.push_back(oEscrow);
    }


	return oRes;
}