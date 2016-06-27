// Copyright (c) 2014 Syscoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
#include "alias.h"
#include "offer.h"
#include "escrow.h"
#include "message.h"
#include "cert.h"
#include "offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "wallet/wallet.h"
#include "rpcserver.h"
#include "base58.h"
#include "txmempool.h"
#include "txdb.h"
#include "chainparams.h"
#include "policy/policy.h"
#include "utiltime.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/hex.hpp>
using namespace std;
CAliasDB *paliasdb = NULL;
COfferDB *pofferdb = NULL;
CCertDB *pcertdb = NULL;
CEscrowDB *pescrowdb = NULL;
CMessageDB *pmessagedb = NULL;
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInOffer=NULL, const CWalletTx* wtxInCert=NULL, const CWalletTx* wtxInAlias=NULL, const CWalletTx* wtxInEscrow=NULL, bool syscoinTx=true);
bool IsSysCompressedOrUncompressedPubKey(const vector<unsigned char> &vchPubKey) {
    if (vchPubKey.size() < 33) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
          //  Non-canonical public key: neither compressed nor uncompressed
          return false;
    }
    return true;
}
bool GetPreviousInput(const COutPoint * outpoint, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if(!pwalletMain || !outpoint)
		return false;
    map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(outpoint->hash);
    if (it != pwalletMain->mapWallet.end())
    {
        const CWalletTx* pcoin = &it->second;
		if(IsSyscoinScript(pcoin->vout[outpoint->n].scriptPubKey, op, vvchArgs))
			return true;

    } else
       return false;
    return false;
}
bool GetSyscoinTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams)
{
	CBlockIndex *pindexSlow = NULL; 
	TRY_LOCK(cs_main, cs_trymain);
	pindexSlow = chainActive[nHeight];
    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    return true;
                }
            }
        }
    }
	return false;
}
bool IsSys21Fork(const uint64_t& nHeight)
{
	if(nHeight <= SYSCOIN_FORK1 && ChainNameFromCommandLine() == CBaseChainParams::MAIN)
		return false;
	return true;
}
bool IsInSys21Fork(const CScript& scriptPubKey, uint64_t &nHeight)
{
	vector<unsigned char> vchData;
	if(!GetSyscoinData(scriptPubKey, vchData))
		return false;

	CAliasIndex alias;
	COffer offer;
	CMessage message;
	CEscrow escrow;
	CCert cert;
	nHeight = 0;
	const string &chainName = ChainNameFromCommandLine();
	if(alias.UnserializeFromData(vchData))
	{
		if(alias.vchName == vchFromString("SYS_RATES") || alias.vchName == vchFromString("SYS_BAN") || alias.vchName == vchFromString("SYS_CATEGORY"))
			return false;
		vector<CAliasIndex> vtxPos;
		if (paliasdb->ReadAlias(alias.vchName, vtxPos))
		{
			// have to check the first tx in the service because if it was created before the fork, the chain has hashed the data, so we can't prune it
			if(IsSys21Fork(vtxPos.front().nHeight))
			{
				if(!alias.vchGUID.empty() && vtxPos.back().vchGUID != alias.vchGUID)
					nHeight = alias.nHeight + GetAliasExpirationDepth();
				else
					nHeight = vtxPos.back().nHeight + GetAliasExpirationDepth();
				return true;	
			}		
		}
		else if(IsSys21Fork(alias.nHeight))
		{
			nHeight = alias.nHeight + GetAliasExpirationDepth();
			return true;
		}
	}
	else if(offer.UnserializeFromData(vchData))
	{
		vector<COffer> vtxPos;
		if (pofferdb->ReadOffer(offer.vchOffer, vtxPos))
		{
			// have to check the first tx in the service because if it was created before the fork, the chain has hashed the data, so we can't prune it
			if(IsSys21Fork(vtxPos.front().nHeight))
			{
				nHeight = vtxPos.back().nHeight + GetOfferExpirationDepth();
				return true;	
			}		
		}
		else if(IsSys21Fork(offer.nHeight))
		{
			nHeight = offer.nHeight + GetOfferExpirationDepth();
			return true;
		}
	}
	else if(cert.UnserializeFromData(vchData))
	{
		vector<CCert> vtxPos;
		if (pcertdb->ReadCert(cert.vchCert, vtxPos))
		{
			// have to check the first tx in the service because if it was created before the fork, the chain has hashed the data, so we can't prune it
			if(IsSys21Fork(vtxPos.front().nHeight))
			{
				nHeight = vtxPos.back().nHeight + GetCertExpirationDepth();
				return true;	
			}		
		}
		else if(IsSys21Fork(cert.nHeight))
		{
			nHeight = cert.nHeight + GetCertExpirationDepth();
			return true;
		}
	}
	else if(escrow.UnserializeFromData(vchData))
	{
		vector<CEscrow> vtxPos;
		if (pescrowdb->ReadEscrow(escrow.vchEscrow, vtxPos))
		{
			// have to check the first tx in the service because if it was created before the fork, the chain has hashed the data, so we can't prune it
			if(IsSys21Fork(vtxPos.front().nHeight))
			{
				// if escrow is not refunded or complete don't prune otherwise escrow gets stuck (coins are still safe, just a GUI thing)
				// by setting to chainheight + a number we effectively tell it not to prune ever unless its complete
				if(vtxPos.back().op != OP_ESCROW_COMPLETE)
					nHeight = chainActive.Tip()->nHeight + GetEscrowExpirationDepth();
				else
					nHeight = vtxPos.back().nHeight + GetEscrowExpirationDepth();
				return true;	
			}		
		}
		else if(IsSys21Fork(escrow.nHeight))
		{
			if(escrow.op != OP_ESCROW_COMPLETE)
				nHeight = chainActive.Tip()->nHeight + GetEscrowExpirationDepth();
			else
				nHeight = escrow.nHeight + GetEscrowExpirationDepth();
			return true;
		}
	}
	else if(message.UnserializeFromData(vchData))
	{
		vector<CMessage> vtxPos;
		if (pmessagedb->ReadMessage(message.vchMessage, vtxPos))
		{
			// have to check the first tx in the service because if it was created before the fork, the chain has hashed the data, so we can't prune it
			if(IsSys21Fork(vtxPos.front().nHeight))
			{
				nHeight = vtxPos.back().nHeight + GetMessageExpirationDepth();
				return true;	
			}		
		}
		else if(IsSys21Fork(message.nHeight))
		{
			nHeight = message.nHeight + GetMessageExpirationDepth();
			return true;
		}
	}

	return false;
}
bool IsSysServiceExpired(const uint64_t &nHeight)
{
	// if we don't have a chain or we are in txindex mode (no pruning or culling), the service never expires
	if(!chainActive.Tip() || fTxIndex)
		return false;
	return (nHeight < chainActive.Tip()->nHeight);

}
bool IsSyscoinScript(const CScript& scriptPubKey, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if (DecodeAliasScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeOfferScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeCertScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeMessageScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeEscrowScript(scriptPubKey, op, vvchArgs))
		return true;
	return false;
}
void RemoveSyscoinScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut)
{
	vector<vector<unsigned char> > vvch;
	int op;
	if (DecodeAliasScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveAliasScriptPrefix(scriptPubKeyIn);
	else if (DecodeOfferScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveOfferScriptPrefix(scriptPubKeyIn);
	else if (DecodeCertScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveCertScriptPrefix(scriptPubKeyIn);
	else if (DecodeEscrowScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveEscrowScriptPrefix(scriptPubKeyIn);
	else if (DecodeMessageScript(scriptPubKeyIn, op, vvch))
		scriptPubKeyOut = RemoveMessageScriptPrefix(scriptPubKeyIn);
}

unsigned int QtyOfPendingAcceptsInMempool(const vector<unsigned char>& vchToFind)
{
	LOCK(mempool.cs);
	unsigned int nQty = 0;
	for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
        const CTransaction& tx = mi->GetTx();
		if (tx.IsCoinBase() || !CheckFinalTx(tx))
			continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		
		if(DecodeOfferTx(tx, op, nOut, vvch)) {
			if(op == OP_OFFER_ACCEPT)
			{
				if(vvch.size() >= 1 && vvch[0] == vchToFind)
				{
					COffer theOffer(tx);
					COfferAccept theOfferAccept = theOffer.accept;
					if (theOffer.IsNull() || theOfferAccept.IsNull())
						continue;
					if(theOfferAccept.vchAcceptRand == vvch[1])
					{
						nQty += theOfferAccept.nQty;
					}
				}
			}
		}		
	}
	return nQty;

}
bool ExistsInMempool(const std::vector<unsigned char> &vchToFind, opcodetype type)
{
	LOCK(mempool.cs);
	for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
        const CTransaction& tx = mi->GetTx();
		if (tx.IsCoinBase() || !CheckFinalTx(tx))
			continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		if(IsAliasOp(type))
		{
			if(DecodeAliasTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsOfferOp(type))
		{
			if(DecodeOfferTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsCertOp(type))
		{
			if(DecodeCertTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsEscrowOp(type))
		{
			if(DecodeEscrowTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
		else if(IsMessageOp(type))
		{
			if(DecodeMessageTx(tx, op, nOut, vvch))
			{
				if(op == type)
				{
					if(vvch.size() >= 1 && vchToFind == vvch[0])
					{
						return true;
					}
				}
			}
		}
	}
	return false;

}

CAmount convertCurrencyCodeToSyscoin(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrencyCode, const float &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount sysPrice = 0;
	CAmount nRate;
	vector<string> rateList;
	try
	{
		if(getCurrencyToSYSFromAlias(vchAliasPeg, vchCurrencyCode, nRate, nHeight, rateList, precision) == "")
		{
			float price = nPrice*(float)nRate;
			sysPrice = CAmount(price);
		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("convertCurrencyCodeToSyscoin() Exception caught getting rate alias information\n");
	}
	if(precision > 8)
		sysPrice = 0;
	return sysPrice;
}
string getCurrencyToSYSFromAlias(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrency, CAmount &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision)
{
	string currencyCodeToFind = stringFromVch(vchCurrency);
	// check for alias existence in DB
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchAliasPeg, vtxPos) || vtxPos.empty())
	{
		if(fDebug)
			LogPrintf("getCurrencyToSYSFromAlias() Could not find %s alias\n", stringFromVch(vchAliasPeg).c_str());
		return "1";
	}
	
	if (vtxPos.size() < 1)
	{
		if(fDebug)
			LogPrintf("getCurrencyToSYSFromAlias() Could not find %s alias (vtxPos.size() == 0)\n", stringFromVch(vchAliasPeg).c_str());
		return "1";
	}
	CAliasIndex foundAlias;
	for(unsigned int i=0;i<vtxPos.size();i++) {
        CAliasIndex a = vtxPos[i];
        if(a.nHeight <= nHeightToFind) {
            foundAlias = a;
        }
		else
			break;
    }
	if(foundAlias.IsNull())
		foundAlias = vtxPos.back();


	bool found = false;
	string value = stringFromVch(foundAlias.vchPublicValue);
	
	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(value);
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue ratesValue = find_value(outerObj, "rates");
		if (ratesValue.isArray())
		{
			UniValue codes = ratesValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue currencyNameValue = find_value(codeObj, "currency");
				UniValue currencyAmountValue = find_value(codeObj, "rate");
				if (currencyNameValue.isStr())
				{		
					string currencyCode = currencyNameValue.get_str();
					rateList.push_back(currencyCode);
					if(currencyCodeToFind == currencyCode)
					{		
						UniValue precisionValue = find_value(codeObj, "precision");
						if(precisionValue.isNum())
						{
							precision = precisionValue.get_int();
						}
						if(currencyAmountValue.isNum())
						{
							found = true;
							try{
							
								float val = currencyAmountValue.get_real();
								nFee = AmountFromValue(strprintf("%.8f", val));
							}
							catch(std::runtime_error& err)
							{
								try
								{
									nFee = currencyAmountValue.get_int()*COIN;
								}
								catch(std::runtime_error& err)
								{
									if(fDebug)
										LogPrintf("getCurrencyToSYSFromAlias() Failed to get currency amount from value\n");
									return "1";
								}
							}
							
						}
					}
				}
			}
		}
		
	}
	else
	{
		if(fDebug)
			LogPrintf("getCurrencyToSYSFromAlias() Failed to get value from alias\n");
		return "1";
	}
	if(!found)
	{
		if(fDebug)
			LogPrintf("getCurrencyToSYSFromAlias() currency %s not found in %s alias\n", stringFromVch(vchCurrency).c_str(), stringFromVch(vchAliasPeg).c_str());
		return "0";
	}
	return "";

}
void getCategoryListFromValue(vector<string>& categoryList,const UniValue& outerValue)
{
	UniValue outerObj = outerValue.get_obj();
	UniValue objCategoriesValue = find_value(outerObj, "categories");
	UniValue categories = objCategoriesValue.get_array();
	for (unsigned int idx = 0; idx < categories.size(); idx++) {
		const UniValue& category = categories[idx];
		const UniValue& categoryObj = category.get_obj();	
		const UniValue categoryValue = find_value(categoryObj, "cat");
		categoryList.push_back(categoryValue.get_str());
	}
}
bool getBanListFromValue(map<string, unsigned char>& banAliasList,  map<string, unsigned char>& banCertList,  map<string, unsigned char>& banOfferList,const UniValue& outerValue)
{
	try
		{
		UniValue outerObj = outerValue.get_obj();
		UniValue objOfferValue = find_value(outerObj, "offers");
		if (objOfferValue.isArray())
		{
			UniValue codes = objOfferValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banOfferList.insert(make_pair(idStr, severityNum));
				}
			}
		}

		UniValue objCertValue = find_value(outerObj, "certs");
		if (objCertValue.isArray())
		{
			UniValue codes = objCertValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banCertList.insert(make_pair(idStr, severityNum));
				}
			}
		}
			
		

		UniValue objAliasValue = find_value(outerObj, "aliases");
		if (objAliasValue.isArray())
		{
			UniValue codes = objAliasValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banAliasList.insert(make_pair(idStr, severityNum));
				}
			}
		}
	}
	catch(std::runtime_error& err)
	{	
		if(fDebug)
			LogPrintf("getBanListFromValue(): Failed to get ban list from value\n");
		return false;
	}
	return true;
}
bool getBanList(const vector<unsigned char>& banData, map<string, unsigned char>& banAliasList,  map<string, unsigned char>& banCertList,  map<string, unsigned char>& banOfferList)
{
	string value = stringFromVch(banData);
	
	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(value);
	if (read)
	{
		return getBanListFromValue(banAliasList, banCertList, banOfferList, outerValue);
	}
	else
	{
		if(fDebug)
			LogPrintf("getBanList() Failed to get value from alias\n");
		return false;
	}
	return false;

}
bool getCategoryList(vector<string>& categoryList)
{
	// check for alias existence in DB
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchFromString("SYS_CATEGORY"), vtxPos) || vtxPos.empty())
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find SYS_CATEGORY alias\n");
		return false;
	}
	
	if (vtxPos.size() < 1)
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find SYS_CATEGORY alias (vtxPos.size() == 0)\n");
		return false;
	}

	CAliasIndex categoryAlias = vtxPos.back();

	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(stringFromVch(categoryAlias.vchPublicValue));
	if (read)
	{
		try{
		
			getCategoryListFromValue(categoryList, outerValue);
			return true;
		}
		catch(std::runtime_error& err)
		{
			
			if(fDebug)
				LogPrintf("getCategoryListFromValue(): Failed to get category list from value\n");
			return false;
		}
	}
	else
	{
		if(fDebug)
			LogPrintf("getCategoryList() Failed to get value from alias\n");
		return false;
	}
	return false;

}
void PutToAliasList(std::vector<CAliasIndex> &aliasList, CAliasIndex& index) {
	int i = aliasList.size() - 1;
	BOOST_REVERSE_FOREACH(CAliasIndex &o, aliasList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	aliasList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	aliasList[i] = index;
            return;
        }
        i--;
	}
    aliasList.push_back(index);
}

bool IsAliasOp(int op) {
	return op == OP_ALIAS_ACTIVATE
			|| op == OP_ALIAS_UPDATE;
}
string aliasFromOp(int op) {
	switch (op) {
	case OP_ALIAS_UPDATE:
		return "aliasupdate";
	case OP_ALIAS_ACTIVATE:
		return "aliasactivate";
	default:
		return "<unknown alias op>";
	}
}
int GetSyscoinDataOutput(const CTransaction& tx) {
   for(unsigned int i = 0; i<tx.vout.size();i++) {
	   if(IsSyscoinDataOutput(tx.vout[i]))
		   return i;
	}
   return -1;
}
bool IsSyscoinDataOutput(const CTxOut& out) {
   txnouttype whichType;
	if (!IsStandard(out.scriptPubKey, whichType))
		return false;
	if (whichType == TX_NULL_DATA)
		return true;
   return false;
}
int GetSyscoinTxVersion()
{
	return SYSCOIN_TX_VERSION;
}

/**
 * [IsSyscoinTxMine check if this transaction is mine or not, must contain a syscoin service vout]
 * @param  tx [syscoin based transaction]
 * @param  type [the type of syscoin service you expect in this transaction]
 * @return    [if syscoin transaction is yours based on type passed in]
 */
bool IsSyscoinTxMine(const CTransaction& tx, const string &type) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	int op, nOut, myNout;
	vector<vector<unsigned char> > vvch;
	if ((type == "alias" || type == "any") && DecodeAliasTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "offer" || type == "any") && DecodeOfferTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "cert" || type == "any") && DecodeCertTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "message" || type == "any") && DecodeMessageTx(tx, op, nOut, vvch))
		myNout = nOut;
	else if ((type == "escrow" || type == "any") && DecodeEscrowTx(tx, op, nOut, vvch))
		myNout = nOut;
	else
		return false;

	return pwalletMain->IsMine(tx.vout[myNout]);
}
void updateBans(const vector<unsigned char> &banData)
{
	map<string, unsigned char> banAliasList;
	map<string, unsigned char> banCertList;
	map<string, unsigned char> banOfferList;
	if(getBanList(banData, banAliasList, banCertList, banOfferList))
	{
		// update alias bans
		for (map<string, unsigned char>::iterator it = banAliasList.begin(); it != banAliasList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(paliasdb->ExistsAlias(vchGUID))
			{
				vector<CAliasIndex> vtxAliasPos;
				if (paliasdb->ReadAlias(vchGUID, vtxAliasPos) && !vtxAliasPos.empty())
				{
					CAliasIndex aliasBan = vtxAliasPos.back();
					aliasBan.safetyLevel = severity;
					PutToAliasList(vtxAliasPos, aliasBan);
					CPubKey PubKey(aliasBan.vchPubKey);
					CSyscoinAddress address(PubKey.GetID());
					paliasdb->WriteAlias(vchGUID, vchFromString(address.ToString()), vtxAliasPos);
					
				}		
			}
		}
		// update cert bans
		for (map<string, unsigned char>::iterator it = banCertList.begin(); it != banCertList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(pcertdb->ExistsCert(vchGUID))
			{
				vector<CCert> vtxCertPos;
				if (pcertdb->ReadCert(vchGUID, vtxCertPos) && !vtxCertPos.empty())
				{
					CCert certBan = vtxCertPos.back();
					certBan.safetyLevel = severity;
					PutToCertList(vtxCertPos, certBan);
					pcertdb->WriteCert(vchGUID, vtxCertPos);
					
				}		
			}
		}
		// update offer bans
		for (map<string, unsigned char>::iterator it = banOfferList.begin(); it != banOfferList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(pofferdb->ExistsOffer(vchGUID))
			{
				vector<COffer> vtxOfferPos;
				if (pofferdb->ReadOffer(vchGUID, vtxOfferPos) && !vtxOfferPos.empty())
				{
					COffer offerBan = vtxOfferPos.back();
					offerBan.safetyLevel = severity;
					offerBan.PutToOfferList(vtxOfferPos);
					pofferdb->WriteOffer(vchGUID, vtxOfferPos);
					
				}		
			}
		}
	}
}
bool CheckAliasInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock* block) {
	
	if (tx.IsCoinBase())
		return true;
	if (fDebug)
		LogPrintf("*** %d %d %s %s\n", nHeight, chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(), fJustCheck ? "JUSTCHECK" : "BLOCK");
	const COutPoint *prevOutput = NULL;
	CCoins prevCoins;
	int prevOp = 0;
	vector<vector<unsigned char> > vvchPrevArgs;
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
			if(!IsSyscoinScript(prevCoins.vout[prevOutput->n].scriptPubKey, pop, vvch))
				continue;

			if (IsAliasOp(pop)) {
				prevOp = pop;
				vvchPrevArgs = vvch;
				break;
			}
		}
	}
	// Make sure alias outputs are not spent by a regular transaction, or the alias would be lost
	if (tx.nVersion != SYSCOIN_TX_VERSION) {
		LogPrintf("CheckAliasInputs() : non-syscoin transaction\n");
		return true;
	}
	// unserialize alias from txn, check for valid
	CAliasIndex theAlias(tx);
	// we need to check for cert update specially because an alias update without data is sent along with offers linked with the alias
	if (theAlias.IsNull() && op != OP_ALIAS_UPDATE)
		return true;
	if(theAlias.vchPublicValue.size() > MAX_VALUE_LENGTH && vvchArgs[0] != vchFromString("SYS_RATES"))
	{
		return error("alias pub value too big");
	}
	if(theAlias.vchPrivateValue.size() > MAX_ENCRYPTED_VALUE_LENGTH)
	{
		return error("alias priv value too big");
	}
	if(!theAlias.vchPubKey.empty() && !IsSysCompressedOrUncompressedPubKey(theAlias.vchPubKey))
	{
		return error("alias pub key invalid length");
	}
	if(!theAlias.vchName.empty() && theAlias.vchName != vvchArgs[0])
	{
		return error("guid in data output doesn't match guid in tx");
	}
	if (vvchArgs[0].size() > MAX_NAME_LENGTH)
		return error("alias name too long");
    if (vvchArgs[1].size() > MAX_NAME_LENGTH)
        return error("alias hex guid too long");
	vector<CAliasIndex> vtxPos;
	string retError = "";
	if(fJustCheck)
	{
		switch (op) {
			case OP_ALIAS_ACTIVATE:
				break;
			case OP_ALIAS_UPDATE:
				if (!IsAliasOp(prevOp))
					return error("aliasupdate previous tx not found");
				// Check name
				if (vvchPrevArgs[0] != vvchArgs[0])
					return error("CheckAliasInputs() : aliasupdate alias mismatch");
				// Check GUID
				if (vvchArgs.size() > 1 && vvchPrevArgs[1] != vvchArgs[1])
					return error("CheckAliasInputs() : aliasupdate GUID mismatch");
				if(vvchArgs[0] != vchFromString("SYS_BAN") && vvchArgs[0] != vchFromString("SYS_RATES") && vvchArgs[0] != vchFromString("SYS_CATEGORY") && !theAlias.IsNull())
				{
					if (!paliasdb->ReadAlias(vvchArgs[0], vtxPos) || vtxPos.empty())
						return error("CheckAliasInputs() : failed to read from alias DB");
					if(vvchArgs.size() > 1 && vtxPos.back().vchGUID != vvchArgs[1])
						return error("CheckAliasInputs() : aliasupdate vchGUID mismatch");
				}
				break;
		default:
			return error(
					"CheckAliasInputs() : alias transaction has unknown op");
		}

	}
	
	if (!fJustCheck ) {
		bool update = false;
		// get the alias from the DB
		if (paliasdb->ExistsAlias(vvchArgs[0])) {
			if (!paliasdb->ReadAlias(vvchArgs[0], vtxPos))
				return error(
						"CheckAliasInputs() : failed to read from alias DB");
		}
		if(op != OP_ALIAS_ACTIVATE)
		{
			if(!vtxPos.empty())
			{
				if(vvchArgs[0] != vchFromString("SYS_BAN") && vvchArgs[0] != vchFromString("SYS_RATES") && vvchArgs[0] != vchFromString("SYS_CATEGORY"))
				{
					if((vtxPos.back().nHeight + GetAliasExpirationDepth()) < nHeight)
					{
						if(fDebug)
							LogPrintf("CheckAliasInputs(): Trying to update an expired service");
						return true;
					}
				}
				update = true;
				if(theAlias.IsNull())
					theAlias = vtxPos.back();
				else
				{
					const CAliasIndex& dbAlias = vtxPos.back();
					if(theAlias.vchPublicValue.empty())
						theAlias.vchPublicValue = dbAlias.vchPublicValue;	
					if(theAlias.vchPrivateValue.empty())
						theAlias.vchPrivateValue = dbAlias.vchPrivateValue;	
					// user can't update safety level or rating after creation
					theAlias.safetyLevel = dbAlias.safetyLevel;
					theAlias.nRating = dbAlias.nRating;
					theAlias.nRatingCount = dbAlias.nRatingCount;
				}
				// if transfer
				if(vtxPos.back().vchPubKey != theAlias.vchPubKey)
				{
					update = false;
					CPubKey xferKey  = CPubKey(theAlias.vchPubKey);	
					CSyscoinAddress myAddress = CSyscoinAddress(xferKey.GetID());
					// make sure xfer to pubkey doesn't point to an alias already, otherwise don't assign pubkey to alias
					if (paliasdb->ExistsAddress(vchFromString(myAddress.ToString())))
					{
						theAlias.vchPubKey = vtxPos.back().vchPubKey;
						LogPrintf("CheckAliasInputs() : Warning, Cannot transfer an alias that points to another alias. Pubkey was not updated");
					}
				}
			}
			else
				return true;
		}
	
		if(op == OP_ALIAS_ACTIVATE)
		{
			if(vvchArgs[0] != vchFromString("SYS_BAN") && vvchArgs[0] != vchFromString("SYS_RATES") && vvchArgs[0] != vchFromString("SYS_CATEGORY") && !theAlias.IsNull())
			{
				if (!vtxPos.empty())
				{
					if((vtxPos.back().nHeight + GetAliasExpirationDepth()) >= nHeight)
					{
						LogPrintf("CheckAliasInputs():  Warning, Trying to renew an alias that isn't expired");
						return true;
					}
				}
			}
			theAlias.nRating = 0;
			theAlias.nRatingCount = 0;
		}
		if(vvchArgs.size() > 1)
			theAlias.vchGUID = vvchArgs[1];
		theAlias.nHeight = nHeight;
		theAlias.txHash = tx.GetHash();
		PutToAliasList(vtxPos, theAlias);
		CPubKey PubKey(theAlias.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		if (!paliasdb->WriteAlias(vvchArgs[0], vchFromString(address.ToString()), vtxPos))
			return error( "CheckAliasInputs() :  failed to write to alias DB");
		if(update && vvchArgs[0] == vchFromString("SYS_BAN"))
		{
			updateBans(theAlias.vchPublicValue);
		}		
		if(fDebug)
			LogPrintf(
				"CONNECTED ALIAS: name=%s  op=%s  hash=%s  height=%d\n",
				stringFromVch(vvchArgs[0]).c_str(),
				aliasFromOp(op).c_str(),
				tx.GetHash().ToString().c_str(), nHeight);
	}

	return true;
}

string stringFromValue(const UniValue& value) {
	string strName = value.get_str();
	return strName;
}

vector<unsigned char> vchFromValue(const UniValue& value) {
	string strName = value.get_str();
	unsigned char *strbeg = (unsigned char*) strName.c_str();
	return vector<unsigned char>(strbeg, strbeg + strName.size());
}

std::vector<unsigned char> vchFromString(const std::string &str) {
	unsigned char *strbeg = (unsigned char*) str.c_str();
	return vector<unsigned char>(strbeg, strbeg + str.size());
}

string stringFromVch(const vector<unsigned char> &vch) {
	string res;
	vector<unsigned char>::const_iterator vi = vch.begin();
	while (vi != vch.end()) {
		res += (char) (*vi);
		vi++;
	}
	return res;
}
bool GetSyscoinData(const CTransaction &tx, vector<unsigned char> &vchData)
{
	int nOut = GetSyscoinDataOutput(tx);
    if(nOut == -1)
	   return false;

	const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if(opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	return true;
}
bool GetSyscoinData(const CScript &scriptPubKey, vector<unsigned char> &vchData)
{
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if(opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	return true;
}
bool CAliasIndex::UnserializeFromData(const vector<unsigned char> &vchData) {
    try {
        CDataStream dsAlias(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsAlias >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	// extra check to ensure data was parsed correctly
	if(!IsSysCompressedOrUncompressedPubKey(vchPubKey))
	{
		SetNull();
		return false;
	}
	return true;
}
bool CAliasIndex::UnserializeFromTx(const CTransaction &tx) {
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
const vector<unsigned char> CAliasIndex::Serialize() {
    CDataStream dsAlias(SER_NETWORK, PROTOCOL_VERSION);
    dsAlias << *this;
    const vector<unsigned char> vchData(dsAlias.begin(), dsAlias.end());
    return vchData;

}
bool CAliasDB::ScanNames(const std::vector<unsigned char>& vchName, const string& strRegexp, bool safeSearch, 
		unsigned int nMax,
		vector<pair<vector<unsigned char>, CAliasIndex> >& nameScan) {
	int nMaxAge  = GetAliasExpirationDepth();

	// regexp
	using namespace boost::xpressive;
	smatch nameparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
	sregex cregex = sregex::compile(strRegexpLower);
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("namei"), vchName));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "namei") {
            	vector<unsigned char> vchName = key.second;
				
                vector<CAliasIndex> vtxPos;
				pcursor->GetValue(vtxPos);
				
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CAliasIndex &txPos = vtxPos.back();
  				if ((chainActive.Tip()->nHeight - txPos.nHeight) >= nMaxAge)
				{
					pcursor->Next();
					continue;
				} 
				if(txPos.safetyLevel >= SAFETY_LEVEL1)
				{
					if(safeSearch)
					{
						pcursor->Next();
						continue;
					}
					if(txPos.safetyLevel > SAFETY_LEVEL1)
					{
						pcursor->Next();
						continue;
					}
				}
				if(!txPos.safeSearch && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				string name = stringFromVch(vchName);
				boost::algorithm::to_lower(name);
				if (strRegexp != "" && !regex_search(name, nameparts, cregex) && strRegexp != name)
				{
					pcursor->Next();
					continue;
				}
                nameScan.push_back(make_pair(vchName, txPos));
            }
            if (nameScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int GetAliasExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 1440;
  #else
    return 525600;
  #endif
}
bool GetTxOfAlias(const vector<unsigned char> &vchName, 
				  CAliasIndex& txPos, CTransaction& tx, bool skipExpiresCheck) {
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchName, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchName != vchFromString("SYS_RATES") && vchName != vchFromString("SYS_BAN") && vchName != vchFromString("SYS_CATEGORY"))
	{
		if (!skipExpiresCheck && (nHeight + GetAliasExpirationDepth()
				< chainActive.Tip()->nHeight)) {
			string name = stringFromVch(vchName);
			LogPrintf("GetTxOfAlias(%s) : expired", name.c_str());
			return false;
		}
	}

	if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfAlias() : could not read tx from disk");

	return true;
}

void GetAddressFromAlias(const std::string& strAlias, std::string& strAddress) {
	try
	{
		const vector<unsigned char> &vchAlias = vchFromValue(strAlias);
		if (paliasdb && !paliasdb->ExistsAlias(vchAlias))
			throw runtime_error("Alias not found");

		// check for alias existence in DB
		vector<CAliasIndex> vtxPos;
		if (paliasdb && !paliasdb->ReadAlias(vchAlias, vtxPos))
			throw runtime_error("failed to read from alias DB");
		if (vtxPos.size() < 1)
			throw runtime_error("no alias result returned");

		// get transaction pointed to by alias
		CTransaction tx;
		const CAliasIndex &alias = vtxPos.back();
		uint256 txHash = alias.txHash;
		if (!GetSyscoinTransaction(alias.nHeight, txHash, tx, Params().GetConsensus()))
			throw runtime_error("failed to read transaction from disk");

		CPubKey PubKey(alias.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		if(!address.IsValid())
			throw runtime_error("alias address is invalid");
		strAddress = address.ToString();
	}
	catch(...)
	{
		throw runtime_error("could not read alias");
	}
}

void GetAliasFromAddress(const std::string& strAddress, std::string& strAlias) {
	try
	{
		const vector<unsigned char> &vchAddress = vchFromValue(strAddress);
		if (paliasdb && !paliasdb->ExistsAddress(vchAddress))
			throw runtime_error("Alias address mapping not found");

		// check for alias address mapping existence in DB
		vector<unsigned char> vchAlias;
		if (paliasdb && !paliasdb->ReadAddress(vchAddress, vchAlias))
			throw runtime_error("failed to read from alias DB");
		if (vchAlias.empty())
			throw runtime_error("no alias address mapping result returned");
		strAlias = stringFromVch(vchAlias);
	}
	catch(...)
	{
		throw runtime_error("could not read alias address mapping");
	}
}
int IndexOfAliasOutput(const CTransaction& tx) {
	vector<vector<unsigned char> > vvch;
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
	int op;
	int nOut;
	bool good = DecodeAliasTx(tx, op, nOut, vvch);
	if (!good)
		return -1;
	return nOut;
}

bool GetAliasOfTx(const CTransaction& tx, vector<unsigned char>& name) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op;
	int nOut;

	bool good = DecodeAliasTx(tx, op, nOut, vvchArgs);
	if (!good)
		return error("GetAliasOfTx() : could not decode a syscoin tx");

	switch (op) {
	case OP_ALIAS_ACTIVATE:
	case OP_ALIAS_UPDATE:
		name = vvchArgs[0];
		return true;
	}
	return false;
}
bool DecodeAndParseSyscoinTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	return DecodeAndParseAliasTx(tx, op, nOut, vvch) 
		|| DecodeAndParseCertTx(tx, op, nOut, vvch)
		|| DecodeAndParseOfferTx(tx, op, nOut, vvch)
		|| DecodeAndParseEscrowTx(tx, op, nOut, vvch)
		|| DecodeAndParseMessageTx(tx, op, nOut, vvch);
}
bool DecodeAndParseAliasTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CAliasIndex alias;
	bool decode = DecodeAliasTx(tx, op, nOut, vvch);
	bool parse = alias.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeAliasTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch) {
	bool found = false;


	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeAliasScript(out.scriptPubKey, op, vvchRead)) {
			nOut = i;
			found = true;
			vvch = vvchRead;
			break;
		}
	}
	if (!found)
		vvch.clear();

	return found && IsAliasOp(op);
}


bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
	opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

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

	if ((op == OP_ALIAS_ACTIVATE && vvch.size() <= 2)
			|| (op == OP_ALIAS_UPDATE && vvch.size() <= 2))
		return true;
	return false;
}
bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAliasScript(script, op, vvch, pc);
}
CScript RemoveAliasScriptPrefix(const CScript& scriptIn) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAliasScript(scriptIn, op, vvch, pc))
		throw runtime_error(
				"RemoveAliasScriptPrefix() : could not decode name script");
	return CScript(pc, scriptIn.end());
}
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient)
{
	CRecipient recp = {scriptPubKey, 0, false};
	recipient = recp;
	CTxOut txout(recipient.nAmount,	recipient.scriptPubKey);
	recipient.nAmount = txout.GetDustThreshold(::minRelayTxFee);
}
void CreateFeeRecipient(const CScript& scriptPubKey, const vector<unsigned char>& data, CRecipient& recipient)
{
	CRecipient recp = {scriptPubKey, 0.02*COIN, false};
	recipient = recp;
	CTxOut txout(0,	recipient.scriptPubKey);
    size_t nSize = txout.GetSerializeSize(SER_DISK,0)+148u;
	CAmount fee = 3*minRelayTxFee.GetFee(nSize);
	// minimum of 0.02 COIN fees for data
	recipient.nAmount = fee > 0.02*COIN? fee: 0.02*COIN;
}
UniValue aliasnew(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 4 < params.size())
		throw runtime_error(
		"aliasnew <aliasname> <public value> [private value] [safe search=Yes]\n"
						"<aliasname> alias name.\n"
						"<public value> alias public profile data, 1023 chars max.\n"
						"<private value> alias private profile data, 1023 chars max. Will be private and readable by owner only.\n"
						"<safe search> set to No if this alias should only show in the search when safe search is not selected. Defaults to Yes (alias shows with or without safe search selected in search lists).\n"										
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromString(params[0].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);

	string strPrivateValue = params.size()>=3?params[2].get_str():"";
	string strSafeSearch = "Yes";
	if(params.size() >= 4)
	{
		strSafeSearch = params[3].get_str();
	}
	vchPrivateValue = vchFromString(strPrivateValue);
	if (vchPublicValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("alias public value cannot exceed 1023 bytes!");
	if (vchPrivateValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("alias private value cannot exceed 1023 bytes!");
	if (vchName.size() > MAX_NAME_LENGTH)
		throw runtime_error("alias name cannot exceed 255 bytes!");


	CSyscoinAddress myAddress = CSyscoinAddress(stringFromVch(vchName));
	if(myAddress.IsValid() && !myAddress.isAlias)
		throw runtime_error("alias name cannot be a syscoin address!");

	CWalletTx wtx;

	CTransaction tx;
	CAliasIndex theAlias;
	if (GetTxOfAlias(vchName, theAlias, tx)) {
		error("aliasactivate() : this alias is already active with tx %s",
				tx.GetHash().GetHex().c_str());
		throw runtime_error("this alias is already active");
	}

	EnsureWalletIsUnlocked();

	// check for existing pending aliases
	if (ExistsInMempool(vchName, OP_ALIAS_ACTIVATE)) {
		throw runtime_error("there are pending operations on that alias");
	}
	
	int64_t rand = GetRand(std::numeric_limits<int64_t>::max());
	vector<unsigned char> vchRand = CScriptNum(rand).getvch();
    vector<unsigned char> vchRandAlias = vchFromValue(HexStr(vchRand));

	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey);
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig = GetScriptForDestination(newDefaultKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchName << vchRandAlias << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	std::vector<unsigned char> vchPubKey(newDefaultKey.begin(), newDefaultKey.end());

	if(vchPrivateValue.size() > 0)
	{
		string strCipherText;
		if(!EncryptMessage(vchPubKey, vchPrivateValue, strCipherText))
		{
			throw runtime_error("Could not encrypt private alias value!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("private data length cannot exceed 1023 bytes!");
		vchPrivateValue = vchFromString(strCipherText);
	}

    // build alias
    CAliasIndex newAlias;
	newAlias.vchGUID = vchRandAlias;
	newAlias.vchName = vchName;
	newAlias.nHeight = chainActive.Tip()->nHeight;
	newAlias.vchPubKey = vchPubKey;
	newAlias.vchPublicValue = vchPublicValue;
	newAlias.vchPrivateValue = vchPrivateValue;
	newAlias.safetyLevel = 0;
	newAlias.safeSearch = strSafeSearch == "Yes"? true: false;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptData;
	const vector<unsigned char> &data = newAlias.Serialize();
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	// send the tranasction
	SendMoneySyscoin(vecSend, recipient.nAmount + fee.nAmount, false, wtx);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchPubKey));
	return res;
}
UniValue aliasupdate(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 5 < params.size())
		throw runtime_error(
		"aliasupdate <aliasname> <public value> [private value=''] [safesearch=Yes] [toalias_pubkey='']\n"
						"Update and possibly transfer an alias.\n"
						"<aliasname> alias name.\n"
						"<public value> alias public profile data, 1023 chars max.\n"
						"<private value> alias private profile data, 1023 chars max. Will be private and readable by owner only.\n"				
						"<safesearch> is this alias safe to search. Defaults to Yes, No for not safe and to hide in GUI search queries\n"
						"<toalias_pubkey> receiver syscoin alias pub key, if transferring alias.\n"
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchName = vchFromString(params[0].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);
	string strPrivateValue = params.size()>=3 && params[2].get_str().size() > 0?params[2].get_str():"";
	vchPrivateValue = vchFromString(strPrivateValue);
	if (vchPublicValue.size() > MAX_VALUE_LENGTH && vchName != vchFromString("SYS_RATES"))
		throw runtime_error("alias public value cannot exceed 1023 bytes!");
	if (vchPrivateValue.size() > MAX_VALUE_LENGTH)
		throw runtime_error("alias public value cannot exceed 1023 bytes!");
	vector<unsigned char> vchPubKeyByte;

	CWalletTx wtx;
	CAliasIndex updateAlias;
	const CWalletTx* wtxIn;
	CScript scriptPubKeyOrig;
	string strPubKey;
    if (params.size() >= 5 && params[4].get_str().size() > 0) {
		vector<unsigned char> vchPubKey;
		vchPubKey = vchFromString(params[4].get_str());
		boost::algorithm::unhex(vchPubKey.begin(), vchPubKey.end(), std::back_inserter(vchPubKeyByte));
		CPubKey xferKey  = CPubKey(vchPubKeyByte);
		if(!xferKey.IsValid())
			throw runtime_error("Invalid public key");
		CSyscoinAddress myAddress = CSyscoinAddress(xferKey.GetID());
		if (paliasdb->ExistsAddress(vchFromString(myAddress.ToString())))
			throw runtime_error("You must transfer to a public key that's not associated with any other alias");
	}

	string strSafeSearch = "Yes";
	if(params.size() >= 4)
	{
		strSafeSearch = params[3].get_str();
	}
	EnsureWalletIsUnlocked();
	CTransaction tx;
	CAliasIndex theAlias;
	if (!GetTxOfAlias(vchName, theAlias, tx))
		throw runtime_error("could not find an alias with this name");

    if(!IsSyscoinTxMine(tx, "alias")) {
		throw runtime_error("This alias is not yours, you cannot update it.");
    }
	wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("this alias is not in your wallet");
	// check for existing pending aliases
	if (ExistsInMempool(vchName, OP_ALIAS_ACTIVATE) || ExistsInMempool(vchName, OP_ALIAS_UPDATE)) {
		throw runtime_error("there are pending operations on that alias");
	}

	if(vchPubKeyByte.empty())
		vchPubKeyByte = theAlias.vchPubKey;
	if(vchPrivateValue.size() > 0)
	{
		string strCipherText;
		
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchPrivateValue, strCipherText))
		{
			throw runtime_error("Could not encrypt alias private data!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("data length cannot exceed 1023 bytes!");
		vchPrivateValue = vchFromString(strCipherText);
	}

	CAliasIndex copyAlias = theAlias;
	theAlias.ClearAlias();

	theAlias.nHeight = chainActive.Tip()->nHeight;
	if(copyAlias.vchPublicValue != vchPublicValue)
		theAlias.vchPublicValue = vchPublicValue;
	if(copyAlias.vchPrivateValue != vchPrivateValue)
		theAlias.vchPrivateValue = vchPrivateValue;
	
	theAlias.vchPubKey = vchPubKeyByte;
	theAlias.safeSearch = strSafeSearch == "Yes"? true: false;
	CPubKey currentKey(vchPubKeyByte);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << vchName << copyAlias.vchGUID << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	const vector<unsigned char> &data = theAlias.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInCert=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxIn, wtxInEscrow);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	return res;
}

UniValue aliaslist(const UniValue& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("aliaslist [<aliasname>]\n"
				"list my own aliases.\n"
				"<aliasname> alias name to use as filter.\n");
	
	vector<unsigned char> vchName;

	if (params.size() == 1)
		vchName = vchFromValue(params[0]);

	vector<unsigned char> vchNameUniq;
	if (params.size() == 1)
		vchNameUniq = vchFromValue(params[0]);
	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vNamesI;
	map<vector<unsigned char>, UniValue> vNamesO;

	{
		uint256 hash;
		CTransaction tx;
		int pending = 0;
		uint64_t nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			pending = 0;
			// get txn hash, read txn index
			hash = item.second.GetHash();
			const CWalletTx &wtx = item.second;
			// skip non-syscoin txns
			if (wtx.nVersion != SYSCOIN_TX_VERSION)
				continue;

			// decode txn, skip non-alias txns
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			if (!DecodeAliasTx(wtx, op, nOut, vvch) || !IsAliasOp(op))
				continue;

			// get the txn alias name
			if (!GetAliasOfTx(wtx, vchName))
				continue;

			// skip this alias if it doesn't match the given filter value
			if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
				continue;
			vector<CAliasIndex> vtxPos;
			CAliasIndex alias;
			if (!paliasdb->ReadAlias(vchName, vtxPos) || vtxPos.empty())
			{
				pending = 1;
				alias = CAliasIndex(wtx);
				if(!IsSyscoinTxMine(wtx, "alias"))
					continue;
			}
			else
			{
				alias = vtxPos.back();
				CTransaction tx;
				if (!GetSyscoinTransaction(alias.nHeight, alias.txHash, tx, Params().GetConsensus()))
				{
					pending = 1;
					if(!IsSyscoinTxMine(wtx, "alias"))
						continue;
				}
				else{
					if (!DecodeAliasTx(tx, op, nOut, vvch) || !IsAliasOp(op))
						continue;
					if(!IsSyscoinTxMine(tx, "alias"))
						continue;
				}
			}
			nHeight = alias.nHeight;
			// get last active name only
			if (vNamesI.find(vchName) != vNamesI.end() && (nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
				continue;	
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			// build the output UniValue
			UniValue oName(UniValue::VOBJ);
			oName.push_back(Pair("name", stringFromVch(vchName)));
			oName.push_back(Pair("value", stringFromVch(alias.vchPublicValue)));
			string strPrivateValue = "";
			if(alias.vchPrivateValue.size() > 0)
				strPrivateValue = "Encrypted for alias owner";
			string strDecrypted = "";
			if(DecryptMessage(alias.vchPubKey, alias.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));
			oName.push_back(Pair("safesearch", alias.safeSearch ? "Yes" : "No"));
			oName.push_back(Pair("safetylevel", alias.safetyLevel ));
			float rating = 0;
			if(alias.nRatingCount > 0)
				rating = roundf(alias.nRating/(float)alias.nRatingCount);
			oName.push_back(Pair("rating", (int)rating));
			oName.push_back(Pair("ratingcount", alias.nRatingCount));
			expired_block = nHeight + GetAliasExpirationDepth();
			if(vchName != vchFromString("SYS_RATES") && vchName != vchFromString("SYS_BAN") && vchName != vchFromString("SYS_CATEGORY"))
			{
				if(expired_block < chainActive.Tip()->nHeight)
				{
					expired = 1;
				}
			}
			expires_in = expired_block - chainActive.Tip()->nHeight;
			oName.push_back(Pair("expires_in", expires_in));
			oName.push_back(Pair("expires_on", expired_block));
			oName.push_back(Pair("expired", expired));
			oName.push_back(Pair("pending", pending));
			vNamesI[vchName] = nHeight;
			vNamesO[vchName] = oName;					

		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
		oRes.push_back(item.second);

	return oRes;
}

UniValue aliasaffiliates(const UniValue& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("aliasaffiliates \n"
				"list my own affiliations with merchant offers.\n");
	

	vector<unsigned char> vchOffer;
	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vOfferI;
	map<vector<unsigned char>, UniValue> vOfferO;
	{
		uint256 hash;
		CTransaction tx;
		int pending = 0;
		uint64_t nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			pending = 0;
			// get txn hash, read txn index
			hash = item.second.GetHash();
			const CWalletTx &wtx = item.second;
			// skip non-syscoin txns
			if (wtx.nVersion != SYSCOIN_TX_VERSION)
				continue;

			// decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(wtx, op, nOut, vvch) 
            	|| !IsOfferOp(op) 
            	|| (op == OP_OFFER_ACCEPT))
                continue;
			if(!IsSyscoinTxMine(wtx, "offer"))
					continue;
            vchOffer = vvch[0];

			vector<COffer> vtxPos;
			COffer theOffer;
			if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
				continue;
			
			theOffer = vtxPos.back();
			nHeight = theOffer.nHeight;
			// get last active name only
			if (vOfferI.find(vchOffer) != vOfferI.end() && (nHeight < vOfferI[vchOffer] || vOfferI[vchOffer] < 0))
				continue;
			vOfferI[vchOffer] = nHeight;
			// if this is my offer and it is linked go through else skip
			if(theOffer.vchLinkOffer.empty())
				continue;
			// get parent offer
			CTransaction tx;
			COffer linkOffer;
			if (!GetTxOfOffer( theOffer.vchLinkOffer, linkOffer, tx))
				continue;

			for(unsigned int i=0;i<linkOffer.linkWhitelist.entries.size();i++) {
				CTransaction txAlias;
				CAliasIndex theAlias;
				COfferLinkWhitelistEntry& entry = linkOffer.linkWhitelist.entries[i];
				if (GetTxOfAlias(entry.aliasLinkVchRand, theAlias, txAlias))
				{
					if (!IsSyscoinTxMine(txAlias, "alias"))
						continue;
					UniValue oList(UniValue::VOBJ);
					oList.push_back(Pair("offer", stringFromVch(vchOffer)));
					oList.push_back(Pair("alias", stringFromVch(entry.aliasLinkVchRand)));
					int expires_in = 0;
					if(nHeight + GetAliasExpirationDepth() - chainActive.Tip()->nHeight > 0)
					{
						expires_in = nHeight + GetAliasExpirationDepth() - chainActive.Tip()->nHeight;
					}  
					oList.push_back(Pair("expiresin",expires_in));
					oList.push_back(Pair("offer_discount_percentage", strprintf("%d%%", entry.nDiscountPct)));
					vOfferO[vchOffer] = oList;	
				}  
			}
		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vOfferO)
		oRes.push_back(item.second);

	return oRes;
}
/**
 * [aliasinfo description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue aliasinfo(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("aliasinfo <aliasname>\n"
				"Show values of an alias.\n");
	vector<unsigned char> vchName = vchFromValue(params[0]);

	CTransaction tx;
	UniValue oShowResult(UniValue::VOBJ);

	{

		// check for alias existence in DB
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchName, vtxPos))
			throw runtime_error("failed to read from alias DB");
		if (vtxPos.size() < 1)
			throw runtime_error("no result returned");

		// get transaction pointed to by alias
		uint256 txHash = vtxPos.back().txHash;
		if (!GetSyscoinTransaction(vtxPos.back().nHeight, txHash, tx, Params().GetConsensus()))
			throw runtime_error("failed to read transaction from disk");

		UniValue oName(UniValue::VOBJ);
		uint64_t nHeight;
		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		nHeight = vtxPos.back().nHeight;
		oName.push_back(Pair("name", stringFromVch(vchName)));
		const CAliasIndex &alias= vtxPos.back();
		if(alias.safetyLevel >= SAFETY_LEVEL2)
			throw runtime_error("alias has been banned");
		oName.push_back(Pair("value", stringFromVch(alias.vchPublicValue)));
		string strPrivateValue = "";
		if(alias.vchPrivateValue.size() > 0)
			strPrivateValue = "Encrypted for alias owner";
		string strDecrypted = "";
		if(DecryptMessage(alias.vchPubKey, alias.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));
		oName.push_back(Pair("txid", alias.txHash.GetHex()));
		CPubKey PubKey(alias.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		if(!address.IsValid())
			throw runtime_error("Invalid alias address");
		oName.push_back(Pair("address", address.ToString()));
		bool fAliasMine = IsSyscoinTxMine(tx, "alias")? true:  false;
		oName.push_back(Pair("ismine", fAliasMine));
		oName.push_back(Pair("safesearch", alias.safeSearch ? "Yes" : "No"));
		oName.push_back(Pair("safetylevel", alias.safetyLevel ));
		float rating = 0;
		if(alias.nRatingCount > 0)
			rating = roundf(alias.nRating/(float)alias.nRatingCount);
		oName.push_back(Pair("rating", (int)rating));
		oName.push_back(Pair("ratingcount", alias.nRatingCount));
        oName.push_back(Pair("lastupdate_height", nHeight));
		expired_block = nHeight + GetAliasExpirationDepth();
		if(vchName != vchFromString("SYS_RATES") && vchName != vchFromString("SYS_BAN") && vchName != vchFromString("SYS_CATEGORY"))
		{
			if(expired_block < chainActive.Tip()->nHeight)
			{
				expired = 1;
			}  
		}
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));
		oShowResult = oName;
	}
	return oShowResult;
}

/**
 * [aliashistory description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue aliashistory(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("aliashistory <aliasname>\n"
				"List all stored values of an alias.\n");
	UniValue oRes(UniValue::VARR);
	vector<unsigned char> vchName = vchFromValue(params[0]);
	string name = stringFromVch(vchName);

	{
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchName, vtxPos) || vtxPos.empty())
			throw runtime_error("failed to read from alias DB");

		CAliasIndex txPos2;
		uint256 txHash;
		BOOST_FOREACH(txPos2, vtxPos) {
			txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetSyscoinTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus()))
			{
				error("could not read txpos");
				continue;
			}
            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeAliasTx(tx, op, nOut, vvch) 
            	|| !IsAliasOp(op) )
                continue;
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			UniValue oName(UniValue::VOBJ);
			uint64_t nHeight;
			nHeight = txPos2.nHeight;
			oName.push_back(Pair("name", name));
			string opName = aliasFromOp(op);
			oName.push_back(Pair("aliastype", opName));
			oName.push_back(Pair("value", stringFromVch(txPos2.vchPublicValue)));
			string strPrivateValue = "";
			if(txPos2.vchPrivateValue.size() > 0)
				strPrivateValue = "Encrypted for alias owner";
			string strDecrypted = "";
			if(DecryptMessage(txPos2.vchPubKey, txPos2.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));
			oName.push_back(Pair("txid", tx.GetHash().GetHex()));
			CPubKey PubKey(txPos2.vchPubKey);
			CSyscoinAddress address(PubKey.GetID());
			oName.push_back(Pair("address", address.ToString()));
            oName.push_back(Pair("lastupdate_height", nHeight));
			float rating = 0;
			if(txPos2.nRatingCount > 0)
				rating = roundf(txPos2.nRating/(float)txPos2.nRatingCount);
			oName.push_back(Pair("rating", (int)rating));
			oName.push_back(Pair("ratingcount", txPos2.nRatingCount));
			expired_block = nHeight + GetAliasExpirationDepth();
			if(vchName != vchFromString("SYS_RATES") && vchName != vchFromString("SYS_BAN") && vchName != vchFromString("SYS_CATEGORY"))
			{
				if(expired_block < chainActive.Tip()->nHeight)
				{
					expired = 1;
				} 
			}
			expires_in = expired_block - chainActive.Tip()->nHeight;
			oName.push_back(Pair("expires_in", expires_in));
			oName.push_back(Pair("expires_on", expired_block));
			oName.push_back(Pair("expired", expired));
			oRes.push_back(oName);
		}
	}
	return oRes;
}
UniValue generatepublickey(const UniValue& params, bool fHelp) {
	if(!pwalletMain)
		throw runtime_error("No wallet defined!");
	CPubKey PubKey = pwalletMain->GenerateNewKey();
	std::vector<unsigned char> vchPubKey(PubKey.begin(), PubKey.end());
	UniValue res(UniValue::VARR);
	res.push_back(HexStr(vchPubKey));
	return res;
}
/**
 * [aliasfilter description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue aliasfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 3)
		throw runtime_error(
				"aliasfilter [[[[[regexp]] from='']] safesearch='Yes']\n"
						"scan and filter aliases\n"
						"[regexp] : apply [regexp] on aliases, empty means all aliases\n"
						"[from] : show results from this GUID [from], empty means first.\n"
						"[aliasfilter] : shows all aliases that are safe to display (not on the ban list)\n"
						"aliasfilter \"\" 5 # list aliases updated in last 5 blocks\n"
						"aliasfilter \"^alias\" # list all aliases starting with \"alias\"\n"
						"aliasfilter 36000 0 0 stat # display stats (number of aliases) on active aliases\n");

	vector<unsigned char> vchName;
	string strRegexp;

	bool safeSearch = true;


	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchName = vchFromValue(params[1]);

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="Yes"? true: false;

	UniValue oRes(UniValue::VARR);

	
	vector<pair<vector<unsigned char>, CAliasIndex> > nameScan;
	if (!paliasdb->ScanNames(vchName, strRegexp, safeSearch, 25, nameScan))
		throw runtime_error("scan failed");

	pair<vector<unsigned char>, CAliasIndex> pairScan;
	BOOST_FOREACH(pairScan, nameScan) {
		const CAliasIndex &alias = pairScan.second;

		CAliasIndex txName = pairScan.second;
		int nHeight = txName.nHeight;

		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		UniValue oName(UniValue::VOBJ);
		oName.push_back(Pair("name", stringFromVch(pairScan.first)));
		oName.push_back(Pair("value", stringFromVch(txName.vchPublicValue)));
		string strPrivateValue = "";
		if(alias.vchPrivateValue.size() > 0)
			strPrivateValue = "Encrypted for alias owner";
		string strDecrypted = "";
		if(DecryptMessage(txName.vchPubKey, alias.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));
        oName.push_back(Pair("lastupdate_height", nHeight));
		float rating = 0;
		if(alias.nRatingCount > 0)
			rating = roundf(alias.nRating/(float)alias.nRatingCount);
		oName.push_back(Pair("rating", (int)rating));
		oName.push_back(Pair("ratingcount", alias.nRatingCount));
		expired_block = nHeight + GetAliasExpirationDepth();
        if(expired_block < chainActive.Tip()->nHeight)
		{
			expired = 1;
		}  
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));

		
		oRes.push_back(oName);
	}


	return oRes;
}

string CheckForAliasExpiry(vector<unsigned char> vchPubKey, int nHeight)
{
	if(!vchPubKey.empty())
	{
		CPubKey PubKey(vchPubKey);
		vector<unsigned char> aliasName;
		vector<CAliasIndex> vtxAliasPos;
		CSyscoinAddress address(PubKey.GetID());
		if(!address.IsValid())
			return string("alias address is invalid");
		string strAddress = address.ToString();

		if(!paliasdb->ExistsAddress(vchFromString(strAddress)))
		{
			return string("alias does not exist in the db");
		}
		if(!paliasdb->ReadAddress(vchFromString(strAddress), aliasName))
		{
			return string("could not read alias address from the db");
		}
		if(!paliasdb->ReadAlias(aliasName, vtxAliasPos) || vtxAliasPos.empty())
		{
			return string("could not read alias from the db");
		}
		if((vtxAliasPos.back().nHeight + GetAliasExpirationDepth()) < nHeight)
		{
			return string("alias is expired");
		}
	}
	return "";
}