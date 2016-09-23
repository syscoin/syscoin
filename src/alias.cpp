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
#include <boost/algorithm/string/find.hpp>
using namespace std;
CAliasDB *paliasdb = NULL;
COfferDB *pofferdb = NULL;
CCertDB *pcertdb = NULL;
CEscrowDB *pescrowdb = NULL;
CMessageDB *pmessagedb = NULL;
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInOffer=NULL, const CWalletTx* wtxInCert=NULL, const CWalletTx* wtxInAlias=NULL, const CWalletTx* wtxInEscrow=NULL, bool syscoinTx=true);
bool GetPreviousInput(const COutPoint * outpoint, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if(!pwalletMain || !outpoint)
		return false;
    map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(outpoint->hash);
    if (it != pwalletMain->mapWallet.end())
    {
        const CWalletTx* pcoin = &it->second;
		if(pcoin->vout.size() >= outpoint->n && IsSyscoinScript(pcoin->vout[outpoint->n].scriptPubKey, op, vvchArgs))
			return true;

    } else
       return false;
    return false;
}
bool GetSyscoinTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams)
{
	CBlockIndex *pindexSlow = NULL; 
	LOCK(cs_main);
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
// if its in SYS2.1 fork (returns true) then we look at nHeight for when to prune
bool IsInSys21Fork(CScript& scriptPubKey, uint64_t &nHeight)
{
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	if(!GetSyscoinData(scriptPubKey, vchData, vchHash))
		return false;
	if(!chainActive.Tip())
		return false;
	CAliasIndex alias;
	COffer offer;
	CMessage message;
	CEscrow escrow;
	CCert cert;
	nHeight = 0;
	const string &chainName = ChainNameFromCommandLine();
	if(alias.UnserializeFromData(vchData, vchHash))
	{
		if(alias.vchAlias == vchFromString("sysrates.peg") || alias.vchAlias == vchFromString("sysban") || alias.vchAlias == vchFromString("syscategory"))
			return false;
		vector<CAliasIndex> vtxPos;
		// we only prune things that we have in our db and that we can verify the last tx is expired
		// nHeight is set to the height at which data is pruned, if the tip is newer than nHeight it won't send data to other nodes
		if (paliasdb->ReadAlias(alias.vchAlias, vtxPos))
		{	
			uint64_t nLastHeight = vtxPos.back().nHeight;
			// if we are renewing alias then prune based on nHeight of tx
			if(!alias.vchGUID.empty() && vtxPos.back().vchGUID != alias.vchGUID)
				nLastHeight = alias.nHeight;
			nHeight = nLastHeight + (vtxPos.back().nRenewal*GetAliasExpirationDepth());
			return true;				
		}
		// this is a new service, either sent to us because it's not supposed to be expired yet or sent to ourselves as a new service, either way we keep the data and validate it into the service db
		else
		{
			// setting to the tip means we don't prune this data, we keep it
			nHeight = chainActive.Tip()->nHeight +  GetAliasExpirationDepth();
			return true;
		}
	}
	else if(offer.UnserializeFromData(vchData, vchHash))
	{
		vector<COffer> vtxPos;
		if (pofferdb->ReadOffer(offer.vchOffer, vtxPos))
		{
			uint64_t nLastHeight =  vtxPos.back().nHeight;
			// if alises of offer is not expired then don't prune the offer yet
			CSyscoinAddress sellerAddress = CSyscoinAddress(stringFromVch(vtxPos.back().vchAlias));
			if(sellerAddress.IsValid() && sellerAddress.isAlias && sellerAddress.nExpireHeight >=  chainActive.Tip()->nHeight)
				nLastHeight = chainActive.Tip()->nHeight;
			nHeight = nLastHeight + GetOfferExpirationDepth();
			return true;			
		}
		else
		{
			nHeight = chainActive.Tip()->nHeight +  GetOfferExpirationDepth();
			return true;
		}
	}
	else if(cert.UnserializeFromData(vchData, vchHash))
	{
		vector<CCert> vtxPos;
		if (pcertdb->ReadCert(cert.vchCert, vtxPos))
		{
			uint64_t nLastHeight = vtxPos.back().nHeight;
			nHeight = vtxPos.back().nHeight + GetCertExpirationDepth();
			return true;			
		}
		else
		{	
			nHeight = chainActive.Tip()->nHeight + GetCertExpirationDepth();
			return true;
		}
	}
	else if(escrow.UnserializeFromData(vchData, vchHash))
	{
		vector<CEscrow> vtxPos;
		if (pescrowdb->ReadEscrow(escrow.vchEscrow, vtxPos))
		{
			uint64_t nLastHeight = vtxPos.back().nHeight;
			if(vtxPos.back().op != OP_ESCROW_COMPLETE)
				nLastHeight = chainActive.Tip()->nHeight;
			// if alises of escrow are not expired then don't prune the escrow yet
			CSyscoinAddress buyerAddress = CSyscoinAddress(stringFromVch(vtxPos.back().vchBuyerAlias));
			if(buyerAddress.IsValid() && buyerAddress.isAlias && buyerAddress.nExpireHeight >=  chainActive.Tip()->nHeight)
				nLastHeight = chainActive.Tip()->nHeight;
			else
			{
				CSyscoinAddress sellerAddress = CSyscoinAddress(stringFromVch(vtxPos.back().vchSellerAlias));
				if(sellerAddress.IsValid() && sellerAddress.isAlias && sellerAddress.nExpireHeight >=  chainActive.Tip()->nHeight)
					nLastHeight = chainActive.Tip()->nHeight;
				else
				{
					CSyscoinAddress arbiterAddress = CSyscoinAddress(stringFromVch(vtxPos.back().vchArbiterAlias));
					if(arbiterAddress.IsValid() && arbiterAddress.isAlias  && arbiterAddress.nExpireHeight >=  chainActive.Tip()->nHeight)
						nLastHeight = chainActive.Tip()->nHeight;
				}
			}
		
			nHeight = nLastHeight + GetEscrowExpirationDepth();
			return true;				
		}
		else 
		{		
			nHeight = chainActive.Tip()->nHeight + GetEscrowExpirationDepth();
			return true;
		}
	}
	else if(message.UnserializeFromData(vchData, vchHash))
	{
		vector<CMessage> vtxPos;
		if (pmessagedb->ReadMessage(message.vchMessage, vtxPos))
		{
			uint64_t nLastHeight = vtxPos.back().nHeight;
			nHeight = vtxPos.back().nHeight + GetMessageExpirationDepth();
			return true;		
		}
		else
		{	
			nHeight = chainActive.Tip()->nHeight + GetMessageExpirationDepth();
			return true;
		}
	}

	return false;
}
bool IsSysServiceExpired(const uint64_t &nHeight)
{
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
// how much is 1.1 BTC in syscoin? 1 BTC = 110000 SYS for example, nPrice would be 1.1, sysPrice would be 110000
CAmount convertCurrencyCodeToSyscoin(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrencyCode, const float &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount sysPrice = 0;
	float nRate;
	vector<string> rateList;
	try
	{
		if(getCurrencyToSYSFromAlias(vchAliasPeg, vchCurrencyCode, nRate, nHeight, rateList, precision) == "")
		{
			sysPrice = CAmount(nPrice*nRate*COIN);
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
// convert 110000*COIN SYS into 1.1*COIN BTC
CAmount convertSyscoinToCurrencyCode(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrencyCode, const CAmount &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount currencyPrice = 0;
	float nRate;
	vector<string> rateList;
	try
	{
		if(getCurrencyToSYSFromAlias(vchAliasPeg, vchCurrencyCode, nRate, nHeight, rateList, precision) == "")
		{
			currencyPrice = CAmount(nPrice/nRate);
		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("convertSyscoinToCurrencyCode() Exception caught getting rate alias information\n");
	}
	if(precision > 8)
		currencyPrice = 0;
	return currencyPrice;
}
string getCurrencyToSYSFromAlias(const vector<unsigned char> &vchAliasPeg, const vector<unsigned char> &vchCurrency, float &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision)
{
	string currencyCodeToFind = stringFromVch(vchCurrency);
	// check for alias existence in DB
	vector<CAliasIndex> vtxPos;
	CAliasIndex tmpAlias;
	CTransaction aliastx;
	bool isExpired;
	if (!GetTxAndVtxOfAlias(vchAliasPeg, tmpAlias, aliastx, vtxPos, isExpired))
	{
		if(fDebug)
			LogPrintf("getCurrencyToSYSFromAlias() Could not find %s alias\n", stringFromVch(vchAliasPeg).c_str());
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
							
								nFee = currencyAmountValue.get_real();
							}
							catch(std::runtime_error& err)
							{
								try
								{
									nFee = currencyAmountValue.get_int();
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
	if (!paliasdb->ReadAlias(vchFromString("syscategory"), vtxPos) || vtxPos.empty())
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find syscategory alias\n");
		return false;
	}
	
	if (vtxPos.size() < 1)
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find syscategory alias (vtxPos.size() == 0)\n");
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
	if ((type == "alias" || type == "any"))
		myNout = IndexOfAliasOutput(tx);
	else if ((type == "offer" || type == "any"))
		myNout = IndexOfOfferOutput(tx);
	else if ((type == "cert" || type == "any"))
		myNout = IndexOfCertOutput(tx);
	else if ((type == "message" || type == "any"))
		myNout = IndexOfMessageOutput(tx);
	else if ((type == "escrow" || type == "any"))
		myNout = IndexOfEscrowOutput(tx);
	else
		return false;
	return myNout >= 0;
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
				vector<COffer> vtxOfferPos, myLinkVtxPos;
				if (pofferdb->ReadOffer(vchGUID, vtxOfferPos) && !vtxOfferPos.empty())
				{
					COffer offerBan = vtxOfferPos.back();
					offerBan.safetyLevel = severity;
					offerBan.PutToOfferList(vtxOfferPos);
					pofferdb->WriteOffer(vchGUID, vtxOfferPos);
					// go through the linked offers, if any, and update the linked offer safety level
					for(unsigned int i=0;i<offerBan.offerLinks.size();i++) {
						vector<COffer> myVtxPos;	
						if (pofferdb->ExistsOffer(offerBan.offerLinks[i])) {
							if (pofferdb->ReadOffer(offerBan.offerLinks[i], myVtxPos))
							{
								COffer offerLink = myVtxPos.back();					
								offerLink.safetyLevel = severity;
								offerLink.PutToOfferList(myVtxPos);
								pofferdb->WriteOffer(offerBan.offerLinks[i], myVtxPos);
							}
						}
					}	
				}		
			}
		}
	}
}
bool CheckAliasInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, const CBlock* block, bool dontaddtodb) {
	if(!IsSys21Fork(nHeight))
		return true;	
	if (tx.IsCoinBase())
		return true;
	if (fDebug)
		LogPrintf("*** ALIAS %d %d %s %s\n", nHeight, chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(), fJustCheck ? "JUSTCHECK" : "BLOCK");
	const COutPoint *prevOutput = NULL;
	CCoins prevCoins;
	int prevOp = 0;
	vector<vector<unsigned char> > vvchPrevArgs;
	// Make sure alias outputs are not spent by a regular transaction, or the alias would be lost
	if (tx.nVersion != SYSCOIN_TX_VERSION) 
	{
		errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1000 - " + _("Non-Syscoin transaction found");
		return true;
	}
	// unserialize alias from txn, check for valid
	CAliasIndex theAlias;
	bool found = false;
	vector<unsigned char> vchData;
	vector<unsigned char> vchAlias;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(GetSyscoinData(tx, vchData, vchHash, nDataOut) && !theAlias.UnserializeFromData(vchData, vchHash))
	{
		theAlias.SetNull();
	}
	// we need to check for cert update specially because an alias update without data is sent along with offers linked with the alias
	if (theAlias.IsNull() && op != OP_ALIAS_UPDATE)
	{
		if(fDebug)
			LogPrintf("CheckAliasInputs(): Null alias, skipping...\n");	
		return true;
	}
	if(fJustCheck)
	{
		if(!vchData.empty())
		{
			CRecipient fee;
			CScript scriptData;
			scriptData << vchData;
			CreateFeeRecipient(scriptData, vchData, fee);
			if (fee.nAmount > tx.vout[nDataOut].nValue) 
			{
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 2 - " + _("Transaction does not pay enough fees");
				return error(errorMessage.c_str());
			}
		}		
		if(vvchArgs.size() != 3)
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1001 - " + _("Alias arguments incorrect size");
			return error(errorMessage.c_str());
		}

		if(!theAlias.IsNull())
		{
			if(vchHash != vvchArgs[2])
			{
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1002 - " + _("Hash provided doesn't match the calculated hash the data");
				return error(errorMessage.c_str());
			}
		}		
		for (unsigned int i = 0; i < tx.vout.size(); i++) {
			int tmpOp;
			vector<vector<unsigned char> > vvchRead;
			if (DecodeAliasScript(tx.vout[i].scriptPubKey, tmpOp, vvchRead) && vvchRead[0] == vvchArgs[0]) {
				if(found)
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1003 - " + _("Too many alias outputs found in a transaction, only 1 allowed");
					return error(errorMessage.c_str());
				}
				found = true; 
			}
		}			
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

			if (IsAliasOp(pop)) {
				prevOp = pop;
				vvchPrevArgs = vvch;
				break;
			}
		}
	}
	vector<CAliasIndex> vtxPos;
	string retError = "";
	if(fJustCheck)
	{
		if(!IsValidAliasName(vvchArgs[0]))
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1004 - " + _("Alias name does not follow the domain name specification");
			return error(errorMessage.c_str());
		}
		if(theAlias.vchPublicValue.size() > MAX_VALUE_LENGTH && vvchArgs[0] != vchFromString("sysrates.peg") && vvchArgs[0] != vchFromString("syscategory"))
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1005 - " + _("Alias public value too big");
			return error(errorMessage.c_str());
		}
		if(theAlias.vchPrivateValue.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1006 - " + _("Alias private value too big");
			return error(errorMessage.c_str());
		}
		if(theAlias.nHeight > nHeight)
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1007 - " + _("Bad alias height");
			return error(errorMessage.c_str());
		}
		if(!theAlias.IsNull() && (theAlias.nRenewal > 5 || theAlias.nRenewal < 1))
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1008 - " + _("Expiration must be within 1 to 5 years");
			return error(errorMessage.c_str());
		}
		switch (op) {
			case OP_ALIAS_ACTIVATE:
				// Check GUID
				if (theAlias.vchGUID != vvchArgs[1])
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1009 - " + _("Alias input guid mismatch");
					return error(errorMessage.c_str());
				}
				if(theAlias.vchAlias != vvchArgs[0])
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1010 - " + _("Guid in data output doesn't match guid in tx");
					return error(errorMessage.c_str());
				}
				if(!theAlias.vchPrivateKey.empty())
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1011 - " + _("Private key must be empty on activate");
					return error(errorMessage.c_str());
				}
				
				break;
			case OP_ALIAS_UPDATE:
				if (!IsAliasOp(prevOp))
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1012 - " + _("Alias input to this transaction not found");
					return error(errorMessage.c_str());
				}
				if(!theAlias.IsNull())
				{
					if(theAlias.vchAlias != vvchArgs[0])
					{
						errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1013 - " + _("Guid in data output doesn't match guid in transaction");
						return error(errorMessage.c_str());
					}
				}
				// Check name
				if (vvchPrevArgs[0] != vvchArgs[0])
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1014 - " + _("Alias input mismatch");
					return error(errorMessage.c_str());
				}
				// Check GUID
				if (vvchPrevArgs[1] != vvchArgs[1])
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Alias Guid input mismatch");
					return error(errorMessage.c_str());
				}
				break;
		default:
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1016 - " + _("Alias transaction has unknown op");
				return error(errorMessage.c_str());
		}

	}
	
	if (!fJustCheck ) {
		bool update = false;
		bool isExpired = false;
		CAliasIndex dbAlias;
		CTransaction aliasTx;
		string strName = stringFromVch(vvchArgs[0]);
		boost::algorithm::to_lower(strName);
		vchAlias = vchFromString(strName);
		// get the alias from the DB
		if(!GetTxAndVtxOfAlias(vchAlias, dbAlias, aliasTx, vtxPos, isExpired))	
		{
			if(op == OP_ALIAS_ACTIVATE)
			{
				if(!isExpired && !vtxPos.empty())
				{
					errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1017 - " + _("Trying to renew an alias that isn't expired");
					return true;
				}
			}
			else
			{
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1018 - " + _("Failed to read from alias DB");
				return true;
			}
		}
		
		if(op != OP_ALIAS_ACTIVATE)
		{
			if(!vtxPos.empty())
			{
				update = true;
				if(theAlias.IsNull())
					theAlias = vtxPos.back();
				else
				{
					if(theAlias.vchPublicValue.empty())
						theAlias.vchPublicValue = dbAlias.vchPublicValue;	
					if(theAlias.vchPrivateValue.empty())
						theAlias.vchPrivateValue = dbAlias.vchPrivateValue;	
					// user can't update safety level or rating after creation
					theAlias.safetyLevel = dbAlias.safetyLevel;
					theAlias.nRatingAsBuyer = dbAlias.nRatingAsBuyer;
					theAlias.nRatingCountAsBuyer = dbAlias.nRatingCountAsBuyer;
					theAlias.nRatingAsSeller = dbAlias.nRatingAsSeller;
					theAlias.nRatingCountAsSeller = dbAlias.nRatingCountAsSeller;
					theAlias.nRatingAsArbiter = dbAlias.nRatingAsArbiter;
					theAlias.nRatingCountAsArbiter= dbAlias.nRatingCountAsArbiter;
					theAlias.vchGUID = dbAlias.vchGUID;
					theAlias.vchAlias = dbAlias.vchAlias;
					
				}
				// if transfer
				if(dbAlias.vchPubKey != theAlias.vchPubKey)
				{
					update = false;
					CPubKey xferKey  = CPubKey(theAlias.vchPubKey);	
					CSyscoinAddress myAddress = CSyscoinAddress(xferKey.GetID());
					// make sure xfer to pubkey doesn't point to an alias already, otherwise don't assign pubkey to alias
					// we want to avoid aliases with duplicate public keys (addresses)
					if (paliasdb->ExistsAddress(vchFromString(myAddress.ToString())))
					{
						theAlias.vchPubKey = dbAlias.vchPubKey;
						errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1019 - " + _("Cannot transfer an alias that points to another alias");
					}
					if(theAlias.vchPrivateKey.empty())
					{
						theAlias.vchPubKey = dbAlias.vchPubKey;
						errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1020 - " + _("Private key cannot be empty on transfer");
					}	
					else if(theAlias.vchPrivateKey == dbAlias.vchPrivateKey)
					{
						theAlias.vchPubKey = dbAlias.vchPubKey;
						errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1021 - " + _("Private key must change on transfer");
					}
					
				}
				else
					theAlias.vchPrivateKey = dbAlias.vchPrivateKey;
			}
			else
			{
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1022 -" + _(" Alias not found when trying to update");
				return true;
			}
		}
		else
		{
			if(!isExpired && !vtxPos.empty())
			{
				errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1023 - " + _("Trying to renew an alias that isn't expired");
				return true;
			}
			theAlias.nRatingAsBuyer = 0;
			theAlias.nRatingCountAsBuyer = 0;
			theAlias.nRatingAsSeller = 0;
			theAlias.nRatingCountAsSeller = 0;
			theAlias.nRatingAsArbiter = 0;
			theAlias.nRatingCountAsArbiter = 0;
		}
		theAlias.nHeight = nHeight;
		theAlias.txHash = tx.GetHash();
		PutToAliasList(vtxPos, theAlias);
		CPubKey PubKey(theAlias.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		if (!dontaddtodb && !paliasdb->WriteAlias(vchAlias, vchFromString(address.ToString()), vtxPos))
		{
			errorMessage = "SYSCOIN_ALIAS_CONSENSUS_ERROR: ERRCODE: 1024 - " + _("Failed to write to alias DB");
			return error(errorMessage.c_str());
		}
		if(!dontaddtodb && update && vchAlias == vchFromString("sysban"))
		{
			updateBans(theAlias.vchPublicValue);
		}		
		if(fDebug)
			LogPrintf(
				"CONNECTED ALIAS: name=%s  op=%s  hash=%s  height=%d\n",
				stringFromVch(vchAlias).c_str(),
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
bool GetSyscoinData(const CTransaction &tx, vector<unsigned char> &vchData, vector<unsigned char> &vchHash, int& nOut)
{
	nOut = GetSyscoinDataOutput(tx);
    if(nOut == -1)
	   return false;

	const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
	return GetSyscoinData(scriptPubKey, vchData, vchHash);
}
bool IsValidAliasName(const std::vector<unsigned char> &vchAlias)
{
	return (vchAlias.size() <= MAX_GUID_LENGTH && vchAlias.size() >= 3);
}
bool GetSyscoinData(const CScript &scriptPubKey, vector<unsigned char> &vchData, vector<unsigned char> &vchHash)
{
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if(opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchHash))
		return false;
	return true;
}
bool CAliasIndex::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsAlias(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsAlias >> *this;

		const vector<unsigned char> &vchAliasData = Serialize();
		uint256 calculatedHash = Hash(vchAliasData.begin(), vchAliasData.end());
		vector<unsigned char> vchRand = CScriptNum(calculatedHash.GetCheapHash()).getvch();
		vector<unsigned char> vchRandAlias = vchFromValue(HexStr(vchRand));
		if(vchRandAlias != vchHash)
		{
			SetNull();
			return false;
		}
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	return true;
}
bool CAliasIndex::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nOut;
	if(!GetSyscoinData(tx, vchData, vchHash, nOut))
	{
		SetNull();
		return false;
	}
	if(!UnserializeFromData(vchData, vchHash))
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
bool CAliasDB::ScanNames(const std::vector<unsigned char>& vchAlias, const string& strRegexp, bool safeSearch, 
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
	pcursor->Seek(make_pair(string("namei"), vchAlias));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "namei") {
            	vector<unsigned char> vchAlias = key.second;
				
                vector<CAliasIndex> vtxPos;
				pcursor->GetValue(vtxPos);
				
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CAliasIndex &txPos = vtxPos.back();
  				if ((chainActive.Tip()->nHeight - txPos.nHeight) >= (txPos.nRenewal*nMaxAge))
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
				string name = stringFromVch(vchAlias);
				if (strRegexp != "" && !regex_search(name, nameparts, cregex) && strRegexp != name)
				{
					pcursor->Next();
					continue;
				}
                nameScan.push_back(make_pair(vchAlias, txPos));
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
bool GetTxOfAlias(const vector<unsigned char> &vchAlias, 
				  CAliasIndex& txPos, CTransaction& tx, bool skipExpiresCheck) {
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchAlias != vchFromString("sysrates.peg") && vchAlias != vchFromString("sysban") && vchAlias != vchFromString("syscategory"))
	{
		if (!skipExpiresCheck && (nHeight + (txPos.nRenewal*GetAliasExpirationDepth())
				< chainActive.Tip()->nHeight)) {
			string name = stringFromVch(vchAlias);
			LogPrintf("GetTxOfAlias(%s) : expired", name.c_str());
			return false;
		}
	}

	if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfAlias() : could not read tx from disk");

	return true;
}
bool GetTxAndVtxOfAlias(const vector<unsigned char> &vchAlias, 
						CAliasIndex& txPos, CTransaction& tx, std::vector<CAliasIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck) {
	isExpired = false;
	if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchAlias != vchFromString("sysrates.peg") && vchAlias != vchFromString("sysban") && vchAlias != vchFromString("syscategory"))
	{
		if (!skipExpiresCheck && (nHeight + (txPos.nRenewal*GetAliasExpirationDepth())
				< chainActive.Tip()->nHeight)) {
			string name = stringFromVch(vchAlias);
			LogPrintf("GetTxOfAlias(%s) : expired", name.c_str());
			isExpired = true;
			return false;
		}
	}

	if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfAlias() : could not read tx from disk");
	return true;
}
void GetAddressFromAlias(const std::string& strAlias, std::string& strAddress, unsigned char& safetyLevel, bool& safeSearch, int64_t& nExpireHeight) {
	try
	{
		string strLowerAlias = strAlias;
		boost::algorithm::to_lower(strLowerAlias);
		const vector<unsigned char> &vchAlias = vchFromValue(strLowerAlias);
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
		CPubKey PubKey(alias.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		if(!address.IsValid())
			throw runtime_error("alias address is invalid");
		strAddress = address.ToString();
		safetyLevel = alias.safetyLevel;
		safeSearch = alias.safeSearch;
		nExpireHeight = alias.nHeight + alias.nRenewal*GetAliasExpirationDepth();
	}
	catch(...)
	{
		throw runtime_error("could not read alias");
	}
}

void GetAliasFromAddress(const std::string& strAddress, std::string& strAlias, unsigned char& safetyLevel, bool& safeSearch, int64_t& nExpireHeight) {
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
		vector<CAliasIndex> vtxPos;
		if (paliasdb && !paliasdb->ReadAlias(vchAlias, vtxPos))
			throw runtime_error("failed to read from alias DB");
		if (vtxPos.size() < 1)
			throw runtime_error("no alias result returned");
		const CAliasIndex &alias = vtxPos.back();
		strAlias = stringFromVch(vchAlias);
		safetyLevel = alias.safetyLevel;
		safeSearch = alias.safeSearch;
		nExpireHeight = alias.nHeight + alias.nRenewal*GetAliasExpirationDepth();
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
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeAliasScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
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

	return found;
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
	return IsAliasOp(op);
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
void CreateFeeRecipient(CScript& scriptPubKey, const vector<unsigned char>& data, CRecipient& recipient)
{
	// add hash to data output (must match hash in inputs check with the tx scriptpubkey hash)
    uint256 hash = Hash(data.begin(), data.end());
 	vector<unsigned char> vchHash = CScriptNum(hash.GetCheapHash()).getvch();
    vector<unsigned char> vchHashRand = vchFromValue(HexStr(vchHash));
	scriptPubKey << vchHashRand;

	CRecipient recp = {scriptPubKey, 0.02*COIN, false};
	recipient = recp;
	CTxOut txout(0,	recipient.scriptPubKey);
    size_t nSize = txout.GetSerializeSize(SER_DISK,0)+148u;
	CAmount fee = 3*minRelayTxFee.GetFee(nSize);
	// minimum of 0.02 COIN fees for data
	recipient.nAmount = fee > 0.02*COIN? fee: 0.02*COIN;
}
UniValue aliasnew(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 5 < params.size())
		throw runtime_error(
		"aliasnew <aliasname> <public value> [private value] [safe search=Yes] [expire=1]\n"
						"<aliasname> alias name.\n"
						"<public value> alias public profile data, 1023 chars max.\n"
						"<private value> alias private profile data, 1023 chars max. Will be private and readable by owner only.\n"
						"<safe search> set to No if this alias should only show in the search when safe search is not selected. Defaults to Yes (alias shows with or without safe search selected in search lists).\n"	
						"<expire> Number of years before expiry. It affects the fees you pay, the cheapest being 1 year. The more years you specify the more fees you pay. Max is 5 years, Min is 1 year. Defaults to 1 year.\n"	
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchAlias = vchFromString(params[0].get_str());
	string strName = params[0].get_str();
	/*Above pattern makes sure domain name matches the following criteria :

	The domain name should be a-z | 0-9 and hyphen(-)
	The domain name should between 3 and 63 characters long
	Last Tld can be 2 to a maximum of 6 characters
	The domain name should not start or end with hyphen (-) (e.g. -syscoin.org or syscoin-.org)
	The domain name can be a subdomain (e.g. sys.blogspot.com)*/

	
	using namespace boost::xpressive;
	using namespace boost::algorithm;
	to_lower(strName);
	smatch nameparts;
	sregex domainwithtldregex = sregex::compile("^((?!-)[a-z0-9-]{3,63}(?<!-)\\.)+[a-z]{2,6}$");
	sregex domainwithouttldregex = sregex::compile("^((?!-)[a-z0-9-]{3,63}(?<!-))");

	if(find_first(strName, "."))
	{
		if (!regex_search(strName, nameparts, domainwithtldregex) || string(nameparts[0]) != strName)
			throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1025 - " + _("Invalid Syscoin Identity. Must follow the domain name spec of 3 to 63 characters with no preceding or trailing dashes and a TLD of 2 to 6 characters"));	
	}
	else
	{
		if (!regex_search(strName, nameparts, domainwithouttldregex)  || string(nameparts[0]) != strName)
			throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1026 - " + _("Invalid Syscoin Identity. Must follow the domain name spec of 3 to 63 characters with no preceding or trailing dashes"));
	}
	


	vchAlias = vchFromString(strName);

	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);

	string strPrivateValue = params.size()>=3?params[2].get_str():"";
	string strSafeSearch = "Yes";
	unsigned char nRenewal = 1;
	if(params.size() >= 4)
	{
		strSafeSearch = params[3].get_str();
	}
	if(params.size() >= 5)
		nRenewal = atoi(params[4].get_str());
	
	vchPrivateValue = vchFromString(strPrivateValue);

	CWalletTx wtx;

	EnsureWalletIsUnlocked();

	

	CPubKey defaultKey;
	pwalletMain->GetKeyFromPool(defaultKey);
	CScript scriptPubKeyOrig;

	// if renewing an alias you already had and its yours, just use the old pubkey
	CAliasIndex theAlias;
	CTransaction aliastx;
	if(GetTxOfAlias(vchAlias, theAlias, aliastx, true))
	{
		if(IsSyscoinTxMine(aliastx, "alias")) {
			defaultKey = CPubKey(theAlias.vchPubKey);
		}
	}

	scriptPubKeyOrig = GetScriptForDestination(defaultKey.GetID());
	std::vector<unsigned char> vchPubKey(defaultKey.begin(), defaultKey.end());

	if(vchPrivateValue.size() > 0)
	{
		string strCipherText;
		if(!EncryptMessage(vchPubKey, vchPrivateValue, strCipherText))
		{
			throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1027 - " + _("Could not encrypt private alias value!"));
		}
		vchPrivateValue = vchFromString(strCipherText);
	}
	vector<unsigned char> vchRandAlias = vchFromString(GenerateSyscoinGuid());
    // build alias
    CAliasIndex newAlias;
	newAlias.vchGUID = vchRandAlias;
	newAlias.vchAlias = vchAlias;
	newAlias.nHeight = chainActive.Tip()->nHeight;
	newAlias.vchPubKey = vchPubKey;
	newAlias.vchPublicValue = vchPublicValue;
	newAlias.vchPrivateValue = vchPrivateValue;
	newAlias.nRenewal = nRenewal;
	newAlias.safetyLevel = 0;
	newAlias.safeSearch = strSafeSearch == "Yes"? true: false;
	const vector<unsigned char> &data = newAlias.Serialize();
    uint256 hash = Hash(data.begin(), data.end());
 	vector<unsigned char> vchHash = CScriptNum(hash.GetCheapHash()).getvch();
    vector<unsigned char> vchHashAlias = vchFromValue(HexStr(vchHash));

	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchAlias << vchRandAlias << vchHashAlias << OP_2DROP << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptData;
	
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	// calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
	if(nRenewal > 1)
		fee.nAmount += 0.02*COIN*nRenewal*nRenewal;
	
	vecSend.push_back(fee);
	// send the tranasction
	SendMoneySyscoin(vecSend, recipient.nAmount + fee.nAmount, false, wtx);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchPubKey));
	return res;
}
UniValue aliasupdate(const UniValue& params, bool fHelp) {
	if (fHelp || 2 > params.size() || 6 < params.size())
		throw runtime_error(
		"aliasupdate <aliasname> <public value> [private value=''] [safesearch=Yes] [toalias_pubkey=''] [expire=1]\n"
						"Update and possibly transfer an alias.\n"
						"<aliasname> alias name.\n"
						"<public value> alias public profile data, 1023 chars max.\n"
						"<private value> alias private profile data, 1023 chars max. Will be private and readable by owner only.\n"				
						"<safesearch> is this alias safe to search. Defaults to Yes, No for not safe and to hide in GUI search queries\n"
						"<toalias_pubkey> receiver syscoin alias pub key, if transferring alias.\n"
						"<expire> Number of years before expiry. It affects the fees you pay, the cheapest being 1 year. The more years you specify the more fees you pay. Max is 5 years, Min is 1 year. Defaults to 1 year.\n"	
						+ HelpRequiringPassphrase());

	vector<unsigned char> vchAlias = vchFromString(params[0].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[1].get_str();
	vchPublicValue = vchFromString(strPublicValue);
	string strPrivateValue = params.size()>=3 && params[2].get_str().size() > 0?params[2].get_str():"";
	vchPrivateValue = vchFromString(strPrivateValue);
	vector<unsigned char> vchPubKeyByte;
	unsigned char nRenewal = 1;
	CWalletTx wtx;
	CAliasIndex updateAlias;
	const CWalletTx* wtxIn;
	CScript scriptPubKeyOrig;
	string strPubKey;
    if (params.size() >= 5 && params[4].get_str().size() > 0) {
		vector<unsigned char> vchPubKey;
		vchPubKey = vchFromString(params[4].get_str());
		boost::algorithm::unhex(vchPubKey.begin(), vchPubKey.end(), std::back_inserter(vchPubKeyByte));
	}

	string strSafeSearch = "Yes";
	if(params.size() >= 4)
	{
		strSafeSearch = params[3].get_str();
	}
	if(params.size() >= 6)
	{
		nRenewal = atoi(params[5].get_str());
	}
	EnsureWalletIsUnlocked();
	CTransaction tx;
	CAliasIndex theAlias;
	if (!GetTxOfAlias(vchAlias, theAlias, tx, true))
		throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1028 - " + _("Could not find an alias with this name"));

    if(!IsSyscoinTxMine(tx, "alias")) {
		throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1029 - " + _("This alias is not yours, you cannot update it"));
    }
	wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL)
		throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1030 - " + _("This alias is not in your wallet"));

	CPubKey pubKey(theAlias.vchPubKey);	
	CSyscoinAddress aliasAddress(pubKey.GetID());
	CKeyID keyID;
	if (!aliasAddress.GetKeyID(keyID))
		throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1031 - " + _("Alias address does not refer to a key"));
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1032 - " + _("Private key for alias is not known"));
	
	vector<unsigned char> vchPrivateKey;
	if(vchPubKeyByte.empty())
	{
		vchPubKeyByte = theAlias.vchPubKey;
		vchSecret = CKey();
	}

	if(!vchPrivateValue.empty())
	{
		string strCipherText;
		
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchPrivateValue, strCipherText))
		{
			throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1033 - " + _("Could not encrypt alias private data"));
		}
		vchPrivateValue = vchFromString(strCipherText);
	}
	if(vchSecret.size() > 0)
	{
		string strPrivateKey = CSyscoinSecret(vchSecret).ToString();
		string strCipherText;
		
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchFromString(strPrivateKey), strCipherText))
		{
			throw runtime_error("SYSCOIN_ALIAS_RPC_ERROR: ERRCODE: 1034 - " + _("Could not encrypt alias private key"));
		}
		vchPrivateKey = vchFromString(strCipherText);
	}

	CAliasIndex copyAlias = theAlias;
	theAlias.ClearAlias();
	theAlias.nHeight = chainActive.Tip()->nHeight;
	if(copyAlias.vchPublicValue != vchPublicValue)
		theAlias.vchPublicValue = vchPublicValue;
	if(copyAlias.vchPrivateValue != vchPrivateValue)
		theAlias.vchPrivateValue = vchPrivateValue;
	
	theAlias.vchPubKey = vchPubKeyByte;
	theAlias.vchPrivateKey = vchPrivateKey;
	theAlias.nRenewal = nRenewal;
	theAlias.safeSearch = strSafeSearch == "Yes"? true: false;
	CPubKey currentKey(vchPubKeyByte);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());

	const vector<unsigned char> &data = theAlias.Serialize();
    uint256 hash = Hash(data.begin(), data.end());
 	vector<unsigned char> vchHash = CScriptNum(hash.GetCheapHash()).getvch();
    vector<unsigned char> vchHashAlias = vchFromValue(HexStr(vchHash));

	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << vchAlias << copyAlias.vchGUID << vchHashAlias << OP_2DROP << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	// calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
	if(nRenewal > 1)
		fee.nAmount +=  0.02*COIN*nRenewal*nRenewal;
	
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
	
	vector<unsigned char> vchAlias;

	if (params.size() == 1)
		vchAlias = vchFromValue(params[0]);

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
			if (!GetAliasOfTx(wtx, vchAlias))
				continue;

			// skip this alias if it doesn't match the given filter value
			if (vchNameUniq.size() > 0 && vchNameUniq != vchAlias)
				continue;
			vector<CAliasIndex> vtxPos;
			CAliasIndex alias;
			if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
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
			if (vNamesI.find(vchAlias) != vNamesI.end() && (nHeight <= vNamesI[vchAlias] || vNamesI[vchAlias] < 0))
				continue;	
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
			// build the output UniValue
			UniValue oName(UniValue::VOBJ);
			oName.push_back(Pair("name", stringFromVch(vchAlias)));
			oName.push_back(Pair("value", stringFromVch(alias.vchPublicValue)));
			string strPrivateValue = "";
			if(!alias.vchPrivateValue.empty())
				strPrivateValue = "Encrypted for alias owner";
			string strDecrypted = "";
			if(DecryptMessage(alias.vchPubKey, alias.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));

			string strPrivateKey = "";
			if(!alias.vchPrivateKey.empty())
				strPrivateKey = "Encrypted for alias owner";
			string strDecryptedKey = "";
			if(DecryptMessage(alias.vchPubKey, alias.vchPrivateKey, strDecryptedKey))
				strPrivateKey = strDecryptedKey;		
			oName.push_back(Pair("privatekey", strPrivateKey));

			oName.push_back(Pair("safesearch", alias.safeSearch ? "Yes" : "No"));
			oName.push_back(Pair("safetylevel", alias.safetyLevel ));
			float ratingAsBuyer = 0;
			if(alias.nRatingCountAsBuyer > 0)
				ratingAsBuyer = roundf(alias.nRatingAsBuyer/(float)alias.nRatingCountAsBuyer);
			float ratingAsSeller = 0;
			if(alias.nRatingCountAsSeller > 0)
				ratingAsSeller = roundf(alias.nRatingAsSeller/(float)alias.nRatingCountAsSeller);
			float ratingAsArbiter = 0;
			if(alias.nRatingCountAsArbiter > 0)
				ratingAsArbiter = roundf(alias.nRatingAsArbiter/(float)alias.nRatingCountAsArbiter);
			oName.push_back(Pair("buyer_rating", (int)ratingAsBuyer));
			oName.push_back(Pair("buyer_ratingcount", alias.nRatingCountAsBuyer));
			oName.push_back(Pair("seller_rating", (int)ratingAsSeller));
			oName.push_back(Pair("seller_ratingcount", alias.nRatingCountAsSeller));
			oName.push_back(Pair("arbiter_rating", (int)ratingAsArbiter));
			oName.push_back(Pair("arbiter_ratingcount", alias.nRatingCountAsArbiter));
			expired_block = nHeight + (alias.nRenewal*GetAliasExpirationDepth());
			if(vchAlias != vchFromString("sysrates.peg") && vchAlias != vchFromString("sysban") && vchAlias != vchFromString("syscategory"))
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
			vNamesI[vchAlias] = nHeight;
			vNamesO[vchAlias] = oName;					

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
			vector<COffer> offerVtxPos;
			if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, tx, offerVtxPos))
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
					if(nHeight + (theAlias.nRenewal*GetAliasExpirationDepth()) - chainActive.Tip()->nHeight > 0)
					{
						expires_in = nHeight + (theAlias.nRenewal*GetAliasExpirationDepth())  - chainActive.Tip()->nHeight;
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
string GenerateSyscoinGuid()
{
	int64_t rand = GetRand(std::numeric_limits<int64_t>::max());
	vector<unsigned char> vchGuidRand = CScriptNum(rand).getvch();
	return HexStr(vchGuidRand);
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
	vector<unsigned char> vchAlias = vchFromValue(params[0]);

	CTransaction tx;
	CAliasIndex alias;
	UniValue oShowResult(UniValue::VOBJ);

	{
		// check for alias existence in DB
		vector<CAliasIndex> vtxPos;
		bool isExpired = false;
		if (!GetTxAndVtxOfAlias(vchAlias, alias, tx, vtxPos, isExpired, true))
			throw runtime_error("failed to read from alias DB");
	

		UniValue oName(UniValue::VOBJ);
		uint64_t nHeight;
		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
		nHeight = alias.nHeight;
		oName.push_back(Pair("name", stringFromVch(vchAlias)));

		if(alias.safetyLevel >= SAFETY_LEVEL2)
			throw runtime_error("alias has been banned");
		oName.push_back(Pair("value", stringFromVch(alias.vchPublicValue)));
		string strPrivateValue = "";
		if(!alias.vchPrivateValue.empty())
			strPrivateValue = "Encrypted for alias owner";
		string strDecrypted = "";
		if(DecryptMessage(alias.vchPubKey, alias.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));

		string strPrivateKey = "";
		if(!alias.vchPrivateKey.empty())
			strPrivateKey = "Encrypted for alias owner";
		string strDecryptedKey = "";
		if(DecryptMessage(alias.vchPubKey, alias.vchPrivateKey, strDecryptedKey))
			strPrivateKey = strDecryptedKey;		
		oName.push_back(Pair("privatekey", strPrivateKey));

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
		float ratingAsBuyer = 0;
		if(alias.nRatingCountAsBuyer > 0)
			ratingAsBuyer = roundf(alias.nRatingAsBuyer/(float)alias.nRatingCountAsBuyer);
		float ratingAsSeller = 0;
		if(alias.nRatingCountAsSeller > 0)
			ratingAsSeller = roundf(alias.nRatingAsSeller/(float)alias.nRatingCountAsSeller);
		float ratingAsArbiter = 0;
		if(alias.nRatingCountAsArbiter > 0)
			ratingAsArbiter = roundf(alias.nRatingAsArbiter/(float)alias.nRatingCountAsArbiter);
		oName.push_back(Pair("buyer_rating", (int)ratingAsBuyer));
		oName.push_back(Pair("buyer_ratingcount", alias.nRatingCountAsBuyer));
		oName.push_back(Pair("seller_rating", (int)ratingAsSeller));
		oName.push_back(Pair("seller_ratingcount", alias.nRatingCountAsSeller));
		oName.push_back(Pair("arbiter_rating", (int)ratingAsArbiter));
		oName.push_back(Pair("arbiter_ratingcount", alias.nRatingCountAsArbiter));
        oName.push_back(Pair("lastupdate_height", nHeight));
		expired_block = nHeight + (alias.nRenewal*GetAliasExpirationDepth());
		if(vchAlias != vchFromString("sysrates.peg") && vchAlias != vchFromString("sysban") && vchAlias != vchFromString("syscategory"))
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
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	string name = stringFromVch(vchAlias);

	{
		vector<CAliasIndex> vtxPos;
		if (!paliasdb->ReadAlias(vchAlias, vtxPos) || vtxPos.empty())
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
			if(!txPos2.vchPrivateValue.empty())
				strPrivateValue = "Encrypted for alias owner";
			string strDecrypted = "";
			if(DecryptMessage(txPos2.vchPubKey, txPos2.vchPrivateValue, strDecrypted))
				strPrivateValue = strDecrypted;		
			oName.push_back(Pair("privatevalue", strPrivateValue));

			string strPrivateKey = "";
			if(!txPos2.vchPrivateKey.empty())
				strPrivateKey = "Encrypted for alias owner";
			string strDecryptedKey = "";
			if(DecryptMessage(txPos2.vchPubKey, txPos2.vchPrivateKey, strDecryptedKey))
				strPrivateKey = strDecryptedKey;		
			oName.push_back(Pair("privatekey", strPrivateKey));

			oName.push_back(Pair("txid", tx.GetHash().GetHex()));
			CPubKey PubKey(txPos2.vchPubKey);
			CSyscoinAddress address(PubKey.GetID());
			oName.push_back(Pair("address", address.ToString()));
            oName.push_back(Pair("lastupdate_height", nHeight));
			float ratingAsBuyer = 0;
			if(txPos2.nRatingCountAsBuyer > 0)
				ratingAsBuyer = roundf(txPos2.nRatingAsBuyer/(float)txPos2.nRatingCountAsBuyer);
			float ratingAsSeller = 0;
			if(txPos2.nRatingCountAsSeller > 0)
				ratingAsSeller = roundf(txPos2.nRatingAsSeller/(float)txPos2.nRatingCountAsSeller);
			float ratingAsArbiter = 0;
			if(txPos2.nRatingCountAsArbiter > 0)
				ratingAsArbiter = roundf(txPos2.nRatingAsArbiter/(float)txPos2.nRatingCountAsArbiter);
			oName.push_back(Pair("buyer_rating", (int)ratingAsBuyer));
			oName.push_back(Pair("buyer_ratingcount", txPos2.nRatingCountAsBuyer));
			oName.push_back(Pair("seller_rating", (int)ratingAsSeller));
			oName.push_back(Pair("seller_ratingcount", txPos2.nRatingCountAsSeller));
			oName.push_back(Pair("arbiter_rating", (int)ratingAsArbiter));
			oName.push_back(Pair("arbiter_ratingcount", txPos2.nRatingCountAsArbiter));
			expired_block = nHeight + (txPos2.nRenewal*GetAliasExpirationDepth()) ;
			if(vchAlias != vchFromString("sysrates.peg") && vchAlias != vchFromString("sysban") && vchAlias != vchFromString("syscategory"))
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
UniValue importalias(const UniValue& params, bool fHelp) {
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	if(!pwalletMain)
		throw runtime_error("No wallet defined!");
	int count = 0;
	vector<CAliasIndex> vtxPos;
	CAliasIndex theAlias;
	CTransaction aliastx;
	bool isExpired;
	if(!GetTxAndVtxOfAlias(vchAlias, theAlias, aliastx, vtxPos, isExpired))
	{
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or expired alias");
	}
	string strDecryptedKey = "";
	DecryptMessage(theAlias.vchPubKey, theAlias.vchPrivateKey, strDecryptedKey);
		
    CSyscoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strDecryptedKey);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey();
    CKeyID vchAddress = pubkey.GetID();
 
	if (!pwalletMain->HaveKey(vchAddress))
	{
		pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;
		if (!pwalletMain->AddKeyPubKey(key, pubkey))
			throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
	}	
	CWalletDB walletdb(pwalletMain->strWalletFile);
	BOOST_FOREACH(theAlias, vtxPos) {
		CTransaction tx;
		if (GetSyscoinTransaction(theAlias.nHeight, theAlias.txHash, tx, Params().GetConsensus()))
		{
            CBlock block;
            if(ReadBlockFromDisk(block, chainActive[theAlias.nHeight], Params().GetConsensus()))
			{
				pwalletMain->SyncTransaction(tx, &block);
			}
		}
	}
	UniValue res(UniValue::VARR);
	res.push_back("Success!");
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

	vector<unsigned char> vchAlias;
	string strRegexp;
	string strName;
	bool safeSearch = true;


	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
	{
		vchAlias = vchFromValue(params[1]);
		strName = params[1].get_str();
	}

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

	UniValue oRes(UniValue::VARR);

	
	vector<pair<vector<unsigned char>, CAliasIndex> > nameScan;
	boost::algorithm::to_lower(strName);
	vchAlias = vchFromString(strName);
	if (!paliasdb->ScanNames(vchAlias, strRegexp, safeSearch, 25, nameScan))
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
		if(!alias.vchPrivateValue.empty())
			strPrivateValue = "Encrypted for alias owner";
		string strDecrypted = "";
		if(DecryptMessage(txName.vchPubKey, alias.vchPrivateValue, strDecrypted))
			strPrivateValue = strDecrypted;		
		oName.push_back(Pair("privatevalue", strPrivateValue));

		string strPrivateKey = "";
		if(!txName.vchPrivateKey.empty())
			strPrivateKey = "Encrypted for alias owner";
		string strDecryptedKey = "";
		if(DecryptMessage(txName.vchPubKey, txName.vchPrivateKey, strDecryptedKey))
			strPrivateKey = strDecryptedKey;		
		oName.push_back(Pair("privatekey", strPrivateKey));


        oName.push_back(Pair("lastupdate_height", nHeight));
		float ratingAsBuyer = 0;
		if(alias.nRatingCountAsBuyer > 0)
			ratingAsBuyer = roundf(alias.nRatingAsBuyer/(float)alias.nRatingCountAsBuyer);
		float ratingAsSeller = 0;
		if(alias.nRatingCountAsSeller > 0)
			ratingAsSeller = roundf(alias.nRatingAsSeller/(float)alias.nRatingCountAsSeller);
		float ratingAsArbiter = 0;
		if(alias.nRatingCountAsArbiter > 0)
			ratingAsArbiter = roundf(alias.nRatingAsArbiter/(float)alias.nRatingCountAsArbiter);
		oName.push_back(Pair("buyer_rating", (int)ratingAsBuyer));
		oName.push_back(Pair("buyer_ratingcount", alias.nRatingCountAsBuyer));
		oName.push_back(Pair("seller_rating", (int)ratingAsSeller));
		oName.push_back(Pair("seller_ratingcount", alias.nRatingCountAsSeller));
		oName.push_back(Pair("arbiter_rating", (int)ratingAsArbiter));
		oName.push_back(Pair("arbiter_ratingcount", alias.nRatingCountAsArbiter));
		expired_block = nHeight + (alias.nRenewal*GetAliasExpirationDepth());
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));

		
		oRes.push_back(oName);
	}


	return oRes;
}
