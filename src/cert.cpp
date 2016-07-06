#include "cert.h"
#include "alias.h"
#include "offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "rpcserver.h"
#include "wallet/wallet.h"
#include "chainparams.h"
#include "messagecrypter.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
using namespace std;
extern void SendMoneySyscoin(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInOffer=NULL, const CWalletTx* wtxInCert=NULL, const CWalletTx* wtxInAlias=NULL, const CWalletTx* wtxInEscrow=NULL, bool syscoinTx=true);
bool EncryptMessage(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchMessage, string &strCipherText)
{
	CMessageCrypter crypter;
	if(!crypter.Encrypt(stringFromVch(vchPubKey), stringFromVch(vchMessage), strCipherText))
		return false;

	return true;
}
bool DecryptMessage(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchCipherText, string &strMessage)
{
	CKey PrivateKey;
	CPubKey PubKey(vchPubKey);
	CKeyID pubKeyID = PubKey.GetID();
	if (!pwalletMain->GetKey(pubKeyID, PrivateKey))
        return false;
	CSyscoinSecret Secret(PrivateKey);
	PrivateKey = Secret.GetKey();
	std::vector<unsigned char> vchPrivateKey(PrivateKey.begin(), PrivateKey.end());
	CMessageCrypter crypter;
	if(!crypter.Decrypt(stringFromVch(vchPrivateKey), stringFromVch(vchCipherText), strMessage))
		return false;
	
	return true;
}
void PutToCertList(std::vector<CCert> &certList, CCert& index) {
	int i = certList.size() - 1;
	BOOST_REVERSE_FOREACH(CCert &o, certList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	certList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	certList[i] = index;
            return;
        }
        i--;
	}
    certList.push_back(index);
}
bool IsCertOp(int op) {
    return op == OP_CERT_ACTIVATE
        || op == OP_CERT_UPDATE
        || op == OP_CERT_TRANSFER;
}

// Increase expiration to 36000 gradually starting at block 24000.
// Use for validation purposes and pass the chain height.
int GetCertExpirationDepth() {
	#ifdef ENABLE_DEBUGRPC
    return 100;
  #else
    return 525600;
  #endif
}


string certFromOp(int op) {
    switch (op) {
    case OP_CERT_ACTIVATE:
        return "certactivate";
    case OP_CERT_UPDATE:
        return "certupdate";
    case OP_CERT_TRANSFER:
        return "certtransfer";
    default:
        return "<unknown cert op>";
    }
}
bool CCert::UnserializeFromData(const vector<unsigned char> &vchData) {
    try {
        CDataStream dsCert(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsCert >> *this;
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
bool CCert::UnserializeFromTx(const CTransaction &tx) {
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
const vector<unsigned char> CCert::Serialize() {
    CDataStream dsCert(SER_NETWORK, PROTOCOL_VERSION);
    dsCert << *this;
    const vector<unsigned char> vchData(dsCert.begin(), dsCert.end());
    return vchData;

}
bool CCertDB::ScanCerts(const std::vector<unsigned char>& vchCert, const string &strRegexp, bool safeSearch, unsigned int nMax,
        std::vector<std::pair<std::vector<unsigned char>, CCert> >& certScan) {
    // regexp
    using namespace boost::xpressive;
    smatch certparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
    sregex cregex = sregex::compile(strRegexpLower);
	int nMaxAge  = GetCertExpirationDepth();
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->Seek(make_pair(string("certi"), vchCert));
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "certi") {
            	vector<unsigned char> vchCert = key.second;
                vector<CCert> vtxPos;
				pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CCert &txPos = vtxPos.back();
  				if (chainActive.Tip()->nHeight - txPos.nHeight >= nMaxAge)
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
				CPubKey OwnerPubKey(txPos.vchPubKey);
				CSyscoinAddress owneraddy(OwnerPubKey.GetID());
				owneraddy = CSyscoinAddress(owneraddy.ToString());
				if(!owneraddy.IsValid() || !owneraddy.isAlias)
				{
					pcursor->Next();
					continue;
				}
				if((owneraddy.nHeight + GetAliasExpirationDepth()) < chainActive.Tip()->nHeight)
				{
					pcursor->Next();
					continue;
				}
				if(!owneraddy.safeSearch && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				if((safeSearch && owneraddy.safetyLevel > txPos.safetyLevel) || (!safeSearch && owneraddy.safetyLevel > SAFETY_LEVEL1))
				{
					pcursor->Next();
					continue;
				}
				const string &cert = stringFromVch(vchCert);
				string title = stringFromVch(txPos.vchTitle);
				boost::algorithm::to_lower(title);
				if (strRegexp != "" && !regex_search(title, certparts, cregex) && strRegexp != cert)
				{
					pcursor->Next();
					continue;
				}
				certScan.push_back(make_pair(vchCert, txPos));
			}
			if (certScan.size() >= nMax)
				break;

			pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfCertOutput(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
    int op, nOut;
	bool good = DecodeCertTx(tx, op, nOut, vvch);
	if (!good)
		return -1;
    return nOut;
}

bool GetTxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, CTransaction& tx, bool skipExpiresCheck) {
    vector<CCert> vtxPos;
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && (nHeight + GetCertExpirationDepth()
            < chainActive.Tip()->nHeight)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    if (!GetSyscoinTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfCert() : could not read tx from disk");

    return true;
}
bool DecodeAndParseCertTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CCert cert;
	bool decode = DecodeCertTx(tx, op, nOut, vvch);
	bool parse = cert.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeCertTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeCertScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found && IsCertOp(op);
}


bool DecodeCertScript(const CScript& script, int& op,
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

    if ((op == OP_CERT_ACTIVATE && vvch.size() == 1)
        || (op == OP_CERT_UPDATE && vvch.size() == 1)
        || (op == OP_CERT_TRANSFER && vvch.size() == 1))
        return true;
    return false;
}
bool DecodeCertScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeCertScript(script, op, vvch, pc);
}
CScript RemoveCertScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeCertScript(scriptIn, op, vvch, pc))
        throw runtime_error(
                "RemoveCertScriptPrefix() : could not decode cert script");
	
    return CScript(pc, scriptIn.end());
}

bool CheckCertInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs,
        const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, const CBlock* block) {
	
	if (tx.IsCoinBase())
		return true;
		LogPrintf("*** %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
    bool foundCert = false;
    const COutPoint *prevOutput = NULL;
    CCoins prevCoins;

    int prevOp = 0;
	
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

			if (!foundCert && IsCertOp(pop)) {
				foundCert = true; 
				prevOp = pop;
				vvchPrevArgs = vvch;
				break;
			}
		}
	}
    // Make sure cert outputs are not spent by a regular transaction, or the cert would be lost
    if (tx.nVersion != SYSCOIN_TX_VERSION) {
        if (foundCert)
            return error(
                    "CheckCertInputs() : a non-syscoin transaction with a syscoin input");
        return true;
    }
    // unserialize cert object from txn, check for valid
    CCert theCert(tx);
	// we need to check for cert update specially because a cert update without data is sent along with offers linked with the cert
    if (theCert.IsNull() && op != OP_CERT_UPDATE)
        return true;
	if(theCert.vchData.size() > MAX_ENCRYPTED_VALUE_LENGTH)
	{
		return error("cert data too big");
	}
	if(theCert.vchTitle.size() > MAX_NAME_LENGTH)
	{
		return error("cert title too big");
	}
	if(!theCert.vchPubKey.empty() && !IsSysCompressedOrUncompressedPubKey(theCert.vchPubKey))
	{
		return error("cert pub key invalid length");
	}
	if(!theCert.vchCert.empty() && theCert.vchCert != vvchArgs[0])
	{
		return error("guid in data output doesn't match guid in tx");
	}
    if (vvchArgs[0].size() > MAX_NAME_LENGTH)
        return error("cert hex guid too long");
	vector<CAliasIndex> vtxAliasPos;
	vector<CCert> vtxPos;
	string retError = "";
	if(fJustCheck)
	{
		switch (op) {
		case OP_CERT_ACTIVATE:
			if (foundCert)
				return error(
						"CheckCertInputs() : certactivate tx pointing to previous syscoin tx");
			break;

		case OP_CERT_UPDATE:
			// previous op must be a cert
			if ( !foundCert || !IsCertOp(prevOp))
				return error("CheckCertInputs(): certupdate previous op is invalid");
			if (vvchPrevArgs[0] != vvchArgs[0])
				return error("CheckCertInputs(): certupdate prev cert mismatch vvchPrevArgs[0]: %s, vvchArgs[0] %s", stringFromVch(vvchPrevArgs[0]).c_str(), stringFromVch(vvchArgs[0]).c_str());	
			break;

		case OP_CERT_TRANSFER:
			// validate conditions
			if ( !foundCert || !IsCertOp(prevOp))
				return error("certtransfer previous op is invalid");
			if (vvchPrevArgs[0] != vvchArgs[0])
				return error("CheckCertInputs() : certtransfer cert mismatch");

			if (!pcertdb->ReadCert(vvchArgs[0], vtxPos) || vtxPos.empty())
				return error("CheckCertInputs() : failed to read from cert DB");
			if((retError = CheckForAliasExpiry(vtxPos.back().vchPubKey, nHeight)) != "")
			{
				retError = string("CheckCertInputs(): ") + retError;
				return error(retError.c_str());
			}
			break;

		default:
			return error( "CheckCertInputs() : cert transaction has unknown op");
		}
		if((retError = CheckForAliasExpiry(theCert.vchPubKey, nHeight)) != "")
		{
			retError = string("CheckCertInputs(): ") + retError;
			return error(retError.c_str());
		}
	}

    if (!fJustCheck ) {
		if(op != OP_CERT_ACTIVATE) 
		{
			// if not an certnew, load the cert data from the DB
			
			if (pcertdb->ExistsCert(vvchArgs[0])) {
				if (!pcertdb->ReadCert(vvchArgs[0], vtxPos))
					return error(
							"CheckCertInputs() : failed to read from cert DB");
			}
			if(!vtxPos.empty())
			{
				if((vtxPos.back().nHeight + GetCertExpirationDepth()) < nHeight)
				{
					if(fDebug)
						LogPrintf("CheckCertInputs(): Trying to update an expired service");
					return true;
				}
				if(theCert.IsNull())
					theCert = vtxPos.back();
				else
				{
					const CCert& dbCert = vtxPos.back();
					if(theCert.vchData.empty())
						theCert.vchData = dbCert.vchData;
					if(theCert.vchTitle.empty())
						theCert.vchTitle = dbCert.vchTitle;
					// user can't update safety level after creation
					theCert.safetyLevel = dbCert.safetyLevel;

				}
			}
			else
				return true;
		}

        // set the cert's txn-dependent values
		theCert.nHeight = nHeight;
		theCert.txHash = tx.GetHash();
		PutToCertList(vtxPos, theCert);
        // write cert  

        if (!pcertdb->WriteCert(vvchArgs[0], vtxPos))
            return error( "CheckCertInputs() : failed to write to cert DB");
		

      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED CERT: op=%s cert=%s title=%s hash=%s height=%d\n",
                certFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                stringFromVch(theCert.vchTitle).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
    }
    return true;
}





UniValue certnew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
		"certnew <alias> <title> <data> [private=0] [safe search=Yes]\n"
						"<alias> An alias you own.\n"
                        "<title> title, 255 bytes max.\n"
                        "<data> data, 1KB max.\n"
						"<private> set to 1 if you only want to make the cert data private, only the owner of the cert can view it. Off by default.\n"
 						"<safe search> set to No if this cert should only show in the search when safe search is not selected. Defaults to Yes (cert shows with or without safe search selected in search lists).\n"                     
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchAlias = vchFromValue(params[0]);
	CSyscoinAddress aliasAddress = CSyscoinAddress(stringFromVch(vchAlias));
	if (!aliasAddress.IsValid())
		throw runtime_error("Invalid syscoin address");
	if (!aliasAddress.isAlias)
		throw runtime_error("Offer must be a valid alias");

	CAliasIndex alias;
	CTransaction aliastx;
	if (!GetTxOfAlias(vchAlias, alias, aliastx))
		throw runtime_error("could not find an alias with this name");
    if(!IsSyscoinTxMine(aliastx, "alias")) {
		throw runtime_error("This alias is not yours.");
    }
	const CWalletTx *wtxAliasIn = pwalletMain->GetWalletTx(aliastx.GetHash());
	if (wtxAliasIn == NULL)
		throw runtime_error("this alias is not in your wallet");
	vector<unsigned char> vchTitle = vchFromString(params[1].get_str());
    vector<unsigned char> vchData = vchFromString(params[2].get_str());
	bool bPrivate = false;
    if(vchTitle.size() < 1)
        throw runtime_error("certificate cannot be empty!");

    if(vchTitle.size() > MAX_NAME_LENGTH)
        throw runtime_error("certificate title cannot exceed 255 bytes!");

	if(params.size() >= 4)
	{
		bPrivate = atoi(params[3].get_str().c_str()) == 1? true: false;
	}
	string strSafeSearch = "Yes";
	if(params.size() >= 5)
	{
		strSafeSearch = params[4].get_str();
	}
    if (vchData.size() < 1)
	{
        vchData = vchFromString(" ");
		bPrivate = false;
	}
    // gather inputs
	int64_t rand = GetRand(std::numeric_limits<int64_t>::max());
	vector<unsigned char> vchRand = CScriptNum(rand).getvch();
    vector<unsigned char> vchCert = vchFromValue(HexStr(vchRand));

    // this is a syscoin transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();
    CScript scriptPubKeyOrig;
	CPubKey aliasKey(alias.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(aliasKey.GetID());
    CScript scriptPubKey;

    

	if(bPrivate)
	{
		string strCipherText;
		if(!EncryptMessage(alias.vchPubKey, vchData, strCipherText))
		{
			throw runtime_error("Could not encrypt certificate data!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("data length cannot exceed 1023 bytes!");
		vchData = vchFromString(strCipherText);
	}

	// calculate net
    // build cert object
    CCert newCert;
	newCert.vchCert = vchCert;
    newCert.vchTitle = vchTitle;
	newCert.vchData = vchData;
	newCert.nHeight = chainActive.Tip()->nHeight;
	newCert.vchPubKey = alias.vchPubKey;
	newCert.bPrivate = bPrivate;
	newCert.safetyLevel = 0;
	newCert.safeSearch = strSafeSearch == "Yes"? true: false;

    scriptPubKey << CScript::EncodeOP_N(OP_CERT_ACTIVATE) << vchCert << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;


	// use the script pub key to create the vecsend which sendmoney takes and puts it into vout
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	const vector<unsigned char> &data = newCert.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);

	const CWalletTx * wtxInAlias=NULL;
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	const CWalletTx * wtxInCert=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxInCert, wtxInAlias, wtxInEscrow);
	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchRand));
	return res;
}

UniValue certupdate(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
		"certupdate <guid> <title> <data> <private> [safesearch=Yes]\n"
                        "Perform an update on an certificate you control.\n"
                        "<guid> certificate guidkey.\n"
                        "<title> certificate title, 255 bytes max.\n"
                        "<data> certificate data, 1KB max.\n"
						"<private> set to 1 if you only want to make the cert data private, only the owner of the cert can view it.\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchCert = vchFromValue(params[0]);
    vector<unsigned char> vchTitle = vchFromValue(params[1]);
    vector<unsigned char> vchData = vchFromValue(params[2]);

	bool bPrivate = atoi(params[3].get_str().c_str()) == 1? true: false;
	string strSafeSearch = "Yes";
	if(params.size() >= 5)
	{
		strSafeSearch = params[4].get_str();
	}
    if(vchTitle.size() < 1)
        throw runtime_error("certificate title cannot be empty!");
    if(vchTitle.size() > MAX_NAME_LENGTH)
        throw runtime_error("certificate title cannot exceed 255 bytes!");

    if (vchData.size() < 1)
        vchData = vchFromString(" ");
    // this is a syscoind txn
    CWalletTx wtx;
	const CWalletTx* wtxIn;
    CScript scriptPubKeyOrig;

    EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CCert theCert;
    if (!GetTxOfCert( vchCert, theCert, tx))
        throw runtime_error("could not find a certificate with this key");
    // make sure cert is in wallet
	wtxIn = pwalletMain->GetWalletTx(tx.GetHash());
	if (wtxIn == NULL || !IsSyscoinTxMine(tx, "cert"))
		throw runtime_error("this cert is not in your wallet");
      	// check for existing cert 's
	if (ExistsInMempool(vchCert, OP_CERT_ACTIVATE) || ExistsInMempool(vchCert, OP_CERT_UPDATE) || ExistsInMempool(vchCert, OP_CERT_TRANSFER)) {
		throw runtime_error("there are pending operations on that cert");
	}

	CCert copyCert = theCert;
	theCert.ClearCert();
	CPubKey currentKey(theCert.vchPubKey);
	scriptPubKeyOrig = GetScriptForDestination(currentKey.GetID());
    // create CERTUPDATE txn keys
    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_UPDATE) << vchCert << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;
	// if we want to make data private, encrypt it
	if(bPrivate)
	{
		string strCipherText;
		if(!EncryptMessage(copyCert.vchPubKey, vchData, strCipherText))
		{
			throw runtime_error("Could not encrypt certificate data!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("data length cannot exceed 1023 bytes!");
		vchData = vchFromString(strCipherText);
	}

    if(copyCert.vchTitle != vchTitle)
		theCert.vchTitle = vchTitle;
	if(copyCert.vchData != vchData)
		theCert.vchData = vchData;
	theCert.nHeight = chainActive.Tip()->nHeight;
	theCert.bPrivate = bPrivate;
	theCert.safeSearch = strSafeSearch == "Yes"? true: false;


	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	const vector<unsigned char> &data = theCert.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInAlias=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxIn, wtxInAlias, wtxInEscrow);	
 	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	return res;
}


UniValue certtransfer(const UniValue& params, bool fHelp) {
 if (fHelp || params.size() != 2)
        throw runtime_error(
		"certtransfer <certkey> <alias>\n"
                "<certkey> certificate guidkey.\n"
				"<alias> Alias to transfer this certificate to.\n"
                 + HelpRequiringPassphrase());

    // gather & validate inputs
	vector<unsigned char> vchCert = vchFromValue(params[0]);

	string strAddress = params[1].get_str();
	CPubKey xferKey;
	std::vector<unsigned char> vchPubKey;
	std::vector<unsigned char> vchPubKeyByte;
	try
	{
		vchPubKey = vchFromString(strAddress);		
		boost::algorithm::unhex(vchPubKey.begin(), vchPubKey.end(), std::back_inserter(vchPubKeyByte));
		xferKey  = CPubKey(vchPubKeyByte);
		if(!xferKey.IsValid())
		{
			throw runtime_error("Invalid public key");
		}
	}
	catch(...)
	{
		CSyscoinAddress myAddress = CSyscoinAddress(strAddress);
		if (!myAddress.IsValid())
			throw runtime_error("Invalid syscoin address");
		if (!myAddress.isAlias)
			throw runtime_error("You must transfer to a valid alias");

		// check for alias existence in DB
		vector<CAliasIndex> vtxAliasPos;
		if (!paliasdb->ReadAlias(vchFromString(myAddress.aliasName), vtxAliasPos))
			throw runtime_error("failed to read alias from alias DB");
		if (vtxAliasPos.size() < 1)
			throw runtime_error("no result returned");
		CAliasIndex xferAlias = vtxAliasPos.back();
		vchPubKeyByte = xferAlias.vchPubKey;
		xferKey = CPubKey(vchPubKeyByte);
		if(!xferKey.IsValid())
		{
			throw runtime_error("Invalid transfer public key");
		}
	}


	CSyscoinAddress sendAddr;
    // this is a syscoin txn
    CWalletTx wtx;
	const CWalletTx* wtxIn;
    CScript scriptPubKeyOrig;

    EnsureWalletIsUnlocked();
	CCert theCert;
	// get the cert from DB
	vector<CCert> vtxPos;
	if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("could not read cert from DB");
	theCert = vtxPos.back();

	// check to see if certificate in wallet
	wtxIn = pwalletMain->GetWalletTx(theCert.txHash);
	if (wtxIn == NULL || !IsSyscoinTxMine(*wtxIn, "cert"))
		throw runtime_error("this certificate is not in your wallet");

	if (ExistsInMempool(vchCert, OP_CERT_UPDATE) || ExistsInMempool(vchCert, OP_CERT_TRANSFER)) {
		throw runtime_error("there are pending operations on that cert ");
	}
	// if cert is private, decrypt the data
	vector<unsigned char> vchData = theCert.vchData;
	if(theCert.bPrivate)
	{		
		string strData = "";
		string strDecryptedData = "";
		string strCipherText;
		
		// decrypt using old key
		if(DecryptMessage(theCert.vchPubKey, theCert.vchData, strData))
			strDecryptedData = strData;
		else
			throw runtime_error("Could not decrypt certificate data!");
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchFromString(strDecryptedData), strCipherText))
		{
			throw runtime_error("Could not encrypt certificate data!");
		}
		if (strCipherText.size() > MAX_ENCRYPTED_VALUE_LENGTH)
			throw runtime_error("data length cannot exceed 1023 bytes!");
		vchData = vchFromString(strCipherText);
	}	
	CCert copyCert = theCert;
	theCert.ClearCert();
    scriptPubKeyOrig= GetScriptForDestination(xferKey.GetID());
    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_TRANSFER) << vchCert << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;
	
	theCert.nHeight = chainActive.Tip()->nHeight;
	theCert.vchPubKey = vchPubKeyByte;
	if(copyCert.vchData != vchData)
		theCert.vchData = vchData;
    // send the cert pay txn
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	const vector<unsigned char> &data = theCert.Serialize();
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, data, fee);
	vecSend.push_back(fee);
	const CWalletTx * wtxInOffer=NULL;
	const CWalletTx * wtxInAlias=NULL;
	const CWalletTx * wtxInEscrow=NULL;
	SendMoneySyscoin(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxInOffer, wtxIn, wtxInAlias, wtxInEscrow);

	UniValue res(UniValue::VARR);
	res.push_back(wtx.GetHash().GetHex());
	return res;
}


UniValue certinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("certinfo <guid>\n"
                "Show stored values of a single certificate and its .\n");

    vector<unsigned char> vchCert = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an cert object if it is found
    CTransaction tx;

	vector<CCert> vtxPos;

	int expired = 0;
	int expires_in = 0;
	int expired_block = 0;
	UniValue oCert(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("failed to read from cert DB");
	CCert ca = vtxPos.back();
	if(ca.safetyLevel >= SAFETY_LEVEL2)
		throw runtime_error("cert has been banned");
	if (!GetSyscoinTransaction(ca.nHeight, ca.txHash, tx, Params().GetConsensus()))
		throw runtime_error("failed to read transaction from disk");   
	// get owner alias
	CPubKey SellerPubKey(vtxPos.back().vchPubKey);
	CSyscoinAddress address(SellerPubKey.GetID());
	address = CSyscoinAddress(address.ToString());

	// check that the seller isn't banned level 2
	vector<CAliasIndex> vtxAliasPos;
	if (!paliasdb->ReadAlias(vchFromString(address.aliasName), vtxAliasPos))
		throw runtime_error("failed to read owner alias from alias DB");
	if (vtxAliasPos.size() < 1)
		throw runtime_error("no owner found for this cert");
	if(vtxAliasPos.back().safetyLevel >= SAFETY_LEVEL2)
		throw runtime_error("cert owner has been banned");

    string sHeight = strprintf("%llu", ca.nHeight);
    oCert.push_back(Pair("cert", stringFromVch(vchCert)));
    oCert.push_back(Pair("txid", ca.txHash.GetHex()));
    oCert.push_back(Pair("height", sHeight));
    oCert.push_back(Pair("title", stringFromVch(ca.vchTitle)));
	string strData = stringFromVch(ca.vchData);
	string strDecrypted = "";
	if(ca.bPrivate)
	{
		if(DecryptMessage(ca.vchPubKey, ca.vchData, strDecrypted))
			strData = strDecrypted;		
	}
    oCert.push_back(Pair("data", strData));
	oCert.push_back(Pair("private", ca.bPrivate? "Yes": "No"));
	oCert.push_back(Pair("safesearch", ca.safeSearch ? "Yes" : "No"));
	oCert.push_back(Pair("safetylevel", ca.safetyLevel));
    oCert.push_back(Pair("ismine", IsSyscoinTxMine(tx, "cert") ? "true" : "false"));

    uint64_t nHeight;
	nHeight = ca.nHeight;
	oCert.push_back(Pair("address", address.ToString()));
	oCert.push_back(Pair("alias", address.aliasName));
	expired_block = nHeight + GetCertExpirationDepth();
    if(expired_block < chainActive.Tip()->nHeight)
	{
		expired = 1;
	}  
	expires_in = expired_block - chainActive.Tip()->nHeight;
	oCert.push_back(Pair("expires_in", expires_in));
	oCert.push_back(Pair("expires_on", expired_block));
	oCert.push_back(Pair("expired", expired));
    return oCert;
}

UniValue certlist(const UniValue& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("certlist [<cert>]\n"
                "list my own Certificates");
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
    CTransaction tx;

    vector<unsigned char> vchValue;
    uint64_t nHeight;
	int pending = 0;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
    {
		const CWalletTx &wtx = item.second;
		int expired = 0;
		pending = 0;
		int expires_in = 0;
		int expired_block = 0;
		// get txn hash, read txn index
        hash = item.second.GetHash();       

        // skip non-syscoin txns
        if (wtx.nVersion != SYSCOIN_TX_VERSION)
            continue;
		// decode txn, skip non-cert txns
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		if (!DecodeCertTx(wtx, op, nOut, vvch))
			continue;

		vchName = vvch[0];
		
		
		// skip this cert if it doesn't match the given filter value
		if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
			continue;
			
		vector<CCert> vtxPos;
		CCert cert;
		if (!pcertdb->ReadCert(vchName, vtxPos) || vtxPos.empty())
		{
			pending = 1;
			cert = CCert(wtx);
			if(!IsSyscoinTxMine(wtx, "cert"))
				continue;
		}
		else
		{
			cert = vtxPos.back();
			CTransaction tx;
			if (!GetSyscoinTransaction(cert.nHeight, cert.txHash, tx, Params().GetConsensus()))
			{
				pending = 1;
				if(!IsSyscoinTxMine(wtx, "cert"))
					continue;
			}
			else{
				if (!DecodeCertTx(tx, op, nOut, vvch) || !IsCertOp(op))
					continue;
				if(!IsSyscoinTxMine(tx, "cert"))
					continue;
			}
		}
		nHeight = cert.nHeight;
		// get last active name only
		if (vNamesI.find(vchName) != vNamesI.end() && (nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
			continue;

		
        // build the output object
		UniValue oName(UniValue::VOBJ);
        oName.push_back(Pair("cert", stringFromVch(vchName)));
        oName.push_back(Pair("title", stringFromVch(cert.vchTitle)));

		string strData = stringFromVch(cert.vchData);

		string strDecrypted = "";
		if(cert.bPrivate)
		{
			strData = "Encrypted for owner of certificate private data";
			if(DecryptMessage(cert.vchPubKey, cert.vchData, strDecrypted))
				strData = strDecrypted;	
		}
		oName.push_back(Pair("private", cert.bPrivate? "Yes": "No"));
		oName.push_back(Pair("safesearch", cert.safeSearch ? "Yes" : "No"));
		oName.push_back(Pair("safetylevel", cert.safetyLevel));
		oName.push_back(Pair("data", strData));
		CPubKey PubKey(cert.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		address = CSyscoinAddress(address.ToString());
		oName.push_back(Pair("address", address.ToString()));
		oName.push_back(Pair("alias", address.aliasName));
		expired_block = nHeight + GetCertExpirationDepth();
        if(expired_block < chainActive.Tip()->nHeight)
		{
			expired = 1;
		}  
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oName.push_back(Pair("expires_in", expires_in));
		oName.push_back(Pair("expires_on", expired_block));
		oName.push_back(Pair("expired", expired));
		oName.push_back(Pair("pending", pending));
 
		vNamesI[vchName] = nHeight;
		vNamesO[vchName] = oName;	
    
	}
    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
        oRes.push_back(item.second);
    return oRes;
}


UniValue certhistory(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("certhistory <cert>\n"
                "List all stored values of an cert.\n");

    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchCert = vchFromValue(params[0]);
    string cert = stringFromVch(vchCert);

    {
        vector<CCert> vtxPos;
        if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
            throw runtime_error("failed to read from cert DB");

        CCert txPos2;
        uint256 txHash;
        BOOST_FOREACH(txPos2, vtxPos) {
            txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetSyscoinTransaction(txPos2.nHeight, txHash, tx, Params().GetConsensus())) {
				error("could not read txpos");
				continue;
			}
            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeCertTx(tx, op, nOut, vvch) 
            	|| !IsCertOp(op) )
                continue;
			int expired = 0;
			int expires_in = 0;
			int expired_block = 0;
            UniValue oCert(UniValue::VOBJ);
            vector<unsigned char> vchValue;
            uint64_t nHeight;
			nHeight = txPos2.nHeight;
            oCert.push_back(Pair("cert", cert));
			string opName = certFromOp(op);
			oCert.push_back(Pair("certtype", opName));
			string strDecrypted = "";
			string strData = "";
			if(txPos2.bPrivate)
			{
				strData = "Encrypted for owner of certificate private data";
				if(DecryptMessage(txPos2.vchPubKey, txPos2.vchData, strDecrypted))
					strData = strDecrypted;

			}
			oCert.push_back(Pair("private", txPos2.bPrivate? "Yes": "No"));
			oCert.push_back(Pair("data", strData));
            oCert.push_back(Pair("txid", tx.GetHash().GetHex()));
			CPubKey PubKey(txPos2.vchPubKey);
			CSyscoinAddress address(PubKey.GetID());
			address = CSyscoinAddress(address.ToString());
			oCert.push_back(Pair("address", address.ToString()));
			oCert.push_back(Pair("alias", address.aliasName));
			expired_block = nHeight + GetCertExpirationDepth();
            if(expired_block < chainActive.Tip()->nHeight)
			{
				expired = 1;
			}  
			expires_in = expired_block - chainActive.Tip()->nHeight;
			oCert.push_back(Pair("expires_in", expires_in));
			oCert.push_back(Pair("expires_on", expired_block));
			oCert.push_back(Pair("expired", expired));
            oRes.push_back(oCert);
        }
    }
    return oRes;
}
UniValue certfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 3)
		throw runtime_error(
				"certfilter [[[[[regexp]] from=0]] safesearch='Yes']\n"
						"scan and filter certs\n"
						"[regexp] : apply [regexp] on certs, empty means all certs\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[certfilter] : shows all certs that are safe to display (not on the ban list)\n"
						"certfilter \"\" 5 # list certs updated in last 5 blocks\n"
						"certfilter \"^cert\" # list all certs starting with \"cert\"\n"
						"certfilter 36000 0 0 stat # display stats (number of certs) on active certs\n");

	vector<unsigned char> vchCert;
	string strRegexp;

	bool safeSearch = true;


	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchCert = vchFromValue(params[1]);

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

    UniValue oRes(UniValue::VARR);
    
    vector<pair<vector<unsigned char>, CCert> > certScan;
    if (!pcertdb->ScanCerts(vchCert, strRegexp, safeSearch, 25, certScan))
        throw runtime_error("scan failed");
    pair<vector<unsigned char>, CCert> pairScan;
	BOOST_FOREACH(pairScan, certScan) {
		const CCert &txCert = pairScan.second;
		const string &cert = stringFromVch(pairScan.first);

       int nHeight = txCert.nHeight;

		int expired = 0;
		int expires_in = 0;
		int expired_block = 0;
        UniValue oCert(UniValue::VOBJ);
        oCert.push_back(Pair("cert", cert));
		vector<unsigned char> vchValue = txCert.vchTitle;
        string value = stringFromVch(vchValue);
        oCert.push_back(Pair("title", value));

		string strData = stringFromVch(txCert.vchData);
		string strDecrypted = "";
		if(txCert.bPrivate)
		{
			strData = string("Encrypted for owner of certificate");
			if(DecryptMessage(txCert.vchPubKey, txCert.vchData, strDecrypted))
				strData = strDecrypted;
			
		}

		oCert.push_back(Pair("data", strData));
		oCert.push_back(Pair("private", txCert.bPrivate? "Yes": "No"));
		expired_block = nHeight + GetCertExpirationDepth();
        if(expired_block < chainActive.Tip()->nHeight)
		{
			expired = 1;
		}  
		expires_in = expired_block - chainActive.Tip()->nHeight;
		oCert.push_back(Pair("expires_in", expires_in));
		oCert.push_back(Pair("expires_on", expired_block));
		oCert.push_back(Pair("expired", expired));
		CPubKey PubKey(txCert.vchPubKey);
		CSyscoinAddress address(PubKey.GetID());
		address = CSyscoinAddress(address.ToString());
		oCert.push_back(Pair("address", address.ToString()));
		oCert.push_back(Pair("alias", address.aliasName));
        oRes.push_back(oCert);
	}


	return oRes;
}



