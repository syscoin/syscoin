#include "offer.h"
#include "init.h"
#include "txdb.h"
#include "util.h"
#include "auxpow.h"
#include "script.h"
#include "main.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"

#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

template<typename T> void ConvertTo(Value& value, bool fAllowNull = false);

std::map<std::vector<unsigned char>, uint256> mapMyOffers;
std::map<std::vector<unsigned char>, uint256> mapMyOfferAccepts;
std::map<std::vector<unsigned char>, std::set<uint256> > mapOfferPending;
std::map<std::vector<unsigned char>, std::set<uint256> > mapOfferAcceptPending;
std::list<COfferFee> lstOfferFees;

#ifdef GUI
extern std::map<uint160, std::vector<unsigned char> > mapMyOfferHashes;
#endif

extern COfferDB *pofferdb;

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo,
		unsigned int nIn, int nHashType);

CScript RemoveOfferScriptPrefix(const CScript& scriptIn);
bool DecodeOfferScript(const CScript& script, int& op,
		std::vector<std::vector<unsigned char> > &vvch,
		CScript::const_iterator& pc);

extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey,
		uint256 hash, int nHashType, CScript& scriptSigRet,
		txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey,
		const CTransaction& txTo, unsigned int nIn, unsigned int flags,
		int nHashType);

bool IsOfferOp(int op) {
	return op == OP_OFFER_NEW
        || op == OP_OFFER_ACTIVATE
        || op == OP_OFFER_UPDATE
        || op == OP_OFFER_ACCEPT
        || op == OP_OFFER_PAY;
}

// 10080 blocks = 1 week
// offer expiration time is ~ 2 weeks
// expiration blocks is 20160 (final)
// expiration starts at 6720, increases by 1 per block starting at
// block 13440 until block 349440

int nStartHeight = 161280;

int64 GetOfferNetworkFee(int seed, int nHeight) {
    if (fCakeNet) return CENT;
    int64 nRes = 88 * COIN;
    int64 nDif = 77 * COIN;
    if(seed==2) {
    	nRes = 474;
    	nDif = 360;
    }
    int nTargetHeight = 130080;
    if(nHeight>nTargetHeight) return nRes - nDif;
    else return nRes - ( (nHeight/nTargetHeight) * nDif );
}

// int64 GetOfferNetworkFee(int seed, int nHeight) {
// 	int nComputedHeight = nHeight - nStartHeight < 0 ? 1 : ( nHeight - nStartHeight ) + 1;
//     if (nComputedHeight >= 13440) nComputedHeight += (nComputedHeight - 13440) * 3;
//     int64 nStart = seed * COIN;
//     if (fTestNet) nStart = 10 * CENT;
//     else if (fCakeNet) return CENT;
//     int64 nRes = nStart >> (nComputedHeight >> 13);
//     nRes -= (nRes >> 14) * (nComputedHeight % 8192);
//     nRes += CENT - 1;
// 	nRes = (nRes / CENT) * CENT;
//     return nRes;
// }

// Increase expiration to 36000 gradually starting at block 24000.
// Use for validation purposes and pass the chain height.
int GetOfferExpirationDepth(int nHeight) {
	int nComputedHeight = ( nHeight - nStartHeight < 0 ) ? 1 : ( nHeight - nStartHeight ) + 1;
    if (nComputedHeight < 13440) return 6720;
    if (nComputedHeight < 26880) return nComputedHeight - 6720;
    return 20160;
}

// For display purposes, pass the name height.
int GetOfferDisplayExpirationDepth(int nHeight) {
    return GetOfferExpirationDepth(nHeight);
}

bool IsMyOffer(const CTransaction& tx, const CTxOut& txout) {
	const CScript& scriptPubKey = RemoveOfferScriptPrefix(txout.scriptPubKey);
	CScript scriptSig;
	txnouttype whichTypeRet;
	if (!Solver(*pwalletMain, scriptPubKey, 0, 0, scriptSig, whichTypeRet))
		return false;
    return true;
}

string offerFromOp(int op) {
	switch (op) {
	case OP_OFFER_NEW:
		return "offernew";
	case OP_OFFER_ACTIVATE:
		return "offeractivate";
	case OP_OFFER_UPDATE:
		return "offerupdate";
	case OP_OFFER_ACCEPT:
		return "offeraccept";
	case OP_OFFER_PAY:
        return "offerpay";
	default:
		return "<unknown offer op>";
	}
}

bool COffer::UnserializeFromTx(const CTransaction &tx) {
	try {
		CDataStream dsOffer(vchFromString(DecodeBase64(stringFromVch(tx.data))), SER_NETWORK, PROTOCOL_VERSION);
		dsOffer >> *this;
	} catch (std::exception &e) {
		return false;
	}
	return true;
}

void COffer::SerializeToTx(CTransaction &tx) {
	vector<unsigned char> vchData = vchFromString(SerializeToString());
	tx.data = vchData;
}

string COffer::SerializeToString() {
	// serialize offer object
	CDataStream dsOffer(SER_NETWORK, PROTOCOL_VERSION);
	dsOffer << *this;
	vector<unsigned char> vchData(dsOffer.begin(), dsOffer.end());
	return EncodeBase64(vchData.data(), vchData.size());
}

//TODO implement
bool COfferDB::ScanOffers(const std::vector<unsigned char>& vchOffer, unsigned int nMax,
		std::vector<std::pair<std::vector<unsigned char>, COffer> >& offerScan) {
    leveldb::Iterator *pcursor = pofferdb->NewIterator();

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair(string("offeri"), vchOffer);
    string sType;
    pcursor->Seek(ssKeySet.str());

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);

            ssKey >> sType;
            if(sType == "offeri") {
            	vector<unsigned char> vchOffer;
                ssKey >> vchOffer;
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                vector<COffer> vtxPos;
                ssValue >> vtxPos;
                COffer txPos;
                if (!vtxPos.empty())
                    txPos = vtxPos.back();
                offerScan.push_back(make_pair(vchOffer, txPos));
            }
            if (offerScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;
    return true;
}

/**
 * [COfferDB::ReconstructOfferIndex description]
 * @param  pindexRescan [description]
 * @return              [description]
 */
bool COfferDB::ReconstructOfferIndex(CBlockIndex *pindexRescan) {
    CBlockIndex* pindex = pindexRescan;
    
    {
	TRY_LOCK(pwalletMain->cs_wallet, cs_trylock);

	uint64 startHeight = pindexRescan->nHeight;
	while(pindex->pnext != NULL) pindex = pindex->pnext;
	uint64 endHeight = pindex->nHeight;

	BOOST_FOREACH(COfferFee &oFee, lstOfferFees) {
		if (oFee.nHeight >= startHeight && oFee.nHeight < endHeight) {
			oFee.nFee = 0;
			break;
		}
	}

    CBlockIndex* pindex = pindexRescan;
    while (pindex) {  

        int nHeight = pindex->nHeight;
        CBlock block;
        block.ReadFromDisk(pindex);
        uint256 txblkhash;
        
        BOOST_FOREACH(CTransaction& tx, block.vtx) {

            if (tx.nVersion != SYSCOIN_TX_VERSION)
                continue;

            vector<vector<unsigned char> > vvchArgs;
            int op, nOut;

            // decode the offer op, params, height
            bool o = DecodeOfferTx(tx, op, nOut, vvchArgs, nHeight);
            if (!o || !IsOfferOp(op)) continue;
            
            if (op == OP_OFFER_NEW) continue;

            vector<unsigned char> vchOffer = vvchArgs[0];
        
            // get the transaction
            if(!GetTransaction(tx.GetHash(), tx, txblkhash, true))
                continue;

            // attempt to read offer from txn
            COffer txOffer;
            COfferAccept txCA;
            if(!txOffer.UnserializeFromTx(tx))
				return error("ReconstructOfferIndex() : failed to unserialize offer from tx");

			// save serialized offer
			COffer serializedOffer = txOffer;

            // read offer from DB if it exists
            vector<COffer> vtxPos;
            if (ExistsOffer(vchOffer)) {
                if (!ReadOffer(vchOffer, vtxPos))
                    return error("ReconstructOfferIndex() : failed to read offer from DB");
                if(vtxPos.size()!=0) {
                	txOffer.nHeight = nHeight;
                	txOffer.GetOfferFromList(vtxPos);
                }
            }

            // read the offer accept from db if exists
            if(op == OP_OFFER_ACCEPT || op == OP_OFFER_PAY) {
            	bool bReadOffer = false;
            	vector<unsigned char> vchOfferAccept = vvchArgs[1];
	            if (ExistsOfferAccept(vchOfferAccept)) {
	                if (!ReadOfferAccept(vchOfferAccept, vchOffer))
	                    printf("ReconstructOfferIndex() : warning - failed to read offer accept from offer DB\n");
	                else bReadOffer = true;
	            }
				if(!bReadOffer && !txOffer.GetAcceptByHash(vchOfferAccept, txCA))
					printf("ReconstructOfferIndex() : failed to read offer accept from offer\n");

				// add txn-specific values to offer accept object
                txCA.vchRand = vvchArgs[1];
		        txCA.nTime = pindex->nTime;
		        txCA.txHash = tx.GetHash();
		        txCA.nHeight = nHeight;
				txOffer.PutOfferAccept(txCA);
			}

			// use the txn offer as master on updates,
			// but grab the accepts from the DB first
			if(op == OP_OFFER_UPDATE) {
				serializedOffer.accepts = txOffer.accepts;
				txOffer = serializedOffer;
			}

			// txn-specific values to offer object
            txOffer.vchRand = vvchArgs[0];
			txOffer.txHash = tx.GetHash();
            txOffer.nHeight = nHeight;
            txOffer.nTime = pindex->nTime;
            txOffer.PutToOfferList(vtxPos);

            if (!WriteOffer(vchOffer, vtxPos))
                return error("ReconstructOfferIndex() : failed to write to offer DB");
            if(op == OP_OFFER_ACCEPT || op == OP_OFFER_PAY)
	            if (!WriteOfferAccept(vvchArgs[1], vvchArgs[0]))
	                return error("ReconstructOfferIndex() : failed to write to offer DB");
			
			// insert offers fees to regenerate list, write offer to
			// master index
			int64 nTheFee = GetOfferNetFee(tx);
			InsertOfferFee(pindex, tx.GetHash(), nTheFee);

			printf( "RECONSTRUCT OFFER: op=%s offer=%s title=%s qty=%llu hash=%s height=%d fees=%llu\n",
					offerFromOp(op).c_str(),
					stringFromVch(vvchArgs[0]).c_str(),
					stringFromVch(txOffer.sTitle).c_str(),
					txOffer.GetRemQty(),
					tx.GetHash().ToString().c_str(), 
					nHeight,
					nTheFee);	            
        }
        pindex = pindex->pnext;
        Flush();
    }
    }
    return true;
}

// get the depth of transaction txnindex relative to block at index pIndexBlock, looking
// up to maxdepth. Return relative depth if found, or -1 if not found and maxdepth reached.
int CheckOfferTransactionAtRelativeDepth(CBlockIndex* pindexBlock,
		const CCoins *txindex, int maxDepth) {
	for (CBlockIndex* pindex = pindexBlock;
			pindex && pindexBlock->nHeight - pindex->nHeight < maxDepth;
			pindex = pindex->pprev)
		if (pindex->nHeight == (int) txindex->nHeight)
			return pindexBlock->nHeight - pindex->nHeight;
	return -1;
}

int GetOfferTxHashHeight(const uint256 txHash) {
	CDiskTxPos postx;
	pblocktree->ReadTxIndex(txHash, postx);
	return GetOfferTxPosHeight(postx);
}

uint64 GetOfferFeeSubsidy(unsigned int nHeight) {
	uint64 hr1 = 1, hr12 = 1;
	{
		TRY_LOCK(cs_main, cs_trymain);
		unsigned int h12 = 360 * 12;
		unsigned int nTargetTime = 0;
		unsigned int nTarget1hrTime = 0;
		unsigned int blk1hrht = nHeight - 1;
		unsigned int blk12hrht = nHeight - 1;
		bool bFound = false;

		BOOST_FOREACH(COfferFee &nmFee, lstOfferFees) {
			if(nmFee.nHeight <= nHeight)
				bFound = true;
			if(bFound) {
				if(nTargetTime==0) {
					hr1 = hr12 = 0;
					nTargetTime = nmFee.nTime - h12;
					nTarget1hrTime = nmFee.nTime - (h12/12);
				}
				if(nmFee.nTime > nTargetTime) {
					hr12 += nmFee.nFee;
					blk12hrht = nmFee.nHeight;
					if(nmFee.nTime > nTarget1hrTime) {
						hr1 += nmFee.nFee;
						blk1hrht = nmFee.nHeight;
					}
				}
			}
		}
		hr12 /= (nHeight - blk12hrht) + 1;
		hr1 /= (nHeight - blk1hrht) + 1;
	}
	uint64 nSubsidyOut = hr1 > hr12 ? hr1 : hr12;
	return nSubsidyOut;
}

bool RemoveOfferFee(COfferFee &txnVal) {
	{
		TRY_LOCK(cs_main, cs_trymain);

		COfferFee *theval = NULL;

		BOOST_FOREACH(COfferFee &nmTxnValue, lstOfferFees) {
			if (txnVal.hash == nmTxnValue.hash
			 && txnVal.nHeight == nmTxnValue.nHeight) {
				theval = &nmTxnValue;
				break;
			}
		}
		if(theval)
			lstOfferFees.remove(*theval);

		return theval != NULL;
	}
}

bool InsertOfferFee(CBlockIndex *pindex, uint256 hash, uint64 nValue) {
	TRY_LOCK(cs_main, cs_trymain);
	list<COfferFee> txnDup;
	COfferFee oFee;
	oFee.nTime = pindex->nTime;
	oFee.nHeight = pindex->nHeight;
	oFee.nFee = nValue;
	bool bFound = false;
	BOOST_FOREACH(COfferFee &nmFee, lstOfferFees) {
		if (oFee.hash == nmFee.hash
				&& oFee.nHeight == nmFee.nHeight) {
			bFound = true;
			break;
		}
	}
	if (!bFound)
		lstOfferFees.push_front(oFee);

	return bFound;
}

int64 GetOfferNetFee(const CTransaction& tx) {
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

int GetOfferHeight(vector<unsigned char> vchOffer) {
	vector<COffer> vtxPos;
	if (pofferdb->ExistsOffer(vchOffer)) {
		if (!pofferdb->ReadOffer(vchOffer, vtxPos))
			return error("GetOfferHeight() : failed to read from offer DB");
		if (vtxPos.empty()) return -1;
		COffer& txPos = vtxPos.back();
		return txPos.nHeight;
	}
	return -1;
}

// Check that the last entry in offer history matches the given tx pos
bool CheckOfferTxPos(const vector<COffer> &vtxPos, const int txPos) {
	if (vtxPos.empty()) return false;
	COffer offer;
	offer.nHeight = txPos;
	return offer.GetOfferFromList(vtxPos);
}

int IndexOfOfferOutput(const CTransaction& tx) {
	vector<vector<unsigned char> > vvch;
	int op, nOut;
	if (!DecodeOfferTx(tx, op, nOut, vvch, -1))
		throw runtime_error("IndexOfOfferOutput() : offer output not found");
	return nOut;
}

bool GetNameOfOfferTx(const CTransaction& tx, vector<unsigned char>& offer) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op, nOut;
	if (!DecodeOfferTx(tx, op, nOut, vvchArgs, -1))
		return error("GetNameOfOfferTx() : could not decode a syscoin tx");

	switch (op) {
		case OP_OFFER_ACCEPT:
		case OP_OFFER_ACTIVATE:
		case OP_OFFER_UPDATE:
		case OP_OFFER_PAY:
			offer = vvchArgs[0];
			return true;
	}
	return false;
}

//TODO come back here check to see how / where this is used
bool IsConflictedOfferTx(CBlockTreeDB& txdb, const CTransaction& tx,
		vector<unsigned char>& offer) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op, nOut, nPrevHeight;
	if (!DecodeOfferTx(tx, op, nOut, vvchArgs, pindexBest->nHeight))
		return error("IsConflictedOfferTx() : could not decode a syscoin tx");

	switch (op) {
	case OP_OFFER_UPDATE:
		nPrevHeight = GetOfferHeight(vvchArgs[0]);
		offer = vvchArgs[0];
		if (nPrevHeight >= 0
				&& pindexBest->nHeight - nPrevHeight
						< GetOfferExpirationDepth(pindexBest->nHeight))
			return true;
	}
	return false;
}

bool GetValueOfOfferTx(const CTransaction& tx, vector<unsigned char>& value) {
	vector<vector<unsigned char> > vvch;
	int op, nOut;

	if (!DecodeOfferTx(tx, op, nOut, vvch, -1))
		return false;

	switch (op) {
	case OP_OFFER_NEW:
		return false;
	case OP_OFFER_ACTIVATE:
	case OP_OFFER_ACCEPT:
		value = vvch[2];
		return true;
	case OP_OFFER_UPDATE:
	case OP_OFFER_PAY:
		value = vvch[1];
		return true;
	default:
		return false;
	}
}

bool IsOfferMine(const CTransaction& tx) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;

	vector<vector<unsigned char> > vvch;
	int op, nOut;

	bool good = DecodeOfferTx(tx, op, nOut, vvch, -1);
	if (!good) 
		return false;
	
	if(!IsOfferOp(op))
		return false;

	const CTxOut& txout = tx.vout[nOut];
	if (IsMyOffer(tx, txout)) {
		printf("IsOfferMine() : found my transaction %s nout %d\n",
				tx.GetHash().GetHex().c_str(), nOut);
		return true;
	}
	return false;
}

bool IsOfferMine(const CTransaction& tx, const CTxOut& txout,
		bool ignore_offernew) {
	if (tx.nVersion != SYSCOIN_TX_VERSION)
		return false;

	vector<vector<unsigned char> > vvch;
	int op;

	if (!DecodeOfferScript(txout.scriptPubKey, op, vvch))
		return false;

	if(!IsOfferOp(op))
		return false;

	if (ignore_offernew && op == OP_OFFER_NEW)
		return false;

	if (IsMyOffer(tx, txout)) {
		printf("IsOfferMine() : found my transaction %s value %d\n",
				tx.GetHash().GetHex().c_str(), (int) txout.nValue);
		return true;
	}
	return false;
}

bool GetValueOfOfferTxHash(const uint256 &txHash,
		vector<unsigned char>& vchValue, uint256& hash, int& nHeight) {
	nHeight = GetOfferTxHashHeight(txHash);
	CTransaction tx;
	uint256 blockHash;
	if (!GetTransaction(txHash, tx, blockHash, true))
		return error("GetValueOfOfferTxHash() : could not read tx from disk");
	if (!GetValueOfOfferTx(tx, vchValue))
		return error("GetValueOfOfferTxHash() : could not decode value from tx");
	hash = tx.GetHash();
	return true;
}

bool GetValueOfOffer(COfferDB& dbOffer, const vector<unsigned char> &vchOffer,
		vector<unsigned char>& vchValue, int& nHeight) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;

	COffer& txPos = vtxPos.back();
	nHeight = txPos.nHeight;
	vchValue = txPos.vchRand;
	return true;
}

bool GetTxOfOffer(COfferDB& dbOffer, const vector<unsigned char> &vchOffer,
		CTransaction& tx) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;
	COffer& txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if (nHeight + GetOfferExpirationDepth(pindexBest->nHeight)
			< pindexBest->nHeight) {
		string offer = stringFromVch(vchOffer);
		printf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}

	uint256 hashBlock;
	if (!GetTransaction(txPos.txHash, tx, hashBlock, true))
		return error("GetTxOfOffer() : could not read tx from disk");

	return true;
}

bool GetTxOfOfferAccept(COfferDB& dbOffer, const vector<unsigned char> &vchOfferAccept,
		COffer &txPos, CTransaction& tx) {
	vector<COffer> vtxPos;
	vector<unsigned char> vchOffer;
	if (!pofferdb->ReadOfferAccept(vchOfferAccept, vchOffer)) return false;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos)) return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if (nHeight + GetOfferExpirationDepth(pindexBest->nHeight)
			< pindexBest->nHeight) {
		string offer = stringFromVch(vchOfferAccept);
		printf("GetTxOfOfferAccept(%s) : expired", offer.c_str());
		return false;
	}

	uint256 hashBlock;
	if (!GetTransaction(txPos.txHash, tx, hashBlock, true))
		return error("GetTxOfOfferAccept() : could not read tx from disk");

	return true;
}

bool DecodeOfferTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch, int nHeight) {
	bool found = false;


	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeOfferScript(out.scriptPubKey, op, vvchRead)) {
			nOut = i; found = true; vvch = vvchRead;
			break;
		}
	}
	if (!found) vvch.clear();
	return found && IsOfferOp(op);
}

bool GetValueOfOfferTx(const CCoins& tx, vector<unsigned char>& value) {
	vector<vector<unsigned char> > vvch;

	int op, nOut;

	if (!DecodeOfferTx(tx, op, nOut, vvch, -1))
		return false;

	switch (op) {
	case OP_OFFER_NEW:
		return false;
	case OP_OFFER_ACTIVATE:
	case OP_OFFER_ACCEPT:
		value = vvch[2];
		return true;
	case OP_OFFER_UPDATE:
	case OP_OFFER_PAY:
		value = vvch[1];
		return true;
	default:
		return false;
	}
}

bool DecodeOfferTx(const CCoins& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch, int nHeight) {
	bool found = false;


	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeOfferScript(out.scriptPubKey, op, vvchRead)) {
			nOut = i; found = true; vvch = vvchRead;
			break;
		}
	}
	if (!found)
		vvch.clear();
	return found;
}

bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeOfferScript(script, op, vvch, pc);
}

bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
	opcodetype opcode;
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

	if ((op == OP_OFFER_NEW && vvch.size() == 1)
		|| (op == OP_OFFER_ACTIVATE && vvch.size() == 3)
		|| (op == OP_OFFER_UPDATE && vvch.size() == 2)
		|| (op == OP_OFFER_ACCEPT && vvch.size() == 3)
		|| (op == OP_OFFER_PAY && vvch.size() == 2))
		return true;
	return false;
}

bool SignOfferSignature(const CTransaction& txFrom, CTransaction& txTo,
		unsigned int nIn, int nHashType = SIGHASH_ALL, CScript scriptPrereq =
				CScript()) {
	assert(nIn < txTo.vin.size());
	CTxIn& txin = txTo.vin[nIn];
	assert(txin.prevout.n < txFrom.vout.size());
	const CTxOut& txout = txFrom.vout[txin.prevout.n];

	// Leave out the signature from the hash, since a signature can't sign itself.
	// The checksig op will also drop the signatures from its hash.
	const CScript& scriptPubKey = RemoveOfferScriptPrefix(txout.scriptPubKey);
	uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn,
			nHashType);
	txnouttype whichTypeRet;

	if (!Solver(*pwalletMain, scriptPubKey, hash, nHashType, txin.scriptSig,
			whichTypeRet))
		return false;

	txin.scriptSig = scriptPrereq + txin.scriptSig;

	// Test the solution
	if (scriptPrereq.empty())
		if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, 0, 0))
			return false;

	return true;
}

bool CreateOfferTransactionWithInputTx(
		const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
		int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet,
		const string& txData) {
	int64 nValue = 0;
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
		if (nValue < 0)
			return false;
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0)
		return false;

	wtxNew.BindWallet(pwalletMain);
	{
		LOCK2(cs_main, pwalletMain->cs_wallet);

		nFeeRet = nTransactionFee;
		loop {
			wtxNew.vin.clear();
			wtxNew.vout.clear();
			wtxNew.fFromMe = true;
			wtxNew.data = vchFromString(txData);

			int64 nTotalValue = nValue + nFeeRet;
			printf("CreateOfferTransactionWithInputTx: total value = %d\n",
					(int) nTotalValue);
			double dPriority = 0;

			// vouts to the payees
			BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
				wtxNew.vout.push_back(CTxOut(s.second, s.first));

			int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

			// Choose coins to use
			set<pair<const CWalletTx*, unsigned int> > setCoins;
			int64 nValueIn = 0;
			printf( "CreateOfferTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n",
					FormatMoney(nTotalValue - nWtxinCredit).c_str(),
					FormatMoney(nTotalValue).c_str(),
					FormatMoney(nWtxinCredit).c_str());
			if (nTotalValue - nWtxinCredit > 0) {
				if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit,
						setCoins, nValueIn))
					return false;
			}

			printf( "CreateOfferTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n",
					(int) setCoins.size(), FormatMoney(nValueIn).c_str());

			vector<pair<const CWalletTx*, unsigned int> > vecCoins(
					setCoins.begin(), setCoins.end());

			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				int64 nCredit = coin.first->vout[coin.second].nValue;
				dPriority += (double) nCredit
						* coin.first->GetDepthInMainChain();
			}

			// Input tx always at first position
			vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

			nValueIn += nWtxinCredit;
			dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain();

			// Fill a vout back to self with any change
			int64 nChange = nValueIn - nTotalValue;
			if (nChange >= CENT) {
				// Note: We use a new key here to keep it from being obvious which side is the change.
				//  The drawback is that by not reusing a previous key, the change may be lost if a
				//  backup is restored, if the backup doesn't have the new private key for the change.
				//  If we reused the old key, it would be possible to add code to look for and
				//  rediscover unknown transactions that were written with keys of ours to recover
				//  post-backup change.

				// Reserve a new key pair from key pool
				CPubKey pubkey;
				assert(reservekey.GetReservedKey(pubkey));

				// -------------- Fill a vout to ourself, using same address type as the payment
				// Now sending always to hash160 (GetBitcoinAddressHash160 will return hash160, even if pubkey is used)
				CScript scriptChange;
				if (Hash160(vecSend[0].first) != 0)
					scriptChange.SetDestination(pubkey.GetID());
				else
					scriptChange << pubkey << OP_CHECKSIG;

				// Insert change txn at random position:
				vector<CTxOut>::iterator position = wtxNew.vout.begin()
						+ GetRandInt(wtxNew.vout.size());
				wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
			} else
				reservekey.ReturnKey();

			// Fill vin
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
				wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

			// Sign
			int nIn = 0;
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
				if (coin.first == &wtxIn
						&& coin.second == (unsigned int) nTxOut) {
					if (!SignOfferSignature(*coin.first, wtxNew, nIn++))
						throw runtime_error("could not sign offer coin output");
				} else {
					if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
						return false;
				}
			}

			// Limit size
			unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
					SER_NETWORK, PROTOCOL_VERSION);
			if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
				return false;
			dPriority /= nBytes;

			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
			bool fAllowFree = CTransaction::AllowFree(dPriority);
			int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
			if (nFeeRet < max(nPayFee, nMinFee)) {
				nFeeRet = max(nPayFee, nMinFee);
				printf( "CreateOfferTransactionWithInputTx: re-iterating (nFreeRet = %s)\n",
						FormatMoney(nFeeRet).c_str());
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			wtxNew.AddSupportingTransactions();
			wtxNew.fTimeReceivedIsTxTime = true;

			break;
		}
	}

	printf("CreateOfferTransactionWithInputTx succeeded:\n%s",
			wtxNew.ToString().c_str());
	return true;
}

int64 GetFeeAssign() {
	int64 iRet = !0;
	return  iRet<<47;
}

// nTxOut is the output from wtxIn that we should grab
string SendOfferMoneyWithInputTx(CScript scriptPubKey, int64 nValue,
		int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee,
		const string& txData) {
	int nTxOut = IndexOfOfferOutput(wtxIn);
	CReserveKey reservekey(pwalletMain);
	int64 nFeeRequired;
	vector<pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKey, nValue));

	if (nNetFee) {
		CScript scriptFee;
		scriptFee << OP_RETURN;
		vecSend.push_back(make_pair(scriptFee, nNetFee));
	}

	if (!CreateOfferTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew,
			reservekey, nFeeRequired, txData)) {
		string strError;
		if (nValue + nFeeRequired > pwalletMain->GetBalance())
			strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "),
							FormatMoney(nFeeRequired).c_str());
		else
			strError = _("Error: Transaction creation failed  ");
		printf("SendMoney() : %s", strError.c_str());
		return strError;
	}

#ifdef GUI
	if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
	return "ABORTED";
#else
	if (fAskFee && !true)
		return "ABORTED";
#endif

	if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
		return _(
				"Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

	return "";
}

bool GetOfferAddress(const CTransaction& tx, std::string& strAddress) {
	int op, nOut = 0;
	vector<vector<unsigned char> > vvch;

	if (!DecodeOfferTx(tx, op, nOut, vvch, -1))
		return error("GetOfferAddress() : could not decode offer tx.");

	const CTxOut& txout = tx.vout[nOut];

	const CScript& scriptPubKey = RemoveOfferScriptPrefix(txout.scriptPubKey);
	strAddress = CBitcoinAddress(scriptPubKey.GetID()).ToString();
	return true;
}

bool GetOfferAddress(const CDiskTxPos& txPos, std::string& strAddress) {
	CTransaction tx;
	if (!tx.ReadFromDisk(txPos))
		return error("GetOfferAddress() : could not read tx from disk");
	return GetOfferAddress(tx, strAddress);
}

CScript RemoveOfferScriptPrefix(const CScript& scriptIn) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeOfferScript(scriptIn, op, vvch, pc))
		throw runtime_error(
				"RemoveOfferScriptPrefix() : could not decode offer script");
	return CScript(pc, scriptIn.end());
}

bool CheckOfferInputs(CBlockIndex *pindexBlock, const CTransaction &tx,
		CValidationState &state, CCoinsViewCache &inputs,
		map<vector<unsigned char>, uint256> &mapTestPool, bool fBlock, bool fMiner,
		bool fJustCheck) {

	if (!tx.IsCoinBase()) {
		printf("*** %d %d %s %s %s %s\n", pindexBlock->nHeight,
				pindexBest->nHeight, tx.GetHash().ToString().c_str(),
				fBlock ? "BLOCK" : "", fMiner ? "MINER" : "",
				fJustCheck ? "JUSTCHECK" : "");

		bool found = false;
		const COutPoint *prevOutput = NULL;
		const CCoins *prevCoins = NULL;
		int prevOp;
		vector<vector<unsigned char> > vvchPrevArgs;

		// Strict check - bug disallowed
		for (int i = 0; i < (int) tx.vin.size(); i++) {
			prevOutput = &tx.vin[i].prevout;
			prevCoins = &inputs.GetCoins(prevOutput->hash);
			vector<vector<unsigned char> > vvch;
			if (DecodeOfferScript(prevCoins->vout[prevOutput->n].scriptPubKey,
					prevOp, vvch)) {
				found = true; vvchPrevArgs = vvch;
				break;
			}
			if(!found)vvchPrevArgs.clear();
		}

		// Make sure offer outputs are not spent by a regular transaction, or the offer would be lost
		if (tx.nVersion != SYSCOIN_TX_VERSION) {
			if (found)
				return error(
						"CheckOfferInputs() : a non-syscoin transaction with a syscoin input");
			return true;
		}

		vector<vector<unsigned char> > vvchArgs;
		int op;
		int nOut;
		bool good = DecodeOfferTx(tx, op, nOut, vvchArgs, pindexBlock->nHeight);
		if (!good)
			return error("CheckOfferInputs() : could not decode a syscoin tx");
		int nPrevHeight;
		int nDepth;
		int64 nNetFee;

		// unserialize offer object from txn, check for valid
		COffer theOffer(tx);
		COfferAccept theOfferAccept;
		if (theOffer.IsNull())
			error("CheckOfferInputs() : null offer object");

		if (vvchArgs[0].size() > MAX_NAME_LENGTH)
			return error("offer hex guid too long");

		switch (op) {
		case OP_OFFER_NEW:

			if (found)
				return error(
						"CheckOfferInputs() : offernew tx pointing to previous syscoin tx");

			if (vvchArgs[0].size() != 20)
				return error("offernew tx with incorrect hash length");

			break;

		case OP_OFFER_ACTIVATE:

			// check for enough fees
			nNetFee = GetOfferNetFee(tx);
			if (nNetFee < GetOfferNetworkFee(1, pindexBlock->nHeight) - COIN)
				return error(
						"CheckOfferInputs() : got tx %s with fee too low %lu",
						tx.GetHash().GetHex().c_str(),
						(long unsigned int) nNetFee);

			// validate conditions
			if ((!found || prevOp != OP_OFFER_NEW) && !fJustCheck)
				return error("CheckOfferInputs() : offeractivate tx without previous offernew tx");

			if (vvchArgs[1].size() > 20)
				return error("offeractivate tx with guid too big");

			if (vvchArgs[2].size() > MAX_VALUE_LENGTH)
				return error("offeractivate tx with value too long");

			if (fBlock && !fJustCheck) {
				// Check hash
				const vector<unsigned char> &vchHash = vvchPrevArgs[0];
				const vector<unsigned char> &vchOffer = vvchArgs[0];
				const vector<unsigned char> &vchRand = vvchArgs[1];
				vector<unsigned char> vchToHash(vchRand);
				vchToHash.insert(vchToHash.end(), vchOffer.begin(), vchOffer.end());
				uint160 hash = Hash160(vchToHash);

				if (uint160(vchHash) != hash)
					return error(
							"CheckOfferInputs() : offeractivate hash mismatch prev : %s cur %s",
							HexStr(stringFromVch(vchHash)).c_str(), HexStr(stringFromVch(vchToHash)).c_str());

				// min activation depth is 1
				nDepth = CheckOfferTransactionAtRelativeDepth(pindexBlock,
						prevCoins, 1);
				if ((fBlock || fMiner) && nDepth >= 0 && (unsigned int) nDepth < 1)
					return false;

				// check for previous offernew
				nDepth = CheckOfferTransactionAtRelativeDepth(pindexBlock,
						prevCoins,
						GetOfferExpirationDepth(pindexBlock->nHeight));
				if (nDepth == -1)
					return error(
							"CheckOfferInputs() : offeractivate cannot be mined if offernew is not already in chain and unexpired");

				nPrevHeight = GetOfferHeight(vchOffer);
				if (!fBlock && nPrevHeight >= 0
						&& pindexBlock->nHeight - nPrevHeight
								< GetOfferExpirationDepth(pindexBlock->nHeight))
					return error(
							"CheckOfferInputs() : offeractivate on an unexpired offer.");

				if(pindexBlock->nHeight == pindexBest->nHeight) {
					BOOST_FOREACH(const MAPTESTPOOLTYPE& s, mapTestPool) {
	                    if (vvchArgs[0] == s.first) {
	                       return error("CheckInputs() : will not mine offeractivate %s because it clashes with %s",
	                               tx.GetHash().GetHex().c_str(),
	                               s.second.GetHex().c_str());
	                    }
	                }
	            }
			}

			break;
		case OP_OFFER_UPDATE:

			if (fBlock && fJustCheck && !found)
				return true;

			if ( !found || ( prevOp != OP_OFFER_ACTIVATE && prevOp != OP_OFFER_UPDATE 
				&& prevOp != OP_OFFER_ACCEPT && prevOp != OP_OFFER_PAY ) )
				return error("offerupdate previous op %s is invalid", offerFromOp(prevOp).c_str());
			
			if (vvchArgs[1].size() > MAX_VALUE_LENGTH)
				return error("offerupdate tx with value too long");
			
			if (vvchPrevArgs[0] != vvchArgs[0])
				return error("CheckOfferInputs() : offerupdate offer mismatch");

			// TODO CPU intensive
			nDepth = CheckOfferTransactionAtRelativeDepth(pindexBlock,
					prevCoins, GetOfferExpirationDepth(pindexBlock->nHeight));
			if ((fBlock || fMiner) && nDepth < 0)
				return error(
						"CheckOfferInputs() : offerupdate on an expired offer, or there is a pending transaction on the offer");
			
			if (fBlock && !fJustCheck && pindexBlock->nHeight == pindexBest->nHeight) {
				BOOST_FOREACH(const MAPTESTPOOLTYPE& s, mapTestPool) {
                    if (vvchArgs[0] == s.first) {
                       return error("CheckInputs() : will not mine offerupdate %s because it clashes with %s",
                               tx.GetHash().GetHex().c_str(),
                               s.second.GetHex().c_str());
                    }
                }
        	}

			break;

		case OP_OFFER_ACCEPT:

			if (vvchArgs[1].size() > 20)
				return error("offeraccept tx with guid too big");

			if (vvchArgs[2].size() > 20)
				return error("offeraccept tx with value too long");

			if (fBlock && !fJustCheck) {
				// Check hash
				const vector<unsigned char> &vchOffer = vvchArgs[0];
				const vector<unsigned char> &vchAcceptRand = vvchArgs[1];

				nPrevHeight = GetOfferHeight(vchOffer);

				// check for existence of offeraccept in txn offer obj
				if(!theOffer.GetAcceptByHash(vchAcceptRand, theOfferAccept))
					return error("could not read accept from offer txn");
	   		}
			break;

		case OP_OFFER_PAY:

			// validate conditions
			if ( ( !found || prevOp != OP_OFFER_ACCEPT ) && !fJustCheck )
				return error("offerpay previous op %s is invalid", offerFromOp(prevOp).c_str());

			if (vvchArgs[0].size() > 20)
				return error("offerpay tx with offer hash too big");

			if (vvchArgs[1].size() > 20)
				return error("offerpay tx with offer accept hash too big");

			if (fBlock && !fJustCheck) {
				// Check hash
				const vector<unsigned char> &vchOffer = vvchArgs[0];
				const vector<unsigned char> &vchOfferAccept = vvchArgs[1];

				// construct offer accept hash
				vector<unsigned char> vchToHash(vchOfferAccept);
				vchToHash.insert(vchToHash.end(), vchOffer.begin(), vchOffer.end());
				uint160 hash = Hash160(vchToHash);

				// check for previous offeraccept
				nDepth = CheckOfferTransactionAtRelativeDepth(pindexBlock,
						prevCoins, pindexBlock->nHeight);
				if (nDepth == -1)
					return error(
							"CheckOfferInputs() : offerpay cannot be mined if offeraccept is not already in chain");

				// check offer accept hash against prev txn
				if (uint160(vvchPrevArgs[2]) != hash)
					return error(
							"CheckOfferInputs() : offerpay prev hash mismatch : %s vs %s",
							HexStr(stringFromVch(vvchPrevArgs[2])).c_str(), HexStr(stringFromVch(vchToHash)).c_str());

				nPrevHeight = GetOfferHeight(vchOffer);

				// check for existence of offeraccept in txn offer obj
				if(!theOffer.GetAcceptByHash(vchOfferAccept, theOfferAccept))
					return error("could not read accept from offer txn");

				// check for enough offer fees with this txn
				int64 expectedFee = GetOfferNetworkFee(2, pindexBlock->nHeight) - COIN;
				nNetFee = GetOfferNetFee(tx);
				if (nNetFee < expectedFee )
					return error(
							"CheckOfferInputs() : got offerpay tx %s with fee too low %lu",
							tx.GetHash().GetHex().c_str(),
							(long unsigned int) nNetFee);

				// make sure we don't attempt to mine an accept & pay in the same block
				if(pindexBlock->nHeight == pindexBest->nHeight) {
	                BOOST_FOREACH(const MAPTESTPOOLTYPE& s, mapTestPool) {
	                    if (vvchArgs[1] == s.first) {
	                       return error("CheckInputs() : will not mine offerpay %s because it clashes with %s",
	                               tx.GetHash().GetHex().c_str(),
	                               s.second.GetHex().c_str());
	                    }
	                }
	            }
			}

			break;

		default:
			return error( "CheckOfferInputs() : offer transaction has unknown op");
		}

		// save serialized offer for later use
		COffer serializedOffer = theOffer;

		// if not an offernew, load the offer data from the DB
		vector<COffer> vtxPos;
		if(op != OP_OFFER_NEW)
			if (pofferdb->ExistsOffer(vvchArgs[0])) {
				if (!pofferdb->ReadOffer(vvchArgs[0], vtxPos))
					return error(
							"CheckOfferInputs() : failed to read from offer DB");
			}

		//todo fucking suspect
		// // for offerupdate or offerpay check to make sure the previous txn exists and is valid
		// if (!fBlock && fJustCheck && (op == OP_OFFER_UPDATE || op == OP_OFFER_PAY)) {
		// 	if (!CheckOfferTxPos(vtxPos, prevCoins->nHeight))
		// 		return error(
		// 				"CheckOfferInputs() : tx %s rejected, since previous tx (%s) is not in the offer DB\n",
		// 				tx.GetHash().ToString().c_str(),
		// 				prevOutput->hash.ToString().c_str());
		// }

		// these ifs are problably total bullshit except for the offernew
		if (fBlock || (!fBlock && !fMiner && !fJustCheck)) {
			if (op != OP_OFFER_NEW) {
				if (!fMiner && !fJustCheck && pindexBlock->nHeight != pindexBest->nHeight) {
					int nHeight = pindexBlock->nHeight;

					// get the latest offer from the db
                	theOffer.nHeight = nHeight;
                	theOffer.GetOfferFromList(vtxPos);
					
					// If update, we make the serialized offer the master
					// but first we assign the accepts from the DB since
					// they are not shipped in an update txn to keep size down
					if(op == OP_OFFER_UPDATE) {
						serializedOffer.accepts = theOffer.accepts;
						theOffer = serializedOffer;
					}

					if (op == OP_OFFER_ACCEPT || op == OP_OFFER_PAY) {
						// get the accept out of the offer object in the txn
						if(!serializedOffer.GetAcceptByHash(vvchArgs[1], theOfferAccept))
							return error("could not read accept from offer txn");

						if(op == OP_OFFER_ACCEPT) {
							// get the offer accept qty, validate acceptance. txn is still valid
							// if qty cannot be fulfilled, first-to-mine makes it
							if(theOfferAccept.nQty < 1 || theOfferAccept.nQty > theOffer.GetRemQty()) {
								printf("txn %s accepted but offer not fulfilled because desired"
									" qty %llu is more than available qty %llu for offer accept %s\n", 
									tx.GetHash().GetHex().c_str(), 
									theOfferAccept.nQty, 
									theOffer.GetRemQty(), 
									stringFromVch(theOfferAccept.vchRand).c_str());
								{
									TRY_LOCK(cs_main, cs_trymain);
									std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi = 
										mapOfferAcceptPending.find(vvchArgs[1]);
									if (mi != mapOfferAcceptPending.end())
										mi->second.erase(tx.GetHash());
								}
								return true;
							}
						} 

						if(op == OP_OFFER_PAY) {
							// validate the offer accept is in the database,
							// this is one of the ways we validate that the accept
							// can be fulfilled
							COfferAccept ca;
							if(!theOffer.GetAcceptByHash(vvchArgs[1], ca))
								return error("could not read accept from DB offer");
							// if the accept exists in the database, great. 
							// we don't need to use it, however, the serialized
							// version is just fine
							theOfferAccept.bPaid = true;
						}

						// set the offer accept txn-dependent values and add to the txn
						theOfferAccept.vchRand = vvchArgs[1];
						theOfferAccept.txHash = tx.GetHash();
						theOfferAccept.nTime = pindexBlock->nTime;
						theOfferAccept.nHeight = nHeight;
						theOffer.PutOfferAccept(theOfferAccept);
						mapTestPool[vvchArgs[1]] = tx.GetHash();

						// write the offer / offer accept mapping to the database
						if (!pofferdb->WriteOfferAccept(vvchArgs[1], vvchArgs[0]))
							return error( "CheckOfferInputs() : failed to write to offer DB");
					}
					
					// only modify the offer's height on an activate or update
					if(op == OP_OFFER_ACTIVATE || op == OP_OFFER_UPDATE)
						theOffer.nHeight = pindexBlock->nHeight;

					// set the offer's txn-dependent values
                    theOffer.vchRand = vvchArgs[0];
					theOffer.txHash = tx.GetHash();
					theOffer.nTime = pindexBlock->nTime;
					theOffer.PutToOfferList(vtxPos);

					// write offer
					if (!pofferdb->WriteOffer(vvchArgs[0], vtxPos))
						return error( "CheckOfferInputs() : failed to write to offer DB");
					mapTestPool[vvchArgs[0]] = tx.GetHash();

                    // compute verify and write fee data to DB
                    int64 nTheFee = GetOfferNetFee(tx);
					InsertOfferFee(pindexBlock, tx.GetHash(), nTheFee);
					if(nTheFee > 0) printf("OFFER FEES: Added %lf in fees to track for regeneration.\n", (double) nTheFee / COIN);
					vector<COfferFee> vOfferFees(lstOfferFees.begin(), lstOfferFees.end());
					if (!pofferdb->WriteOfferTxFees(vOfferFees))
						return error( "CheckOfferInputs() : failed to write fees to offer DB");

					// remove offer from pendings
					// activate or update - seller txn
                    if (op == OP_OFFER_ACTIVATE || op == OP_OFFER_UPDATE) {
						vector<unsigned char> vchOffer = op == OP_OFFER_NEW ? vchFromString(HexStr(vvchArgs[0])) : vvchArgs[0];
						TRY_LOCK(cs_main, cs_trymain);
						std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi = mapOfferPending.find(vchOffer);
						if (mi != mapOfferPending.end())
							mi->second.erase(tx.GetHash());
					}
					// accept or pay - buyer txn
					else {
						TRY_LOCK(cs_main, cs_trymain);
						std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi = mapOfferAcceptPending.find(vvchArgs[1]);
						if (mi != mapOfferAcceptPending.end())
							mi->second.erase(tx.GetHash());
					}

					// debug
					printf( "CONNECTED OFFER: op=%s offer=%s title=%s qty=%llu hash=%s height=%d fees=%llu\n",
							offerFromOp(op).c_str(),
							stringFromVch(vvchArgs[0]).c_str(),
							stringFromVch(theOffer.sTitle).c_str(),
							theOffer.GetRemQty(),
							tx.GetHash().ToString().c_str(), 
							nHeight, nTheFee / COIN);
				}
			}
		}
	}
	return true;
}

bool ExtractOfferAddress(const CScript& script, string& address) {
	if (script.size() == 1 && script[0] == OP_RETURN) {
		address = string("network fee");
		return true;
	}
	vector<vector<unsigned char> > vvch;
	int op;
	if (!DecodeOfferScript(script, op, vvch))
		return false;

	string strOp = offerFromOp(op);
	string strOffer;
	if (op == OP_OFFER_NEW) {
#ifdef GUI

		std::map<uint160, std::vector<unsigned char> >::const_iterator mi = mapMyOfferHashes.find(uint160(vvch[0]));
		if (mi != mapMyOfferHashes.end())
		strOffer = stringFromVch(mi->second);
		else
#endif
		strOffer = HexStr(vvch[0]);
	} 
	else
		strOffer = stringFromVch(vvch[0]);

	address = strOp + ": " + strOffer;
	return true;
}

void rescanforoffers(CBlockIndex *pindexRescan) {
    printf("Scanning blockchain for offers to create fast index...\n");
    pofferdb->ReconstructOfferIndex(pindexRescan);
}

int GetOfferTxPosHeight(const CDiskTxPos& txPos) {
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(txPos)) return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end()) return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) return 0;
    return pindex->nHeight;
}

int GetOfferTxPosHeight2(const CDiskTxPos& txPos, int nHeight) {
    nHeight = GetOfferTxPosHeight(txPos);
    return nHeight;
}

Value getofferfees(const Array& params, bool fHelp) {
	if (fHelp || 0 != params.size())
		throw runtime_error(
				"getaliasfees\n"
						"get current service fees for alias transactions\n");
	Object oRes;
	oRes.push_back(Pair("height", nBestHeight ));
	oRes.push_back(Pair("subsidy", ValueFromAmount(GetOfferFeeSubsidy(nBestHeight) )));
	oRes.push_back(Pair("new_fee", (double)1.0));
	oRes.push_back(Pair("activate_fee", ValueFromAmount(GetOfferNetworkFee(1, nBestHeight) )));
	oRes.push_back(Pair("update_fee", ValueFromAmount(GetOfferNetworkFee(2, nBestHeight) )));
	oRes.push_back(Pair("pay_fee", ValueFromAmount(GetOfferNetworkFee(3, nBestHeight) )));
	return oRes;

}

Value offernew(const Array& params, bool fHelp) {
	if (fHelp || params.size() != 6)
		throw runtime_error(
				"offernew <address> <category> <title> <quantity> <price> [<description>]\n"
						"<address> offerpay receive address.\n"
						"<category> category, 255 chars max.\n"
						"<title> title, 255 chars max.\n"
						"<quantity> quantity, > 0\n"
						"<price> price in syscoin, > 0\n"
						"<description> description, 64 KB max.\n"
						+ HelpRequiringPassphrase());
	// gather inputs
	string baSig;
	unsigned int nParamIdx = 0;
	int64 nQty, nPrice;

	vector<unsigned char> vchPaymentAddress = vchFromValue(params[nParamIdx]);
	CBitcoinAddress payAddr(stringFromVch(vchPaymentAddress));
	if(payAddr.IsValid()) nParamIdx++;
	else {
	    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
	        if (IsMine(*pwalletMain, entry.first)) {
	            // sign the data and store it as the alias value
	            CKeyID keyID;
	            payAddr.Set(entry.first);
	            if (payAddr.GetKeyID(keyID) && payAddr.IsValid()) {
		            vchPaymentAddress = vchFromString(payAddr.ToString());
		            break;
	            }
	        }
	    }
	}

	vector<unsigned char> vchCat = vchFromValue(params[nParamIdx++]);
	vector<unsigned char> vchTitle = vchFromValue(params[nParamIdx++]);
	vector<unsigned char> vchDesc;

	nQty = atoi(params[nParamIdx++].get_str().c_str());
	nPrice = atoi64(params[nParamIdx++].get_str().c_str());

	if(nParamIdx < params.size()) vchDesc = vchFromValue(params[nParamIdx++]);
    else vchDesc = vchFromString("");

	if(vchCat.size() < 1)
        throw runtime_error("offer category < 1 bytes!\n");
	if(vchTitle.size() < 1)
        throw runtime_error("offer title < 1 bytes!\n");
	if(vchCat.size() > 255)
        throw runtime_error("offer category > 255 bytes!\n");
	if(vchTitle.size() > 255)
        throw runtime_error("offer title > 255 bytes!\n");
    // 64Kbyte offer desc. maxlen
	if (vchDesc.size() > 1024 * 64)
		throw JSONRPCError(RPC_INVALID_PARAMETER, "offer description > 65536 bytes!\n");

	// set wallet tx ver
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;

	// generate rand identifier
	uint64 rand = GetRand((uint64) -1);
	vector<unsigned char> vchRand = CBigNum(rand).getvch();
	vector<unsigned char> vchOffer = vchFromString(HexStr(vchRand));
	vector<unsigned char> vchToHash(vchRand);
	vchToHash.insert(vchToHash.end(), vchOffer.begin(), vchOffer.end());
	uint160 offerHash = Hash160(vchToHash);

	// build offer object
	COffer newOffer;
	newOffer.vchRand = vchRand;
	newOffer.vchPaymentAddress = vchPaymentAddress;
	newOffer.sCategory = vchCat;
	newOffer.sTitle = vchTitle;
	newOffer.sDescription = vchDesc;
	newOffer.nQty = nQty;
	newOffer.nPrice = nPrice * COIN;

	string bdata = newOffer.SerializeToString();

	// create transaction keys
	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false);
	CScript scriptPubKeyOrig;
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_NEW) << offerHash << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

	// send transaction
	{
		EnsureWalletIsUnlocked();
		string strError = pwalletMain->SendMoney(scriptPubKey, MIN_AMOUNT, wtx,
				false, bdata);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
		mapMyOffers[vchOffer] = wtx.GetHash();
	}
	printf("SENT:OFFERNEW : title=%s, guid=%s, tx=%s, data:\n%s\n",
			stringFromVch(vchTitle).c_str(), stringFromVch(vchOffer).c_str(),
			wtx.GetHash().GetHex().c_str(), bdata.c_str());

	// return results
	vector<Value> res;
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchRand));

	return res;
}

Value offeractivate(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 1 || params.size() > 2)
		throw runtime_error(
				"offeractivate <guid> [<tx>]\n"
						"Activate an offer after creating it with offernew.\n"
						+ HelpRequiringPassphrase());

	// gather inputs
	vector<unsigned char> vchRand = ParseHex(params[0].get_str());
	vector<unsigned char> vchOffer = vchFromValue(params[0]);

	// this is a syscoin transaction
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;

	// check for existing pending offers
	{
		LOCK2(cs_main, pwalletMain->cs_wallet);
		if (mapOfferPending.count(vchOffer)
				&& mapOfferPending[vchOffer].size()) {
			error( "offeractivate() : there are %d pending operations on that offer, including %s",
				   (int) mapOfferPending[vchOffer].size(),
				   mapOfferPending[vchOffer].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that offer");
		}

		// look for an offer with identical hex rand keys. wont happen.
		CTransaction tx;
		if (GetTxOfOffer(*pofferdb, vchOffer, tx)) {
			error( "offeractivate() : this offer is already active with tx %s",
				   tx.GetHash().GetHex().c_str());
			throw runtime_error("this offer is already active");
		}

		EnsureWalletIsUnlocked();

		// Make sure there is a previous offernew tx on this offer and that the random value matches
		uint256 wtxInHash;
		if (params.size() == 1) {
			if (!mapMyOffers.count(vchOffer))
				throw runtime_error(
						"could not find a coin with this offer, try specifying the offernew transaction id");
			wtxInHash = mapMyOffers[vchOffer];
		} else
			wtxInHash.SetHex(params[1].get_str());
		if (!pwalletMain->mapWallet.count(wtxInHash))
			throw runtime_error("previous transaction is not in the wallet");

		// verify previous txn was offernew
		CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
		vector<unsigned char> vchHash;
		bool found = false;
		BOOST_FOREACH(CTxOut& out, wtxIn.vout) {
			vector<vector<unsigned char> > vvch;
			int op;
			if (DecodeOfferScript(out.scriptPubKey, op, vvch)) {
				if (op != OP_OFFER_NEW)
					throw runtime_error(
							"previous transaction wasn't a offernew");
				vchHash = vvch[0]; found = true;
				break;
			}
		}
		if (!found)
			throw runtime_error("Could not decode offer transaction");

		// calculate network fees
		int64 nNetFee = GetOfferNetworkFee(1, pindexBest->nHeight);

		// unserialize offer object from txn, serialize back
		COffer newOffer;
		if(!newOffer.UnserializeFromTx(wtxIn))
			throw runtime_error(
					"could not unserialize offer from txn");

        newOffer.vchRand = vchOffer;
		newOffer.nFee = nNetFee;

		string bdata = newOffer.SerializeToString();
		vector<unsigned char> vchbdata = vchFromString(bdata);

		// check this hash against previous, ensure they match
		vector<unsigned char> vchToHash(vchRand);
		vchToHash.insert(vchToHash.end(), vchOffer.begin(), vchOffer.end());
		uint160 hash = Hash160(vchToHash);
		if (uint160(vchHash) != hash)
			throw runtime_error("previous tx used a different random value");

		//create offeractivate txn keys
		CPubKey newDefaultKey;
		pwalletMain->GetKeyFromPool(newDefaultKey, false);
		CScript scriptPubKeyOrig;
		scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
		CScript scriptPubKey;
		scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACTIVATE) << vchOffer
				<< vchRand << newOffer.sTitle << OP_2DROP << OP_2DROP;
		scriptPubKey += scriptPubKeyOrig;

		// send the tranasction
		string strError = SendOfferMoneyWithInputTx(scriptPubKey, MIN_AMOUNT,
				nNetFee, wtxIn, wtx, false, bdata);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);

		printf("SENT:OFFERACTIVATE: title=%s, guid=%s, tx=%s, data:\n%s\n",
				stringFromVch(newOffer.sTitle).c_str(),
				stringFromVch(vchOffer).c_str(), wtx.GetHash().GetHex().c_str(),
				stringFromVch(vchbdata).c_str() );
	}
	return wtx.GetHash().GetHex();
}

Value offerupdate(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 5 || params.size() > 6)
		throw runtime_error(
				"offerupdate <guid> <category> <title> <quantity> <price> [<description>]\n"
						"Perform an update on an offer you control.\n"
						+ HelpRequiringPassphrase());

	// gather & validate inputs
	vector<unsigned char> vchRand = ParseHex(params[0].get_str());
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchCat = vchFromValue(params[1]);
	vector<unsigned char> vchTitle = vchFromValue(params[2]);
	vector<unsigned char> vchDesc;
	int qty;
	uint64 price;
	if (params.size() == 6) vchDesc = vchFromValue(params[5]);
	try {
		qty = atoi(params[3].get_str().c_str());
		price = atoi64(params[4].get_str().c_str());
	} catch (std::exception &e) {
		throw runtime_error("invalid price and/or quantity values.");
	}
	if(vchCat.size() < 1)
        throw runtime_error("offer category < 1 bytes!\n");
	if(vchTitle.size() < 1)
        throw runtime_error("offer title < 1 bytes!\n");
	if(vchCat.size() > 255)
        throw runtime_error("offer category > 255 bytes!\n");
	if(vchTitle.size() > 255)
        throw runtime_error("offer title > 255 bytes!\n");
    // 64Kbyte offer desc. maxlen
	if (vchDesc.size() > 1024 * 64)
		throw JSONRPCError(RPC_INVALID_PARAMETER, "offer description > 65536 bytes!\n");

	// this is a syscoind txn
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;
	CScript scriptPubKeyOrig;

	// get a key from our wallet set dest as ourselves
	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false);
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());

	// create OFFERUPDATE txn keys
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchTitle
			<< OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	{
		LOCK2(cs_main, pwalletMain->cs_wallet);

		if (mapOfferPending.count(vchOffer)
				&& mapOfferPending[vchOffer].size()) 
			throw runtime_error("there are pending operations on that offer");

		EnsureWalletIsUnlocked();

		// look for a transaction with this key
		CTransaction tx;
		if (!GetTxOfOffer(*pofferdb, vchOffer, tx))
			throw runtime_error("could not find an offer with this name");

		// make sure offer is in wallet
		uint256 wtxInHash = tx.GetHash();
		if (!pwalletMain->mapWallet.count(wtxInHash)) 
			throw runtime_error("this offer is not in your wallet");
		
		// unserialize offer object from txn
		COffer theOffer;
		if(!theOffer.UnserializeFromTx(tx))
			throw runtime_error("cannot unserialize offer from txn");

		// get the offer from DB
		vector<COffer> vtxPos;
		if (!pofferdb->ReadOffer(vchOffer, vtxPos))
			throw runtime_error("could not read offer from DB");
		theOffer = vtxPos.back();
		theOffer.accepts.clear();

		// calculate network fees
		int64 nNetFee = GetOfferNetworkFee(1, pindexBest->nHeight);
		
		// update offer values
		theOffer.sCategory = vchCat;
		theOffer.sTitle = vchTitle;
		theOffer.sDescription = vchDesc;
		if(theOffer.GetRemQty() + qty >= 0)
			theOffer.nQty += qty;
		theOffer.nPrice = price * COIN;
		theOffer.nFee += nNetFee;

		// serialize offer object
		string bdata = theOffer.SerializeToString();

		CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
		string strError = SendOfferMoneyWithInputTx(scriptPubKey, MIN_AMOUNT, nNetFee,
				wtxIn, wtx, false, bdata);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	return wtx.GetHash().GetHex();
}

Value offeraccept(const Array& params, bool fHelp) {
	if (fHelp || params.size() < 1 || params.size() > 2)
		throw runtime_error("offeraccept <guid> [<quantity]>\n"
				"Accept an offer.\n" + HelpRequiringPassphrase());

	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchQty;
	int nQty=1;
	if (params.size() == 2) {
		try {
			nQty=atoi(params[1].get_str().c_str());
		} catch (std::exception &e) {
			throw runtime_error("invalid price and/or quantity values.");
		}
		vchQty = vchFromValue(params[1]);
	} else vchQty = vchFromValue("1");

	// this is a syscoin txn
	CWalletTx wtx;
	wtx.nVersion = SYSCOIN_TX_VERSION;
	CScript scriptPubKeyOrig;

	// generate offer accept identifier and hash
	uint64 rand = GetRand((uint64) -1);
	vector<unsigned char> vchAcceptRand = CBigNum(rand).getvch();
	vector<unsigned char> vchAccept = vchFromString(HexStr(vchAcceptRand));
	vector<unsigned char> vchToHash(vchAcceptRand);
	vchToHash.insert(vchToHash.end(), vchOffer.begin(), vchOffer.end());
	uint160 acceptHash = Hash160(vchToHash);

	// get a key from our wallet set dest as ourselves
	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false);
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());

	// create OFFERACCEPT txn keys
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACCEPT)
			<< vchOffer << vchAcceptRand << acceptHash << OP_2DROP << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;
	{
		LOCK2(cs_main, pwalletMain->cs_wallet);

		if (mapOfferPending.count(vchOffer)
				&& mapOfferPending[vchOffer].size()) {
			error(  "offeraccept() : there are %d pending operations on that offer, including %s",
					(int) mapOfferPending[vchOffer].size(),
					mapOfferPending[vchOffer].begin()->GetHex().c_str());
			throw runtime_error("there are pending operations on that offer");
		}

		EnsureWalletIsUnlocked();

		// look for a transaction with this key
		CTransaction tx;
		if (!GetTxOfOffer(*pofferdb, vchOffer, tx))
			throw runtime_error("could not find an offer with this identifier");

		// unserialize offer object from txn
		COffer theOffer;
		if(!theOffer.UnserializeFromTx(tx))
			throw runtime_error("could not unserialize offer from txn");

		// get the offer id from DB
		vector<COffer> vtxPos;
		if (!pofferdb->ReadOffer(vchOffer, vtxPos))
			throw runtime_error("could not read offer with this name from DB");
		theOffer = vtxPos.back();

		if(theOffer.GetRemQty() < nQty)
			throw runtime_error("not enough remaining quantity to fulfill this orderaccept");

		// create accept object
		COfferAccept txAccept;
		txAccept.vchRand = vchAcceptRand;
		txAccept.nQty = nQty;
		txAccept.nPrice = theOffer.nPrice;
		theOffer.accepts.clear();
		theOffer.PutOfferAccept(txAccept);

		// serialize offer object
		string bdata = theOffer.SerializeToString();

		string strError = pwalletMain->SendMoney(scriptPubKey, MIN_AMOUNT, wtx,
				false, bdata);
		if (strError != "")
			throw JSONRPCError(RPC_WALLET_ERROR, strError);
		mapMyOfferAccepts[vchAcceptRand] = wtx.GetHash();
	}
	// return results
	vector<Value> res;
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchAcceptRand));

	return res;
}

Value offerpay(const Array& params, bool fHelp) {
	if (fHelp || 2 > params.size() || params.size() > 3)
		throw runtime_error("offerpay <guid> [<accepttxid>] <message>\n"
				"Pay for a confirmed accepted offer.\n"
				"<guid> guidkey from offeraccept txn.\n"
				"<accepttxid> offeraccept txn id, if daemon restarted.\n"
				"<message> payment message to seller, 16 KB max.\n"
				+ HelpRequiringPassphrase());

	// gather & validate inputs
	vector<unsigned char> vchRand = ParseHex(params[0].get_str());
	vector<unsigned char> vchMessage = vchFromValue(params.size()==3?params[2]:params[1]);

    if (vchMessage.size() < 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerpay message data < 1 bytes!\n");
    if (vchMessage.size() > 16 * 1024)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerpay message data > 16384 bytes!\n");

	// this is a syscoin txn
	CWalletTx wtx, wtxPay;
	wtx.nVersion = SYSCOIN_TX_VERSION;
	CScript scriptPubKeyOrig;

	{
	LOCK2(cs_main, pwalletMain->cs_wallet);

	// exit if pending offers
	if (mapOfferAcceptPending.count(vchRand)
			&& mapOfferAcceptPending[vchRand].size()) 
		throw runtime_error( "offerpay() : there are pending operations on that offer" );

	EnsureWalletIsUnlocked();

	uint256 wtxInHash;
	if (params.size() == 2) {
		if (!mapMyOfferAccepts.count(vchRand))
			throw runtime_error(
					"could not find a coin associated with this offer key, "
					"try specifying the offernew transaction id");
		wtxInHash = mapMyOfferAccepts[vchRand];
	} else
		wtxInHash.SetHex(params[1].get_str());
	if (!pwalletMain->mapWallet.count(wtxInHash))
		throw runtime_error("previous transaction is not in the wallet");

	// look for a transaction with this key.
	CTransaction tx;
	COffer theOffer;
	COfferAccept theOfferAccept;
	if (!GetTxOfOfferAccept(*pofferdb, vchRand, theOffer, tx))
		throw runtime_error("could not find an offer with this name");
    if(!theOffer.GetAcceptByHash(vchRand, theOfferAccept))
		throw runtime_error("could not find an offer accept with this hash in DB");

	// check if paid already
	if(theOfferAccept.bPaid)
		throw runtime_error("This offer accept has already been successfully paid.");

	// get a key from our wallet set dest as ourselves
	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false);
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());

	// create OFFERPAY txn keys
	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_PAY) << theOffer.vchRand << vchRand << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

    // make sure wallet is unlocked
    if (pwalletMain->IsLocked()) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, 
    	"Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check for sufficient funds to pay for order
    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64 nValueIn = 0;
    uint64 nTotalValue = ( theOfferAccept.nPrice * theOfferAccept.nQty );
    int64 nNetFee = GetOfferNetworkFee(2, pindexBest->nHeight);
    if (!pwalletMain->SelectCoins(nTotalValue + nNetFee, setCoins, nValueIn)) 
        throw runtime_error("insufficient funds to pay for offer");

    theOfferAccept.vchRand = vchRand;
    theOfferAccept.txPayId = wtxPay.GetHash();
    theOfferAccept.vchMessage = vchMessage;
    theOfferAccept.nFee = nNetFee;
    theOffer.accepts.clear();
    theOffer.PutOfferAccept(theOfferAccept);

    // add a copy of the offer object with just
    // the one accept object to payment txn to identify
    // this txn as an offer payment
    COffer offerCopy = theOffer;
    COfferAccept offerAcceptCopy = theOfferAccept;
    offerAcceptCopy.bPaid = true;
    offerCopy.accepts.clear();
    offerCopy.PutOfferAccept(offerAcceptCopy);

    // send payment to offer address
    CBitcoinAddress address(stringFromVch(theOffer.vchPaymentAddress));
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nTotalValue, 
    	wtxPay, false, offerCopy.SerializeToString());
    if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);

	// send the offer pay txn 
	CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
	strError = SendOfferMoneyWithInputTx(scriptPubKey, MIN_AMOUNT, nNetFee,
			wtxIn, wtx, false, theOffer.SerializeToString());
	if (strError != "")
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	mapMyOfferAccepts[vchRand] = wtx.GetHash();
	
	// return results
	vector<Value> res;
	res.push_back(wtxPay.GetHash().GetHex());
	res.push_back(wtx.GetHash().GetHex());

	return res;
}

Value offerinfo(const Array& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerinfo <guid>\n"
				"Show values of an offer.\n");

	Object oLastOffer;
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	string offer = stringFromVch(vchOffer);
	{
		vector<COffer> vtxPos;
		if (!pofferdb->ReadOffer(vchOffer, vtxPos))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read from offer DB");
		if (vtxPos.size() < 1)
			throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");

        // get transaction pointed to by offer
        CTransaction tx;
        uint256 blockHash;
        uint256 txHash = vtxPos.back().txHash;
        if (!GetTransaction(txHash, tx, blockHash, true))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read transaction from disk");

        COffer theOffer = vtxPos.back();

		Object oOffer;
		vector<unsigned char> vchValue;
		Array aoOfferAccepts;
		for(unsigned int i=0;i<theOffer.accepts.size();i++) {
			COfferAccept ca = theOffer.accepts[i];
			Object oOfferAccept;
			string sTime = strprintf("%llu", ca.nTime);
            string sHeight = strprintf("%llu", ca.nHeight);
			oOfferAccept.push_back(Pair("id", HexStr(ca.vchRand)));
			oOfferAccept.push_back(Pair("txid", ca.txHash.GetHex()));
			oOfferAccept.push_back(Pair("height", sHeight));
			oOfferAccept.push_back(Pair("time", sTime));
			oOfferAccept.push_back(Pair("quantity", strprintf("%llu", ca.nQty)));
			oOfferAccept.push_back(Pair("price", ValueFromAmount(ca.nPrice)));
			oOfferAccept.push_back(Pair("paid", ca.bPaid ? "true" : "false"));
			if(ca.bPaid) {
				oOfferAccept.push_back(Pair("service_fee", ValueFromAmount(ca.nFee)));
				oOfferAccept.push_back(Pair("paytxid", ca.txPayId.GetHex() ));
				oOfferAccept.push_back(Pair("message", stringFromVch(ca.vchMessage)));
			}
			aoOfferAccepts.push_back(oOfferAccept);
		}
		int nHeight;
		uint256 offerHash;
        if (GetValueOfOfferTxHash(txHash, vchValue, offerHash, nHeight)) {
			oOffer.push_back(Pair("id", offer));
			oOffer.push_back(Pair("txid", tx.GetHash().GetHex()));
			oOffer.push_back(Pair("service_fee", ValueFromAmount(theOffer.nFee)));
			string strAddress = "";
			GetOfferAddress(tx, strAddress);
			oOffer.push_back(Pair("address", strAddress));
			oOffer.push_back(
					Pair("expires_in",
							nHeight + GetOfferExpirationDepth(nHeight)
									- pindexBest->nHeight));
			if (nHeight + GetOfferExpirationDepth(nHeight)
					- pindexBest->nHeight <= 0) {
				oOffer.push_back(Pair("expired", 1));
			}
			oOffer.push_back(Pair("payment_address", stringFromVch(theOffer.vchPaymentAddress)));
			oOffer.push_back(Pair("category", stringFromVch(theOffer.sCategory)));
			oOffer.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
			oOffer.push_back(Pair("quantity", strprintf("%llu", theOffer.GetRemQty())));
			oOffer.push_back(Pair("price", ValueFromAmount(theOffer.nPrice) ) );
			oOffer.push_back(Pair("description", stringFromVch(theOffer.sDescription)));
			oOffer.push_back(Pair("accepts", aoOfferAccepts));
			oLastOffer = oOffer;
		}
	}
	return oLastOffer;

}

Value offerlist(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
		throw runtime_error("offerlist [<offer>]\n"
				"list my own offers");

    vector<unsigned char> vchName;

    if (params.size() == 1)
        vchName = vchFromValue(params[0]);

    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    Array oRes;
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, Object > vNamesO;

    {

        uint256 blockHash;
        uint256 hash;
        CTransaction tx;

        vector<unsigned char> vchValue;
        int nHeight;

        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
        {
            // get txn hash, read txn index
            hash = item.second.GetHash();

            if (!GetTransaction(hash, tx, blockHash, true))
                continue;

            // skip non-syscoin txns
            if (tx.nVersion != SYSCOIN_TX_VERSION)
                continue;

            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(tx, op, nOut, vvch, -1) 
            	|| !IsOfferOp(op) 
            	|| (op == OP_OFFER_ACCEPT || op == OP_OFFER_PAY))
                continue;

            // get the txn height
            nHeight = GetOfferTxHashHeight(hash);

            // get the txn alias name
            if(!GetNameOfOfferTx(tx, vchName))
                continue;

            // skip this alias if it doesn't match the given filter value
            if(vchNameUniq.size() > 0 && vchNameUniq != vchName)
                continue;

            // get the value of the alias txn
            if(!GetValueOfOfferTx(tx, vchValue))
                continue;

            // build the output object
            Object oName;
            oName.push_back(Pair("name", stringFromVch(vchName)));
            oName.push_back(Pair("value", stringFromVch(vchValue)));

            string strAddress = "";
            GetOfferAddress(tx, strAddress);
            oName.push_back(Pair("address", strAddress));

            oName.push_back(Pair("expires_in", nHeight
                                 + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight));
            if(nHeight + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight <= 0)
                oName.push_back(Pair("expired", 1));

            // get last active name only
            if(vNamesI.find(vchName) != vNamesI.end() && vNamesI[vchName] > nHeight)
                continue;

            vNamesI[vchName] = nHeight;
            vNamesO[vchName] = oName;
        }
    }

    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, Object)& item, vNamesO)
        oRes.push_back(item.second);

    return oRes;
}

Value offeracceptlist(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
		throw runtime_error("offeracceptlist [<offer>]\n"
				"list my accepted offers");

    vector<unsigned char> vchName;

    if (params.size() == 1)
        vchName = vchFromValue(params[0]);

    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    Array oRes;
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, Object > vNamesO;

    {

        uint256 blockHash;
        uint256 hash;
        CTransaction tx;

        vector<unsigned char> vchValue;
        int nHeight;

        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
        {
            // get txn hash, read txn index
            hash = item.second.GetHash();

            if (!GetTransaction(hash, tx, blockHash, true))
                continue;

            // skip non-syscoin txns
            if (tx.nVersion != SYSCOIN_TX_VERSION)
                continue;

            // decode txn, skip non-alias txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(tx, op, nOut, vvch, -1) 
            	|| !IsOfferOp(op) 
            	|| !(op == OP_OFFER_ACCEPT || op == OP_OFFER_PAY))
                continue;

            // get the txn height
            nHeight = GetOfferTxHashHeight(hash);

            // get the txn alias name
            if(!GetNameOfOfferTx(tx, vchName))
                continue;

            // skip this alias if it doesn't match the given filter value
            if(vchNameUniq.size() > 0 && vchNameUniq != vchName)
                continue;

            // get the value of the alias txn
            if(!GetValueOfOfferTx(tx, vchValue))
                continue;

            // build the output object
            Object oName;
            oName.push_back(Pair("name", stringFromVch(vchName)));
            oName.push_back(Pair("value", stringFromVch(vchValue)));
            if(op == OP_OFFER_ACCEPT)
            	oName.push_back(Pair("status", "accepted"));
           	else if(op == OP_OFFER_PAY)
            	oName.push_back(Pair("status", "paid"));           	        

            string strAddress = "";
            GetOfferAddress(tx, strAddress);
            oName.push_back(Pair("address", strAddress));

            oName.push_back(Pair("expires_in", nHeight
                                 + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight));
            if(nHeight + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight <= 0)
                oName.push_back(Pair("expired", 1));

            // get last active name only
            if(vNamesI.find(vchName) != vNamesI.end() && vNamesI[vchName] > nHeight)
                continue;

            vNamesI[vchName] = nHeight;
            vNamesO[vchName] = oName;
        }
    }

    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, Object)& item, vNamesO)
        oRes.push_back(item.second);

    return oRes;
}


Value offerhistory(const Array& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerhistory <offer>\n"
				"List all stored values of an offer.\n");

	Array oRes;
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	string offer = stringFromVch(vchOffer);

	{

		//vector<CDiskTxPos> vtxPos;
		vector<COffer> vtxPos;
		//COfferDB dbOffer("r");
		if (!pofferdb->ReadOffer(vchOffer, vtxPos))
			throw JSONRPCError(RPC_WALLET_ERROR,
					"failed to read from offer DB");

		COffer txPos2;
		uint256 txHash;
		uint256 blockHash;
		BOOST_FOREACH(txPos2, vtxPos) {
			txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetTransaction(txHash, tx, blockHash, true)) {
				error("could not read txpos");
				continue;
			}

			Object oOffer;
			vector<unsigned char> vchValue;
			int nHeight;
			uint256 hash;
			if (GetValueOfOfferTxHash(txHash, vchValue, hash, nHeight)) {
				oOffer.push_back(Pair("offer", offer));
				string value = stringFromVch(vchValue);
				oOffer.push_back(Pair("value", value));
				oOffer.push_back(Pair("txid", tx.GetHash().GetHex()));
				string strAddress = "";
				GetOfferAddress(tx, strAddress);
				oOffer.push_back(Pair("address", strAddress));
				oOffer.push_back(
						Pair("expires_in",
								nHeight + GetOfferDisplayExpirationDepth(nHeight)
										- pindexBest->nHeight));
				if (nHeight + GetOfferDisplayExpirationDepth(nHeight)
						- pindexBest->nHeight <= 0) {
					oOffer.push_back(Pair("expired", 1));
				}
				oRes.push_back(oOffer);
			}
		}
	}
	return oRes;
}

Value offerfilter(const Array& params, bool fHelp) {
	if (fHelp || params.size() > 5)
		throw runtime_error(
				"offerfilter [[[[[regexp] maxage=36000] from=0] nb=0] stat]\n"
						"scan and filter offeres\n"
						"[regexp] : apply [regexp] on offeres, empty means all offeres\n"
						"[maxage] : look in last [maxage] blocks\n"
						"[from] : show results from number [from]\n"
						"[nb] : show [nb] results, 0 means all\n"
						"[stats] : show some stats instead of results\n"
						"offerfilter \"\" 5 # list offeres updated in last 5 blocks\n"
						"offerfilter \"^offer\" # list all offeres starting with \"offer\"\n"
						"offerfilter 36000 0 0 stat # display stats (number of offers) on active offeres\n");

	string strRegexp;
	int nFrom = 0;
	int nNb = 0;
	int nMaxAge = 36000;
	bool fStat = false;
	int nCountFrom = 0;
	int nCountNb = 0;

	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		nMaxAge = params[1].get_int();

	if (params.size() > 2)
		nFrom = params[2].get_int();

	if (params.size() > 3)
		nNb = params[3].get_int();

	if (params.size() > 4)
		fStat = (params[4].get_str() == "stat" ? true : false);

	//COfferDB dbOffer("r");
	Array oRes;

	vector<unsigned char> vchOffer;
	vector<pair<vector<unsigned char>, COffer> > offerScan;
	if (!pofferdb->ScanOffers(vchOffer, 100000000, offerScan))
		throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

	pair<vector<unsigned char>, COffer> pairScan;
	BOOST_FOREACH(pairScan, offerScan) {
		string offer = stringFromVch(pairScan.first);

		// regexp
		using namespace boost::xpressive;
		smatch offerparts;
		sregex cregex = sregex::compile(strRegexp);
		if (strRegexp != "" && !regex_search(offer, offerparts, cregex))
			continue;

		COffer txOffer = pairScan.second;
		int nHeight = txOffer.nHeight;

		// max age
		if (nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
			continue;

		// from limits
		nCountFrom++;
		if (nCountFrom < nFrom + 1)
			continue;

		Object oOffer;
		oOffer.push_back(Pair("offer", offer));
		CTransaction tx;
		uint256 blockHash;
		uint256 txHash = txOffer.txHash;
		if ((nHeight + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight
				<= 0) || !GetTransaction(txHash, tx, blockHash, true)) {
			oOffer.push_back(Pair("expired", 1));
		} else {
			vector<unsigned char> vchValue = txOffer.sTitle;
			string value = stringFromVch(vchValue);
			oOffer.push_back(Pair("value", value));
			oOffer.push_back(
					Pair("expires_in",
							nHeight + GetOfferDisplayExpirationDepth(nHeight)
									- pindexBest->nHeight));
		}
		oRes.push_back(oOffer);

		nCountNb++;
		// nb limits
		if (nNb > 0 && nCountNb >= nNb)
			break;
	}

	if (fStat) {
		Object oStat;
		oStat.push_back(Pair("blocks", (int) nBestHeight));
		oStat.push_back(Pair("count", (int) oRes.size()));
		//oStat.push_back(Pair("sha256sum", SHA256(oRes), true));
		return oStat;
	}

	return oRes;
}

Value offerscan(const Array& params, bool fHelp) {
	if (fHelp || 2 > params.size())
		throw runtime_error(
				"offerscan [<start-offer>] [<max-returned>]\n"
						"scan all offers, starting at start-offer and returning a maximum number of entries (default 500)\n");

	vector<unsigned char> vchOffer;
	int nMax = 500;
	if (params.size() > 0) {
		vchOffer = vchFromValue(params[0]);
	}

	if (params.size() > 1) {
		Value vMax = params[1];
		ConvertTo<double>(vMax);
		nMax = (int) vMax.get_real();
	}

	//COfferDB dbOffer("r");
	Array oRes;

	vector<pair<vector<unsigned char>, COffer> > offerScan;
	if (!pofferdb->ScanOffers(vchOffer, nMax, offerScan))
		throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

	pair<vector<unsigned char>, COffer> pairScan;
	BOOST_FOREACH(pairScan, offerScan) {
		Object oOffer;
		string offer = stringFromVch(pairScan.first);
		oOffer.push_back(Pair("offer", offer));
		CTransaction tx;
		COffer txOffer = pairScan.second;
		uint256 blockHash;

		int nHeight = txOffer.nHeight;
		vector<unsigned char> vchValue = txOffer.sTitle;
		if ((nHeight + GetOfferDisplayExpirationDepth(nHeight) - pindexBest->nHeight
				<= 0) || !GetTransaction(txOffer.txHash, tx, blockHash, true)) {
			oOffer.push_back(Pair("expired", 1));
		} else {
			string value = stringFromVch(vchValue);
			//string strAddress = "";
			//GetOfferAddress(tx, strAddress);
			oOffer.push_back(Pair("value", value));
			//oOffer.push_back(Pair("txid", tx.GetHash().GetHex()));
			//oOffer.push_back(Pair("address", strAddress));
			oOffer.push_back(
					Pair("expires_in",
							nHeight + GetOfferDisplayExpirationDepth(nHeight)
									- pindexBest->nHeight));
		}
		oRes.push_back(oOffer);
	}

	return oRes;
}


 Value offerclean(const Array& params, bool fHelp)
 {
	if (fHelp || params.size())
	throw runtime_error("offer_clean\nClean unsatisfiable transactions from the wallet - including offer_update on an already taken offer\n");

	{
		LOCK2(cs_main,pwalletMain->cs_wallet);
		map<uint256, CWalletTx> mapRemove;

		printf("-----------------------------\n");

		{
			BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet){
	 			CWalletTx& wtx = item.second;
			 	vector<unsigned char> vchOffer;
	 			if (wtx.GetDepthInMainChain() < 1 && IsConflictedOfferTx(*pblocktree, wtx, vchOffer))
	 			{
	 				uint256 hash = wtx.GetHash();
	 				mapRemove[hash] = wtx;
	 			}
	 		}
	 	}

	 	bool fRepeat = true;
	 	while (fRepeat)
	 	{
	 		fRepeat = false;
	 		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
	 		{
	 			CWalletTx& wtx = item.second;
	 			BOOST_FOREACH(const CTxIn& txin, wtx.vin)
	 			{
	 				uint256 hash = wtx.GetHash();

	 				// If this tx depends on a tx to be removed, remove it too
	 				if (mapRemove.count(txin.prevout.hash) && !mapRemove.count(hash))
	 				{
	 					mapRemove[hash] = wtx;
	 					fRepeat = true;
	 				}
	 			}
	 		}
	 	}

		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapRemove)
		{
		 	CWalletTx& wtx = item.second;

		 	UnspendInputs(wtx);
		 	wtx.RemoveFromMemoryPool();
		 	pwalletMain->EraseFromWallet(wtx.GetHash());
		 	vector<unsigned char> vchOffer;
		 	if (GetNameOfOfferTx(wtx, vchOffer) && mapOfferPending.count(vchOffer))
		 	{
		 		string offer = stringFromVch(vchOffer);
		 		printf("offer_clean() : erase %s from pending of offer %s",
		 			wtx.GetHash().GetHex().c_str(), offer.c_str());
		 		if (!mapOfferPending[vchOffer].erase(wtx.GetHash()))
		 			error("offer_clean() : erase but it was not pending");
		 	}
		 	wtx.print();
		}

		printf("-----------------------------\n");
	}
	return true;
 }
