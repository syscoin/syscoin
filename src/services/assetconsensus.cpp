// Copyright (c) 2013-2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <services/assetconsensus.h>
#include <validation.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <nevm/nevm.h>
#include <nevm/address.h>
#include <nevm/sha3.h>
#include <messagesigner.h>
#include <util/rbf.h>
#include <undo.h>
#include <validationinterface.h>
#include <timedata.h>
#include <key_io.h>
#include <logging.h>
std::unique_ptr<CNEVMTxRootsDB> pnevmtxrootsdb;
std::unique_ptr<CNEVMMintedTxDB> pnevmtxmintdb;
RecursiveMutex cs_setethstatus;
bool CheckSyscoinMint(const bool &ibd, const CTransaction& tx, const uint256& txHash, TxValidationState& state, const bool &fJustCheck, const bool& bSanityCheck, const uint32_t& nHeight, const int64_t& nTime, const uint256& blockhash, NEVMMintTxMap &mapMintKeys, CAssetsMap &mapAssetIn, CAssetsMap &mapAssetOut) {
    if (!bSanityCheck)
        LogPrint(BCLog::SYS,"*** ASSET MINT %d %s %s bSanityCheck=%d\n", nHeight,
            txHash.ToString().c_str(),
            fJustCheck ? "JUSTCHECK" : "BLOCK", bSanityCheck? 1: 0);
    // unserialize mint object from txn, check for valid
    CMintSyscoin mintSyscoin(tx);
    if(mintSyscoin.IsNull()) {
        return FormatSyscoinErrorMessage(state, "mint-unserialize", bSanityCheck);
    }

    NEVMTxRoot txRootDB;
    {
        LOCK(cs_setethstatus);
        if(!pnevmtxrootsdb || !pnevmtxrootsdb->ReadTxRoots(mintSyscoin.nBlockHash, txRootDB)) {
            return FormatSyscoinErrorMessage(state, "mint-txroot-missing", bSanityCheck);
        }
    }
     // check transaction receipt validity
    dev::RLP rlpReceiptParentNodes(&mintSyscoin.vchReceiptParentNodes);
    std::vector<unsigned char> vchReceiptValue(mintSyscoin.vchReceiptParentNodes.begin()+mintSyscoin.posReceipt, mintSyscoin.vchReceiptParentNodes.end());
    dev::RLP rlpReceiptValue(&vchReceiptValue);
    
    if (!rlpReceiptValue.isList()) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-tx-receipt", bSanityCheck);
    }
    if (rlpReceiptValue.itemCount() != 4) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-tx-receipt-count", bSanityCheck);
    }
    const uint64_t &nStatus = rlpReceiptValue[0].toInt<uint64_t>(dev::RLP::VeryStrict);
    if (nStatus != 1) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-tx-receipt-status", bSanityCheck);
    } 
    dev::RLP rlpReceiptLogsValue(rlpReceiptValue[3]);
    if (!rlpReceiptLogsValue.isList()) {
        return FormatSyscoinErrorMessage(state, "mint-receipt-rlp-logs-list", bSanityCheck);
    }
    const size_t &itemCount = rlpReceiptLogsValue.itemCount();
    // just sanity checks for bounds
    if (itemCount < 1 || itemCount > 10) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-logs-count", bSanityCheck);
    }
    // look for TokenFreeze event and get the last parameter which should be the precisions
    uint8_t nERC20Precision = 0;
    uint8_t nSPTPrecision = 0;
    for(uint32_t i = 0;i<itemCount;i++) {
        dev::RLP rlpReceiptLogValue(rlpReceiptLogsValue[i]);
        if (!rlpReceiptLogValue.isList()) {
            return FormatSyscoinErrorMessage(state, "mint-receipt-log-rlp-list", bSanityCheck);
        }
        // ensure this log has at least the address to check against
        if (rlpReceiptLogValue.itemCount() < 1) {
            return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-log-count", bSanityCheck);
        }
        const dev::Address &address160Log = rlpReceiptLogValue[0].toHash<dev::Address>(dev::RLP::VeryStrict);
        if(Params().GetConsensus().vchSYSXERC20Manager == address160Log.asBytes()) {
            // for mint log we should have exactly 3 entries in it, this event we control through our erc20manager contract
            if (rlpReceiptLogValue.itemCount() != 3) {
                return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-log-count-bridgeid", bSanityCheck);
            }
            // check topic
            dev::RLP rlpReceiptLogTopicsValue(rlpReceiptLogValue[1]);
            if (!rlpReceiptLogTopicsValue.isList()) {
                return FormatSyscoinErrorMessage(state, "mint-receipt-log-topics-rlp-list", bSanityCheck);
            }
            if (rlpReceiptLogTopicsValue.itemCount() != 1) {
                return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-log-topics-count", bSanityCheck);
            }
            // topic hash matches with TokenFreeze signature
            if(Params().GetConsensus().vchTokenFreezeMethod == rlpReceiptLogTopicsValue[0].toBytes(dev::RLP::VeryStrict)) {
                const std::vector<unsigned char> &dataValue = rlpReceiptLogValue[2].toBytes(dev::RLP::VeryStrict);
                if(dataValue.size() < 128) {
                     return FormatSyscoinErrorMessage(state, "mint-receipt-log-data-invalid-size", fJustCheck);
                }
                // get last data field which should be our precisions
                const std::vector<unsigned char> precisions(dataValue.begin()+96, dataValue.end());
                // get precision
                nERC20Precision = static_cast<uint8_t>(precisions[31]);
                nSPTPrecision = static_cast<uint8_t>(precisions[27]);
            }
        }
    }
    if(nERC20Precision == 0 || nSPTPrecision == 0) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-missing-precision", bSanityCheck);
    }
    // check transaction spv proofs
    std::vector<unsigned char> rlpTxRootVec(txRootDB.nTxRoot.begin(), txRootDB.nTxRoot.end());
    dev::RLPStream sTxRoot, sReceiptRoot;
    sTxRoot.append(rlpTxRootVec);
    std::vector<unsigned char> rlpReceiptRootVec(txRootDB.nReceiptRoot.begin(),  txRootDB.nReceiptRoot.end());
    sReceiptRoot.append(rlpReceiptRootVec);
    dev::RLP rlpTxRoot(sTxRoot.out());
    dev::RLP rlpReceiptRoot(sReceiptRoot.out());
    if(mintSyscoin.nTxRoot != txRootDB.nTxRoot){
        return FormatSyscoinErrorMessage(state, "mint-mismatching-txroot", bSanityCheck);
    }
    if(mintSyscoin.nReceiptRoot != txRootDB.nReceiptRoot){
        return FormatSyscoinErrorMessage(state, "mint-mismatching-receiptroot", bSanityCheck);
    }
    
    
    dev::RLP rlpTxParentNodes(&mintSyscoin.vchTxParentNodes);
    std::vector<unsigned char> vchTxValue(mintSyscoin.vchTxParentNodes.begin()+mintSyscoin.posTx, mintSyscoin.vchTxParentNodes.end());
    std::vector<unsigned char> vchTxHash(dev::sha3(vchTxValue).asBytes());
    // we must reverse the endian-ness because we store uint256 in BE but Eth uses LE.
    std::reverse(vchTxHash.begin(), vchTxHash.end());
    // validate mintSyscoin.nTxHash is the hash of vchTxValue, this is not the TXID which would require deserializataion of the transaction object, for our purpose we only need
    // uniqueness per transaction that is immutable and we do not care specifically for the txid but only that the hash cannot be reproduced for double-spend
    if(uint256S(HexStr(vchTxHash)) != mintSyscoin.nTxHash) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-hash", bSanityCheck);
    }
    dev::RLP rlpTxValue(&vchTxValue);
    const std::vector<unsigned char> &vchTxPath = mintSyscoin.vchTxPath;
    // ensure eth tx not already spent in a previous block
    if(pnevmtxmintdb->ExistsTx(mintSyscoin.nTxHash)) {
        return FormatSyscoinErrorMessage(state, "mint-exists", bSanityCheck);
    } 
    // sanity check is set in mempool during m_test_accept and when miner validates block
    // we care to ensure unique bridge id's in the mempool, not to emplace on test_accept
    if(bSanityCheck) {
        if(mapMintKeys.find(mintSyscoin.nTxHash) != mapMintKeys.end()) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-transfer");
        }
    }
    else {
        // ensure eth tx not already spent in current processing block or mempool(mapMintKeysMempool passed in)
        auto itMap = mapMintKeys.try_emplace(mintSyscoin.nTxHash, txHash);
        if(!itMap.second) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-transfer");
        }
    }
    // verify receipt proof
    if(!VerifyProof(&vchTxPath, rlpReceiptValue, rlpReceiptParentNodes, rlpReceiptRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-receipt-proof", bSanityCheck);
    }
    // verify transaction proof
    if(!VerifyProof(&vchTxPath, rlpTxValue, rlpTxParentNodes, rlpTxRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-proof", bSanityCheck);
    }
    if (!rlpTxValue.isList()) {
        return FormatSyscoinErrorMessage(state, "mint-tx-rlp-list", bSanityCheck);
    }
    if (rlpTxValue.itemCount() < 8) {
        return FormatSyscoinErrorMessage(state, "mint-tx-itemcount", bSanityCheck);
    }
    const dev::u256& nChainID = rlpTxValue[0].toInt<dev::u256>(dev::RLP::VeryStrict);
    if(nChainID != (dev::u256(Params().GetConsensus().nNEVMChainID))) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-chainid", bSanityCheck);
    }
    if (!rlpTxValue[7].isData()) {
        return FormatSyscoinErrorMessage(state, "mint-tx-array", bSanityCheck);
    }    
    if (rlpTxValue[5].isEmpty()) {
        return FormatSyscoinErrorMessage(state, "mint-tx-invalid-receiver", bSanityCheck);
    }             
    const dev::Address &address160 = rlpTxValue[5].toHash<dev::Address>(dev::RLP::VeryStrict);

    // ensure ERC20Manager is in the "to" field for the contract, meaning the function was called on this contract for freezing supply
    if(Params().GetConsensus().vchSYSXERC20Manager != address160.asBytes()) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-contract-manager", bSanityCheck);
    }
    CAmount outputAmount;
    uint64_t nAssetNEVM = 0;
    const std::vector<unsigned char> &rlpBytes = rlpTxValue[7].toBytes(dev::RLP::VeryStrict);
    std::vector<unsigned char> vchERC20ContractAddress;
    CTxDestination dest;
    std::string witnessAddress;
    if(!parseNEVMMethodInputData(Params().GetConsensus().vchSYSXBurnMethodSignature, nERC20Precision, nSPTPrecision, rlpBytes, outputAmount, nAssetNEVM, witnessAddress)) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-tx-data", bSanityCheck);
    }
    auto itOut = mapAssetOut.find(nAssetNEVM);
    if(itOut == mapAssetOut.end()) {
        return FormatSyscoinErrorMessage(state, "mint-asset-output-notfound", bSanityCheck);             
    }
    if(!fRegTest) {
        bool bFoundDest = false;
        // look through outputs to find one that matches the destination with the right asset and asset amount
        for(const auto &vout: tx.vout) {
            if(vout.scriptPubKey.IsUnspendable()) {
                continue;
            }
            if(!ExtractDestination(vout.scriptPubKey, dest)) {
                return FormatSyscoinErrorMessage(state, "mint-extract-destination", bSanityCheck);  
            }
            if(EncodeDestination(dest) == witnessAddress && vout.assetInfo.nAsset == nAssetNEVM && vout.assetInfo.nValue == outputAmount) {
                bFoundDest = true;
                break;
            }
        }
        if(!bFoundDest) {
            return FormatSyscoinErrorMessage(state, "mint-mismatch-destination", bSanityCheck);
        }
    }
    if(outputAmount <= 0) {
        return FormatSyscoinErrorMessage(state, "mint-value-negative", bSanityCheck);
    }
    
    // if input for this asset exists, must also include it as change in output, so output-input should be the new amount created
    auto itIn = mapAssetIn.find(nAssetNEVM);
    CAmount nTotal;
    if(itIn != mapAssetIn.end()) {
        nTotal = itOut->second - itIn->second;
        mapAssetIn.erase(itIn);
    } else {
        nTotal = itOut->second;
    }
    // erase in / out of this asset as equality is checked for the rest after CheckSyscoinInputs()
    mapAssetOut.erase(itOut);
    // the event logged amount must be only the amount we mint
    if(outputAmount != nTotal) {
        return FormatSyscoinErrorMessage(state, "mint-mismatch-value", bSanityCheck);  
    }
    if (!MoneyRangeAsset(nTotal)) {
        return FormatSyscoinErrorMessage(state, "mint-value-outofrange", bSanityCheck);
    }
    if(!fJustCheck) {
        if(!bSanityCheck && nHeight > 0) {   
            LogPrint(BCLog::SYS,"CONNECTED ASSET MINT: op=%s asset=%llu hash=%s height=%d fJustCheck=%s\n",
                stringFromSyscoinTx(tx.nVersion).c_str(),
                nAssetNEVM,
                txHash.ToString().c_str(),
                nHeight,
                fJustCheck ? "JUSTCHECK" : "BLOCK");      
        }           
    }               
    return true;
}
bool DisconnectMintAsset(const CTransaction &tx, const uint256& txHash, NEVMMintTxMap &mapMintKeys){
    CMintSyscoin mintSyscoin(tx);
    if(mintSyscoin.IsNull()) {
        LogPrint(BCLog::SYS,"DisconnectMintAsset: Cannot unserialize data inside of this transaction relating to an assetallocationmint\n");
        return false;
    }
    mapMintKeys.try_emplace(mintSyscoin.nTxHash, txHash);
    return true;
}

bool CheckSyscoinInputs(const CTransaction& tx, const Consensus::Params& params, const uint256& txHash, TxValidationState& state, const uint32_t &nHeight, const int64_t& nTime, NEVMMintTxMap &mapMintKeys, const bool &bSanityCheck, CAssetsMap& mapAssetIn, CAssetsMap& mapAssetOut) {
    if(!fRegTest && nHeight < (uint32_t)params.nNexusStartBlock)
        return false;
    if(tx.nVersion == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN_LEGACY)
        return false;
    return CheckSyscoinInputs(false, params, tx, txHash, state, true, nHeight, nTime, uint256(), bSanityCheck, mapMintKeys, mapAssetIn, mapAssetOut);
}

bool CheckSyscoinInputs(const bool &ibd, const Consensus::Params& params, const CTransaction& tx, const uint256& txHash, TxValidationState& state, const bool &fJustCheck, const uint32_t &nHeight, const int64_t& nTime, const uint256 & blockHash, const bool &bSanityCheck, NEVMMintTxMap &mapMintKeys, CAssetsMap& mapAssetIn, CAssetsMap& mapAssetOut) {
    bool good = true;
    if(nHeight < (uint32_t)params.nNexusStartBlock)
        return true;
    try{
        if(IsSyscoinMintTx(tx.nVersion)) {
            good = CheckSyscoinMint(ibd, tx, txHash, state, fJustCheck, bSanityCheck, nHeight, nTime, blockHash, mapMintKeys, mapAssetIn, mapAssetOut);
        }
        else if (IsAssetAllocationTx(tx.nVersion)) {
            good = CheckAssetAllocationInputs(tx, txHash, state, fJustCheck, nHeight, blockHash, bSanityCheck, mapAssetIn, mapAssetOut);
        }
        if (good && mapAssetIn != mapAssetOut) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-asset-io-mismatch");
        }
    } catch (...) {
        return FormatSyscoinErrorMessage(state, "checksyscoininputs-exception", bSanityCheck);
    }
    return good;
}

bool CheckAssetAllocationInputs(const CTransaction &tx, const uint256& txHash, TxValidationState &state,
        const bool &fJustCheck, const uint32_t &nHeight, const uint256& blockhash, const bool &bSanityCheck, CAssetsMap &mapAssetIn, CAssetsMap &mapAssetOut) {
    if (!bSanityCheck)
        LogPrint(BCLog::SYS,"*** ASSET ALLOCATION %d %s %s bSanityCheck=%d\n", nHeight,
            txHash.ToString().c_str(),
            fJustCheck ? "JUSTCHECK" : "BLOCK", bSanityCheck? 1: 0);
        
    const int &nOut = GetSyscoinDataOutput(tx);
    if(nOut < 0) {
        return FormatSyscoinErrorMessage(state, "assetallocation-missing-burn-output", bSanityCheck);
    }
    switch (tx.nVersion) {
        case SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        break;
        case SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        {   
            const uint64_t &nAsset = Params().GetConsensus().nSYSXAsset;
            const CAmount &nBurnAmount = tx.vout[nOut].nValue;
            if(nBurnAmount <= 0) {
                return FormatSyscoinErrorMessage(state, "syscoin-burn-invalid-amount", bSanityCheck);
            }
            auto itOut = mapAssetOut.find(nAsset);
            if(itOut == mapAssetOut.end()) {
                return FormatSyscoinErrorMessage(state, "syscoin-burn-asset-output-notfound", bSanityCheck);             
            }
            // if input for this asset exists, must also include it as change in output, so output-input should be the new amount created
            auto itIn = mapAssetIn.find(nAsset);
            CAmount nTotal;
            if(itIn != mapAssetIn.end()) {
                nTotal = itOut->second - itIn->second;
                mapAssetIn.erase(itIn);
            } else {
                nTotal = itOut->second;
            }
            mapAssetOut.erase(itOut);
            // erase in / out of this asset as equality is checked for the rest after CheckSyscoinInputs()
            // the burn amount in opreturn (SYS) should match total output for SYSX
            if(nTotal != nBurnAmount) {
                return FormatSyscoinErrorMessage(state, "syscoin-burn-mismatch-amount", bSanityCheck);
            }
        }
        break;
        case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        {
            const CAmount &nBurnAmount = tx.vout[nOut].assetInfo.nValue;
            if (nBurnAmount <= 0) {
                return FormatSyscoinErrorMessage(state, "assetallocation-invalid-burn-amount", bSanityCheck);
            }
            if(tx.nVersion == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN) {
                if(nOut == 0) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-invalid-burn-index", bSanityCheck);
                }
                // the burn of asset in opreturn should match the output value of index 0 (sys)
                if(nBurnAmount != tx.vout[0].nValue) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-mismatch-burn-amount", bSanityCheck);
                }  
                if(tx.vout[nOut].assetInfo.nAsset != Params().GetConsensus().nSYSXAsset) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-invalid-sysx-asset", bSanityCheck);
                }  
            }
        } 
        break;
        default:
            return FormatSyscoinErrorMessage(state, "assetallocation-invalid-op", bSanityCheck);
    }

    if(!fJustCheck){
        if(!bSanityCheck && nHeight > 0) {  
            LogPrint(BCLog::SYS,"CONNECTED ASSET ALLOCATION: op=%s hash=%s height=%d fJustCheck=%s\n",
                stringFromSyscoinTx(tx.nVersion).c_str(),
                txHash.ToString().c_str(),
                nHeight,
                "BLOCK");      
        }             
    }  
    return true;
}
// called on connect

void CNEVMTxRootsDB::FlushDataToCache(const NEVMTxRootMap &mapNEVMTxRoots) {
    if(mapNEVMTxRoots.empty()) {
        return;
    }
    for (auto const& [key, val] : mapNEVMTxRoots) {
        mapCache.try_emplace(key, val);
    }
    LogPrint(BCLog::SYS, "Flushing to cache, storing %d nevm tx roots\n", mapNEVMTxRoots.size());
}
bool CNEVMTxRootsDB::FlushCacheToDisk() {
    if(mapCache.empty()) {
        return true;
    }
    CDBBatch batch(*this);    
    for (auto const& [key, val] : mapCache) {
        batch.Write(key, val);
    }
    LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm tx roots\n", mapCache.size());
    auto res = WriteBatch(batch, true);
    mapCache.clear();
    return res;
}
bool CNEVMTxRootsDB::ReadTxRoots(const uint256& nBlockHash, NEVMTxRoot& txRoot) {
    auto it = mapCache.find(nBlockHash);
    if(it != mapCache.end()){
        txRoot = it->second;
        return true;
    } else {
        return Read(nBlockHash, txRoot);
    }
    return false;
} 
bool CNEVMTxRootsDB::FlushErase(const std::vector<uint256> &vecBlockHashes) {
    if(vecBlockHashes.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : vecBlockHashes) {
        batch.Erase(key);
        auto it = mapCache.find(key);
        if(it != mapCache.end()){
            mapCache.erase(it);
        }
    }
    LogPrint(BCLog::SYS, "Flushing, erasing %d nevm tx roots\n", vecBlockHashes.size());
    return WriteBatch(batch, true);
}
void CNEVMMintedTxDB::FlushDataToCache(const NEVMMintTxMap &mapNEVMTxRoots) {
    if(mapNEVMTxRoots.empty()) {
        return;
    }
    for (auto const& [key, val] : mapNEVMTxRoots) {
        mapCache.try_emplace(key, val);
    }
    LogPrint(BCLog::SYS, "Flushing to cache, storing %d nevm tx mints\n", mapNEVMTxRoots.size());
}
bool CNEVMMintedTxDB::FlushCacheToDisk() {
    if(mapCache.empty()) {
        return true;
    }
    CDBBatch batch(*this);    
    for (auto const& [key, val] : mapCache) {
        batch.Write(key, val);
    }
    LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm tx mints\n", mapCache.size());
    auto res = WriteBatch(batch, true);
    mapCache.clear();
    return res;
}
bool CNEVMMintedTxDB::FlushErase(const NEVMMintTxMap &mapNEVMTxRoots) {
    if(mapNEVMTxRoots.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : mapNEVMTxRoots) {
        batch.Erase(key);
        auto it = mapCache.find(key.first);
        if(it != mapCache.end()){
            mapCache.erase(it);
        }
    }
    LogPrint(BCLog::SYS, "Flushing, erasing %d nevm tx mints\n", mapNEVMTxRoots.size());
    return WriteBatch(batch, true);
}
bool CNEVMMintedTxDB::ExistsTx(const uint256& nTxHash) {
    return (mapCache.find(nTxHash) != mapCache.end()) || Exists(nTxHash);
}
std::string stringFromSyscoinTx(const int &nVersion) {
    switch (nVersion) {
	case SYSCOIN_TX_VERSION_ALLOCATION_SEND:
		return "assetallocationsend";
	case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
		return "assetallocationburntonevm"; 
	case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
		return "assetallocationburntosyscoin";
	case SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
		return "syscoinburntoassetallocation";            
    case SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        return "assetallocationmint";   
    default:
        return "<unknown assetallocation op>";
    }
}