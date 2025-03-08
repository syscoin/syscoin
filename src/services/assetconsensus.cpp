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
const arith_uint256 nMax = arith_uint256(MAX_MONEY);
bool CheckSyscoinMint(
    const bool &ibd,
    const CTransaction &tx,
    const uint256 &txHash,
    TxValidationState &state,
    const bool &fJustCheck,
    const bool &bSanityCheck,
    const uint32_t &nHeight,
    const int64_t &nTime,
    const uint256 &blockhash,
    NEVMMintTxMap &mapMintKeys,
    CAssetsMap &mapAssetIn,
    CAssetsMap &mapAssetOut
) {
    if (!bSanityCheck) {
        LogPrint(BCLog::SYS,"*** ASSET MINT blockHeight=%d tx=%s %s bSanityCheck=%d\n",
            nHeight, txHash.ToString(), fJustCheck ? "JUSTCHECK" : "BLOCK",
            bSanityCheck? 1: 0);
    }

    // 1) Unserialize the mint object from the syscoin TX
    CMintSyscoin mintSyscoin(tx);
    if (mintSyscoin.IsNull()) {
        return FormatSyscoinErrorMessage(state, "mint-unserialize-failed", bSanityCheck);
    }

    // 2) Load the NEVM block’s TxRoot / ReceiptRoot
    NEVMTxRoot txRootDB;
    if(!fRegTest)
    {
        LOCK(cs_setethstatus);
        if (!pnevmtxrootsdb || !pnevmtxrootsdb->ReadTxRoots(mintSyscoin.nBlockHash, txRootDB)) {
            return FormatSyscoinErrorMessage(state, "mint-txroot-missing", bSanityCheck);
        }
    }

    // 3) RLP decode the receipt
    dev::RLP rlpReceiptParentNodes(&mintSyscoin.vchReceiptParentNodes);
    std::vector<unsigned char> vchReceiptValue(
        mintSyscoin.vchReceiptParentNodes.begin() + mintSyscoin.posReceipt,
        mintSyscoin.vchReceiptParentNodes.end()
    );
    dev::RLP rlpReceiptValue(&vchReceiptValue);
    if (!rlpReceiptValue.isList() || rlpReceiptValue.itemCount() != 4) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-structure", bSanityCheck);
    }

    // 4) Check status field (EIP2718)
    uint64_t nStatus = rlpReceiptValue[0].toInt<uint64_t>(dev::RLP::VeryStrict);
    if (nStatus != 1) {
        return FormatSyscoinErrorMessage(state, "mint-receipt-status-failed", bSanityCheck);
    }

    // 5) Parse logs from the 4th field (index=3)
    dev::RLP rlpLogs(rlpReceiptValue[3]);
    if (!rlpLogs.isList() || rlpLogs.itemCount() < 1) {
        return FormatSyscoinErrorMessage(state, "mint-no-logs", bSanityCheck);
    }
    size_t itemCount = rlpLogs.itemCount();
    if (itemCount < 1 || itemCount > 10) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-logs-count", bSanityCheck);
    }
    uint64_t nAssetFromLog  = 0;
    CAmount outputAmount = 0;
    std::string witnessAddress;
    // The bridging contract we expect
    const std::vector<unsigned char> &vchManagerAddress = Params().GetConsensus().vchSYSXERC20Manager;

    // The known topic for event TokenFreeze(...)
    const std::vector<unsigned char> &vchFreezeTopic = Params().GetConsensus().vchTokenFreezeMethod;

    // Iterate each log
    for (size_t i = 0; i < rlpLogs.itemCount(); i++) {
        const dev::RLP& rlpLog = rlpLogs[i];
        if (!rlpLog.isList() || rlpLog.itemCount() < 3) {
            continue;
        }
    
        const dev::Address& addressLog = rlpLog[0].toHash<dev::Address>(dev::RLP::VeryStrict);
        if (addressLog.asBytes() != vchManagerAddress) {
            continue;
        }
    
        const dev::RLP& rlpLogTopics = rlpLog[1];
        if (!rlpLogTopics.isList() || rlpLogTopics.itemCount() == 0) {
            continue;
        }
    
        if (rlpLogTopics[0].toBytes(dev::RLP::VeryStrict) != vchFreezeTopic) {
            continue;
        }
    
        const std::vector<unsigned char>& dataValue = rlpLog[2].toBytes(dev::RLP::VeryStrict);
        if (dataValue.size() < 160) {
            return FormatSyscoinErrorMessage(state, "mint-log-data-too-small", bSanityCheck);
        }
    
        nAssetFromLog = ReadBE64(&dataValue[24]);
    
        const std::vector<unsigned char> vchValue(dataValue.begin() + 64, dataValue.begin() + 96);
        const arith_uint256 valueArith = UintToArith256(uint256(vchValue));
        if (valueArith > nMax) {
            return FormatSyscoinErrorMessage(state, "mint-value-overflow", bSanityCheck);
        }
        outputAmount = static_cast<CAmount>(valueArith.GetLow64());
        if (!MoneyRange(outputAmount)) {
            return FormatSyscoinErrorMessage(state, "mint-value-out-of-range", bSanityCheck);
        }
    
        const std::vector<unsigned char> vchOffset(dataValue.begin() + 96, dataValue.begin() + 128);
        const arith_uint256 offsetArith = UintToArith256(uint256(vchOffset));
        const uint64_t offsetToString = offsetArith.GetLow64();
    
        if (offsetToString < 128 || offsetToString + 32 > dataValue.size()) {
            return FormatSyscoinErrorMessage(state, "mint-log-invalid-string-offset", bSanityCheck);
        }
    
        const std::vector<unsigned char> vchStrLen(dataValue.begin() + offsetToString, dataValue.begin() + offsetToString + 32);
        const arith_uint256 strLenArith = UintToArith256(uint256(vchStrLen));
        const uint64_t lenString = strLenArith.GetLow64();
    
        if (offsetToString + 32 + lenString > dataValue.size()) {
            return FormatSyscoinErrorMessage(state, "mint-log-invalid-string-length", bSanityCheck);
        }
    
        witnessAddress = std::string(reinterpret_cast<const char*>(&dataValue[offsetToString + 32]), lenString);
    
        break;
    }

    if (nAssetFromLog == 0 || outputAmount == 0 || witnessAddress.empty()) {
        return FormatSyscoinErrorMessage(state, "mint-missing-freeze-log", bSanityCheck);
    }

    // 6) Check TxProof & ReceiptProof
    if(!fRegTest) {
        if (mintSyscoin.nTxRoot != txRootDB.nTxRoot) {
            return FormatSyscoinErrorMessage(state, "mint-mismatching-txroot", bSanityCheck);
        }
        if (mintSyscoin.nReceiptRoot != txRootDB.nReceiptRoot) {
            return FormatSyscoinErrorMessage(state, "mint-mismatching-receiptroot", bSanityCheck);
        }
    }

    // verify receipt proof
    dev::RLP rlpReceiptRoot(dev::bytesConstRef(mintSyscoin.nReceiptRoot.begin(), mintSyscoin.nReceiptRoot.size()));
    if(!VerifyProof(&mintSyscoin.vchTxPath, rlpReceiptValue, rlpReceiptParentNodes, rlpReceiptRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-receipt-proof-failed", bSanityCheck);
    }

    // verify transaction proof
    dev::RLP rlpTxParentNodes(&mintSyscoin.vchTxParentNodes);
    std::vector<unsigned char> vchTxValue(
        mintSyscoin.vchTxParentNodes.begin()+mintSyscoin.posTx,
        mintSyscoin.vchTxParentNodes.end()
    );
    std::vector<unsigned char> vchTxHash(dev::sha3(vchTxValue).asBytes());
    std::reverse(vchTxHash.begin(), vchTxHash.end());
    if (uint256S(HexStr(vchTxHash)) != mintSyscoin.nTxHash) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-hash", bSanityCheck);
    }
    dev::RLP rlpTxValue(&vchTxValue);
    dev::RLP rlpTxRoot(dev::bytesConstRef(mintSyscoin.nTxRoot.begin(), mintSyscoin.nTxRoot.size()));
    if(!VerifyProof(&mintSyscoin.vchTxPath, rlpTxValue, rlpTxParentNodes, rlpTxRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-proof-failed", bSanityCheck);
    }

    // check we haven't used nTxHash before
    if (pnevmtxmintdb->ExistsTx(mintSyscoin.nTxHash)) {
        return FormatSyscoinErrorMessage(state, "mint-tx-already-processed", bSanityCheck);
    }
    // also check in mapMintKeys for duplicates
    if(bSanityCheck) {
        if (mapMintKeys.find(mintSyscoin.nTxHash) != mapMintKeys.end()) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-tx");
        }
    } else {
        auto itMap = mapMintKeys.try_emplace(mintSyscoin.nTxHash, txHash);
        if(!itMap.second) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-tx");
        }
    }

    // 7) Check chainID, "to" field, parse method input
    if (!rlpTxValue.isList() || rlpTxValue.itemCount() < 8) {
        return FormatSyscoinErrorMessage(state, "mint-tx-rlp-structure-fail", bSanityCheck);
    }
    dev::u256 nChainID = rlpTxValue[0].toInt<dev::u256>(dev::RLP::VeryStrict);
    if (nChainID != dev::u256(Params().GetConsensus().nNEVMChainID)) {
        return FormatSyscoinErrorMessage(state, "mint-wrong-chainid", bSanityCheck);
    }
    if (!rlpTxValue[5].isData()) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receiver-field", bSanityCheck);
    }
    dev::Address toField = rlpTxValue[5].toHash<dev::Address>(dev::RLP::VeryStrict);
    if (toField.asBytes() != Params().GetConsensus().vchSYSXERC20Manager) {
        return FormatSyscoinErrorMessage(state, "mint-incorrect-bridge-manager", bSanityCheck);
    }
    bool bFoundDest = false;
    for (const auto &vout : tx.vout) {
        if (vout.scriptPubKey.IsUnspendable()) {
            continue;
        }
        CTxDestination dest;
        if (!ExtractDestination(vout.scriptPubKey, dest)) {
            return FormatSyscoinErrorMessage(state, "mint-extract-destination", bSanityCheck);  
        }
        if (EncodeDestination(dest) == witnessAddress && vout.assetInfo.nAsset == nAssetFromLog && vout.assetInfo.nValue == outputAmount) {
            bFoundDest = true;
            break;
        }
    }
    if (!bFoundDest) {
        return FormatSyscoinErrorMessage(state, "mint-mismatch-destination", bSanityCheck);
    }
    // 8) Now you have final "outputAmount" and "nAssetFromLog" => see if the UTXO outputs match
    //    That part depends on your bridging logic: checking mapAssetOut, ensuring there's an output
    //    to witnessAddress with the correct asset, etc.

    // For example:
    auto itOut = mapAssetOut.find(nAssetFromLog);
    if (itOut == mapAssetOut.end()) {
        return FormatSyscoinErrorMessage(state, "mint-asset-output-notfound", bSanityCheck);
    }

    // If there's also an input for this asset, remove it and see how much was net minted
    CAmount nTotalMinted;
    auto itIn = mapAssetIn.find(nAssetFromLog);
    if (itIn != mapAssetIn.end()) {
        nTotalMinted = itOut->second - itIn->second;
        mapAssetIn.erase(itIn);
    } else {
        nTotalMinted = itOut->second;
    }
    mapAssetOut.erase(itOut);

    // Must match the bridging "outputAmount"
    if (outputAmount != nTotalMinted) {
        return FormatSyscoinErrorMessage(state, "mint-output-mismatch", bSanityCheck);
    }

    // Optionally check that there's a matching vout to witnessAddress
    // e.g. loop over tx.vout, compare the address and asset.

    if (!fJustCheck) {
        if (!bSanityCheck && nHeight > 0) {
            LogPrint(BCLog::SYS,"CONNECTED ASSET MINT: asset=%llu tx=%s height=%d fJustCheck=%s\n",
                nAssetFromLog,
                txHash.ToString(),
                nHeight,
                fJustCheck ? "JUSTCHECK" : "BLOCK"
            );
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
    } catch (const std::exception& e) {
        return FormatSyscoinErrorMessage(state, e.what(), bSanityCheck);
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