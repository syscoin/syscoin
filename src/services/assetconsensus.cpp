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
bool CheckSyscoinMintInternal(
    const CMintSyscoin &mintSyscoin,
    TxValidationState &state,
    const bool &fJustCheck,
    NEVMMintTxSet &setMintTxs,
    uint64_t &nAssetFromLog,
    CAmount &outputAmount,
    std::string &witnessAddress) {
    nAssetFromLog = 0;
    outputAmount = 0;
    witnessAddress.clear();
    NEVMTxRoot txRootDB;
    if (!fRegTest) {
        LOCK(cs_setethstatus);
        if (!pnevmtxrootsdb || !pnevmtxrootsdb->ReadTxRoots(mintSyscoin.nBlockHash, txRootDB)) {
            return FormatSyscoinErrorMessage(state, "mint-txroot-missing", fJustCheck);
        }
    }
    const dev::RLP rlpReceiptParentNodes(&mintSyscoin.vchReceiptParentNodes);
    const std::vector<unsigned char> vchReceiptValue(
        mintSyscoin.vchReceiptParentNodes.begin() + mintSyscoin.posReceipt,
        mintSyscoin.vchReceiptParentNodes.end()
    );
    const dev::RLP rlpReceiptValue(&vchReceiptValue);
    if (!rlpReceiptValue.isList() || rlpReceiptValue.itemCount() != 4) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-structure", fJustCheck);
    }

    const uint64_t nStatus = rlpReceiptValue[0].toInt<uint64_t>(dev::RLP::VeryStrict);
    if (nStatus != 1) {
        return FormatSyscoinErrorMessage(state, "mint-receipt-status-failed", fJustCheck);
    }
    const dev::RLP rlpLogs(rlpReceiptValue[3]);
    const size_t itemCount = rlpLogs.itemCount();
    if (!rlpLogs.isList() || itemCount < 1 || itemCount > 10) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receipt-logs-count", fJustCheck);
    }
    const std::vector<unsigned char>& vchManagerAddress = Params().GetConsensus().vchSYSXERC20Manager;
    const std::vector<unsigned char>& vchFreezeTopic = Params().GetConsensus().vchTokenFreezeMethod;

    for (size_t i = 0; i < itemCount; ++i) {
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
            return FormatSyscoinErrorMessage(state, "mint-log-data-too-small", fJustCheck);
        }

        nAssetFromLog = ReadBE64(&dataValue[24]);
       
        std::vector<unsigned char> vchValue(dataValue.begin() + 64, dataValue.begin() + 96);
        std::reverse(vchValue.begin(), vchValue.end());
        const arith_uint256 valueArith = UintToArith256(uint256(vchValue));
        if (valueArith > nMax) {
            return FormatSyscoinErrorMessage(state, "mint-value-overflow", fJustCheck);
        }
        outputAmount = static_cast<CAmount>(valueArith.GetLow64());
       
        if (!MoneyRange(outputAmount)) {
            return FormatSyscoinErrorMessage(state, "mint-value-out-of-range", fJustCheck);
        }

        std::vector<unsigned char> vchOffset(dataValue.begin() + 96, dataValue.begin() + 128);
        std::reverse(vchOffset.begin(), vchOffset.end());
        const uint64_t offsetToString = UintToArith256(uint256(vchOffset)).GetLow64();
        if (offsetToString < 128 || offsetToString + 32 > dataValue.size()) {
            return FormatSyscoinErrorMessage(state, "mint-log-invalid-string-offset", fJustCheck);
        }

        // Parse string length correctly:
        std::vector<unsigned char> vchLenString(
            dataValue.begin() + offsetToString,
            dataValue.begin() + offsetToString + 32
        );
        std::reverse(vchLenString.begin(), vchLenString.end());
        const uint64_t lenString = UintToArith256(uint256(vchLenString)).GetLow64();

        if (offsetToString + 32 + lenString > dataValue.size()) {
            return FormatSyscoinErrorMessage(state, "mint-log-invalid-string-length", fJustCheck);
        }

        witnessAddress = std::string(reinterpret_cast<const char*>(&dataValue[offsetToString + 32]), lenString);
        break;
    }

    if (nAssetFromLog == 0 || outputAmount == 0 || witnessAddress.empty()) {
        return FormatSyscoinErrorMessage(state, "mint-missing-freeze-log", fJustCheck);
    }

    if (!fRegTest && (mintSyscoin.nTxRoot != txRootDB.nTxRoot || mintSyscoin.nReceiptRoot != txRootDB.nReceiptRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-mismatching-txroot-or-receiptroot", fJustCheck);
    }
    std::vector<unsigned char> rlpTxRootVec(txRootDB.nTxRoot.begin(), txRootDB.nTxRoot.end());
    dev::RLPStream sTxRoot, sReceiptRoot;
    sTxRoot.append(rlpTxRootVec);
    std::vector<unsigned char> rlpReceiptRootVec(txRootDB.nReceiptRoot.begin(),  txRootDB.nReceiptRoot.end());
    sReceiptRoot.append(rlpReceiptRootVec);
    dev::RLP rlpTxRoot(sTxRoot.out());
    dev::RLP rlpReceiptRoot(sReceiptRoot.out());
    dev::bytes receiptRootBytes = ParseHex(rlpReceiptRoot.toString());
    dev::RLP rlpReceiptRootNode(receiptRootBytes);
    // Verify the Merkle Patricia Proof
    if (!VerifyProof(&mintSyscoin.vchTxPath, rlpReceiptValue, rlpReceiptParentNodes, rlpReceiptRootNode)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-receipt-proof-failed", fJustCheck);
    }
    
    const dev::RLP rlpTxParentNodes(&mintSyscoin.vchTxParentNodes);
    const std::vector<unsigned char> vchTxValue(mintSyscoin.vchTxParentNodes.begin() + mintSyscoin.posTx, mintSyscoin.vchTxParentNodes.end());
    std::vector<unsigned char> vchTxHash(dev::sha3(vchTxValue).asBytes());
    std::reverse(vchTxHash.begin(), vchTxHash.end());
    if (uint256S(HexStr(vchTxHash)) != mintSyscoin.nTxHash) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-hash", fJustCheck);
    }
    const dev::RLP rlpTxValue(&vchTxValue);
    if (!VerifyProof(&mintSyscoin.vchTxPath, rlpTxValue, rlpTxParentNodes, rlpTxRoot)) {
        return FormatSyscoinErrorMessage(state, "mint-verify-tx-proof-failed", fJustCheck);
    }

    // check we haven't used nTxHash before
    if (pnevmtxmintdb->ExistsTx(mintSyscoin.nTxHash)) {
        return FormatSyscoinErrorMessage(state, "mint-tx-already-processed", fJustCheck);
    }
    // fJustCheck set on mempool test or block test
    if(fJustCheck) {
        if (setMintTxs.find(mintSyscoin.nTxHash) != setMintTxs.end()) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-tx");
        }
    } else {
        if (!setMintTxs.insert(mintSyscoin.nTxHash).second) {
            return state.Invalid(TxValidationResult::TX_MINT_DUPLICATE, "mint-duplicate-tx");
        }
    }

    // 7) Check chainID, "to" field, parse method input
    if (!rlpTxValue.isList() || rlpTxValue.itemCount() < 8) {
        return FormatSyscoinErrorMessage(state, "mint-tx-rlp-structure-fail", fJustCheck);
    }
    const dev::u256 &nChainID = rlpTxValue[0].toInt<dev::u256>(dev::RLP::VeryStrict);
    if (nChainID != dev::u256(Params().GetConsensus().nNEVMChainID)) {
        return FormatSyscoinErrorMessage(state, "mint-wrong-chainid", fJustCheck);
    }
    if (!rlpTxValue[5].isData()) {
        return FormatSyscoinErrorMessage(state, "mint-invalid-receiver-field", fJustCheck);
    }
    const dev::Address &toField = rlpTxValue[5].toHash<dev::Address>(dev::RLP::VeryStrict);
    if (toField.asBytes() != Params().GetConsensus().vchSYSXERC20Manager) {
        return FormatSyscoinErrorMessage(state, "mint-incorrect-bridge-manager", fJustCheck);
    }
    return true;
}
bool CheckSyscoinMint(
    const CTransaction &tx,
    const uint256 &txHash,
    TxValidationState &state,
    const uint32_t &nHeight,
    const bool &fJustCheck,
    NEVMMintTxSet &setMintTxs,
    CAssetsMap &mapAssetIn,
    CAssetsMap &mapAssetOut
) {
    LogPrint(BCLog::SYS,"*** ASSET MINT blockHeight=%d tx=%s %s\n",
            nHeight, txHash.ToString(), fJustCheck ? "JUSTCHECK" : "BLOCK");
    const CMintSyscoin mintSyscoin(tx);
    if (mintSyscoin.IsNull()) {
        return FormatSyscoinErrorMessage(state, "mint-unserialize-failed", fJustCheck);
    }
    std::string witnessAddress;
    uint64_t nAssetFromLog;
    CAmount outputAmount;
    if(!CheckSyscoinMintInternal(mintSyscoin, state, fJustCheck, setMintTxs, nAssetFromLog, outputAmount, witnessAddress)) {
        return false; // state filled in by CheckSyscoinMintInternal
    }
    bool bFoundDest = false;
    for (const auto &vout : tx.vout) {
        if (vout.scriptPubKey.IsUnspendable()) {
            continue;
        }
        CTxDestination dest;
        if (!ExtractDestination(vout.scriptPubKey, dest)) {
            return FormatSyscoinErrorMessage(state, "mint-extract-destination", fJustCheck);  
        }
        if (EncodeDestination(dest) == witnessAddress && vout.assetInfo.nAsset == nAssetFromLog && vout.assetInfo.nValue == outputAmount) {
            bFoundDest = true;
            break;
        }
    }
    if (!bFoundDest) {
        return FormatSyscoinErrorMessage(state, "mint-mismatch-destination", fJustCheck);
    }
    // 8) Now you have final "outputAmount" and "nAssetFromLog" => see if the UTXO outputs match
    //    That part depends on your bridging logic: checking mapAssetOut, ensuring there's an output
    //    to witnessAddress with the correct asset, etc.

    auto itOut = mapAssetOut.find(nAssetFromLog);
    if (itOut == mapAssetOut.end()) {
        return FormatSyscoinErrorMessage(state, "mint-asset-output-notfound", fJustCheck);
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
        return FormatSyscoinErrorMessage(state, "mint-output-mismatch", fJustCheck);
    }

    // Optionally check that there's a matching vout to witnessAddress
    // e.g. loop over tx.vout, compare the address and asset.

    if (!fJustCheck) {
        if (nHeight > 0) {
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

bool DisconnectMintAsset(const CTransaction &tx, NEVMMintTxSet &setMintTxs){
    CMintSyscoin mintSyscoin(tx);
    if(mintSyscoin.IsNull()) {
        LogPrint(BCLog::SYS,"DisconnectMintAsset: Cannot unserialize data inside of this transaction relating to an assetallocationmint\n");
        return false;
    }
    setMintTxs.insert(mintSyscoin.nTxHash);
    return true;
}

bool CheckSyscoinInputs(const Consensus::Params& params, const CTransaction& tx, const uint256& txHash, TxValidationState& state, const uint32_t &nHeight, const bool &fJustCheck, NEVMMintTxSet &setMintTxs, CAssetsMap& mapAssetIn, CAssetsMap& mapAssetOut) {
    bool good = true;
    if(nHeight < (uint32_t)params.nNexusStartBlock)
        return !fJustCheck;
    if(tx.nVersion == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN_LEGACY)
        return !fJustCheck;
    try{
        if(IsSyscoinMintTx(tx.nVersion)) {
            good = CheckSyscoinMint(tx, txHash, state, nHeight, fJustCheck, setMintTxs, mapAssetIn, mapAssetOut);
        }
        else if (IsAssetAllocationTx(tx.nVersion)) {
            good = CheckAssetAllocationInputs(tx, txHash, state, nHeight, fJustCheck, mapAssetIn, mapAssetOut);
        }
        if (good && mapAssetIn != mapAssetOut) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-asset-io-mismatch");
        }
    } catch (const std::exception& e) {
        return FormatSyscoinErrorMessage(state, e.what(), fJustCheck);
    } catch (...) {
        return FormatSyscoinErrorMessage(state, "checksyscoininputs-exception", fJustCheck);
    }
    return good;
}

bool CheckAssetAllocationInputs(const CTransaction &tx, const uint256& txHash, TxValidationState &state,
    const uint32_t &nHeight, const bool &fJustCheck, CAssetsMap &mapAssetIn, CAssetsMap &mapAssetOut) {
    LogPrint(BCLog::SYS,"*** ASSET ALLOCATION %d %s %s\n", nHeight,
            txHash.ToString().c_str(),
            fJustCheck ? "JUSTCHECK" : "BLOCK");
        
    const int &nOut = GetSyscoinDataOutput(tx);
    if(nOut < 0) {
        return FormatSyscoinErrorMessage(state, "assetallocation-missing-burn-output", fJustCheck);
    }
    switch (tx.nVersion) {
        case SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        break;
        case SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        {   
            const uint64_t &nAsset = Params().GetConsensus().nSYSXAsset;
            const CAmount &nBurnAmount = tx.vout[nOut].nValue;
            if(nBurnAmount <= 0) {
                return FormatSyscoinErrorMessage(state, "syscoin-burn-invalid-amount", fJustCheck);
            }
            auto itOut = mapAssetOut.find(nAsset);
            if(itOut == mapAssetOut.end()) {
                return FormatSyscoinErrorMessage(state, "syscoin-burn-asset-output-notfound", fJustCheck);             
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
                return FormatSyscoinErrorMessage(state, "syscoin-burn-mismatch-amount", fJustCheck);
            }
        }
        break;
        case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        case SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        {
            const CAmount &nBurnAmount = tx.vout[nOut].assetInfo.nValue;
            if (nBurnAmount <= 0) {
                return FormatSyscoinErrorMessage(state, "assetallocation-invalid-burn-amount", fJustCheck);
            }
            if(tx.nVersion == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN) {
                if(nOut == 0) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-invalid-burn-index", fJustCheck);
                }
                // the burn of asset in opreturn should match the output value of index 0 (sys)
                if(nBurnAmount != tx.vout[0].nValue) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-mismatch-burn-amount", fJustCheck);
                }  
                if(tx.vout[nOut].assetInfo.nAsset != Params().GetConsensus().nSYSXAsset) {
                    return FormatSyscoinErrorMessage(state, "assetallocation-invalid-sysx-asset", fJustCheck);
                }  
            }
        } 
        break;
        default:
            return FormatSyscoinErrorMessage(state, "assetallocation-invalid-op", fJustCheck);
    }

    if(!fJustCheck){
        if(nHeight > 0) {  
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
void CNEVMMintedTxDB::FlushDataToCache(const NEVMMintTxSet &mapNEVMTxRoots) {
    if(mapNEVMTxRoots.empty()) {
        return;
    }
    for (auto const& key : mapNEVMTxRoots) {
        mapCache.insert(key);
    }
    LogPrint(BCLog::SYS, "Flushing to cache, storing %d nevm tx mints\n", mapNEVMTxRoots.size());
}
bool CNEVMMintedTxDB::FlushCacheToDisk() {
    if(mapCache.empty()) {
        return true;
    }
    CDBBatch batch(*this);    
    for (auto const& key : mapCache) {
        batch.Write(key, true);
    }
    LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm tx mints\n", mapCache.size());
    auto res = WriteBatch(batch, true);
    mapCache.clear();
    return res;
}
bool CNEVMMintedTxDB::FlushErase(const NEVMMintTxSet &mapNEVMTxRoots) {
    if(mapNEVMTxRoots.empty())
        return true;
    CDBBatch batch(*this);
    for (const auto &key : mapNEVMTxRoots) {
        batch.Erase(key);
        auto it = mapCache.find(key);
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