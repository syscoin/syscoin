// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_ASSETCONSENSUS_H
#define SYSCOIN_SERVICES_ASSETCONSENSUS_H
#include <primitives/transaction.h>
#include <dbwrapper.h>
#include <consensus/params.h>
class TxValidationState;
class CTxUndo;
class CBlock;
class CNEVMTxRootsDB : public CDBWrapper {
    NEVMTxRootMap mapCache;
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const std::vector<uint256> &vecBlockHashes);
    bool ReadTxRoots(const uint256& nBlockHash, NEVMTxRoot& txRoot);
    bool FlushCacheToDisk();
    void FlushDataToCache(const NEVMTxRootMap &mapNEVMTxRoots);
};

class CNEVMMintedTxDB : public CDBWrapper {
    NEVMMintTxMap mapCache;
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const NEVMMintTxMap &mapMintKeys);
    bool FlushWrite(const NEVMMintTxMap &mapMintKeys);
    bool FlushCacheToDisk();
    void FlushDataToCache(const NEVMMintTxMap &mapNEVMTxRoots);
    bool ExistsTx(const uint256& nTxHash);
};

extern std::unique_ptr<CNEVMTxRootsDB> pnevmtxrootsdb;
extern std::unique_ptr<CNEVMMintedTxDB> pnevmtxmintdb;
bool DisconnectMintAsset(const CTransaction &tx, const uint256& txHash, NEVMMintTxMap &mapMintKeys);
bool CheckSyscoinMint(const bool &ibd, const CTransaction& tx, const uint256& txHash, TxValidationState &tstate, const bool &fJustCheck, const bool& bSanityCheck, const uint32_t& nHeight, const int64_t& nTime, const uint256& blockhash, NEVMMintTxMap &mapMintKeys, CAssetsMap &mapAssetIn, CAssetsMap &mapAssetOut);
bool CheckSyscoinInputs(const CTransaction& tx, const Consensus::Params& params, const uint256& txHash, TxValidationState &tstate, const uint32_t &nHeight, const int64_t& nTime, NEVMMintTxMap &mapMintKeys, const bool &bSanityCheck, CAssetsMap& mapAssetIn, CAssetsMap& mapAssetOut);
bool CheckSyscoinInputs(const bool &ibd, const Consensus::Params& params, const CTransaction& tx,  const uint256& txHash, TxValidationState &tstate, const bool &fJustCheck, const uint32_t &nHeight, const int64_t& nTime, const uint256 & blockHash, const bool &bSanityCheck, NEVMMintTxMap &mapMintKeys, CAssetsMap& mapAssetIn, CAssetsMap& mapAssetOut);
bool CheckAssetAllocationInputs(const CTransaction &tx, const uint256& txHash, TxValidationState &tstate, const bool &fJustCheck, const uint32_t &nHeight, const uint256& blockhash, const bool &bSanityCheck, CAssetsMap &mapAssetIn, CAssetsMap &mapAssetOut);
std::string stringFromSyscoinTx(const int &nVersion);
#endif // SYSCOIN_SERVICES_ASSETCONSENSUS_H
