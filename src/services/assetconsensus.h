// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_ASSETCONSENSUS_H
#define SYSCOIN_SERVICES_ASSETCONSENSUS_H
#include <primitives/transaction.h>
#include <dbwrapper.h>
#include <consensus/params.h>
#include <util/hasher.h>
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
    NEVMMintTxSet mapCache;
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const NEVMMintTxSet &setMintTxs);
    bool FlushWrite(const NEVMMintTxSet &setMintTxs);
    bool FlushCacheToDisk();
    void FlushDataToCache(const NEVMMintTxSet &mapNEVMTxRoots);
    bool ExistsTx(const uint256& nTxHash);
};

extern std::unique_ptr<CNEVMTxRootsDB> pnevmtxrootsdb;
extern std::unique_ptr<CNEVMMintedTxDB> pnevmtxmintdb;
bool DisconnectMintAsset(const CTransaction &tx, NEVMMintTxSet &setMintTxs);
bool CheckSyscoinMint(const CTransaction& tx, 
    const uint256& txHash,
    TxValidationState &tstate,
    const uint32_t& nHeight, 
    const bool &fJustCheck, 
    NEVMMintTxSet &setMintTxs, 
    CAssetsMap &mapAssetIn, 
    CAssetsMap &mapAssetOut);
bool CheckSyscoinMintInternal(const CMintSyscoin &mintSyscoin,
    TxValidationState &state,
    const bool &fJustCheck,
    NEVMMintTxSet &setMintTxs,
    uint64_t &nAssetFromLog,
    CAmount &outputAmount,
    std::string &witnessAddress);
bool CheckSyscoinInputs(const Consensus::Params& params, 
    const CTransaction& tx, 
    const uint256& txHash, 
    TxValidationState &tstate, 
    const uint32_t &nHeight, 
    const bool &fJustCheck, 
    NEVMMintTxSet &setMintTxs, 
    CAssetsMap& mapAssetIn, 
    CAssetsMap& mapAssetOut);
bool CheckAssetAllocationInputs(const CTransaction &tx, 
    const uint256& txHash, 
    TxValidationState &tstate, 
    const uint32_t &nHeight, 
    const bool &fJustCheck, 
    CAssetsMap &mapAssetIn, 
    CAssetsMap &mapAssetOut);
std::string stringFromSyscoinTx(const int &nVersion);
#endif // SYSCOIN_SERVICES_ASSETCONSENSUS_H
