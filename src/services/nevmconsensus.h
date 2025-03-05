// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_NEVMCONSENSUS_H
#define SYSCOIN_SERVICES_NEVMCONSENSUS_H
#include <primitives/transaction.h>
#include <dbwrapper.h>
#include <consensus/params.h>
class TxValidationState;
class CCoinsViewCache;
class CTxUndo;
class CBlock;
class BlockValidationState;
class CBlockIndexDB;
class CNEVMData;

class CNEVMDataDB : public CDBWrapper {
private:
    PoDAMAP mapCache;
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const NEVMDataVec &vecDataKeys);
    bool FlushEraseMTPs(const NEVMDataVec &vecDataKeys);
    bool FlushCacheToDisk();
    void FlushDataToCache(const PoDAMAPMemory &mapPoDA, const int64_t &nMedianTime);
    bool ReadData(const std::vector<uint8_t>& nVersionHash, std::vector<uint8_t>& vchData);
    bool ReadDataSize(const std::vector<uint8_t>& nVersionHash, uint32_t &nSize);
    bool ReadMTP(const std::vector<uint8_t>& nVersionHash, int64_t &nMedianTime);
    bool Prune(int64_t nMedianTime);
    bool BlobExists(const std::vector<uint8_t>& vchVersionhash);
    const PoDAMAP& GetMapCache() const { return mapCache;}
};
extern std::unique_ptr<CNEVMDataDB> pnevmdatadb;
bool DisconnectSyscoinTransaction(const CTransaction& tx, const uint256& txHash, const CTxUndo& txundo, CCoinsViewCache& view, AssetMap &mapAssets, NEVMMintTxMap &mapMintKeys, NEVMDataVec &NEVMDataVecOut);
#endif // SYSCOIN_SERVICES_NEVMCONSENSUS_H
