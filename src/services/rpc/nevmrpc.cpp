// Copyright (c) 2013-2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <validation.h>
#include <node/blockstorage.h>
#include <rpc/util.h>
#include <services/nevmconsensus.h>
#include <chainparams.h>
#include <rpc/server.h>
#include <thread>
#include <policy/rbf.h>
#include <policy/policy.h>
#include <index/txindex.h>
#include <core_io.h>
#include <rpc/blockchain.h>
#include <node/context.h>
#include <node/transaction.h>
#include <rpc/server_util.h>
#include <interfaces/node.h>
#include <llmq/btc_header_policy.h>
#include <llmq/quorums_chainlocks.h>
#include <key_io.h>
#include <common/args.h>
#include <logging.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
using node::GetTransaction;

static RPCHelpMan getnevmblockchaininfo()
{
    return RPCHelpMan{"getnevmblockchaininfo",
        "\nReturn NEVM blockchain information and status.\n",
        {
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "bestblockhash", "The tip of the NEVM blockchain"},
                {RPCResult::Type::STR_HEX, "previousblockhash", "The hash of the previous block"},
                {RPCResult::Type::STR_HEX, "txroot", "Transaction root of the current tip"},
                {RPCResult::Type::STR_HEX, "receiptroot", "Receipt root of the current tip"},
                {RPCResult::Type::NUM, "blocksize", "Serialized NEVM block size. 0 means it has been pruned."},
                {RPCResult::Type::NUM, "height", "The current NEVM blockchain height"},
                {RPCResult::Type::STR, "commandline", "The NEVM command line parameters used to pass through to sysgeth"},
                {RPCResult::Type::STR, "status", "The NEVM status, online or offline"},
            }},
        RPCExamples{
            HelpExampleCli("getnevmblockchaininfo", "")
            + HelpExampleRpc("getnevmblockchaininfo", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    UniValue oNEVM(UniValue::VOBJ);
    CNEVMHeader evmBlock;
    BlockValidationState state;
    int nHeight;
    CBlock block;
    {
        LOCK(cs_main);
        auto *tip = chainman.ActiveChain().Tip();
        nHeight = tip->nHeight;
        auto *pblockindex = chainman.m_blockman.LookupBlockIndex(tip->GetBlockHash());
        if (!pblockindex) {
            throw JSONRPCError(RPC_MISC_ERROR, tip->GetBlockHash().ToString() + " not found");
        }
        if (chainman.m_blockman.IsBlockPruned(pblockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, tip->GetBlockHash().ToString() + " not available (pruned data)");
        }
        if (!chainman.m_blockman.ReadBlockFromDisk(block, *pblockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, tip->GetBlockHash().ToString() + " not found");
        }
        if(!GetNEVMData(state, block, evmBlock)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, state.ToString());
        }
    }
    const std::vector<std::string> cmdLine = chainman.GethCommandLine();
    std::vector<UniValue> vec;
    for(auto& cmd: cmdLine) {
        UniValue v;
        v.setStr(cmd);
        vec.push_back(v);
    }
    std::reverse (evmBlock.nBlockHash.begin (), evmBlock.nBlockHash.end ()); // correct endian
    oNEVM.pushKVEnd("bestblockhash", "0x" + evmBlock.nBlockHash.ToString());
    oNEVM.pushKVEnd("txroot", "0x" + evmBlock.nTxRoot.GetHex());
    oNEVM.pushKVEnd("receiptroot", "0x" + evmBlock.nReceiptRoot.GetHex());
    oNEVM.pushKVEnd("height", (nHeight - Params().GetConsensus().nNEVMStartBlock) + 1);
    oNEVM.pushKVEnd("blocksize", (int)block.vchNEVMBlockData.size());
    UniValue arrVec(UniValue::VARR);
    arrVec.push_backV(vec);
    oNEVM.pushKVEnd("commandline", arrVec);
    bool bResponse = false;
    GetMainSignals().NotifyNEVMComms("status", bResponse);
    oNEVM.pushKVEnd("status", bResponse? "online": "offline");
    return oNEVM;
},
    };
}

static RPCHelpMan getnevmblobdata()
{
    return RPCHelpMan{"getnevmblobdata",
        "\nReturn NEVM blob information and status from a version hash.\n",
        {
            {"versionhash_or_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte version hash digest or txid of the NEVM blob"},
            {"getdata", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Optional, retrieve the blob data"}
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
            HelpExampleCli("getnevmblobdata", "")
            + HelpExampleRpc("getnevmblobdata", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    bool bGetData = false;
    if(request.params.size() > 1) {
        bGetData = request.params[1].get_bool();
    }
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    CBlockIndex* pblockindex = nullptr;
    uint256 hashBlock;
    uint256 txhash = ParseHashV(request.params[0], "parameter 1");
    std::vector<uint8_t> vchVH;
    CNEVMData nevmData;
    CTransactionRef tx;
    {
        LOCK(cs_main);
        const Coin& coin = AccessByTxid(node.chainman->ActiveChainstate().CoinsTip(), txhash);
        if (!coin.IsSpent()) {
            pblockindex = node.chainman->ActiveChain()[coin.nHeight];
        }
        if (pblockindex == nullptr) {
            uint32_t nBlockHeight;
            if(pblockindexdb != nullptr && pblockindexdb->ReadBlockHeight(txhash, nBlockHeight)) {
                pblockindex = node.chainman->ActiveChain()[nBlockHeight];
            }
        }
        hashBlock.SetNull();
        if(pblockindex != nullptr) {
            tx = GetTransaction(pblockindex, nullptr, txhash, hashBlock, node.chainman->m_blockman);
        }
        if(!tx || hashBlock.IsNull()) {
            vchVH = ParseHex(request.params[0].get_str());
            if(vchVH.size() != NEVM_DATA_LEGACY_VERSIONHASH_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid version hash length");
            }
        }
        else {
            nevmData = CNEVMData(*tx);
            if(nevmData.IsNull()){
                throw JSONRPCError(RPC_INVALID_PARAMS, "Could not parse blob data from transaction");
            }
            vchVH = nevmData.vchVersionHash;
        }
    }

    UniValue oNEVM(UniValue::VOBJ);
    BlockValidationState state;
    MapPoDAPayloadMeta meta;
    if(!pnevmdatadb->GetBlobMetaData(vchVH, meta)) {
        throw JSONRPCError(RPC_INVALID_PARAMS, strprintf("Could not find blob information for versionhash %s", HexStr(vchVH)));
    }
    int64_t active_tip_mtp{0};
    {
        LOCK(cs_main);
        const CBlockIndex* active_tip{node.chainman->ActiveChain().Tip()};
        if (active_tip != nullptr) {
            active_tip_mtp = active_tip->GetMedianTimePast();
        }
    }
    // SYSCOIN: expiry is an active-chain query property even when ChainLocks
    // are temporarily unavailable. Keep the underlying bytes until a verified
    // ChainLock permits irreversible pruning so a reorg can expose them again.
    if (IsNEVMDataExpired(active_tip_mtp, meta.nMedianTime)) {
        throw JSONRPCError(RPC_INVALID_PARAMS, strprintf("Could not find blob information for versionhash %s", HexStr(vchVH)));
    }
    oNEVM.pushKVEnd("versionhash", HexStr(vchVH));
    oNEVM.pushKVEnd("mtp", meta.nMedianTime);
    oNEVM.pushKVEnd("datasize", meta.nSize);
    oNEVM.pushKVEnd("txid", meta.txid.GetHex());
    if(pblockindex != nullptr) {
        oNEVM.pushKVEnd("blockhash", pblockindex->GetBlockHash().GetHex());
        oNEVM.pushKVEnd("height", pblockindex->nHeight);
        if(llmq::chainLocksHandler)
            oNEVM.pushKV("chainlock", llmq::chainLocksHandler->HasChainLock(pblockindex->nHeight, pblockindex->GetBlockHash()));
    } else {
        {
            LOCK(cs_main);
            const Coin& coin = AccessByTxid(node.chainman->ActiveChainstate().CoinsTip(), meta.txid);
            if (!coin.IsSpent()) {
                pblockindex = node.chainman->ActiveChain()[coin.nHeight];
            }
            if (pblockindex == nullptr) {
                uint32_t nBlockHeight;
                if(pblockindexdb != nullptr && pblockindexdb->ReadBlockHeight(meta.txid, nBlockHeight)) {
                    pblockindex = node.chainman->ActiveChain()[nBlockHeight];
                }
            }
        }
        if(pblockindex != nullptr) {
            oNEVM.pushKVEnd("blockhash", pblockindex->GetBlockHash().GetHex());
            oNEVM.pushKVEnd("height", pblockindex->nHeight);
            if(llmq::chainLocksHandler)
                oNEVM.pushKV("chainlock", llmq::chainLocksHandler->HasChainLock(pblockindex->nHeight, pblockindex->GetBlockHash()));
        }
    }
    if(bGetData) {
        std::vector<uint8_t> vchData;
        if (!pnevmdatablobdb->Read(vchVH, vchData)) {
            throw JSONRPCError(RPC_INVALID_PARAMS, strprintf("Could not find data for versionhash %s", HexStr(vchVH)));
        }       
        oNEVM.pushKVEnd("data", HexStr(vchData));
    }
    return oNEVM;
},
    };
}


bool ScanBlobs(CNEVMDataDB& pnevmdatadb, const uint32_t count, const uint32_t from, const UniValue& oOptions, UniValue& oRes) {
    bool stats = false;

    if (!oOptions.isNull()) {
        const UniValue &statsObj = oOptions.find_value("stats");
        if (statsObj.isBool()) {
            stats = statsObj.get_bool();
        }
    }

    uint64_t totalSize = 0;
    uint64_t totalBlobs = 0;
    uint64_t oldest = UINT64_MAX;
    uint64_t newest = 0;
    LOCK(pnevmdatadb.cs_cache);
    const PoDAMAPMemory &cache = pnevmdatadb.GetCache();

    if (stats) {
        for (const auto& [key, val] : cache) {
            totalSize += val.nSize;
            totalBlobs++;
            oldest = std::min(oldest, static_cast<uint64_t>(val.nMedianTime));
            newest = std::max(newest, static_cast<uint64_t>(val.nMedianTime));         
        }

        std::unique_ptr<CDBIterator> pcursor(pnevmdatadb.NewIterator());
        pcursor->SeekToFirst();
        std::vector<uint8_t> vchVersionHash;
        while (pcursor->Valid()) {
            vchVersionHash.clear();
            if (pcursor->GetKey(vchVersionHash)) {
                if(cache.find(vchVersionHash) == cache.end()) {
                    MapPoDAPayloadMeta meta;
                    if(pcursor->GetValue(meta)) {
                        totalSize += meta.nSize;
                        totalBlobs++;
                        oldest = std::min(oldest, static_cast<uint64_t>(meta.nMedianTime));
                        newest = std::max(newest, static_cast<uint64_t>(meta.nMedianTime));    
                    }
                }
            }
            pcursor->Next();
        }

        UniValue oStats(UniValue::VOBJ);
        oStats.pushKV("total_blobs", totalBlobs);
        oStats.pushKV("total_size", totalSize);
        oStats.pushKV("oldest_mpt", oldest == UINT64_MAX ? 0 : oldest);
        oStats.pushKV("newest_mpt", newest);
        oRes.push_back(oStats);
        return true;
    }

    uint32_t index = 0;
    for (auto const& [key, val] : cache) {
        if (++index <= from) continue;

        UniValue oBlob(UniValue::VOBJ);
        oBlob.pushKV("versionhash", HexStr(key));
        oBlob.pushKV("mtp", val.nMedianTime);
        oBlob.pushKV("datasize", (uint32_t)val.nSize);
        oBlob.pushKV("txid", val.txid.ToString());
        oRes.push_back(oBlob);

        if (index >= count + from) return true;
    }

    std::unique_ptr<CDBIterator> pcursor(pnevmdatadb.NewIterator());
    pcursor->SeekToFirst();
    std::vector<uint8_t> vchVersionHash;
    while (pcursor->Valid()) {
        if (pcursor->GetKey(vchVersionHash)) {
            if(cache.find(vchVersionHash) == cache.end()) {
                if (++index <= from) { pcursor->Next(); continue; }
                UniValue oBlob(UniValue::VOBJ);
                MapPoDAPayloadMeta meta;
                if(pcursor->GetValue(meta)) {
                    oBlob.pushKV("versionhash", HexStr(vchVersionHash));
                    oBlob.pushKV("mtp", meta.nMedianTime);
                    oBlob.pushKV("datasize", meta.nSize);
                    oBlob.pushKV("txid", meta.txid.ToString());
                    oRes.push_back(oBlob);
                }
                if (index >= count + from) break;
            }
        }
        pcursor->Next();
    }

    return true;
}

static RPCHelpMan listnevmblobdata()
{
    return RPCHelpMan{"listnevmblobdata",
        "\nScan through all blobs or get blob statistics.\n",
        {
            {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "The number of results to return."},
            {"from", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of results to skip."},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "A json object with options to filter results.",
                {
                    {"stats", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Return statistics for all blobs (ignores count/from)"},
                }
            }
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "versionhash", "The version hash of the NEVM blob"},
                    {RPCResult::Type::NUM, "datasize", "Size of data blob in bytes"},
                    {RPCResult::Type::STR_HEX, "txid", "Transaction ID of the blob tx"},
                    {RPCResult::Type::NUM, "mtp", "Median timestamp of the blob"},
                }},
                {RPCResult::Type::OBJ, "(if stats=true)", "",
                {
                    {RPCResult::Type::NUM, "total_blobs", "Total number of blobs"},
                    {RPCResult::Type::NUM, "total_size", "Total size of all blobs in bytes"},
                    {RPCResult::Type::NUM, "oldest_mpt", "Median timestamp of the oldest blob"},
                    {RPCResult::Type::NUM, "newest_mpt", "Median timestamp of the newest blob"},
                }},
            },
        },
        RPCExamples{
            HelpExampleCli("listnevmblobdata", "0")
            + HelpExampleCli("listnevmblobdata", "10 10")
            + HelpExampleCli("listnevmblobdata", "0 0 '{\"stats\":true}'")
        },
        [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    const UniValue &params = request.params;
    UniValue options;
    uint32_t count = 10;
    uint32_t from = 0;
    if (params.size() > 0) {
        count = params[0].getInt<int>();
        if (count == 0) {
            count = 10;
        }
    }
    if (params.size() > 1) {
        from = params[1].getInt<int>();
    }
    if (params.size() > 2) {
        options = params[2];
    }
    UniValue oRes(UniValue::VARR);
    if (!ScanBlobs(*pnevmdatadb, count, from, options, oRes))
        throw JSONRPCError(RPC_MISC_ERROR, "Scan failed");
    // Extract into a sortable vector
    std::vector<UniValue> blobVec;
    for (size_t i = 0; i < oRes.size(); i++) {
        blobVec.push_back(oRes[i]);
    }

    // Sort by mtp
    std::sort(blobVec.begin(), blobVec.end(), [](const UniValue &a, const UniValue &b) {
        return a["mtp"].getInt<int64_t>() < b["mtp"].getInt<int64_t>();
    });

    // Reconstruct the sorted UniValue result
    UniValue sortedRes(UniValue::VARR);
    for (const auto& blob : blobVec) {
        sortedRes.push_back(blob);
    }

    return sortedRes;
},
    };
}


static RPCHelpMan syscoingetspvproof()
{
    return RPCHelpMan{"syscoingetspvproof",
    "\nReturns SPV proof for use with inter-chain transfers.\n",
    {
        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A transaction that is in the block"},
        {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "If specified, looks for txid in the block with this hash"}
    },
    RPCResult{
        RPCResult::Type::ANY, "proof", "JSON representation of merkle proof (transaction, coinbase, index, siblings, header, nevm_blockhash, ...)"},
    RPCExamples{""},
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    CBlockIndex* pblockindex = nullptr;
    uint256 hashBlock;
    uint256 txhash = ParseHashV(request.params[0], "parameter 1");
    UniValue res(UniValue::VOBJ);
    {
        LOCK(cs_main);
        if (!request.params[1].isNull()) {
            hashBlock = ParseHashV(request.params[1], "blockhash");
            pblockindex = node.chainman->m_blockman.LookupBlockIndex(hashBlock);
            if (!pblockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
        } else {
            const Coin& coin = AccessByTxid(node.chainman->ActiveChainstate().CoinsTip(), txhash);
            if (!coin.IsSpent()) {
                pblockindex = node.chainman->ActiveChain()[coin.nHeight];
            }
        }
        if (pblockindex == nullptr) {
            uint32_t nBlockHeight;
            if(pblockindexdb != nullptr && pblockindexdb->ReadBlockHeight(txhash, nBlockHeight)) {
                pblockindex = node.chainman->ActiveChain()[nBlockHeight];
            }
        }
    }

    // Allow txindex to catch up if we need to query it and before we acquire cs_main.
    if (g_txindex && !pblockindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    if(!pblockindex) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
    }
    CTransactionRef tx;
    hashBlock.SetNull();
    tx = GetTransaction(pblockindex, nullptr, txhash, hashBlock, node.chainman->m_blockman);
    if(!tx || hashBlock.IsNull())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");

    CBlock block;
    {
        LOCK(cs_main);
        if (node.chainman->m_blockman.IsBlockPruned(pblockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
        }
    }

    if (!node.chainman->m_blockman.ReadBlockFromDisk(block, *pblockindex)) {
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }
    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << pblockindex->GetBlockHeader(node.chainman->m_blockman);
    const std::string rawTx = EncodeHexTx(*tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    res.pushKVEnd("transaction",rawTx);
    // Witness-stripped coinbase for NEVM relay same-depth Merkle checks (GHSA-wg2x class).
    if (block.vtx.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block has no transactions");
    }
    res.pushKVEnd("coinbase", EncodeHexTx(*block.vtx[0], PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS));
    res.pushKVEnd("blockhash", hashBlock.GetHex());
    const auto bytesVec = MakeUCharSpan(ssBlock);
    // get first 80 bytes of header (non auxpow part)
    res.pushKVEnd("header", HexStr(std::vector<unsigned char>(bytesVec.begin(), bytesVec.begin()+80)));
    UniValue siblings(UniValue::VARR);
    // store the index of the transaction we are looking for within the block
    int nIndex = 0;
    for (unsigned int i = 0;i < block.vtx.size();i++) {
        const uint256 &txHashFromBlock = block.vtx[i]->GetHash();
        if(txhash == txHashFromBlock)
            nIndex = i;
        siblings.push_back(txHashFromBlock.GetHex());
    }
    res.pushKVEnd("siblings", siblings);
    res.pushKVEnd("index", nIndex);
    CNEVMHeader evmBlock;
    BlockValidationState state;
    if(!GetNEVMData(state, block, evmBlock)) {
        throw JSONRPCError(RPC_MISC_ERROR, state.ToString());
    }
    std::reverse (evmBlock.nBlockHash.begin (), evmBlock.nBlockHash.end ()); // correct endian
    res.pushKVEnd("nevm_blockhash", evmBlock.nBlockHash.GetHex());
    // SYSCOIN
    if(llmq::chainLocksHandler)
        res.pushKVEnd("chainlock", llmq::chainLocksHandler->HasChainLock(pblockindex->nHeight, hashBlock));
    return res;
},
    };
}

static RPCHelpMan syscoinstopgeth()
{
    return RPCHelpMan{"syscoinstopgeth",
    "\nStops Geth from running.\n",
    {},
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "status", "Result"},
        }},
    RPCExamples{
        HelpExampleCli("syscoinstopgeth", "")
        + HelpExampleRpc("syscoinstopgeth", "")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if(!chainman.ActiveChainstate().StopGethNode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Could not stop Geth");
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKVEnd("status", "success");
    return ret;
},
    };
}

static RPCHelpMan syscoinstartgeth()
{
    return RPCHelpMan{"syscoinstartgeth",
    "\nStarts Geth.\n",
    {},
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "status", "Result"},
        }},
    RPCExamples{
        HelpExampleCli("syscoinstartgeth", "")
        + HelpExampleRpc("syscoinstartgeth", "")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if(!chainman.ActiveChainstate().RestartGethNode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Could not restart geth, see debug.log for more information...");
    }
    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKVEnd("status", "success");
    return ret;
},
    };
}

static RPCHelpMan syscoinstopbtcheadernode()
{
    return RPCHelpMan{"syscoinstopbtcheadernode",
    "\nStops the dedicated managed Bitcoin headers-only node.\n",
    {},
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "status", "Result"},
        }},
    RPCExamples{
        HelpExampleCli("syscoinstopbtcheadernode", "")
        + HelpExampleRpc("syscoinstopbtcheadernode", "")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    if (!gArgs.GetBoolArg("-btcheadermanaged", DEFAULT_BTC_HEADER_MANAGED)) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Managed Bitcoin headers are disabled; an external backend is not "
            "owned by Syscoin and cannot be stopped by this RPC");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.ActiveChainstate().StopBTCHeaderNode()) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Could not stop the managed Bitcoin header node");
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKVEnd("status", "success");
    return ret;
},
    };
}

static bool BTCHeaderChainInfoReady(const UniValue& chain_info, bool managed,
                                    std::string& error)
{
    if (!chain_info.isObject()) {
        error = "btcheader-invalid-chaininfo";
        return false;
    }
    const UniValue& chain{chain_info.find_value("chain")};
    const UniValue& headers_only{chain_info.find_value("headersonly")};
    if (!chain.isStr() || chain.get_str() != Params().GetChainTypeString()) {
        error = "btcheader-wrong-chain";
        return false;
    }
    if (managed &&
        (!headers_only.isBool() || !headers_only.get_bool())) {
        error = "btcheader-managed-endpoint-not-headers-only";
        return false;
    }
    error.clear();
    return true;
}

static RPCHelpMan syscoinstartbtcheadernode()
{
    return RPCHelpMan{"syscoinstartbtcheadernode",
    "\nStarts or restarts the dedicated managed Bitcoin headers-only node and waits for RPC readiness.\n",
    {},
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "status", "Result"},
        }},
    RPCExamples{
        HelpExampleCli("syscoinstartbtcheadernode", "")
        + HelpExampleRpc("syscoinstartbtcheadernode", "")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    if (!gArgs.GetBoolArg("-btcheadermanaged", DEFAULT_BTC_HEADER_MANAGED)) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Managed Bitcoin headers are disabled; configure and operate the "
            "external backend independently");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.ActiveChainstate().RestartBTCHeaderNode()) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Could not start the managed Bitcoin header node; see debug.log");
    }

    const int64_t timeout{std::clamp<int64_t>(
        gArgs.GetIntArg("-btcheaderstartuptimeout", 30), 1, 300)};
    const auto deadline{SteadyClock::now() + std::chrono::seconds{timeout}};
    std::string error;
    do {
        UniValue chain_info;
        if (llmq::pq::RunConfiguredBTCHeaderCommand(
                {"getblockchaininfo"}, chain_info, error) &&
            BTCHeaderChainInfoReady(chain_info, /*managed=*/true, error)) {
            UniValue ret(UniValue::VOBJ);
            ret.pushKVEnd("status", "success");
            return ret;
        }
        UninterruptibleSleep(std::chrono::milliseconds{200});
    } while (SteadyClock::now() < deadline);

    chainman.ActiveChainstate().StopBTCHeaderNode(/*bOnStart=*/true);
    throw JSONRPCError(
        RPC_MISC_ERROR,
        strprintf("Managed Bitcoin header RPC did not become ready: %s", error));
},
    };
}

static RPCHelpMan syscoinbtcheaderstatus()
{
    return RPCHelpMan{"syscoinbtcheaderstatus",
    "\nReturns Bitcoin-header policy backend process and RPC readiness without changing lifecycle state.\n",
    {},
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::BOOL, "managed", "Whether the dedicated managed backend mode is configured"},
            {RPCResult::Type::BOOL, "process_running", "Whether the managed process is running"},
            {RPCResult::Type::BOOL, "policy_healthy", "Whether watchdog progress and chain-view checks pass"},
            {RPCResult::Type::BOOL, "ready", "Whether the bounded RPC probe succeeded"},
            {RPCResult::Type::STR, "reason", /*optional=*/true, "Readiness failure reason"},
            {RPCResult::Type::ANY, "chaininfo", /*optional=*/true, "Backend getblockchaininfo response"},
        }},
    RPCExamples{
        HelpExampleCli("syscoinbtcheaderstatus", "")
        + HelpExampleRpc("syscoinbtcheaderstatus", "")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const bool managed{
        gArgs.GetBoolArg("-btcheadermanaged", DEFAULT_BTC_HEADER_MANAGED)};
    bool process_running{true};
    std::string reason;
    if (managed) {
        process_running =
            chainman.ActiveChainstate().IsManagedBTCHeaderNodeRunning(reason);
    }

    // SYSCOIN: A responsive but frozen Bitcoin tip is not BTCC-ready. Reuse
    // the non-recovering watchdog check so status exposes persisted
    // no-progress/eclipse failures without restarting the managed child.
    std::string health_reason;
    const bool policy_healthy{process_running &&
        chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
            /*recover=*/false, health_reason)};
    if (!policy_healthy && reason.empty()) reason = health_reason;

    UniValue chain_info;
    std::string rpc_error;
    const bool ready{process_running && policy_healthy &&
        llmq::pq::RunConfiguredBTCHeaderCommand(
            {"getblockchaininfo"}, chain_info, rpc_error) &&
        BTCHeaderChainInfoReady(chain_info, managed, rpc_error)};
    if (!ready && reason.empty()) {
        reason = rpc_error.empty() ? "btcheader-invalid-chaininfo" : rpc_error;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("managed", managed);
    ret.pushKV("process_running", process_running);
    ret.pushKV("policy_healthy", policy_healthy);
    ret.pushKV("ready", ready);
    if (!reason.empty()) ret.pushKV("reason", reason);
    if (ready) ret.pushKV("chaininfo", std::move(chain_info));
    return ret;
},
    };
}

// clang-format on
void RegisterNEVMRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"syscoin", &syscoingetspvproof},
        {"syscoin", &listnevmblobdata},
        {"syscoin", &syscoinstopgeth},
        {"syscoin", &syscoinstartgeth},
        {"syscoin", &syscoinstopbtcheadernode},
        {"syscoin", &syscoinstartbtcheadernode},
        {"syscoin", &syscoinbtcheaderstatus},
        {"syscoin", &getnevmblockchaininfo},
        {"syscoin", &getnevmblobdata},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
