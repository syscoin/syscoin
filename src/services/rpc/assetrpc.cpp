// Copyright (c) 2013-2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <validation.h>
#include <node/blockstorage.h>
#include <rpc/util.h>
#include <services/assetconsensus.h>
#include <services/rpc/assetrpc.h>
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
#include <llmq/quorums_chainlocks.h>
#include <key_io.h>
#include <common/args.h>
#include <logging.h>
using node::GetTransaction;
extern RecursiveMutex cs_setethstatus;

int CheckActorsInTransactionGraph(const CTxMemPool& mempool, const uint256& lookForTxHash) {
    LOCK(cs_main);
    LOCK(mempool.cs);
    {
        CTxMemPool::setEntries setAncestors;
        const CTransactionRef txRef = mempool.get(lookForTxHash);
        if (!txRef)
            return ZDAG_NOT_FOUND;
        if(!IsZdagTx(txRef->nVersion))
            return ZDAG_WARNING_NOT_ZDAG_TX;
        // the zdag tx should be under MTU of IP packet
        if(txRef->GetTotalSize() > MAX_STANDARD_ZDAG_TX_SIZE)
            return ZDAG_WARNING_SIZE_OVER_POLICY;
        // check if any inputs are dbl spent, reject if so
        if(mempool.existsConflicts(*txRef))
            return ZDAG_MAJOR_CONFLICT;        

        // check this transaction isn't RBF enabled
        RBFTransactionState rbfState = IsRBFOptIn(*txRef, mempool, setAncestors);
        if (rbfState == RBFTransactionState::UNKNOWN)
            return ZDAG_NOT_FOUND;
        else if (rbfState == RBFTransactionState::REPLACEABLE_BIP125)
            return ZDAG_WARNING_RBF;
        for (CTxMemPool::txiter it : setAncestors) {
            const CTransactionRef& ancestorTxRef = it->GetSharedTx();
            // should be under MTU of IP packet
            if(ancestorTxRef->GetTotalSize() > MAX_STANDARD_ZDAG_TX_SIZE)
                return ZDAG_WARNING_SIZE_OVER_POLICY;
            // check if any ancestor inputs are dbl spent, reject if so
            if(mempool.existsConflicts(*ancestorTxRef))
                return ZDAG_MAJOR_CONFLICT;
            if(!IsZdagTx(ancestorTxRef->nVersion))
                return ZDAG_WARNING_NOT_ZDAG_TX;
        }  
    }
    return ZDAG_STATUS_OK;
}

int VerifyTransactionGraph(const CTxMemPool& mempool, const uint256& lookForTxHash) {  
    int status = CheckActorsInTransactionGraph(mempool, lookForTxHash);
    if(status != ZDAG_STATUS_OK){
        return status;
    }
	return ZDAG_STATUS_OK;
}

static RPCHelpMan assetallocationverifyzdag()
{
    return RPCHelpMan{"assetallocationverifyzdag",
        "\nShow status as it pertains to any current Z-DAG conflicts or warnings related to a ZDAG transaction.\n"
        "Return value is in the status field and can represent 3 levels(0, 1 or 2)\n"
        "Level -1 means not found, not a ZDAG transaction, perhaps it is already confirmed.\n"
        "Level 0 means OK.\n"
        "Level 1 means warning (checked that in the mempool there are more spending balances than current POW sender balance). An active stance should be taken and perhaps a deeper analysis as to potential conflicts related to the sender.\n"
        "Level 2 means an active double spend was found and any depending asset allocation sends are also flagged as dangerous and should wait for POW confirmation before proceeding.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id of the ZDAG transaction."}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "status", "The status level of the transaction"},
            }}, 
        RPCExamples{
            HelpExampleCli("assetallocationverifyzdag", "\"txid\"")
            + HelpExampleRpc("assetallocationverifyzdag", "\"txid\"")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
	const UniValue &params = request.params;
    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
	uint256 txid;
	txid.SetHex(params[0].get_str());
	UniValue oAssetAllocationStatus(UniValue::VOBJ);
    oAssetAllocationStatus.pushKV("status", VerifyTransactionGraph(mempool, txid));
	return oAssetAllocationStatus;
},
    };
}

static RPCHelpMan syscoindecoderawtransaction()
{
    return RPCHelpMan{"syscoindecoderawtransaction",
    "\nDecode raw syscoin transaction (serialized, hex-encoded) and display information pertaining to the service that is included in the transactiion data output(OP_RETURN)\n",
    {
        {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string."}
    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "txtype", "The syscoin transaction type"},
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            {RPCResult::Type::STR_HEX, "blockhash", "Block confirming the transaction, if any"},
            {RPCResult::Type::ARR, "allocations", "(array of json receiver objects)",
                {
                    {RPCResult::Type::OBJ, "receiverObj", /*optional=*/true, "",
                        {
                            {RPCResult::Type::NUM, "asset_guid", "Asset guid"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "Value"}
                    }},
                }},
            {RPCResult::Type::STR, "nevm_destination", /*optional=*/true, "NEVM destination address"},
        }}, 
    RPCExamples{
        HelpExampleCli("syscoindecoderawtransaction", "\"hexstring\"")
        + HelpExampleRpc("syscoindecoderawtransaction", "\"hexstring\"")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    const UniValue &params = request.params;
    const node::NodeContext& node = EnsureAnyNodeContext(request.context);

    std::string hexstring = params[0].get_str();
    CMutableTransaction tx;
    if(!DecodeHexTx(tx, hexstring, false, true)) {
        if(!DecodeHexTx(tx, hexstring, true, true)) {
             throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Could not decode transaction");
        }
    }
    CTransactionRef rawTx(MakeTransactionRef(std::move(tx)));
    if (rawTx->IsNull())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Could not decode transaction");

    CBlockIndex* blockindex = nullptr;
    uint256 hashBlock;
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    // block may not be found
    rawTx = GetTransaction(blockindex, node.mempool.get(), rawTx->GetHash(), hashBlock, node.chainman->m_blockman);

    UniValue output(UniValue::VOBJ);
    if(rawTx && !DecodeSyscoinRawtransaction(*rawTx, output))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Not a Syscoin transaction");
    return output;
},
    };
}

static RPCHelpMan syscoingettxroots()
{
    return RPCHelpMan{"syscoingettxroots",
    "\nGet NEVM transaction and receipt roots based on block hash.\n",
    {
        {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to lookup."}
    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txroot", "The transaction merkle root"},
            {RPCResult::Type::STR_HEX, "receiptroot", "The receipt merkle root"},
        }},
    RPCExamples{
        HelpExampleCli("syscoingettxroots", "0xd8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10")
        + HelpExampleRpc("syscoingettxroots", "0xd8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_setethstatus);
    std::string blockHashStr = request.params[0].get_str();
    blockHashStr = RemovePrefix(blockHashStr, "0x");  // strip 0x
    uint256 nBlockHash;
    if(!ParseHashStr(blockHashStr, nBlockHash)) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Could not read block hash");
    }
    NEVMTxRoot txRootDB;
    if(!pnevmtxrootsdb || !pnevmtxrootsdb->ReadTxRoots(nBlockHash, txRootDB)){
       throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Could not read transaction roots");
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("blockhash", nBlockHash.GetHex());
    ret.pushKV("txroot", txRootDB.nTxRoot.GetHex());
    ret.pushKV("receiptroot", txRootDB.nReceiptRoot.GetHex());

    return ret;
},
    };
}

static RPCHelpMan syscoincheckmint()
{
    return RPCHelpMan{"syscoincheckmint",
    "\nGet the Syscoin mint transaction by looking up using NEVM tx hash (This is no the txid, it is the sha3 of the transaction bytes value).\n",
    {
        {"nevm_txhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "NEVM Tx Hash used to burn funds to move to Syscoin."}
    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
        }},
    RPCExamples{
        HelpExampleCli("syscoincheckmint", "d8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10")
        + HelpExampleRpc("syscoincheckmint", "d8ac75c7b4084c85a89d6e28219ff162661efb8b794d4b66e6e9ea52b4139b10")
    },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::string strTxHash = request.params[0].get_str();
    strTxHash = RemovePrefix(strTxHash, "0x");  // strip 0x
    uint256 sysTxid;
    if(!pnevmtxmintdb || !pnevmtxmintdb->Read(uint256S(strTxHash), sysTxid)){
       throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Could not read Syscoin txid using mint transaction hash");
    }
    UniValue output(UniValue::VOBJ);
    output.pushKV("txid", sysTxid.GetHex());
    return output;
},
    };
}

// clang-format on
void RegisterAssetRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"syscoin", &syscoingettxroots},
        {"syscoin", &syscoindecoderawtransaction},
        {"syscoin", &assetallocationverifyzdag},
        {"syscoin", &syscoincheckmint},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
