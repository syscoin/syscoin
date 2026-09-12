// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>

#include <chainparams.h>
#include <index/txindex.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <span.h>
#include <txdb.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cstddef>

static RPCHelpMan gettxchainlocks()
{
    return RPCHelpMan{
        "gettxchainlocks",
        "\nReturns the block height at which each transaction was mined, and "
        "indicates whether it is in the mempool, ChainLocked, or neither.\n",
        {
            {"txids", RPCArg::Type::ARR, RPCArg::Optional::NO,
             "The transaction ids (no more than 100)",
             {{"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
               "A transaction hash"}}},
        },
        RPCResult{RPCResult::Type::ARR, "",
                  "Response is an array with the same size as the input txids",
                  {{RPCResult::Type::OBJ, "", "",
                    {{RPCResult::Type::NUM, "height", "The block height"},
                     {RPCResult::Type::BOOL, "chainlock",
                      "Whether the corresponding block is ChainLocked"},
                     {RPCResult::Type::BOOL, "mempool",
                      "Whether the transaction is in the mempool"}}}}},
        RPCExamples{HelpExampleCli("gettxchainlocks", "'[\"mytxid\",...]'") +
                    HelpExampleRpc("gettxchainlocks", "[\"mytxid\",...]")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            const node::NodeContext& node = EnsureAnyNodeContext(request.context);
            const ChainstateManager& chainman = EnsureChainman(node);
            const UniValue txids{request.params[0].get_array()};
            if (txids.size() > 100) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Up to 100 txids only");
            }
            if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();

            UniValue results{UniValue::VARR};
            LOCK(cs_main);
            for (size_t index{0}; index < txids.size(); ++index) {
                UniValue result{UniValue::VOBJ};
                const uint256 txid{ParseHashV(txids[index], "txid")};
                if (txid == Params().GenesisBlock().hashMerkleRoot) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "The genesis block coinbase is not an ordinary transaction");
                }

                uint32_t block_height{0};
                const CBlockIndex* block_index{nullptr};
                if (pblockindexdb->ReadBlockHeight(txid, block_height)) {
                    block_index = chainman.ActiveChain()[block_height];
                }
                uint256 block_hash;
                const auto tx = GetTransaction(block_index, node.mempool.get(), txid,
                                               block_hash,
                                               chainman.m_blockman);
                if (!tx) {
                    result.pushKV("height", 0);
                    result.pushKV("chainlock", false);
                    result.pushKV("mempool", false);
                } else {
                    result.pushKV("height", block_height);
                    result.pushKV(
                        "chainlock",
                        block_index && llmq::chainLocksHandler &&
                            llmq::chainLocksHandler->HasChainLock(
                                block_height, block_hash));
                    result.pushKV("mempool", block_index == nullptr);
                }
                results.push_back(result);
            }
            return results;
        }};
}

static RPCHelpMan getbestchainlock()
{
    return RPCHelpMan{
        "getbestchainlock",
        "\nReturns the best verified post-quantum ChainLock.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "",
                  {{RPCResult::Type::STR_HEX, "blockhash", "Block hash"},
                   {RPCResult::Type::NUM, "height", "Block height"},
                   {RPCResult::Type::STR_HEX, "logicalid", "Statement identifier"},
                   {RPCResult::Type::STR_HEX, "witnessid", "Certificate identifier"},
                   {RPCResult::Type::NUM, "previous_height", "Predecessor height"},
                   {RPCResult::Type::STR_HEX, "previous_blockhash", "Predecessor hash"},
                   {RPCResult::Type::STR_HEX, "quorum_context_hash", "Quorum context"},
                   {RPCResult::Type::NUM, "selected_quorum_mask", "Selected quorum slots"},
                   {RPCResult::Type::ARR, "signer_bitmaps", "Signer bitmaps",
                    {{RPCResult::Type::STR_HEX, "", "Signer bitmap"}}},
                   {RPCResult::Type::NUM, "signature_count", "Child signature count"},
                   {RPCResult::Type::OBJ, "accepted_btcc_cursor", "Accepted BTC cursor",
                    {{RPCResult::Type::NUM, "sysheight", "Syscoin candidate height"},
                     {RPCResult::Type::STR_HEX, "syshash", "Syscoin candidate hash"},
                     {RPCResult::Type::STR_HEX, "btchash", "Bitcoin parent hash"}}},
                   {RPCResult::Type::STR, "btcc_advance", "keep or advance"},
                   {RPCResult::Type::BOOL, "known_block", "Whether the block is known"}}},
        RPCExamples{HelpExampleCli("getbestchainlock", "") +
                    HelpExampleRpc("getbestchainlock", "")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            const node::NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            const auto chainlock = llmq::chainLocksHandler
                ? llmq::chainLocksHandler->GetBestChainLock()
                : nullptr;
            if (!chainlock) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "Unable to find any ChainLock");
            }

            const uint256& genesis_hash{chainman.GetConsensus().hashGenesisBlock};
            UniValue result{UniValue::VOBJ};
            result.pushKV("blockhash", chainlock->statement.block_hash.GetHex());
            result.pushKV("height", chainlock->statement.height);
            result.pushKV("logicalid", chainlock->GetLogicalId(genesis_hash).GetHex());
            result.pushKV("witnessid", chainlock->GetWitnessId(genesis_hash).GetHex());
            result.pushKV("previous_height",
                          chainlock->statement.previous_chainlock_height);
            result.pushKV("previous_blockhash",
                          chainlock->statement.previous_chainlock_hash.GetHex());
            result.pushKV("quorum_context_hash",
                          chainlock->statement.quorum_context_hash.GetHex());
            result.pushKV("selected_quorum_mask",
                          static_cast<uint64_t>(chainlock->selected_quorum_mask));
            UniValue signer_bitmaps{UniValue::VARR};
            for (const auto& bitmap : chainlock->signer_bitmaps) {
                signer_bitmaps.push_back(HexStr(Span{bitmap}));
            }
            result.pushKV("signer_bitmaps", signer_bitmaps);
            result.pushKV("signature_count",
                          static_cast<uint64_t>(chainlock->signatures.size()));

            UniValue cursor{UniValue::VOBJ};
            cursor.pushKV("sysheight",
                          chainlock->statement.accepted_btcc_cursor.sys_height);
            cursor.pushKV("syshash",
                          chainlock->statement.accepted_btcc_cursor.sys_hash.GetHex());
            cursor.pushKV("btchash",
                          chainlock->statement.accepted_btcc_cursor.btc_hash.GetHex());
            result.pushKV("accepted_btcc_cursor", cursor);
            result.pushKV(
                "btcc_advance",
                chainlock->statement.btcc_advance == llmq::pq::BTCCAdvance::ADVANCE
                    ? "advance"
                    : "keep");
            {
                LOCK(cs_main);
                result.pushKV(
                    "known_block",
                    chainman.m_blockman.LookupBlockIndex(
                        chainlock->statement.block_hash) != nullptr);
            }
            return result;
        }};
}

void RegisterQuorumsRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"evo", &getbestchainlock},
        {"evo", &gettxchainlocks},
    };
    for (const auto& command : commands) table.appendCommand(command.name, &command);
}
