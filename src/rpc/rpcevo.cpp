// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <chainparams.h>
#include <core_io.h>
#include <evo/pq_registry.h>
#include <init.h>
#include <rpc/server.h>
#include <util/moneystr.h>
#include <validation.h>

#include <evo/deterministicmns.h>

#include <masternode/masternodemeta.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <node/context.h>
#include <rpc/server_util.h>
#include <index/txindex.h>
UniValue BuildDMNListEntry(
    const node::NodeContext& node,
    const CDeterministicMN& dmn,
    bool detailed,
    const llmq::pq::PQPaymentProbationStateView* payment_state = nullptr)
{
    if (!detailed) {
        return dmn.proTxHash.ToString();
    }
    UniValue o(UniValue::VOBJ);

    dmn.ToJson(*node.chain, o);
    std::map<COutPoint, Coin> coins;
    coins[dmn.collateralOutpoint]; 
    node.chain->findCoins(coins);
    int confirmations = 0;
    const Coin &coin = coins.at(dmn.collateralOutpoint);
    if (!coin.IsSpent()) {
        confirmations = *node.chain->getHeight() - coin.nHeight;
    }
    o.pushKV("confirmations", confirmations);
    auto metaInfo = mmetaman->GetMetaInfo(dmn.proTxHash);
    o.pushKV("metaInfo", metaInfo->ToJson());
    if (payment_state != nullptr) {
        UniValue payment_audit{UniValue::VOBJ};
        payment_audit.pushKV(
            "consecutiveMisses",
            static_cast<int>(payment_state->MissCount(dmn.proTxHash)));
        payment_audit.pushKV(
            "paymentWithheld",
            payment_state->IsPaymentWithheld(dmn.proTxHash));
        payment_audit.pushKV(
            "paymentEligibleSinceHeight",
            payment_state->PaymentEligibleSinceHeight(dmn.proTxHash));
        o.pushKV("paymentAudit", std::move(payment_audit));
    }

    return o;
}

static RPCHelpMan protx_list()
{
    return RPCHelpMan{"protx_list",
        "\nLists all ProTxs on-chain, depending on the given type.\n"
        "This will also include ProTx which failed PoSe verification.\n",
        {
             {"type", RPCArg::Type::STR, RPCArg::Default{"registered"},
            "\nAvailable types:\n"
            "  registered   - List all ProTx which are registered at the given chain height.\n"
            "                 This will also include ProTx which failed PoSe verification.\n"
            "  valid        - List only ProTx which are active/valid at the given chain height.\n"},
            {"detailed", RPCArg::Type::BOOL,  RPCArg::Default{false}, "If true, only the hashes of the ProTx will be returned."},
            {"height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Height to look for ProTx transactions, if not specified defaults to current chain-tip"},                   
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("protx_list", "registered true")
            + HelpExampleRpc("protx_list", "\"registered\", true")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{

    const node::NodeContext& node = EnsureAnyNodeContext(request.context);
    std::string type = "registered";
    if (!request.params[0].isNull()) {
        type = request.params[0].get_str();
    }

    UniValue ret(UniValue::VARR);
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    if (type == "valid" || type == "registered") {
        CDeterministicMNList mnList;
        llmq::pq::PQPaymentProbationStateView payment_state;
        bool detailed = !request.params[1].isNull() ? request.params[1].get_bool() : false;
        {
            LOCK(cs_main);
            int height = !request.params[2].isNull() ? request.params[2].getInt<int>() : node.chainman->ActiveHeight();
            if (height < 1 || height > node.chainman->ActiveHeight()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");
            }
            const CBlockIndex* index{node.chainman->ActiveChain()[height]};
            mnList = deterministicMNManager->GetListForBlock(index);
            if (detailed &&
                !deterministicMNManager->GetPaymentProbationStateView(
                    index, payment_state)) {
                throw JSONRPCError(
                    RPC_INTERNAL_ERROR,
                    "payment audit state is unavailable at requested height");
            }
        }
        bool onlyValid = type == "valid";
        mnList.ForEachMN(onlyValid, [&](const auto& dmn) {
            ret.push_back(BuildDMNListEntry(
                node, dmn, detailed,
                detailed ? &payment_state : nullptr));
        });

    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type specified");
    }
    

    return ret;
},
    };
} 

static RPCHelpMan protx_info()
{
    return RPCHelpMan{"protx_info",
        "\nReturns detailed information about a deterministic masternode.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the initial ProRegTx."},                 
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("protx_info", "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")
            + HelpExampleRpc("protx_info", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    const node::NodeContext& node = EnsureAnyNodeContext(request.context);
    uint256 proTxHash = ParseHashV(request.params[0], "proTxHash");
    CDeterministicMNList mnList;
    llmq::pq::PQPaymentProbationStateView payment_state;
    {
        LOCK(cs_main);
        const CBlockIndex* tip{node.chainman->ActiveTip()};
        if (tip == nullptr ||
            !deterministicMNManager->GetPaymentProbationStateView(
                tip, payment_state)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "payment audit state is unavailable");
        }
        mnList = deterministicMNManager->GetListForBlock(tip);
    }
    auto dmn = mnList.GetMN(proTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s not found", proTxHash.ToString()));
    }
   
    return BuildDMNListEntry(node, *dmn, true, &payment_state);
},
    };
}

static RPCHelpMan protx_operator_key_info()
{
    return RPCHelpMan{
        "protx_operator_key_info",
        "\nReturns the active post-quantum operator public key and version for a deterministic masternode.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The hash of the initial ProRegTx."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "Active PQ operator identity.",
            {
                {RPCResult::Type::STR_HEX, "publicKey", "32-byte SLH-DSA public key"},
                {RPCResult::Type::NUM, "keyVersion", "Nonzero global key version"},
            }},
        RPCExamples{HelpExampleCli("protx_operator_key_info", "<proTxHash>") +
                    HelpExampleRpc("protx_operator_key_info", "\"<proTxHash>\"")},
        [&](const RPCHelpMan& self,
            const node::JSONRPCRequest& request) -> UniValue {
            const node::NodeContext& node =
                EnsureAnyNodeContext(request.context);
            const uint256 pro_tx_hash =
                ParseHashV(request.params[0], "proTxHash");

            llmq::pq::PQRegistrySnapshot snapshot;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = node.chainman->ActiveChain().Tip();
                if (tip == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Active chain tip is unavailable");
                }
                std::string error;
                if (!deterministicMNManager->GetPQRegistrySnapshot(
                        tip, snapshot, error)) {
                    throw JSONRPCError(
                        RPC_MISC_ERROR,
                        strprintf("Unable to read PQ registry snapshot: %s",
                                  error));
                }
            }
            const auto* state = snapshot.FindOperator(pro_tx_hash);
            if (state == nullptr || !state->HasActiveGlobalKey()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Masternode has no active global key");
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("publicKey",
                          HexStr(state->global_key.public_key));
            result.pushKV("keyVersion", state->global_key.key_version);
            return result;
        }};
}

// SYSCOIN BEGIN: Branch-local deterministic-state diagnostic RPC.
static RPCHelpMan protx_migration_info()
{
    return RPCHelpMan{
        "protx_migration_info",
        "\nReturns branch-local deterministic-masternode and PQ-registry "
        "state diagnostics for the active tip. These values are not a "
        "consensus checkpoint.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "Branch-local state diagnostics for the active tip.",
            {
                {RPCResult::Type::NUM, "height", "Active-tip block height"},
                {RPCResult::Type::STR_HEX, "blockHash", "Active-tip block hash"},
                {RPCResult::Type::STR_HEX, "dmnStateHash", "Deterministic-masternode state commitment"},
                {RPCResult::Type::STR_HEX, "pqRegistryStateHash", "PQ operator-key registry state commitment"},
            }},
        RPCExamples{HelpExampleCli("protx_migration_info", "") +
                    HelpExampleRpc("protx_migration_info", "")},
        [&](const RPCHelpMan& self,
            const node::JSONRPCRequest& request) -> UniValue {
            const node::NodeContext& node =
                EnsureAnyNodeContext(request.context);

            CDeterministicMNList mn_list;
            llmq::pq::PQRegistrySnapshot pq_snapshot;
            int tip_height{-1};
            uint256 tip_block_hash;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = node.chainman->ActiveChain().Tip();
                if (tip == nullptr ||
                    tip->nHeight < Params().GetConsensus().DIP0003Height) {
                    throw JSONRPCError(
                        RPC_MISC_ERROR,
                        "DIP3 must be active before deriving masternode state diagnostics");
                }
                tip_height = tip->nHeight;
                tip_block_hash = tip->GetBlockHash();
                mn_list = deterministicMNManager->GetListForBlock(tip);

                llmq::pq::PQRegistryConfig config;
                const auto deployment = llmq::pq::GetPQRegistryConfig(
                    Params().GetConsensus(), config);
                if (deployment ==
                    llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Invalid PQ registry configuration");
                }
                if (deployment == llmq::pq::PQRegistryDeploymentResult::VALID) {
                    std::string error;
                    if (!deterministicMNManager->GetPQRegistrySnapshot(
                            tip, pq_snapshot, error)) {
                        throw JSONRPCError(
                            RPC_INTERNAL_ERROR,
                            strprintf("Unable to read PQ registry snapshot: %s",
                                      error));
                    }
                }
            }

            const uint256 genesis_hash = Params().GetConsensus().hashGenesisBlock;
            const auto pq_root = pq_snapshot.RecomputeConsensusStateRoot(
                genesis_hash);
            if (!pq_root) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "Unable to derive PQ registry state root");
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("height", tip_height);
            result.pushKV("blockHash", tip_block_hash.GetHex());
            result.pushKV("dmnStateHash",
                          mn_list.GetPQLegacyStateHash(genesis_hash).GetHex());
            result.pushKV("pqRegistryStateHash", pq_root->GetHex());
            return result;
        }};
}
// SYSCOIN END: Branch-local deterministic-state diagnostic RPC.

void RegisterEvoRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"evo", &protx_list},
        {"evo", &protx_info},
        {"evo", &protx_operator_key_info},
        {"evo", &protx_migration_info},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
