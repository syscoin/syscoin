// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <common/args.h>
#include <chainparams.h>
#include <core_io.h>
#include <init.h>
#include <rpc/server.h>
#include <util/moneystr.h>
#include <validation.h>

#include <evo/deterministicmns.h>

#include <bls/bls.h>

#include <masternode/masternodemeta.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <node/context.h>
#include <rpc/server_util.h>
#include <llmq/quorums_utils.h>
#include <index/txindex.h>
static RPCHelpMan protx_capabilities()
{
    return RPCHelpMan{
        "protx_capabilities",
        "\nReturns public signing rules for the next block and the active-tip identity. No wallet or private keys are accessed.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "Versioned Sentry signing capabilities.",
            {{RPCResult::Type::NUM, "version", "Response schema version"},
             {RPCResult::Type::STR_HEX, "genesisHash", "Network genesis hash"},
             {RPCResult::Type::STR, "network", "Core network name"},
             {RPCResult::Type::NUM, "height", "Active tip height"},
             {RPCResult::Type::STR_HEX, "blockHash", "Active tip hash"},
             {RPCResult::Type::NUM, "nextBlockHeight", "Height for signing rules"},
             {RPCResult::Type::STR, "era", "legacy-v1, legacy-v3, or pq-v4"},
             {RPCResult::Type::NUM, "servicePayloadVersion", "Service payload version"},
             {RPCResult::Type::STR, "requiredCollateralSatoshis", "Required node collateral in atomic units"},
             {RPCResult::Type::ANY, "preparationHeight", "PQ preparation height or null"},
             {RPCResult::Type::ANY, "activationHeight", "PQ activation height or null"},
             {RPCResult::Type::BOOL, "preparationActive", "PQ preparation is active for the next block"},
             {RPCResult::Type::BOOL, "pqActive", "PQ rules are active for the next block"}}},
        RPCExamples{HelpExampleCli("protx_capabilities", "")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            const auto& node = EnsureAnyNodeContext(request.context);
            LOCK(cs_main);
            const auto* tip = node.chainman->ActiveChain().Tip();
            if (tip == nullptr) throw JSONRPCError(RPC_INTERNAL_ERROR, "Active chain tip is unavailable");
            const int64_t next_height = int64_t{tip->nHeight} + 1;
            const auto& params = node.chainman->GetParams();
            bool pq_active{false};
            bool preparation_active{false};
            UniValue preparation_height;
            UniValue activation_height;

            const uint16_t payload_version = pq_active ? 4 :
                (llmq::CLLMQUtils::IsV19Active(tip->nHeight) ? 3 : 1);
            UniValue result{UniValue::VOBJ};
            result.pushKV("version", 1);
            result.pushKV("genesisHash", params.GetConsensus().hashGenesisBlock.GetHex());
            result.pushKV("network", params.GetChainTypeString());
            result.pushKV("height", tip->nHeight);
            result.pushKV("blockHash", tip->GetBlockHash().GetHex());
            result.pushKV("nextBlockHeight", next_height);
            result.pushKV("era", pq_active ? "pq-v4" : (payload_version == 3 ? "legacy-v3" : "legacy-v1"));
            result.pushKV("servicePayloadVersion", payload_version);
            result.pushKV("requiredCollateralSatoshis", std::to_string(nMNCollateralRequired));
            result.pushKV("preparationHeight", preparation_height);
            result.pushKV("activationHeight", activation_height);
            result.pushKV("preparationActive", preparation_active);
            result.pushKV("pqActive", pq_active);
            return result;
        }};
}

UniValue BuildDMNListEntry(const node::NodeContext& node, const CDeterministicMN& dmn, bool detailed)
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
        bool detailed = !request.params[1].isNull() ? request.params[1].get_bool() : false;
        {
            LOCK(cs_main);
            int height = !request.params[2].isNull() ? request.params[2].getInt<int>() : node.chainman->ActiveHeight();
            if (height < 1 || height > node.chainman->ActiveHeight()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");
            }
            mnList = deterministicMNManager->GetListForBlock(node.chainman->ActiveChain()[height]);
        }
        bool onlyValid = type == "valid";
        mnList.ForEachMN(onlyValid, [&](const auto& dmn) {
            ret.push_back(BuildDMNListEntry(node, dmn, detailed));
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
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetMN(proTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s not found", proTxHash.ToString()));
    }
   
    return BuildDMNListEntry(node, *dmn, true);
},
    };
}

static RPCHelpMan bls_generate()
{
     return RPCHelpMan{"bls_generate",
        "\nReturns a BLS secret/public key pair.\n",
        {   
            {"legacy", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use legacy BLS scheme"},           
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("bls_generate", "")
            + HelpExampleRpc("bls_generate", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    CBLSSecretKey sk;
    sk.MakeNewKey();
    bool bls_legacy_scheme{false};
    if (!request.params[0].isNull()) {
        bls_legacy_scheme = request.params[0].get_bool();
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("secret", sk.ToString());
    ret.pushKV("public", sk.GetPublicKey().ToString(bls_legacy_scheme));
    std::string bls_scheme_str = bls_legacy_scheme ? "legacy" : "basic";
    ret.pushKV("scheme", bls_scheme_str);
    return ret;
},
    };
} 
static CBLSSecretKey ParseBLSSecretKey(const std::string& hexKey, const std::string& paramName)
{
    CBLSSecretKey secKey;
    // Actually, bool flag for bls::PrivateKey has other meaning (modOrder)
    if (!secKey.SetHexStr(hexKey, false)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid BLS secret key", paramName));
    }
    return secKey;
}
static RPCHelpMan bls_fromsecret()
{
     return RPCHelpMan{"bls_fromsecret",
        "\nParses a BLS secret key and returns the secret/public key pair.\n",
        {              
             {"secret", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The BLS secret key."},  
             {"legacy", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use legacy BLS scheme"},
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("bls_fromsecret", "")
            + HelpExampleRpc("bls_fromsecret", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    bool bls_legacy_scheme{false};
    if (!request.params[1].isNull()) {
        bls_legacy_scheme = request.params[1].get_bool();
    }
    CBLSSecretKey sk = ParseBLSSecretKey(request.params[0].get_str(), "secretKey");
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("secret", sk.ToString());
    ret.pushKV("public", sk.GetPublicKey().ToString(bls_legacy_scheme));
    std::string bls_scheme_str = bls_legacy_scheme ? "legacy" : "basic";
    ret.pushKV("scheme", bls_scheme_str);
    return ret;
},
    };
}


void RegisterEvoRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"evo", &bls_generate},
        {"evo", &bls_fromsecret},
        {"evo", &protx_list},
        {"evo", &protx_info},
        {"evo", &protx_capabilities},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
