// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <consensus/pq_migration_config.h>
#include <common/args.h>
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
#include <llmq/quorums_utils.h>
#include <streams.h>

// SYSCOIN: zero-copy PQ registry RPC views.
#include <span>
#include <limits>

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
            if (next_height > std::numeric_limits<int>::max())
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Next block height is outside the consensus range");
            const auto& params = node.chainman->GetParams();
            bool pq_active{false};
            bool preparation_active{false};
            UniValue preparation_height;
            UniValue activation_height;
            const auto activation = Consensus::CheckPQActivationConfiguration(params.GetConsensus());
            if (activation == Consensus::PQActivationResult::INVALID_CONFIGURATION)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid PQ activation configuration");
            if (activation == Consensus::PQActivationResult::VALID) {
                activation_height.setInt(params.GetConsensus().nPQActivationHeight);
                pq_active = Consensus::CheckPQLegacyReplay(params.GetConsensus(), static_cast<int>(next_height)) ==
                    Consensus::PQLegacyReplayResult::RETIRED;
            }
            llmq::pq::PQRegistryConfig config;
            const auto deployment = llmq::pq::GetPQRegistryConfig(params.GetConsensus(), config);
            if (deployment == llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid PQ registry configuration");
            if (deployment == llmq::pq::PQRegistryDeploymentResult::VALID) {
                preparation_height.setInt(config.preparation_height);
                preparation_active = next_height >= config.preparation_height;
            }
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
        "\nReturns public post-quantum operator identity and its exact registry snapshot.\n"
        "With includeInactive, returns retained revoked records for recovery or an explicit absent-key status.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The hash of the initial ProRegTx."},
            {"includeInactive", RPCArg::Type::BOOL, RPCArg::Default{false},
             "Include revoked records or an explicit absent-key status for recovery preparation."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "PQ operator identity at the returned active-tip snapshot.",
            {
                {RPCResult::Type::STR_HEX, "genesisHash", "Network genesis hash"},
                {RPCResult::Type::NUM, "height", "Height of the captured registry snapshot"},
                {RPCResult::Type::STR_HEX, "blockHash", "Block hash of the captured registry snapshot"},
                {RPCResult::Type::BOOL, "hasGlobalKey", "A retained global key record exists"},
                {RPCResult::Type::BOOL, "active", "The retained global key is currently active"},
                {RPCResult::Type::NUM, "revokedHeight", "Revocation height, or zero if not revoked"},
                {RPCResult::Type::STR_HEX, "publicKey", /*optional=*/true, "32-byte SLH-DSA public key; present only when hasGlobalKey is true"},
                {RPCResult::Type::NUM, "keyVersion", /*optional=*/true, "Nonzero global key version"},
                {RPCResult::Type::NUM, "recordVersion", /*optional=*/true, "Global key record serialization version"},
                {RPCResult::Type::NUM, "profile", /*optional=*/true, "Global signature algorithm profile"},
                {RPCResult::Type::NUM, "activatedHeight", /*optional=*/true, "Height where this key version activated"},
                {RPCResult::Type::STR_HEX, "childKeyCommitment", /*optional=*/true, "Exact 80-byte canonical child-key commitment"},
            }},
        RPCExamples{HelpExampleCli("protx_operator_key_info", "<proTxHash>") +
                    HelpExampleRpc("protx_operator_key_info", "\"<proTxHash>\"")},
        [&](const RPCHelpMan& self,
            const node::JSONRPCRequest& request) -> UniValue {
            const node::NodeContext& node =
                EnsureAnyNodeContext(request.context);
            const uint256 pro_tx_hash =
                ParseHashV(request.params[0], "proTxHash");

            llmq::pq::PQRegistryReadView snapshot;
            int height{-1};
            uint256 block_hash;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = node.chainman->ActiveChain().Tip();
                if (tip == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Active chain tip is unavailable");
                }
                height = tip->nHeight;
                block_hash = tip->GetBlockHash();
                std::string error;
                if (!deterministicMNManager->GetPQRegistryReadView(
                        tip, snapshot, error)) {
                    throw JSONRPCError(
                        RPC_MISC_ERROR,
                        strprintf("Unable to read PQ registry snapshot: %s",
                                  error));
                }
            }
            const auto* state = snapshot.FindOperator(pro_tx_hash);
            const bool include_inactive = !request.params[1].isNull() && request.params[1].get_bool();
            if (!include_inactive && (state == nullptr || !state->HasActiveGlobalKey())) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Masternode has no active global key");
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("genesisHash", Params().GetConsensus().hashGenesisBlock.GetHex());
            result.pushKV("height", height);
            result.pushKV("blockHash", block_hash.GetHex());
            const bool has_key = state != nullptr && state->has_global_key != 0;
            result.pushKV("hasGlobalKey", has_key);
            result.pushKV("active", state != nullptr && state->HasActiveGlobalKey());
            result.pushKV("revokedHeight", state != nullptr ? state->revoked_height : 0);
            if (!has_key) return result;
            result.pushKV("publicKey",
                          HexStr(state->global_key.public_key));
            result.pushKV("keyVersion", state->global_key.key_version);
            result.pushKV("recordVersion", state->global_key.version);
            result.pushKV("profile", state->global_key.profile);
            result.pushKV("activatedHeight", state->global_key.activated_height);
            CDataStream commitment{SER_NETWORK, PROTOCOL_VERSION};
            commitment << state->global_key.child_key_commitment;
            result.pushKV("childKeyCommitment", HexStr(commitment));
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
            llmq::pq::PQRegistryReadView pq_snapshot;
            bool pq_registry_enabled{false};
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
                    pq_registry_enabled = true;
                    std::string error;
                    if (!deterministicMNManager->GetPQRegistryReadView(
                            tip, pq_snapshot, error)) {
                        throw JSONRPCError(
                            RPC_INTERNAL_ERROR,
                            strprintf("Unable to read PQ registry snapshot: %s",
                                      error));
                    }
                }
            }

            const uint256 genesis_hash = Params().GetConsensus().hashGenesisBlock;
            const auto pq_root{pq_registry_enabled
                ? pq_snapshot.RecomputeConsensusStateRoot(genesis_hash)
                : llmq::pq::GetCanonicalPQKeyConsensusStateHash(
                      genesis_hash,
                      std::span<const llmq::pq::OperatorKeyState>{})};
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
        {"evo", &protx_capabilities},
        {"evo", &protx_operator_key_info},
        {"evo", &protx_migration_info},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
