// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <core_io.h>
#include <governance/governance.h>
#include <governance/governanceclasses.h>
#include <governance/governancevalidators.h>
#include <evo/deterministicmns.h>
#include <validation.h>
#include <masternode/masternodesync.h>
#include <rpc/server.h>
#include <rpc/blockchain.h>
#include <node/context.h>
#include <timedata.h>
#include <rpc/server_util.h>
#include <index/txindex.h>
static RPCHelpMan gobject_count()
{
    return RPCHelpMan{"gobject_count",
        "\nCount governance objects and votes\n",
        {
            {"mode", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Output format: json (\"json\") or string in free form (\"all\")."},                
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_count", "json")
            + HelpExampleRpc("gobject_count", "json")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{

    std::string strMode{"json"};

    if (!request.params[0].isNull()) {
        strMode = request.params[0].get_str();
    }

    return strMode == "json" ? governance->ToJson() : governance->ToString();
},
    };
} 


static RPCHelpMan gobject_deserialize()
{
    return RPCHelpMan{"gobject_deserialize",
        "\nDeserialize governance object from hex string to JSON\n",
        {
            {"hex_data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Data in hex string form."},                
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_deserialize", "")
            + HelpExampleRpc("gobject_deserialize", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::string strHex = request.params[0].get_str();

    std::vector<unsigned char> v = ParseHex(strHex);
    std::string s(v.begin(), v.end());

    UniValue u(UniValue::VOBJ);
    u.read(s);

    return u.write().c_str();
},
    };
} 


static RPCHelpMan gobject_check()
{
    return RPCHelpMan{"gobject_check",
        "\nValidate governance object data (proposal only)\n",
        {
            {"hex_data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Data in hex string form."},                
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_check", "")
            + HelpExampleRpc("gobject_check", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{

    // ASSEMBLE NEW GOVERNANCE OBJECT FROM USER PARAMETERS

    uint256 hashParent;

    int nRevision = 1;

    int64_t nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    std::string strDataHex = request.params[0].get_str();

    CGovernanceObject govobj(hashParent, nRevision, nTime, uint256(), strDataHex);

    if (govobj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
        CProposalValidator validator(strDataHex);
        if (!validator.Validate())  {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposal data, error messages:" + validator.GetErrorMessages());
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid object type, only proposals can be validated");
    }

    UniValue objResult(UniValue::VOBJ);

    objResult.pushKV("Object status", "OK");

    return objResult;
},
    };
} 

static RPCHelpMan gobject_submit()
{
    return RPCHelpMan{"gobject_submit",
        "\nSubmit governance object to network\n",
        {      
            {"parentHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the parent object, \"0\" is root."},
            {"revision", RPCArg::Type::NUM, RPCArg::Optional::NO, "Object revision in the system."},   
            {"time", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time this object was created."},
            {"dataHex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Data in hex string form."},
            {"feeTxid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Fee-tx id, required for all objects except triggers."},                                         
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_submit", "")
            + HelpExampleRpc("gobject_submit", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    if(!masternodeSync.IsBlockchainSynced()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Must wait for client to sync with masternode network. Try again in a minute or so.");
    }
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if(!node.connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    auto mnList = deterministicMNManager->GetListAtChainTip();
    bool fMnFound = WITH_LOCK(activeMasternodeInfoCs, return mnList.HasValidMNByCollateral(activeMasternodeInfo.outpoint));

    LogPrint(BCLog::GOBJECT, "gobject_submit -- pubKeyOperator = %s, outpoint = %s, params.size() = %lld, fMnFound = %d\n",
            (WITH_LOCK(activeMasternodeInfoCs, return activeMasternodeInfo.blsPubKeyOperator ? activeMasternodeInfo.blsPubKeyOperator->ToString() : "N/A")),
            WITH_LOCK(activeMasternodeInfoCs, return activeMasternodeInfo.outpoint.ToStringShort()), request.params.size(), fMnFound);

    // ASSEMBLE NEW GOVERNANCE OBJECT FROM USER PARAMETERS

    uint256 txidFee;

    if (!request.params[4].isNull()) {
        txidFee = ParseHashV(request.params[4], "feeTxid");
    }
    uint256 hashParent;
    if (request.params[0].get_str() == "0") { // attach to root node (root node doesn't really exist, but has a hash of zero)
        hashParent = uint256();
    } else {
        hashParent = ParseHashV(request.params[0], "parentHash");
    }

    // GET THE PARAMETERS FROM USER

    int nRevision = request.params[1].getInt<int>();
    int64_t nTime = request.params[2].getInt<int64_t>();
    std::string strDataHex = request.params[3].get_str();

    CGovernanceObject govobj(hashParent, nRevision, nTime, txidFee, strDataHex);

    LogPrint(BCLog::GOBJECT, "gobject_submit -- GetDataAsPlainString = %s, hash = %s, txid = %s\n",
                govobj.GetDataAsPlainString(), govobj.GetHash().ToString(), txidFee.ToString());

    if (govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
        LogPrintf("govobject(submit) -- Object submission rejected because submission of trigger is disabled\n");
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Submission of triggers is not available");
    }

    if (govobj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
        CProposalValidator validator(strDataHex);
        if (!validator.Validate()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposal data, error messages:" + validator.GetErrorMessages());
        }
    }
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    std::string strHash = govobj.GetHash().ToString();

    std::string strError;
    bool fMissingConfirmations;
    {
        LOCK2(cs_main, node.mempool->cs);
        if (!govobj.IsValidLocally(*node.chainman, deterministicMNManager->GetListAtChainTip(), strError, fMissingConfirmations, true) && !fMissingConfirmations) {
            LogPrintf("gobject(submit) -- Object submission rejected because object is not valid - hash = %s, strError = %s\n", strHash, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Governance object is not valid - " + strHash + " - " + strError);
        }
    }

    // RELAY THIS OBJECT
    // Reject if rate check fails but don't update buffer
    if (!governance->MasternodeRateCheck(govobj)) {
        LogPrintf("gobject(submit) -- Object submission rejected because of rate check failure - hash = %s\n", strHash);
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Object creation rate limit exceeded");
    }

    LogPrintf("gobject(submit) -- Adding locally created governance object - %s\n", strHash);

    if (fMissingConfirmations) {
        governance->AddPostponedObject(govobj);
        govobj.Relay(*node.peerman);
    } else {
        governance->AddGovernanceObject(govobj, *node.peerman);
    }

    return govobj.GetHash().ToString();
},
    };
} 


UniValue ListObjects(ChainstateManager& chainman, const CDeterministicMNList& tip_mn_list, const std::string& strCachedSignal,
                            const std::string& strType, int nStartTime)
{
    UniValue objResult(UniValue::VOBJ);

    // GET MATCHING GOVERNANCE OBJECTS
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    LOCK2(cs_main, governance->cs);

    std::vector<CGovernanceObject> objs;
    governance->GetAllNewerThan(objs, nStartTime);

    governance->UpdateLastDiffTime(GetTime());
    // CREATE RESULTS FOR USER

    for (const auto& govObj : objs) {
        if (strCachedSignal == "valid" && !govObj.IsSetCachedValid()) continue;
        if (strCachedSignal == "funding" && !govObj.IsSetCachedFunding()) continue;
        if (strCachedSignal == "delete" && !govObj.IsSetCachedDelete()) continue;
        if (strCachedSignal == "endorsed" && !govObj.IsSetCachedEndorsed()) continue;

        if (strType == "proposals" && govObj.GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) continue;
        if (strType == "triggers" && govObj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) continue;

        UniValue bObj(UniValue::VOBJ);
        bObj.pushKV("DataHex",  govObj.GetDataAsHexString());
        bObj.pushKV("DataString",  govObj.GetDataAsPlainString());
        bObj.pushKV("Hash",  govObj.GetDataHash().ToString());
        bObj.pushKV("CollateralHash",  govObj.GetCollateralHash().ToString());
        bObj.pushKV("ObjectType", govObj.GetObjectType());
        bObj.pushKV("CreationTime", govObj.GetCreationTime());
        const COutPoint& masternodeOutpoint = govObj.GetMasternodeOutpoint();
        if (masternodeOutpoint != COutPoint()) {
            bObj.pushKV("SigningMasternode", masternodeOutpoint.ToStringShort());
        }

        // REPORT STATUS FOR FUNDING VOTES SPECIFICALLY
        bObj.pushKV("AbsoluteYesCount",  govObj.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING));
        bObj.pushKV("YesCount",  govObj.GetYesCount(VOTE_SIGNAL_FUNDING));
        bObj.pushKV("NoCount",  govObj.GetNoCount(VOTE_SIGNAL_FUNDING));
        bObj.pushKV("AbstainCount",  govObj.GetAbstainCount(VOTE_SIGNAL_FUNDING));

        // REPORT VALIDITY AND CACHING FLAGS FOR VARIOUS SETTINGS
        std::string strError = "";
        bObj.pushKV("fBlockchainValidity",  govObj.IsValidLocally(chainman, tip_mn_list, strError, false));
        bObj.pushKV("IsValidReason",  strError.c_str());
        bObj.pushKV("fCachedValid",  govObj.IsSetCachedValid());
        bObj.pushKV("fCachedFunding",  govObj.IsSetCachedFunding());
        bObj.pushKV("fCachedDelete",  govObj.IsSetCachedDelete());
        bObj.pushKV("fCachedEndorsed",  govObj.IsSetCachedEndorsed());

        objResult.pushKV(govObj.GetHash().ToString(), bObj);
    }
    return objResult;
}

static RPCHelpMan gobject_list()
{
    return RPCHelpMan{"gobject_list",
        "\nList governance objects (can be filtered by signal and/or object type)\n",
        {      
            {"signal", RPCArg::Type::STR, RPCArg::Default{"valid"}, "Cached signal, possible values: [valid|funding|delete|endorsed|all]."},
            {"type", RPCArg::Type::STR, RPCArg::Default{"all"}, "Object type, possible values: [proposals|triggers|all]."},                                    
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_list", "")
            + HelpExampleRpc("gobject_list", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    std::string strCachedSignal = "valid";
    if (!request.params[0].isNull()) {
        strCachedSignal = request.params[0].get_str();
    }
    if (strCachedSignal != "valid" && strCachedSignal != "funding" && strCachedSignal != "delete" && strCachedSignal != "endorsed" && strCachedSignal != "all")
        return "Invalid signal, should be 'valid', 'funding', 'delete', 'endorsed' or 'all'";

    std::string strType = "all";
    if (!request.params[1].isNull()) {
        strType = request.params[1].get_str();
    }
    if (strType != "proposals" && strType != "triggers" && strType != "all")
        return "Invalid type, should be 'proposals', 'triggers' or 'all'";
    
    return ListObjects(*node.chainman, deterministicMNManager->GetListAtChainTip(), strCachedSignal, strType, 0);
},
    };
} 

static RPCHelpMan gobject_diff()
{
    return RPCHelpMan{"gobject_diff",
        "\nList differences since last diff or list\n",
        {      
            {"signal", RPCArg::Type::STR, RPCArg::Default{"valid"}, "Cached signal, possible values: [valid|funding|delete|endorsed|all]."},
            {"type", RPCArg::Type::STR, RPCArg::Default{"all"}, "Object type, possible values: [proposals|triggers|all]."},                                    
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_diff", "")
            + HelpExampleRpc("gobject_diff", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    std::string strCachedSignal = "valid";
    if (!request.params[0].isNull()) {
        strCachedSignal = request.params[0].get_str();
    }
    if (strCachedSignal != "valid" && strCachedSignal != "funding" && strCachedSignal != "delete" && strCachedSignal != "endorsed" && strCachedSignal != "all")
        return "Invalid signal, should be 'valid', 'funding', 'delete', 'endorsed' or 'all'";

    std::string strType = "all";
    if (!request.params[1].isNull()) {
        strType = request.params[1].get_str();
    }
    if (strType != "proposals" && strType != "triggers" && strType != "all")
        return "Invalid type, should be 'proposals', 'triggers' or 'all'";

    return ListObjects(*node.chainman, deterministicMNManager->GetListAtChainTip(), strCachedSignal, strType, governance->GetLastDiffTime());
},
    };
} 

static RPCHelpMan gobject_get()
{
    return RPCHelpMan{"gobject_get",
        "\nGet governance object by hash\n",
        {      
            {"governanceHash", RPCArg::Type::STR_HEX,  RPCArg::Optional::NO, "Object id."},                                   
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_get", "")
            + HelpExampleRpc("gobject_get", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    // COLLECT VARIABLES FROM OUR USER
    uint256 hash = ParseHashV(request.params[0], "GovObj hash");
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    LOCK2(cs_main, governance->cs);

    // FIND THE GOVERNANCE OBJECT THE USER IS LOOKING FOR
    CGovernanceObject* pGovObj = governance->FindGovernanceObject(hash);

    if (pGovObj == nullptr) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown governance object");
    }

    // REPORT BASIC OBJECT STATS

    UniValue objResult(UniValue::VOBJ);
    objResult.pushKV("DataHex",  pGovObj->GetDataAsHexString());
    objResult.pushKV("DataString",  pGovObj->GetDataAsPlainString());
    objResult.pushKV("Hash",  pGovObj->GetHash().ToString());
    objResult.pushKV("CollateralHash",  pGovObj->GetCollateralHash().ToString());
    objResult.pushKV("ObjectType", pGovObj->GetObjectType());
    objResult.pushKV("CreationTime", pGovObj->GetCreationTime());
    const COutPoint& masternodeOutpoint = pGovObj->GetMasternodeOutpoint();
    if (masternodeOutpoint != COutPoint()) {
        objResult.pushKV("SigningMasternode", masternodeOutpoint.ToStringShort());
    }

    // SHOW (MUCH MORE) INFORMATION ABOUT VOTES FOR GOVERNANCE OBJECT (THAN LIST/DIFF ABOVE)
    // -- FUNDING VOTING RESULTS

    UniValue objFundingResult(UniValue::VOBJ);
    objFundingResult.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING));
    objFundingResult.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_FUNDING));
    objFundingResult.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_FUNDING));
    objFundingResult.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_FUNDING));
    objResult.pushKV("FundingResult", objFundingResult);

    // -- VALIDITY VOTING RESULTS
    UniValue objValid(UniValue::VOBJ);
    objValid.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_VALID));
    objValid.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_VALID));
    objValid.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_VALID));
    objValid.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_VALID));
    objResult.pushKV("ValidResult", objValid);

    // -- DELETION CRITERION VOTING RESULTS
    UniValue objDelete(UniValue::VOBJ);
    objDelete.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_DELETE));
    objDelete.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_DELETE));
    objDelete.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_DELETE));
    objDelete.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_DELETE));
    objResult.pushKV("DeleteResult", objDelete);

    // -- ENDORSED VIA MASTERNODE-ELECTED BOARD
    UniValue objEndorsed(UniValue::VOBJ);
    objEndorsed.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_ENDORSED));
    objEndorsed.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_ENDORSED));
    objEndorsed.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_ENDORSED));
    objEndorsed.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_ENDORSED));
    objResult.pushKV("EndorsedResult", objEndorsed);

    // --
    std::string strError;
    objResult.pushKV("fLocalValidity",  pGovObj->IsValidLocally(*node.chainman, deterministicMNManager->GetListAtChainTip(), strError, false));
    objResult.pushKV("IsValidReason",  strError.c_str());
    objResult.pushKV("fCachedValid",  pGovObj->IsSetCachedValid());
    objResult.pushKV("fCachedFunding",  pGovObj->IsSetCachedFunding());
    objResult.pushKV("fCachedDelete",  pGovObj->IsSetCachedDelete());
    objResult.pushKV("fCachedEndorsed",  pGovObj->IsSetCachedEndorsed());
    return objResult;
},
    };
} 

static RPCHelpMan gobject_getcurrentvotes()
{
    return RPCHelpMan{"gobject_getcurrentvotes",
        "\nGet only current (tallying) votes for a governance object hash (does not include old votes)\n",
        {      
            {"governanceHash", RPCArg::Type::STR_HEX,  RPCArg::Optional::NO, "Object id."},
            {"txid", RPCArg::Type::STR_HEX,  RPCArg::Optional::OMITTED, "Masternode collateral txid."}, 
            {"vout", RPCArg::Type::NUM,  RPCArg::Optional::OMITTED, "Masternode collateral output index, required if <txid> presents."},                                   
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("gobject_getcurrentvotes", "")
            + HelpExampleRpc("gobject_getcurrentvotes", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    // COLLECT PARAMETERS FROM USER

    uint256 hash = ParseHashV(request.params[0], "Governance hash");

    COutPoint mnCollateralOutpoint;
    if (!request.params[1].isNull() && !request.params[2].isNull()) {
        uint256 txid = ParseHashV(request.params[1], "Masternode Collateral hash");
        int nVout = request.params[2].getInt<int>();
        mnCollateralOutpoint = COutPoint(txid, (uint32_t)nVout);
    }

    // FIND OBJECT USER IS LOOKING FOR

    LOCK(governance->cs);

    CGovernanceObject* pGovObj = governance->FindGovernanceObject(hash);

    if (pGovObj == nullptr) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown governance-hash");
    }

    // REPORT RESULTS TO USER

    UniValue bResult(UniValue::VOBJ);

    // GET MATCHING VOTES BY HASH, THEN SHOW USERS VOTE INFORMATION

    std::vector<CGovernanceVote> vecVotes = governance->GetCurrentVotes(hash, mnCollateralOutpoint);
    for (const auto& vote : vecVotes) {
        bResult.pushKV(vote.GetHash().ToString(),  vote.ToString());
    }

    return bResult;
},
    };
} 

static RPCHelpMan voteraw()
{
    return RPCHelpMan{"voteraw",
        "\nCompile and relay a governance vote with provided external signature instead of signing vote internally\n",
        {
            {"collateralTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Masternode collateral txid."}, 
            {"collateralTxIndex", RPCArg::Type::NUM, RPCArg::Optional::NO, "Masternode collateral output index."}, 
            {"governanceHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Governance proposal hash."},    
            {"voteSignal", RPCArg::Type::STR, RPCArg::Optional::NO, "One of following (funding|valid|delete|endorsed)."}, 
            {"voteOutcome", RPCArg::Type::STR, RPCArg::Optional::NO, "One of following (yes|no|abstain)."},
            {"time", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time of vote."},
            {"voteSig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Vote signature. Must be encoded in base64."},                 
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("voteraw", "")
            + HelpExampleRpc("voteraw", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{

    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if(!node.connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    uint256 hashMnCollateralTx = ParseHashV(request.params[0], "mn collateral tx hash");
    int nMnCollateralTxIndex = request.params[1].getInt<int>();
    COutPoint outpoint = COutPoint(hashMnCollateralTx, nMnCollateralTxIndex);

    uint256 hashGovObj = ParseHashV(request.params[2], "Governance hash");
    std::string strVoteSignal = request.params[3].get_str();
    std::string strVoteOutcome = request.params[4].get_str();

    vote_signal_enum_t eVoteSignal = CGovernanceVoting::ConvertVoteSignal(strVoteSignal);
    if (eVoteSignal == VOTE_SIGNAL_NONE)  {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Invalid vote signal. Please using one of the following: "
                           "(funding|valid|delete|endorsed)");
    }

    vote_outcome_enum_t eVoteOutcome = CGovernanceVoting::ConvertVoteOutcome(strVoteOutcome);
    if (eVoteOutcome == VOTE_OUTCOME_NONE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vote outcome. Please use one of the following: 'yes', 'no' or 'abstain'");
    }

    GovernanceObject govObjType = WITH_LOCK(governance->cs, return [&](){
        const CGovernanceObject *pGovObj = governance->FindConstGovernanceObject(hashGovObj);
        if (!pGovObj) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Governance object not found");
        }
        return pGovObj->GetObjectType();
    }());

    int64_t nTime = request.params[5].getInt<int64_t>();
    std::string strSig = request.params[6].get_str();
    auto vchSig = DecodeBase64(strSig);

    if (!vchSig) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");
    }
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetValidMNByCollateral(outpoint);

    if (!dmn) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failure to find masternode in list : " + outpoint.ToStringShort());
    }

    CGovernanceVote vote(outpoint, hashGovObj, eVoteSignal, eVoteOutcome);
    vote.SetTime(nTime);
    vote.SetSignature(*vchSig);

    bool onlyVotingKeyAllowed = govObjType.GetValue() == GOVERNANCE_OBJECT_PROPOSAL && vote.GetSignal() == VOTE_SIGNAL_FUNDING;
    if (!vote.IsValid(mnList, onlyVotingKeyAllowed)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failure to verify vote.");
    }

    CGovernanceException exception;
    if (governance->ProcessVoteAndRelay(vote, mnList, exception, *node.connman, *node.peerman)) {
        return "Voted successfully";
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Error voting : " + std::string(exception.what()));
    }
},
    };
} 
bool ScanGovLimits(UniValue& oRes, const CBlockIndex* pindexStart)
{
    static constexpr size_t MAX_COUNT = 10;
    size_t found = 0;
    std::vector<std::tuple<int, uint256, CAmount>> results;

    const CBlockIndex* pindex = pindexStart;
    if (!pindex) return false;

    while (pindex && found < MAX_COUNT) {
        // If the current block is a superblock, try to read its limit
        if (CSuperblock::IsValidBlockHeight(pindex->nHeight)) {
            uint256 h = pindex->GetBlockHash();
            CAmount cVal = 0;
            if (governance->m_sb->ReadCache(h, cVal)) {
                results.emplace_back(pindex->nHeight, h, cVal);
                found++;
            } else {
                LogPrintf("ScanGovLimits: Could not find block %s (%d) in the cache...\n", h.GetHex(), pindex->nHeight);
                break;
            }
        } else {
            LogPrintf("ScanGovLimits: Block %s (%d) not a valid SB height...\n", pindex->GetBlockHash().GetHex(), pindex->nHeight);
            break;
        }
        // Jump to the previous superblock height
        int sbCycle = Params().GetConsensus().SuperBlockCycle(pindex->nHeight);
        // If we can't go back any further, break
        if (pindex->nHeight < sbCycle) {
            // no more possible superblocks
            LogPrintf("ScanGovLimits: No more SB\n");
            break;
        }
        int nLastSuperblock = pindex->nHeight - sbCycle;
        // Now move pindex to that older superblock
        pindex = pindex->GetAncestor(nLastSuperblock);
    }

    std::reverse(results.begin(), results.end());

    for (const auto& [height, bh, val] : results) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", (int)height);
        obj.pushKV("blockhash", bh.GetHex());
        obj.pushKV("governancebudget", ValueFromAmount(val));
        oRes.push_back(obj);
    }

    return true;
}


static RPCHelpMan getgovernanceinfo()
{
    return RPCHelpMan{"getgovernanceinfo",
        "\nReturns an object containing governance parameters.\n",
        {                
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "governanceminquorum", "The absolute minimum number of votes needed to trigger a governance action"},
                {RPCResult::Type::NUM, "proposalfee", "The collateral transaction fee which must be paid to create a proposal in " + CURRENCY_UNIT},
                {RPCResult::Type::NUM, "superblockcycle", "The number of blocks between superblocks"},
                {RPCResult::Type::NUM, "superblockmaturitywindow", "the superblock trigger creation window"},
                {RPCResult::Type::NUM, "lastsuperblock", "The block number of the last superblock"},
                {RPCResult::Type::NUM, "nextsuperblock", "The block number of the next superblock"},
                {RPCResult::Type::NUM, "fundingthreshold", "the number of absolute yes votes required for a proposal to be passing"},
                {RPCResult::Type::NUM, "governancebudget", "the governance budget for the next superblock in " + CURRENCY_UNIT + ""},
                {RPCResult::Type::ARR, "last10governancebudgets", "",
                {
                    {RPCResult::Type::OBJ, "last10governancebudgets", "the last 10 governance budgets",
                    {
                        {RPCResult::Type::NUM, "height", "Superblock height"},
                        {RPCResult::Type::STR, "blockhash", "Superblock hash"},
                        {RPCResult::Type::STR_AMOUNT, "governancebudget", "Superblock budget"}
                    }}
                }}
            },
        },
        RPCExamples{
                HelpExampleCli("getgovernanceinfo", "")
            + HelpExampleRpc("getgovernanceinfo", "")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);

    int nLastSuperblock = 0, nNextSuperblock = 0;
    int nBlockHeight = WITH_LOCK(cs_main, return node.chainman->ActiveHeight());

    CSuperblock::GetNearestSuperblocksHeights(nBlockHeight, nLastSuperblock, nNextSuperblock);
    const CBlockIndex* nLastSBIndex = WITH_LOCK(cs_main, return node.chainman->ActiveChain()[nLastSuperblock]);
    
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("governanceminquorum", Params().GetConsensus().nGovernanceMinQuorum);
    obj.pushKV("proposalfee", ValueFromAmount(GOVERNANCE_PROPOSAL_FEE_TX));
    obj.pushKV("superblockcycle", Params().GetConsensus().SuperBlockCycle(nBlockHeight));
    obj.pushKV("superblockmaturitywindow", Params().GetConsensus().nSuperblockMaturityWindow);
    obj.pushKV("lastsuperblock", nLastSuperblock);
    obj.pushKV("nextsuperblock", nNextSuperblock);
    obj.pushKV("fundingthreshold", int(deterministicMNManager->GetListAtChainTip().GetValidMNsCount() / 10));
    obj.pushKV("governancebudget", ValueFromAmount(CSuperblock::GetPaymentsLimit(nLastSBIndex)));
    UniValue oLimits(UniValue::VARR);
    if(!ScanGovLimits(oLimits, nLastSBIndex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not retrieve last 10 governance budgets!");
    }
    obj.pushKV("last10governancebudgets", oLimits);
    return obj;
},
    };
} 

static RPCHelpMan getsuperblockbudget()
{
    return RPCHelpMan{"getsuperblockbudget",
        "\nReturns the absolute maximum sum of superblock payments allowed.\n",
        {
            {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The block index"},
        },
        RPCResult{
            RPCResult::Type::NUM, "n", "The absolute maximum sum of superblock payments allowed, in " + CURRENCY_UNIT
        },
        RPCExamples{
            HelpExampleCli("getsuperblockbudget", "1000")
    + HelpExampleRpc("getsuperblockbudget", "1000")
        },
        [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    int nLastSuperblock = 0, nNextSuperblock = 0;
    int nBlockHeight = WITH_LOCK(cs_main, return node.chainman->ActiveHeight());

    CSuperblock::GetNearestSuperblocksHeights(nBlockHeight, nLastSuperblock, nNextSuperblock);

    if(request.params.size() > 0) {
        nNextSuperblock = request.params[0].getInt<int>();
        if (nNextSuperblock < 0 || nNextSuperblock > nBlockHeight) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
    }
    const CBlockIndex* nLastSBIndex = WITH_LOCK(cs_main, return node.chainman->ActiveChain()[nLastSuperblock]);
    return ValueFromAmount(CSuperblock::GetPaymentsLimit(nLastSBIndex));
},
    };
}



void RegisterGovernanceRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{  
        {"governance", &getgovernanceinfo },
        {"governance", &getsuperblockbudget},
        {"governance", &gobject_count},
        {"governance", &gobject_deserialize},
        {"governance", &gobject_check},
        {"governance", &gobject_getcurrentvotes},
        {"governance", &gobject_get},
        {"governance", &gobject_submit},
        {"governance", &gobject_list},
        {"governance", &gobject_diff},
        {"governance", &voteraw},

    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
