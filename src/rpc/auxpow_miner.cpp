// Copyright (c) 2018-2020 Daniel Kraft
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/auxpow_miner.h>

#include <arith_uint256.h>
#include <auxpow.h>
#include <chainparams.h>
#include <evo/specialtx.h>
#include <llmq/btc_header_policy.h>
#include <llmq/pq_btcc.h>
#include <net.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>
#include <node/context.h>
#include <cassert>
#include <util/check.h>
#include <rpc/server_util.h>

namespace
{
constexpr const char* BTCPREV_TIP_CHANGED_ERROR{
    "Syscoin tip changed while selecting BTCPREV; retry template request"};

void auxMiningCheck(const node::JSONRPCRequest& request)
{
  node::NodeContext& node = request.nodeContext? *request.nodeContext: EnsureAnyNodeContext (request.context);
  if (!node.connman)
    throw JSONRPCError (RPC_CLIENT_P2P_DISABLED,
                        "Error: Peer-to-peer functionality missing or"
                        " disabled");

  if (node.connman->GetNodeCount (ConnectionDirection::Both) == 0
        && !Params ().MineBlocksOnDemand ())
    throw JSONRPCError (RPC_CLIENT_NOT_CONNECTED,
                        "Syscoin is not connected!");

  if (node.chainman->IsInitialBlockDownload ()
        && !Params ().MineBlocksOnDemand ())
    throw JSONRPCError (RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                        "Syscoin is downloading blocks...");

  /* This should never fail, since the chain is already
     past the point of merge-mining start.  Check nevertheless.  */
  {
    LOCK (cs_main);
    const auto auxpowStart = Params ().GetConsensus ().nAuxpowStartHeight;
    if (node.chainman->ActiveChain().Height () + 1 < auxpowStart)
      throw std::runtime_error ("mining auxblock method is not yet available");
  }
}
}  // anonymous namespace
// SYSCOIN
bool AuxpowMiner::TemplateMatchesBTCPREV(
    const CBlock* block,
    bool required,
    const std::optional<uint256>& expected)
{
  if (!required) return true;
  if (block == nullptr || !expected) return false;
  uint256 committed;
  return ExtractBTCPREVCommitment(*block, committed) &&
         committed == *expected;
}

const CBlock*
AuxpowMiner::getCurrentBlock (ChainstateManager &chainman, const CTxMemPool& mempool,
                              const CScript& scriptPubKey, uint256& target,
                              const BTCPrevResolution& btcPrev)
{
  AssertLockHeld(cs);
  const CBlock* pblockCur = nullptr;

  {
    LOCK (cs_main);
    const int nextHeight = chainman.ActiveChain().Height() + 1;
    if (btcPrev.next_height != nextHeight) {
      throw JSONRPCError(RPC_MISC_ERROR, BTCPREV_TIP_CHANGED_ERROR);
    }
    const bool btcpRequired = llmq::pq::IsBTCPREVCommitmentHeight(Params().GetConsensus(), nextHeight);
    const auto& btcPrevHash{btcPrev.hash};
    CScriptID scriptID (scriptPubKey);
    auto iter = curBlocks.find(scriptID);
    if (iter != curBlocks.end())
      pblockCur = iter->second;
    // SYSCOIN
    const bool templateHasCorrectBTCPREV{
        TemplateMatchesBTCPREV(pblockCur, btcpRequired, btcPrevHash)};
    // SYSCOIN
    if (pblockCur == nullptr
        || pindexPrev != chainman.ActiveTip()
        || (mempool.GetTransactionsUpdated () != txUpdatedLast
            && GetTime () - startTime > 60)
        || !templateHasCorrectBTCPREV)
      {
        if (pindexPrev != chainman.ActiveTip())
          {
            /* Clear old blocks since they're obsolete now.  */
            blocks.clear ();
            templates.clear ();
            curBlocks.clear ();
          }

        /* Create new block with nonce = 0 and extraNonce = 1.  */
        if (btcpRequired && !btcPrevHash) {
          throw JSONRPCError(RPC_INVALID_PARAMETER,
                             "btcprevhash is required at this height");
        }
        std::unique_ptr<CBlockTemplate> newBlock =
            BlockAssembler(chainman.ActiveChainstate(), &mempool)
                .CreateNewBlock(scriptPubKey,
                                btcpRequired ? btcPrevHash : std::nullopt);
        if (newBlock == nullptr)
          throw JSONRPCError (RPC_OUT_OF_MEMORY, "out of memory");

        /* Update state only when CreateNewBlock succeeded.  */
        txUpdatedLast = mempool.GetTransactionsUpdated ();
        pindexPrev = chainman.ActiveTip();
        startTime = GetTime ();

        /* Finalise it by setting the version and building the merkle root.  */
        IncrementExtraNonce (&newBlock->block, pindexPrev, extraNonce);
        // SYSCOIN
        // SetBaseVersion rewrites modifier bits. Preserve BlockAssembler's
        // regtest NEVM decision so its sidecar remains durable across reorgs.
        const bool template_is_nevm{newBlock->block.IsNEVM()};
        if (!newBlock->block.IsAuxpow()) {
          const int32_t nChainId = chainman.GetConsensus().nAuxpowChainId;
          const int32_t nVersion =
              chainman.m_versionbitscache.ComputeBlockVersion(
                  pindexPrev, chainman.GetConsensus());
          newBlock->block.SetBaseVersion(nVersion, nChainId);
          newBlock->block.SetAuxpowVersion(true);
        }
        // Work templates carry the AuxPoW version but never a synthetic proof;
        // submitauxblock replaces this null slot with the miner's real proof.
        CHECK_NONFATAL(newBlock->block.auxpow == nullptr);
        if(!fRegTest || template_is_nevm) {
          newBlock->block.SetNEVMVersion();
        }

        /* Save in our map of constructed blocks.  */
        pblockCur = &newBlock->block;
        // SYSCOIN
        curBlocks[scriptID] = pblockCur;
        blocks[pblockCur->GetHash ()] = pblockCur;
        templates.push_back (std::move (newBlock));
      }
  }

  /* At this point, pblockCur is always initialised:  If we make it here
     without creating a new block above, it means that, in particular,
     pindexPrev == chainman->ActiveTip().  But for that to happen, we must
     already have created a pblockCur in a previous call, as pindexPrev is
     initialised only when pblockCur is.  */
  CHECK_NONFATAL(pblockCur);

  arith_uint256 arithTarget;
  bool fNegative, fOverflow;
  arithTarget.SetCompact (pblockCur->nBits, &fNegative, &fOverflow);
  if (fNegative || fOverflow || arithTarget == 0)
    throw std::runtime_error ("invalid difficulty bits in block");
  target = ArithToUint256 (arithTarget);

  return pblockCur;
}

const CBlock*
AuxpowMiner::lookupSavedBlock (const std::string& hashHex) const
{
  AssertLockHeld(cs);

  uint256 hash;
  hash.SetHex (hashHex);

  const auto iter = blocks.find (hash);
  if (iter == blocks.end ())
    throw JSONRPCError (RPC_INVALID_PARAMETER, "block hash unknown");

  return iter->second;
}
// SYSCOIN
const CScript AuxpowMiner::createScriptPubKey(const uint256& auxRoot, int height)
{
  CScript sysCommitScript;
  CDataStream ssData(SER_NETWORK, PROTOCOL_VERSION);
  ssData << pchSyscoinHeader;
  ssData << auxRoot;
  ssData << static_cast<uint32_t>(height);

  // Build OP_RETURN output script
  const auto bytesVec = MakeUCharSpan(ssData);
  sysCommitScript << OP_RETURN << std::vector<unsigned char>(bytesVec.begin(), bytesVec.end());
  return sysCommitScript;
}

AuxpowMiner::BTCPrevResolution AuxpowMiner::resolveBTCPrevHash(
    ChainstateManager& chainman,
    const std::optional<uint256>& requested)
{
  int32_t next_height{-1};
  {
    LOCK(cs_main);
    next_height = chainman.ActiveHeight() + 1;
  }
  if (!llmq::pq::IsBTCPREVCommitmentHeight(chainman.GetConsensus(),
                                            next_height) ||
      !llmq::pq::IsBTCHeaderPolicyEnabled()) {
    return {next_height, requested};
  }

  std::string health_reason;
  if (!chainman.ActiveChainstate().CheckBTCHeaderNodeHealth(
          /*recover=*/true, health_reason)) {
    throw JSONRPCError(
        RPC_MISC_ERROR,
        strprintf("BTCPREV unavailable: Bitcoin header policy backend is "
                  "not ready (%s)", health_reason));
  }

  const int64_t now{GetTime()};
  std::string reason;
  const auto config{llmq::pq::GetConfiguredBTCHeaderPolicy(reason)};
  const llmq::pq::BTCHeaderPolicy policy{
      llmq::pq::MakeConfiguredBTCHeaderPolicy()};
  const auto checked{
      !config
          ? std::nullopt
          : requested
                ? policy.CheckCandidate(*config, *requested, std::nullopt,
                                        now, reason)
                : policy.SelectMiningHash(*config, now, reason)};
  if (!checked) {
    throw JSONRPCError(
        RPC_MISC_ERROR,
        strprintf("BTCPREV unavailable from independent Bitcoin header "
                  "policy backend (%s)",
                  reason));
  }

  {
    LOCK(cs_main);
    if (chainman.ActiveHeight() + 1 != next_height) {
      throw JSONRPCError(
          RPC_MISC_ERROR,
          BTCPREV_TIP_CHANGED_ERROR);
    }
  }
  return {next_height, checked->btc_hash};
}

UniValue
AuxpowMiner::createAuxBlock (const node::JSONRPCRequest& request,
                             const CScript& scriptPubKey,
                             const std::optional<uint256>& requestedBTCPrevHash)
{
  auxMiningCheck (request);
  const node::NodeContext& node = request.nodeContext? *request.nodeContext: EnsureAnyNodeContext(request.context);
  const BTCPrevResolution btcPrev{
      resolveBTCPrevHash(*node.chainman, requestedBTCPrevHash)};

  const auto& mempool = EnsureAnyMemPool (request.nodeContext? request.nodeContext: request.context);
  uint256 target;
  std::string blockHashHex;
  int64_t chainId{0};
  std::string previousBlockHashHex;
  int64_t coinbaseValue{0};
  std::string coinbaseScriptHex;
  std::string bitsHex;
  int64_t blockHeight{0};
  std::optional<uint256> committedBTCPrevHash;
  {
    LOCK (cs);
    const CBlock* pblock = getCurrentBlock (*node.chainman, mempool, scriptPubKey, target, btcPrev);
    CHECK_NONFATAL(pindexPrev != nullptr);
    const int nextHeight = pindexPrev->nHeight + 1;
    const bool btcpRequired = llmq::pq::IsBTCPREVCommitmentHeight(Params().GetConsensus(), nextHeight);
    int nActiveHeight = pindexPrev->nHeight - 5;
    nActiveHeight -= nActiveHeight % 10;
    const CBlockIndex* refIndex = pindexPrev->GetAncestor(nActiveHeight);
    CHECK_NONFATAL(refIndex != nullptr);

    blockHashHex = pblock->GetHash().GetHex();
    chainId = pblock->GetChainId();
    previousBlockHashHex = pblock->hashPrevBlock.GetHex();
    coinbaseValue = static_cast<int64_t>(pblock->vtx[0]->vout[0].nValue);
    coinbaseScriptHex = HexStr(createScriptPubKey(refIndex->GetBlockHash(), refIndex->nHeight));
    bitsHex = strprintf ("%08x", pblock->nBits);
    blockHeight = nextHeight;
    committedBTCPrevHash = btcpRequired ? btcPrev.hash : std::nullopt;
  }

  UniValue result(UniValue::VOBJ);
  result.pushKV ("hash", blockHashHex);
  result.pushKV ("chainid", chainId);
  result.pushKV ("previousblockhash", previousBlockHashHex);
  result.pushKV ("coinbasevalue", coinbaseValue);
  result.pushKV ("coinbasescript", coinbaseScriptHex);
  result.pushKV ("bits", bitsHex);
  result.pushKV ("height", blockHeight);
  result.pushKV ("_target", HexStr (target));
  if (committedBTCPrevHash.has_value()) {
    result.pushKV("_btcprevhash", committedBTCPrevHash->GetHex());
  }

  return result;
}

bool
AuxpowMiner::submitAuxBlock (const node::JSONRPCRequest& request,
                             const std::string& hashHex,
                             const std::string& auxpowHex) const
{
  auxMiningCheck (request);
  auto& chainman = EnsureAnyChainman (request.nodeContext? request.nodeContext: request.context);

  std::shared_ptr<CBlock> shared_block;
  {
    LOCK (cs);
    const CBlock* pblock = lookupSavedBlock (hashHex);
    shared_block = std::make_shared<CBlock> (*pblock);
  }

  const std::vector<unsigned char> vchAuxPow = ParseHex (auxpowHex);
  CDataStream ss(vchAuxPow, SER_GETHASH, PROTOCOL_VERSION);
  std::unique_ptr<CAuxPow> pow(new CAuxPow ());
  ss >> *pow;
  shared_block->SetAuxpow (std::move (pow));
  CHECK_NONFATAL(shared_block->GetHash ().GetHex () == hashHex);

  return chainman.ProcessNewBlock(shared_block, true, true, nullptr);
}

AuxpowMiner&
AuxpowMiner::get ()
{
  static AuxpowMiner* instance = nullptr;
  static RecursiveMutex lock;

  LOCK (lock);
  if (instance == nullptr)
    instance = new AuxpowMiner ();

  return *instance;
}
