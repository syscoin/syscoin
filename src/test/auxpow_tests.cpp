// Copyright (c) 2014-2020 Daniel Kraft
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <auxpow.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <evo/specialtx.h>
#include <llmq/pq_btcc.h>
#include <validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <rpc/auxpow_miner.h>
#include <rpc/protocol.h>
#include <script/script.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <uint256.h>
#include <univalue.h>
#include <validationinterface.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>
#include <test/util/txmempool.h>

/* No space between BOOST_AUTO_TEST_SUITE and '(', so that extraction of
   the test-suite name works with grep as done in the Makefile.  */
BOOST_AUTO_TEST_SUITE(auxpow_tests)

/* ************************************************************************** */

/**
 * Tamper with a uint256 (modify it).
 * @param num The number to modify.
 */
static void
tamperWith (uint256& num)
{
  arith_uint256 modifiable = UintToArith256 (num);
  modifiable += 1;
  num = ArithToUint256 (modifiable);
}

/**
 * Helper class that is friend to CAuxPow and makes the internals accessible
 * to the test code.
 */
class CAuxPowForTest : public CAuxPow
{

public:

  explicit inline CAuxPowForTest (CTransactionRef txIn)
    : CAuxPow (std::move (txIn))
  {}

  using CAuxPow::coinbaseTx;
  using CAuxPow::vMerkleBranch;
  using CAuxPow::vChainMerkleBranch;
  using CAuxPow::nChainIndex;
  using CAuxPow::parentBlock;

  using CAuxPow::CheckMerkleBranch;

};

/**
 * Utility class to construct auxpow's and manipulate them.  This is used
 * to simulate various scenarios.
 */
class CAuxpowBuilder
{
public:

  /** The parent block (with coinbase, not just header).  */
  CBlock parentBlock;

  /** The auxpow's merkle branch (connecting it to the coinbase).  */
  std::vector<uint256> auxpowChainMerkleBranch;
  /** The auxpow's merkle tree index.  */
  int auxpowChainIndex{-1};

  /**
   * Initialise everything.
   * @param baseVersion The parent block's base version to use.
   * @param chainId The parent block's chain ID to use.
   */
  CAuxpowBuilder (int baseVersion, int chainId);

  /**
   * Set the coinbase's script.
   * @param scr Set it to this script.
   */
  void setCoinbase (const CScript& scr);

  /**
   * Build the auxpow merkle branch.  The member variables will be
   * set accordingly.  This has to be done before constructing the coinbase
   * itself (which must contain the root merkle hash).  When we have the
   * coinbase afterwards, the member variables can be used to initialise
   * the CAuxPow object from it.
   * @param hashAux The merge-mined chain's block hash.
   * @param h Height of the merkle tree to build.
   * @param index Index to use in the merkle tree.
   * @return The root hash, with reversed endian.
   */
  valtype buildAuxpowChain (const uint256& hashAux, unsigned h, int index);

  /**
   * Build the finished CAuxPow object.  We assume that the auxpowChain
   * member variables are already set.  We use the passed in transaction
   * as the base.  It should (probably) be the parent block's coinbase.
   * @param tx The base tx to use.
   * @return The constructed CAuxPow object.
   */
  CAuxPow get (const CTransactionRef tx) const;

  /**
   * Build the finished CAuxPow object from the parent block's coinbase.
   * @return The constructed CAuxPow object.
   */
  inline CAuxPow
  get () const
  {
    assert (!parentBlock.vtx.empty ());
    return get (parentBlock.vtx[0]);
  }

  /**
   * Returns the finished CAuxPow object and returns it as std::unique_ptr.
   */
  inline std::unique_ptr<CAuxPow>
  getUnique () const
  {
    return std::unique_ptr<CAuxPow>(new CAuxPow (get ()));
  }

  /**
   * Build a data vector to be included in the coinbase.  It consists
   * of the aux hash, the merkle tree size and the nonce.  Optionally,
   * the header can be added as well.
   * @param header Add the header?
   * @param auxRoot The aux merkle root hash.
   * @param h Height of the merkle tree.
   * @param nonce The nonce value to use.
   * @return The constructed data.
   */
  static valtype buildCoinbaseData (bool header, const valtype& auxRoot,
                                    unsigned h, int nonce);

};

CAuxpowBuilder::CAuxpowBuilder (int baseVersion, int chainId)
{
  parentBlock.SetBaseVersion(baseVersion, chainId);
}

void
CAuxpowBuilder::setCoinbase (const CScript& scr)
{
  CMutableTransaction mtx;
  mtx.vin.resize (1);
  mtx.vin[0].prevout.SetNull ();
  mtx.vin[0].scriptSig = scr;

  parentBlock.vtx.clear ();
  parentBlock.vtx.push_back (MakeTransactionRef (std::move (mtx)));
  parentBlock.hashMerkleRoot = BlockMerkleRoot (parentBlock);
}

valtype
CAuxpowBuilder::buildAuxpowChain (const uint256& hashAux, unsigned h, int index)
{
  auxpowChainIndex = index;

  /* Just use "something" for the branch.  Doesn't really matter.  */
  auxpowChainMerkleBranch.clear ();
  for (unsigned i = 0; i < h; ++i)
    auxpowChainMerkleBranch.push_back (ArithToUint256 (arith_uint256 (i)));

  const uint256 hash
    = CAuxPowForTest::CheckMerkleBranch (hashAux, auxpowChainMerkleBranch,
                                         index);

  valtype res = ToByteVector (hash);
  std::reverse (res.begin (), res.end ());

  return res;
}

CAuxPow
CAuxpowBuilder::get (const CTransactionRef tx) const
{
  LOCK(cs_main);

  CAuxPowForTest res(tx);
  res.vMerkleBranch = merkle_tests::BlockMerkleBranch (parentBlock, 0);

  res.vChainMerkleBranch = auxpowChainMerkleBranch;
  res.nChainIndex = auxpowChainIndex;
  res.parentBlock = parentBlock;

  return std::move(res);
}

valtype
CAuxpowBuilder::buildCoinbaseData (bool header, const valtype& auxRoot,
                                   unsigned h, int nonce)
{
  valtype res;

  if (header)
    res.insert (res.end (),
                pchMergedMiningHeader,
                pchMergedMiningHeader + sizeof (pchMergedMiningHeader));
  res.insert (res.end (), auxRoot.begin (), auxRoot.end ());

  int size = (1 << h);
  for (int i = 0; i < 4; ++i)
    {
      res.insert (res.end (), size & 0xFF);
      size >>= 8;
    }
  for (int i = 0; i < 4; ++i)
    {
      res.insert (res.end (), nonce & 0xFF);
      nonce >>= 8;
    }

  return res;
}

/* ************************************************************************** */

BOOST_FIXTURE_TEST_CASE (check_auxpow, BasicTestingSetup)
{
  const Consensus::Params& params = Params ().GetConsensus ();
  CAuxpowBuilder builder(5, 42);
  CAuxPow auxpow;

  const uint256 hashAux = ArithToUint256 (arith_uint256(12345));
  const int32_t ourChainId = params.nAuxpowChainId;
  const unsigned height = 30;
  const int nonce = 7;
  int index;

  valtype auxRoot, data;
  CScript scr;

  /* Build a correct auxpow.  The height is the maximally allowed one.  */
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  auxRoot = builder.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder.setCoinbase (scr);
  BOOST_CHECK (builder.get ().check (hashAux, ourChainId, params));

  /* An auxpow without any inputs in the parent coinbase tx should be
     handled gracefully (and be considered invalid).  */
  CMutableTransaction mtx(*builder.parentBlock.vtx[0]);
  mtx.vin.clear ();
  builder.parentBlock.vtx.clear ();
  builder.parentBlock.vtx.push_back (MakeTransactionRef (std::move (mtx)));
  builder.parentBlock.hashMerkleRoot = BlockMerkleRoot (builder.parentBlock);
  BOOST_CHECK (!builder.get ().check (hashAux, ourChainId, params));

  /* Check that the auxpow is invalid if we change either the aux block's
     hash or the chain ID.  */
  uint256 modifiedAux(hashAux);
  tamperWith (modifiedAux);
  BOOST_CHECK (!builder.get ().check (modifiedAux, ourChainId, params));
  BOOST_CHECK (!builder.get ().check (hashAux, ourChainId + 1, params));

  /* Non-coinbase parent tx should fail.  Note that we can't just copy
     the coinbase literally, as we have to get a tx with different hash.  */
  const CTransactionRef oldCoinbase = builder.parentBlock.vtx[0];
  builder.setCoinbase (scr << 5);
  builder.parentBlock.vtx.push_back (oldCoinbase);
  builder.parentBlock.hashMerkleRoot = BlockMerkleRoot (builder.parentBlock);
  auxpow = builder.get (builder.parentBlock.vtx[0]);
  BOOST_CHECK (auxpow.check (hashAux, ourChainId, params));
  auxpow = builder.get (builder.parentBlock.vtx[1]);
  BOOST_CHECK (!auxpow.check (hashAux, ourChainId, params));

  /* The parent chain can't have the same chain ID if its using auxpow.  */
  CAuxpowBuilder builder2(builder);
  builder2.parentBlock.SetChainId (100);
  builder2.parentBlock.SetAuxpowVersion (true);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  builder2.parentBlock.SetChainId (ourChainId);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  // without auxpow parent have whatever it wants in those chain id bits
  builder2.parentBlock.SetAuxpowVersion (false);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  /* Disallow too long merkle branches.  */
  builder2 = builder;
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height + 1);
  auxRoot = builder2.buildAuxpowChain (hashAux, height + 1, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height + 1, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder2.setCoinbase (scr);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Verify that we compare correctly to the parent block's merkle root.  */
  builder2 = builder;
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  tamperWith (builder2.parentBlock.hashMerkleRoot);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Build a non-header legacy version and check that it should be rejected, no backwards compat auxpow unlike NMC, 
  because bridge smart contracts validates auxpow and doesn't have compat fallback, so syscoin consensus needs to enforce.  */
  builder2 = builder;
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  auxRoot = builder2.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (false, auxRoot, height, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder2.setCoinbase (scr);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* However, various attempts at smuggling two roots in should be detected.  */

  const valtype wrongAuxRoot
    = builder2.buildAuxpowChain (modifiedAux, height, index);
  valtype data2
    = CAuxpowBuilder::buildCoinbaseData (false, wrongAuxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data2 = CAuxpowBuilder::buildCoinbaseData (true, wrongAuxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data2 = CAuxpowBuilder::buildCoinbaseData (false, wrongAuxRoot,
                                             height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  /* Verify that the appended nonce/size values are checked correctly.  */

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  data.pop_back ();
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height - 1, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce + 3);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Put the aux hash in an invalid merkle tree position.  */

  auxRoot = builder.buildAuxpowChain (hashAux, height, index + 1);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  auxRoot = builder.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
}

BOOST_FIXTURE_TEST_CASE (auxpow_parent_wrapper_is_not_child_hash_committed,
                         BasicTestingSetup)
{
  const Consensus::Params& params = Params ().GetConsensus ();
  const int32_t ourChainId = params.nAuxpowChainId;
  const uint256 anchor = ArithToUint256 (arith_uint256 (77));

  CBlockHeader child;
  child.SetBaseVersion (2, ourChainId);
  child.SetAuxpowVersion (true);
  child.hashMerkleRoot = ArithToUint256 (arith_uint256 (123));
  const uint256 childHash = child.GetHash ();

  CAuxpowBuilder builder(5, 42);
  builder.parentBlock.hashPrevBlock = anchor;
  const int nonce = 7;
  const unsigned height = 3;
  const int index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  const valtype auxRoot = builder.buildAuxpowChain (childHash, height, index);
  const valtype data = CAuxpowBuilder::buildCoinbaseData (
      true, auxRoot, height, nonce);
  builder.setCoinbase (CScript () << data);

  const CAuxPow first = builder.get ();
  ++builder.parentBlock.nNonce;
  const CAuxPow second = builder.get ();

  BOOST_REQUIRE (first.check (childHash, ourChainId, params));
  BOOST_REQUIRE (second.check (childHash, ourChainId, params));
  BOOST_CHECK (first.getParentPrevBlockHash () == anchor);
  BOOST_CHECK (second.getParentPrevBlockHash () == anchor);
  BOOST_CHECK (first.getParentBlockHash () != second.getParentBlockHash ());
  BOOST_CHECK (child.GetHash () == childHash);
}

/* ************************************************************************** */

/**
 * Mine a block (assuming minimal difficulty) that either matches
 * or doesn't match the difficulty target specified in the block header.
 * @param block The block to mine (by updating nonce).
 * @param ok Whether the block should be ok for PoW.
 * @param nBits Use this as difficulty if specified.
 */
static void
mineBlock (CBlockHeader& block, bool ok, int nBits = -1)
{
  if (nBits == -1)
    nBits = block.nBits;

  arith_uint256 target;
  target.SetCompact (nBits);

  block.nNonce = 0;
  while (true)
    {
      const bool nowOk = (UintToArith256 (block.GetHash ()) <= target);
      if ((ok && nowOk) || (!ok && !nowOk))
        break;

      ++block.nNonce;
    }

  if (ok)
    BOOST_CHECK (CheckProofOfWork (block.GetHash (), nBits, Params().GetConsensus()));
  else
    BOOST_CHECK (!CheckProofOfWork (block.GetHash (), nBits, Params().GetConsensus()));
}

BOOST_FIXTURE_TEST_CASE (auxpow_pow, BasicTestingSetup)
{
  /* Use regtest parameters to allow mining with easy difficulty.  */
  SelectParams (ChainType::REGTEST);
  const Consensus::Params& params = Params ().GetConsensus ();

  const arith_uint256 target = (~arith_uint256 (0) >> 1);
  CBlockHeader block;
  block.nBits = target.GetCompact ();

  /* Verify the block version checks.  */

  block.nVersion = 1;
  mineBlock (block, true);
  BOOST_CHECK (HasValidProofOfWork({block}, params));

  block.nVersion = 2;
  mineBlock (block, true);
  BOOST_CHECK (HasValidProofOfWork({block}, params));

  block.SetBaseVersion (2, params.nAuxpowChainId);
  mineBlock (block, true);
  BOOST_CHECK (HasValidProofOfWork({block}, params));

  block.SetChainId (params.nAuxpowChainId + 1);
  block.SetAuxpowVersion (true);
  mineBlock (block, true);
  BOOST_CHECK (!HasValidProofOfWork({block}, params));

  /* Check the case when the block does not have auxpow (this is true
     right now).  */

  block.SetChainId (params.nAuxpowChainId);
  block.SetAuxpowVersion (true);
  mineBlock (block, true);
  BOOST_CHECK (!HasValidProofOfWork({block}, params));

  block.SetAuxpowVersion (false);
  mineBlock (block, true);
  BOOST_CHECK (HasValidProofOfWork({block}, params));
  mineBlock (block, false);
  BOOST_CHECK (!HasValidProofOfWork({block}, params));

  /* ****************************************** */
  /* Check the case that the block has auxpow.  */

  CAuxpowBuilder builder(5, 42);
  CAuxPow auxpow;
  const int32_t ourChainId = params.nAuxpowChainId;
  const unsigned height = 3;
  const int nonce = 7;
  const int index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  valtype auxRoot, data;

  /* Valid auxpow, PoW check of parent block.  */
  block.SetAuxpowVersion (true);
  auxRoot = builder.buildAuxpowChain (block.GetHash (), height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder.setCoinbase (CScript () << data);
  mineBlock (builder.parentBlock, false, block.nBits);
  block.SetAuxpow (builder.getUnique ());
  BOOST_CHECK (!HasValidProofOfWork({block}, params));
  mineBlock (builder.parentBlock, true, block.nBits);
  block.SetAuxpow (builder.getUnique ());
  BOOST_CHECK (HasValidProofOfWork({block}, params));

  /* Mismatch between auxpow being present and block.nVersion.  Note that
     block.SetAuxpow sets also the version and that we want to ensure
     that the block hash itself doesn't change due to version changes.
     This requires some work arounds.  */
  block.SetAuxpowVersion (false);
  const uint256 hashAux = block.GetHash ();
  auxRoot = builder.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder.setCoinbase (CScript () << data);
  mineBlock (builder.parentBlock, true, block.nBits);
  block.SetAuxpow (builder.getUnique ());
  BOOST_CHECK (hashAux != block.GetHash ());
  block.SetAuxpowVersion (false);
  BOOST_CHECK (hashAux == block.GetHash ());
  BOOST_CHECK (!HasValidProofOfWork({block}, params));

  /* Modifying the block invalidates the PoW.  */
  block.SetAuxpowVersion (true);
  auxRoot = builder.buildAuxpowChain (block.GetHash (), height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder.setCoinbase (CScript () << data);
  mineBlock (builder.parentBlock, true, block.nBits);
  block.SetAuxpow (builder.getUnique ());
  BOOST_CHECK (HasValidProofOfWork({block}, params));
  tamperWith (block.hashMerkleRoot);
  BOOST_CHECK (!HasValidProofOfWork({block}, params));
}

/* ************************************************************************** */

/**
 * Helper class that is friend to AuxpowMiner and makes the tested methods
 * accessible to the test code.
 */
class AuxpowMinerForTest : public AuxpowMiner
{

public:

  using Resolution = AuxpowMiner::BTCPrevResolution;

  using AuxpowMiner::cs;

  using AuxpowMiner::lookupSavedBlock;
  using AuxpowMiner::TemplateMatchesBTCPREV;

  Resolution resolveBTCPrevHash(
      ChainstateManager& chainman,
      const std::optional<uint256>& requested)
  {
    return AuxpowMiner::resolveBTCPrevHash(chainman, requested);
  }

  const CBlock* getCurrentBlock(
      ChainstateManager& chainman, const CTxMemPool& mempool,
      const CScript& scriptPubKey, uint256& target,
      const std::optional<uint256>& btc_prev = std::nullopt)
      EXCLUSIVE_LOCKS_REQUIRED(cs)
  {
    const int32_t next_height{
        WITH_LOCK(cs_main, return chainman.ActiveHeight() + 1)};
    return AuxpowMiner::getCurrentBlock(
        chainman, mempool, scriptPubKey, target,
        Resolution{next_height, btc_prev});
  }

  const CBlock* getCurrentBlockWithResolution(
      ChainstateManager& chainman, const CTxMemPool& mempool,
      const CScript& scriptPubKey, uint256& target,
      const Resolution& resolution) EXCLUSIVE_LOCKS_REQUIRED(cs)
  {
    return AuxpowMiner::getCurrentBlock(
        chainman, mempool, scriptPubKey, target, resolution);
  }

};

// SYSCOIN BEGIN: Helpers for exercising multiple mutable AuxPoW wrappers that
// share one pure child-header identity.
static CBlock BuildAuxpowChildTemplate(
    node::NodeContext& node,
    const std::optional<uint256>& btc_prev = std::nullopt)
{
  CTxMemPool mempool{MemPoolOptionsForTest(node)};
  AuxpowMinerForTest miner;
  CScript script_pub_key;
  uint256 target;
  LOCK(miner.cs);
  const CBlock* block{miner.getCurrentBlock(
      *Assert(node.chainman), mempool, script_pub_key, target, btc_prev)};
  if (block == nullptr) {
    throw std::runtime_error("failed to create AuxPoW child template");
  }
  return *block;
}

static CScript CurrentAuxpowTag(ChainstateManager& chainman)
{
  LOCK(cs_main);
  const CBlockIndex* tip{Assert(chainman.ActiveTip())};
  int ref_height{tip->nHeight - 5};
  ref_height -= ref_height % 10;
  const CBlockIndex* ref{Assert(tip->GetAncestor(ref_height))};
  return AuxpowMiner::createScriptPubKey(ref->GetBlockHash(), ref->nHeight);
}

static std::shared_ptr<CBlock> BuildAuxpowWrapper(
    const CBlock& child,
    const uint256& parent_prev,
    const CScript& syscoin_tag)
{
  auto block{std::make_shared<CBlock>(child)};
  const uint256 child_hash{block->GetHash()};
  CAuxpowBuilder builder{/*baseVersion=*/5, /*chainId=*/42};
  builder.parentBlock.hashPrevBlock = parent_prev;

  constexpr unsigned merkle_height{0};
  constexpr int nonce{7};
  const int index{CAuxPow::getExpectedIndex(
      nonce, Params().GetConsensus().nAuxpowChainId, merkle_height)};
  const valtype aux_root{
      builder.buildAuxpowChain(child_hash, merkle_height, index)};
  const valtype data{CAuxpowBuilder::buildCoinbaseData(
      /*header=*/true, aux_root, merkle_height, nonce)};
  builder.setCoinbase(CScript{} << data);

  CMutableTransaction parent_coinbase{*builder.parentBlock.vtx[0]};
  parent_coinbase.vout.emplace_back(/*nValue=*/0, syscoin_tag);
  builder.parentBlock.vtx[0] =
      MakeTransactionRef(std::move(parent_coinbase));
  builder.parentBlock.hashMerkleRoot = BlockMerkleRoot(builder.parentBlock);
  mineBlock(builder.parentBlock, /*ok=*/true, block->nBits);
  block->SetAuxpow(builder.getUnique());
  block->fChecked = false;
  return block;
}

struct NexusAuxpowWrapperSetup : TestChain100Setup {
  NexusAuxpowWrapperSetup()
      : TestChain100Setup(ChainType::REGTEST,
                          {"-dip3params=101:101"}) {}
};

class AuxpowConnectedObserver final : public CValidationInterface {
public:
  explicit AuxpowConnectedObserver(const uint256& target) : target{target} {}

  void BlockConnected(ChainstateRole,
                      const std::shared_ptr<const CBlock>& block,
                      const CBlockIndex* index) override
  {
    if (index->GetBlockHash() != target) return;
    connected = true;
    if (block->auxpow) {
      had_auxpow = true;
      parent_prev = block->auxpow->getParentPrevBlockHash();
    }
  }

  const uint256 target;
  bool connected{false};
  bool had_auxpow{false};
  uint256 parent_prev;
};
BOOST_FIXTURE_TEST_CASE(
    auxpow_btcp_mismatch_does_not_poison_child_header,
    NexusAuxpowWrapperSetup)
{
  ChainstateManager& chainman{*Assert(m_node.chainman)};
  const uint256 committed{ArithToUint256(arith_uint256{101})};
  const uint256 mismatched{ArithToUint256(arith_uint256{202})};
  CBlock child{BuildAuxpowChildTemplate(m_node)};
  CDataStream btcp_data{SER_NETWORK, PROTOCOL_VERSION};
  btcp_data << BTCPREV_MAGIC_BYTES << committed;
  const auto btcp_bytes{MakeUCharSpan(btcp_data)};
  node::RegenerateCommitments(
      child, chainman,
      std::vector<unsigned char>{btcp_bytes.begin(), btcp_bytes.end()});
  uint256 extracted;
  BOOST_REQUIRE(ExtractBTCPREVCommitment(child, extracted));
  BOOST_REQUIRE(extracted == committed);

  auto& consensus{
      const_cast<Consensus::Params&>(Params().GetConsensus())};
  struct RestoreCandidateOrigin {
    Consensus::Params& consensus;
    const int origin{consensus.nPQBTCCCandidateOrigin};
    ~RestoreCandidateOrigin()
    {
      consensus.nPQBTCCCandidateOrigin = origin;
    }
  } restore{consensus};
  consensus.nPQBTCCCandidateOrigin = 101;
  BOOST_REQUIRE(llmq::pq::IsBTCPREVCommitmentHeight(consensus, 101));

  const CScript tag{CurrentAuxpowTag(chainman)};
  const auto bad{BuildAuxpowWrapper(child, mismatched, tag)};
  const auto good{BuildAuxpowWrapper(child, committed, tag)};
  BOOST_REQUIRE(bad->GetHash() == good->GetHash());

  LOCK(cs_main);
  CBlockIndex* index{nullptr};
  bool is_new{false};
  BlockValidationState bad_state;
  BOOST_REQUIRE(!chainman.AcceptBlock(
      bad, bad_state, &index, /*fRequested=*/true, /*dbp=*/nullptr,
      &is_new, /*min_pow_checked=*/true));
  BOOST_REQUIRE(index != nullptr);
  BOOST_CHECK(bad_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
  BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "bad-btcp-mismatch");
  BOOST_CHECK(!(index->nStatus & BLOCK_FAILED_MASK));
  BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));
  BOOST_CHECK(!is_new);

  BlockValidationState good_state;
  CBlockIndex* good_index{nullptr};
  BOOST_REQUIRE(chainman.AcceptBlock(
      good, good_state, &good_index, /*fRequested=*/true, /*dbp=*/nullptr,
      &is_new, /*min_pow_checked=*/true));
  BOOST_CHECK(good_index == index);
  BOOST_CHECK(is_new);
  BOOST_CHECK(good_index->nStatus & BLOCK_HAVE_DATA);
  BOOST_CHECK(!(good_index->nStatus & BLOCK_FAILED_MASK));
}

BOOST_FIXTURE_TEST_CASE(
    auxpow_known_header_rechecks_first_storable_wrapper,
    NexusAuxpowWrapperSetup)
{
  ChainstateManager& chainman{*Assert(m_node.chainman)};
  const CBlock child{BuildAuxpowChildTemplate(m_node)};
  const uint256 parent_prev{ArithToUint256(arith_uint256{303})};
  const CScript good_tag{CurrentAuxpowTag(chainman)};
  const CScript bad_tag{AuxpowMiner::createScriptPubKey(
      ArithToUint256(arith_uint256{404}), /*nHeight=*/90)};
  const auto good{BuildAuxpowWrapper(child, parent_prev, good_tag)};
  const auto bad{BuildAuxpowWrapper(child, parent_prev, bad_tag)};
  BOOST_REQUIRE(good->GetHash() == bad->GetHash());

  BlockValidationState header_state;
  const CBlockIndex* index{nullptr};
  BOOST_REQUIRE(chainman.ProcessNewBlockHeaders(
      {good->GetBlockHeader()}, /*min_pow_checked=*/true, header_state,
      &index));
  BOOST_REQUIRE(index != nullptr);

  LOCK(cs_main);
  bool is_new{false};
  CBlockIndex* bad_index{nullptr};
  BlockValidationState bad_state;
  BOOST_REQUIRE(!chainman.AcceptBlock(
      bad, bad_state, &bad_index, /*fRequested=*/true, /*dbp=*/nullptr,
      &is_new, /*min_pow_checked=*/true));
  BOOST_CHECK(bad_index == index);
  BOOST_CHECK(bad_state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
  BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "bad-auxpow-tag");
  BOOST_CHECK(!(index->nStatus & BLOCK_FAILED_MASK));
  BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));

  BlockValidationState good_state;
  CBlockIndex* good_index{nullptr};
  BOOST_REQUIRE(chainman.AcceptBlock(
      good, good_state, &good_index, /*fRequested=*/true, /*dbp=*/nullptr,
      &is_new, /*min_pow_checked=*/true));
  BOOST_CHECK(good_index == index);
  BOOST_CHECK(is_new);
  BOOST_CHECK(good_index->nStatus & BLOCK_HAVE_DATA);
  BOOST_CHECK(!(good_index->nStatus & BLOCK_FAILED_MASK));
}

BOOST_FIXTURE_TEST_CASE(
    auxpow_duplicate_activation_uses_persisted_wrapper,
    NexusAuxpowWrapperSetup)
{
  ChainstateManager& chainman{*Assert(m_node.chainman)};
  const CBlock child{BuildAuxpowChildTemplate(m_node)};
  const CScript tag{CurrentAuxpowTag(chainman)};
  const uint256 persisted_parent_prev{
      ArithToUint256(arith_uint256{505})};
  const uint256 alternate_parent_prev{
      ArithToUint256(arith_uint256{606})};
  const CScript alternate_tag{AuxpowMiner::createScriptPubKey(
      ArithToUint256(arith_uint256{707}), /*nHeight=*/90)};
  const auto persisted{
      BuildAuxpowWrapper(child, persisted_parent_prev, tag)};
  const auto alternate{
      BuildAuxpowWrapper(child, alternate_parent_prev, alternate_tag)};
  BOOST_REQUIRE(persisted->GetHash() == alternate->GetHash());

  {
    LOCK(cs_main);
    BlockValidationState state;
    CBlockIndex* index{nullptr};
    bool is_new{false};
    BOOST_REQUIRE(chainman.AcceptBlock(
        persisted, state, &index, /*fRequested=*/true, /*dbp=*/nullptr,
        &is_new, /*min_pow_checked=*/true));
    BOOST_REQUIRE(index != nullptr);
    BOOST_REQUIRE(is_new);
    BOOST_REQUIRE(index->nStatus & BLOCK_HAVE_DATA);
    BOOST_REQUIRE(chainman.ActiveTip()->GetBlockHash() !=
                  persisted->GetHash());
  }

  auto observer{
      std::make_shared<AuxpowConnectedObserver>(persisted->GetHash())};
  RegisterSharedValidationInterface(observer);
  bool is_new{true};
  const bool processed{chainman.ProcessNewBlock(
      alternate, /*force_processing=*/true, /*min_pow_checked=*/true,
      &is_new)};
  SyncWithValidationInterfaceQueue();
  UnregisterSharedValidationInterface(observer);

  BOOST_REQUIRE(processed);
  BOOST_CHECK(!is_new);
  BOOST_REQUIRE(observer->connected);
  BOOST_REQUIRE(observer->had_auxpow);
  BOOST_CHECK(observer->parent_prev == persisted_parent_prev);
  BOOST_CHECK(observer->parent_prev != alternate_parent_prev);
  BOOST_CHECK(WITH_LOCK(cs_main,
                        return chainman.ActiveTip()->GetBlockHash()) ==
              persisted->GetHash());
}
// SYSCOIN END: Mutable AuxPoW wrapper regression coverage.

BOOST_FIXTURE_TEST_CASE (auxpow_miner_blockRegeneration, TestChain100Setup)
{
  CTxMemPool mempool{MemPoolOptionsForTest(m_node)};
  AuxpowMinerForTest miner;
  int64_t nMedianTime;
  {
      LOCK(cs_main);
      nMedianTime = m_node.chainman->ActiveTip()->GetMedianTimePast();
  }
  LOCK (miner.cs);

  /* We use mocktime so that we can control GetTime() as it is used in the
     logic that determines whether or not to reconstruct a block.  The "base"
     time is set such that the blocks we have from the fixture are fresh.  */
  const int64_t baseTime = nMedianTime + 1;
  SetMockTime (baseTime);

  /* Construct a first block.  */
  CScript scriptPubKey;
  uint256 target;
  const CBlock* pblock1 = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock1 != nullptr);
  const uint256 hash1 = pblock1->GetHash ();

  /* Verify target computation.  */
  arith_uint256 expected;
  expected.SetCompact (pblock1->nBits);
  BOOST_CHECK (target == ArithToUint256 (expected));

  /* Calling the method again should return the same, cached block a second
     time (even if we advance the clock, since there are no new
     transactions).  */
  SetMockTime (baseTime + 100);
  const CBlock* pblock = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock == pblock1 && pblock->GetHash () == hash1);

  /* Mine a block, then we should get a new auxpow block constructed.  Note that
     it can be the same *pointer* if the memory was reused after clearing it,
     so we can only verify that the hash is different.  */
  CreateAndProcessBlock ({}, scriptPubKey);
  const CBlock* pblock2 = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock2 != nullptr);
  const uint256 hash2 = pblock2->GetHash ();
  BOOST_CHECK (hash2 != hash1);

  /* Add a new transaction to the mempool.  */
  TestMemPoolEntryHelper entry;
  CMutableTransaction mtx;
  mtx.vout.emplace_back (1234, scriptPubKey);
  {
    LOCK2 (cs_main, mempool.cs);
    mempool.addUnchecked (entry.FromTx (mtx));
  }

  /* We should still get back the cached block, for now.  */
  SetMockTime (baseTime + 160);
  pblock = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock == pblock2 && pblock->GetHash () == hash2);

  /* With time advanced too far, we get a new block.  This time, we should also
     definitely get a different pointer, as there is no clearing.  The old
     blocks are freed only after a new tip is found.  */
  SetMockTime (baseTime + 161);
  const CBlock* pblock3 = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock3 != pblock2 && pblock3->GetHash () != hash2);
}

BOOST_FIXTURE_TEST_CASE (auxpow_miner_createAndLookupBlock, TestChain100Setup)
{
  CTxMemPool mempool{MemPoolOptionsForTest(m_node)};
  AuxpowMinerForTest miner;
  LOCK (miner.cs);

  CScript scriptPubKey;
  uint256 target;
  const CBlock* pblock = miner.getCurrentBlock (*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_CHECK (pblock != nullptr);

  BOOST_CHECK (miner.lookupSavedBlock (pblock->GetHash ().GetHex ()) == pblock);
  BOOST_CHECK_THROW (miner.lookupSavedBlock ("foobar"), UniValue);
}
// SYSCOIN

struct AuxpowCLReceiptOnlySetup : TestChain100Setup {
  AuxpowCLReceiptOnlySetup()
      : TestChain100Setup(ChainType::REGTEST, {"-clreceiptstartheight=0"}) {}
};

BOOST_FIXTURE_TEST_CASE(
    auxpow_miner_btcp_resolution_is_bound_to_exact_next_height,
    TestChain100Setup)
{
  CTxMemPool mempool{MemPoolOptionsForTest(m_node)};
  AuxpowMinerForTest miner;
  CScript script_pub_key;
  uint256 target;
  const uint256 requested{uint256S(std::string(64, '1'))};

  const auto stale_resolution{
      miner.resolveBTCPrevHash(*m_node.chainman, requested)};
  BOOST_REQUIRE_EQUAL(stale_resolution.next_height, 101);
  auto boundary_schedule{
      llmq::pq::GetBTCCScheduleConfig(Params().GetConsensus())};
  // Isolate the height-binding invariant without mutating the complete PQ
  // deployment profile required by block validation.
  boundary_schedule.candidate_origin = 102;
  BOOST_REQUIRE(boundary_schedule.IsValid());
  BOOST_REQUIRE(!llmq::pq::IsBTCCCandidateHeight(
      boundary_schedule, stale_resolution.next_height));
  BOOST_REQUIRE(llmq::pq::IsBTCCCandidateHeight(
      boundary_schedule, /*height=*/102));
  {
    LOCK(miner.cs);
    const CBlock* unscheduled{miner.getCurrentBlockWithResolution(
        *m_node.chainman, mempool, script_pub_key, target,
        stale_resolution)};
    BOOST_REQUIRE(unscheduled != nullptr);
    uint256 committed;
    BOOST_CHECK(!ExtractBTCPREVCommitment(*unscheduled, committed));
  }

  CreateAndProcessBlock({}, script_pub_key);
  BOOST_REQUIRE_EQUAL(
      WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight() + 1), 102);
  const auto tip_changed = [](const UniValue& error) {
    return error["code"].getInt<int>() == RPC_MISC_ERROR &&
           error["message"].get_str() ==
               "Syscoin tip changed while selecting BTCPREV; retry template request";
  };
  {
    LOCK(miner.cs);
    BOOST_CHECK_EXCEPTION(
        miner.getCurrentBlockWithResolution(
            *m_node.chainman, mempool, script_pub_key, target,
            stale_resolution),
        UniValue, tip_changed);
  }

  const auto current_resolution{
      miner.resolveBTCPrevHash(*m_node.chainman, requested)};
  BOOST_REQUIRE_EQUAL(current_resolution.next_height, 102);
  {
    LOCK(miner.cs);
    const CBlock* current{miner.getCurrentBlockWithResolution(
        *m_node.chainman, mempool, script_pub_key, target,
        current_resolution)};
    BOOST_REQUIRE(current != nullptr);
    uint256 committed;
    BOOST_CHECK(!ExtractBTCPREVCommitment(*current, committed));
  }
}

BOOST_FIXTURE_TEST_CASE(auxpow_miner_doesNotEmbedBTCPREVWhenBTCCDisabled, AuxpowCLReceiptOnlySetup)
{
  CTxMemPool mempool{MemPoolOptionsForTest(m_node)};
  AuxpowMinerForTest miner;
  CScript scriptPubKey;

  // CL receipt rules are active, but BTCC remains at its disabled default.
  // Move to height 101 so the next template can be a PQ BTCC candidate.
  CreateAndProcessBlock({}, scriptPubKey);
  const int next_height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height() + 1);
  BOOST_CHECK_EQUAL(next_height, 102);

  LOCK(miner.cs);
  uint256 target;
  const CBlock* pblock = miner.getCurrentBlock(*m_node.chainman, mempool, scriptPubKey, target);
  BOOST_REQUIRE(pblock != nullptr);

  uint256 committed;
  BOOST_CHECK(!ExtractBTCPREVCommitment(*pblock, committed));
}

BOOST_AUTO_TEST_CASE(auxpow_miner_btcp_cache_key_requires_exact_commitment)
{
  const uint256 btc_prev_1 = uint256S(std::string(64, '1'));
  const uint256 btc_prev_2 = uint256S(std::string(64, '2'));
  CDataStream payload{SER_NETWORK, PROTOCOL_VERSION};
  payload << BTCPREV_MAGIC_BYTES << btc_prev_1;
  const auto bytes{MakeUCharSpan(payload)};

  CMutableTransaction coinbase;
  coinbase.vin.resize(1);
  coinbase.vin[0].prevout.SetNull();
  coinbase.vout.emplace_back(
      /*nValue=*/0,
      CScript{} << OP_RETURN <<
          std::vector<unsigned char>{bytes.begin(), bytes.end()});
  CBlock block;
  block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

  BOOST_CHECK(AuxpowMinerForTest::TemplateMatchesBTCPREV(
      &block, /*required=*/false, std::nullopt));
  BOOST_CHECK(!AuxpowMinerForTest::TemplateMatchesBTCPREV(
      nullptr, /*required=*/true, btc_prev_1));
  BOOST_CHECK(!AuxpowMinerForTest::TemplateMatchesBTCPREV(
      &block, /*required=*/true, std::nullopt));
  BOOST_CHECK(AuxpowMinerForTest::TemplateMatchesBTCPREV(
      &block, /*required=*/true, btc_prev_1));
  BOOST_CHECK(!AuxpowMinerForTest::TemplateMatchesBTCPREV(
      &block, /*required=*/true, btc_prev_2));
}

/* ************************************************************************** */

BOOST_AUTO_TEST_SUITE_END ()
