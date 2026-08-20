// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_blockprocessor.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/pq_migration.h>
#include <consensus/validation.h>
#include <evo/specialtx.h>
#include <primitives/block.h>
#include <validation.h>

namespace llmq {

CQuorumBlockProcessor* quorumBlockProcessor{nullptr};

bool CQuorumBlockProcessor::ProcessBlock(
    const CBlock& block,
    const CBlockIndex* index,
    BlockValidationState& state,
    CFinalCommitmentTxPayload& commitment,
    bool,
    bool) const
{
    AssertLockHeld(cs_main);
    if (index == nullptr) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-null-index");
    }
    commitment = {};
    const auto& consensus{Params().GetConsensus()};
    if (index->nHeight < consensus.nNexusStartBlock) return true;

    if (!GetCommitmentFromBlock(block, index->nHeight, commitment, state)) {
        return false;
    }
    if (commitment.IsNull()) return true;

    if (Consensus::CheckPQLegacyReplay(consensus, index->nHeight) !=
        Consensus::PQLegacyReplayResult::ALLOWED) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-retired");
    }

    const auto& quorum_params{consensus.legacyQuorumReplay};
    if (quorum_params.size <= 0 ||
        quorum_params.size > static_cast<int>(legacy::MAX_QUORUM_MEMBERS) ||
        quorum_params.threshold <= 0 ||
        quorum_params.threshold > quorum_params.size ||
        quorum_params.session_interval <= 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-replay-params");
    }
    const int quorum_height{
        index->nHeight - (index->nHeight % quorum_params.session_interval)};
    const CBlockIndex* quorum_base{
        index->pprev ? index->pprev->GetAncestor(quorum_height) : nullptr};
    if (quorum_base == nullptr ||
        quorum_base->GetBlockHash() != commitment.commitment.quorumHash) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-block-mismatch");
    }
    if (!commitment.commitment.Verify(quorum_base, false)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-structure");
    }
    return true;
}

bool CQuorumBlockProcessor::UndoBlock(const CBlock&, const CBlockIndex*) const
{
    AssertLockHeld(cs_main);
    return true;
}

bool CQuorumBlockProcessor::GetCommitmentFromBlock(
    const CBlock& block,
    uint32_t height,
    CFinalCommitmentTxPayload& commitment,
    BlockValidationState& state) const
{
    commitment = {};
    if (block.vtx.empty() || !block.vtx[0]) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-missing-coinbase");
    }
    if (block.vtx[0]->nVersion !=
        SYSCOIN_TX_VERSION_MN_QUORUM_COMMITMENT) {
        return true;
    }
    if (height < static_cast<uint32_t>(Params().GetConsensus().DIP0003Height)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-premature");
    }
    if (!GetTxPayload(*block.vtx[0], commitment)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-payload");
    }
    if (commitment.nVersion != CFinalCommitmentTxPayload::CURRENT_VERSION) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-cbtx-version");
    }
    if (commitment.nHeight != height) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                             "bad-qc-cbtx-height");
    }
    return true;
}

} // namespace llmq
