// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_BLOCKPROCESSOR_H
#define SYSCOIN_LLMQ_QUORUMS_BLOCKPROCESSOR_H

#include <kernel/cs_main.h>
#include <llmq/quorums_commitment.h>

class BlockValidationState;
class CBlock;
class CBlockIndex;

namespace llmq {

/**
 * Compatibility replay parser for legacy on-chain quorum commitments. An
 * unassigned migration profile keeps all legacy blocks replayable; a configured
 * activation height retires this path starting with the PQ-only block. There is
 * deliberately no DKG, P2P, mining, key-share, or signature-verification
 * surface here.
 */
class CQuorumBlockProcessor final {
public:
    CQuorumBlockProcessor() = default;

    bool ProcessBlock(const CBlock& block,
                      const CBlockIndex* index,
                      BlockValidationState& state,
                      CFinalCommitmentTxPayload& commitment,
                      bool just_check,
                      bool check_sigs) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool UndoBlock(const CBlock& block, const CBlockIndex* index) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

private:
    bool GetCommitmentFromBlock(const CBlock& block,
                                uint32_t height,
                                CFinalCommitmentTxPayload& commitment,
                                BlockValidationState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

extern CQuorumBlockProcessor* quorumBlockProcessor;

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_BLOCKPROCESSOR_H
