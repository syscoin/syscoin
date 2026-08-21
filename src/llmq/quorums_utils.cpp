// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_utils.h>

#include <chain.h>
#include <chainparams.h>
#include <evo/deterministicmns.h>
#include <hash.h>
#include <sync.h>
#include <unordered_lru_cache.h>

namespace llmq
{
bool CLLMQUtils::IsV19Active(const int nHeight)
{
    return nHeight >= Params().GetConsensus().nV19StartBlock; 
}

std::vector<CDeterministicMNCPtr> CLLMQUtils::GetAllQuorumMembers(const CBlockIndex* pQuorumBaseBlockIndex)
{
    static RecursiveMutex cs_members;
    static unordered_lru_cache<uint256, std::vector<CDeterministicMNCPtr>, StaticSaltedHasher, 10> mapQuorumMembers;
    const auto& legacy_params{Params().GetConsensus().legacyQuorumReplay};
    std::vector<CDeterministicMNCPtr> quorumMembers;
    {
        LOCK(cs_members);
        if (mapQuorumMembers.get(pQuorumBaseBlockIndex->GetBlockHash(), quorumMembers)) {
            return quorumMembers;
        }
    }

    auto allMns = deterministicMNManager->GetListForBlock(pQuorumBaseBlockIndex);
    auto modifier = pQuorumBaseBlockIndex->GetBlockHash();
    quorumMembers = allMns.CalculateQuorum(legacy_params.size, modifier);
    LOCK(cs_members);
    mapQuorumMembers.insert(pQuorumBaseBlockIndex->GetBlockHash(), quorumMembers);
    return quorumMembers;
}

uint256 CLLMQUtils::DeterministicOutboundConnection(const uint256& proTxHash1, const uint256& proTxHash2)
{
    // We need to deterministically select who is going to initiate the connection. The naive way would be to simply
    // return the min(proTxHash1, proTxHash2), but this would create a bias towards MNs with a numerically low
    // hash. To fix this, we return the proTxHash that has the lowest value of:
    //   hash(min(proTxHash1, proTxHash2), max(proTxHash1, proTxHash2), proTxHashX)
    // where proTxHashX is the proTxHash to compare
    uint256 h1;
    uint256 h2;
    if (proTxHash1 < proTxHash2) {
        h1 = ::SerializeHash(std::make_tuple(proTxHash1, proTxHash2, proTxHash1));
        h2 = ::SerializeHash(std::make_tuple(proTxHash1, proTxHash2, proTxHash2));
    } else {
        h1 = ::SerializeHash(std::make_tuple(proTxHash2, proTxHash1, proTxHash1));
        h2 = ::SerializeHash(std::make_tuple(proTxHash2, proTxHash1, proTxHash2));
    }
    if (h1 < h2) {
        return proTxHash1;
    }
    return proTxHash2;
}

} // namespace llmq
