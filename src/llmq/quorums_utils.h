// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_UTILS_H
#define SYSCOIN_LLMQ_QUORUMS_UTILS_H

#include <util/strencodings.h>
#include <uint256.h>

#include <memory>
#include <vector>

class CBlockIndex;
class CDeterministicMN;
using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;
namespace llmq
{
class CLLMQUtils
{
public:
    static bool IsV19Active(const int nHeight);
    static std::vector<CDeterministicMNCPtr> GetAllQuorumMembers(const CBlockIndex* pindexQuorum);
    static uint256 DeterministicOutboundConnection(const uint256& proTxHash1, const uint256& proTxHash2);
    static std::string ToHexStr(const std::vector<bool>& vBits)
    {
        std::vector<uint8_t> vBytes((vBits.size() + 7) / 8);
        for (size_t i = 0; i < vBits.size(); i++) {
            vBytes[i / 8] |= vBits[i] << (i % 8);
        }
        return HexStr(vBytes);
    }

};

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_UTILS_H
