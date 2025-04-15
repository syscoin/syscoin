// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_UTILS_H
#define SYSCOIN_LLMQ_QUORUMS_UTILS_H
#include <set>
#include <unordered_set>
#include <vector>
#include <util/strencodings.h>
#include <uint256.h>
#include <saltedhasher.h>
class CBlockIndex;
class CDeterministicMN;
using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;
class CConnman;
namespace llmq
{


class CLLMQUtils
{
public:
    static bool IsV19Active(const int nHeight);
    static const CBlockIndex* V19ActivationIndex(const CBlockIndex* pindex);
    // includes members which failed DKG
    static std::vector<CDeterministicMNCPtr> GetAllQuorumMembers(const CBlockIndex* pindexQuorum);

    static bool IsAllMembersConnectedEnabled();
    static bool IsQuorumPoseEnabled();
    static uint256 DeterministicOutboundConnection(const uint256& proTxHash1, const uint256& proTxHash2);
    static std::unordered_set<uint256, StaticSaltedHasher> GetQuorumConnections(const CBlockIndex* pQuorumBaseBlockIndex, const uint256& forMember, bool onlyOutbound);
    static std::unordered_set<uint256, StaticSaltedHasher> GetQuorumRelayMembers(const CBlockIndex* pQuorumBaseBlockIndex, const uint256& forMember, bool onlyOutbound);
    static std::set<size_t> CalcDeterministicWatchConnections(const CBlockIndex *pQuorumBaseBlockIndex, size_t memberCount, size_t connectionCount);

    static bool EnsureQuorumConnections(const CBlockIndex* pQuorumBaseBlockIndex, const uint256& myProTxHash, CConnman& connman);
    static void AddQuorumProbeConnections(const CBlockIndex* pQuorumBaseBlockIndex, const uint256& myProTxHash, CConnman& connman);

    /// Returns the state of `-watchquorums`
    static bool IsWatchQuorumsEnabled();
    static std::string ToHexStr(const std::vector<bool>& vBits)
    {
        std::vector<uint8_t> vBytes((vBits.size() + 7) / 8);
        for (size_t i = 0; i < vBits.size(); i++) {
            vBytes[i / 8] |= vBits[i] << (i % 8);
        }
        return HexStr(vBytes);
    }

    static std::optional<std::vector<bool>> HexStrToBits(const std::string& hex, size_t expectedBits) {
        const auto vBytes{TryParseHex<uint8_t>(hex)};
        if (!vBytes) {
            return std::nullopt;
        }
        std::vector<bool> vBits(expectedBits);
        for (size_t i = 0; i < vBytes->size(); ++i) {
            for (size_t bit = 0; bit < 8; ++bit) {
                size_t bitIndex = i * 8 + bit;
                if (bitIndex < expectedBits) {
                    vBits[bitIndex] = ((*vBytes)[i] >> bit) & 1;
                }
            }
        }
        return vBits;
    }

};

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_UTILS_H
