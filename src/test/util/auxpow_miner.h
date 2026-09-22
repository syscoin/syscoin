// Copyright (c) 2014-2020 Daniel Kraft
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_UTIL_AUXPOW_MINER_H
#define SYSCOIN_TEST_UTIL_AUXPOW_MINER_H

#include <rpc/auxpow_miner.h>
#include <validation.h>

namespace auxpow_tests {

/** Expose the real AuxPoW template cache and saved-block lookup to tests. */
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

} // namespace auxpow_tests

#endif // SYSCOIN_TEST_UTIL_AUXPOW_MINER_H
