// Copyright (c) 2017-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_CBTX_H
#define SYSCOIN_EVO_CBTX_H

#include <univalue.h>
#include <llmq/quorums_chainlocks.h>
class CBlock;
class CBlockIndex;
class BlockValidationState;

// coinbase transaction
class CCbTxCLSIG
{
public:
    static constexpr uint16_t CURRENT_VERSION = 2;

public:
    uint16_t nVersion{CURRENT_VERSION};
    llmq::CChainLockSig cl;

public:
    SERIALIZE_METHODS(CCbTxCLSIG, obj) {
        READWRITE(obj.nVersion, obj.cl);
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", (int)nVersion);
        obj.pushKV("chainlock", cl.ToString());
    }
};

bool CheckCbTxBestChainlock(const CBlock& block, const CBlockIndex* pindexPrev, BlockValidationState& state, bool fJustCheck);
bool CalcCbTxBestChainlock(const CBlockIndex* pindexPrev, llmq::CChainLockSig& bestCL);

#endif // SYSCOIN_EVO_CBTX_H
