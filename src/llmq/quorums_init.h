// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_INIT_H
#define SYSCOIN_LLMQ_QUORUMS_INIT_H

#include <kernel/cs_main.h> // SYSCOIN: Restore prune locks under cs_main.

class CConnman;
class PeerManager;
class ChainstateManager;
namespace llmq
{

// Initialize the pre-anchor commitment replay shim and PQ finality service.
void InitLLMQSystem(CConnman& connman,
                    PeerManager& peerman,
                    ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);
void DestroyLLMQSystem();

// Manage the PQ ChainLock service lifecycle.
void StartLLMQSystem();
void StopLLMQSystem();
} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_INIT_H
