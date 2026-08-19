// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/validation.h>

#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

void TestChainstateManager::ResetIbd()
{
    m_cached_finished_ibd = false;
    assert(IsInitialBlockDownload());
}

void TestChainstateManager::ResetIbd(PQHistoryAuthState state)
{
    LOCK(cs_main);
    m_cached_finished_ibd.store(false, std::memory_order_relaxed);
    m_pq_history_auth_state = state;
    m_nevm_network_start_sent.store(false, std::memory_order_relaxed);
}

void TestChainstateManager::JumpOutOfIbd()
{
    Assert(IsInitialBlockDownload());
    m_cached_finished_ibd = true;
    Assert(!IsInitialBlockDownload());
}

void ValidationInterfaceTest::BlockConnected(
        ChainstateRole role,
        CValidationInterface& obj,
        const std::shared_ptr<const CBlock>& block,
        const CBlockIndex* pindex)
{
    obj.BlockConnected(role, block, pindex);
}
