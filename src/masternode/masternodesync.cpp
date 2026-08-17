// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governance.h>
#include <init.h>
#include <validation.h>
#include <masternode/masternodesync.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <node/interface_ui.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_chainlocks.h>
#include <shutdown.h>
#include <util/translation.h>
#include <timedata.h>
#include <net.h>
#include <net_processing.h>
#include <node/mempool_persist_args.h>
#include <common/args.h>
#include <algorithm>
#include <limits>
#include <tuple>
using node::ShouldSyncMempool;
class CMasternodeSync;
CMasternodeSync masternodeSync;

static constexpr int64_t GOVERNANCE_PAGE_RESOURCE_RETRY_SECONDS{
    static_cast<int64_t>(
        (GovernancePageBuildRateLimiter::TOKEN_CAPACITY +
         GovernancePageBuildRateLimiter::REFILL_BYTES_PER_SECOND - 1) /
        GovernancePageBuildRateLimiter::REFILL_BYTES_PER_SECOND) + 1};

CMasternodeSync::CMasternodeSync() :
    nTimeAssetSyncStarted(GetTime()),
    nTimeLastBumped(GetTime())
{
    const int64_t now{GetTime()};
    m_last_process_tick.store(now);
    m_last_maintenance_tick.store(now);
}

void CMasternodeSync::SetSyncMode(int mode)
{
    LOCK(m_governance_page_mutex);
    if (nCurrentAsset.load() == mode) return;

    nCurrentAsset = mode;
    m_governance_page_generation.fetch_add(1);
    m_governance_page_sync = GovernancePageSyncState{};
    m_governance_page_sync.reset_tracker_session = true;
}

void CMasternodeSync::Reset(bool fForce, bool fNotifyReset)
{
    // Avoid resetting the sync process if we just "recently" received a new block
    if (!fForce) {
        if (GetTime() - nTimeLastUpdateBlockTip < MASTERNODE_SYNC_RESET_SECONDS) {
            return;
        }
    }
    nTriedPeerCount = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastUpdateBlockTip = 0;
    fReachedBestHeader = false;
    m_next_governance_page_attempt = 0;
    m_governance_page_legacy_fallback = false;
    {
        LOCK(m_governance_page_mutex);
        nCurrentAsset = MASTERNODE_SYNC_BLOCKCHAIN;
        m_governance_page_generation.fetch_add(1);
        m_governance_page_sync = GovernancePageSyncState{};
        // EndPageSession preserves ordinary in-flight relay work, so every
        // reset can safely drain the page tracker even while locally parked.
        m_governance_page_sync.reset_tracker_session = true;
    }
    if (fNotifyReset) {
        uiInterface.NotifyAdditionalDataSyncProgressChanged(-1);
    }
}

void CMasternodeSync::BumpAssetLastTime(const std::string& strFuncName)
{
    if(IsSynced()) return;
    nTimeLastBumped = GetTime();
    LogPrint(BCLog::MNSYNC, "CMasternodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CMasternodeSync::GetAssetName() const
{
    switch(GetAssetID())
    {
        case(MASTERNODE_SYNC_BLOCKCHAIN):   return "MASTERNODE_SYNC_BLOCKCHAIN";
        case(MASTERNODE_SYNC_GOVERNANCE):   return "MASTERNODE_SYNC_GOVERNANCE";
        case MASTERNODE_SYNC_FINISHED:      return "MASTERNODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CMasternodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(GetAssetID())
    {
        case(MASTERNODE_SYNC_BLOCKCHAIN):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - GetAssetStartTime());
            SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
            m_next_governance_page_attempt = 0;
            m_governance_page_legacy_fallback = false;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_GOVERNANCE):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - GetAssetStartTime());
            SetSyncMode(MASTERNODE_SYNC_FINISHED);
            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);

            connman.ForEachNode(AllNodes, [](CNode* pnode) {
                netfulfilledman->AddFulfilledRequest(pnode->addr, "full-sync");
            });
            if (m_next_governance_page_resync.load() <= GetTime()) {
                m_next_governance_page_resync = GetTime() + 30;
            }
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nTriedPeerCount = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CMasternodeSync::SwitchToNextAsset");
}

bilingual_str CMasternodeSync::GetSyncStatus()
{
    switch (GetAssetID()) {
        case MASTERNODE_SYNC_BLOCKCHAIN:    return _("Synchronizing blockchain...");
        case MASTERNODE_SYNC_GOVERNANCE:    return _("Synchronizing governance objects...");
        case MASTERNODE_SYNC_FINISHED:      return _("Synchronization finished");
        default:                            return _("Unknown State");
    }
}

void CMasternodeSync::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv) const
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrint(BCLog::MNSYNC, "SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->GetId());
    }
}

bool CMasternodeSync::IsGovernancePagePumpEligible(
    GovernancePagePumpContext context, uint64_t generation) const
{
    if (generation != m_governance_page_generation.load()) return false;
    if (context == GovernancePagePumpContext::INITIAL_SYNC) {
        return GetAssetID() == MASTERNODE_SYNC_GOVERNANCE;
    }
    return IsSynced() &&
           GetTime() >= m_next_governance_page_resync.load();
}

bool CMasternodeSync::DrainGovernancePageReset(PeerManager& peerman)
{
    bool drain{false};
    {
        LOCK(m_governance_page_mutex);
        if (m_governance_page_sync.reset_tracker_session) {
            m_governance_page_sync = GovernancePageSyncState{};
            drain = true;
        }
    }
    if (drain) peerman.EndGovernancePageSession();
    return drain;
}

void CMasternodeSync::CancelGovernancePageSession(PeerManager& peerman)
{
    {
        LOCK(m_governance_page_mutex);
        m_governance_page_sync = GovernancePageSyncState{};
    }
    // This is unconditional because the reset generation, rather than a
    // potentially stale local lease bit, is the cancellation authority.
    peerman.EndGovernancePageSession();
}

void CMasternodeSync::ProcessGovernancePage(
    CNode* pfrom, const CGovernancePageResponse& response,
    PeerManager& peerman)
{
    if (pfrom == nullptr || !CanUseGovernancePageProtocol(*pfrom)) {
        return;
    }
    if (!peerman.IsGovernancePageRequested(pfrom->GetId(), response)) {
        (void)peerman.RejectGovernancePage(pfrom->GetId(), response);
        return;
    }

    std::vector<CInv> missing;
    bool valid{true};
    bool locally_cancelled{false};
    {
        LOCK(m_governance_page_mutex);
        auto& state{m_governance_page_sync};
        auto& scope{state.scope};
        if (state.reset_tracker_session ||
            state.phase == GovernancePagePhase::IDLE) {
            valid = false;
            locally_cancelled = true;
        } else if (
            state.source_index >= state.sources.size() ||
            state.sources[state.source_index] != pfrom->GetId() ||
            state.pending_response ||
            response.scope_hash != scope.scope_hash) {
            valid = false;
        } else if (response.status == GOVERNANCE_PAGE_OK) {
            const uint64_t prospective_count{
                static_cast<uint64_t>(scope.seen_count) +
                response.inventory.size()};
            if ((scope.established &&
                 (response.view_id != scope.view_id ||
                  response.total_count != scope.total_count)) ||
                (!scope.established && !scope.cursor.IsNull()) ||
                prospective_count > response.total_count ||
                response.done !=
                    (prospective_count == response.total_count) ||
                scope.page_count >= MAX_GOVERNANCE_PAGES_PER_SCOPE ||
                (!scope.transcript.empty() &&
                 !response.inventory.empty() &&
                 !(scope.transcript.back().hash <
                   response.inventory.front().hash))) {
                valid = false;
            }
            if (valid && response.done) {
                std::vector<CInv> transcript{scope.transcript};
                transcript.insert(transcript.end(),
                                  response.inventory.begin(),
                                  response.inventory.end());
                const auto view{ComputeGovernancePageViewHash(
                    scope.scope_hash, transcript)};
                valid = view && *view == response.view_id;
            }
            if (valid) {
                for (const CInv& inv : response.inventory) {
                    const bool have{
                        inv.type == MSG_GOVERNANCE_OBJECT
                            ? governance->HaveObjectForPage(inv.hash)
                            : governance->HaveVoteForPage(
                                  scope.scope_hash, inv.hash)};
                    if (!have) missing.push_back(inv);
                }
            }
        }
        if (valid) state.pending_response = response;
    }

    if (!valid) {
        if (locally_cancelled) return;
        (void)peerman.RejectGovernancePage(pfrom->GetId(), response);
        return;
    }
    if (!peerman.ReceiveGovernancePage(
            pfrom->GetId(), response, missing)) {
        LOCK(m_governance_page_mutex);
        m_governance_page_sync.pending_response.reset();
        return;
    }
    // The scheduler is the sole owner of page-state advancement and asset
    // transitions. A message-handler pump could race a terminal transition,
    // start a replacement tracker lease, and then strand it after FINISHED.
}

void CMasternodeSync::ResetGovernanceScope(const uint256& scope_hash)
{
    AssertLockHeld(m_governance_page_mutex);
    auto& state{m_governance_page_sync};
    state.scope.Reset(scope_hash);
    state.scope.restarts = 0;
    state.pending_response.reset();
}

bool CMasternodeSync::ParkGovernancePageSessionUntil(
    std::chrono::microseconds retry_not_before)
{
    AssertLockHeld(m_governance_page_mutex);
    auto& state{m_governance_page_sync};
    state.scope.retry_not_before = retry_not_before;
    const bool release_tracker_session{state.tracker_session_active};
    state.tracker_session_active = false;
    state.tracker_source = -1;
    return release_tracker_session;
}

CMasternodeSync::GovernanceScopeRetryAction
CMasternodeSync::ScheduleGovernanceScopeRetry(
    std::chrono::microseconds now)
{
    AssertLockHeld(m_governance_page_mutex);
    auto& state{m_governance_page_sync};
    auto& scope{state.scope};
    const std::size_t restarts{
        scope.restarts == std::numeric_limits<std::size_t>::max()
            ? scope.restarts
            : scope.restarts + 1};
    const uint256 scope_hash{scope.scope_hash};
    ResetGovernanceScope(scope_hash);
    scope.restarts = restarts;
    if (restarts <= MAX_GOVERNANCE_VIEW_RESTARTS) {
        return GovernanceScopeRetryAction::RETRY;
    }
    if (restarts > MAX_GOVERNANCE_VIEW_RESTARTS + 1) {
        return GovernanceScopeRetryAction::ADVANCE;
    }

    // One full refill retry lets an honestly depleted server recover without
    // letting canonical TEMP replies hold initial sync active indefinitely.
    (void)ParkGovernancePageSessionUntil(
        now + std::chrono::seconds{GOVERNANCE_PAGE_RESOURCE_RETRY_SECONDS});
    return GovernanceScopeRetryAction::PARK;
}

bool CMasternodeSync::ScheduleGovernancePageSessionAdmissionRetry(
    std::chrono::microseconds now)
{
    AssertLockHeld(m_governance_page_mutex);
    auto& state{m_governance_page_sync};
    if (state.tracker_session_admission_retries >=
        MAX_GOVERNANCE_PAGE_SESSION_ADMISSION_RETRIES) {
        state.tracker_session_admission_retries = 0;
        return false;
    }
    ++state.tracker_session_admission_retries;
    state.scope.retry_not_before = now + std::chrono::seconds{1};
    return true;
}

void CMasternodeSync::AdvanceGovernanceScope(
    GovernancePageSourceOutcome outcome, bool& restart_state,
    bool& complete, bool& temporarily_unavailable,
    bool& unserviceable)
{
    AssertLockHeld(m_governance_page_mutex);
    auto& state{m_governance_page_sync};
    state.tracker_session_admission_retries = 0;
    const bool successful{
        outcome == GovernancePageSourceOutcome::SUCCESS};
    if (successful) ++state.successful_sources_for_scope;
    if (!successful) {
        ++state.failed_sources_for_scope;
        if (outcome ==
            GovernancePageSourceOutcome::SCOPE_TOO_LARGE) {
            ++state.scope_too_large_sources_for_scope;
        }
    }
    if (state.phase == GovernancePagePhase::OBJECTS) {
        if (successful) {
            for (const CInv& inv : state.scope.transcript) {
                state.object_union.insert(inv.hash);
            }
            state.successful_object_sources.push_back(
                state.sources[state.source_index]);
        }
        ++state.source_index;
        if (state.source_index >= state.sources.size()) {
            if (state.successful_sources_for_scope == 0) {
                unserviceable =
                    state.scope_too_large_sources_for_scope ==
                        state.sources.size() &&
                    state.failed_sources_for_scope ==
                        state.sources.size();
                temporarily_unavailable = !unserviceable;
                restart_state = true;
                return;
            }
            const auto local_objects{
                governance->GetGovernancePageObjectHashes()};
            if (local_objects.status != GOVERNANCE_PAGE_OK) {
                unserviceable =
                    local_objects.status ==
                    GOVERNANCE_PAGE_SCOPE_TOO_LARGE;
                temporarily_unavailable = !unserviceable;
                restart_state = true;
                return;
            }
            state.object_union.insert(
                local_objects.hashes.begin(), local_objects.hashes.end());
            // A server only permits vote scopes after that connection has
            // completed its object phase. Keeping failed object sources here
            // would turn every vote scope into a full transfer timeout.
            state.sources = std::move(state.successful_object_sources);
            state.successful_object_sources.clear();
            state.vote_scopes.assign(
                state.object_union.begin(), state.object_union.end());
            state.phase = GovernancePagePhase::VOTES;
            state.source_index = 0;
            state.vote_scope_index = 0;
            state.successful_sources_for_scope = 0;
            state.failed_sources_for_scope = 0;
            state.scope_too_large_sources_for_scope = 0;
            if (state.vote_scopes.empty()) {
                if (!state.reconciliation_pass) {
                    state.reconciliation_pass = true;
                    state.reconciliation_context_epoch =
                        governance->GetPQGovernanceValidationContextEpoch();
                    state.phase = GovernancePagePhase::OBJECTS;
                    state.sources = state.cohort_sources;
                    state.source_index = 0;
                    ResetGovernanceScope(uint256{});
                } else {
                    const auto current_epoch{
                        governance->
                            GetPQGovernanceValidationContextEpoch()};
                    if (!state.reconciliation_context_epoch ||
                        current_epoch !=
                            state.reconciliation_context_epoch) {
                        restart_state = true;
                    } else {
                        complete = true;
                    }
                }
                return;
            }
            ResetGovernanceScope(state.vote_scopes.front());
            return;
        }
        ResetGovernanceScope(uint256{});
        return;
    }

    ++state.source_index;
    if (state.source_index >= state.sources.size()) {
        if (state.successful_sources_for_scope == 0) {
            unserviceable =
                state.scope_too_large_sources_for_scope ==
                    state.sources.size() &&
                state.failed_sources_for_scope ==
                    state.sources.size();
            temporarily_unavailable = !unserviceable;
            restart_state = true;
            return;
        }
        state.source_index = 0;
        state.successful_sources_for_scope = 0;
        state.failed_sources_for_scope = 0;
        state.scope_too_large_sources_for_scope = 0;
        ++state.vote_scope_index;
        if (state.vote_scope_index >= state.vote_scopes.size()) {
            if (!state.reconciliation_pass) {
                state.reconciliation_pass = true;
                state.reconciliation_context_epoch =
                    governance->GetPQGovernanceValidationContextEpoch();
                state.phase = GovernancePagePhase::OBJECTS;
                state.sources = state.cohort_sources;
                state.source_index = 0;
                state.successful_sources_for_scope = 0;
                state.failed_sources_for_scope = 0;
                state.scope_too_large_sources_for_scope = 0;
                ResetGovernanceScope(uint256{});
            } else {
                const auto current_epoch{
                    governance->GetPQGovernanceValidationContextEpoch()};
                if (!state.reconciliation_context_epoch ||
                    current_epoch !=
                        state.reconciliation_context_epoch) {
                    restart_state = true;
                } else {
                    complete = true;
                }
            }
            return;
        }
    }
    ResetGovernanceScope(state.vote_scopes[state.vote_scope_index]);
}

std::vector<CNode*> CMasternodeSync::DeduplicateGovernancePageCandidates(
    std::vector<CNode*> candidates)
{
    std::sort(candidates.begin(), candidates.end(),
              [](const CNode* lhs, const CNode* rhs) {
                  const bool lhs_auth{
                      !lhs->GetVerifiedProRegTxHash().IsNull()};
                  const bool rhs_auth{
                      !rhs->GetVerifiedProRegTxHash().IsNull()};
                  const bool lhs_out{lhs->IsOutboundOrBlockRelayConn()};
                  const bool rhs_out{rhs->IsOutboundOrBlockRelayConn()};
                  const int lhs_rank{lhs_out ? (lhs_auth ? 3 : 2)
                                             : (lhs_auth ? 1 : 0)};
                  const int rhs_rank{rhs_out ? (rhs_auth ? 3 : 2)
                                             : (rhs_auth ? 1 : 0)};
                  return std::tuple{lhs_rank,
                                    lhs->nKeyedNetGroup, lhs->GetId()} >
                         std::tuple{rhs_rank,
                                    rhs->nKeyedNetGroup, rhs->GetId()};
              });
    std::set<std::tuple<uint8_t, uint256, uint64_t, NodeId>> identities;
    std::vector<CNode*> unique_candidates;
    unique_candidates.reserve(candidates.size());
    for (CNode* node : candidates) {
        const uint256 pro_tx{node->GetVerifiedProRegTxHash()};
        const auto identity{!pro_tx.IsNull()
            ? std::tuple<uint8_t, uint256, uint64_t, NodeId>{
                  0, pro_tx, 0, -1}
            : node->nKeyedNetGroup != 0
                ? std::tuple<uint8_t, uint256, uint64_t, NodeId>{
                      1, {}, node->nKeyedNetGroup, -1}
                : std::tuple<uint8_t, uint256, uint64_t, NodeId>{
                      2, {}, 0, node->GetId()}};
        if (identities.insert(identity).second) {
            unique_candidates.push_back(node);
        }
    }
    return unique_candidates;
}

CNode* CMasternodeSync::FindGovernancePageSource(
    const std::vector<CNode*>& eligible_nodes, int64_t id)
{
    const auto it{std::find_if(
        eligible_nodes.begin(), eligible_nodes.end(),
        [&](const CNode* node) { return node->GetId() == id; })};
    return it == eligible_nodes.end() ? nullptr : *it;
}

CMasternodeSync::GovernancePagePumpResult
CMasternodeSync::NoUsableGovernancePageCandidateResult(
    bool has_capable_peer)
{
    return has_capable_peer
        ? GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE
        : GovernancePagePumpResult::NO_CAPABLE_PEERS;
}

CMasternodeSync::GovernancePagePumpResult
CMasternodeSync::PumpGovernancePages(
    CConnman& connman, PeerManager& peerman,
    GovernancePagePumpContext context, uint64_t generation)
{
    if (DrainGovernancePageReset(peerman)) {
        return GovernancePagePumpResult::CANCELLED;
    }
    if (!IsGovernancePagePumpEligible(context, generation)) {
        CancelGovernancePageSession(peerman);
        return GovernancePagePumpResult::CANCELLED;
    }

    const CConnman::NodesSnapshot snap{
        connman, /*filter=*/FullyConnectedOnly};
    bool has_capable_peer{false};
    std::vector<CNode*> eligible_nodes;
    eligible_nodes.reserve(snap.Nodes().size());
    for (CNode* node : snap.Nodes()) {
        if (!CanUseGovernancePageProtocol(*node) ||
            (fMasternodeMode && node->IsInboundConn())) {
            continue;
        }
        // A transient cooldown must not look like an absence of upgraded
        // peers, because only the latter permits lossy legacy fallback.
        has_capable_peer = true;
        if (!peerman.CanUseGovernancePageSource(*node)) continue;
        eligible_nodes.push_back(node);
    }
    auto candidates{DeduplicateGovernancePageCandidates(eligible_nodes)};
    if (candidates.empty()) {
        {
            LOCK(m_governance_page_mutex);
            m_governance_page_sync = GovernancePageSyncState{};
        }
        // This also drains a reset which raced candidate discovery. Ordinary
        // in-flight relay work is deliberately preserved by EndPageSession.
        peerman.EndGovernancePageSession();
        if (!IsGovernancePagePumpEligible(context, generation)) {
            return GovernancePagePumpResult::CANCELLED;
        }
        return NoUsableGovernancePageCandidateResult(has_capable_peer);
    }

    const auto find_node = [&](NodeId id) -> CNode* {
        // Deduplication bounds cohort admission. Once admitted, retain the
        // exact connection while it remains eligible; a later same-netgroup
        // connection must not replace its representative mid-traversal.
        return FindGovernancePageSource(eligible_nodes, id);
    };

    const auto result{peerman.TakeGovernancePageResult()};
    bool progress{false};
    bool complete{false};
    bool restart_state{false};
    bool temporarily_unavailable{false};
    bool unserviceable{false};
    bool finish_tracker_session{false};
    bool cancelled{false};
    std::optional<NodeId> failed_page_source;
    {
        LOCK(m_governance_page_mutex);
        auto& state{m_governance_page_sync};
        if (state.reset_tracker_session ||
            !IsGovernancePagePumpEligible(context, generation)) {
            state = GovernancePageSyncState{};
            cancelled = true;
        }

        if (!cancelled && result &&
            state.phase != GovernancePagePhase::IDLE) {
            progress = true;
            state.FinishMetadataRequest();
            const auto pending{state.pending_response};
            state.pending_response.reset();
            if (!result->success || !pending || !result->response ||
                *pending != *result->response) {
                AdvanceGovernanceScope(
                    GovernancePageSourceOutcome::FAILED,
                    restart_state, complete, temporarily_unavailable,
                    unserviceable);
            } else if (pending->status == GOVERNANCE_PAGE_OK) {
                auto& scope{state.scope};
                if (!scope.established) {
                    scope.established = true;
                    scope.view_id = pending->view_id;
                    scope.total_count = pending->total_count;
                }
                scope.transcript.insert(
                    scope.transcript.end(), pending->inventory.begin(),
                    pending->inventory.end());
                scope.seen_count += pending->inventory.size();
                scope.cursor = pending->next_cursor;
                ++scope.page_count;
                if (pending->done) {
                    AdvanceGovernanceScope(
                        GovernancePageSourceOutcome::SUCCESS,
                        restart_state, complete,
                        temporarily_unavailable, unserviceable);
                }
            } else if (
                pending->status ==
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE) {
                const bool tracker_session_was_active{
                    state.tracker_session_active};
                const auto action{ScheduleGovernanceScopeRetry(
                    GetTime<std::chrono::microseconds>())};
                if (action == GovernanceScopeRetryAction::PARK) {
                    finish_tracker_session |=
                        tracker_session_was_active;
                } else if (
                    action == GovernanceScopeRetryAction::ADVANCE) {
                    AdvanceGovernanceScope(
                        GovernancePageSourceOutcome::
                            TEMPORARILY_UNAVAILABLE,
                        restart_state, complete,
                        temporarily_unavailable, unserviceable);
                }
            } else if (
                pending->status == GOVERNANCE_PAGE_SCOPE_TOO_LARGE) {
                AdvanceGovernanceScope(
                    GovernancePageSourceOutcome::SCOPE_TOO_LARGE,
                    restart_state, complete, temporarily_unavailable,
                    unserviceable);
            } else {
                auto& scope{state.scope};
                const std::size_t restarts{scope.restarts + 1};
                const uint256 scope_hash{scope.scope_hash};
                ResetGovernanceScope(scope_hash);
                scope.restarts = restarts;
                if (restarts > MAX_GOVERNANCE_VIEW_RESTARTS) {
                    failed_page_source = result->source.peer;
                    AdvanceGovernanceScope(
                        GovernancePageSourceOutcome::FAILED,
                        restart_state, complete,
                        temporarily_unavailable, unserviceable);
                }
            }
        }

        if (!cancelled && restart_state) {
            finish_tracker_session |= state.tracker_session_active;
            state = GovernancePageSyncState{};
        }
        if (!cancelled && complete) {
            finish_tracker_session |= state.tracker_session_active;
            state = GovernancePageSyncState{};
        }
    }
    if (cancelled) {
        peerman.EndGovernancePageSession();
        return GovernancePagePumpResult::CANCELLED;
    }
    if (failed_page_source) {
        (void)peerman.FailGovernancePageSource(*failed_page_source);
    }
    if (finish_tracker_session) peerman.EndGovernancePageSession();
    if (restart_state) {
        if (unserviceable) {
            return GovernancePagePumpResult::UNSERVICEABLE;
        }
        return temporarily_unavailable
            ? GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE
            : GovernancePagePumpResult::ACTIVE;
    }
    if (complete) {
        return GovernancePagePumpResult::COMPLETE;
    }
    if (temporarily_unavailable) {
        return GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE;
    }
    if (progress) BumpAssetLastTime("CMasternodeSync::GovernancePage");

    {
        LOCK(m_governance_page_mutex);
        auto& state{m_governance_page_sync};
        if (state.reset_tracker_session ||
            !IsGovernancePagePumpEligible(context, generation)) {
            state = GovernancePageSyncState{};
            cancelled = true;
        }
        if (!cancelled && state.phase == GovernancePagePhase::IDLE) {
            CNode* first{nullptr};
            const std::size_t source_count{std::min(
                MAX_GOVERNANCE_PAGE_SOURCES, candidates.size())};
            const std::size_t start{
                m_governance_page_source_window % candidates.size()};
            m_governance_page_source_window =
                (start + source_count) % candidates.size();
            for (std::size_t offset{0}; offset < candidates.size();
                 ++offset) {
                CNode* node{
                    candidates[(start + offset) % candidates.size()]};
                if (first == nullptr) {
                    if (!peerman.BeginGovernancePageSession(*node)) {
                        continue;
                    }
                    first = node;
                    state.tracker_session_active = true;
                    state.tracker_source = node->GetId();
                }
                state.sources.push_back(node->GetId());
                state.cohort_sources.push_back(node->GetId());
                if (state.sources.size() >= source_count) {
                    break;
                }
            }
            if (first == nullptr) {
                return GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE;
            }
            state.phase = GovernancePagePhase::OBJECTS;
            state.source_index = 0;
            state.successful_sources_for_scope = 0;
            state.scope.Reset(uint256{});
            state.scope.restarts = 0;
        }

        const auto now{GetTime<std::chrono::microseconds>()};
        if (cancelled) {
            // The tracker drain must happen after releasing the page mutex.
        } else if (state.metadata_request_outstanding ||
            state.pending_response ||
            state.source_index >= state.sources.size()) {
            return GovernancePagePumpResult::ACTIVE;
        } else if (state.scope.retry_not_before > now) {
            return GovernancePagePumpResult::ACTIVE;
        } else {
        CNode* source{find_node(state.sources[state.source_index])};
        if (source == nullptr) {
            AdvanceGovernanceScope(
                GovernancePageSourceOutcome::TEMPORARILY_UNAVAILABLE,
                restart_state, complete, temporarily_unavailable,
                unserviceable);
        } else {
            if (!state.tracker_session_active) {
                if (!peerman.BeginGovernancePageSession(*source)) {
                    // Give an ordinary in-flight request one scheduler
                    // heartbeat to finish. A cooldown or persistent admission
                    // conflict must then rotate sources instead of pinning the
                    // exact traversal to this peer indefinitely.
                    if (!ScheduleGovernancePageSessionAdmissionRetry(now)) {
                        AdvanceGovernanceScope(
                            GovernancePageSourceOutcome::
                                TEMPORARILY_UNAVAILABLE,
                            restart_state, complete,
                            temporarily_unavailable, unserviceable);
                    }
                    source = nullptr;
                } else {
                    state.tracker_session_active = true;
                    state.tracker_source = source->GetId();
                }
            } else if (state.tracker_source != source->GetId()) {
                if (!peerman.SetGovernancePageSessionSource(*source)) {
                    AdvanceGovernanceScope(
                        GovernancePageSourceOutcome::
                            TEMPORARILY_UNAVAILABLE,
                        restart_state, complete,
                        temporarily_unavailable, unserviceable);
                    source = nullptr;
                } else {
                    state.tracker_source = source->GetId();
                }
            }

            if (source != nullptr) {
                state.scope.retry_not_before =
                    std::chrono::microseconds{0};
                CGovernancePageRequest request;
                request.scope_hash = state.scope.scope_hash;
                request.cursor = state.scope.cursor;
                request.view_id = state.scope.view_id;
                if (m_next_governance_page_nonce == 0 ||
                    m_next_governance_page_nonce ==
                        std::numeric_limits<uint64_t>::max()) {
                    state.reset_tracker_session = true;
                    state.phase = GovernancePagePhase::IDLE;
                    return GovernancePagePumpResult::ACTIVE;
                }
                request.nonce = m_next_governance_page_nonce++;
                if (!state.TryBeginMetadataRequest()) {
                    return GovernancePagePumpResult::ACTIVE;
                }
                if (peerman.RequestGovernancePage(
                        *source, request,
                        now + GOVERNANCE_PAGE_RESPONSE_TIMEOUT +
                            GOVERNANCE_PAGE_TRANSFER_TIMEOUT)) {
                    state.tracker_session_admission_retries = 0;
                    BumpAssetLastTime(
                        "CMasternodeSync::RequestGovernancePage");
                } else {
                    state.FinishMetadataRequest();
                    // BeginPageSession can succeed while an ordinary request
                    // from another source is still in flight. Bound that same
                    // admission conflict across successful lease acquisition;
                    // otherwise continuous relay could starve exact sync.
                    const bool retry{
                        ScheduleGovernancePageSessionAdmissionRetry(now)};
                    finish_tracker_session |=
                        ParkGovernancePageSessionUntil(
                            now + std::chrono::seconds{1});
                    if (!retry) {
                        AdvanceGovernanceScope(
                            GovernancePageSourceOutcome::
                                TEMPORARILY_UNAVAILABLE,
                            restart_state, complete,
                            temporarily_unavailable, unserviceable);
                    }
                }
            }
        }
        if (restart_state) {
            finish_tracker_session |= state.tracker_session_active;
            state = GovernancePageSyncState{};
        }
        if (complete) {
            finish_tracker_session |= state.tracker_session_active;
            state = GovernancePageSyncState{};
        }
        }
    }
    if (cancelled) {
        peerman.EndGovernancePageSession();
        return GovernancePagePumpResult::CANCELLED;
    }
    if (finish_tracker_session) peerman.EndGovernancePageSession();
    if (restart_state) {
        if (unserviceable) {
            return GovernancePagePumpResult::UNSERVICEABLE;
        }
        return temporarily_unavailable
            ? GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE
            : GovernancePagePumpResult::ACTIVE;
    }
    if (complete) {
        return GovernancePagePumpResult::COMPLETE;
    }
    if (temporarily_unavailable) {
        return GovernancePagePumpResult::TEMPORARILY_UNAVAILABLE;
    }
    return GovernancePagePumpResult::ACTIVE;
}

void CMasternodeSync::ProcessTick(CConnman& connman, PeerManager& peerman)
{
    static int nTick = 0;
    nTick++;

    (void)DrainGovernancePageReset(peerman);

    const static int64_t nSyncStart = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    const static std::string strAllow = strprintf("allow-sync-%lld", nSyncStart);
    const int nMode = GetAssetID();
    const int64_t now{GetTime()};
    const int64_t previous_process{
        m_last_process_tick.exchange(now)};
    // Detect an actual scheduler sleep, not a long-running page traversal.
    if(now >= previous_process &&
       now - previous_process > 60*60 && !fMasternodeMode) {
        LogPrint(BCLog::MNSYNC, "CMasternodeSync::ProcessTick -- WARNING: no actions for too long, restarting sync...\n");
        Reset(true);
        return;
    }

    bool governance_pages_active{false};
    if (GetAssetID() == MASTERNODE_SYNC_GOVERNANCE) {
        if (now < m_next_governance_page_attempt.load()) {
            if (!m_governance_page_legacy_fallback.load()) return;
        } else {
            m_governance_page_legacy_fallback = false;
            constexpr auto context{
                GovernancePagePumpContext::INITIAL_SYNC};
            const uint64_t generation{
                m_governance_page_generation.load()};
            const auto page_result{
                PumpGovernancePages(
                    connman, peerman, context, generation)};
            if (page_result == GovernancePagePumpResult::CANCELLED) {
                return;
            }
            if (!IsGovernancePagePumpEligible(context, generation)) {
                CancelGovernancePageSession(peerman);
                return;
            }
            if (page_result == GovernancePagePumpResult::COMPLETE) {
                m_next_governance_page_resync = now + 5 * 60;
                SwitchToNextAsset(connman);
                return;
            }
            if (page_result == GovernancePagePumpResult::ACTIVE) return;
            if (page_result ==
                GovernancePagePumpResult::UNSERVICEABLE) {
                m_next_governance_page_attempt = now + 5 * 60;
                LogPrintf("CMasternodeSync::ProcessTick -- governance page scope exceeds the bounded service contract\n");
                return;
            }
            if (page_result == GovernancePagePumpResult::
                    TEMPORARILY_UNAVAILABLE) {
                m_next_governance_page_attempt =
                    now + GOVERNANCE_PAGE_RESOURCE_RETRY_SECONDS;
                return;
            }
            m_governance_page_legacy_fallback = true;
            m_next_governance_page_attempt = now + 30;
        }
    } else if (IsSynced() &&
               GetTime() >= m_next_governance_page_resync.load()) {
        constexpr auto context{
            GovernancePagePumpContext::PERIODIC_RESYNC};
        const uint64_t generation{
            m_governance_page_generation.load()};
        const auto page_result{PumpGovernancePages(
            connman, peerman, context, generation)};
        if (page_result == GovernancePagePumpResult::CANCELLED) {
            return;
        }
        if (!IsGovernancePagePumpEligible(context, generation)) {
            CancelGovernancePageSession(peerman);
            return;
        }
        governance_pages_active =
            page_result == GovernancePagePumpResult::ACTIVE;
        if (page_result == GovernancePagePumpResult::COMPLETE) {
            m_next_governance_page_resync = GetTime() + 5 * 60;
        } else if (page_result ==
                   GovernancePagePumpResult::UNSERVICEABLE) {
            m_next_governance_page_resync = now + 5 * 60;
        } else if (page_result ==
                       GovernancePagePumpResult::NO_CAPABLE_PEERS ||
                   page_result == GovernancePagePumpResult::
                       TEMPORARILY_UNAVAILABLE) {
            m_next_governance_page_resync =
                now + GOVERNANCE_PAGE_RESOURCE_RETRY_SECONDS;
        }
    }

    const int64_t previous_maintenance{
        m_last_maintenance_tick.load()};
    if (now >= previous_maintenance &&
        now - previous_maintenance < MASTERNODE_SYNC_TICK_SECONDS) {
        // too early, nothing to do here
        return;
    }

    m_last_maintenance_tick.store(now);
    const CConnman::NodesSnapshot snap{connman, /* filter = */ FullyConnectedOnly};
    // Gradually request the rest of the votes after sync finished and make sure
    // we recover the latest CLSIG after startup if local state is still empty.
    if(IsSynced()) {
        if (!governance_pages_active) {
            governance->RequestGovernanceObjectVotes(
                snap.Nodes(), connman, peerman);
        }
        static int64_t nTimeLastSigSyncRequest = 0;
        const int64_t nNow = GetTime<std::chrono::seconds>().count();
        const bool fNeedCLSIG = llmq::chainLocksHandler &&
                                !llmq::chainLocksHandler->GetBestChainLock();
        if (fNeedCLSIG &&
            nNow - nTimeLastSigSyncRequest >= MASTERNODE_SYNC_TIMEOUT_SECONDS) {
            size_t nRequested = 0;
            for (auto& pnode : snap.Nodes()) {
                if (!pnode->CanRelay() || pnode->IsInboundConn() || pnode->nVersion < PROTOCOL_VERSION) {
                    continue;
                }
                CNetMsgMaker msgMaker(pnode->GetCommonVersion());
                if (fNeedCLSIG) {
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETCLSIG));
                }
                ++nRequested;
            }
            if (nRequested > 0) {
                nTimeLastSigSyncRequest = nNow;
                LogPrint(BCLog::MNSYNC,
                         "CMasternodeSync::ProcessTick -- re-requested CLSIG from %d peer(s)\n",
                         nRequested);
            }
        }
        return;
    }


    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nTriedPeerCount + (nMode - 1) * 8) / (8*4);
    LogPrint(BCLog::MNSYNC, "CMasternodeSync::ProcessTick -- nTick %d nCurrentAsset %d nTriedPeerCount %d nSyncProgress %f\n", nTick, nMode, nTriedPeerCount, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);
    for (auto& pnode : snap.Nodes())
    {
        CNetMsgMaker msgMaker(pnode->GetCommonVersion());

        // Don't try to sync any data from outbound non-relay "masternode" connections.
        // Inbound connection this early is most likely a "masternode" connection
        // initiated from another node, so skip it too.
        if (!pnode->CanRelay() || (fMasternodeMode && pnode->IsInboundConn())) continue;

        // QUICK MODE (REGTEST ONLY!)
        if(fRegTest)
        {
            if (nMode == MASTERNODE_SYNC_BLOCKCHAIN) {
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS)); //get current network sporks
                SwitchToNextAsset(connman);
                // Now that the blockchain is synced request the mempool from the connected outbound nodes if possible
                for (auto pNodeTmp : snap.Nodes()) {
                    bool fRequestedEarlier = netfulfilledman->HasFulfilledRequest(pNodeTmp->addr, "mempool-sync");
                    if (pNodeTmp->nVersion >= PROTOCOL_VERSION && !pNodeTmp->IsInboundConn() && !fRequestedEarlier) {
                        netfulfilledman->AddFulfilledRequest(pNodeTmp->addr, "mempool-sync");
                        connman.PushMessage(pNodeTmp, msgMaker.Make(NetMsgType::GETCLSIG));
                        LogPrint(BCLog::MNSYNC, "CMasternodeSync::ProcessTick -- nTick %d nMode %d -- syncing mempool from peer=%d\n", nTick, nMode, pNodeTmp->GetId());
                    }
                }
                return;
            } else if (nMode == MASTERNODE_SYNC_GOVERNANCE) {
                if (!governance->IsValid()) {
                    SwitchToNextAsset(connman);
                    return;
                }
                // check for timeout first
                if(GetTime() - GetTimeLastBumped() > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    if (nTriedPeerCount == 0) {
                        BumpAssetLastTime(
                            "CMasternodeSync::NoLegacyGovernanceSource");
                        return;
                    }
                    SwitchToNextAsset(connman);
                    return;
                }

                // only request obj sync once from each peer
                if(netfulfilledman->HasFulfilledRequest(pnode->addr, "governance-sync")) {
                    // will request votes on per-obj basis from each node in a separate loop below
                    // to avoid deadlocks here
                    continue;
                }
                if (!SendGovernanceSyncRequest(pnode, connman)) continue;
                netfulfilledman->AddFulfilledRequest(
                    pnode->addr, "governance-sync");
                nTriedPeerCount++;
                continue; //this will cause each peer to get one request each six seconds for the various assets we need
            }
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if ((pnode->HasPermission(NetPermissionFlags::NoBan) || pnode->IsManualConn()) && !netfulfilledman->HasFulfilledRequest(pnode->addr, strAllow)) {
                netfulfilledman->RemoveAllFulfilledRequests(pnode->addr);
                netfulfilledman->AddFulfilledRequest(pnode->addr, strAllow);
                LogPrintf("CMasternodeSync::ProcessTick -- skipping mnsync restrictions for peer=%d\n", pnode->GetId());
            }

            if(netfulfilledman->HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CMasternodeSync::ProcessTick -- disconnecting from recently synced peer=%d\n", pnode->GetId());
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC

            if(!netfulfilledman->HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // always get sporks first, only request once from each peer
                netfulfilledman->AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS));
                LogPrint(BCLog::MNSYNC, "CMasternodeSync::ProcessTick -- nTick %d nMode %d -- requesting sporks from peer=%d\n", nTick, nMode, pnode->GetId());
            }

            if (nMode == MASTERNODE_SYNC_BLOCKCHAIN) {
                int64_t nTimeSyncTimeout = snap.Nodes().size() > 3 ? MASTERNODE_SYNC_TICK_SECONDS : MASTERNODE_SYNC_TIMEOUT_SECONDS;
                if (ReachedBestHeader() && (GetTime() - GetTimeLastBumped() > nTimeSyncTimeout)) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least MASTERNODE_SYNC_TICK_SECONDS/MASTERNODE_SYNC_TIMEOUT_SECONDS
                    //    (depending on the number of connected peers) since we reached the headers tip the last
                    //    time (i.e. since fReachedBestHeader has been set to true);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip)
                    //    for at least MASTERNODE_SYNC_TICK_SECONDS/MASTERNODE_SYNC_TIMEOUT_SECONDS (depending on
                    //    the number of connected peers).
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);
                    bool bShouldSyncMempool = ShouldSyncMempool(gArgs);
                    // Now that the blockchain is synced request the mempool from the connected outbound nodes if possible
                    for (auto pNodeTmp : snap.Nodes()) {
                        bool fRequestedEarlier = netfulfilledman->HasFulfilledRequest(pNodeTmp->addr, "mempool-sync");
                        if (pNodeTmp->nVersion >= PROTOCOL_VERSION && !pNodeTmp->IsInboundConn()) {
                            if (!fRequestedEarlier) {
                                netfulfilledman->AddFulfilledRequest(pNodeTmp->addr, "mempool-sync");
                                if(bShouldSyncMempool) {
                                    connman.PushMessage(pNodeTmp, msgMaker.Make(NetMsgType::MEMPOOL));
                                }
                            }
                            // Keep CLSIG requests independent from mempool-sync bookkeeping.
                            connman.PushMessage(pNodeTmp, msgMaker.Make(NetMsgType::GETCLSIG));
                            LogPrint(BCLog::MNSYNC,
                                     "CMasternodeSync::ProcessTick -- nTick %d nMode %d -- requested CLSIG from peer=%d\n",
                                     nTick, nMode, pNodeTmp->GetId());
                        }
                    }
                }
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS

            if(nMode == MASTERNODE_SYNC_GOVERNANCE) {
                if (!governance->IsValid()) {
                    SwitchToNextAsset(connman);
                    return;
                }
                LogPrint(BCLog::GOBJECT, "CMasternodeSync::ProcessTick -- nTick %d nMode %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nMode, GetTimeLastBumped(), GetTime(), GetTime() - GetTimeLastBumped());

                // check for timeout first
                if(GetTime() - GetTimeLastBumped() > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nMode %d -- timeout\n", nTick, nMode);
                    if(nTriedPeerCount == 0) {
                        LogPrintf("CMasternodeSync::ProcessTick -- WARNING: failed to sync %s\n", GetAssetName());
                        BumpAssetLastTime(
                            "CMasternodeSync::NoLegacyGovernanceSource");
                        return;
                    }
                    SwitchToNextAsset(connman);
                    return;
                }

                // only request obj sync once from each peer
                if(netfulfilledman->HasFulfilledRequest(pnode->addr, "governance-sync")) {
                    // will request votes on per-obj basis from each node in a separate loop below
                    // to avoid deadlocks here
                    continue;
                }
                if (!SendGovernanceSyncRequest(pnode, connman)) continue;
                netfulfilledman->AddFulfilledRequest(
                    pnode->addr, "governance-sync");
                nTriedPeerCount++;

                break; //this will cause each peer to get one request each six seconds for the various assets we need
            }
        }
    }


    if (nCurrentAsset != MASTERNODE_SYNC_GOVERNANCE) {
        return;
    }

    // request votes on per-obj basis from each node
    for (auto& pnode : snap.Nodes()) {
        if(!netfulfilledman->HasFulfilledRequest(pnode->addr, "governance-sync")) {
            continue; // to early for this node
        }
        int nObjsLeftToAsk = governance->RequestGovernanceObjectVotes(pnode, connman, peerman);
        // check for data
        if(nObjsLeftToAsk == 0) {
            static int64_t nTimeNoObjectsLeft = 0;
            static int nLastTick = 0;
            static int nLastVotes = 0;
            if(nTimeNoObjectsLeft == 0) {
                // asked all objects for votes for the first time
                nTimeNoObjectsLeft = GetTime();
            }
            // make sure the condition below is checked only once per tick
            if(nLastTick == nTick) continue;
            if(GetTime() - nTimeNoObjectsLeft > MASTERNODE_SYNC_TIMEOUT_SECONDS &&
                governance->GetVoteCount() - nLastVotes < std::max(int(0.0001 * nLastVotes), MASTERNODE_SYNC_TICK_SECONDS)
            ) {
                // We already asked for all objects, waited for MASTERNODE_SYNC_TIMEOUT_SECONDS
                // after that and less then 0.01% or MASTERNODE_SYNC_TICK_SECONDS
                // (i.e. 1 per second) votes were received during the last tick.
                // We can be pretty sure that we are done syncing.
                LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nCurrentAsset %d -- asked for all objects, nothing to do\n", nTick, MASTERNODE_SYNC_GOVERNANCE);
                // reset nTimeNoObjectsLeft to be able to use the same condition on resync
                nTimeNoObjectsLeft = 0;
                SwitchToNextAsset(connman);
                return;
            }
            nLastTick = nTick;
            nLastVotes = governance->GetVoteCount();
        }
    }
}

bool CMasternodeSync::SendGovernanceSyncRequest(
    CNode* pnode, CConnman& connman)
{
    if (SupportsGovernancePages(pnode->GetCommonVersion())) return false;
    CNetMsgMaker msgMaker(pnode->GetCommonVersion());

    CBloomFilter filter;

    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNGOVERNANCESYNC, uint256(), filter));
    return true;
}

void CMasternodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew)
{
    if (pindexNew == nullptr) {
        return;
    }
    LogPrint(BCLog::MNSYNC, "CMasternodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (IsSynced())
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::NotifyHeaderTip");
    }
}

void CMasternodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, ChainstateManager& chainman, bool fInitialDownload)
{
    LogPrint(BCLog::MNSYNC, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);


    nTimeLastUpdateBlockTip = GetTime<std::chrono::seconds>().count();
    CBlockIndex* pindexTip = WITH_LOCK(cs_main, return chainman.m_best_header);

    if (IsSynced() || !pindexTip || !pindexNew)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset(true);
        }

        // no need to check any further while still in IBD mode
        return;
    }
    // Note: since we sync headers first, it should be ok to use this
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexTip->GetBlockHash();

    if (ReachedBestHeader() && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previously stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset(true);
    }

    fReachedBestHeader = fReachedBestHeaderNew;
    LogPrint(BCLog::MNSYNC, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexTip->nHeight, fInitialDownload, ReachedBestHeader());
}

void CMasternodeSync::DoMaintenance(CConnman &connman, PeerManager& peerman)
{
    if (ShutdownRequested()) return;

    ProcessTick(connman, peerman);
}
