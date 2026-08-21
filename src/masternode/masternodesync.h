// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef SYSCOIN_MASTERNODE_MASTERNODESYNC_H
#define SYSCOIN_MASTERNODE_MASTERNODESYNC_H

#include <util/translation.h>
#include <sync.h>
#include <protocol.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <vector>
class CMasternodeSync;
class PeerManager;
class CBlockIndex;
class CConnman;
class CNode;
class CDataStream;
class ChainstateManager;
namespace masternode_sync_tests {
class CMasternodeSyncTestAccess;
}
static constexpr int MASTERNODE_SYNC_BLOCKCHAIN      = 1;
static constexpr int MASTERNODE_SYNC_GOVERNANCE      = 4;
static constexpr int MASTERNODE_SYNC_GOVOBJ          = 10;
static constexpr int MASTERNODE_SYNC_GOVOBJ_VOTE     = 11;
static constexpr int MASTERNODE_SYNC_FINISHED        = 999;

static constexpr int MASTERNODE_SYNC_TICK_SECONDS    = 6;
static constexpr int MASTERNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine
static constexpr int MASTERNODE_SYNC_RESET_SECONDS   = 900; // Reset fReachedBestHeader in CMasternodeSync::Reset if UpdateBlockTip hasn't been called for this seconds

extern CMasternodeSync masternodeSync;

//
// CMasternodeSync : Sync masternode assets in stages
//

class CMasternodeSync
{
    friend class masternode_sync_tests::CMasternodeSyncTestAccess;

private:
    static constexpr std::size_t MAX_GOVERNANCE_PAGE_SOURCES{3};
    static constexpr std::size_t MAX_GOVERNANCE_PAGES_PER_SCOPE{
        (MAX_GOVERNANCE_PAGE_SCOPE_ITEMS +
         MAX_GOVERNANCE_PAGE_INVENTORY - 1) /
        MAX_GOVERNANCE_PAGE_INVENTORY};
    static constexpr std::size_t MAX_GOVERNANCE_VIEW_RESTARTS{4};
    static constexpr std::size_t
        MAX_GOVERNANCE_PAGE_SESSION_ADMISSION_RETRIES{1};

    enum class GovernancePagePhase : uint8_t {
        IDLE,
        OBJECTS,
        VOTES,
    };

    enum class GovernancePageSourceOutcome : uint8_t {
        SUCCESS,
        TEMPORARILY_UNAVAILABLE,
        SCOPE_TOO_LARGE,
        FAILED,
    };

    enum class GovernanceScopeRetryAction : uint8_t {
        RETRY,
        PARK,
        ADVANCE,
    };

    enum class GovernancePagePumpContext : uint8_t {
        INITIAL_SYNC,
        PERIODIC_RESYNC,
    };

    struct GovernanceScopeProgress {
        uint256 scope_hash;
        uint256 cursor;
        uint256 view_id;
        uint32_t total_count{0};
        uint32_t seen_count{0};
        std::size_t page_count{0};
        std::size_t restarts{0};
        std::chrono::microseconds retry_not_before{0};
        bool established{false};
        std::vector<CInv> transcript;

        void Reset(const uint256& scope = {})
        {
            scope_hash = scope;
            cursor.SetNull();
            view_id.SetNull();
            total_count = 0;
            seen_count = 0;
            page_count = 0;
            retry_not_before = std::chrono::microseconds{0};
            established = false;
            transcript.clear();
        }
    };

    struct GovernancePageSyncState {
        GovernancePagePhase phase{GovernancePagePhase::IDLE};
        std::vector<int64_t> cohort_sources;
        std::vector<int64_t> sources;
        std::vector<int64_t> successful_object_sources;
        std::size_t source_index{0};
        std::set<uint256> object_union;
        std::vector<uint256> vote_scopes;
        std::size_t vote_scope_index{0};
        std::size_t successful_sources_for_scope{0};
        std::size_t failed_sources_for_scope{0};
        std::size_t scope_too_large_sources_for_scope{0};
        bool reconciliation_pass{false};
        std::optional<uint64_t> reconciliation_context_epoch;
        GovernanceScopeProgress scope;
        // The tracker owns expiry for an accepted metadata request. Scheduler
        // heartbeats must wait for its terminal result instead of mistaking a
        // duplicate BeginPage rejection for a new admission failure.
        bool metadata_request_outstanding{false};
        std::optional<CGovernancePageResponse> pending_response;
        bool tracker_session_active{false};
        int64_t tracker_source{-1};
        std::size_t tracker_session_admission_retries{0};
        bool reset_tracker_session{false};

        [[nodiscard]] bool TryBeginMetadataRequest() noexcept
        {
            if (metadata_request_outstanding || pending_response) {
                return false;
            }
            metadata_request_outstanding = true;
            return true;
        }

        void FinishMetadataRequest() noexcept
        {
            metadata_request_outstanding = false;
        }
    };

    mutable Mutex m_governance_page_mutex;
    GovernancePageSyncState m_governance_page_sync
        GUARDED_BY(m_governance_page_mutex);
    // GovernanceRequestTracker rejects nonce reuse across sync resets, so the
    // client high-water mark deliberately lives outside the resettable state.
    uint64_t m_next_governance_page_nonce
        GUARDED_BY(m_governance_page_mutex){1};
    std::size_t m_governance_page_source_window
        GUARDED_BY(m_governance_page_mutex){0};
    std::atomic<uint64_t> m_governance_page_generation{1};
    std::atomic<int64_t> m_next_governance_page_attempt{0};
    std::atomic<int64_t> m_next_governance_page_resync{0};
    // Only an actual absence of upgraded peers permits the legacy best-effort
    // path. Transient page backpressure must keep exact sync fail-closed.
    std::atomic<bool> m_governance_page_legacy_fallback{false};

    // Paging is pumped every scheduler call. Keep that heartbeat separate
    // from the six-second cadence used by the legacy maintenance path.
    std::atomic<int64_t> m_last_process_tick{0};
    std::atomic<int64_t> m_last_maintenance_tick{0};

    // Keep track of current asset
    std::atomic<int> nCurrentAsset {MASTERNODE_SYNC_BLOCKCHAIN};
    // Count peers we've requested the asset from
    std::atomic<int> nTriedPeerCount {0};

    // Time when current masternode asset sync started
    std::atomic<int64_t> nTimeAssetSyncStarted {0};
    // ... last bumped
    std::atomic<int64_t> nTimeLastBumped {0};

    /// Set to true if best header is reached in CMasternodeSync::UpdatedBlockTip
    std::atomic<bool> fReachedBestHeader {false};
    /// Last time UpdateBlockTip has been called
    std::atomic<int64_t> nTimeLastUpdateBlockTip {0};

public:
    CMasternodeSync();


    [[nodiscard]] static bool SendGovernanceSyncRequest(
        CNode* pnode, CConnman& connman);

    bool IsBlockchainSynced() const {return nCurrentAsset > MASTERNODE_SYNC_BLOCKCHAIN; }
    bool IsSynced() const { return nCurrentAsset == MASTERNODE_SYNC_FINISHED; }
    void SetSyncMode(int nMode)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);

    int GetAssetID() const {  return nCurrentAsset; }
    int64_t GetLastUpdateBlockTip() const { return nTimeLastUpdateBlockTip; }
    int GetAttempt() const { return nTriedPeerCount; }
    void BumpAssetLastTime(const std::string& strFuncName);
    int64_t GetAssetStartTime() { return nTimeAssetSyncStarted; }
    int64_t GetTimeLastBumped() { return nTimeLastBumped; }
    bool ReachedBestHeader() { return fReachedBestHeader;}
    std::string GetAssetName() const;
    bilingual_str GetSyncStatus();

    void Reset(bool fForce = false, bool fNotifyReset = true)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    void SwitchToNextAsset(CConnman& connman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv) const;
    void ProcessGovernancePage(CNode* pfrom,
                               const CGovernancePageResponse& response,
                               PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    void ProcessTick(CConnman& connman, PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    void NotifyHeaderTip(const CBlockIndex *pindexNew);
    void UpdatedBlockTip(const CBlockIndex *pindexNew,
                         ChainstateManager& chainman,
                         bool fInitialDownload)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);

    void DoMaintenance(CConnman &connman, PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);

private:
    enum class GovernancePagePumpResult : uint8_t {
        CANCELLED,
        NO_CAPABLE_PEERS,
        TEMPORARILY_UNAVAILABLE,
        UNSERVICEABLE,
        ACTIVE,
        COMPLETE,
    };
    GovernancePagePumpResult PumpGovernancePages(
        CConnman& connman, PeerManager& peerman,
        GovernancePagePumpContext context, uint64_t generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    [[nodiscard]] bool IsGovernancePagePumpEligible(
        GovernancePagePumpContext context, uint64_t generation) const;
    [[nodiscard]] bool DrainGovernancePageReset(PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    void CancelGovernancePageSession(PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_governance_page_mutex);
    void ResetGovernanceScope(const uint256& scope_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_governance_page_mutex);
    [[nodiscard]] bool ParkGovernancePageSessionUntil(
        std::chrono::microseconds retry_not_before)
        EXCLUSIVE_LOCKS_REQUIRED(m_governance_page_mutex);
    [[nodiscard]] GovernanceScopeRetryAction ScheduleGovernanceScopeRetry(
        std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(m_governance_page_mutex);
    [[nodiscard]] static std::vector<CNode*>
    DeduplicateGovernancePageCandidates(std::vector<CNode*> candidates);
    [[nodiscard]] static CNode* FindGovernancePageSource(
        const std::vector<CNode*>& eligible_nodes, int64_t id);
    [[nodiscard]] static GovernancePagePumpResult
    NoUsableGovernancePageCandidateResult(bool has_capable_peer);
    [[nodiscard]] bool ScheduleGovernancePageSessionAdmissionRetry(
        std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(m_governance_page_mutex);
    void AdvanceGovernanceScope(
        GovernancePageSourceOutcome outcome, bool& restart_state,
        bool& complete, bool& temporarily_unavailable,
        bool& unserviceable)
        EXCLUSIVE_LOCKS_REQUIRED(m_governance_page_mutex);
};

#endif // SYSCOIN_MASTERNODE_MASTERNODESYNC_H
