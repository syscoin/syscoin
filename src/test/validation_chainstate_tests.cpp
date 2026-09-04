// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <addresstype.h>
#include <consensus/validation.h>
#include <crypto/common.h> // SYSCOIN: PQ authority fixture serialization.
#include <evo/deterministicmns.h> // SYSCOIN: governance authority fixtures.
#include <evo/pq_registry.h> // SYSCOIN: PQ authority snapshot fixtures.
#include <governance/governanceclasses.h>
#include <governance/governanceexceptions.h>
#include <governance/pq_governance_auth.h> // SYSCOIN: PQ governance authorization fixtures.
#include <governance/governancevote.h>
#include <masternode/masternodepayments.h>
#include <masternode/masternodesync.h>
#include <net.h> // SYSCOIN: bounded governance transport fixtures.
#include <net_processing.h> // SYSCOIN: governance peer-state fixtures.
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h> // SYSCOIN: delegated governance signature fixtures.
#include <random.h>
#include <rpc/blockchain.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

// SYSCOIN BEGIN: fork governance/PQ chainstate test dependencies.
#include <algorithm>
#include <array>
#include <atomic>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <thread>
#include <utility>
// SYSCOIN END: fork governance/PQ chainstate test dependencies.
#include <vector>

#include <boost/test/unit_test.hpp>

// SYSCOIN BEGIN: fork governance/PQ test accessors.
namespace governance_tests {

class CGovernanceManagerTestAccess
{
public:
    using AuthorityView =
        std::map<COutPoint, std::pair<uint256, uint32_t>>;

    static void SetReady(CGovernanceManager& manager, bool ready)
    {
        const CBlockIndex* tip{WITH_LOCK(
            manager.chainman.GetMutex(), return manager.chainman.ActiveTip())};
        manager.is_valid.store(true, std::memory_order_release);
        manager.ObserveChainTip(tip);
        if (tip == nullptr) return;
        if (ready) {
            BOOST_REQUIRE(manager.PublishPQGovernanceReadyForTip(*tip));
        } else {
            manager.MarkPQGovernanceUnavailableForTip(*tip);
        }
    }

    static bool AddTriggerAtHeight(
        CGovernanceManager& manager,
        int observed_height,
        CGovernanceObject&& trigger,
        uint256& trigger_hash)
    {
        const auto [active_height, tip] = WITH_LOCK(
            manager.chainman.GetMutex(),
            return (std::pair{manager.chainman.ActiveHeight(),
                              manager.chainman.ActiveTip()}));
        trigger_hash = trigger.GetHash();
        LOCK(manager.cs);
        manager.is_valid.store(true, std::memory_order_release);
        manager.ObserveChainTip(tip);
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE(manager.PublishPQGovernanceReadyForTip(*tip));
        manager.nCachedBlockHeight = observed_height;
        const auto [it, inserted] =
            manager.mapObjects.emplace(trigger_hash, std::move(trigger));
        return inserted &&
            manager.AddNewTrigger(trigger_hash, active_height) ==
                GovernanceTriggerAdmissionResult::ACCEPTED;
    }

    static bool ProcessVoteAtHeight(
        CGovernanceManager& manager,
        int observed_height,
        const CGovernanceVote& vote,
        CGovernanceException& exception,
        CConnman& connman,
        bool* orphan_vote_retained = nullptr)
    {
        const CBlockIndex* tip{WITH_LOCK(
            manager.chainman.GetMutex(), return manager.chainman.ActiveTip())};
        {
            LOCK(manager.cs);
            manager.is_valid.store(true, std::memory_order_release);
            manager.ObserveChainTip(tip);
            BOOST_REQUIRE(tip != nullptr);
            BOOST_REQUIRE(manager.PublishPQGovernanceReadyForTip(*tip));
            manager.nCachedBlockHeight = observed_height;
        }
        return manager.ProcessVote(
            /*pfrom=*/nullptr, vote, exception, connman,
            orphan_vote_retained);
    }

    static bool InsertPreviouslyAdmittedTrigger(
        CGovernanceManager& manager,
        CGovernanceObject&& trigger,
        uint256& trigger_hash)
    {
        trigger_hash = trigger.GetHash();
        const CBlockIndex* tip{WITH_LOCK(
            manager.chainman.GetMutex(), return manager.chainman.ActiveTip())};
        LOCK(manager.cs);
        manager.is_valid.store(true, std::memory_order_release);
        manager.ObserveChainTip(tip);
        BOOST_REQUIRE(tip != nullptr);
        BOOST_REQUIRE(manager.PublishPQGovernanceReadyForTip(*tip));
        const auto [it, inserted] =
            manager.mapObjects.emplace(trigger_hash, std::move(trigger));
        if (!inserted) return false;

        auto superblock = std::make_shared<CSuperblock>(trigger_hash);
        superblock->SetStatus(SeenObjectStatus::Valid);
        return manager.mapTrigger.emplace(
            trigger_hash, std::move(superblock)).second;
    }

    static CSuperblock_sptr GetTrigger(
        CGovernanceManager& manager,
        const uint256& trigger_hash)
    {
        LOCK(manager.cs);
        const auto it = manager.mapTrigger.find(trigger_hash);
        return it == manager.mapTrigger.end() ? nullptr : it->second;
    }

    // SYSCOIN: governance orphan admission regression accessors.
    static std::size_t OrphanVoteCount(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return manager.cmmapOrphanVotes.GetSize();
    }

    static bool StoreOrphanVote(
        CGovernanceManager& manager, const uint256& object_hash,
        const CGovernanceVote& vote, int64_t expiry)
    {
        LOCK(manager.cs);
        return manager.StoreOrphanVote(
            object_hash, vote_time_pair_t{vote, expiry});
    }

    static void CheckOrphanVotes(
        CGovernanceManager& manager, const uint256& object_hash,
        PeerManager& peerman)
    {
        manager.CheckOrphanVotes(object_hash, peerman);
    }

    static constexpr std::size_t MaxOrphanVotes()
    {
        return CGovernanceManager::MAX_ORPHAN_VOTES;
    }

    static constexpr std::size_t MaxOrphanVotesPerObject()
    {
        return CGovernanceManager::MAX_ORPHAN_VOTES_PER_OBJECT;
    }

    static std::string CacheVersion()
    {
        return GovernanceStore::SERIALIZATION_VERSION_STRING;
    }

    static bool OldCacheVersionIsIgnored()
    {
        GovernanceStore store;
        CGovernanceObject object{
            uint256{}, /*revision=*/1, /*time=*/1, uint256{},
            "7b2274797065223a317d"};
        {
            LOCK(store.cs);
            store.mapObjects.emplace(object.GetHash(), object);
        }
        CDataStream legacy{SER_DISK, PROTOCOL_VERSION};
        legacy << std::string{"CGovernanceManager-Version-16"};
        legacy >> store;
        LOCK(store.cs);
        return store.mapObjects.empty();
    }

    static bool BuildAuthorityView(
        const CBlockIndex& tip,
        const CDeterministicMNList& mn_list,
        const llmq::pq::PQRegistrySnapshot& snapshot,
        AuthorityView& view,
        std::string& error)
    {
        CGovernanceManager::pq_authority_map_t authorities;
        CGovernanceManager::delegated_authority_map_t delegated;
        std::size_t valid_mn_count{0};
        if (!CGovernanceManager::BuildPQGovernanceAuthoritySnapshot(
                tip, mn_list, snapshot, authorities, delegated,
                valid_mn_count, error)) {
            view.clear();
            return false;
        }
        view.clear();
        for (const auto& [outpoint, authority] : authorities) {
            view.emplace(
                outpoint,
                std::pair{authority.pro_tx_hash,
                          authority.global_key_version});
        }
        return true;
    }

    static bool BuildDelegatedAuthorityView(
        const CBlockIndex& tip,
        const CDeterministicMNList& mn_list,
        const llmq::pq::PQRegistrySnapshot& snapshot,
        std::size_t& authority_count,
        std::string& error)
    {
        CGovernanceManager::pq_authority_map_t pq_authorities;
        CGovernanceManager::delegated_authority_map_t authorities;
        std::size_t valid_mn_count{0};
        const bool result{
            CGovernanceManager::BuildPQGovernanceAuthoritySnapshot(
                tip, mn_list, snapshot, pq_authorities, authorities,
                valid_mn_count, error)};
        authority_count = authorities.size();
        return result;
    }

    static std::size_t ChangedAuthorityCount(
        const AuthorityView& previous,
        const AuthorityView& next)
    {
        const auto convert = [](const AuthorityView& view) {
            CGovernanceManager::pq_authority_map_t converted;
            for (const auto& [outpoint, authority] : view) {
                converted.emplace(
                    outpoint,
                    CGovernanceManager::PQGovernanceAuthority{
                        authority.first, authority.second});
            }
            return converted;
        };
        return CGovernanceManager::FindChangedPQGovernanceAuthorities(
                   convert(previous), convert(next))
            .size();
    }

    static void RememberAuthorityTip(
        CGovernanceManager& manager,
        const CBlockIndex& tip,
        const AuthorityView& view,
        bool snapshot_valid = true)
    {
        LOCK(manager.cs);
        manager.m_pq_authorities.clear();
        for (const auto& [outpoint, authority] : view) {
            manager.m_pq_authorities.emplace(
                outpoint,
                CGovernanceManager::PQGovernanceAuthority{
                    authority.first, authority.second});
        }
        manager.m_pq_authority_tip_hash = tip.GetBlockHash();
        manager.m_pq_authority_tip_height = tip.nHeight;
        manager.m_pq_authority_snapshot_valid = snapshot_valid;
    }

    struct AuthoritySnapshotCacheStats {
        uint64_t builds{0};
        uint64_t reuses{0};
    };

    static void RememberAuthorityContent(
        CGovernanceManager& manager,
        const CBlockIndex& tip,
        const uint256& dmn_content_hash,
        const uint256& registry_state_root)
    {
        LOCK(manager.cs);
        manager.m_pq_authority_tip_hash = tip.GetBlockHash();
        manager.m_pq_authority_tip_height = tip.nHeight;
        manager.m_pq_authority_snapshot_valid = true;
        manager.m_pq_authority_dmn_content_hash = dmn_content_hash;
        manager.m_pq_authority_registry_state_root = registry_state_root;
        manager.m_pq_trigger_state_initialized = true;
    }

    static bool TryReuseAuthorityContent(
        CGovernanceManager& manager,
        const CBlockIndex& tip,
        const uint256& dmn_content_hash,
        const uint256& registry_state_root)
    {
        LOCK(manager.cs);
        return manager.TryReusePQGovernanceSnapshot(
            tip, dmn_content_hash, registry_state_root);
    }

    static AuthoritySnapshotCacheStats AuthoritySnapshotStats(
        CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return {manager.m_pq_authority_snapshot_builds,
                manager.m_pq_authority_snapshot_reuses};
    }

    static bool IsStraightExtension(
        CGovernanceManager& manager,
        const CBlockIndex& tip)
    {
        LOCK(manager.cs);
        return manager.IsStraightPQGovernanceExtension(tip);
    }

    static bool IsRememberedTip(
        CGovernanceManager& manager,
        const CBlockIndex& tip)
    {
        LOCK(manager.cs);
        return manager.IsRememberedPQGovernanceTip(tip);
    }

    static std::pair<int32_t, uint256> RememberedAuthorityTip(
        CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return {manager.m_pq_authority_tip_height,
                manager.m_pq_authority_tip_hash};
    }

    static uint256 InsertObject(
        CGovernanceManager& manager,
        CGovernanceObject&& object)
    {
        const uint256 hash{object.GetHash()};
        LOCK(manager.cs);
        manager.mapObjects.emplace(hash, std::move(object));
        return hash;
    }

    static void InvalidateObjectPage(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        manager.InvalidateObjectPageCache();
    }

    static std::size_t ObjectCount(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return manager.mapObjects.size();
    }

    static void InsertActiveTriggerMarker(
        CGovernanceManager& manager, const uint256& object_hash)
    {
        LOCK(manager.cs);
        manager.mapTrigger.emplace(
            object_hash, std::make_shared<CSuperblock>());
    }

    static std::size_t ActiveTriggerCount(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return manager.GetActiveTriggers().size();
    }

    static void InsertFutureTriggerForVoting(
        CGovernanceManager& manager, const uint256& trigger_hash,
        int trigger_height)
    {
        LOCK(manager.cs);
        manager.mapObjects.try_emplace(trigger_hash);
        manager.mapTrigger.emplace(
            trigger_hash,
            std::make_shared<CSuperblock>(
                trigger_height, std::vector<CGovernancePayment>{}));
    }

    static void SetVotedFundingYesTrigger(
        CGovernanceManager& manager,
        std::optional<uint256> trigger_hash)
    {
        LOCK(manager.cs);
        manager.votedFundingYesTriggerHash = std::move(trigger_hash);
    }

    static std::vector<uint256> NoFundingTriggerHashes(
        CGovernanceManager& manager, int active_height)
    {
        LOCK(manager.cs);
        manager.nCachedBlockHeight = active_height;
        return manager.GetNoFundingTriggerHashes();
    }

    static bool ObjectHasVote(
        CGovernanceManager& manager, const uint256& object_hash,
        const uint256& vote_hash)
    {
        LOCK(manager.cs);
        auto object{manager.mapObjects.find(object_hash)};
        return object != manager.mapObjects.end() &&
            object->second.GetVoteFile().HasVote(vote_hash);
    }

    static bool InsertVoteForSerializationTest(
        CGovernanceManager& manager, const uint256& object_hash,
        const CGovernanceVote& vote)
    {
        LOCK(manager.cs);
        auto object{manager.mapObjects.find(object_hash)};
        if (object == manager.mapObjects.end()) return false;
        auto& vote_file{const_cast<CGovernanceObjectVoteFile&>(
            object->second.GetVoteFile())};
        vote_file.AddVote(vote);
        return manager.cmapVoteToObject.Insert(
            vote.GetHash(), &object->second);
    }

    static bool PublishReadyForTip(
        CGovernanceManager& manager, const CBlockIndex& tip,
        bool advance_validation_context = false)
    {
        manager.is_valid.store(true, std::memory_order_release);
        return manager.PublishPQGovernanceReadyForTip(
            tip, advance_validation_context);
    }

    static std::optional<uint64_t> ValidationContextEpoch(
        const CGovernanceManager& manager)
    {
        return manager.GetPQGovernanceValidationContextEpoch();
    }

    static bool RebuildTriggerState(
        CGovernanceManager& manager,
        const CBlockIndex& tip,
        const CDeterministicMNList& mn_list,
        const llmq::pq::PQRegistrySnapshot& snapshot,
        bool recompute_cached_flags = true,
        std::set<uint256>* reactivated_triggers = nullptr)
    {
        LOCK(manager.cs);
        return manager.RebuildPQTriggerState(
            tip, mn_list, snapshot,
            recompute_cached_flags,
            reactivated_triggers);
    }

    struct ReconcileResult {
        std::set<uint256> refreshed_objects;
        std::size_t checked_pq_votes{0};
        std::size_t checked_delegated_votes{0};
    };

    static bool ReconcileAuthorityDeltas(
        CGovernanceManager& manager,
        const CBlockIndex& tip,
        const CDeterministicMNList& mn_list,
        const llmq::pq::PQRegistrySnapshot& snapshot,
        const std::set<COutPoint>& changed_pq_operators,
        const std::set<COutPoint>& changed_delegated_operators,
        const std::set<uint256>& reactivated_triggers,
        ReconcileResult& result)
    {
        LOCK(manager.cs);
        result = {};
        return manager.ReconcileGovernanceVotes(
            tip, mn_list, snapshot,
            /*full_revalidation=*/false,
            changed_pq_operators, changed_delegated_operators,
            reactivated_triggers, result.refreshed_objects,
            result.checked_pq_votes,
            result.checked_delegated_votes);
    }

    static bool RebuildIndexes(CGovernanceManager& manager)
    {
        return manager.RebuildIndexes();
    }

    static std::pair<std::size_t, std::size_t> TriggerStateCounts(
        CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return {manager.mapTrigger.size(),
                manager.m_pq_inactive_triggers.size()};
    }

    static bool IsCachedDelete(
        CGovernanceManager& manager, const uint256& object_hash)
    {
        LOCK(manager.cs);
        const auto it{manager.mapObjects.find(object_hash)};
        return it == manager.mapObjects.end() ||
            it->second.IsSetCachedDelete();
    }

    static bool IsCachedDeleteByVotes(
        CGovernanceManager& manager, const uint256& object_hash)
    {
        LOCK(manager.cs);
        const auto it{manager.mapObjects.find(object_hash)};
        return it != manager.mapObjects.end() &&
            it->second.IsSetCachedDeleteByVotes();
    }

    static void RefreshObjectFlags(
        CGovernanceManager& manager, const uint256& object_hash,
        const CDeterministicMNList& mn_list)
    {
        LOCK(manager.cs);
        const auto it{manager.mapObjects.find(object_hash)};
        BOOST_REQUIRE(it != manager.mapObjects.end());
        it->second.UpdateSentinelVariables(
            mn_list, /*reset_vote_caused_deletion=*/true);
    }

    static void RememberValidMNCount(
        CGovernanceManager& manager, std::size_t count)
    {
        LOCK(manager.cs);
        manager.m_governance_valid_mn_count = count;
    }

    static std::size_t RememberedValidMNCount(
        CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return manager.m_governance_valid_mn_count;
    }

    static void SetTriggerStatus(
        CGovernanceManager& manager, const uint256& object_hash,
        SeenObjectStatus status)
    {
        LOCK(manager.cs);
        const auto it{manager.mapTrigger.find(object_hash)};
        BOOST_REQUIRE(it != manager.mapTrigger.end());
        BOOST_REQUIRE(it->second != nullptr);
        it->second->SetStatus(status);
    }

    static SeenObjectStatus TriggerStatus(
        CGovernanceManager& manager, const uint256& object_hash)
    {
        LOCK(manager.cs);
        const auto it{manager.mapTrigger.find(object_hash)};
        BOOST_REQUIRE(it != manager.mapTrigger.end());
        BOOST_REQUIRE(it->second != nullptr);
        return it->second->GetStatus();
    }

    static constexpr uint64_t MaxPersistedVoteBytes()
    {
        return CGovernanceManager::MAX_PERSISTED_VOTE_BYTES;
    }

    static uint64_t VoteBytes(const CGovernanceVote& vote)
    {
        return CGovernanceManager::PersistedVoteBytes(vote);
    }

    static void SetPersistedVoteBytes(
        CGovernanceManager& manager, uint64_t bytes)
    {
        LOCK(manager.cs);
        manager.m_persisted_vote_bytes = bytes;
    }

    static uint64_t PersistedVoteBytes(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        return manager.m_persisted_vote_bytes;
    }

    static GovernanceObjectAdmissionResult AddObject(
        CGovernanceManager& manager, CGovernanceObject& object,
        PeerManager& peerman) NO_THREAD_SAFETY_ANALYSIS
    {
        return manager.AddGovernanceObject(object, peerman);
    }

    static void ClearOrphanVotes(CGovernanceManager& manager)
    {
        LOCK(manager.cs);
        manager.cmmapOrphanVotes.Clear();
        BOOST_REQUIRE(manager.RebuildPersistedVoteBytes());
    }
};

} // namespace governance_tests
// SYSCOIN END: fork governance/PQ test accessors.

// SYSCOIN BEGIN: fork governance-page sync test accessors.
namespace masternode_sync_tests {

class CMasternodeSyncTestAccess
{
public:
    struct AdvanceResult {
        bool restart_state{false};
        bool complete{false};
        bool temporarily_unavailable{false};
        bool unserviceable{false};
    };

    struct RetryResult {
        bool release_tracker_session{false};
        bool advance_scope{false};
        bool restart_state{false};
        bool temporarily_unavailable{false};
        bool tracker_session_active{false};
        int64_t tracker_source{-1};
        std::size_t source_index{0};
        std::size_t restarts{0};
        std::size_t session_admission_retries{0};
        std::chrono::microseconds retry_not_before{0};
    };

    static uint64_t PrepareInitialPagePump(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        sync.nCurrentAsset = MASTERNODE_SYNC_GOVERNANCE;
        sync.m_governance_page_sync =
            CMasternodeSync::GovernancePageSyncState{};
        return sync.m_governance_page_generation.load();
    }

    static bool IsInitialPagePumpEligible(
        const CMasternodeSync& sync, uint64_t generation)
    {
        return sync.IsGovernancePagePumpEligible(
            CMasternodeSync::GovernancePagePumpContext::INITIAL_SYNC,
            generation);
    }

    static uint64_t PreparePeriodicPagePump(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        sync.nCurrentAsset = MASTERNODE_SYNC_FINISHED;
        sync.m_next_governance_page_resync = GetTime() - 1;
        sync.m_governance_page_sync =
            CMasternodeSync::GovernancePageSyncState{};
        return sync.m_governance_page_generation.load();
    }

    static bool IsPeriodicPagePumpEligible(
        const CMasternodeSync& sync, uint64_t generation)
    {
        return sync.IsGovernancePagePumpEligible(
            CMasternodeSync::GovernancePagePumpContext::PERIODIC_RESYNC,
            generation);
    }

    static void DeferPeriodicPagePump(CMasternodeSync& sync)
    {
        sync.m_next_governance_page_resync = GetTime() + 60;
    }

    static bool ResetDrainPending(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.reset_tracker_session;
    }

    static void ConsumeResetMarker(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        BOOST_REQUIRE(
            sync.m_governance_page_sync.reset_tracker_session);
        sync.m_governance_page_sync =
            CMasternodeSync::GovernancePageSyncState{};
    }

    static void StartObjectPass(
        CMasternodeSync& sync, std::vector<int64_t> sources)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        state = CMasternodeSync::GovernancePageSyncState{};
        state.phase = CMasternodeSync::GovernancePagePhase::OBJECTS;
        state.cohort_sources = sources;
        state.sources = std::move(sources);
        state.scope.Reset(uint256{});
    }

    static std::vector<CNode*> DeduplicatePageCandidates(
        std::vector<CNode*> candidates)
    {
        return CMasternodeSync::DeduplicateGovernancePageCandidates(
            std::move(candidates));
    }

    static CNode* FindPageSource(
        const std::vector<CNode*>& eligible_nodes, int64_t id)
    {
        return CMasternodeSync::FindGovernancePageSource(
            eligible_nodes, id);
    }

    static bool NoUsablePageCandidatesAreTemporary(
        bool has_capable_peer)
    {
        const auto result{
            CMasternodeSync::NoUsableGovernancePageCandidateResult(
                has_capable_peer)};
        return result == CMasternodeSync::GovernancePagePumpResult::
            TEMPORARILY_UNAVAILABLE;
    }

    static AdvanceResult AdvanceObjectSource(
        CMasternodeSync& sync, bool success,
        std::optional<uint256> received_hash = std::nullopt)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        if (received_hash) {
            state.scope.transcript.emplace_back(
                MSG_GOVERNANCE_OBJECT, *received_hash);
        }
        AdvanceResult result;
        sync.AdvanceGovernanceScope(
            success
                ? CMasternodeSync::GovernancePageSourceOutcome::SUCCESS
                : CMasternodeSync::GovernancePageSourceOutcome::FAILED,
            result.restart_state, result.complete,
            result.temporarily_unavailable, result.unserviceable);
        return result;
    }

    static AdvanceResult CompleteFinalVoteScope(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        state.vote_scope_index = state.vote_scopes.size() - 1;
        state.source_index = state.sources.size() - 1;
        AdvanceResult result;
        sync.AdvanceGovernanceScope(
            CMasternodeSync::GovernancePageSourceOutcome::SUCCESS,
            result.restart_state, result.complete,
            result.temporarily_unavailable, result.unserviceable);
        return result;
    }

    static void SetTrackerSession(CMasternodeSync& sync, int64_t source)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        state.tracker_session_active = true;
        state.tracker_source = source;
        state.scope.retry_not_before = std::chrono::microseconds{0};
    }

    static bool SetMetadataRequestOutstanding(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.TryBeginMetadataRequest();
    }

    static void FinishMetadataRequest(CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        sync.m_governance_page_sync.FinishMetadataRequest();
    }

    static bool MetadataRequestOutstanding(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.metadata_request_outstanding;
    }

    static RetryResult ScheduleTemporaryUnavailable(
        CMasternodeSync& sync, std::chrono::microseconds now)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        RetryResult result;
        const bool tracker_session_was_active{
            state.tracker_session_active};
        const auto action{sync.ScheduleGovernanceScopeRetry(now)};
        result.release_tracker_session =
            tracker_session_was_active &&
            action == CMasternodeSync::GovernanceScopeRetryAction::PARK;
        result.advance_scope =
            action == CMasternodeSync::GovernanceScopeRetryAction::ADVANCE;
        if (result.advance_scope) {
            bool complete{false};
            bool unserviceable{false};
            sync.AdvanceGovernanceScope(
                CMasternodeSync::GovernancePageSourceOutcome::
                    TEMPORARILY_UNAVAILABLE,
                result.restart_state, complete,
                result.temporarily_unavailable, unserviceable);
            if (result.restart_state) {
                result.release_tracker_session |=
                    state.tracker_session_active;
                state = CMasternodeSync::GovernancePageSyncState{};
            }
        }
        result.tracker_session_active = state.tracker_session_active;
        result.tracker_source = state.tracker_source;
        result.source_index = state.source_index;
        result.restarts = state.scope.restarts;
        result.retry_not_before = state.scope.retry_not_before;
        return result;
    }

    static RetryResult ParkFailedPageRequest(
        CMasternodeSync& sync, std::chrono::microseconds now)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        RetryResult result;
        const bool retry{
            sync.ScheduleGovernancePageSessionAdmissionRetry(now)};
        result.release_tracker_session =
            sync.ParkGovernancePageSessionUntil(
                now + std::chrono::seconds{1});
        result.advance_scope = !retry;
        if (result.advance_scope) {
            bool complete{false};
            bool unserviceable{false};
            sync.AdvanceGovernanceScope(
                CMasternodeSync::GovernancePageSourceOutcome::
                    TEMPORARILY_UNAVAILABLE,
                result.restart_state, complete,
                result.temporarily_unavailable, unserviceable);
            if (result.restart_state) {
                state = CMasternodeSync::GovernancePageSyncState{};
            }
        }
        result.tracker_session_active = state.tracker_session_active;
        result.tracker_source = state.tracker_source;
        result.source_index = state.source_index;
        result.restarts = state.scope.restarts;
        result.session_admission_retries =
            state.tracker_session_admission_retries;
        result.retry_not_before = state.scope.retry_not_before;
        return result;
    }

    static RetryResult ScheduleSessionAdmissionFailure(
        CMasternodeSync& sync, std::chrono::microseconds now)
    {
        LOCK(sync.m_governance_page_mutex);
        auto& state{sync.m_governance_page_sync};
        RetryResult result;
        const bool retry{
            sync.ScheduleGovernancePageSessionAdmissionRetry(now)};
        result.advance_scope = !retry;
        if (result.advance_scope) {
            bool complete{false};
            bool unserviceable{false};
            sync.AdvanceGovernanceScope(
                CMasternodeSync::GovernancePageSourceOutcome::
                    TEMPORARILY_UNAVAILABLE,
                result.restart_state, complete,
                result.temporarily_unavailable, unserviceable);
            if (result.restart_state) {
                state = CMasternodeSync::GovernancePageSyncState{};
            }
        }
        result.tracker_session_active = state.tracker_session_active;
        result.tracker_source = state.tracker_source;
        result.source_index = state.source_index;
        result.restarts = state.scope.restarts;
        result.session_admission_retries =
            state.tracker_session_admission_retries;
        result.retry_not_before = state.scope.retry_not_before;
        return result;
    }

    static std::size_t ImmediateTemporaryRetries()
    {
        return CMasternodeSync::MAX_GOVERNANCE_VIEW_RESTARTS;
    }

    static bool IsIdleAndEmpty(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        const auto& state{sync.m_governance_page_sync};
        return state.phase == CMasternodeSync::GovernancePagePhase::IDLE &&
               state.sources.empty() && state.cohort_sources.empty() &&
               !state.metadata_request_outstanding &&
               !state.tracker_session_active &&
               state.scope.retry_not_before ==
                   std::chrono::microseconds{0};
    }

    static std::vector<int64_t> Sources(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.sources;
    }

    static std::vector<uint256> VoteScopes(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.vote_scopes;
    }

    static bool IsObjectReconciliation(const CMasternodeSync& sync)
    {
        LOCK(sync.m_governance_page_mutex);
        return sync.m_governance_page_sync.phase ==
                   CMasternodeSync::GovernancePagePhase::OBJECTS &&
               sync.m_governance_page_sync.reconciliation_pass;
    }
};

} // namespace masternode_sync_tests
// SYSCOIN END: fork governance-page sync test accessors.

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /* cache_size_bytes */ 1 << 23, /* in_memory */ true, /* should_wipe */ false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    BOOST_REQUIRE(c1.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(c1.CoinsTip());

        // SYSCOIN: Set a real indexed best block so recovery-marker validation
        // permits this inherited cache-resize flush path.
        c1.CoinsTip().SetBestBlock(
            Params().GetConsensus().hashGenesisBlock);

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 24,  // upsizing the coinsview cache
            1 << 22  // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 22,  // downsizing the coinsview cache
            1 << 23  // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    uint256 curr_tip = ::g_best_block;

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlockFromDisk(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = ::g_best_block;

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    curr_tip = ::g_best_block;

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2U);

    Chainstate& background_cs{*[&] {
        for (Chainstate* cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        assert(false);
    }()};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // g_best_block should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, ::g_best_block);
}

// SYSCOIN BEGIN: fork governance and PQ finality chainstate regressions.
BOOST_FIXTURE_TEST_CASE(
    superblock_first_adaptive_cycle_uses_default_budget_only,
    TestChain100Setup)
{
    auto& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct DIP3HeightGuard {
        Consensus::Params& consensus;
        const int old_height;
        ~DIP3HeightGuard() { consensus.DIP0003Height = old_height; }
    } dip3_guard{consensus, consensus.DIP0003Height};
    consensus.DIP0003Height = 1;

    int before_first{0};
    int first_height{0};
    CSuperblock::GetNearestSuperblocksHeights(
        /*nBlockHeight=*/0, before_first, first_height);
    BOOST_REQUIRE_EQUAL(before_first, 0);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(first_height));

    int last_height{0};
    int second_height{0};
    CSuperblock::GetNearestSuperblocksHeights(
        first_height, last_height, second_height);
    BOOST_REQUIRE_EQUAL(last_height, first_height);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(second_height));

    const CBlockIndex* first_index;
    const CBlockIndex* second_index;
    {
        LOCK(::cs_main);
        first_index = m_node.chainman->ActiveChain()[first_height];
        second_index = m_node.chainman->ActiveChain()[second_height];
    }
    BOOST_REQUIRE(first_index != nullptr);
    BOOST_REQUIRE(second_index != nullptr);
    BOOST_REQUIRE(first_index->pprev != nullptr);
    BOOST_CHECK_EQUAL(CSuperblock::GetPaymentsLimit(nullptr),
                      CSuperblock::SUPERBLOCK_BUDGET);
    BOOST_CHECK_EQUAL(
        CSuperblock::GetPaymentsLimit(first_index->pprev),
        CSuperblock::SUPERBLOCK_BUDGET);

    const CAmount block_reward{50 * COIN};
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(block_reward + 1, CScript() << OP_TRUE);
    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(coinbase));

    struct SyncModeGuard {
        const int old_mode;
        ~SyncModeGuard() { masternodeSync.SetSyncMode(old_mode); }
    } sync_mode_guard{masternodeSync.GetAssetID()};
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
    BOOST_REQUIRE(!masternodeSync.IsSynced());

    std::string error;
    bool exact_superblock_validation{true};
    BOOST_CHECK(IsBlockValueValid(
        block, first_index, block_reward, error,
        /*fJustCheck=*/true, /*check_superblock=*/true,
        &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);

    BOOST_REQUIRE(governance != nullptr);
    CAmount previous_limit{0};
    const bool had_previous_limit{governance->m_sb->ReadCache(
        first_index->GetBlockHash(), previous_limit)};
    struct BudgetCacheGuard {
        CGovernanceManager& manager;
        const uint256 block_hash;
        const bool had_previous_limit;
        const CAmount previous_limit;
        ~BudgetCacheGuard()
        {
            if (had_previous_limit) {
                manager.m_sb->WriteCache(block_hash, previous_limit);
            } else {
                manager.m_sb->EraseCache(block_hash);
            }
        }
    } budget_cache_guard{*governance, first_index->GetBlockHash(),
                         had_previous_limit, previous_limit};
    governance->m_sb->WriteCache(first_index->GetBlockHash(), 0);
    BOOST_CHECK_EQUAL(CSuperblock::GetPaymentsLimit(first_index), 0);

    error.clear();
    exact_superblock_validation = true;
    BOOST_CHECK(!IsBlockValueValid(
        block, second_index, block_reward, error,
        /*fJustCheck=*/true, /*check_superblock=*/true,
        &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);
    BOOST_CHECK(error.find("exceeded superblock max value") !=
                std::string::npos);

    struct NEVMStartHeightGuard {
        Consensus::Params& consensus;
        const int old_height;
        ~NEVMStartHeightGuard()
        {
            consensus.nNEVMStartBlock = old_height;
        }
    } nevm_start_guard{consensus, consensus.nNEVMStartBlock};
    consensus.nNEVMStartBlock = second_height;
    const int transition_cycle{consensus.SuperBlockCycle(second_height)};
    const int cadence_predecessor_height{second_height - transition_cycle};
    const CBlockIndex* cadence_predecessor;
    {
        LOCK(::cs_main);
        cadence_predecessor =
            m_node.chainman->ActiveChain()[cadence_predecessor_height];
    }
    BOOST_REQUIRE(cadence_predecessor != nullptr);
    BOOST_REQUIRE(!CSuperblock::IsValidBlockHeight(
        cadence_predecessor_height));
    BOOST_CHECK_EQUAL(
        CSuperblock::GetPaymentsLimit(cadence_predecessor), 0);

    error.clear();
    exact_superblock_validation = true;
    BOOST_CHECK(!IsBlockValueValid(
        block, second_index, block_reward, error,
        /*fJustCheck=*/true, /*check_superblock=*/true,
        &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);
    BOOST_CHECK(error.find("exceeded superblock max value") !=
                std::string::npos);

    consensus.nNEVMStartBlock = 1;
    const CBlockIndex* early_predecessor;
    const CBlockIndex* post_first_invalid;
    {
        LOCK(::cs_main);
        early_predecessor = m_node.chainman->ActiveChain()[9];
        post_first_invalid = m_node.chainman->ActiveChain()[14];
    }
    BOOST_REQUIRE(early_predecessor != nullptr);
    BOOST_REQUIRE(post_first_invalid != nullptr);
    BOOST_REQUIRE(!CSuperblock::IsValidBlockHeight(
        early_predecessor->nHeight));
    BOOST_REQUIRE(!CSuperblock::IsValidBlockHeight(
        post_first_invalid->nHeight));
    BOOST_CHECK_EQUAL(
        CSuperblock::GetPaymentsLimit(early_predecessor),
        CSuperblock::SUPERBLOCK_BUDGET);
    BOOST_CHECK_EQUAL(
        CSuperblock::GetPaymentsLimit(post_first_invalid), 0);
}

BOOST_FIXTURE_TEST_CASE(superblock_chainlock_requires_exact_governance_provenance,
                        TestChainDIP3V19Setup)
{
    struct SyncModeGuard {
        const int old_mode;
        ~SyncModeGuard() { masternodeSync.SetSyncMode(old_mode); }
    } sync_mode_guard{masternodeSync.GetAssetID()};

    const CBlockIndex* pindex;
    {
        LOCK(::cs_main);
        pindex = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_REQUIRE(pindex != nullptr);
    BOOST_REQUIRE(pindex->nHeight >= Params().GetConsensus().DIP0003Height);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(pindex->nHeight));

    const CAmount regular_reward =
        GetBlockSubsidy(pindex->nHeight, Params().GetConsensus());
    const CAmount unbacked_issuance = COIN;

    BOOST_REQUIRE(!m_coinbase_txns.empty());
    CMutableTransaction coinbase{*m_coinbase_txns.back()};
    coinbase.vout.emplace_back(unbacked_issuance, CScript() << OP_TRUE);

    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(coinbase));

    CAmount mn_seniority = 0;
    CAmount mn_floor_diff = 0;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(IsBlockPayeeValid(m_node.chainman->ActiveChain(),
                                        *block.vtx[0], pindex->nHeight,
                                        regular_reward, /*fees=*/0, mn_seniority,
                                        mn_floor_diff));
    }
    const CAmount value_limit =
        regular_reward + mn_seniority + mn_floor_diff;
    BOOST_REQUIRE_EQUAL(m_coinbase_txns.back()->GetValueOut(), value_limit);
    BOOST_REQUIRE_EQUAL(block.vtx[0]->GetValueOut(),
                        value_limit + unbacked_issuance);
    BOOST_REQUIRE(pindex->pprev != nullptr);

    std::string error;
    bool exact_superblock_validation{true};

    // The historical sync fallback remains bounded by the adaptive cap, but
    // must not produce exact-governance provenance for ChainLock signing.
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
    BOOST_REQUIRE(masternodeSync.IsBlockchainSynced());
    BOOST_REQUIRE(!masternodeSync.IsSynced());
    BOOST_CHECK(IsBlockValueValid(block, pindex, value_limit, error,
                                  /*fJustCheck=*/true,
                                  /*check_superblock=*/true,
                                  &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);

    BOOST_REQUIRE(governance != nullptr);
    BOOST_REQUIRE(governance_tests::PublishGovernanceReadyForTest(
        *governance, *pindex->pprev));
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_FINISHED);
    error.clear();
    exact_superblock_validation = false;
    BOOST_CHECK(!IsBlockValueValid(block, pindex, value_limit, error,
                                   /*fJustCheck=*/true,
                                   /*check_superblock=*/true,
                                   &exact_superblock_validation));
    BOOST_CHECK(exact_superblock_validation);

    // Equal height is not historical: the ChainLocked block itself must take
    // the exact path. Only a strict ancestor may set this predicate false.
    const int best_chainlock_height = pindex->nHeight;
    const bool check_superblock =
        best_chainlock_height <= pindex->nHeight;
    BOOST_REQUIRE(check_superblock);

    error.clear();
    exact_superblock_validation = false;
    BOOST_CHECK(!IsBlockValueValid(block, pindex, value_limit, error,
                                   /*fJustCheck=*/true, check_superblock,
                                   &exact_superblock_validation));
    BOOST_CHECK(exact_superblock_validation);

    error.clear();
    exact_superblock_validation = true;
    BOOST_CHECK(IsBlockValueValid(block, pindex, value_limit, error,
                                  /*fJustCheck=*/true,
                                  /*check_superblock=*/false,
                                  &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);
}

BOOST_FIXTURE_TEST_CASE(chainlock_enforcement_provenance_mode_matrix,
                        TestChainDIP3V19Setup)
{
    using Provenance = ChainLockEnforcementProvenance;

    auto& chainstate{m_node.chainman->ActiveChainstate()};
    CBlockIndex* target;
    uint32_t original_status;
    {
        LOCK(::cs_main);
        target = m_node.chainman->ActiveChain().Tip();
        BOOST_REQUIRE(target != nullptr);
        BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(target->nHeight));
        original_status = target->nStatus;
    }
    struct RestoreStatus {
        CBlockIndex* target;
        uint32_t status;
        ~RestoreStatus()
        {
            LOCK(::cs_main);
            target->nStatus = status;
        }
    } restore{target, original_status};

    const auto enforce = [&](uint32_t status, Provenance provenance) {
        {
            LOCK(::cs_main);
            target->nStatus = status;
        }
        BlockValidationState state;
        return chainstate.EnforceBlock(
            state, target, target->pprev, provenance);
    };
    constexpr uint32_t usable{
        BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA};

    // Exact local finality requires both the legacy exact-governance/BTCC bit
    // and the independently reconstructed full-receipt bit.
    BOOST_CHECK(enforce(
        usable | BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED,
        Provenance::EXACT_LOCAL));
    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED,
        Provenance::EXACT_LOCAL));
    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED,
        Provenance::EXACT_LOCAL));
    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_PQ_RECEIPT_INDEX_VALIDATED,
        Provenance::EXACT_LOCAL));

    // A fully reverified durable certificate supplies historical governance,
    // but never the locally reconstructed receipt provenance represented by
    // 4096. Legacy 2048 cannot substitute for it in this mode.
    BOOST_CHECK(enforce(
        usable | BLOCK_PQ_RECEIPT_INDEX_VALIDATED,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));

    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_RECEIPT_INDEX_VALIDATED | BLOCK_ASSUMED_VALID,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    BOOST_CHECK(!enforce(
        usable | BLOCK_PQ_RECEIPT_INDEX_VALIDATED | BLOCK_FAILED_VALID,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    // Pruning the body cannot prevent restart from recognizing a fully
    // validated durable target that is already on the active chain. A real
    // reorg still requires the candidate's block data below.
    BOOST_CHECK(enforce(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    CBlockIndex detached;
    const uint256 detached_hash{InsecureRand256()};
    detached.phashBlock = &detached_hash;
    detached.nHeight = target->nHeight;
    {
        LOCK(::cs_main);
        detached.nStatus =
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
    }
    BlockValidationState detached_state;
    BOOST_CHECK(!chainstate.EnforceBlock(
        detached_state, &detached, target->pprev,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    BOOST_CHECK(!enforce(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA |
            BLOCK_PQ_RECEIPT_INDEX_VALIDATED,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
}

// SYSCOIN BEGIN: Batched ChainLock-conflict correctness and work bounds.
BOOST_FIXTURE_TEST_CASE(
    active_chainlock_marks_preindexed_interval_siblings,
    TestChain100Setup)
{
    using Provenance = ChainLockEnforcementProvenance;

    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* target;
    CBlockIndex* predecessor;
    CBlockIndex* sibling;
    CBlockIndex* sibling_child;
    CBlockIndex* earlier_sibling;
    CBlockIndex* earlier_sibling_child;
    uint32_t original_status;
    {
        LOCK(::cs_main);
        target = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(target != nullptr);
        predecessor = target->pprev;
        BOOST_REQUIRE(predecessor != nullptr);
        BOOST_REQUIRE(predecessor->pprev != nullptr);
        original_status = target->nStatus;
        target->nStatus |= BLOCK_PQ_RECEIPT_INDEX_VALIDATED;

        const auto add_header = [&](const CBlockIndex& parent,
                                    uint32_t time_offset)
            EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = parent.GetBlockHash();
            header.hashMerkleRoot = InsecureRand256();
            header.nTime = parent.nTime + time_offset;
            header.nBits = parent.nBits;
            return chainman.m_blockman.AddToBlockIndex(
                header, chainman.m_best_header);
        };
        sibling = add_header(*predecessor, 1);
        sibling_child = add_header(*sibling, 1);
        earlier_sibling = add_header(*predecessor->pprev, 1);
        earlier_sibling_child = add_header(*earlier_sibling, 1);
        BOOST_REQUIRE(!(sibling->nStatus & BLOCK_CONFLICT_CHAINLOCK));
        BOOST_REQUIRE(!(sibling_child->nStatus & BLOCK_CONFLICT_CHAINLOCK));
        BOOST_REQUIRE(!(earlier_sibling->nStatus &
                        BLOCK_CONFLICT_CHAINLOCK));
        BOOST_REQUIRE(!(earlier_sibling_child->nStatus &
                        BLOCK_CONFLICT_CHAINLOCK));
        chainstate.ResetChainLockConflictMarkingStatsForTesting();
    }
    struct RestoreStatus {
        CBlockIndex* target;
        uint32_t status;
        ~RestoreStatus()
        {
            LOCK(::cs_main);
            target->nStatus = status;
        }
    } restore{target, original_status};

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.EnforceBlock(
        state, target, predecessor,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    ChainLockConflictMarkingStatsForTesting first_stats;
    {
        LOCK(::cs_main);
        BOOST_CHECK(sibling->nStatus & BLOCK_CONFLICT_CHAINLOCK);
        BOOST_CHECK(sibling_child->nStatus & BLOCK_CONFLICT_CHAINLOCK);
        BOOST_CHECK(earlier_sibling->nStatus & BLOCK_CONFLICT_CHAINLOCK);
        BOOST_CHECK(earlier_sibling_child->nStatus &
                    BLOCK_CONFLICT_CHAINLOCK);
        BOOST_CHECK(!(target->nStatus & BLOCK_CONFLICT_CHAINLOCK));
        BOOST_CHECK(chainman.m_best_header == target);
        first_stats =
            chainstate.GetChainLockConflictMarkingStatsForTesting();
        BOOST_CHECK_EQUAL(first_stats.batch_calls, 1U);
        BOOST_CHECK_EQUAL(first_stats.input_roots, 2U);
        BOOST_CHECK_EQUAL(first_stats.visited_blocks, 4U);
        BOOST_CHECK_EQUAL(first_stats.block_index_scans, 1U);
        BOOST_CHECK_EQUAL(first_stats.disconnect_tip_calls, 0U);
        BOOST_CHECK_EQUAL(first_stats.tip_publications, 1U);
    }

    BlockValidationState repeat_state;
    BOOST_REQUIRE(chainstate.EnforceBlock(
        repeat_state, target, predecessor,
        Provenance::VERIFIED_DURABLE_CERTIFICATE));
    {
        LOCK(::cs_main);
        const auto repeat_stats{
            chainstate.GetChainLockConflictMarkingStatsForTesting()};
        BOOST_CHECK_EQUAL(repeat_stats.batch_calls, first_stats.batch_calls);
        BOOST_CHECK_EQUAL(repeat_stats.input_roots, first_stats.input_roots);
        BOOST_CHECK_EQUAL(repeat_stats.visited_blocks,
                          first_stats.visited_blocks);
        BOOST_CHECK_EQUAL(repeat_stats.block_index_scans,
                          first_stats.block_index_scans);
        BOOST_CHECK_EQUAL(repeat_stats.tip_publications,
                          first_stats.tip_publications);
    }
    SyncWithValidationInterfaceQueue();
}

BOOST_FIXTURE_TEST_CASE(
    inactive_chainlock_conflict_batch_is_mempool_lock_safe,
    TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    LOCK(::cs_main);
    CBlockIndex* const tip{chainman.ActiveChain().Tip()};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->pprev != nullptr);

    const auto add_header = [&](const CBlockIndex& parent,
                                uint32_t time_offset)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = parent.GetBlockHash();
        header.hashMerkleRoot = InsecureRand256();
        header.nTime = parent.nTime + time_offset;
        header.nBits = parent.nBits;
        return chainman.m_blockman.AddToBlockIndex(
            header, chainman.m_best_header);
    };
    CBlockIndex* const root{add_header(*tip->pprev, 1)};
    CBlockIndex* const child{add_header(*root, 1)};
    chainstate.ResetChainLockConflictMarkingStatsForTesting();

    std::array<CBlockIndex*, 1> roots{root};
    BlockValidationState state;
    {
        LOCK(chainstate.MempoolMutex());
        BOOST_REQUIRE(
            chainstate.MarkConflictingBlocksInactive(state, roots));
    }
    BOOST_CHECK(root->nStatus & BLOCK_CONFLICT_CHAINLOCK);
    BOOST_CHECK(child->nStatus & BLOCK_CONFLICT_CHAINLOCK);
    const auto stats{
        chainstate.GetChainLockConflictMarkingStatsForTesting()};
    BOOST_CHECK_EQUAL(stats.batch_calls, 1U);
    BOOST_CHECK_EQUAL(stats.input_roots, 1U);
    BOOST_CHECK_EQUAL(stats.visited_blocks, 2U);
    BOOST_CHECK_EQUAL(stats.block_index_scans, 1U);
    BOOST_CHECK_EQUAL(stats.disconnect_tip_calls, 0U);
    BOOST_CHECK_EQUAL(stats.tip_publications, 0U);

    std::array<CBlockIndex*, 1> active_root{tip};
    BlockValidationState active_state;
    {
        LOCK(chainstate.MempoolMutex());
        BOOST_CHECK(!chainstate.MarkConflictingBlocksInactive(
            active_state, active_root));
    }
    BOOST_CHECK(active_state.IsError());
    BOOST_CHECK(!(tip->nStatus & BLOCK_CONFLICT_CHAINLOCK));
    const auto rejected_stats{
        chainstate.GetChainLockConflictMarkingStatsForTesting()};
    BOOST_CHECK_EQUAL(rejected_stats.batch_calls, stats.batch_calls);
    BOOST_CHECK_EQUAL(rejected_stats.block_index_scans,
                      stats.block_index_scans);
}
// SYSCOIN END: Batched ChainLock-conflict correctness and work bounds.

// SYSCOIN BEGIN: Preparation remains open only to PQ-authenticated tx86.
BOOST_AUTO_TEST_CASE(pq_activation_quarantine_provider_version_policy)
{
    BOOST_CHECK(IsPQActivationQuarantinedProviderTxVersion(
        SYSCOIN_TX_VERSION_MN_REGISTER));
    BOOST_CHECK(IsPQActivationQuarantinedProviderTxVersion(
        SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE));
    BOOST_CHECK(IsPQActivationQuarantinedProviderTxVersion(
        SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR));
    BOOST_CHECK(IsPQActivationQuarantinedProviderTxVersion(
        SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE));
    BOOST_CHECK(IsMasternodeTx(SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY));
    BOOST_CHECK(!IsPQActivationQuarantinedProviderTxVersion(
        SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY));
    BOOST_CHECK(!IsPQActivationQuarantinedProviderTxVersion(
        CTransaction::CURRENT_VERSION));
}
// SYSCOIN END: Preparation remains open only to PQ-authenticated tx86.

BOOST_FIXTURE_TEST_CASE(
    past_superblock_trigger_and_funding_vote_are_rejected,
    TestChainDIP3V19Setup)
{
    const CBlockIndex* tip =
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip != nullptr);
    const int event_height = tip->nHeight;
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(event_height));

    const CTxDestination destination =
        PKHash(coinbaseKey.GetPubKey());
    const auto make_trigger = [&](const int trigger_height,
                                  const uint256& proposal_hash) {
        std::vector<CGovernancePayment> payments;
        payments.emplace_back(destination, COIN, proposal_hash);
        CSuperblock schedule{trigger_height, std::move(payments)};
        return CGovernanceObject{
            uint256{},
            /*revision=*/1,
            GetTime<std::chrono::seconds>().count(),
            uint256{},
            schedule.GetHexStrData()};
    };

    uint256 late_trigger_hash;
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::
            AddTriggerAtHeight(
                *governance,
                event_height - 1,
                make_trigger(event_height, InsecureRand256()),
                late_trigger_hash));

    const int future_event_height =
        event_height +
        Params().GetConsensus().SuperBlockCycle(event_height);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(future_event_height));
    uint256 future_trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            AddTriggerAtHeight(
                *governance,
                event_height - 1,
                make_trigger(future_event_height, InsecureRand256()),
                future_trigger_hash));

    uint256 on_time_trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            InsertPreviouslyAdmittedTrigger(
                *governance,
                make_trigger(event_height, InsecureRand256()),
                on_time_trigger_hash));

    CGovernanceVote late_funding_vote{
        COutPoint{InsecureRand256(), 0},
        on_time_trigger_hash,
        VOTE_SIGNAL_FUNDING,
        VOTE_OUTCOME_YES};
    CGovernanceException exception;
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::
            ProcessVoteAtHeight(
                *governance,
                event_height - 1,
                late_funding_vote,
                exception,
                *m_node.connman));
    BOOST_CHECK_EQUAL(
        exception.GetType(), GOVERNANCE_EXCEPTION_WARNING);
    BOOST_CHECK_EQUAL(exception.GetNodePenalty(), 0);
    BOOST_CHECK(
        std::string{exception.what()}.find("event height has passed") !=
        std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(
    governance_yes_trigger_is_excluded_from_no_funding_candidates,
    TestChainDIP3V19Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);

    constexpr int active_height{100};
    const int trigger_height{active_height + 1};
    const uint256 chosen_trigger{InsecureRand256()};
    uint256 competing_trigger{InsecureRand256()};
    while (competing_trigger == chosen_trigger) {
        competing_trigger = InsecureRand256();
    }
    Access::InsertFutureTriggerForVoting(
        *governance, chosen_trigger, trigger_height);
    Access::InsertFutureTriggerForVoting(
        *governance, competing_trigger, trigger_height);
    Access::SetVotedFundingYesTrigger(*governance, chosen_trigger);

    const auto candidates{
        Access::NoFundingTriggerHashes(*governance, active_height)};
    BOOST_CHECK(
        std::find(candidates.begin(), candidates.end(), chosen_trigger) ==
        candidates.end());
    BOOST_CHECK(
        std::find(candidates.begin(), candidates.end(), competing_trigger) !=
        candidates.end());

    Access::SetVotedFundingYesTrigger(*governance, std::nullopt);
    const auto candidates_after_reset{
        Access::NoFundingTriggerHashes(*governance, active_height)};
    BOOST_CHECK(
        std::find(candidates_after_reset.begin(),
                  candidates_after_reset.end(), chosen_trigger) !=
        candidates_after_reset.end());
}

BOOST_FIXTURE_TEST_CASE(
    governance_required_outputs_are_matched_once,
    TestChainDIP3V19Setup)
{
    const CBlockIndex* tip =
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip != nullptr);
    const int event_height = tip->nHeight;
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(event_height));

    const CTxDestination destination = PKHash(coinbaseKey.GetPubKey());
    std::vector<CGovernancePayment> payments;
    payments.emplace_back(destination, COIN, InsecureRand256());
    payments.emplace_back(destination, COIN, InsecureRand256());
    CSuperblock schedule{event_height, std::move(payments)};
    CGovernanceObject trigger{
        uint256{},
        /*revision=*/1,
        GetTime<std::chrono::seconds>().count(),
        uint256{},
        schedule.GetHexStrData()};

    uint256 trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            InsertPreviouslyAdmittedTrigger(
                *governance, std::move(trigger), trigger_hash));
    const auto superblock =
        governance_tests::CGovernanceManagerTestAccess::
            GetTrigger(*governance, trigger_hash);
    BOOST_REQUIRE(superblock != nullptr);

    const CTxOut miner_output{10 * COIN, CScript{}};
    const CTxOut required_output{
        COIN, GetScriptForDestination(destination)};
    CMutableTransaction tx;
    tx.vout = {miner_output, required_output};

    BOOST_CHECK(
        !superblock->IsValid(
            CTransaction{tx},
            event_height,
            /*blockReward=*/10 * COIN,
            /*nGovernanceBudget=*/2 * COIN));

    tx.vout.push_back(required_output);
    BOOST_CHECK(
        superblock->IsValid(
            CTransaction{tx},
            event_height,
            /*blockReward=*/10 * COIN,
            /*nGovernanceBudget=*/2 * COIN));

    std::vector<bool> previously_matched(tx.vout.size());
    previously_matched[1] = true;
    BOOST_CHECK(
        !superblock->IsValid(
            CTransaction{tx},
            event_height,
            /*blockReward=*/11 * COIN,
            /*nGovernanceBudget=*/2 * COIN,
            &previously_matched));

    tx.vout.push_back(required_output);
    previously_matched.resize(tx.vout.size());
    BOOST_CHECK(
        superblock->IsValid(
            CTransaction{tx},
            event_height,
            /*blockReward=*/11 * COIN,
            /*nGovernanceBudget=*/2 * COIN,
            &previously_matched));
}

BOOST_FIXTURE_TEST_CASE(
    proposal_operator_signals_reject_delegated_voting_key,
    TestChain100Setup)
{
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);

    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner = coinbaseKey.GetPubKey().GetID();
    state->keyIDVoting = coinbaseKey.GetPubKey().GetID();
    auto dmn{std::make_shared<CDeterministicMN>(1)};
    dmn->proTxHash = InsecureRand256();
    dmn->collateralOutpoint = COutPoint{InsecureRand256(), 0};
    dmn->pdmnState = std::move(state);
    CDeterministicMNList mn_list{
        tip->GetBlockHash(), tip->nHeight, /*total_registered_count=*/0};
    mn_list.AddMN(dmn);

    // {"type":1} is sufficient here because ProcessVote exercises vote
    // authorization, not proposal collateral or schema validation.
    CGovernanceObject proposal{
        uint256{}, /*revision=*/1,
        GetTime<std::chrono::seconds>().count(), uint256{},
        "7b2274797065223a317d"};
    BOOST_REQUIRE_EQUAL(
        proposal.GetObjectType(), GOVERNANCE_OBJECT_PROPOSAL);

    CGovernanceVote funding{
        dmn->collateralOutpoint, proposal.GetHash(),
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    BOOST_REQUIRE(funding.Sign(
        coinbaseKey, coinbaseKey.GetPubKey().GetID()));
    BOOST_REQUIRE(funding.IsValid(mn_list));
    CGovernanceException funding_exception;
    BOOST_CHECK(proposal.ProcessVote(
        *tip, mn_list, funding, funding_exception));

    for (const auto signal : {VOTE_SIGNAL_VALID, VOTE_SIGNAL_DELETE,
                              VOTE_SIGNAL_ENDORSED}) {
        CGovernanceVote operator_vote{
            dmn->collateralOutpoint, proposal.GetHash(), signal,
            VOTE_OUTCOME_YES};
        BOOST_REQUIRE(operator_vote.Sign(
            coinbaseKey, coinbaseKey.GetPubKey().GetID()));
        // This is a valid delegated-key signature, so rejection proves the
        // object/signal authorization boundary rather than malformed input.
        BOOST_REQUIRE(operator_vote.IsValid(mn_list));
        CGovernanceException exception;
        BOOST_CHECK(!proposal.ProcessVote(
            *tip, mn_list, operator_vote, exception,
            /*pq_signature_preverified=*/false));
        BOOST_CHECK(
            std::string{exception.what()}.find(
                "requires preverified SLH authorization") !=
            std::string::npos);
    }
    BOOST_CHECK_EQUAL(proposal.GetVoteFile().GetVoteCount(), 1);
}

BOOST_FIXTURE_TEST_CASE(
    governance_upload_precharge_bounds_wire_serialization,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    Access::SetReady(*governance, true);

    CGovernanceObject proposal{
        uint256{}, /*revision=*/1, /*time=*/100,
        InsecureRand256(), "7b2274797065223a317d"};
    const std::size_t expected_object_size{
        ::GetSerializeSize(proposal, PROTOCOL_VERSION, SER_NETWORK)};
    const uint256 proposal_hash{
        Access::InsertObject(*governance, std::move(proposal))};
    const auto object_size{governance->GetObjectSerializedSizeForHash(
        proposal_hash, PROTOCOL_VERSION)};
    BOOST_REQUIRE(object_size);
    BOOST_CHECK_EQUAL(*object_size, expected_object_size);
    CDataStream object_stream{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_REQUIRE(governance->SerializeObjectForHash(
        proposal_hash, object_stream));
    BOOST_CHECK_EQUAL(object_stream.size(), *object_size);

    CGovernanceVote stored_vote{
        COutPoint{InsecureRand256(), 0}, proposal_hash,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    stored_vote.SetTime(101);
    stored_vote.SetSignature(std::vector<unsigned char>{0x01});
    BOOST_REQUIRE(Access::InsertVoteForSerializationTest(
        *governance, proposal_hash, stored_vote));
    const auto vote_bound{
        governance->GetVoteSerializedSizeUpperBoundForHash(
            stored_vote.GetHash(), PROTOCOL_VERSION)};
    BOOST_REQUIRE(vote_bound);
    CDataStream vote_stream{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_REQUIRE(governance->SerializeVoteForHash(
        stored_vote.GetHash(), vote_stream));
    BOOST_CHECK_LE(vote_stream.size(), *vote_bound);

    // Vote signatures are omitted from the logical hash. The precharge must
    // therefore cover the largest canonical signature that could replace the
    // stored variant between sizing and serialization.
    CGovernanceVote largest_same_hash{stored_vote};
    largest_same_hash.SetSignature(std::vector<unsigned char>(
        MAX_GOVERNANCE_SIGNATURE_SIZE, 0x02));
    BOOST_CHECK(largest_same_hash.GetHash() == stored_vote.GetHash());
    BOOST_CHECK_LE(
        ::GetSerializeSize(
            largest_same_hash, PROTOCOL_VERSION, SER_NETWORK),
        *vote_bound);

    uint256 missing{InsecureRand256()};
    while (missing == proposal_hash ||
           missing == stored_vote.GetHash()) {
        missing = InsecureRand256();
    }
    BOOST_CHECK(!governance->GetObjectSerializedSizeForHash(
        missing, PROTOCOL_VERSION));
    BOOST_CHECK(!governance->GetVoteSerializedSizeUpperBoundForHash(
        missing, PROTOCOL_VERSION));
}

BOOST_FIXTURE_TEST_CASE(
    governance_object_pages_are_exact_sorted_and_view_bound,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    Access::SetReady(*governance, true);

    std::set<uint256> expected;
    for (int i{0}; i < 5; ++i) {
        CGovernanceObject proposal{
            uint256{}, /*revision=*/i + 1,
            /*time=*/100 + i, InsecureRand256(),
            "7b2274797065223a317d"};
        BOOST_REQUIRE_EQUAL(
            proposal.GetObjectType(), GOVERNANCE_OBJECT_PROPOSAL);
        expected.insert(Access::InsertObject(
            *governance, std::move(proposal)));
    }

    CGovernancePageRequest request;
    request.nonce = 1;
    std::vector<uint256> received;
    std::optional<CGovernancePageResponse> first_page;
    std::shared_ptr<const GovernancePageImmutableSnapshot> snapshot;
    while (true) {
        const auto page{governance->BuildGovernancePage(
            request, snapshot)};
        BOOST_REQUIRE(page);
        const auto& response{page->response};
        BOOST_REQUIRE(IsValidGovernancePageResponse(request, response));
        BOOST_CHECK_EQUAL(response.status, GOVERNANCE_PAGE_OK);
        BOOST_CHECK_EQUAL(response.total_count, expected.size());
        BOOST_REQUIRE_EQUAL(
            page->entry_indices.size(), response.inventory.size());
        BOOST_REQUIRE(page->snapshot);
        if (!first_page) first_page = response;
        if (!snapshot) snapshot = page->snapshot;
        BOOST_CHECK(page->snapshot == snapshot);

        for (std::size_t i{0}; i < response.inventory.size(); ++i) {
            BOOST_CHECK_EQUAL(
                response.inventory[i].type, MSG_GOVERNANCE_OBJECT);
            received.push_back(response.inventory[i].hash);
            const auto& entry{page->snapshot->Entries()[
                page->entry_indices[i]]};
            BOOST_CHECK(entry.inv == response.inventory[i]);
            CDataStream stream{
                Span<const uint8_t>{entry.payload}, SER_NETWORK,
                GOVERNANCE_PAGE_PROTO_VERSION};
            CGovernanceObject decoded;
            stream >> decoded;
            BOOST_CHECK(decoded.GetHash() == response.inventory[i].hash);
            BOOST_CHECK(stream.empty());
        }
        if (response.done) break;
        request.cursor = response.next_cursor;
        request.view_id = response.view_id;
        ++request.nonce;
    }

    BOOST_REQUIRE_EQUAL(received.size(), expected.size());
    BOOST_CHECK(std::equal(
        received.begin(), received.end(), expected.begin()));
    const auto local_hashes{
        governance->GetGovernancePageObjectHashes()};
    BOOST_REQUIRE_EQUAL(local_hashes.status, GOVERNANCE_PAGE_OK);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        local_hashes.hashes.begin(), local_hashes.hashes.end(),
        expected.begin(), expected.end());
    BOOST_REQUIRE(first_page);

    CGovernancePageRequest restart_request;
    restart_request.nonce = request.nonce + 1;
    const auto restarted{governance->BuildGovernancePage(
        restart_request, snapshot)};
    BOOST_REQUIRE(restarted);
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        restart_request, restarted->response));
    BOOST_CHECK_EQUAL(restarted->response.status, GOVERNANCE_PAGE_OK);
    BOOST_CHECK(restarted->snapshot == snapshot);
    BOOST_CHECK(restarted->response.view_id == first_page->view_id);
    BOOST_CHECK(restarted->response.inventory == first_page->inventory);

    const CBlockIndex* active_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(active_tip != nullptr);
    BOOST_REQUIRE(Access::PublishReadyForTip(
        *governance, *active_tip,
        /*advance_validation_context=*/true));
    CGovernancePageRequest stale_context_request;
    stale_context_request.nonce = restart_request.nonce + 1;
    const auto stale_context{governance->BuildGovernancePage(
        stale_context_request, snapshot)};
    BOOST_REQUIRE(stale_context);
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        stale_context_request, stale_context->response));
    BOOST_CHECK_EQUAL(
        stale_context->response.status,
        GOVERNANCE_PAGE_RESTART_REQUIRED);
    BOOST_CHECK(!stale_context->snapshot);

    CGovernancePageRequest context_request;
    context_request.nonce = stale_context_request.nonce + 1;
    const auto new_context{governance->BuildGovernancePage(
        context_request)};
    BOOST_REQUIRE(new_context);
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        context_request, new_context->response));
    BOOST_REQUIRE(new_context->snapshot);
    BOOST_CHECK(new_context->snapshot != snapshot);
    BOOST_CHECK(new_context->response.view_id == first_page->view_id);
    BOOST_CHECK_EQUAL(
        new_context->snapshot->ValidationContextEpoch(),
        snapshot->ValidationContextEpoch() + 1);

    CGovernanceObject later{
        uint256{}, /*revision=*/99, /*time=*/999,
        InsecureRand256(), "7b2274797065223a317d"};
    expected.insert(Access::InsertObject(
        *governance, std::move(later)));
    Access::InvalidateObjectPage(*governance);

    CGovernancePageRequest fresh_request;
    fresh_request.nonce = context_request.nonce + 1;
    const auto fresh{governance->BuildGovernancePage(
        fresh_request)};
    BOOST_REQUIRE(fresh);
    BOOST_REQUIRE(IsValidGovernancePageResponse(
        fresh_request, fresh->response));
    BOOST_CHECK_EQUAL(fresh->response.status, GOVERNANCE_PAGE_OK);
    BOOST_REQUIRE(fresh->snapshot);
    BOOST_CHECK(fresh->snapshot != snapshot);
    BOOST_CHECK(fresh->response.view_id != first_page->view_id);
    BOOST_CHECK_EQUAL(fresh->response.total_count, expected.size());
    BOOST_CHECK_EQUAL(snapshot->TotalCount(), expected.size() - 1);
}

BOOST_FIXTURE_TEST_CASE(
    governance_page_client_filters_vote_sources_and_seeds_local_objects,
    TestChain100Setup)
{
    using GovernanceAccess =
        governance_tests::CGovernanceManagerTestAccess;
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    GovernanceAccess::SetReady(*governance, true);

    CGovernanceObject local_proposal{
        uint256{}, /*revision=*/1, /*time=*/100,
        InsecureRand256(), "7b2274797065223a317d"};
    const uint256 local_hash{GovernanceAccess::InsertObject(
        *governance, std::move(local_proposal))};
    uint256 remote_hash{InsecureRand256()};
    while (remote_hash == local_hash) remote_hash = InsecureRand256();

    CMasternodeSync sync;
    const std::vector<int64_t> cohort{11, 12, 13};
    SyncAccess::StartObjectPass(sync, cohort);
    const auto first{SyncAccess::AdvanceObjectSource(
        sync, /*success=*/true, remote_hash)};
    BOOST_CHECK(!first.restart_state && !first.complete &&
                !first.temporarily_unavailable &&
                !first.unserviceable);
    const auto failed{SyncAccess::AdvanceObjectSource(
        sync, /*success=*/false)};
    BOOST_CHECK(!failed.restart_state && !failed.complete &&
                !failed.temporarily_unavailable &&
                !failed.unserviceable);
    const auto last{SyncAccess::AdvanceObjectSource(
        sync, /*success=*/true)};
    BOOST_CHECK(!last.restart_state && !last.complete &&
                !last.temporarily_unavailable &&
                !last.unserviceable);

    const std::vector<int64_t> expected_vote_sources{11, 13};
    const auto vote_sources{SyncAccess::Sources(sync)};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        vote_sources.begin(), vote_sources.end(),
        expected_vote_sources.begin(), expected_vote_sources.end());
    const auto vote_scopes{SyncAccess::VoteScopes(sync)};
    BOOST_CHECK(std::binary_search(
        vote_scopes.begin(), vote_scopes.end(), local_hash));
    BOOST_CHECK(std::binary_search(
        vote_scopes.begin(), vote_scopes.end(), remote_hash));

    const auto reconciled{SyncAccess::CompleteFinalVoteScope(sync)};
    BOOST_CHECK(!reconciled.restart_state && !reconciled.complete &&
                !reconciled.temporarily_unavailable &&
                !reconciled.unserviceable);
    BOOST_CHECK(SyncAccess::IsObjectReconciliation(sync));
    const auto reconciliation_sources{SyncAccess::Sources(sync)};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        reconciliation_sources.begin(), reconciliation_sources.end(),
        cohort.begin(), cohort.end());
}

BOOST_AUTO_TEST_CASE(governance_page_client_reset_generation_is_terminal)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    CMasternodeSync sync;
    const uint64_t generation{SyncAccess::PrepareInitialPagePump(sync)};
    BOOST_REQUIRE(
        SyncAccess::IsInitialPagePumpEligible(sync, generation));

    sync.Reset(/*fForce=*/true, /*fNotifyReset=*/false);
    BOOST_CHECK(SyncAccess::ResetDrainPending(sync));
    BOOST_CHECK(
        !SyncAccess::IsInitialPagePumpEligible(sync, generation));

    // Consuming the tracker-drain marker cannot make the stale pump token
    // eligible again; the generation is the ABA guard.
    SyncAccess::ConsumeResetMarker(sync);
    BOOST_CHECK(!SyncAccess::ResetDrainPending(sync));
    BOOST_CHECK(
        !SyncAccess::IsInitialPagePumpEligible(sync, generation));

    const uint64_t periodic_generation{
        SyncAccess::PreparePeriodicPagePump(sync)};
    BOOST_REQUIRE(SyncAccess::IsPeriodicPagePumpEligible(
        sync, periodic_generation));
    SyncAccess::DeferPeriodicPagePump(sync);
    BOOST_CHECK(!SyncAccess::IsPeriodicPagePumpEligible(
        sync, periodic_generation));
}

BOOST_AUTO_TEST_CASE(
    governance_page_client_retains_admitted_same_netgroup_source)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    constexpr uint64_t keyed_net_group{77};
    const CAddress address;
    const auto make_manual_node = [&](NodeId id) {
        return std::make_unique<CNode>(
            id, /*sock=*/nullptr, address, keyed_net_group,
            /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"",
            ConnectionType::MANUAL, /*inbound_onion=*/false);
    };
    auto admitted{make_manual_node(9)};
    auto replacement{make_manual_node(11)};
    const std::vector<CNode*> eligible{
        admitted.get(), replacement.get()};

    const auto cohort{SyncAccess::DeduplicatePageCandidates(eligible)};
    BOOST_REQUIRE_EQUAL(cohort.size(), 1U);
    BOOST_CHECK_EQUAL(cohort.front()->GetId(), replacement->GetId());
    BOOST_CHECK(
        SyncAccess::FindPageSource(eligible, admitted->GetId()) ==
        admitted.get());
    BOOST_CHECK(
        SyncAccess::FindPageSource(cohort, admitted->GetId()) == nullptr);
}

BOOST_AUTO_TEST_CASE(
    governance_page_client_does_not_legacy_fallback_while_sources_cool)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;

    BOOST_CHECK(
        SyncAccess::NoUsablePageCandidatesAreTemporary(
            /*has_capable_peer=*/true));
    BOOST_CHECK(
        !SyncAccess::NoUsablePageCandidatesAreTemporary(
            /*has_capable_peer=*/false));
}

BOOST_AUTO_TEST_CASE(
    governance_page_client_latches_outstanding_metadata_request)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    CMasternodeSync sync;
    SyncAccess::StartObjectPass(sync, {11});

    BOOST_REQUIRE(SyncAccess::SetMetadataRequestOutstanding(sync));
    BOOST_CHECK(SyncAccess::MetadataRequestOutstanding(sync));
    BOOST_CHECK(!SyncAccess::SetMetadataRequestOutstanding(sync));

    // A tracker result releases the metadata lane for the next cursor. The
    // traversal state itself stays live until that result is interpreted.
    SyncAccess::FinishMetadataRequest(sync);
    BOOST_CHECK(!SyncAccess::MetadataRequestOutstanding(sync));
    BOOST_CHECK(SyncAccess::SetMetadataRequestOutstanding(sync));

    sync.Reset(/*fForce=*/true, /*fNotifyReset=*/false);
    BOOST_CHECK(!SyncAccess::MetadataRequestOutstanding(sync));
    BOOST_CHECK(SyncAccess::IsIdleAndEmpty(sync));
}

BOOST_AUTO_TEST_CASE(
    governance_page_client_bounds_dormant_session_admission)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    CMasternodeSync sync;
    const std::vector<int64_t> cohort{11, 12};
    SyncAccess::StartObjectPass(sync, cohort);
    const auto start{std::chrono::seconds{90}};

    const auto first{SyncAccess::ScheduleSessionAdmissionFailure(
        sync, start)};
    BOOST_CHECK(!first.advance_scope);
    BOOST_CHECK_EQUAL(first.source_index, 0U);
    BOOST_CHECK_EQUAL(first.session_admission_retries, 1U);
    BOOST_CHECK(first.retry_not_before ==
                start + std::chrono::seconds{1});

    const auto rotated{SyncAccess::ScheduleSessionAdmissionFailure(
        sync, first.retry_not_before)};
    BOOST_CHECK(rotated.advance_scope);
    BOOST_CHECK(!rotated.restart_state);
    BOOST_CHECK(!rotated.temporarily_unavailable);
    BOOST_CHECK_EQUAL(rotated.source_index, 1U);
    BOOST_CHECK_EQUAL(rotated.session_admission_retries, 0U);

    const auto second_first{SyncAccess::ScheduleSessionAdmissionFailure(
        sync, first.retry_not_before + std::chrono::seconds{1})};
    BOOST_CHECK(!second_first.advance_scope);
    BOOST_CHECK_EQUAL(second_first.source_index, 1U);
    BOOST_CHECK_EQUAL(second_first.session_admission_retries, 1U);

    const auto exhausted{SyncAccess::ScheduleSessionAdmissionFailure(
        sync, second_first.retry_not_before)};
    BOOST_CHECK(exhausted.advance_scope);
    BOOST_CHECK(exhausted.restart_state);
    BOOST_CHECK(exhausted.temporarily_unavailable);
    BOOST_CHECK_EQUAL(exhausted.session_admission_retries, 0U);
}

BOOST_AUTO_TEST_CASE(
    governance_page_client_bounds_temporary_unavailability)
{
    using SyncAccess =
        masternode_sync_tests::CMasternodeSyncTestAccess;
    CMasternodeSync sync;
    const std::vector<int64_t> cohort{11, 12};
    SyncAccess::StartObjectPass(sync, cohort);
    SyncAccess::SetTrackerSession(sync, cohort.front());

    const auto start{std::chrono::seconds{100}};
    for (std::size_t retry{1};
         retry <= SyncAccess::ImmediateTemporaryRetries(); ++retry) {
        const auto retry_time{
            start + std::chrono::seconds{static_cast<int64_t>(retry)}};
        const auto result{SyncAccess::ScheduleTemporaryUnavailable(
            sync, retry_time)};
        BOOST_CHECK(!result.release_tracker_session);
        BOOST_CHECK(!result.advance_scope);
        BOOST_CHECK(result.tracker_session_active);
        BOOST_CHECK_EQUAL(result.tracker_source, cohort.front());
        BOOST_CHECK_EQUAL(result.source_index, 0U);
        BOOST_CHECK_EQUAL(result.restarts, retry);
        BOOST_CHECK(result.retry_not_before ==
                    std::chrono::microseconds{0});
    }

    const auto depleted_at{start + std::chrono::seconds{
        static_cast<int64_t>(
            SyncAccess::ImmediateTemporaryRetries() + 1)}};
    const auto parked{
        SyncAccess::ScheduleTemporaryUnavailable(sync, depleted_at)};
    BOOST_CHECK(parked.release_tracker_session);
    BOOST_CHECK(!parked.advance_scope);
    BOOST_CHECK(!parked.tracker_session_active);
    BOOST_CHECK_EQUAL(parked.tracker_source, -1);
    BOOST_CHECK_EQUAL(parked.source_index, 0U);
    BOOST_CHECK_EQUAL(
        parked.restarts,
        SyncAccess::ImmediateTemporaryRetries() + 1);
    const auto refill_delay{std::chrono::seconds{
        static_cast<int64_t>(
            (GovernancePageBuildRateLimiter::TOKEN_CAPACITY +
             GovernancePageBuildRateLimiter::REFILL_BYTES_PER_SECOND - 1) /
            GovernancePageBuildRateLimiter::REFILL_BYTES_PER_SECOND) + 1}};
    BOOST_CHECK(parked.retry_not_before == depleted_at + refill_delay);

    // A source gets one retry after the bounded refill interval. A second TEMP
    // advances without cooling instead of holding initial sync indefinitely.
    SyncAccess::SetTrackerSession(sync, cohort.front());
    const auto exhausted{SyncAccess::ScheduleTemporaryUnavailable(
        sync, parked.retry_not_before)};
    BOOST_CHECK(!exhausted.release_tracker_session);
    BOOST_CHECK(exhausted.advance_scope);
    BOOST_CHECK(!exhausted.restart_state);
    BOOST_CHECK(!exhausted.temporarily_unavailable);
    BOOST_CHECK(exhausted.tracker_session_active);
    BOOST_CHECK_EQUAL(exhausted.source_index, 1U);
    BOOST_CHECK_EQUAL(exhausted.restarts, 0U);
    BOOST_CHECK(exhausted.retry_not_before ==
                std::chrono::microseconds{0});

    const auto second_start{parked.retry_not_before};
    SyncAccess::SetTrackerSession(sync, cohort.back());
    for (std::size_t retry{1};
         retry <= SyncAccess::ImmediateTemporaryRetries(); ++retry) {
        const auto result{SyncAccess::ScheduleTemporaryUnavailable(
            sync, second_start + std::chrono::seconds{
                static_cast<int64_t>(retry)})};
        BOOST_CHECK(!result.advance_scope);
    }
    const auto second_depleted_at{
        second_start + std::chrono::seconds{
            static_cast<int64_t>(
                SyncAccess::ImmediateTemporaryRetries() + 1)}};
    const auto second_parked{
        SyncAccess::ScheduleTemporaryUnavailable(
            sync, second_depleted_at)};
    BOOST_CHECK(second_parked.release_tracker_session);
    BOOST_CHECK(!second_parked.advance_scope);
    SyncAccess::SetTrackerSession(sync, cohort.back());
    const auto all_sources_exhausted{
        SyncAccess::ScheduleTemporaryUnavailable(
            sync, second_parked.retry_not_before)};
    BOOST_CHECK(all_sources_exhausted.advance_scope);
    BOOST_CHECK(all_sources_exhausted.restart_state);
    BOOST_CHECK(all_sources_exhausted.temporarily_unavailable);
    BOOST_CHECK(all_sources_exhausted.release_tracker_session);
    BOOST_CHECK(!all_sources_exhausted.tracker_session_active);

    CMasternodeSync failed_request_sync;
    SyncAccess::StartObjectPass(failed_request_sync, cohort);
    SyncAccess::SetTrackerSession(
        failed_request_sync, cohort.front());
    const auto request_failed{SyncAccess::ParkFailedPageRequest(
        failed_request_sync, start)};
    BOOST_CHECK(request_failed.release_tracker_session);
    BOOST_CHECK(!request_failed.advance_scope);
    BOOST_CHECK(!request_failed.tracker_session_active);
    BOOST_CHECK_EQUAL(request_failed.tracker_source, -1);
    BOOST_CHECK_EQUAL(request_failed.source_index, 0U);
    BOOST_CHECK_EQUAL(request_failed.session_admission_retries, 1U);
    BOOST_CHECK(request_failed.retry_not_before ==
                start + std::chrono::seconds{1});

    SyncAccess::SetTrackerSession(
        failed_request_sync, cohort.front());
    const auto request_failed_again{
        SyncAccess::ParkFailedPageRequest(
            failed_request_sync, request_failed.retry_not_before)};
    BOOST_CHECK(request_failed_again.release_tracker_session);
    BOOST_CHECK(request_failed_again.advance_scope);
    BOOST_CHECK(!request_failed_again.restart_state);
    BOOST_CHECK_EQUAL(request_failed_again.source_index, 1U);
    BOOST_CHECK_EQUAL(
        request_failed_again.session_admission_retries, 0U);

    SyncAccess::SetTrackerSession(
        failed_request_sync, cohort.back());
    const auto final_source_first{
        SyncAccess::ParkFailedPageRequest(
            failed_request_sync,
            request_failed.retry_not_before + std::chrono::seconds{1})};
    BOOST_CHECK(final_source_first.release_tracker_session);
    BOOST_CHECK(!final_source_first.advance_scope);
    SyncAccess::SetTrackerSession(
        failed_request_sync, cohort.back());
    const auto final_source_exhausted{
        SyncAccess::ParkFailedPageRequest(
            failed_request_sync, final_source_first.retry_not_before)};
    BOOST_CHECK(final_source_exhausted.release_tracker_session);
    BOOST_CHECK(final_source_exhausted.advance_scope);
    BOOST_CHECK(final_source_exhausted.restart_state);
    BOOST_CHECK(final_source_exhausted.temporarily_unavailable);

    failed_request_sync.Reset(
        /*fForce=*/true, /*fNotifyReset=*/false);
    BOOST_CHECK(SyncAccess::IsIdleAndEmpty(failed_request_sync));
}

BOOST_AUTO_TEST_CASE(governance_page_build_work_is_globally_bounded)
{
    GovernancePageBuildRateLimiter limiter;
    const auto start{std::chrono::seconds{100}};

    BOOST_REQUIRE(limiter.Begin(start));
    BOOST_REQUIRE(limiter.Charge(
        GovernancePageBuildRateLimiter::TOKEN_CAPACITY));
    BOOST_CHECK(!limiter.Begin(
        start + GovernancePageBuildRateLimiter::MIN_BUILD_INTERVAL));
    BOOST_CHECK(!limiter.Begin(start + std::chrono::seconds{1}));
    BOOST_REQUIRE(limiter.Begin(start + std::chrono::seconds{64}));

    GovernancePageBuildRateLimiter small;
    BOOST_REQUIRE(small.Begin(start));
    BOOST_REQUIRE(small.Charge(
        GovernancePageBuildRateLimiter::MINIMUM_BUILD_CHARGE));
    BOOST_CHECK(!small.Begin(
        start + GovernancePageBuildRateLimiter::MIN_BUILD_INTERVAL));
    BOOST_REQUIRE(small.Begin(start + std::chrono::seconds{1}));

    GovernancePageBuildRateLimiter oversized;
    BOOST_REQUIRE(oversized.Begin(start));
    BOOST_CHECK(!oversized.Charge(
        GovernancePageBuildRateLimiter::TOKEN_CAPACITY + 1));
    BOOST_CHECK(!oversized.Begin(start));
    BOOST_CHECK(!oversized.Begin(start + std::chrono::seconds{1}));
    BOOST_REQUIRE(oversized.Begin(start + std::chrono::seconds{64}));
}

BOOST_AUTO_TEST_CASE(governance_page_payload_authorization_is_byte_bounded)
{
    GovernancePageServeRateLimiter relay_limiter;
    GovernancePageServeRateLimiter limiter;
    const auto start{std::chrono::seconds{200}};
    const uint64_t netgroup{17};

    // Ordinary relay credits use the same byte budget without first consuming
    // a page-request token.
    BOOST_REQUIRE(relay_limiter.ConsumePayloadBytes(
        2, {}, netgroup + 1, 1, start));

    using RequestResult = GovernancePageServeRateLimiter::RequestResult;
    BOOST_CHECK(limiter.Consume(1, {}, netgroup, start) ==
                RequestResult::ACCEPTED);
    BOOST_REQUIRE(limiter.ConsumePayloadBytes(
        1, {}, netgroup,
        GovernancePageServeRateLimiter::SOURCE_BYTE_CAPACITY, start));

    const auto half_second{start + std::chrono::milliseconds{500}};
    BOOST_CHECK(limiter.Consume(1, {}, netgroup, half_second) ==
                RequestResult::ACCEPTED);
    BOOST_CHECK(!limiter.ConsumePayloadBytes(
        1, {}, netgroup, 1, half_second));

    const auto one_second{start + std::chrono::seconds{1}};
    BOOST_CHECK(limiter.Consume(1, {}, netgroup, one_second) ==
                RequestResult::ACCEPTED);
    BOOST_REQUIRE(limiter.ConsumePayloadBytes(
        1, {}, netgroup,
        GovernancePageServeRateLimiter::SOURCE_BYTE_REFILL_PER_SECOND,
        one_second));
    BOOST_CHECK(!limiter.ConsumePayloadBytes(
        1, {}, netgroup,
        GovernancePageServeRateLimiter::SOURCE_BYTE_CAPACITY + 1,
        one_second));

    GovernancePageServeRateLimiter concurrent;
    const uint256 first_identity{uint256S("a001")};
    const uint256 second_identity{uint256S("a002")};
    const uint256 third_identity{uint256S("a003")};
    const uint256 fourth_identity{uint256S("a004")};
    BOOST_CHECK(concurrent.Consume(
                    10, first_identity, netgroup, start) ==
                RequestResult::ACCEPTED);
    BOOST_CHECK(concurrent.Consume(
                    11, second_identity, netgroup, start) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(concurrent.Consume(
                    12, third_identity, netgroup, start) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(concurrent.Consume(
                    11, second_identity, netgroup, start) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(concurrent.Consume(
                    11, second_identity, netgroup, start) ==
                RequestResult::SOURCE_LIMITED);
    BOOST_CHECK(concurrent.Consume(
                    12, third_identity, netgroup,
                    start + GovernancePageServeRateLimiter::
                                GLOBAL_MIN_INTERVAL) ==
                RequestResult::ACCEPTED);
    BOOST_CHECK(concurrent.Consume(
                    13, fourth_identity, netgroup,
                    start + 2 * GovernancePageServeRateLimiter::
                                    GLOBAL_MIN_INTERVAL) ==
                RequestResult::SOURCE_LIMITED);
    BOOST_CHECK(concurrent.Consume(
                    11, second_identity, netgroup, half_second) ==
                RequestResult::ACCEPTED);

    GovernancePageServeRateLimiter authenticated_bytes;
    const std::size_t half_source_bytes{
        GovernancePageServeRateLimiter::SOURCE_BYTE_CAPACITY / 2};
    BOOST_REQUIRE(authenticated_bytes.ConsumePayloadBytes(
        14, first_identity, netgroup, half_source_bytes, start));
    BOOST_REQUIRE(authenticated_bytes.ConsumePayloadBytes(
        15, second_identity, netgroup, half_source_bytes, start));
    BOOST_CHECK(!authenticated_bytes.ConsumePayloadBytes(
        16, third_identity, netgroup, 1, start));

    GovernancePageServeRateLimiter shared_netgroup;
    BOOST_CHECK(shared_netgroup.Consume(20, {}, netgroup, start) ==
                RequestResult::ACCEPTED);
    BOOST_CHECK(shared_netgroup.Consume(21, {}, netgroup, start) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(shared_netgroup.Consume(22, {}, netgroup, start) ==
                RequestResult::SOURCE_LIMITED);

    GovernancePageServeRateLimiter full_table;
    constexpr uint64_t target_netgroup{5000};
    BOOST_CHECK(full_table.Consume(
                    30, {}, target_netgroup, start) ==
                RequestResult::ACCEPTED);
    for (std::size_t i{0};
         i < GovernancePageServeRateLimiter::MAX_SOURCE_RECORDS - 1;
         ++i) {
        BOOST_CHECK(full_table.Consume(
                        static_cast<int64_t>(31 + i), {},
                        6000 + i, start) ==
                    RequestResult::GLOBAL_BUSY);
    }
    BOOST_CHECK(full_table.Consume(
                    30, {}, target_netgroup,
                    start + std::chrono::microseconds{1}) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(full_table.Consume(
                    2000, {}, 9000,
                    start + std::chrono::microseconds{2}) ==
                RequestResult::GLOBAL_BUSY);
    BOOST_CHECK(full_table.Consume(
                    30, {}, target_netgroup,
                    start + std::chrono::microseconds{3}) ==
                RequestResult::SOURCE_LIMITED);

    GovernancePageServeRateLimiter full_byte_table;
    BOOST_REQUIRE(full_byte_table.ConsumePayloadBytes(
        3000, {}, target_netgroup,
        GovernancePageServeRateLimiter::SOURCE_BYTE_CAPACITY, start));
    for (std::size_t i{0};
         i < GovernancePageServeRateLimiter::MAX_SOURCE_RECORDS - 1;
         ++i) {
        BOOST_REQUIRE(full_byte_table.ConsumePayloadBytes(
            static_cast<int64_t>(3001 + i), {}, 10000 + i, 1, start));
    }
    BOOST_CHECK(!full_byte_table.ConsumePayloadBytes(
        3000, {}, target_netgroup, 1,
        start + std::chrono::microseconds{1}));
    BOOST_REQUIRE(full_byte_table.ConsumePayloadBytes(
        5000, {}, 12000, 1,
        start + std::chrono::microseconds{2}));
    BOOST_CHECK(!full_byte_table.ConsumePayloadBytes(
        3000, {}, target_netgroup, 1,
        start + std::chrono::microseconds{3}));
}

BOOST_FIXTURE_TEST_CASE(
    legacy_governance_sync_rejects_oversized_bloom_filter,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    Access::SetReady(*governance, true);
    BOOST_REQUIRE(masternodeSync.IsSynced());

    in_addr ipv4_addr;
    ipv4_addr.s_addr = 0xa0b0c006;
    const CAddress address{CService{ipv4_addr, 7782}, NODE_NETWORK};
    CNode node{
        /*id=*/7, /*sock=*/nullptr, address,
        /*nKeyedNetGroupIn=*/6, /*nLocalHostNonceIn=*/7, CAddress{},
        /*addrNameIn=*/std::string{}, ConnectionType::INBOUND,
        /*inbound_onion=*/false};
    node.SetCommonVersion(GOVERNANCE_PAGE_PROTO_VERSION - 1);
    m_node.peerman->InitializeNode(node, NODE_NETWORK);

    CDataStream request{
        SER_NETWORK, GOVERNANCE_PAGE_PROTO_VERSION - 1};
    request << uint256::ONEV;
    request << std::vector<unsigned char>{0xff};
    request << std::numeric_limits<unsigned int>::max();
    request << static_cast<unsigned int>(0);
    request << static_cast<unsigned char>(BLOOM_UPDATE_NONE);

    governance->ProcessMessage(
        &node, NetMsgType::MNGOVERNANCESYNC, request,
        *m_node.connman, *m_node.peerman);

    BOOST_CHECK(request.empty());
    BOOST_CHECK(m_node.peerman->IsBanned(node.GetId()));
    m_node.peerman->FinalizeNode(node);
}

BOOST_AUTO_TEST_CASE(
    governance_authority_delta_tracks_rotation_revocation_and_pose)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;

    uint256 tip_hash{InsecureRand256()};
    CBlockIndex tip;
    tip.nHeight = 101;
    tip.phashBlock = &tip_hash;

    const uint256 pro_tx_hash{InsecureRand256()};
    const COutPoint collateral{InsecureRand256(), 1};
    const auto make_list = [&](bool pose_banned, bool include_member) {
        CDeterministicMNList list{
            tip_hash, tip.nHeight, /*total_registered_count=*/1};
        if (!include_member) return list;

        auto state{std::make_shared<CDeterministicMNState>()};
        state->keyIDOwner.begin()[0] = 1;
        state->nRegisteredHeight = 1;
        if (pose_banned) state->BanIfNotBanned(tip.nHeight);
        auto member{std::make_shared<CDeterministicMN>(1)};
        member->proTxHash = pro_tx_hash;
        member->collateralOutpoint = collateral;
        member->pdmnState = std::move(state);
        list.AddMN(member, /*fBumpTotalCount=*/false);
        return list;
    };
    const auto make_snapshot = [&](uint32_t key_version, bool active) {
        llmq::pq::PQRegistrySnapshot snapshot;
        snapshot.height = tip.nHeight;
        snapshot.block_hash = tip_hash;
        auto state{
            llmq::pq::OperatorKeyState::ForOperator(pro_tx_hash)};
        state.has_global_key = 1;
        state.global_key_active = active ? 1 : 0;
        state.global_key.key_version = key_version;
        snapshot.operator_states.push_back(std::move(state));
        return snapshot;
    };

    std::string error;
    Access::AuthorityView initial;
    BOOST_REQUIRE(Access::BuildAuthorityView(
        tip, make_list(/*pose_banned=*/false, /*include_member=*/true),
        make_snapshot(/*key_version=*/1, /*active=*/true), initial,
        error));
    BOOST_REQUIRE_EQUAL(initial.size(), 1U);
    BOOST_CHECK(initial.at(collateral).first == pro_tx_hash);
    BOOST_CHECK_EQUAL(initial.at(collateral).second, 1U);

    Access::AuthorityView unchanged;
    BOOST_REQUIRE(Access::BuildAuthorityView(
        tip, make_list(false, true), make_snapshot(1, true), unchanged,
        error));
    BOOST_CHECK_EQUAL(
        Access::ChangedAuthorityCount(initial, unchanged), 0U);

    Access::AuthorityView rotated;
    BOOST_REQUIRE(Access::BuildAuthorityView(
        tip, make_list(false, true), make_snapshot(2, true), rotated,
        error));
    BOOST_CHECK_EQUAL(rotated.at(collateral).second, 2U);
    BOOST_CHECK_EQUAL(
        Access::ChangedAuthorityCount(initial, rotated), 1U);

    for (const auto& [list, snapshot] : {
             std::pair{make_list(false, true), make_snapshot(2, false)},
             std::pair{make_list(true, true), make_snapshot(2, true)},
             std::pair{make_list(false, false), make_snapshot(2, true)}}) {
        Access::AuthorityView removed;
        BOOST_REQUIRE(Access::BuildAuthorityView(
            tip, list, snapshot, removed, error));
        BOOST_CHECK(removed.empty());
        BOOST_CHECK_EQUAL(
            Access::ChangedAuthorityCount(initial, removed), 1U);
    }

    auto wrong_snapshot{make_snapshot(1, true)};
    wrong_snapshot.block_hash = InsecureRand256();
    Access::AuthorityView rejected;
    BOOST_CHECK(!Access::BuildAuthorityView(
        tip, make_list(false, true), wrong_snapshot, rejected, error));
    BOOST_CHECK(rejected.empty());
    BOOST_CHECK(error.find("exact tip") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    governance_authority_maps_fail_closed_for_reindex_sentinel)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;

    uint256 tip_hash{InsecureRand256()};
    CBlockIndex tip;
    tip.nHeight = 1;
    tip.phashBlock = &tip_hash;
    llmq::pq::PQRegistrySnapshot registry_snapshot;
    registry_snapshot.height = tip.nHeight;
    registry_snapshot.block_hash = tip_hash;

    std::string error;
    Access::AuthorityView pq_authorities;
    BOOST_CHECK(!Access::BuildAuthorityView(
        tip, CDeterministicMNList{}, registry_snapshot, pq_authorities,
        error));
    BOOST_CHECK(pq_authorities.empty());
    BOOST_CHECK(error.find("exact tip") != std::string::npos);

    std::size_t delegated_authority_count{1};
    BOOST_CHECK(!Access::BuildDelegatedAuthorityView(
        tip, CDeterministicMNList{}, registry_snapshot,
        delegated_authority_count, error));
    BOOST_CHECK_EQUAL(delegated_authority_count, 0U);
    BOOST_CHECK(error.find("exact tip") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(
    governance_authority_reorg_requires_one_full_pass,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);

    uint256 parent_hash{InsecureRand256()};
    uint256 main_hash{InsecureRand256()};
    uint256 next_hash{InsecureRand256()};
    uint256 fork_hash{InsecureRand256()};
    CBlockIndex parent;
    parent.nHeight = 50;
    parent.phashBlock = &parent_hash;
    CBlockIndex main;
    main.nHeight = 51;
    main.pprev = &parent;
    main.phashBlock = &main_hash;
    CBlockIndex next;
    next.nHeight = 52;
    next.pprev = &main;
    next.phashBlock = &next_hash;
    CBlockIndex fork;
    fork.nHeight = 51;
    fork.pprev = &parent;
    fork.phashBlock = &fork_hash;

    const COutPoint collateral{InsecureRand256(), 0};
    const Access::AuthorityView authorities{
        {collateral, {InsecureRand256(), 1}}};

    Access::RememberAuthorityTip(*governance, parent, authorities);
    BOOST_CHECK(Access::IsRememberedTip(*governance, parent));
    BOOST_CHECK(Access::IsStraightExtension(*governance, main));

    Access::RememberAuthorityTip(*governance, main, authorities);
    BOOST_CHECK(Access::IsRememberedTip(*governance, main));
    BOOST_CHECK(Access::IsStraightExtension(*governance, next));
    BOOST_CHECK(!Access::IsStraightExtension(*governance, fork));

    // Recovery deliberately forces one full pass even on the next child.
    Access::RememberAuthorityTip(
        *governance, main, authorities, /*snapshot_valid=*/false);
    BOOST_CHECK(!Access::IsRememberedTip(*governance, main));
    BOOST_CHECK(!Access::IsStraightExtension(*governance, next));
}

// SYSCOIN BEGIN: exact governance authority snapshot cache coverage.
BOOST_FIXTURE_TEST_CASE(
    governance_authority_content_reuse_is_constant_time_and_branch_safe,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->pprev != nullptr);

    const uint256 dmn_content_hash{InsecureRand256()};
    const uint256 registry_state_root{InsecureRand256()};
    BOOST_REQUIRE(!dmn_content_hash.IsNull());
    BOOST_REQUIRE(!registry_state_root.IsNull());
    Access::RememberAuthorityContent(
        *governance, *tip, dmn_content_hash, registry_state_root);
    governance->ObserveChainTip(tip);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *tip));

    const auto initial_context{
        Access::ValidationContextEpoch(*governance)};
    BOOST_REQUIRE(initial_context);
    const auto before{Access::AuthoritySnapshotStats(*governance)};
    BOOST_CHECK(Access::TryReuseAuthorityContent(
        *governance, *tip, dmn_content_hash, registry_state_root));
    BOOST_CHECK(Access::TryReuseAuthorityContent(
        *governance, *tip, dmn_content_hash, registry_state_root));
    const auto repeated{Access::AuthoritySnapshotStats(*governance)};
    BOOST_CHECK_EQUAL(repeated.builds, before.builds);
    BOOST_CHECK_EQUAL(repeated.reuses, before.reuses + 2);

    uint256 child_hash{InsecureRand256()};
    CBlockIndex child;
    child.nHeight = tip->nHeight + 1;
    child.pprev = tip;
    child.phashBlock = &child_hash;
    governance->ObserveChainTip(&child);
    BOOST_REQUIRE(Access::TryReuseAuthorityContent(
        *governance, child, dmn_content_hash, registry_state_root));
    BOOST_CHECK(Access::IsRememberedTip(*governance, child));
    BOOST_CHECK_EQUAL(governance->GetCachedBlockHeight(), child.nHeight);
    BOOST_REQUIRE(Access::ValidationContextEpoch(*governance));
    BOOST_CHECK_EQUAL(
        *Access::ValidationContextEpoch(*governance), *initial_context);

    // Crossing a trigger height keeps the immutable authority maps but must
    // invalidate queued validation/page contexts.
    uint256 trigger_hash{InsecureRand256()};
    Access::InsertFutureTriggerForVoting(
        *governance, trigger_hash, child.nHeight + 1);
    uint256 boundary_hash{InsecureRand256()};
    CBlockIndex boundary;
    boundary.nHeight = child.nHeight + 1;
    boundary.pprev = &child;
    boundary.phashBlock = &boundary_hash;
    governance->ObserveChainTip(&boundary);
    BOOST_REQUIRE(Access::TryReuseAuthorityContent(
        *governance, boundary, dmn_content_hash, registry_state_root));
    BOOST_REQUIRE(Access::ValidationContextEpoch(*governance));
    BOOST_CHECK_EQUAL(
        *Access::ValidationContextEpoch(*governance),
        *initial_context + 1);

    // Either authenticated content identity changing rejects the shortcut;
    // the caller consequently takes the normal one-scan rebuild path.
    uint256 changed_hash{InsecureRand256()};
    CBlockIndex changed;
    changed.nHeight = boundary.nHeight + 1;
    changed.pprev = &boundary;
    changed.phashBlock = &changed_hash;
    governance->ObserveChainTip(&changed);
    BOOST_CHECK(!Access::TryReuseAuthorityContent(
        *governance, changed, InsecureRand256(), registry_state_root));

    Access::RememberAuthorityContent(
        *governance, boundary, dmn_content_hash, registry_state_root);
    governance->ObserveChainTip(&boundary);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, boundary));
    governance->ObserveChainTip(&changed);
    BOOST_CHECK(!Access::TryReuseAuthorityContent(
        *governance, changed, dmn_content_hash, InsecureRand256()));

    Access::RememberAuthorityContent(
        *governance, boundary, dmn_content_hash, registry_state_root);
    governance->ObserveChainTip(&boundary);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, boundary));
    uint256 sibling_hash{InsecureRand256()};
    CBlockIndex sibling;
    sibling.nHeight = boundary.nHeight + 1;
    sibling.pprev = &boundary;
    sibling.phashBlock = &sibling_hash;
    governance->ObserveChainTip(&sibling);
    governance->ObserveChainTip(&boundary);
    // Observing another branch and returning A-B-A must not revive A's former
    // publication without the normal recovery rebuild.
    BOOST_CHECK(!Access::TryReuseAuthorityContent(
        *governance, boundary, dmn_content_hash, registry_state_root));

    // Nor may an unvalidated branch observation be skipped as A-B-C merely
    // because C happens to be another direct child of remembered A.
    uint256 alternate_hash{InsecureRand256()};
    CBlockIndex alternate;
    alternate.nHeight = sibling.nHeight;
    alternate.pprev = &boundary;
    alternate.phashBlock = &alternate_hash;
    governance->ObserveChainTip(&sibling);
    governance->ObserveChainTip(&alternate);
    BOOST_CHECK(!Access::TryReuseAuthorityContent(
        *governance, alternate, dmn_content_hash, registry_state_root));

    const auto invalidated{Access::AuthoritySnapshotStats(*governance)};
    BOOST_CHECK_EQUAL(invalidated.builds, before.builds);
    BOOST_CHECK_EQUAL(invalidated.reuses, repeated.reuses + 2);
}

BOOST_FIXTURE_TEST_CASE(
    governance_validation_context_is_hidden_during_pq_quarantine,
    TestingSetup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    BOOST_REQUIRE(!m_node.chainman->IsPQParticipationAllowed());

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);

    // Preserve the exact race shape: readiness was published before the
    // activation handoff revoked public participation.
    Access::SetReady(*governance, true);
    BOOST_CHECK(!governance->IsReady());
    BOOST_CHECK(
        !governance->GetPQGovernanceValidationContextEpoch().has_value());
}
// SYSCOIN END: exact governance authority snapshot cache coverage.

BOOST_FIXTURE_TEST_CASE(
    governance_startup_snapshot_failure_is_fail_closed_and_recoverable,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    BOOST_CHECK_EQUAL(
        Access::CacheVersion(), "CGovernanceManager-Version-17");
    BOOST_CHECK(Access::OldCacheVersionIsIgnored());

    Access::SetReady(*governance, true);
    CGovernanceObject proposal{
        uint256{}, /*revision=*/1,
        GetTime<std::chrono::seconds>().count(), uint256{},
        "7b2274797065223a317d"};
    const uint256 proposal_hash{
        Access::InsertObject(*governance, std::move(proposal))};
    Access::InsertActiveTriggerMarker(*governance, proposal_hash);
    BOOST_REQUIRE(governance->HaveObjectForHash(proposal_hash));
    BOOST_REQUIRE_EQUAL(Access::ActiveTriggerCount(*governance), 1U);

    // The default unit-test chain has no PQ registry deployment, which is the
    // startup failure mode this gate must survive without exposing cache data.
    BOOST_CHECK(!governance->InitOnLoad());
    BOOST_CHECK(!governance->IsReady());
    BOOST_CHECK(!governance->HaveObjectForHash(proposal_hash));
    BOOST_CHECK_EQUAL(governance->GetVoteCount(), 0);
    BOOST_CHECK_EQUAL(Access::ActiveTriggerCount(*governance), 0U);
    BOOST_CHECK(!governance->ToJson()["ready"].get_bool());

    CDataStream serialized{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK(!governance->SerializeObjectForHash(
        proposal_hash, serialized));
    std::vector<CGovernanceObject> objects;
    governance->GetAllNewerThan(objects, /*nMoreThanTime=*/0);
    BOOST_CHECK(objects.empty());

    const std::size_t retained{Access::ObjectCount(*governance)};
    governance->CheckAndRemove();
    BOOST_CHECK_EQUAL(Access::ObjectCount(*governance), retained);

    const CBlockIndex* active_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(active_tip != nullptr);
    const auto remembered{Access::RememberedAuthorityTip(*governance)};
    BOOST_CHECK_EQUAL(remembered.first, active_tip->nHeight);
    BOOST_CHECK(remembered.second == active_tip->GetBlockHash());

    // A later exact snapshot uses the same idempotent startup/reorg rebuild
    // before publication; no cache reload or permanent trigger mutation is
    // required to recover from the earlier local availability failure.
    CDeterministicMNList recovered_list{
        active_tip->GetBlockHash(), active_tip->nHeight,
        /*total_registered_count=*/0};
    llmq::pq::PQRegistrySnapshot recovered_snapshot;
    recovered_snapshot.height = active_tip->nHeight;
    recovered_snapshot.block_hash = active_tip->GetBlockHash();
    BOOST_REQUIRE(Access::RebuildIndexes(*governance));
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, *active_tip, recovered_list, recovered_snapshot));
    Access::RememberAuthorityTip(
        *governance, *active_tip, Access::AuthorityView{});
    governance->ObserveChainTip(active_tip);
    BOOST_REQUIRE(Access::PublishReadyForTip(
        *governance, *active_tip));
    BOOST_CHECK(governance->HaveObjectForHash(proposal_hash));
    BOOST_CHECK_EQUAL(Access::ActiveTriggerCount(*governance), 0U);
}

BOOST_FIXTURE_TEST_CASE(
    governance_disconnect_and_stale_tip_transitions_fail_closed,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->pprev != nullptr);

    Access::SetReady(*governance, true);
    CGovernanceObject retained{
        uint256{}, /*revision=*/1,
        GetTime<std::chrono::seconds>().count(), uint256{},
        "7b2274797065223a317d"};
    const uint256 retained_hash{
        Access::InsertObject(*governance, std::move(retained))};
    BOOST_REQUIRE(governance->HaveObjectForHash(retained_hash));

    // UndoSpecialTxs runs before CChain publishes the parent. The rollback
    // callback must close all governance reads during that mixed-state gap.
    BOOST_REQUIRE(governance->UndoBlock(tip));
    BOOST_CHECK(!governance->IsReady());
    BOOST_CHECK(!governance->HaveObjectForHash(retained_hash));

    CGovernanceObject rejected{
        uint256{}, /*revision=*/2,
        GetTime<std::chrono::seconds>().count(), uint256{},
        "7b2274797065223a317d"};
    const std::size_t before{Access::ObjectCount(*governance)};
    BOOST_CHECK(
        Access::AddObject(*governance, rejected, *m_node.peerman) ==
        GovernanceObjectAdmissionResult::UNAVAILABLE);
    BOOST_CHECK_EQUAL(Access::ObjectCount(*governance), before);

    governance->ObserveChainTip(tip->pprev);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *tip->pprev));
    BOOST_CHECK(governance->IsReadyForTip(tip->pprev));
    // The parent publication is internally consistent, but public reads still
    // resolve readiness against the active child until CChain disconnects it.
    BOOST_CHECK(!governance->HaveObjectForHash(retained_hash));
    BOOST_CHECK_EQUAL(Access::ObjectCount(*governance), before);

    governance->ObserveChainTip(tip);
    BOOST_CHECK(!governance->IsReadyForTip(tip));
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *tip));
    BOOST_CHECK(governance->HaveObjectForHash(retained_hash));

    uint256 stale_hash{InsecureRand256()};
    CBlockIndex stale;
    stale.nHeight = tip->nHeight;
    stale.pprev = tip->pprev;
    stale.phashBlock = &stale_hash;
    stale.BuildSkip();

    BOOST_CHECK(!governance->RevalidatePQGovernance(stale));
    BOOST_CHECK(governance->IsReadyForTip(tip));

    governance->ObserveChainTip(&stale);
    BOOST_CHECK(!governance->IsReady());
    BOOST_CHECK(!Access::PublishReadyForTip(*governance, *tip));
    BOOST_CHECK(!governance->IsReady());

    governance->ObserveChainTip(tip);
    // Returning A-B-A must not resurrect A's earlier readiness publication;
    // the active snapshot has to be rebuilt and published again.
    BOOST_CHECK(!governance->IsReadyForTip(tip));
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *tip));
    BOOST_CHECK(governance->IsReadyForTip(tip));
}

BOOST_FIXTURE_TEST_CASE(
    governance_validation_context_epoch_is_atomic_with_readiness,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    BOOST_REQUIRE(tip->pprev != nullptr);

    Access::SetReady(*governance, true);
    const auto initial{Access::ValidationContextEpoch(*governance)};
    BOOST_REQUIRE(initial);

    governance->ObserveChainTip(tip->pprev);
    BOOST_CHECK(!Access::ValidationContextEpoch(*governance));
    BOOST_REQUIRE(Access::PublishReadyForTip(
        *governance, *tip->pprev));
    BOOST_CHECK_EQUAL(
        *Access::ValidationContextEpoch(*governance), *initial);

    BOOST_REQUIRE(Access::PublishReadyForTip(
        *governance, *tip->pprev,
        /*advance_validation_context=*/true));
    const auto advanced{Access::ValidationContextEpoch(*governance)};
    BOOST_REQUIRE(advanced);
    BOOST_CHECK_EQUAL(*advanced, *initial + 1);

    governance->ObserveChainTip(nullptr);
    BOOST_CHECK(!Access::ValidationContextEpoch(*governance));
    governance->ObserveChainTip(tip);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *tip));
    const auto after_disconnect{
        Access::ValidationContextEpoch(*governance)};
    BOOST_REQUIRE(after_disconnect);
    BOOST_CHECK_EQUAL(*after_disconnect, *advanced + 1);
}

BOOST_FIXTURE_TEST_CASE(
    governance_readiness_publication_is_atomic_across_stale_callbacks,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    BOOST_REQUIRE(governance != nullptr);
    const CBlockIndex* active_tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(active_tip != nullptr);

    uint256 branch_hash{InsecureRand256()};
    CBlockIndex branch_tip;
    branch_tip.nHeight = active_tip->nHeight;
    branch_tip.pprev = active_tip->pprev;
    branch_tip.phashBlock = &branch_hash;
    branch_tip.BuildSkip();

    governance->ObserveChainTip(active_tip);
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *active_tip));

    std::promise<void> branch_observed_promise;
    std::shared_future<void> branch_observed{
        branch_observed_promise.get_future()};
    std::promise<void> stale_publication_attempted_promise;
    std::shared_future<void> stale_publication_attempted{
        stale_publication_attempted_promise.get_future()};
    std::atomic<bool> stale_publication{true};

    std::thread observer{[&] {
        governance->ObserveChainTip(&branch_tip);
        branch_observed_promise.set_value();
        stale_publication_attempted.wait();
        governance->ObserveChainTip(active_tip);
    }};
    std::thread stale_callback{[&] {
        branch_observed.wait();
        stale_publication.store(
            Access::PublishReadyForTip(*governance, *active_tip),
            std::memory_order_release);
        stale_publication_attempted_promise.set_value();
    }};
    observer.join();
    stale_callback.join();

    BOOST_CHECK(!stale_publication.load(std::memory_order_acquire));
    BOOST_CHECK(!governance->IsReadyForTip(active_tip));
    BOOST_REQUIRE(Access::PublishReadyForTip(*governance, *active_tip));
    BOOST_CHECK(governance->IsReadyForTip(active_tip));
}

BOOST_FIXTURE_TEST_CASE(
    governance_trigger_quarantine_restores_on_a_b_a,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    using namespace llmq::pq;
    BOOST_REQUIRE(governance != nullptr);

    auto& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct ActivationRestore {
        Consensus::Params& consensus;
        int height{consensus.nPQActivationHeight};
        int min_quorum{consensus.nGovernanceMinQuorum};
        ~ActivationRestore()
        {
            consensus.nPQActivationHeight = height;
            consensus.nGovernanceMinQuorum = min_quorum;
        }
    } restore{consensus};
    // Keep the initial DELETE vote below threshold; the test lowers this to
    // one only after the trigger has entered the reversible quarantine.
    consensus.nGovernanceMinQuorum = 2;

    std::array<uint256, 6> hashes{
        uint256{90}, uint256{91}, uint256{92}, uint256{93},
        uint256{94}, uint256{101}};
    BOOST_REQUIRE_GE(consensus.DIP0003Height, 0);
    std::vector<uint256> anchor_hashes(
        static_cast<std::size_t>(consensus.DIP0003Height) + 1);
    std::vector<CBlockIndex> anchor_chain(
        static_cast<std::size_t>(consensus.DIP0003Height) + 1);
    for (int height{0}; height <= consensus.DIP0003Height; ++height) {
        CBlockIndex& block{anchor_chain[height]};
        WriteLE32(anchor_hashes[height].begin(),
                  static_cast<uint32_t>(height) + 1);
        block.nHeight = height;
        block.pprev = height == 0 ? nullptr : &anchor_chain[height - 1];
        block.phashBlock = &anchor_hashes[height];
        block.BuildSkip();
    }
    CBlockIndex& anchor{anchor_chain.back()};
    anchor_hashes.back() = hashes[0];
    CBlockIndex signed_a;
    signed_a.nHeight = anchor.nHeight + 1;
    signed_a.pprev = &anchor;
    signed_a.phashBlock = &hashes[1];
    signed_a.BuildSkip();
    CBlockIndex tip_a;
    tip_a.nHeight = signed_a.nHeight + 1;
    tip_a.pprev = &signed_a;
    tip_a.phashBlock = &hashes[2];
    tip_a.BuildSkip();
    CBlockIndex signed_b;
    signed_b.nHeight = anchor.nHeight + 1;
    signed_b.pprev = &anchor;
    signed_b.phashBlock = &hashes[3];
    signed_b.BuildSkip();
    CBlockIndex tip_b;
    tip_b.nHeight = signed_b.nHeight + 1;
    tip_b.pprev = &signed_b;
    tip_b.phashBlock = &hashes[4];
    tip_b.BuildSkip();
    CBlockIndex tip_reactivated;
    tip_reactivated.nHeight = tip_a.nHeight + 1;
    tip_reactivated.pprev = &tip_a;
    tip_reactivated.phashBlock = &hashes[5];
    tip_reactivated.BuildSkip();

    consensus.nPQActivationHeight = signed_a.nHeight;

    const uint256 pro_tx_hash{uint256{95}};
    const COutPoint collateral{uint256{96}, 0};
    auto dmn_state{std::make_shared<CDeterministicMNState>()};
    dmn_state->keyIDOwner.begin()[0] = 1;
    dmn_state->nRegisteredHeight = 1;
    auto dmn{std::make_shared<CDeterministicMN>(1)};
    dmn->proTxHash = pro_tx_hash;
    dmn->collateralOutpoint = collateral;
    dmn->pdmnState = std::move(dmn_state);

    const uint256 voter_pro_tx_hash{uint256{102}};
    const COutPoint voter_collateral{uint256{103}, 0};
    auto voter_state{std::make_shared<CDeterministicMNState>()};
    voter_state->keyIDOwner.begin()[0] = 2;
    voter_state->nRegisteredHeight = 1;
    auto voter{std::make_shared<CDeterministicMN>(2)};
    voter->proTxHash = voter_pro_tx_hash;
    voter->collateralOutpoint = voter_collateral;
    voter->pdmnState = std::move(voter_state);

    OperatorKeyState operator_state{
        OperatorKeyState::ForOperator(pro_tx_hash)};
    operator_state.has_global_key = 1;
    operator_state.global_key_active = 1;
    operator_state.global_key.key_version = 1;
    operator_state.global_key.public_key[0] = 1;
    operator_state.global_key.activated_height = 1;
    operator_state.global_key.child_key_commitment.generation = 1;
    operator_state.global_key.child_key_commitment.first_epoch = 0;
    operator_state.global_key.child_key_commitment.tree_id = uint256{97};
    operator_state.global_key.child_key_commitment.root = uint256{98};
    BOOST_REQUIRE(IsStoredGlobalKeyRecordStructurallyValid(
        operator_state.global_key));

    OperatorKeyState voter_operator_state{
        OperatorKeyState::ForOperator(voter_pro_tx_hash)};
    voter_operator_state.has_global_key = 1;
    voter_operator_state.global_key_active = 1;
    voter_operator_state.global_key = operator_state.global_key;
    voter_operator_state.global_key.public_key[0] = 2;
    voter_operator_state.global_key.child_key_commitment.tree_id =
        uint256{104};
    voter_operator_state.global_key.child_key_commitment.root =
        uint256{105};
    BOOST_REQUIRE(IsStoredGlobalKeyRecordStructurallyValid(
        voter_operator_state.global_key));

    const auto make_context = [&](const CBlockIndex& tip,
                                  bool include_voter,
                                  std::size_t extra_members = 0) {
        CDeterministicMNList list{
            tip.GetBlockHash(), tip.nHeight,
            /*total_registered_count=*/
                static_cast<uint32_t>(
                    (include_voter ? 2 : 1) + extra_members)};
        list.AddMN(dmn, /*fBumpTotalCount=*/false);
        if (include_voter) {
            list.AddMN(voter, /*fBumpTotalCount=*/false);
        }
        for (std::size_t i{0}; i < extra_members; ++i) {
            auto extra_state{
                std::make_shared<CDeterministicMNState>()};
            extra_state->keyIDOwner.begin()[0] =
                static_cast<unsigned char>(10 + i);
            extra_state->nRegisteredHeight = 1;
            auto extra{std::make_shared<CDeterministicMN>(10 + i)};
            extra->proTxHash =
                uint256{static_cast<uint8_t>(200 + i)};
            extra->collateralOutpoint =
                COutPoint{
                    uint256{static_cast<uint8_t>(220 + i)}, 0};
            extra->pdmnState = std::move(extra_state);
            list.AddMN(extra, /*fBumpTotalCount=*/false);
        }
        PQRegistrySnapshot snapshot;
        snapshot.height = tip.nHeight;
        snapshot.block_hash = tip.GetBlockHash();
        snapshot.operator_states.push_back(operator_state);
        if (include_voter) {
            snapshot.operator_states.push_back(voter_operator_state);
        }
        return std::pair{std::move(list), std::move(snapshot)};
    };
    const auto [list_a, snapshot_a]{
        make_context(tip_a, /*include_voter=*/true)};
    const auto [list_b, snapshot_b]{
        make_context(tip_b, /*include_voter=*/false)};
    const auto [list_reactivated, snapshot_reactivated]{
        make_context(tip_reactivated, /*include_voter=*/false)};
    const auto [list_b_high_threshold, snapshot_b_high_threshold]{
        make_context(tip_b, /*include_voter=*/true,
                     /*extra_members=*/4)};
    const auto [list_reactivated_high_threshold,
                snapshot_reactivated_high_threshold]{
        make_context(tip_reactivated, /*include_voter=*/true,
                     /*extra_members=*/4)};

    const auto make_trigger = [&](uint256 proposal_hash,
                                  bool canonical) {
        std::vector<CGovernancePayment> payments;
        payments.emplace_back(
            PKHash(coinbaseKey.GetPubKey()), COIN, proposal_hash);
        const int event_height{
            tip_a.nHeight +
            (Params().GetConsensus().SuperBlockCycle(tip_a.nHeight) -
             tip_a.nHeight %
                 Params().GetConsensus().SuperBlockCycle(tip_a.nHeight))};
        CSuperblock schedule{event_height, std::move(payments)};
        CGovernanceObject trigger{
            uint256{}, /*revision=*/1,
            GetTime<std::chrono::seconds>().count(), uint256{},
            schedule.GetHexStrData()};
        Governance::Object wire{trigger.Object()};
        wire.masternodeOutpoint = collateral;
        GovernanceAuthorization authorization;
        authorization.signed_height = signed_a.nHeight;
        authorization.signed_block_hash = signed_a.GetBlockHash();
        authorization.pro_tx_hash = pro_tx_hash;
        authorization.global_key_version = 1;
        authorization.signature[0] = 1;
        if (canonical) {
            BOOST_REQUIRE(EncodeGovernanceAuthorization(
                authorization, wire.vchSig));
        } else {
            wire.vchSig.assign(GovernanceAuthorization::WIRE_SIZE, 0);
        }
        CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
        encoded << wire;
        CGovernanceObject decoded;
        encoded >> decoded;
        return decoded;
    };

    const auto make_trigger_with_delete_vote =
        [&](uint256 proposal_hash, const COutPoint& vote_collateral,
            const uint256& vote_pro_tx_hash) {
            CGovernanceObject trigger{
                make_trigger(proposal_hash, /*canonical=*/true)};
            CGovernanceVote vote{
                vote_collateral, trigger.GetHash(), VOTE_SIGNAL_DELETE,
                VOTE_OUTCOME_YES};
            vote.SetTime(GetTime<std::chrono::seconds>().count());
            GovernanceAuthorization vote_authorization;
            vote_authorization.signed_height = signed_a.nHeight;
            vote_authorization.signed_block_hash = signed_a.GetBlockHash();
            vote_authorization.pro_tx_hash = vote_pro_tx_hash;
            vote_authorization.global_key_version = 1;
            vote_authorization.signature[0] = 1;
            std::vector<unsigned char> encoded_vote_authorization;
            BOOST_REQUIRE(EncodeGovernanceAuthorization(
                vote_authorization, encoded_vote_authorization));
            vote.SetSignature(std::move(encoded_vote_authorization));

            CGovernanceObjectVoteFile vote_file;
            vote_file.AddVote(vote);
            CGovernanceObject::vote_m_t current_votes;
            vote_rec_t vote_record;
            vote_record.mapInstances.emplace(
                VOTE_SIGNAL_DELETE,
                vote_instance_t{VOTE_OUTCOME_YES,
                                /*last_update=*/0,
                                vote.GetTimestamp()});
            current_votes.emplace(
                vote_collateral, std::move(vote_record));
            CDataStream disk_object{SER_DISK, PROTOCOL_VERSION};
            disk_object << trigger.Object() << int64_t{0} << false
                        << current_votes << vote_file;
            CGovernanceObject trigger_with_vote;
            disk_object >> trigger_with_vote;
            return std::pair{std::move(trigger_with_vote),
                             std::move(vote)};
        };

    auto [trigger_with_vote, vote]{make_trigger_with_delete_vote(
        uint256{99}, voter_collateral, voter_pro_tx_hash)};

    const uint256 trigger_hash{Access::InsertObject(
        *governance, std::move(trigger_with_vote))};
    BOOST_REQUIRE(Access::RebuildIndexes(*governance));
    BOOST_REQUIRE(Access::ObjectHasVote(
        *governance, trigger_hash, vote.GetHash()));
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_a, list_a, snapshot_a));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 0}));
    BOOST_CHECK(!Access::IsCachedDelete(*governance, trigger_hash));
    Access::SetTriggerStatus(
        *governance, trigger_hash, SeenObjectStatus::Executed);
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_a, list_a, snapshot_a));
    BOOST_CHECK(Access::TriggerStatus(*governance, trigger_hash) ==
                SeenObjectStatus::Valid);

    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_b, list_b, snapshot_b));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 1}));
    BOOST_CHECK(!Access::IsCachedDelete(*governance, trigger_hash));

    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_a, list_a, snapshot_a));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 0}));
    BOOST_CHECK(!Access::IsCachedDelete(*governance, trigger_hash));

    // The voter becomes invalid while the trigger is branch-quarantined.
    // That delta is deliberately skipped so A-B-A recovery can retain votes
    // which may become valid again on the restored branch.
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_b, list_b, snapshot_b));
    consensus.nGovernanceMinQuorum = 1;
    Access::RefreshObjectFlags(
        *governance, trigger_hash, list_b);
    BOOST_REQUIRE(Access::IsCachedDeleteByVotes(
        *governance, trigger_hash));
    Access::ReconcileResult inactive_result;
    BOOST_REQUIRE(Access::ReconcileAuthorityDeltas(
        *governance, tip_b, list_b, snapshot_b,
        /*changed_pq_operators=*/{voter_collateral},
        /*changed_delegated_operators=*/{},
        /*reactivated_triggers=*/{}, inactive_result));
    BOOST_CHECK_EQUAL(inactive_result.checked_pq_votes, 0U);
    BOOST_REQUIRE(Access::ObjectHasVote(
        *governance, trigger_hash, vote.GetHash()));

    // Reactivating on A's descendant must force a complete per-object pass:
    // the old voter delta has already been consumed and cannot be rediscovered
    // from the current authority-map transition.
    std::set<uint256> reactivated;
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_reactivated, list_reactivated,
        snapshot_reactivated,
        /*recompute_cached_flags=*/false, &reactivated));
    BOOST_REQUIRE_EQUAL(reactivated.size(), 1U);
    BOOST_CHECK(reactivated.contains(trigger_hash));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{0, 0}));
    BOOST_REQUIRE(Access::IsCachedDeleteByVotes(
        *governance, trigger_hash));
    Access::ReconcileResult reactivated_result;
    BOOST_REQUIRE(Access::ReconcileAuthorityDeltas(
        *governance, tip_reactivated, list_reactivated,
        snapshot_reactivated,
        /*changed_pq_operators=*/{},
        /*changed_delegated_operators=*/{}, reactivated,
        reactivated_result));
    BOOST_CHECK_EQUAL(reactivated_result.checked_pq_votes, 1U);
    BOOST_CHECK(reactivated_result.refreshed_objects.contains(
        trigger_hash));
    BOOST_CHECK(!Access::ObjectHasVote(
        *governance, trigger_hash, vote.GetHash()));
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_reactivated, list_reactivated,
        snapshot_reactivated));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 0}));

    const uint256 malformed_hash{Access::InsertObject(
        *governance, make_trigger(uint256{100}, /*canonical=*/false))};
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_a, list_a, snapshot_a));
    BOOST_CHECK(Access::IsCachedDelete(*governance, malformed_hash));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 0}));

    // A second trigger keeps a valid DELETE vote while its creator is
    // quarantined. The larger roster raises the threshold during that
    // interval, and this remembered count is already current when the creator
    // becomes active again.
    governance->DeleteGovernanceObject(trigger_hash);
    auto [threshold_trigger, threshold_vote]{
        make_trigger_with_delete_vote(
            uint256{106}, collateral, pro_tx_hash)};
    const uint256 threshold_trigger_hash{Access::InsertObject(
        *governance, std::move(threshold_trigger))};
    BOOST_REQUIRE(Access::RebuildIndexes(*governance));
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_a, list_a, snapshot_a));
    BOOST_REQUIRE(Access::IsCachedDeleteByVotes(
        *governance, threshold_trigger_hash));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{0, 0}));

    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_b, list_b_high_threshold,
        snapshot_b_high_threshold));
    BOOST_CHECK((Access::TriggerStateCounts(*governance) ==
                 std::pair<std::size_t, std::size_t>{1, 1}));
    Access::RememberValidMNCount(
        *governance, list_b_high_threshold.GetValidMNsCount());
    BOOST_REQUIRE_EQUAL(
        Access::RememberedValidMNCount(*governance),
        list_reactivated_high_threshold.GetValidMNsCount());

    std::set<uint256> threshold_reactivated;
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_reactivated,
        list_reactivated_high_threshold,
        snapshot_reactivated_high_threshold,
        /*recompute_cached_flags=*/false,
        &threshold_reactivated));
    BOOST_REQUIRE_EQUAL(threshold_reactivated.size(), 1U);
    BOOST_CHECK(threshold_reactivated.contains(
        threshold_trigger_hash));
    BOOST_REQUIRE(Access::IsCachedDeleteByVotes(
        *governance, threshold_trigger_hash));

    Access::ReconcileResult threshold_result;
    BOOST_REQUIRE(Access::ReconcileAuthorityDeltas(
        *governance, tip_reactivated,
        list_reactivated_high_threshold,
        snapshot_reactivated_high_threshold,
        /*changed_pq_operators=*/{},
        /*changed_delegated_operators=*/{},
        threshold_reactivated, threshold_result));
    BOOST_CHECK_EQUAL(threshold_result.checked_pq_votes, 1U);
    BOOST_CHECK(threshold_result.refreshed_objects.contains(
        threshold_trigger_hash));
    BOOST_REQUIRE(Access::ObjectHasVote(
        *governance, threshold_trigger_hash,
        threshold_vote.GetHash()));

    Access::RefreshObjectFlags(
        *governance, threshold_trigger_hash,
        list_reactivated_high_threshold);
    BOOST_CHECK(!Access::IsCachedDelete(
        *governance, threshold_trigger_hash));
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_reactivated,
        list_reactivated_high_threshold,
        snapshot_reactivated_high_threshold,
        /*recompute_cached_flags=*/false));
    const auto incremental_state{
        Access::TriggerStateCounts(*governance)};
    BOOST_CHECK((incremental_state ==
                 std::pair<std::size_t, std::size_t>{1, 0}));

    // A complete cached-flag rebuild must now be idempotent: incremental
    // reactivation converged to exactly the full-rebuild state.
    BOOST_REQUIRE(Access::RebuildTriggerState(
        *governance, tip_reactivated,
        list_reactivated_high_threshold,
        snapshot_reactivated_high_threshold));
    BOOST_CHECK(Access::TriggerStateCounts(*governance) ==
                incremental_state);
    BOOST_CHECK(!Access::IsCachedDelete(
        *governance, threshold_trigger_hash));
}

BOOST_FIXTURE_TEST_CASE(
    governance_persisted_vote_budget_is_atomic_at_boundary,
    TestChain100Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    const uint256 parent{uint256{110}};
    CGovernanceVote first{
        COutPoint{uint256{111}, 0}, parent,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    first.SetTime(1);
    first.SetSignature(std::vector<unsigned char>{0x01});
    const uint64_t vote_bytes{Access::VoteBytes(first)};
    const uint64_t limit{Access::MaxPersistedVoteBytes()};
    BOOST_REQUIRE_LT(vote_bytes, limit);

    Access::SetPersistedVoteBytes(*governance, limit);
    BOOST_CHECK(!Access::StoreOrphanVote(
        *governance, parent, first,
        GetTime<std::chrono::seconds>().count() + 60));
    BOOST_CHECK_EQUAL(Access::OrphanVoteCount(*governance), 0U);
    BOOST_CHECK_EQUAL(Access::PersistedVoteBytes(*governance), limit);

    Access::SetPersistedVoteBytes(*governance, limit - vote_bytes);
    BOOST_REQUIRE(Access::StoreOrphanVote(
        *governance, parent, first,
        GetTime<std::chrono::seconds>().count() + 60));
    BOOST_CHECK_EQUAL(Access::PersistedVoteBytes(*governance), limit);

    CGovernanceVote overflow{
        COutPoint{uint256{112}, 0}, parent,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    overflow.SetTime(2);
    BOOST_CHECK(!Access::StoreOrphanVote(
        *governance, parent, overflow,
        GetTime<std::chrono::seconds>().count() + 60));
    BOOST_CHECK_EQUAL(Access::OrphanVoteCount(*governance), 1U);
    BOOST_CHECK_EQUAL(Access::PersistedVoteBytes(*governance), limit);

    Access::ClearOrphanVotes(*governance);
    BOOST_CHECK_EQUAL(Access::PersistedVoteBytes(*governance), 0U);
}

BOOST_FIXTURE_TEST_CASE(
    verified_orphan_vote_reports_retention_and_rejects_corrupt_variant,
    TestChainDIP3V19Setup)
{
    using Access = governance_tests::CGovernanceManagerTestAccess;
    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);

    const uint256 tip_hash{tip->GetBlockHash()};
    const CDeterministicMNList original_list{
        deterministicMNManager->GetListForBlock(tip)};
    struct RestoreMNList {
        uint256 tip_hash;
        CDeterministicMNList list;
        ~RestoreMNList()
        {
            deterministicMNManager->m_evoDb->WriteCache(
                tip_hash, std::move(list));
        }
    } restore{tip_hash, original_list};

    CKey voting_key;
    voting_key.MakeNewKey(/*fCompressed=*/true);
    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner = voting_key.GetPubKey().GetID();
    state->keyIDVoting = voting_key.GetPubKey().GetID();
    state->nRegisteredHeight = 1;
    uint64_t internal_id{1};
    while (original_list.GetMNByInternalId(internal_id)) ++internal_id;
    auto dmn{std::make_shared<CDeterministicMN>(internal_id)};
    dmn->proTxHash = InsecureRand256();
    dmn->collateralOutpoint = COutPoint{InsecureRand256(), 0};
    dmn->pdmnState = std::move(state);
    CDeterministicMNList validation_mn_list{original_list};
    validation_mn_list.AddMN(dmn);
    deterministicMNManager->m_evoDb->WriteCache(
        tip_hash, validation_mn_list);

    CGovernanceVote vote{
        dmn->collateralOutpoint, InsecureRand256(),
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    BOOST_REQUIRE(vote.Sign(
        voting_key, voting_key.GetPubKey().GetID()));
    BOOST_REQUIRE(vote.IsValid(validation_mn_list));

    bool orphan_vote_retained{false};
    CGovernanceException orphan_exception;
    BOOST_CHECK(!Access::ProcessVoteAtHeight(
        *governance, tip->nHeight, vote, orphan_exception,
        *m_node.connman, &orphan_vote_retained));
    BOOST_CHECK(orphan_vote_retained);
    BOOST_CHECK_EQUAL(
        orphan_exception.GetType(), GOVERNANCE_EXCEPTION_WARNING);
    BOOST_CHECK_EQUAL(Access::OrphanVoteCount(*governance), 1U);

    bool duplicate_vote_retained{false};
    CGovernanceException duplicate_exception;
    BOOST_CHECK(!Access::ProcessVoteAtHeight(
        *governance, tip->nHeight, vote, duplicate_exception,
        *m_node.connman, &duplicate_vote_retained));
    BOOST_CHECK(duplicate_vote_retained);
    BOOST_CHECK_EQUAL(
        duplicate_exception.GetType(), GOVERNANCE_EXCEPTION_WARNING);
    BOOST_CHECK_EQUAL(Access::OrphanVoteCount(*governance), 1U);

    CGovernanceVote corrupt{vote};
    corrupt.SetSignature(std::vector<unsigned char>(
        CPubKey::COMPACT_SIGNATURE_SIZE, 0));
    bool corrupt_vote_retained{true};
    CGovernanceException corrupt_exception;
    BOOST_CHECK(!Access::ProcessVoteAtHeight(
        *governance, tip->nHeight, corrupt, corrupt_exception,
        *m_node.connman, &corrupt_vote_retained));
    BOOST_CHECK(!corrupt_vote_retained);
    BOOST_CHECK_EQUAL(
        corrupt_exception.GetType(),
        GOVERNANCE_EXCEPTION_PERMANENT_ERROR);
    BOOST_CHECK_EQUAL(corrupt_exception.GetNodePenalty(), 20);
    BOOST_CHECK_EQUAL(Access::OrphanVoteCount(*governance), 1U);
}

// SYSCOIN: invalid orphan votes never consume retained admission capacity.
BOOST_FIXTURE_TEST_CASE(
    invalid_orphan_governance_votes_are_rejected_and_storage_is_bounded,
    TestChain100Setup)
{
    const uint256 unknown_parent{InsecureRand256()};
    CGovernanceVote invalid{
        COutPoint{InsecureRand256(), 0}, unknown_parent,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    invalid.SetSignature(std::vector<unsigned char>(
        CPubKey::COMPACT_SIGNATURE_SIZE, 0));
    CGovernanceException exception;
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::
            ProcessVoteAtHeight(
                *governance, /*observed_height=*/1000, invalid,
                exception, *m_node.connman));
    BOOST_CHECK_EQUAL(
        exception.GetType(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR);
    BOOST_CHECK_EQUAL(exception.GetNodePenalty(), 20);
    BOOST_CHECK_EQUAL(
        governance_tests::CGovernanceManagerTestAccess::
            OrphanVoteCount(*governance),
        0U);

    const CBlockIndex* tip{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
    BOOST_REQUIRE(tip != nullptr);
    const int future_event_height{
        tip->nHeight + Params().GetConsensus().SuperBlockCycle(tip->nHeight)};
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(future_event_height));
    std::vector<CGovernancePayment> payments;
    payments.emplace_back(
        PKHash(coinbaseKey.GetPubKey()), COIN, InsecureRand256());
    CSuperblock schedule{future_event_height, std::move(payments)};
    CGovernanceObject trigger{
        uint256{}, /*revision=*/1,
        GetTime<std::chrono::seconds>().count(), uint256{},
        schedule.GetHexStrData()};
    const uint256 intended_trigger_hash{trigger.GetHash()};
    CGovernanceVote invalid_pq{
        COutPoint{InsecureRand256(), 0}, intended_trigger_hash,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    invalid_pq.SetSignature(std::vector<unsigned char>(
        llmq::pq::GovernanceAuthorization::WIRE_SIZE, 0));
    const auto validation_mn_list{
        deterministicMNManager->GetListForBlock(tip)};
    CGovernanceException preverification_required;
    BOOST_CHECK(!trigger.ProcessVote(
        *tip, validation_mn_list, invalid_pq,
        preverification_required,
        /*pq_signature_preverified=*/false));
    BOOST_CHECK(
        std::string{preverification_required.what()}.find(
            "requires preverified SLH authorization") !=
        std::string::npos);

    uint256 trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            InsertPreviouslyAdmittedTrigger(
                *governance, std::move(trigger), trigger_hash));
    BOOST_CHECK(trigger_hash == intended_trigger_hash);
    const int64_t orphan_expiry{
        GetTime<std::chrono::seconds>().count() +
        GOVERNANCE_ORPHAN_EXPIRATION_TIME};
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::StoreOrphanVote(
            *governance, trigger_hash, invalid_pq, orphan_expiry));
    governance_tests::CGovernanceManagerTestAccess::CheckOrphanVotes(
        *governance, trigger_hash, *m_node.peerman);
    BOOST_CHECK_EQUAL(
        governance_tests::CGovernanceManagerTestAccess::
            OrphanVoteCount(*governance),
        0U);

    const auto per_object{
        governance_tests::CGovernanceManagerTestAccess::
            MaxOrphanVotesPerObject()};
    const auto total{
        governance_tests::CGovernanceManagerTestAccess::MaxOrphanVotes()};
    const int64_t expiry{orphan_expiry};
    const auto hash_for = [](uint64_t value) {
        uint256 hash;
        WriteLE64(hash.begin(), value);
        return hash;
    };
    for (std::size_t i{0}; i < per_object; ++i) {
        CGovernanceVote vote{
            COutPoint{hash_for(i + 1), 0},
            unknown_parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
        vote.SetTime(static_cast<int64_t>(i + 1));
        const bool stored{
            governance_tests::CGovernanceManagerTestAccess::StoreOrphanVote(
                *governance, unknown_parent, vote,
                expiry + static_cast<int64_t>(i))};
        BOOST_REQUIRE_MESSAGE(
            stored,
            "orphan index=" << i << ", total="
                            << governance_tests::
                                   CGovernanceManagerTestAccess::
                                   OrphanVoteCount(*governance));
    }
    CGovernanceVote overflow{
        COutPoint{hash_for(per_object + 1), 0},
        unknown_parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    overflow.SetTime(static_cast<int64_t>(per_object + 1));
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::StoreOrphanVote(
            *governance, unknown_parent, overflow,
            expiry + static_cast<int64_t>(per_object)));

    for (std::size_t i{per_object}; i < total; ++i) {
        const uint256 parent{hash_for(i + 1)};
        CGovernanceVote vote{
            COutPoint{hash_for(total + i + 1), 0},
            parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
        vote.SetTime(static_cast<int64_t>(i + 1));
        BOOST_REQUIRE(
            governance_tests::CGovernanceManagerTestAccess::
                StoreOrphanVote(*governance, parent, vote, expiry));
    }
    BOOST_CHECK_EQUAL(
        governance_tests::CGovernanceManagerTestAccess::
            OrphanVoteCount(*governance),
        total);
    CGovernanceVote global_overflow{
        COutPoint{hash_for(2 * total + 1), 0},
        hash_for(total + 1),
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::StoreOrphanVote(
            *governance, global_overflow.GetParentHash(),
            global_overflow, expiry));
}

// SYSCOIN END: fork governance and PQ finality chainstate regressions.
BOOST_AUTO_TEST_SUITE_END()
