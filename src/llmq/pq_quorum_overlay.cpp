// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_overlay.h>
#include <llmq/quorums_chainlocks.h>

#include <chain.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <logging.h>
#include <masternode/activemasternode.h>
#include <net.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace llmq {
std::optional<int32_t> GetPQQuorumOverlayTargetHeight(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t predecessor_height,
    int32_t tip_height) noexcept
{
    const auto window{pq::CurrentChainLockSigningWindow(
        schedule, predecessor_height, tip_height)};
    return window ? std::optional<int32_t>{window->target_height}
                  : std::nullopt;
}

namespace {

std::optional<pq::GlobalPublicKey> GetLocalGlobalPublicKey()
{
    LOCK(activeMasternodeInfoCs);
    if (!fMasternodeMode || !activeMasternodeInfo.operatorKeyManager ||
        !activeMasternodeInfo.operatorKeyManager->IsValid()) {
        return std::nullopt;
    }
    return activeMasternodeInfo.operatorKeyManager->GetGlobalPublicKey();
}

PQQuorumConnectionSet GetRelayConnections(
    const std::vector<uint256>& participants,
    const uint256& local_pro_tx_hash)
{
    const auto local_it{
        std::find(participants.begin(), participants.end(), local_pro_tx_hash)};
    if (local_it == participants.end() || participants.size() <= 1) return {};

    const std::size_t local_index{
        static_cast<std::size_t>(local_it - participants.begin())};
    PQQuorumConnectionSet result;
    std::size_t gap{1};
    std::size_t gap_max{participants.size() - 1};
    std::size_t step{0};
    while ((gap_max >>= 1) != 0 || step <= 1) {
        const std::size_t index{(local_index + gap) % participants.size()};
        gap <<= 1;
        ++step;
        if (participants[index] != local_pro_tx_hash) {
            result.emplace(participants[index]);
        }
    }
    return result;
}

std::array<pq::QuorumDescriptor, pq::ACTIVE_QUORUMS> Descriptors(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters)
{
    std::array<pq::QuorumDescriptor, pq::ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    return descriptors;
}

} // namespace

CPQQuorumConnectionOverlay* pqQuorumConnectionOverlay{nullptr};

PQQuorumConnectionSet GetPQQuorumRelayConnections(
    const pq::FrozenQuorumRoster& roster,
    const uint256& local_pro_tx_hash)
{
    std::vector<uint256> participants;
    participants.reserve(roster.members.size());
    for (const auto& member : roster.members) {
        if (member.eligible && member.child_root) {
            participants.push_back(member.pro_tx_hash);
        }
    }

    return GetRelayConnections(participants, local_pro_tx_hash);
}

PQQuorumConnectionSet GetPQQuorumUnionRelayConnections(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash)
{
    std::vector<uint256> participants;
    participants.reserve(pq::ACTIVE_QUORUMS * pq::QUORUM_SIZE);
    std::unordered_set<uint256, StaticSaltedHasher> seen;
    for (const auto& roster : rosters) {
        for (const auto& member : roster.members) {
            if (member.eligible && member.child_root &&
                seen.emplace(member.pro_tx_hash).second) {
                participants.push_back(member.pro_tx_hash);
            }
        }
    }
    return GetRelayConnections(participants, local_pro_tx_hash);
}

PQQuorumOverlayPlan BuildPQQuorumOverlayPlan(
    const uint256& genesis_hash,
    int32_t target_height,
    const uint256& target_block_hash,
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash)
{
    PQQuorumOverlayPlan plan;
    if (genesis_hash.IsNull() || target_height < 0 ||
        target_block_hash.IsNull() || local_pro_tx_hash.IsNull()) return plan;
    auto connections{
        GetPQQuorumUnionRelayConnections(rosters, local_pro_tx_hash)};
    if (connections.empty()) return plan;
    const uint256 group{pq::GetQuorumContextHash(
        genesis_hash, target_height, target_block_hash,
        Descriptors(rosters))};
    if (!group.IsNull()) plan.emplace(group, std::move(connections));
    return plan;
}

PQQuorumOverlayPlan BuildPreparedPQQuorumOverlayPlan(
    const uint256& quorum_context_hash,
    const PQQuorumConnectionSet& relay_members)
{
    if (quorum_context_hash.IsNull() || relay_members.empty()) return {};
    return {{quorum_context_hash, relay_members}};
}

bool IsPreparedPQQuorumOverlaySourceCurrent(
    const std::optional<PQQuorumOverlayPredecessor>& expected,
    const std::optional<PQQuorumOverlayPredecessor>& accepted) noexcept
{
    if (expected.has_value() != accepted.has_value()) return false;
    return !expected ||
           (expected->height == accepted->height &&
            expected->block_hash == accepted->block_hash);
}

PQQuorumOverlayReconciler::PQQuorumOverlayReconciler(Install install,
                                                     Remove remove)
    : m_install{std::move(install)}, m_remove{std::move(remove)}
{
}

void PQQuorumOverlayReconciler::Apply(const PQQuorumOverlayPlan& plan)
{
    for (const auto& [group, connections] : m_installed) {
        (void)connections;
        if (plan.count(group) == 0 && m_remove) m_remove(group);
    }
    for (const auto& [group, connections] : plan) {
        const auto old{m_installed.find(group)};
        if ((old == m_installed.end() || old->second != connections) &&
            m_install) {
            m_install(group, connections);
        }
    }
    m_installed = plan;
}

void PQQuorumOverlayReconciler::Clear()
{
    for (const auto& [group, connections] : m_installed) {
        (void)connections;
        if (m_remove) m_remove(group);
    }
    m_installed.clear();
}

CPQQuorumConnectionOverlay::CPQQuorumConnectionOverlay(
    CConnman& connman,
    pq::FrozenQuorumRosterCachePtr roster_cache,
    PQChainLockPredecessorHeight predecessor_height)
    : m_roster_cache{std::move(roster_cache)},
      m_predecessor_height{std::move(predecessor_height)},
      m_reconciler{
          [&connman](const uint256& group,
                     const PQQuorumConnectionSet& connections) {
              connman.SetMasternodeQuorumNodes(group, connections);
              connman.SetMasternodeQuorumRelayMembers(group, connections);
          },
          [&connman](const uint256& group) {
              connman.RemoveMasternodeQuorumNodes(group);
          }}
{
}

CPQQuorumConnectionOverlay::~CPQQuorumConnectionOverlay()
{
    Clear();
}

void CPQQuorumConnectionOverlay::ReconcileLocked()
{
    PQQuorumOverlayPlan combined{m_chainlock_plan};
    if (m_payment_audit_plan) {
        const bool inserted{combined.emplace(
            m_payment_audit_plan->group,
            m_payment_audit_plan->relay_members).second};
        if (!inserted) {
            // The audit group is domain-separated from ChainLock contexts.
            // Treat a collision as an invalid lease, never as permission to
            // replace the finality topology.
            m_retired_payment_audit_generation = std::max(
                m_retired_payment_audit_generation,
                m_payment_audit_plan->runtime_generation);
            m_payment_audit_plan.reset();
        }
    }
    m_reconciler.Apply(combined);
}

void CPQQuorumConnectionOverlay::ClearLocked()
{
    ++m_revision;
    m_context.reset();
    m_chainlock_plan.clear();
    m_payment_audit_plan.reset();
    m_reconciler.Clear();
}

void CPQQuorumConnectionOverlay::Clear()
{
    LOCK(m_mutex);
    ClearLocked();
}

bool CPQQuorumConnectionOverlay::ApplyPreparedContext(
    const uint256& quorum_context_hash,
    const PQQuorumConnectionSet& relay_members,
    const std::optional<PQQuorumOverlayPredecessor>& accepted_predecessor)
{
    const auto plan{BuildPreparedPQQuorumOverlayPlan(
        quorum_context_hash, relay_members)};
    if (plan.empty()) return false;
    uint64_t observed_revision{0};
    {
        LOCK(m_mutex);
        observed_revision = m_revision;
    }
    const auto accepted{chainLocksHandler
        ? chainLocksHandler->GetBestChainLock()
        : CChainLockSigCPtr{}};
    const std::optional<PQQuorumOverlayPredecessor> current_predecessor{
        accepted
            ? std::optional<PQQuorumOverlayPredecessor>{
                  PQQuorumOverlayPredecessor{
                      accepted->statement.height,
                      accepted->statement.block_hash}}
            : std::nullopt};
    if (!IsPreparedPQQuorumOverlaySourceCurrent(
            accepted_predecessor, current_predecessor)) {
        return false;
    }
    LOCK(m_mutex);
    if (m_revision != observed_revision) return false;
    if (m_chainlock_plan == plan) return true;
    if (m_payment_audit_plan &&
        plan.count(m_payment_audit_plan->group) != 0) {
        return false;
    }
    m_chainlock_plan = plan;
    ReconcileLocked();
    // A later tip callback must compare its accepted context against the
    // prepared plan instead of skipping on an older accepted-context cache.
    m_context.reset();
    ++m_revision;
    return true;
}

bool CPQQuorumConnectionOverlay::ApplyPaymentAuditContext(
    const uint256& group,
    const PQQuorumConnectionSet& relay_members,
    uint64_t runtime_generation)
{
    if (group.IsNull() || relay_members.empty() ||
        runtime_generation == 0) {
        return false;
    }
    LOCK(m_mutex);
    if (runtime_generation <= m_retired_payment_audit_generation ||
        m_chainlock_plan.count(group) != 0) {
        return false;
    }
    if (m_payment_audit_plan) {
        if (runtime_generation <
            m_payment_audit_plan->runtime_generation) {
            return false;
        }
        if (runtime_generation ==
            m_payment_audit_plan->runtime_generation) {
            return m_payment_audit_plan->group == group &&
                   m_payment_audit_plan->relay_members == relay_members;
        }
        m_retired_payment_audit_generation = std::max(
            m_retired_payment_audit_generation,
            m_payment_audit_plan->runtime_generation);
    }
    m_payment_audit_plan = PaymentAuditPlan{
        group, relay_members, runtime_generation};
    ReconcileLocked();
    ++m_revision;
    return true;
}

bool CPQQuorumConnectionOverlay::RemovePaymentAuditContext(
    const uint256& group,
    uint64_t runtime_generation)
{
    if (group.IsNull() || runtime_generation == 0) return false;
    LOCK(m_mutex);
    if (m_payment_audit_plan) {
        if (runtime_generation !=
                m_payment_audit_plan->runtime_generation ||
            m_payment_audit_plan->group != group) {
            return false;
        }
    }
    m_retired_payment_audit_generation = std::max(
        m_retired_payment_audit_generation, runtime_generation);
    if (!m_payment_audit_plan) return true;
    m_payment_audit_plan.reset();
    ReconcileLocked();
    ++m_revision;
    return true;
}

void CPQQuorumConnectionOverlay::UpdatedBlockTip(
    const CBlockIndex* new_tip,
    bool initial_download)
{
    const auto predecessor_height{
        m_predecessor_height ? m_predecessor_height() : std::nullopt};
    // Validation callbacks normally hold cs_main. Taking it recursively also
    // makes direct startup/test calls safe and fixes the lock order relative
    // to active-chain updates.
    LOCK(cs_main);
    LOCK(m_mutex);
    ++m_revision;

    if (initial_download || new_tip == nullptr || !m_roster_cache ||
        !deterministicMNManager || !predecessor_height) {
        ClearLocked();
        return;
    }
    const auto& quorum_config{m_roster_cache->Config()};
    const auto& genesis_hash{m_roster_cache->GenesisHash()};

    const auto target_height{GetPQQuorumOverlayTargetHeight(
        quorum_config.schedule, *predecessor_height,
        new_tip->nHeight)};
    const CBlockIndex* target{
        target_height ? new_tip->GetAncestor(*target_height) : nullptr};
    const auto active_epochs{
        target_height
            ? pq::ActiveEpochsAtHeight(quorum_config.schedule,
                                       *target_height)
            : std::nullopt};
    if (target == nullptr || !active_epochs) {
        ClearLocked();
        return;
    }

    const auto public_key{GetLocalGlobalPublicKey()};
    if (!public_key) {
        ClearLocked();
        return;
    }

    pq::PQRegistryReadView current_registry;
    std::string registry_error;
    if (!deterministicMNManager->GetPQRegistryReadView(
            new_tip, current_registry, registry_error)) {
        // Snapshot recovery may be transient during a reorg. Keeping the old
        // bounded overlay cannot authorize a share and avoids needless
        // liveness loss while deterministic state catches up.
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology at height=%d: %s\n",
                 new_tip->nHeight, registry_error);
        return;
    }
    if (current_registry.Height() != new_tip->nHeight ||
        current_registry.BlockHash() != new_tip->GetBlockHash()) {
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology; active registry "
                 "snapshot mismatch at height=%d\n",
                 new_tip->nHeight);
        return;
    }
    const auto local_operator{
        current_registry.FindActiveOperatorByGlobalKey(*public_key)};
    if (!local_operator) {
        ClearLocked();
        return;
    }

    const auto& newest_identity{active_epochs->back()};
    const CBlockIndex* newest_base{
        target->GetAncestor(newest_identity.base_height)};
    if (newest_base == nullptr) {
        ClearLocked();
        return;
    }
    const auto accepted_chainlock{
        chainLocksHandler ? chainLocksHandler->GetBestChainLock() : nullptr};
    if (!accepted_chainlock ||
        !accepted_chainlock->statement.roster_beacons.active
             .IsForNewestEpoch(newest_identity.epoch)) {
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology; no exact accepted "
                 "roster beacon bundle for target=%d\n",
                 *target_height);
        return;
    }
    const auto& beacon_bundle{
        accepted_chainlock->statement.roster_beacons.active};
    const auto beacon_bundle_hash{pq::GetActiveRosterBeaconBundleHash(
        genesis_hash, beacon_bundle)};
    if (!beacon_bundle_hash) {
        ClearLocked();
        return;
    }
    const Context context{*local_operator, newest_identity.epoch,
                          newest_base->GetBlockHash(), *beacon_bundle_hash};
    if (m_context && *m_context == context) return;

    pq::QuorumBuildError build_error{pq::QuorumBuildError::NONE};
    const auto verified{
        chainLocksHandler->GetVerifiedRosterSetForAccepted(
            *accepted_chainlock, *target_height, *target, &build_error)};
    const auto rosters{verified ? verified->RostersPtr()
                                : pq::FrozenQuorumRostersPtr{}};
    if (!rosters) {
        // Consensus validation and share verification remain fail-closed. A
        // stale bounded connection set is harmless and can help recovery.
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology; roster build "
                 "failed at target=%d error=%u\n",
                 *target_height, static_cast<unsigned>(build_error));
        return;
    }

    const auto plan{BuildPQQuorumOverlayPlan(
        genesis_hash, *target_height, target->GetBlockHash(), *rosters,
        *local_operator)};
    if (m_payment_audit_plan &&
        plan.count(m_payment_audit_plan->group) != 0) {
        m_retired_payment_audit_generation = std::max(
            m_retired_payment_audit_generation,
            m_payment_audit_plan->runtime_generation);
        m_payment_audit_plan.reset();
    }
    m_chainlock_plan = plan;
    ReconcileLocked();
    m_context = context;
    LogPrint(BCLog::NET_NETCONN,
             "PQ overlay updated at target=%d epoch=%u groups=%u\n",
             *target_height, newest_identity.epoch,
             static_cast<unsigned>(plan.size()));
}

} // namespace llmq
