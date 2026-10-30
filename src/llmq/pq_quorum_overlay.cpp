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
#include <stdexcept>
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

struct LocalOperatorIdentity {
    uint256 pro_tx_hash;
    uint32_t key_version{0};
    pq::GlobalPublicKey public_key{};
};

std::optional<LocalOperatorIdentity> GetLocalOperatorIdentity()
{
    LocalOperatorIdentity identity;
    CService service;
    if (!GetActiveMasternodeIdentity(identity.pro_tx_hash, identity.key_version,
                                    identity.public_key, service)) return std::nullopt;
    return identity;
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

bool PQShareRelayFallback::Start(PQShareRelayFallbackKey key,
                                  std::vector<uint256> candidates,
                                  int64_t now_seconds)
{
    if (m_key == key) return true;
    Reset();
    if (key.context_hash.IsNull() || key.local_pro_tx_hash.IsNull() ||
        key.admission_generation == 0 || key.collector_generation == 0 ||
        now_seconds < 0 || candidates.size() > pq::ACTIVE_QUORUMS * pq::QUORUM_SIZE) return false;
    PQQuorumConnectionSet seen;
    for (const auto& identity : candidates) {
        if (identity.IsNull() || identity == key.local_pro_tx_hash || !seen.insert(identity).second) return false;
    }
    m_key = std::move(key);
    m_candidates = std::move(candidates);
    m_started = now_seconds;
    return true;
}

bool PQShareRelayFallback::Advance(int64_t now_seconds, bool certificate_complete)
{
    if (!m_key) return false;
    if (certificate_complete || now_seconds < m_started ||
        (m_attempted && now_seconds < m_last_attempt)) {
        const bool changed{!m_members.empty()};
        m_members.clear();
        m_selected.clear();
        m_complete = true;
        return changed;
    }
    if (m_complete || now_seconds - m_started < GRACE_SECONDS ||
        (m_attempted && now_seconds - m_last_attempt < ROTATION_SECONDS) ||
        m_next == m_candidates.size()) return false;
    if (m_selected.size() == MAX_EXTRA_CONNECTIONS) {
        m_members.erase(m_selected.front());
        m_selected.erase(m_selected.begin());
    }
    const auto identity{m_candidates[m_next++]};
    m_selected.push_back(identity);
    m_members.insert(identity);
    m_last_attempt = now_seconds;
    m_attempted = true;
    return true;
}

void PQShareRelayFallback::Reset()
{
    m_key.reset();
    m_candidates.clear();
    m_selected.clear();
    m_members.clear();
    m_next = 0;
    m_started = 0;
    m_last_attempt = 0;
    m_attempted = false;
    m_complete = false;
}

std::vector<uint256> BuildPQShareRelayFallbackCandidates(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash)
{
    if (local_pro_tx_hash.IsNull()) return {};
    const auto normal{GetPQQuorumUnionRelayConnections(rosters, local_pro_tx_hash)};
    PQQuorumConnectionSet seen;
    std::vector<uint256> candidates;
    for (const auto& roster : rosters) {
        for (const auto& member : roster.members) {
            if (member.eligible && member.child_root && !member.pro_tx_hash.IsNull() &&
                member.pro_tx_hash != local_pro_tx_hash && !normal.contains(member.pro_tx_hash) &&
                seen.insert(member.pro_tx_hash).second) candidates.push_back(member.pro_tx_hash);
        }
    }
    return candidates;
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

void PQQuorumOverlayReconciler::Apply(const PQQuorumOverlayPlan& plan, bool force_install)
{
    // Publish replacement intent first. Retiring an old fallback group must
    // see another group's continuing need before deciding to close its socket.
    for (const auto& [group, connections] : plan) {
        const auto old{m_installed.find(group)};
        if ((force_install || old == m_installed.end() || old->second != connections) && m_install) {
            m_install(group, connections);
        }
    }
    for (const auto& [group, connections] : m_installed) {
        (void)connections;
        if (plan.count(group) == 0 && m_remove) m_remove(group);
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
    PQChainLockPredecessorHeight predecessor_height,
    pq::BTCCScheduleConfig btcc_schedule,
    PQQuorumOverlaySourceValidator source_validator)
    : m_roster_cache{std::move(roster_cache)},
      m_predecessor_height{std::move(predecessor_height)},
      m_btcc_schedule{btcc_schedule},
      m_source_validator{std::move(source_validator)},
      m_reconciler{
          [this, &connman](const uint256& group,
                     const PQQuorumConnectionSet& connections) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
              const auto fallback{m_chainlock_fallback.find(group)};
              connman.SetMasternodeQuorumNodes(group, connections,
                  fallback == m_chainlock_fallback.end() ? PQQuorumConnectionSet{} : fallback->second);
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

void CPQQuorumConnectionOverlay::ReconcileLocked(bool force_install)
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
    m_reconciler.Apply(combined, force_install);
}

void CPQQuorumConnectionOverlay::ClearLocked()
{
    ++m_revision;
    m_context.reset();
    m_chainlock_plan.clear();
    m_chainlock_fallback.clear();
    m_fallback_context.reset();
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
    const std::optional<PQQuorumOverlayPredecessor>& accepted_predecessor,
    const PQQuorumConnectionSet& fallback_members,
    const uint256& local_pro_tx_hash,
    const std::optional<PQQuorumOverlayTarget>& prepared_target,
    const std::optional<PQShareRelayFallbackKey>& source_key)
{
    const auto local_identity{fallback_members.empty()
        ? std::optional<LocalOperatorIdentity>{} : GetLocalOperatorIdentity()};
    if ((!fallback_members.empty() && local_pro_tx_hash.IsNull()) ||
        (!fallback_members.empty() &&
         (!local_identity || local_identity->pro_tx_hash != local_pro_tx_hash)) ||
        (!fallback_members.empty() &&
         (!prepared_target || prepared_target->height < 0 || prepared_target->block_hash.IsNull())) ||
        (!fallback_members.empty() &&
         (!source_key || source_key->context_hash != quorum_context_hash ||
          source_key->local_pro_tx_hash != local_pro_tx_hash ||
          source_key->admission_generation == 0 || source_key->collector_generation == 0 ||
          !m_source_validator)) ||
        fallback_members.size() > PQShareRelayFallback::MAX_EXTRA_CONNECTIONS ||
        !std::all_of(fallback_members.begin(), fallback_members.end(),
                     [&](const auto& member) { return relay_members.contains(member); })) return false;
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
    if (!fallback_members.empty() && !m_source_validator(*source_key)) return false;
    LOCK(m_mutex);
    if (m_revision != observed_revision) return false;
    const PQQuorumOverlayPlan fallback{fallback_members.empty()
        ? PQQuorumOverlayPlan{} : PQQuorumOverlayPlan{{quorum_context_hash, fallback_members}}};
    const std::optional<FallbackContext> fallback_context{fallback_members.empty()
        ? std::nullopt : std::optional<FallbackContext>{FallbackContext{
            quorum_context_hash, local_pro_tx_hash, local_identity->key_version,
            local_identity->public_key, *prepared_target, accepted_predecessor, *source_key}}};
    if (m_chainlock_plan == plan && m_chainlock_fallback == fallback &&
        m_fallback_context == fallback_context) return true;
    if (m_payment_audit_plan &&
        plan.count(m_payment_audit_plan->group) != 0) {
        return false;
    }
    const bool fallback_changed{m_chainlock_fallback != fallback};
    m_chainlock_plan = plan;
    m_chainlock_fallback = fallback;
    m_fallback_context = fallback_context;
    ReconcileLocked(fallback_changed);
    // A later tip callback must compare its accepted context against the
    // prepared plan instead of skipping on an older accepted-context cache.
    m_context.reset();
    ++m_revision;
    return true;
}

void CPQQuorumConnectionOverlay::ClearChainLockFallback()
{
    LOCK(m_mutex);
    ClearChainLockFallbackLocked();
}

void CPQQuorumConnectionOverlay::ClearChainLockFallbackLocked()
{
    m_fallback_context.reset();
    if (m_chainlock_fallback.empty()) return;
    for (const auto& [group, members] : m_chainlock_fallback) {
        const auto plan{m_chainlock_plan.find(group)};
        if (plan != m_chainlock_plan.end()) {
            for (const auto& member : members) plan->second.erase(member);
        }
    }
    m_chainlock_fallback.clear();
    ReconcileLocked(/*force_install=*/true);
    ++m_revision;
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
    WAIT_LOCK(m_mutex, overlay_lock);
    ++m_revision;

    if (initial_download || new_tip == nullptr || !m_roster_cache ||
        !deterministicMNManager || !predecessor_height) {
        ClearLocked();
        return;
    }
    const auto& quorum_config{m_roster_cache->Config()};
    const auto& genesis_hash{m_roster_cache->GenesisHash()};
    const auto accepted_chainlock{
        chainLocksHandler ? chainLocksHandler->GetBestChainLock() : nullptr};
    const bool initialization_fallback{!accepted_chainlock && m_fallback_context &&
        m_fallback_context->target.mode == PQQuorumOverlayTargetMode::ROSTER_INITIALIZATION};

    const auto target_height{initialization_fallback
        ? pq::CurrentRosterInitializationTargetHeight(quorum_config.schedule,
              m_btcc_schedule, *predecessor_height, new_tip->nHeight)
        : GetPQQuorumOverlayTargetHeight(quorum_config.schedule,
              *predecessor_height, new_tip->nHeight)};
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

    const auto local_identity{GetLocalOperatorIdentity()};
    if (!local_identity) {
        ClearLocked();
        return;
    }

    pq::PQRegistryReadView current_registry;
    std::string registry_error;
    bool have_registry{false};
    try {
        have_registry = deterministicMNManager->GetPQRegistryReadView(
            new_tip, current_registry, registry_error);
    } catch (const std::runtime_error& e) {
        registry_error = e.what();
        LogPrintf("PQ overlay local authority read failed: %s\n",
                  registry_error);
    }
    if (!have_registry) {
        // Snapshot recovery may be transient during a reorg. Keep ordinary
        // topology while state catches up, but temporary routes require a
        // current identity and signing context.
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology at height=%d: %s\n",
                 new_tip->nHeight, registry_error);
        ClearChainLockFallbackLocked();
        return;
    }
    if (current_registry.Height() != new_tip->nHeight ||
        current_registry.BlockHash() != new_tip->GetBlockHash()) {
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology; active registry "
                 "snapshot mismatch at height=%d\n",
                 new_tip->nHeight);
        ClearChainLockFallbackLocked();
        return;
    }
    const auto local_operator{
        current_registry.FindActiveOperatorByGlobalKey(local_identity->public_key)};
    const auto* registered_operator{current_registry.FindOperator(local_identity->pro_tx_hash)};
    if (!local_operator || *local_operator != local_identity->pro_tx_hash ||
        !registered_operator ||
        registered_operator->global_key.key_version != local_identity->key_version) {
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
    const std::optional<PQQuorumOverlayPredecessor> accepted_predecessor{accepted_chainlock
        ? std::optional<PQQuorumOverlayPredecessor>{PQQuorumOverlayPredecessor{
            accepted_chainlock->statement.height, accepted_chainlock->statement.block_hash}}
        : std::nullopt};
    const PQQuorumOverlayTarget current_fallback_target{*target_height, target->GetBlockHash(),
        initialization_fallback ? PQQuorumOverlayTargetMode::ROSTER_INITIALIZATION
                                : PQQuorumOverlayTargetMode::ORDINARY};
    const bool exact_fallback_source{m_fallback_context &&
        m_fallback_context->target == current_fallback_target &&
        m_fallback_context->local_pro_tx_hash == *local_operator &&
        m_fallback_context->global_key_version == local_identity->key_version &&
        m_fallback_context->global_public_key == local_identity->public_key &&
        m_fallback_context->accepted_predecessor == accepted_predecessor};
    // The prepared source can legitimately use a rotated or recovered roster
    // before that roster has an accepted winner. Retain its exact group only
    // while the handler still authenticates the same published source.
    if (!m_chainlock_fallback.empty() && exact_fallback_source && m_source_validator) {
        const auto source_key{m_fallback_context->source_key};
        const auto observed_revision{m_revision};
        bool current_source{false};
        {
            REVERSE_LOCK(overlay_lock);
            current_source = m_source_validator(source_key);
        }
        // A clear or replacement while the handler was checked owns the
        // newer topology; this callback must not restore or retire it.
        if (m_revision != observed_revision) return;
        if (current_source) return;
    }
    if (!accepted_chainlock ||
        !accepted_chainlock->statement.roster_beacons.active
             .IsForNewestEpoch(newest_identity.epoch)) {
        LogPrint(BCLog::NET_NETCONN,
                 "PQ overlay retaining previous topology; no exact accepted "
                 "roster beacon bundle for target=%d\n",
                 *target_height);
        ClearChainLockFallbackLocked();
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
    const Context context{*local_operator, local_identity->key_version, local_identity->public_key,
                          *target_height, target->GetBlockHash(),
                          *accepted_predecessor, newest_identity.epoch,
                          newest_base->GetBlockHash(), *beacon_bundle_hash};
    if (m_context && *m_context == context && m_chainlock_fallback.empty()) return;

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
        ClearChainLockFallbackLocked();
        return;
    }

    auto plan{BuildPQQuorumOverlayPlan(
        genesis_hash, *target_height, target->GetBlockHash(), *rosters,
        *local_operator)};
    const bool fallback_changed{!m_chainlock_fallback.empty()};
    m_chainlock_fallback.clear();
    m_fallback_context.reset();
    if (m_payment_audit_plan &&
        plan.count(m_payment_audit_plan->group) != 0) {
        m_retired_payment_audit_generation = std::max(
            m_retired_payment_audit_generation,
            m_payment_audit_plan->runtime_generation);
        m_payment_audit_plan.reset();
    }
    m_chainlock_plan = plan;
    ReconcileLocked(fallback_changed);
    m_context = context;
    LogPrint(BCLog::NET_NETCONN,
             "PQ overlay updated at target=%d epoch=%u groups=%u\n",
             *target_height, newest_identity.epoch,
             static_cast<unsigned>(plan.size()));
}

} // namespace llmq
