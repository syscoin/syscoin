// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governance.h>

#include <common/bloom.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <flatdatabase.h>
#include <governance/governanceclasses.h>
#include <governance/governancecommon.h>
#include <governance/governancevalidators.h>
#include <llmq/pq_global_auth.h>
#include <masternode/masternodemeta.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <net_processing.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <pubkey.h>
#include <shutdown.h>
#include <spork.h>
#include <util/time.h>
#include <validation.h>
#include <timedata.h>

#include <algorithm>

std::unique_ptr<CGovernanceManager> governance;
int nSubmittedFinalBudget;

void AssertGovernanceLockNotHeld()
{
    if (governance) AssertLockNotHeld(governance->cs);
}

namespace {

constexpr int GOVERNANCE_AUTH_SIGNING_DEPTH{6};

const CBlockIndex* GetGovernanceSigningBlock(const CBlockIndex* tip)
{
    // Governance relay is independent of block relay. A shallow confirmation
    // floor prevents an otherwise synced peer from seeing the authorization
    // before it has the referenced registry snapshot.
    return tip != nullptr && tip->nHeight >= GOVERNANCE_AUTH_SIGNING_DEPTH
        ? tip->GetAncestor(tip->nHeight - GOVERNANCE_AUTH_SIGNING_DEPTH)
        : nullptr;
}

bool IsDelegatedProposalFundingVote(
    int object_type, vote_signal_enum_t signal)
{
    return object_type == GOVERNANCE_OBJECT_PROPOSAL &&
        signal == VOTE_SIGNAL_FUNDING;
}

class ScopedGovernanceResponse final
{
public:
    ScopedGovernanceResponse(
        PeerManager& peerman,
        std::optional<GovernanceRequestTracker::ResponseAuthorization>
            authorization) :
        m_peerman{peerman},
        m_authorization{std::move(authorization)}
    {
    }

    ~ScopedGovernanceResponse()
    {
        if (m_authorization) {
            (void)m_peerman.CompleteGovernanceResponse(
                *m_authorization, m_outcome);
        }
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return m_authorization.has_value();
    }

    [[nodiscard]] const GovernanceRequestTracker::ResponseAuthorization&
    Authorization() const
    {
        return *m_authorization;
    }

    void SetOutcome(GovernanceRequestTracker::ResponseOutcome outcome)
    {
        m_outcome = outcome;
    }

private:
    PeerManager& m_peerman;
    std::optional<GovernanceRequestTracker::ResponseAuthorization>
        m_authorization;
    GovernanceRequestTracker::ResponseOutcome m_outcome{
        GovernanceRequestTracker::ResponseOutcome::LOCAL_CONTEXT_CHANGED};
};

} // namespace

// SYSCOIN: reconnect-resistant and Sybil-independent admission for expensive
// trigger-vote sync verification.
bool GovernanceVoteSyncRateLimiter::Consume(
    int64_t peer, const uint256& authenticated_pro_tx,
    uint64_t keyed_net_group, std::chrono::microseconds now)
{
    SourceIdentity source;
    if (!authenticated_pro_tx.IsNull()) {
        source.authenticated_pro_tx = authenticated_pro_tx;
    } else if (keyed_net_group != 0) {
        source.keyed_net_group = keyed_net_group;
    } else if (peer >= 0) {
        source.fallback_peer = peer;
    } else {
        return false;
    }

    if (now < m_next_global_request) return false;

    auto bucket{m_buckets.find(source)};
    if (bucket == m_buckets.end()) {
        if (m_buckets.size() >= MAX_SOURCES) {
            for (auto it{m_buckets.begin()}; it != m_buckets.end();) {
                if (now >= it->second.last_seen &&
                    now - it->second.last_seen >= SOURCE_EXPIRY) {
                    it = m_buckets.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (m_buckets.size() >= MAX_SOURCES) {
            const auto oldest{std::min_element(
                m_buckets.begin(), m_buckets.end(),
                [](const auto& lhs, const auto& rhs) {
                    return lhs.second.last_seen < rhs.second.last_seen;
                })};
            if (oldest != m_buckets.end()) m_buckets.erase(oldest);
        }
        bucket = m_buckets.emplace(
            source, Bucket{SOURCE_BURST, now, now}).first;
    }

    Bucket& state{bucket->second};
    if (now < state.last_refill) state.last_refill = now;
    if (now > state.last_refill) {
        const auto refills{(now - state.last_refill) /
                           SOURCE_REFILL_INTERVAL};
        if (refills > 0) {
            state.tokens = static_cast<uint8_t>(std::min<uint64_t>(
                SOURCE_BURST,
                static_cast<uint64_t>(state.tokens) +
                    static_cast<uint64_t>(refills)));
            state.last_refill += SOURCE_REFILL_INTERVAL * refills;
        }
    }
    state.last_seen = std::max(state.last_seen, now);
    if (state.tokens == 0) return false;

    --state.tokens;
    m_next_global_request = now + GLOBAL_MIN_INTERVAL;
    return true;
}
// SYSCOIN: end bounded governance vote sync admission.

GovernancePageServeRateLimiter::RequestResult
GovernancePageServeRateLimiter::Consume(
    int64_t peer, const uint256& authenticated_pro_tx,
    uint64_t keyed_net_group, std::chrono::microseconds now)
{
    std::array<SourceKey, 2> keys;
    std::size_t key_count{0};
    if (!authenticated_pro_tx.IsNull()) {
        keys[key_count++] = SourceKey{
            true, authenticated_pro_tx, 0, -1};
    }
    if (keyed_net_group != 0) {
        keys[key_count++] = SourceKey{
            false, {}, keyed_net_group, -1};
    }
    if (key_count == 0 && peer >= 0) {
        keys[key_count++] = SourceKey{false, {}, 0, peer};
    }
    if (key_count == 0) return RequestResult::SOURCE_LIMITED;

    for (auto it{m_buckets.begin()}; it != m_buckets.end();) {
        if (now >= it->second.last_seen &&
            now - it->second.last_seen >= SOURCE_EXPIRY) {
            it = m_buckets.erase(it);
        } else {
            ++it;
        }
    }
    const auto is_current_key = [&](const SourceKey& candidate) {
        for (std::size_t i{0}; i < key_count; ++i) {
            if (!(candidate < keys[i]) && !(keys[i] < candidate)) {
                return true;
            }
        }
        return false;
    };
    std::size_t missing_keys{0};
    for (std::size_t i{0}; i < key_count; ++i) {
        if (!m_buckets.contains(keys[i])) ++missing_keys;
    }
    while (m_buckets.size() + missing_keys > MAX_SOURCE_RECORDS) {
        auto oldest{m_buckets.end()};
        for (auto it{m_buckets.begin()}; it != m_buckets.end(); ++it) {
            if (is_current_key(it->first)) continue;
            if (oldest == m_buckets.end() ||
                it->second.last_seen < oldest->second.last_seen) {
                oldest = it;
            }
        }
        if (oldest == m_buckets.end()) {
            return RequestResult::SOURCE_LIMITED;
        }
        m_buckets.erase(oldest);
    }

    std::array<Bucket*, 2> buckets{};
    for (std::size_t i{0}; i < key_count; ++i) {
        auto [it, inserted]{m_buckets.try_emplace(
            keys[i], Bucket{SOURCE_BURST, now, now,
                            SOURCE_BYTE_CAPACITY, now})};
        Bucket& bucket{it->second};
        if (!inserted) {
            if (now < bucket.last_refill) bucket.last_refill = now;
            if (now > bucket.last_refill) {
                const auto refills{
                    (now - bucket.last_refill) /
                    SOURCE_REFILL_INTERVAL};
                if (refills > 0) {
                    bucket.tokens = static_cast<uint8_t>(
                        std::min<uint64_t>(
                            SOURCE_BURST,
                            static_cast<uint64_t>(bucket.tokens) +
                                static_cast<uint64_t>(refills)));
                    bucket.last_refill +=
                        SOURCE_REFILL_INTERVAL * refills;
                }
            }
            bucket.last_seen = std::max(bucket.last_seen, now);
        }
        buckets[i] = &bucket;
    }
    if (now < m_next_global_request) {
        if (buckets[0]->tokens == 0) {
            return RequestResult::SOURCE_LIMITED;
        }
        --buckets[0]->tokens;
        return RequestResult::GLOBAL_BUSY;
    }
    for (std::size_t i{0}; i < key_count; ++i) {
        if (buckets[i]->tokens == 0) {
            return RequestResult::SOURCE_LIMITED;
        }
    }
    for (std::size_t i{0}; i < key_count; ++i) --buckets[i]->tokens;
    m_next_global_request = now + GLOBAL_MIN_INTERVAL;
    return RequestResult::ACCEPTED;
}

bool GovernancePageServeRateLimiter::ConsumePayloadBytes(
    int64_t peer, const uint256& authenticated_pro_tx,
    uint64_t keyed_net_group, std::size_t bytes,
    std::chrono::microseconds now)
{
    if (bytes == 0 || bytes > SOURCE_BYTE_CAPACITY ||
        bytes > GLOBAL_BYTE_CAPACITY) {
        return false;
    }

    std::array<SourceKey, 2> keys;
    std::size_t key_count{0};
    if (!authenticated_pro_tx.IsNull()) {
        keys[key_count++] = SourceKey{
            true, authenticated_pro_tx, 0, -1};
    }
    if (keyed_net_group != 0) {
        keys[key_count++] = SourceKey{
            false, {}, keyed_net_group, -1};
    }
    if (key_count == 0 && peer >= 0) {
        keys[key_count++] = SourceKey{false, {}, 0, peer};
    }
    if (key_count == 0) return false;

    const auto refill = [&](std::size_t capacity,
                            std::size_t per_second,
                            std::size_t& tokens,
                            std::chrono::microseconds& last_refill) {
        if (last_refill == std::chrono::microseconds{0} ||
            now < last_refill) {
            last_refill = now;
        }
        const auto elapsed_seconds{
            (now - last_refill) / std::chrono::seconds{1}};
        if (elapsed_seconds <= 0) return;
        const uint64_t bounded_seconds{std::min<uint64_t>(
            static_cast<uint64_t>(elapsed_seconds),
            capacity / per_second)};
        const std::size_t added{static_cast<std::size_t>(
            bounded_seconds * per_second)};
        tokens = std::min(capacity, tokens + added);
        last_refill += std::chrono::seconds{elapsed_seconds};
    };

    for (auto it{m_buckets.begin()}; it != m_buckets.end();) {
        if (now >= it->second.last_seen &&
            now - it->second.last_seen >= SOURCE_EXPIRY) {
            it = m_buckets.erase(it);
        } else {
            ++it;
        }
    }
    const auto is_current_key = [&](const SourceKey& candidate) {
        for (std::size_t i{0}; i < key_count; ++i) {
            if (!(candidate < keys[i]) && !(keys[i] < candidate)) {
                return true;
            }
        }
        return false;
    };
    std::size_t missing_keys{0};
    for (std::size_t i{0}; i < key_count; ++i) {
        if (!m_buckets.contains(keys[i])) ++missing_keys;
    }
    while (m_buckets.size() + missing_keys > MAX_SOURCE_RECORDS) {
        auto oldest{m_buckets.end()};
        for (auto it{m_buckets.begin()}; it != m_buckets.end(); ++it) {
            if (is_current_key(it->first)) continue;
            if (oldest == m_buckets.end() ||
                it->second.last_seen < oldest->second.last_seen) {
                oldest = it;
            }
        }
        if (oldest == m_buckets.end()) return false;
        m_buckets.erase(oldest);
    }

    std::array<Bucket*, 2> buckets{};
    for (std::size_t i{0}; i < key_count; ++i) {
        const auto it{m_buckets.try_emplace(
            keys[i], Bucket{SOURCE_BURST, now, now,
                            SOURCE_BYTE_CAPACITY, now}).first};
        refill(SOURCE_BYTE_CAPACITY,
               SOURCE_BYTE_REFILL_PER_SECOND,
               it->second.byte_tokens,
               it->second.byte_last_refill);
        it->second.last_seen = std::max(it->second.last_seen, now);
        buckets[i] = &it->second;
    }
    refill(GLOBAL_BYTE_CAPACITY,
           GLOBAL_BYTE_REFILL_PER_SECOND,
           m_global_byte_tokens,
           m_global_byte_last_refill);
    if (m_global_byte_tokens < bytes) return false;
    for (std::size_t i{0}; i < key_count; ++i) {
        if (buckets[i]->byte_tokens < bytes) return false;
    }
    m_global_byte_tokens -= bytes;
    for (std::size_t i{0}; i < key_count; ++i) {
        buckets[i]->byte_tokens -= bytes;
    }
    return true;
}

bool GovernancePageBuildRateLimiter::Begin(
    std::chrono::microseconds now)
{
    // BuildGovernancePage is serialized by the governance lock. If a prior
    // serializer threw before Charge(), retain its full-cap charge but clear
    // the stale marker so the bucket can recover normally instead of wedging
    // every future cache miss until process restart.
    if (m_build_active) m_build_active = false;
    if (now < m_next_build) return false;
    if (m_last_refill == std::chrono::microseconds{0} ||
        now < m_last_refill) {
        m_last_refill = now;
    }
    const auto elapsed_seconds{
        (now - m_last_refill) / std::chrono::seconds{1}};
    if (elapsed_seconds > 0) {
        const uint64_t bounded_seconds{std::min<uint64_t>(
            static_cast<uint64_t>(elapsed_seconds),
            TOKEN_CAPACITY / REFILL_BYTES_PER_SECOND)};
        const uint64_t refill{
            bounded_seconds * REFILL_BYTES_PER_SECOND};
        m_tokens = static_cast<std::size_t>(std::min<uint64_t>(
            TOKEN_CAPACITY,
            static_cast<uint64_t>(m_tokens) + refill));
        m_last_refill += std::chrono::seconds{elapsed_seconds};
    }
    // Reserve the maximum legal build before even sizing the scope. This
    // makes a rejected/oversized preflight consume real work budget too.
    if (TOKEN_CAPACITY > m_tokens) return false;
    m_tokens -= TOKEN_CAPACITY;
    m_build_active = true;
    m_next_build = now + std::chrono::duration_cast<
        std::chrono::microseconds>(MIN_BUILD_INTERVAL);
    return true;
}

bool GovernancePageBuildRateLimiter::Charge(
    std::size_t retained_bytes)
{
    if (!m_build_active) return false;
    m_build_active = false;
    if (retained_bytes == 0 || retained_bytes > TOKEN_CAPACITY) {
        return false;
    }
    const std::size_t charge{
        std::max(MINIMUM_BUILD_CHARGE, retained_bytes)};
    m_tokens += TOKEN_CAPACITY - charge;
    return true;
}

const std::string GovernanceStore::SERIALIZATION_VERSION_STRING = "CGovernanceManager-Version-17";
const int CGovernanceManager::MAX_TIME_FUTURE_DEVIATION = 60 * 60;
const int CGovernanceManager::RELIABLE_PROPAGATION_TIME = 60;

std::string_view GovernanceObjectAdmissionError(
    GovernanceObjectAdmissionResult result)
{
    switch (result) {
    case GovernanceObjectAdmissionResult::ACCEPTED:
        return {};
    case GovernanceObjectAdmissionResult::UNAVAILABLE:
        return "governance authority state is unavailable";
    case GovernanceObjectAdmissionResult::LOCAL_INELIGIBLE:
        return "governance object is not eligible at the active tip";
    case GovernanceObjectAdmissionResult::STALE_TIP:
        return "active chain tip changed during admission";
    case GovernanceObjectAdmissionResult::DUPLICATE:
        return "governance object is already known";
    case GovernanceObjectAdmissionResult::RESOURCE_LIMIT:
        return "governance object admission resource limit";
    case GovernanceObjectAdmissionResult::INVALID:
        return "governance object failed admission";
    }
    return "unknown governance admission result";
}

CGovernanceManager::PQGovernanceTipIdentity::PQGovernanceTipIdentity(
    const CBlockIndex& tip) :
    height{tip.nHeight}, hash{tip.GetBlockHash()}
{
}

GovernanceStore::GovernanceStore() :
    cs(),
    mapObjects(),
    m_page_snapshot_budget(
        std::make_shared<GovernancePageSnapshotBudget>()),
    mapErasedGovernanceObjects(),
    cmapVoteToObject(MAX_CACHE_SIZE),
    cmapInvalidVotes(MAX_CACHE_SIZE),
    cmmapOrphanVotes(MAX_ORPHAN_VOTES),
    mapLastMasternodeObject(),
    lastMNListForVotingKeys(std::make_shared<CDeterministicMNList>())
{
}

void GovernanceStore::InvalidateObjectPageCache() const
{
    AssertLockHeld(cs);
    m_object_page_dirty = true;
    m_object_page_snapshot.reset();
    m_object_page_next_trigger_height = std::numeric_limits<int>::max();
}

std::optional<uint64_t>
GovernanceStore::NextGovernancePageSnapshotInstance() const
{
    AssertLockHeld(cs);
    if (m_next_page_snapshot_instance == 0 ||
        m_next_page_snapshot_instance ==
            std::numeric_limits<uint64_t>::max()) {
        return std::nullopt;
    }
    return m_next_page_snapshot_instance++;
}

CGovernanceManager::CGovernanceManager(ChainstateManager& _chainman) :
    chainman(_chainman),
    m_db{std::make_unique<db_type>(
        "governance.dat", "magicGovernanceCache",
        MAX_GOVERNANCE_CACHE_FILE_BYTES)},
    m_pq_governance_readiness{
        std::make_shared<const PQGovernanceReadinessState>()},
    nTimeLastDiff(0),
    nCachedBlockHeight(0),
    fRateChecksEnabled(true),
    votedFundingYesTriggerHash(std::nullopt),
    mapTrigger{},
    m_pq_inactive_triggers{},
    m_pq_authorities{},
    m_delegated_funding_authorities{},
    m_pq_vote_objects{},
    m_delegated_funding_vote_objects{},
    m_pq_authority_tip_hash{},
    m_sb(std::make_unique<CEvoDB<uint256, CAmount, StaticSaltedHasher>>(DBParams{.path = chainman.m_options.datadir / "evodb_sb", .cache_bytes = static_cast<size_t>(1 << 20), .wipe_data = chainman.m_options.reindex}, 0))
{
}

bool CGovernanceManager::IsReady() const
{
    if (!IsValid()) return false;
    const auto state{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    return state && state->observed_tip && state->ready_tip &&
        *state->observed_tip == *state->ready_tip;
}

bool CGovernanceManager::IsReadyForTip(const CBlockIndex* tip) const
{
    if (tip == nullptr || !IsValid()) return false;
    const PQGovernanceTipIdentity expected{*tip};
    const auto state{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    return state && state->observed_tip == expected &&
        state->ready_tip == expected;
}

std::optional<uint64_t>
CGovernanceManager::GetPQGovernanceValidationContextEpoch() const
{
    if (!IsValid()) return std::nullopt;
    const auto state{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    if (!state || !state->observed_tip ||
        state->ready_tip != state->observed_tip ||
        state->validation_context_epoch == 0) {
        return std::nullopt;
    }
    return state->validation_context_epoch;
}

void CGovernanceManager::ObserveChainTip(const CBlockIndex* tip)
{
    const std::optional<PQGovernanceTipIdentity> observed{
        tip == nullptr
            ? std::nullopt
            : std::make_optional(PQGovernanceTipIdentity{*tip})};
    auto current{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    while (true) {
        auto next{std::make_shared<PQGovernanceReadinessState>(
            current ? *current : PQGovernanceReadinessState{})};
        if (next->observed_tip == observed) return;
        if (!observed && next->observed_tip) {
            if (next->validation_context_epoch ==
                std::numeric_limits<uint64_t>::max()) {
                next->validation_context_epoch = 0;
            } else if (next->validation_context_epoch != 0) {
                ++next->validation_context_epoch;
            }
        }
        next->observed_tip = observed;
        // Readiness is a property of one observed chain transition, not a
        // reusable cache entry keyed only by hash. Clearing it on every tip
        // change prevents A-B-A observation from resurrecting an old ready
        // state while B's recovery pass is still in flight.
        next->ready_tip.reset();
        std::shared_ptr<const PQGovernanceReadinessState> desired{
            std::move(next)};
        if (m_pq_governance_readiness.compare_exchange_weak(
                current, desired,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            return;
        }
    }
}

bool CGovernanceManager::AdvancePQGovernanceValidationContext()
{
    auto current{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    while (current) {
        auto next{std::make_shared<PQGovernanceReadinessState>(*current)};
        if (next->validation_context_epoch == 0 ||
            next->validation_context_epoch ==
                std::numeric_limits<uint64_t>::max()) {
            next->validation_context_epoch = 0;
        } else {
            ++next->validation_context_epoch;
        }
        next->ready_tip.reset();
        const bool valid_epoch{
            next->validation_context_epoch != 0};
        std::shared_ptr<const PQGovernanceReadinessState> desired{
            std::move(next)};
        if (m_pq_governance_readiness.compare_exchange_weak(
                current, desired,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            return valid_epoch;
        }
    }
    return false;
}

void CGovernanceManager::MarkPQGovernanceUnavailableForTip(
    const CBlockIndex& validation_tip)
{
    const PQGovernanceTipIdentity expected_tip{validation_tip};
    auto current{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    while (current && current->observed_tip == expected_tip) {
        if (!current->ready_tip) return;
        auto next{std::make_shared<PQGovernanceReadinessState>(*current)};
        next->ready_tip.reset();
        std::shared_ptr<const PQGovernanceReadinessState> desired{
            std::move(next)};
        if (m_pq_governance_readiness.compare_exchange_weak(
                current, desired,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            return;
        }
    }
}

bool CGovernanceManager::PublishPQGovernanceReadyForTip(
    const CBlockIndex& validation_tip,
    bool advance_validation_context)
{
    const PQGovernanceTipIdentity expected_tip{validation_tip};
    auto current{
        m_pq_governance_readiness.load(std::memory_order_acquire)};
    while (current && current->observed_tip == expected_tip) {
        if (current->validation_context_epoch == 0) return false;
        if (current->ready_tip == expected_tip &&
            !advance_validation_context) {
            return true;
        }
        auto next{std::make_shared<PQGovernanceReadinessState>(*current)};
        if (advance_validation_context) {
            if (next->validation_context_epoch ==
                std::numeric_limits<uint64_t>::max()) {
                next->validation_context_epoch = 0;
                next->ready_tip.reset();
                std::shared_ptr<const PQGovernanceReadinessState> desired{
                    std::move(next)};
                if (m_pq_governance_readiness.compare_exchange_weak(
                        current, desired,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    return false;
                }
                continue;
            }
            ++next->validation_context_epoch;
        }
        next->ready_tip = expected_tip;
        std::shared_ptr<const PQGovernanceReadinessState> desired{
            std::move(next)};
        if (m_pq_governance_readiness.compare_exchange_weak(
                current, desired,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            return true;
        }
    }
    return false;
}

CGovernanceManager::~CGovernanceManager()
{
    if (!IsValid()) return;
    m_db->Store(*this);
}

bool CGovernanceManager::LoadCache(bool load_cache)
{
    assert(m_db != nullptr);
    ObserveChainTip(nullptr);
    is_valid.store(load_cache ? m_db->Load(*this) : m_db->Store(*this),
                   std::memory_order_release);
    if (IsValid() && !InitOnLoad()) {
        LogPrintf("Governance cache loaded but exact-tip PQ authority "
                  "revalidation is unavailable; governance remains "
                  "fail-closed until a later tip update succeeds\n");
    }
    return is_valid;
}

// Accessors for thread-safe access to maps
bool CGovernanceManager::HaveObjectForHash(const uint256& nHash) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return false;
    if (m_pq_inactive_triggers.contains(nHash)) return false;
    return (mapObjects.count(nHash) == 1 ||
            mapPostponedObjects.count(nHash) == 1);
}

bool CGovernanceManager::SerializeObjectForHash(const uint256& nHash, CDataStream& ss) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return false;
    if (m_pq_inactive_triggers.contains(nHash)) return false;
    auto it = mapObjects.find(nHash);
    if (it == mapObjects.end()) {
        it = mapPostponedObjects.find(nHash);
        if (it == mapPostponedObjects.end())
            return false;
    }
    ss << it->second;
    return true;
}

std::optional<std::size_t>
CGovernanceManager::GetObjectSerializedSizeForHash(
    const uint256& nHash, int version) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return std::nullopt;
    if (m_pq_inactive_triggers.contains(nHash)) return std::nullopt;
    auto it{mapObjects.find(nHash)};
    if (it == mapObjects.end()) {
        it = mapPostponedObjects.find(nHash);
        if (it == mapPostponedObjects.end()) return std::nullopt;
    }
    // Every variable-length network field participates in the logical hash;
    // the omitted outer type and collateral fields have fixed wire widths.
    // A same-hash replacement therefore cannot exceed this precharge.
    return ::GetSerializeSize(it->second, version, SER_NETWORK);
}

bool CGovernanceManager::HaveVoteForHash(const uint256& nHash) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return false;

    CGovernanceObject* pGovobj = nullptr;
    return cmapVoteToObject.Get(nHash, pGovobj) &&
        !m_pq_inactive_triggers.contains(pGovobj->GetHash()) &&
        pGovobj->GetVoteFile().HasVote(nHash);
}

int CGovernanceManager::GetVoteCount() const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return 0;
    return (int)cmapVoteToObject.GetSize();
}

bool CGovernanceManager::SerializeVoteForHash(const uint256& nHash, CDataStream& ss) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return false;

    CGovernanceObject* pGovobj = nullptr;
    return cmapVoteToObject.Get(nHash, pGovobj) &&
        !m_pq_inactive_triggers.contains(pGovobj->GetHash()) &&
        pGovobj->GetVoteFile().SerializeVoteToStream(nHash, ss);
}

std::optional<std::size_t>
CGovernanceManager::GetVoteSerializedSizeUpperBoundForHash(
    const uint256& nHash, int version) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return std::nullopt;

    CGovernanceObject* pGovobj{nullptr};
    if (!cmapVoteToObject.Get(nHash, pGovobj) ||
        m_pq_inactive_triggers.contains(pGovobj->GetHash())) {
        return std::nullopt;
    }
    return pGovobj->GetVoteFile().GetVoteSerializedSizeUpperBound(
        nHash, version);
}

bool CGovernanceManager::ConsumeGovernancePayloadBytes(
    int64_t peer, const uint256& authenticated_pro_tx,
    uint64_t keyed_net_group, std::size_t bytes,
    std::chrono::microseconds now)
{
    LOCK(m_page_serve_rate_mutex);
    return m_page_serve_rate.ConsumePayloadBytes(
        peer, authenticated_pro_tx, keyed_net_group, bytes, now);
}

bool CGovernanceManager::IsGovernancePageObjectEligible(
    const uint256& hash, const CGovernanceObject& object,
    int active_height) const
{
    AssertLockHeld(cs);
    if (object.IsSetCachedDelete() || object.IsSetExpired() ||
        m_pq_inactive_triggers.contains(hash)) {
        return false;
    }
    if (object.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
        return true;
    }
    const auto trigger{mapTrigger.find(hash)};
    return trigger != mapTrigger.end() && trigger->second &&
           trigger->second->GetBlockHeight() > active_height;
}

std::optional<GovernancePageBuildResult>
CGovernanceManager::BuildGovernancePage(
    const CGovernancePageRequest& request,
    std::shared_ptr<const GovernancePageImmutableSnapshot> continuation,
    std::optional<std::chrono::microseconds> build_request_time) const
{
    if (request.nonce == 0 ||
        request.cursor.IsNull() != request.view_id.IsNull()) {
        return std::nullopt;
    }

    GovernancePageBuildResult result;
    auto& response{result.response};
    response.scope_hash = request.scope_hash;
    response.cursor = request.cursor;
    response.request_view_id = request.view_id;
    response.nonce = request.nonce;
    response.next_cursor = request.cursor;
    const auto status_result = [&](uint8_t status)
        -> std::optional<GovernancePageBuildResult> {
        response.status = status;
        response.view_id.SetNull();
        response.total_count = 0;
        response.next_cursor = request.cursor;
        response.done = false;
        response.inventory.clear();
        result.snapshot.reset();
        result.entry_indices.clear();
        return result;
    };

    LOCK2(chainman.GetMutex(), cs);
    const CBlockIndex* tip{chainman.ActiveTip()};
    if (!IsReadyForTip(tip)) {
        return status_result(
            GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
    }
    const auto validation_context_epoch{
        GetPQGovernanceValidationContextEpoch()};
    if (!validation_context_epoch) {
        return status_result(
            GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
    }
    const int active_height{tip->nHeight};
    const auto begin_build = [&]() {
        if (!build_request_time) return true;
        LOCK(m_page_build_rate_mutex);
        return m_page_build_rate.Begin(*build_request_time);
    };
    const auto charge_build = [&](std::size_t retained_bytes) {
        if (!build_request_time) return true;
        LOCK(m_page_build_rate_mutex);
        return m_page_build_rate.Charge(retained_bytes);
    };

    if (continuation) {
        if (continuation->ScopeHash() != request.scope_hash ||
            (!request.cursor.IsNull() &&
             continuation->ViewId() != request.view_id)) {
            return std::nullopt;
        }
        if (continuation->ValidationContextEpoch() !=
            *validation_context_epoch) {
            return status_result(GOVERNANCE_PAGE_RESTART_REQUIRED);
        }
    }
    if (!continuation && !request.cursor.IsNull()) {
        return status_result(GOVERNANCE_PAGE_RESTART_REQUIRED);
    }

    std::shared_ptr<const GovernancePageImmutableSnapshot> snapshot{
        std::move(continuation)};
    if (!snapshot && request.scope_hash.IsNull()) {
        snapshot = m_object_page_snapshot.lock();
        if (m_object_page_dirty || !snapshot ||
            snapshot->ValidationContextEpoch() !=
                *validation_context_epoch ||
            active_height >= m_object_page_next_trigger_height) {
            snapshot.reset();
            if (!begin_build()) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            if (mapObjects.size() >
                MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
                (void)charge_build(
                    MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES);
                return status_result(
                    GOVERNANCE_PAGE_SCOPE_TOO_LARGE);
            }
            std::size_t eligible_count{0};
            int next_trigger_height{std::numeric_limits<int>::max()};
            for (const auto& [hash, object] : mapObjects) {
                if (!IsGovernancePageObjectEligible(
                        hash, object, active_height)) {
                    continue;
                }
                ++eligible_count;
                if (object.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
                    const auto trigger{mapTrigger.find(hash)};
                    Assume(trigger != mapTrigger.end() && trigger->second);
                    next_trigger_height = std::min(
                        next_trigger_height,
                        trigger->second->GetBlockHeight());
                }
            }
            std::optional<uint8_t> preflight_status;
            std::size_t retained_bytes{
                MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES};
            if (eligible_count > MAX_GOVERNANCE_PAGE_SCOPE_ITEMS ||
                eligible_count >
                    (std::numeric_limits<std::size_t>::max() -
                     sizeof(GovernancePageImmutableSnapshot)) /
                        sizeof(GovernancePageSnapshotEntry)) {
                preflight_status = GOVERNANCE_PAGE_SCOPE_TOO_LARGE;
            } else {
                retained_bytes =
                    sizeof(GovernancePageImmutableSnapshot) +
                    eligible_count *
                        sizeof(GovernancePageSnapshotEntry);
                if (retained_bytes >
                    MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES) {
                    preflight_status =
                        GOVERNANCE_PAGE_SCOPE_TOO_LARGE;
                }
            }
            if (!preflight_status) {
                for (const auto& [hash, object] : mapObjects) {
                    if (!IsGovernancePageObjectEligible(
                            hash, object, active_height)) {
                        continue;
                    }
                    const std::size_t payload_size{
                        ::GetSerializeSize(
                            object, GOVERNANCE_PAGE_PROTO_VERSION,
                            SER_NETWORK)};
                    if (payload_size == 0) {
                        preflight_status =
                            GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE;
                        break;
                    }
                    if (payload_size >
                            MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES ||
                        payload_size >
                            MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES -
                                retained_bytes) {
                        preflight_status =
                            GOVERNANCE_PAGE_SCOPE_TOO_LARGE;
                        break;
                    }
                    retained_bytes += payload_size;
                }
            }
            const bool build_charged{charge_build(
                preflight_status
                    ? MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES
                    : retained_bytes)};
            if (preflight_status) {
                return status_result(*preflight_status);
            }
            if (!build_charged) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            GovernancePageSnapshotReservation reservation{
                m_page_snapshot_budget};
            if (!reservation.Reserve(retained_bytes)) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            CGovernancePageViewHasher hasher{
                uint256{}, static_cast<uint32_t>(eligible_count)};
            std::vector<GovernancePageSnapshotEntry> entries;
            entries.reserve(eligible_count);
            if (entries.capacity() > eligible_count &&
                !reservation.Reserve(
                    (entries.capacity() - eligible_count) *
                    sizeof(GovernancePageSnapshotEntry))) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            for (const auto& [hash, object] : mapObjects) {
                if (!IsGovernancePageObjectEligible(
                        hash, object, active_height)) {
                    continue;
                }
                const CInv inv{MSG_GOVERNANCE_OBJECT, hash};
                if (!hasher.Append(inv)) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                const std::size_t payload_size{
                    ::GetSerializeSize(
                        object, GOVERNANCE_PAGE_PROTO_VERSION,
                        SER_NETWORK)};
                if (payload_size == 0) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                if (payload_size > MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES) {
                    return status_result(
                        GOVERNANCE_PAGE_SCOPE_TOO_LARGE);
                }
                std::vector<unsigned char> payload;
                payload.reserve(payload_size);
                CVectorWriter{
                    SER_NETWORK, GOVERNANCE_PAGE_PROTO_VERSION,
                    payload, 0, object};
                if (payload.size() != payload_size) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                if (payload.capacity() > payload_size &&
                    !reservation.Reserve(
                        payload.capacity() - payload_size)) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                entries.push_back(GovernancePageSnapshotEntry{
                    inv, std::move(payload)});
            }
            const auto view{hasher.Finalize()};
            if (!view) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            const auto instance_id{
                NextGovernancePageSnapshotInstance()};
            if (!instance_id) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            const auto built{
                GovernancePageImmutableSnapshot::Create(
                    std::move(reservation), *instance_id,
                    *validation_context_epoch, uint256{}, *view,
                    std::move(entries))};
            if (!built) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            m_object_page_snapshot = built;
            snapshot = built;
            m_object_page_next_trigger_height = next_trigger_height;
            m_object_page_dirty = false;
        }
    } else if (!snapshot) {
        const auto object{mapObjects.find(request.scope_hash)};
        if (object == mapObjects.end() ||
            !IsGovernancePageObjectEligible(
                object->first, object->second, active_height)) {
            const std::vector<CInv> empty;
            const auto view{ComputeGovernancePageViewHash(
                request.scope_hash, empty)};
            if (!view) {
                return status_result(
                    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
            }
            response.status = GOVERNANCE_PAGE_OK;
            response.view_id = *view;
            response.total_count = 0;
            response.done = true;
            response.next_cursor.SetNull();
            return result;
        } else {
            if (object->second.GetVoteFile().GetVoteCount() < 0 ||
                static_cast<uint64_t>(
                    object->second.GetVoteFile().GetVoteCount()) >
                    MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
                return status_result(
                    GOVERNANCE_PAGE_SCOPE_TOO_LARGE);
            }
            snapshot = object->second.GetCachedVotePageSnapshot(
                *validation_context_epoch);
            if (!snapshot) {
                if (!begin_build()) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                const auto retained_bytes{
                    object->second.GetVotePageSnapshotRetainedBytes()};
                const bool build_charged{charge_build(
                    retained_bytes
                        ? *retained_bytes
                        : MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES)};
                if (!retained_bytes) {
                    return status_result(
                        GOVERNANCE_PAGE_SCOPE_TOO_LARGE);
                }
                if (!build_charged) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                const auto instance_id{
                    NextGovernancePageSnapshotInstance()};
                if (!instance_id) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
                snapshot = object->second.GetVotePageSnapshot(
                    m_page_snapshot_budget, *instance_id,
                    *validation_context_epoch, retained_bytes);
                if (!snapshot) {
                    return status_result(
                        GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE);
                }
            }
        }
    }

    if (!snapshot || snapshot->ScopeHash() != request.scope_hash) {
        return std::nullopt;
    }
    if (snapshot->ValidationContextEpoch() !=
        *validation_context_epoch) {
        return status_result(GOVERNANCE_PAGE_RESTART_REQUIRED);
    }
    const auto& entries{snapshot->Entries()};
    auto it{entries.begin()};
    if (!request.cursor.IsNull()) {
        it = std::lower_bound(
            entries.begin(), entries.end(), request.cursor,
            [](const GovernancePageSnapshotEntry& entry,
               const uint256& cursor) {
                return entry.inv.hash < cursor;
            });
        if (it == entries.end() || it->inv.hash != request.cursor) {
            return status_result(GOVERNANCE_PAGE_RESTART_REQUIRED);
        }
        ++it;
    }
    if (!request.cursor.IsNull() && it == entries.end()) {
        return status_result(GOVERNANCE_PAGE_RESTART_REQUIRED);
    }

    response.status = GOVERNANCE_PAGE_OK;
    response.view_id = snapshot->ViewId();
    response.total_count = snapshot->TotalCount();
    response.inventory.reserve(MAX_GOVERNANCE_PAGE_INVENTORY);
    result.entry_indices.reserve(MAX_GOVERNANCE_PAGE_INVENTORY);
    while (it != entries.end() &&
           response.inventory.size() <
               MAX_GOVERNANCE_PAGE_INVENTORY) {
        response.inventory.push_back(it->inv);
        result.entry_indices.push_back(
            static_cast<std::size_t>(it - entries.begin()));
        ++it;
    }
    response.done = it == entries.end();
    response.next_cursor = response.inventory.empty()
        ? request.cursor
        : response.inventory.back().hash;
    result.snapshot = std::move(snapshot);
    return result;
}

bool CGovernanceManager::SerializeObjectForPage(
    const uint256& hash, CDataStream& ss) const
{
    LOCK(cs);
    const auto it{mapObjects.find(hash)};
    if (it == mapObjects.end()) return false;
    ss << it->second;
    return true;
}

bool CGovernanceManager::SerializeVoteForPage(
    const uint256& parent_hash, const uint256& vote_hash,
    CDataStream& ss) const
{
    LOCK(cs);
    const auto it{mapObjects.find(parent_hash)};
    return it != mapObjects.end() &&
           it->second.SerializeVoteForPage(vote_hash, ss);
}

bool CGovernanceManager::HaveObjectForPage(const uint256& hash) const
{
    LOCK(cs);
    return mapObjects.contains(hash);
}

bool CGovernanceManager::HaveVoteForPage(
    const uint256& parent_hash, const uint256& vote_hash) const
{
    LOCK(cs);
    const auto it{mapObjects.find(parent_hash)};
    return it != mapObjects.end() &&
           it->second.HasVoteForPage(vote_hash);
}

GovernancePageObjectHashesResult
CGovernanceManager::GetGovernancePageObjectHashes() const
{
    GovernancePageObjectHashesResult result;
    LOCK2(chainman.GetMutex(), cs);
    const CBlockIndex* tip{chainman.ActiveTip()};
    if (!IsReadyForTip(tip)) return result;
    if (mapObjects.size() > MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
        result.status = GOVERNANCE_PAGE_SCOPE_TOO_LARGE;
        return result;
    }

    result.hashes.reserve(mapObjects.size());
    for (const auto& [hash, object] : mapObjects) {
        if (IsGovernancePageObjectEligible(hash, object, tip->nHeight)) {
            result.hashes.push_back(hash);
        }
    }
    result.status = GOVERNANCE_PAGE_OK;
    return result;
}

void CGovernanceManager::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman, PeerManager& peerman)
{
    if (strCommand == NetMsgType::GETGOVPAGE) {
        if (!CanUseGovernancePageProtocol(*pfrom)) {
            LogPrint(BCLog::GOBJECT,
                     "GETGOVPAGE rejected peer=%d nonce=unknown "
                     "scope=unknown cursor=unknown "
                     "reason=protocol-unavailable\n",
                     pfrom->GetId());
            return;
        }

        CGovernancePageRequest request;
        vRecv >> request;
        const auto log_rejection{[&](const char* reason) {
            LogPrint(BCLog::GOBJECT,
                     "GETGOVPAGE rejected peer=%d nonce=%u scope=%s "
                     "cursor=%s reason=%s\n",
                     pfrom->GetId(), request.nonce,
                     request.scope_hash.ToString(),
                     request.cursor.IsNull() ? "absent" : "present",
                     reason);
        }};
        if (request.nonce == 0 ||
            request.cursor.IsNull() != request.view_id.IsNull()) {
            log_rejection(request.nonce == 0
                              ? "malformed-zero-nonce"
                              : "malformed-cursor-view-presence-mismatch");
            if (const PeerRef peer{peerman.GetPeerRef(pfrom->GetId())}) {
                peerman.Misbehaving(
                    *peer, 20, "malformed governance page request");
            }
            return;
        }

        const auto page_request_time{
            GetTime<std::chrono::microseconds>()};
        auto page_request_admission{
            GovernancePageServeRateLimiter::RequestResult::SOURCE_LIMITED};
        {
            LOCK(m_page_serve_rate_mutex);
            const auto admission{m_page_serve_rate.Consume(
                pfrom->GetId(), pfrom->GetVerifiedProRegTxHash(),
                pfrom->nKeyedNetGroup, page_request_time)};
            page_request_admission = admission;
        }
        if (page_request_admission ==
            GovernancePageServeRateLimiter::RequestResult::SOURCE_LIMITED) {
            log_rejection("source-limited");
            return;
        }

        auto preparation{peerman.PrepareGovernancePageRequest(
            *pfrom, request)};
        if (!preparation) return;
        if (page_request_admission ==
            GovernancePageServeRateLimiter::RequestResult::GLOBAL_BUSY) {
            GovernancePageBuildResult unavailable;
            unavailable.response.scope_hash = request.scope_hash;
            unavailable.response.cursor = request.cursor;
            unavailable.response.request_view_id = request.view_id;
            unavailable.response.nonce = request.nonce;
            unavailable.response.status =
                GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE;
            unavailable.response.next_cursor = request.cursor;
            (void)peerman.SendGovernancePage(*pfrom, unavailable);
            return;
        }
        if (connman.OutboundTargetReached(false) &&
            !pfrom->HasPermission(NetPermissionFlags::Download)) {
            GovernancePageBuildResult unavailable;
            unavailable.response.scope_hash = request.scope_hash;
            unavailable.response.cursor = request.cursor;
            unavailable.response.request_view_id = request.view_id;
            unavailable.response.nonce = request.nonce;
            unavailable.response.status =
                GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE;
            unavailable.response.next_cursor = request.cursor;
            (void)peerman.SendGovernancePage(*pfrom, unavailable);
            return;
        }
        auto page{BuildGovernancePage(
            request, std::move(*preparation), page_request_time)};
        if (!page) {
            log_rejection("build-null");
            return;
        }
        if (!IsValidGovernancePageResponse(request, page->response)) {
            log_rejection("build-invalid-response");
            return;
        }
        (void)peerman.SendGovernancePage(*pfrom, *page);
        return;
    }

    // ANOTHER USER IS ASKING US TO HELP THEM SYNC GOVERNANCE OBJECT DATA
    if (strCommand == NetMsgType::MNGOVERNANCESYNC) {
        // Upgraded peers must use the bounded exact protocol; permitting the
        // legacy bulk path would restore the dropped-tail and CPU-amplification
        // behavior the version gate removes.
        if (SupportsGovernancePages(pfrom->GetCommonVersion())) return;
        if (!IsReady() || !masternodeSync.IsBlockchainSynced()) return;
        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return;

        uint256 nProp;
        CBloomFilter filter;

        vRecv >> nProp;

        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints()) {
            const PeerRef peer{peerman.GetPeerRef(pfrom->GetId())};
            if (peer) {
                peerman.Misbehaving(*peer, 100, "too-large bloom filter");
            }
            return;
        }

        LogPrint(BCLog::GOBJECT, "MNGOVERNANCESYNC -- syncing governance objects to our peer %s\n", pfrom->addr.ToStringAddr());
        const auto legacy_request_time{
            GetTime<std::chrono::microseconds>()};
        {
            LOCK(m_page_serve_rate_mutex);
            if (m_page_serve_rate.Consume(
                    pfrom->GetId(), pfrom->GetVerifiedProRegTxHash(),
                    pfrom->nKeyedNetGroup, legacy_request_time) !=
                GovernancePageServeRateLimiter::RequestResult::ACCEPTED) {
                return;
            }
        }
        if (connman.OutboundTargetReached(false) &&
            !pfrom->HasPermission(NetPermissionFlags::Download)) {
            return;
        }

        const PeerRef peer{peerman.GetPeerRef(pfrom->GetId())};
        if (!peer) return;
        if (nProp.IsNull()) {
            if (netfulfilledman->HasFulfilledRequest(
                    pfrom->addr, NetMsgType::MNGOVERNANCESYNC)) {
                peerman.Misbehaving(
                    *peer, 20, "peer already asked for list");
                return;
            }
            netfulfilledman->AddFulfilledRequest(
                pfrom->addr, NetMsgType::MNGOVERNANCESYNC);
        }

        CGovernancePageRequest bounded_request;
        bounded_request.scope_hash = nProp;
        bounded_request.nonce = 1;
        const auto bounded_page{BuildGovernancePage(
            bounded_request, {}, legacy_request_time)};
        if (!bounded_page ||
            bounded_page->response.status != GOVERNANCE_PAGE_OK) {
            return;
        }

        std::vector<CInv> relay_inventory;
        if (bounded_page->snapshot) {
            relay_inventory.reserve(
                bounded_page->snapshot->Entries().size());
            for (const auto& entry :
                 bounded_page->snapshot->Entries()) {
                if (!nProp.IsNull() &&
                    filter.contains(entry.inv.hash)) {
                    continue;
                }
                relay_inventory.push_back(entry.inv);
            }
        }
        for (const CInv& inv : relay_inventory) {
            peerman.PushTxInventoryOther(*peer, inv);
        }
        connman.PushMessage(
            pfrom, CNetMsgMaker(pfrom->GetCommonVersion()).Make(
                       NetMsgType::SYNCSTATUSCOUNT,
                       nProp.IsNull() ? MASTERNODE_SYNC_GOVOBJ
                                      : MASTERNODE_SYNC_GOVOBJ_VOTE,
                       static_cast<int>(relay_inventory.size())));
        return;
    }

    // A NEW GOVERNANCE OBJECT HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECT) {
        // MAKE SURE WE HAVE A VALID REFERENCE TO THE TIP BEFORE CONTINUING

        CGovernanceObject govobj;
        vRecv >> govobj;

        uint256 nHash = govobj.GetHash();
        PeerRef peer = peerman.GetPeerRef(pfrom->GetId());
        ScopedGovernanceResponse response{
            peerman,
            peerman.BeginGovernanceResponse(
                pfrom->GetId(),
                CInv{MSG_GOVERNANCE_OBJECT, nHash})};
        if (!response) {
            LogPrint(BCLog::GOBJECT,
                     "MNGOVERNANCEOBJECT -- Received unrequested object: %s, peer = %d\n",
                     nHash.ToString(), pfrom->GetId());
            // A null authorization can also mean this exact request expired
            // immediately before the payload arrived. The tracker has already
            // attributed that timeout, so it is not proof of unsolicited data.
            return;
        }
        if (response.Authorization().page_required &&
            !response.Authorization().page_scope.IsNull()) {
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::PAGE_INVALID);
            return;
        }
        if (!IsReady()) return;

        if (!masternodeSync.IsBlockchainSynced()) {
            LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- masternode list not synced\n");
            return;
        }

        std::string strHash = nHash.ToString();

        LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- Received object: %s\n", strHash);

        // Resolve a byte-exact stored object before branch-specific trigger
        // verification. A reorg can make historical data locally inactive,
        // but cannot turn the exact requested bytes into peer misconduct.
        bool resolve_known_object{false};
        {
            LOCK2(cs_main, cs);
            const CBlockIndex* active_tip{chainman.ActiveTip()};
            if (!IsReadyForTip(active_tip)) return;
            if (const auto known{mapObjects.find(nHash)};
                known != mapObjects.end()) {
                const bool exact_wire{
                    known->second.HasSameWireEncoding(govobj)};
                if (exact_wire ||
                    !response.Authorization().page_required) {
                    resolve_known_object = true;
                } else {
                    if (known->second.GetObjectType() !=
                        govobj.GetObjectType()) {
                        response.SetOutcome(
                            GovernanceRequestTracker::ResponseOutcome::
                                PAYLOAD_INVALID);
                        return;
                    }
                    bool eligible{
                        !known->second.IsSetCachedDelete() &&
                        !known->second.IsSetExpired() &&
                        !m_pq_inactive_triggers.contains(nHash)};
                    if (eligible && known->second.GetObjectType() ==
                                        GOVERNANCE_OBJECT_TRIGGER) {
                        const auto trigger_it{mapTrigger.find(nHash)};
                        eligible = trigger_it != mapTrigger.end() &&
                            trigger_it->second->GetBlockHeight() >
                                chainman.ActiveHeight();
                    }
                    if (!eligible) return;
                }
            }
        }
        if (resolve_known_object) {
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::
                    VALID_OR_EXACT_KNOWN);
            if (peer) peerman.AddKnownTx(*peer, nHash);
            return;
        }

        const CBlockIndex* expected_tip{nullptr};
        const CBlockIndex* pq_preverified_tip{nullptr};
        CDeterministicMNList object_mn_list;
        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
            std::string authorization_error;
            bool authorization_context_valid{false};
            {
                LOCK(cs_main);
                pq_preverified_tip = chainman.ActiveTip();
                if (pq_preverified_tip == nullptr) return;
                object_mn_list = deterministicMNManager->GetListForBlock(
                    pq_preverified_tip);
                authorization_context_valid =
                    govobj.CheckPQAuthorizationContext(
                        *pq_preverified_tip, object_mn_list,
                        authorization_error);
            }
            const bool signature_valid{
                authorization_context_valid &&
                govobj.CheckPQSignature(*pq_preverified_tip,
                                        object_mn_list,
                                        authorization_error)};
            if (!signature_valid) {
                bool stable_context{false};
                {
                    LOCK(cs_main);
                    stable_context =
                        chainman.ActiveTip() == pq_preverified_tip &&
                        IsReadyForTip(pq_preverified_tip);
                }
                if (stable_context) {
                    response.SetOutcome(
                        GovernanceRequestTracker::ResponseOutcome::
                            PAYLOAD_INVALID);
                    if (peer && masternodeSync.IsSynced() &&
                        !response.Authorization().page_required) {
                        peerman.Misbehaving(
                            *peer, 20, "invalid governance trigger");
                    }
                }
                LogPrint(BCLog::GOBJECT,
                         "MNGOVERNANCEOBJECT -- Invalid trigger authorization: %s\n",
                         authorization_error);
                return;
            }
        }

        {
            LOCK2(cs_main, cs);
            const CBlockIndex* active_tip{chainman.ActiveTip()};
            if (!IsReadyForTip(active_tip)) return;
            expected_tip = active_tip;

            if (pq_preverified_tip != nullptr &&
                active_tip != pq_preverified_tip) {
                LogPrint(BCLog::GOBJECT,
                         "MNGOVERNANCEOBJECT -- chain tip changed during trigger verification: %s\n",
                         strHash);
                return;
            }
            if (pq_preverified_tip == nullptr) {
                object_mn_list =
                    deterministicMNManager->GetListForBlock(active_tip);
            }

            if (const auto known{mapObjects.find(nHash)};
                known != mapObjects.end()) {
                const CGovernanceObject& stored{known->second};
                if (response.Authorization().page_required &&
                    stored.GetObjectType() != govobj.GetObjectType()) {
                    response.SetOutcome(
                        GovernanceRequestTracker::ResponseOutcome::
                            PAYLOAD_INVALID);
                    return;
                }
                bool eligible{
                    !stored.IsSetCachedDelete() && !stored.IsSetExpired() &&
                    !m_pq_inactive_triggers.contains(nHash)};
                if (eligible &&
                    stored.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
                    const auto trigger_it{mapTrigger.find(nHash)};
                    eligible = trigger_it != mapTrigger.end() &&
                        trigger_it->second->GetBlockHeight() >
                            chainman.ActiveHeight();
                }
                const bool exact_wire{stored.HasSameWireEncoding(govobj)};
                if (!response.Authorization().page_required || exact_wire) {
                    response.SetOutcome(
                        GovernanceRequestTracker::ResponseOutcome::
                            VALID_OR_EXACT_KNOWN);
                    LogPrint(BCLog::GOBJECT,
                             "MNGOVERNANCEOBJECT -- Received already seen object: %s\n",
                             strHash);
                    return;
                }
                if (!eligible) {
                    // The source supplied an alternate form while our active
                    // eligibility changed. Retry without blaming either peer.
                    LogPrint(BCLog::GOBJECT,
                             "MNGOVERNANCEOBJECT -- Received locally ineligible object: %s\n",
                             strHash);
                    return;
                }
                // The governance hash does not commit every wire field. Let
                // the alternate form pass full local/PQ validation below;
                // AddGovernanceObject will then report DUPLICATE.
            }
            if (mapPostponedObjects.count(nHash) ||
                mapErasedGovernanceObjects.count(nHash)) {
                if (!response.Authorization().page_required) {
                    response.SetOutcome(
                        GovernanceRequestTracker::ResponseOutcome::
                            VALID_OR_EXACT_KNOWN);
                }
                LogPrint(BCLog::GOBJECT,
                         "MNGOVERNANCEOBJECT -- Received unavailable already seen object: %s\n",
                         strHash);
                return;
            }


            bool fRateCheckBypassed = false;
            if (!MasternodeRateCheck(govobj, true, false, fRateCheckBypassed)) {
                LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- masternode rate check failed - %s - (current block height %d) \n", strHash, GetCachedBlockHeight());
                return;
            }

            std::string strError;
            // CHECK OBJECT AGAINST LOCAL BLOCKCHAIN

            bool fMissingConfirmations = false;
            bool fIsValid = govobj.IsValidLocally(
                chainman, object_mn_list, strError, fMissingConfirmations, true,
                pq_preverified_tip != nullptr);

            if (fRateCheckBypassed && fIsValid && !MasternodeRateCheck(govobj, true)) {
                LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- masternode rate check failed (after signature verification) - %s - (current block height %d)\n", strHash, GetCachedBlockHeight());
                return;
            }

            if (!fIsValid) {
                if (fMissingConfirmations) {
                    const auto admission{
                        AddPostponedObject(govobj, active_tip)};
                    if (admission != GovernanceObjectAdmissionResult::ACCEPTED &&
                        admission != GovernanceObjectAdmissionResult::DUPLICATE) {
                        LogPrint(BCLog::GOBJECT,
                                 "MNGOVERNANCEOBJECT -- postponed admission failed: %s\n",
                                 GovernanceObjectAdmissionError(admission));
                    }
                    LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- Not enough fee confirmations for: %s, strError = %s\n", strHash, strError);
                } else {
                    LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECT -- Governance object is invalid - %s\n", strError);
                    response.SetOutcome(
                        GovernanceRequestTracker::ResponseOutcome::
                            PAYLOAD_INVALID);
                    // apply node's ban score
                    if (peer && !response.Authorization().page_required)
                        peerman.Misbehaving(*peer, 20, "invalid governance object");
                }

                return;
            }
        }

        // SYSCOIN: do not inherit recursive state locks into orphan SLH work.
        const auto admission{AddGovernanceObject(
            govobj, peerman, pfrom, expected_tip, pq_preverified_tip)};
        switch (admission) {
        case GovernanceObjectAdmissionResult::ACCEPTED:
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::
                    VALID_OR_EXACT_KNOWN);
            if (peer) peerman.AddKnownTx(*peer, nHash);
            break;
        case GovernanceObjectAdmissionResult::DUPLICATE: {
            bool stored_active{false};
            bool exact_wire{false};
            bool same_type{false};
            bool stored_found{false};
            {
                LOCK2(cs_main, cs);
                const auto it{mapObjects.find(nHash)};
                if (it != mapObjects.end()) {
                    stored_found = true;
                    stored_active = !it->second.IsSetCachedDelete() &&
                        !it->second.IsSetExpired() &&
                        !m_pq_inactive_triggers.contains(nHash);
                    if (stored_active &&
                        it->second.GetObjectType() ==
                            GOVERNANCE_OBJECT_TRIGGER) {
                        const auto trigger_it{mapTrigger.find(nHash)};
                        stored_active = trigger_it != mapTrigger.end() &&
                            trigger_it->second->GetBlockHeight() >
                                chainman.ActiveHeight();
                    }
                    exact_wire = it->second.HasSameWireEncoding(govobj);
                    same_type = it->second.GetObjectType() ==
                        govobj.GetObjectType();
                }
            }
            if (response.Authorization().page_required && stored_found &&
                !same_type) {
                response.SetOutcome(
                    GovernanceRequestTracker::ResponseOutcome::
                        PAYLOAD_INVALID);
            } else if (!response.Authorization().page_required ||
                       stored_active) {
                response.SetOutcome(
                    exact_wire
                        ? GovernanceRequestTracker::ResponseOutcome::
                              VALID_OR_EXACT_KNOWN
                        : GovernanceRequestTracker::ResponseOutcome::
                              VALID_SUPERSEDED);
                if (peer) peerman.AddKnownTx(*peer, nHash);
            }
            break;
        }
        case GovernanceObjectAdmissionResult::INVALID:
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::PAYLOAD_INVALID);
            break;
        case GovernanceObjectAdmissionResult::UNAVAILABLE:
        case GovernanceObjectAdmissionResult::LOCAL_INELIGIBLE:
        case GovernanceObjectAdmissionResult::STALE_TIP:
        case GovernanceObjectAdmissionResult::RESOURCE_LIMIT:
            break;
        }
    }

    // A NEW GOVERNANCE OBJECT VOTE HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECTVOTE) {
        CGovernanceVote vote;
        vRecv >> vote;

        const uint256 nHash = vote.GetHash();
        PeerRef peer = peerman.GetPeerRef(pfrom->GetId());
        ScopedGovernanceResponse response{
            peerman,
            peerman.BeginGovernanceResponse(
                pfrom->GetId(),
                CInv{MSG_GOVERNANCE_OBJECT_VOTE, nHash})};
        if (!response) {
            LogPrint(BCLog::GOBJECT,
                     "MNGOVERNANCEOBJECTVOTE -- Received unrequested vote object: %s, hash: %s, peer = %d\n",
                     vote.ToString(), nHash.ToString(), pfrom->GetId());
            // A just-expired request is indistinguishable here from an
            // unsolicited payload; timeout attribution belongs to the
            // request tracker rather than a second peer penalty.
            return;
        }
        if (response.Authorization().page_required &&
            response.Authorization().page_scope != vote.GetParentHash()) {
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::PAGE_INVALID);
            return;
        }
        if (!IsReady()) return;

        // Ignore such messages until masternode list is synced
        if (!masternodeSync.IsBlockchainSynced()) {
            LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECTVOTE -- masternode list not synced\n");
            return;
        }

        LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECTVOTE -- Received vote: %s\n", vote.ToString());

        std::string strHash = nHash.ToString();

        // A logical vote hash omits signature bytes. Resolve an exact stored
        // wire form immediately, but fully verify any alternate form before
        // treating it as a valid superseded response.
        const CBlockIndex* known_tip{nullptr};
        CDeterministicMNList known_mn_list;
        std::optional<llmq::pq::GovernanceAuthPurpose> known_purpose;
        int known_object_type{GOVERNANCE_OBJECT_UNKNOWN};
        std::optional<CGovernanceVote> stored_vote;
        bool stored_vote_eligible{false};
        {
            LOCK2(chainman.GetMutex(), cs);
            known_tip = chainman.ActiveTip();
            if (IsReadyForTip(known_tip)) {
                const auto object_it{mapObjects.find(vote.GetParentHash())};
                if (object_it != mapObjects.end()) {
                    const CGovernanceObject& object{object_it->second};
                    stored_vote_eligible =
                        !object.IsSetCachedDelete() &&
                        !object.IsSetExpired() &&
                        !m_pq_inactive_triggers.contains(
                            vote.GetParentHash());
                    known_object_type = object.GetObjectType();
                    if (stored_vote_eligible &&
                        known_object_type == GOVERNANCE_OBJECT_TRIGGER) {
                        const auto trigger_it{
                            mapTrigger.find(vote.GetParentHash())};
                        stored_vote_eligible =
                            trigger_it != mapTrigger.end() &&
                            trigger_it->second->GetBlockHeight() >
                                chainman.ActiveHeight();
                    }
                    if (const auto found_vote{
                            object.GetVoteFile().GetVote(nHash)}) {
                        stored_vote.emplace(*found_vote);
                        known_mn_list =
                            deterministicMNManager->GetListForBlock(
                                known_tip);
                        known_purpose = GetGovernanceVoteAuthPurpose(
                            known_object_type, vote.GetSignal());
                    }
                }
            }
        }
        if (stored_vote) {
            if (stored_vote->HasSameWireEncoding(vote)) {
                response.SetOutcome(
                    GovernanceRequestTracker::ResponseOutcome::
                        VALID_OR_EXACT_KNOWN);
                if (peer) peerman.AddKnownTx(*peer, nHash);
                return;
            }
            if (!stored_vote_eligible) {
                // An alternate form needs current semantic validation, but
                // the parent/trigger view moved while it was in flight.
                return;
            }

            std::string known_error;
            const bool valid_alternate{known_purpose
                ? VerifyPQVoteUnlocked(
                      vote, *known_tip, known_mn_list,
                      *known_purpose, known_error)
                : vote.IsValid(known_mn_list)};
            bool stable_known_vote{false};
            {
                LOCK2(chainman.GetMutex(), cs);
                const auto object_it{mapObjects.find(
                    vote.GetParentHash())};
                bool rebound_eligible{
                    object_it != mapObjects.end() &&
                    !object_it->second.IsSetCachedDelete() &&
                    !object_it->second.IsSetExpired() &&
                    !m_pq_inactive_triggers.contains(
                        vote.GetParentHash())};
                if (rebound_eligible &&
                    object_it->second.GetObjectType() ==
                        GOVERNANCE_OBJECT_TRIGGER) {
                    const auto trigger_it{
                        mapTrigger.find(vote.GetParentHash())};
                    rebound_eligible =
                        trigger_it != mapTrigger.end() &&
                        trigger_it->second->GetBlockHeight() >
                            chainman.ActiveHeight();
                }
                if (chainman.ActiveTip() == known_tip &&
                    IsReadyForTip(known_tip) &&
                    rebound_eligible &&
                    object_it->second.GetObjectType() ==
                        known_object_type &&
                    GetGovernanceVoteAuthPurpose(
                        known_object_type, vote.GetSignal()) ==
                        known_purpose) {
                    const auto rebound{
                        object_it->second.GetVoteFile().GetVote(nHash)};
                    stable_known_vote = rebound &&
                        rebound->HasSameWireEncoding(*stored_vote);
                }
            }
            if (!stable_known_vote) return;
            if (!valid_alternate) {
                response.SetOutcome(
                    GovernanceRequestTracker::ResponseOutcome::
                        PAYLOAD_INVALID);
                if (peer && masternodeSync.IsSynced() &&
                    !response.Authorization().page_required) {
                    peerman.Misbehaving(
                        *peer, 20, "invalid alternate governance vote");
                }
                return;
            }
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::
                    VALID_SUPERSEDED);
            if (peer) peerman.AddKnownTx(*peer, nHash);
            return;
        }

        CGovernanceException exception;
        bool orphan_vote_retained{false};
        if (ProcessVote(
                pfrom, vote, exception, connman,
                &orphan_vote_retained)) {
            response.SetOutcome(
                GovernanceRequestTracker::ResponseOutcome::
                    VALID_OR_EXACT_KNOWN);
            if (peer) peerman.AddKnownTx(*peer, nHash);
            LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECTVOTE -- %s new\n", strHash);
            masternodeSync.BumpAssetLastTime("MNGOVERNANCEOBJECTVOTE");
            {
                LOCK2(chainman.GetMutex(), cs);
                const CBlockIndex* relay_tip{chainman.ActiveTip()};
                if (!IsReadyForTip(relay_tip)) return;
                CGovernanceObject* relayed_object{nullptr};
                if (!cmapVoteToObject.Get(nHash, relayed_object) ||
                    relayed_object == nullptr ||
                    m_pq_inactive_triggers.contains(
                        relayed_object->GetHash()) ||
                    !relayed_object->GetVoteFile().HasVote(nHash)) {
                    return;
                }
                const auto relay_mn_list{
                    deterministicMNManager->GetListForBlock(relay_tip)};
                vote.Relay(peerman, relay_mn_list);
            }
        } else {
            if (orphan_vote_retained) {
                LogPrint(
                    BCLog::GOBJECT,
                    "MNGOVERNANCEOBJECTVOTE -- Stored verified orphan vote %s\n",
                    strHash);
                response.SetOutcome(
                    GovernanceRequestTracker::ResponseOutcome::
                        VALID_ORPHAN_STORED);
                if (peer) peerman.AddKnownTx(*peer, nHash);
                return;
            }
            LogPrint(BCLog::GOBJECT, "MNGOVERNANCEOBJECTVOTE -- Rejected vote, error = %s\n", exception.what());
            if (exception.GetType() == GOVERNANCE_EXCEPTION_NONE) {
                const CBlockIndex* rejected_tip{nullptr};
                CDeterministicMNList rejected_mn_list;
                int rejected_object_type{GOVERNANCE_OBJECT_UNKNOWN};
                std::optional<llmq::pq::GovernanceAuthPurpose>
                    rejected_purpose;
                {
                    LOCK2(chainman.GetMutex(), cs);
                    rejected_tip = chainman.ActiveTip();
                    const auto object_it{mapObjects.find(
                        vote.GetParentHash())};
                    if (IsReadyForTip(rejected_tip) &&
                        object_it != mapObjects.end() &&
                        !object_it->second.IsSetCachedDelete() &&
                        !object_it->second.IsSetExpired() &&
                        !m_pq_inactive_triggers.contains(
                            vote.GetParentHash())) {
                        rejected_object_type =
                            object_it->second.GetObjectType();
                        if (rejected_object_type ==
                            GOVERNANCE_OBJECT_TRIGGER) {
                            const auto trigger_it{
                                mapTrigger.find(vote.GetParentHash())};
                            if (trigger_it == mapTrigger.end() ||
                                trigger_it->second->GetBlockHeight() <=
                                    chainman.ActiveHeight()) {
                                rejected_tip = nullptr;
                            }
                        }
                    }
                    if (rejected_tip != nullptr) {
                        rejected_mn_list =
                            deterministicMNManager->GetListForBlock(
                                rejected_tip);
                        rejected_purpose =
                            GetGovernanceVoteAuthPurpose(
                                rejected_object_type,
                                vote.GetSignal());
                    } else {
                        rejected_tip = nullptr;
                    }
                }
                if (rejected_tip != nullptr) {
                    std::string rejected_error;
                    const bool valid_rejected{rejected_purpose
                        ? VerifyPQVoteUnlocked(
                              vote, *rejected_tip,
                              rejected_mn_list,
                              *rejected_purpose,
                              rejected_error)
                        : vote.IsValid(rejected_mn_list)};
                    bool stable_rejected_context{false};
                    {
                        LOCK2(chainman.GetMutex(), cs);
                        const auto object_it{mapObjects.find(
                            vote.GetParentHash())};
                        bool rebound_eligible{
                            object_it != mapObjects.end() &&
                            !object_it->second.IsSetCachedDelete() &&
                            !object_it->second.IsSetExpired() &&
                            !m_pq_inactive_triggers.contains(
                                vote.GetParentHash())};
                        if (rebound_eligible &&
                            object_it->second.GetObjectType() ==
                                GOVERNANCE_OBJECT_TRIGGER) {
                            const auto trigger_it{
                                mapTrigger.find(vote.GetParentHash())};
                            rebound_eligible =
                                trigger_it != mapTrigger.end() &&
                                trigger_it->second->GetBlockHeight() >
                                    chainman.ActiveHeight();
                        }
                        stable_rejected_context =
                            chainman.ActiveTip() == rejected_tip &&
                            IsReadyForTip(rejected_tip) &&
                            rebound_eligible &&
                            object_it->second.GetObjectType() ==
                                rejected_object_type &&
                            object_it->second.HasStoredSupersedingVote(vote) &&
                            GetGovernanceVoteAuthPurpose(
                                rejected_object_type,
                                vote.GetSignal()) ==
                                rejected_purpose;
                    }
                    if (stable_rejected_context) {
                        response.SetOutcome(
                            valid_rejected
                                ? GovernanceRequestTracker::
                                      ResponseOutcome::VALID_SUPERSEDED
                                : GovernanceRequestTracker::
                                      ResponseOutcome::PAYLOAD_INVALID);
                        if (valid_rejected) {
                            if (peer) peerman.AddKnownTx(*peer, nHash);
                        } else if (peer && masternodeSync.IsSynced() &&
                                   !response.Authorization().page_required) {
                            peerman.Misbehaving(
                                *peer, 20,
                                "invalid superseded governance vote");
                        }
                    }
                }
            } else if (exception.GetNodePenalty() != 0) {
                response.SetOutcome(
                    GovernanceRequestTracker::ResponseOutcome::
                        PAYLOAD_INVALID);
            }
            if ((exception.GetNodePenalty() != 0) &&
                masternodeSync.IsSynced() &&
                !response.Authorization().page_required) {
                if(peer)
                    peerman.Misbehaving(*peer, exception.GetNodePenalty(), "rejected vote");
            }
            return;
        }
    }
}

bool CGovernanceManager::VerifyPQVoteUnlocked(
    const CGovernanceVote& vote, const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    llmq::pq::GovernanceAuthPurpose purpose,
    std::string& error) const
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    return vote.IsValidPQ(validation_tip, validation_mn_list, purpose,
                          error);
}

bool CGovernanceManager::VerifyOrphanPQVoteUnlocked(
    const CGovernanceVote& vote, const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);

    if (vote.GetSignal() == VOTE_SIGNAL_FUNDING) {
        return VerifyPQVoteUnlocked(
            vote, validation_tip, validation_mn_list,
            llmq::pq::GovernanceAuthPurpose::TRIGGER_VOTE, error);
    }

    std::string proposal_error;
    if (VerifyPQVoteUnlocked(
            vote, validation_tip, validation_mn_list,
            llmq::pq::GovernanceAuthPurpose::PROPOSAL_VOTE,
            proposal_error)) {
        error.clear();
        return true;
    }

    std::string trigger_error;
    if (VerifyPQVoteUnlocked(
            vote, validation_tip, validation_mn_list,
            llmq::pq::GovernanceAuthPurpose::TRIGGER_VOTE,
            trigger_error)) {
        error.clear();
        return true;
    }
    error = "proposal authorization: " + proposal_error +
            "; trigger authorization: " + trigger_error;
    return false;
}

bool CGovernanceManager::VerifyTriggerObjectUnlocked(
    const CGovernanceObject& object, const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    return object.CheckPQSignature(validation_tip, validation_mn_list, error);
}

void CGovernanceManager::CheckOrphanVotes(
    const uint256& object_hash, PeerManager& peerman)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);

    struct CheckedVote {
        vote_time_pair_t pair;
        bool signature_valid{false};
    };

    // SYSCOIN: one ordinary tip advance must not strand an orphan batch after
    // its parent is committed. Keep the retry count fixed so adversarial tip
    // churn cannot turn this path into an unbounded verification loop.
    static constexpr std::size_t MAX_DRAIN_ATTEMPTS{2};
    for (std::size_t attempt{0}; attempt < MAX_DRAIN_ATTEMPTS; ++attempt) {
    const CBlockIndex* validation_tip{nullptr};
    CDeterministicMNList validation_mn_list;
    std::vector<vote_time_pair_t> candidates;
    int object_type{GOVERNANCE_OBJECT_UNKNOWN};
    const int64_t now{
        TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime())};
    {
        LOCK2(chainman.GetMutex(), cs);
        validation_tip = chainman.ActiveTip();
        if (!IsReadyForTip(validation_tip)) return;
        const auto object_it{mapObjects.find(object_hash)};
        if (object_it == mapObjects.end() ||
            object_it->second.IsSetCachedDelete() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(object_hash)) {
            return;
        }
        validation_mn_list =
            deterministicMNManager->GetListForBlock(validation_tip);
        object_type = object_it->second.GetObjectType();

        std::vector<vote_time_pair_t> stored;
        cmmapOrphanVotes.GetAll(object_hash, stored);
        candidates.reserve(stored.size());
        for (const auto& pair : stored) {
            if (pair.second < now) {
                EraseOrphanVote(object_hash, pair);
            } else if (candidates.size() <
                       MAX_ORPHAN_VOTES_PER_OBJECT) {
                candidates.push_back(pair);
            } else {
                // A cache created by older code can carry a larger serialized
                // per-parent bucket. Never let it bypass the current bound.
                EraseOrphanVote(object_hash, pair);
            }
        }
    }
    if (candidates.empty()) return;

    std::vector<CheckedVote> checked;
    checked.reserve(candidates.size());
    for (const auto& pair : candidates) {
        bool signature_valid{false};
        const auto pq_purpose{GetGovernanceVoteAuthPurpose(
            object_type, pair.first.GetSignal())};
        if (pq_purpose) {
            // SYSCOIN: the full SLH operation must never run under chain,
            // governance, or governance-object locks.
            AssertLockNotHeld(cs_main);
            AssertLockNotHeld(cs);
            std::string signature_error;
            signature_valid = VerifyPQVoteUnlocked(
                pair.first, *validation_tip, validation_mn_list,
                *pq_purpose, signature_error);
        } else {
            signature_valid = pair.first.IsValid(validation_mn_list);
        }
        checked.push_back(CheckedVote{pair, signature_valid});
    }

    std::vector<CGovernanceVote> accepted;
    bool branch_changed{false};
    {
        LOCK2(chainman.GetMutex(), cs);
        if (chainman.ActiveTip() != validation_tip ||
            !IsReadyForTip(validation_tip)) {
            branch_changed = true;
        } else {
            const auto object_it{mapObjects.find(object_hash)};
            if (object_it == mapObjects.end() ||
                object_it->second.IsSetCachedDelete() ||
                object_it->second.IsSetExpired() ||
                m_pq_inactive_triggers.contains(object_hash) ||
                object_it->second.GetObjectType() != object_type) {
                return;
            }
            if (object_type == GOVERNANCE_OBJECT_TRIGGER) {
                const auto trigger_it{mapTrigger.find(object_hash)};
                if (trigger_it == mapTrigger.end() ||
                    trigger_it->second->GetBlockHeight() <=
                        chainman.ActiveHeight()) {
                    return;
                }
            }

            CGovernanceObject& object{object_it->second};
            ScopedLockBool guard(cs, fRateChecksEnabled, false);
            std::vector<vote_time_pair_t> current;
            cmmapOrphanVotes.GetAll(object_hash, current);
            for (const auto& result : checked) {
                const bool still_orphaned{std::any_of(
                    current.begin(), current.end(), [&](const auto& candidate) {
                        return candidate.second == result.pair.second &&
                               candidate.first == result.pair.first &&
                               candidate.first.vchSig == result.pair.first.vchSig;
                    })};
                if (!still_orphaned) continue;

                // Move, rather than duplicate, the persisted vote budget.
                // Stable invalid candidates are discarded in this same
                // atomic manager critical section.
                EraseOrphanVote(object_hash, result.pair);

                if (result.signature_valid) {
                    CGovernanceException exception;
                    const bool pq_signature_preverified{
                        GetGovernanceVoteAuthPurpose(
                            object_type, result.pair.first.GetSignal())
                            .has_value()};
                    if (ProcessVoteWithBudget(
                            object, *validation_tip, validation_mn_list,
                            result.pair.first, exception,
                            pq_signature_preverified) &&
                        cmapVoteToObject.Insert(
                            result.pair.first.GetHash(), &object)) {
                        IndexGovernanceVote(
                            object_hash, object_type, result.pair.first);
                        accepted.push_back(result.pair.first);
                    }
                }
            }
            // Processing a newer vote can evict an earlier vote from the same
            // masternode/signal slot. Advertise only the final authoritative
            // survivors; stale relay credits would otherwise end in NOTFOUND
            // and make downstream peers blame this honest source.
            std::vector<CGovernanceVote> final_accepted;
            final_accepted.reserve(accepted.size());
            for (const auto& vote : accepted) {
                CGovernanceObject* indexed_object{nullptr};
                if (object.GetVoteFile().HasVote(vote.GetHash()) &&
                    cmapVoteToObject.Get(
                        vote.GetHash(), indexed_object) &&
                    indexed_object == &object) {
                    final_accepted.push_back(vote);
                }
            }
            accepted.swap(final_accepted);
        }
    }

    if (branch_changed) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s -- branch changed while verifying orphan votes for %s, attempt=%u\n",
                 __func__, object_hash.ToString(), attempt + 1);
        continue;
    }

    for (const auto& vote : accepted) {
        vote.Relay(peerman, validation_mn_list);
    }
    return;
    }
}

void CGovernanceManager::DrainReadyOrphanVotes(PeerManager& peerman)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    static constexpr std::size_t MAX_PARENTS_PER_PASS{8};
    std::vector<uint256> candidates;
    {
        LOCK2(chainman.GetMutex(), cs);
        const CBlockIndex* tip{chainman.ActiveTip()};
        if (!IsReadyForTip(tip)) return;
        std::vector<uint256> orphan_parents;
        cmmapOrphanVotes.GetKeys(orphan_parents);
        candidates.reserve(std::min(
            orphan_parents.size(), MAX_PARENTS_PER_PASS));
        for (const uint256& hash : orphan_parents) {
            const auto object{mapObjects.find(hash)};
            if (object == mapObjects.end() ||
                object->second.IsSetCachedDelete() ||
                object->second.IsSetExpired() ||
                m_pq_inactive_triggers.contains(hash)) {
                continue;
            }
            if (object->second.GetObjectType() ==
                GOVERNANCE_OBJECT_TRIGGER) {
                const auto trigger{mapTrigger.find(hash)};
                if (trigger == mapTrigger.end() || !trigger->second ||
                    trigger->second->GetBlockHeight() <= tip->nHeight) {
                    continue;
                }
            }
            candidates.push_back(hash);
            if (candidates.size() >= MAX_PARENTS_PER_PASS) break;
        }
    }
    for (const uint256& hash : candidates) {
        CheckOrphanVotes(hash, peerman);
    }
}

GovernanceObjectAdmissionResult CGovernanceManager::AddGovernanceObject(
    CGovernanceObject& govobj, PeerManager& peerman, const CNode* pfrom,
    const CBlockIndex* expected_tip,
    const CBlockIndex* pq_preverified_tip)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) return GovernanceObjectAdmissionResult::UNAVAILABLE;
    uint256 nHash = govobj.GetHash();
    std::string strHash = nHash.ToString();

    CDeterministicMNList tip_mn_list;
    const CBlockIndex* validation_tip{nullptr};
    {
        LOCK(cs_main);
        validation_tip = chainman.ActiveTip();
        if (!IsReadyForTip(validation_tip)) {
            return GovernanceObjectAdmissionResult::UNAVAILABLE;
        }
        if (expected_tip != nullptr && validation_tip != expected_tip) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::AddGovernanceObject -- validation branch changed for %s\n",
                     nHash.ToString());
            return GovernanceObjectAdmissionResult::STALE_TIP;
        }
        // SYSCOIN: bind the MN snapshot to the exact tip whose PQ signature
        // was verified; independently sampling the manager tip permits an
        // A-to-B-to-A race to pair the proof with the wrong list.
        if (validation_tip != nullptr) {
            tip_mn_list =
                deterministicMNManager->GetListForBlock(validation_tip);
        }
    }

    // Update cached variables for this object and add it to our managed data
    govobj.UpdateSentinelVariables(tip_mn_list); // This sets local vars in object

    {
        LOCK2(cs_main, cs);
        if (chainman.ActiveTip() != validation_tip ||
            !IsReadyForTip(validation_tip)) {
            return GovernanceObjectAdmissionResult::STALE_TIP;
        }
        std::string strError;

        const bool use_preverified_pq{
            pq_preverified_tip != nullptr &&
            govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER &&
            chainman.ActiveTip() == pq_preverified_tip};
        if (pq_preverified_tip != nullptr && !use_preverified_pq) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::AddGovernanceObject -- PQ verification branch changed for %s\n",
                     nHash.ToString());
            return GovernanceObjectAdmissionResult::STALE_TIP;
        }

        // Make sure this object is valid locally
        if (!govobj.IsValidLocally(chainman, tip_mn_list, strError, true,
                                   use_preverified_pq)) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- invalid governance object - %s - (nCachedBlockHeight %d) \n", strError, GetCachedBlockHeight());
            return GovernanceObjectAdmissionResult::INVALID;
        }

        LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- Adding object: hash = %s, type = %d\n", nHash.ToString(), govobj.GetObjectType());

        // Insert into our governance object memory; if we have this object already, we don't want another copy
        auto objpair = mapObjects.try_emplace(nHash, std::move(govobj));

        if (!objpair.second) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- already have governance object %s\n", nHash.ToString());
            return GovernanceObjectAdmissionResult::DUPLICATE;
        }
        InvalidateObjectPageCache();

        CGovernanceObject& govObjRef = objpair.first->second;
        const uint64_t object_vote_bytes{
            govObjRef.GetVoteFile().GetSerializedVoteBytes()};
        if (!CanAdmitPersistedVoteBytes(/*current_object_bytes=*/0,
                                        object_vote_bytes)) {
            mapObjects.erase(objpair.first);
            return GovernanceObjectAdmissionResult::RESOURCE_LIMIT;
        }

        // Should we add this object to any other managers?
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- Before trigger block, GetDataAsPlainString = %s, nObjectType = %d\n",
                    govObjRef.GetDataAsPlainString(), govObjRef.GetObjectType());

        const auto trigger_admission{
            govObjRef.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER
                ? AddNewTrigger(nHash, chainman.ActiveHeight())
                : GovernanceTriggerAdmissionResult::ACCEPTED};
        if (trigger_admission != GovernanceTriggerAdmissionResult::ACCEPTED) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- undo adding invalid trigger object: hash = %s\n", nHash.ToString());
            mapObjects.erase(objpair.first);
            mapTrigger.erase(nHash);
            m_pq_inactive_triggers.erase(nHash);
            switch (trigger_admission) {
            case GovernanceTriggerAdmissionResult::UNAVAILABLE:
                return GovernanceObjectAdmissionResult::UNAVAILABLE;
            case GovernanceTriggerAdmissionResult::LOCAL_INELIGIBLE:
                return GovernanceObjectAdmissionResult::LOCAL_INELIGIBLE;
            case GovernanceTriggerAdmissionResult::INVALID:
                return GovernanceObjectAdmissionResult::INVALID;
            case GovernanceTriggerAdmissionResult::ACCEPTED:
                break;
            }
            Assume(false);
        }

        m_persisted_vote_bytes += object_vote_bytes;

        LogPrint(BCLog::GOBJECT, "CGovernanceManager::AddGovernanceObject -- %s new, received from peer %s\n", strHash, pfrom ? pfrom->addr.ToStringAddr() : "nullptr");
        govObjRef.Relay(peerman);

        // Update the rate buffer
        MasternodeRateUpdate(govObjRef);

        masternodeSync.BumpAssetLastTime("CGovernanceManager::AddGovernanceObject");
    }

    // SYSCOIN: orphan signatures are verified after releasing every state
    // lock and rebound to the exact branch/object before insertion.
    CheckOrphanVotes(nHash, peerman);

    // Send notification to script/ZMQ
    GetMainSignals().NotifyGovernanceObject(nHash);
    return GovernanceObjectAdmissionResult::ACCEPTED;
}

GovernanceObjectAdmissionResult CGovernanceManager::AddPostponedObject(
    const CGovernanceObject& govobj,
    const CBlockIndex* expected_tip)
{
    if (!IsReady()) return GovernanceObjectAdmissionResult::UNAVAILABLE;
    LOCK2(chainman.GetMutex(), cs);
    const CBlockIndex* tip{chainman.ActiveTip()};
    if (expected_tip != nullptr && tip != expected_tip) {
        return GovernanceObjectAdmissionResult::STALE_TIP;
    }
    if (!IsReadyForTip(tip)) {
        return GovernanceObjectAdmissionResult::UNAVAILABLE;
    }
    const uint256 hash{govobj.GetHash()};
    if (mapObjects.contains(hash) || mapPostponedObjects.contains(hash)) {
        return GovernanceObjectAdmissionResult::DUPLICATE;
    }
    mapPostponedObjects.emplace(hash, govobj);
    return GovernanceObjectAdmissionResult::ACCEPTED;
}

void CGovernanceManager::CheckAndRemove()
{
    if (!IsReady()) return;
    // Return on initial sync, spammed the debug.log and provided no use
    if (!masternodeSync.IsBlockchainSynced()) return;

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdateCachesAndClean\n");

    LOCK2(cs_main, cs);
    const CBlockIndex* validation_tip{chainman.ActiveTip()};
    if (!IsReadyForTip(validation_tip)) return;
    const int nHeight{validation_tip->nHeight};
    const auto tip_mn_list{
        deterministicMNManager->GetListForBlock(validation_tip)};


    ScopedLockBool guard(cs, fRateChecksEnabled, false);

    // Clean up any expired or invalid triggers
    CleanAndRemoveTriggers();

    auto it = mapObjects.begin();
    int64_t nNow = GetTime<std::chrono::seconds>().count();

    while (it != mapObjects.end()) {
        CGovernanceObject* pObj = &((*it).second);

        uint256 nHash = it->first;
        if (m_pq_inactive_triggers.contains(nHash)) {
            ++it;
            continue;
        }
        std::string strHash = nHash.ToString();
        const bool was_page_eligible{
            !pObj->IsSetCachedDelete() && !pObj->IsSetExpired()};

        // IF CACHE IS NOT DIRTY, WHY DO THIS?
        if (pObj->IsSetDirtyCache()) {
            // UPDATE LOCAL VALIDITY AGAINST CRYPTO DATA
            pObj->UpdateLocalValidity(chainman, tip_mn_list);

            // UPDATE SENTINEL SIGNALING VARIABLES
            pObj->UpdateSentinelVariables(tip_mn_list);
            const bool is_page_eligible{
                !pObj->IsSetCachedDelete() && !pObj->IsSetExpired()};
            if (was_page_eligible != is_page_eligible) {
                InvalidateObjectPageCache();
            }
        }

        // IF DELETE=TRUE, THEN CLEAN THE MESS UP!

        int64_t nTimeSinceDeletion = nNow - pObj->GetDeletionTime();

        LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdateCachesAndClean -- Checking object for deletion: %s, deletion time = %d, time since deletion = %d, delete flag = %d, expired flag = %d\n",
            strHash, pObj->GetDeletionTime(), nTimeSinceDeletion, pObj->IsSetCachedDelete(), pObj->IsSetExpired());

        if ((pObj->IsSetCachedDelete() || pObj->IsSetExpired()) &&
            (nTimeSinceDeletion >= GOVERNANCE_DELETION_DELAY)) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdateCachesAndClean -- erase obj %s\n", (*it).first.ToString());
            mmetaman->RemoveGovernanceObject(pObj->GetHash());

            // Remove vote references
            const object_ref_cm_t::list_t& listItems = cmapVoteToObject.GetItemList();
            auto lit = listItems.begin();
            while (lit != listItems.end()) {
                if (lit->value == pObj) {
                    uint256 nKey = lit->key;
                    ++lit;
                    cmapVoteToObject.Erase(nKey);
                } else {
                    ++lit;
                }
            }

            int64_t nTimeExpired{0};

            if (pObj->GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
                // keep hashes of deleted proposals forever
                nTimeExpired = std::numeric_limits<int64_t>::max();
            } else {
                int64_t nSuperblockCycleSeconds = Params().GetConsensus().SuperBlockCycle(nHeight) * Params().GetConsensus().PowTargetSpacing(nHeight);
                nTimeExpired = pObj->GetCreationTime() + 2 * nSuperblockCycleSeconds + GOVERNANCE_DELETION_DELAY;
            }

            mapErasedGovernanceObjects.insert(std::make_pair(nHash, nTimeExpired));
            RemoveObjectFromGovernanceVoteIndexes(nHash, *pObj);
            m_persisted_vote_bytes -= std::min<uint64_t>(
                m_persisted_vote_bytes,
                pObj->GetVoteFile().GetSerializedVoteBytes());
            mapTrigger.erase(nHash);
            m_pq_inactive_triggers.erase(nHash);
            InvalidateObjectPageCache();
            mapObjects.erase(it++);
        } else {
            if (pObj->GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
                CProposalValidator validator(pObj->GetDataAsHexString());
                if (!validator.Validate()) {
                    LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdateCachesAndClean -- set for deletion expired obj %s\n", strHash);
                    pObj->PrepareDeletion(nNow);
                    InvalidateObjectPageCache();
                }
            }
            ++it;
        }
    }

    // forget about expired deleted objects
    auto s_it = mapErasedGovernanceObjects.begin();
    while (s_it != mapErasedGovernanceObjects.end()) {
        if (s_it->second < nNow) {
            mapErasedGovernanceObjects.erase(s_it++);
        } else {
            ++s_it;
        }
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdateCachesAndClean -- %s\n", ToString());
}

const CGovernanceObject* CGovernanceManager::FindConstGovernanceObject(const uint256& nHash) const
{
    LOCK(cs);
    if (!IsReady() && !m_rebuilding_cached_triggers) return nullptr;
    if (!m_rebuilding_cached_triggers &&
        m_pq_inactive_triggers.contains(nHash)) {
        return nullptr;
    }

    auto it = mapObjects.find(nHash);
    if (it != mapObjects.end()) return &(it->second);

    return nullptr;
}

CGovernanceObject* CGovernanceManager::FindGovernanceObject(const uint256& nHash)
{
    LOCK(cs);
    if (!IsReady() && !m_rebuilding_cached_triggers) return nullptr;
    if (!m_rebuilding_cached_triggers &&
        m_pq_inactive_triggers.contains(nHash)) {
        return nullptr;
    }

    if (mapObjects.count(nHash)) return &mapObjects[nHash];

    return nullptr;
}

CGovernanceObject* CGovernanceManager::FindGovernanceObjectByDataHash(const uint256 &nDataHash)
{
    LOCK(cs);
    if (!IsReady()) return nullptr;

    for (const auto& [nHash, object] : mapObjects) {
        if (!object.IsSetCachedDelete() && !object.IsSetExpired() &&
            mapTrigger.contains(nHash) &&
            !m_pq_inactive_triggers.contains(nHash) &&
            object.GetDataHash() == nDataHash) {
            return &mapObjects[nHash];
        }
    }

    return nullptr;
}

void CGovernanceManager::DeleteGovernanceObject(const uint256& nHash)
{
    LOCK(cs);

    if (const auto it{mapObjects.find(nHash)}; it != mapObjects.end()) {
        RemoveObjectFromGovernanceVoteIndexes(nHash, it->second);
        m_persisted_vote_bytes -= std::min<uint64_t>(
            m_persisted_vote_bytes,
            it->second.GetVoteFile().GetSerializedVoteBytes());
        mapObjects.erase(it);
    }
    mapTrigger.erase(nHash);
    m_pq_inactive_triggers.erase(nHash);
    InvalidateObjectPageCache();
}

std::vector<CGovernanceVote> CGovernanceManager::GetCurrentVotes(const uint256& nParentHash, const COutPoint& mnCollateralOutpointFilter) const
{
    std::vector<CGovernanceVote> vecResult;
    LOCK2(chainman.GetMutex(), cs);
    const CBlockIndex* validation_tip{chainman.ActiveTip()};
    if (!IsReadyForTip(validation_tip)) return vecResult;
    if (m_pq_inactive_triggers.contains(nParentHash)) return vecResult;

    // Find the governance object or short-circuit.
    auto it = mapObjects.find(nParentHash);
    if (it == mapObjects.end()) return vecResult;
    const CGovernanceObject& govobj = it->second;

    const auto tip_mn_list{
        deterministicMNManager->GetListForBlock(validation_tip)};
    std::map<COutPoint, CDeterministicMNCPtr> mapMasternodes;
    if (mnCollateralOutpointFilter.IsNull()) {
        tip_mn_list.ForEachMNShared(false, [&](const CDeterministicMNCPtr& dmn) {
            mapMasternodes.emplace(dmn->collateralOutpoint, dmn);
        });
    } else {
        auto dmn = tip_mn_list.GetMNByCollateral(mnCollateralOutpointFilter);
        if (dmn) {
            mapMasternodes.emplace(dmn->collateralOutpoint, dmn);
        }
    }

    // Loop through each MN collateral outpoint and get the votes for the `nParentHash` governance object
    for (const auto& mnpair : mapMasternodes) {
        // get a vote_rec_t from the govobj
        vote_rec_t voteRecord;
        if (!govobj.GetCurrentMNVotes(mnpair.first, voteRecord)) continue;

        for (const auto& voteInstancePair : voteRecord.mapInstances) {
            int signal = voteInstancePair.first;
            int outcome = voteInstancePair.second.eOutcome;
            int64_t nCreationTime = voteInstancePair.second.nCreationTime;

            CGovernanceVote vote = CGovernanceVote(mnpair.first, nParentHash, (vote_signal_enum_t)signal, (vote_outcome_enum_t)outcome);
            vote.SetTime(nCreationTime);

            vecResult.push_back(vote);
        }
    }

    return vecResult;
}

void CGovernanceManager::GetAllNewerThan(std::vector<CGovernanceObject>& objs, int64_t nMoreThanTime) const
{
    LOCK2(chainman.GetMutex(), cs);
    if (!IsReadyForTip(chainman.ActiveTip())) return;

    for (const auto& objPair : mapObjects) {
        if (m_pq_inactive_triggers.contains(objPair.first)) continue;
        // IF THIS OBJECT IS OLDER THAN TIME, CONTINUE
        if (objPair.second.GetCreationTime() < nMoreThanTime) {
            continue;
        }

        // ADD GOVERNANCE OBJECT TO LIST
        objs.push_back(objPair.second);
    }
}


std::optional<const CSuperblock> CGovernanceManager::CreateSuperblockCandidate(const CBlockIndex* pindex) const
{
    AssertLockNotHeld(cs);
    const int nHeight = pindex->nHeight;
    if (!IsReady()) return std::nullopt;
    if (!masternodeSync.IsSynced()) return std::nullopt;
    if (nHeight % Params().GetConsensus().SuperBlockCycle(nHeight) < Params().GetConsensus().SuperBlockCycle(nHeight) - Params().GetConsensus().nSuperblockMaturityWindow) return std::nullopt;

    // Use std::vector of std::shared_ptr<const CGovernanceObject> because CGovernanceObject doesn't support move operations (needed for sorting the vector later)
    std::vector<std::shared_ptr<const CGovernanceObject>> approvedProposals;

    {
        LOCK2(chainman.GetMutex(), cs);
        if (chainman.ActiveTip() != pindex ||
            !IsReadyForTip(pindex) ||
            HasAlreadyVotedFundingTrigger()) {
            return std::nullopt;
        }
        // A proposal is considered passing if (YES votes) >= (Total Weight
        // of Masternodes / 10), using the exact readiness-bound roster.
        const auto tip_mn_list{
            deterministicMNManager->GetListForBlock(pindex)};
        const int nWeightedMnCount{
            static_cast<int>(tip_mn_list.GetValidMNsCount())};
        const int nAbsVoteReq{std::max(
            Params().GetConsensus().nGovernanceMinQuorum,
            nWeightedMnCount / 10)};
        for (const auto& [unused, object] : mapObjects) {
            // Skip all non-proposals objects
            if (object.GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) continue;

            const int absYesCount = object.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
            // Skip non-passing proposals
            if (absYesCount < nAbsVoteReq) continue;

            approvedProposals.emplace_back(std::make_shared<const CGovernanceObject>(object));
        }
    } // cs
    // Sort approved proposals by absolute Yes votes descending
    std::sort(approvedProposals.begin(), approvedProposals.end(), [](std::shared_ptr<const CGovernanceObject> a, std::shared_ptr<const CGovernanceObject> b) {
        const auto a_yes = a->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
        const auto b_yes = b->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
        return a_yes == b_yes ? UintToArith256(a->GetHash()) > UintToArith256(b->GetHash()) : a_yes > b_yes;
    });

    if (approvedProposals.empty()) {
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s nHeight:%d empty approvedProposals\n", __func__, nHeight);
        return std::nullopt;
    }
    std::vector<CGovernancePayment> payments;
    int nLastSuperblock;
    int nNextSuperblock;
    CSuperblock::GetNearestSuperblocksHeights(nHeight, nLastSuperblock, nNextSuperblock);
    const CBlockIndex* nLastSBIndex = pindex->GetAncestor(nLastSuperblock);
    auto SBEpochTime = static_cast<int64_t>(GetTime<std::chrono::seconds>().count() + (nNextSuperblock - nHeight) * 2.5 * 60);
    // fund up to the next limit which is governed by IsBlockValueValid block validation
    CAmount nGovernanceBudgetUp   = (CSuperblock::GetPaymentsLimit(nLastSBIndex) * CSuperblock::SHIFT_UP)   / CSuperblock::SHIFT;
    if (nGovernanceBudgetUp > CSuperblock::SUPERBLOCK_BUDGET_MAX) {
        nGovernanceBudgetUp = CSuperblock::SUPERBLOCK_BUDGET_MAX;
    }
    CAmount budgetAllocated{};
    for (const auto& proposal : approvedProposals) {
        // Extract payment address and amount from proposal
        UniValue jproposal = proposal->GetJSONObject();

        CTxDestination dest = DecodeDestination(jproposal["payment_address"].getValStr());
        if (!IsValidDestination(dest)) continue;

        CAmount nAmount{};
        try {
            nAmount = ParsePaymentAmount(jproposal["payment_amount"].getValStr());
        }
        catch (const std::runtime_error& e) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s nHeight:%d Skipping payment exception:%s\n", __func__, nHeight, e.what());
            continue;
        }

        // Construct CGovernancePayment object and make sure it is valid
        CGovernancePayment payment(dest, nAmount, proposal->GetHash());
        if (!payment.IsValid()) continue;

        // Skip proposals that are too expensive
        if (budgetAllocated + payment.nAmount > nGovernanceBudgetUp) continue;

        int64_t windowStart = jproposal["start_epoch"].getInt<int64_t>() - GOVERNANCE_FUDGE_WINDOW;
        int64_t windowEnd = jproposal["end_epoch"].getInt<int64_t>() + GOVERNANCE_FUDGE_WINDOW;

        // Skip proposals if the SB isn't within the proposal time window
        if (SBEpochTime < windowStart) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s nHeight:%d SB:%d windowStart:%d\n", __func__,nHeight, SBEpochTime, windowStart);
            continue;
        }
        if (SBEpochTime > windowEnd) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s nHeight:%d SB:%d windowEnd:%d\n", __func__,nHeight, SBEpochTime, windowEnd);
            continue;
        }

        // Keep track of total budget allocation
        budgetAllocated += payment.nAmount;

        // Add the payment
        payments.push_back(payment);
    }

    // No proposals made the cut
    if (payments.empty()) {
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s CreateSuperblockCandidate nHeight:%d empty payments\n", __func__, nHeight);
        return std::nullopt;
    }
    // Sort by proposal hash descending
    std::sort(payments.begin(), payments.end(), [](const CGovernancePayment& a, const CGovernancePayment& b) {
        return UintToArith256(a.proposalHash) > UintToArith256(b.proposalHash);
    });

    // Create Superblock
    return CSuperblock(nNextSuperblock, std::move(payments));
}

std::optional<const CGovernanceObject> CGovernanceManager::CreateGovernanceTrigger(
    const std::optional<const CSuperblock>& sb_opt,
    const CBlockIndex* expected_tip, PeerManager& peerman)
{
    if (!IsReady()) return std::nullopt;
    // no sb_opt, no trigger
    if (!sb_opt.has_value()) return std::nullopt;
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    //TODO: Check if nHashParentIn, nRevision and nCollateralHashIn are correct
    CGovernanceObject gov_sb(uint256(), 1, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()), uint256(), sb_opt.value().GetHexStrData());

    const CBlockIndex* validation_tip{nullptr};
    const CBlockIndex* signing_block{nullptr};
    CDeterministicMNList validation_mn_list;
    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    {
        LOCK2(cs_main, cs);
        validation_tip = chainman.ActiveTip();
        if (validation_tip != expected_tip ||
            !IsReadyForTip(validation_tip)) {
            return std::nullopt;
        }

        // Check if identical trigger (equal DataHash()) is already created (signed by other masternode)
        if (auto identical_sb = FindGovernanceObjectByDataHash(gov_sb.GetDataHash())) {
            // Somebody submitted a trigger with the same data, support it instead of submitting a duplicate
            return std::make_optional<CGovernanceObject>(*identical_sb);
        }

        // Nobody submitted a trigger we'd like to see, so let's do it but only if we are the payee
        validation_mn_list =
            deterministicMNManager->GetListForBlock(validation_tip);
        CDeterministicMNCPtr next_payee;
        if (!deterministicMNManager->GetMNPayeeForBlock(
                validation_tip, next_payee)) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s payment eligibility state is unavailable\n",
                     __func__);
            return std::nullopt;
        }

        if (!next_payee) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s payee list is empty\n", __func__);
            return std::nullopt;
        }

        llmq::pq::GlobalPublicKey global_public_key;
        CService local_service;
        if (!GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                         global_public_key, local_service) ||
            next_payee->proTxHash != local_pro_tx_hash) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s we are not the payee, skipping\n", __func__);
            return std::nullopt;
        }

        signing_block = GetGovernanceSigningBlock(validation_tip);
        const auto local_dmn{
            validation_mn_list.GetMN(local_pro_tx_hash)};
        if (signing_block == nullptr || !local_dmn) return std::nullopt;
        gov_sb.SetMasternodeOutpoint(local_dmn->collateralOutpoint);
    }

    // SYSCOIN: reconstructing/signing with SLH and verifying the result are
    // deliberately outside chain, governance, and governance-object locks.
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!gov_sb.SignPQ(*signing_block, local_pro_tx_hash,
                       global_key_version)) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s failed to sign PQ trigger\n",
                 __func__);
        return std::nullopt;
    }
    std::string signature_error;
    if (!VerifyTriggerObjectUnlocked(
            gov_sb, *validation_tip, validation_mn_list,
            signature_error)) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s Created trigger has invalid PQ authorization: %s\n",
                 __func__, signature_error);
        return std::nullopt;
    }

    {
        LOCK2(cs_main, cs);
        if (chainman.ActiveTip() != validation_tip ||
            !IsReadyForTip(validation_tip)) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s chain tip changed while signing trigger\n",
                     __func__);
            return std::nullopt;
        }
        if (auto identical_sb =
                FindGovernanceObjectByDataHash(gov_sb.GetDataHash())) {
            return std::make_optional<CGovernanceObject>(*identical_sb);
        }

        // SYSCOIN: only cheap authorization context is repeated while the
        // exact verified tip is locked for commit.
        if (std::string strError;
            !gov_sb.IsValidLocally(chainman, validation_mn_list, strError,
                                   /*fCheckCollateral=*/true,
                                   /*fPQSignaturePreverified=*/true)) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s Created trigger is invalid: %s\n",
                     __func__, strError);
            return std::nullopt;
        }
        if (!MasternodeRateCheck(gov_sb)) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s Trigger rate check failed hash=%s\n",
                     __func__, gov_sb.GetHash().ToString());
            return std::nullopt;
        }
    }
    // SYSCOIN: Add rebinds the preverified authorization to this exact tip;
    // orphan processing cannot inherit any construction lock.
    const uint256 trigger_hash{gov_sb.GetHash()};
    const auto admission{AddGovernanceObject(
        gov_sb, peerman, /*pfrom=*/nullptr,
        /*expected_tip=*/validation_tip,
        /*pq_preverified_tip=*/validation_tip)};
    if (admission != GovernanceObjectAdmissionResult::ACCEPTED &&
        admission != GovernanceObjectAdmissionResult::DUPLICATE) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s trigger admission failed: %s\n",
                 __func__, GovernanceObjectAdmissionError(admission));
        return std::nullopt;
    }
    // SYSCOIN: AddGovernanceObject moves the candidate into mapObjects. Return
    // the committed object rather than the moved-from local value.
    LOCK(cs);
    const auto committed{mapObjects.find(trigger_hash)};
    if (committed == mapObjects.end()) return std::nullopt;
    return std::make_optional<CGovernanceObject>(committed->second);
}

void CGovernanceManager::VoteGovernanceTriggers(const std::optional<const CGovernanceObject>& trigger_opt, CConnman& connman, PeerManager& peerman)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) return;

    // only active masternodes can vote on triggers
    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    llmq::pq::GlobalPublicKey global_public_key;
    CService local_service;
    if (!GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                     global_public_key, local_service)) {
        return;
    }
    std::optional<uint256> yes_hash;
    std::vector<uint256> no_hashes;
    {
        LOCK2(chainman.GetMutex(), cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return;
        if (trigger_opt.has_value()) {
            const uint256 candidate_hash{trigger_opt->GetHash()};
            const auto object_it{mapObjects.find(candidate_hash)};
            const auto trigger_it{mapTrigger.find(candidate_hash)};
            if (object_it == mapObjects.end() ||
                object_it->second.IsSetCachedDelete() ||
                object_it->second.IsSetExpired() ||
                m_pq_inactive_triggers.contains(candidate_hash) ||
                trigger_it == mapTrigger.end() ||
                trigger_it->second->GetBlockHeight() <=
                    validation_tip->nHeight) {
                return;
            }
            // SYSCOIN: reserve the sole YES vote before releasing the manager
            // lock so concurrent maintenance cannot create a second one.
            assert(!votedFundingYesTriggerHash.has_value());
            yes_hash = candidate_hash;
            votedFundingYesTriggerHash = *yes_hash;
        }

        no_hashes = GetNoFundingTriggerHashes();
    }

    if (yes_hash) {
        if (!VoteFundingTrigger(*yes_hash, VOTE_OUTCOME_YES, connman,
                                peerman)) {
            LOCK(cs);
            if (votedFundingYesTriggerHash == yes_hash) {
                votedFundingYesTriggerHash.reset();
            }
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s Voting YES-FUNDING for new trigger:%s failed\n", __func__, yes_hash->ToString());
            return;
        }
        const uint256& gov_sb_hash{*yes_hash};
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s Voting YES-FUNDING for new trigger:%s success\n", __func__, gov_sb_hash.ToString());
    }

    // Vote NO-FUNDING for the rest of the active triggers
    for (const uint256& trigger_hash : no_hashes) {
        if (!VoteFundingTrigger(trigger_hash, VOTE_OUTCOME_NO, connman, peerman)) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s Voting NO-FUNDING for trigger:%s failed\n", __func__, trigger_hash.ToString());
            // failing here is ok-ish
            continue;
        }
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s Voting NO-FUNDING for trigger:%s success\n", __func__, trigger_hash.ToString());
    }
}

std::vector<uint256> CGovernanceManager::GetNoFundingTriggerHashes() const
{
    AssertLockHeld(cs);
    std::vector<uint256> no_hashes;
    no_hashes.reserve(mapTrigger.size());
    for (const auto& [trigger_hash, trigger] : mapTrigger) {
        if (!mapObjects.contains(trigger_hash)) continue;
        if (m_pq_inactive_triggers.contains(trigger_hash)) continue;
        if (trigger->GetBlockHeight() <= GetCachedBlockHeight()) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s Not voting NO-FUNDING for outdated trigger:%s\n",
                     __func__, trigger_hash.ToString());
            continue;
        }
        if (votedFundingYesTriggerHash &&
            trigger_hash == *votedFundingYesTriggerHash) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s Not voting NO-FUNDING for "
                     "trigger:%s, we voted yes for it already\n",
                     __func__, trigger_hash.ToString());
            continue;
        }
        no_hashes.push_back(trigger_hash);
    }
    return no_hashes;
}

bool CGovernanceManager::VoteFundingTrigger(const uint256& nHash, const vote_outcome_enum_t outcome, CConnman& connman, PeerManager& peerman)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) return false;

    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    llmq::pq::GlobalPublicKey global_public_key;
    CService local_service;
    if (!GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                     global_public_key, local_service)) {
        return false;
    }
    const CBlockIndex* signing_tip{nullptr};
    CDeterministicMNList signing_mn_list;
    COutPoint local_outpoint;
    {
        LOCK2(cs_main, cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return false;
        const auto object_it{mapObjects.find(nHash)};
        const auto trigger_it{mapTrigger.find(nHash)};
        if (validation_tip == nullptr || object_it == mapObjects.end() ||
            object_it->second.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER ||
            object_it->second.IsSetCachedDelete() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(nHash) ||
            trigger_it == mapTrigger.end() ||
            trigger_it->second->GetBlockHeight() <=
                validation_tip->nHeight) {
            return false;
        }
        signing_tip = GetGovernanceSigningBlock(validation_tip);
        if (signing_tip == nullptr) return false;
        signing_mn_list =
            deterministicMNManager->GetListForBlock(signing_tip);
        const auto local_dmn{
            signing_mn_list.GetMN(local_pro_tx_hash)};
        if (!local_dmn) return false;
        local_outpoint = local_dmn->collateralOutpoint;
    }

    CGovernanceVote vote(local_outpoint, nHash,
                         VOTE_SIGNAL_FUNDING, outcome);
    vote.SetTime(TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
    // SYSCOIN: local signing and ProcessVote's full verification must not
    // inherit the trigger-selection locks above.
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!vote.SignPQ(*signing_tip, local_pro_tx_hash,
                     global_key_version,
                     llmq::pq::GovernanceAuthPurpose::TRIGGER_VOTE)) {
        return false;
    }

    CGovernanceException exception;
    if (!ProcessVoteAndRelay(vote, signing_mn_list, exception, connman,
                             peerman)) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s Vote FUNDING %d for trigger %s "
                 "failed: %s\n",
                 __func__, outcome, nHash.ToString(), exception.what());
        return false;
    }
    return true;
}

bool CGovernanceManager::HasAlreadyVotedFundingTrigger() const
{
    LOCK(cs);
    return votedFundingYesTriggerHash.has_value();
}

void CGovernanceManager::ResetVotedFundingTrigger()
{
    LOCK(cs);
    votedFundingYesTriggerHash = std::nullopt;
}

void CGovernanceManager::DoMaintenance(CConnman& connman)
{
    if (!IsReady()) return;
    if (!masternodeSync.IsSynced()) return;
    if (ShutdownRequested()) return;

    // CHECK OBJECTS WE'VE ASKED FOR, REMOVE OLD ENTRIES
    CleanOrphanObjects();
    RequestOrphanObjects(connman);

    // CHECK AND REMOVE - REPROCESS GOVERNANCE OBJECTS
    CheckAndRemove();
}

void CGovernanceManager::SyncSingleObjVotes(CNode* pnode, const uint256& nProp, const CBloomFilter& filter, CConnman& connman, PeerManager& peerman)
{
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) return;

    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    int nVoteCount = 0;
    const CBlockIndex* validation_tip{nullptr};
    CDeterministicMNList validation_mn_list;
    std::vector<CGovernanceVote> candidates;
    int object_type{GOVERNANCE_OBJECT_UNKNOWN};

    // SYNC GOVERNANCE OBJECTS WITH OTHER CLIENT

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- syncing single object to peer=%d, nProp = %s\n", __func__, nProp.ToString(), pnode->GetId());
    {
        LOCK(cs);
        const auto it = mapObjects.find(nProp);
        if (it == mapObjects.end()) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- no matching object for hash %s, peer=%d\n", __func__, nProp.ToString(), pnode->GetId());
            return;
        }
        const CGovernanceObject& govobj = it->second;
        if (m_pq_inactive_triggers.contains(nProp)) return;
        std::string strHash = it->first.ToString();

        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- attempting to sync govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());

        if (govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- not syncing deleted/expired govobj: %s, peer=%d\n", __func__,
                strHash, pnode->GetId());
            return;
        }
        object_type = govobj.GetObjectType();
    }

    // Snapshot at most one delegated funding vote per valid masternode and a
    // fixed number of operator votes. SLH work runs only after locks release.
    {
        LOCK2(chainman.GetMutex(), cs);
        validation_tip = chainman.ActiveTip();
        if (!IsReadyForTip(validation_tip)) return;
        const auto object_it{mapObjects.find(nProp)};
        if (object_it == mapObjects.end() ||
            object_it->second.IsSetCachedDelete() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(nProp) ||
            object_it->second.GetObjectType() != object_type) {
            return;
        }

        validation_mn_list =
            deterministicMNManager->GetListForBlock(validation_tip);
        const std::size_t max_delegated_votes{
            validation_mn_list.GetValidMNsCount()};
        std::size_t delegated_votes{0};
        std::size_t operator_votes{0};
        object_it->second.GetVoteFile().ForEachVote(
            [&](const CGovernanceVote& vote) {
                const bool requires_operator{
                    GetGovernanceVoteAuthPurpose(
                        object_type, vote.GetSignal())
                        .has_value()};
                if (!filter.contains(vote.GetHash())) {
                    if (requires_operator &&
                        operator_votes <
                            GovernanceVoteSyncRateLimiter::
                                MAX_VERIFICATIONS_PER_REQUEST) {
                        candidates.push_back(vote);
                        ++operator_votes;
                    } else if (!requires_operator &&
                               delegated_votes < max_delegated_votes) {
                        candidates.push_back(vote);
                        ++delegated_votes;
                    }
                }
                return operator_votes <
                           GovernanceVoteSyncRateLimiter::
                               MAX_VERIFICATIONS_PER_REQUEST ||
                       delegated_votes < max_delegated_votes;
            });
    }

    const bool has_operator_votes{std::any_of(
        candidates.begin(), candidates.end(), [&](const auto& vote) {
            return GetGovernanceVoteAuthPurpose(
                       object_type, vote.GetSignal())
                .has_value();
        })};
    bool operator_votes_admitted{!has_operator_votes};
    if (has_operator_votes) {
        const uint256 authenticated_pro_tx{
            pnode->GetVerifiedProRegTxHash()};
        const uint64_t keyed_net_group{pnode->nKeyedNetGroup};
        // SYSCOIN: the non-recursive limiter mutex is scoped only around its
        // small in-memory token table; SLH work never inherits it.
        UniqueLock rate_lock{m_vote_sync_rate_mutex,
                             "m_vote_sync_rate_mutex", __FILE__, __LINE__};
        operator_votes_admitted = m_vote_sync_rate.Consume(
            pnode->GetId(), authenticated_pro_tx, keyed_net_group,
            GetTime<std::chrono::microseconds>());
    }
    if (!operator_votes_admitted) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s -- rate limited operator-vote sync from peer=%d, object=%s\n",
                 __func__, pnode->GetId(), nProp.ToString());
        // CGovernanceVote caches its hash in a const member and is therefore
        // deliberately non-assignable; vector erase/compaction is invalid.
        std::vector<CGovernanceVote> delegated_candidates;
        delegated_candidates.reserve(candidates.size());
        for (const auto& vote : candidates) {
            if (!GetGovernanceVoteAuthPurpose(
                     object_type, vote.GetSignal())) {
                delegated_candidates.push_back(vote);
            }
        }
        candidates.swap(delegated_candidates);
    }

    std::vector<CGovernanceVote> verified_votes;
    verified_votes.reserve(candidates.size());
    for (const auto& vote : candidates) {
        bool valid{false};
        const auto pq_purpose{GetGovernanceVoteAuthPurpose(
            object_type, vote.GetSignal())};
        if (pq_purpose) {
            // SYSCOIN: never hold chain/governance/object locks across SLH.
            AssertLockNotHeld(cs_main);
            AssertLockNotHeld(cs);
            std::string signature_error;
            valid = VerifyPQVoteUnlocked(
                vote, *validation_tip, validation_mn_list,
                *pq_purpose, signature_error);
        } else {
            valid = vote.IsValid(validation_mn_list);
        }
        if (valid) verified_votes.push_back(vote);
    }

    std::vector<uint256> relay_hashes;
    if (!verified_votes.empty()) {
        std::map<uint256, const CGovernanceVote*> verified_by_hash;
        for (const auto& vote : verified_votes) {
            verified_by_hash.emplace(vote.GetHash(), &vote);
        }
        LOCK2(chainman.GetMutex(), cs);
        if (chainman.ActiveTip() != validation_tip ||
            !IsReadyForTip(validation_tip)) return;
        const auto object_it{mapObjects.find(nProp)};
        if (object_it == mapObjects.end() ||
            object_it->second.IsSetCachedDelete() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(nProp) ||
            object_it->second.GetObjectType() != object_type) {
            return;
        }
        object_it->second.GetVoteFile().ForEachVote(
            [&](const CGovernanceVote& current) {
                const auto verified{verified_by_hash.find(current.GetHash())};
                if (verified != verified_by_hash.end() &&
                    current == *verified->second &&
                    current.vchSig == verified->second->vchSig &&
                    !filter.contains(current.GetHash())) {
                    relay_hashes.push_back(current.GetHash());
                    verified_by_hash.erase(verified);
                }
                return !verified_by_hash.empty();
            });
    }

    const PeerRef peer{peerman.GetPeerRef(pnode->GetId())};
    if (peer) {
        LOCK2(chainman.GetMutex(), cs);
        if (chainman.ActiveTip() != validation_tip ||
            !IsReadyForTip(validation_tip)) {
            return;
        }
        const auto object_it{mapObjects.find(nProp)};
        if (object_it == mapObjects.end() ||
            object_it->second.IsSetCachedDelete() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(nProp) ||
            object_it->second.GetObjectType() != object_type) {
            return;
        }
        for (const uint256& hash : relay_hashes) {
            if (!object_it->second.GetVoteFile().HasVote(hash)) continue;
            peerman.PushTxInventoryOther(
                *peer, CInv(MSG_GOVERNANCE_OBJECT_VOTE, hash));
            ++nVoteCount;
        }
    }

    CNetMsgMaker msgMaker(pnode->GetCommonVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ_VOTE, nVoteCount));
    LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- sent %d votes to peer=%d\n", __func__, nVoteCount, pnode->GetId());
}

void CGovernanceManager::SyncObjects(CNode* pnode, CConnman& connman, PeerManager& peerman) const
{
    if (!IsReady()) return;
    if (!masternodeSync.IsSynced()) return;
    PeerRef peer = peerman.GetPeerRef(pnode->GetId());
    if (netfulfilledman->HasFulfilledRequest(pnode->addr, NetMsgType::MNGOVERNANCESYNC)) {
        // Asking for the whole list multiple times in a short period of time is no good
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- peer already asked me for the list\n", __func__);
        if(peer)
            peerman.Misbehaving(*peer, 20, "peer already asked for list");
        return;
    }
    netfulfilledman->AddFulfilledRequest(pnode->addr, NetMsgType::MNGOVERNANCESYNC);

    int nObjCount = 0;

    // SYNC GOVERNANCE OBJECTS WITH OTHER CLIENT

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- syncing all objects to peer=%d\n", __func__, pnode->GetId());
    {
        LOCK2(cs_main, cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return;

        // all valid objects, no votes
        for (const auto& objPair : mapObjects) {
            uint256 nHash = objPair.first;
            const CGovernanceObject& govobj = objPair.second;
            std::string strHash = nHash.ToString();

            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- attempting to sync govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());

            if (govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
                LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- not syncing deleted/expired govobj: %s, peer=%d\n", __func__,
                    strHash, pnode->GetId());
                continue;
            }
            if (m_pq_inactive_triggers.contains(nHash)) continue;

            // Push the inventory budget proposal message over to the other client
            LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- syncing govobj: %s, peer=%d\n", __func__, strHash, pnode->GetId());
            if(peer) {
                peerman.PushTxInventoryOther(*peer, CInv(MSG_GOVERNANCE_OBJECT, nHash));
            }
            ++nObjCount;
        }
    }

    CNetMsgMaker msgMaker(pnode->GetCommonVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ, nObjCount));
    LogPrint(BCLog::GOBJECT, "CGovernanceManager::%s -- sent %d objects to peer=%d\n", __func__, nObjCount, pnode->GetId());
}

void CGovernanceManager::MasternodeRateUpdate(const CGovernanceObject& govobj)
{
    if (govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) return;

    const COutPoint& masternodeOutpoint = govobj.GetMasternodeOutpoint();
    auto it = mapLastMasternodeObject.find(masternodeOutpoint);

    if (it == mapLastMasternodeObject.end()) {
        it = mapLastMasternodeObject.insert(txout_m_t::value_type(masternodeOutpoint, last_object_rec(true))).first;
    }

    int64_t nTimestamp = govobj.GetCreationTime();
    it->second.triggerBuffer.AddTimestamp(nTimestamp);

    if (nTimestamp > GetTime() + MAX_TIME_FUTURE_DEVIATION - RELIABLE_PROPAGATION_TIME) {
        // schedule additional relay for the object
        setAdditionalRelayObjects.insert(govobj.GetHash());
    }

    it->second.fStatusOK = true;
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus)
{
    bool fRateCheckBypassed;
    return MasternodeRateCheck(govobj, fUpdateFailStatus, true, fRateCheckBypassed);
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus, bool fForce, bool& fRateCheckBypassed)
{
    int nHeight = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight());
    LOCK(cs);

    fRateCheckBypassed = false;

    if (!masternodeSync.IsSynced() || !fRateChecksEnabled) {
        return true;
    }

    if (govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) {
        return true;
    }

    const COutPoint& masternodeOutpoint = govobj.GetMasternodeOutpoint();
    int64_t nTimestamp = govobj.GetCreationTime();
    int64_t nNow = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    int64_t nSuperblockCycleSeconds = Params().GetConsensus().SuperBlockCycle(nHeight) * Params().GetConsensus().PowTargetSpacing(nHeight);

    std::string strHash = govobj.GetHash().ToString();

    if (nTimestamp < nNow - 2 * nSuperblockCycleSeconds) {
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too old timestamp, masternode = %s, timestamp = %d, current time = %d\n",
            strHash, masternodeOutpoint.ToStringShort(), nTimestamp, nNow);
        return false;
    }

    if (nTimestamp > nNow + MAX_TIME_FUTURE_DEVIATION) {
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too new (future) timestamp, masternode = %s, timestamp = %d, current time = %d\n",
            strHash, masternodeOutpoint.ToStringShort(), nTimestamp, nNow);
        return false;
    }

    auto it = mapLastMasternodeObject.find(masternodeOutpoint);
    if (it == mapLastMasternodeObject.end()) return true;

    if (it->second.fStatusOK && !fForce) {
        fRateCheckBypassed = true;
        return true;
    }

    // Allow 1 trigger per mn per cycle, with a small fudge factor
    double dMaxRate = 2 * 1.1 / double(nSuperblockCycleSeconds);

    // Temporary copy to check rate after new timestamp is added
    CRateCheckBuffer buffer = it->second.triggerBuffer;

    buffer.AddTimestamp(nTimestamp);
    double dRate = buffer.GetRate();

    if (dRate < dMaxRate) {
        return true;
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::MasternodeRateCheck -- Rate too high: object hash = %s, masternode = %s, object timestamp = %d, rate = %f, max rate = %f\n",
        strHash, masternodeOutpoint.ToStringShort(), nTimestamp, dRate, dMaxRate);

    if (fUpdateFailStatus) {
        it->second.fStatusOK = false;
    }

    return false;
}

bool CGovernanceManager::ProcessVoteAndRelay(const CGovernanceVote& vote, const CDeterministicMNList&, CGovernanceException& exception, CConnman& connman, PeerManager& peerman)
{
    // SYSCOIN: trigger authorization may enter SLH verification below.
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) return false;
    if (!ProcessVote(/* pfrom = */ nullptr, vote, exception, connman)) {
        return false;
    }

    LOCK2(chainman.GetMutex(), cs);
    const CBlockIndex* relay_tip{chainman.ActiveTip()};
    if (!IsReadyForTip(relay_tip)) return false;
    CGovernanceObject* relayed_object{nullptr};
    if (!cmapVoteToObject.Get(vote.GetHash(), relayed_object) ||
        relayed_object == nullptr ||
        m_pq_inactive_triggers.contains(relayed_object->GetHash()) ||
        !relayed_object->GetVoteFile().HasVote(vote.GetHash())) {
        return false;
    }
    const auto relay_mn_list{
        deterministicMNManager->GetListForBlock(relay_tip)};
    vote.Relay(peerman, relay_mn_list);
    return true;
}

// SYSCOIN: bound unauthenticated orphan state independently of cache policy.
bool CGovernanceManager::StoreOrphanVote(
    const uint256& object_hash, const vote_time_pair_t& vote_pair)
{
    AssertLockHeld(cs);
    std::vector<vote_time_pair_t> existing;
    cmmapOrphanVotes.GetAll(object_hash, existing);
    std::vector<vote_time_pair_t> equivalent;
    uint64_t replaced_bytes{0};
    int64_t refreshed_expiry{vote_pair.second};
    for (const auto& retained : existing) {
        if (!(retained.first == vote_pair.first)) continue;
        const uint64_t bytes{PersistedVoteBytes(retained.first)};
        if (bytes > std::numeric_limits<uint64_t>::max() -
                        replaced_bytes) {
            throw std::logic_error(
                "orphan governance vote byte accounting overflow");
        }
        replaced_bytes += bytes;
        refreshed_expiry = std::max(refreshed_expiry, retained.second);
        equivalent.push_back(retained);
    }
    if (!equivalent.empty()) {
        if (replaced_bytes > m_persisted_vote_bytes) {
            throw std::logic_error(
                "orphan governance vote byte accounting underflow");
        }
        const uint64_t retained_bytes{
            m_persisted_vote_bytes - replaced_bytes};
        const uint64_t replacement_bytes{
            PersistedVoteBytes(vote_pair.first)};
        if (replacement_bytes >
            MAX_PERSISTED_VOTE_BYTES - retained_bytes) {
            return false;
        }

        vote_time_pair_t replacement{vote_pair.first, refreshed_expiry};
        for (const auto& retained : equivalent) {
            cmmapOrphanVotes.Erase(object_hash, retained);
        }
        if (!cmmapOrphanVotes.Insert(object_hash, replacement)) {
            for (const auto& retained : equivalent) {
                if (!cmmapOrphanVotes.Insert(object_hash, retained)) {
                    throw std::logic_error(
                        "failed to restore retained orphan governance vote");
                }
            }
            return false;
        }
        m_persisted_vote_bytes = retained_bytes + replacement_bytes;
        return true;
    }
    if (cmmapOrphanVotes.GetSize() >= MAX_ORPHAN_VOTES) return false;
    if (existing.size() >= MAX_ORPHAN_VOTES_PER_OBJECT) return false;
    const uint64_t vote_bytes{PersistedVoteBytes(vote_pair.first)};
    if (m_persisted_vote_bytes > MAX_PERSISTED_VOTE_BYTES ||
        vote_bytes > MAX_PERSISTED_VOTE_BYTES -
                         m_persisted_vote_bytes) {
        return false;
    }
    if (!cmmapOrphanVotes.Insert(object_hash, vote_pair)) return false;
    m_persisted_vote_bytes += vote_bytes;
    return true;
}

bool CGovernanceManager::ProcessVote(
    CNode* pfrom, const CGovernanceVote& vote,
    CGovernanceException& exception, CConnman& connman,
    bool* orphan_vote_retained)
{
    if (orphan_vote_retained != nullptr) *orphan_vote_retained = false;
    // SYSCOIN: callers must not smuggle recursive global locks into the
    // two-phase operator-vote verifier.
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs);
    if (!IsReady()) {
        exception = CGovernanceException(
            "CGovernanceManager::ProcessVote -- governance authority state is not ready",
            GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
        return false;
    }

    const uint256 nHashVote = vote.GetHash();
    const uint256 nHashGovobj = vote.GetParentHash();
    const CBlockIndex* validation_tip{nullptr};
    CDeterministicMNList validation_mn_list;
    bool missing_parent{false};
    bool request_parent{false};
    int object_type{GOVERNANCE_OBJECT_UNKNOWN};
    std::optional<llmq::pq::GovernanceAuthPurpose> pq_purpose;
    bool orphan_signature_is_pq{false};

    {
        LOCK2(chainman.GetMutex(), cs);
        validation_tip = chainman.ActiveTip();
        if (!IsReadyForTip(validation_tip)) {
            exception = CGovernanceException(
                "CGovernanceManager::ProcessVote -- governance authority state changed",
                GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
            return false;
        }
        const auto it{mapObjects.find(nHashGovobj)};
        if (it != mapObjects.end() &&
            it->second.GetVoteFile().HasVote(nHashVote)) {
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceObject::ProcessVote -- skipping known valid vote %s for object %s\n",
                     nHashVote.ToString(), nHashGovobj.ToString());
            return false;
        }
        // This LRU is only a lookup hint. Replacement/removal happens in the
        // authoritative per-object vote file, so a stale hint must not block
        // re-admission of a vote that is no longer stored.
        if (cmapVoteToObject.HasKey(nHashVote)) {
            cmapVoteToObject.Erase(nHashVote);
        }
        if (it == mapObjects.end()) {
            validation_mn_list =
                deterministicMNManager->GetListForBlock(validation_tip);
            if (!vote.IsValidBasic(validation_mn_list) ||
                !IsPotentialOrphanGovernanceVoteAuthorization(
                    vote.GetSignal(), vote.GetSignatureSize())) {
                const std::string error{strprintf(
                    "CGovernanceManager::ProcessVote -- Invalid orphan vote fields, identity, or signature encoding for object %s",
                    nHashGovobj.ToString())};
                exception = CGovernanceException(
                    error, GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
                LogPrint(BCLog::GOBJECT, "%s\n", error);
                return false;
            }
            missing_parent = true;
            orphan_signature_is_pq =
                vote.GetSignatureSize() ==
                llmq::pq::GovernanceAuthorization::WIRE_SIZE;
        } else {
            CGovernanceObject& govobj{it->second};
            if (govobj.IsSetCachedDelete() || govobj.IsSetExpired()) {
                LogPrint(BCLog::GOBJECT,
                         "CGovernanceObject::ProcessVote -- ignoring vote for expired or deleted object, hash = %s\n",
                         nHashGovobj.ToString());
                return false;
            }

            object_type = govobj.GetObjectType();
            if (object_type == GOVERNANCE_OBJECT_TRIGGER) {
                const auto trigger_it{mapTrigger.find(nHashGovobj)};
                if (m_pq_inactive_triggers.contains(nHashGovobj) ||
                    trigger_it == mapTrigger.end() ||
                    trigger_it->second->GetBlockHeight() <=
                        chainman.ActiveHeight()) {
                    std::ostringstream ostr;
                    ostr << "CGovernanceManager::ProcessVote -- Trigger event height has passed"
                         << ", governance object hash = "
                         << nHashGovobj.ToString()
                         << ", current block height = "
                         << chainman.ActiveHeight();
                    LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
                    exception = CGovernanceException(
                        ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
                    return false;
                }
            }

            validation_mn_list =
                deterministicMNManager->GetListForBlock(validation_tip);
            pq_purpose = GetGovernanceVoteAuthPurpose(
                object_type, vote.GetSignal());
            if (!pq_purpose) {
                const bool accepted{
                    ProcessVoteWithBudget(
                        govobj, *validation_tip, validation_mn_list,
                        vote, exception,
                        /*pq_signature_preverified=*/false) &&
                    cmapVoteToObject.Insert(nHashVote, &govobj)};
                if (accepted) {
                    IndexGovernanceVote(
                        nHashGovobj, object_type, vote);
                }
                return accepted;
            }
        }
    }

    if (missing_parent) {
        // SYSCOIN: a vote hash excludes signature bytes. Verify the canonical
        // variant before storage so an invalid same-hash relay cannot occupy
        // the sole logical-vote slot and suppress a later valid response.
        static constexpr std::size_t MAX_ORPHAN_ADMISSION_ATTEMPTS{2};
        for (std::size_t attempt{0};
             attempt < MAX_ORPHAN_ADMISSION_ATTEMPTS; ++attempt) {
            std::string signature_error;
            const bool signature_valid{orphan_signature_is_pq
                ? VerifyOrphanPQVoteUnlocked(
                      vote, *validation_tip, validation_mn_list,
                      signature_error)
                : vote.IsValid(validation_mn_list)};
            if (!signature_valid) {
                const std::string error{strprintf(
                    "CGovernanceManager::ProcessVote -- Invalid orphan vote authorization for object %s%s%s",
                    nHashGovobj.ToString(),
                    signature_error.empty() ? "" : ": ",
                    signature_error)};
                bool stable_context{false};
                {
                    LOCK2(chainman.GetMutex(), cs);
                    stable_context =
                        chainman.ActiveTip() == validation_tip &&
                        IsReadyForTip(validation_tip);
                }
                if (!stable_context) {
                    if (attempt + 1 < MAX_ORPHAN_ADMISSION_ATTEMPTS) {
                        LOCK2(chainman.GetMutex(), cs);
                        validation_tip = chainman.ActiveTip();
                        if (!IsReadyForTip(validation_tip)) {
                            exception = CGovernanceException(
                                "CGovernanceManager::ProcessVote -- governance authority state changed",
                                GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
                            return false;
                        }
                        validation_mn_list =
                            deterministicMNManager->GetListForBlock(
                                validation_tip);
                        continue;
                    }
                    exception = CGovernanceException(
                        "CGovernanceManager::ProcessVote -- chain tip changed during orphan-vote verification",
                        GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
                    return false;
                }
                exception = CGovernanceException(
                    error, GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
                LogPrint(BCLog::GOBJECT, "%s\n", error);
                return false;
            }

            bool branch_changed{false};
            bool parent_arrived{false};
            {
                LOCK2(chainman.GetMutex(), cs);
                branch_changed = chainman.ActiveTip() != validation_tip;
                if (!branch_changed &&
                    !IsReadyForTip(validation_tip)) {
                    exception = CGovernanceException(
                        "CGovernanceManager::ProcessVote -- governance authority state changed",
                        GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
                    return false;
                }
                parent_arrived = mapObjects.contains(nHashGovobj);
                if (!branch_changed && !parent_arrived) {
                    request_parent = StoreOrphanVote(
                        nHashGovobj,
                        vote_time_pair_t{
                            vote,
                            GetTime<std::chrono::seconds>().count() +
                                GOVERNANCE_ORPHAN_EXPIRATION_TIME});
                    if (request_parent && orphan_vote_retained != nullptr) {
                        *orphan_vote_retained = true;
                    }
                }
            }
            if (parent_arrived) {
                return ProcessVote(
                    pfrom, vote, exception, connman,
                    orphan_vote_retained);
            }
            if (branch_changed) {
                if (attempt + 1 == MAX_ORPHAN_ADMISSION_ATTEMPTS) {
                    exception = CGovernanceException(
                        "CGovernanceManager::ProcessVote -- chain tip changed during orphan-vote verification",
                        GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
                    return false;
                }
                LOCK2(chainman.GetMutex(), cs);
                validation_tip = chainman.ActiveTip();
                if (!IsReadyForTip(validation_tip)) return false;
                validation_mn_list =
                    deterministicMNManager->GetListForBlock(validation_tip);
                continue;
            }

            std::ostringstream ostr;
            ostr << "CGovernanceManager::ProcessVote -- Unknown parent object "
                 << nHashGovobj.ToString() << ", MN outpoint = "
                 << vote.GetMasternodeOutpoint().ToStringShort();
            exception = CGovernanceException(
                ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
            if (request_parent) {
                RequestGovernanceObject(pfrom, nHashGovobj, connman);
            }
            LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
            return false;
        }

        return false;
    }

    // The request tracker bounds entry into this operation. Keep the pure SLH
    // work outside chain/governance/object locks, then bind the result to the
    // exact branch again before mutating vote state.
    std::string signature_error;
    if (!pq_purpose || !VerifyPQVoteUnlocked(
            vote, *validation_tip, validation_mn_list,
            *pq_purpose, signature_error)) {
        const std::string error{strprintf(
            "CGovernanceManager::ProcessVote -- Invalid operator vote: %s",
            signature_error)};
        bool stable_context{false};
        {
            LOCK2(chainman.GetMutex(), cs);
            const auto object{mapObjects.find(nHashGovobj)};
            stable_context = chainman.ActiveTip() == validation_tip &&
                IsReadyForTip(validation_tip) &&
                object != mapObjects.end() &&
                object->second.GetObjectType() == object_type &&
                !object->second.IsSetCachedDelete() &&
                !object->second.IsSetExpired() &&
                GetGovernanceVoteAuthPurpose(
                    object_type, vote.GetSignal()) == pq_purpose;
            if (stable_context &&
                object_type == GOVERNANCE_OBJECT_TRIGGER) {
                const auto trigger{mapTrigger.find(nHashGovobj)};
                stable_context =
                    !m_pq_inactive_triggers.contains(nHashGovobj) &&
                    trigger != mapTrigger.end() && trigger->second &&
                    trigger->second->GetBlockHeight() >
                        chainman.ActiveHeight();
            }
        }
        exception = stable_context
            ? CGovernanceException(
                  error, GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20)
            : CGovernanceException(
                  "CGovernanceManager::ProcessVote -- chain tip changed during operator-vote verification",
                  GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
        LogPrint(BCLog::GOBJECT, "%s\n", error);
        return false;
    }

    LOCK2(chainman.GetMutex(), cs);
    if (chainman.ActiveTip() != validation_tip ||
        !IsReadyForTip(validation_tip)) {
        exception = CGovernanceException(
            "CGovernanceManager::ProcessVote -- governance authority state changed",
            GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
        return false;
    }
    const auto it{mapObjects.find(nHashGovobj)};
    if (it == mapObjects.end()) return false;
    CGovernanceObject& govobj{it->second};
    if (govobj.GetVoteFile().HasVote(nHashVote)) return false;
    if (cmapVoteToObject.HasKey(nHashVote)) {
        cmapVoteToObject.Erase(nHashVote);
    }
    if (govobj.GetObjectType() != object_type ||
        govobj.IsSetCachedDelete() || govobj.IsSetExpired() ||
        GetGovernanceVoteAuthPurpose(
            object_type, vote.GetSignal()) != pq_purpose) {
        return false;
    }
    if (object_type == GOVERNANCE_OBJECT_TRIGGER) {
        const auto trigger_it{mapTrigger.find(nHashGovobj)};
        if (m_pq_inactive_triggers.contains(nHashGovobj) ||
            trigger_it == mapTrigger.end() ||
            trigger_it->second->GetBlockHeight() <=
                chainman.ActiveHeight()) {
            return false;
        }
    }
    const bool accepted{
        ProcessVoteWithBudget(
            govobj, *validation_tip, validation_mn_list, vote,
            exception, /*pq_signature_preverified=*/true) &&
        cmapVoteToObject.Insert(nHashVote, &govobj)};
    if (accepted) IndexGovernanceVote(nHashGovobj, object_type, vote);
    return accepted;
}

void CGovernanceManager::CheckPostponedObjects(PeerManager& peerman)
{
    if (!IsReady()) return;
    if (!masternodeSync.IsSynced()) return;

    std::vector<CGovernanceObject> ready_objects;
    const CBlockIndex* batch_validation_tip{nullptr};
    {
        LOCK2(cs_main, cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return;
        batch_validation_tip = validation_tip;
        const auto mnList{
            deterministicMNManager->GetListForBlock(validation_tip)};
        // Check postponed proposals
        for (auto it = mapPostponedObjects.begin(); it != mapPostponedObjects.end();) {
            const uint256& nHash = it->first;
            CGovernanceObject& govobj = it->second;

            assert(govobj.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER);

            std::string strError;
            bool fMissingConfirmations;
            if (govobj.IsCollateralValid(chainman, strError, fMissingConfirmations)) {
                if (govobj.IsValidLocally(chainman, mnList, strError, false)) {
                    ready_objects.push_back(govobj);
                } else {
                    LogPrint(BCLog::GOBJECT, "CGovernanceManager::CheckPostponedObjects -- %s invalid\n", nHash.ToString());
                }

            } else if (fMissingConfirmations) {
                // wait for more confirmations
                ++it;
                continue;
            }

            // remove processed or invalid object from the queue
            mapPostponedObjects.erase(it++);
        }
    }

    // SYSCOIN: AddGovernanceObject can drain orphan votes and must not inherit
    // the postponed-map validation locks.
    for (auto& object : ready_objects) {
        const uint256 hash{object.GetHash()};
        const auto admission{AddGovernanceObject(
            object, peerman, /*pfrom=*/nullptr, batch_validation_tip)};
        if (admission == GovernanceObjectAdmissionResult::UNAVAILABLE ||
            admission == GovernanceObjectAdmissionResult::STALE_TIP) {
            LOCK(cs);
            mapPostponedObjects.try_emplace(hash, std::move(object));
        }
    }

    {
        LOCK2(cs_main, cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return;
        // Perform additional relays for triggers
        int64_t nNow = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
        int nHeight = chainman.ActiveHeight();
        int64_t nSuperblockCycleSeconds = Params().GetConsensus().SuperBlockCycle(nHeight) * Params().GetConsensus().PowTargetSpacing(nHeight);

        for (auto it = setAdditionalRelayObjects.begin(); it != setAdditionalRelayObjects.end();) {
            auto itObject = mapObjects.find(*it);
            if (itObject != mapObjects.end()) {
                const CGovernanceObject& govobj = itObject->second;

                int64_t nTimestamp = govobj.GetCreationTime();

                bool fValid = (nTimestamp <= nNow + MAX_TIME_FUTURE_DEVIATION) && (nTimestamp >= nNow - 2 * nSuperblockCycleSeconds);
                bool fReady = (nTimestamp <= nNow + MAX_TIME_FUTURE_DEVIATION - RELIABLE_PROPAGATION_TIME);

                if (fValid) {
                    if (fReady) {
                        LogPrint(BCLog::GOBJECT, "CGovernanceManager::CheckPostponedObjects -- additional relay: hash = %s\n", govobj.GetHash().ToString());
                        govobj.Relay(peerman);
                    } else {
                        it++;
                        continue;
                    }
                }

            } else {
                LogPrint(BCLog::GOBJECT, "CGovernanceManager::CheckPostponedObjects -- additional relay of unknown object: %s\n", it->ToString());
            }

            setAdditionalRelayObjects.erase(it++);
        }
    }
}

void CGovernanceManager::RequestGovernanceObject(CNode* pfrom, const uint256& nHash, CConnman& connman, bool fUseFilter) const
{
    if (!pfrom || SupportsGovernancePages(pfrom->GetCommonVersion())) {
        return;
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::RequestGovernanceObject -- nHash %s peer=%d\n", nHash.ToString(), pfrom->GetId());

    CNetMsgMaker msgMaker(pfrom->GetCommonVersion());

    CBloomFilter filter;

    size_t nVoteCount = 0;
    if (fUseFilter) {
        LOCK2(chainman.GetMutex(), cs);
        if (!IsReadyForTip(chainman.ActiveTip())) return;
        const CGovernanceObject* pObj = FindConstGovernanceObject(nHash);

        if (pObj) {
            filter = CBloomFilter(Params().GetConsensus().nGovernanceFilterElements, GOVERNANCE_FILTER_FP_RATE, GetRand(999999), BLOOM_UPDATE_ALL);
            pObj->GetVoteFile().ForEachVote([&](const auto& vote) {
                filter.insert(vote.GetHash());
                ++nVoteCount;
                return true;
            });
        }
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::RequestGovernanceObject -- nHash %s nVoteCount %d peer=%d\n", nHash.ToString(), nVoteCount, pfrom->GetId());
    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::MNGOVERNANCESYNC, nHash, filter));
}

int CGovernanceManager::RequestGovernanceObjectVotes(CNode* pnode, CConnman& connman, const PeerManager& peerman) const
{
    const std::vector<CNode*> vNodeCopy{pnode};
    return RequestGovernanceObjectVotes(vNodeCopy, connman, peerman);
}

int CGovernanceManager::RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy, CConnman& connman, const PeerManager& peerman) const
{
    static std::map<uint256, std::map<CService, int64_t> > mapAskedRecently;

    if (!IsReady() || vNodesCopy.empty()) return -1;

    int64_t nNow = GetTime();
    int nTimeout = 60 * 60;
    size_t nPeersPerHashMax = 3;

    std::vector<uint256> vTriggerObjHashes;
    std::vector<uint256> vOtherObjHashes;

    // This should help us to get some idea about an impact this can bring once deployed on mainnet.
    // Testnet is ~40 times smaller in masternode count, but only ~1000 masternodes usually vote,
    // so 1 obj on mainnet == ~10 objs or ~1000 votes on testnet. However we want to test a higher
    // number of votes to make sure it's robust enough, so aim at 2000 votes per masternode per request.
    // On mainnet nMaxObjRequestsPerNode is always set to 1.
    int nMaxObjRequestsPerNode = 1;
    size_t nProjectedVotes = 2000;

    {
        LOCK2(chainman.GetMutex(), cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return -1;
        if (Params().GetChainType() != ChainType::MAIN) {
            const auto validation_mn_list{
                deterministicMNManager->GetListForBlock(validation_tip)};
            nMaxObjRequestsPerNode = std::max(
                1, int(nProjectedVotes /
                       std::max(
                           1,
                           static_cast<int>(
                               validation_mn_list.GetValidMNsCount()))));
        }

        if (mapObjects.empty()) return -2;

        for (const auto& [nHash, govobj] : mapObjects) {
            if (govobj.IsSetCachedDelete()) continue;
            if (m_pq_inactive_triggers.contains(nHash)) continue;
            if (mapAskedRecently.count(nHash)) {
                auto it = mapAskedRecently[nHash].begin();
                while (it != mapAskedRecently[nHash].end()) {
                    if (it->second < nNow) {
                        mapAskedRecently[nHash].erase(it++);
                    } else {
                        ++it;
                    }
                }
                if (mapAskedRecently[nHash].size() >= nPeersPerHashMax) continue;
            }

            if (govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
                vTriggerObjHashes.push_back(nHash);
            } else {
                vOtherObjHashes.push_back(nHash);
            }
        }
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceManager::RequestGovernanceObjectVotes -- start: vTriggerObjHashes %d vOtherObjHashes %d mapAskedRecently %d\n",
        vTriggerObjHashes.size(), vOtherObjHashes.size(), mapAskedRecently.size());

    Shuffle(vTriggerObjHashes.begin(), vTriggerObjHashes.end(), FastRandomContext());
    Shuffle(vOtherObjHashes.begin(), vOtherObjHashes.end(), FastRandomContext());

    for (int i = 0; i < nMaxObjRequestsPerNode; ++i) {
        uint256 nHashGovobj;

        // ask for triggers first
        if (!vTriggerObjHashes.empty()) {
            nHashGovobj = vTriggerObjHashes.back();
        } else {
            if (vOtherObjHashes.empty()) break;
            nHashGovobj = vOtherObjHashes.back();
        }
        bool fAsked = false;
        for (const auto& pnode : vNodesCopy) {
            // Don't try to sync any data from outbound non-relay "masternode" connections.
            // Inbound connection this early is most likely a "masternode" connection
            // initiated from another node, so skip it too.
            if (!pnode->CanRelay() ||
                SupportsGovernancePages(pnode->GetCommonVersion()) ||
                (fMasternodeMode && pnode->IsInboundConn())) continue;
            // stop early to prevent setAskFor overflow
            {
                LOCK(cs_main);
                size_t nProjectedSize = peerman.GetRequestedCount(pnode->GetId()) + nProjectedVotes;
                if (nProjectedSize > GetMaxInv()) continue;
                // to early to ask the same node
                if (mapAskedRecently[nHashGovobj].count(pnode->addr)) continue;
            }

            RequestGovernanceObject(pnode, nHashGovobj, connman, true);
            mapAskedRecently[nHashGovobj][pnode->addr] = nNow + nTimeout;
            fAsked = true;
            // stop loop if max number of peers per obj was asked
            if (mapAskedRecently[nHashGovobj].size() >= nPeersPerHashMax) break;
        }
        // NOTE: this should match `if` above (the one before `while`)
        if (!vTriggerObjHashes.empty()) {
            vTriggerObjHashes.pop_back();
        } else {
            vOtherObjHashes.pop_back();
        }
        if (!fAsked) i--;
    }
    LogPrint(BCLog::GOBJECT, "CGovernanceManager::RequestGovernanceObjectVotes -- end: vTriggerObjHashes %d vOtherObjHashes %d mapAskedRecently %d\n",
        vTriggerObjHashes.size(), vOtherObjHashes.size(), mapAskedRecently.size());

    return int(vTriggerObjHashes.size() + vOtherObjHashes.size());
}

uint64_t CGovernanceManager::PersistedVoteBytes(
    const CGovernanceVote& vote)
{
    return ::GetSerializeSize(vote, CLIENT_VERSION, SER_DISK);
}

bool CGovernanceManager::CanAdmitPersistedVoteBytes(
    uint64_t current_object_bytes, uint64_t projected_object_bytes) const
{
    AssertLockHeld(cs);
    if (current_object_bytes > m_persisted_vote_bytes) return false;
    const uint64_t retained{m_persisted_vote_bytes - current_object_bytes};
    return retained <= MAX_PERSISTED_VOTE_BYTES &&
        projected_object_bytes <= MAX_PERSISTED_VOTE_BYTES - retained;
}

bool CGovernanceManager::ProcessVoteWithBudget(
    CGovernanceObject& object,
    const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    const CGovernanceVote& vote,
    CGovernanceException& exception,
    bool pq_signature_preverified)
{
    AssertLockHeld(cs);
    const uint64_t current_bytes{
        object.GetVoteFile().GetSerializedVoteBytes()};
    const uint64_t projected_bytes{
        object.GetVoteFile().ProjectedSerializedVoteBytes(vote)};
    if (!CanAdmitPersistedVoteBytes(current_bytes, projected_bytes)) {
        exception = CGovernanceException(
            "CGovernanceManager::ProcessVote -- persisted vote byte budget exhausted",
            GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
        return false;
    }
    if (!object.ProcessVote(validation_tip, validation_mn_list, vote,
                            exception, pq_signature_preverified)) {
        return false;
    }
    const uint64_t actual_bytes{
        object.GetVoteFile().GetSerializedVoteBytes()};
    if (!CanAdmitPersistedVoteBytes(current_bytes, actual_bytes)) {
        // ProjectedSerializedVoteBytes is intentionally the same replacement
        // rule as AddVote. Treat divergence as an invariant failure rather
        // than retaining state beyond the persisted budget.
        throw std::logic_error(
            "governance vote byte projection diverged from admission");
    }
    m_persisted_vote_bytes =
        m_persisted_vote_bytes - current_bytes + actual_bytes;
    return true;
}

bool CGovernanceManager::RebuildPersistedVoteBytes()
{
    AssertLockHeld(cs);
    uint64_t total{0};
    const auto add_bytes = [&](uint64_t bytes) {
        if (bytes > MAX_PERSISTED_VOTE_BYTES - total) return false;
        total += bytes;
        return true;
    };
    for (const auto& [hash, object] : mapObjects) {
        if (!add_bytes(object.GetVoteFile().GetSerializedVoteBytes())) {
            LogPrintf("CGovernanceManager::%s -- persisted vote budget exceeded by object %s\n",
                      __func__, hash.ToString());
            return false;
        }
    }
    for (const auto& item : cmapInvalidVotes.GetItemList()) {
        if (!add_bytes(PersistedVoteBytes(item.value))) return false;
    }
    for (const auto& item : cmmapOrphanVotes.GetItemList()) {
        if (!add_bytes(PersistedVoteBytes(item.value.first))) return false;
    }
    m_persisted_vote_bytes = total;
    return true;
}

void CGovernanceManager::EraseOrphanVote(
    const uint256& object_hash, const vote_time_pair_t& vote_pair)
{
    AssertLockHeld(cs);
    std::vector<vote_time_pair_t> existing;
    cmmapOrphanVotes.GetAll(object_hash, existing);
    const bool present{std::find(existing.begin(), existing.end(),
                                 vote_pair) != existing.end()};
    cmmapOrphanVotes.Erase(object_hash, vote_pair);
    if (present) {
        const uint64_t bytes{PersistedVoteBytes(vote_pair.first)};
        m_persisted_vote_bytes -=
            std::min(m_persisted_vote_bytes, bytes);
    }
}

void CGovernanceManager::EraseOrphanVotes(const uint256& object_hash)
{
    AssertLockHeld(cs);
    std::vector<vote_time_pair_t> existing;
    cmmapOrphanVotes.GetAll(object_hash, existing);
    for (const auto& vote_pair : existing) {
        const uint64_t bytes{PersistedVoteBytes(vote_pair.first)};
        m_persisted_vote_bytes -=
            std::min(m_persisted_vote_bytes, bytes);
    }
    cmmapOrphanVotes.Erase(object_hash);
}

bool CGovernanceManager::RebuildIndexes()
{
    LOCK(cs);

    cmapVoteToObject.Clear();
    m_pq_vote_objects.clear();
    m_delegated_funding_vote_objects.clear();
    for (auto& object_entry : mapObjects) {
        const uint256& object_hash{object_entry.first};
        CGovernanceObject& govobj{object_entry.second};
        std::vector<COutPoint> pq_operators;
        std::vector<COutPoint> delegated_operators;
        govobj.GetVoteFile().ForEachVote(
            [&](const CGovernanceVote& vote) {
                cmapVoteToObject.Insert(vote.GetHash(), &govobj);
                if (GetGovernanceVoteAuthPurpose(
                        govobj.GetObjectType(), vote.GetSignal())) {
                    pq_operators.push_back(
                        vote.GetMasternodeOutpoint());
                } else if (IsDelegatedProposalFundingVote(
                               govobj.GetObjectType(),
                               vote.GetSignal())) {
                    delegated_operators.push_back(
                        vote.GetMasternodeOutpoint());
                }
                return true;
            });
        for (const COutPoint& outpoint : pq_operators) {
            m_pq_vote_objects[outpoint].insert(object_hash);
        }
        for (const COutPoint& outpoint : delegated_operators) {
            m_delegated_funding_vote_objects[outpoint].insert(
                object_hash);
        }
    }
    return RebuildPersistedVoteBytes();
}

void CGovernanceManager::IndexGovernanceVote(
    const uint256& object_hash, int object_type,
    const CGovernanceVote& vote)
{
    AssertLockHeld(cs);
    if (GetGovernanceVoteAuthPurpose(object_type, vote.GetSignal())) {
        m_pq_vote_objects[vote.GetMasternodeOutpoint()].insert(
            object_hash);
    } else if (IsDelegatedProposalFundingVote(
                   object_type, vote.GetSignal())) {
        m_delegated_funding_vote_objects[
            vote.GetMasternodeOutpoint()].insert(object_hash);
    }
}

void CGovernanceManager::RemoveObjectFromGovernanceVoteIndexes(
    const uint256& object_hash, const CGovernanceObject& object)
{
    AssertLockHeld(cs);
    std::set<COutPoint> pq_operators;
    std::set<COutPoint> delegated_operators;
    object.GetVoteFile().ForEachVote([&](const CGovernanceVote& vote) {
        if (GetGovernanceVoteAuthPurpose(
                object.GetObjectType(), vote.GetSignal())) {
            pq_operators.insert(vote.GetMasternodeOutpoint());
        } else if (IsDelegatedProposalFundingVote(
                       object.GetObjectType(), vote.GetSignal())) {
            delegated_operators.insert(
                vote.GetMasternodeOutpoint());
        }
        return true;
    });
    const auto erase_from_index = [&](auto& index,
                                      const auto& operators) {
        for (const COutPoint& outpoint : operators) {
            const auto operator_it{index.find(outpoint)};
            if (operator_it == index.end()) continue;
            operator_it->second.erase(object_hash);
            if (operator_it->second.empty()) index.erase(operator_it);
        }
    };
    erase_from_index(m_pq_vote_objects, pq_operators);
    erase_from_index(
        m_delegated_funding_vote_objects, delegated_operators);
}

void CGovernanceManager::RememberFailedPQGovernanceTip(
    const CBlockIndex& validation_tip)
{
    AssertLockHeld(cs);
    const bool new_failed_context{
        m_pq_authority_snapshot_valid ||
        m_pq_authority_tip_height != validation_tip.nHeight ||
        m_pq_authority_tip_hash != validation_tip.GetBlockHash()};
    if (new_failed_context) {
        (void)AdvancePQGovernanceValidationContext();
    }
    m_pq_authority_tip_hash = validation_tip.GetBlockHash();
    m_pq_authority_tip_height = validation_tip.nHeight;
    m_pq_authority_snapshot_valid = false;
}

bool CGovernanceManager::IsPQInactiveTrigger(
    const uint256& object_hash) const
{
    AssertLockHeld(cs);
    return m_pq_inactive_triggers.contains(object_hash);
}

bool CGovernanceManager::RebuildPQTriggerState(
    const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& registry_snapshot,
    bool recompute_cached_flags,
    std::set<uint256>* reactivated_triggers)
{
    AssertLockHeld(cs);

    ScopedLockBool rebuilding{cs, m_rebuilding_cached_triggers, true};
    std::map<uint256, std::shared_ptr<CSuperblock>> rebuilt;
    std::set<uint256> inactive;
    const int64_t now{GetTime<std::chrono::seconds>().count()};
    if (reactivated_triggers != nullptr) {
        reactivated_triggers->clear();
    }

    for (auto& [object_hash, object] : mapObjects) {
        if (object.GetObjectType() != GOVERNANCE_OBJECT_TRIGGER ||
            object.IsSetExpired()) {
            continue;
        }
        // A permanent local deletion is not branch-dependent. Vote-derived
        // deletion is reconsidered below only after the trigger's authority
        // is shown active on this branch.
        if (object.IsSetCachedDelete() &&
            !object.IsSetCachedDeleteByVotes()) {
            continue;
        }

        std::shared_ptr<CSuperblock> trigger;
        try {
            uint256 mutable_hash{object_hash};
            trigger = std::make_shared<CSuperblock>(mutable_hash);
        } catch (const std::exception& e) {
            object.PrepareDeletion(now);
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s rejected malformed cached trigger %s: %s\n",
                     __func__, object_hash.ToString(), e.what());
            continue;
        }

        if (const auto previous{mapTrigger.find(object_hash)};
            previous != mapTrigger.end() && previous->second &&
            previous->second->GetStatus() == SeenObjectStatus::Executed &&
            trigger->GetBlockHeight() <= validation_tip.nHeight) {
            trigger->SetStatus(SeenObjectStatus::Executed);
        } else {
            trigger->SetStatus(SeenObjectStatus::Valid);
        }

        std::string authorization_error;
        if (!object.CheckPQAuthorizationContext(
                validation_tip, validation_mn_list, registry_snapshot,
                authorization_error)) {
            // A non-canonical envelope cannot become valid on another branch.
            // Keep only context-dependent failures (branch, roster, rotation,
            // revocation, or PoSe) in the reversible quarantine.
            if (authorization_error ==
                "non-canonical governance SLH authorization") {
                object.PrepareDeletion(now);
                LogPrint(BCLog::GOBJECT,
                         "CGovernanceManager::%s rejected malformed cached trigger %s\n",
                         __func__, object_hash.ToString());
                continue;
            }
            inactive.insert(object_hash);
            rebuilt.emplace(object_hash, std::move(trigger));
            LogPrint(BCLog::GOBJECT,
                     "CGovernanceManager::%s quarantined branch-inactive trigger %s: %s\n",
                     __func__, object_hash.ToString(), authorization_error);
            continue;
        }

        const bool was_inactive{
            m_pq_inactive_triggers.contains(object_hash)};
        // An authorization-invalid trigger above deliberately bypasses this
        // irreversible temporal cleanup so an A-B-A reorg can restore it.
        // Once its authorization is active again, a past event can never be
        // made visible merely by clearing a vote-derived deletion flag.
        if (trigger->GetBlockHeight() < validation_tip.nHeight) {
            object.PrepareDeletion(now);
            continue;
        }
        if (was_inactive && reactivated_triggers != nullptr) {
            // Report the transition before the visibility gate below. Votes
            // skipped while quarantined may themselves be the reason this
            // trigger is still cached as deleted.
            reactivated_triggers->insert(object_hash);
        }

        if (recompute_cached_flags) {
            object.UpdateSentinelVariables(
                validation_mn_list,
                /*reset_vote_caused_deletion=*/true);
        }
        if (object.IsSetCachedDelete()) continue;
        rebuilt.emplace(object_hash, std::move(trigger));
    }

    mapTrigger.swap(rebuilt);
    m_pq_inactive_triggers.swap(inactive);
    InvalidateObjectPageCache();
    m_pq_trigger_state_initialized = true;
    return true;
}

bool CGovernanceManager::InitOnLoad()
{
    int64_t nStart = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    LogPrintf("Preparing masternode indexes and governance triggers...\n");
    {
        LOCK2(chainman.GetMutex(), cs);
        const CBlockIndex* tip{chainman.ActiveTip()};
        ObserveChainTip(tip);
        if (tip == nullptr) return false;
        MarkPQGovernanceUnavailableForTip(*tip);
        m_pq_trigger_state_initialized = false;
        if (!RebuildIndexes()) {
            RememberFailedPQGovernanceTip(*tip);
            return false;
        }
        if (!RevalidatePQGovernanceImpl(*tip)) {
            return false;
        }
    }

    CheckAndRemove();
    LogPrintf("Masternode indexes and governance triggers prepared  %dms\n", TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) - nStart);
    LogPrintf("     %s\n", ToString());
    return true;
}

void GovernanceStore::Clear()
{
    LOCK(cs);

    LogPrint(BCLog::GOBJECT, "Governance object manager was cleared\n");
    mapObjects.clear();
    mapErasedGovernanceObjects.clear();
    cmapVoteToObject.Clear();
    cmapInvalidVotes.Clear();
    cmmapOrphanVotes.Clear();
    mapLastMasternodeObject.clear();
    InvalidateObjectPageCache();
}

std::string GovernanceStore::ToString() const
{
    LOCK(cs);

    int nProposalCount = 0;
    int nTriggerCount = 0;
    int nOtherCount = 0;

    for (const auto& objPair : mapObjects) {
        switch (objPair.second.GetObjectType()) {
        case GOVERNANCE_OBJECT_PROPOSAL:
            nProposalCount++;
            break;
        case GOVERNANCE_OBJECT_TRIGGER:
            nTriggerCount++;
            break;
        default:
            nOtherCount++;
            break;
        }
    }

    return strprintf("Governance Objects: %d (Proposals: %d, Triggers: %d, Other: %d; Erased: %d), Votes: %d",
        (int)mapObjects.size(),
        nProposalCount, nTriggerCount, nOtherCount, (int)mapErasedGovernanceObjects.size(),
        (int)cmapVoteToObject.GetSize());
}

std::string CGovernanceManager::ToString() const
{
    LOCK(cs);
    if (!IsReady()) return "Governance authority state is not ready";
    return GovernanceStore::ToString();
}

UniValue CGovernanceManager::ToJson() const
{
    LOCK(cs);
    if (!IsReady()) {
        UniValue unavailable{UniValue::VOBJ};
        unavailable.pushKV("ready", false);
        return unavailable;
    }
    int nProposalCount = 0;
    int nTriggerCount = 0;
    int nOtherCount = 0;

    for (const auto& objpair : mapObjects) {
        if (m_pq_inactive_triggers.contains(objpair.first)) continue;
        switch (objpair.second.GetObjectType()) {
        case GOVERNANCE_OBJECT_PROPOSAL:
            nProposalCount++;
            break;
        case GOVERNANCE_OBJECT_TRIGGER:
            nTriggerCount++;
            break;
        default:
            nOtherCount++;
            break;
        }
    }

    UniValue jsonObj(UniValue::VOBJ);
    jsonObj.pushKV("ready", true);
    jsonObj.pushKV("objects_total",
                   static_cast<int>(mapObjects.size() -
                                    m_pq_inactive_triggers.size()));
    jsonObj.pushKV("proposals", nProposalCount);
    jsonObj.pushKV("triggers", nTriggerCount);
    jsonObj.pushKV("other", nOtherCount);
    jsonObj.pushKV("quarantined_triggers",
                   static_cast<int>(m_pq_inactive_triggers.size()));
    jsonObj.pushKV("erased", (int)mapErasedGovernanceObjects.size());
    jsonObj.pushKV("votes", (int)cmapVoteToObject.GetSize());
    return jsonObj;
}

bool CGovernanceManager::BuildPQGovernanceAuthorityMap(
    const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& registry_snapshot,
    pq_authority_map_t& authorities,
    std::string& error)
{
    authorities.clear();
    if (validation_mn_list.IsNull() ||
        validation_mn_list.GetHeight() != validation_tip.nHeight ||
        validation_mn_list.GetBlockHash() !=
            validation_tip.GetBlockHash() ||
        registry_snapshot.height != validation_tip.nHeight ||
        registry_snapshot.block_hash != validation_tip.GetBlockHash()) {
        error = "governance authority inputs do not match the exact tip";
        return false;
    }

    bool unique{true};
    validation_mn_list.ForEachMN(
        /*onlyValid=*/true, [&](const CDeterministicMN& dmn) {
            const llmq::pq::OperatorKeyState* state{
                registry_snapshot.FindOperator(dmn.proTxHash)};
            if (state == nullptr || !state->HasActiveGlobalKey()) return;
            unique &= authorities.emplace(
                dmn.collateralOutpoint,
                PQGovernanceAuthority{
                    dmn.proTxHash, state->global_key.key_version})
                          .second;
        });
    if (!unique) {
        authorities.clear();
        error = "duplicate collateral in governance authority snapshot";
        return false;
    }
    error.clear();
    return true;
}

bool CGovernanceManager::BuildDelegatedGovernanceAuthorityMap(
    const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    delegated_authority_map_t& authorities,
    std::string& error)
{
    authorities.clear();
    if (validation_mn_list.IsNull() ||
        validation_mn_list.GetHeight() != validation_tip.nHeight ||
        validation_mn_list.GetBlockHash() !=
            validation_tip.GetBlockHash()) {
        error = "delegated governance authority input does not match the exact tip";
        return false;
    }

    bool unique{true};
    validation_mn_list.ForEachMN(
        /*onlyValid=*/true, [&](const CDeterministicMN& dmn) {
            unique &= authorities.emplace(
                dmn.collateralOutpoint,
                dmn.pdmnState->keyIDVoting).second;
        });
    if (!unique) {
        authorities.clear();
        error = "duplicate collateral in delegated governance authority snapshot";
        return false;
    }
    error.clear();
    return true;
}

bool CGovernanceManager::IsStraightPQGovernanceExtension(
    const CBlockIndex& validation_tip) const
{
    AssertLockHeld(cs);
    return m_pq_authority_snapshot_valid &&
        validation_tip.pprev != nullptr &&
        validation_tip.pprev->nHeight == m_pq_authority_tip_height &&
        validation_tip.pprev->GetBlockHash() == m_pq_authority_tip_hash;
}

bool CGovernanceManager::IsRememberedPQGovernanceTip(
    const CBlockIndex& validation_tip) const
{
    AssertLockHeld(cs);
    return m_pq_authority_snapshot_valid &&
        validation_tip.nHeight == m_pq_authority_tip_height &&
        validation_tip.GetBlockHash() == m_pq_authority_tip_hash;
}

std::set<COutPoint>
CGovernanceManager::FindChangedPQGovernanceAuthorities(
    const pq_authority_map_t& previous,
    const pq_authority_map_t& next)
{
    std::set<COutPoint> changed;
    for (const auto& [outpoint, authority] : previous) {
        const auto candidate{next.find(outpoint)};
        if (candidate == next.end() || candidate->second != authority) {
            changed.insert(outpoint);
        }
    }
    for (const auto& [outpoint, authority] : next) {
        const auto candidate{previous.find(outpoint)};
        if (candidate == previous.end() || candidate->second != authority) {
            changed.insert(outpoint);
        }
    }
    return changed;
}

std::set<COutPoint>
CGovernanceManager::FindChangedDelegatedGovernanceAuthorities(
    const delegated_authority_map_t& previous,
    const delegated_authority_map_t& next)
{
    std::set<COutPoint> changed;
    for (const auto& [outpoint, authority] : previous) {
        const auto candidate{next.find(outpoint)};
        if (candidate == next.end() || candidate->second != authority) {
            changed.insert(outpoint);
        }
    }
    for (const auto& [outpoint, authority] : next) {
        const auto candidate{previous.find(outpoint)};
        if (candidate == previous.end() || candidate->second != authority) {
            changed.insert(outpoint);
        }
    }
    return changed;
}

bool CGovernanceManager::ReconcileGovernanceVotes(
    const CBlockIndex& validation_tip,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& registry_snapshot,
    bool full_revalidation,
    const std::set<COutPoint>& changed_pq_operators,
    const std::set<COutPoint>& changed_delegated_operators,
    const std::set<uint256>& reactivated_triggers,
    std::set<uint256>& flags_to_refresh,
    std::size_t& checked_pq_votes,
    std::size_t& checked_delegated_votes)
{
    AssertLockHeld(cs);
    const auto erase_vote_refs = [&](const std::set<uint256>& removed) {
        for (const uint256& vote_hash : removed) {
            cmapVoteToObject.Erase(vote_hash);
            cmapInvalidVotes.Erase(vote_hash);
        }
    };
    const auto update_vote_bytes = [&](uint64_t before,
                                       uint64_t after)
        EXCLUSIVE_LOCKS_REQUIRED(cs) {
        m_persisted_vote_bytes =
            m_persisted_vote_bytes -
                std::min(m_persisted_vote_bytes, before) +
            after;
    };
    const auto erase_empty_operator = [&](auto& index,
                                          const COutPoint& outpoint,
                                          const uint256& object_hash) {
        const auto indexed{index.find(outpoint)};
        if (indexed == index.end()) return;
        indexed->second.erase(object_hash);
        if (indexed->second.empty()) index.erase(indexed);
    };

    const auto reconcile_object = [&](const uint256& object_hash,
                                      CGovernanceObject& object)
        EXCLUSIVE_LOCKS_REQUIRED(cs) {
        const uint64_t vote_bytes_before{
            object.GetVoteFile().GetSerializedVoteBytes()};
        std::set<COutPoint> removed_pq_operators;
        const auto removed_pq{object.RemoveInvalidPQVotes(
            validation_tip, validation_mn_list, registry_snapshot,
            /*masternode_filter=*/std::nullopt,
            &checked_pq_votes, &removed_pq_operators)};
        std::set<COutPoint> removed_delegated_operators;
        const auto removed_delegated{
            object.RemoveInvalidDelegatedFundingVotes(
                validation_mn_list,
                /*masternode_filter=*/std::nullopt,
                &checked_delegated_votes,
                &removed_delegated_operators)};
        const uint64_t vote_bytes_after{
            object.GetVoteFile().GetSerializedVoteBytes()};
        update_vote_bytes(vote_bytes_before, vote_bytes_after);

        if (!removed_pq.empty() || !removed_delegated.empty()) {
            flags_to_refresh.insert(object_hash);
        }
        erase_vote_refs(removed_pq);
        erase_vote_refs(removed_delegated);
        for (const COutPoint& outpoint : removed_pq_operators) {
            if (!object.HasPQVoteFromMasternode(outpoint)) {
                erase_empty_operator(
                    m_pq_vote_objects, outpoint, object_hash);
            }
        }
        for (const COutPoint& outpoint : removed_delegated_operators) {
            if (!object.HasDelegatedFundingVoteFromMasternode(outpoint)) {
                erase_empty_operator(
                    m_delegated_funding_vote_objects, outpoint,
                    object_hash);
            }
        }
    };

    if (full_revalidation) {
        ++m_pq_full_revalidations;
        for (auto& [object_hash, object] : mapObjects) {
            if (object.IsSetExpired() ||
                m_pq_inactive_triggers.contains(object_hash)) {
                continue;
            }
            reconcile_object(object_hash, object);
        }
        // RebuildIndexes populated both authority indexes on startup. The
        // removals above update them in place, so only aggregate bytes need
        // recounting after the recovery/reorg pass.
        return RebuildPersistedVoteBytes();
    }

    std::set<uint256> fully_reconciled_objects;
    for (const uint256& object_hash : reactivated_triggers) {
        const auto object_it{mapObjects.find(object_hash)};
        if (object_it == mapObjects.end() ||
            object_it->second.IsSetExpired() ||
            m_pq_inactive_triggers.contains(object_hash)) {
            continue;
        }
        // Authority deltas that occurred while a trigger was quarantined were
        // intentionally skipped to preserve reversible A-B-A state. The
        // object must therefore get a complete vote-authority pass before it
        // can become visible again.
        reconcile_object(object_hash, object_it->second);
        // Cached thresholds may also have changed while this object was
        // quarantined. The authority scan cannot infer that from vote
        // removals, so reactivation itself invalidates the cached flags.
        flags_to_refresh.insert(object_hash);
        fully_reconciled_objects.insert(object_hash);
    }

    for (const COutPoint& outpoint : changed_pq_operators) {
        const auto indexed{m_pq_vote_objects.find(outpoint)};
        if (indexed == m_pq_vote_objects.end()) continue;
        const std::vector<uint256> object_hashes{
            indexed->second.begin(), indexed->second.end()};
        for (const uint256& object_hash : object_hashes) {
            const auto object_it{mapObjects.find(object_hash)};
            if (object_it == mapObjects.end() ||
                fully_reconciled_objects.contains(object_hash) ||
                m_pq_inactive_triggers.contains(object_hash)) {
                continue;
            }
            CGovernanceObject& object{object_it->second};
            const uint64_t vote_bytes_before{
                object.GetVoteFile().GetSerializedVoteBytes()};
            const auto removed{object.RemoveInvalidPQVotes(
                validation_tip, validation_mn_list, registry_snapshot,
                outpoint, &checked_pq_votes)};
            const uint64_t vote_bytes_after{
                object.GetVoteFile().GetSerializedVoteBytes()};
            update_vote_bytes(vote_bytes_before, vote_bytes_after);
            if (!removed.empty()) {
                flags_to_refresh.insert(object_hash);
                erase_vote_refs(removed);
            }
            if (!object.HasPQVoteFromMasternode(outpoint)) {
                indexed->second.erase(object_hash);
            }
        }
        if (indexed->second.empty()) m_pq_vote_objects.erase(indexed);
    }

    for (const COutPoint& outpoint : changed_delegated_operators) {
        const auto indexed{
            m_delegated_funding_vote_objects.find(outpoint)};
        if (indexed == m_delegated_funding_vote_objects.end()) continue;
        const std::vector<uint256> object_hashes{
            indexed->second.begin(), indexed->second.end()};
        for (const uint256& object_hash : object_hashes) {
            const auto object_it{mapObjects.find(object_hash)};
            if (object_it == mapObjects.end() ||
                fully_reconciled_objects.contains(object_hash)) {
                continue;
            }
            CGovernanceObject& object{object_it->second};
            const uint64_t vote_bytes_before{
                object.GetVoteFile().GetSerializedVoteBytes()};
            const auto removed{
                object.RemoveInvalidDelegatedFundingVotes(
                    validation_mn_list, outpoint,
                    &checked_delegated_votes)};
            const uint64_t vote_bytes_after{
                object.GetVoteFile().GetSerializedVoteBytes()};
            update_vote_bytes(vote_bytes_before, vote_bytes_after);
            if (!removed.empty()) {
                flags_to_refresh.insert(object_hash);
                erase_vote_refs(removed);
            }
            if (!object.HasDelegatedFundingVoteFromMasternode(
                    outpoint)) {
                indexed->second.erase(object_hash);
            }
        }
        if (indexed->second.empty()) {
            m_delegated_funding_vote_objects.erase(indexed);
        }
    }
    return true;
}

bool CGovernanceManager::RevalidatePQGovernance(
    const CBlockIndex& validation_tip)
{
    return RevalidatePQGovernanceImpl(validation_tip);
}

bool CGovernanceManager::RevalidatePQGovernanceImpl(
    const CBlockIndex& validation_tip)
{
    LOCK2(chainman.GetMutex(), cs);
    if (chainman.ActiveTip() != &validation_tip) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s rejected a non-active validation tip\n",
                 __func__);
        return false;
    }
    ObserveChainTip(&validation_tip);
    MarkPQGovernanceUnavailableForTip(validation_tip);
    if (deterministicMNManager == nullptr) {
        RememberFailedPQGovernanceTip(validation_tip);
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s deterministic masternode state is unavailable\n",
                 __func__);
        return false;
    }

    CDeterministicMNList mn_list;
    try {
        mn_list = deterministicMNManager->GetListForBlock(&validation_tip);
    } catch (const std::exception& e) {
        RememberFailedPQGovernanceTip(validation_tip);
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s unable to read deterministic masternode snapshot: %s\n",
                 __func__, e.what());
        return false;
    }
    llmq::pq::PQRegistrySnapshot registry_snapshot;
    std::string registry_error;
    if (!deterministicMNManager->GetPQRegistrySnapshot(
            &validation_tip, registry_snapshot, registry_error)) {
        RememberFailedPQGovernanceTip(validation_tip);
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s unable to read PQ registry: %s\n",
                 __func__, registry_error);
        return false;
    }

    pq_authority_map_t next_authorities;
    if (!BuildPQGovernanceAuthorityMap(
            validation_tip, mn_list, registry_snapshot,
            next_authorities, registry_error)) {
        RememberFailedPQGovernanceTip(validation_tip);
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s invalid authority snapshot: %s\n",
                 __func__, registry_error);
        return false;
    }
    delegated_authority_map_t next_delegated_authorities;
    if (!BuildDelegatedGovernanceAuthorityMap(
            validation_tip, mn_list, next_delegated_authorities,
            registry_error)) {
        RememberFailedPQGovernanceTip(validation_tip);
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::%s invalid delegated authority snapshot: %s\n",
                 __func__, registry_error);
        return false;
    }
    const std::size_t next_valid_mn_count{
        mn_list.GetValidMNsCount()};

    const bool straight_extension{
        IsStraightPQGovernanceExtension(validation_tip)};
    bool trigger_boundary_crossed{false};
    if (straight_extension && m_pq_authority_snapshot_valid) {
        for (const auto& [hash, trigger] : mapTrigger) {
            const auto object{mapObjects.find(hash)};
            if (trigger && object != mapObjects.end() &&
                IsGovernancePageObjectEligible(
                    hash, object->second,
                    m_pq_authority_tip_height) &&
                trigger->GetBlockHeight() <= validation_tip.nHeight) {
                trigger_boundary_crossed = true;
                break;
            }
        }
    }
    // Duplicate tip notifications are common during startup and must not
    // turn an immutable snapshot into another full governance-vote scan.
    const bool unchanged_repeated_tip{
        IsRememberedPQGovernanceTip(validation_tip) &&
        m_pq_authorities == next_authorities &&
        m_delegated_funding_authorities ==
            next_delegated_authorities &&
        m_governance_valid_mn_count == next_valid_mn_count};
    const bool full_revalidation{
        !straight_extension && !unchanged_repeated_tip};
    const std::set<COutPoint> changed_pq_operators{full_revalidation
        ? std::set<COutPoint>{}
        : FindChangedPQGovernanceAuthorities(m_pq_authorities,
                                             next_authorities)};
    const std::set<COutPoint> changed_delegated_operators{
        full_revalidation
            ? std::set<COutPoint>{}
            : FindChangedDelegatedGovernanceAuthorities(
                  m_delegated_funding_authorities,
                  next_delegated_authorities)};
    const bool valid_roster_count_changed{
        !m_pq_authority_snapshot_valid ||
        m_governance_valid_mn_count != next_valid_mn_count};
    const bool recompute_all_cached_flags{
        full_revalidation || valid_roster_count_changed ||
        !m_pq_trigger_state_initialized};
    const bool advance_validation_context{
        full_revalidation || valid_roster_count_changed ||
        !changed_pq_operators.empty() ||
        !changed_delegated_operators.empty() ||
        !m_pq_trigger_state_initialized ||
        trigger_boundary_crossed};

    nCachedBlockHeight.store(validation_tip.nHeight,
                             std::memory_order_relaxed);
    // Establish branch-inactive trigger quarantine before vote cleanup so a
    // temporary fork cannot destroy votes needed to restore an A-B-A branch.
    // Cached thresholds are rebuilt only after both authority domains have
    // been reconciled below.
    std::set<uint256> reactivated_triggers;
    if (full_revalidation || !changed_pq_operators.empty() ||
        valid_roster_count_changed ||
        !m_pq_trigger_state_initialized) {
        if (!RebuildPQTriggerState(validation_tip, mn_list,
                                   registry_snapshot,
                                   /*recompute_cached_flags=*/false,
                                   &reactivated_triggers)) {
            RememberFailedPQGovernanceTip(validation_tip);
            return false;
        }
    }

    std::set<uint256> flags_to_refresh;
    std::size_t checked_pq_votes{0};
    std::size_t checked_delegated_votes{0};
    if (!ReconcileGovernanceVotes(
            validation_tip, mn_list, registry_snapshot,
            full_revalidation, changed_pq_operators,
            changed_delegated_operators, reactivated_triggers,
            flags_to_refresh,
            checked_pq_votes, checked_delegated_votes)) {
        RememberFailedPQGovernanceTip(validation_tip);
        return false;
    }

    bool rebuild_trigger_flags{false};
    if (recompute_all_cached_flags) {
        // Cached flags are memory-only. A recovery/reorg or a valid-roster
        // count change can move every quorum threshold, including clearing a
        // vote-caused deletion, even when no authority key changed.
        for (auto& [object_hash, object] : mapObjects) {
            if (object.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL &&
                !object.IsSetExpired()) {
                object.UpdateSentinelVariables(
                    mn_list, /*reset_vote_caused_deletion=*/true);
            }
        }
    } else {
        for (const uint256& object_hash : flags_to_refresh) {
            const auto object{mapObjects.find(object_hash)};
            if (object != mapObjects.end() &&
                !object->second.IsSetExpired()) {
                object->second.UpdateSentinelVariables(
                    mn_list, /*reset_vote_caused_deletion=*/true);
                rebuild_trigger_flags |=
                    object->second.GetObjectType() ==
                    GOVERNANCE_OBJECT_TRIGGER;
            }
        }
    }
    // The first rebuild must precede vote validation so branch-inactive
    // triggers retain their votes. If invalid active-branch votes then clear
    // a vote-caused delete flag, rebuild once more so the restored object is
    // present before readiness is published.
    if ((recompute_all_cached_flags || rebuild_trigger_flags) &&
        !RebuildPQTriggerState(validation_tip, mn_list,
                               registry_snapshot,
                               /*recompute_cached_flags=*/
                                   recompute_all_cached_flags)) {
        RememberFailedPQGovernanceTip(validation_tip);
        return false;
    }

    if (chainman.ActiveTip() != &validation_tip) {
        RememberFailedPQGovernanceTip(validation_tip);
        return false;
    }
    m_pq_vote_context_checks += checked_pq_votes;
    m_delegated_vote_context_checks += checked_delegated_votes;
    m_pq_authorities = std::move(next_authorities);
    m_delegated_funding_authorities =
        std::move(next_delegated_authorities);
    m_governance_valid_mn_count = next_valid_mn_count;
    m_pq_authority_tip_hash = validation_tip.GetBlockHash();
    m_pq_authority_tip_height = validation_tip.nHeight;
    m_pq_authority_snapshot_valid = true;
    return PublishPQGovernanceReadyForTip(
        validation_tip, advance_validation_context);
}

void CGovernanceManager::UpdatedBlockTip(
    const CBlockIndex* pindex, CConnman& connman, PeerManager& peerman)
    EXCLUSIVE_LOCKS_REQUIRED(!cs_main, !cs)
{
    // Note this gets called from ActivateBestChain without cs_main being held
    // so it should be safe to lock our mutex here without risking a deadlock
    // On the other hand it should be safe for us to access pindex without holding a lock
    // on cs_main because the CBlockIndex objects are dynamically allocated and
    // presumably never deleted.
    if (!pindex) {
        ObserveChainTip(nullptr);
        return;
    }

    if (!RevalidatePQGovernance(*pindex)) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceManager::UpdatedBlockTip -- governance remains fail-closed at height %d\n",
                 pindex->nHeight);
        return;
    }

    uint256 local_pro_tx_hash;
    uint32_t global_key_version{0};
    llmq::pq::GlobalPublicKey global_public_key;
    CService local_service;
    if (GetActiveMasternodeIdentity(local_pro_tx_hash, global_key_version,
                                    global_public_key, local_service)) {
        const auto sb_opt = CreateSuperblockCandidate(pindex);
        const auto trigger_opt =
            CreateGovernanceTrigger(sb_opt, pindex, peerman);
        VoteGovernanceTriggers(trigger_opt, connman, peerman);
    }
    LogPrint(BCLog::GOBJECT, "CGovernanceManager::UpdatedBlockTip -- nCachedBlockHeight: %d\n", GetCachedBlockHeight());

    CheckPostponedObjects(peerman);
    DrainReadyOrphanVotes(peerman);

    CSuperblockManager::ExecuteBestSuperblock(pindex->nHeight, pindex);
}

void CGovernanceManager::RequestOrphanObjects(CConnman& connman)
{
    const CConnman::NodesSnapshot snap{connman, /* filter = */ FullyConnectedOnly};

    std::vector<uint256> vecHashesFiltered;
    {
        std::vector<uint256> vecHashes;
        LOCK2(chainman.GetMutex(), cs);
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        if (!IsReadyForTip(validation_tip)) return;
        cmmapOrphanVotes.GetKeys(vecHashes);
        for (const uint256& nHash : vecHashes) {
            if (mapObjects.find(nHash) == mapObjects.end()) {
                vecHashesFiltered.push_back(nHash);
            }
        }
    }

    LogPrint(BCLog::GOBJECT, "CGovernanceObject::RequestOrphanObjects -- number objects = %d\n", vecHashesFiltered.size());
    for (const uint256& nHash : vecHashesFiltered) {
        for (CNode* pnode : snap.Nodes()) {
            if (!pnode->CanRelay()) {
                continue;
            }
            RequestGovernanceObject(pnode, nHash, connman);
        }
    }
}

void CGovernanceManager::CleanOrphanObjects()
{
    LOCK(cs);
    const vote_cmm_t::list_t& items = cmmapOrphanVotes.GetItemList();

    int64_t nNow = GetTime<std::chrono::seconds>().count();

    auto it = items.begin();
    while (it != items.end()) {
        auto prevIt = it;
        ++it;
        const vote_time_pair_t& pairVote = prevIt->value;
        if (pairVote.second < nNow) {
            EraseOrphanVote(prevIt->key, prevIt->value);
        }
    }
}

bool CGovernanceManager::FlushCacheToDisk(bool fSync)
{
    return m_sb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync);
}
bool CGovernanceManager::UndoBlock(const CBlockIndex* pindex)
{
    // UndoSpecialTxsInBlock closes readiness before branch-bound state is
    // rolled back. Keep this idempotent closure for direct callers; UpdateTip
    // will bind and publish the exact parent snapshot synchronously.
    ObserveChainTip(nullptr);
    if (CSuperblock::IsValidBlockHeight(pindex->nHeight)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceManager::UndoBlock -- Removing superblock at height from SB cache: %d\n", pindex->nHeight);
        m_sb->EraseCache(pindex->GetBlockHash());
    }
    return true;
}
bool AreSuperblocksEnabled()
{
    return sporkManager->IsSporkActive(SPORK_9_SUPERBLOCKS_ENABLED);
}
