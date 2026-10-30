// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_QUORUM_OVERLAY_H
#define SYSCOIN_LLMQ_PQ_QUORUM_OVERLAY_H

#include <llmq/pq_quorum_builder.h>

#include <saltedhasher.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <unordered_set>
#include <vector>

class CBlockIndex;
class CConnman;

namespace llmq {

using PQQuorumConnectionSet =
    std::unordered_set<uint256, StaticSaltedHasher>;
using PQQuorumOverlayPlan = std::map<uint256, PQQuorumConnectionSet>;
using PQChainLockPredecessorHeight =
    std::function<std::optional<int32_t>()>;

struct PQQuorumOverlayPredecessor {
    int32_t height{-1};
    uint256 block_hash;

    friend bool operator==(const PQQuorumOverlayPredecessor&,
                           const PQQuorumOverlayPredecessor&) = default;
};

enum class PQQuorumOverlayTargetMode : uint8_t {
    ORDINARY,
    ROSTER_INITIALIZATION,
};

struct PQQuorumOverlayTarget {
    int32_t height{-1};
    uint256 block_hash;
    PQQuorumOverlayTargetMode mode{PQQuorumOverlayTargetMode::ORDINARY};

    friend bool operator==(const PQQuorumOverlayTarget&,
                           const PQQuorumOverlayTarget&) = default;
};

/** Resolve the current relay target, including a missed-window recovery. */
[[nodiscard]] std::optional<int32_t> GetPQQuorumOverlayTargetHeight(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t predecessor_height,
    int32_t tip_height) noexcept;

/**
 * Select a bounded directed ring-plus-shortcuts neighborhood.
 *
 * Every signer has an edge to its successor, so the honest overlay remains a
 * single relay ring when all roster members are reachable. Power-of-two
 * shortcuts reduce propagation diameter without creating an all-to-all
 * connection requirement.
 */
[[nodiscard]] PQQuorumConnectionSet GetPQQuorumRelayConnections(
    const pq::FrozenQuorumRoster& roster,
    const uint256& local_pro_tx_hash);

/**
 * Select the same bounded neighborhood over the union of all active rosters.
 * A single connected overlay is required because each final certificate needs
 * three independently selected roster thresholds.
 */
[[nodiscard]] PQQuorumConnectionSet GetPQQuorumUnionRelayConnections(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash);

/** Runtime-only identity of one collector generation's additional local-share routes. */
struct PQShareRelayFallbackKey {
    uint256 context_hash;
    uint256 local_pro_tx_hash;
    uint64_t admission_generation{0};
    uint64_t collector_generation{0};
    friend bool operator==(const PQShareRelayFallbackKey&, const PQShareRelayFallbackKey&) = default;
};

/**
 * Bounded exploration of an already shuffled frozen eligible union. The caller
 * owns authentication and only reannounces its own journaled shares. Remote
 * progress cannot reset the grace period or delay the next exploration step.
 */
class PQShareRelayFallback final {
public:
    static constexpr int64_t GRACE_SECONDS{30};
    static constexpr int64_t ROTATION_SECONDS{60};
    static constexpr std::size_t MAX_EXTRA_CONNECTIONS{4};

    bool Start(PQShareRelayFallbackKey key, std::vector<uint256> candidates,
               int64_t now_seconds);
    /** Advance by at most one candidate; true means the connection set changed. */
    bool Advance(int64_t now_seconds, bool certificate_complete);
    void Reset();
    const std::optional<PQShareRelayFallbackKey>& Key() const { return m_key; }
    const PQQuorumConnectionSet& Members() const { return m_members; }

private:
    std::optional<PQShareRelayFallbackKey> m_key;
    std::vector<uint256> m_candidates;
    std::vector<uint256> m_selected;
    PQQuorumConnectionSet m_members;
    std::size_t m_next{0};
    int64_t m_started{0};
    int64_t m_last_attempt{0};
    bool m_attempted{false};
    bool m_complete{false};
};

/** Frozen candidates excluding the local identity and its normal relay edges. */
[[nodiscard]] std::vector<uint256> BuildPQShareRelayFallbackCandidates(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash);

/** Build one context-bound union group when the local signer participates. */
[[nodiscard]] PQQuorumOverlayPlan BuildPQQuorumOverlayPlan(
    const uint256& genesis_hash,
    int32_t target_height,
    const uint256& target_block_hash,
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash);

/** Install the exact plan already derived by a prepared signing context. */
[[nodiscard]] PQQuorumOverlayPlan BuildPreparedPQQuorumOverlayPlan(
    const uint256& quorum_context_hash,
    const PQQuorumConnectionSet& relay_members);

/** Reject a prepared plan after its accepted predecessor changes. */
[[nodiscard]] bool IsPreparedPQQuorumOverlaySourceCurrent(
    const std::optional<PQQuorumOverlayPredecessor>& expected,
    const std::optional<PQQuorumOverlayPredecessor>& accepted) noexcept;

/**
 * Pure reconciliation policy shared by production wiring and rollover tests.
 * Reapplying an unchanged plan is intentionally a no-op; CConnman's existing
 * quorum connector continuously retries entries that are not connected.
 */
class PQQuorumOverlayReconciler final {
public:
    using Install = std::function<void(const uint256&,
                                       const PQQuorumConnectionSet&)>;
    using Remove = std::function<void(const uint256&)>;

    PQQuorumOverlayReconciler(Install install, Remove remove);

    void Apply(const PQQuorumOverlayPlan& plan, bool force_install = false);
    void Clear();

    [[nodiscard]] const PQQuorumOverlayPlan& GetInstalledPlan() const noexcept
    {
        return m_installed;
    }

private:
    Install m_install;
    Remove m_remove;
    PQQuorumOverlayPlan m_installed;
};

/** Maintains the connected union of four frozen ChainLock rosters. */
class CPQQuorumConnectionOverlay final {
public:
    CPQQuorumConnectionOverlay(
        CConnman& connman,
        pq::FrozenQuorumRosterCachePtr roster_cache,
        PQChainLockPredecessorHeight predecessor_height,
        pq::BTCCScheduleConfig btcc_schedule = {});
    ~CPQQuorumConnectionOverlay();

    CPQQuorumConnectionOverlay(const CPQQuorumConnectionOverlay&) = delete;
    CPQQuorumConnectionOverlay& operator=(
        const CPQQuorumConnectionOverlay&) = delete;

    void UpdatedBlockTip(const CBlockIndex* new_tip, bool initial_download)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Nonempty fallback routes must identify their local owner and exact target. */
    [[nodiscard]] bool ApplyPreparedContext(
        const uint256& quorum_context_hash,
        const PQQuorumConnectionSet& relay_members,
        const std::optional<PQQuorumOverlayPredecessor>& accepted_predecessor,
        const PQQuorumConnectionSet& fallback_members = {},
        const uint256& local_pro_tx_hash = {},
        const std::optional<PQQuorumOverlayTarget>& prepared_target = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Remove only temporary local-share routes, keeping ordinary plans intact. */
    void ClearChainLockFallback() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool ApplyPaymentAuditContext(
        const uint256& group,
        const PQQuorumConnectionSet& relay_members,
        uint64_t runtime_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool RemovePaymentAuditContext(
        const uint256& group,
        uint64_t runtime_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Context {
        uint256 local_pro_tx_hash;
        uint32_t global_key_version{0};
        pq::GlobalPublicKey global_public_key{};
        int32_t target_height{-1};
        uint256 target_block_hash;
        PQQuorumOverlayPredecessor accepted_predecessor;
        uint32_t newest_epoch{0};
        uint256 newest_base_hash;
        uint256 roster_beacon_bundle_hash;

        friend bool operator==(const Context&, const Context&) = default;
    };

    struct FallbackContext {
        uint256 quorum_context_hash;
        uint256 local_pro_tx_hash;
        uint32_t global_key_version{0};
        pq::GlobalPublicKey global_public_key{};
        PQQuorumOverlayTarget target;
        std::optional<PQQuorumOverlayPredecessor> accepted_predecessor;

        friend bool operator==(const FallbackContext&, const FallbackContext&) = default;
    };

    const pq::FrozenQuorumRosterCachePtr m_roster_cache;
    const PQChainLockPredecessorHeight m_predecessor_height;
    // The roster config may omit BTCC when recovery refresh is disabled.
    const pq::BTCCScheduleConfig m_btcc_schedule;
    Mutex m_mutex;
    struct PaymentAuditPlan {
        uint256 group;
        PQQuorumConnectionSet relay_members;
        uint64_t runtime_generation{0};
    };

    void ReconcileLocked(bool force_install = false) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ClearLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ClearChainLockFallbackLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    PQQuorumOverlayReconciler m_reconciler GUARDED_BY(m_mutex);
    PQQuorumOverlayPlan m_chainlock_plan GUARDED_BY(m_mutex);
    PQQuorumOverlayPlan m_chainlock_fallback GUARDED_BY(m_mutex);
    std::optional<FallbackContext> m_fallback_context GUARDED_BY(m_mutex);
    std::optional<PaymentAuditPlan> m_payment_audit_plan
        GUARDED_BY(m_mutex);
    uint64_t m_retired_payment_audit_generation GUARDED_BY(m_mutex){0};
    std::optional<Context> m_context GUARDED_BY(m_mutex);
    uint64_t m_revision GUARDED_BY(m_mutex){0};
};

extern CPQQuorumConnectionOverlay* pqQuorumConnectionOverlay;

} // namespace llmq

#endif // SYSCOIN_LLMQ_PQ_QUORUM_OVERLAY_H
