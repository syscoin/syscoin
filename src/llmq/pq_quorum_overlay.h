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

class CBlockIndex;
class CConnman;

namespace llmq {

using PQQuorumConnectionSet =
    std::unordered_set<uint256, StaticSaltedHasher>;
using PQQuorumOverlayPlan = std::map<uint256, PQQuorumConnectionSet>;
using PQChainLockPredecessorHeight =
    std::function<std::optional<int32_t>()>;

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

/** Build one context-bound union group when the local signer participates. */
[[nodiscard]] PQQuorumOverlayPlan BuildPQQuorumOverlayPlan(
    const uint256& genesis_hash,
    int32_t target_height,
    const uint256& target_block_hash,
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const uint256& local_pro_tx_hash);

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

    void Apply(const PQQuorumOverlayPlan& plan);
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
        PQChainLockPredecessorHeight predecessor_height);
    ~CPQQuorumConnectionOverlay();

    CPQQuorumConnectionOverlay(const CPQQuorumConnectionOverlay&) = delete;
    CPQQuorumConnectionOverlay& operator=(
        const CPQQuorumConnectionOverlay&) = delete;

    void UpdatedBlockTip(const CBlockIndex* new_tip, bool initial_download)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Context {
        uint256 local_pro_tx_hash;
        uint32_t newest_epoch{0};
        uint256 newest_base_hash;

        friend bool operator==(const Context&, const Context&) = default;
    };

    const pq::FrozenQuorumRosterCachePtr m_roster_cache;
    const PQChainLockPredecessorHeight m_predecessor_height;
    Mutex m_mutex;
    void ClearLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    PQQuorumOverlayReconciler m_reconciler GUARDED_BY(m_mutex);
    std::optional<Context> m_context GUARDED_BY(m_mutex);
};

extern CPQQuorumConnectionOverlay* pqQuorumConnectionOverlay;

} // namespace llmq

#endif // SYSCOIN_LLMQ_PQ_QUORUM_OVERLAY_H
