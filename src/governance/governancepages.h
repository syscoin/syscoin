// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_GOVERNANCEPAGES_H
#define SYSCOIN_GOVERNANCE_GOVERNANCEPAGES_H

#include <protocol.h>
#include <uint256.h>

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

/**
 * Shared accounting for immutable governance snapshots retained by page
 * sessions. The bound is global, so reconnects and concurrent peers can pin
 * old generations without multiplying memory past the governance cache's own
 * maximum serialized size.
 */
class GovernancePageSnapshotBudget final
{
public:
    static constexpr std::size_t MAX_RETAINED_BYTES{768ULL << 20};

    [[nodiscard]] bool Reserve(std::size_t bytes) noexcept
    {
        if (bytes == 0 || bytes > MAX_RETAINED_BYTES) return false;
        std::size_t retained{m_retained.load(std::memory_order_relaxed)};
        while (retained <= MAX_RETAINED_BYTES - bytes) {
            if (m_retained.compare_exchange_weak(
                    retained, retained + bytes,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    void Release(std::size_t bytes) noexcept
    {
        const std::size_t previous{
            m_retained.fetch_sub(bytes, std::memory_order_acq_rel)};
        assert(previous >= bytes);
    }

    [[nodiscard]] std::size_t Retained() const noexcept
    {
        return m_retained.load(std::memory_order_acquire);
    }

private:
    std::atomic_size_t m_retained{0};
};

// A single cache miss must remain materially smaller than the aggregate
// resident budget. Larger logical scopes fail closed and require a future
// partitioned protocol instead of monopolizing validation locks.
inline constexpr std::size_t MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES{
    64ULL << 20};

struct GovernancePageSnapshotEntry
{
    CInv inv;
    std::vector<unsigned char> payload;
};

/** Incremental reservation which rolls back unless a snapshot adopts it. */
class GovernancePageSnapshotReservation final
{
public:
    explicit GovernancePageSnapshotReservation(
        std::shared_ptr<GovernancePageSnapshotBudget> budget)
        : m_budget{std::move(budget)}
    {
    }

    ~GovernancePageSnapshotReservation()
    {
        if (m_budget && m_reserved != 0 && !m_committed) {
            m_budget->Release(m_reserved);
        }
    }

    GovernancePageSnapshotReservation(
        const GovernancePageSnapshotReservation&) = delete;
    GovernancePageSnapshotReservation& operator=(
        const GovernancePageSnapshotReservation&) = delete;

    [[nodiscard]] bool Reserve(std::size_t bytes) noexcept
    {
        if (!m_budget || bytes == 0 ||
            bytes > std::numeric_limits<std::size_t>::max() - m_reserved ||
            !m_budget->Reserve(bytes)) {
            return false;
        }
        m_reserved += bytes;
        return true;
    }

    [[nodiscard]] std::size_t Reserved() const noexcept
    {
        return m_reserved;
    }

    [[nodiscard]] const std::shared_ptr<GovernancePageSnapshotBudget>&
    Budget() const noexcept
    {
        return m_budget;
    }

    void Commit() noexcept { m_committed = true; }

private:
    std::shared_ptr<GovernancePageSnapshotBudget> m_budget;
    std::size_t m_reserved{0};
    bool m_committed{false};
};

/** One exact logical inventory generation and its immutable wire payloads. */
class GovernancePageImmutableSnapshot final
{
public:
    static std::shared_ptr<const GovernancePageImmutableSnapshot> Create(
        GovernancePageSnapshotReservation&& reservation,
        uint64_t instance_id, uint64_t validation_context_epoch,
        const uint256& scope_hash, uint256 view_id,
        std::vector<GovernancePageSnapshotEntry> entries)
    {
        if (!reservation.Budget() || instance_id == 0 ||
            validation_context_epoch == 0 || view_id.IsNull() ||
            entries.size() > MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
            return {};
        }
        std::size_t retained{sizeof(GovernancePageImmutableSnapshot)};
        if (entries.capacity() >
            (std::numeric_limits<std::size_t>::max() - retained) /
                sizeof(GovernancePageSnapshotEntry)) {
            return {};
        }
        retained += entries.capacity() * sizeof(GovernancePageSnapshotEntry);
        for (const auto& entry : entries) {
            if (entry.payload.empty() ||
                entry.payload.size() >
                    MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES ||
                entry.payload.capacity() >
                    std::numeric_limits<std::size_t>::max() - retained) {
                return {};
            }
            retained += entry.payload.capacity();
        }
        if (retained > MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES ||
            retained > reservation.Reserved()) {
            return {};
        }
        auto snapshot{std::unique_ptr<GovernancePageImmutableSnapshot>{
            new GovernancePageImmutableSnapshot{
                reservation.Budget(), instance_id,
                validation_context_epoch, scope_hash,
                std::move(view_id), std::move(entries),
                reservation.Reserved()}}};
        reservation.Commit();
        return std::shared_ptr<const GovernancePageImmutableSnapshot>{
            std::move(snapshot)};
    }

    ~GovernancePageImmutableSnapshot()
    {
        m_budget->Release(m_retained_bytes);
    }

    GovernancePageImmutableSnapshot(
        const GovernancePageImmutableSnapshot&) = delete;
    GovernancePageImmutableSnapshot& operator=(
        const GovernancePageImmutableSnapshot&) = delete;

    [[nodiscard]] uint64_t InstanceId() const noexcept
    {
        return m_instance_id;
    }
    [[nodiscard]] uint64_t ValidationContextEpoch() const noexcept
    {
        return m_validation_context_epoch;
    }
    [[nodiscard]] const uint256& ScopeHash() const noexcept
    {
        return m_scope_hash;
    }
    [[nodiscard]] const uint256& ViewId() const noexcept
    {
        return m_view_id;
    }
    [[nodiscard]] uint32_t TotalCount() const noexcept
    {
        return static_cast<uint32_t>(m_entries.size());
    }
    [[nodiscard]] const std::vector<GovernancePageSnapshotEntry>& Entries()
        const noexcept
    {
        return m_entries;
    }
    [[nodiscard]] std::size_t RetainedBytes() const noexcept
    {
        return m_retained_bytes;
    }

private:
    GovernancePageImmutableSnapshot(
        std::shared_ptr<GovernancePageSnapshotBudget> budget,
        uint64_t instance_id, uint64_t validation_context_epoch,
        uint256 scope_hash, uint256 view_id,
        std::vector<GovernancePageSnapshotEntry> entries,
        std::size_t retained_bytes)
        : m_budget{std::move(budget)},
          m_instance_id{instance_id},
          m_validation_context_epoch{validation_context_epoch},
          m_scope_hash{std::move(scope_hash)},
          m_view_id{std::move(view_id)},
          m_entries{std::move(entries)},
          m_retained_bytes{retained_bytes}
    {
    }

    std::shared_ptr<GovernancePageSnapshotBudget> m_budget;
    uint64_t m_instance_id{0};
    uint64_t m_validation_context_epoch{0};
    uint256 m_scope_hash;
    uint256 m_view_id;
    std::vector<GovernancePageSnapshotEntry> m_entries;
    std::size_t m_retained_bytes{0};
};

struct GovernancePageBuildResult
{
    CGovernancePageResponse response;
    std::shared_ptr<const GovernancePageImmutableSnapshot> snapshot;
    std::vector<std::size_t> entry_indices;
};

struct GovernancePageObjectHashesResult
{
    uint8_t status{GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE};
    std::vector<uint256> hashes;
};

#endif // SYSCOIN_GOVERNANCE_GOVERNANCEPAGES_H
