// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_GOVERNANCEPAGES_H
#define SYSCOIN_GOVERNANCE_GOVERNANCEPAGES_H

#include <protocol.h>
#include <span.h>
#include <uint256.h>
#include <util/fs.h>

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <random.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/**
 * Shared accounting for immutable governance snapshots retained by page
 * sessions. Ordinary allocations share a global bound. One admitted scope
 * whose metadata exceeds that bound may hold an exclusive reservation, so
 * peers cannot multiply retention of such generations.
 */
class GovernancePageSnapshotBudget final
{
public:
    static constexpr std::size_t MAX_RETAINED_BYTES{768ULL << 20};
    // Ordinary generations share space for twice the maximum serialized
    // governance cache. A larger already-admitted scope can additionally hold
    // one exclusive reservation for its exact preflight payload size, so the
    // ordinary quota does not become a new per-scope admission limit.
    static constexpr std::size_t MAX_SPOOLED_BYTES{
        2 * MAX_RETAINED_BYTES};

    explicit GovernancePageSnapshotBudget(
        std::size_t max_spooled_bytes = MAX_SPOOLED_BYTES,
        std::size_t max_retained_bytes = MAX_RETAINED_BYTES)
        : m_max_spooled_bytes{max_spooled_bytes},
          m_max_retained_bytes{max_retained_bytes}
    {
        assert(max_spooled_bytes > 0 &&
               max_spooled_bytes <= MAX_SPOOLED_BYTES);
        assert(max_retained_bytes > 0 &&
               max_retained_bytes <= MAX_RETAINED_BYTES);
    }

    [[nodiscard]] bool Reserve(std::size_t bytes) noexcept
    {
        if (bytes == 0 || bytes > m_max_retained_bytes) return false;
        std::size_t retained{m_retained.load(std::memory_order_relaxed)};
        while (retained <= m_max_retained_bytes - bytes) {
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
        return m_retained.load(std::memory_order_acquire) +
            m_oversized_metadata.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::size_t RetainedLimit() const noexcept
    {
        return m_max_retained_bytes;
    }

    /** Exclusive storage for metadata of one trusted, preflighted scope. */
    [[nodiscard]] bool ReserveOversizedMetadata(std::size_t bytes) noexcept
    {
        if (bytes <= m_max_retained_bytes ||
            bytes > std::numeric_limits<std::size_t>::max() -
                m_max_retained_bytes) {
            return false;
        }
        std::size_t expected{0};
        return m_oversized_metadata.compare_exchange_strong(
            expected, bytes, std::memory_order_acq_rel,
            std::memory_order_relaxed);
    }

    [[nodiscard]] bool GrowOversizedMetadata(
        std::size_t old_size, std::size_t extra) noexcept
    {
        if (old_size <= m_max_retained_bytes || extra == 0 ||
            old_size > std::numeric_limits<std::size_t>::max() -
                m_max_retained_bytes ||
            extra > std::numeric_limits<std::size_t>::max() -
                m_max_retained_bytes - old_size) {
            return false;
        }
        return m_oversized_metadata.compare_exchange_strong(
            old_size, old_size + extra, std::memory_order_acq_rel,
            std::memory_order_relaxed);
    }

    void ReleaseOversizedMetadata(std::size_t bytes) noexcept
    {
        assert(bytes > m_max_retained_bytes);
        std::size_t expected{bytes};
        const bool released{m_oversized_metadata.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel,
            std::memory_order_relaxed)};
        assert(released);
        (void)released;
    }

    [[nodiscard]] bool ReserveSpooled(std::size_t bytes) noexcept
    {
        if (bytes == 0) return false;
        if (bytes > m_max_spooled_bytes) {
            // Only trusted full-scope preflight sizes may request this lease.
            // Keep addition with the ordinary quota representable, including
            // while a concurrent reader observes both accounting counters.
            if (bytes > std::numeric_limits<std::size_t>::max() -
                    m_max_spooled_bytes) {
                return false;
            }
            std::size_t expected{0};
            return m_oversized_spooled.compare_exchange_strong(
                expected, bytes, std::memory_order_acq_rel,
                std::memory_order_relaxed);
        }
        std::size_t spooled{m_spooled.load(std::memory_order_relaxed)};
        while (spooled <= m_max_spooled_bytes - bytes) {
            if (m_spooled.compare_exchange_weak(
                    spooled, spooled + bytes,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    void ReleaseSpooled(std::size_t bytes) noexcept
    {
        if (bytes > m_max_spooled_bytes) {
            std::size_t expected{bytes};
            const bool released{m_oversized_spooled.compare_exchange_strong(
                expected, 0, std::memory_order_acq_rel,
                std::memory_order_relaxed)};
            assert(released);
            (void)released;
            return;
        }
        const std::size_t previous{
            m_spooled.fetch_sub(bytes, std::memory_order_acq_rel)};
        assert(previous >= bytes);
    }

    [[nodiscard]] std::size_t Spooled() const noexcept
    {
        return m_spooled.load(std::memory_order_acquire) +
            m_oversized_spooled.load(std::memory_order_acquire);
    }

private:
    const std::size_t m_max_spooled_bytes;
    const std::size_t m_max_retained_bytes;
    std::atomic_size_t m_retained{0};
    std::atomic_size_t m_oversized_metadata{0};
    std::atomic_size_t m_spooled{0};
    std::atomic_size_t m_oversized_spooled{0};
};

// Keep small snapshots in memory; larger snapshots spill immutable payloads.
inline constexpr std::size_t MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES{
    64ULL << 20};

/** Append-only temporary payload storage, immutable after sealing. */
class GovernancePagePayloadSpool final
{
public:
    static std::shared_ptr<GovernancePagePayloadSpool> Create(
        std::shared_ptr<GovernancePageSnapshotBudget> budget,
        std::size_t expected_payload_bytes)
    {
        if (!budget || expected_payload_bytes == 0 ||
            expected_payload_bytes > MaxOffset()) {
            return {};
        }
        try {
            auto spool{std::unique_ptr<GovernancePagePayloadSpool>{
                new GovernancePagePayloadSpool{
                    budget, expected_payload_bytes}}};
            if (!budget->ReserveSpooled(expected_payload_bytes)) return {};
            spool->m_reserved_bytes = expected_payload_bytes;
            spool->m_file = OpenTemporaryFile();
            if (!spool->m_file ||
                std::setvbuf(spool->m_file, nullptr, _IONBF, 0) != 0) {
                return {};
            }
            return std::shared_ptr<GovernancePagePayloadSpool>{
                std::move(spool)};
        } catch (const std::bad_alloc&) {
            return {};
        } catch (const fs::filesystem_error&) {
            return {};
        }
    }

    ~GovernancePagePayloadSpool() { Close(); }

    GovernancePagePayloadSpool(const GovernancePagePayloadSpool&) = delete;
    GovernancePagePayloadSpool& operator=(
        const GovernancePagePayloadSpool&) = delete;

    /** No stdio payload buffer is allocated: only the spool and FILE remain. */
    static constexpr std::size_t ResidentBytes() noexcept
    {
        return sizeof(GovernancePagePayloadSpool) + sizeof(std::FILE);
    }

    [[nodiscard]] const std::shared_ptr<GovernancePageSnapshotBudget>&
    Budget() const noexcept
    {
        return m_budget;
    }

    [[nodiscard]] std::optional<uint64_t> Append(
        Span<const unsigned char> payload)
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        if (!m_file || m_sealed) return {};
        if (payload.empty() ||
            payload.size() > MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES ||
            payload.size() > m_expected_bytes - m_size) {
            Close();
            return {};
        }
        const uint64_t offset{m_size};
        m_size += payload.size();
        if (std::fwrite(payload.data(), 1, payload.size(), m_file) !=
                payload.size()) {
            Close();
            return {};
        }
        return offset;
    }

    [[nodiscard]] bool Seal()
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        if (!m_file) return false;
        if (m_sealed) return true;
        if (m_size != m_expected_bytes || std::fflush(m_file) != 0) {
            Close();
            return false;
        }
        m_sealed = true;
        return true;
    }

    [[nodiscard]] bool Contains(uint64_t offset, std::size_t size) const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        return ContainsLocked(offset, size);
    }

    [[nodiscard]] bool Read(uint64_t offset, std::size_t size,
                            std::vector<unsigned char>& payload) const
    {
        payload.clear();
        std::lock_guard<std::mutex> lock{m_mutex};
        if (!ContainsLocked(offset, size)) return false;
#ifdef _WIN32
        const int seek_result{::_fseeki64(
            m_file, static_cast<__int64>(offset), SEEK_SET)};
#else
        const int seek_result{::fseeko(
            m_file, static_cast<off_t>(offset), SEEK_SET)};
#endif
        if (seek_result != 0) {
            Close();
            return false;
        }
        try {
            payload.resize(size);
        } catch (const std::bad_alloc&) {
            return false;
        }
        if (std::fread(payload.data(), 1, size, m_file) != size) {
            payload.clear();
            Close();
            return false;
        }
        return true;
    }

private:
    GovernancePagePayloadSpool(
        std::shared_ptr<GovernancePageSnapshotBudget> budget,
        std::size_t expected_payload_bytes)
        : m_budget{std::move(budget)}, m_expected_bytes{expected_payload_bytes}
    {
    }

    static std::FILE* OpenTemporaryFile()
    {
        std::error_code error;
        const fs::path directory{fs::temp_directory_path(error)};
        if (error || directory.empty()) return nullptr;
#ifdef _WIN32
        // Unlike MSVC tmpfile(), the user's temporary directory does not
        // require permission to create files in a drive's root directory.
        // Exclusive creation avoids opening existing files or following a
        // colliding name; the OS removes the file when its handle closes.
        for (int attempt{0}; attempt < 8; ++attempt) {
            const fs::path path{directory / fs::u8path(
                "syscoin-governance-" + GetRandHash().GetHex())};
            const HANDLE handle{::CreateFileW(
                path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, nullptr)};
            if (handle == INVALID_HANDLE_VALUE) {
                const DWORD file_error{::GetLastError()};
                if (file_error == ERROR_FILE_EXISTS ||
                    file_error == ERROR_ALREADY_EXISTS) {
                    continue;
                }
                return nullptr;
            }
            const int descriptor{::_open_osfhandle(
                reinterpret_cast<intptr_t>(handle), _O_BINARY)};
            if (descriptor == -1) {
                ::CloseHandle(handle);
                return nullptr;
            }
            std::FILE* file{::_fdopen(descriptor, "w+b")};
            if (!file) ::_close(descriptor);
            return file;
        }
        return nullptr;
#else
        auto path{fs::PathToString(directory / "syscoin-governance-XXXXXX")};
        const int descriptor{::mkstemp(path.data())};
        if (descriptor == -1) return nullptr;
        const int unlink_result{::unlink(path.c_str())};
        if (unlink_result != 0 ||
            ::fcntl(descriptor, F_SETFD, FD_CLOEXEC) == -1) {
            ::close(descriptor);
            return nullptr;
        }
        std::FILE* file{::fdopen(descriptor, "w+b")};
        if (!file) ::close(descriptor);
        return file;
#endif
    }

    static constexpr uint64_t MaxOffset() noexcept
    {
#ifdef _WIN32
        return std::numeric_limits<__int64>::max();
#else
        return std::numeric_limits<off_t>::max();
#endif
    }

    bool ContainsLocked(uint64_t offset, std::size_t size) const noexcept
    {
        return m_file && m_sealed && size != 0 &&
            size <= MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES &&
            offset <= m_size && size <= m_size - offset;
    }

    // Call only while holding m_mutex, or during destruction. A failed I/O
    // operation invalidates the entire spool and removes its temporary file.
    void Close() const noexcept
    {
        if (m_file) {
            std::fclose(m_file);
            m_file = nullptr;
        }
        if (m_reserved_bytes != 0) {
            m_budget->ReleaseSpooled(m_reserved_bytes);
            m_reserved_bytes = 0;
        }
        m_size = 0;
    }

    const std::shared_ptr<GovernancePageSnapshotBudget> m_budget;
    mutable std::mutex m_mutex;
    const std::size_t m_expected_bytes;
    mutable std::FILE* m_file{nullptr};
    mutable std::size_t m_reserved_bytes{0};
    mutable uint64_t m_size{0};
    bool m_sealed{false};
};

struct GovernancePageSnapshotEntry
{
    CInv inv;
    std::vector<unsigned char> payload;
    uint64_t payload_offset{0};
    uint32_t payload_size{0};

    [[nodiscard]] std::size_t PayloadSize() const noexcept
    {
        return payload.empty() ? payload_size : payload.size();
    }
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
            if (m_oversized_metadata) {
                m_budget->ReleaseOversizedMetadata(m_reserved);
            } else {
                m_budget->Release(m_reserved);
            }
        }
    }

    GovernancePageSnapshotReservation(
        const GovernancePageSnapshotReservation&) = delete;
    GovernancePageSnapshotReservation& operator=(
        const GovernancePageSnapshotReservation&) = delete;

    [[nodiscard]] bool Reserve(
        std::size_t bytes, bool allow_oversized_metadata = false) noexcept
    {
        if (!m_budget || m_committed || bytes == 0 ||
            bytes > std::numeric_limits<std::size_t>::max() - m_reserved) {
            return false;
        }
        if (m_oversized_metadata) {
            if (!m_budget->GrowOversizedMetadata(m_reserved, bytes)) {
                return false;
            }
        } else if (allow_oversized_metadata &&
                   m_reserved + bytes > m_budget->RetainedLimit()) {
            // Acquire the full exclusive reservation before releasing the
            // original charge, so failed promotion leaves it intact.
            if (!m_budget->ReserveOversizedMetadata(m_reserved + bytes)) {
                return false;
            }
            if (m_reserved != 0) m_budget->Release(m_reserved);
            m_oversized_metadata = true;
        } else if (!m_budget->Reserve(bytes)) {
            return false;
        }
        m_reserved += bytes;
        return true;
    }

    [[nodiscard]] std::size_t Reserved() const noexcept
    {
        return m_reserved;
    }

    [[nodiscard]] bool IsOversizedMetadata() const noexcept
    {
        return m_oversized_metadata;
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
    bool m_oversized_metadata{false};
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
        std::vector<GovernancePageSnapshotEntry> entries,
        std::shared_ptr<GovernancePagePayloadSpool> spool = {})
    {
        if (!reservation.Budget() || instance_id == 0 ||
            validation_context_epoch == 0 || view_id.IsNull() ||
            entries.size() > std::numeric_limits<uint32_t>::max() ||
            (reservation.IsOversizedMetadata() && !spool) ||
            (spool && (spool->Budget() != reservation.Budget() ||
                       !spool->Seal()))) {
            return {};
        }
        std::size_t retained{sizeof(GovernancePageImmutableSnapshot)};
        if (spool) retained += GovernancePagePayloadSpool::ResidentBytes();
        if (entries.capacity() >
            (std::numeric_limits<std::size_t>::max() - retained) /
                sizeof(GovernancePageSnapshotEntry)) {
            return {};
        }
        retained += entries.capacity() * sizeof(GovernancePageSnapshotEntry);
        for (const auto& entry : entries) {
            if (entry.PayloadSize() == 0 ||
                entry.PayloadSize() > MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES ||
                (reservation.IsOversizedMetadata() &&
                    entry.payload.capacity() != 0) ||
                (entry.payload.empty()
                    ? (!spool || !spool->Contains(
                          entry.payload_offset, entry.payload_size))
                    : (entry.payload_offset != 0 || entry.payload_size != 0)) ||
                entry.payload.capacity() >
                    std::numeric_limits<std::size_t>::max() - retained) {
                return {};
            }
            retained += entry.payload.capacity();
        }
        if (retained > reservation.Reserved()) {
            return {};
        }
        auto snapshot{std::unique_ptr<GovernancePageImmutableSnapshot>{
            new GovernancePageImmutableSnapshot{
                reservation.Budget(), instance_id,
                validation_context_epoch, scope_hash,
                std::move(view_id), std::move(entries),
                std::move(spool), reservation.Reserved(),
                reservation.IsOversizedMetadata()}}};
        reservation.Commit();
        return std::shared_ptr<const GovernancePageImmutableSnapshot>{
            std::move(snapshot)};
    }

    ~GovernancePageImmutableSnapshot()
    {
        // Free retained storage before admitting a replacement generation.
        std::vector<GovernancePageSnapshotEntry>{}.swap(m_entries);
        m_spool.reset();
        if (m_oversized_metadata) {
            m_budget->ReleaseOversizedMetadata(m_retained_bytes);
        } else {
            m_budget->Release(m_retained_bytes);
        }
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

    [[nodiscard]] bool ReadPayload(
        std::size_t index, std::vector<unsigned char>& payload) const
    {
        payload.clear();
        if (index >= m_entries.size()) return false;
        const auto& entry{m_entries[index]};
        if (entry.payload.empty()) {
            return m_spool && m_spool->Read(
                entry.payload_offset, entry.payload_size, payload);
        }
        try {
            payload = entry.payload;
        } catch (const std::bad_alloc&) {
            return false;
        }
        return true;
    }

private:
    GovernancePageImmutableSnapshot(
        std::shared_ptr<GovernancePageSnapshotBudget> budget,
        uint64_t instance_id, uint64_t validation_context_epoch,
        uint256 scope_hash, uint256 view_id,
        std::vector<GovernancePageSnapshotEntry> entries,
        std::shared_ptr<GovernancePagePayloadSpool> spool,
        std::size_t retained_bytes, bool oversized_metadata)
        : m_budget{std::move(budget)},
          m_instance_id{instance_id},
          m_validation_context_epoch{validation_context_epoch},
          m_scope_hash{std::move(scope_hash)},
          m_view_id{std::move(view_id)},
          m_entries{std::move(entries)},
          m_spool{std::move(spool)},
          m_retained_bytes{retained_bytes},
          m_oversized_metadata{oversized_metadata}
    {
    }

    std::shared_ptr<GovernancePageSnapshotBudget> m_budget;
    uint64_t m_instance_id{0};
    uint64_t m_validation_context_epoch{0};
    uint256 m_scope_hash;
    uint256 m_view_id;
    std::vector<GovernancePageSnapshotEntry> m_entries;
    std::shared_ptr<GovernancePagePayloadSpool> m_spool;
    std::size_t m_retained_bytes{0};
    const bool m_oversized_metadata;
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
