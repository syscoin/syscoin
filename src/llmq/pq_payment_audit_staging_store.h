// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STAGING_STORE_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STAGING_STORE_H

#include <dbwrapper.h>
#include <llmq/pq_payment_audit.h>
#include <sync.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace llmq::pq {

enum class PaymentAuditStagingResult : uint8_t {
    ACCEPTED = 0,
    DUPLICATE,
    NOT_FOUND,
    WRONG_EPOCH,
    BRANCH_CONFLICT,
    FROZEN,
    DEADLINE_REACHED,
    CAPACITY_EXCEEDED,
    INVALID,
    CORRUPT,
    DATABASE_ERROR,
};

/** One open, branch-bound response row. */
struct PaymentAuditStagingRow {
    PaymentAuditHave expected;
    int32_t deadline_height{-1};
    uint256 response_block_hash;
    QuorumBitmap subject_valid_members{};
    BTCCAdvance response_advance{BTCCAdvance::ADVANCE};
    std::map<uint16_t, PaymentAuditResponse> responses;

    [[nodiscard]] bool IsStructurallyValid(
        const uint256& genesis_hash) const noexcept;
    friend bool operator==(const PaymentAuditStagingRow&,
                           const PaymentAuditStagingRow&) = default;
};

/** Fixed-size open-row state used for network admission and inventory. */
struct PaymentAuditOpenRowMetadata {
    PaymentAuditHave expected;
    int32_t deadline_height{-1};
    uint256 response_block_hash;
    QuorumBitmap subject_valid_members{};
    QuorumBitmap available_members{};
    BTCCAdvance response_advance{BTCCAdvance::ADVANCE};

    friend bool operator==(const PaymentAuditOpenRowMetadata&,
                           const PaymentAuditOpenRowMetadata&) = default;
};

/**
 * Compact result produced only by the row's successful same-database sync
 * barrier. Raw response signatures are no longer needed after this record is
 * durable: the eventual 801-signature audit certificate attests the selected
 * result to historical validators.
 */
struct PaymentAuditFrozenRowSummary {
    PaymentAuditHave identity;
    int32_t deadline_height{-1};
    uint256 response_block_hash;
    uint256 deadline_block_hash;
    QuorumBitmap subject_valid_members{};
    // This node's verified A-row evidence, not a consensus/common report.
    QuorumBitmap locally_observed_members{};
    BTCCAdvance response_advance{BTCCAdvance::ADVANCE};

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditFrozenRowSummary&,
                           const PaymentAuditFrozenRowSummary&) = default;
};

/** Test-only failure hook invoked immediately before a real sync barrier. */
using PaymentAuditStagingSyncHook = std::function<bool()>;

/**
 * Crash-safe bounded staging for retrospective payment audits.
 *
 * Responses use asynchronous WAL batches and are relayed only after that
 * write succeeds. At a row deadline, one fSync batch durably orders every
 * preceding response, writes the compact summary, and deletes the raw row.
 * Thus a durable summary can never refer to responses omitted by a crash.
 * A crash before the barrier may lose an open row and simply forces abstention.
 */
class PaymentAuditStagingStore final {
public:
    static constexpr uint32_t DB_FORMAT_VERSION{1};
    static constexpr std::size_t MAX_OPEN_ROWS{2};

    PaymentAuditStagingStore(
        fs::path path,
        uint256 genesis_hash,
        std::size_t cache_bytes = 8 << 20,
        bool wipe = false,
        PaymentAuditStagingSyncHook sync_hook = {});
    ~PaymentAuditStagingStore();

    [[nodiscard]] bool IsHealthy() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<uint32_t> ActiveEpoch() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<uint32_t> RetainedEpoch() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Start one epoch, retain the immediately preceding epoch's compact
     * summaries for its delayed B, and discard all obsolete/open old rows.
     */
    [[nodiscard]] PaymentAuditStagingResult ActivateEpoch(uint32_t epoch)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] PaymentAuditStagingResult EnsureRow(
        const PaymentAuditStagingRow& row)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] PaymentAuditStagingResult ReplaceRowBranch(
        const PaymentAuditStagingRow& row)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Drop branch-stale, unsealed evidence; a missing summary means abstain. */
    [[nodiscard]] PaymentAuditStagingResult DiscardOpenRow(
        uint32_t epoch, uint8_t row_index)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Async WAL acceptance; callers may relay only after ACCEPTED. */
    [[nodiscard]] PaymentAuditStagingResult AddVerifiedResponse(
        uint32_t epoch,
        uint8_t row_index,
        int32_t observed_tip_height,
        const PaymentAuditResponse& response)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Sync, summarize, and atomically erase the raw row and responses. */
    [[nodiscard]] PaymentAuditStagingResult FreezeRow(
        uint32_t epoch,
        uint8_t row_index,
        const uint256& response_block_hash,
        const uint256& deadline_block_hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] std::optional<PaymentAuditStagingRow> GetOpenRow(
        uint32_t epoch, uint8_t row_index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::vector<PaymentAuditStagingRow> GetOpenRows(
        uint32_t epoch) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PaymentAuditOpenRowMetadata>
    GetOpenRowMetadata(uint32_t epoch, uint8_t row_index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::vector<PaymentAuditOpenRowMetadata>
    GetOpenRowsMetadata(uint32_t epoch) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Copy only requested responses from the exact open-row identity. */
    [[nodiscard]] std::optional<std::vector<PaymentAuditResponse>>
    GetVerifiedResponses(
        const PaymentAuditHave& expected,
        const QuorumBitmap& requested_members) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PaymentAuditFrozenRowSummary> GetSummary(
        uint32_t epoch, uint8_t row_index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::vector<PaymentAuditFrozenRowSummary>
    GetEpochSummaries(uint32_t epoch) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Drop a completed/expired prior-epoch audit obligation. */
    [[nodiscard]] PaymentAuditStagingResult ClearRetainedEpoch(
        uint32_t epoch) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Impl;

    uint256 m_genesis_hash;
    std::unique_ptr<Impl> m_impl;
    mutable Mutex m_mutex;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STAGING_STORE_H
