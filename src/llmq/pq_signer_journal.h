// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H
#define SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H

#include <dbwrapper.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>

namespace llmq {

class CChainLocksHandler;
namespace pq {
struct FinalChainLock;
}
namespace test {
class PQSignerJournalTestAccess;
}

inline constexpr std::size_t PQ_C11_SIGNATURE_SIZE{3976};
inline constexpr std::uint16_t PQ_C11_CHILD_USAGE_CAP{256};

using PQC11Signature = std::array<unsigned char, PQ_C11_SIGNATURE_SIZE>;

enum class PQSignerPurpose : std::uint8_t {
    CHAINLOCK = 1,
    PAYMENT_AUDIT = 2,
};

/**
 * Complete identity of one usage-limited child-key signing slot.
 *
 * Eligibility is a consensus-layer decision. The journal accepts only a
 * fully validated candidate and supplies the irreversible reservation needed
 * immediately before invoking the signer.
 */
struct PQSignerJournalKey
{
    uint256 genesis_hash;
    std::uint16_t child_profile{0};
    uint256 pro_tx_hash;
    std::uint32_t quorum_epoch{0};
    uint256 child_key_hash;
    PQSignerPurpose purpose{PQSignerPurpose::CHAINLOCK};
    std::int32_t absolute_height{-1};

    bool operator==(const PQSignerJournalKey&) const = default;
    bool operator<(const PQSignerJournalKey& other) const;

    SERIALIZE_METHODS(PQSignerJournalKey, obj)
    {
        std::uint8_t purpose{static_cast<std::uint8_t>(obj.purpose)};
        READWRITE(obj.genesis_hash,
                  obj.child_profile,
                  obj.pro_tx_hash,
                  obj.quorum_epoch,
                  obj.child_key_hash,
                  purpose,
                  obj.absolute_height);
        SER_READ(obj, obj.purpose = static_cast<PQSignerPurpose>(purpose));
    }
};

/**
 * Operator-wide finality lock advanced atomically with each slot reservation.
 *
 * This is intentionally independent of a child key and epoch. Quorum rotation
 * or a child-root rotation must not let one operator sign incompatible branches.
 * The caller proves ancestry under cs_main; the journal makes that proof
 * race-free by requiring the exact lock value that was checked.
 */
struct PQSignerBranchLock
{
    std::int32_t height{-1};
    uint256 block_hash;
    uint256 statement_hash;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return height >= 0 && !block_hash.IsNull() && !statement_hash.IsNull();
    }

    bool operator==(const PQSignerBranchLock&) const = default;

    SERIALIZE_METHODS(PQSignerBranchLock, obj)
    {
        READWRITE(obj.height, obj.block_hash, obj.statement_hash);
    }
};

enum class PQSignerJournalOutcome : std::uint8_t {
    /** A durable, fsynced reservation was created; signing may begin once. */
    RESERVED,
    /** The signature was durably committed and may now be announced. */
    STORED,
    /** The same message was already signed; return the stored signature. */
    REPLAY,
    /** The slot belongs to a different message and is permanently unusable. */
    CONFLICT,
    /** The slot is reserved, but this process does not own the reservation. */
    CONSUMED,
    /** No reservation exists for a requested signature commit. */
    NOT_RESERVED,
    /** The child key has already consumed its 256 authorized heights. */
    CAP_EXHAUSTED,
    /** The candidate does not extend the exact durable operator branch lock. */
    BRANCH_CONFLICT,
    /** A durable accepted certificate replaced or initialized the branch lock. */
    CERTIFICATE_RECONCILED,
    /** The exact certificate reconciliation was already committed. */
    CERTIFICATE_REPLAY,
    /** The certificate was recorded, but a higher local branch lock remains. */
    CERTIFICATE_RECORDED,
    /** The key is structurally invalid; no database mutation occurred. */
    INVALID_ARGUMENT,
    /** Stored journal state is inconsistent or has an unsupported format. */
    CORRUPT,
    /** A database operation failed and the journal stopped accepting work. */
    DATABASE_ERROR,
};

struct PQSignerJournalResult
{
    PQSignerJournalOutcome outcome{PQSignerJournalOutcome::DATABASE_ERROR};
    std::optional<PQC11Signature> signature;
};

/**
 * Durable burn-before-sign state for C11 ChainLock child keys.
 *
 * This database must live outside chainstate/EvoDB and must never be restored,
 * rewound, or erased during a reorg. A RESERVED entry is intentionally not
 * recoverable after process restart: the signature operation might already
 * have happened, so the slot remains consumed. The local database cannot
 * detect rollback or cloning of its entire storage. A clone cannot gain extra
 * quorum weight because collectors count one frozen roster slot, but it can
 * make that identity equivocate and exceed this profile's per-key usage bound.
 * Public-network operation therefore requires an external monotonic,
 * single-active fence in addition to this crash-safety layer.
 */
class CPQSignerJournal final
{
public:
    static constexpr std::uint32_t DB_FORMAT_VERSION{3};

    explicit CPQSignerJournal(const fs::path& path, std::size_t cache_bytes = 1 << 20);

    CPQSignerJournal(const CPQSignerJournal&) = delete;
    CPQSignerJournal& operator=(const CPQSignerJournal&) = delete;

    /**
     * Fsync EMPTY -> RESERVED before returning RESERVED. REPLAY is the only
     * outcome carrying a signature and never calls a cryptographic signer.
     */
    [[nodiscard]] PQSignerJournalResult Reserve(
        const PQSignerJournalKey& key,
        const uint256& message_hash,
        const PQSignerBranchLock& candidate_lock,
        const std::optional<PQSignerBranchLock>& expected_lock)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Fsync RESERVED -> SIGNED. This succeeds only for a reservation created
     * by this live journal instance, preventing restart from reviving an
     * uncertain signing operation.
     */
    [[nodiscard]] PQSignerJournalResult StoreSignature(
        const PQSignerJournalKey& key,
        const uint256& message_hash,
        const PQC11Signature& signature) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool IsHealthy() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Read the lock that a caller must validate as an ancestor before Reserve.
     * A null result means no signature has been reserved for this operator;
     * callers must separately require IsHealthy() to distinguish DB failure.
     */
    [[nodiscard]] std::optional<PQSignerBranchLock> GetBranchLock(
        const uint256& genesis_hash,
        const uint256& pro_tx_hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    friend class CChainLocksHandler;
    friend class test::PQSignerJournalTestAccess;

    struct PendingReservation {
        uint256 message_hash;
    };

    CDBWrapper m_db;
    mutable Mutex m_mutex;
    std::map<PQSignerJournalKey, PendingReservation> m_pending GUARDED_BY(m_mutex);
    std::optional<PQSignerJournalOutcome> m_failure GUARDED_BY(m_mutex);

    void Initialize() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Atomically record a fully verified, durably accepted certificate and
     * rebase this operator's lock when the certificate is at least as high.
     *
     * Only CChainLocksHandler can supply this authority, after finality-store
     * acceptance has completed its certificate fsync. The test friend exists
     * solely to exercise the crash and monotonicity invariants. Usage and slot
     * records are deliberately outside the batch and can never be refunded.
     */
    [[nodiscard]] PQSignerJournalResult ReconcileDurableAcceptedChainLock(
        const uint256& genesis_hash,
        const uint256& pro_tx_hash,
        const pq::FinalChainLock& chainlock)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace llmq

#endif // SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H
