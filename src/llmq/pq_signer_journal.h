// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H
#define SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H

#include <crypto/scheduled_wots/scheduled_wots.h>
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
#include <vector>

namespace llmq {

class CChainLocksHandler;
namespace pq {
struct FinalChainLockRecordMetadata;
}
namespace test {
class PQSignerJournalTestAccess;
}

inline constexpr std::size_t PQ_CHILD_SIGNATURE_SIZE{
    scheduled_wots::SIGNATURE_SIZE};
inline constexpr std::uint16_t PQ_CHILD_USAGE_CAP{
    scheduled_wots::AUTHORIZED_LEAF_COUNT};

using PQChildSignature = std::array<unsigned char, PQ_CHILD_SIGNATURE_SIZE>;

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
    std::uint8_t leaf_index{0xff};
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
                  obj.leaf_index,
                  purpose,
                  obj.absolute_height);
        SER_READ(obj, obj.purpose = static_cast<PQSignerPurpose>(purpose));
    }
};

/** Physical one-time leaf identity; purpose and height are stored metadata. */
struct PQSignerJournalLeafKey
{
    uint256 genesis_hash;
    std::uint16_t child_profile{0};
    uint256 pro_tx_hash;
    std::uint32_t quorum_epoch{0};
    uint256 child_key_hash;
    std::uint8_t leaf_index{0xff};

    explicit PQSignerJournalLeafKey(const PQSignerJournalKey& key)
        : genesis_hash{key.genesis_hash},
          child_profile{key.child_profile},
          pro_tx_hash{key.pro_tx_hash},
          quorum_epoch{key.quorum_epoch},
          child_key_hash{key.child_key_hash},
          leaf_index{key.leaf_index}
    {
    }

    bool operator==(const PQSignerJournalLeafKey&) const = default;
    bool operator<(const PQSignerJournalLeafKey& other) const;

    SERIALIZE_METHODS(PQSignerJournalLeafKey, obj)
    {
        READWRITE(obj.genesis_hash, obj.child_profile, obj.pro_tx_hash,
                  obj.quorum_epoch, obj.child_key_hash, obj.leaf_index);
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
    std::optional<PQChildSignature> signature;
};

/**
 * Durable burn-before-sign state for scheduled WOTS+ child keys.
 *
 * This database must live outside chainstate/EvoDB and must never be restored,
 * rewound, or erased during a reorg. A RESERVED entry is intentionally not
 * recoverable after process restart: the signature operation might already
 * have happened, so the slot remains consumed. The local database cannot
 * detect rollback or cloning of its entire storage. A clone cannot gain extra
 * quorum weight because collectors count one frozen roster slot, but it can
 * make that identity equivocate and exceed this profile's per-key usage bound.
 * After synchronized startup, the handler therefore fsyncs tombstones for
 * absent physical slots that were already live at the captured startup tip.
 * Existing reservations and signatures remain authoritative, while future and
 * expired schedule slots are not rewritten. A coordinated restart can make
 * many operators miss the current ChainLock or audit opportunity; this bounded
 * liveness cost protects sequential restore recovery without pretending that
 * local state detects a concurrent clone.
 * Supported operation therefore keeps one active signer datadir and never
 * restores this journal behind its signing history. External monotonic leases
 * are optional hardening for clustered deployments, not a consensus rule.
 */
class CPQSignerJournal final
{
public:
    static constexpr std::uint32_t DB_FORMAT_VERSION{1};

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
        const PQChildSignature& signature) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

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
    std::map<PQSignerJournalLeafKey, PendingReservation> m_pending GUARDED_BY(m_mutex);
    std::optional<PQSignerJournalOutcome> m_failure GUARDED_BY(m_mutex);

    void Initialize() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Atomically record a fully verified, durably accepted certificate and
     * rebase this operator's lock when the certificate is at least as high.
     *
     * Only CChainLocksHandler can supply this authority, after finality-store
     * acceptance has completed its certificate fsync. The test friend exists
     * solely to exercise the crash and monotonicity invariants. Leaf-slot
     * records are deliberately outside the batch and can never be refunded.
     */
    [[nodiscard]] PQSignerJournalResult ReconcileDurableAcceptedChainLock(
        const uint256& genesis_hash,
        const uint256& pro_tx_hash,
        const pq::FinalChainLockRecordMetadata& chainlock)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Fsync explicit tombstones only for physical leaves with no record.
     * Existing reservations and signatures are left untouched so their normal
     * consumed, replay, and conflict behavior remains authoritative.
     *
     * This is private because only the local startup signing gate may retire a
     * live schedule slot without a message or branch vote.
     */
    [[nodiscard]] bool ConsumeIfAbsent(
        const std::vector<PQSignerJournalKey>& keys)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace llmq

#endif // SYSCOIN_LLMQ_PQ_SIGNER_JOURNAL_H
