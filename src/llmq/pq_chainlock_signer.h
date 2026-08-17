// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_SIGNER_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_SIGNER_H

#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_signer_journal.h>

#include <array>
#include <cstdint>
#include <optional>

namespace llmq::pq {

enum class ChainLockSigningError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_SCHEDULE,
    INELIGIBLE_HEIGHT,
    INVALID_CONTEXT,
    INVALID_QUORUM_SLOT,
    INACTIVE_QUORUM,
    INVALID_MEMBER,
    WRONG_OPERATOR,
    SECRET_KEY_MISMATCH,
    JOURNAL_CONFLICT,
    JOURNAL_CONSUMED,
    USAGE_CAP_EXHAUSTED,
    JOURNAL_FAILURE,
    SIGNING_FAILURE,
};

struct ChainLockSigningResult {
    std::optional<ChainLockShare> share;
    bool replayed{false};
};

/**
 * The sole child-key signing entry point. Callers must first fully validate the
 * candidate block and previous ChainLock; this class independently enforces
 * schedule, roster, key identity, transcript, and burn-before-sign rules.
 */
class ChainLockShareSigner final {
public:
    ChainLockShareSigner(uint256 genesis_hash,
                         uint256 local_pro_tx_hash,
                         ChainLockScheduleConfig schedule,
                         CPQSignerJournal& journal);

    [[nodiscard]] ChainLockSigningResult Sign(
        const ChainLockStatement& statement,
        const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
        uint8_t quorum_slot,
        uint16_t member_index,
        const sphincs_c11::SecretKey& child_secret_key,
        const ChildKeyProof& child_key_proof,
        const std::optional<PQSignerBranchLock>& expected_branch_lock,
        ChainLockSigningError* error = nullptr);

private:
    uint256 m_genesis_hash;
    uint256 m_local_pro_tx_hash;
    ChainLockScheduleConfig m_schedule;
    CPQSignerJournal& m_journal;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_SIGNER_H
