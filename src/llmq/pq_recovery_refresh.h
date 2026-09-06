// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_RECOVERY_REFRESH_H
#define SYSCOIN_LLMQ_PQ_RECOVERY_REFRESH_H

#include <llmq/pq_btcc.h>
#include <span.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

class CBlockIndex;
class CBlock;

namespace llmq::pq {

struct RecoveryRefreshConfig {
    // Preparation starts no earlier than activation: the whole fixed window,
    // including its readiness reference, must lie in the activated profile.
    int32_t activation_height{-1};
    uint32_t grace_groups{0};
    uint32_t snapshot_lag_blocks{0};
    uint32_t entropy_delay_blocks{0};
    uint32_t carrier_delay_blocks{0};
    uint32_t carrier_min_depth_blocks{0};
    uint32_t snapshot_min_work_blocks{0};
    uint32_t carrier_min_work_blocks{0};
    uint32_t readiness_window_blocks{0};

    [[nodiscard]] bool IsDisabled() const noexcept;
    [[nodiscard]] bool IsValid(const ChainLockScheduleConfig& chainlock,
                               const BTCCScheduleConfig& btcc) const noexcept;
    friend bool operator==(const RecoveryRefreshConfig&,
                           const RecoveryRefreshConfig&) = default;
};

[[nodiscard]] RecoveryRefreshConfig GetRecoveryRefreshConfig(
    const Consensus::Params& consensus) noexcept;

// An enabled profile must expose all four recovery epochs at its fixed key
// snapshot; a long-lived commitment cannot bypass the operator lookup horizon.
[[nodiscard]] bool IsRecoveryRefreshOperatorScheduleValid(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, uint32_t registration_cutoff_blocks,
    uint32_t future_horizon_epochs) noexcept;

struct RecoveryRefreshCoordinates {
    uint32_t group{0};
    uint32_t first_epoch{0};
    int32_t readiness_reference_height{-1};
    int32_t snapshot_height{-1};
    int32_t entropy_height{-1};
    int32_t carrier_height{-1};
    int32_t target_height{-1};
    int32_t authority_height{-1};

    friend bool operator==(const RecoveryRefreshCoordinates&,
                           const RecoveryRefreshCoordinates&) = default;
};

[[nodiscard]] std::optional<RecoveryRefreshCoordinates>
DeriveRecoveryRefreshCoordinates(const ChainLockScheduleConfig& chainlock,
                                 const BTCCScheduleConfig& btcc,
                                 const RecoveryRefreshConfig& config,
                                 uint32_t group) noexcept;

[[nodiscard]] std::optional<RecoveryRefreshCoordinates>
RecoveryRefreshCoordinatesForCarrierHeight(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t carrier_height) noexcept;

[[nodiscard]] std::optional<RecoveryRefreshCoordinates>
RecoveryRefreshCoordinatesForSnapshotHeight(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t snapshot_height) noexcept;

[[nodiscard]] std::optional<uint32_t> FirstStaleRecoveryGroup(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    int32_t latest_receipted_target_height) noexcept;

enum class RecoveryRefreshMode : uint8_t {
    FROZEN_SOURCE,
    POW_REFRESHED_SOURCE,
};

// A missing result is not permission to retry the other source at this height.
[[nodiscard]] std::optional<RecoveryRefreshMode> GetRecoveryRefreshMode(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t target_height,
    int32_t latest_receipted_target_height) noexcept;

// The intervals additionally require actual cumulative work, measured in the
// difficulty of their fixed starting block. Height alone does not establish it.
[[nodiscard]] bool ValidateRecoveryRefreshWorkDepth(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config,
    const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& authority_anchor) noexcept;

inline constexpr uint16_t RECOVERY_REFRESH_WORK_VERSION{1};
inline constexpr std::size_t RECOVERY_REFRESH_MAX_PROOF_BYTES{16'384};
inline constexpr std::size_t RECOVERY_REFRESH_MAX_COMMITMENT_BYTES{
    sizeof(uint16_t) + sizeof(uint32_t) + 2 * 32 + 3 +
    RECOVERY_REFRESH_MAX_PROOF_BYTES};

struct RecoveryRefreshWorkCommitment {
    uint16_t version{RECOVERY_REFRESH_WORK_VERSION};
    uint32_t group{0};
    uint256 entropy_block_hash;
    uint256 parent_work_hash;
    std::vector<uint8_t> proof;

    SERIALIZE_METHODS(RecoveryRefreshWorkCommitment, obj)
    {
        READWRITE(obj.version, obj.group, obj.entropy_block_hash,
                  obj.parent_work_hash, obj.proof);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RecoveryRefreshWorkCommitment&,
                           const RecoveryRefreshWorkCommitment&) = default;
};

[[nodiscard]] std::optional<RecoveryRefreshWorkCommitment>
DecodeRecoveryRefreshWorkCommitment(Span<const uint8_t> payload);

[[nodiscard]] std::optional<std::vector<uint8_t>>
EncodeRecoveryRefreshWorkCommitment(const RecoveryRefreshWorkCommitment& commitment);

// A missing tag is a valid block with no work sample, not an alternate seed.
[[nodiscard]] bool ExtractRecoveryRefreshWorkCommitment(
    const CBlock& block, std::optional<RecoveryRefreshWorkCommitment>& commitment);
// Producer-only framing checks may refuse a valid sample that collides with
// existing coinbase receipt tags. Failure leaves coinbase_extra unchanged.
[[nodiscard]] bool AppendRecoveryRefreshWorkCommitment(
    std::vector<uint8_t>& coinbase_extra,
    const RecoveryRefreshWorkCommitment& commitment);

class ValidatedRecoveryRefreshWorkSample {
public:
    [[nodiscard]] uint32_t Group() const noexcept { return m_group; }
    [[nodiscard]] const uint256& SnapshotHash() const noexcept { return m_snapshot_hash; }
    [[nodiscard]] const uint256& EntropyBlockHash() const noexcept { return m_entropy_hash; }
    [[nodiscard]] const uint256& CarrierHash() const noexcept { return m_carrier_hash; }
    [[nodiscard]] const uint256& ParentWorkHash() const noexcept { return m_parent_work_hash; }
    [[nodiscard]] const uint256& CommitmentHash() const noexcept { return m_commitment_hash; }

private:
    ValidatedRecoveryRefreshWorkSample(uint32_t group, uint256 snapshot_hash,
        uint256 entropy_hash, uint256 carrier_hash, uint256 parent_work_hash,
        uint256 commitment_hash);

    uint32_t m_group;
    uint256 m_snapshot_hash;
    uint256 m_entropy_hash;
    uint256 m_carrier_hash;
    uint256 m_parent_work_hash;
    uint256 m_commitment_hash;

    friend std::optional<ValidatedRecoveryRefreshWorkSample>
    VerifyRecoveryRefreshWorkCommitment(const ChainLockScheduleConfig&,
        const BTCCScheduleConfig&, const RecoveryRefreshConfig&,
        const RecoveryRefreshCoordinates&, const CBlockIndex&,
        const RecoveryRefreshWorkCommitment&, const Consensus::Params&);
    friend std::optional<ValidatedRecoveryRefreshWorkSample>
    ValidateIndexedRecoveryRefreshWork(const ChainLockScheduleConfig&,
        const BTCCScheduleConfig&, const RecoveryRefreshConfig&,
        const RecoveryRefreshCoordinates&, const CBlockIndex&);
};

// The caller extracts exactly one immutable commitment from G's coinbase and
// validates the indexed branch normally. This checks a fresh merged-work proof
// binding F's immutable child hash at F's nBits and chain ID, not F's accepted
// mutable wrapper. BTCPREV / Nexus wrapper context and Bitcoin-tip membership
// are not entropy authority; neither a stored wrapper nor a tip claim is read.
[[nodiscard]] std::optional<ValidatedRecoveryRefreshWorkSample>
VerifyRecoveryRefreshWorkCommitment(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config,
    const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& carrier, const RecoveryRefreshWorkCommitment& commitment,
    const Consensus::Params& consensus);

[[nodiscard]] std::optional<ValidatedRecoveryRefreshWorkSample>
ValidateIndexedRecoveryRefreshWork(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config,
    const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& authority_anchor);

[[nodiscard]] std::optional<uint256> GetRecoveryRefreshEntropyHash(
    const uint256& genesis_hash, const uint256& universe_root, uint32_t group,
    const uint256& snapshot_hash, const uint256& entropy_block_hash,
    const uint256& parent_work_hash);

// Work-backed selection remains producer-biasable before G commits its sample.
[[nodiscard]] std::optional<uint256> GetRecoveryRefreshEntropyHash(
    const uint256& genesis_hash, const uint256& universe_root,
    const ValidatedRecoveryRefreshWorkSample& sample);

[[nodiscard]] std::optional<uint256> GetRecoveryRefreshRosterModifier(
    const uint256& genesis_hash, const uint256& entropy_hash,
    uint32_t group, uint32_t epoch);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_RECOVERY_REFRESH_H
