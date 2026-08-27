// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_OPERATOR_KEY_STATE_H
#define SYSCOIN_LLMQ_PQ_OPERATOR_KEY_STATE_H

#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_types.h>

#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace llmq::pq {

struct ProviderRevokeAuthorization;

inline constexpr uint16_t OPERATOR_KEY_STATE_VERSION{1};
inline constexpr std::size_t MAX_OPERATOR_SCHEDULE_EPOCHS{32};
inline constexpr std::size_t MAX_RETAINED_FROZEN_CHILD_ROOTS{32};
/** Owner recovery cannot replace a live key and remains observable for the
 * complete active-quorum window after a PQ-authorized revocation. */
inline constexpr uint32_t OWNER_RECOVERY_DELAY_BLOCKS{
    static_cast<uint32_t>(ACTIVE_QUORUMS) * PQ_EPOCH_BLOCKS};
inline constexpr std::string_view OPERATOR_KEY_STATE_DOMAIN{
    "SYS_PQ_OPERATOR_KEY_STATE_V1"};
inline constexpr uint16_t PQ_KEY_CONSENSUS_STATE_VERSION{1};
inline constexpr std::string_view PQ_KEY_CONSENSUS_STATE_DOMAIN{
    "SYS_PQ_KEY_CONSENSUS_STATE_V1"};

struct OperatorKeyScheduleView {
    int32_t block_height{-1};
    uint8_t has_current_epoch{0};
    uint32_t current_epoch{0};
    uint32_t first_mutable_epoch{0};
    uint32_t last_admissible_epoch{0};
    uint32_t first_retained_frozen_epoch{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const OperatorKeyScheduleView&,
                           const OperatorKeyScheduleView&) = default;
};

struct OperatorKeyScheduleState {
    uint8_t has_current_epoch{0};
    uint32_t current_epoch{0};
    uint32_t first_mutable_epoch{0};
    uint32_t last_admissible_epoch{0};
    uint32_t first_retained_frozen_epoch{0};

    [[nodiscard]] static OperatorKeyScheduleState FromView(
        const OperatorKeyScheduleView& view) noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsCompatible(
        const OperatorKeyScheduleView& view) const noexcept;
    friend bool operator==(const OperatorKeyScheduleState&,
                           const OperatorKeyScheduleState&) = default;
};

[[nodiscard]] std::optional<OperatorKeyScheduleView>
DeriveOperatorKeyScheduleView(
    const ChainLockScheduleConfig& config,
    int32_t block_height,
    uint32_t registration_cutoff_blocks,
    uint32_t future_horizon_epochs) noexcept;

enum class OperatorKeyStateResult : uint8_t {
    OK = 0,
    INVALID_STATE,
    INVALID_SCHEDULE,
    NON_MONOTONIC_SCHEDULE,
    STATE_NOT_ADVANCED,
    OWNER_AUTHORIZATION_REQUIRED,
    GLOBAL_KEY_ALREADY_REGISTERED,
    GLOBAL_KEY_MISSING,
    GLOBAL_REGISTRATION_AUTH_FAILED,
    GLOBAL_ROTATION_AUTH_FAILED,
    GLOBAL_KEY_INACTIVE,
    GLOBAL_RECOVERY_NOT_ALLOWED,
    PROVIDER_REVOCATION_AUTH_FAILED,
    INVALID_CHILD_ROOT_COMMITMENT,
    STATE_CAP_EXCEEDED,
};

enum class ChildRootResolutionStatus : uint8_t {
    INVALID_STATE = 0,
    PRUNED,
    FROZEN_ABSENT,
    FROZEN_PRESENT,
    MUTABLE_ABSENT,
    MUTABLE_PRESENT,
    OUTSIDE_HORIZON,
};

struct ChildRootResolution {
    ChildRootResolutionStatus status{
        ChildRootResolutionStatus::INVALID_STATE};
    std::optional<FrozenChildRootRecord> record;
};

/**
 * Bounded branch state for one operator.
 *
 * The active global record authorizes a fixed 2^16-epoch child-key root.
 * Only roots already closed by a registration cutoff are retained separately,
 * and only for the active quorum history. There is no per-epoch registration,
 * pending key vector, or wallet-controlled maintenance.
 */
struct OperatorKeyState {
    uint16_t version{OPERATOR_KEY_STATE_VERSION};
    uint256 pro_tx_hash;
    uint8_t has_global_key{0};
    uint8_t global_key_active{0};
    /** Nonzero only while the current record is PQ-revoked. */
    uint32_t revoked_height{0};
    GlobalKeyRecord global_key;
    uint8_t schedule_initialized{0};
    OperatorKeyScheduleState schedule;
    std::vector<FrozenChildRootRecord> frozen_child_roots;

    SERIALIZE_METHODS(OperatorKeyState, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ operator-key state");
        });
        READWRITE(obj.version, obj.pro_tx_hash, obj.has_global_key,
                  obj.global_key_active, obj.revoked_height);
        SER_READ(obj, if (obj.has_global_key > 1 ||
                          obj.global_key_active > 1) {
            throw std::ios_base::failure(
                "invalid PQ global-key presence flag");
        });
        if (obj.has_global_key != 0) READWRITE(obj.global_key);
        READWRITE(obj.schedule_initialized);
        SER_READ(obj, if (obj.schedule_initialized > 1) {
            throw std::ios_base::failure("invalid PQ schedule presence flag");
        });
        if (obj.schedule_initialized != 0) {
            READWRITE(obj.schedule.has_current_epoch,
                      obj.schedule.current_epoch,
                      obj.schedule.first_mutable_epoch,
                      obj.schedule.last_admissible_epoch,
                      obj.schedule.first_retained_frozen_epoch);
        }
        uint16_t frozen_count{
            static_cast<uint16_t>(obj.frozen_child_roots.size())};
        SER_WRITE(obj, if (obj.frozen_child_roots.size() >
                           MAX_RETAINED_FROZEN_CHILD_ROOTS) {
            throw std::ios_base::failure("too many frozen PQ child roots");
        });
        READWRITE(frozen_count);
        SER_READ(obj, if (frozen_count > MAX_RETAINED_FROZEN_CHILD_ROOTS) {
            throw std::ios_base::failure("too many frozen PQ child roots");
        });
        SER_READ(obj, obj.frozen_child_roots.resize(frozen_count));
        for (auto& record : obj.frozen_child_roots) READWRITE(record);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ operator-key state");
        });
    }

    [[nodiscard]] static OperatorKeyState ForOperator(
        const uint256& pro_tx_hash);
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool HasActiveGlobalKey() const noexcept
    {
        return has_global_key != 0 && global_key_active != 0;
    }
    [[nodiscard]] bool IsAdvancedTo(
        const OperatorKeyScheduleView& view) const noexcept;
    [[nodiscard]] bool UsesTreeId(const uint256& tree_id) const noexcept;

    [[nodiscard]] OperatorKeyStateResult Advance(
        const OperatorKeyScheduleView& view);

    [[nodiscard]] OperatorKeyStateResult ApplyInitialGlobalKey(
        const OperatorKeyScheduleView& view,
        const uint256& genesis_hash,
        const GlobalKeyRecord& candidate,
        const uint256& transaction_inputs_hash,
        const GlobalSignature& proof_of_possession,
        bool owner_authorization_verified,
        bool check_sigs = true);

    [[nodiscard]] OperatorKeyStateResult ApplyGlobalKeyRotation(
        const OperatorKeyScheduleView& view,
        const uint256& genesis_hash,
        const GlobalKeyRecord& candidate,
        const uint256& transaction_inputs_hash,
        const GlobalSignature& old_global_key_signature,
        bool check_sigs = true);

    [[nodiscard]] OperatorKeyStateResult ApplyProviderRevocation(
        const OperatorKeyScheduleView& view,
        const uint256& genesis_hash,
        const ProviderRevokeAuthorization& authorization,
        const GlobalSignature& current_global_key_signature,
        bool check_sigs = true);

    [[nodiscard]] ChildRootResolution ResolveChildRoot(
        uint32_t epoch) const;
    friend bool operator==(const OperatorKeyState&,
                           const OperatorKeyState&) = default;
};

[[nodiscard]] std::optional<uint256> GetOperatorKeyStateHash(
    const uint256& genesis_hash,
    const OperatorKeyState& state);

[[nodiscard]] std::optional<uint256> GetPQKeyConsensusStateHash(
    const uint256& genesis_hash,
    std::span<const OperatorKeyState> operator_states,
    const uint256& used_tree_id_set_hash);

/**
 * Hash states already strictly ordered and unique by proTxHash without
 * allocating or sorting.
 */
[[nodiscard]] std::optional<uint256> GetCanonicalPQKeyConsensusStateHash(
    const uint256& genesis_hash,
    std::span<const OperatorKeyState> operator_states,
    const uint256& used_tree_id_set_hash);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_OPERATOR_KEY_STATE_H
