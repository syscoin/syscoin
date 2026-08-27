// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_operator_key_state.h>

#include <llmq/pq_global_auth.h>

#include <hash.h>
#include <span.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace llmq::pq {
namespace {

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

bool IsZeroRecord(const GlobalKeyRecord& record)
{
    return record == GlobalKeyRecord{};
}

bool AreFrozenRootsCanonical(
    const std::vector<FrozenChildRootRecord>& records,
    const uint256& pro_tx_hash) noexcept
{
    for (std::size_t i{0}; i < records.size(); ++i) {
        if (!records[i].IsStructurallyValid() ||
            records[i].pro_tx_hash != pro_tx_hash ||
            (i != 0 && records[i - 1].epoch >= records[i].epoch)) {
            return false;
        }
    }
    return true;
}

const FrozenChildRootRecord* FindFrozenRoot(
    const std::vector<FrozenChildRootRecord>& records,
    uint32_t epoch) noexcept
{
    const auto it{std::lower_bound(
        records.begin(), records.end(), epoch,
        [](const auto& record, uint32_t sought) {
            return record.epoch < sought;
        })};
    return it != records.end() && it->epoch == epoch ? &*it : nullptr;
}

OperatorKeyStateResult CheckPrepared(
    const OperatorKeyState& state,
    const OperatorKeyScheduleView& view)
{
    if (!state.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    if (!view.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_SCHEDULE;
    }
    if (!state.IsAdvancedTo(view)) {
        return OperatorKeyStateResult::STATE_NOT_ADVANCED;
    }
    return OperatorKeyStateResult::OK;
}

bool StartsAtMutableCutoff(
    const ChildKeyTreeCommitment& commitment,
    const OperatorKeyScheduleView& view) noexcept
{
    return commitment.IsStructurallyValid() &&
           commitment.first_epoch == view.first_mutable_epoch;
}

template <typename StateAt>
std::optional<uint256> HashCanonicalOperatorKeyStates(
    const uint256& genesis_hash,
    std::size_t state_count,
    const uint256& used_tree_id_set_hash,
    StateAt&& state_at)
{
    if (genesis_hash.IsNull() || used_tree_id_set_hash.IsNull()) {
        return std::nullopt;
    }
    for (std::size_t index{0}; index < state_count; ++index) {
        const auto& state{state_at(index)};
        if (!state.IsStructurallyValid() ||
            (index != 0 &&
             !(state_at(index - 1).pro_tx_hash < state.pro_tx_hash))) {
            return std::nullopt;
        }
    }

    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PQ_KEY_CONSENSUS_STATE_DOMAIN);
    writer << genesis_hash << PQ_KEY_CONSENSUS_STATE_VERSION
           << static_cast<uint64_t>(state_count);
    for (std::size_t index{0}; index < state_count; ++index) {
        writer << state_at(index);
    }
    writer << used_tree_id_set_hash;
    return writer.GetHash();
}

} // namespace

bool OperatorKeyScheduleView::IsStructurallyValid() const noexcept
{
    if (block_height <= 0 || has_current_epoch > 1 ||
        last_admissible_epoch < first_mutable_epoch ||
        first_retained_frozen_epoch > first_mutable_epoch) {
        return false;
    }
    if (has_current_epoch != 0) {
        if (first_mutable_epoch <= current_epoch) return false;
    } else if (current_epoch != 0 || first_retained_frozen_epoch != 0) {
        return false;
    }
    const uint64_t future_window{
        uint64_t{last_admissible_epoch} - first_mutable_epoch + 1};
    const uint64_t retained_window{
        uint64_t{first_mutable_epoch} - first_retained_frozen_epoch};
    return future_window <= MAX_OPERATOR_SCHEDULE_EPOCHS &&
           retained_window <= MAX_RETAINED_FROZEN_CHILD_ROOTS;
}

OperatorKeyScheduleState OperatorKeyScheduleState::FromView(
    const OperatorKeyScheduleView& view) noexcept
{
    return {
        view.has_current_epoch,
        view.current_epoch,
        view.first_mutable_epoch,
        view.last_admissible_epoch,
        view.first_retained_frozen_epoch,
    };
}

bool OperatorKeyScheduleState::IsStructurallyValid() const noexcept
{
    OperatorKeyScheduleView view;
    view.block_height = 1;
    view.has_current_epoch = has_current_epoch;
    view.current_epoch = current_epoch;
    view.first_mutable_epoch = first_mutable_epoch;
    view.last_admissible_epoch = last_admissible_epoch;
    view.first_retained_frozen_epoch = first_retained_frozen_epoch;
    return view.IsStructurallyValid();
}

bool OperatorKeyScheduleState::IsCompatible(
    const OperatorKeyScheduleView& view) const noexcept
{
    return view.IsStructurallyValid() && *this == FromView(view);
}

std::optional<OperatorKeyScheduleView> DeriveOperatorKeyScheduleView(
    const ChainLockScheduleConfig& config,
    int32_t block_height,
    uint32_t registration_cutoff_blocks,
    uint32_t future_horizon_epochs) noexcept
{
    if (!config.IsValid() || block_height <= 0 ||
        future_horizon_epochs == 0 ||
        future_horizon_epochs > MAX_OPERATOR_SCHEDULE_EPOCHS) {
        return std::nullopt;
    }
    const auto current_epoch{EpochForHeight(config, block_height)};
    if (current_epoch &&
        *current_epoch == std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }

    uint32_t first_mutable_epoch{current_epoch ? *current_epoch + 1 : 0};
    std::size_t skipped_cutoffs{0};
    while (!IsBeforeRegistrationCutoff(
        config, first_mutable_epoch, registration_cutoff_blocks,
        block_height)) {
        if (first_mutable_epoch == std::numeric_limits<uint32_t>::max() ||
            ++skipped_cutoffs > MAX_RETAINED_FROZEN_CHILD_ROOTS) {
            return std::nullopt;
        }
        ++first_mutable_epoch;
    }
    if (future_horizon_epochs - 1 >
        std::numeric_limits<uint32_t>::max() - first_mutable_epoch) {
        return std::nullopt;
    }

    const uint32_t active_history{
        static_cast<uint32_t>(ACTIVE_QUORUMS - 1)};
    const uint32_t first_retained_frozen_epoch{
        current_epoch && *current_epoch > active_history
            ? *current_epoch - active_history
            : 0};
    OperatorKeyScheduleView view{
        block_height,
        static_cast<uint8_t>(current_epoch.has_value()),
        current_epoch.value_or(0),
        first_mutable_epoch,
        first_mutable_epoch + future_horizon_epochs - 1,
        first_retained_frozen_epoch,
    };
    return view.IsStructurallyValid()
        ? std::optional<OperatorKeyScheduleView>{view}
        : std::nullopt;
}

OperatorKeyState OperatorKeyState::ForOperator(
    const uint256& pro_tx_hash)
{
    OperatorKeyState state;
    state.pro_tx_hash = pro_tx_hash;
    return state;
}

bool OperatorKeyState::IsStructurallyValid() const noexcept
{
    if (version != OPERATOR_KEY_STATE_VERSION || pro_tx_hash.IsNull() ||
        has_global_key > 1 || global_key_active > 1 ||
        global_key_active > has_global_key || schedule_initialized > 1 ||
        frozen_child_roots.size() > MAX_RETAINED_FROZEN_CHILD_ROOTS) {
        return false;
    }
    if (schedule_initialized == 0) {
        return has_global_key == 0 && global_key_active == 0 &&
               revoked_height == 0 &&
               schedule == OperatorKeyScheduleState{} &&
               frozen_child_roots.empty() && IsZeroRecord(global_key);
    }
    if (!schedule.IsStructurallyValid()) return false;
    if (has_global_key == 0) {
        return global_key_active == 0 && revoked_height == 0 &&
               frozen_child_roots.empty() &&
               IsZeroRecord(global_key);
    }
    if (!IsStoredGlobalKeyRecordStructurallyValid(global_key) ||
        !AreFrozenRootsCanonical(frozen_child_roots, pro_tx_hash) ||
        (global_key_active == 0 &&
         (revoked_height < global_key.activated_height ||
          !frozen_child_roots.empty())) ||
        (global_key_active != 0 && revoked_height != 0)) {
        return false;
    }
    for (const auto& frozen : frozen_child_roots) {
        if (frozen.epoch < schedule.first_retained_frozen_epoch ||
            frozen.epoch >= schedule.first_mutable_epoch ||
            frozen.global_key_version > global_key.key_version) {
            return false;
        }
    }
    return true;
}

bool OperatorKeyState::IsAdvancedTo(
    const OperatorKeyScheduleView& view) const noexcept
{
    return schedule_initialized != 0 && schedule.IsCompatible(view);
}

bool OperatorKeyState::UsesTreeId(const uint256& tree_id) const noexcept
{
    if (tree_id.IsNull() || has_global_key == 0) return false;
    if (global_key.child_key_commitment.tree_id == tree_id) return true;
    return std::any_of(
        frozen_child_roots.begin(), frozen_child_roots.end(),
        [&](const auto& record) {
            return record.commitment.tree_id == tree_id;
        });
}

OperatorKeyStateResult OperatorKeyState::Advance(
    const OperatorKeyScheduleView& view)
{
    if (!IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    if (!view.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_SCHEDULE;
    }
    if (schedule_initialized == 0) {
        OperatorKeyState next{*this};
        next.schedule_initialized = 1;
        next.schedule = OperatorKeyScheduleState::FromView(view);
        if (!next.IsStructurallyValid()) {
            return OperatorKeyStateResult::INVALID_STATE;
        }
        *this = std::move(next);
        return OperatorKeyStateResult::OK;
    }

    const auto revision{OperatorKeyScheduleState::FromView(view)};
    if (schedule == revision) return OperatorKeyStateResult::OK;
    if ((schedule.has_current_epoch != 0 && view.has_current_epoch == 0) ||
        (schedule.has_current_epoch != 0 && view.has_current_epoch != 0 &&
         view.current_epoch < schedule.current_epoch) ||
        view.first_mutable_epoch < schedule.first_mutable_epoch ||
        view.last_admissible_epoch < schedule.last_admissible_epoch ||
        view.first_retained_frozen_epoch <
            schedule.first_retained_frozen_epoch) {
        return OperatorKeyStateResult::NON_MONOTONIC_SCHEDULE;
    }

    OperatorKeyState next{*this};
    next.frozen_child_roots.erase(
        std::remove_if(
            next.frozen_child_roots.begin(),
            next.frozen_child_roots.end(),
            [&](const auto& record) {
                return record.epoch < view.first_retained_frozen_epoch;
            }),
        next.frozen_child_roots.end());

    if (HasActiveGlobalKey()) {
        for (uint64_t epoch{schedule.first_mutable_epoch};
             epoch < view.first_mutable_epoch; ++epoch) {
            const uint32_t frozen_epoch{static_cast<uint32_t>(epoch)};
            if (frozen_epoch >= view.first_retained_frozen_epoch &&
                global_key.child_key_commitment.CoversEpoch(frozen_epoch)) {
                next.frozen_child_roots.push_back(FrozenChildRootRecord{
                    pro_tx_hash,
                    global_key.key_version,
                    frozen_epoch,
                    global_key.child_key_commitment,
                });
            }
        }
    }
    if (next.frozen_child_roots.size() >
        MAX_RETAINED_FROZEN_CHILD_ROOTS) {
        return OperatorKeyStateResult::STATE_CAP_EXCEEDED;
    }
    next.schedule = revision;
    if (!next.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    *this = std::move(next);
    return OperatorKeyStateResult::OK;
}

OperatorKeyStateResult OperatorKeyState::ApplyInitialGlobalKey(
    const OperatorKeyScheduleView& view,
    const uint256& genesis_hash,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& proof_of_possession,
    bool owner_authorization_verified,
    bool check_sigs)
{
    const auto prepared{CheckPrepared(*this, view)};
    if (prepared != OperatorKeyStateResult::OK) return prepared;
    if (!owner_authorization_verified) {
        return OperatorKeyStateResult::OWNER_AUTHORIZATION_REQUIRED;
    }
    if (HasActiveGlobalKey()) {
        return OperatorKeyStateResult::GLOBAL_KEY_ALREADY_REGISTERED;
    }
    if (!StartsAtMutableCutoff(candidate.child_key_commitment, view)) {
        return OperatorKeyStateResult::INVALID_CHILD_ROOT_COMMITMENT;
    }
    if (has_global_key != 0) {
        const uint64_t recovery_height{
            static_cast<uint64_t>(revoked_height) +
            OWNER_RECOVERY_DELAY_BLOCKS};
        if (revoked_height == 0 ||
            static_cast<uint64_t>(view.block_height) < recovery_height ||
            global_key.key_version == std::numeric_limits<uint32_t>::max() ||
            candidate.key_version != global_key.key_version + 1 ||
            candidate.public_key == global_key.public_key ||
            candidate.child_key_commitment ==
                global_key.child_key_commitment ||
            candidate.child_key_commitment.tree_id ==
                global_key.child_key_commitment.tree_id ||
            candidate.child_key_commitment.root ==
                global_key.child_key_commitment.root) {
            return OperatorKeyStateResult::GLOBAL_RECOVERY_NOT_ALLOWED;
        }
    }
    const bool authorization_transcript_valid{has_global_key == 0
        ? GetGlobalRegistrationAuthorizationHash(
              genesis_hash, pro_tx_hash, candidate,
              transaction_inputs_hash).has_value()
        : GetGlobalRecoveryAuthorizationHash(
              genesis_hash, pro_tx_hash, global_key, candidate,
              transaction_inputs_hash).has_value()};
    if (!authorization_transcript_valid) {
        return OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED;
    }
    if (check_sigs) {
        const bool valid{has_global_key == 0
            ? VerifyGlobalKeyRegistration(
                  genesis_hash, pro_tx_hash, candidate,
                  transaction_inputs_hash, proof_of_possession)
            : VerifyGlobalKeyRecovery(
                  genesis_hash, pro_tx_hash, global_key, candidate,
                  transaction_inputs_hash, proof_of_possession)};
        if (!valid) {
            return OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED;
        }
    }

    OperatorKeyState next{*this};
    next.has_global_key = 1;
    next.global_key_active = 1;
    next.revoked_height = 0;
    next.global_key = candidate;
    next.global_key.activated_height =
        static_cast<uint32_t>(view.block_height);
    next.frozen_child_roots.clear();
    if (!next.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    *this = std::move(next);
    return OperatorKeyStateResult::OK;
}

OperatorKeyStateResult OperatorKeyState::ApplyGlobalKeyRotation(
    const OperatorKeyScheduleView& view,
    const uint256& genesis_hash,
    const GlobalKeyRecord& candidate,
    const uint256& transaction_inputs_hash,
    const GlobalSignature& old_global_key_signature,
    bool check_sigs)
{
    const auto prepared{CheckPrepared(*this, view)};
    if (prepared != OperatorKeyStateResult::OK) return prepared;
    if (has_global_key == 0) {
        return OperatorKeyStateResult::GLOBAL_KEY_MISSING;
    }
    if (!HasActiveGlobalKey()) {
        return OperatorKeyStateResult::GLOBAL_KEY_INACTIVE;
    }
    if (candidate.child_key_commitment !=
            global_key.child_key_commitment &&
        !StartsAtMutableCutoff(candidate.child_key_commitment, view)) {
        return OperatorKeyStateResult::INVALID_CHILD_ROOT_COMMITMENT;
    }
    if (!GetGlobalRotationAuthorizationHash(
            genesis_hash, pro_tx_hash, global_key, candidate,
            transaction_inputs_hash)) {
        return OperatorKeyStateResult::GLOBAL_ROTATION_AUTH_FAILED;
    }
    if (check_sigs &&
        !VerifyGlobalKeyRotation(
            genesis_hash, pro_tx_hash, global_key, candidate,
            transaction_inputs_hash, old_global_key_signature)) {
        return OperatorKeyStateResult::GLOBAL_ROTATION_AUTH_FAILED;
    }

    OperatorKeyState next{*this};
    next.global_key = candidate;
    next.global_key.activated_height =
        static_cast<uint32_t>(view.block_height);
    if (!next.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    *this = std::move(next);
    return OperatorKeyStateResult::OK;
}

OperatorKeyStateResult OperatorKeyState::ApplyProviderRevocation(
    const OperatorKeyScheduleView& view,
    const uint256& genesis_hash,
    const ProviderRevokeAuthorization& authorization,
    const GlobalSignature& current_global_key_signature,
    bool check_sigs)
{
    const auto prepared{CheckPrepared(*this, view)};
    if (prepared != OperatorKeyStateResult::OK) return prepared;
    if (has_global_key == 0) {
        return OperatorKeyStateResult::GLOBAL_KEY_MISSING;
    }
    if (!HasActiveGlobalKey()) {
        return OperatorKeyStateResult::GLOBAL_KEY_INACTIVE;
    }
    if (authorization.pro_tx_hash != pro_tx_hash ||
        !GetProviderRevokeAuthorizationHash(
            genesis_hash, global_key, authorization) ||
        (check_sigs &&
         !VerifyProviderRevokeAuthorization(
             genesis_hash, global_key, authorization,
             current_global_key_signature))) {
        return OperatorKeyStateResult::PROVIDER_REVOCATION_AUTH_FAILED;
    }

    OperatorKeyState next{*this};
    next.global_key_active = 0;
    next.revoked_height = static_cast<uint32_t>(view.block_height);
    next.frozen_child_roots.clear();
    if (!next.IsStructurallyValid()) {
        return OperatorKeyStateResult::INVALID_STATE;
    }
    *this = std::move(next);
    return OperatorKeyStateResult::OK;
}

ChildRootResolution OperatorKeyState::ResolveChildRoot(
    uint32_t epoch) const
{
    if (!IsStructurallyValid() || schedule_initialized == 0 ||
        !HasActiveGlobalKey()) {
        return {};
    }
    if (epoch < schedule.first_retained_frozen_epoch) {
        return {ChildRootResolutionStatus::PRUNED, std::nullopt};
    }
    if (epoch < schedule.first_mutable_epoch) {
        if (const auto* frozen{FindFrozenRoot(frozen_child_roots, epoch)}) {
            return {ChildRootResolutionStatus::FROZEN_PRESENT, *frozen};
        }
        return {ChildRootResolutionStatus::FROZEN_ABSENT, std::nullopt};
    }
    if (epoch > schedule.last_admissible_epoch) {
        return {ChildRootResolutionStatus::OUTSIDE_HORIZON,
                std::nullopt};
    }
    if (!global_key.child_key_commitment.CoversEpoch(epoch)) {
        return {ChildRootResolutionStatus::MUTABLE_ABSENT,
                std::nullopt};
    }
    return {
        ChildRootResolutionStatus::MUTABLE_PRESENT,
        FrozenChildRootRecord{
            pro_tx_hash,
            global_key.key_version,
            epoch,
            global_key.child_key_commitment,
        },
    };
}

std::optional<uint256> GetOperatorKeyStateHash(
    const uint256& genesis_hash,
    const OperatorKeyState& state)
{
    if (genesis_hash.IsNull() || !state.IsStructurallyValid()) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, OPERATOR_KEY_STATE_DOMAIN);
    writer << genesis_hash << state;
    return writer.GetHash();
}

std::optional<uint256> GetPQKeyConsensusStateHash(
    const uint256& genesis_hash,
    std::span<const OperatorKeyState> operator_states,
    const uint256& used_tree_id_set_hash)
{
    if (genesis_hash.IsNull() || used_tree_id_set_hash.IsNull()) {
        return std::nullopt;
    }
    std::vector<const OperatorKeyState*> ordered;
    ordered.reserve(operator_states.size());
    for (const auto& state : operator_states) {
        if (!state.IsStructurallyValid()) return std::nullopt;
        ordered.push_back(&state);
    }
    std::sort(
        ordered.begin(), ordered.end(),
        [](const auto* lhs, const auto* rhs) {
            return lhs->pro_tx_hash < rhs->pro_tx_hash;
        });
    return HashCanonicalOperatorKeyStates(
        genesis_hash, ordered.size(), used_tree_id_set_hash,
        [&](std::size_t index) -> const OperatorKeyState& {
            return *ordered[index];
        });
}

std::optional<uint256> GetCanonicalPQKeyConsensusStateHash(
    const uint256& genesis_hash,
    std::span<const OperatorKeyState> operator_states,
    const uint256& used_tree_id_set_hash)
{
    return HashCanonicalOperatorKeyStates(
        genesis_hash, operator_states.size(), used_tree_id_set_hash,
        [&](std::size_t index) -> const OperatorKeyState& {
            return operator_states[index];
        });
}

} // namespace llmq::pq
