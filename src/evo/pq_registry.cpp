// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_registry.h>

#include <consensus/pq_migration.h>
#include <evo/provider_revoke_payload.h>
#include <evo/specialtx_payload.h>
#include <hash.h>
#include <llmq/pq_global_auth.h>
#include <memusage.h>
#include <span.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <string>
#include <utility>
#include <variant>

namespace llmq::pq {

struct PQRegistryIndexes {
    // Retained inactive/revoked records continue to own their global key until
    // a later rotation or deterministic-MN removal changes consensus state.
    std::map<GlobalPublicKey, uint256> global_key_owner;
};

struct PQRegistryStateData {
    std::shared_ptr<const std::vector<OperatorKeyState>> operator_states;
    std::shared_ptr<const std::vector<uint256>> used_tree_ids;
    std::shared_ptr<const PQRegistryIndexes> indexes;
    std::optional<OperatorKeyScheduleState> schedule;
    uint256 used_tree_ids_hash;
    uint256 consensus_state_root;
    std::size_t owned_dynamic_memory_usage{0};
    std::size_t used_tree_ids_dynamic_memory_usage{0};
};

struct PQRegistrySnapshotView {
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    std::shared_ptr<const PQRegistryStateData> state;
    std::shared_ptr<const std::vector<uint256>> block_tree_ids;
};

namespace {

struct DecodedProviderRevocation {
    ProviderRevokeAuthorization authorization;
    GlobalSignature signature;
};

using DecodedPayload =
    std::variant<GlobalKeyTxPayload, DecodedProviderRevocation>;

struct DecodedUpdate {
    std::size_t transaction_index{0};
    const CTransaction* transaction{nullptr};
    uint256 pro_tx_hash;
    DecodedPayload payload;
};

DBParams RegistryDBParams(DBParams params, std::string_view suffix)
{
    params.path /= fs::PathFromString(std::string{suffix});
    return params;
}

bool SetError(
    PQRegistryError& error,
    PQRegistryResult result,
    std::size_t transaction_index = std::numeric_limits<std::size_t>::max(),
    const uint256& pro_tx_hash = {},
    OperatorKeyStateResult state_result = OperatorKeyStateResult::OK)
{
    error.result = result;
    error.transaction_index = transaction_index;
    error.pro_tx_hash = pro_tx_hash;
    error.state_result = state_result;
    return false;
}

template <typename Records>
auto FindOperatorPosition(Records& records, const uint256& pro_tx_hash)
{
    return std::lower_bound(
        records.begin(), records.end(), pro_tx_hash,
        [](const auto& state, const uint256& sought) {
            return state.pro_tx_hash < sought;
        });
}

bool IsStrictlySortedUnique(std::span<const uint256> values) noexcept
{
    for (std::size_t index{0}; index < values.size(); ++index) {
        if (values[index].IsNull() ||
            (index != 0 && !(values[index - 1] < values[index]))) {
            return false;
        }
    }
    return true;
}

bool IsStrictlySortedOperators(
    std::span<const OperatorKeyState> states) noexcept
{
    for (std::size_t index{0}; index < states.size(); ++index) {
        if (!states[index].IsStructurallyValid() ||
            (index != 0 && !(states[index - 1].pro_tx_hash <
                             states[index].pro_tx_hash))) {
            return false;
        }
    }
    return true;
}

bool IsSubset(std::span<const uint256> subset,
              std::span<const uint256> superset) noexcept
{
    return std::includes(superset.begin(), superset.end(),
                         subset.begin(), subset.end());
}

bool StateTreeIdsAreRecorded(
    std::span<const OperatorKeyState> states,
    std::span<const uint256> used_tree_ids) noexcept
{
    for (const auto& state : states) {
        if (state.has_global_key == 0) continue;
        if (!std::binary_search(used_tree_ids.begin(), used_tree_ids.end(),
                                state.global_key.child_key_commitment.tree_id)) {
            return false;
        }
        for (const auto& frozen : state.frozen_child_roots) {
            if (!std::binary_search(used_tree_ids.begin(), used_tree_ids.end(),
                                    frozen.commitment.tree_id)) {
                return false;
            }
        }
    }
    return true;
}

std::optional<uint256> GetUsedTreeIdSetHash(
    const uint256& genesis_hash,
    std::span<const uint256> tree_ids)
{
    if (genesis_hash.IsNull() || tree_ids.size() > MAX_PQ_USED_TREE_IDS ||
        (!tree_ids.empty() && !IsStrictlySortedUnique(tree_ids))) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{USED_TREE_ID_SET_DOMAIN.data(),
                              USED_TREE_ID_SET_DOMAIN.size()}));
    writer << genesis_hash << static_cast<uint64_t>(tree_ids.size());
    for (const auto& tree_id : tree_ids) writer << tree_id;
    const uint256 hash{writer.GetHash()};
    return hash.IsNull() ? std::nullopt : std::optional<uint256>{hash};
}

bool MergeNewTreeIds(std::span<const uint256> current,
                     std::span<const uint256> additions,
                     std::vector<uint256>& merged)
{
    if ((!current.empty() && !IsStrictlySortedUnique(current)) ||
        (!additions.empty() && !IsStrictlySortedUnique(additions)) ||
        current.size() + additions.size() > MAX_PQ_USED_TREE_IDS) {
        return false;
    }
    merged.clear();
    merged.reserve(current.size() + additions.size());
    auto old_it{current.begin()};
    auto new_it{additions.begin()};
    while (old_it != current.end() || new_it != additions.end()) {
        if (new_it == additions.end() ||
            (old_it != current.end() && *old_it < *new_it)) {
            merged.push_back(*old_it++);
        } else if (old_it == current.end() || *new_it < *old_it) {
            merged.push_back(*new_it++);
        } else {
            return false;
        }
    }
    return true;
}

std::optional<OperatorKeyScheduleState> ScheduleStateAtHeight(
    const PQRegistryConfig& config,
    int32_t height)
{
    const auto view{DeriveOperatorKeyScheduleView(
        config.schedule, height, config.registration_cutoff_blocks,
        config.future_horizon_epochs)};
    if (!view) return std::nullopt;
    return OperatorKeyScheduleState::FromView(*view);
}

std::shared_ptr<const PQRegistryIndexes> BuildRegistryIndexes(
    std::span<const OperatorKeyState> states)
{
    auto indexes{std::make_shared<PQRegistryIndexes>()};
    for (const auto& state : states) {
        if (state.has_global_key == 0) continue;
        if (!indexes->global_key_owner
                 .emplace(state.global_key.public_key, state.pro_tx_hash)
                 .second) {
            return nullptr;
        }
    }
    return indexes;
}

std::size_t RegistryStateOwnedDynamicMemoryUsage(
    const PQRegistryStateData& state) noexcept
{
    std::size_t usage{sizeof(PQRegistryStateData)};
    if (state.operator_states) {
        usage += sizeof(std::vector<OperatorKeyState>) +
                 memusage::DynamicUsage(*state.operator_states);
        for (const auto& key_state : *state.operator_states) {
            usage += memusage::DynamicUsage(key_state.frozen_child_roots);
        }
    }
    if (state.indexes) {
        usage += sizeof(PQRegistryIndexes) +
                 memusage::DynamicUsage(state.indexes->global_key_owner);
    }
    return usage;
}

std::size_t SnapshotCacheDynamicMemoryUsage(
    const std::list<std::pair<
        uint256, std::shared_ptr<const PQRegistrySnapshotView>>>& cache,
    const PQRegistryStateData* baseline)
{
    std::vector<const PQRegistryStateData*> counted_states;
    std::vector<const std::vector<uint256>*> counted_tree_sets;
    counted_states.reserve(cache.size());
    counted_tree_sets.reserve(cache.size());
    if (baseline != nullptr) {
        counted_states.push_back(baseline);
        if (baseline->used_tree_ids) {
            counted_tree_sets.push_back(baseline->used_tree_ids.get());
        }
    }
    std::size_t usage{0};
    for (const auto& [block_hash, snapshot] : cache) {
        (void)block_hash;
        if (!snapshot) continue;
        usage += sizeof(PQRegistrySnapshotView);
        if (snapshot->block_tree_ids) {
            usage += sizeof(std::vector<uint256>) +
                     memusage::DynamicUsage(*snapshot->block_tree_ids);
        }
        const auto* state{snapshot->state.get()};
        if (state != nullptr &&
            std::find(counted_states.begin(), counted_states.end(), state) ==
                counted_states.end()) {
            counted_states.push_back(state);
            usage += state->owned_dynamic_memory_usage;
        }
        const auto* tree_set{
            state != nullptr ? state->used_tree_ids.get() : nullptr};
        if (tree_set != nullptr &&
            std::find(counted_tree_sets.begin(), counted_tree_sets.end(),
                      tree_set) == counted_tree_sets.end()) {
            counted_tree_sets.push_back(tree_set);
            usage += state->used_tree_ids_dynamic_memory_usage;
        }
    }
    return usage;
}

PQRegistrySnapshot MaterializeSnapshot(
    const PQRegistrySnapshotView& snapshot)
{
    PQRegistrySnapshot result;
    result.height = snapshot.height;
    result.block_hash = snapshot.block_hash;
    result.previous_block_hash = snapshot.previous_block_hash;
    if (snapshot.state) {
        if (snapshot.state->operator_states) {
            result.operator_states = *snapshot.state->operator_states;
        }
        if (snapshot.state->used_tree_ids) {
            result.used_tree_ids = *snapshot.state->used_tree_ids;
        }
        result.consensus_state_root = snapshot.state->consensus_state_root;
    }
    if (snapshot.block_tree_ids) {
        result.block_tree_ids = *snapshot.block_tree_ids;
    }
    return result;
}

bool ExtractCanonicalPQPayload(const CTransaction& transaction,
                               std::vector<unsigned char>& encoded)
{
    bool found{false};
    for (const auto& output : transaction.vout) {
        if (output.scriptPubKey.empty() ||
            output.scriptPubKey.front() != OP_RETURN) {
            continue;
        }
        if (found) return false;
        std::vector<unsigned char> candidate;
        if (!GetSyscoinData(output.scriptPubKey, candidate)) return false;
        CScript canonical;
        canonical << OP_RETURN << candidate;
        if (canonical != output.scriptPubKey) return false;
        encoded = std::move(candidate);
        found = true;
    }
    return found;
}

bool DecodeProviderRevocation(const CTransaction& transaction,
                              const std::vector<unsigned char>& encoded,
                              DecodedProviderRevocation& decoded)
{
    if (transaction.nVersion != SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        return false;
    }
    try {
        CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
        CProUpRevTx payload;
        stream >> payload;
        if (!stream.empty() || payload.nVersion != CProUpRevTx::PQ_VERSION) {
            return false;
        }
        decoded.authorization.payload_version = payload.nVersion;
        decoded.authorization.pro_tx_hash = payload.proTxHash;
        decoded.authorization.global_key_version = payload.globalKeyVersion;
        decoded.authorization.reason = payload.nReason;
        decoded.authorization.transaction_inputs_hash = payload.inputsHash;
        decoded.signature = payload.pqSig;
        return decoded.authorization.IsStructurallyValid();
    } catch (const std::exception&) {
        return false;
    }
}

bool IsPQProviderRevocation(const CTransaction& transaction)
{
    if (transaction.nVersion != SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        return false;
    }
    CProUpRevTx payload;
    return GetTxPayload(transaction, payload) &&
           payload.nVersion == CProUpRevTx::PQ_VERSION;
}

bool DecodeRegistryUpdate(const CTransaction& transaction,
                          std::size_t transaction_index,
                          std::optional<DecodedUpdate>& decoded,
                          PQRegistryError& error)
{
    decoded.reset();
    const bool global{transaction.nVersion == PQ_GLOBAL_KEY_TX_VERSION};
    const bool provider_revoke{
        transaction.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE};
    if (!global && !provider_revoke) return true;

    if (provider_revoke) {
        CProUpRevTx provider_payload;
        if (!GetTxPayload(transaction, provider_payload)) {
            return SetError(
                error,
                PQRegistryResult::INVALID_PROVIDER_REVOCATION_PAYLOAD,
                transaction_index);
        }
        if (provider_payload.nVersion <= CProUpRevTx::BASIC_BLS_VERSION) {
            return true;
        }
        if (provider_payload.nVersion != CProUpRevTx::PQ_VERSION) {
            return SetError(
                error,
                PQRegistryResult::INVALID_PROVIDER_REVOCATION_PAYLOAD,
                transaction_index);
        }
    }

    std::vector<unsigned char> encoded;
    if (!ExtractCanonicalPQPayload(transaction, encoded)) {
        return SetError(
            error,
            global ? PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD
                   : PQRegistryResult::INVALID_PROVIDER_REVOCATION_PAYLOAD,
            transaction_index);
    }

    DecodedUpdate update;
    update.transaction_index = transaction_index;
    update.transaction = &transaction;
    if (global) {
        GlobalKeyTxPayload payload;
        if (!DecodeGlobalKeyTxPayload(encoded, payload)) {
            return SetError(error,
                            PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD,
                            transaction_index);
        }
        update.pro_tx_hash = payload.pro_tx_hash;
        update.payload = std::move(payload);
    } else {
        DecodedProviderRevocation revocation;
        if (!DecodeProviderRevocation(transaction, encoded, revocation)) {
            return SetError(
                error,
                PQRegistryResult::INVALID_PROVIDER_REVOCATION_PAYLOAD,
                transaction_index);
        }
        update.pro_tx_hash = revocation.authorization.pro_tx_hash;
        update.payload = std::move(revocation);
    }
    decoded = std::move(update);
    return true;
}

bool CallMembership(const std::function<bool(const uint256&)>& callback,
                    const uint256& pro_tx_hash,
                    bool& exists,
                    PQRegistryError& error,
                    std::size_t transaction_index =
                        std::numeric_limits<std::size_t>::max())
{
    try {
        exists = callback(pro_tx_hash);
        return true;
    } catch (...) {
        return SetError(error, PQRegistryResult::CALLBACK_FAILED,
                        transaction_index, pro_tx_hash);
    }
}

template <typename FindGlobalKeyOwner, typename HasUsedTreeId>
bool ApplyDecodedUpdate(
    OperatorKeyState& state,
    const DecodedUpdate& update,
    const OperatorKeyScheduleView& schedule_view,
    const uint256& genesis_hash,
    const PQRegistryCallbacks& callbacks,
    bool check_sigs,
    FindGlobalKeyOwner&& find_global_key_owner,
    HasUsedTreeId&& has_used_tree_id,
    std::optional<uint256>& introduced_tree_id,
    PQRegistryError& error)
{
    introduced_tree_id.reset();
    OperatorKeyStateResult transition{OperatorKeyStateResult::INVALID_STATE};
    if (const auto* global{
            std::get_if<GlobalKeyTxPayload>(&update.payload)}) {
        if (global->transaction_inputs_hash !=
            CalcTxInputsHash(*update.transaction)) {
            return SetError(
                error, PQRegistryResult::TRANSACTION_INPUTS_HASH_MISMATCH,
                update.transaction_index, update.pro_tx_hash);
        }
        const auto key_owner{find_global_key_owner(
            global->candidate.public_key)};
        if (key_owner && *key_owner != update.pro_tx_hash) {
            return SetError(error, PQRegistryResult::DUPLICATE_GLOBAL_KEY,
                            update.transaction_index, update.pro_tx_hash);
        }
        const bool introduces_tree{
            state.has_global_key == 0 ||
            state.global_key.child_key_commitment !=
                global->candidate.child_key_commitment};
        if (introduces_tree) {
            const uint256& tree_id{
                global->candidate.child_key_commitment.tree_id};
            if (has_used_tree_id(tree_id)) {
                return SetError(
                    error, PQRegistryResult::DUPLICATE_CHILD_TREE_ID,
                    update.transaction_index, update.pro_tx_hash);
            }
            introduced_tree_id = tree_id;
        }

        if (global->operation == GlobalKeyOperation::INITIAL) {
            if (check_sigs &&
                !callbacks.verify_initial_owner_authorization) {
                return SetError(error, PQRegistryResult::CALLBACK_MISSING,
                                update.transaction_index,
                                update.pro_tx_hash);
            }
            const auto owner_hash{
                GetGlobalOwnerRegistrationAuthorizationHash(
                    genesis_hash, *global)};
            if (!owner_hash) {
                return SetError(
                    error, PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD,
                    update.transaction_index, update.pro_tx_hash);
            }
            if (check_sigs) {
                bool authorized{false};
                try {
                    authorized =
                        callbacks.verify_initial_owner_authorization(
                            *global, *owner_hash);
                } catch (...) {
                    return SetError(error, PQRegistryResult::CALLBACK_FAILED,
                                    update.transaction_index,
                                    update.pro_tx_hash);
                }
                if (!authorized) {
                    return SetError(
                        error,
                        PQRegistryResult::OWNER_AUTHORIZATION_FAILED,
                        update.transaction_index, update.pro_tx_hash);
                }
            }
            transition = state.ApplyInitialGlobalKey(
                schedule_view, genesis_hash, global->candidate,
                global->transaction_inputs_hash, global->authorization,
                /*owner_authorization_verified=*/true, check_sigs);
        } else {
            transition = state.ApplyGlobalKeyRotation(
                schedule_view, genesis_hash, global->candidate,
                global->transaction_inputs_hash, global->authorization,
                check_sigs);
        }
    } else {
        const auto& revocation{
            std::get<DecodedProviderRevocation>(update.payload)};
        if (revocation.authorization.transaction_inputs_hash !=
            CalcTxInputsHash(*update.transaction)) {
            return SetError(
                error, PQRegistryResult::TRANSACTION_INPUTS_HASH_MISMATCH,
                update.transaction_index, update.pro_tx_hash);
        }
        transition = state.ApplyProviderRevocation(
            schedule_view, genesis_hash, revocation.authorization,
            revocation.signature, check_sigs);
    }
    if (transition != OperatorKeyStateResult::OK) {
        return SetError(
            error, PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
            update.transaction_index, update.pro_tx_hash, transition);
    }
    return true;
}

bool MakePrePreparationSnapshot(const uint256& genesis_hash,
                                const uint256& block_hash,
                                const uint256& previous_block_hash,
                                int32_t height,
                                PQRegistrySnapshot& snapshot,
                                PQRegistryError& error)
{
    snapshot = {};
    snapshot.height = height;
    snapshot.block_hash = block_hash;
    snapshot.previous_block_hash = previous_block_hash;
    const auto root{snapshot.RecomputeConsensusStateRoot(genesis_hash)};
    if (!root) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    snapshot.consensus_state_root = *root;
    return snapshot.IsStructurallyValid()
        ? true
        : SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
}

} // namespace

PQRegistryReadView::PQRegistryReadView(
    std::shared_ptr<const PQRegistrySnapshotView> snapshot)
    : m_snapshot{std::move(snapshot)}
{
}

bool PQRegistryReadView::IsValid() const noexcept
{
    return m_snapshot && m_snapshot->state &&
           m_snapshot->state->operator_states &&
           m_snapshot->state->used_tree_ids && m_snapshot->state->indexes &&
           m_snapshot->block_tree_ids;
}

int32_t PQRegistryReadView::Height() const noexcept
{
    return IsValid() ? m_snapshot->height : -1;
}

uint256 PQRegistryReadView::BlockHash() const noexcept
{
    return IsValid() ? m_snapshot->block_hash : uint256{};
}

uint256 PQRegistryReadView::PreviousBlockHash() const noexcept
{
    return IsValid() ? m_snapshot->previous_block_hash : uint256{};
}

uint256 PQRegistryReadView::ConsensusStateRoot() const noexcept
{
    return IsValid() ? m_snapshot->state->consensus_state_root : uint256{};
}

std::size_t PQRegistryReadView::OperatorCount() const noexcept
{
    return IsValid() ? m_snapshot->state->operator_states->size() : 0;
}

std::size_t PQRegistryReadView::UsedTreeIdCount() const noexcept
{
    return IsValid() ? m_snapshot->state->used_tree_ids->size() : 0;
}

bool PQRegistryReadView::HasUsedTreeId(const uint256& tree_id) const noexcept
{
    if (!IsValid() || tree_id.IsNull()) return false;
    const auto& ids{*m_snapshot->state->used_tree_ids};
    return std::binary_search(ids.begin(), ids.end(), tree_id);
}

const OperatorKeyState* PQRegistryReadView::FindOperator(
    const uint256& pro_tx_hash) const noexcept
{
    if (!IsValid() || pro_tx_hash.IsNull()) return nullptr;
    const auto& states{*m_snapshot->state->operator_states};
    const auto position{FindOperatorPosition(states, pro_tx_hash)};
    return position != states.end() && position->pro_tx_hash == pro_tx_hash
        ? &*position
        : nullptr;
}

std::optional<uint256> PQRegistryReadView::FindRetainedGlobalKeyOwner(
    const GlobalPublicKey& public_key) const noexcept
{
    if (!IsValid()) return std::nullopt;
    const auto owner{
        m_snapshot->state->indexes->global_key_owner.find(public_key)};
    if (owner == m_snapshot->state->indexes->global_key_owner.end()) {
        return std::nullopt;
    }
    return owner->second;
}

std::optional<uint256> PQRegistryReadView::FindActiveOperatorByGlobalKey(
    const GlobalPublicKey& public_key) const noexcept
{
    const auto owner{FindRetainedGlobalKeyOwner(public_key)};
    if (!owner) return std::nullopt;
    const auto* state{FindOperator(*owner)};
    return state != nullptr && state->HasActiveGlobalKey()
        ? owner
        : std::nullopt;
}

std::span<const OperatorKeyState> PQRegistryReadView::Operators() const noexcept
{
    if (!IsValid()) return {};
    return *m_snapshot->state->operator_states;
}

std::shared_ptr<const std::vector<OperatorKeyState>>
PQRegistryReadView::ShareOperatorStates() const noexcept
{
    return IsValid() ? m_snapshot->state->operator_states : nullptr;
}

bool PQRegistryReadView::SharesStateWith(
    const PQRegistryReadView& other) const noexcept
{
    return IsValid() && other.IsValid() &&
           m_snapshot->state == other.m_snapshot->state;
}

bool PQRegistryReadView::SharesTreeHistoryWith(
    const PQRegistryReadView& other) const noexcept
{
    return IsValid() && other.IsValid() &&
           m_snapshot->state->used_tree_ids ==
               other.m_snapshot->state->used_tree_ids;
}

bool PQRegistryConfig::IsValid() const noexcept
{
    if (preparation_height <= 0 || !schedule.IsValid() ||
        registration_cutoff_blocks == 0 ||
        future_horizon_epochs < ACTIVE_QUORUMS ||
        future_horizon_epochs > MAX_OPERATOR_SCHEDULE_EPOCHS ||
        preparation_height >= schedule.epoch_origin) {
        return false;
    }
    const auto epoch_zero_cutoff{RegistrationCutoffHeight(
        schedule, 0, registration_cutoff_blocks)};
    const auto preparation_view{DeriveOperatorKeyScheduleView(
        schedule, preparation_height, registration_cutoff_blocks,
        future_horizon_epochs)};
    return epoch_zero_cutoff && preparation_height < *epoch_zero_cutoff &&
           preparation_view && preparation_view->has_current_epoch == 0 &&
           preparation_view->first_mutable_epoch == 0 &&
           preparation_view->last_admissible_epoch >= ACTIVE_QUORUMS - 1;
}

PQRegistryDeploymentResult GetPQRegistryConfig(
    const Consensus::Params& params,
    PQRegistryConfig& config) noexcept
{
    config = {};
    const bool disabled{
        params.nPQPreparationHeight == std::numeric_limits<int>::max() &&
        params.nPQChainLockEpochOrigin == std::numeric_limits<int>::max() &&
        params.nPQRegistrationCutoffBlocks == 0 &&
        params.nPQFutureHorizonEpochs == 0};
    if (disabled) return PQRegistryDeploymentResult::DISABLED;
    const auto anchor_configuration{
        Consensus::CheckPQLegacyAnchorConfiguration(params)};
    if (params.nPQPreparationHeight < params.DIP0003Height ||
        params.nPQPreparationHeight == std::numeric_limits<int>::max() ||
        params.nPQChainLockEpochOrigin == std::numeric_limits<int>::max() ||
        params.nPQRegistrationCutoffBlocks == 0 ||
        params.nPQFutureHorizonEpochs == 0 ||
        anchor_configuration ==
            Consensus::PQAnchorResult::INVALID_CONFIGURATION ||
        (anchor_configuration == Consensus::PQAnchorResult::VALID &&
         params.nPQPreparationHeight > params.nPQLegacyAnchorHeight)) {
        return PQRegistryDeploymentResult::INVALID_CONFIGURATION;
    }
    const auto schedule{
        MakeChainLockScheduleConfig(params.nPQChainLockEpochOrigin)};
    if (!schedule) return PQRegistryDeploymentResult::INVALID_CONFIGURATION;
    config.preparation_height = params.nPQPreparationHeight;
    config.schedule = *schedule;
    config.registration_cutoff_blocks = params.nPQRegistrationCutoffBlocks;
    config.future_horizon_epochs = params.nPQFutureHorizonEpochs;
    return config.IsValid() ? PQRegistryDeploymentResult::VALID
                            : PQRegistryDeploymentResult::INVALID_CONFIGURATION;
}

bool PQRegistrySnapshot::IsStructurallyValid() const noexcept
{
    if (version != PQ_REGISTRY_SNAPSHOT_VERSION || height < 0 ||
        block_hash.IsNull() || consensus_state_root.IsNull() ||
        operator_states.size() > MAX_PQ_OPERATOR_STATES ||
        used_tree_ids.size() > MAX_PQ_USED_TREE_IDS ||
        block_tree_ids.size() > MAX_PQ_TREE_IDS_PER_BLOCK ||
        !IsStrictlySortedOperators(operator_states) ||
        (!used_tree_ids.empty() &&
         !IsStrictlySortedUnique(used_tree_ids)) ||
        (!block_tree_ids.empty() &&
         !IsStrictlySortedUnique(block_tree_ids)) ||
        !IsSubset(block_tree_ids, used_tree_ids) ||
        !StateTreeIdsAreRecorded(operator_states, used_tree_ids)) {
        return false;
    }
    for (std::size_t index{0}; index < operator_states.size(); ++index) {
        const auto& state{operator_states[index]};
        if (state.schedule_initialized == 0 ||
            (state.has_global_key != 0 &&
             state.global_key.activated_height >
                 static_cast<uint32_t>(height)) ||
            state.revoked_height > static_cast<uint32_t>(height) ||
            (index != 0 && state.schedule != operator_states[0].schedule)) {
            return false;
        }
    }
    return true;
}

bool PQRegistrySnapshot::IsEmpty() const noexcept
{
    return operator_states.empty() && used_tree_ids.empty();
}

bool PQRegistrySnapshot::HasUsedTreeId(const uint256& tree_id) const noexcept
{
    return !tree_id.IsNull() &&
           std::binary_search(used_tree_ids.begin(), used_tree_ids.end(),
                              tree_id);
}

const OperatorKeyState* PQRegistrySnapshot::FindOperator(
    const uint256& pro_tx_hash) const noexcept
{
    if (pro_tx_hash.IsNull()) return nullptr;
    const auto position{FindOperatorPosition(operator_states, pro_tx_hash)};
    return position != operator_states.end() &&
                   position->pro_tx_hash == pro_tx_hash
        ? &*position
        : nullptr;
}

std::optional<uint256> PQRegistrySnapshot::RecomputeConsensusStateRoot(
    const uint256& genesis_hash) const
{
    const auto tree_set_hash{GetUsedTreeIdSetHash(genesis_hash,
                                                  used_tree_ids)};
    if (!tree_set_hash || !IsStrictlySortedOperators(operator_states) ||
        !StateTreeIdsAreRecorded(operator_states, used_tree_ids)) {
        return std::nullopt;
    }
    return GetPQKeyConsensusStateHash(
        genesis_hash,
        std::span<const OperatorKeyState>{operator_states.data(),
                                          operator_states.size()},
        *tree_set_hash);
}

bool PQRegistryDiskSnapshot::IsStructurallyValid() const noexcept
{
    if (version != PQ_REGISTRY_DISK_VERSION || is_checkpoint > 1 ||
        height < 0 || block_hash.IsNull() || previous_block_hash.IsNull() ||
        previous_consensus_state_root.IsNull() ||
        consensus_state_root.IsNull() ||
        operator_states.size() > MAX_PQ_OPERATOR_STATES ||
        removed_operators.size() > MAX_PQ_OPERATOR_STATES ||
        tree_ids.size() > MAX_PQ_USED_TREE_IDS ||
        block_tree_ids.size() > MAX_PQ_TREE_IDS_PER_BLOCK ||
        !IsStrictlySortedOperators(operator_states) ||
        (!removed_operators.empty() &&
         !IsStrictlySortedUnique(removed_operators)) ||
        (!tree_ids.empty() && !IsStrictlySortedUnique(tree_ids)) ||
        (!block_tree_ids.empty() &&
         !IsStrictlySortedUnique(block_tree_ids)) ||
        (is_checkpoint != 0 && !removed_operators.empty()) ||
        (is_checkpoint == 0 && !tree_ids.empty()) ||
        (is_checkpoint != 0 &&
         (!IsSubset(block_tree_ids, tree_ids) ||
          !StateTreeIdsAreRecorded(operator_states, tree_ids)))) {
        return false;
    }
    for (const auto& state : operator_states) {
        if (state.has_global_key != 0 &&
            state.global_key.activated_height >
                static_cast<uint32_t>(height)) {
            return false;
        }
        if (state.revoked_height > static_cast<uint32_t>(height)) {
            return false;
        }
    }
    for (const auto& removed : removed_operators) {
        const auto position{FindOperatorPosition(operator_states, removed)};
        if (position != operator_states.end() &&
            position->pro_tx_hash == removed) {
            return false;
        }
    }
    return true;
}

void PQRegistryError::Clear() noexcept
{
    *this = {};
}

std::string_view PQRegistryResultString(PQRegistryResult result) noexcept
{
    switch (result) {
    case PQRegistryResult::OK: return "ok";
    case PQRegistryResult::INVALID_CONFIGURATION: return "invalid-configuration";
    case PQRegistryResult::INVALID_BLOCK: return "invalid-block";
    case PQRegistryResult::PQ_TX_BEFORE_PREPARATION: return "pq-tx-before-preparation";
    case PQRegistryResult::MISSING_PARENT_SNAPSHOT: return "missing-parent-snapshot";
    case PQRegistryResult::INVALID_SCHEDULE: return "invalid-schedule";
    case PQRegistryResult::CALLBACK_MISSING: return "callback-missing";
    case PQRegistryResult::CALLBACK_FAILED: return "callback-failed";
    case PQRegistryResult::PARENT_DMN_MISMATCH: return "parent-dmn-mismatch";
    case PQRegistryResult::DMN_MISSING_AT_PARENT: return "dmn-missing-at-parent";
    case PQRegistryResult::DMN_REMOVED_IN_BLOCK: return "dmn-removed-in-block";
    case PQRegistryResult::DUPLICATE_OPERATOR_UPDATE: return "duplicate-operator-update";
    case PQRegistryResult::DUPLICATE_GLOBAL_KEY: return "duplicate-global-key";
    case PQRegistryResult::DUPLICATE_CHILD_TREE_ID: return "duplicate-child-tree-id";
    case PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD: return "invalid-global-key-payload";
    case PQRegistryResult::INVALID_PROVIDER_REVOCATION_PAYLOAD: return "invalid-provider-revocation-payload";
    case PQRegistryResult::TRANSACTION_INPUTS_HASH_MISMATCH: return "transaction-inputs-hash-mismatch";
    case PQRegistryResult::OWNER_AUTHORIZATION_FAILED: return "owner-authorization-failed";
    case PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED: return "operator-state-transition-failed";
    case PQRegistryResult::INVALID_RESULTING_STATE: return "invalid-resulting-state";
    case PQRegistryResult::SNAPSHOT_NOT_FOUND: return "snapshot-not-found";
    case PQRegistryResult::SNAPSHOT_CORRUPT: return "snapshot-corrupt";
    case PQRegistryResult::SNAPSHOT_CONFLICT: return "snapshot-conflict";
    case PQRegistryResult::PERSISTENCE_FAILED: return "persistence-failed";
    case PQRegistryResult::UNDO_MISMATCH: return "undo-mismatch";
    case PQRegistryResult::INTERNAL_ERROR: return "internal-error";
    }
    return "unknown";
}

bool PQRegistryCallbacks::HasMembershipCallbacks() const noexcept
{
    return static_cast<bool>(dmn_exists_before) &&
           static_cast<bool>(dmn_exists_after);
}

const PQRegistryMempoolOperatorState* PQRegistryMempoolView::FindOperator(
    const uint256& pro_tx_hash) const noexcept
{
    const auto position{std::lower_bound(
        operators.begin(), operators.end(), pro_tx_hash,
        [](const PQRegistryMempoolOperatorState& state,
           const uint256& sought) {
            return state.pro_tx_hash < sought;
        })};
    return position != operators.end() &&
                   position->pro_tx_hash == pro_tx_hash
        ? &*position
        : nullptr;
}

PQRegistryManager::PQRegistryManager(const DBParams& db_params,
                                     const uint256& genesis_hash,
                                     const PQRegistryConfig& config)
    : m_genesis_hash(genesis_hash),
      m_config(config),
      m_snapshot_db(std::make_unique<CEvoDB<
          uint256, PQRegistryDiskSnapshot, StaticSaltedHasher>>(
          RegistryDBParams(db_params, "snapshots"),
          /*maxCacheSizeIn=*/0, PQ_REGISTRY_SNAPSHOT_CACHE_SIZE))
{
}

bool PQRegistryManager::IsEnabled() const noexcept
{
    return !m_genesis_hash.IsNull() && m_config.IsValid();
}

bool PQRegistryManager::CacheSnapshot(
    const PQRegistrySnapshot& snapshot,
    std::shared_ptr<const PQRegistrySnapshotView>* cached) const
{
    std::optional<OperatorKeyScheduleState> schedule;
    if (snapshot.height > 0) {
        schedule = ScheduleStateAtHeight(m_config, snapshot.height);
        if (!schedule) return false;
    }

    std::shared_ptr<const PQRegistryStateData> state;
    for (auto entry{m_snapshot_cache.rbegin()};
         entry != m_snapshot_cache.rend(); ++entry) {
        const auto& candidate{entry->second};
        if (candidate && candidate->state &&
            candidate->state->consensus_state_root ==
                snapshot.consensus_state_root &&
            candidate->state->schedule == schedule) {
            state = candidate->state;
            break;
        }
    }
    if (!state) {
        const auto tree_hash{
            GetUsedTreeIdSetHash(m_genesis_hash, snapshot.used_tree_ids)};
        const auto indexes{BuildRegistryIndexes(snapshot.operator_states)};
        if (!tree_hash || !indexes) return false;

        std::shared_ptr<const std::vector<uint256>> used_tree_ids;
        for (auto entry{m_snapshot_cache.rbegin()};
             entry != m_snapshot_cache.rend(); ++entry) {
            const auto& candidate{entry->second};
            if (candidate && candidate->state &&
                candidate->state->used_tree_ids_hash == *tree_hash &&
                candidate->state->used_tree_ids &&
                candidate->state->used_tree_ids->size() ==
                    snapshot.used_tree_ids.size()) {
                used_tree_ids = candidate->state->used_tree_ids;
                break;
            }
        }
        if (!used_tree_ids) {
            used_tree_ids =
                std::make_shared<const std::vector<uint256>>(
                    snapshot.used_tree_ids);
        }

        auto next{std::make_shared<PQRegistryStateData>()};
        next->operator_states =
            std::make_shared<const std::vector<OperatorKeyState>>(
                snapshot.operator_states);
        next->used_tree_ids = std::move(used_tree_ids);
        next->indexes = std::move(indexes);
        next->schedule = schedule;
        next->used_tree_ids_hash = *tree_hash;
        next->consensus_state_root = snapshot.consensus_state_root;
        next->owned_dynamic_memory_usage =
            RegistryStateOwnedDynamicMemoryUsage(*next);
        next->used_tree_ids_dynamic_memory_usage =
            sizeof(std::vector<uint256>) +
            memusage::DynamicUsage(*next->used_tree_ids);
        state = std::move(next);
    }

    auto view{std::make_shared<PQRegistrySnapshotView>()};
    view->height = snapshot.height;
    view->block_hash = snapshot.block_hash;
    view->previous_block_hash = snapshot.previous_block_hash;
    view->state = std::move(state);
    view->block_tree_ids =
        std::make_shared<const std::vector<uint256>>(snapshot.block_tree_ids);

    auto existing{m_snapshot_cache_index.find(snapshot.block_hash)};
    if (existing != m_snapshot_cache_index.end()) {
        m_snapshot_cache.erase(existing->second);
        m_snapshot_cache_index.erase(existing);
    }
    m_snapshot_cache.emplace_back(snapshot.block_hash, std::move(view));
    m_snapshot_cache_index[snapshot.block_hash] =
        std::prev(m_snapshot_cache.end());
    if (cached != nullptr) {
        *cached = m_snapshot_cache.back().second;
    }
    // The newest state is the unavoidable live baseline. Bound only additional
    // historical ownership so a large baseline can still retain cheap no-op
    // block views without making the cache itself unbounded.
    while (m_snapshot_cache.size() > 1 &&
           (m_snapshot_cache.size() > PQ_REGISTRY_SNAPSHOT_CACHE_SIZE ||
            SnapshotCacheDynamicMemoryUsage(
                m_snapshot_cache,
                m_snapshot_cache.back().second->state.get()) >
                PQ_REGISTRY_SNAPSHOT_CACHE_MAX_INCREMENTAL_BYTES)) {
        m_snapshot_cache_index.erase(m_snapshot_cache.front().first);
        m_snapshot_cache.pop_front();
    }
    return true;
}

bool PQRegistryManager::ReadDiskSnapshot(
    const uint256& block_hash,
    PQRegistryDiskSnapshot& snapshot,
    PQRegistryError& error) const
{
    if (block_hash.IsNull()) {
        return SetError(error, PQRegistryResult::SNAPSHOT_NOT_FOUND);
    }
    if (!m_snapshot_db->ReadCache(block_hash, snapshot)) {
        return SetError(
            error, m_snapshot_db->ExistsCache(block_hash)
                ? PQRegistryResult::SNAPSHOT_CORRUPT
                : PQRegistryResult::SNAPSHOT_NOT_FOUND);
    }
    if (!snapshot.IsStructurallyValid() || snapshot.block_hash != block_hash) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    return true;
}

bool PQRegistryManager::ReconstructPersistentSnapshotView(
    const uint256& block_hash,
    int32_t expected_height,
    std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
    PQRegistryError& error) const
{
    snapshot.reset();
    const auto cached{m_snapshot_cache_index.find(block_hash)};
    if (cached != m_snapshot_cache_index.end()) {
        const auto& candidate{cached->second->second};
        if (!candidate || !candidate->state ||
            candidate->height != expected_height ||
            candidate->block_hash != block_hash) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        snapshot = candidate;
        m_snapshot_cache.splice(m_snapshot_cache.end(), m_snapshot_cache,
                                cached->second);
        cached->second = std::prev(m_snapshot_cache.end());
        return true;
    }

    std::vector<PQRegistryDiskSnapshot> reverse_journal;
    reverse_journal.reserve(PQ_REGISTRY_CHECKPOINT_INTERVAL);
    uint256 cursor{block_hash};
    int32_t cursor_height{expected_height};
    for (int32_t depth{0}; depth < PQ_REGISTRY_CHECKPOINT_INTERVAL; ++depth) {
        PQRegistryDiskSnapshot record;
        if (!ReadDiskSnapshot(cursor, record, error)) return false;
        const bool expected_checkpoint{
            (cursor_height - m_config.preparation_height) %
                PQ_REGISTRY_CHECKPOINT_INTERVAL ==
            0};
        if (record.height != cursor_height || record.block_hash != cursor ||
            (record.is_checkpoint != 0) != expected_checkpoint) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        if (!reverse_journal.empty()) {
            const auto& child{reverse_journal.back()};
            if (child.previous_block_hash != record.block_hash ||
                child.previous_consensus_state_root !=
                    record.consensus_state_root ||
                child.height != record.height + 1) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }
        reverse_journal.push_back(std::move(record));
        if (reverse_journal.back().is_checkpoint != 0) break;
        if (reverse_journal.back().previous_block_hash.IsNull() ||
            cursor_height <= 0) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        cursor = reverse_journal.back().previous_block_hash;
        --cursor_height;
    }
    if (reverse_journal.empty() ||
        reverse_journal.back().is_checkpoint == 0) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    const auto& checkpoint{reverse_journal.back()};
    if (checkpoint.height == m_config.preparation_height) {
        PQRegistrySnapshot parent;
        if (!MakePrePreparationSnapshot(
                m_genesis_hash, checkpoint.previous_block_hash, uint256{},
                checkpoint.height - 1, parent, error) ||
            checkpoint.previous_consensus_state_root !=
                parent.consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    } else {
        PQRegistryDiskSnapshot parent;
        if (!ReadDiskSnapshot(checkpoint.previous_block_hash, parent, error) ||
            parent.height != checkpoint.height - 1 ||
            parent.consensus_state_root !=
                checkpoint.previous_consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }

    std::vector<OperatorKeyState> states;
    std::vector<uint256> used_tree_ids;
    for (auto record{reverse_journal.rbegin()};
         record != reverse_journal.rend(); ++record) {
        if (record->is_checkpoint != 0) {
            states = record->operator_states;
            used_tree_ids = record->tree_ids;
        } else {
            for (const auto& removed : record->removed_operators) {
                auto position{FindOperatorPosition(states, removed)};
                if (position == states.end() ||
                    position->pro_tx_hash != removed) {
                    return SetError(error,
                                    PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                states.erase(position);
            }
            for (const auto& changed : record->operator_states) {
                auto position{
                    FindOperatorPosition(states, changed.pro_tx_hash)};
                if (position != states.end() &&
                    position->pro_tx_hash == changed.pro_tx_hash) {
                    if (*position == changed) {
                        return SetError(error,
                                        PQRegistryResult::SNAPSHOT_CORRUPT);
                    }
                    *position = changed;
                } else {
                    states.insert(position, changed);
                }
            }
            std::vector<uint256> merged;
            if (!MergeNewTreeIds(used_tree_ids, record->block_tree_ids,
                                 merged)) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            used_tree_ids = std::move(merged);
        }
        const auto schedule_view{DeriveOperatorKeyScheduleView(
            m_config.schedule, record->height,
            m_config.registration_cutoff_blocks,
            m_config.future_horizon_epochs)};
        const auto tree_set_hash{
            GetUsedTreeIdSetHash(m_genesis_hash, used_tree_ids)};
        if (!schedule_view || !tree_set_hash ||
            !StateTreeIdsAreRecorded(states, used_tree_ids) ||
            std::any_of(states.begin(), states.end(),
                        [&](const OperatorKeyState& state) {
                            return !state.IsAdvancedTo(*schedule_view);
                        })) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto root{GetPQKeyConsensusStateHash(
            m_genesis_hash,
            std::span<const OperatorKeyState>{states.data(), states.size()},
            *tree_set_hash)};
        if (!root || *root != record->consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }

    const auto& disk{reverse_journal.front()};
    PQRegistrySnapshot rebuilt;
    rebuilt.height = disk.height;
    rebuilt.block_hash = disk.block_hash;
    rebuilt.previous_block_hash = disk.previous_block_hash;
    rebuilt.operator_states = std::move(states);
    rebuilt.used_tree_ids = std::move(used_tree_ids);
    rebuilt.block_tree_ids = disk.block_tree_ids;
    rebuilt.consensus_state_root = disk.consensus_state_root;
    const auto root{rebuilt.RecomputeConsensusStateRoot(m_genesis_hash)};
    if (!rebuilt.IsStructurallyValid() || !root ||
        *root != rebuilt.consensus_state_root) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    if (!CacheSnapshot(rebuilt, &snapshot) || !snapshot) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    return true;
}

bool PQRegistryManager::ReconstructPersistentSnapshot(
    const uint256& block_hash,
    int32_t expected_height,
    PQRegistrySnapshot& snapshot,
    PQRegistryError& error) const
{
    std::shared_ptr<const PQRegistrySnapshotView> view;
    if (!ReconstructPersistentSnapshotView(block_hash, expected_height, view,
                                           error) ||
        !view) {
        return false;
    }
    snapshot = MaterializeSnapshot(*view);
    return true;
}

bool PQRegistryManager::CommitSnapshot(
    const PQRegistrySnapshot& snapshot,
    const PQRegistrySnapshot& parent,
    PQRegistryError& error)
{
    const auto parent_root{parent.RecomputeConsensusStateRoot(m_genesis_hash)};
    const auto snapshot_root{
        snapshot.RecomputeConsensusStateRoot(m_genesis_hash)};
    if (!parent.IsStructurallyValid() || !parent_root ||
        *parent_root != parent.consensus_state_root ||
        !snapshot.IsStructurallyValid() || !snapshot_root ||
        *snapshot_root != snapshot.consensus_state_root ||
        snapshot.height != parent.height + 1 ||
        snapshot.previous_block_hash != parent.block_hash ||
        snapshot.block_hash == parent.block_hash) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    std::vector<uint256> expected_tree_ids;
    if (!MergeNewTreeIds(parent.used_tree_ids, snapshot.block_tree_ids,
                         expected_tree_ids) ||
        expected_tree_ids != snapshot.used_tree_ids) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }

    PQRegistryDiskSnapshot disk;
    disk.is_checkpoint = static_cast<uint8_t>(
        (snapshot.height - m_config.preparation_height) %
            PQ_REGISTRY_CHECKPOINT_INTERVAL ==
        0);
    disk.height = snapshot.height;
    disk.block_hash = snapshot.block_hash;
    disk.previous_block_hash = snapshot.previous_block_hash;
    disk.previous_consensus_state_root = parent.consensus_state_root;
    disk.block_tree_ids = snapshot.block_tree_ids;
    if (disk.is_checkpoint != 0) {
        disk.operator_states = snapshot.operator_states;
        disk.tree_ids = snapshot.used_tree_ids;
    } else {
        auto previous{parent.operator_states.begin()};
        auto current{snapshot.operator_states.begin()};
        while (previous != parent.operator_states.end() ||
               current != snapshot.operator_states.end()) {
            if (current == snapshot.operator_states.end() ||
                (previous != parent.operator_states.end() &&
                 previous->pro_tx_hash < current->pro_tx_hash)) {
                disk.removed_operators.push_back(previous++->pro_tx_hash);
            } else if (previous == parent.operator_states.end() ||
                       current->pro_tx_hash < previous->pro_tx_hash) {
                disk.operator_states.push_back(*current++);
            } else {
                if (*previous != *current) {
                    disk.operator_states.push_back(*current);
                }
                ++previous;
                ++current;
            }
        }
    }
    disk.consensus_state_root = snapshot.consensus_state_root;
    if (!disk.IsStructurallyValid()) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }

    PQRegistryDiskSnapshot existing;
    if (m_snapshot_db->ReadCache(snapshot.block_hash, existing)) {
        if (!existing.IsStructurallyValid() || existing != disk) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CONFLICT);
        }
    } else if (m_snapshot_db->ExistsCache(snapshot.block_hash)) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    } else if (!m_snapshot_db->WriteThrough(
                   snapshot.block_hash, disk, /*fSync=*/false)) {
        // SYSCOIN: Every branch-local journal link enters LevelDB immediately
        // so bounded memory cannot discard it, but a per-block fsync would make
        // IBD needlessly serial. The UTXO best-block publication path places a
        // synchronous PQ-registry barrier before committing CoinsTip.
        return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
    }
    return CacheSnapshot(snapshot)
        ? true
        : SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
}

bool PQRegistryManager::ProcessBlock(
    const CBlock& block,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    bool fJustCheck,
    PQRegistryError& error,
    uint256* resulting_state_root)
{
    return ProcessBlockInternal(block, height, callbacks, fJustCheck,
                                /*check_sigs=*/true, error,
                                resulting_state_root);
}

bool PQRegistryManager::ProcessBlockInternal(
    const CBlock& block,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    bool fJustCheck,
    bool check_sigs,
    PQRegistryError& error,
    uint256* resulting_state_root)
{
    error.Clear();
    if (!check_sigs && !fJustCheck) {
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
    }
    if (!IsEnabled()) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    if (height <= 0 || block.vtx.empty() || block.hashPrevBlock.IsNull()) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }
    const uint256 block_hash{block.GetHash()};
    if (block_hash.IsNull()) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }

    if (height < m_config.preparation_height) {
        for (std::size_t index{0}; index < block.vtx.size(); ++index) {
            if (block.vtx[index] &&
                (block.vtx[index]->nVersion == PQ_GLOBAL_KEY_TX_VERSION ||
                 IsPQProviderRevocation(*block.vtx[index]))) {
                return SetError(error,
                                PQRegistryResult::PQ_TX_BEFORE_PREPARATION,
                                index);
            }
        }
        if (resulting_state_root != nullptr) {
            PQRegistrySnapshot empty;
            if (!MakePrePreparationSnapshot(
                    m_genesis_hash, block_hash, block.hashPrevBlock, height,
                    empty, error)) {
                return false;
            }
            *resulting_state_root = empty.consensus_state_root;
        }
        return true;
    }
    if (!callbacks.HasMembershipCallbacks()) {
        return SetError(error, PQRegistryResult::CALLBACK_MISSING);
    }
    const auto schedule_view{DeriveOperatorKeyScheduleView(
        m_config.schedule, height, m_config.registration_cutoff_blocks,
        m_config.future_horizon_epochs)};
    if (!schedule_view) {
        return SetError(error, PQRegistryResult::INVALID_SCHEDULE);
    }

    std::vector<DecodedUpdate> updates;
    updates.reserve(block.vtx.size());
    std::vector<uint256> updated_operators;
    updated_operators.reserve(block.vtx.size());
    for (std::size_t index{0}; index < block.vtx.size(); ++index) {
        if (!block.vtx[index]) {
            return SetError(error, PQRegistryResult::INVALID_BLOCK, index);
        }
        const CTransaction& transaction{*block.vtx[index]};
        std::optional<DecodedUpdate> decoded;
        if (!DecodeRegistryUpdate(transaction, index, decoded, error)) {
            return false;
        }
        if (!decoded) continue;
        auto& update{*decoded};
        if (std::find(updated_operators.begin(), updated_operators.end(),
                      update.pro_tx_hash) != updated_operators.end()) {
            return SetError(error,
                            PQRegistryResult::DUPLICATE_OPERATOR_UPDATE,
                            index, update.pro_tx_hash);
        }
        updated_operators.push_back(update.pro_tx_hash);
        updates.push_back(std::move(update));
    }

    PQRegistrySnapshot parent;
    if (height == m_config.preparation_height) {
        if (!MakePrePreparationSnapshot(
                m_genesis_hash, block.hashPrevBlock, uint256{}, height - 1,
                parent, error)) {
            return false;
        }
    } else {
        LOCK(m_mutex);
        if (!ReconstructPersistentSnapshot(block.hashPrevBlock, height - 1,
                                           parent, error)) {
            if (error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND) {
                error.result = PQRegistryResult::MISSING_PARENT_SNAPSHOT;
            }
            return false;
        }
    }

    for (const auto& state : parent.operator_states) {
        bool exists{false};
        if (!CallMembership(callbacks.dmn_exists_before, state.pro_tx_hash,
                            exists, error)) {
            return false;
        }
        if (!exists) {
            return SetError(error, PQRegistryResult::PARENT_DMN_MISMATCH,
                            std::numeric_limits<std::size_t>::max(),
                            state.pro_tx_hash);
        }
    }

    PQRegistrySnapshot next{parent};
    next.height = height;
    next.block_hash = block_hash;
    next.previous_block_hash = block.hashPrevBlock;
    next.block_tree_ids.clear();
    for (auto& state : next.operator_states) {
        const auto result{state.Advance(*schedule_view)};
        if (result != OperatorKeyStateResult::OK) {
            return SetError(
                error, PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                std::numeric_limits<std::size_t>::max(), state.pro_tx_hash,
                result);
        }
    }

    for (const auto& update : updates) {
        bool exists_before{false};
        if (!CallMembership(callbacks.dmn_exists_before, update.pro_tx_hash,
                            exists_before, error,
                            update.transaction_index)) {
            return false;
        }
        if (!exists_before) {
            return SetError(error, PQRegistryResult::DMN_MISSING_AT_PARENT,
                            update.transaction_index, update.pro_tx_hash);
        }
        bool exists_after{false};
        if (!CallMembership(callbacks.dmn_exists_after, update.pro_tx_hash,
                            exists_after, error,
                            update.transaction_index)) {
            return false;
        }
        if (!exists_after) {
            return SetError(error, PQRegistryResult::DMN_REMOVED_IN_BLOCK,
                            update.transaction_index, update.pro_tx_hash);
        }

        auto state{FindOperatorPosition(next.operator_states,
                                        update.pro_tx_hash)};
        if (state == next.operator_states.end() ||
            state->pro_tx_hash != update.pro_tx_hash) {
            OperatorKeyState fresh{
                OperatorKeyState::ForOperator(update.pro_tx_hash)};
            const auto result{fresh.Advance(*schedule_view)};
            if (result != OperatorKeyStateResult::OK) {
                return SetError(
                    error,
                    PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                    update.transaction_index, update.pro_tx_hash, result);
            }
            state = next.operator_states.insert(state, std::move(fresh));
        }

        std::optional<uint256> introduced_tree_id;
        const auto find_global_key_owner{
            [&](const GlobalPublicKey& public_key)
                -> std::optional<uint256> {
                const auto owner{std::find_if(
                    next.operator_states.begin(),
                    next.operator_states.end(),
                    [&](const OperatorKeyState& existing) {
                        return existing.pro_tx_hash != update.pro_tx_hash &&
                               existing.has_global_key != 0 &&
                               existing.global_key.public_key == public_key;
                    })};
                return owner == next.operator_states.end()
                    ? std::nullopt
                    : std::optional<uint256>{owner->pro_tx_hash};
            }};
        if (!ApplyDecodedUpdate(
                *state, update, *schedule_view, m_genesis_hash, callbacks,
                check_sigs, find_global_key_owner,
                [&](const uint256& tree_id) {
                    return next.HasUsedTreeId(tree_id);
                },
                introduced_tree_id, error)) {
            return false;
        }
        if (introduced_tree_id) {
            next.block_tree_ids.push_back(*introduced_tree_id);
            auto position{std::lower_bound(next.used_tree_ids.begin(),
                                           next.used_tree_ids.end(),
                                           *introduced_tree_id)};
            next.used_tree_ids.insert(position, *introduced_tree_id);
        }
    }

    for (auto state{next.operator_states.begin()};
         state != next.operator_states.end();) {
        bool exists_after{false};
        if (!CallMembership(callbacks.dmn_exists_after, state->pro_tx_hash,
                            exists_after, error)) {
            return false;
        }
        if (!exists_after) {
            state = next.operator_states.erase(state);
        } else {
            ++state;
        }
    }
    std::sort(next.block_tree_ids.begin(), next.block_tree_ids.end());
    if ((!next.block_tree_ids.empty() &&
         !IsStrictlySortedUnique(next.block_tree_ids)) ||
        next.used_tree_ids.size() > MAX_PQ_USED_TREE_IDS) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    const auto state_root{next.RecomputeConsensusStateRoot(m_genesis_hash)};
    if (!state_root) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    next.consensus_state_root = *state_root;
    if (!next.IsStructurallyValid()) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    if (resulting_state_root != nullptr) {
        *resulting_state_root = next.consensus_state_root;
    }
    if (fJustCheck) return true;

    LOCK(m_mutex);
    return CommitSnapshot(next, parent, error);
}

bool PQRegistryManager::ValidateTransaction(
    const CTransaction& transaction,
    const uint256& parent_block_hash,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    bool check_sigs,
    PQRegistryError& error)
{
    error.Clear();
    if (transaction.nVersion != PQ_GLOBAL_KEY_TX_VERSION ||
        parent_block_hash.IsNull() || height <= 0) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }
    if (!IsEnabled()) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    if (height < m_config.preparation_height) {
        return SetError(error, PQRegistryResult::PQ_TX_BEFORE_PREPARATION,
                        /*transaction_index=*/0);
    }
    if (!callbacks.HasMembershipCallbacks()) {
        return SetError(error, PQRegistryResult::CALLBACK_MISSING);
    }
    const auto schedule_view{DeriveOperatorKeyScheduleView(
        m_config.schedule, height, m_config.registration_cutoff_blocks,
        m_config.future_horizon_epochs)};
    if (!schedule_view) {
        return SetError(error, PQRegistryResult::INVALID_SCHEDULE);
    }

    std::optional<DecodedUpdate> decoded;
    if (!DecodeRegistryUpdate(transaction, /*transaction_index=*/0,
                              decoded, error)) {
        return false;
    }
    if (!decoded) {
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
    }

    const bool logical_empty_parent{
        height == m_config.preparation_height};
    PQRegistryReadView parent;
    if (logical_empty_parent) {
        PQRegistrySnapshot empty;
        if (!MakePrePreparationSnapshot(
                m_genesis_hash, parent_block_hash, uint256{}, height - 1,
                empty, error)) {
            return false;
        }
    } else {
        std::shared_ptr<const PQRegistrySnapshotView> snapshot;
        {
            LOCK(m_mutex);
            if (!ReconstructPersistentSnapshotView(
                    parent_block_hash, height - 1, snapshot, error)) {
                if (error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND) {
                    error.result = PQRegistryResult::MISSING_PARENT_SNAPSHOT;
                }
                return false;
            }
        }
        parent = PQRegistryReadView{std::move(snapshot)};
        if (!parent.IsValid()) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }

    const auto* inherited{logical_empty_parent
        ? nullptr
        : parent.FindOperator(decoded->pro_tx_hash)};
    std::optional<OperatorKeyState> candidate_state;
    if (inherited != nullptr) {
        bool parent_contains_target{false};
        if (!CallMembership(callbacks.dmn_exists_before,
                            decoded->pro_tx_hash, parent_contains_target,
                            error)) {
            return false;
        }
        if (!parent_contains_target) {
            return SetError(error, PQRegistryResult::PARENT_DMN_MISMATCH,
                            std::numeric_limits<std::size_t>::max(),
                            decoded->pro_tx_hash);
        }
        candidate_state = *inherited;
        const auto advance{candidate_state->Advance(*schedule_view)};
        if (advance != OperatorKeyStateResult::OK) {
            return SetError(
                error, PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                std::numeric_limits<std::size_t>::max(),
                decoded->pro_tx_hash, advance);
        }
    }

    bool exists_before{false};
    if (!CallMembership(callbacks.dmn_exists_before,
                        decoded->pro_tx_hash, exists_before, error,
                        decoded->transaction_index)) {
        return false;
    }
    if (!exists_before) {
        return SetError(error, PQRegistryResult::DMN_MISSING_AT_PARENT,
                        decoded->transaction_index, decoded->pro_tx_hash);
    }
    bool exists_after{false};
    if (!CallMembership(callbacks.dmn_exists_after, decoded->pro_tx_hash,
                        exists_after, error,
                        decoded->transaction_index)) {
        return false;
    }
    if (!exists_after) {
        return SetError(error, PQRegistryResult::DMN_REMOVED_IN_BLOCK,
                        decoded->transaction_index, decoded->pro_tx_hash);
    }

    // SYSCOIN: Accepted parents were reconciled against their complete DMN
    // view during block validation, and policy passes that exact parent list
    // as both membership views. Rechecking unrelated operators here would turn
    // every mempool admission into an O(N) block replay.
    if (!candidate_state) {
        candidate_state =
            OperatorKeyState::ForOperator(decoded->pro_tx_hash);
        const auto advance{candidate_state->Advance(*schedule_view)};
        if (advance != OperatorKeyStateResult::OK) {
            return SetError(
                error, PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                decoded->transaction_index, decoded->pro_tx_hash, advance);
        }
    }
    auto& state{*candidate_state};

    std::optional<uint256> introduced_tree_id;
    if (!ApplyDecodedUpdate(
            state, *decoded, *schedule_view, m_genesis_hash, callbacks,
            check_sigs,
            [&](const GlobalPublicKey& public_key) {
                return logical_empty_parent
                    ? std::nullopt
                    : parent.FindRetainedGlobalKeyOwner(public_key);
            },
            [&](const uint256& tree_id) {
                return !logical_empty_parent &&
                       parent.HasUsedTreeId(tree_id);
            },
            introduced_tree_id, error)) {
        return false;
    }

    if ((inherited == nullptr &&
         !logical_empty_parent &&
         parent.OperatorCount() >= MAX_PQ_OPERATOR_STATES) ||
        (introduced_tree_id &&
         !logical_empty_parent &&
         parent.UsedTreeIdCount() >= MAX_PQ_USED_TREE_IDS) ||
        !state.IsStructurallyValid()) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    return true;
}

bool PQRegistryManager::GetSnapshot(
    const uint256& block_hash,
    const uint256& previous_block_hash,
    int32_t height,
    PQRegistrySnapshot& snapshot,
    PQRegistryError& error) const
{
    PQRegistryReadView view;
    if (!GetReadView(block_hash, previous_block_hash, height, view, error) ||
        !view.m_snapshot) {
        return false;
    }
    snapshot = MaterializeSnapshot(*view.m_snapshot);
    return true;
}

bool PQRegistryManager::GetReadView(
    const uint256& block_hash,
    const uint256& previous_block_hash,
    int32_t height,
    PQRegistryReadView& view,
    PQRegistryError& error) const
{
    error.Clear();
    view = {};
    if (!IsEnabled()) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    if (height < 0 || block_hash.IsNull() ||
        (height != 0 && previous_block_hash.IsNull())) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }

    LOCK(m_mutex);
    std::shared_ptr<const PQRegistrySnapshotView> snapshot;
    if (height < m_config.preparation_height) {
        PQRegistrySnapshot materialized;
        if (!MakePrePreparationSnapshot(
                m_genesis_hash, block_hash, previous_block_hash, height,
                materialized, error) ||
            !CacheSnapshot(materialized, &snapshot)) {
            if (error.result == PQRegistryResult::OK) {
                SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            return false;
        }
    } else if (!ReconstructPersistentSnapshotView(
                   block_hash, height, snapshot, error)) {
        return false;
    }
    if (!snapshot || snapshot->previous_block_hash != previous_block_hash) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    view = PQRegistryReadView{std::move(snapshot)};
    return true;
}

bool PQRegistryManager::GetPaymentEligibleProTxHashes(
    const uint256& block_hash,
    const uint256& previous_block_hash,
    int32_t height,
    uint32_t epoch,
    PQPaymentEligibleProTxHashesPtr& eligible,
    PQRegistryError& error) const
{
    error.Clear();
    eligible.reset();
    if (!IsEnabled() || height < 0 || block_hash.IsNull() ||
        (height != 0 && previous_block_hash.IsNull())) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }
    if (height < m_config.preparation_height) {
        eligible =
            std::make_shared<const PQPaymentEligibleProTxHashes>();
        return true;
    }

    PQRegistryReadView snapshot;
    if (!GetReadView(block_hash, previous_block_hash, height, snapshot,
                     error)) {
        return false;
    }

    const PaymentEligibilityCacheKey key{snapshot.ConsensusStateRoot(), epoch};
    {
        LOCK(m_mutex);
        const auto eligibility_cached{
            m_payment_eligibility_cache_index.find(key)};
        if (eligibility_cached != m_payment_eligibility_cache_index.end()) {
            eligible = eligibility_cached->second->second;
            m_payment_eligibility_cache.splice(
                m_payment_eligibility_cache.end(),
                m_payment_eligibility_cache, eligibility_cached->second);
            eligibility_cached->second =
                std::prev(m_payment_eligibility_cache.end());
            return true;
        }
    }

    auto derived{std::make_shared<PQPaymentEligibleProTxHashes>()};
    derived->reserve(snapshot.OperatorCount());
    for (const auto& state : snapshot.Operators()) {
        const auto root{state.ResolveChildRoot(epoch)};
        if (root.status != ChildRootResolutionStatus::FROZEN_PRESENT ||
            !root.record || root.record->pro_tx_hash != state.pro_tx_hash ||
            root.record->epoch != epoch) {
            continue;
        }
        derived->push_back(state.pro_tx_hash);
    }
    {
        LOCK(m_mutex);
        const auto winner{m_payment_eligibility_cache_index.find(key)};
        if (winner != m_payment_eligibility_cache_index.end()) {
            eligible = winner->second->second;
            m_payment_eligibility_cache.splice(
                m_payment_eligibility_cache.end(),
                m_payment_eligibility_cache, winner->second);
            winner->second = std::prev(m_payment_eligibility_cache.end());
            return true;
        }
        eligible = derived;
        m_payment_eligibility_cache.emplace_back(key, std::move(derived));
        m_payment_eligibility_cache_index[key] =
            std::prev(m_payment_eligibility_cache.end());
        while (m_payment_eligibility_cache.size() >
               PQ_PAYMENT_ELIGIBILITY_CACHE_SIZE) {
            m_payment_eligibility_cache_index.erase(
                m_payment_eligibility_cache.front().first);
            m_payment_eligibility_cache.pop_front();
        }
    }
    return true;
}

bool PQRegistryManager::GetMempoolView(
    const uint256& block_hash,
    int32_t height,
    std::span<const uint256> requested_operators,
    PQRegistryMempoolView& view,
    PQRegistryError& error) const
{
    error.Clear();
    view = {};
    if (!IsEnabled() || height < 0 || block_hash.IsNull() ||
        requested_operators.size() > MAX_PQ_MEMPOOL_OPERATOR_REQUESTS ||
        (!requested_operators.empty() &&
         !IsStrictlySortedUnique(requested_operators))) {
        return SetError(error, PQRegistryResult::INVALID_BLOCK);
    }

    view.operators.reserve(requested_operators.size());
    if (height < m_config.preparation_height) {
        for (const auto& pro_tx_hash : requested_operators) {
            view.operators.push_back(PQRegistryMempoolOperatorState{
                .pro_tx_hash = pro_tx_hash,
                .state_exists = 0,
                .has_global_key = 0,
                .current_commitment = {},
            });
        }
        return true;
    }

    if (height == std::numeric_limits<int32_t>::max()) {
        return SetError(error, PQRegistryResult::INVALID_SCHEDULE);
    }
    const auto next_schedule{DeriveOperatorKeyScheduleView(
        m_config.schedule, height + 1, m_config.registration_cutoff_blocks,
        m_config.future_horizon_epochs)};
    if (!next_schedule) {
        return SetError(error, PQRegistryResult::INVALID_SCHEDULE);
    }
    view.has_next_block_schedule = 1;
    view.next_first_mutable_epoch = next_schedule->first_mutable_epoch;

    std::shared_ptr<const PQRegistrySnapshotView> snapshot;
    {
        LOCK(m_mutex);
        if (!ReconstructPersistentSnapshotView(block_hash, height, snapshot,
                                               error)) {
            return false;
        }
    }
    if (!snapshot || !snapshot->state || snapshot->height != height ||
        snapshot->block_hash != block_hash) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    const PQRegistryReadView read_view{snapshot};
    view.operator_state_count = read_view.OperatorCount();
    view.used_tree_id_count = read_view.UsedTreeIdCount();
    for (const auto& pro_tx_hash : requested_operators) {
        PQRegistryMempoolOperatorState state;
        state.pro_tx_hash = pro_tx_hash;
        if (const auto* current{read_view.FindOperator(pro_tx_hash)}) {
            state.state_exists = 1;
            state.has_global_key = current->has_global_key;
            if (current->has_global_key != 0) {
                state.current_commitment =
                    current->global_key.child_key_commitment;
            }
        }
        view.operators.push_back(std::move(state));
    }
    return true;
}

bool PQRegistryManager::UndoBlock(
    const uint256& block_hash,
    int32_t height,
    PQRegistrySnapshot& parent_snapshot,
    PQRegistryError& error) const
{
    error.Clear();
    if (!IsEnabled() || height < m_config.preparation_height ||
        block_hash.IsNull()) {
        return SetError(error, PQRegistryResult::UNDO_MISMATCH);
    }
    LOCK(m_mutex);
    PQRegistrySnapshot current;
    if (!ReconstructPersistentSnapshot(block_hash, height, current, error)) {
        return false;
    }
    if (height == m_config.preparation_height) {
        return MakePrePreparationSnapshot(
            m_genesis_hash, current.previous_block_hash, uint256{}, height - 1,
            parent_snapshot, error);
    }
    return ReconstructPersistentSnapshot(current.previous_block_hash,
                                         height - 1, parent_snapshot, error);
}

bool PQRegistryManager::Flush(bool fSync)
{
    LOCK(m_mutex);
    return m_snapshot_db->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync);
}

bool PQRegistryManager::PruneSnapshot(const uint256& block_hash, bool fSync)
{
    if (block_hash.IsNull()) return false;
    LOCK(m_mutex);
    const auto cached{m_snapshot_cache_index.find(block_hash)};
    if (cached != m_snapshot_cache_index.end()) {
        m_snapshot_cache.erase(cached->second);
        m_snapshot_cache_index.erase(cached);
    }
    // Individual records are journal links. Pruning one without its complete
    // checkpoint segment would make surviving descendants unreconstructible.
    return !fSync || m_snapshot_db->FlushCacheToDisk(
                         /*CHUNK_ITEMS=*/256, /*fSync=*/true);
}

} // namespace llmq::pq
