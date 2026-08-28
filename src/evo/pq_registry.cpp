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
#include <unordered_set>
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
    uint64_t gc_floor_revision{0};
    std::shared_ptr<const PQRegistryStateData> state;
    std::shared_ptr<const std::vector<uint256>> block_tree_ids;
};

namespace {

inline constexpr std::string_view PQ_GC_LEGACY_ISLAND_DOMAIN{
    "SYS_PQ_GC_LEGACY_ISLAND_V1"};
inline constexpr std::string_view PQ_GC_LINEAGE_BASE_DOMAIN{
    "SYS_PQ_GC_LINEAGE_BASE_V1"};
inline constexpr std::string_view PQ_GC_ROOTED_SEGMENT_DOMAIN{
    "SYS_PQ_GC_ROOTED_SEGMENT_V1"};

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

bool ApplySparseOperatorDelta(
    std::vector<OperatorKeyState>& current,
    std::span<const uint256> removed,
    std::span<const OperatorKeyState> changed)
{
    if (removed.empty() && changed.empty()) return true;

    std::vector<OperatorKeyState> merged;
    merged.reserve(std::min(
        MAX_PQ_OPERATOR_STATES, current.size() + changed.size()));

    const auto append = [&](OperatorKeyState state) {
        if (merged.size() >= MAX_PQ_OPERATOR_STATES ||
            (!merged.empty() &&
             !(merged.back().pro_tx_hash < state.pro_tx_hash))) {
            return false;
        }
        merged.push_back(std::move(state));
        return true;
    };

    auto current_it{current.begin()};
    auto removed_it{removed.begin()};
    auto changed_it{changed.begin()};
    while (current_it != current.end() || changed_it != changed.end()) {
        if (removed_it != removed.end() &&
            (current_it == current.end() ||
             *removed_it < current_it->pro_tx_hash)) {
            return false;
        }

        if (changed_it != changed.end() &&
            (current_it == current.end() ||
             changed_it->pro_tx_hash < current_it->pro_tx_hash)) {
            if (removed_it != removed.end() &&
                *removed_it == changed_it->pro_tx_hash) {
                return false;
            }
            if (!append(*changed_it++)) return false;
            continue;
        }

        if (removed_it != removed.end() &&
            *removed_it == current_it->pro_tx_hash) {
            if (changed_it != changed.end() &&
                changed_it->pro_tx_hash == current_it->pro_tx_hash) {
                return false;
            }
            ++current_it;
            ++removed_it;
            continue;
        }

        if (changed_it != changed.end() &&
            changed_it->pro_tx_hash == current_it->pro_tx_hash) {
            if (*changed_it == *current_it || !append(*changed_it)) {
                return false;
            }
            ++current_it;
            ++changed_it;
            continue;
        }

        if (!append(std::move(*current_it++))) return false;
    }
    if (removed_it != removed.end()) return false;
    current = std::move(merged);
    return true;
}

bool IsRegistryCheckpoint(const PQRegistryConfig& config,
                          int32_t height) noexcept
{
    return height >= config.preparation_height &&
           (height - config.preparation_height) %
                   PQ_REGISTRY_CHECKPOINT_INTERVAL ==
               0;
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

bool BuildPreparedDiskSnapshot(
    const PQRegistryConfig& config,
    const std::shared_ptr<const PQRegistrySnapshotView>& parent,
    const std::shared_ptr<const PQRegistrySnapshotView>& result,
    PQRegistryDiskSnapshot& disk,
    PQRegistryError& error)
{
    disk = {};
    if (!parent || !parent->state || !parent->state->operator_states ||
        !parent->state->used_tree_ids || !parent->state->indexes ||
        !result || !result->state || !result->state->operator_states ||
        !result->state->used_tree_ids || !result->state->indexes ||
        !result->block_tree_ids || result->height != parent->height + 1 ||
        result->previous_block_hash != parent->block_hash ||
        result->block_hash.IsNull() ||
        result->block_hash == parent->block_hash ||
        parent->state->consensus_state_root.IsNull() ||
        result->state->consensus_state_root.IsNull() ||
        (parent->state == result->state &&
         !result->block_tree_ids->empty())) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }

    disk.is_checkpoint =
        static_cast<uint8_t>(IsRegistryCheckpoint(config, result->height));
    disk.height = result->height;
    disk.block_hash = result->block_hash;
    disk.previous_block_hash = parent->block_hash;
    disk.previous_consensus_state_root =
        parent->state->consensus_state_root;
    disk.block_tree_ids = *result->block_tree_ids;
    if (disk.is_checkpoint != 0) {
        disk.checkpoint_operator_states =
            *result->state->operator_states;
        disk.tree_ids = *result->state->used_tree_ids;
    }
    if (parent->state != result->state) {
        const auto& previous_states{*parent->state->operator_states};
        const auto& current_states{*result->state->operator_states};
        auto previous{previous_states.begin()};
        auto current{current_states.begin()};
        while (previous != previous_states.end() ||
               current != current_states.end()) {
            if (current == current_states.end() ||
                (previous != previous_states.end() &&
                 previous->pro_tx_hash < current->pro_tx_hash)) {
                disk.removed_operators.push_back(previous++->pro_tx_hash);
            } else if (previous == previous_states.end() ||
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
    disk.consensus_state_root = result->state->consensus_state_root;
    return disk.IsStructurallyValid()
        ? true
        : SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
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

std::shared_ptr<const PQRegistryStateData> MakeRegistryStateData(
    std::shared_ptr<const std::vector<OperatorKeyState>> operator_states,
    std::shared_ptr<const std::vector<uint256>> used_tree_ids,
    std::shared_ptr<const PQRegistryIndexes> indexes,
    std::optional<OperatorKeyScheduleState> schedule,
    const uint256& used_tree_ids_hash,
    const uint256& consensus_state_root)
{
    if (!operator_states || !used_tree_ids || !indexes ||
        used_tree_ids_hash.IsNull() || consensus_state_root.IsNull()) {
        return nullptr;
    }
    auto state{std::make_shared<PQRegistryStateData>()};
    state->operator_states = std::move(operator_states);
    state->used_tree_ids = std::move(used_tree_ids);
    state->indexes = std::move(indexes);
    state->schedule = std::move(schedule);
    state->used_tree_ids_hash = used_tree_ids_hash;
    state->consensus_state_root = consensus_state_root;
    state->owned_dynamic_memory_usage =
        RegistryStateOwnedDynamicMemoryUsage(*state);
    state->used_tree_ids_dynamic_memory_usage =
        sizeof(std::vector<uint256>) +
        memusage::DynamicUsage(*state->used_tree_ids);
    return state;
}

std::optional<uint256> EmptyRegistryConsensusStateRoot(
    const uint256& genesis_hash)
{
    const auto tree_hash{GetUsedTreeIdSetHash(
        genesis_hash, std::span<const uint256>{})};
    return tree_hash
        ? GetCanonicalPQKeyConsensusStateHash(
              genesis_hash, std::span<const OperatorKeyState>{}, *tree_hash)
        : std::nullopt;
}

using SnapshotViewCache = std::list<std::pair<
    uint256, std::shared_ptr<const PQRegistrySnapshotView>>>;

struct ReusableSnapshotBacking {
    std::shared_ptr<const PQRegistryStateData> state;
    std::shared_ptr<const std::vector<uint256>> tree_ids;
};

void FindReusableSnapshotBacking(
    const SnapshotViewCache& cache,
    const std::optional<OperatorKeyScheduleState>& schedule,
    const uint256& used_tree_ids_hash,
    std::size_t used_tree_id_count,
    const uint256& consensus_state_root,
    ReusableSnapshotBacking& reusable)
{
    if (reusable.state) return;
    for (auto entry{cache.rbegin()}; entry != cache.rend(); ++entry) {
        const auto& candidate{entry->second};
        if (!candidate || !candidate->state) continue;
        const auto& candidate_state{candidate->state};
        const bool same_tree_history{
            candidate_state->used_tree_ids_hash == used_tree_ids_hash &&
            candidate_state->used_tree_ids &&
            candidate_state->used_tree_ids->size() == used_tree_id_count};
        if (candidate_state->consensus_state_root == consensus_state_root &&
            candidate_state->schedule == schedule && same_tree_history) {
            reusable.state = candidate_state;
            reusable.tree_ids = candidate_state->used_tree_ids;
            return;
        }
        if (!reusable.tree_ids && same_tree_history) {
            reusable.tree_ids = candidate_state->used_tree_ids;
        }
    }
}

std::shared_ptr<const PQRegistrySnapshotView> MakeSnapshotView(
    int32_t height,
    const uint256& block_hash,
    const uint256& previous_block_hash,
    std::shared_ptr<const PQRegistryStateData> state,
    std::vector<uint256> block_tree_ids,
    uint64_t gc_floor_revision = 0)
{
    if (!state) return nullptr;
    auto snapshot{std::make_shared<PQRegistrySnapshotView>()};
    snapshot->height = height;
    snapshot->block_hash = block_hash;
    snapshot->previous_block_hash = previous_block_hash;
    snapshot->gc_floor_revision = gc_floor_revision;
    snapshot->state = std::move(state);
    snapshot->block_tree_ids =
        std::make_shared<const std::vector<uint256>>(
            std::move(block_tree_ids));
    return snapshot;
}

std::shared_ptr<const PQRegistrySnapshotView>
MakeAuthenticatedSnapshotView(
    const SnapshotViewCache& cache,
    int32_t height,
    const uint256& block_hash,
    const uint256& previous_block_hash,
    std::vector<OperatorKeyState> operator_states,
    std::vector<uint256> used_tree_ids,
    std::vector<uint256> block_tree_ids,
    std::optional<OperatorKeyScheduleState> schedule,
    const uint256& used_tree_ids_hash,
    const uint256& consensus_state_root,
    uint64_t gc_floor_revision = 0)
{
    ReusableSnapshotBacking reusable;
    FindReusableSnapshotBacking(
        cache, schedule, used_tree_ids_hash, used_tree_ids.size(),
        consensus_state_root, reusable);
    if (!reusable.state) {
        auto indexes{BuildRegistryIndexes(operator_states)};
        if (!indexes) return nullptr;
        if (!reusable.tree_ids) {
            reusable.tree_ids =
                std::make_shared<const std::vector<uint256>>(
                    std::move(used_tree_ids));
        }
        reusable.state = MakeRegistryStateData(
            std::make_shared<const std::vector<OperatorKeyState>>(
                std::move(operator_states)),
            std::move(reusable.tree_ids), std::move(indexes),
            std::move(schedule), used_tree_ids_hash, consensus_state_root);
        if (!reusable.state) return nullptr;
    }
    return MakeSnapshotView(
        height, block_hash, previous_block_hash,
        std::move(reusable.state), std::move(block_tree_ids),
        gc_floor_revision);
}

std::shared_ptr<const PQRegistrySnapshotView>
MakeAuthenticatedReplaySnapshotView(
    const SnapshotViewCache& staged,
    const SnapshotViewCache& cache,
    const PQRegistryDiskSnapshot& disk,
    const std::vector<OperatorKeyState>& operator_states,
    const std::shared_ptr<const std::vector<uint256>>& used_tree_ids,
    const OperatorKeyScheduleState& schedule,
    const uint256& used_tree_ids_hash,
    uint64_t gc_floor_revision = 0)
{
    if (!used_tree_ids) return nullptr;
    ReusableSnapshotBacking reusable;
    FindReusableSnapshotBacking(
        staged, schedule, used_tree_ids_hash, used_tree_ids->size(),
        disk.consensus_state_root, reusable);
    FindReusableSnapshotBacking(
        cache, schedule, used_tree_ids_hash, used_tree_ids->size(),
        disk.consensus_state_root, reusable);
    if (!reusable.state) {
        auto indexes{BuildRegistryIndexes(operator_states)};
        if (!indexes) return nullptr;
        if (!reusable.tree_ids) {
            reusable.tree_ids = used_tree_ids;
        }
        reusable.state = MakeRegistryStateData(
            std::make_shared<const std::vector<OperatorKeyState>>(
                operator_states),
            std::move(reusable.tree_ids), std::move(indexes), schedule,
            used_tree_ids_hash, disk.consensus_state_root);
        if (!reusable.state) return nullptr;
    }
    return MakeSnapshotView(
        disk.height, disk.block_hash, disk.previous_block_hash,
        std::move(reusable.state), disk.block_tree_ids,
        gc_floor_revision);
}

std::shared_ptr<const PQRegistrySnapshotView>
MakePrePreparationSnapshotView(
    const SnapshotViewCache& cache,
    const uint256& genesis_hash,
    const PQRegistryConfig& config,
    const uint256& block_hash,
    const uint256& previous_block_hash,
    int32_t height,
    PQRegistryError& error)
{
    const auto tree_hash{GetUsedTreeIdSetHash(
        genesis_hash, std::span<const uint256>{})};
    const auto root{tree_hash
        ? GetCanonicalPQKeyConsensusStateHash(
              genesis_hash, std::span<const OperatorKeyState>{}, *tree_hash)
        : std::nullopt};
    const auto schedule{height > 0
        ? ScheduleStateAtHeight(config, height)
        : std::optional<OperatorKeyScheduleState>{}};
    if (height < 0 || block_hash.IsNull() || !tree_hash || !root ||
        (height > 0 && !schedule)) {
        SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
        return nullptr;
    }
    auto snapshot{MakeAuthenticatedSnapshotView(
        cache, height, block_hash, previous_block_hash, {}, {}, {}, schedule,
        *tree_hash, *root)};
    if (!snapshot) {
        SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    return snapshot;
}

std::size_t SnapshotCacheDynamicMemoryUsage(
    const SnapshotViewCache& cache,
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

} // namespace

PQRegistryPreparedBlock::PQRegistryPreparedBlock(
    PQRegistryPreparedBlock&& other) noexcept
{
    *this = std::move(other);
}

PQRegistryPreparedBlock& PQRegistryPreparedBlock::operator=(
    PQRegistryPreparedBlock&& other) noexcept
{
    if (this == &other) return *this;
    m_incarnation = std::move(other.m_incarnation);
    m_kind = std::exchange(other.m_kind, Kind::INVALID);
    m_block_hash = std::move(other.m_block_hash);
    m_consensus_state_root = std::move(other.m_consensus_state_root);
    m_height = std::exchange(other.m_height, -1);
    m_gc_floor_revision =
        std::exchange(other.m_gc_floor_revision, 0);
    m_parent = std::move(other.m_parent);
    m_result = std::move(other.m_result);
    m_disk = std::move(other.m_disk);
    other.m_incarnation.reset();
    other.m_block_hash.SetNull();
    other.m_consensus_state_root.SetNull();
    other.m_parent.reset();
    other.m_result.reset();
    other.m_disk.reset();
    return *this;
}

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

bool PQRegistryGCRootConfig::IsValid(
    const PQRegistryConfig& registry) const noexcept
{
    if (!registry.IsValid() || configuration_id.IsNull() ||
        !legacy_anchor.IsValid() || legacy_anchor_state_root.IsNull() ||
        legacy_anchor.height < registry.preparation_height) {
        return false;
    }
    const int64_t anchor_delta{
        static_cast<int64_t>(legacy_anchor.height) -
        registry.preparation_height};
    const int64_t base_height{
        static_cast<int64_t>(registry.preparation_height) +
        anchor_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL *
            PQ_REGISTRY_CHECKPOINT_INTERVAL};
    return base_height <= std::numeric_limits<int32_t>::max() -
                              PQ_REGISTRY_CHECKPOINT_INTERVAL;
}

bool PQRegistryGCAuthenticationContext::IsStructurallyValid() const noexcept
{
    const auto valid_path = [](const auto& path) {
        if (path.empty() || path.size() > MAX_PATH_RECORDS) return false;
        for (std::size_t i{0}; i < path.size(); ++i) {
            if (!path[i].IsValid() ||
                (i != 0 &&
                 (path[i].height != path[i - 1].height + 1 ||
                  path[i].block_hash == path[i - 1].block_hash))) {
                return false;
            }
        }
        return true;
    };
    return valid_path(legacy_island) && valid_path(rooted_segment);
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
    return GetCanonicalPQKeyConsensusStateHash(
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
        checkpoint_operator_states.size() > MAX_PQ_OPERATOR_STATES ||
        tree_ids.size() > MAX_PQ_USED_TREE_IDS ||
        block_tree_ids.size() > MAX_PQ_TREE_IDS_PER_BLOCK ||
        !IsStrictlySortedOperators(operator_states) ||
        !IsStrictlySortedOperators(checkpoint_operator_states) ||
        (!removed_operators.empty() &&
         !IsStrictlySortedUnique(removed_operators)) ||
        (!tree_ids.empty() && !IsStrictlySortedUnique(tree_ids)) ||
        (!block_tree_ids.empty() &&
         !IsStrictlySortedUnique(block_tree_ids)) ||
        (is_checkpoint == 0 &&
         (!checkpoint_operator_states.empty() || !tree_ids.empty())) ||
        (is_checkpoint != 0 &&
         (!IsSubset(block_tree_ids, tree_ids) ||
          !StateTreeIdsAreRecorded(checkpoint_operator_states,
                                   tree_ids)))) {
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
    for (const auto& state : checkpoint_operator_states) {
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
    if (is_checkpoint != 0) {
        for (const auto& state : operator_states) {
            const auto position{FindOperatorPosition(
                checkpoint_operator_states, state.pro_tx_hash)};
            if (position == checkpoint_operator_states.end() ||
                *position != state) {
                return false;
            }
        }
        for (const auto& removed : removed_operators) {
            const auto position{FindOperatorPosition(
                checkpoint_operator_states, removed)};
            if (position != checkpoint_operator_states.end() &&
                position->pro_tx_hash == removed) {
                return false;
            }
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
    case PQRegistryResult::HISTORY_PRUNED: return "history-pruned";
    case PQRegistryResult::FLOOR_CONFLICT: return "floor-conflict";
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
                                     const PQRegistryConfig& config,
                                     std::optional<PQRegistryGCRootConfig>
                                         gc_root_config)
    : m_genesis_hash(genesis_hash),
      m_config(config),
      m_gc_root_config(std::move(gc_root_config)),
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

bool PQRegistryManager::CheckGCFloorAccess(
    const uint256& block_hash,
    int32_t height,
    PQRegistryError& error) const
{
    if (!m_gc_floor) return true;
    if (height < m_gc_floor->checkpoint.height) {
        return SetError(error, PQRegistryResult::HISTORY_PRUNED);
    }
    if (height == m_gc_floor->checkpoint.height &&
        block_hash != m_gc_floor->checkpoint.block_hash) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    return true;
}

bool PQRegistryManager::AuthenticateGCFloorCheckpoint(
    const evo::PQRegistryGCClosure& closure,
    std::shared_ptr<const PQRegistrySnapshotView>* snapshot,
    PQRegistryError& error,
    bool* missing) const
{
    if (missing != nullptr) *missing = false;
    PQRegistryDiskSnapshot disk;
    const auto read_result{m_snapshot_db->ReadExactDiskForGC(
        closure.checkpoint.block_hash, disk)};
    using ExactReadResult =
        typename CEvoDB<uint256, PQRegistryDiskSnapshot,
                        StaticSaltedHasher>::ExactDiskReadResult;
    if (read_result == ExactReadResult::NOT_FOUND) {
        if (missing != nullptr) {
            *missing = true;
            return true;
        }
        return SetError(error, PQRegistryResult::SNAPSHOT_NOT_FOUND);
    }
    if (read_result != ExactReadResult::FOUND ||
        !disk.IsStructurallyValid() ||
        disk.block_hash != closure.checkpoint.block_hash ||
        disk.height != closure.checkpoint.height || disk.is_checkpoint != 1 ||
        disk.consensus_state_root != closure.checkpoint_state_root ||
        ::SerializeHash(disk) != closure.checkpoint_record_hash ||
        disk.height < m_config.preparation_height ||
        !IsRegistryCheckpoint(m_config, disk.height)) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    const auto schedule_view{DeriveOperatorKeyScheduleView(
        m_config.schedule, disk.height,
        m_config.registration_cutoff_blocks,
        m_config.future_horizon_epochs)};
    const auto tree_ids_hash{GetUsedTreeIdSetHash(
        m_genesis_hash, disk.tree_ids)};
    if (!schedule_view || !tree_ids_hash ||
        !StateTreeIdsAreRecorded(disk.checkpoint_operator_states,
                                 disk.tree_ids) ||
        std::any_of(
            disk.checkpoint_operator_states.begin(),
            disk.checkpoint_operator_states.end(),
            [&](const OperatorKeyState& state) {
                return !state.IsAdvancedTo(*schedule_view);
            })) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    const auto state_root{GetCanonicalPQKeyConsensusStateHash(
        m_genesis_hash, disk.checkpoint_operator_states,
        *tree_ids_hash)};
    const auto indexes{
        BuildRegistryIndexes(disk.checkpoint_operator_states)};
    if (!state_root || *state_root != disk.consensus_state_root ||
        !indexes) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    if (snapshot != nullptr) {
        auto authenticated{MakeAuthenticatedSnapshotView(
            m_snapshot_cache, disk.height, disk.block_hash,
            disk.previous_block_hash, disk.checkpoint_operator_states,
            disk.tree_ids, disk.block_tree_ids,
            OperatorKeyScheduleState::FromView(*schedule_view),
            *tree_ids_hash, disk.consensus_state_root,
            m_gc_floor_revision)};
        if (!authenticated) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        *snapshot = std::move(authenticated);
    }
    return true;
}

bool PQRegistryManager::AuthenticateGCContext(
    const PQRegistryGCAuthenticationContext& context,
    const uint256& claimed_lineage_base,
    const evo::PQRegistryGCClosure* previous,
    GCAuthenticationResult& result,
    PQRegistryError& error,
    bool derive_initial_base,
    bool verify_island_only) const
{
    if (m_gc_context_authentications !=
        std::numeric_limits<uint64_t>::max()) {
        ++m_gc_context_authentications;
    }
    result = {};
    if (!m_gc_root_config ||
        !m_gc_root_config->IsValid(m_config) ||
        !context.IsStructurallyValid() ||
        (claimed_lineage_base.IsNull() && !derive_initial_base)) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }

    const auto& root_config{*m_gc_root_config};
    const int64_t anchor_delta{
        static_cast<int64_t>(root_config.legacy_anchor.height) -
        m_config.preparation_height};
    const int32_t island_base_height{static_cast<int32_t>(
        static_cast<int64_t>(m_config.preparation_height) +
        anchor_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL *
            PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    const int32_t initial_checkpoint_height{
        island_base_height + PQ_REGISTRY_CHECKPOINT_INTERVAL};
    const auto& island{context.legacy_island};
    const auto& segment{context.rooted_segment};
    const auto& target_identity{segment.back()};
    const int64_t target_delta{
        static_cast<int64_t>(target_identity.height) -
        initial_checkpoint_height};
    if (island.front().height != island_base_height ||
        island.back() != root_config.legacy_anchor ||
        island.size() != static_cast<std::size_t>(
            root_config.legacy_anchor.height - island_base_height + 1)) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    const bool initial{!verify_island_only &&
        target_identity.height == initial_checkpoint_height};
    if (!verify_island_only &&
        (target_delta < 0 ||
         target_delta % PQ_REGISTRY_CHECKPOINT_INTERVAL != 0 ||
         !IsRegistryCheckpoint(m_config, target_identity.height))) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    if (derive_initial_base && !initial) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    const int32_t expected_segment_base{initial
        ? root_config.legacy_anchor.height
        : target_identity.height - PQ_REGISTRY_CHECKPOINT_INTERVAL};
    if (!verify_island_only &&
        (segment.front().height != expected_segment_base ||
        segment.size() != static_cast<std::size_t>(
            target_identity.height - expected_segment_base + 1) ||
         (initial && segment.front() != root_config.legacy_anchor))) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    struct ExactRecordCommitment {
        evo::AuxiliaryHistoryGCBlockIdentity identity;
        uint256 state_root;
        uint256 record_hash;
    };
    struct ReplayState {
        evo::AuxiliaryHistoryGCBlockIdentity identity;
        std::vector<OperatorKeyState> operators;
        std::vector<uint256> tree_ids;
        OperatorKeyScheduleState schedule;
        uint256 tree_ids_hash;
        uint256 state_root;
        std::vector<ExactRecordCommitment> records;
    };
    using SnapshotDB = CEvoDB<
        uint256, PQRegistryDiskSnapshot, StaticSaltedHasher>;
    const auto read_exact = [&](
        const evo::AuxiliaryHistoryGCBlockIdentity& identity,
        PQRegistryDiskSnapshot& disk) {
        const auto read_result{m_snapshot_db->ReadExactDiskForGC(
            identity.block_hash, disk)};
        if (read_result != SnapshotDB::ExactDiskReadResult::FOUND) {
            return SetError(
                error, read_result ==
                               SnapshotDB::ExactDiskReadResult::NOT_FOUND
                           ? PQRegistryResult::SNAPSHOT_NOT_FOUND
                           : PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        if (!disk.IsStructurallyValid() ||
            disk.height != identity.height ||
            disk.block_hash != identity.block_hash ||
            (disk.is_checkpoint != 0) !=
                IsRegistryCheckpoint(m_config, identity.height)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        return true;
    };
    const auto authenticate_checkpoint = [&]
        (const evo::AuxiliaryHistoryGCBlockIdentity& identity,
         ReplayState& replay) {
        PQRegistryDiskSnapshot disk;
        if (!read_exact(identity, disk)) return false;
        const auto schedule_view{DeriveOperatorKeyScheduleView(
            m_config.schedule, disk.height,
            m_config.registration_cutoff_blocks,
            m_config.future_horizon_epochs)};
        const auto tree_ids_hash{GetUsedTreeIdSetHash(
            m_genesis_hash, disk.tree_ids)};
        const auto indexes{BuildRegistryIndexes(
            disk.checkpoint_operator_states)};
        if (disk.is_checkpoint != 1 || !schedule_view ||
            !tree_ids_hash || !indexes ||
            !StateTreeIdsAreRecorded(
                disk.checkpoint_operator_states, disk.tree_ids) ||
            std::any_of(
                disk.checkpoint_operator_states.begin(),
                disk.checkpoint_operator_states.end(),
                [&](const OperatorKeyState& state) {
                    return !state.IsAdvancedTo(*schedule_view);
                })) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto state_root{GetCanonicalPQKeyConsensusStateHash(
            m_genesis_hash, disk.checkpoint_operator_states,
            *tree_ids_hash)};
        if (!state_root || *state_root != disk.consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        replay.identity = identity;
        replay.operators = disk.checkpoint_operator_states;
        replay.tree_ids = disk.tree_ids;
        replay.schedule =
            OperatorKeyScheduleState::FromView(*schedule_view);
        replay.tree_ids_hash = *tree_ids_hash;
        replay.state_root = disk.consensus_state_root;
        replay.records.push_back(
            {identity, disk.consensus_state_root, ::SerializeHash(disk)});
        return true;
    };
    const auto replay_descendant = [&]
        (const evo::AuxiliaryHistoryGCBlockIdentity& identity,
         ReplayState& replay) {
        PQRegistryDiskSnapshot disk;
        if (!read_exact(identity, disk) ||
            identity.height != replay.identity.height + 1 ||
            disk.previous_block_hash != replay.identity.block_hash ||
            disk.previous_consensus_state_root != replay.state_root ||
            !ApplySparseOperatorDelta(
                replay.operators, disk.removed_operators,
                disk.operator_states)) {
            if (error.result == PQRegistryResult::OK) {
                SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            return false;
        }
        const bool operators_changed{
            !disk.removed_operators.empty() ||
            !disk.operator_states.empty()};
        const bool tree_ids_changed{!disk.block_tree_ids.empty()};
        if (tree_ids_changed) {
            std::vector<uint256> merged;
            if (!MergeNewTreeIds(
                    replay.tree_ids, disk.block_tree_ids, merged)) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            replay.tree_ids = std::move(merged);
        }
        if (disk.is_checkpoint != 0 &&
            (replay.operators != disk.checkpoint_operator_states ||
             replay.tree_ids != disk.tree_ids)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto schedule_view{DeriveOperatorKeyScheduleView(
            m_config.schedule, disk.height,
            m_config.registration_cutoff_blocks,
            m_config.future_horizon_epochs)};
        if (!schedule_view) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto schedule{
            OperatorKeyScheduleState::FromView(*schedule_view)};
        const bool unchanged_sparse_record{
            disk.is_checkpoint == 0 && !operators_changed &&
            !tree_ids_changed && replay.schedule == schedule};
        if (unchanged_sparse_record) {
            if (disk.consensus_state_root != replay.state_root) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            replay.identity = identity;
            replay.records.push_back(
                {identity, disk.consensus_state_root,
                 ::SerializeHash(disk)});
            return true;
        }
        if (disk.is_checkpoint != 0 || tree_ids_changed) {
            const auto tree_ids_hash{GetUsedTreeIdSetHash(
                m_genesis_hash, replay.tree_ids)};
            if (!tree_ids_hash) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            replay.tree_ids_hash = *tree_ids_hash;
        }
        if (replay.tree_ids_hash.IsNull() ||
            !StateTreeIdsAreRecorded(replay.operators, replay.tree_ids) ||
            std::any_of(
                replay.operators.begin(), replay.operators.end(),
                [&](const OperatorKeyState& state) {
                    return !state.IsAdvancedTo(*schedule_view);
                })) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        if (operators_changed && !BuildRegistryIndexes(replay.operators)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto state_root{GetCanonicalPQKeyConsensusStateHash(
            m_genesis_hash, replay.operators, replay.tree_ids_hash)};
        if (!state_root || *state_root != disk.consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        replay.identity = identity;
        replay.schedule = schedule;
        replay.state_root = disk.consensus_state_root;
        replay.records.push_back(
            {identity, disk.consensus_state_root, ::SerializeHash(disk)});
        return true;
    };
    const auto replay_path = [&]
        (std::span<const evo::AuxiliaryHistoryGCBlockIdentity> path,
         ReplayState& replay, bool has_authenticated_base) {
        std::size_t first{0};
        if (has_authenticated_base) {
            if (path.front() != replay.identity) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
            PQRegistryDiskSnapshot disk;
            if (!read_exact(path.front(), disk) ||
                disk.consensus_state_root != replay.state_root) {
                if (error.result == PQRegistryResult::OK) {
                    SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                return false;
            }
            replay.records = {{path.front(), disk.consensus_state_root,
                               ::SerializeHash(disk)}};
            first = 1;
        } else if (!authenticate_checkpoint(path.front(), replay)) {
            return false;
        } else {
            first = 1;
        }
        for (std::size_t i{first}; i < path.size(); ++i) {
            if (!replay_descendant(path[i], replay)) return false;
        }
        return true;
    };

    ReplayState island_replay;
    if (!replay_path(island, island_replay,
                     /*has_authenticated_base=*/false) ||
        island_replay.identity != root_config.legacy_anchor ||
        island_replay.state_root !=
            root_config.legacy_anchor_state_root) {
        if (error.result == PQRegistryResult::OK) {
            SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        return false;
    }

    CHashWriter island_writer{SER_GETHASH, 0};
    island_writer.write(AsBytes(Span{
        PQ_GC_LEGACY_ISLAND_DOMAIN.data(),
        PQ_GC_LEGACY_ISLAND_DOMAIN.size()}));
    island_writer << root_config.configuration_id << m_genesis_hash
                  << evo::PQRegistryGCClosure::FORMAT_GUARD
                  << evo::PQRegistryGCClosure::VERSION
                  << evo::PQRegistryGCClosure::LINEAGE_PROFILE_VERSION
                  << PQ_REGISTRY_DISK_VERSION
                  << static_cast<int32_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL)
                  << island.front() << root_config.legacy_anchor
                  << root_config.legacy_anchor_state_root
                  << static_cast<uint32_t>(island_replay.records.size());
    for (const auto& record : island_replay.records) {
        island_writer << record.identity << record.state_root
                      << record.record_hash;
    }
    result.legacy_island_commitment = island_writer.GetHash();
    if (result.legacy_island_commitment.IsNull()) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    if (previous != nullptr &&
        previous->legacy_island_commitment !=
            result.legacy_island_commitment) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    if (verify_island_only) {
        result.checkpoint = root_config.legacy_anchor;
        result.checkpoint_state_root = island_replay.state_root;
        result.checkpoint_record_hash =
            island_replay.records.back().record_hash;
        result.protected_records.assign(island.begin(), island.end());
        return true;
    }

    ReplayState segment_replay;
    if (initial) {
        segment_replay = island_replay;
        if (!replay_path(segment, segment_replay,
                         /*has_authenticated_base=*/true)) {
            return false;
        }
        CHashWriter base_writer{SER_GETHASH, 0};
        base_writer.write(AsBytes(Span{
            PQ_GC_LINEAGE_BASE_DOMAIN.data(),
            PQ_GC_LINEAGE_BASE_DOMAIN.size()}));
        base_writer << root_config.configuration_id << m_genesis_hash
                    << evo::PQRegistryGCClosure::FORMAT_GUARD
                    << evo::PQRegistryGCClosure::VERSION
                    << evo::PQRegistryGCClosure::LINEAGE_PROFILE_VERSION
                    << PQ_REGISTRY_DISK_VERSION
                    << static_cast<int32_t>(
                           PQ_REGISTRY_CHECKPOINT_INTERVAL)
                    << root_config.legacy_anchor
                    << root_config.legacy_anchor_state_root
                    << result.legacy_island_commitment;
        result.lineage_base_commitment = base_writer.GetHash();
    } else {
        if (!replay_path(segment, segment_replay,
                         /*has_authenticated_base=*/false)) {
            return false;
        }
        result.lineage_base_commitment = claimed_lineage_base;
        if (previous != nullptr) {
            const bool same_checkpoint{
                previous->checkpoint == target_identity};
            if ((same_checkpoint &&
                 previous->lineage_base_commitment !=
                     claimed_lineage_base) ||
                (!same_checkpoint &&
                 (previous->checkpoint != segment.front() ||
                  previous->checkpoint_state_root !=
                      segment_replay.records.front().state_root ||
                  previous->checkpoint_record_hash !=
                      segment_replay.records.front().record_hash ||
                  previous->rooted_lineage_commitment !=
                      claimed_lineage_base))) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        }
    }
    if (initial && !derive_initial_base &&
        claimed_lineage_base != result.lineage_base_commitment) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    CHashWriter rooted_writer{SER_GETHASH, 0};
    rooted_writer.write(AsBytes(Span{
        PQ_GC_ROOTED_SEGMENT_DOMAIN.data(),
        PQ_GC_ROOTED_SEGMENT_DOMAIN.size()}));
    rooted_writer << root_config.configuration_id << m_genesis_hash
                  << evo::PQRegistryGCClosure::FORMAT_GUARD
                  << evo::PQRegistryGCClosure::VERSION
                  << evo::PQRegistryGCClosure::LINEAGE_PROFILE_VERSION
                  << PQ_REGISTRY_DISK_VERSION
                  << static_cast<int32_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL)
                  << result.lineage_base_commitment
                  << static_cast<uint32_t>(segment_replay.records.size());
    for (const auto& record : segment_replay.records) {
        rooted_writer << record.identity << record.state_root
                      << record.record_hash;
    }
    result.rooted_lineage_commitment = rooted_writer.GetHash();
    if (result.rooted_lineage_commitment.IsNull()) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    if (previous != nullptr &&
        previous->checkpoint == target_identity &&
        (previous->legacy_island_commitment !=
             result.legacy_island_commitment ||
         previous->lineage_base_commitment !=
             result.lineage_base_commitment ||
         previous->rooted_lineage_commitment !=
             result.rooted_lineage_commitment)) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    result.checkpoint = segment_replay.identity;
    result.checkpoint_state_root = segment_replay.state_root;
    result.checkpoint_record_hash =
        segment_replay.records.back().record_hash;
    result.protected_records.reserve(
        island.size() + segment.size());
    std::unordered_map<uint256, int32_t, StaticSaltedHasher>
        protected_index;
    protected_index.reserve(island.size() + segment.size());
    const auto append_protected = [&](const auto& identities) {
        for (const auto& identity : identities) {
            const auto [position, inserted]{protected_index.emplace(
                identity.block_hash, identity.height)};
            if (!inserted && position->second != identity.height) {
                return false;
            }
            if (inserted) result.protected_records.push_back(identity);
        }
        return true;
    };
    if (!append_protected(island) || !append_protected(segment)) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    return true;
}

bool PQRegistryManager::VerifyGCLegacyIsland(
    std::span<const evo::AuxiliaryHistoryGCBlockIdentity> island,
    PQRegistryError& error) const
{
    error.Clear();
    if (island.empty()) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    PQRegistryGCAuthenticationContext context;
    context.legacy_island.assign(island.begin(), island.end());
    context.rooted_segment.push_back(island.back());
    GCAuthenticationResult authenticated;
    LOCK(m_mutex);
    return AuthenticateGCContext(
        context, uint256::ONEV, nullptr, authenticated, error,
        /*derive_initial_base=*/false,
        /*verify_island_only=*/true);
}

bool PQRegistryManager::BuildGCFloorClosure(
    uint64_t generation,
    std::optional<uint256> scan_after_key,
    const PQRegistryGCAuthenticationContext& context,
    const evo::PQRegistryGCClosure* previous,
    evo::PQRegistryGCClosure& closure,
    PQRegistryError& error) const
{
    error.Clear();
    LOCK(m_mutex);
    return BuildGCFloorClosureLocked(
        generation, std::move(scan_after_key), context, previous,
        closure, error);
}

bool PQRegistryManager::BuildGCFloorClosureLocked(
    uint64_t generation,
    std::optional<uint256> scan_after_key,
    const PQRegistryGCAuthenticationContext& context,
    const evo::PQRegistryGCClosure* previous,
    evo::PQRegistryGCClosure& closure,
    PQRegistryError& error) const
{
    closure = {};
    if (!m_gc_root_config ||
        !m_gc_root_config->IsValid(m_config) ||
        !context.IsStructurallyValid() || generation == 0 ||
        (scan_after_key && scan_after_key->IsNull())) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    if (previous == nullptr) {
        if (generation != 1) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
    } else {
        if (!previous->IsValid() ||
            previous->generation == std::numeric_limits<uint64_t>::max() ||
            generation != previous->generation + 1) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        const bool same_checkpoint{
            previous->checkpoint == context.rooted_segment.back()};
        if (same_checkpoint) {
            const bool cursor_advances{
                previous->scan_complete ==
                    evo::PQRegistryGCClosure::SCANNING &&
                ((!scan_after_key) ||
                 (previous->scan_after_key &&
                  *previous->scan_after_key < *scan_after_key))};
            if (!cursor_advances) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        } else {
            const int64_t height_delta{
                static_cast<int64_t>(
                    context.rooted_segment.back().height) -
                previous->checkpoint.height};
            if (previous->scan_complete !=
                    evo::PQRegistryGCClosure::COMPLETE ||
                height_delta != PQ_REGISTRY_CHECKPOINT_INTERVAL) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        }
    }

    uint256 claimed_base;
    bool derive_initial_base{false};
    if (previous != nullptr) {
        claimed_base = previous->checkpoint == context.rooted_segment.back()
            ? previous->lineage_base_commitment
            : previous->rooted_lineage_commitment;
    } else {
        derive_initial_base = true;
    }
    GCAuthenticationResult authenticated;
    if (!AuthenticateGCContext(
            context, claimed_base, previous, authenticated, error,
            derive_initial_base)) {
        return false;
    }
    return BuildGCFloorClosureFromAuthenticatedLocked(
        generation, std::move(scan_after_key), authenticated, closure,
        error);
}

bool PQRegistryManager::BuildGCFloorClosureFromAuthenticatedLocked(
    uint64_t generation,
    std::optional<uint256> scan_after_key,
    const GCAuthenticationResult& authenticated,
    evo::PQRegistryGCClosure& closure,
    PQRegistryError& error) const
{
    closure = {};
    if (!m_gc_root_config ||
        !m_gc_root_config->IsValid(m_config) || generation == 0 ||
        (scan_after_key && scan_after_key->IsNull())) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    const int64_t initial_height{
        static_cast<int64_t>(m_config.preparation_height) +
        (static_cast<int64_t>(
             m_gc_root_config->legacy_anchor.height) -
         m_config.preparation_height) /
            PQ_REGISTRY_CHECKPOINT_INTERVAL *
            PQ_REGISTRY_CHECKPOINT_INTERVAL +
        PQ_REGISTRY_CHECKPOINT_INTERVAL};
    const uint64_t minimum_generation{static_cast<uint64_t>(
        1 + (authenticated.checkpoint.height - initial_height) /
                PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    if (generation < minimum_generation) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    closure.generation = generation;
    closure.checkpoint = authenticated.checkpoint;
    closure.checkpoint_state_root = authenticated.checkpoint_state_root;
    closure.checkpoint_record_hash = authenticated.checkpoint_record_hash;
    closure.lineage_base_commitment =
        authenticated.lineage_base_commitment;
    closure.rooted_lineage_commitment =
        authenticated.rooted_lineage_commitment;
    closure.legacy_island_commitment =
        authenticated.legacy_island_commitment;
    closure.scan_complete = scan_after_key
        ? evo::PQRegistryGCClosure::SCANNING
        : evo::PQRegistryGCClosure::COMPLETE;
    closure.scan_after_key = std::move(scan_after_key);
    return closure.IsValid()
        ? true
        : SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
}

bool PQRegistryManager::BuildGCEraseBatch(
    const PQRegistryGCAuthenticationContext& context,
    const std::optional<evo::AuxiliaryHistoryGCComponent>& previous,
    std::size_t max_scanned_records,
    std::size_t max_scanned_value_bytes,
    std::size_t max_candidates,
    evo::AuxiliaryHistoryGCComponent& target,
    evo::PQRegistryGCEraseManifest& manifest,
    PQRegistryError& error) const
{
    error.Clear();
    target = {};
    manifest = {};
    if (max_scanned_records == 0 || max_scanned_value_bytes == 0 ||
        max_candidates == 0 ||
        max_scanned_records >
            evo::PQRegistryGCEraseManifest::MAX_CANDIDATES ||
        max_candidates >
            evo::PQRegistryGCEraseManifest::MAX_CANDIDATES ||
        !context.IsStructurallyValid() ||
        (previous && !previous->IsValid())) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }

    std::optional<evo::PQRegistryGCClosure> previous_closure;
    uint64_t generation{1};
    if (previous) {
        previous_closure = evo::DecodePQRegistryGCClosure(
            previous->closure);
        if (!previous_closure ||
            previous->version != evo::PQRegistryGCClosure::VERSION ||
            previous->monotonic_position !=
                previous_closure->generation ||
            previous_closure->generation ==
                std::numeric_limits<uint64_t>::max()) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        generation = previous_closure->generation + 1;
    }

    try {
        LOCK(m_mutex);
        LOCK(m_snapshot_db->cs);
        if (!m_gc_root_config ||
            !m_gc_root_config->IsValid(m_config)) {
            return SetError(
                error, PQRegistryResult::INVALID_CONFIGURATION);
        }
        if (m_snapshot_db->GetReadWriteCacheSize() != 0 ||
            m_snapshot_db->GetEraseCacheSize() != 0) {
            return SetError(
                error, PQRegistryResult::PERSISTENCE_FAILED);
        }

        uint256 claimed_base;
        bool derive_initial_base{false};
        if (previous_closure) {
            claimed_base = previous_closure->checkpoint ==
                    context.rooted_segment.back()
                ? previous_closure->lineage_base_commitment
                : previous_closure->rooted_lineage_commitment;
        } else {
            derive_initial_base = true;
        }
        GCAuthenticationResult authenticated;
        if (!AuthenticateGCContext(
                context, claimed_base,
                previous_closure ? &*previous_closure : nullptr,
                authenticated, error, derive_initial_base)) {
            return false;
        }
        if (previous_closure &&
            previous_closure->checkpoint != authenticated.checkpoint) {
            const int64_t height_delta{
                static_cast<int64_t>(authenticated.checkpoint.height) -
                previous_closure->checkpoint.height};
            if (previous_closure->scan_complete !=
                    evo::PQRegistryGCClosure::COMPLETE ||
                height_delta != PQ_REGISTRY_CHECKPOINT_INTERVAL) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        }
        std::unordered_map<uint256, int32_t, StaticSaltedHasher>
            protected_records;
        protected_records.reserve(authenticated.protected_records.size());
        for (const auto& identity : authenticated.protected_records) {
            const auto [position, inserted]{protected_records.emplace(
                identity.block_hash, identity.height)};
            if (!inserted && position->second != identity.height) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }

        const bool same_checkpoint{previous_closure &&
            previous_closure->checkpoint == authenticated.checkpoint};
        const std::optional<uint256> from_cursor{same_checkpoint
            ? previous_closure->scan_after_key
            : std::nullopt};
        if (same_checkpoint &&
            (previous_closure->scan_complete !=
                 evo::PQRegistryGCClosure::SCANNING ||
             !from_cursor)) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }

        std::vector<evo::PQRegistryGCEraseCandidate> candidates;
        candidates.reserve(std::min(
            max_scanned_records, max_candidates));
        std::optional<uint256> last_key;
        bool reached_eof{false};
        {
            std::unique_ptr<CDBIterator> cursor{
                m_snapshot_db->NewIterator()};
            if (!cursor) {
                return SetError(
                    error, PQRegistryResult::PERSISTENCE_FAILED);
            }
            if (from_cursor) {
                cursor->Seek(*from_cursor);
                if (cursor->Valid()) {
                    uint256 found_key;
                    if (!cursor->GetKeyExact(found_key)) {
                        return SetError(
                            error, PQRegistryResult::SNAPSHOT_CORRUPT);
                    }
                    if (found_key == *from_cursor) cursor->Next();
                }
            } else {
                cursor->SeekToFirst();
            }

            std::size_t scanned{0};
            std::size_t scanned_value_bytes{0};
            while (cursor->Valid() && scanned < max_scanned_records &&
                   candidates.size() < max_candidates) {
                const std::size_t value_size{cursor->GetValueSize()};
                if (value_size > PQRegistryDiskSnapshot::MAX_SERIALIZED_SIZE) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                const bool exceeds_soft_budget{
                    scanned_value_bytes >= max_scanned_value_bytes ||
                    value_size >
                        max_scanned_value_bytes - scanned_value_bytes};
                // SYSCOIN: Defer a value that would cross the aggregate
                // budget, but always consume one value so a large valid
                // checkpoint cannot strand this cursor forever.
                if (scanned != 0 && exceeds_soft_budget) break;
                uint256 key;
                PQRegistryDiskSnapshot disk;
                if (!cursor->GetKeyExact(key) ||
                    !cursor->GetValueExact(disk) ||
                    !disk.IsStructurallyValid() ||
                    disk.block_hash != key ||
                    disk.height < m_config.preparation_height ||
                    (disk.is_checkpoint != 0) !=
                        IsRegistryCheckpoint(m_config, disk.height)) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                const auto protected_position{
                    protected_records.find(key)};
                const bool protected_record{
                    protected_position != protected_records.end() &&
                    protected_position->second == disk.height};
                if (disk.height <= authenticated.checkpoint.height &&
                    !protected_record) {
                    candidates.push_back({
                        key, disk.height, ::SerializeHash(disk)});
                }
                last_key = key;
                scanned_value_bytes += value_size;
                ++scanned;
                cursor->Next();
            }
            cursor->CheckStatus();
            reached_eof = !cursor->Valid();
        }
        if (!reached_eof && !last_key) {
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }

        evo::PQRegistryGCClosure closure;
        if (!BuildGCFloorClosureFromAuthenticatedLocked(
                generation,
                reached_eof ? std::nullopt : last_key,
                authenticated,
                closure, error)) {
            return false;
        }
        const auto encoded_closure{
            evo::EncodePQRegistryGCClosure(closure)};
        if (!encoded_closure) {
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }
        target = {
            evo::PQRegistryGCClosure::VERSION,
            closure.generation,
            *encoded_closure,
        };
        const auto target_hash{
            evo::GetAuxiliaryHistoryGCComponentHash(target)};
        const auto previous_hash{previous
            ? evo::GetAuxiliaryHistoryGCComponentHash(*previous)
            : std::optional<uint256>{}};
        if (!target.IsValid() || !target_hash ||
            (previous && !previous_hash)) {
            target = {};
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }

        manifest.previous_component_hash = previous_hash;
        manifest.target_component_hash = *target_hash;
        manifest.from_cursor = from_cursor;
        manifest.scan_through = last_key;
        manifest.reached_eof = reached_eof ? 1 : 0;
        manifest.candidates = std::move(candidates);
        if (!manifest.IsValid()) {
            target = {};
            manifest = {};
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }
        return true;
    } catch (const std::exception&) {
        target = {};
        manifest = {};
        return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
    }
}

bool PQRegistryManager::FlushForGC(PQRegistryError& error)
{
    error.Clear();
    try {
        LOCK(m_mutex);
        if (!m_snapshot_db->FlushCacheToDisk(
                /*CHUNK_ITEMS=*/256, /*fSync=*/true)) {
            return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
        }
        return true;
    } catch (const std::exception&) {
        return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
    }
}

bool PQRegistryManager::EraseGCManifest(
    const evo::AuxiliaryHistoryGCComponent& target,
    const std::optional<evo::AuxiliaryHistoryGCComponent>& previous,
    const PQRegistryGCAuthenticationContext& context,
    const evo::PQRegistryGCEraseManifest& manifest,
    PQRegistryError& error)
{
    error.Clear();
    if (!target.IsValid() || !manifest.IsValid() ||
        !context.IsStructurallyValid() ||
        (previous && !previous->IsValid())) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    const auto target_closure{
        evo::DecodePQRegistryGCClosure(target.closure)};
    std::optional<evo::PQRegistryGCClosure> previous_closure;
    if (previous) {
        previous_closure = evo::DecodePQRegistryGCClosure(
            previous->closure);
    }
    const auto target_hash{
        evo::GetAuxiliaryHistoryGCComponentHash(target)};
    const auto previous_hash{previous
        ? evo::GetAuxiliaryHistoryGCComponentHash(*previous)
        : std::optional<uint256>{}};
    if (!target_closure || (previous && !previous_closure) ||
        !target_hash || (previous && !previous_hash) ||
        manifest.target_component_hash != *target_hash ||
        manifest.previous_component_hash != previous_hash ||
        target.version != evo::PQRegistryGCClosure::VERSION ||
        target.monotonic_position != target_closure->generation) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    try {
        LOCK(m_mutex);
        if (!m_gc_floor_component ||
            *m_gc_floor_component != target || !m_gc_floor ||
            *m_gc_floor != *target_closure) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        LOCK(m_snapshot_db->cs);
        if (m_snapshot_db->GetReadWriteCacheSize() != 0 ||
            m_snapshot_db->GetEraseCacheSize() != 0) {
            return SetError(
                error, PQRegistryResult::PERSISTENCE_FAILED);
        }

        const bool same_checkpoint{previous_closure &&
            previous_closure->checkpoint == target_closure->checkpoint};
        const std::optional<uint256> expected_from_cursor{same_checkpoint
            ? previous_closure->scan_after_key
            : std::nullopt};
        if (manifest.from_cursor != expected_from_cursor ||
            (target_closure->scan_complete ==
                 evo::PQRegistryGCClosure::SCANNING &&
             (manifest.reached_eof != 0 ||
              manifest.scan_through !=
                  target_closure->scan_after_key)) ||
            (target_closure->scan_complete ==
                 evo::PQRegistryGCClosure::COMPLETE &&
             manifest.reached_eof != 1)) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        if (!previous_closure) {
            if (target_closure->generation != 1) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        } else {
            if (previous_closure->generation ==
                    std::numeric_limits<uint64_t>::max() ||
                target_closure->generation !=
                    previous_closure->generation + 1 ||
                target_closure->legacy_island_commitment !=
                    previous_closure->legacy_island_commitment) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
            if (same_checkpoint) {
                if (previous_closure->scan_complete !=
                        evo::PQRegistryGCClosure::SCANNING ||
                    target_closure->checkpoint_state_root !=
                        previous_closure->checkpoint_state_root ||
                    target_closure->checkpoint_record_hash !=
                        previous_closure->checkpoint_record_hash ||
                    target_closure->lineage_base_commitment !=
                        previous_closure->lineage_base_commitment ||
                    target_closure->rooted_lineage_commitment !=
                        previous_closure->rooted_lineage_commitment) {
                    return SetError(
                        error, PQRegistryResult::FLOOR_CONFLICT);
                }
            } else if (previous_closure->scan_complete !=
                           evo::PQRegistryGCClosure::COMPLETE ||
                       target_closure->checkpoint.height !=
                           previous_closure->checkpoint.height +
                               PQ_REGISTRY_CHECKPOINT_INTERVAL ||
                       target_closure->lineage_base_commitment !=
                           previous_closure->rooted_lineage_commitment) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        }

        GCAuthenticationResult authenticated;
        if (!AuthenticateGCContext(
                context, target_closure->lineage_base_commitment,
                previous_closure ? &*previous_closure : nullptr,
                authenticated, error) ||
            authenticated.checkpoint != target_closure->checkpoint ||
            authenticated.checkpoint_state_root !=
                target_closure->checkpoint_state_root ||
            authenticated.checkpoint_record_hash !=
                target_closure->checkpoint_record_hash ||
            authenticated.lineage_base_commitment !=
                target_closure->lineage_base_commitment ||
            authenticated.rooted_lineage_commitment !=
                target_closure->rooted_lineage_commitment ||
            authenticated.legacy_island_commitment !=
                target_closure->legacy_island_commitment) {
            if (error.result == PQRegistryResult::OK) {
                SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
            return false;
        }

        std::unordered_map<uint256, int32_t, StaticSaltedHasher>
            protected_records;
        protected_records.reserve(authenticated.protected_records.size());
        for (const auto& identity : authenticated.protected_records) {
            const auto [position, inserted]{protected_records.emplace(
                identity.block_hash, identity.height)};
            if (!inserted && position->second != identity.height) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }
        const auto is_protected = [&](const uint256& key, int32_t height) {
            const auto position{protected_records.find(key)};
            return position != protected_records.end() &&
                   position->second == height;
        };
        std::size_t first_present{manifest.candidates.size()};
        {
            for (const auto& candidate : manifest.candidates) {
                if (candidate.height < m_config.preparation_height ||
                    candidate.height > target_closure->checkpoint.height ||
                    is_protected(candidate.key, candidate.height)) {
                    return SetError(
                        error, PQRegistryResult::FLOOR_CONFLICT);
                }
            }

            std::unique_ptr<CDBIterator> cursor{
                m_snapshot_db->NewIterator()};
            if (!cursor) {
                return SetError(
                    error, PQRegistryResult::PERSISTENCE_FAILED);
            }
            if (manifest.from_cursor) {
                cursor->Seek(*manifest.from_cursor);
                if (cursor->Valid()) {
                    uint256 found_key;
                    if (!cursor->GetKeyExact(found_key)) {
                        return SetError(
                            error, PQRegistryResult::SNAPSHOT_CORRUPT);
                    }
                    if (found_key == *manifest.from_cursor) {
                        cursor->Next();
                    }
                }
            } else {
                cursor->SeekToFirst();
            }
            if (!manifest.from_cursor && !manifest.scan_through) {
                cursor->CheckStatus();
                if (cursor->Valid()) {
                    return SetError(
                        error, PQRegistryResult::FLOOR_CONFLICT);
                }
            }
            bool found_present{false};
            std::size_t candidate_index{0};
            while (cursor->Valid()) {
                uint256 key;
                if (!cursor->GetKeyExact(key)) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                if (manifest.scan_through &&
                    *manifest.scan_through < key) {
                    break;
                }
                if (!manifest.scan_through) break;
                PQRegistryDiskSnapshot disk;
                if (!cursor->GetValueExact(disk) ||
                    !disk.IsStructurallyValid() ||
                    disk.block_hash != key ||
                    disk.height < m_config.preparation_height ||
                    (disk.is_checkpoint != 0) !=
                        IsRegistryCheckpoint(m_config, disk.height)) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                while (candidate_index < manifest.candidates.size() &&
                       manifest.candidates[candidate_index].key < key) {
                    if (found_present) {
                        return SetError(
                            error, PQRegistryResult::FLOOR_CONFLICT);
                    }
                    ++candidate_index;
                }
                const bool erasable{
                    disk.height <= target_closure->checkpoint.height &&
                    !is_protected(key, disk.height)};
                if (erasable) {
                    if (candidate_index >= manifest.candidates.size() ||
                        manifest.candidates[candidate_index].key != key) {
                        return SetError(
                            error, PQRegistryResult::FLOOR_CONFLICT);
                    }
                    const auto& candidate{
                        manifest.candidates[candidate_index]};
                    if (candidate.height != disk.height ||
                        candidate.exact_record_hash !=
                            ::SerializeHash(disk)) {
                        return SetError(
                            error, PQRegistryResult::SNAPSHOT_CORRUPT);
                    }
                    if (!found_present) {
                        first_present = candidate_index;
                        found_present = true;
                    }
                    ++candidate_index;
                } else if (candidate_index <
                               manifest.candidates.size() &&
                           manifest.candidates[candidate_index].key == key) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                cursor->Next();
            }
            cursor->CheckStatus();
            if (found_present &&
                candidate_index != manifest.candidates.size()) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }

            static constexpr std::size_t ERASE_CHUNK_ITEMS{256};
            for (std::size_t begin{first_present};
                 begin < manifest.candidates.size();
                 begin += ERASE_CHUNK_ITEMS) {
                const std::size_t end{std::min(
                    manifest.candidates.size(),
                    begin + ERASE_CHUNK_ITEMS)};
                std::vector<uint256> keys;
                keys.reserve(end - begin);
                for (std::size_t i{begin}; i < end; ++i) {
                    keys.push_back(manifest.candidates[i].key);
                }
                if (!m_snapshot_db->EraseExactDiskKeysForGC(
                        keys, /*fSync=*/true)) {
                    return SetError(
                        error, PQRegistryResult::PERSISTENCE_FAILED);
                }
            }
        }
        return true;
    } catch (const std::exception&) {
        return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
    }
}

bool PQRegistryManager::InstallGCFloor(
    const evo::AuxiliaryHistoryGCComponent& component,
    const evo::AuxiliaryHistoryGCAuthorization& authorization,
    PQRegistryError& error,
    const PQRegistryGCAuthenticationContext& context)
{
    error.Clear();
    if (!IsEnabled() ||
        !evo::IsPQRegistryGCComponentBoundedByAuthorization(
            component, authorization)) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    const auto closure{evo::DecodePQRegistryGCClosure(component.closure)};
    if (!closure) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    LOCK(m_mutex);
    GCAuthenticationResult authenticated;
    if (!AuthenticateGCContext(
            context, closure->lineage_base_commitment,
            m_gc_floor ? &*m_gc_floor : nullptr,
            authenticated, error)) {
        return false;
    }
    return InstallGCFloorFromAuthenticatedLocked(
        component, &*closure, authenticated, error);
}

bool PQRegistryManager::InstallGCFloorFromAuthenticatedLocked(
    const evo::AuxiliaryHistoryGCComponent& component,
    const evo::PQRegistryGCClosure* closure,
    const GCAuthenticationResult& authenticated,
    PQRegistryError& error)
{
    if (closure == nullptr) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    const int64_t anchor_delta{
        static_cast<int64_t>(m_gc_root_config->legacy_anchor.height) -
        m_config.preparation_height};
    const int64_t initial_checkpoint_height{
        static_cast<int64_t>(m_config.preparation_height) +
        anchor_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL *
            PQ_REGISTRY_CHECKPOINT_INTERVAL +
        PQ_REGISTRY_CHECKPOINT_INTERVAL};
    const int64_t checkpoint_delta{
        static_cast<int64_t>(closure->checkpoint.height) -
        initial_checkpoint_height};
    const uint64_t minimum_generation{static_cast<uint64_t>(
        1 + checkpoint_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    if (checkpoint_delta < 0 ||
        checkpoint_delta % PQ_REGISTRY_CHECKPOINT_INTERVAL != 0 ||
        closure->generation < minimum_generation ||
        closure->checkpoint != authenticated.checkpoint ||
        closure->checkpoint_state_root !=
            authenticated.checkpoint_state_root ||
        closure->checkpoint_record_hash !=
            authenticated.checkpoint_record_hash ||
        closure->lineage_base_commitment !=
            authenticated.lineage_base_commitment ||
        closure->rooted_lineage_commitment !=
            authenticated.rooted_lineage_commitment ||
        closure->legacy_island_commitment !=
            authenticated.legacy_island_commitment) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    bool idempotent{false};
    if (m_gc_floor_component &&
        component.monotonic_position ==
            m_gc_floor_component->monotonic_position) {
        if (component != *m_gc_floor_component) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        idempotent = true;
    }
    if (!idempotent && m_gc_floor_component &&
        (component.monotonic_position !=
             m_gc_floor_component->monotonic_position + 1 ||
         component.monotonic_position == 0)) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    const bool same_checkpoint{
        m_gc_floor && closure->checkpoint == m_gc_floor->checkpoint};
    if (m_gc_floor && !idempotent) {
        if (closure->legacy_island_commitment !=
            m_gc_floor->legacy_island_commitment) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
        if (same_checkpoint) {
            const bool immutable_closure_matches{
                closure->checkpoint_state_root ==
                    m_gc_floor->checkpoint_state_root &&
                closure->checkpoint_record_hash ==
                    m_gc_floor->checkpoint_record_hash &&
                closure->lineage_base_commitment ==
                    m_gc_floor->lineage_base_commitment &&
                closure->rooted_lineage_commitment ==
                    m_gc_floor->rooted_lineage_commitment};
            const bool cursor_advances{
                m_gc_floor->scan_complete ==
                    evo::PQRegistryGCClosure::SCANNING &&
                ((closure->scan_complete ==
                      evo::PQRegistryGCClosure::SCANNING &&
                  m_gc_floor->scan_after_key &&
                  closure->scan_after_key &&
                  *m_gc_floor->scan_after_key <
                      *closure->scan_after_key) ||
                 closure->scan_complete ==
                     evo::PQRegistryGCClosure::COMPLETE)};
            if (!immutable_closure_matches || !cursor_advances) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        } else {
            const int64_t height_delta{
                static_cast<int64_t>(closure->checkpoint.height) -
                m_gc_floor->checkpoint.height};
            if (m_gc_floor->scan_complete !=
                    evo::PQRegistryGCClosure::COMPLETE ||
                height_delta != PQ_REGISTRY_CHECKPOINT_INTERVAL) {
                return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
        }
    }
    if (!AuthenticateGCFloorCheckpoint(*closure, nullptr, error)) {
        return false;
    }
    if (idempotent) return true;

    // Finish every allocation before mutating the effective floor. A failed
    // component copy must leave both the boundary revision and caches intact.
    std::optional<evo::AuxiliaryHistoryGCComponent> prepared_component{
        component};
    std::optional<evo::PQRegistryGCClosure> prepared_closure{*closure};
    const bool boundary_changed{!same_checkpoint};
    if (boundary_changed) {
        if (m_gc_floor_revision ==
            std::numeric_limits<uint64_t>::max()) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
    }

    m_gc_floor_component.swap(prepared_component);
    m_gc_floor.swap(prepared_closure);
    if (boundary_changed) {
        m_snapshot_cache.clear();
        m_snapshot_cache_index.clear();
        m_payment_eligibility_cache.clear();
        m_payment_eligibility_cache_index.clear();
        ++m_gc_floor_revision;
    }
    return true;
}

bool PQRegistryManager::InstallEffectiveGCFloor(
    const evo::AuxiliaryHistoryGCState& state,
    PQRegistryError& error,
    const PQRegistryGCAuthenticationContext& context)
{
    error.Clear();
    const auto fail_transition = [&] {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    };
    const auto component_dominates = [](
        const std::optional<evo::AuxiliaryHistoryGCComponent>& previous,
        const std::optional<evo::AuxiliaryHistoryGCComponent>& next) {
        if (!previous) return true;
        return next && next->version == previous->version &&
               next->monotonic_position >= previous->monotonic_position &&
               (next->monotonic_position != previous->monotonic_position ||
                *next == *previous);
    };
    const auto component_advances = [](
        const std::optional<evo::AuxiliaryHistoryGCComponent>& previous,
        const std::optional<evo::AuxiliaryHistoryGCComponent>& next) {
        return next &&
               (!previous || next->monotonic_position >
                                previous->monotonic_position);
    };

    const evo::AuxiliaryHistoryGCFrontier* completed_frontier{nullptr};
    const evo::AuxiliaryHistoryGCAuthorization* completed_authorization{
        nullptr};
    if (state.watermark) {
        const auto& watermark{*state.watermark};
        if (watermark.sequence == 0 || watermark.configuration_id.IsNull() ||
            (m_gc_root_config && watermark.configuration_id !=
                 m_gc_root_config->configuration_id) ||
            !watermark.authorization.IsValid() ||
            !watermark.frontier.IsValid() ||
            watermark.completed_intent_id.IsNull() ||
            watermark.watermark_id.IsNull()) {
            return fail_transition();
        }
        completed_frontier = &watermark.frontier;
        completed_authorization = &watermark.authorization;
    }

    const evo::AuxiliaryHistoryGCFrontier* effective_frontier{
        completed_frontier};
    const evo::AuxiliaryHistoryGCAuthorization* effective_authorization{
        completed_authorization};
    const evo::AuxiliaryHistoryGCManifest* pending_manifest{nullptr};
    bool pq_advances{false};
    if (state.intent) {
        const auto& intent{*state.intent};
        if (intent.sequence == 0 || intent.configuration_id.IsNull() ||
            (m_gc_root_config && intent.configuration_id !=
                 m_gc_root_config->configuration_id) ||
            !intent.target.IsValid() || intent.intent_id.IsNull()) {
            return fail_transition();
        }
        const auto& target{intent.target};
        if (state.watermark) {
            const auto& watermark{*state.watermark};
            if (watermark.sequence == std::numeric_limits<uint64_t>::max() ||
                intent.sequence != watermark.sequence + 1 ||
                intent.configuration_id != watermark.configuration_id ||
                target.authorization.block.height <=
                    watermark.authorization.block.height ||
                static_cast<uint8_t>(target.authorization.source) <
                    static_cast<uint8_t>(
                        watermark.authorization.source) ||
                !component_dominates(
                    watermark.frontier.dmn, target.frontier.dmn) ||
                !component_dominates(
                    watermark.frontier.pq_registry,
                    target.frontier.pq_registry)) {
                return fail_transition();
            }
            const bool dmn_advances{component_advances(
                watermark.frontier.dmn, target.frontier.dmn)};
            pq_advances = component_advances(
                watermark.frontier.pq_registry,
                target.frontier.pq_registry);
            if (dmn_advances == pq_advances) return fail_transition();
        } else {
            if (intent.sequence != 1) return fail_transition();
            const bool has_dmn{target.frontier.dmn.has_value()};
            const bool has_pq{target.frontier.pq_registry.has_value()};
            if (has_dmn == has_pq) return fail_transition();
            pq_advances = has_pq;
        }
        if (target.pq_erase_manifest.has_value() != pq_advances) {
            return fail_transition();
        }
        pending_manifest = target.pq_erase_manifest
            ? &*target.pq_erase_manifest
            : nullptr;
        effective_frontier = &target.frontier;
        effective_authorization = &target.authorization;
    }

    const auto& previous_component{state.watermark
        ? state.watermark->frontier.pq_registry
        : std::optional<evo::AuxiliaryHistoryGCComponent>{}};
    const auto& effective_component{effective_frontier
        ? effective_frontier->pq_registry
        : std::optional<evo::AuxiliaryHistoryGCComponent>{}};
    if (!effective_component) {
        return previous_component || pq_advances
            ? fail_transition()
            : true;
    }
    if (!m_gc_root_config ||
        !m_gc_root_config->IsValid(m_config)) {
        return SetError(error, PQRegistryResult::INVALID_CONFIGURATION);
    }
    if ((state.watermark &&
         state.watermark->configuration_id !=
             m_gc_root_config->configuration_id) ||
        (state.intent && state.intent->configuration_id !=
             m_gc_root_config->configuration_id)) {
        return fail_transition();
    }
    if (effective_authorization == nullptr ||
        !evo::IsPQRegistryGCComponentBoundedByAuthorization(
            *effective_component, *effective_authorization)) {
        return fail_transition();
    }
    const auto effective_closure{evo::DecodePQRegistryGCClosure(
        effective_component->closure)};
    if (!effective_closure) return fail_transition();

    std::optional<evo::PQRegistryGCClosure> previous_closure;
    if (previous_component) {
        if (completed_authorization == nullptr ||
            !evo::IsPQRegistryGCComponentBoundedByAuthorization(
                *previous_component, *completed_authorization)) {
            return fail_transition();
        }
        previous_closure = evo::DecodePQRegistryGCClosure(
            previous_component->closure);
        if (!previous_closure) return fail_transition();
    }

    // A compact completed watermark carries only its latest rooted base. On
    // restart that durable, configuration-bound closure is the inherited
    // trust link; exact replay below independently rebinds its current
    // segment and the permanently pinned Q..A island.
    GCAuthenticationResult authenticated;
    // Keep the authenticated records and effective floor under one lock until
    // publication so the reused result cannot become stale between phases.
    LOCK(m_mutex);
    if (!AuthenticateGCContext(
            context, effective_closure->lineage_base_commitment,
            previous_closure ? &*previous_closure : nullptr,
            authenticated, error)) {
        return false;
    }
    const int64_t anchor_delta{
        static_cast<int64_t>(m_gc_root_config->legacy_anchor.height) -
        m_config.preparation_height};
    const int64_t initial_checkpoint_height{
        static_cast<int64_t>(m_config.preparation_height) +
        anchor_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL *
            PQ_REGISTRY_CHECKPOINT_INTERVAL +
        PQ_REGISTRY_CHECKPOINT_INTERVAL};
    const int64_t checkpoint_delta{
        static_cast<int64_t>(effective_closure->checkpoint.height) -
        initial_checkpoint_height};
    if (checkpoint_delta < 0 ||
        checkpoint_delta % PQ_REGISTRY_CHECKPOINT_INTERVAL != 0) {
        return fail_transition();
    }
    const uint64_t minimum_generation{static_cast<uint64_t>(
        1 + checkpoint_delta / PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    if (effective_closure->generation < minimum_generation ||
        effective_closure->checkpoint != authenticated.checkpoint ||
        effective_closure->checkpoint_state_root !=
            authenticated.checkpoint_state_root ||
        effective_closure->checkpoint_record_hash !=
            authenticated.checkpoint_record_hash ||
        effective_closure->lineage_base_commitment !=
            authenticated.lineage_base_commitment ||
        effective_closure->rooted_lineage_commitment !=
            authenticated.rooted_lineage_commitment ||
        effective_closure->legacy_island_commitment !=
            authenticated.legacy_island_commitment) {
        return fail_transition();
    }

    std::optional<evo::PQRegistryGCEraseManifest> decoded_manifest;
    if (pq_advances) {
        if (pending_manifest == nullptr ||
            pending_manifest->version !=
                evo::PQRegistryGCEraseManifest::VERSION) {
            return fail_transition();
        }
        decoded_manifest = evo::DecodePQRegistryGCEraseManifest(
            pending_manifest->payload);
        const auto target_hash{evo::GetAuxiliaryHistoryGCComponentHash(
            *effective_component)};
        const auto previous_hash{previous_component
            ? evo::GetAuxiliaryHistoryGCComponentHash(*previous_component)
            : std::optional<uint256>{}};
        if (!decoded_manifest || !target_hash ||
            decoded_manifest->target_component_hash != *target_hash ||
            decoded_manifest->previous_component_hash != previous_hash) {
            return fail_transition();
        }
        if (!previous_component &&
            (effective_component->monotonic_position != 1 ||
             effective_closure->generation != 1)) {
            return fail_transition();
        }

        const bool same_checkpoint{previous_closure &&
            previous_closure->checkpoint ==
                effective_closure->checkpoint};
        if (previous_closure) {
            if (effective_component->monotonic_position !=
                    previous_component->monotonic_position + 1 ||
                effective_closure->legacy_island_commitment !=
                    previous_closure->legacy_island_commitment) {
                return fail_transition();
            }
            if (same_checkpoint) {
                if (previous_closure->scan_complete !=
                        evo::PQRegistryGCClosure::SCANNING ||
                    effective_closure->checkpoint_state_root !=
                        previous_closure->checkpoint_state_root ||
                    effective_closure->checkpoint_record_hash !=
                        previous_closure->checkpoint_record_hash ||
                    effective_closure->lineage_base_commitment !=
                        previous_closure->lineage_base_commitment ||
                    effective_closure->rooted_lineage_commitment !=
                        previous_closure->rooted_lineage_commitment) {
                    return fail_transition();
                }
            } else {
                const int64_t height_delta{
                    static_cast<int64_t>(
                        effective_closure->checkpoint.height) -
                    previous_closure->checkpoint.height};
                if (previous_closure->scan_complete !=
                        evo::PQRegistryGCClosure::COMPLETE ||
                    height_delta != PQ_REGISTRY_CHECKPOINT_INTERVAL ||
                    effective_closure->lineage_base_commitment !=
                        previous_closure->rooted_lineage_commitment) {
                    return fail_transition();
                }
            }
        }

        const std::optional<uint256> expected_from_cursor{
            previous_closure && same_checkpoint
                ? previous_closure->scan_after_key
                : std::nullopt};
        if (decoded_manifest->from_cursor != expected_from_cursor) {
            return fail_transition();
        }
        if (effective_closure->scan_complete ==
            evo::PQRegistryGCClosure::SCANNING) {
            if (decoded_manifest->reached_eof != 0 ||
                decoded_manifest->scan_through !=
                    effective_closure->scan_after_key) {
                return fail_transition();
            }
        } else if (decoded_manifest->reached_eof != 1) {
            return fail_transition();
        }
        std::unordered_map<uint256, int32_t, StaticSaltedHasher>
            protected_records;
        protected_records.reserve(authenticated.protected_records.size());
        for (const auto& identity : authenticated.protected_records) {
            const auto [position, inserted]{protected_records.emplace(
                identity.block_hash, identity.height)};
            if (!inserted && position->second != identity.height) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }
        using SnapshotDB = CEvoDB<
            uint256, PQRegistryDiskSnapshot, StaticSaltedHasher>;
        bool found_present_candidate{false};
        for (const auto& candidate : decoded_manifest->candidates) {
            const auto protected_position{
                protected_records.find(candidate.key)};
            const bool protects_authentication_path{
                protected_position != protected_records.end() &&
                protected_position->second == candidate.height};
            if (protects_authentication_path) return fail_transition();
            if (candidate.height < m_config.preparation_height ||
                candidate.height >
                    effective_closure->checkpoint.height) {
                return fail_transition();
            }
            PQRegistryDiskSnapshot disk;
            const auto read_result{m_snapshot_db->ReadExactDiskForGC(
                candidate.key, disk)};
            if (read_result == SnapshotDB::ExactDiskReadResult::BLOCKED) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            if (read_result ==
                SnapshotDB::ExactDiskReadResult::NOT_FOUND) {
                if (found_present_candidate) return fail_transition();
                continue;
            }
            found_present_candidate = true;
            if (!disk.IsStructurallyValid() ||
                disk.block_hash != candidate.key ||
                disk.height != candidate.height ||
                ::SerializeHash(disk) != candidate.exact_record_hash ||
                (disk.is_checkpoint != 0) !=
                    IsRegistryCheckpoint(m_config, disk.height)) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }

        if (previous_closure && !same_checkpoint) {
            bool previous_missing{false};
            if (!AuthenticateGCFloorCheckpoint(
                    *previous_closure, nullptr, error,
                    &previous_missing)) {
                return false;
            }
            if (previous_missing) return fail_transition();
        }
    } else if (pending_manifest != nullptr ||
               (previous_component &&
                *previous_component != *effective_component)) {
        return fail_transition();
    }

    return InstallGCFloorFromAuthenticatedLocked(
        *effective_component, &*effective_closure, authenticated, error);
}

bool PQRegistryManager::CacheSnapshotView(
    std::shared_ptr<const PQRegistrySnapshotView> snapshot,
    std::shared_ptr<const PQRegistrySnapshotView>* cached) const
{
    PQRegistryError floor_error;
    if (!snapshot || !snapshot->state ||
        !snapshot->state->operator_states ||
        !snapshot->state->used_tree_ids || !snapshot->state->indexes ||
        !snapshot->block_tree_ids || snapshot->height < 0 ||
        snapshot->block_hash.IsNull() ||
        (snapshot->height != 0 && snapshot->previous_block_hash.IsNull()) ||
        snapshot->state->consensus_state_root.IsNull() ||
        snapshot->gc_floor_revision != m_gc_floor_revision ||
        !CheckGCFloorAccess(snapshot->block_hash, snapshot->height,
                            floor_error)) {
        return false;
    }

    auto existing{m_snapshot_cache_index.find(snapshot->block_hash)};
    m_snapshot_cache.emplace_back(snapshot->block_hash, std::move(snapshot));
    const auto inserted{std::prev(m_snapshot_cache.end())};
    if (existing != m_snapshot_cache_index.end()) {
        const auto replaced{existing->second};
        existing->second = inserted;
        m_snapshot_cache.erase(replaced);
    } else {
        try {
            const auto insertion{m_snapshot_cache_index.emplace(
                inserted->first, inserted)};
            if (!insertion.second) {
                m_snapshot_cache.pop_back();
                return false;
            }
        } catch (...) {
            // A prepared transition must remain safely retryable after an
            // allocation failure; never leave a list node without its index.
            m_snapshot_cache.pop_back();
            throw;
        }
    }
    if (cached != nullptr) {
        *cached = inserted->second;
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

bool PQRegistryManager::CommitPreparedSnapshot(
    const std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
    const PQRegistryDiskSnapshot& disk,
    uint64_t floor_revision,
    PQRegistryError& error)
{
    if (floor_revision != m_gc_floor_revision ||
        !snapshot || snapshot->gc_floor_revision != floor_revision ||
        !snapshot->state ||
        !snapshot->state->operator_states ||
        !snapshot->state->used_tree_ids || !snapshot->state->indexes ||
        !snapshot->block_tree_ids || snapshot->block_hash.IsNull() ||
        disk.block_hash != snapshot->block_hash ||
        disk.previous_block_hash != snapshot->previous_block_hash ||
        disk.height != snapshot->height ||
        disk.consensus_state_root !=
            snapshot->state->consensus_state_root ||
        disk.block_tree_ids != *snapshot->block_tree_ids ||
        (disk.is_checkpoint != 0) !=
            IsRegistryCheckpoint(m_config, snapshot->height) ||
        !CheckGCFloorAccess(snapshot->block_hash, snapshot->height,
                            error)) {
        if (error.result != PQRegistryResult::OK) return false;
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }

    PQRegistryDiskSnapshot existing;
    if (m_snapshot_db->ReadCache(snapshot->block_hash, existing)) {
        if (!existing.IsStructurallyValid() || existing != disk) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CONFLICT);
        }
    } else if (m_snapshot_db->ExistsCache(snapshot->block_hash)) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    } else if (!m_snapshot_db->WriteThrough(
                   snapshot->block_hash, disk, /*fSync=*/false)) {
        // SYSCOIN: Publish every branch link before CoinsTip can advance; the
        // shared flush barrier supplies durability without an IBD fsync here.
        return SetError(error, PQRegistryResult::PERSISTENCE_FAILED);
    }
    return CacheSnapshotView(snapshot)
        ? true
        : SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
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

bool PQRegistryManager::ReconstructPersistentSnapshotViewAboveFloor(
    const uint256& block_hash,
    int32_t expected_height,
    std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
    PQRegistryError& error) const
{
    if (!m_gc_floor || expected_height < m_gc_floor->checkpoint.height) {
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
    }

    std::vector<uint256> reverse_hashes;
    const int64_t distance{
        static_cast<int64_t>(expected_height) -
        m_gc_floor->checkpoint.height};
    reverse_hashes.reserve(static_cast<std::size_t>(std::min<int64_t>(
        distance, 2 * PQ_REGISTRY_CHECKPOINT_INTERVAL)));
    uint256 cursor{block_hash};
    for (int32_t cursor_height{expected_height};
         cursor_height > m_gc_floor->checkpoint.height; --cursor_height) {
        PQRegistryDiskSnapshot record;
        if (!ReadDiskSnapshot(cursor, record, error)) return false;
        if (record.height != cursor_height || record.block_hash != cursor ||
            (record.is_checkpoint != 0) !=
                IsRegistryCheckpoint(m_config, cursor_height) ||
            record.previous_block_hash.IsNull()) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        reverse_hashes.push_back(cursor);
        cursor = record.previous_block_hash;
    }
    if (cursor != m_gc_floor->checkpoint.block_hash) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }

    std::shared_ptr<const PQRegistrySnapshotView> base;
    if (!AuthenticateGCFloorCheckpoint(*m_gc_floor, &base, error) ||
        !base || !base->state || !base->state->operator_states ||
        !base->state->used_tree_ids || !base->state->indexes ||
        !base->block_tree_ids) {
        if (error.result == PQRegistryResult::OK) {
            SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        return false;
    }

    std::vector<OperatorKeyState> states{*base->state->operator_states};
    std::shared_ptr<const std::vector<uint256>> used_tree_ids{
        base->state->used_tree_ids};
    std::shared_ptr<const PQRegistryStateData> authenticated_state{
        base->state};
    uint256 used_tree_ids_hash{base->state->used_tree_ids_hash};
    uint256 previous_hash{base->block_hash};
    int32_t replay_height{base->height};

    SnapshotViewCache staged;
    staged.emplace_back(base->block_hash, base);
    ++m_reconstruction_authenticated_records;
    ++m_reconstruction_tree_id_hashes;
    ++m_reconstruction_state_hashes;

    for (auto hash{reverse_hashes.rbegin()};
         hash != reverse_hashes.rend(); ++hash) {
        PQRegistryDiskSnapshot record;
        if (!ReadDiskSnapshot(*hash, record, error)) return false;
        ++replay_height;
        if (record.block_hash != *hash || record.height != replay_height ||
            record.previous_block_hash != previous_hash ||
            record.previous_consensus_state_root !=
                authenticated_state->consensus_state_root ||
            (record.is_checkpoint != 0) !=
                IsRegistryCheckpoint(m_config, record.height) ||
            !ApplySparseOperatorDelta(
                states, record.removed_operators,
                record.operator_states)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }

        const bool has_tree_id_additions{!record.block_tree_ids.empty()};
        if (has_tree_id_additions) {
            std::vector<uint256> merged;
            if (!MergeNewTreeIds(*used_tree_ids,
                                 record.block_tree_ids, merged)) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            used_tree_ids =
                std::make_shared<const std::vector<uint256>>(
                    std::move(merged));
        }
        const bool is_checkpoint{record.is_checkpoint != 0};
        if (is_checkpoint &&
            (states != record.checkpoint_operator_states ||
             *used_tree_ids != record.tree_ids)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }

        const auto schedule_view{DeriveOperatorKeyScheduleView(
            m_config.schedule, record.height,
            m_config.registration_cutoff_blocks,
            m_config.future_horizon_epochs)};
        if (!schedule_view) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto schedule{
            OperatorKeyScheduleState::FromView(*schedule_view)};
        const bool unchanged_sparse_record{
            !is_checkpoint && record.operator_states.empty() &&
            record.removed_operators.empty() &&
            !has_tree_id_additions &&
            authenticated_state->schedule == schedule};

        std::shared_ptr<const PQRegistrySnapshotView> rebuilt;
        if (unchanged_sparse_record) {
            if (record.consensus_state_root !=
                authenticated_state->consensus_state_root) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            used_tree_ids = authenticated_state->used_tree_ids;
            used_tree_ids_hash = authenticated_state->used_tree_ids_hash;
            ++m_reconstruction_reused_records;
        } else {
            if (is_checkpoint || has_tree_id_additions) {
                const auto tree_set_hash{GetUsedTreeIdSetHash(
                    m_genesis_hash, *used_tree_ids)};
                ++m_reconstruction_tree_id_hashes;
                if (!tree_set_hash) {
                    return SetError(error,
                                    PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                used_tree_ids_hash = *tree_set_hash;
            }
            if (states.size() > MAX_PQ_OPERATOR_STATES ||
                !StateTreeIdsAreRecorded(states, *used_tree_ids) ||
                std::any_of(states.begin(), states.end(),
                            [&](const OperatorKeyState& state) {
                                return !state.IsAdvancedTo(*schedule_view);
                            })) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            const auto root{GetCanonicalPQKeyConsensusStateHash(
                m_genesis_hash, states, used_tree_ids_hash)};
            ++m_reconstruction_state_hashes;
            if (!root || *root != record.consensus_state_root) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            rebuilt = MakeAuthenticatedReplaySnapshotView(
                staged, m_snapshot_cache, record, states, used_tree_ids,
                schedule, used_tree_ids_hash, m_gc_floor_revision);
            if (!rebuilt || !rebuilt->state) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            authenticated_state = rebuilt->state;
            used_tree_ids = authenticated_state->used_tree_ids;
            used_tree_ids_hash = authenticated_state->used_tree_ids_hash;
        }
        ++m_reconstruction_authenticated_records;
        if (!rebuilt) {
            rebuilt = MakeSnapshotView(
                record.height, record.block_hash,
                record.previous_block_hash, authenticated_state,
                record.block_tree_ids, m_gc_floor_revision);
        }
        if (!rebuilt) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        staged.emplace_back(record.block_hash, std::move(rebuilt));
        while (staged.size() > 1 &&
               (staged.size() > PQ_REGISTRY_SNAPSHOT_CACHE_SIZE ||
                SnapshotCacheDynamicMemoryUsage(
                    staged, staged.back().second->state.get()) >
                    PQ_REGISTRY_SNAPSHOT_CACHE_MAX_INCREMENTAL_BYTES)) {
            staged.pop_front();
        }
        previous_hash = record.block_hash;
    }

    if (staged.empty() || staged.back().first != block_hash ||
        !staged.back().second ||
        staged.back().second->height != expected_height) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    const auto target{std::prev(staged.end())};
    for (auto view{staged.begin()}; view != staged.end(); ++view) {
        if (!CacheSnapshotView(
                view->second, view == target ? &snapshot : nullptr)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }
    return snapshot != nullptr;
}

bool PQRegistryManager::ReconstructPersistentSnapshotView(
    const uint256& block_hash,
    int32_t expected_height,
    std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
    PQRegistryError& error) const
{
    snapshot.reset();
    if (!CheckGCFloorAccess(block_hash, expected_height, error)) {
        return false;
    }
    const auto cached{m_snapshot_cache_index.find(block_hash)};
    if (cached != m_snapshot_cache_index.end()) {
        const auto& candidate{cached->second->second};
        if (!candidate || !candidate->state ||
            candidate->height != expected_height ||
            candidate->block_hash != block_hash ||
            candidate->gc_floor_revision != m_gc_floor_revision) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        snapshot = candidate;
        m_snapshot_cache.splice(m_snapshot_cache.end(), m_snapshot_cache,
                                cached->second);
        cached->second = std::prev(m_snapshot_cache.end());
        return true;
    }

    if (m_gc_floor) {
        return ReconstructPersistentSnapshotViewAboveFloor(
            block_hash, expected_height, snapshot, error);
    }

    std::vector<PQRegistryDiskSnapshot> reverse_journal;
    reverse_journal.reserve(2 * PQ_REGISTRY_CHECKPOINT_INTERVAL);
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

    // A checkpoint delta can only be authenticated against its parent state.
    // Retain one earlier full checkpoint as the bounded cold base, then replay
    // no more than one complete interval through the newer checkpoint.
    if (reverse_journal.back().height != m_config.preparation_height) {
        cursor = reverse_journal.back().previous_block_hash;
        cursor_height = reverse_journal.back().height - 1;
        bool found_base{false};
        for (int32_t depth{0}; depth < PQ_REGISTRY_CHECKPOINT_INTERVAL;
             ++depth) {
            PQRegistryDiskSnapshot record;
            if (!ReadDiskSnapshot(cursor, record, error)) return false;
            const bool expected_checkpoint{
                (cursor_height - m_config.preparation_height) %
                    PQ_REGISTRY_CHECKPOINT_INTERVAL ==
                0};
            const auto& child{reverse_journal.back()};
            if (record.height != cursor_height ||
                record.block_hash != cursor ||
                (record.is_checkpoint != 0) != expected_checkpoint ||
                child.previous_block_hash != record.block_hash ||
                child.previous_consensus_state_root !=
                    record.consensus_state_root ||
                child.height != record.height + 1) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            reverse_journal.push_back(std::move(record));
            if (reverse_journal.back().is_checkpoint != 0) {
                found_base = true;
                break;
            }
            if (reverse_journal.back().previous_block_hash.IsNull() ||
                cursor_height <= 0) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            cursor = reverse_journal.back().previous_block_hash;
            --cursor_height;
        }
        if (!found_base) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }
    if (reverse_journal.size() >
        2 * static_cast<std::size_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL)) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    const auto& base_checkpoint{reverse_journal.back()};
    std::optional<uint256> preparation_parent_root;
    if (base_checkpoint.height == m_config.preparation_height) {
        const auto parent_root{
            EmptyRegistryConsensusStateRoot(m_genesis_hash)};
        if (!parent_root || base_checkpoint.previous_consensus_state_root !=
                                *parent_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        preparation_parent_root = *parent_root;
    } else {
        PQRegistryDiskSnapshot parent;
        if (!ReadDiskSnapshot(base_checkpoint.previous_block_hash, parent,
                              error) ||
            parent.height != base_checkpoint.height - 1 ||
            parent.consensus_state_root !=
                base_checkpoint.previous_consensus_state_root) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }

    std::vector<OperatorKeyState> states;
    std::shared_ptr<const std::vector<uint256>> used_tree_ids;
    std::shared_ptr<const PQRegistryStateData> authenticated_state;
    uint256 used_tree_ids_hash;
    if (preparation_parent_root) {
        used_tree_ids =
            std::make_shared<const std::vector<uint256>>();
    }
    SnapshotViewCache staged;
    const std::size_t staged_count{std::min(
        reverse_journal.size(), PQ_REGISTRY_SNAPSHOT_CACHE_SIZE)};
    const std::size_t first_staged_record{
        reverse_journal.size() - staged_count};
    std::size_t replayed_record{0};
    for (auto record{reverse_journal.rbegin()};
         record != reverse_journal.rend(); ++record) {
        const bool is_checkpoint{record->is_checkpoint != 0};
        const bool is_cold_base{
            replayed_record == 0 &&
            record->height != m_config.preparation_height};
        const bool has_tree_id_additions{
            !record->block_tree_ids.empty()};
        if (is_cold_base) {
            states = record->checkpoint_operator_states;
            used_tree_ids =
                std::make_shared<const std::vector<uint256>>(
                    record->tree_ids);
        } else {
            const uint256 prior_root{authenticated_state
                ? authenticated_state->consensus_state_root
                : preparation_parent_root.value_or(uint256{})};
            if (prior_root.IsNull() ||
                record->previous_consensus_state_root != prior_root) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            if (!ApplySparseOperatorDelta(
                    states, record->removed_operators,
                    record->operator_states)) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            if (!used_tree_ids) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            if (has_tree_id_additions) {
                std::vector<uint256> merged;
                if (!MergeNewTreeIds(*used_tree_ids,
                                     record->block_tree_ids, merged)) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                used_tree_ids =
                    std::make_shared<const std::vector<uint256>>(
                        std::move(merged));
            }
            if (is_checkpoint &&
                (states != record->checkpoint_operator_states ||
                 *used_tree_ids != record->tree_ids)) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
        }
        const auto schedule_view{DeriveOperatorKeyScheduleView(
            m_config.schedule, record->height,
            m_config.registration_cutoff_blocks,
            m_config.future_horizon_epochs)};
        if (!schedule_view || !used_tree_ids) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
        const auto schedule{
            OperatorKeyScheduleState::FromView(*schedule_view)};
        const bool unchanged_sparse_record{
            !is_checkpoint && record->operator_states.empty() &&
            record->removed_operators.empty() && !has_tree_id_additions &&
            authenticated_state &&
            authenticated_state->schedule == schedule};

        std::shared_ptr<const PQRegistrySnapshotView> rebuilt;
        if (unchanged_sparse_record) {
            // SYSCOIN: A claimed root is never trusted merely because the
            // sparse payload is empty. Exact equality with the immediately
            // prior authenticated state is what authorizes pointer reuse.
            if (record->previous_consensus_state_root !=
                    authenticated_state->consensus_state_root ||
                record->consensus_state_root !=
                    authenticated_state->consensus_state_root) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            used_tree_ids = authenticated_state->used_tree_ids;
            used_tree_ids_hash =
                authenticated_state->used_tree_ids_hash;
            ++m_reconstruction_reused_records;
        } else {
            if (is_checkpoint || has_tree_id_additions) {
                const auto tree_set_hash{GetUsedTreeIdSetHash(
                    m_genesis_hash, *used_tree_ids)};
                ++m_reconstruction_tree_id_hashes;
                if (!tree_set_hash) {
                    return SetError(
                        error, PQRegistryResult::SNAPSHOT_CORRUPT);
                }
                used_tree_ids_hash = *tree_set_hash;
            } else if (used_tree_ids_hash.IsNull()) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            if (states.size() > MAX_PQ_OPERATOR_STATES ||
                !StateTreeIdsAreRecorded(states, *used_tree_ids) ||
                std::any_of(states.begin(), states.end(),
                            [&](const OperatorKeyState& state) {
                                return !state.IsAdvancedTo(*schedule_view);
                            })) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            const auto root{GetCanonicalPQKeyConsensusStateHash(
                m_genesis_hash,
                std::span<const OperatorKeyState>{
                    states.data(), states.size()},
                used_tree_ids_hash)};
            ++m_reconstruction_state_hashes;
            if (!root || *root != record->consensus_state_root) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            rebuilt = MakeAuthenticatedReplaySnapshotView(
                staged, m_snapshot_cache, *record, states, used_tree_ids,
                schedule, used_tree_ids_hash);
            if (!rebuilt || !rebuilt->state) {
                return SetError(
                    error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            authenticated_state = rebuilt->state;
            used_tree_ids = authenticated_state->used_tree_ids;
            used_tree_ids_hash =
                authenticated_state->used_tree_ids_hash;
        }
        ++m_reconstruction_authenticated_records;

        if (replayed_record >= first_staged_record) {
            if (!rebuilt) {
                rebuilt = MakeSnapshotView(
                    record->height, record->block_hash,
                    record->previous_block_hash, authenticated_state,
                    record->block_tree_ids);
            }
            if (!rebuilt) {
                return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
            }
            staged.emplace_back(record->block_hash, std::move(rebuilt));
            // The replay tail is unpublished authority. Bound its temporary
            // ownership exactly like the live cache while a later corrupt
            // record can still make the complete reconstruction fail.
            while (staged.size() > 1 &&
                   (staged.size() > PQ_REGISTRY_SNAPSHOT_CACHE_SIZE ||
                    SnapshotCacheDynamicMemoryUsage(
                        staged, staged.back().second->state.get()) >
                        PQ_REGISTRY_SNAPSHOT_CACHE_MAX_INCREMENTAL_BYTES)) {
                staged.pop_front();
            }
        }
        ++replayed_record;
    }

    if (staged.empty() || staged.back().first != block_hash ||
        !staged.back().second ||
        staged.back().second->height != expected_height) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }

    // A corrupt suffix must not make an authenticated prefix observable as a
    // successful cache side effect. Publish only after the target completed.
    const auto target{std::prev(staged.end())};
    for (auto view{staged.begin()}; view != staged.end(); ++view) {
        if (!CacheSnapshotView(
                view->second, view == target ? &snapshot : nullptr)) {
            return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
        }
    }
    if (!snapshot) {
        return SetError(error, PQRegistryResult::SNAPSHOT_CORRUPT);
    }
    return true;
}

bool PQRegistryManager::ProcessBlock(
    const CBlock& block,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    std::span<const uint256> net_removed_pro_tx_hashes,
    bool fJustCheck,
    PQRegistryError& error,
    uint256* resulting_state_root)
{
    PQRegistryPreparedBlock prepared;
    if (!PrepareBlock(block, height, callbacks,
                      net_removed_pro_tx_hashes, prepared, error)) {
        return false;
    }
    if (resulting_state_root != nullptr) {
        *resulting_state_root = prepared.ConsensusStateRoot();
    }
    if (!fJustCheck) return CommitPreparedBlock(prepared, error);
    LOCK(m_mutex);
    return prepared.m_gc_floor_revision == m_gc_floor_revision
        ? true
        : SetError(error, PQRegistryResult::FLOOR_CONFLICT);
}

bool PQRegistryManager::PrepareBlock(
    const CBlock& block,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    std::span<const uint256> net_removed_pro_tx_hashes,
    PQRegistryPreparedBlock& prepared,
    PQRegistryError& error)
{
    return PrepareBlockInternal(
        block, height, callbacks, net_removed_pro_tx_hashes, prepared,
        error);
}

bool PQRegistryManager::PrepareBlockInternal(
    const CBlock& block,
    int32_t height,
    const PQRegistryCallbacks& callbacks,
    std::span<const uint256> net_removed_pro_tx_hashes,
    PQRegistryPreparedBlock& prepared,
    PQRegistryError& error)
{
    prepared = {};
    error.Clear();
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
    uint64_t floor_revision{0};
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
        const auto root{EmptyRegistryConsensusStateRoot(m_genesis_hash)};
        if (!root) {
            SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
            return false;
        }
        {
            LOCK(m_mutex);
            if (m_gc_floor && height <= m_gc_floor->checkpoint.height) {
                return SetError(error, PQRegistryResult::HISTORY_PRUNED);
            }
            floor_revision = m_gc_floor_revision;
        }
        prepared.m_incarnation = m_incarnation;
        prepared.m_kind = PQRegistryPreparedBlock::Kind::NO_COMMIT;
        prepared.m_block_hash = block_hash;
        prepared.m_consensus_state_root = *root;
        prepared.m_height = height;
        prepared.m_gc_floor_revision = floor_revision;
        return true;
    }
    if (!net_removed_pro_tx_hashes.empty() &&
        !IsStrictlySortedUnique(net_removed_pro_tx_hashes)) {
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
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
    std::unordered_set<uint256, StaticSaltedHasher> updated_operators;
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
        if (!updated_operators.emplace(update.pro_tx_hash).second) {
            return SetError(error,
                            PQRegistryResult::DUPLICATE_OPERATOR_UPDATE,
                            index, update.pro_tx_hash);
        }
        updates.push_back(std::move(update));
    }

    std::shared_ptr<const PQRegistrySnapshotView> parent_view;
    if (height == m_config.preparation_height) {
        LOCK(m_mutex);
        if (m_gc_floor && height <= m_gc_floor->checkpoint.height) {
            return SetError(error, PQRegistryResult::HISTORY_PRUNED);
        }
        floor_revision = m_gc_floor_revision;
        parent_view = MakePrePreparationSnapshotView(
            m_snapshot_cache, m_genesis_hash, m_config,
            block.hashPrevBlock, uint256{}, height - 1, error);
        if (!parent_view) return false;
    } else {
        LOCK(m_mutex);
        if (m_gc_floor && height <= m_gc_floor->checkpoint.height) {
            return SetError(error, PQRegistryResult::HISTORY_PRUNED);
        }
        if (!ReconstructPersistentSnapshotView(
                block.hashPrevBlock, height - 1, parent_view, error)) {
            if (error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND) {
                error.result = PQRegistryResult::MISSING_PARENT_SNAPSHOT;
            }
            return false;
        }
        floor_revision = m_gc_floor_revision;
    }

    if (IsRegistryCheckpoint(m_config, height)) {
        // SYSCOIN: Exact deterministic-MN removals maintain membership on
        // ordinary blocks. Reconcile the complete invariant periodically so
        // the hot path only queries operators explicitly changed by a block.
        const std::span<const OperatorKeyState> parent_states{
            *parent_view->state->operator_states};
        for (const auto& state : parent_states) {
            bool exists{false};
            if (!CallMembership(callbacks.dmn_exists_before,
                                state.pro_tx_hash, exists, error)) {
                return false;
            }
            if (!exists) {
                return SetError(
                    error, PQRegistryResult::PARENT_DMN_MISMATCH,
                    std::numeric_limits<std::size_t>::max(),
                    state.pro_tx_hash);
            }
        }
    }

    const auto next_schedule{
        OperatorKeyScheduleState::FromView(*schedule_view)};
    const auto& parent_operator_states{
        *parent_view->state->operator_states};
    const bool schedule_changed{
        !parent_view->state->schedule ||
        *parent_view->state->schedule != next_schedule};
    const bool removes_registry_operator{std::any_of(
        net_removed_pro_tx_hashes.begin(),
        net_removed_pro_tx_hashes.end(), [&](const uint256& pro_tx_hash) {
            const auto position{FindOperatorPosition(
                parent_operator_states, pro_tx_hash)};
            return position != parent_operator_states.end() &&
                   position->pro_tx_hash == pro_tx_hash;
        })};
    const bool unchanged_state{
        !schedule_changed && updates.empty() &&
        !removes_registry_operator};
    if (unchanged_state) {
        auto result{std::make_shared<PQRegistrySnapshotView>()};
        result->height = height;
        result->block_hash = block_hash;
        result->previous_block_hash = block.hashPrevBlock;
        result->gc_floor_revision = floor_revision;
        result->state = parent_view->state;
        result->block_tree_ids =
            std::make_shared<const std::vector<uint256>>();
        prepared.m_incarnation = m_incarnation;
        prepared.m_kind = PQRegistryPreparedBlock::Kind::TRANSITION;
        prepared.m_block_hash = block_hash;
        prepared.m_consensus_state_root =
            result->state->consensus_state_root;
        prepared.m_height = height;
        prepared.m_gc_floor_revision = floor_revision;
        prepared.m_parent = std::move(parent_view);
        prepared.m_result = std::move(result);
        return true;
    }

    std::vector<OperatorKeyState> next_operator_states{
        parent_operator_states};
    std::vector<uint256> block_tree_ids;
    block_tree_ids.reserve(updates.size());
    if (schedule_changed) {
        for (auto& state : next_operator_states) {
            const auto result{state.Advance(*schedule_view)};
            if (result != OperatorKeyStateResult::OK) {
                return SetError(
                    error,
                    PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                    std::numeric_limits<std::size_t>::max(),
                    state.pro_tx_hash, result);
            }
        }
    }

    std::vector<OperatorKeyState> replacements;
    replacements.reserve(updates.size());
    // Ownership and tree reuse are sequential consensus checks: later
    // transactions see successful earlier updates, while removals remain a
    // final-state operation and cannot release either namespace mid-block.
    std::map<GlobalPublicKey, std::optional<uint256>> key_owner_overlay;
    std::unordered_set<uint256, StaticSaltedHasher> new_tree_id_set;
    new_tree_id_set.reserve(updates.size());
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

        const auto inherited{FindOperatorPosition(next_operator_states,
                                                  update.pro_tx_hash)};
        OperatorKeyState candidate{
            inherited != next_operator_states.end() &&
                    inherited->pro_tx_hash == update.pro_tx_hash
                ? *inherited
                : OperatorKeyState::ForOperator(update.pro_tx_hash)};
        if (inherited == next_operator_states.end() ||
            inherited->pro_tx_hash != update.pro_tx_hash) {
            const auto result{candidate.Advance(*schedule_view)};
            if (result != OperatorKeyStateResult::OK) {
                return SetError(
                    error,
                    PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED,
                    update.transaction_index, update.pro_tx_hash, result);
            }
        }

        std::optional<GlobalPublicKey> previous_global_key;
        if (candidate.has_global_key != 0) {
            previous_global_key = candidate.global_key.public_key;
        }
        std::optional<uint256> introduced_tree_id;
        const auto find_global_key_owner{
            [&](const GlobalPublicKey& public_key)
                -> std::optional<uint256> {
                const auto changed{key_owner_overlay.find(public_key)};
                if (changed != key_owner_overlay.end()) {
                    return changed->second;
                }
                if (!parent_view || !parent_view->state ||
                    !parent_view->state->indexes) {
                    return std::nullopt;
                }
                const auto owner{
                    parent_view->state->indexes->global_key_owner.find(
                        public_key)};
                return owner ==
                        parent_view->state->indexes->global_key_owner.end()
                    ? std::nullopt
                    : std::optional<uint256>{owner->second};
            }};
        if (!ApplyDecodedUpdate(
                candidate, update, *schedule_view, m_genesis_hash, callbacks,
                /*check_sigs=*/true, find_global_key_owner,
                [&](const uint256& tree_id) {
                    return std::binary_search(
                               parent_view->state->used_tree_ids->begin(),
                               parent_view->state->used_tree_ids->end(),
                               tree_id) ||
                           new_tree_id_set.contains(tree_id);
                },
                introduced_tree_id, error)) {
            return false;
        }
        if (previous_global_key &&
            (candidate.has_global_key == 0 ||
             candidate.global_key.public_key != *previous_global_key)) {
            key_owner_overlay[*previous_global_key] = std::nullopt;
        }
        if (candidate.has_global_key != 0) {
            key_owner_overlay[candidate.global_key.public_key] =
                update.pro_tx_hash;
        }
        if (introduced_tree_id) {
            block_tree_ids.push_back(*introduced_tree_id);
            if (!new_tree_id_set.emplace(*introduced_tree_id).second) {
                return SetError(error, PQRegistryResult::INTERNAL_ERROR,
                                update.transaction_index,
                                update.pro_tx_hash);
            }
        }
        replacements.push_back(std::move(candidate));
    }

    if (!replacements.empty()) {
        std::sort(replacements.begin(), replacements.end(),
                  [](const OperatorKeyState& left,
                     const OperatorKeyState& right) {
                      return left.pro_tx_hash < right.pro_tx_hash;
                  });
        std::vector<OperatorKeyState> merged;
        merged.reserve(next_operator_states.size() + replacements.size());
        auto current{next_operator_states.begin()};
        auto replacement{replacements.begin()};
        while (current != next_operator_states.end() ||
               replacement != replacements.end()) {
            if (replacement == replacements.end() ||
                (current != next_operator_states.end() &&
                 current->pro_tx_hash < replacement->pro_tx_hash)) {
                merged.push_back(std::move(*current++));
            } else if (current == next_operator_states.end() ||
                       replacement->pro_tx_hash < current->pro_tx_hash) {
                merged.push_back(std::move(*replacement++));
            } else {
                merged.push_back(std::move(*replacement++));
                ++current;
            }
        }
        next_operator_states = std::move(merged);
    }

    if (!net_removed_pro_tx_hashes.empty()) {
        std::size_t write_index{0};
        auto removal{net_removed_pro_tx_hashes.begin()};
        for (std::size_t read_index{0};
             read_index < next_operator_states.size(); ++read_index) {
            auto& state{next_operator_states[read_index]};
            while (removal != net_removed_pro_tx_hashes.end() &&
                   *removal < state.pro_tx_hash) {
                ++removal;
            }
            if (removal != net_removed_pro_tx_hashes.end() &&
                *removal == state.pro_tx_hash) {
                ++removal;
                continue;
            }
            if (write_index != read_index) {
                next_operator_states[write_index] = std::move(state);
            }
            ++write_index;
        }
        next_operator_states.resize(write_index);
    }
    std::sort(block_tree_ids.begin(), block_tree_ids.end());
    std::shared_ptr<const std::vector<uint256>> used_tree_ids{
        parent_view->state->used_tree_ids};
    uint256 used_tree_ids_hash{parent_view->state->used_tree_ids_hash};
    if (!block_tree_ids.empty()) {
        std::vector<uint256> merged_tree_ids;
        if (!MergeNewTreeIds(*parent_view->state->used_tree_ids,
                             block_tree_ids, merged_tree_ids)) {
            return SetError(error,
                            PQRegistryResult::INVALID_RESULTING_STATE);
        }
        const auto tree_hash{
            GetUsedTreeIdSetHash(m_genesis_hash, merged_tree_ids)};
        if (!tree_hash) {
            return SetError(error,
                            PQRegistryResult::INVALID_RESULTING_STATE);
        }
        used_tree_ids_hash = *tree_hash;
        used_tree_ids =
            std::make_shared<const std::vector<uint256>>(
                std::move(merged_tree_ids));
    }
    if (next_operator_states.size() > MAX_PQ_OPERATOR_STATES ||
        block_tree_ids.size() > MAX_PQ_TREE_IDS_PER_BLOCK ||
        !IsSubset(block_tree_ids, *used_tree_ids) ||
        !StateTreeIdsAreRecorded(next_operator_states, *used_tree_ids) ||
        std::any_of(
            next_operator_states.begin(), next_operator_states.end(),
            [&](const OperatorKeyState& state) {
                return state.schedule_initialized == 0 ||
                       state.schedule != next_schedule ||
                       (state.has_global_key != 0 &&
                        state.global_key.activated_height >
                            static_cast<uint32_t>(height)) ||
                       state.revoked_height >
                           static_cast<uint32_t>(height);
            })) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    const auto state_root{GetCanonicalPQKeyConsensusStateHash(
        m_genesis_hash, next_operator_states, used_tree_ids_hash)};
    if (!state_root) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    const auto indexes{BuildRegistryIndexes(next_operator_states)};
    auto state{indexes
        ? MakeRegistryStateData(
              std::make_shared<const std::vector<OperatorKeyState>>(
                  std::move(next_operator_states)),
              std::move(used_tree_ids), indexes, next_schedule,
              used_tree_ids_hash, *state_root)
        : nullptr};
    if (!state) {
        return SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
    }
    auto result{std::make_shared<PQRegistrySnapshotView>()};
    result->height = height;
    result->block_hash = block_hash;
    result->previous_block_hash = block.hashPrevBlock;
    result->gc_floor_revision = floor_revision;
    result->state = std::move(state);
    result->block_tree_ids =
        std::make_shared<const std::vector<uint256>>(
            std::move(block_tree_ids));
    prepared.m_incarnation = m_incarnation;
    prepared.m_kind = PQRegistryPreparedBlock::Kind::TRANSITION;
    prepared.m_block_hash = block_hash;
    prepared.m_consensus_state_root = result->state->consensus_state_root;
    prepared.m_height = height;
    prepared.m_gc_floor_revision = floor_revision;
    prepared.m_parent = std::move(parent_view);
    prepared.m_result = std::move(result);
    return true;
}

bool PQRegistryManager::CommitPreparedBlock(
    PQRegistryPreparedBlock& prepared,
    PQRegistryError& error)
{
    error.Clear();
    if (!prepared.IsValid() || prepared.m_incarnation != m_incarnation ||
        prepared.m_block_hash.IsNull() || prepared.m_height <= 0) {
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
    }

    LOCK(m_mutex);
    if (prepared.m_gc_floor_revision != m_gc_floor_revision) {
        return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
    }
    if (m_gc_floor &&
        prepared.m_height <= m_gc_floor->checkpoint.height) {
        return SetError(error, PQRegistryResult::HISTORY_PRUNED);
    }
    bool committed{false};
    switch (prepared.m_kind) {
    case PQRegistryPreparedBlock::Kind::NO_COMMIT:
        if (prepared.m_parent || prepared.m_result || prepared.m_disk) {
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }
        committed = true;
        break;
    case PQRegistryPreparedBlock::Kind::TRANSITION:
        if (!prepared.m_parent || !prepared.m_parent->state ||
            !prepared.m_result || !prepared.m_result->state ||
            prepared.m_result->block_hash != prepared.m_block_hash ||
            prepared.m_result->height != prepared.m_height ||
            prepared.m_result->state->consensus_state_root !=
                prepared.m_consensus_state_root ||
            prepared.m_result->previous_block_hash !=
                prepared.m_parent->block_hash) {
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }
        if (!prepared.m_disk) {
            PQRegistryDiskSnapshot disk;
            if (!BuildPreparedDiskSnapshot(
                    m_config, prepared.m_parent, prepared.m_result, disk,
                    error)) {
                return false;
            }
            prepared.m_disk.emplace(std::move(disk));
        }
        if (prepared.m_disk->previous_consensus_state_root !=
            prepared.m_parent->state->consensus_state_root) {
            return SetError(error, PQRegistryResult::INTERNAL_ERROR);
        }
        committed = CommitPreparedSnapshot(
            prepared.m_result, *prepared.m_disk,
            prepared.m_gc_floor_revision, error);
        break;
    case PQRegistryPreparedBlock::Kind::INVALID:
        return SetError(error, PQRegistryResult::INTERNAL_ERROR);
    }
    if (committed) prepared = {};
    return committed;
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
    uint64_t validation_floor_revision{0};
    {
        LOCK(m_mutex);
        if (m_gc_floor && height <= m_gc_floor->checkpoint.height) {
            return SetError(error, PQRegistryResult::HISTORY_PRUNED);
        }
        validation_floor_revision = m_gc_floor_revision;
        if (!logical_empty_parent) {
            std::shared_ptr<const PQRegistrySnapshotView> snapshot;
            if (!ReconstructPersistentSnapshotView(
                    parent_block_hash, height - 1, snapshot, error)) {
                if (error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND) {
                    error.result = PQRegistryResult::MISSING_PARENT_SNAPSHOT;
                }
                return false;
            }
            parent = PQRegistryReadView{std::move(snapshot)};
        }
    }
    if (logical_empty_parent) {
        if (!EmptyRegistryConsensusStateRoot(m_genesis_hash)) {
            SetError(error, PQRegistryResult::INVALID_RESULTING_STATE);
            return false;
        }
    } else {
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

    // SYSCOIN: Exact block-removal deltas preserve parent membership, with a
    // complete reconciliation at registry checkpoints. Policy passes the exact
    // accepted parent list as both views, so walking unrelated operators here
    // would turn every mempool admission into an O(N) block replay.
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
    {
        LOCK(m_mutex);
        if (validation_floor_revision != m_gc_floor_revision) {
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
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
    {
        LOCK(m_mutex);
        if (view.m_snapshot->gc_floor_revision != m_gc_floor_revision) {
            snapshot = {};
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
    }
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
    if (!CheckGCFloorAccess(block_hash, height, error)) return false;
    std::shared_ptr<const PQRegistrySnapshotView> snapshot;
    if (height < m_config.preparation_height) {
        auto empty{MakePrePreparationSnapshotView(
            m_snapshot_cache, m_genesis_hash, m_config, block_hash,
            previous_block_hash, height, error)};
        if (!empty || !CacheSnapshotView(std::move(empty), &snapshot)) {
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
        auto empty{
            std::make_shared<const PQPaymentEligibleProTxHashes>()};
        LOCK(m_mutex);
        if (!CheckGCFloorAccess(block_hash, height, error)) return false;
        eligible = std::move(empty);
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
        if (!snapshot.m_snapshot ||
            snapshot.m_snapshot->gc_floor_revision !=
                m_gc_floor_revision ||
            !CheckGCFloorAccess(block_hash, height, error)) {
            if (error.result == PQRegistryResult::OK) {
                SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
            return false;
        }
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
        if (!snapshot.m_snapshot ||
            snapshot.m_snapshot->gc_floor_revision !=
                m_gc_floor_revision ||
            !CheckGCFloorAccess(block_hash, height, error)) {
            if (error.result == PQRegistryResult::OK) {
                SetError(error, PQRegistryResult::FLOOR_CONFLICT);
            }
            eligible.reset();
            return false;
        }
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
        LOCK(m_mutex);
        if (!CheckGCFloorAccess(block_hash, height, error)) {
            view = {};
            return false;
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
    {
        LOCK(m_mutex);
        if (snapshot->gc_floor_revision != m_gc_floor_revision) {
            view = {};
            return SetError(error, PQRegistryResult::FLOOR_CONFLICT);
        }
    }
    return true;
}

bool PQRegistryManager::PreflightUndoBlock(
    const uint256& block_hash,
    const uint256& expected_parent_block_hash,
    int32_t height,
    PQRegistryError& error) const
{
    error.Clear();
    if (!IsEnabled() || height < m_config.preparation_height ||
        block_hash.IsNull() || expected_parent_block_hash.IsNull()) {
        return SetError(error, PQRegistryResult::UNDO_MISMATCH);
    }
    LOCK(m_mutex);
    if (m_gc_floor && height <= m_gc_floor->checkpoint.height) {
        return SetError(error, PQRegistryResult::HISTORY_PRUNED);
    }
    std::shared_ptr<const PQRegistrySnapshotView> current;
    if (!ReconstructPersistentSnapshotView(block_hash, height, current,
                                           error)) {
        return false;
    }
    if (!current ||
        current->previous_block_hash != expected_parent_block_hash) {
        return SetError(error, PQRegistryResult::UNDO_MISMATCH);
    }
    if (height == m_config.preparation_height) {
        if (!EmptyRegistryConsensusStateRoot(m_genesis_hash)) {
            return SetError(error,
                            PQRegistryResult::INVALID_RESULTING_STATE);
        }
        return true;
    }
    std::shared_ptr<const PQRegistrySnapshotView> parent;
    return ReconstructPersistentSnapshotView(
        expected_parent_block_hash, height - 1, parent, error);
}

bool PQRegistryManager::Flush(bool fSync)
{
    LOCK(m_mutex);
    return m_snapshot_db->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync);
}

} // namespace llmq::pq
