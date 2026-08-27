// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_REGISTRY_H
#define SYSCOIN_EVO_PQ_REGISTRY_H

#include <evo/evodb.h>
#include <evo/pq_providertx.h>
#include <llmq/pq_operator_key_state.h>

#include <primitives/block.h>
#include <saltedhasher.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <list>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Consensus {
struct Params;
}

namespace llmq::pq {

using PQPaymentEligibleProTxHashes = std::vector<uint256>;
using PQPaymentEligibleProTxHashesPtr =
    std::shared_ptr<const PQPaymentEligibleProTxHashes>;

inline constexpr uint16_t PQ_REGISTRY_SNAPSHOT_VERSION{1};
inline constexpr uint16_t PQ_REGISTRY_DISK_VERSION{1};
inline constexpr int32_t PQ_REGISTRY_CHECKPOINT_INTERVAL{288};
inline constexpr std::size_t PQ_REGISTRY_SNAPSHOT_CACHE_SIZE{64};
inline constexpr std::size_t
    PQ_REGISTRY_SNAPSHOT_CACHE_MAX_INCREMENTAL_BYTES{
    256U * 1024U * 1024U};
inline constexpr std::size_t PQ_PAYMENT_ELIGIBILITY_CACHE_SIZE{8};
inline constexpr std::size_t MAX_PQ_OPERATOR_STATES{65'535};
inline constexpr std::size_t MAX_PQ_TREE_IDS_PER_BLOCK{65'535};
inline constexpr std::size_t MAX_PQ_USED_TREE_IDS{1'000'000};
/** Active reservations plus one standard package, without an unbounded copy. */
inline constexpr std::size_t MAX_PQ_MEMPOOL_OPERATOR_REQUESTS{
    MAX_PQ_OPERATOR_STATES + 64};
inline constexpr std::string_view USED_TREE_ID_SET_DOMAIN{
    "SYS_PQ_USED_TREE_ID_SET_V1"};

struct PQRegistryConfig {
    int32_t preparation_height{-1};
    ChainLockScheduleConfig schedule;
    uint32_t registration_cutoff_blocks{0};
    uint32_t future_horizon_epochs{0};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const PQRegistryConfig&,
                           const PQRegistryConfig&) = default;
};

enum class PQRegistryDeploymentResult : uint8_t {
    DISABLED = 0,
    VALID,
    INVALID_CONFIGURATION,
};

[[nodiscard]] PQRegistryDeploymentResult GetPQRegistryConfig(
    const Consensus::Params& params,
    PQRegistryConfig& config) noexcept;

/** Exact, branch-local operator state plus append-only tree-id history. */
struct PQRegistrySnapshot {
    uint16_t version{PQ_REGISTRY_SNAPSHOT_VERSION};
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    std::vector<OperatorKeyState> operator_states;
    /** Sorted, append-only on this branch; survives operator removal. */
    std::vector<uint256> used_tree_ids;
    /** Sorted ids first accepted by this exact block. */
    std::vector<uint256> block_tree_ids;
    uint256 consensus_state_root;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsEmpty() const noexcept;
    [[nodiscard]] bool HasUsedTreeId(const uint256& tree_id) const noexcept;
    [[nodiscard]] const OperatorKeyState* FindOperator(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] std::optional<uint256> RecomputeConsensusStateRoot(
        const uint256& genesis_hash) const;
    friend bool operator==(const PQRegistrySnapshot&,
                           const PQRegistrySnapshot&) = default;
};

/**
 * One sparse branch journal record. Checkpoints contain the full operator and
 * used-tree-id sets; intermediate records contain only operator deltas and
 * tree ids introduced by that block.
 */
struct PQRegistryDiskSnapshot {
    uint16_t version{PQ_REGISTRY_DISK_VERSION};
    uint8_t is_checkpoint{0};
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    uint256 previous_consensus_state_root;
    std::vector<OperatorKeyState> operator_states;
    std::vector<uint256> removed_operators;
    /** Full append-only set at checkpoints; empty on sparse records. */
    std::vector<uint256> tree_ids;
    /** Exact additions made by this block, including checkpoint blocks. */
    std::vector<uint256> block_tree_ids;
    uint256 consensus_state_root;

    SERIALIZE_METHODS(PQRegistryDiskSnapshot, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ registry disk snapshot");
        });
        READWRITE(obj.version, obj.is_checkpoint, obj.height, obj.block_hash,
                  obj.previous_block_hash,
                  obj.previous_consensus_state_root);
        uint16_t operator_count{
            static_cast<uint16_t>(obj.operator_states.size())};
        SER_WRITE(obj, if (obj.operator_states.size() >
                           MAX_PQ_OPERATOR_STATES) {
            throw std::ios_base::failure("too many PQ operator states");
        });
        READWRITE(operator_count);
        SER_READ(obj, obj.operator_states.resize(operator_count));
        for (auto& state : obj.operator_states) READWRITE(state);

        uint16_t removed_count{
            static_cast<uint16_t>(obj.removed_operators.size())};
        SER_WRITE(obj, if (obj.removed_operators.size() >
                           MAX_PQ_OPERATOR_STATES) {
            throw std::ios_base::failure("too many removed PQ operators");
        });
        READWRITE(removed_count);
        SER_READ(obj, obj.removed_operators.resize(removed_count));
        for (auto& pro_tx_hash : obj.removed_operators) {
            READWRITE(pro_tx_hash);
        }

        uint32_t tree_id_count{
            static_cast<uint32_t>(obj.tree_ids.size())};
        SER_WRITE(obj, if (obj.tree_ids.size() > MAX_PQ_USED_TREE_IDS ||
                           (obj.is_checkpoint == 0 &&
                            obj.tree_ids.size() >
                                MAX_PQ_TREE_IDS_PER_BLOCK)) {
            throw std::ios_base::failure("too many PQ child-tree ids");
        });
        READWRITE(tree_id_count);
        SER_READ(obj, if (tree_id_count > MAX_PQ_USED_TREE_IDS ||
                          (obj.is_checkpoint == 0 && tree_id_count >
                               MAX_PQ_TREE_IDS_PER_BLOCK)) {
            throw std::ios_base::failure("too many PQ child-tree ids");
        });
        SER_READ(obj, obj.tree_ids.resize(tree_id_count));
        for (auto& tree_id : obj.tree_ids) READWRITE(tree_id);
        uint16_t block_tree_id_count{
            static_cast<uint16_t>(obj.block_tree_ids.size())};
        SER_WRITE(obj, if (obj.block_tree_ids.size() >
                           MAX_PQ_TREE_IDS_PER_BLOCK) {
            throw std::ios_base::failure(
                "too many block PQ child-tree ids");
        });
        READWRITE(block_tree_id_count);
        SER_READ(obj, obj.block_tree_ids.resize(block_tree_id_count));
        for (auto& tree_id : obj.block_tree_ids) READWRITE(tree_id);
        READWRITE(obj.consensus_state_root);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ registry disk snapshot");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQRegistryDiskSnapshot&,
                           const PQRegistryDiskSnapshot&) = default;
};

enum class PQRegistryResult : uint8_t {
    OK = 0,
    INVALID_CONFIGURATION,
    INVALID_BLOCK,
    PQ_TX_BEFORE_PREPARATION,
    MISSING_PARENT_SNAPSHOT,
    INVALID_SCHEDULE,
    CALLBACK_MISSING,
    CALLBACK_FAILED,
    PARENT_DMN_MISMATCH,
    DMN_MISSING_AT_PARENT,
    DMN_REMOVED_IN_BLOCK,
    DUPLICATE_OPERATOR_UPDATE,
    DUPLICATE_GLOBAL_KEY,
    DUPLICATE_CHILD_TREE_ID,
    INVALID_GLOBAL_KEY_PAYLOAD,
    INVALID_PROVIDER_REVOCATION_PAYLOAD,
    TRANSACTION_INPUTS_HASH_MISMATCH,
    OWNER_AUTHORIZATION_FAILED,
    OPERATOR_STATE_TRANSITION_FAILED,
    INVALID_RESULTING_STATE,
    SNAPSHOT_NOT_FOUND,
    SNAPSHOT_CORRUPT,
    SNAPSHOT_CONFLICT,
    PERSISTENCE_FAILED,
    UNDO_MISMATCH,
    INTERNAL_ERROR,
};

struct PQRegistryError {
    PQRegistryResult result{PQRegistryResult::OK};
    std::size_t transaction_index{
        std::numeric_limits<std::size_t>::max()};
    uint256 pro_tx_hash;
    OperatorKeyStateResult state_result{OperatorKeyStateResult::OK};

    void Clear() noexcept;
    friend bool operator==(const PQRegistryError&,
                           const PQRegistryError&) = default;
};

[[nodiscard]] std::string_view PQRegistryResultString(
    PQRegistryResult result) noexcept;

struct PQRegistryCallbacks {
    std::function<bool(const uint256&)> dmn_exists_before;
    std::function<bool(const uint256&)> dmn_exists_after;
    std::function<bool(const GlobalKeyTxPayload&,
                       const uint256& owner_authorization_hash)>
        verify_initial_owner_authorization;

    [[nodiscard]] bool HasMembershipCallbacks() const noexcept;
};

/**
 * Bounded registry state needed to reserve mempool capacity. The complete
 * append-only tree-id set can contain one million entries, so admission only
 * copies its size and the current commitment for explicitly requested
 * operators.
 */
struct PQRegistryMempoolOperatorState {
    uint256 pro_tx_hash;
    uint8_t state_exists{0};
    uint8_t has_global_key{0};
    ChildKeyTreeCommitment current_commitment;

    friend bool operator==(const PQRegistryMempoolOperatorState&,
                           const PQRegistryMempoolOperatorState&) = default;
};

struct PQRegistryMempoolView {
    uint8_t has_next_block_schedule{0};
    uint32_t next_first_mutable_epoch{0};
    std::size_t operator_state_count{0};
    std::size_t used_tree_id_count{0};
    /** One entry per requested proTxHash, in the same strictly sorted order. */
    std::vector<PQRegistryMempoolOperatorState> operators;

    [[nodiscard]] const PQRegistryMempoolOperatorState* FindOperator(
        const uint256& pro_tx_hash) const noexcept;
};

struct PQRegistrySnapshotView;

/**
 * Immutable ownership handle for one exact branch-local registry snapshot.
 * Hot readers retain the backing state and perform indexed lookups without
 * materializing the disk/RPC transfer object.
 */
class PQRegistryReadView {
public:
    PQRegistryReadView() = default;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] int32_t Height() const noexcept;
    [[nodiscard]] uint256 BlockHash() const noexcept;
    [[nodiscard]] uint256 PreviousBlockHash() const noexcept;
    [[nodiscard]] uint256 ConsensusStateRoot() const noexcept;
    [[nodiscard]] std::size_t OperatorCount() const noexcept;
    [[nodiscard]] std::size_t UsedTreeIdCount() const noexcept;
    [[nodiscard]] bool HasUsedTreeId(const uint256& tree_id) const noexcept;
    [[nodiscard]] const OperatorKeyState* FindOperator(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] std::optional<uint256> FindRetainedGlobalKeyOwner(
        const GlobalPublicKey& public_key) const noexcept;
    [[nodiscard]] std::optional<uint256> FindActiveOperatorByGlobalKey(
        const GlobalPublicKey& public_key) const noexcept;
    [[nodiscard]] std::span<const OperatorKeyState> Operators() const noexcept;
    [[nodiscard]] std::shared_ptr<const std::vector<OperatorKeyState>>
    ShareOperatorStates() const noexcept;
    [[nodiscard]] bool SharesStateWith(
        const PQRegistryReadView& other) const noexcept;
    [[nodiscard]] bool SharesTreeHistoryWith(
        const PQRegistryReadView& other) const noexcept;

private:
    explicit PQRegistryReadView(
        std::shared_ptr<const PQRegistrySnapshotView> snapshot);

    std::shared_ptr<const PQRegistrySnapshotView> m_snapshot;

    friend class PQRegistryManager;
};

class PQRegistryManager {
private:
    using CacheList = std::list<std::pair<
        uint256, std::shared_ptr<const PQRegistrySnapshotView>>>;
    using CacheMap = std::unordered_map<
        uint256, CacheList::iterator, StaticSaltedHasher>;
    using PaymentEligibilityCacheKey = std::pair<uint256, uint32_t>;
    using PaymentEligibilityCacheList = std::list<std::pair<
        PaymentEligibilityCacheKey, PQPaymentEligibleProTxHashesPtr>>;
    using PaymentEligibilityCacheMap = std::map<
        PaymentEligibilityCacheKey, PaymentEligibilityCacheList::iterator>;

    const uint256 m_genesis_hash;
    const PQRegistryConfig m_config;
    mutable Mutex m_mutex;
    std::unique_ptr<CEvoDB<uint256, PQRegistryDiskSnapshot,
                           StaticSaltedHasher>> m_snapshot_db;
    mutable CacheList m_snapshot_cache GUARDED_BY(m_mutex);
    mutable CacheMap m_snapshot_cache_index GUARDED_BY(m_mutex);
    mutable PaymentEligibilityCacheList m_payment_eligibility_cache
        GUARDED_BY(m_mutex);
    mutable PaymentEligibilityCacheMap m_payment_eligibility_cache_index
        GUARDED_BY(m_mutex);

    [[nodiscard]] bool ReadDiskSnapshot(
        const uint256& block_hash,
        PQRegistryDiskSnapshot& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ReconstructPersistentSnapshotView(
        const uint256& block_hash,
        int32_t expected_height,
        std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ReconstructPersistentSnapshot(
        const uint256& block_hash,
        int32_t expected_height,
        PQRegistrySnapshot& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CacheSnapshot(
        const PQRegistrySnapshot& snapshot,
        std::shared_ptr<const PQRegistrySnapshotView>* cached = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CommitSnapshot(
        const PQRegistrySnapshot& snapshot,
        const PQRegistrySnapshot& parent,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ProcessBlockInternal(
        const CBlock& block,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        std::span<const uint256> net_removed_pro_tx_hashes,
        bool fJustCheck,
        bool check_sigs,
        PQRegistryError& error,
        uint256* resulting_state_root)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

public:
    PQRegistryManager(const DBParams& db_params,
                      const uint256& genesis_hash,
                      const PQRegistryConfig& config);

    [[nodiscard]] const PQRegistryConfig& GetConfig() const noexcept
    {
        return m_config;
    }
    [[nodiscard]] bool IsEnabled() const noexcept;

    [[nodiscard]] bool ProcessBlock(
        const CBlock& block,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        std::span<const uint256> net_removed_pro_tx_hashes,
        bool fJustCheck,
        PQRegistryError& error,
        uint256* resulting_state_root = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool ValidateTransaction(
        const CTransaction& transaction,
        const uint256& parent_block_hash,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        bool check_sigs,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool GetSnapshot(
        const uint256& block_hash,
        const uint256& previous_block_hash,
        int32_t height,
        PQRegistrySnapshot& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool GetReadView(
        const uint256& block_hash,
        const uint256& previous_block_hash,
        int32_t height,
        PQRegistryReadView& view,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Return a shared, branch-exact frozen-root eligibility view. Identical
     * registry roots reuse the derived set across ordinary blocks, while the
     * epoch key forces one rebuild when the payment schedule advances.
     */
    [[nodiscard]] bool GetPaymentEligibleProTxHashes(
        const uint256& block_hash,
        const uint256& previous_block_hash,
        int32_t height,
        uint32_t epoch,
        PQPaymentEligibleProTxHashesPtr& eligible,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool GetMempoolView(
        const uint256& block_hash,
        int32_t height,
        std::span<const uint256> requested_operators,
        PQRegistryMempoolView& view,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool UndoBlock(
        const uint256& block_hash,
        int32_t height,
        PQRegistrySnapshot& parent_snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool Flush(bool fSync = true)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool PruneSnapshot(
        const uint256& block_hash,
        bool fSync = false) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] CEvoDB<uint256, PQRegistryDiskSnapshot,
                         StaticSaltedHasher>& SnapshotDatabase()
    {
        return *m_snapshot_db;
    }
};

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_REGISTRY_H
