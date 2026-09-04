// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_REGISTRY_H
#define SYSCOIN_EVO_PQ_REGISTRY_H

#include <evo/auxiliary_history_gc.h>
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

namespace test {
class PQRegistryManagerTestAccess;
}

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
inline constexpr std::size_t PQ_REGISTRY_GC_MAX_SCANNED_VALUE_BYTES{
    16U * 1024U * 1024U};
/** Exact maximum serialized size of one fully populated operator state. */
inline constexpr std::size_t PQ_OPERATOR_KEY_STATE_MAX_SERIALIZED_SIZE{
    (sizeof(uint16_t) + uint256::size() + 2 * sizeof(uint8_t) +
     sizeof(uint32_t)) +
    (2 * sizeof(uint16_t) + sizeof(uint32_t) + GLOBAL_PUBLIC_KEY_SIZE +
     ChildKeyTreeCommitment::WIRE_SIZE + sizeof(uint32_t)) +
    sizeof(uint8_t) + (sizeof(uint8_t) + 4 * sizeof(uint32_t)) +
    sizeof(uint16_t) +
    MAX_RETAINED_FROZEN_CHILD_ROOTS *
        (uint256::size() + 2 * sizeof(uint32_t) +
         ChildKeyTreeCommitment::WIRE_SIZE)};
static_assert(PQ_OPERATOR_KEY_STATE_MAX_SERIALIZED_SIZE == 4'024);
/** Active reservations plus one standard package, without an unbounded copy. */
inline constexpr std::size_t MAX_PQ_MEMPOOL_OPERATOR_REQUESTS{
    MAX_PQ_OPERATOR_STATES + 64};

struct PQRegistryConfig {
    int32_t preparation_height{-1};
    ChainLockScheduleConfig schedule;
    uint32_t registration_cutoff_blocks{0};
    uint32_t future_horizon_epochs{0};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const PQRegistryConfig&,
                           const PQRegistryConfig&) = default;
};

/**
 * Caller-provided active-chain identities for one bounded authenticated
 * checkpoint interval. The registry independently exact-reads and validates
 * every named record; database predecessor links never select a trusted
 * branch.
 */
struct PQRegistryGCAuthenticationContext {
    static constexpr std::size_t MAX_PATH_RECORDS{
        PQ_REGISTRY_CHECKPOINT_INTERVAL + 1};

    std::vector<evo::AuxiliaryHistoryGCBlockIdentity> rooted_segment;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQRegistryGCAuthenticationContext&,
                           const PQRegistryGCAuthenticationContext&) =
        default;
};

enum class PQRegistryDeploymentResult : uint8_t {
    DISABLED = 0,
    VALID,
    INVALID_CONFIGURATION,
};

[[nodiscard]] PQRegistryDeploymentResult GetPQRegistryConfig(
    const Consensus::Params& params,
    PQRegistryConfig& config) noexcept;

/** Exact, branch-local operator state. */
struct PQRegistrySnapshot {
    uint16_t version{PQ_REGISTRY_SNAPSHOT_VERSION};
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    std::vector<OperatorKeyState> operator_states;
    uint256 consensus_state_root;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsEmpty() const noexcept;
    [[nodiscard]] const OperatorKeyState* FindOperator(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] std::optional<uint256> RecomputeConsensusStateRoot(
        const uint256& genesis_hash) const;
    friend bool operator==(const PQRegistrySnapshot&,
                           const PQRegistrySnapshot&) = default;
};

/**
 * One sparse branch journal record. Every record retains its exact operator
 * delta. Checkpoints additionally retain the full resulting set so replay can
 * authenticate the sparse transition before accepting the checkpoint as a
 * reconstruction base.
 */
struct PQRegistryDiskSnapshot {
    /** Exact decoder envelope implied by every fixed-width collection cap. */
    static constexpr std::size_t MAX_SERIALIZED_SIZE{
        (sizeof(uint16_t) + sizeof(uint8_t) + sizeof(int32_t) +
         3 * uint256::size()) +
        sizeof(uint16_t) +
        MAX_PQ_OPERATOR_STATES *
            PQ_OPERATOR_KEY_STATE_MAX_SERIALIZED_SIZE +
        sizeof(uint16_t) + MAX_PQ_OPERATOR_STATES * uint256::size() +
        sizeof(uint16_t) +
        MAX_PQ_OPERATOR_STATES *
            PQ_OPERATOR_KEY_STATE_MAX_SERIALIZED_SIZE + uint256::size()};
    static_assert(MAX_SERIALIZED_SIZE == 529'522'941);

    uint16_t version{PQ_REGISTRY_DISK_VERSION};
    uint8_t is_checkpoint{0};
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    uint256 previous_consensus_state_root;
    /** Operators added or changed by this exact block. */
    std::vector<OperatorKeyState> operator_states;
    /** Operators removed by this exact block. */
    std::vector<uint256> removed_operators;
    /** Full resulting operator set at checkpoints; empty otherwise. */
    std::vector<OperatorKeyState> checkpoint_operator_states;
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

        uint16_t checkpoint_operator_count{
            static_cast<uint16_t>(obj.checkpoint_operator_states.size())};
        SER_WRITE(obj, if (obj.checkpoint_operator_states.size() >
                           MAX_PQ_OPERATOR_STATES) {
            throw std::ios_base::failure(
                "too many checkpoint PQ operator states");
        });
        READWRITE(checkpoint_operator_count);
        SER_READ(obj, obj.checkpoint_operator_states.resize(
                          checkpoint_operator_count));
        for (auto& state : obj.checkpoint_operator_states) READWRITE(state);

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
    INVALID_GLOBAL_KEY_PAYLOAD,
    INVALID_PROVIDER_REVOCATION_PAYLOAD,
    TRANSACTION_INPUTS_HASH_MISMATCH,
    OWNER_AUTHORIZATION_FAILED,
    OPERATOR_STATE_TRANSITION_FAILED,
    INVALID_RESULTING_STATE,
    SNAPSHOT_NOT_FOUND,
    SNAPSHOT_CORRUPT,
    SNAPSHOT_CONFLICT,
    HISTORY_PRUNED,
    FLOOR_CONFLICT,
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

/** Whether a registry preparation result reflects local auxiliary state. */
[[nodiscard]] bool IsPQRegistryLocalFailure(
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
 * Bounded registry state needed to reserve mempool capacity.
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
    /** One entry per requested proTxHash, in the same strictly sorted order. */
    std::vector<PQRegistryMempoolOperatorState> operators;

    [[nodiscard]] const PQRegistryMempoolOperatorState* FindOperator(
        const uint256& pro_tx_hash) const noexcept;
};

struct PQRegistrySnapshotView;
struct PQRegistryMemoryTracker;
class PQRegistryManager;

/** Process-local immutable registry payload retained by the cache and readers. */
struct PQRegistryMemoryStats {
    std::size_t cache_owned_bytes{0};
    std::size_t externally_pinned_state_bytes{0};
    std::size_t live_registry_views{0};
};

/**
 * Immutable ownership handle for one exact branch-local registry snapshot.
 * Hot readers retain the backing state and perform indexed lookups without
 * materializing the disk/RPC transfer object.
 */
class PQRegistryReadView {
public:
    PQRegistryReadView() = default;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] int32_t Height() const noexcept;
    [[nodiscard]] uint256 BlockHash() const noexcept;
    [[nodiscard]] uint256 PreviousBlockHash() const noexcept;
    [[nodiscard]] uint256 ConsensusStateRoot() const noexcept;
    [[nodiscard]] std::optional<uint256> RecomputeConsensusStateRoot(
        const uint256& genesis_hash) const;
    [[nodiscard]] std::size_t OperatorCount() const noexcept;
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

private:
    explicit PQRegistryReadView(
        std::shared_ptr<const PQRegistrySnapshotView> snapshot);

    std::shared_ptr<const PQRegistrySnapshotView> m_snapshot;

    friend class PQRegistryManager;
};

/**
 * Move-only result of complete, signature-checked block preparation. A failed
 * commit may be retried, but one token must never be committed concurrently.
 */
class PQRegistryPreparedBlock {
public:
    PQRegistryPreparedBlock() = default;
    PQRegistryPreparedBlock(const PQRegistryPreparedBlock&) = delete;
    PQRegistryPreparedBlock& operator=(const PQRegistryPreparedBlock&) =
        delete;
    PQRegistryPreparedBlock(PQRegistryPreparedBlock&& other) noexcept;
    PQRegistryPreparedBlock& operator=(
        PQRegistryPreparedBlock&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept
    {
        return m_incarnation != nullptr && m_kind != Kind::INVALID &&
               !m_consensus_state_root.IsNull();
    }

    [[nodiscard]] uint256 ConsensusStateRoot() const noexcept
    {
        return IsValid() ? m_consensus_state_root : uint256{};
    }

private:
    enum class Kind : uint8_t {
        INVALID = 0,
        NO_COMMIT,
        TRANSITION,
    };

    std::shared_ptr<const uint8_t> m_incarnation;
    Kind m_kind{Kind::INVALID};
    uint256 m_block_hash;
    uint256 m_consensus_state_root;
    int32_t m_height{-1};
    uint64_t m_gc_floor_revision{0};
    std::shared_ptr<const PQRegistrySnapshotView> m_parent;
    std::shared_ptr<const PQRegistrySnapshotView> m_result;
    std::optional<PQRegistryDiskSnapshot> m_disk;

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
    /** Generic journal deployment binding; null disables destructive GC. */
    const uint256 m_gc_configuration_id;
    const std::shared_ptr<const uint8_t> m_incarnation{
        std::make_shared<const uint8_t>(0)};
    const std::shared_ptr<PQRegistryMemoryTracker> m_memory_tracker;
    mutable Mutex m_mutex;
    std::unique_ptr<CEvoDB<uint256, PQRegistryDiskSnapshot,
                           StaticSaltedHasher>> m_snapshot_db;
    mutable CacheList m_snapshot_cache GUARDED_BY(m_mutex);
    mutable CacheMap m_snapshot_cache_index GUARDED_BY(m_mutex);
    mutable PaymentEligibilityCacheList m_payment_eligibility_cache
        GUARDED_BY(m_mutex);
    mutable PaymentEligibilityCacheMap m_payment_eligibility_cache_index
        GUARDED_BY(m_mutex);
    std::optional<evo::AuxiliaryHistoryGCComponent> m_gc_floor_component
        GUARDED_BY(m_mutex);
    std::optional<evo::PQRegistryGCClosure> m_gc_floor
        GUARDED_BY(m_mutex);
    uint64_t m_gc_floor_revision GUARDED_BY(m_mutex){0};
    // SYSCOIN: Cursor-only GC publications leave the logical access boundary
    // unchanged, but they still invalidate a pass prepared against the prior
    // durable component.
    uint64_t m_gc_floor_state_revision GUARDED_BY(m_mutex){0};
    // SYSCOIN: This process-local generation is a freshness witness for a
    // fully authenticated destructive pass. The durable journal, not this
    // counter, remains the restart authority.
    uint64_t m_snapshot_content_revision GUARDED_BY(m_mutex){0};
    // Diagnostic counters prove that bounded replay caching changes work,
    // never the authenticated result or any production cache decision.
    mutable uint64_t m_reconstruction_authenticated_records
        GUARDED_BY(m_mutex){0};
    mutable uint64_t m_reconstruction_reused_records
        GUARDED_BY(m_mutex){0};
    mutable uint64_t m_reconstruction_state_hashes
        GUARDED_BY(m_mutex){0};
    mutable uint64_t m_gc_context_authentications
        GUARDED_BY(m_mutex){0};

    struct GCAuthenticationResult {
        evo::AuxiliaryHistoryGCBlockIdentity checkpoint;
        uint256 checkpoint_state_root;
        uint256 checkpoint_record_hash;
        uint256 lineage_base_commitment;
        uint256 rooted_lineage_commitment;
        std::vector<evo::AuxiliaryHistoryGCBlockIdentity>
            protected_records;
    };

    struct ValidatedGCPass {
        enum class Phase : uint8_t {
            PREPARED = 0,
            INSTALLED,
        };

        Phase phase{Phase::PREPARED};
        uint64_t content_revision{0};
        uint64_t floor_state_revision{0};
        std::optional<evo::AuxiliaryHistoryGCComponent> previous;
        evo::AuxiliaryHistoryGCComponent target;
        evo::PQRegistryGCEraseManifest manifest;
        PQRegistryGCAuthenticationContext context;
        GCAuthenticationResult authenticated;
        std::optional<evo::AuxiliaryHistoryGCWatermark> bound_watermark;
        std::optional<evo::AuxiliaryHistoryGCIntent> bound_intent;
        std::size_t first_present_candidate{0};
    };
    std::optional<ValidatedGCPass> m_validated_gc_pass
        GUARDED_BY(m_mutex);

    [[nodiscard]] bool ReadDiskSnapshot(
        const uint256& block_hash,
        PQRegistryDiskSnapshot& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CheckGCFloorAccess(
        const uint256& block_hash,
        int32_t height,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool AuthenticateGCFloorCheckpoint(
        const evo::PQRegistryGCClosure& closure,
        std::shared_ptr<const PQRegistrySnapshotView>* snapshot,
        PQRegistryError& error,
        bool* missing = nullptr) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool AuthenticateGCContext(
        const PQRegistryGCAuthenticationContext& context,
        const uint256& claimed_lineage_base,
        const evo::PQRegistryGCClosure* previous,
        GCAuthenticationResult& result,
        PQRegistryError& error,
        bool derive_initial_base = false) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool BuildGCFloorClosureLocked(
        uint64_t generation,
        std::optional<uint256> scan_after_key,
        const PQRegistryGCAuthenticationContext& context,
        const evo::PQRegistryGCClosure* previous,
        evo::PQRegistryGCClosure& closure,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool BuildGCFloorClosureFromAuthenticatedLocked(
        uint64_t generation,
        uint8_t scan_state,
        std::optional<uint256> scan_after_key,
        const GCAuthenticationResult& authenticated,
        evo::PQRegistryGCClosure& closure,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool InstallGCFloorFromAuthenticatedLocked(
        const evo::AuxiliaryHistoryGCComponent& component,
        const evo::PQRegistryGCClosure* closure,
        const GCAuthenticationResult& authenticated,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ValidateGCEraseIntervalLocked(
        const evo::PQRegistryGCClosure& target,
        const evo::PQRegistryGCClosure* previous,
        const GCAuthenticationResult& authenticated,
        const evo::PQRegistryGCEraseManifest& manifest,
        std::size_t& first_present_candidate,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool NoteSnapshotContentMutationLocked()
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ReconstructPersistentSnapshotViewAboveFloor(
        const uint256& block_hash,
        int32_t expected_height,
        std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool ReconstructPersistentSnapshotView(
        const uint256& block_hash,
        int32_t expected_height,
        std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CacheSnapshotView(
        std::shared_ptr<const PQRegistrySnapshotView> snapshot,
        std::shared_ptr<const PQRegistrySnapshotView>* cached = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool CommitPreparedSnapshot(
        const std::shared_ptr<const PQRegistrySnapshotView>& snapshot,
        const PQRegistryDiskSnapshot& disk,
        uint64_t floor_revision,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool PrepareBlockInternal(
        const CBlock& block,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        std::span<const uint256> net_removed_pro_tx_hashes,
        PQRegistryPreparedBlock& prepared,
        PQRegistryError& error)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

public:
    PQRegistryManager(const DBParams& db_params,
                      const uint256& genesis_hash,
                      const PQRegistryConfig& config,
                      const uint256& gc_configuration_id = {});

    [[nodiscard]] const PQRegistryConfig& GetConfig() const noexcept
    {
        return m_config;
    }
    [[nodiscard]] bool IsEnabled() const noexcept;
    /** Allocation-payload accounting; allocator and shared_ptr overhead excluded. */
    [[nodiscard]] PQRegistryMemoryStats GetMemoryStats() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Construct the only closure accepted for the supplied exact paths. */
    [[nodiscard]] bool BuildGCFloorClosure(
        uint64_t generation,
        std::optional<uint256> scan_after_key,
        const PQRegistryGCAuthenticationContext& context,
        const evo::PQRegistryGCClosure* previous,
        evo::PQRegistryGCClosure& closure,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Build one deterministic, bounded physical erase pass and the closure
     * that durably advances over it. Generation is derived from the previous
     * component so callers cannot select a journal position independently.
     * Independent record, serialized-value, and candidate budgets bound
     * ordinary aggregate decode work and the number of synchronously erased
     * keys in the resulting intent. One schema-bounded oversized first value
     * is admitted so a valid checkpoint cannot strand the physical cursor.
     */
    [[nodiscard]] bool BuildGCEraseBatch(
        const PQRegistryGCAuthenticationContext& context,
        const std::optional<evo::AuxiliaryHistoryGCComponent>& previous,
        std::size_t max_scanned_records,
        std::size_t max_scanned_value_bytes,
        std::size_t max_candidates,
        evo::AuxiliaryHistoryGCComponent& target,
        evo::PQRegistryGCEraseManifest& manifest,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Synchronously make every registry write visible to a later GC scan. */
    [[nodiscard]] bool FlushForGC(PQRegistryError& error)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Consume the exact authenticated pass retained while installing this
     * fsynced pending journal intent. The pass is burned before any erase I/O;
     * a retry must reconstruct it from the durable intent and physical DB.
     */
    [[nodiscard]] bool EraseInstalledGCIntent(
        const evo::AuxiliaryHistoryGCState& state,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Install the crash-monotonic PQ history floor selected by the shared GC
     * journal. The checkpoint is authenticated from its exact physical record
     * before any cached view can observe a new boundary revision.
     */
    [[nodiscard]] bool InstallGCFloor(
        const evo::AuxiliaryHistoryGCComponent& component,
        const evo::AuxiliaryHistoryGCAuthorization& authorization,
        PQRegistryError& error,
        const PQRegistryGCAuthenticationContext& context = {})
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Validate and publish the effective crash-restored journal floor. A
     * pending target wins over the completed watermark, including when only
     * the deterministic-MN component advanced.
     */
    [[nodiscard]] bool InstallEffectiveGCFloor(
        const evo::AuxiliaryHistoryGCState& state,
        PQRegistryError& error,
        const PQRegistryGCAuthenticationContext& context = {})
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool ProcessBlock(
        const CBlock& block,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        std::span<const uint256> net_removed_pro_tx_hashes,
        bool fJustCheck,
        PQRegistryError& error,
        uint256* resulting_state_root = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool PrepareBlock(
        const CBlock& block,
        int32_t height,
        const PQRegistryCallbacks& callbacks,
        std::span<const uint256> net_removed_pro_tx_hashes,
        PQRegistryPreparedBlock& prepared,
        PQRegistryError& error)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool CommitPreparedBlock(
        PQRegistryPreparedBlock& prepared,
        PQRegistryError& error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

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

    [[nodiscard]] bool PreflightUndoBlock(
        const uint256& block_hash,
        const uint256& expected_parent_block_hash,
        int32_t height,
        PQRegistryError& error) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] bool Flush(bool fSync = true)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Narrow seams used by deterministic-manager failure/fixture tests. */
    void FailNextSnapshotWriteThroughForTesting()
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool WriteExactSnapshotForTesting(
        const uint256& block_hash,
        const PQRegistryDiskSnapshot& snapshot)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    friend class test::PQRegistryManagerTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_REGISTRY_H
