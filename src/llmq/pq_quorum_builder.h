// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
#define SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H

#include <evo/deterministicmns.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_operator_key_state.h>
#include <llmq/pq_roster_beacon.h>
#include <sync.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <memory>
#include <optional>
#include <span>
#include <vector>

class CBlockIndex;

namespace llmq::pq {

/**
 * Fork-pinned inputs needed to reconstruct a roster at one exact branch.
 *
 * The registration cutoff and roster snapshot are deliberately independent.
 * A key must already be frozen when the snapshot is taken, so the cutoff is
 * at least as far before the epoch base as the snapshot.
 */
struct QuorumBuildConfig {
    ChainLockScheduleConfig schedule;
    uint32_t roster_snapshot_lag_blocks{0};
    uint32_t registration_cutoff_blocks{0};
    uint32_t future_horizon_epochs{0};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const QuorumBuildConfig&,
                           const QuorumBuildConfig&) = default;
};

enum class QuorumBuildError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_SCHEDULE,
    INVALID_TARGET_HEIGHT,
    INVALID_MASTERNODE_STATE,
    INSUFFICIENT_ELIGIBLE_MEMBERS,
    INVALID_OPERATOR_STATE,
    DUPLICATE_OPERATOR_STATE,
    OPERATOR_STATE_SNAPSHOT_MISMATCH,
    CHILD_KEY_NOT_FROZEN,
    DUPLICATE_CHILD_KEY,
    MISSING_BRANCH_ANCESTOR,
    SNAPSHOT_LOOKUP_FAILED,
    SNAPSHOT_MISMATCH,
    INVALID_ROSTER_BEACON,
    INVALID_FROZEN_ROSTER,
    RECOVERY_UNIVERSE_LOOKUP_FAILED,
    INVALID_RECOVERY_UNIVERSE,
};

inline constexpr uint16_t RECOVERY_UNIVERSE_CAPSULE_VERSION{1};
inline constexpr std::size_t RECOVERY_UNIVERSE_MAX_MEMBERS{65'535};

/**
 * The immutable identity-and-lineage projection used by recovery scoring.
 * Current key availability is deliberately absent: it is resolved at each
 * recovery group's own cutoff so later groups can regain liveness.
 */
struct RecoveryUniverseMember {
    static constexpr std::size_t DISK_SIZE{2 * uint256::size() +
                                           uint256::size() +
                                           sizeof(uint32_t)};

    uint256 pro_tx_hash;
    uint256 confirmed_hash_with_pro_reg_tx_hash;
    COutPoint collateral_outpoint;

    SERIALIZE_METHODS(RecoveryUniverseMember, obj)
    {
        READWRITE(obj.pro_tx_hash,
                  obj.confirmed_hash_with_pro_reg_tx_hash,
                  obj.collateral_outpoint);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "invalid recovery-universe member");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RecoveryUniverseMember&,
                           const RecoveryUniverseMember&) = default;
};

static_assert(RecoveryUniverseMember::DISK_SIZE == 100);

/**
 * Local-only frozen recovery identity universe. The source and exact branch
 * snapshot are part of the capsule identity; every recovery group re-scores
 * the complete member vector with that group's epoch.
 */
class RecoveryUniverseCapsule final {
public:
    static constexpr std::size_t MAX_SERIALIZED_SIZE{
        sizeof(uint16_t) + uint256::size() +
        RecoveryRosterAuthoritySource::WIRE_SIZE + sizeof(int32_t) +
        uint256::size() + sizeof(uint32_t) +
        RECOVERY_UNIVERSE_MAX_MEMBERS *
            RecoveryUniverseMember::DISK_SIZE +
        3 * uint256::size()};

    static constexpr std::size_t MIN_SERIALIZED_SIZE{
        MAX_SERIALIZED_SIZE -
        (RECOVERY_UNIVERSE_MAX_MEMBERS - QUORUM_SIZE) *
            RecoveryUniverseMember::DISK_SIZE};

    /** Decode only bytes obtained from authenticated local persistence. */
    [[nodiscard]] static std::optional<RecoveryUniverseCapsule>
    DecodeTrustedPersistence(
        Span<const uint8_t> encoded,
        QuorumBuildError* error = nullptr);

    [[nodiscard]] std::vector<uint8_t> Encode() const;
    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_genesis_hash;
    }
    [[nodiscard]] const RecoveryRosterAuthoritySource& Source() const noexcept
    {
        return m_source;
    }
    [[nodiscard]] int32_t SourceSnapshotHeight() const noexcept
    {
        return m_source_snapshot_height;
    }
    [[nodiscard]] const uint256& SourceSnapshotHash() const noexcept
    {
        return m_source_snapshot_hash;
    }
    [[nodiscard]] const uint256& SourceId() const noexcept
    {
        return m_source_id;
    }
    [[nodiscard]] std::span<const RecoveryUniverseMember> Members() const
        noexcept
    {
        return m_members;
    }
    [[nodiscard]] const uint256& MembersHash() const noexcept
    {
        return m_members_hash;
    }
    [[nodiscard]] const uint256& CapsuleId() const noexcept
    {
        return m_capsule_id;
    }
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool Matches(
        const uint256& expected_genesis_hash,
        const RecoveryRosterAuthoritySource& expected_source,
        const CBlockIndex& expected_source_snapshot) const noexcept;
    friend bool operator==(const RecoveryUniverseCapsule& lhs,
                           const RecoveryUniverseCapsule& rhs)
    {
        return lhs.m_version == rhs.m_version &&
               lhs.m_genesis_hash == rhs.m_genesis_hash &&
               lhs.m_source == rhs.m_source &&
               lhs.m_source_snapshot_height == rhs.m_source_snapshot_height &&
               lhs.m_source_snapshot_hash == rhs.m_source_snapshot_hash &&
               lhs.m_source_id == rhs.m_source_id &&
               lhs.m_members == rhs.m_members &&
               lhs.m_members_hash == rhs.m_members_hash &&
               lhs.m_capsule_id == rhs.m_capsule_id;
    }

private:
    RecoveryUniverseCapsule(
        uint256 genesis_hash,
        RecoveryRosterAuthoritySource source,
        int32_t source_snapshot_height,
        uint256 source_snapshot_hash,
        uint256 source_id,
        std::vector<RecoveryUniverseMember> members,
        uint256 members_hash,
        uint256 capsule_id);

    uint16_t m_version{RECOVERY_UNIVERSE_CAPSULE_VERSION};
    uint256 m_genesis_hash;
    RecoveryRosterAuthoritySource m_source;
    int32_t m_source_snapshot_height{-1};
    uint256 m_source_snapshot_hash;
    uint256 m_source_id;
    std::vector<RecoveryUniverseMember> m_members;
    uint256 m_members_hash;
    uint256 m_capsule_id;

    friend class RecoveryUniverseCapsuleFactory;
};

static_assert(RecoveryUniverseCapsule::MAX_SERIALIZED_SIZE == 6'553'782);
static_assert(RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE == 40'282);

using RecoveryUniverseCapsulePtr =
    std::shared_ptr<const RecoveryUniverseCapsule>;
/** Authenticated local-persistence lookup by source ID; never use a peer. */
using RecoveryUniverseLookup = std::function<RecoveryUniverseCapsulePtr(
    const uint256&)>;

[[nodiscard]] uint256 GetRecoveryUniverseSourceId(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source);

[[nodiscard]] uint256 GetRecoveryUniverseMembersHash(
    const uint256& genesis_hash,
    std::span<const RecoveryUniverseMember> members);

[[nodiscard]] uint256 GetRecoveryUniverseCapsuleId(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source,
    int32_t source_snapshot_height,
    const uint256& source_snapshot_hash,
    const uint256& members_hash,
    std::size_t member_count);

/**
 * State looked up at an exact block on the branch supplied by the caller.
 * The deterministic list is structurally shared internally; registry
 * operators retain the exact immutable registry allocation without also
 * pinning its potentially much larger tree-ID history.
 */
struct QuorumSnapshotState {
    CDeterministicMNList deterministic_mns;
    std::shared_ptr<const std::vector<OperatorKeyState>> operator_key_states;
};

using QuorumSnapshotLookup =
    std::function<std::optional<QuorumSnapshotState>(const CBlockIndex&)>;

using AuthorizationBoundaryLookup =
    std::function<bool(int32_t, const uint256&)>;

inline constexpr std::size_t FROZEN_QUORUM_ROSTER_CACHE_CAPACITY{16};

/**
 * Bounded success-only cache for complete branch-pinned active roster sets.
 * Retained verified sets also seed overlapping roster epochs after rotation.
 */
class FrozenQuorumRosterCache final {
public:
    [[nodiscard]] static std::shared_ptr<const FrozenQuorumRosterCache> Create(
        uint256 genesis_hash,
        QuorumBuildConfig config,
        QuorumSnapshotLookup snapshot_lookup,
        bool cache_results = true,
        RecoveryUniverseLookup recovery_universe_lookup = {});

    [[nodiscard]] FrozenQuorumRostersPtr GetActive(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActive(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Cache hits may be reused, but a miss is not published before auth. */
    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActiveNoPublish(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        QuorumBuildError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Always invoke the source; independent reconstruction must not self-hit. */
    [[nodiscard]] std::optional<QuorumSnapshotState> LookupSnapshot(
        const CBlockIndex& index) const;

    /**
     * Evaluate a newly authenticated normal recovery source against its exact
     * branch snapshot. False is an objective lack of 400 unique frozen roots;
     * nullopt denotes unavailable or inconsistent local source state.
     */
    [[nodiscard]] std::optional<bool> EvaluateNormalRecoverySource(
        const RecoveryRosterAuthoritySource& source,
        const CBlockIndex& branch_tip,
        QuorumBuildError* error = nullptr) const;

    /**
     * Return a matching trusted persisted capsule, or capture it from the
     * exact raw snapshot when persistence does not have it yet.
     */
    [[nodiscard]] RecoveryUniverseCapsulePtr GetOrCaptureRecoveryUniverse(
        const RecoveryRosterAuthoritySource& source,
        const CBlockIndex& branch_tip,
        QuorumBuildError* error = nullptr) const;

    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_genesis_hash;
    }
    [[nodiscard]] const QuorumBuildConfig& Config() const noexcept
    {
        return m_config;
    }

private:
    struct Key {
        uint32_t newest_epoch{0};
        uint256 branch_context_hash;
        uint256 beacon_bundle_hash;

        friend bool operator==(const Key&, const Key&) = default;
    };

    struct Entry {
        Key key;
        VerifiedRosterSetPtr roster_set;
        bool recently_used{false};
    };

    FrozenQuorumRosterCache(uint256 genesis_hash,
                            QuorumBuildConfig config,
                            QuorumSnapshotLookup snapshot_lookup,
                            bool cache_results,
                            RecoveryUniverseLookup recovery_universe_lookup);

    [[nodiscard]] VerifiedRosterSetPtr GetVerifiedActiveImpl(
        int32_t target_height,
        const CBlockIndex& branch_tip,
        const ActiveRosterBeaconBundle& beacon_bundle,
        bool publish,
        QuorumBuildError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    const uint256 m_genesis_hash;
    const QuorumBuildConfig m_config;
    const QuorumSnapshotLookup m_snapshot_lookup;
    const bool m_cache_results;
    const RecoveryUniverseLookup m_recovery_universe_lookup;
    // A verified set may seed unchecked roster reuse only for the immutable
    // builder configuration and snapshot source that created it.
    const VerifiedRosterSet::BuildProvenancePtr m_build_provenance;

    mutable Mutex m_mutex;
    mutable std::array<Entry, FROZEN_QUORUM_ROSTER_CACHE_CAPACITY>
        m_entries GUARDED_BY(m_mutex);
    mutable std::size_t m_clock_hand GUARDED_BY(m_mutex){0};

    friend class VerifiedRosterSet;
};

using FrozenQuorumRosterCachePtr =
    std::shared_ptr<const FrozenQuorumRosterCache>;

/**
 * Build one canonical 400-slot roster from an exact deterministic-MN snapshot.
 * The base height is derived from the fixed schedule, not accepted from a
 * caller. Payment state never enters validator selection. Every selected
 * member must have an exact frozen child root for the roster epoch; dormant
 * legacy records and payment probation do not fill or reorder PQ roster slots.
 * Candidates are ordered by the epoch score derived from the exact NORMAL
 * READY delayed-Bitcoin seed. The branch base hash remains descriptor identity
 * only and never enters that score.
 */
[[nodiscard]] std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const RosterBeaconSeed& beacon_seed,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error = nullptr);

/**
 * Build the four oldest-to-newest active rosters on one explicit branch from
 * the exact corresponding READY beacon bundle. Recovery rosters select their
 * identities from the authenticated pre-F source, freeze keys at the shared
 * cutoff before the oldest recovery epoch, and use target state only to
 * disable those fixed entries. A newly revealed source that is not active yet
 * is accepted only after its exact snapshot can build a complete normal
 * 400-root roster. Every lookup is an ancestor of branch_tip and its returned
 * height, hash, and registry schedule revision are checked.
 */
[[nodiscard]] FrozenQuorumRostersPtr
BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr);

/** Create a source capsule only after the exact normal source is usable. */
[[nodiscard]] RecoveryUniverseCapsulePtr BuildRecoveryUniverseCapsule(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& branch_tip,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr);

/**
 * Derive the oldest-to-newest authorization prefix at one exact finality
 * boundary. Bootstrap rosters use their base; later rotations use their
 * snapshot. Callers reject masks with fewer than three authorized slots.
 */
[[nodiscard]] uint8_t GetSigningRosterAuthorizationMask(
    const FrozenQuorumRosters& rosters,
    const AuthorizationBoundaryLookup& is_boundary_ancestor);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_QUORUM_BUILDER_H
