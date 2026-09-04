// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmq::pq {

class RecoveryUniverseCapsuleFactory final {
public:
    [[nodiscard]] static RecoveryUniverseCapsulePtr Create(
        uint256 genesis_hash,
        RecoveryRosterAuthoritySource source,
        int32_t source_snapshot_height,
        uint256 source_snapshot_hash,
        uint256 source_id,
        std::vector<RecoveryUniverseMember> members,
        uint256 members_hash,
        uint256 capsule_id)
    {
        auto capsule{std::shared_ptr<const RecoveryUniverseCapsule>{
            new RecoveryUniverseCapsule{
                std::move(genesis_hash), std::move(source),
                source_snapshot_height, std::move(source_snapshot_hash),
                std::move(source_id), std::move(members),
                std::move(members_hash),
                std::move(capsule_id)}}};
        return capsule->IsStructurallyValid() ? capsule : nullptr;
    }
};

namespace {

inline constexpr std::string_view RECOVERY_ROSTER_MODIFIER_DOMAIN{
    "SYS_PQ_RECOVERY_ROSTER_MODIFIER_V1"};
inline constexpr std::string_view RECOVERY_UNIVERSE_MEMBERS_DOMAIN{
    "SYS_PQ_RECOVERY_UNIVERSE_MEMBERS_V1"};
inline constexpr std::string_view RECOVERY_UNIVERSE_SOURCE_ID_DOMAIN{
    "SYS_PQ_RECOVERY_UNIVERSE_SOURCE_ID_V1"};
inline constexpr std::string_view RECOVERY_UNIVERSE_CAPSULE_DOMAIN{
    "SYS_PQ_RECOVERY_UNIVERSE_CAPSULE_V1"};

struct ScoredMember {
    arith_uint256 score;
    CDeterministicMNCPtr dmn;
    std::optional<FrozenChildRootRecord> child_root;
};

struct ScoredRecoveryUniverseMember {
    arith_uint256 score;
    const RecoveryUniverseMember* member{nullptr};
};

enum class CandidateDisposition : uint8_t {
    EXCLUDE,
    INCLUDE,
    INVALID,
};

struct CandidateKeyResolution {
    CandidateDisposition disposition{CandidateDisposition::INVALID};
    std::optional<FrozenChildRootRecord> child_root;
};

/**
 * Registry snapshots are already strictly ordered. Preserve insertion-order
 * independence for synthetic callers without rebuilding a tree map on the
 * production path: only non-registry input pays for the pointer sort.
 */
struct OperatorStateLookup {
    std::span<const OperatorKeyState> states;
    std::vector<const OperatorKeyState*> reordered;

    [[nodiscard]] const OperatorKeyState* Find(
        const uint256& pro_tx_hash) const noexcept
    {
        if (reordered.empty()) {
            const auto position{std::lower_bound(
                states.begin(), states.end(), pro_tx_hash,
                [](const OperatorKeyState& state, const uint256& hash) {
                    return state.pro_tx_hash < hash;
                })};
            return position != states.end() &&
                    position->pro_tx_hash == pro_tx_hash
                ? &*position
                : nullptr;
        }
        const auto position{std::lower_bound(
            reordered.begin(), reordered.end(), pro_tx_hash,
            [](const OperatorKeyState* state, const uint256& hash) {
                return state->pro_tx_hash < hash;
            })};
        return position != reordered.end() &&
                (*position)->pro_tx_hash == pro_tx_hash
            ? *position
            : nullptr;
    }
};

void SetError(QuorumBuildError* error, QuorumBuildError value)
{
    if (error != nullptr) *error = value;
}

std::optional<uint256> GetRecoveryRosterModifier(
    const uint256& genesis_hash,
    const uint256& entropy_commitment,
    uint32_t recovery_epoch,
    int32_t snapshot_height,
    const uint256& snapshot_hash)
{
    if (genesis_hash.IsNull() || entropy_commitment.IsNull() ||
        snapshot_height < 0 || snapshot_hash.IsNull()) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_ROSTER_MODIFIER_DOMAIN);
    writer << genesis_hash << entropy_commitment << recovery_epoch
           << snapshot_height << snapshot_hash;
    return writer.GetHash();
}

bool PrepareOperatorStateLookup(
    std::span<const OperatorKeyState> operator_key_states,
    OperatorStateLookup& lookup,
    QuorumBuildError* error)
{
    bool strictly_ordered{true};
    const OperatorKeyState* previous_state{nullptr};
    for (const auto& state : operator_key_states) {
        if (!state.IsStructurallyValid() || state.schedule_initialized == 0) {
            SetError(error, QuorumBuildError::INVALID_OPERATOR_STATE);
            return false;
        }
        if (previous_state != nullptr &&
            !(previous_state->pro_tx_hash < state.pro_tx_hash)) {
            strictly_ordered = false;
        }
        previous_state = &state;
    }
    if (strictly_ordered) return true;

    lookup.reordered.reserve(operator_key_states.size());
    for (const auto& state : operator_key_states) {
        lookup.reordered.push_back(&state);
    }
    std::sort(lookup.reordered.begin(), lookup.reordered.end(),
              [](const OperatorKeyState* lhs,
                 const OperatorKeyState* rhs) {
                  return lhs->pro_tx_hash < rhs->pro_tx_hash;
              });
    if (std::adjacent_find(
            lookup.reordered.begin(), lookup.reordered.end(),
            [](const OperatorKeyState* lhs,
               const OperatorKeyState* rhs) {
                return lhs->pro_tx_hash == rhs->pro_tx_hash;
            }) != lookup.reordered.end()) {
        SetError(error, QuorumBuildError::DUPLICATE_OPERATOR_STATE);
        return false;
    }
    return true;
}

template <typename ResolveCandidate>
std::optional<std::vector<ScoredMember>> SelectRosterMembers(
    const CDeterministicMNList& snapshot,
    const uint256& modifier,
    const OperatorStateLookup& operator_states,
    ResolveCandidate&& resolve_candidate,
    QuorumBuildError* error)
{
    std::vector<ScoredMember> candidates;
    candidates.reserve(snapshot.GetAllMNsCount());
    bool invalid_masternode_state{false};
    bool invalid_child_state{false};
    snapshot.ForEachMNShared(false, [&](const CDeterministicMNCPtr& dmn) {
        if (!dmn || !dmn->pdmnState || dmn->proTxHash.IsNull() ||
            dmn->collateralOutpoint.IsNull()) {
            invalid_masternode_state = true;
            return;
        }
        if (!CDeterministicMNList::IsMNValid(*dmn) ||
            dmn->pdmnState->confirmedHash.IsNull()) {
            return;
        }
        auto resolution{resolve_candidate(
            operator_states.Find(dmn->proTxHash), dmn->proTxHash)};
        if (resolution.disposition == CandidateDisposition::EXCLUDE) {
            return;
        }
        if (resolution.disposition != CandidateDisposition::INCLUDE) {
            invalid_child_state = true;
            return;
        }

        // Preserve the deployed deterministic score: the first SHA256 is the
        // cached confirmedHashWithProRegTxHash, followed by one SHA256 with the
        // new domain-separated modifier. This is not double-SHA256.
        uint256 score_hash;
        CSHA256 hasher;
        hasher.Write(dmn->pdmnState->confirmedHashWithProRegTxHash.begin(),
                     dmn->pdmnState->confirmedHashWithProRegTxHash.size());
        hasher.Write(modifier.begin(), modifier.size());
        hasher.Finalize(score_hash.begin());
        candidates.push_back(
            {UintToArith256(score_hash), dmn,
             std::move(resolution.child_root)});
    });
    if (invalid_masternode_state) {
        SetError(error, QuorumBuildError::INVALID_MASTERNODE_STATE);
        return std::nullopt;
    }
    if (invalid_child_state) {
        SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
        return std::nullopt;
    }
    if (candidates.size() < QUORUM_SIZE) {
        SetError(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
        return std::nullopt;
    }

    const auto score_less = [](const ScoredMember& lhs,
                               const ScoredMember& rhs) {
        if (lhs.score != rhs.score) return lhs.score > rhs.score;
        // This is the direct form of the legacy reverse-iterator tie break,
        // which places the larger outpoint first. Deterministic-MN lists
        // enforce unique collateral outpoints, so valid candidates form a
        // total order even when their scores are equal.
        return rhs.dmn->collateralOutpoint < lhs.dmn->collateralOutpoint;
    };

    std::partial_sort(candidates.begin(),
                      candidates.begin() + QUORUM_SIZE,
                      candidates.end(), score_less);
    candidates.resize(QUORUM_SIZE);
    return candidates;
}

std::optional<std::vector<ScoredRecoveryUniverseMember>>
SelectRecoveryUniverseMembers(
    const RecoveryUniverseCapsule& universe,
    const uint256& modifier,
    QuorumBuildError* error)
{
    if (modifier.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
        return std::nullopt;
    }
    std::vector<ScoredRecoveryUniverseMember> candidates;
    candidates.reserve(universe.Members().size());
    for (const auto& member : universe.Members()) {
        uint256 score_hash;
        CSHA256 hasher;
        hasher.Write(member.confirmed_hash_with_pro_reg_tx_hash.begin(),
                     member.confirmed_hash_with_pro_reg_tx_hash.size());
        hasher.Write(modifier.begin(), modifier.size());
        hasher.Finalize(score_hash.begin());
        candidates.push_back({UintToArith256(score_hash), &member});
    }
    if (candidates.size() < QUORUM_SIZE) {
        SetError(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
        return std::nullopt;
    }
    const auto score_less = [](const ScoredRecoveryUniverseMember& lhs,
                               const ScoredRecoveryUniverseMember& rhs) {
        if (lhs.score != rhs.score) return lhs.score > rhs.score;
        return rhs.member->collateral_outpoint <
               lhs.member->collateral_outpoint;
    };
    std::partial_sort(candidates.begin(),
                      candidates.begin() + QUORUM_SIZE,
                      candidates.end(), score_less);
    candidates.resize(QUORUM_SIZE);
    return candidates;
}

CandidateKeyResolution ResolveNormalCandidate(
    const OperatorKeyState* state,
    const uint256& pro_tx_hash,
    uint32_t epoch)
{
    if (state == nullptr || !state->HasActiveGlobalKey()) {
        return {CandidateDisposition::EXCLUDE, std::nullopt};
    }
    const ChildRootResolution resolution{state->ResolveChildRoot(epoch)};
    if (resolution.status == ChildRootResolutionStatus::FROZEN_ABSENT) {
        return {CandidateDisposition::EXCLUDE, std::nullopt};
    }
    if (resolution.status != ChildRootResolutionStatus::FROZEN_PRESENT ||
        !resolution.record ||
        resolution.record->pro_tx_hash != pro_tx_hash ||
        resolution.record->epoch != epoch) {
        return {CandidateDisposition::INVALID, std::nullopt};
    }
    return {CandidateDisposition::INCLUDE, resolution.record};
}

std::optional<std::vector<ScoredMember>> SelectNormalRosterMembers(
    const CDeterministicMNList& snapshot,
    const uint256& modifier,
    const OperatorStateLookup& operator_states,
    uint32_t epoch,
    QuorumBuildError* error)
{
    return SelectRosterMembers(
        snapshot, modifier, operator_states,
        [epoch](const OperatorKeyState* state, const uint256& pro_tx_hash) {
            return ResolveNormalCandidate(state, pro_tx_hash, epoch);
        },
        error);
}

bool HasUniqueSelectedChildRoots(
    std::span<const ScoredMember> selected,
    QuorumBuildError* error)
{
    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    for (const auto& candidate : selected) {
        if (!candidate.child_root ||
            !tree_owners.emplace(
                candidate.child_root->commitment.tree_id,
                std::pair{candidate.dmn->proTxHash,
                          candidate.child_root->commitment.generation})
                 .second) {
            SetError(error, candidate.child_root
                                ? QuorumBuildError::DUPLICATE_CHILD_KEY
                                : QuorumBuildError::CHILD_KEY_NOT_FROZEN);
            return false;
        }
    }
    return true;
}

bool AddActiveChildRootsToSet(const FrozenQuorumRoster& roster,
                              std::map<uint256,
                                       std::pair<uint256, uint32_t>>& tree_owners)
{
    for (const auto& member : roster.members) {
        if (!member.child_root) continue;
        const auto [it, inserted]{tree_owners.emplace(
            member.child_root->commitment.tree_id,
            std::pair{member.pro_tx_hash,
                      member.child_root->commitment.generation})};
        if (!inserted &&
            it->second != std::pair{member.pro_tx_hash,
                                    member.child_root->commitment.generation}) {
            return false;
        }
    }
    return true;
}

bool HasPresentChildRoot(const ChildRootResolution& resolution) noexcept
{
    return (resolution.status ==
                ChildRootResolutionStatus::FROZEN_PRESENT ||
            resolution.status ==
                ChildRootResolutionStatus::MUTABLE_PRESENT) &&
           resolution.record.has_value();
}

} // namespace

uint256 GetRecoveryUniverseSourceId(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source)
{
    if (genesis_hash.IsNull() || source.IsNull() ||
        !source.IsStructurallyValid()) {
        return {};
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_UNIVERSE_SOURCE_ID_DOMAIN);
    writer << genesis_hash << source;
    return writer.GetHash();
}

uint256 GetRecoveryUniverseMembersHash(
    const uint256& genesis_hash,
    std::span<const RecoveryUniverseMember> members)
{
    if (genesis_hash.IsNull() ||
        members.size() > RECOVERY_UNIVERSE_MAX_MEMBERS) {
        return {};
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_UNIVERSE_MEMBERS_DOMAIN);
    writer << genesis_hash << static_cast<uint32_t>(members.size());
    for (const auto& member : members) writer << member;
    return writer.GetHash();
}

uint256 GetRecoveryUniverseCapsuleId(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source,
    int32_t source_snapshot_height,
    const uint256& source_snapshot_hash,
    const uint256& members_hash,
    std::size_t member_count)
{
    if (genesis_hash.IsNull() || source.IsNull() ||
        !source.IsStructurallyValid() || source_snapshot_height < 0 ||
        source_snapshot_hash.IsNull() || members_hash.IsNull() ||
        member_count < QUORUM_SIZE ||
        member_count > RECOVERY_UNIVERSE_MAX_MEMBERS) {
        return {};
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_UNIVERSE_CAPSULE_DOMAIN);
    writer << genesis_hash << RECOVERY_UNIVERSE_CAPSULE_VERSION
           << GetRecoveryUniverseSourceId(genesis_hash, source)
           << source_snapshot_height << source_snapshot_hash
           << static_cast<uint32_t>(member_count) << members_hash;
    return writer.GetHash();
}

bool RecoveryUniverseMember::IsStructurallyValid() const noexcept
{
    // Raw roster scoring requires a confirmed DMN but hashes the cached
    // lineage value verbatim. Do not silently narrow that accepted set here.
    return !pro_tx_hash.IsNull() && !collateral_outpoint.IsNull();
}

RecoveryUniverseCapsule::RecoveryUniverseCapsule(
    uint256 genesis_hash,
    RecoveryRosterAuthoritySource source,
    int32_t source_snapshot_height,
    uint256 source_snapshot_hash,
    uint256 source_id,
    std::vector<RecoveryUniverseMember> members,
    uint256 members_hash,
    uint256 capsule_id)
    : m_genesis_hash{std::move(genesis_hash)},
      m_source{std::move(source)},
      m_source_snapshot_height{source_snapshot_height},
      m_source_snapshot_hash{std::move(source_snapshot_hash)},
      m_source_id{std::move(source_id)},
      m_members{std::move(members)},
      m_members_hash{std::move(members_hash)},
      m_capsule_id{std::move(capsule_id)}
{
}

std::vector<uint8_t> RecoveryUniverseCapsule::Encode() const
{
    if (!IsStructurallyValid()) {
        throw std::logic_error("invalid recovery-universe capsule");
    }
    DataStream stream{SER_DISK};
    stream.reserve(sizeof(uint16_t) + uint256::size() +
                   RecoveryRosterAuthoritySource::WIRE_SIZE +
                   sizeof(int32_t) + uint256::size() + sizeof(uint32_t) +
                   m_members.size() * RecoveryUniverseMember::DISK_SIZE +
                   3 * uint256::size());
    stream << m_version << m_genesis_hash << m_source
           << m_source_snapshot_height << m_source_snapshot_hash << m_source_id
           << static_cast<uint32_t>(m_members.size());
    for (const auto& member : m_members) stream << member;
    stream << m_members_hash << m_capsule_id;
    if (stream.size() < MIN_SERIALIZED_SIZE ||
        stream.size() > MAX_SERIALIZED_SIZE) {
        throw std::logic_error("recovery-universe capsule size invariant");
    }
    return {UCharCast(stream.data()),
            UCharCast(stream.data() + stream.size())};
}

std::optional<RecoveryUniverseCapsule>
RecoveryUniverseCapsule::DecodeTrustedPersistence(
    Span<const uint8_t> encoded,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (encoded.size() < MIN_SERIALIZED_SIZE ||
        encoded.size() > MAX_SERIALIZED_SIZE) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
        return std::nullopt;
    }

    uint16_t version{0};
    uint256 genesis_hash;
    RecoveryRosterAuthoritySource source;
    int32_t source_snapshot_height{-1};
    uint256 source_snapshot_hash;
    uint256 source_id;
    std::vector<RecoveryUniverseMember> members;
    uint256 members_hash;
    uint256 capsule_id;
    try {
        SpanReader reader{SER_DISK, 0, encoded};
        reader >> version >> genesis_hash >> source
               >> source_snapshot_height >> source_snapshot_hash >> source_id;
        if (version != RECOVERY_UNIVERSE_CAPSULE_VERSION ||
            genesis_hash.IsNull() || source.IsNull() ||
            !source.IsStructurallyValid() || source_snapshot_height < 0 ||
            source_snapshot_hash.IsNull() ||
            source_id != GetRecoveryUniverseSourceId(
                genesis_hash, source)) {
            SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
            return std::nullopt;
        }
        uint32_t member_count{0};
        reader >> member_count;
        if (member_count < QUORUM_SIZE ||
            member_count > RECOVERY_UNIVERSE_MAX_MEMBERS) {
            SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
            return std::nullopt;
        }
        members.reserve(member_count);
        for (uint32_t index{0}; index < member_count; ++index) {
            RecoveryUniverseMember member;
            reader >> member;
            members.push_back(std::move(member));
        }
        reader >> members_hash >> capsule_id;
        if (!reader.empty()) {
            SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
            return std::nullopt;
        }
    } catch (const std::ios_base::failure&) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
        return std::nullopt;
    }

    RecoveryUniverseCapsule capsule{
        std::move(genesis_hash), std::move(source),
        source_snapshot_height, std::move(source_snapshot_hash),
        std::move(source_id), std::move(members),
        std::move(members_hash),
        std::move(capsule_id)};
    capsule.m_version = version;
    if (!capsule.IsStructurallyValid()) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
        return std::nullopt;
    }
    return capsule;
}

bool RecoveryUniverseCapsule::IsStructurallyValid() const noexcept
{
    if (m_version != RECOVERY_UNIVERSE_CAPSULE_VERSION ||
        m_genesis_hash.IsNull() || m_source.IsNull() ||
        !m_source.IsStructurallyValid() || m_source_snapshot_height < 0 ||
        m_source_snapshot_hash.IsNull() || m_members.size() < QUORUM_SIZE ||
        m_members.size() > RECOVERY_UNIVERSE_MAX_MEMBERS) {
        return false;
    }
    std::set<COutPoint> collateral_outpoints;
    const RecoveryUniverseMember* previous{nullptr};
    for (const auto& member : m_members) {
        if (!member.IsStructurallyValid() ||
            (previous != nullptr &&
             !(previous->pro_tx_hash < member.pro_tx_hash)) ||
            !collateral_outpoints.insert(member.collateral_outpoint).second) {
            return false;
        }
        previous = &member;
    }
    const uint256 expected_members_hash{GetRecoveryUniverseMembersHash(
        m_genesis_hash, m_members)};
    return !expected_members_hash.IsNull() &&
           m_source_id == GetRecoveryUniverseSourceId(
               m_genesis_hash, m_source) &&
           m_members_hash == expected_members_hash &&
           m_capsule_id == GetRecoveryUniverseCapsuleId(
               m_genesis_hash, m_source, m_source_snapshot_height,
               m_source_snapshot_hash, m_members_hash, m_members.size());
}

bool RecoveryUniverseCapsule::Matches(
    const uint256& expected_genesis_hash,
    const RecoveryRosterAuthoritySource& expected_source,
    const CBlockIndex& expected_source_snapshot) const noexcept
{
    return m_genesis_hash == expected_genesis_hash &&
           m_source == expected_source &&
           m_source_snapshot_height == expected_source_snapshot.nHeight &&
           m_source_snapshot_hash == expected_source_snapshot.GetBlockHash();
}

bool QuorumBuildConfig::IsValid() const noexcept
{
    // The snapshot must not be newer than the earliest target's signing
    // boundary, and keeping it within its epoch leaves at most one
    // branch-derived roster after a finalized predecessor. Together these
    // preserve threshold intersection across sibling targets.
    if (!schedule.IsValid() || roster_snapshot_lag_blocks == 0 ||
        roster_snapshot_lag_blocks < schedule.sign_lag ||
        roster_snapshot_lag_blocks > schedule.epoch_blocks ||
        registration_cutoff_blocks < roster_snapshot_lag_blocks ||
        future_horizon_epochs < ACTIVE_QUORUMS ||
        future_horizon_epochs > MAX_OPERATOR_SCHEDULE_EPOCHS) {
        return false;
    }
    const auto epoch_zero_snapshot = RegistrationCutoffHeight(
        schedule, 0, roster_snapshot_lag_blocks);
    const auto epoch_zero_cutoff = RegistrationCutoffHeight(
        schedule, 0, registration_cutoff_blocks);
    return epoch_zero_snapshot && epoch_zero_cutoff &&
           *epoch_zero_cutoff <= *epoch_zero_snapshot;
}

namespace {

std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRosterWithModifier(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const uint256& modifier,
    const uint256& beacon_hash,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || base_hash.IsNull() || modifier.IsNull() ||
        beacon_hash.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!config.IsValid()) {
        SetError(error, QuorumBuildError::INVALID_SCHEDULE);
        return nullptr;
    }
    const auto base_height{EpochBaseHeight(config.schedule, epoch)};
    if (!base_height || snapshot.IsNull() ||
        snapshot.GetHeight() >= *base_height || snapshot.GetBlockHash().IsNull()) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    OperatorStateLookup operator_states{operator_key_states, {}};
    if (!PrepareOperatorStateLookup(
            operator_key_states, operator_states, error)) return nullptr;

    const auto expected_snapshot_height = RegistrationCutoffHeight(
        config.schedule, epoch, config.roster_snapshot_lag_blocks);
    if (!expected_snapshot_height || snapshot.GetHeight() != *expected_snapshot_height) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const auto schedule_view = DeriveOperatorKeyScheduleView(
        config.schedule, snapshot.GetHeight(),
        config.registration_cutoff_blocks, config.future_horizon_epochs);
    if (!schedule_view) {
        SetError(error, QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
        return nullptr;
    }
    for (const auto& state : operator_key_states) {
        if (!state.IsAdvancedTo(*schedule_view)) {
            SetError(error,
                     QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
            return nullptr;
        }
    }

    auto selected{SelectNormalRosterMembers(
        snapshot, modifier, operator_states, epoch, error)};
    if (!selected || !HasUniqueSelectedChildRoots(*selected, error)) {
        return nullptr;
    }

    auto roster{std::make_unique<FrozenQuorumRoster>()};
    roster->descriptor.epoch = epoch;
    roster->descriptor.base_height = *base_height;
    roster->descriptor.base_hash = base_hash;
    roster->descriptor.snapshot_height = snapshot.GetHeight();
    roster->descriptor.snapshot_hash = snapshot.GetBlockHash();
    roster->descriptor.roster_beacon_hash = beacon_hash;

    std::set<uint256> selected_members;
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        auto& member = roster->members[slot];
        member.pro_tx_hash = (*selected)[slot].dmn->proTxHash;
        if (member.pro_tx_hash.IsNull() ||
            !selected_members.insert(member.pro_tx_hash).second) {
            SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
            return nullptr;
        }
        member.eligible = true;
        member.child_root = std::move((*selected)[slot].child_root);
        SetQuorumMember(roster->descriptor.valid_members, slot);
    }

    roster->descriptor.valid_count =
        static_cast<uint16_t>(CountSet(roster->descriptor.valid_members));
    roster->descriptor.member_root =
        ComputeQuorumMemberRoot(genesis_hash, *roster);
    roster->descriptor.child_key_root =
        ComputeQuorumChildKeyRoot(genesis_hash, *roster);
    if (roster->descriptor.member_root.IsNull() ||
        roster->descriptor.child_key_root.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }
    return roster;
}

} // namespace

std::unique_ptr<FrozenQuorumRoster> BuildFrozenQuorumRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const RosterBeaconSeed& beacon_seed,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error)
{
    if (!beacon_seed.IsReady() ||
        beacon_seed.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    if (snapshot.IsNull() || snapshot.GetBlockHash().IsNull()) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const auto modifier{GetPQQuorumModifier(
        genesis_hash, epoch, snapshot.GetHeight(), snapshot.GetBlockHash(),
        beacon_seed)};
    const auto beacon_hash{
        GetRosterBeaconCommitmentHash(genesis_hash, beacon_seed)};
    if (!modifier || !beacon_hash) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    return BuildFrozenQuorumRosterWithModifier(
        genesis_hash, config, epoch, base_hash, *modifier, *beacon_hash,
        snapshot, operator_key_states, error);
}

namespace {

// An exact base hash commits the branch through its snapshot. Matching both
// descriptor identities and the seed commitment lets rotations reuse already
// verified bytes without trusting a roster built for another fork, cutoff, or
// delayed-Bitcoin observation.
const FrozenQuorumRoster* FindReusableRoster(
    const uint256& genesis_hash,
    const EpochIdentity& identity,
    const CBlockIndex& base_index,
    const CBlockIndex& snapshot_index,
    const uint256& beacon_hash,
    std::span<const VerifiedRosterSetPtr> reusable_sets)
{
    for (const auto& roster_set : reusable_sets) {
        if (!roster_set || roster_set->GenesisHash() != genesis_hash) continue;
        for (const auto& roster : roster_set->Rosters()) {
            const auto& descriptor{roster.descriptor};
            if (descriptor.epoch == identity.epoch &&
                descriptor.base_height == identity.base_height &&
                descriptor.base_hash == base_index.GetBlockHash() &&
                descriptor.snapshot_height == snapshot_index.nHeight &&
                descriptor.snapshot_hash == snapshot_index.GetBlockHash() &&
                descriptor.roster_beacon_hash == beacon_hash) {
                return &roster;
            }
        }
    }
    return nullptr;
}

std::optional<QuorumSnapshotState> LookupSnapshotExact(
    const CBlockIndex& index,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    std::optional<QuorumSnapshotState> state;
    try {
        state = snapshot_lookup(index);
    } catch (...) {
        SetError(error, QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
        return std::nullopt;
    }
    if (!state) {
        SetError(error, QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
        return std::nullopt;
    }
    if (state->deterministic_mns.IsNull() ||
        state->deterministic_mns.GetHeight() != index.nHeight ||
        state->deterministic_mns.GetBlockHash() != index.GetBlockHash() ||
        !state->operator_key_states) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return std::nullopt;
    }
    return state;
}

bool PrepareSnapshotOperatorLookup(
    const QuorumBuildConfig& config,
    const QuorumSnapshotState& state,
    OperatorStateLookup& lookup,
    QuorumBuildError* error)
{
    lookup.states = std::span<const OperatorKeyState>{
        state.operator_key_states->data(),
        state.operator_key_states->size()};
    if (!PrepareOperatorStateLookup(lookup.states, lookup, error)) {
        return false;
    }
    const auto schedule_view{DeriveOperatorKeyScheduleView(
        config.schedule, state.deterministic_mns.GetHeight(),
        config.registration_cutoff_blocks, config.future_horizon_epochs)};
    if (!schedule_view ||
        std::any_of(
            lookup.states.begin(), lookup.states.end(),
            [&](const OperatorKeyState& operator_state) {
                return !operator_state.IsAdvancedTo(*schedule_view);
            })) {
        SetError(error,
                 QuorumBuildError::OPERATOR_STATE_SNAPSHOT_MISMATCH);
        return false;
    }
    return true;
}

const CBlockIndex* ResolveRecoverySourceSnapshot(
    const QuorumBuildConfig& config,
    const CBlockIndex& target_index,
    const RecoveryRosterAuthoritySource& source,
    QuorumBuildError* error)
{
    if (!source.IsStructurallyValid() || source.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    const auto& normal_beacon{source.normal_beacon};
    const auto snapshot_height{RegistrationCutoffHeight(
        config.schedule, normal_beacon.epoch,
        config.roster_snapshot_lag_blocks)};
    if (!snapshot_height ||
        *snapshot_height >= normal_beacon.anchor_cursor.sys_height ||
        normal_beacon.anchor_cursor.sys_height > target_index.nHeight) {
        SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
        return nullptr;
    }
    const CBlockIndex* anchor_index{target_index.GetAncestor(
        normal_beacon.anchor_cursor.sys_height)};
    if (anchor_index == nullptr ||
        anchor_index->GetBlockHash() != normal_beacon.anchor_cursor.sys_hash) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const CBlockIndex* snapshot_index{
        anchor_index->GetAncestor(*snapshot_height)};
    if (snapshot_index == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    return snapshot_index;
}

bool HasUsableNormalRecoverySource(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& source_snapshot_index,
    const QuorumSnapshotState& source_state,
    const OperatorStateLookup& source_operator_states,
    QuorumBuildError* error)
{
    const auto modifier{GetPQQuorumModifier(
        genesis_hash, source.normal_beacon.epoch,
        source_snapshot_index.nHeight,
        source_snapshot_index.GetBlockHash(), source.normal_beacon)};
    if (!modifier) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return false;
    }
    const auto selected{SelectNormalRosterMembers(
        source_state.deterministic_mns, *modifier,
        source_operator_states, source.normal_beacon.epoch, error)};
    return selected && HasUniqueSelectedChildRoots(*selected, error);
}

RecoveryUniverseCapsulePtr BuildRecoveryUniverseCapsuleFromPrepared(
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& source_snapshot_index,
    const QuorumSnapshotState& source_state,
    const OperatorStateLookup& source_operator_states,
    QuorumBuildError* error)
{
    std::vector<RecoveryUniverseMember> members;
    members.reserve(std::min<std::size_t>(
        source_state.deterministic_mns.GetAllMNsCount(),
        RECOVERY_UNIVERSE_MAX_MEMBERS));

    bool invalid_masternode_state{false};
    bool over_capacity{false};
    source_state.deterministic_mns.ForEachMNShared(
        false, [&](const CDeterministicMNCPtr& dmn) {
            if (!dmn || !dmn->pdmnState || dmn->proTxHash.IsNull() ||
                dmn->collateralOutpoint.IsNull()) {
                invalid_masternode_state = true;
                return;
            }
            if (!CDeterministicMNList::IsMNValid(*dmn) ||
                dmn->pdmnState->confirmedHash.IsNull()) {
                return;
            }
            const auto* operator_state{
                source_operator_states.Find(dmn->proTxHash)};
            if (operator_state == nullptr ||
                operator_state->has_global_key == 0) {
                return;
            }
            if (members.size() ==
                RECOVERY_UNIVERSE_MAX_MEMBERS) {
                over_capacity = true;
                return;
            }
            members.push_back(RecoveryUniverseMember{
                dmn->proTxHash,
                dmn->pdmnState->confirmedHashWithProRegTxHash,
                dmn->collateralOutpoint});
        });
    if (invalid_masternode_state) {
        SetError(error, QuorumBuildError::INVALID_MASTERNODE_STATE);
        return nullptr;
    }
    if (over_capacity) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
        return nullptr;
    }
    if (members.size() < QUORUM_SIZE) {
        SetError(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
        return nullptr;
    }
    std::sort(members.begin(), members.end(),
              [](const RecoveryUniverseMember& lhs,
                 const RecoveryUniverseMember& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    const uint256 members_hash{GetRecoveryUniverseMembersHash(
        genesis_hash, members)};
    const uint256 source_id{GetRecoveryUniverseSourceId(
        genesis_hash, source)};
    const uint256 capsule_id{GetRecoveryUniverseCapsuleId(
        genesis_hash, source, source_snapshot_index.nHeight,
        source_snapshot_index.GetBlockHash(), members_hash,
        members.size())};
    auto capsule{RecoveryUniverseCapsuleFactory::Create(
        genesis_hash, source, source_snapshot_index.nHeight,
        source_snapshot_index.GetBlockHash(), source_id, std::move(members),
        members_hash, capsule_id)};
    if (!capsule) {
        SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
    }
    return capsule;
}

std::unique_ptr<FrozenQuorumRoster> BuildRecoveryFrozenQuorumRoster(
    const uint256& genesis_hash,
    const EpochIdentity& identity,
    const CBlockIndex& base_index,
    const CBlockIndex& source_snapshot_index,
    const RosterBeaconSeed& normal_source,
    const RosterBeaconSeed& recovery_seed,
    const RecoveryUniverseCapsule* recovery_universe,
    const QuorumSnapshotState* source_state,
    const OperatorStateLookup* source_operator_states,
    const QuorumSnapshotState& key_state,
    const OperatorStateLookup& key_operator_states,
    const QuorumSnapshotState& signing_boundary_state,
    const OperatorStateLookup& signing_boundary_operator_states,
    QuorumBuildError* error)
{
    const auto beacon_hash{
        GetRosterBeaconCommitmentHash(genesis_hash, recovery_seed)};
    const auto entropy_commitment{
        GetRecoveryRosterEntropyCommitment(genesis_hash, normal_source)};
    auto expected_recovery_seed{normal_source};
    expected_recovery_seed.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    expected_recovery_seed.epoch = identity.epoch;
    if (!beacon_hash ||
        !entropy_commitment ||
        !normal_source.IsReady() ||
        normal_source.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
        recovery_seed != expected_recovery_seed ||
        source_snapshot_index.nHeight >= base_index.nHeight ||
        key_state.deterministic_mns.GetHeight() >= base_index.nHeight) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }

    const auto modifier{GetRecoveryRosterModifier(
        genesis_hash, *entropy_commitment,
        identity.epoch, source_snapshot_index.nHeight,
        source_snapshot_index.GetBlockHash())};
    if (!modifier) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    std::vector<uint256> selected_pro_tx_hashes;
    selected_pro_tx_hashes.reserve(QUORUM_SIZE);
    if (recovery_universe != nullptr) {
        const RecoveryRosterAuthoritySource expected_source{normal_source};
        if (source_state != nullptr || source_operator_states != nullptr ||
            recovery_universe->GenesisHash() != genesis_hash ||
            recovery_universe->Source() != expected_source ||
            recovery_universe->SourceSnapshotHeight() !=
                source_snapshot_index.nHeight ||
            recovery_universe->SourceSnapshotHash() !=
                source_snapshot_index.GetBlockHash()) {
            SetError(error, QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
            return nullptr;
        }
        const auto selected{SelectRecoveryUniverseMembers(
            *recovery_universe, *modifier, error)};
        if (!selected) return nullptr;
        for (const auto& candidate : *selected) {
            selected_pro_tx_hashes.push_back(candidate.member->pro_tx_hash);
        }
    } else {
        if (source_state == nullptr || source_operator_states == nullptr) {
            SetError(error, QuorumBuildError::INVALID_ARGUMENT);
            return nullptr;
        }
        const auto selected{SelectRosterMembers(
            source_state->deterministic_mns, *modifier,
            *source_operator_states,
            [](const OperatorKeyState* state, const uint256&) {
                return CandidateKeyResolution{
                    state != nullptr && state->has_global_key != 0
                        ? CandidateDisposition::INCLUDE
                        : CandidateDisposition::EXCLUDE,
                    std::nullopt};
            },
            error)};
        if (!selected) return nullptr;
        for (const auto& candidate : *selected) {
            selected_pro_tx_hashes.push_back(candidate.dmn->proTxHash);
        }
    }

    auto roster{std::make_unique<FrozenQuorumRoster>()};
    auto& descriptor{roster->descriptor};
    descriptor.epoch = identity.epoch;
    descriptor.base_height = identity.base_height;
    descriptor.base_hash = base_index.GetBlockHash();
    descriptor.snapshot_height = source_snapshot_index.nHeight;
    descriptor.snapshot_hash = source_snapshot_index.GetBlockHash();
    descriptor.roster_beacon_hash = *beacon_hash;

    for (std::size_t member_index{0};
         member_index < QUORUM_SIZE; ++member_index) {
        const uint256& pro_tx_hash{selected_pro_tx_hashes[member_index]};
        auto& member{roster->members[member_index]};
        member.pro_tx_hash = pro_tx_hash;

        const auto* key_operator_state{key_operator_states.Find(pro_tx_hash)};
        const auto key_child_root{key_operator_state != nullptr
            ? key_operator_state->ResolveChildRoot(identity.epoch)
            : ChildRootResolution{}};
        if (!HasPresentChildRoot(key_child_root) ||
            key_child_root.record->pro_tx_hash != pro_tx_hash ||
            key_child_root.record->epoch != identity.epoch) {
            continue;
        }

        member.child_root = *key_child_root.record;
        const auto boundary_dmn{
            signing_boundary_state.deterministic_mns.GetMN(pro_tx_hash)};
        const auto* boundary_operator_state{
            signing_boundary_operator_states.Find(pro_tx_hash)};
        const auto boundary_child_root{boundary_operator_state != nullptr
            ? boundary_operator_state->ResolveChildRoot(identity.epoch)
            : ChildRootResolution{}};
        if (!boundary_dmn ||
            !CDeterministicMNList::IsMNValid(*boundary_dmn) ||
            !HasPresentChildRoot(boundary_child_root) ||
            *boundary_child_root.record != *key_child_root.record) {
            continue;
        }
        member.eligible = true;
        SetQuorumMember(descriptor.valid_members, member_index);
    }

    descriptor.valid_count = static_cast<uint16_t>(
        CountSet(descriptor.valid_members));
    descriptor.member_root = ComputeQuorumMemberRoot(genesis_hash, *roster);
    descriptor.child_key_root =
        ComputeQuorumChildKeyRoot(genesis_hash, *roster);
    if (descriptor.member_root.IsNull() ||
        descriptor.child_key_root.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }
    return roster;
}

std::unique_ptr<FrozenQuorumRosters> BuildActiveFrozenQuorumRostersImpl(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    const RecoveryUniverseLookup& recovery_universe_lookup,
    std::span<const VerifiedRosterSetPtr> reusable_sets,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || !snapshot_lookup) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!config.IsValid()) {
        SetError(error, QuorumBuildError::INVALID_SCHEDULE);
        return nullptr;
    }
    if (!IsEligibleChainLockTarget(config.schedule, target_height)) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    if (branch_tip.nHeight < target_height) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const CBlockIndex* target_index{branch_tip.GetAncestor(target_height)};
    if (target_index == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const auto active_epochs{ActiveEpochsAtHeight(config.schedule, target_height)};
    if (!active_epochs) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    if (!beacon_bundle.IsForNewestEpoch(active_epochs->back().epoch)) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    const bool has_recovery_seed{std::any_of(
        beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    if (beacon_bundle.recovery_authority_source.IsNull()) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }

    const bool source_is_active_normal_seed{std::any_of(
        beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
        [&](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::NORMAL &&
                   seed == beacon_bundle.recovery_authority_source.normal_beacon;
        })};
    const bool prevalidate_source{
        has_recovery_seed || !source_is_active_normal_seed};
    const CBlockIndex* recovery_source_snapshot{nullptr};
    RecoveryUniverseCapsulePtr recovery_universe;
    std::optional<QuorumSnapshotState> recovery_source_state;
    OperatorStateLookup recovery_source_operator_states{{}, {}};
    if (prevalidate_source) {
        recovery_source_snapshot = ResolveRecoverySourceSnapshot(
            config, *target_index,
            beacon_bundle.recovery_authority_source, error);
        if (recovery_source_snapshot == nullptr) return nullptr;
        if (recovery_universe_lookup) {
            try {
                recovery_universe = recovery_universe_lookup(
                    GetRecoveryUniverseSourceId(
                        genesis_hash,
                        beacon_bundle.recovery_authority_source));
            } catch (...) {
                SetError(error,
                         QuorumBuildError::RECOVERY_UNIVERSE_LOOKUP_FAILED);
                return nullptr;
            }
            if (recovery_universe &&
                !recovery_universe->Matches(
                    genesis_hash,
                    beacon_bundle.recovery_authority_source,
                    *recovery_source_snapshot)) {
                SetError(error,
                         QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
                return nullptr;
            }
        }
        if (!recovery_universe) {
            recovery_source_state = LookupSnapshotExact(
                *recovery_source_snapshot, snapshot_lookup, error);
            if (!recovery_source_state ||
                !PrepareSnapshotOperatorLookup(
                    config, *recovery_source_state,
                    recovery_source_operator_states, error) ||
                !HasUsableNormalRecoverySource(
                    genesis_hash, beacon_bundle.recovery_authority_source,
                    *recovery_source_snapshot, *recovery_source_state,
                    recovery_source_operator_states, error)) {
                return nullptr;
            }
        }
    }

    std::optional<QuorumSnapshotState> recovery_key_state;
    std::optional<QuorumSnapshotState> signing_boundary_state;
    OperatorStateLookup recovery_key_operator_states{{}, {}};
    OperatorStateLookup signing_boundary_operator_states{{}, {}};
    if (has_recovery_seed) {
        const auto recovery_seed{std::find_if(
            beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
            [](const RosterBeaconSeed& seed) {
                return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
            })};
        const uint32_t recovery_first_epoch{
            recovery_seed->epoch -
            recovery_seed->epoch % static_cast<uint32_t>(ACTIVE_QUORUMS)};
        if (std::any_of(
                recovery_seed, beacon_bundle.seeds.end(),
                [recovery_first_epoch](const RosterBeaconSeed& seed) {
                    return seed.anchor_kind ==
                               RosterBeaconAnchorKind::RECOVERY &&
                           seed.epoch - seed.epoch %
                               static_cast<uint32_t>(ACTIVE_QUORUMS) !=
                               recovery_first_epoch;
                })) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
        const auto recovery_first_base{EpochBaseHeight(
            config.schedule, recovery_first_epoch)};
        const auto recovery_key_cutoff{RegistrationCutoffHeight(
            config.schedule, recovery_first_epoch,
            config.registration_cutoff_blocks)};
        if (!recovery_first_base || !recovery_key_cutoff ||
            *recovery_key_cutoff < recovery_source_snapshot->nHeight ||
            *recovery_key_cutoff >= *recovery_first_base) {
            SetError(error, QuorumBuildError::SNAPSHOT_MISMATCH);
            return nullptr;
        }
        const CBlockIndex* recovery_key_snapshot{
            target_index->GetAncestor(*recovery_key_cutoff)};
        if (recovery_key_snapshot == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        recovery_key_state = LookupSnapshotExact(
            *recovery_key_snapshot, snapshot_lookup, error);
        const int32_t signing_boundary_height{
            target_height - static_cast<int32_t>(config.schedule.sign_lag)};
        const CBlockIndex* signing_boundary_index{
            target_index->GetAncestor(signing_boundary_height)};
        if (signing_boundary_index == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        signing_boundary_state = LookupSnapshotExact(
            *signing_boundary_index, snapshot_lookup, error);
        if (!recovery_key_state || !signing_boundary_state ||
            !PrepareSnapshotOperatorLookup(
                config, *recovery_key_state,
                recovery_key_operator_states, error) ||
            !PrepareSnapshotOperatorLookup(
                config, *signing_boundary_state,
                signing_boundary_operator_states, error)) {
            return nullptr;
        }
    }

    auto rosters{std::make_unique<FrozenQuorumRosters>()};
    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& identity{(*active_epochs)[slot]};
        const CBlockIndex* base_index{
            target_index->GetAncestor(identity.base_height)};
        if (base_index == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        const auto& beacon_seed{beacon_bundle.seeds[slot]};
        if (beacon_seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY) {
            auto roster{BuildRecoveryFrozenQuorumRoster(
                genesis_hash, identity, *base_index,
                *recovery_source_snapshot,
                beacon_bundle.recovery_authority_source.normal_beacon,
                beacon_seed, recovery_universe.get(),
                recovery_source_state ? &*recovery_source_state : nullptr,
                recovery_source_state
                    ? &recovery_source_operator_states
                    : nullptr,
                *recovery_key_state, recovery_key_operator_states,
                *signing_boundary_state,
                signing_boundary_operator_states, error)};
            if (!roster) return nullptr;
            if (!AddActiveChildRootsToSet(*roster, tree_owners)) {
                SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
                return nullptr;
            }
            (*rosters)[slot] = std::move(*roster);
            continue;
        }
        if (beacon_seed.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
        const auto snapshot_height{
            RegistrationCutoffHeight(config.schedule, identity.epoch,
                                     config.roster_snapshot_lag_blocks)};
        if (!snapshot_height ||
            *snapshot_height >= identity.base_height) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        const CBlockIndex* snapshot_index{base_index->GetAncestor(*snapshot_height)};
        if (snapshot_index == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        const auto beacon_hash{GetRosterBeaconCommitmentHash(
            genesis_hash, beacon_bundle.seeds[slot])};
        if (!beacon_hash) {
            SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
            return nullptr;
        }
        const FrozenQuorumRoster* reusable{FindReusableRoster(
            genesis_hash, identity, *base_index, *snapshot_index,
            *beacon_hash, reusable_sets)};
        if (reusable != nullptr) {
            if (!AddActiveChildRootsToSet(*reusable, tree_owners)) {
                SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
                return nullptr;
            }
            (*rosters)[slot] = *reusable;
            continue;
        }
        auto snapshot_state{
            LookupSnapshotExact(*snapshot_index, snapshot_lookup, error)};
        if (!snapshot_state) return nullptr;
        auto roster{BuildFrozenQuorumRoster(
            genesis_hash, config, identity.epoch, base_index->GetBlockHash(),
            beacon_seed,
            snapshot_state->deterministic_mns,
            std::span<const OperatorKeyState>{
                snapshot_state->operator_key_states->data(),
                snapshot_state->operator_key_states->size()},
            error)};
        if (!roster) return nullptr;
        if (!AddActiveChildRootsToSet(*roster, tree_owners)) {
            SetError(error, QuorumBuildError::DUPLICATE_CHILD_KEY);
            return nullptr;
        }
        (*rosters)[slot] = std::move(*roster);
    }
    const bool complete_recovery_window{
        beacon_bundle.seeds.back().epoch % ACTIVE_QUORUMS ==
            ACTIVE_QUORUMS - 1 &&
        std::all_of(
            beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
            [](const RosterBeaconSeed& seed) {
                return seed.anchor_kind ==
                       RosterBeaconAnchorKind::RECOVERY;
            })};
    if (complete_recovery_window) {
        // RECOVER itself may use any three thresholds. The first normal
        // rotation drops slot 0, so its retained slots 1/2/3 must all remain
        // independently usable or recovery would immediately dead-end.
        for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
            if ((*rosters)[slot].descriptor.valid_count <
                QUORUM_MIN_VALID) {
                SetError(error, QuorumBuildError::CHILD_KEY_NOT_FROZEN);
                return nullptr;
            }
        }
    }
    return rosters;
}

} // namespace

FrozenQuorumRostersPtr BuildActiveFrozenQuorumRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    auto rosters{BuildActiveFrozenQuorumRostersImpl(
        genesis_hash, config, target_height, branch_tip, beacon_bundle,
        snapshot_lookup, /*recovery_universe_lookup=*/{},
        /*reusable_sets=*/{}, error)};
    if (!rosters) return nullptr;
    return FrozenQuorumRostersPtr{std::move(rosters)};
}

RecoveryUniverseCapsulePtr BuildRecoveryUniverseCapsule(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& branch_tip,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error)
{
    SetError(error, QuorumBuildError::NONE);
    if (genesis_hash.IsNull() || !snapshot_lookup) {
        SetError(error, QuorumBuildError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!config.IsValid()) {
        SetError(error, QuorumBuildError::INVALID_SCHEDULE);
        return nullptr;
    }
    const CBlockIndex* source_snapshot{ResolveRecoverySourceSnapshot(
        config, branch_tip, source, error)};
    if (source_snapshot == nullptr) return nullptr;
    auto source_state{LookupSnapshotExact(
        *source_snapshot, snapshot_lookup, error)};
    OperatorStateLookup source_operator_states{{}, {}};
    if (!source_state || !PrepareSnapshotOperatorLookup(
            config, *source_state, source_operator_states, error) ||
        !HasUsableNormalRecoverySource(
            genesis_hash, source, *source_snapshot, *source_state,
            source_operator_states, error)) {
        return nullptr;
    }
    return BuildRecoveryUniverseCapsuleFromPrepared(
        genesis_hash, source, *source_snapshot, *source_state,
        source_operator_states, error);
}

FrozenQuorumRosterCache::FrozenQuorumRosterCache(
    uint256 genesis_hash,
    QuorumBuildConfig config,
    QuorumSnapshotLookup snapshot_lookup,
    bool cache_results,
    RecoveryUniverseLookup recovery_universe_lookup)
    : m_genesis_hash{std::move(genesis_hash)},
      m_config{config},
      m_snapshot_lookup{std::move(snapshot_lookup)},
      m_cache_results{cache_results},
      m_recovery_universe_lookup{std::move(recovery_universe_lookup)},
      m_build_provenance{VerifiedRosterSet::NewBuildProvenance()}
{
}

std::shared_ptr<const VerifiedRosterSet>
VerifiedRosterSet::MintCanonicalBuild(
    std::unique_ptr<FrozenQuorumRosters> rosters,
    const FrozenQuorumRosterCache& cache)
{
    if (!rosters || !cache.m_build_provenance) {
        return nullptr;
    }
    // Exclusive transfer prevents a producer alias from changing the bytes
    // whose roots were established during canonical construction.
    FrozenQuorumRostersPtr immutable_rosters{std::move(rosters)};
    return std::shared_ptr<const VerifiedRosterSet>{
        new VerifiedRosterSet{
            cache.m_genesis_hash, std::move(immutable_rosters),
            cache.m_build_provenance}};
}

bool VerifiedRosterSet::WasBuiltBy(
    const FrozenQuorumRosterCache& cache) const noexcept
{
    return m_build_provenance &&
           m_build_provenance == cache.m_build_provenance;
}

std::shared_ptr<const FrozenQuorumRosterCache>
FrozenQuorumRosterCache::Create(
    uint256 genesis_hash,
    QuorumBuildConfig config,
    QuorumSnapshotLookup snapshot_lookup,
    bool cache_results,
    RecoveryUniverseLookup recovery_universe_lookup)
{
    if (genesis_hash.IsNull() || !config.IsValid() || !snapshot_lookup) {
        return nullptr;
    }
    return std::shared_ptr<const FrozenQuorumRosterCache>{
        new FrozenQuorumRosterCache{
            std::move(genesis_hash), config, std::move(snapshot_lookup),
            cache_results, std::move(recovery_universe_lookup)}};
}

FrozenQuorumRostersPtr FrozenQuorumRosterCache::GetActive(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    const auto roster_set{GetVerifiedActive(
        target_height, branch_tip, beacon_bundle, error)};
    return roster_set ? roster_set->RostersPtr() : nullptr;
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActive(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    return GetVerifiedActiveImpl(
        target_height, branch_tip, beacon_bundle,
        /*publish=*/true, error);
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActiveNoPublish(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    QuorumBuildError* error) const
{
    return GetVerifiedActiveImpl(
        target_height, branch_tip, beacon_bundle,
        /*publish=*/false, error);
}

VerifiedRosterSetPtr FrozenQuorumRosterCache::GetVerifiedActiveImpl(
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const ActiveRosterBeaconBundle& beacon_bundle,
    bool publish,
    QuorumBuildError* error) const
{
    SetError(error, QuorumBuildError::NONE);
    if (!m_cache_results) {
        auto built{BuildActiveFrozenQuorumRostersImpl(
            m_genesis_hash, m_config, target_height, branch_tip,
            beacon_bundle, m_snapshot_lookup, m_recovery_universe_lookup,
            /*reusable_sets=*/{}, error)};
        if (!built) return nullptr;
        auto roster_set{VerifiedRosterSet::MintCanonicalBuild(
            std::move(built), *this)};
        if (!roster_set) {
            SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        }
        return roster_set;
    }
    if (!IsEligibleChainLockTarget(m_config.schedule, target_height)) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    if (branch_tip.nHeight < target_height) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const CBlockIndex* target{branch_tip.GetAncestor(target_height)};
    if (target == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    const auto active_epochs{
        ActiveEpochsAtHeight(m_config.schedule, target_height)};
    if (!active_epochs) {
        SetError(error, QuorumBuildError::INVALID_TARGET_HEIGHT);
        return nullptr;
    }
    const auto& newest{active_epochs->back()};
    const auto beacon_bundle_hash{GetActiveRosterBeaconBundleHash(
        m_genesis_hash, beacon_bundle)};
    if (!beacon_bundle_hash ||
        !beacon_bundle.IsForNewestEpoch(newest.epoch)) {
        SetError(error, QuorumBuildError::INVALID_ROSTER_BEACON);
        return nullptr;
    }
    const CBlockIndex* newest_base{
        target->GetAncestor(newest.base_height)};
    if (newest_base == nullptr) {
        SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
        return nullptr;
    }
    // Descriptor identity always binds the newest epoch base. Recovery also
    // applies a disable-only overlay from the shared signing-round boundary.
    const bool uses_recovery_rosters{std::any_of(
        beacon_bundle.seeds.begin(), beacon_bundle.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    const int32_t signing_boundary_height{
        target_height -
        static_cast<int32_t>(m_config.schedule.sign_lag)};
    uint256 signing_boundary_hash;
    if (uses_recovery_rosters) {
        const CBlockIndex* signing_boundary{
            target->GetAncestor(signing_boundary_height)};
        if (signing_boundary == nullptr) {
            SetError(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);
            return nullptr;
        }
        signing_boundary_hash = signing_boundary->GetBlockHash();
    }
    const Key key{newest.epoch, newest_base->GetBlockHash(),
                  signing_boundary_hash,
                  *beacon_bundle_hash};

    std::array<VerifiedRosterSetPtr,
               FROZEN_QUORUM_ROSTER_CACHE_CAPACITY> reusable_sets;
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.roster_set && entry.key == key &&
                entry.roster_set->WasBuiltBy(*this)) {
                entry.recently_used = true;
                return entry.roster_set;
            }
        }
        for (std::size_t slot{0}; slot < m_entries.size(); ++slot) {
            if (m_entries[slot].roster_set &&
                m_entries[slot].roster_set->WasBuiltBy(*this)) {
                reusable_sets[slot] = m_entries[slot].roster_set;
            }
        }
    }

    auto built{BuildActiveFrozenQuorumRostersImpl(
        m_genesis_hash, m_config, target_height, branch_tip,
        beacon_bundle, m_snapshot_lookup, m_recovery_universe_lookup,
        reusable_sets, error)};
    if (!built) return nullptr;
    auto verified{VerifiedRosterSet::MintCanonicalBuild(
        std::move(built), *this)};
    if (!verified) {
        SetError(error, QuorumBuildError::INVALID_FROZEN_ROSTER);
        return nullptr;
    }
    if (!publish) return verified;

    VerifiedRosterSetPtr displaced;
    VerifiedRosterSetPtr result;
    {
        LOCK(m_mutex);
        for (auto& entry : m_entries) {
            if (entry.roster_set && entry.key == key &&
                entry.roster_set->WasBuiltBy(*this)) {
                entry.recently_used = true;
                result = entry.roster_set;
                break;
            }
        }
        if (!result) {
            std::optional<std::size_t> victim;
            for (std::size_t slot{0}; slot < m_entries.size(); ++slot) {
                if (!m_entries[slot].roster_set) {
                    victim = slot;
                    break;
                }
            }
            while (!victim) {
                auto& candidate{m_entries[m_clock_hand]};
                if (!candidate.recently_used) {
                    victim = m_clock_hand;
                } else {
                    candidate.recently_used = false;
                }
                m_clock_hand = (m_clock_hand + 1) % m_entries.size();
            }
            auto& entry{m_entries[*victim]};
            displaced = std::move(entry.roster_set);
            entry.key = key;
            entry.roster_set = std::move(verified);
            entry.recently_used = true;
            result = entry.roster_set;
        }
    }
    return result;
}

std::optional<QuorumSnapshotState>
FrozenQuorumRosterCache::LookupSnapshot(const CBlockIndex& index) const
{
    return m_snapshot_lookup(index);
}

std::optional<bool> FrozenQuorumRosterCache::EvaluateNormalRecoverySource(
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& branch_tip,
    QuorumBuildError* error) const
{
    QuorumBuildError capture_error{QuorumBuildError::NONE};
    if (GetOrCaptureRecoveryUniverse(source, branch_tip, &capture_error)) {
        SetError(error, QuorumBuildError::NONE);
        return true;
    }
    if (capture_error == QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS ||
        capture_error == QuorumBuildError::DUPLICATE_CHILD_KEY ||
        capture_error == QuorumBuildError::CHILD_KEY_NOT_FROZEN) {
        SetError(error, capture_error);
        return false;
    }
    SetError(error, capture_error);
    return std::nullopt;
}

RecoveryUniverseCapsulePtr
FrozenQuorumRosterCache::GetOrCaptureRecoveryUniverse(
    const RecoveryRosterAuthoritySource& source,
    const CBlockIndex& branch_tip,
    QuorumBuildError* error) const
{
    SetError(error, QuorumBuildError::NONE);
    const CBlockIndex* source_snapshot{ResolveRecoverySourceSnapshot(
        m_config, branch_tip, source, error)};
    if (source_snapshot == nullptr) return nullptr;
    if (m_recovery_universe_lookup) {
        RecoveryUniverseCapsulePtr persisted;
        try {
            persisted = m_recovery_universe_lookup(
                GetRecoveryUniverseSourceId(m_genesis_hash, source));
        } catch (...) {
            SetError(error,
                     QuorumBuildError::RECOVERY_UNIVERSE_LOOKUP_FAILED);
            return nullptr;
        }
        if (persisted) {
            if (!persisted->Matches(
                    m_genesis_hash, source, *source_snapshot)) {
                SetError(error,
                         QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
                return nullptr;
            }
            return persisted;
        }
    }
    return BuildRecoveryUniverseCapsule(
        m_genesis_hash, m_config, source, branch_tip,
        m_snapshot_lookup, error);
}

uint8_t GetSigningRosterAuthorizationMask(
    const FrozenQuorumRosters& rosters,
    const AuthorizationBoundaryLookup& is_boundary_ancestor)
{
    if (!is_boundary_ancestor) return 0;
    uint8_t mask{0};
    bool found_unauthorized{false};
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        const auto& roster{rosters[slot]};
        const auto& descriptor{roster.descriptor};
        const bool bootstrap{descriptor.epoch < ACTIVE_QUORUMS};
        const int32_t authorization_height{
            bootstrap ? descriptor.base_height : descriptor.snapshot_height};
        const uint256& authorization_hash{
            bootstrap ? descriptor.base_hash : descriptor.snapshot_hash};
        const bool authorized{
            authorization_height >= 0 && !authorization_hash.IsNull() &&
            is_boundary_ancestor(authorization_height,
                                 authorization_hash)};
        if (!authorized) {
            found_unauthorized = true;
            continue;
        }
        if (found_unauthorized) return 0;
        mask |= static_cast<uint8_t>(uint8_t{1} << slot);
    }
    return mask;
}

} // namespace llmq::pq
