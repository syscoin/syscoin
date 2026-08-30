// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_verify.h>

#include <hash.h>
#include <memusage.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

constexpr std::size_t MERKLE_LEAF_COUNT{512};
constexpr uint64_t TAGGED_HASHES_PER_FIXED_ROOT{
    2 * MERKLE_LEAF_COUNT - 1};
constexpr std::size_t SERIAL_PREFLIGHT_CHECKS{4};
constexpr uint8_t ALL_ROSTERS_AUTHORIZATION_MASK{
    static_cast<uint8_t>((uint8_t{1} << ACTIVE_QUORUMS) - 1)};
constexpr uint8_t PRE_ROTATION_AUTHORIZATION_MASK{
    static_cast<uint8_t>(ALL_ROSTERS_AUTHORIZATION_MASK &
                         ~(uint8_t{1} << (ACTIVE_QUORUMS - 1)))};
static_assert(ALL_ROSTERS_AUTHORIZATION_MASK == 0b1111);
static_assert(PRE_ROTATION_AUTHORIZATION_MASK == 0b0111);
constexpr std::string_view MEMBER_LEAF_DOMAIN{"SYS_PQ_QUORUM_MEMBER_LEAF_V1"};
constexpr std::string_view MEMBER_PAD_DOMAIN{"SYS_PQ_QUORUM_MEMBER_PAD_V1"};
constexpr std::string_view MEMBER_NODE_DOMAIN{"SYS_PQ_QUORUM_MEMBER_NODE_V1"};
constexpr std::string_view CHILD_ABSENT_DOMAIN{"SYS_PQ_QUORUM_CHILD_ABSENT_V1"};
constexpr std::string_view CHILD_PAD_DOMAIN{"SYS_PQ_QUORUM_CHILD_PAD_V1"};
constexpr std::string_view CHILD_NODE_DOMAIN{"SYS_PQ_QUORUM_CHILD_NODE_V1"};
std::atomic<uint64_t> g_quorum_root_tagged_hashes{0};
std::atomic<std::size_t> g_live_roster_contexts{0};
std::atomic<std::size_t> g_verification_worker_pinned_bytes{0};
static_assert(MERKLE_LEAF_COUNT >= QUORUM_SIZE);
static_assert((MERKLE_LEAF_COUNT & (MERKLE_LEAF_COUNT - 1)) == 0);
static_assert(MERKLE_LEAF_COUNT <= std::numeric_limits<uint16_t>::max());

class ScopedVerificationPinnedBytes final {
public:
    explicit ScopedVerificationPinnedBytes(std::size_t bytes)
        : m_bytes{bytes}
    {
        g_verification_worker_pinned_bytes.fetch_add(
            m_bytes, std::memory_order_relaxed);
    }

    ~ScopedVerificationPinnedBytes()
    {
        g_verification_worker_pinned_bytes.fetch_sub(
            m_bytes, std::memory_order_relaxed);
    }

private:
    const std::size_t m_bytes;
};

void SetError(ChainLockVerificationError* error, ChainLockVerificationError value)
{
    if (error != nullptr) *error = value;
}

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

template <typename... Args>
uint256 TaggedHash(std::string_view domain, const uint256& genesis_hash, const Args&... args)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, domain);
    writer << genesis_hash;
    (writer << ... << args);
    return writer.GetHash();
}

template <typename LeafBuilder>
uint256 ComputeFixedMerkleRoot(const uint256& genesis_hash,
                               uint32_t epoch,
                               std::string_view node_domain,
                               LeafBuilder&& make_leaf)
{
    std::array<uint256, MERKLE_LEAF_COUNT> hashes;
    for (std::size_t slot{0}; slot < MERKLE_LEAF_COUNT; ++slot) {
        hashes[slot] = make_leaf(static_cast<uint16_t>(slot));
    }

    std::size_t width{MERKLE_LEAF_COUNT};
    uint16_t level{0};
    while (width > 1) {
        for (std::size_t index{0}; index < width / 2; ++index) {
            hashes[index] = TaggedHash(node_domain, genesis_hash, epoch, level,
                                       static_cast<uint16_t>(index), hashes[2 * index],
                                       hashes[2 * index + 1]);
        }
        width /= 2;
        ++level;
    }
    g_quorum_root_tagged_hashes.fetch_add(
        TAGGED_HASHES_PER_FIXED_ROOT, std::memory_order_relaxed);
    return hashes[0];
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member)
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

bool IsDescriptorStructureValid(const QuorumDescriptor& descriptor)
{
    // Unselected, unusable descriptors with fewer than QUORUM_MIN_VALID keys
    // still participate in the context. The threshold is enforced separately
    // only for selected quorums.
    return descriptor.version == QUORUM_DESCRIPTOR_VERSION &&
           descriptor.base_height >= 0 &&
           descriptor.snapshot_height >= 0 &&
           descriptor.snapshot_height < descriptor.base_height &&
           !descriptor.base_hash.IsNull() &&
           !descriptor.snapshot_hash.IsNull() &&
           !descriptor.roster_beacon_hash.IsNull() &&
           descriptor.profile == CHILD_SCHEDULED_WOTS_SHAKE_128_V1 &&
           descriptor.usage_cap == SCHEDULED_WOTS_USAGE_CAP &&
           descriptor.valid_count == CountSet(descriptor.valid_members) &&
           descriptor.valid_count <= QUORUM_SIZE && !descriptor.member_root.IsNull() &&
           !descriptor.child_key_root.IsNull();
}

bool IsSelected(uint8_t selected_quorum_mask, std::size_t slot)
{
    return (selected_quorum_mask & (uint8_t{1} << slot)) != 0;
}

std::optional<uint8_t> GetAuthorizationMask(
    RosterAuthorizationTransitionKind transition,
    RosterAuthorizationAdmission admission) noexcept
{
    switch (admission) {
    case RosterAuthorizationAdmission::LIVE:
        if (transition == RosterAuthorizationTransitionKind::INITIALIZE ||
            transition == RosterAuthorizationTransitionKind::RECOVER) {
            return std::nullopt;
        }
        break;
    case RosterAuthorizationAdmission::INITIALIZE:
        if (transition != RosterAuthorizationTransitionKind::INITIALIZE) {
            return std::nullopt;
        }
        break;
    case RosterAuthorizationAdmission::RECOVER:
        if (transition != RosterAuthorizationTransitionKind::RECOVER) {
            return std::nullopt;
        }
        break;
    case RosterAuthorizationAdmission::TRUSTED_PERSISTENCE:
    case RosterAuthorizationAdmission::ATTESTED_HISTORY:
        break;
    default:
        return std::nullopt;
    }
    return transition == RosterAuthorizationTransitionKind::ROTATE
        ? PRE_ROTATION_AUTHORIZATION_MASK
        : ALL_ROSTERS_AUTHORIZATION_MASK;
}

std::optional<uint8_t> ValidateRosterAuthorizationStateInternal(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const RosterAuthorizationVerificationContext& context,
    ChainLockVerificationError* error)
{
    if (genesis_hash.IsNull()) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return std::nullopt;
    }
    if (!statement.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    const bool externally_authenticated{
        context.admission ==
            RosterAuthorizationAdmission::TRUSTED_PERSISTENCE ||
        context.admission ==
            RosterAuthorizationAdmission::ATTESTED_HISTORY};
    if (context.predecessor_height !=
            statement.previous_chainlock_height ||
        context.predecessor_block_hash !=
            statement.previous_chainlock_hash ||
        context.predecessor_height < -1 ||
        ((context.predecessor_height == -1) !=
         context.predecessor_block_hash.IsNull()) ||
        (context.admission == RosterAuthorizationAdmission::LIVE &&
         (!context.previous || !context.normal_input)) ||
        (context.admission != RosterAuthorizationAdmission::LIVE &&
         context.normal_input) ||
        (context.admission == RosterAuthorizationAdmission::INITIALIZE &&
         context.previous) ||
        (externally_authenticated && context.previous) ||
        (context.previous && !context.previous->IsStructurallyValid())) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }

    RosterAuthorizationTransition transition;
    transition.kind = statement.roster_transition;
    transition.target_height = statement.height;
    transition.target_block_hash = statement.block_hash;
    transition.predecessor_height = statement.previous_chainlock_height;
    transition.predecessor_block_hash = statement.previous_chainlock_hash;
    transition.previous = context.previous;
    transition.new_window = statement.roster_beacons;

    if (context.admission == RosterAuthorizationAdmission::LIVE) {
        const auto& normal{*context.normal_input};
        if (normal.target_height != statement.height ||
            normal.target_block_hash != statement.block_hash ||
            normal.predecessor_height !=
                statement.previous_chainlock_height ||
            normal.predecessor_block_hash !=
                statement.previous_chainlock_hash ||
            normal.previous != *context.previous ||
            normal.previous_btcc_cursor !=
                statement.previous_btcc_cursor ||
            normal.accepted_btcc_cursor !=
                statement.accepted_btcc_cursor ||
            normal.btcc_advance != statement.btcc_advance) {
            SetError(error,
                     ChainLockVerificationError::INVALID_AUTHORIZATION);
            return std::nullopt;
        }
        const auto authorization_mask{
            ValidateNormalRosterAuthorizationDecision(
                genesis_hash, normal, transition,
                statement.roster_authorization_state_hash)};
        if (!authorization_mask) {
            SetError(error,
                     ChainLockVerificationError::INVALID_AUTHORIZATION);
            return std::nullopt;
        }
        SetError(error, ChainLockVerificationError::NONE);
        return authorization_mask;
    }

    const auto authorization_mask{
        GetAuthorizationMask(statement.roster_transition,
                             context.admission)};
    if (!authorization_mask) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }

    // These two narrow integration boundaries already authenticate the exact
    // complete statement: either its local fsynced record or a durable
    // descendant receipt checkpoint. The predecessor certificate may have
    // been pruned, so recomputing its state-hash edge is intentionally
    // impossible here. Ordinary network/live admission never selects these
    // modes and must prove the transition below.
    if (externally_authenticated) {
        SetError(error, ChainLockVerificationError::NONE);
        return authorization_mask;
    }

    const auto expected_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    if (!expected_hash ||
        *expected_hash != statement.roster_authorization_state_hash) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return authorization_mask;
}

bool ValidateDescriptorBeaconBinding(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const QuorumDescriptor& descriptor,
    std::size_t slot,
    ChainLockVerificationError* error)
{
    const auto& seed{statement.roster_beacons.active.seeds[slot]};
    const auto expected_hash{
        GetRosterBeaconCommitmentHash(genesis_hash, seed)};
    if (descriptor.epoch != seed.epoch || !expected_hash ||
        descriptor.roster_beacon_hash != *expected_hash ||
        !GetPQQuorumModifier(
            genesis_hash, descriptor.epoch, descriptor.snapshot_height,
            descriptor.snapshot_hash, seed)) {
        SetError(error, ChainLockVerificationError::INVALID_ROSTER_BEACON);
        return false;
    }
    return true;
}

std::optional<std::size_t> FindQuorumSlot(
    const ChainLockShareTranscript& transcript,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters)
{
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        const auto& descriptor = rosters[slot].descriptor;
        if (descriptor.epoch == transcript.quorum_epoch &&
            descriptor.base_hash == transcript.quorum_base_hash) {
            return slot;
        }
    }
    return std::nullopt;
}

bool ValidateRosterMembersAndRoots(
    const uint256& genesis_hash,
    const FrozenQuorumRoster& roster,
    std::map<uint256, std::pair<uint256, uint32_t>>& tree_owners,
    ChainLockVerificationError* error)
{
    const auto& descriptor{roster.descriptor};
    std::set<uint256> members;
    QuorumBitmap expected_valid_members{};
    for (std::size_t member_index{0}; member_index < QUORUM_SIZE;
         ++member_index) {
        const auto& member{roster.members[member_index]};
        if (member.pro_tx_hash.IsNull()) {
            SetError(error, ChainLockVerificationError::INVALID_ROSTER);
            return false;
        }
        if (!members.insert(member.pro_tx_hash).second) {
            SetError(error, ChainLockVerificationError::DUPLICATE_MEMBER);
            return false;
        }

        if (member.child_root) {
            const auto& child{*member.child_root};
            if (!child.IsStructurallyValid() ||
                child.pro_tx_hash != member.pro_tx_hash ||
                child.epoch != descriptor.epoch) {
                SetError(error, ChainLockVerificationError::INVALID_ROSTER);
                return false;
            }
            const auto [owner, inserted]{tree_owners.emplace(
                child.commitment.tree_id,
                std::pair{member.pro_tx_hash,
                          child.commitment.generation})};
            if (!inserted &&
                owner->second != std::pair{member.pro_tx_hash,
                                           child.commitment.generation}) {
                SetError(error,
                         ChainLockVerificationError::DUPLICATE_CHILD_KEY);
                return false;
            }
            if (member.eligible) SetBit(expected_valid_members, member_index);
        }
    }
    if (expected_valid_members != descriptor.valid_members) {
        SetError(error, ChainLockVerificationError::INVALID_ROSTER);
        return false;
    }
    if (ComputeQuorumMemberRoot(genesis_hash, roster) !=
        descriptor.member_root) {
        SetError(error, ChainLockVerificationError::MEMBER_ROOT_MISMATCH);
        return false;
    }
    if (ComputeQuorumChildKeyRoot(genesis_hash, roster) !=
        descriptor.child_key_root) {
        SetError(error,
                 ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);
        return false;
    }
    return true;
}

bool ValidateRosterSetInternal(
    const uint256& genesis_hash,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    ChainLockVerificationError* error)
{
    if (genesis_hash.IsNull()) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return false;
    }

    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    std::set<std::pair<uint32_t, uint256>> quorum_identities;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& roster = rosters[slot];
        const auto& descriptor = roster.descriptor;
        if (!IsDescriptorStructureValid(descriptor) ||
            !quorum_identities.emplace(descriptor.epoch, descriptor.base_hash).second ||
            (slot != 0 &&
             (descriptor.epoch <= rosters[slot - 1].descriptor.epoch ||
              descriptor.base_height <= rosters[slot - 1].descriptor.base_height))) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }

        if (!ValidateRosterMembersAndRoots(
                genesis_hash, roster, tree_owners, error)) {
            return false;
        }
    }

    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

bool ValidateStatementBindingInternal(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    uint8_t selected_quorum_mask,
    uint8_t* authorization_mask_out,
    ChainLockVerificationError* error)
{
    const auto authorization_mask{
        ValidateRosterAuthorizationStateInternal(
            genesis_hash, statement, authorization, error)};
    if (!authorization_mask) return false;
    if ((selected_quorum_mask & ~*authorization_mask) != 0) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return false;
    }

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& descriptor{rosters[slot].descriptor};
        if (!ValidateDescriptorBeaconBinding(
                genesis_hash, statement, descriptor, slot, error)) {
            return false;
        }
        if (descriptor.base_height > statement.height ||
            (IsSelected(selected_quorum_mask, slot) &&
             descriptor.valid_count < QUORUM_MIN_VALID)) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }
    }

    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    if (GetQuorumContextHash(genesis_hash, statement.height,
                             statement.block_hash, descriptors) !=
        statement.quorum_context_hash) {
        SetError(error, ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
        return false;
    }
    if (authorization_mask_out != nullptr) {
        *authorization_mask_out = *authorization_mask;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

bool ValidateFrozenQuorumContextInternal(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    uint8_t selected_quorum_mask,
    uint8_t* authorization_mask_out,
    ChainLockVerificationError* error)
{
    const auto authorization_mask{
        ValidateRosterAuthorizationStateInternal(
            genesis_hash, statement, authorization, error)};
    if (!authorization_mask) return false;
    if ((selected_quorum_mask & ~*authorization_mask) != 0) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return false;
    }

    // Preserve the raw validator's historical per-slot error ordering while
    // the prevalidated capability is free to split intrinsic and contextual
    // checks across two explicit construction boundaries.
    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    std::set<std::pair<uint32_t, uint256>> quorum_identities;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& roster{rosters[slot]};
        const auto& descriptor{roster.descriptor};
        if (!IsDescriptorStructureValid(descriptor) ||
            descriptor.base_height > statement.height ||
            !quorum_identities.emplace(descriptor.epoch,
                                       descriptor.base_hash).second ||
            (slot != 0 &&
             (descriptor.epoch <= rosters[slot - 1].descriptor.epoch ||
              descriptor.base_height <=
                  rosters[slot - 1].descriptor.base_height))) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }
        if (!ValidateDescriptorBeaconBinding(
                genesis_hash, statement, descriptor, slot, error)) {
            return false;
        }
        if (IsSelected(selected_quorum_mask, slot) &&
            descriptor.valid_count < QUORUM_MIN_VALID) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }
        if (!ValidateRosterMembersAndRoots(
                genesis_hash, roster, tree_owners, error)) {
            return false;
        }
    }

    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    if (GetQuorumContextHash(genesis_hash, statement.height,
                             statement.block_hash, descriptors) !=
        statement.quorum_context_hash) {
        SetError(error,
                 ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
        return false;
    }
    if (authorization_mask_out != nullptr) {
        *authorization_mask_out = *authorization_mask;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

} // namespace

class VerifiedRosterSet::BuildProvenance final {};

VerifiedRosterSet::VerifiedRosterSet(
    uint256 genesis_hash,
    FrozenQuorumRostersPtr rosters,
    BuildProvenancePtr build_provenance)
    : m_genesis_hash{std::move(genesis_hash)},
      m_rosters{std::move(rosters)},
      m_build_provenance{std::move(build_provenance)}
{
    g_live_roster_contexts.fetch_add(1, std::memory_order_relaxed);
}

VerifiedRosterSet::~VerifiedRosterSet()
{
    g_live_roster_contexts.fetch_sub(1, std::memory_order_relaxed);
}

PQVerificationMemoryStats GetPQVerificationMemoryStats() noexcept
{
    return {
        g_live_roster_contexts.load(std::memory_order_relaxed),
        g_verification_worker_pinned_bytes.load(std::memory_order_relaxed),
    };
}

VerifiedRosterSet::BuildProvenancePtr
VerifiedRosterSet::NewBuildProvenance()
{
    return std::make_shared<const BuildProvenance>();
}

std::shared_ptr<const VerifiedRosterSet>
VerifiedRosterSet::Create(
    const uint256& genesis_hash,
    FrozenQuorumRostersPtr rosters,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (genesis_hash.IsNull() || !rosters) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return nullptr;
    }
    // shared_ptr<const T> is shallowly const if its producer retained a
    // mutable alias. The capability must own the bytes whose roots it proves.
    rosters = std::make_shared<const FrozenQuorumRosters>(*rosters);
    if (!ValidateRosterSetInternal(genesis_hash, *rosters, error)) {
        return nullptr;
    }
    return std::shared_ptr<const VerifiedRosterSet>{
        new VerifiedRosterSet{genesis_hash, std::move(rosters)}};
}

PreparedChainLockContext::PreparedChainLockContext(
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
    VerifiedRosterSetPtr roster_set,
    uint8_t authorization_mask)
    : m_schedule{schedule},
      m_statement{std::move(statement)},
      m_roster_set{std::move(roster_set)},
      m_authorization_mask{authorization_mask}
{
}

std::shared_ptr<const PreparedChainLockContext>
PreparedChainLockContext::Create(
    const uint256& genesis_hash,
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
    FrozenQuorumRostersPtr rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!schedule.IsValid() || !rosters) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (genesis_hash.IsNull()) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return nullptr;
    }
    if (!statement.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return nullptr;
    }
    // The raw factory preserves the single validation boundary for callers
    // that do not yet hold an intrinsic roster capability.
    rosters = std::make_shared<const FrozenQuorumRosters>(*rosters);
    uint8_t authorization_mask{0};
    if (!ValidateFrozenQuorumContextInternal(
            genesis_hash, statement, *rosters, authorization,
            /*selected_quorum_mask=*/0, &authorization_mask, error)) {
        return nullptr;
    }
    VerifiedRosterSetPtr roster_set{new VerifiedRosterSet{
        genesis_hash, std::move(rosters)}};
    return std::shared_ptr<const PreparedChainLockContext>{
        new PreparedChainLockContext{
            schedule, std::move(statement), std::move(roster_set),
            authorization_mask}};
}

std::shared_ptr<const PreparedChainLockContext>
PreparedChainLockContext::Create(
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
    VerifiedRosterSetPtr roster_set,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!schedule.IsValid() || !roster_set) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return nullptr;
    }
    uint8_t authorization_mask{0};
    if (!ValidateStatementBindingInternal(
            roster_set->GenesisHash(), statement, roster_set->Rosters(),
            authorization, /*selected_quorum_mask=*/0,
            &authorization_mask, error)) {
        return nullptr;
    }
    return std::shared_ptr<const PreparedChainLockContext>{
        new PreparedChainLockContext{
            schedule, std::move(statement), std::move(roster_set),
            authorization_mask}};
}

std::optional<std::size_t> PreparedChainLockContext::FindQuorumSlot(
    const ChainLockShareTranscript& transcript) const noexcept
{
    return llmq::pq::FindQuorumSlot(transcript, Rosters());
}

ScheduledWOTSCheck::ScheduledWOTSCheck(
    scheduled_wots::PublicKey public_key,
    uint8_t leaf_index,
    scheduled_wots::Message message,
    scheduled_wots::Signature signature)
    : m_public_key(std::move(public_key)),
      m_leaf_index(leaf_index),
      m_message(std::move(message)),
      m_signature(std::move(signature))
{
}

bool ScheduledWOTSCheck::operator()() const
{
    return scheduled_wots::Verify(m_public_key, m_leaf_index, m_message,
                                  m_signature);
}

const scheduled_wots::PublicKey&
ScheduledWOTSCheck::GetPublicKey() const noexcept
{
    return m_public_key;
}

const scheduled_wots::Message&
ScheduledWOTSCheck::GetMessageBytes() const noexcept
{
    return m_message;
}

const scheduled_wots::Signature&
ScheduledWOTSCheck::GetSignature() const noexcept
{
    return m_signature;
}

uint256 ComputeQuorumMemberRoot(const uint256& genesis_hash,
                                const FrozenQuorumRoster& roster)
{
    const uint32_t epoch{roster.descriptor.epoch};
    return ComputeFixedMerkleRoot(
        genesis_hash, epoch, MEMBER_NODE_DOMAIN, [&](uint16_t slot) {
            if (slot < QUORUM_SIZE) {
                return TaggedHash(MEMBER_LEAF_DOMAIN, genesis_hash, epoch, slot,
                                  roster.members[slot].pro_tx_hash);
            }
            return TaggedHash(MEMBER_PAD_DOMAIN, genesis_hash, epoch, slot);
        });
}

uint256 ComputeQuorumChildKeyRoot(const uint256& genesis_hash,
                                  const FrozenQuorumRoster& roster)
{
    const uint32_t epoch{roster.descriptor.epoch};
    return ComputeFixedMerkleRoot(
        genesis_hash, epoch, CHILD_NODE_DOMAIN, [&](uint16_t slot) {
            if (slot >= QUORUM_SIZE) {
                return TaggedHash(CHILD_PAD_DOMAIN, genesis_hash, epoch, slot);
            }
            const auto& member = roster.members[slot];
            if (!member.child_root) {
                return TaggedHash(CHILD_ABSENT_DOMAIN, genesis_hash, epoch, slot,
                                  member.pro_tx_hash);
            }
            return GetChildRootLeafHash(genesis_hash, slot,
                                        *member.child_root);
        });
}

uint64_t GetQuorumRootTaggedHashCountForTesting() noexcept
{
    return g_quorum_root_tagged_hashes.load(std::memory_order_relaxed);
}

ChainLockShareTranscript BuildChainLockShareTranscript(
    const FinalChainLock& chainlock,
    const QuorumDescriptor& descriptor,
    uint16_t member_index,
    const uint256& member_pro_tx_hash)
{
    ChainLockShareTranscript transcript;
    transcript.chainlock_version = chainlock.statement.version;
    transcript.child_profile = chainlock.statement.child_profile;
    transcript.height = chainlock.statement.height;
    transcript.block_hash = chainlock.statement.block_hash;
    transcript.previous_chainlock_height = chainlock.statement.previous_chainlock_height;
    transcript.previous_chainlock_hash = chainlock.statement.previous_chainlock_hash;
    transcript.quorum_context_hash = chainlock.statement.quorum_context_hash;
    transcript.roster_transition = chainlock.statement.roster_transition;
    transcript.roster_beacons = chainlock.statement.roster_beacons;
    transcript.roster_authorization_state_hash =
        chainlock.statement.roster_authorization_state_hash;
    transcript.quorum_epoch = descriptor.epoch;
    transcript.quorum_base_hash = descriptor.base_hash;
    transcript.member_index = member_index;
    transcript.member_pro_tx_hash = member_pro_tx_hash;
    transcript.previous_btcc_cursor = chainlock.statement.previous_btcc_cursor;
    transcript.accepted_btcc_cursor = chainlock.statement.accepted_btcc_cursor;
    transcript.btcc_advance = chainlock.statement.btcc_advance;
    transcript.btcc_receipt_state = chainlock.statement.btcc_receipt_state;
    transcript.payment_audit_receipt_state =
        chainlock.statement.payment_audit_receipt_state;
    transcript.payment_probation_state_hash =
        chainlock.statement.payment_probation_state_hash;
    return transcript;
}

std::optional<uint8_t> ValidateRosterAuthorizationState(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const RosterAuthorizationVerificationContext& context,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    return ValidateRosterAuthorizationStateInternal(
        genesis_hash, statement, context, error);
}

bool ValidateFrozenQuorumContext(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    return ValidateFrozenQuorumContextInternal(
        genesis_hash, statement, rosters, authorization,
        /*selected_quorum_mask=*/0, /*authorization_mask_out=*/nullptr,
        error);
}

namespace {

std::optional<ScheduledWOTSCheck>
PrepareChainLockShareVerificationInternal(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    std::optional<std::size_t> prepared_quorum_slot,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    const auto quorum_slot{prepared_quorum_slot};
    if (!quorum_slot || !IsSelected(authorization_mask, *quorum_slot)) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }

    const auto& roster{rosters[*quorum_slot]};
    const auto leaf_index{ChainLockLeafIndex(
        schedule, roster.descriptor.epoch, share.transcript.height)};
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID || !leaf_index) {
        SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
        return std::nullopt;
    }
    const std::size_t member_index{share.transcript.member_index};
    if (member_index >= QUORUM_SIZE ||
        !IsBitSet(roster.descriptor.valid_members, member_index)) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    const auto& member{roster.members[member_index]};
    if (!member.eligible || !member.child_root ||
        member.pro_tx_hash != share.transcript.member_pro_tx_hash) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }

    if (!VerifyCommittedChildKeyProof(
            genesis_hash, member.child_root->commitment,
            roster.descriptor.epoch,
            share.authenticated_signature.key_proof)) {
        SetError(error, ChainLockVerificationError::INVALID_CHILD_PROOF);
        return std::nullopt;
    }
    scheduled_wots::PublicKey public_key{
        share.authenticated_signature.key_proof.public_key};
    const uint256 share_hash{GetChainLockShareHash(genesis_hash, share.transcript)};
    scheduled_wots::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    scheduled_wots::Signature signature;
    std::copy(share.authenticated_signature.signature.begin(),
              share.authenticated_signature.signature.end(),
              signature.begin());
    return ScheduledWOTSCheck{
        std::move(public_key), *leaf_index, std::move(message),
        std::move(signature)};
}

} // namespace

std::optional<ScheduledWOTSCheck> PrepareChainLockShareVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    uint8_t authorization_mask{0};
    if (!ValidateFrozenQuorumContextInternal(
            genesis_hash, share.GetStatement(), rosters, authorization,
            /*selected_quorum_mask=*/0, &authorization_mask, error)) {
        return std::nullopt;
    }
    return PrepareChainLockShareVerificationInternal(
        genesis_hash, schedule, share, rosters, authorization_mask,
        FindQuorumSlot(share.transcript, rosters), error);
}

std::optional<ScheduledWOTSCheck> PrepareChainLockShareVerification(
    const ChainLockShare& share,
    const PreparedChainLockContext& context,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (share.GetStatement() != context.Statement()) {
        SetError(error, ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
        return std::nullopt;
    }
    return PrepareChainLockShareVerificationInternal(
        context.GenesisHash(), context.Schedule(), share, context.Rosters(),
        context.AuthorizationMask(),
        context.FindQuorumSlot(share.transcript), error);
}

bool VerifyChainLockShare(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    auto check{PrepareChainLockShareVerification(
        genesis_hash, schedule, share, rosters, authorization, error)};
    if (!check) return false;
    if (!(*check)()) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNATURE);
        return false;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

namespace {

std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerificationInternal(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    ChainLockVerificationError* error)
{
    PreparedChainLockVerification prepared;
    prepared.checks.reserve(FINAL_SIGNATURE_COUNT);
    std::size_t signature_index{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if (!IsSelected(chainlock.selected_quorum_mask, slot)) continue;
        const auto& roster = rosters[slot];
        const auto leaf_index{ChainLockLeafIndex(
            schedule, roster.descriptor.epoch, chainlock.statement.height)};
        if (!leaf_index) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return std::nullopt;
        }
        for (std::size_t member_index{0}; member_index < QUORUM_SIZE; ++member_index) {
            if (!IsBitSet(chainlock.signer_bitmaps[slot], member_index)) continue;
            if (!IsBitSet(roster.descriptor.valid_members, member_index) ||
                !roster.members[member_index].child_root ||
                signature_index >= chainlock.signatures.size()) {
                SetError(error, ChainLockVerificationError::INVALID_SIGNER);
                return std::nullopt;
            }

            const auto& member = roster.members[member_index];
            const auto& authenticated{
                chainlock.signatures[signature_index]};
            if (!VerifyCommittedChildKeyProof(
                    genesis_hash, member.child_root->commitment,
                    roster.descriptor.epoch,
                    authenticated.key_proof)) {
                SetError(error,
                         ChainLockVerificationError::INVALID_CHILD_PROOF);
                return std::nullopt;
            }
            scheduled_wots::PublicKey public_key{
                authenticated.key_proof.public_key};

            const auto transcript = BuildChainLockShareTranscript(
                chainlock, roster.descriptor, static_cast<uint16_t>(member_index),
                member.pro_tx_hash);
            if (!transcript.IsStructurallyValid()) {
                SetError(error, ChainLockVerificationError::INVALID_SIGNER);
                return std::nullopt;
            }
            const uint256 share_hash = GetChainLockShareHash(genesis_hash, transcript);
            scheduled_wots::Message message;
            std::copy(share_hash.begin(), share_hash.end(), message.begin());
            scheduled_wots::Signature signature;
            std::copy(authenticated.signature.begin(),
                      authenticated.signature.end(), signature.begin());
            prepared.checks.emplace_back(
                std::move(public_key), *leaf_index, std::move(message),
                std::move(signature));
            ++signature_index;
        }
    }
    if (signature_index != FINAL_SIGNATURE_COUNT ||
        prepared.checks.size() != FINAL_SIGNATURE_COUNT) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    return prepared;
}

} // namespace

std::optional<PreparedChainLockVerification> PrepareFinalChainLockVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!chainlock.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (!ValidateFrozenQuorumContextInternal(
            genesis_hash, chainlock.statement, rosters, authorization,
            chainlock.selected_quorum_mask,
            /*authorization_mask_out=*/nullptr, error)) {
        return std::nullopt;
    }
    return PrepareFinalChainLockVerificationInternal(
        genesis_hash, schedule, chainlock, rosters, error);
}

std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerification(
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const VerifiedRosterSet& roster_set,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!chainlock.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (!ValidateStatementBindingInternal(
            roster_set.GenesisHash(), chainlock.statement,
            roster_set.Rosters(), authorization,
            chainlock.selected_quorum_mask,
            /*authorization_mask_out=*/nullptr, error)) {
        return std::nullopt;
    }
    return PrepareFinalChainLockVerificationInternal(
        roster_set.GenesisHash(), schedule, chainlock,
        roster_set.Rosters(), error);
}

std::optional<PreparedChainLockVerification>
PrepareFinalChainLockVerification(
    const FinalChainLock& chainlock,
    const PreparedChainLockContext& context,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!chainlock.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (chainlock.statement != context.Statement()) {
        SetError(error,
                 ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
        return std::nullopt;
    }
    if ((chainlock.selected_quorum_mask &
         ~context.AuthorizationMask()) != 0) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }
    return PrepareFinalChainLockVerificationInternal(
        context.GenesisHash(), context.Schedule(), chainlock,
        context.Rosters(), error);
}

bool VerifyScheduledWOTSChecks(std::vector<ScheduledWOTSCheck>&& checks,
                              ScheduledWOTSCheckQueue* queue)
{
    const ScopedVerificationPinnedBytes pinned{
        memusage::DynamicUsage(checks)};
    if (queue == nullptr) {
        for (const auto& check : checks) {
            if (!check()) return false;
        }
        return true;
    }
    CCheckQueueControl<ScheduledWOTSCheck> control{queue};
    control.Add(std::move(checks));
    return control.Wait();
}

bool VerifyFinalChainLock(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ScheduledWOTSCheckQueue* queue,
    ChainLockVerificationError* error)
{
    auto prepared = PrepareFinalChainLockVerification(
        genesis_hash, schedule, chainlock, rosters, authorization,
        error);
    if (!prepared) return false;
    if (!VerifyScheduledWOTSChecks(std::move(prepared->checks), queue)) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNATURE);
        return false;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

ChainLockVerifier::ChainLockVerifier(std::size_t worker_threads, unsigned int batch_size)
    : m_queue(batch_size == 0 ? 1 : batch_size)
{
    if (worker_threads > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("PQ ChainLock worker count exceeds int range");
    }
    if (worker_threads == 0) return;
    try {
        m_queue.StartWorkerThreads(static_cast<int>(worker_threads));
    } catch (...) {
        if (m_queue.HasThreads()) m_queue.StopWorkerThreads();
        throw;
    }
}

ChainLockVerifier::~ChainLockVerifier()
{
    if (m_queue.HasThreads()) m_queue.StopWorkerThreads();
}

bool ChainLockVerifier::Verify(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    auto prepared = PrepareFinalChainLockVerification(
        genesis_hash, schedule, chainlock, rosters, authorization,
        error);
    if (!prepared) return false;
    if (!VerifyChecks(std::move(prepared->checks))) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNATURE);
        return false;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

bool ChainLockVerifier::VerifyChecks(std::vector<ScheduledWOTSCheck>&& checks)
{
    {
        const ScopedVerificationPinnedBytes pinned{
            memusage::DynamicUsage(checks)};
        // Random invalid bundles normally fail after one serial WOTS+ check
        // instead of occupying every worker. The process-secret RNG makes the
        // sampled member positions unpredictable to a remote sender. Every
        // sampled job is removed only after it succeeds, so valid certificates
        // still execute all checks exactly once.
        const std::size_t preflight_count{
            std::min(SERIAL_PREFLIGHT_CHECKS, checks.size())};
        for (std::size_t checked{0}; checked < preflight_count; ++checked) {
            std::size_t index{0};
            {
                LOCK(m_preflight_mutex);
                index = static_cast<std::size_t>(
                    m_preflight_rng.randrange(checks.size()));
            }
            if (!checks[index]()) return false;
            if (index != checks.size() - 1) {
                checks[index] = std::move(checks.back());
            }
            checks.pop_back();
        }
        if (checks.empty()) return true;
    }
    return VerifyScheduledWOTSChecks(std::move(checks), &m_queue);
}

} // namespace llmq::pq
