// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_verify.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

constexpr std::size_t MERKLE_LEAF_COUNT{512};
constexpr std::size_t SERIAL_PREFLIGHT_CHECKS{4};
constexpr std::string_view MEMBER_LEAF_DOMAIN{"SYS_PQ_QUORUM_MEMBER_LEAF_V1"};
constexpr std::string_view MEMBER_PAD_DOMAIN{"SYS_PQ_QUORUM_MEMBER_PAD_V1"};
constexpr std::string_view MEMBER_NODE_DOMAIN{"SYS_PQ_QUORUM_MEMBER_NODE_V1"};
constexpr std::string_view CHILD_ABSENT_DOMAIN{"SYS_PQ_QUORUM_CHILD_ABSENT_V1"};
constexpr std::string_view CHILD_PAD_DOMAIN{"SYS_PQ_QUORUM_CHILD_PAD_V1"};
constexpr std::string_view CHILD_NODE_DOMAIN{"SYS_PQ_QUORUM_CHILD_NODE_V1"};
static_assert(MERKLE_LEAF_COUNT >= QUORUM_SIZE);
static_assert((MERKLE_LEAF_COUNT & (MERKLE_LEAF_COUNT - 1)) == 0);
static_assert(MERKLE_LEAF_COUNT <= std::numeric_limits<uint16_t>::max());

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

bool IsDescriptorHeaderValid(const QuorumDescriptor& descriptor, int32_t target_height)
{
    // Unselected, unusable descriptors with fewer than QUORUM_MIN_VALID keys
    // still participate in the context. The threshold is enforced separately
    // only for selected quorums.
    return descriptor.version == QUORUM_DESCRIPTOR_VERSION &&
           descriptor.base_height >= 0 && descriptor.base_height <= target_height &&
           descriptor.snapshot_height >= 0 &&
           descriptor.snapshot_height < descriptor.base_height &&
           !descriptor.base_hash.IsNull() && !descriptor.snapshot_hash.IsNull() &&
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

bool ValidateFrozenQuorumContextInternal(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    uint8_t selected_quorum_mask,
    ChainLockVerificationError* error)
{
    if (genesis_hash.IsNull()) {
        SetError(error, ChainLockVerificationError::INVALID_ARGUMENT);
        return false;
    }
    if (!statement.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return false;
    }
    if (!IsSigningRosterAuthorizationMask(authorization_mask) ||
        (selected_quorum_mask & ~authorization_mask) != 0) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return false;
    }

    std::map<uint256, std::pair<uint256, uint32_t>> tree_owners;
    std::set<std::pair<uint32_t, uint256>> quorum_identities;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& roster = rosters[slot];
        const auto& descriptor = roster.descriptor;
        // The predecessor-derived mask is the transition evidence. A newest
        // unselected roster may already be context-bound before its snapshot
        // is authorized, but no authorized descriptor may cross the boundary.
        const int32_t authorization_height{
            descriptor.epoch < ACTIVE_QUORUMS
                ? descriptor.base_height
                : descriptor.snapshot_height};
        if (!IsDescriptorHeaderValid(descriptor, statement.height) ||
            !quorum_identities.emplace(descriptor.epoch, descriptor.base_hash).second ||
            (IsSelected(authorization_mask, slot) &&
             authorization_height > statement.previous_chainlock_height) ||
            (slot != 0 &&
             (descriptor.epoch <= rosters[slot - 1].descriptor.epoch ||
              descriptor.base_height <= rosters[slot - 1].descriptor.base_height))) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }
        if (IsSelected(selected_quorum_mask, slot) &&
            descriptor.valid_count < QUORUM_MIN_VALID) {
            SetError(error, ChainLockVerificationError::INVALID_DESCRIPTOR);
            return false;
        }

        std::set<uint256> members;
        QuorumBitmap expected_valid_members{};
        for (std::size_t member_index{0}; member_index < QUORUM_SIZE; ++member_index) {
            const auto& member = roster.members[member_index];
            if (member.pro_tx_hash.IsNull()) {
                SetError(error, ChainLockVerificationError::INVALID_ROSTER);
                return false;
            }
            if (!members.insert(member.pro_tx_hash).second) {
                SetError(error, ChainLockVerificationError::DUPLICATE_MEMBER);
                return false;
            }

            if (member.child_root) {
                const auto& child = *member.child_root;
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
                    SetError(error, ChainLockVerificationError::DUPLICATE_CHILD_KEY);
                    return false;
                }
                if (member.eligible) SetBit(expected_valid_members, member_index);
            }
        }
        if (expected_valid_members != descriptor.valid_members) {
            SetError(error, ChainLockVerificationError::INVALID_ROSTER);
            return false;
        }
        if (ComputeQuorumMemberRoot(genesis_hash, roster) != descriptor.member_root) {
            SetError(error, ChainLockVerificationError::MEMBER_ROOT_MISMATCH);
            return false;
        }
        if (ComputeQuorumChildKeyRoot(genesis_hash, roster) != descriptor.child_key_root) {
            SetError(error, ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);
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
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

} // namespace

PreparedChainLockContext::PreparedChainLockContext(
    uint256 genesis_hash,
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
    FrozenQuorumRostersPtr rosters,
    uint8_t authorization_mask)
    : m_genesis_hash{std::move(genesis_hash)},
      m_schedule{schedule},
      m_statement{std::move(statement)},
      m_rosters{std::move(rosters)},
      m_authorization_mask{authorization_mask}
{
}

std::shared_ptr<const PreparedChainLockContext>
PreparedChainLockContext::Create(
    const uint256& genesis_hash,
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
    FrozenQuorumRostersPtr rosters,
    uint8_t authorization_mask,
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
    if (!IsSigningRosterAuthorizationMask(authorization_mask)) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return nullptr;
    }
    // shared_ptr<const T> is only shallowly const when the caller retains a
    // mutable alias. Copy before validation so the capability owns state that
    // cannot change after its roots and statement binding are checked.
    rosters = std::make_shared<const FrozenQuorumRosters>(*rosters);
    if (!ValidateFrozenQuorumContext(
            genesis_hash, statement, *rosters, authorization_mask, error)) {
        return nullptr;
    }
    return std::shared_ptr<const PreparedChainLockContext>{
        new PreparedChainLockContext{
            genesis_hash, schedule, std::move(statement), std::move(rosters),
            authorization_mask}};
}

std::optional<std::size_t> PreparedChainLockContext::FindQuorumSlot(
    const ChainLockShareTranscript& transcript) const noexcept
{
    return llmq::pq::FindQuorumSlot(transcript, *m_rosters);
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

bool ValidateFrozenQuorumContext(
    const uint256& genesis_hash,
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    return ValidateFrozenQuorumContextInternal(
        genesis_hash, statement, rosters, authorization_mask,
        /*selected_quorum_mask=*/0, error);
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
    bool context_prepared,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    const auto quorum_slot{context_prepared
        ? prepared_quorum_slot
        : FindQuorumSlot(share.transcript, rosters)};
    if (!quorum_slot || !IsSelected(authorization_mask, *quorum_slot)) {
        SetError(error, ChainLockVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }
    if (!context_prepared) {
        const ChainLockStatement statement{share.GetStatement()};
        if (!ValidateFrozenQuorumContextInternal(
                genesis_hash, statement, rosters, authorization_mask,
                /*selected_quorum_mask=*/0, error)) {
            return std::nullopt;
        }
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
    uint8_t authorization_mask,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    return PrepareChainLockShareVerificationInternal(
        genesis_hash, schedule, share, rosters, authorization_mask,
        /*prepared_quorum_slot=*/std::nullopt,
        /*context_prepared=*/false, error);
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
        context.FindQuorumSlot(share.transcript),
        /*context_prepared=*/true, error);
}

bool VerifyChainLockShare(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const ChainLockShare& share,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error)
{
    auto check{PrepareChainLockShareVerification(
        genesis_hash, schedule, share, rosters, authorization_mask, error)};
    if (!check) return false;
    if (!(*check)()) {
        SetError(error, ChainLockVerificationError::INVALID_SIGNATURE);
        return false;
    }
    SetError(error, ChainLockVerificationError::NONE);
    return true;
}

std::optional<PreparedChainLockVerification> PrepareFinalChainLockVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const FinalChainLock& chainlock,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    ChainLockVerificationError* error)
{
    SetError(error, ChainLockVerificationError::NONE);
    if (!chainlock.IsStructurallyValid()) {
        SetError(error, ChainLockVerificationError::INVALID_CHAINLOCK);
        return std::nullopt;
    }
    if (!ValidateFrozenQuorumContextInternal(
            genesis_hash, chainlock.statement, rosters, authorization_mask,
            chainlock.selected_quorum_mask, error)) {
        return std::nullopt;
    }

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

bool VerifyScheduledWOTSChecks(std::vector<ScheduledWOTSCheck>&& checks,
                              ScheduledWOTSCheckQueue* queue)
{
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
    uint8_t authorization_mask,
    ScheduledWOTSCheckQueue* queue,
    ChainLockVerificationError* error)
{
    auto prepared = PrepareFinalChainLockVerification(
        genesis_hash, schedule, chainlock, rosters, authorization_mask,
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
    uint8_t authorization_mask,
    ChainLockVerificationError* error)
{
    auto prepared = PrepareFinalChainLockVerification(
        genesis_hash, schedule, chainlock, rosters, authorization_mask,
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
    // Random invalid bundles normally fail after one serial WOTS+ check instead
    // of occupying every worker. The process-secret RNG makes the sampled
    // member positions unpredictable to a remote sender. Every sampled job is
    // removed only after it succeeds, so valid certificates still execute all
    // checks exactly once.
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
    return VerifyScheduledWOTSChecks(std::move(checks), &m_queue);
}

} // namespace llmq::pq
