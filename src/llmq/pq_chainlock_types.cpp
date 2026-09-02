// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_types.h>

#include <algorithm>
#include <bit>

namespace llmq::pq {
namespace {

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    // Raw fixed tags avoid CompactSize ambiguity at consensus transcript boundaries.
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

bool IsKnownAdvance(BTCCAdvance advance)
{
    return advance == BTCCAdvance::KEEP || advance == BTCCAdvance::ADVANCE;
}

bool IsKnownRosterBeaconAnchorKind(RosterBeaconAnchorKind kind)
{
    return kind == RosterBeaconAnchorKind::NORMAL ||
           kind == RosterBeaconAnchorKind::RECOVERY;
}

bool IsKnownRosterBeaconState(RosterBeaconState state)
{
    return state == RosterBeaconState::EMPTY ||
           state == RosterBeaconState::PENDING ||
           state == RosterBeaconState::READY;
}

bool IsKnownRosterAuthorizationTransition(
    RosterAuthorizationTransitionKind kind)
{
    return kind == RosterAuthorizationTransitionKind::INITIALIZE ||
           kind == RosterAuthorizationTransitionKind::KEEP ||
           kind == RosterAuthorizationTransitionKind::OBSERVE ||
           kind == RosterAuthorizationTransitionKind::REVEAL ||
           kind == RosterAuthorizationTransitionKind::ROTATE ||
           kind == RosterAuthorizationTransitionKind::RECOVER;
}

bool IsCursorTransitionStructurallyValid(
    int32_t previous_chainlock_height,
    const BTCCursor& previous,
    const BTCCursor& accepted,
    BTCCAdvance advance)
{
    if (!previous.IsStructurallyValid() ||
        !accepted.IsStructurallyValid() || !IsKnownAdvance(advance) ||
        (previous_chainlock_height < 0 && !previous.IsNull()) ||
        (!previous.IsNull() &&
         previous.sys_height > previous_chainlock_height)) {
        return false;
    }
    if (advance == BTCCAdvance::KEEP) return accepted == previous;
    return !accepted.IsNull() &&
           (previous.IsNull() || accepted.sys_height > previous.sys_height);
}

bool IsReceiptStateCompatible(const BTCCursor& accepted,
                              const BTCCReceiptState& receipt_state)
{
    if (!receipt_state.IsStructurallyValid()) return false;
    if (receipt_state.cursor.IsNull()) return true;
    if (accepted.IsNull() ||
        receipt_state.cursor.sys_height > accepted.sys_height) {
        return false;
    }
    return receipt_state.cursor.sys_height != accepted.sys_height ||
           receipt_state.cursor == accepted;
}

} // namespace

bool ChildKeyTreeCommitment::IsStructurallyValid() const noexcept
{
    if (version != CHILD_KEY_TREE_COMMITMENT_VERSION ||
        profile != CHILD_SCHEDULED_WOTS_SHAKE_128_V1 || usage_cap != SCHEDULED_WOTS_USAGE_CAP ||
        depth != CHILD_KEY_TREE_DEPTH ||
        !IsValidChildKeyTreeGeneration(generation) || tree_id.IsNull() ||
        root.IsNull()) {
        return false;
    }
    const uint64_t last_epoch{static_cast<uint64_t>(first_epoch) +
                              CHILD_KEY_TREE_LEAF_COUNT - 1};
    return last_epoch <= std::numeric_limits<uint32_t>::max();
}

bool ChildKeyTreeCommitment::CoversEpoch(uint32_t epoch) const noexcept
{
    return IsStructurallyValid() && epoch >= first_epoch &&
           static_cast<uint64_t>(epoch) - first_epoch <
               CHILD_KEY_TREE_LEAF_COUNT;
}

bool GlobalKeyRecord::IsStructurallyValid() const
{
    return version == GLOBAL_KEY_RECORD_VERSION &&
           profile == GLOBAL_SLH_DSA_SHAKE_128S_V1 && key_version != 0 &&
           activated_height > 0 && child_key_commitment.IsStructurallyValid() &&
           std::any_of(public_key.begin(), public_key.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool FrozenChildRootRecord::IsStructurallyValid() const noexcept
{
    return !pro_tx_hash.IsNull() && global_key_version != 0 &&
           commitment.CoversEpoch(epoch);
}

bool ChildKeyProof::IsStructurallyValid() const noexcept
{
    return std::any_of(public_key.begin(), public_key.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool BTCCursor::IsNull() const
{
    return sys_height == -1 && sys_hash.IsNull() && btc_hash.IsNull();
}

bool BTCCursor::IsStructurallyValid() const
{
    if (sys_height == -1) return IsNull();
    return sys_height >= 0 && !sys_hash.IsNull() && !btc_hash.IsNull();
}

std::optional<int32_t> RosterBeaconSeed::FutureBTCHeight() const noexcept
{
    if (anchor_btc_height < 0 ||
        static_cast<int64_t>(anchor_btc_height) +
                ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA >
            std::numeric_limits<int32_t>::max()) {
        return std::nullopt;
    }
    return anchor_btc_height +
           static_cast<int32_t>(ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA);
}

bool RosterBeaconSeed::IsStructurallyValid() const noexcept
{
    if (version != ROSTER_BEACON_VERSION ||
        !IsKnownRosterBeaconAnchorKind(anchor_kind) ||
        !IsKnownRosterBeaconState(state)) {
        return false;
    }
    if (anchor_kind == RosterBeaconAnchorKind::RECOVERY) {
        if (!anchor_cursor.IsStructurallyValid() ||
            anchor_cursor.IsNull() || !FutureBTCHeight()) {
            return false;
        }
        return state == RosterBeaconState::READY &&
               !future_btc_hash.IsNull() &&
               future_btc_hash != anchor_cursor.btc_hash;
    }
    if (state == RosterBeaconState::EMPTY) {
        return anchor_kind == RosterBeaconAnchorKind::NORMAL &&
               anchor_cursor.IsNull() && anchor_btc_height == -1 &&
               future_btc_hash.IsNull();
    }
    if (!anchor_cursor.IsStructurallyValid() || anchor_cursor.IsNull() ||
        !FutureBTCHeight()) {
        return false;
    }
    if (state == RosterBeaconState::PENDING) {
        return future_btc_hash.IsNull();
    }
    return !future_btc_hash.IsNull() &&
           future_btc_hash != anchor_cursor.btc_hash;
}

bool RosterBeaconSeed::IsReady() const noexcept
{
    return state == RosterBeaconState::READY && IsStructurallyValid();
}

bool RecoveryRosterAuthoritySource::IsNull() const noexcept
{
    return normal_beacon == RosterBeaconSeed{};
}

bool RecoveryRosterAuthoritySource::IsStructurallyValid() const noexcept
{
    return IsNull() ||
           (normal_beacon.anchor_kind == RosterBeaconAnchorKind::NORMAL &&
            normal_beacon.IsReady());
}

bool ActiveRosterBeaconBundle::IsStructurallyValid() const noexcept
{
    if (version != ROSTER_BEACON_BUNDLE_VERSION ||
        !seeds.front().IsReady()) {
        return false;
    }
    const uint64_t first_epoch{seeds.front().epoch};
    for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
        if (!seeds[slot].IsReady() ||
            first_epoch + slot > std::numeric_limits<uint32_t>::max() ||
            seeds[slot].epoch != first_epoch + slot) {
            return false;
        }
    }
    if (!recovery_authority_source.IsStructurallyValid()) return false;
    return recovery_authority_hash.IsNull() ==
           recovery_authority_source.IsNull();
}

bool ActiveRosterBeaconBundle::IsForNewestEpoch(
    uint32_t newest_epoch) const noexcept
{
    return IsStructurallyValid() && seeds.back().epoch == newest_epoch;
}

bool RosterBeaconWindow::IsStructurallyValid() const noexcept
{
    return active.IsStructurallyValid() && next.IsStructurallyValid() &&
           active.seeds.back().epoch <
               std::numeric_limits<uint32_t>::max() &&
           next.epoch == active.seeds.back().epoch + 1;
}

bool BTCCReceiptState::IsStructurallyValid() const
{
    return cursor.IsStructurallyValid() &&
           (cursor.IsNull() == cumulative_hash.IsNull());
}

bool PaymentAuditReceiptCursor::IsNull() const noexcept
{
    return carrier_height == -1 && epoch == 0 && seal_block_hash.IsNull() &&
           audit_logical_id.IsNull() && audit_witness_id.IsNull();
}

bool PaymentAuditReceiptCursor::IsStructurallyValid() const noexcept
{
    return IsNull() ||
           (carrier_height >= 0 && !seal_block_hash.IsNull() &&
            !audit_logical_id.IsNull() && !audit_witness_id.IsNull());
}

bool PaymentAuditReceiptState::IsStructurallyValid() const noexcept
{
    return cursor.IsStructurallyValid() &&
           (cursor.IsNull() == cumulative_hash.IsNull());
}

std::size_t CountSet(const QuorumBitmap& bitmap)
{
    std::size_t count{0};
    for (const uint8_t byte : bitmap) count += std::popcount(byte);
    return count;
}

bool QuorumDescriptor::IsStructurallyValid() const
{
    return version == QUORUM_DESCRIPTOR_VERSION && base_height >= 0 &&
           snapshot_height >= 0 && snapshot_height < base_height && !base_hash.IsNull() &&
           !snapshot_hash.IsNull() && !roster_beacon_hash.IsNull() &&
           profile == CHILD_SCHEDULED_WOTS_SHAKE_128_V1 &&
           usage_cap == SCHEDULED_WOTS_USAGE_CAP && valid_count == CountSet(valid_members) &&
           valid_count >= QUORUM_MIN_VALID && valid_count <= QUORUM_SIZE &&
           !member_root.IsNull() && !child_key_root.IsNull();
}

bool RosterAuthorizationBaseIdentity::IsNull() const noexcept
{
    return height == -1 && block_hash.IsNull() && logical_id.IsNull();
}

bool RosterAuthorizationBaseIdentity::IsStructurallyValid() const noexcept
{
    return IsNull() ||
           (height >= 0 && !block_hash.IsNull() && !logical_id.IsNull());
}

bool ChainLockShareTranscript::IsStructurallyValid() const
{
    const bool initializes{
        roster_transition ==
            RosterAuthorizationTransitionKind::INITIALIZE};
    return chainlock_version == CHAINLOCK_VERSION && child_profile == CHILD_SCHEDULED_WOTS_SHAKE_128_V1 &&
           height >= 0 && !block_hash.IsNull() && previous_chainlock_height < height &&
           (previous_chainlock_height >= 0 || previous_chainlock_hash.IsNull()) &&
           (previous_chainlock_height < 0 || !previous_chainlock_hash.IsNull()) &&
           !quorum_context_hash.IsNull() &&
           IsKnownRosterAuthorizationTransition(roster_transition) &&
           roster_beacons.IsStructurallyValid() &&
           !roster_authorization_state_hash.IsNull() &&
           roster_authorization_base.IsStructurallyValid() &&
           (initializes == roster_authorization_base.IsNull()) &&
           (roster_authorization_base.IsNull() ||
            roster_authorization_base.height < height) &&
           !quorum_base_hash.IsNull() &&
           member_index < QUORUM_SIZE && !member_pro_tx_hash.IsNull() &&
           IsCursorTransitionStructurallyValid(
               previous_chainlock_height, previous_btcc_cursor,
               accepted_btcc_cursor, btcc_advance) &&
           IsReceiptStateCompatible(accepted_btcc_cursor,
                                    btcc_receipt_state) &&
           payment_audit_receipt_state.IsStructurallyValid() &&
           !payment_probation_state_hash.IsNull();
}

bool ChainLockStatement::IsStructurallyValid() const
{
    const bool initializes{
        roster_transition ==
            RosterAuthorizationTransitionKind::INITIALIZE};
    return version == CHAINLOCK_VERSION && child_profile == CHILD_SCHEDULED_WOTS_SHAKE_128_V1 && height >= 0 &&
           !block_hash.IsNull() && previous_chainlock_height < height &&
           (previous_chainlock_height >= 0 || previous_chainlock_hash.IsNull()) &&
           (previous_chainlock_height < 0 || !previous_chainlock_hash.IsNull()) &&
           !quorum_context_hash.IsNull() &&
           IsKnownRosterAuthorizationTransition(roster_transition) &&
           roster_beacons.IsStructurallyValid() &&
           !roster_authorization_state_hash.IsNull() &&
           roster_authorization_base.IsStructurallyValid() &&
           (initializes == roster_authorization_base.IsNull()) &&
           (roster_authorization_base.IsNull() ||
            roster_authorization_base.height < height) &&
           IsCursorTransitionStructurallyValid(
               previous_chainlock_height, previous_btcc_cursor,
               accepted_btcc_cursor, btcc_advance) &&
           IsReceiptStateCompatible(accepted_btcc_cursor,
                                    btcc_receipt_state) &&
           payment_audit_receipt_state.IsStructurallyValid() &&
           !payment_probation_state_hash.IsNull();
}

bool ChainLockShare::IsStructurallyValid() const
{
    return transcript.IsStructurallyValid() &&
           authenticated_signature.IsStructurallyValid();
}

std::optional<uint16_t> PackChainLockShareSignerPosition(
    uint8_t quorum_slot, uint16_t member_index) noexcept
{
    if (quorum_slot >= ACTIVE_QUORUMS || member_index >= QUORUM_SIZE) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(
        static_cast<std::size_t>(quorum_slot) * QUORUM_SIZE + member_index);
}

std::optional<ChainLockShareSignerPosition>
CompactChainLockShare::GetSignerPosition() const noexcept
{
    if (signer_position >= ACTIVE_QUORUMS * QUORUM_SIZE) {
        return std::nullopt;
    }
    return ChainLockShareSignerPosition{
        static_cast<uint8_t>(signer_position / QUORUM_SIZE),
        static_cast<uint16_t>(signer_position % QUORUM_SIZE)};
}

bool CompactChainLockShare::IsStructurallyValid() const noexcept
{
    return !statement_logical_id.IsNull() && GetSignerPosition() &&
           authenticated_signature.IsStructurallyValid();
}

ChainLockStatement ChainLockShare::GetStatement() const
{
    ChainLockStatement statement;
    statement.version = transcript.chainlock_version;
    statement.child_profile = transcript.child_profile;
    statement.height = transcript.height;
    statement.block_hash = transcript.block_hash;
    statement.previous_chainlock_height = transcript.previous_chainlock_height;
    statement.previous_chainlock_hash = transcript.previous_chainlock_hash;
    statement.quorum_context_hash = transcript.quorum_context_hash;
    statement.roster_transition = transcript.roster_transition;
    statement.roster_beacons = transcript.roster_beacons;
    statement.roster_authorization_state_hash =
        transcript.roster_authorization_state_hash;
    statement.roster_authorization_base =
        transcript.roster_authorization_base;
    statement.previous_btcc_cursor = transcript.previous_btcc_cursor;
    statement.accepted_btcc_cursor = transcript.accepted_btcc_cursor;
    statement.btcc_advance = transcript.btcc_advance;
    statement.btcc_receipt_state = transcript.btcc_receipt_state;
    statement.payment_audit_receipt_state =
        transcript.payment_audit_receipt_state;
    statement.payment_probation_state_hash =
        transcript.payment_probation_state_hash;
    return statement;
}

uint256 ChainLockShare::GetId(const uint256& genesis_hash) const
{
    return GetChainLockShareId(genesis_hash, *this);
}

bool IsSelectedQuorumMask(uint8_t mask)
{
    constexpr uint8_t ACTIVE_MASK{(uint8_t{1} << ACTIVE_QUORUMS) - 1};
    return (mask & ~ACTIVE_MASK) == 0 && std::popcount(mask) == REQUIRED_QUORUMS;
}

bool IsSigningRosterAuthorizationMask(uint8_t mask)
{
    constexpr uint8_t ACTIVE_MASK{(uint8_t{1} << ACTIVE_QUORUMS) - 1};
    if ((mask & ~ACTIVE_MASK) != 0 ||
        static_cast<std::size_t>(std::popcount(mask)) < REQUIRED_QUORUMS) {
        return false;
    }
    // Authorized rosters are always an oldest-to-newest prefix. This leaves
    // exactly 0111 during one in-flight transition and 1111 otherwise.
    return (mask & static_cast<uint8_t>(mask + 1)) == 0;
}

bool FinalChainLock::IsStructurallyValid() const
{
    if (!statement.IsStructurallyValid() || !IsSelectedQuorumMask(selected_quorum_mask)) {
        return false;
    }
    if (signatures.size() != FINAL_SIGNATURE_COUNT ||
        !std::all_of(signatures.begin(), signatures.end(),
                     [](const auto& signature) {
                         return signature.IsStructurallyValid();
                     })) {
        return false;
    }
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const bool selected = (selected_quorum_mask & (uint8_t{1} << slot)) != 0;
        const std::size_t count = CountSet(signer_bitmaps[slot]);
        if ((selected && count != QUORUM_THRESHOLD) || (!selected && count != 0)) return false;
    }
    return true;
}

uint256 FinalChainLock::GetLogicalId(const uint256& genesis_hash) const
{
    return GetLogicalChainLockId(genesis_hash, statement);
}

uint256 FinalChainLock::GetWitnessId(const uint256& genesis_hash) const
{
    return pq::GetWitnessId(genesis_hash, *this);
}

std::optional<std::size_t> FinalChainLock::SignatureOffset(uint8_t quorum_slot,
                                                          uint16_t member_index) const
{
    if (quorum_slot >= ACTIVE_QUORUMS || member_index >= QUORUM_SIZE ||
        !IsStructurallyValid() ||
        (selected_quorum_mask & (uint8_t{1} << quorum_slot)) == 0) {
        return std::nullopt;
    }
    const uint8_t member_mask{static_cast<uint8_t>(uint8_t{1} << (member_index % 8))};
    if ((signer_bitmaps[quorum_slot][member_index / 8] & member_mask) == 0) return std::nullopt;

    std::size_t offset{0};
    for (uint8_t slot{0}; slot < quorum_slot; ++slot) {
        if ((selected_quorum_mask & (uint8_t{1} << slot)) != 0) offset += QUORUM_THRESHOLD;
    }
    for (uint16_t member{0}; member < member_index; ++member) {
        if ((signer_bitmaps[quorum_slot][member / 8] &
             static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0) {
            ++offset;
        }
    }
    return offset;
}

uint256 GetGlobalRegistrationHash(const uint256& genesis_hash,
                                  const uint256& pro_tx_hash,
                                  const GlobalKeyRecord& record,
                                  const uint256& transaction_inputs_hash)
{
    return TaggedHash(GLOBAL_REGISTER_DOMAIN, genesis_hash, pro_tx_hash, record.version,
                      record.profile, record.key_version, record.public_key,
                      record.child_key_commitment, transaction_inputs_hash);
}

uint256 GetGlobalRotationHash(const uint256& genesis_hash,
                              const uint256& pro_tx_hash,
                              const GlobalKeyRecord& old_record,
                              const GlobalKeyRecord& new_record,
                              const uint256& transaction_inputs_hash)
{
    return TaggedHash(
        GLOBAL_ROTATE_DOMAIN, genesis_hash, pro_tx_hash, old_record.version,
        old_record.profile, old_record.key_version, old_record.public_key,
        old_record.child_key_commitment, new_record.version,
        new_record.profile, new_record.key_version, new_record.public_key,
        new_record.child_key_commitment, transaction_inputs_hash);
}

uint256 GetChildRootLeafHash(const uint256& genesis_hash,
                            uint16_t slot,
                            const FrozenChildRootRecord& record)
{
    return TaggedHash(CHILD_ROOT_LEAF_DOMAIN, genesis_hash, record.epoch,
                      slot, record.pro_tx_hash, record.global_key_version,
                      record.commitment);
}

uint256 GetQuorumContextHash(
    const uint256& genesis_hash,
    int32_t target_height,
    const uint256& target_block_hash,
    const std::array<QuorumDescriptor, ACTIVE_QUORUMS>& descriptors)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, QUORUM_CONTEXT_DOMAIN);
    writer << genesis_hash << target_height << target_block_hash;
    for (const auto& descriptor : descriptors) writer << descriptor;
    return writer.GetHash();
}

uint256 GetChainLockShareHash(const uint256& genesis_hash,
                             const ChainLockShareTranscript& transcript)
{
    return TaggedHash(CHAINLOCK_SHARE_DOMAIN, genesis_hash, transcript);
}

uint256 GetChainLockShareId(const uint256& genesis_hash, const ChainLockShare& share)
{
    return TaggedHash(CHAINLOCK_SHARE_ID_DOMAIN, genesis_hash, share);
}

uint256 GetLogicalChainLockId(const uint256& genesis_hash,
                             const ChainLockStatement& statement)
{
    return TaggedHash(CHAINLOCK_LOGICAL_ID_DOMAIN, genesis_hash, statement);
}

uint256 GetWitnessId(const uint256& genesis_hash, const FinalChainLock& chainlock)
{
    return TaggedHash(CHAINLOCK_WITNESS_ID_DOMAIN, genesis_hash, chainlock);
}

} // namespace llmq::pq
