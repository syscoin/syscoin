// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_TYPES_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_TYPES_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace llmq::pq {

inline constexpr uint16_t GLOBAL_KEY_RECORD_VERSION{1};
inline constexpr uint16_t CHILD_KEY_TREE_COMMITMENT_VERSION{1};
inline constexpr uint16_t QUORUM_DESCRIPTOR_VERSION{1};
inline constexpr uint16_t CHAINLOCK_VERSION{1};

inline constexpr uint16_t GLOBAL_SLH_DSA_SHAKE_128S_V1{1};
inline constexpr uint16_t CHILD_SCHEDULED_WOTS_SHAKE_128_V1{1};

inline constexpr std::size_t GLOBAL_PUBLIC_KEY_SIZE{32};
inline constexpr std::size_t GLOBAL_SIGNATURE_SIZE{7856};
inline constexpr std::size_t CHILD_PUBLIC_KEY_SIZE{32};
inline constexpr std::size_t CHILD_SIGNATURE_SIZE{704};
inline constexpr uint16_t CHILD_KEY_TREE_DEPTH{16};
/** One initial tree plus at most fifteen exceptional root replacements. */
inline constexpr uint32_t CHILD_KEY_TREE_MAX_GENERATION{16};
inline constexpr std::size_t CHILD_KEY_TREE_LEAF_COUNT{
    std::size_t{1} << CHILD_KEY_TREE_DEPTH};
inline constexpr std::size_t CHILD_KEY_PROOF_SIZE{
    CHILD_PUBLIC_KEY_SIZE + CHILD_KEY_TREE_DEPTH * 32};

inline constexpr uint16_t SCHEDULED_WOTS_TREE_HEIGHT{8};
inline constexpr uint16_t SCHEDULED_WOTS_TREE_LEAF_COUNT{256};
inline constexpr uint16_t SCHEDULED_WOTS_CHAINLOCK_LEAF_COUNT{231};
inline constexpr uint16_t SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE{
    SCHEDULED_WOTS_CHAINLOCK_LEAF_COUNT};
inline constexpr uint16_t SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_COUNT{4};
inline constexpr uint16_t SCHEDULED_WOTS_USAGE_CAP{235};
static_assert(SCHEDULED_WOTS_USAGE_CAP ==
              SCHEDULED_WOTS_CHAINLOCK_LEAF_COUNT +
                  SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_COUNT);
static_assert(SCHEDULED_WOTS_USAGE_CAP <=
              SCHEDULED_WOTS_TREE_LEAF_COUNT);
inline constexpr std::size_t QUORUM_SIZE{400};
inline constexpr uint16_t QUORUM_MIN_VALID{300};
inline constexpr std::size_t QUORUM_MAX_BYZANTINE{
    (QUORUM_SIZE - 1) / 3};
// With n=400 and f=133, any two 267-member certificates intersect in at
// least 134 members. A conflicting pair therefore requires an honest signer
// to equivocate under the standard <1/3 Byzantine assumption.
inline constexpr std::size_t QUORUM_THRESHOLD{267};
inline constexpr std::size_t ACTIVE_QUORUMS{4};
inline constexpr std::size_t REQUIRED_QUORUMS{3};
inline constexpr std::size_t BITMAP_SIZE{QUORUM_SIZE / 8};
inline constexpr std::size_t FINAL_SIGNATURE_COUNT{REQUIRED_QUORUMS * QUORUM_THRESHOLD};
inline constexpr std::size_t MAX_CHAINLOCK_SIZE{4'000'000};
inline constexpr std::string_view GLOBAL_REGISTER_DOMAIN{"SYS_PQ_GLOBAL_REGISTER_V1"};
inline constexpr std::string_view GLOBAL_ROTATE_DOMAIN{"SYS_PQ_GLOBAL_ROTATE_V1"};
inline constexpr std::string_view CHILD_ROOT_LEAF_DOMAIN{"SYS_PQ_CHILD_ROOT_LEAF_V1"};
inline constexpr std::string_view QUORUM_CONTEXT_DOMAIN{"SYS_PQ_QUORUM_CONTEXT_V1"};
inline constexpr std::string_view CHAINLOCK_SHARE_DOMAIN{"SYS_PQ_CHAINLOCK_SHARE_V1"};
inline constexpr std::string_view CHAINLOCK_SHARE_ID_DOMAIN{"SYS_PQ_CHAINLOCK_SHARE_ID_V1"};
inline constexpr std::string_view CHAINLOCK_LOGICAL_ID_DOMAIN{"SYS_PQ_CHAINLOCK_LOGICAL_ID_V1"};
inline constexpr std::string_view CHAINLOCK_WITNESS_ID_DOMAIN{"SYS_PQ_CHAINLOCK_WITNESS_ID_V1"};

static_assert(QUORUM_SIZE % 8 == 0);
static_assert(QUORUM_THRESHOLD == 2 * QUORUM_MAX_BYZANTINE + 1);
static_assert(2 * QUORUM_THRESHOLD - QUORUM_SIZE > QUORUM_MAX_BYZANTINE);
static_assert(QUORUM_THRESHOLD <= QUORUM_SIZE - QUORUM_MAX_BYZANTINE);

[[nodiscard]] inline constexpr bool IsValidChildKeyTreeGeneration(
    uint32_t generation) noexcept
{
    return generation >= 1 &&
           generation <= CHILD_KEY_TREE_MAX_GENERATION;
}

[[nodiscard]] inline constexpr bool CanAdvanceChildKeyTreeGeneration(
    uint32_t generation) noexcept
{
    return generation >= 1 &&
           generation < CHILD_KEY_TREE_MAX_GENERATION;
}

using GlobalPublicKey = std::array<uint8_t, GLOBAL_PUBLIC_KEY_SIZE>;
using GlobalSignature = std::array<uint8_t, GLOBAL_SIGNATURE_SIZE>;
using ChildPublicKey = std::array<uint8_t, CHILD_PUBLIC_KEY_SIZE>;
using ChildSignature = std::array<uint8_t, CHILD_SIGNATURE_SIZE>;
using QuorumBitmap = std::array<uint8_t, BITMAP_SIZE>;

/** One fixed 2^16-epoch commitment authorized by the global operator key. */
struct ChildKeyTreeCommitment {
    static constexpr std::size_t WIRE_SIZE{
        4 * sizeof(uint16_t) + 2 * sizeof(uint32_t) + 2 * 32};

    uint16_t version{CHILD_KEY_TREE_COMMITMENT_VERSION};
    uint16_t profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    uint16_t usage_cap{SCHEDULED_WOTS_USAGE_CAP};
    uint16_t depth{CHILD_KEY_TREE_DEPTH};
    uint32_t generation{0};
    uint32_t first_epoch{0};
    uint256 tree_id;
    uint256 root;

    SERIALIZE_METHODS(ChildKeyTreeCommitment, obj)
    {
        READWRITE(obj.version, obj.profile, obj.usage_cap, obj.depth,
                  obj.generation, obj.first_epoch, obj.tree_id, obj.root);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool CoversEpoch(uint32_t epoch) const noexcept;
    friend bool operator==(const ChildKeyTreeCommitment&,
                           const ChildKeyTreeCommitment&) = default;
};

static_assert(ChildKeyTreeCommitment::WIRE_SIZE == 80);

enum class BTCCAdvance : uint8_t {
    KEEP = 0,
    ADVANCE = 1,
};

struct GlobalKeyRecord {
    uint16_t version{GLOBAL_KEY_RECORD_VERSION};
    uint16_t profile{GLOBAL_SLH_DSA_SHAKE_128S_V1};
    uint32_t key_version{0};
    GlobalPublicKey public_key{};
    ChildKeyTreeCommitment child_key_commitment;
    uint32_t activated_height{0};

    SERIALIZE_METHODS(GlobalKeyRecord, obj)
    {
        READWRITE(obj.version, obj.profile, obj.key_version, obj.public_key,
                  obj.child_key_commitment, obj.activated_height);
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const GlobalKeyRecord&, const GlobalKeyRecord&) = default;
};

/** Root metadata frozen for one operator at one quorum-registration cutoff. */
struct FrozenChildRootRecord {
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    uint32_t epoch{0};
    ChildKeyTreeCommitment commitment;

    SERIALIZE_METHODS(FrozenChildRootRecord, obj)
    {
        READWRITE(obj.pro_tx_hash, obj.global_key_version, obj.epoch,
                  obj.commitment);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const FrozenChildRootRecord&,
                           const FrozenChildRootRecord&) = default;
};

/** Exact, allocation-free membership witness carried by every share. */
struct ChildKeyProof {
    static constexpr std::size_t WIRE_SIZE{CHILD_KEY_PROOF_SIZE};

    ChildPublicKey public_key{};
    std::array<uint256, CHILD_KEY_TREE_DEPTH> siblings{};

    SERIALIZE_METHODS(ChildKeyProof, obj)
    {
        READWRITE(obj.public_key);
        for (auto& sibling : obj.siblings) READWRITE(sibling);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const ChildKeyProof&, const ChildKeyProof&) = default;
};

/** A scheduled WOTS+ signature plus its exact public-key authorization witness. */
struct AuthenticatedChildSignature {
    static constexpr std::size_t WIRE_SIZE{
        ChildKeyProof::WIRE_SIZE + CHILD_SIGNATURE_SIZE};

    ChildKeyProof key_proof;
    ChildSignature signature{};

    SERIALIZE_METHODS(AuthenticatedChildSignature, obj)
    {
        READWRITE(obj.key_proof, obj.signature);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return key_proof.IsStructurallyValid();
    }
    friend bool operator==(const AuthenticatedChildSignature&,
                           const AuthenticatedChildSignature&) = default;
};

struct BTCCursor {
    static constexpr std::size_t WIRE_SIZE{sizeof(int32_t) + 2 * 32};

    int32_t sys_height{-1};
    uint256 sys_hash;
    uint256 btc_hash;

    SERIALIZE_METHODS(BTCCursor, obj)
    {
        READWRITE(obj.sys_height, obj.sys_hash, obj.btc_hash);
    }

    [[nodiscard]] bool IsNull() const;
    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const BTCCursor&, const BTCCursor&) = default;
};

inline constexpr uint16_t ROSTER_BEACON_VERSION{1};
inline constexpr uint16_t ROSTER_BEACON_BUNDLE_VERSION{1};
inline constexpr uint32_t ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA{37};
inline constexpr uint32_t ROSTER_BEACON_MAX_ANCHOR_BTC_LAG{6};

enum class RosterBeaconAnchorKind : uint8_t {
    NORMAL = 1,
    RECOVERY = 2,
};

enum class RosterBeaconState : uint8_t {
    EMPTY = 0,
    PENDING = 1,
    READY = 2,
};

/**
 * Non-self-referential delayed-Bitcoin observation for one roster epoch.
 * The future height is implied by anchor_btc_height + 37, so PENDING can be
 * signed before the corresponding Bitcoin hash is knowable.
 */
struct RosterBeaconSeed {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 2 * sizeof(uint8_t) + sizeof(uint32_t) +
        sizeof(int32_t) + 32 + BTCCursor::WIRE_SIZE};

    uint16_t version{ROSTER_BEACON_VERSION};
    RosterBeaconAnchorKind anchor_kind{RosterBeaconAnchorKind::NORMAL};
    RosterBeaconState state{RosterBeaconState::EMPTY};
    uint32_t epoch{0};
    BTCCursor anchor_cursor;
    int32_t anchor_btc_height{-1};
    uint256 future_btc_hash;

    SERIALIZE_METHODS(RosterBeaconSeed, obj)
    {
        uint8_t anchor_kind{static_cast<uint8_t>(obj.anchor_kind)};
        uint8_t state{static_cast<uint8_t>(obj.state)};
        READWRITE(obj.version, anchor_kind, state, obj.epoch,
                  obj.anchor_cursor, obj.anchor_btc_height,
                  obj.future_btc_hash);
        SER_READ(obj, obj.anchor_kind =
                          static_cast<RosterBeaconAnchorKind>(anchor_kind));
        SER_READ(obj, obj.state = static_cast<RosterBeaconState>(state));
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical roster beacon seed");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsReady() const noexcept;
    [[nodiscard]] std::optional<int32_t> FutureBTCHeight() const noexcept;
    friend bool operator==(const RosterBeaconSeed&,
                           const RosterBeaconSeed&) = default;
};

static_assert(RosterBeaconSeed::WIRE_SIZE == 112);

enum class RecoveryRosterAuthoritySourceKind : uint8_t {
    NONE = 0,
    ACTIVATION = 1,
    NORMAL_ROSTERS = 2,
};

/**
 * Non-recursive source from which fixed recovery membership is reproduced.
 * INITIALIZE names the exact activation predecessor. RECOVER snapshots one
 * fully normal, already-authorized roster context; mixed windows retain the
 * source that introduced their fixed authority.
 */
struct RecoveryRosterAuthoritySource {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint8_t) + sizeof(int32_t) + 2 * 32 +
        ACTIVE_QUORUMS * RosterBeaconSeed::WIRE_SIZE};

    RecoveryRosterAuthoritySourceKind kind{
        RecoveryRosterAuthoritySourceKind::NONE};
    int32_t height{-1};
    uint256 block_hash;
    uint256 quorum_context_hash;
    std::array<RosterBeaconSeed, ACTIVE_QUORUMS> normal_beacons{};

    SERIALIZE_METHODS(RecoveryRosterAuthoritySource, obj)
    {
        uint8_t kind{static_cast<uint8_t>(obj.kind)};
        READWRITE(kind, obj.height, obj.block_hash,
                  obj.quorum_context_hash);
        for (auto& beacon : obj.normal_beacons) READWRITE(beacon);
        SER_READ(obj, obj.kind =
                          static_cast<RecoveryRosterAuthoritySourceKind>(kind));
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical recovery roster authority source");
        });
    }

    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RecoveryRosterAuthoritySource&,
                           const RecoveryRosterAuthoritySource&) = default;
};

static_assert(RecoveryRosterAuthoritySource::WIRE_SIZE == 517);

/** Oldest-to-newest READY beacon identities for the four active rosters. */
struct ActiveRosterBeaconBundle {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + ACTIVE_QUORUMS * RosterBeaconSeed::WIRE_SIZE +
        32 + RecoveryRosterAuthoritySource::WIRE_SIZE};

    uint16_t version{ROSTER_BEACON_BUNDLE_VERSION};
    std::array<RosterBeaconSeed, ACTIVE_QUORUMS> seeds{};
    uint256 recovery_authority_hash;
    RecoveryRosterAuthoritySource recovery_authority_source;

    SERIALIZE_METHODS(ActiveRosterBeaconBundle, obj)
    {
        READWRITE(obj.version);
        for (auto& seed : obj.seeds) READWRITE(seed);
        READWRITE(obj.recovery_authority_hash,
                  obj.recovery_authority_source);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical active roster beacon bundle");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsForNewestEpoch(uint32_t newest_epoch) const noexcept;
    friend bool operator==(const ActiveRosterBeaconBundle&,
                           const ActiveRosterBeaconBundle&) = default;
};

static_assert(ActiveRosterBeaconBundle::WIRE_SIZE == 999);

/** The active four READY beacons plus the next EMPTY/PENDING/READY record. */
struct RosterBeaconWindow {
    static constexpr std::size_t WIRE_SIZE{
        ActiveRosterBeaconBundle::WIRE_SIZE + RosterBeaconSeed::WIRE_SIZE};

    ActiveRosterBeaconBundle active;
    RosterBeaconSeed next;

    SERIALIZE_METHODS(RosterBeaconWindow, obj)
    {
        READWRITE(obj.active, obj.next);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical roster beacon window");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const RosterBeaconWindow&,
                           const RosterBeaconWindow&) = default;
};

static_assert(RosterBeaconWindow::WIRE_SIZE == 1'111);

enum class RosterAuthorizationTransitionKind : uint8_t {
    INITIALIZE = 0,
    KEEP = 1,
    OBSERVE = 2,
    REVEAL = 3,
    ROTATE = 4,
    RECOVER = 5,
};

/**
 * Compact branch-local accumulator over accepted on-chain BTCC receipts.
 * Every ChainLock signs this state, so the first verified descendant seals
 * the exact ordered receipt history without retaining each full
 * witness.
 */
struct BTCCReceiptState {
    static constexpr std::size_t WIRE_SIZE{sizeof(int32_t) + 3 * 32};

    BTCCursor cursor;
    uint256 cumulative_hash;

    SERIALIZE_METHODS(BTCCReceiptState, obj)
    {
        READWRITE(obj.cursor, obj.cumulative_hash);
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const BTCCReceiptState&,
                           const BTCCReceiptState&) = default;
};

static_assert(BTCCReceiptState::WIRE_SIZE == 100);

/** Compact branch-local accumulator over accepted payment-audit receipts. */
struct PaymentAuditReceiptCursor {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(int32_t) + sizeof(uint32_t) + 3 * 32};

    int32_t carrier_height{-1};
    uint32_t epoch{0};
    uint256 seal_block_hash;
    uint256 audit_logical_id;
    uint256 audit_witness_id;

    SERIALIZE_METHODS(PaymentAuditReceiptCursor, obj)
    {
        READWRITE(obj.carrier_height, obj.epoch, obj.seal_block_hash,
                  obj.audit_logical_id, obj.audit_witness_id);
    }

    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditReceiptCursor&,
                           const PaymentAuditReceiptCursor&) = default;
};

struct PaymentAuditReceiptState {
    static constexpr std::size_t WIRE_SIZE{
        PaymentAuditReceiptCursor::WIRE_SIZE + 32};

    PaymentAuditReceiptCursor cursor;
    uint256 cumulative_hash;

    SERIALIZE_METHODS(PaymentAuditReceiptState, obj)
    {
        READWRITE(obj.cursor, obj.cumulative_hash);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditReceiptState&,
                           const PaymentAuditReceiptState&) = default;
};

static_assert(PaymentAuditReceiptState::WIRE_SIZE == 136);

struct QuorumDescriptor {
    uint16_t version{QUORUM_DESCRIPTOR_VERSION};
    uint32_t epoch{0};
    int32_t base_height{-1};
    uint256 base_hash;
    int32_t snapshot_height{-1};
    uint256 snapshot_hash;
    uint256 roster_beacon_hash;
    uint16_t profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    uint16_t usage_cap{SCHEDULED_WOTS_USAGE_CAP};
    QuorumBitmap valid_members{};
    uint256 member_root;
    uint256 child_key_root;
    uint16_t valid_count{0};

    SERIALIZE_METHODS(QuorumDescriptor, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.base_height, obj.base_hash,
                  obj.snapshot_height, obj.snapshot_hash,
                  obj.roster_beacon_hash, obj.profile, obj.usage_cap,
                  obj.valid_members, obj.member_root, obj.child_key_root,
                  obj.valid_count);
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const QuorumDescriptor&, const QuorumDescriptor&) = default;
};

struct ChainLockShareTranscript {
    uint16_t chainlock_version{CHAINLOCK_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    int32_t height{-1};
    uint256 block_hash;
    int32_t previous_chainlock_height{-1};
    uint256 previous_chainlock_hash;
    uint256 quorum_context_hash;
    RosterAuthorizationTransitionKind roster_transition{
        RosterAuthorizationTransitionKind::INITIALIZE};
    RosterBeaconWindow roster_beacons;
    uint256 roster_authorization_state_hash;
    uint32_t quorum_epoch{0};
    uint256 quorum_base_hash;
    uint16_t member_index{std::numeric_limits<uint16_t>::max()};
    uint256 member_pro_tx_hash;
    BTCCursor previous_btcc_cursor;
    BTCCursor accepted_btcc_cursor;
    BTCCAdvance btcc_advance{BTCCAdvance::KEEP};
    BTCCReceiptState btcc_receipt_state;
    PaymentAuditReceiptState payment_audit_receipt_state;
    uint256 payment_probation_state_hash;

    SERIALIZE_METHODS(ChainLockShareTranscript, obj)
    {
        uint8_t btcc_advance{static_cast<uint8_t>(obj.btcc_advance)};
        uint8_t roster_transition{
            static_cast<uint8_t>(obj.roster_transition)};
        READWRITE(obj.chainlock_version, obj.child_profile, obj.height, obj.block_hash,
                  obj.previous_chainlock_height, obj.previous_chainlock_hash,
                  obj.quorum_context_hash, roster_transition,
                  obj.roster_beacons, obj.roster_authorization_state_hash,
                  obj.quorum_epoch, obj.quorum_base_hash,
                  obj.member_index, obj.member_pro_tx_hash,
                  obj.previous_btcc_cursor, obj.accepted_btcc_cursor,
                  btcc_advance, obj.btcc_receipt_state,
                  obj.payment_audit_receipt_state,
                  obj.payment_probation_state_hash);
        SER_READ(obj, obj.btcc_advance = static_cast<BTCCAdvance>(btcc_advance));
        SER_READ(obj, obj.roster_transition =
                          static_cast<RosterAuthorizationTransitionKind>(
                              roster_transition));
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const ChainLockShareTranscript&, const ChainLockShareTranscript&) = default;
};

struct ChainLockStatement {
    static constexpr std::size_t WIRE_SIZE{
        2 * sizeof(uint16_t) + 2 * sizeof(int32_t) + 3 * 32 +
        sizeof(uint8_t) + RosterBeaconWindow::WIRE_SIZE + 32 +
        2 * BTCCursor::WIRE_SIZE + sizeof(uint8_t) +
        BTCCReceiptState::WIRE_SIZE +
        PaymentAuditReceiptState::WIRE_SIZE + 32};
    uint16_t version{CHAINLOCK_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    int32_t height{-1};
    uint256 block_hash;
    int32_t previous_chainlock_height{-1};
    uint256 previous_chainlock_hash;
    uint256 quorum_context_hash;
    RosterAuthorizationTransitionKind roster_transition{
        RosterAuthorizationTransitionKind::INITIALIZE};
    RosterBeaconWindow roster_beacons;
    uint256 roster_authorization_state_hash;
    BTCCursor previous_btcc_cursor;
    BTCCursor accepted_btcc_cursor;
    BTCCAdvance btcc_advance{BTCCAdvance::KEEP};
    BTCCReceiptState btcc_receipt_state;
    PaymentAuditReceiptState payment_audit_receipt_state;
    uint256 payment_probation_state_hash;

    SERIALIZE_METHODS(ChainLockStatement, obj)
    {
        uint8_t btcc_advance{static_cast<uint8_t>(obj.btcc_advance)};
        uint8_t roster_transition{
            static_cast<uint8_t>(obj.roster_transition)};
        READWRITE(obj.version, obj.child_profile, obj.height, obj.block_hash,
                  obj.previous_chainlock_height, obj.previous_chainlock_hash,
                  obj.quorum_context_hash, roster_transition,
                  obj.roster_beacons, obj.roster_authorization_state_hash,
                  obj.previous_btcc_cursor,
                  obj.accepted_btcc_cursor, btcc_advance,
                  obj.btcc_receipt_state,
                  obj.payment_audit_receipt_state,
                  obj.payment_probation_state_hash);
        SER_READ(obj, obj.btcc_advance = static_cast<BTCCAdvance>(btcc_advance));
        SER_READ(obj, obj.roster_transition =
                          static_cast<RosterAuthorizationTransitionKind>(
                              roster_transition));
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const ChainLockStatement&, const ChainLockStatement&) = default;
};

/**
 * One member's fixed-width ChainLock vote. Shares are restricted to
 * authenticated quorum links; the final CLSIG remains the public object.
 */
struct ChainLockShare {
    static constexpr std::size_t WIRE_SIZE{
        2 * sizeof(uint16_t) + 2 * sizeof(int32_t) + 7 * 32 +
        sizeof(uint8_t) + RosterBeaconWindow::WIRE_SIZE + 32 +
        sizeof(uint32_t) + sizeof(uint16_t) + sizeof(int32_t) +
        sizeof(uint8_t) + sizeof(int32_t) + 2 * 32 +
        BTCCReceiptState::WIRE_SIZE +
        PaymentAuditReceiptState::WIRE_SIZE + 32 +
        AuthenticatedChildSignature::WIRE_SIZE};
    static_assert(WIRE_SIZE == 2'975);

    ChainLockShareTranscript transcript;
    AuthenticatedChildSignature authenticated_signature;

    SERIALIZE_METHODS(ChainLockShare, obj)
    {
        READWRITE(obj.transcript, obj.authenticated_signature);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ ChainLock share");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    [[nodiscard]] ChainLockStatement GetStatement() const;
    [[nodiscard]] uint256 GetId(const uint256& genesis_hash) const;
    friend bool operator==(const ChainLockShare&, const ChainLockShare&) = default;
};

[[nodiscard]] std::size_t CountSet(const QuorumBitmap& bitmap);
[[nodiscard]] bool IsSelectedQuorumMask(uint8_t mask);
[[nodiscard]] bool IsSigningRosterAuthorizationMask(uint8_t mask);

struct FinalChainLock {
    static constexpr std::size_t WIRE_SIZE{
        ChainLockStatement::WIRE_SIZE + sizeof(uint8_t) +
        ACTIVE_QUORUMS * BITMAP_SIZE + sizeof(uint16_t) +
        FINAL_SIGNATURE_COUNT * AuthenticatedChildSignature::WIRE_SIZE};
    static_assert(WIRE_SIZE < MAX_CHAINLOCK_SIZE);
    static_assert(WIRE_SIZE == 1'001'508);

    ChainLockStatement statement;
    uint8_t selected_quorum_mask{0};
    std::array<QuorumBitmap, ACTIVE_QUORUMS> signer_bitmaps{};
    std::vector<AuthenticatedChildSignature> signatures;

    SERIALIZE_METHODS(FinalChainLock, obj)
    {
        READWRITE(obj.statement, obj.selected_quorum_mask);
        SER_READ(obj, if (!obj.statement.IsStructurallyValid() ||
                          !IsSelectedQuorumMask(obj.selected_quorum_mask)) {
            throw std::ios_base::failure("invalid PQ ChainLock header");
        });
        for (auto& bitmap : obj.signer_bitmaps) READWRITE(bitmap);
        SER_READ(obj, for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            const bool selected = (obj.selected_quorum_mask & (uint8_t{1} << slot)) != 0;
            const std::size_t count = CountSet(obj.signer_bitmaps[slot]);
            if ((selected && count != QUORUM_THRESHOLD) || (!selected && count != 0)) {
                throw std::ios_base::failure("invalid PQ ChainLock signer bitmap");
            }
        });
        SER_READ(obj, if (FinalChainLock::WIRE_SIZE > MAX_CHAINLOCK_SIZE) {
            throw std::ios_base::failure("oversize PQ ChainLock");
        });
        uint16_t signature_count{static_cast<uint16_t>(obj.signatures.size())};
        SER_WRITE(obj, if (obj.signatures.size() != FINAL_SIGNATURE_COUNT) {
            throw std::ios_base::failure("invalid PQ ChainLock signature count");
        });
        READWRITE(signature_count);
        SER_READ(obj, if (signature_count != FINAL_SIGNATURE_COUNT) {
            throw std::ios_base::failure("invalid PQ ChainLock signature count");
        });
        SER_READ(obj, obj.signatures.resize(FINAL_SIGNATURE_COUNT));
        for (auto& signature : obj.signatures) READWRITE(signature);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ ChainLock");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const;
    [[nodiscard]] uint256 GetLogicalId(const uint256& genesis_hash) const;
    [[nodiscard]] uint256 GetWitnessId(const uint256& genesis_hash) const;
    [[nodiscard]] std::optional<std::size_t> SignatureOffset(uint8_t quorum_slot,
                                                            uint16_t member_index) const;
    friend bool operator==(const FinalChainLock&, const FinalChainLock&) = default;
};

[[nodiscard]] uint256 GetGlobalRegistrationHash(const uint256& genesis_hash,
                                                const uint256& pro_tx_hash,
                                                const GlobalKeyRecord& record,
                                                const uint256& transaction_inputs_hash);
[[nodiscard]] uint256 GetGlobalRotationHash(const uint256& genesis_hash,
                                            const uint256& pro_tx_hash,
                                            const GlobalKeyRecord& old_record,
                                            const GlobalKeyRecord& new_record,
                                            const uint256& transaction_inputs_hash);
[[nodiscard]] uint256 GetChildRootLeafHash(
    const uint256& genesis_hash,
    uint16_t slot,
    const FrozenChildRootRecord& record);
[[nodiscard]] uint256 GetQuorumContextHash(
    const uint256& genesis_hash,
    int32_t target_height,
    const uint256& target_block_hash,
    const std::array<QuorumDescriptor, ACTIVE_QUORUMS>& descriptors);
[[nodiscard]] uint256 GetChainLockShareHash(const uint256& genesis_hash,
                                           const ChainLockShareTranscript& transcript);
[[nodiscard]] uint256 GetChainLockShareId(const uint256& genesis_hash,
                                         const ChainLockShare& share);
[[nodiscard]] uint256 GetLogicalChainLockId(const uint256& genesis_hash,
                                           const ChainLockStatement& statement);
[[nodiscard]] uint256 GetWitnessId(const uint256& genesis_hash, const FinalChainLock& chainlock);

template <typename Stream>
FinalChainLock ReadFinalChainLock(Stream& stream, std::size_t payload_size)
{
    if (payload_size != FinalChainLock::WIRE_SIZE || payload_size > MAX_CHAINLOCK_SIZE) {
        throw std::ios_base::failure("invalid PQ ChainLock payload size");
    }
    FinalChainLock chainlock;
    stream >> chainlock;
    return chainlock;
}

[[nodiscard]] constexpr std::size_t FinalChainLockSerializedSize()
{
    return FinalChainLock::WIRE_SIZE;
}

static_assert(FinalChainLockSerializedSize() < MAX_CHAINLOCK_SIZE);
static_assert(ChainLockShare::WIRE_SIZE == 2'975);
static_assert(FinalChainLockSerializedSize() == 1'001'508);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_TYPES_H
