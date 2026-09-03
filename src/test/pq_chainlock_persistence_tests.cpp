// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_persistence.h>
#include <llmq/pq_roster_beacon.h>

#include <chain.h>
#include <chainparams.h>
#include <node/blockstorage.h>
#include <test/util/setup_common.h>
#include <util/signalinterrupt.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace llmq::pq {

class PaymentAuditSealContextCapsuleTestAccess {
public:
    static PaymentAuditSealContextCapsule Make(
        const uint256& genesis_hash,
        const ChainLockFinalityStoreConfig& config,
        uint32_t epoch,
        const FinalChainLock& seal,
        uint8_t authorization_mask)
    {
        const PaymentAuditScheduleConfig schedule_config{
            config.chainlock_schedule, config.btcc_schedule};
        const auto schedule{
            BuildPaymentAuditEpochSchedule(schedule_config, epoch)};
        BOOST_REQUIRE(schedule);
        BOOST_REQUIRE_EQUAL(schedule->seal_height,
                            seal.statement.height);
        PaymentAuditSealContextCapsule capsule{
            epoch, schedule->carrier_end_height_exclusive,
            FinalChainLockRecordMetadata{
                seal.GetLogicalId(genesis_hash),
                seal.GetWitnessId(genesis_hash), seal.statement},
            authorization_mask};
        BOOST_REQUIRE(capsule.IsInternallyConsistent(
            genesis_hash, config));
        return capsule;
    }
};

} // namespace llmq::pq

namespace {

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

RosterBeaconSeed MakeInitializationPendingSeed(
    uint32_t newest_epoch,
    uint64_t salt,
    int32_t anchor_height = 870)
{
    RosterBeaconSeed seed;
    seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
    seed.state = RosterBeaconState::PENDING;
    seed.epoch = newest_epoch;
    seed.anchor_cursor = BTCCursor{
        anchor_height, NonNullHash(700'000 + salt),
        NonNullHash(710'000 + salt)};
    seed.anchor_btc_height = 900'000 + static_cast<int32_t>(salt);
    BOOST_REQUIRE(seed.IsStructurallyValid());
    return seed;
}

RosterBeaconWindow MakeRecoveryWindow(
    const RecoveryRosterAuthoritySource& source,
    uint32_t newest_epoch)
{
    const auto window{MakeRecoveryRosterBeaconWindow(
        source, newest_epoch)};
    BOOST_REQUIRE(window);
    return *window;
}

RosterBeaconWindow MakeInitializationWindow(
    const RosterBeaconSeed& pending,
    uint64_t salt)
{
    BOOST_REQUIRE(pending.anchor_kind == RosterBeaconAnchorKind::NORMAL);
    BOOST_REQUIRE(pending.epoch >= ACTIVE_QUORUMS - 1);
    RosterBeaconWindow window;
    const uint256 future_hash{NonNullHash(720'000 + salt)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& seed{window.active.seeds[slot]};
        seed = pending;
        seed.state = RosterBeaconState::READY;
        seed.epoch = pending.epoch - (ACTIVE_QUORUMS - 1) + slot;
        seed.future_btc_hash = future_hash;
    }
    window.active.recovery_authority_source.normal_beacon =
        window.active.seeds.back();
    window.next.epoch = pending.epoch + 1;
    BOOST_REQUIRE(IsInitialNormalRosterBeaconWindow(window));
    return window;
}

RosterBeaconWindow MakeNormalWindow()
{
    RosterBeaconWindow window;
    const auto pending{MakeInitializationPendingSeed(3, 900'000)};
    const uint256 future_hash{NonNullHash(1'620'001)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& seed{window.active.seeds[slot]};
        seed = pending;
        seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
        seed.state = RosterBeaconState::READY;
        seed.epoch = slot;
        seed.future_btc_hash = future_hash;
    }
    window.active.recovery_authority_source.normal_beacon =
        window.active.seeds.back();
    window.next.epoch = ACTIVE_QUORUMS;
    BOOST_REQUIRE(window.IsStructurallyValid());
    return window;
}

RosterRecoveryPrecommit MakeInitializationPrecommit(
    uint64_t salt,
    int32_t anchor_height = 865,
    uint32_t epoch = ACTIVE_QUORUMS - 1)
{
    RosterRecoveryPrecommit precommit;
    precommit.pending_seed =
        MakeInitializationPendingSeed(epoch, salt, anchor_height);
    BOOST_REQUIRE(precommit.IsStructurallyValid());
    return precommit;
}

FinalChainLock MakeChainLock(int32_t height,
                             int32_t previous_height,
                             const uint256& previous_hash,
                             uint64_t salt)
{
    FinalChainLock chainlock;
    chainlock.statement.height = height;
    chainlock.statement.block_hash = NonNullHash(10000 + salt);
    chainlock.statement.previous_chainlock_height = previous_height;
    chainlock.statement.previous_chainlock_hash = previous_hash;
    chainlock.statement.quorum_context_hash = NonNullHash(20000 + salt);
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    chainlock.statement.roster_beacons = MakeNormalWindow();
    chainlock.statement.roster_authorization_state_hash =
        NonNullHash(25'000 + salt);
    if (previous_height >= 0) {
        chainlock.statement.roster_authorization_base = {
            previous_height, previous_hash,
            NonNullHash(26'000 + salt)};
    }
    chainlock.statement.payment_probation_state_hash = NonNullHash(30'000);
    chainlock.selected_quorum_mask = 0b0111;
    chainlock.signatures.resize(FINAL_SIGNATURE_COUNT);
    for (auto& authenticated : chainlock.signatures) {
        authenticated.key_proof.public_key[0] = 1;
    }
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        SetFirstMembers(chainlock.signer_bitmaps[slot], QUORUM_THRESHOLD);
    }
    chainlock.signatures.front().signature.front() = static_cast<uint8_t>(salt);
    return chainlock;
}

void SetInitializationTransition(
    FinalChainLock& chainlock,
    const RosterRecoveryPrecommit& precommit,
    const uint256& genesis_hash,
    uint64_t salt)
{
    chainlock.statement.block_hash =
        precommit.pending_seed.anchor_cursor.sys_hash;
    chainlock.statement.accepted_btcc_cursor =
        precommit.pending_seed.anchor_cursor;
    chainlock.statement.btcc_advance = BTCCAdvance::ADVANCE;
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    chainlock.statement.roster_authorization_base = {};
    chainlock.statement.roster_beacons =
        MakeInitializationWindow(precommit.pending_seed, salt);
    (void)genesis_hash;
    chainlock.statement.roster_authorization_state_hash =
        NonNullHash(730'000 + salt);
}

void SetExactRosterAuthorizationStateHash(
    FinalChainLock& chainlock,
    const uint256& genesis_hash,
    const FinalChainLock* prior = nullptr)
{
    RosterAuthorizationTransition transition;
    transition.kind = chainlock.statement.roster_transition;
    transition.target_height = chainlock.statement.height;
    transition.target_block_hash = chainlock.statement.block_hash;
    transition.predecessor_height =
        chainlock.statement.previous_chainlock_height;
    transition.predecessor_block_hash =
        chainlock.statement.previous_chainlock_hash;
    if (prior) {
        chainlock.statement.roster_authorization_base = {
            prior->statement.height, prior->statement.block_hash,
            prior->GetLogicalId(genesis_hash)};
    }
    transition.authorization_base =
        chainlock.statement.roster_authorization_base;
    transition.new_window = chainlock.statement.roster_beacons;
    if (prior) {
        transition.previous = RosterAuthorizationPriorState{
            prior->statement.roster_authorization_state_hash,
            prior->statement.roster_beacons};
    }
    const auto state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    BOOST_REQUIRE(state_hash);
    chainlock.statement.roster_authorization_state_hash = *state_hash;
}

void SetExactInitialization(
    FinalChainLock& chainlock,
    const uint256& genesis_hash,
    uint64_t salt)
{
    auto precommit{MakeInitializationPrecommit(
        salt, chainlock.statement.height)};
    precommit.pending_seed.anchor_cursor.sys_hash =
        chainlock.statement.block_hash;
    precommit.pending_seed.anchor_cursor.btc_hash =
        NonNullHash(42'100'000 + salt);
    BOOST_REQUIRE(precommit.IsStructurallyValid());
    SetInitializationTransition(chainlock, precommit, genesis_hash, salt);
    SetExactRosterAuthorizationStateHash(chainlock, genesis_hash);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
}

void SetExactContinuation(FinalChainLock& chainlock,
                          const uint256& genesis_hash,
                          const FinalChainLock& prior)
{
    if (chainlock.statement.accepted_btcc_cursor.IsNull() &&
        !prior.statement.accepted_btcc_cursor.IsNull()) {
        chainlock.statement.previous_btcc_cursor =
            prior.statement.accepted_btcc_cursor;
        chainlock.statement.accepted_btcc_cursor =
            prior.statement.accepted_btcc_cursor;
    }
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    chainlock.statement.roster_beacons =
        prior.statement.roster_beacons;
    SetExactRosterAuthorizationStateHash(
        chainlock, genesis_hash, &prior);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
}

RecoveryRosterAuthoritySource RecoverySourceFromPrior(
    const FinalChainLock& prior)
{
    const auto& source{prior.statement.roster_beacons.active
                           .recovery_authority_source};
    BOOST_REQUIRE(!source.IsNull());
    return source;
}

void SetExactRecoveryTransitionFromPrior(
    FinalChainLock& chainlock,
    const uint256& genesis_hash,
    const FinalChainLock& prior,
    uint32_t newest_epoch)
{
    chainlock.statement.previous_btcc_cursor =
        prior.statement.accepted_btcc_cursor;
    chainlock.statement.accepted_btcc_cursor =
        prior.statement.accepted_btcc_cursor;
    chainlock.statement.btcc_advance = BTCCAdvance::KEEP;
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    chainlock.statement.roster_beacons = MakeRecoveryWindow(
        RecoverySourceFromPrior(prior), newest_epoch);
    SetExactRosterAuthorizationStateHash(
        chainlock, genesis_hash, &prior);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
}

void SetExactPostRecoveryRotation(FinalChainLock& chainlock,
                                  const uint256& genesis_hash,
                                  const FinalChainLock& prior)
{
    SetExactContinuation(chainlock, genesis_hash, prior);
    auto& window{chainlock.statement.roster_beacons};
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] = window.active.seeds[slot + 1];
    }
    auto normal_seed{prior.statement.roster_beacons.next};
    if (normal_seed.state == RosterBeaconState::PENDING) {
        normal_seed.state = RosterBeaconState::READY;
        normal_seed.future_btc_hash = NonNullHash(630'000);
    }
    BOOST_REQUIRE(normal_seed.IsReady());
    window.active.seeds.back() = std::move(normal_seed);
    window.next = {};
    window.next.epoch = window.active.seeds.back().epoch + 1;
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::ROTATE;
    SetExactRosterAuthorizationStateHash(
        chainlock, genesis_hash, &prior);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
    BOOST_REQUIRE(HasRecoveryRosterBeacon(window));
    BOOST_REQUIRE(!IsRecoveryRosterBeaconWindow(window));
}

void SetExactRecoveryObservation(FinalChainLock& chainlock,
                                 const uint256& genesis_hash,
                                 const FinalChainLock& prior)
{
    SetExactContinuation(chainlock, genesis_hash, prior);
    auto& next{chainlock.statement.roster_beacons.next};
    BOOST_REQUIRE(next.state == RosterBeaconState::EMPTY);
    const auto source{RecoverySourceFromPrior(prior).normal_beacon};
    next.state = RosterBeaconState::PENDING;
    next.anchor_cursor = source.anchor_cursor;
    next.anchor_btc_height = source.anchor_btc_height;
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::OBSERVE;
    SetExactRosterAuthorizationStateHash(
        chainlock, genesis_hash, &prior);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
}

ChainLockFinalityStoreConfig MakeConfig()
{
    ChainLockFinalityStoreConfig config;
    config.chainlock_schedule = *MakeChainLockScheduleConfig(0);
    config.btcc_schedule.candidate_origin = 865;
    config.activation_predecessor_height = 864;
    return config;
}

BTCCCursorReconciliationProof MakeReconciliationProof(
    const FinalChainLock& durable, uint64_t salt)
{
    BTCCCursorReconciliationProof proof;
    proof.carrier_height =
        durable.statement.accepted_btcc_cursor.sys_height +
        static_cast<int32_t>(PQ_BTCC_NEVM_LAG);
    proof.carrier_hash = NonNullHash(90'000 + salt);
    proof.carrier_parent_hash = NonNullHash(91'000 + salt);
    proof.skipped_cursor = durable.statement.accepted_btcc_cursor;
    proof.previous_receipt_state = durable.statement.btcc_receipt_state;
    proof.current_receipt_state = durable.statement.btcc_receipt_state;
    return proof;
}

ChainLockFinalityStoreConfig MakePaymentAuditConfig()
{
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 865;
    return config;
}

DBParams DiskParams(const fs::path& path, bool wipe = false)
{
    return DBParams{
        .path = path,
        .cache_bytes = 4U << 20,
        .wipe_data = wipe,
    };
}

DBParams MemoryParams(const fs::path& path)
{
    return DBParams{
        .path = path,
        .cache_bytes = 4U << 20,
        .memory_only = true,
    };
}

struct RawDiskKey {
    uint8_t type{0};

    SERIALIZE_METHODS(RawDiskKey, obj) { READWRITE(obj.type); }
};

struct RawTruncatedBTCCPresealMarker {
    uint16_t version{1};
    uint256 schema_hash;
    int32_t carrier_height{-1};
    uint256 carrier_hash;
    uint256 checksum;

    SERIALIZE_METHODS(RawTruncatedBTCCPresealMarker, obj)
    {
        READWRITE(obj.version, obj.schema_hash, obj.carrier_height,
                  obj.carrier_hash, obj.checksum);
    }
};

struct RawBTCCPresealMarkerV1 {
    uint16_t version{1};
    uint256 schema_hash;
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    BTCCReceiptState predecessor_receipt_state;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    BTCCReceiptState terminal_parent_receipt_state;
    BTCCReceipt terminal_receipt;
    uint64_t revision{0};
    uint256 checksum;

    SERIALIZE_METHODS(RawBTCCPresealMarkerV1, obj)
    {
        READWRITE(obj.version, obj.schema_hash,
                  obj.earliest_carrier_height,
                  obj.earliest_carrier_hash,
                  obj.predecessor_receipt_state,
                  obj.terminal_carrier_height,
                  obj.terminal_carrier_hash,
                  obj.terminal_parent_receipt_state,
                  obj.terminal_receipt,
                  obj.revision, obj.checksum);
    }
};

struct RawReceiptArchiveRosterAuthorizationV1 {
    uint16_t version{1};
    uint256 schema_hash;
    uint256 owner_logical_id;
    uint256 owner_witness_id;
    ChainLockStatement owner_statement;
    uint256 covering_logical_id;
    uint256 covering_witness_id;
    uint256 predecessor_logical_id;
    uint256 predecessor_witness_id;
    ChainLockStatement predecessor_statement;
    uint256 checksum;

    SERIALIZE_METHODS(RawReceiptArchiveRosterAuthorizationV1, obj)
    {
        READWRITE(obj.version, obj.schema_hash, obj.owner_logical_id,
                  obj.owner_witness_id, obj.owner_statement,
                  obj.covering_logical_id, obj.covering_witness_id,
                  obj.predecessor_logical_id,
                  obj.predecessor_witness_id,
                  obj.predecessor_statement, obj.checksum);
    }
};

struct RawPaymentAuditSealContextV1 {
    uint16_t version{1};
    uint256 schema_hash;
    uint32_t epoch{0};
    int32_t carrier_end_height_exclusive{-1};
    uint256 seal_logical_id;
    uint256 seal_witness_id;
    ChainLockStatement seal_statement;
    uint8_t authorization_mask{0};
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(
            stream, version, schema_hash, epoch,
            carrier_end_height_exclusive, seal_logical_id,
            seal_witness_id, seal_statement, authorization_mask,
            checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        ::UnserializeMany(
            stream, version, schema_hash, epoch,
            carrier_end_height_exclusive, seal_logical_id,
            seal_witness_id, seal_statement, authorization_mask,
            checksum);
    }
};

BTCCPresealMarker MakePresealMarker(int32_t earliest_height,
                                    int32_t terminal_height,
                                    uint64_t revision,
                                    uint64_t salt)
{
    BTCCReceipt receipt;
    receipt.chainlock_target_height = terminal_height - PQ_BTCC_NEVM_LAG;
    receipt.chainlock_target_hash = NonNullHash(100000 + salt);
    receipt.chainlock_logical_id = NonNullHash(200000 + salt);
    receipt.accepted_cursor = BTCCursor{
        receipt.chainlock_target_height, receipt.chainlock_target_hash,
        NonNullHash(300000 + salt)};
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    const uint256 earliest_hash{NonNullHash(400000 + salt)};
    BTCCReceiptState terminal_parent;
    if (terminal_height > earliest_height) {
        const int32_t previous_target{
            earliest_height - static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
        terminal_parent = BTCCReceiptState{
            BTCCursor{previous_target, NonNullHash(410000 + salt),
                       NonNullHash(420000 + salt)},
            NonNullHash(430000 + salt), previous_target,
            earliest_height};
        BOOST_REQUIRE(terminal_parent.IsStructurallyValid());
    }
    return BTCCPresealMarker{
        earliest_height, earliest_hash, BTCCReceiptState{}, terminal_height,
        terminal_height == earliest_height
            ? earliest_hash
            : NonNullHash(500000 + salt),
        terminal_parent, receipt, revision};
}

BTCCPresealMarker MakeKeepPresealMarker(uint64_t revision,
                                        uint64_t salt)
{
    constexpr int32_t PREVIOUS_TARGET{865};
    constexpr int32_t PREVIOUS_CARRIER{875};
    constexpr int32_t TARGET{875};
    constexpr int32_t CARRIER{885};
    const BTCCursor cursor{
        PREVIOUS_TARGET, NonNullHash(510'000 + salt),
        NonNullHash(520'000 + salt)};
    const BTCCReceiptState predecessor{
        cursor, NonNullHash(530'000 + salt), PREVIOUS_TARGET,
        PREVIOUS_CARRIER};
    BOOST_REQUIRE(predecessor.IsStructurallyValid());

    BTCCReceipt receipt;
    receipt.chainlock_target_height = TARGET;
    receipt.chainlock_target_hash = NonNullHash(540'000 + salt);
    receipt.chainlock_logical_id = NonNullHash(550'000 + salt);
    receipt.accepted_cursor = cursor;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    return BTCCPresealMarker{
        CARRIER, NonNullHash(560'000 + salt), predecessor,
        CARRIER, NonNullHash(560'000 + salt), predecessor,
        receipt, revision};
}

BTCCPresealMarker MakeLateInitialPresealMarker(uint64_t revision,
                                               uint64_t salt)
{
    constexpr int32_t INITIAL_TARGET{865};
    constexpr int32_t LATE_CARRIER{885};
    BTCCReceipt receipt;
    receipt.chainlock_target_height = INITIAL_TARGET;
    receipt.chainlock_target_hash = NonNullHash(565'000 + salt);
    receipt.chainlock_logical_id = NonNullHash(566'000 + salt);
    receipt.accepted_cursor = BTCCursor{
        INITIAL_TARGET, receipt.chainlock_target_hash,
        NonNullHash(567'000 + salt)};
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    return BTCCPresealMarker{
        LATE_CARRIER, NonNullHash(568'000 + salt), BTCCReceiptState{},
        LATE_CARRIER, NonNullHash(568'000 + salt), BTCCReceiptState{},
        receipt, revision};
}

BTCCPresealMarker MakeAdvanceThenKeepPresealMarker(uint64_t revision,
                                                   uint64_t salt)
{
    constexpr int32_t PREDECESSOR_TARGET{855};
    constexpr int32_t PREDECESSOR_CARRIER{865};
    constexpr int32_t ADVANCE_TARGET{865};
    constexpr int32_t ADVANCE_CARRIER{875};
    constexpr int32_t KEEP_TARGET{875};
    constexpr int32_t KEEP_CARRIER{885};
    const BTCCReceiptState predecessor{
        BTCCursor{PREDECESSOR_TARGET, NonNullHash(570'000 + salt),
                   NonNullHash(580'000 + salt)},
        NonNullHash(590'000 + salt), PREDECESSOR_TARGET,
        PREDECESSOR_CARRIER};
    const BTCCursor advanced_cursor{
        ADVANCE_TARGET, NonNullHash(600'000 + salt),
        NonNullHash(610'000 + salt)};
    const BTCCReceiptState terminal_parent{
        advanced_cursor, NonNullHash(620'000 + salt), ADVANCE_TARGET,
        ADVANCE_CARRIER};
    BOOST_REQUIRE(predecessor.IsStructurallyValid());
    BOOST_REQUIRE(terminal_parent.IsStructurallyValid());
    BOOST_REQUIRE(IsDurableBTCCReceiptStateMonotonic(
        predecessor, terminal_parent));

    BTCCReceipt receipt;
    receipt.chainlock_target_height = KEEP_TARGET;
    receipt.chainlock_target_hash = NonNullHash(630'000 + salt);
    receipt.chainlock_logical_id = NonNullHash(640'000 + salt);
    receipt.accepted_cursor = advanced_cursor;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    return BTCCPresealMarker{
        ADVANCE_CARRIER, NonNullHash(650'000 + salt), predecessor,
        KEEP_CARRIER, NonNullHash(660'000 + salt), terminal_parent,
        receipt, revision};
}

PaymentAuditPresealMarker MakePaymentAuditPresealMarker(
    const ChainLockFinalityStoreConfig& config,
    uint32_t epoch,
    uint64_t revision,
    uint64_t salt)
{
    const PaymentAuditScheduleConfig schedule_config{
        config.chainlock_schedule, config.btcc_schedule};
    const auto schedule{
        BuildPaymentAuditEpochSchedule(schedule_config, epoch)};
    BOOST_REQUIRE(schedule);

    PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = epoch;
    receipt.seal_height = schedule->seal_height;
    receipt.seal_block_hash = NonNullHash(600'000 + salt);
    receipt.carrier_height = schedule->carrier_start_height;
    receipt.audit_logical_id = NonNullHash(610'000 + salt);
    receipt.audit_witness_id = NonNullHash(620'000 + salt);
    receipt.commitment_hash = NonNullHash(630'000 + salt);
    receipt.result_hash = NonNullHash(640'000 + salt);
    receipt.next_probation_state_hash = NonNullHash(650'000 + salt);
    receipt.subject_roster_beacon =
        MakeInitializationPendingSeed(epoch, 680'000 + salt);
    receipt.subject_roster_beacon.state = RosterBeaconState::READY;
    receipt.subject_roster_beacon.future_btc_hash =
        NonNullHash(690'000 + salt);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    return PaymentAuditPresealMarker{
        receipt.carrier_height,
        NonNullHash(660'000 + salt),
        PaymentAuditReceiptState{},
        NonNullHash(670'000 + salt),
        receipt.carrier_height,
        NonNullHash(660'000 + salt),
        receipt,
        revision};
}

struct DurableBTCCIndexState {
    uint256 block_hash;
    uint256 btcp_prev;
    BTCCReceiptState receipt_state;
    uint32_t status{0};
};

DurableBTCCIndexState WriteDurableBTCCIndexState(const fs::path& path)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 1;
    header.nNonce = 1;
    CBlockIndex target{header};
    const uint256 block_hash{header.GetHash()};
    target.phashBlock = &block_hash;
    target.nHeight = 870;
    target.btcpPrevCommitment = NonNullHash(8701);
    target.pqBTCCReceiptCursorHeight = target.nHeight;
    target.pqBTCCReceiptCursorSysHash = block_hash;
    target.pqBTCCReceiptCursorBTCHash = target.btcpPrevCommitment;
    target.pqBTCCReceiptStateHash = NonNullHash(8702);
    target.pqBTCCReceiptLatestTargetHeight = target.nHeight;
    target.pqBTCCReceiptLatestCarrierHeight =
        target.nHeight + static_cast<int32_t>(PQ_BTCC_NEVM_LAG);

    kernel::BlockTreeDB db{DiskParams(path, /*wipe=*/true)};
    {
        LOCK(cs_main);
        target.nStatus = BLOCK_VALID_SCRIPTS |
                         BLOCK_PQ_BTCC_INDEX_VALIDATED;
        BOOST_REQUIRE(db.WriteBatchSync({}, 0, {&target}));
    }
    return DurableBTCCIndexState{
        block_hash, target.btcpPrevCommitment,
        BTCCReceiptState{
            BTCCursor{target.pqBTCCReceiptCursorHeight,
                       target.pqBTCCReceiptCursorSysHash,
                       target.pqBTCCReceiptCursorBTCHash},
            target.pqBTCCReceiptStateHash,
            target.pqBTCCReceiptLatestTargetHeight,
            target.pqBTCCReceiptLatestCarrierHeight},
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED};
}

DurableBTCCIndexState LoadDurableBTCCIndexState(const fs::path& path,
                                                const uint256& target_hash)
{
    kernel::BlockTreeDB db{DiskParams(path)};
    node::BlockMap loaded;
    const auto insert_index{[&](const uint256& hash) -> CBlockIndex* {
        if (hash.IsNull()) return nullptr;
        auto [it, inserted]{loaded.try_emplace(hash)};
        if (inserted) it->second.phashBlock = &it->first;
        return &it->second;
    }};
    util::SignalInterrupt interrupt;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(db.LoadBlockIndexGuts(
            Params().GetConsensus(), insert_index, interrupt));
    }
    const auto found{loaded.find(target_hash)};
    BOOST_REQUIRE(found != loaded.end());
    const CBlockIndex& target{found->second};
    const uint32_t status{WITH_LOCK(cs_main, return target.nStatus)};
    return DurableBTCCIndexState{
        target.GetBlockHash(), target.btcpPrevCommitment,
        BTCCReceiptState{
            BTCCursor{target.pqBTCCReceiptCursorHeight,
                       target.pqBTCCReceiptCursorSysHash,
                       target.pqBTCCReceiptCursorBTCHash},
            target.pqBTCCReceiptStateHash,
            target.pqBTCCReceiptLatestTargetHeight,
            target.pqBTCCReceiptLatestCarrierHeight},
        status};
}

FinalChainLock MakeBTCCWinner(const DurableBTCCIndexState& index_state,
                              const ChainLockFinalityStoreConfig& config,
                              uint64_t salt)
{
    const auto predecessor{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, config.activation_predecessor_height)};
    BOOST_REQUIRE(predecessor);
    auto winner{MakeChainLock(
        870, *predecessor, NonNullHash(*predecessor), salt)};
    winner.statement.block_hash = index_state.block_hash;
    winner.statement.accepted_btcc_cursor = index_state.receipt_state.cursor;
    winner.statement.btcc_advance = BTCCAdvance::ADVANCE;
    winner.statement.btcc_receipt_state = index_state.receipt_state;
    BOOST_REQUIRE(winner.IsStructurallyValid());
    return winner;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_persistence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(incomplete_audit_cursor_requires_reindex)
{
    const fs::path path{m_path_root / "pqcl_incomplete_audit_index"};
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1;
    header.nBits = 1;
    header.nNonce = 1;
    CBlockIndex target{header};
    const uint256 block_hash{header.GetHash()};
    target.phashBlock = &block_hash;
    target.nHeight = 900;
    target.pqPaymentAuditReceiptCursorHeight = 900;
    target.pqPaymentAuditReceiptCursorEpoch = 3;
    target.pqPaymentAuditReceiptCursorSealHash = NonNullHash(9001);
    target.pqPaymentAuditReceiptCursorLogicalId = NonNullHash(9002);
    target.pqPaymentAuditReceiptStateHash = NonNullHash(9003);
    target.pqPaymentProbationStateHash = NonNullHash(9004);
    BOOST_REQUIRE(target.pqPaymentAuditReceiptCursorWitnessId.IsNull());

    {
        kernel::BlockTreeDB db{DiskParams(path, /*wipe=*/true)};
        LOCK(cs_main);
        target.nStatus = BLOCK_VALID_SCRIPTS;
        BOOST_REQUIRE(db.WriteBatchSync({}, 0, {&target}));
    }

    kernel::BlockTreeDB db{DiskParams(path)};
    node::BlockMap loaded;
    const auto insert_index{[&](const uint256& hash) -> CBlockIndex* {
        if (hash.IsNull()) return nullptr;
        auto [it, inserted]{loaded.try_emplace(hash)};
        if (inserted) it->second.phashBlock = &it->first;
        return &it->second;
    }};
    util::SignalInterrupt interrupt;
    LOCK(cs_main);
    BOOST_CHECK(!db.LoadBlockIndexGuts(
        Params().GetConsensus(), insert_index, interrupt));
}

BOOST_AUTO_TEST_CASE(empty_database_initializes_fixed_schema)
{
    PQChainLockPersistence persistence{
        MemoryParams(m_path_root / "pqcl_empty"), NonNullHash(1),
        MakeConfig()};
    BOOST_CHECK(!persistence.HasBest());
    BOOST_CHECK(!persistence.LoadBest());
    const auto state{persistence.GetFinalityState()};
    BOOST_CHECK_EQUAL(state.certificate_revision, 0U);
    BOOST_CHECK(!state.best);
    BOOST_CHECK(!state.unsealed_btcc);
}

BOOST_AUTO_TEST_CASE(authorization_base_exact_lookup_survives_restart)
{
    const fs::path path{m_path_root / "pqcl_authorization_base_lookup"};
    const uint256 genesis{NonNullHash(820)};
    const auto config{MakeConfig()};
    auto base{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 820)};
    SetExactInitialization(base, genesis, 820);
    const auto recovery_source{base.statement.roster_beacons.active
                                   .recovery_authority_source};
    BOOST_REQUIRE(base.IsStructurallyValid());
    const uint256 logical_id{base.GetLogicalId(genesis)};

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistVerifiedAuthorizationBase(base));
        const auto exact{persistence.LoadAuthorizationBase(logical_id)};
        BOOST_REQUIRE(exact);
        BOOST_CHECK(*exact == base);
        BOOST_CHECK(!persistence.LoadAuthorizationBase(NonNullHash(821)));
        const auto sources{
            persistence.LoadAuthorizationBaseRecoverySources()};
        BOOST_REQUIRE_EQUAL(sources.size(), 1U);
        BOOST_CHECK(sources.front() == recovery_source);

        auto precommit{MakeInitializationPrecommit(
            820, base.statement.height)};
        precommit.pending_seed.anchor_cursor.sys_hash =
            base.statement.block_hash;
        precommit.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(42'100'000 + 820);
        BOOST_REQUIRE(precommit.IsStructurallyValid());
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(precommit));
        BOOST_REQUIRE(persistence.PersistInitializedBest(base));
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == base);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(logical_id));
        BOOST_CHECK(*persistence.LoadAuthorizationBase(logical_id) == base);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == base);
        const auto exact{persistence.LoadAuthorizationBase(logical_id)};
        BOOST_REQUIRE(exact);
        BOOST_CHECK(*exact == base);
        const auto sources{
            persistence.LoadAuthorizationBaseRecoverySources()};
        BOOST_REQUIRE_EQUAL(sources.size(), 1U);
        BOOST_CHECK(sources.front() == recovery_source);
    }
}

BOOST_AUTO_TEST_CASE(
    authorization_base_capacity_retains_incoming_referenced_base)
{
    const fs::path path{
        m_path_root / "pqcl_authorization_base_referenced_capacity"};
    const uint256 genesis{NonNullHash(822)};
    const auto config{MakeConfig()};
    auto referenced{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 822)};
    SetExactInitialization(referenced, genesis, 822);

    uint256 oldest_unprotected_id;
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(
            persistence.PersistVerifiedAuthorizationBase(referenced));
        for (std::size_t index{0};
             index + 1 < VERIFIED_AUTHORIZATION_BASE_CAPACITY;
             ++index) {
            const int32_t height{
                870 + static_cast<int32_t>(index * PQ_CL_PERIOD)};
            auto retained{MakeChainLock(
                height, height - static_cast<int32_t>(PQ_CL_PERIOD),
                NonNullHash(8'220'000 + index), 8'230'000 + index)};
            SetExactContinuation(retained, genesis, referenced);
            if (index == 0) {
                oldest_unprotected_id = retained.GetLogicalId(genesis);
            }
            BOOST_REQUIRE(
                persistence.PersistVerifiedAuthorizationBase(retained));
        }
        BOOST_REQUIRE_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);

        const int32_t incoming_height{
            870 + static_cast<int32_t>(
                      VERIFIED_AUTHORIZATION_BASE_CAPACITY * PQ_CL_PERIOD)};
        auto incoming{MakeChainLock(
            incoming_height,
            incoming_height - static_cast<int32_t>(PQ_CL_PERIOD),
            NonNullHash(8'240'000), 8'240'001)};
        SetExactContinuation(incoming, genesis, referenced);
        BOOST_REQUIRE(
            persistence.PersistVerifiedAuthorizationBase(incoming));

        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            referenced.GetLogicalId(genesis)));
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            incoming.GetLogicalId(genesis)));
        BOOST_CHECK(
            !persistence.LoadAuthorizationBase(oldest_unprotected_id));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            referenced.GetLogicalId(genesis)));
        BOOST_CHECK(
            !persistence.LoadAuthorizationBase(oldest_unprotected_id));
    }
}

BOOST_AUTO_TEST_CASE(
    recovery_source_base_survives_repeated_capacity_eviction_and_restart)
{
    const fs::path path{
        m_path_root / "pqcl_recovery_source_capacity_restart"};
    const uint256 genesis{NonNullHash(8'250)};
    const auto config{MakeConfig()};
    auto source{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 8'250)};
    SetExactInitialization(source, genesis, 8'250);
    const uint256 source_logical_id{source.GetLogicalId(genesis)};
    uint256 newest_logical_id;

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(
            persistence.PersistVerifiedAuthorizationBase(source));
        for (std::size_t index{1};
             index <= VERIFIED_AUTHORIZATION_BASE_CAPACITY + 8;
             ++index) {
            const uint32_t newest_epoch{
                static_cast<uint32_t>(ACTIVE_QUORUMS - 1 +
                                      index * ACTIVE_QUORUMS)};
            const auto target{CanonicalRosterRecoveryTargetHeight(
                config.chainlock_schedule, config.btcc_schedule,
                newest_epoch)};
            BOOST_REQUIRE(target);
            auto recovery{MakeChainLock(
                *target, *target - static_cast<int32_t>(PQ_CL_PERIOD),
                NonNullHash(8'300'000 + index), 8'400'000 + index)};
            SetExactRecoveryTransitionFromPrior(
                recovery, genesis, source, newest_epoch);
            BOOST_REQUIRE(
                persistence.PersistVerifiedAuthorizationBase(recovery));
            newest_logical_id = recovery.GetLogicalId(genesis);
            BOOST_REQUIRE(
                persistence.LoadAuthorizationBase(source_logical_id));
        }
        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_REQUIRE(
            persistence.LoadAuthorizationBase(newest_logical_id));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        const auto retained_source{
            persistence.LoadAuthorizationBase(source_logical_id)};
        BOOST_REQUIRE(retained_source);
        BOOST_CHECK(*retained_source == source);
        BOOST_REQUIRE(
            persistence.LoadAuthorizationBase(newest_logical_id));
    }
}

BOOST_AUTO_TEST_CASE(
    best_capacity_retains_previous_and_disappearing_unsealed_bases)
{
    const fs::path path{
        m_path_root / "pqcl_best_dual_base_capacity"};
    const uint256 genesis{NonNullHash(823)};
    const auto config{MakeConfig()};

    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 823)};
    SetExactInitialization(initialized, genesis, 823);
    auto intermediate{MakeChainLock(
        870, initialized.statement.height,
        initialized.statement.block_hash, 824)};
    SetExactContinuation(intermediate, genesis, initialized);
    auto boundary{MakeChainLock(
        875, intermediate.statement.height,
        intermediate.statement.block_hash, 825)};
    SetExactContinuation(boundary, genesis, intermediate);
    auto previous_best{MakeChainLock(
        880, boundary.statement.height,
        boundary.statement.block_hash, 826)};
    SetExactContinuation(previous_best, genesis, boundary);

    auto winner{MakeChainLock(
        885, previous_best.statement.height,
        previous_best.statement.block_hash, 828)};
    winner.statement.previous_btcc_cursor =
        previous_best.statement.accepted_btcc_cursor;
    winner.statement.accepted_btcc_cursor =
        previous_best.statement.accepted_btcc_cursor;
    winner.statement.btcc_advance = BTCCAdvance::KEEP;
    winner.statement.btcc_receipt_state = BTCCReceiptState{
        boundary.statement.accepted_btcc_cursor,
        NonNullHash(8'260'000), boundary.statement.height,
        winner.statement.height};
    SetExactContinuation(winner, genesis, boundary);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_REQUIRE(persistence.PersistBest(intermediate));
        BOOST_REQUIRE(persistence.PersistBest(boundary));
        BOOST_REQUIRE(persistence.PersistBest(previous_best));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == boundary);

        for (std::size_t index{0};
             index + 3 < VERIFIED_AUTHORIZATION_BASE_CAPACITY;
             ++index) {
            auto retained{MakeChainLock(
                870, initialized.statement.height,
                NonNullHash(8'270'000 + index), 8'280'000 + index)};
            ChainLockPersistenceError error{
                ChainLockPersistenceError::NONE};
            BOOST_REQUIRE_MESSAGE(
                persistence.PersistVerifiedAuthorizationBase(
                    retained, &error),
                "authorization-base index " << index << ", error "
                                              << static_cast<int>(error));
        }
        BOOST_REQUIRE_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_CHECK(!persistence.LoadAuthorizationBase(
            previous_best.GetLogicalId(genesis)));
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            boundary.GetLogicalId(genesis)));

        BOOST_REQUIRE(persistence.PersistBest(winner));
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == winner);
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == winner);
        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            previous_best.GetLogicalId(genesis)));
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            boundary.GetLogicalId(genesis)));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == winner);
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == winner);
        BOOST_CHECK_EQUAL(
            persistence.LoadAuthorizationBases().size(),
            VERIFIED_AUTHORIZATION_BASE_CAPACITY);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            previous_best.GetLogicalId(genesis)));
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            boundary.GetLogicalId(genesis)));
    }
}

BOOST_AUTO_TEST_CASE(roster_recovery_precommit_is_canonical_and_durable)
{
    const fs::path path{m_path_root / "pqcl_roster_recovery_precommit"};
    const uint256 genesis{NonNullHash(81)};
    const auto config{MakeConfig()};
    const auto staged{MakeInitializationPrecommit(1)};

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());

        auto ready_first{staged};
        ready_first.pending_seed.state = RosterBeaconState::READY;
        ready_first.pending_seed.future_btc_hash = NonNullHash(798'999);
        BOOST_REQUIRE(ready_first.IsStructurallyValid());
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            ready_first, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(staged));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);
        BOOST_CHECK(persistence.PersistRosterRecoveryPrecommit(staged));

        auto conflict{staged};
        conflict.pending_seed.anchor_btc_height++;
        BOOST_REQUIRE(conflict.IsStructurallyValid());
        error = ChainLockPersistenceError::NONE;
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            conflict, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto resolved{staged};
        resolved.pending_seed.state = RosterBeaconState::READY;
        resolved.pending_seed.future_btc_hash = NonNullHash(799'001);
        BOOST_REQUIRE(resolved.IsStructurallyValid());
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(resolved));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == resolved);
        BOOST_CHECK(persistence.PersistRosterRecoveryPrecommit(resolved));

        auto different_resolution{resolved};
        different_resolution.pending_seed.future_btc_hash =
            NonNullHash(799'002);
        BOOST_REQUIRE(different_resolution.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            different_resolution, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == resolved);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto resolved{persistence.LoadRosterRecoveryPrecommit()};
        BOOST_REQUIRE(resolved);
        BOOST_CHECK(resolved->pending_seed.IsReady());
        BOOST_CHECK(resolved->pending_seed.future_btc_hash ==
                    NonNullHash(799'001));
        BOOST_CHECK(persistence.PersistRosterRecoveryPrecommit(*resolved));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == resolved);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit());
    }

    auto invalid{staged};
    invalid.pending_seed.epoch = 4;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = staged;
    invalid.pending_seed.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    BOOST_CHECK(!invalid.IsStructurallyValid());

    auto initialize{MakeInitializationPrecommit(2)};
    BOOST_CHECK(initialize.IsStructurallyValid());
    BOOST_CHECK_EQUAL(initialize.version,
                      ROSTER_RECOVERY_PRECOMMIT_VERSION);
    auto stale_version{initialize};
    --stale_version.version;
    BOOST_CHECK(!stale_version.IsStructurallyValid());
    auto initialize_with_recovery_seed{initialize};
    initialize_with_recovery_seed.pending_seed.anchor_kind =
        RosterBeaconAnchorKind::RECOVERY;
    BOOST_CHECK(!initialize_with_recovery_seed.IsStructurallyValid());
    {
        PQChainLockPersistence persistence{
            MemoryParams(path / "stale_precommit_version"),
            genesis, config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            stale_version, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
    }

    auto wrong_epoch{staged};
    wrong_epoch.pending_seed.epoch = 7;
    BOOST_REQUIRE(wrong_epoch.IsStructurallyValid());
    {
        PQChainLockPersistence persistence{
            MemoryParams(path / "wrong_epoch"), genesis, config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            wrong_epoch, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    }

    auto later_joint_target{staged};
    later_joint_target.pending_seed.anchor_cursor.sys_height = 880;
    later_joint_target.pending_seed.anchor_cursor.sys_hash =
        NonNullHash(880);
    later_joint_target.pending_seed.anchor_cursor.btc_hash =
        NonNullHash(881);
    BOOST_REQUIRE(later_joint_target.IsStructurallyValid());
    {
        PQChainLockPersistence persistence{
            MemoryParams(path / "noncanonical_target"), genesis, config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            later_joint_target, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    }

    auto off_target_config{config};
    off_target_config.btcc_schedule.candidate_origin = 0;
    off_target_config.activation_predecessor_height = -1;
    const auto off_target{MakeInitializationPrecommit(
        2, /*anchor_height=*/0)};
    {
        PQChainLockPersistence persistence{
            MemoryParams(path / "off_target"), genesis,
            off_target_config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            off_target, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    }
}

BOOST_AUTO_TEST_CASE(roster_recovery_precommit_replacement_is_exact_cas)
{
    const fs::path path{m_path_root / "pqcl_roster_recovery_replace"};
    const uint256 genesis{NonNullHash(811)};
    const auto config{MakeConfig()};
    const auto staged{MakeInitializationPrecommit(811)};

    auto same_slot{staged};
    same_slot.pending_seed.anchor_cursor.sys_hash = NonNullHash(812);
    same_slot.pending_seed.anchor_cursor.btc_hash = NonNullHash(813);
    same_slot.pending_seed.anchor_btc_height++;
    BOOST_REQUIRE(same_slot.IsStructurallyValid());

    auto stale_expected{staged};
    stale_expected.pending_seed.anchor_btc_height++;
    BOOST_REQUIRE(stale_expected.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(staged));

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.ReplaceRosterRecoveryPrecommit(
            stale_expected, same_slot, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        BOOST_REQUIRE(persistence.ReplaceRosterRecoveryPrecommit(
            staged, same_slot));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == same_slot);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == same_slot);

        auto ready{same_slot};
        ready.pending_seed.state = RosterBeaconState::READY;
        ready.pending_seed.future_btc_hash = NonNullHash(814);
        BOOST_REQUIRE(ready.IsStructurallyValid());
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(ready));

        auto ready_same_slot_retarget{same_slot};
        ready_same_slot_retarget.pending_seed.anchor_cursor.sys_hash =
            NonNullHash(815);
        ready_same_slot_retarget.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(816);
        BOOST_REQUIRE(ready_same_slot_retarget.IsStructurallyValid());
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.ReplaceRosterRecoveryPrecommit(
            ready, ready_same_slot_retarget, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == ready);

        const auto later{MakeInitializationPrecommit(
            817, /*anchor_height=*/2'025, /*epoch=*/7)};
        BOOST_CHECK(!persistence.ReplaceRosterRecoveryPrecommit(
            ready, later, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == ready);

        BOOST_CHECK(!persistence.ReplaceRosterRecoveryPrecommit(
            ready, same_slot, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto ready{persistence.LoadRosterRecoveryPrecommit()};
        BOOST_REQUIRE(ready);
        BOOST_CHECK(ready->pending_seed.IsReady());
        BOOST_CHECK_EQUAL(ready->pending_seed.epoch,
                          ACTIVE_QUORUMS - 1);
    }
}

BOOST_AUTO_TEST_CASE(initialized_best_atomically_consumes_recovery_precommit)
{
    const fs::path path{m_path_root / "pqcl_roster_initialize"};
    const uint256 genesis{NonNullHash(82)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 865;
    auto staged{MakeInitializationPrecommit(
        3, /*anchor_height=*/865)};
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 82)};
    SetInitializationTransition(initialized, staged, genesis, 3);
    SetExactRosterAuthorizationStateHash(initialized, genesis);
    BOOST_REQUIRE(initialized.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(staged));
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistBest(initialized, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto bypass{initialized};
        bypass.statement.roster_transition =
            RosterAuthorizationTransitionKind::KEEP;
        BOOST_CHECK(!persistence.PersistBest(bypass, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto wrong_target_hash{initialized};
        wrong_target_hash.statement.block_hash = NonNullHash(999'990);
        BOOST_REQUIRE(wrong_target_hash.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistInitializedBest(
            wrong_target_hash, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto mismatched{initialized};
        mismatched.statement.roster_beacons.active.seeds.back()
            .future_btc_hash = NonNullHash(999'991);
        BOOST_REQUIRE(mismatched.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistInitializedBest(mismatched, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto keep{initialized};
        keep.statement.btcc_advance = BTCCAdvance::KEEP;
        keep.statement.accepted_btcc_cursor = {};
        BOOST_REQUIRE(keep.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistInitializedBest(keep, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto wrong_cursor{initialized};
        wrong_cursor.statement.accepted_btcc_cursor.btc_hash =
            NonNullHash(999'994);
        BOOST_REQUIRE(wrong_cursor.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistInitializedBest(
            wrong_cursor, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_CHECK(persistence.HasBest());
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_CHECK(persistence.PersistInitializedBest(initialized));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == initialized);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(staged));
    }
}

BOOST_AUTO_TEST_CASE(
    initial_normal_rosters_roundtrip_with_exact_recovery_source)
{
    const fs::path path{
        m_path_root / "pqcl_initial_authority_worker_stack"};
    const uint256 genesis{NonNullHash(820)};
    const auto config{MakeConfig()};
    auto initialized{std::make_shared<FinalChainLock>(MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 820))};
    SetExactInitialization(*initialized, genesis, 820);
    const auto source{initialized->statement.roster_beacons.active
                          .recovery_authority_source};

    bool persisted{false};
    bool restarted{false};
    ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
    // Network workers have a smaller stack than the Boost test runner. Keep
    // both the write and startup-read paths safe on the real call shape.
    std::thread worker{[&] {
        {
            PQChainLockPersistence persistence{
                DiskParams(path), genesis, config};
            persisted = persistence.PersistInitializedBest(
                *initialized, &error);
        }
        if (!persisted) return;
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto loaded{persistence.LoadBest()};
        restarted = loaded &&
            loaded->statement.roster_beacons.active
                    .recovery_authority_source == source;
    }};
    worker.join();

    BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    BOOST_REQUIRE(persisted);
    BOOST_CHECK(restarted);
}

BOOST_AUTO_TEST_CASE(
    verified_recovery_persistence_does_not_require_local_precommit)
{
    const uint256 genesis{NonNullHash(84)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 865;
    auto initialize_marker{MakeInitializationPrecommit(
        41, /*anchor_height=*/865)};
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 841)};
    SetInitializationTransition(
        initialized, initialize_marker, genesis, 41);
    SetExactRosterAuthorizationStateHash(initialized, genesis);
    BOOST_REQUIRE(initialized.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{
            MemoryParams(m_path_root / "pqcl_recovery_no_local_initialize"),
            genesis, config};
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_CHECK(persistence.LoadBest() == initialized);
    }

    const auto catchup_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(catchup_target);
    auto recovered{MakeChainLock(
        *catchup_target,
        *catchup_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*catchup_target - PQ_CL_PERIOD), 842)};
    SetExactRecoveryTransitionFromPrior(
        recovered, genesis, initialized, /*newest_epoch=*/7);
    BOOST_REQUIRE(recovered.IsStructurallyValid());
    {
        PQChainLockPersistence persistence{
            MemoryParams(m_path_root / "pqcl_recovery_no_local_catchup"),
            genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(recovered));
        BOOST_CHECK(persistence.LoadBest() == recovered);
    }
    {
        PQChainLockPersistence persistence{
            MemoryParams(m_path_root / "pqcl_recovery_empty_store"),
            genesis, config};
        BOOST_CHECK(!persistence.LoadBest());
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            recovered, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(!persistence.LoadBest());
    }
}

BOOST_AUTO_TEST_CASE(corrupt_roster_recovery_precommit_fails_closed)
{
    const fs::path path{m_path_root / "pqcl_roster_recovery_corrupt"};
    const uint256 genesis{NonNullHash(84)};
    const auto config{MakeConfig()};
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
    }
    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Write(
            RawDiskKey{
                PQ_CHAINLOCK_PERSISTENCE_ROSTER_RECOVERY_PRECOMMIT_KEY},
            uint8_t{1}, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(activation_predecessor_hash_is_not_configuration)
{
    const uint256 genesis{NonNullHash(64)};
    const auto config{MakeConfig()};
    auto branch_a{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(8641), 64)};
    auto branch_b{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(8642), 65)};
    SetExactInitialization(branch_a, genesis, 64);
    SetExactInitialization(branch_b, genesis, 65);
    const fs::path path_a{m_path_root / "pqcl_height_boundary_a"};
    const fs::path path_b{m_path_root / "pqcl_height_boundary_b"};

    {
        PQChainLockPersistence persistence{DiskParams(path_a), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(branch_a));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path_a), genesis, config};
        const auto loaded{persistence.LoadBest()};
        BOOST_REQUIRE(loaded);
        BOOST_CHECK(*loaded == branch_a);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path_b), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(branch_b));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path_b), genesis, config};
        const auto loaded{persistence.LoadBest()};
        BOOST_REQUIRE(loaded);
        BOOST_CHECK(*loaded == branch_b);
    }
}

BOOST_AUTO_TEST_CASE(activation_predecessor_requires_valid_boundary_shape)
{
    const auto config{MakeConfig()};
    PQChainLockPersistence persistence{
        MemoryParams(m_path_root / "pqcl_height_boundary_shape"),
        NonNullHash(66), config};
    ChainLockPersistenceError error{ChainLockPersistenceError::NONE};

    const auto null_hash{
        MakeChainLock(865, config.activation_predecessor_height, {}, 66)};
    BOOST_CHECK(!persistence.PersistBest(null_hash, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

    auto cursor_mismatch{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(8643), 67)};
    cursor_mismatch.statement.previous_btcc_cursor = BTCCursor{
        860, NonNullHash(8601), NonNullHash(8602)};
    cursor_mismatch.statement.accepted_btcc_cursor =
        cursor_mismatch.statement.previous_btcc_cursor;
    BOOST_REQUIRE(cursor_mismatch.IsStructurallyValid());
    BOOST_CHECK(!persistence.PersistBest(cursor_mismatch, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

    const int32_t earlier_predecessor{
        config.activation_predecessor_height -
        static_cast<int32_t>(config.chainlock_schedule.chainlock_period)};
    const auto earlier_target{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, earlier_predecessor)};
    BOOST_REQUIRE(earlier_target);
    const auto before_boundary{MakeChainLock(
        *earlier_target, earlier_predecessor,
        NonNullHash(earlier_predecessor), 68)};
    BOOST_REQUIRE(before_boundary.IsStructurallyValid());
    BOOST_CHECK(!persistence.PersistBest(before_boundary, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    BOOST_CHECK(!persistence.LoadBest());
}

BOOST_AUTO_TEST_CASE(roundtrip_survives_restart)
{
    const fs::path path{m_path_root / "pqcl_roundtrip"};
    const uint256 genesis{NonNullHash(2)};
    const auto config{MakeConfig()};
    auto chainlock{
        MakeChainLock(865, config.activation_predecessor_height,
                      NonNullHash(config.activation_predecessor_height), 1)};
    SetExactInitialization(chainlock, genesis, 1);
    auto next{MakeChainLock(
        870, chainlock.statement.height, chainlock.statement.block_hash, 2)};
    SetExactContinuation(next, genesis, chainlock);

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(chainlock));
        BOOST_REQUIRE(persistence.PersistBest(next));
        BOOST_REQUIRE(persistence.HasBest());
        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.best);
        BOOST_CHECK_EQUAL(state.certificate_revision, 2U);
        BOOST_CHECK(state.best->statement == next.statement);
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto loaded{persistence.LoadBest()};
        BOOST_REQUIRE(loaded);
        BOOST_CHECK(*loaded == next);
        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.best);
        BOOST_CHECK_EQUAL(state.certificate_revision, 1U);
        BOOST_CHECK(state.best->logical_id == next.GetLogicalId(genesis));
        BOOST_CHECK(state.best->witness_id == next.GetWitnessId(genesis));
        BOOST_CHECK(state.best->statement == next.statement);
    }
}

BOOST_AUTO_TEST_CASE(stale_base_rebase_hashes_against_the_exact_retained_prior)
{
    const fs::path path{m_path_root / "pqcl_exact_stale_base_rebase"};
    const uint256 genesis{NonNullHash(2'001)};
    const auto config{MakeConfig()};

    auto base{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 2'001)};
    SetExactInitialization(base, genesis, 2'001);

    auto hidden{MakeChainLock(
        870, base.statement.height, base.statement.block_hash, 2'002)};
    SetExactContinuation(hidden, genesis, base);

    auto higher{MakeChainLock(
        875, hidden.statement.height, hidden.statement.block_hash, 2'003)};
    SetExactContinuation(higher, genesis, base);
    const RosterAuthorizationBaseIdentity base_identity{
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    BOOST_REQUIRE(higher.statement.roster_authorization_base ==
                  base_identity);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(base));
        BOOST_REQUIRE(persistence.PersistBest(hidden));
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            base.GetLogicalId(genesis)));
        BOOST_REQUIRE(persistence.PersistBest(higher));
        const auto best{persistence.LoadBest()};
        BOOST_REQUIRE(best);
        BOOST_CHECK(*best == higher);
        BOOST_REQUIRE(persistence.LoadAuthorizationBase(
            base.GetLogicalId(genesis)));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto best{persistence.LoadBest()};
        BOOST_REQUIRE(best);
        BOOST_CHECK(*best == higher);
        const auto retained{
            persistence.LoadAuthorizationBase(base.GetLogicalId(genesis))};
        BOOST_REQUIRE(retained);
        BOOST_CHECK(*retained == base);
    }
}

BOOST_AUTO_TEST_CASE(
    receipt_archive_authorization_is_owner_bound_atomic_and_durable)
{
    const fs::path path{m_path_root / "pqcl_receipt_archive_authorization"};
    const uint256 genesis{NonNullHash(201)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 880;
    config.activation_predecessor_height = 879;
    BOOST_REQUIRE(config.IsValid());

    auto predecessor{MakeChainLock(
        880, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 201)};
    SetExactInitialization(predecessor, genesis, 201);
    auto owner{MakeChainLock(
        895, 890, NonNullHash(890), 202)};
    SetExactContinuation(owner, genesis, predecessor);
    auto archive{MakeChainLock(
        890, 885, NonNullHash(885), 203)};
    archive.statement.accepted_btcc_cursor = BTCCursor{
        archive.statement.height, archive.statement.block_hash,
        NonNullHash(890'203)};
    archive.statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(archive.IsStructurallyValid());

    ReceiptArchiveRosterAuthorization authorization;
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(owner));

        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.best);
        BOOST_REQUIRE(state.receipt_archive_authorization);
        authorization = *state.receipt_archive_authorization;
        BOOST_CHECK_EQUAL(state.certificate_revision, 2U);
        BOOST_CHECK(authorization.owner.logical_id ==
                    owner.GetLogicalId(genesis));
        BOOST_CHECK(authorization.owner.witness_id ==
                    owner.GetWitnessId(genesis));
        BOOST_CHECK(authorization.owner.statement == owner.statement);
        BOOST_CHECK(authorization.covering_logical_id ==
                    owner.GetLogicalId(genesis));
        BOOST_CHECK(authorization.covering_witness_id ==
                    owner.GetWitnessId(genesis));
        BOOST_CHECK(authorization.predecessor.logical_id ==
                    predecessor.GetLogicalId(genesis));
        BOOST_CHECK(authorization.predecessor.witness_id ==
                    predecessor.GetWitnessId(genesis));
        BOOST_CHECK(authorization.predecessor.statement ==
                    predecessor.statement);

        const auto before_rejections{persistence.GetFinalityState()};
        auto second_catchup{MakeChainLock(
            910, 905, NonNullHash(905), 204)};
        SetExactContinuation(second_catchup, genesis, owner);
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistCatchupBest(
            second_catchup, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.GetFinalityState() == before_rejections);

        auto wrong_authorization{authorization};
        wrong_authorization.owner.logical_id = NonNullHash(205);
        BOOST_CHECK(!persistence.PersistAuthorizedUnsealedBTCC(
            archive, wrong_authorization, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == before_rejections);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.best);
        BOOST_REQUIRE(restarted.receipt_archive_authorization);
        BOOST_CHECK(*restarted.receipt_archive_authorization ==
                    authorization);
        BOOST_CHECK_EQUAL(restarted.certificate_revision, 1U);

        BOOST_REQUIRE(persistence.PersistAuthorizedUnsealedBTCC(
            archive, authorization));
        const auto consumed{persistence.GetFinalityState()};
        BOOST_REQUIRE(consumed.best);
        BOOST_REQUIRE(consumed.unsealed_btcc);
        BOOST_CHECK(!consumed.receipt_archive_authorization);
        BOOST_CHECK(consumed.best->statement == owner.statement);
        BOOST_CHECK(consumed.unsealed_btcc->logical_id ==
                    archive.GetLogicalId(genesis));
        BOOST_CHECK(consumed.unsealed_btcc->witness_id ==
                    archive.GetWitnessId(genesis));
        BOOST_CHECK(consumed.unsealed_btcc->statement == archive.statement);
        BOOST_CHECK_EQUAL(consumed.certificate_revision, 2U);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.best);
        BOOST_REQUIRE(restarted.unsealed_btcc);
        BOOST_CHECK(!restarted.receipt_archive_authorization);
        BOOST_CHECK(restarted.unsealed_btcc->statement == archive.statement);
    }
}

BOOST_AUTO_TEST_CASE(
    archive_learned_receipt_source_survives_replacement_and_restart)
{
    const fs::path path{
        m_path_root / "pqcl_archive_receipt_source_restart"};
    const uint256 genesis{NonNullHash(205)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 880;
    config.activation_predecessor_height = 879;
    BOOST_REQUIRE(config.IsValid());

    auto predecessor{MakeChainLock(
        880, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 205)};
    SetExactInitialization(predecessor, genesis, 205);
    auto owner{MakeChainLock(895, 890, NonNullHash(890), 206)};
    SetExactContinuation(owner, genesis, predecessor);
    auto archive{MakeChainLock(890, 885, NonNullHash(885), 207)};
    archive.statement.accepted_btcc_cursor = BTCCursor{
        archive.statement.height, archive.statement.block_hash,
        NonNullHash(890'207)};
    archive.statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(archive.IsStructurallyValid());

    ReceiptArchiveRosterAuthorization authorization;
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(owner));
        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.receipt_archive_authorization);
        authorization = *state.receipt_archive_authorization;
        BOOST_REQUIRE(persistence.PersistAuthorizedUnsealedBTCC(
            archive, authorization));
        BOOST_CHECK(!persistence.LoadAuthorizationBase(
            archive.GetLogicalId(genesis)));
    }

    auto next_advance{MakeChainLock(
        900, owner.statement.height, owner.statement.block_hash, 208)};
    next_advance.statement.previous_btcc_cursor =
        owner.statement.accepted_btcc_cursor;
    next_advance.statement.accepted_btcc_cursor = BTCCursor{
        next_advance.statement.height, next_advance.statement.block_hash,
        NonNullHash(900'208)};
    next_advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactContinuation(next_advance, genesis, owner);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == archive);
        BOOST_REQUIRE(persistence.PersistBest(next_advance));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == next_advance);
        const auto retained{persistence.LoadAuthorizationBase(
            archive.GetLogicalId(genesis))};
        BOOST_REQUIRE(retained);
        BOOST_CHECK(*retained == archive);
        BOOST_CHECK_LE(persistence.LoadAuthorizationBases().size(),
                       VERIFIED_AUTHORIZATION_BASE_CAPACITY);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == next_advance);
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == next_advance);
        const auto retained{persistence.LoadAuthorizationBase(
            archive.GetLogicalId(genesis))};
        BOOST_REQUIRE(retained);
        BOOST_CHECK(*retained == archive);
        BOOST_CHECK_LE(persistence.LoadAuthorizationBases().size(),
                       VERIFIED_AUTHORIZATION_BASE_CAPACITY);
    }
}

BOOST_AUTO_TEST_CASE(corrupt_receipt_archive_authorization_fails_closed)
{
    const fs::path path{
        m_path_root / "pqcl_receipt_archive_authorization_corrupt"};
    const uint256 genesis{NonNullHash(206)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 206)};
    SetExactInitialization(predecessor, genesis, 206);
    auto owner{MakeChainLock(
        875, 870, NonNullHash(870), 207)};
    SetExactContinuation(owner, genesis, predecessor);
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(owner));
        BOOST_REQUIRE(
            persistence.GetFinalityState().receipt_archive_authorization);
    }
    {
        CDBWrapper raw{DiskParams(path)};
        RawReceiptArchiveRosterAuthorizationV1 authorization;
        const RawDiskKey key{
            PQ_CHAINLOCK_PERSISTENCE_RECEIPT_ARCHIVE_AUTHORIZATION_KEY};
        BOOST_REQUIRE(raw.Read(key, authorization));
        authorization.checksum.begin()[0] ^= 1;
        BOOST_REQUIRE(raw.Write(key, authorization, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(
    covering_catchup_atomically_replaces_receipt_archive_authorization)
{
    const fs::path path{
        m_path_root / "pqcl_receipt_archive_covering_catchup"};
    const uint256 genesis{NonNullHash(213)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 213)};
    SetExactInitialization(predecessor, genesis, 213);
    auto first_catchup{MakeChainLock(
        875, 870, NonNullHash(870), 214)};
    SetExactContinuation(first_catchup, genesis, predecessor);
    auto second_catchup{MakeChainLock(
        885, 880, NonNullHash(880), 215)};
    SetExactContinuation(second_catchup, genesis, first_catchup);

    ReceiptArchiveRosterAuthorization replacement;
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(first_catchup));
        const auto first_state{persistence.GetFinalityState()};
        BOOST_REQUIRE(first_state.receipt_archive_authorization);
        const auto first_authorization{
            *first_state.receipt_archive_authorization};

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistCatchupBest(
            second_catchup, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.GetFinalityState() == first_state);

        auto wrong_authorization{first_authorization};
        wrong_authorization.covering_witness_id = NonNullHash(216);
        BOOST_CHECK(!persistence.PersistCatchupBest(
            second_catchup, &error, std::nullopt,
            &wrong_authorization));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == first_state);

        BOOST_REQUIRE(persistence.PersistCatchupBest(
            second_catchup, &error, std::nullopt,
            &first_authorization));
        const auto replaced{persistence.GetFinalityState()};
        BOOST_REQUIRE(replaced.best);
        BOOST_REQUIRE(replaced.receipt_archive_authorization);
        BOOST_CHECK(replaced.best->statement == second_catchup.statement);
        replacement = *replaced.receipt_archive_authorization;
        BOOST_CHECK(replacement.owner.statement ==
                    second_catchup.statement);
        BOOST_CHECK(replacement.predecessor.statement ==
                    first_catchup.statement);
        BOOST_CHECK(replacement.covering_logical_id ==
                    second_catchup.GetLogicalId(genesis));
        BOOST_CHECK(replacement.covering_witness_id ==
                    second_catchup.GetWitnessId(genesis));
        BOOST_CHECK_EQUAL(replaced.certificate_revision, 3U);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.best);
        BOOST_REQUIRE(restarted.receipt_archive_authorization);
        BOOST_CHECK(restarted.best->statement == second_catchup.statement);
        BOOST_CHECK(*restarted.receipt_archive_authorization == replacement);
        BOOST_CHECK_EQUAL(restarted.certificate_revision, 1U);
    }
}

BOOST_AUTO_TEST_CASE(
    recovery_catchup_replaces_archive_authorization_without_precommit)
{
    const fs::path path{
        m_path_root / "pqcl_recovery_covering_receipt_archive"};
    const uint256 genesis{NonNullHash(217)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 217)};
    SetExactInitialization(predecessor, genesis, 217);
    auto first_catchup{MakeChainLock(
        875, 870, NonNullHash(870), 218)};
    SetExactContinuation(first_catchup, genesis, predecessor);
    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(recovery_target);
    auto recovered{MakeChainLock(
        *recovery_target,
        *recovery_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*recovery_target - PQ_CL_PERIOD), 220)};
    SetExactRecoveryTransitionFromPrior(
        recovered, genesis, first_catchup, /*newest_epoch=*/7);
    BOOST_REQUIRE(recovered.IsStructurallyValid());

    ReceiptArchiveRosterAuthorization replacement;
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(first_catchup));
        const auto before{persistence.GetFinalityState()};
        BOOST_REQUIRE(before.receipt_archive_authorization);
        const auto authorization{*before.receipt_archive_authorization};
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            recovered, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.GetFinalityState() == before);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());

        auto wrong_authorization{authorization};
        wrong_authorization.covering_witness_id = NonNullHash(221);
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            recovered, &error, std::nullopt, &wrong_authorization));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == before);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());

        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(
            recovered, &error, std::nullopt, &authorization));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
        const auto resolved{persistence.GetFinalityState()};
        BOOST_REQUIRE(resolved.best);
        BOOST_REQUIRE(resolved.receipt_archive_authorization);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_CHECK(resolved.best->statement == recovered.statement);
        replacement = *resolved.receipt_archive_authorization;
        BOOST_CHECK(replacement.owner.statement == recovered.statement);
        BOOST_CHECK(replacement.predecessor.statement ==
                    first_catchup.statement);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == recovered);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_REQUIRE(
            persistence.GetFinalityState().receipt_archive_authorization);
        BOOST_CHECK(
            *persistence.GetFinalityState().receipt_archive_authorization ==
            replacement);
    }
}

BOOST_AUTO_TEST_CASE(
    covering_best_rolls_and_atomically_retires_receipt_authorization)
{
    const fs::path path{
        m_path_root / "pqcl_receipt_archive_covering_best"};
    const uint256 genesis{NonNullHash(208)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 208)};
    SetExactInitialization(predecessor, genesis, 208);
    auto owner{MakeChainLock(
        875, 870, NonNullHash(870), 209)};
    SetExactContinuation(owner, genesis, predecessor);
    auto live{MakeChainLock(
        880, owner.statement.height, owner.statement.block_hash, 210)};
    SetExactContinuation(live, genesis, owner);
    auto covering{MakeChainLock(
        885, live.statement.height, live.statement.block_hash, 211)};
    SetExactContinuation(covering, genesis, live);

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(owner));
        BOOST_REQUIRE(persistence.PersistBest(live));

        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.receipt_archive_authorization);
        BOOST_CHECK(state.receipt_archive_authorization->owner.statement ==
                    owner.statement);
        BOOST_CHECK(
            state.receipt_archive_authorization->covering_logical_id ==
            live.GetLogicalId(genesis));
        BOOST_CHECK(
            state.receipt_archive_authorization->covering_witness_id ==
            live.GetWitnessId(genesis));
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.receipt_archive_authorization);
        const auto authorization{
            *restarted.receipt_archive_authorization};
        BOOST_CHECK(authorization.covering_logical_id ==
                    live.GetLogicalId(genesis));
        BOOST_CHECK(authorization.covering_witness_id ==
                    live.GetWitnessId(genesis));

        auto wrong_authorization{authorization};
        wrong_authorization.covering_witness_id = NonNullHash(212);
        const auto before_rejection{persistence.GetFinalityState()};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistBestCoveringReceiptArchive(
            covering, wrong_authorization, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == before_rejection);

        BOOST_REQUIRE(persistence.PersistBestCoveringReceiptArchive(
            covering, authorization, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
        const auto consumed{persistence.GetFinalityState()};
        BOOST_REQUIRE(consumed.best);
        BOOST_CHECK(consumed.best->statement == covering.statement);
        BOOST_CHECK(!consumed.receipt_archive_authorization);
        BOOST_REQUIRE(consumed.unsealed_btcc);
        BOOST_CHECK(consumed.unsealed_btcc->statement == covering.statement);
        BOOST_CHECK_EQUAL(consumed.certificate_revision, 2U);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.best);
        BOOST_CHECK(restarted.best->statement == covering.statement);
        BOOST_CHECK(!restarted.receipt_archive_authorization);
        BOOST_REQUIRE(restarted.unsealed_btcc);
        BOOST_CHECK(restarted.unsealed_btcc->statement == covering.statement);
    }
}

BOOST_AUTO_TEST_CASE(durable_record_view_is_coherent_and_idempotence_is_stable)
{
    const uint256 genesis{NonNullHash(61)};
    const auto config{MakeConfig()};
    PQChainLockPersistence persistence{
        MemoryParams(m_path_root / "pqcl_finality_view"), genesis, config};

    auto first{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(config.activation_predecessor_height), 61)};
    SetExactInitialization(first, genesis, 61);
    BOOST_REQUIRE(persistence.PersistInitializedBest(first));
    const auto first_state{persistence.GetFinalityState()};
    BOOST_REQUIRE(first_state.best);
    BOOST_CHECK_EQUAL(first_state.certificate_revision, 1U);
    BOOST_REQUIRE(first_state.unsealed_btcc);
    BOOST_CHECK(*first_state.best == *first_state.unsealed_btcc);
    BOOST_CHECK(first_state.best->logical_id == first.GetLogicalId(genesis));
    BOOST_CHECK(first_state.best->witness_id == first.GetWitnessId(genesis));
    BOOST_CHECK(first_state.best->statement == first.statement);

    BOOST_REQUIRE(persistence.PersistInitializedBest(first));
    BOOST_CHECK(persistence.GetFinalityState() == first_state);
    auto conflict{first};
    conflict.statement.block_hash = NonNullHash(6100);
    BOOST_CHECK(!persistence.PersistBest(conflict));
    BOOST_CHECK(persistence.GetFinalityState() == first_state);

    auto advance{MakeChainLock(
        870, first.statement.height, first.statement.block_hash, 62)};
    advance.statement.accepted_btcc_cursor = BTCCursor{
        advance.statement.height, advance.statement.block_hash,
        NonNullHash(6200)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactContinuation(advance, genesis, first);
    BOOST_REQUIRE(persistence.PersistBest(advance));
    const auto advance_state{persistence.GetFinalityState()};
    BOOST_REQUIRE(advance_state.best);
    BOOST_REQUIRE(advance_state.unsealed_btcc);
    BOOST_CHECK_EQUAL(advance_state.certificate_revision, 2U);
    BOOST_CHECK(*first_state.unsealed_btcc ==
                *advance_state.unsealed_btcc);
    BOOST_CHECK(advance_state.best->logical_id ==
                advance.GetLogicalId(genesis));
    BOOST_CHECK(advance_state.best->witness_id ==
                advance.GetWitnessId(genesis));
    BOOST_CHECK(advance_state.best->statement == advance.statement);
}

BOOST_AUTO_TEST_CASE(unsealed_record_idempotence_preserves_certificate_revision)
{
    const fs::path path{m_path_root / "pqcl_unsealed_view"};
    const uint256 genesis{NonNullHash(63)};
    const auto config{MakeConfig()};
    auto archived{MakeChainLock(875, 870, NonNullHash(870), 63)};
    archived.statement.accepted_btcc_cursor = BTCCursor{
        archived.statement.height, archived.statement.block_hash,
        NonNullHash(6300)};
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 639)};
    SetExactInitialization(initialized, genesis, 639);
    auto intermediate{MakeChainLock(
        870, initialized.statement.height,
        initialized.statement.block_hash, 640)};
    SetExactContinuation(intermediate, genesis, initialized);
    auto authorization_boundary{MakeChainLock(
        875, intermediate.statement.height,
        intermediate.statement.block_hash, 641)};
    authorization_boundary.statement.btcc_receipt_state =
        BTCCReceiptState{
            initialized.statement.accepted_btcc_cursor,
            NonNullHash(630'001), initialized.statement.height,
            authorization_boundary.statement.height};
    SetExactContinuation(
        authorization_boundary, genesis, intermediate);
    archived = authorization_boundary;
    auto authorization_predecessor{MakeChainLock(
        880, authorization_boundary.statement.height,
        authorization_boundary.statement.block_hash, 642)};
    authorization_predecessor.statement.btcc_receipt_state =
        authorization_boundary.statement.btcc_receipt_state;
    SetExactContinuation(
        authorization_predecessor, genesis, authorization_boundary);
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_REQUIRE(persistence.PersistBest(intermediate));
        BOOST_REQUIRE(persistence.PersistBest(
            authorization_boundary));
        BOOST_REQUIRE(persistence.PersistBest(
            authorization_predecessor));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == archived);
        BOOST_REQUIRE(persistence.PersistUnsealedBTCC(archived));

        const auto state{persistence.GetFinalityState()};
        BOOST_CHECK_EQUAL(state.certificate_revision, 4U);
        BOOST_REQUIRE(state.best);
        BOOST_CHECK(state.best->statement ==
                    authorization_predecessor.statement);
        BOOST_REQUIRE(state.unsealed_btcc);
        BOOST_CHECK(state.unsealed_btcc->logical_id ==
                    archived.GetLogicalId(genesis));
        BOOST_CHECK(state.unsealed_btcc->witness_id ==
                    archived.GetWitnessId(genesis));
        BOOST_CHECK(state.unsealed_btcc->statement == archived.statement);

        BOOST_REQUIRE(persistence.PersistUnsealedBTCC(archived));
        BOOST_CHECK(persistence.GetFinalityState() == state);
        auto conflict{archived};
        conflict.statement.block_hash = NonNullHash(6301);
        BOOST_CHECK(!persistence.PersistUnsealedBTCC(conflict));
        BOOST_CHECK(persistence.GetFinalityState() == state);
    }

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_CHECK_EQUAL(restarted.certificate_revision, 1U);
        BOOST_REQUIRE(restarted.best);
        BOOST_CHECK(restarted.best->statement ==
                    authorization_predecessor.statement);
        BOOST_REQUIRE(restarted.unsealed_btcc);
        BOOST_CHECK(restarted.unsealed_btcc->logical_id ==
                    archived.GetLogicalId(genesis));
        BOOST_CHECK(restarted.unsealed_btcc->witness_id ==
                    archived.GetWitnessId(genesis));
        BOOST_CHECK(restarted.unsealed_btcc->statement ==
                    archived.statement);

        auto seal{MakeChainLock(
            885, authorization_predecessor.statement.height,
            authorization_predecessor.statement.block_hash, 64)};
        seal.statement.previous_btcc_cursor =
            authorization_predecessor.statement.accepted_btcc_cursor;
        seal.statement.accepted_btcc_cursor =
            archived.statement.accepted_btcc_cursor;
        seal.statement.btcc_advance = BTCCAdvance::KEEP;
        seal.statement.btcc_receipt_state = BTCCReceiptState{
            archived.statement.accepted_btcc_cursor, NonNullHash(6302),
            archived.statement.height, seal.statement.height};
        SetExactContinuation(
            seal, genesis, authorization_predecessor);
        BOOST_REQUIRE(persistence.PersistBest(seal));

        const auto sealed{persistence.GetFinalityState()};
        BOOST_CHECK_EQUAL(sealed.certificate_revision, 2U);
        BOOST_REQUIRE(sealed.best);
        BOOST_CHECK(sealed.best->logical_id == seal.GetLogicalId(genesis));
        BOOST_CHECK(sealed.best->witness_id == seal.GetWitnessId(genesis));
        BOOST_CHECK(sealed.best->statement == seal.statement);
        BOOST_REQUIRE(sealed.unsealed_btcc);
        BOOST_CHECK(sealed.unsealed_btcc->statement == seal.statement);
    }
}

BOOST_AUTO_TEST_CASE(
    recovery_unsealed_retains_exact_source_across_restart)
{
    const fs::path path{m_path_root / "pqcl_recovery_unsealed_source"};
    const uint256 genesis{NonNullHash(630)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 629)};
    SetExactInitialization(prior, genesis, 629);
    const auto source{RecoverySourceFromPrior(prior)};

    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(recovery_target);
    auto recovered{MakeChainLock(
        *recovery_target,
        *recovery_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*recovery_target - PQ_CL_PERIOD), 630)};
    SetExactRecoveryTransitionFromPrior(
        recovered, genesis, prior, /*newest_epoch=*/7);
    const auto intermediate_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, *recovery_target)};
    BOOST_REQUIRE(intermediate_height);
    auto intermediate{MakeChainLock(
        *intermediate_height, recovered.statement.height,
        recovered.statement.block_hash, 631)};
    SetExactContinuation(intermediate, genesis, recovered);
    const auto archived_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, *intermediate_height)};
    BOOST_REQUIRE(archived_height);
    auto archived{MakeChainLock(
        *archived_height, intermediate.statement.height,
        intermediate.statement.block_hash, 632)};
    archived.statement.previous_btcc_cursor =
        intermediate.statement.accepted_btcc_cursor;
    archived.statement.accepted_btcc_cursor = BTCCursor{
        archived.statement.height, archived.statement.block_hash,
        NonNullHash(630'001)};
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactContinuation(archived, genesis, intermediate);
    BOOST_REQUIRE(archived.IsStructurallyValid());
    BOOST_REQUIRE(HasRecoveryRosterBeacon(
        archived.statement.roster_beacons));
    BOOST_CHECK(archived.statement.roster_beacons.active
                    .recovery_authority_source == source);

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_REQUIRE_MESSAGE(
            persistence.PersistUnsealedBTCC(archived, &error),
            "persistence error " << static_cast<int>(error));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == archived);
        BOOST_CHECK(persistence.LoadUnsealedBTCC()
                        ->statement.roster_beacons.active
                        .recovery_authority_source == source);
    }
}

BOOST_AUTO_TEST_CASE(
    mixed_recovery_rotation_retains_and_validates_exact_source)
{
    const fs::path path{m_path_root / "pqcl_mixed_recovery_source"};
    const uint256 genesis{NonNullHash(633)};
    const auto config{MakeConfig()};
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 633)};
    SetExactInitialization(initialized, genesis, 633);

    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(recovery_target);
    auto recovered{MakeChainLock(
        *recovery_target,
        *recovery_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*recovery_target - PQ_CL_PERIOD), 634)};
    SetExactRecoveryTransitionFromPrior(
        recovered, genesis, initialized, /*newest_epoch=*/7);

    const auto observed_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, recovered.statement.height)};
    BOOST_REQUIRE(observed_height);
    auto observed{MakeChainLock(
        *observed_height, recovered.statement.height,
        recovered.statement.block_hash, 635)};
    SetExactRecoveryObservation(observed, genesis, recovered);

    const auto mixed_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, observed.statement.height)};
    BOOST_REQUIRE(mixed_height);
    auto mixed{MakeChainLock(
        *mixed_height, observed.statement.height,
        observed.statement.block_hash, 636)};
    SetExactPostRecoveryRotation(mixed, genesis, observed);
    const auto source{RecoverySourceFromPrior(recovered)};

    auto mismatched_source{mixed};
    mismatched_source.statement.roster_beacons.active.seeds.front()
        .future_btc_hash = NonNullHash(637);
    BOOST_REQUIRE(mismatched_source.IsStructurallyValid());

    auto recovery_after_normal{mixed};
    auto normal_seed{
        recovery_after_normal.statement.roster_beacons.active.seeds.back()};
    normal_seed.epoch = recovery_after_normal.statement.roster_beacons
                            .active.seeds[1].epoch;
    auto recovery_seed{
        recovery_after_normal.statement.roster_beacons.active.seeds.front()};
    recovery_seed.epoch = recovery_after_normal.statement.roster_beacons
                              .active.seeds[2].epoch;
    recovery_after_normal.statement.roster_beacons.active.seeds[1] =
        std::move(normal_seed);
    recovery_after_normal.statement.roster_beacons.active.seeds[2] =
        std::move(recovery_seed);
    BOOST_REQUIRE(recovery_after_normal.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(recovered));
        BOOST_REQUIRE(persistence.PersistBest(observed));
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistBest(mismatched_source, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(!persistence.PersistBest(recovery_after_normal, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_REQUIRE(persistence.PersistBest(mixed, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto loaded{persistence.LoadBest()};
        BOOST_REQUIRE(loaded);
        BOOST_CHECK(*loaded == mixed);
        BOOST_CHECK(loaded->statement.roster_beacons.active
                        .recovery_authority_source == source);
    }
}

BOOST_AUTO_TEST_CASE(marker_only_mutations_do_not_advance_certificate_revision)
{
    auto btcc_config{MakeConfig()};
    btcc_config.btcc_receipt_assumption_anchor =
        BTCCReceiptAssumptionAnchor{
            860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(btcc_config.IsValid());
    PQChainLockPersistence btcc_persistence{
        MemoryParams(m_path_root / "pqcl_btcc_marker_only"),
        NonNullHash(64), btcc_config};
    const auto empty_btcc_state{btcc_persistence.GetFinalityState()};
    BOOST_REQUIRE(btcc_persistence.PersistBTCCPresealState(
        BTCCPresealState{
            MakePresealMarker(875, 875, 1, 64), std::nullopt}));
    BOOST_CHECK(btcc_persistence.GetFinalityState() == empty_btcc_state);
    BOOST_REQUIRE(btcc_persistence.ClearBTCCPresealState());
    BOOST_CHECK(btcc_persistence.GetFinalityState() == empty_btcc_state);

    const auto payment_config{MakePaymentAuditConfig()};
    BOOST_REQUIRE(payment_config.IsValid());
    PQChainLockPersistence payment_persistence{
        MemoryParams(m_path_root / "pqcl_payment_marker_only"),
        NonNullHash(65), payment_config};
    const auto empty_payment_state{payment_persistence.GetFinalityState()};
    BOOST_REQUIRE(payment_persistence.PersistPaymentAuditPresealState(
        PaymentAuditPresealState{
            MakePaymentAuditPresealMarker(
                payment_config, /*epoch=*/3, /*revision=*/1, /*salt=*/65),
            std::nullopt}));
    BOOST_CHECK(payment_persistence.GetFinalityState() ==
                empty_payment_state);
    BOOST_REQUIRE(payment_persistence.ClearPaymentAuditPresealState());
    BOOST_CHECK(payment_persistence.GetFinalityState() ==
                empty_payment_state);
}

BOOST_AUTO_TEST_CASE(active_and_prospective_preseals_survive_crash_cut)
{
    const fs::path path{m_path_root / "pqcl_preseal_two_branch"};
    const uint256 genesis{NonNullHash(23)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(config.IsValid());

    const BTCCPresealMarker active_b_revision_1{
        MakePresealMarker(875, 875, 1, 880)};
    const BTCCPresealMarker active_b_revision_2{
        MakePresealMarker(875, 875, 2, 880)};
    const BTCCPresealMarker prospective_a_revision_2{
        MakePresealMarker(875, 885, 2, 890)};
    const BTCCPresealState both{
        active_b_revision_2, prospective_a_revision_2};

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(
            BTCCPresealState{active_b_revision_1, std::nullopt}));
        // Crash cut: A's prospective boundary is fsynced before A activates.
        // B's earlier active replay obligation must remain in the same atomic
        // state rather than being overwritten by A.
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(both));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == both);

        const BTCCPresealMarker prospective_a_revision_3{
            MakePresealMarker(875, 885, 3, 890)};
        const BTCCPresealState after_b_replay{
            std::nullopt, prospective_a_revision_3};
        BOOST_REQUIRE(
            persistence.PersistBTCCPresealState(after_b_replay));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const BTCCPresealState expected{
            std::nullopt, MakePresealMarker(875, 885, 3, 890)};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == expected);
    }
}

BOOST_AUTO_TEST_CASE(exact_keep_preseal_survives_restart)
{
    const fs::path path{m_path_root / "pqcl_preseal_keep"};
    const uint256 genesis{NonNullHash(29)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(config.IsValid());
    const BTCCPresealMarker marker{MakeKeepPresealMarker(1, 29)};
    const BTCCPresealState expected{marker, std::nullopt};

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(expected));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == expected);

        auto cursor_substitution{marker};
        cursor_substitution.revision = 2;
        cursor_substitution.terminal_receipt.accepted_cursor.sys_hash =
            NonNullHash(570'000);
        BOOST_CHECK(!persistence.PersistBTCCPresealState(
            BTCCPresealState{cursor_substitution, std::nullopt}));
    }
}

BOOST_AUTO_TEST_CASE(late_initial_preseal_survives_restart)
{
    const fs::path path{m_path_root / "pqcl_preseal_late_initial"};
    const uint256 genesis{NonNullHash(31)};
    auto config{MakeConfig()};
    auto late_anchor_config{config};
    late_anchor_config.btcc_receipt_assumption_anchor =
        BTCCReceiptAssumptionAnchor{
            885, NonNullHash(885),
            BTCCReceiptState{
                BTCCursor{865, NonNullHash(570'000),
                           NonNullHash(570'001)},
                NonNullHash(570'002), 865, 885}};
    BOOST_CHECK(late_anchor_config.IsValid());

    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(config.IsValid());
    const BTCCPresealMarker marker{MakeLateInitialPresealMarker(1, 31)};
    const BTCCPresealState expected{marker, std::nullopt};

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(expected));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == expected);

        auto non_initial_first{marker};
        non_initial_first.revision = 2;
        non_initial_first.terminal_receipt.chainlock_target_height = 875;
        non_initial_first.terminal_receipt.chainlock_target_hash =
            NonNullHash(569'000);
        non_initial_first.terminal_receipt.accepted_cursor = BTCCursor{
            875, non_initial_first.terminal_receipt.chainlock_target_hash,
            NonNullHash(569'001)};
        BOOST_CHECK(!persistence.PersistBTCCPresealState(
            BTCCPresealState{non_initial_first, std::nullopt}));
    }
}

BOOST_AUTO_TEST_CASE(advance_then_keep_preseal_range_survives_restart)
{
    const fs::path path{m_path_root / "pqcl_preseal_advance_keep"};
    const uint256 genesis{NonNullHash(30)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(config.IsValid());
    const BTCCPresealMarker marker{
        MakeAdvanceThenKeepPresealMarker(1, 30)};
    const BTCCPresealState expected{marker, std::nullopt};

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(expected));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == expected);

        auto parent_substitution{marker};
        parent_substitution.revision = 2;
        parent_substitution.terminal_parent_receipt_state =
            parent_substitution.predecessor_receipt_state;
        BOOST_CHECK(!persistence.PersistBTCCPresealState(
            BTCCPresealState{parent_substitution, std::nullopt}));
    }
}

BOOST_AUTO_TEST_CASE(preseal_marker_revisions_and_dependencies_fail_closed)
{
    const fs::path path{m_path_root / "pqcl_preseal_revision"};
    const uint256 genesis{NonNullHash(24)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    BOOST_REQUIRE(config.IsValid());

    const BTCCPresealMarker initial{MakePresealMarker(875, 875, 7, 1)};
    PQChainLockPersistence persistence{DiskParams(path), genesis, config};
    BOOST_REQUIRE(persistence.PersistBTCCPresealState(
        BTCCPresealState{initial, std::nullopt}));
    BOOST_CHECK(persistence.PersistBTCCPresealState(
        BTCCPresealState{initial, std::nullopt}));

    auto changed_without_revision{initial};
    changed_without_revision.terminal_carrier_height = 885;
    changed_without_revision.terminal_carrier_hash = NonNullHash(885);
    const auto advanced{MakePresealMarker(875, 885, 7, 2)};
    changed_without_revision.terminal_parent_receipt_state =
        advanced.terminal_parent_receipt_state;
    changed_without_revision.terminal_receipt = advanced.terminal_receipt;
    BOOST_CHECK(!persistence.PersistBTCCPresealState(
        BTCCPresealState{changed_without_revision, std::nullopt}));

    auto changed{changed_without_revision};
    changed.revision = 8;
    BOOST_REQUIRE(persistence.PersistBTCCPresealState(
        BTCCPresealState{changed, std::nullopt}));
    BOOST_CHECK(persistence.LoadBTCCPresealState().active == changed);

    auto corrupt_receipt{changed};
    corrupt_receipt.revision = 9;
    corrupt_receipt.terminal_receipt.chainlock_logical_id.SetNull();
    BOOST_CHECK(!persistence.PersistBTCCPresealState(
        BTCCPresealState{corrupt_receipt, std::nullopt}));

    BOOST_REQUIRE(persistence.ClearBTCCPresealState());
    auto reused_revision{MakePresealMarker(875, 895, 8, 3)};
    BOOST_CHECK(!persistence.PersistBTCCPresealState(
        BTCCPresealState{reused_revision, std::nullopt}));
    reused_revision.revision = 9;
    BOOST_CHECK(persistence.PersistBTCCPresealState(
        BTCCPresealState{reused_revision, std::nullopt}));
}

BOOST_AUTO_TEST_CASE(payment_audit_preseal_state_is_atomic_and_monotonic)
{
    const fs::path path{m_path_root / "pqcl_payment_audit_preseal"};
    const uint256 genesis{NonNullHash(27)};
    const auto config{MakePaymentAuditConfig()};
    BOOST_REQUIRE(config.IsValid());

    const auto active_revision_1{
        MakePaymentAuditPresealMarker(config, 3, 1, 1)};
    const auto active_revision_2{
        MakePaymentAuditPresealMarker(config, 3, 2, 1)};
    auto prospective_revision_2{
        MakePaymentAuditPresealMarker(config, 4, 2, 2)};
    // Two branches can share the first missing receipt and diverge only at a
    // later carrier. Both crash-durable obligations must survive together.
    prospective_revision_2.earliest_carrier_height =
        active_revision_2.earliest_carrier_height;
    prospective_revision_2.earliest_carrier_hash =
        active_revision_2.earliest_carrier_hash;
    prospective_revision_2.predecessor_receipt_state =
        active_revision_2.predecessor_receipt_state;
    prospective_revision_2.predecessor_probation_state_hash =
        active_revision_2.predecessor_probation_state_hash;
    const PaymentAuditPresealState both{
        active_revision_2, prospective_revision_2};

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadPaymentAuditPresealState().IsEmpty());
        BOOST_REQUIRE(persistence.PersistPaymentAuditPresealState(
            PaymentAuditPresealState{active_revision_1, std::nullopt}));
        BOOST_REQUIRE(
            persistence.PersistPaymentAuditPresealState(both));
        BOOST_CHECK(persistence.LoadPaymentAuditPresealState() == both);

        auto stale{active_revision_2};
        stale.terminal_receipt.audit_witness_id = NonNullHash(999'002);
        BOOST_CHECK(!persistence.PersistPaymentAuditPresealState(
            PaymentAuditPresealState{stale, std::nullopt}));

        auto impossible_schedule{active_revision_2};
        ++impossible_schedule.terminal_receipt.seal_height;
        ++impossible_schedule.revision;
        BOOST_CHECK(!persistence.PersistPaymentAuditPresealState(
            PaymentAuditPresealState{impossible_schedule, std::nullopt}));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadPaymentAuditPresealState() == both);

        const auto prospective_revision_3{
            MakePaymentAuditPresealMarker(config, 4, 3, 2)};
        const PaymentAuditPresealState after_active_replay{
            std::nullopt, prospective_revision_3};
        BOOST_REQUIRE(persistence.PersistPaymentAuditPresealState(
            after_active_replay));
        BOOST_REQUIRE(persistence.ClearPaymentAuditPresealState());
        BOOST_CHECK(persistence.LoadPaymentAuditPresealState().IsEmpty());

        auto reused{MakePaymentAuditPresealMarker(config, 5, 3, 3)};
        BOOST_CHECK(!persistence.PersistPaymentAuditPresealState(
            PaymentAuditPresealState{reused, std::nullopt}));
        reused.revision = 4;
        BOOST_CHECK(persistence.PersistPaymentAuditPresealState(
            PaymentAuditPresealState{reused, std::nullopt}));
    }
}

BOOST_AUTO_TEST_CASE(truncated_preseal_marker_fails_closed)
{
    const fs::path path{m_path_root / "pqcl_preseal_truncated"};
    const uint256 genesis{NonNullHash(25)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
    }
    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Write(
            RawDiskKey{PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY},
            RawTruncatedBTCCPresealMarker{
                1, NonNullHash(1), 870, NonNullHash(870), NonNullHash(2)},
            true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(corrupt_preseal_marker_fails_closed)
{
    const fs::path path{m_path_root / "pqcl_preseal_corrupt"};
    const uint256 genesis{NonNullHash(26)};
    auto config{MakeConfig()};
    config.btcc_receipt_assumption_anchor = BTCCReceiptAssumptionAnchor{
        860, NonNullHash(860), BTCCReceiptState{}};
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistBTCCPresealState(
            BTCCPresealState{MakePresealMarker(875, 875, 1, 4),
                             std::nullopt}));
    }
    {
        CDBWrapper raw{DiskParams(path)};
        RawBTCCPresealMarkerV1 marker;
        BOOST_REQUIRE(raw.Read(
            RawDiskKey{PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY}, marker));
        BOOST_CHECK_EQUAL(GetSerializeSize(marker), 500U);
        marker.terminal_receipt.chainlock_logical_id.begin()[0] ^= 1;
        BOOST_REQUIRE(raw.Write(
            RawDiskKey{PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY}, marker,
            true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(wrong_schema_and_configuration_fail_closed)
{
    const fs::path path{m_path_root / "pqcl_wrong_schema"};
    const uint256 genesis{NonNullHash(3)};
    auto config{MakeConfig()};
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
    }

    config.btcc_schedule.candidate_origin +=
        config.btcc_schedule.candidate_period;
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), NonNullHash(4), MakeConfig()),
        std::runtime_error);

    const fs::path activation_path{
        m_path_root / "pqcl_wrong_activation_height"};
    {
        PQChainLockPersistence persistence{
            DiskParams(activation_path), genesis, MakeConfig()};
    }
    auto changed_activation{MakeConfig()};
    changed_activation.activation_predecessor_height -= static_cast<int32_t>(
        changed_activation.chainlock_schedule.chainlock_period);
    BOOST_REQUIRE(changed_activation.IsValid());
    BOOST_CHECK_THROW(
        PQChainLockPersistence(
            DiskParams(activation_path), genesis, changed_activation),
        std::runtime_error);

    const fs::path missing_schema{m_path_root / "pqcl_missing_schema"};
    {
        CDBWrapper raw{DiskParams(missing_schema)};
        BOOST_REQUIRE(raw.Write(RawDiskKey{
                                    PQ_CHAINLOCK_PERSISTENCE_BEST_KEY},
                                uint8_t{1}, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(
            DiskParams(missing_schema), genesis, MakeConfig()),
        std::runtime_error);

    const fs::path unknown_key{m_path_root / "pqcl_unknown_key"};
    {
        CDBWrapper raw{DiskParams(unknown_key)};
        BOOST_REQUIRE(raw.Write(RawDiskKey{99}, uint8_t{1}, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(
            DiskParams(unknown_key), genesis, MakeConfig()),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(corrupt_best_record_fails_closed)
{
    const fs::path path{m_path_root / "pqcl_corrupt"};
    const uint256 genesis{NonNullHash(5)};
    const auto config{MakeConfig()};
    auto chainlock{
        MakeChainLock(865, config.activation_predecessor_height,
                      NonNullHash(config.activation_predecessor_height), 5)};
    SetExactInitialization(chainlock, genesis, 5);
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(chainlock));
    }
    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Write(RawDiskKey{
                                    PQ_CHAINLOCK_PERSISTENCE_BEST_KEY},
                                std::vector<unsigned char>{1, 2, 3}, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(writes_are_monotonic_and_first_winner_is_durable)
{
    const uint256 genesis{NonNullHash(6)};
    const auto config{MakeConfig()};
    PQChainLockPersistence persistence{
        MemoryParams(m_path_root / "pqcl_monotonic"), genesis, config};

    auto first{
        MakeChainLock(865, config.activation_predecessor_height,
                      NonNullHash(config.activation_predecessor_height), 6)};
    first.statement.accepted_btcc_cursor =
        BTCCursor{860, NonNullHash(8600), NonNullHash(8601)};
    first.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactInitialization(first, genesis, 6);
    BOOST_REQUIRE(first.IsStructurallyValid());
    BOOST_REQUIRE(persistence.PersistInitializedBest(first));
    BOOST_CHECK(persistence.PersistInitializedBest(first));

    auto conflict{first};
    conflict.statement.block_hash = NonNullHash(9999);
    BOOST_CHECK(!persistence.PersistBest(conflict));

    auto next{MakeChainLock(870, 865, first.statement.block_hash, 7)};
    next.statement.previous_btcc_cursor =
        first.statement.accepted_btcc_cursor;
    next.statement.accepted_btcc_cursor =
        first.statement.accepted_btcc_cursor;
    SetExactContinuation(next, genesis, first);
    BOOST_REQUIRE(persistence.PersistBest(next));

    auto stale{
        MakeChainLock(865, config.activation_predecessor_height,
                      NonNullHash(config.activation_predecessor_height), 8)};
    BOOST_CHECK(!persistence.PersistBest(stale));

    auto rollback{MakeChainLock(875, 870, next.statement.block_hash, 9)};
    rollback.statement.previous_btcc_cursor = {};
    rollback.statement.accepted_btcc_cursor = {};
    BOOST_REQUIRE(rollback.IsStructurallyValid());
    BOOST_CHECK(!persistence.PersistBest(rollback));

    const auto loaded{persistence.LoadBest()};
    BOOST_REQUIRE(loaded);
    BOOST_CHECK(*loaded == next);
}

BOOST_AUTO_TEST_CASE(durable_records_require_the_unique_successor_geometry)
{
    const uint256 genesis{NonNullHash(60)};
    const auto config{MakeConfig()};
    PQChainLockPersistence persistence{
        MemoryParams(m_path_root / "pqcl_successor_geometry"),
        genesis, config};
    const auto skipped{MakeChainLock(
        870, config.activation_predecessor_height, NonNullHash(config.activation_predecessor_height), 60)};
    ChainLockPersistenceError error{ChainLockPersistenceError::NONE};

    BOOST_CHECK(!persistence.PersistBest(skipped, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    BOOST_CHECK(!persistence.PersistCatchupBest(skipped, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    BOOST_CHECK(!persistence.LoadBest());

    auto later_initialize{skipped};
    SetExactInitialization(later_initialize, genesis, 60);
    BOOST_CHECK(!persistence.PersistInitializedBest(
        later_initialize, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    BOOST_CHECK(!persistence.LoadBest());

    const auto first_target{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, config.activation_predecessor_height)};
    BOOST_REQUIRE(first_target);
    auto initialized{MakeChainLock(
        *first_target, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 61)};
    SetExactInitialization(initialized, genesis, 61);
    BOOST_REQUIRE(persistence.PersistInitializedBest(
        initialized, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    auto exact{MakeChainLock(
        870, *first_target, initialized.statement.block_hash, 62)};
    SetExactContinuation(exact, genesis, initialized);
    BOOST_REQUIRE(persistence.PersistBest(exact, &error));
    BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    BOOST_REQUIRE(persistence.LoadBest());
    BOOST_CHECK(*persistence.LoadBest() == exact);
}

BOOST_AUTO_TEST_CASE(unsealed_advance_survives_restart_until_descendant_seal)
{
    const fs::path path{m_path_root / "pqcl_unsealed_btcc"};
    const uint256 genesis{NonNullHash(10)};
    const auto config{MakeConfig()};

    auto advance{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 10)};
    advance.statement.accepted_btcc_cursor =
        BTCCursor{865, advance.statement.block_hash, NonNullHash(8650)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactInitialization(advance, genesis, 10);
    BOOST_REQUIRE(advance.IsStructurallyValid());

    auto before_seal{
        MakeChainLock(870, 865, advance.statement.block_hash, 11)};
    before_seal.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    before_seal.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    SetExactContinuation(before_seal, genesis, advance);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(advance));
        BOOST_REQUIRE(persistence.PersistBest(before_seal));
        // A LIVE winner below the carrier retains the outstanding advance.
        // CATCHUP is a per-candidate mode and follows the same sealing rule.
        BOOST_CHECK(!persistence.HasCatchupMarker());
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == advance);
        const auto base{persistence.LoadAuthorizationBase(
            advance.GetLogicalId(genesis))};
        BOOST_REQUIRE(base);
        BOOST_CHECK(*base == advance);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == advance);
        const auto base{persistence.LoadAuthorizationBase(
            advance.GetLogicalId(genesis))};
        BOOST_REQUIRE(base);
        BOOST_CHECK(*base == advance);
        BOOST_CHECK(!persistence.HasCatchupMarker());

        auto seal{MakeChainLock(875, 870,
                                before_seal.statement.block_hash, 12)};
        seal.statement.previous_btcc_cursor =
            advance.statement.accepted_btcc_cursor;
        seal.statement.accepted_btcc_cursor =
            advance.statement.accepted_btcc_cursor;
        seal.statement.btcc_receipt_state = BTCCReceiptState{
            advance.statement.accepted_btcc_cursor, NonNullHash(8750),
            advance.statement.height, seal.statement.height};
        SetExactContinuation(seal, genesis, before_seal);
        BOOST_REQUIRE(persistence.PersistBest(seal));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == seal);
        BOOST_CHECK(!persistence.HasCatchupMarker());
    }
}

BOOST_AUTO_TEST_CASE(
    unsealed_recovery_keep_survives_restart_until_exact_receipt_slot)
{
    const fs::path path{m_path_root / "pqcl_unsealed_recovery_keep"};
    const uint256 genesis{NonNullHash(18)};
    const auto config{MakeConfig()};

    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 18)};
    SetExactInitialization(initialized, genesis, 18);

    const auto recovery_height{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(recovery_height);
    auto recovery{MakeChainLock(
        *recovery_height,
        *recovery_height - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*recovery_height - PQ_CL_PERIOD), 19)};
    SetExactRecoveryTransitionFromPrior(
        recovery, genesis, initialized, /*newest_epoch=*/7);
    BOOST_REQUIRE(recovery.statement.btcc_advance == BTCCAdvance::KEEP);
    BOOST_REQUIRE(!recovery.statement.accepted_btcc_cursor.IsNull());
    BOOST_REQUIRE(IsBTCCCandidateHeight(
        config.btcc_schedule, recovery.statement.height));

    const auto intermediate_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, recovery.statement.height)};
    BOOST_REQUIRE(intermediate_height);
    auto intermediate{MakeChainLock(
        *intermediate_height, recovery.statement.height,
        recovery.statement.block_hash, 20)};
    SetExactContinuation(intermediate, genesis, recovery);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(recovery));
        BOOST_REQUIRE(persistence.PersistBest(intermediate));
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == recovery);
    }

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == recovery);

        const int32_t carrier_height{
            recovery.statement.height +
            static_cast<int32_t>(config.btcc_schedule.nevm_injection_lag)};
        BOOST_REQUIRE_EQUAL(
            carrier_height,
            *intermediate_height + static_cast<int32_t>(PQ_CL_PERIOD));
        auto seal{MakeChainLock(
            carrier_height, intermediate.statement.height,
            intermediate.statement.block_hash, 21)};
        seal.statement.btcc_receipt_state = BTCCReceiptState{
            recovery.statement.accepted_btcc_cursor, NonNullHash(180'021),
            recovery.statement.height, carrier_height};
        SetExactContinuation(seal, genesis, intermediate);
        BOOST_REQUIRE(persistence.PersistBest(seal));

        // The recovery certificate has passed its sole receipt slot. The
        // carrier-height KEEP is itself the next exact-slot candidate, so the
        // single bounded record rolls forward rather than retaining both.
        const auto rolled{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(rolled);
        BOOST_CHECK(*rolled == seal);
        BOOST_CHECK(*rolled != recovery);
    }
}

BOOST_AUTO_TEST_CASE(
    candidate_bound_cursor_reconciliation_is_atomic_across_restart)
{
    const fs::path path{m_path_root / "pqcl_cursor_reconciliation"};
    const fs::path no_unsealed_path{
        m_path_root / "pqcl_cursor_reconciliation_no_unsealed"};
    const uint256 genesis{NonNullHash(13)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(config.activation_predecessor_height), 13)};
    SetExactInitialization(prior, genesis, 13);
    auto bridge{MakeChainLock(870, 865, prior.statement.block_hash, 140)};
    SetExactContinuation(bridge, genesis, prior);
    auto advance{MakeChainLock(875, 870, bridge.statement.block_hash, 14)};
    advance.statement.accepted_btcc_cursor =
        BTCCursor{875, advance.statement.block_hash, NonNullHash(87'514)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactContinuation(advance, genesis, bridge);
    auto premature{
        MakeChainLock(880, 875, advance.statement.block_hash, 15)};
    SetExactContinuation(premature, genesis, advance);
    auto keep{MakeChainLock(880, 875, advance.statement.block_hash, 16)};
    keep.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    keep.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    SetExactContinuation(keep, genesis, advance);
    auto recovery{
        MakeChainLock(885, 880, keep.statement.block_hash, 17)};
    SetExactContinuation(recovery, genesis, keep);
    recovery.statement.previous_btcc_cursor = {};
    recovery.statement.accepted_btcc_cursor = {};
    const auto proof{MakeReconciliationProof(keep, 17)};
    BOOST_REQUIRE(proof.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(prior));
        BOOST_REQUIRE(persistence.PersistBest(bridge));
        BOOST_REQUIRE(persistence.PersistBest(advance));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistCatchupBest(
            premature, &error, proof));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        BOOST_REQUIRE(persistence.PersistBest(keep, &error));
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(!persistence.PersistCatchupBest(recovery, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::NON_MONOTONIC_BTCC);

        auto wrong_proof{proof};
        ++wrong_proof.carrier_height;
        BOOST_CHECK(!persistence.PersistCatchupBest(
            recovery, &error, wrong_proof));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        BOOST_REQUIRE(persistence.PersistCatchupBest(
            recovery, &error, proof));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
        BOOST_CHECK(persistence.HasCatchupMarker());
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto best{persistence.LoadBest()};
        BOOST_REQUIRE(best);
        BOOST_CHECK(*best == recovery);
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
        BOOST_CHECK(persistence.HasCatchupMarker());
    }

    // A peer can catch up directly to KEEP(C) without ever archiving the
    // ADVANCE(C). Its signed winner still carries the same cursor-vs-receipt
    // gap and must converge through the identical null-carrier proof.
    auto direct_keep{keep};
    SetExactContinuation(direct_keep, genesis, prior);
    auto direct_recovery{recovery};
    SetExactContinuation(direct_recovery, genesis, direct_keep);
    direct_recovery.statement.previous_btcc_cursor = {};
    direct_recovery.statement.accepted_btcc_cursor = {};
    {
        PQChainLockPersistence persistence{
            DiskParams(no_unsealed_path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(prior));
        BOOST_REQUIRE(persistence.PersistCatchupBest(direct_keep));
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(no_unsealed_path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == direct_keep);
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
        BOOST_REQUIRE(persistence.PersistCatchupBest(
            direct_recovery, nullptr, proof));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(no_unsealed_path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == direct_recovery);
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
    }
}

BOOST_AUTO_TEST_CASE(normal_winner_block_index_precedes_certificate_crash_cuts)
{
    const fs::path index_path{m_path_root / "pqcl_index_before_normal"};
    const fs::path certificate_path{m_path_root / "pqcl_cert_after_normal"};
    const uint256 genesis{NonNullHash(20)};
    const auto config{MakeConfig()};
    const auto index_state{WriteDurableBTCCIndexState(index_path)};
    auto winner{MakeBTCCWinner(index_state, config, 20)};
    auto predecessor{MakeChainLock(
        winner.statement.previous_chainlock_height,
        config.activation_predecessor_height,
        winner.statement.previous_chainlock_hash, 19)};
    SetExactInitialization(predecessor, genesis, 19);
    SetExactContinuation(winner, genesis, predecessor);

    // Crash cut 1: the index fsync happened but certificate acceptance did
    // not. Restart sees usable branch metadata and no invented winner.
    {
        const auto loaded_index{
            LoadDurableBTCCIndexState(index_path, index_state.block_hash)};
        BOOST_CHECK(loaded_index.receipt_state == index_state.receipt_state);
        BOOST_CHECK(loaded_index.status &
                    BLOCK_PQ_BTCC_INDEX_VALIDATED);
        PQChainLockPersistence persistence{
            DiskParams(certificate_path), genesis, config};
        BOOST_CHECK(!persistence.LoadBest());
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(certificate_path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistBest(winner));
    }

    // Crash cut 2: once the certificate fsync completes, restart can verify
    // it against the exact BTCPREV and receipt state already on disk.
    {
        const auto loaded_index{
            LoadDurableBTCCIndexState(index_path, index_state.block_hash)};
        BOOST_CHECK(loaded_index.btcp_prev == index_state.btcp_prev);
        BOOST_CHECK(loaded_index.receipt_state == winner.statement.btcc_receipt_state);
        PQChainLockPersistence persistence{
            DiskParams(certificate_path), genesis, config};
        const auto loaded_winner{persistence.LoadBest()};
        BOOST_REQUIRE(loaded_winner);
        BOOST_CHECK(*loaded_winner == winner);
    }
}

BOOST_AUTO_TEST_CASE(catchup_winner_block_index_precedes_certificate_crash_cuts)
{
    const fs::path index_path{m_path_root / "pqcl_index_before_catchup"};
    const fs::path certificate_path{m_path_root / "pqcl_cert_after_catchup"};
    const uint256 genesis{NonNullHash(21)};
    const auto config{MakeConfig()};
    const auto index_state{WriteDurableBTCCIndexState(index_path)};
    auto winner{MakeBTCCWinner(index_state, config, 21)};
    auto predecessor{MakeChainLock(
        winner.statement.previous_chainlock_height,
        config.activation_predecessor_height,
        winner.statement.previous_chainlock_hash, 20)};
    SetExactInitialization(predecessor, genesis, 20);
    SetExactContinuation(winner, genesis, predecessor);

    {
        PQChainLockPersistence persistence{
            DiskParams(certificate_path), genesis, config};
        BOOST_CHECK(!persistence.LoadBest());
        BOOST_CHECK(!persistence.HasCatchupMarker());
        BOOST_REQUIRE(persistence.PersistInitializedBest(predecessor));
        BOOST_REQUIRE(persistence.PersistCatchupBest(winner));
    }

    const auto loaded_index{
        LoadDurableBTCCIndexState(index_path, index_state.block_hash)};
    BOOST_CHECK(loaded_index.btcp_prev == index_state.btcp_prev);
    BOOST_CHECK(loaded_index.receipt_state == winner.statement.btcc_receipt_state);
    PQChainLockPersistence persistence{
        DiskParams(certificate_path), genesis, config};
    const auto loaded_winner{persistence.LoadBest()};
    BOOST_REQUIRE(loaded_winner);
    BOOST_CHECK(*loaded_winner == winner);
    BOOST_CHECK(persistence.HasCatchupMarker());
}

BOOST_AUTO_TEST_CASE(catchup_audit_marker_advances_across_later_outages)
{
    const fs::path path{m_path_root / "pqcl_repeatable_catchup"};
    const uint256 genesis{NonNullHash(22)};
    const auto config{MakeConfig()};
    auto first{MakeChainLock(
        865, config.activation_predecessor_height, NonNullHash(config.activation_predecessor_height), 220)};
    SetExactInitialization(first, genesis, 220);
    auto live{MakeChainLock(
        870, first.statement.height, first.statement.block_hash, 221)};
    SetExactContinuation(live, genesis, first);
    auto second{MakeChainLock(895, 890, NonNullHash(890), 222)};
    SetExactContinuation(second, genesis, live);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(first));
        BOOST_REQUIRE(persistence.PersistBest(live));
        BOOST_REQUIRE(persistence.PersistCatchupBest(second));
        BOOST_CHECK(persistence.HasCatchupMarker());
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == second);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.HasCatchupMarker());
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == second);
        BOOST_CHECK(!persistence.PersistCatchupBest(first));
    }
}

BOOST_AUTO_TEST_CASE(
    payment_audit_seal_capsule_restarts_replaces_and_expires_atomically)
{
    const fs::path path{m_path_root / "pqcl_payment_audit_seal_capsule"};
    const uint256 genesis{NonNullHash(23)};
    const auto config{MakePaymentAuditConfig()};
    const PaymentAuditScheduleConfig schedule_config{
        config.chainlock_schedule, config.btcc_schedule};
    constexpr uint32_t first_epoch{3};
    const auto first_schedule{
        BuildPaymentAuditEpochSchedule(schedule_config, first_epoch)};
    BOOST_REQUIRE(first_schedule);

    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 229)};
    SetExactInitialization(initialized, genesis, 229);
    auto first{MakeChainLock(
        first_schedule->seal_height,
        first_schedule->seal_height -
            config.chainlock_schedule.chainlock_period,
        NonNullHash(first_schedule->seal_height -
                    config.chainlock_schedule.chainlock_period),
        230)};
    SetExactContinuation(first, genesis, initialized);
    constexpr uint8_t all_rosters_mask{
        static_cast<uint8_t>((uint16_t{1} << ACTIVE_QUORUMS) - 1)};
    const auto first_capsule{
        PaymentAuditSealContextCapsuleTestAccess::Make(
            genesis, config, first_epoch, first, all_rosters_mask)};
    constexpr uint32_t second_epoch{first_epoch + 1};
    const auto second_schedule{
        BuildPaymentAuditEpochSchedule(schedule_config, second_epoch)};
    BOOST_REQUIRE(second_schedule);
    BOOST_REQUIRE_EQUAL(first_schedule->carrier_end_height_exclusive,
                        second_schedule->seal_height);
    auto second{MakeChainLock(
        second_schedule->seal_height,
        second_schedule->seal_height -
            config.chainlock_schedule.chainlock_period,
        NonNullHash(second_schedule->seal_height -
                    config.chainlock_schedule.chainlock_period),
        231)};
    SetExactContinuation(second, genesis, first);
    const auto second_capsule{
        PaymentAuditSealContextCapsuleTestAccess::Make(
            genesis, config, second_epoch, second, all_rosters_mask)};

    ReceiptArchiveRosterAuthorization first_authorization;
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        ChainLockPersistenceError error{
            ChainLockPersistenceError::NONE};
        BOOST_REQUIRE(persistence.PersistInitializedBest(initialized));
        const bool persisted{persistence.PersistCatchupBest(
            first, &error, std::nullopt, nullptr,
            first_capsule)};
        BOOST_TEST_CONTEXT("persistence error " <<
                           static_cast<int>(error)) {
            BOOST_REQUIRE(persisted);
        }
        BOOST_REQUIRE(persistence.LoadPaymentAuditSealContext());
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);
        const auto state{persistence.GetFinalityState()};
        BOOST_REQUIRE(state.receipt_archive_authorization);
        first_authorization = *state.receipt_archive_authorization;

        // Byte-identical replay is a no-op and cannot clear the still-live
        // capsule merely because the caller omitted its optional input.
        BOOST_REQUIRE(persistence.PersistCatchupBest(first));
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        BOOST_REQUIRE(persistence.LoadPaymentAuditSealContext());
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);

        BOOST_REQUIRE(persistence.PersistBestCoveringReceiptArchive(
            second, first_authorization, nullptr,
            second_capsule));
        BOOST_REQUIRE(persistence.LoadPaymentAuditSealContext());
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    second_capsule);

        BOOST_REQUIRE(persistence.PersistBest(second));
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    second_capsule);
    }

    RawPaymentAuditSealContextV1 stale_capsule;
    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Read(
            RawDiskKey{
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY},
            stale_capsule));
    }

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        auto after_window{MakeChainLock(
            second_schedule->carrier_end_height_exclusive,
            second_schedule->carrier_end_height_exclusive -
                config.chainlock_schedule.chainlock_period,
            NonNullHash(
                second_schedule->carrier_end_height_exclusive -
                config.chainlock_schedule.chainlock_period),
            232)};
        SetExactContinuation(after_window, genesis, second);
        BOOST_REQUIRE(persistence.PersistBest(after_window));
        BOOST_CHECK(!persistence.LoadPaymentAuditSealContext());
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        BOOST_CHECK(!persistence.LoadPaymentAuditSealContext());
    }
    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Write(
            RawDiskKey{
                PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_SEAL_CONTEXT_KEY},
            stale_capsule, true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
