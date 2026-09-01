// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/btc_header_policy.h>
#include <llmq/pq_chainlock_persistence.h>
#include <llmq/pq_roster_beacon.h>

#include <chain.h>
#include <chainparams.h>
#include <node/blockstorage.h>
#include <test/util/setup_common.h>
#include <univalue.h>
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
        uint8_t authorization_mask,
        RecoveryRosterAuthorityPtr recovery_authority)
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
            authorization_mask, std::move(recovery_authority)};
        BOOST_REQUIRE(capsule.IsInternallyConsistent(
            genesis_hash, config));
        return capsule;
    }
};

class RosterRecoveryPrecommitRolloverTestAccess {
public:
    static bool Replace(
        PQChainLockPersistence& persistence,
        const RosterRecoveryPrecommit& expected,
        const RosterRecoveryPrecommit& replacement,
        const BTCRecoveryPrecommitRolloverProof& rollover_proof,
        ChainLockPersistenceError* error = nullptr)
    {
        return persistence.ReplaceStablyInactiveRosterRecoveryPrecommit(
            expected, replacement, rollover_proof, error);
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

BTCRecoveryPrecommitRolloverProof MakeRolloverProof(
    const uint256& genesis_hash,
    const RosterRecoveryPrecommit& expected,
    const RosterRecoveryPrecommit& replacement,
    const std::optional<uint256>& previous_hash,
    uint64_t salt)
{
    const uint256& anchor_hash{
        expected.pending_seed.anchor_cursor.btc_hash};
    const int32_t anchor_height{expected.pending_seed.anchor_btc_height};
    const uint256& replacement_hash{
        replacement.pending_seed.anchor_cursor.btc_hash};
    const int32_t replacement_height{
        replacement.pending_seed.anchor_btc_height};
    const int32_t tip_height{
        std::max(anchor_height, replacement_height) +
        static_cast<int32_t>(
            ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA) +
        static_cast<int32_t>(
            ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS - 1)};
    const uint256 active_hash{NonNullHash(8'000'000 + salt)};
    const uint256 tip_hash{NonNullHash(8'100'000 + salt)};
    constexpr int64_t now{2'000'000};

    BTCHeaderPolicy policy{[&](const std::vector<std::string>& args,
                              UniValue& result,
                              std::string& error) {
        if (args == std::vector<std::string>{"getblockchaininfo"}) {
            result = UniValue{UniValue::VOBJ};
            result.pushKV("chain", "regtest");
            result.pushKV("initialblockdownload", false);
            result.pushKV("bestblockhash", tip_hash.GetHex());
            return true;
        }
        if (args.size() == 2 && args[0] == "getblockhash") {
            if (args[1] == std::to_string(anchor_height)) {
                result.setStr(active_hash.GetHex());
                return true;
            }
            if (args[1] == std::to_string(replacement_height)) {
                result.setStr(replacement_hash.GetHex());
                return true;
            }
        }
        if (args.size() == 3 && args[0] == "getblockheader" &&
            args[2] == "true") {
            uint256 requested;
            requested.SetHex(args[1]);
            result = UniValue{UniValue::VOBJ};
            result.pushKV("hash", requested.GetHex());
            if (requested == tip_hash) {
                result.pushKV("height", tip_height);
                result.pushKV("confirmations", 1);
                result.pushKV("time", now - 30);
                return true;
            }
            if (requested == anchor_hash) {
                result.pushKV("height", anchor_height);
                result.pushKV("confirmations", -1);
                result.pushKV("time", now - 600);
                return true;
            }
            if (requested == replacement_hash) {
                result.pushKV("height", replacement_height);
                result.pushKV(
                    "confirmations",
                    tip_height - replacement_height + 1);
                result.pushKV("time", now - 300);
                return true;
            }
            if (previous_hash && requested == *previous_hash) {
                result.pushKV(
                    "height",
                    std::min(anchor_height, replacement_height));
                result.pushKV("confirmations", -1);
                result.pushKV("time", now - 600);
                return true;
            }
        }
        error = "unexpected-test-bitcoin-command";
        return false;
    }};
    BTCHeaderPolicyConfig config{
        .expected_chain = "regtest",
        .min_confirmations = 1,
        .tip_max_age = 7200,
        .max_lag_blocks = 0,
        .recent_fork_depth = 0,
    };
    std::string error;
    const uint256 rollover_context_id{
        GetRosterRecoveryPrecommitRolloverContextId(
            genesis_hash, expected, replacement)};
    BOOST_REQUIRE(!rollover_context_id.IsNull());
    const auto proof{policy.AuthorizeStableInactiveAnchorReplacement(
        config, anchor_hash, anchor_height, replacement_hash,
        previous_hash, rollover_context_id, now, error)};
    BOOST_REQUIRE_MESSAGE(proof, error);
    return *proof;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

RecoveryRosterAuthoritySource RecoveryAuthoritySource()
{
    RecoveryRosterAuthoritySource source;
    source.kind = RecoveryRosterAuthoritySourceKind::ACTIVATION;
    source.height = 864;
    source.block_hash = NonNullHash(799'999);
    return source;
}

uint256 RecoveryAuthorityHash()
{
    return NonNullHash(800'000);
}

RecoveryRosterAuthorityPtr MakeRecoveryAuthority(
    const uint256& genesis_hash, uint64_t salt)
{
    auto authority{std::make_shared<RecoveryRosterAuthority>()};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            auto& entry{authority->slots[slot][member]};
            entry.pro_tx_hash = NonNullHash(
                salt + slot * QUORUM_SIZE + member + 1);
            entry.eligible = member < QUORUM_MIN_VALID;
            if (entry.eligible) {
                RecoveryRosterChildCommitment child_root;
                child_root.global_key_version = 1;
                child_root.commitment.generation = 1;
                child_root.commitment.tree_id = NonNullHash(
                    salt + 10'000 + slot * QUORUM_SIZE + member);
                child_root.commitment.root = NonNullHash(
                    salt + 20'000 + slot * QUORUM_SIZE + member);
                entry.child_root = std::move(child_root);
            }
        }
    }
    BOOST_REQUIRE(authority->IsStructurallyValid());
    BOOST_REQUIRE(GetRecoveryRosterAuthorityHash(
        genesis_hash, *authority));
    return authority;
}

RosterBeaconSeed MakeRecoveryPendingSeed(uint32_t newest_epoch,
                                         uint64_t salt,
                                         int32_t anchor_height = 870)
{
    RosterBeaconSeed seed;
    seed.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    seed.state = RosterBeaconState::PENDING;
    seed.epoch = newest_epoch;
    seed.anchor_cursor = BTCCursor{
        anchor_height, NonNullHash(700'000 + salt),
        NonNullHash(710'000 + salt)};
    seed.anchor_btc_height = 900'000 + static_cast<int32_t>(salt);
    BOOST_REQUIRE(seed.IsStructurallyValid());
    return seed;
}

RosterBeaconWindow MakeRecoveryWindow(const RosterBeaconSeed& pending,
                                      uint64_t salt)
{
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
    window.active.recovery_authority_hash = RecoveryAuthorityHash();
    window.active.recovery_authority_source = RecoveryAuthoritySource();
    window.next.epoch = pending.epoch + 1;
    BOOST_REQUIRE(window.IsStructurallyValid());
    return window;
}

RosterBeaconWindow MakeNormalWindow()
{
    RosterBeaconWindow window;
    const auto pending{MakeRecoveryPendingSeed(3, 900'000)};
    const uint256 future_hash{NonNullHash(1'620'001)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& seed{window.active.seeds[slot]};
        seed = pending;
        seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
        seed.state = RosterBeaconState::READY;
        seed.epoch = slot;
        seed.future_btc_hash = future_hash;
    }
    window.next.epoch = ACTIVE_QUORUMS;
    BOOST_REQUIRE(window.IsStructurallyValid());
    return window;
}

RosterRecoveryPrecommit MakeRecoveryPrecommit(
    RosterRecoveryAdmission admission,
    uint64_t salt,
    int32_t predecessor_height = -1,
    uint256 predecessor_hash = {},
    int32_t anchor_height = 870,
    uint32_t epoch = 3)
{
    RosterRecoveryPrecommit precommit;
    precommit.admission = admission;
    precommit.predecessor_height = predecessor_height;
    precommit.predecessor_hash = predecessor_hash;
    precommit.recovery_authority_hash = RecoveryAuthorityHash();
    precommit.recovery_authority_source = RecoveryAuthoritySource();
    precommit.pending_seed =
        MakeRecoveryPendingSeed(epoch, salt, anchor_height);
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

void SetRecoveryTransition(FinalChainLock& chainlock,
                           const RosterRecoveryPrecommit& precommit,
                           uint64_t salt)
{
    chainlock.statement.block_hash =
        precommit.pending_seed.anchor_cursor.sys_hash;
    chainlock.statement.accepted_btcc_cursor =
        precommit.pending_seed.anchor_cursor;
    chainlock.statement.btcc_advance = BTCCAdvance::ADVANCE;
    chainlock.statement.roster_transition =
        precommit.admission == RosterRecoveryAdmission::INITIALIZE
            ? RosterAuthorizationTransitionKind::INITIALIZE
            : RosterAuthorizationTransitionKind::RECOVER;
    chainlock.statement.roster_beacons =
        MakeRecoveryWindow(precommit.pending_seed, salt);
    chainlock.statement.roster_beacons.active.recovery_authority_hash =
        precommit.recovery_authority_hash;
    chainlock.statement.roster_beacons.active.recovery_authority_source =
        precommit.recovery_authority_source;
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

RecoveryRosterAuthorityPtr MakeDefaultRecoveryAuthority(
    const uint256& genesis_hash)
{
    return MakeRecoveryAuthority(genesis_hash, 42'000'000);
}

uint256 DefaultRecoveryAuthorityHash(const uint256& genesis_hash)
{
    const auto authority{MakeDefaultRecoveryAuthority(genesis_hash)};
    const auto hash{
        GetRecoveryRosterAuthorityHash(genesis_hash, *authority)};
    BOOST_REQUIRE(hash);
    return *hash;
}

RecoveryRosterAuthorityPtr SetExactInitialization(
    FinalChainLock& chainlock,
    const uint256& genesis_hash,
    uint64_t salt)
{
    const auto authority{MakeDefaultRecoveryAuthority(genesis_hash)};
    const auto authority_hash{
        GetRecoveryRosterAuthorityHash(genesis_hash, *authority)};
    BOOST_REQUIRE(authority_hash);

    auto precommit{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, salt, -1, {},
        chainlock.statement.height)};
    precommit.recovery_authority_hash = *authority_hash;
    precommit.pending_seed.anchor_cursor.sys_hash =
        chainlock.statement.block_hash;
    precommit.pending_seed.anchor_cursor.btc_hash =
        NonNullHash(42'100'000 + salt);
    BOOST_REQUIRE(precommit.IsStructurallyValid());
    SetRecoveryTransition(chainlock, precommit, salt);
    SetExactRosterAuthorizationStateHash(chainlock, genesis_hash);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
    return authority;
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

void BindRecoveryPrecommitToPrior(
    RosterRecoveryPrecommit& precommit,
    const FinalChainLock& prior)
{
    precommit.recovery_authority_hash =
        prior.statement.roster_beacons.active.recovery_authority_hash;
    precommit.recovery_authority_source =
        prior.statement.roster_beacons.active.recovery_authority_source;
    BOOST_REQUIRE(precommit.IsStructurallyValid());
}

void SetExactRecoveryTransitionFromPrior(
    FinalChainLock& chainlock,
    RosterRecoveryPrecommit& precommit,
    const uint256& genesis_hash,
    const FinalChainLock& prior,
    uint64_t salt)
{
    BindRecoveryPrecommitToPrior(precommit, prior);
    chainlock.statement.previous_btcc_cursor =
        prior.statement.accepted_btcc_cursor;
    SetRecoveryTransition(chainlock, precommit, salt);
    SetExactRosterAuthorizationStateHash(
        chainlock, genesis_hash, &prior);
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
}

ChainLockFinalityStoreConfig MakeConfig()
{
    ChainLockFinalityStoreConfig config;
    config.chainlock_schedule = *MakeChainLockScheduleConfig(0);
    config.btcc_schedule.candidate_origin = 870;
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
                  obj.terminal_carrier_hash, obj.terminal_receipt,
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

struct RawRecoveryRosterAuthorityV1 {
    uint16_t version{1};
    uint256 schema_hash;
    uint256 owner_logical_id;
    uint256 owner_witness_id;
    uint256 authority_hash;
    RecoveryRosterAuthority authority;
    uint256 checksum;

    SERIALIZE_METHODS(RawRecoveryRosterAuthorityV1, obj)
    {
        READWRITE(obj.version, obj.schema_hash, obj.owner_logical_id,
                  obj.owner_witness_id, obj.authority_hash,
                  obj.authority, obj.checksum);
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
    std::optional<RecoveryRosterAuthority> recovery_authority;
    uint256 checksum;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        const uint8_t has_authority{
            recovery_authority ? uint8_t{1} : uint8_t{0}};
        ::SerializeMany(
            stream, version, schema_hash, epoch,
            carrier_end_height_exclusive, seal_logical_id,
            seal_witness_id, seal_statement, authorization_mask,
            has_authority);
        if (recovery_authority) {
            ::Serialize(stream, *recovery_authority);
        }
        ::Serialize(stream, checksum);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        uint8_t has_authority{0};
        ::UnserializeMany(
            stream, version, schema_hash, epoch,
            carrier_end_height_exclusive, seal_logical_id,
            seal_witness_id, seal_statement, authorization_mask,
            has_authority);
        if (has_authority > 1) {
            throw std::ios_base::failure(
                "non-canonical payment-audit seal authority flag");
        }
        if (has_authority != 0) {
            RecoveryRosterAuthority authority;
            ::Unserialize(stream, authority);
            recovery_authority = std::move(authority);
        } else {
            recovery_authority.reset();
        }
        ::Unserialize(stream, checksum);
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
    return BTCCPresealMarker{
        earliest_height, earliest_hash, BTCCReceiptState{}, terminal_height,
        terminal_height == earliest_height
            ? earliest_hash
            : NonNullHash(500000 + salt),
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
        MakeRecoveryPendingSeed(epoch, 680'000 + salt);
    receipt.subject_roster_beacon.anchor_kind =
        RosterBeaconAnchorKind::NORMAL;
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
            target.pqBTCCReceiptStateHash},
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
            target.pqBTCCReceiptStateHash},
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

BOOST_AUTO_TEST_CASE(roster_recovery_precommit_is_canonical_and_durable)
{
    const fs::path path{m_path_root / "pqcl_roster_recovery_precommit"};
    const uint256 genesis{NonNullHash(81)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 80)};
    const auto authority{SetExactInitialization(prior, genesis, 80)};
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 1,
        prior.statement.height, prior.statement.block_hash)};
    BindRecoveryPrecommitToPrior(staged, prior);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
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
    invalid.pending_seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = staged;
    invalid.predecessor_height = invalid.pending_seed.anchor_cursor.sys_height;
    BOOST_CHECK(!invalid.IsStructurallyValid());

    auto initialize{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 2)};
    BOOST_CHECK(initialize.IsStructurallyValid());
    initialize.predecessor_height = 864;
    initialize.predecessor_hash = NonNullHash(864);
    BOOST_CHECK(!initialize.IsStructurallyValid());

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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRosterRecoveryPrecommit(
            later_joint_target, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
    }

    auto off_target_config{config};
    off_target_config.btcc_schedule.candidate_origin = 0;
    off_target_config.activation_predecessor_height = -1;
    const auto off_target{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 2, -1, {},
        /*anchor_height=*/0)};
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
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 811)};
    const auto authority{SetExactInitialization(prior, genesis, 811)};
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 811,
        prior.statement.height, prior.statement.block_hash)};
    BindRecoveryPrecommitToPrior(staged, prior);

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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
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

        const auto later_target{CanonicalRosterRecoveryTargetHeight(
            config.chainlock_schedule, config.btcc_schedule, 7)};
        BOOST_REQUIRE(later_target);
        const auto later{MakeRecoveryPrecommit(
            RosterRecoveryAdmission::CURRENT_CATCHUP, 817,
            prior.statement.height, prior.statement.block_hash,
            *later_target, /*epoch=*/7)};
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
        BOOST_CHECK_EQUAL(ready->pending_seed.epoch, 3U);
    }
}

BOOST_AUTO_TEST_CASE(
    stably_inactive_pending_recovery_rolls_only_to_disjoint_epoch)
{
    using Access = RosterRecoveryPrecommitRolloverTestAccess;
    const fs::path path{m_path_root / "pqcl_roster_recovery_rollover"};
    const uint256 genesis{NonNullHash(818)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 818)};
    const auto authority{SetExactInitialization(prior, genesis, 818)};
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 819,
        prior.statement.height, prior.statement.block_hash)};
    BindRecoveryPrecommitToPrior(staged, prior);
    const auto later_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(later_target);
    auto later{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 820,
        prior.statement.height, prior.statement.block_hash,
        *later_target, /*epoch=*/7)};
    BindRecoveryPrecommitToPrior(later, prior);
    const std::optional<uint256> previous_btc_hash{
        prior.statement.accepted_btcc_cursor.btc_hash};
    const auto proof{MakeRolloverProof(
        genesis, staged, later, previous_btc_hash, 819)};

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(staged));
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};

        auto stale_expected{staged};
        ++stale_expected.pending_seed.anchor_btc_height;
        BOOST_CHECK(!Access::Replace(
            persistence, stale_expected, later, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto wrong_hash_expected{staged};
        wrong_hash_expected.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(9'000'001);
        BOOST_REQUIRE(wrong_hash_expected.IsStructurallyValid());
        const auto wrong_hash_proof{MakeRolloverProof(
            genesis, wrong_hash_expected, later,
            previous_btc_hash, 821)};
        BOOST_CHECK(!Access::Replace(
            persistence, staged, later, wrong_hash_proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto wrong_height_expected{staged};
        wrong_height_expected.pending_seed.anchor_btc_height += 2;
        BOOST_REQUIRE(wrong_height_expected.IsStructurallyValid());
        const auto wrong_height_proof{MakeRolloverProof(
            genesis, wrong_height_expected, later,
            previous_btc_hash, 822)};
        BOOST_CHECK(!Access::Replace(
            persistence, staged, later, wrong_height_proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        const auto wrong_previous_proof{MakeRolloverProof(
            genesis, staged, later, std::nullopt, 825)};
        BOOST_CHECK(!Access::Replace(
            persistence, staged, later, wrong_previous_proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto same_epoch{staged};
        same_epoch.pending_seed.anchor_cursor.sys_hash =
            NonNullHash(9'000'002);
        same_epoch.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(9'000'003);
        BOOST_REQUIRE(same_epoch.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, same_epoch, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto ready_replacement{later};
        ready_replacement.pending_seed.state = RosterBeaconState::READY;
        ready_replacement.pending_seed.future_btc_hash =
            NonNullHash(9'000'004);
        BOOST_REQUIRE(ready_replacement.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, ready_replacement, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto noncanonical{later};
        noncanonical.pending_seed.anchor_cursor.sys_height +=
            static_cast<int32_t>(PQ_CL_PERIOD);
        noncanonical.pending_seed.anchor_cursor.sys_hash =
            NonNullHash(9'000'005);
        noncanonical.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(9'000'006);
        BOOST_REQUIRE(noncanonical.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, noncanonical, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto wrong_predecessor{later};
        wrong_predecessor.predecessor_hash = NonNullHash(9'000'007);
        BOOST_REQUIRE(wrong_predecessor.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, wrong_predecessor, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto wrong_authority{later};
        wrong_authority.recovery_authority_hash =
            NonNullHash(9'000'008);
        BOOST_REQUIRE(wrong_authority.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, wrong_authority, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto wrong_source{later};
        wrong_source.recovery_authority_source.block_hash =
            NonNullHash(9'000'009);
        BOOST_REQUIRE(wrong_source.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, wrong_source, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto other_context{later};
        other_context.pending_seed.anchor_cursor.sys_hash =
            NonNullHash(9'000'012);
        BOOST_REQUIRE(other_context.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, other_context, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        auto other_replacement{later};
        other_replacement.pending_seed.anchor_cursor.sys_hash =
            NonNullHash(9'000'010);
        other_replacement.pending_seed.anchor_cursor.btc_hash =
            NonNullHash(9'000'011);
        ++other_replacement.pending_seed.anchor_btc_height;
        BOOST_REQUIRE(other_replacement.IsStructurallyValid());
        BOOST_CHECK(!Access::Replace(
            persistence, staged, other_replacement, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);

        BOOST_REQUIRE(Access::Replace(
            persistence, staged, later, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == later);

        BOOST_CHECK(!Access::Replace(
            persistence, staged, same_epoch, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == later);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == later);
    }

    const fs::path ready_path{
        m_path_root / "pqcl_roster_recovery_rollover_ready"};
    {
        PQChainLockPersistence persistence{
            DiskParams(ready_path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(staged));
        auto ready{staged};
        ready.pending_seed.state = RosterBeaconState::READY;
        ready.pending_seed.future_btc_hash = NonNullHash(9'000'010);
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(ready));
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!Access::Replace(
            persistence, ready, later, proof, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == ready);
    }

    const fs::path initialize_path{
        m_path_root / "pqcl_roster_recovery_rollover_initialize"};
    auto initialize{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 823)};
    const auto much_later_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 11)};
    BOOST_REQUIRE(much_later_target);
    auto much_later{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 824, -1, {},
        *much_later_target, /*epoch=*/11)};
    const auto initialize_proof{MakeRolloverProof(
        genesis, initialize, much_later, std::nullopt, 823)};
    {
        PQChainLockPersistence persistence{
            DiskParams(initialize_path), genesis, config};
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(initialize));
        BOOST_REQUIRE(Access::Replace(
            persistence, initialize, much_later, initialize_proof));
        BOOST_CHECK(
            persistence.LoadRosterRecoveryPrecommit() == much_later);
    }
}

BOOST_AUTO_TEST_CASE(initialized_best_atomically_consumes_recovery_precommit)
{
    const fs::path path{m_path_root / "pqcl_roster_initialize"};
    const uint256 genesis{NonNullHash(82)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 865;
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 3, -1, {},
        /*anchor_height=*/865)};
    const auto authority{MakeDefaultRecoveryAuthority(genesis)};
    staged.recovery_authority_hash =
        DefaultRecoveryAuthorityHash(genesis);
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 82)};
    SetRecoveryTransition(initialized, staged, 3);
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

        BOOST_REQUIRE(persistence.PersistInitializedBest(
            initialized, nullptr, authority));
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
    initial_recovery_authority_roundtrip_is_worker_stack_safe)
{
    const fs::path path{
        m_path_root / "pqcl_initial_authority_worker_stack"};
    const uint256 genesis{NonNullHash(820)};
    const auto config{MakeConfig()};
    auto initialized{std::make_shared<FinalChainLock>(MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 820))};
    const auto authority{
        SetExactInitialization(*initialized, genesis, 820)};

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
                *initialized, &error, authority);
        }
        if (!persisted) return;
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto loaded{persistence.LoadRecoveryRosterAuthority()};
        restarted = loaded && *loaded == *authority;
    }};
    worker.join();

    BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    BOOST_REQUIRE(persisted);
    BOOST_CHECK(restarted);
}

BOOST_AUTO_TEST_CASE(catchup_best_atomically_consumes_recovery_precommit)
{
    const fs::path path{m_path_root / "pqcl_roster_recover"};
    const fs::path wrong_path{
        m_path_root / "pqcl_roster_recover_wrong_target"};
    const uint256 genesis{NonNullHash(83)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 83)};
    const auto authority{SetExactInitialization(prior, genesis, 83)};
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 4,
        prior.statement.height, prior.statement.block_hash)};
    BindRecoveryPrecommitToPrior(staged, prior);
    const auto future_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(future_target);
    auto future_staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 40,
        prior.statement.height, prior.statement.block_hash,
        *future_target, /*epoch=*/7)};
    BindRecoveryPrecommitToPrior(future_staged, prior);
    auto recovered{MakeChainLock(
        870, prior.statement.height, prior.statement.block_hash, 84)};
    SetExactRecoveryTransitionFromPrior(
        recovered, staged, genesis, prior, 4);
    BOOST_REQUIRE(recovered.IsStructurallyValid());
    auto wrong_target_height{recovered};
    SetExactRecoveryTransitionFromPrior(
        wrong_target_height, future_staged, genesis, prior, 40);
    BOOST_REQUIRE(wrong_target_height.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{
            DiskParams(wrong_path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(future_staged));

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            wrong_target_height, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(
            persistence.LoadRosterRecoveryPrecommit() == future_staged);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(staged));

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistCatchupBest(recovered, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto wrong_reveal{recovered};
        wrong_reveal.statement.roster_beacons.active.seeds.back()
            .future_btc_hash = NonNullHash(999'992);
        BOOST_REQUIRE(wrong_reveal.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            wrong_reveal, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto keep{recovered};
        keep.statement.btcc_advance = BTCCAdvance::KEEP;
        keep.statement.previous_btcc_cursor = {};
        keep.statement.accepted_btcc_cursor = {};
        BOOST_REQUIRE(keep.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(keep, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        auto wrong_cursor{recovered};
        wrong_cursor.statement.accepted_btcc_cursor.btc_hash =
            NonNullHash(999'995);
        BOOST_REQUIRE(wrong_cursor.IsStructurallyValid());
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            wrong_cursor, &error));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        BOOST_REQUIRE(
            persistence.PersistRecoveryCatchupBest(
                recovered, nullptr, std::nullopt, nullptr,
                authority));
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_CHECK(persistence.HasCatchupMarker());
        BOOST_CHECK(persistence.PersistRecoveryCatchupBest(
            recovered, nullptr, std::nullopt, nullptr, authority));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadBest());
        BOOST_CHECK(*persistence.LoadBest() == recovered);
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_CHECK(persistence.HasCatchupMarker());
    }
}

BOOST_AUTO_TEST_CASE(
    exact_recovery_replay_preserves_later_recovery_precommit)
{
    const fs::path path{
        m_path_root / "pqcl_exact_recovery_replay_later_precommit"};
    const uint256 genesis{NonNullHash(831)};
    const auto config{MakeConfig()};
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 831)};
    const auto authority{SetExactInitialization(
        initialized, genesis, 831)};

    auto recovery{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 832,
        initialized.statement.height, initialized.statement.block_hash)};
    auto recovered{MakeChainLock(
        870, initialized.statement.height,
        initialized.statement.block_hash, 832)};
    SetExactRecoveryTransitionFromPrior(
        recovered, recovery, genesis, initialized, 832);

    const auto later_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(later_target);
    auto later{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 833,
        recovered.statement.height, recovered.statement.block_hash,
        *later_target, /*epoch=*/7)};
    BindRecoveryPrecommitToPrior(later, recovered);

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            initialized, nullptr, authority));
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(
            recovery));
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(
            recovered, nullptr, std::nullopt, nullptr, authority));

        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(later));
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(
            recovered, nullptr, std::nullopt, nullptr, authority));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == later);
        BOOST_REQUIRE(persistence.LoadRecoveryRosterAuthority());
        BOOST_CHECK(*persistence.LoadRecoveryRosterAuthority() ==
                    *authority);
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_CHECK(persistence.LoadBest() == recovered);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == later);
        BOOST_REQUIRE(persistence.LoadRecoveryRosterAuthority());
        BOOST_CHECK(*persistence.LoadRecoveryRosterAuthority() ==
                    *authority);
    }
}

BOOST_AUTO_TEST_CASE(
    verified_recovery_persistence_does_not_require_local_precommit)
{
    const uint256 genesis{NonNullHash(84)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 865;
    const auto authority{MakeDefaultRecoveryAuthority(genesis)};
    auto initialize_marker{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::INITIALIZE, 41, -1, {},
        /*anchor_height=*/865)};
    initialize_marker.recovery_authority_hash =
        DefaultRecoveryAuthorityHash(genesis);
    auto initialized{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 841)};
    SetRecoveryTransition(initialized, initialize_marker, 41);
    SetExactRosterAuthorizationStateHash(initialized, genesis);
    BOOST_REQUIRE(initialized.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{
            MemoryParams(m_path_root / "pqcl_recovery_no_local_initialize"),
            genesis, config};
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            initialized, nullptr, authority));
        BOOST_CHECK(persistence.LoadBest() == initialized);
    }

    const auto catchup_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(catchup_target);
    auto catchup_marker{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 42,
        initialized.statement.height, initialized.statement.block_hash,
        *catchup_target, /*epoch=*/7)};
    BindRecoveryPrecommitToPrior(catchup_marker, initialized);
    auto recovered{MakeChainLock(
        *catchup_target,
        *catchup_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*catchup_target - PQ_CL_PERIOD), 842)};
    SetExactRecoveryTransitionFromPrior(
        recovered, catchup_marker, genesis, initialized, 42);
    BOOST_REQUIRE(recovered.IsStructurallyValid());
    {
        PQChainLockPersistence persistence{
            MemoryParams(m_path_root / "pqcl_recovery_no_local_catchup"),
            genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            initialized, nullptr, authority));
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(
            recovered, nullptr, std::nullopt, nullptr, authority));
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
            recovered, &error, std::nullopt, nullptr, authority));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(!persistence.LoadBest());
    }
}

BOOST_AUTO_TEST_CASE(ordinary_winner_atomically_discards_stale_catchup_precommit)
{
    const fs::path path{m_path_root / "pqcl_roster_recover_superseded"};
    const uint256 genesis{NonNullHash(85)};
    const auto config{MakeConfig()};
    auto prior{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 85)};
    const auto authority{SetExactInitialization(prior, genesis, 85)};
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 5,
        prior.statement.height, prior.statement.block_hash)};
    BindRecoveryPrecommitToPrior(staged, prior);
    auto ordinary{MakeChainLock(
        870, prior.statement.height, prior.statement.block_hash, 86)};
    SetExactContinuation(ordinary, genesis, prior);
    auto ordinary_successor{MakeChainLock(
        875, ordinary.statement.height, ordinary.statement.block_hash, 87)};
    SetExactContinuation(ordinary_successor, genesis, ordinary);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(staged));

        auto rejected{prior};
        rejected.statement.block_hash = NonNullHash(999'993);
        rejected.signatures.front().signature.front() ^= 1;
        SetExactContinuation(rejected, genesis, prior);
        BOOST_REQUIRE(rejected.IsStructurallyValid());
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistBest(rejected, &error));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == staged);

        BOOST_REQUIRE(persistence.PersistBest(ordinary));
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());

        BOOST_REQUIRE(persistence.PersistBest(ordinary_successor));

        const auto replacement_target{CanonicalRosterRecoveryTargetHeight(
            config.chainlock_schedule, config.btcc_schedule, 7)};
        BOOST_REQUIRE(replacement_target);
        auto replacement{MakeRecoveryPrecommit(
            RosterRecoveryAdmission::CURRENT_CATCHUP, 6,
            ordinary_successor.statement.height,
            ordinary_successor.statement.block_hash,
            *replacement_target, /*epoch=*/7)};
        BindRecoveryPrecommitToPrior(
            replacement, ordinary_successor);
        BOOST_REQUIRE(
            persistence.PersistRosterRecoveryPrecommit(replacement));
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() == replacement);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto best{persistence.LoadBest()};
        BOOST_REQUIRE(best);
        BOOST_CHECK(*best == ordinary_successor);
        BOOST_REQUIRE(persistence.LoadRosterRecoveryPrecommit());

        auto replacement{*persistence.LoadRosterRecoveryPrecommit()};
        auto recovered{MakeChainLock(
            replacement.pending_seed.anchor_cursor.sys_height,
            replacement.pending_seed.anchor_cursor.sys_height -
                static_cast<int32_t>(PQ_CL_PERIOD),
            NonNullHash(replacement.pending_seed.anchor_cursor.sys_height -
                        PQ_CL_PERIOD),
            88)};
        SetExactRecoveryTransitionFromPrior(
            recovered, replacement, genesis, *best, 6);
        BOOST_REQUIRE(recovered.IsStructurallyValid());
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_REQUIRE_MESSAGE(
            persistence.PersistRecoveryCatchupBest(
                recovered, &error, std::nullopt, nullptr,
                authority),
            "persistence error " << static_cast<int>(error));
        BOOST_CHECK(!persistence.LoadRosterRecoveryPrecommit());
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
    const auto authority{SetExactInitialization(branch_a, genesis, 64)};
    SetExactInitialization(branch_b, genesis, 65);
    const fs::path path_a{m_path_root / "pqcl_height_boundary_a"};
    const fs::path path_b{m_path_root / "pqcl_height_boundary_b"};

    {
        PQChainLockPersistence persistence{DiskParams(path_a), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            branch_a, nullptr, authority));
    }
    {
        PQChainLockPersistence persistence{DiskParams(path_a), genesis, config};
        const auto loaded{persistence.LoadBest()};
        BOOST_REQUIRE(loaded);
        BOOST_CHECK(*loaded == branch_a);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path_b), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            branch_b, nullptr, authority));
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
    const auto authority{SetExactInitialization(chainlock, genesis, 1)};
    auto next{MakeChainLock(
        870, chainlock.statement.height, chainlock.statement.block_hash, 2)};
    SetExactContinuation(next, genesis, chainlock);

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            chainlock, nullptr, authority));
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

BOOST_AUTO_TEST_CASE(
    receipt_archive_authorization_is_owner_bound_atomic_and_durable)
{
    const fs::path path{m_path_root / "pqcl_receipt_archive_authorization"};
    const uint256 genesis{NonNullHash(201)};
    auto config{MakeConfig()};
    config.btcc_schedule.candidate_origin = 880;
    BOOST_REQUIRE(config.IsValid());

    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 201)};
    const auto authority{
        SetExactInitialization(predecessor, genesis, 201)};
    auto owner{MakeChainLock(
        885, 880, NonNullHash(880), 202)};
    SetExactContinuation(owner, genesis, predecessor);
    auto archive{MakeChainLock(
        880, 875, NonNullHash(875), 203)};
    archive.statement.accepted_btcc_cursor = BTCCursor{
        archive.statement.height, archive.statement.block_hash,
        NonNullHash(880'203)};
    archive.statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(archive.IsStructurallyValid());

    ReceiptArchiveRosterAuthorization authorization;
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
            900, 895, NonNullHash(895), 204)};
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

BOOST_AUTO_TEST_CASE(corrupt_receipt_archive_authorization_fails_closed)
{
    const fs::path path{
        m_path_root / "pqcl_receipt_archive_authorization_corrupt"};
    const uint256 genesis{NonNullHash(206)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 206)};
    const auto authority{
        SetExactInitialization(predecessor, genesis, 206)};
    auto owner{MakeChainLock(
        875, 870, NonNullHash(870), 207)};
    SetExactContinuation(owner, genesis, predecessor);
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
    const auto authority{
        SetExactInitialization(predecessor, genesis, 213)};
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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
    recovery_catchup_atomically_consumes_precommit_and_replaces_archive_authority)
{
    const fs::path path{
        m_path_root / "pqcl_recovery_covering_receipt_archive"};
    const uint256 genesis{NonNullHash(217)};
    const auto config{MakeConfig()};
    auto predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 217)};
    const auto authority{
        SetExactInitialization(predecessor, genesis, 217)};
    auto first_catchup{MakeChainLock(
        875, 870, NonNullHash(870), 218)};
    SetExactContinuation(first_catchup, genesis, predecessor);
    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        config.chainlock_schedule, config.btcc_schedule, 7)};
    BOOST_REQUIRE(recovery_target);
    auto staged{MakeRecoveryPrecommit(
        RosterRecoveryAdmission::CURRENT_CATCHUP, 219,
        first_catchup.statement.height,
        first_catchup.statement.block_hash,
        *recovery_target, /*epoch=*/7)};
    BindRecoveryPrecommitToPrior(staged, first_catchup);
    auto recovered{MakeChainLock(
        *recovery_target,
        *recovery_target - static_cast<int32_t>(PQ_CL_PERIOD),
        NonNullHash(*recovery_target - PQ_CL_PERIOD), 220)};
    SetExactRecoveryTransitionFromPrior(
        recovered, staged, genesis, first_catchup, 220);
    BOOST_REQUIRE(recovered.IsStructurallyValid());

    ReceiptArchiveRosterAuthorization replacement;
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
        BOOST_REQUIRE(persistence.PersistCatchupBest(first_catchup));
        const auto before{persistence.GetFinalityState()};
        BOOST_REQUIRE(before.receipt_archive_authorization);
        const auto authorization{*before.receipt_archive_authorization};
        BOOST_REQUIRE(persistence.PersistRosterRecoveryPrecommit(staged));
        const auto staged_precommit{
            persistence.LoadRosterRecoveryPrecommit()};
        BOOST_REQUIRE(staged_precommit);

        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            recovered, &error, std::nullopt, nullptr, authority));
        BOOST_CHECK(error == ChainLockPersistenceError::HEIGHT_CONFLICT);
        BOOST_CHECK(persistence.GetFinalityState() == before);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() ==
                    staged_precommit);

        auto wrong_authorization{authorization};
        wrong_authorization.covering_witness_id = NonNullHash(221);
        BOOST_CHECK(!persistence.PersistRecoveryCatchupBest(
            recovered, &error, std::nullopt, &wrong_authorization,
            authority));
        BOOST_CHECK(error == ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == before);
        BOOST_CHECK(persistence.LoadRosterRecoveryPrecommit() ==
                    staged_precommit);

        BOOST_REQUIRE(persistence.PersistRecoveryCatchupBest(
            recovered, &error, std::nullopt, &authorization,
            authority));
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
    const auto authority{
        SetExactInitialization(predecessor, genesis, 208)};
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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
        BOOST_CHECK(!consumed.unsealed_btcc);
        BOOST_CHECK_EQUAL(consumed.certificate_revision, 2U);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const auto restarted{persistence.GetFinalityState()};
        BOOST_REQUIRE(restarted.best);
        BOOST_CHECK(restarted.best->statement == covering.statement);
        BOOST_CHECK(!restarted.receipt_archive_authorization);
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
    const auto authority{SetExactInitialization(first, genesis, 61)};
    BOOST_REQUIRE(persistence.PersistInitializedBest(
        first, nullptr, authority));
    const auto first_state{persistence.GetFinalityState()};
    BOOST_REQUIRE(first_state.best);
    BOOST_CHECK_EQUAL(first_state.certificate_revision, 1U);
    BOOST_CHECK(!first_state.unsealed_btcc);
    BOOST_CHECK(first_state.best->logical_id == first.GetLogicalId(genesis));
    BOOST_CHECK(first_state.best->witness_id == first.GetWitnessId(genesis));
    BOOST_CHECK(first_state.best->statement == first.statement);

    BOOST_REQUIRE(persistence.PersistInitializedBest(
        first, nullptr, authority));
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
    BOOST_CHECK(*advance_state.best == *advance_state.unsealed_btcc);
    BOOST_CHECK(advance_state.best->logical_id ==
                advance.GetLogicalId(genesis));
    BOOST_CHECK(advance_state.best->witness_id ==
                advance.GetWitnessId(genesis));
    BOOST_CHECK(advance_state.best->statement == advance.statement);
}

BOOST_AUTO_TEST_CASE(unsealed_record_mutation_advances_certificate_revision)
{
    const fs::path path{m_path_root / "pqcl_unsealed_view"};
    const uint256 genesis{NonNullHash(63)};
    const auto config{MakeConfig()};
    auto archived{MakeChainLock(870, 865, NonNullHash(865), 63)};
    archived.statement.accepted_btcc_cursor = BTCCursor{
        archived.statement.height, archived.statement.block_hash,
        NonNullHash(6300)};
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto authorization_predecessor{MakeChainLock(
        875, 870, archived.statement.block_hash, 640)};
    const auto authority{SetExactInitialization(
        authorization_predecessor, genesis, 640)};
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            authorization_predecessor, nullptr, authority));
        BOOST_REQUIRE(persistence.PersistUnsealedBTCC(archived));

        const auto state{persistence.GetFinalityState()};
        BOOST_CHECK_EQUAL(state.certificate_revision, 2U);
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
            880, authorization_predecessor.statement.height,
            authorization_predecessor.statement.block_hash, 64)};
        seal.statement.btcc_receipt_state = BTCCReceiptState{
            archived.statement.accepted_btcc_cursor, NonNullHash(6302)};
        SetExactContinuation(
            seal, genesis, authorization_predecessor);
        BOOST_REQUIRE(persistence.PersistBest(seal));

        const auto sealed{persistence.GetFinalityState()};
        BOOST_CHECK_EQUAL(sealed.certificate_revision, 2U);
        BOOST_REQUIRE(sealed.best);
        BOOST_CHECK(sealed.best->logical_id == seal.GetLogicalId(genesis));
        BOOST_CHECK(sealed.best->witness_id == seal.GetWitnessId(genesis));
        BOOST_CHECK(sealed.best->statement == seal.statement);
        BOOST_CHECK(!sealed.unsealed_btcc);
    }
}

BOOST_AUTO_TEST_CASE(
    recovery_unsealed_retains_exact_authority_across_restart)
{
    const fs::path path{m_path_root / "pqcl_recovery_unsealed_authority"};
    const uint256 genesis{NonNullHash(630)};
    const auto config{MakeConfig()};
    const auto authority{MakeRecoveryAuthority(genesis, 630'000)};
    const auto authority_hash{
        GetRecoveryRosterAuthorityHash(genesis, *authority)};
    BOOST_REQUIRE(authority_hash);

    auto archived{MakeChainLock(870, 865, NonNullHash(865), 630)};
    archived.statement.roster_beacons = MakeRecoveryWindow(
        MakeRecoveryPendingSeed(3, 630, archived.statement.height),
        630);
    archived.statement.roster_beacons.active.recovery_authority_hash =
        *authority_hash;
    archived.statement.accepted_btcc_cursor = BTCCursor{
        archived.statement.height, archived.statement.block_hash,
        NonNullHash(630'001)};
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(archived.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistUnsealedBTCC(
            archived, &error));
        BOOST_CHECK(error ==
                    ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
        BOOST_CHECK(!persistence.LoadRecoveryRosterAuthority());

        BOOST_REQUIRE(persistence.PersistUnsealedBTCC(
            archived, &error, authority));
        BOOST_CHECK(error == ChainLockPersistenceError::NONE);
        const auto retained{persistence.LoadRecoveryRosterAuthority()};
        BOOST_REQUIRE(retained);
        BOOST_CHECK(*retained == *authority);
    }

    {
        CDBWrapper raw{DiskParams(path)};
        RawRecoveryRosterAuthorityV1 disk;
        BOOST_REQUIRE(raw.Read(
            RawDiskKey{PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY},
            disk));
        BOOST_CHECK(disk.owner_logical_id ==
                    archived.GetLogicalId(genesis));
        BOOST_CHECK(disk.owner_witness_id ==
                    archived.GetWitnessId(genesis));
        BOOST_CHECK(disk.authority_hash == *authority_hash);
    }

    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.LoadUnsealedBTCC());
        BOOST_CHECK(*persistence.LoadUnsealedBTCC() == archived);
        const auto retained{persistence.LoadRecoveryRosterAuthority()};
        BOOST_REQUIRE(retained);
        BOOST_CHECK(*retained == *authority);

        const auto conflicting_authority{
            MakeRecoveryAuthority(genesis, 640'000)};
        const auto before{persistence.GetFinalityState()};
        ChainLockPersistenceError error{ChainLockPersistenceError::NONE};
        BOOST_CHECK(!persistence.PersistUnsealedBTCC(
            archived, &error, conflicting_authority));
        BOOST_CHECK(error ==
                    ChainLockPersistenceError::INVALID_CHAINLOCK);
        BOOST_CHECK(persistence.GetFinalityState() == before);
        BOOST_REQUIRE(persistence.LoadRecoveryRosterAuthority());
        BOOST_CHECK(*persistence.LoadRecoveryRosterAuthority() ==
                    *authority);
    }

    {
        CDBWrapper raw{DiskParams(path)};
        BOOST_REQUIRE(raw.Erase(
            RawDiskKey{
                PQ_CHAINLOCK_PERSISTENCE_RECOVERY_AUTHORITY_KEY},
            /*fSync=*/true));
    }
    BOOST_CHECK_THROW(
        PQChainLockPersistence(DiskParams(path), genesis, config),
        std::runtime_error);
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
            MakePresealMarker(880, 880, 1, 64), std::nullopt}));
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
        MakePresealMarker(880, 880, 1, 880)};
    const BTCCPresealMarker active_b_revision_2{
        MakePresealMarker(880, 880, 2, 880)};
    const BTCCPresealMarker prospective_a_revision_2{
        MakePresealMarker(890, 890, 2, 890)};
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
            MakePresealMarker(890, 890, 3, 890)};
        const BTCCPresealState after_b_replay{
            std::nullopt, prospective_a_revision_3};
        BOOST_REQUIRE(
            persistence.PersistBTCCPresealState(after_b_replay));
    }
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        const BTCCPresealState expected{
            std::nullopt, MakePresealMarker(890, 890, 3, 890)};
        BOOST_CHECK(persistence.LoadBTCCPresealState() == expected);
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

    const BTCCPresealMarker initial{MakePresealMarker(880, 880, 7, 1)};
    PQChainLockPersistence persistence{DiskParams(path), genesis, config};
    BOOST_REQUIRE(persistence.PersistBTCCPresealState(
        BTCCPresealState{initial, std::nullopt}));
    BOOST_CHECK(persistence.PersistBTCCPresealState(
        BTCCPresealState{initial, std::nullopt}));

    auto changed_without_revision{initial};
    changed_without_revision.terminal_carrier_height = 890;
    changed_without_revision.terminal_carrier_hash = NonNullHash(890);
    changed_without_revision.terminal_receipt =
        MakePresealMarker(880, 890, 7, 2).terminal_receipt;
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
    auto reused_revision{MakePresealMarker(900, 900, 8, 3)};
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
            BTCCPresealState{MakePresealMarker(880, 880, 1, 4),
                             std::nullopt}));
    }
    {
        CDBWrapper raw{DiskParams(path)};
        RawBTCCPresealMarkerV1 marker;
        BOOST_REQUIRE(raw.Read(
            RawDiskKey{PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY}, marker));
        BOOST_CHECK_EQUAL(GetSerializeSize(marker), 384U);
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
    const auto authority{SetExactInitialization(chainlock, genesis, 5)};
    {
        PQChainLockPersistence persistence{
            DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            chainlock, nullptr, authority));
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
    const auto authority{SetExactInitialization(first, genesis, 6)};
    BOOST_REQUIRE(first.IsStructurallyValid());
    BOOST_REQUIRE(persistence.PersistInitializedBest(
        first, nullptr, authority));
    BOOST_CHECK(persistence.PersistInitializedBest(
        first, nullptr, authority));

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

    const auto predecessor{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, config.activation_predecessor_height)};
    BOOST_REQUIRE(predecessor);
    auto exact{MakeChainLock(
        870, *predecessor, NonNullHash(*predecessor), 61)};
    const auto authority{SetExactInitialization(exact, genesis, 61)};
    BOOST_REQUIRE(persistence.PersistInitializedBest(
        exact, &error, authority));
    BOOST_CHECK(error == ChainLockPersistenceError::NONE);
    BOOST_REQUIRE(persistence.LoadBest());
    BOOST_CHECK(*persistence.LoadBest() == exact);
}

BOOST_AUTO_TEST_CASE(unsealed_advance_survives_restart_until_descendant_seal)
{
    const fs::path path{m_path_root / "pqcl_unsealed_btcc"};
    const uint256 genesis{NonNullHash(10)};
    const auto config{MakeConfig()};

    auto advance{MakeChainLock(870, 865, NonNullHash(865), 10)};
    advance.statement.accepted_btcc_cursor =
        BTCCursor{870, advance.statement.block_hash, NonNullHash(8700)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    const auto authority{SetExactInitialization(advance, genesis, 10)};
    BOOST_REQUIRE(advance.IsStructurallyValid());

    auto before_seal{
        MakeChainLock(875, 870, advance.statement.block_hash, 11)};
    before_seal.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    before_seal.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    SetExactContinuation(before_seal, genesis, advance);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            advance, nullptr, authority));
        BOOST_REQUIRE(persistence.PersistBest(before_seal));
        // A LIVE winner below the carrier retains the outstanding advance.
        // CATCHUP is a per-candidate mode and follows the same sealing rule.
        BOOST_CHECK(!persistence.HasCatchupMarker());
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == advance);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        const auto unsealed{persistence.LoadUnsealedBTCC()};
        BOOST_REQUIRE(unsealed);
        BOOST_CHECK(*unsealed == advance);
        BOOST_CHECK(!persistence.HasCatchupMarker());

        auto seal{MakeChainLock(880, 875,
                                before_seal.statement.block_hash, 12)};
        seal.statement.previous_btcc_cursor =
            advance.statement.accepted_btcc_cursor;
        seal.statement.accepted_btcc_cursor =
            advance.statement.accepted_btcc_cursor;
        seal.statement.btcc_receipt_state = BTCCReceiptState{
            advance.statement.accepted_btcc_cursor, NonNullHash(8800)};
        SetExactContinuation(seal, genesis, before_seal);
        BOOST_REQUIRE(persistence.PersistBest(seal));
        BOOST_CHECK(!persistence.LoadUnsealedBTCC());
        BOOST_CHECK(!persistence.HasCatchupMarker());
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
    const auto authority{SetExactInitialization(prior, genesis, 13)};
    auto advance{MakeChainLock(870, 865, prior.statement.block_hash, 14)};
    advance.statement.accepted_btcc_cursor =
        BTCCursor{870, advance.statement.block_hash, NonNullHash(87'014)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    SetExactContinuation(advance, genesis, prior);
    auto premature{
        MakeChainLock(875, 870, advance.statement.block_hash, 15)};
    SetExactContinuation(premature, genesis, advance);
    auto keep{MakeChainLock(875, 870, advance.statement.block_hash, 16)};
    keep.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    keep.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    SetExactContinuation(keep, genesis, advance);
    auto recovery{
        MakeChainLock(880, 875, keep.statement.block_hash, 17)};
    SetExactContinuation(recovery, genesis, keep);
    recovery.statement.previous_btcc_cursor = {};
    recovery.statement.accepted_btcc_cursor = {};
    const auto proof{MakeReconciliationProof(keep, 17)};
    BOOST_REQUIRE(proof.IsStructurallyValid());

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            prior, nullptr, authority));
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
    const auto authority{
        SetExactInitialization(predecessor, genesis, 19)};
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
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
    const auto authority{
        SetExactInitialization(predecessor, genesis, 20)};
    SetExactContinuation(winner, genesis, predecessor);

    {
        PQChainLockPersistence persistence{
            DiskParams(certificate_path), genesis, config};
        BOOST_CHECK(!persistence.LoadBest());
        BOOST_CHECK(!persistence.HasCatchupMarker());
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            predecessor, nullptr, authority));
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
    const auto authority{SetExactInitialization(first, genesis, 220)};
    auto live{MakeChainLock(
        870, first.statement.height, first.statement.block_hash, 221)};
    SetExactContinuation(live, genesis, first);
    auto second{MakeChainLock(895, 890, NonNullHash(890), 222)};
    SetExactContinuation(second, genesis, live);

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis, config};
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            first, nullptr, authority));
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

    auto first{MakeChainLock(
        first_schedule->seal_height,
        first_schedule->seal_height -
            config.chainlock_schedule.chainlock_period,
        NonNullHash(first_schedule->seal_height -
                    config.chainlock_schedule.chainlock_period),
        230)};
    const auto authority{SetExactInitialization(first, genesis, 230)};
    constexpr uint8_t all_rosters_mask{
        static_cast<uint8_t>((uint16_t{1} << ACTIVE_QUORUMS) - 1)};
    const auto first_capsule{
        PaymentAuditSealContextCapsuleTestAccess::Make(
            genesis, config, first_epoch, first, all_rosters_mask,
            authority)};
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
            genesis, config, second_epoch, second, all_rosters_mask,
            authority)};

    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        ChainLockPersistenceError error{
            ChainLockPersistenceError::NONE};
        const bool persisted{persistence.PersistInitializedBest(
            first, &error, authority, nullptr, first_capsule)};
        BOOST_TEST_CONTEXT("persistence error " <<
                           static_cast<int>(error)) {
            BOOST_REQUIRE(persisted);
        }
        BOOST_REQUIRE(persistence.LoadPaymentAuditSealContext());
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);

        // Byte-identical replay is a no-op and cannot clear the still-live
        // capsule merely because the caller omitted its optional input.
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            first, nullptr, authority));
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);
    }
    {
        PQChainLockPersistence persistence{DiskParams(path), genesis,
                                           config};
        BOOST_REQUIRE(persistence.LoadPaymentAuditSealContext());
        BOOST_CHECK(*persistence.LoadPaymentAuditSealContext() ==
                    first_capsule);

        BOOST_REQUIRE(persistence.PersistBest(
            second, nullptr, nullptr, second_capsule));
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
