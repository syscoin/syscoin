// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_store.h>

#include <test/util/setup_common.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

static_assert(!std::is_constructible_v<
              VerifiedPaymentAuditAdmission, FinalPaymentAudit, uint8_t>);
static_assert(!std::is_constructible_v<
              StoredVerifiedPaymentAudit, FinalPaymentAudit, uint256,
              uint256, uint8_t, uint64_t>);

namespace llmq_tests {

class PaymentAuditStoreTestAccess final {
public:
    static VerifiedPaymentAuditAdmission Admission(
        FinalPaymentAudit audit, uint8_t authorization_mask)
    {
        return VerifiedPaymentAuditAdmission{
            std::move(audit), authorization_mask};
    }
};

} // namespace llmq_tests

namespace {

VerifiedPaymentAuditAdmission Verified(
    FinalPaymentAudit audit, uint8_t authorization_mask = 0x0f)
{
    return llmq_tests::PaymentAuditStoreTestAccess::Admission(
        std::move(audit), authorization_mask);
}

struct TestWitnessKey {
    uint8_t prefix{0xa1};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 witness_id;

    SERIALIZE_METHODS(TestWitnessKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash,
                  obj.witness_id);
    }
};

struct TestPresenceKey {
    uint8_t prefix{0xa4};
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint256 genesis_hash;
    uint256 witness_id;

    SERIALIZE_METHODS(TestPresenceKey, obj)
    {
        READWRITE(obj.prefix, obj.version, obj.genesis_hash,
                  obj.witness_id);
    }
};

struct TestTrailingPresenceKey {
    TestPresenceKey key;
    uint8_t trailing{0xa5};

    SERIALIZE_METHODS(TestTrailingPresenceKey, obj)
    {
        READWRITE(obj.key, obj.trailing);
    }
};

struct TestPresenceRecord {
    uint32_t version{PaymentAuditStore::DB_FORMAT_VERSION};
    uint32_t epoch{0};
    uint256 witness_id;
    uint32_t guard{0x50525031};

    SERIALIZE_METHODS(TestPresenceRecord, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.witness_id, obj.guard);
    }
};

struct TestTrailingPresenceRecord {
    TestPresenceRecord record;
    uint8_t trailing{0xa5};

    SERIALIZE_METHODS(TestTrailingPresenceRecord, obj)
    {
        READWRITE(obj.record, obj.trailing);
    }
};

struct TestTrailingScalarKey {
    uint8_t prefix{0xa6};
    uint8_t trailing{0x01};

    SERIALIZE_METHODS(TestTrailingScalarKey, obj)
    {
        READWRITE(obj.prefix, obj.trailing);
    }
};

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

RosterBeaconSeed ReadyRosterBeacon(uint32_t epoch)
{
    RosterBeaconSeed seed;
    seed.state = RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = BTCCursor{
        10'000 + static_cast<int32_t>(epoch),
        NonNullHash(100'000 + epoch), NonNullHash(200'000 + epoch)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(300'000 + epoch);
    return seed;
}

RosterBeaconWindow ReadyRosterWindow(uint32_t first_epoch)
{
    RosterBeaconWindow window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] = ReadyRosterBeacon(
            first_epoch + static_cast<uint32_t>(slot));
    }
    window.next.epoch = first_epoch + ACTIVE_QUORUMS;
    BOOST_REQUIRE(window.IsStructurallyValid());
    return window;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

FinalPaymentAudit Audit(uint32_t epoch, uint8_t mask, uint64_t salt)
{
    FinalPaymentAudit audit;
    auto& commitment{audit.statement.commitment};
    const int32_t anchor_height{
        static_cast<int32_t>(10'000 + epoch * 1'000)};
    commitment.seed.epoch = epoch;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        anchor_height, NonNullHash(10 + salt),
        BTCCursor{anchor_height, NonNullHash(11 + salt),
                  NonNullHash(12 + salt)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(13 + salt);
    commitment.selected_row = 3;
    commitment.response_height = anchor_height - 30;
    commitment.deadline_height = anchor_height - 10;
    commitment.response_chainlock_logical_id = NonNullHash(14 + salt);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = anchor_height + PAYMENT_AUDIT_SEAL_DELAY;
    commitment.subject_epoch = epoch;
    commitment.subject_quorum_base_hash = NonNullHash(15 + salt);
    commitment.subject_descriptor_hash = NonNullHash(16 + salt);
    SetFirstMembers(commitment.subject_valid_members, QUORUM_SIZE);
    commitment.previous_probation_state_hash = NonNullHash(17 + salt);

    auto& seal{audit.statement.seal_statement};
    seal.height = commitment.seal_height;
    seal.block_hash = NonNullHash(18 + salt);
    seal.previous_chainlock_height = commitment.seal_height - 5;
    seal.previous_chainlock_hash = NonNullHash(19 + salt);
    seal.quorum_context_hash = NonNullHash(20 + salt);
    seal.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    seal.roster_authorization_base = {
        seal.previous_chainlock_height, seal.previous_chainlock_hash,
        NonNullHash(22 + salt)};
    const uint32_t first_active_epoch{
        epoch >= ACTIVE_QUORUMS - 2
            ? epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 2)
            : 0};
    seal.roster_beacons = ReadyRosterWindow(first_active_epoch);
    seal.roster_authorization_state_hash = NonNullHash(21 + salt);
    seal.payment_probation_state_hash =
        commitment.previous_probation_state_hash;

    audit.selected_quorum_mask = mask;
    audit.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((mask & (uint8_t{1} << slot)) == 0) continue;
        SetFirstMembers(audit.signer_bitmaps[slot], QUORUM_THRESHOLD);
        for (std::size_t reporter{0}; reporter < QUORUM_THRESHOLD;
             ++reporter) {
            PaymentAuditReportWitness witness;
            SetFirstMembers(witness.observed_members, QUORUM_MIN_VALID);
            witness.authenticated_signature.key_proof.public_key[0] = 1;
            witness.authenticated_signature.signature[0] =
                static_cast<uint8_t>(salt + slot + reporter);
            audit.report_witnesses.push_back(std::move(witness));
        }
    }
    BOOST_REQUIRE(audit.IsStructurallyValid());
    return audit;
}

PaymentAuditStoreCheckpoint Checkpoint(uint32_t epoch, uint64_t salt,
                                       int32_t target_height)
{
    const int32_t covered_through_height{target_height - 2};
    PaymentAuditReceiptState receipt_state;
    receipt_state.cursor = {
        covered_through_height - 1,
        epoch,
        NonNullHash(700 + salt),
        NonNullHash(800 + salt),
        NonNullHash(900 + salt)};
    receipt_state.cumulative_hash = NonNullHash(1'000 + salt);
    return PaymentAuditStoreCheckpoint{
        epoch,
        covered_through_height,
        NonNullHash(1'500 + salt),
        receipt_state,
        NonNullHash(1'750 + salt),
        target_height,
        NonNullHash(2'000 + salt),
        NonNullHash(3'000 + salt),
        NonNullHash(4'000 + salt)};
}

std::size_t CountDatabaseRecords(const fs::path& path)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    std::size_t count{0};
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
        ++count;
    }
    iterator->CheckStatus();
    return count;
}

void ErasePayloadAndPresence(const fs::path& path,
                             const uint256& genesis_hash,
                             const uint256& witness_id,
                             bool erase_presence = true)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    CDBBatch batch{db};
    batch.Erase(TestWitnessKey{0xa1,
                               PaymentAuditStore::DB_FORMAT_VERSION,
                               genesis_hash, witness_id});
    if (erase_presence) {
        batch.Erase(TestPresenceKey{0xa4,
                                    PaymentAuditStore::DB_FORMAT_VERSION,
                                    genesis_hash, witness_id});
    }
    BOOST_REQUIRE(db.WriteBatch(batch, true));
}

void ErasePresence(const fs::path& path, const uint256& genesis_hash,
                   const uint256& witness_id)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    BOOST_REQUIRE(db.Erase(
        TestPresenceKey{0xa4, PaymentAuditStore::DB_FORMAT_VERSION,
                        genesis_hash, witness_id},
        true));
}

void AppendTrailingPresenceKey(const fs::path& path,
                               const uint256& genesis_hash,
                               uint32_t epoch,
                               const uint256& witness_id)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    const TestPresenceKey key{0xa4, PaymentAuditStore::DB_FORMAT_VERSION,
                              genesis_hash, witness_id};
    CDBBatch batch{db};
    batch.Erase(key);
    batch.Write(TestTrailingPresenceKey{key},
                TestPresenceRecord{PaymentAuditStore::DB_FORMAT_VERSION,
                                   epoch, witness_id});
    BOOST_REQUIRE(db.WriteBatch(batch, true));
}

void AppendTrailingPresenceValue(const fs::path& path,
                                 const uint256& genesis_hash,
                                 uint32_t epoch,
                                 const uint256& witness_id)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    BOOST_REQUIRE(db.Write(
        TestPresenceKey{0xa4, PaymentAuditStore::DB_FORMAT_VERSION,
                        genesis_hash, witness_id},
        TestTrailingPresenceRecord{
            TestPresenceRecord{PaymentAuditStore::DB_FORMAT_VERSION,
                               epoch, witness_id}},
        true));
}

void AppendTrailingPruneIntentKey(const fs::path& path)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    BOOST_REQUIRE(db.Write(TestTrailingScalarKey{}, uint8_t{1}, true));
}

void OverwritePruneIntentValue(const fs::path& path)
{
    CDBWrapper db{DBParams{.path = path,
                           .cache_bytes = 1 << 20,
                           .memory_only = false,
                           .wipe_data = false,
                           .obfuscate = false}};
    BOOST_REQUIRE(db.Write(uint8_t{0xa6}, uint8_t{1}, true));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_audit_store_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(archive_bounds_live_candidates_by_missing_quorum)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_live_candidates"};
    const uint256 genesis_hash{NonNullHash(1)};
    constexpr uint32_t epoch{7};
    const std::array<uint8_t, ACTIVE_QUORUMS> masks{0x0e, 0x0d, 0x0b,
                                                   0x07};
    std::array<FinalPaymentAudit, ACTIVE_QUORUMS> candidates;

    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.IsHealthy());
    for (std::size_t slot{0}; slot < candidates.size(); ++slot) {
        candidates[slot] = Audit(epoch, masks[slot], 100 + slot);
        BOOST_CHECK(store.ProbeLiveCandidateSlot(epoch, masks[slot]) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(candidates[slot])) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.ProbeLiveCandidateSlot(epoch, masks[slot]) ==
                    PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL);
        BOOST_CHECK(store.Has(
            candidates[slot].GetWitnessId(genesis_hash)));
    }

    auto replacement{candidates[0]};
    replacement.report_witnesses[0]
        .authenticated_signature.signature[1] ^= 1;
    BOOST_REQUIRE(replacement.IsStructurallyValid());
    const uint256 replaced_id{
        candidates[0].GetWitnessId(genesis_hash)};
    const uint256 replacement_id{
        replacement.GetWitnessId(genesis_hash)};
    BOOST_REQUIRE(replacement_id != replaced_id);
    BOOST_CHECK(store.ProbeLiveCandidateSlot(
                    epoch, replacement.selected_quorum_mask) ==
                PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL);
    BOOST_CHECK(store.AcceptVerified(Verified(replacement)) ==
                PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL);

    // The exact witness named by an on-chain dependency always admits,
    // evicting only the live candidate with the same 3-of-4 mask.
    BOOST_CHECK(store.AcceptVerified(
                    Verified(replacement), /*required_witness=*/true) ==
                PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.Has(replaced_id));
    BOOST_CHECK(store.Has(replacement_id));
    BOOST_CHECK(store.ProbeLiveCandidateSlot(
                    epoch, replacement.selected_quorum_mask) ==
                PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL);
    for (std::size_t slot{1}; slot < candidates.size(); ++slot) {
        BOOST_CHECK(store.Has(
            candidates[slot].GetWitnessId(genesis_hash)));
    }
}

BOOST_AUTO_TEST_CASE(candidate_snapshot_is_coherent_ordered_and_revisioned)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_candidate_snapshot"};
    const uint256 genesis_hash{NonNullHash(12)};
    constexpr uint32_t epoch{12};
    const auto pinned{Audit(epoch, 0x0b, 800)};
    const auto late_slot{Audit(epoch, 0x07, 801)};
    const auto early_slot{Audit(epoch, 0x0e, 802)};
    const uint256 pinned_id{pinned.GetWitnessId(genesis_hash)};

    PaymentAuditStore store{path, genesis_hash};
    const auto initial_revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(initial_revision);
    BOOST_CHECK(*initial_revision != 0);
    const auto empty{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(empty);
    BOOST_CHECK_EQUAL(empty->revision, *initial_revision);
    BOOST_CHECK_EQUAL(empty->epoch, epoch);
    BOOST_CHECK(empty->ordered_candidates.empty());

    BOOST_REQUIRE(store.AcceptVerified(Verified(pinned)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    const auto accepted_revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(accepted_revision);
    BOOST_CHECK_EQUAL(*accepted_revision, *initial_revision + 1);
    BOOST_CHECK(store.AcceptVerified(Verified(pinned)) ==
                PaymentAuditStoreResult::DUPLICATE_WITNESS);
    BOOST_CHECK(store.ObserveCandidateRevision() == accepted_revision);

    BOOST_REQUIRE(store.PinReferencedWitness(epoch, pinned_id) ==
                  PaymentAuditStoreResult::ACCEPTED);
    const auto pinned_revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(pinned_revision);
    BOOST_CHECK_EQUAL(*pinned_revision, *accepted_revision + 1);
    BOOST_REQUIRE(store.AcceptVerified(Verified(late_slot)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(Verified(early_slot)) ==
                  PaymentAuditStoreResult::ACCEPTED);

    const auto snapshot{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(snapshot);
    BOOST_CHECK_EQUAL(snapshot->epoch, epoch);
    BOOST_REQUIRE_EQUAL(snapshot->ordered_candidates.size(), 3U);
    const std::array<const FinalPaymentAudit*, 3> expected{
        &pinned, &early_slot, &late_slot};
    for (std::size_t index{0}; index < expected.size(); ++index) {
        const auto& candidate{snapshot->ordered_candidates[index]};
        BOOST_CHECK(candidate.audit == *expected[index]);
        BOOST_CHECK(candidate.logical_id ==
                    expected[index]->GetLogicalId(genesis_hash));
        BOOST_CHECK(candidate.witness_id ==
                    expected[index]->GetWitnessId(genesis_hash));
    }
    BOOST_CHECK(store.IsCandidateRevisionCurrent(snapshot->revision));

    const auto compatibility{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(compatibility);
    BOOST_REQUIRE_EQUAL(compatibility->ordered_candidates.size(),
                        expected.size());
    for (std::size_t index{0}; index < expected.size(); ++index) {
        BOOST_CHECK(compatibility->ordered_candidates[index].audit ==
                    *expected[index]);
    }

    auto rejected{early_slot};
    rejected.report_witnesses[0]
        .authenticated_signature.signature[2] ^= 1;
    BOOST_REQUIRE(rejected.IsStructurallyValid());
    BOOST_CHECK(store.AcceptVerified(Verified(rejected)) ==
                PaymentAuditStoreResult::LIVE_CANDIDATE_SLOT_FULL);
    BOOST_CHECK(store.IsCandidateRevisionCurrent(snapshot->revision));

    // Re-pinning the same witness removes branch candidates once, then is a
    // true no-op until another candidate arrives.
    BOOST_CHECK(store.PinReferencedWitness(epoch, pinned_id) ==
                PaymentAuditStoreResult::DUPLICATE_WITNESS);
    const auto repinned_revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(repinned_revision);
    BOOST_CHECK_EQUAL(*repinned_revision, snapshot->revision + 1);
    BOOST_CHECK(store.PinReferencedWitness(epoch, pinned_id) ==
                PaymentAuditStoreResult::DUPLICATE_WITNESS);
    BOOST_CHECK(store.ObserveCandidateRevision() == repinned_revision);

    const auto checkpoint{Checkpoint(epoch, 80, 90'000)};
    BOOST_REQUIRE(store.PruneThroughCheckpoint(checkpoint));
    const auto pruned_revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(pruned_revision);
    BOOST_CHECK_EQUAL(*pruned_revision, *repinned_revision + 1);
    BOOST_REQUIRE(store.PruneThroughCheckpoint(checkpoint));
    BOOST_CHECK(store.ObserveCandidateRevision() == pruned_revision);
    const auto pruned{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(pruned);
    BOOST_CHECK_EQUAL(pruned->revision, *pruned_revision);
    BOOST_CHECK(pruned->ordered_candidates.empty());
}

BOOST_AUTO_TEST_CASE(candidate_revision_tracks_repairs_and_fails_closed)
{
    const fs::path repair_path{m_path_root /
                               "pq_payment_audit_store_revision_repair"};
    const uint256 genesis_hash{NonNullHash(13)};
    constexpr uint32_t epoch{13};
    const auto audit{Audit(epoch, 0x07, 900)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{repair_path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePresence(repair_path, genesis_hash, witness_id);
    {
        PaymentAuditStore store{repair_path, genesis_hash};
        const auto before{store.ObserveCandidateRevision()};
        BOOST_REQUIRE(before);
        const auto restored{store.Get(witness_id)};
        BOOST_REQUIRE(restored);
        BOOST_CHECK(*restored == audit);
        const auto after{store.ObserveCandidateRevision()};
        BOOST_REQUIRE(after);
        BOOST_CHECK_EQUAL(*after, *before + 1);
        BOOST_CHECK(store.AcceptVerified(Verified(audit)) ==
                    PaymentAuditStoreResult::DUPLICATE_WITNESS);
        BOOST_CHECK(store.ObserveCandidateRevision() == after);
    }

    const fs::path corrupt_path{m_path_root /
                                "pq_payment_audit_store_revision_corrupt"};
    {
        PaymentAuditStore store{corrupt_path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePayloadAndPresence(corrupt_path, genesis_hash, witness_id,
                            /*erase_presence=*/false);
    PaymentAuditStore corrupt{corrupt_path, genesis_hash};
    const auto before_repair{corrupt.ObserveCandidateRevision()};
    BOOST_REQUIRE(before_repair);
    BOOST_CHECK(!corrupt.Get(witness_id));
    const auto repaired_revision{corrupt.ObserveCandidateRevision()};
    BOOST_REQUIRE(repaired_revision);
    BOOST_CHECK_EQUAL(*repaired_revision, *before_repair + 1);
    BOOST_CHECK(!corrupt.GetEpochCandidateSnapshot(epoch));
    BOOST_CHECK(!corrupt.IsHealthy());
    BOOST_CHECK(!corrupt.ObserveCandidateRevision());
    BOOST_CHECK(!corrupt.IsCandidateRevisionCurrent(*repaired_revision));
}

BOOST_AUTO_TEST_CASE(
    exact_verified_witness_capability_is_atomic_and_revision_bound)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_witness_snapshot"};
    const uint256 genesis_hash{NonNullHash(14)};
    constexpr uint32_t epoch{14};
    const auto audit{Audit(epoch, 0x07, 910)};
    const auto mutation{Audit(epoch, 0x0b, 911)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_CHECK(!store.GetVerifiedWithCandidateRevision(NonNullHash(999)));
    BOOST_REQUIRE(store.IsHealthy());
    BOOST_REQUIRE(store.AcceptVerified(Verified(audit, 0x07)) ==
                  PaymentAuditStoreResult::ACCEPTED);

    const auto exact{store.GetVerifiedWithCandidateRevision(witness_id)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK(exact->Audit() == audit);
    BOOST_CHECK(exact->LogicalId() == audit.GetLogicalId(genesis_hash));
    BOOST_CHECK(exact->WitnessId() == witness_id);
    BOOST_CHECK_EQUAL(exact->AuthorizationMask(), 0x07);
    BOOST_CHECK_NE(exact->Revision(), 0U);
    BOOST_CHECK(store.IsCandidateRevisionCurrent(exact->Revision()));

    BOOST_REQUIRE(store.AcceptVerified(Verified(mutation)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(exact->Revision()));
}

BOOST_AUTO_TEST_CASE(
    exact_verified_witness_capability_captures_repair_revision)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_witness_snapshot_repair"};
    const uint256 genesis_hash{NonNullHash(15)};
    constexpr uint32_t epoch{15};
    const auto audit{Audit(epoch, 0x07, 920)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit, 0x07)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePresence(path, genesis_hash, witness_id);

    PaymentAuditStore repaired{path, genesis_hash};
    const auto before{repaired.ObserveCandidateRevision()};
    BOOST_REQUIRE(before);
    const auto exact{
        repaired.GetVerifiedWithCandidateRevision(witness_id)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK(exact->Audit() == audit);
    BOOST_CHECK(exact->LogicalId() == audit.GetLogicalId(genesis_hash));
    BOOST_CHECK(exact->WitnessId() == witness_id);
    BOOST_CHECK_EQUAL(exact->AuthorizationMask(), 0x07);
    BOOST_CHECK_EQUAL(exact->Revision(), *before + 1);
    BOOST_CHECK(repaired.IsCandidateRevisionCurrent(exact->Revision()));
}

BOOST_AUTO_TEST_CASE(verified_admission_mask_is_exact_and_fail_closed)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_admission_mask"};
    const uint256 genesis_hash{NonNullHash(16)};
    const auto audit{Audit(16, 0x07, 930)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_CHECK(store.AcceptVerified(Verified(audit, 0x03)) ==
                PaymentAuditStoreResult::INVALID);
    BOOST_CHECK(store.AcceptVerified(Verified(audit, 0x0b)) ==
                PaymentAuditStoreResult::INVALID);
    BOOST_CHECK(!store.Has(witness_id));

    BOOST_REQUIRE(store.AcceptVerified(Verified(audit, 0x0f)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    const auto revision{store.ObserveCandidateRevision()};
    BOOST_REQUIRE(revision);
    const auto stored{
        store.GetVerifiedWithCandidateRevision(witness_id)};
    BOOST_REQUIRE(stored);
    BOOST_CHECK_EQUAL(stored->AuthorizationMask(), 0x0f);

    // The same witness cannot be rebound to a different authorization
    // context after its durable admission.
    BOOST_CHECK(store.AcceptVerified(Verified(audit, 0x07)) ==
                PaymentAuditStoreResult::INVALID);
    BOOST_CHECK(store.ObserveCandidateRevision() == revision);
    const auto unchanged{
        store.GetVerifiedWithCandidateRevision(witness_id)};
    BOOST_REQUIRE(unchanged);
    BOOST_CHECK_EQUAL(unchanged->AuthorizationMask(), 0x0f);
}

BOOST_AUTO_TEST_CASE(pin_prunes_old_candidates_but_accepts_new_branch_candidate)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_pin"};
    const uint256 genesis_hash{NonNullHash(2)};
    constexpr uint32_t epoch{8};
    const auto first{Audit(epoch, 0x07, 200)};
    const auto second{Audit(epoch, 0x0b, 201)};
    const uint256 first_id{first.GetWitnessId(genesis_hash)};
    const uint256 second_id{second.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(store.AcceptVerified(Verified(first)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(second)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.PinReferencedWitness(epoch, second_id) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(!store.Has(first_id));
        BOOST_CHECK(store.Has(second_id));
        const auto selected{store.GetEpochCandidateSnapshot(epoch)};
        BOOST_REQUIRE(selected);
        BOOST_REQUIRE_EQUAL(selected->ordered_candidates.size(), 1U);
        BOOST_CHECK(selected->ordered_candidates.front().witness_id ==
                    second_id);

        const auto unsolicited{Audit(epoch, 0x0d, 202)};
        BOOST_CHECK(store.AcceptVerified(Verified(unsolicited)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        const auto with_unsolicited{
            store.GetEpochCandidateSnapshot(epoch)};
        BOOST_REQUIRE(with_unsolicited);
        BOOST_CHECK_EQUAL(with_unsolicited->ordered_candidates.size(), 2U);
    }
    {
        PaymentAuditStore restarted{path, genesis_hash};
        BOOST_REQUIRE(restarted.IsHealthy());
        BOOST_CHECK(!restarted.Has(first_id));
        const auto selected{restarted.GetEpochCandidateSnapshot(epoch)};
        BOOST_REQUIRE(selected);
        BOOST_REQUIRE_EQUAL(selected->ordered_candidates.size(), 2U);
        BOOST_CHECK(selected->ordered_candidates.front().audit == second);
        BOOST_CHECK(restarted.PinReferencedWitness(epoch, second_id) ==
                    PaymentAuditStoreResult::DUPLICATE_WITNESS);
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_prunes_prefix_and_preserves_live_suffix)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_checkpoint"};
    const uint256 genesis_hash{NonNullHash(3)};
    const auto old_first{Audit(9, 0x07, 300)};
    const auto old_second{Audit(9, 0x07, 301)};
    const auto boundary{Audit(10, 0x0b, 302)};
    const auto live_first{Audit(11, 0x0d, 303)};
    const auto live_second{Audit(11, 0x07, 304)};
    const std::array<uint256, 3> pruned_ids{
        old_first.GetWitnessId(genesis_hash),
        old_second.GetWitnessId(genesis_hash),
        boundary.GetWitnessId(genesis_hash)};
    const std::array<uint256, 2> live_ids{
        live_first.GetWitnessId(genesis_hash),
        live_second.GetWitnessId(genesis_hash)};
    const auto checkpoint{Checkpoint(10, 30, 50'000)};

    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(store.AcceptVerified(Verified(old_first)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.PinReferencedWitness(9, pruned_ids[0]) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(old_second)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.PinReferencedWitness(9, pruned_ids[1]) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(boundary)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.PinReferencedWitness(10, pruned_ids[2]) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(live_first)) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.AcceptVerified(Verified(live_second)) ==
                    PaymentAuditStoreResult::ACCEPTED);

        BOOST_REQUIRE(store.PruneThroughCheckpoint(checkpoint));
        BOOST_CHECK(store.GetPruneCheckpoint() == checkpoint);
        for (const auto& witness_id : pruned_ids) {
            BOOST_CHECK(!store.Has(witness_id));
            BOOST_CHECK(!store.Get(witness_id));
        }
        const auto old_epoch{store.GetEpochCandidateSnapshot(9)};
        const auto boundary_epoch{store.GetEpochCandidateSnapshot(10)};
        BOOST_REQUIRE(old_epoch);
        BOOST_REQUIRE(boundary_epoch);
        BOOST_CHECK(old_epoch->ordered_candidates.empty());
        BOOST_CHECK(boundary_epoch->ordered_candidates.empty());
        BOOST_CHECK(store.AcceptVerified(
                        Verified(old_first), /*required_witness=*/true) ==
                    PaymentAuditStoreResult::INVALID);
        BOOST_CHECK(store.PinReferencedWitness(10, pruned_ids[2]) ==
                    PaymentAuditStoreResult::INVALID);
        for (const auto& witness_id : live_ids) {
            BOOST_CHECK(store.Has(witness_id));
        }
        const auto live_epoch{store.GetEpochCandidateSnapshot(11)};
        BOOST_REQUIRE(live_epoch);
        BOOST_CHECK_EQUAL(live_epoch->ordered_candidates.size(), 2U);
    }

    PaymentAuditStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.GetPruneCheckpoint() == checkpoint);
    for (const auto& witness_id : pruned_ids) {
        BOOST_CHECK(!restarted.Has(witness_id));
    }
    for (const auto& witness_id : live_ids) {
        BOOST_CHECK(restarted.Has(witness_id));
    }
    const auto live_epoch{restarted.GetEpochCandidateSnapshot(11)};
    BOOST_REQUIRE(live_epoch);
    BOOST_CHECK_EQUAL(live_epoch->ordered_candidates.size(), 2U);
}

BOOST_AUTO_TEST_CASE(checkpoint_steps_are_bounded_logical_and_crash_resumable)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_step_resume"};
    const uint256 genesis_hash{NonNullHash(31)};
    constexpr uint32_t epoch{70};
    const auto checkpoint{Checkpoint(epoch, 310, 55'000)};
    std::vector<FinalPaymentAudit> retired;
    std::vector<uint256> retired_ids;
    retired.reserve(10);
    retired_ids.reserve(10);
    for (std::size_t index{0}; index < 10; ++index) {
        retired.emplace_back(Audit(epoch, 0x07, 3'100 + index));
        retired_ids.emplace_back(
            retired.back().GetWitnessId(genesis_hash));
    }
    const auto suffix{Audit(epoch + 1, 0x0b, 3'200)};
    const uint256 suffix_id{suffix.GetWitnessId(genesis_hash)};

    const auto check_bounds = [](const PaymentAuditPruneProgress& progress) {
        BOOST_CHECK_LE(
            progress.scanned_records,
            PaymentAuditStore::MAX_PRUNE_SCAN_RECORDS_PER_PASS);
        BOOST_CHECK_LE(
            progress.scanned_value_bytes,
            PaymentAuditStore::MAX_PRUNE_VALUE_BYTES_PER_PASS);
        BOOST_CHECK_LE(
            progress.erased_records,
            PaymentAuditStore::MAX_PRUNE_ERASE_RECORDS_PER_PASS);
    };

    {
        PaymentAuditStore store{path, genesis_hash};
        for (std::size_t index{0}; index < retired.size(); ++index) {
            BOOST_REQUIRE(store.AcceptVerified(Verified(retired[index])) ==
                          PaymentAuditStoreResult::ACCEPTED);
            BOOST_REQUIRE(store.PinReferencedWitness(
                              epoch, retired_ids[index]) ==
                          PaymentAuditStoreResult::ACCEPTED);
        }

        const auto first{store.PruneThroughCheckpointStep(checkpoint)};
        check_bounds(first);
        BOOST_CHECK(first.status == PaymentAuditPruneStatus::IN_PROGRESS);
        BOOST_CHECK(store.GetPendingPruneCheckpoint() == checkpoint);
        BOOST_CHECK(!store.GetPruneCheckpoint());

        // The synced intent is the visibility boundary; physical rows can
        // survive several bounded passes without re-entering any read or
        // admission surface.
        BOOST_CHECK(!store.Has(retired_ids.front()));
        BOOST_CHECK(!store.Get(retired_ids.front()));
        const auto hidden{store.GetEpochCandidateSnapshot(epoch)};
        BOOST_REQUIRE(hidden);
        BOOST_CHECK(hidden->ordered_candidates.empty());
        BOOST_CHECK(store.AcceptVerified(
                        Verified(retired.front()),
                        /*required_witness=*/true) ==
                    PaymentAuditStoreResult::INVALID);
        BOOST_CHECK(store.PinReferencedWitness(
                        epoch, retired_ids.front()) ==
                    PaymentAuditStoreResult::INVALID);
        BOOST_REQUIRE(store.AcceptVerified(Verified(suffix)) ==
                      PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.Has(suffix_id));
    }

    {
        PaymentAuditStore restarted{path, genesis_hash};
        BOOST_REQUIRE(restarted.IsHealthy());
        BOOST_CHECK(restarted.GetPendingPruneCheckpoint() == checkpoint);
        BOOST_CHECK(!restarted.Has(retired_ids.back()));
        BOOST_CHECK(restarted.Has(suffix_id));

        bool erased_prefix{false};
        for (std::size_t pass{0}; pass < 100 && !erased_prefix; ++pass) {
            const auto progress{
                restarted.PruneThroughCheckpointStep(checkpoint)};
            check_bounds(progress);
            BOOST_REQUIRE(progress.status ==
                          PaymentAuditPruneStatus::IN_PROGRESS);
            erased_prefix = progress.erased_records != 0;
        }
        BOOST_REQUIRE(erased_prefix);
        BOOST_CHECK(restarted.GetPendingPruneCheckpoint() == checkpoint);
        BOOST_CHECK(!restarted.GetPruneCheckpoint());
    }

    {
        PaymentAuditStore restarted{path, genesis_hash};
        BOOST_REQUIRE(restarted.IsHealthy());
        BOOST_CHECK(restarted.GetPendingPruneCheckpoint() == checkpoint);
        PaymentAuditPruneStatus status{
            PaymentAuditPruneStatus::IN_PROGRESS};
        for (std::size_t pass{0}; pass < 100 &&
             status == PaymentAuditPruneStatus::IN_PROGRESS; ++pass) {
            const auto progress{
                restarted.PruneThroughCheckpointStep(checkpoint)};
            check_bounds(progress);
            status = progress.status;
        }
        BOOST_REQUIRE(status == PaymentAuditPruneStatus::COMPLETE);
        BOOST_CHECK(restarted.GetPruneCheckpoint() == checkpoint);
        BOOST_CHECK(!restarted.GetPendingPruneCheckpoint());
        for (const auto& witness_id : retired_ids) {
            BOOST_CHECK(!restarted.Has(witness_id));
        }
        BOOST_CHECK(restarted.Has(suffix_id));
    }

    // schema + checkpoint + one retained epoch/witness/presence.
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), 5U);
}

BOOST_AUTO_TEST_CASE(epoch_pruning_uses_numeric_not_leveldb_order)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_epoch_byte_order"};
    const uint256 genesis_hash{NonNullHash(32)};
    const std::array<uint32_t, 4> epochs{1, 255, 256, 65'536};
    std::array<FinalPaymentAudit, epochs.size()> audits;
    std::array<uint256, epochs.size()> witness_ids;
    PaymentAuditStore store{path, genesis_hash};
    for (std::size_t index{0}; index < epochs.size(); ++index) {
        audits[index] = Audit(epochs[index], 0x07, 3'300 + index);
        witness_ids[index] = audits[index].GetWitnessId(genesis_hash);
        BOOST_REQUIRE(store.AcceptVerified(Verified(audits[index])) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }

    const auto checkpoint{Checkpoint(255, 330, 56'000)};
    BOOST_REQUIRE(store.PruneThroughCheckpoint(checkpoint));
    BOOST_CHECK(!store.Has(witness_ids[0]));
    BOOST_CHECK(!store.Has(witness_ids[1]));
    BOOST_CHECK(store.Has(witness_ids[2]));
    BOOST_CHECK(store.Has(witness_ids[3]));
    for (std::size_t index{0}; index < epochs.size(); ++index) {
        const auto snapshot{
            store.GetEpochCandidateSnapshot(epochs[index])};
        BOOST_REQUIRE(snapshot);
        BOOST_CHECK_EQUAL(snapshot->ordered_candidates.size(),
                          index < 2 ? 0U : 1U);
    }
}

BOOST_AUTO_TEST_CASE(pending_checkpoint_revalidates_links_after_restart)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_pending_links"};
    const uint256 genesis_hash{NonNullHash(33)};
    constexpr uint32_t epoch{80};
    const auto audit{Audit(epoch, 0x07, 3'400)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    const auto checkpoint{Checkpoint(epoch, 340, 57'000)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
        BOOST_REQUIRE(store.PinReferencedWitness(epoch, witness_id) ==
                      PaymentAuditStoreResult::ACCEPTED);
        const auto progress{
            store.PruneThroughCheckpointStep(checkpoint)};
        BOOST_REQUIRE(progress.status ==
                      PaymentAuditPruneStatus::IN_PROGRESS);
        BOOST_CHECK(store.GetPendingPruneCheckpoint() == checkpoint);
    }
    ErasePresence(path, genesis_hash, witness_id);

    {
        PaymentAuditStore restarted{path, genesis_hash};
        BOOST_REQUIRE(restarted.IsHealthy());
        BOOST_CHECK(restarted.GetPendingPruneCheckpoint() == checkpoint);
        const auto progress{
            restarted.PruneThroughCheckpointStep(checkpoint)};
        BOOST_CHECK(progress.status == PaymentAuditPruneStatus::CORRUPT);
        BOOST_CHECK(!restarted.IsHealthy());
        BOOST_CHECK(!restarted.GetPruneCheckpoint());
    }
    // Validation failed before physical pruning, so its intent was rolled
    // back and restart cannot mistake a partial prefix for completion.
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), 4U);
}

BOOST_AUTO_TEST_CASE(pending_checkpoint_rejects_corrupt_scalar_records)
{
    const uint256 genesis_hash{NonNullHash(34)};
    const auto checkpoint{Checkpoint(90, 350, 58'000)};

    const fs::path trailing_path{
        m_path_root / "pq_payment_audit_store_pending_trailing_key"};
    {
        PaymentAuditStore store{trailing_path, genesis_hash};
        const auto progress{
            store.PruneThroughCheckpointStep(checkpoint)};
        BOOST_REQUIRE(progress.status ==
                      PaymentAuditPruneStatus::IN_PROGRESS);
    }
    AppendTrailingPruneIntentKey(trailing_path);
    PaymentAuditStore trailing{trailing_path, genesis_hash};
    BOOST_CHECK(!trailing.IsHealthy());

    const fs::path value_path{
        m_path_root / "pq_payment_audit_store_pending_bad_value"};
    {
        PaymentAuditStore store{value_path, genesis_hash};
        const auto progress{
            store.PruneThroughCheckpointStep(checkpoint)};
        BOOST_REQUIRE(progress.status ==
                      PaymentAuditPruneStatus::IN_PROGRESS);
    }
    OverwritePruneIntentValue(value_path);
    PaymentAuditStore bad_value{value_path, genesis_hash};
    BOOST_CHECK(!bad_value.IsHealthy());
}

BOOST_AUTO_TEST_CASE(checkpoint_is_strictly_monotonic_and_idempotent)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_monotonic"};
    const uint256 genesis_hash{NonNullHash(4)};
    const auto first{Checkpoint(20, 40, 60'000)};
    const auto next{Checkpoint(21, 41, 60'005)};

    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.PruneThroughCheckpoint(first));
        BOOST_REQUIRE(store.PruneThroughCheckpoint(first));

        auto conflict{first};
        conflict.authorizing_chainlock_witness_id = NonNullHash(9'999);
        BOOST_CHECK(!store.PruneThroughCheckpoint(conflict));

        auto refreshed{first};
        refreshed.authorizing_target_height += 1;
        refreshed.authorizing_target_hash = NonNullHash(10'001);
        refreshed.authorizing_chainlock_logical_id = NonNullHash(10'002);
        refreshed.authorizing_chainlock_witness_id = NonNullHash(10'003);
        BOOST_REQUIRE(store.PruneThroughCheckpoint(refreshed));
        BOOST_CHECK(store.GetPruneCheckpoint() == refreshed);

        BOOST_CHECK(!store.PruneThroughCheckpoint(
            Checkpoint(19, 42, 60'010)));
        BOOST_CHECK(!store.PruneThroughCheckpoint(
            Checkpoint(21, 43, 60'000)));
        BOOST_CHECK(store.GetPruneCheckpoint() == refreshed);
        BOOST_CHECK(store.IsHealthy());

        BOOST_REQUIRE(store.PruneThroughCheckpoint(next));
        BOOST_CHECK(store.GetPruneCheckpoint() == next);
        BOOST_CHECK(store.AcceptVerified(
                        Verified(Audit(21, 0x07, 400))) ==
                    PaymentAuditStoreResult::INVALID);
        BOOST_CHECK(store.AcceptVerified(
                        Verified(Audit(22, 0x07, 401))) ==
                    PaymentAuditStoreResult::ACCEPTED);
    }

    PaymentAuditStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.GetPruneCheckpoint() == next);
    BOOST_CHECK(restarted.PruneThroughCheckpoint(next));
    BOOST_CHECK(!restarted.PruneThroughCheckpoint(first));
    BOOST_CHECK(restarted.IsHealthy());
}

BOOST_AUTO_TEST_CASE(repeated_checkpoints_bound_all_archive_record_classes)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_bounded"};
    const uint256 genesis_hash{NonNullHash(5)};
    std::array<uint256, 2> retained_ids{};
    PaymentAuditStoreCheckpoint final_checkpoint;

    {
        PaymentAuditStore store{path, genesis_hash};
        for (uint32_t epoch{30}; epoch <= 35; ++epoch) {
            const auto first{Audit(epoch, 0x07, 500 + 2 * epoch)};
            const auto second{Audit(epoch, 0x07, 501 + 2 * epoch)};
            const uint256 first_id{first.GetWitnessId(genesis_hash)};
            const uint256 second_id{second.GetWitnessId(genesis_hash)};
            BOOST_REQUIRE(store.AcceptVerified(Verified(first)) ==
                          PaymentAuditStoreResult::ACCEPTED);
            BOOST_REQUIRE(store.PinReferencedWitness(epoch, first_id) ==
                          PaymentAuditStoreResult::ACCEPTED);
            BOOST_REQUIRE(store.AcceptVerified(Verified(second)) ==
                          PaymentAuditStoreResult::ACCEPTED);
            BOOST_REQUIRE(store.PinReferencedWitness(epoch, second_id) ==
                          PaymentAuditStoreResult::ACCEPTED);
            retained_ids = {first_id, second_id};

            if (epoch != 30) {
                final_checkpoint = Checkpoint(
                    epoch - 1, 500 + epoch,
                    static_cast<int32_t>(70'000 + 5 * epoch));
                BOOST_REQUIRE(
                    store.PruneThroughCheckpoint(final_checkpoint));
                const auto candidates{
                    store.GetEpochCandidateSnapshot(epoch)};
                BOOST_REQUIRE(candidates);
                BOOST_CHECK_EQUAL(candidates->ordered_candidates.size(), 1U);
                BOOST_CHECK(store.Has(first_id));
                BOOST_CHECK(store.Has(second_id));
            }
        }
    }

    // schema + checkpoint + epoch + two witnesses + two references + two
    // presence records. The five retired epochs leave no residual keys.
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), 9U);
    PaymentAuditStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.GetPruneCheckpoint() == final_checkpoint);
    BOOST_CHECK(restarted.Has(retained_ids[0]));
    BOOST_CHECK(restarted.Has(retained_ids[1]));
    const auto candidates{restarted.GetEpochCandidateSnapshot(35)};
    BOOST_REQUIRE(candidates);
    BOOST_CHECK_EQUAL(candidates->ordered_candidates.size(), 1U);
}

BOOST_AUTO_TEST_CASE(checkpoint_prune_fails_closed_on_dangling_index)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_bad_index"};
    const uint256 genesis_hash{NonNullHash(6)};
    const auto audit{Audit(40, 0x07, 700)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePayloadAndPresence(path, genesis_hash, witness_id,
                            /*erase_presence=*/false);
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(!store.PruneThroughCheckpoint(
            Checkpoint(40, 60, 80'000)));
        BOOST_CHECK(!store.IsHealthy());
        BOOST_CHECK(!store.GetPruneCheckpoint());
    }
    // The failed validation published neither deletes nor a checkpoint.
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), 3U);
}

BOOST_AUTO_TEST_CASE(checkpoint_prune_rejects_trailing_physical_key)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_trailing_key"};
    const uint256 genesis_hash{NonNullHash(61)};
    constexpr uint32_t epoch{41};
    const auto audit{Audit(epoch, 0x07, 710)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    AppendTrailingPresenceKey(path, genesis_hash, epoch, witness_id);
    const std::size_t records_before{CountDatabaseRecords(path)};

    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(!store.PruneThroughCheckpoint(
            Checkpoint(epoch, 62, 81'000)));
        BOOST_CHECK(!store.IsHealthy());
        BOOST_CHECK(!store.GetPruneCheckpoint());
    }
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), records_before);
}

BOOST_AUTO_TEST_CASE(checkpoint_prune_rejects_trailing_physical_value)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_store_trailing_value"};
    const uint256 genesis_hash{NonNullHash(63)};
    constexpr uint32_t epoch{42};
    const auto audit{Audit(epoch, 0x07, 720)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.AcceptVerified(Verified(audit)) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }
    AppendTrailingPresenceValue(path, genesis_hash, epoch, witness_id);
    const std::size_t records_before{CountDatabaseRecords(path)};

    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(!store.PruneThroughCheckpoint(
            Checkpoint(epoch, 64, 81'005)));
        BOOST_CHECK(!store.IsHealthy());
        BOOST_CHECK(!store.GetPruneCheckpoint());
    }
    BOOST_CHECK_EQUAL(CountDatabaseRecords(path), records_before);
}

BOOST_AUTO_TEST_CASE(required_response_repairs_missing_live_and_referenced_payload)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_repair"};
    const uint256 genesis_hash{NonNullHash(5)};
    constexpr uint32_t epoch{11};
    const auto audit{Audit(epoch, 0x07, 600)};
    const uint256 witness_id{audit.GetWitnessId(genesis_hash)};

    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(store.AcceptVerified(Verified(audit)) ==
                    PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePayloadAndPresence(path, genesis_hash, witness_id,
                            /*erase_presence=*/false);
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(store.Has(witness_id));
        BOOST_CHECK(!store.Get(witness_id));
        BOOST_CHECK(!store.Has(witness_id));
        BOOST_CHECK(store.AcceptVerified(
                        Verified(audit), /*required_witness=*/true) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.Has(witness_id));
        BOOST_REQUIRE(store.Get(witness_id));
        BOOST_CHECK(store.PinReferencedWitness(epoch, witness_id) ==
                    PaymentAuditStoreResult::ACCEPTED);
    }
    ErasePayloadAndPresence(path, genesis_hash, witness_id);
    {
        PaymentAuditStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_CHECK(!store.Has(witness_id));
        BOOST_CHECK(store.AcceptVerified(
                        Verified(audit), /*required_witness=*/true) ==
                    PaymentAuditStoreResult::ACCEPTED);
        BOOST_CHECK(store.Has(witness_id));
        const auto restored{store.Get(witness_id)};
        BOOST_REQUIRE(restored);
        BOOST_CHECK(*restored == audit);
        BOOST_CHECK(store.PinReferencedWitness(epoch, witness_id) ==
                    PaymentAuditStoreResult::DUPLICATE_WITNESS);
    }
}

BOOST_AUTO_TEST_CASE(schema_or_genesis_mismatch_fails_closed_until_wipe)
{
    const fs::path path{m_path_root / "pq_payment_audit_store_schema"};
    {
        PaymentAuditStore store{path, NonNullHash(10)};
        BOOST_REQUIRE(store.IsHealthy());
    }
    {
        PaymentAuditStore wrong_network{path, NonNullHash(11)};
        BOOST_CHECK(!wrong_network.IsHealthy());
    }
    {
        PaymentAuditStore wiped{path, NonNullHash(11), 8 << 20,
                                 /*wipe=*/true};
        BOOST_CHECK(wiped.IsHealthy());
    }
}

BOOST_AUTO_TEST_SUITE_END()
