// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_staging_store.h>

#include <dbwrapper.h>
#include <test/util/setup_common.h>

#include <cstddef>
#include <cstdint>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

struct TestDiskKey {
    uint8_t type{0};
    uint32_t epoch{0};
    uint8_t row_index{0};
    uint16_t member_index{0};

    SERIALIZE_METHODS(TestDiskKey, obj)
    {
        READWRITE(obj.type, obj.epoch, obj.row_index, obj.member_index);
    }
};

struct TestTrailingDiskKey {
    TestDiskKey key;
    uint8_t trailing{0xa5};

    SERIALIZE_METHODS(TestTrailingDiskKey, obj)
    {
        READWRITE(obj.key, obj.trailing);
    }
};

struct TestDiskState {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{0};
    uint8_t has_active_epoch{0};
    uint32_t active_epoch{0};
    uint8_t has_retained_epoch{0};
    uint32_t retained_epoch{0};
    uint256 checksum;

    SERIALIZE_METHODS(TestDiskState, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.has_active_epoch,
                  obj.active_epoch, obj.has_retained_epoch,
                  obj.retained_epoch, obj.checksum);
    }
};

struct TestTrailingDiskState {
    TestDiskState state;
    uint8_t trailing{0xa5};

    SERIALIZE_METHODS(TestTrailingDiskState, obj)
    {
        READWRITE(obj.state, obj.trailing);
    }
};

DBParams DiskParams(const fs::path& path)
{
    return DBParams{.path = path,
                    .cache_bytes = 1 << 20,
                    .memory_only = false,
                    .wipe_data = false,
                    .obfuscate = false};
}

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

RosterBeaconWindow ReadyRosterWindow(uint32_t newest_epoch)
{
    BOOST_REQUIRE(newest_epoch >= ACTIVE_QUORUMS - 1);
    const uint32_t first_epoch{
        newest_epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 1)};
    RosterBeaconWindow window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] = ReadyRosterBeacon(
            first_epoch + static_cast<uint32_t>(slot));
    }
    window.active.recovery_authority_source.normal_beacon =
        window.active.seeds.back();
    window.next.epoch = newest_epoch + 1;
    BOOST_REQUIRE(window.IsStructurallyValid());
    return window;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

ChainLockShare ResponseShare(int32_t height,
                             uint16_t member,
                             uint64_t branch_salt)
{
    ChainLockShare share;
    auto& transcript{share.transcript};
    auto& statement{transcript.statement};
    statement.height = height;
    statement.block_hash =
        NonNullHash(branch_salt + static_cast<uint64_t>(height));
    statement.previous_chainlock_height = height - 5;
    statement.previous_chainlock_hash = NonNullHash(branch_salt + 1);
    statement.quorum_context_hash = NonNullHash(branch_salt + 2);
    transcript.quorum_epoch = 7;
    transcript.quorum_base_hash = NonNullHash(branch_salt + 3);
    statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    statement.roster_authorization_base = {
        statement.previous_chainlock_height,
        statement.previous_chainlock_hash, NonNullHash(branch_salt + 9)};
    statement.roster_beacons =
        ReadyRosterWindow(transcript.quorum_epoch);
    statement.roster_authorization_state_hash =
        NonNullHash(branch_salt + 8);
    transcript.member_index = member;
    transcript.member_pro_tx_hash = NonNullHash(branch_salt + 100 + member);
    statement.previous_btcc_cursor =
        BTCCursor{height - 10, NonNullHash(branch_salt + 4),
                  NonNullHash(branch_salt + 5)};
    statement.accepted_btcc_cursor =
        BTCCursor{height, statement.block_hash,
                  NonNullHash(branch_salt + 6)};
    statement.btcc_advance = BTCCAdvance::ADVANCE;
    statement.payment_probation_state_hash = NonNullHash(branch_salt + 7);
    share.authenticated_signature.key_proof.public_key[0] = 1;
    share.authenticated_signature.signature[0] =
        static_cast<uint8_t>(member % 255 + 1);
    BOOST_REQUIRE(share.IsStructurallyValid());
    return share;
}

PaymentAuditStagingRow Row(const uint256& genesis_hash,
                           uint32_t epoch,
                           uint8_t row_index,
                           uint64_t branch_salt = 1'000)
{
    const int32_t height{
        static_cast<int32_t>(1'000 + epoch * 300 + row_index * 10)};
    const auto response{ResponseShare(height, 0, branch_salt)};
    PaymentAuditStagingRow row;
    row.expected.epoch = epoch;
    row.expected.row_index = row_index;
    row.expected.response_height = height;
    row.expected.response_chainlock_logical_id =
        GetLogicalChainLockId(genesis_hash, response.GetStatement());
    row.expected.subject_descriptor_hash = NonNullHash(branch_salt + 8);
    row.deadline_height = height + PAYMENT_AUDIT_ROW_DEADLINE_DELAY;
    row.response_block_hash = response.GetStatement().block_hash;
    for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
        SetBit(row.subject_valid_members, member);
    }
    BOOST_REQUIRE(row.IsStructurallyValid(genesis_hash));
    return row;
}

PaymentAuditResponse Response(const PaymentAuditStagingRow& row,
                              uint16_t member,
                              uint64_t branch_salt = 1'000)
{
    PaymentAuditResponse response;
    response.epoch = row.expected.epoch;
    response.row_index = row.expected.row_index;
    response.subject_descriptor_hash = row.expected.subject_descriptor_hash;
    response.response = ResponseShare(
        row.expected.response_height, member, branch_salt);
    BOOST_REQUIRE(response.response.GetStatement().block_hash ==
                  row.response_block_hash);
    BOOST_REQUIRE(response.IsStructurallyValid());
    return response;
}

void FreezeEpoch(PaymentAuditStagingStore& store,
                 const uint256& genesis_hash,
                 uint32_t epoch)
{
    for (uint8_t index{0}; index < PAYMENT_AUDIT_ROW_COUNT; ++index) {
        const auto row{Row(genesis_hash, epoch, index)};
        BOOST_REQUIRE(store.EnsureRow(row) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.FreezeRow(
                          epoch, index, row.response_block_hash,
                          NonNullHash(50'000 + epoch * 100 + index)) ==
                      PaymentAuditStagingResult::ACCEPTED);
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_audit_staging_store_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deadline_barrier_compacts_and_survives_restart)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_restart"};
    const uint256 genesis_hash{NonNullHash(1)};
    const auto row{Row(genesis_hash, 4, 0)};
    const auto first{Response(row, 0)};
    const auto late{Response(row, 1)};
    const uint256 deadline_hash{NonNullHash(2)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
        BOOST_REQUIRE(store.ActivateEpoch(4) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.EnsureRow(row) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(store.AddVerifiedResponse(
                        4, 0, row.deadline_height - 1, first) ==
                    PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(store.AddVerifiedResponse(
                        4, 0, row.deadline_height, late) ==
                    PaymentAuditStagingResult::DEADLINE_REACHED);
        BOOST_REQUIRE(store.FreezeRow(
                          4, 0, row.response_block_hash, deadline_hash) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(!store.GetOpenRow(4, 0));
    }
    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.ActiveEpoch() == 4);
    BOOST_CHECK(!restarted.GetOpenRow(4, 0));
    const auto summary{restarted.GetSummary(4, 0)};
    BOOST_REQUIRE(summary);
    BOOST_CHECK(summary->deadline_block_hash == deadline_hash);
    BOOST_CHECK_EQUAL(CountSet(summary->locally_observed_members), 1U);
}

BOOST_AUTO_TEST_CASE(unsealed_wal_rows_are_discarded_after_restart)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_unsealed"};
    const uint256 genesis_hash{NonNullHash(3)};
    const auto row{Row(genesis_hash, 5, 0)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.ActivateEpoch(5) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.EnsureRow(row) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.AddVerifiedResponse(
                          5, 0, row.deadline_height - 1,
                          Response(row, 0)) ==
                      PaymentAuditStagingResult::ACCEPTED);
    }
    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(!restarted.GetOpenRow(5, 0));
    BOOST_CHECK(!restarted.GetSummary(5, 0));
}

BOOST_AUTO_TEST_CASE(branch_replacement_drops_old_evidence)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_reorg"};
    const uint256 genesis_hash{NonNullHash(10)};
    const auto old_row{Row(genesis_hash, 6, 3, 2'000)};
    const auto replacement{Row(genesis_hash, 6, 3, 3'000)};
    PaymentAuditStagingStore store{path, genesis_hash};
    BOOST_REQUIRE(store.ActivateEpoch(6) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.EnsureRow(old_row) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.AddVerifiedResponse(
                      6, 3, old_row.deadline_height - 1,
                      Response(old_row, 0, 2'000)) ==
                  PaymentAuditStagingResult::ACCEPTED);
    const auto old_statement{
        store.GetVerifiedResponseStatement(old_row.expected)};
    BOOST_REQUIRE(old_statement);
    BOOST_CHECK(*old_statement ==
                Response(old_row, 0, 2'000).response.GetStatement());
    BOOST_CHECK(store.EnsureRow(replacement) ==
                PaymentAuditStagingResult::BRANCH_CONFLICT);
    BOOST_REQUIRE(store.ReplaceRowBranch(replacement) ==
                  PaymentAuditStagingResult::ACCEPTED);
    const auto loaded{store.GetOpenRow(6, 3)};
    BOOST_REQUIRE(loaded);
    BOOST_CHECK(loaded->response_block_hash == replacement.response_block_hash);
    BOOST_CHECK(loaded->responses.empty());
    const auto metadata{store.GetOpenRowMetadata(6, 3)};
    BOOST_REQUIRE(metadata);
    BOOST_CHECK(!CountSet(metadata->available_members));
    BOOST_CHECK(!store.GetVerifiedResponseStatement(replacement.expected));
}

BOOST_AUTO_TEST_CASE(compact_inventory_preserves_full_quorum_burst)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_inventory"};
    const uint256 genesis_hash{NonNullHash(15)};
    auto row{Row(genesis_hash, 12, 0)};
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        SetBit(row.subject_valid_members, member);
    }
    BOOST_REQUIRE(row.IsStructurallyValid(genesis_hash));

    std::size_t sync_barriers{0};
    PaymentAuditStagingStore store{
        path, genesis_hash, 8 << 20, false,
        [&] {
            ++sync_barriers;
            return true;
        }};
    BOOST_REQUIRE(store.ActivateEpoch(12) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.EnsureRow(row) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(!store.GetVerifiedResponseStatement(row.expected));
    for (uint16_t member{0}; member < QUORUM_SIZE; ++member) {
        BOOST_REQUIRE(store.AddVerifiedResponse(
                          12, 0, row.deadline_height - 1,
                          Response(row, member)) ==
                      PaymentAuditStagingResult::ACCEPTED);
    }

    const auto metadata{store.GetOpenRowMetadata(12, 0)};
    BOOST_REQUIRE(metadata);
    BOOST_CHECK_EQUAL(CountSet(metadata->available_members), QUORUM_SIZE);
    const auto statement{store.GetVerifiedResponseStatement(row.expected)};
    BOOST_REQUIRE(statement);
    BOOST_CHECK(*statement == Response(row, 0).response.GetStatement());
    const auto rows{store.GetOpenRowsMetadata(12)};
    BOOST_REQUIRE_EQUAL(rows.size(), 1U);
    BOOST_CHECK(rows.front() == *metadata);
    const auto burst{store.GetVerifiedResponses(
        row.expected, metadata->available_members)};
    BOOST_REQUIRE(burst);
    BOOST_CHECK_EQUAL(burst->size(), QUORUM_SIZE);

    QuorumBitmap requested{};
    SetBit(requested, 0);
    SetBit(requested, QUORUM_SIZE - 1);
    const auto selected{
        store.GetVerifiedResponses(row.expected, requested)};
    BOOST_REQUIRE(selected);
    BOOST_REQUIRE_EQUAL(selected->size(), 2U);
    BOOST_CHECK_EQUAL(
        selected->front().response.transcript.member_index, 0U);
    BOOST_CHECK_EQUAL(
        selected->back().response.transcript.member_index,
        QUORUM_SIZE - 1);

    auto stale_identity{row.expected};
    stale_identity.response_chainlock_logical_id = NonNullHash(16);
    BOOST_CHECK(!store.GetVerifiedResponseStatement(stale_identity));
    BOOST_CHECK(!store.GetVerifiedResponses(stale_identity, requested));
    BOOST_CHECK_EQUAL(sync_barriers, 0U);

    BOOST_REQUIRE(store.FreezeRow(
                      12, 0, row.response_block_hash,
                      NonNullHash(17)) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(!store.GetVerifiedResponseStatement(row.expected));
    BOOST_CHECK_EQUAL(sync_barriers, 1U);
    const auto summary{store.GetSummary(12, 0)};
    BOOST_REQUIRE(summary);
    BOOST_CHECK_EQUAL(
        CountSet(summary->locally_observed_members), QUORUM_SIZE);
}

BOOST_AUTO_TEST_CASE(two_open_rows_are_bounded)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_bound"};
    const uint256 genesis_hash{NonNullHash(20)};
    PaymentAuditStagingStore store{path, genesis_hash};
    BOOST_REQUIRE(store.ActivateEpoch(7) ==
                  PaymentAuditStagingResult::ACCEPTED);
    const auto first{Row(genesis_hash, 7, 0)};
    const auto second{Row(genesis_hash, 7, 1)};
    const auto third{Row(genesis_hash, 7, 2)};
    BOOST_REQUIRE(store.EnsureRow(first) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.EnsureRow(second) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(store.EnsureRow(third) ==
                PaymentAuditStagingResult::CAPACITY_EXCEEDED);
    BOOST_REQUIRE(store.FreezeRow(7, 0, first.response_block_hash,
                                  NonNullHash(70'000)) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.EnsureRow(third) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_REQUIRE(store.DiscardOpenRow(7, 1) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(!store.GetOpenRow(7, 1));
}

BOOST_AUTO_TEST_CASE(prior_epoch_summaries_survive_current_collection)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_overlap"};
    const uint256 genesis_hash{NonNullHash(30)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.ActivateEpoch(8) ==
                      PaymentAuditStagingResult::ACCEPTED);
        FreezeEpoch(store, genesis_hash, 8);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(8).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_REQUIRE(store.ActivateEpoch(9) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(store.RetainedEpoch() == 8);
        FreezeEpoch(store, genesis_hash, 9);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(8).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(9).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_REQUIRE(store.ActivateEpoch(10) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(store.RetainedEpoch() == 9);
        FreezeEpoch(store, genesis_hash, 10);
        const auto retained{store.RetainedEpochs()};
        BOOST_REQUIRE_EQUAL(retained.size(), 2U);
        BOOST_CHECK_EQUAL(retained[0], 8U);
        BOOST_CHECK_EQUAL(retained[1], 9U);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(8).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(9).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(10).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
    }
    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.ActiveEpoch() == 10);
    BOOST_CHECK(restarted.RetainedEpoch() == 9);
    const auto retained{restarted.RetainedEpochs()};
    BOOST_REQUIRE_EQUAL(retained.size(), 2U);
    BOOST_CHECK_EQUAL(retained[0], 8U);
    BOOST_CHECK_EQUAL(retained[1], 9U);
    BOOST_CHECK_EQUAL(restarted.GetEpochSummaries(8).size(),
                      PAYMENT_AUDIT_ROW_COUNT);
    BOOST_REQUIRE(restarted.ClearRetainedEpoch(8) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(restarted.GetEpochSummaries(8).empty());
    BOOST_CHECK(restarted.RetainedEpoch() == 9);
    BOOST_CHECK_EQUAL(restarted.GetEpochSummaries(9).size(),
                      PAYMENT_AUDIT_ROW_COUNT);
    BOOST_CHECK_EQUAL(restarted.GetEpochSummaries(10).size(),
                      PAYMENT_AUDIT_ROW_COUNT);
}

BOOST_AUTO_TEST_CASE(two_epoch_activation_jump_preserves_live_summaries)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_staging_epoch_jump"};
    const uint256 genesis_hash{NonNullHash(31)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.ActivateEpoch(20) ==
                      PaymentAuditStagingResult::ACCEPTED);
        FreezeEpoch(store, genesis_hash, 20);
        BOOST_REQUIRE(store.ActivateEpoch(22) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(!store.RetainedEpoch());
        const auto retained{store.RetainedEpochs()};
        BOOST_REQUIRE_EQUAL(retained.size(), 1U);
        BOOST_CHECK_EQUAL(retained.front(), 20U);
        BOOST_CHECK_EQUAL(store.GetEpochSummaries(20).size(),
                          PAYMENT_AUDIT_ROW_COUNT);
    }
    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(restarted.ActiveEpoch() == 22);
    BOOST_CHECK_EQUAL(restarted.GetEpochSummaries(20).size(),
                      PAYMENT_AUDIT_ROW_COUNT);
    BOOST_REQUIRE(restarted.ActivateEpoch(23) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(restarted.GetEpochSummaries(20).empty());
}

BOOST_AUTO_TEST_CASE(retained_epochs_clear_independently)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_staging_independent_clear"};
    const uint256 genesis_hash{NonNullHash(32)};
    PaymentAuditStagingStore store{path, genesis_hash};
    BOOST_REQUIRE(store.ActivateEpoch(30) ==
                  PaymentAuditStagingResult::ACCEPTED);
    FreezeEpoch(store, genesis_hash, 30);
    BOOST_REQUIRE(store.ActivateEpoch(31) ==
                  PaymentAuditStagingResult::ACCEPTED);
    FreezeEpoch(store, genesis_hash, 31);
    BOOST_REQUIRE(store.ActivateEpoch(32) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(store.RetainedEpoch() == 31);

    BOOST_REQUIRE(store.ClearRetainedEpoch(31) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(!store.RetainedEpoch());
    BOOST_CHECK(store.GetEpochSummaries(31).empty());
    BOOST_CHECK_EQUAL(store.GetEpochSummaries(30).size(),
                      PAYMENT_AUDIT_ROW_COUNT);
    const auto retained{store.RetainedEpochs()};
    BOOST_REQUIRE_EQUAL(retained.size(), 1U);
    BOOST_CHECK_EQUAL(retained.front(), 30U);
    BOOST_REQUIRE(store.ClearRetainedEpoch(30) ==
                  PaymentAuditStagingResult::ACCEPTED);
    BOOST_CHECK(store.RetainedEpochs().empty());
}

BOOST_AUTO_TEST_CASE(incomplete_epoch_forces_selection_abstention)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_incomplete"};
    const uint256 genesis_hash{NonNullHash(40)};
    PaymentAuditStagingStore store{path, genesis_hash};
    BOOST_REQUIRE(store.ActivateEpoch(10) ==
                  PaymentAuditStagingResult::ACCEPTED);
    for (uint8_t index{0}; index + 1 < PAYMENT_AUDIT_ROW_COUNT; ++index) {
        const auto row{Row(genesis_hash, 10, index)};
        BOOST_REQUIRE(store.EnsureRow(row) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.FreezeRow(
                          10, index, row.response_block_hash,
                          NonNullHash(80'000 + index)) ==
                      PaymentAuditStagingResult::ACCEPTED);
    }
    BOOST_CHECK_EQUAL(store.GetEpochSummaries(10).size(),
                      PAYMENT_AUDIT_ROW_COUNT - 1);
    BOOST_CHECK(!store.GetSummary(10, PAYMENT_AUDIT_ROW_COUNT - 1));
}

BOOST_AUTO_TEST_CASE(failed_sync_barrier_never_leaves_a_summary)
{
    const fs::path path{m_path_root / "pq_payment_audit_staging_barrier"};
    const uint256 genesis_hash{NonNullHash(50)};
    const auto row{Row(genesis_hash, 11, 0)};
    {
        PaymentAuditStagingStore store{
            path, genesis_hash, 8 << 20, false, [] { return false; }};
        BOOST_REQUIRE(store.ActivateEpoch(11) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.EnsureRow(row) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_REQUIRE(store.AddVerifiedResponse(
                          11, 0, row.deadline_height - 1,
                          Response(row, 0)) ==
                      PaymentAuditStagingResult::ACCEPTED);
        BOOST_CHECK(store.FreezeRow(
                        11, 0, row.response_block_hash,
                        NonNullHash(90'000)) ==
                    PaymentAuditStagingResult::DATABASE_ERROR);
        BOOST_CHECK(!store.IsHealthy());
    }
    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_REQUIRE(restarted.IsHealthy());
    BOOST_CHECK(!restarted.GetOpenRow(11, 0));
    BOOST_CHECK(!restarted.GetSummary(11, 0));
}

BOOST_AUTO_TEST_CASE(startup_rejects_trailing_physical_key)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_staging_trailing_key"};
    const uint256 genesis_hash{NonNullHash(60)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
    }
    {
        CDBWrapper db{DiskParams(path)};
        BOOST_REQUIRE(db.Write(
            TestTrailingDiskKey{TestDiskKey{0xa2, 12, 0, 0}},
            uint8_t{1}, true));
    }

    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_CHECK(!restarted.IsHealthy());
}

BOOST_AUTO_TEST_CASE(startup_rejects_trailing_physical_value)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_staging_trailing_value"};
    const uint256 genesis_hash{NonNullHash(61)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
    }
    {
        CDBWrapper db{DiskParams(path)};
        const TestDiskKey state_key{0xa1, 0, 0, 0};
        TestDiskState state;
        BOOST_REQUIRE(db.Read(state_key, state));
        BOOST_REQUIRE(db.Write(
            state_key, TestTrailingDiskState{state}, true));
    }

    PaymentAuditStagingStore restarted{path, genesis_hash};
    BOOST_CHECK(!restarted.IsHealthy());
}

BOOST_AUTO_TEST_CASE(startup_scan_is_physically_bounded)
{
    const fs::path path{m_path_root /
                        "pq_payment_audit_staging_physical_bound"};
    const uint256 genesis_hash{NonNullHash(62)};
    constexpr std::size_t max_persisted_records{
        2 + (1 + PaymentAuditStagingStore::MAX_RETAINED_EPOCHS) *
                PAYMENT_AUDIT_ROW_COUNT +
        PaymentAuditStagingStore::MAX_OPEN_ROWS * (1 + QUORUM_SIZE)};
    {
        PaymentAuditStagingStore store{path, genesis_hash};
        BOOST_REQUIRE(store.IsHealthy());
    }
    const TestDiskKey first_extra{0xa2, 100, 0, 0};
    {
        CDBWrapper db{DiskParams(path)};
        CDBBatch batch{db};
        for (std::size_t index{0}; index < max_persisted_records - 1;
             ++index) {
            batch.Write(
                TestDiskKey{
                    0xa2,
                    static_cast<uint32_t>(100 +
                                          index / PAYMENT_AUDIT_ROW_COUNT),
                    static_cast<uint8_t>(index %
                                         PAYMENT_AUDIT_ROW_COUNT),
                    0},
                uint8_t{1});
        }
        BOOST_REQUIRE(db.WriteBatch(batch, true));
    }
    {
        PaymentAuditStagingStore restarted{path, genesis_hash};
        BOOST_CHECK(!restarted.IsHealthy());
    }
    CDBWrapper db{DiskParams(path)};
    BOOST_CHECK(db.Exists(first_extra));
}

BOOST_AUTO_TEST_SUITE_END()
