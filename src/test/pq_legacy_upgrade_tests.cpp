// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_upgrade.h>

#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace {
using node::PQLegacyUpgradeJournal;
using node::PQLegacyUpgradePhase;
using node::PQLegacyUpgradeRecord;

PQLegacyUpgradeRecord MakeRecord()
{
    return {
        .genesis_hash = uint256{1},
        .activation_height = 100,
        .legacy_tip_height = 103,
        .legacy_tip_hash = uint256{2},
        .predecessor_hash = uint256{3},
    };
}

DataStream EncodeUnchecked(const PQLegacyUpgradeRecord& record)
{
    DataStream bytes;
    bytes << record.version << record.genesis_hash << record.activation_height
          << record.legacy_tip_height << record.legacy_tip_hash
          << record.predecessor_hash << static_cast<uint8_t>(record.phase);
    return bytes;
}

std::vector<PQLegacyUpgradeRecord> InvalidRecords()
{
    const auto valid{MakeRecord()};
    std::vector<PQLegacyUpgradeRecord> records;
    auto record{valid};
    record.version = 0;
    records.push_back(record);
    record.version = 2;
    records.push_back(record);
    record = valid;
    record.genesis_hash.SetNull();
    records.push_back(record);
    record = valid;
    record.activation_height = 0;
    records.push_back(record);
    record.activation_height = -1;
    records.push_back(record);
    record.activation_height = std::numeric_limits<int32_t>::max();
    records.push_back(record);
    record = valid;
    record.legacy_tip_height = record.activation_height - 2;
    records.push_back(record);
    record.legacy_tip_height = record.activation_height - 1;
    records.push_back(record);
    record = valid;
    record.legacy_tip_hash.SetNull();
    records.push_back(record);
    record = valid;
    record.predecessor_hash.SetNull();
    records.push_back(record);
    record = valid;
    record.phase = static_cast<PQLegacyUpgradePhase>(0);
    records.push_back(record);
    record.phase = static_cast<PQLegacyUpgradePhase>(3);
    records.push_back(record);
    return records;
}

class FailingUpgradeJournal final : public PQLegacyUpgradeJournal {
public:
    enum class Failure { NONE, RETURN_FALSE, THROW_BEFORE, THROW_AFTER };
    using PQLegacyUpgradeJournal::PQLegacyUpgradeJournal;
    Failure next_failure{Failure::NONE};
    std::size_t writes{0};

protected:
    bool WriteBatch(CDBBatch& batch, bool sync) override
    {
        BOOST_CHECK(sync);
        ++writes;
        const auto failure{next_failure};
        next_failure = Failure::NONE;
        if (failure == Failure::RETURN_FALSE) return false;
        if (failure == Failure::THROW_BEFORE) {
            throw dbwrapper_error("injected upgrade write failure");
        }
        const bool written{PQLegacyUpgradeJournal::WriteBatch(batch, sync)};
        if (failure == Failure::THROW_AFTER) {
            throw dbwrapper_error("injected uncertain upgrade write result");
        }
        return written;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_legacy_upgrade_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(record_encoding_is_canonical)
{
    for (const auto phase : {PQLegacyUpgradePhase::REBUILD_REQUIRED,
                            PQLegacyUpgradePhase::REPLAY_READY}) {
        auto record{MakeRecord()};
        record.phase = phase;
        BOOST_REQUIRE(record.IsValid());
        DataStream bytes;
        bytes << record;
        BOOST_CHECK_EQUAL(bytes.size(), 106U);
        BOOST_CHECK(bytes.str() == EncodeUnchecked(record).str());
        PQLegacyUpgradeRecord decoded;
        bytes >> decoded;
        BOOST_CHECK(bytes.empty());
        BOOST_CHECK(decoded == record);
    }
    for (const auto& record : InvalidRecords()) {
        BOOST_CHECK(!record.IsValid());
        DataStream bytes;
        BOOST_CHECK_THROW(bytes << record, std::ios_base::failure);
        bytes = EncodeUnchecked(record);
        PQLegacyUpgradeRecord decoded;
        BOOST_CHECK_THROW(bytes >> decoded, std::ios_base::failure);
    }
    auto boundary{MakeRecord()};
    boundary.activation_height = 1;
    boundary.legacy_tip_height = 0;
    boundary.predecessor_hash = boundary.legacy_tip_hash;
    BOOST_CHECK(boundary.IsValid());
    boundary.activation_height = std::numeric_limits<int32_t>::max() - 1;
    boundary.legacy_tip_height = std::numeric_limits<int32_t>::max();
    BOOST_CHECK(boundary.IsValid());
}

BOOST_AUTO_TEST_CASE(capture_and_replay_preserve_identity_across_reopen)
{
    const DBParams params{
        .path = m_args.GetDataDirBase() / "pq-upgrade",
        .cache_bytes = 1 << 20,
        .obfuscate = true,
    };
    const auto captured{MakeRecord()};
    auto ready{captured};
    ready.phase = PQLegacyUpgradePhase::REPLAY_READY;
    {
        PQLegacyUpgradeJournal journal{params};
        BOOST_CHECK(!journal.ReadUpgrade());
        BOOST_CHECK(!journal.HasBLSFreeHistory());
        BOOST_CHECK(!journal.MarkReplayReady());
        BOOST_CHECK(!journal.RequireReplayRebuild());
        BOOST_REQUIRE(journal.CaptureLegacyUpgrade(captured));
        BOOST_REQUIRE(journal.MarkBLSFreeHistory());
        BOOST_REQUIRE(journal.CaptureLegacyUpgrade(captured));
    }
    {
        PQLegacyUpgradeJournal journal{params};
        BOOST_REQUIRE(journal.ReadUpgrade());
        BOOST_CHECK(*journal.ReadUpgrade() == captured);
        BOOST_CHECK(journal.HasBLSFreeHistory());
        BOOST_REQUIRE(journal.MarkReplayReady());
        BOOST_REQUIRE(journal.MarkReplayReady());
        BOOST_CHECK(!journal.CaptureLegacyUpgrade(captured));
    }
    {
        PQLegacyUpgradeJournal journal{params};
        BOOST_REQUIRE(journal.ReadUpgrade());
        BOOST_CHECK(*journal.ReadUpgrade() == ready);
        BOOST_CHECK(journal.HasBLSFreeHistory());
        BOOST_REQUIRE(journal.MarkBLSFreeHistory());
        BOOST_REQUIRE(journal.MarkReplayReady());
        BOOST_CHECK(*journal.ReadUpgrade() == ready);
    }
    {
        PQLegacyUpgradeJournal journal{params};
        BOOST_REQUIRE(journal.RequireReplayRebuild());
        BOOST_REQUIRE(journal.RequireReplayRebuild());
        BOOST_CHECK(*journal.ReadUpgrade() == captured);
        BOOST_CHECK(journal.HasBLSFreeHistory());
    }
    {
        PQLegacyUpgradeJournal journal{params};
        BOOST_REQUIRE(journal.ReadUpgrade());
        BOOST_CHECK(*journal.ReadUpgrade() == captured);
        BOOST_REQUIRE(journal.MarkReplayReady());
        BOOST_CHECK(*journal.ReadUpgrade() == ready);
    }
}

BOOST_AUTO_TEST_CASE(origin_and_existing_capture_cannot_be_replaced)
{
    const auto record{MakeRecord()};
    FailingUpgradeJournal origin{
        {.path = "upgrade-origin", .cache_bytes = 1 << 20, .memory_only = true}};
    BOOST_REQUIRE(origin.MarkBLSFreeHistory());
    BOOST_REQUIRE(origin.MarkBLSFreeHistory());
    BOOST_CHECK_EQUAL(origin.writes, 1U);
    BOOST_CHECK(!origin.CaptureLegacyUpgrade(record));
    BOOST_CHECK(!origin.ReadUpgrade());
    BOOST_CHECK(!origin.MarkReplayReady());
    BOOST_CHECK(!origin.RequireReplayRebuild());

    FailingUpgradeJournal captured{
        {.path = "upgrade-capture", .cache_bytes = 1 << 20, .memory_only = true}};
    for (const auto& invalid : InvalidRecords()) {
        BOOST_CHECK(!captured.CaptureLegacyUpgrade(invalid));
    }
    auto ready{record};
    ready.phase = PQLegacyUpgradePhase::REPLAY_READY;
    BOOST_CHECK(!captured.CaptureLegacyUpgrade(ready));
    BOOST_CHECK_EQUAL(captured.writes, 0U);
    BOOST_REQUIRE(captured.CaptureLegacyUpgrade(record));
    BOOST_REQUIRE(captured.CaptureLegacyUpgrade(record));
    BOOST_CHECK_EQUAL(captured.writes, 1U);

    std::vector<PQLegacyUpgradeRecord> conflicts(5, record);
    conflicts[0].genesis_hash = uint256{4};
    conflicts[1].activation_height = 99;
    conflicts[2].legacy_tip_height = 104;
    conflicts[3].legacy_tip_hash = uint256{5};
    conflicts[4].predecessor_hash = uint256{6};
    for (const auto& conflict : conflicts) {
        BOOST_CHECK(!captured.CaptureLegacyUpgrade(conflict));
    }
    BOOST_CHECK_EQUAL(captured.writes, 1U);
    BOOST_CHECK(*captured.ReadUpgrade() == record);
}

BOOST_AUTO_TEST_CASE(present_corrupt_records_fail_closed)
{
    const fs::path path{m_args.GetDataDirBase() / "upgrade-corrupt"};
    const DBParams params{.path = path, .cache_bytes = 1 << 20};
    const auto check = [&](uint8_t key, const auto& bytes) {
        {
            CDBWrapper db{
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true}};
            BOOST_REQUIRE(db.Write(key, bytes, /*fSync=*/true));
        }
        BOOST_CHECK_THROW(PQLegacyUpgradeJournal{params}, dbwrapper_error);
    };
    for (const auto& record : InvalidRecords()) {
        check(uint8_t{'u'}, EncodeUnchecked(record));
    }
    const auto valid{EncodeUnchecked(MakeRecord())};
    for (std::size_t length{0}; length < valid.size(); ++length) {
        auto truncated{valid};
        truncated.resize(length);
        check(uint8_t{'u'}, truncated);
    }
    auto trailing{valid};
    trailing << uint8_t{0};
    check(uint8_t{'u'}, trailing);
    check(uint8_t{'o'}, uint8_t{0});
    check(uint8_t{'o'}, uint8_t{2});
    check(uint8_t{'o'}, uint16_t{1});
    check(uint8_t{'o'}, DataStream{});
    // A malformed key with the reserved prefix is not an absent record.
    for (const uint8_t key : {uint8_t{'u'}, uint8_t{'o'}}) {
        {
            CDBWrapper db{
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true}};
            BOOST_REQUIRE(db.Write(std::pair{key, uint8_t{0}}, valid, true));
        }
        BOOST_CHECK_THROW(PQLegacyUpgradeJournal{params}, dbwrapper_error);
    }
}

BOOST_AUTO_TEST_CASE(failed_and_uncertain_writes_are_retryable_without_new_identity)
{
    using Failure = FailingUpgradeJournal::Failure;
    const auto record{MakeRecord()};
    for (const auto failure : {Failure::RETURN_FALSE, Failure::THROW_BEFORE,
                               Failure::THROW_AFTER}) {
        FailingUpgradeJournal journal{
            {.path = "upgrade-write-failure", .cache_bytes = 1 << 20,
             .memory_only = true}};
        const auto fail_next = [&](const auto& write) {
            journal.next_failure = failure;
            if (failure == Failure::RETURN_FALSE) {
                BOOST_CHECK(!write());
            } else {
                BOOST_CHECK_THROW(write(), dbwrapper_error);
            }
        };
        fail_next([&] { return journal.CaptureLegacyUpgrade(record); });
        BOOST_CHECK_EQUAL(journal.ReadUpgrade().has_value(),
                          failure == Failure::THROW_AFTER);
        BOOST_REQUIRE(journal.CaptureLegacyUpgrade(record));
        BOOST_CHECK(*journal.ReadUpgrade() == record);
        fail_next([&] { return journal.MarkBLSFreeHistory(); });
        BOOST_CHECK_EQUAL(journal.HasBLSFreeHistory(),
                          failure == Failure::THROW_AFTER);
        BOOST_REQUIRE(journal.MarkBLSFreeHistory());
        fail_next([&] { return journal.MarkReplayReady(); });
        auto expected{record};
        if (failure == Failure::THROW_AFTER) {
            expected.phase = PQLegacyUpgradePhase::REPLAY_READY;
        }
        BOOST_CHECK(*journal.ReadUpgrade() == expected);
        BOOST_REQUIRE(journal.MarkReplayReady());
        expected.phase = PQLegacyUpgradePhase::REPLAY_READY;
        BOOST_CHECK(*journal.ReadUpgrade() == expected);
        BOOST_CHECK(journal.HasBLSFreeHistory());
        fail_next([&] { return journal.RequireReplayRebuild(); });
        if (failure == Failure::THROW_AFTER) {
            expected.phase = PQLegacyUpgradePhase::REBUILD_REQUIRED;
        }
        BOOST_CHECK(*journal.ReadUpgrade() == expected);
        BOOST_REQUIRE(journal.RequireReplayRebuild());
        BOOST_CHECK(*journal.ReadUpgrade() == record);
        BOOST_CHECK(journal.HasBLSFreeHistory());
    }
}

BOOST_AUTO_TEST_SUITE_END()
