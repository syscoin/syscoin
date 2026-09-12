// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/auxiliary_history_gc.h>
#include <evo/deterministicmns.h>

#include <chainparams.h>
#include <hash.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <boost/test/unit_test.hpp>

namespace {

uint256 TestHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<unsigned char>(value >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

evo::AuxiliaryHistoryGCDeployment TestDeployment(uint64_t salt = 1)
{
    return {TestHash(salt), TestHash(salt + 1)};
}

DBParams TestDBParams(const fs::path& path, bool wipe)
{
    return DBParams{
        .path = path,
        .cache_bytes = 1 << 20,
        .memory_only = false,
        .wipe_data = wipe,
    };
}

evo::AuxiliaryHistoryGCComponent Component(uint64_t position,
                                           unsigned char closure_byte)
{
    return evo::AuxiliaryHistoryGCComponent{
        /*version=*/1, position, {closure_byte}};
}

evo::AuxiliaryHistoryGCAuthorization Authorization(
    int32_t authorization_height)
{
    return {
        evo::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {authorization_height,
         TestHash(static_cast<uint64_t>(authorization_height) + 100)}};
}

evo::AuxiliaryHistoryGCIntentTarget DMNTarget(
    int32_t authorization_height,
    uint64_t dmn_position)
{
    evo::AuxiliaryHistoryGCIntentTarget target;
    target.authorization = Authorization(authorization_height);
    target.frontier.dmn = Component(
        dmn_position, static_cast<unsigned char>(dmn_position));
    return target;
}

evo::AuxiliaryHistoryGCIntentTarget PQTarget(
    int32_t authorization_height,
    uint64_t pq_position)
{
    evo::AuxiliaryHistoryGCIntentTarget target;
    target.authorization = Authorization(authorization_height);
    target.frontier.pq_registry = Component(
        pq_position, static_cast<unsigned char>(pq_position));
    // SYSCOIN: Versioned empty is the exact canonical manifest for a PQ
    // frontier advance that has no physical keys to erase.
    target.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
        /*version=*/1, {}};
    return target;
}

evo::PQRegistryGCClosure PQClosure(
    uint64_t generation,
    int32_t checkpoint_height,
    bool complete)
{
    evo::PQRegistryGCClosure closure;
    closure.generation = generation;
    closure.checkpoint = {
        checkpoint_height,
        TestHash(static_cast<uint64_t>(checkpoint_height) + 1)};
    closure.checkpoint_state_root = TestHash(1001);
    closure.checkpoint_record_hash = TestHash(1002);
    closure.lineage_base_commitment = TestHash(1003);
    closure.rooted_lineage_commitment = TestHash(1005);
    closure.scan_complete = complete
        ? evo::PQRegistryGCClosure::COMPLETE
        : evo::PQRegistryGCClosure::SCANNING;
    if (!complete) closure.scan_after_key = TestHash(1005);
    return closure;
}

evo::PQRegistryGCEraseCandidate Candidate(uint64_t key,
                                          int32_t height)
{
    return {TestHash(key), height, TestHash(key + 10000)};
}

uint256 OrderedKey(uint32_t value)
{
    uint256 key;
    key.begin()[0] = static_cast<unsigned char>(value >> 24);
    key.begin()[1] = static_cast<unsigned char>(value >> 16);
    key.begin()[2] = static_cast<unsigned char>(value >> 8);
    key.begin()[3] = static_cast<unsigned char>(value);
    return key;
}

uint256 TestIntentId(
    uint64_t sequence,
    const uint256& configuration_id,
    const evo::AuxiliaryHistoryGCIntentTarget& target)
{
    constexpr std::string_view domain{
        "SYS_AUXILIARY_HISTORY_GC_INTENT_ID_V1"};
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
    writer << sequence << configuration_id << target;
    return writer.GetHash();
}

uint256 TestWatermarkId(
    const evo::AuxiliaryHistoryGCWatermark& watermark)
{
    constexpr std::string_view domain{
        "SYS_AUXILIARY_HISTORY_GC_WATERMARK_ID_V1"};
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
    writer << watermark.sequence << watermark.configuration_id
           << watermark.authorization << watermark.frontier
           << watermark.completed_intent_id;
    return writer.GetHash();
}

struct RawDiskIntent {
    uint32_t version{evo::AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION};
    evo::AuxiliaryHistoryGCIntent intent;
    uint32_t guard{0x494e5431}; // "INT1"

    SERIALIZE_METHODS(RawDiskIntent, obj)
    {
        READWRITE(obj.version, obj.intent.sequence,
                  obj.intent.configuration_id, obj.intent.target,
                  obj.intent.intent_id, obj.guard);
    }
};

struct RawDiskWatermark {
    uint32_t version{evo::AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION};
    evo::AuxiliaryHistoryGCWatermark watermark;
    uint32_t guard{0x574d4b31}; // "WMK1"

    SERIALIZE_METHODS(RawDiskWatermark, obj)
    {
        READWRITE(obj.version, obj.watermark.sequence,
                  obj.watermark.configuration_id,
                  obj.watermark.authorization, obj.watermark.frontier,
                  obj.watermark.completed_intent_id,
                  obj.watermark.watermark_id, obj.guard);
    }
};

struct TrailingDiskKey {
    uint8_t type{1};
    uint8_t trailing{0};

    SERIALIZE_METHODS(TrailingDiskKey, obj)
    {
        READWRITE(obj.type, obj.trailing);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(auxiliary_history_gc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_registry_closure_codec_is_fixed_and_strict)
{
    const auto scanning{PQClosure(/*generation=*/7,
                                  /*checkpoint_height=*/288,
                                  /*complete=*/false)};
    const auto encoded_scanning{
        evo::EncodePQRegistryGCClosure(scanning)};
    BOOST_REQUIRE(encoded_scanning);
    static_assert(evo::PQRegistryGCClosure::VERSION == 1);
    static_assert(evo::PQRegistryGCClosure::SCANNING == 0);
    static_assert(evo::PQRegistryGCClosure::COMPLETE == 1);
    static_assert(evo::PQRegistryGCClosure::SCANNING_DIRTY == 2);
    static_assert(evo::PQRegistryGCClosure::RESTART_REQUIRED == 3);
    static_assert(evo::PQRegistryGCClosure::SERIALIZED_SIZE == 212);
    BOOST_CHECK_EQUAL(encoded_scanning->size(),
                      evo::PQRegistryGCClosure::SERIALIZED_SIZE);
    BOOST_CHECK(evo::DecodePQRegistryGCClosure(*encoded_scanning) ==
                scanning);

    const auto complete{PQClosure(/*generation=*/8,
                                  /*checkpoint_height=*/576,
                                  /*complete=*/true)};
    const auto encoded_complete{
        evo::EncodePQRegistryGCClosure(complete)};
    BOOST_REQUIRE(encoded_complete);
    BOOST_CHECK_EQUAL(encoded_complete->size(),
                      evo::PQRegistryGCClosure::SERIALIZED_SIZE);
    BOOST_CHECK(evo::DecodePQRegistryGCClosure(*encoded_complete) ==
                complete);

    auto dirty_scanning{scanning};
    dirty_scanning.scan_complete =
        evo::PQRegistryGCClosure::SCANNING_DIRTY;
    const auto encoded_dirty{
        evo::EncodePQRegistryGCClosure(dirty_scanning)};
    BOOST_REQUIRE(encoded_dirty);
    BOOST_CHECK_EQUAL(encoded_dirty->size(),
                      evo::PQRegistryGCClosure::SERIALIZED_SIZE);
    BOOST_CHECK(evo::DecodePQRegistryGCClosure(*encoded_dirty) ==
                dirty_scanning);

    auto restart_required{complete};
    restart_required.scan_complete =
        evo::PQRegistryGCClosure::RESTART_REQUIRED;
    const auto encoded_restart{
        evo::EncodePQRegistryGCClosure(restart_required)};
    BOOST_REQUIRE(encoded_restart);
    BOOST_CHECK_EQUAL(encoded_restart->size(),
                      evo::PQRegistryGCClosure::SERIALIZED_SIZE);
    BOOST_CHECK(evo::DecodePQRegistryGCClosure(*encoded_restart) ==
                restart_required);

    auto invalid{scanning};
    invalid.generation = 0;
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = scanning;
    invalid.checkpoint.block_hash.SetNull();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = scanning;
    invalid.checkpoint_state_root.SetNull();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = scanning;
    invalid.lineage_base_commitment.SetNull();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = scanning;
    invalid.rooted_lineage_commitment.SetNull();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = scanning;
    invalid.scan_after_key.reset();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = complete;
    invalid.scan_after_key = TestHash(2000);
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = dirty_scanning;
    invalid.scan_after_key.reset();
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = complete;
    invalid.scan_complete =
        evo::PQRegistryGCClosure::RESTART_REQUIRED;
    invalid.scan_after_key = TestHash(2002);
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));
    invalid = complete;
    invalid.scan_complete = 4;
    BOOST_CHECK(!evo::EncodePQRegistryGCClosure(invalid));

    auto trailing{*encoded_scanning};
    trailing.push_back(0);
    BOOST_CHECK(!evo::DecodePQRegistryGCClosure(trailing));
    auto truncated{*encoded_scanning};
    truncated.pop_back();
    BOOST_CHECK(!evo::DecodePQRegistryGCClosure(truncated));

    // SYSCOIN: The optional cursor occupies a presence byte followed by a
    // fixed-width hash. An absent marker with nonzero cursor bytes is not a
    // second encoding of the same closure.
    auto noncanonical_cursor{*encoded_scanning};
    noncanonical_cursor[noncanonical_cursor.size() - uint256::size() - 1] = 0;
    BOOST_CHECK(!evo::DecodePQRegistryGCClosure(noncanonical_cursor));

    evo::AuxiliaryHistoryGCComponent component{
        evo::PQRegistryGCClosure::VERSION, scanning.generation,
        *encoded_scanning};
    const auto authorization{Authorization(300)};
    BOOST_CHECK(evo::IsPQRegistryGCComponentBoundedByAuthorization(
        component, authorization));
    const auto component_hash{
        evo::GetAuxiliaryHistoryGCComponentHash(component)};
    BOOST_REQUIRE(component_hash);
    auto changed_component{component};
    changed_component.closure.back() ^= 1;
    BOOST_CHECK(evo::GetAuxiliaryHistoryGCComponentHash(
                    changed_component) != component_hash);
    changed_component.closure.clear();
    BOOST_CHECK(!evo::GetAuxiliaryHistoryGCComponentHash(
        changed_component));
    component.monotonic_position++;
    BOOST_CHECK(!evo::IsPQRegistryGCComponentBoundedByAuthorization(
        component, authorization));
    component.monotonic_position--;
    BOOST_CHECK(!evo::IsPQRegistryGCComponentBoundedByAuthorization(
        component, Authorization(287)));
}

BOOST_AUTO_TEST_CASE(pq_registry_manifest_codec_is_bounded_and_strict)
{
    evo::PQRegistryGCEraseManifest manifest;
    manifest.target_component_hash = TestHash(4000);
    manifest.from_cursor = TestHash(10);
    manifest.scan_through = TestHash(13);
    manifest.candidates = {Candidate(11, 100), Candidate(12, 101)};

    const auto encoded{
        evo::EncodePQRegistryGCEraseManifest(manifest)};
    BOOST_REQUIRE(encoded);
    BOOST_CHECK(evo::DecodePQRegistryGCEraseManifest(*encoded) ==
                manifest);

    auto with_previous{manifest};
    with_previous.previous_component_hash = TestHash(3999);
    with_previous.reached_eof = 1;
    const auto encoded_with_previous{
        evo::EncodePQRegistryGCEraseManifest(with_previous)};
    BOOST_REQUIRE(encoded_with_previous);
    BOOST_CHECK(evo::DecodePQRegistryGCEraseManifest(
                    *encoded_with_previous) == with_previous);

    evo::PQRegistryGCEraseManifest empty_eof;
    empty_eof.target_component_hash = TestHash(5000);
    empty_eof.reached_eof = 1;
    BOOST_REQUIRE(evo::EncodePQRegistryGCEraseManifest(empty_eof));

    auto invalid{manifest};
    invalid.target_component_hash.SetNull();
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.previous_component_hash = uint256{};
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.from_cursor = uint256{};
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.scan_through = uint256{};
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.scan_through = invalid.from_cursor;
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.from_cursor = TestHash(14);
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.scan_through.reset();
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.candidates[1].key = invalid.candidates[0].key;
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    std::swap(invalid.candidates[0], invalid.candidates[1]);
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.candidates[0].key = *invalid.from_cursor;
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.candidates[1].key = TestHash(14);
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.candidates[0].height = -1;
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = manifest;
    invalid.reached_eof = 2;
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));
    invalid = empty_eof;
    invalid.candidates.push_back(Candidate(11, 100));
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));

    invalid = empty_eof;
    invalid.candidates.resize(
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES + 1,
        Candidate(11, 100));
    BOOST_CHECK(!evo::EncodePQRegistryGCEraseManifest(invalid));

    auto trailing{*encoded};
    trailing.push_back(0);
    BOOST_CHECK(!evo::DecodePQRegistryGCEraseManifest(trailing));
    auto truncated{*encoded};
    truncated.pop_back();
    BOOST_CHECK(!evo::DecodePQRegistryGCEraseManifest(truncated));

    auto noncanonical_optional{*encoded};
    noncanonical_optional[sizeof(uint32_t) + sizeof(uint16_t)] = 2;
    BOOST_CHECK(!evo::DecodePQRegistryGCEraseManifest(
        noncanonical_optional));

    DataStream oversized_count;
    oversized_count << evo::PQRegistryGCEraseManifest::FORMAT_GUARD
                    << evo::PQRegistryGCEraseManifest::VERSION
                    << uint8_t{0} << TestHash(6000)
                    << uint8_t{0} << uint8_t{0} << uint8_t{1};
    WriteCompactSize(
        oversized_count,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES + 1);
    const auto oversized_bytes{MakeUCharSpan(oversized_count)};
    BOOST_CHECK(!evo::DecodePQRegistryGCEraseManifest(oversized_bytes));
}

BOOST_AUTO_TEST_CASE(pq_registry_manifest_roundtrips_at_candidate_bound)
{
    evo::PQRegistryGCEraseManifest manifest;
    manifest.previous_component_hash = TestHash(7000);
    manifest.target_component_hash = TestHash(7001);
    manifest.from_cursor = OrderedKey(1);
    manifest.scan_through = OrderedKey(
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES + 2);
    manifest.candidates.reserve(
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES);
    for (std::size_t i{0};
         i < evo::PQRegistryGCEraseManifest::MAX_CANDIDATES; ++i) {
        manifest.candidates.push_back({
            OrderedKey(static_cast<uint32_t>(i + 2)),
            static_cast<int32_t>(i),
            TestHash(static_cast<uint64_t>(i) + 8000)});
    }

    const auto encoded{
        evo::EncodePQRegistryGCEraseManifest(manifest)};
    BOOST_REQUIRE(encoded);
    BOOST_CHECK(encoded->size() <
                evo::AuxiliaryHistoryGCManifest::MAX_MANIFEST_BYTES);
    const auto decoded{
        evo::DecodePQRegistryGCEraseManifest(*encoded)};
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(*decoded == manifest);
    BOOST_CHECK_EQUAL(decoded->candidates.size(),
                      evo::PQRegistryGCEraseManifest::MAX_CANDIDATES);
}

BOOST_AUTO_TEST_CASE(intent_survives_restart_and_completion_is_atomic)
{
    const fs::path base{m_path_root / "aux_gc_restart"};
    const auto deployment{TestDeployment()};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto target{PQTarget(/*authorization_height=*/100,
                               /*pq_position=*/64)};
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_CHECK(journal.IsHealthy());
        BOOST_CHECK(journal.GetState().watermark == std::nullopt);
        BOOST_CHECK(journal.GetState().intent == std::nullopt);
        BOOST_CHECK(journal.Begin(target, &intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_CHECK(!intent_id.IsNull());
        BOOST_REQUIRE(journal.GetState().intent);
        BOOST_CHECK(journal.GetState().intent->target == target);
    }

    params.wipe_data = false;
    {
        evo::AuxiliaryHistoryGCJournal resumed{params, deployment};
        const auto state{resumed.GetState()};
        BOOST_REQUIRE(state.intent);
        BOOST_CHECK(state.intent->intent_id == intent_id);
        BOOST_CHECK(resumed.HighestAuthorization() ==
                    target.authorization);
        uint256 replay_id;
        BOOST_CHECK(resumed.Begin(target, &replay_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::EXISTING);
        BOOST_CHECK(replay_id == intent_id);
        BOOST_CHECK(resumed.Complete(intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }

    {
        evo::AuxiliaryHistoryGCJournal completed{params, deployment};
        const auto state{completed.GetState()};
        BOOST_CHECK(!state.intent);
        BOOST_REQUIRE(state.watermark);
        BOOST_CHECK(state.watermark->frontier == target.frontier);
        BOOST_CHECK(state.watermark->completed_intent_id == intent_id);
        BOOST_CHECK(completed.Complete(intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE);
        uint256 replay_id;
        BOOST_CHECK(completed.Begin(target, &replay_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE);
        BOOST_CHECK(replay_id == intent_id);
    }
}

BOOST_AUTO_TEST_CASE(sequence_two_cumulative_watermark_survives_restart)
{
    const fs::path base{m_path_root / "aux_gc_sequence_two_restart"};
    const auto deployment{TestDeployment(8)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto first{DMNTarget(/*authorization_height=*/100,
                               /*dmn_position=*/80)};
    auto second{first};
    second.authorization = Authorization(101);
    second.frontier.pq_registry = Component(/*position=*/1,
                                            /*closure_byte=*/1);
    second.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
        /*version=*/1, {}};

    uint256 first_id;
    uint256 second_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_REQUIRE(journal.Begin(first, &first_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(first_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
        BOOST_REQUIRE(journal.Begin(second, &second_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(second_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
        BOOST_REQUIRE(journal.GetState().watermark);
        BOOST_CHECK_EQUAL(journal.GetState().watermark->sequence, 2U);
    }

    params.wipe_data = false;
    evo::AuxiliaryHistoryGCJournal resumed{params, deployment};
    const auto state{resumed.GetState()};
    BOOST_CHECK(!state.intent);
    BOOST_REQUIRE(state.watermark);
    BOOST_CHECK_EQUAL(state.watermark->sequence, 2U);
    BOOST_CHECK(state.watermark->frontier == second.frontier);
    BOOST_CHECK(state.watermark->frontier.dmn == first.frontier.dmn);
    BOOST_CHECK(state.watermark->completed_intent_id == second_id);
    BOOST_CHECK(resumed.HighestAuthorization() == second.authorization);
    uint256 replay_id;
    BOOST_CHECK(resumed.Begin(second, &replay_id) ==
                evo::AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE);
    BOOST_CHECK(replay_id == second_id);
}

BOOST_AUTO_TEST_CASE(one_authorization_drives_bounded_cross_store_progress)
{
    const fs::path base{m_path_root / "aux_gc_reused_authorization"};
    const auto deployment{TestDeployment(9)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto authorization{Authorization(100)};

    auto dmn_first{DMNTarget(/*authorization_height=*/100,
                             /*dmn_position=*/80)};
    auto pq_first{PQTarget(/*authorization_height=*/100,
                           /*pq_position=*/1)};
    pq_first.frontier.dmn = dmn_first.frontier.dmn;
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_REQUIRE(journal.Begin(dmn_first, &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
        BOOST_REQUIRE(journal.Begin(pq_first, &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }

    // Cursor batches remain independently crash-atomic, but do not consume
    // the durable winner that bounds their monotonically advancing frontier.
    params.wipe_data = false;
    auto pq_second{pq_first};
    pq_second.frontier.pq_registry = Component(2, 2);
    uint256 pending_id;
    {
        evo::AuxiliaryHistoryGCJournal resumed{params, deployment};
        BOOST_REQUIRE(resumed.Begin(pq_second, &pending_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_CHECK(!pending_id.IsNull());
    }

    // Startup preserves exact idempotence for an intent whose authorizer is
    // equal to the completed watermark, then permits later components to keep
    // using that same durable winner.
    evo::AuxiliaryHistoryGCJournal resumed{params, deployment};
    uint256 replayed_id;
    BOOST_REQUIRE(resumed.Begin(pq_second, &replayed_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::EXISTING);
    BOOST_CHECK(replayed_id == pending_id);
    BOOST_REQUIRE(resumed.Complete(replayed_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    auto dmn_second{pq_second};
    dmn_second.frontier.dmn = Component(81, 81);
    dmn_second.pq_erase_manifest.reset();
    BOOST_REQUIRE(resumed.Begin(dmn_second, &intent_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::STARTED);
    BOOST_REQUIRE(resumed.Complete(intent_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    const auto state{resumed.GetState()};
    BOOST_REQUIRE(state.watermark);
    BOOST_CHECK_EQUAL(state.watermark->sequence, 4U);
    BOOST_CHECK(state.watermark->authorization == authorization);
    BOOST_CHECK(state.watermark->frontier == dmn_second.frontier);

    auto conflicting_authorizer{dmn_second};
    conflicting_authorizer.frontier.dmn = Component(82, 82);
    conflicting_authorizer.authorization.block.block_hash = TestHash(9999);
    BOOST_CHECK(resumed.Begin(conflicting_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
    auto regressed_authorizer{conflicting_authorizer};
    regressed_authorizer.authorization = Authorization(99);
    BOOST_CHECK(resumed.Begin(regressed_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
}

BOOST_AUTO_TEST_CASE(begin_enforces_exact_idempotence_and_cumulative_progress)
{
    const fs::path base{m_path_root / "aux_gc_monotonic"};
    const auto deployment{TestDeployment(10)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    evo::AuxiliaryHistoryGCJournal journal{params, deployment};

    const auto first{DMNTarget(100, 80)};
    auto initial_pq_without_manifest{PQTarget(100, 1)};
    initial_pq_without_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(initial_pq_without_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT);
    auto initial_manifest_without_pq{first};
    initial_manifest_without_pq.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(initial_manifest_without_pq) ==
                evo::AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT);
    auto initial_combined{first};
    initial_combined.frontier.pq_registry = Component(1, 1);
    initial_combined.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(initial_combined) ==
                evo::AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT);

    uint256 first_id;
    BOOST_REQUIRE(journal.Begin(first, &first_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::STARTED);
    BOOST_CHECK(journal.Begin(DMNTarget(101, 81)) ==
                evo::AuxiliaryHistoryGCJournalResult::BUSY);
    BOOST_CHECK(journal.Complete(TestHash(999)) ==
                evo::AuxiliaryHistoryGCJournalResult::MISMATCH);
    BOOST_REQUIRE(journal.Complete(first_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    auto same_frontier_different_authorizer{first};
    same_frontier_different_authorizer.authorization.block.height = 101;
    same_frontier_different_authorizer.authorization.block.block_hash =
        TestHash(201);
    BOOST_CHECK(journal.Begin(same_frontier_different_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto changed_equal_position{DMNTarget(101, 80)};
    changed_equal_position.frontier.dmn->closure = {42};
    BOOST_CHECK(journal.Begin(changed_equal_position) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto changed_component_version{DMNTarget(101, 81)};
    changed_component_version.frontier.dmn->version = 2;
    BOOST_CHECK(journal.Begin(changed_component_version) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto removed_component{DMNTarget(101, 81)};
    removed_component.frontier.dmn.reset();
    removed_component.frontier.pq_registry = Component(1, 1);
    removed_component.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(removed_component) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto add_pq_without_manifest{first};
    add_pq_without_manifest.authorization = Authorization(101);
    add_pq_without_manifest.frontier.pq_registry = Component(1, 1);
    add_pq_without_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(add_pq_without_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto combined_advance{add_pq_without_manifest};
    combined_advance.frontier.dmn = Component(81, 81);
    combined_advance.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(combined_advance) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto second{add_pq_without_manifest};
    second.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    uint256 second_id;
    BOOST_REQUIRE(journal.Begin(second, &second_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::STARTED);
    BOOST_REQUIRE(journal.Complete(second_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    auto same_frontier_lower_authorizer{second};
    same_frontier_lower_authorizer.authorization.block.height = 100;
    same_frontier_lower_authorizer.authorization.block.block_hash =
        TestHash(200);
    BOOST_CHECK(journal.Begin(same_frontier_lower_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
    auto same_frontier_changed_manifest{second};
    same_frontier_changed_manifest.pq_erase_manifest->payload = {1};
    BOOST_CHECK(journal.Begin(same_frontier_changed_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto unchanged_pq_with_manifest{second};
    unchanged_pq_with_manifest.authorization = Authorization(102);
    unchanged_pq_with_manifest.frontier.dmn = Component(82, 82);
    BOOST_CHECK(journal.Begin(unchanged_pq_with_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
    unchanged_pq_with_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(unchanged_pq_with_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::STARTED);
}

BOOST_AUTO_TEST_CASE(manager_restores_persisted_authorization_high_watermark)
{
    SelectParams(ChainType::REGTEST);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreActivation {
        Consensus::Params& consensus;
        int32_t height{consensus.nPQActivationHeight};
        ~RestoreActivation()
        {
            consensus.nPQActivationHeight = height;
        }
    } restore{consensus};
    const int32_t activation_height{consensus.DIP0003Height + 10};
    consensus.nPQActivationHeight = activation_height;

    const fs::path base{m_path_root / "aux_gc_manager_restore"};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto deployment{
        evo::MakeAuxiliaryHistoryGCDeployment(consensus)};
    auto target{PQTarget(activation_height + 100, 80)};
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_REQUIRE(journal.Begin(target, &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }

    params.wipe_data = false;
    CDeterministicMNManager manager{params};
    const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization lower{
        CDeterministicMNManager::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {activation_height + 50, TestHash(650)}};
    BOOST_CHECK(!manager.UpdateAuxiliaryHistoryGCAuthorization(lower));
}

BOOST_AUTO_TEST_CASE(empty_schema_rebinds_but_durable_state_is_deployment_bound)
{
    const fs::path base{m_path_root / "aux_gc_strict"};
    const auto deployment{TestDeployment(20)};
    const evo::AuxiliaryHistoryGCDeployment rebound_deployment{
        deployment.genesis_hash, TestHash(22)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
    }
    params.wipe_data = false;
    BOOST_CHECK_THROW(
        evo::AuxiliaryHistoryGCJournal(params, TestDeployment(21)),
        std::runtime_error);
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal rebound{params,
                                               rebound_deployment};
        BOOST_REQUIRE(rebound.Begin(DMNTarget(100, 80), &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params, deployment),
                      std::runtime_error);
    {
        evo::AuxiliaryHistoryGCJournal resumed{params,
                                               rebound_deployment};
        BOOST_REQUIRE(resumed.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params, deployment),
                      std::runtime_error);

    {
        auto raw_params{params};
        raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
        CDBWrapper raw{raw_params};
        BOOST_REQUIRE(raw.Write(uint8_t{99}, uint8_t{1},
                                /*fSync=*/true));
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params,
                                                      rebound_deployment),
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(startup_rejects_sequence_one_combined_state)
{
    const auto deployment{TestDeployment(29)};
    {
        const fs::path base{m_path_root / "aux_gc_combined_intent"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        { evo::AuxiliaryHistoryGCJournal journal{params, deployment}; }
        params.wipe_data = false;

        auto combined_target{DMNTarget(100, 80)};
        combined_target.frontier.pq_registry = Component(1, 1);
        combined_target.pq_erase_manifest =
            evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
        RawDiskIntent disk_intent;
        disk_intent.intent.sequence = 1;
        disk_intent.intent.configuration_id =
            deployment.configuration_id;
        disk_intent.intent.target = combined_target;
        disk_intent.intent.intent_id = TestIntentId(
            disk_intent.intent.sequence,
            disk_intent.intent.configuration_id,
            disk_intent.intent.target);
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{3}, disk_intent,
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }

    {
        const fs::path base{m_path_root / "aux_gc_combined_watermark"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        RawDiskWatermark disk_watermark;
        {
            evo::AuxiliaryHistoryGCJournal journal{params, deployment};
            uint256 intent_id;
            BOOST_REQUIRE(journal.Begin(DMNTarget(100, 80), &intent_id) ==
                          evo::AuxiliaryHistoryGCJournalResult::STARTED);
            BOOST_REQUIRE(journal.Complete(intent_id) ==
                          evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
            const auto state{journal.GetState()};
            BOOST_REQUIRE(state.watermark);
            disk_watermark.watermark = *state.watermark;
        }
        params.wipe_data = false;
        disk_watermark.watermark.frontier.pq_registry = Component(1, 1);
        disk_watermark.watermark.watermark_id =
            TestWatermarkId(disk_watermark.watermark);
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{2}, disk_watermark,
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(startup_rejects_trailing_keys_and_corrupt_values)
{
    const auto deployment{TestDeployment(30)};
    {
        const fs::path base{m_path_root / "aux_gc_schema_less"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{2}, uint8_t{0},
                                    /*fSync=*/true));
        }
        params.wipe_data = false;
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }

    {
        const fs::path base{m_path_root / "aux_gc_trailing_key"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        { evo::AuxiliaryHistoryGCJournal journal{params, deployment}; }
        params.wipe_data = false;
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(TrailingDiskKey{}, uint8_t{1},
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }

    {
        const fs::path base{m_path_root / "aux_gc_corrupt_intent"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        uint256 intent_id;
        {
            evo::AuxiliaryHistoryGCJournal journal{params, deployment};
            BOOST_REQUIRE(journal.Begin(DMNTarget(100, 80), &intent_id) ==
                          evo::AuxiliaryHistoryGCJournalResult::STARTED);
        }
        params.wipe_data = false;
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{3}, uint8_t{0},
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }
}

BOOST_AUTO_TEST_SUITE_END()
