// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_verify.h>
#include <llmq/pq_quorum_builder.h>

#include <chain.h>
#include <streams.h>
#include <support/cleanse.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

constexpr int32_t TARGET_HEIGHT{2810};
constexpr int32_t PREVIOUS_CHAINLOCK_HEIGHT{2805};
constexpr int32_t EPOCH_ORIGIN{1440};
constexpr int32_t BTCC_CANDIDATE_ORIGIN{2305};
constexpr uint32_t SNAPSHOT_LAG{144};
constexpr std::size_t MAX_TEST_WORKERS{8};
constexpr uint8_t AUTHORIZATION_MASK{0b0111};
constexpr std::size_t CHILD_KEY_COUNT{
    (ACTIVE_QUORUMS + 1) * QUORUM_MIN_VALID};

uint256 NonNullHash(uint64_t value, uint64_t salt = 0)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
        hash.begin()[8 + byte] =
            static_cast<uint8_t>(salt >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

CKeyID KeyId(uint64_t value)
{
    CKeyID key;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        key.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    key.begin()[key.size() - 1] = 0xa5;
    return key;
}

CDeterministicMNCPtr Member(std::size_t member_index)
{
    auto dmn{std::make_shared<CDeterministicMN>(member_index + 1)};
    dmn->proTxHash = NonNullHash(10'000 + member_index);
    dmn->collateralOutpoint = COutPoint(
        NonNullHash(20'000 + member_index),
        static_cast<uint32_t>(member_index + 1));

    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner = KeyId(30'000 + member_index);
    state->nRegisteredHeight = 100;
    state->UpdateConfirmedHash(
        dmn->proTxHash, NonNullHash(40'000 + member_index));
    dmn->pdmnState = std::move(state);
    return dmn;
}

CDeterministicMNList Snapshot(int32_t height, const uint256& block_hash)
{
    CDeterministicMNList snapshot{
        block_hash, height, static_cast<uint32_t>(QUORUM_SIZE)};
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        snapshot.AddMN(Member(member), /*fBumpTotalCount=*/false);
    }
    return snapshot;
}

struct IndexChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;

    explicit IndexChain(int32_t tip_height)
        : hashes(static_cast<std::size_t>(tip_height) + 1),
          indices(static_cast<std::size_t>(tip_height) + 1)
    {
        for (int32_t height{0}; height <= tip_height; ++height) {
            hashes[height] = NonNullHash(static_cast<uint64_t>(height) + 1);
            indices[height].nHeight = height;
            indices[height].phashBlock = &hashes[height];
            indices[height].pprev =
                height == 0 ? nullptr : &indices[height - 1];
            indices[height].BuildSkip();
        }
    }

    const CBlockIndex& Tip() const { return indices.back(); }
};

QuorumBuildConfig BuildConfig()
{
    QuorumBuildConfig config;
    config.schedule.epoch_origin = EPOCH_ORIGIN;
    config.roster_snapshot_lag_blocks = SNAPSHOT_LAG;
    config.registration_cutoff_blocks = SNAPSHOT_LAG;
    config.future_horizon_epochs = 8;
    return config;
}

std::size_t TestWorkerCount()
{
    const std::size_t available{
        std::max(1U, std::thread::hardware_concurrency())};
    return std::min(MAX_TEST_WORKERS, available);
}

// Preserve jthread's exception-safe join behavior on supported libc++ releases
// that do not provide jthread.
class WorkerJoinGuard
{
public:
    explicit WorkerJoinGuard(std::vector<std::thread>& workers) : m_workers{workers}
    {
    }

    ~WorkerJoinGuard()
    {
        for (std::thread& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
    }

private:
    std::vector<std::thread>& m_workers;
};

template <typename Function>
bool ParallelFor(std::size_t count, Function&& function)
{
    std::atomic_size_t next{0};
    std::atomic_bool success{true};
    {
        std::vector<std::thread> workers;
        WorkerJoinGuard join_guard{workers};
        const std::size_t worker_count{
            std::min(count, TestWorkerCount())};
        workers.reserve(worker_count);
        for (std::size_t worker{0}; worker < worker_count; ++worker) {
            workers.emplace_back([&] {
                while (success.load(std::memory_order_relaxed)) {
                    const std::size_t index{
                        next.fetch_add(1, std::memory_order_relaxed)};
                    if (index >= count) return;
                    try {
                        if (!function(index)) {
                            success.store(false, std::memory_order_relaxed);
                        }
                    } catch (...) {
                        success.store(false, std::memory_order_relaxed);
                    }
                }
            });
        }
    }
    return success.load(std::memory_order_relaxed);
}

void FillKeySeed(std::size_t key_index,
                 scheduled_wots::KeyGenerationSeed& seed)
{
    const uint64_t seed_index{static_cast<uint64_t>(key_index) + 1};
    for (std::size_t byte{0}; byte < seed.size(); ++byte) {
        const unsigned int shift{static_cast<unsigned int>((byte % 8) * 8)};
        seed[byte] = static_cast<unsigned char>(
            (seed_index >> shift) ^ (0x5dU + 37U * byte));
    }
}

std::size_t ChildKeyIndex(uint32_t epoch, std::size_t member_index)
{
    return static_cast<std::size_t>(epoch) * QUORUM_MIN_VALID + member_index;
}

uint64_t AuthorizationDiscriminator(uint32_t epoch, std::size_t member_index)
{
    return (static_cast<uint64_t>(epoch) << 32) |
           static_cast<uint64_t>(member_index + 1);
}

struct FullDimensionFixture {
    uint256 genesis_hash{NonNullHash(90'001)};
    QuorumBuildConfig config{BuildConfig()};
    std::unique_ptr<IndexChain> chain{
        std::make_unique<IndexChain>(TARGET_HEIGHT)};
    std::vector<scheduled_wots::PublicKey> public_keys{
        CHILD_KEY_COUNT};
    std::vector<std::optional<scheduled_wots::SecretKey>> secret_keys{
        CHILD_KEY_COUNT};
    std::map<uint256, std::size_t> member_indices;
    FrozenQuorumRostersPtr rosters;
    ChainLockStatement statement;
    std::vector<ChainLockShare> shares;
};

std::optional<uint32_t> EpochForSnapshot(
    const FullDimensionFixture& fixture, int32_t snapshot_height)
{
    for (uint32_t epoch{0}; epoch <= ACTIVE_QUORUMS; ++epoch) {
        const auto expected{RegistrationCutoffHeight(
            fixture.config.schedule, epoch, SNAPSHOT_LAG)};
        if (expected && *expected == snapshot_height) return epoch;
    }
    return std::nullopt;
}

test::SyntheticChildAuthorization MakeAuthorization(
    const FullDimensionFixture& fixture, const uint256& pro_tx_hash,
    uint32_t epoch, std::size_t member_index)
{
    const std::size_t key_index{ChildKeyIndex(epoch, member_index)};
    return test::MakeSyntheticChildAuthorization(
        fixture.genesis_hash, pro_tx_hash, epoch,
        fixture.public_keys[key_index],
        AuthorizationDiscriminator(epoch, member_index));
}

OperatorKeyState MakeOperatorState(
    const FullDimensionFixture& fixture, const uint256& pro_tx_hash,
    uint32_t epoch, int32_t snapshot_height, std::size_t member_index)
{
    const auto view{DeriveOperatorKeyScheduleView(
        fixture.config.schedule, snapshot_height,
        fixture.config.registration_cutoff_blocks,
        fixture.config.future_horizon_epochs)};
    if (!view) return {};

    auto authorization{
        MakeAuthorization(fixture, pro_tx_hash, epoch, member_index)};
    const uint32_t key_version{epoch + 1};
    const std::size_t key_index{ChildKeyIndex(epoch, member_index)};
    authorization.record.global_key_version = key_version;

    OperatorKeyState state{OperatorKeyState::ForOperator(pro_tx_hash)};
    state.has_global_key = 1;
    state.global_key_active = 1;
    state.global_key.key_version = key_version;
    state.global_key.public_key[0] = 1;
    state.global_key.public_key[1] = static_cast<uint8_t>(key_index);
    state.global_key.public_key[2] = static_cast<uint8_t>(key_index >> 8);
    state.global_key.child_key_commitment =
        authorization.record.commitment;
    state.global_key.activated_height = 1;
    state.schedule_initialized = 1;
    state.schedule = OperatorKeyScheduleState::FromView(*view);
    state.frozen_child_roots.push_back(std::move(authorization.record));
    return state;
}

bool GenerateMemberKeys(FullDimensionFixture& fixture)
{
    for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
        fixture.member_indices.emplace(NonNullHash(10'000 + member), member);
    }
    return ParallelFor(CHILD_KEY_COUNT, [&](std::size_t key_index) {
        scheduled_wots::KeyGenerationSeed seed{};
        FillKeySeed(key_index, seed);
        auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
        memory_cleanse(seed.data(), seed.size());
        if (!secret_key ||
            !secret_key->GetPublicKey(fixture.public_keys[key_index])) {
            return false;
        }
        fixture.secret_keys[key_index] = std::move(*secret_key);
        return true;
    });
}

bool BuildRostersAndStatement(FullDimensionFixture& fixture)
{
    QuorumBuildError build_error{QuorumBuildError::NONE};
    fixture.rosters = BuildActiveFrozenQuorumRosters(
        fixture.genesis_hash, fixture.config, TARGET_HEIGHT,
        fixture.chain->Tip(),
        [&](const CBlockIndex& snapshot_index)
            -> std::optional<QuorumSnapshotState> {
            const auto epoch{
                EpochForSnapshot(fixture, snapshot_index.nHeight)};
            if (!epoch) return std::nullopt;

            QuorumSnapshotState snapshot_state;
            snapshot_state.deterministic_mns = Snapshot(
                snapshot_index.nHeight, snapshot_index.GetBlockHash());
            snapshot_state.operator_key_states.reserve(QUORUM_MIN_VALID);
            for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
                const uint256 pro_tx_hash{NonNullHash(10'000 + member)};
                auto state{MakeOperatorState(
                    fixture, pro_tx_hash, *epoch, snapshot_index.nHeight,
                    member)};
                if (!state.IsStructurallyValid()) return std::nullopt;
                snapshot_state.operator_key_states.push_back(
                    std::move(state));
            }
            return snapshot_state;
        },
        &build_error);
    if (!fixture.rosters || build_error != QuorumBuildError::NONE) {
        return false;
    }

    for (const auto& roster : *fixture.rosters) {
        if (roster.descriptor.valid_count != QUORUM_MIN_VALID ||
            CountSet(roster.descriptor.valid_members) != QUORUM_MIN_VALID ||
            std::count_if(
                roster.members.begin(), roster.members.end(),
                [](const FrozenQuorumMember& member) {
                    return !member.pro_tx_hash.IsNull();
                }) != static_cast<std::ptrdiff_t>(QUORUM_SIZE) ||
            std::count_if(
                roster.members.begin(), roster.members.end(),
                [](const FrozenQuorumMember& member) {
                    return member.eligible && member.child_root.has_value();
                }) != static_cast<std::ptrdiff_t>(QUORUM_MIN_VALID)) {
            return false;
        }
    }

    fixture.statement.height = TARGET_HEIGHT;
    fixture.statement.block_hash = fixture.chain->Tip().GetBlockHash();
    fixture.statement.previous_chainlock_height =
        PREVIOUS_CHAINLOCK_HEIGHT;
    fixture.statement.previous_chainlock_hash = NonNullHash(90'002);
    fixture.statement.payment_probation_state_hash = NonNullHash(90'003);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = (*fixture.rosters)[slot].descriptor;
    }
    fixture.statement.quorum_context_hash = GetQuorumContextHash(
        fixture.genesis_hash, fixture.statement.height,
        fixture.statement.block_hash, descriptors);
    return fixture.statement.IsStructurallyValid() &&
           ValidateFrozenQuorumContext(
               fixture.genesis_hash, fixture.statement, *fixture.rosters,
               AUTHORIZATION_MASK);
}

bool BuildAndSignShares(FullDimensionFixture& fixture)
{
    struct SignerPosition {
        std::size_t quorum_slot{0};
        uint16_t member_index{0};
        std::size_t operator_index{0};
        std::size_t key_index{0};
    };

    auto positions{std::make_unique<std::vector<SignerPosition>>()};
    positions->reserve(FINAL_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        std::size_t selected{0};
        const auto& roster{(*fixture.rosters)[slot]};
        for (std::size_t member{0};
             member < QUORUM_SIZE && selected < QUORUM_THRESHOLD;
            ++member) {
            const auto member_position{fixture.member_indices.find(
                roster.members[member].pro_tx_hash)};
            if (member_position == fixture.member_indices.end() ||
                !roster.members[member].eligible ||
                !roster.members[member].child_root) {
                continue;
            }
            positions->push_back(SignerPosition{
                slot, static_cast<uint16_t>(member),
                member_position->second,
                ChildKeyIndex(roster.descriptor.epoch,
                              member_position->second)});
            ++selected;
        }
        if (selected != QUORUM_THRESHOLD) return false;
    }
    if (positions->size() != FINAL_SIGNATURE_COUNT) return false;

    fixture.shares.resize(FINAL_SIGNATURE_COUNT);
    FinalChainLock shell;
    shell.statement = fixture.statement;
    return ParallelFor(FINAL_SIGNATURE_COUNT, [&](std::size_t index) {
        const auto& position{(*positions)[index]};
        const auto& roster{(*fixture.rosters)[position.quorum_slot]};
        const auto& member{roster.members[position.member_index]};
        auto& share{fixture.shares[index]};
        share.transcript = BuildChainLockShareTranscript(
            shell, roster.descriptor, position.member_index,
            member.pro_tx_hash);
        auto authorization{MakeAuthorization(
            fixture, member.pro_tx_hash, roster.descriptor.epoch,
            position.operator_index)};
        authorization.record.global_key_version =
            roster.descriptor.epoch + 1;
        if (!member.child_root ||
            *member.child_root != authorization.record) {
            return false;
        }
        share.authenticated_signature.key_proof =
            std::move(authorization.proof);

        const uint256 share_hash{GetChainLockShareHash(
            fixture.genesis_hash, share.transcript)};
        scheduled_wots::Message message;
        std::copy(share_hash.begin(), share_hash.end(), message.begin());
        const auto leaf_index{ChainLockLeafIndex(
            fixture.config.schedule, roster.descriptor.epoch,
            fixture.statement.height)};
        return leaf_index && fixture.secret_keys[position.key_index] &&
            scheduled_wots::SignDeterministic(
            *fixture.secret_keys[position.key_index], *leaf_index, message,
            share.authenticated_signature.signature);
    });
}

std::optional<PaymentAuditStatement> BuildPaymentAuditStatement(
    const FullDimensionFixture& fixture, const FinalChainLock& seal)
{
    if (!fixture.rosters || !seal.IsStructurallyValid()) {
        return std::nullopt;
    }
    const auto& subject{
        (*fixture.rosters)[REQUIRED_QUORUMS - 1].descriptor};
    const PaymentAuditScheduleConfig schedule{
        fixture.config.schedule,
        BTCCScheduleConfig{.candidate_origin = BTCC_CANDIDATE_ORIGIN}};
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(schedule, subject.epoch)};
    if (!audit_schedule || audit_schedule->seal_height != seal.statement.height) {
        return std::nullopt;
    }
    PaymentAuditCommitment commitment;
    commitment.seed.epoch = subject.epoch;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        audit_schedule->anchor_height, NonNullHash(91'001),
        BTCCursor{audit_schedule->anchor_height, NonNullHash(91'002),
                  NonNullHash(91'003)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(91'004);
    commitment.selected_row = 0;
    commitment.response_height = audit_schedule->rows[0].response_height;
    commitment.deadline_height = audit_schedule->rows[0].deadline_height;
    commitment.response_chainlock_logical_id = NonNullHash(91'004);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = seal.statement.height;
    commitment.subject_epoch = subject.epoch;
    commitment.subject_quorum_base_hash = subject.base_hash;
    commitment.subject_descriptor_hash =
        GetPaymentAuditDescriptorHash(fixture.genesis_hash, subject);
    commitment.subject_valid_members = subject.valid_members;
    commitment.previous_probation_state_hash =
        seal.statement.payment_probation_state_hash;

    PaymentAuditStatement statement{commitment, seal.statement};
    if (!statement.IsStructurallyValid()) return std::nullopt;
    return statement;
}

bool BuildAndSignPaymentAuditShares(
    const FullDimensionFixture& fixture,
    const PaymentAuditStatement& statement,
    std::vector<PaymentAuditShare>& shares)
{
    if (!fixture.rosters || !statement.IsStructurallyValid()) return false;
    shares.clear();
    shares.resize(PAYMENT_AUDIT_SIGNATURE_COUNT);

    struct SignerPosition {
        std::size_t quorum_slot{0};
        uint16_t member_index{0};
        std::size_t operator_index{0};
        std::size_t key_index{0};
    };
    auto positions{std::make_unique<std::vector<SignerPosition>>()};
    positions->reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        std::size_t selected{0};
        const auto& roster{(*fixture.rosters)[slot]};
        for (std::size_t member{0};
             member < QUORUM_SIZE && selected < QUORUM_THRESHOLD;
             ++member) {
            const auto position{fixture.member_indices.find(
                roster.members[member].pro_tx_hash)};
            if (position == fixture.member_indices.end() ||
                !roster.members[member].eligible ||
                !roster.members[member].child_root) {
                continue;
            }
            positions->push_back(SignerPosition{
                slot, static_cast<uint16_t>(member), position->second,
                ChildKeyIndex(roster.descriptor.epoch,
                              position->second)});
            ++selected;
        }
        if (selected != QUORUM_THRESHOLD) return false;
    }
    if (positions->size() != PAYMENT_AUDIT_SIGNATURE_COUNT) return false;

    return ParallelFor(PAYMENT_AUDIT_SIGNATURE_COUNT,
                       [&](std::size_t index) {
        const auto& position{(*positions)[index]};
        const auto& roster{(*fixture.rosters)[position.quorum_slot]};
        const auto& member{roster.members[position.member_index]};
        auto& share{shares[index]};
        share.transcript = BuildPaymentAuditShareTranscript(
            statement, statement.commitment.subject_valid_members,
            roster.descriptor, position.member_index,
            member.pro_tx_hash);
        auto authorization{MakeAuthorization(
            fixture, member.pro_tx_hash, roster.descriptor.epoch,
            position.operator_index)};
        authorization.record.global_key_version =
            roster.descriptor.epoch + 1;
        if (!member.child_root ||
            *member.child_root != authorization.record) {
            return false;
        }
        share.authenticated_signature.key_proof =
            std::move(authorization.proof);

        const uint256 share_hash{GetPaymentAuditShareHash(
            fixture.genesis_hash, share.transcript)};
        scheduled_wots::Message message;
        std::copy(share_hash.begin(), share_hash.end(), message.begin());
        const PaymentAuditScheduleConfig schedule{
            fixture.config.schedule,
            BTCCScheduleConfig{.candidate_origin = BTCC_CANDIDATE_ORIGIN}};
        const auto leaf_index{PaymentAuditLeafIndex(
            schedule, statement.commitment.subject_epoch,
            statement.commitment.seal_height, roster.descriptor.epoch)};
        return leaf_index && fixture.secret_keys[position.key_index] &&
            scheduled_wots::SignDeterministic(
            *fixture.secret_keys[position.key_index], *leaf_index, message,
            share.authenticated_signature.signature);
    });
}

std::unique_ptr<FullDimensionFixture> MakeFullDimensionFixture()
{
    auto fixture{std::make_unique<FullDimensionFixture>()};
    if (!GenerateMemberKeys(*fixture) ||
        !BuildRostersAndStatement(*fixture) ||
        !BuildAndSignShares(*fixture)) {
        return nullptr;
    }
    return fixture;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_integration_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(full_dimension_builder_collector_wire_and_verifier)
{
    auto fixture{MakeFullDimensionFixture()};
    BOOST_REQUIRE(fixture);
    BOOST_REQUIRE(fixture->rosters);
    BOOST_REQUIRE_EQUAL(fixture->shares.size(), FINAL_SIGNATURE_COUNT);

    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->config.schedule,
        fixture->statement, fixture->rosters,
        AUTHORIZATION_MASK,
        &collection_error)};
    BOOST_REQUIRE(collector);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);

    // Deliver every non-completing share in reverse order so finalization must
    // derive canonical slot/member order rather than preserving arrival order.
    for (std::size_t arrival{FINAL_SIGNATURE_COUNT - 1}; arrival > 0;
         --arrival) {
        const std::size_t index{arrival - 1};
        BOOST_REQUIRE(
            collector->AddVerifiedShare(
                fixture->shares[index], &collection_error) ==
            ShareCollectionResult::ACCEPTED);
        BOOST_REQUIRE(collection_error == ShareCollectionError::NONE);
    }
    BOOST_CHECK(!collector->IsComplete());
    BOOST_CHECK(!collector->Finalize());
    const auto incomplete_counts{collector->ShareCounts()};
    BOOST_CHECK_EQUAL(incomplete_counts[0], QUORUM_THRESHOLD);
    BOOST_CHECK_EQUAL(incomplete_counts[1], QUORUM_THRESHOLD);
    BOOST_CHECK_EQUAL(incomplete_counts[2], QUORUM_THRESHOLD - 1);
    BOOST_CHECK_EQUAL(incomplete_counts[3], 0U);

    BOOST_REQUIRE(
        collector->AddVerifiedShare(
            fixture->shares.back(), &collection_error) ==
        ShareCollectionResult::ACCEPTED);
    BOOST_REQUIRE(collection_error == ShareCollectionError::NONE);
    BOOST_REQUIRE(collector->IsComplete());

    const auto final{collector->Finalize()};
    BOOST_REQUIRE(final);
    BOOST_REQUIRE(final->IsStructurallyValid());
    BOOST_CHECK_EQUAL(final->selected_quorum_mask, 0b0111);
    BOOST_CHECK_EQUAL(final->signatures.size(), FINAL_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        BOOST_CHECK_EQUAL(
            CountSet(final->signer_bitmaps[slot]), QUORUM_THRESHOLD);
    }
    BOOST_CHECK_EQUAL(CountSet(final->signer_bitmaps[3]), 0U);
    for (std::size_t index{0}; index < FINAL_SIGNATURE_COUNT; ++index) {
        BOOST_CHECK(
            final->signatures[index] ==
            fixture->shares[index].authenticated_signature);
    }

    DataStream encoded;
    encoded << *final;
    BOOST_REQUIRE_EQUAL(encoded.size(), FinalChainLock::WIRE_SIZE);
    auto decoded{ReadFinalChainLock(encoded, FinalChainLock::WIRE_SIZE)};
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK(decoded == *final);

    ChainLockVerificationError verification_error{
        ChainLockVerificationError::NONE};
    ChainLockVerifier verifier{/*worker_threads=*/TestWorkerCount()};
    BOOST_CHECK(verifier.Verify(
        fixture->genesis_hash, fixture->config.schedule, decoded,
        *fixture->rosters,
        AUTHORIZATION_MASK,
        &verification_error));
    BOOST_CHECK(verification_error == ChainLockVerificationError::NONE);

    const auto expected_audit_schedule{BuildPaymentAuditEpochSchedule(
        PaymentAuditScheduleConfig{
            fixture->config.schedule,
            BTCCScheduleConfig{.candidate_origin = BTCC_CANDIDATE_ORIGIN}},
        (*fixture->rosters)[REQUIRED_QUORUMS - 1].descriptor.epoch)};
    BOOST_REQUIRE(expected_audit_schedule);
    BOOST_REQUIRE_EQUAL(
        expected_audit_schedule->seal_height, final->statement.height);
    const auto audit_statement{
        BuildPaymentAuditStatement(*fixture, *final)};
    BOOST_REQUIRE(audit_statement);
    std::vector<PaymentAuditShare> audit_shares;
    BOOST_REQUIRE(BuildAndSignPaymentAuditShares(
        *fixture, *audit_statement, audit_shares));
    BOOST_REQUIRE_EQUAL(audit_shares.size(),
                        PAYMENT_AUDIT_SIGNATURE_COUNT);

    auto audit_collector{PaymentAuditCollector::Create(
        fixture->genesis_hash,
        PaymentAuditScheduleConfig{
            fixture->config.schedule,
            BTCCScheduleConfig{.candidate_origin = BTCC_CANDIDATE_ORIGIN}},
        *audit_statement, *final,
        fixture->rosters, AUTHORIZATION_MASK, &collection_error)};
    BOOST_REQUIRE(audit_collector);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
    for (std::size_t arrival{PAYMENT_AUDIT_SIGNATURE_COUNT - 1};
         arrival > 0; --arrival) {
        const std::size_t index{arrival - 1};
        BOOST_REQUIRE(
            audit_collector->AddVerifiedShare(
                audit_shares[index], &collection_error) ==
            ShareCollectionResult::ACCEPTED);
        BOOST_REQUIRE(collection_error == ShareCollectionError::NONE);
    }
    BOOST_CHECK(!audit_collector->IsComplete());
    BOOST_CHECK(!audit_collector->Finalize());
    const auto incomplete_audit_counts{audit_collector->ShareCounts()};
    BOOST_CHECK_EQUAL(incomplete_audit_counts[0], QUORUM_THRESHOLD);
    BOOST_CHECK_EQUAL(incomplete_audit_counts[1], QUORUM_THRESHOLD);
    BOOST_CHECK_EQUAL(incomplete_audit_counts[2],
                      QUORUM_THRESHOLD - 1);
    BOOST_CHECK_EQUAL(incomplete_audit_counts[3], 0U);

    BOOST_REQUIRE(
        audit_collector->AddVerifiedShare(
            audit_shares.back(), &collection_error) ==
        ShareCollectionResult::ACCEPTED);
    BOOST_REQUIRE(collection_error == ShareCollectionError::NONE);
    const auto final_audit{audit_collector->Finalize()};
    BOOST_REQUIRE(final_audit);
    BOOST_REQUIRE(final_audit->IsStructurallyValid());
    BOOST_CHECK_EQUAL(final_audit->selected_quorum_mask, 0b0111);
    BOOST_CHECK_EQUAL(final_audit->report_witnesses.size(),
                      PAYMENT_AUDIT_SIGNATURE_COUNT);

    DataStream encoded_audit;
    encoded_audit << *final_audit;
    BOOST_REQUIRE_EQUAL(encoded_audit.size(),
                        FinalPaymentAudit::WIRE_SIZE);
    FinalPaymentAudit decoded_audit;
    encoded_audit >> decoded_audit;
    BOOST_CHECK(encoded_audit.empty());
    BOOST_CHECK(decoded_audit == *final_audit);

    PaymentAuditVerificationError audit_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    BOOST_CHECK(VerifyFinalPaymentAudit(
        fixture->genesis_hash,
        PaymentAuditScheduleConfig{
            fixture->config.schedule,
            BTCCScheduleConfig{.candidate_origin = BTCC_CANDIDATE_ORIGIN}},
        decoded_audit, *fixture->rosters,
        AUTHORIZATION_MASK, nullptr, &audit_error));
    BOOST_CHECK(audit_error == PaymentAuditVerificationError::NONE);
}

BOOST_AUTO_TEST_SUITE_END()
