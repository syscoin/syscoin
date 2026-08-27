// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_chainlock_test_fixture.h>
#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_quorum_builder.h>
#include <llmq/pq_signer_journal.h>

#include <chain.h>
#include <evo/pq_payment_probation.h>
#include <hash.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <test/pq_test_util.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using namespace llmq::pq;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

namespace {

constexpr std::size_t MAX_TEST_WORKERS{8};
constexpr uint8_t AUTHORIZATION_MASK{0b0111};
constexpr std::size_t MAX_FIXTURE_EPOCHS{5};
constexpr std::size_t CHILD_KEY_COUNT{
    MAX_FIXTURE_EPOCHS * QUORUM_MIN_VALID};
constexpr uint64_t SHARE_BUNDLE_MAGIC{0x315246534c435150ULL};
constexpr uint16_t SHARE_BUNDLE_VERSION{1};
constexpr std::size_t MAX_SHARE_BUNDLE_BYTES{8U << 20};
constexpr std::string_view SHARE_BUNDLE_CHECKSUM_DOMAIN{
    "SYS_PQ_CHAINLOCK_SHARE_FIXTURE_V1"};
constexpr uint64_t PAYMENT_AUDIT_BUNDLE_MAGIC{0x3154414550505153ULL};
constexpr uint16_t PAYMENT_AUDIT_BUNDLE_VERSION{1};
constexpr std::size_t MAX_PAYMENT_AUDIT_BUNDLE_BYTES{24U << 20};
constexpr std::string_view PAYMENT_AUDIT_BUNDLE_CHECKSUM_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_FUNCTIONAL_FIXTURE_V1"};
constexpr uint64_t PAYMENT_AUDIT_PREFIX_BUNDLE_MAGIC{0x3158465250505153ULL};
constexpr uint16_t PAYMENT_AUDIT_PREFIX_BUNDLE_VERSION{1};
constexpr std::size_t MAX_PAYMENT_AUDIT_PREFIX_BUNDLE_BYTES{8U << 20};
constexpr std::string_view PAYMENT_AUDIT_PREFIX_BUNDLE_CHECKSUM_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_PREFIX_FUNCTIONAL_FIXTURE_V1"};
constexpr uint64_t POST_CHAINLOCK_BUNDLE_MAGIC{0x3154534f50435153ULL};
constexpr uint16_t POST_CHAINLOCK_BUNDLE_VERSION{1};
constexpr std::string_view POST_CHAINLOCK_BUNDLE_CHECKSUM_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_POST_CHAINLOCK_V1"};

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
    std::map<int32_t, uint256> exact_hashes;

    explicit IndexChain(int32_t tip_height)
        : hashes(static_cast<std::size_t>(tip_height) + 1),
          indices(static_cast<std::size_t>(tip_height) + 1)
    {
        if (tip_height < 0) {
            throw std::invalid_argument("negative fixture target height");
        }
        for (int32_t height{0}; height <= tip_height; ++height) {
            hashes[height] = NonNullHash(static_cast<uint64_t>(height) + 1);
            indices[height].nHeight = height;
            indices[height].phashBlock = &hashes[height];
            indices[height].pprev =
                height == 0 ? nullptr : &indices[height - 1];
            indices[height].BuildSkip();
        }
    }

    bool SetExactHash(int32_t height, const uint256& hash)
    {
        if (height < 0 ||
            static_cast<std::size_t>(height) >= hashes.size() ||
            hash.IsNull()) {
            return false;
        }
        const auto [it, inserted]{exact_hashes.emplace(height, hash)};
        if (!inserted && it->second != hash) return false;
        hashes[height] = hash;
        return true;
    }

    const CBlockIndex& Tip() const { return indices.back(); }
};

std::size_t WorkerCount()
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
        const std::size_t worker_count{std::min(count, WorkerCount())};
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

std::size_t ChildKeyIndex(uint32_t epoch,
                          std::size_t member_index)
{
    return static_cast<std::size_t>(epoch) * QUORUM_MIN_VALID +
           member_index;
}

uint64_t AuthorizationDiscriminator(uint32_t epoch,
                                    std::size_t member_index)
{
    return (static_cast<uint64_t>(epoch) << 32) |
           static_cast<uint64_t>(member_index + 1);
}

struct GeneratorArguments {
    fs::path snapshot_output;
    fs::path shares_output;
    uint256 genesis_hash;
    int32_t target_height{-1};
    uint256 target_hash;
    int32_t predecessor_height{-1};
    uint256 predecessor_hash;
    QuorumBuildConfig build_config;
    std::array<uint256, ACTIVE_QUORUMS> base_hashes;
    std::array<uint256, ACTIVE_QUORUMS> snapshot_hashes;
};

struct FullDimensionFixture {
    explicit FullDimensionFixture(GeneratorArguments arguments)
        : args{std::move(arguments)}, chain{args.target_height},
          public_keys(CHILD_KEY_COUNT), secret_keys(CHILD_KEY_COUNT)
    {
        snapshot_fixture.genesis_hash = args.genesis_hash;
        snapshot_fixture.build_config = args.build_config;
        snapshot_fixture.branch_anchor = IsEligibleChainLockTarget(
                args.build_config.schedule, args.predecessor_height)
            ? test::FixtureBranchPoint{
                  args.predecessor_height, args.predecessor_hash}
            : test::FixtureBranchPoint{
                  args.target_height, args.target_hash};
        snapshot_fixture.max_active_tip_height =
            args.target_height +
            static_cast<int32_t>(args.build_config.schedule.sign_lag) +
            static_cast<int32_t>(
                args.build_config.schedule.chainlock_period);
        snapshot_fixture.quorum_bases.resize(ACTIVE_QUORUMS);
        snapshot_fixture.snapshots.resize(ACTIVE_QUORUMS);
    }

    GeneratorArguments args;
    IndexChain chain;
    std::vector<scheduled_wots::PublicKey> public_keys;
    std::vector<std::optional<scheduled_wots::SecretKey>> secret_keys;
    std::map<uint256, std::size_t> member_indices;
    test::QuorumSnapshotFixture snapshot_fixture;
    FrozenQuorumRostersPtr rosters;
    ChainLockStatement statement;
    std::vector<ChainLockShare> shares;
};

struct PaymentAuditArguments {
    fs::path snapshot_output;
    fs::path bundle_output;
    uint256 genesis_hash;
    int32_t branch_anchor_height{-1};
    uint256 branch_anchor_hash;
    int32_t response_predecessor_height{-1};
    uint256 response_predecessor_hash;
    int32_t anchor_predecessor_height{-1};
    uint256 anchor_predecessor_hash;
    int32_t seal_predecessor_height{-1};
    uint256 seal_predecessor_hash;
    QuorumBuildConfig build_config;
    BTCCScheduleConfig btcc_config;
    uint32_t audit_epoch{0};
    uint256 response_hash;
    uint256 response_btc_hash;
    uint256 anchor_hash;
    uint256 anchor_btc_hash;
    uint256 seal_hash;
    uint256 seed_carrier_hash;
    BTCCReceipt seed_receipt;
    std::array<uint256, MAX_FIXTURE_EPOCHS> base_hashes;
    std::array<uint256, MAX_FIXTURE_EPOCHS> snapshot_hashes;
};

struct PaymentAuditFixture {
    explicit PaymentAuditFixture(PaymentAuditArguments arguments,
                                 int32_t tip_height,
                                 std::size_t epoch_count = MAX_FIXTURE_EPOCHS)
        : args{std::move(arguments)}, chain{tip_height},
          public_keys(CHILD_KEY_COUNT), secret_keys(CHILD_KEY_COUNT)
    {
        snapshot_fixture.genesis_hash = args.genesis_hash;
        snapshot_fixture.build_config = args.build_config;
        snapshot_fixture.branch_anchor = {
            args.branch_anchor_height, args.branch_anchor_hash};
        snapshot_fixture.max_active_tip_height = tip_height;
        snapshot_fixture.quorum_bases.resize(epoch_count);
        snapshot_fixture.snapshots.resize(epoch_count);
    }

    PaymentAuditArguments args;
    IndexChain chain;
    std::vector<scheduled_wots::PublicKey> public_keys;
    std::vector<std::optional<scheduled_wots::SecretKey>> secret_keys;
    std::map<uint256, std::size_t> member_indices;
    test::QuorumSnapshotFixture snapshot_fixture;
};

struct PaymentAuditPostArguments {
    fs::path bundle_output;
    uint256 genesis_hash;
    int32_t target_height{-1};
    uint256 target_hash;
    int32_t predecessor_height{-1};
    uint256 predecessor_hash;
    BTCCursor cursor;
    QuorumBuildConfig build_config;
    BTCCScheduleConfig btcc_config;
    BTCCReceiptState btcc_receipt_state;
    PaymentAuditReceiptState payment_audit_receipt_state;
    uint256 payment_probation_state_hash;
    std::array<uint256, MAX_FIXTURE_EPOCHS> base_hashes;
    std::array<uint256, MAX_FIXTURE_EPOCHS> snapshot_hashes;
};

test::SyntheticChildAuthorization MakeAuthorization(
    const uint256& genesis_hash,
    const std::vector<scheduled_wots::PublicKey>& public_keys,
    const uint256& pro_tx_hash,
    uint32_t epoch,
    std::size_t member_index)
{
    const std::size_t key_index{ChildKeyIndex(epoch, member_index)};
    return test::MakeSyntheticChildAuthorization(
        genesis_hash, pro_tx_hash, epoch,
        public_keys.at(key_index),
        AuthorizationDiscriminator(epoch, member_index));
}

OperatorKeyState MakeOperatorState(
    const uint256& genesis_hash,
    const QuorumBuildConfig& build_config,
    const std::vector<scheduled_wots::PublicKey>& public_keys,
    const uint256& pro_tx_hash,
    uint32_t epoch,
    int32_t snapshot_height,
    std::size_t member_index)
{
    const auto view{DeriveOperatorKeyScheduleView(
        build_config.schedule, snapshot_height,
        build_config.registration_cutoff_blocks,
        build_config.future_horizon_epochs)};
    if (!view) return {};

    auto authorization{MakeAuthorization(
        genesis_hash, public_keys, pro_tx_hash, epoch, member_index)};
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

bool GenerateMemberKeys(
    std::vector<scheduled_wots::PublicKey>& public_keys,
    std::vector<std::optional<scheduled_wots::SecretKey>>& secret_keys,
    std::map<uint256, std::size_t>& member_indices)
{
    if (public_keys.size() != CHILD_KEY_COUNT ||
        secret_keys.size() != CHILD_KEY_COUNT) {
        return false;
    }
    for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
        member_indices.emplace(NonNullHash(10'000 + member), member);
    }
    return ParallelFor(CHILD_KEY_COUNT, [&](std::size_t key_index) {
        scheduled_wots::KeyGenerationSeed seed{};
        FillKeySeed(key_index, seed);
        auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
        memory_cleanse(seed.data(), seed.size());
        if (!secret_key ||
            !secret_key->GetPublicKey(public_keys[key_index])) {
            return false;
        }
        secret_keys[key_index] = std::move(*secret_key);
        return true;
    });
}

bool GenerateMemberKeys(FullDimensionFixture& fixture)
{
    return GenerateMemberKeys(fixture.public_keys, fixture.secret_keys,
                              fixture.member_indices);
}

bool IsBitSetLocal(const QuorumBitmap& bitmap, std::size_t member)
{
    return member < QUORUM_SIZE &&
           (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

void ClearBitLocal(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] &=
        static_cast<uint8_t>(~(uint8_t{1} << (member % 8)));
}

bool PopulatePaymentAuditSnapshots(PaymentAuditFixture& fixture)
{
    if (!fixture.chain.SetExactHash(fixture.args.branch_anchor_height,
                                    fixture.args.branch_anchor_hash)) {
        return false;
    }
    if (fixture.snapshot_fixture.quorum_bases.size() !=
            fixture.snapshot_fixture.snapshots.size() ||
        fixture.snapshot_fixture.quorum_bases.size() < ACTIVE_QUORUMS ||
        fixture.snapshot_fixture.quorum_bases.size() > MAX_FIXTURE_EPOCHS) {
        return false;
    }
    for (uint32_t epoch{0};
         epoch < fixture.snapshot_fixture.quorum_bases.size(); ++epoch) {
        const auto base_height{EpochBaseHeight(
            fixture.args.build_config.schedule, epoch)};
        const auto snapshot_height{RegistrationCutoffHeight(
            fixture.args.build_config.schedule, epoch,
            fixture.args.build_config.roster_snapshot_lag_blocks)};
        if (!base_height || !snapshot_height ||
            !fixture.chain.SetExactHash(
                *base_height, fixture.args.base_hashes[epoch]) ||
            !fixture.chain.SetExactHash(
                *snapshot_height, fixture.args.snapshot_hashes[epoch])) {
            return false;
        }
        fixture.snapshot_fixture.quorum_bases[epoch] = {
            *base_height, fixture.args.base_hashes[epoch]};
        auto& snapshot{fixture.snapshot_fixture.snapshots[epoch]};
        snapshot.branch_point = {
            *snapshot_height, fixture.args.snapshot_hashes[epoch]};
        snapshot.state.deterministic_mns = Snapshot(
            *snapshot_height, fixture.args.snapshot_hashes[epoch]);
        auto operator_states{
            std::make_shared<std::vector<OperatorKeyState>>()};
        operator_states->reserve(QUORUM_MIN_VALID);
        for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
            const uint256 pro_tx_hash{NonNullHash(10'000 + member)};
            auto state{MakeOperatorState(
                fixture.args.genesis_hash, fixture.args.build_config,
                fixture.public_keys, pro_tx_hash, epoch,
                *snapshot_height, member)};
            if (!state.IsStructurallyValid()) return false;
            operator_states->push_back(std::move(state));
        }
        snapshot.state.operator_key_states = std::move(operator_states);
    }
    return true;
}

std::optional<QuorumSnapshotState> LookupPaymentAuditSnapshot(
    const PaymentAuditFixture& fixture, const CBlockIndex& index)
{
    for (const auto& snapshot : fixture.snapshot_fixture.snapshots) {
        if (snapshot.branch_point.height == index.nHeight &&
            snapshot.branch_point.block_hash == index.GetBlockHash()) {
            return snapshot.state;
        }
    }
    return std::nullopt;
}

FrozenQuorumRostersPtr BuildPaymentAuditRosters(
    const PaymentAuditFixture& fixture, int32_t target_height)
{
    QuorumBuildError build_error{QuorumBuildError::NONE};
    const auto rosters{BuildActiveFrozenQuorumRosters(
        fixture.args.genesis_hash, fixture.args.build_config,
        target_height, fixture.chain.Tip(),
        [&](const CBlockIndex& index) {
            return LookupPaymentAuditSnapshot(fixture, index);
        },
        &build_error)};
    return build_error == QuorumBuildError::NONE ? rosters : nullptr;
}

std::array<QuorumDescriptor, ACTIVE_QUORUMS> Descriptors(
    const FrozenQuorumRosters& rosters)
{
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = rosters[slot].descriptor;
    }
    return descriptors;
}

std::optional<ChainLockStatement> MakeChainLockStatement(
    const PaymentAuditFixture& fixture,
    const FrozenQuorumRosters& rosters,
    int32_t height,
    const uint256& block_hash,
    int32_t predecessor_height,
    const uint256& predecessor_hash,
    const BTCCursor& previous_cursor,
    const BTCCursor& accepted_cursor,
    BTCCAdvance advance,
    const BTCCReceiptState& btcc_receipt_state,
    const PaymentAuditReceiptState& payment_receipt_state,
    const uint256& probation_state_hash)
{
    const auto next_target{NextEligibleChainLockTargetHeight(
        fixture.args.build_config.schedule, predecessor_height)};
    if (!next_target || *next_target != height) return std::nullopt;

    ChainLockStatement statement;
    statement.height = height;
    statement.block_hash = block_hash;
    statement.previous_chainlock_height = predecessor_height;
    statement.previous_chainlock_hash = predecessor_hash;
    statement.previous_btcc_cursor = previous_cursor;
    statement.accepted_btcc_cursor = accepted_cursor;
    statement.btcc_advance = advance;
    statement.btcc_receipt_state = btcc_receipt_state;
    statement.payment_audit_receipt_state = payment_receipt_state;
    statement.payment_probation_state_hash = probation_state_hash;
    statement.quorum_context_hash = GetQuorumContextHash(
        fixture.args.genesis_hash, height, block_hash,
        Descriptors(rosters));
    if (!statement.IsStructurallyValid() ||
        !ValidateFrozenQuorumContext(
            fixture.args.genesis_hash, statement, rosters,
            AUTHORIZATION_MASK)) {
        return std::nullopt;
    }
    return statement;
}

struct ChainLockSignerPosition {
    std::size_t quorum_slot{0};
    uint16_t member_index{0};
    std::size_t operator_index{0};
    std::size_t key_index{0};
};

std::optional<std::vector<ChainLockSignerPosition>> SelectSignerPositions(
    const FrozenQuorumRosters& rosters,
    const std::map<uint256, std::size_t>& member_indices)
{
    std::vector<ChainLockSignerPosition> positions;
    positions.reserve(FINAL_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        std::size_t selected{0};
        const auto& roster{rosters[slot]};
        for (std::size_t member{0};
             member < QUORUM_SIZE && selected < QUORUM_THRESHOLD;
             ++member) {
            const auto found{
                member_indices.find(roster.members[member].pro_tx_hash)};
            if (found == member_indices.end() ||
                !roster.members[member].eligible ||
                !roster.members[member].child_root) {
                continue;
            }
            positions.push_back(ChainLockSignerPosition{
                slot, static_cast<uint16_t>(member), found->second,
                ChildKeyIndex(roster.descriptor.epoch, found->second)});
            ++selected;
        }
        if (selected != QUORUM_THRESHOLD) return std::nullopt;
    }
    return positions.size() == FINAL_SIGNATURE_COUNT
               ? std::optional<std::vector<ChainLockSignerPosition>>{
                     std::move(positions)}
               : std::nullopt;
}

std::optional<FinalChainLock> SignAndVerifyChainLock(
    const PaymentAuditFixture& fixture,
    const ChainLockStatement& statement,
    FrozenQuorumRostersPtr rosters)
{
    if (!rosters) return std::nullopt;
    const auto positions{SelectSignerPositions(
        *rosters, fixture.member_indices)};
    if (!positions) return std::nullopt;

    std::vector<ChainLockShare> shares(FINAL_SIGNATURE_COUNT);
    FinalChainLock shell;
    shell.statement = statement;
    if (!ParallelFor(FINAL_SIGNATURE_COUNT, [&](std::size_t index) {
            const auto& position{(*positions)[index]};
            const auto& roster{(*rosters)[position.quorum_slot]};
            const auto& member{roster.members[position.member_index]};
            auto& share{shares[index]};
            share.transcript = BuildChainLockShareTranscript(
                shell, roster.descriptor, position.member_index,
                member.pro_tx_hash);
            auto authorization{MakeAuthorization(
                fixture.args.genesis_hash, fixture.public_keys,
                member.pro_tx_hash, roster.descriptor.epoch,
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
                fixture.args.genesis_hash, share.transcript)};
            scheduled_wots::Message message;
            std::copy(share_hash.begin(), share_hash.end(), message.begin());
            const auto leaf_index{ChainLockLeafIndex(
                fixture.args.build_config.schedule,
                roster.descriptor.epoch, statement.height)};
            return leaf_index && fixture.secret_keys[position.key_index] &&
                scheduled_wots::SignDeterministic(
                *fixture.secret_keys[position.key_index], *leaf_index, message,
                share.authenticated_signature.signature);
        })) {
        return std::nullopt;
    }

    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{ChainLockCollector::Create(
        fixture.args.genesis_hash, fixture.args.build_config.schedule,
        statement, rosters,
        AUTHORIZATION_MASK, &collection_error)};
    if (!collector) return std::nullopt;
    for (const auto& share : shares) {
        if (collector->AddVerifiedShare(share, &collection_error) !=
                ShareCollectionResult::ACCEPTED ||
            collection_error != ShareCollectionError::NONE) {
            return std::nullopt;
        }
    }
    const auto finalized{collector->FinalizeCollection()};
    if (!finalized) return std::nullopt;
    const auto& final{finalized->Certificate()};
    ChainLockVerificationError verification_error{
        ChainLockVerificationError::NONE};
    ChainLockVerifier verifier{WorkerCount()};
    if (!verifier.Verify(fixture.args.genesis_hash,
                         fixture.args.build_config.schedule,
                         final, *rosters,
                         AUTHORIZATION_MASK,
                         &verification_error) ||
        verification_error != ChainLockVerificationError::NONE) {
        return std::nullopt;
    }
    return final;
}

std::optional<FinalPaymentAudit> SignAndVerifyPaymentAudit(
    const PaymentAuditFixture& fixture,
    const PaymentAuditStatement& statement,
    const FinalChainLock& seal_chainlock,
    FrozenQuorumRostersPtr rosters,
    const QuorumBitmap& observed_members)
{
    if (!rosters) return std::nullopt;
    const auto positions{SelectSignerPositions(
        *rosters, fixture.member_indices)};
    if (!positions) return std::nullopt;

    std::vector<PaymentAuditShare> shares(PAYMENT_AUDIT_SIGNATURE_COUNT);
    if (!ParallelFor(PAYMENT_AUDIT_SIGNATURE_COUNT,
                     [&](std::size_t index) {
        const auto& position{(*positions)[index]};
        const auto& roster{(*rosters)[position.quorum_slot]};
        const auto& member{roster.members[position.member_index]};
        auto& share{shares[index]};
        share.transcript = BuildPaymentAuditShareTranscript(
            statement, observed_members, roster.descriptor,
            position.member_index, member.pro_tx_hash);
        auto authorization{MakeAuthorization(
            fixture.args.genesis_hash, fixture.public_keys,
            member.pro_tx_hash, roster.descriptor.epoch,
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
            fixture.args.genesis_hash, share.transcript)};
        scheduled_wots::Message message;
        std::copy(share_hash.begin(), share_hash.end(), message.begin());
        const PaymentAuditScheduleConfig schedule{
            fixture.args.build_config.schedule, fixture.args.btcc_config};
        const auto leaf_index{PaymentAuditLeafIndex(
            schedule, statement.commitment.subject_epoch,
            statement.commitment.seal_height, roster.descriptor.epoch)};
        return leaf_index && fixture.secret_keys[position.key_index] &&
            scheduled_wots::SignDeterministic(
            *fixture.secret_keys[position.key_index], *leaf_index, message,
            share.authenticated_signature.signature);
    })) {
        return std::nullopt;
    }

    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{PaymentAuditCollector::Create(
        fixture.args.genesis_hash,
        PaymentAuditScheduleConfig{
            fixture.args.build_config.schedule, fixture.args.btcc_config},
        statement, seal_chainlock, rosters,
        AUTHORIZATION_MASK,
        &collection_error)};
    if (!collector) return std::nullopt;
    for (const auto& share : shares) {
        if (collector->AddVerifiedShare(share, &collection_error) !=
                ShareCollectionResult::ACCEPTED ||
            collection_error != ShareCollectionError::NONE) {
            return std::nullopt;
        }
    }
    const auto finalized{collector->FinalizeCollection()};
    if (!finalized) return std::nullopt;
    const auto& final{finalized->Certificate()};
    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    auto prepared{PrepareFinalPaymentAuditVerification(
        fixture.args.genesis_hash,
        PaymentAuditScheduleConfig{fixture.args.build_config.schedule,
                                   fixture.args.btcc_config},
        final, *rosters, AUTHORIZATION_MASK,
        &verification_error)};
    ChainLockVerifier verifier{WorkerCount()};
    if (!prepared ||
        !verifier.VerifyChecks(std::move(prepared->checks)) ||
        verification_error != PaymentAuditVerificationError::NONE) {
        return std::nullopt;
    }
    return final;
}

bool ValidatePlannedChildUsage(
    const ChainLockScheduleConfig& schedule,
    const std::vector<std::pair<int32_t, FrozenQuorumRostersPtr>>&
        chainlocks,
    uint32_t audit_epoch,
    int32_t audit_height,
    FrozenQuorumRostersPtr audit_rosters)
{
    using Usage = std::tuple<uint32_t, std::size_t,
                             llmq::PQSignerPurpose, int32_t>;
    std::set<Usage> uses;
    std::map<std::pair<uint32_t, std::size_t>, std::size_t> totals;
    const auto record = [&](uint32_t epoch, std::size_t operator_index,
                            llmq::PQSignerPurpose purpose,
                            int32_t absolute_height) {
        if (!uses.emplace(epoch, operator_index, purpose,
                          absolute_height).second) {
            return false;
        }
        const auto key{std::make_pair(epoch, operator_index)};
        return ++totals[key] <= SCHEDULED_WOTS_USAGE_CAP;
    };

    for (const auto& [height, rosters] : chainlocks) {
        if (!rosters) return false;
        const auto positions{SelectSignerPositions(*rosters, [&] {
            std::map<uint256, std::size_t> indices;
            for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
                indices.emplace(NonNullHash(10'000 + member), member);
            }
            return indices;
        }())};
        if (!positions) return false;
        for (const auto& position : *positions) {
            const uint32_t epoch{
                (*rosters)[position.quorum_slot].descriptor.epoch};
            const auto span{EligibleTargetsForEpoch(schedule, epoch)};
            if (!span || height < span->first_height ||
                height > span->last_height ||
                (height - span->first_height) %
                        static_cast<int32_t>(schedule.chainlock_period) !=
                    0) {
                return false;
            }
            const auto usage_index{static_cast<uint16_t>(
                (height - span->first_height) /
                static_cast<int32_t>(schedule.chainlock_period))};
            if (usage_index >= PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD ||
                !record(epoch, position.operator_index,
                        llmq::PQSignerPurpose::CHAINLOCK, height)) {
                return false;
            }
        }
    }

    if (!audit_rosters) return false;
    std::map<uint256, std::size_t> indices;
    for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
        indices.emplace(NonNullHash(10'000 + member), member);
    }
    const auto positions{SelectSignerPositions(*audit_rosters, indices)};
    if (!positions) return false;
    for (const auto& position : *positions) {
        const uint32_t epoch{
            (*audit_rosters)[position.quorum_slot].descriptor.epoch};
        if (audit_epoch < epoch || audit_epoch - epoch >= ACTIVE_QUORUMS ||
            !record(epoch, position.operator_index,
                    llmq::PQSignerPurpose::PAYMENT_AUDIT,
                    audit_height)) {
            return false;
        }
    }
    return true;
}

bool BuildSnapshotsAndRosters(FullDimensionFixture& fixture)
{
    const auto active_epochs{ActiveEpochsAtHeight(
        fixture.args.build_config.schedule, fixture.args.target_height)};
    const auto next_target{NextEligibleChainLockTargetHeight(
        fixture.args.build_config.schedule,
        fixture.args.predecessor_height)};
    if (!active_epochs || !next_target ||
        *next_target != fixture.args.target_height ||
        !fixture.chain.SetExactHash(fixture.args.target_height,
                                    fixture.args.target_hash) ||
        !fixture.chain.SetExactHash(fixture.args.predecessor_height,
                                    fixture.args.predecessor_hash)) {
        return false;
    }

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& identity{(*active_epochs)[slot]};
        const auto snapshot_height{RegistrationCutoffHeight(
            fixture.args.build_config.schedule, identity.epoch,
            fixture.args.build_config.roster_snapshot_lag_blocks)};
        if (!snapshot_height ||
            !fixture.chain.SetExactHash(identity.base_height,
                                        fixture.args.base_hashes[slot]) ||
            !fixture.chain.SetExactHash(*snapshot_height,
                                        fixture.args.snapshot_hashes[slot])) {
            return false;
        }

        fixture.snapshot_fixture.quorum_bases[slot] =
            {identity.base_height, fixture.args.base_hashes[slot]};
        auto& output{fixture.snapshot_fixture.snapshots[slot]};
        output.branch_point =
            {*snapshot_height, fixture.args.snapshot_hashes[slot]};
        output.state.deterministic_mns =
            Snapshot(*snapshot_height, fixture.args.snapshot_hashes[slot]);
        auto operator_states{
            std::make_shared<std::vector<OperatorKeyState>>()};
        operator_states->reserve(QUORUM_MIN_VALID);
        for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
            const uint256 pro_tx_hash{NonNullHash(10'000 + member)};
            auto state{MakeOperatorState(
                fixture.args.genesis_hash, fixture.args.build_config,
                fixture.public_keys, pro_tx_hash, identity.epoch,
                *snapshot_height, member)};
            if (!state.IsStructurallyValid()) return false;
            operator_states->push_back(std::move(state));
        }
        output.state.operator_key_states = std::move(operator_states);
    }

    QuorumBuildError build_error{QuorumBuildError::NONE};
    fixture.rosters = BuildActiveFrozenQuorumRosters(
        fixture.args.genesis_hash, fixture.args.build_config,
        fixture.args.target_height, fixture.chain.Tip(),
        [&](const CBlockIndex& snapshot_index)
            -> std::optional<QuorumSnapshotState> {
            for (const auto& snapshot : fixture.snapshot_fixture.snapshots) {
                if (snapshot.branch_point.height == snapshot_index.nHeight &&
                    snapshot.branch_point.block_hash ==
                        snapshot_index.GetBlockHash()) {
                    return snapshot.state;
                }
            }
            return std::nullopt;
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

    fixture.statement.height = fixture.args.target_height;
    fixture.statement.block_hash = fixture.args.target_hash;
    fixture.statement.previous_chainlock_height =
        fixture.args.predecessor_height;
    fixture.statement.previous_chainlock_hash =
        fixture.args.predecessor_hash;
    const auto empty_probation_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_probation_hash) return false;
    fixture.statement.payment_probation_state_hash =
        *empty_probation_hash;
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = (*fixture.rosters)[slot].descriptor;
    }
    fixture.statement.quorum_context_hash = GetQuorumContextHash(
        fixture.args.genesis_hash, fixture.statement.height,
        fixture.statement.block_hash, descriptors);
    return fixture.statement.IsStructurallyValid() &&
           ValidateFrozenQuorumContext(
               fixture.args.genesis_hash, fixture.statement,
               *fixture.rosters, AUTHORIZATION_MASK);
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
            fixture.args.genesis_hash, fixture.public_keys,
            member.pro_tx_hash,
            roster.descriptor.epoch, position.operator_index)};
        authorization.record.global_key_version =
            roster.descriptor.epoch + 1;
        if (!member.child_root ||
            *member.child_root != authorization.record) {
            return false;
        }
        share.authenticated_signature.key_proof =
            std::move(authorization.proof);

        const uint256 share_hash{GetChainLockShareHash(
            fixture.args.genesis_hash, share.transcript)};
        scheduled_wots::Message message;
        std::copy(share_hash.begin(), share_hash.end(), message.begin());
        const auto leaf_index{ChainLockLeafIndex(
            fixture.args.build_config.schedule,
            roster.descriptor.epoch, fixture.statement.height)};
        return leaf_index && fixture.secret_keys[position.key_index] &&
            scheduled_wots::SignDeterministic(
            *fixture.secret_keys[position.key_index], *leaf_index, message,
            share.authenticated_signature.signature);
    });
}

uint256 BundleChecksum(Span<const uint8_t> body)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{SHARE_BUNDLE_CHECKSUM_DOMAIN.data(),
                              SHARE_BUNDLE_CHECKSUM_DOMAIN.size()}));
    writer.write(AsBytes(body));
    return writer.GetHash();
}

bool WriteShareBundle(const fs::path& path,
                      const FullDimensionFixture& fixture,
                      const FinalChainLock& chainlock,
                      std::string& error)
{
    if (fixture.member_indices.size() < 2 ||
        fixture.shares.size() != FINAL_SIGNATURE_COUNT) {
        error = "incomplete full-dimension fixture";
        return false;
    }
    DataStream certificate;
    certificate << chainlock;
    if (certificate.size() != FinalChainLock::WIRE_SIZE) {
        error = "final certificate size mismatch";
        return false;
    }

    auto identity{fixture.member_indices.begin()};
    const uint256 sender_identity{identity->first};
    ++identity;
    const uint256 observer_identity{identity->first};

    DataStream body;
    body << SHARE_BUNDLE_MAGIC << SHARE_BUNDLE_VERSION
         << static_cast<uint32_t>(fixture.shares.size())
         << static_cast<uint32_t>(ChainLockShare::WIRE_SIZE)
         << static_cast<uint32_t>(certificate.size())
         << sender_identity << observer_identity
         << chainlock.GetLogicalId(fixture.args.genesis_hash)
         << chainlock.GetWitnessId(fixture.args.genesis_hash);
    for (const auto& share : fixture.shares) {
        const std::size_t before{body.size()};
        body << share;
        if (body.size() - before != ChainLockShare::WIRE_SIZE) {
            error = "share size mismatch";
            return false;
        }
    }
    body.write(MakeByteSpan(certificate));
    if (body.size() + uint256::size() > MAX_SHARE_BUNDLE_BYTES) {
        error = "share fixture exceeds size cap";
        return false;
    }

    const uint256 checksum{BundleChecksum(MakeUCharSpan(body))};
    DataStream file;
    file.write(MakeByteSpan(body));
    file << checksum;
    if (!WriteBinaryFile(path, file.str())) {
        error = "unable to write share fixture";
        return false;
    }
    return true;
}

uint256 FixtureBodyChecksum(std::string_view domain,
                            Span<const uint8_t> body)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
    writer.write(AsBytes(body));
    return writer.GetHash();
}

template <typename T>
bool AppendFixedObject(DataStream& body, const T& object,
                       std::size_t expected_size)
{
    const std::size_t before{body.size()};
    body << object;
    return body.size() - before == expected_size;
}

struct PaymentAuditArtifacts {
    PaymentAuditEpochSchedule schedule;
    uint8_t selected_row{0};
    uint16_t online_count{0};
    bool conclusive{false};
    uint256 unobserved_member;
    uint8_t unobserved_member_misses{0};
    FinalChainLock response_chainlock;
    FinalChainLock anchor_chainlock;
    FinalChainLock seal_chainlock;
    FinalPaymentAudit audit;
    PaymentAuditReceipt receipt;
    BTCCReceiptState btcc_receipt_state;
    PaymentAuditReceiptState receipt_state;
    uint256 probation_state_hash;
};

bool AppendChainLockCertificate(DataStream& body,
                                const uint256& genesis_hash,
                                const FinalChainLock& chainlock)
{
    DataStream encoded;
    encoded << chainlock;
    if (encoded.size() != FinalChainLock::WIRE_SIZE) return false;
    body << chainlock.GetLogicalId(genesis_hash)
         << chainlock.GetWitnessId(genesis_hash)
         << static_cast<uint32_t>(encoded.size());
    body.write(MakeByteSpan(encoded));
    return true;
}

bool WritePaymentAuditBundle(const fs::path& path,
                             const uint256& genesis_hash,
                             const PaymentAuditArtifacts& artifacts,
                             std::string& error)
{
    DataStream audit_bytes;
    audit_bytes << artifacts.audit;
    if (audit_bytes.size() != FinalPaymentAudit::WIRE_SIZE) {
        error = "payment audit certificate size mismatch";
        return false;
    }

    DataStream body;
    body << PAYMENT_AUDIT_BUNDLE_MAGIC << PAYMENT_AUDIT_BUNDLE_VERSION
         << artifacts.schedule.epoch << artifacts.selected_row
         << artifacts.online_count
         << static_cast<uint8_t>(artifacts.conclusive)
         << artifacts.unobserved_member
         << artifacts.unobserved_member_misses
         << artifacts.response_chainlock.statement.height
         << artifacts.schedule.anchor_height
         << artifacts.schedule.seal_height
         << artifacts.schedule.carrier_start_height;
    if (!AppendChainLockCertificate(
            body, genesis_hash, artifacts.response_chainlock) ||
        !AppendChainLockCertificate(
            body, genesis_hash, artifacts.anchor_chainlock) ||
        !AppendChainLockCertificate(
            body, genesis_hash, artifacts.seal_chainlock)) {
        error = "payment audit ChainLock certificate size mismatch";
        return false;
    }
    body << artifacts.audit.GetLogicalId(genesis_hash)
         << artifacts.audit.GetWitnessId(genesis_hash)
         << static_cast<uint32_t>(audit_bytes.size());
    body.write(MakeByteSpan(audit_bytes));
    if (!AppendFixedObject(body, artifacts.receipt,
                           PaymentAuditReceipt::WIRE_SIZE) ||
        !AppendFixedObject(body, artifacts.btcc_receipt_state,
                           BTCCReceiptState::WIRE_SIZE) ||
        !AppendFixedObject(body, artifacts.receipt_state,
                           PaymentAuditReceiptState::WIRE_SIZE)) {
        error = "payment audit receipt size mismatch";
        return false;
    }
    body << artifacts.probation_state_hash;
    if (body.size() + uint256::size() >
        MAX_PAYMENT_AUDIT_BUNDLE_BYTES) {
        error = "payment audit bundle exceeds size cap";
        return false;
    }
    const uint256 checksum{FixtureBodyChecksum(
        PAYMENT_AUDIT_BUNDLE_CHECKSUM_DOMAIN,
        MakeUCharSpan(body))};
    DataStream file;
    file.write(MakeByteSpan(body));
    file << checksum;
    if (!WriteBinaryFile(path, file.str())) {
        error = "unable to write payment audit bundle";
        return false;
    }
    return true;
}

struct PaymentAuditPrefixArtifacts {
    FinalChainLock response_chainlock;
    FinalChainLock anchor_chainlock;
};

bool WritePaymentAuditPrefixBundle(
    const fs::path& path,
    const uint256& genesis_hash,
    const PaymentAuditPrefixArtifacts& artifacts,
    std::string& error)
{
    DataStream body;
    body << PAYMENT_AUDIT_PREFIX_BUNDLE_MAGIC
         << PAYMENT_AUDIT_PREFIX_BUNDLE_VERSION;
    if (!AppendChainLockCertificate(
            body, genesis_hash, artifacts.response_chainlock) ||
        !AppendChainLockCertificate(
            body, genesis_hash, artifacts.anchor_chainlock)) {
        error = "payment audit prefix certificate size mismatch";
        return false;
    }
    if (body.size() + uint256::size() >
        MAX_PAYMENT_AUDIT_PREFIX_BUNDLE_BYTES) {
        error = "payment audit prefix bundle exceeds size cap";
        return false;
    }
    const uint256 checksum{FixtureBodyChecksum(
        PAYMENT_AUDIT_PREFIX_BUNDLE_CHECKSUM_DOMAIN,
        MakeUCharSpan(body))};
    DataStream file;
    file.write(MakeByteSpan(body));
    file << checksum;
    if (!WriteBinaryFile(path, file.str())) {
        error = "unable to write payment audit prefix bundle";
        return false;
    }
    return true;
}

std::optional<PaymentAuditPrefixArtifacts> BuildPaymentAuditPrefixArtifacts(
    PaymentAuditFixture& fixture)
{
    const PaymentAuditScheduleConfig schedule_config{
        fixture.args.build_config.schedule, fixture.args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, fixture.args.audit_epoch)};
    if (!schedule) return std::nullopt;
    const int32_t response_height{schedule->rows.back().response_height};
    const int32_t anchor_height{schedule->anchor_height};
    if (!fixture.chain.SetExactHash(
            fixture.args.response_predecessor_height,
            fixture.args.response_predecessor_hash) ||
        !fixture.chain.SetExactHash(
            response_height, fixture.args.response_hash) ||
        !fixture.chain.SetExactHash(
            fixture.args.anchor_predecessor_height,
            fixture.args.anchor_predecessor_hash) ||
        !fixture.chain.SetExactHash(
            anchor_height, fixture.args.anchor_hash)) {
        return std::nullopt;
    }
    fixture.chain.indices[response_height].btcpPrevCommitment =
        fixture.args.response_btc_hash;
    fixture.chain.indices[anchor_height].btcpPrevCommitment =
        fixture.args.anchor_btc_hash;

    const auto response_rosters{
        BuildPaymentAuditRosters(fixture, response_height)};
    const auto anchor_rosters{
        BuildPaymentAuditRosters(fixture, anchor_height)};
    if (!response_rosters || !anchor_rosters ||
        response_rosters->back().descriptor.epoch !=
            fixture.args.audit_epoch) {
        return std::nullopt;
    }
    const auto empty_probation_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_probation_hash) return std::nullopt;
    const BTCCursor response_cursor{
        response_height, fixture.args.response_hash,
        fixture.args.response_btc_hash};
    const BTCCursor anchor_cursor{
        anchor_height, fixture.args.anchor_hash,
        fixture.args.anchor_btc_hash};
    const auto anchor_selection{SelectBTCCForChainLock(
        fixture.args.btcc_config,
        fixture.chain.indices[anchor_height], BTCCursor{})};
    BTCCValidationError btcc_error{BTCCValidationError::NONE};
    if (!ValidateBTCCursorTransition(
            fixture.args.btcc_config,
            fixture.chain.indices[response_height], BTCCursor{},
            response_cursor, BTCCAdvance::ADVANCE, &btcc_error) ||
        !anchor_selection || anchor_selection->cursor != anchor_cursor ||
        anchor_selection->advance != BTCCAdvance::ADVANCE) {
        return std::nullopt;
    }
    const auto response_statement{MakeChainLockStatement(
        fixture, *response_rosters, response_height,
        fixture.args.response_hash,
        fixture.args.response_predecessor_height,
        fixture.args.response_predecessor_hash, BTCCursor{},
        response_cursor, BTCCAdvance::ADVANCE, BTCCReceiptState{},
        PaymentAuditReceiptState{}, *empty_probation_hash)};
    const auto response_chainlock{
        response_statement
            ? SignAndVerifyChainLock(
                  fixture, *response_statement, response_rosters)
            : std::nullopt};
    if (!response_chainlock) return std::nullopt;

    const auto anchor_statement{MakeChainLockStatement(
        fixture, *anchor_rosters, anchor_height,
        fixture.args.anchor_hash,
        fixture.args.anchor_predecessor_height,
        fixture.args.anchor_predecessor_hash, BTCCursor{},
        anchor_selection->cursor, anchor_selection->advance,
        BTCCReceiptState{},
        PaymentAuditReceiptState{}, *empty_probation_hash)};
    const auto anchor_chainlock{
        anchor_statement
            ? SignAndVerifyChainLock(
                  fixture, *anchor_statement, anchor_rosters)
            : std::nullopt};
    if (!anchor_chainlock) return std::nullopt;
    return PaymentAuditPrefixArtifacts{
        std::move(*response_chainlock), std::move(*anchor_chainlock)};
}

std::optional<PaymentAuditArtifacts> BuildPaymentAuditArtifacts(
    PaymentAuditFixture& fixture)
{
    const PaymentAuditScheduleConfig schedule_config{
        fixture.args.build_config.schedule, fixture.args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, fixture.args.audit_epoch)};
    if (!schedule) return std::nullopt;
    const auto& response_row{schedule->rows.back()};
    const int32_t response_height{response_row.response_height};
    const int32_t anchor_height{schedule->anchor_height};
    const int32_t seal_height{schedule->seal_height};
    const int32_t post_height{
        schedule->carrier_start_height +
        static_cast<int32_t>(PQ_CL_PERIOD)};

    if (!fixture.chain.SetExactHash(
            fixture.args.response_predecessor_height,
            fixture.args.response_predecessor_hash) ||
        !fixture.chain.SetExactHash(response_height,
                                    fixture.args.response_hash) ||
        !fixture.chain.SetExactHash(
            fixture.args.anchor_predecessor_height,
            fixture.args.anchor_predecessor_hash) ||
        !fixture.chain.SetExactHash(anchor_height,
                                    fixture.args.anchor_hash) ||
        !fixture.chain.SetExactHash(
            fixture.args.seal_predecessor_height,
            fixture.args.seal_predecessor_hash) ||
        !fixture.chain.SetExactHash(seal_height,
                                    fixture.args.seal_hash)) {
        return std::nullopt;
    }
    fixture.chain.indices[response_height].btcpPrevCommitment =
        fixture.args.response_btc_hash;
    fixture.chain.indices[anchor_height].btcpPrevCommitment =
        fixture.args.anchor_btc_hash;

    const auto response_rosters{
        BuildPaymentAuditRosters(fixture, response_height)};
    const auto anchor_rosters{
        BuildPaymentAuditRosters(fixture, anchor_height)};
    const auto seal_rosters{
        BuildPaymentAuditRosters(fixture, seal_height)};
    const auto post_rosters{
        BuildPaymentAuditRosters(fixture, post_height)};
    if (!response_rosters || !anchor_rosters || !seal_rosters ||
        !post_rosters ||
        response_rosters->back().descriptor.epoch !=
            fixture.args.audit_epoch) {
        return std::nullopt;
    }

    const auto empty_probation_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_probation_hash) return std::nullopt;
    const BTCCursor response_cursor{
        response_height, fixture.args.response_hash,
        fixture.args.response_btc_hash};
    const BTCCursor anchor_cursor{
        anchor_height, fixture.args.anchor_hash,
        fixture.args.anchor_btc_hash};
    const auto anchor_selection{SelectBTCCForChainLock(
        fixture.args.btcc_config,
        fixture.chain.indices[anchor_height], BTCCursor{})};
    BTCCValidationError btcc_error{BTCCValidationError::NONE};
    if (!ValidateBTCCursorTransition(
            fixture.args.btcc_config,
            fixture.chain.indices[response_height], BTCCursor{},
            response_cursor, BTCCAdvance::ADVANCE, &btcc_error) ||
        !anchor_selection || anchor_selection->cursor != anchor_cursor ||
        anchor_selection->advance != BTCCAdvance::ADVANCE ||
        !ValidateBTCCursorTransition(
            fixture.args.btcc_config,
            fixture.chain.indices[seal_height], anchor_cursor,
            anchor_cursor, BTCCAdvance::KEEP, &btcc_error) ||
        !ValidateBTCCursorTransition(
            fixture.args.btcc_config,
            fixture.chain.indices[post_height], anchor_cursor,
            anchor_cursor, BTCCAdvance::KEEP, &btcc_error)) {
        return std::nullopt;
    }
    const auto response_statement{MakeChainLockStatement(
        fixture, *response_rosters, response_height,
        fixture.args.response_hash,
        fixture.args.response_predecessor_height,
        fixture.args.response_predecessor_hash, BTCCursor{},
        response_cursor, BTCCAdvance::ADVANCE, BTCCReceiptState{},
        PaymentAuditReceiptState{},
        *empty_probation_hash)};
    if (!response_statement) return std::nullopt;
    const auto response_chainlock{SignAndVerifyChainLock(
        fixture, *response_statement, response_rosters)};
    if (!response_chainlock) return std::nullopt;

    const auto anchor_statement{MakeChainLockStatement(
        fixture, *anchor_rosters, anchor_height,
        fixture.args.anchor_hash,
        fixture.args.anchor_predecessor_height,
        fixture.args.anchor_predecessor_hash, BTCCursor{},
        anchor_selection->cursor, anchor_selection->advance,
        BTCCReceiptState{},
        PaymentAuditReceiptState{},
        *empty_probation_hash)};
    if (!anchor_statement) return std::nullopt;
    const auto anchor_chainlock{SignAndVerifyChainLock(
        fixture, *anchor_statement, anchor_rosters)};
    if (!anchor_chainlock) return std::nullopt;

    BTCCReceipt expected_seed_receipt;
    expected_seed_receipt.chainlock_target_height = anchor_height;
    expected_seed_receipt.chainlock_target_hash = fixture.args.anchor_hash;
    expected_seed_receipt.chainlock_logical_id =
        anchor_chainlock->GetLogicalId(fixture.args.genesis_hash);
    expected_seed_receipt.accepted_cursor = anchor_cursor;
    if (fixture.args.seed_receipt != expected_seed_receipt) {
        return std::nullopt;
    }
    const int32_t seed_carrier_height{
        anchor_height +
        static_cast<int32_t>(fixture.args.btcc_config.nevm_injection_lag)};
    const auto btcc_receipt_state{ApplyBTCCReceiptState(
        fixture.args.genesis_hash, fixture.args.build_config.schedule,
        fixture.args.btcc_config, seed_carrier_height,
        fixture.args.seed_carrier_hash, BTCCReceiptState{},
        fixture.args.seed_receipt)};
    if (!btcc_receipt_state) return std::nullopt;

    const auto seal_statement{MakeChainLockStatement(
        fixture, *seal_rosters, seal_height, fixture.args.seal_hash,
        fixture.args.seal_predecessor_height,
        fixture.args.seal_predecessor_hash, anchor_cursor, anchor_cursor,
        BTCCAdvance::KEEP, *btcc_receipt_state,
        PaymentAuditReceiptState{}, *empty_probation_hash)};
    if (!seal_statement) return std::nullopt;
    const auto seal_chainlock{SignAndVerifyChainLock(
        fixture, *seal_statement, seal_rosters)};
    if (!seal_chainlock) return std::nullopt;

    const auto& subject{response_rosters->back()};
    const uint256 subject_descriptor_hash{GetPaymentAuditDescriptorHash(
        fixture.args.genesis_hash, subject.descriptor)};
    const auto anchor_seed{
        PaymentAuditSeedPointFromBTCCReceipt(fixture.args.seed_receipt)};
    if (!anchor_seed) return std::nullopt;
    PaymentAuditSeed seed;
    seed.epoch = fixture.args.audit_epoch;
    seed.anchor = *anchor_seed;
    seed.anchor_btc_height = 800'000;
    seed.future_btc_height =
        seed.anchor_btc_height + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;

    std::optional<PaymentAuditRound> round;
    for (uint64_t nonce{1}; nonce < 1'000'000; ++nonce) {
        seed.future_btc_hash = NonNullHash(900'000 + nonce, nonce);
        if (seed.future_btc_hash == anchor_cursor.btc_hash) continue;
        round = SelectPaymentAuditRound(
            schedule_config, *schedule, fixture.args.genesis_hash,
            subject_descriptor_hash, seed);
        if (round && round->selected_row ==
                         PAYMENT_AUDIT_ROW_COUNT - 1) {
            break;
        }
        round.reset();
    }
    if (!round || round->response_height != response_height) {
        return std::nullopt;
    }

    PaymentAuditCommitment commitment;
    commitment.seed = seed;
    commitment.selected_row = round->selected_row;
    commitment.response_height = round->response_height;
    commitment.deadline_height = round->deadline_height;
    commitment.response_chainlock_logical_id =
        response_chainlock->GetLogicalId(fixture.args.genesis_hash);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = round->seal_height;
    commitment.subject_epoch = subject.descriptor.epoch;
    commitment.subject_quorum_base_hash = subject.descriptor.base_hash;
    commitment.subject_descriptor_hash = subject_descriptor_hash;
    commitment.subject_valid_members = subject.descriptor.valid_members;
    commitment.previous_probation_state_hash = *empty_probation_hash;
    const PaymentAuditStatement audit_statement{
        commitment, seal_chainlock->statement};
    if (!audit_statement.IsStructurallyValid()) return std::nullopt;

    QuorumBitmap observed{commitment.subject_valid_members};
    std::optional<std::size_t> unobserved_index;
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        if (IsBitSetLocal(observed, member)) {
            unobserved_index = member;
            ClearBitLocal(observed, member);
            break;
        }
    }
    if (!unobserved_index || CountSet(observed) != QUORUM_MIN_VALID - 1) {
        return std::nullopt;
    }
    const auto audit{SignAndVerifyPaymentAudit(
        fixture, audit_statement, *seal_chainlock, seal_rosters,
        observed)};
    if (!audit) return std::nullopt;
    const auto classification{ClassifyPaymentAuditReports(*audit)};
    if (!classification || classification->conclusive ||
        classification->online_count != QUORUM_MIN_VALID - 1 ||
        classification->online_members != observed) {
        return std::nullopt;
    }
    const uint256 result_hash{GetPaymentAuditResultHash(
        fixture.args.genesis_hash, *audit, *classification)};

    PQPaymentProbationTransitionInput transition_input;
    transition_input.receipt = {
        fixture.args.audit_epoch, schedule->carrier_start_height,
        result_hash};
    transition_input.roster_valid_members =
        commitment.subject_valid_members;
    transition_input.observed_members = classification->online_members;
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        transition_input.frozen_roster[member] =
            subject.members[member].pro_tx_hash;
    }
    const auto transition{ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, transition_input)};
    const uint256 unobserved_member{
        subject.members[*unobserved_index].pro_tx_hash};
    if (!transition || transition->conclusive ||
        transition->effective_observed_count != 0 ||
        !transition->state.entries.empty() ||
        transition->state.MissCount(unobserved_member) != 0) {
        return std::nullopt;
    }

    PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = fixture.args.audit_epoch;
    receipt.seal_height = seal_height;
    receipt.seal_block_hash = fixture.args.seal_hash;
    receipt.carrier_height = schedule->carrier_start_height;
    receipt.audit_logical_id =
        audit->GetLogicalId(fixture.args.genesis_hash);
    receipt.audit_witness_id =
        audit->GetWitnessId(fixture.args.genesis_hash);
    receipt.commitment_hash = GetPaymentAuditCommitmentHash(
        fixture.args.genesis_hash, commitment);
    receipt.result_hash = result_hash;
    receipt.next_probation_state_hash =
        transition->undo.applied_state_hash;
    receipt.online_members = classification->online_members;
    const auto receipt_state{ApplyPaymentAuditReceipt(
        fixture.args.genesis_hash, PaymentAuditReceiptState{}, receipt)};
    if (!receipt.IsStructurallyValid() || !receipt_state ||
        !ValidatePlannedChildUsage(
            fixture.args.build_config.schedule,
            {{response_height, response_rosters},
             {anchor_height, anchor_rosters},
             {seal_height, seal_rosters},
             {post_height, post_rosters}},
            fixture.args.audit_epoch, seal_height, seal_rosters)) {
        return std::nullopt;
    }

    return PaymentAuditArtifacts{
        *schedule,
        round->selected_row,
        classification->online_count,
        classification->conclusive,
        unobserved_member,
        transition->state.MissCount(unobserved_member),
        std::move(*response_chainlock),
        std::move(*anchor_chainlock),
        std::move(*seal_chainlock),
        std::move(*audit),
        receipt,
        *btcc_receipt_state,
        *receipt_state,
        transition->undo.applied_state_hash};
}

std::optional<GeneratorArguments> ParseArguments(int argc, char* argv[],
                                                 std::string& error)
{
    if (argc != 20) {
        error =
            "usage: pq_chainlock_fixture SNAPSHOT_OUT SHARES_OUT GENESIS "
            "TARGET_HEIGHT TARGET_HASH PREDECESSOR_HEIGHT PREDECESSOR_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BASE0 BASE1 BASE2 BASE3 SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3";
        return std::nullopt;
    }

    GeneratorArguments args;
    args.snapshot_output = fs::u8path(argv[1]);
    args.shares_output = fs::u8path(argv[2]);
    args.genesis_hash = uint256S(argv[3]);
    int32_t target_height{0};
    args.target_hash = uint256S(argv[5]);
    int32_t predecessor_height{0};
    args.predecessor_hash = uint256S(argv[7]);
    int32_t epoch_origin{0};
    uint32_t registration_cutoff{0};
    uint32_t snapshot_lag{0};
    uint32_t future_horizon{0};
    if (!ParseInt32(argv[4], &target_height) ||
        !ParseInt32(argv[6], &predecessor_height) ||
        !ParseInt32(argv[8], &epoch_origin) ||
        !ParseUInt32(argv[9], &registration_cutoff) ||
        !ParseUInt32(argv[10], &snapshot_lag) ||
        !ParseUInt32(argv[11], &future_horizon) ||
        args.genesis_hash.IsNull() || args.target_hash.IsNull() ||
        args.predecessor_hash.IsNull()) {
        error = "invalid full-dimension fixture argument";
        return std::nullopt;
    }
    args.target_height = target_height;
    args.predecessor_height = predecessor_height;
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        args.base_hashes[slot] = uint256S(argv[12 + slot]);
        args.snapshot_hashes[slot] = uint256S(argv[16 + slot]);
        if (args.base_hashes[slot].IsNull() ||
            args.snapshot_hashes[slot].IsNull()) {
            error = "null branch hash in full-dimension fixture";
            return std::nullopt;
        }
    }
    const auto next_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.predecessor_height)};
    if (!args.snapshot_output.is_absolute() ||
        !args.shares_output.is_absolute() ||
        !args.build_config.IsValid() ||
        args.predecessor_height < 0 ||
        !next_target || *next_target != args.target_height ||
        !IsEligibleChainLockTarget(args.build_config.schedule,
                                   args.target_height)) {
        error = "invalid full-dimension fixture geometry";
        return std::nullopt;
    }
    return args;
}

std::optional<PaymentAuditArguments> ParsePaymentAuditPrefixArguments(
    int argc, char* argv[], std::string& error)
{
    if (argc != 29) {
        error =
            "usage: pq_chainlock_fixture payment-audit-prefix SNAPSHOT_OUT "
            "BUNDLE_OUT GENESIS BRANCH_ANCHOR_HEIGHT BRANCH_ANCHOR_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BTCC_ORIGIN AUDIT_EPOCH RESPONSE_PREDECESSOR_HEIGHT "
            "RESPONSE_PREDECESSOR_HASH RESPONSE_HASH RESPONSE_BTC_HASH "
            "ANCHOR_PREDECESSOR_HEIGHT ANCHOR_PREDECESSOR_HASH ANCHOR_HASH "
            "ANCHOR_BTC_HASH BASE0 BASE1 BASE2 BASE3 "
            "SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3";
        return std::nullopt;
    }

    PaymentAuditArguments args;
    args.snapshot_output = fs::u8path(argv[2]);
    args.bundle_output = fs::u8path(argv[3]);
    args.genesis_hash = uint256S(argv[4]);
    int32_t epoch_origin{0};
    int32_t btcc_origin{0};
    uint32_t registration_cutoff{0};
    uint32_t snapshot_lag{0};
    uint32_t future_horizon{0};
    if (!ParseInt32(argv[5], &args.branch_anchor_height) ||
        !ParseInt32(argv[7], &epoch_origin) ||
        !ParseUInt32(argv[8], &registration_cutoff) ||
        !ParseUInt32(argv[9], &snapshot_lag) ||
        !ParseUInt32(argv[10], &future_horizon) ||
        !ParseInt32(argv[11], &btcc_origin) ||
        !ParseUInt32(argv[12], &args.audit_epoch) ||
        !ParseInt32(argv[13], &args.response_predecessor_height) ||
        !ParseInt32(argv[17], &args.anchor_predecessor_height)) {
        error = "invalid payment audit prefix numeric argument";
        return std::nullopt;
    }
    args.branch_anchor_hash = uint256S(argv[6]);
    args.response_predecessor_hash = uint256S(argv[14]);
    args.response_hash = uint256S(argv[15]);
    args.response_btc_hash = uint256S(argv[16]);
    args.anchor_predecessor_hash = uint256S(argv[18]);
    args.anchor_hash = uint256S(argv[19]);
    args.anchor_btc_hash = uint256S(argv[20]);
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    args.btcc_config.candidate_origin = btcc_origin;
    for (std::size_t epoch{0}; epoch < ACTIVE_QUORUMS; ++epoch) {
        args.base_hashes[epoch] = uint256S(argv[21 + epoch]);
        args.snapshot_hashes[epoch] = uint256S(argv[25 + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit prefix branch hash";
            return std::nullopt;
        }
    }

    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, args.audit_epoch)};
    const int32_t max_tip{
        schedule
            ? schedule->anchor_height +
                  static_cast<int32_t>(args.btcc_config.nevm_injection_lag)
            : -1};
    const auto first_active{ActiveEpochsAtHeight(
        args.build_config.schedule, args.branch_anchor_height)};
    const auto last_active{ActiveEpochsAtHeight(
        args.build_config.schedule, max_tip)};
    const auto response_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.response_predecessor_height)};
    const auto anchor_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.anchor_predecessor_height)};
    if (!args.snapshot_output.is_absolute() ||
        !args.bundle_output.is_absolute() || args.genesis_hash.IsNull() ||
        args.branch_anchor_hash.IsNull() ||
        args.response_predecessor_hash.IsNull() ||
        args.anchor_predecessor_hash.IsNull() ||
        args.response_hash.IsNull() ||
        args.response_btc_hash.IsNull() || args.anchor_hash.IsNull() ||
        args.anchor_btc_hash.IsNull() || !args.build_config.IsValid() ||
        !schedule_config.IsValid() || !schedule || !first_active ||
        !last_active || first_active->front().epoch != 0 ||
        last_active->back().epoch != ACTIVE_QUORUMS - 1 ||
        !response_target ||
        *response_target != schedule->rows.back().response_height ||
        !anchor_target || *anchor_target != schedule->anchor_height ||
        args.branch_anchor_height > args.response_predecessor_height ||
        !IsEligibleChainLockTarget(args.build_config.schedule,
                                   args.branch_anchor_height)) {
        error = "invalid payment audit prefix fixture geometry";
        return std::nullopt;
    }
    return args;
}

int GeneratePaymentAuditPrefix(const PaymentAuditArguments& args)
{
    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, args.audit_epoch)};
    if (!schedule) {
        throw std::runtime_error(
            "unable to derive payment audit prefix schedule");
    }
    const int32_t max_tip{
        schedule->anchor_height +
        static_cast<int32_t>(args.btcc_config.nevm_injection_lag)};
    auto fixture{std::make_unique<PaymentAuditFixture>(
        args, max_tip, ACTIVE_QUORUMS)};
    if (!GenerateMemberKeys(fixture->public_keys, fixture->secret_keys,
                            fixture->member_indices) ||
        !PopulatePaymentAuditSnapshots(*fixture)) {
        throw std::runtime_error(
            "unable to construct payment audit prefix fixture");
    }
    const auto artifacts{BuildPaymentAuditPrefixArtifacts(*fixture)};
    if (!artifacts) {
        throw std::runtime_error(
            "unable to construct production-verified payment audit prefix");
    }

    std::string error;
    if (!test::ValidateQuorumSnapshotFixture(
            fixture->snapshot_fixture, error) ||
        !test::WriteQuorumSnapshotFixture(
            args.snapshot_output, fixture->snapshot_fixture, error)) {
        throw std::runtime_error(
            "unable to write payment audit prefix snapshot fixture: " +
            error);
    }
    if (!WritePaymentAuditPrefixBundle(
            args.bundle_output, args.genesis_hash, *artifacts, error)) {
        throw std::runtime_error(error);
    }
    return 0;
}

std::optional<PaymentAuditArguments> ParsePaymentAuditArguments(
    int argc, char* argv[], std::string& error)
{
    if (argc != 36) {
        error =
            "usage: pq_chainlock_fixture payment-audit SNAPSHOT_OUT "
            "BUNDLE_OUT GENESIS BRANCH_ANCHOR_HEIGHT BRANCH_ANCHOR_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BTCC_ORIGIN AUDIT_EPOCH RESPONSE_PREDECESSOR_HEIGHT "
            "RESPONSE_PREDECESSOR_HASH RESPONSE_HASH RESPONSE_BTC_HASH "
            "ANCHOR_PREDECESSOR_HEIGHT ANCHOR_PREDECESSOR_HASH ANCHOR_HASH "
            "ANCHOR_BTC_HASH SEAL_PREDECESSOR_HEIGHT "
            "SEAL_PREDECESSOR_HASH SEAL_HASH SEED_CARRIER_HASH "
            "SEED_RECEIPT_HEX BASE0 BASE1 BASE2 BASE3 BASE4 "
            "SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3 SNAPSHOT4";
        return std::nullopt;
    }

    PaymentAuditArguments args;
    args.snapshot_output = fs::u8path(argv[2]);
    args.bundle_output = fs::u8path(argv[3]);
    args.genesis_hash = uint256S(argv[4]);
    int32_t epoch_origin{0};
    int32_t btcc_origin{0};
    uint32_t registration_cutoff{0};
    uint32_t snapshot_lag{0};
    uint32_t future_horizon{0};
    if (!ParseInt32(argv[5], &args.branch_anchor_height) ||
        !ParseInt32(argv[7], &epoch_origin) ||
        !ParseUInt32(argv[8], &registration_cutoff) ||
        !ParseUInt32(argv[9], &snapshot_lag) ||
        !ParseUInt32(argv[10], &future_horizon) ||
        !ParseInt32(argv[11], &btcc_origin) ||
        !ParseUInt32(argv[12], &args.audit_epoch) ||
        !ParseInt32(argv[13], &args.response_predecessor_height) ||
        !ParseInt32(argv[17], &args.anchor_predecessor_height) ||
        !ParseInt32(argv[21], &args.seal_predecessor_height)) {
        error = "invalid payment audit numeric argument";
        return std::nullopt;
    }
    args.branch_anchor_hash = uint256S(argv[6]);
    args.response_predecessor_hash = uint256S(argv[14]);
    args.response_hash = uint256S(argv[15]);
    args.response_btc_hash = uint256S(argv[16]);
    args.anchor_predecessor_hash = uint256S(argv[18]);
    args.anchor_hash = uint256S(argv[19]);
    args.anchor_btc_hash = uint256S(argv[20]);
    args.seal_predecessor_hash = uint256S(argv[22]);
    args.seal_hash = uint256S(argv[23]);
    args.seed_carrier_hash = uint256S(argv[24]);
    const auto seed_receipt_bytes{ParseHex(argv[25])};
    if (seed_receipt_bytes.size() != BTCCReceipt::WIRE_SIZE) {
        error = "invalid payment audit seed-receipt size";
        return std::nullopt;
    }
    DataStream seed_receipt_stream{seed_receipt_bytes};
    try {
        seed_receipt_stream >> args.seed_receipt;
    } catch (const std::exception&) {
        error = "invalid payment audit seed-receipt encoding";
        return std::nullopt;
    }
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    args.btcc_config.candidate_origin = btcc_origin;
    for (std::size_t epoch{0}; epoch < MAX_FIXTURE_EPOCHS; ++epoch) {
        args.base_hashes[epoch] = uint256S(argv[26 + epoch]);
        args.snapshot_hashes[epoch] = uint256S(argv[31 + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit branch hash";
            return std::nullopt;
        }
    }

    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, args.audit_epoch)};
    const int32_t max_tip{schedule
        ? schedule->carrier_start_height +
              static_cast<int32_t>(2 * PQ_CL_PERIOD)
        : -1};
    const auto first_active{ActiveEpochsAtHeight(
        args.build_config.schedule, args.branch_anchor_height)};
    const auto last_active{ActiveEpochsAtHeight(
        args.build_config.schedule, max_tip)};
    const auto response_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.response_predecessor_height)};
    const auto anchor_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.anchor_predecessor_height)};
    const auto seal_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.seal_predecessor_height)};
    if (!args.snapshot_output.is_absolute() ||
        !args.bundle_output.is_absolute() || args.genesis_hash.IsNull() ||
        args.branch_anchor_hash.IsNull() ||
        args.response_predecessor_hash.IsNull() ||
        args.anchor_predecessor_hash.IsNull() ||
        args.seal_predecessor_hash.IsNull() || args.response_hash.IsNull() ||
        args.response_btc_hash.IsNull() || args.anchor_hash.IsNull() ||
        args.anchor_btc_hash.IsNull() || args.seal_hash.IsNull() ||
        args.seed_carrier_hash.IsNull() ||
        !args.seed_receipt.IsStructurallyValid() ||
        args.seed_receipt.IsNull() ||
        !args.build_config.IsValid() || !schedule_config.IsValid() ||
        !schedule || !first_active || !last_active ||
        first_active->front().epoch != 0 ||
        last_active->back().epoch != MAX_FIXTURE_EPOCHS - 1 ||
        !response_target ||
        *response_target != schedule->rows.back().response_height ||
        !anchor_target || *anchor_target != schedule->anchor_height ||
        !seal_target || *seal_target != schedule->seal_height ||
        args.branch_anchor_height > args.response_predecessor_height ||
        !IsEligibleChainLockTarget(args.build_config.schedule,
                                   args.branch_anchor_height)) {
        error = "invalid payment audit fixture geometry";
        return std::nullopt;
    }
    return args;
}

int GeneratePaymentAudit(const PaymentAuditArguments& args)
{
    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, args.audit_epoch)};
    if (!schedule) {
        throw std::runtime_error("unable to derive payment audit schedule");
    }
    const int32_t max_tip{
        schedule->carrier_start_height +
        static_cast<int32_t>(2 * PQ_CL_PERIOD)};
    auto fixture{std::make_unique<PaymentAuditFixture>(args, max_tip)};
    if (!GenerateMemberKeys(fixture->public_keys, fixture->secret_keys,
                            fixture->member_indices) ||
        !PopulatePaymentAuditSnapshots(*fixture)) {
        throw std::runtime_error(
            "unable to construct five-epoch payment audit fixture");
    }
    const auto artifacts{BuildPaymentAuditArtifacts(*fixture)};
    if (!artifacts) {
        throw std::runtime_error(
            "unable to construct production-verified payment audit artifacts");
    }

    std::string error;
    if (!test::ValidateQuorumSnapshotFixture(
            fixture->snapshot_fixture, error)) {
        throw std::runtime_error(
            "generated payment audit snapshot fixture is invalid: " +
            error);
    }
    {
        auto duplicate{fixture->snapshot_fixture};
        duplicate.quorum_bases.back() = duplicate.quorum_bases.front();
        if (test::ValidateQuorumSnapshotFixture(duplicate, error)) {
            throw std::runtime_error(
                "duplicate fixture coordinate was not rejected");
        }
        auto cross_kind_conflict{fixture->snapshot_fixture};
        cross_kind_conflict.quorum_bases[0].block_hash =
            NonNullHash(0xf000);
        if (test::ValidateQuorumSnapshotFixture(
                cross_kind_conflict, error)) {
            throw std::runtime_error(
                "cross-kind fixture coordinate conflict was not rejected");
        }
        auto extra{fixture->snapshot_fixture};
        extra.quorum_bases.push_back({
            extra.max_active_tip_height, NonNullHash(0xf001)});
        if (test::ValidateQuorumSnapshotFixture(extra, error)) {
            throw std::runtime_error(
                "extra fixture coordinate was not rejected");
        }
        auto off_window{fixture->snapshot_fixture};
        off_window.max_active_tip_height =
            off_window.branch_anchor.height - 1;
        if (test::ValidateQuorumSnapshotFixture(off_window, error)) {
            throw std::runtime_error(
                "off-window fixture bounds were not rejected");
        }
    }
    if (!test::WriteQuorumSnapshotFixture(
            args.snapshot_output, fixture->snapshot_fixture, error)) {
        throw std::runtime_error(
            "unable to write payment audit snapshot fixture: " + error);
    }
    if (!WritePaymentAuditBundle(
            args.bundle_output, args.genesis_hash, *artifacts, error)) {
        throw std::runtime_error(
            "unable to write payment audit artifact bundle: " + error);
    }
    return 0;
}

std::optional<PaymentAuditPostArguments> ParsePaymentAuditPostArguments(
    int argc, char* argv[], std::string& error)
{
    if (argc != 29) {
        error =
            "usage: pq_chainlock_fixture payment-audit-post BUNDLE_OUT "
            "GENESIS TARGET_HEIGHT TARGET_HASH PREDECESSOR_HEIGHT "
            "PREDECESSOR_HASH CURSOR_HEIGHT CURSOR_SYS_HASH "
            "CURSOR_BTC_HASH EPOCH_ORIGIN REGISTRATION_CUTOFF "
            "SNAPSHOT_LAG FUTURE_HORIZON BTCC_ORIGIN "
            "BTCC_RECEIPT_STATE_HEX PAYMENT_RECEIPT_STATE_HEX "
            "PROBATION_STATE_HASH "
            "BASE0 BASE1 BASE2 BASE3 BASE4 "
            "SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3 SNAPSHOT4";
        return std::nullopt;
    }

    PaymentAuditPostArguments args;
    args.bundle_output = fs::u8path(argv[2]);
    args.genesis_hash = uint256S(argv[3]);
    int32_t epoch_origin{0};
    int32_t btcc_origin{0};
    uint32_t registration_cutoff{0};
    uint32_t snapshot_lag{0};
    uint32_t future_horizon{0};
    if (!ParseInt32(argv[4], &args.target_height) ||
        !ParseInt32(argv[6], &args.predecessor_height) ||
        !ParseInt32(argv[8], &args.cursor.sys_height) ||
        !ParseInt32(argv[11], &epoch_origin) ||
        !ParseUInt32(argv[12], &registration_cutoff) ||
        !ParseUInt32(argv[13], &snapshot_lag) ||
        !ParseUInt32(argv[14], &future_horizon) ||
        !ParseInt32(argv[15], &btcc_origin)) {
        error = "invalid payment audit post numeric argument";
        return std::nullopt;
    }
    args.target_hash = uint256S(argv[5]);
    args.predecessor_hash = uint256S(argv[7]);
    args.cursor.sys_hash = uint256S(argv[9]);
    args.cursor.btc_hash = uint256S(argv[10]);
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    args.btcc_config.candidate_origin = btcc_origin;
    const auto btcc_receipt_bytes{ParseHex(argv[16])};
    if (btcc_receipt_bytes.size() != BTCCReceiptState::WIRE_SIZE) {
        error = "invalid BTCC receipt-state size";
        return std::nullopt;
    }
    DataStream btcc_receipt_stream{btcc_receipt_bytes};
    try {
        btcc_receipt_stream >> args.btcc_receipt_state;
    } catch (const std::exception&) {
        error = "invalid BTCC receipt-state encoding";
        return std::nullopt;
    }
    const auto receipt_bytes{ParseHex(argv[17])};
    if (receipt_bytes.size() != PaymentAuditReceiptState::WIRE_SIZE) {
        error = "invalid payment audit receipt-state size";
        return std::nullopt;
    }
    DataStream receipt_stream{receipt_bytes};
    try {
        receipt_stream >> args.payment_audit_receipt_state;
    } catch (const std::exception&) {
        error = "invalid payment audit receipt-state encoding";
        return std::nullopt;
    }
    args.payment_probation_state_hash = uint256S(argv[18]);
    for (std::size_t epoch{0}; epoch < MAX_FIXTURE_EPOCHS; ++epoch) {
        args.base_hashes[epoch] = uint256S(argv[19 + epoch]);
        args.snapshot_hashes[epoch] = uint256S(argv[24 + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit post branch hash";
            return std::nullopt;
        }
    }

    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto receipt_epoch{PaymentAuditReceiptSlotEpoch(
        schedule_config, args.target_height -
                             static_cast<int32_t>(PQ_CL_PERIOD))};
    const auto window{receipt_epoch
        ? BuildPaymentAuditCarrierWindow(schedule_config, *receipt_epoch)
        : std::nullopt};
    const auto audit_schedule{receipt_epoch
        ? BuildPaymentAuditEpochSchedule(schedule_config, *receipt_epoch)
        : std::nullopt};
    const auto next_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.predecessor_height)};
    const int64_t expected_target{
        window
            ? static_cast<int64_t>(window->start_height) + PQ_CL_PERIOD
            : -1};
    if (!args.bundle_output.is_absolute() || args.genesis_hash.IsNull() ||
        args.target_hash.IsNull() || args.predecessor_hash.IsNull() ||
        !args.cursor.IsStructurallyValid() || args.cursor.IsNull() ||
        !args.build_config.IsValid() || !schedule_config.IsValid() ||
        !args.btcc_receipt_state.IsStructurallyValid() ||
        args.btcc_receipt_state.cursor != args.cursor ||
        !args.payment_audit_receipt_state.IsStructurallyValid() ||
        args.payment_audit_receipt_state.cursor.IsNull() ||
        args.payment_probation_state_hash.IsNull() || !receipt_epoch ||
        !window || expected_target != args.target_height ||
        !audit_schedule ||
        args.payment_audit_receipt_state.cursor.carrier_height !=
            window->start_height ||
        !next_target || *next_target != args.target_height ||
        !IsEligibleChainLockTarget(args.build_config.schedule,
                                   args.target_height) ||
        IsBTCCCandidateHeight(args.btcc_config, args.target_height)) {
        error = "invalid payment audit post fixture geometry";
        return std::nullopt;
    }
    return args;
}

bool WritePostChainLockBundle(const PaymentAuditPostArguments& args,
                              const FinalChainLock& chainlock,
                              std::string& error)
{
    DataStream encoded;
    encoded << chainlock;
    if (encoded.size() != FinalChainLock::WIRE_SIZE) {
        error = "post-audit ChainLock certificate size mismatch";
        return false;
    }
    DataStream body;
    body << POST_CHAINLOCK_BUNDLE_MAGIC << POST_CHAINLOCK_BUNDLE_VERSION
         << chainlock.statement.height << chainlock.statement.block_hash
         << chainlock.GetLogicalId(args.genesis_hash)
         << chainlock.GetWitnessId(args.genesis_hash)
         << static_cast<uint32_t>(encoded.size());
    body.write(MakeByteSpan(encoded));
    body << chainlock.statement.payment_audit_receipt_state
         << chainlock.statement.payment_probation_state_hash;
    const uint256 checksum{FixtureBodyChecksum(
        POST_CHAINLOCK_BUNDLE_CHECKSUM_DOMAIN, MakeUCharSpan(body))};
    DataStream file;
    file.write(MakeByteSpan(body));
    file << checksum;
    if (!WriteBinaryFile(args.bundle_output, file.str())) {
        error = "unable to write post-audit ChainLock bundle";
        return false;
    }
    return true;
}

int GeneratePaymentAuditPost(const PaymentAuditPostArguments& args)
{
    PaymentAuditArguments fixture_args;
    fixture_args.genesis_hash = args.genesis_hash;
    fixture_args.branch_anchor_height = args.predecessor_height;
    fixture_args.branch_anchor_hash = args.predecessor_hash;
    fixture_args.build_config = args.build_config;
    fixture_args.btcc_config = args.btcc_config;
    fixture_args.base_hashes = args.base_hashes;
    fixture_args.snapshot_hashes = args.snapshot_hashes;
    auto fixture{std::make_unique<PaymentAuditFixture>(
        std::move(fixture_args), args.target_height)};
    if (!GenerateMemberKeys(fixture->public_keys, fixture->secret_keys,
                            fixture->member_indices) ||
        !PopulatePaymentAuditSnapshots(*fixture) ||
        !fixture->chain.SetExactHash(args.cursor.sys_height,
                                     args.cursor.sys_hash) ||
        !fixture->chain.SetExactHash(args.predecessor_height,
                                     args.predecessor_hash) ||
        !fixture->chain.SetExactHash(args.target_height,
                                     args.target_hash)) {
        throw std::runtime_error(
            "unable to construct post-audit ChainLock fixture");
    }
    fixture->chain.indices[args.cursor.sys_height].btcpPrevCommitment =
        args.cursor.btc_hash;
    const auto rosters{BuildPaymentAuditRosters(
        *fixture, args.target_height)};
    BTCCValidationError btcc_error{BTCCValidationError::NONE};
    const bool valid_cursor_transition{ValidateBTCCursorTransition(
        args.btcc_config, fixture->chain.indices[args.target_height],
        args.cursor, args.cursor, BTCCAdvance::KEEP, &btcc_error)};
    const auto statement{rosters && valid_cursor_transition
        ? MakeChainLockStatement(
        *fixture, *rosters, args.target_height, args.target_hash,
        args.predecessor_height, args.predecessor_hash, args.cursor,
        args.cursor, BTCCAdvance::KEEP, args.btcc_receipt_state,
        args.payment_audit_receipt_state,
        args.payment_probation_state_hash)
        : std::nullopt};
    const auto chainlock{statement ? SignAndVerifyChainLock(
        *fixture, *statement, rosters) : std::nullopt};
    if (!chainlock) {
        throw std::runtime_error(
            "unable to construct production-verified post-audit ChainLock");
    }
    std::string error;
    if (!WritePostChainLockBundle(args, *chainlock, error)) {
        throw std::runtime_error(error);
    }
    return 0;
}

int Generate(const GeneratorArguments& args)
{
    auto fixture{std::make_unique<FullDimensionFixture>(args)};
    if (!GenerateMemberKeys(*fixture) ||
        !BuildSnapshotsAndRosters(*fixture) ||
        !BuildAndSignShares(*fixture)) {
        throw std::runtime_error(
            "unable to construct full-dimension ChainLock fixture");
    }

    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{ChainLockCollector::Create(
        args.genesis_hash, args.build_config.schedule,
        fixture->statement, fixture->rosters,
        AUTHORIZATION_MASK,
        &collection_error)};
    if (!collector) {
        throw std::runtime_error("unable to create production collector");
    }
    for (const auto& share : fixture->shares) {
        if (collector->AddVerifiedShare(share, &collection_error) !=
                ShareCollectionResult::ACCEPTED ||
            collection_error != ShareCollectionError::NONE) {
            throw std::runtime_error(
                "production collector rejected generated share");
        }
    }
    const auto finalized{collector->FinalizeCollection()};
    if (!finalized ||
        !finalized->Certificate().IsStructurallyValid()) {
        throw std::runtime_error(
            "production collector did not finalize 801 shares");
    }
    const auto& final{finalized->Certificate()};
    ChainLockVerificationError verification_error{
        ChainLockVerificationError::NONE};
    ChainLockVerifier verifier{WorkerCount()};
    if (!verifier.Verify(args.genesis_hash, args.build_config.schedule,
                         final, *fixture->rosters,
                         AUTHORIZATION_MASK,
                         &verification_error) ||
        verification_error != ChainLockVerificationError::NONE) {
        throw std::runtime_error(
            "production verifier rejected generated certificate");
    }

    std::string error;
    if (!test::WriteQuorumSnapshotFixture(
            args.snapshot_output, fixture->snapshot_fixture, error)) {
        throw std::runtime_error(
            "unable to write snapshot fixture: " + error);
    }
    if (!WriteShareBundle(args.shares_output, *fixture, final, error)) {
        throw std::runtime_error(
            "unable to write share fixture: " + error);
    }
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        std::string error;
        if (argc > 1 &&
            std::string_view{argv[1]} == "payment-audit-prefix") {
            const auto args{
                ParsePaymentAuditPrefixArguments(argc, argv, error)};
            if (!args) {
                std::cerr << error << '\n';
                return 1;
            }
            return GeneratePaymentAuditPrefix(*args);
        }
        if (argc > 1 && std::string_view{argv[1]} == "payment-audit") {
            const auto args{ParsePaymentAuditArguments(argc, argv, error)};
            if (!args) {
                std::cerr << error << '\n';
                return 1;
            }
            return GeneratePaymentAudit(*args);
        }
        if (argc > 1 &&
            std::string_view{argv[1]} == "payment-audit-post") {
            const auto args{
                ParsePaymentAuditPostArguments(argc, argv, error)};
            if (!args) {
                std::cerr << error << '\n';
                return 1;
            }
            return GeneratePaymentAuditPost(*args);
        }
        const auto args{ParseArguments(argc, argv, error)};
        if (!args) {
            std::cerr << error << '\n';
            return 1;
        }
        return Generate(*args);
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
