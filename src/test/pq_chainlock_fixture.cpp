// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_chainlock_store.h>
#include <llmq/pq_chainlock_test_fixture.h>
#include <llmq/pq_btcc.h>
#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_quorum_builder.h>
#include <llmq/pq_signer_journal.h>
#include <masternode/pq_operatorkeys.h>

#include <chain.h>
#include <evo/pq_payment_probation.h>
#include <hash.h>
#include <netbase.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <test/pq_test_util.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <univalue.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
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
constexpr std::size_t MAX_FIXTURE_EPOCHS{6};
constexpr std::size_t MAX_CATCHUP_FIXTURE_EPOCHS{12};
constexpr std::size_t MAX_FIXTURE_KEY_EPOCHS{MAX_CATCHUP_FIXTURE_EPOCHS};
constexpr std::size_t CHILD_KEY_COUNT{
    MAX_FIXTURE_KEY_EPOCHS * QUORUM_MIN_VALID};
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

RosterBeaconSeed FixtureReadySeed(uint32_t epoch)
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

RosterAuthorizationVerificationContext SealLiveFixtureAuthorization(
    const uint256& genesis_hash,
    ChainLockStatement& statement,
    const ActiveRosterBeaconBundle& bundle,
    const ChainLockStatement* authorizer = nullptr)
{
    if (authorizer == nullptr) {
        statement.roster_beacons.active = bundle;
        statement.roster_beacons.next.epoch = bundle.seeds.back().epoch + 1;
        statement.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    }

    RosterAuthorizationVerificationContext authorization;
    authorization.predecessor_height = statement.previous_chainlock_height;
    authorization.predecessor_block_hash = statement.previous_chainlock_hash;
    statement.roster_authorization_base = authorizer != nullptr
        ? RosterAuthorizationBaseIdentity{
              authorizer->height, authorizer->block_hash,
              GetLogicalChainLockId(genesis_hash, *authorizer)}
        : RosterAuthorizationBaseIdentity{
              statement.previous_chainlock_height,
              statement.previous_chainlock_hash,
              statement.previous_chainlock_hash};
    authorization.authorization_base =
        statement.roster_authorization_base;
    authorization.previous = authorizer != nullptr
        ? RosterAuthorizationPriorState{
              authorizer->roster_authorization_state_hash,
              authorizer->roster_beacons}
        : RosterAuthorizationPriorState{
              NonNullHash(static_cast<uint64_t>(
                              statement.previous_chainlock_height + 2),
                          0x41555448),
              statement.roster_beacons};
    authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            statement, *authorization.previous);
    if (authorizer != nullptr) {
        authorization.normal_input->authorization_base =
            statement.roster_authorization_base;
        if (authorization.normal_input->next_snapshot
                .prior_authorization_is_descendant) {
            authorization.normal_input->next_snapshot.height =
                authorizer->height;
            authorization.normal_input->next_snapshot.hash =
                authorizer->block_hash;
        }
    }
    RosterAuthorizationTransition transition;
    transition.kind = statement.roster_transition;
    transition.target_height = statement.height;
    transition.target_block_hash = statement.block_hash;
    transition.predecessor_height = statement.previous_chainlock_height;
    transition.predecessor_block_hash = statement.previous_chainlock_hash;
    transition.authorization_base = statement.roster_authorization_base;
    transition.previous = authorization.previous;
    transition.new_window = statement.roster_beacons;
    const auto state_hash{GetRosterAuthorizationStateHash(
        genesis_hash, transition)};
    if (state_hash) statement.roster_authorization_state_hash = *state_hash;
    return authorization;
}

RosterAuthorizationVerificationContext FixtureAuthorizationFor(
    const ChainLockStatement& statement,
    const ChainLockStatement* authorizer = nullptr)
{
    RosterAuthorizationVerificationContext authorization;
    authorization.predecessor_height = statement.previous_chainlock_height;
    authorization.predecessor_block_hash = statement.previous_chainlock_hash;
    authorization.authorization_base = statement.roster_authorization_base;
    if (statement.roster_transition ==
        RosterAuthorizationTransitionKind::INITIALIZE) {
        authorization.admission = RosterAuthorizationAdmission::INITIALIZE;
        return authorization;
    }
    authorization.previous = authorizer != nullptr
        ? RosterAuthorizationPriorState{
              authorizer->roster_authorization_state_hash,
              authorizer->roster_beacons}
        : RosterAuthorizationPriorState{
              NonNullHash(static_cast<uint64_t>(
                              statement.previous_chainlock_height + 2),
                          0x41555448),
              statement.roster_beacons};
    authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            statement, *authorization.previous);
    if (authorizer != nullptr) {
        authorization.normal_input->authorization_base =
            statement.roster_authorization_base;
    }
    return authorization;
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
    uint256 target_btc_hash;
    int32_t anchor_btc_height{-1};
    uint256 future_btc_hash;
    QuorumBuildConfig build_config;
    std::array<uint256, ACTIVE_QUORUMS> base_hashes;
    std::array<uint256, ACTIVE_QUORUMS> snapshot_hashes;
    std::optional<ChainLockStatement> authorizer;
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
    std::vector<std::shared_ptr<const scheduled_wots::SecretKey>> secret_keys;
    std::map<uint256, std::size_t> member_indices;
    test::QuorumSnapshotFixture snapshot_fixture;
    FrozenQuorumRostersPtr rosters;
    VerifiedRosterSetPtr verified_rosters;
    PreparedChainLockContextPtr prepared_context;
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
    uint256 authorizer_receipt_carrier_hash;
    uint256 response_receipt_carrier_hash;
    std::size_t epoch_count{MAX_FIXTURE_EPOCHS};
    std::array<uint256, MAX_FIXTURE_KEY_EPOCHS> base_hashes;
    std::array<uint256, MAX_FIXTURE_KEY_EPOCHS> snapshot_hashes;
    std::optional<ChainLockStatement> authorizer;
    std::optional<ChainLockStatement> receipt_authorizer;
    uint256 receipt_authorizer_carrier_hash;
    std::optional<ChainLockStatement> durable_best;
    bool chainlock_step{false};
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
    std::vector<std::shared_ptr<const scheduled_wots::SecretKey>> secret_keys;
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
    std::array<uint256, MAX_FIXTURE_KEY_EPOCHS> base_hashes;
    std::array<uint256, MAX_FIXTURE_KEY_EPOCHS> snapshot_hashes;
    std::optional<ChainLockStatement> authorizer;
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

    auto authorization = [&] {
        if (member_index < QUORUM_MIN_VALID) {
            return MakeAuthorization(
                genesis_hash, public_keys, pro_tx_hash, epoch,
                member_index);
        }
        scheduled_wots::PublicKey public_key{};
        const uint256 material{NonNullHash(
            static_cast<uint64_t>(epoch) * QUORUM_SIZE + member_index + 1,
            0x524f4f54)};
        std::copy(material.begin(), material.end(), public_key.begin());
        return test::MakeSyntheticChildAuthorization(
            genesis_hash, pro_tx_hash, epoch, public_key,
            AuthorizationDiscriminator(epoch, member_index));
    }();
    const uint32_t key_version{epoch + 1};
    const std::size_t key_index{
        static_cast<std::size_t>(epoch) * QUORUM_SIZE + member_index};
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
    std::vector<std::shared_ptr<const scheduled_wots::SecretKey>>& secret_keys,
    std::map<uint256, std::size_t>& member_indices,
    std::size_t key_epochs = MAX_FIXTURE_EPOCHS)
{
    if (public_keys.size() != CHILD_KEY_COUNT ||
        secret_keys.size() != CHILD_KEY_COUNT ||
        key_epochs > MAX_FIXTURE_KEY_EPOCHS) {
        return false;
    }
    for (std::size_t member{0}; member < QUORUM_MIN_VALID; ++member) {
        member_indices.emplace(NonNullHash(10'000 + member), member);
    }
    // Long history regressions sign many independent scheduled leaves. Keep
    // their immutable public authentication trees instead of rebuilding all
    // child keys for every certificate; signature generation stays unchanged.
    static std::vector<std::shared_ptr<const scheduled_wots::SecretKey>>
        cached_keys(CHILD_KEY_COUNT);
    const std::size_t key_count{key_epochs * QUORUM_MIN_VALID};
    if (!ParallelFor(key_count, [&](std::size_t key_index) {
        if (cached_keys[key_index]) return true;
        scheduled_wots::KeyGenerationSeed seed{};
        FillKeySeed(key_index, seed);
        auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
        memory_cleanse(seed.data(), seed.size());
        if (!secret_key) return false;
        cached_keys[key_index] =
            std::make_shared<scheduled_wots::SecretKey>(std::move(*secret_key));
        return true;
    })) return false;
    secret_keys = cached_keys;
    for (std::size_t key_index{0}; key_index < key_count; ++key_index) {
        if (!secret_keys[key_index]->GetPublicKey(public_keys[key_index])) {
            return false;
        }
    }
    return true;
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
    const std::size_t base_count{
        fixture.snapshot_fixture.quorum_bases.size()};
    const std::size_t snapshot_count{
        fixture.snapshot_fixture.snapshots.size()};
    if (base_count < ACTIVE_QUORUMS ||
        base_count > MAX_FIXTURE_EPOCHS ||
        snapshot_count < base_count ||
        snapshot_count > MAX_FIXTURE_KEY_EPOCHS ||
        snapshot_count - base_count > 1) {
        return false;
    }
    for (uint32_t epoch{0}; epoch < snapshot_count; ++epoch) {
        const auto base_height{EpochBaseHeight(
            fixture.args.build_config.schedule, epoch)};
        const auto snapshot_height{RegistrationCutoffHeight(
            fixture.args.build_config.schedule, epoch,
            fixture.args.build_config.roster_snapshot_lag_blocks)};
        if (!base_height || !snapshot_height) {
            return false;
        }
        uint256 snapshot_hash;
        if (epoch < base_count) {
            if (!fixture.chain.SetExactHash(
                    *base_height, fixture.args.base_hashes[epoch])) {
                return false;
            }
            fixture.snapshot_fixture.quorum_bases[epoch] = {
                *base_height, fixture.args.base_hashes[epoch]};
            snapshot_hash = fixture.args.snapshot_hashes[epoch];
        } else {
            for (uint32_t known_epoch{0}; known_epoch < base_count;
                 ++known_epoch) {
                const auto known_base{EpochBaseHeight(
                    fixture.args.build_config.schedule, known_epoch)};
                if (known_base && *known_base == *snapshot_height) {
                    snapshot_hash = fixture.args.base_hashes[known_epoch];
                    break;
                }
            }
        }
        if (snapshot_hash.IsNull() ||
            !fixture.chain.SetExactHash(*snapshot_height, snapshot_hash)) {
            return false;
        }
        auto& snapshot{fixture.snapshot_fixture.snapshots[epoch]};
        snapshot.branch_point = {
            *snapshot_height, snapshot_hash};
        snapshot.state.deterministic_mns = Snapshot(
            *snapshot_height, snapshot_hash);
        auto operator_states{
            std::make_shared<std::vector<OperatorKeyState>>()};
        operator_states->reserve(QUORUM_SIZE);
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
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

    if (!fixture.args.authorizer ||
        fixture.args.authorizer->roster_beacons.active
            .recovery_authority_source.IsNull()) {
        return true;
    }

    for (const auto& seed :
         fixture.args.authorizer->roster_beacons.active.seeds) {
        if (!seed.IsReady() ||
            !fixture.chain.SetExactHash(seed.anchor_cursor.sys_height,
                                        seed.anchor_cursor.sys_hash)) {
            return false;
        }
    }
    const auto& next_seed{fixture.args.authorizer->roster_beacons.next};
    if (next_seed.IsReady() &&
        !fixture.chain.SetExactHash(next_seed.anchor_cursor.sys_height,
                                    next_seed.anchor_cursor.sys_hash)) {
        return false;
    }

    const auto& source{fixture.args.authorizer->roster_beacons.active
                           .recovery_authority_source};
    if (!source.IsStructurallyValid() || source.IsNull() ||
        !fixture.chain.SetExactHash(
            source.normal_beacon.anchor_cursor.sys_height,
            source.normal_beacon.anchor_cursor.sys_hash)) {
        return false;
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

VerifiedRosterSetPtr BuildPaymentAuditRosters(
    const PaymentAuditFixture& fixture,
    int32_t target_height,
    const ActiveRosterBeaconBundle& beacon_bundle)
{
    const auto cache{FrozenQuorumRosterCache::Create(
        fixture.args.genesis_hash, fixture.args.build_config,
        [&](const CBlockIndex& index) {
            return LookupPaymentAuditSnapshot(fixture, index);
        },
        /*cache_results=*/false)};
    if (!cache) return nullptr;
    QuorumBuildError build_error{QuorumBuildError::NONE};
    const auto& source{beacon_bundle.recovery_authority_source};
    if (source.IsNull()) return nullptr;
    const auto rosters{cache->GetVerifiedActiveNoPublish(
        target_height, fixture.chain.Tip(), beacon_bundle, &build_error)};
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

bool ClaimAuthorizedFixtureRosterTransition(
    const PaymentAuditFixture& fixture,
    ChainLockStatement& statement,
    const ChainLockStatement& authorizer)
{
    const auto& config{fixture.args.build_config};
    const auto newest_epoch{
        EpochForHeight(config.schedule, statement.height)};
    if (!newest_epoch ||
        authorizer.roster_authorization_state_hash.IsNull() ||
        !authorizer.roster_beacons.IsStructurallyValid()) {
        return false;
    }

    const auto& previous{authorizer.roster_beacons};
    const uint32_t previous_newest{
        previous.active.seeds.back().epoch};
    if (*newest_epoch < previous_newest ||
        *newest_epoch > static_cast<uint64_t>(previous_newest) + 1) {
        return false;
    }

    statement.roster_beacons = previous;
    statement.roster_transition = RosterAuthorizationTransitionKind::KEEP;
    const auto make_ready = [](RosterBeaconSeed seed) {
        seed.state = RosterBeaconState::READY;
        seed.future_btc_hash = FixtureReadySeed(seed.epoch).future_btc_hash;
        return seed;
    };
    const auto make_pending = [&](RosterBeaconSeed seed) {
        seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
        seed.state = RosterBeaconState::PENDING;
        seed.anchor_cursor = statement.accepted_btcc_cursor;
        seed.anchor_btc_height =
            800'000 + static_cast<int32_t>(seed.epoch);
        seed.future_btc_hash.SetNull();
        return seed;
    };
    const auto next_snapshot{RegistrationCutoffHeight(
        config.schedule, *newest_epoch + 1,
        config.roster_snapshot_lag_blocks)};
    const bool observe_next{
        statement.btcc_advance == BTCCAdvance::ADVANCE &&
        next_snapshot && authorizer.height >= *next_snapshot};
    const auto bind_recovery_source = [&] {
        RecoveryRosterAuthoritySource expected_source{
            previous.active.recovery_authority_source};
        if (!HasRecoveryRosterBeacon(statement.roster_beacons)) {
            const auto* newest_normal{
                FindNewestNormalReadySeed(statement.roster_beacons)};
            if (newest_normal == nullptr) return false;
            expected_source.normal_beacon = *newest_normal;
        }
        if (expected_source.IsNull()) return false;
        statement.roster_beacons.active.recovery_authority_source =
            expected_source;
        return true;
    };

    if (*newest_epoch == previous_newest) {
        if (previous.next.state == RosterBeaconState::PENDING) {
            statement.roster_beacons.next = make_ready(previous.next);
            statement.roster_transition =
                RosterAuthorizationTransitionKind::REVEAL;
        } else if (previous.next.state == RosterBeaconState::EMPTY &&
                   observe_next) {
            statement.roster_beacons.next = make_pending(previous.next);
            statement.roster_transition =
                RosterAuthorizationTransitionKind::OBSERVE;
        }
        return bind_recovery_source() &&
               statement.roster_beacons.IsStructurallyValid();
    }

    if (previous.next.state == RosterBeaconState::EMPTY) return false;
    const RosterBeaconSeed consumed{
        previous.next.IsReady() ? previous.next
                                : make_ready(previous.next)};
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        statement.roster_beacons.active.seeds[slot] =
            previous.active.seeds[slot + 1];
    }
    statement.roster_beacons.active.seeds.back() = consumed;
    statement.roster_beacons.next = {};
    statement.roster_beacons.next.anchor_kind =
        RosterBeaconAnchorKind::NORMAL;
    statement.roster_beacons.next.state = RosterBeaconState::EMPTY;
    statement.roster_beacons.next.epoch = *newest_epoch + 1;
    if (observe_next) {
        statement.roster_beacons.next =
            make_pending(statement.roster_beacons.next);
    }
    statement.roster_transition = RosterAuthorizationTransitionKind::ROTATE;
    return bind_recovery_source() &&
           statement.roster_beacons.IsStructurallyValid();
}

struct PreparedPaymentChainLockStatement {
    ChainLockStatement statement;
    PreparedChainLockContextPtr context;
};

std::optional<PreparedPaymentChainLockStatement> MakeChainLockStatement(
    const PaymentAuditFixture& fixture,
    int32_t height,
    const uint256& block_hash,
    int32_t predecessor_height,
    const uint256& predecessor_hash,
    const BTCCursor& previous_cursor,
    const BTCCursor& accepted_cursor,
    BTCCAdvance advance,
    const BTCCReceiptState& btcc_receipt_state,
    const PaymentAuditReceiptState& payment_receipt_state,
    const uint256& probation_state_hash,
    const ChainLockStatement& authorizer)
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
    if (!ClaimAuthorizedFixtureRosterTransition(
            fixture, statement, authorizer)) {
        if (fixture.args.chainlock_step) {
            std::cerr << "ChainLock step cannot derive roster transition at "
                      << height << " from " << authorizer.height << '\n';
        }
        return std::nullopt;
    }
    const auto roster_set{BuildPaymentAuditRosters(
        fixture, height, statement.roster_beacons.active)};
    if (!roster_set) {
        if (fixture.args.chainlock_step) {
            std::cerr << "ChainLock step cannot build rosters at "
                      << height << '\n';
        }
        return std::nullopt;
    }
    statement.quorum_context_hash = GetQuorumContextHash(
        fixture.args.genesis_hash, height, block_hash,
        Descriptors(roster_set->Rosters()));
    const auto authorization{SealLiveFixtureAuthorization(
        fixture.args.genesis_hash, statement,
        statement.roster_beacons.active, &authorizer)};
    auto scheduled_authorization{authorization};
    scheduled_authorization.reset_policy = RosterResetVerificationPolicy{
        fixture.args.build_config.schedule, fixture.args.btcc_config,
        fixture.args.btcc_config.candidate_origin - 1};
    ChainLockVerificationError verification_error{
        ChainLockVerificationError::NONE};
    const auto context{PreparedChainLockContext::Create(
        fixture.args.build_config.schedule, statement, roster_set,
        scheduled_authorization, &verification_error)};
    if (!context ||
        verification_error != ChainLockVerificationError::NONE) {
        if (fixture.args.chainlock_step) {
            std::cerr << "ChainLock step context rejected at " << height
                      << " transition=" << static_cast<int>(statement.roster_transition)
                      << " error=" << static_cast<int>(verification_error) << '\n';
        }
        return std::nullopt;
    }
    return PreparedPaymentChainLockStatement{
        std::move(statement), std::move(context)};
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
    PreparedChainLockContextPtr context)
{
    if (!context) return std::nullopt;
    const auto& statement{context->Statement()};
    const auto& rosters{context->Rosters()};
    const auto positions{SelectSignerPositions(
        rosters, fixture.member_indices)};
    if (!positions) return std::nullopt;

    std::vector<ChainLockShare> shares(FINAL_SIGNATURE_COUNT);
    FinalChainLock shell;
    shell.statement = statement;
    if (!ParallelFor(FINAL_SIGNATURE_COUNT, [&](std::size_t index) {
            const auto& position{(*positions)[index]};
            const auto& roster{rosters[position.quorum_slot]};
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
        context, &collection_error)};
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
    auto prepared{PrepareFinalChainLockVerification(
        final, *context, &verification_error)};
    if (!prepared ||
        !verifier.VerifyChecks(std::move(prepared->checks)) ||
        verification_error != ChainLockVerificationError::NONE) {
        return std::nullopt;
    }
    return final;
}

std::optional<FinalPaymentAudit> SignAndVerifyPaymentAudit(
    const PaymentAuditFixture& fixture,
    const PaymentAuditStatement& statement,
    const FinalChainLock& seal_chainlock,
    PreparedChainLockContextPtr seal_context,
    const QuorumBitmap& observed_members)
{
    if (!seal_context) return std::nullopt;
    const auto& rosters{seal_context->Rosters()};
    const auto positions{SelectSignerPositions(
        rosters, fixture.member_indices)};
    if (!positions) return std::nullopt;

    std::vector<PaymentAuditShare> shares(PAYMENT_AUDIT_SIGNATURE_COUNT);
    if (!ParallelFor(PAYMENT_AUDIT_SIGNATURE_COUNT,
                     [&](std::size_t index) {
        const auto& position{(*positions)[index]};
        const auto& roster{rosters[position.quorum_slot]};
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

    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    const PaymentAuditScheduleConfig schedule{
        fixture.args.build_config.schedule, fixture.args.btcc_config};
    const auto context{PreparedPaymentAuditContext::Create(
        schedule, statement, seal_chainlock,
        seal_context->RosterSetPtr(), seal_context->Authorization(),
        &verification_error)};
    if (!context ||
        verification_error != PaymentAuditVerificationError::NONE) {
        return std::nullopt;
    }
    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{PaymentAuditCollector::Create(context,
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
    auto prepared{PrepareFinalPaymentAuditVerification(
        schedule, final, seal_context->RosterSetPtr(),
        seal_context->Authorization(),
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
                                    fixture.args.predecessor_hash) ||
        (fixture.args.authorizer &&
         !fixture.chain.SetExactHash(fixture.args.authorizer->height,
                                     fixture.args.authorizer->block_hash))) {
        std::cerr << "invalid full-dimension target geometry\n";
        return false;
    }
    fixture.chain.indices[fixture.args.target_height].btcpPrevCommitment =
        fixture.args.target_btc_hash;

    RosterBeaconWindow beacon_window;
    if (fixture.args.authorizer) {
        beacon_window = fixture.args.authorizer->roster_beacons;
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            if (beacon_window.active.seeds[slot].epoch !=
                (*active_epochs)[slot].epoch) {
                std::cerr << "authorizer roster epoch mismatch\n";
                return false;
            }
        }
    } else {
        const BTCCursor cursor{fixture.args.target_height,
                               fixture.args.target_hash,
                               fixture.args.target_btc_hash};
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            RosterBeaconSeed seed;
            seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
            seed.state = RosterBeaconState::READY;
            seed.epoch = (*active_epochs)[slot].epoch;
            seed.anchor_cursor = cursor;
            seed.anchor_btc_height = fixture.args.anchor_btc_height;
            seed.future_btc_hash = fixture.args.future_btc_hash;
            beacon_window.active.seeds[slot] = std::move(seed);
        }
        beacon_window.active.recovery_authority_source.normal_beacon =
            beacon_window.active.seeds.back();
        beacon_window.next.epoch =
            beacon_window.active.seeds.back().epoch + 1;
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
            std::cerr << "invalid full-dimension snapshot coordinate\n";
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
        operator_states->reserve(QUORUM_SIZE);
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            const uint256 pro_tx_hash{NonNullHash(10'000 + member)};
            auto state{MakeOperatorState(
                fixture.args.genesis_hash, fixture.args.build_config,
                fixture.public_keys, pro_tx_hash, identity.epoch,
                *snapshot_height, member)};
            if (!state.IsStructurallyValid()) {
                std::cerr << "invalid full-dimension operator state\n";
                return false;
            }
            operator_states->push_back(std::move(state));
        }
        output.state.operator_key_states = std::move(operator_states);
    }

    const bool has_recovery_seed{std::any_of(
        beacon_window.active.seeds.begin(),
        beacon_window.active.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    const RecoveryRosterAuthoritySource authority_source{
        beacon_window.active.recovery_authority_source};
    if (!authority_source.IsStructurallyValid() ||
        authority_source.IsNull() ||
        !fixture.chain.SetExactHash(
            authority_source.normal_beacon.anchor_cursor.sys_height,
            authority_source.normal_beacon.anchor_cursor.sys_hash)) {
        std::cerr << "invalid recovery source\n";
        return false;
    }
    if (fixture.args.authorizer) {
        if (beacon_window.active.recovery_authority_source !=
                authority_source) {
            std::cerr << "recovery source mismatch\n";
            return false;
        }
    }
    if ((has_recovery_seed &&
         !IsRecoveryRosterBeaconWindow(beacon_window)) ||
        (!fixture.args.authorizer &&
         !IsInitialNormalRosterBeaconWindow(beacon_window))) {
        std::cerr << "invalid source-bound roster beacon window\n";
        return false;
    }

    QuorumBuildError build_error{QuorumBuildError::NONE};
    const auto snapshot_lookup = [&](const CBlockIndex& snapshot_index)
        -> std::optional<QuorumSnapshotState> {
            for (const auto& snapshot : fixture.snapshot_fixture.snapshots) {
                if (snapshot.branch_point.height == snapshot_index.nHeight &&
                    snapshot.branch_point.block_hash ==
                        snapshot_index.GetBlockHash()) {
                    return snapshot.state;
                }
            }
            return std::nullopt;
        };
    const auto cache{FrozenQuorumRosterCache::Create(
        fixture.args.genesis_hash, fixture.args.build_config,
        snapshot_lookup, /*cache_results=*/false)};
    fixture.verified_rosters = cache
        ? cache->GetVerifiedActiveNoPublish(
              fixture.args.target_height, fixture.chain.Tip(),
              beacon_window.active, &build_error)
        : nullptr;
    fixture.rosters = fixture.verified_rosters
        ? fixture.verified_rosters->RostersPtr()
        : nullptr;
    if (!fixture.rosters || build_error != QuorumBuildError::NONE) {
        std::cerr << "unable to build active rosters: "
                  << static_cast<int>(build_error) << '\n';
        return false;
    }

    for (const auto& roster : *fixture.rosters) {
        if (roster.descriptor.valid_count != QUORUM_SIZE ||
            CountSet(roster.descriptor.valid_members) != QUORUM_SIZE ||
            std::count_if(
                roster.members.begin(), roster.members.end(),
                [](const FrozenQuorumMember& member) {
                    return !member.pro_tx_hash.IsNull();
                }) != static_cast<std::ptrdiff_t>(QUORUM_SIZE) ||
            std::count_if(
                roster.members.begin(), roster.members.end(),
                [](const FrozenQuorumMember& member) {
                    return member.eligible && member.child_root.has_value();
                }) != static_cast<std::ptrdiff_t>(QUORUM_SIZE)) {
            std::cerr << "unexpected full-dimension roster shape\n";
            return false;
        }
    }

    fixture.statement.height = fixture.args.target_height;
    fixture.statement.block_hash = fixture.args.target_hash;
    fixture.statement.previous_chainlock_height =
        fixture.args.predecessor_height;
    fixture.statement.previous_chainlock_hash =
        fixture.args.predecessor_hash;
    if (fixture.args.authorizer) {
        fixture.statement.previous_btcc_cursor =
            fixture.args.authorizer->accepted_btcc_cursor;
        fixture.statement.accepted_btcc_cursor =
            fixture.args.authorizer->accepted_btcc_cursor;
        fixture.statement.btcc_advance = BTCCAdvance::KEEP;
        fixture.statement.btcc_receipt_state =
            fixture.args.authorizer->btcc_receipt_state;
        fixture.statement.payment_audit_receipt_state =
            fixture.args.authorizer->payment_audit_receipt_state;
        fixture.statement.payment_probation_state_hash =
            fixture.args.authorizer->payment_probation_state_hash;

        // Bind the authorizing ADVANCE to the exact carrier hash supplied by
        // the fixture. The carrier is either the target in legacy scenarios
        // or the shared predecessor at the first valid post-receipt round.
        const auto& authorizer{*fixture.args.authorizer};
        const int64_t authorizer_carrier_height{
            static_cast<int64_t>(authorizer.height) + PQ_BTCC_NEVM_LAG};
        if (authorizer.btcc_advance == BTCCAdvance::ADVANCE &&
            (authorizer_carrier_height == fixture.args.target_height ||
             authorizer_carrier_height == fixture.args.predecessor_height)) {
            const bool carrier_is_target{
                authorizer_carrier_height == fixture.args.target_height};
            const int32_t carrier_height{
                carrier_is_target ? fixture.args.target_height
                                  : fixture.args.predecessor_height};
            const uint256& carrier_hash{
                carrier_is_target ? fixture.args.target_hash
                                  : fixture.args.predecessor_hash};
            BTCCReceipt receipt;
            receipt.chainlock_target_height = authorizer.height;
            receipt.chainlock_target_hash = authorizer.block_hash;
            receipt.chainlock_logical_id = GetLogicalChainLockId(
                fixture.args.genesis_hash, authorizer);
            receipt.accepted_cursor = authorizer.accepted_btcc_cursor;
            const auto applied{ApplyBTCCReceiptState(
                fixture.args.genesis_hash,
                fixture.args.build_config.schedule,
                BTCCScheduleConfig{authorizer.height},
                authorizer.previous_chainlock_height,
                carrier_height, carrier_hash,
                fixture.statement.btcc_receipt_state, receipt)};
            if (!applied) {
                std::cerr << "unable to apply fixture BTCC receipt\n";
                return false;
            }
            fixture.statement.btcc_receipt_state = *applied;
        }
    } else {
        fixture.statement.accepted_btcc_cursor = BTCCursor{
            fixture.args.target_height, fixture.args.target_hash,
            fixture.args.target_btc_hash};
        fixture.statement.btcc_advance = BTCCAdvance::ADVANCE;
        const auto empty_probation_hash{
            GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
        if (!empty_probation_hash) {
            std::cerr << "unable to derive empty probation hash\n";
            return false;
        }
        fixture.statement.payment_probation_state_hash =
            *empty_probation_hash;
    }
    if (fixture.args.authorizer) {
        fixture.statement.roster_beacons = beacon_window;
        fixture.statement.roster_transition =
            RosterAuthorizationTransitionKind::KEEP;
    }
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = (*fixture.rosters)[slot].descriptor;
    }
    fixture.statement.quorum_context_hash = GetQuorumContextHash(
        fixture.args.genesis_hash, fixture.statement.height,
        fixture.statement.block_hash, descriptors);
    RosterAuthorizationVerificationContext authorization;
    if (fixture.args.authorizer) {
        authorization = SealLiveFixtureAuthorization(
            fixture.args.genesis_hash, fixture.statement,
            beacon_window.active, &*fixture.args.authorizer);
    } else {
        fixture.statement.roster_beacons = beacon_window;
        fixture.statement.roster_transition =
            RosterAuthorizationTransitionKind::INITIALIZE;
        RosterAuthorizationTransition transition;
        transition.kind = fixture.statement.roster_transition;
        transition.target_height = fixture.statement.height;
        transition.target_block_hash = fixture.statement.block_hash;
        transition.predecessor_height =
            fixture.statement.previous_chainlock_height;
        transition.predecessor_block_hash =
            fixture.statement.previous_chainlock_hash;
        transition.new_window = fixture.statement.roster_beacons;
        const auto state_hash{GetRosterAuthorizationStateHash(
            fixture.args.genesis_hash, transition)};
        if (!state_hash) {
            std::cerr << "unable to derive INITIALIZE state hash\n";
            return false;
        }
        fixture.statement.roster_authorization_state_hash = *state_hash;
        authorization = FixtureAuthorizationFor(fixture.statement);
    }
    const int32_t reset_origin{
        authority_source.normal_beacon.anchor_cursor.sys_height};
    const int64_t reset_predecessor{
        static_cast<int64_t>(reset_origin) -
        fixture.args.build_config.schedule.chainlock_period};
    if (reset_origin < 0 || reset_predecessor < -1 ||
        reset_predecessor > std::numeric_limits<int32_t>::max()) {
        std::cerr << "invalid fixture reset policy\n";
        return false;
    }
    BTCCScheduleConfig reset_btcc;
    reset_btcc.candidate_origin = reset_origin;
    authorization.reset_policy = RosterResetVerificationPolicy{
        fixture.args.build_config.schedule, reset_btcc,
        static_cast<int32_t>(reset_predecessor)};
    if (!fixture.statement.IsStructurallyValid()) {
        std::cerr << "invalid full-dimension statement\n";
        return false;
    }
    ChainLockVerificationError verification_error{
        ChainLockVerificationError::NONE};
    fixture.prepared_context = PreparedChainLockContext::Create(
        fixture.args.build_config.schedule, fixture.statement,
        fixture.verified_rosters, authorization, &verification_error);
    if (!fixture.prepared_context ||
        verification_error != ChainLockVerificationError::NONE) {
        std::cerr << "full-dimension roster context rejected\n";
        return false;
    }
    return true;
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
         << static_cast<uint32_t>(CompactChainLockShare::WIRE_SIZE)
         << static_cast<uint32_t>(certificate.size())
         << sender_identity << observer_identity
         << chainlock.GetLogicalId(fixture.args.genesis_hash)
         << chainlock.GetWitnessId(fixture.args.genesis_hash);
    for (const auto& share : fixture.shares) {
        const auto compact{fixture.prepared_context
            ? BuildCompactChainLockShare(
                  share, *fixture.prepared_context)
            : std::nullopt};
        if (!compact) {
            error = "unable to compact share";
            return false;
        }
        const std::size_t before{body.size()};
        body << *compact;
        if (body.size() - before != CompactChainLockShare::WIRE_SIZE) {
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

bool WritePaymentAuditPrefixBundle(
    const fs::path& path,
    const uint256& genesis_hash,
    const FinalChainLock& chainlock,
    std::string& error)
{
    DataStream body;
    body << PAYMENT_AUDIT_PREFIX_BUNDLE_MAGIC
         << PAYMENT_AUDIT_PREFIX_BUNDLE_VERSION;
    if (!AppendChainLockCertificate(body, genesis_hash, chainlock)) {
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

std::optional<BTCCReceiptState> ApplyChainLockReceiptState(
    PaymentAuditFixture& fixture,
    const ChainLockStatement& statement,
    const uint256& carrier_hash)
{
    if (statement.btcc_advance != BTCCAdvance::ADVANCE) {
        return statement.btcc_receipt_state;
    }
    const int64_t carrier_height{
        static_cast<int64_t>(statement.height) +
        fixture.args.btcc_config.nevm_injection_lag};
    if (carrier_height > std::numeric_limits<int32_t>::max() ||
        carrier_hash.IsNull() ||
        !fixture.chain.SetExactHash(
            static_cast<int32_t>(carrier_height),
            carrier_hash)) {
        return std::nullopt;
    }

    BTCCReceipt receipt;
    receipt.chainlock_target_height = statement.height;
    receipt.chainlock_target_hash = statement.block_hash;
    receipt.chainlock_logical_id =
        GetLogicalChainLockId(fixture.args.genesis_hash, statement);
    receipt.accepted_cursor = statement.accepted_btcc_cursor;
    const auto& carrier{
        fixture.chain.indices[static_cast<int32_t>(carrier_height)]};
    if (!ValidateBTCCReceiptOnBranch(
            fixture.args.build_config.schedule, fixture.args.btcc_config,
            statement.previous_chainlock_height, carrier,
            statement.btcc_receipt_state, receipt)) {
        return std::nullopt;
    }
    return ApplyBTCCReceiptState(
        fixture.args.genesis_hash, fixture.args.build_config.schedule,
        fixture.args.btcc_config,
        statement.previous_chainlock_height,
        static_cast<int32_t>(carrier_height),
        carrier_hash, statement.btcc_receipt_state, receipt);
}

std::optional<FinalChainLock> BuildPaymentAuditPrefixArtifact(
    PaymentAuditFixture& fixture)
{
    if (!fixture.args.authorizer) {
        return std::nullopt;
    }
    const auto& authorizer{*fixture.args.authorizer};
    const auto& receipt_authorizer{fixture.args.receipt_authorizer
        ? *fixture.args.receipt_authorizer : authorizer};
    const auto target_height{NextEligibleChainLockTargetHeight(
        fixture.args.build_config.schedule,
        fixture.args.response_predecessor_height)};
    if (!target_height) return std::nullopt;
    if (!fixture.chain.SetExactHash(
            fixture.args.response_predecessor_height,
            fixture.args.response_predecessor_hash) ||
        !fixture.chain.SetExactHash(
            *target_height, fixture.args.response_hash) ||
        !fixture.chain.SetExactHash(authorizer.height,
                                    authorizer.block_hash) ||
        (!authorizer.accepted_btcc_cursor.IsNull() &&
         !fixture.chain.SetExactHash(
             authorizer.accepted_btcc_cursor.sys_height,
             authorizer.accepted_btcc_cursor.sys_hash)) ||
        (!authorizer.btcc_receipt_state.cursor.IsNull() &&
         !fixture.chain.SetExactHash(
             authorizer.btcc_receipt_state.cursor.sys_height,
             authorizer.btcc_receipt_state.cursor.sys_hash))) {
        return std::nullopt;
    }
    fixture.chain.indices[*target_height].btcpPrevCommitment =
        fixture.args.response_btc_hash;
    if (!authorizer.accepted_btcc_cursor.IsNull()) {
        fixture.chain.indices[authorizer.accepted_btcc_cursor.sys_height]
            .btcpPrevCommitment = authorizer.accepted_btcc_cursor.btc_hash;
    }
    if (!authorizer.btcc_receipt_state.cursor.IsNull()) {
        fixture.chain.indices[authorizer.btcc_receipt_state.cursor.sys_height]
            .btcpPrevCommitment =
                authorizer.btcc_receipt_state.cursor.btc_hash;
    }
    if (!fixture.chain.SetExactHash(receipt_authorizer.height,
                                   receipt_authorizer.block_hash)) {
        return std::nullopt;
    }
    for (const BTCCursor* cursor : {
             &receipt_authorizer.accepted_btcc_cursor,
             &receipt_authorizer.btcc_receipt_state.cursor}) {
        if (!cursor->IsNull()) {
            if (!fixture.chain.SetExactHash(cursor->sys_height,
                                            cursor->sys_hash)) {
                return std::nullopt;
            }
            fixture.chain.indices[cursor->sys_height].btcpPrevCommitment =
                cursor->btc_hash;
        }
    }
    const auto authorizer_receipt_state{ApplyChainLockReceiptState(
        fixture, receipt_authorizer,
        fixture.args.receipt_authorizer
            ? fixture.args.receipt_authorizer_carrier_hash
            : fixture.args.authorizer_receipt_carrier_hash)};
    if (!authorizer_receipt_state) return std::nullopt;

    const BTCCursor target_cursor{
        *target_height, fixture.args.response_hash,
        fixture.args.response_btc_hash};
    BTCCursor previous_cursor{authorizer_receipt_state->cursor};
    if (fixture.args.durable_best) {
        const auto& best{*fixture.args.durable_best};
        if (!fixture.chain.SetExactHash(best.height, best.block_hash)) {
            return std::nullopt;
        }
        const auto& durable_cursor{best.accepted_btcc_cursor};
        if (!IsDurableBTCCursorMonotonic(durable_cursor, previous_cursor)) {
            // An accepted ADVANCE is carried ten blocks later. The intervening
            // KEEP must retain that durable cursor, not regress to the receipt
            // index. This is SelectCurrentChainLockBTCC's pre-carrier branch.
            const int64_t carrier_height{
                static_cast<int64_t>(durable_cursor.sys_height) +
                fixture.args.btcc_config.nevm_injection_lag};
            if (*target_height >= carrier_height ||
                *authorizer_receipt_state != best.btcc_receipt_state ||
                (!previous_cursor.IsNull() &&
                 previous_cursor.sys_height == durable_cursor.sys_height) ||
                !fixture.chain.SetExactHash(durable_cursor.sys_height,
                                            durable_cursor.sys_hash)) {
                return std::nullopt;
            }
            fixture.chain.indices[durable_cursor.sys_height]
                .btcpPrevCommitment = durable_cursor.btc_hash;
            previous_cursor = durable_cursor;
        }
    }
    const auto selection{SelectBTCCForChainLock(
        fixture.args.btcc_config,
        fixture.chain.indices[*target_height], previous_cursor)};
    if (!selection ||
        (!fixture.args.chainlock_step &&
         (selection->cursor != target_cursor ||
          selection->advance != BTCCAdvance::ADVANCE))) {
        return std::nullopt;
    }
    const auto statement{MakeChainLockStatement(
        fixture, *target_height, fixture.args.response_hash,
        fixture.args.response_predecessor_height,
        fixture.args.response_predecessor_hash,
        previous_cursor, selection->cursor, selection->advance,
        *authorizer_receipt_state,
        authorizer.payment_audit_receipt_state,
        authorizer.payment_probation_state_hash, authorizer)};
    return statement
        ? SignAndVerifyChainLock(fixture, statement->context)
        : std::nullopt;
}

std::optional<PaymentAuditArtifacts> BuildPaymentAuditArtifacts(
    PaymentAuditFixture& fixture)
{
    const PaymentAuditScheduleConfig schedule_config{
        fixture.args.build_config.schedule, fixture.args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, fixture.args.audit_epoch)};
    if (!schedule || !fixture.args.authorizer) {
        return std::nullopt;
    }
    const auto& authorizer{*fixture.args.authorizer};
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
                                    fixture.args.seal_hash) ||
        !fixture.chain.SetExactHash(authorizer.height,
                                    authorizer.block_hash) ||
        (!authorizer.accepted_btcc_cursor.IsNull() &&
         !fixture.chain.SetExactHash(
             authorizer.accepted_btcc_cursor.sys_height,
             authorizer.accepted_btcc_cursor.sys_hash)) ||
        (!authorizer.btcc_receipt_state.cursor.IsNull() &&
         !fixture.chain.SetExactHash(
             authorizer.btcc_receipt_state.cursor.sys_height,
             authorizer.btcc_receipt_state.cursor.sys_hash))) {
        return std::nullopt;
    }
    fixture.chain.indices[response_height].btcpPrevCommitment =
        fixture.args.response_btc_hash;
    fixture.chain.indices[anchor_height].btcpPrevCommitment =
        fixture.args.anchor_btc_hash;
    if (!authorizer.accepted_btcc_cursor.IsNull()) {
        fixture.chain.indices[authorizer.accepted_btcc_cursor.sys_height]
            .btcpPrevCommitment = authorizer.accepted_btcc_cursor.btc_hash;
    }
    if (!authorizer.btcc_receipt_state.cursor.IsNull()) {
        fixture.chain.indices[authorizer.btcc_receipt_state.cursor.sys_height]
            .btcpPrevCommitment =
                authorizer.btcc_receipt_state.cursor.btc_hash;
    }
    const auto authorizer_receipt_state{ApplyChainLockReceiptState(
        fixture, authorizer,
        fixture.args.authorizer_receipt_carrier_hash)};
    if (!authorizer_receipt_state) return std::nullopt;

    const auto empty_probation_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_probation_hash ||
        authorizer.payment_probation_state_hash !=
            *empty_probation_hash) {
        return std::nullopt;
    }
    const BTCCursor response_cursor{
        response_height, fixture.args.response_hash,
        fixture.args.response_btc_hash};
    const BTCCursor anchor_cursor{
        anchor_height, fixture.args.anchor_hash,
        fixture.args.anchor_btc_hash};
    const BTCCursor indexed_cursor{authorizer_receipt_state->cursor};
    BTCCValidationError btcc_error{BTCCValidationError::NONE};
    if (!ValidateBTCCursorTransition(
            fixture.args.btcc_config,
            fixture.chain.indices[response_height],
            indexed_cursor,
            response_cursor, BTCCAdvance::ADVANCE, &btcc_error)) {
        return std::nullopt;
    }
    const auto response_statement{MakeChainLockStatement(
        fixture, response_height, fixture.args.response_hash,
        fixture.args.response_predecessor_height,
        fixture.args.response_predecessor_hash,
        indexed_cursor, response_cursor,
        BTCCAdvance::ADVANCE, *authorizer_receipt_state,
        authorizer.payment_audit_receipt_state,
        *empty_probation_hash, authorizer)};
    if (!response_statement) {
        return std::nullopt;
    }
    const auto response_chainlock{SignAndVerifyChainLock(
        fixture, response_statement->context)};
    if (!response_chainlock) {
        return std::nullopt;
    }
    const auto response_receipt_state{ApplyChainLockReceiptState(
        fixture, response_chainlock->statement,
        fixture.args.response_receipt_carrier_hash)};
    if (!response_receipt_state ||
        response_receipt_state->cursor != response_cursor) {
        return std::nullopt;
    }
    const auto anchor_selection{SelectBTCCForChainLock(
        fixture.args.btcc_config,
        fixture.chain.indices[anchor_height], response_cursor)};
    if (!anchor_selection || anchor_selection->cursor != anchor_cursor ||
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

    const auto anchor_statement{MakeChainLockStatement(
        fixture, anchor_height, fixture.args.anchor_hash,
        fixture.args.anchor_predecessor_height,
        fixture.args.anchor_predecessor_hash, response_cursor,
        anchor_selection->cursor, anchor_selection->advance,
        *response_receipt_state,
        response_chainlock->statement.payment_audit_receipt_state,
        response_chainlock->statement.payment_probation_state_hash,
        response_chainlock->statement)};
    if (!anchor_statement) {
        return std::nullopt;
    }
    const auto anchor_chainlock{SignAndVerifyChainLock(
        fixture, anchor_statement->context)};
    if (!anchor_chainlock) {
        return std::nullopt;
    }

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
        fixture.args.btcc_config,
        anchor_chainlock->statement.previous_chainlock_height,
        seed_carrier_height,
        fixture.args.seed_carrier_hash,
        anchor_chainlock->statement.btcc_receipt_state,
        fixture.args.seed_receipt)};
    if (!btcc_receipt_state) {
        return std::nullopt;
    }

    const auto seal_statement{MakeChainLockStatement(
        fixture, seal_height, fixture.args.seal_hash,
        fixture.args.seal_predecessor_height,
        fixture.args.seal_predecessor_hash, anchor_cursor, anchor_cursor,
        BTCCAdvance::KEEP, *btcc_receipt_state,
        anchor_chainlock->statement.payment_audit_receipt_state,
        anchor_chainlock->statement.payment_probation_state_hash,
        anchor_chainlock->statement)};
    if (!seal_statement) {
        return std::nullopt;
    }
    const auto seal_chainlock{SignAndVerifyChainLock(
        fixture, seal_statement->context)};
    if (!seal_chainlock) {
        return std::nullopt;
    }
    const auto post_rosters{BuildPaymentAuditRosters(
        fixture, post_height,
        seal_chainlock->statement.roster_beacons.active)};
    if (!post_rosters ||
        response_statement->context->Rosters().back().descriptor.epoch !=
            fixture.args.audit_epoch) {
        return std::nullopt;
    }

    const auto& subject{
        response_statement->context->Rosters().back()};
    const uint256 subject_descriptor_hash{GetPaymentAuditDescriptorHash(
        fixture.args.genesis_hash, subject.descriptor)};
    const auto anchor_seed{
        PaymentAuditSeedPointFromBTCCReceipt(fixture.args.seed_receipt)};
    if (!anchor_seed) {
        return std::nullopt;
    }
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
    commitment.previous_probation_state_hash =
        seal_chainlock->statement.payment_probation_state_hash;
    const PaymentAuditStatement audit_statement{
        commitment, seal_chainlock->statement};
    if (!audit_statement.IsStructurallyValid()) {
        return std::nullopt;
    }

    QuorumBitmap observed{commitment.subject_valid_members};
    std::optional<std::size_t> unobserved_index;
    const std::size_t valid_count{CountSet(observed)};
    const std::size_t target_online_count{QUORUM_MIN_VALID - 1};
    std::size_t removed{0};
    if (valid_count < QUORUM_MIN_VALID) {
        return std::nullopt;
    }
    for (std::size_t member{0};
         member < QUORUM_SIZE &&
         removed < valid_count - target_online_count;
         ++member) {
        if (IsBitSetLocal(observed, member)) {
            if (!unobserved_index) unobserved_index = member;
            ClearBitLocal(observed, member);
            ++removed;
        }
    }
    if (!unobserved_index || CountSet(observed) != target_online_count) {
        return std::nullopt;
    }
    const auto audit{SignAndVerifyPaymentAudit(
        fixture, audit_statement, *seal_chainlock,
        seal_statement->context, observed)};
    if (!audit) {
        return std::nullopt;
    }
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
    const RosterBeaconSeed* subject_beacon{nullptr};
    for (const auto& seed : seal_chainlock->statement.roster_beacons.active
                                .seeds) {
        if (seed.epoch == receipt.epoch) subject_beacon = &seed;
    }
    if (!subject_beacon) {
        return std::nullopt;
    }
    receipt.subject_roster_beacon = *subject_beacon;
    receipt.online_members = classification->online_members;
    const auto receipt_state{ApplyPaymentAuditReceipt(
        fixture.args.genesis_hash,
        seal_chainlock->statement.payment_audit_receipt_state, receipt)};
    if (!receipt.IsStructurallyValid() || !receipt_state) {
        return std::nullopt;
    }
    if (!ValidatePlannedChildUsage(
            fixture.args.build_config.schedule,
            {{response_height,
              response_statement->context->RostersPtr()},
             {anchor_height,
              anchor_statement->context->RostersPtr()},
             {seal_height, seal_statement->context->RostersPtr()},
             {post_height, post_rosters->RostersPtr()}},
            fixture.args.audit_epoch, seal_height,
            seal_statement->context->RostersPtr())) {
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

bool ReadAuthorizingChainLock(
    const fs::path& path,
    std::optional<ChainLockStatement>& statement,
    std::string& error)
{
    const auto [read_ok, contents]{ReadBinaryFile(
        path, FinalChainLock::WIRE_SIZE + 1)};
    if (!path.is_absolute() || !read_ok ||
        contents.size() != FinalChainLock::WIRE_SIZE) {
        error = "invalid authorizing ChainLock file";
        return false;
    }
    try {
        DataStream stream{MakeUCharSpan(contents)};
        const FinalChainLock chainlock{
            ReadFinalChainLock(stream, contents.size())};
        if (!stream.empty() || !chainlock.statement.IsStructurallyValid()) {
            error = "invalid authorizing ChainLock encoding";
            return false;
        }
        statement = chainlock.statement;
        return true;
    } catch (const std::exception&) {
        error = "invalid authorizing ChainLock encoding";
        return false;
    }
}

std::optional<GeneratorArguments> ParseArguments(int argc, char* argv[],
                                                 std::string& error)
{
    if (argc != 23 && argc != 24) {
        error =
            "usage: pq_chainlock_fixture SNAPSHOT_OUT SHARES_OUT GENESIS "
            "TARGET_HEIGHT TARGET_HASH PREDECESSOR_HEIGHT PREDECESSOR_HASH "
            "TARGET_BTC_HASH ANCHOR_BTC_HEIGHT FUTURE_BTC_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BASE0 BASE1 BASE2 BASE3 SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3 "
            "[AUTHORIZER_CLSIG]";
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
    args.target_btc_hash = uint256S(argv[8]);
    int32_t anchor_btc_height{0};
    args.future_btc_hash = uint256S(argv[10]);
    int32_t epoch_origin{0};
    uint32_t registration_cutoff{0};
    uint32_t snapshot_lag{0};
    uint32_t future_horizon{0};
    if (!ParseInt32(argv[4], &target_height) ||
        !ParseInt32(argv[6], &predecessor_height) ||
        !ParseInt32(argv[9], &anchor_btc_height) ||
        !ParseInt32(argv[11], &epoch_origin) ||
        !ParseUInt32(argv[12], &registration_cutoff) ||
        !ParseUInt32(argv[13], &snapshot_lag) ||
        !ParseUInt32(argv[14], &future_horizon) ||
        args.genesis_hash.IsNull() || args.target_hash.IsNull() ||
        args.predecessor_hash.IsNull() || args.target_btc_hash.IsNull() ||
        args.future_btc_hash.IsNull()) {
        error = "invalid full-dimension fixture argument";
        return std::nullopt;
    }
    args.target_height = target_height;
    args.predecessor_height = predecessor_height;
    args.anchor_btc_height = anchor_btc_height;
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        args.base_hashes[slot] = uint256S(argv[15 + slot]);
        args.snapshot_hashes[slot] = uint256S(argv[19 + slot]);
        if (args.base_hashes[slot].IsNull() ||
            args.snapshot_hashes[slot].IsNull()) {
            error = "null branch hash in full-dimension fixture";
            return std::nullopt;
        }
    }
    if (argc == 24) {
        if (!ReadAuthorizingChainLock(
                fs::u8path(argv[23]), args.authorizer, error)) {
            return std::nullopt;
        }
    }
    const auto next_target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.predecessor_height)};
    if (!args.snapshot_output.is_absolute() ||
        !args.shares_output.is_absolute() ||
        !args.build_config.IsValid() ||
        args.anchor_btc_height < 0 ||
        args.predecessor_height < 0 ||
        (args.authorizer &&
         (args.authorizer->height < 0 ||
          args.authorizer->height > args.predecessor_height)) ||
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
    const bool chainlock_step{argc > 1 &&
        std::string_view{argv[1]} == "chainlock-step"};
    const int FIXED_ARGUMENT_COUNT{chainlock_step ? 22 : 19};
    if (argc < FIXED_ARGUMENT_COUNT +
                   static_cast<int>(2 * ACTIVE_QUORUMS) ||
        (argc - FIXED_ARGUMENT_COUNT) % 2 != 0) {
        error =
            "usage: pq_chainlock_fixture payment-audit-prefix SNAPSHOT_OUT "
            "BUNDLE_OUT GENESIS BRANCH_ANCHOR_HEIGHT BRANCH_ANCHOR_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BTCC_ORIGIN AUDIT_EPOCH TARGET_PREDECESSOR_HEIGHT "
            "TARGET_PREDECESSOR_HASH TARGET_HASH TARGET_BTC_HASH "
            "AUTHORIZER_RECEIPT_CARRIER_HASH "
            "BASE... SNAPSHOT... AUTHORIZER_CLSIG";
        return std::nullopt;
    }

    PaymentAuditArguments args;
    args.chainlock_step = chainlock_step;
    args.epoch_count = static_cast<std::size_t>(
        (argc - FIXED_ARGUMENT_COUNT) / 2);
    if (args.epoch_count < ACTIVE_QUORUMS ||
        args.epoch_count > MAX_FIXTURE_EPOCHS) {
        error = "invalid payment audit prefix epoch count";
        return std::nullopt;
    }
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
        !ParseInt32(argv[13], &args.response_predecessor_height)) {
        error = "invalid payment audit prefix numeric argument";
        return std::nullopt;
    }
    args.branch_anchor_hash = uint256S(argv[6]);
    args.response_predecessor_hash = uint256S(argv[14]);
    args.response_hash = uint256S(argv[15]);
    args.response_btc_hash = uint256S(argv[16]);
    args.authorizer_receipt_carrier_hash = uint256S(argv[17]);
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    args.btcc_config.candidate_origin = btcc_origin;
    constexpr std::size_t BASE_ARGUMENT{18};
    for (std::size_t epoch{0}; epoch < args.epoch_count; ++epoch) {
        args.base_hashes[epoch] = uint256S(argv[BASE_ARGUMENT + epoch]);
        args.snapshot_hashes[epoch] = uint256S(
            argv[BASE_ARGUMENT + args.epoch_count + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit prefix branch hash";
            return std::nullopt;
        }
    }
    if (!ReadAuthorizingChainLock(
            fs::u8path(argv[BASE_ARGUMENT + 2 * args.epoch_count]),
            args.authorizer, error)) {
        return std::nullopt;
    }
    if (chainlock_step) {
        if (!ReadAuthorizingChainLock(
                fs::u8path(argv[BASE_ARGUMENT + 2 * args.epoch_count + 1]),
                args.receipt_authorizer, error)) {
            return std::nullopt;
        }
        args.receipt_authorizer_carrier_hash = uint256S(
            argv[BASE_ARGUMENT + 2 * args.epoch_count + 2]);
        if (args.receipt_authorizer_carrier_hash.IsNull()) {
            error = "null ChainLock step receipt carrier";
            return std::nullopt;
        }
        if (!ReadAuthorizingChainLock(
                fs::u8path(argv[BASE_ARGUMENT + 2 * args.epoch_count + 3]),
                args.durable_best, error) ||
            args.durable_best->height > args.response_predecessor_height) {
            error = "invalid ChainLock step durable best";
            return std::nullopt;
        }
    }

    const PaymentAuditScheduleConfig schedule_config{
        args.build_config.schedule, args.btcc_config};
    const auto schedule{BuildPaymentAuditEpochSchedule(
        schedule_config, args.audit_epoch)};
    const auto step_epoch_end{EpochEndHeightExclusive(
        args.build_config.schedule, args.audit_epoch)};
    const int32_t max_tip{
        chainlock_step && step_epoch_end ? *step_epoch_end - 1 : schedule
            ? schedule->anchor_height +
                  static_cast<int32_t>(args.btcc_config.nevm_injection_lag)
            : -1};
    const auto first_active{ActiveEpochsAtHeight(
        args.build_config.schedule, args.branch_anchor_height)};
    const auto last_active{ActiveEpochsAtHeight(
        args.build_config.schedule, max_tip)};
    const auto target{NextEligibleChainLockTargetHeight(
        args.build_config.schedule, args.response_predecessor_height)};
    if (!args.snapshot_output.is_absolute() ||
        !args.bundle_output.is_absolute() || args.genesis_hash.IsNull() ||
        args.branch_anchor_hash.IsNull() ||
        args.response_predecessor_hash.IsNull() ||
        args.response_hash.IsNull() ||
        args.response_btc_hash.IsNull() || !args.build_config.IsValid() ||
        !schedule_config.IsValid() || !schedule || !first_active ||
        !last_active || first_active->front().epoch != 0 ||
        last_active->back().epoch != args.epoch_count - 1 ||
        static_cast<uint64_t>(args.audit_epoch) + 1 != args.epoch_count ||
        !target ||
        (chainlock_step
             ? static_cast<int64_t>(*target) +
                       args.build_config.schedule.sign_lag > max_tip
             : (*target != schedule->rows.back().response_height &&
                *target != schedule->anchor_height)) ||
        !args.authorizer ||
        (args.authorizer->btcc_advance == BTCCAdvance::ADVANCE &&
         args.authorizer_receipt_carrier_hash.IsNull()) ||
        args.authorizer->height > args.response_predecessor_height ||
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
        args.chainlock_step
            ? *EpochEndHeightExclusive(args.build_config.schedule,
                                      args.audit_epoch) - 1
            : schedule->anchor_height +
                  static_cast<int32_t>(args.btcc_config.nevm_injection_lag)};
    auto fixture{std::make_unique<PaymentAuditFixture>(
        args, max_tip, args.epoch_count)};
    const auto next_snapshot{RegistrationCutoffHeight(
        args.build_config.schedule, args.audit_epoch + 1,
        args.build_config.roster_snapshot_lag_blocks)};
    const uint32_t authorizer_newest{
        args.authorizer->roster_beacons.active.seeds.back().epoch};
    const bool rotates{authorizer_newest != args.audit_epoch};
    const bool observes_next{
        next_snapshot && args.authorizer->height >= *next_snapshot};
    const bool retains_nonempty_next{
        !rotates && args.authorizer->roster_beacons.next.state !=
                        RosterBeaconState::EMPTY};
    if (args.chainlock_step || observes_next || retains_nonempty_next) {
        if (args.epoch_count == MAX_FIXTURE_EPOCHS && !args.chainlock_step) {
            throw std::runtime_error(
                "payment audit prefix needs an auxiliary snapshot");
        }
        // A READY next-epoch seed is evaluated as the recovery source before
        // it rotates into the active roster window.
        fixture->snapshot_fixture.snapshots.resize(args.epoch_count + 1);
    }
    if (!GenerateMemberKeys(fixture->public_keys, fixture->secret_keys,
                            fixture->member_indices,
                            fixture->snapshot_fixture.snapshots.size()) ||
        !PopulatePaymentAuditSnapshots(*fixture)) {
        throw std::runtime_error(
            "unable to construct payment audit prefix fixture");
    }
    const auto artifact{BuildPaymentAuditPrefixArtifact(*fixture)};
    if (!artifact) {
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
            args.bundle_output, args.genesis_hash, *artifact, error)) {
        throw std::runtime_error(error);
    }
    return 0;
}

std::optional<PaymentAuditArguments> ParsePaymentAuditArguments(
    int argc, char* argv[], std::string& error)
{
    constexpr std::size_t BASE_ARGUMENT{28};
    constexpr std::size_t SNAPSHOT_ARGUMENT{
        BASE_ARGUMENT + MAX_FIXTURE_EPOCHS};
    constexpr std::size_t AUTHORIZER_ARGUMENT{
        SNAPSHOT_ARGUMENT + MAX_FIXTURE_EPOCHS};
    if (argc != static_cast<int>(AUTHORIZER_ARGUMENT + 1)) {
        error =
            "usage: pq_chainlock_fixture payment-audit SNAPSHOT_OUT "
            "BUNDLE_OUT GENESIS BRANCH_ANCHOR_HEIGHT BRANCH_ANCHOR_HASH "
            "EPOCH_ORIGIN REGISTRATION_CUTOFF SNAPSHOT_LAG FUTURE_HORIZON "
            "BTCC_ORIGIN AUDIT_EPOCH RESPONSE_PREDECESSOR_HEIGHT "
            "RESPONSE_PREDECESSOR_HASH RESPONSE_HASH RESPONSE_BTC_HASH "
            "ANCHOR_PREDECESSOR_HEIGHT ANCHOR_PREDECESSOR_HASH ANCHOR_HASH "
            "ANCHOR_BTC_HASH SEAL_PREDECESSOR_HEIGHT "
            "SEAL_PREDECESSOR_HASH SEAL_HASH SEED_CARRIER_HASH "
            "SEED_RECEIPT_HEX AUTHORIZER_RECEIPT_CARRIER_HASH "
            "RESPONSE_RECEIPT_CARRIER_HASH "
            "BASE0 BASE1 BASE2 BASE3 BASE4 BASE5 "
            "SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3 SNAPSHOT4 SNAPSHOT5 "
            "AUTHORIZER_CLSIG";
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
    args.authorizer_receipt_carrier_hash = uint256S(argv[26]);
    args.response_receipt_carrier_hash = uint256S(argv[27]);
    args.build_config.schedule.epoch_origin = epoch_origin;
    args.build_config.registration_cutoff_blocks = registration_cutoff;
    args.build_config.roster_snapshot_lag_blocks = snapshot_lag;
    args.build_config.future_horizon_epochs = future_horizon;
    args.btcc_config.candidate_origin = btcc_origin;
    for (std::size_t epoch{0}; epoch < MAX_FIXTURE_EPOCHS; ++epoch) {
        args.base_hashes[epoch] = uint256S(argv[BASE_ARGUMENT + epoch]);
        args.snapshot_hashes[epoch] =
            uint256S(argv[SNAPSHOT_ARGUMENT + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit branch hash";
            return std::nullopt;
        }
    }
    if (!ReadAuthorizingChainLock(
            fs::u8path(argv[AUTHORIZER_ARGUMENT]), args.authorizer,
            error)) {
        return std::nullopt;
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
        args.response_receipt_carrier_hash.IsNull() ||
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
        !args.authorizer ||
        (args.authorizer->btcc_advance == BTCCAdvance::ADVANCE &&
         args.authorizer_receipt_carrier_hash.IsNull()) ||
        args.authorizer->height > args.response_predecessor_height ||
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
            "unable to construct payment audit fixture");
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
    constexpr std::size_t BASE_ARGUMENT{19};
    constexpr std::size_t SNAPSHOT_ARGUMENT{
        BASE_ARGUMENT + MAX_FIXTURE_EPOCHS};
    constexpr std::size_t AUTHORIZER_ARGUMENT{
        SNAPSHOT_ARGUMENT + MAX_FIXTURE_EPOCHS};
    if (argc != static_cast<int>(AUTHORIZER_ARGUMENT + 1)) {
        error =
            "usage: pq_chainlock_fixture payment-audit-post BUNDLE_OUT "
            "GENESIS TARGET_HEIGHT TARGET_HASH PREDECESSOR_HEIGHT "
            "PREDECESSOR_HASH CURSOR_HEIGHT CURSOR_SYS_HASH "
            "CURSOR_BTC_HASH EPOCH_ORIGIN REGISTRATION_CUTOFF "
            "SNAPSHOT_LAG FUTURE_HORIZON BTCC_ORIGIN "
            "BTCC_RECEIPT_STATE_HEX PAYMENT_RECEIPT_STATE_HEX "
            "PROBATION_STATE_HASH "
            "BASE0 BASE1 BASE2 BASE3 BASE4 BASE5 "
            "SNAPSHOT0 SNAPSHOT1 SNAPSHOT2 SNAPSHOT3 SNAPSHOT4 SNAPSHOT5 "
            "AUTHORIZER_CLSIG";
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
        args.base_hashes[epoch] = uint256S(argv[BASE_ARGUMENT + epoch]);
        args.snapshot_hashes[epoch] =
            uint256S(argv[SNAPSHOT_ARGUMENT + epoch]);
        if (args.base_hashes[epoch].IsNull() ||
            args.snapshot_hashes[epoch].IsNull()) {
            error = "null payment audit post branch hash";
            return std::nullopt;
        }
    }
    if (!ReadAuthorizingChainLock(
            fs::u8path(argv[AUTHORIZER_ARGUMENT]), args.authorizer,
            error)) {
        return std::nullopt;
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
        !args.authorizer ||
        args.authorizer->height > args.predecessor_height ||
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
    if (!args.authorizer) {
        throw std::runtime_error(
            "missing authorizing payment-audit ChainLock");
    }
    PaymentAuditArguments fixture_args;
    fixture_args.genesis_hash = args.genesis_hash;
    fixture_args.branch_anchor_height = args.predecessor_height;
    fixture_args.branch_anchor_hash = args.predecessor_hash;
    fixture_args.response_predecessor_height = args.predecessor_height;
    fixture_args.build_config = args.build_config;
    fixture_args.btcc_config = args.btcc_config;
    fixture_args.base_hashes = args.base_hashes;
    fixture_args.snapshot_hashes = args.snapshot_hashes;
    fixture_args.authorizer = args.authorizer;
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
                                     args.target_hash) ||
        !fixture->chain.SetExactHash(args.authorizer->height,
                                     args.authorizer->block_hash)) {
        throw std::runtime_error(
            "unable to construct post-audit ChainLock fixture");
    }
    fixture->chain.indices[args.cursor.sys_height].btcpPrevCommitment =
        args.cursor.btc_hash;
    BTCCValidationError btcc_error{BTCCValidationError::NONE};
    const bool valid_cursor_transition{ValidateBTCCursorTransition(
        args.btcc_config, fixture->chain.indices[args.target_height],
        args.cursor, args.cursor, BTCCAdvance::KEEP, &btcc_error)};
    const auto statement{valid_cursor_transition
        ? MakeChainLockStatement(
        *fixture, args.target_height, args.target_hash,
        args.predecessor_height, args.predecessor_hash, args.cursor,
        args.cursor, BTCCAdvance::KEEP, args.btcc_receipt_state,
        args.payment_audit_receipt_state,
        args.payment_probation_state_hash, *args.authorizer)
        : std::nullopt};
    const auto chainlock{statement ? SignAndVerifyChainLock(
        *fixture, statement->context)
        : std::nullopt};
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

int Generate(const GeneratorArguments& args, bool retain_epoch_snapshots = false)
{
    auto fixture{std::make_unique<FullDimensionFixture>(args)};
    if (!GenerateMemberKeys(*fixture)) {
        throw std::runtime_error(
            "unable to generate full-dimension ChainLock member keys");
    }
    if (!BuildSnapshotsAndRosters(*fixture)) {
        throw std::runtime_error(
            "unable to build full-dimension ChainLock rosters");
    }
    if (!BuildAndSignShares(*fixture)) {
        throw std::runtime_error(
            "unable to sign full-dimension ChainLock shares");
    }

    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{ChainLockCollector::Create(
        fixture->prepared_context, &collection_error)};
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
    auto prepared{PrepareFinalChainLockVerification(
        final, *fixture->prepared_context, &verification_error)};
    if (!prepared ||
        !verifier.VerifyChecks(std::move(prepared->checks)) ||
        verification_error != ChainLockVerificationError::NONE) {
        throw std::runtime_error(
            "production verifier rejected generated certificate");
    }

    if (retain_epoch_snapshots) {
        const auto epoch{EpochForHeight(args.build_config.schedule,
                                       args.target_height)};
        const auto epoch_end{epoch ? EpochEndHeightExclusive(
            args.build_config.schedule, *epoch) : std::nullopt};
        const auto auxiliary_height{epoch ? RegistrationCutoffHeight(
            args.build_config.schedule, *epoch + 1,
            args.build_config.roster_snapshot_lag_blocks) : std::nullopt};
        uint256 auxiliary_hash;
        if (auxiliary_height) {
            for (const auto& point : fixture->snapshot_fixture.quorum_bases) {
                if (point.height == *auxiliary_height) {
                    auxiliary_hash = point.block_hash;
                }
            }
            for (const auto& snapshot : fixture->snapshot_fixture.snapshots) {
                if (snapshot.branch_point.height == *auxiliary_height) {
                    auxiliary_hash = snapshot.branch_point.block_hash;
                }
            }
        }
        if (!epoch || !epoch_end || !auxiliary_height ||
            auxiliary_hash.IsNull()) {
            throw std::runtime_error("missing streaming auxiliary snapshot");
        }
        auto& auxiliary{fixture->snapshot_fixture.snapshots.emplace_back()};
        auxiliary.branch_point = {*auxiliary_height, auxiliary_hash};
        auxiliary.state.deterministic_mns = Snapshot(
            *auxiliary_height, auxiliary_hash);
        auto states{std::make_shared<std::vector<OperatorKeyState>>()};
        states->reserve(QUORUM_SIZE);
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            states->push_back(MakeOperatorState(
                args.genesis_hash, args.build_config, fixture->public_keys,
                NonNullHash(10'000 + member), *epoch + 1,
                *auxiliary_height, member));
        }
        auxiliary.state.operator_key_states = std::move(states);
        fixture->snapshot_fixture.max_active_tip_height = *epoch_end - 1;
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

struct CatchupFixtureState {
    test::QuorumSnapshotFixture fixture;
    std::vector<scheduled_wots::PublicKey> public_keys;
    std::vector<std::shared_ptr<const scheduled_wots::SecretKey>> secret_keys;
    std::map<uint256, std::size_t> member_indices;
    uint32_t first_epoch{0};
    uint32_t last_epoch{0};
};

std::optional<CatchupFixtureState>& CachedCatchupFixture()
{
    static std::optional<CatchupFixtureState> fixture;
    return fixture;
}

std::map<uint32_t, test::SyntheticChildAuthorization> CatchupAuthorizations(
    const uint256& genesis_hash,
    const std::vector<scheduled_wots::PublicKey>& public_keys,
    std::size_t member_index, uint32_t first_epoch, uint32_t last_epoch)
{
    const uint256 pro_tx_hash{NonNullHash(10'000 + member_index)};
    ChildKeyTreeCommitment commitment;
    commitment.generation = 1;
    commitment.first_epoch = 0;
    const auto tree_id{GetChildKeyTreeId(
        genesis_hash, pro_tx_hash, commitment.generation, commitment.first_epoch)};
    if (!tree_id || first_epoch > last_epoch ||
        last_epoch >= MAX_CATCHUP_FIXTURE_EPOCHS) {
        throw std::runtime_error("invalid catch-up helper child-tree window");
    }
    commitment.tree_id = *tree_id;
    const ChildKeyTreeConfig config{
        genesis_hash, *tree_id, commitment.generation,
        commitment.first_epoch, commitment.depth};
    std::map<uint32_t, test::SyntheticChildAuthorization> authorizations;
    std::map<uint32_t, uint256> nodes;
    for (uint32_t epoch{first_epoch}; epoch <= last_epoch; ++epoch) {
        auto& proof{authorizations[epoch].proof};
        if (member_index < QUORUM_MIN_VALID) {
            proof.public_key = public_keys.at(ChildKeyIndex(epoch, member_index));
        } else {
            const uint256 material{NonNullHash(
                static_cast<uint64_t>(epoch) * QUORUM_SIZE + member_index + 1,
                0x524f4f54)};
            std::copy(material.begin(), material.end(), proof.public_key.begin());
        }
        nodes.emplace(epoch, GetChildKeyTreeLeafHash(config, epoch, proof.public_key));
    }
    // Every participating epoch shares one committed root. Omitted subtrees
    // are synthetic, but paths between live leaves and all WOTS signatures
    // are checked by the ordinary production verifier.
    for (uint16_t level{1}; level <= config.depth; ++level) {
        const auto node_hash = [&](uint32_t index) {
            const auto found{nodes.find(index)};
            return found != nodes.end() ? found->second : test::SyntheticHash(
                "SYS_PQ_CATCHUP_HELPER_SUBTREE_V1", genesis_hash, pro_tx_hash,
                (static_cast<uint64_t>(first_epoch) << 32) | index, level);
        };
        for (auto& [epoch, authorization] : authorizations) {
            authorization.proof.siblings[level - 1] =
                node_hash((epoch >> (level - 1)) ^ 1U);
        }
        std::map<uint32_t, uint256> parents;
        for (const auto& [index, hash] : nodes) {
            const uint32_t parent{index >> 1};
            parents.emplace(parent, GetChildKeyTreeNodeHash(
                config, level, node_hash(parent * 2), node_hash(parent * 2 + 1)));
        }
        nodes = std::move(parents);
    }
    commitment.root = nodes.at(0);
    for (auto& [epoch, authorization] : authorizations) {
        authorization.record = FrozenChildRootRecord{
            pro_tx_hash, first_epoch + 1, epoch, commitment};
        if (!VerifyCommittedChildKeyProof(
                genesis_hash, commitment, epoch, authorization.proof)) {
            throw std::runtime_error("invalid catch-up helper child proof");
        }
    }
    return authorizations;
}

void PrepareCatchupOperator(
    test::QuorumSnapshotFixture& fixture,
    uint32_t first_epoch,
    uint32_t last_epoch,
    const fs::path& output,
    const CService& service)
{
    if (!output.is_absolute() || !service.IsIPv4() ||
        !service.IsLocal() || service.GetPort() == 0) {
        throw std::runtime_error("invalid catch-up operator output or service");
    }
    slhdsa::KeyGenerationSeed global_seed{};
    for (std::size_t i{0}; i < global_seed.size(); ++i) {
        global_seed[i] = static_cast<uint8_t>(0x51 + i);
    }
    auto global_key{slhdsa::GenerateSecretKey(global_seed)};
    memory_cleanse(global_seed.data(), global_seed.size());
    std::array<uint8_t, slhdsa::SECRET_KEY_SIZE> encoded_global_key{};
    if (!global_key || !global_key->Export(encoded_global_key)) {
        throw std::runtime_error("unable to derive catch-up operator SLH key");
    }
    ChainLockMasterSeed master_seed{};
    for (std::size_t i{0}; i < master_seed.size(); ++i) {
        master_seed[i] = static_cast<uint8_t>(0xa1 + i);
    }
    const std::string master_seed_hex{HexStr(master_seed)};
    LocalOperatorKeyManager key_manager{
        std::move(*global_key), std::move(master_seed)};
    const uint256 pro_tx_hash{NonNullHash(10'000)};
    ChildKeyTreeCommitment commitment;
    commitment.generation = 1;
    commitment.first_epoch = 0;
    const auto tree_id{GetChildKeyTreeId(
        fixture.genesis_hash, pro_tx_hash, commitment.generation,
        commitment.first_epoch)};
    if (!tree_id) throw std::runtime_error("invalid catch-up operator tree ID");
    commitment.tree_id = *tree_id;
    const ChildKeyTreeConfig config{
        fixture.genesis_hash, *tree_id, commitment.generation,
        commitment.first_epoch, commitment.depth};
    const std::size_t leaf_count{config.LeafCount()};
    std::vector<uint256> nodes(2 * leaf_count - 1);
    const std::size_t leaf_base{leaf_count - 1};
    // Unused fixture leaves need no expensive private keys. The participating
    // epochs use the daemon's exact independent-seed KDF, and its ordinary
    // cache loader verifies this entire public tree before producing proofs.
    for (std::size_t leaf{0}; leaf < leaf_count; ++leaf) {
        ChildPublicKey public_key{};
        const uint256 material{test::SyntheticHash(
            "SYS_PQ_CATCHUP_UNUSED_CHILD_V1", fixture.genesis_hash,
            pro_tx_hash, leaf, 0)};
        std::copy(material.begin(), material.end(), public_key.begin());
        nodes[leaf_base + leaf] = GetChildKeyTreeLeafHash(
            config, static_cast<uint32_t>(leaf), public_key);
    }
    std::map<uint32_t, ChildPublicKey> live_keys;
    for (uint32_t epoch{first_epoch}; epoch <= last_epoch; ++epoch) {
        auto child{key_manager.DeriveCommittedChildKey(
            fixture.genesis_hash, *tree_id, commitment.generation, epoch)};
        ChildPublicKey public_key{};
        if (!child || !child->GetPublicKey(public_key)) {
            throw std::runtime_error("unable to derive catch-up operator child");
        }
        live_keys.emplace(epoch, public_key);
        nodes[leaf_base + epoch] = GetChildKeyTreeLeafHash(
            config, epoch, public_key);
    }
    for (uint16_t level{1}; level <= config.depth; ++level) {
        const std::size_t parent_count{leaf_count >> level};
        const std::size_t parent_base{parent_count - 1};
        const std::size_t child_base{2 * parent_count - 1};
        for (std::size_t node{0}; node < parent_count; ++node) {
            const std::size_t left{child_base + 2 * node};
            nodes[parent_base + node] = GetChildKeyTreeNodeHash(
                config, level, nodes[left], nodes[left + 1]);
        }
    }
    commitment.root = nodes.front();
    constexpr uint16_t cache_version{1};
    CHashWriter checksum{SER_GETHASH, 0};
    WriteDomain(checksum, "SYS_PQ_CHILD_TREE_CACHE_V1");
    checksum << cache_version << config.genesis_hash << config.tree_id
             << config.generation << config.first_epoch << config.depth
             << commitment.root << static_cast<uint32_t>(nodes.size());
    DataStream cache;
    cache << cache_version << config.genesis_hash << config.tree_id
          << config.generation << config.first_epoch << config.depth
          << commitment.root << static_cast<uint32_t>(nodes.size());
    for (const auto& node : nodes) {
        checksum << node;
        cache << node;
    }
    cache << checksum.GetHash();
    const std::string cache_filename{
        commitment.tree_id.ToString() + "-" +
        std::to_string(commitment.generation) + "-" +
        commitment.root.ToString() + ".dat"};
    const fs::path cache_path{fs::path{output.parent_path()} / fs::u8path(cache_filename)};
    if (!WriteBinaryFile(cache_path, cache.str())) {
        throw std::runtime_error("unable to write catch-up operator public cache");
    }
    const auto loaded{ChildKeyTree::Load(cache_path, config, commitment.root)};
    if (!loaded) throw std::runtime_error("catch-up operator cache failed reload");
    for (const auto& [epoch, public_key] : live_keys) {
        const auto proof{loaded->GetConsensusProof(public_key, epoch)};
        if (!proof || !VerifyCommittedChildKeyProof(
                fixture.genesis_hash, commitment, epoch, *proof)) {
            throw std::runtime_error("catch-up operator cache has invalid live proof");
        }
    }
    auto states{std::make_shared<std::vector<OperatorKeyState>>(
        *fixture.snapshots.at(first_epoch).state.operator_key_states)};
    auto& state{states->at(0)};
    if (state.pro_tx_hash != pro_tx_hash ||
        state.frozen_child_roots.size() != 1 ||
        state.frozen_child_roots.front().epoch != first_epoch) {
        throw std::runtime_error("unexpected catch-up operator frozen identity");
    }
    state.global_key.public_key = key_manager.GetGlobalPublicKey();
    state.global_key.child_key_commitment = commitment;
    state.frozen_child_roots.front().commitment = commitment;
    if (!state.IsStructurallyValid()) {
        throw std::runtime_error("invalid catch-up operator key state");
    }
    fixture.snapshots.at(first_epoch).state.operator_key_states = std::move(states);
    fixture.local_operator = test::FixtureOperatorService{pro_tx_hash, service};
    UniValue result{UniValue::VOBJ};
    result.pushKV("pro_tx_hash", pro_tx_hash.ToString());
    result.pushKV("global_secret_key", HexStr(encoded_global_key));
    result.pushKV("global_public_key", HexStr(key_manager.GetGlobalPublicKey()));
    result.pushKV("chainlock_seed", master_seed_hex);
    result.pushKV("cache_filename", cache_filename);
    result.pushKV("cache_path", fs::PathToString(cache_path));
    result.pushKV("genesis_hash", fixture.genesis_hash.ToString());
    result.pushKV("tree_id", commitment.tree_id.ToString());
    result.pushKV("generation", commitment.generation);
    result.pushKV("tree_first_epoch", commitment.first_epoch);
    result.pushKV("tree_root", commitment.root.ToString());
    result.pushKV("epoch_origin", fixture.build_config.schedule.epoch_origin);
    result.pushKV("first_epoch", first_epoch);
    result.pushKV("last_epoch", last_epoch);
    result.pushKV("service", service.ToStringAddrPort());
    memory_cleanse(encoded_global_key.data(), encoded_global_key.size());
    if (!WriteBinaryFile(output, result.write(2) + "\n")) {
        throw std::runtime_error("unable to write catch-up operator identity");
    }
}

int VerifyCatchupOperatorJournal(int argc, char* argv[])
{
    if (argc != 9) {
        throw std::runtime_error(
            "usage: pq_chainlock_fixture verify-operator-journal JOURNAL_DIR "
            "OPERATOR_JSON GENESIS TARGET_HEIGHT TARGET_HASH SHARES_JSON REPORT_OUT");
    }
    const fs::path journal_path{fs::u8path(argv[2])};
    const fs::path operator_path{fs::u8path(argv[3])};
    const fs::path shares_path{fs::u8path(argv[7])};
    const fs::path report_path{fs::u8path(argv[8])};
    const uint256 genesis_hash{uint256S(argv[4])};
    const uint256 target_hash{uint256S(argv[6])};
    int32_t target_height{-1};
    if (!journal_path.is_absolute() || !operator_path.is_absolute() ||
        !shares_path.is_absolute() || !report_path.is_absolute() || genesis_hash.IsNull() ||
        target_hash.IsNull() || !ParseInt32(argv[5], &target_height) ||
        target_height < 0 || !fs::is_regular_file(journal_path / "CURRENT")) {
        throw std::runtime_error("invalid existing operator journal arguments");
    }
    const fs::path canonical_journal{fs::canonical(journal_path)};
    const fs::path canonical_report{fs::weakly_canonical(report_path)};
    const auto journal_component{std::mismatch(
        canonical_journal.begin(), canonical_journal.end(),
        canonical_report.begin(), canonical_report.end()).first};
    // A report must not alias the evidence being inspected, including
    // through symlinks into the journal or hard links to an existing file.
    if (journal_component == canonical_journal.end() ||
        (fs::exists(report_path) && fs::hard_link_count(report_path) > 1)) {
        throw std::runtime_error("operator journal report aliases protected evidence");
    }
    const auto [read_ok, contents]{ReadBinaryFile(operator_path, 16U << 10)};
    UniValue identity;
    if (!read_ok || !identity.read(contents) || !identity.isObject() ||
        uint256S(identity["genesis_hash"].get_str()) != genesis_hash) {
        throw std::runtime_error("invalid catch-up operator identity document");
    }
    const uint256 pro_tx_hash{uint256S(identity["pro_tx_hash"].get_str())};
    const auto encoded_seed{TryParseHex<uint8_t>(identity["chainlock_seed"].get_str())};
    ChainLockMasterSeed seed{};
    if (!encoded_seed || !ImportChainLockMasterSeed(*encoded_seed, seed)) {
        throw std::runtime_error("invalid catch-up operator child seed");
    }
    ChildKeyTreeCommitment commitment;
    commitment.tree_id = uint256S(identity["tree_id"].get_str());
    commitment.generation = identity["generation"].getInt<uint32_t>();
    commitment.first_epoch = identity["tree_first_epoch"].getInt<uint32_t>();
    commitment.root = uint256S(identity["tree_root"].get_str());
    const auto tree_id{GetChildKeyTreeId(
        genesis_hash, pro_tx_hash, commitment.generation, commitment.first_epoch)};
    const auto config{ChildKeyTreeConfig::FromCommitment(genesis_hash, commitment)};
    const auto tree{config ? ChildKeyTree::Load(
        fs::u8path(identity["cache_path"].get_str()), *config, commitment.root)
                           : std::nullopt};
    if (!tree_id || *tree_id != commitment.tree_id || !tree) {
        throw std::runtime_error("invalid catch-up operator committed public cache");
    }
    ChainLockScheduleConfig schedule;
    schedule.epoch_origin = identity["epoch_origin"].getInt<int32_t>();
    const uint32_t first_epoch{identity["first_epoch"].getInt<uint32_t>()};
    const uint32_t last_epoch{identity["last_epoch"].getInt<uint32_t>()};
    const auto [shares_read, shares_contents]{ReadBinaryFile(shares_path, 32U << 10)};
    UniValue serialized_shares;
    if (!shares_read || !serialized_shares.read(shares_contents) ||
        !serialized_shares.isArray() || serialized_shares.empty() ||
        serialized_shares.size() > ACTIVE_QUORUMS) {
        throw std::runtime_error("invalid captured operator share document");
    }
    std::map<uint32_t, ChainLockShare> captured_shares;
    for (const auto& encoded_share : serialized_shares.getValues()) {
        const auto bytes{TryParseHex<uint8_t>(encoded_share.get_str())};
        if (!bytes || bytes->size() != ChainLockShare::WIRE_SIZE) {
            throw std::runtime_error("invalid captured operator share size");
        }
        DataStream stream{MakeByteSpan(*bytes)};
        ChainLockShare share;
        stream >> share;
        DataStream canonical;
        canonical << share;
        const auto& statement{share.GetStatement()};
        if (!stream.empty() || !share.IsStructurallyValid() ||
            HexStr(MakeUCharSpan(canonical)) != HexStr(*bytes) ||
            statement.height != target_height || statement.block_hash != target_hash ||
            statement.roster_transition != RosterAuthorizationTransitionKind::RECOVER ||
            statement.btcc_advance != BTCCAdvance::KEEP ||
            share.transcript.member_pro_tx_hash != pro_tx_hash ||
            share.transcript.quorum_epoch < first_epoch ||
            share.transcript.quorum_epoch > last_epoch ||
            (!captured_shares.empty() &&
             captured_shares.begin()->second.GetStatement() != statement) ||
            !captured_shares.emplace(share.transcript.quorum_epoch, share).second) {
            throw std::runtime_error("captured operator share does not match the recovery target");
        }
    }
    // Inspect existing rows directly, without constructing a signer journal:
    // that avoids its schema-initialization path and never reserves a leaf.
    CDBWrapper db{DBParams{
        .path = journal_path, .cache_bytes = 1U << 20,
        .memory_only = false, .wipe_data = false, .obfuscate = false}};
    const auto expected_schema{std::make_tuple(
        llmq::CPQSignerJournal::DB_FORMAT_VERSION, uint32_t{0x50514a31},
        uint16_t{CHILD_SCHEDULED_WOTS_SHAKE_128_V1},
        uint16_t{llmq::PQ_CHILD_USAGE_CAP},
        uint32_t{llmq::PQ_CHILD_SIGNATURE_SIZE})};
    auto schema{expected_schema};
    if (!db.Read(uint8_t{0x70}, schema) || schema != expected_schema) {
        throw std::runtime_error("unsupported operator journal schema");
    }
    std::tuple<uint32_t, llmq::PQSignerBranchLock, uint32_t> branch_value;
    if (!db.Read(std::make_tuple(
            uint8_t{0x73}, llmq::CPQSignerJournal::DB_FORMAT_VERSION,
            genesis_hash, pro_tx_hash, target_height), branch_value)) {
        throw std::runtime_error("operator journal lacks the target branch vote");
    }
    const auto& [branch_version, branch, branch_guard]{branch_value};
    if (branch_version != llmq::CPQSignerJournal::DB_FORMAT_VERSION ||
        branch_guard != 0x42524c31 || !branch.IsStructurallyValid() ||
        branch.height != target_height || branch.block_hash != target_hash) {
        throw std::runtime_error("operator journal target branch vote mismatch");
    }
    if (GetLogicalChainLockId(
            genesis_hash, captured_shares.begin()->second.GetStatement()) !=
        branch.statement_hash) {
        throw std::runtime_error("captured operator statement differs from the durable branch vote");
    }
    std::set<uint32_t> signed_epochs;
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    for (iterator->Seek(uint8_t{0x72}); iterator->Valid(); iterator->Next()) {
        uint8_t prefix{0};
        if (!iterator->GetKey(prefix)) {
            throw std::runtime_error("unreadable operator journal key");
        }
        if (prefix != 0x72) break;
        std::tuple<uint8_t, uint32_t, llmq::PQSignerJournalLeafKey> physical{
            0, 0, llmq::PQSignerJournalLeafKey{llmq::PQSignerJournalKey{}}};
        std::tuple<uint32_t, uint8_t, llmq::PQSignerJournalKey, uint256,
                   llmq::PQChildSignature, uint32_t> value;
        if (!iterator->GetKeyExact(physical) || !iterator->GetValueExact(value)) {
            throw std::runtime_error("invalid operator journal slot encoding");
        }
        const auto& [version, state, logical, message_hash, signature, guard]{value};
        if (logical.genesis_hash != genesis_hash ||
            logical.pro_tx_hash != pro_tx_hash ||
            logical.absolute_height != target_height) continue;
        const auto captured{captured_shares.find(logical.quorum_epoch)};
        if (captured == captured_shares.end()) {
            throw std::runtime_error("operator journal target slot lacks its captured share");
        }
        const auto& share{captured->second};
        const auto expected_leaf{ChainLockLeafIndex(
            schedule, logical.quorum_epoch, target_height)};
        const auto public_key{DeriveCommittedChildPublicKey(
            seed, genesis_hash, commitment.tree_id, commitment.generation,
            logical.quorum_epoch)};
        const auto proof{public_key ? tree->GetConsensusProof(
            *public_key, logical.quorum_epoch) : std::nullopt};
        if (version != llmq::CPQSignerJournal::DB_FORMAT_VERSION ||
            std::get<1>(physical) != version || guard != 0x534c5431 ||
            std::get<2>(physical) != llmq::PQSignerJournalLeafKey{logical} ||
            state != 2 || logical.child_profile != CHILD_SCHEDULED_WOTS_SHAKE_128_V1 ||
            logical.purpose != llmq::PQSignerPurpose::CHAINLOCK ||
            logical.quorum_epoch < first_epoch || logical.quorum_epoch > last_epoch ||
            !expected_leaf || logical.leaf_index != *expected_leaf ||
            !public_key || logical.child_key_hash != ::Hash(*public_key) ||
            message_hash != GetChainLockShareHash(genesis_hash, share.transcript) ||
            signature != share.authenticated_signature.signature || !proof ||
            *proof != share.authenticated_signature.key_proof ||
            !VerifyCommittedChildKeyProof(
                genesis_hash, commitment, logical.quorum_epoch, *proof) ||
            !scheduled_wots::Verify(*public_key, logical.leaf_index,
                std::span<const uint8_t>{message_hash.begin(), message_hash.size()},
                signature) ||
            !signed_epochs.insert(logical.quorum_epoch).second) {
            throw std::runtime_error("operator journal slot lacks a valid durable signature");
        }
    }
    iterator->CheckStatus();
    memory_cleanse(seed.data(), seed.size());
    if (signed_epochs.empty() || signed_epochs.size() != captured_shares.size()) {
        throw std::runtime_error("operator journal signed slots do not match captured shares");
    }
    UniValue report{UniValue::VOBJ};
    report.pushKV("signed_slots", static_cast<uint64_t>(signed_epochs.size()));
    report.pushKV("height", target_height);
    report.pushKV("block_hash", target_hash.ToString());
    report.pushKV("logicalid", branch.statement_hash.ToString());
    report.pushKV("pro_tx_hash", pro_tx_hash.ToString());
    UniValue epochs{UniValue::VARR};
    for (const auto epoch : signed_epochs) epochs.push_back(epoch);
    report.pushKV("epochs", std::move(epochs));
    if (!WriteBinaryFile(report_path, report.write(2) + "\n")) {
        throw std::runtime_error("unable to write operator journal verification report");
    }
    return 0;
}

int GenerateCatchupSnapshots(
    int argc, char* argv[], const fs::path& operator_output = {},
    std::optional<CService> operator_service = std::nullopt)
{
    constexpr int FIXED_ARGUMENTS{12};
    if (argc < FIXED_ARGUMENTS + 2 * static_cast<int>(ACTIVE_QUORUMS) ||
        (argc - FIXED_ARGUMENTS) % 2 != 0) {
        throw std::runtime_error(
            "usage: pq_chainlock_fixture catchup-snapshots SNAPSHOT_OUT "
            "GENESIS BRANCH_HEIGHT BRANCH_HASH EPOCH_ORIGIN CUTOFF "
            "SNAPSHOT_LAG FUTURE_HORIZON MAX_TIP SIGNING_ANCHOR_HASH "
            "BASE... SNAPSHOT...");
    }
    test::QuorumSnapshotFixture fixture;
    const fs::path output{fs::u8path(argv[2])};
    fixture.genesis_hash = uint256S(argv[3]);
    fixture.branch_anchor.block_hash = uint256S(argv[5]);
    const uint256 signing_anchor_hash{uint256S(argv[11])};
    const std::size_t epochs{static_cast<std::size_t>(
        (argc - FIXED_ARGUMENTS) / 2)};
    if (!output.is_absolute() || fixture.genesis_hash.IsNull() ||
        fixture.branch_anchor.block_hash.IsNull() ||
        signing_anchor_hash.IsNull() || epochs > MAX_CATCHUP_FIXTURE_EPOCHS ||
        !ParseInt32(argv[4], &fixture.branch_anchor.height) ||
        !ParseInt32(argv[6], &fixture.build_config.schedule.epoch_origin) ||
        !ParseUInt32(argv[7], &fixture.build_config.registration_cutoff_blocks) ||
        !ParseUInt32(argv[8], &fixture.build_config.roster_snapshot_lag_blocks) ||
        !ParseUInt32(argv[9], &fixture.build_config.future_horizon_epochs) ||
        !ParseInt32(argv[10], &fixture.max_active_tip_height) ||
        !fixture.build_config.IsValid()) {
        throw std::runtime_error("invalid catch-up snapshot arguments");
    }
    const auto& schedule{fixture.build_config.schedule};
    const auto target{LatestEligibleChainLockTargetHeight(
        schedule, fixture.max_active_tip_height)};
    const auto first{ActiveEpochsAtHeight(schedule, fixture.branch_anchor.height)};
    const auto last{ActiveEpochsAtHeight(schedule, fixture.max_active_tip_height)};
    if (!target || !first || !last || first->front().epoch != 0 ||
        last->back().epoch + 1 != epochs) {
        throw std::runtime_error("invalid catch-up snapshot epoch window");
    }
    std::vector<scheduled_wots::PublicKey> public_keys(CHILD_KEY_COUNT);
    std::vector<std::shared_ptr<const scheduled_wots::SecretKey>>
        secret_keys(CHILD_KEY_COUNT);
    std::map<uint256, std::size_t> member_indices;
    if (!GenerateMemberKeys(public_keys, secret_keys, member_indices, epochs)) {
        throw std::runtime_error("unable to derive catch-up snapshot keys");
    }
    const auto add_snapshot = [&](uint32_t epoch, int32_t height,
                                  const uint256& block_hash) {
        auto& snapshot{fixture.snapshots.emplace_back()};
        snapshot.branch_point = {height, block_hash};
        snapshot.state.deterministic_mns = Snapshot(height, block_hash);
        auto states{std::make_shared<std::vector<OperatorKeyState>>()};
        states->reserve(QUORUM_SIZE);
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            states->push_back(MakeOperatorState(
                fixture.genesis_hash, fixture.build_config, public_keys,
                NonNullHash(10'000 + member), epoch, height, member));
        }
        snapshot.state.operator_key_states = std::move(states);
    };
    for (uint32_t epoch{0}; epoch < epochs; ++epoch) {
        const auto base{EpochBaseHeight(schedule, epoch)};
        const auto cutoff{RegistrationCutoffHeight(
            schedule, epoch, fixture.build_config.roster_snapshot_lag_blocks)};
        if (!base || !cutoff) {
            throw std::runtime_error("invalid catch-up snapshot coordinates");
        }
        fixture.quorum_bases.push_back({
            *base, uint256S(argv[FIXED_ARGUMENTS + epoch])});
        add_snapshot(epoch, *cutoff,
            uint256S(argv[FIXED_ARGUMENTS + epochs + epoch]));
    }
    const int32_t signing_anchor{*target - static_cast<int32_t>(schedule.sign_lag)};
    add_snapshot(last->back().epoch, signing_anchor, signing_anchor_hash);
    // Recovery freezes all four child-root identities at its first cutoff.
    // Advance that exact state normally, without synthetic key replacements
    // during the recovery window, including at the live H-5 boundary.
    const uint32_t recovery_first{last->front().epoch};
    auto helper_states{std::make_shared<std::vector<OperatorKeyState>>(
        *fixture.snapshots.at(recovery_first).state.operator_key_states)};
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        const auto authorizations{CatchupAuthorizations(
            fixture.genesis_hash, public_keys, member,
            recovery_first, last->back().epoch)};
        auto& state{helper_states->at(member)};
        const auto& commitment{authorizations.at(recovery_first).record.commitment};
        state.global_key.child_key_commitment = commitment;
        state.frozen_child_roots.front().commitment = commitment;
        if (!state.IsStructurallyValid()) {
            throw std::runtime_error("invalid catch-up helper key state");
        }
    }
    fixture.snapshots.at(recovery_first).state.operator_key_states =
        std::move(helper_states);
    if (!operator_output.empty()) {
        if (!operator_service) {
            throw std::runtime_error("missing catch-up operator service");
        }
        PrepareCatchupOperator(fixture, recovery_first, last->back().epoch,
                               operator_output, *operator_service);
    }
    const auto recovery_keys{
        fixture.snapshots.at(recovery_first).state.operator_key_states};
    for (std::size_t point{recovery_first + 1};
         point < fixture.snapshots.size(); ++point) {
        auto& snapshot{fixture.snapshots[point]};
        const auto view{DeriveOperatorKeyScheduleView(
            schedule, snapshot.branch_point.height,
            fixture.build_config.registration_cutoff_blocks,
            fixture.build_config.future_horizon_epochs)};
        if (!view) throw std::runtime_error("invalid recovery snapshot view");
        auto states{std::make_shared<std::vector<OperatorKeyState>>(*recovery_keys)};
        for (auto& state : *states) {
            if (state.Advance(*view) != OperatorKeyStateResult::OK) {
                throw std::runtime_error("unable to advance recovery snapshot keys");
            }
        }
        snapshot.state.operator_key_states = std::move(states);
    }
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        for (const auto& identity : *last) {
            const auto before{(*recovery_keys)[member].ResolveChildRoot(identity.epoch)};
            const auto after{(*fixture.snapshots.back().state.operator_key_states)[member]
                .ResolveChildRoot(identity.epoch)};
            if (!before.record || before.record != after.record) {
                throw std::runtime_error("recovery snapshot changed a frozen child root");
            }
        }
    }
    std::string error;
    if (!test::ValidateQuorumSnapshotFixture(fixture, error)) {
        throw std::runtime_error("invalid catch-up snapshot fixture: " + error);
    }
    // The extra live point must not turn the loader into an arbitrary-height
    // snapshot provider. Its branch hash is checked again by the daemon.
    auto off_anchor{fixture};
    ++off_anchor.snapshots.back().branch_point.height;
    if (test::ValidateQuorumSnapshotFixture(off_anchor, error) ||
        error != "PQ ChainLock fixture auxiliary snapshot is invalid") {
        throw std::runtime_error("accepted off-anchor catch-up snapshot");
    }
    if (!test::WriteQuorumSnapshotFixture(output, fixture, error)) {
        throw std::runtime_error("unable to write catch-up snapshots: " + error);
    }
    CachedCatchupFixture() = CatchupFixtureState{
        std::move(fixture), std::move(public_keys), std::move(secret_keys),
        std::move(member_indices), recovery_first, last->back().epoch};
    return 0;
}

int CompleteCatchupChainLock(int argc, char* argv[])
{
    if (argc != 6 || !CachedCatchupFixture() ||
        !CachedCatchupFixture()->fixture.local_operator) {
        throw std::runtime_error(
            "usage after catchup-operator in the same stream: "
            "catchup-complete SHARES_JSON AUTHORIZER_CLSIG BTCC_ORIGIN BUNDLE_OUT");
    }
    const auto& cached{*CachedCatchupFixture()};
    const auto& snapshots{cached.fixture};
    const fs::path shares_path{fs::u8path(argv[2])};
    const fs::path authorizer_path{fs::u8path(argv[3])};
    const fs::path output{fs::u8path(argv[5])};
    int32_t btcc_origin{-1};
    if (!shares_path.is_absolute() || !authorizer_path.is_absolute() ||
        !output.is_absolute() || !ParseInt32(argv[4], &btcc_origin) ||
        btcc_origin < 0) {
        throw std::runtime_error("invalid catch-up completion arguments");
    }
    const auto [read_ok, contents]{ReadBinaryFile(shares_path, 32U << 10)};
    UniValue encoded_shares;
    if (!read_ok || !encoded_shares.read(contents) ||
        !encoded_shares.isArray() || encoded_shares.size() < REQUIRED_QUORUMS ||
        encoded_shares.size() > ACTIVE_QUORUMS) {
        throw std::runtime_error("invalid catch-up captured shares");
    }
    std::map<uint32_t, ChainLockShare> captured;
    for (const auto& encoded : encoded_shares.getValues()) {
        const auto bytes{TryParseHex<uint8_t>(encoded.get_str())};
        if (!bytes || bytes->size() != ChainLockShare::WIRE_SIZE) {
            throw std::runtime_error("invalid catch-up captured share size");
        }
        DataStream stream{MakeByteSpan(*bytes)};
        ChainLockShare share;
        stream >> share;
        DataStream canonical;
        canonical << share;
        if (!stream.empty() || !share.IsStructurallyValid() ||
            HexStr(MakeUCharSpan(canonical)) != HexStr(*bytes) ||
            share.transcript.member_pro_tx_hash != snapshots.local_operator->pro_tx_hash ||
            share.transcript.quorum_epoch < cached.first_epoch ||
            share.transcript.quorum_epoch > cached.last_epoch ||
            (!captured.empty() &&
             captured.begin()->second.GetStatement() != share.GetStatement()) ||
            !captured.emplace(share.transcript.quorum_epoch, share).second) {
            throw std::runtime_error("catch-up captured shares disagree with the frozen operator");
        }
    }
    const auto& statement{captured.begin()->second.GetStatement()};
    const auto target{LatestEligibleChainLockTargetHeight(
        snapshots.build_config.schedule, snapshots.max_active_tip_height)};
    if (!target || statement.height != *target ||
        (statement.roster_transition == RosterAuthorizationTransitionKind::RECOVER &&
         captured.size() != ACTIVE_QUORUMS)) {
        throw std::runtime_error("catch-up completion target or recovery share count mismatch");
    }
    std::optional<ChainLockStatement> authorizer;
    std::string error;
    if (!ReadAuthorizingChainLock(authorizer_path, authorizer, error) ||
        !authorizer || statement.roster_authorization_base !=
            RosterAuthorizationBaseIdentity{
                authorizer->height, authorizer->block_hash,
                GetLogicalChainLockId(snapshots.genesis_hash, *authorizer)}) {
        throw std::runtime_error("catch-up completion authorizer mismatch: " + error);
    }
    GeneratorArguments args;
    args.genesis_hash = snapshots.genesis_hash;
    args.target_height = snapshots.max_active_tip_height;
    args.build_config = snapshots.build_config;
    auto fixture{std::make_unique<FullDimensionFixture>(std::move(args))};
    fixture->statement = statement;
    fixture->member_indices = cached.member_indices;
    const auto bind = [&](int32_t height, const uint256& hash) {
        if (!fixture->chain.SetExactHash(height, hash)) {
            throw std::runtime_error("catch-up completion has inconsistent branch anchors");
        }
    };
    bind(snapshots.branch_anchor.height, snapshots.branch_anchor.block_hash);
    bind(statement.height, statement.block_hash);
    bind(statement.previous_chainlock_height, statement.previous_chainlock_hash);
    bind(authorizer->height, authorizer->block_hash);
    for (const auto& point : snapshots.quorum_bases) bind(point.height, point.block_hash);
    for (const auto& snapshot : snapshots.snapshots) {
        bind(snapshot.branch_point.height, snapshot.branch_point.block_hash);
    }
    for (const auto* window : std::array<const RosterBeaconWindow*, 2>{
             &statement.roster_beacons, &authorizer->roster_beacons}) {
        for (const auto& seed : window->active.seeds) {
            if (seed.anchor_cursor.sys_height >= 0) {
                bind(seed.anchor_cursor.sys_height, seed.anchor_cursor.sys_hash);
            }
        }
        if (window->next.anchor_cursor.sys_height >= 0) {
            bind(window->next.anchor_cursor.sys_height, window->next.anchor_cursor.sys_hash);
        }
        const auto& source{window->active.recovery_authority_source};
        if (!source.IsNull()) {
            bind(source.normal_beacon.anchor_cursor.sys_height,
                 source.normal_beacon.anchor_cursor.sys_hash);
        }
    }
    const auto cache{FrozenQuorumRosterCache::Create(
        snapshots.genesis_hash, snapshots.build_config,
        [&](const CBlockIndex& index) -> std::optional<QuorumSnapshotState> {
            for (const auto& snapshot : snapshots.snapshots) {
                if (snapshot.branch_point.height == index.nHeight &&
                    snapshot.branch_point.block_hash == index.GetBlockHash()) {
                    return snapshot.state;
                }
            }
            return std::nullopt;
        }, /*cache_results=*/false)};
    QuorumBuildError build_error{QuorumBuildError::NONE};
    fixture->verified_rosters = cache ? cache->GetVerifiedActiveNoPublish(
        statement.height, fixture->chain.Tip(), statement.roster_beacons.active,
        &build_error) : nullptr;
    fixture->rosters = fixture->verified_rosters
        ? fixture->verified_rosters->RostersPtr() : nullptr;
    if (!fixture->rosters || build_error != QuorumBuildError::NONE ||
        GetQuorumContextHash(snapshots.genesis_hash, statement.height,
            statement.block_hash, Descriptors(*fixture->rosters)) !=
                statement.quorum_context_hash) {
        throw std::runtime_error("catch-up completion roster mismatch: " +
                                 std::to_string(static_cast<int>(build_error)));
    }
    auto authorization{FixtureAuthorizationFor(statement, &*authorizer)};
    if (statement.roster_transition == RosterAuthorizationTransitionKind::RECOVER) {
        authorization.admission = RosterAuthorizationAdmission::RECOVER;
        authorization.normal_input.reset();
    } else if (authorization.normal_input &&
               authorization.normal_input->next_snapshot.prior_authorization_is_descendant) {
        authorization.normal_input->next_snapshot.height = authorizer->height;
        authorization.normal_input->next_snapshot.hash = authorizer->block_hash;
    }
    BTCCScheduleConfig btcc;
    btcc.candidate_origin = btcc_origin;
    authorization.reset_policy = RosterResetVerificationPolicy{
        snapshots.build_config.schedule, btcc, btcc_origin - 1};
    ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
    fixture->prepared_context = PreparedChainLockContext::Create(
        snapshots.build_config.schedule, statement, fixture->verified_rosters,
        authorization, &verification_error);
    if (!fixture->prepared_context || verification_error != ChainLockVerificationError::NONE) {
        throw std::runtime_error("catch-up completion authorization rejected: " +
                                 std::to_string(static_cast<int>(verification_error)));
    }
    ShareCollectionError collection_error{ShareCollectionError::NONE};
    auto collector{ChainLockCollector::Create(fixture->prepared_context, &collection_error)};
    if (!collector) throw std::runtime_error("unable to create catch-up production collector");
    const auto collect = [&](const ChainLockShare& share) {
        if (collector->AddVerifiedShare(share, &collection_error) !=
                ShareCollectionResult::ACCEPTED || collection_error != ShareCollectionError::NONE) {
            throw std::runtime_error("catch-up production collector rejected share: " +
                                     std::to_string(static_cast<int>(collection_error)));
        }
    };
    // Verify every captured daemon share, including the fourth quorum that
    // is not required in the final certificate. Never re-sign its operator.
    for (const auto& [epoch, share] : captured) collect(share);
    struct SignerPosition {
        std::size_t share_index;
        std::size_t quorum_slot;
        uint16_t member_index;
        std::size_t operator_index;
    };
    std::vector<SignerPosition> positions;
    fixture->shares.reserve(FINAL_SIGNATURE_COUNT);
    std::size_t selected_quorums{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS && selected_quorums < REQUIRED_QUORUMS; ++slot) {
        if ((fixture->prepared_context->AuthorizationMask() & (1U << slot)) == 0) continue;
        const auto& roster{(*fixture->rosters)[slot]};
        const auto local_share{captured.find(roster.descriptor.epoch)};
        if (local_share == captured.end()) {
            throw std::runtime_error("catch-up completion lacks an authorized local share");
        }
        fixture->shares.push_back(local_share->second);
        std::size_t selected{1};
        for (std::size_t member{0}; member < QUORUM_SIZE && selected < QUORUM_THRESHOLD; ++member) {
            const auto& identity{roster.members[member]};
            const auto signer{cached.member_indices.find(identity.pro_tx_hash)};
            if (signer == cached.member_indices.end() || signer->second == 0 ||
                !identity.eligible || !identity.child_root) continue;
            positions.push_back({fixture->shares.size(), slot,
                                 static_cast<uint16_t>(member), signer->second});
            fixture->shares.emplace_back();
            ++selected;
        }
        if (selected != QUORUM_THRESHOLD) {
            throw std::runtime_error("insufficient catch-up helper signers");
        }
        ++selected_quorums;
    }
    FinalChainLock shell;
    shell.statement = statement;
    if (fixture->shares.size() != FINAL_SIGNATURE_COUNT ||
        !ParallelFor(positions.size(), [&](std::size_t index) {
            const auto& position{positions[index]};
            const auto& roster{(*fixture->rosters)[position.quorum_slot]};
            const auto& member{roster.members[position.member_index]};
            const auto authorizations{CatchupAuthorizations(
                snapshots.genesis_hash, cached.public_keys, position.operator_index,
                cached.first_epoch, cached.last_epoch)};
            const auto& child{authorizations.at(roster.descriptor.epoch)};
            if (!member.child_root || *member.child_root != child.record) return false;
            auto& share{fixture->shares[position.share_index]};
            share.transcript = BuildChainLockShareTranscript(
                shell, roster.descriptor, position.member_index, member.pro_tx_hash);
            share.authenticated_signature.key_proof = child.proof;
            const uint256 hash{GetChainLockShareHash(snapshots.genesis_hash, share.transcript)};
            scheduled_wots::Message message;
            std::copy(hash.begin(), hash.end(), message.begin());
            const auto leaf{ChainLockLeafIndex(
                snapshots.build_config.schedule, roster.descriptor.epoch, statement.height)};
            const auto& key{cached.secret_keys.at(
                ChildKeyIndex(roster.descriptor.epoch, position.operator_index))};
            return leaf && key && scheduled_wots::SignDeterministic(
                *key, *leaf, message, share.authenticated_signature.signature);
        })) {
        throw std::runtime_error("unable to sign catch-up helper shares");
    }
    for (const auto& position : positions) collect(fixture->shares[position.share_index]);
    const auto finalized{collector->FinalizeCollection()};
    if (!finalized || !finalized->Certificate().IsStructurallyValid()) {
        throw std::runtime_error("catch-up collector did not finalize 801 shares");
    }
    const auto& certificate{finalized->Certificate()};
    auto prepared{PrepareFinalChainLockVerification(
        certificate, *fixture->prepared_context, &verification_error)};
    ChainLockVerifier verifier{WorkerCount()};
    if (!prepared || verification_error != ChainLockVerificationError::NONE ||
        !verifier.VerifyChecks(std::move(prepared->checks)) ||
        !WriteShareBundle(output, *fixture, certificate, error)) {
        throw std::runtime_error("catch-up final certificate verification or write failed: " + error);
    }
    return 0;
}

int ExtendCatchupSnapshots(int argc, char* argv[])
{
    if (argc != 5 || !CachedCatchupFixture()) {
        throw std::runtime_error(
            "usage after catchup-operator in the same stream: "
            "catchup-extend SNAPSHOT_OUT MAX_TIP SIGNING_ANCHOR_HASH");
    }
    auto& cached{*CachedCatchupFixture()};
    auto fixture{cached.fixture};
    const fs::path output{fs::u8path(argv[2])};
    const uint256 anchor_hash{uint256S(argv[4])};
    int32_t max_tip{-1};
    const auto& schedule{fixture.build_config.schedule};
    if (!output.is_absolute() || anchor_hash.IsNull() ||
        !ParseInt32(argv[3], &max_tip) || max_tip <= fixture.max_active_tip_height) {
        throw std::runtime_error("invalid catch-up extension arguments");
    }
    const auto target{LatestEligibleChainLockTargetHeight(schedule, max_tip)};
    const auto active{ActiveEpochsAtHeight(schedule, max_tip)};
    if (!target || !active || active->front().epoch != cached.first_epoch ||
        active->back().epoch != cached.last_epoch ||
        fixture.snapshots.size() != fixture.quorum_bases.size() + 1) {
        throw std::runtime_error("catch-up extension changes the frozen recovery window");
    }
    const int32_t anchor_height{*target - static_cast<int32_t>(schedule.sign_lag)};
    auto& auxiliary{fixture.snapshots.back()};
    const auto view{DeriveOperatorKeyScheduleView(
        schedule, anchor_height, fixture.build_config.registration_cutoff_blocks,
        fixture.build_config.future_horizon_epochs)};
    if (!view || anchor_height <= auxiliary.branch_point.height) {
        throw std::runtime_error("invalid catch-up extension signing anchor");
    }
    auto states{std::make_shared<std::vector<OperatorKeyState>>(
        *auxiliary.state.operator_key_states)};
    for (auto& state : *states) {
        const auto before{state};
        if (state.Advance(*view) != OperatorKeyStateResult::OK) {
            throw std::runtime_error("unable to advance catch-up extension keys");
        }
        for (const auto& epoch : *active) {
            const auto frozen{before.ResolveChildRoot(epoch.epoch)};
            if (!frozen.record || frozen.record != state.ResolveChildRoot(epoch.epoch).record) {
                throw std::runtime_error("catch-up extension changed a frozen child root");
            }
        }
    }
    auxiliary.branch_point = {anchor_height, anchor_hash};
    auxiliary.state.deterministic_mns = Snapshot(anchor_height, anchor_hash);
    auxiliary.state.operator_key_states = std::move(states);
    fixture.max_active_tip_height = max_tip;
    std::string error;
    if (!test::ValidateQuorumSnapshotFixture(fixture, error) ||
        !test::WriteQuorumSnapshotFixture(output, fixture, error)) {
        throw std::runtime_error("invalid catch-up extension fixture: " + error);
    }
    cached.fixture = std::move(fixture);
    return 0;
}

int RunCommand(int argc, char* argv[], bool stream = false)
{
    try {
        std::string error;
        if (argc > 1 && std::string_view{argv[1]} == "catchup-complete") {
            return CompleteCatchupChainLock(argc, argv);
        }
        if (argc > 1 && std::string_view{argv[1]} == "catchup-extend") {
            return ExtendCatchupSnapshots(argc, argv);
        }
        if (argc > 1 && std::string_view{argv[1]} == "verify-operator-journal") {
            return VerifyCatchupOperatorJournal(argc, argv);
        }
        if (argc > 1 && std::string_view{argv[1]} == "catchup-snapshots") {
            return GenerateCatchupSnapshots(argc, argv);
        }
        if (argc > 5 && std::string_view{argv[1]} == "catchup-operator") {
            const fs::path output{fs::u8path(argv[3])};
            const auto service{Lookup(argv[4], 0, false)};
            std::vector<char*> arguments{argv[0], argv[1], argv[2]};
            for (int arg{5}; arg < argc; ++arg) arguments.push_back(argv[arg]);
            return GenerateCatchupSnapshots(
                static_cast<int>(arguments.size()), arguments.data(),
                output, service);
        }
        if (argc > 1 &&
            (std::string_view{argv[1]} == "payment-audit-prefix" ||
             std::string_view{argv[1]} == "chainlock-step")) {
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
        return Generate(*args, stream);
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc != 2 || std::string_view{argv[1]} != "stream") {
        return RunCommand(argc, argv);
    }
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input{line};
        std::vector<std::string> arguments{argv[0]};
        for (std::string argument; input >> std::quoted(argument);) {
            arguments.push_back(std::move(argument));
        }
        if (!input.eof() || arguments.size() == 1) {
            std::cerr << "invalid quoted fixture command\n";
            return 1;
        }
        std::vector<char*> pointers;
        pointers.reserve(arguments.size());
        for (auto& argument : arguments) pointers.push_back(argument.data());
        const int result{RunCommand(static_cast<int>(pointers.size()),
                                    pointers.data(), true)};
        if (result != 0) return result;
        std::cout << "OK\n" << std::flush;
    }
    return std::cin.eof() ? 0 : 1;
}
