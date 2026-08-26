// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <masternode/pq_operatorkeys.h>

#include <evo/deterministicmns.h>
#include <llmq/pq_global_auth.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <thread>
#include <type_traits>
#include <utility>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value == 0 ? 1 : value;
    return hash;
}

slhdsa::SecretKey DeterministicGlobalKey()
{
    slhdsa::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0x40 + i);
    }
    auto key = slhdsa::GenerateSecretKey(seed);
    BOOST_REQUIRE(key);
    return std::move(*key);
}

LocalOperatorKeyManager DeterministicManager(uint8_t seed_offset = 0xa0)
{
    ChainLockMasterSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(seed_offset + i);
    }
    return LocalOperatorKeyManager{DeterministicGlobalKey(), std::move(seed)};
}

ChildPublicKey ChildPublicKeyOf(const scheduled_wots::SecretKey& key)
{
    ChildPublicKey public_key{};
    BOOST_REQUIRE(key.GetPublicKey(public_key));
    return public_key;
}

ChildKeyTreeCommitment Commitment(uint8_t tag)
{
    ChildKeyTreeCommitment commitment;
    commitment.generation = 1;
    commitment.tree_id = NonNullHash(tag);
    commitment.root = NonNullHash(static_cast<uint8_t>(tag + 1));
    BOOST_REQUIRE(commitment.IsStructurallyValid());
    return commitment;
}

class ActiveMasternodeInfoGuard final {
public:
    ActiveMasternodeInfoGuard()
    {
        LOCK(activeMasternodeInfoCs);
        m_previous_mode = fMasternodeMode;
        m_previous = std::move(activeMasternodeInfo);
        activeMasternodeInfo = {};
        activeMasternodeInfo.identityGeneration =
            m_previous.identityGeneration + 1;
        fMasternodeMode = false;
    }

    ~ActiveMasternodeInfoGuard()
    {
        LOCK(activeMasternodeInfoCs);
        const uint64_t next_generation{
            activeMasternodeInfo.identityGeneration + 1};
        activeMasternodeInfo = std::move(m_previous);
        activeMasternodeInfo.identityGeneration = next_generation;
        fMasternodeMode = m_previous_mode;
    }

    ActiveMasternodeInfoGuard(const ActiveMasternodeInfoGuard&) = delete;
    ActiveMasternodeInfoGuard& operator=(
        const ActiveMasternodeInfoGuard&) = delete;

private:
    bool m_previous_mode{false};
    CActiveMasternodeInfo m_previous;
};

} // namespace

static_assert(!std::is_copy_constructible_v<LocalOperatorKeyManager>);
static_assert(!std::is_copy_assignable_v<LocalOperatorKeyManager>);
static_assert(std::is_nothrow_move_constructible_v<LocalOperatorKeyManager>);
static_assert(scheduled_wots::KEY_GENERATION_SEED_SIZE == 48);
static_assert(!std::is_copy_constructible_v<scheduled_wots::SecretKey>);
static_assert(!std::is_copy_assignable_v<scheduled_wots::SecretKey>);
static_assert(std::is_nothrow_move_constructible_v<scheduled_wots::SecretKey>);
static_assert(std::is_nothrow_move_assignable_v<scheduled_wots::SecretKey>);

BOOST_AUTO_TEST_SUITE(pq_operator_keys_tests)

BOOST_AUTO_TEST_CASE(global_key_is_private_and_signing_is_purpose_scoped)
{
    auto manager = DeterministicManager();
    BOOST_REQUIRE(manager.IsValid());

    GlobalKeyRecord record;
    record.key_version = 1;
    record.activated_height = 100;
    record.public_key = manager.GetGlobalPublicKey();
    record.child_key_commitment = Commitment(20);
    BOOST_CHECK(manager.Matches(record));
    ++record.key_version;
    BOOST_CHECK(manager.Matches(record));
    record.public_key[0] ^= 1;
    BOOST_CHECK(!manager.Matches(record));

    const uint256 digest = NonNullHash(7);
    GlobalSignature signature{};
    BOOST_REQUIRE(manager.SignMNAUTH(digest, signature));
    BOOST_CHECK(slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::MNAUTH), signature));
    BOOST_CHECK(!slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GLOBAL_ROTATION), signature));

    BOOST_REQUIRE(manager.SignGovernanceTrigger(digest, signature));
    BOOST_CHECK(slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_TRIGGER),
        signature));
    BOOST_CHECK(!slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_VOTE), signature));

    BOOST_REQUIRE(manager.SignGovernanceVote(digest, signature));
    BOOST_CHECK(slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_VOTE), signature));
    BOOST_CHECK(!slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_TRIGGER),
        signature));

    BOOST_REQUIRE(manager.SignGovernanceProposalVote(digest, signature));
    BOOST_CHECK(slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(
            GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE),
        signature));
    BOOST_CHECK(!slhdsa::Verify(
        manager.GetGlobalPublicKey(),
        std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(GlobalAuthPurpose::GOVERNANCE_VOTE),
        signature));

    uint256 null_digest;
    BOOST_CHECK(!manager.SignMNAUTH(null_digest, signature));
    BOOST_CHECK(std::all_of(signature.begin(), signature.end(),
                            [](uint8_t byte) { return byte == 0; }));
}

BOOST_AUTO_TEST_CASE(active_identity_reads_do_not_wait_for_global_signing)
{
    ActiveMasternodeInfoGuard active_info_guard;
    ChainLockMasterSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0xc0 + i);
    }
    auto manager = std::make_shared<LocalOperatorKeyManager>(
        DeterministicGlobalKey(), std::move(seed));
    BOOST_REQUIRE(manager->IsValid());

    const uint256 pro_tx_hash{NonNullHash(31)};
    constexpr uint32_t KEY_VERSION{7};
    {
        LOCK(activeMasternodeInfoCs);
        activeMasternodeInfo.operatorKeyManager = manager;
        activeMasternodeInfo.proTxHash = pro_tx_hash;
        activeMasternodeInfo.globalKeyVersion = KEY_VERSION;
        ++activeMasternodeInfo.identityGeneration;
        fMasternodeMode = true;
    }

    const uint256 digest{NonNullHash(32)};
    GlobalSignature signature{};
    bool sign_result{true};
    std::atomic_bool finished{false};
    std::thread signer{[&] {
        sign_result = SignActiveMasternodeMNAUTH(
            pro_tx_hash, KEY_VERSION, digest, signature);
        finished.store(true, std::memory_order_release);
    }};

    const auto observation_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{30}};
    while (GetActiveMasternodeGlobalSigningCount() == 0 &&
           !finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < observation_deadline) {
        std::this_thread::yield();
    }
    const bool observed_inflight{
        GetActiveMasternodeGlobalSigningCount() == 1};

    uint256 observed_pro_tx_hash;
    uint32_t observed_key_version{0};
    GlobalPublicKey observed_public_key{};
    CService observed_service;
    const bool identity_read{GetActiveMasternodeIdentity(
        observed_pro_tx_hash, observed_key_version, observed_public_key,
        observed_service)};
    const bool identity_read_while_signing{
        GetActiveMasternodeGlobalSigningCount() == 1};

    bool rotated_while_signing{false};
    {
        LOCK(activeMasternodeInfoCs);
        if (GetActiveMasternodeGlobalSigningCount() == 1) {
            ++activeMasternodeInfo.globalKeyVersion;
            ++activeMasternodeInfo.identityGeneration;
            rotated_while_signing = true;
        }
    }
    signer.join();

    BOOST_REQUIRE(observed_inflight);
    BOOST_REQUIRE(identity_read);
    BOOST_CHECK(observed_pro_tx_hash == pro_tx_hash);
    BOOST_CHECK_EQUAL(observed_key_version, KEY_VERSION);
    BOOST_CHECK(observed_public_key == manager->GetGlobalPublicKey());
    BOOST_CHECK(identity_read_while_signing);
    BOOST_REQUIRE(rotated_while_signing);
    BOOST_CHECK(!sign_result);
    BOOST_CHECK(std::all_of(signature.begin(), signature.end(),
                            [](uint8_t byte) { return byte == 0; }));
}

BOOST_AUTO_TEST_CASE(mnauth_waiter_precedes_queued_governance_signing)
{
    ActiveMasternodeInfoGuard active_info_guard;
    ChainLockMasterSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0xd0 + i);
    }
    auto manager = std::make_shared<LocalOperatorKeyManager>(
        DeterministicGlobalKey(), std::move(seed));
    BOOST_REQUIRE(manager->IsValid());

    const uint256 pro_tx_hash{NonNullHash(41)};
    constexpr uint32_t KEY_VERSION{9};
    {
        LOCK(activeMasternodeInfoCs);
        activeMasternodeInfo.operatorKeyManager = manager;
        activeMasternodeInfo.proTxHash = pro_tx_hash;
        activeMasternodeInfo.globalKeyVersion = KEY_VERSION;
        ++activeMasternodeInfo.identityGeneration;
        fMasternodeMode = true;
    }

    std::atomic_bool release_waiters{false};
    std::atomic_bool mnauth_ready{false};
    std::atomic_bool governance_ready{false};
    std::atomic_bool first_finished{false};
    std::atomic<int> completion_sequence{0};
    int first_order{0};
    int mnauth_order{0};
    int second_governance_order{0};
    bool first_result{false};
    bool mnauth_result{false};
    bool second_governance_result{false};
    GlobalSignature first_signature{};
    GlobalSignature mnauth_signature{};
    GlobalSignature second_governance_signature{};

    std::thread mnauth_waiter{[&] {
        mnauth_ready.store(true, std::memory_order_release);
        while (!release_waiters.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        mnauth_result = SignActiveMasternodeMNAUTH(
            pro_tx_hash, KEY_VERSION, NonNullHash(42), mnauth_signature);
        mnauth_order = completion_sequence.fetch_add(
                            1, std::memory_order_acq_rel) +
                        1;
    }};
    std::thread governance_waiter{[&] {
        governance_ready.store(true, std::memory_order_release);
        while (!release_waiters.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        second_governance_result =
            SignActiveMasternodeGovernanceProposalVote(
                pro_tx_hash, KEY_VERSION, NonNullHash(43),
                second_governance_signature);
        second_governance_order = completion_sequence.fetch_add(
                                      1, std::memory_order_acq_rel) +
                                  1;
    }};

    const auto readiness_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{30}};
    while ((!mnauth_ready.load(std::memory_order_acquire) ||
            !governance_ready.load(std::memory_order_acquire)) &&
           std::chrono::steady_clock::now() < readiness_deadline) {
        std::this_thread::yield();
    }

    std::thread first_governance{[&] {
        first_result = SignActiveMasternodeGovernanceTrigger(
            pro_tx_hash, KEY_VERSION, NonNullHash(44), first_signature);
        first_order = completion_sequence.fetch_add(
                          1, std::memory_order_acq_rel) +
                      1;
        first_finished.store(true, std::memory_order_release);
    }};
    const auto active_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{30}};
    bool observed_first_active{false};
    while (!first_finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < active_deadline) {
        if (GetActiveMasternodeGlobalSigningCount() == 1) {
            observed_first_active = true;
            break;
        }
        std::this_thread::yield();
    }

    release_waiters.store(true, std::memory_order_release);
    const auto queued_deadline{
        std::chrono::steady_clock::now() + std::chrono::seconds{30}};
    bool observed_competing_waiters{false};
    while (!first_finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < queued_deadline) {
        const auto stats{GetActiveMasternodeGlobalSigningStats()};
        if (stats.mnauth_waiters == 1 && stats.governance_waiters == 1) {
            observed_competing_waiters = true;
            break;
        }
        std::this_thread::yield();
    }

    first_governance.join();
    mnauth_waiter.join();
    governance_waiter.join();

    BOOST_CHECK(mnauth_ready.load(std::memory_order_acquire));
    BOOST_CHECK(governance_ready.load(std::memory_order_acquire));
    BOOST_REQUIRE(observed_first_active);
    BOOST_REQUIRE(observed_competing_waiters);
    BOOST_REQUIRE(first_result);
    BOOST_REQUIRE(mnauth_result);
    BOOST_REQUIRE(second_governance_result);
    BOOST_CHECK_EQUAL(first_order, 1);
    BOOST_CHECK_EQUAL(mnauth_order, 2);
    BOOST_CHECK_EQUAL(second_governance_order, 3);
}

BOOST_AUTO_TEST_CASE(committed_child_kdf_is_deterministic_and_tree_bound)
{
    auto first_manager = DeterministicManager();
    auto second_manager = DeterministicManager();
    const uint256 genesis = NonNullHash(1);
    const uint256 tree_id = NonNullHash(2);

    auto first = first_manager.DeriveCommittedChildKey(
        genesis, tree_id, /*generation=*/1, /*epoch=*/9);
    auto second = second_manager.DeriveCommittedChildKey(
        genesis, tree_id, /*generation=*/1, /*epoch=*/9);
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);
    BOOST_CHECK(ChildPublicKeyOf(*first) == ChildPublicKeyOf(*second));

    auto changed_genesis = first_manager.DeriveCommittedChildKey(
        NonNullHash(3), tree_id, 1, 9);
    auto changed_identity = first_manager.DeriveCommittedChildKey(
        genesis, NonNullHash(4), 1, 9);
    auto changed_generation = first_manager.DeriveCommittedChildKey(
        genesis, tree_id, 2, 9);
    auto changed_epoch = first_manager.DeriveCommittedChildKey(
        genesis, tree_id, 1, 10);
    auto changed_master_seed = DeterministicManager(0xb0)
                                   .DeriveCommittedChildKey(
                                       genesis, tree_id, 1, 9);
    BOOST_REQUIRE(changed_genesis);
    BOOST_REQUIRE(changed_identity);
    BOOST_REQUIRE(changed_generation);
    BOOST_REQUIRE(changed_epoch);
    BOOST_REQUIRE(changed_master_seed);
    const auto expected{ChildPublicKeyOf(*first)};
    ChainLockMasterSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0xa0 + i);
    }
    const auto public_only = DeriveCommittedChildPublicKey(
        seed, genesis, tree_id, 1, 9);
    BOOST_REQUIRE(public_only);
    BOOST_CHECK(*public_only == expected);

    ChainLockMasterSeed imported{};
    BOOST_CHECK(ImportChainLockMasterSeed(seed, imported));
    BOOST_CHECK(imported == seed);
    ChainLockMasterSeed zero_seed{};
    BOOST_CHECK(!ImportChainLockMasterSeed(zero_seed, imported));
    BOOST_CHECK(std::all_of(imported.begin(), imported.end(),
                            [](uint8_t byte) { return byte == 0; }));
    BOOST_CHECK(expected != ChildPublicKeyOf(*changed_genesis));
    BOOST_CHECK(expected != ChildPublicKeyOf(*changed_identity));
    BOOST_CHECK(expected != ChildPublicKeyOf(*changed_generation));
    BOOST_CHECK(expected != ChildPublicKeyOf(*changed_epoch));
    BOOST_CHECK(expected != ChildPublicKeyOf(*changed_master_seed));

    uint256 null_hash;
    BOOST_CHECK(!first_manager.DeriveCommittedChildKey(
        null_hash, tree_id, 1, 9));
    BOOST_CHECK(!first_manager.DeriveCommittedChildKey(
        genesis, null_hash, 1, 9));
    BOOST_CHECK(!first_manager.DeriveCommittedChildKey(
        genesis, tree_id, 0, 9));
}

BOOST_AUTO_TEST_SUITE_END()
