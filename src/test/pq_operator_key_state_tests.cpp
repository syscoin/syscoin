// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_operator_key_state.h>

#include <llmq/pq_global_auth.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <ostream>

using namespace llmq::pq;

namespace llmq::pq {

std::ostream& operator<<(std::ostream& out, OperatorKeyStateResult value)
{
    return out << static_cast<unsigned>(value);
}

std::ostream& operator<<(std::ostream& out, ChildRootResolutionStatus value)
{
    return out << static_cast<unsigned>(value);
}

} // namespace llmq::pq

namespace {

uint256 NonNullHash(uint32_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<uint8_t>(value >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

ChainLockScheduleConfig Schedule()
{
    ChainLockScheduleConfig config;
    config.epoch_origin = 1440;
    return config;
}

OperatorKeyScheduleView View(int32_t height)
{
    const auto view = DeriveOperatorKeyScheduleView(
        Schedule(), height, /*registration_cutoff_blocks=*/144,
        /*future_horizon_epochs=*/8);
    BOOST_REQUIRE(view);
    return *view;
}

GlobalKeyRecord Candidate(uint32_t key_version,
                          uint32_t generation,
                          uint32_t first_epoch,
                          uint32_t tag)
{
    GlobalKeyRecord record;
    record.key_version = key_version;
    record.public_key[0] = static_cast<uint8_t>(tag);
    record.child_key_commitment.generation = generation;
    record.child_key_commitment.first_epoch = first_epoch;
    record.child_key_commitment.tree_id = NonNullHash(1000 + tag);
    record.child_key_commitment.root = NonNullHash(2000 + tag);
    return record;
}

GlobalSignature DummySignature()
{
    GlobalSignature signature{};
    signature[0] = 1;
    return signature;
}

ProviderRevokeAuthorization RevokeAuthorization(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    uint32_t tag)
{
    ProviderRevokeAuthorization authorization;
    authorization.payload_version = 1;
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = global_key_version;
    authorization.transaction_inputs_hash = NonNullHash(tag);
    return authorization;
}

OperatorKeyState RegisteredState(const uint256& genesis,
                                 const uint256& pro_tx_hash,
                                 const OperatorKeyScheduleView& view,
                                 const GlobalKeyRecord& candidate)
{
    auto state = OperatorKeyState::ForOperator(pro_tx_hash);
    BOOST_REQUIRE(state.Advance(view) == OperatorKeyStateResult::OK);
    BOOST_REQUIRE(
        state.ApplyInitialGlobalKey(
            view, genesis, candidate, NonNullHash(9), DummySignature(),
            /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) == OperatorKeyStateResult::OK);
    return state;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_operator_key_state_tests)

BOOST_AUTO_TEST_CASE(schedule_view_uses_exclusive_canonical_cutoff)
{
    const auto preparation = View(1000);
    BOOST_CHECK_EQUAL(preparation.has_current_epoch, 0U);
    BOOST_CHECK_EQUAL(preparation.first_mutable_epoch, 0U);
    BOOST_CHECK_EQUAL(preparation.last_admissible_epoch, 7U);

    BOOST_CHECK_EQUAL(View(1295).first_mutable_epoch, 0U);
    BOOST_CHECK_EQUAL(View(1296).first_mutable_epoch, 1U);
    BOOST_CHECK_EQUAL(View(1440).current_epoch, 0U);
    BOOST_CHECK_EQUAL(View(1440).first_mutable_epoch, 1U);
    BOOST_CHECK_EQUAL(View(1871).first_mutable_epoch, 2U);
    BOOST_CHECK_EQUAL(View(1872).first_mutable_epoch, 3U);

    BOOST_CHECK(!DeriveOperatorKeyScheduleView(Schedule(), 1872, 144, 0));
    BOOST_CHECK(!DeriveOperatorKeyScheduleView(
        Schedule(), 1872, 144, MAX_OPERATOR_SCHEDULE_EPOCHS + 1));
}

BOOST_AUTO_TEST_CASE(owner_bootstrap_binds_root_and_requires_authorization)
{
    const uint256 genesis{NonNullHash(1)};
    const uint256 pro_tx_hash{NonNullHash(2)};
    const auto view{View(1000)};
    const auto candidate{Candidate(1, 1, view.first_mutable_epoch, 1)};
    auto state = OperatorKeyState::ForOperator(pro_tx_hash);
    BOOST_REQUIRE(state.Advance(view) == OperatorKeyStateResult::OK);

    BOOST_CHECK(
        state.ApplyInitialGlobalKey(
            view, genesis, candidate, NonNullHash(3), DummySignature(),
            /*owner_authorization_verified=*/false,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::OWNER_AUTHORIZATION_REQUIRED);
    auto wrong_version{candidate};
    wrong_version.key_version = 2;
    BOOST_CHECK(
        state.ApplyInitialGlobalKey(
            view, genesis, wrong_version, NonNullHash(3), DummySignature(),
            /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);
    auto wrong_generation{candidate};
    wrong_generation.child_key_commitment.generation = 2;
    BOOST_CHECK(
        state.ApplyInitialGlobalKey(
            view, genesis, wrong_generation, NonNullHash(3), DummySignature(),
            /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);
    BOOST_REQUIRE(
        state.ApplyInitialGlobalKey(
            view, genesis, candidate, NonNullHash(3), DummySignature(),
            /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) == OperatorKeyStateResult::OK);
    BOOST_CHECK(state.HasActiveGlobalKey());
    BOOST_CHECK(state.global_key.child_key_commitment ==
                candidate.child_key_commitment);

    DataStream stream;
    stream << state;
    OperatorKeyState decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(decoded == state);
}

BOOST_AUTO_TEST_CASE(rotation_cutoff_preserves_branch_historical_roots)
{
    const uint256 genesis{NonNullHash(10)};
    const uint256 pro_tx_hash{NonNullHash(11)};
    const auto initial_view{View(1000)};
    const auto initial{Candidate(1, 1, initial_view.first_mutable_epoch, 10)};
    auto state{RegisteredState(genesis, pro_tx_hash, initial_view, initial)};

    const auto cutoff_view{View(1440)};
    BOOST_REQUIRE(state.Advance(cutoff_view) == OperatorKeyStateResult::OK);
    const auto frozen_zero{state.ResolveChildRoot(0)};
    BOOST_REQUIRE(frozen_zero.record);
    BOOST_CHECK(frozen_zero.status ==
                ChildRootResolutionStatus::FROZEN_PRESENT);
    BOOST_CHECK(frozen_zero.record->commitment ==
                initial.child_key_commitment);

    auto wrong_cutoff{Candidate(2, 2, 0, 11)};
    BOOST_CHECK(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, wrong_cutoff, NonNullHash(12),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::INVALID_CHILD_ROOT_COMMITMENT);

    const auto replacement{Candidate(
        2, 2, cutoff_view.first_mutable_epoch, 12)};
    auto skipped_generation{replacement};
    skipped_generation.child_key_commitment.generation = 3;
    BOOST_CHECK(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, skipped_generation, NonNullHash(13),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_ROTATION_AUTH_FAILED);
    auto skipped_key_version{replacement};
    skipped_key_version.key_version = 3;
    BOOST_CHECK(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, skipped_key_version, NonNullHash(13),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_ROTATION_AUTH_FAILED);
    BOOST_REQUIRE(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, replacement, NonNullHash(13),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::OK);
    const auto historical{state.ResolveChildRoot(0)};
    const auto future{state.ResolveChildRoot(1)};
    BOOST_REQUIRE(historical.record);
    BOOST_REQUIRE(future.record);
    BOOST_CHECK(historical.record->commitment ==
                initial.child_key_commitment);
    BOOST_CHECK(future.record->commitment ==
                replacement.child_key_commitment);

    auto key_only = replacement;
    key_only.key_version = 3;
    key_only.public_key[0]++;
    BOOST_REQUIRE(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, key_only, NonNullHash(14),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::OK);
    BOOST_CHECK(state.ResolveChildRoot(1).record->commitment ==
                replacement.child_key_commitment);
}

BOOST_AUTO_TEST_CASE(owner_recovery_is_delayed_and_starts_a_fresh_tree)
{
    const uint256 genesis{NonNullHash(20)};
    const uint256 pro_tx_hash{NonNullHash(21)};
    const auto initial_view{View(1440)};
    const auto initial{Candidate(
        1, 1, initial_view.first_mutable_epoch, 20)};
    auto revoked{RegisteredState(genesis, pro_tx_hash, initial_view, initial)};

    const auto authorization{
        RevokeAuthorization(pro_tx_hash, initial.key_version, 25)};
    auto wrong_key_version{authorization};
    ++wrong_key_version.global_key_version;
    BOOST_CHECK(
        revoked.ApplyProviderRevocation(
            initial_view, genesis, wrong_key_version, DummySignature(),
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::PROVIDER_REVOCATION_AUTH_FAILED);
    BOOST_REQUIRE(
        revoked.ApplyProviderRevocation(
            initial_view, genesis, authorization, DummySignature(),
            /*check_sigs=*/false) == OperatorKeyStateResult::OK);
    BOOST_CHECK(!revoked.HasActiveGlobalKey());
    BOOST_CHECK_EQUAL(revoked.revoked_height,
                      static_cast<uint32_t>(initial_view.block_height));

    const auto early_view{View(
        initial_view.block_height + OWNER_RECOVERY_DELAY_BLOCKS - 1)};
    auto early{revoked};
    BOOST_REQUIRE(early.Advance(early_view) == OperatorKeyStateResult::OK);
    const auto early_candidate{Candidate(
        2, 2, early_view.first_mutable_epoch, 21)};
    BOOST_CHECK(
        early.ApplyInitialGlobalKey(
            early_view, genesis, early_candidate, NonNullHash(22),
            DummySignature(), /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_RECOVERY_NOT_ALLOWED);

    const auto recovery_view{View(
        initial_view.block_height + OWNER_RECOVERY_DELAY_BLOCKS)};
    BOOST_REQUIRE(revoked.Advance(recovery_view) ==
                  OperatorKeyStateResult::OK);
    auto reused_tree = initial;
    reused_tree.key_version = 2;
    reused_tree.public_key[0]++;
    reused_tree.child_key_commitment.first_epoch =
        recovery_view.first_mutable_epoch;
    BOOST_CHECK(
        revoked.ApplyInitialGlobalKey(
            recovery_view, genesis, reused_tree, NonNullHash(23),
            DummySignature(), /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::GLOBAL_RECOVERY_NOT_ALLOWED);

    const auto recovery{Candidate(
        2, 2, recovery_view.first_mutable_epoch, 22)};
    BOOST_REQUIRE(
        revoked.ApplyInitialGlobalKey(
            recovery_view, genesis, recovery, NonNullHash(24),
            DummySignature(), /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) == OperatorKeyStateResult::OK);
    BOOST_CHECK(revoked.HasActiveGlobalKey());
    BOOST_CHECK_EQUAL(revoked.revoked_height, 0U);
    BOOST_CHECK(revoked.global_key.child_key_commitment.tree_id !=
                initial.child_key_commitment.tree_id);
}

BOOST_AUTO_TEST_CASE(child_root_generation_cap_is_lifetime_bound)
{
    const uint256 genesis{NonNullHash(30)};
    const uint256 pro_tx_hash{NonNullHash(31)};
    const auto initial_view{View(1000)};
    const auto initial{Candidate(
        1, 1, initial_view.first_mutable_epoch, 30)};
    auto state{RegisteredState(genesis, pro_tx_hash, initial_view, initial)};
    state.global_key.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION - 1;
    BOOST_REQUIRE(state.IsStructurallyValid());

    const auto cutoff_view{View(1440)};
    BOOST_REQUIRE(state.Advance(cutoff_view) == OperatorKeyStateResult::OK);
    const auto final_root{Candidate(
        2, CHILD_KEY_TREE_MAX_GENERATION,
        cutoff_view.first_mutable_epoch, 31)};
    BOOST_REQUIRE(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, final_root, NonNullHash(32),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::OK);

    const auto seventeenth{Candidate(
        3, CHILD_KEY_TREE_MAX_GENERATION + 1,
        cutoff_view.first_mutable_epoch, 32)};
    BOOST_CHECK(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, seventeenth, NonNullHash(33),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::INVALID_CHILD_ROOT_COMMITMENT);

    auto key_only{state.global_key};
    key_only.activated_height = 0;
    ++key_only.key_version;
    ++key_only.public_key[0];
    BOOST_REQUIRE(
        state.ApplyGlobalKeyRotation(
            cutoff_view, genesis, key_only, NonNullHash(34),
            DummySignature(), /*check_sigs=*/false) ==
        OperatorKeyStateResult::OK);

    const auto recovery_initial{Candidate(
        1, 1, cutoff_view.first_mutable_epoch, 34)};
    auto revoked{RegisteredState(
        genesis, pro_tx_hash, cutoff_view, recovery_initial)};
    revoked.global_key.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION;
    BOOST_REQUIRE(revoked.IsStructurallyValid());
    const auto authorization{
        RevokeAuthorization(pro_tx_hash, recovery_initial.key_version, 35)};
    BOOST_REQUIRE(
        revoked.ApplyProviderRevocation(
            cutoff_view, genesis, authorization, DummySignature(),
            /*check_sigs=*/false) == OperatorKeyStateResult::OK);
    const auto recovery_view{View(
        cutoff_view.block_height + OWNER_RECOVERY_DELAY_BLOCKS)};
    BOOST_REQUIRE(revoked.Advance(recovery_view) ==
                  OperatorKeyStateResult::OK);
    const auto exhausted_recovery{Candidate(
        2, CHILD_KEY_TREE_MAX_GENERATION + 1,
        recovery_view.first_mutable_epoch, 33)};
    BOOST_CHECK(
        revoked.ApplyInitialGlobalKey(
            recovery_view, genesis, exhausted_recovery, NonNullHash(36),
            DummySignature(), /*owner_authorization_verified=*/true,
            /*check_sigs=*/false) ==
        OperatorKeyStateResult::INVALID_CHILD_ROOT_COMMITMENT);
}

BOOST_AUTO_TEST_SUITE_END()
