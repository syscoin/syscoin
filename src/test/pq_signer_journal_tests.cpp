// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_signer_journal.h>

#include <llmq/pq_chainlock_types.h>

#include <dbwrapper.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>

namespace llmq::test {

class PQSignerJournalTestAccess
{
public:
    static PQSignerJournalResult Reconcile(
        CPQSignerJournal& journal,
        const uint256& genesis_hash,
        const uint256& pro_tx_hash,
        const pq::FinalChainLock& chainlock)
    {
        return journal.ReconcileDurableAcceptedChainLock(
            genesis_hash, pro_tx_hash, chainlock);
    }
};

} // namespace llmq::test

namespace {

llmq::PQSignerJournalKey MakeKey()
{
    return {
        .genesis_hash = uint256{1},
        .child_profile = 1,
        .pro_tx_hash = uint256{2},
        .quorum_epoch = 17,
        .child_key_hash = uint256{3},
        .absolute_height = 100,
    };
}

llmq::PQC11Signature MakeSignature(unsigned char salt)
{
    llmq::PQC11Signature signature;
    for (std::size_t i = 0; i < signature.size(); ++i) {
        signature[i] = static_cast<unsigned char>((i * 29 + salt) & 0xff);
    }
    return signature;
}

uint256 MakeHash(std::uint64_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
    return hash;
}

void SetFirstMembers(llmq::pq::QuorumBitmap& bitmap, std::size_t count)
{
    bitmap.fill(0);
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<std::uint8_t>(std::uint8_t{1} << (member % 8));
    }
}

llmq::pq::FinalChainLock MakeCertificate(
    std::int32_t height,
    const uint256& block_hash,
    unsigned char witness_salt)
{
    llmq::pq::FinalChainLock chainlock;
    chainlock.statement.height = height;
    chainlock.statement.block_hash = block_hash;
    chainlock.statement.previous_chainlock_height = height - 5;
    chainlock.statement.previous_chainlock_hash =
        MakeHash(static_cast<std::uint64_t>(30'000 + height));
    chainlock.statement.quorum_context_hash =
        MakeHash(static_cast<std::uint64_t>(40'000 + height));
    chainlock.statement.payment_probation_state_hash = MakeHash(50'000);
    chainlock.selected_quorum_mask = 0b1011;
    SetFirstMembers(chainlock.signer_bitmaps[0], llmq::pq::QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[1], llmq::pq::QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[3], llmq::pq::QUORUM_THRESHOLD);
    chainlock.signatures.resize(llmq::pq::FINAL_SIGNATURE_COUNT);
    for (auto& authenticated : chainlock.signatures) {
        authenticated.key_proof.public_key[0] = 1;
    }
    chainlock.signatures[0].signature[0] = witness_salt;
    return chainlock;
}

llmq::PQSignerBranchLock CertificateLock(
    const uint256& genesis_hash,
    const llmq::pq::FinalChainLock& chainlock)
{
    return {
        chainlock.statement.height,
        chainlock.statement.block_hash,
        chainlock.GetLogicalId(genesis_hash),
    };
}

llmq::PQSignerBranchLock MakeBranchLock(
    const llmq::PQSignerJournalKey& key)
{
    return {
        key.absolute_height,
        MakeHash(static_cast<std::uint64_t>(10'000 + key.absolute_height)),
        MakeHash(static_cast<std::uint64_t>(20'000 + key.absolute_height)),
    };
}

llmq::PQSignerJournalResult ReserveSlot(
    llmq::CPQSignerJournal& journal,
    const llmq::PQSignerJournalKey& key,
    const uint256& message_hash)
{
    const auto expected{journal.GetBranchLock(key.genesis_hash,
                                              key.pro_tx_hash)};
    auto candidate{MakeBranchLock(key)};
    if (expected && expected->height == key.absolute_height) {
        candidate = *expected;
    }
    return journal.Reserve(key, message_hash, candidate, expected);
}

void CheckOutcome(
    const llmq::PQSignerJournalResult& result,
    llmq::PQSignerJournalOutcome expected)
{
    BOOST_CHECK(result.outcome == expected);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_signer_journal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signed_message_replays_exact_bytes_across_restart)
{
    const fs::path path = m_path_root / "pq_signer_journal_replay";
    const auto key = MakeKey();
    const uint256 message_hash{11};
    const auto signature = MakeSignature(7);

    {
        llmq::CPQSignerJournal journal{path};
        BOOST_REQUIRE(journal.IsHealthy());
        CheckOutcome(ReserveSlot(journal, key, message_hash), llmq::PQSignerJournalOutcome::RESERVED);
        CheckOutcome(
            journal.StoreSignature(key, message_hash, signature),
            llmq::PQSignerJournalOutcome::STORED);

        const auto replay = ReserveSlot(journal, key, message_hash);
        CheckOutcome(replay, llmq::PQSignerJournalOutcome::REPLAY);
        BOOST_REQUIRE(replay.signature.has_value());
        BOOST_CHECK(*replay.signature == signature);
    }

    {
        llmq::CPQSignerJournal restarted{path};
        BOOST_REQUIRE(restarted.IsHealthy());
        const auto replay = ReserveSlot(restarted, key, message_hash);
        CheckOutcome(replay, llmq::PQSignerJournalOutcome::REPLAY);
        BOOST_REQUIRE(replay.signature.has_value());
        BOOST_CHECK(*replay.signature == signature);

        // StoreSignature is idempotent but never replaces the first bytes.
        const auto different_signature = MakeSignature(8);
        const auto stored_replay = restarted.StoreSignature(key, message_hash, different_signature);
        CheckOutcome(stored_replay, llmq::PQSignerJournalOutcome::REPLAY);
        BOOST_REQUIRE(stored_replay.signature.has_value());
        BOOST_CHECK(*stored_replay.signature == signature);
    }
}

BOOST_AUTO_TEST_CASE(reserved_after_restart_is_permanently_consumed)
{
    const fs::path path = m_path_root / "pq_signer_journal_consumed";
    const auto key = MakeKey();
    const uint256 message_hash{21};

    {
        llmq::CPQSignerJournal journal{path};
        CheckOutcome(ReserveSlot(journal, key, message_hash), llmq::PQSignerJournalOutcome::RESERVED);
        // Simulate a crash after fsync and before the signature commit.
    }

    llmq::CPQSignerJournal restarted{path};
    CheckOutcome(ReserveSlot(restarted, key, message_hash), llmq::PQSignerJournalOutcome::CONSUMED);
    CheckOutcome(
        restarted.StoreSignature(key, message_hash, MakeSignature(1)),
        llmq::PQSignerJournalOutcome::CONSUMED);
    CheckOutcome(ReserveSlot(restarted, key, uint256{22}), llmq::PQSignerJournalOutcome::CONFLICT);
}

BOOST_AUTO_TEST_CASE(competing_message_never_replaces_live_reservation)
{
    const fs::path path = m_path_root / "pq_signer_journal_conflict";
    const auto key = MakeKey();
    const uint256 first_message{31};
    const uint256 competing_message{32};
    const auto signature = MakeSignature(3);

    llmq::CPQSignerJournal journal{path};
    CheckOutcome(ReserveSlot(journal, key, first_message), llmq::PQSignerJournalOutcome::RESERVED);
    CheckOutcome(ReserveSlot(journal, key, competing_message), llmq::PQSignerJournalOutcome::CONFLICT);
    CheckOutcome(
        journal.StoreSignature(key, competing_message, signature),
        llmq::PQSignerJournalOutcome::CONFLICT);

    // Rejecting the competitor does not revoke the original live owner.
    CheckOutcome(
        journal.StoreSignature(key, first_message, signature),
        llmq::PQSignerJournalOutcome::STORED);
    CheckOutcome(ReserveSlot(journal, key, competing_message), llmq::PQSignerJournalOutcome::CONFLICT);
}

BOOST_AUTO_TEST_CASE(operator_branch_lock_is_atomic_monotonic_and_persistent)
{
    const fs::path path = m_path_root / "pq_signer_journal_branch_lock";
    auto first_key = MakeKey();
    const auto first_lock = MakeBranchLock(first_key);

    {
        llmq::CPQSignerJournal journal{path};
        CheckOutcome(
            journal.Reserve(first_key, uint256{71}, first_lock, std::nullopt),
            llmq::PQSignerJournalOutcome::RESERVED);
        BOOST_REQUIRE(journal.GetBranchLock(first_key.genesis_hash,
                                            first_key.pro_tx_hash));
        BOOST_CHECK(*journal.GetBranchLock(first_key.genesis_hash,
                                           first_key.pro_tx_hash) == first_lock);

        auto competing_lock = first_lock;
        competing_lock.block_hash = uint256{99};
        CheckOutcome(
            journal.Reserve(first_key, uint256{72}, competing_lock, first_lock),
            llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);

        auto next_key = first_key;
        next_key.absolute_height += 5;
        const auto next_lock = MakeBranchLock(next_key);
        CheckOutcome(
            journal.Reserve(next_key, uint256{73}, next_lock, std::nullopt),
            llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);
        CheckOutcome(
            journal.Reserve(next_key, uint256{73}, next_lock, first_lock),
            llmq::PQSignerJournalOutcome::RESERVED);
    }

    llmq::CPQSignerJournal restarted{path};
    const auto durable{restarted.GetBranchLock(first_key.genesis_hash,
                                               first_key.pro_tx_hash)};
    BOOST_REQUIRE(durable);
    BOOST_CHECK(durable->height == first_key.absolute_height + 5);
    CheckOutcome(
        restarted.Reserve(first_key, uint256{71}, first_lock, durable),
        llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);
}

BOOST_AUTO_TEST_CASE(durable_certificate_rebases_fork_without_refunding_slot)
{
    const fs::path path = m_path_root / "pq_signer_journal_reconcile";
    const auto fork_a_key{MakeKey()};
    const auto fork_a_lock{MakeBranchLock(fork_a_key)};
    const uint256 fork_a_message{81};
    const auto fork_a_signature{MakeSignature(11)};
    const auto fork_b_certificate{
        MakeCertificate(fork_a_key.absolute_height, MakeHash(50'000), 12)};
    const auto fork_b_lock{
        CertificateLock(fork_a_key.genesis_hash, fork_b_certificate)};

    {
        llmq::CPQSignerJournal journal{path};
        CheckOutcome(
            journal.Reserve(fork_a_key, fork_a_message, fork_a_lock,
                            std::nullopt),
            llmq::PQSignerJournalOutcome::RESERVED);
        CheckOutcome(
            journal.StoreSignature(
                fork_a_key, fork_a_message, fork_a_signature),
            llmq::PQSignerJournalOutcome::STORED);

        // A valid-looking but merely pending certificate has no journal API
        // authority. Until durable acceptance invokes the private boundary,
        // the conflicting branch remains rejected.
        CheckOutcome(
            journal.Reserve(fork_a_key, uint256{82}, fork_b_lock, fork_a_lock),
            llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);
        const llmq::pq::FinalChainLock invalid_certificate;
        CheckOutcome(
            llmq::test::PQSignerJournalTestAccess::Reconcile(
                journal, fork_a_key.genesis_hash, fork_a_key.pro_tx_hash,
                invalid_certificate),
            llmq::PQSignerJournalOutcome::INVALID_ARGUMENT);
        BOOST_REQUIRE(journal.GetBranchLock(
            fork_a_key.genesis_hash, fork_a_key.pro_tx_hash));
        BOOST_CHECK(*journal.GetBranchLock(
                        fork_a_key.genesis_hash, fork_a_key.pro_tx_hash) ==
                    fork_a_lock);
    }

    // Model a crash after the accepted certificate DB fsync but before the
    // signer-journal batch. Startup full verification supplies the same winner
    // to this idempotent reconciliation boundary.
    {
        llmq::CPQSignerJournal restarted{path};
        CheckOutcome(
            llmq::test::PQSignerJournalTestAccess::Reconcile(
                restarted, fork_a_key.genesis_hash, fork_a_key.pro_tx_hash,
                fork_b_certificate),
            llmq::PQSignerJournalOutcome::CERTIFICATE_RECONCILED);
        const auto rebased{restarted.GetBranchLock(
            fork_a_key.genesis_hash, fork_a_key.pro_tx_hash)};
        BOOST_REQUIRE(rebased);
        BOOST_CHECK(*rebased == fork_b_lock);

        // Reconciliation changes only the operator branch authority. The old
        // child slot and exact signature remain permanently consumed.
        const auto replay{restarted.Reserve(
            fork_a_key, fork_a_message, fork_b_lock, fork_b_lock)};
        CheckOutcome(replay, llmq::PQSignerJournalOutcome::REPLAY);
        BOOST_REQUIRE(replay.signature.has_value());
        BOOST_CHECK(*replay.signature == fork_a_signature);
        CheckOutcome(
            restarted.Reserve(
                fork_a_key, uint256{82}, fork_b_lock, fork_b_lock),
            llmq::PQSignerJournalOutcome::CONFLICT);

        auto descendant_key{fork_a_key};
        descendant_key.absolute_height += 5;
        const llmq::PQSignerBranchLock descendant_lock{
            descendant_key.absolute_height,
            MakeHash(50'005),
            MakeHash(60'005),
        };
        CheckOutcome(
            restarted.Reserve(descendant_key, uint256{83}, descendant_lock,
                              fork_b_lock),
            llmq::PQSignerJournalOutcome::RESERVED);
    }

    llmq::CPQSignerJournal restarted_again{path};
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            restarted_again, fork_a_key.genesis_hash, fork_a_key.pro_tx_hash,
            fork_b_certificate),
        llmq::PQSignerJournalOutcome::CERTIFICATE_REPLAY);
    const auto durable{restarted_again.GetBranchLock(
        fork_a_key.genesis_hash, fork_a_key.pro_tx_hash)};
    BOOST_REQUIRE(durable);
    BOOST_CHECK_EQUAL(durable->height, fork_a_key.absolute_height + 5);
    BOOST_CHECK(durable->block_hash == MakeHash(50'005));
}

BOOST_AUTO_TEST_CASE(certificate_marker_detects_conflicting_durable_restore)
{
    const fs::path path = m_path_root / "pq_signer_journal_cert_conflict";
    const auto key{MakeKey()};
    const auto certificate{
        MakeCertificate(key.absolute_height, MakeHash(70'000), 21)};
    auto conflicting_witness{certificate};
    conflicting_witness.signatures[0].signature[0] = 22;

    llmq::CPQSignerJournal journal{path};
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            journal, key.genesis_hash, key.pro_tx_hash, certificate),
        llmq::PQSignerJournalOutcome::CERTIFICATE_RECONCILED);
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            journal, key.genesis_hash, key.pro_tx_hash,
            conflicting_witness),
        llmq::PQSignerJournalOutcome::CORRUPT);
    BOOST_CHECK(!journal.IsHealthy());
}

BOOST_AUTO_TEST_CASE(lower_certificate_never_rewinds_a_higher_local_vote)
{
    const fs::path path = m_path_root / "pq_signer_journal_no_rewind";
    auto key{MakeKey()};
    key.absolute_height += 5;
    const auto local_lock{MakeBranchLock(key)};
    const auto lower_certificate{
        MakeCertificate(key.absolute_height - 5, MakeHash(80'000), 31)};
    const auto adjudicating_certificate{
        MakeCertificate(key.absolute_height, MakeHash(80'005), 32)};

    llmq::CPQSignerJournal journal{path};
    CheckOutcome(
        journal.Reserve(key, uint256{91}, local_lock, std::nullopt),
        llmq::PQSignerJournalOutcome::RESERVED);
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            journal, key.genesis_hash, key.pro_tx_hash, lower_certificate),
        llmq::PQSignerJournalOutcome::CERTIFICATE_RECORDED);
    BOOST_REQUIRE(journal.GetBranchLock(key.genesis_hash, key.pro_tx_hash));
    BOOST_CHECK(*journal.GetBranchLock(key.genesis_hash, key.pro_tx_hash) ==
                local_lock);
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            journal, key.genesis_hash, key.pro_tx_hash, lower_certificate),
        llmq::PQSignerJournalOutcome::CERTIFICATE_REPLAY);

    // A certificate at the local vote's height has adjudicated that fork and
    // may replace it; the lower certificate alone could not.
    CheckOutcome(
        llmq::test::PQSignerJournalTestAccess::Reconcile(
            journal, key.genesis_hash, key.pro_tx_hash,
            adjudicating_certificate),
        llmq::PQSignerJournalOutcome::CERTIFICATE_RECONCILED);
    const auto reconciled{journal.GetBranchLock(
        key.genesis_hash, key.pro_tx_hash)};
    BOOST_REQUIRE(reconciled);
    BOOST_CHECK(*reconciled == CertificateLock(
        key.genesis_hash, adjudicating_certificate));
}

BOOST_AUTO_TEST_CASE(cap_is_exactly_256_distinct_heights)
{
    const fs::path path = m_path_root / "pq_signer_journal_cap";
    const auto base_key = MakeKey();
    auto over_cap = base_key;
    over_cap.absolute_height = 100 + 5 * llmq::PQ_C11_CHILD_USAGE_CAP;

    {
        llmq::CPQSignerJournal journal{path};
        for (std::uint16_t i = 0; i < llmq::PQ_C11_CHILD_USAGE_CAP; ++i) {
            auto key = base_key;
            key.absolute_height = static_cast<std::int32_t>(100 + 5 * i);
            CheckOutcome(
                ReserveSlot(journal, key, uint256{static_cast<std::uint8_t>((i % 250) + 1)}),
                llmq::PQSignerJournalOutcome::RESERVED);
        }
        CheckOutcome(
            ReserveSlot(journal, over_cap, uint256{251}),
            llmq::PQSignerJournalOutcome::CAP_EXHAUSTED);
    }

    llmq::CPQSignerJournal restarted{path};
    CheckOutcome(
        ReserveSlot(restarted, over_cap, uint256{251}),
        llmq::PQSignerJournalOutcome::CAP_EXHAUSTED);

    // Existing slots retain their state even after the cap and restart.
    CheckOutcome(ReserveSlot(restarted, base_key, uint256{1}),
                 llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);
    CheckOutcome(ReserveSlot(restarted, base_key, uint256{252}),
                 llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);

    // The cap is scoped to the complete child identity, not to the process.
    auto other_child = over_cap;
    other_child.child_key_hash = uint256{4};
    CheckOutcome(ReserveSlot(restarted, other_child, uint256{251}),
                 llmq::PQSignerJournalOutcome::RESERVED);
}

BOOST_AUTO_TEST_CASE(payment_audit_uses_distinct_slot_without_moving_branch_lock)
{
    const fs::path path{m_path_root / "pq_signer_journal_purpose"};
    llmq::CPQSignerJournal journal{path};
    BOOST_REQUIRE(journal.IsHealthy());
    const auto chainlock_key{MakeKey()};
    const uint256 chainlock_message{MakeHash(201)};
    CheckOutcome(ReserveSlot(journal, chainlock_key, chainlock_message),
                 llmq::PQSignerJournalOutcome::RESERVED);
    CheckOutcome(journal.StoreSignature(
                     chainlock_key, chainlock_message, MakeSignature(1)),
                 llmq::PQSignerJournalOutcome::STORED);
    const auto branch_lock{journal.GetBranchLock(
        chainlock_key.genesis_hash, chainlock_key.pro_tx_hash)};
    BOOST_REQUIRE(branch_lock);

    auto audit_key{chainlock_key};
    audit_key.purpose = llmq::PQSignerPurpose::PAYMENT_AUDIT;
    const uint256 audit_message{MakeHash(202)};
    CheckOutcome(journal.Reserve(audit_key, audit_message, *branch_lock,
                                 branch_lock),
                 llmq::PQSignerJournalOutcome::RESERVED);
    CheckOutcome(journal.StoreSignature(
                     audit_key, audit_message, MakeSignature(2)),
                 llmq::PQSignerJournalOutcome::STORED);
    BOOST_CHECK(journal.GetBranchLock(chainlock_key.genesis_hash,
                                      chainlock_key.pro_tx_hash) ==
                branch_lock);
    CheckOutcome(journal.Reserve(audit_key, MakeHash(203), *branch_lock,
                                 branch_lock),
                 llmq::PQSignerJournalOutcome::CONFLICT);

    const auto replay{ReserveSlot(journal, chainlock_key,
                                  chainlock_message)};
    CheckOutcome(replay, llmq::PQSignerJournalOutcome::REPLAY);
    BOOST_REQUIRE(replay.signature);
    BOOST_CHECK(*replay.signature == MakeSignature(1));
}

BOOST_AUTO_TEST_CASE(all_key_dimensions_are_isolated)
{
    const fs::path path = m_path_root / "pq_signer_journal_isolation";
    const auto base = MakeKey();
    const uint256 message_hash{41};
    llmq::CPQSignerJournal journal{path};

    CheckOutcome(ReserveSlot(journal, base, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    auto other = base;
    other.genesis_hash = uint256{5};
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    other = base;
    other.child_profile = 2;
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    other = base;
    other.pro_tx_hash = uint256{6};
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    other = base;
    other.quorum_epoch = base.quorum_epoch + 1;
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    other = base;
    other.child_key_hash = uint256{7};
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::RESERVED);

    other = base;
    // Child-key changes do not reset the operator-wide branch lock.
    other.absolute_height -= 5;
    CheckOutcome(ReserveSlot(journal, other, message_hash),
                 llmq::PQSignerJournalOutcome::BRANCH_CONFLICT);
}

BOOST_AUTO_TEST_CASE(null_message_hash_never_consumes_a_slot)
{
    const fs::path path = m_path_root / "pq_signer_journal_null_message";
    const auto key = MakeKey();
    llmq::CPQSignerJournal journal{path};

    CheckOutcome(ReserveSlot(journal, key, uint256{}),
                 llmq::PQSignerJournalOutcome::INVALID_ARGUMENT);
    CheckOutcome(journal.StoreSignature(key, uint256{}, MakeSignature(9)),
                 llmq::PQSignerJournalOutcome::INVALID_ARGUMENT);
    CheckOutcome(ReserveSlot(journal, key, uint256{61}),
                 llmq::PQSignerJournalOutcome::RESERVED);
}

BOOST_AUTO_TEST_CASE(schema_less_nonempty_database_fails_closed)
{
    const fs::path path = m_path_root / "pq_signer_journal_corrupt";
    {
        CDBWrapper raw_db{DBParams{
            .path = path,
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = false}};
        BOOST_REQUIRE(raw_db.Write(std::uint8_t{0x01}, std::uint32_t{7}, /*fSync=*/true));
    }

    llmq::CPQSignerJournal journal{path};
    BOOST_CHECK(!journal.IsHealthy());
    CheckOutcome(ReserveSlot(journal, MakeKey(), uint256{51}),
                 llmq::PQSignerJournalOutcome::CORRUPT);
}

BOOST_AUTO_TEST_SUITE_END()
