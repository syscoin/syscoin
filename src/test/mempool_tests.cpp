// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <evo/deterministicmns.h> // SYSCOIN: deterministic provider-state fixtures.
#include <evo/pq_providertx.h> // SYSCOIN: PQ provider transaction fixtures.
#include <evo/pq_registry.h> // SYSCOIN: PQ registry reservation fixtures.
#include <evo/providertx.h> // SYSCOIN: provider transaction fixtures.
#include <evo/specialtx.h> // SYSCOIN: special-transaction mempool fixtures.
#include <netbase.h> // SYSCOIN: provider service fixtures.
#include <policy/policy.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h> // SYSCOIN: branch-bound provider admission fixtures.

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <vector>

static constexpr auto REMOVAL_REASON_DUMMY = MemPoolRemovalReason::REPLACED;

class MemPoolTest final : public CTxMemPool
{
public:
    using CTxMemPool::GetMinFee;
};

// SYSCOIN BEGIN: expose fork-only mempool reservation invariants to tests.
struct PQMempoolTestAccess {
    static void ResetPackageProviderConflictStats(CTxMemPool& pool)
        EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
    {
        pool.m_last_package_provider_conflict_stats = {};
    }

    static std::pair<std::size_t, std::size_t>
    LastPackageProviderConflictStats(const CTxMemPool& pool)
        EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
    {
        const auto& stats{pool.m_last_package_provider_conflict_stats};
        return {stats.registry_operator_requests,
                stats.indexed_provider_references_examined};
    }

    static std::optional<size_t> FindPackageProviderTxConflict(
        const CTxMemPool& pool,
        const std::vector<CTransactionRef>& package,
        const CDeterministicMNList& mn_list,
        const llmq::pq::PQRegistryMempoolView& registry_view)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
    {
        return pool.FindPackageProviderTxConflict(package, mn_list,
                                                   registry_view);
    }

    static bool RebuildPQRegistryReservations(
        CTxMemPool& pool,
        const llmq::pq::PQRegistryMempoolView& registry_view)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
    {
        return pool.RebuildPQRegistryReservations(registry_view);
    }

    static void RemoveProTxConflicts(
        CTxMemPool& pool,
        const CTransaction& tx,
        const CDeterministicMNList& mn_list)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
    {
        pool.removeProTxConflicts(tx, mn_list);
    }
};
// SYSCOIN END: expose fork-only mempool reservation invariants to tests.

BOOST_FIXTURE_TEST_SUITE(mempool_tests, TestingSetup)

// SYSCOIN BEGIN: PQ provider mempool conflict and reservation tests.
namespace {

uint256 PQMempoolHash(uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = value & 0xff;
    hash.begin()[1] = (value >> 8) & 0xff;
    hash.begin()[2] = (value >> 16) & 0xff;
    hash.begin()[3] = (value >> 24) & 0xff;
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

CMutableTransaction PQMempoolBaseTransaction(int32_t version, uint32_t id)
{
    CMutableTransaction tx;
    tx.nVersion = version;
    tx.vin.emplace_back(COutPoint{PQMempoolHash(10'000 + id), id});
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    return tx;
}

llmq::pq::ChildKeyTreeCommitment PQMempoolCommitment(uint32_t tag)
{
    llmq::pq::ChildKeyTreeCommitment commitment;
    commitment.generation = 1;
    commitment.tree_id = PQMempoolHash(20'000 + tag);
    commitment.root = PQMempoolHash(30'000 + tag);
    return commitment;
}

CMutableTransaction PQGlobalKeyTransaction(const uint256& pro_tx_hash,
                                            uint32_t key_tag = 1,
                                            uint32_t tree_tag = 0)
{
    CMutableTransaction tx = PQMempoolBaseTransaction(
        SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY, 1);
    llmq::pq::GlobalKeyTxPayload payload;
    payload.operation = llmq::pq::GlobalKeyOperation::ROTATE;
    payload.pro_tx_hash = pro_tx_hash;
    payload.candidate.key_version = 2;
    payload.candidate.public_key[0] = static_cast<uint8_t>(key_tag);
    payload.candidate.child_key_commitment =
        PQMempoolCommitment(tree_tag == 0 ? key_tag : tree_tag);
    payload.transaction_inputs_hash = PQMempoolHash(2);
    payload.authorization[0] = 1;
    SetTxPayload(tx, payload);
    return tx;
}

CMutableTransaction PQRevokeTransaction(const uint256& pro_tx_hash)
{
    CMutableTransaction tx = PQMempoolBaseTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE, 3);
    CProUpRevTx payload;
    payload.nVersion = CProUpRevTx::PQ_VERSION;
    payload.proTxHash = pro_tx_hash;
    payload.inputsHash = PQMempoolHash(4);
    payload.globalKeyVersion = 1;
    payload.pqSig[0] = 1;
    SetTxPayload(tx, payload);
    return tx;
}

CMutableTransaction PQServiceTransaction(
    const uint256& pro_tx_hash,
    const CService& service = {},
    std::vector<unsigned char> nevm_address = {})
{
    CMutableTransaction tx = PQMempoolBaseTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE, 4);
    CProUpServTx payload;
    payload.nVersion = CProUpServTx::PQ_VERSION;
    payload.proTxHash = pro_tx_hash;
    payload.addr = service;
    payload.inputsHash = PQMempoolHash(5);
    payload.globalKeyVersion = 1;
    payload.pqSig[0] = 1;
    payload.vchNEVMAddress = std::move(nevm_address);
    SetTxPayload(tx, payload);
    return tx;
}

CMutableTransaction PQRegistrarTransaction(const uint256& pro_tx_hash)
{
    CMutableTransaction tx = PQMempoolBaseTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR, 5);
    CProUpRegTx payload;
    payload.nVersion = CProUpRegTx::PQ_VERSION;
    payload.proTxHash = pro_tx_hash;
    payload.keyIDVoting.begin()[0] = 1;
    payload.inputsHash = PQMempoolHash(6);
    payload.vchSig.assign(1, 1);
    SetTxPayload(tx, payload);
    return tx;
}

CMutableTransaction PQRegisterTransaction(
    uint32_t tag,
    const CService& service,
    const CKeyID& owner,
    const COutPoint& collateral)
{
    CMutableTransaction tx = PQMempoolBaseTransaction(
        SYSCOIN_TX_VERSION_MN_REGISTER, 100 + tag);
    CProRegTx payload;
    payload.nVersion = CProRegTx::PQ_VERSION;
    payload.collateralOutpoint = collateral;
    payload.addr = service;
    payload.keyIDOwner = owner;
    payload.keyIDVoting.begin()[0] = 1;
    payload.scriptPayout = CScript{} << OP_TRUE;
    payload.inputsHash = PQMempoolHash(40'000 + tag);
    payload.vchSig.assign(1, 1);
    SetTxPayload(tx, payload);
    return tx;
}

CDeterministicMNList PQMempoolMNList(const uint256& pro_tx_hash,
                                     const COutPoint& collateral)
{
    CDeterministicMNList list{PQMempoolHash(60'000), 1, 1};
    auto dmn{std::make_shared<CDeterministicMN>(1)};
    dmn->proTxHash = pro_tx_hash;
    dmn->collateralOutpoint = collateral;
    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner.begin()[0] = 1;
    dmn->pdmnState = std::move(state);
    list.AddMN(std::move(dmn), /*fBumpTotalCount=*/false);
    return list;
}

} // namespace

BOOST_AUTO_TEST_CASE(PQOperatorUpdateConflicts)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    const CBlockIndex* active_tip{m_node.chainman->ActiveTip()};

    const uint256 pro_tx_hash{PQMempoolHash(1)};
    const auto global{PQGlobalKeyTransaction(pro_tx_hash)};
    const auto revoke{PQRevokeTransaction(pro_tx_hash)};
    const auto service{PQServiceTransaction(pro_tx_hash)};
    const auto registrar{PQRegistrarTransaction(pro_tx_hash)};

    // Production admission supplies a non-null tip and requires the exact-tip
    // target collateral to be resolved before addUnchecked mutates any index.
    // A missing target/incomplete admission result must fail closed without
    // publishing an unguarded PQ reservation.
    std::optional<COutPoint> unresolved_collateral;
    BOOST_CHECK(pool.existsProviderTxConflict(
        CTransaction{global}, active_tip, &unresolved_collateral));
    BOOST_CHECK(!unresolved_collateral);
    BOOST_CHECK(!pool.addUnchecked(entry.FromTx(global), true, active_tip,
                                   unresolved_collateral));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(global.GetHash())));

    BOOST_CHECK(!pool.existsProviderTxConflict(CTransaction{global},
                                                active_tip));
    pool.addUnchecked(entry.FromTx(global));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{revoke},
                                               active_tip));
    pool.removeRecursive(CTransaction{global}, REMOVAL_REASON_DUMMY);

    pool.addUnchecked(entry.FromTx(service));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{revoke},
                                               active_tip));
    pool.removeRecursive(CTransaction{service}, REMOVAL_REASON_DUMMY);

    pool.addUnchecked(entry.FromTx(registrar));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{revoke},
                                               active_tip));
    pool.removeRecursive(CTransaction{registrar}, REMOVAL_REASON_DUMMY);

    pool.addUnchecked(entry.FromTx(revoke));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{global},
                                               active_tip));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{service},
                                               active_tip));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{registrar},
                                               active_tip));
    pool.removeRecursive(CTransaction{revoke}, REMOVAL_REASON_DUMMY);

    BOOST_CHECK(!pool.existsProviderTxConflict(CTransaction{global},
                                                active_tip));
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    const auto same_key{PQGlobalKeyTransaction(PQMempoolHash(2), 1, 2)};
    const auto same_tree{PQGlobalKeyTransaction(PQMempoolHash(3), 2, 1)};
    const auto distinct_global{
        PQGlobalKeyTransaction(PQMempoolHash(4), 3, 3)};
    llmq::pq::PQRegistryMempoolView synthetic_registry_view;
    synthetic_registry_view.operators = {
        {.pro_tx_hash = pro_tx_hash,
         .state_exists = 0,
         .has_global_key = 0,
         .current_commitment = {}},
        {.pro_tx_hash = PQMempoolHash(2),
         .state_exists = 0,
         .has_global_key = 0,
         .current_commitment = {}},
        {.pro_tx_hash = PQMempoolHash(3),
         .state_exists = 0,
         .has_global_key = 0,
         .current_commitment = {}},
        {.pro_tx_hash = PQMempoolHash(4),
         .state_exists = 0,
         .has_global_key = 0,
         .current_commitment = {}},
    };
    std::sort(synthetic_registry_view.operators.begin(),
              synthetic_registry_view.operators.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    const auto find_package_conflict =
        [&](const std::vector<CTransactionRef>& package)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
            return PQMempoolTestAccess::FindPackageProviderTxConflict(
                pool, package, CDeterministicMNList{},
                synthetic_registry_view);
        };
    pool.addUnchecked(entry.FromTx(global));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{same_key},
                                               active_tip));
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{same_tree},
                                               active_tip));
    BOOST_CHECK(!pool.existsProviderTxConflict(CTransaction{distinct_global},
                                                active_tip));
    pool.removeRecursive(CTransaction{global}, REMOVAL_REASON_DUMMY);

    // Removing an unchecked duplicate must not erase the first transaction's
    // uniqueness reservations.
    pool.addUnchecked(entry.FromTx(global));
    pool.addUnchecked(entry.FromTx(same_key));
    pool.removeRecursive(CTransaction{same_key}, REMOVAL_REASON_DUMMY);
    BOOST_CHECK(pool.existsProviderTxConflict(CTransaction{same_tree},
                                               active_tip));
    pool.removeRecursive(CTransaction{global}, REMOVAL_REASON_DUMMY);
    BOOST_CHECK(!pool.existsProviderTxConflict(CTransaction{same_tree},
                                                active_tip));

    // Package members are prechecked before any of them updates the mempool's
    // provider indexes. The package-level view must enforce the same ordering
    // invariants without inserting a partial package.
    const auto other_global{PQGlobalKeyTransaction(PQMempoolHash(2), 2)};
    auto conflict_index = find_package_conflict(
        {MakeTransactionRef(global), MakeTransactionRef(global)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 1U);
    BOOST_CHECK(!find_package_conflict(
        {MakeTransactionRef(global), MakeTransactionRef(other_global)}));
    conflict_index = find_package_conflict(
        {MakeTransactionRef(global), MakeTransactionRef(same_key)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 1U);
    conflict_index = find_package_conflict(
        {MakeTransactionRef(global), MakeTransactionRef(same_tree)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 1U);

    pool.addUnchecked(entry.FromTx(global));
    conflict_index = find_package_conflict({MakeTransactionRef(same_key)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 0U);
    pool.removeRecursive(CTransaction{global}, REMOVAL_REASON_DUMMY);

    const std::vector<std::pair<const CMutableTransaction*,
                                const CMutableTransaction*>> package_conflicts{
        {&global, &revoke},
        {&service, &revoke},
        {&registrar, &revoke},
        {&revoke, &global},
        {&revoke, &service},
        {&revoke, &registrar},
    };
    for (const auto& [first, second] : package_conflicts) {
        conflict_index = find_package_conflict(
            {MakeTransactionRef(*first), MakeTransactionRef(*second)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 1U);
    }
    BOOST_CHECK(!find_package_conflict(
        {MakeTransactionRef(service), MakeTransactionRef(registrar)}));

    // Mirror the other provider indexes as well: batching must not bypass
    // address, NEVM-address, owner-key, or collateral uniqueness merely
    // because no package member has reached addUnchecked yet.
    const CService shared_service{LookupNumeric("127.0.0.1", 19'999)};
    const CService other_service{LookupNumeric("127.0.0.1", 20'000)};
    std::vector<unsigned char> shared_nevm_address(20, 7);
    const auto service_address_a{PQServiceTransaction(
        PQMempoolHash(11), shared_service)};
    const auto service_address_b{PQServiceTransaction(
        PQMempoolHash(12), shared_service)};
    const auto service_nevm_a{PQServiceTransaction(
        PQMempoolHash(13), shared_service, shared_nevm_address)};
    const auto service_nevm_b{PQServiceTransaction(
        PQMempoolHash(14), other_service, shared_nevm_address)};
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(service_address_a),
         MakeTransactionRef(service_address_b)}));
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(service_nevm_a),
         MakeTransactionRef(service_nevm_b)}));
    BOOST_CHECK(!find_package_conflict(
        {MakeTransactionRef(service_address_a),
         MakeTransactionRef(service_nevm_b)}));

    CKeyID owner_a;
    owner_a.begin()[0] = 1;
    CKeyID owner_b;
    owner_b.begin()[0] = 2;
    const COutPoint shared_collateral{PQMempoolHash(50'000), 0};
    const auto registration_a{PQRegisterTransaction(
        1, shared_service, owner_a, shared_collateral)};
    const auto registration_owner_conflict{PQRegisterTransaction(
        2, other_service, owner_a,
        COutPoint{PQMempoolHash(50'001), 0})};
    const auto registration_collateral_conflict{PQRegisterTransaction(
        3, other_service, owner_b, shared_collateral)};
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(registration_a),
         MakeTransactionRef(registration_owner_conflict)}));
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(registration_a),
         MakeTransactionRef(registration_collateral_conflict)}));
    const auto registration_distinct{PQRegisterTransaction(
        4, CService{LookupNumeric("127.0.0.1", 20'001)}, owner_b,
        COutPoint{PQMempoolHash(50'002), 0})};
    BOOST_CHECK(!find_package_conflict(
        {MakeTransactionRef(registration_a),
         MakeTransactionRef(registration_distinct)}));
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(service_address_a),
         MakeTransactionRef(registration_a)}));

    // Removing an unchecked duplicate must leave the first provider index
    // owner intact, just as for global-key and tree-id reservations above.
    pool.addUnchecked(entry.FromTx(registration_a));
    pool.addUnchecked(entry.FromTx(registration_owner_conflict));
    pool.removeRecursive(CTransaction{registration_owner_conflict},
                         REMOVAL_REASON_DUMMY);
    conflict_index = find_package_conflict(
        {MakeTransactionRef(registration_owner_conflict)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 0U);
    pool.removeRecursive(CTransaction{registration_a}, REMOVAL_REASON_DUMMY);

    CMutableTransaction collateral_spend{PQMempoolBaseTransaction(2, 200)};
    collateral_spend.vin[0].prevout = shared_collateral;
    BOOST_CHECK(find_package_conflict(
        {MakeTransactionRef(collateral_spend),
         MakeTransactionRef(registration_a)}));

    // An external-collateral ProReg removes the existing operator from the
    // deterministic list. PQ registry mutations are invalid in either order.
    // Ordinary mutations may precede replacement only when transaction
    // ancestry forces that order; independent entries remain excluded because
    // fee sorting gives them no deterministic block order.
    const uint256 replaced_operator{PQMempoolHash(60'001)};
    const COutPoint replaced_collateral{PQMempoolHash(60'002), 1};
    const auto replacement{PQRegisterTransaction(
        20, CService{LookupNumeric("127.0.0.1", 20'020)}, owner_b,
        replaced_collateral)};
    const auto replacement_global{
        PQGlobalKeyTransaction(replaced_operator, 20, 20)};
    const auto replacement_revoke{PQRevokeTransaction(replaced_operator)};
    const auto replacement_service{
        PQServiceTransaction(replaced_operator)};
    const auto replacement_registrar{
        PQRegistrarTransaction(replaced_operator)};
    const auto replacement_list{
        PQMempoolMNList(replaced_operator, replaced_collateral)};
    llmq::pq::PQRegistryMempoolView replacement_view;
    replacement_view.operator_state_count = 1;
    replacement_view.used_tree_id_count = 1;
    replacement_view.operators.push_back({
        .pro_tx_hash = replaced_operator,
        .state_exists = 1,
        .has_global_key = 1,
        .current_commitment = PQMempoolCommitment(21),
    });
    const auto find_replacement_conflict =
        [&](const std::vector<CTransactionRef>& package)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
            return PQMempoolTestAccess::FindPackageProviderTxConflict(
                pool, package, replacement_list, replacement_view);
        };
    // SYSCOIN: A single registry update cannot remove its own target DMN;
    // reject it before admission or block-template assembly.
    for (const auto* mutation : {&replacement_global,
                                 &replacement_revoke}) {
        CMutableTransaction self_spend{*mutation};
        self_spend.vin[0].prevout = replaced_collateral;
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(self_spend)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 0U);
    }
    for (const auto* mutation : {&replacement_global,
                                 &replacement_revoke}) {
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(*mutation), MakeTransactionRef(replacement)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 1U);
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(replacement), MakeTransactionRef(*mutation)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 1U);

        pool.addUnchecked(entry.FromTx(*mutation));
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(replacement)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 0U);
        pool.removeRecursive(CTransaction{*mutation}, REMOVAL_REASON_DUMMY);

        pool.addUnchecked(entry.FromTx(replacement));
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(*mutation)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 0U);
        pool.removeRecursive(CTransaction{replacement}, REMOVAL_REASON_DUMMY);
    }

    for (const auto* mutation : {&replacement_service,
                                 &replacement_registrar}) {
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(*mutation), MakeTransactionRef(replacement)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 1U);
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(replacement), MakeTransactionRef(*mutation)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 1U);

        CMutableTransaction ordered_replacement{replacement};
        ordered_replacement.vin[0].prevout =
            COutPoint{mutation->GetHash(), 0};
        BOOST_CHECK(!find_replacement_conflict(
            {MakeTransactionRef(*mutation),
             MakeTransactionRef(ordered_replacement)}));

        pool.addUnchecked(entry.FromTx(*mutation));
        BOOST_CHECK(!find_replacement_conflict(
            {MakeTransactionRef(ordered_replacement)}));
        pool.removeRecursive(CTransaction{*mutation}, REMOVAL_REASON_DUMMY);

        pool.addUnchecked(entry.FromTx(replacement));
        conflict_index = find_replacement_conflict(
            {MakeTransactionRef(*mutation)});
        BOOST_REQUIRE(conflict_index);
        BOOST_CHECK_EQUAL(*conflict_index, 0U);
        pool.removeRecursive(CTransaction{replacement}, REMOVAL_REASON_DUMMY);
    }

    // A replacement only needs one ancestry walk even when an operator has
    // many pending mutations. Every live reference is allowed when the UTXO
    // chain forces all mutations to precede the replacement.
    std::vector<CMutableTransaction> ordered_mutations;
    ordered_mutations.reserve(32);
    for (uint32_t i{0}; i < 32; ++i) {
        CMutableTransaction mutation{
            (i % 2 == 0) ? PQServiceTransaction(replaced_operator)
                         : PQRegistrarTransaction(replaced_operator)};
        mutation.vin[0].prevout =
            i == 0
                ? COutPoint{PQMempoolHash(61'000), 0}
                : COutPoint{ordered_mutations.back().GetHash(), 0};
        ordered_mutations.push_back(std::move(mutation));
    }
    CMutableTransaction ordered_many_replacement{replacement};
    ordered_many_replacement.vin[0].prevout =
        COutPoint{ordered_mutations.back().GetHash(), 0};
    std::vector<CTransactionRef> ordered_package;
    ordered_package.reserve(ordered_mutations.size() + 1);
    for (const auto& mutation : ordered_mutations) {
        ordered_package.push_back(MakeTransactionRef(mutation));
    }
    ordered_package.push_back(MakeTransactionRef(ordered_many_replacement));
    BOOST_CHECK(!find_replacement_conflict(ordered_package));

    for (const auto& mutation : ordered_mutations) {
        pool.addUnchecked(entry.FromTx(mutation));
    }
    BOOST_CHECK(!find_replacement_conflict(
        {MakeTransactionRef(ordered_many_replacement)}));
    pool.removeRecursive(CTransaction{ordered_mutations.front()},
                         REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    // Package admission may stage up to 64 provider mutations locally, but it
    // must fail closed before doing unbounded package-local work.
    std::vector<CMutableTransaction> bounded_mutations;
    std::vector<CTransactionRef> bounded_package;
    bounded_mutations.reserve(65);
    bounded_package.reserve(65);
    for (uint32_t i{0}; i < 65; ++i) {
        auto mutation{PQServiceTransaction(PQMempoolHash(90'000 + i))};
        mutation.vin[0].prevout =
            COutPoint{PQMempoolHash(91'000 + i), 0};
        bounded_mutations.push_back(std::move(mutation));
        bounded_package.push_back(
            MakeTransactionRef(bounded_mutations.back()));
    }
    const std::vector<CTransactionRef> allowed_package{
        bounded_package.begin(), bounded_package.begin() + 64};
    BOOST_CHECK(!find_replacement_conflict(allowed_package));
    conflict_index = find_replacement_conflict(bounded_package);
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 0U);

    // Unrelated provider reservations must not be copied or walked for a
    // replacement. Only references indexed under the replaced operator are
    // relevant to its UTXO-ordering check.
    constexpr uint32_t unrelated_count{512};
    std::vector<CMutableTransaction> unrelated_mutations;
    unrelated_mutations.reserve(unrelated_count);
    for (uint32_t i{0}; i < unrelated_count; ++i) {
        auto mutation{PQServiceTransaction(PQMempoolHash(100'000 + i))};
        mutation.vin[0].prevout =
            COutPoint{PQMempoolHash(110'000 + i), 0};
        unrelated_mutations.push_back(std::move(mutation));
        pool.addUnchecked(entry.FromTx(unrelated_mutations.back()));
    }
    pool.addUnchecked(entry.FromTx(replacement_service));
    CMutableTransaction indexed_replacement{replacement};
    indexed_replacement.vin[0].prevout =
        COutPoint{replacement_service.GetHash(), 0};
    PQMempoolTestAccess::ResetPackageProviderConflictStats(pool);
    BOOST_CHECK(!find_replacement_conflict(
        {MakeTransactionRef(indexed_replacement)}));
    const auto [registry_requests, indexed_references]{
        PQMempoolTestAccess::LastPackageProviderConflictStats(pool)};
    BOOST_CHECK_EQUAL(registry_requests, 0U);
    BOOST_CHECK_EQUAL(indexed_references, 1U);
    BOOST_CHECK_EQUAL(pool.size(), unrelated_count + 1);
    pool.RemoveProviderTransactionsForReorg();
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    // Connected external-collateral replacement and PQ mutations evict the
    // opposite pending transaction plus descendants using the parent-tip DMN
    // list, so block assembly never sees a stale provider entry.
    CMutableTransaction replacement_global_child{
        PQMempoolBaseTransaction(2, 410)};
    replacement_global_child.vin[0].prevout =
        COutPoint{replacement_global.GetHash(), 0};
    CMutableTransaction replacement_service_child{
        PQMempoolBaseTransaction(2, 411)};
    replacement_service_child.vin[0].prevout =
        COutPoint{replacement_service.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(replacement_global));
    pool.addUnchecked(entry.FromTx(replacement_global_child));
    pool.addUnchecked(entry.FromTx(replacement_service));
    pool.addUnchecked(entry.FromTx(replacement_service_child));
    BOOST_REQUIRE_EQUAL(pool.size(), 4U);
    PQMempoolTestAccess::RemoveProTxConflicts(
        pool, CTransaction{replacement}, replacement_list);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    CMutableTransaction replacement_child{
        PQMempoolBaseTransaction(2, 412)};
    replacement_child.vin[0].prevout =
        COutPoint{replacement.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(replacement));
    pool.addUnchecked(entry.FromTx(replacement_child));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);
    PQMempoolTestAccess::RemoveProTxConflicts(
        pool, CTransaction{replacement_global}, replacement_list);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    CMutableTransaction mined_collateral_spend{
        PQMempoolBaseTransaction(2, 420)};
    mined_collateral_spend.vin[0].prevout = replaced_collateral;
    BOOST_CHECK(!find_replacement_conflict(
        {MakeTransactionRef(replacement_service),
         MakeTransactionRef(mined_collateral_spend)}));
    BOOST_CHECK(!find_replacement_conflict(
        {MakeTransactionRef(mined_collateral_spend),
         MakeTransactionRef(replacement_service)}));
    conflict_index = find_replacement_conflict(
        {MakeTransactionRef(replacement_global),
         MakeTransactionRef(mined_collateral_spend)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 1U);
    conflict_index = find_replacement_conflict(
        {MakeTransactionRef(mined_collateral_spend),
         MakeTransactionRef(replacement_global)});
    BOOST_REQUIRE(conflict_index);
    BOOST_CHECK_EQUAL(*conflict_index, 1U);

    const std::vector<std::pair<const CMutableTransaction*,
                                const CMutableTransaction*>> conflict_cases{
        {&global, &revoke},
        {&service, &revoke},
        {&registrar, &revoke},
        {&revoke, &service},
        {&revoke, &registrar},
    };
    for (const auto& [mempool_tx, block_tx] : conflict_cases) {
        pool.addUnchecked(entry.FromTx(*mempool_tx));
        BOOST_REQUIRE_EQUAL(pool.size(), 1U);
        pool.removeForBlock({MakeTransactionRef(*block_tx)}, 1);
        BOOST_CHECK_EQUAL(pool.size(), 0U);
    }

    CMutableTransaction registration_child{
        PQMempoolBaseTransaction(2, 450)};
    registration_child.vin[0].prevout =
        COutPoint{registration_a.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(registration_a));
    pool.addUnchecked(entry.FromTx(registration_child));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);
    pool.removeForBlock({MakeTransactionRef(collateral_spend)}, 1);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    CMutableTransaction global_child{PQMempoolBaseTransaction(2, 500)};
    global_child.vin[0].prevout = COutPoint{global.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(global));
    pool.addUnchecked(entry.FromTx(global_child));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);
    pool.removeForBlock({MakeTransactionRef(same_key)}, 1);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    pool.addUnchecked(entry.FromTx(global));
    BOOST_REQUIRE_EQUAL(pool.size(), 1U);
    pool.removeForBlock({MakeTransactionRef(same_tree)}, 1);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    const uint256 rotated_operator{PQMempoolHash(80'000)};
    const auto pending_service{PQServiceTransaction(rotated_operator)};
    CMutableTransaction pending_service_child{
        PQMempoolBaseTransaction(2, 799)};
    pending_service_child.vin[0].prevout =
        COutPoint{pending_service.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(pending_service));
    pool.addUnchecked(entry.FromTx(pending_service_child));
    BOOST_REQUIRE_EQUAL(pool.size(), 2U);
    pool.removeForBlock(
        {MakeTransactionRef(PQGlobalKeyTransaction(rotated_operator, 30, 30))},
        1);
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    // A reorg changes branch-bound provider membership and signing keys. Drop
    // those transactions and descendants without scanning/verifying SLH under
    // the global locks; unrelated ordinary transactions must survive.
    const auto stale_service{
        PQServiceTransaction(PQMempoolHash(80'001))};
    CMutableTransaction stale_child{PQMempoolBaseTransaction(2, 800)};
    stale_child.vin[0].prevout = COutPoint{stale_service.GetHash(), 0};
    const auto ordinary{PQMempoolBaseTransaction(2, 801)};
    pool.addUnchecked(entry.FromTx(stale_service));
    pool.addUnchecked(entry.FromTx(stale_child));
    pool.addUnchecked(entry.FromTx(ordinary));
    BOOST_REQUIRE_EQUAL(pool.size(), 3U);
    pool.RemoveProviderTransactionsForReorg();
    BOOST_CHECK_EQUAL(pool.size(), 1U);
    BOOST_CHECK(pool.exists(GenTxid::Txid(ordinary.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(stale_service.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(stale_child.GetHash())));
    BOOST_CHECK(!pool.existsProviderTxConflict(
        CTransaction{PQRevokeTransaction(PQMempoolHash(80'001))},
        active_tip));
    pool.removeRecursive(CTransaction{ordinary}, REMOVAL_REASON_DUMMY);

    // A normal forward connection to A - 1 changes the next-block provider
    // wire era. Drop legacy provider payloads and descendants without evicting
    // preparation-era global-key registrations or ordinary transactions.
    CMutableTransaction legacy_service{PQServiceTransaction(
        PQMempoolHash(80'002))};
    CProUpServTx legacy_payload;
    BOOST_REQUIRE(GetTxPayload(legacy_service, legacy_payload));
    legacy_payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
    legacy_payload.legacySig = {};
    legacy_payload.globalKeyVersion = 0;
    legacy_payload.pqSig = {};
    SetTxPayload(legacy_service, legacy_payload);
    CMutableTransaction legacy_child{PQMempoolBaseTransaction(2, 802)};
    legacy_child.vin[0].prevout =
        COutPoint{legacy_service.GetHash(), 0};
    const auto retained_global{
        PQGlobalKeyTransaction(PQMempoolHash(80'003), 31, 31)};
    const auto retained_ordinary{PQMempoolBaseTransaction(2, 803)};
    pool.addUnchecked(entry.FromTx(legacy_service));
    pool.addUnchecked(entry.FromTx(legacy_child));
    pool.addUnchecked(entry.FromTx(retained_global));
    pool.addUnchecked(entry.FromTx(retained_ordinary));
    BOOST_REQUIRE_EQUAL(pool.size(), 4U);
    pool.RemoveLegacyProviderTransactionsForPQActivation();
    BOOST_CHECK_EQUAL(pool.size(), 2U);
    BOOST_CHECK(!pool.exists(GenTxid::Txid(legacy_service.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(legacy_child.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(retained_global.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(retained_ordinary.GetHash())));
    pool.removeRecursive(CTransaction{retained_global}, REMOVAL_REASON_DUMMY);
    pool.removeRecursive(CTransaction{retained_ordinary},
                         REMOVAL_REASON_DUMMY);
}
BOOST_AUTO_TEST_CASE(PQRegistryMempoolCapacity)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const CBlockIndex* active_tip{m_node.chainman->ActiveTip()};

    const uint256 operator_a{PQMempoolHash(70'001)};
    const uint256 operator_b{PQMempoolHash(70'002)};
    const auto global_a{PQGlobalKeyTransaction(operator_a, 10, 10)};
    const auto global_b{PQGlobalKeyTransaction(operator_b, 11, 11)};
    const std::vector<CTransactionRef> both{
        MakeTransactionRef(global_a), MakeTransactionRef(global_b)};

    auto missing_view = [&](size_t operator_count, size_t tree_count) {
        llmq::pq::PQRegistryMempoolView view;
        view.operator_state_count = operator_count;
        view.used_tree_id_count = tree_count;
        view.operators = {
            {.pro_tx_hash = operator_a,
             .state_exists = 0,
             .has_global_key = 0,
             .current_commitment = {}},
            {.pro_tx_hash = operator_b,
             .state_exists = 0,
             .has_global_key = 0,
             .current_commitment = {}},
        };
        std::sort(view.operators.begin(), view.operators.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return lhs.pro_tx_hash < rhs.pro_tx_hash;
                  });
        return view;
    };

    auto view{missing_view(llmq::pq::MAX_PQ_OPERATOR_STATES - 1,
                           llmq::pq::MAX_PQ_USED_TREE_IDS - 1)};
    BOOST_CHECK(!pool.FindPackageProviderTxConflict(
        {both.front()}, active_tip, view));
    const auto boundary_conflict{pool.FindPackageProviderTxConflict(
        both, active_tip, view)};
    BOOST_REQUIRE(boundary_conflict);
    BOOST_CHECK_EQUAL(*boundary_conflict, 1U);

    // A rotation that retains the exact current commitment consumes neither
    // permanent counter, even when both registries are exactly full.
    view = missing_view(llmq::pq::MAX_PQ_OPERATOR_STATES,
                        llmq::pq::MAX_PQ_USED_TREE_IDS);
    auto current_a{std::find_if(
        view.operators.begin(), view.operators.end(), [&](const auto& state) {
            return state.pro_tx_hash == operator_a;
        })};
    BOOST_REQUIRE(current_a != view.operators.end());
    current_a->state_exists = 1;
    current_a->has_global_key = 1;
    current_a->current_commitment = PQMempoolCommitment(10);
    BOOST_CHECK(!pool.FindPackageProviderTxConflict(
        {both.front()}, active_tip, view));
    const auto full_operator_conflict{pool.FindPackageProviderTxConflict(
        {both.back()}, active_tip, view)};
    BOOST_REQUIRE(full_operator_conflict);
    BOOST_CHECK_EQUAL(*full_operator_conflict, 0U);

    // Existing operator state does not hide a newly consumed tree-id slot.
    auto current_b{std::find_if(
        view.operators.begin(), view.operators.end(), [&](const auto& state) {
            return state.pro_tx_hash == operator_b;
        })};
    BOOST_REQUIRE(current_b != view.operators.end());
    current_b->state_exists = 1;
    current_b->has_global_key = 1;
    current_b->current_commitment = PQMempoolCommitment(12);
    const auto full_tree_conflict{pool.FindPackageProviderTxConflict(
        {both.back()}, active_tip, view)};
    BOOST_REQUIRE(full_tree_conflict);
    BOOST_CHECK_EQUAL(*full_tree_conflict, 0U);

    // Malformed over-cap summaries fail closed without unsigned wraparound.
    view.operator_state_count = llmq::pq::MAX_PQ_OPERATOR_STATES + 1;
    const auto over_cap_conflict{pool.FindPackageProviderTxConflict(
        {both.front()}, active_tip, view)};
    BOOST_REQUIRE(over_cap_conflict);
    BOOST_CHECK_EQUAL(*over_cap_conflict, 0U);

    TestMemPoolEntryHelper entry;
    CMutableTransaction child{PQMempoolBaseTransaction(2, 900)};
    child.vin[0].prevout = COutPoint{global_a.GetHash(), 0};
    pool.addUnchecked(entry.FromTx(global_a));
    pool.addUnchecked(entry.FromTx(child));
    auto aged_view{missing_view(0, 0)};
    aged_view.has_next_block_schedule = 1;
    aged_view.next_first_mutable_epoch = 1;
    BOOST_CHECK(PQMempoolTestAccess::RebuildPQRegistryReservations(
        pool, aged_view));
    BOOST_CHECK_EQUAL(pool.size(), 0U);

    // StartsAtMutableCutoff does not apply when a rotation deliberately keeps
    // the exact current commitment, so it survives the same cutoff advance.
    pool.addUnchecked(entry.FromTx(global_a));
    auto reused_view{aged_view};
    auto reused{std::find_if(
        reused_view.operators.begin(), reused_view.operators.end(),
        [&](const auto& state) {
            return state.pro_tx_hash == operator_a;
        })};
    BOOST_REQUIRE(reused != reused_view.operators.end());
    reused->state_exists = 1;
    reused->has_global_key = 1;
    reused->current_commitment = PQMempoolCommitment(10);
    BOOST_CHECK(PQMempoolTestAccess::RebuildPQRegistryReservations(
        pool, reused_view));
    BOOST_CHECK_EQUAL(pool.size(), 1U);
    pool.removeRecursive(CTransaction{global_a}, REMOVAL_REASON_DUMMY);

    // Loading branch state for a package is proportional to the package's
    // operators, regardless of unrelated global-key reservations already in
    // the mempool.
    constexpr uint32_t unrelated_count{128};
    std::vector<CMutableTransaction> unrelated_globals;
    unrelated_globals.reserve(unrelated_count);
    for (uint32_t i{0}; i < unrelated_count; ++i) {
        auto unrelated{PQGlobalKeyTransaction(
            PQMempoolHash(120'000 + i), 64 + i, 1'000 + i)};
        unrelated.vin[0].prevout =
            COutPoint{PQMempoolHash(130'000 + i), 0};
        unrelated_globals.push_back(std::move(unrelated));
        pool.addUnchecked(entry.FromTx(unrelated_globals.back()));
    }
    const auto package_global{
        PQGlobalKeyTransaction(PQMempoolHash(140'000), 250, 2'000)};
    (void)pool.FindPackageProviderTxConflict(
        {MakeTransactionRef(package_global)}, active_tip);
    const auto [registry_requests, indexed_references]{
        PQMempoolTestAccess::LastPackageProviderConflictStats(pool)};
    BOOST_CHECK_EQUAL(registry_requests, 1U);
    BOOST_CHECK_EQUAL(indexed_references, 0U);
    BOOST_CHECK_EQUAL(pool.size(), unrelated_count);
    pool.RemoveProviderTransactionsForReorg();
    BOOST_CHECK_EQUAL(pool.size(), 0U);
}

// SYSCOIN END: PQ provider mempool conflict and reservation tests.

BOOST_AUTO_TEST_CASE(MempoolRemoveTest)
{
    // Test CTxMemPool::remove functionality

    TestMemPoolEntryHelper entry;
    // Parent transaction with three children,
    // and three grand-children:
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++)
    {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000LL;
    }
    CMutableTransaction txChild[3];
    for (int i = 0; i < 3; i++)
    {
        txChild[i].vin.resize(1);
        txChild[i].vin[0].scriptSig = CScript() << OP_11;
        txChild[i].vin[0].prevout.hash = txParent.GetHash();
        txChild[i].vin[0].prevout.n = i;
        txChild[i].vout.resize(1);
        txChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txChild[i].vout[0].nValue = 11000LL;
    }
    CMutableTransaction txGrandChild[3];
    for (int i = 0; i < 3; i++)
    {
        txGrandChild[i].vin.resize(1);
        txGrandChild[i].vin[0].scriptSig = CScript() << OP_11;
        txGrandChild[i].vin[0].prevout.hash = txChild[i].GetHash();
        txGrandChild[i].vin[0].prevout.n = 0;
        txGrandChild[i].vout.resize(1);
        txGrandChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txGrandChild[i].vout[0].nValue = 11000LL;
    }


    CTxMemPool& testPool = *Assert(m_node.mempool);
    LOCK2(::cs_main, testPool.cs);

    // Nothing in pool, remove should do nothing:
    unsigned int poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);

    // Just the parent:
    testPool.addUnchecked(entry.FromTx(txParent));
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 1);

    // Parent, children, grandchildren:
    testPool.addUnchecked(entry.FromTx(txParent));
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Remove Child[0], GrandChild[0] should be removed:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txChild[0]), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 2);
    // ... make sure grandchild and child are gone:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txGrandChild[0]), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txChild[0]), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    // Remove parent, all children/grandchildren should go:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 5);
    BOOST_CHECK_EQUAL(testPool.size(), 0U);

    // Add children and grandchildren, but NOT the parent (simulate the parent being in a block)
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Now remove the parent, as might happen if a block-re-org occurs but the parent cannot be
    // put into the mempool (maybe because it is non-standard):
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 6);
    BOOST_CHECK_EQUAL(testPool.size(), 0U);
}

template <typename name>
static void CheckSort(CTxMemPool& pool, std::vector<std::string>& sortedOrder) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    BOOST_CHECK_EQUAL(pool.size(), sortedOrder.size());
    typename CTxMemPool::indexed_transaction_set::index<name>::type::iterator it = pool.mapTx.get<name>().begin();
    int count = 0;
    for (; it != pool.mapTx.get<name>().end(); ++it, ++count) {
        BOOST_CHECK_EQUAL(it->GetTx().GetHash().ToString(), sortedOrder[count]);
    }
}

BOOST_AUTO_TEST_CASE(MempoolIndexingTest)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    /* 3rd highest fee */
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1));

    /* highest fee */
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).FromTx(tx2));

    /* lowest fee */
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(entry.Fee(0LL).FromTx(tx3));

    /* 2nd highest fee */
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(15000LL).FromTx(tx4));

    /* equal fee rate to tx1, but newer */
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    entry.time = NodeSeconds{1s};
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5U);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx3.GetHash().ToString(); // 0
    sortedOrder[1] = tx5.GetHash().ToString(); // 10000
    sortedOrder[2] = tx1.GetHash().ToString(); // 10000
    sortedOrder[3] = tx4.GetHash().ToString(); // 15000
    sortedOrder[4] = tx2.GetHash().ToString(); // 20000
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee but with high fee child */
    /* tx6 -> tx7 -> tx8, tx9 -> tx10 */
    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(entry.Fee(0LL).FromTx(tx6));
    BOOST_CHECK_EQUAL(pool.size(), 6U);
    // Check that at this point, tx6 is sorted low
    sortedOrder.insert(sortedOrder.begin(), tx6.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    CTxMemPool::setEntries setAncestors;
    setAncestors.insert(pool.mapTx.find(tx6.GetHash()));
    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[1].nValue = 1 * COIN;

    auto ancestors_calculated{pool.CalculateMemPoolAncestors(entry.Fee(2000000LL).FromTx(tx7), CTxMemPool::Limits::NoLimits())};
    BOOST_REQUIRE(ancestors_calculated.has_value());
    BOOST_CHECK(*ancestors_calculated == setAncestors);

    pool.addUnchecked(entry.FromTx(tx7), setAncestors);
    BOOST_CHECK_EQUAL(pool.size(), 7U);

    // Now tx6 should be sorted higher (high fee child): tx7, tx6, tx2, ...
    sortedOrder.erase(sortedOrder.begin());
    sortedOrder.push_back(tx6.GetHash().ToString());
    sortedOrder.push_back(tx7.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee child of tx7 */
    CMutableTransaction tx8 = CMutableTransaction();
    tx8.vin.resize(1);
    tx8.vin[0].prevout = COutPoint(tx7.GetHash(), 0);
    tx8.vin[0].scriptSig = CScript() << OP_11;
    tx8.vout.resize(1);
    tx8.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx8.vout[0].nValue = 10 * COIN;
    setAncestors.insert(pool.mapTx.find(tx7.GetHash()));
    pool.addUnchecked(entry.Fee(0LL).Time(NodeSeconds{2s}).FromTx(tx8), setAncestors);

    // Now tx8 should be sorted low, but tx6/tx both high
    sortedOrder.insert(sortedOrder.begin(), tx8.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee child of tx7 */
    CMutableTransaction tx9 = CMutableTransaction();
    tx9.vin.resize(1);
    tx9.vin[0].prevout = COutPoint(tx7.GetHash(), 1);
    tx9.vin[0].scriptSig = CScript() << OP_11;
    tx9.vout.resize(1);
    tx9.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx9.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(entry.Fee(0LL).Time(NodeSeconds{3s}).FromTx(tx9), setAncestors);

    // tx9 should be sorted low
    BOOST_CHECK_EQUAL(pool.size(), 9U);
    sortedOrder.insert(sortedOrder.begin(), tx9.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    std::vector<std::string> snapshotOrder = sortedOrder;

    setAncestors.insert(pool.mapTx.find(tx8.GetHash()));
    setAncestors.insert(pool.mapTx.find(tx9.GetHash()));
    /* tx10 depends on tx8 and tx9 and has a high fee*/
    CMutableTransaction tx10 = CMutableTransaction();
    tx10.vin.resize(2);
    tx10.vin[0].prevout = COutPoint(tx8.GetHash(), 0);
    tx10.vin[0].scriptSig = CScript() << OP_11;
    tx10.vin[1].prevout = COutPoint(tx9.GetHash(), 0);
    tx10.vin[1].scriptSig = CScript() << OP_11;
    tx10.vout.resize(1);
    tx10.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx10.vout[0].nValue = 10 * COIN;

    ancestors_calculated = pool.CalculateMemPoolAncestors(entry.Fee(200000LL).Time(NodeSeconds{4s}).FromTx(tx10), CTxMemPool::Limits::NoLimits());
    BOOST_REQUIRE(ancestors_calculated);
    BOOST_CHECK(*ancestors_calculated == setAncestors);

    pool.addUnchecked(entry.FromTx(tx10), setAncestors);

    /**
     *  tx8 and tx9 should both now be sorted higher
     *  Final order after tx10 is added:
     *
     *  tx3 = 0 (1)
     *  tx5 = 10000 (1)
     *  tx1 = 10000 (1)
     *  tx4 = 15000 (1)
     *  tx2 = 20000 (1)
     *  tx9 = 200k (2 txs)
     *  tx8 = 200k (2 txs)
     *  tx10 = 200k (1 tx)
     *  tx6 = 2.2M (5 txs)
     *  tx7 = 2.2M (4 txs)
     */
    sortedOrder.erase(sortedOrder.begin(), sortedOrder.begin()+2); // take out tx9, tx8 from the beginning
    sortedOrder.insert(sortedOrder.begin()+5, tx9.GetHash().ToString());
    sortedOrder.insert(sortedOrder.begin()+6, tx8.GetHash().ToString());
    sortedOrder.insert(sortedOrder.begin()+7, tx10.GetHash().ToString()); // tx10 is just before tx6
    CheckSort<descendant_score>(pool, sortedOrder);

    // there should be 10 transactions in the mempool
    BOOST_CHECK_EQUAL(pool.size(), 10U);

    // Now try removing tx10 and verify the sort order returns to normal
    pool.removeRecursive(pool.mapTx.find(tx10.GetHash())->GetTx(), REMOVAL_REASON_DUMMY);
    CheckSort<descendant_score>(pool, snapshotOrder);

    pool.removeRecursive(pool.mapTx.find(tx9.GetHash())->GetTx(), REMOVAL_REASON_DUMMY);
    pool.removeRecursive(pool.mapTx.find(tx8.GetHash())->GetTx(), REMOVAL_REASON_DUMMY);
}

BOOST_AUTO_TEST_CASE(MempoolAncestorIndexingTest)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    /* 3rd highest fee */
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1));

    /* highest fee */
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).FromTx(tx2));
    uint64_t tx2Size = GetVirtualTransactionSize(CTransaction(tx2));

    /* lowest fee */
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(entry.Fee(0LL).FromTx(tx3));

    /* 2nd highest fee */
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(15000LL).FromTx(tx4));

    /* equal fee rate to tx1, but newer */
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5U);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx2.GetHash().ToString(); // 20000
    sortedOrder[1] = tx4.GetHash().ToString(); // 15000
    // tx1 and tx5 are both 10000
    // Ties are broken by hash, not timestamp, so determine which
    // hash comes first.
    if (tx1.GetHash() < tx5.GetHash()) {
        sortedOrder[2] = tx1.GetHash().ToString();
        sortedOrder[3] = tx5.GetHash().ToString();
    } else {
        sortedOrder[2] = tx5.GetHash().ToString();
        sortedOrder[3] = tx1.GetHash().ToString();
    }
    sortedOrder[4] = tx3.GetHash().ToString(); // 0

    CheckSort<ancestor_score>(pool, sortedOrder);

    /* low fee parent with high fee child */
    /* tx6 (0) -> tx7 (high) */
    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 20 * COIN;
    uint64_t tx6Size = GetVirtualTransactionSize(CTransaction(tx6));

    pool.addUnchecked(entry.Fee(0LL).FromTx(tx6));
    BOOST_CHECK_EQUAL(pool.size(), 6U);
    // Ties are broken by hash
    if (tx3.GetHash() < tx6.GetHash())
        sortedOrder.push_back(tx6.GetHash().ToString());
    else
        sortedOrder.insert(sortedOrder.end()-1,tx6.GetHash().ToString());

    CheckSort<ancestor_score>(pool, sortedOrder);

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vout.resize(1);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    uint64_t tx7Size = GetVirtualTransactionSize(CTransaction(tx7));

    /* set the fee to just below tx2's feerate when including ancestor */
    CAmount fee = (20000/tx2Size)*(tx7Size + tx6Size) - 1;

    pool.addUnchecked(entry.Fee(fee).FromTx(tx7));
    BOOST_CHECK_EQUAL(pool.size(), 7U);
    sortedOrder.insert(sortedOrder.begin()+1, tx7.GetHash().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);

    /* after tx6 is mined, tx7 should move up in the sort */
    std::vector<CTransactionRef> vtx;
    vtx.push_back(MakeTransactionRef(tx6));
    pool.removeForBlock(vtx, 1);

    sortedOrder.erase(sortedOrder.begin()+1);
    // Ties are broken by hash
    if (tx3.GetHash() < tx6.GetHash())
        sortedOrder.pop_back();
    else
        sortedOrder.erase(sortedOrder.end()-2);
    sortedOrder.insert(sortedOrder.begin(), tx7.GetHash().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);

    // High-fee parent, low-fee child
    // tx7 -> tx8
    CMutableTransaction tx8 = CMutableTransaction();
    tx8.vin.resize(1);
    tx8.vin[0].prevout  = COutPoint(tx7.GetHash(), 0);
    tx8.vin[0].scriptSig = CScript() << OP_11;
    tx8.vout.resize(1);
    tx8.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx8.vout[0].nValue = 10*COIN;

    // Check that we sort by min(feerate, ancestor_feerate):
    // set the fee so that the ancestor feerate is above tx1/5,
    // but the transaction's own feerate is lower
    pool.addUnchecked(entry.Fee(5000LL).FromTx(tx8));
    sortedOrder.insert(sortedOrder.end()-1, tx8.GetHash().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);
}


BOOST_AUTO_TEST_CASE(MempoolSizeLimitTest)
{
    auto& pool = static_cast<MemPoolTest&>(*Assert(m_node.mempool));
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vin.resize(1);
    tx1.vin[0].scriptSig = CScript() << OP_1;
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1));

    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vin.resize(1);
    tx2.vin[0].scriptSig = CScript() << OP_2;
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_2 << OP_EQUAL;
    tx2.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(5000LL).FromTx(tx2));

    pool.TrimToSize(pool.DynamicMemoryUsage()); // should do nothing
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx1.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx2.GetHash())));

    pool.TrimToSize(pool.DynamicMemoryUsage() * 3 / 4); // should remove the lower-feerate transaction
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx1.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx2.GetHash())));

    pool.addUnchecked(entry.FromTx(tx2));
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vin.resize(1);
    tx3.vin[0].prevout = COutPoint(tx2.GetHash(), 0);
    tx3.vin[0].scriptSig = CScript() << OP_2;
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_3 << OP_EQUAL;
    tx3.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(20000LL).FromTx(tx3));

    pool.TrimToSize(pool.DynamicMemoryUsage() * 3 / 4); // tx3 should pay for tx2 (CPFP)
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx1.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx2.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx3.GetHash())));

    pool.TrimToSize(GetVirtualTransactionSize(CTransaction(tx1))); // mempool is limited to tx1's size in memory usage, so nothing fits
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx1.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx2.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx3.GetHash())));

    CFeeRate maxFeeRateRemoved(25000, GetVirtualTransactionSize(CTransaction(tx3)) + GetVirtualTransactionSize(CTransaction(tx2)));
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(), maxFeeRateRemoved.GetFeePerK() + 1000);

    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vin.resize(2);
    tx4.vin[0].prevout.SetNull();
    tx4.vin[0].scriptSig = CScript() << OP_4;
    tx4.vin[1].prevout.SetNull();
    tx4.vin[1].scriptSig = CScript() << OP_4;
    tx4.vout.resize(2);
    tx4.vout[0].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[0].nValue = 10 * COIN;
    tx4.vout[1].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vin.resize(2);
    tx5.vin[0].prevout = COutPoint(tx4.GetHash(), 0);
    tx5.vin[0].scriptSig = CScript() << OP_4;
    tx5.vin[1].prevout.SetNull();
    tx5.vin[1].scriptSig = CScript() << OP_5;
    tx5.vout.resize(2);
    tx5.vout[0].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[0].nValue = 10 * COIN;
    tx5.vout[1].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vin.resize(2);
    tx6.vin[0].prevout = COutPoint(tx4.GetHash(), 1);
    tx6.vin[0].scriptSig = CScript() << OP_4;
    tx6.vin[1].prevout.SetNull();
    tx6.vin[1].scriptSig = CScript() << OP_6;
    tx6.vout.resize(2);
    tx6.vout[0].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[0].nValue = 10 * COIN;
    tx6.vout[1].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(2);
    tx7.vin[0].prevout = COutPoint(tx5.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_5;
    tx7.vin[1].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[1].scriptSig = CScript() << OP_6;
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[1].nValue = 10 * COIN;

    pool.addUnchecked(entry.Fee(7000LL).FromTx(tx4));
    pool.addUnchecked(entry.Fee(1000LL).FromTx(tx5));
    pool.addUnchecked(entry.Fee(1100LL).FromTx(tx6));
    pool.addUnchecked(entry.Fee(9000LL).FromTx(tx7));

    // we only require this to remove, at max, 2 txn, because it's not clear what we're really optimizing for aside from that
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1);
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx4.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx6.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx7.GetHash())));

    if (!pool.exists(GenTxid::Txid(tx5.GetHash())))
        pool.addUnchecked(entry.Fee(1000LL).FromTx(tx5));
    pool.addUnchecked(entry.Fee(9000LL).FromTx(tx7));

    pool.TrimToSize(pool.DynamicMemoryUsage() / 2); // should maximize mempool size by only removing 5/7
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx4.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx5.GetHash())));
    BOOST_CHECK(pool.exists(GenTxid::Txid(tx6.GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(tx7.GetHash())));

    pool.addUnchecked(entry.Fee(1000LL).FromTx(tx5));
    pool.addUnchecked(entry.Fee(9000LL).FromTx(tx7));

    std::vector<CTransactionRef> vtx;
    SetMockTime(42);
    SetMockTime(42 + CTxMemPool::ROLLING_FEE_HALFLIFE);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(), maxFeeRateRemoved.GetFeePerK() + 1000);
    // ... we should keep the same min fee until we get a block
    pool.removeForBlock(vtx, 1);
    SetMockTime(42 + 2*CTxMemPool::ROLLING_FEE_HALFLIFE);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(), llround((maxFeeRateRemoved.GetFeePerK() + 1000)/2.0));
    // ... then feerate should drop 1/2 each halflife

    SetMockTime(42 + 2*CTxMemPool::ROLLING_FEE_HALFLIFE + CTxMemPool::ROLLING_FEE_HALFLIFE/2);
    BOOST_CHECK_EQUAL(pool.GetMinFee(pool.DynamicMemoryUsage() * 5 / 2).GetFeePerK(), llround((maxFeeRateRemoved.GetFeePerK() + 1000)/4.0));
    // ... with a 1/2 halflife when mempool is < 1/2 its target size

    SetMockTime(42 + 2*CTxMemPool::ROLLING_FEE_HALFLIFE + CTxMemPool::ROLLING_FEE_HALFLIFE/2 + CTxMemPool::ROLLING_FEE_HALFLIFE/4);
    BOOST_CHECK_EQUAL(pool.GetMinFee(pool.DynamicMemoryUsage() * 9 / 2).GetFeePerK(), llround((maxFeeRateRemoved.GetFeePerK() + 1000)/8.0));
    // ... with a 1/4 halflife when mempool is < 1/4 its target size

    SetMockTime(42 + 7*CTxMemPool::ROLLING_FEE_HALFLIFE + CTxMemPool::ROLLING_FEE_HALFLIFE/2 + CTxMemPool::ROLLING_FEE_HALFLIFE/4);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(), 1000);
    // ... but feerate should never drop below 1000

    SetMockTime(42 + 8*CTxMemPool::ROLLING_FEE_HALFLIFE + CTxMemPool::ROLLING_FEE_HALFLIFE/2 + CTxMemPool::ROLLING_FEE_HALFLIFE/4);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(), 0);
    // ... unless it has gone all the way to 0 (after getting past 1000/2)
}

inline CTransactionRef make_tx(std::vector<CAmount>&& output_values, std::vector<CTransactionRef>&& inputs=std::vector<CTransactionRef>(), std::vector<uint32_t>&& input_indices=std::vector<uint32_t>())
{
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(output_values.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout.hash = inputs[i]->GetHash();
        tx.vin[i].prevout.n = input_indices.size() > i ? input_indices[i] : 0;
    }
    for (size_t i = 0; i < output_values.size(); ++i) {
        tx.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        tx.vout[i].nValue = output_values[i];
    }
    return MakeTransactionRef(tx);
}


BOOST_AUTO_TEST_CASE(MempoolAncestryTests)
{
    size_t ancestors, descendants;

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    /* Base transaction */
    //
    // [tx1]
    //
    CTransactionRef tx1 = make_tx(/*output_values=*/{10 * COIN});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx1));

    // Ancestors / descendants should be 1 / 1 (itself / itself)
    pool.GetTransactionAncestry(tx1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 1ULL);

    /* Child transaction */
    //
    // [tx1].0 <- [tx2]
    //
    CTransactionRef tx2 = make_tx(/*output_values=*/{495 * CENT, 5 * COIN}, /*inputs=*/{tx1});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx2));

    // Ancestors / descendants should be:
    // transaction  ancestors   descendants
    // ============ =========== ===========
    // tx1          1 (tx1)     2 (tx1,2)
    // tx2          2 (tx1,2)   2 (tx1,2)
    pool.GetTransactionAncestry(tx1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 2ULL);
    pool.GetTransactionAncestry(tx2->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 2ULL);

    /* Grand-child 1 */
    //
    // [tx1].0 <- [tx2].0 <- [tx3]
    //
    CTransactionRef tx3 = make_tx(/*output_values=*/{290 * CENT, 200 * CENT}, /*inputs=*/{tx2});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx3));

    // Ancestors / descendants should be:
    // transaction  ancestors   descendants
    // ============ =========== ===========
    // tx1          1 (tx1)     3 (tx1,2,3)
    // tx2          2 (tx1,2)   3 (tx1,2,3)
    // tx3          3 (tx1,2,3) 3 (tx1,2,3)
    pool.GetTransactionAncestry(tx1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 3ULL);
    pool.GetTransactionAncestry(tx2->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 3ULL);
    pool.GetTransactionAncestry(tx3->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 3ULL);

    /* Grand-child 2 */
    //
    // [tx1].0 <- [tx2].0 <- [tx3]
    //              |
    //              \---1 <- [tx4]
    //
    CTransactionRef tx4 = make_tx(/*output_values=*/{290 * CENT, 250 * CENT}, /*inputs=*/{tx2}, /*input_indices=*/{1});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tx4));

    // Ancestors / descendants should be:
    // transaction  ancestors   descendants
    // ============ =========== ===========
    // tx1          1 (tx1)     4 (tx1,2,3,4)
    // tx2          2 (tx1,2)   4 (tx1,2,3,4)
    // tx3          3 (tx1,2,3) 4 (tx1,2,3,4)
    // tx4          3 (tx1,2,4) 4 (tx1,2,3,4)
    pool.GetTransactionAncestry(tx1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(tx2->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(tx3->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(tx4->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);

    /* Make an alternate branch that is longer and connect it to tx3 */
    //
    // [ty1].0 <- [ty2].0 <- [ty3].0 <- [ty4].0 <- [ty5].0
    //                                              |
    // [tx1].0 <- [tx2].0 <- [tx3].0 <- [ty6] --->--/
    //              |
    //              \---1 <- [tx4]
    //
    CTransactionRef ty1, ty2, ty3, ty4, ty5;
    CTransactionRef* ty[5] = {&ty1, &ty2, &ty3, &ty4, &ty5};
    CAmount v = 5 * COIN;
    for (uint64_t i = 0; i < 5; i++) {
        CTransactionRef& tyi = *ty[i];
        tyi = make_tx(/*output_values=*/{v}, /*inputs=*/i > 0 ? std::vector<CTransactionRef>{*ty[i - 1]} : std::vector<CTransactionRef>{});
        v -= 50 * CENT;
        pool.addUnchecked(entry.Fee(10000LL).FromTx(tyi));
        pool.GetTransactionAncestry(tyi->GetHash(), ancestors, descendants);
        BOOST_CHECK_EQUAL(ancestors, i+1);
        BOOST_CHECK_EQUAL(descendants, i+1);
    }
    CTransactionRef ty6 = make_tx(/*output_values=*/{5 * COIN}, /*inputs=*/{tx3, ty5});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(ty6));

    // Ancestors / descendants should be:
    // transaction  ancestors           descendants
    // ============ =================== ===========
    // tx1          1 (tx1)             5 (tx1,2,3,4, ty6)
    // tx2          2 (tx1,2)           5 (tx1,2,3,4, ty6)
    // tx3          3 (tx1,2,3)         5 (tx1,2,3,4, ty6)
    // tx4          3 (tx1,2,4)         5 (tx1,2,3,4, ty6)
    // ty1          1 (ty1)             6 (ty1,2,3,4,5,6)
    // ty2          2 (ty1,2)           6 (ty1,2,3,4,5,6)
    // ty3          3 (ty1,2,3)         6 (ty1,2,3,4,5,6)
    // ty4          4 (y1234)           6 (ty1,2,3,4,5,6)
    // ty5          5 (y12345)          6 (ty1,2,3,4,5,6)
    // ty6          9 (tx123, ty123456) 6 (ty1,2,3,4,5,6)
    pool.GetTransactionAncestry(tx1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 5ULL);
    pool.GetTransactionAncestry(tx2->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 5ULL);
    pool.GetTransactionAncestry(tx3->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 5ULL);
    pool.GetTransactionAncestry(tx4->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 5ULL);
    pool.GetTransactionAncestry(ty1->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
    pool.GetTransactionAncestry(ty2->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
    pool.GetTransactionAncestry(ty3->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
    pool.GetTransactionAncestry(ty4->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 4ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
    pool.GetTransactionAncestry(ty5->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 5ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
    pool.GetTransactionAncestry(ty6->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 9ULL);
    BOOST_CHECK_EQUAL(descendants, 6ULL);
}

BOOST_AUTO_TEST_CASE(MempoolAncestryTestsDiamond)
{
    size_t ancestors, descendants;

    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    /* Ancestors represented more than once ("diamond") */
    //
    // [ta].0 <- [tb].0 -----<------- [td].0
    //            |                    |
    //            \---1 <- [tc].0 --<--/
    //
    CTransactionRef ta, tb, tc, td;
    ta = make_tx(/*output_values=*/{10 * COIN});
    tb = make_tx(/*output_values=*/{5 * COIN, 3 * COIN}, /*inputs=*/ {ta});
    tc = make_tx(/*output_values=*/{2 * COIN}, /*inputs=*/{tb}, /*input_indices=*/{1});
    td = make_tx(/*output_values=*/{6 * COIN}, /*inputs=*/{tb, tc}, /*input_indices=*/{0, 0});
    pool.addUnchecked(entry.Fee(10000LL).FromTx(ta));
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tb));
    pool.addUnchecked(entry.Fee(10000LL).FromTx(tc));
    pool.addUnchecked(entry.Fee(10000LL).FromTx(td));

    // Ancestors / descendants should be:
    // transaction  ancestors           descendants
    // ============ =================== ===========
    // ta           1 (ta               4 (ta,tb,tc,td)
    // tb           2 (ta,tb)           4 (ta,tb,tc,td)
    // tc           3 (ta,tb,tc)        4 (ta,tb,tc,td)
    // td           4 (ta,tb,tc,td)     4 (ta,tb,tc,td)
    pool.GetTransactionAncestry(ta->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 1ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(tb->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 2ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(tc->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 3ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
    pool.GetTransactionAncestry(td->GetHash(), ancestors, descendants);
    BOOST_CHECK_EQUAL(ancestors, 4ULL);
    BOOST_CHECK_EQUAL(descendants, 4ULL);
}

BOOST_AUTO_TEST_SUITE_END()
