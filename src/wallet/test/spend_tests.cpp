// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/fees.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <algorithm> // SYSCOIN: inspect asset-bearing inventory outputs.

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        constexpr int RANDOM_CHANGE_POSITION = -1;
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, 50 BTC each, to the wallet (total balance 200 BTC)
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 BTC total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 BTC, and the tx target is 299 BTC.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 BTC from a wallet that only has 200 BTC. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 BTC payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 BTC.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 BTC)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    util::Result<CreatedTransactionResult> res_tx = CreateTransaction(*wallet, recipients, /*change_pos*/-1, coin_control);
    BOOST_CHECK(!res_tx.has_value());

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    res_tx = CreateTransaction(*wallet, recipients, /*change_pos*/-1, coin_control);
    BOOST_CHECK(!res_tx.has_value());
}

// SYSCOIN BEGIN: Ordinary wallet spending must preserve asset-bearing UTXOs.
BOOST_AUTO_TEST_CASE(asset_selected_inputs_require_asset_version)
{
    LOCK(m_wallet.cs_wallet);
    const CAssetCoinInfo asset{42, 7};
    const CTxOut asset_output{COIN, CScript{} << OP_TRUE, asset};
    CMutableTransaction tx;
    tx.vout.push_back(asset_output);
    // Exercise stored UTXO metadata directly; asset consensus validation is
    // independent of this coin-control policy test.
    const auto* wallet_tx{m_wallet.AddToWallet(
        MakeTransactionRef(tx), TxStateInactive{})};
    BOOST_REQUIRE(wallet_tx != nullptr);

    FastRandomContext rng{/*fDeterministic=*/true};
    const CoinSelectionParams selection_params{rng};
    for (const bool external : {false, true}) {
        const COutPoint outpoint{
            external ? uint256S("a55e7") : wallet_tx->GetHash(), 0};
        CCoinControl coin_control;
        coin_control.SetInputWeight(outpoint, 272);
        if (external) {
            coin_control.SelectExternal(outpoint, asset_output);
        } else {
            coin_control.Select(outpoint);
        }

        const auto rejected{FetchSelectedInputs(
            m_wallet, coin_control, selection_params)};
        BOOST_REQUIRE(!rejected);
        BOOST_CHECK_EQUAL(util::ErrorString(rejected).original,
                          "Asset inputs require an asset transaction");

        coin_control.m_version = SYSCOIN_TX_VERSION_ALLOCATION_SEND;
        const auto accepted{FetchSelectedInputs(
            m_wallet, coin_control, selection_params)};
        BOOST_REQUIRE(accepted);
        BOOST_REQUIRE_EQUAL(accepted->coins.size(), 1U);
        const auto& selected{**accepted->coins.begin()};
        BOOST_CHECK(selected.outpoint == outpoint);
        BOOST_CHECK(selected.txout.assetInfo == asset);
        BOOST_CHECK_EQUAL(selected.txout.nValue, COIN);
    }

    // Explicit external SYS inputs remain available to ordinary transactions.
    const COutPoint plain_outpoint{uint256S("a55e8"), 0};
    CCoinControl ordinary_control;
    ordinary_control.SetInputWeight(plain_outpoint, 272);
    ordinary_control.SelectExternal(
        plain_outpoint, CTxOut{COIN, CScript{} << OP_TRUE});
    const auto ordinary{FetchSelectedInputs(
        m_wallet, ordinary_control, selection_params)};
    BOOST_REQUIRE(ordinary);
    BOOST_REQUIRE_EQUAL(ordinary->coins.size(), 1U);
    BOOST_CHECK((*ordinary->coins.begin())->txout.assetInfo.IsNull());
}

BOOST_AUTO_TEST_CASE(asset_inventory_excluded_from_automatic_selection)
{
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();
    const auto destination{m_wallet.GetNewDestination(OutputType::BECH32, "")};
    BOOST_REQUIRE(destination);
    const auto script{GetScriptForDestination(*destination)};
    const CAssetCoinInfo asset{42, 7};
    CMutableTransaction tx;
    tx.vout.emplace_back(COIN, script);
    tx.vout.emplace_back(2 * COIN, script, asset);
    const uint256 block_hash{m_node.chainman->GetConsensus().hashGenesisBlock};
    m_wallet.SetLastBlockProcessed(0, block_hash);
    BOOST_REQUIRE(m_wallet.AddToWallet(
        MakeTransactionRef(tx), TxStateConfirmed{block_hash, 0, 0}));

    const auto spendable{AvailableCoins(m_wallet).All()};
    BOOST_REQUIRE_EQUAL(spendable.size(), 1U);
    BOOST_CHECK(spendable[0].outpoint == COutPoint(tx.GetHash(), 0));
    BOOST_CHECK_EQUAL(spendable[0].txout.nValue, COIN);

    const auto inventory{AvailableCoinsListUnspent(m_wallet).All()};
    BOOST_REQUIRE_EQUAL(inventory.size(), 2U);
    const auto asset_coin{std::find_if(inventory.begin(), inventory.end(),
        [&](const COutput& output) {
            return output.outpoint == COutPoint(tx.GetHash(), 1);
        })};
    BOOST_REQUIRE(asset_coin != inventory.end());
    BOOST_CHECK(asset_coin->txout.assetInfo == asset);
    BOOST_CHECK_EQUAL(asset_coin->txout.nValue, 2 * COIN);
}
// SYSCOIN END: Ordinary wallet spending must preserve asset-bearing UTXOs.

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
