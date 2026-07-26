// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <nevm/rlp.h>
#include <nevm/sha3.h>
#include <services/assetconsensus.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

CMintSyscoin g_mint;
uint256 g_tx_hash;

uint256 TxHash(const CMintSyscoin& mint)
{
    const dev::bytesConstRef preimage(
        mint.vchTxParentNodes.data() + mint.posTx,
        mint.vchTxParentNodes.size() - mint.posTx);
    std::vector<unsigned char> bytes = dev::sha3(preimage).asBytes();
    std::reverse(bytes.begin(), bytes.end());
    return uint256S(HexStr(bytes));
}

std::vector<unsigned char> MakeProof(
    const dev::bytes& value,
    uint16_t& value_pos,
    uint256& root)
{
    dev::bytes trie_value{2};
    trie_value.insert(trie_value.end(), value.begin(), value.end());

    dev::RLPStream leaf(2);
    leaf.append(dev::bytes{0x20});
    leaf.append(trie_value);
    const dev::bytes leaf_data = leaf.out();

    dev::RLPStream parents(1);
    parents.appendRaw(leaf_data);
    const dev::bytes parent_data = parents.out();
    const auto value_it = std::find_end(
        parent_data.begin(), parent_data.end(), value.begin(), value.end());
    assert(value_it != parent_data.end());
    value_pos = static_cast<uint16_t>(
        std::distance(parent_data.begin(), value_it));

    const dev::bytes root_bytes = dev::sha3(
                                      dev::bytesConstRef(leaf_data.data(), leaf_data.size()))
                                      .asBytes();
    std::copy(root_bytes.begin(), root_bytes.end(), root.begin());
    return {parent_data.begin(), parent_data.end()};
}

void InitializeSyscoinMint()
{
    static const auto testing_setup = MakeNoLogFileContext<>();

    pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(DBParams{
        .path = "syscoin_mint_fuzz_roots",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});
    pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
        .path = "syscoin_mint_fuzz_txs",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});

    const dev::bytes manager =
        Params().GetConsensus().vchSyscoinVaultManagerLegacy;
    const dev::bytes freeze_topic =
        Params().GetConsensus().vchTokenFreezeMethod;

    dev::bytes guid_topic(32, 0);
    guid_topic.back() = 1;
    dev::bytes freezer_topic(32, 0);
    freezer_topic.back() = 1;
    dev::RLPStream topics(3);
    topics.append(freeze_topic);
    topics.append(guid_topic);
    topics.append(freezer_topic);

    const std::string witness{"abc"};
    dev::bytes event_data(128, 0);
    event_data[31] = 1;
    event_data[63] = 64;
    event_data[95] = witness.size();
    std::copy(witness.begin(), witness.end(), event_data.begin() + 96);

    dev::RLPStream log(3);
    log.append(manager);
    log.appendRaw(topics.out());
    log.append(event_data);
    dev::RLPStream logs(1);
    logs.appendRaw(log.out());
    dev::RLPStream receipt(4);
    receipt.append(1U);
    receipt.append(0U);
    receipt.append(dev::bytes(256, 0));
    receipt.appendRaw(logs.out());

    const uint64_t chain_id = Params().GetConsensus().nNEVMChainID;
    const dev::RLPStream empty_list(0);
    dev::RLPStream transaction(12);
    transaction.append(chain_id);
    transaction.append(0U);
    transaction.append(0U);
    transaction.append(0U);
    transaction.append(0U);
    transaction.append(manager);
    transaction.append(0U);
    transaction.append(dev::bytes{});
    transaction.appendRaw(empty_list.out());
    transaction.append(0U);
    transaction.append(0U);
    transaction.append(0U);

    g_mint.nBlockHash = uint256S("599");
    g_mint.vchTxParentNodes = MakeProof(
        transaction.out(), g_mint.posTx, g_mint.nTxRoot);
    g_mint.vchReceiptParentNodes = MakeProof(
        receipt.out(), g_mint.posReceipt, g_mint.nReceiptRoot);
    g_tx_hash = TxHash(g_mint);
    g_mint.nTxHash = g_tx_hash;
    pnevmtxrootsdb->FlushDataToCache(
        {{g_mint.nBlockHash, {g_mint.nTxRoot, g_mint.nReceiptRoot}}});
}

CMintSyscoin MakeMint()
{
    CMintSyscoin mint;
    mint.voutAssets = g_mint.voutAssets;
    mint.posTx = g_mint.posTx;
    mint.vchTxParentNodes = g_mint.vchTxParentNodes;
    mint.nTxRoot = g_mint.nTxRoot;
    mint.vchTxPath = g_mint.vchTxPath;
    mint.posReceipt = g_mint.posReceipt;
    mint.vchReceiptParentNodes = g_mint.vchReceiptParentNodes;
    mint.nReceiptRoot = g_mint.nReceiptRoot;
    mint.nTxHash = g_mint.nTxHash;
    mint.nBlockHash = g_mint.nBlockHash;
    return mint;
}

} // namespace

FUZZ_TARGET(syscoin_mint, .init = InitializeSyscoinMint)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    CMintSyscoin mint = MakeMint();

    if (provider.remaining_bytes() > 0) {
        const uint8_t mode =
            provider.ConsumeIntegralInRange<uint8_t>(0, 4);
        const bool change_position = provider.ConsumeBool();
        const uint16_t position = provider.ConsumeIntegral<uint16_t>();
        const std::vector<uint8_t> mutation =
            provider.ConsumeRemainingBytes<uint8_t>();

        switch (mode) {
        case 0:
            mint.vchTxParentNodes = mutation;
            break;
        case 1:
            mint.vchTxParentNodes.insert(
                mint.vchTxParentNodes.end(),
                mutation.begin(),
                mutation.end());
            break;
        case 2: {
            const size_t insertion_position = mint.vchTxParentNodes.empty() ? 0 : position % (mint.vchTxParentNodes.size() + 1);
            mint.vchTxParentNodes.insert(
                mint.vchTxParentNodes.begin() + insertion_position,
                mutation.begin(),
                mutation.end());
            break;
        }
        case 3:
            mint.vchTxPath = mutation;
            break;
        case 4:
            mint.vchReceiptParentNodes = mutation;
            mint.posReceipt = position;
            break;
        }
        if (change_position) {
            mint.posTx = position;
        }
    }

    if (mint.posTx >= mint.vchTxParentNodes.size()) {
        return;
    }
    mint.nTxHash = TxHash(mint);

    TxValidationState state;
    NEVMMintTxSet mint_txs;
    uint64_t asset_guid{0};
    CAmount amount{0};
    std::string address;
    try {
        if (CheckSyscoinMintInternal(
                mint,
                state,
                true,
                true,
                /*nHeight=*/0,
                mint_txs,
                asset_guid,
                amount,
                address)) {
            assert(mint.nTxHash == g_tx_hash);
        }
    } catch (...) {
        // The public validation entry point converts parser exceptions to
        // consensus rejection.
    }
}
