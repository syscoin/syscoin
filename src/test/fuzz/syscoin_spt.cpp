// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <nevm/rlp.h>
#include <nevm/sha3.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <services/assetconsensus.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

CMintSyscoin g_valid_legacy_mint;
CMintSyscoin g_valid_v2_mint;
CScript g_mint_output_script;

enum class ValidMintFixture {
    NONE,
    LEGACY,
    V2,
};

enum class ValidAllocationFixture {
    NONE,
    BURN_TO_SYSCOIN,
    BURN_TO_NEVM,
};

template <typename Payload>
void CheckPayloadRoundTrip(const std::vector<unsigned char>& data)
{
    Payload decoded;
    if (decoded.UnserializeFromData(data) < 0) {
        return;
    }
    for (const auto& asset : decoded.voutAssets) {
        for (const auto& output : asset.values) {
            if (!MoneyRange(output.nValue)) {
                return;
            }
        }
    }

    std::vector<unsigned char> canonical;
    decoded.SerializeData(canonical);

    Payload reparsed;
    assert(reparsed.UnserializeFromData(canonical) == 0);

    std::vector<unsigned char> canonical_again;
    reparsed.SerializeData(canonical_again);
    assert(canonical == canonical_again);
}

CAssetAllocation ConsumeAllocation(FuzzedDataProvider& provider, const size_t output_count)
{
    CAssetAllocation allocation;
    const size_t asset_count = provider.ConsumeIntegralInRange<size_t>(0, 4);
    allocation.voutAssets.reserve(asset_count);
    for (size_t asset_index = 0; asset_index < asset_count; ++asset_index) {
        CAssetOut asset;
        asset.key = provider.ConsumeBool()
            ? Params().GetConsensus().nSYSXAsset
            : provider.ConsumeIntegral<uint64_t>();
        const size_t value_count = provider.ConsumeIntegralInRange<size_t>(0, 4);
        asset.values.reserve(value_count);
        for (size_t value_index = 0; value_index < value_count; ++value_index) {
            CAssetOutValue value;
            value.n = provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(output_count + 2));
            value.nValue = provider.ConsumeBool()
                ? ConsumeMoney(provider)
                : provider.ConsumeIntegral<int64_t>();
            asset.values.push_back(value);
        }
        allocation.voutAssets.push_back(std::move(asset));
    }
    return allocation;
}

uint16_t ConsumeProofPosition(FuzzedDataProvider& provider, const size_t proof_size)
{
    if (proof_size > 0 && provider.ConsumeBool()) {
        return provider.ConsumeIntegralInRange<uint16_t>(
            0, static_cast<uint16_t>(std::min<size_t>(
                   proof_size - 1, std::numeric_limits<uint16_t>::max())));
    }
    return provider.ConsumeIntegral<uint16_t>();
}

std::vector<unsigned char> MakeMintProof(
    const dev::bytes& value,
    uint16_t& value_position,
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
    const auto value_it = std::search(
        parent_data.begin(), parent_data.end(), value.begin(), value.end());
    assert(value_it != parent_data.end());
    value_position = static_cast<uint16_t>(
        std::distance(parent_data.begin(), value_it));

    const dev::bytes root_bytes = dev::sha3(
        dev::bytesConstRef(leaf_data.data(), leaf_data.size())).asBytes();
    std::copy(root_bytes.begin(), root_bytes.end(), root.begin());
    return {parent_data.begin(), parent_data.end()};
}

CMintSyscoin MakeValidMint(const CMintSyscoin& source)
{
    CMintSyscoin mint;
    mint.voutAssets = source.voutAssets;
    mint.posTx = source.posTx;
    mint.vchTxParentNodes = source.vchTxParentNodes;
    mint.nTxRoot = source.nTxRoot;
    mint.vchTxPath = source.vchTxPath;
    mint.posReceipt = source.posReceipt;
    mint.vchReceiptParentNodes = source.vchReceiptParentNodes;
    mint.nReceiptRoot = source.nReceiptRoot;
    mint.nTxHash = source.nTxHash;
    mint.nBlockHash = source.nBlockHash;
    return mint;
}

CMintSyscoin ConsumeMint(
    FuzzedDataProvider& provider,
    const size_t output_count,
    ValidMintFixture& valid_fixture)
{
    const bool use_v2_fixture = provider.ConsumeBool();
    CMintSyscoin mint = MakeValidMint(
        use_v2_fixture ? g_valid_v2_mint : g_valid_legacy_mint);
    if (!provider.ConsumeBool()) {
        valid_fixture = use_v2_fixture ? ValidMintFixture::V2
                                       : ValidMintFixture::LEGACY;
        return mint;
    }

    const uint8_t mode = provider.ConsumeIntegralInRange<uint8_t>(0, 11);
    const std::vector<unsigned char> mutation =
        ConsumeRandomLengthByteVector(provider, /*max_length=*/128);
    switch (mode) {
    case 0:
        mint.vchTxParentNodes = mutation;
        break;
    case 1:
        mint.vchTxParentNodes.insert(
            mint.vchTxParentNodes.end(), mutation.begin(), mutation.end());
        break;
    case 2:
        mint.vchReceiptParentNodes = mutation;
        break;
    case 3:
        mint.vchReceiptParentNodes.insert(
            mint.vchReceiptParentNodes.end(), mutation.begin(), mutation.end());
        break;
    case 4:
        mint.vchTxPath = mutation;
        break;
    case 5:
        mint.posTx = ConsumeProofPosition(provider, mint.vchTxParentNodes.size());
        break;
    case 6:
        mint.posReceipt =
            ConsumeProofPosition(provider, mint.vchReceiptParentNodes.size());
        break;
    case 7:
        mint.nTxHash = ConsumeUInt256(provider);
        break;
    case 8:
        mint.nTxRoot = ConsumeUInt256(provider);
        break;
    case 9:
        mint.nReceiptRoot = ConsumeUInt256(provider);
        break;
    case 10:
        mint.nBlockHash = ConsumeUInt256(provider);
        break;
    case 11:
        mint.voutAssets = ConsumeAllocation(provider, output_count).voutAssets;
        break;
    }
    return mint;
}

std::vector<unsigned char> ConsumeStructuredPayload(
    FuzzedDataProvider& provider,
    const int32_t version,
    const size_t output_count,
    const std::optional<CAmount>& burn_to_syscoin_amount,
    ValidMintFixture& valid_mint_fixture,
    ValidAllocationFixture& valid_allocation_fixture)
{
    std::vector<unsigned char> data;

    if (version == SYSCOIN_TX_VERSION_ALLOCATION_MINT) {
        CMintSyscoin mint =
            ConsumeMint(provider, output_count, valid_mint_fixture);
        mint.SerializeData(data);
        return data;
    }

    CAssetAllocation allocation;
    if (version == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN &&
        burn_to_syscoin_amount.has_value() && provider.ConsumeBool()) {
        allocation.voutAssets.emplace_back(
            Params().GetConsensus().nSYSXAsset,
            std::vector<CAssetOutValue>{{
                static_cast<uint32_t>(output_count),
                static_cast<uint64_t>(*burn_to_syscoin_amount)}});
        valid_allocation_fixture =
            ValidAllocationFixture::BURN_TO_SYSCOIN;
    } else if (
        version == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM &&
        provider.ConsumeBool()) {
        allocation.voutAssets.emplace_back(
            /*key=*/1,
            std::vector<CAssetOutValue>{{
                static_cast<uint32_t>(output_count),
                static_cast<uint64_t>(
                    provider.ConsumeIntegralInRange<CAmount>(1, MAX_MONEY))}});
        valid_allocation_fixture = ValidAllocationFixture::BURN_TO_NEVM;
    } else {
        allocation = ConsumeAllocation(provider, output_count);
    }
    if (version == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM) {
        CBurnSyscoin burn;
        burn.voutAssets = std::move(allocation.voutAssets);
        burn.vchNEVMAddress =
            valid_allocation_fixture == ValidAllocationFixture::BURN_TO_NEVM
                ? std::vector<unsigned char>(20, 1)
                : ConsumeRandomLengthByteVector(provider, /*max_length=*/32);
        burn.SerializeData(data);
    } else {
        allocation.SerializeData(data);
    }
    return data;
}

CMintSyscoin BuildValidMintFixture(
    const Consensus::Params& consensus,
    const dev::bytes& manager,
    const std::string& witness,
    const uint256& block_hash)
{
    dev::bytes guid_topic(32, 0);
    guid_topic.back() = 1;
    dev::bytes freezer_topic(32, 0);
    freezer_topic.back() = 1;
    dev::RLPStream topics(3);
    topics.append(consensus.vchTokenFreezeMethod);
    topics.append(guid_topic);
    topics.append(freezer_topic);

    const size_t padded_witness_length =
        (witness.size() + 31) & ~size_t{31};
    dev::bytes event_data(96 + padded_witness_length, 0);
    event_data[31] = 1;
    event_data[63] = 64;
    event_data[95] = static_cast<unsigned char>(witness.size());
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

    const dev::RLPStream empty_list(0);
    dev::RLPStream transaction(12);
    transaction.append(consensus.nNEVMChainID);
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

    const dev::bytes transaction_data = transaction.out();
    const dev::bytes receipt_data = receipt.out();
    CMintSyscoin mint;
    mint.voutAssets.emplace_back(
        /*key=*/1, std::vector<CAssetOutValue>{{/*n=*/0, /*nAmountIn=*/1}});
    mint.nBlockHash = block_hash;
    mint.vchTxParentNodes =
        MakeMintProof(transaction_data, mint.posTx, mint.nTxRoot);
    mint.vchReceiptParentNodes =
        MakeMintProof(receipt_data, mint.posReceipt, mint.nReceiptRoot);

    const dev::h256 tx_hash = dev::sha3(
        dev::bytesConstRef(transaction_data.data(), transaction_data.size()));
    std::vector<unsigned char> tx_hash_bytes = tx_hash.asBytes();
    std::reverse(tx_hash_bytes.begin(), tx_hash_bytes.end());
    mint.nTxHash = uint256S(HexStr(tx_hash_bytes));
    return mint;
}

void InitializeSPT()
{
    static const auto testing_setup = MakeNoLogFileContext<>();

    pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(DBParams{
        .path = "syscoin_spt_fuzz_roots",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});
    pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
        .path = "syscoin_spt_fuzz_txs",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});

    const Consensus::Params& consensus = Params().GetConsensus();
    const PKHash witness_destination{
        uint160(ParseHex("1111111111111111111111111111111111111111"))};
    g_mint_output_script = GetScriptForDestination(witness_destination);
    const std::string witness = EncodeDestination(witness_destination);

    g_valid_legacy_mint = BuildValidMintFixture(
        consensus,
        consensus.vchSyscoinVaultManagerLegacy,
        witness,
        uint256S("599"));
    g_valid_v2_mint = BuildValidMintFixture(
        consensus,
        consensus.vchSyscoinVaultManager,
        witness,
        uint256S("600"));
}

CAssetsMap ConsumeAssetInputs(
    FuzzedDataProvider& provider,
    const CTransaction& tx,
    const CAssetsMap& assets_out)
{
    CAssetsMap assets_in;
    if (provider.ConsumeBool()) {
        if (IsSyscoinMintTx(tx.nVersion)) {
            return assets_in;
        }

        assets_in = assets_out;
        if (tx.nVersion == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION) {
            const uint64_t asset = Params().GetConsensus().nSYSXAsset;
            const auto output = assets_out.find(asset);
            const int data_output = GetSyscoinDataOutput(tx);
            if (output != assets_out.end() && data_output >= 0) {
                const CAmount burn = tx.vout[data_output].nValue;
                if (burn > 0 && output->second >= burn) {
                    const CAmount input = output->second - burn;
                    if (input == 0) {
                        assets_in.erase(asset);
                    } else {
                        assets_in[asset] = input;
                    }
                }
            }
        }
        return assets_in;
    }

    const size_t asset_count = provider.ConsumeIntegralInRange<size_t>(0, 4);
    for (size_t i = 0; i < asset_count; ++i) {
        const uint64_t asset = provider.ConsumeBool()
            ? Params().GetConsensus().nSYSXAsset
            : provider.ConsumeIntegral<uint64_t>();
        assets_in[asset] = provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY);
    }
    return assets_in;
}

bool CheckConsensusAtHeight(
    const CTransaction& tx,
    const uint32_t height,
    const CAssetsMap& initial_assets_in,
    const CAssetsMap& initial_assets_out)
{
    TxValidationState state;
    NEVMMintTxSet mint_txs;
    CAssetsMap assets_in{initial_assets_in};
    CAssetsMap assets_out{initial_assets_out};
    return CheckSyscoinInputs(
        Params().GetConsensus(),
        tx,
        tx.GetHash(),
        state,
        height,
        /*fJustCheck=*/true,
        mint_txs,
        assets_in,
        assets_out);
}

} // namespace

FUZZ_TARGET(syscoin_spt_payload)
{
    const std::vector<unsigned char> data(buffer.begin(), buffer.end());
    CheckPayloadRoundTrip<CAssetAllocation>(data);
    CheckPayloadRoundTrip<CBurnSyscoin>(data);
    CheckPayloadRoundTrip<CMintSyscoin>(data);
}

FUZZ_TARGET(syscoin_spt_consensus, .init = InitializeSPT)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    static constexpr std::array<int32_t, 5> SPT_VERSIONS{
        SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN,
        SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION,
        SYSCOIN_TX_VERSION_ALLOCATION_MINT,
        SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM,
        SYSCOIN_TX_VERSION_ALLOCATION_SEND,
    };

    CMutableTransaction mutable_tx;
    mutable_tx.nVersion = provider.PickValueInArray(SPT_VERSIONS);
    mutable_tx.nLockTime = provider.ConsumeIntegral<uint32_t>();

    const size_t input_count = provider.ConsumeIntegralInRange<size_t>(0, 100);
    mutable_tx.vin.resize(input_count);
    const size_t output_count = provider.ConsumeIntegralInRange<size_t>(1, 10);
    mutable_tx.vout.reserve(output_count + 1);
    for (size_t output_index = 0; output_index < output_count; ++output_index) {
        const bool use_mint_destination =
            IsSyscoinMintTx(mutable_tx.nVersion) && output_index == 0;
        CScript output_script =
            use_mint_destination
                ? g_mint_output_script
                : provider.ConsumeBool() ? CScript() << OP_TRUE
                                         : ConsumeScript(provider);
        if (output_script.IsUnspendable()) {
            output_script = CScript() << OP_TRUE;
        }
        mutable_tx.vout.emplace_back(
            ConsumeMoney(provider), std::move(output_script));
    }

    std::vector<unsigned char> data;
    ValidMintFixture valid_mint_fixture{ValidMintFixture::NONE};
    ValidAllocationFixture valid_allocation_fixture{
        ValidAllocationFixture::NONE};
    std::optional<CAmount> burn_to_syscoin_amount;
    if (provider.ConsumeBool()) {
        data = provider.ConsumeRemainingBytes<unsigned char>();
    } else {
        if (mutable_tx.nVersion ==
            SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN) {
            burn_to_syscoin_amount =
                provider.ConsumeIntegralInRange<CAmount>(1, MAX_MONEY);
            mutable_tx.vout[0].nValue = *burn_to_syscoin_amount;
        }
        data = ConsumeStructuredPayload(
            provider,
            mutable_tx.nVersion,
            output_count,
            burn_to_syscoin_amount,
            valid_mint_fixture,
            valid_allocation_fixture);
    }

    CScript data_script = CScript() << OP_RETURN << data;
    if (provider.ConsumeBool() && provider.ConsumeBool()) {
        data_script.push_back(provider.ConsumeIntegral<uint8_t>());
        valid_mint_fixture = ValidMintFixture::NONE;
        valid_allocation_fixture = ValidAllocationFixture::NONE;
    }
    mutable_tx.vout.emplace_back(ConsumeMoney(provider), data_script);

    bool assets_loaded{false};
    try {
        mutable_tx.LoadAssets();
        assets_loaded = true;
    } catch (const std::exception&) {
    }

    const CTransaction tx{mutable_tx};
    std::optional<uint256> seeded_mint_root;
    if (assets_loaded && IsSyscoinMintTx(tx.nVersion)) {
        const CMintSyscoin mint{tx};
        if (!mint.IsNull()) {
            pnevmtxrootsdb->FlushDataToCache(
                {{mint.nBlockHash, {mint.nTxRoot, mint.nReceiptRoot}}});
            seeded_mint_root = mint.nBlockHash;
        }
    }

    CAssetsMap assets_out;
    std::string asset_error;
    if (assets_loaded && !tx.GetAssetValueOut(assets_out, asset_error)) {
        assets_out.clear();
    }
    FuzzedDataProvider input_provider(buffer.data(), buffer.size());
    const CAssetsMap assets_in =
        valid_mint_fixture == ValidMintFixture::NONE &&
            valid_allocation_fixture == ValidAllocationFixture::NONE
            ? ConsumeAssetInputs(input_provider, tx, assets_out)
            : CAssetsMap{};
    const CAssetsMap fixture_assets_in =
        valid_allocation_fixture == ValidAllocationFixture::NONE
            ? assets_in
            : assets_out;

    const Consensus::Params& consensus = Params().GetConsensus();
    const uint32_t nexus_height =
        static_cast<uint32_t>(std::max(consensus.nNexusStartBlock, 0));
    const uint32_t canonical_height =
        static_cast<uint32_t>(std::max(consensus.nCLReceiptStartBlock, 0));
    const uint32_t bridge_v2_height =
        static_cast<uint32_t>(std::max(consensus.nBridgeV2StartBlock, 0));
    const uint32_t pre_canonical_height =
        canonical_height > nexus_height ? canonical_height - 1 : nexus_height;
    const std::optional<uint32_t> legacy_height =
        bridge_v2_height > nexus_height
            ? std::optional<uint32_t>{std::min(
                  pre_canonical_height, bridge_v2_height - 1)}
            : std::nullopt;
    const uint32_t canonical_v2_height =
        std::max({nexus_height, canonical_height, bridge_v2_height});

    const bool valid_at_nexus =
        CheckConsensusAtHeight(tx, nexus_height, fixture_assets_in, assets_out);
    const bool valid_at_legacy_height =
        legacy_height.has_value() &&
        CheckConsensusAtHeight(
            tx, *legacy_height, fixture_assets_in, assets_out);
    const bool valid_at_canonical_v2 = CheckConsensusAtHeight(
        tx, canonical_v2_height, fixture_assets_in, assets_out);
    if (valid_mint_fixture == ValidMintFixture::LEGACY) {
        if (legacy_height.has_value()) {
            assert(valid_at_nexus);
            assert(valid_at_legacy_height);
        }
    } else if (valid_mint_fixture == ValidMintFixture::V2) {
        assert(valid_at_canonical_v2);
    }
    if (valid_allocation_fixture ==
        ValidAllocationFixture::BURN_TO_SYSCOIN) {
        assert(valid_at_nexus);
        assert(valid_at_canonical_v2);
    } else if (
        valid_allocation_fixture == ValidAllocationFixture::BURN_TO_NEVM) {
        assert(valid_at_nexus);
        assert(
            valid_at_canonical_v2 ==
            (input_count < 100 && output_count < 9));
    }

    if (seeded_mint_root.has_value()) {
        assert(pnevmtxrootsdb->FlushErase({*seeded_mint_root}));
        NEVMTxRoot removed_root;
        assert(!pnevmtxrootsdb->ReadTxRoots(*seeded_mint_root, removed_root));
    }
}
