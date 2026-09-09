// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_UTIL_NEVM_MINT_H
#define SYSCOIN_TEST_UTIL_NEVM_MINT_H

#include <addresstype.h>
#include <consensus/params.h>
#include <key_io.h>
#include <nevm/nevm.h>
#include <nevm/sha3.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

struct ValidNEVMMintFixture {
    CMintSyscoin mint;
    CMutableTransaction tx;
};

/** A complete canonical mint proof; callers supply transaction funding. */
inline ValidNEVMMintFixture MakeValidNEVMMintFixture(
    const Consensus::Params& params, uint32_t height,
    const CTxDestination& destination, const uint256& source_block_hash)
{
    const dev::bytes manager{height < static_cast<uint32_t>(params.nBridgeV2StartBlock)
        ? params.vchSyscoinVaultManagerLegacy : params.vchSyscoinVaultManager};
    const std::string address{EncodeDestination(destination)};
    dev::bytes guid(32, 0), freezer(32, 0);
    guid.back() = 1;
    freezer.back() = 1;
    dev::RLPStream topics(3);
    topics.append(params.vchTokenFreezeMethod);
    topics.append(guid);
    topics.append(freezer);

    dev::bytes event_data(96 + ((address.size() + 31) & ~size_t{31}), 0);
    event_data[31] = 1;
    event_data[63] = 64;
    event_data[95] = address.size();
    std::copy(address.begin(), address.end(), event_data.begin() + 96);
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

    dev::RLPStream eth_tx(9);
    eth_tx.append(0U);
    eth_tx.append(0U);
    eth_tx.append(0U);
    eth_tx.append(manager);
    eth_tx.append(0U);
    eth_tx.append(dev::bytes{});
    eth_tx.append(static_cast<uint64_t>(params.nNEVMChainID) * 2 + 35);
    eth_tx.append(0U);
    eth_tx.append(0U);
    const dev::bytes tx_value{eth_tx.out()};

    const auto make_proof = [](const dev::bytes& value,
                               uint16_t& value_pos, uint256& root) {
        dev::RLPStream leaf(2);
        leaf.append(dev::bytes{0x20});
        leaf.append(value);
        const dev::bytes leaf_data{leaf.out()};
        dev::RLPStream parents(1);
        parents.appendRaw(leaf_data);
        const dev::bytes parent_data{parents.out()};
        const auto value_it{std::search(parent_data.begin(), parent_data.end(),
                                       value.begin(), value.end())};
        assert(value_it != parent_data.end());
        value_pos = static_cast<uint16_t>(std::distance(parent_data.begin(), value_it));
        const auto root_bytes{dev::sha3(
            dev::bytesConstRef(leaf_data.data(), leaf_data.size())).asBytes()};
        std::copy(root_bytes.begin(), root_bytes.end(), root.begin());
        return std::vector<unsigned char>{parent_data.begin(), parent_data.end()};
    };

    ValidNEVMMintFixture fixture;
    fixture.mint.nBlockHash = source_block_hash;
    fixture.mint.vchReceiptParentNodes = make_proof(
        receipt.out(), fixture.mint.posReceipt, fixture.mint.nReceiptRoot);
    fixture.mint.vchTxParentNodes = make_proof(
        tx_value, fixture.mint.posTx, fixture.mint.nTxRoot);
    const auto tx_hash{dev::sha3(dev::bytesConstRef(tx_value.data(), tx_value.size())).asBytes()};
    std::copy(tx_hash.begin(), tx_hash.end(), fixture.mint.nTxHash.begin());
    fixture.mint.voutAssets.emplace_back(1, std::vector<CAssetOutValue>{{0, 1}});
    std::vector<unsigned char> payload;
    fixture.mint.SerializeData(payload);
    fixture.tx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_MINT;
    fixture.tx.vout.emplace_back(10000, GetScriptForDestination(destination));
    fixture.tx.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
    fixture.tx.LoadAssets();
    return fixture;
}

#endif // SYSCOIN_TEST_UTIL_NEVM_MINT_H
