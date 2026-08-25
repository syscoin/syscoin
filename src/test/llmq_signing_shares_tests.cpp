// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_signing_shares.h>

#include <protocol.h>
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_AUTO_TEST_SUITE(llmq_signing_shares_tests)

BOOST_AUTO_TEST_CASE(inventory_size_is_bounded_before_allocation)
{
    {
        CDataStream stream{ParseHex("00fd90010100"), SER_NETWORK, PROTOCOL_VERSION};
        llmq::CSigSharesInv inventory;
        BOOST_REQUIRE_NO_THROW(stream >> inventory);
        BOOST_CHECK(stream.empty());
        BOOST_CHECK_EQUAL(inventory.inv.size(), Consensus::MAX_LLMQ_SIZE);
        BOOST_CHECK_EQUAL(inventory.CountSet(), 0U);
    }

    for (const auto& wire : {"00fd91010100", "00fe000000020100"}) {
        CDataStream stream{ParseHex(wire), SER_NETWORK, PROTOCOL_VERSION};
        llmq::CSigSharesInv inventory;
        BOOST_CHECK_THROW(stream >> inventory, std::ios_base::failure);
        BOOST_CHECK(inventory.inv.empty());
        BOOST_CHECK_EQUAL(stream.size(), 2U);
    }

    llmq::CSigSharesInv dense;
    dense.sessionId = 7;
    dense.inv.assign(Consensus::MAX_LLMQ_SIZE, true);
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << dense;
    llmq::CSigSharesInv decoded;
    BOOST_REQUIRE_NO_THROW(stream >> decoded);
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(decoded.sessionId, dense.sessionId);
    BOOST_CHECK(decoded.inv == dense.inv);
}

BOOST_AUTO_TEST_CASE(inventory_vector_count_is_bounded_before_elements)
{
    const std::vector<uint8_t> element{ParseHex("00fd90010100")};

    std::vector<uint8_t> accepted_wire{0xc8};
    for (size_t i = 0; i < 200; ++i) {
        accepted_wire.insert(accepted_wire.end(), element.begin(), element.end());
    }
    CDataStream accepted_stream{accepted_wire, SER_NETWORK, PROTOCOL_VERSION};
    std::vector<llmq::CSigSharesInv> accepted;
    BOOST_REQUIRE(UnserializeVectorWithMaxSize(accepted_stream, accepted, 200));
    BOOST_CHECK(accepted_stream.empty());
    BOOST_CHECK_EQUAL(accepted.size(), 200U);

    std::vector<uint8_t> rejected_wire{0xc9};
    rejected_wire.insert(rejected_wire.end(), element.begin(), element.end());
    CDataStream rejected_stream{rejected_wire, SER_NETWORK, PROTOCOL_VERSION};
    std::vector<llmq::CSigSharesInv> rejected;
    BOOST_CHECK(!UnserializeVectorWithMaxSize(rejected_stream, rejected, 200));
    BOOST_CHECK(rejected.empty());
    BOOST_CHECK_EQUAL(rejected_stream.size(), element.size());
}

BOOST_AUTO_TEST_CASE(batched_share_count_is_bounded_before_allocation)
{
    CDataStream stream{ParseHex("00fd91010000ff"), SER_NETWORK, PROTOCOL_VERSION};
    llmq::CBatchedSigShares batch;
    BOOST_CHECK_THROW(stream >> batch, std::ios_base::failure);
    BOOST_CHECK(batch.sigShares.empty());
    BOOST_CHECK_EQUAL(stream.size(), 3U);
}

BOOST_AUTO_TEST_CASE(batched_share_aggregate_is_bounded_before_inner_allocation)
{
    using BatchedSigShares = std::vector<llmq::CBatchedSigShares>;

    BatchedSigShares accepted(2);
    accepted[0].sessionId = 1;
    accepted[0].sigShares.resize(200);
    accepted[1].sessionId = 2;
    accepted[1].sigShares.resize(Consensus::MAX_LLMQ_SIZE - accepted[0].sigShares.size());

    CDataStream accepted_stream{SER_NETWORK, PROTOCOL_VERSION};
    accepted_stream << accepted;
    BatchedSigShares decoded;
    BOOST_REQUIRE(llmq::UnserializeBatchedSigSharesWithLimits(
        accepted_stream, decoded, Consensus::MAX_LLMQ_SIZE, Consensus::MAX_LLMQ_SIZE));
    BOOST_CHECK(accepted_stream.empty());
    BOOST_REQUIRE_EQUAL(decoded.size(), accepted.size());
    BOOST_CHECK_EQUAL(decoded[0].sessionId, accepted[0].sessionId);
    BOOST_CHECK_EQUAL(decoded[1].sessionId, accepted[1].sessionId);
    BOOST_CHECK_EQUAL(decoded[0].sigShares.size() + decoded[1].sigShares.size(), Consensus::MAX_LLMQ_SIZE);

    BatchedSigShares rejected(2);
    rejected[0].sessionId = 1;
    rejected[0].sigShares.resize(1);
    rejected[1].sessionId = 2;
    rejected[1].sigShares.resize(Consensus::MAX_LLMQ_SIZE);

    CDataStream rejected_stream{SER_NETWORK, PROTOCOL_VERSION};
    rejected_stream << rejected;
    CDataStream rejected_inner{SER_NETWORK, PROTOCOL_VERSION};
    rejected_inner << rejected[1].sigShares;
    const size_t rejected_inner_payload_size = rejected_inner.size() - GetSizeOfCompactSize(rejected[1].sigShares.size());

    BOOST_CHECK(!llmq::UnserializeBatchedSigSharesWithLimits(
        rejected_stream, decoded, Consensus::MAX_LLMQ_SIZE, Consensus::MAX_LLMQ_SIZE));
    BOOST_CHECK(decoded.empty());
    BOOST_CHECK_EQUAL(rejected_stream.size(), rejected_inner_payload_size);
}

BOOST_AUTO_TEST_CASE(sparse_inventory_offsets_are_checked_before_indexing)
{
    {
        CDataStream stream{ParseHex("01010186fefeff0100"), SER_NETWORK, PROTOCOL_VERSION};
        llmq::CSigSharesInv inventory;
        BOOST_CHECK_THROW(stream >> inventory, std::ios_base::failure);
        BOOST_CHECK_EQUAL(stream.size(), 1U);
    }

    {
        CDataStream stream{ParseHex("0103010300"), SER_NETWORK, PROTOCOL_VERSION};
        llmq::CSigSharesInv inventory;
        BOOST_REQUIRE_NO_THROW(stream >> inventory);
        BOOST_CHECK(stream.empty());
        BOOST_REQUIRE_EQUAL(inventory.inv.size(), 3U);
        BOOST_CHECK(!inventory.inv[0]);
        BOOST_CHECK(!inventory.inv[1]);
        BOOST_CHECK(inventory.inv[2]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
