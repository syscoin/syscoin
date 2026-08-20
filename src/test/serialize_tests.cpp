// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <evo/specialtx.h>
#include <hash.h>
#include <llmq/pq_btcc.h> // SYSCOIN: branch-bound BTCC receipt records.
#include <llmq/pq_payment_audit.h> // SYSCOIN: payment-audit receipt records.
#include <llmq/quorums_commitment.h> // SYSCOIN: bounded historical tx85 replay.
#include <primitives/block.h>
#include <serialize.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <stdint.h>
#include <array>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#ifdef LOWER
#undef LOWER
#endif

BOOST_FIXTURE_TEST_SUITE(serialize_tests, BasicTestingSetup)

class CSerializeMethodsTestSingle
{
protected:
    int intval;
    bool boolval;
    std::string stringval;
    char charstrval[16];
    CTransactionRef txval;
public:
    CSerializeMethodsTestSingle() = default;
    CSerializeMethodsTestSingle(int intvalin, bool boolvalin, std::string stringvalin, const uint8_t* charstrvalin, const CTransactionRef& txvalin) : intval(intvalin), boolval(boolvalin), stringval(std::move(stringvalin)), txval(txvalin)
    {
        memcpy(charstrval, charstrvalin, sizeof(charstrval));
    }

    SERIALIZE_METHODS(CSerializeMethodsTestSingle, obj)
    {
        READWRITE(obj.intval);
        READWRITE(obj.boolval);
        READWRITE(obj.stringval);
        READWRITE(obj.charstrval);
        READWRITE(obj.txval);
    }

    bool operator==(const CSerializeMethodsTestSingle& rhs) const
    {
        return intval == rhs.intval &&
               boolval == rhs.boolval &&
               stringval == rhs.stringval &&
               strcmp(charstrval, rhs.charstrval) == 0 &&
               *txval == *rhs.txval;
    }
};

class CSerializeMethodsTestMany : public CSerializeMethodsTestSingle
{
public:
    using CSerializeMethodsTestSingle::CSerializeMethodsTestSingle;

    SERIALIZE_METHODS(CSerializeMethodsTestMany, obj)
    {
        READWRITE(obj.intval, obj.boolval, obj.stringval, obj.charstrval, obj.txval);
    }
};

BOOST_AUTO_TEST_CASE(sizes)
{
    BOOST_CHECK_EQUAL(sizeof(unsigned char), GetSerializeSize((unsigned char)0, 0));
    BOOST_CHECK_EQUAL(sizeof(int8_t), GetSerializeSize(int8_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(uint8_t), GetSerializeSize(uint8_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(int16_t), GetSerializeSize(int16_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(uint16_t), GetSerializeSize(uint16_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(int32_t), GetSerializeSize(int32_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(uint32_t), GetSerializeSize(uint32_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(int64_t), GetSerializeSize(int64_t(0), 0));
    BOOST_CHECK_EQUAL(sizeof(uint64_t), GetSerializeSize(uint64_t(0), 0));
    // Bool is serialized as uint8_t
    BOOST_CHECK_EQUAL(sizeof(uint8_t), GetSerializeSize(bool(0), 0));

    // Sanity-check GetSerializeSize and c++ type matching
    BOOST_CHECK_EQUAL(GetSerializeSize((unsigned char)0, 0), 1U);
    BOOST_CHECK_EQUAL(GetSerializeSize(int8_t(0), 0), 1U);
    BOOST_CHECK_EQUAL(GetSerializeSize(uint8_t(0), 0), 1U);
    BOOST_CHECK_EQUAL(GetSerializeSize(int16_t(0), 0), 2U);
    BOOST_CHECK_EQUAL(GetSerializeSize(uint16_t(0), 0), 2U);
    BOOST_CHECK_EQUAL(GetSerializeSize(int32_t(0), 0), 4U);
    BOOST_CHECK_EQUAL(GetSerializeSize(uint32_t(0), 0), 4U);
    BOOST_CHECK_EQUAL(GetSerializeSize(int64_t(0), 0), 8U);
    BOOST_CHECK_EQUAL(GetSerializeSize(uint64_t(0), 0), 8U);
    BOOST_CHECK_EQUAL(GetSerializeSize(bool(0), 0), 1U);
}

BOOST_AUTO_TEST_CASE(varints)
{
    // encode

    DataStream ss{};
    DataStream::size_type size = 0;
    for (int i = 0; i < 100000; i++) {
        ss << VARINT_MODE(i, VarIntMode::NONNEGATIVE_SIGNED);
        size += ::GetSerializeSize(VARINT_MODE(i, VarIntMode::NONNEGATIVE_SIGNED), 0);
        BOOST_CHECK(size == ss.size());
    }

    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        ss << VARINT(i);
        size += ::GetSerializeSize(VARINT(i), 0);
        BOOST_CHECK(size == ss.size());
    }

    // decode
    for (int i = 0; i < 100000; i++) {
        int j = -1;
        ss >> VARINT_MODE(j, VarIntMode::NONNEGATIVE_SIGNED);
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
    }

    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        uint64_t j = std::numeric_limits<uint64_t>::max();
        ss >> VARINT(j);
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
    }
}

BOOST_AUTO_TEST_CASE(varints_bitpatterns)
{
    DataStream ss{};
    ss << VARINT_MODE(0, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "00"); ss.clear();
    ss << VARINT_MODE(0x7f, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "7f"); ss.clear();
    ss << VARINT_MODE(int8_t{0x7f}, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "7f"); ss.clear();
    ss << VARINT_MODE(0x80, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "8000"); ss.clear();
    ss << VARINT(uint8_t{0x80}); BOOST_CHECK_EQUAL(HexStr(ss), "8000"); ss.clear();
    ss << VARINT_MODE(0x1234, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "a334"); ss.clear();
    ss << VARINT_MODE(int16_t{0x1234}, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "a334"); ss.clear();
    ss << VARINT_MODE(0xffff, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "82fe7f"); ss.clear();
    ss << VARINT(uint16_t{0xffff}); BOOST_CHECK_EQUAL(HexStr(ss), "82fe7f"); ss.clear();
    ss << VARINT_MODE(0x123456, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "c7e756"); ss.clear();
    ss << VARINT_MODE(int32_t{0x123456}, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "c7e756"); ss.clear();
    ss << VARINT(0x80123456U); BOOST_CHECK_EQUAL(HexStr(ss), "86ffc7e756"); ss.clear();
    ss << VARINT(uint32_t{0x80123456U}); BOOST_CHECK_EQUAL(HexStr(ss), "86ffc7e756"); ss.clear();
    ss << VARINT(0xffffffff); BOOST_CHECK_EQUAL(HexStr(ss), "8efefefe7f"); ss.clear();
    ss << VARINT_MODE(0x7fffffffffffffffLL, VarIntMode::NONNEGATIVE_SIGNED); BOOST_CHECK_EQUAL(HexStr(ss), "fefefefefefefefe7f"); ss.clear();
    ss << VARINT(0xffffffffffffffffULL); BOOST_CHECK_EQUAL(HexStr(ss), "80fefefefefefefefe7f"); ss.clear();
}

BOOST_AUTO_TEST_CASE(compactsize)
{
    DataStream ss{};
    std::vector<char>::size_type i, j;

    for (i = 1; i <= MAX_SIZE; i *= 2)
    {
        WriteCompactSize(ss, i-1);
        WriteCompactSize(ss, i);
    }
    for (i = 1; i <= MAX_SIZE; i *= 2)
    {
        j = ReadCompactSize(ss);
        BOOST_CHECK_MESSAGE((i-1) == j, "decoded:" << j << " expected:" << (i-1));
        j = ReadCompactSize(ss);
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
    }
}

static bool isCanonicalException(const std::ios_base::failure& ex)
{
    std::ios_base::failure expectedException("non-canonical ReadCompactSize()");

    // The string returned by what() can be different for different platforms.
    // Instead of directly comparing the ex.what() with an expected string,
    // create an instance of exception to see if ex.what() matches
    // the expected explanatory string returned by the exception instance.
    return strcmp(expectedException.what(), ex.what()) == 0;
}

BOOST_AUTO_TEST_CASE(vector_bool)
{
    std::vector<uint8_t> vec1{1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1};
    std::vector<bool> vec2{1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1};

    BOOST_CHECK(vec1 == std::vector<uint8_t>(vec2.begin(), vec2.end()));
    BOOST_CHECK((HashWriter{} << vec1).GetHash() == (HashWriter{} << vec2).GetHash());
}

// SYSCOIN: Historical tx85 replay must reject truncated dense signer bitmaps
// before allocating or changing the destination vector.
static bool isBitSetSizeException(const std::ios_base::failure& ex)
{
    const std::ios_base::failure expected("ReadFixedBitSet(): declared size exceeds remaining bytes");
    return strcmp(expected.what(), ex.what()) == 0;
}

BOOST_AUTO_TEST_CASE(fixedbitset_rejects_underfilled_payload_before_allocation)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    const std::vector<bool> original{true, false, true};
    std::vector<bool> decoded{original};
    BOOST_CHECK_EXCEPTION(ReadFixedBitSet(stream, decoded, 1'000'000), std::ios_base::failure, isBitSetSizeException);
    BOOST_CHECK(decoded == original);
}

BOOST_AUTO_TEST_CASE(qfcommitment_rejects_underfilled_signers_before_allocation)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << static_cast<uint16_t>(llmq::CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION);
    stream << uint256{};
    WriteCompactSize(stream, llmq::legacy::MAX_QUORUM_MEMBERS);
    stream << uint8_t{0xaa};

    llmq::CFinalCommitment commitment;
    BOOST_CHECK_EXCEPTION(stream >> commitment, std::ios_base::failure, isBitSetSizeException);
    BOOST_CHECK(commitment.signers.empty());
    BOOST_CHECK_EQUAL(stream.size(), 1U);
}

BOOST_AUTO_TEST_CASE(noncanonical)
{
    // Write some non-canonical CompactSize encodings, and
    // make sure an exception is thrown when read back.
    DataStream ss{};
    std::vector<char>::size_type n;

    // zero encoded with three bytes:
    ss << Span{"\xfd\x00\x00"}.first(3);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);

    // 0xfc encoded with three bytes:
    ss << Span{"\xfd\xfc\x00"}.first(3);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);

    // 0xfd encoded with three bytes is OK:
    ss << Span{"\xfd\xfd\x00"}.first(3);
    n = ReadCompactSize(ss);
    BOOST_CHECK(n == 0xfd);

    // zero encoded with five bytes:
    ss << Span{"\xfe\x00\x00\x00\x00"}.first(5);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);

    // 0xffff encoded with five bytes:
    ss << Span{"\xfe\xff\xff\x00\x00"}.first(5);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);

    // zero encoded with nine bytes:
    ss << Span{"\xff\x00\x00\x00\x00\x00\x00\x00\x00"}.first(9);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);

    // 0x01ffffff encoded with nine bytes:
    ss << Span{"\xff\xff\xff\xff\x01\x00\x00\x00\x00"}.first(9);
    BOOST_CHECK_EXCEPTION(ReadCompactSize(ss), std::ios_base::failure, isCanonicalException);
}

BOOST_AUTO_TEST_CASE(class_methods)
{
    int intval(100);
    bool boolval(true);
    std::string stringval("testing");
    const uint8_t charstrval[16]{"testing charstr"};
    CMutableTransaction txval;
    CTransactionRef tx_ref{MakeTransactionRef(txval)};
    CSerializeMethodsTestSingle methodtest1(intval, boolval, stringval, charstrval, tx_ref);
    CSerializeMethodsTestMany methodtest2(intval, boolval, stringval, charstrval, tx_ref);
    CSerializeMethodsTestSingle methodtest3;
    CSerializeMethodsTestMany methodtest4;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    BOOST_CHECK(methodtest1 == methodtest2);
    ss << methodtest1;
    ss >> methodtest4;
    ss << methodtest2;
    ss >> methodtest3;
    BOOST_CHECK(methodtest1 == methodtest2);
    BOOST_CHECK(methodtest2 == methodtest3);
    BOOST_CHECK(methodtest3 == methodtest4);

    CDataStream ss2{SER_DISK, PROTOCOL_VERSION};
    ss2 << intval << boolval << stringval << charstrval << txval;
    ss2 >> methodtest3;
    BOOST_CHECK(methodtest3 == methodtest4);
    {
        DataStream ds;
        const std::string in{"ab"};
        ds << Span{in} << std::byte{'c'};
        std::array<std::byte, 2> out;
        std::byte out_3;
        ds >> Span{out} >> out_3;
        BOOST_CHECK_EQUAL(out.at(0), std::byte{'a'});
        BOOST_CHECK_EQUAL(out.at(1), std::byte{'b'});
        BOOST_CHECK_EQUAL(out_3, std::byte{'c'});
    }
}
// SYSCOIN BEGIN: fork block-index and payment-audit serialization.
BOOST_AUTO_TEST_CASE(cdiskblockindex_btcp_prev_serialization)
{
    const auto make_disk_index = [](const uint256& btcp_prev,
                                    bool with_receipt_state = false) {
        LOCK(cs_main);
        CBlockIndex index{};
        index.nHeight = 42;
        index.nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
        index.nTx = 7;
        index.nFile = 3;
        index.nDataPos = 64;
        index.nUndoPos = 96;
        index.nVersion = 4;
        index.hashMerkleRoot = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
        index.nTime = 1234567890;
        index.nBits = 0x1d00ffff;
        index.nNonce = 9;
        index.btcpPrevCommitment = btcp_prev;
        if (with_receipt_state) {
            index.pqBTCCReceiptCursorHeight = 40;
            index.pqBTCCReceiptCursorSysHash = uint256S(std::string(64, '2'));
            index.pqBTCCReceiptCursorBTCHash = uint256S(std::string(64, '3'));
            index.pqBTCCReceiptStateHash = uint256S(std::string(64, '4'));
            index.pqBTCCReceiptLogicalId = uint256S(std::string(64, 'a'));
            index.pqPaymentAuditReceiptCursorHeight = 41;
            index.pqPaymentAuditReceiptCursorEpoch = 7;
            index.pqPaymentAuditReceiptCursorSealHash = uint256S(std::string(64, '5'));
            index.pqPaymentAuditReceiptCursorLogicalId = uint256S(std::string(64, '6'));
            index.pqPaymentAuditReceiptCursorWitnessId =
                uint256S(std::string(64, '9'));
            index.pqPaymentAuditReceiptStateHash = uint256S(std::string(64, '7'));
            index.pqPaymentProbationStateHash = uint256S(std::string(64, '8'));
        }
        return CDiskBlockIndex{&index};
    };

    const CDiskBlockIndex without_btcp_prev = make_disk_index(uint256{});
    const CDiskBlockIndex with_btcp_prev = make_disk_index(
        uint256S("00000000000000000000000000000000000000000000000000000000000000aa"));
    const CDiskBlockIndex with_receipt_state = make_disk_index(
        with_btcp_prev.btcpPrevCommitment, true);

    DataStream without_btcp_prev_ser{};
    without_btcp_prev_ser << without_btcp_prev;
    DataStream with_btcp_prev_ser{};
    with_btcp_prev_ser << with_btcp_prev;
    DataStream with_receipt_state_ser{};
    with_receipt_state_ser << with_receipt_state;

    int without_btcp_prev_version{0};
    {
        DataStream version_stream{without_btcp_prev_ser};
        version_stream >> VARINT_MODE(without_btcp_prev_version, VarIntMode::NONNEGATIVE_SIGNED);
    }

    int with_btcp_prev_version{0};
    {
        DataStream version_stream{with_btcp_prev_ser};
        version_stream >> VARINT_MODE(with_btcp_prev_version, VarIntMode::NONNEGATIVE_SIGNED);
    }

    BOOST_CHECK(with_btcp_prev_version > without_btcp_prev_version);
    BOOST_CHECK_EQUAL(with_btcp_prev_ser.size() - without_btcp_prev_ser.size(), GetSerializeSize(uint256{}));

    int with_receipt_state_version{0};
    {
        DataStream version_stream{with_receipt_state_ser};
        version_stream >> VARINT_MODE(with_receipt_state_version,
                                      VarIntMode::NONNEGATIVE_SIGNED);
    }
    BOOST_CHECK(with_receipt_state_version > with_btcp_prev_version);
    BOOST_CHECK_EQUAL(with_receipt_state_ser.size() - with_btcp_prev_ser.size(),
                      300U);

    CDiskBlockIndex without_btcp_prev_roundtrip;
    DataStream without_btcp_prev_read{without_btcp_prev_ser};
    without_btcp_prev_read >> without_btcp_prev_roundtrip;
    BOOST_CHECK(without_btcp_prev_roundtrip.btcpPrevCommitment.IsNull());

    CDiskBlockIndex with_btcp_prev_roundtrip;
    DataStream with_btcp_prev_read{with_btcp_prev_ser};
    with_btcp_prev_read >> with_btcp_prev_roundtrip;
    BOOST_CHECK(with_btcp_prev_roundtrip.btcpPrevCommitment == with_btcp_prev.btcpPrevCommitment);

    CDiskBlockIndex with_receipt_state_roundtrip;
    DataStream with_receipt_state_read{with_receipt_state_ser};
    with_receipt_state_read >> with_receipt_state_roundtrip;
    BOOST_CHECK(with_receipt_state_roundtrip.btcpPrevCommitment ==
                with_receipt_state.btcpPrevCommitment);
    BOOST_CHECK_EQUAL(with_receipt_state_roundtrip.pqBTCCReceiptCursorHeight,
                      with_receipt_state.pqBTCCReceiptCursorHeight);
    BOOST_CHECK(with_receipt_state_roundtrip.pqBTCCReceiptCursorSysHash ==
                with_receipt_state.pqBTCCReceiptCursorSysHash);
    BOOST_CHECK(with_receipt_state_roundtrip.pqBTCCReceiptCursorBTCHash ==
                with_receipt_state.pqBTCCReceiptCursorBTCHash);
    BOOST_CHECK(with_receipt_state_roundtrip.pqBTCCReceiptStateHash ==
                with_receipt_state.pqBTCCReceiptStateHash);
    BOOST_CHECK(with_receipt_state_roundtrip.pqBTCCReceiptLogicalId ==
                with_receipt_state.pqBTCCReceiptLogicalId);
    BOOST_CHECK_EQUAL(
        with_receipt_state_roundtrip.pqPaymentAuditReceiptCursorHeight,
        with_receipt_state.pqPaymentAuditReceiptCursorHeight);
    BOOST_CHECK_EQUAL(
        with_receipt_state_roundtrip.pqPaymentAuditReceiptCursorEpoch,
        with_receipt_state.pqPaymentAuditReceiptCursorEpoch);
    BOOST_CHECK(
        with_receipt_state_roundtrip.pqPaymentAuditReceiptCursorSealHash ==
        with_receipt_state.pqPaymentAuditReceiptCursorSealHash);
    BOOST_CHECK(
        with_receipt_state_roundtrip.pqPaymentAuditReceiptCursorLogicalId ==
        with_receipt_state.pqPaymentAuditReceiptCursorLogicalId);
    BOOST_CHECK(
        with_receipt_state_roundtrip.pqPaymentAuditReceiptCursorWitnessId ==
        with_receipt_state.pqPaymentAuditReceiptCursorWitnessId);
    BOOST_CHECK(with_receipt_state_roundtrip.pqPaymentAuditReceiptStateHash ==
                with_receipt_state.pqPaymentAuditReceiptStateHash);
    BOOST_CHECK(with_receipt_state_roundtrip.pqPaymentProbationStateHash ==
                with_receipt_state.pqPaymentProbationStateHash);

    for (const uint32_t provenance : {
             static_cast<uint32_t>(BLOCK_PQ_BTCC_INDEX_VALIDATED),
             static_cast<uint32_t>(BLOCK_PQ_RECEIPT_INDEX_VALIDATED),
             static_cast<uint32_t>(BLOCK_PQ_BTCC_INDEX_VALIDATED |
                                   BLOCK_PQ_RECEIPT_INDEX_VALIDATED)}) {
        CBlockIndex index;
        {
            LOCK(cs_main);
            index.nHeight = 43;
            index.nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | provenance);
        }
        const CDiskBlockIndex disk{&index};
        DataStream encoded;
        encoded << disk;
        CDiskBlockIndex decoded;
        encoded >> decoded;
        const uint32_t decoded_status{WITH_LOCK(
            cs_main, return static_cast<uint32_t>(decoded.nStatus))};
        BOOST_CHECK_EQUAL(
            decoded_status &
                (BLOCK_PQ_BTCC_INDEX_VALIDATED |
                 BLOCK_PQ_RECEIPT_INDEX_VALIDATED),
            provenance);
    }
}

static CBlock BuildCoinbaseOnlyBlockWithPayload(const std::vector<unsigned char>& payload)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << payload);

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

BOOST_AUTO_TEST_CASE(extract_btcprev_ignores_embedded_magic_in_hash_tail)
{
    static constexpr std::array<uint8_t, 4> BTCP_MAGIC{{'b', 't', 'c', 'p'}};

    std::vector<unsigned char> hash_bytes(32, 0x11);
    hash_bytes[28] = BTCP_MAGIC[0];
    hash_bytes[29] = BTCP_MAGIC[1];
    hash_bytes[30] = BTCP_MAGIC[2];
    hash_bytes[31] = BTCP_MAGIC[3];

    std::vector<unsigned char> payload;
    payload.reserve(BTCP_MAGIC.size() + hash_bytes.size());
    payload.insert(payload.end(), BTCP_MAGIC.begin(), BTCP_MAGIC.end());
    payload.insert(payload.end(), hash_bytes.begin(), hash_bytes.end());

    const CBlock block = BuildCoinbaseOnlyBlockWithPayload(payload);

    uint256 extracted{};
    BOOST_CHECK(ExtractBTCPREVCommitment(block, extracted));

    DataStream hash_stream;
    hash_stream << extracted;
    const std::string extracted_bytes = hash_stream.str();
    BOOST_CHECK_EQUAL(extracted_bytes.size(), hash_bytes.size());
    BOOST_CHECK(std::equal(extracted_bytes.begin(), extracted_bytes.end(), hash_bytes.begin()));
}

// SYSCOIN: keep the BTCC decoder's canonical optional-BTCPREV tail contract
// covered after moving it out of the special-transaction dispatcher.
BOOST_AUTO_TEST_CASE(extract_btcc_receipt_accepts_canonical_coinbase_tails)
{
    const llmq::pq::BTCCReceipt expected;
    DataStream receipt_stream;
    receipt_stream << expected;
    const auto receipt_bytes{MakeUCharSpan(receipt_stream)};

    std::vector<unsigned char> payload{
        std::begin(BTCC_RECEIPT_MAGIC_BYTES),
        std::end(BTCC_RECEIPT_MAGIC_BYTES)};
    payload.insert(payload.end(), receipt_bytes.begin(), receipt_bytes.end());
    const uint256 btc_prev{uint256S(std::string(64, '1'))};
    DataStream btcprev_stream;
    btcprev_stream << BTCPREV_MAGIC_BYTES << btc_prev;
    const auto btcprev_bytes{MakeUCharSpan(btcprev_stream)};
    payload.insert(payload.end(), btcprev_bytes.begin(), btcprev_bytes.end());

    const CBlock block{BuildCoinbaseOnlyBlockWithPayload(payload)};
    llmq::pq::BTCCReceipt extracted;
    BOOST_CHECK(HasBTCCReceiptCommitment(block));
    BOOST_CHECK(ExtractBTCCReceipt(block, extracted));
    BOOST_CHECK(extracted == expected);

    payload.pop_back();
    const CBlock truncated{BuildCoinbaseOnlyBlockWithPayload(payload)};
    BOOST_CHECK(HasBTCCReceiptCommitment(truncated));
    BOOST_CHECK(!ExtractBTCCReceipt(truncated, extracted));
}

BOOST_AUTO_TEST_CASE(payment_audit_and_btcc_use_one_canonical_coinbase_suffix)
{
    const llmq::pq::PaymentAuditReceipt expected_audit;
    const llmq::pq::BTCCReceipt expected_btcc;
    DataStream audit_stream;
    audit_stream << expected_audit;
    BOOST_CHECK_EQUAL(audit_stream.size(),
                      llmq::pq::PaymentAuditReceipt::WIRE_SIZE);
    DataStream btcc_stream;
    btcc_stream << expected_btcc;

    std::vector<unsigned char> payload{
        std::begin(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
        std::end(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES)};
    const auto audit_bytes{MakeUCharSpan(audit_stream)};
    payload.insert(payload.end(), audit_bytes.begin(), audit_bytes.end());
    payload.insert(payload.end(), std::begin(BTCC_RECEIPT_MAGIC_BYTES),
                   std::end(BTCC_RECEIPT_MAGIC_BYTES));
    const auto btcc_bytes{MakeUCharSpan(btcc_stream)};
    payload.insert(payload.end(), btcc_bytes.begin(), btcc_bytes.end());
    const uint256 btc_prev{uint256S(std::string(64, '2'))};
    DataStream btcprev_stream;
    btcprev_stream << BTCPREV_MAGIC_BYTES << btc_prev;
    const auto btcprev_bytes{MakeUCharSpan(btcprev_stream)};
    payload.insert(payload.end(), btcprev_bytes.begin(), btcprev_bytes.end());

    const CBlock canonical{BuildCoinbaseOnlyBlockWithPayload(payload)};
    llmq::pq::PaymentAuditReceipt decoded_audit;
    llmq::pq::BTCCReceipt decoded_btcc;
    BOOST_CHECK(HasPaymentAuditReceiptCommitment(canonical));
    BOOST_CHECK(ExtractPaymentAuditReceipt(canonical, decoded_audit));
    BOOST_CHECK(decoded_audit == expected_audit);
    BOOST_CHECK(HasBTCCReceiptCommitment(canonical));
    BOOST_CHECK(ExtractBTCCReceipt(canonical, decoded_btcc));
    BOOST_CHECK(decoded_btcc == expected_btcc);

    auto truncated_payload{payload};
    truncated_payload.pop_back();
    const CBlock truncated{
        BuildCoinbaseOnlyBlockWithPayload(truncated_payload)};
    BOOST_CHECK(!ExtractPaymentAuditReceipt(truncated, decoded_audit));
    BOOST_CHECK(!ExtractBTCCReceipt(truncated, decoded_btcc));

    std::vector<unsigned char> reversed_payload{
        std::begin(BTCC_RECEIPT_MAGIC_BYTES),
        std::end(BTCC_RECEIPT_MAGIC_BYTES)};
    reversed_payload.insert(reversed_payload.end(), btcc_bytes.begin(),
                            btcc_bytes.end());
    reversed_payload.insert(
        reversed_payload.end(),
        std::begin(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
        std::end(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES));
    reversed_payload.insert(reversed_payload.end(), audit_bytes.begin(),
                            audit_bytes.end());
    reversed_payload.insert(reversed_payload.end(), btcprev_bytes.begin(),
                            btcprev_bytes.end());
    const CBlock reversed{
        BuildCoinbaseOnlyBlockWithPayload(reversed_payload)};
    BOOST_CHECK(!ExtractPaymentAuditReceipt(reversed, decoded_audit));
    BOOST_CHECK(!ExtractBTCCReceipt(reversed, decoded_btcc));
}

// SYSCOIN END: fork block-index and payment-audit serialization.

enum class BaseFormat {
    RAW,
    HEX,
};

/// (Un)serialize a number as raw byte or 2 hexadecimal chars.
class Base
{
public:
    uint8_t m_base_data;

    Base() : m_base_data(17) {}
    explicit Base(uint8_t data) : m_base_data(data) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (*s.GetParams() == BaseFormat::RAW) {
            s << m_base_data;
        } else {
            s << Span{HexStr(Span{&m_base_data, 1})};
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        if (*s.GetParams() == BaseFormat::RAW) {
            s >> m_base_data;
        } else {
            std::string hex{"aa"};
            s >> Span{hex}.first(hex.size());
            m_base_data = TryParseHex<uint8_t>(hex).value().at(0);
        }
    }
};

class DerivedAndBaseFormat
{
public:
    BaseFormat m_base_format;

    enum class DerivedFormat {
        LOWER,
        UPPER,
    } m_derived_format;
};

class Derived : public Base
{
public:
    std::string m_derived_data;

    SERIALIZE_METHODS_PARAMS(Derived, obj, DerivedAndBaseFormat, fmt)
    {
        READWRITE(WithParams(fmt->m_base_format, AsBase<Base>(obj)));

        if (ser_action.ForRead()) {
            std::string str;
            s >> str;
            SER_READ(obj, obj.m_derived_data = str);
        } else {
            s << (fmt->m_derived_format == DerivedAndBaseFormat::DerivedFormat::LOWER ?
                      ToLower(obj.m_derived_data) :
                      ToUpper(obj.m_derived_data));
        }
    }
};

BOOST_AUTO_TEST_CASE(with_params_base)
{
    Base b{0x0F};

    DataStream stream;

    stream << WithParams(BaseFormat::RAW, b);
    BOOST_CHECK_EQUAL(stream.str(), "\x0F");

    b.m_base_data = 0;
    stream >> WithParams(BaseFormat::RAW, b);
    BOOST_CHECK_EQUAL(b.m_base_data, 0x0F);

    stream.clear();

    stream << WithParams(BaseFormat::HEX, b);
    BOOST_CHECK_EQUAL(stream.str(), "0f");

    b.m_base_data = 0;
    stream >> WithParams(BaseFormat::HEX, b);
    BOOST_CHECK_EQUAL(b.m_base_data, 0x0F);
}

BOOST_AUTO_TEST_CASE(with_params_vector_of_base)
{
    std::vector<Base> v{Base{0x0F}, Base{0xFF}};

    DataStream stream;

    stream << WithParams(BaseFormat::RAW, v);
    BOOST_CHECK_EQUAL(stream.str(), "\x02\x0F\xFF");

    v[0].m_base_data = 0;
    v[1].m_base_data = 0;
    stream >> WithParams(BaseFormat::RAW, v);
    BOOST_CHECK_EQUAL(v[0].m_base_data, 0x0F);
    BOOST_CHECK_EQUAL(v[1].m_base_data, 0xFF);

    stream.clear();

    stream << WithParams(BaseFormat::HEX, v);
    BOOST_CHECK_EQUAL(stream.str(), "\x02"
                                    "0fff");

    v[0].m_base_data = 0;
    v[1].m_base_data = 0;
    stream >> WithParams(BaseFormat::HEX, v);
    BOOST_CHECK_EQUAL(v[0].m_base_data, 0x0F);
    BOOST_CHECK_EQUAL(v[1].m_base_data, 0xFF);
}

BOOST_AUTO_TEST_CASE(with_params_derived)
{
    Derived d;
    d.m_base_data = 0x0F;
    d.m_derived_data = "xY";

    DerivedAndBaseFormat fmt;

    DataStream stream;

    fmt.m_base_format = BaseFormat::RAW;
    fmt.m_derived_format = DerivedAndBaseFormat::DerivedFormat::LOWER;
    stream << WithParams(fmt, d);

    fmt.m_base_format = BaseFormat::HEX;
    fmt.m_derived_format = DerivedAndBaseFormat::DerivedFormat::UPPER;
    stream << WithParams(fmt, d);

    BOOST_CHECK_EQUAL(stream.str(), "\x0F\x02xy"
                                    "0f\x02XY");
}

BOOST_AUTO_TEST_SUITE_END()
