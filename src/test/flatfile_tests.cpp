// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <compat/compat.h>
#include <common/args.h>
#include <flatfile.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs_helpers.h>

#include <limits>

#ifdef WIN32
#include <io.h>
#include <winioctl.h>
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flatfile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flatfile_filename)
{
    const auto data_dir = m_args.GetDataDirBase();

    FlatFilePos pos(456, 789);

    FlatFileSeq seq1(data_dir, "a", 16 * 1024);
    BOOST_CHECK_EQUAL(seq1.FileName(pos), data_dir / "a00456.dat");

    FlatFileSeq seq2(data_dir / "a", "b", 16 * 1024);
    BOOST_CHECK_EQUAL(seq2.FileName(pos), data_dir / "a" / "b00456.dat");

    // Check default constructor IsNull
    assert(FlatFilePos{}.IsNull());
}

BOOST_AUTO_TEST_CASE(flatfile_open)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 16 * 1024);

    std::string line1("A purely peer-to-peer version of electronic cash would allow online "
                      "payments to be sent directly from one party to another without going "
                      "through a financial institution.");
    std::string line2("Digital signatures provide part of the solution, but the main benefits are "
                      "lost if a trusted third party is still required to prevent double-spending.");

    size_t pos1 = 0;
    size_t pos2 = pos1 + GetSerializeSize(line1, CLIENT_VERSION);

    // Write first line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos1))};
        file << LIMITED_STRING(line1, 256);
    }

    // Attempt to append to file opened in read-only mode.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2), true)};
        BOOST_CHECK_THROW(file << LIMITED_STRING(line2, 256), std::ios_base::failure);
    }

    // Append second line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};
        file << LIMITED_STRING(line2, 256);
    }

    // Read text from file in read-only mode.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos1), true)};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line1);

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Read text from file with position offset.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Ensure another file in the sequence has no data.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(1, pos2))};
        BOOST_CHECK_THROW(file >> LIMITED_STRING(text, 256), std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_allocate)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 0), 1, out_of_space), 100U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 0))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 1, out_of_space), 0U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 2, out_of_space), 101U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 200U);
    BOOST_CHECK(!out_of_space);
}

BOOST_AUTO_TEST_CASE(flatfile_flush)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;
    seq.Allocate(FlatFilePos(0, 0), 1, out_of_space);

    // Flush without finalize should not truncate file.
    seq.Flush(FlatFilePos(0, 1));
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 100U);

    // Flush with finalize should truncate file.
    seq.Flush(FlatFilePos(0, 1), true);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 1U);
}

BOOST_AUTO_TEST_CASE(flatfile_position_serialization_compatibility)
{
    for (uint32_t offset : {0U, 1U, 127U, 128U, std::numeric_limits<uint32_t>::max()}) {
        int file_number{7};
        CDataStream legacy{SER_DISK, CLIENT_VERSION};
        legacy << VARINT_MODE(file_number, VarIntMode::NONNEGATIVE_SIGNED) << VARINT(offset);
        CDataStream current{SER_DISK, CLIENT_VERSION};
        current << FlatFilePos{file_number, offset};
        BOOST_CHECK_EQUAL(current.str(), legacy.str());
        FlatFilePos decoded;
        legacy >> decoded;
        BOOST_CHECK(decoded == FlatFilePos(file_number, offset));
        BOOST_CHECK(legacy.empty());
    }
    const FlatFilePos high{7, (uint64_t{1} << 32) + 123};
    CDataStream stream{SER_DISK, CLIENT_VERSION};
    stream << high;
    FlatFilePos decoded;
    stream >> decoded;
    BOOST_CHECK(decoded == high);
}

BOOST_AUTO_TEST_CASE(flatfile_large_sparse_position_and_xor)
{
    FlatFileSeq seq{m_args.GetDataDirBase(), "large", 16 * 1024};
    const uint64_t high{(uint64_t{1} << 32) + 123};
    const uint8_t marker{0x5a};
    const std::vector<std::byte> key{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}};
    {
        AutoFile low{seq.Open(FlatFilePos{0, 0})};
        BOOST_REQUIRE(!low.IsNull());
#ifdef WIN32
        // Avoid allocating several GiB on NTFS when writing beyond EOF.
        DWORD returned{};
        BOOST_REQUIRE(DeviceIoControl(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(low.Get()))),
                                      FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr));
#endif
        low << marker;
    }
#if !defined(WIN32)
    if (sizeof(off_t) < sizeof(int64_t)) {
        // Reject large positions on platforms without large-file support.
        AutoFile unsupported{seq.Open(FlatFilePos{0, high})};
        BOOST_CHECK(unsupported.IsNull());
        return;
    }
#endif
    {
        AutoFile file{seq.Open(FlatFilePos{0, high}), key};
        BOOST_REQUIRE(!file.IsNull());
        BOOST_CHECK_EQUAL(FileTell64(file.Get()), high);
        file << marker;
        BOOST_CHECK_EQUAL(FileTell64(file.Get()), high + 1);
        BOOST_CHECK_EQUAL(FileSeek64(file.Get(), -1, SEEK_CUR), 0);
        BOOST_CHECK_EQUAL(FileTell64(file.Get()), high);
    }
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos{0, 0})), high + 1);
    {
        AutoFile file{seq.Open(FlatFilePos{0, high}, true)};
        BOOST_REQUIRE(!file.IsNull());
        uint8_t encoded{};
        file >> encoded;
        BOOST_CHECK_EQUAL(encoded, marker ^ std::to_integer<uint8_t>(key[high % key.size()]));
    }
    {
        AutoFile file{seq.Open(FlatFilePos{0, high}, true), key};
        BOOST_REQUIRE(!file.IsNull());
        uint8_t actual{};
        file >> actual;
        BOOST_CHECK_EQUAL(actual, marker);
    }
    {
        AutoFile file{seq.Open(FlatFilePos{0, 0}, true)};
        uint8_t actual{};
        file >> actual;
        BOOST_CHECK_EQUAL(actual, marker);
    }
    BOOST_REQUIRE(seq.Flush(FlatFilePos{0, high}, true));
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos{0, 0})), high);
}

BOOST_AUTO_TEST_CASE(flatfile_allocation_rejects_position_overflow)
{
    constexpr uint64_t chunk_size{16 * 1024};
    FlatFileSeq seq{m_args.GetDataDirBase(), "overflow", chunk_size};
    bool out_of_space{false};
    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos{0, std::numeric_limits<uint64_t>::max()}, 1, out_of_space), 0U);
    BOOST_CHECK(out_of_space);
    // The requested data fits, but rounding up to a whole chunk must not overflow.
    const auto max_position{static_cast<uint64_t>(std::numeric_limits<int64_t>::max())};
    const auto last_chunk_boundary{max_position - max_position % chunk_size};
    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos{0, last_chunk_boundary}, 1, out_of_space), 0U);
    BOOST_CHECK(out_of_space);
    BOOST_CHECK(!fs::exists(seq.FileName(FlatFilePos{0, 0})));
    AutoFile file{seq.Open(FlatFilePos{0, std::numeric_limits<uint64_t>::max()})};
    BOOST_CHECK(file.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
