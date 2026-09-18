// Copyright (c) 2014-2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_FLATDATABASE_H
#define SYSCOIN_FLATDATABASE_H

#include <clientversion.h>
#include <chainparams.h>
#include <util/fs.h>
#include <hash.h>
#include <streams.h>
#include <common/args.h>
#include <logging.h>

#include <cstdint>
#include <limits>

// SYSCOIN: Bound inherited flat-file caches before allocation while still
// permitting independently configured cache sizes.
[[nodiscard]] inline constexpr bool FlatDatabaseFileSizeAllowed(
    uintmax_t file_size, uint64_t max_file_size) noexcept
{
    return file_size >= sizeof(uint256) && file_size <= max_file_size;
}
/**
*   Generic Dumping and Loading
*   ---------------------------
*/

template<typename T>
class CFlatDB
{
private:

    enum ReadResult {
        Ok,
        FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat,
        FileTooLarge,
    };

    fs::path pathDB;
    std::string strFilename;
    std::string strMagicMessage;
    uint64_t maxFileSize;

    bool CoreWrite(const T& objToSave)
    {
        // LOCK(objToSave.cs);

        int64_t nStart = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());

        CSizeComputer sizeComputer{CLIENT_VERSION, SER_DISK};
        sizeComputer << strMagicMessage << Params().MessageStart()
                     << objToSave;
        const uint64_t dataSize{sizeComputer.size()};
        if (dataSize > maxFileSize ||
            sizeof(uint256) > maxFileSize - dataSize) {
            return error("%s: Refusing to write oversized file %s",
                         __func__, pathDB.u8string());
        }

        // open output file, and associate with CAutoFile
        FILE *file = fopen(pathDB.u8string().c_str(), "wb");
        CAutoFile fileout(file, CLIENT_VERSION);
        if (fileout.IsNull())
            return error("%s: Failed to open file %s", __func__, pathDB.u8string());

        // SYSCOIN: Stream directly to disk so a large but valid cache is never
        // copied into a second whole-file allocation just to calculate its hash.
        try {
            HashedSourceWriter<CAutoFile> writer{
                fileout, SER_DISK, CLIENT_VERSION};
            writer << strMagicMessage << Params().MessageStart()
                   << objToSave;
            fileout << writer.GetHash();
        }
        catch (std::exception &e) {
            return error("%s: Serialize or I/O error - %s", __func__, e.what());
        }
        fileout.fclose();

        LogPrintf("Written info to %s  %dms\n", strFilename, TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) - nStart);
        LogPrintf("     %s\n", objToSave.ToString());

        return true;
    }

    ReadResult CoreRead(T& objToLoad)
    {
        //LOCK(objToLoad.cs);

        int64_t nStart = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
        // open input file, and associate with CAutoFile
        FILE *file = fopen(pathDB.u8string().c_str(), "rb");
        CAutoFile filein(file, CLIENT_VERSION);
        if (filein.IsNull())
        {
            error("%s: Failed to open file %s", __func__, pathDB.u8string());
            return FileError;
        }

        uintmax_t fileSize{0};
        try {
            fileSize = fs::file_size(pathDB);
        } catch (const std::exception& e) {
            error("%s: Failed to stat file %s: %s", __func__,
                  pathDB.u8string(), e.what());
            return FileError;
        }
        if (fileSize < sizeof(uint256)) {
            error("%s: File %s is too small", __func__, pathDB.u8string());
            return HashReadError;
        }
        // SYSCOIN: Reject oversized cache files before allocating their payload.
        if (!FlatDatabaseFileSizeAllowed(fileSize, maxFileSize)) {
            error("%s: File %s exceeds its configured size limit",
                  __func__, pathDB.u8string());
            return FileTooLarge;
        }

        MessageStartChars pchMsgTmp;
        std::string strMagicMessageTmp;
        uint256 hashIn;
        // SYSCOIN: Hash the bounded payload while deserializing and require
        // checksum EOF so appended data cannot be accepted.
        try {
            HashVerifier<CAutoFile> verifier{
                filein, SER_DISK, CLIENT_VERSION};
            // de-serialize file header (file specific magic message) and ..
            verifier >> strMagicMessageTmp;

            // ... verify the message matches predefined one
            if (strMagicMessage != strMagicMessageTmp)
            {
                error("%s: Invalid magic message", __func__);
                return IncorrectMagicMessage;
            }


            // de-serialize file header (network specific magic number) and ..
            verifier >> pchMsgTmp;

            // ... verify the network matches ours
            if (pchMsgTmp != Params().MessageStart())
            {
                error("%s: Invalid network magic number", __func__);
                return IncorrectMagicNumber;
            }

            // de-serialize data into T object
            verifier >> objToLoad;
            filein >> hashIn;
            if (std::fgetc(file) != EOF) {
                objToLoad.Clear();
                error("%s: Trailing data after checksum", __func__);
                return IncorrectFormat;
            }
            if (hashIn != verifier.GetHash()) {
                objToLoad.Clear();
                error("%s: Checksum mismatch, data corrupted", __func__);
                return IncorrectHash;
            }
        }
        catch (std::exception &e) {
            objToLoad.Clear();
            error("%s: Deserialize or I/O error - %s", __func__, e.what());
            return IncorrectFormat;
        }
        filein.fclose();

        LogPrintf("Loaded info from %s  %dms\n", strFilename, TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) - nStart);
        LogPrintf("     %s\n", objToLoad.ToString());

        return Ok;
    }

    bool Read(T& objToLoad)
    {
        ReadResult readResult = CoreRead(objToLoad);
        if (readResult == FileError)
            LogPrintf("Missing file %s, will try to recreate\n", strFilename);
        else if (readResult != Ok)
        {
            LogPrintf("Error reading %s: ", strFilename);
            if(readResult == IncorrectFormat)
            {
                LogPrintf("%s: Magic is ok but data has invalid format, will try to recreate\n", __func__);
            }
            else {
                LogPrintf("%s: File format is unknown or invalid, please fix it manually\n", __func__);
                // program should exit with an error
                return false;
            }
        }
        return true;
    }

public:
    CFlatDB(std::string strFilenameIn, std::string strMagicMessageIn,
            uint64_t maxFileSizeIn =
                std::numeric_limits<uint64_t>::max())
    {
        pathDB = gArgs.GetDataDirNet() / fs::u8path(strFilenameIn);
        strFilename = strFilenameIn;
        strMagicMessage = strMagicMessageIn;
        maxFileSize = maxFileSizeIn;
    }

    bool Load(T& objToLoad)
    {
        LogPrintf("Reading info from %s...\n", strFilename);
        return Read(objToLoad);
    }

    bool Store(T& objToSave)
    {
        LogPrintf("Verifying %s format...\n", strFilename);
        T tmpObjToLoad;
        if (!Read(tmpObjToLoad)) return false;

        int64_t nStart = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());

        LogPrintf("Writing info to %s...\n", strFilename);
        if (!CoreWrite(objToSave)) return false;
        LogPrintf("%s dump finished  %dms\n", strFilename, TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) - nStart);

        return true;
    }
};


#endif // SYSCOIN_FLATDATABASE_H
