// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_UTIL_FS_HELPERS_H
#define SYSCOIN_UTIL_FS_HELPERS_H

#include <util/fs.h>

#ifndef WIN32
#include <sys/types.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <iosfwd>
#include <limits>
#include <optional>

/**
 * Ensure file contents are fully committed to disk, using a platform-specific
 * feature analogous to fsync().
 */
bool FileCommit(FILE* file);

/**
 * Sync directory contents. This is required on some environments to ensure that
 * newly created files are committed to disk.
 */
void DirectoryCommit(const fs::path& dirname);

bool TruncateFile(FILE* file, uint64_t length);

/** Use 64-bit file positions, including on Windows where long remains 32 bits. */
inline int FileSeek64(FILE* file, int64_t offset, int origin)
{
#ifdef WIN32
    return _fseeki64(file, offset, origin);
#else
    // Fail instead of narrowing on platforms without large-file support.
    if (offset < std::numeric_limits<off_t>::min() || offset > std::numeric_limits<off_t>::max()) {
        errno = EOVERFLOW;
        return -1;
    }
    return ::fseeko(file, static_cast<off_t>(offset), origin);
#endif
}

inline int64_t FileTell64(FILE* file)
{
#ifdef WIN32
    return _ftelli64(file);
#else
    return ::ftello(file);
#endif
}

int RaiseFileDescriptorLimit(int nMinFD);
void AllocateFileRange(FILE* file, uint64_t offset, uint64_t length);

/**
 * Rename src to dest.
 * @return true if the rename was successful.
 */
[[nodiscard]] bool RenameOver(fs::path src, fs::path dest);

namespace util {
enum class LockResult {
    Success,
    ErrorWrite,
    ErrorLock,
};
[[nodiscard]] LockResult LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only = false);
} // namespace util
void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);

/** Get the size of a file by scanning it.
 *
 * @param[in] path The file path
 * @param[in] max Stop seeking beyond this limit
 * @return The file size or max
 */
std::streampos GetFileSize(const char* path, std::streamsize max = std::numeric_limits<std::streamsize>::max());

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);
fs::path GetDefaultDataDir();

/** Convert fs::perms to symbolic string of the form 'rwxrwxrwx'
 *
 * @param[in] p the perms to be converted
 * @return Symbolic permissions string
 */
std::string PermsToSymbolicString(fs::perms p);
/** Interpret a custom permissions level string as fs::perms
 *
 * @param[in] s Permission level string
 * @return Permissions as fs::perms
 */
std::optional<fs::perms> InterpretPermString(const std::string& s);

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif // SYSCOIN_UTIL_FS_HELPERS_H
