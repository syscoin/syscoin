// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_GETH_STARTUP_H
#define SYSCOIN_NODE_GETH_STARTUP_H

#include <util/fs.h>
#include <util/syserror.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

#ifndef WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace node {

// Preserve keys in place. An old copy/restore attempt may have left its only
// complete key set in a temporary path; neither path establishes authority.
inline bool PrepareGethDataDirectory(const fs::path& data_dir, bool reindex, std::string& error,
                                    std::function<bool()> stop_owner = {},
                                    std::chrono::milliseconds shutdown_timeout = std::chrono::seconds{40})
{
    error.clear();
    try {
        for (const auto* name : {"keystoretmp", "nodekeytmp"}) {
            const auto backup = data_dir / name;
            if (fs::symlink_status(backup).type() != fs::file_type::not_found) {
                error = "Geth key backup requires manual recovery: " + fs::PathToString(backup) +
                    ". Original and backup key files were left untouched.";
                return false;
            }
        }
        if (!reindex && !stop_owner) return true;
#ifdef WIN32
        error = "Managed Geth startup is not supported on WIN32 builds";
        return false;
#else
        const auto geth_dir = data_dir / "geth";
        // Refuse ambiguous directory aliases before deleting any chain data.
        for (const auto& dir : {geth_dir, geth_dir / "geth"}) {
            const auto status = fs::symlink_status(dir);
            if (status.type() != fs::file_type::not_found && !fs::is_directory(status)) {
                error = "Managed Geth requires a directory at " + fs::PathToString(dir);
                return false;
            }
        }
        const auto instance_dir = geth_dir / "geth";
        fs::create_directories(instance_dir);
        const auto lock_path = instance_dir / "LOCK";
        // Geth's gofrs/flock uses flock, not Core's fcntl FileLock. Keep the
        // same lock inode and hold ownership until both removals finish.
        struct InstanceLock {
            const int fd;
            ~InstanceLock() { if (fd >= 0) ::close(fd); }
        };
        const InstanceLock instance_lock{::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600)};
        const auto lock_error = [&](const std::string& reason) {
            error = "Unable to exclusively lock Geth database at " + fs::PathToString(lock_path) + ": " + reason;
            return false;
        };
        if (instance_lock.fd < 0) return lock_error(SysErrorString(errno));
        struct stat lock_stat{};
        if (::fstat(instance_lock.fd, &lock_stat) != 0) return lock_error(SysErrorString(errno));
        if (!S_ISREG(lock_stat.st_mode)) return lock_error("instance lock is not a regular file");
        if (::flock(instance_lock.fd, LOCK_EX | LOCK_NB) != 0) {
            const int lock_errno{errno};
            if ((lock_errno != EWOULDBLOCK && lock_errno != EAGAIN) || !stop_owner) {
                return lock_error(SysErrorString(lock_errno));
            }
            if (!stop_owner()) return lock_error("Unable to request Geth shutdown");
            const auto deadline = std::chrono::steady_clock::now() + shutdown_timeout;
            while (::flock(instance_lock.fd, LOCK_EX | LOCK_NB) != 0) {
                const int retry_errno{errno};
                if (retry_errno != EWOULDBLOCK && retry_errno != EAGAIN) return lock_error(SysErrorString(retry_errno));
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) return lock_error("Geth did not release its instance lock before the shutdown timeout");
                std::this_thread::sleep_until(std::min(deadline, now + std::chrono::milliseconds{100}));
            }
        }
        if (!reindex) return true;
        // Paired NEVM state and default ancients live in this database. Geth
        // also recognizes the older location directly below its data directory.
        fs::remove_all(geth_dir / "geth" / "chaindata");
        fs::remove_all(geth_dir / "chaindata");
        return true;
#endif
    } catch (const fs::filesystem_error& e) {
        error = "Unable to prepare Geth data directory: " + std::string{e.what()};
        return false;
    }
}

class GethStartupWaitState
{
public:
    using Clock = std::chrono::steady_clock;
    using Seconds = std::chrono::seconds;

    GethStartupWaitState(Clock::time_point start, Seconds normal_timeout, Seconds bootstrap_timeout)
        : m_normal_timeout{normal_timeout},
          m_bootstrap_timeout{bootstrap_timeout},
          m_normal_start{start},
          m_bootstrap_start{start},
          m_normal_deadline{start + normal_timeout},
          m_bootstrap_deadline{start + bootstrap_timeout}
    {
    }

    void Observe(bool bootstrap_status_present, bool geth_running, Clock::time_point now)
    {
        m_bootstrap_active = bootstrap_status_present && geth_running;
        if (m_bootstrap_active) {
            if (!m_bootstrap_started) {
                m_bootstrap_started = true;
                m_bootstrap_start = now;
                m_bootstrap_deadline = now + m_bootstrap_timeout;
            }
            m_bootstrap_completed = false;
        } else if (!bootstrap_status_present && geth_running && m_bootstrap_started && !m_bootstrap_completed) {
            m_bootstrap_completed = true;
            m_normal_start = now;
            m_normal_deadline = now + m_normal_timeout;
        }
    }

    bool BootstrapActive() const { return m_bootstrap_active; }

    Seconds ActiveTimeout() const
    {
        return m_bootstrap_active ? m_bootstrap_timeout : m_normal_timeout;
    }

    Seconds ActiveElapsed(Clock::time_point now) const
    {
        return std::chrono::duration_cast<Seconds>(now - (m_bootstrap_active ? m_bootstrap_start : m_normal_start));
    }

    bool Expired(Clock::time_point now) const
    {
        const Seconds timeout = ActiveTimeout();
        if (timeout == Seconds::zero()) return false;
        return now >= (m_bootstrap_active ? m_bootstrap_deadline : m_normal_deadline);
    }

private:
    const Seconds m_normal_timeout;
    const Seconds m_bootstrap_timeout;
    Clock::time_point m_normal_start;
    Clock::time_point m_bootstrap_start;
    Clock::time_point m_normal_deadline;
    Clock::time_point m_bootstrap_deadline;
    bool m_bootstrap_started{false};
    bool m_bootstrap_completed{false};
    bool m_bootstrap_active{false};
};

} // namespace node

#endif // SYSCOIN_NODE_GETH_STARTUP_H
