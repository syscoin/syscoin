// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_GETH_STARTUP_H
#define SYSCOIN_NODE_GETH_STARTUP_H

#include <chrono>

namespace node {

class GethStartupWaitState
{
public:
    using Clock = std::chrono::steady_clock;
    using Seconds = std::chrono::seconds;

    GethStartupWaitState(Clock::time_point start, Seconds normal_timeout, Seconds bootstrap_timeout)
        : m_normal_timeout{normal_timeout},
          m_bootstrap_timeout{bootstrap_timeout},
          m_normal_deadline{start + normal_timeout},
          m_bootstrap_deadline{start + bootstrap_timeout}
    {
    }

    void Observe(bool bootstrap_status_present, bool geth_running, Clock::time_point now)
    {
        m_bootstrap_active = bootstrap_status_present && geth_running;
        if (m_bootstrap_active && !m_bootstrap_started) {
            m_bootstrap_started = true;
            m_bootstrap_deadline = now + m_bootstrap_timeout;
        } else if (!bootstrap_status_present && geth_running && m_bootstrap_started && !m_bootstrap_completed) {
            m_bootstrap_completed = true;
            m_normal_deadline = now + m_normal_timeout;
        }
    }

    bool BootstrapActive() const { return m_bootstrap_active; }

    Seconds ActiveTimeout() const
    {
        return m_bootstrap_active ? m_bootstrap_timeout : m_normal_timeout;
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
    Clock::time_point m_normal_deadline;
    Clock::time_point m_bootstrap_deadline;
    bool m_bootstrap_started{false};
    bool m_bootstrap_completed{false};
    bool m_bootstrap_active{false};
};

} // namespace node

#endif // SYSCOIN_NODE_GETH_STARTUP_H
