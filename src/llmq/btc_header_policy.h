// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_BTC_HEADER_POLICY_H
#define SYSCOIN_LLMQ_BTC_HEADER_POLICY_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

class UniValue;

namespace llmq::pq {

inline constexpr int64_t DEFAULT_BTC_HEADER_MIN_CONFIRMATIONS{1};
inline constexpr int64_t DEFAULT_BTC_HEADER_TIP_MAX_AGE{2 * 60 * 60};
inline constexpr int64_t DEFAULT_BTC_HEADER_MAX_LAG_BLOCKS{36};
inline constexpr int64_t DEFAULT_BTC_HEADER_RECENT_FORK_DEPTH{2};
inline constexpr int64_t DEFAULT_BTC_HEADER_COMMAND_TIMEOUT{10};
inline constexpr std::size_t MAX_BTC_HEADER_COMMAND_OUTPUT{1024 * 1024};

struct BTCHeaderPolicyConfig {
    std::string expected_chain;
    int64_t min_confirmations{DEFAULT_BTC_HEADER_MIN_CONFIRMATIONS};
    int64_t tip_max_age{DEFAULT_BTC_HEADER_TIP_MAX_AGE};
    int64_t max_lag_blocks{DEFAULT_BTC_HEADER_MAX_LAG_BLOCKS};
    int64_t recent_fork_depth{DEFAULT_BTC_HEADER_RECENT_FORK_DEPTH};

    [[nodiscard]] bool IsValid() const noexcept;
};

struct BTCHeaderPolicyResult {
    uint256 btc_hash;
    int32_t btc_height{-1};
    int64_t confirmations{0};
    bool previous_was_reorged{false};
};

/** One fresh Bitcoin view binding the K anchor to its H+37 descendant. */
struct BTCHeaderActiveRange {
    uint256 anchor_hash;
    int32_t anchor_height{-1};
    uint256 future_hash;
    int32_t future_height{-1};
};

/**
 * Execute one fixed Bitcoin RPC method. Implementations must not invoke a
 * shell. The configured implementation also bounds runtime and output size.
 */
using BTCHeaderCommandRunner = std::function<bool(
    const std::vector<std::string>& method_and_args,
    UniValue& result,
    std::string& error)>;

class BTCHeaderPolicy {
public:
    explicit BTCHeaderPolicy(BTCHeaderCommandRunner runner);

    /** Select an active Bitcoin hash with the configured confirmation depth. */
    [[nodiscard]] std::optional<BTCHeaderPolicyResult> SelectMiningHash(
        const BTCHeaderPolicyConfig& config,
        int64_t now,
        std::string& deny_reason) const;

    /**
     * Validate the exact BTCPREV committed by a scheduled Syscoin candidate.
     * The previous hash is the quorum-certified cursor, not local miner state.
     */
    [[nodiscard]] std::optional<BTCHeaderPolicyResult> CheckCandidate(
        const BTCHeaderPolicyConfig& config,
        const uint256& candidate_hash,
        const std::optional<uint256>& previous_hash,
        int64_t now,
        std::string& deny_reason) const;

    /**
     * Recheck a previously accepted K anchor and select the exact active
     * H+37 hash from one fresh tip/fork view. The anchor's audit lag cap is
     * enforced when K is signed; at B it is necessarily older than that cap.
     */
    [[nodiscard]] std::optional<BTCHeaderActiveRange>
    CheckPaymentAuditActiveRange(
        const BTCHeaderPolicyConfig& config,
        const uint256& anchor_hash,
        int64_t now,
        std::string& deny_reason) const;

private:
    BTCHeaderCommandRunner m_runner;
};

/** Local policy is opt-in on mine-on-demand networks and always on otherwise. */
[[nodiscard]] bool IsBTCHeaderPolicyEnabled();

/** Whether this binary contains the bounded argv process runner. */
[[nodiscard]] bool BTCHeaderCommandSupportAvailable() noexcept;

/** Read and range-check local policy settings. */
[[nodiscard]] std::optional<BTCHeaderPolicyConfig>
GetConfiguredBTCHeaderPolicy(std::string& error);

/** Execute the configured -btcheadercmd/-btcheaderarg argv backend. */
[[nodiscard]] bool RunConfiguredBTCHeaderCommand(
    const std::vector<std::string>& method_and_args,
    UniValue& result,
    std::string& error);

/** Construct a policy backed by the local node's independently configured RPC. */
[[nodiscard]] BTCHeaderPolicy MakeConfiguredBTCHeaderPolicy();

/** Ask the dedicated managed Bitcoin process to stop using bounded argv I/O. */
[[nodiscard]] bool RequestManagedBTCHeaderStop(std::string& error);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_BTC_HEADER_POLICY_H
