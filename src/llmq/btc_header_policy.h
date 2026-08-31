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

class BTCHeaderPolicy;
class PQChainLockPersistence;

/** Proof that one exact durable Bitcoin anchor is stably inactive. */
class BTCRecoveryPrecommitRolloverProof final {
public:
    BTCRecoveryPrecommitRolloverProof(
        const BTCRecoveryPrecommitRolloverProof&) = default;
    BTCRecoveryPrecommitRolloverProof(
        BTCRecoveryPrecommitRolloverProof&&) = default;
    BTCRecoveryPrecommitRolloverProof& operator=(
        const BTCRecoveryPrecommitRolloverProof&) = default;
    BTCRecoveryPrecommitRolloverProof& operator=(
        BTCRecoveryPrecommitRolloverProof&&) = default;

    [[nodiscard]] const uint256& AnchorHash() const noexcept
    {
        return m_anchor_hash;
    }
    [[nodiscard]] int32_t AnchorHeight() const noexcept
    {
        return m_anchor_height;
    }
    [[nodiscard]] const uint256& ReplacementHash() const noexcept
    {
        return m_replacement_hash;
    }
    [[nodiscard]] int32_t ReplacementHeight() const noexcept
    {
        return m_replacement_height;
    }
    [[nodiscard]] const uint256& ObservedActiveHash() const noexcept
    {
        return m_observed_active_hash;
    }
    [[nodiscard]] const uint256& StableTipHash() const noexcept
    {
        return m_stable_tip_hash;
    }
    [[nodiscard]] int32_t StableTipHeight() const noexcept
    {
        return m_stable_tip_height;
    }
    [[nodiscard]] int64_t RequiredMaturityHeight() const noexcept
    {
        return m_required_maturity_height;
    }

private:
    class IssuerKey final {
    private:
        friend class BTCHeaderPolicy;
        IssuerKey() = default;
    };

    friend class BTCHeaderPolicy;
    friend class PQChainLockPersistence;

    BTCRecoveryPrecommitRolloverProof(
        IssuerKey,
        uint256 anchor_hash,
        int32_t anchor_height,
        uint256 replacement_hash,
        int32_t replacement_height,
        std::optional<uint256> previous_hash,
        uint256 rollover_context_id,
        uint256 observed_active_hash,
        uint256 stable_tip_hash,
        int32_t stable_tip_height,
        int64_t required_maturity_height);

    [[nodiscard]] bool Authorizes(
        const uint256& anchor_hash,
        int32_t anchor_height,
        const uint256& replacement_hash,
        int32_t replacement_height,
        const std::optional<uint256>& previous_hash,
        const uint256& rollover_context_id) const noexcept;

    uint256 m_anchor_hash;
    int32_t m_anchor_height{-1};
    uint256 m_replacement_hash;
    int32_t m_replacement_height{-1};
    std::optional<uint256> m_previous_hash;
    uint256 m_rollover_context_id;
    uint256 m_observed_active_hash;
    uint256 m_stable_tip_hash;
    int32_t m_stable_tip_height{-1};
    int64_t m_required_maturity_height{-1};
};

enum class BTCHeaderActiveRangeStatus : uint8_t {
    READY = 0,
    WAITING,
    STABLE_ANCHOR_INACTIVE,
    TRANSIENT,
};

struct BTCHeaderActiveRangeCheck {
    BTCHeaderActiveRangeStatus status{BTCHeaderActiveRangeStatus::TRANSIENT};
    std::optional<BTCHeaderActiveRange> range;
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

    /**
     * Classify an exact durable anchor using one stable Bitcoin tip view.
     * Only STABLE_ANCHOR_INACTIVE may authorize replacement of unsigned local
     * PENDING state; every other non-READY result is non-mutating.
     */
    [[nodiscard]] BTCHeaderActiveRangeCheck
    ClassifyPaymentAuditActiveRange(
        const BTCHeaderPolicyConfig& config,
        const uint256& anchor_hash,
        int32_t expected_anchor_height,
        int64_t now,
        std::string& deny_reason) const;

    /**
     * Bind one exact inactive durable anchor and its exact active replacement
     * to the same repeated Bitcoin tip/fork view. The opaque result is the
     * only capability accepted by the later-epoch persistence CAS.
     */
    [[nodiscard]] std::optional<
        BTCRecoveryPrecommitRolloverProof>
    AuthorizeStableInactiveAnchorReplacement(
        const BTCHeaderPolicyConfig& config,
        const uint256& anchor_hash,
        int32_t expected_anchor_height,
        const uint256& replacement_hash,
        const std::optional<uint256>& previous_hash,
        const uint256& rollover_context_id,
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
