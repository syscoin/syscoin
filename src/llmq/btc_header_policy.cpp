// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/syscoin-config.h>
#endif

#include <llmq/btc_header_policy.h>

#include <llmq/pq_payment_audit.h>
#include <llmq/pq_roster_beacon.h>

#include <chainparams.h>
#include <common/args.h>
#include <node/btcheader_state.h> // SYSCOIN: avoid importing validation into Bitcoin policy.
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>

#if defined(HAVE_BOOST_PROCESS)
#include <boost/version.hpp>
#if BOOST_VERSION >= 108800
#include <boost/process/v1/args.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/exe.hpp>
#include <boost/process/v1/group.hpp>
#include <boost/process/v1/io.hpp>
#include <boost/process/v1/pipe.hpp>
#else
#include <boost/process.hpp>
#endif
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace llmq::pq {
namespace {

static_assert(PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA ==
              ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA);
static_assert(PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS ==
              ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS);

constexpr int64_t MAX_BTC_HEADER_COMMAND_TIMEOUT{60};
constexpr int64_t MAX_BTC_HEADER_FUTURE_TIME{2 * 60 * 60};
constexpr std::size_t MAX_BTC_HEADER_BASE_ARGS{64};
constexpr std::size_t MAX_BTC_HEADER_ARG_SIZE{4096};
#if defined(HAVE_BOOST_PROCESS)
constexpr std::size_t MAX_BTC_HEADER_ERROR_DETAIL{4096};
#endif

struct TipView {
    uint256 hash;
    int64_t height{-1};
    int64_t time{0};
};

struct HeaderView {
    uint256 hash;
    int64_t height{-1};
    int64_t confirmations{0};
};

void SetError(std::string& error, const std::string& value)
{
    error = value;
}

bool ParseHash(const UniValue& value, uint256& out)
{
    if (!value.isStr()) return false;
    const std::string encoded{value.get_str()};
    if (encoded.size() != 64 || !IsHex(encoded)) return false;
    out.SetHex(encoded);
    return !out.IsNull();
}

bool ParseInt64(const UniValue& object, const char* key, int64_t& out)
{
    if (!object.isObject()) return false;
    const UniValue& value{object.find_value(key)};
    if (!value.isNum()) return false;
    try {
        out = value.getInt<int64_t>();
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool IsAllowedMethod(const std::vector<std::string>& method_and_args)
{
    if (method_and_args.empty()) return false;
    const std::string& method{method_and_args.front()};
    if ((method == "getblockchaininfo" || method == "getchaintips" ||
         method == "getnetworkinfo") &&
        method_and_args.size() == 1) {
        return true;
    }
    if (method == "getblockhash" && method_and_args.size() == 2) {
        int64_t height{-1};
        return ::ParseInt64(method_and_args[1], &height) && height >= 0 &&
               height <= std::numeric_limits<int32_t>::max();
    }
    if (method == "getblockheader" && method_and_args.size() == 3 &&
        method_and_args[2] == "true") {
        const std::string& hash{method_and_args[1]};
        return hash.size() == 64 && IsHex(hash) &&
               hash.find_first_not_of('0') != std::string::npos;
    }
    return false;
}

#if defined(HAVE_BOOST_PROCESS)
bool ParseCommandResult(const std::string& output,
                        bool raw_hash,
                        UniValue& result,
                        std::string& error)
{
    const std::string trimmed{TrimString(output)};
    if (raw_hash) {
        UniValue hash_value;
        if (trimmed.size() == 64 && IsHex(trimmed)) {
            hash_value.setStr(trimmed);
            result = std::move(hash_value);
            return true;
        }
        if (hash_value.read(trimmed) && hash_value.isStr()) {
            uint256 parsed;
            if (ParseHash(hash_value, parsed)) {
                result = std::move(hash_value);
                return true;
            }
        }
        SetError(error, "btc-getblockhash-invalid-output");
        return false;
    }

    UniValue parsed;
    if (!parsed.read(trimmed)) {
        SetError(error, "btc-rpc-invalid-json");
        return false;
    }
    result = std::move(parsed);
    return true;
}

#if BOOST_VERSION >= 108800
namespace bp = boost::process::v1;
#else
namespace bp = boost::process;
#endif

void ReadBounded(bp::ipstream& stream,
                 std::string& output,
                 std::atomic_bool& oversized)
{
    std::array<char, 4096> buffer{};
    while (stream.good()) {
        stream.read(buffer.data(), buffer.size());
        const std::streamsize count{stream.gcount()};
        if (count <= 0) break;
        const std::size_t available{
            output.size() < MAX_BTC_HEADER_COMMAND_OUTPUT
                ? MAX_BTC_HEADER_COMMAND_OUTPUT - output.size()
                : 0};
        const std::size_t append_count{
            std::min<std::size_t>(available, static_cast<std::size_t>(count))};
        output.append(buffer.data(), append_count);
        if (append_count != static_cast<std::size_t>(count)) {
            oversized.store(true);
        }
    }
}

// SYSCOIN: Boost.Process v1's timed wait is deprecated as unreliable. Polling
// the non-blocking child status uses the same portable process handle while
// keeping the timeout on a monotonic clock.
bool WaitForExitBounded(bp::child& process,
                        std::chrono::seconds timeout)
{
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (true) {
        std::error_code status_error;
        if (!process.running(status_error)) {
            if (status_error) {
                throw std::system_error{status_error,
                                        "Bitcoin header child status"};
            }
            return true;
        }
        const auto now{std::chrono::steady_clock::now()};
        if (now >= deadline) return false;
        std::this_thread::sleep_until(std::min(
            deadline, now + std::chrono::milliseconds{10}));
    }
}

// SYSCOIN: Always kill the whole process group first so descendants cannot
// retain the captured pipes, then kill/reap the direct child as a fallback.
void TerminateAndReap(bp::group& process_group,
                      bp::child& process) noexcept
{
    std::error_code ignored;
    process_group.terminate(ignored);
    ignored.clear();
    if (process.running(ignored)) {
        ignored.clear();
        process.terminate(ignored);
    }
    ignored.clear();
    process.wait(ignored);
}

bool RunBoundedCommand(const std::vector<std::string>& command,
                       int64_t timeout_seconds,
                       std::string& output,
                       std::string& error)
{
    if (command.empty()) {
        SetError(error, "btcheadercmd-not-set");
        return false;
    }
    std::vector<std::string> args;
    args.assign(command.begin() + 1, command.end());

    bp::ipstream stdout_stream;
    bp::ipstream stderr_stream;
    try {
        bp::group process_group;
        bp::child process(
            bp::exe = command.front(), bp::args = args,
            bp::std_out > stdout_stream, bp::std_err > stderr_stream,
            process_group);
        std::string stderr_output;
        std::atomic_bool oversized{false};
        std::thread stdout_reader;
        std::thread stderr_reader;
        bool exited{false};
        try {
            stdout_reader = std::thread{
                ReadBounded, std::ref(stdout_stream), std::ref(output),
                std::ref(oversized)};
            stderr_reader = std::thread{
                ReadBounded, std::ref(stderr_stream),
                std::ref(stderr_output), std::ref(oversized)};
            exited = WaitForExitBounded(
                process, std::chrono::seconds{timeout_seconds});
            if (!exited) {
                TerminateAndReap(process_group, process);
            }
        } catch (...) {
            TerminateAndReap(process_group, process);
            if (stdout_reader.joinable()) stdout_reader.join();
            if (stderr_reader.joinable()) stderr_reader.join();
            throw;
        }
        // A command must not leave descendants holding the captured pipes
        // open after its direct child exits.
        {
            std::error_code ignored;
            process_group.terminate(ignored);
        }
        if (stdout_reader.joinable()) stdout_reader.join();
        if (stderr_reader.joinable()) stderr_reader.join();

        if (!exited) {
            SetError(error, "btcheadercmd-timeout");
            return false;
        }
        if (oversized.load()) {
            SetError(error, "btcheadercmd-output-too-large");
            return false;
        }
        if (process.exit_code() != 0) {
            if (stderr_output.size() > MAX_BTC_HEADER_ERROR_DETAIL) {
                stderr_output.resize(MAX_BTC_HEADER_ERROR_DETAIL);
            }
            SetError(error,
                     strprintf("btcheadercmd-exit-%d: %s",
                               process.exit_code(), stderr_output));
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        SetError(error, strprintf("btcheadercmd-failed: %s", e.what()));
        return false;
    }
}
#endif

bool QueryHeader(const BTCHeaderCommandRunner& runner,
                 const uint256& requested_hash,
                 HeaderView& header,
                 std::string& error)
{
    UniValue result;
    if (!runner({"getblockheader", requested_hash.GetHex(), "true"},
                result, error)) {
        return false;
    }
    if (!result.isObject() ||
        !ParseHash(result.find_value("hash"), header.hash) ||
        header.hash != requested_hash ||
        !ParseInt64(result, "height", header.height) ||
        !ParseInt64(result, "confirmations", header.confirmations) ||
        header.height < 0 ||
        header.height > std::numeric_limits<int32_t>::max()) {
        SetError(error, "btc-header-invalid-response");
        return false;
    }
    return true;
}

bool CheckRecentForks(const BTCHeaderCommandRunner& runner,
                      const TipView& tip,
                      int64_t recent_fork_depth,
                      std::string& error)
{
    if (recent_fork_depth == 0) return true;

    UniValue result;
    if (!runner({"getchaintips"}, result, error)) return false;
    if (!result.isArray()) {
        SetError(error, "btc-chaintips-not-array");
        return false;
    }

    bool found_active{false};
    for (const UniValue& value : result.getValues()) {
        if (!value.isObject() || !value.find_value("status").isStr()) {
            SetError(error, "btc-chaintips-invalid-entry");
            return false;
        }
        uint256 hash;
        int64_t height{-1};
        if (!ParseHash(value.find_value("hash"), hash) ||
            !ParseInt64(value, "height", height) || height < 0 ||
            height > std::numeric_limits<int32_t>::max()) {
            SetError(error, "btc-chaintips-invalid-entry");
            return false;
        }
        const std::string status{value.find_value("status").get_str()};
        if (status == "active") {
            if (found_active || hash != tip.hash || height != tip.height) {
                SetError(error, "btc-chaintips-active-mismatch");
                return false;
            }
            found_active = true;
            continue;
        }
        if (status == "invalid") continue;
        if (status != "valid-fork" && status != "valid-headers" &&
            status != "headers-only") {
            SetError(error, "btc-chaintips-unknown-status");
            return false;
        }
        if (height >= tip.height - recent_fork_depth) {
            SetError(error,
                     strprintf("btc-recent-fork(status=%s height=%d tip=%d depth=%d)",
                               status, height, tip.height,
                               recent_fork_depth));
            return false;
        }
    }
    if (!found_active) {
        SetError(error, "btc-chaintips-missing-active");
        return false;
    }
    return true;
}

bool QueryTip(const BTCHeaderCommandRunner& runner,
              const BTCHeaderPolicyConfig& config,
              int64_t now,
              TipView& tip,
              std::string& error)
{
    UniValue chain_info;
    if (!runner({"getblockchaininfo"}, chain_info, error)) return false;
    if (!chain_info.isObject()) {
        SetError(error, "btc-chaininfo-not-object");
        return false;
    }
    const UniValue& chain{chain_info.find_value("chain")};
    const UniValue& ibd{chain_info.find_value("initialblockdownload")};
    if (!chain.isStr() || chain.get_str() != config.expected_chain) {
        SetError(error, "btc-chaininfo-wrong-chain");
        return false;
    }
    if (!ibd.isBool()) {
        SetError(error, "btc-chaininfo-missing-ibd");
        return false;
    }
    if (ibd.get_bool()) {
        SetError(error, "btc-node-ibd");
        return false;
    }
    if (!ParseHash(chain_info.find_value("bestblockhash"), tip.hash)) {
        SetError(error, "btc-chaininfo-badhash");
        return false;
    }

    UniValue best_header;
    if (!runner({"getblockheader", tip.hash.GetHex(), "true"},
                best_header, error)) {
        return false;
    }
    uint256 response_hash;
    int64_t confirmations{0};
    if (!best_header.isObject() ||
        !ParseHash(best_header.find_value("hash"), response_hash) ||
        response_hash != tip.hash ||
        !ParseInt64(best_header, "height", tip.height) ||
        !ParseInt64(best_header, "time", tip.time) ||
        !ParseInt64(best_header, "confirmations", confirmations) ||
        now < 0 || tip.height < 0 || tip.time < 0 ||
        tip.height > std::numeric_limits<int32_t>::max() ||
        confirmations < 1) {
        SetError(error, "btc-bestheader-invalid-response");
        return false;
    }
    if (tip.time > now && tip.time - now > MAX_BTC_HEADER_FUTURE_TIME) {
        SetError(error, "btc-tip-time-too-far-in-future");
        return false;
    }
    if (config.tip_max_age > 0 && now > tip.time &&
        now - tip.time > config.tip_max_age) {
        SetError(error,
                 strprintf("btc-tip-stale(age=%d)", now - tip.time));
        return false;
    }
    return CheckRecentForks(runner, tip, config.recent_fork_depth,
                            error);
}

bool QueryActiveHash(const BTCHeaderCommandRunner& runner,
                     int64_t height,
                     uint256& hash,
                     std::string& error)
{
    UniValue result;
    if (!runner({"getblockhash", strprintf("%d", height)}, result, error)) {
        return false;
    }
    if (!ParseHash(result, hash)) {
        SetError(error, "btc-getblockhash-invalid-output");
        return false;
    }
    return true;
}

std::optional<BTCHeaderPolicyResult> CheckCandidateWithTip(
    const BTCHeaderCommandRunner& runner,
    const BTCHeaderPolicyConfig& config,
    const TipView& tip,
    const uint256& candidate_hash,
    const std::optional<uint256>& previous_hash,
    std::string& error)
{
    if (candidate_hash.IsNull()) {
        SetError(error, "btc-candidate-null");
        return std::nullopt;
    }

    HeaderView candidate;
    if (!QueryHeader(runner, candidate_hash, candidate, error)) {
        if (error.empty()) SetError(error, "btc-candidate-header-failed");
        return std::nullopt;
    }
    if (candidate.confirmations < config.min_confirmations) {
        SetError(error,
                 strprintf("btc-candidate-unconfirmed(confirmations=%d min=%d)",
                           candidate.confirmations,
                           config.min_confirmations));
        return std::nullopt;
    }
    if (candidate.height > tip.height) {
        SetError(error, "btc-candidate-height-ahead-of-tip");
        return std::nullopt;
    }
    uint256 active_candidate_hash;
    if (!QueryActiveHash(runner, candidate.height, active_candidate_hash,
                         error)) {
        return std::nullopt;
    }
    if (active_candidate_hash != candidate_hash) {
        SetError(error, "btc-candidate-not-active-chain");
        return std::nullopt;
    }
    const int64_t lag{tip.height - candidate.height};
    if (config.max_lag_blocks > 0 && lag > config.max_lag_blocks) {
        SetError(error,
                 strprintf("btc-candidate-too-old(lag=%d max=%d)",
                           lag, config.max_lag_blocks));
        return std::nullopt;
    }

    bool previous_was_reorged{false};
    if (previous_hash && !previous_hash->IsNull() &&
        *previous_hash != candidate_hash) {
        HeaderView previous;
        if (!QueryHeader(runner, *previous_hash, previous, error)) {
            if (error.empty()) SetError(error, "btc-previous-header-failed");
            return std::nullopt;
        }
        if (candidate.height < previous.height) {
            SetError(error,
                     strprintf("btc-non-monotonic-height(prev=%d cand=%d)",
                               previous.height, candidate.height));
            return std::nullopt;
        }
        uint256 active_at_previous_height;
        if (!QueryActiveHash(runner, previous.height,
                             active_at_previous_height, error)) {
            return std::nullopt;
        }
        previous_was_reorged = active_at_previous_height != *previous_hash;
        if (!previous_was_reorged && candidate.height == previous.height) {
            SetError(error, "btc-same-height-different-active-hash");
            return std::nullopt;
        }
    }

    error.clear();
    return BTCHeaderPolicyResult{
        candidate_hash, static_cast<int32_t>(candidate.height),
        candidate.confirmations, previous_was_reorged};
}

bool IsSameTip(const TipView& first, const TipView& second) noexcept
{
    return first.hash == second.hash && first.height == second.height;
}

struct StableInactiveAnchorFacts {
    uint256 anchor_hash;
    int32_t anchor_height{-1};
    uint256 observed_active_hash;
    uint256 stable_tip_hash;
    int32_t stable_tip_height{-1};
    int64_t required_maturity_height{-1};
};

struct ActiveRangeCheckInternal {
    BTCHeaderActiveRangeStatus status{BTCHeaderActiveRangeStatus::TRANSIENT};
    std::optional<BTCHeaderActiveRange> range;
    std::optional<StableInactiveAnchorFacts> stable_inactive;
};

ActiveRangeCheckInternal CheckPaymentAuditActiveRangeImpl(
    const BTCHeaderCommandRunner& runner,
    const BTCHeaderPolicyConfig& config,
    const uint256& anchor_hash,
    const std::optional<int32_t>& expected_anchor_height,
    int64_t now,
    std::string& deny_reason)
{
    const auto transient = [&]() {
        return ActiveRangeCheckInternal{
            BTCHeaderActiveRangeStatus::TRANSIENT, std::nullopt,
            std::nullopt};
    };
    const auto waiting = [&]() {
        return ActiveRangeCheckInternal{
            BTCHeaderActiveRangeStatus::WAITING, std::nullopt,
            std::nullopt};
    };

    deny_reason.clear();
    if (!config.IsValid() || !runner || anchor_hash.IsNull() ||
        (expected_anchor_height && *expected_anchor_height < 0)) {
        SetError(deny_reason, "btc-policy-invalid-audit-range");
        return transient();
    }

    TipView first_tip;
    if (!QueryTip(runner, config, now, first_tip, deny_reason)) {
        return transient();
    }

    HeaderView anchor;
    if (!QueryHeader(runner, anchor_hash, anchor, deny_reason)) {
        if (deny_reason.empty()) {
            SetError(deny_reason, "btc-audit-anchor-header-failed");
        }
        return transient();
    }
    if (anchor.height > first_tip.height ||
        (expected_anchor_height &&
         anchor.height != *expected_anchor_height)) {
        SetError(deny_reason, "btc-audit-anchor-height-mismatch");
        return transient();
    }

    uint256 first_active_anchor;
    if (!QueryActiveHash(runner, anchor.height, first_active_anchor,
                         deny_reason)) {
        return transient();
    }
    if (first_active_anchor.IsNull()) {
        SetError(deny_reason, "btc-audit-active-anchor-null");
        return transient();
    }

    const auto finish_stable_view = [&](const uint256& first_future,
                                        bool require_future)
        -> std::optional<bool> {
        uint256 second_active_anchor;
        if (!QueryActiveHash(runner, anchor.height, second_active_anchor,
                             deny_reason)) {
            return std::nullopt;
        }
        uint256 second_future;
        if (require_future &&
            !QueryActiveHash(runner,
                             anchor.height +
                                 PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA,
                             second_future, deny_reason)) {
            return std::nullopt;
        }
        TipView final_tip;
        if (!QueryTip(runner, config, now, final_tip, deny_reason)) {
            return std::nullopt;
        }
        if (!IsSameTip(first_tip, final_tip)) {
            SetError(deny_reason, "btc-audit-tip-view-changed");
            return false;
        }
        if (second_active_anchor != first_active_anchor ||
            (require_future && second_future != first_future)) {
            SetError(deny_reason, "btc-audit-active-view-changed");
            return false;
        }
        return true;
    };

    if (first_active_anchor != anchor_hash) {
        if (anchor.height >
            std::numeric_limits<int32_t>::max() -
                static_cast<int64_t>(
                    PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA) -
                static_cast<int64_t>(
                    PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS - 1)) {
            SetError(deny_reason,
                     "btc-audit-inactive-anchor-maturity-overflow");
            return transient();
        }
        const auto stable{finish_stable_view({}, /*require_future=*/false)};
        if (!stable || !*stable) return transient();

        const int64_t stable_inactive_height{
            anchor.height + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA +
            PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS - 1};
        if (first_tip.height < stable_inactive_height) {
            SetError(
                deny_reason,
                strprintf("btc-audit-inactive-anchor-immature(tip=%d required=%d)",
                          first_tip.height, stable_inactive_height));
            return waiting();
        }
        SetError(deny_reason, "btc-audit-anchor-not-active-chain");
        return ActiveRangeCheckInternal{
            BTCHeaderActiveRangeStatus::STABLE_ANCHOR_INACTIVE,
            std::nullopt,
            StableInactiveAnchorFacts{
                anchor_hash, static_cast<int32_t>(anchor.height),
                first_active_anchor, first_tip.hash,
                static_cast<int32_t>(first_tip.height),
                stable_inactive_height}};
    }

    if (anchor.confirmations != first_tip.height - anchor.height + 1) {
        SetError(deny_reason, "btc-audit-anchor-tip-inconsistent");
        return transient();
    }
    if (anchor.height >
        std::numeric_limits<int32_t>::max() -
            static_cast<int64_t>(PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA)) {
        SetError(deny_reason, "btc-audit-future-height-overflow");
        return transient();
    }
    const int64_t future_height{
        anchor.height + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA};
    const int64_t minimum_confirmations{
        std::max<int64_t>(config.min_confirmations,
                          PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS)};
    if (first_tip.height < future_height + minimum_confirmations - 1) {
        const auto stable{finish_stable_view({}, /*require_future=*/false)};
        if (!stable || !*stable) return transient();
        SetError(deny_reason,
                 strprintf("btc-audit-future-unconfirmed(tip=%d future=%d min=%d)",
                           first_tip.height, future_height,
                           minimum_confirmations));
        return waiting();
    }

    uint256 first_future;
    if (!QueryActiveHash(runner, future_height, first_future, deny_reason)) {
        return transient();
    }
    HeaderView future;
    if (!QueryHeader(runner, first_future, future, deny_reason)) {
        if (deny_reason.empty()) {
            SetError(deny_reason, "btc-audit-future-header-failed");
        }
        return transient();
    }
    if (future.hash != first_future || future.height != future_height ||
        future.confirmations != first_tip.height - future_height + 1 ||
        future.confirmations < minimum_confirmations) {
        SetError(deny_reason, "btc-audit-future-tip-inconsistent");
        return transient();
    }

    const auto stable{finish_stable_view(first_future,
                                         /*require_future=*/true)};
    if (!stable || !*stable) return transient();

    deny_reason.clear();
    return ActiveRangeCheckInternal{
        BTCHeaderActiveRangeStatus::READY,
        BTCHeaderActiveRange{
            anchor_hash, static_cast<int32_t>(anchor.height), first_future,
            static_cast<int32_t>(future_height)},
        std::nullopt};
}

} // namespace

bool BTCHeaderPolicyConfig::IsValid() const noexcept
{
    return (expected_chain == "main" || expected_chain == "test" ||
            expected_chain == "signet" || expected_chain == "regtest") &&
           min_confirmations >= 1 &&
           min_confirmations <= std::numeric_limits<int32_t>::max() &&
           tip_max_age >= 0 &&
           max_lag_blocks >= 0 &&
           max_lag_blocks <= std::numeric_limits<int32_t>::max() &&
           recent_fork_depth >= 0 &&
           recent_fork_depth <= std::numeric_limits<int32_t>::max() &&
           (max_lag_blocks == 0 ||
            max_lag_blocks >= min_confirmations - 1);
}

BTCHeaderPolicy::BTCHeaderPolicy(BTCHeaderCommandRunner runner)
    : m_runner{std::move(runner)}
{
}

std::optional<BTCHeaderPolicyResult> BTCHeaderPolicy::SelectMiningHash(
    const BTCHeaderPolicyConfig& config,
    int64_t now,
    std::string& deny_reason) const
{
    deny_reason.clear();
    if (!config.IsValid() || !m_runner) {
        SetError(deny_reason, "btc-policy-invalid-config");
        return std::nullopt;
    }
    TipView tip;
    if (!QueryTip(m_runner, config, now, tip, deny_reason)) {
        return std::nullopt;
    }
    const int64_t selected_height{tip.height - config.min_confirmations + 1};
    if (selected_height < 0) {
        SetError(deny_reason, "btc-insufficient-chain-height");
        return std::nullopt;
    }
    uint256 selected_hash{tip.hash};
    if (selected_height != tip.height &&
        !QueryActiveHash(m_runner, selected_height, selected_hash,
                         deny_reason)) {
        return std::nullopt;
    }
    return CheckCandidateWithTip(m_runner, config, tip, selected_hash,
                                 std::nullopt, deny_reason);
}

std::optional<BTCHeaderPolicyResult> BTCHeaderPolicy::CheckCandidate(
    const BTCHeaderPolicyConfig& config,
    const uint256& candidate_hash,
    const std::optional<uint256>& previous_hash,
    int64_t now,
    std::string& deny_reason) const
{
    deny_reason.clear();
    if (!config.IsValid() || !m_runner) {
        SetError(deny_reason, "btc-policy-invalid-config");
        return std::nullopt;
    }
    TipView tip;
    if (!QueryTip(m_runner, config, now, tip, deny_reason)) {
        return std::nullopt;
    }
    return CheckCandidateWithTip(m_runner, config, tip, candidate_hash,
                                 previous_hash, deny_reason);
}

std::optional<BTCHeaderActiveRange>
BTCHeaderPolicy::CheckPaymentAuditActiveRange(
    const BTCHeaderPolicyConfig& config,
    const uint256& anchor_hash,
    int64_t now,
    std::string& deny_reason) const
{
    auto checked{CheckPaymentAuditActiveRangeImpl(
        m_runner, config, anchor_hash, std::nullopt, now,
        deny_reason)};
    return checked.status == BTCHeaderActiveRangeStatus::READY
        ? std::move(checked.range)
        : std::nullopt;
}

BTCHeaderActiveRangeCheck
BTCHeaderPolicy::ClassifyPaymentAuditActiveRange(
    const BTCHeaderPolicyConfig& config,
    const uint256& anchor_hash,
    int32_t expected_anchor_height,
    int64_t now,
    std::string& deny_reason) const
{
    auto checked{CheckPaymentAuditActiveRangeImpl(
        m_runner, config, anchor_hash, expected_anchor_height,
        now, deny_reason)};
    return BTCHeaderActiveRangeCheck{
        checked.status, std::move(checked.range)};
}

bool IsBTCHeaderPolicyEnabled()
{
    return !Params().MineBlocksOnDemand() ||
           gArgs.GetBoolArg("-btcheaderpolicyondemand", false);
}

bool BTCHeaderCommandSupportAvailable() noexcept
{
#if defined(HAVE_BOOST_PROCESS)
    return true;
#else
    return false;
#endif
}

std::optional<BTCHeaderPolicyConfig>
GetConfiguredBTCHeaderPolicy(std::string& error)
{
    BTCHeaderPolicyConfig config;
    config.expected_chain = Params().GetChainTypeString();
    config.min_confirmations = gArgs.GetIntArg(
        "-btcheaderminconfirmations",
        DEFAULT_BTC_HEADER_MIN_CONFIRMATIONS);
    config.tip_max_age = gArgs.GetIntArg(
        "-btcheadertipmaxage", DEFAULT_BTC_HEADER_TIP_MAX_AGE);
    config.max_lag_blocks = gArgs.GetIntArg(
        "-btcheadermaxlagblocks", DEFAULT_BTC_HEADER_MAX_LAG_BLOCKS);
    config.recent_fork_depth = gArgs.GetIntArg(
        "-btcheaderrecentforkdepth",
        DEFAULT_BTC_HEADER_RECENT_FORK_DEPTH);
    if (!config.IsValid()) {
        SetError(error, "btc-policy-invalid-config");
        return std::nullopt;
    }
    error.clear();
    return config;
}

bool RunConfiguredBTCHeaderCommand(
    const std::vector<std::string>& method_and_args,
    UniValue& result,
    std::string& error)
{
    error.clear();
    if (!IsAllowedMethod(method_and_args)) {
        SetError(error, "btcheadercmd-method-not-allowed");
        return false;
    }
    std::vector<std::string> command;
    if (gArgs.GetBoolArg("-btcheadermanaged", DEFAULT_BTC_HEADER_MANAGED)) {
        if (!GetManagedBTCHeaderRPCCommandArgs(command)) {
            SetError(error, "btcheader-managed-rpc-not-ready");
            return false;
        }
    } else {
        const std::string executable{gArgs.GetArg("-btcheadercmd", "")};
        if (executable.empty()) {
            SetError(error, "btcheadercmd-not-set");
            return false;
        }
        if (executable.size() > MAX_BTC_HEADER_ARG_SIZE ||
            executable.find('\0') != std::string::npos) {
            SetError(error, "btcheadercmd-invalid-executable");
            return false;
        }
        command.push_back(executable);
        const std::vector<std::string> base_args{
            gArgs.GetArgs("-btcheaderarg")};
        if (base_args.size() > MAX_BTC_HEADER_BASE_ARGS) {
            SetError(error, "btcheadercmd-too-many-args");
            return false;
        }
        for (const std::string& arg : base_args) {
            if (arg.size() > MAX_BTC_HEADER_ARG_SIZE ||
                arg.find('\0') != std::string::npos) {
                SetError(error, "btcheadercmd-invalid-arg");
                return false;
            }
            command.push_back(arg);
        }
    }
    command.insert(command.end(), method_and_args.begin(),
                   method_and_args.end());

    const int64_t timeout{gArgs.GetIntArg(
        "-btcheadercmdtimeout", DEFAULT_BTC_HEADER_COMMAND_TIMEOUT)};
    if (timeout < 1 || timeout > MAX_BTC_HEADER_COMMAND_TIMEOUT) {
        SetError(error, "btcheadercmd-invalid-timeout");
        return false;
    }

#if defined(HAVE_BOOST_PROCESS)
    std::string output;
    if (!RunBoundedCommand(command, timeout, output, error)) return false;
    return ParseCommandResult(output,
                              method_and_args.front() == "getblockhash",
                              result, error);
#else
    (void)result;
    SetError(error, "btcheadercmd-process-support-unavailable");
    return false;
#endif
}

BTCHeaderPolicy MakeConfiguredBTCHeaderPolicy()
{
    return BTCHeaderPolicy{RunConfiguredBTCHeaderCommand};
}

bool RequestManagedBTCHeaderStop(std::string& error)
{
    error.clear();
    std::vector<std::string> command;
    if (!GetManagedBTCHeaderRPCCommandArgs(command)) {
        SetError(error, "btcheader-managed-rpc-not-ready");
        return false;
    }
    command.emplace_back("stop");
#if defined(HAVE_BOOST_PROCESS)
    std::string output;
    const int64_t timeout{std::clamp<int64_t>(
        gArgs.GetIntArg("-btcheadercmdtimeout",
                        DEFAULT_BTC_HEADER_COMMAND_TIMEOUT),
        1, MAX_BTC_HEADER_COMMAND_TIMEOUT)};
    return RunBoundedCommand(command, timeout, output, error);
#else
    SetError(error, "btcheadercmd-process-support-unavailable");
    return false;
#endif
}

} // namespace llmq::pq
