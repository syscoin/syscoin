// Copyright (c) 2019-2020 The Dash Core developers
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/mnauth.h>

#include <chainparams.h>
#include <evo/deterministicmns.h>
#include <hash.h>
#include <llmq/pq_global_auth.h>
#include <llmq/quorums_utils.h>
#include <logging.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodemeta.h>
#include <masternode/masternodesync.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <random.h>
#include <timedata.h>
#include <util/time.h>
#include <util/thread.h>
#include <validation.h>
#include <version.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {

constexpr uint64_t REQUIRED_MNAUTH_SERVICES{NODE_NETWORK};

struct RegistryConnectionContext {
    const CBlockIndex* tip{nullptr};
    uint256 tip_hash;
    llmq::pq::GlobalKeyRecord local_key;
    llmq::pq::GlobalKeyRecord remote_key;
    llmq::pq::NetworkEndpoint local_endpoint;
    llmq::pq::NetworkEndpoint remote_endpoint;
    CService local_service;
    CService remote_service;
};

bool CaptureActiveTip(ChainstateManager& chainman,
                      const CBlockIndex*& tip,
                      uint256& tip_hash)
{
    tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    if (tip == nullptr) return false;
    tip_hash = tip->GetBlockHash();
    return true;
}

bool ActiveTipStillMatches(ChainstateManager& chainman,
                           const uint256& expected_tip_hash)
{
    return WITH_LOCK(chainman.GetMutex(), {
        const CBlockIndex* tip = chainman.ActiveTip();
        return tip != nullptr && tip->GetBlockHash() == expected_tip_hash;
    });
}

bool LoadRegistryConnectionContext(
    ChainstateManager& chainman,
    const CMNAuthConnectionData& connection,
    RegistryConnectionContext& context,
    std::string& error)
{
    if (!connection.IsComplete() || deterministicMNManager == nullptr ||
        !CaptureActiveTip(chainman, context.tip, context.tip_hash)) {
        error = "incomplete MNAUTH connection state or active tip unavailable";
        return false;
    }

    llmq::pq::PQRegistryReadView snapshot;
    if (!deterministicMNManager->GetPQRegistryReadView(
            context.tip, snapshot, error)) {
        return false;
    }
    if (snapshot.BlockHash() != context.tip_hash) {
        error = "PQ registry snapshot does not match the active tip";
        return false;
    }

    const auto* local_operator =
        snapshot.FindOperator(connection.local.pro_tx_hash);
    const auto* remote_operator =
        snapshot.FindOperator(connection.remote.pro_tx_hash);
    if (local_operator == nullptr || remote_operator == nullptr ||
        !local_operator->HasActiveGlobalKey() ||
        !remote_operator->HasActiveGlobalKey() ||
        !local_operator->IsStructurallyValid() ||
        !remote_operator->IsStructurallyValid() ||
        local_operator->global_key.key_version !=
            connection.local.global_key_version ||
        remote_operator->global_key.key_version !=
            connection.remote.global_key_version) {
        error = "MNAUTH identity does not match the active PQ registry";
        return false;
    }

    const CDeterministicMNList mn_list =
        deterministicMNManager->GetListForBlock(context.tip);
    if (!mn_list.IsMNValid(connection.local.pro_tx_hash) ||
        !mn_list.IsMNValid(connection.remote.pro_tx_hash)) {
        error = "MNAUTH identity is not an active deterministic masternode";
        return false;
    }
    const auto local_dmn = mn_list.GetMN(connection.local.pro_tx_hash);
    const auto remote_dmn = mn_list.GetMN(connection.remote.pro_tx_hash);
    if (!local_dmn || !remote_dmn) {
        error = "MNAUTH deterministic masternode state is missing";
        return false;
    }
    const auto local_endpoint =
        llmq::pq::MakeNetworkEndpoint(local_dmn->pdmnState->addr);
    const auto remote_endpoint =
        llmq::pq::MakeNetworkEndpoint(remote_dmn->pdmnState->addr);
    if (!local_endpoint || !remote_endpoint) {
        error = "MNAUTH deterministic service endpoint is invalid";
        return false;
    }

    context.local_key = local_operator->global_key;
    context.remote_key = remote_operator->global_key;
    context.local_endpoint = *local_endpoint;
    context.remote_endpoint = *remote_endpoint;
    context.local_service = local_dmn->pdmnState->addr;
    context.remote_service = remote_dmn->pdmnState->addr;
    return true;
}

bool LocalIdentityMatches(const CMNAuthConnectionData& connection,
                          const RegistryConnectionContext& context)
{
    uint256 pro_tx_hash;
    uint32_t key_version{0};
    llmq::pq::GlobalPublicKey public_key{};
    CService service;
    if (!GetActiveMasternodeIdentity(pro_tx_hash, key_version, public_key,
                                     service)) {
        return false;
    }
    const auto endpoint = llmq::pq::MakeNetworkEndpoint(service);
    return pro_tx_hash == connection.local.pro_tx_hash &&
           key_version == connection.local.global_key_version &&
           context.local_key.key_version == key_version &&
           context.local_key.public_key == public_key && endpoint &&
           *endpoint == context.local_endpoint;
}

void Punish(PeerManager& peerman,
            const PeerRef& peer,
            int score,
            const std::string& reason)
{
    if (peer) peerman.Misbehaving(*peer, score, reason);
}

bool IsAdmissionLimit(llmq::pq::MNAUTHVerificationError error) noexcept
{
    using Error = llmq::pq::MNAUTHVerificationError;
    return error == Error::PEER_STATE_LIMIT ||
           error == Error::REPLAY_STATE_LIMIT ||
           error == Error::RATE_STATE_LIMIT || error == Error::RATE_LIMIT ||
           error == Error::INFLIGHT_LIMIT;
}

bool BuildContextToken(CNode& node,
                       ChainstateManager& chainman,
                       CMNAuth::ContextToken& token,
                       std::string& error)
{
    const CMNAuthConnectionData connection{
        node.GetMNAuthConnectionData()};
    RegistryConnectionContext registry;
    if (!LoadRegistryConnectionContext(
            chainman, connection, registry, error) ||
        !LocalIdentityMatches(connection, registry)) {
        if (error.empty()) error = "local MNAUTH identity changed";
        return false;
    }

    token.peer_id = node.GetId();
    token.connection = connection;
    token.tip_hash = registry.tip_hash;
    token.local_key = registry.local_key;
    token.remote_key = registry.remote_key;
    token.local_endpoint = registry.local_endpoint;
    token.remote_endpoint = registry.remote_endpoint;
    token.local_service = registry.local_service;
    token.remote_service = registry.remote_service;
    token.connected_service = static_cast<CService>(node.addr);
    token.authenticated_remote_pro_tx_hash =
        node.GetVerifiedProRegTxHash();
    token.keyed_net_group = node.nKeyedNetGroup;
    token.common_version = node.GetCommonVersion();
    token.local_is_initiator = !node.IsInboundConn();
    token.masternode_connection = node.m_masternode_connection;
    token.masternode_probe_connection =
        node.m_masternode_probe_connection;
    if (!token.IsStructurallyValid()) {
        error = "invalid immutable MNAUTH context token";
        return false;
    }
    return true;
}

bool ContextStillMatches(CNode& node,
                         ChainstateManager& chainman,
                         const CMNAuth::ContextToken& expected)
{
    if (node.fDisconnect || node.GetId() != expected.peer_id ||
        node.GetCommonVersion() != expected.common_version ||
        node.nKeyedNetGroup != expected.keyed_net_group ||
        static_cast<CService>(node.addr) != expected.connected_service ||
        node.m_masternode_connection != expected.masternode_connection ||
        node.m_masternode_probe_connection !=
            expected.masternode_probe_connection ||
        node.IsInboundConn() == expected.local_is_initiator ||
        node.GetMNAuthConnectionData() != expected.connection ||
        !ActiveTipStillMatches(chainman, expected.tip_hash)) {
        return false;
    }
    CMNAuth::ContextToken current;
    std::string error;
    return BuildContextToken(node, chainman, current, error) &&
           current == expected;
}

bool HasAttributedOutboundIdentity(
    const CNode& node, const CMNAuth::ContextToken& token)
{
    return token.local_is_initiator && token.masternode_connection &&
           token.connected_service == token.remote_service &&
           static_cast<CService>(node.addr) == token.connected_service;
}

bool CompletionIsCurrent(const CNode& node,
                         const CMNAuth::Completion& completion,
                         CMNAuthPendingPhase expected_phase,
                         int64_t now_micros)
{
    const CMNAuthPendingState pending{node.GetMNAuthPending()};
    return now_micros >= 0 && now_micros < completion.deadline_micros &&
           pending.phase == expected_phase &&
           pending.deadline_micros == completion.deadline_micros;
}

bool EnqueueLocalSignature(CNode& node,
                           const CMNAuth::ContextToken& context,
                           CMNAuth::AsyncProcessor& async)
{
    const auto signer_role{
        context.local_is_initiator
            ? llmq::pq::MNAUTHSignerRole::INITIATOR
            : llmq::pq::MNAUTHSignerRole::RESPONDER};
    if (context.local_is_initiator) {
        if (!HasAttributedOutboundIdentity(node, context)) return false;
    } else if (node.GetVerifiedProRegTxHash() !=
               context.connection.remote.pro_tx_hash) {
        return false;
    }

    const auto transcript = BuildMNAUTHTranscript(
        context.connection, context.local_is_initiator,
        context.local_endpoint, context.remote_endpoint, signer_role,
        Params().MessageStart(), REQUIRED_MNAUTH_SERVICES);
    if (!transcript) return false;
    const auto authorization_hash = llmq::pq::GetMNAUTHAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock,
        context.local_is_initiator ? context.local_key : context.remote_key,
        context.local_is_initiator ? context.remote_key : context.local_key,
        *transcript, REQUIRED_MNAUTH_SERVICES);
    if (!authorization_hash || !node.ReserveMNAuthResponse()) return false;

    CMNAuth::SignRequest request;
    request.context = context;
    request.authorization_hash = *authorization_hash;
    request.attributed_pro_tx_hash =
        context.connection.remote.pro_tx_hash;
    request.signer_role = signer_role;
    const auto result{async.EnqueueSign(std::move(request))};
    if (!result.Accepted()) {
        LogPrint(BCLog::NET_NETCONN,
                 "MNAUTH signing admission failed (%d/%d), peer=%d\n",
                 static_cast<uint8_t>(result.error),
                 static_cast<uint8_t>(result.signing_error), node.GetId());
        return false;
    }
    node.SetMNAuthPending(CMNAuthPendingPhase::SIGN_PENDING,
                          result.deadline_micros);
    return true;
}

} // namespace

bool CMNAuth::ContextToken::IsStructurallyValid() const noexcept
{
    const auto expected_local_endpoint{
        llmq::pq::MakeNetworkEndpoint(local_service)};
    const auto expected_remote_endpoint{
        llmq::pq::MakeNetworkEndpoint(remote_service)};
    return peer_id >= 0 && connection.IsComplete() && !tip_hash.IsNull() &&
           local_key.IsStructurallyValid() &&
           remote_key.IsStructurallyValid() && local_service.IsValid() &&
           remote_service.IsValid() && connected_service.IsValid() &&
           expected_local_endpoint &&
           expected_remote_endpoint &&
           *expected_local_endpoint == local_endpoint &&
           *expected_remote_endpoint == remote_endpoint &&
           local_key.key_version == connection.local.global_key_version &&
           remote_key.key_version == connection.remote.global_key_version &&
           common_version >= PQ_MNAUTH_PROTO_VERSION &&
           masternode_connection &&
           (authenticated_remote_pro_tx_hash.IsNull() ||
            authenticated_remote_pro_tx_hash ==
                connection.remote.pro_tx_hash);
}

bool CMNAuth::AsyncConfig::IsValid() const noexcept
{
    if (verify_threads == 0 || max_verify_queue == 0 || sign_threads != 1 ||
        max_sign_queue == 0 || max_initiator_sign_queue == 0 ||
        max_responder_sign_queue == 0 ||
        max_completion_queue == 0 || reserved_sign_completion_slots == 0 ||
        reserved_sign_completion_slots >= max_completion_queue ||
        await_remote_timeout <= std::chrono::microseconds::zero() ||
        verify_timeout <= std::chrono::microseconds::zero() ||
        sign_timeout <= std::chrono::microseconds::zero() ||
        !verification_admission.IsValid() || !signing_admission.IsValid()) {
        return false;
    }
    if (max_initiator_sign_queue >
            std::numeric_limits<std::size_t>::max() -
                max_responder_sign_queue ||
        max_initiator_sign_queue + max_responder_sign_queue !=
            max_sign_queue) {
        return false;
    }
    if (initiator_sign_attempts_per_window == 0 ||
        responder_sign_attempts_per_window == 0 ||
        initiator_sign_attempts_per_window >
            signing_admission.global_attempts_per_window ||
        responder_sign_attempts_per_window >
            signing_admission.global_attempts_per_window -
                initiator_sign_attempts_per_window) {
        return false;
    }
    auto initiator_admission{signing_admission};
    initiator_admission.global_attempts_per_window =
        initiator_sign_attempts_per_window;
    initiator_admission.source_attempts_per_window =
        initiator_sign_source_attempts_per_window;
    auto responder_admission{signing_admission};
    responder_admission.global_attempts_per_window =
        responder_sign_attempts_per_window;
    responder_admission.source_attempts_per_window =
        responder_sign_source_attempts_per_window;
    if (!initiator_admission.IsValid() || !responder_admission.IsValid()) {
        return false;
    }
    if (verify_threads >
            std::numeric_limits<std::size_t>::max() - max_verify_queue ||
        sign_threads > std::numeric_limits<std::size_t>::max() -
                           max_sign_queue) {
        return false;
    }
    const std::size_t verify_capacity{verify_threads + max_verify_queue};
    const std::size_t sign_capacity{sign_threads + max_sign_queue};
    if (verify_capacity > std::numeric_limits<std::size_t>::max() -
                              sign_capacity) {
        return false;
    }
    return verification_admission.max_inflight >= verify_capacity &&
           max_completion_queue >= verify_capacity + sign_capacity;
}

struct CMNAuth::AsyncProcessor::Impl {
    inline static thread_local Impl* active_worker{nullptr};

    struct WorkerMarker {
        explicit WorkerMarker(Impl* impl) : previous{active_worker}
        {
            active_worker = impl;
        }
        ~WorkerMarker() { active_worker = previous; }
        Impl* previous;
    };

    struct PeerRegistration {
        std::shared_ptr<std::atomic_bool> cancelled;
        uint64_t generation{0};
    };

    struct VerifyWork {
        ContextToken context;
        llmq::pq::PQMNAUTHMessage message;
        llmq::pq::MNAUTHVerificationTask task;
        std::shared_ptr<std::atomic_bool> cancelled;
        uint64_t registration_generation{0};
        int64_t started_micros{0};
        int64_t deadline_micros{0};
    };

    struct SignWork {
        ContextToken context;
        uint256 authorization_hash;
        llmq::pq::MNAUTHSignerRole signer_role{
            llmq::pq::MNAUTHSignerRole::INITIATOR};
        std::shared_ptr<std::atomic_bool> cancelled;
        uint64_t registration_generation{0};
        int64_t started_micros{0};
        int64_t deadline_micros{0};
        ActiveMasternodeMNAUTHSigningDemand signing_demand;
    };

    static llmq::pq::MNAUTHSigningRuntimeConfig SigningLaneConfig(
        llmq::pq::MNAUTHSigningRuntimeConfig config,
        uint32_t lane_attempts,
        uint32_t source_attempts)
    {
        config.global_attempts_per_window = lane_attempts;
        config.source_attempts_per_window = source_attempts;
        return config;
    }

    explicit Impl(AsyncConfig config_in, AsyncHooks hooks_in)
        : config{std::move(config_in)},
          hooks{std::move(hooks_in)},
          verifier{config.verification_admission},
          initiator_signing_admission{SigningLaneConfig(
              config.signing_admission,
              config.initiator_sign_attempts_per_window,
              config.initiator_sign_source_attempts_per_window)},
          responder_signing_admission{SigningLaneConfig(
              config.signing_admission,
              config.responder_sign_attempts_per_window,
              config.responder_sign_source_attempts_per_window)},
          valid_config{config.IsValid()}
    {
        if (!hooks.verify) {
            hooks.verify = [](llmq::pq::MNAUTHVerificationTask& task) {
                return task();
            };
        }
        if (!hooks.sign) {
            hooks.sign = [](const uint256& pro_tx_hash,
                            uint32_t key_version,
                            const uint256& authorization_hash,
                            llmq::pq::GlobalSignature& signature) {
                return SignActiveMasternodeMNAUTH(
                    pro_tx_hash, key_version, authorization_hash, signature);
            };
        }
        if (!hooks.now_micros) {
            hooks.now_micros = [] {
                return TicksSinceEpoch<std::chrono::microseconds>(
                    SteadyClock::now());
            };
        }
        if (!hooks.wake) hooks.wake = [] {};

        if (!valid_config) return;
        try {
            verify_workers.reserve(config.verify_threads);
            for (std::size_t i{0}; i < config.verify_threads; ++i) {
                verify_workers.emplace_back(
                    &util::TraceThread, "mnauthv", [this] { VerifyLoop(); });
            }
            sign_workers.reserve(config.sign_threads);
            for (std::size_t i{0}; i < config.sign_threads; ++i) {
                sign_workers.emplace_back(
                    &util::TraceThread, "mnauths", [this] { SignLoop(); });
            }
        } catch (...) {
            {
                std::lock_guard lock{mutex};
                stopping = true;
            }
            verify_ready.notify_all();
            sign_ready.notify_all();
            for (std::thread& worker : verify_workers) {
                if (worker.joinable()) worker.join();
            }
            for (std::thread& worker : sign_workers) {
                if (worker.joinable()) worker.join();
            }
            throw;
        }
    }

    ~Impl() { Stop(); }

    [[nodiscard]] int64_t NowMicros() const noexcept
    {
        try {
            return hooks.now_micros();
        } catch (...) {
            return -1;
        }
    }

    [[nodiscard]] int64_t Deadline(
        std::chrono::microseconds timeout) const noexcept
    {
        return DeadlineFrom(NowMicros(), timeout);
    }

    [[nodiscard]] static int64_t DeadlineFrom(
        int64_t now, std::chrono::microseconds timeout) noexcept
    {
        if (now < 0 || timeout.count() <= 0) return 0;
        if (timeout.count() > std::numeric_limits<int64_t>::max() - now) {
            return std::numeric_limits<int64_t>::max();
        }
        return now + timeout.count();
    }

    [[nodiscard]] std::optional<PeerRegistration> Registration(
        int64_t peer_id) const
    {
        const auto it{peers.find(peer_id)};
        return it == peers.end()
            ? std::nullopt
            : std::optional<PeerRegistration>{it->second};
    }

    void PushCompletion(Completion completion,
                        const std::shared_ptr<std::atomic_bool>& cancelled)
    {
        std::unique_lock lock{mutex};
        bool recorded_backpressure{false};
        const std::size_t completion_limit{
            completion.kind == CompletionKind::VERIFY
                ? config.max_completion_queue -
                      config.reserved_sign_completion_slots
                : config.max_completion_queue};
        while (!stopping && !cancelled->load(std::memory_order_acquire) &&
               completions.size() >= completion_limit) {
            if (!recorded_backpressure) {
                ++stats.completion_backpressure_events;
                recorded_backpressure = true;
            }
            completion_space.wait(lock);
        }
        if (stopping || cancelled->load(std::memory_order_acquire)) {
            ++stats.cancelled_jobs;
            return;
        }
        completions.push_back(std::move(completion));
        if (completions.back().kind == CompletionKind::SIGN) {
            sign_completion_outstanding = std::tuple{
                completions.back().context.peer_id,
                completions.back().registration_generation,
                completions.back().deadline_micros};
        }
        lock.unlock();
        completion_ready.notify_all();
        try {
            hooks.wake();
        } catch (...) {
            // A wake-up is only a latency optimization. The message handler's
            // bounded poll will still drain this completion.
        }
    }

    void VerifyLoop()
    {
        WorkerMarker worker_marker{this};
        while (true) {
            std::optional<VerifyWork> work;
            {
                std::unique_lock lock{mutex};
                verify_ready.wait(
                    lock, [this] { return stopping || !verify_queue.empty(); });
                if (stopping && verify_queue.empty()) return;
                work.emplace(std::move(verify_queue.front()));
                verify_queue.pop_front();
                ++stats.verify_inflight;
            }

            const int64_t execution_started{NowMicros()};
            const bool expired{execution_started < 0 ||
                               execution_started >= work->deadline_micros};
            bool success{false};
            bool local_error{false};
            if (!expired &&
                !work->cancelled->load(std::memory_order_acquire)) {
                try {
                    success = hooks.verify(work->task);
                } catch (...) {
                    local_error = true;
                }
            }
            const int64_t finished{NowMicros()};
            const bool completed_late{
                finished < 0 || finished >= work->deadline_micros};
            const uint64_t latency{
                finished >= work->started_micros
                    ? static_cast<uint64_t>(finished - work->started_micros)
                    : 0};
            const CompletionError completion_error{
                (expired || completed_late) ? CompletionError::EXPIRED
                        : local_error ? CompletionError::LOCAL_ERROR
                        : success ? CompletionError::NONE
                                  : CompletionError::CRYPTO_FAILED};
            {
                std::lock_guard lock{mutex};
                if (stats.verify_inflight != 0) --stats.verify_inflight;
                ++stats.verify_completed;
                if (completion_error != CompletionError::NONE) {
                    ++stats.verify_failed;
                }
                if (expired) ++stats.verify_expired_before_execution;
                stats.verify_latency_total_micros += latency;
                stats.verify_latency_max_micros =
                    std::max(stats.verify_latency_max_micros, latency);
            }
            Completion completion{
                CompletionKind::VERIFY, std::move(work->context),
                work->registration_generation, std::move(work->message),
                completion_error, latency,
                work->deadline_micros};
            auto cancelled{std::move(work->cancelled)};
            work.reset();
            PushCompletion(std::move(completion), cancelled);
        }
    }

    void SignLoop()
    {
        WorkerMarker worker_marker{this};
        while (true) {
            std::optional<SignWork> work;
            {
                std::unique_lock lock{mutex};
                sign_ready.wait(lock, [this] {
                    return stopping ||
                           (!sign_completion_outstanding &&
                            (!initiator_sign_queue.empty() ||
                             !responder_sign_queue.empty()));
                });
                if (stopping && initiator_sign_queue.empty() &&
                    responder_sign_queue.empty()) {
                    return;
                }
                // Outbound initiator work has reserved capacity and receives
                // bounded priority, while every third ready slot is available
                // to responders so neither role can starve the other.
                const bool take_initiator{
                    !initiator_sign_queue.empty() &&
                    (responder_sign_queue.empty() || initiator_streak < 2)};
                auto& selected_queue{take_initiator
                                         ? initiator_sign_queue
                                         : responder_sign_queue};
                work.emplace(std::move(selected_queue.front()));
                selected_queue.pop_front();
                initiator_streak = take_initiator ? initiator_streak + 1 : 0;
                ++stats.sign_inflight;
            }

            llmq::pq::PQMNAUTHMessage message;
            message.signer_pro_tx_hash = work->context.connection.local.pro_tx_hash;
            message.signer_global_key_version =
                work->context.connection.local.global_key_version;
            message.signer_role = work->signer_role;
            const int64_t execution_started{NowMicros()};
            const bool expired{execution_started < 0 ||
                               execution_started >= work->deadline_micros};
            bool success{false};
            bool local_error{false};
            if (!expired &&
                !work->cancelled->load(std::memory_order_acquire)) {
                try {
                    success = hooks.sign(
                        message.signer_pro_tx_hash,
                        message.signer_global_key_version,
                        work->authorization_hash, message.signature) &&
                              message.IsStructurallyValid();
                } catch (...) {
                    local_error = true;
                }
            }
            const int64_t finished{NowMicros()};
            const bool completed_late{
                finished < 0 || finished >= work->deadline_micros};
            const uint64_t latency{
                finished >= work->started_micros
                    ? static_cast<uint64_t>(finished - work->started_micros)
                    : 0};
            const CompletionError completion_error{
                (expired || completed_late) ? CompletionError::EXPIRED
                        : local_error ? CompletionError::LOCAL_ERROR
                        : success ? CompletionError::NONE
                                  : CompletionError::CRYPTO_FAILED};
            {
                std::lock_guard lock{mutex};
                if (stats.sign_inflight != 0) --stats.sign_inflight;
                ++stats.sign_completed;
                if (completion_error != CompletionError::NONE) {
                    ++stats.sign_failed;
                }
                if (expired) ++stats.sign_expired_before_execution;
                stats.sign_latency_total_micros += latency;
                stats.sign_latency_max_micros =
                    std::max(stats.sign_latency_max_micros, latency);
            }
            Completion completion{
                CompletionKind::SIGN, std::move(work->context),
                work->registration_generation, std::move(message),
                completion_error, latency,
                work->deadline_micros};
            auto cancelled{std::move(work->cancelled)};
            work.reset();
            PushCompletion(std::move(completion), cancelled);
        }
    }

    [[nodiscard]] std::vector<Completion> TakeCompletionsLocked()
    {
        std::vector<Completion> result;
        result.reserve(completions.size());
        while (!completions.empty()) {
            result.push_back(std::move(completions.front()));
            completions.pop_front();
        }
        completion_space.notify_all();
        return result;
    }

    void Stop() noexcept
    {
        {
            std::lock_guard lock{mutex};
            if (!stopping) {
                stopping = true;
                for (auto& [peer_id, registration] : peers) {
                    registration.cancelled->store(
                        true, std::memory_order_release);
                }
                stats.cancelled_jobs += verify_queue.size() +
                                        initiator_sign_queue.size() +
                                        responder_sign_queue.size() +
                                        completions.size();
                verify_queue.clear();
                initiator_sign_queue.clear();
                responder_sign_queue.clear();
                completions.clear();
                sign_completion_outstanding.reset();
                peers.clear();
            }
        }
        verify_ready.notify_all();
        sign_ready.notify_all();
        completion_space.notify_all();
        completion_ready.notify_all();

        // A test hook may request shutdown from a worker. It can safely stop
        // admission and wake every lane, but the owner must perform the join.
        if (active_worker == this) return;

        std::lock_guard stop_lock{stop_mutex};
        for (std::thread& worker : verify_workers) {
            if (worker.joinable()) worker.join();
        }
        for (std::thread& worker : sign_workers) {
            if (worker.joinable()) worker.join();
        }
        verify_workers.clear();
        sign_workers.clear();
    }

    AsyncConfig config;
    AsyncHooks hooks;
    llmq::pq::MNAUTHVerificationManager verifier;
    llmq::pq::MNAUTHSigningAdmissionManager initiator_signing_admission;
    llmq::pq::MNAUTHSigningAdmissionManager responder_signing_admission;
    const bool valid_config{false};
    std::mutex stop_mutex;
    mutable std::mutex mutex;
    std::condition_variable verify_ready;
    std::condition_variable sign_ready;
    std::condition_variable completion_ready;
    std::condition_variable completion_space;
    bool stopping{false};
    std::map<int64_t, PeerRegistration> peers;
    std::deque<VerifyWork> verify_queue;
    std::deque<SignWork> initiator_sign_queue;
    std::deque<SignWork> responder_sign_queue;
    std::size_t initiator_streak{0};
    std::optional<std::tuple<int64_t, uint64_t, int64_t>>
        sign_completion_outstanding;
    uint64_t next_registration_generation{1};
    std::deque<Completion> completions;
    std::vector<std::thread> verify_workers;
    std::vector<std::thread> sign_workers;
    CMNAuthAsyncStats stats;
};

CMNAuth::AsyncProcessor::AsyncProcessor()
    : AsyncProcessor(AsyncConfig{}, AsyncHooks{})
{
}

CMNAuth::AsyncProcessor::AsyncProcessor(AsyncConfig config, AsyncHooks hooks)
    : m_impl{std::make_unique<Impl>(std::move(config), std::move(hooks))}
{
}

CMNAuth::AsyncProcessor::~AsyncProcessor() = default;

bool CMNAuth::AsyncProcessor::RegisterPeer(int64_t peer_id)
{
    if (peer_id < 0) return false;
    std::lock_guard lock{m_impl->mutex};
    if (m_impl->stopping || !m_impl->valid_config ||
        m_impl->next_registration_generation == 0) {
        return false;
    }
    const uint64_t generation{m_impl->next_registration_generation++};
    return m_impl->peers
        .emplace(peer_id,
                 Impl::PeerRegistration{
                     std::make_shared<std::atomic_bool>(false),
                     generation})
        .second;
}

void CMNAuth::AsyncProcessor::CancelPeer(int64_t peer_id) noexcept
{
    {
        std::lock_guard lock{m_impl->mutex};
        const auto peer{m_impl->peers.find(peer_id)};
        if (peer != m_impl->peers.end()) {
            peer->second.cancelled->store(true, std::memory_order_release);
            m_impl->peers.erase(peer);
        }
        const auto verify_before{m_impl->verify_queue.size()};
        const auto initiator_sign_before{
            m_impl->initiator_sign_queue.size()};
        const auto responder_sign_before{
            m_impl->responder_sign_queue.size()};
        const auto completions_before{m_impl->completions.size()};
        std::erase_if(m_impl->verify_queue, [&](const Impl::VerifyWork& work) {
            return work.context.peer_id == peer_id;
        });
        std::erase_if(
            m_impl->initiator_sign_queue, [&](const Impl::SignWork& work) {
                return work.context.peer_id == peer_id;
            });
        std::erase_if(
            m_impl->responder_sign_queue, [&](const Impl::SignWork& work) {
                return work.context.peer_id == peer_id;
            });
        std::erase_if(m_impl->completions, [&](const Completion& completion) {
            return completion.context.peer_id == peer_id;
        });
        if (m_impl->sign_completion_outstanding &&
            std::get<0>(*m_impl->sign_completion_outstanding) == peer_id) {
            m_impl->sign_completion_outstanding.reset();
        }
        m_impl->stats.cancelled_jobs +=
            verify_before - m_impl->verify_queue.size() +
            initiator_sign_before - m_impl->initiator_sign_queue.size() +
            responder_sign_before - m_impl->responder_sign_queue.size() +
            completions_before - m_impl->completions.size();
        // Keep the executor->verifier lock order used by EnqueueVerify so a
        // reused NodeId cannot have its new verifier session erased by an old
        // connection's cancellation.
        m_impl->verifier.ForgetPeer(peer_id);
    }
    m_impl->verify_ready.notify_all();
    m_impl->sign_ready.notify_all();
    m_impl->completion_space.notify_all();
    m_impl->completion_ready.notify_all();
}

CMNAuth::EnqueueResult CMNAuth::AsyncProcessor::EnqueueVerify(
    VerifyRequest request)
{
    EnqueueResult result;
    if (!request.context.IsStructurallyValid() ||
        !request.message.IsStructurallyValid() ||
        !request.transcript.IsStructurallyValid(
            request.required_service_flags)) {
        result.error = AsyncError::INVALID_REQUEST;
        return result;
    }

    const int64_t peer_id{request.context.peer_id};
    const bool local_is_initiator{request.context.local_is_initiator};
    const auto& initiator_key{local_is_initiator
                                  ? request.context.local_key
                                  : request.context.remote_key};
    const auto& responder_key{local_is_initiator
                                  ? request.context.remote_key
                                  : request.context.local_key};
    std::lock_guard lock{m_impl->mutex};
    if (m_impl->stopping || !m_impl->valid_config) {
        result.error = AsyncError::STOPPED;
        return result;
    }
    const int64_t now{m_impl->NowMicros()};
    const int64_t deadline{Impl::DeadlineFrom(
        now, m_impl->config.verify_timeout)};
    if (now < 0) {
        result.error = AsyncError::INVALID_REQUEST;
        return result;
    }
    const auto registration{m_impl->Registration(request.context.peer_id)};
    if (!registration) {
        result.error = AsyncError::UNKNOWN_PEER;
        return result;
    }
    auto cancelled{registration->cancelled};
    if (cancelled->load(std::memory_order_acquire)) {
        result.error = AsyncError::CANCELLED;
        return result;
    }
    if (m_impl->verify_queue.size() >= m_impl->config.max_verify_queue) {
        ++m_impl->stats.verify_saturation_drops;
        result.error = AsyncError::VERIFY_QUEUE_FULL;
        return result;
    }

    // Admission and queue insertion share the registration lock. CancelPeer
    // cannot erase the generation between Prepare() and insertion, which
    // would otherwise leave a verifier peer-session behind permanently.
    auto task = m_impl->verifier.Prepare(
        peer_id, request.context.keyed_net_group,
        request.genesis_hash, initiator_key, responder_key,
        request.transcript, request.expected_signer_role,
        request.required_service_flags, request.message,
        static_cast<uint64_t>(now) / 1'000'000,
        &result.verification_error);
    if (!task) {
        result.error = AsyncError::VERIFY_ADMISSION;
        if (result.verification_error ==
                llmq::pq::MNAUTHVerificationError::RATE_LIMIT ||
            result.verification_error ==
                llmq::pq::MNAUTHVerificationError::RATE_STATE_LIMIT) {
            ++m_impl->stats.preverify_rate_limit_drops;
        }
        return result;
    }

    try {
        m_impl->verify_queue.push_back(Impl::VerifyWork{
            std::move(request.context), std::move(request.message),
            std::move(*task), std::move(cancelled),
            registration->generation, now, deadline});
    } catch (...) {
        task.reset();
        m_impl->verifier.ForgetPeer(peer_id);
        throw;
    }
    result.deadline_micros = deadline;
    m_impl->verify_ready.notify_one();
    return result;
}

CMNAuth::EnqueueResult CMNAuth::AsyncProcessor::EnqueueSign(
    SignRequest request)
{
    EnqueueResult result;
    const auto expected_role{request.context.local_is_initiator
                                 ? llmq::pq::MNAUTHSignerRole::INITIATOR
                                 : llmq::pq::MNAUTHSignerRole::RESPONDER};
    const bool attributed_context{
        request.context.local_is_initiator
            ? request.context.connected_service ==
                      request.context.remote_service &&
                  request.context.authenticated_remote_pro_tx_hash.IsNull()
            : request.context.authenticated_remote_pro_tx_hash ==
                  request.context.connection.remote.pro_tx_hash};
    if (!request.context.IsStructurallyValid() ||
        request.authorization_hash.IsNull() ||
        request.attributed_pro_tx_hash.IsNull() ||
        request.attributed_pro_tx_hash !=
            request.context.connection.remote.pro_tx_hash ||
        request.signer_role != expected_role || !attributed_context) {
        result.error = AsyncError::INVALID_REQUEST;
        return result;
    }

    std::lock_guard lock{m_impl->mutex};
    if (m_impl->stopping || !m_impl->valid_config) {
        result.error = AsyncError::STOPPED;
        return result;
    }
    const int64_t now{m_impl->NowMicros()};
    const int64_t deadline{Impl::DeadlineFrom(
        now, m_impl->config.sign_timeout)};
    if (now < 0) {
        result.error = AsyncError::INVALID_REQUEST;
        return result;
    }
    const auto registration{m_impl->Registration(request.context.peer_id)};
    if (!registration) {
        result.error = AsyncError::UNKNOWN_PEER;
        return result;
    }
    auto cancelled{registration->cancelled};
    if (cancelled->load(std::memory_order_acquire)) {
        result.error = AsyncError::CANCELLED;
        return result;
    }

    const bool initiator_lane{request.context.local_is_initiator};
    auto& queue{initiator_lane ? m_impl->initiator_sign_queue
                               : m_impl->responder_sign_queue};
    const std::size_t queue_limit{
        initiator_lane ? m_impl->config.max_initiator_sign_queue
                       : m_impl->config.max_responder_sign_queue};
    if (queue.size() >= queue_limit) {
        ++m_impl->stats.sign_saturation_drops;
        if (initiator_lane) {
            ++m_impl->stats.initiator_sign_saturation_drops;
        } else {
            ++m_impl->stats.responder_sign_saturation_drops;
        }
        result.error = AsyncError::SIGN_QUEUE_FULL;
        return result;
    }

    auto& admission{initiator_lane
                        ? m_impl->initiator_signing_admission
                        : m_impl->responder_signing_admission};
    if (!admission.Admit(request.context.keyed_net_group,
                         request.attributed_pro_tx_hash,
                         static_cast<uint64_t>(now) / 1'000'000,
                         &result.signing_error)) {
        result.error = AsyncError::SIGN_ADMISSION;
        if (result.signing_error ==
                llmq::pq::MNAUTHSigningAdmissionError::RATE_LIMIT ||
            result.signing_error ==
                llmq::pq::MNAUTHSigningAdmissionError::SOURCE_STATE_LIMIT ||
            result.signing_error ==
                llmq::pq::MNAUTHSigningAdmissionError::IDENTITY_STATE_LIMIT) {
            ++m_impl->stats.sign_rate_limit_drops;
        }
        return result;
    }

    queue.push_back(Impl::SignWork{
        std::move(request.context), request.authorization_hash,
        request.signer_role, std::move(cancelled),
        registration->generation, now, deadline,
        ActiveMasternodeMNAUTHSigningDemand{}});
    result.deadline_micros = deadline;
    m_impl->sign_ready.notify_one();
    return result;
}

std::vector<CMNAuth::Completion>
CMNAuth::AsyncProcessor::TakeCompletions()
{
    std::lock_guard lock{m_impl->mutex};
    return m_impl->TakeCompletionsLocked();
}

std::vector<CMNAuth::Completion>
CMNAuth::AsyncProcessor::WaitForCompletions(std::chrono::milliseconds timeout)
{
    std::unique_lock lock{m_impl->mutex};
    m_impl->completion_ready.wait_for(lock, timeout, [this] {
        return m_impl->stopping || !m_impl->completions.empty();
    });
    return m_impl->TakeCompletionsLocked();
}

void CMNAuth::AsyncProcessor::AcknowledgeSignCompletion(
    int64_t peer_id,
    uint64_t registration_generation,
    int64_t deadline_micros) noexcept
{
    {
        std::lock_guard lock{m_impl->mutex};
        const std::tuple expected{
            peer_id, registration_generation, deadline_micros};
        if (!m_impl->sign_completion_outstanding ||
            *m_impl->sign_completion_outstanding != expected) {
            return;
        }
        m_impl->sign_completion_outstanding.reset();
    }
    m_impl->sign_ready.notify_one();
}

bool CMNAuth::AsyncProcessor::IsCurrentRegistration(
    int64_t peer_id, uint64_t registration_generation) const noexcept
{
    std::lock_guard lock{m_impl->mutex};
    const auto registration{m_impl->peers.find(peer_id)};
    return registration != m_impl->peers.end() &&
           registration->second.generation == registration_generation &&
           !registration->second.cancelled->load(std::memory_order_acquire);
}

CMNAuthAsyncStats CMNAuth::AsyncProcessor::GetStats() const noexcept
{
    std::lock_guard lock{m_impl->mutex};
    CMNAuthAsyncStats result{m_impl->stats};
    result.verify_queue_depth = m_impl->verify_queue.size();
    result.initiator_sign_queue_depth =
        m_impl->initiator_sign_queue.size();
    result.responder_sign_queue_depth =
        m_impl->responder_sign_queue.size();
    result.sign_queue_depth = result.initiator_sign_queue_depth +
                              result.responder_sign_queue_depth;
    result.completion_queue_depth = m_impl->completions.size();
    return result;
}

int64_t CMNAuth::AsyncProcessor::DeadlineFor(
    CMNAuthPendingPhase phase) const noexcept
{
    switch (phase) {
    case CMNAuthPendingPhase::AWAITING_REMOTE:
        return m_impl->Deadline(m_impl->config.await_remote_timeout);
    case CMNAuthPendingPhase::VERIFY_PENDING:
        return m_impl->Deadline(m_impl->config.verify_timeout);
    case CMNAuthPendingPhase::SIGN_PENDING:
        return m_impl->Deadline(m_impl->config.sign_timeout);
    case CMNAuthPendingPhase::NONE:
    case CMNAuthPendingPhase::COMPLETE:
        return 0;
    }
    return 0;
}

void CMNAuth::AsyncProcessor::RecordStaleCompletion() noexcept
{
    std::lock_guard lock{m_impl->mutex};
    ++m_impl->stats.stale_completion_drops;
}

void CMNAuth::AsyncProcessor::Stop() noexcept
{
    m_impl->Stop();
}

bool CMNAuthVersionData::IsStructurallyValid() const noexcept
{
    return version == PQ_MNAUTH_VERSION_DATA_VERSION && !cookie.IsNull() &&
           (pro_tx_hash.IsNull() == (global_key_version == 0));
}

bool CMNAuthConnectionData::IsComplete() const noexcept
{
    return has_local && has_remote && local.IsStructurallyValid() &&
           remote.IsStructurallyValid() && local.HasMasternodeIdentity() &&
           remote.HasMasternodeIdentity() &&
           local.pro_tx_hash != remote.pro_tx_hash &&
           local.cookie != remote.cookie && !local_challenge.IsNull() &&
           !remote_challenge.IsNull() &&
           local_challenge != remote_challenge && local_version_nonce != 0 &&
           remote_version_nonce != 0 &&
           local_version_nonce != remote_version_nonce &&
           local_protocol_version != 0 && remote_protocol_version != 0;
}

std::optional<llmq::pq::MNAUTHTranscript> BuildMNAUTHTranscript(
    const CMNAuthConnectionData& connection,
    bool local_is_initiator,
    const llmq::pq::NetworkEndpoint& local_endpoint,
    const llmq::pq::NetworkEndpoint& remote_endpoint,
    llmq::pq::MNAUTHSignerRole signer_role,
    const std::array<uint8_t, 4>& network_magic,
    uint64_t required_service_flags)
{
    if (!connection.IsComplete()) return std::nullopt;

    const CMNAuthVersionData& initiator =
        local_is_initiator ? connection.local : connection.remote;
    const CMNAuthVersionData& responder =
        local_is_initiator ? connection.remote : connection.local;

    llmq::pq::MNAUTHTranscript transcript;
    transcript.network_magic = network_magic;
    transcript.initiator_pro_tx_hash = initiator.pro_tx_hash;
    transcript.responder_pro_tx_hash = responder.pro_tx_hash;
    transcript.initiator_global_key_version = initiator.global_key_version;
    transcript.responder_global_key_version = responder.global_key_version;
    transcript.initiator_cookie = initiator.cookie;
    transcript.responder_cookie = responder.cookie;
    transcript.initiator_challenge = local_is_initiator
        ? connection.local_challenge
        : connection.remote_challenge;
    transcript.responder_challenge = local_is_initiator
        ? connection.remote_challenge
        : connection.local_challenge;
    transcript.initiator_version_nonce = local_is_initiator
        ? connection.local_version_nonce
        : connection.remote_version_nonce;
    transcript.responder_version_nonce = local_is_initiator
        ? connection.remote_version_nonce
        : connection.local_version_nonce;
    transcript.initiator_protocol_version = local_is_initiator
        ? connection.local_protocol_version
        : connection.remote_protocol_version;
    transcript.responder_protocol_version = local_is_initiator
        ? connection.remote_protocol_version
        : connection.local_protocol_version;
    transcript.initiator_service_flags = local_is_initiator
        ? connection.local_service_flags
        : connection.remote_service_flags;
    transcript.responder_service_flags = local_is_initiator
        ? connection.remote_service_flags
        : connection.local_service_flags;
    transcript.initiator_endpoint =
        local_is_initiator ? local_endpoint : remote_endpoint;
    transcript.responder_endpoint =
        local_is_initiator ? remote_endpoint : local_endpoint;
    transcript.signer_role = signer_role;

    if (!transcript.IsStructurallyValid(required_service_flags)) {
        return std::nullopt;
    }
    return transcript;
}

CMNAuthVersionData CMNAuth::MakeVersionData(bool masternode_connection)
{
    CMNAuthVersionData version_data;
    do {
        version_data.cookie = GetRandHash();
    } while (version_data.cookie.IsNull());

    if (masternode_connection) {
        llmq::pq::GlobalPublicKey public_key{};
        CService service;
        GetActiveMasternodeIdentity(
            version_data.pro_tx_hash, version_data.global_key_version,
            public_key, service);
    }
    return version_data;
}

void CMNAuth::BeginMNAUTH(CNode* pnode,
                          ChainstateManager& chainman,
                          AsyncProcessor& async)
{
    // SYSCOIN: Quarantine suppresses local authenticated masternode participation.
    if (pnode == nullptr || !fMasternodeMode ||
        !chainman.IsPQParticipationAllowed() ||
        !masternodeSync.IsBlockchainSynced() ||
        !pnode->m_masternode_connection) {
        return;
    }
    if (pnode->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        pnode->fDisconnect = true;
        return;
    }
    ContextToken context;
    std::string error;
    if (!BuildContextToken(*pnode, chainman, context, error)) {
        LogPrint(BCLog::NET_NETCONN,
                 "CMNAuth::BeginMNAUTH -- refusing stale identity: %s, peer=%d\n",
                 error, pnode->GetId());
        pnode->fDisconnect = true;
        return;
    }

    // An inbound responder does no private-key work until this connection's
    // initiator has authenticated. Its explicit deadline replaces the old
    // fixed five-second transport heuristic.
    if (!context.local_is_initiator) {
        pnode->SetMNAuthPending(
            CMNAuthPendingPhase::AWAITING_REMOTE,
            async.DeadlineFor(CMNAuthPendingPhase::AWAITING_REMOTE));
        return;
    }
    if (!EnqueueLocalSignature(*pnode, context, async)) {
        pnode->fDisconnect = true;
    }
}

void CMNAuth::ProcessMessage(CNode* pnode,
                             const std::string& str_command,
                             CDataStream& recv,
                             ChainstateManager& chainman,
                             AsyncProcessor& async,
                             PeerManager& peerman)
{
    // SYSCOIN: Quarantine consumes no authenticated masternode traffic.
    if (pnode == nullptr || str_command != NetMsgType::MNAUTH ||
        !chainman.IsPQParticipationAllowed() ||
        !masternodeSync.IsBlockchainSynced()) {
        return;
    }
    const PeerRef peer = peerman.GetPeerRef(pnode->GetId());
    if (pnode->GetCommonVersion() < PQ_MNAUTH_PROTO_VERSION) {
        pnode->fDisconnect = true;
        return;
    }
    if (!pnode->GetVerifiedProRegTxHash().IsNull()) {
        Punish(peerman, peer, 100, "duplicate mnauth");
        return;
    }
    const CMNAuthPendingState pending{pnode->GetMNAuthPending()};
    if (pending.phase != CMNAuthPendingPhase::AWAITING_REMOTE) {
        Punish(peerman, peer, 100, "premature or duplicate mnauth");
        return;
    }
    const int64_t now_micros{
        TicksSinceEpoch<std::chrono::microseconds>(SteadyClock::now())};
    const int64_t provisional_deadline{
        async.DeadlineFor(CMNAuthPendingPhase::VERIFY_PENDING)};
    if (!pnode->TransitionMNAuthPending(
            CMNAuthPendingPhase::AWAITING_REMOTE,
            {CMNAuthPendingPhase::VERIFY_PENDING,
             provisional_deadline},
            now_micros)) {
        pnode->fDisconnect = true;
        return;
    }

    llmq::pq::PQMNAUTHMessage message;
    if (!llmq::pq::DecodePQMNAUTHMessage(recv, message)) {
        Punish(peerman, peer, 100, "non-canonical pq mnauth");
        return;
    }

    const CMNAuthConnectionData connection =
        pnode->GetMNAuthConnectionData();
    const bool local_is_initiator = !pnode->IsInboundConn();
    const auto expected_role = local_is_initiator
        ? llmq::pq::MNAUTHSignerRole::RESPONDER
        : llmq::pq::MNAUTHSignerRole::INITIATOR;
    if (!connection.IsComplete() ||
        (connection.remote_service_flags & REQUIRED_MNAUTH_SERVICES) !=
            REQUIRED_MNAUTH_SERVICES ||
        message.signer_pro_tx_hash != connection.remote.pro_tx_hash ||
        message.signer_global_key_version !=
            connection.remote.global_key_version ||
        message.signer_role != expected_role) {
        Punish(peerman, peer, 100, "pq mnauth transcript mismatch");
        return;
    }

    ContextToken context;
    std::string error;
    if (!BuildContextToken(*pnode, chainman, context, error)) {
        LogPrint(BCLog::NET_NETCONN,
                 "CMNAuth::ProcessMessage -- stale registry context: %s, peer=%d\n",
                 error, pnode->GetId());
        pnode->fDisconnect = true;
        return;
    }
    const auto transcript = BuildMNAUTHTranscript(
        connection, local_is_initiator, context.local_endpoint,
        context.remote_endpoint, expected_role, Params().MessageStart(),
        REQUIRED_MNAUTH_SERVICES);
    if (!transcript) {
        Punish(peerman, peer, 100, "invalid pq mnauth transcript");
        return;
    }

    VerifyRequest request;
    request.context = std::move(context);
    request.genesis_hash = Params().GetConsensus().hashGenesisBlock;
    request.transcript = *transcript;
    request.expected_signer_role = expected_role;
    request.required_service_flags = REQUIRED_MNAUTH_SERVICES;
    request.message = std::move(message);
    const auto result{async.EnqueueVerify(std::move(request))};
    if (!result.Accepted()) {
        LogPrint(BCLog::NET_NETCONN,
                 "CMNAuth::ProcessMessage -- PQ verification admission failed (%d/%d), peer=%d\n",
                 static_cast<uint8_t>(result.error),
                 static_cast<uint8_t>(result.verification_error),
                 pnode->GetId());
        if (result.error != AsyncError::VERIFY_ADMISSION ||
            IsAdmissionLimit(result.verification_error)) {
            pnode->fDisconnect = true;
        } else {
            Punish(peerman, peer, 100, "invalid or replayed pq mnauth");
        }
        return;
    }
    pnode->SetMNAuthPending(CMNAuthPendingPhase::VERIFY_PENDING,
                            result.deadline_micros);
}

void CMNAuth::ProcessAsyncCompletions(AsyncProcessor& async,
                                      ChainstateManager& chainman,
                                      CConnman& connman,
                                      PeerManager& peerman)
{
    // NodesSnapshot pins lifetimes while releasing m_nodes_mutex before any
    // chain-state or peer-tracker locks are acquired below.
    const CConnman::NodesSnapshot nodes_snapshot{
        connman, AllNodes, /*shuffle=*/false};
    const int64_t sweep_now{
        TicksSinceEpoch<std::chrono::microseconds>(SteadyClock::now())};
    for (CNode* pnode : nodes_snapshot.Nodes()) {
        const CMNAuthPendingState pending{pnode->GetMNAuthPending()};
        if (pending.IsPending() &&
            (pending.deadline_micros <= 0 || sweep_now < 0 ||
             sweep_now >= pending.deadline_micros)) {
            LogPrint(BCLog::NET_NETCONN,
                     "CMNAuth -- phase %d deadline expired, peer=%d\n",
                     static_cast<uint8_t>(pending.phase), pnode->GetId());
            pnode->fDisconnect = true;
        }
    }

    for (Completion& completion : async.TakeCompletions()) {
        const bool sign_completion{
            completion.kind == CompletionKind::SIGN};
        const auto node_it{std::find_if(
            nodes_snapshot.Nodes().begin(), nodes_snapshot.Nodes().end(),
            [&](const CNode* node) {
                return node->GetId() == completion.context.peer_id;
            })};
        const bool found{
            node_it != nodes_snapshot.Nodes().end() &&
            async.IsCurrentRegistration(
                completion.context.peer_id,
                completion.registration_generation)};
        if (found) {
            CNode* pnode{*node_it};
            (void)[&](CNode* pnode) -> bool {
                const int64_t now_micros{
                    TicksSinceEpoch<std::chrono::microseconds>(
                        SteadyClock::now())};
                const CMNAuthPendingPhase expected_phase{
                    sign_completion ? CMNAuthPendingPhase::SIGN_PENDING
                                    : CMNAuthPendingPhase::VERIFY_PENDING};
                if (!CompletionIsCurrent(
                        *pnode, completion, expected_phase, now_micros) ||
                    !ContextStillMatches(
                        *pnode, chainman, completion.context)) {
                    async.RecordStaleCompletion();
                    pnode->fDisconnect = true;
                    return true;
                }

                const PeerRef peer{peerman.GetPeerRef(pnode->GetId())};
                if (!completion.Success()) {
                    if (!sign_completion &&
                        completion.error == CompletionError::CRYPTO_FAILED) {
                        Punish(peerman, peer, 100,
                               "pq mnauth signature verification failed");
                    } else {
                        pnode->fDisconnect = true;
                    }
                    return true;
                }

                if (sign_completion) {
                    const bool attributed{
                        completion.context.local_is_initiator
                            ? HasAttributedOutboundIdentity(
                                  *pnode, completion.context)
                            : pnode->GetVerifiedProRegTxHash() ==
                                  completion.context.connection.remote
                                      .pro_tx_hash};
                    if (!attributed ||
                        !completion.message.IsStructurallyValid()) {
                        pnode->fDisconnect = true;
                        return true;
                    }
                    LogPrint(BCLog::NET_NETCONN,
                             "CMNAuth -- sending PQ MNAUTH, role=%d, peer=%d\n",
                             static_cast<uint8_t>(
                                 completion.message.signer_role),
                             pnode->GetId());
                    connman.PushMessage(
                        pnode,
                        CNetMsgMaker(completion.context.common_version)
                            .Make(NetMsgType::MNAUTH,
                                  completion.message));
                    if (completion.context.local_is_initiator) {
                        pnode->SetMNAuthPending(
                            CMNAuthPendingPhase::AWAITING_REMOTE,
                            async.DeadlineFor(
                                CMNAuthPendingPhase::AWAITING_REMOTE));
                    } else {
                        pnode->SetMNAuthPending(
                            CMNAuthPendingPhase::COMPLETE, 0);
                    }
                    return true;
                }

                const auto& message{completion.message};
                if (!pnode->IsInboundConn()) {
                    mmetaman->GetMetaInfo(message.signer_pro_tx_hash)
                        ->SetLastOutboundSuccess(
                            GetTime<std::chrono::seconds>().count());
                    if (pnode->m_masternode_probe_connection) {
                        LogPrint(BCLog::NET_NETCONN,
                                 "CMNAuth -- PQ masternode probe succeeded for %s, peer=%d\n",
                                 message.signer_pro_tx_hash.ToString(),
                                 pnode->GetId());
                        pnode->fDisconnect = true;
                        return true;
                    }
                }

                uint256 local_pro_tx_hash;
                uint32_t local_key_version{0};
                llmq::pq::GlobalPublicKey local_public_key{};
                CService local_service;
                GetActiveMasternodeIdentity(
                    local_pro_tx_hash, local_key_version,
                    local_public_key, local_service);
                for (CNode* other : nodes_snapshot.Nodes()) {
                    if (pnode->fDisconnect || other == pnode ||
                        other->GetVerifiedProRegTxHash() !=
                            message.signer_pro_tx_hash) {
                        continue;
                    }
                    if (!local_pro_tx_hash.IsNull()) {
                        const uint256 deterministic_outbound =
                            llmq::CLLMQUtils::DeterministicOutboundConnection(
                                local_pro_tx_hash,
                                message.signer_pro_tx_hash);
                        if (deterministic_outbound == local_pro_tx_hash) {
                            if (other->IsInboundConn()) {
                                other->m_masternode_probe_connection = true;
                            } else if (pnode->IsInboundConn()) {
                                pnode->m_masternode_probe_connection = true;
                            }
                        } else if (!other->IsInboundConn()) {
                            other->fDisconnect = true;
                        } else if (!pnode->IsInboundConn()) {
                            pnode->fDisconnect = true;
                        }
                    } else {
                        pnode->fDisconnect = true;
                    }
                }
                if (pnode->fDisconnect) return true;

                pnode->SetVerifiedMasternode(
                    message.signer_pro_tx_hash,
                    ::Hash(completion.context.remote_key.public_key),
                    completion.context.remote_key.key_version,
                    completion.context.remote_service);
                peerman.UpdateChainLockSourceIdentity(
                    pnode->GetId(), message.signer_pro_tx_hash,
                    completion.context.keyed_net_group,
                    pnode->IsOutboundOrBlockRelayConn());
                peerman.UpdateGovernanceSourceIdentity(
                    pnode->GetId(), message.signer_pro_tx_hash,
                    completion.context.keyed_net_group,
                    pnode->IsOutboundOrBlockRelayConn());

                LogPrint(BCLog::NET_NETCONN,
                         "CMNAuth -- valid PQ MNAUTH for %s key-version=%u, peer=%d\n",
                         message.signer_pro_tx_hash.ToString(),
                         message.signer_global_key_version, pnode->GetId());

                if (pnode->IsInboundConn()) {
                    ContextToken authenticated_context;
                    std::string context_error;
                    if (!BuildContextToken(
                            *pnode, chainman, authenticated_context,
                            context_error) ||
                        authenticated_context
                                .authenticated_remote_pro_tx_hash !=
                            message.signer_pro_tx_hash ||
                        !EnqueueLocalSignature(
                            *pnode, authenticated_context, async)) {
                        pnode->fDisconnect = true;
                    }
                } else {
                    pnode->SetMNAuthPending(
                        CMNAuthPendingPhase::COMPLETE, 0);
                }
                return true;
            }(pnode);
        }
        if (!found) async.RecordStaleCompletion();
        if (sign_completion) {
            // Full main-thread revalidation/send/drop is complete before the
            // sole signer may begin another private-key operation.
            async.AcknowledgeSignCompletion(
                completion.context.peer_id,
                completion.registration_generation,
                completion.deadline_micros);
        }
    }
}

void CMNAuth::UpdatedBlockTip(const CBlockIndex* pindex_new,
                              CConnman& connman)
{
    if (pindex_new == nullptr || deterministicMNManager == nullptr) return;

    llmq::pq::PQRegistryReadView snapshot;
    std::string error;
    const bool have_snapshot =
        deterministicMNManager->GetPQRegistryReadView(
            pindex_new, snapshot, error) &&
        snapshot.BlockHash() == pindex_new->GetBlockHash();
    const CDeterministicMNList mn_list =
        deterministicMNManager->GetListForBlock(pindex_new);

    connman.ForEachNode([&](CNode* pnode) {
        const uint256 pro_tx_hash = pnode->GetVerifiedProRegTxHash();
        if (pro_tx_hash.IsNull()) return;

        const auto* operator_state =
            have_snapshot ? snapshot.FindOperator(pro_tx_hash) : nullptr;
        const auto dmn = mn_list.GetMN(pro_tx_hash);
        const bool current =
            operator_state != nullptr && operator_state->HasActiveGlobalKey() &&
            operator_state->IsStructurallyValid() &&
            mn_list.IsMNValid(pro_tx_hash) && dmn != nullptr &&
            dmn->pdmnState->addr == pnode->GetVerifiedMasternodeService() &&
            operator_state->global_key.key_version ==
                pnode->GetVerifiedGlobalKeyVersion() &&
            ::Hash(operator_state->global_key.public_key) ==
                pnode->GetVerifiedGlobalKeyHash();
        if (!current) {
            LogPrint(BCLog::NET_NETCONN,
                     "CMNAuth::UpdatedBlockTip -- disconnecting stale PQ identity %s, peer=%d\n",
                     pro_tx_hash.ToString(), pnode->GetId());
            pnode->fDisconnect = true;
        }
    });
}
