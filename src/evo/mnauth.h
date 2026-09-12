// Copyright (c) 2019 The Dash Core developers
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_MNAUTH_H
#define SYSCOIN_EVO_MNAUTH_H

#include <evo/mnauth_types.h>
#include <llmq/pq_mnauth.h>
#include <netaddress.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

class CBlockIndex;
class CConnman;
class CDataStream;
class CNode;
class ChainstateManager;
class PeerManager;

struct MNAUTHConnectionSelectionCandidate {
    int64_t peer_id{-1};
    bool inbound{false};
    bool disconnecting{false};
};

/** Select one stable socket in the deterministic direction when available. */
[[nodiscard]] std::optional<int64_t> SelectPreferredMNAUTHConnection(
    bool local_is_deterministic_initiator,
    std::span<const MNAUTHConnectionSelectionCandidate> connections) noexcept;

/** Map local/remote VERSION facts into canonical initiator/responder order. */
[[nodiscard]] std::optional<llmq::pq::MNAUTHTranscript> BuildMNAUTHTranscript(
    const CMNAuthConnectionData& connection,
    bool local_is_initiator,
    const llmq::pq::NetworkEndpoint& local_endpoint,
    const llmq::pq::NetworkEndpoint& remote_endpoint,
    llmq::pq::MNAUTHSignerRole signer_role,
    const std::array<uint8_t, 4>& network_magic,
    uint64_t required_service_flags);

/** Live post-quantum MNAUTH handler. The wire command remains `mnauth`. */
class CMNAuth final {
public:
    struct ContextToken {
        int64_t peer_id{-1};
        CMNAuthConnectionData connection;
        uint256 tip_hash;
        llmq::pq::GlobalKeyRecord local_key;
        llmq::pq::GlobalKeyRecord remote_key;
        llmq::pq::NetworkEndpoint local_endpoint;
        llmq::pq::NetworkEndpoint remote_endpoint;
        CService local_service;
        CService remote_service;
        CService connected_service;
        uint256 authenticated_remote_pro_tx_hash;
        uint64_t keyed_net_group{0};
        int common_version{0};
        bool local_is_initiator{false};
        bool masternode_connection{false};
        bool masternode_probe_connection{false};

        [[nodiscard]] bool IsStructurallyValid() const noexcept;
        friend bool operator==(const ContextToken&,
                               const ContextToken&) = default;
    };

    enum class AsyncError : uint8_t {
        NONE = 0,
        STOPPED,
        UNKNOWN_PEER,
        CANCELLED,
        INVALID_REQUEST,
        VERIFY_ADMISSION,
        SIGN_ADMISSION,
        VERIFY_QUEUE_FULL,
        SIGN_QUEUE_FULL,
    };

    struct EnqueueResult {
        AsyncError error{AsyncError::NONE};
        llmq::pq::MNAUTHVerificationError verification_error{
            llmq::pq::MNAUTHVerificationError::NONE};
        llmq::pq::MNAUTHSigningAdmissionError signing_error{
            llmq::pq::MNAUTHSigningAdmissionError::NONE};
        int64_t deadline_micros{0};

        [[nodiscard]] bool Accepted() const noexcept
        {
            return error == AsyncError::NONE;
        }
    };

    struct VerifyRequest {
        ContextToken context;
        uint256 genesis_hash;
        llmq::pq::MNAUTHTranscript transcript;
        llmq::pq::MNAUTHSignerRole expected_signer_role{
            llmq::pq::MNAUTHSignerRole::INITIATOR};
        uint64_t required_service_flags{0};
        llmq::pq::PQMNAUTHMessage message;
    };

    struct SignRequest {
        ContextToken context;
        uint256 authorization_hash;
        uint256 attributed_pro_tx_hash;
        llmq::pq::MNAUTHSignerRole signer_role{
            llmq::pq::MNAUTHSignerRole::INITIATOR};
    };

    enum class CompletionKind : uint8_t { VERIFY = 0, SIGN };
    enum class CompletionError : uint8_t {
        NONE = 0,
        CRYPTO_FAILED,
        LOCAL_ERROR,
        EXPIRED,
    };

    struct Completion {
        CompletionKind kind{CompletionKind::VERIFY};
        ContextToken context;
        uint64_t registration_generation{0};
        llmq::pq::PQMNAUTHMessage message;
        CompletionError error{CompletionError::NONE};
        uint64_t latency_micros{0};
        int64_t deadline_micros{0};

        [[nodiscard]] bool Success() const noexcept
        {
            return error == CompletionError::NONE;
        }
    };

    struct AsyncConfig {
        std::size_t verify_threads{2};
        std::size_t max_verify_queue{16};
        std::size_t sign_threads{1};
        std::size_t max_sign_queue{8};
        std::size_t max_initiator_sign_queue{6};
        std::size_t max_responder_sign_queue{2};
        std::size_t max_completion_queue{32};
        std::size_t reserved_sign_completion_slots{1};
        std::chrono::microseconds await_remote_timeout{
            std::chrono::seconds{60}};
        std::chrono::microseconds verify_timeout{
            std::chrono::seconds{60}};
        std::chrono::microseconds sign_timeout{
            std::chrono::seconds{120}};
        llmq::pq::MNAUTHRuntimeConfig verification_admission;
        llmq::pq::MNAUTHSigningRuntimeConfig signing_admission;
        uint32_t initiator_sign_attempts_per_window{6};
        uint32_t responder_sign_attempts_per_window{2};
        uint32_t initiator_sign_source_attempts_per_window{6};
        uint32_t responder_sign_source_attempts_per_window{2};

        [[nodiscard]] bool IsValid() const noexcept;
    };

    struct AsyncHooks {
        std::function<bool(llmq::pq::MNAUTHVerificationTask&)> verify;
        std::function<bool(const uint256&, uint32_t, const uint256&,
                           llmq::pq::GlobalSignature&)> sign;
        std::function<int64_t()> now_micros;
        std::function<void()> wake;
    };

    class AsyncProcessor final {
    public:
        AsyncProcessor();
        explicit AsyncProcessor(AsyncConfig config, AsyncHooks hooks);
        ~AsyncProcessor();

        AsyncProcessor(const AsyncProcessor&) = delete;
        AsyncProcessor& operator=(const AsyncProcessor&) = delete;

        [[nodiscard]] bool RegisterPeer(int64_t peer_id);
        void CancelPeer(int64_t peer_id) noexcept;
        [[nodiscard]] EnqueueResult EnqueueVerify(VerifyRequest request);
        [[nodiscard]] EnqueueResult EnqueueSign(SignRequest request);
        [[nodiscard]] std::vector<Completion> TakeCompletions();
        [[nodiscard]] std::vector<Completion> WaitForCompletions(
            std::chrono::milliseconds timeout);
        void AcknowledgeSignCompletion(int64_t peer_id,
                                       uint64_t registration_generation,
                                       int64_t deadline_micros) noexcept;
        [[nodiscard]] bool IsCurrentRegistration(
            int64_t peer_id,
            uint64_t registration_generation) const noexcept;
        [[nodiscard]] CMNAuthAsyncStats GetStats() const noexcept;
        [[nodiscard]] int64_t DeadlineFor(
            CMNAuthPendingPhase phase) const noexcept;
        void RecordStaleCompletion() noexcept;
        void Stop() noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

    static CMNAuthVersionData MakeVersionData(bool masternode_connection);
    static void BeginMNAUTH(CNode* pnode, ChainstateManager& chainman,
                            AsyncProcessor& async);
    static void ProcessMessage(CNode* pnode, const std::string& str_command,
                               CDataStream& recv, ChainstateManager& chainman,
                               AsyncProcessor& async, PeerManager& peerman);
    static void ProcessAsyncCompletions(AsyncProcessor& async,
                                        ChainstateManager& chainman,
                                        CConnman& connman,
                                        PeerManager& peerman);
    static void UpdatedBlockTip(const CBlockIndex* pindex_new,
                                CConnman& connman);
};

#endif // SYSCOIN_EVO_MNAUTH_H
