// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_MNAUTH_H
#define SYSCOIN_LLMQ_PQ_MNAUTH_H

#include <checkqueue.h>
#include <llmq/pq_global_auth.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <memory>
#include <optional>
#include <vector>

class CDataStream;

namespace llmq::pq {

inline constexpr uint16_t PQ_MNAUTH_WIRE_VERSION{1};

/**
 * A fixed-width MNAUTH proof. Connection data is deliberately omitted from
 * the wire message: each peer reconstructs it from its authenticated VERSION
 * exchange, so a sender cannot substitute cookies, nonces, roles, or services.
 */
struct PQMNAUTHMessage {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 32 + sizeof(uint32_t) + sizeof(uint8_t) +
        GLOBAL_SIGNATURE_SIZE};

    uint16_t version{PQ_MNAUTH_WIRE_VERSION};
    uint256 signer_pro_tx_hash;
    uint32_t signer_global_key_version{0};
    MNAUTHSignerRole signer_role{MNAUTHSignerRole::INITIATOR};
    GlobalSignature signature{};

    SERIALIZE_METHODS(PQMNAUTHMessage, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ MNAUTH message");
        });
        uint8_t signer_role{static_cast<uint8_t>(obj.signer_role)};
        READWRITE(obj.version, obj.signer_pro_tx_hash,
                  obj.signer_global_key_version, signer_role);
        SER_READ(obj, obj.signer_role = static_cast<MNAUTHSignerRole>(signer_role));
        SER_READ(obj, if (!obj.IsHeaderValid()) {
            throw std::ios_base::failure("invalid PQ MNAUTH header");
        });
        READWRITE(obj.signature);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ MNAUTH message");
        });
    }

    [[nodiscard]] bool IsHeaderValid() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQMNAUTHMessage&, const PQMNAUTHMessage&) = default;
};

static_assert(PQMNAUTHMessage::WIRE_SIZE == 7'895);

/** Exact-size decoder for untrusted P2P payloads; suffix bytes are rejected. */
[[nodiscard]] bool DecodePQMNAUTHMessage(
    CDataStream& stream,
    PQMNAUTHMessage& message) noexcept;

/** Exact-size decoder for retained or test payload bytes. */
[[nodiscard]] bool DecodePQMNAUTHMessage(
    const std::vector<unsigned char>& encoded,
    PQMNAUTHMessage& message) noexcept;

enum class MNAUTHVerificationError : uint8_t {
    NONE = 0,
    INVALID_CONFIGURATION,
    INVALID_TIME,
    INVALID_MESSAGE,
    INVALID_TRANSCRIPT,
    WRONG_SIGNER_ROLE,
    WRONG_SIGNER_IDENTITY,
    INVALID_AUTHORIZATION,
    DUPLICATE_PEER,
    REPLAY,
    PEER_STATE_LIMIT,
    REPLAY_STATE_LIMIT,
    RATE_STATE_LIMIT,
    RATE_LIMIT,
    INFLIGHT_LIMIT,
};

/**
 * Runtime-only DoS bounds. now_seconds passed to Prepare() must come from a
 * monotonic clock, not adjusted network time.
 */
struct MNAUTHRuntimeConfig {
    std::size_t max_inflight{18};
    std::size_t max_peer_sessions{1'024};
    std::size_t max_rate_sources{1'024};
    std::size_t max_replay_entries{2'048};
    std::size_t max_success_cache_entries{256};
    uint32_t global_attempts_per_window{64};
    // Shared-NAT and regtest topologies can legitimately place a full small
    // quorum in one keyed network group; the global bound remains dominant.
    uint32_t source_attempts_per_window{8};
    uint64_t rate_window_seconds{60};
    uint64_t replay_retention_seconds{600};

    [[nodiscard]] bool IsValid() const noexcept;
};

struct MNAUTHRuntimeStats {
    std::size_t inflight{0};
    std::size_t peer_sessions{0};
    std::size_t rate_sources{0};
    std::size_t replay_entries{0};
    std::size_t success_cache_entries{0};
};

/** One self-contained, queueable SLH-DSA verification. */
class MNAUTHSignatureCheck {
public:
    MNAUTHSignatureCheck(uint256 genesis_hash,
                         GlobalKeyRecord initiator_key,
                         GlobalKeyRecord responder_key,
                         MNAUTHTranscript transcript,
                         uint64_t required_service_flags,
                         GlobalSignature signature);

    [[nodiscard]] bool operator()() const;

private:
    uint256 m_genesis_hash;
    GlobalKeyRecord m_initiator_key;
    GlobalKeyRecord m_responder_key;
    MNAUTHTranscript m_transcript;
    uint64_t m_required_service_flags{0};
    GlobalSignature m_signature{};
};

struct MNAUTHVerificationState;

/**
 * Move-only admission ticket and verification job.
 *
 * Destroying an unexecuted task releases its in-flight slot but deliberately
 * does not refund the peer attempt or replay reservation. This prevents cheap
 * cancellation loops from bypassing admission accounting.
 */
class MNAUTHVerificationTask final {
public:
    MNAUTHVerificationTask(const MNAUTHVerificationTask&) = delete;
    MNAUTHVerificationTask& operator=(const MNAUTHVerificationTask&) = delete;
    MNAUTHVerificationTask(MNAUTHVerificationTask&& other) noexcept;
    MNAUTHVerificationTask& operator=(MNAUTHVerificationTask&& other) noexcept;
    ~MNAUTHVerificationTask();

    [[nodiscard]] bool operator()();
    [[nodiscard]] bool IsActive() const noexcept { return m_active; }
    [[nodiscard]] const uint256& GetAuthorizationHash() const noexcept
    {
        return m_authorization_hash;
    }

private:
    MNAUTHVerificationTask(std::shared_ptr<MNAUTHVerificationState> state,
                           MNAUTHSignatureCheck check,
                           uint256 authorization_hash,
                           uint256 cache_key,
                           uint64_t expires_at);
    void Abandon() noexcept;

    std::shared_ptr<MNAUTHVerificationState> m_state;
    std::unique_ptr<MNAUTHSignatureCheck> m_check;
    uint256 m_authorization_hash;
    uint256 m_cache_key;
    uint64_t m_expires_at{0};
    bool m_active{false};

    friend class MNAUTHVerificationManager;
};

using MNAUTHCheckQueue = CCheckQueue<MNAUTHVerificationTask>;

/** Execute admitted tasks serially or through a caller-owned check queue. */
[[nodiscard]] bool VerifyMNAUTHTasks(
    std::vector<MNAUTHVerificationTask>&& tasks,
    MNAUTHCheckQueue* queue = nullptr);

/**
 * Thread-safe bounded admission, replay, and success-cache state.
 *
 * A peer id represents one live connection. Call ForgetPeer() on disconnect;
 * until then, exactly one MNAUTH attempt is admitted for that connection.
 */
class MNAUTHVerificationManager final {
public:
    explicit MNAUTHVerificationManager(MNAUTHRuntimeConfig config = {});

    MNAUTHVerificationManager(const MNAUTHVerificationManager&) = delete;
    MNAUTHVerificationManager& operator=(const MNAUTHVerificationManager&) = delete;

    [[nodiscard]] std::optional<MNAUTHVerificationTask> Prepare(
        int64_t peer_id,
        uint64_t source_key,
        const uint256& genesis_hash,
        const GlobalKeyRecord& initiator_key,
        const GlobalKeyRecord& responder_key,
        const MNAUTHTranscript& transcript,
        MNAUTHSignerRole expected_signer_role,
        uint64_t required_service_flags,
        const PQMNAUTHMessage& message,
        uint64_t now_seconds,
        MNAUTHVerificationError* error = nullptr);

    /** Remove per-connection state. Replay and rate records remain bounded. */
    void ForgetPeer(int64_t peer_id) noexcept;

    [[nodiscard]] MNAUTHRuntimeStats GetStats() const noexcept;

    /** Diagnostic/cache-layer lookup; never substitutes for replay admission. */
    [[nodiscard]] bool HasCachedSuccess(
        const uint256& authorization_hash,
        const GlobalSignature& signature) const noexcept;

private:
    std::shared_ptr<MNAUTHVerificationState> m_state;
};

enum class MNAUTHSigningAdmissionError : uint8_t {
    NONE = 0,
    INVALID_CONFIGURATION,
    INVALID_TIME,
    INVALID_IDENTITY,
    SOURCE_STATE_LIMIT,
    IDENTITY_STATE_LIMIT,
    RATE_LIMIT,
};

/**
 * Reconnect-resistant admission for locally generated global-SLH proofs.
 *
 * Callers must establish that attributed_pro_tx_hash is either authenticated
 * by a verified proof on this connection or attributed to the exact outbound
 * deterministic-masternode service. The limiter deliberately has no API that
 * accepts an unauthenticated wire claim as a rate key.
 */
struct MNAUTHSigningRuntimeConfig {
    std::size_t max_source_records{1'024};
    std::size_t max_identity_records{1'024};
    // One SLH-DSA signer sustains roughly nine signatures per minute on the
    // reference host. Admission stays below that measured service rate.
    uint32_t global_attempts_per_window{8};
    uint32_t source_attempts_per_window{2};
    uint32_t identity_attempts_per_window{2};
    uint64_t rate_window_seconds{60};

    [[nodiscard]] bool IsValid() const noexcept;
};

struct MNAUTHSigningRuntimeStats {
    std::size_t source_records{0};
    std::size_t identity_records{0};
};

struct MNAUTHSigningAdmissionState;

class MNAUTHSigningAdmissionManager final {
public:
    explicit MNAUTHSigningAdmissionManager(
        MNAUTHSigningRuntimeConfig config = {});

    MNAUTHSigningAdmissionManager(const MNAUTHSigningAdmissionManager&) =
        delete;
    MNAUTHSigningAdmissionManager& operator=(
        const MNAUTHSigningAdmissionManager&) = delete;

    [[nodiscard]] bool Admit(
        uint64_t source_key,
        const uint256& attributed_pro_tx_hash,
        uint64_t now_seconds,
        MNAUTHSigningAdmissionError* error = nullptr);

    [[nodiscard]] MNAUTHSigningRuntimeStats GetStats() const noexcept;

private:
    std::shared_ptr<MNAUTHSigningAdmissionState> m_state;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_MNAUTH_H
