// Copyright (c) 2019 The Dash Core developers
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_MNAUTH_TYPES_H
#define SYSCOIN_EVO_MNAUTH_TYPES_H

#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>

inline constexpr uint16_t PQ_MNAUTH_VERSION_DATA_VERSION{1};

enum class CMNAuthPendingPhase : uint8_t {
    NONE = 0,
    AWAITING_REMOTE,
    VERIFY_PENDING,
    SIGN_PENDING,
    COMPLETE,
};

/** Monotonic deadline owned by the connection's exact MNAUTH attempt. */
struct CMNAuthPendingState {
    CMNAuthPendingPhase phase{CMNAuthPendingPhase::NONE};
    int64_t deadline_micros{0};

    [[nodiscard]] bool IsPending() const noexcept
    {
        return phase == CMNAuthPendingPhase::AWAITING_REMOTE ||
               phase == CMNAuthPendingPhase::VERIFY_PENDING ||
               phase == CMNAuthPendingPhase::SIGN_PENDING;
    }

    [[nodiscard]] bool IsLiveAt(int64_t now_micros) const noexcept
    {
        return IsPending() && now_micros >= 0 && deadline_micros > 0 &&
               now_micros < deadline_micros;
    }
};

/** Process-wide bounded MNAUTH executor counters exposed through RPC. */
struct CMNAuthAsyncStats {
    std::size_t verify_queue_depth{0};
    std::size_t sign_queue_depth{0};
    std::size_t initiator_sign_queue_depth{0};
    std::size_t responder_sign_queue_depth{0};
    std::size_t completion_queue_depth{0};
    std::size_t verify_inflight{0};
    std::size_t sign_inflight{0};
    uint64_t verify_completed{0};
    uint64_t sign_completed{0};
    uint64_t verify_failed{0};
    uint64_t sign_failed{0};
    uint64_t verify_saturation_drops{0};
    uint64_t sign_saturation_drops{0};
    uint64_t initiator_sign_saturation_drops{0};
    uint64_t responder_sign_saturation_drops{0};
    uint64_t verify_expired_before_execution{0};
    uint64_t sign_expired_before_execution{0};
    uint64_t preverify_rate_limit_drops{0};
    uint64_t sign_rate_limit_drops{0};
    uint64_t cancelled_jobs{0};
    uint64_t stale_completion_drops{0};
    uint64_t completion_backpressure_events{0};
    uint64_t verify_latency_total_micros{0};
    uint64_t verify_latency_max_micros{0};
    uint64_t sign_latency_total_micros{0};
    uint64_t sign_latency_max_micros{0};
};

/**
 * Authenticated identity claim appended to VERSION.
 *
 * A zero identity denotes a regular node. The random cookie is mandatory for
 * every peer and makes an otherwise repeated VERSION tuple connection-unique.
 * Identity fields are only claims until the MNAUTH signature is checked
 * against the exact active-tip PQ registry snapshot.
 */
struct CMNAuthVersionData {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + 32 + sizeof(uint32_t) + 32};

    uint16_t version{PQ_MNAUTH_VERSION_DATA_VERSION};
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    uint256 cookie;

    SERIALIZE_METHODS(CMNAuthVersionData, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ MNAUTH VERSION data");
        });
        READWRITE(obj.version, obj.pro_tx_hash, obj.global_key_version,
                  obj.cookie);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ MNAUTH VERSION data");
        });
    }

    [[nodiscard]] bool HasMasternodeIdentity() const noexcept
    {
        return !pro_tx_hash.IsNull();
    }
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const CMNAuthVersionData&,
                           const CMNAuthVersionData&) = default;
};

/**
 * SYSCOIN: Immutable inputs captured from the bidirectional VERSION exchange.
 * The transport stores this passive value type without depending on the live
 * MNAUTH handler, avoiding a net <-> authentication implementation cycle.
 */
struct CMNAuthConnectionData {
    CMNAuthVersionData local;
    CMNAuthVersionData remote;
    uint256 local_challenge;
    uint256 remote_challenge;
    uint64_t local_version_nonce{0};
    uint64_t remote_version_nonce{0};
    uint32_t local_protocol_version{0};
    uint32_t remote_protocol_version{0};
    uint64_t local_service_flags{0};
    uint64_t remote_service_flags{0};
    bool has_local{false};
    bool has_remote{false};

    [[nodiscard]] bool IsComplete() const noexcept;
    friend bool operator==(const CMNAuthConnectionData&,
                           const CMNAuthConnectionData&) = default;
};

#endif // SYSCOIN_EVO_MNAUTH_TYPES_H
