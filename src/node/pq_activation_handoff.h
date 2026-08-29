// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_PQ_ACTIVATION_HANDOFF_H
#define SYSCOIN_NODE_PQ_ACTIVATION_HANDOFF_H

#include <consensus/pq_migration_config.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <limits>
#include <optional>

namespace node {

enum class PQActivationHandoffState : uint8_t {
    HISTORICAL_REPLAY = 1,
    PINNED = 2,
    FAILED = 3,
};

/** Durable local provenance for the BLS-free activation handoff. */
struct PQActivationHandoffRecord {
    static constexpr uint8_t VERSION{1};

    uint8_t version{VERSION};
    PQActivationHandoffState state{
        PQActivationHandoffState::HISTORICAL_REPLAY};
    int32_t activation_height{-1};
    uint256 predecessor_hash;

    SERIALIZE_METHODS(PQActivationHandoffRecord, obj)
    {
        uint8_t state{static_cast<uint8_t>(obj.state)};
        READWRITE(obj.version, state, obj.activation_height,
                  obj.predecessor_hash);
        SER_READ(obj, if (state < static_cast<uint8_t>(
                                  PQActivationHandoffState::HISTORICAL_REPLAY) ||
                          state > static_cast<uint8_t>(
                                  PQActivationHandoffState::FAILED)) {
            throw std::ios_base::failure(
                "invalid PQ activation handoff state");
        });
        SER_READ(obj, obj.state =
            static_cast<PQActivationHandoffState>(state));
    }

    [[nodiscard]] bool IsValid(int32_t expected_activation_height) const
    {
        if (version != VERSION || activation_height <= 0 ||
            activation_height == std::numeric_limits<int32_t>::max() ||
            activation_height != expected_activation_height) {
            return false;
        }
        switch (state) {
        case PQActivationHandoffState::HISTORICAL_REPLAY:
            return predecessor_hash.IsNull();
        case PQActivationHandoffState::PINNED:
            return !predecessor_hash.IsNull();
        case PQActivationHandoffState::FAILED:
            return true;
        }
        return false;
    }
};

enum class PQActivationRuntimeState : uint8_t {
    BYPASS = 0,
    SYNC_ONLY,
    DEFERRED_HANDOFF,
    HISTORICAL_REPLAY,
    PINNED,
    FAILED,
};

struct PQActivationHandoffResolution {
    PQActivationRuntimeState state{PQActivationRuntimeState::FAILED};
    std::optional<PQActivationHandoffRecord> record_to_write;
};

struct PQActivationHandoffTip {
    int32_t height{-1};
    uint256 predecessor_hash;
    uint256 active_predecessor_hash;
    bool predecessor_fully_validated{false};
    bool activation_fully_validated{false};
};

inline bool IsPQActivationHandoffActiveView(
    bool candidate_is_active_tip,
    bool candidate_extends_active_tip) noexcept
{
    return candidate_is_active_tip || candidate_extends_active_tip;
}

/** Resolve persistent state before any chainstate replay occurs. */
inline PQActivationHandoffResolution PreparePQActivationHandoff(
    const Consensus::Params& params,
    bool public_network,
    bool force_historical_replay,
    bool empty_chainstate,
    const std::optional<PQActivationHandoffRecord>& persisted)
{
    if (!public_network) {
        return {PQActivationRuntimeState::BYPASS, std::nullopt};
    }
    const auto deployment{Consensus::CheckPQActivationConfiguration(params)};
    if (deployment == Consensus::PQActivationResult::DISABLED) {
        return {PQActivationRuntimeState::SYNC_ONLY, std::nullopt};
    }
    if (deployment != Consensus::PQActivationResult::VALID) {
        return {PQActivationRuntimeState::FAILED, std::nullopt};
    }

    if (force_historical_replay || empty_chainstate) {
        return {
            PQActivationRuntimeState::HISTORICAL_REPLAY,
            PQActivationHandoffRecord{
                PQActivationHandoffRecord::VERSION,
                PQActivationHandoffState::HISTORICAL_REPLAY,
                params.nPQActivationHeight,
                {}}};
    }
    if (!persisted) {
        return {PQActivationRuntimeState::DEFERRED_HANDOFF, std::nullopt};
    }
    if (!persisted->IsValid(params.nPQActivationHeight)) {
        return {PQActivationRuntimeState::FAILED, std::nullopt};
    }
    switch (persisted->state) {
    case PQActivationHandoffState::HISTORICAL_REPLAY:
        return {PQActivationRuntimeState::HISTORICAL_REPLAY, std::nullopt};
    case PQActivationHandoffState::PINNED:
        return {PQActivationRuntimeState::DEFERRED_HANDOFF, std::nullopt};
    case PQActivationHandoffState::FAILED:
        return {PQActivationRuntimeState::FAILED, std::nullopt};
    }
    return {PQActivationRuntimeState::FAILED, std::nullopt};
}

/** Resolve the recovered or newly validated tip without trusting its height alone. */
inline PQActivationHandoffResolution FinalizePQActivationHandoff(
    const Consensus::Params& params,
    PQActivationRuntimeState runtime_state,
    const std::optional<PQActivationHandoffRecord>& persisted,
    const PQActivationHandoffTip& tip)
{
    if (runtime_state == PQActivationRuntimeState::BYPASS ||
        runtime_state == PQActivationRuntimeState::SYNC_ONLY ||
        runtime_state == PQActivationRuntimeState::FAILED ||
        runtime_state == PQActivationRuntimeState::PINNED) {
        return {runtime_state, std::nullopt};
    }
    if (Consensus::CheckPQActivationConfiguration(params) !=
        Consensus::PQActivationResult::VALID) {
        return {PQActivationRuntimeState::FAILED, std::nullopt};
    }

    const int32_t predecessor_height{params.nPQActivationHeight - 1};
    const bool usable_predecessor{
        tip.height >= predecessor_height &&
        tip.predecessor_fully_validated &&
        !tip.predecessor_hash.IsNull() &&
        tip.active_predecessor_hash == tip.predecessor_hash};
    if (runtime_state == PQActivationRuntimeState::HISTORICAL_REPLAY) {
        if (tip.height < params.nPQActivationHeight ||
            !tip.activation_fully_validated) {
            return {runtime_state, std::nullopt};
        }
        if (!usable_predecessor) {
            return {
                PQActivationRuntimeState::FAILED,
                PQActivationHandoffRecord{
                    PQActivationHandoffRecord::VERSION,
                    PQActivationHandoffState::FAILED,
                    params.nPQActivationHeight,
                    {}}};
        }
        return {
            PQActivationRuntimeState::PINNED,
            PQActivationHandoffRecord{
                PQActivationHandoffRecord::VERSION,
                PQActivationHandoffState::PINNED,
                params.nPQActivationHeight,
                tip.predecessor_hash}};
    }

    if (runtime_state != PQActivationRuntimeState::DEFERRED_HANDOFF) {
        return {PQActivationRuntimeState::FAILED, std::nullopt};
    }
    // A release must be deployable before the announced activation height.
    // There is no predecessor to authenticate yet, so remain quarantined and
    // retry as the active tip advances instead of poisoning the durable state.
    if (tip.height < predecessor_height) {
        return {PQActivationRuntimeState::DEFERRED_HANDOFF, std::nullopt};
    }
    // A legacy-capable release can establish the handoff at A-1. Above the
    // boundary, strong block provenance is meaningful only together with the
    // pin this activation release necessarily wrote before connecting A.
    if (!usable_predecessor ||
        (tip.height >= params.nPQActivationHeight &&
         (!persisted || !tip.activation_fully_validated))) {
        return {
            PQActivationRuntimeState::FAILED,
            PQActivationHandoffRecord{
                PQActivationHandoffRecord::VERSION,
                PQActivationHandoffState::FAILED,
                params.nPQActivationHeight,
                persisted ? persisted->predecessor_hash : uint256{}}};
    }
    if (persisted &&
        persisted->state == PQActivationHandoffState::PINNED &&
        persisted->predecessor_hash != tip.predecessor_hash &&
        tip.height == predecessor_height) {
        // The block-tree pin can outrun the chainstate tip across a crash.
        // Reaching a different fully validated A-1 is therefore an ordinary
        // pre-finality PoW replacement, not evidence of corruption. Burn the
        // stale hash before connecting A; only A's full validation may pin the
        // replacement branch.
        return {
            PQActivationRuntimeState::HISTORICAL_REPLAY,
            PQActivationHandoffRecord{
                PQActivationHandoffRecord::VERSION,
                PQActivationHandoffState::HISTORICAL_REPLAY,
                params.nPQActivationHeight,
                {}}};
    }
    if (persisted &&
        (persisted->state != PQActivationHandoffState::PINNED ||
         persisted->predecessor_hash != tip.predecessor_hash)) {
        return {
            PQActivationRuntimeState::FAILED,
            PQActivationHandoffRecord{
                PQActivationHandoffRecord::VERSION,
                PQActivationHandoffState::FAILED,
                params.nPQActivationHeight,
                persisted->predecessor_hash}};
    }
    if (persisted) {
        return {PQActivationRuntimeState::PINNED, std::nullopt};
    }
    return {
        PQActivationRuntimeState::PINNED,
        PQActivationHandoffRecord{
            PQActivationHandoffRecord::VERSION,
            PQActivationHandoffState::PINNED,
            params.nPQActivationHeight,
            tip.predecessor_hash}};
}

/**
 * Keep ordinary participation quarantined while allowing the one block that
 * completes a fully reconstructed activation handoff. The caller must bind
 * these facts to one stable active tip under cs_main.
 */
inline bool IsPQActivationBlockProductionAllowed(
    const Consensus::Params& params,
    PQActivationRuntimeState runtime_state,
    bool participation_allowed,
    bool durable_replay_marker,
    int32_t active_tip_height,
    bool active_tip_fully_validated,
    bool local_state_usable,
    bool durable_finality_clear) noexcept
{
    if (participation_allowed) return true;
    return Consensus::CheckPQActivationConfiguration(params) ==
               Consensus::PQActivationResult::VALID &&
           runtime_state == PQActivationRuntimeState::HISTORICAL_REPLAY &&
           durable_replay_marker &&
           active_tip_height == params.nPQActivationHeight - 1 &&
           active_tip_fully_validated && local_state_usable &&
           durable_finality_clear;
}

inline bool DisconnectCrossesPQActivationHandoff(
    const Consensus::Params& params,
    PQActivationRuntimeState runtime_state,
    const std::optional<PQActivationHandoffRecord>& persisted,
    int32_t disconnect_height,
    const uint256& disconnect_hash)
{
    return Consensus::CheckPQActivationConfiguration(params) ==
               Consensus::PQActivationResult::VALID &&
           runtime_state == PQActivationRuntimeState::PINNED && persisted &&
           persisted->state == PQActivationHandoffState::PINNED &&
           disconnect_height == params.nPQActivationHeight - 1 &&
           disconnect_hash == persisted->predecessor_hash;
}

/**
 * Quarantine before replacing the locally pinned predecessor. The durable
 * null marker must be written before chainstate mutation; a replacement pin
 * is authorized only after this process fully validates the new block A.
 */
inline PQActivationHandoffResolution ResolvePQActivationHandoffDisconnect(
    const Consensus::Params& params,
    PQActivationRuntimeState runtime_state,
    const std::optional<PQActivationHandoffRecord>& persisted,
    int32_t disconnect_height,
    const uint256& disconnect_hash)
{
    if (!DisconnectCrossesPQActivationHandoff(
            params, runtime_state, persisted, disconnect_height,
            disconnect_hash)) {
        return {runtime_state, std::nullopt};
    }
    return {
        PQActivationRuntimeState::HISTORICAL_REPLAY,
        PQActivationHandoffRecord{
            PQActivationHandoffRecord::VERSION,
            PQActivationHandoffState::HISTORICAL_REPLAY,
            params.nPQActivationHeight,
            {}}};
}

} // namespace node

#endif // SYSCOIN_NODE_PQ_ACTIVATION_HANDOFF_H
