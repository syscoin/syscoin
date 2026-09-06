// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_recovery_refresh.h>

#include <arith_uint256.h>
#include <auxpow.h>
#include <chain.h>
#include <consensus/params.h>
#include <llmq/pq_roster_beacon.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <version.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace llmq::pq {
namespace {

constexpr uint64_t GROUP_BLOCKS{ACTIVE_QUORUMS * PQ_EPOCH_BLOCKS};
constexpr uint64_t MAX_GROUP{(std::numeric_limits<uint32_t>::max() -
                            (ACTIVE_QUORUMS - 1)) / ACTIVE_QUORUMS};
constexpr uint8_t WORK_MAGIC[]{'p', 'q', 'r', 'w'};

bool HasWorkDepth(const CBlockIndex& start, const CBlockIndex& end,
                  uint32_t minimum_blocks) noexcept
{
    if (minimum_blocks == 0 || end.nHeight <= start.nHeight ||
        end.GetAncestor(start.nHeight) != &start ||
        end.nChainWork <= start.nChainWork) return false;
    const arith_uint256 unit{GetBlockProof(start)};
    const arith_uint256 maximum{~arith_uint256{0}};
    if (unit == 0 || unit > maximum / arith_uint256{minimum_blocks}) return false;
    return end.nChainWork - start.nChainWork >= unit * minimum_blocks;
}

template <typename T>
std::vector<uint8_t> Encode(const T& object)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << object;
    return {UCharCast(stream.data()), UCharCast(stream.data() + stream.size())};
}

} // namespace

bool RecoveryRefreshConfig::IsDisabled() const noexcept
{
    return *this == RecoveryRefreshConfig{};
}

bool RecoveryRefreshConfig::IsValid(const ChainLockScheduleConfig& chainlock,
                                   const BTCCScheduleConfig& btcc) const noexcept
{
    if (IsDisabled()) return true;
    if (!chainlock.IsValid() || !btcc.IsValid() || activation_height < 0 ||
        grace_groups != 1 || snapshot_lag_blocks == 0 ||
        entropy_delay_blocks == 0 || carrier_delay_blocks == 0 ||
        carrier_min_depth_blocks == 0 || snapshot_min_work_blocks == 0 ||
        carrier_min_work_blocks == 0 || readiness_window_blocks == 0 ||
        readiness_window_blocks >= GROUP_BLOCKS) return false;
    // Nonoverlapping readiness windows prevent one declaration from serving as
    // a reusable liveness claim for several independently selected attempts.
    const uint64_t available{(ACTIVE_QUORUMS - 1) * chainlock.epoch_blocks +
                             uint64_t{snapshot_lag_blocks}};
    const uint64_t required{uint64_t{entropy_delay_blocks} + carrier_delay_blocks +
                            carrier_min_depth_blocks + chainlock.sign_lag};
    return required <= available;
}

RecoveryRefreshConfig GetRecoveryRefreshConfig(const Consensus::Params& consensus) noexcept
{
    return RecoveryRefreshConfig{
        .activation_height = consensus.nPQRecoveryRefreshActivationHeight,
        .grace_groups = consensus.nPQRecoveryRefreshGraceGroups,
        .snapshot_lag_blocks = consensus.nPQRecoveryRefreshSnapshotLagBlocks,
        .entropy_delay_blocks = consensus.nPQRecoveryRefreshEntropyDelayBlocks,
        .carrier_delay_blocks = consensus.nPQRecoveryRefreshCarrierDelayBlocks,
        .carrier_min_depth_blocks = consensus.nPQRecoveryRefreshCarrierMinDepthBlocks,
        .snapshot_min_work_blocks = consensus.nPQRecoveryRefreshSnapshotMinWorkBlocks,
        .carrier_min_work_blocks = consensus.nPQRecoveryRefreshCarrierMinWorkBlocks,
        .readiness_window_blocks = consensus.nPQRecoveryReadinessWindowBlocks,
    };
}

std::optional<RecoveryRefreshCoordinates> DeriveRecoveryRefreshCoordinates(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, uint32_t group) noexcept
{
    if (config.IsDisabled() || !config.IsValid(chainlock, btcc) || group > MAX_GROUP) {
        return std::nullopt;
    }
    const auto first_epoch{static_cast<uint32_t>(uint64_t{group} * ACTIVE_QUORUMS)};
    const auto first_base{EpochBaseHeight(chainlock, first_epoch)};
    const auto target{CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, first_epoch + ACTIVE_QUORUMS - 1)};
    if (!first_base || !target || *target < config.activation_height) return std::nullopt;
    const int64_t snapshot{int64_t{*first_base} - config.snapshot_lag_blocks};
    const int64_t reference{snapshot - config.readiness_window_blocks};
    const int64_t entropy{snapshot + config.entropy_delay_blocks};
    const int64_t carrier{entropy + config.carrier_delay_blocks};
    const int64_t authority{int64_t{*target} - chainlock.sign_lag};
    if (reference < config.activation_height || snapshot <= reference || entropy <= snapshot ||
        carrier <= entropy || carrier + config.carrier_min_depth_blocks > authority) {
        return std::nullopt;
    }
    return RecoveryRefreshCoordinates{
        group, first_epoch, static_cast<int32_t>(reference), static_cast<int32_t>(snapshot),
        static_cast<int32_t>(entropy), static_cast<int32_t>(carrier), *target,
        static_cast<int32_t>(authority)};
}

std::optional<RecoveryRefreshCoordinates> RecoveryRefreshCoordinatesForCarrierHeight(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t carrier_height) noexcept
{
    if (carrier_height < 0 || config.IsDisabled() || !config.IsValid(chainlock, btcc)) {
        return std::nullopt;
    }
    const int64_t offset{int64_t{carrier_height} - chainlock.epoch_origin +
        config.snapshot_lag_blocks - config.entropy_delay_blocks - config.carrier_delay_blocks};
    if (offset < 0 || static_cast<uint64_t>(offset) % GROUP_BLOCKS != 0 ||
        static_cast<uint64_t>(offset) / GROUP_BLOCKS > MAX_GROUP) return std::nullopt;
    auto coordinates{DeriveRecoveryRefreshCoordinates(
        chainlock, btcc, config, static_cast<uint32_t>(offset / GROUP_BLOCKS))};
    return coordinates && coordinates->carrier_height == carrier_height
        ? coordinates : std::nullopt;
}

std::optional<uint32_t> FirstStaleRecoveryGroup(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    int32_t latest_receipted_target_height) noexcept
{
    if (!btcc.IsValid() || !IsEligibleChainLockTarget(chainlock, latest_receipted_target_height)) {
        return std::nullopt;
    }
    const auto epoch{EpochForHeight(chainlock, latest_receipted_target_height)};
    if (!epoch) return std::nullopt;
    const uint64_t group{(uint64_t{*epoch} + 2) / ACTIVE_QUORUMS};
    if (group > MAX_GROUP) return std::nullopt;
    const auto target{CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, static_cast<uint32_t>(group * ACTIVE_QUORUMS + ACTIVE_QUORUMS - 1))};
    return target ? std::optional<uint32_t>{static_cast<uint32_t>(group)} : std::nullopt;
}

std::optional<RecoveryRefreshCoordinates> RecoveryRefreshCoordinatesForSnapshotHeight(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t snapshot_height) noexcept
{
    if (snapshot_height < 0 || config.IsDisabled() || !config.IsValid(chainlock, btcc)) {
        return std::nullopt;
    }
    const int64_t offset{int64_t{snapshot_height} - chainlock.epoch_origin + config.snapshot_lag_blocks};
    if (offset < 0 || static_cast<uint64_t>(offset) % GROUP_BLOCKS != 0 ||
        static_cast<uint64_t>(offset) / GROUP_BLOCKS > MAX_GROUP) return std::nullopt;
    auto coordinates{DeriveRecoveryRefreshCoordinates(
        chainlock, btcc, config, static_cast<uint32_t>(offset / GROUP_BLOCKS))};
    return coordinates && coordinates->snapshot_height == snapshot_height
        ? coordinates : std::nullopt;
}

std::optional<RecoveryRefreshMode> GetRecoveryRefreshMode(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, int32_t target_height,
    int32_t latest_receipted_target_height) noexcept
{
    if (!config.IsValid(chainlock, btcc)) return std::nullopt;
    const auto epoch{EpochForHeight(chainlock, target_height)};
    if (!epoch || GetObjectiveRosterAuthorizationMode(chainlock, btcc, *epoch,
            target_height, latest_receipted_target_height) !=
            ObjectiveRosterAuthorizationMode::RECOVER) return std::nullopt;
    if (config.IsDisabled() || target_height < config.activation_height) {
        return RecoveryRefreshMode::FROZEN_SOURCE;
    }
    const auto first{FirstStaleRecoveryGroup(chainlock, btcc, latest_receipted_target_height)};
    if (!first) return std::nullopt;
    const auto group{static_cast<uint32_t>(*epoch / ACTIVE_QUORUMS)};
    if (uint64_t{group} < uint64_t{*first} + config.grace_groups) {
        return RecoveryRefreshMode::FROZEN_SOURCE;
    }
    if (!DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, group)) return std::nullopt;
    return RecoveryRefreshMode::POW_REFRESHED_SOURCE;
}

bool ValidateRecoveryRefreshWorkDepth(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& authority_anchor) noexcept
{
    if (DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, coordinates.group) != coordinates ||
        authority_anchor.nHeight != coordinates.authority_height) return false;
    const auto* snapshot{authority_anchor.GetAncestor(coordinates.snapshot_height)};
    const auto* entropy{authority_anchor.GetAncestor(coordinates.entropy_height)};
    const auto* carrier{authority_anchor.GetAncestor(coordinates.carrier_height)};
    return snapshot && entropy && carrier &&
        HasWorkDepth(*snapshot, *entropy, config.snapshot_min_work_blocks) &&
        HasWorkDepth(*carrier, authority_anchor, config.carrier_min_work_blocks);
}

bool RecoveryRefreshWorkCommitment::IsStructurallyValid() const noexcept
{
    return version == RECOVERY_REFRESH_WORK_VERSION && group <= MAX_GROUP &&
        !entropy_block_hash.IsNull() && !parent_work_hash.IsNull() &&
        !proof.empty() && proof.size() <= RECOVERY_REFRESH_MAX_PROOF_BYTES;
}

std::optional<RecoveryRefreshWorkCommitment> DecodeRecoveryRefreshWorkCommitment(
    Span<const uint8_t> payload)
{
    if (payload.empty() || payload.size() > RECOVERY_REFRESH_MAX_COMMITMENT_BYTES) return std::nullopt;
    try {
        SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, payload};
        RecoveryRefreshWorkCommitment result;
        reader >> result.version >> result.group >> result.entropy_block_hash >> result.parent_work_hash;
        const uint64_t proof_size{ReadCompactSize(reader)};
        if (proof_size == 0 || proof_size > RECOVERY_REFRESH_MAX_PROOF_BYTES ||
            proof_size != reader.size()) return std::nullopt;
        result.proof.resize(proof_size);
        reader.read(AsWritableBytes(Span{result.proof}));
        if (!result.IsStructurallyValid()) return std::nullopt;
        return result;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::vector<uint8_t>> EncodeRecoveryRefreshWorkCommitment(
    const RecoveryRefreshWorkCommitment& commitment)
{
    if (!commitment.IsStructurallyValid()) return std::nullopt;
    return Encode(commitment);
}

bool ExtractRecoveryRefreshWorkCommitment(
    const CBlock& block, std::optional<RecoveryRefreshWorkCommitment>& commitment)
{
    commitment.reset();
    if (block.vtx.empty() || !block.vtx.front()) return false;
    for (const auto& output : block.vtx.front()->vout) {
        std::vector<uint8_t> data;
        if (!GetSyscoinData(output.scriptPubKey, data)) continue;
        const auto found{std::search(data.begin(), data.end(), std::begin(WORK_MAGIC), std::end(WORK_MAGIC))};
        if (found == data.end()) continue;
        if (commitment || std::search(found + sizeof(WORK_MAGIC), data.end(),
                std::begin(WORK_MAGIC), std::end(WORK_MAGIC)) != data.end()) return false;
        const auto offset{static_cast<std::size_t>(found - data.begin()) + sizeof(WORK_MAGIC)};
        try {
            SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, Span{data}.subspan(offset)};
            uint32_t size{0};
            reader >> size;
            if (size == 0 || size > RECOVERY_REFRESH_MAX_COMMITMENT_BYTES || size > reader.size()) return false;
            auto decoded{DecodeRecoveryRefreshWorkCommitment(
                Span{data}.subspan(offset + sizeof(size), size))};
            if (!decoded) return false;
            commitment = std::move(decoded);
        } catch (const std::exception&) {
            return false;
        }
    }
    return true;
}

bool AppendRecoveryRefreshWorkCommitment(
    std::vector<uint8_t>& coinbase_extra, const RecoveryRefreshWorkCommitment& commitment)
{
    auto payload{EncodeRecoveryRefreshWorkCommitment(commitment)};
    // A valid parent proof can contain a receipt tag in its opaque coinbase.
    // The existing tail scanner would reject G at a non-receipt height, so
    // omit that optional sample instead of stalling mining.
    if (!payload || std::search(payload->begin(), payload->end(),
            std::begin(WORK_MAGIC), std::end(WORK_MAGIC)) != payload->end() ||
        std::search(payload->begin(), payload->end(),
            std::begin(BTCC_RECEIPT_MAGIC_BYTES),
            std::end(BTCC_RECEIPT_MAGIC_BYTES)) != payload->end() ||
        std::search(coinbase_extra.begin(), coinbase_extra.end(),
            std::begin(WORK_MAGIC), std::end(WORK_MAGIC)) != coinbase_extra.end()) return false;
    CDataStream frame{SER_NETWORK, PROTOCOL_VERSION};
    frame << WORK_MAGIC << static_cast<uint32_t>(payload->size());
    const auto bytes{MakeUCharSpan(frame)};
    coinbase_extra.insert(coinbase_extra.end(), bytes.begin(), bytes.end());
    coinbase_extra.insert(coinbase_extra.end(), payload->begin(), payload->end());
    return true;
}

ValidatedRecoveryRefreshWorkSample::ValidatedRecoveryRefreshWorkSample(
    uint32_t group, uint256 snapshot_hash, uint256 entropy_hash, uint256 carrier_hash,
    uint256 parent_work_hash, uint256 commitment_hash)
    : m_group{group}, m_snapshot_hash{std::move(snapshot_hash)},
      m_entropy_hash{std::move(entropy_hash)}, m_carrier_hash{std::move(carrier_hash)},
      m_parent_work_hash{std::move(parent_work_hash)}, m_commitment_hash{std::move(commitment_hash)}
{
}

std::optional<ValidatedRecoveryRefreshWorkSample> VerifyRecoveryRefreshWorkCommitment(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& carrier, const RecoveryRefreshWorkCommitment& commitment,
    const Consensus::Params& consensus)
{
    if (DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, coordinates.group) != coordinates ||
        carrier.nHeight != coordinates.carrier_height || commitment.group != coordinates.group ||
        !commitment.IsStructurallyValid()) return std::nullopt;
    const auto* entropy{carrier.GetAncestor(coordinates.entropy_height)};
    const auto* snapshot{carrier.GetAncestor(coordinates.snapshot_height)};
    if (!entropy || !snapshot || entropy->GetBlockHash() != commitment.entropy_block_hash) return std::nullopt;
    const auto header{entropy->GetBlockHeader()};
    if (!header.IsAuxpow() || header.GetHash() != entropy->GetBlockHash()) return std::nullopt;
    try {
        SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, commitment.proof};
        CAuxPow proof;
        reader >> proof;
        // Legacy AuxPoW decoding discards two redundant fields. Canonical
        // re-encoding also rejects alternate encodings of this new commitment.
        if (!reader.empty() || Encode(proof) != commitment.proof || !proof.getCoinbaseTx() ||
            proof.getParentBlockHash() != commitment.parent_work_hash ||
            !CheckProofOfWork(proof.getParentBlockHash(), entropy->nBits, consensus) ||
            !proof.check(entropy->GetBlockHash(), header.GetChainId(), consensus)) return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    const uint256 commitment_hash{TaggedHash("SYS_PQ_RECOVERY_WORK_COMMITMENT_V1",
        consensus.hashGenesisBlock, commitment)};
    return ValidatedRecoveryRefreshWorkSample{coordinates.group, snapshot->GetBlockHash(),
        entropy->GetBlockHash(), carrier.GetBlockHash(), commitment.parent_work_hash, commitment_hash};
}

std::optional<uint256> GetRecoveryRefreshEntropyHash(
    const uint256& genesis_hash, const uint256& universe_root, uint32_t group,
    const uint256& snapshot_hash, const uint256& entropy_block_hash,
    const uint256& parent_work_hash)
{
    if (genesis_hash.IsNull() || universe_root.IsNull() || group > MAX_GROUP ||
        snapshot_hash.IsNull() || entropy_block_hash.IsNull() || parent_work_hash.IsNull()) {
        return std::nullopt;
    }
    return TaggedHash("SYS_PQ_RECOVERY_REFRESH_V1", genesis_hash, group,
        snapshot_hash, universe_root, entropy_block_hash, parent_work_hash);
}

std::optional<ValidatedRecoveryRefreshWorkSample> ValidateIndexedRecoveryRefreshWork(
    const ChainLockScheduleConfig& chainlock, const BTCCScheduleConfig& btcc,
    const RecoveryRefreshConfig& config, const RecoveryRefreshCoordinates& coordinates,
    const CBlockIndex& authority_anchor)
{
    LOCK(::cs_main);
    if (!ValidateRecoveryRefreshWorkDepth(chainlock, btcc, config, coordinates, authority_anchor)) {
        return std::nullopt;
    }
    const auto* carrier{authority_anchor.GetAncestor(coordinates.carrier_height)};
    const auto* snapshot{authority_anchor.GetAncestor(coordinates.snapshot_height)};
    const auto* entropy{authority_anchor.GetAncestor(coordinates.entropy_height)};
    if (!carrier || !snapshot || !entropy ||
        (carrier->nStatus & BLOCK_FAILED_MASK) || carrier->IsAssumedValid() ||
        !carrier->IsValid(BLOCK_VALID_SCRIPTS) || !carrier->pqRecoveryRefreshWorkValidated ||
        carrier->pqRecoveryRefreshGroup != coordinates.group ||
        carrier->pqRecoveryRefreshEntropyBlockHash != entropy->GetBlockHash() ||
        carrier->pqRecoveryRefreshParentWorkHash.IsNull() ||
        carrier->pqRecoveryRefreshCommitmentHash.IsNull()) return std::nullopt;
    return ValidatedRecoveryRefreshWorkSample{coordinates.group, snapshot->GetBlockHash(),
        entropy->GetBlockHash(), carrier->GetBlockHash(), carrier->pqRecoveryRefreshParentWorkHash,
        carrier->pqRecoveryRefreshCommitmentHash};
}

std::optional<uint256> GetRecoveryRefreshEntropyHash(
    const uint256& genesis_hash, const uint256& universe_root,
    const ValidatedRecoveryRefreshWorkSample& sample)
{
    return GetRecoveryRefreshEntropyHash(genesis_hash, universe_root, sample.Group(),
        sample.SnapshotHash(), sample.EntropyBlockHash(), sample.ParentWorkHash());
}

std::optional<uint256> GetRecoveryRefreshRosterModifier(
    const uint256& genesis_hash, const uint256& entropy_hash, uint32_t group, uint32_t epoch)
{
    if (genesis_hash.IsNull() || entropy_hash.IsNull() || group > MAX_GROUP ||
        epoch / ACTIVE_QUORUMS != group) return std::nullopt;
    return TaggedHash("SYS_PQ_RECOVERY_REFRESH_ROSTER_V1", genesis_hash, entropy_hash, group, epoch);
}

} // namespace llmq::pq
