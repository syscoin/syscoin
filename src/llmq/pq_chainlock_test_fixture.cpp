// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_test_fixture.h>

#include <chain.h>
#include <hash.h>
#include <logging.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <util/readwritefile.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <exception>
#include <map>
#include <memory>
#include <set>
#include <string_view>
#include <utility>

namespace llmq::pq::test {
namespace {

constexpr uint64_t FIXTURE_MAGIC{0x3158464c43515053ULL}; // "SPQCLFX1"
constexpr std::string_view FIXTURE_CHECKSUM_DOMAIN{
    "SYS_PQ_CHAINLOCK_SNAPSHOT_FIXTURE_V1"};

uint256 SyntheticMemberHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

CKeyID SyntheticMemberKeyId(uint64_t value)
{
    CKeyID key;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        key.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    key.begin()[key.size() - 1] = 0xa5;
    return key;
}

CDeterministicMNList SyntheticDeterministicMNList(
    int32_t height, const uint256& block_hash)
{
    CDeterministicMNList list{
        block_hash, height, static_cast<uint32_t>(QUORUM_SIZE)};
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        auto dmn{std::make_shared<CDeterministicMN>(member + 1)};
        dmn->proTxHash = SyntheticMemberHash(10'000 + member);
        dmn->collateralOutpoint = COutPoint(
            SyntheticMemberHash(20'000 + member),
            static_cast<uint32_t>(member + 1));
        auto state{std::make_shared<CDeterministicMNState>()};
        state->keyIDOwner = SyntheticMemberKeyId(30'000 + member);
        state->nRegisteredHeight = 100;
        state->UpdateConfirmedHash(
            dmn->proTxHash, SyntheticMemberHash(40'000 + member));
        dmn->pdmnState = std::move(state);
        list.AddMN(std::move(dmn), /*fBumpTotalCount=*/false);
    }
    return list;
}

void SetError(std::string& error, std::string message)
{
    error = std::move(message);
}

uint256 GetFixtureChecksum(Span<const uint8_t> body)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{FIXTURE_CHECKSUM_DOMAIN.data(),
                              FIXTURE_CHECKSUM_DOMAIN.size()}));
    writer.write(AsBytes(body));
    return writer.GetHash();
}

void SerializeBuildConfig(DataStream& stream,
                          const QuorumBuildConfig& config)
{
    stream << config.schedule.epoch_origin
           << config.schedule.epoch_blocks
           << config.schedule.chainlock_period
           << config.schedule.sign_lag
           << config.schedule.active_epochs
           << config.roster_snapshot_lag_blocks
           << config.registration_cutoff_blocks
           << config.future_horizon_epochs;
}

void UnserializeBuildConfig(DataStream& stream,
                            QuorumBuildConfig& config)
{
    stream >> config.schedule.epoch_origin
           >> config.schedule.epoch_blocks
           >> config.schedule.chainlock_period
           >> config.schedule.sign_lag
           >> config.schedule.active_epochs
           >> config.roster_snapshot_lag_blocks
           >> config.registration_cutoff_blocks
           >> config.future_horizon_epochs;
}

void SerializeBranchPoint(DataStream& stream,
                          const FixtureBranchPoint& point)
{
    stream << point.height << point.block_hash;
}

void UnserializeBranchPoint(DataStream& stream,
                            FixtureBranchPoint& point)
{
    stream >> point.height >> point.block_hash;
}

void SerializeFixtureBody(DataStream& stream,
                          const QuorumSnapshotFixture& fixture)
{
    stream << FIXTURE_MAGIC << QUORUM_SNAPSHOT_FIXTURE_VERSION
           << fixture.genesis_hash;
    SerializeBuildConfig(stream, fixture.build_config);
    SerializeBranchPoint(stream, fixture.branch_anchor);
    stream << fixture.max_active_tip_height;
    stream << static_cast<uint8_t>(fixture.quorum_bases.size());
    for (const auto& base : fixture.quorum_bases) {
        SerializeBranchPoint(stream, base);
    }
    stream << static_cast<uint8_t>(fixture.snapshots.size());
    for (const auto& snapshot : fixture.snapshots) {
        SerializeBranchPoint(stream, snapshot.branch_point);
        const auto operator_count{
            static_cast<uint16_t>(snapshot.state.operator_key_states.size())};
        stream << operator_count;
        for (const auto& state : snapshot.state.operator_key_states) {
            stream << state;
        }
    }
}

bool UnserializeFixtureBody(DataStream& stream,
                            QuorumSnapshotFixture& fixture,
                            std::string& error)
{
    uint64_t magic{0};
    uint16_t version{0};
    stream >> magic >> version >> fixture.genesis_hash;
    if (magic != FIXTURE_MAGIC ||
        version != QUORUM_SNAPSHOT_FIXTURE_VERSION) {
        SetError(error, "unsupported PQ ChainLock snapshot fixture");
        return false;
    }

    UnserializeBuildConfig(stream, fixture.build_config);
    UnserializeBranchPoint(stream, fixture.branch_anchor);
    stream >> fixture.max_active_tip_height;
    uint8_t base_count{0};
    stream >> base_count;
    if (base_count < ACTIVE_QUORUMS ||
        base_count > MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS) {
        SetError(error, "PQ ChainLock fixture base count is out of bounds");
        return false;
    }
    fixture.quorum_bases.resize(base_count);
    for (auto& base : fixture.quorum_bases) {
        UnserializeBranchPoint(stream, base);
    }

    uint8_t snapshot_count{0};
    stream >> snapshot_count;
    if (snapshot_count < ACTIVE_QUORUMS ||
        snapshot_count > MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS) {
        SetError(error,
                 "PQ ChainLock fixture snapshot count is out of bounds");
        return false;
    }
    fixture.snapshots.resize(snapshot_count);
    for (auto& snapshot : fixture.snapshots) {
        UnserializeBranchPoint(stream, snapshot.branch_point);
        if (snapshot.branch_point.height < 0 ||
            snapshot.branch_point.block_hash.IsNull()) {
            SetError(error,
                     "PQ ChainLock fixture snapshot coordinate is invalid");
            return false;
        }
        snapshot.state.deterministic_mns = SyntheticDeterministicMNList(
            snapshot.branch_point.height,
            snapshot.branch_point.block_hash);
        uint16_t operator_count{0};
        stream >> operator_count;
        if (operator_count < QUORUM_MIN_VALID ||
            operator_count > QUORUM_SIZE) {
            SetError(error,
                     "PQ ChainLock fixture operator count is out of bounds");
            return false;
        }
        snapshot.state.operator_key_states.resize(operator_count);
        for (auto& state : snapshot.state.operator_key_states) {
            stream >> state;
        }
    }
    if (!stream.empty()) {
        SetError(error, "PQ ChainLock fixture has trailing bytes");
        return false;
    }
    return true;
}

bool ValidateFixture(const QuorumSnapshotFixture& fixture,
                     const uint256& expected_genesis_hash,
                     const QuorumBuildConfig& expected_build_config,
                     std::string& error)
{
    if (expected_genesis_hash.IsNull() ||
        fixture.genesis_hash != expected_genesis_hash) {
        SetError(error, "PQ ChainLock fixture genesis hash mismatch");
        return false;
    }
    if (!expected_build_config.IsValid() ||
        fixture.build_config != expected_build_config) {
        SetError(error, "PQ ChainLock fixture deployment profile mismatch");
        return false;
    }
    if (fixture.branch_anchor.height < 0 ||
        fixture.branch_anchor.block_hash.IsNull() ||
        fixture.max_active_tip_height < fixture.branch_anchor.height ||
        !IsEligibleChainLockTarget(expected_build_config.schedule,
                                   fixture.branch_anchor.height)) {
        SetError(error, "PQ ChainLock fixture branch window is invalid");
        return false;
    }
    if (fixture.quorum_bases.size() < ACTIVE_QUORUMS ||
        fixture.quorum_bases.size() >
            MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS ||
        fixture.snapshots.size() < ACTIVE_QUORUMS ||
        fixture.snapshots.size() >
            MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS) {
        SetError(error, "PQ ChainLock fixture point count is out of bounds");
        return false;
    }

    std::map<int32_t, const FixtureBranchPoint*> bases;
    for (const auto& base : fixture.quorum_bases) {
        if (base.height < 0 || base.block_hash.IsNull() ||
            !bases.emplace(base.height, &base).second) {
            SetError(error,
                     "PQ ChainLock fixture has conflicting base coordinates");
            return false;
        }
    }
    std::map<int32_t, const FixtureSnapshot*> snapshots;
    for (const auto& snapshot : fixture.snapshots) {
        if (snapshot.branch_point.height < 0 ||
            snapshot.branch_point.block_hash.IsNull() ||
            !snapshots.emplace(snapshot.branch_point.height,
                               &snapshot).second) {
            SetError(
                error,
                "PQ ChainLock fixture has conflicting snapshot coordinates");
            return false;
        }
    }
    for (const auto& [height, base] : bases) {
        const auto snapshot{snapshots.find(height)};
        if (snapshot != snapshots.end() &&
            base->block_hash != snapshot->second->branch_point.block_hash) {
            SetError(error,
                     "PQ ChainLock fixture has conflicting branch coordinates");
            return false;
        }
    }

    const auto first_active{ActiveEpochsAtHeight(
        expected_build_config.schedule, fixture.branch_anchor.height)};
    const auto last_active{ActiveEpochsAtHeight(
        expected_build_config.schedule, fixture.max_active_tip_height)};
    if (!first_active || !last_active) {
        SetError(error, "PQ ChainLock fixture window has no active rosters");
        return false;
    }
    const uint32_t first_epoch{first_active->front().epoch};
    const uint32_t last_epoch{last_active->back().epoch};
    if (last_epoch < first_epoch ||
        static_cast<uint64_t>(last_epoch) - first_epoch + 1 >
            MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS) {
        SetError(error, "PQ ChainLock fixture epoch window is out of bounds");
        return false;
    }

    const auto required_points{static_cast<std::size_t>(
        static_cast<uint64_t>(last_epoch) - first_epoch + 1)};
    if (fixture.quorum_bases.size() != required_points ||
        fixture.snapshots.size() != required_points) {
        SetError(error,
                 "PQ ChainLock fixture point count does not match window");
        return false;
    }

    for (uint32_t epoch{first_epoch};; ++epoch) {
        const auto base_height{
            EpochBaseHeight(expected_build_config.schedule, epoch)};
        const auto expected_snapshot_height{RegistrationCutoffHeight(
            expected_build_config.schedule, epoch,
            expected_build_config.roster_snapshot_lag_blocks)};
        const auto base_it{base_height ? bases.find(*base_height)
                                       : bases.end()};
        const auto snapshot_it{
            expected_snapshot_height
                ? snapshots.find(*expected_snapshot_height)
                : snapshots.end()};
        if (!base_height || !expected_snapshot_height ||
            base_it == bases.end() || snapshot_it == snapshots.end() ||
            *expected_snapshot_height >= *base_height ||
            *base_height > fixture.max_active_tip_height) {
            SetError(error, "PQ ChainLock fixture branch geometry mismatch");
            return false;
        }
        if (epoch == last_epoch) break;
    }

    for (const auto& [height, snapshot_ptr] : snapshots) {
        const auto& snapshot{*snapshot_ptr};
        const auto expected_mns{SyntheticDeterministicMNList(
            snapshot.branch_point.height,
            snapshot.branch_point.block_hash)};
        if (snapshot.state.deterministic_mns.IsNull() ||
            snapshot.state.deterministic_mns.GetHeight() !=
                snapshot.branch_point.height ||
            snapshot.state.deterministic_mns.GetBlockHash() !=
                snapshot.branch_point.block_hash ||
            snapshot.state.deterministic_mns.GetAllMNsCount() != QUORUM_SIZE ||
            snapshot.state.deterministic_mns.GetValidMNsCount() != QUORUM_SIZE ||
            snapshot.state.deterministic_mns.GetPQLegacyStateHash(
                fixture.genesis_hash) !=
                expected_mns.GetPQLegacyStateHash(fixture.genesis_hash) ||
            snapshot.state.operator_key_states.size() < QUORUM_MIN_VALID ||
            snapshot.state.operator_key_states.size() > QUORUM_SIZE) {
            SetError(error, "PQ ChainLock fixture snapshot state mismatch");
            return false;
        }

        const auto schedule_view{DeriveOperatorKeyScheduleView(
            expected_build_config.schedule, height,
            expected_build_config.registration_cutoff_blocks,
            expected_build_config.future_horizon_epochs)};
        if (!schedule_view) {
            SetError(error, "PQ ChainLock fixture schedule view is invalid");
            return false;
        }
        std::set<uint256> operators;
        for (const auto& state : snapshot.state.operator_key_states) {
            if (!state.IsStructurallyValid() ||
                !state.IsAdvancedTo(*schedule_view) ||
                !operators.insert(state.pro_tx_hash).second ||
                !snapshot.state.deterministic_mns.IsMNValid(
                    state.pro_tx_hash)) {
                SetError(error,
                         "PQ ChainLock fixture operator state is invalid");
                return false;
            }
        }
    }
    return true;
}

bool BranchMatchesFixture(const QuorumSnapshotFixture& fixture,
                          const CBlockIndex& tip)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (tip.nHeight < fixture.branch_anchor.height ||
        tip.nHeight > fixture.max_active_tip_height ||
        !(tip.nStatus & BLOCK_HAVE_DATA) ||
        (tip.nStatus & BLOCK_FAILED_MASK) ||
        !tip.IsValid(BLOCK_VALID_SCRIPTS)) {
        return false;
    }
    const auto matches = [&](const FixtureBranchPoint& point) {
        if (point.height > tip.nHeight) return true;
        const CBlockIndex* ancestor{tip.GetAncestor(point.height)};
        return ancestor != nullptr &&
               ancestor->GetBlockHash() == point.block_hash;
    };
    if (!matches(fixture.branch_anchor)) return false;
    for (const auto& base : fixture.quorum_bases) {
        if (!matches(base)) return false;
    }
    for (const auto& snapshot : fixture.snapshots) {
        if (!matches(snapshot.branch_point)) return false;
    }
    return true;
}

} // namespace

bool ValidateQuorumSnapshotFixture(const QuorumSnapshotFixture& fixture,
                                   std::string& error) noexcept
{
    error.clear();
    try {
        return ValidateFixture(fixture, fixture.genesis_hash,
                               fixture.build_config, error);
    } catch (const std::exception& exception) {
        SetError(error, exception.what());
        return false;
    }
}

bool WriteQuorumSnapshotFixture(const fs::path& path,
                                const QuorumSnapshotFixture& fixture,
                                std::string& error) noexcept
{
    error.clear();
    try {
        if (!ValidateQuorumSnapshotFixture(fixture, error)) {
            return false;
        }
        DataStream body;
        SerializeFixtureBody(body, fixture);
        if (body.size() + uint256::size() >
            MAX_QUORUM_SNAPSHOT_FIXTURE_BYTES) {
            SetError(error, "PQ ChainLock snapshot fixture exceeds size cap");
            return false;
        }
        const uint256 checksum{GetFixtureChecksum(MakeUCharSpan(body))};
        DataStream file;
        file.write(MakeByteSpan(body));
        file << checksum;
        if (!WriteBinaryFile(path, file.str())) {
            SetError(error, "unable to write PQ ChainLock snapshot fixture");
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        SetError(error, exception.what());
        return false;
    }
}

std::optional<QuorumSnapshotLookup> LoadQuorumSnapshotFixture(
    const fs::path& path,
    const uint256& expected_genesis_hash,
    const QuorumBuildConfig& expected_build_config,
    ChainstateManager& chainman,
    std::string& error) noexcept
{
    error.clear();
    try {
        const auto [read_ok, contents]{ReadBinaryFile(
            path, MAX_QUORUM_SNAPSHOT_FIXTURE_BYTES + 1)};
        if (!read_ok || contents.size() <= uint256::size() ||
            contents.size() > MAX_QUORUM_SNAPSHOT_FIXTURE_BYTES) {
            SetError(error,
                     "PQ ChainLock snapshot fixture is missing or oversized");
            return std::nullopt;
        }
        const Span<const uint8_t> bytes{MakeUCharSpan(contents)};
        const auto body{bytes.first(bytes.size() - uint256::size())};
        SpanReader checksum_reader{
            0, bytes.last(uint256::size())};
        uint256 checksum;
        checksum_reader >> checksum;
        if (!checksum_reader.empty() || checksum != GetFixtureChecksum(body)) {
            SetError(error, "PQ ChainLock snapshot fixture checksum mismatch");
            return std::nullopt;
        }

        auto fixture{std::make_shared<QuorumSnapshotFixture>()};
        DataStream stream{body};
        if (!UnserializeFixtureBody(stream, *fixture, error) ||
            !ValidateFixture(*fixture, expected_genesis_hash,
                             expected_build_config, error)) {
            return std::nullopt;
        }

        return QuorumSnapshotLookup{
            [fixture = std::move(fixture), &chainman](const CBlockIndex& index)
                -> std::optional<QuorumSnapshotState> {
                LOCK(cs_main);
                const CBlockIndex* tip{chainman.ActiveTip()};
                if (tip == nullptr ||
                    !BranchMatchesFixture(*fixture, *tip)) {
                    LogPrint(BCLog::CHAINLOCKS,
                             "PQ ChainLock test fixture unavailable for "
                             "snapshot height=%d: bounded branch is not active\n",
                             index.nHeight);
                    return std::nullopt;
                }
                for (const auto& snapshot : fixture->snapshots) {
                    const CBlockIndex* exact{
                        tip->GetAncestor(snapshot.branch_point.height)};
                    if (exact == &index &&
                        index.GetBlockHash() ==
                            snapshot.branch_point.block_hash) {
                        LogPrint(BCLog::CHAINLOCKS,
                                 "PQ ChainLock test fixture matched snapshot "
                                 "height=%d block=%s\n",
                                 index.nHeight,
                                 index.GetBlockHash().ToString());
                        return snapshot.state;
                    }
                }
                LogPrint(BCLog::CHAINLOCKS,
                         "PQ ChainLock test fixture rejected undeclared "
                         "snapshot height=%d block=%s\n",
                         index.nHeight, index.GetBlockHash().ToString());
                return std::nullopt;
            }};
    } catch (const std::exception& exception) {
        SetError(error, exception.what());
        return std::nullopt;
    }
}

} // namespace llmq::pq::test
