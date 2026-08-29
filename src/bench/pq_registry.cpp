// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <evo/auxiliary_history_gc.h>
#include <evo/pq_registry.h>
#include <hash.h>
#include <memusage.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace llmq::pq::test {

class PQRegistryManagerTestAccess {
public:
    static bool WriteCheckpointUnderLock(
        PQRegistryManager& manager,
        const PQRegistryDiskSnapshot& checkpoint)
    {
        LOCK(manager.m_mutex);
        PQRegistryDiskSnapshot materialized{checkpoint};
        if (!materialized.IsStructurallyValid() ||
            materialized.block_hash != checkpoint.block_hash) {
            return false;
        }
        manager.m_snapshot_cache.clear();
        manager.m_snapshot_cache_index.clear();
        manager.m_payment_eligibility_cache.clear();
        manager.m_payment_eligibility_cache_index.clear();
        if (!manager.NoteSnapshotContentMutationLocked()) return false;
        return manager.m_snapshot_db->WriteThrough(
            checkpoint.block_hash, materialized, /*fSync=*/true);
    }

    static bool AuthenticateCheckpointAfterRestart(
        PQRegistryManager& manager,
        const evo::PQRegistryGCClosure& closure)
    {
        LOCK(manager.m_mutex);
        std::shared_ptr<const PQRegistrySnapshotView> snapshot;
        PQRegistryError error;
        return manager.AuthenticateGCFloorCheckpoint(
                   closure, &snapshot, error) &&
               snapshot != nullptr;
    }
};

} // namespace llmq::pq::test

namespace {

using namespace llmq::pq;

constexpr int32_t MAX_CHECKPOINT_HEIGHT{
    1295 + 4 * PQ_REGISTRY_CHECKPOINT_INTERVAL};

void Require(bool condition, const char* operation)
{
    if (!condition) {
        throw std::runtime_error{
            std::string{"maximum PQ-registry checkpoint benchmark failed: "} +
            operation};
    }
}

uint256 OrderedHash(uint8_t domain, uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = domain;
    hash.begin()[28] = static_cast<uint8_t>(value >> 24);
    hash.begin()[29] = static_cast<uint8_t>(value >> 16);
    hash.begin()[30] = static_cast<uint8_t>(value >> 8);
    hash.begin()[31] = static_cast<uint8_t>(value);
    return hash;
}

GlobalPublicKey OrderedPublicKey(uint32_t value)
{
    GlobalPublicKey key{};
    key[0] = 0x40;
    key[28] = static_cast<uint8_t>(value >> 24);
    key[29] = static_cast<uint8_t>(value >> 16);
    key[30] = static_cast<uint8_t>(value >> 8);
    key[31] = static_cast<uint8_t>(value);
    return key;
}

PQRegistryConfig MaxCheckpointConfig()
{
    PQRegistryConfig config;
    config.preparation_height = 1295;
    config.schedule.epoch_origin = 1440;
    config.registration_cutoff_blocks = 144;
    config.future_horizon_epochs = 8;
    Require(config.IsValid(), "configuration");
    return config;
}

std::size_t CheckpointDynamicMemoryUsage(
    const PQRegistryDiskSnapshot& checkpoint)
{
    std::size_t usage{memusage::DynamicUsage(
        checkpoint.checkpoint_operator_states)};
    for (const auto& state : checkpoint.checkpoint_operator_states) {
        usage += memusage::DynamicUsage(state.frozen_child_roots);
    }
    usage += memusage::DynamicUsage(checkpoint.tree_ids);
    usage += memusage::DynamicUsage(checkpoint.operator_states);
    usage += memusage::DynamicUsage(checkpoint.removed_operators);
    usage += memusage::DynamicUsage(checkpoint.block_tree_ids);
    return usage;
}

uint64_t DirectorySizeBytes(const fs::path& path)
{
    uint64_t total{0};
    std::error_code error;
    for (auto entry{fs::recursive_directory_iterator(path, error)};
         !error && entry != fs::recursive_directory_iterator();
         entry.increment(error)) {
        if (!entry->is_regular_file(error) || error) continue;
        total += entry->file_size(error);
        if (error) return 0;
    }
    return error ? 0 : total;
}

struct MaxCheckpointFixture {
    PQRegistryConfig config{MaxCheckpointConfig()};
    uint256 genesis_hash{OrderedHash(0x01, 1)};
    PQRegistryDiskSnapshot checkpoint;
    evo::PQRegistryGCClosure closure;
    std::size_t serialized_bytes{0};
    std::size_t dynamic_bytes{0};
    std::size_t frozen_roots_per_operator{0};

    MaxCheckpointFixture()
    {
        const auto schedule_view{DeriveOperatorKeyScheduleView(
            config.schedule, MAX_CHECKPOINT_HEIGHT,
            config.registration_cutoff_blocks,
            config.future_horizon_epochs)};
        Require(schedule_view.has_value(), "checkpoint schedule");
        Require(schedule_view->has_current_epoch != 0,
                "mature checkpoint schedule");
        Require(schedule_view->first_mutable_epoch >=
                    schedule_view->first_retained_frozen_epoch,
                "frozen-root range");
        frozen_roots_per_operator =
            schedule_view->first_mutable_epoch -
            schedule_view->first_retained_frozen_epoch;
        Require(frozen_roots_per_operator == ACTIVE_QUORUMS,
                "realistic frozen-root maximum");

        PQRegistrySnapshot snapshot;
        snapshot.height = MAX_CHECKPOINT_HEIGHT;
        snapshot.block_hash = OrderedHash(0x02, 2);
        snapshot.previous_block_hash = OrderedHash(0x02, 1);
        snapshot.operator_states.reserve(MAX_PQ_OPERATOR_STATES);
        snapshot.used_tree_ids.reserve(MAX_PQ_USED_TREE_IDS);

        for (uint32_t index{0}; index < MAX_PQ_USED_TREE_IDS; ++index) {
            snapshot.used_tree_ids.push_back(
                OrderedHash(0x20, index + 1));
        }

        const auto schedule{
            OperatorKeyScheduleState::FromView(*schedule_view)};
        for (uint32_t index{0}; index < MAX_PQ_OPERATOR_STATES;
             ++index) {
            OperatorKeyState state;
            state.pro_tx_hash = OrderedHash(0x10, index + 1);
            state.has_global_key = 1;
            state.global_key_active = 1;
            state.global_key.key_version = 1;
            state.global_key.public_key = OrderedPublicKey(index + 1);
            state.global_key.activated_height =
                static_cast<uint32_t>(config.preparation_height);
            state.global_key.child_key_commitment.generation = 1;
            state.global_key.child_key_commitment.first_epoch = 0;
            state.global_key.child_key_commitment.tree_id =
                snapshot.used_tree_ids[index];
            state.global_key.child_key_commitment.root =
                OrderedHash(0x30, index + 1);
            state.schedule_initialized = 1;
            state.schedule = schedule;
            state.frozen_child_roots.reserve(
                frozen_roots_per_operator);
            for (uint32_t epoch{
                     schedule_view->first_retained_frozen_epoch};
                 epoch < schedule_view->first_mutable_epoch; ++epoch) {
                state.frozen_child_roots.push_back(FrozenChildRootRecord{
                    state.pro_tx_hash, state.global_key.key_version,
                    epoch, state.global_key.child_key_commitment});
            }
            Require(state.IsStructurallyValid(), "operator state");
            snapshot.operator_states.push_back(std::move(state));
        }

        const auto state_root{
            snapshot.RecomputeConsensusStateRoot(genesis_hash)};
        Require(state_root.has_value(), "checkpoint state root");
        snapshot.consensus_state_root = *state_root;
        Require(snapshot.IsStructurallyValid(), "checkpoint snapshot");

        checkpoint.is_checkpoint = 1;
        checkpoint.height = snapshot.height;
        checkpoint.block_hash = snapshot.block_hash;
        checkpoint.previous_block_hash = snapshot.previous_block_hash;
        checkpoint.previous_consensus_state_root = *state_root;
        checkpoint.checkpoint_operator_states =
            std::move(snapshot.operator_states);
        checkpoint.tree_ids = std::move(snapshot.used_tree_ids);
        checkpoint.consensus_state_root = *state_root;
        Require(checkpoint.IsStructurallyValid(), "disk checkpoint");

        DataStream encoded;
        encoded << checkpoint;
        serialized_bytes = encoded.size();
        dynamic_bytes = CheckpointDynamicMemoryUsage(checkpoint);
        Require(serialized_bytes <=
                    PQRegistryDiskSnapshot::MAX_SERIALIZED_SIZE,
                "serialized-size envelope");

        closure.generation = 1;
        closure.checkpoint = {
            checkpoint.height, checkpoint.block_hash};
        closure.checkpoint_state_root = checkpoint.consensus_state_root;
        closure.checkpoint_record_hash = ::SerializeHash(checkpoint);
        closure.lineage_base_commitment = OrderedHash(0x50, 1);
        closure.rooted_lineage_commitment = OrderedHash(0x50, 2);
        closure.scan_complete = evo::PQRegistryGCClosure::COMPLETE;
        Require(closure.IsValid(), "restart closure");
    }
};

void ConfigureMaxCheckpointBench(benchmark::Bench& bench,
                                 const MaxCheckpointFixture& fixture)
{
    std::cout << "PQ registry maximum-checkpoint fixture: operators="
              << MAX_PQ_OPERATOR_STATES
              << " tree_ids=" << MAX_PQ_USED_TREE_IDS
              << " frozen_roots_per_operator="
              << fixture.frozen_roots_per_operator
              << " serialized_bytes=" << fixture.serialized_bytes
              << " materialized_dynamic_bytes=" << fixture.dynamic_bytes
              << '\n';
    bench.epochs(1)
        .epochIterations(1)
        .unit("checkpoint")
        .context("operators", std::to_string(MAX_PQ_OPERATOR_STATES))
        .context("tree_ids", std::to_string(MAX_PQ_USED_TREE_IDS))
        .context("frozen_roots_per_operator",
                 std::to_string(fixture.frozen_roots_per_operator))
        .context("serialized_bytes",
                 std::to_string(fixture.serialized_bytes))
        .context("fixture_dynamic_bytes",
                 std::to_string(fixture.dynamic_bytes));
}

DBParams DiskDB(const fs::path& path, bool wipe)
{
    return DBParams{
        .path = path,
        .cache_bytes = 8U * 1024U * 1024U,
        .memory_only = false,
        .wipe_data = wipe,
    };
}

void PQRegistryCheckpointMaxSerialize(benchmark::Bench& bench)
{
    const MaxCheckpointFixture fixture;
    ConfigureMaxCheckpointBench(bench, fixture);

    bench.run([&] {
        DataStream encoded;
        encoded << fixture.checkpoint;
        Require(encoded.size() == fixture.serialized_bytes,
                "deterministic serialization size");
        ankerl::nanobench::doNotOptimizeAway(encoded.data());
    });
}

void PQRegistryCheckpointMaxLockHeldWrite(benchmark::Bench& bench)
{
    const auto setup{MakeNoLogFileContext<const BasicTestingSetup>()};
    const MaxCheckpointFixture fixture;
    ConfigureMaxCheckpointBench(bench, fixture);
    const auto db{DiskDB(
        setup->m_path_root / "pq_registry_checkpoint_max_write",
        /*wipe=*/true)};
    PQRegistryManager manager{db, fixture.genesis_hash, fixture.config};

    bench.run([&] {
        Require(test::PQRegistryManagerTestAccess::WriteCheckpointUnderLock(
                    manager, fixture.checkpoint),
                "locked checkpoint write");
    });

    const uint64_t leveldb_bytes{
        DirectorySizeBytes(db.path / "snapshots")};
    Require(leveldb_bytes != 0, "LevelDB physical size");
    std::cout << "PQ registry maximum-checkpoint LevelDB bytes="
              << leveldb_bytes << '\n';
}

void PQRegistryCheckpointMaxRestart(benchmark::Bench& bench)
{
    const auto setup{MakeNoLogFileContext<const BasicTestingSetup>()};
    const MaxCheckpointFixture fixture;
    const auto db_path{
        setup->m_path_root / "pq_registry_checkpoint_max_restart"};
    {
        PQRegistryManager writer{
            DiskDB(db_path, /*wipe=*/true), fixture.genesis_hash,
            fixture.config};
        Require(writer.WriteExactSnapshotForTesting(
                    fixture.checkpoint.block_hash, fixture.checkpoint),
                "restart fixture write");
    }
    const uint64_t leveldb_bytes{
        DirectorySizeBytes(db_path / "snapshots")};
    Require(leveldb_bytes != 0, "restart LevelDB physical size");

    ConfigureMaxCheckpointBench(bench, fixture);
    bench.context("leveldb_bytes", std::to_string(leveldb_bytes));
    std::cout << "PQ registry maximum-checkpoint restart LevelDB bytes="
              << leveldb_bytes << '\n';
    bench.run([&] {
        PQRegistryManager reader{
            DiskDB(db_path, /*wipe=*/false), fixture.genesis_hash,
            fixture.config};
        Require(test::PQRegistryManagerTestAccess::
                    AuthenticateCheckpointAfterRestart(
                        reader, fixture.closure),
                "restart checkpoint authentication");
    });
}

} // namespace

// The maximum fixture is intentionally opt-in: CI's high-priority benchmark
// sanity pass compiles these cases without allocating their production caps.
BENCHMARK(PQRegistryCheckpointMaxSerialize,
          benchmark::PriorityLevel::LOW);
BENCHMARK(PQRegistryCheckpointMaxLockHeldWrite,
          benchmark::PriorityLevel::LOW);
BENCHMARK(PQRegistryCheckpointMaxRestart,
          benchmark::PriorityLevel::LOW);
