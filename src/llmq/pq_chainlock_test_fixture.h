// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_TEST_FIXTURE_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_TEST_FIXTURE_H

#include <llmq/pq_quorum_builder.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class ChainstateManager;

namespace llmq::pq::test {

inline constexpr uint16_t QUORUM_SNAPSHOT_FIXTURE_VERSION{1};
inline constexpr std::size_t MAX_QUORUM_SNAPSHOT_FIXTURE_BYTES{8U << 20};
inline constexpr std::size_t MAX_QUORUM_SNAPSHOT_FIXTURE_POINTS{16};

struct FixtureBranchPoint {
    int32_t height{-1};
    uint256 block_hash;

    friend bool operator==(const FixtureBranchPoint&,
                           const FixtureBranchPoint&) = default;
};

struct FixtureSnapshot {
    FixtureBranchPoint branch_point;
    QuorumSnapshotState state;
};

/**
 * An exact-branch, height-bounded roster fixture for daemon functional tests.
 * It is never a certificate or an alternate validation result: the existing
 * builder consumes these snapshots and every live share still passes the
 * production collector, cryptography, store, and chain validation paths.
 */
struct QuorumSnapshotFixture {
    uint256 genesis_hash;
    QuorumBuildConfig build_config;
    FixtureBranchPoint branch_anchor;
    int32_t max_active_tip_height{-1};
    std::vector<FixtureBranchPoint> quorum_bases;
    std::vector<FixtureSnapshot> snapshots;
};

/** Validate the complete in-memory shape without touching disk. */
[[nodiscard]] bool ValidateQuorumSnapshotFixture(
    const QuorumSnapshotFixture& fixture,
    std::string& error) noexcept;

/** Write the checksummed bounded format used by the test helper. */
[[nodiscard]] bool WriteQuorumSnapshotFixture(
    const fs::path& path,
    const QuorumSnapshotFixture& fixture,
    std::string& error) noexcept;

/**
 * Load and validate a fixture against the exact daemon deployment profile,
 * returning a lookup that remains bound to the declared target branch.
 */
[[nodiscard]] std::optional<QuorumSnapshotLookup>
LoadQuorumSnapshotFixture(
    const fs::path& path,
    const uint256& expected_genesis_hash,
    const QuorumBuildConfig& expected_build_config,
    ChainstateManager& chainman,
    std::string& error) noexcept;

} // namespace llmq::pq::test

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_TEST_FIXTURE_H
