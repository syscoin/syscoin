// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHILD_KEY_TREE_H
#define SYSCOIN_LLMQ_PQ_CHILD_KEY_TREE_H

#include <llmq/pq_chainlock_types.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <util/fs.h>
#include <vector>

namespace llmq::pq {

// The builder accepts shallow trees for deterministic unit vectors. Consensus
// fixes one production depth in the serialized commitment record.
inline constexpr uint16_t CHILD_KEY_TREE_MIN_DEPTH{1};
inline constexpr uint16_t CHILD_KEY_TREE_MAX_DEPTH{16};
inline constexpr std::size_t CHILD_KEY_TREE_MAX_WORKERS{16};
inline constexpr std::string_view CHILD_KEY_TREE_LEAF_DOMAIN{
    "SYS_PQ_CHILD_TREE_LEAF_V1"};
inline constexpr std::string_view CHILD_KEY_TREE_NODE_DOMAIN{
    "SYS_PQ_CHILD_TREE_NODE_V1"};

/** Production worker policy: one thread when topology is unknown, otherwise
 * no more than the reported hardware concurrency or the fixed safety cap. */
[[nodiscard]] std::size_t DefaultChildKeyTreeWorkerCount() noexcept;

/** Runtime parameters used to compare candidate fixed consensus depths. */
struct ChildKeyTreeConfig {
    uint256 genesis_hash;
    uint256 tree_id;
    uint32_t generation{0};
    uint32_t first_epoch{0};
    uint16_t depth{0};

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::size_t LeafCount() const noexcept;
    [[nodiscard]] std::optional<uint32_t> EpochAt(std::size_t index) const noexcept;
    [[nodiscard]] std::optional<std::size_t> IndexForEpoch(uint32_t epoch) const noexcept;
    [[nodiscard]] static std::optional<ChildKeyTreeConfig> FromCommitment(
        const uint256& genesis_hash,
        const ChildKeyTreeCommitment& commitment) noexcept;
    [[nodiscard]] bool MatchesCommitment(
        const ChildKeyTreeCommitment& commitment) const noexcept;
};

struct ChildKeyTreeProof {
    ChildPublicKey public_key{};
    std::vector<uint256> siblings;
};

/**
 * Complete public Merkle cache for one deterministic C11 child-key range.
 * Secret keys are derived only transiently and are never retained here.
 */
class ChildKeyTree final {
public:
    [[nodiscard]] static std::optional<ChildKeyTree> Build(
        std::span<const uint8_t> chainlock_master_seed,
        const ChildKeyTreeConfig& config,
        std::size_t worker_count = 1);

    [[nodiscard]] const ChildKeyTreeConfig& GetConfig() const noexcept
    {
        return m_config;
    }
    [[nodiscard]] const uint256& GetRoot() const noexcept { return m_nodes.front(); }
    [[nodiscard]] std::size_t CacheBytes() const noexcept
    {
        return m_nodes.size() * sizeof(uint256);
    }

    [[nodiscard]] std::optional<ChildKeyTreeProof> GetProof(
        std::span<const uint8_t> chainlock_master_seed,
        uint32_t epoch) const;

    /** Fixed-width production witness; shallow benchmark trees are rejected. */
    [[nodiscard]] std::optional<ChildKeyProof> GetConsensusProof(
        std::span<const uint8_t> chainlock_master_seed,
        uint32_t epoch) const;

    /** Atomic, checksummed persistence for the public-only tree cache. */
    [[nodiscard]] bool Save(const fs::path& path) const noexcept;
    [[nodiscard]] static std::optional<ChildKeyTree> Load(
        const fs::path& path,
        const ChildKeyTreeConfig& expected_config,
        const uint256& expected_root) noexcept;

private:
    ChildKeyTreeConfig m_config;
    std::vector<uint256> m_nodes;
};

[[nodiscard]] uint256 GetChildKeyTreeLeafHash(
    const ChildKeyTreeConfig& config,
    uint32_t epoch,
    const ChildPublicKey& public_key);

[[nodiscard]] uint256 GetChildKeyTreeNodeHash(
    const ChildKeyTreeConfig& config,
    uint16_t level,
    const uint256& left,
    const uint256& right);

[[nodiscard]] bool VerifyChildKeyTreeProof(
    const ChildKeyTreeConfig& config,
    const uint256& expected_root,
    uint32_t epoch,
    const ChildKeyTreeProof& proof) noexcept;

[[nodiscard]] bool VerifyCommittedChildKeyProof(
    const uint256& genesis_hash,
    const ChildKeyTreeCommitment& commitment,
    uint32_t epoch,
    const ChildKeyProof& proof) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHILD_KEY_TREE_H
