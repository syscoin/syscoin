// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_child_key_tree.h>

#include <clientversion.h>
#include <hash.h>
#include <llmq/pq_child_key_derivation.h>
#include <span.h>
#include <streams.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <string_view>
#include <thread>
#include <utility>

namespace llmq::pq {
namespace {

constexpr uint16_t CHILD_KEY_TREE_CACHE_VERSION{1};
constexpr std::string_view CHILD_KEY_TREE_CACHE_DOMAIN{
    "SYS_PQ_CHILD_TREE_CACHE_V1"};

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

template <typename Function>
bool ParallelFor(std::size_t count, std::size_t requested_workers,
                 Function&& function)
{
    if (count == 0) return true;
    const std::size_t workers{
        std::max<std::size_t>(1, std::min(count, requested_workers))};
    if (workers == 1) {
        for (std::size_t i{0}; i < count; ++i) {
            if (!function(i)) return false;
        }
        return true;
    }

    std::atomic<std::size_t> next{0};
    std::atomic<bool> success{true};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (std::size_t worker{0}; worker < workers; ++worker) {
        threads.emplace_back([&] {
            while (success.load(std::memory_order_relaxed)) {
                const std::size_t index{
                    next.fetch_add(1, std::memory_order_relaxed)};
                if (index >= count) break;
                if (!function(index)) {
                    success.store(false, std::memory_order_relaxed);
                    break;
                }
            }
        });
    }
    for (auto& thread : threads) thread.join();
    return success.load(std::memory_order_relaxed);
}

void WriteTreeMetadata(CHashWriter& writer, const ChildKeyTreeConfig& config)
{
    writer << config.genesis_hash << config.tree_id << config.generation
           << config.first_epoch << config.depth << CHILD_C11_SHA_V1
           << C11_USAGE_CAP;
}

uint256 GetCacheChecksum(const ChildKeyTreeConfig& config,
                         const uint256& root,
                         const std::vector<uint256>& nodes)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, CHILD_KEY_TREE_CACHE_DOMAIN);
    writer << CHILD_KEY_TREE_CACHE_VERSION << config.genesis_hash
           << config.tree_id << config.generation << config.first_epoch
           << config.depth << root
           << static_cast<uint32_t>(nodes.size());
    for (const auto& node : nodes) writer << node;
    return writer.GetHash();
}

bool SameConfig(const ChildKeyTreeConfig& lhs,
                const ChildKeyTreeConfig& rhs) noexcept
{
    return lhs.genesis_hash == rhs.genesis_hash &&
           lhs.tree_id == rhs.tree_id &&
           lhs.generation == rhs.generation &&
           lhs.first_epoch == rhs.first_epoch && lhs.depth == rhs.depth;
}

bool HasCanonicalInternalNodes(const ChildKeyTreeConfig& config,
                               const std::vector<uint256>& nodes)
{
    const std::size_t leaf_count{config.LeafCount()};
    if (leaf_count == 0 || nodes.size() != 2 * leaf_count - 1) return false;
    for (uint16_t level{1}; level <= config.depth; ++level) {
        const std::size_t parent_count{leaf_count >> level};
        const std::size_t parent_base{parent_count - 1};
        const std::size_t child_base{(parent_count << 1) - 1};
        for (std::size_t index{0}; index < parent_count; ++index) {
            const std::size_t left{child_base + 2 * index};
            if (nodes[parent_base + index] != GetChildKeyTreeNodeHash(
                    config, level, nodes[left], nodes[left + 1])) {
                return false;
            }
        }
    }
    return !nodes.front().IsNull();
}

} // namespace

std::size_t DefaultChildKeyTreeWorkerCount() noexcept
{
    const unsigned int available{std::thread::hardware_concurrency()};
    return available == 0
        ? 1
        : std::min<std::size_t>(available,
                                CHILD_KEY_TREE_MAX_WORKERS);
}

bool ChildKeyTreeConfig::IsValid() const noexcept
{
    if (genesis_hash.IsNull() || tree_id.IsNull() ||
        !IsValidChildKeyTreeGeneration(generation) ||
        depth < CHILD_KEY_TREE_MIN_DEPTH || depth > CHILD_KEY_TREE_MAX_DEPTH) {
        return false;
    }
    const uint64_t last_epoch{static_cast<uint64_t>(first_epoch) +
                              (uint64_t{1} << depth) - 1};
    return last_epoch <= std::numeric_limits<uint32_t>::max();
}

std::size_t ChildKeyTreeConfig::LeafCount() const noexcept
{
    return IsValid() ? std::size_t{1} << depth : 0;
}

std::optional<uint32_t> ChildKeyTreeConfig::EpochAt(std::size_t index) const noexcept
{
    if (!IsValid() || index >= LeafCount()) return std::nullopt;
    return static_cast<uint32_t>(static_cast<uint64_t>(first_epoch) + index);
}

std::optional<std::size_t> ChildKeyTreeConfig::IndexForEpoch(
    uint32_t epoch) const noexcept
{
    if (!IsValid() || epoch < first_epoch) return std::nullopt;
    const uint64_t index{static_cast<uint64_t>(epoch) - first_epoch};
    return index < LeafCount() ? std::optional<std::size_t>{index}
                               : std::nullopt;
}

std::optional<ChildKeyTreeConfig> ChildKeyTreeConfig::FromCommitment(
    const uint256& genesis_hash,
    const ChildKeyTreeCommitment& commitment) noexcept
{
    if (genesis_hash.IsNull() || !commitment.IsStructurallyValid()) {
        return std::nullopt;
    }
    ChildKeyTreeConfig config{
        genesis_hash,
        commitment.tree_id,
        commitment.generation,
        commitment.first_epoch,
        commitment.depth,
    };
    return config.IsValid() ? std::optional<ChildKeyTreeConfig>{config}
                            : std::nullopt;
}

bool ChildKeyTreeConfig::MatchesCommitment(
    const ChildKeyTreeCommitment& commitment) const noexcept
{
    return IsValid() && commitment.IsStructurallyValid() &&
           tree_id == commitment.tree_id &&
           generation == commitment.generation &&
           first_epoch == commitment.first_epoch && depth == commitment.depth;
}

uint256 GetChildKeyTreeLeafHash(const ChildKeyTreeConfig& config,
                                uint32_t epoch,
                                const ChildPublicKey& public_key)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, CHILD_KEY_TREE_LEAF_DOMAIN);
    WriteTreeMetadata(writer, config);
    writer << epoch << public_key;
    return writer.GetHash();
}

uint256 GetChildKeyTreeNodeHash(const ChildKeyTreeConfig& config,
                                uint16_t level,
                                const uint256& left,
                                const uint256& right)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, CHILD_KEY_TREE_NODE_DOMAIN);
    WriteTreeMetadata(writer, config);
    writer << level << left << right;
    return writer.GetHash();
}

std::optional<ChildKeyTree> ChildKeyTree::Build(
    std::span<const uint8_t> chainlock_master_seed,
    const ChildKeyTreeConfig& config,
    std::size_t worker_count)
{
    if (!config.IsValid() || worker_count == 0 ||
        worker_count > CHILD_KEY_TREE_MAX_WORKERS) {
        return std::nullopt;
    }
    const std::size_t leaf_count{config.LeafCount()};
    ChildKeyTree tree;
    tree.m_config = config;
    tree.m_nodes.resize(2 * leaf_count - 1);
    const std::size_t leaf_base{leaf_count - 1};

    if (!ParallelFor(leaf_count, worker_count, [&](std::size_t index) {
            const auto epoch{config.EpochAt(index)};
            if (!epoch) return false;
            const auto public_key{DeriveCommittedChildPublicKey(
                chainlock_master_seed, config.genesis_hash, config.tree_id,
                config.generation, *epoch)};
            if (!public_key) return false;
            tree.m_nodes[leaf_base + index] =
                GetChildKeyTreeLeafHash(config, *epoch, *public_key);
            return true;
        })) {
        return std::nullopt;
    }

    for (uint16_t level{1}; level <= config.depth; ++level) {
        const std::size_t parent_count{leaf_count >> level};
        const std::size_t parent_base{parent_count - 1};
        const std::size_t child_base{(parent_count << 1) - 1};
        if (!ParallelFor(parent_count, worker_count, [&](std::size_t index) {
                const std::size_t left{child_base + 2 * index};
                tree.m_nodes[parent_base + index] = GetChildKeyTreeNodeHash(
                    config, level, tree.m_nodes[left], tree.m_nodes[left + 1]);
                return true;
            })) {
            return std::nullopt;
        }
    }
    if (tree.m_nodes.front().IsNull()) return std::nullopt;
    return tree;
}

std::optional<ChildKeyTreeProof> ChildKeyTree::GetProof(
    std::span<const uint8_t> chainlock_master_seed,
    uint32_t epoch) const
{
    const auto leaf_index{m_config.IndexForEpoch(epoch)};
    if (!leaf_index || m_nodes.size() != 2 * m_config.LeafCount() - 1) {
        return std::nullopt;
    }
    const auto public_key{DeriveCommittedChildPublicKey(
        chainlock_master_seed, m_config.genesis_hash, m_config.tree_id,
        m_config.generation, epoch)};
    if (!public_key) return std::nullopt;

    ChildKeyTreeProof proof;
    proof.public_key = *public_key;
    proof.siblings.reserve(m_config.depth);
    std::size_t node{m_config.LeafCount() - 1 + *leaf_index};
    for (uint16_t level{0}; level < m_config.depth; ++level) {
        const std::size_t sibling{(node & 1U) != 0 ? node + 1 : node - 1};
        proof.siblings.push_back(m_nodes[sibling]);
        node = (node - 1) / 2;
    }
    return proof;
}

std::optional<ChildKeyProof> ChildKeyTree::GetConsensusProof(
    std::span<const uint8_t> chainlock_master_seed,
    uint32_t epoch) const
{
    if (m_config.depth != CHILD_KEY_TREE_DEPTH) return std::nullopt;
    auto variable{GetProof(chainlock_master_seed, epoch)};
    if (!variable || variable->siblings.size() != CHILD_KEY_TREE_DEPTH) {
        return std::nullopt;
    }
    ChildKeyProof proof;
    proof.public_key = variable->public_key;
    std::copy(variable->siblings.begin(), variable->siblings.end(),
              proof.siblings.begin());
    ChildKeyTreeProof check;
    check.public_key = proof.public_key;
    check.siblings.assign(proof.siblings.begin(), proof.siblings.end());
    return proof.IsStructurallyValid() && VerifyChildKeyTreeProof(
               m_config, m_nodes.front(), epoch, check)
        ? std::optional<ChildKeyProof>{proof}
        : std::nullopt;
}

bool ChildKeyTree::Save(const fs::path& path) const noexcept
{
    if (!m_config.IsValid() ||
        m_nodes.size() != 2 * m_config.LeafCount() - 1 ||
        m_nodes.front().IsNull()) {
        return false;
    }
    fs::path temporary{path};
    temporary += ".new";
    try {
        CAutoFile file{fsbridge::fopen(temporary, "wb"), CLIENT_VERSION};
        if (file.IsNull()) return false;
        const uint32_t node_count{static_cast<uint32_t>(m_nodes.size())};
        const uint256 checksum{
            GetCacheChecksum(m_config, m_nodes.front(), m_nodes)};
        file << CHILD_KEY_TREE_CACHE_VERSION << m_config.genesis_hash
             << m_config.tree_id << m_config.generation
             << m_config.first_epoch << m_config.depth << m_nodes.front()
             << node_count;
        for (const auto& node : m_nodes) file << node;
        file << checksum;
        if (!FileCommit(file.Get())) {
            file.fclose();
            std::error_code ignored;
            fs::remove(temporary, ignored);
            return false;
        }
        file.fclose();
        if (!RenameOver(temporary, path)) {
            std::error_code ignored;
            fs::remove(temporary, ignored);
            return false;
        }
        return true;
    } catch (...) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
}

std::optional<ChildKeyTree> ChildKeyTree::Load(
    const fs::path& path,
    const ChildKeyTreeConfig& expected_config,
    const uint256& expected_root) noexcept
{
    if (!expected_config.IsValid() || expected_root.IsNull()) {
        return std::nullopt;
    }
    try {
        CAutoFile file{fsbridge::fopen(path, "rb"), CLIENT_VERSION};
        if (file.IsNull()) return std::nullopt;
        uint16_t version{0};
        ChildKeyTreeConfig config;
        uint256 root;
        uint32_t node_count{0};
        file >> version >> config.genesis_hash >> config.tree_id
             >> config.generation >> config.first_epoch >> config.depth
             >> root >> node_count;
        const std::size_t expected_node_count{
            2 * expected_config.LeafCount() - 1};
        if (version != CHILD_KEY_TREE_CACHE_VERSION ||
            !SameConfig(config, expected_config) || root != expected_root ||
            node_count != expected_node_count) {
            return std::nullopt;
        }

        ChildKeyTree tree;
        tree.m_config = config;
        tree.m_nodes.resize(node_count);
        for (auto& node : tree.m_nodes) file >> node;
        uint256 checksum;
        file >> checksum;
        if (std::fgetc(file.Get()) != EOF || std::ferror(file.Get()) != 0 ||
            tree.m_nodes.empty() || tree.m_nodes.front() != root ||
            !HasCanonicalInternalNodes(config, tree.m_nodes) ||
            checksum != GetCacheChecksum(config, root, tree.m_nodes)) {
            return std::nullopt;
        }
        return tree;
    } catch (...) {
        return std::nullopt;
    }
}

bool VerifyChildKeyTreeProof(const ChildKeyTreeConfig& config,
                             const uint256& expected_root,
                             uint32_t epoch,
                             const ChildKeyTreeProof& proof) noexcept
{
    const auto index{config.IndexForEpoch(epoch)};
    if (!index || expected_root.IsNull() ||
        proof.siblings.size() != config.depth) {
        return false;
    }
    try {
        uint256 current{GetChildKeyTreeLeafHash(config, epoch,
                                                proof.public_key)};
        std::size_t path{*index};
        for (uint16_t level{1}; level <= config.depth; ++level) {
            const uint256& sibling{proof.siblings[level - 1]};
            current = (path & 1U) != 0
                ? GetChildKeyTreeNodeHash(config, level, sibling, current)
                : GetChildKeyTreeNodeHash(config, level, current, sibling);
            path >>= 1;
        }
        return current == expected_root;
    } catch (...) {
        return false;
    }
}

bool VerifyCommittedChildKeyProof(
    const uint256& genesis_hash,
    const ChildKeyTreeCommitment& commitment,
    uint32_t epoch,
    const ChildKeyProof& proof) noexcept
{
    const auto config{
        ChildKeyTreeConfig::FromCommitment(genesis_hash, commitment)};
    if (!config || !commitment.CoversEpoch(epoch) ||
        !proof.IsStructurallyValid()) {
        return false;
    }
    try {
        const auto index{config->IndexForEpoch(epoch)};
        if (!index) return false;
        uint256 current{
            GetChildKeyTreeLeafHash(*config, epoch, proof.public_key)};
        std::size_t path{*index};
        for (uint16_t level{1}; level <= CHILD_KEY_TREE_DEPTH; ++level) {
            const uint256& sibling{proof.siblings[level - 1]};
            current = (path & 1U) != 0
                ? GetChildKeyTreeNodeHash(*config, level, sibling, current)
                : GetChildKeyTreeNodeHash(*config, level, current, sibling);
            path >>= 1;
        }
        return current == commitment.root;
    } catch (...) {
        return false;
    }
}

} // namespace llmq::pq
