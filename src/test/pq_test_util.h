// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_PQ_TEST_UTIL_H
#define SYSCOIN_TEST_PQ_TEST_UTIL_H

#include <hash.h>
#include <llmq/pq_child_key_tree.h>
#include <span.h>

#include <cstdint>
#include <string_view>

namespace llmq::pq::test {

struct SyntheticChildAuthorization {
    FrozenChildRootRecord record;
    ChildKeyProof proof;
};

inline uint256 SyntheticHash(std::string_view domain,
                             const uint256& genesis_hash,
                             const uint256& pro_tx_hash,
                             uint64_t discriminator,
                             uint16_t level)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
    writer << genesis_hash << pro_tx_hash << discriminator << level;
    return writer.GetHash();
}

/**
 * Build a valid fixed-depth membership witness without constructing all
 * 65,536 leaves. Synthetic siblings define a test-only tree whose root still
 * exercises the exact production verification and wire format.
 */
inline SyntheticChildAuthorization MakeSyntheticChildAuthorization(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    uint32_t epoch,
    const ChildPublicKey& public_key,
    uint64_t discriminator)
{
    ChildKeyTreeCommitment commitment;
    commitment.generation = 1;
    commitment.first_epoch = 0;
    commitment.tree_id = SyntheticHash(
        "SYS_PQ_TEST_TREE_ID_V1", genesis_hash, pro_tx_hash,
        discriminator, 0);

    const ChildKeyTreeConfig config{
        genesis_hash,
        commitment.tree_id,
        commitment.generation,
        commitment.first_epoch,
        commitment.depth,
    };
    ChildKeyProof proof;
    proof.public_key = public_key;
    uint256 current{GetChildKeyTreeLeafHash(config, epoch, public_key)};
    std::size_t path{static_cast<std::size_t>(epoch)};
    for (uint16_t level{1}; level <= CHILD_KEY_TREE_DEPTH; ++level) {
        proof.siblings[level - 1] = SyntheticHash(
            "SYS_PQ_TEST_SIBLING_V1", genesis_hash, pro_tx_hash,
            discriminator, level);
        current = (path & 1U) != 0
            ? GetChildKeyTreeNodeHash(config, level,
                                      proof.siblings[level - 1], current)
            : GetChildKeyTreeNodeHash(config, level, current,
                                      proof.siblings[level - 1]);
        path >>= 1;
    }
    commitment.root = current;
    return {
        FrozenChildRootRecord{pro_tx_hash, 1, epoch, commitment},
        proof,
    };
}

} // namespace llmq::pq::test

#endif // SYSCOIN_TEST_PQ_TEST_UTIL_H
