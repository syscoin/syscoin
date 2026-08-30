// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_PQ_TEST_UTIL_H
#define SYSCOIN_TEST_PQ_TEST_UTIL_H

#include <hash.h>
#include <llmq/pq_child_key_tree.h>
#include <llmq/pq_roster_beacon.h>
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

/**
 * Reconstruct the external normal-path facts represented by a synthetic test
 * statement. Production must obtain these facts from chain ancestry and the
 * active Bitcoin header view instead.
 */
inline NormalRosterAuthorizationInput
MakeSyntheticNormalRosterAuthorizationInput(
    const ChainLockStatement& statement,
    const RosterAuthorizationPriorState& previous)
{
    NormalRosterAuthorizationInput input;
    input.newest_epoch =
        statement.roster_beacons.active.seeds.back().epoch;
    input.target_height = statement.height;
    input.target_block_hash = statement.block_hash;
    input.predecessor_height = statement.previous_chainlock_height;
    input.predecessor_block_hash =
        statement.previous_chainlock_hash;
    input.prior_authorization_height =
        statement.previous_chainlock_height;
    input.prior_authorization_block_hash =
        statement.previous_chainlock_hash;
    input.previous = previous;
    input.previous_btcc_cursor = statement.previous_btcc_cursor;
    input.accepted_btcc_cursor = statement.accepted_btcc_cursor;
    input.btcc_advance = statement.btcc_advance;
    input.next_snapshot = RosterBeaconSnapshotCoverage{
        input.newest_epoch + 1, statement.previous_chainlock_height + 1,
        {}, false};

    const auto active_range = [](const RosterBeaconSeed& seed) {
        ValidatedRosterBeaconRange range;
        const auto future_height{seed.FutureBTCHeight()};
        if (!future_height) return range;
        range.anchor_hash = seed.anchor_cursor.btc_hash;
        range.anchor_height = seed.anchor_btc_height;
        range.future_hash = seed.future_btc_hash;
        range.future_height = *future_height;
        range.active_tip_height =
            *future_height +
            static_cast<int32_t>(
                ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS) -
            1;
        range.is_active = true;
        return range;
    };

    if (statement.roster_transition ==
        RosterAuthorizationTransitionKind::ROTATE) {
        if (previous.window.next.IsReady()) {
            input.ready_rotation = active_range(previous.window.next);
        } else if (previous.window.next.state ==
                   RosterBeaconState::PENDING) {
            input.pending_reveal = active_range(
                statement.roster_beacons.active.seeds.back());
        }
    } else if (statement.roster_transition ==
               RosterAuthorizationTransitionKind::REVEAL) {
        input.pending_reveal = active_range(statement.roster_beacons.next);
    }

    const bool observed_next{
        (statement.roster_transition ==
             RosterAuthorizationTransitionKind::OBSERVE ||
         statement.roster_transition ==
             RosterAuthorizationTransitionKind::ROTATE) &&
        statement.roster_beacons.next.state ==
            RosterBeaconState::PENDING};
    if (observed_next) {
        input.next_snapshot.height = input.prior_authorization_height;
        input.next_snapshot.hash = input.prior_authorization_block_hash;
        input.next_snapshot.prior_authorization_is_descendant = true;
        input.accepted_anchor = ValidatedRosterBeaconAnchor{
            statement.roster_beacons.next.anchor_cursor,
            statement.roster_beacons.next.anchor_btc_height,
            statement.roster_beacons.next.anchor_btc_height,
            true};
    }
    return input;
}

} // namespace llmq::pq::test

#endif // SYSCOIN_TEST_PQ_TEST_UTIL_H
