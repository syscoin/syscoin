// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_PQ_GOVERNANCE_AUTH_INTERFACE_H
#define SYSCOIN_GOVERNANCE_PQ_GOVERNANCE_AUTH_INTERFACE_H

#include <llmq/pq_global_auth.h>

#include <span>
#include <string>

class CBlockIndex;
class CDeterministicMNList;
class COutPoint;

namespace llmq::pq {

struct PQRegistrySnapshot;
class PQRegistryReadView;

[[nodiscard]] bool IsGovernanceAuthorizationOnBranch(
    const CBlockIndex& validation_branch,
    const GovernanceAuthorization& authorization) noexcept;

/** Resolve the current active global key at the post-anchor signing tip. */
[[nodiscard]] bool GetCurrentGovernanceSigningKey(
    const CBlockIndex& signing_tip,
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    GlobalKeyRecord& key,
    std::string& error);

/** Cheap branch/current-authority checks used to revalidate cached objects. */
[[nodiscard]] bool CheckGovernanceAuthorizationContextForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error);

[[nodiscard]] bool CheckGovernanceAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistrySnapshot& current_snapshot,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error);

[[nodiscard]] bool CheckGovernanceAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistryReadView& current_snapshot,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error);

/**
 * Verify with the exact active key at validation_branch. The signed block
 * remains an ancestry/freshness commitment, while rotation or revocation at
 * the validation tip immediately invalidates an off-chain authorization.
 */
[[nodiscard]] bool VerifyGovernanceAuthorizationForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const COutPoint& masternode_outpoint,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash,
    std::span<const unsigned char> encoded,
    std::string& error);

/** Snapshot overload for callers that already hold the authenticated tip. */
[[nodiscard]] bool VerifyGovernanceAuthorizationForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistrySnapshot& current_snapshot,
    const COutPoint& masternode_outpoint,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash,
    std::span<const unsigned char> encoded,
    std::string& error);

} // namespace llmq::pq

#endif // SYSCOIN_GOVERNANCE_PQ_GOVERNANCE_AUTH_INTERFACE_H
