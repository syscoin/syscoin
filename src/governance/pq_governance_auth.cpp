// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/pq_governance_auth.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/pq_migration.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <governance/governancecommon.h>

#include <utility>

static_assert(llmq::pq::GovernanceAuthorization::WIRE_SIZE <=
              MAX_GOVERNANCE_SIGNATURE_SIZE);

namespace llmq::pq {
namespace {

bool CheckPostAnchorBranch(const CBlockIndex& block, std::string& error)
{
    const auto& consensus{Params().GetConsensus()};
    if (Consensus::CheckPQLegacyAnchorConfiguration(consensus) !=
        Consensus::PQAnchorResult::VALID) {
        error = "PQ legacy anchor is not configured";
        return false;
    }
    if (block.nHeight <= consensus.nPQLegacyAnchorHeight) {
        error = "governance authorization is not post-anchor";
        return false;
    }
    const CBlockIndex* anchor{
        block.GetAncestor(consensus.nPQLegacyAnchorHeight)};
    if (anchor == nullptr ||
        anchor->GetBlockHash() != consensus.hashPQLegacyAnchorBlock) {
        error = "governance authorization is on an incompatible branch";
        return false;
    }
    return true;
}

template <typename FindOperator>
bool CheckGovernanceAuthorizationContextImpl(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    int32_t registry_height,
    const uint256& registry_block_hash,
    FindOperator&& find_operator,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    GlobalKeyRecord* resolved_current_key,
    std::string& error)
{
    if (encoded.size() != GovernanceAuthorization::WIRE_SIZE ||
        !DecodeGovernanceAuthorization(encoded, authorization)) {
        error = "non-canonical governance SLH authorization";
        return false;
    }
    if (validation_mn_list.IsNull() ||
        validation_mn_list.GetHeight() != validation_branch.nHeight ||
        validation_mn_list.GetBlockHash() !=
            validation_branch.GetBlockHash()) {
        error = "governance validation contexts do not match";
        return false;
    }
    if (!IsGovernanceAuthorizationOnBranch(validation_branch,
                                           authorization)) {
        error = "invalid governance signing height or branch";
        return false;
    }
    const CBlockIndex* signing_block{
        validation_branch.GetAncestor(authorization.signed_height)};
    if (signing_block == nullptr ||
        signing_block->GetBlockHash() != authorization.signed_block_hash ||
        !CheckPostAnchorBranch(*signing_block, error)) {
        if (error.empty()) {
            error = "governance signed block is not a branch ancestor";
        }
        return false;
    }

    const auto dmn{
        validation_mn_list.GetValidMNByCollateral(masternode_outpoint)};
    if (!dmn || dmn->proTxHash != authorization.pro_tx_hash) {
        error = "governance signer is not a current valid deterministic masternode";
        return false;
    }
    if (registry_height != validation_branch.nHeight ||
        registry_block_hash != validation_branch.GetBlockHash()) {
        error = "current governance registry does not match the branch";
        return false;
    }
    const OperatorKeyState* current_state{
        find_operator(authorization.pro_tx_hash)};
    // Registry key versions are immutable and monotonic. The exact current
    // record plus its activation bound proves authority without replaying the
    // signed-height registry, while preserving immediate rotation/revocation.
    if (current_state == nullptr || !current_state->HasActiveGlobalKey() ||
        !GovernanceAuthorizationMatchesCurrentKey(
            authorization, current_state->global_key)) {
        error = "governance signer key is revoked, rotated, or replaced";
        return false;
    }
    if (resolved_current_key != nullptr) {
        *resolved_current_key = current_state->global_key;
    }

    error.clear();
    return true;
}

template <typename FindOperator>
bool VerifyGovernanceAuthorizationWithCurrentRegistry(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    int32_t registry_height,
    const uint256& registry_block_hash,
    FindOperator&& find_operator,
    const COutPoint& masternode_outpoint,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash,
    std::span<const unsigned char> encoded,
    std::string& error)
{
    if (unsigned_payload_hash.IsNull()) {
        error = "invalid governance unsigned payload hash";
        return false;
    }
    GovernanceAuthorization authorization;
    GlobalKeyRecord current_key;
    if (!CheckGovernanceAuthorizationContextImpl(
            validation_branch, validation_mn_list, registry_height,
            registry_block_hash, std::forward<FindOperator>(find_operator),
            masternode_outpoint, encoded, authorization, &current_key,
            error)) {
        return false;
    }
    if (!VerifyGovernanceAuthorization(
            Params().GetConsensus().hashGenesisBlock, current_key,
            authorization, purpose, unsigned_payload_hash)) {
        error = "invalid governance SLH signature";
        return false;
    }
    error.clear();
    return true;
}

} // namespace

bool IsGovernanceAuthorizationOnBranch(
    const CBlockIndex& validation_branch,
    const GovernanceAuthorization& authorization) noexcept
{
    if (!authorization.IsHeaderStructurallyValid() ||
        authorization.signed_height > validation_branch.nHeight) {
        return false;
    }
    const CBlockIndex* signing_block{
        validation_branch.GetAncestor(authorization.signed_height)};
    return signing_block != nullptr &&
           signing_block->GetBlockHash() == authorization.signed_block_hash;
}

bool GetCurrentGovernanceSigningKey(const CBlockIndex& signing_tip,
                                    const uint256& pro_tx_hash,
                                    uint32_t global_key_version,
                                    GlobalKeyRecord& key,
                                    std::string& error)
{
    if (pro_tx_hash.IsNull() || global_key_version == 0 ||
        !CheckPostAnchorBranch(signing_tip, error)) {
        if (error.empty()) error = "invalid governance signer identity";
        return false;
    }
    if (deterministicMNManager == nullptr) {
        error = "deterministic masternode manager is unavailable";
        return false;
    }

    PQRegistryReadView snapshot;
    if (!deterministicMNManager->GetPQRegistryReadView(
            &signing_tip, snapshot, error)) {
        error = "unable to reconstruct current governance signing registry: " +
                error;
        return false;
    }
    const OperatorKeyState* state{snapshot.FindOperator(pro_tx_hash)};
    if (state == nullptr || !state->HasActiveGlobalKey() ||
        state->global_key.key_version != global_key_version ||
        state->global_key.activated_height >
            static_cast<uint32_t>(signing_tip.nHeight)) {
        error = "governance signer key is not current at the signing tip";
        return false;
    }
    key = state->global_key;
    error.clear();
    return true;
}

bool CheckGovernanceAuthorizationContextForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error)
{
    PQRegistryReadView current_snapshot;
    if (deterministicMNManager == nullptr ||
        !deterministicMNManager->GetPQRegistryReadView(
            &validation_branch, current_snapshot, error)) {
        error = "unable to reconstruct current governance registry: " + error;
        return false;
    }
    return CheckGovernanceAuthorizationContext(
        validation_branch, validation_mn_list, current_snapshot,
        masternode_outpoint, encoded, authorization, error);
}

bool CheckGovernanceAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistrySnapshot& current_snapshot,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error)
{
    return CheckGovernanceAuthorizationContextImpl(
        validation_branch, validation_mn_list, current_snapshot.height,
        current_snapshot.block_hash,
        [&](const uint256& pro_tx_hash) {
            return current_snapshot.FindOperator(pro_tx_hash);
        },
        masternode_outpoint, encoded, authorization,
        /*resolved_current_key=*/nullptr, error);
}

bool CheckGovernanceAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistryReadView& current_snapshot,
    const COutPoint& masternode_outpoint,
    std::span<const unsigned char> encoded,
    GovernanceAuthorization& authorization,
    std::string& error)
{
    return CheckGovernanceAuthorizationContextImpl(
        validation_branch, validation_mn_list, current_snapshot.Height(),
        current_snapshot.BlockHash(),
        [&](const uint256& pro_tx_hash) {
            return current_snapshot.FindOperator(pro_tx_hash);
        },
        masternode_outpoint, encoded, authorization,
        /*resolved_current_key=*/nullptr, error);
}

bool VerifyGovernanceAuthorizationForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const COutPoint& masternode_outpoint,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash,
    std::span<const unsigned char> encoded,
    std::string& error)
{
    if (unsigned_payload_hash.IsNull()) {
        error = "invalid governance unsigned payload hash";
        return false;
    }
    PQRegistryReadView current_snapshot;
    if (deterministicMNManager == nullptr ||
        !deterministicMNManager->GetPQRegistryReadView(
            &validation_branch, current_snapshot, error)) {
        error = "unable to reconstruct current governance registry: " + error;
        return false;
    }
    return VerifyGovernanceAuthorizationWithCurrentRegistry(
        validation_branch, validation_mn_list, current_snapshot.Height(),
        current_snapshot.BlockHash(),
        [&](const uint256& pro_tx_hash) {
            return current_snapshot.FindOperator(pro_tx_hash);
        },
        masternode_outpoint, purpose, unsigned_payload_hash, encoded, error);
}

bool VerifyGovernanceAuthorizationForBranch(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const PQRegistrySnapshot& current_snapshot,
    const COutPoint& masternode_outpoint,
    GovernanceAuthPurpose purpose,
    const uint256& unsigned_payload_hash,
    std::span<const unsigned char> encoded,
    std::string& error)
{
    return VerifyGovernanceAuthorizationWithCurrentRegistry(
        validation_branch, validation_mn_list, current_snapshot.height,
        current_snapshot.block_hash,
        [&](const uint256& pro_tx_hash) {
            return current_snapshot.FindOperator(pro_tx_hash);
        },
        masternode_outpoint, purpose, unsigned_payload_hash, encoded, error);
}

} // namespace llmq::pq
