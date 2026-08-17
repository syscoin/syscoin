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

static_assert(llmq::pq::GovernanceAuthorization::WIRE_SIZE <=
              MAX_GOVERNANCE_SIGNATURE_SIZE);

namespace llmq::pq {
namespace {

bool CheckPostAnchorBranch(const CBlockIndex& block, std::string& error)
{
    const auto& consensus{Params().GetConsensus()};
    if (Consensus::CheckPQLegacyAnchorConfiguration(consensus) !=
        Consensus::PQLegacyAnchorResult::VALID) {
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

bool GetGovernanceSigningKey(const CBlockIndex& signing_block,
                             const uint256& pro_tx_hash,
                             uint32_t global_key_version,
                             GlobalKeyRecord& key,
                             std::string& error)
{
    if (pro_tx_hash.IsNull() || global_key_version == 0 ||
        !CheckPostAnchorBranch(signing_block, error)) {
        if (error.empty()) error = "invalid governance signer identity";
        return false;
    }
    if (deterministicMNManager == nullptr) {
        error = "deterministic masternode manager is unavailable";
        return false;
    }

    PQRegistrySnapshot snapshot;
    if (!deterministicMNManager->GetPQRegistrySnapshot(
            &signing_block, snapshot, error)) {
        error = "unable to reconstruct governance signing registry: " + error;
        return false;
    }
    const OperatorKeyState* state{snapshot.FindOperator(pro_tx_hash)};
    if (state == nullptr || !state->HasActiveGlobalKey() ||
        state->global_key.key_version != global_key_version ||
        state->global_key.activated_height >
            static_cast<uint32_t>(signing_block.nHeight)) {
        error = "governance signer key is not active at the signed block";
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
    PQRegistrySnapshot current_snapshot;
    if (deterministicMNManager == nullptr ||
        !deterministicMNManager->GetPQRegistrySnapshot(
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

    if (current_snapshot.height != validation_branch.nHeight ||
        current_snapshot.block_hash != validation_branch.GetBlockHash()) {
        error = "current governance registry does not match the branch";
        return false;
    }
    const OperatorKeyState* current_state{
        current_snapshot.FindOperator(authorization.pro_tx_hash)};
    if (current_state == nullptr || !current_state->HasActiveGlobalKey() ||
        !GovernanceAuthorizationMatchesCurrentKey(
            authorization, current_state->global_key)) {
        error = "governance signer key is revoked, rotated, or replaced";
        return false;
    }

    error.clear();
    return true;
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
    GovernanceAuthorization authorization;
    if (unsigned_payload_hash.IsNull() ||
        !CheckGovernanceAuthorizationContextForBranch(
            validation_branch, validation_mn_list, masternode_outpoint,
            encoded, authorization, error)) {
        if (unsigned_payload_hash.IsNull()) {
            error = "invalid governance unsigned payload hash";
        }
        return false;
    }
    const CBlockIndex* signing_block{
        validation_branch.GetAncestor(authorization.signed_height)};
    if (signing_block == nullptr) {
        error = "governance signing block disappeared";
        return false;
    }

    GlobalKeyRecord historical_key;
    if (!GetGovernanceSigningKey(
            *signing_block, authorization.pro_tx_hash,
            authorization.global_key_version, historical_key, error)) {
        return false;
    }
    if (!VerifyGovernanceAuthorization(
            Params().GetConsensus().hashGenesisBlock, historical_key,
            authorization, purpose, unsigned_payload_hash)) {
        error = "invalid governance SLH signature";
        return false;
    }
    error.clear();
    return true;
}

} // namespace llmq::pq
