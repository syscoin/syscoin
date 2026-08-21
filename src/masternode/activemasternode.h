// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_MASTERNODE_ACTIVEMASTERNODE_H
#define SYSCOIN_MASTERNODE_ACTIVEMASTERNODE_H

#include <chainparams.h>
#include <masternode/pq_operatorkeys.h>
#include <primitives/transaction.h>
#include <validationinterface.h>
#include <netaddress.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class CConnman;
class ChainstateManager;

namespace llmq::pq {

struct ActiveChildSigningMaterial {
    sphincs_c11::SecretKey secret_key;
    ChildKeyProof key_proof;
};

/**
 * Asynchronous owner of validated public child-key trees.
 *
 * Request() only schedules cache work. GetSigningMaterial() never builds a
 * tree, so consensus and P2P callers cannot be stalled by the expensive
 * 2^16-leaf setup operation.
 */
class ActiveChildKeyCache final {
public:
    ActiveChildKeyCache(const LocalOperatorKeyManager& key_manager,
                        fs::path cache_directory);
    ~ActiveChildKeyCache();

    ActiveChildKeyCache(const ActiveChildKeyCache&) = delete;
    ActiveChildKeyCache& operator=(const ActiveChildKeyCache&) = delete;

    void Request(const uint256& genesis_hash,
                 const std::vector<ChildKeyTreeCommitment>& commitments);

    [[nodiscard]] std::optional<ActiveChildSigningMaterial>
    GetSigningMaterial(const uint256& genesis_hash,
                       const uint256& pro_tx_hash,
                       const FrozenChildRootRecord& record) const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace llmq::pq

struct CActiveMasternodeInfo;
extern CActiveMasternodeInfo activeMasternodeInfo;
extern RecursiveMutex activeMasternodeInfoCs;

struct CActiveMasternodeInfo {
    // The only live operator secret. Short-lived signing leases keep an
    // in-progress operation memory-safe across identity rotation or teardown;
    // the manager still exposes only purpose-specific operations.
    std::shared_ptr<llmq::pq::LocalOperatorKeyManager> operatorKeyManager;
    // Declared after the key manager so its worker is joined first.
    std::unique_ptr<llmq::pq::ActiveChildKeyCache> childKeyCache;

    // Initialized while registering Masternode
    uint256 proTxHash;
    uint32_t globalKeyVersion{0};
    COutPoint outpoint;
    CService service;
    // Reject a signature if the active identity changed and then returned to
    // the same visible values while the expensive operation was in flight.
    uint64_t identityGeneration{0};
};

/** Return only the public, active-tip-bound local MNAUTH identity. */
bool GetActiveMasternodeIdentity(uint256& pro_tx_hash,
                                 uint32_t& global_key_version,
                                 llmq::pq::GlobalPublicKey& global_public_key,
                                 CService& service);

/** Sign only if the caller's identity still matches the active local state. */
bool SignActiveMasternodeMNAUTH(const uint256& pro_tx_hash,
                                uint32_t global_key_version,
                                const uint256& authorization_hash,
                                llmq::pq::GlobalSignature& signature);

bool SignActiveMasternodeGovernanceTrigger(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature);

bool SignActiveMasternodeGovernanceVote(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature);

bool SignActiveMasternodeGovernanceProposalVote(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature);

/**
 * Keep admitted MNAUTH signing demand ahead of governance signing.
 *
 * The async executor owns one move-only reservation for every accepted
 * queued or in-flight sign job. This closes the completion-acknowledgement
 * gap where the next job is not yet an active signer waiter.
 */
class ActiveMasternodeMNAUTHSigningDemand final {
public:
    ActiveMasternodeMNAUTHSigningDemand();
    ~ActiveMasternodeMNAUTHSigningDemand();

    ActiveMasternodeMNAUTHSigningDemand(
        const ActiveMasternodeMNAUTHSigningDemand&) = delete;
    ActiveMasternodeMNAUTHSigningDemand& operator=(
        const ActiveMasternodeMNAUTHSigningDemand&) = delete;
    ActiveMasternodeMNAUTHSigningDemand(
        ActiveMasternodeMNAUTHSigningDemand&& other) noexcept;
    ActiveMasternodeMNAUTHSigningDemand& operator=(
        ActiveMasternodeMNAUTHSigningDemand&& other) noexcept;

private:
    void Release() noexcept;
    bool m_active{true};
};

struct ActiveMasternodeGlobalSigningStats {
    uint32_t active_operations{0};
    uint32_t mnauth_waiters{0};
    uint32_t governance_waiters{0};
    uint32_t mnauth_demands{0};
};

/** Number of global-SLH operations currently inside the serialized signer. */
uint32_t GetActiveMasternodeGlobalSigningCount() noexcept;

/** Snapshot the cross-purpose signer gate without waiting for active crypto. */
ActiveMasternodeGlobalSigningStats
GetActiveMasternodeGlobalSigningStats() noexcept;

/** Return a key and membership proof only from a ready, validated cache. */
std::optional<llmq::pq::ActiveChildSigningMaterial>
GetActiveMasternodeChildSigningMaterial(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const llmq::pq::FrozenChildRootRecord& record);


class CActiveMasternodeManager : public CValidationInterface
{
public:
    enum masternode_state_t {
        MASTERNODE_WAITING_FOR_PROTX,
        MASTERNODE_POSE_BANNED,
        MASTERNODE_REMOVED,
        MASTERNODE_OPERATOR_KEY_CHANGED,
        MASTERNODE_PROTX_IP_CHANGED,
        MASTERNODE_READY,
        MASTERNODE_ERROR,
    };

private:
    masternode_state_t state{MASTERNODE_WAITING_FOR_PROTX};
    std::string strError;
    CConnman& connman;

public:
    CActiveMasternodeManager(CConnman& _connman): connman(_connman) {}
    virtual ~CActiveMasternodeManager() {}
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, ChainstateManager& chainman, bool fInitialDownload) override;

    void Init(const CBlockIndex* pindex);

    std::string GetStateString() const;
    std::string GetStatus() const;

    static bool IsValidNetAddr(CService addrIn);

private:
    bool GetLocalAddress(CService& addrRet);
};
extern std::unique_ptr<CActiveMasternodeManager> activeMasternodeManager;
#endif // SYSCOIN_MASTERNODE_ACTIVEMASTERNODE_H
