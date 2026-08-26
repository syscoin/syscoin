// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <evo/deterministicmns.h>

#include <common/args.h>
#include <net.h>
#include <netbase.h>
#include <protocol.h>
#include <tinyformat.h>
#include <util/thread.h>
#include <validation.h>
#include <warnings.h>
#include <logging.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

namespace llmq::pq {
namespace {

bool ContainsCommitment(
    const std::vector<ChildKeyTreeCommitment>& commitments,
    const ChildKeyTreeCommitment& sought)
{
    return std::find(commitments.begin(), commitments.end(), sought) !=
           commitments.end();
}

fs::path ChildTreeCachePath(
    const fs::path& directory,
    const ChildKeyTreeCommitment& commitment)
{
    return directory / fs::u8path(strprintf(
        "%s-%u-%s.dat", commitment.tree_id.ToString(),
        commitment.generation, commitment.root.ToString()));
}

} // namespace

class ActiveChildKeyCache::Impl final {
public:
    Impl(const LocalOperatorKeyManager& key_manager,
         fs::path cache_directory)
        : m_key_manager{key_manager},
          m_cache_directory{std::move(cache_directory)},
          m_worker{&util::TraceThread, "pq-key-cache", [this] { Run(); }}
    {
    }

    ~Impl()
    {
        {
            std::lock_guard lock{m_mutex};
            m_stopping = true;
        }
        m_condition.notify_one();
        if (m_worker.joinable()) m_worker.join();
    }

    void Request(
        const uint256& genesis_hash,
        const std::vector<ChildKeyTreeCommitment>& commitments)
    {
        std::vector<ChildKeyTreeCommitment> desired;
        desired.reserve(commitments.size());
        for (const auto& commitment : commitments) {
            if (!ChildKeyTreeConfig::FromCommitment(genesis_hash,
                                                    commitment) ||
                ContainsCommitment(desired, commitment)) {
                continue;
            }
            desired.push_back(commitment);
        }

        {
            std::lock_guard lock{m_mutex};
            m_genesis_hash = genesis_hash;
            m_desired = std::move(desired);
            m_ready.erase(
                std::remove_if(
                    m_ready.begin(), m_ready.end(),
                    [&](const auto& entry) {
                        return !ContainsCommitment(m_desired,
                                                   entry.commitment);
                    }),
                m_ready.end());
            m_pending.clear();
            for (const auto& commitment : m_desired) {
                const bool ready{std::any_of(
                    m_ready.begin(), m_ready.end(), [&](const auto& entry) {
                        return entry.commitment == commitment;
                    })};
                if (!ready && (!m_building || *m_building != commitment)) {
                    m_pending.push_back(commitment);
                }
            }
        }
        m_condition.notify_one();
    }

    std::optional<ActiveChildSigningMaterial> GetSigningMaterial(
        const uint256& genesis_hash,
        const uint256& pro_tx_hash,
        const FrozenChildRootRecord& record) const
    {
        if (genesis_hash.IsNull() || pro_tx_hash.IsNull() ||
            !record.IsStructurallyValid() ||
            record.pro_tx_hash != pro_tx_hash) {
            return std::nullopt;
        }

        {
            std::lock_guard lock{m_mutex};
            if (m_genesis_hash != genesis_hash ||
                !ContainsCommitment(m_desired, record.commitment)) {
                return std::nullopt;
            }
            const auto it{std::find_if(
                m_ready.begin(), m_ready.end(), [&](const auto& entry) {
                    return entry.commitment == record.commitment;
                })};
            if (it == m_ready.end()) return std::nullopt;
        }

        auto secret_key{m_key_manager.DeriveCommittedChildKey(
            genesis_hash, record.commitment.tree_id,
            record.commitment.generation, record.epoch)};
        if (!secret_key) return std::nullopt;
        const ChildPublicKey public_key{
            sphincs_c11::SerializePublicKey(secret_key->GetPublicKey())};

        std::optional<ChildKeyProof> proof;
        {
            // Key derivation is expensive, so keep it outside this lock and
            // revalidate that Request() did not replace the ready tree.
            std::lock_guard lock{m_mutex};
            if (m_genesis_hash != genesis_hash ||
                !ContainsCommitment(m_desired, record.commitment)) {
                return std::nullopt;
            }
            const auto it{std::find_if(
                m_ready.begin(), m_ready.end(), [&](const auto& entry) {
                    return entry.commitment == record.commitment;
                })};
            if (it == m_ready.end()) return std::nullopt;
            proof = it->tree.GetConsensusProof(public_key, record.epoch);
        }
        if (!proof || proof->public_key != public_key ||
            !VerifyCommittedChildKeyProof(
                genesis_hash, record.commitment, record.epoch, *proof)) {
            return std::nullopt;
        }
        return ActiveChildSigningMaterial{std::move(*secret_key), *proof};
    }

private:
    struct ReadyTree {
        ChildKeyTreeCommitment commitment;
        ChildKeyTree tree;
    };

    void Run()
    {
        while (true) {
            ChildKeyTreeCommitment commitment;
            uint256 genesis_hash;
            {
                std::unique_lock lock{m_mutex};
                m_condition.wait(lock, [&] {
                    return m_stopping || !m_pending.empty();
                });
                if (m_stopping) return;
                commitment = m_pending.front();
                m_pending.pop_front();
                m_building = commitment;
                genesis_hash = m_genesis_hash;
            }

            std::optional<ChildKeyTree> tree;
            const auto config{ChildKeyTreeConfig::FromCommitment(
                genesis_hash, commitment)};
            if (config) {
                const fs::path path{
                    ChildTreeCachePath(m_cache_directory, commitment)};
                tree = ChildKeyTree::Load(path, *config, commitment.root);
                if (!tree) {
                    LogPrintf("PQ child-key tree cache miss for %s; "
                              "building public cache asynchronously\n",
                              commitment.tree_id.ToString());
                    tree = m_key_manager.BuildCommittedChildKeyTree(
                        *config, DefaultChildKeyTreeWorkerCount());
                    if (tree && tree->GetRoot() == commitment.root) {
                        try {
                            fs::create_directories(m_cache_directory);
                        } catch (...) {
                            LogPrintf("Unable to create PQ child-key cache "
                                      "directory %s\n",
                                      fs::PathToString(m_cache_directory));
                        }
                        if (!tree->Save(path)) {
                            LogPrintf("Unable to persist PQ child-key tree "
                                      "cache %s\n",
                                      fs::PathToString(path));
                        }
                    } else {
                        tree.reset();
                    }
                }
            }

            {
                std::lock_guard lock{m_mutex};
                m_building.reset();
                if (tree && m_genesis_hash == genesis_hash &&
                    ContainsCommitment(m_desired, commitment)) {
                    m_ready.erase(
                        std::remove_if(
                            m_ready.begin(), m_ready.end(),
                            [&](const auto& entry) {
                                return entry.commitment == commitment;
                            }),
                        m_ready.end());
                    m_ready.push_back(
                        ReadyTree{commitment, std::move(*tree)});
                }
            }
        }
    }

    const LocalOperatorKeyManager& m_key_manager;
    const fs::path m_cache_directory;
    mutable std::mutex m_mutex;
    std::condition_variable m_condition;
    bool m_stopping{false};
    uint256 m_genesis_hash;
    std::vector<ChildKeyTreeCommitment> m_desired;
    std::deque<ChildKeyTreeCommitment> m_pending;
    std::optional<ChildKeyTreeCommitment> m_building;
    std::vector<ReadyTree> m_ready;
    std::thread m_worker;
};

ActiveChildKeyCache::ActiveChildKeyCache(
    const LocalOperatorKeyManager& key_manager,
    fs::path cache_directory)
    : m_impl{std::make_unique<Impl>(key_manager,
                                    std::move(cache_directory))}
{
}

ActiveChildKeyCache::~ActiveChildKeyCache() = default;

void ActiveChildKeyCache::Request(
    const uint256& genesis_hash,
    const std::vector<ChildKeyTreeCommitment>& commitments)
{
    m_impl->Request(genesis_hash, commitments);
}

std::optional<ActiveChildSigningMaterial>
ActiveChildKeyCache::GetSigningMaterial(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const FrozenChildRootRecord& record) const
{
    return m_impl->GetSigningMaterial(genesis_hash, pro_tx_hash, record);
}

} // namespace llmq::pq

// Keep track of the active Masternode
RecursiveMutex activeMasternodeInfoCs;
CActiveMasternodeInfo activeMasternodeInfo GUARDED_BY(activeMasternodeInfoCs);
std::unique_ptr<CActiveMasternodeManager> activeMasternodeManager;

namespace {

std::mutex activeMasternodeGlobalSigningMutex;
std::condition_variable activeMasternodeGlobalSigningCv;
bool activeMasternodeGlobalSigningOccupied{false};
uint32_t activeMasternodeMNAUTHWaiters{0};
uint32_t activeMasternodeGovernanceWaiters{0};
uint32_t activeMasternodeMNAUTHSigningDemands{0};
std::atomic<uint32_t> activeMasternodeGlobalSigningCount{0};

class ActiveGlobalSigningGuard final {
public:
    explicit ActiveGlobalSigningGuard(bool mnauth_priority)
        : m_mnauth_priority{mnauth_priority}
    {
        std::unique_lock lock{activeMasternodeGlobalSigningMutex};
        uint32_t& waiters{m_mnauth_priority
                              ? activeMasternodeMNAUTHWaiters
                              : activeMasternodeGovernanceWaiters};
        ++waiters;
        try {
            activeMasternodeGlobalSigningCv.wait(lock, [&] {
                return !activeMasternodeGlobalSigningOccupied &&
                       (m_mnauth_priority ||
                        (activeMasternodeMNAUTHWaiters == 0 &&
                         activeMasternodeMNAUTHSigningDemands == 0));
            });
        } catch (...) {
            --waiters;
            activeMasternodeGlobalSigningCv.notify_all();
            throw;
        }
        --waiters;
        activeMasternodeGlobalSigningOccupied = true;
    }

    ~ActiveGlobalSigningGuard()
    {
        {
            std::lock_guard lock{activeMasternodeGlobalSigningMutex};
            assert(activeMasternodeGlobalSigningOccupied);
            activeMasternodeGlobalSigningOccupied = false;
        }
        activeMasternodeGlobalSigningCv.notify_all();
    }

    ActiveGlobalSigningGuard(const ActiveGlobalSigningGuard&) = delete;
    ActiveGlobalSigningGuard& operator=(const ActiveGlobalSigningGuard&) =
        delete;

private:
    const bool m_mnauth_priority;
};

struct ActiveGlobalSigningLease {
    std::shared_ptr<const llmq::pq::LocalOperatorKeyManager> key_manager;
    uint256 pro_tx_hash;
    uint32_t global_key_version{0};
    uint64_t identity_generation{0};
};

bool ActiveGlobalSigningLeaseIsCurrent(
    const ActiveGlobalSigningLease& lease)
    EXCLUSIVE_LOCKS_REQUIRED(activeMasternodeInfoCs)
{
    AssertLockHeld(activeMasternodeInfoCs);
    return fMasternodeMode && lease.key_manager &&
           lease.key_manager->IsValid() &&
           activeMasternodeInfo.operatorKeyManager == lease.key_manager &&
           activeMasternodeInfo.proTxHash == lease.pro_tx_hash &&
           activeMasternodeInfo.globalKeyVersion ==
               lease.global_key_version &&
           activeMasternodeInfo.identityGeneration ==
               lease.identity_generation;
}

template <typename Sign>
bool SignWithActiveGlobalKey(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature,
    bool mnauth_priority,
    Sign&& sign)
{
    signature.fill(0);
    if (pro_tx_hash.IsNull() || global_key_version == 0 ||
        authorization_hash.IsNull()) {
        return false;
    }

    ActiveGlobalSigningLease lease;
    {
        LOCK(activeMasternodeInfoCs);
        if (!fMasternodeMode ||
            activeMasternodeInfo.proTxHash != pro_tx_hash ||
            activeMasternodeInfo.globalKeyVersion != global_key_version ||
            !activeMasternodeInfo.operatorKeyManager ||
            !activeMasternodeInfo.operatorKeyManager->IsValid()) {
            return false;
        }
        lease = {activeMasternodeInfo.operatorKeyManager, pro_tx_hash,
                 global_key_version,
                 activeMasternodeInfo.identityGeneration};
    }

    // The manager lease preserves secret lifetime across teardown. The gate
    // serializes every global-SLH purpose without blocking cheap identity reads;
    // queued MNAUTH work takes the next slot between governance operations.
    ActiveGlobalSigningGuard signing_guard{mnauth_priority};
    {
        LOCK(activeMasternodeInfoCs);
        if (!ActiveGlobalSigningLeaseIsCurrent(lease)) return false;
    }

    struct InflightGuard {
        InflightGuard()
        {
            activeMasternodeGlobalSigningCount.fetch_add(
                1, std::memory_order_release);
        }
        ~InflightGuard()
        {
            activeMasternodeGlobalSigningCount.fetch_sub(
                1, std::memory_order_release);
        }
    } inflight_guard;

    llmq::pq::GlobalSignature candidate{};
    if (!sign(*lease.key_manager, authorization_hash, candidate)) {
        return false;
    }
    {
        LOCK(activeMasternodeInfoCs);
        if (!ActiveGlobalSigningLeaseIsCurrent(lease)) return false;
    }
    signature = std::move(candidate);
    return true;
}

void ClearActiveIdentity() EXCLUSIVE_LOCKS_REQUIRED(activeMasternodeInfoCs)
{
    ++activeMasternodeInfo.identityGeneration;
    activeMasternodeInfo.proTxHash.SetNull();
    activeMasternodeInfo.globalKeyVersion = 0;
    activeMasternodeInfo.outpoint.SetNull();
}

void RequestActiveChildKeyTrees(
    const llmq::pq::OperatorKeyState& operator_state)
    EXCLUSIVE_LOCKS_REQUIRED(activeMasternodeInfoCs)
{
    // Preparation-only functional tests commit synthetic roots because their
    // governance/MNAUTH coverage never requests a child signature. Do not
    // wastefully build a production tree that cannot match that test root.
    if (gArgs.GetBoolArg("-pqoperatorcommitmentteststub", false) &&
        Params().GetChainType() == ChainType::REGTEST &&
        Params().MineBlocksOnDemand() &&
        gArgs.GetBoolArg("-pqfinalitypreparation", false)) {
        return;
    }
    if (!activeMasternodeInfo.operatorKeyManager ||
        !operator_state.HasActiveGlobalKey()) {
        return;
    }
    if (!activeMasternodeInfo.childKeyCache) {
        activeMasternodeInfo.childKeyCache =
            std::make_unique<llmq::pq::ActiveChildKeyCache>(
                *activeMasternodeInfo.operatorKeyManager,
                gArgs.GetDataDirNet() / "llmq/pq-child-key-trees");
    }
    std::vector<llmq::pq::ChildKeyTreeCommitment> commitments;
    commitments.reserve(1 + operator_state.frozen_child_roots.size());
    commitments.push_back(operator_state.global_key.child_key_commitment);
    for (const auto& frozen : operator_state.frozen_child_roots) {
        commitments.push_back(frozen.commitment);
    }
    activeMasternodeInfo.childKeyCache->Request(
        Params().GenesisBlock().GetHash(), commitments);
}

} // namespace

ActiveMasternodeMNAUTHSigningDemand::
    ActiveMasternodeMNAUTHSigningDemand()
{
    std::lock_guard lock{activeMasternodeGlobalSigningMutex};
    ++activeMasternodeMNAUTHSigningDemands;
}

ActiveMasternodeMNAUTHSigningDemand::
    ~ActiveMasternodeMNAUTHSigningDemand()
{
    Release();
}

ActiveMasternodeMNAUTHSigningDemand::
    ActiveMasternodeMNAUTHSigningDemand(
        ActiveMasternodeMNAUTHSigningDemand&& other) noexcept
    : m_active{std::exchange(other.m_active, false)}
{
}

ActiveMasternodeMNAUTHSigningDemand&
ActiveMasternodeMNAUTHSigningDemand::operator=(
    ActiveMasternodeMNAUTHSigningDemand&& other) noexcept
{
    if (this == &other) return *this;
    Release();
    m_active = std::exchange(other.m_active, false);
    return *this;
}

void ActiveMasternodeMNAUTHSigningDemand::Release() noexcept
{
    if (!m_active) return;
    {
        std::lock_guard lock{activeMasternodeGlobalSigningMutex};
        assert(activeMasternodeMNAUTHSigningDemands > 0);
        --activeMasternodeMNAUTHSigningDemands;
        m_active = false;
    }
    activeMasternodeGlobalSigningCv.notify_all();
}

bool GetActiveMasternodeIdentity(uint256& pro_tx_hash,
                                 uint32_t& global_key_version,
                                 llmq::pq::GlobalPublicKey& global_public_key,
                                 CService& service)
{
    LOCK(activeMasternodeInfoCs);
    if (!fMasternodeMode || activeMasternodeInfo.proTxHash.IsNull() ||
        activeMasternodeInfo.globalKeyVersion == 0 ||
        !activeMasternodeInfo.operatorKeyManager ||
        !activeMasternodeInfo.operatorKeyManager->IsValid()) {
        return false;
    }
    pro_tx_hash = activeMasternodeInfo.proTxHash;
    global_key_version = activeMasternodeInfo.globalKeyVersion;
    global_public_key =
        activeMasternodeInfo.operatorKeyManager->GetGlobalPublicKey();
    service = activeMasternodeInfo.service;
    return true;
}

bool SignActiveMasternodeMNAUTH(const uint256& pro_tx_hash,
                                uint32_t global_key_version,
                                const uint256& authorization_hash,
                                llmq::pq::GlobalSignature& signature)
{
    return SignWithActiveGlobalKey(
        pro_tx_hash, global_key_version, authorization_hash, signature,
        /*mnauth_priority=*/true,
        [](const llmq::pq::LocalOperatorKeyManager& key_manager,
           const uint256& hash, llmq::pq::GlobalSignature& output) {
            return key_manager.SignMNAUTH(hash, output);
        });
}

bool SignActiveMasternodeGovernanceTrigger(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature)
{
    return SignWithActiveGlobalKey(
        pro_tx_hash, global_key_version, authorization_hash, signature,
        /*mnauth_priority=*/false,
        [](const llmq::pq::LocalOperatorKeyManager& key_manager,
           const uint256& hash, llmq::pq::GlobalSignature& output) {
            return key_manager.SignGovernanceTrigger(hash, output);
        });
}

bool SignActiveMasternodeGovernanceVote(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature)
{
    return SignWithActiveGlobalKey(
        pro_tx_hash, global_key_version, authorization_hash, signature,
        /*mnauth_priority=*/false,
        [](const llmq::pq::LocalOperatorKeyManager& key_manager,
           const uint256& hash, llmq::pq::GlobalSignature& output) {
            return key_manager.SignGovernanceVote(hash, output);
        });
}

bool SignActiveMasternodeGovernanceProposalVote(
    const uint256& pro_tx_hash,
    uint32_t global_key_version,
    const uint256& authorization_hash,
    llmq::pq::GlobalSignature& signature)
{
    return SignWithActiveGlobalKey(
        pro_tx_hash, global_key_version, authorization_hash, signature,
        /*mnauth_priority=*/false,
        [](const llmq::pq::LocalOperatorKeyManager& key_manager,
           const uint256& hash, llmq::pq::GlobalSignature& output) {
            return key_manager.SignGovernanceProposalVote(hash, output);
        });
}

uint32_t GetActiveMasternodeGlobalSigningCount() noexcept
{
    return activeMasternodeGlobalSigningCount.load(std::memory_order_acquire);
}

ActiveMasternodeGlobalSigningStats
GetActiveMasternodeGlobalSigningStats() noexcept
{
    std::lock_guard lock{activeMasternodeGlobalSigningMutex};
    return {
        activeMasternodeGlobalSigningCount.load(std::memory_order_acquire),
        activeMasternodeMNAUTHWaiters,
        activeMasternodeGovernanceWaiters,
        activeMasternodeMNAUTHSigningDemands,
    };
}

std::optional<llmq::pq::ActiveChildSigningMaterial>
GetActiveMasternodeChildSigningMaterial(
    const uint256& genesis_hash,
    const uint256& pro_tx_hash,
    const llmq::pq::FrozenChildRootRecord& record)
{
    LOCK(activeMasternodeInfoCs);
    if (!fMasternodeMode || pro_tx_hash.IsNull() ||
        activeMasternodeInfo.proTxHash != pro_tx_hash ||
        !activeMasternodeInfo.operatorKeyManager ||
        !activeMasternodeInfo.childKeyCache) {
        return std::nullopt;
    }
    return activeMasternodeInfo.childKeyCache->GetSigningMaterial(
        genesis_hash, pro_tx_hash, record);
}

std::string CActiveMasternodeManager::GetStateString() const
{
    switch (state) {
    case MASTERNODE_WAITING_FOR_PROTX:
        return "WAITING_FOR_PROTX";
    case MASTERNODE_POSE_BANNED:
        return "POSE_BANNED";
    case MASTERNODE_REMOVED:
        return "REMOVED";
    case MASTERNODE_OPERATOR_KEY_CHANGED:
        return "OPERATOR_KEY_CHANGED";
    case MASTERNODE_PROTX_IP_CHANGED:
        return "PROTX_IP_CHANGED";
    case MASTERNODE_READY:
        return "READY";
    case MASTERNODE_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

std::string CActiveMasternodeManager::GetStatus() const
{
    switch (state) {
    case MASTERNODE_WAITING_FOR_PROTX:
        return "Waiting for ProTx to appear on-chain";
    case MASTERNODE_POSE_BANNED:
        return "Masternode was PoSe banned";
    case MASTERNODE_REMOVED:
        return "Masternode removed from list";
    case MASTERNODE_OPERATOR_KEY_CHANGED:
        return "Operator key changed or revoked";
    case MASTERNODE_PROTX_IP_CHANGED:
        return "IP address specified in ProTx changed";
    case MASTERNODE_READY:
        return "Ready";
    case MASTERNODE_ERROR:
        return "Error. " + strError;
    default:
        return "Unknown";
    }
}

void CActiveMasternodeManager::Init(const CBlockIndex* pindex)
{
    LOCK2(cs_main, activeMasternodeInfoCs);

    if (!fMasternodeMode) return;

    if (!deterministicMNManager || !deterministicMNManager->IsDIP3Enforced(pindex->nHeight)) return;

    // Check that our local network configuration is correct
    if (!fListen && Params().RequireRoutableExternalIP()) {
        // listen option is probably overwritten by something else, no good
        state = MASTERNODE_ERROR;
        strError = "Masternode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }

    if (!GetLocalAddress(activeMasternodeInfo.service)) {
        state = MASTERNODE_ERROR;
        return;
    }
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindex);
    if (!activeMasternodeInfo.operatorKeyManager ||
        !activeMasternodeInfo.operatorKeyManager->IsValid()) {
        state = MASTERNODE_ERROR;
        strError = "Local SLH-DSA operator key is unavailable";
        return;
    }

    llmq::pq::PQRegistrySnapshot pq_snapshot;
    std::string registry_error;
    if (!deterministicMNManager->GetPQRegistrySnapshot(
            pindex, pq_snapshot, registry_error)) {
        state = MASTERNODE_ERROR;
        strError = "Unable to load the active PQ operator registry: " +
                   registry_error;
        return;
    }

    const llmq::pq::OperatorKeyState* local_operator{nullptr};
    for (const auto& operator_state : pq_snapshot.operator_states) {
        if (!operator_state.HasActiveGlobalKey() ||
            !activeMasternodeInfo.operatorKeyManager->Matches(
                operator_state.global_key)) {
            continue;
        }
        if (local_operator != nullptr) {
            state = MASTERNODE_ERROR;
            strError = "Local SLH-DSA key is registered to multiple masternodes";
            return;
        }
        local_operator = &operator_state;
    }
    if (local_operator == nullptr) return;

    CDeterministicMNCPtr dmn = mnList.GetMN(local_operator->pro_tx_hash);
    if (!dmn) {
        // MN not appeared on the chain yet
        return;
    }

    if (!mnList.IsMNValid(dmn->proTxHash)) {
        if (mnList.IsMNPoSeBanned(dmn->proTxHash)) {
            state = MASTERNODE_POSE_BANNED;
        } else {
            state = MASTERNODE_REMOVED;
        }
        return;
    }

    LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- proTxHash=%s, proTx=%s\n", dmn->proTxHash.ToString(), dmn->ToString());

    if (activeMasternodeInfo.service != dmn->pdmnState->addr) {
        state = MASTERNODE_ERROR;
        strError = "Local address does not match the address from ProTx";
        LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }

    // Check socket connectivity
    LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- Checking inbound connection to '%s'\n", activeMasternodeInfo.service.ToStringAddrPort());
    std::unique_ptr<Sock> sockPtr = CreateSockTCP(activeMasternodeInfo.service);
    if(!sockPtr) {
        state = MASTERNODE_ERROR;
        strError = "Could not create socket to connect to " + activeMasternodeInfo.service.ToStringAddrPort();
        LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }

    if (sockPtr->Get() == INVALID_SOCKET) {
        state = MASTERNODE_ERROR;
        strError = "Could not create socket to connect to " + activeMasternodeInfo.service.ToStringAddrPort();
        LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }
    bool fConnected = ConnectSocketDirectly(activeMasternodeInfo.service, *sockPtr, nConnectTimeout, true) && sockPtr->IsSelectable();
    sockPtr = std::make_unique<Sock>(INVALID_SOCKET);

    if (!fConnected && Params().RequireRoutableExternalIP()) {
        state = MASTERNODE_ERROR;
        strError = "Could not connect to " + activeMasternodeInfo.service.ToStringAddrPort();
        LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }

    activeMasternodeInfo.proTxHash = dmn->proTxHash;
    activeMasternodeInfo.globalKeyVersion =
        local_operator->global_key.key_version;
    activeMasternodeInfo.outpoint = dmn->collateralOutpoint;
    ++activeMasternodeInfo.identityGeneration;
    RequestActiveChildKeyTrees(*local_operator);
    state = MASTERNODE_READY;
}

void CActiveMasternodeManager::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, ChainstateManager& chainman, bool fInitialDownload)
{
    LOCK2(cs_main, activeMasternodeInfoCs);

    if (!fMasternodeMode) return;
    if (!deterministicMNManager || !deterministicMNManager->IsDIP3Enforced(pindexNew->nHeight)) return;

    if (state == MASTERNODE_READY) {
        auto newMNList = deterministicMNManager->GetListForBlock(pindexNew);
        if (!newMNList.IsMNValid(activeMasternodeInfo.proTxHash)) {
            // MN disappeared from MN list
            state = MASTERNODE_REMOVED;
            ClearActiveIdentity();
            // MN might have reappeared in same block with a new ProTx
            Init(pindexNew);
            return;
        }

        auto newDmn = newMNList.GetMN(activeMasternodeInfo.proTxHash);
        llmq::pq::PQRegistrySnapshot pq_snapshot;
        std::string registry_error;
        const auto* operator_state =
            deterministicMNManager->GetPQRegistrySnapshot(
                pindexNew, pq_snapshot, registry_error)
                ? pq_snapshot.FindOperator(activeMasternodeInfo.proTxHash)
                : nullptr;
        if (operator_state == nullptr || !operator_state->HasActiveGlobalKey() ||
            !activeMasternodeInfo.operatorKeyManager ||
            !activeMasternodeInfo.operatorKeyManager->Matches(
                operator_state->global_key)) {
            // The global operator key changed, was revoked, or its branch
            // snapshot could not be established.
            state = MASTERNODE_OPERATOR_KEY_CHANGED;
            ClearActiveIdentity();
            // MN might have reappeared in same block with a new ProTx
            Init(pindexNew);
            return;
        }
        if (activeMasternodeInfo.globalKeyVersion !=
            operator_state->global_key.key_version) {
            activeMasternodeInfo.globalKeyVersion =
                operator_state->global_key.key_version;
            ++activeMasternodeInfo.identityGeneration;
        }
        RequestActiveChildKeyTrees(*operator_state);

        if (newDmn->pdmnState->addr != activeMasternodeInfo.service) {
            // MN IP changed
            state = MASTERNODE_PROTX_IP_CHANGED;
            ClearActiveIdentity();
            Init(pindexNew);
            return;
        }
    } else {
        // MN might have (re)appeared with a new ProTx or we've found some peers
        // and figured out our local address
        Init(pindexNew);
    }
}

bool CActiveMasternodeManager::GetLocalAddress(CService& addrRet)
{
    // First try to find whatever our own local address is known internally.
    // Addresses could be specified via externalip or bind option, discovered via UPnP
    // or added by TorController. Use some random dummy IPv4 peer to prefer the one
    // reachable via IPv4.
    CNetAddr addrDummyPeer;
    bool fFoundLocal{false};
    std::optional<CNetAddr> addr = LookupHost("8.8.8.8", false);
    if (addr.has_value()) {
        addrDummyPeer = addr.value();
        fFoundLocal = GetLocal(addrRet, &addrDummyPeer) && IsValidNetAddr(addrRet);
    }
    if (!fFoundLocal && !Params().RequireRoutableExternalIP()) {
        std::optional<CService> service_addr = Lookup("127.0.0.1", GetListenPort(), false);
        if (service_addr.has_value()) {
            addrRet = service_addr.value();
            fFoundLocal = true;
        }
    }
    if (!fFoundLocal) {
        bool empty = true;
        // If we have some peers, let's try to find our local address from one of them
        auto service = WITH_LOCK(activeMasternodeInfoCs, return activeMasternodeInfo.service);
        connman.ForEachNodeContinueIf(AllNodes, [&](CNode* pnode) {
            empty = false;
            if (pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(service, &pnode->addr) && IsValidNetAddr(service);
            return !fFoundLocal;
        });
        // nothing and no live connections, can't do anything for now
        if (empty) {
            strError = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
            LogPrint(BCLog::MNSYNC, "CActiveMasternodeManager::GetLocalAddress -- ERROR: %s\n", strError);
            return false;
        }
    }
    return true;
}

bool CActiveMasternodeManager::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return !Params().RequireRoutableExternalIP() ||
           (addrIn.IsIPv4() && g_reachable_nets.Contains(addrIn) && addrIn.IsRoutable());
}
