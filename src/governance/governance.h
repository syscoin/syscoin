// Copyright (c) 2014-2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_GOVERNANCE_H
#define SYSCOIN_GOVERNANCE_GOVERNANCE_H

#include <governance/governanceobject.h>

#include <array>
#include <atomic>
#include <cachemap.h>
#include <cachemultimap.h>
#include <chrono>
#include <evo/evodb.h>
#include <limits>
#include <map>
#include <memory>
#include <net_types.h>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <util/check.h>
#include <utility>

class CBloomFilter;
class CBlockIndex;
class CConnman;
template<typename T>
class CFlatDB;
class CInv;

class CGovernanceManager;
class CGovernanceTriggerManager;
class CGovernanceObject;
class CGovernanceVote;
class CConnman;
class PeerManager;
class CSuperblock;
extern std::unique_ptr<CGovernanceManager> governance;

static constexpr int RATE_BUFFER_SIZE = 5;
static constexpr bool DEFAULT_GOVERNANCE_ENABLE{true};

class CDeterministicMNList;
using CDeterministicMNListPtr = std::shared_ptr<CDeterministicMNList>;

namespace governance_tests {
class CGovernanceManagerTestAccess;
bool PublishGovernanceReadyForTest(CGovernanceManager& manager,
                                   const CBlockIndex& tip);
}

enum class GovernanceObjectAdmissionResult {
    ACCEPTED,
    UNAVAILABLE,
    LOCAL_INELIGIBLE,
    STALE_TIP,
    DUPLICATE,
    RESOURCE_LIMIT,
    INVALID,
};

enum class GovernanceTriggerAdmissionResult {
    ACCEPTED,
    UNAVAILABLE,
    LOCAL_INELIGIBLE,
    INVALID,
};

[[nodiscard]] std::string_view GovernanceObjectAdmissionError(
    GovernanceObjectAdmissionResult result);

// SYSCOIN: bound peer-triggered SLH work when serving governance votes.
class GovernanceVoteSyncRateLimiter final
{
public:
    static constexpr std::size_t MAX_SOURCES{512};
    static constexpr std::size_t MAX_VERIFICATIONS_PER_REQUEST{256};
    static constexpr uint8_t SOURCE_BURST{2};
    static constexpr auto SOURCE_REFILL_INTERVAL{std::chrono::minutes{5}};
    static constexpr auto GLOBAL_MIN_INTERVAL{std::chrono::seconds{2}};
    static constexpr auto SOURCE_EXPIRY{std::chrono::hours{24}};

    [[nodiscard]] bool Consume(
        int64_t peer, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, std::chrono::microseconds now);
    [[nodiscard]] std::size_t Size() const noexcept { return m_buckets.size(); }

private:
    struct SourceIdentity {
        uint256 authenticated_pro_tx;
        uint64_t keyed_net_group{0};
        int64_t fallback_peer{-1};

        friend bool operator<(const SourceIdentity& lhs,
                              const SourceIdentity& rhs) noexcept
        {
            return std::tie(lhs.authenticated_pro_tx,
                            lhs.keyed_net_group, lhs.fallback_peer) <
                   std::tie(rhs.authenticated_pro_tx,
                            rhs.keyed_net_group, rhs.fallback_peer);
        }
    };

    struct Bucket {
        uint8_t tokens{SOURCE_BURST};
        std::chrono::microseconds last_refill{0};
        std::chrono::microseconds last_seen{0};
    };

    std::map<SourceIdentity, Bucket> m_buckets;
    std::chrono::microseconds m_next_global_request{0};
};
// SYSCOIN: end bounded governance vote sync admission.

// Cheap page requests are rate-limited independently of expensive payload
// verification. Authenticated peers remain constrained by both their ProTx
// identity and the keyed netgroup they used before MNAUTH.
class GovernancePageServeRateLimiter final
{
public:
    enum class RequestResult : uint8_t {
        ACCEPTED,
        GLOBAL_BUSY,
        SOURCE_LIMITED,
    };

    static constexpr std::size_t MAX_SOURCE_RECORDS{1024};
    static constexpr uint8_t SOURCE_BURST{2};
    static constexpr auto SOURCE_REFILL_INTERVAL{
        std::chrono::milliseconds{500}};
    static constexpr auto GLOBAL_MIN_INTERVAL{
        std::chrono::milliseconds{25}};
    static constexpr auto SOURCE_EXPIRY{std::chrono::hours{1}};
    static constexpr std::size_t SOURCE_BYTE_CAPACITY{
        MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES};
    static constexpr std::size_t GLOBAL_BYTE_CAPACITY{
        2 * MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES};
    static constexpr std::size_t SOURCE_BYTE_REFILL_PER_SECOND{1ULL << 20};
    static constexpr std::size_t GLOBAL_BYTE_REFILL_PER_SECOND{4ULL << 20};

    [[nodiscard]] RequestResult Consume(
        int64_t peer, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, std::chrono::microseconds now);

    /** Charge an authorized payload before allocating its wire encoding. */
    [[nodiscard]] bool ConsumePayloadBytes(
        int64_t peer, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, std::size_t bytes,
        std::chrono::microseconds now);

private:
    struct SourceKey {
        bool authenticated{false};
        uint256 pro_tx_hash;
        uint64_t keyed_net_group{0};
        int64_t fallback_peer{-1};

        friend bool operator<(const SourceKey& lhs,
                              const SourceKey& rhs) noexcept
        {
            return std::tie(lhs.authenticated, lhs.pro_tx_hash,
                            lhs.keyed_net_group, lhs.fallback_peer) <
                   std::tie(rhs.authenticated, rhs.pro_tx_hash,
                            rhs.keyed_net_group, rhs.fallback_peer);
        }
    };
    struct Bucket {
        uint8_t tokens{SOURCE_BURST};
        std::chrono::microseconds last_refill{0};
        std::chrono::microseconds last_seen{0};
        std::size_t byte_tokens{SOURCE_BYTE_CAPACITY};
        std::chrono::microseconds byte_last_refill{0};
    };

    std::map<SourceKey, Bucket> m_buckets;
    std::chrono::microseconds m_next_global_request{0};
    std::size_t m_global_byte_tokens{GLOBAL_BYTE_CAPACITY};
    std::chrono::microseconds m_global_byte_last_refill{0};
};

// Cache hits are cheap, but constructing a new immutable scope can serialize
// tens of MiB. Charge that work independently from the per-request limiter so
// rotating peers/scopes cannot repeatedly hold governance validation locks.
class GovernancePageBuildRateLimiter final
{
public:
    static constexpr std::size_t TOKEN_CAPACITY{
        MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES};
    static constexpr std::size_t MINIMUM_BUILD_CHARGE{1ULL << 20};
    static constexpr std::size_t REFILL_BYTES_PER_SECOND{1ULL << 20};
    static constexpr auto MIN_BUILD_INTERVAL{
        std::chrono::milliseconds{500}};

    /** Reserve the minimum work charge before inspecting an uncached scope. */
    [[nodiscard]] bool Begin(std::chrono::microseconds now);

    /** Charge the measured remainder after the bounded size preflight. */
    [[nodiscard]] bool Charge(std::size_t retained_bytes);

private:
    std::size_t m_tokens{TOKEN_CAPACITY};
    std::chrono::microseconds m_last_refill{0};
    std::chrono::microseconds m_next_build{0};
    bool m_build_active{false};
};

class CRateCheckBuffer
{
private:
    std::vector<int64_t> vecTimestamps;

    int nDataStart;

    int nDataEnd;

    bool fBufferEmpty;

public:
    CRateCheckBuffer() :
        vecTimestamps(RATE_BUFFER_SIZE),
        nDataStart(0),
        nDataEnd(0),
        fBufferEmpty(true)
    {
    }

    void AddTimestamp(int64_t nTimestamp)
    {
        if ((nDataEnd == nDataStart) && !fBufferEmpty) {
            // Buffer full, discard 1st element
            nDataStart = (nDataStart + 1) % RATE_BUFFER_SIZE;
        }
        vecTimestamps[nDataEnd] = nTimestamp;
        nDataEnd = (nDataEnd + 1) % RATE_BUFFER_SIZE;
        fBufferEmpty = false;
    }

    int64_t GetMinTimestamp()
    {
        int nIndex = nDataStart;
        int64_t nMin = std::numeric_limits<int64_t>::max();
        if (fBufferEmpty) {
            return nMin;
        }
        do {
            if (vecTimestamps[nIndex] < nMin) {
                nMin = vecTimestamps[nIndex];
            }
            nIndex = (nIndex + 1) % RATE_BUFFER_SIZE;
        } while (nIndex != nDataEnd);
        return nMin;
    }

    int64_t GetMaxTimestamp()
    {
        int nIndex = nDataStart;
        int64_t nMax = 0;
        if (fBufferEmpty) {
            return nMax;
        }
        do {
            if (vecTimestamps[nIndex] > nMax) {
                nMax = vecTimestamps[nIndex];
            }
            nIndex = (nIndex + 1) % RATE_BUFFER_SIZE;
        } while (nIndex != nDataEnd);
        return nMax;
    }

    int GetCount() const
    {
        if (fBufferEmpty) {
            return 0;
        }
        if (nDataEnd > nDataStart) {
            return nDataEnd - nDataStart;
        }
        return RATE_BUFFER_SIZE - nDataStart + nDataEnd;
    }

    double GetRate()
    {
        int nCount = GetCount();
        if (nCount < RATE_BUFFER_SIZE) {
            return 0.0;
        }
        int64_t nMin = GetMinTimestamp();
        int64_t nMax = GetMaxTimestamp();
        if (nMin == nMax) {
            // multiple objects with the same timestamp => infinite rate
            return 1.0e10;
        }
        return double(nCount) / double(nMax - nMin);
    }

    SERIALIZE_METHODS(CRateCheckBuffer, obj)
    {
        READWRITE(obj.vecTimestamps, obj.nDataStart, obj.nDataEnd, obj.fBufferEmpty);
    }
};

class GovernanceStore
{
    friend class governance_tests::CGovernanceManagerTestAccess;

protected:
    struct last_object_rec {
        explicit last_object_rec(bool fStatusOKIn = true) :
            triggerBuffer(),
            fStatusOK(fStatusOKIn)
        {
        }

        SERIALIZE_METHODS(last_object_rec, obj)
        {
            READWRITE(obj.triggerBuffer, obj.fStatusOK);
        }

        CRateCheckBuffer triggerBuffer;
        bool fStatusOK;
    };

    using object_ref_cm_t = CacheMap<uint256, CGovernanceObject*>;
    using txout_m_t = std::map<COutPoint, last_object_rec>;
    using vote_cmm_t = CacheMultiMap<uint256, vote_time_pair_t>;

protected:
    static constexpr int MAX_CACHE_SIZE = 1000000;
    // SYSCOIN: orphan votes are unauthenticated until their parent arrives.
    static constexpr std::size_t MAX_ORPHAN_VOTES{4096};
    static constexpr std::size_t MAX_ORPHAN_VOTES_PER_OBJECT{32};
    static const std::string SERIALIZATION_VERSION_STRING;

public:
    // critical section to protect the inner data structures
    mutable RecursiveMutex cs;

protected:
    // keep track of the scanning errors
    std::map<uint256, CGovernanceObject> mapObjects GUARDED_BY(cs);
    // Shared immutable object-page view. It is rebuilt only when object
    // eligibility changes or the next cached trigger reaches its event height.
    mutable bool m_object_page_dirty GUARDED_BY(cs){true};
    mutable std::weak_ptr<const GovernancePageImmutableSnapshot>
        m_object_page_snapshot GUARDED_BY(cs);
    mutable int m_object_page_next_trigger_height GUARDED_BY(cs){
        std::numeric_limits<int>::max()};
    std::shared_ptr<GovernancePageSnapshotBudget> m_page_snapshot_budget;
    mutable uint64_t m_next_page_snapshot_instance GUARDED_BY(cs){1};
    // mapErasedGovernanceObjects contains key-value pairs, where
    //   key   - governance object's hash
    //   value - expiration time for deleted objects
    std::map<uint256, int64_t> mapErasedGovernanceObjects;
    object_ref_cm_t cmapVoteToObject;
    CacheMap<uint256, CGovernanceVote> cmapInvalidVotes;
    vote_cmm_t cmmapOrphanVotes;
    txout_m_t mapLastMasternodeObject;
    // used to check for changed voting keys
    CDeterministicMNListPtr lastMNListForVotingKeys;

public:
    GovernanceStore();
    ~GovernanceStore() = default;

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        LOCK(cs);
        s   << SERIALIZATION_VERSION_STRING
            << mapErasedGovernanceObjects
            << cmapInvalidVotes
            << cmmapOrphanVotes
            << mapObjects
            << mapLastMasternodeObject
            << *lastMNListForVotingKeys;
    }

    template<typename Stream>
    void Unserialize(Stream &s)
    {
        Clear();

        LOCK(cs);
        std::string strVersion;
        s >> strVersion;
        if (strVersion != SERIALIZATION_VERSION_STRING) {
            return;
        }

        s   >> mapErasedGovernanceObjects
            >> cmapInvalidVotes
            >> cmmapOrphanVotes
            >> mapObjects
            >> mapLastMasternodeObject
            >> *lastMNListForVotingKeys;
    }

    void Clear();

protected:
    void InvalidateObjectPageCache() const EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] std::optional<uint64_t>
    NextGovernancePageSnapshotInstance() const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    std::string ToString() const;
};

//
// Governance Manager : Contains all proposals for the budget
//
class CGovernanceManager : public GovernanceStore
{
    friend class CGovernanceObject;
    friend class governance_tests::CGovernanceManagerTestAccess;
    friend bool governance_tests::PublishGovernanceReadyForTest(
        CGovernanceManager& manager, const CBlockIndex& tip);

private:
    using hash_s_t = std::set<uint256>;
    using db_type = CFlatDB<GovernanceStore>;

    struct PQGovernanceTipIdentity {
        int32_t height{-1};
        uint256 hash;

        PQGovernanceTipIdentity() = default;
        explicit PQGovernanceTipIdentity(const CBlockIndex& tip);

        friend bool operator==(const PQGovernanceTipIdentity&,
                               const PQGovernanceTipIdentity&) = default;
    };

    struct PQGovernanceReadinessState {
        std::optional<PQGovernanceTipIdentity> observed_tip;
        std::optional<PQGovernanceTipIdentity> ready_tip;
        uint64_t validation_context_epoch{1};
    };

    // MSVC deprecates the legacy shared-pointer atomics, while supported older
    // libc++ releases do not yet provide the C++20 specialization.
    class AtomicPQGovernanceReadiness
    {
        using value_type =
            std::shared_ptr<const PQGovernanceReadinessState>;

    public:
        explicit AtomicPQGovernanceReadiness(value_type value) noexcept : m_value{std::move(value)}
        {
        }

        value_type load(std::memory_order order) const noexcept
        {
#if defined(__cpp_lib_atomic_shared_ptr) && \
    __cpp_lib_atomic_shared_ptr >= 201711L
            return m_value.load(order);
#else
            return std::atomic_load_explicit(&m_value, order);
#endif
        }

        bool compare_exchange_weak(value_type& expected,
                                   value_type desired,
                                   std::memory_order success,
                                   std::memory_order failure) noexcept
        {
#if defined(__cpp_lib_atomic_shared_ptr) && \
    __cpp_lib_atomic_shared_ptr >= 201711L
            return m_value.compare_exchange_weak(
                expected, std::move(desired), success, failure);
#else
            return std::atomic_compare_exchange_weak_explicit(
                &m_value, &expected, std::move(desired), success, failure);
#endif
        }

    private:
#if defined(__cpp_lib_atomic_shared_ptr) && \
    __cpp_lib_atomic_shared_ptr >= 201711L
        std::atomic<value_type> m_value;
#else
        value_type m_value;
#endif
    };

    struct PQGovernanceAuthority {
        uint256 pro_tx_hash;
        uint32_t global_key_version{0};

        friend bool operator==(const PQGovernanceAuthority&,
                               const PQGovernanceAuthority&) = default;
    };
    using pq_authority_map_t =
        std::map<COutPoint, PQGovernanceAuthority>;
    using delegated_authority_map_t = std::map<COutPoint, CKeyID>;
    using pq_vote_object_index_t =
        std::map<COutPoint, std::set<uint256>>;

    class ScopedLockBool
    {
        bool& ref;
        bool fPrevValue;

    public:
        ScopedLockBool(RecursiveMutex& _cs, bool& _ref, bool _value) EXCLUSIVE_LOCKS_REQUIRED(_cs):
            ref(_ref)
        {
            AssertLockHeld(_cs);
            fPrevValue = ref;
            ref = _value;
        }

        ~ScopedLockBool()
        {
            ref = fPrevValue;
        }
    };

private:
    static const int MAX_TIME_FUTURE_DEVIATION;
    static const int RELIABLE_PROPAGATION_TIME;
    static constexpr uint64_t MAX_PERSISTED_VOTE_BYTES{512ULL << 20};
    static constexpr uint64_t MAX_GOVERNANCE_CACHE_FILE_BYTES{768ULL << 20};

private:
    ChainstateManager& chainman;
    const std::unique_ptr<db_type> m_db;
    std::atomic<bool> is_valid{false};
    AtomicPQGovernanceReadiness m_pq_governance_readiness;


    int64_t nTimeLastDiff;
    // keep track of current block height
    std::atomic<int> nCachedBlockHeight;
    std::map<uint256, CGovernanceObject> mapPostponedObjects;
    hash_s_t setAdditionalRelayObjects;
    bool fRateChecksEnabled;
    std::optional<uint256> votedFundingYesTriggerHash;
    std::map<uint256, std::shared_ptr<CSuperblock>> mapTrigger;
    std::set<uint256> m_pq_inactive_triggers GUARDED_BY(cs);
    Mutex m_vote_sync_rate_mutex;
    GovernanceVoteSyncRateLimiter m_vote_sync_rate
        GUARDED_BY(m_vote_sync_rate_mutex);
    Mutex m_page_serve_rate_mutex;
    GovernancePageServeRateLimiter m_page_serve_rate
        GUARDED_BY(m_page_serve_rate_mutex);
    mutable Mutex m_page_build_rate_mutex;
    mutable GovernancePageBuildRateLimiter m_page_build_rate
        GUARDED_BY(m_page_build_rate_mutex);
    pq_authority_map_t m_pq_authorities GUARDED_BY(cs);
    delegated_authority_map_t m_delegated_funding_authorities
        GUARDED_BY(cs);
    pq_vote_object_index_t m_pq_vote_objects GUARDED_BY(cs);
    pq_vote_object_index_t m_delegated_funding_vote_objects
        GUARDED_BY(cs);
    uint256 m_pq_authority_tip_hash GUARDED_BY(cs);
    int32_t m_pq_authority_tip_height GUARDED_BY(cs){-1};
    bool m_pq_authority_snapshot_valid GUARDED_BY(cs){false};
    std::size_t m_governance_valid_mn_count GUARDED_BY(cs){0};
    bool m_rebuilding_cached_triggers GUARDED_BY(cs){false};
    bool m_pq_trigger_state_initialized GUARDED_BY(cs){false};
    uint64_t m_pq_vote_context_checks GUARDED_BY(cs){0};
    uint64_t m_delegated_vote_context_checks GUARDED_BY(cs){0};
    uint64_t m_pq_full_revalidations GUARDED_BY(cs){0};
    uint64_t m_persisted_vote_bytes GUARDED_BY(cs){0};

public:
    const std::unique_ptr<CEvoDB<uint256, CAmount, StaticSaltedHasher>> m_sb;
    explicit CGovernanceManager(ChainstateManager& _chainman);
    ~CGovernanceManager();
    bool FlushCacheToDisk(bool fSync = true);

    bool LoadCache(bool load_cache);

    bool IsValid() const
    {
        return is_valid.load(std::memory_order_acquire);
    }
    [[nodiscard]] bool IsReady() const;
    [[nodiscard]] bool IsReadyForTip(const CBlockIndex* tip) const;
    [[nodiscard]] std::optional<uint64_t>
    GetPQGovernanceValidationContextEpoch() const;
    void ObserveChainTip(const CBlockIndex* tip);

    // SYSCOIN: SLH vote verification is forbidden under global state locks.
    void SyncSingleObjVotes(CNode* pnode, const uint256& nProp,
                            const CBloomFilter& filter, CConnman& connman,
                            PeerManager& peerman);
    void SyncObjects(CNode* pnode, CConnman& connman, PeerManager &peerman) const;

    void ProcessMessage(CNode* pfrom, const std::string& strCommand,
                        CDataStream& vRecv, CConnman& connman,
                        PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!m_page_serve_rate_mutex);

    /** Build a deterministic bounded page for objects or one parent's votes. */
    [[nodiscard]] std::optional<GovernancePageBuildResult>
    BuildGovernancePage(
        const CGovernancePageRequest& request,
        std::shared_ptr<const GovernancePageImmutableSnapshot>
            continuation = {},
        std::optional<std::chrono::microseconds>
            build_request_time = std::nullopt) const;

    void ResetVotedFundingTrigger();

    void DoMaintenance(CConnman& connman);

    const CGovernanceObject* FindConstGovernanceObject(const uint256& nHash) const;
    CGovernanceObject* FindGovernanceObject(const uint256& nHash);
    CGovernanceObject* FindGovernanceObjectByDataHash(const uint256& nDataHash);
    void DeleteGovernanceObject(const uint256& nHash);

    // These commands are only used in RPC
    std::vector<CGovernanceVote> GetCurrentVotes(const uint256& nParentHash, const COutPoint& mnCollateralOutpointFilter) const;
    void GetAllNewerThan(std::vector<CGovernanceObject>& objs, int64_t nMoreThanTime) const;

    [[nodiscard]] GovernanceObjectAdmissionResult AddGovernanceObject(
        CGovernanceObject& govobj, PeerManager& peerman,
        const CNode* pfrom = nullptr,
        const CBlockIndex* expected_tip = nullptr,
        const CBlockIndex* pq_preverified_tip = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main, !cs);

    void CheckAndRemove();

    UniValue ToJson() const;

    void UpdatedBlockTip(const CBlockIndex* pindex, CConnman& connman,
                         PeerManager& peerman);
    int64_t GetLastDiffTime() const
    {
        LOCK(cs);
        return nTimeLastDiff;
    }
    void UpdateLastDiffTime(int64_t nTimeIn)
    {
        LOCK(cs);
        nTimeLastDiff = nTimeIn;
    }

    int GetCachedBlockHeight() const { return nCachedBlockHeight.load(std::memory_order_relaxed); }

    // Accessors for thread-safe access to maps
    bool HaveObjectForHash(const uint256& nHash) const;

    bool HaveVoteForHash(const uint256& nHash) const;

    int GetVoteCount() const;

    bool SerializeObjectForHash(const uint256& nHash, CDataStream& ss) const;

    bool SerializeVoteForHash(const uint256& nHash, CDataStream& ss) const;

    /** Size a currently serviceable payload before consuming upload bytes. */
    [[nodiscard]] std::optional<std::size_t>
    GetObjectSerializedSizeForHash(const uint256& nHash, int version) const;

    /** Includes signature slack because vote hashes omit wire signatures. */
    [[nodiscard]] std::optional<std::size_t>
    GetVoteSerializedSizeUpperBoundForHash(const uint256& nHash,
                                           int version) const;

    /** Charge a one-shot governance upload before it enters a peer send queue. */
    [[nodiscard]] bool ConsumeGovernancePayloadBytes(
        int64_t peer, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, std::size_t bytes,
        std::chrono::microseconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_page_serve_rate_mutex);

    /** Exact upload paths authorized by a preceding GOVPAGE response. */
    bool SerializeObjectForPage(const uint256& hash, CDataStream& ss) const;
    bool SerializeVoteForPage(const uint256& parent_hash,
                              const uint256& vote_hash,
                              CDataStream& ss) const;
    bool HaveObjectForPage(const uint256& hash) const;
    bool HaveVoteForPage(const uint256& parent_hash,
                         const uint256& vote_hash) const;

    /**
     * Return the exact bounded root-page object set used to seed vote scopes.
     * A missing result means the current governance view is not ready or is
     * too large to satisfy the paged protocol contract.
     */
    [[nodiscard]] GovernancePageObjectHashesResult
    GetGovernancePageObjectHashes() const;

    [[nodiscard]] GovernanceObjectAdmissionResult AddPostponedObject(
        const CGovernanceObject& govobj,
        const CBlockIndex* expected_tip = nullptr);

    void MasternodeRateUpdate(const CGovernanceObject& govobj);

    bool MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus = false);

    bool MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateFailStatus, bool fForce, bool& fRateCheckBypassed);

    bool ProcessVoteAndRelay(const CGovernanceVote& vote, const CDeterministicMNList& mnList, CGovernanceException& exception, CConnman& connman, PeerManager& peerman);

    void CheckPostponedObjects(PeerManager& peerman);

    bool AreRateChecksEnabled() const
    {
        LOCK(cs);
        return fRateChecksEnabled;
    }

    bool InitOnLoad();

    int RequestGovernanceObjectVotes(CNode* pnode, CConnman& connman, const PeerManager& peerman) const;
    int RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy, CConnman& connman, const PeerManager& peerman) const;

    /*
     * Trigger Management (formerly CGovernanceTriggerManager)
     *   - Track governance objects which are triggers
     *   - After triggers are activated and executed, they can be removed
    */
    std::vector<std::shared_ptr<CSuperblock>> GetActiveTriggers(
        const CBlockIndex* expected_tip = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] GovernanceTriggerAdmissionResult AddNewTrigger(
        uint256 nHash, int active_height) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void CleanAndRemoveTriggers() EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] bool RevalidatePQGovernance(
        const CBlockIndex& validation_tip);
    bool UndoBlock(const CBlockIndex* pindex);

    std::string ToString() const;

private:
    [[nodiscard]] bool IsGovernancePageObjectEligible(
        const uint256& hash, const CGovernanceObject& object,
        int active_height) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::optional<const CSuperblock> CreateSuperblockCandidate(const CBlockIndex* pindex) const EXCLUSIVE_LOCKS_REQUIRED(!cs);
    std::optional<const CGovernanceObject> CreateGovernanceTrigger(
        const std::optional<const CSuperblock>& sb_opt,
        const CBlockIndex* expected_tip, PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void VoteGovernanceTriggers(const std::optional<const CGovernanceObject>& trigger_opt, CConnman& connman, PeerManager& peerman) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    [[nodiscard]] std::vector<uint256> GetNoFundingTriggerHashes() const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    bool VoteFundingTrigger(const uint256& nHash,
                            const vote_outcome_enum_t outcome,
                            CConnman& connman, PeerManager& peerman);
    bool HasAlreadyVotedFundingTrigger() const;

    void RequestGovernanceObject(CNode* pfrom, const uint256& nHash, CConnman& connman, bool fUseFilter = false) const;

    bool ProcessVote(CNode* pfrom, const CGovernanceVote& vote,
                     CGovernanceException& exception, CConnman& connman,
                     bool* orphan_vote_retained = nullptr);

    // SYSCOIN: performs SLH verification without chain/governance/object locks.
    void CheckOrphanVotes(const uint256& object_hash, PeerManager& peerman);
    void DrainReadyOrphanVotes(PeerManager& peerman)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main, !cs);

    [[nodiscard]] bool StoreOrphanVote(
        const uint256& object_hash, const vote_time_pair_t& vote_pair)
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    [[nodiscard]] bool VerifyPQVoteUnlocked(
        const CGovernanceVote& vote,
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        llmq::pq::GovernanceAuthPurpose purpose,
        std::string& error) const;

    [[nodiscard]] bool VerifyOrphanPQVoteUnlocked(
        const CGovernanceVote& vote,
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        std::string& error) const;

    [[nodiscard]] bool VerifyTriggerObjectUnlocked(
        const CGovernanceObject& object,
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        std::string& error) const;

    [[nodiscard]] bool RevalidatePQGovernanceImpl(
        const CBlockIndex& validation_tip);

    [[nodiscard]] static bool BuildPQGovernanceAuthorityMap(
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        const llmq::pq::PQRegistrySnapshot& registry_snapshot,
        pq_authority_map_t& authorities,
        std::string& error);

    [[nodiscard]] static bool BuildDelegatedGovernanceAuthorityMap(
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        delegated_authority_map_t& authorities,
        std::string& error);

    [[nodiscard]] bool IsStraightPQGovernanceExtension(
        const CBlockIndex& validation_tip) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    [[nodiscard]] bool IsRememberedPQGovernanceTip(
        const CBlockIndex& validation_tip) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    [[nodiscard]] static std::set<COutPoint>
    FindChangedPQGovernanceAuthorities(
        const pq_authority_map_t& previous,
        const pq_authority_map_t& next);

    [[nodiscard]] static std::set<COutPoint>
    FindChangedDelegatedGovernanceAuthorities(
        const delegated_authority_map_t& previous,
        const delegated_authority_map_t& next);

    void IndexGovernanceVote(const uint256& object_hash, int object_type,
                             const CGovernanceVote& vote)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    void RemoveObjectFromGovernanceVoteIndexes(
        const uint256& object_hash, const CGovernanceObject& object)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] bool ReconcileGovernanceVotes(
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        const llmq::pq::PQRegistrySnapshot& registry_snapshot,
        bool full_revalidation,
        const std::set<COutPoint>& changed_pq_operators,
        const std::set<COutPoint>& changed_delegated_operators,
        const std::set<uint256>& reactivated_triggers,
        std::set<uint256>& flags_to_refresh,
        std::size_t& checked_pq_votes,
        std::size_t& checked_delegated_votes)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    void RememberFailedPQGovernanceTip(
        const CBlockIndex& validation_tip)
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    void MarkPQGovernanceUnavailableForTip(
        const CBlockIndex& validation_tip);
    [[nodiscard]] bool AdvancePQGovernanceValidationContext();
    [[nodiscard]] bool PublishPQGovernanceReadyForTip(
        const CBlockIndex& validation_tip,
        bool advance_validation_context = false);

    [[nodiscard]] bool RebuildPQTriggerState(
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        const llmq::pq::PQRegistrySnapshot& registry_snapshot,
        bool recompute_cached_flags,
        std::set<uint256>* reactivated_triggers = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] bool IsPQInactiveTrigger(const uint256& object_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    [[nodiscard]] static uint64_t PersistedVoteBytes(
        const CGovernanceVote& vote);
    [[nodiscard]] bool CanAdmitPersistedVoteBytes(
        uint64_t current_object_bytes, uint64_t projected_object_bytes) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] bool ProcessVoteWithBudget(
        CGovernanceObject& object,
        const CBlockIndex& validation_tip,
        const CDeterministicMNList& validation_mn_list,
        const CGovernanceVote& vote,
        CGovernanceException& exception,
        bool pq_signature_preverified)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] bool RebuildPersistedVoteBytes()
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    void EraseOrphanVote(const uint256& object_hash,
                         const vote_time_pair_t& vote_pair)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    void EraseOrphanVotes(const uint256& object_hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    [[nodiscard]] bool RebuildIndexes();

    void RequestOrphanObjects(CConnman& connman);

    void CleanOrphanObjects();

};

bool AreSuperblocksEnabled();

#endif // SYSCOIN_GOVERNANCE_GOVERNANCE_H
