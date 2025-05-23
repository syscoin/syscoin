// Copyright (c) 2014-2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_GOVERNANCE_H
#define SYSCOIN_GOVERNANCE_GOVERNANCE_H

#include <governance/governanceobject.h>

#include <cachemap.h>
#include <cachemultimap.h>
#include <net_types.h>
#include <util/check.h>
#include <evo/evodb.h>
#include <optional>

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
    static const std::string SERIALIZATION_VERSION_STRING;

public:
    // critical section to protect the inner data structures
    mutable RecursiveMutex cs;

protected:
    // keep track of the scanning errors
    std::map<uint256, CGovernanceObject> mapObjects GUARDED_BY(cs);
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

    std::string ToString() const;
};

//
// Governance Manager : Contains all proposals for the budget
//
class CGovernanceManager : public GovernanceStore
{
    friend class CGovernanceObject;
private:
    using hash_s_t = std::set<uint256>;
    using db_type = CFlatDB<GovernanceStore>;

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

private:
    ChainstateManager& chainman;
    const std::unique_ptr<db_type> m_db;
    bool is_valid{false};


    int64_t nTimeLastDiff;
    // keep track of current block height
    int nCachedBlockHeight;
    std::map<uint256, CGovernanceObject> mapPostponedObjects;
    hash_s_t setAdditionalRelayObjects;
    hash_s_t setRequestedObjects;
    hash_s_t setRequestedVotes;
    bool fRateChecksEnabled;
    std::optional<uint256> votedFundingYesTriggerHash;
    std::map<uint256, std::shared_ptr<CSuperblock>> mapTrigger;

public:
    const std::unique_ptr<CEvoDB<uint256, CAmount, StaticSaltedHasher>> m_sb;
    explicit CGovernanceManager(ChainstateManager& _chainman);
    ~CGovernanceManager();
    bool FlushCacheToDisk();

    bool LoadCache(bool load_cache);

    bool IsValid() const { return is_valid; }

    /**
     * This is called by AlreadyHave in net_processing.cpp as part of the inventory
     * retrieval process.  Returns true if we want to retrieve the object, otherwise
     * false. (Note logic is inverted in AlreadyHave).
     */
    bool ConfirmInventoryRequest(const GenTxid& gtxid);

    void SyncSingleObjVotes(CNode* pnode, const uint256& nProp, const CBloomFilter& filter, CConnman& connman, PeerManager& peerman);
    void SyncObjects(CNode* pnode, CConnman& connman, PeerManager &peerman) const;

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman, PeerManager& peerman);

    void ResetVotedFundingTrigger();

    void DoMaintenance(CConnman& connman);

    const CGovernanceObject* FindConstGovernanceObject(const uint256& nHash) const;
    CGovernanceObject* FindGovernanceObject(const uint256& nHash);
    CGovernanceObject* FindGovernanceObjectByDataHash(const uint256& nDataHash);
    void DeleteGovernanceObject(const uint256& nHash);

    // These commands are only used in RPC
    std::vector<CGovernanceVote> GetCurrentVotes(const uint256& nParentHash, const COutPoint& mnCollateralOutpointFilter) const;
    void GetAllNewerThan(std::vector<CGovernanceObject>& objs, int64_t nMoreThanTime) const;

    void AddGovernanceObject(CGovernanceObject& govobj, PeerManager& peerman, const CNode* pfrom = nullptr);

    void CheckAndRemove();

    UniValue ToJson() const;

    void UpdatedBlockTip(const CBlockIndex* pindex, CConnman& connman, PeerManager& peerman);
    int64_t GetLastDiffTime() const { return nTimeLastDiff; }
    void UpdateLastDiffTime(int64_t nTimeIn) { nTimeLastDiff = nTimeIn; }

    int GetCachedBlockHeight() const { return nCachedBlockHeight; }

    // Accessors for thread-safe access to maps
    bool HaveObjectForHash(const uint256& nHash) const;

    bool HaveVoteForHash(const uint256& nHash) const;

    int GetVoteCount() const;

    bool SerializeObjectForHash(const uint256& nHash, CDataStream& ss) const;

    bool SerializeVoteForHash(const uint256& nHash, CDataStream& ss) const;

    void AddPostponedObject(const CGovernanceObject& govobj)
    {
        LOCK(cs);
        mapPostponedObjects.insert(std::make_pair(govobj.GetHash(), govobj));
    }

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

    void InitOnLoad();

    int RequestGovernanceObjectVotes(CNode* pnode, CConnman& connman, const PeerManager& peerman) const;
    int RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy, CConnman& connman, const PeerManager& peerman) const;

    /*
     * Trigger Management (formerly CGovernanceTriggerManager)
     *   - Track governance objects which are triggers
     *   - After triggers are activated and executed, they can be removed
    */
    std::vector<std::shared_ptr<CSuperblock>> GetActiveTriggers() EXCLUSIVE_LOCKS_REQUIRED(cs);
    bool AddNewTrigger(uint256 nHash) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void CleanAndRemoveTriggers();
    bool UndoBlock(const CBlockIndex* pindex);

private:
    std::optional<const CSuperblock> CreateSuperblockCandidate(const CBlockIndex* pindex) const EXCLUSIVE_LOCKS_REQUIRED(!cs);
    std::optional<const CGovernanceObject> CreateGovernanceTrigger(const std::optional<const CSuperblock>& sb_opt, PeerManager& peerman) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void VoteGovernanceTriggers(const std::optional<const CGovernanceObject>& trigger_opt, CConnman& connman, PeerManager& peerman) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool VoteFundingTrigger(const uint256& nHash, const vote_outcome_enum_t outcome, CConnman& connman, PeerManager& peerman);
    bool HasAlreadyVotedFundingTrigger() const;

    void RequestGovernanceObject(CNode* pfrom, const uint256& nHash, CConnman& connman, bool fUseFilter = false) const;

    void AddInvalidVote(const CGovernanceVote& vote)
    {
        cmapInvalidVotes.Insert(vote.GetHash(), vote);
    }

    bool ProcessVote(CNode* pfrom, const CGovernanceVote& vote, CGovernanceException& exception, CConnman& connman);

    /// Called to indicate a requested object has been received
    bool AcceptObjectMessage(const uint256& nHash);

    /// Called to indicate a requested vote has been received
    bool AcceptVoteMessage(const uint256& nHash);

    static bool AcceptMessage(const uint256& nHash, hash_s_t& setHash);

    void CheckOrphanVotes(CGovernanceObject& govobj, PeerManager& peerman) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void RebuildIndexes();

    void AddCachedTriggers();

    void RequestOrphanObjects(CConnman& connman);

    void CleanOrphanObjects();

    void RemoveInvalidVotes();

};

bool AreSuperblocksEnabled();

#endif // SYSCOIN_GOVERNANCE_GOVERNANCE_H
