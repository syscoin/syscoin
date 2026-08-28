// Copyright (c) 2018-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_DETERMINISTICMNS_H
#define SYSCOIN_EVO_DETERMINISTICMNS_H

#include <evo/dmnstate.h>
#include <arith_uint256.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <evo/auxiliary_history_gc.h>
#include <evo/evodb.h>
#include <evo/pq_registry.h>
#include <evo/pq_payment_probation_db.h>
#include <evo/providertx.h>
#include <saltedhasher.h>
#include <scheduler.h>
#include <sync.h>
#include <util/ranges.h>

#include <immer/map.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <ios>
#include <limits>
#include <mutex>
#include <numeric>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <interfaces/chain.h>
class CBlock;
class UniValue;
class CBlockIndex;
class TxValidationState;
class ChainstateManager;
namespace llmq {
class CFinalCommitmentTxPayload;
}
class CDeterministicMN
{
private:
    uint64_t internalId{std::numeric_limits<uint64_t>::max()};

public:
    uint256 proTxHash;
    COutPoint collateralOutpoint;
    uint16_t nOperatorReward{0};
    std::shared_ptr<const CDeterministicMNState> pdmnState;

    CDeterministicMN() = delete; // no default constructor, must specify internalId
    explicit CDeterministicMN(uint64_t _internalId) :
        internalId(_internalId)
    {
        // only non-initial values
        assert(_internalId != std::numeric_limits<uint64_t>::max());
    }

    template <typename Stream>
    CDeterministicMN(deserialize_type, Stream& s)
    {
        s >> *this;
    }

public:
    SERIALIZE_METHODS(CDeterministicMN, obj) {
        READWRITE(obj.proTxHash, VARINT(obj.internalId), obj.collateralOutpoint, obj.nOperatorReward, obj.pdmnState);
    }

    [[nodiscard]] uint64_t GetInternalId() const;

    [[nodiscard]] std::string ToString() const;
    void ToJson(interfaces::Chain& chain, UniValue& obj) const;
};
using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;

class CDeterministicMNListDiff;
class CDeterministicMNListNEVMAddressDiff;


class CDeterministicMNList
{
private:
    struct ImmerHasher
    {
        size_t operator()(const uint256& hash) const { return ReadLE64(hash.begin()); }
    };

public:
    using MnMap = immer::map<uint256, CDeterministicMNCPtr, ImmerHasher>;
    using MnInternalIdMap = immer::map<uint64_t, uint256>;
    using MnUniquePropertyMap = immer::map<uint256, std::pair<uint256, uint32_t>, ImmerHasher>;
    bool m_changed_nevm_address{false};
private:
    uint256 blockHash;
    int nHeight{-1};
    uint32_t nTotalRegisteredCount{0};
    MnMap mnMap;
    MnInternalIdMap mnInternalIdMap;
    // Memory-only seal cache. Accepted children inherit it, so validating the
    // next inverse link does not rescan/sort the full list in steady state.
    mutable std::optional<uint256> m_pq_legacy_state_hash;
    mutable uint256 m_pq_legacy_state_hash_genesis;
    // Memory-only mutation keys for compact inverse-journal construction.
    // BuildNewListFromBlock resets this after copying the parent list.
    std::set<uint256> m_tracked_changes;

    // map of unique properties like address and keys
    // we keep track of this as checking for duplicates would otherwise be painfully slow
    MnUniquePropertyMap mnUniquePropertyMap;

public:
    CDeterministicMNList() = default;
    explicit CDeterministicMNList(const uint256& _blockHash, int _height, uint32_t _totalRegisteredCount) :
        blockHash(_blockHash),
        nHeight(_height),
        nTotalRegisteredCount(_totalRegisteredCount)
    {
        assert(nHeight >= 0);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << blockHash;
        s << nHeight;
        s << nTotalRegisteredCount;
        // Serialize the map as a vector
        WriteCompactSize(s, mnMap.size());
        for (const auto& p : mnMap) {
            s << *p.second;
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        mnMap = MnMap();
        mnUniquePropertyMap = MnUniquePropertyMap();
        mnInternalIdMap = MnInternalIdMap();
        m_pq_legacy_state_hash.reset();
        m_tracked_changes.clear();
        s >> blockHash;
        s >> nHeight;
        s >> nTotalRegisteredCount;

        size_t cnt = ReadCompactSize(s);
        for (size_t i = 0; i < cnt; i++) {
            AddMN(std::make_shared<CDeterministicMN>(deserialize, s), false);
        }
        m_pq_legacy_state_hash.reset();
        m_tracked_changes.clear();
    }
    void clear() {
        mnMap = MnMap();
        mnUniquePropertyMap = MnUniquePropertyMap();
        mnInternalIdMap = MnInternalIdMap();
        m_pq_legacy_state_hash.reset();
        m_tracked_changes.clear();
        blockHash.SetNull();
        nHeight = -1;
        nTotalRegisteredCount = 0;
        m_changed_nevm_address = false;
    }
    [[nodiscard]] size_t GetAllMNsCount() const
    {
        return mnMap.size();
    }

    [[nodiscard]] size_t GetValidMNsCount() const
    {
        return ranges::count_if(mnMap, [](const auto& p){ return IsMNValid(*p.second); });
    }



    /**
     * Execute a callback on all masternodes in the mnList. This will pass a reference
     * of each masternode to the callback function. This should be preferred over ForEachMNShared.
     * @param onlyValid Run on all masternodes, or only "valid" (not banned) masternodes
     * @param cb callback to execute
     */
    template <typename Callback>
    void ForEachMN(bool onlyValid, Callback&& cb) const
    {
        for (const auto& p : mnMap) {
            if (!onlyValid || IsMNValid(*p.second)) {
                cb(*p.second);
            }
        }
    }

    /**
     * Prefer ForEachMN. Execute a callback on all masternodes in the mnList.
     * This will pass a non-null shared_ptr of each masternode to the callback function.
     * Use this function only when a shared_ptr is needed in order to take shared ownership.
     * @param onlyValid Run on all masternodes, or only "valid" (not banned) masternodes
     * @param cb callback to execute
     */
    template <typename Callback>
    void ForEachMNShared(bool onlyValid, Callback&& cb) const
    {
        for (const auto& p : mnMap) {
            if (!onlyValid || IsMNValid(*p.second)) {
                cb(p.second);
            }
        }
    }

    [[nodiscard]] const uint256& GetBlockHash() const
    {
        return blockHash;
    }
    void SetBlockHash(const uint256& _blockHash)
    {
        blockHash = _blockHash;
        m_pq_legacy_state_hash.reset();
    }
    /** The default list is the intentional pre-DIP3 / unavailable sentinel. */
    [[nodiscard]] bool IsNull() const noexcept
    {
        return nHeight < 0;
    }
    [[nodiscard]] int GetHeight() const
    {
        assert(nHeight >= 0);
        return nHeight;
    }
    void SetHeight(int _height)
    {
        assert(_height >= 0);
        nHeight = _height;
        m_pq_legacy_state_hash.reset();
    }
    [[nodiscard]] uint32_t GetTotalRegisteredCount() const
    {
        return nTotalRegisteredCount;
    }

    /** SYSCOIN: Stable versioned digest for migration anchors. */
    [[nodiscard]] uint256 GetPQLegacyStateHash(const uint256& genesis_hash) const;
    [[nodiscard]] uint256 GetOrComputePQLegacyStateHash(
        const uint256& genesis_hash) const;

    [[nodiscard]] bool IsMNValid(const uint256& proTxHash) const;
    [[nodiscard]] bool IsMNPoSeBanned(const uint256& proTxHash) const;
    static bool IsMNValid(const CDeterministicMN& dmn);
    static bool IsMNPoSeBanned(const CDeterministicMN& dmn);

    [[nodiscard]] bool HasMN(const uint256& proTxHash) const
    {
        return GetMN(proTxHash) != nullptr;
    }
    [[nodiscard]] bool HasMNByCollateral(const COutPoint& collateralOutpoint) const
    {
        return GetMNByCollateral(collateralOutpoint) != nullptr;
    }
    [[nodiscard]] bool HasValidMNByCollateral(const COutPoint& collateralOutpoint) const
    {
        return GetValidMNByCollateral(collateralOutpoint) != nullptr;
    }
    [[nodiscard]] CDeterministicMNCPtr GetMN(const uint256& proTxHash) const;
    [[nodiscard]] CDeterministicMNCPtr GetValidMN(const uint256& proTxHash) const;
    [[nodiscard]] CDeterministicMNCPtr GetMNByCollateral(const COutPoint& collateralOutpoint) const;
    [[nodiscard]] CDeterministicMNCPtr GetValidMNByCollateral(const COutPoint& collateralOutpoint) const;
    [[nodiscard]] CDeterministicMNCPtr GetMNByService(const CService& service) const;
    [[nodiscard]] CDeterministicMNCPtr GetMNByInternalId(uint64_t internalId) const;
    [[nodiscard]] CDeterministicMNCPtr GetMNPayee(
        const llmq::pq::PQPaymentProbationStateView* payment_state = nullptr,
        const llmq::pq::PQPaymentEligibleProTxHashes* pq_payment_eligible =
            nullptr) const;

    /** SYSCOIN:
     * Calculates the projected MN payees for the next *count* blocks. The result is not guaranteed to be correct
     * as PoSe banning might occur later
     * @param nCount the number of payees to return. "nCount = max()"" means "all", use it to avoid calling GetValidMNsCount twice.
     * @param payment_state exact parent payment-probation state, when active
     * @param pq_payment_eligible exact frozen root-capable set, when required
     * @return
     */
    [[nodiscard]] std::vector<CDeterministicMNCPtr> GetProjectedMNPayees(
        int nCount = std::numeric_limits<int>::max(),
        const llmq::pq::PQPaymentProbationStateView* payment_state = nullptr,
        const llmq::pq::PQPaymentEligibleProTxHashes* pq_payment_eligible =
            nullptr) const;

    /**
     * Calculate a quorum based on the modifier. The resulting list is deterministically sorted by score
     * @param maxSize
     * @param modifier
     * @return
     */
    [[nodiscard]] std::vector<CDeterministicMNCPtr> CalculateQuorum(size_t maxSize, const uint256& modifier) const;
    [[nodiscard]] std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>> CalculateScores(const uint256& modifier) const;

    /**
     * Calculates the maximum penalty which is allowed at the height of this MN list. It is dynamic and might change
     * for every block.
     * @return
     */
    [[nodiscard]] int CalcMaxPoSePenalty() const;

    /**
     * Returns a the given percentage from the max penalty for this MN list. Always use this method to calculate the
     * value later passed to PoSePunish. The percentage should be high enough to take per-block penalty decreasing for MNs
     * into account. This means, if you want to accept 2 failures per payment cycle, you should choose a percentage that
     * is higher then 50%, e.g. 66%.
     * @param percent
     * @return
     */
    [[nodiscard]] int CalcPenalty(int percent) const;

    /**
     * Punishes a MN for misbehavior. If the resulting penalty score of the MN reaches the max penalty, it is banned.
     * Penalty scores are only increased when the MN is not already banned, which means that after banning the penalty
     * might appear lower then the current max penalty, while the MN is still banned.
     * @param proTxHash
     * @param penalty
     */
    void PoSePunish(const uint256& proTxHash, int penalty);

    void DecreaseScores();
    /**
     * Decrease penalty score of MN by 1.
     * Only allowed on non-banned MNs.
     */
    void PoSeDecrease(const CDeterministicMN& dmn);

    void BuildDiff(const CDeterministicMNList& to, CDeterministicMNListDiff &diffRet, CDeterministicMNListNEVMAddressDiff &diffRetNEVMAddress) const;
    void BuildTrackedInverseDiff(const CDeterministicMNList& parent,
                                 CDeterministicMNListDiff& inverse) const;
    [[nodiscard]] std::vector<uint256> BuildTrackedNetRemovedProTxHashes(
        const CDeterministicMNList& parent) const;
    void ResetTrackedChanges() { m_tracked_changes.clear(); }
    [[nodiscard]] size_t TrackedChangeCountForTesting() const
    {
        return m_tracked_changes.size();
    }
    [[nodiscard]] bool HasPQLegacyStateHashCacheForTesting(
        const uint256& genesis_hash) const
    {
        return m_pq_legacy_state_hash &&
               m_pq_legacy_state_hash_genesis == genesis_hash;
    }
    [[nodiscard]] CDeterministicMNList ApplyDiff(
        const CBlockIndex* pindex,
        const CDeterministicMNListDiff& diff,
        std::optional<uint32_t> total_registered_count = std::nullopt) const;

    void AddMN(const CDeterministicMNCPtr& dmn, bool fBumpTotalCount = true);
    void UpdateMN(const CDeterministicMN& oldDmn, const std::shared_ptr<const CDeterministicMNState>& pdmnState);
    void UpdateMN(const uint256& proTxHash, const std::shared_ptr<const CDeterministicMNState>& pdmnState);
    void UpdateMN(const CDeterministicMN& oldDmn, const CDeterministicMNStateDiff& stateDiff);
    void RemoveMN(const uint256& proTxHash);

    template <typename T>
    [[nodiscard]] bool HasUniqueProperty(const T& v) const
    {
        return mnUniquePropertyMap.count(GetUniquePropertyHash(v)) != 0;
    }
    template <typename T>
    [[nodiscard]] CDeterministicMNCPtr GetUniquePropertyMN(const T& v) const
    {
        auto p = mnUniquePropertyMap.find(GetUniquePropertyHash(v));
        if (!p) {
            return nullptr;
        }
        return GetMN(p->first);
    }

private:
    template <typename T>
    [[nodiscard]] uint256 GetUniquePropertyHash(const T& v) const
    {
        return ::SerializeHash(v);
    }
    template <typename T>
    [[nodiscard]] bool AddUniqueProperty(const CDeterministicMN& dmn, const T& v)
    {
        static const T nullValue;
        if (v == nullValue) {
            return false;
        }

        auto hash = GetUniquePropertyHash(v);
        auto oldEntry = mnUniquePropertyMap.find(hash);
        if (oldEntry != nullptr && oldEntry->first != dmn.proTxHash) {
            return false;
        }
        std::pair<uint256, uint32_t> newEntry(dmn.proTxHash, 1);
        if (oldEntry != nullptr) {
            newEntry.second = oldEntry->second + 1;
        }
        mnUniquePropertyMap = mnUniquePropertyMap.set(hash, newEntry);
        return true;
    }
    template <typename T>
    [[nodiscard]] bool DeleteUniqueProperty(const CDeterministicMN& dmn, const T& oldValue)
    {
        static const T nullValue;
        if (oldValue == nullValue) {
            return false;
        }

        auto oldHash = GetUniquePropertyHash(oldValue);
        auto p = mnUniquePropertyMap.find(oldHash);
        if (p == nullptr || p->first != dmn.proTxHash) {
            return false;
        }
        if (p->second == 1) {
            mnUniquePropertyMap = mnUniquePropertyMap.erase(oldHash);
        } else {
            mnUniquePropertyMap = mnUniquePropertyMap.set(oldHash, std::make_pair(dmn.proTxHash, p->second - 1));
        }
        return true;
    }
    template <typename T>
    [[nodiscard]] bool UpdateUniqueProperty(const CDeterministicMN& dmn, const T& oldValue, const T& newValue)
    {
        if (oldValue == newValue) {
            return true;
        }
        static const T nullValue;

        if (oldValue != nullValue && !DeleteUniqueProperty(dmn, oldValue)) {
            return false;
        }

        if (newValue != nullValue && !AddUniqueProperty(dmn, newValue)) {
            return false;
        }
        return true;
    }

    friend bool operator==(const CDeterministicMNList& a, const CDeterministicMNList& b)
    {
        return  a.blockHash == b.blockHash &&
                a.nHeight == b.nHeight &&
                a.nTotalRegisteredCount == b.nTotalRegisteredCount &&
                a.mnMap == b.mnMap &&
                a.mnInternalIdMap == b.mnInternalIdMap &&
                a.mnUniquePropertyMap == b.mnUniquePropertyMap;
    }
};


class CDeterministicMNListNEVMAddressDiff
{
public:

    std::vector<std::pair<std::vector<unsigned char>, uint32_t>> addedMNNEVM;
    std::vector<std::pair<std::vector<unsigned char>, std::pair<std::vector<unsigned char>, uint32_t>>> updatedMNNEVM;
    std::vector<std::vector<unsigned char>> removedMNNEVM;

    SERIALIZE_METHODS(CDeterministicMNListNEVMAddressDiff, obj) {
        READWRITE(obj.addedMNNEVM, obj.updatedMNNEVM, obj.removedMNNEVM);
    }
    std::string ToString() const;
};
// Temporary map to collect and deduplicate NEVM address changes.
// Keyed by masternode proTxHash.
enum class NEVMDiffType {
    None,
    Added,
    Updated,
    Removed
};

struct NEVMDiffEntry {
    NEVMDiffType type = NEVMDiffType::None;
    // For an update, both addresses are set;
    // For an add, only newAddress and collateral height are relevant;
    // For a removal, only oldAddress is needed.
    std::vector<unsigned char> oldAddress;
    std::vector<unsigned char> newAddress;
    uint32_t collateralHeight = 0;
};
class CDeterministicMNListDiff
{
public:
    static constexpr size_t MAX_CHANGES{1'000'000};

    int nHeight{-1}; //memory only

    std::vector<CDeterministicMNCPtr> addedMNs;
    // keys are all relating to the internalId of MNs
    std::unordered_map<uint64_t, CDeterministicMNStateDiff> updatedMNs;
    std::set<uint64_t> removedMns;

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << addedMNs;
        WriteCompactSize(s, updatedMNs.size());
        std::vector<uint64_t> updated_ids;
        updated_ids.reserve(updatedMNs.size());
        for (const auto& [internal_id, _] : updatedMNs) {
            updated_ids.emplace_back(internal_id);
        }
        std::sort(updated_ids.begin(), updated_ids.end());
        for (const uint64_t internal_id : updated_ids) {
            WriteVarInt<Stream, VarIntMode::DEFAULT, uint64_t>(s, internal_id);
            s << updatedMNs.at(internal_id);
        }
        WriteCompactSize(s, removedMns.size());
        for (const auto& p : removedMns) {
            WriteVarInt<Stream, VarIntMode::DEFAULT, uint64_t>(s, p);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        addedMNs.clear();
        updatedMNs.clear();
        removedMns.clear();

        size_t tmp;
        uint64_t tmp2;
        tmp = ReadCompactSize(s);
        if (tmp > MAX_CHANGES) {
            throw std::ios_base::failure(
                "too many added deterministic-MN diff entries");
        }
        addedMNs.reserve(tmp);
        for (size_t i = 0; i < tmp; ++i) {
            CDeterministicMNCPtr dmn;
            s >> dmn;
            addedMNs.emplace_back(std::move(dmn));
        }
        tmp = ReadCompactSize(s);
        if (tmp > MAX_CHANGES - addedMNs.size()) {
            throw std::ios_base::failure(
                "too many updated deterministic-MN diff entries");
        }
        for (size_t i = 0; i < tmp; i++) {
            CDeterministicMNStateDiff diff;
            // CDeterministicMNState holds a new field {nVersion} but no migration is needed here since:
            // CDeterministicMNStateDiff is always serialised using a bitmask.
            // Because the new field have a new bit guide value then we are good to continue
            tmp2 = ReadVarInt<Stream, VarIntMode::DEFAULT, uint64_t>(s);
            s >> diff;
            if (!updatedMNs.emplace(tmp2, std::move(diff)).second) {
                throw std::ios_base::failure(
                    "duplicate deterministic-MN state diff ID");
            }
        }
        tmp = ReadCompactSize(s);
        if (tmp > MAX_CHANGES - addedMNs.size() - updatedMNs.size()) {
            throw std::ios_base::failure(
                "too many removed deterministic-MN diff entries");
        }
        for (size_t i = 0; i < tmp; i++) {
            tmp2 = ReadVarInt<Stream, VarIntMode::DEFAULT, uint64_t>(s);
            if (!removedMns.emplace(tmp2).second) {
                throw std::ios_base::failure(
                    "duplicate removed deterministic-MN diff ID");
            }
        }
    }

    bool HasChanges() const
    {
        return !addedMNs.empty() || !updatedMNs.empty() || !removedMns.empty();
    }
};

/**
 * Compact branch-local inverse of one accepted deterministic-MN transition.
 * The two state hashes bind both ends so local database damage cannot turn an
 * otherwise valid reorg into a silently different provider state.
 */
class CDeterministicMNListInverse
{
public:
    static constexpr uint16_t VERSION{1};
    static constexpr size_t MAX_CHANGES{
        CDeterministicMNListDiff::MAX_CHANGES};

    uint16_t version{VERSION};
    uint256 genesis_hash;
    int32_t coverage_base_height{-1};
    uint256 parent_history_commitment;
    uint256 history_commitment;
    int32_t child_height{-1};
    uint256 child_hash;
    uint256 child_state_hash;
    int32_t parent_height{-1};
    uint256 parent_hash;
    uint256 parent_state_hash;
    uint32_t parent_total_registered_count{0};
    CDeterministicMNListDiff inverse_diff;

    SERIALIZE_METHODS(CDeterministicMNListInverse, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "invalid deterministic-MN inverse journal entry");
        });
        READWRITE(obj.version, obj.genesis_hash, obj.coverage_base_height,
                  obj.parent_history_commitment, obj.history_commitment,
                  obj.child_height, obj.child_hash, obj.child_state_hash,
                  obj.parent_height, obj.parent_hash, obj.parent_state_hash,
                  obj.parent_total_registered_count, obj.inverse_diff);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "invalid deterministic-MN inverse journal entry");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const;
};

class CDeterministicMNManager
{
public:
    using AuxiliaryHistoryGCAuthorizationSource =
        evo::AuxiliaryHistoryGCAuthorizationSource;
    using AuxiliaryHistoryBlockIdentity =
        evo::AuxiliaryHistoryGCBlockIdentity;
    using AuxiliaryHistoryGCAuthorization =
        evo::AuxiliaryHistoryGCAuthorization;

    struct AuxiliaryHistoryBranchRequirement {
        bool active{false};
        AuxiliaryHistoryBlockIdentity head;
        AuxiliaryHistoryBlockIdentity random_access_floor;
        std::vector<uint256> snapshot_window;
    };

    /**
     * SYSCOIN: One immutable maintenance observation for both append-only
     * auxiliary histories. Finality authorizes destruction; branch windows,
     * roster floors, and fixed anchors independently describe what survives.
     */
    struct AuxiliaryHistoryRetentionPlan {
        std::optional<AuxiliaryHistoryGCAuthorization>
            destructive_authorization;
        std::optional<int32_t> replay_floor;
        std::optional<int32_t> finality_roster_floor;
        std::vector<AuxiliaryHistoryBranchRequirement> branches;
        std::vector<AuxiliaryHistoryBlockIdentity> fixed_dependencies;
        bool finality_verification_active{false};
        bool finality_publication_pending{false};
        bool requirements_valid{false};
        bool finality_health_ambiguous{true};
        uint64_t generation{0};

        [[nodiscard]] bool AllowsDestructiveGC() const noexcept
        {
            return destructive_authorization.has_value() &&
                   finality_roster_floor.has_value() && !branches.empty() &&
                   !replay_floor.has_value() &&
                   !finality_verification_active &&
                   !finality_publication_pending &&
                   requirements_valid &&
                   !finality_health_ambiguous;
        }
    };

    enum class DMNInverseGCBoundaryStatus : uint8_t {
        BLOCKED = 0,
        NO_OP,
        READY,
    };

    struct DMNInverseGCBoundary {
        DMNInverseGCBoundaryStatus status{
            DMNInverseGCBoundaryStatus::BLOCKED};
        std::optional<AuxiliaryHistoryBlockIdentity> boundary;
        std::optional<evo::AuxiliaryHistoryGCComponent> component;
        std::optional<CDeterministicMNList> snapshot;
    };

    struct InverseJournalEntryStatsForTesting {
        size_t serialized_size{0};
        size_t added_mns{0};
        size_t updated_mns{0};
        size_t removed_mns{0};
    };

    static constexpr int DISK_SNAPSHOT_PERIOD = 576; // once per day
    static constexpr int DISK_SNAPSHOTS = 3; // keep cache for 3 disk snapshots to have 2 full days covered
public:
    // Full snapshots are a bounded random-access availability/performance
    // window. Sequential rollback depth is provided by the inverse journal
    // and must never be inferred from this cache size.
    static constexpr int LIST_CACHE_SIZE = DISK_SNAPSHOT_PERIOD * DISK_SNAPSHOTS;
    static constexpr int HOT_LIST_CACHE_SIZE = 128;
    // SYSCOIN: Exact-parent payment selection is shared by consensus,
    // templates, governance, and RPC without retaining an unbounded branch
    // history.
    static constexpr std::size_t MN_PAYEE_CACHE_SIZE{64};

    struct MNPayeeCacheStatsForTesting {
        std::size_t entries{0};
        uint64_t hits{0};
        uint64_t builds{0};
    };
private:
    struct MNPayeeCacheKey {
        uint256 block_hash;
        int32_t height{-1};
        uint256 payment_probation_state_hash;

        friend bool operator==(const MNPayeeCacheKey&,
                               const MNPayeeCacheKey&) = default;
    };
    struct MNPayeeCacheEntry {
        MNPayeeCacheKey key;
        CDeterministicMNCPtr payee;
        bool occupied{false};
        bool recently_used{false};
    };
    class MNPayeeCache final {
    public:
        [[nodiscard]] std::optional<CDeterministicMNCPtr> Get(
            const MNPayeeCacheKey& key) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
        [[nodiscard]] CDeterministicMNCPtr Publish(
            const MNPayeeCacheKey& key,
            CDeterministicMNCPtr payee) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
        [[nodiscard]] MNPayeeCacheStatsForTesting Stats()
            EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    private:
        Mutex m_mutex;
        std::array<MNPayeeCacheEntry, MN_PAYEE_CACHE_SIZE> m_entries
            GUARDED_BY(m_mutex);
        std::size_t m_clock GUARDED_BY(m_mutex){0};
        uint64_t m_hits GUARDED_BY(m_mutex){0};
        uint64_t m_builds GUARDED_BY(m_mutex){0};
    };

    Mutex cs;
    // Main thread has indicated we should perform cleanup up to this height
    std::atomic<int> to_cleanup {0};
    std::atomic<bool> m_persistent_window_initialized{false};

    const CBlockIndex* tipIndex GUARDED_BY(cs) {nullptr};
    uint256 m_last_maintained_tip GUARDED_BY(cs);
    std::vector<uint256> m_last_maintained_recovery_blocks GUARDED_BY(cs);
    // SYSCOIN: A crash-durable BTCC/NEVM replay obligation retains every
    // branch snapshot at or above this floor. It is memory-only because the
    // preseal marker is the authoritative crash-restored record.
    int m_replay_snapshot_retention_floor GUARDED_BY(cs){
        std::numeric_limits<int>::max()};
    // SYSCOIN: This replaceable floor keeps every persisted branch snapshot
    // that can still supply a roster for an admissible finality certificate.
    int m_finality_snapshot_retention_floor GUARDED_BY(cs){
        std::numeric_limits<int>::max()};
    // SYSCOIN: Candidate verification and durable-but-not-yet-enforced
    // finality must temporarily retain every branch. The transient count is
    // globally bounded by the ChainLock verifier mutex; the publication flag
    // survives verification until the durable winner is active.
    size_t m_finality_snapshot_verifications_in_flight GUARDED_BY(cs){0};
    bool m_finality_snapshot_publication_pending GUARDED_BY(cs){false};
    uint64_t m_replay_snapshot_retention_generation GUARDED_BY(cs){0};
    // SYSCOIN: These process-local values are admission proofs, not persisted
    // deletion metadata. Physical GC must rederive durable authority and
    // validate each retained database boundary before publishing tombstones.
    std::optional<AuxiliaryHistoryGCAuthorization>
        m_auxiliary_history_gc_authorization GUARDED_BY(cs);
    std::optional<AuxiliaryHistoryGCAuthorization>
        m_auxiliary_history_gc_high_watermark GUARDED_BY(cs);
    DBParams m_pq_registry_db_params;
    // SYSCOIN: The registry is immutable after successful publication. A
    // once-flag models that lifetime directly and avoids imposing a private
    // initialization-lock precondition on every consensus caller.
    mutable std::once_flag m_pq_registry_init_once;
    mutable std::atomic_bool m_pq_registry_init_requested{false};
    mutable std::unique_ptr<llmq::pq::PQRegistryManager> m_pq_registry;
    std::unique_ptr<llmq::pq::PQPaymentProbationManager>
        m_payment_probation;
    std::unique_ptr<CEvoDB<uint256, CDeterministicMNListInverse,
                          StaticSaltedHasher>> m_inverse_journal;
    // SYSCOIN: One crash-monotonic coordinator owns physical-GC progress for
    // both auxiliary stores; store-specific deletion is intentionally separate.
    std::unique_ptr<evo::AuxiliaryHistoryGCJournal>
        m_auxiliary_history_gc_journal;
    // SYSCOIN: The key includes every branch-local input not already
    // committed by the parent block hash. Miss derivation stays outside this
    // mutex; publication is double-checked.
    MNPayeeCache m_mn_payee_cache;

    llmq::pq::PQRegistryManager* GetOrCreatePQRegistry(
        std::string& error) const;
    bool CommitInverseJournal(
        const CBlockIndex* child,
        const CDeterministicMNList& child_list,
        CDeterministicMNList& parent_list,
        const uint256& child_state_hash);
    bool LoadAndVerifyInverseJournal(
        const CBlockIndex* child,
        const CDeterministicMNList& child_list,
        CDeterministicMNList& parent_list);
    bool LoadAndVerifyInverseJournalExactForGC(
        const CBlockIndex* child,
        const CDeterministicMNList& child_list,
        CDeterministicMNList& parent_list);
    bool LoadAndVerifyInverseJournalInternal(
        const CBlockIndex* child,
        const CDeterministicMNList& child_list,
        CDeterministicMNList& parent_list,
        bool exact_disk_for_gc);
    bool EnsureRetainedSnapshotWindow(
        const CBlockIndex* tip,
        const CDeterministicMNList& tip_list);
    [[nodiscard]] AuxiliaryHistoryRetentionPlan
    BuildAuxiliaryHistoryRetentionPlan(
        const CBlockIndex* tip,
        std::span<const CBlockIndex* const> recovery_snapshot_indexes) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    [[nodiscard]] DMNInverseGCBoundary DeriveDMNInverseGCBoundary(
        const CBlockIndex* tip,
        std::span<const CBlockIndex* const> recovery_snapshot_indexes,
        const AuxiliaryHistoryRetentionPlan& plan,
        const std::optional<evo::AuxiliaryHistoryGCComponent>&
            previous_component = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(m_evoDb->cs, cs);
    bool PrepareDMNInverseGCIntent(
        const CBlockIndex* tip,
        std::span<const CBlockIndex* const> recovery_snapshot_indexes,
        const AuxiliaryHistoryRetentionPlan& plan,
        bool& retry_required)
        EXCLUSIVE_LOCKS_REQUIRED(m_evoDb->cs, cs);
    bool AuthenticateInitialDMNInverseGCLineage(
        const CBlockIndex* boundary,
        const CDeterministicMNList& boundary_snapshot)
        EXCLUSIVE_LOCKS_REQUIRED(m_evoDb->cs, cs);
    bool GetPQPaymentEligibleProTxHashes(
        const CBlockIndex* pindex,
        llmq::pq::PQPaymentEligibleProTxHashesPtr& eligible) const;
public:
    struct EvoDBStats {
        int64_t approxPersistedEntries{0};
        uint64_t estimatedDiskSizeBytes{0};
        size_t cacheEntries{0};
        size_t eraseCacheEntries{0};
        std::string dbPath;
    };
    std::unique_ptr<CEvoDB<uint256, CDeterministicMNList, StaticSaltedHasher>> m_evoDb;
    explicit CDeterministicMNManager(const DBParams& db_params);
       
    ~CDeterministicMNManager() = default;

    bool ProcessBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state,
                      const CCoinsViewCache& view, const llmq::CFinalCommitmentTxPayload& legacy_commitment,
                      CDeterministicMNListNEVMAddressDiff &diff, bool fJustCheck, bool ibd) EXCLUSIVE_LOCKS_REQUIRED(!cs, cs_main);
    bool UndoBlock(const CBlockIndex* pindex, CDeterministicMNListNEVMAddressDiff &inversedDiffNEVMAddress) EXCLUSIVE_LOCKS_REQUIRED(!cs, cs_main);

    // the returned list will not contain the correct block hash (we can't know it yet as the coinbase TX is not updated yet)
    bool BuildNewListFromBlock(const CBlock& block, const CBlockIndex* pindexPrev, BlockValidationState& state, const CCoinsViewCache& view,
                                CDeterministicMNList& mnListRet, CDeterministicMNList& mnOldListRet,
                                const llmq::CFinalCommitmentTxPayload& legacy_commitment) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    static void DecreasePoSePenalties(CDeterministicMNList& mnList, const std::vector<CDeterministicMNCPtr> &toDecrease);

    const CDeterministicMNList GetListForBlock(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void GetListForBlock(const CBlockIndex* pindex, CDeterministicMNList& list);
    const CDeterministicMNList GetListAtChainTip() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** SYSCOIN: Validate PQ operator-key transactions against exact parent snapshots. */
    bool CheckPQTransaction(const CTransaction& tx,
                            const CBlockIndex* pindexPrev,
                            TxValidationState& state,
                            bool fJustCheck,
                            bool check_sigs)
        EXCLUSIVE_LOCKS_REQUIRED(!cs, cs_main);

    /** SYSCOIN: Exact branch lookup used by quorum construction and MNAUTH. */
    bool GetPQRegistrySnapshot(const CBlockIndex* pindex,
                               llmq::pq::PQRegistrySnapshot& snapshot,
                               std::string& error) const;

    /** Immutable exact-branch handle for hot registry readers. */
    bool GetPQRegistryReadView(const CBlockIndex* pindex,
                               llmq::pq::PQRegistryReadView& view,
                               std::string& error) const;

    /** Resolve an immutable exact branch-local payment-only state view. */
    bool GetPaymentProbationStateView(
        const CBlockIndex* pindex,
        llmq::pq::PQPaymentProbationStateView& view) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Derive membership and state from one exact carrier parent. */
    [[nodiscard]] llmq::pq::PQPaymentProbationTransitionOutcome
    ApplyPaymentProbationTransition(
        const CBlockIndex& carrier_parent,
        const llmq::pq::PQPaymentProbationTransitionContext& context)
        EXCLUSIVE_LOCKS_REQUIRED(!cs, cs_main);

    /** Compatibility copying API retained for tests. */
    bool GetPaymentProbationState(
        const CBlockIndex* pindex,
        llmq::pq::PQPaymentProbationState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Publish one receipt-derived state before the block index root is durable. */
    bool CommitPaymentProbationState(
        const llmq::pq::PQPaymentProbationState& state,
        const uint256& expected_hash,
        bool fJustCheck) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Persist and publish an exact manager-authenticated transition result. */
    bool CommitPaymentProbationTransition(
        const llmq::pq::PQPaymentProbationTransitionView& transition,
        bool fJustCheck,
        llmq::pq::PQPaymentProbationStateView* published = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    [[nodiscard]] uint256 EmptyPaymentProbationStateHash() const;

    [[nodiscard]] uint64_t PaymentProbationStateViewGeneration() const;

    /** Whether state GC completed for the same authenticated deletion boundary. */
    bool IsPaymentProbationGCCompleteForCheckpoint(
        const llmq::pq::PaymentAuditStoreCheckpoint& checkpoint) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /**
     * After an authenticated audit checkpoint is durably committed, prune
     * covered payment-state roots synchronously. Callers must retain every
     * root referenced by active/prospective replay markers and the
     * authenticated current suffix.
     */
    bool PrunePaymentProbationStatesThroughCheckpoint(
        const llmq::pq::PaymentAuditStoreCheckpoint& checkpoint,
        std::span<const uint256> retained_state_hashes)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Select the deterministic payee after applying payment-only probation. */
    bool GetMNPayeeForBlock(const CBlockIndex* pindex,
                            CDeterministicMNCPtr& payee)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** SYSCOIN: Deterministic counters for cache regression tests. */
    [[nodiscard]] MNPayeeCacheStatsForTesting
    GetMNPayeeCacheStatsForTesting();

    /** SYSCOIN:
     * Project payees only through the currently knowable payment-root epoch.
     * Future PQ epochs may have a different frozen root-capable set, so a
     * shorter successful result means the remaining requested heights are
     * not yet knowable from this parent state.
     */
    bool GetProjectedMNPayeesForBlock(
        const CBlockIndex* pindex,
        int count,
        std::vector<CDeterministicMNCPtr>& payees)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** SYSCOIN: Bounded exact-parent registry view for mempool reservations. */
    bool GetPQRegistryMempoolView(
        const CBlockIndex* pindex,
        std::span<const uint256> requested_operators,
        llmq::pq::PQRegistryMempoolView& view,
        std::string& error) const;

    // Test if given TX is a ProRegTx which also contains the collateral at index n
    static bool IsProTxWithCollateral(const CTransactionRef& tx, uint32_t n);
    bool IsDIP3Enforced(int nHeight = -1) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool FlushCacheToDisk(
        bool bForceFlush,
        bool fSync = true,
        std::span<const CBlockIndex* const> recovery_snapshot_indexes = {})
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /**
     * SYSCOIN: Persist dirty DMN snapshots and order prior asynchronous PQ
     * registry writes without pruning against a potentially stale tip.
     */
    bool FlushPendingSnapshotsToDisk(bool fSync = true) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool DoMaintenance(
        bool bForceFlush,
        bool fSync = true,
        std::span<const CBlockIndex* const> recovery_snapshot_indexes = {})
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    void UpdatedBlockTip(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool GetEvoDBStats(EvoDBStats& stats) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool HasPersistentWindow() const;
    bool VerifyPQLegacyAnchorState(const CBlockIndex* anchor) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    bool VerifyPersistedPQRegistrySnapshot(const CBlockIndex* pindex);
    /** SYSCOIN: Read an existing snapshot without creating recovery state on a miss. */
    bool VerifyPersistedSnapshot(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /**
     * Verify the tip and its immediate predecessor seals. Ordered publication
     * proves normal upgrade/crash lineage; like other LevelDB-backed state,
     * later arbitrary key loss is detected fail-closed when that link is read.
     */
    bool VerifyInverseJournalTipSeal(const CBlockIndex* tip)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** Restore the active tip's bounded random-access snapshot window. */
    bool EnsureRetainedSnapshotWindow(const CBlockIndex* tip)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** Inject a self-consistent but semantically wrong parent hash in tests. */
    bool CorruptInverseJournalForTesting(const uint256& child_hash);
    bool AppendInverseJournalTrailingByteForTesting(
        const uint256& child_hash);
    bool RewriteExactInverseJournalValueForTesting(
        const uint256& child_hash);
    bool GetInverseJournalEntryStatsForTesting(
        const uint256& child_hash,
        InverseJournalEntryStatsForTesting& stats);
    bool EraseInverseJournalEntryForTesting(const uint256& child_hash);
    void FailNextInverseJournalFlushForTesting();
    void FailNextInverseJournalSynchronousFlushForTesting();
    /** SYSCOIN: Verify rejected and check-only blocks never reach PQ publication. */
    void FailNextPQRegistryWriteThroughForTesting();
    /** SYSCOIN: Lower a replay floor, or erase it only after the durable marker clears. */
    int UpdateReplaySnapshotRetentionFloor(
        std::optional<int32_t> floor) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Replace the roster floor derived from durable certificates. */
    int UpdateFinalitySnapshotRetentionFloor(
        std::optional<int32_t> floor) EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Serialize candidate-roster use against snapshot pruning. */
    void BeginFinalitySnapshotVerificationRetention()
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Release one globally bounded candidate-verification hold. */
    void EndFinalitySnapshotVerificationRetention()
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Retain all branches until durable finality is active. */
    void UpdateFinalitySnapshotPublicationRetention(bool retain)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /**
     * SYSCOIN: Publish only an exact active finality decision already proven
     * by the ChainLock handler. Null marks finality health as ambiguous.
     */
    [[nodiscard]] bool UpdateAuxiliaryHistoryGCAuthorization(
        std::optional<AuxiliaryHistoryGCAuthorization> authorization,
        bool release_publication = false)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Observe the immutable plan without granting erase authority. */
    [[nodiscard]] AuxiliaryHistoryRetentionPlan
    GetAuxiliaryHistoryRetentionPlanForTesting(
        std::span<const CBlockIndex* const> recovery_snapshot_indexes = {})
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    /** SYSCOIN: Derive the read-only authenticated DMN GC closure. */
    [[nodiscard]] DMNInverseGCBoundary
    GetDMNInverseGCBoundaryForTesting(
        std::span<const CBlockIndex* const> recovery_snapshot_indexes = {},
        const std::optional<evo::AuxiliaryHistoryGCComponent>&
            previous_component = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);
    [[nodiscard]] evo::AuxiliaryHistoryGCState
    GetAuxiliaryHistoryGCStateForTesting() const;
private:
    const CDeterministicMNList GetListForBlockInternal(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(!cs);
};
extern std::unique_ptr<CDeterministicMNManager> deterministicMNManager;
extern bool fMasternodeMode;
#endif // SYSCOIN_EVO_DETERMINISTICMNS_H
