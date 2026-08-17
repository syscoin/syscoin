// Copyright (c) 2014-2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_GOVERNANCE_GOVERNANCEVOTEDB_H
#define SYSCOIN_GOVERNANCE_GOVERNANCEVOTEDB_H

#include <governance/governancepages.h>
#include <governance/governancevote.h>
#include <protocol.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <list>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

class CDeterministicMNList;

/**
 * Represents the collection of votes associated with a given CGovernanceObject
 * Recently received votes are held in memory until a maximum size is reached after
 * which older votes a flushed to a disk file.
 *
 * Note: This is a stub implementation that doesn't limit the number of votes held
 * in memory and doesn't flush to disk.
 */
class CGovernanceObjectVoteFile
{
public: // Types
    using vote_l_t = std::list<CGovernanceVote>;

    using vote_m_t = std::map<uint256, vote_l_t::iterator>;

private:
    int nMemoryVotes;
    uint64_t nSerializedVoteBytes;

    vote_l_t listVotes;

    vote_m_t mapVoteIndex;

    // Existing sessions keep old immutable generations alive while mutation
    // publishes a fresh snapshot for new cursor-zero requests.
    mutable std::weak_ptr<const GovernancePageImmutableSnapshot>
        m_page_snapshot;

    /** Memory-only index used by authority-delta revalidation. */
    std::multimap<COutPoint, vote_l_t::iterator> mapMasternodeIndex;

public:
    CGovernanceObjectVoteFile();

    CGovernanceObjectVoteFile(const CGovernanceObjectVoteFile& other);

    /**
     * Add a vote to the file
     */
    void AddVote(const CGovernanceVote& vote);

    /**
     * Return true if the vote with this hash is currently cached in memory
     */
    bool HasVote(const uint256& nHash) const;

    /** Retrieve one exact stored vote without relying on the lossy global LRU. */
    [[nodiscard]] std::optional<CGovernanceVote> GetVote(
        const uint256& nHash) const;

    /** Exact fixed-wire bytes retained by a fresh page snapshot. */
    [[nodiscard]] std::optional<std::size_t>
    GetPageSnapshotRetainedBytes() const;

    [[nodiscard]] std::shared_ptr<
        const GovernancePageImmutableSnapshot>
    GetCachedPageSnapshot(uint64_t validation_context_epoch) const;

    /** Capture or reuse one exact immutable vote generation. */
    [[nodiscard]] std::shared_ptr<const GovernancePageImmutableSnapshot>
    GetPageSnapshot(
        const uint256& scope_hash,
        const std::shared_ptr<GovernancePageSnapshotBudget>& budget,
        uint64_t instance_id,
        uint64_t validation_context_epoch,
        std::optional<std::size_t> retained_bytes = std::nullopt) const;

    /**
     * Retrieve a vote cached in memory
     */
    bool SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const;

    /** Conservative network-wire size used before charging an upload. */
    [[nodiscard]] std::optional<std::size_t>
    GetVoteSerializedSizeUpperBound(const uint256& nHash,
                                    int version) const;

    int GetVoteCount() const
    {
        return nMemoryVotes;
    }

    [[nodiscard]] uint64_t GetSerializedVoteBytes() const
    {
        return nSerializedVoteBytes;
    }

    [[nodiscard]] uint64_t ProjectedSerializedVoteBytes(
        const CGovernanceVote& vote) const;

    std::vector<CGovernanceVote> GetVotes() const;

    // SYSCOIN: allow bounded/filtering snapshots without first copying an
    // attacker-selected object's entire vote file.
    template <typename Callback>
    void ForEachVote(Callback&& callback) const
    {
        for (const auto& vote : listVotes) {
            if (!callback(vote)) break;
        }
    }

    template <typename Callback>
    void ForEachVoteFromMasternode(const COutPoint& outpoint,
                                   Callback&& callback) const
    {
        const auto [begin, end]{mapMasternodeIndex.equal_range(outpoint)};
        for (auto it{begin}; it != end; ++it) {
            if (!callback(*it->second)) break;
        }
    }

    [[nodiscard]] bool HasVoteFromMasternode(
        const COutPoint& outpoint) const
    {
        return mapMasternodeIndex.contains(outpoint);
    }

    void RemoveVotesFromMasternode(const COutPoint& outpointMasternode);
    void RemoveVotes(const std::set<uint256>& vote_hashes);
    std::set<uint256> RemoveInvalidVotes(const CDeterministicMNList& tip_mn_list, const COutPoint& outpointMasternode, bool fProposal);

    SERIALIZE_METHODS(CGovernanceObjectVoteFile, obj)
    {
        READWRITE(obj.nMemoryVotes, obj.listVotes);
        SER_READ(obj, obj.RebuildIndex());
    }

private:
    // Drop older votes for the same gobject from the same masternode
    void RemoveOldVotes(const CGovernanceVote& vote);

    vote_l_t::iterator EraseVote(vote_l_t::iterator vote);

    [[nodiscard]] static uint64_t SerializedVoteBytes(
        const CGovernanceVote& vote);

    void RebuildIndex();

    void InvalidatePageView() noexcept
    {
        m_page_snapshot.reset();
    }
};

#endif // SYSCOIN_GOVERNANCE_GOVERNANCEVOTEDB_H
