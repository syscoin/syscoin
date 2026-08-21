// Copyright (c) 2014-2021 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governancevotedb.h>

#include <clientversion.h>

#include <limits>

CGovernanceObjectVoteFile::CGovernanceObjectVoteFile() :
    nMemoryVotes(0),
    nSerializedVoteBytes(0),
    listVotes(),
    mapVoteIndex(),
    m_page_snapshot(),
    mapMasternodeIndex()
{
}

CGovernanceObjectVoteFile::CGovernanceObjectVoteFile(const CGovernanceObjectVoteFile& other) :
    nMemoryVotes(other.nMemoryVotes),
    nSerializedVoteBytes(other.nSerializedVoteBytes),
    listVotes(other.listVotes),
    mapVoteIndex(),
    m_page_snapshot(),
    mapMasternodeIndex()
{
    RebuildIndex();
}

void CGovernanceObjectVoteFile::AddVote(const CGovernanceVote& vote)
{
    const uint256 nHash = vote.GetHash();
    // make sure to never add/update already known votes
    if (HasVote(nHash))
        return;
    listVotes.push_front(vote);
    mapVoteIndex.emplace(nHash, listVotes.begin());
    InvalidatePageView();
    mapMasternodeIndex.emplace(vote.GetMasternodeOutpoint(),
                               listVotes.begin());
    nSerializedVoteBytes += SerializedVoteBytes(vote);
    ++nMemoryVotes;
    RemoveOldVotes(vote);
}

uint64_t CGovernanceObjectVoteFile::SerializedVoteBytes(
    const CGovernanceVote& vote)
{
    return ::GetSerializeSize(vote, CLIENT_VERSION, SER_DISK);
}

uint64_t CGovernanceObjectVoteFile::ProjectedSerializedVoteBytes(
    const CGovernanceVote& vote) const
{
    if (HasVote(vote.GetHash())) return nSerializedVoteBytes;

    const uint64_t vote_bytes{SerializedVoteBytes(vote)};
    uint64_t removed_bytes{0};
    for (const auto& current : listVotes) {
        if (current.GetMasternodeOutpoint() ==
                vote.GetMasternodeOutpoint() &&
            current.GetParentHash() == vote.GetParentHash() &&
            current.GetSignal() == vote.GetSignal() &&
            current.GetTimestamp() < vote.GetTimestamp()) {
            removed_bytes += SerializedVoteBytes(current);
        }
    }
    if (vote_bytes > std::numeric_limits<uint64_t>::max() -
                         nSerializedVoteBytes) {
        return std::numeric_limits<uint64_t>::max();
    }
    const uint64_t with_vote{nSerializedVoteBytes + vote_bytes};
    return removed_bytes > with_vote ? 0 : with_vote - removed_bytes;
}

bool CGovernanceObjectVoteFile::HasVote(const uint256& nHash) const
{
    return mapVoteIndex.find(nHash) != mapVoteIndex.end();
}

std::optional<CGovernanceVote> CGovernanceObjectVoteFile::GetVote(
    const uint256& nHash) const
{
    const auto it{mapVoteIndex.find(nHash)};
    if (it == mapVoteIndex.end()) return std::nullopt;
    return *it->second;
}

std::optional<std::size_t>
CGovernanceObjectVoteFile::GetPageSnapshotRetainedBytes() const
{
    if (mapVoteIndex.size() > MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
        return std::nullopt;
    }
    if (mapVoteIndex.size() >
        (std::numeric_limits<std::size_t>::max() -
         sizeof(GovernancePageImmutableSnapshot)) /
            sizeof(GovernancePageSnapshotEntry)) {
        return std::nullopt;
    }
    std::size_t retained{
        sizeof(GovernancePageImmutableSnapshot) +
        mapVoteIndex.size() * sizeof(GovernancePageSnapshotEntry)};
    if (retained > MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES) {
        return std::nullopt;
    }
    for (const auto& [hash, vote] : mapVoteIndex) {
        (void)hash;
        const std::size_t payload_size{::GetSerializeSize(
            *vote, GOVERNANCE_PAGE_PROTO_VERSION, SER_NETWORK)};
        if (payload_size == 0 ||
            payload_size > MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES ||
            payload_size >
                MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES - retained) {
            return std::nullopt;
        }
        retained += payload_size;
    }
    return retained;
}

std::shared_ptr<const GovernancePageImmutableSnapshot>
CGovernanceObjectVoteFile::GetCachedPageSnapshot(
    uint64_t validation_context_epoch) const
{
    const auto cached{m_page_snapshot.lock()};
    return cached && cached->ValidationContextEpoch() ==
                         validation_context_epoch
        ? cached
        : std::shared_ptr<const GovernancePageImmutableSnapshot>{};
}

std::shared_ptr<const GovernancePageImmutableSnapshot>
CGovernanceObjectVoteFile::GetPageSnapshot(
    const uint256& scope_hash,
    const std::shared_ptr<GovernancePageSnapshotBudget>& budget,
    uint64_t instance_id,
    uint64_t validation_context_epoch,
    std::optional<std::size_t> retained_bytes) const
{
    if (scope_hash.IsNull() ||
        mapVoteIndex.size() > MAX_GOVERNANCE_PAGE_SCOPE_ITEMS) {
        return {};
    }
    if (const auto cached{
            GetCachedPageSnapshot(validation_context_epoch)}) {
        return cached;
    }

    if (!retained_bytes) {
        retained_bytes = GetPageSnapshotRetainedBytes();
    }
    if (!retained_bytes) return {};

    const uint32_t total_count{static_cast<uint32_t>(mapVoteIndex.size())};
    CGovernancePageViewHasher hasher{scope_hash, total_count};
    GovernancePageSnapshotReservation reservation{budget};
    if (!reservation.Reserve(*retained_bytes)) return {};
    std::vector<GovernancePageSnapshotEntry> entries;
    entries.reserve(total_count);
    if (entries.capacity() > total_count &&
        !reservation.Reserve(
            (entries.capacity() - total_count) *
            sizeof(GovernancePageSnapshotEntry))) {
        return {};
    }
    for (const auto& [hash, vote] : mapVoteIndex) {
        const CInv inv{MSG_GOVERNANCE_OBJECT_VOTE, hash};
        if (!hasher.Append(inv)) return {};
        const std::size_t payload_size{
            ::GetSerializeSize(
                *vote, GOVERNANCE_PAGE_PROTO_VERSION, SER_NETWORK)};
        if (payload_size == 0 ||
            payload_size > MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES) {
            return {};
        }
        std::vector<unsigned char> payload;
        payload.reserve(payload_size);
        CVectorWriter{
            SER_NETWORK, GOVERNANCE_PAGE_PROTO_VERSION,
            payload, 0, *vote};
        if (payload.size() != payload_size) return {};
        if (payload.capacity() > payload_size &&
            !reservation.Reserve(
                payload.capacity() - payload_size)) {
            return {};
        }
        entries.push_back(
            GovernancePageSnapshotEntry{inv, std::move(payload)});
    }
    const auto view{hasher.Finalize()};
    if (!view) return {};
    const auto snapshot{GovernancePageImmutableSnapshot::Create(
        std::move(reservation), instance_id,
        validation_context_epoch, scope_hash, *view,
        std::move(entries))};
    m_page_snapshot = snapshot;
    return snapshot;
}

bool CGovernanceObjectVoteFile::SerializeVoteToStream(const uint256& nHash, CDataStream& ss) const
{
    auto it = mapVoteIndex.find(nHash);
    if (it == mapVoteIndex.end()) {
        return false;
    }
    ss << *(it->second);
    return true;
}

std::optional<std::size_t>
CGovernanceObjectVoteFile::GetVoteSerializedSizeUpperBound(
    const uint256& nHash, int version) const
{
    const auto it{mapVoteIndex.find(nHash)};
    if (it == mapVoteIndex.end()) return std::nullopt;
    const std::size_t size{
        ::GetSerializeSize(*it->second, version, SER_NETWORK)};
    // The logical vote hash omits its signature. Charge enough for any
    // canonical alternate before serialization so a remove/reinsert race
    // cannot exceed the admitted byte budget.
    const std::size_t signature_slack{
        MAX_GOVERNANCE_SIGNATURE_SIZE +
        GetSizeOfCompactSize(MAX_GOVERNANCE_SIGNATURE_SIZE)};
    if (size > std::numeric_limits<std::size_t>::max() -
                   signature_slack) {
        return std::nullopt;
    }
    return size + signature_slack;
}

std::vector<CGovernanceVote> CGovernanceObjectVoteFile::GetVotes() const
{
    std::vector<CGovernanceVote> vecResult;
    vecResult.reserve(listVotes.size());
    std::copy(std::begin(listVotes), std::end(listVotes), std::back_inserter(vecResult));
    return vecResult;
}

void CGovernanceObjectVoteFile::RemoveVotesFromMasternode(const COutPoint& outpointMasternode)
{
    const auto [begin, end]{mapMasternodeIndex.equal_range(
        outpointMasternode)};
    std::vector<uint256> hashes;
    hashes.reserve(std::distance(begin, end));
    for (auto it{begin}; it != end; ++it) {
        hashes.push_back(it->second->GetHash());
    }
    RemoveVotes(std::set<uint256>{hashes.begin(), hashes.end()});
}

void CGovernanceObjectVoteFile::RemoveVotes(
    const std::set<uint256>& vote_hashes)
{
    auto it = listVotes.begin();
    while (it != listVotes.end()) {
        if (!vote_hashes.contains(it->GetHash())) {
            ++it;
            continue;
        }
        it = EraseVote(it);
    }
}

std::set<uint256> CGovernanceObjectVoteFile::RemoveInvalidVotes(const CDeterministicMNList& tip_mn_list, const COutPoint& outpointMasternode, bool fProposal)
{
    std::set<uint256> removedVotes;
    ForEachVoteFromMasternode(
        outpointMasternode, [&](const CGovernanceVote& vote) {
            if ((!fProposal || vote.GetSignal() == VOTE_SIGNAL_FUNDING) &&
                !vote.IsValid(tip_mn_list)) {
                removedVotes.emplace(vote.GetHash());
            }
            return true;
        });
    RemoveVotes(removedVotes);
    return removedVotes;
}

void CGovernanceObjectVoteFile::RemoveOldVotes(const CGovernanceVote& vote)
{
    auto it = listVotes.begin();
    while (it != listVotes.end()) {
        if (it->GetMasternodeOutpoint() == vote.GetMasternodeOutpoint() // same masternode
            && it->GetParentHash() == vote.GetParentHash() // same governance object (e.g. same proposal)
            && it->GetSignal() == vote.GetSignal() // same signal (e.g. "funding", "delete", etc.)
            && it->GetTimestamp() < vote.GetTimestamp()) // older than new vote
        {
            it = EraseVote(it);
        } else {
            ++it;
        }
    }
}

CGovernanceObjectVoteFile::vote_l_t::iterator
CGovernanceObjectVoteFile::EraseVote(vote_l_t::iterator vote)
{
    const auto [begin, end]{mapMasternodeIndex.equal_range(
        vote->GetMasternodeOutpoint())};
    for (auto it{begin}; it != end; ++it) {
        if (it->second == vote) {
            mapMasternodeIndex.erase(it);
            break;
        }
    }
    const uint64_t vote_bytes{SerializedVoteBytes(*vote)};
    assert(nSerializedVoteBytes >= vote_bytes);
    nSerializedVoteBytes -= vote_bytes;
    --nMemoryVotes;
    mapVoteIndex.erase(vote->GetHash());
    InvalidatePageView();
    return listVotes.erase(vote);
}

void CGovernanceObjectVoteFile::RebuildIndex()
{
    InvalidatePageView();
    mapVoteIndex.clear();
    mapMasternodeIndex.clear();
    nMemoryVotes = 0;
    nSerializedVoteBytes = 0;
    auto it = listVotes.begin();
    while (it != listVotes.end()) {
        const CGovernanceVote& vote = *it;
        const uint256 nHash = vote.GetHash();
        if (mapVoteIndex.find(nHash) == mapVoteIndex.end()) {
            mapVoteIndex[nHash] = it;
            mapMasternodeIndex.emplace(vote.GetMasternodeOutpoint(), it);
            const uint64_t vote_bytes{SerializedVoteBytes(vote)};
            if (vote_bytes > std::numeric_limits<uint64_t>::max() -
                                 nSerializedVoteBytes) {
                throw std::ios_base::failure(
                    "governance vote byte count overflow");
            }
            nSerializedVoteBytes += vote_bytes;
            ++nMemoryVotes;
            ++it;
        } else {
            listVotes.erase(it++);
        }
    }
}
