// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation_db.h>

#include <logging.h>
#include <util/fs.h>

#include <algorithm>
#include <ios>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace llmq::pq {
namespace {

DBParams PaymentProbationDBParams(DBParams params)
{
    if (params.path.empty()) {
        params.path = "evodb_pq_payment_probation_v2";
    } else {
        const std::string sibling_name{
            fs::PathToString(params.path.filename()) +
            "_pq_payment_probation_v2"};
        params.path = params.path.parent_path() / sibling_name;
    }
    params.cache_bytes = std::max<std::size_t>(1, params.cache_bytes / 4);
    return params;
}

struct ExactPaymentProbationStateKey {
    uint256 hash;

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> hash;
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing payment probation state key bytes"};
        }
    }
};

struct ExactPaymentProbationStateValue {
    PQPaymentProbationState state;

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> state;
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing payment probation state value bytes"};
        }
    }
};

} // namespace

PQPaymentProbationManager::PQPaymentProbationManager(
    const DBParams& db_params)
    : m_state_db(std::make_unique<CEvoDB<
          uint256, PQPaymentProbationState, StaticSaltedHasher>>(
          PaymentProbationDBParams(db_params),
          /*maxCacheSizeIn=*/0,
          /*maxReadCacheSizeIn=*/64))
{
    const auto empty_hash{
        GetPQPaymentProbationStateHash(PQPaymentProbationState{})};
    if (!empty_hash) {
        throw std::runtime_error{
            "failed to derive empty payment probation state"};
    }
    m_empty_state_hash = *empty_hash;
}

bool PQPaymentProbationManager::GetState(
    const uint256& state_hash,
    PQPaymentProbationState& state) const
{
    LOCK(m_mutex);
    if (state_hash.IsNull()) return false;
    if (state_hash == m_empty_state_hash) {
        state = PQPaymentProbationState{};
        return true;
    }
    if (!m_state_db->ReadCache(state_hash, state) ||
        !state.IsStructurallyValid()) {
        return false;
    }
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    return actual_hash && *actual_hash == state_hash;
}

bool PQPaymentProbationManager::CommitState(
    const PQPaymentProbationState& state,
    const uint256& expected_hash,
    bool fJustCheck)
{
    LOCK(m_mutex);
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    if (!actual_hash || *actual_hash != expected_hash) return false;
    if (expected_hash == m_empty_state_hash || fJustCheck) return true;

    PQPaymentProbationState existing;
    if (m_state_db->ReadCache(expected_hash, existing)) {
        return existing == state;
    }
    return m_state_db->WriteThrough(expected_hash, state, /*fSync=*/false);
}

bool PQPaymentProbationManager::Flush(bool fSync)
{
    LOCK(m_mutex);
    return m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256, fSync);
}

bool PQPaymentProbationManager::PruneStatesThroughEpoch(
    uint32_t prune_through_epoch,
    std::span<const uint256> retained_state_hashes)
{
    LOCK(m_mutex);

    std::unordered_set<uint256, StaticSaltedHasher> retained;
    retained.reserve(retained_state_hashes.size() + 1);
    retained.insert(m_empty_state_hash);
    for (const uint256& state_hash : retained_state_hashes) {
        if (state_hash.IsNull()) {
            LogPrintf("%s -- refusing null retained payment probation "
                      "state hash\n",
                      __func__);
            return false;
        }
        retained.insert(state_hash);
    }

    // Publish every earlier state write before taking the iterator snapshot.
    // This is also the ordering barrier between the durable audit checkpoint
    // and the tombstones below.
    if (!m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256,
                                      /*fSync=*/true)) {
        return false;
    }

    std::unordered_set<uint256, StaticSaltedHasher> unresolved_retained{
        retained};
    unresolved_retained.erase(m_empty_state_hash);
    std::vector<uint256> prune_keys;
    std::unique_ptr<CDBIterator> cursor{m_state_db->NewIterator()};
    if (!cursor) {
        LogPrintf("%s -- failed to create payment probation state iterator\n",
                  __func__);
        return false;
    }

    for (cursor->SeekToFirst(); cursor->Valid(); cursor->Next()) {
        ExactPaymentProbationStateKey decoded_key;
        ExactPaymentProbationStateValue decoded_value;
        if (!cursor->GetKey(decoded_key) ||
            !cursor->GetValue(decoded_value) ||
            decoded_key.hash.IsNull() ||
            !decoded_value.state.IsStructurallyValid()) {
            LogPrintf("%s -- invalid persisted payment probation state "
                      "record\n",
                      __func__);
            return false;
        }

        const auto actual_hash{
            GetPQPaymentProbationStateHash(decoded_value.state)};
        if (!actual_hash || *actual_hash != decoded_key.hash ||
            (decoded_key.hash == m_empty_state_hash &&
             decoded_value.state != PQPaymentProbationState{})) {
            LogPrintf("%s -- payment probation state hash mismatch for %s\n",
                      __func__, decoded_key.hash.ToString());
            return false;
        }

        unresolved_retained.erase(decoded_key.hash);
        if (retained.count(decoded_key.hash) != 0 ||
            decoded_value.state.cursor.has_receipt == 0 ||
            decoded_value.state.cursor.receipt.epoch >
                prune_through_epoch) {
            continue;
        }
        prune_keys.emplace_back(decoded_key.hash);
    }

    if (!unresolved_retained.empty()) {
        LogPrintf("%s -- retained payment probation state %s is missing\n",
                  __func__, unresolved_retained.begin()->ToString());
        return false;
    }

    for (const uint256& state_hash : prune_keys) {
        // EraseCache removes both dirty and read-cache copies before staging a
        // tombstone, so a later lookup cannot resurrect the deleted state.
        m_state_db->EraseCache(state_hash);
    }
    if (!m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256,
                                      /*fSync=*/true)) {
        return false;
    }

    LogPrint(BCLog::SYS,
             "%s -- pruned %zu payment probation states through epoch %u; "
             "retained=%zu\n",
             __func__, prune_keys.size(), prune_through_epoch,
             retained.size());
    return true;
}

} // namespace llmq::pq
