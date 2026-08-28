// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation_db.h>

#include <logging.h>
#include <util/fs.h>

#include <algorithm>
#include <ios>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace llmq::pq {

struct PQPaymentProbationStateViewOwner {};

struct PQPaymentProbationStateViewData {
    std::shared_ptr<const PQPaymentProbationStateViewOwner> owner;
    uint64_t generation{0};
    uint256 state_hash;
    PQPaymentProbationState state;
    std::unordered_map<uint256, std::size_t, StaticSaltedHasher>
        entry_index;
};

namespace {

constexpr uint32_t PAYMENT_PROBATION_GC_VERSION{1};
constexpr uint32_t PAYMENT_PROBATION_GC_GUARD{0x50504731}; // "PPG1"

const uint256& PaymentProbationGCKey()
{
    // State keys are hashes. Reserve the all-ones value for metadata and
    // reject the cryptographically-improbable collision at state admission.
    static const uint256 key{[] {
        uint256 value;
        std::fill(value.begin(), value.end(), 0xff);
        return value;
    }()};
    return key;
}

struct PaymentProbationGCRecord {
    static constexpr std::size_t WIRE_SIZE{
        5 * sizeof(uint32_t) + 5 * 32 +
        PaymentAuditReceiptState::WIRE_SIZE};

    uint32_t version{PAYMENT_PROBATION_GC_VERSION};
    PaymentAuditStoreCheckpoint checkpoint;
    uint32_t guard{PAYMENT_PROBATION_GC_GUARD};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(
            stream, version, checkpoint.prune_through_epoch,
            checkpoint.covered_through_height,
            checkpoint.covered_through_hash,
            checkpoint.authenticated_receipt_state,
            checkpoint.authenticated_probation_state_hash,
            checkpoint.authorizing_target_height,
            checkpoint.authorizing_target_hash,
            checkpoint.authorizing_chainlock_logical_id,
            checkpoint.authorizing_chainlock_witness_id, guard);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (stream.size() != WIRE_SIZE) {
            throw std::ios_base::failure{
                "invalid payment probation GC marker size"};
        }
        ::UnserializeMany(
            stream, version, checkpoint.prune_through_epoch,
            checkpoint.covered_through_height,
            checkpoint.covered_through_hash,
            checkpoint.authenticated_receipt_state,
            checkpoint.authenticated_probation_state_hash,
            checkpoint.authorizing_target_height,
            checkpoint.authorizing_target_hash,
            checkpoint.authorizing_chainlock_logical_id,
            checkpoint.authorizing_chainlock_witness_id, guard);
    }
};

static_assert(PaymentProbationGCRecord::WIRE_SIZE == 316);

bool IsGCRecordValid(const PaymentProbationGCRecord& record)
{
    return record.version == PAYMENT_PROBATION_GC_VERSION &&
           record.guard == PAYMENT_PROBATION_GC_GUARD &&
           record.checkpoint.IsStructurallyValid();
}

bool HasSameGCBoundary(const PaymentAuditStoreCheckpoint& left,
                       const PaymentAuditStoreCheckpoint& right)
{
    return left.IsStructurallyValid() && right.IsStructurallyValid() &&
           left.prune_through_epoch == right.prune_through_epoch &&
           left.covered_through_height == right.covered_through_height &&
           left.covered_through_hash == right.covered_through_hash &&
           left.authenticated_receipt_state ==
               right.authenticated_receipt_state &&
           left.authenticated_probation_state_hash ==
               right.authenticated_probation_state_hash;
}

enum class GCRecordStatus : uint8_t {
    ABSENT,
    VALID,
    CORRUPT,
};

GCRecordStatus ReadGCRecord(
    const CEvoDB<uint256, PQPaymentProbationState, StaticSaltedHasher>& db,
    PaymentProbationGCRecord& record)
{
    if (!db.Exists(PaymentProbationGCKey())) {
        return GCRecordStatus::ABSENT;
    }
    if (!db.Read(PaymentProbationGCKey(), record) ||
        !IsGCRecordValid(record)) {
        return GCRecordStatus::CORRUPT;
    }
    return GCRecordStatus::VALID;
}

DBParams PaymentProbationDBParams(DBParams params)
{
    if (params.path.empty()) {
        params.path = "evodb_pq_payment_probation";
    } else {
        const std::string sibling_name{
            fs::PathToString(params.path.filename()) +
            "_pq_payment_probation"};
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

PQPaymentProbationStateView::PQPaymentProbationStateView(
    std::shared_ptr<const PQPaymentProbationStateViewData> state)
    : m_state{std::move(state)}
{
}

bool PQPaymentProbationStateView::IsValid() const noexcept
{
    return m_state != nullptr;
}

uint256 PQPaymentProbationStateView::StateHash() const noexcept
{
    return IsValid() ? m_state->state_hash : uint256{};
}

const PQPaymentProbationState*
PQPaymentProbationStateView::State() const noexcept
{
    return IsValid() ? &m_state->state : nullptr;
}

uint8_t PQPaymentProbationStateView::MissCount(
    const uint256& pro_tx_hash) const noexcept
{
    if (!IsValid() || pro_tx_hash.IsNull()) return 0;
    const auto position{m_state->entry_index.find(pro_tx_hash)};
    return position == m_state->entry_index.end()
        ? 0
        : m_state->state.entries[position->second].consecutive_misses;
}

bool PQPaymentProbationStateView::IsPaymentWithheld(
    const uint256& pro_tx_hash) const noexcept
{
    return MissCount(pro_tx_hash) == PQ_PAYMENT_PROBATION_MAX_MISSES;
}

int32_t PQPaymentProbationStateView::PaymentEligibleSinceHeight(
    const uint256& pro_tx_hash) const noexcept
{
    if (!IsValid() || pro_tx_hash.IsNull()) return -1;
    const auto position{m_state->entry_index.find(pro_tx_hash)};
    return position == m_state->entry_index.end()
        ? -1
        : m_state->state.entries[position->second]
              .payment_eligible_since_height;
}

bool PQPaymentProbationStateView::SharesStateWith(
    const PQPaymentProbationStateView& other) const noexcept
{
    return IsValid() && other.IsValid() && m_state == other.m_state;
}

bool PQPaymentProbationTransitionView::IsValid() const noexcept
{
    return m_result.IsValid() && !m_previous_state_hash.IsNull() &&
           m_applied_receipt.IsStructurallyValid() &&
           m_result.State() != nullptr &&
           m_result.State()->cursor.has_receipt == 1 &&
           m_result.State()->cursor.receipt == m_applied_receipt;
}

const PQPaymentProbationStateView&
PQPaymentProbationTransitionView::Result() const noexcept
{
    return m_result;
}

uint256 PQPaymentProbationTransitionView::PreviousStateHash() const noexcept
{
    return IsValid() ? m_previous_state_hash : uint256{};
}

const PQPaymentAuditReceiptIdentity&
PQPaymentProbationTransitionView::AppliedReceipt() const noexcept
{
    return m_applied_receipt;
}

uint64_t PQPaymentProbationTransitionView::ProvenanceGeneration() const noexcept
{
    return m_result.m_state ? m_result.m_state->generation : 0;
}

PQPaymentProbationManager::PQPaymentProbationManager(
    const DBParams& db_params)
    : m_state_db(std::make_unique<CEvoDB<
          uint256, PQPaymentProbationState, StaticSaltedHasher>>(
          PaymentProbationDBParams(db_params),
          /*maxCacheSizeIn=*/0,
          /*maxReadCacheSizeIn=*/0))
{
    m_view_owner = std::make_shared<PQPaymentProbationStateViewOwner>();
    PQPaymentProbationState empty_state;
    const auto empty_hash{GetPQPaymentProbationStateHash(empty_state)};
    if (!empty_hash) {
        throw std::runtime_error{
            "failed to derive empty payment probation state"};
    }
    m_empty_state_hash = *empty_hash;
    if (m_empty_state_hash == PaymentProbationGCKey()) {
        throw std::runtime_error{
            "payment probation empty-state hash collides with metadata key"};
    }
    auto empty_view{std::make_shared<PQPaymentProbationStateViewData>()};
    empty_view->owner = m_view_owner;
    empty_view->generation = m_state_view_generation;
    empty_view->state_hash = m_empty_state_hash;
    empty_view->state = std::move(empty_state);
    m_empty_state_view = std::move(empty_view);
}

PQPaymentProbationManager::StateViewDataPtr
PQPaymentProbationManager::BuildValidatedStateView(
    const uint256& state_hash,
    PQPaymentProbationState state) const
{
    if (state_hash.IsNull() || state_hash == PaymentProbationGCKey()) {
        return nullptr;
    }
    auto view{std::make_shared<PQPaymentProbationStateViewData>()};
    view->owner = m_view_owner;
    view->generation = m_state_view_generation;
    view->state_hash = state_hash;
    view->state = std::move(state);
    view->entry_index.reserve(view->state.entries.size());
    for (std::size_t index{0}; index < view->state.entries.size(); ++index) {
        if (!view->entry_index
                 .emplace(view->state.entries[index].pro_tx_hash, index)
                 .second) {
            return nullptr;
        }
    }
    ++m_state_view_builds;
    return view;
}

bool PQPaymentProbationManager::PublishStateView(
    StateViewDataPtr state,
    StateViewDataPtr* published) const
{
    if (!state || state->state_hash.IsNull() ||
        state->state_hash == PaymentProbationGCKey() ||
        state->state_hash == m_empty_state_hash) {
        return false;
    }

    const auto existing{m_state_view_cache_index.find(state->state_hash)};
    if (existing != m_state_view_cache_index.end()) {
        m_state_view_cache.splice(m_state_view_cache.end(),
                                  m_state_view_cache, existing->second);
        if (published != nullptr) *published = existing->second->second;
        return true;
    }

    m_state_view_cache.emplace_back(state->state_hash, std::move(state));
    const auto inserted{std::prev(m_state_view_cache.end())};
    try {
        if (!m_state_view_cache_index.emplace(inserted->first, inserted)
                 .second) {
            m_state_view_cache.pop_back();
            return false;
        }
    } catch (...) {
        m_state_view_cache.pop_back();
        throw;
    }
    if (published != nullptr) *published = inserted->second;

    while (m_state_view_cache.size() > STATE_VIEW_CACHE_SIZE) {
        m_state_view_cache_index.erase(m_state_view_cache.front().first);
        m_state_view_cache.pop_front();
    }
    return true;
}

bool PQPaymentProbationManager::GetStateView(
    const uint256& state_hash,
    PQPaymentProbationStateView& view) const
{
    view = PQPaymentProbationStateView{};
    LOCK(m_mutex);
    if (state_hash.IsNull() || state_hash == PaymentProbationGCKey()) {
        return false;
    }
    if (state_hash == m_empty_state_hash) {
        ++m_state_view_cache_hits;
        view = PQPaymentProbationStateView{m_empty_state_view};
        return true;
    }

    const auto cached{m_state_view_cache_index.find(state_hash)};
    if (cached != m_state_view_cache_index.end()) {
        m_state_view_cache.splice(m_state_view_cache.end(),
                                  m_state_view_cache, cached->second);
        ++m_state_view_cache_hits;
        view = PQPaymentProbationStateView{cached->second->second};
        return true;
    }

    ++m_state_view_cache_misses;
    PQPaymentProbationState state;
    if (!m_state_db->ReadCache(state_hash, state)) return false;
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    if (!actual_hash || *actual_hash != state_hash) return false;
    auto built{BuildValidatedStateView(state_hash, std::move(state))};
    if (!built) return false;
    StateViewDataPtr published;
    if (!PublishStateView(std::move(built), &published)) return false;
    view = PQPaymentProbationStateView{std::move(published)};
    return true;
}

bool PQPaymentProbationManager::GetState(
    const uint256& state_hash,
    PQPaymentProbationState& state) const
{
    PQPaymentProbationStateView view;
    if (!GetStateView(state_hash, view) || view.State() == nullptr) {
        return false;
    }
    state = *view.State();
    return true;
}

bool PQPaymentProbationManager::AuthenticateTransitionParent(
    const PQPaymentProbationStateView& previous,
    StateViewDataPtr& authenticated,
    uint64_t& generation,
    PQPaymentProbationError* error) const
{
    if (error != nullptr) *error = PQPaymentProbationError::NONE;
    LOCK(m_mutex);
    if (!previous.m_state || previous.m_state->owner != m_view_owner ||
        previous.m_state->generation != m_state_view_generation) {
        if (error != nullptr) {
            *error = PQPaymentProbationError::INVALID_STATE;
        }
        return false;
    }
    authenticated = previous.m_state;
    generation = m_state_view_generation;
    return true;
}

std::optional<PQPaymentProbationTransitionView>
PQPaymentProbationManager::FinalizeTransition(
    StateViewDataPtr previous,
    uint64_t generation,
    CompactTransitionResult result,
    PQPaymentProbationError* error) const
{
    if (!previous || result.previous_state_hash != previous->state_hash) {
        if (error != nullptr) {
            *error = PQPaymentProbationError::INVALID_RESULT;
        }
        return std::nullopt;
    }
    auto result_state{std::make_shared<PQPaymentProbationStateViewData>()};
    result_state->owner = previous->owner;
    result_state->generation = generation;
    result_state->state_hash = result.applied_state_hash;
    result_state->state = std::move(result.state);
    result_state->entry_index.reserve(result_state->state.entries.size());
    for (std::size_t index{0}; index < result_state->state.entries.size();
         ++index) {
        if (!result_state->entry_index.emplace(
                result_state->state.entries[index].pro_tx_hash, index).second) {
            if (error != nullptr) {
                *error = PQPaymentProbationError::INVALID_RESULT;
            }
            return std::nullopt;
        }
    }
    {
        LOCK(m_mutex);
        if (generation != m_state_view_generation) {
            if (error != nullptr) {
                *error = PQPaymentProbationError::INVALID_STATE;
            }
            return std::nullopt;
        }
        ++m_state_view_builds;
    }
    PQPaymentProbationTransitionView transition;
    transition.m_result = PQPaymentProbationStateView{std::move(result_state)};
    transition.m_previous_state_hash = result.previous_state_hash;
    transition.m_applied_receipt = result.applied_receipt;
    return transition;
}

std::optional<PQPaymentProbationTransitionView>
PQPaymentProbationManager::ApplyTransitionWithMembership(
    const PQPaymentProbationStateView& previous,
    const PQPaymentProbationTransitionContext& context,
    const MembershipResolver& membership,
    PQPaymentProbationError* error) const
{
    if (!membership) {
        if (error != nullptr) {
            *error = PQPaymentProbationError::INVALID_RESULT;
        }
        return std::nullopt;
    }
    StateViewDataPtr previous_state;
    uint64_t generation{0};
    if (!AuthenticateTransitionParent(
            previous, previous_state, generation, error)) {
        return std::nullopt;
    }
    AssertLockNotHeld(m_mutex);
    std::optional<CompactTransitionResult> result;
    try {
        result = ApplyCompactTransition(previous, context, membership, error);
    } catch (...) {
        if (error != nullptr) {
            *error = PQPaymentProbationError::INVALID_RESULT;
        }
        return std::nullopt;
    }
    if (!result) return std::nullopt;
    return FinalizeTransition(
        std::move(previous_state), generation, std::move(*result), error);
}

bool PQPaymentProbationManager::CommitState(
    const PQPaymentProbationState& state,
    const uint256& expected_hash,
    bool fJustCheck)
{
    LOCK(m_mutex);
    const auto actual_hash{GetPQPaymentProbationStateHash(state)};
    if (!actual_hash || *actual_hash != expected_hash ||
        expected_hash == PaymentProbationGCKey()) {
        return false;
    }
    if (expected_hash == m_empty_state_hash || fJustCheck) return true;

    PQPaymentProbationState existing;
    if (m_state_db->ReadCache(expected_hash, existing)) {
        if (existing != state) return false;
    } else if (!m_state_db->WriteThrough(expected_hash, state,
                                         /*fSync=*/false)) {
        return false;
    }

    const auto cached{m_state_view_cache_index.find(expected_hash)};
    if (cached != m_state_view_cache_index.end()) {
        m_state_view_cache.splice(m_state_view_cache.end(),
                                  m_state_view_cache, cached->second);
        return true;
    }
    auto built{BuildValidatedStateView(expected_hash, state)};
    return built && PublishStateView(std::move(built));
}

bool PQPaymentProbationManager::CommitTransition(
    const PQPaymentProbationTransitionView& transition,
    bool fJustCheck,
    PQPaymentProbationStateView* published)
{
    if (published != nullptr) *published = PQPaymentProbationStateView{};
    LOCK(m_mutex);
    if (!transition.IsValid() || !transition.m_result.m_state ||
        transition.m_result.m_state->owner != m_view_owner ||
        transition.m_result.m_state->generation != m_state_view_generation) {
        return false;
    }
    if (fJustCheck) return true;

    const auto& result{transition.m_result.m_state};
    if (result->state_hash == m_empty_state_hash) return false;
    const auto cached{m_state_view_cache_index.find(result->state_hash)};
    StateViewDataPtr exact;
    if (cached != m_state_view_cache_index.end()) {
        if (cached->second->second != result &&
            cached->second->second->state != result->state) return false;
        m_state_view_cache.splice(m_state_view_cache.end(),
                                  m_state_view_cache, cached->second);
        exact = cached->second->second;
    } else {
        PQPaymentProbationState existing;
        if (m_state_db->ReadCache(result->state_hash, existing)) {
            if (existing != result->state) return false;
        } else if (!m_state_db->WriteThrough(
                       result->state_hash, result->state,
                       /*fSync=*/false)) {
            return false;
        }
        if (!PublishStateView(result, &exact)) return false;
    }
    if (published != nullptr) {
        *published = PQPaymentProbationStateView{std::move(exact)};
    }
    return true;
}

uint64_t PQPaymentProbationManager::StateViewGeneration() const
{
    LOCK(m_mutex);
    return m_state_view_generation;
}

bool PQPaymentProbationManager::Flush(bool fSync)
{
    LOCK(m_mutex);
    return m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256, fSync);
}

bool PQPaymentProbationManager::IsGCCompleteForCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint) const
{
    LOCK(m_mutex);
    if (!checkpoint.IsStructurallyValid()) return false;
    try {
        PaymentProbationGCRecord record;
        return ReadGCRecord(*m_state_db, record) == GCRecordStatus::VALID &&
               HasSameGCBoundary(record.checkpoint, checkpoint);
    } catch (const std::exception& exception) {
        LogPrintf("%s -- unable to read payment probation GC marker: %s\n",
                  __func__, exception.what());
        return false;
    }
}

bool PQPaymentProbationManager::PruneStatesThroughCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes)
{
    LOCK(m_mutex);
    if (!checkpoint.IsStructurallyValid()) return false;

    PaymentProbationGCRecord previous_gc;
    const auto previous_gc_status{ReadGCRecord(*m_state_db, previous_gc)};
    if (previous_gc_status == GCRecordStatus::CORRUPT) {
        LogPrintf("%s -- corrupt payment probation GC marker\n", __func__);
        return false;
    }
    if (previous_gc_status == GCRecordStatus::VALID) {
        if (HasSameGCBoundary(previous_gc.checkpoint, checkpoint)) {
            return true;
        }
        if (checkpoint.prune_through_epoch <=
            previous_gc.checkpoint.prune_through_epoch) {
            LogPrintf("%s -- refusing non-monotonic payment probation GC "
                      "checkpoint\n",
                      __func__);
            return false;
        }
    }

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
    bool found_gc_record{false};
    std::unique_ptr<CDBIterator> cursor{m_state_db->NewIterator()};
    if (!cursor) {
        LogPrintf("%s -- failed to create payment probation state iterator\n",
                  __func__);
        return false;
    }

    for (cursor->SeekToFirst(); cursor->Valid(); cursor->Next()) {
        ExactPaymentProbationStateKey decoded_key;
        if (!cursor->GetKey(decoded_key) || decoded_key.hash.IsNull()) {
            LogPrintf("%s -- invalid persisted payment probation state "
                      "key\n",
                      __func__);
            return false;
        }
        if (decoded_key.hash == PaymentProbationGCKey()) {
            PaymentProbationGCRecord record;
            if (found_gc_record || !cursor->GetValue(record) ||
                !IsGCRecordValid(record) ||
                previous_gc_status != GCRecordStatus::VALID ||
                record.checkpoint != previous_gc.checkpoint) {
                LogPrintf("%s -- invalid persisted payment probation GC "
                          "marker\n",
                          __func__);
                return false;
            }
            found_gc_record = true;
            continue;
        }

        ExactPaymentProbationStateValue decoded_value;
        if (!cursor->GetValue(decoded_value) ||
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
                checkpoint.prune_through_epoch) {
            continue;
        }
        prune_keys.emplace_back(decoded_key.hash);
    }

    if (found_gc_record !=
        (previous_gc_status == GCRecordStatus::VALID)) {
        LogPrintf("%s -- payment probation GC marker iterator mismatch\n",
                  __func__);
        return false;
    }
    if (!unresolved_retained.empty()) {
        LogPrintf("%s -- retained payment probation state %s is missing\n",
                  __func__, unresolved_retained.begin()->ToString());
        return false;
    }

    // Invalidate every prepared transition before the first destructive or
    // marker mutation. This also covers an accepted empty-prune boundary: an
    // unpublished old result must not later recreate a below-boundary state.
    if (m_state_view_generation == std::numeric_limits<uint64_t>::max()) {
        LogPrintf("%s -- payment probation state-view generation exhausted\n",
                  __func__);
        return false;
    }
    const uint64_t next_generation{m_state_view_generation + 1};
    auto empty_view{std::make_shared<PQPaymentProbationStateViewData>()};
    empty_view->owner = m_view_owner;
    empty_view->generation = next_generation;
    empty_view->state_hash = m_empty_state_hash;

    m_state_view_generation = next_generation;
    m_state_view_cache.clear();
    m_state_view_cache_index.clear();
    m_empty_state_view = std::move(empty_view);

    for (const uint256& state_hash : prune_keys) {
        // Future root resolution must fail after pruning, while a reader that
        // already owns this immutable state may safely finish its operation.
        // EraseCache removes both dirty and read-cache copies before staging a
        // tombstone, so a later lookup cannot resurrect the deleted state.
        m_state_db->EraseCache(state_hash);
    }
    if (!m_state_db->FlushCacheToDisk(/*nMaxBatchSize=*/256,
                                      /*fSync=*/true)) {
        return false;
    }

    // The marker follows durable tombstones. A crash between the two writes
    // repeats an idempotent repair pass; once this marker is durable the
    // scheduler can skip every fsync for the unchanged checkpoint.
    if (!m_state_db->Write(
            PaymentProbationGCKey(),
            PaymentProbationGCRecord{
                PAYMENT_PROBATION_GC_VERSION, checkpoint,
                PAYMENT_PROBATION_GC_GUARD},
            /*fSync=*/true)) {
        return false;
    }

    LogPrint(BCLog::SYS,
             "%s -- pruned %zu payment probation states through epoch %u; "
             "retained=%zu\n",
             __func__, prune_keys.size(), checkpoint.prune_through_epoch,
             retained.size());
    return true;
}

} // namespace llmq::pq
