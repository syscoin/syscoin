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
constexpr uint32_t PAYMENT_PROBATION_GC_INTENT_GUARD{0x50504732}; // "PPG2"

constexpr std::size_t PAYMENT_PROBATION_STATE_MAX_WIRE_SIZE{
    sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint32_t) +
    sizeof(int32_t) + 32 + sizeof(uint16_t) +
    MAX_PQ_PAYMENT_PROBATION_ENTRIES *
        (32 + sizeof(uint8_t) + sizeof(int32_t))};

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

const uint256& PaymentProbationGCIntentKey()
{
    static const uint256 key{[] {
        uint256 value;
        std::fill(value.begin(), value.end(), 0xff);
        value.begin()[0] = 0xfe;
        return value;
    }()};
    return key;
}

bool IsPaymentProbationMetadataKey(const uint256& key)
{
    return key == PaymentProbationGCKey() ||
           key == PaymentProbationGCIntentKey();
}

template <typename Stream>
void SerializeGCCheckpoint(Stream& stream,
                           const PaymentAuditStoreCheckpoint& checkpoint)
{
    ::SerializeMany(
        stream, checkpoint.prune_through_epoch,
        checkpoint.covered_through_height,
        checkpoint.covered_through_hash,
        checkpoint.authenticated_receipt_state,
        checkpoint.authenticated_probation_state_hash,
        checkpoint.authorizing_target_height,
        checkpoint.authorizing_target_hash,
        checkpoint.authorizing_chainlock_logical_id,
        checkpoint.authorizing_chainlock_witness_id);
}

template <typename Stream>
void UnserializeGCCheckpoint(Stream& stream,
                             PaymentAuditStoreCheckpoint& checkpoint)
{
    ::UnserializeMany(
        stream, checkpoint.prune_through_epoch,
        checkpoint.covered_through_height,
        checkpoint.covered_through_hash,
        checkpoint.authenticated_receipt_state,
        checkpoint.authenticated_probation_state_hash,
        checkpoint.authorizing_target_height,
        checkpoint.authorizing_target_hash,
        checkpoint.authorizing_chainlock_logical_id,
        checkpoint.authorizing_chainlock_witness_id);
}

struct PaymentProbationGCRecord {
    static constexpr std::size_t CHECKPOINT_WIRE_SIZE{
        5 * sizeof(uint32_t) + 5 * 32 +
        PaymentAuditReceiptState::WIRE_SIZE};
    static constexpr std::size_t MAX_WIRE_SIZE{
        CHECKPOINT_WIRE_SIZE + sizeof(uint8_t) +
        PQPaymentProbationManager::MAX_GC_RETAINED_ROOTS * 32};

    uint32_t version{PAYMENT_PROBATION_GC_VERSION};
    PQPaymentProbationGCRequest request;
    uint32_t guard{PAYMENT_PROBATION_GC_GUARD};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (request.retained_state_hashes.size() >
            PQPaymentProbationManager::MAX_GC_RETAINED_ROOTS) {
            throw std::ios_base::failure{
                "too many retained payment probation roots"};
        }
        stream << version;
        SerializeGCCheckpoint(stream, request.checkpoint);
        const uint8_t retained_count{
            static_cast<uint8_t>(request.retained_state_hashes.size())};
        stream << retained_count;
        for (const auto& state_hash : request.retained_state_hashes) {
            stream << state_hash;
        }
        stream << guard;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> version;
        UnserializeGCCheckpoint(stream, request.checkpoint);
        uint8_t retained_count{0};
        stream >> retained_count;
        if (retained_count >
            PQPaymentProbationManager::MAX_GC_RETAINED_ROOTS) {
            throw std::ios_base::failure{
                "too many retained payment probation roots"};
        }
        request.retained_state_hashes.resize(retained_count);
        for (auto& state_hash : request.retained_state_hashes) {
            stream >> state_hash;
        }
        stream >> guard;
    }
};

static_assert(PaymentProbationGCRecord::CHECKPOINT_WIRE_SIZE == 316);
static_assert(PaymentProbationGCRecord::MAX_WIRE_SIZE == 829);

struct PaymentProbationGCIntentRecord {
    uint32_t version{PAYMENT_PROBATION_GC_VERSION};
    PaymentProbationGCRecord target;
    uint8_t phase{0};
    uint8_t retained_index{0};
    uint8_t has_cursor{0};
    uint256 cursor;
    uint32_t guard{PAYMENT_PROBATION_GC_INTENT_GUARD};

    SERIALIZE_METHODS(PaymentProbationGCIntentRecord, obj)
    {
        READWRITE(obj.version, obj.target, obj.phase,
                  obj.retained_index, obj.has_cursor, obj.cursor,
                  obj.guard);
    }
};

constexpr std::size_t PAYMENT_PROBATION_GC_INTENT_MAX_WIRE_SIZE{
    sizeof(uint32_t) + PaymentProbationGCRecord::MAX_WIRE_SIZE +
    3 * sizeof(uint8_t) + 32 + sizeof(uint32_t)};
static_assert(PAYMENT_PROBATION_GC_INTENT_MAX_WIRE_SIZE == 872);

bool AreRetainedRootsCanonical(const std::vector<uint256>& roots,
                               const uint256& empty_state_hash)
{
    if (roots.size() >
        PQPaymentProbationManager::MAX_GC_RETAINED_ROOTS) {
        return false;
    }
    for (std::size_t index{0}; index < roots.size(); ++index) {
        if (roots[index].IsNull() ||
            IsPaymentProbationMetadataKey(roots[index]) ||
            roots[index] == empty_state_hash ||
            (index != 0 && !(roots[index - 1] < roots[index]))) {
            return false;
        }
    }
    return true;
}

bool IsGCRecordValid(const PaymentProbationGCRecord& record,
                     const uint256& empty_state_hash)
{
    return record.version == PAYMENT_PROBATION_GC_VERSION &&
           record.guard == PAYMENT_PROBATION_GC_GUARD &&
           record.request.checkpoint.IsStructurallyValid() &&
           !IsPaymentProbationMetadataKey(
               record.request.checkpoint
                   .authenticated_probation_state_hash) &&
           AreRetainedRootsCanonical(
               record.request.retained_state_hashes,
               empty_state_hash);
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

bool IsGCCheckpointAdvance(
    const PaymentAuditStoreCheckpoint& previous,
    const PaymentAuditStoreCheckpoint& candidate) noexcept
{
    if (candidate.prune_through_epoch <= previous.prune_through_epoch ||
        candidate.covered_through_height <=
            previous.covered_through_height ||
        candidate.authorizing_target_height <=
            previous.authorizing_target_height) {
        return false;
    }
    const auto& old_state{previous.authenticated_receipt_state};
    const auto& new_state{candidate.authenticated_receipt_state};
    if (old_state.cursor.IsNull()) {
        return !new_state.cursor.IsNull() ||
               candidate.authenticated_probation_state_hash ==
                   previous.authenticated_probation_state_hash;
    }
    if (new_state.cursor.IsNull() ||
        new_state.cursor.epoch < old_state.cursor.epoch ||
        new_state.cursor.carrier_height <
            old_state.cursor.carrier_height) {
        return false;
    }
    if (new_state.cursor == old_state.cursor) {
        return new_state == old_state &&
               candidate.authenticated_probation_state_hash ==
                   previous.authenticated_probation_state_hash;
    }
    return true;
}

enum class BoundedReadResult : uint8_t {
    NOT_FOUND = 0,
    FOUND,
    CORRUPT,
};

template <typename Value>
BoundedReadResult ReadExactBounded(
    CDBWrapper& db, const uint256& key,
    std::size_t maximum_value_size, Value& value)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return BoundedReadResult::NOT_FOUND;
    }
    uint256 found;
    if (!iterator->GetKey(found) || found != key) {
        iterator->CheckStatus();
        return BoundedReadResult::NOT_FOUND;
    }
    if (!iterator->GetKeyExact(found) ||
        iterator->GetValueSize() > maximum_value_size ||
        !iterator->GetValueExact(value)) {
        return BoundedReadResult::CORRUPT;
    }
    iterator->CheckStatus();
    return BoundedReadResult::FOUND;
}

bool HasExactSingletonRange(CDBWrapper& db, const uint256& key,
                            bool expected_present)
{
    std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
    iterator->Seek(key);
    if (!iterator->Valid()) {
        iterator->CheckStatus();
        return !expected_present;
    }
    uint256 found;
    if (!iterator->GetKey(found)) return false;
    if (found != key) {
        iterator->CheckStatus();
        return !expected_present;
    }
    uint256 exact;
    if (!expected_present || !iterator->GetKeyExact(exact) ||
        exact != key) {
        return false;
    }
    iterator->Next();
    if (iterator->Valid()) {
        uint256 next;
        if (!iterator->GetKey(next) || next == key) return false;
    }
    iterator->CheckStatus();
    return true;
}

std::optional<PQPaymentProbationGCRequest> NormalizeGCRequest(
    const PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes,
    const uint256& empty_state_hash)
{
    if (!checkpoint.IsStructurallyValid() ||
        IsPaymentProbationMetadataKey(
            checkpoint.authenticated_probation_state_hash) ||
        retained_state_hashes.size() >
            PQPaymentProbationManager::MAX_GC_RETAINED_ROOTS) {
        return std::nullopt;
    }
    PQPaymentProbationGCRequest request{checkpoint, {}};
    request.retained_state_hashes.reserve(retained_state_hashes.size());
    for (const auto& state_hash : retained_state_hashes) {
        if (state_hash.IsNull() ||
            IsPaymentProbationMetadataKey(state_hash)) {
            return std::nullopt;
        }
        if (state_hash != empty_state_hash) {
            request.retained_state_hashes.emplace_back(state_hash);
        }
    }
    std::sort(request.retained_state_hashes.begin(),
              request.retained_state_hashes.end());
    request.retained_state_hashes.erase(
        std::unique(request.retained_state_hashes.begin(),
                    request.retained_state_hashes.end()),
        request.retained_state_hashes.end());
    return request;
}

PaymentProbationGCRecord MakeGCRecord(
    const PQPaymentProbationGCRequest& request)
{
    return {PAYMENT_PROBATION_GC_VERSION, request,
            PAYMENT_PROBATION_GC_GUARD};
}

bool IsGCIntentRecordValid(
    const PaymentProbationGCIntentRecord& record,
    const uint256& empty_state_hash)
{
    if (record.version != PAYMENT_PROBATION_GC_VERSION ||
        record.guard != PAYMENT_PROBATION_GC_INTENT_GUARD ||
        !IsGCRecordValid(record.target, empty_state_hash) ||
        record.phase > 2 || record.has_cursor > 1 ||
        record.retained_index >
            record.target.request.retained_state_hashes.size()) {
        return false;
    }
    if (record.phase == 0) {
        return record.retained_index <
                   record.target.request.retained_state_hashes.size() &&
               record.has_cursor == 0 && record.cursor.IsNull();
    }
    return record.retained_index ==
               record.target.request.retained_state_hashes.size() &&
           ((record.has_cursor == 0 && record.cursor.IsNull()) ||
            (record.has_cursor == 1 && !record.cursor.IsNull()));
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

struct CorruptPaymentProbationGC {};
struct InvalidPaymentProbationGCRetainedRoot {};

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
    if (IsPaymentProbationMetadataKey(m_empty_state_hash)) {
        throw std::runtime_error{
            "payment probation empty-state hash collides with metadata key"};
    }
    InitializeGCState();
    auto empty_view{std::make_shared<PQPaymentProbationStateViewData>()};
    empty_view->owner = m_view_owner;
    empty_view->generation = m_state_view_generation;
    empty_view->state_hash = m_empty_state_hash;
    empty_view->state = std::move(empty_state);
    m_empty_state_view = std::move(empty_view);
}

void PQPaymentProbationManager::InitializeGCState()
{
    LOCK(m_mutex);
    try {
        PaymentProbationGCRecord completed;
        const auto completed_status{ReadExactBounded(
            *m_state_db, PaymentProbationGCKey(),
            PaymentProbationGCRecord::MAX_WIRE_SIZE, completed)};
        if (completed_status == BoundedReadResult::CORRUPT ||
            !HasExactSingletonRange(
                *m_state_db, PaymentProbationGCKey(),
                completed_status == BoundedReadResult::FOUND) ||
            (completed_status == BoundedReadResult::FOUND &&
             !IsGCRecordValid(completed, m_empty_state_hash))) {
            throw std::runtime_error{
                "corrupt payment probation GC marker"};
        }
        if (completed_status == BoundedReadResult::FOUND) {
            m_completed_gc = completed.request;
        }

        PaymentProbationGCIntentRecord pending;
        const auto pending_status{ReadExactBounded(
            *m_state_db, PaymentProbationGCIntentKey(),
            PAYMENT_PROBATION_GC_INTENT_MAX_WIRE_SIZE, pending)};
        if (pending_status == BoundedReadResult::CORRUPT ||
            !HasExactSingletonRange(
                *m_state_db, PaymentProbationGCIntentKey(),
                pending_status == BoundedReadResult::FOUND) ||
            (pending_status == BoundedReadResult::FOUND &&
             (!IsGCIntentRecordValid(pending, m_empty_state_hash) ||
              (m_completed_gc &&
               !IsGCCheckpointAdvance(
                   m_completed_gc->checkpoint,
                   pending.target.request.checkpoint))))) {
            throw std::runtime_error{
                "corrupt payment probation GC intent"};
        }
        if (pending_status == BoundedReadResult::FOUND) {
            m_gc_intent = GCIntentState{
                pending.target.request,
                static_cast<GCPhase>(pending.phase),
                pending.retained_index,
                pending.has_cursor != 0,
                pending.cursor};
        }
    } catch (const dbwrapper_error&) {
        throw;
    } catch (const std::runtime_error&) {
        throw;
    } catch (const std::exception& exception) {
        throw std::runtime_error{
            std::string{"failed to initialize payment probation GC: "} +
            exception.what()};
    }
}

const PQPaymentProbationGCRequest*
PQPaymentProbationManager::EffectiveGCRequest() const
{
    return m_gc_intent ? &m_gc_intent->request
                       : m_completed_gc ? &*m_completed_gc : nullptr;
}

bool PQPaymentProbationManager::IsStateAllowedByGC(
    const uint256& state_hash,
    const PQPaymentProbationState& state) const
{
    if (state_hash == m_empty_state_hash) return true;
    const auto* request{EffectiveGCRequest()};
    if (request == nullptr) return true;
    if (std::binary_search(request->retained_state_hashes.begin(),
                           request->retained_state_hashes.end(),
                           state_hash)) {
        return true;
    }
    return state.cursor.has_receipt == 0 ||
           state.cursor.receipt.epoch >
               request->checkpoint.prune_through_epoch;
}

bool PQPaymentProbationManager::WriteGCBatch(CDBBatch& batch)
{
    if (m_fail_next_gc_batch_for_testing) {
        m_fail_next_gc_batch_for_testing = false;
        throw dbwrapper_error{
            "injected payment probation GC batch failure"};
    }
    return m_state_db->WriteBatch(batch, /*fSync=*/true);
}

PQPaymentProbationManager::StateViewDataPtr
PQPaymentProbationManager::BuildValidatedStateView(
    const uint256& state_hash,
    PQPaymentProbationState state) const
{
    if (state_hash.IsNull() || IsPaymentProbationMetadataKey(state_hash)) {
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
        IsPaymentProbationMetadataKey(state->state_hash) ||
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
    if (state_hash.IsNull() || IsPaymentProbationMetadataKey(state_hash)) {
        return false;
    }
    if (state_hash == m_empty_state_hash) {
        ++m_state_view_cache_hits;
        view = PQPaymentProbationStateView{m_empty_state_view};
        return true;
    }

    const auto cached{m_state_view_cache_index.find(state_hash)};
    if (cached != m_state_view_cache_index.end()) {
        if (!IsStateAllowedByGC(
                state_hash, cached->second->second->state)) {
            return false;
        }
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
    if (!actual_hash || *actual_hash != state_hash ||
        !IsStateAllowedByGC(state_hash, state)) {
        return false;
    }
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
        IsPaymentProbationMetadataKey(expected_hash) ||
        !IsStateAllowedByGC(expected_hash, state)) {
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
        transition.m_result.m_state->generation != m_state_view_generation ||
        IsPaymentProbationMetadataKey(
            transition.m_result.m_state->state_hash) ||
        !IsStateAllowedByGC(
            transition.m_result.m_state->state_hash,
            transition.m_result.m_state->state)) {
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
    return checkpoint.IsStructurallyValid() && m_completed_gc &&
           HasSameGCBoundary(
               m_completed_gc->checkpoint, checkpoint);
}

bool PQPaymentProbationManager::PruneStatesThroughCheckpoint(
    const PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes)
{
    while (true) {
        const auto progress{PruneStatesThroughCheckpointStep(
            checkpoint, retained_state_hashes)};
        if (progress.status ==
            PQPaymentProbationPruneStatus::COMPLETE) {
            return true;
        }
        if (progress.status !=
            PQPaymentProbationPruneStatus::IN_PROGRESS) {
            return false;
        }
    }
}

PQPaymentProbationPruneProgress
PQPaymentProbationManager::PruneStatesThroughCheckpointStep(
    const PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes)
{
    LOCK(m_mutex);
    PQPaymentProbationPruneProgress progress;

    if (!checkpoint.IsStructurallyValid() ||
        IsPaymentProbationMetadataKey(
            checkpoint.authenticated_probation_state_hash)) {
        return progress;
    }
    const auto normalized{NormalizeGCRequest(
        checkpoint, retained_state_hashes, m_empty_state_hash)};
    if (!normalized) return progress;
    if (m_completed_gc && HasSameGCBoundary(
            m_completed_gc->checkpoint, checkpoint)) {
        if (m_completed_gc->retained_state_hashes ==
            normalized->retained_state_hashes) {
            progress.status = PQPaymentProbationPruneStatus::COMPLETE;
        }
        return progress;
    }

    const auto make_disk_intent = [](const GCIntentState& intent) {
        return PaymentProbationGCIntentRecord{
            PAYMENT_PROBATION_GC_VERSION,
            MakeGCRecord(intent.request),
            static_cast<uint8_t>(intent.phase),
            intent.retained_index,
            static_cast<uint8_t>(intent.has_cursor),
            intent.cursor,
            PAYMENT_PROBATION_GC_INTENT_GUARD};
    };

    try {
        if (m_gc_intent) {
            if (!HasSameGCBoundary(
                    m_gc_intent->request.checkpoint, checkpoint) ||
                m_gc_intent->request.retained_state_hashes !=
                    normalized->retained_state_hashes) {
                return progress;
            }
        } else {
            if (m_completed_gc &&
                !IsGCCheckpointAdvance(
                    m_completed_gc->checkpoint, checkpoint)) {
                return progress;
            }
            if (m_state_view_generation ==
                std::numeric_limits<uint64_t>::max()) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }

            // Order every earlier state write before publishing a durable
            // logical floor. Once installed, ordinary admission prevents a
            // covered non-retained root from being recreated during GC.
            if (!m_state_db->FlushCacheToDisk(
                    /*nMaxBatchSize=*/256, /*fSync=*/true)) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }
            GCIntentState intent{
                *normalized,
                normalized->retained_state_hashes.empty()
                    ? GCPhase::VALIDATE_RECORDS
                    : GCPhase::VALIDATE_RETAINED,
                0, false, {}};
            if (intent.phase != GCPhase::VALIDATE_RETAINED) {
                intent.retained_index = static_cast<uint8_t>(
                    intent.request.retained_state_hashes.size());
            }

            const uint64_t next_generation{
                m_state_view_generation + 1};
            auto empty_view{
                std::make_shared<PQPaymentProbationStateViewData>()};
            empty_view->owner = m_view_owner;
            empty_view->generation = next_generation;
            empty_view->state_hash = m_empty_state_hash;

            CDBBatch batch{*m_state_db};
            batch.Write(PaymentProbationGCIntentKey(),
                        make_disk_intent(intent));
            if (!WriteGCBatch(batch)) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }
            m_gc_intent = std::move(intent);
            m_state_view_generation = next_generation;
            m_state_view_cache.clear();
            m_state_view_cache_index.clear();
            m_empty_state_view = std::move(empty_view);
        }

        const GCIntentState original_intent{*m_gc_intent};
        GCIntentState next_intent{original_intent};
        const PaymentProbationGCIntentRecord original_disk_intent{
            make_disk_intent(original_intent)};
        const auto can_scan = [&](std::size_t value_size) {
            return progress.scanned_records <
                       MAX_GC_SCAN_RECORDS_PER_PASS &&
                   progress.scanned_value_bytes + value_size <=
                       MAX_GC_VALUE_BYTES_PER_PASS;
        };
        const auto note_scan = [&](std::size_t value_size) {
            ++progress.scanned_records;
            progress.scanned_value_bytes += value_size;
        };
        const auto reset_cursor = [&] {
            next_intent.has_cursor = false;
            next_intent.cursor.SetNull();
        };
        const auto validate_state = [&](
            const uint256& state_hash,
            const PQPaymentProbationState& state) {
            const auto actual_hash{
                GetPQPaymentProbationStateHash(state)};
            return actual_hash && *actual_hash == state_hash &&
                   (!state_hash.IsNull()) &&
                   (!IsPaymentProbationMetadataKey(state_hash)) &&
                   (state_hash != m_empty_state_hash ||
                    state == PQPaymentProbationState{});
        };

        CDBBatch batch{*m_state_db};
        bool phase_complete{false};

        if (original_intent.phase == GCPhase::VALIDATE_RETAINED) {
            while (next_intent.retained_index <
                   next_intent.request.retained_state_hashes.size()) {
                const uint256& state_hash{
                    next_intent.request.retained_state_hashes[
                        next_intent.retained_index]};
                std::unique_ptr<CDBIterator> iterator{
                    m_state_db->NewIterator()};
                iterator->Seek(state_hash);
                if (!iterator->Valid()) {
                    iterator->CheckStatus();
                    throw InvalidPaymentProbationGCRetainedRoot{};
                }
                uint256 found;
                if (!iterator->GetKey(found) || found != state_hash) {
                    iterator->CheckStatus();
                    throw InvalidPaymentProbationGCRetainedRoot{};
                }
                const std::size_t value_size{iterator->GetValueSize()};
                if (!iterator->GetKeyExact(found) ||
                    value_size >
                        PAYMENT_PROBATION_STATE_MAX_WIRE_SIZE) {
                    throw CorruptPaymentProbationGC{};
                }
                if (!can_scan(value_size)) break;
                ExactPaymentProbationStateValue value;
                if (!iterator->GetValueExact(value) ||
                    !validate_state(state_hash, value.state)) {
                    throw CorruptPaymentProbationGC{};
                }
                iterator->CheckStatus();
                note_scan(value_size);
                ++next_intent.retained_index;
            }
            if (next_intent.retained_index ==
                next_intent.request.retained_state_hashes.size()) {
                next_intent.phase = GCPhase::VALIDATE_RECORDS;
                reset_cursor();
            }
        } else {
            const bool erasing{
                original_intent.phase == GCPhase::ERASE_RECORDS};
            std::unique_ptr<CDBIterator> iterator{
                m_state_db->NewIterator()};
            if (original_intent.has_cursor) {
                iterator->Seek(original_intent.cursor);
            } else {
                iterator->SeekToFirst();
            }

            while (iterator->Valid()) {
                uint256 state_hash;
                if (!iterator->GetKey(state_hash) ||
                    state_hash.IsNull()) {
                    throw CorruptPaymentProbationGC{};
                }
                const std::size_t value_size{iterator->GetValueSize()};
                const std::size_t maximum_value_size{
                    state_hash == PaymentProbationGCKey()
                        ? PaymentProbationGCRecord::MAX_WIRE_SIZE
                        : state_hash == PaymentProbationGCIntentKey()
                            ? PAYMENT_PROBATION_GC_INTENT_MAX_WIRE_SIZE
                            : PAYMENT_PROBATION_STATE_MAX_WIRE_SIZE};
                ExactPaymentProbationStateKey exact_key;
                if (!iterator->GetKey(exact_key) ||
                    exact_key.hash != state_hash ||
                    value_size > maximum_value_size) {
                    throw CorruptPaymentProbationGC{};
                }
                if (!can_scan(value_size) ||
                    (erasing && progress.erased_records >=
                                     MAX_GC_ERASE_RECORDS_PER_PASS)) {
                    next_intent.has_cursor = true;
                    next_intent.cursor = state_hash;
                    break;
                }

                bool erase{false};
                if (state_hash == PaymentProbationGCKey()) {
                    PaymentProbationGCRecord record;
                    if (!iterator->GetValueExact(record) ||
                        !m_completed_gc ||
                        !IsGCRecordValid(record, m_empty_state_hash) ||
                        record.request != *m_completed_gc) {
                        throw CorruptPaymentProbationGC{};
                    }
                } else if (state_hash ==
                           PaymentProbationGCIntentKey()) {
                    PaymentProbationGCIntentRecord record;
                    if (!iterator->GetValueExact(record) ||
                        !IsGCIntentRecordValid(
                            record, m_empty_state_hash) ||
                        record.version != original_disk_intent.version ||
                        record.target.request !=
                            original_disk_intent.target.request ||
                        record.target.version !=
                            original_disk_intent.target.version ||
                        record.target.guard !=
                            original_disk_intent.target.guard ||
                        record.phase != original_disk_intent.phase ||
                        record.retained_index !=
                            original_disk_intent.retained_index ||
                        record.has_cursor !=
                            original_disk_intent.has_cursor ||
                        record.cursor != original_disk_intent.cursor ||
                        record.guard != original_disk_intent.guard) {
                        throw CorruptPaymentProbationGC{};
                    }
                } else {
                    ExactPaymentProbationStateValue value;
                    if (!iterator->GetValueExact(value) ||
                        !validate_state(state_hash, value.state)) {
                        throw CorruptPaymentProbationGC{};
                    }
                    erase = erasing &&
                        !IsStateAllowedByGC(state_hash, value.state);
                }

                note_scan(value_size);
                if (erase) {
                    batch.Erase(state_hash);
                    ++progress.erased_records;
                }
                iterator->Next();
            }
            iterator->CheckStatus();
            if (!iterator->Valid()) phase_complete = true;
            if (phase_complete && !erasing) {
                next_intent.phase = GCPhase::ERASE_RECORDS;
                reset_cursor();
            }
        }

        if (original_intent.phase == GCPhase::ERASE_RECORDS &&
            phase_complete) {
            batch.Write(PaymentProbationGCKey(),
                        MakeGCRecord(original_intent.request));
            batch.Erase(PaymentProbationGCIntentKey());
            if (!WriteGCBatch(batch)) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }
            m_completed_gc = original_intent.request;
            m_gc_intent.reset();
            progress.status = PQPaymentProbationPruneStatus::COMPLETE;
            return progress;
        }

        batch.Write(PaymentProbationGCIntentKey(),
                    make_disk_intent(next_intent));
        if (!WriteGCBatch(batch)) {
            progress.status =
                PQPaymentProbationPruneStatus::DATABASE_ERROR;
            return progress;
        }
        m_gc_intent = std::move(next_intent);
        progress.status = PQPaymentProbationPruneStatus::IN_PROGRESS;
        return progress;
    } catch (const InvalidPaymentProbationGCRetainedRoot&) {
        if (m_gc_intent &&
            m_gc_intent->phase != GCPhase::ERASE_RECORDS) {
            try {
                CDBBatch batch{*m_state_db};
                batch.Erase(PaymentProbationGCIntentKey());
                if (!WriteGCBatch(batch)) {
                    progress.status =
                        PQPaymentProbationPruneStatus::DATABASE_ERROR;
                    return progress;
                }
                m_gc_intent.reset();
            } catch (const std::exception&) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }
        }
        progress.status = PQPaymentProbationPruneStatus::INVALID;
        return progress;
    } catch (const CorruptPaymentProbationGC&) {
        if (m_gc_intent &&
            m_gc_intent->phase != GCPhase::ERASE_RECORDS) {
            try {
                CDBBatch batch{*m_state_db};
                batch.Erase(PaymentProbationGCIntentKey());
                if (!WriteGCBatch(batch)) {
                    progress.status =
                        PQPaymentProbationPruneStatus::DATABASE_ERROR;
                    return progress;
                }
                m_gc_intent.reset();
            } catch (const std::exception&) {
                progress.status =
                    PQPaymentProbationPruneStatus::DATABASE_ERROR;
                return progress;
            }
        }
        progress.status = PQPaymentProbationPruneStatus::CORRUPT;
        return progress;
    } catch (const std::exception& exception) {
        LogPrintf("%s -- payment probation GC database failure: %s\n",
                  __func__, exception.what());
        progress.status =
            PQPaymentProbationPruneStatus::DATABASE_ERROR;
        return progress;
    }
}

std::optional<PQPaymentProbationGCRequest>
PQPaymentProbationManager::GetPendingGCRequest() const
{
    LOCK(m_mutex);
    return m_gc_intent
        ? std::optional<PQPaymentProbationGCRequest>{m_gc_intent->request}
        : std::nullopt;
}

} // namespace llmq::pq
