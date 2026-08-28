// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation.h>
#include <evo/pq_payment_probation_db.h>

#include <hash.h>
#include <span.h>

#include <algorithm>

namespace llmq::pq {
namespace {

void SetError(PQPaymentProbationError* error,
              PQPaymentProbationError value) noexcept
{
    if (error != nullptr) *error = value;
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member) noexcept
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

std::size_t BitmapCount(const QuorumBitmap& bitmap) noexcept
{
    std::size_t count{0};
    for (const uint8_t byte : bitmap) {
        uint8_t value{byte};
        while (value != 0) {
            value &= static_cast<uint8_t>(value - 1);
            ++count;
        }
    }
    return count;
}

bool IsStrictlySortedUnique(std::span<const uint256> values) noexcept
{
    if (values.size() > MAX_PQ_PAYMENT_PROBATION_ENTRIES) return false;
    for (std::size_t index{0}; index < values.size(); ++index) {
        if (values[index].IsNull() ||
            (index != 0 && !(values[index - 1] < values[index]))) {
            return false;
        }
    }
    return true;
}

bool IsValidMissCount(uint8_t misses) noexcept
{
    return misses <= PQ_PAYMENT_PROBATION_MAX_MISSES;
}

bool IsValidEligibilityHeight(int32_t height) noexcept
{
    return height >= -1;
}

template <typename Records>
auto FindEntry(Records& entries, const uint256& pro_tx_hash)
{
    return std::lower_bound(
        entries.begin(), entries.end(), pro_tx_hash,
        [](const PQPaymentProbationEntry& entry, const uint256& sought) {
            return entry.pro_tx_hash < sought;
        });
}

PQPaymentProbationError ValidateTransitionRosterContext(
    const PQPaymentProbationTransitionContext& context) noexcept
{
    if (BitmapCount(context.roster_valid_members) < QUORUM_MIN_VALID) {
        return PQPaymentProbationError::INVALID_BITMAP;
    }
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        if (context.frozen_roster[member].IsNull()) {
            return PQPaymentProbationError::INVALID_ROSTER;
        }
        if (IsBitSet(context.observed_members, member) &&
            !IsBitSet(context.roster_valid_members, member)) {
            return PQPaymentProbationError::INVALID_BITMAP;
        }
    }
    auto sorted_roster{context.frozen_roster};
    std::sort(sorted_roster.begin(), sorted_roster.end());
    if (std::adjacent_find(sorted_roster.begin(), sorted_roster.end()) !=
        sorted_roster.end()) {
        return PQPaymentProbationError::INVALID_ROSTER;
    }
    return PQPaymentProbationError::NONE;
}

PQPaymentProbationError ValidateTransitionContext(
    const PQPaymentProbationTransitionContext& context) noexcept
{
    if (!context.receipt.IsStructurallyValid()) {
        return PQPaymentProbationError::INVALID_RECEIPT;
    }
    return ValidateTransitionRosterContext(context);
}

PQPaymentProbationError ValidateTransitionInput(
    const PQPaymentProbationTransitionInput& input) noexcept
{
    // Preserve the compatibility API's historical error precedence even
    // though the semantic context can now be validated independently.
    if (!input.receipt.IsStructurallyValid()) {
        return PQPaymentProbationError::INVALID_RECEIPT;
    }
    if (!IsStrictlySortedUnique(input.existing_pro_tx_hashes)) {
        return PQPaymentProbationError::INVALID_COLLATERAL_SET;
    }
    if (!IsStrictlySortedUnique(input.current_valid_pro_tx_hashes) ||
        !std::includes(input.existing_pro_tx_hashes.begin(),
                       input.existing_pro_tx_hashes.end(),
                       input.current_valid_pro_tx_hashes.begin(),
                       input.current_valid_pro_tx_hashes.end())) {
        return PQPaymentProbationError::INVALID_CURRENT_VALID_SET;
    }
    return ValidateTransitionRosterContext(input);
}

/** Sorted vectors retain the exact compatibility semantics at the public API. */
class SortedVectorMembershipLookup final
{
public:
    explicit SortedVectorMembershipLookup(
        const PQPaymentProbationTransitionInput& input)
        : m_existing{input.existing_pro_tx_hashes},
          m_current_valid{input.current_valid_pro_tx_hashes}
    {
    }

    [[nodiscard]] PQPaymentProbationMembership Lookup(
        const uint256& pro_tx_hash) const noexcept
    {
        if (!std::binary_search(
                m_existing.begin(), m_existing.end(), pro_tx_hash)) {
            return PQPaymentProbationMembership::ABSENT;
        }
        return std::binary_search(
                   m_current_valid.begin(), m_current_valid.end(), pro_tx_hash)
            ? PQPaymentProbationMembership::PRESENT_VALID
            : PQPaymentProbationMembership::PRESENT_INVALID;
    }

private:
    std::span<const uint256> m_existing;
    std::span<const uint256> m_current_valid;
};

std::vector<PQPaymentProbationChange> BuildChanges(
    std::span<const PQPaymentProbationEntry> before,
    std::span<const PQPaymentProbationEntry> after)
{
    std::vector<PQPaymentProbationChange> changes;
    changes.reserve(before.size() + after.size());
    std::size_t old_index{0};
    std::size_t new_index{0};
    while (old_index < before.size() || new_index < after.size()) {
        if (new_index == after.size() ||
            (old_index < before.size() &&
             before[old_index].pro_tx_hash < after[new_index].pro_tx_hash)) {
            changes.push_back({before[old_index].pro_tx_hash,
                               before[old_index].consecutive_misses, 0,
                               before[old_index]
                                   .payment_eligible_since_height,
                               -1});
            ++old_index;
        } else if (old_index == before.size() ||
                   after[new_index].pro_tx_hash <
                       before[old_index].pro_tx_hash) {
            changes.push_back({
                after[new_index].pro_tx_hash, 0,
                after[new_index].consecutive_misses, -1,
                after[new_index].payment_eligible_since_height});
            ++new_index;
        } else {
            if (before[old_index].consecutive_misses !=
                    after[new_index].consecutive_misses ||
                before[old_index].payment_eligible_since_height !=
                    after[new_index].payment_eligible_since_height) {
                changes.push_back({
                    before[old_index].pro_tx_hash,
                    before[old_index].consecutive_misses,
                    after[new_index].consecutive_misses,
                    before[old_index].payment_eligible_since_height,
                    after[new_index].payment_eligible_since_height});
            }
            ++old_index;
            ++new_index;
        }
    }
    return changes;
}

} // namespace

bool PQPaymentAuditReceiptIdentity::IsStructurallyValid() const noexcept
{
    return carrier_height >= 0 && !receipt_id.IsNull();
}

bool PQPaymentProbationCursor::IsStructurallyValid() const noexcept
{
    if (has_receipt == 0) {
        return receipt.epoch == 0 && receipt.carrier_height == -1 &&
               receipt.receipt_id.IsNull();
    }
    return has_receipt == 1 && receipt.IsStructurallyValid();
}

bool PQPaymentProbationEntry::IsStructurallyValid() const noexcept
{
    return !pro_tx_hash.IsNull() &&
           IsValidMissCount(consecutive_misses) &&
           IsValidEligibilityHeight(payment_eligible_since_height) &&
           (consecutive_misses != 0 ||
            payment_eligible_since_height != -1);
}

bool PQPaymentProbationState::IsStructurallyValid() const noexcept
{
    if (version != PQ_PAYMENT_PROBATION_STATE_VERSION ||
        !cursor.IsStructurallyValid() ||
        entries.size() > MAX_PQ_PAYMENT_PROBATION_ENTRIES) {
        return false;
    }
    for (std::size_t index{0}; index < entries.size(); ++index) {
        if (!entries[index].IsStructurallyValid() ||
            (index != 0 && !(entries[index - 1].pro_tx_hash <
                             entries[index].pro_tx_hash))) {
            return false;
        }
    }
    return true;
}

uint8_t PQPaymentProbationState::MissCount(
    const uint256& pro_tx_hash) const noexcept
{
    const auto position{FindEntry(entries, pro_tx_hash)};
    return position != entries.end() && position->pro_tx_hash == pro_tx_hash
               ? position->consecutive_misses
               : 0;
}

bool PQPaymentProbationState::IsPaymentWithheld(
    const uint256& pro_tx_hash) const noexcept
{
    return MissCount(pro_tx_hash) == PQ_PAYMENT_PROBATION_MAX_MISSES;
}

int32_t PQPaymentProbationState::PaymentEligibleSinceHeight(
    const uint256& pro_tx_hash) const noexcept
{
    const auto position{FindEntry(entries, pro_tx_hash)};
    return position != entries.end() && position->pro_tx_hash == pro_tx_hash
               ? position->payment_eligible_since_height
               : -1;
}

bool PQPaymentProbationChange::IsStructurallyValid() const noexcept
{
    return !pro_tx_hash.IsNull() && IsValidMissCount(before_misses) &&
           IsValidMissCount(after_misses) &&
           IsValidEligibilityHeight(before_payment_eligible_since_height) &&
           IsValidEligibilityHeight(after_payment_eligible_since_height) &&
           (before_misses != after_misses ||
            before_payment_eligible_since_height !=
                after_payment_eligible_since_height);
}

bool PQPaymentProbationDiff::IsStructurallyValid() const noexcept
{
    if (version != PQ_PAYMENT_PROBATION_DIFF_VERSION ||
        !previous_cursor.IsStructurallyValid() ||
        !applied_receipt.IsStructurallyValid() ||
        previous_state_hash.IsNull() || applied_state_hash.IsNull() ||
        changes.size() > MAX_PQ_PAYMENT_PROBATION_CHANGES ||
        (previous_cursor.has_receipt != 0 &&
         (applied_receipt.epoch <= previous_cursor.receipt.epoch ||
          applied_receipt.carrier_height <=
              previous_cursor.receipt.carrier_height))) {
        return false;
    }
    for (std::size_t index{0}; index < changes.size(); ++index) {
        if (!changes[index].IsStructurallyValid() ||
            (index != 0 && !(changes[index - 1].pro_tx_hash <
                             changes[index].pro_tx_hash))) {
            return false;
        }
    }
    return true;
}

std::optional<uint256> GetPQPaymentProbationStateHash(
    const PQPaymentProbationState& state)
{
    try {
        CHashWriter writer{SER_GETHASH, 0};
        writer.write(AsBytes(Span{
            PQ_PAYMENT_PROBATION_STATE_HASH_DOMAIN.data(),
            PQ_PAYMENT_PROBATION_STATE_HASH_DOMAIN.size()}));
        // Serialization owns the canonical structural gate. Rechecking it
        // here would scan the potentially maximal sparse state twice.
        writer << state;
        const uint256 hash{writer.GetHash()};
        return hash.IsNull() ? std::nullopt : std::optional<uint256>{hash};
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

bool PQPaymentProbationTransitionContext::IsStructurallyValid() const noexcept
{
    return ValidationError() == PQPaymentProbationError::NONE;
}

PQPaymentProbationError
PQPaymentProbationTransitionContext::ValidationError() const noexcept
{
    return ValidateTransitionContext(*this);
}

bool PQPaymentProbationTransitionInput::IsStructurallyValid() const noexcept
{
    return ValidateTransitionInput(*this) == PQPaymentProbationError::NONE;
}

template <typename MembershipLookup>
static std::optional<PQPaymentProbationTransitionResult>
ApplyPQPaymentProbationTransitionImpl(
    const PQPaymentProbationState& previous,
    const std::optional<uint256>& authenticated_previous_hash,
    const PQPaymentProbationTransitionContext& context,
    const MembershipLookup& membership,
    PQPaymentProbationError input_error,
    bool compact_result,
    PQPaymentProbationError* error)
{
    SetError(error, PQPaymentProbationError::NONE);
    if (!authenticated_previous_hash && !previous.IsStructurallyValid()) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    if (input_error != PQPaymentProbationError::NONE) {
        SetError(error, input_error);
        return std::nullopt;
    }
    if (previous.cursor.has_receipt != 0) {
        if (context.receipt.epoch == previous.cursor.receipt.epoch) {
            SetError(error,
                     context.receipt == previous.cursor.receipt
                         ? PQPaymentProbationError::DUPLICATE_RECEIPT
                         : PQPaymentProbationError::CONFLICTING_RECEIPT);
            return std::nullopt;
        }
        if (context.receipt.epoch < previous.cursor.receipt.epoch ||
            context.receipt.carrier_height <=
                previous.cursor.receipt.carrier_height) {
            SetError(error, PQPaymentProbationError::OUT_OF_ORDER_RECEIPT);
            return std::nullopt;
        }
    }

    PQPaymentProbationTransitionResult result;
    result.state.version = previous.version;
    result.undo.previous_cursor = previous.cursor;
    result.undo.applied_receipt = context.receipt;
    const auto previous_state_hash{authenticated_previous_hash
        ? authenticated_previous_hash
        : GetPQPaymentProbationStateHash(previous)};
    if (!previous_state_hash) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    result.undo.previous_state_hash = *previous_state_hash;

    // Roster order is intentionally unrelated to the canonical state order.
    // Sort the bounded update set once so applying it never repeatedly moves
    // the potentially maximal sparse state vector under the chainstate lock.
    struct RosterTransition {
        uint256 pro_tx_hash;
        bool observed{false};
        bool exists{false};
        bool current_valid{false};
    };
    std::vector<RosterTransition> roster_transitions;
    roster_transitions.reserve(QUORUM_SIZE);
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        if (!IsBitSet(context.roster_valid_members, member)) continue;
        const auto& pro_tx_hash{context.frozen_roster[member]};
        const auto membership_status{membership.Lookup(pro_tx_hash)};
        if (membership_status != PQPaymentProbationMembership::ABSENT &&
            membership_status !=
                PQPaymentProbationMembership::PRESENT_INVALID &&
            membership_status != PQPaymentProbationMembership::PRESENT_VALID) {
            SetError(error, PQPaymentProbationError::INVALID_RESULT);
            return std::nullopt;
        }
        roster_transitions.push_back({pro_tx_hash,
                                      IsBitSet(context.observed_members, member),
                                      membership_status !=
                                          PQPaymentProbationMembership::ABSENT,
                                      membership_status ==
                                          PQPaymentProbationMembership::PRESENT_VALID});
    }
    std::sort(roster_transitions.begin(), roster_transitions.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    for (const auto& transition : roster_transitions) {
        if (transition.observed && transition.current_valid) {
            ++result.effective_observed_count;
        }
    }

    result.conclusive = result.effective_observed_count >=
                        PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS;

    std::vector<PQPaymentProbationEntry> surviving_entries;
    surviving_entries.reserve(previous.entries.size());
    for (const auto& entry : previous.entries) {
        const auto membership_status{membership.Lookup(entry.pro_tx_hash)};
        if (membership_status != PQPaymentProbationMembership::ABSENT &&
            membership_status !=
                PQPaymentProbationMembership::PRESENT_INVALID &&
            membership_status != PQPaymentProbationMembership::PRESENT_VALID) {
            SetError(error, PQPaymentProbationError::INVALID_RESULT);
            return std::nullopt;
        }
        if (membership_status == PQPaymentProbationMembership::ABSENT) {
            if (!compact_result) {
                result.pruned_pro_tx_hashes.push_back(entry.pro_tx_hash);
            }
        } else {
            surviving_entries.push_back(entry);
        }
    }

    result.state.entries.reserve(
        surviving_entries.size() + roster_transitions.size());
    std::size_t entry_index{0};
    std::size_t transition_index{0};
    const auto emit = [&](const PQPaymentProbationEntry& entry) {
        if (entry.consecutive_misses != 0 ||
            entry.payment_eligible_since_height != -1) {
            result.state.entries.push_back(entry);
        }
    };
    while (entry_index < surviving_entries.size() ||
           transition_index < roster_transitions.size()) {
        if (transition_index == roster_transitions.size() ||
            (entry_index < surviving_entries.size() &&
             surviving_entries[entry_index].pro_tx_hash <
                 roster_transitions[transition_index].pro_tx_hash)) {
            result.state.entries.push_back(
                surviving_entries[entry_index++]);
            continue;
        }

        const auto& transition{roster_transitions[transition_index++]};
        PQPaymentProbationEntry entry{
            transition.pro_tx_hash, 0, -1};
        if (entry_index < surviving_entries.size() &&
            surviving_entries[entry_index].pro_tx_hash ==
                transition.pro_tx_hash) {
            entry = surviving_entries[entry_index++];
        }

        if (transition.observed && transition.exists) {
            if (entry.consecutive_misses ==
                PQ_PAYMENT_PROBATION_MAX_MISSES) {
                if (!compact_result) {
                    result.recovered_pro_tx_hashes.push_back(
                        transition.pro_tx_hash);
                }
            }
            if (entry.consecutive_misses != 0) {
                entry.payment_eligible_since_height =
                    entry.consecutive_misses ==
                            PQ_PAYMENT_PROBATION_MAX_MISSES
                        ? context.receipt.carrier_height
                        : entry.payment_eligible_since_height;
                entry.consecutive_misses = 0;
            }
        } else if (result.conclusive && !transition.observed &&
                   transition.current_valid) {
            entry.consecutive_misses = std::min<uint8_t>(
                PQ_PAYMENT_PROBATION_MAX_MISSES,
                static_cast<uint8_t>(entry.consecutive_misses + 1));
        }
        emit(entry);
    }

    result.state.cursor = PQPaymentProbationCursor{1, context.receipt};
    if (!compact_result) {
        result.undo.changes = BuildChanges(
            previous.entries, result.state.entries);
    }
    const auto applied_state_hash{
        GetPQPaymentProbationStateHash(result.state)};
    if (!applied_state_hash) {
        SetError(error, PQPaymentProbationError::INVALID_RESULT);
        return std::nullopt;
    }
    result.undo.applied_state_hash = *applied_state_hash;
    if ((!compact_result && !result.undo.IsStructurallyValid()) ||
        result.undo.previous_state_hash.IsNull() ||
        result.undo.applied_state_hash.IsNull() ||
        !result.undo.applied_receipt.IsStructurallyValid()) {
        SetError(error, PQPaymentProbationError::INVALID_RESULT);
        return std::nullopt;
    }
    return result;
}

std::optional<PQPaymentProbationTransitionResult>
ApplyPQPaymentProbationTransition(
    const PQPaymentProbationState& previous,
    const PQPaymentProbationTransitionInput& input,
    PQPaymentProbationError* error)
{
    const SortedVectorMembershipLookup membership{input};
    return ApplyPQPaymentProbationTransitionImpl(
        previous, std::nullopt, input, membership,
        ValidateTransitionInput(input),
        /*compact_result=*/false, error);
}

std::optional<PQPaymentProbationManager::CompactTransitionResult>
PQPaymentProbationManager::ApplyCompactTransition(
    const PQPaymentProbationStateView& previous,
    const PQPaymentProbationTransitionInput& input,
    PQPaymentProbationError* error)
{
    if (!previous.IsValid() || previous.State() == nullptr ||
        previous.StateHash().IsNull()) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    const SortedVectorMembershipLookup membership{input};
    auto result{ApplyPQPaymentProbationTransitionImpl(
        *previous.State(), previous.StateHash(), input, membership,
        ValidateTransitionInput(input),
        /*compact_result=*/true, error)};
    if (!result) return std::nullopt;
    return CompactTransitionResult{
        std::move(result->state), result->undo.previous_state_hash,
        result->undo.applied_receipt, result->undo.applied_state_hash};
}

std::optional<PQPaymentProbationManager::CompactTransitionResult>
PQPaymentProbationManager::ApplyCompactTransition(
    const PQPaymentProbationStateView& previous,
    const PQPaymentProbationTransitionContext& context,
    const MembershipResolver& membership_resolver,
    PQPaymentProbationError* error)
{
    if (!previous.IsValid() || previous.State() == nullptr ||
        previous.StateHash().IsNull() || !membership_resolver) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    struct ResolverLookup final {
        const MembershipResolver& resolver;

        [[nodiscard]] PQPaymentProbationMembership Lookup(
            const uint256& pro_tx_hash) const
        {
            return resolver(pro_tx_hash);
        }
    } membership{membership_resolver};
    auto result{ApplyPQPaymentProbationTransitionImpl(
        *previous.State(), previous.StateHash(), context, membership,
        ValidateTransitionContext(context), /*compact_result=*/true, error)};
    if (!result) return std::nullopt;
    return CompactTransitionResult{
        std::move(result->state), result->undo.previous_state_hash,
        result->undo.applied_receipt, result->undo.applied_state_hash};
}

std::optional<PQPaymentProbationState>
UndoPQPaymentProbationTransition(
    const PQPaymentProbationState& current,
    const PQPaymentProbationDiff& undo,
    PQPaymentProbationError* error)
{
    SetError(error, PQPaymentProbationError::NONE);
    if (!current.IsStructurallyValid()) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    if (!undo.IsStructurallyValid()) {
        SetError(error, PQPaymentProbationError::INVALID_DIFF);
        return std::nullopt;
    }
    if (current.cursor.has_receipt == 0 ||
        current.cursor.receipt != undo.applied_receipt) {
        SetError(error, PQPaymentProbationError::UNDO_MISMATCH);
        return std::nullopt;
    }
    const auto current_state_hash{GetPQPaymentProbationStateHash(current)};
    if (!current_state_hash || *current_state_hash != undo.applied_state_hash) {
        SetError(error, PQPaymentProbationError::UNDO_MISMATCH);
        return std::nullopt;
    }
    // Merge the two sorted sequences once. Replaying a maximal reorg diff
    // with repeated vector insertion would otherwise be quadratic under the
    // chainstate lock.
    PQPaymentProbationState previous;
    previous.entries.reserve(std::min<std::size_t>(
        MAX_PQ_PAYMENT_PROBATION_ENTRIES,
        current.entries.size() + undo.changes.size()));
    std::size_t current_index{0};
    std::size_t change_index{0};
    const auto is_empty = [](uint8_t misses, int32_t eligible_height) {
        return misses == 0 && eligible_height == -1;
    };
    const auto emit_before = [&](const PQPaymentProbationChange& change) {
        if (!is_empty(change.before_misses,
                      change.before_payment_eligible_since_height)) {
            previous.entries.push_back({
                change.pro_tx_hash, change.before_misses,
                change.before_payment_eligible_since_height});
        }
    };
    while (current_index < current.entries.size() ||
           change_index < undo.changes.size()) {
        if (change_index == undo.changes.size() ||
            (current_index < current.entries.size() &&
             current.entries[current_index].pro_tx_hash <
                 undo.changes[change_index].pro_tx_hash)) {
            previous.entries.push_back(current.entries[current_index++]);
            continue;
        }
        const auto& change{undo.changes[change_index++]};
        if (current_index == current.entries.size() ||
            change.pro_tx_hash <
                current.entries[current_index].pro_tx_hash) {
            if (!is_empty(change.after_misses,
                          change.after_payment_eligible_since_height)) {
                SetError(error, PQPaymentProbationError::UNDO_MISMATCH);
                return std::nullopt;
            }
            emit_before(change);
            continue;
        }
        const auto& entry{current.entries[current_index++]};
        if (entry.pro_tx_hash != change.pro_tx_hash ||
            entry.consecutive_misses != change.after_misses ||
            entry.payment_eligible_since_height !=
                change.after_payment_eligible_since_height) {
            SetError(error, PQPaymentProbationError::UNDO_MISMATCH);
            return std::nullopt;
        }
        emit_before(change);
    }
    previous.cursor = undo.previous_cursor;
    const auto previous_state_hash{GetPQPaymentProbationStateHash(previous)};
    if (!previous_state_hash ||
        *previous_state_hash != undo.previous_state_hash) {
        SetError(error, PQPaymentProbationError::UNDO_MISMATCH);
        return std::nullopt;
    }
    return previous;
}

std::optional<PQPaymentPayeeSelection>
SelectPQPaymentPayee(
    const PQPaymentProbationState& state,
    std::span<const uint256> ordinary_payment_queue,
    PQPaymentProbationError* error)
{
    SetError(error, PQPaymentProbationError::NONE);
    if (!state.IsStructurallyValid()) {
        SetError(error, PQPaymentProbationError::INVALID_STATE);
        return std::nullopt;
    }
    if (ordinary_payment_queue.size() >
        MAX_PQ_PAYMENT_PROBATION_ENTRIES) {
        SetError(error, PQPaymentProbationError::INVALID_PAYMENT_QUEUE);
        return std::nullopt;
    }
    std::vector<uint256> uniqueness_check;
    uniqueness_check.reserve(ordinary_payment_queue.size());
    for (const auto& pro_tx_hash : ordinary_payment_queue) {
        if (pro_tx_hash.IsNull()) {
            SetError(error, PQPaymentProbationError::INVALID_PAYMENT_QUEUE);
            return std::nullopt;
        }
        uniqueness_check.push_back(pro_tx_hash);
    }
    std::sort(uniqueness_check.begin(), uniqueness_check.end());
    if (std::adjacent_find(uniqueness_check.begin(), uniqueness_check.end()) !=
        uniqueness_check.end()) {
        SetError(error, PQPaymentProbationError::INVALID_PAYMENT_QUEUE);
        return std::nullopt;
    }

    if (ordinary_payment_queue.empty()) {
        return PQPaymentPayeeSelection{};
    }
    for (const auto& pro_tx_hash : ordinary_payment_queue) {
        if (!state.IsPaymentWithheld(pro_tx_hash)) {
            return PQPaymentPayeeSelection{pro_tx_hash, false};
        }
    }
    return PQPaymentPayeeSelection{ordinary_payment_queue.front(), true};
}

} // namespace llmq::pq
