// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_roster_beacon.h>

#include <hash.h>
#include <span.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace llmq::pq {
namespace {

inline constexpr std::string_view PQ_QUORUM_MODIFIER_DOMAIN{
    "SYS_PQ_QUORUM_MODIFIER_V1"};

void WriteDomain(CHashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

bool IsKnownTransitionKind(
    RosterAuthorizationTransitionKind kind) noexcept
{
    return kind == RosterAuthorizationTransitionKind::INITIALIZE ||
           kind == RosterAuthorizationTransitionKind::KEEP ||
           kind == RosterAuthorizationTransitionKind::OBSERVE ||
           kind == RosterAuthorizationTransitionKind::REVEAL ||
           kind == RosterAuthorizationTransitionKind::ROTATE ||
           kind == RosterAuthorizationTransitionKind::RECOVER;
}

bool IsExactCandidateBoundary(
    const NormalRosterAuthorizationInput& input) noexcept
{
    if (input.target_height < 0 || input.target_block_hash.IsNull() ||
        input.predecessor_height < 0 ||
        input.predecessor_height >= input.target_height ||
        input.predecessor_block_hash.IsNull() ||
        input.predecessor_block_hash == input.target_block_hash ||
        !input.authorization_base.IsStructurallyValid() ||
        input.authorization_base.IsNull() ||
        input.authorization_base.height > input.predecessor_height ||
        (input.authorization_base.height == input.predecessor_height &&
         input.authorization_base.block_hash !=
             input.predecessor_block_hash) ||
        !input.previous.IsStructurallyValid() ||
        !input.previous_btcc_cursor.IsStructurallyValid() ||
        !input.accepted_btcc_cursor.IsStructurallyValid() ||
        !input.recovery_authority_source.IsStructurallyValid() ||
        input.recovery_authority_source.IsNull() ||
        input.recovery_authority_hash.IsNull() ||
        (!input.previous_btcc_cursor.IsNull() &&
         input.previous_btcc_cursor.sys_height >
             input.predecessor_height)) {
        return false;
    }
    if (input.btcc_advance == BTCCAdvance::KEEP) {
        return input.accepted_btcc_cursor == input.previous_btcc_cursor;
    }
    if (input.btcc_advance != BTCCAdvance::ADVANCE ||
        input.accepted_btcc_cursor.IsNull() ||
        input.accepted_btcc_cursor.sys_height != input.target_height ||
        input.accepted_btcc_cursor.sys_hash != input.target_block_hash) {
        return false;
    }
    return input.previous_btcc_cursor.IsNull() ||
           input.accepted_btcc_cursor.sys_height >
               input.previous_btcc_cursor.sys_height;
}

bool IsExactNextSnapshotCoverage(
    const NormalRosterAuthorizationInput& input) noexcept
{
    if (input.newest_epoch == std::numeric_limits<uint32_t>::max() ||
        input.next_snapshot.epoch != input.newest_epoch + 1 ||
        input.next_snapshot.height < 0) {
        return false;
    }
    const bool covered_by_height{
        input.authorization_base.height >= input.next_snapshot.height};
    if (input.next_snapshot.prior_authorization_is_descendant !=
            covered_by_height ||
        covered_by_height != !input.next_snapshot.hash.IsNull()) {
        return false;
    }
    return !covered_by_height ||
           input.next_snapshot.height != input.authorization_base.height ||
           input.next_snapshot.hash ==
               input.authorization_base.block_hash;
}

bool IsUsableObservationAnchor(
    const ValidatedRosterBeaconAnchor& anchor,
    const BTCCursor& accepted_cursor) noexcept
{
    if (!anchor.is_active || anchor.cursor != accepted_cursor ||
        !anchor.cursor.IsStructurallyValid() || anchor.cursor.IsNull() ||
        anchor.btc_height < 0 ||
        anchor.active_tip_height < anchor.btc_height) {
        return false;
    }
    return static_cast<int64_t>(anchor.active_tip_height) -
               anchor.btc_height <=
           ROSTER_BEACON_MAX_ANCHOR_BTC_LAG;
}

std::optional<RosterBeaconSeed> MakeObservedSeed(
    const RosterBeaconSeed& empty,
    const ValidatedRosterBeaconAnchor& anchor,
    const BTCCursor& accepted_cursor) noexcept
{
    if (empty.state != RosterBeaconState::EMPTY ||
        !IsUsableObservationAnchor(anchor, accepted_cursor)) {
        return std::nullopt;
    }
    RosterBeaconSeed pending{empty};
    pending.state = RosterBeaconState::PENDING;
    pending.anchor_cursor = accepted_cursor;
    pending.anchor_btc_height = anchor.btc_height;
    return IsExactRosterBeaconObservation(empty, pending)
               ? std::optional<RosterBeaconSeed>{pending}
               : std::nullopt;
}

std::optional<RosterBeaconSeed> MakeRevealedSeed(
    const RosterBeaconSeed& pending,
    const ValidatedRosterBeaconRange& range) noexcept
{
    const auto future_height{pending.FutureBTCHeight()};
    if (pending.state != RosterBeaconState::PENDING || !future_height ||
        !range.is_active || range.anchor_hash.IsNull() ||
        range.future_hash.IsNull() ||
        range.anchor_hash != pending.anchor_cursor.btc_hash ||
        range.anchor_height != pending.anchor_btc_height ||
        range.future_height != *future_height ||
        range.active_tip_height < range.future_height ||
        static_cast<int64_t>(range.active_tip_height) -
                    range.future_height +
                1 <
            ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS) {
        return std::nullopt;
    }
    RosterBeaconSeed ready{pending};
    ready.state = RosterBeaconState::READY;
    ready.future_btc_hash = range.future_hash;
    return IsExactRosterBeaconReveal(pending, ready)
               ? std::optional<RosterBeaconSeed>{ready}
               : std::nullopt;
}

bool IsStillActiveReadySeed(
    const RosterBeaconSeed& ready,
    const ValidatedRosterBeaconRange& range) noexcept
{
    const auto future_height{ready.FutureBTCHeight()};
    return ready.IsReady() && future_height && range.is_active &&
           range.anchor_hash == ready.anchor_cursor.btc_hash &&
           range.anchor_height == ready.anchor_btc_height &&
           range.future_hash == ready.future_btc_hash &&
           range.future_height == *future_height &&
           range.active_tip_height >= range.future_height &&
           static_cast<int64_t>(range.active_tip_height) -
                       range.future_height +
                   1 >=
               ROSTER_BEACON_MIN_FUTURE_CONFIRMATIONS;
}

RosterBeaconSeed EmptyNormalSeed(uint32_t epoch) noexcept
{
    RosterBeaconSeed seed;
    seed.epoch = epoch;
    return seed;
}

} // namespace

bool IsExactRosterBeaconObservation(const RosterBeaconSeed& empty,
                                    const RosterBeaconSeed& pending) noexcept
{
    return empty.IsStructurallyValid() && pending.IsStructurallyValid() &&
           empty.state == RosterBeaconState::EMPTY &&
           pending.state == RosterBeaconState::PENDING &&
           empty.version == pending.version &&
           empty.anchor_kind == pending.anchor_kind &&
           empty.epoch == pending.epoch;
}

bool IsExactRosterBeaconReveal(const RosterBeaconSeed& pending,
                               const RosterBeaconSeed& ready) noexcept
{
    return pending.IsStructurallyValid() && ready.IsReady() &&
           pending.state == RosterBeaconState::PENDING &&
           pending.version == ready.version &&
           pending.anchor_kind == ready.anchor_kind &&
           pending.epoch == ready.epoch &&
           pending.anchor_cursor == ready.anchor_cursor &&
           pending.anchor_btc_height == ready.anchor_btc_height;
}

bool IsExactRosterBeaconRotation(const RosterBeaconWindow& old_window,
                                 const RosterBeaconWindow& new_window) noexcept
{
    if (!old_window.IsStructurallyValid() ||
        !new_window.IsStructurallyValid() ||
        new_window.next.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
        (new_window.next.state != RosterBeaconState::EMPTY &&
         new_window.next.state != RosterBeaconState::PENDING)) {
        return false;
    }
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        if (new_window.active.seeds[slot] !=
            old_window.active.seeds[slot + 1]) {
            return false;
        }
    }
    const auto& consumed{new_window.active.seeds.back()};
    return ((old_window.next.IsReady() && consumed == old_window.next) ||
            IsExactRosterBeaconReveal(old_window.next, consumed));
}

std::optional<uint8_t> GetNormalRosterAuthorizationMask(
    RosterAuthorizationTransitionKind kind) noexcept
{
    constexpr uint8_t FULL_MASK{
        static_cast<uint8_t>((uint8_t{1} << ACTIVE_QUORUMS) - 1)};
    constexpr uint8_t ROTATION_MASK{
        static_cast<uint8_t>(FULL_MASK >> 1)};
    switch (kind) {
    case RosterAuthorizationTransitionKind::KEEP:
    case RosterAuthorizationTransitionKind::OBSERVE:
    case RosterAuthorizationTransitionKind::REVEAL:
        return FULL_MASK;
    case RosterAuthorizationTransitionKind::ROTATE:
        return ROTATION_MASK;
    case RosterAuthorizationTransitionKind::INITIALIZE:
    case RosterAuthorizationTransitionKind::RECOVER:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<NormalRosterAuthorizationDecision>
DeriveNormalRosterAuthorizationDecision(
    const uint256& genesis_hash,
    const NormalRosterAuthorizationInput& input) noexcept
{
    if (genesis_hash.IsNull() || !IsExactCandidateBoundary(input) ||
        !IsExactNextSnapshotCoverage(input)) {
        return std::nullopt;
    }

    const uint32_t previous_newest_epoch{
        input.previous.window.active.seeds.back().epoch};
    const bool rotate{
        previous_newest_epoch != input.newest_epoch};
    if (rotate &&
        (previous_newest_epoch == std::numeric_limits<uint32_t>::max() ||
         previous_newest_epoch + 1 != input.newest_epoch)) {
        return std::nullopt;
    }

    RosterBeaconWindow new_window{input.previous.window};
    RosterAuthorizationTransitionKind kind{
        RosterAuthorizationTransitionKind::KEEP};

    if (rotate) {
        RosterBeaconSeed consumed;
        if (input.previous.window.next.IsReady()) {
            if (input.pending_reveal || !input.ready_rotation ||
                !IsStillActiveReadySeed(input.previous.window.next,
                                        *input.ready_rotation)) {
                return std::nullopt;
            }
            consumed = input.previous.window.next;
        } else {
            if (!input.pending_reveal || input.ready_rotation) {
                return std::nullopt;
            }
            const auto revealed{MakeRevealedSeed(
                input.previous.window.next, *input.pending_reveal)};
            if (!revealed) return std::nullopt;
            consumed = *revealed;
        }
        for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
            new_window.active.seeds[slot] =
                input.previous.window.active.seeds[slot + 1];
        }
        new_window.active.seeds.back() = consumed;
        new_window.next = EmptyNormalSeed(input.newest_epoch + 1);
        kind = RosterAuthorizationTransitionKind::ROTATE;
    } else if (input.pending_reveal) {
        if (input.ready_rotation) return std::nullopt;
        const auto revealed{MakeRevealedSeed(
            input.previous.window.next, *input.pending_reveal)};
        if (!revealed) return std::nullopt;
        new_window.next = *revealed;
        kind = RosterAuthorizationTransitionKind::REVEAL;
    } else if (input.ready_rotation) {
        return std::nullopt;
    }

    if (new_window.next.state == RosterBeaconState::EMPTY) {
        const bool must_observe{
            input.btcc_advance == BTCCAdvance::ADVANCE &&
            input.next_snapshot.prior_authorization_is_descendant};
        if (must_observe) {
            if (!input.accepted_anchor) return std::nullopt;
            const auto observed{MakeObservedSeed(
                new_window.next, *input.accepted_anchor,
                input.accepted_btcc_cursor)};
            if (!observed) return std::nullopt;
            new_window.next = *observed;
            if (!rotate) kind = RosterAuthorizationTransitionKind::OBSERVE;
        } else if (input.accepted_anchor) {
            return std::nullopt;
        }
    } else if (input.accepted_anchor) {
        return std::nullopt;
    }

    const bool recovery_authorized{std::any_of(
        input.previous.window.active.seeds.begin(),
        input.previous.window.active.seeds.end(),
        [](const RosterBeaconSeed& seed) {
            return seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY;
        })};
    RecoveryRosterAuthoritySource expected_source{
        input.previous.window.active.recovery_authority_source};
    if (!recovery_authorized) {
        const auto* newest_normal{
            FindNewestNormalReadySeed(input.previous.window)};
        if (newest_normal == nullptr) return std::nullopt;
        expected_source.normal_beacon = *newest_normal;
    }
    const auto& previous_source{
        input.previous.window.active.recovery_authority_source};
    const auto& previous_hash{
        input.previous.window.active.recovery_authority_hash};
    if (input.recovery_authority_source != expected_source ||
        (expected_source == previous_source &&
         input.recovery_authority_hash != previous_hash)) {
        return std::nullopt;
    }
    new_window.active.recovery_authority_source = expected_source;
    new_window.active.recovery_authority_hash =
        input.recovery_authority_hash;

    RosterAuthorizationTransition transition;
    transition.kind = kind;
    transition.target_height = input.target_height;
    transition.target_block_hash = input.target_block_hash;
    transition.predecessor_height = input.predecessor_height;
    transition.predecessor_block_hash = input.predecessor_block_hash;
    transition.authorization_base = input.authorization_base;
    transition.previous = input.previous;
    transition.new_window = std::move(new_window);
    const auto mask{GetNormalRosterAuthorizationMask(kind)};
    const auto state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    if (!mask || !state_hash) return std::nullopt;
    return NormalRosterAuthorizationDecision{
        std::move(transition), *mask, *state_hash};
}

std::optional<uint8_t> ValidateNormalRosterAuthorizationDecision(
    const uint256& genesis_hash,
    const NormalRosterAuthorizationInput& input,
    const RosterAuthorizationTransition& claimed_transition,
    const uint256& claimed_state_hash) noexcept
{
    const auto expected{
        DeriveNormalRosterAuthorizationDecision(genesis_hash, input)};
    if (!expected || expected->transition != claimed_transition ||
        expected->state_hash != claimed_state_hash) {
        return std::nullopt;
    }
    return expected->authorization_mask;
}

bool IsRecoveryRosterBeaconWindow(const RosterBeaconWindow& window) noexcept
{
    if (!window.IsStructurallyValid() ||
        window.active.seeds.back().epoch % ACTIVE_QUORUMS !=
            ACTIVE_QUORUMS - 1 ||
        window.next.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
        window.next.state != RosterBeaconState::EMPTY ||
        window.active.recovery_authority_hash.IsNull() ||
        window.active.recovery_authority_source.IsNull()) {
        return false;
    }
    const auto& source{
        window.active.recovery_authority_source.normal_beacon};
    if (!source.IsReady() ||
        source.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        return false;
    }
    for (const auto& seed : window.active.seeds) {
        if (!seed.IsReady() ||
            seed.anchor_kind != RosterBeaconAnchorKind::RECOVERY ||
            seed.anchor_cursor != source.anchor_cursor ||
            seed.anchor_btc_height != source.anchor_btc_height ||
            seed.future_btc_hash != source.future_btc_hash) {
            return false;
        }
    }
    return true;
}

std::optional<RosterBeaconWindow> MakeRecoveryRosterBeaconWindow(
    const RecoveryRosterAuthoritySource& source,
    const uint256& recovery_authority_hash,
    uint32_t newest_epoch) noexcept
{
    if (!source.IsStructurallyValid() || source.IsNull() ||
        recovery_authority_hash.IsNull() ||
        newest_epoch < ACTIVE_QUORUMS - 1 ||
        newest_epoch == std::numeric_limits<uint32_t>::max() ||
        newest_epoch % ACTIVE_QUORUMS != ACTIVE_QUORUMS - 1) {
        return std::nullopt;
    }
    RosterBeaconWindow window;
    window.active.recovery_authority_source = source;
    window.active.recovery_authority_hash = recovery_authority_hash;
    const uint32_t first_epoch{
        newest_epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 1)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto seed{source.normal_beacon};
        seed.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
        seed.epoch = first_epoch + static_cast<uint32_t>(slot);
        window.active.seeds[slot] = std::move(seed);
    }
    window.next = EmptyNormalSeed(newest_epoch + 1);
    return IsRecoveryRosterBeaconWindow(window)
        ? std::optional<RosterBeaconWindow>{std::move(window)}
        : std::nullopt;
}

bool IsInitialNormalRosterBeaconWindow(
    const RosterBeaconWindow& window) noexcept
{
    if (!window.IsStructurallyValid() ||
        window.active.seeds.back().epoch % ACTIVE_QUORUMS !=
            ACTIVE_QUORUMS - 1 ||
        window.active.recovery_authority_hash.IsNull() ||
        window.active.recovery_authority_source.IsNull() ||
        window.active.recovery_authority_source.normal_beacon !=
            window.active.seeds.back() ||
        window.next.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
        window.next.state != RosterBeaconState::EMPTY) {
        return false;
    }
    const auto& anchor{window.active.seeds.front()};
    if (!anchor.IsReady() ||
        anchor.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        return false;
    }
    for (const auto& seed : window.active.seeds) {
        if (!seed.IsReady() ||
            seed.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
            seed.anchor_cursor != anchor.anchor_cursor ||
            seed.anchor_btc_height != anchor.anchor_btc_height ||
            seed.future_btc_hash != anchor.future_btc_hash) {
            return false;
        }
    }
    return true;
}

bool HasRecoveryRosterBeacon(const RosterBeaconWindow& window) noexcept
{
    return window.IsStructurallyValid() &&
           std::any_of(
               window.active.seeds.begin(), window.active.seeds.end(),
               [](const RosterBeaconSeed& seed) {
                   return seed.anchor_kind ==
                          RosterBeaconAnchorKind::RECOVERY;
               });
}

bool RosterAuthorizationPriorState::IsStructurallyValid() const noexcept
{
    return !state_hash.IsNull() && window.IsStructurallyValid();
}

bool RosterAuthorizationTransition::IsStructurallyValid() const noexcept
{
    if (version != ROSTER_AUTHORIZATION_TRANSITION_VERSION ||
        !IsKnownTransitionKind(kind) || target_height < 0 ||
        target_block_hash.IsNull() || predecessor_height >= target_height ||
        ((predecessor_height == -1) != predecessor_block_hash.IsNull()) ||
        predecessor_height < -1 ||
        (!predecessor_block_hash.IsNull() &&
         predecessor_block_hash == target_block_hash) ||
        !authorization_base.IsStructurallyValid() ||
        (!authorization_base.IsNull() &&
         (authorization_base.height >= target_height ||
          authorization_base.block_hash == target_block_hash)) ||
        !new_window.IsStructurallyValid()) {
        return false;
    }
    if (kind == RosterAuthorizationTransitionKind::INITIALIZE) {
        return authorization_base.IsNull() && !previous &&
               IsInitialNormalRosterBeaconWindow(new_window);
    }
    if (kind == RosterAuthorizationTransitionKind::RECOVER) {
        return !authorization_base.IsNull() && previous &&
               previous->IsStructurallyValid() &&
               IsRecoveryRosterBeaconWindow(new_window);
    }
    if (authorization_base.IsNull()) return false;
    if (!previous || !previous->IsStructurallyValid()) return false;
    if (kind == RosterAuthorizationTransitionKind::KEEP) {
        return previous->window.active.seeds == new_window.active.seeds &&
               previous->window.next == new_window.next;
    }
    if (kind == RosterAuthorizationTransitionKind::OBSERVE) {
        return previous->window.active.seeds == new_window.active.seeds &&
               IsExactRosterBeaconObservation(previous->window.next,
                                              new_window.next);
    }
    if (kind == RosterAuthorizationTransitionKind::REVEAL) {
        return previous->window.active.seeds == new_window.active.seeds &&
               IsExactRosterBeaconReveal(previous->window.next,
                                          new_window.next);
    }
    return IsExactRosterBeaconRotation(previous->window, new_window);
}

std::optional<uint256> GetRosterBeaconCommitmentHash(
    const uint256& genesis_hash,
    const RosterBeaconSeed& seed) noexcept
{
    if (genesis_hash.IsNull() || !seed.IsStructurallyValid()) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, ROSTER_BEACON_COMMITMENT_DOMAIN);
    writer << genesis_hash << seed;
    return writer.GetHash();
}

std::optional<uint256> GetRecoveryRosterEntropyCommitment(
    const uint256& genesis_hash,
    const RosterBeaconSeed& normal_beacon) noexcept
{
    if (genesis_hash.IsNull() || !normal_beacon.IsReady() ||
        normal_beacon.anchor_kind != RosterBeaconAnchorKind::NORMAL) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RECOVERY_ROSTER_ENTROPY_DOMAIN);
    writer << genesis_hash << normal_beacon;
    return writer.GetHash();
}

std::optional<uint256> GetActiveRosterBeaconBundleHash(
    const uint256& genesis_hash,
    const ActiveRosterBeaconBundle& bundle) noexcept
{
    if (genesis_hash.IsNull() || !bundle.IsStructurallyValid()) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, ROSTER_BEACON_BUNDLE_DOMAIN);
    writer << genesis_hash << bundle;
    return writer.GetHash();
}

const RosterBeaconSeed* FindRosterBeaconSeed(
    const ActiveRosterBeaconBundle& bundle,
    uint32_t epoch) noexcept
{
    if (!bundle.IsStructurallyValid() || epoch < bundle.seeds.front().epoch) {
        return nullptr;
    }
    const uint64_t slot{static_cast<uint64_t>(epoch) -
                        bundle.seeds.front().epoch};
    return slot < bundle.seeds.size() ? &bundle.seeds[slot] : nullptr;
}

const RosterBeaconSeed* FindNewestNormalReadySeed(
    const RosterBeaconWindow& window) noexcept
{
    if (!window.IsStructurallyValid()) return nullptr;
    if (window.next.anchor_kind == RosterBeaconAnchorKind::NORMAL &&
        window.next.IsReady()) {
        return &window.next;
    }
    for (auto it{window.active.seeds.rbegin()};
         it != window.active.seeds.rend(); ++it) {
        if (it->anchor_kind == RosterBeaconAnchorKind::NORMAL &&
            it->IsReady()) {
            return &*it;
        }
    }
    return nullptr;
}

std::optional<uint256> GetPQQuorumModifier(
    const uint256& genesis_hash,
    uint32_t epoch,
    int32_t snapshot_height,
    const uint256& snapshot_hash,
    const RosterBeaconSeed& seed) noexcept
{
    if (genesis_hash.IsNull() || snapshot_height < 0 ||
        snapshot_hash.IsNull() || !seed.IsReady() || seed.epoch != epoch ||
        seed.anchor_kind != RosterBeaconAnchorKind::NORMAL ||
        snapshot_height >= seed.anchor_cursor.sys_height) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PQ_QUORUM_MODIFIER_DOMAIN);
    writer << genesis_hash << epoch << snapshot_height << snapshot_hash
           << static_cast<uint8_t>(seed.anchor_kind)
           << seed.anchor_btc_height << seed.anchor_cursor.btc_hash
           << seed.future_btc_hash;
    return writer.GetHash();
}

std::optional<int32_t> CanonicalRosterRecoveryTargetHeight(
    const ChainLockScheduleConfig& chainlock,
    const BTCCScheduleConfig& btcc,
    uint32_t epoch) noexcept
{
    if (epoch % ACTIVE_QUORUMS != ACTIVE_QUORUMS - 1) {
        return std::nullopt;
    }
    const auto base{EpochBaseHeight(chainlock, epoch)};
    const auto end{EpochEndHeightExclusive(chainlock, epoch)};
    if (!base || !end) return std::nullopt;
    for (int64_t height{*base}; height < *end; ++height) {
        const auto candidate{static_cast<int32_t>(height)};
        if (IsEligibleChainLockTarget(chainlock, candidate) &&
            IsBTCCCandidateHeight(btcc, candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::optional<RosterAuthorizationTransitionKind>
CanonicalRosterResetTransitionForTarget(
    const ChainLockScheduleConfig& chainlock,
    const BTCCScheduleConfig& btcc,
    int32_t activation_predecessor_height,
    int32_t target_height) noexcept
{
    if (!chainlock.IsValid() || !btcc.IsValid() ||
        activation_predecessor_height < -1 ||
        target_height <= activation_predecessor_height) {
        return std::nullopt;
    }
    const auto first_target{NextEligibleChainLockTargetHeight(
        chainlock, activation_predecessor_height)};
    const auto first_epoch{first_target
        ? EpochForHeight(chainlock, *first_target)
        : std::optional<uint32_t>{}};
    const auto first_canonical{first_epoch
        ? CanonicalRosterRecoveryTargetHeight(
              chainlock, btcc, *first_epoch)
        : std::optional<int32_t>{}};
    if (!first_target || !first_canonical ||
        *first_target != *first_canonical) {
        return std::nullopt;
    }
    if (target_height == *first_target) {
        return RosterAuthorizationTransitionKind::INITIALIZE;
    }
    if (target_height < *first_target) return std::nullopt;

    const auto target_epoch{EpochForHeight(chainlock, target_height)};
    const auto canonical{target_epoch
        ? CanonicalRosterRecoveryTargetHeight(
              chainlock, btcc, *target_epoch)
        : std::optional<int32_t>{}};
    if (!canonical || *canonical != target_height) {
        return std::nullopt;
    }
    return RosterAuthorizationTransitionKind::RECOVER;
}

std::optional<uint256> GetRosterAuthorizationStateHash(
    const uint256& genesis_hash,
    const RosterAuthorizationTransition& transition) noexcept
{
    if (genesis_hash.IsNull() || !transition.IsStructurallyValid()) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, ROSTER_AUTHORIZATION_STATE_DOMAIN);
    writer << genesis_hash << transition.version
           << static_cast<uint8_t>(transition.kind)
           << transition.target_height << transition.target_block_hash
           << transition.predecessor_height
           << transition.predecessor_block_hash
           << transition.authorization_base
           << static_cast<uint8_t>(transition.previous.has_value());
    if (transition.previous) {
        writer << transition.previous->state_hash
               << transition.previous->window;
    }
    writer << transition.new_window;
    return writer.GetHash();
}

} // namespace llmq::pq
