// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_types.h>
#include <llmq/pq_payment_audit.h>

#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <vector>

using namespace llmq::pq;

namespace {

std::vector<std::uint8_t> g_final_chainlock_fixture;
std::vector<std::uint8_t> g_final_payment_audit_fixture;

uint256 NonNullHash(std::uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = value & 0xff;
    hash.begin()[1] = (value >> 8) & 0xff;
    hash.begin()[2] = (value >> 16) & 0xff;
    hash.begin()[3] = (value >> 24) & 0xff;
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    bitmap.fill(0);
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |= static_cast<std::uint8_t>(
            std::uint8_t{1} << (member % 8));
    }
}

void InitializeFinalChainLockFixture()
{
    FinalChainLock chainlock;
    chainlock.statement.height = 1445;
    chainlock.statement.block_hash = NonNullHash(1);
    chainlock.statement.previous_chainlock_height = 1440;
    chainlock.statement.previous_chainlock_hash = NonNullHash(2);
    chainlock.statement.quorum_context_hash = NonNullHash(3);
    chainlock.statement.payment_probation_state_hash = NonNullHash(4);
    chainlock.selected_quorum_mask = 0b1011;
    SetFirstMembers(chainlock.signer_bitmaps[0], QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[1], QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[3], QUORUM_THRESHOLD);
    chainlock.signatures.resize(FINAL_SIGNATURE_COUNT);
    for (std::size_t index{0}; index < chainlock.signatures.size(); ++index) {
        chainlock.signatures[index].key_proof.public_key[0] = 1;
        chainlock.signatures[index].signature[0] =
            static_cast<std::uint8_t>(index);
        chainlock.signatures[index].signature[1] =
            static_cast<std::uint8_t>(index >> 8);
    }
    Assert(chainlock.IsStructurallyValid());

    DataStream encoded;
    encoded << chainlock;
    const auto bytes = MakeUCharSpan(encoded);
    g_final_chainlock_fixture.assign(bytes.begin(), bytes.end());
    Assert(g_final_chainlock_fixture.size() == FinalChainLock::WIRE_SIZE);
}

void DecodeFinalChainLock(Span<const std::uint8_t> payload)
{
    SpanReader stream{0, payload};
    try {
        const FinalChainLock chainlock = ReadFinalChainLock(stream, payload.size());
        assert(payload.size() == FinalChainLock::WIRE_SIZE);
        assert(stream.empty());
        assert(chainlock.IsStructurallyValid());

        DataStream encoded;
        encoded << chainlock;
        const auto canonical = MakeUCharSpan(encoded);
        assert(canonical.size() == payload.size());
        assert(std::equal(canonical.begin(), canonical.end(), payload.begin()));
    } catch (const std::ios_base::failure&) {
    }
}

void DecodeMutatedFixture(FuzzedDataProvider& provider, bool structural_only)
{
    auto encoded = g_final_chainlock_fixture;
    constexpr std::size_t SIGNATURE_COUNT_OFFSET{
        FinalChainLock::WIRE_SIZE - sizeof(std::uint16_t) -
        FINAL_SIGNATURE_COUNT * AuthenticatedChildSignature::WIRE_SIZE};
    const std::size_t maximum_offset = structural_only
        ? SIGNATURE_COUNT_OFFSET + sizeof(std::uint16_t) - 1
        : encoded.size() - 1;

    LIMITED_WHILE(provider.remaining_bytes() != 0, 8) {
        const std::size_t offset = provider.ConsumeIntegralInRange<std::size_t>(
            0, maximum_offset);
        encoded[offset] ^= provider.ConsumeIntegral<std::uint8_t>();
    }
    DecodeFinalChainLock(encoded);
}

void DecodeFixtureLengthBoundary(FuzzedDataProvider& provider)
{
    constexpr std::array<std::size_t, 3> SIZES{
        FinalChainLock::WIRE_SIZE, FinalChainLock::WIRE_SIZE - 1,
        FinalChainLock::WIRE_SIZE + 1};
    const std::size_t size = SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, SIZES.size() - 1)];
    if (size <= g_final_chainlock_fixture.size()) {
        DecodeFinalChainLock(Span<const std::uint8_t>{g_final_chainlock_fixture}.first(size));
        return;
    }
    auto oversized = g_final_chainlock_fixture;
    oversized.push_back(0);
    DecodeFinalChainLock(oversized);
}

void InitializeFinalPaymentAuditFixture()
{
    FinalPaymentAudit audit;
    auto& commitment{audit.statement.commitment};
    commitment.seed.epoch = 5;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        1'440, NonNullHash(10),
        BTCCursor{1'440, NonNullHash(11), NonNullHash(12)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        commitment.seed.anchor_btc_height +
        PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(13);
    commitment.selected_row = 0;
    commitment.response_height = 1'400;
    commitment.deadline_height =
        commitment.response_height + PAYMENT_AUDIT_ROW_DEADLINE_DELAY;
    commitment.response_chainlock_logical_id = NonNullHash(13);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = 1'680;
    commitment.subject_epoch = commitment.seed.epoch;
    commitment.subject_quorum_base_hash = NonNullHash(14);
    commitment.subject_descriptor_hash = NonNullHash(15);
    SetFirstMembers(commitment.subject_valid_members, QUORUM_MIN_VALID);
    commitment.previous_probation_state_hash = NonNullHash(16);

    auto& seal{audit.statement.seal_statement};
    seal.height = commitment.seal_height;
    seal.block_hash = NonNullHash(18);
    seal.previous_chainlock_height = seal.height - 5;
    seal.previous_chainlock_hash = NonNullHash(19);
    seal.quorum_context_hash = NonNullHash(20);
    seal.payment_probation_state_hash =
        commitment.previous_probation_state_hash;

    audit.selected_quorum_mask = 0b1011;
    SetFirstMembers(audit.signer_bitmaps[0], QUORUM_THRESHOLD);
    SetFirstMembers(audit.signer_bitmaps[1], QUORUM_THRESHOLD);
    SetFirstMembers(audit.signer_bitmaps[3], QUORUM_THRESHOLD);
    audit.report_witnesses.resize(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t index{0};
         index < audit.report_witnesses.size(); ++index) {
        auto& witness{audit.report_witnesses[index]};
        SetFirstMembers(witness.observed_members, QUORUM_MIN_VALID);
        witness.authenticated_signature.key_proof.public_key[0] = 1;
        witness.authenticated_signature.signature[0] =
            static_cast<std::uint8_t>(index);
        witness.authenticated_signature.signature[1] =
            static_cast<std::uint8_t>(index >> 8);
    }
    Assert(audit.IsStructurallyValid());

    DataStream encoded;
    encoded << audit;
    const auto bytes{MakeUCharSpan(encoded)};
    g_final_payment_audit_fixture.assign(bytes.begin(), bytes.end());
    Assert(g_final_payment_audit_fixture.size() ==
           FinalPaymentAudit::WIRE_SIZE);
}

void DecodeFinalPaymentAudit(Span<const std::uint8_t> payload)
{
    if (payload.size() != FinalPaymentAudit::WIRE_SIZE) return;
    SpanReader stream{0, payload};
    try {
        FinalPaymentAudit audit;
        stream >> audit;
        assert(stream.empty());
        assert(audit.IsStructurallyValid());

        DataStream encoded;
        encoded << audit;
        const auto canonical{MakeUCharSpan(encoded)};
        assert(canonical.size() == payload.size());
        assert(std::equal(canonical.begin(), canonical.end(),
                          payload.begin()));
    } catch (const std::ios_base::failure&) {
    }
}

void DecodeMutatedPaymentAudit(FuzzedDataProvider& provider,
                               bool structural_only)
{
    auto encoded{g_final_payment_audit_fixture};
    constexpr std::size_t SIGNATURE_COUNT_OFFSET{
        FinalPaymentAudit::WIRE_SIZE - sizeof(std::uint16_t) -
        PAYMENT_AUDIT_SIGNATURE_COUNT *
            PaymentAuditReportWitness::WIRE_SIZE};
    const std::size_t maximum_offset{
        structural_only
            ? SIGNATURE_COUNT_OFFSET + sizeof(std::uint16_t) - 1
            : encoded.size() - 1};
    LIMITED_WHILE(provider.remaining_bytes() != 0, 8) {
        const std::size_t offset{
            provider.ConsumeIntegralInRange<std::size_t>(
                0, maximum_offset)};
        encoded[offset] ^= provider.ConsumeIntegral<std::uint8_t>();
    }
    DecodeFinalPaymentAudit(encoded);
}

void DecodePaymentAuditLengthBoundary(FuzzedDataProvider& provider)
{
    constexpr std::array<std::size_t, 3> SIZES{
        FinalPaymentAudit::WIRE_SIZE,
        FinalPaymentAudit::WIRE_SIZE - 1,
        FinalPaymentAudit::WIRE_SIZE + 1};
    const std::size_t size{SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0,
                                                     SIZES.size() - 1)]};
    if (size <= g_final_payment_audit_fixture.size()) {
        DecodeFinalPaymentAudit(
            Span<const std::uint8_t>{g_final_payment_audit_fixture}
                .first(size));
        return;
    }
    auto oversized{g_final_payment_audit_fixture};
    oversized.push_back(0);
    DecodeFinalPaymentAudit(oversized);
}

} // namespace

FUZZ_TARGET(pq_chainlock_final_decode, .init = InitializeFinalChainLockFixture)
{
    if (buffer.empty()) {
        DecodeFinalChainLock(buffer);
        return;
    }
    const auto framed_input = buffer.subspan(1);
    FuzzedDataProvider provider{framed_input.data(), framed_input.size()};
    switch (buffer.front() & 0x07) {
    case 1:
        DecodeMutatedFixture(provider, /*structural_only=*/false);
        break;
    case 2:
        DecodeMutatedFixture(provider, /*structural_only=*/true);
        break;
    case 3:
        DecodeFixtureLengthBoundary(provider);
        break;
    default:
        DecodeFinalChainLock(framed_input);
        break;
    }
}

FUZZ_TARGET(pq_payment_audit_decode,
            .init = InitializeFinalPaymentAuditFixture)
{
    if (buffer.empty()) {
        DecodeFinalPaymentAudit(buffer);
        return;
    }
    const auto framed_input{buffer.subspan(1)};
    FuzzedDataProvider provider{framed_input.data(), framed_input.size()};
    switch (buffer.front() & 0x07) {
    case 1:
        DecodeMutatedPaymentAudit(provider, /*structural_only=*/false);
        break;
    case 2:
        DecodeMutatedPaymentAudit(provider, /*structural_only=*/true);
        break;
    case 3:
        DecodePaymentAuditLengthBoundary(provider);
        break;
    default:
        DecodeFinalPaymentAudit(framed_input);
        break;
    }
}
