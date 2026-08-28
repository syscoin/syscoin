// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_AUXILIARY_HISTORY_GC_H
#define SYSCOIN_EVO_AUXILIARY_HISTORY_GC_H

#include <dbwrapper.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Consensus {
struct Params;
}

namespace evo {

template <std::size_t MaximumSize>
struct AuxiliaryHistoryGCLimitedBytesFormatter {
    template <typename Stream>
    void Ser(Stream& stream, const std::vector<unsigned char>& bytes)
    {
        if (bytes.size() > MaximumSize) {
            throw std::ios_base::failure{
                "auxiliary-history GC payload too large"};
        }
        WriteCompactSize(stream, bytes.size());
        if (!bytes.empty()) stream.write(MakeByteSpan(bytes));
    }

    template <typename Stream>
    void Unser(Stream& stream, std::vector<unsigned char>& bytes)
    {
        const std::size_t size{ReadCompactSize(stream)};
        if (size > MaximumSize) {
            throw std::ios_base::failure{
                "auxiliary-history GC payload too large"};
        }
        bytes.resize(size);
        if (!bytes.empty()) stream.read(MakeWritableByteSpan(bytes));
    }
};

template <typename Value>
struct AuxiliaryHistoryGCOptionalFormatter {
    template <typename Stream>
    void Ser(Stream& stream, const std::optional<Value>& value)
    {
        stream << static_cast<uint8_t>(value.has_value());
        if (value) stream << *value;
    }

    template <typename Stream>
    void Unser(Stream& stream, std::optional<Value>& value)
    {
        uint8_t present{0};
        stream >> present;
        if (present > 1) {
            throw std::ios_base::failure{
                "non-canonical auxiliary-history GC optional"};
        }
        if (present == 0) {
            value.reset();
            return;
        }
        Value decoded;
        stream >> decoded;
        value = std::move(decoded);
    }
};

enum class AuxiliaryHistoryGCAuthorizationSource : uint8_t {
    IMMUTABLE_CHAINLOCK_ANCHOR = 0,
    ENFORCED_DURABLE_CHAINLOCK,
};

struct AuxiliaryHistoryGCBlockIdentity {
    int32_t height{-1};
    uint256 block_hash;

    [[nodiscard]] bool IsValid() const noexcept
    {
        return height >= 0 && !block_hash.IsNull();
    }

    SERIALIZE_METHODS(AuxiliaryHistoryGCBlockIdentity, obj)
    {
        READWRITE(obj.height, obj.block_hash);
    }

    friend bool operator==(const AuxiliaryHistoryGCBlockIdentity&,
                           const AuxiliaryHistoryGCBlockIdentity&) = default;
};

struct AuxiliaryHistoryGCAuthorization {
    AuxiliaryHistoryGCAuthorizationSource source{
        AuxiliaryHistoryGCAuthorizationSource::IMMUTABLE_CHAINLOCK_ANCHOR};
    AuxiliaryHistoryGCBlockIdentity block;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(AuxiliaryHistoryGCAuthorization, obj)
    {
        uint8_t source{static_cast<uint8_t>(obj.source)};
        READWRITE(source, obj.block);
        SER_READ(obj, obj.source =
            static_cast<AuxiliaryHistoryGCAuthorizationSource>(source));
    }

    friend bool operator==(const AuxiliaryHistoryGCAuthorization&,
                           const AuxiliaryHistoryGCAuthorization&) = default;
};

/**
 * SYSCOIN: Authenticated trust base retained when a deterministic-MN inverse
 * prefix is eventually removed. The boundary inverse itself remains stored.
 */
struct DMNInverseGCClosure {
    static constexpr uint32_t FORMAT_GUARD{0x444d4e31}; // "DMN1"
    static constexpr uint16_t VERSION{1};
    static constexpr std::size_t SERIALIZED_SIZE{
        sizeof(uint32_t) + sizeof(uint16_t) + sizeof(int32_t) +
        4 * uint256::size()};

    uint32_t format_guard{FORMAT_GUARD};
    uint16_t version{VERSION};
    AuxiliaryHistoryGCBlockIdentity boundary;
    uint256 boundary_state_hash;
    uint256 inverse_history_commitment;
    uint256 inverse_record_hash;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(DMNInverseGCClosure, obj)
    {
        READWRITE(obj.format_guard, obj.version, obj.boundary,
                  obj.boundary_state_hash,
                  obj.inverse_history_commitment,
                  obj.inverse_record_hash);
    }

    friend bool operator==(const DMNInverseGCClosure&,
                           const DMNInverseGCClosure&) = default;
};

[[nodiscard]] std::optional<std::vector<unsigned char>>
EncodeDMNInverseGCClosure(const DMNInverseGCClosure& closure);

[[nodiscard]] std::optional<DMNInverseGCClosure>
DecodeDMNInverseGCClosure(Span<const unsigned char> payload);

/**
 * SYSCOIN: Bounded, versioned closure data owned by one auxiliary store.
 * The coordinator treats the payload as opaque; the store-specific GC pass
 * must decode it before Begin() and again before applying any deletion.
 */
struct AuxiliaryHistoryGCComponent {
    static constexpr std::size_t MAX_CLOSURE_BYTES{4 * 1024};

    uint16_t version{0};
    uint64_t monotonic_position{0};
    std::vector<unsigned char> closure;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(AuxiliaryHistoryGCComponent, obj)
    {
        READWRITE(obj.version, obj.monotonic_position);
        READWRITE(Using<AuxiliaryHistoryGCLimitedBytesFormatter<
            MAX_CLOSURE_BYTES>>(obj.closure));
    }

    friend bool operator==(const AuxiliaryHistoryGCComponent&,
                           const AuxiliaryHistoryGCComponent&) = default;
};

[[nodiscard]] bool IsDMNInverseGCComponentBoundedByAuthorization(
    const AuxiliaryHistoryGCComponent& component,
    const AuxiliaryHistoryGCAuthorization& authorization);

/** Compact cumulative closures that survive after an erase completes. */
struct AuxiliaryHistoryGCFrontier {
    std::optional<AuxiliaryHistoryGCComponent> dmn;
    std::optional<AuxiliaryHistoryGCComponent> pq_registry;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(AuxiliaryHistoryGCFrontier, obj)
    {
        READWRITE(Using<AuxiliaryHistoryGCOptionalFormatter<
                      AuxiliaryHistoryGCComponent>>(obj.dmn),
                  Using<AuxiliaryHistoryGCOptionalFormatter<
                      AuxiliaryHistoryGCComponent>>(obj.pq_registry));
    }

    friend bool operator==(const AuxiliaryHistoryGCFrontier&,
                           const AuxiliaryHistoryGCFrontier&) = default;
};

/**
 * SYSCOIN: Ephemeral exact erase manifest. It is fsynced in INTENT but is
 * deliberately omitted from the compact WATERMARK after completion.
 */
struct AuxiliaryHistoryGCManifest {
    // SYSCOIN: This is a fail-closed per-intent chunk bound. Callers that
    // need more space must advance over multiple strictly newer authorizers;
    // an erase manifest must never be truncated.
    static constexpr std::size_t MAX_MANIFEST_BYTES{4 * 1024 * 1024};

    uint16_t version{0};
    // SYSCOIN: A canonical empty payload explicitly records that advancing
    // the PQ frontier requires no physical erases in this generation.
    std::vector<unsigned char> payload;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(AuxiliaryHistoryGCManifest, obj)
    {
        READWRITE(obj.version);
        READWRITE(Using<AuxiliaryHistoryGCLimitedBytesFormatter<
            MAX_MANIFEST_BYTES>>(obj.payload));
    }

    friend bool operator==(const AuxiliaryHistoryGCManifest&,
                           const AuxiliaryHistoryGCManifest&) = default;
};

struct AuxiliaryHistoryGCIntentTarget {
    AuxiliaryHistoryGCAuthorization authorization;
    AuxiliaryHistoryGCFrontier frontier;
    std::optional<AuxiliaryHistoryGCManifest> pq_erase_manifest;

    [[nodiscard]] bool IsValid() const noexcept;

    SERIALIZE_METHODS(AuxiliaryHistoryGCIntentTarget, obj)
    {
        READWRITE(obj.authorization, obj.frontier,
                  Using<AuxiliaryHistoryGCOptionalFormatter<
                      AuxiliaryHistoryGCManifest>>(
                      obj.pq_erase_manifest));
    }

    friend bool operator==(const AuxiliaryHistoryGCIntentTarget&,
                           const AuxiliaryHistoryGCIntentTarget&) = default;
};

struct AuxiliaryHistoryGCIntent {
    uint64_t sequence{0};
    uint256 configuration_id;
    AuxiliaryHistoryGCIntentTarget target;
    uint256 intent_id;

    friend bool operator==(const AuxiliaryHistoryGCIntent&,
                           const AuxiliaryHistoryGCIntent&) = default;
};

struct AuxiliaryHistoryGCWatermark {
    uint64_t sequence{0};
    uint256 configuration_id;
    AuxiliaryHistoryGCAuthorization authorization;
    AuxiliaryHistoryGCFrontier frontier;
    uint256 completed_intent_id;
    uint256 watermark_id;

    friend bool operator==(const AuxiliaryHistoryGCWatermark&,
                           const AuxiliaryHistoryGCWatermark&) = default;
};

struct AuxiliaryHistoryGCState {
    std::optional<AuxiliaryHistoryGCWatermark> watermark;
    std::optional<AuxiliaryHistoryGCIntent> intent;
};

enum class AuxiliaryHistoryGCJournalResult : uint8_t {
    STARTED = 0,
    EXISTING,
    COMPLETED,
    ALREADY_COMPLETE,
    BUSY,
    NON_MONOTONIC,
    INVALID_ARGUMENT,
    MISMATCH,
    CORRUPT,
    DB_ERROR,
};

struct AuxiliaryHistoryGCDeployment {
    uint256 genesis_hash;
    uint256 configuration_id;

    [[nodiscard]] bool IsValid() const noexcept
    {
        return !genesis_hash.IsNull() && !configuration_id.IsNull();
    }

    friend bool operator==(const AuxiliaryHistoryGCDeployment&,
                           const AuxiliaryHistoryGCDeployment&) = default;
};

[[nodiscard]] AuxiliaryHistoryGCDeployment
MakeAuxiliaryHistoryGCDeployment(const Consensus::Params& consensus);

[[nodiscard]] fs::path AuxiliaryHistoryGCDBPath(const fs::path& evo_db_path);

/**
 * Crash-monotonic coordinator shared by deterministic-MN and PQ history GC.
 * Begin() durably publishes the exact resumable intent. Complete() atomically
 * replaces it with the compact cumulative watermark; there is no cancel API.
 */
class AuxiliaryHistoryGCJournal final {
public:
    static constexpr uint32_t DB_FORMAT_VERSION{1};

    AuxiliaryHistoryGCJournal(DBParams evo_db_params,
                              AuxiliaryHistoryGCDeployment deployment);
    ~AuxiliaryHistoryGCJournal();

    AuxiliaryHistoryGCJournal(const AuxiliaryHistoryGCJournal&) = delete;
    AuxiliaryHistoryGCJournal& operator=(
        const AuxiliaryHistoryGCJournal&) = delete;

    [[nodiscard]] AuxiliaryHistoryGCJournalResult Begin(
        const AuxiliaryHistoryGCIntentTarget& target,
        uint256* intent_id = nullptr);
    [[nodiscard]] AuxiliaryHistoryGCJournalResult Complete(
        const uint256& intent_id);

    [[nodiscard]] AuxiliaryHistoryGCState GetState() const;
    [[nodiscard]] std::optional<AuxiliaryHistoryGCAuthorization>
    HighestAuthorization() const;
    [[nodiscard]] bool IsHealthy() const;
    /** SYSCOIN: Fail the next completion write after physical GC in tests. */
    void FailNextCompleteForTesting();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace evo

#endif // SYSCOIN_EVO_AUXILIARY_HISTORY_GC_H
