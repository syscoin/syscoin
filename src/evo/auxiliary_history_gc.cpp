// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/auxiliary_history_gc.h>

#include <consensus/params.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <hash.h>
#include <streams.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace evo {
namespace {

constexpr uint8_t DB_SCHEMA_KEY{1};
constexpr uint8_t DB_WATERMARK_KEY{2};
constexpr uint8_t DB_INTENT_KEY{3};
constexpr uint32_t SCHEMA_GUARD{0x41474331};    // "AGC1"
constexpr uint32_t INTENT_GUARD{0x494e5431};    // "INT1"
constexpr uint32_t WATERMARK_GUARD{0x574d4b31}; // "WMK1"
constexpr std::string_view CONFIGURATION_DOMAIN{
    "SYS_AUXILIARY_HISTORY_GC_CONFIGURATION_V1"};
constexpr std::string_view INTENT_ID_DOMAIN{
    "SYS_AUXILIARY_HISTORY_GC_INTENT_ID_V1"};
constexpr std::string_view WATERMARK_ID_DOMAIN{
    "SYS_AUXILIARY_HISTORY_GC_WATERMARK_ID_V1"};

struct DiskKey {
    uint8_t type{0};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        stream << type;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> type;
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing auxiliary-history GC key bytes"};
        }
    }
};

struct DiskSchema {
    uint32_t version{AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION};
    uint32_t guard{SCHEMA_GUARD};
    uint256 genesis_hash;
    uint256 configuration_id;
    uint32_t max_closure_bytes{
        AuxiliaryHistoryGCComponent::MAX_CLOSURE_BYTES};
    uint32_t max_manifest_bytes{
        AuxiliaryHistoryGCManifest::MAX_MANIFEST_BYTES};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, guard, genesis_hash,
                        configuration_id, max_closure_bytes,
                        max_manifest_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        ::UnserializeMany(stream, version, guard, genesis_hash,
                          configuration_id, max_closure_bytes,
                          max_manifest_bytes);
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing auxiliary-history GC schema bytes"};
        }
    }
};

struct DiskIntent {
    uint32_t version{AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION};
    AuxiliaryHistoryGCIntent intent;
    uint32_t guard{INTENT_GUARD};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, intent.sequence,
                        intent.configuration_id, intent.target,
                        intent.intent_id, guard);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        ::UnserializeMany(stream, version, intent.sequence,
                          intent.configuration_id, intent.target,
                          intent.intent_id, guard);
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing auxiliary-history GC intent bytes"};
        }
    }
};

struct DiskWatermark {
    uint32_t version{AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION};
    AuxiliaryHistoryGCWatermark watermark;
    uint32_t guard{WATERMARK_GUARD};

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ::SerializeMany(stream, version, watermark.sequence,
                        watermark.configuration_id,
                        watermark.authorization, watermark.frontier,
                        watermark.completed_intent_id,
                        watermark.watermark_id, guard);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        ::UnserializeMany(stream, version, watermark.sequence,
                          watermark.configuration_id,
                          watermark.authorization, watermark.frontier,
                          watermark.completed_intent_id,
                          watermark.watermark_id, guard);
        if (!stream.empty()) {
            throw std::ios_base::failure{
                "trailing auxiliary-history GC watermark bytes"};
        }
    }
};

DBParams MakeDBParams(DBParams params)
{
    params.path = AuxiliaryHistoryGCDBPath(params.path);
    params.cache_bytes = std::max<std::size_t>(1, params.cache_bytes / 16);
    params.obfuscate = false;
    return params;
}

uint256 GetIntentId(uint64_t sequence,
                    const uint256& configuration_id,
                    const AuxiliaryHistoryGCIntentTarget& target)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{INTENT_ID_DOMAIN.data(),
                              INTENT_ID_DOMAIN.size()}));
    writer << sequence << configuration_id << target;
    return writer.GetHash();
}

uint256 GetWatermarkId(
    uint64_t sequence,
    const uint256& configuration_id,
    const AuxiliaryHistoryGCAuthorization& authorization,
    const AuxiliaryHistoryGCFrontier& frontier,
    const uint256& completed_intent_id)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{WATERMARK_ID_DOMAIN.data(),
                              WATERMARK_ID_DOMAIN.size()}));
    writer << sequence << configuration_id << authorization << frontier
           << completed_intent_id;
    return writer.GetHash();
}

bool ComponentDominates(
    const std::optional<AuxiliaryHistoryGCComponent>& previous,
    const std::optional<AuxiliaryHistoryGCComponent>& next)
{
    if (!previous) return true;
    if (!next || next->version != previous->version ||
        next->monotonic_position < previous->monotonic_position) {
        return false;
    }
    return next->monotonic_position != previous->monotonic_position ||
           *next == *previous;
}

bool PQFrontierAdvances(const AuxiliaryHistoryGCFrontier& previous,
                        const AuxiliaryHistoryGCFrontier& next)
{
    if (!next.pq_registry) return false;
    return !previous.pq_registry ||
           next.pq_registry->monotonic_position >
               previous.pq_registry->monotonic_position;
}

bool ManifestMatchesPQAdvance(
    const AuxiliaryHistoryGCFrontier& previous,
    const AuxiliaryHistoryGCIntentTarget& target)
{
    return PQFrontierAdvances(previous, target.frontier) ==
           target.pq_erase_manifest.has_value();
}

bool ManifestMatchesInitialFrontier(
    const AuxiliaryHistoryGCIntentTarget& target)
{
    return target.frontier.pq_registry.has_value() ==
           target.pq_erase_manifest.has_value();
}

bool FrontierDominates(const AuxiliaryHistoryGCFrontier& previous,
                       const AuxiliaryHistoryGCFrontier& next)
{
    return ComponentDominates(previous.dmn, next.dmn) &&
           ComponentDominates(previous.pq_registry, next.pq_registry);
}

bool AuthorizationStrictlyAdvances(
    const AuxiliaryHistoryGCAuthorization& previous,
    const AuxiliaryHistoryGCAuthorization& next)
{
    // SYSCOIN: This journal proves only durable local monotonicity. Before an
    // erase or resume, the store-specific caller must independently prove
    // authorizer ancestry and decode both retained closure payloads.
    if (next.block.height <= previous.block.height) return false;
    return static_cast<uint8_t>(next.source) >=
           static_cast<uint8_t>(previous.source);
}

bool IsValidIntent(const AuxiliaryHistoryGCIntent& intent,
                   const AuxiliaryHistoryGCDeployment& deployment)
{
    return intent.sequence > 0 &&
           intent.configuration_id == deployment.configuration_id &&
           intent.target.IsValid() && !intent.intent_id.IsNull() &&
           intent.intent_id == GetIntentId(
               intent.sequence, intent.configuration_id, intent.target);
}

bool IsValidWatermark(const AuxiliaryHistoryGCWatermark& watermark,
                      const AuxiliaryHistoryGCDeployment& deployment)
{
    return watermark.sequence > 0 &&
           watermark.configuration_id == deployment.configuration_id &&
           watermark.authorization.IsValid() &&
           watermark.frontier.IsValid() &&
           !watermark.completed_intent_id.IsNull() &&
           !watermark.watermark_id.IsNull() &&
           watermark.watermark_id == GetWatermarkId(
               watermark.sequence, watermark.configuration_id,
               watermark.authorization, watermark.frontier,
               watermark.completed_intent_id);
}

bool IntentAdvancesWatermark(
    const AuxiliaryHistoryGCWatermark& watermark,
    const AuxiliaryHistoryGCIntent& intent)
{
    return watermark.sequence != std::numeric_limits<uint64_t>::max() &&
           intent.sequence == watermark.sequence + 1 &&
           AuthorizationStrictlyAdvances(watermark.authorization,
                                         intent.target.authorization) &&
           FrontierDominates(watermark.frontier,
                             intent.target.frontier) &&
           ManifestMatchesPQAdvance(watermark.frontier,
                                    intent.target) &&
           watermark.frontier != intent.target.frontier;
}

AuxiliaryHistoryGCWatermark WatermarkFromIntent(
    const AuxiliaryHistoryGCIntent& intent)
{
    AuxiliaryHistoryGCWatermark watermark;
    watermark.sequence = intent.sequence;
    watermark.configuration_id = intent.configuration_id;
    watermark.authorization = intent.target.authorization;
    watermark.frontier = intent.target.frontier;
    watermark.completed_intent_id = intent.intent_id;
    watermark.watermark_id = GetWatermarkId(
        watermark.sequence, watermark.configuration_id,
        watermark.authorization, watermark.frontier,
        watermark.completed_intent_id);
    return watermark;
}

} // namespace

bool AuxiliaryHistoryGCAuthorization::IsValid() const noexcept
{
    const auto source_value{static_cast<uint8_t>(source)};
    return source_value <= static_cast<uint8_t>(
               AuxiliaryHistoryGCAuthorizationSource::
                   ENFORCED_DURABLE_CHAINLOCK) &&
           block.IsValid();
}

bool DMNInverseGCClosure::IsValid() const noexcept
{
    return format_guard == FORMAT_GUARD && version == VERSION &&
           boundary.IsValid() &&
           !boundary_state_hash.IsNull() &&
           !inverse_history_commitment.IsNull() &&
           !inverse_record_hash.IsNull();
}

std::optional<std::vector<unsigned char>>
EncodeDMNInverseGCClosure(const DMNInverseGCClosure& closure)
{
    if (!closure.IsValid()) return std::nullopt;
    DataStream stream;
    stream << closure;
    if (stream.size() != DMNInverseGCClosure::SERIALIZED_SIZE) {
        return std::nullopt;
    }
    const auto bytes{MakeUCharSpan(stream)};
    return std::vector<unsigned char>{bytes.begin(), bytes.end()};
}

std::optional<DMNInverseGCClosure>
DecodeDMNInverseGCClosure(Span<const unsigned char> payload)
{
    if (payload.size() != DMNInverseGCClosure::SERIALIZED_SIZE) {
        return std::nullopt;
    }
    try {
        DataStream stream{payload};
        DMNInverseGCClosure closure;
        stream >> closure;
        if (!stream.empty() || !closure.IsValid()) return std::nullopt;
        return closure;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool AuxiliaryHistoryGCComponent::IsValid() const noexcept
{
    return version > 0 && monotonic_position > 0 && !closure.empty() &&
           closure.size() <= MAX_CLOSURE_BYTES;
}

bool AuxiliaryHistoryGCFrontier::IsValid() const noexcept
{
    return (dmn || pq_registry) && (!dmn || dmn->IsValid()) &&
           (!pq_registry || pq_registry->IsValid());
}

bool AuxiliaryHistoryGCManifest::IsValid() const noexcept
{
    return version > 0 && payload.size() <= MAX_MANIFEST_BYTES;
}

bool AuxiliaryHistoryGCIntentTarget::IsValid() const noexcept
{
    return authorization.IsValid() && frontier.IsValid() &&
           (frontier.pq_registry || !pq_erase_manifest) &&
           (!pq_erase_manifest || pq_erase_manifest->IsValid());
}

AuxiliaryHistoryGCDeployment
MakeAuxiliaryHistoryGCDeployment(const Consensus::Params& consensus)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{CONFIGURATION_DOMAIN.data(),
                              CONFIGURATION_DOMAIN.size()}));
    writer << consensus.hashGenesisBlock
           << static_cast<int32_t>(consensus.DIP0003Height)
           << static_cast<int32_t>(consensus.DIP0003EnforcementHeight)
           << static_cast<int32_t>(consensus.nPQLegacyAnchorHeight)
           << consensus.hashPQLegacyAnchorBlock
           << consensus.hashPQLegacyMNState
           << consensus.hashPQLegacyPQRegistryState
           << static_cast<int32_t>(consensus.nPQChainLockAnchorHeight)
           << consensus.hashPQChainLockAnchorBlock
           << static_cast<int32_t>(consensus.nPQPreparationHeight)
           << static_cast<int32_t>(consensus.nPQChainLockEpochOrigin)
           << consensus.nPQRegistrationCutoffBlocks
           << static_cast<int32_t>(consensus.nPQRosterSnapshotLag)
           << consensus.nPQFutureHorizonEpochs
           << static_cast<int32_t>(consensus.nPQBTCCCandidateOrigin)
           << static_cast<int32_t>(consensus.nPQBTCCNEVMInjectionLag)
           << static_cast<int32_t>(consensus.nPQBTCCReceiptAnchorHeight)
           << consensus.hashPQBTCCReceiptAnchorBlock
           << static_cast<int32_t>(
                  consensus.nPQBTCCReceiptAnchorCursorHeight)
           << consensus.hashPQBTCCReceiptAnchorCursorSysBlock
           << consensus.hashPQBTCCReceiptAnchorCursorBTCBlock
           << consensus.hashPQBTCCReceiptAnchorState
           << static_cast<int32_t>(consensus.nCLReceiptStartBlock)
           << CDeterministicMNListInverse::VERSION
           << CDeterministicMNManager::LIST_CACHE_SIZE
           << llmq::pq::PQ_REGISTRY_DISK_VERSION
           << llmq::pq::PQ_REGISTRY_CHECKPOINT_INTERVAL;
    return AuxiliaryHistoryGCDeployment{
        consensus.hashGenesisBlock, writer.GetHash()};
}

fs::path AuxiliaryHistoryGCDBPath(const fs::path& evo_db_path)
{
    if (evo_db_path.empty()) return "evodb_aux_gc";
    return evo_db_path.parent_path() /
        (fs::PathToString(evo_db_path.filename()) + "_aux_gc");
}

struct AuxiliaryHistoryGCJournal::Impl {
    Impl(DBParams params, AuxiliaryHistoryGCDeployment deployment_in)
        : deployment{std::move(deployment_in)},
          db{MakeDBParams(std::move(params))}
    {
        if (!deployment.IsValid()) {
            throw std::runtime_error{
                "invalid auxiliary-history GC deployment binding"};
        }
        Initialize();
    }

    void Initialize() EXCLUSIVE_LOCKS_REQUIRED(!mutex)
    {
        LOCK(mutex);
        bool any{false};
        bool found_schema{false};
        bool found_watermark{false};
        bool found_intent{false};
        DiskSchema schema;
        DiskWatermark disk_watermark;
        DiskIntent disk_intent;

        std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
        if (!iterator) {
            throw std::runtime_error{
                "failed to open auxiliary-history GC iterator"};
        }
        for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
            any = true;
            DiskKey key;
            if (!iterator->GetKey(key)) {
                throw std::runtime_error{
                    "corrupt auxiliary-history GC key"};
            }
            switch (key.type) {
            case DB_SCHEMA_KEY:
                if (found_schema || !iterator->GetValue(schema)) {
                    throw std::runtime_error{
                        "corrupt auxiliary-history GC schema"};
                }
                found_schema = true;
                break;
            case DB_WATERMARK_KEY:
                if (found_watermark ||
                    !iterator->GetValue(disk_watermark)) {
                    throw std::runtime_error{
                        "corrupt auxiliary-history GC watermark"};
                }
                found_watermark = true;
                break;
            case DB_INTENT_KEY:
                if (found_intent || !iterator->GetValue(disk_intent)) {
                    throw std::runtime_error{
                        "corrupt auxiliary-history GC intent"};
                }
                found_intent = true;
                break;
            default:
                throw std::runtime_error{
                    "unknown auxiliary-history GC key"};
            }
        }

        const DiskSchema expected{
            AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION, SCHEMA_GUARD,
            deployment.genesis_hash, deployment.configuration_id,
            AuxiliaryHistoryGCComponent::MAX_CLOSURE_BYTES,
            AuxiliaryHistoryGCManifest::MAX_MANIFEST_BYTES};
        if (!any) {
            if (!db.Write(DiskKey{DB_SCHEMA_KEY}, expected,
                          /*fSync=*/true)) {
                throw std::runtime_error{
                    "failed to initialize auxiliary-history GC schema"};
            }
            return;
        }
        const bool static_schema_matches{
            found_schema && schema.version == expected.version &&
            schema.guard == expected.guard &&
            schema.genesis_hash == expected.genesis_hash &&
            schema.max_closure_bytes == expected.max_closure_bytes &&
            schema.max_manifest_bytes == expected.max_manifest_bytes};
        if (!static_schema_matches) {
            throw std::runtime_error{
                "auxiliary-history GC deployment/schema mismatch"};
        }
        if (schema.configuration_id != expected.configuration_id) {
            // SYSCOIN: A release-disabled node may have opened this database
            // before deployment constants were pinned. With no durable work,
            // a synchronous rebind is safe; any progress makes it fail closed.
            if (found_watermark || found_intent ||
                !db.Write(DiskKey{DB_SCHEMA_KEY}, expected,
                          /*fSync=*/true)) {
                throw std::runtime_error{
                    "auxiliary-history GC configuration mismatch"};
            }
        }
        if (found_watermark) {
            if (disk_watermark.version !=
                    AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION ||
                disk_watermark.guard != WATERMARK_GUARD ||
                !IsValidWatermark(disk_watermark.watermark,
                                  deployment)) {
                throw std::runtime_error{
                    "invalid auxiliary-history GC watermark"};
            }
            state.watermark = std::move(disk_watermark.watermark);
        }
        if (found_intent) {
            if (disk_intent.version !=
                    AuxiliaryHistoryGCJournal::DB_FORMAT_VERSION ||
                disk_intent.guard != INTENT_GUARD ||
                !IsValidIntent(disk_intent.intent, deployment) ||
                (state.watermark
                     ? !IntentAdvancesWatermark(*state.watermark,
                                                disk_intent.intent)
                     : disk_intent.intent.sequence != 1 ||
                           !ManifestMatchesInitialFrontier(
                               disk_intent.intent.target))) {
                throw std::runtime_error{
                    "invalid auxiliary-history GC pending intent"};
            }
            state.intent = std::move(disk_intent.intent);
        }
    }

    const AuxiliaryHistoryGCDeployment deployment;
    mutable Mutex mutex;
    CDBWrapper db GUARDED_BY(mutex);
    AuxiliaryHistoryGCState state GUARDED_BY(mutex);
    std::optional<AuxiliaryHistoryGCJournalResult> failure
        GUARDED_BY(mutex);
};

AuxiliaryHistoryGCJournal::AuxiliaryHistoryGCJournal(
    DBParams evo_db_params,
    AuxiliaryHistoryGCDeployment deployment)
    : m_impl{std::make_unique<Impl>(std::move(evo_db_params),
                                   std::move(deployment))}
{
}

AuxiliaryHistoryGCJournal::~AuxiliaryHistoryGCJournal() = default;

AuxiliaryHistoryGCJournalResult AuxiliaryHistoryGCJournal::Begin(
    const AuxiliaryHistoryGCIntentTarget& target,
    uint256* intent_id)
{
    LOCK(m_impl->mutex);
    if (intent_id != nullptr) intent_id->SetNull();
    if (m_impl->failure) return *m_impl->failure;
    if (!target.IsValid()) {
        return AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT;
    }
    if (m_impl->state.intent) {
        if (m_impl->state.intent->target != target) {
            return AuxiliaryHistoryGCJournalResult::BUSY;
        }
        if (intent_id != nullptr) {
            *intent_id = m_impl->state.intent->intent_id;
        }
        return AuxiliaryHistoryGCJournalResult::EXISTING;
    }
    uint64_t sequence{1};
    if (m_impl->state.watermark) {
        const auto& watermark{*m_impl->state.watermark};
        if (watermark.frontier == target.frontier) {
            if (GetIntentId(watermark.sequence,
                            m_impl->deployment.configuration_id,
                            target) != watermark.completed_intent_id) {
                return AuxiliaryHistoryGCJournalResult::NON_MONOTONIC;
            }
            if (intent_id != nullptr) {
                *intent_id = watermark.completed_intent_id;
            }
            return AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE;
        }
        if (!AuthorizationStrictlyAdvances(watermark.authorization,
                                           target.authorization) ||
            !FrontierDominates(watermark.frontier, target.frontier) ||
            !ManifestMatchesPQAdvance(watermark.frontier, target) ||
            watermark.frontier == target.frontier ||
            watermark.sequence == std::numeric_limits<uint64_t>::max()) {
            return AuxiliaryHistoryGCJournalResult::NON_MONOTONIC;
        }
        sequence = watermark.sequence + 1;
    } else if (!ManifestMatchesInitialFrontier(target)) {
        return AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT;
    }

    AuxiliaryHistoryGCIntent intent;
    intent.sequence = sequence;
    intent.configuration_id = m_impl->deployment.configuration_id;
    intent.target = target;
    intent.intent_id = GetIntentId(
        intent.sequence, intent.configuration_id, intent.target);
    if (!IsValidIntent(intent, m_impl->deployment)) {
        return AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT;
    }
    try {
        if (!m_impl->db.Write(DiskKey{DB_INTENT_KEY},
                              DiskIntent{
                                  DB_FORMAT_VERSION, intent, INTENT_GUARD},
                              /*fSync=*/true)) {
            m_impl->failure = AuxiliaryHistoryGCJournalResult::DB_ERROR;
            return *m_impl->failure;
        }
    } catch (const std::exception&) {
        m_impl->failure = AuxiliaryHistoryGCJournalResult::DB_ERROR;
        return *m_impl->failure;
    }
    m_impl->state.intent = intent;
    if (intent_id != nullptr) *intent_id = intent.intent_id;
    return AuxiliaryHistoryGCJournalResult::STARTED;
}

AuxiliaryHistoryGCJournalResult AuxiliaryHistoryGCJournal::Complete(
    const uint256& intent_id)
{
    LOCK(m_impl->mutex);
    if (m_impl->failure) return *m_impl->failure;
    if (intent_id.IsNull()) {
        return AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT;
    }
    if (!m_impl->state.intent) {
        return m_impl->state.watermark &&
                m_impl->state.watermark->completed_intent_id == intent_id
            ? AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE
            : AuxiliaryHistoryGCJournalResult::MISMATCH;
    }
    if (m_impl->state.intent->intent_id != intent_id) {
        return AuxiliaryHistoryGCJournalResult::MISMATCH;
    }

    const auto watermark{WatermarkFromIntent(*m_impl->state.intent)};
    if (!IsValidWatermark(watermark, m_impl->deployment)) {
        m_impl->failure = AuxiliaryHistoryGCJournalResult::CORRUPT;
        return *m_impl->failure;
    }
    try {
        CDBBatch batch{m_impl->db};
        batch.Write(DiskKey{DB_WATERMARK_KEY},
                    DiskWatermark{
                        DB_FORMAT_VERSION, watermark, WATERMARK_GUARD});
        batch.Erase(DiskKey{DB_INTENT_KEY});
        if (!m_impl->db.WriteBatch(batch, /*fSync=*/true)) {
            m_impl->failure = AuxiliaryHistoryGCJournalResult::DB_ERROR;
            return *m_impl->failure;
        }
    } catch (const std::exception&) {
        m_impl->failure = AuxiliaryHistoryGCJournalResult::DB_ERROR;
        return *m_impl->failure;
    }
    m_impl->state.watermark = watermark;
    m_impl->state.intent.reset();
    return AuxiliaryHistoryGCJournalResult::COMPLETED;
}

AuxiliaryHistoryGCState AuxiliaryHistoryGCJournal::GetState() const
{
    LOCK(m_impl->mutex);
    return m_impl->state;
}

std::optional<AuxiliaryHistoryGCAuthorization>
AuxiliaryHistoryGCJournal::HighestAuthorization() const
{
    LOCK(m_impl->mutex);
    if (m_impl->state.intent) {
        return m_impl->state.intent->target.authorization;
    }
    if (m_impl->state.watermark) {
        return m_impl->state.watermark->authorization;
    }
    return std::nullopt;
}

bool AuxiliaryHistoryGCJournal::IsHealthy() const
{
    LOCK(m_impl->mutex);
    return !m_impl->failure.has_value();
}

} // namespace evo
