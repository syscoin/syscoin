// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_staging_store.h>

#include <hash.h>

#include <algorithm>
#include <exception>
#include <ios>
#include <limits>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

constexpr uint8_t DB_SCHEMA_KEY{0xa0};
constexpr uint8_t DB_STATE_KEY{0xa1};
constexpr uint8_t DB_ROW_PREFIX{0xa2};
constexpr uint8_t DB_RESPONSE_PREFIX{0xa3};
constexpr uint8_t DB_SUMMARY_PREFIX{0xa4};
constexpr uint32_t SCHEMA_GUARD{0x50415331}; // "PAS1"
constexpr uint32_t STATE_GUARD{0x50415354}; // "PAST"
constexpr uint32_t ROW_GUARD{0x50415231}; // "PAR1"
constexpr uint32_t RESPONSE_GUARD{0x50415031}; // "PAP1"
constexpr uint32_t SUMMARY_GUARD{0x50414631}; // "PAF1"
constexpr std::string_view SCHEMA_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_STAGING_SCHEMA_V1"};
constexpr std::string_view STATE_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_STAGING_STATE_V1"};
constexpr std::string_view ROW_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_STAGING_ROW_V1"};
constexpr std::string_view RESPONSE_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_STAGING_RESPONSE_V1"};
constexpr std::string_view SUMMARY_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_STAGING_SUMMARY_V1"};
// Active and retained epochs can each hold one summary per row; only the
// active epoch can additionally own the bounded open-row response set.
constexpr std::size_t MAX_PERSISTED_RECORDS{
    2 + 2 * PAYMENT_AUDIT_ROW_COUNT +
    PaymentAuditStagingStore::MAX_OPEN_ROWS * (1 + QUORUM_SIZE)};

using RowKey = std::pair<uint32_t, uint8_t>;

void WriteDomain(HashWriter& writer, std::string_view domain)
{
    writer.write(AsBytes(Span{domain.data(), domain.size()}));
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member) noexcept
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member) noexcept
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

bool IsSubset(const QuorumBitmap& subset,
              const QuorumBitmap& superset) noexcept
{
    for (std::size_t i{0}; i < subset.size(); ++i) {
        if ((subset[i] & static_cast<uint8_t>(~superset[i])) != 0) {
            return false;
        }
    }
    return true;
}

struct DiskKey {
    uint8_t type{0};
    uint32_t epoch{0};
    uint8_t row_index{0};
    uint16_t member_index{0};

    SERIALIZE_METHODS(DiskKey, obj)
    {
        READWRITE(obj.type, obj.epoch, obj.row_index, obj.member_index);
    }
};

DiskKey SchemaKey()
{
    return DiskKey{DB_SCHEMA_KEY};
}

DiskKey StateKey()
{
    return DiskKey{DB_STATE_KEY};
}

DiskKey RowDiskKey(const RowKey& key)
{
    return DiskKey{DB_ROW_PREFIX, key.first, key.second, 0};
}

DiskKey ResponseDiskKey(const RowKey& key, uint16_t member)
{
    return DiskKey{DB_RESPONSE_PREFIX, key.first, key.second, member};
}

DiskKey SummaryDiskKey(const RowKey& key)
{
    return DiskKey{DB_SUMMARY_PREFIX, key.first, key.second, 0};
}

struct DiskSchema {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{SCHEMA_GUARD};
    uint256 genesis_hash;
    uint16_t audit_version{PAYMENT_AUDIT_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    uint16_t child_usage_cap{SCHEDULED_WOTS_USAGE_CAP};
    uint32_t child_signature_size{CHILD_SIGNATURE_SIZE};
    uint32_t response_wire_size{PaymentAuditResponse::WIRE_SIZE};
    uint8_t row_count{PAYMENT_AUDIT_ROW_COUNT};
    uint8_t max_open_rows{PaymentAuditStagingStore::MAX_OPEN_ROWS};
    uint256 checksum;

    SERIALIZE_METHODS(DiskSchema, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.genesis_hash,
                  obj.audit_version, obj.child_profile,
                  obj.child_usage_cap, obj.child_signature_size,
                  obj.response_wire_size, obj.row_count,
                  obj.max_open_rows, obj.checksum);
    }

    friend bool operator==(const DiskSchema&, const DiskSchema&) = default;
};

uint256 GetSchemaChecksum(const DiskSchema& schema)
{
    DiskSchema unhashed{schema};
    unhashed.checksum.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, SCHEMA_DOMAIN);
    writer << unhashed;
    return writer.GetHash();
}

DiskSchema MakeSchema(const uint256& genesis_hash)
{
    DiskSchema schema;
    schema.genesis_hash = genesis_hash;
    schema.checksum = GetSchemaChecksum(schema);
    return schema;
}

struct DiskState {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{STATE_GUARD};
    uint8_t has_active_epoch{0};
    uint32_t active_epoch{0};
    uint8_t has_retained_epoch{0};
    uint32_t retained_epoch{0};
    uint256 checksum;

    SERIALIZE_METHODS(DiskState, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.has_active_epoch,
                  obj.active_epoch, obj.has_retained_epoch,
                  obj.retained_epoch, obj.checksum);
    }
};

uint256 GetStateChecksum(const uint256& genesis_hash,
                         const DiskState& state)
{
    DiskState unhashed{state};
    unhashed.checksum.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, STATE_DOMAIN);
    writer << genesis_hash << unhashed;
    return writer.GetHash();
}

DiskState MakeState(const uint256& genesis_hash,
                    const std::optional<uint32_t>& active_epoch,
                    const std::optional<uint32_t>& retained_epoch)
{
    DiskState state;
    if (active_epoch) {
        state.has_active_epoch = 1;
        state.active_epoch = *active_epoch;
    }
    if (retained_epoch) {
        state.has_retained_epoch = 1;
        state.retained_epoch = *retained_epoch;
    }
    state.checksum = GetStateChecksum(genesis_hash, state);
    return state;
}

bool IsStateValid(const uint256& genesis_hash, const DiskState& state)
{
    return state.format_version ==
               PaymentAuditStagingStore::DB_FORMAT_VERSION &&
           state.guard == STATE_GUARD && state.has_active_epoch <= 1 &&
           state.has_retained_epoch <= 1 &&
           (!state.has_retained_epoch ||
            (state.has_active_epoch && state.retained_epoch !=
                                           std::numeric_limits<uint32_t>::max() &&
             state.retained_epoch + 1 == state.active_epoch)) &&
           state.checksum == GetStateChecksum(genesis_hash, state);
}

struct DiskRow {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{ROW_GUARD};
    PaymentAuditHave expected;
    int32_t deadline_height{-1};
    uint256 response_block_hash;
    QuorumBitmap subject_valid_members{};
    uint8_t response_advance{static_cast<uint8_t>(BTCCAdvance::ADVANCE)};
    QuorumBitmap available_members{};
    uint256 checksum;

    SERIALIZE_METHODS(DiskRow, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.expected,
                  obj.deadline_height, obj.response_block_hash,
                  obj.subject_valid_members, obj.response_advance,
                  obj.available_members, obj.checksum);
    }
};

uint256 GetRowChecksum(const uint256& genesis_hash, const DiskRow& row)
{
    DiskRow unhashed{row};
    unhashed.checksum.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, ROW_DOMAIN);
    writer << genesis_hash << unhashed;
    return writer.GetHash();
}

DiskRow MakeDiskRow(const uint256& genesis_hash,
                    const PaymentAuditStagingRow& row,
                    const QuorumBitmap& available_members)
{
    DiskRow disk;
    disk.expected = row.expected;
    disk.deadline_height = row.deadline_height;
    disk.response_block_hash = row.response_block_hash;
    disk.subject_valid_members = row.subject_valid_members;
    disk.response_advance = static_cast<uint8_t>(row.response_advance);
    disk.available_members = available_members;
    disk.checksum = GetRowChecksum(genesis_hash, disk);
    return disk;
}

struct DiskResponse {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{RESPONSE_GUARD};
    uint32_t epoch{0};
    uint8_t row_index{0};
    uint16_t member_index{0};
    PaymentAuditResponse response;
    uint256 checksum;

    SERIALIZE_METHODS(DiskResponse, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.epoch,
                  obj.row_index, obj.member_index, obj.response,
                  obj.checksum);
    }
};

uint256 GetResponseChecksum(const uint256& genesis_hash,
                            const DiskResponse& response)
{
    DiskResponse unhashed{response};
    unhashed.checksum.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, RESPONSE_DOMAIN);
    writer << genesis_hash << unhashed;
    return writer.GetHash();
}

DiskResponse MakeDiskResponse(const uint256& genesis_hash,
                              const RowKey& key,
                              uint16_t member,
                              const PaymentAuditResponse& response)
{
    DiskResponse disk;
    disk.epoch = key.first;
    disk.row_index = key.second;
    disk.member_index = member;
    disk.response = response;
    disk.checksum = GetResponseChecksum(genesis_hash, disk);
    return disk;
}

struct DiskSummary {
    uint32_t format_version{PaymentAuditStagingStore::DB_FORMAT_VERSION};
    uint32_t guard{SUMMARY_GUARD};
    PaymentAuditHave identity;
    int32_t deadline_height{-1};
    uint256 response_block_hash;
    uint256 deadline_block_hash;
    QuorumBitmap subject_valid_members{};
    QuorumBitmap locally_observed_members{};
    uint8_t response_advance{static_cast<uint8_t>(BTCCAdvance::ADVANCE)};
    uint256 checksum;

    SERIALIZE_METHODS(DiskSummary, obj)
    {
        READWRITE(obj.format_version, obj.guard, obj.identity,
                  obj.deadline_height, obj.response_block_hash,
                  obj.deadline_block_hash, obj.subject_valid_members,
                  obj.locally_observed_members, obj.response_advance,
                  obj.checksum);
    }
};

uint256 GetSummaryChecksum(const uint256& genesis_hash,
                           const DiskSummary& summary)
{
    DiskSummary unhashed{summary};
    unhashed.checksum.SetNull();
    HashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, SUMMARY_DOMAIN);
    writer << genesis_hash << unhashed;
    return writer.GetHash();
}

DiskSummary MakeDiskSummary(
    const uint256& genesis_hash,
    const PaymentAuditFrozenRowSummary& summary)
{
    DiskSummary disk;
    disk.identity = summary.identity;
    disk.deadline_height = summary.deadline_height;
    disk.response_block_hash = summary.response_block_hash;
    disk.deadline_block_hash = summary.deadline_block_hash;
    disk.subject_valid_members = summary.subject_valid_members;
    disk.locally_observed_members = summary.locally_observed_members;
    disk.response_advance = static_cast<uint8_t>(summary.response_advance);
    disk.checksum = GetSummaryChecksum(genesis_hash, disk);
    return disk;
}

PaymentAuditFrozenRowSummary FromDiskSummary(const DiskSummary& disk)
{
    return PaymentAuditFrozenRowSummary{
        disk.identity,
        disk.deadline_height,
        disk.response_block_hash,
        disk.deadline_block_hash,
        disk.subject_valid_members,
        disk.locally_observed_members,
        static_cast<BTCCAdvance>(disk.response_advance)};
}

bool IsExpectedIdentity(const PaymentAuditHave& expected) noexcept
{
    return expected.IsStructurallyValid() &&
           expected.row_index < PAYMENT_AUDIT_ROW_COUNT &&
           expected.available_members == QuorumBitmap{};
}

bool ResponseMatchesRow(const uint256& genesis_hash,
                        const PaymentAuditStagingRow& row,
                        const PaymentAuditResponse& response) noexcept
{
    if (genesis_hash.IsNull() || !response.IsStructurallyValid() ||
        response.epoch != row.expected.epoch ||
        response.row_index != row.expected.row_index ||
        response.subject_descriptor_hash !=
            row.expected.subject_descriptor_hash ||
        response.response.transcript.height !=
            row.expected.response_height ||
        response.response.GetStatement().block_hash !=
            row.response_block_hash ||
        response.response.GetStatement().btcc_advance !=
            row.response_advance ||
        response.response.transcript.member_index >= QUORUM_SIZE ||
        !IsBitSet(row.subject_valid_members,
                  response.response.transcript.member_index)) {
        return false;
    }
    return GetLogicalChainLockId(
               genesis_hash, response.response.GetStatement()) ==
           row.expected.response_chainlock_logical_id;
}

bool SameRowIdentity(const PaymentAuditStagingRow& first,
                     const PaymentAuditStagingRow& second) noexcept
{
    return first.expected == second.expected &&
           first.deadline_height == second.deadline_height &&
           first.response_block_hash == second.response_block_hash &&
           first.subject_valid_members == second.subject_valid_members &&
           first.response_advance == second.response_advance;
}

struct OpenRowState {
    PaymentAuditStagingRow row;
    QuorumBitmap available_members{};
};

PaymentAuditOpenRowMetadata MakeOpenRowMetadata(
    const OpenRowState& state)
{
    return PaymentAuditOpenRowMetadata{
        state.row.expected,
        state.row.deadline_height,
        state.row.response_block_hash,
        state.row.subject_valid_members,
        state.available_members,
        state.row.response_advance};
}

} // namespace

bool PaymentAuditStagingRow::IsStructurallyValid(
    const uint256& genesis_hash) const noexcept
{
    if (genesis_hash.IsNull() || !IsExpectedIdentity(expected) ||
        expected.response_height < 0 ||
        deadline_height <= expected.response_height ||
        response_block_hash.IsNull() ||
        response_advance != BTCCAdvance::ADVANCE ||
        CountSet(subject_valid_members) < QUORUM_MIN_VALID ||
        CountSet(subject_valid_members) > QUORUM_SIZE ||
        responses.size() > QUORUM_SIZE) {
        return false;
    }
    for (const auto& [member, response] : responses) {
        if (member >= QUORUM_SIZE ||
            member != response.response.transcript.member_index ||
            !ResponseMatchesRow(genesis_hash, *this, response)) {
            return false;
        }
    }
    return true;
}

bool PaymentAuditFrozenRowSummary::IsStructurallyValid() const noexcept
{
    return IsExpectedIdentity(identity) && identity.response_height >= 0 &&
           deadline_height > identity.response_height &&
           !response_block_hash.IsNull() && !deadline_block_hash.IsNull() &&
           response_advance == BTCCAdvance::ADVANCE &&
           CountSet(subject_valid_members) >= QUORUM_MIN_VALID &&
           CountSet(subject_valid_members) <= QUORUM_SIZE &&
           IsSubset(locally_observed_members, subject_valid_members);
}

struct PaymentAuditStagingStore::Impl {
    Impl(fs::path path,
         uint256 genesis_hash,
         std::size_t cache_bytes,
         bool wipe,
         PaymentAuditStagingSyncHook sync_hook)
        : genesis_hash{std::move(genesis_hash)},
          schema{MakeSchema(this->genesis_hash)},
          db{DBParams{.path = std::move(path),
                      .cache_bytes = cache_bytes,
                      .memory_only = false,
                      .wipe_data = wipe,
                      .obfuscate = false}},
          sync_hook{std::move(sync_hook)}
    {
        Initialize();
    }

    void Fail(PaymentAuditStagingResult result)
    {
        failure = result;
    }

    bool ValidateBounds() const
    {
        if (!active_epoch) {
            return open_rows.empty() && summaries.empty() &&
                   !retained_epoch;
        }
        if (open_rows.size() > PaymentAuditStagingStore::MAX_OPEN_ROWS) {
            return false;
        }
        for (const auto& [key, state] : open_rows) {
            (void)state;
            if (key.first != *active_epoch) return false;
        }
        std::map<uint32_t, std::size_t> counts;
        for (const auto& [key, summary] : summaries) {
            (void)summary;
            if (++counts[key.first] > PAYMENT_AUDIT_ROW_COUNT ||
                (key.first != *active_epoch &&
                 (!retained_epoch || key.first != *retained_epoch))) {
                return false;
            }
        }
        return !retained_epoch ||
               (*retained_epoch != std::numeric_limits<uint32_t>::max() &&
                *retained_epoch + 1 == *active_epoch);
    }

    void Initialize()
    {
        if (genesis_hash.IsNull()) {
            Fail(PaymentAuditStagingResult::INVALID);
            return;
        }
        try {
            bool any{false};
            bool found_schema{false};
            bool found_state{false};
            DiskState loaded_state;
            std::vector<DiskKey> discard_open;
            std::size_t persisted_records{0};
            std::unique_ptr<CDBIterator> iterator{db.NewIterator()};
            for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
                if (++persisted_records > MAX_PERSISTED_RECORDS) {
                    Fail(PaymentAuditStagingResult::CORRUPT);
                    return;
                }
                any = true;
                DiskKey key;
                if (!iterator->GetKeyExact(key)) {
                    Fail(PaymentAuditStagingResult::CORRUPT);
                    return;
                }
                if (key.type == DB_SCHEMA_KEY) {
                    DiskSchema loaded;
                    if (key.epoch != 0 || key.row_index != 0 ||
                        key.member_index != 0 || found_schema ||
                        !iterator->GetValueExact(loaded) || loaded != schema) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                    found_schema = true;
                } else if (key.type == DB_STATE_KEY) {
                    if (key.epoch != 0 || key.row_index != 0 ||
                        key.member_index != 0 || found_state ||
                        !iterator->GetValueExact(loaded_state) ||
                        !IsStateValid(genesis_hash, loaded_state)) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                    found_state = true;
                } else if (key.type == DB_ROW_PREFIX) {
                    if (key.member_index != 0 ||
                        key.row_index >= PAYMENT_AUDIT_ROW_COUNT) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                    // An open row has no completed durability barrier. Never
                    // infer absence from it after a restart.
                    discard_open.push_back(key);
                } else if (key.type == DB_RESPONSE_PREFIX) {
                    if (key.row_index >= PAYMENT_AUDIT_ROW_COUNT ||
                        key.member_index >= QUORUM_SIZE) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                    discard_open.push_back(key);
                } else if (key.type == DB_SUMMARY_PREFIX) {
                    DiskSummary disk;
                    if (key.member_index != 0 ||
                        key.row_index >= PAYMENT_AUDIT_ROW_COUNT ||
                        !iterator->GetValueExact(disk) ||
                        disk.format_version != DB_FORMAT_VERSION ||
                        disk.guard != SUMMARY_GUARD ||
                        disk.identity.epoch != key.epoch ||
                        disk.identity.row_index != key.row_index ||
                        disk.checksum !=
                            GetSummaryChecksum(genesis_hash, disk)) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                    auto summary{FromDiskSummary(disk)};
                    if (!summary.IsStructurallyValid() ||
                        !summaries.emplace(
                             RowKey{key.epoch, key.row_index},
                             std::move(summary)).second) {
                        Fail(PaymentAuditStagingResult::CORRUPT);
                        return;
                    }
                } else {
                    Fail(PaymentAuditStagingResult::CORRUPT);
                    return;
                }
            }
            iterator->CheckStatus();
            if (!any) {
                CDBBatch batch{db};
                batch.Write(SchemaKey(), schema);
                batch.Write(StateKey(), MakeState(genesis_hash, {}, {}));
                if (!db.WriteBatch(batch, true)) {
                    Fail(PaymentAuditStagingResult::DATABASE_ERROR);
                }
                return;
            }
            if (!found_schema || !found_state) {
                Fail(PaymentAuditStagingResult::CORRUPT);
                return;
            }
            if (loaded_state.has_active_epoch) {
                active_epoch = loaded_state.active_epoch;
            }
            if (loaded_state.has_retained_epoch) {
                retained_epoch = loaded_state.retained_epoch;
            }
            if (!ValidateBounds()) {
                Fail(PaymentAuditStagingResult::CORRUPT);
                return;
            }
            if (!discard_open.empty()) {
                CDBBatch batch{db};
                for (const auto& key : discard_open) batch.Erase(key);
                if (!db.WriteBatch(batch, true)) {
                    Fail(PaymentAuditStagingResult::DATABASE_ERROR);
                }
            }
        } catch (const std::exception&) {
            Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        }
    }

    void EraseOpenRow(CDBBatch& batch,
                      const RowKey& key,
                      const OpenRowState& state)
    {
        batch.Erase(RowDiskKey(key));
        for (const auto& [member, response] : state.row.responses) {
            (void)response;
            batch.Erase(ResponseDiskKey(key, member));
        }
    }

    uint256 genesis_hash;
    DiskSchema schema;
    CDBWrapper db;
    PaymentAuditStagingSyncHook sync_hook;
    std::optional<uint32_t> active_epoch;
    std::optional<uint32_t> retained_epoch;
    std::map<RowKey, OpenRowState> open_rows;
    std::map<RowKey, PaymentAuditFrozenRowSummary> summaries;
    std::optional<PaymentAuditStagingResult> failure;
};

PaymentAuditStagingStore::PaymentAuditStagingStore(
    fs::path path,
    uint256 genesis_hash,
    std::size_t cache_bytes,
    bool wipe,
    PaymentAuditStagingSyncHook sync_hook)
    : m_genesis_hash{genesis_hash},
      m_impl{std::make_unique<Impl>(
          std::move(path), std::move(genesis_hash), cache_bytes, wipe,
          std::move(sync_hook))}
{
}

PaymentAuditStagingStore::~PaymentAuditStagingStore() = default;

bool PaymentAuditStagingStore::IsHealthy() const
{
    LOCK(m_mutex);
    return !m_impl->failure;
}

std::optional<uint32_t> PaymentAuditStagingStore::ActiveEpoch() const
{
    LOCK(m_mutex);
    return m_impl->failure ? std::nullopt : m_impl->active_epoch;
}

std::optional<uint32_t> PaymentAuditStagingStore::RetainedEpoch() const
{
    LOCK(m_mutex);
    return m_impl->failure ? std::nullopt : m_impl->retained_epoch;
}

PaymentAuditStagingResult PaymentAuditStagingStore::ActivateEpoch(
    uint32_t epoch)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    if (m_impl->active_epoch == epoch) {
        return PaymentAuditStagingResult::DUPLICATE;
    }
    try {
        std::optional<uint32_t> retained;
        if (m_impl->active_epoch &&
            *m_impl->active_epoch != std::numeric_limits<uint32_t>::max() &&
            *m_impl->active_epoch + 1 == epoch) {
            retained = *m_impl->active_epoch;
        }
        CDBBatch batch{m_impl->db};
        for (const auto& [key, state] : m_impl->open_rows) {
            m_impl->EraseOpenRow(batch, key, state);
        }
        std::vector<RowKey> erase_summaries;
        for (const auto& [key, summary] : m_impl->summaries) {
            (void)summary;
            if (key.first != epoch &&
                (!retained || key.first != *retained)) {
                batch.Erase(SummaryDiskKey(key));
                erase_summaries.push_back(key);
            }
        }
        batch.Write(StateKey(), MakeState(m_genesis_hash, epoch, retained));
        if (!m_impl->db.WriteBatch(batch, true)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        m_impl->open_rows.clear();
        for (const auto& key : erase_summaries) {
            m_impl->summaries.erase(key);
        }
        m_impl->active_epoch = epoch;
        m_impl->retained_epoch = retained;
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

PaymentAuditStagingResult PaymentAuditStagingStore::EnsureRow(
    const PaymentAuditStagingRow& row)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    if (!row.IsStructurallyValid(m_genesis_hash) ||
        !row.responses.empty()) {
        return PaymentAuditStagingResult::INVALID;
    }
    if (!m_impl->active_epoch ||
        *m_impl->active_epoch != row.expected.epoch) {
        return PaymentAuditStagingResult::WRONG_EPOCH;
    }
    const RowKey key{row.expected.epoch, row.expected.row_index};
    if (m_impl->summaries.contains(key)) {
        return PaymentAuditStagingResult::FROZEN;
    }
    if (const auto existing{m_impl->open_rows.find(key)};
        existing != m_impl->open_rows.end()) {
        return SameRowIdentity(existing->second.row, row)
                   ? PaymentAuditStagingResult::DUPLICATE
                   : PaymentAuditStagingResult::BRANCH_CONFLICT;
    }
    if (m_impl->open_rows.size() >= MAX_OPEN_ROWS) {
        return PaymentAuditStagingResult::CAPACITY_EXCEEDED;
    }
    try {
        if (!m_impl->db.Write(RowDiskKey(key),
                              MakeDiskRow(m_genesis_hash, row, {}), false)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        m_impl->open_rows.emplace(key, OpenRowState{row, {}});
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

PaymentAuditStagingResult PaymentAuditStagingStore::ReplaceRowBranch(
    const PaymentAuditStagingRow& row)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    if (!row.IsStructurallyValid(m_genesis_hash) ||
        !row.responses.empty()) {
        return PaymentAuditStagingResult::INVALID;
    }
    if (!m_impl->active_epoch ||
        *m_impl->active_epoch != row.expected.epoch) {
        return PaymentAuditStagingResult::WRONG_EPOCH;
    }
    const RowKey key{row.expected.epoch, row.expected.row_index};
    if (m_impl->summaries.contains(key)) {
        return PaymentAuditStagingResult::FROZEN;
    }
    auto existing{m_impl->open_rows.find(key)};
    if (existing == m_impl->open_rows.end()) {
        return PaymentAuditStagingResult::NOT_FOUND;
    }
    if (SameRowIdentity(existing->second.row, row)) {
        return PaymentAuditStagingResult::DUPLICATE;
    }
    try {
        CDBBatch batch{m_impl->db};
        m_impl->EraseOpenRow(batch, key, existing->second);
        batch.Write(RowDiskKey(key),
                    MakeDiskRow(m_genesis_hash, row, {}));
        if (!m_impl->db.WriteBatch(batch, false)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        existing->second = OpenRowState{row, {}};
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

PaymentAuditStagingResult PaymentAuditStagingStore::AddVerifiedResponse(
    uint32_t epoch,
    uint8_t row_index,
    int32_t observed_tip_height,
    const PaymentAuditResponse& response)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    const RowKey key{epoch, row_index};
    auto found{m_impl->open_rows.find(key)};
    if (found == m_impl->open_rows.end()) {
        return m_impl->summaries.contains(key)
                   ? PaymentAuditStagingResult::FROZEN
                   : PaymentAuditStagingResult::NOT_FOUND;
    }
    auto& state{found->second};
    auto& row{state.row};
    if (observed_tip_height >= row.deadline_height) {
        return PaymentAuditStagingResult::DEADLINE_REACHED;
    }
    if (!ResponseMatchesRow(m_genesis_hash, row, response)) {
        return PaymentAuditStagingResult::INVALID;
    }
    const uint16_t member{response.response.transcript.member_index};
    if (const auto existing{row.responses.find(member)};
        existing != row.responses.end()) {
        return existing->second == response
                   ? PaymentAuditStagingResult::DUPLICATE
                   : PaymentAuditStagingResult::INVALID;
    }
    try {
        QuorumBitmap updated_members{state.available_members};
        SetBit(updated_members, member);
        CDBBatch batch{m_impl->db};
        batch.Write(ResponseDiskKey(key, member),
                    MakeDiskResponse(m_genesis_hash, key, member,
                                     response));
        batch.Write(RowDiskKey(key),
                    MakeDiskRow(m_genesis_hash, row, updated_members));
        // The WAL append must succeed before relay, but fsync is deliberately
        // deferred to the row's single deadline barrier.
        if (!m_impl->db.WriteBatch(batch, false)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        row.responses.emplace(member, response);
        state.available_members = updated_members;
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

PaymentAuditStagingResult PaymentAuditStagingStore::DiscardOpenRow(
    uint32_t epoch,
    uint8_t row_index)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    const RowKey key{epoch, row_index};
    auto found{m_impl->open_rows.find(key)};
    if (found == m_impl->open_rows.end()) {
        return m_impl->summaries.contains(key)
                   ? PaymentAuditStagingResult::FROZEN
                   : PaymentAuditStagingResult::NOT_FOUND;
    }
    try {
        CDBBatch batch{m_impl->db};
        m_impl->EraseOpenRow(batch, key, found->second);
        // No durable conclusion is created, so the ordinary asynchronous WAL
        // ordering is sufficient. Restart also discards every open-row key.
        if (!m_impl->db.WriteBatch(batch, false)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        m_impl->open_rows.erase(found);
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

PaymentAuditStagingResult PaymentAuditStagingStore::FreezeRow(
    uint32_t epoch,
    uint8_t row_index,
    const uint256& response_block_hash,
    const uint256& deadline_block_hash)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    const RowKey key{epoch, row_index};
    if (const auto summary{m_impl->summaries.find(key)};
        summary != m_impl->summaries.end()) {
        return summary->second.response_block_hash == response_block_hash &&
                       summary->second.deadline_block_hash ==
                           deadline_block_hash
                   ? PaymentAuditStagingResult::DUPLICATE
                   : PaymentAuditStagingResult::BRANCH_CONFLICT;
    }
    auto found{m_impl->open_rows.find(key)};
    if (found == m_impl->open_rows.end()) {
        return PaymentAuditStagingResult::NOT_FOUND;
    }
    const auto& state{found->second};
    const auto& row{state.row};
    if (response_block_hash.IsNull() || deadline_block_hash.IsNull() ||
        row.response_block_hash != response_block_hash) {
        return PaymentAuditStagingResult::BRANCH_CONFLICT;
    }
    PaymentAuditFrozenRowSummary summary;
    summary.identity = row.expected;
    summary.deadline_height = row.deadline_height;
    summary.response_block_hash = row.response_block_hash;
    summary.deadline_block_hash = deadline_block_hash;
    summary.subject_valid_members = row.subject_valid_members;
    summary.response_advance = row.response_advance;
    summary.locally_observed_members = state.available_members;
    if (!summary.IsStructurallyValid()) {
        return PaymentAuditStagingResult::INVALID;
    }
    try {
        if (m_impl->sync_hook && !m_impl->sync_hook()) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        CDBBatch batch{m_impl->db};
        batch.Write(SummaryDiskKey(key),
                    MakeDiskSummary(m_genesis_hash, summary));
        m_impl->EraseOpenRow(batch, key, state);
        // This is the durability boundary: prior asynchronous response WAL
        // entries and this summary/deletion batch are ordered by one fSync.
        if (!m_impl->db.WriteBatch(batch, true)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        m_impl->open_rows.erase(found);
        m_impl->summaries.emplace(key, summary);
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

std::optional<PaymentAuditStagingRow>
PaymentAuditStagingStore::GetOpenRow(uint32_t epoch,
                                     uint8_t row_index) const
{
    LOCK(m_mutex);
    if (m_impl->failure) return std::nullopt;
    const auto found{m_impl->open_rows.find(RowKey{epoch, row_index})};
    return found == m_impl->open_rows.end()
               ? std::nullopt
               : std::optional<PaymentAuditStagingRow>{found->second.row};
}

std::vector<PaymentAuditStagingRow>
PaymentAuditStagingStore::GetOpenRows(uint32_t epoch) const
{
    LOCK(m_mutex);
    std::vector<PaymentAuditStagingRow> result;
    if (m_impl->failure) return result;
    for (const auto& [key, state] : m_impl->open_rows) {
        if (key.first == epoch) result.push_back(state.row);
    }
    return result;
}

std::optional<PaymentAuditOpenRowMetadata>
PaymentAuditStagingStore::GetOpenRowMetadata(
    uint32_t epoch,
    uint8_t row_index) const
{
    LOCK(m_mutex);
    if (m_impl->failure) return std::nullopt;
    const auto found{m_impl->open_rows.find(RowKey{epoch, row_index})};
    return found == m_impl->open_rows.end()
               ? std::nullopt
               : std::optional<PaymentAuditOpenRowMetadata>{
                     MakeOpenRowMetadata(found->second)};
}

std::vector<PaymentAuditOpenRowMetadata>
PaymentAuditStagingStore::GetOpenRowsMetadata(uint32_t epoch) const
{
    LOCK(m_mutex);
    std::vector<PaymentAuditOpenRowMetadata> result;
    if (m_impl->failure) return result;
    result.reserve(MAX_OPEN_ROWS);
    for (const auto& [key, state] : m_impl->open_rows) {
        if (key.first == epoch) {
            result.push_back(MakeOpenRowMetadata(state));
        }
    }
    return result;
}

std::optional<ChainLockStatement>
PaymentAuditStagingStore::GetVerifiedResponseStatement(
    const PaymentAuditHave& expected) const
{
    LOCK(m_mutex);
    if (m_impl->failure || !IsExpectedIdentity(expected)) {
        return std::nullopt;
    }
    const auto found{m_impl->open_rows.find(
        RowKey{expected.epoch, expected.row_index})};
    if (found == m_impl->open_rows.end() ||
        found->second.row.expected != expected ||
        found->second.row.responses.empty()) {
        return std::nullopt;
    }
    return found->second.row.responses.begin()->second.response.GetStatement();
}

std::optional<std::vector<PaymentAuditResponse>>
PaymentAuditStagingStore::GetVerifiedResponses(
    const PaymentAuditHave& expected,
    const QuorumBitmap& requested_members) const
{
    LOCK(m_mutex);
    if (m_impl->failure || !IsExpectedIdentity(expected)) {
        return std::nullopt;
    }
    const auto found{m_impl->open_rows.find(
        RowKey{expected.epoch, expected.row_index})};
    if (found == m_impl->open_rows.end() ||
        found->second.row.expected != expected) {
        return std::nullopt;
    }
    std::vector<PaymentAuditResponse> result;
    result.reserve(CountSet(requested_members));
    for (const auto& [member, response] : found->second.row.responses) {
        if (IsBitSet(requested_members, member)) {
            result.push_back(response);
        }
    }
    return result;
}

std::optional<PaymentAuditFrozenRowSummary>
PaymentAuditStagingStore::GetSummary(uint32_t epoch,
                                     uint8_t row_index) const
{
    LOCK(m_mutex);
    if (m_impl->failure) return std::nullopt;
    const auto found{m_impl->summaries.find(RowKey{epoch, row_index})};
    return found == m_impl->summaries.end()
               ? std::nullopt
               : std::optional<PaymentAuditFrozenRowSummary>{found->second};
}

std::vector<PaymentAuditFrozenRowSummary>
PaymentAuditStagingStore::GetEpochSummaries(uint32_t epoch) const
{
    LOCK(m_mutex);
    std::vector<PaymentAuditFrozenRowSummary> result;
    if (m_impl->failure) return result;
    for (uint8_t index{0}; index < PAYMENT_AUDIT_ROW_COUNT; ++index) {
        const auto found{m_impl->summaries.find(RowKey{epoch, index})};
        if (found != m_impl->summaries.end()) {
            result.push_back(found->second);
        }
    }
    return result;
}

PaymentAuditStagingResult PaymentAuditStagingStore::ClearRetainedEpoch(
    uint32_t epoch)
{
    LOCK(m_mutex);
    if (m_impl->failure) return *m_impl->failure;
    if (!m_impl->retained_epoch || *m_impl->retained_epoch != epoch) {
        return PaymentAuditStagingResult::NOT_FOUND;
    }
    try {
        CDBBatch batch{m_impl->db};
        std::vector<RowKey> erase;
        for (const auto& [key, summary] : m_impl->summaries) {
            (void)summary;
            if (key.first == epoch) {
                batch.Erase(SummaryDiskKey(key));
                erase.push_back(key);
            }
        }
        batch.Write(StateKey(), MakeState(
                                    m_genesis_hash,
                                    m_impl->active_epoch, {}));
        if (!m_impl->db.WriteBatch(batch, true)) {
            m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
            return *m_impl->failure;
        }
        for (const auto& key : erase) m_impl->summaries.erase(key);
        m_impl->retained_epoch.reset();
        return PaymentAuditStagingResult::ACCEPTED;
    } catch (const std::exception&) {
        m_impl->Fail(PaymentAuditStagingResult::DATABASE_ERROR);
        return *m_impl->failure;
    }
}

} // namespace llmq::pq
