// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_migration.h>

#include <chain.h>
#include <consensus/pq_migration_config.h>
#include <dbwrapper.h>
#include <evo/deterministicmns.h>
#include <flatfile.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <node/pq_legacy_database.h>
#include <node/pq_legacy_upgrade.h>
#include <node/utxo_snapshot.h>
#include <txdb.h>
#include <util/fs.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace node {
namespace {
constexpr uint8_t DB_BEST_BLOCK{'B'};
constexpr uint8_t DB_HEAD_BLOCKS{'H'};
constexpr uint8_t DB_BLOCK_INDEX{'b'};
constexpr uint8_t DB_FLAG{'F'};
constexpr std::size_t INSPECTION_CACHE_BYTES{1 << 20};

template <typename Key, typename Value>
std::optional<Value> ReadExact(CDBWrapper& db, const Key& key,
                               std::size_t max_value_size)
{
    std::unique_ptr<CDBIterator> cursor{db.NewIterator()};
    cursor->Seek(key);
    cursor->CheckStatus();
    Key found;
    if (!cursor->Valid() || !cursor->GetKey(found) || found != key) {
        return std::nullopt;
    }
    Value value;
    if (!cursor->GetKeyExact(found) ||
        cursor->GetValueSize() > max_value_size ||
        !cursor->GetValueExact(value)) {
        throw dbwrapper_error("Malformed legacy database record during PQ upgrade");
    }
    return value;
}

bool Fail(bilingual_str& error, const std::string& message)
{
    error = Untranslated(message);
    return false;
}

DBParams InspectionParams(const ChainstateManager& chainman,
                          const fs::path& path)
{
    return {.path = path,
            .cache_bytes = INSPECTION_CACHE_BYTES,
            .options = chainman.m_options.block_tree_db};
}

/** Getters treat malformed markers as absent; validate exact encodings first. */
bool ReadLegacyCoinsTip(const ChainstateManager& chainman, uint256& best,
                        bilingual_str& error)
{
    const fs::path path{chainman.m_options.datadir / "chainstate"};
    if (!fs::exists(path)) return true;
    {
        CDBWrapper raw{InspectionParams(chainman, path)};
        const auto heads{ReadExact<uint8_t, std::vector<uint256>>(
            raw, DB_HEAD_BLOCKS, 1 + 2 * uint256::size())};
        if (heads && !heads->empty()) {
            return Fail(error,
                "Legacy coins have an interrupted flush. Restart the legacy "
                "Syscoin release and shut it down cleanly before the PQ upgrade.");
        }
        const auto stored{ReadExact<uint8_t, uint256>(
            raw, DB_BEST_BLOCK, uint256::size())};
        best = stored.value_or(uint256{});
    }
    CCoinsViewDB coins{InspectionParams(chainman, path),
                       chainman.m_options.coins_view};
    if (coins.NeedsUpgrade() || coins.GetBestBlock() != best ||
        !coins.GetHeadBlocks().empty()) {
        return Fail(error,
            "Legacy coins are not a clean supported chainstate. Restart the "
            "legacy Syscoin release before the PQ upgrade.");
    }
    return true;
}

bool ReadSourceIndex(BlockTreeDB& db, const uint256& hash,
                     CDiskBlockIndex& index, bilingual_str& error)
{
    if (hash.IsNull() ||
        !db.Read(std::make_pair(DB_BLOCK_INDEX, hash), index)) {
        return Fail(error,
            "The legacy block index is missing or unreadable. Restore a "
            "complete legacy datadir before the PQ upgrade.");
    }
    return true;
}

bool InspectLegacyHistory(ChainstateManager& chainman,
                          const ChainstateLoadOptions& options,
                          BlockTreeDB& db, const uint256& best,
                          const CDiskBlockIndex& tip,
                          PQLegacyUpgradeRecord& record,
                          bilingual_str& error)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto& consensus{chainman.GetConsensus()};
    const auto pruned{ReadExact<std::pair<uint8_t, std::string>, uint8_t>(
        db, {DB_FLAG, "prunedblockfiles"}, sizeof(uint8_t))};
    if (pruned && *pruned != uint8_t{'0'} && *pruned != uint8_t{'1'}) {
        return Fail(error, "Invalid legacy pruning flag; the datadir was not changed.");
    }
    if (pruned && *pruned == uint8_t{'1'}) {
        return Fail(error,
            "Automatic PQ upgrade requires the complete local block history. "
            "This legacy datadir was pruned; restore an unpruned legacy datadir "
            "before upgrading. No chainstate was erased.");
    }
    if (!tip.IsValid(BLOCK_VALID_SCRIPTS) || tip.IsAssumedValid()) {
        return Fail(error,
            "The legacy coins tip is not fully validated. Finish validation "
            "with the legacy Syscoin release before the PQ upgrade.");
    }

    record = {.genesis_hash = consensus.hashGenesisBlock,
              .activation_height = consensus.nPQActivationHeight,
              .legacy_tip_height = tip.nHeight,
              .legacy_tip_hash = best,
              .predecessor_hash = {}};
    const int32_t predecessor_height{record.activation_height - 1};
    std::unordered_map<int, uintmax_t> block_file_sizes;
    uint256 hash{best};
    CDiskBlockIndex cursor{tip};
    LogPrintf("Checking retained legacy blocks before paired PQ replay from "
              "height %d (activation %d)\n", tip.nHeight,
              record.activation_height);
    for (int32_t height{tip.nHeight}; height >= 0; --height) {
        if (options.check_interrupt && options.check_interrupt()) {
            return Fail(error, "PQ upgrade preflight interrupted; no chainstate was erased.");
        }
        if (cursor.nHeight != height ||
            (cursor.nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)) != 0 ||
            cursor.IsAssumedValid() ||
            (height > 0 && !cursor.IsValid(BLOCK_VALID_SCRIPTS))) {
            return Fail(error,
                "Legacy history is inconsistent or not fully validated. "
                "Finish validation with the legacy Syscoin release before upgrading.");
        }
        if ((cursor.nStatus & BLOCK_HAVE_DATA) == 0 || cursor.nFile < 0) {
            return Fail(error,
                "Automatic PQ upgrade requires every local block body. "
                "Legacy history is pruned or incomplete; no chainstate was erased.");
        }
        auto found{block_file_sizes.find(cursor.nFile)};
        if (found == block_file_sizes.end()) {
            const fs::path file{chainman.m_blockman.GetBlockPosFilename(
                FlatFilePos{cursor.nFile, 0})};
            if (!fs::is_regular_file(file)) {
                return Fail(error,
                    "A legacy block file is missing. Restore the complete "
                    "local block history before upgrading; no chainstate was erased.");
            }
            found = block_file_sizes.emplace(cursor.nFile, fs::file_size(file)).first;
        }
        if (uint64_t{cursor.nDataPos} + 80 > found->second) {
            return Fail(error,
                "A legacy block file is truncated. Restore the complete local "
                "block history before upgrading; no chainstate was erased.");
        }
        if (height == predecessor_height) record.predecessor_hash = hash;
        if (height == 0) {
            if (hash != consensus.hashGenesisBlock || !cursor.hashPrev.IsNull()) {
                return Fail(error,
                    "Legacy history has the wrong genesis; the datadir was not changed.");
            }
            break;
        }
        hash = cursor.hashPrev;
        if (!ReadSourceIndex(db, hash, cursor, error)) return false;
    }
    if (!record.IsValid()) {
        return Fail(error, "Cannot authenticate the legacy activation predecessor.");
    }
    return true;
}

void RequestPairedReplay(ChainstateManager& chainman,
                         ChainstateLoadOptions& options,
                         const PQLegacyUpgradeRecord& record)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    options.reindex_chainstate = true;
    options.fReindexGeth = true;
    fReindexGeth = true;
    chainman.SetPQLegacyUpgrade(record, /*rebuilding=*/true);
}
} // namespace

bool PreparePQLegacyUpgrade(ChainstateManager& chainman,
                            ChainstateLoadOptions& options,
                            const CacheSizes& cache_sizes,
                            bilingual_str& error)
{
    AssertLockHeld(cs_main);
    error = {};
    if (options.block_tree_db_in_memory || options.coins_db_in_memory) return true;
    (void)cache_sizes; // Inspection is bounded independently of the live caches.
    try {
        const auto& consensus{chainman.GetConsensus()};
        const fs::path& datadir{chainman.m_options.datadir};
        PQLegacyUpgradeJournal journal{InspectionParams(chainman, datadir / "pq-upgrade")};
        if (auto record{journal.ReadUpgrade()}) {
            if (Consensus::CheckPQActivationConfiguration(consensus) !=
                    Consensus::PQActivationResult::VALID ||
                record->genesis_hash != consensus.hashGenesisBlock ||
                record->activation_height != consensus.nPQActivationHeight) {
                return Fail(error,
                    "The saved PQ upgrade belongs to a different network or "
                    "activation height; the datadir was not changed.");
            }
            if (record->phase == PQLegacyUpgradePhase::REBUILD_REQUIRED ||
                options.reindex || options.reindex_chainstate) {
                if (!journal.RequireReplayRebuild()) {
                    return Fail(error, "Cannot persist the paired PQ rebuild request.");
                }
                record->phase = PQLegacyUpgradePhase::REBUILD_REQUIRED;
                RequestPairedReplay(chainman, options, *record);
            } else {
                chainman.SetPQLegacyUpgrade(*record, /*rebuilding=*/false);
            }
            return true;
        }
        if (journal.HasBLSFreeHistory()) return true;

        NEVMRootSchema roots{NEVMRootSchema::EMPTY};
        const fs::path root_path{datadir / "nevmtxroots"};
        if (fs::exists(root_path)) {
            CDBWrapper root_db{InspectionParams(chainman, root_path)};
            roots = InspectNEVMRootSchema(root_db);
        }
        if (roots == NEVMRootSchema::CORRUPT) {
            return Fail(error,
                "Cannot identify the NEVM roots database for PQ upgrade. "
                "Restore a valid datadir before upgrading; no chainstate was erased.");
        }
        const bool has_inverse{fs::exists(datadir / "evodb_dmn_inverse")};
        if (has_inverse && roots == NEVMRootSchema::LEGACY) {
            return Fail(error,
                "Legacy NEVM roots coexist with new inverse-journal state. "
                "The datadir's validation origin is ambiguous; automatic PQ "
                "upgrade cannot capture it and no chainstate was erased.");
        }
        if (roots == NEVMRootSchema::CURRENT || has_inverse) {
            return journal.MarkBLSFreeHistory() ||
                   Fail(error, "Cannot persist the BLS-free history origin marker.");
        }

        uint256 best;
        if (!ReadLegacyCoinsTip(chainman, best, error)) return false;
        if (best.IsNull()) {
            if (roots == NEVMRootSchema::LEGACY) {
                return Fail(error,
                    "Legacy NEVM roots have no clean coins endpoint. Restore "
                    "a complete legacy datadir before the PQ upgrade.");
            }
            return journal.MarkBLSFreeHistory() ||
                   Fail(error, "Cannot persist the BLS-free history origin marker.");
        }
        const fs::path block_index_path{datadir / "blocks" / "index"};
        if (!fs::exists(block_index_path)) {
            return Fail(error, "Legacy coins have no block index; the datadir was not changed.");
        }
        BlockTreeDB block_db{InspectionParams(chainman, block_index_path)};
        CDiskBlockIndex tip;
        if (!ReadSourceIndex(block_db, best, tip, error)) return false;
        if (roots == NEVMRootSchema::EMPTY &&
            tip.nHeight >= consensus.nNEVMStartBlock) {
            return Fail(error,
                "The existing chainstate is missing its NEVM roots. It cannot "
                "establish legacy upgrade provenance; no chainstate was erased.");
        }
        if (fs::exists(datadir / fs::u8path(
                "chainstate" + std::string{SNAPSHOT_CHAINSTATE_SUFFIX}))) {
            return Fail(error,
                "An AssumeUTXO snapshot chainstate is present. Automatic PQ "
                "upgrade requires the fully validated legacy active chainstate; "
                "finish snapshot validation with the legacy release first. "
                "No chainstate was erased.");
        }
        if (Consensus::CheckPQActivationConfiguration(consensus) !=
            Consensus::PQActivationResult::VALID) {
            return Fail(error,
                "This legacy datadir requires a PQ release with a configured "
                "activation height. The sync-only release cannot upgrade it; "
                "continue using the legacy release. No chainstate was erased.");
        }
        if (tip.nHeight < consensus.nPQActivationHeight - 1) {
            return Fail(error,
                "The legacy datadir has not reached the block before PQ "
                "activation. Continue syncing with the legacy release through "
                "activation height minus one, shut down cleanly, then upgrade.");
        }
        const fs::path dmn_path{datadir / "evodb_dmn"};
        if (!fs::exists(dmn_path)) {
            return Fail(error, "The legacy deterministic masternode snapshot is missing.");
        }
        {
            CDBWrapper dmn_db{InspectionParams(chainman, dmn_path)};
            const auto snapshot{ReadExact<uint256, CDeterministicMNList>(
                dmn_db, best,
                CDeterministicMNManager::SNAPSHOT_GC_MAX_RECORD_BYTES)};
            if (!snapshot || snapshot->IsNull() ||
                snapshot->GetBlockHash() != best ||
                snapshot->GetHeight() != tip.nHeight) {
                return Fail(error,
                    "The exact legacy coins-tip masternode snapshot is missing "
                    "or inconsistent; no chainstate was erased.");
            }
        }

        PQLegacyUpgradeRecord record;
        if (!InspectLegacyHistory(chainman, options, block_db, best, tip,
                                   record, error)) return false;
        if (!journal.CaptureLegacyUpgrade(record)) {
            return Fail(error, "Cannot persist authenticated legacy upgrade provenance.");
        }
        RequestPairedReplay(chainman, options, record);
        LogPrintf("Captured legacy PQ predecessor %s at height %d; rebuilding "
                  "Core chainstate and paired Geth from retained local blocks\n",
                  record.predecessor_hash.ToString(), record.activation_height - 1);
        return true;
    } catch (const std::exception& exception) {
        return Fail(error,
            std::string{"Cannot prepare the direct PQ upgrade: "} + exception.what());
    }
}
} // namespace node
