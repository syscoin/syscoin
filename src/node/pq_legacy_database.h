// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PQ_LEGACY_DATABASE_H
#define BITCOIN_NODE_PQ_LEGACY_DATABASE_H

class CDBWrapper;

namespace node {

enum class NEVMRootSchema {
    EMPTY,
    LEGACY,
    CURRENT,
    CORRUPT,
};

/**
 * Inspect an already-open roots database without initializing or changing it.
 * LEGACY requires every application record to have the exact old root layout.
 * EMPTY provides no legacy provenance. CURRENT recognizes schema version 1;
 * the ordinary typed database remains responsible for its record validation.
 * Unsupported formats and iterator/database errors return CORRUPT.
 * The caller must exclude concurrent writes and distinguish a missing path
 * before opening the wrapper, which can create a database itself.
 */
NEVMRootSchema InspectNEVMRootSchema(CDBWrapper& db);

} // namespace node

#endif // BITCOIN_NODE_PQ_LEGACY_DATABASE_H
