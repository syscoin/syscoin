﻿// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_RPC_ASSETRPC_H
#define SYSCOIN_SERVICES_RPC_ASSETRPC_H
#include <string>
bool SysTxToJSON(const CTransaction &tx, const uint256& hashBlock, UniValue &entry);
bool DecodeSyscoinRawtransaction(const CTransaction& rawTx, const uint256 &hashBlock, UniValue& output);
#endif // SYSCOIN_SERVICES_RPC_ASSETRPC_H
