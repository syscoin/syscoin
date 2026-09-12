// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_BTCHEADER_STATE_H
#define SYSCOIN_NODE_BTCHEADER_STATE_H

#include <string>
#include <vector>

// SYSCOIN: Keep the managed-backend default with its narrow state API so the
// Bitcoin-view policy does not need to import the validation implementation.
inline constexpr bool DEFAULT_BTC_HEADER_MANAGED{true};

/**
 * SYSCOIN: Copy the managed bitcoin-cli base argv after startup has claimed
 * the helper. Keeping this narrow state boundary outside validation.h lets
 * the Bitcoin-view policy operate without importing the validation module.
 */
bool GetManagedBTCHeaderRPCCommandArgs(std::vector<std::string>& args_out);

#endif // SYSCOIN_NODE_BTCHEADER_STATE_H
