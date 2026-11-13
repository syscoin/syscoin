// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_ZMQ_ZMQUTIL_H
#define SYSCOIN_ZMQ_ZMQUTIL_H

#include <util/strencodings.h>

#include <cstdint>
#include <string>
#include <vector>

void zmqError(const std::string& str);

/** Parse legacy count-only status and newer count/paired-Core-hash status.
 * The optional hash is display-order hex metadata, not proof of chain membership.
 */
inline bool ParseNEVMBlockInfoResponse(const std::vector<std::string>& parts, uint64_t& height, std::string& state)
{
    if (parts.size() != 2 && parts.size() != 3) {
        state = "nevm-response-invalid-parts";
        return false;
    }
    if (parts[0] != "nevmblockinfo") {
        state = "nevm-response-wrong-command";
        return false;
    }
    uint64_t parsed_height;
    if (parts[1].size() > 20 || !ParseUInt64(parts[1], &parsed_height)) {
        state = "nevm-response-unserialize";
        return false;
    }
    if (parts.size() == 3) {
        const auto& paired_hash = parts[2];
        if (paired_hash.size() != 64 || !IsHex(paired_hash)) {
            state = "nevm-response-parse-hash";
            return false;
        }
        const bool null_hash = paired_hash.find_first_not_of('0') == std::string::npos;
        if ((parsed_height == 0) != null_hash) {
            state = "nevm-response-invalid-pair";
            return false;
        }
    }
    height = parsed_height;
    state.clear();
    return true;
}

#endif // SYSCOIN_ZMQ_ZMQUTIL_H
