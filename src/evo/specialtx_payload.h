// Copyright (c) 2018-2026 The Dash Core developers
// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_SPECIALTX_PAYLOAD_H
#define SYSCOIN_EVO_SPECIALTX_PAYLOAD_H

#include <primitives/transaction.h>
#include <streams.h>
#include <version.h>

#include <exception>
#include <vector>

// SYSCOIN: Keep the wire codec independent of special-transaction validation
// so consensus state machines can decode payloads without importing chain
// processing dependencies.
template <typename T>
inline bool GetTxPayload(const std::vector<unsigned char>& payload, T& obj)
{
    CDataStream ds(payload, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ds >> obj;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template <typename T>
inline bool GetTxPayload(const CMutableTransaction& tx, T& obj)
{
    return GetTxPayload(CTransaction(tx), obj);
}

template <typename T>
inline bool GetTxPayload(const CTransaction& tx, T& obj)
{
    std::vector<unsigned char> data;
    int output_index;
    if (!GetSyscoinData(tx, data, output_index)) return false;
    return GetTxPayload(data, obj);
}

template <typename T>
void SetTxPayload(CMutableTransaction& tx, const T& payload)
{
    std::vector<unsigned char> data;
    int output_index;
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << payload;
    CScript payload_script;
    const auto bytes{MakeUCharSpan(stream)};
    payload_script << OP_RETURN
                   << std::vector<unsigned char>(bytes.begin(), bytes.end());
    if (GetSyscoinData(CTransaction(tx), data, output_index)) {
        tx.vout[output_index].scriptPubKey = payload_script;
    } else {
        tx.vout.emplace_back(0, payload_script);
    }
}

uint256 CalcTxInputsHash(const CTransaction& tx);

#endif // SYSCOIN_EVO_SPECIALTX_PAYLOAD_H
