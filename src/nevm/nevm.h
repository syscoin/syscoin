// Copyright (c) 2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NEVM_NEVM_H
#define SYSCOIN_NEVM_NEVM_H
#include <nevm/commondata.h>
#include <nevm/rlp.h>

#include <optional>
#include <string>
#include <vector>

class CNEVMHeader;

/** Authenticate retained NEVM block bytes against an already validated Core
 * commitment before destructive local migration. This checks the header and
 * body commitments, not EVM execution or contextual consensus validity. */
bool CheckNEVMBlockPayloadIntegrity(const std::vector<uint8_t>& payload,
                                   const CNEVMHeader& commitment,
                                   std::string& error);

bool VerifyProof(dev::bytesConstRef path,
                 const dev::RLP& value,
                 const dev::RLP& parentNodes,
                 const dev::RLP& root,
                 std::optional<uint8_t>* envelope_type = nullptr);
#endif // SYSCOIN_NEVM_NEVM_H
