﻿// Copyright (c) 2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NEVM_NEVM_H
#define SYSCOIN_NEVM_NEVM_H
#include <nevm/commondata.h>
#include <nevm/rlp.h>
bool VerifyProof(dev::bytesConstRef path, const dev::RLP& value, const dev::RLP& parentNodes, const dev::RLP& root); 
#endif // SYSCOIN_NEVM_NEVM_H
