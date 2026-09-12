// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_global_auth.h>

#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <cassert>
#include <vector>

using namespace llmq::pq;

FUZZ_TARGET(pq_governance_auth_decode)
{
    const std::vector<unsigned char> input{buffer.begin(), buffer.end()};
    GovernanceAuthorization authorization;
    if (!DecodeGovernanceAuthorization(input, authorization)) return;

    assert(authorization.IsStructurallyValid());
    std::vector<unsigned char> encoded;
    assert(EncodeGovernanceAuthorization(authorization, encoded));
    assert(encoded == input);
}
