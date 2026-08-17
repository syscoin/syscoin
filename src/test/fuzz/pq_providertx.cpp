// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_providertx.h>

#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <cassert>
#include <vector>

using namespace llmq::pq;

namespace {

template <typename Payload>
void AssertCanonicalRoundTrip(const std::vector<unsigned char>& input,
                              const Payload& payload)
{
    DataStream encoded;
    encoded << payload;
    const auto bytes = MakeUCharSpan(encoded);
    assert(bytes.size() == input.size());
    assert(std::equal(bytes.begin(), bytes.end(), input.begin()));
}

} // namespace

FUZZ_TARGET(pq_providertx_decode)
{
    const std::vector<unsigned char> input{buffer.begin(), buffer.end()};

    GlobalKeyTxPayload global;
    if (DecodeGlobalKeyTxPayload(input, global)) {
        assert(global.IsTriviallyValid(PQ_GLOBAL_KEY_TX_VERSION));
        AssertCanonicalRoundTrip(input, global);
    }

}
