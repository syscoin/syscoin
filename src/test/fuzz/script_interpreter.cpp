// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

bool CastToBool(const std::vector<unsigned char>& vch);

FUZZ_TARGET(script_interpreter)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    {
        const CScript script_code = ConsumeScript(fuzzed_data_provider);
        const std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
        if (mtx) {
            const CTransaction tx_to{*mtx};
            const unsigned int in = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
            if (in < tx_to.vin.size()) {
                (void)SignatureHash(script_code, tx_to, in, fuzzed_data_provider.ConsumeIntegral<int>(), ConsumeMoney(fuzzed_data_provider), fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0}), nullptr);
                const std::optional<CMutableTransaction> mtx_precomputed = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
                if (mtx_precomputed) {
                    const CTransaction tx_precomputed{*mtx_precomputed};
                    const PrecomputedTransactionData precomputed_transaction_data{tx_precomputed};
                    (void)SignatureHash(script_code, tx_to, in, fuzzed_data_provider.ConsumeIntegral<int>(), ConsumeMoney(fuzzed_data_provider), fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0}), &precomputed_transaction_data);
                }
            }
        }
    }
    {
        (void)CastToBool(ConsumeRandomLengthByteVector(fuzzed_data_provider));
    }
}

/** Differential fuzzing of cached ECDSA signature hashes. */
FUZZ_TARGET(sighash_cache)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const auto tx{ConsumeTransaction(provider, std::nullopt)};
    if (tx.vin.empty()) return;
    const auto input{provider.ConsumeIntegralInRange<unsigned int>(0, tx.vin.size() - 1)};
    const auto amount{ConsumeMoney(provider)};
    const auto script{ConsumeScript(provider)};
    const auto other_script{ConsumeScript(provider)};
    SigHashCache cache;
    for (int i = 0; i < 100; ++i) {
        const auto hash_type{i % 2 ? provider.ConsumeIntegral<int8_t>() : provider.ConsumeIntegral<int>()};
        const auto sigversion{provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0})};
        const auto& script_code{i % 3 ? script : other_script};
        const auto expected{SignatureHash(script_code, tx, input, hash_type, amount, sigversion)};
        Assert(expected == SignatureHash(script_code, tx, input, hash_type, amount, sigversion, nullptr, &cache));
        Assert(expected == SignatureHash(script_code, tx, input, hash_type, amount, sigversion, nullptr, &cache));
    }
}
