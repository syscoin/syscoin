// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CRYPTO_SLHDSA_SELFTEST_H
#define SYSCOIN_CRYPTO_SLHDSA_SELFTEST_H

namespace slhdsa {

/**
 * Run the module-local deterministic regression vector and negative tests.
 *
 * This performs key generation and two signatures, so callers should invoke it
 * only as an explicit diagnostic or test, not on a latency-sensitive path.
 */
[[nodiscard]] bool RunSelfTest() noexcept;

} // namespace slhdsa

#endif // SYSCOIN_CRYPTO_SLHDSA_SELFTEST_H
