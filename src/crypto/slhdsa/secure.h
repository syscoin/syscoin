// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CRYPTO_SLHDSA_SECURE_H
#define SYSCOIN_CRYPTO_SLHDSA_SECURE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Overwrite secret material in a way that cannot be removed as a dead store. */
void syscoin_slhdsa_secure_zero(void* ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SYSCOIN_CRYPTO_SLHDSA_SECURE_H
