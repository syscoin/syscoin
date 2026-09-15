/*
 * Copyright (c) 2026 The Syscoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef SYSCOIN_CRYPTO_SLHDSA_VENDOR_SLH_WOTS_INTERNAL_H
#define SYSCOIN_CRYPTO_SLHDSA_VENDOR_SLH_WOTS_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/*
 * SYSCOIN: Private adapters for the n=16, w=16 WOTS+ and TREE primitives in
 * the pinned SLH-DSA-SHAKE-128s implementation. This is not an SLH-DSA API.
 */
#define SYSCOIN_SLH_WOTS_N 16u
#define SYSCOIN_SLH_WOTS_LEN 35u
#define SYSCOIN_SLH_WOTS_SIGNATURE_SIZE \
  (SYSCOIN_SLH_WOTS_N * SYSCOIN_SLH_WOTS_LEN)
#define SYSCOIN_SLH_WOTS_TREE_HEIGHT 8u
#define SYSCOIN_SLH_WOTS_TREE_LEAVES (1u << SYSCOIN_SLH_WOTS_TREE_HEIGHT)

int syscoin_slhdsa_vendor_wots_128s_pkgen(
  uint8_t out[SYSCOIN_SLH_WOTS_N],
  const uint8_t sk_seed[SYSCOIN_SLH_WOTS_N],
  const uint8_t pk_seed[SYSCOIN_SLH_WOTS_N], uint32_t keypair);

int syscoin_slhdsa_vendor_wots_128s_sign(
  uint8_t out[SYSCOIN_SLH_WOTS_SIGNATURE_SIZE],
  const uint8_t digest[SYSCOIN_SLH_WOTS_N],
  const uint8_t sk_seed[SYSCOIN_SLH_WOTS_N],
  const uint8_t pk_seed[SYSCOIN_SLH_WOTS_N], uint32_t keypair);

int syscoin_slhdsa_vendor_wots_128s_pk_from_sig(
  uint8_t out[SYSCOIN_SLH_WOTS_N],
  const uint8_t signature[SYSCOIN_SLH_WOTS_SIGNATURE_SIZE],
  const uint8_t digest[SYSCOIN_SLH_WOTS_N],
  const uint8_t pk_seed[SYSCOIN_SLH_WOTS_N], uint32_t keypair);

int syscoin_slhdsa_vendor_wots_128s_tree_hash(
  uint8_t out[SYSCOIN_SLH_WOTS_N],
  const uint8_t pk_seed[SYSCOIN_SLH_WOTS_N], uint32_t height,
  uint32_t index, const uint8_t left[SYSCOIN_SLH_WOTS_N],
  const uint8_t right[SYSCOIN_SLH_WOTS_N]);

#ifdef __cplusplus
}
#endif

#endif /* SYSCOIN_CRYPTO_SLHDSA_VENDOR_SLH_WOTS_INTERNAL_H */
