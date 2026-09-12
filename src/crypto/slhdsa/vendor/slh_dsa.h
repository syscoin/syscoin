/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Modified by the Syscoin project: restrict the declared parameter-set
 * surface to SLH-DSA-SHAKE-128s and prefix vendored C symbols.
 */

/* === FIPS 205 Stateless Hash-Based Digital Signature Standard. */
/* Minimized API for the FIPS 205 "pure" variant. */

#ifndef _SLH_DSA_H_
#define _SLH_DSA_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

/* Avoid collisions with other copies of slhdsa-c in the final executable. */
#define slh_dsa_shake_128s syscoin_slhdsa_vendor_shake_128s
#define slh_keygen_internal syscoin_slhdsa_vendor_keygen_internal
#define slh_pk_sz syscoin_slhdsa_vendor_pk_size
#define slh_sig_sz syscoin_slhdsa_vendor_signature_size
#define slh_sign syscoin_slhdsa_vendor_sign
#define slh_sk_sz syscoin_slhdsa_vendor_secret_key_size
#define slh_verify syscoin_slhdsa_vendor_verify

#ifndef _SLH_PARAM_H_
  typedef struct slh_param_s slh_param_t;
#endif

  /* === SLH-DSA parameter sets */
  extern const slh_param_t slh_dsa_shake_128s;

  /* === SLH_DSA pure API. */

  /* Return public (verification) key size in bytes for parameter set *prm. */
  size_t slh_pk_sz(const slh_param_t *prm);

  /* Return private (signing) key size in bytes for parameter set *prm. */
  size_t slh_sk_sz(const slh_param_t *prm);

  /* Return signature size in bytes for parameter set *prm. */
  size_t slh_sig_sz(const slh_param_t *prm);

  int slh_keygen_internal(uint8_t *sk, uint8_t *pk, const uint8_t *sk_seed,
                          const uint8_t *sk_prf, const uint8_t *pk_seed,
                          const slh_param_t *prm);

  /* Generate an SLH-DSA signature. */
  size_t slh_sign(uint8_t *sig, const uint8_t *m, size_t m_sz,
                  const uint8_t *ctx, size_t ctx_sz, const uint8_t *sk,
                  const uint8_t *addrnd, const slh_param_t *prm);

  /* Verify an SLH-DSA signature. */
  /* return 0 on verification failure, 1 on success */
  int slh_verify(const uint8_t *m, size_t m_sz, const uint8_t *sig,
                 size_t sig_sz, const uint8_t *ctx, size_t ctx_sz,
                 const uint8_t *pk, const slh_param_t *prm);

#ifdef __cplusplus
}
#endif

/* _SLH_DSA_H_ */
#endif
