/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Modified by the Syscoin project: retain only the FIPS 205
 * SLH-DSA-SHAKE-128s parameter set, cleanse transient SHAKE state, and encode
 * optimized SHAKE padding independently of native byte order.
 */

/* === Portable C code: Functions for instantiation of SLH-DSA with SHAKE */

#include "sha3_api.h"
#include "slh_adrs.h"
#include "slh_dsa.h"
#include "slh_var.h"
#include "../secure.h"

/* === 10.1.   SLH-DSA Using SHAKE */

/* Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, */
/* 8m) */

static void shake_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                        const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                        size_t ctx_sz)
{
  sha3_var_t sha3;
  size_t n = var->prm->n;
  uint8_t buf[2];

  shake256_init(&sha3);
  shake_update(&sha3, r, n);
  shake_update(&sha3, var->pk_seed, n);
  shake_update(&sha3, var->pk_root, n);

  /* add the FIPS 205 pure-interface domain separator and context */
  buf[0] = 0;
  buf[1] = ctx_sz & 0xFF;
  shake_update(&sha3, buf, 2);
  shake_update(&sha3, ctx, ctx_sz);
  shake_update(&sha3, m, m_sz);

  shake_out(&sha3, h, var->prm->m);
  syscoin_slhdsa_secure_zero(buf, sizeof(buf));
  syscoin_slhdsa_secure_zero(&sha3, sizeof(sha3));
}

/* F(PK.seed, ADRS, M1 ) = SHAKE256(PK.seed || ADRS || M1, 8n) */

static void shake_f(slh_var_t *var, uint8_t *h, const uint8_t *m1)
{
  sha3_var_t sha3;
  size_t n = var->prm->n;

  shake256_init(&sha3);
  shake_update(&sha3, var->pk_seed, n);
  shake_update(&sha3, (const uint8_t *)var->adrs->u8, 32);
  shake_update(&sha3, m1, n);

  shake_out(&sha3, h, n);
  syscoin_slhdsa_secure_zero(&sha3, sizeof(sha3));
}

/* PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n) */

static void shake_prf(slh_var_t *var, uint8_t *h)
{
  shake_f(var, h, var->sk_seed);
}

/* PRFmsg (SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n) */

static void shake_prf_msg(slh_var_t *var, uint8_t *h, const uint8_t *opt_rand,
                          const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                          size_t ctx_sz)

{
  sha3_var_t sha3;
  size_t n = var->prm->n;
  uint8_t buf[2];

  shake256_init(&sha3);
  shake_update(&sha3, var->sk_prf, n);
  shake_update(&sha3, opt_rand, n);

  /* add the FIPS 205 pure-interface domain separator and context */
  buf[0] = 0;
  buf[1] = ctx_sz & 0xFF;
  shake_update(&sha3, buf, 2);
  shake_update(&sha3, ctx, ctx_sz);
  shake_update(&sha3, m, m_sz);

  shake_out(&sha3, h, n);
  syscoin_slhdsa_secure_zero(buf, sizeof(buf));
  syscoin_slhdsa_secure_zero(&sha3, sizeof(sha3));
}

/* T_l(PK.seed, ADRS, M ) = SHAKE256(PK.seed || ADRS || Ml, 8n) */

static void shake_t(slh_var_t *var, uint8_t *h, const uint8_t *m, size_t m_sz)
{
  sha3_var_t sha3;
  size_t n = var->prm->n;

  shake256_init(&sha3);
  shake_update(&sha3, var->pk_seed, n);
  shake_update(&sha3, (const uint8_t *)var->adrs->u8, 32);
  shake_update(&sha3, m, m_sz);

  shake_out(&sha3, h, n);
  syscoin_slhdsa_secure_zero(&sha3, sizeof(sha3));
}

/* H(PK.seed, ADRS, M2 ) = SHAKE256(PK.seed || ADRS || M2, 8n) */

static void shake_h(slh_var_t *var, uint8_t *h, const uint8_t *m1,
                    const uint8_t *m2)
{
  sha3_var_t sha3;
  size_t n = var->prm->n;

  shake256_init(&sha3);
  shake_update(&sha3, var->pk_seed, n);
  shake_update(&sha3, (const uint8_t *)var->adrs->u8, 32);
  shake_update(&sha3, m1, n);
  shake_update(&sha3, m2, n);

  shake_out(&sha3, h, n);
  syscoin_slhdsa_secure_zero(&sha3, sizeof(sha3));
}

/* create a context */

static void shake_mk_var(slh_var_t *var, const uint8_t *pk, const uint8_t *sk,
                         const slh_param_t *prm)
{
  size_t n = prm->n;

  memset(var, 0, sizeof(*var));
  var->prm = prm; /* store fixed parameters */
  if (sk != NULL)
  {
    memcpy(var->sk_seed, sk, n);
    memcpy(var->sk_prf, sk + n, n);
    memcpy(var->pk_seed, sk + 2 * n, n);
    memcpy(var->pk_root, sk + 3 * n, n);
  }
  else if (pk != NULL)
  {
    memcpy(var->pk_seed, pk, n);
    memcpy(var->pk_root, pk + n, n);
  }

  /* local ADRS buffer */
  var->adrs = &var->t_adrs;
}

/* === Chaining function used in WOTS+ */
/* Algorithm 5: chain(X, i, s, PK.seed, ADRS) */

/* chaining by processor (some optimizations) */

static void shake_chain(slh_var_t *var, uint8_t *tmp, const uint8_t *x,
                        uint32_t i, uint32_t s)
{
  uint32_t j;
  uint64_t ks[25];
  size_t n = var->prm->n;
  const uint32_t r = (1600 - 256 * 2) / 64; /* SHAKE256 rate */
  uint32_t n8 = n / 8;                      /* number of words */
  uint32_t h = n8 + (32 / 8);               /* static part len */
  uint32_t l = h + n8;                      /* input length */

  if (s == 0)
  { /* no-op */
    memcpy(tmp, x, n);
    return;
  }

  memcpy(ks + h, x, n); /* start node */
  for (j = 0; j < s; j++)
  {
    if (j > 0)
    {
      memcpy(ks + h, ks, n); /* chaining */
    }
    memcpy(ks, var->pk_seed, n);       /* PK.seed */
    adrs_set_hash_address(var, i + j); /* address */
    memcpy(ks + n8, (const uint8_t *)var->adrs->u8, 32);

    /* SYSCOIN: Encode FIPS 202 padding in canonical lane-byte order. */
    memset(ks + l, 0, (25 - l) * sizeof(*ks));
    ((uint8_t *)ks)[l * sizeof(*ks)] = 0x1F;
    ((uint8_t *)ks)[r * sizeof(*ks) - 1] = 0x80;

    keccak_f1600(ks); /* permutation */
  }
  memcpy(tmp, ks, n);
  syscoin_slhdsa_secure_zero(ks, sizeof(ks));
}

/* Combination WOTS PRF + Chain */

static void shake_wots_chain(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  /* PRF secret key */
  adrs_set_type(var, ADRS_WOTS_PRF);
  adrs_set_tree_index(var, 0);
  shake_prf(var, tmp);

  /* chain */
  adrs_set_type(var, ADRS_WOTS_HASH);
  shake_chain(var, tmp, tmp, 0, s);
}

/* Combination FORS PRF + F (if s == 1) */

static void shake_fors_hash(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  /* PRF secret key */
  adrs_set_type(var, ADRS_FORS_PRF);
  adrs_set_tree_height(var, 0);
  shake_prf(var, tmp);

  /* hash it again */
  if (s == 1)
  {
    adrs_set_type(var, ADRS_FORS_TREE);
    shake_f(var, tmp, tmp);
  }
}

/* parameter sets */

const slh_param_t slh_dsa_shake_128s = {/* .n = */ 16,
                                        /* .h = */ 63,
                                        /* .d = */ 7,
                                        /* .hp = */ 9,
                                        /* .a = */ 12,
                                        /* .k = */ 14,
                                        /* .lg_w = */ 4,
                                        /* .m = */ 30,
                                        /* .mk_var = */ shake_mk_var,
                                        /* .chain = */ shake_chain,
                                        /* .wots_chain = */ shake_wots_chain,
                                        /* .fors_hash = */ shake_fors_hash,
                                        /* .h_msg = */ shake_h_msg,
                                        /* .prf = */ shake_prf,
                                        /* .prf_msg = */ shake_prf_msg,
                                        /* .h_f = */ shake_f,
                                        /* .h_h = */ shake_h,
                                        /* .h_t = */ shake_t};
