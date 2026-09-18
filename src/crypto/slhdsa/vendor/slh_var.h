/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Modified by the Syscoin project: size internal buffers for the sole
 * vendored parameter set, SLH-DSA-SHAKE-128s, and remove SHA-2 state.
 */

/* === Internal parameter definition structure. */

#ifndef _SLH_VAR_H_
#define _SLH_VAR_H_

#include "cbmc.h"
#include "slh_param.h"

/* Exact maxima for FIPS 205 SLH-DSA-SHAKE-128s. */
#define SLH_MAX_N 16
#define SLH_MAX_LEN 35
#define SLH_MAX_K 14
#define SLH_MAX_HP 9
#define SLH_MAX_A 12
#define SLH_MAX_M 30

/* context */
struct slh_var_s
{
  const slh_param_t *prm;
  uint8_t sk_seed[SLH_MAX_N];
  uint8_t sk_prf[SLH_MAX_N];
  uint8_t pk_seed[SLH_MAX_N];
  uint8_t pk_root[SLH_MAX_N];

  adrs_t *adrs;  /* regular pointer */
  adrs_t t_adrs; /* local ADRS buffer */
};

/* _SLH_VAR_H_ */
#endif
