/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef _R5_PARAMETER_SETS_H_
#define _R5_PARAMETER_SETS_H_

#include <stdint.h>
#include <stddef.h>
#include "misc.h"

#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           372
#define PARAMS_N           372
#define PARAMS_H           178
#define PARAMS_HMAX        403
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      3
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           2
#define PARAMS_XE          53
#define CRYPTO_ALGNAME     "R5ND_0CPA_2iot"

// appropriate types
typedef uint16_t modq_t;
typedef uint8_t modp_t;
typedef uint8_t modt_t;

// derived parameters
#define PARAMS_K        (PARAMS_D/PARAMS_N)
#define PARAMS_Q        (1 << PARAMS_Q_BITS)
#define PARAMS_Q_MASK   (PARAMS_Q - 1)
#define PARAMS_P        (1 << PARAMS_P_BITS)
#define PARAMS_P_MASK   (PARAMS_P - 1)
#define PARAMS_KAPPA    (8 * PARAMS_KAPPA_BYTES)
#define PARAMS_MU       CEIL_DIV((PARAMS_KAPPA + PARAMS_XE), PARAMS_B_BITS)
#define PARAMS_MUT_SIZE BITS_TO_BYTES(PARAMS_MU * PARAMS_T_BITS)

// parameters required for sampling of secret keys
#define PARAMS_RS_DIV       (0x10000 / PARAMS_D)
#define PARAMS_RS_LIM       (PARAMS_D * PARAMS_RS_DIV)
#define PARAMS_CUSTOM_LEN   8   // lenght of custom_lenght in drbg_init_customization
#define PARAMS_XSIZE        32  // amount of 16 bit numbers sampled at once
#define PARAMS_XMASK        0x1F
#define CTSECRETVECTOR64  (PARAMS_D+63)/64 //# of 64-bit words.

//    fast index type
typedef uint16_t tern_coef_type;
typedef tern_coef_type tern_secret[PARAMS_H/2][2];
typedef tern_secret tern_secret_s[PARAMS_N_BAR];
typedef tern_secret tern_secret_r[PARAMS_M_BAR];

#define PARAMS_DP_SIZE  BITS_TO_BYTES(PARAMS_N_BAR * PARAMS_D * PARAMS_P_BITS)
#define PARAMS_DPU_SIZE BITS_TO_BYTES(PARAMS_M_BAR * PARAMS_D * PARAMS_P_BITS)
#define PARAMS_PK_SIZE  (PARAMS_KAPPA_BYTES + PARAMS_DP_SIZE)
#define PARAMS_CT_SIZE  (PARAMS_DPU_SIZE + PARAMS_MUT_SIZE)


// Definition of TAU parameter
// Default for non-ring is 2
#if !defined(ROUND5_API_TAU) && PARAMS_K != 1
#undef ROUND5_API_TAU
#define ROUND5_API_TAU 2
#endif
// Ring only allows for 0
#if PARAMS_K == 1
#undef ROUND5_API_TAU
#define ROUND5_API_TAU 0
#endif

#define PARAMS_TAU      ROUND5_API_TAU

// Define the length of the random vector when TAU is 2 is used for generating A, defaults to parameter 2^11.
// Important: Must be a power of two and > d
#if !defined(ROUND5_API_TAU2_LEN) || ROUND5_API_TAU2_LEN == 0
#undef ROUND5_API_TAU2_LEN
#define ROUND5_API_TAU2_LEN (1<<11)
#endif
#if ROUND5_API_TAU2_LEN > (1<<31)
#error ROUND5_API_TAU2_LEN must be less than or equal to 2^31
#endif
#if (ROUND5_API_TAU2_LEN & (ROUND5_API_TAU2_LEN - 1)) != 0 || ROUND5_API_TAU2_LEN < PARAMS_D
#error ROUND5_API_TAU2_LEN must be a power of two and greater than or equal to PARAMS_D
#endif
#define PARAMS_TAU2_LEN ROUND5_API_TAU2_LEN

// Rounding constants
#if ((PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS) < PARAMS_P_BITS)
#define PARAMS_Z_BITS   PARAMS_P_BITS
#else
#define PARAMS_Z_BITS   (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS)
#endif
#define PARAMS_H1       (1 << (PARAMS_Q_BITS - PARAMS_P_BITS - 1))
#define PARAMS_H2       (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1))
#define PARAMS_H3       ((1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1)))

// Packing shift
//#if PARAMS_K != 1
#if PARAMS_B_BITS == 1
#define PACK_SHIFT 3
#define PACK_AND 7
#endif
#if PARAMS_B_BITS == 2
#define PACK_SHIFT 2
#define PACK_AND 3
#endif
#if PARAMS_B_BITS == 4
#define PACK_SHIFT 1
#define PACK_AND 1
#endif
//#endif

#endif /* _R5_PARAMETER_SETS_H_ */

