/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NEWHOPEERR_H
# define OPENSSL_NEWHOPEERR_H

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_NEWHOPE_strings(void);

/*
 * NEWHOPE function codes.
 */
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define NEWHOPE_F_NEWHOPE_COMPUTE_KEY_ALICE              0
#  define NEWHOPE_F_NEWHOPE_COMPUTE_KEY_BOB                0
#  define NEWHOPE_F_NEWHOPE_CTX_FREE                       0
#  define NEWHOPE_F_NEWHOPE_CTX_NEW                        0
#  define NEWHOPE_F_NEWHOPE_PAIR_DUP                       0
#  define NEWHOPE_F_NEWHOPE_PAIR_GENERATE_KEY              0
#  define NEWHOPE_F_NEWHOPE_PAIR_NEW                       0
#  define NEWHOPE_F_NEWHOPE_PUB_DUP                        0
#  define NEWHOPE_F_NEWHOPE_PUB_NEW                        0
# endif

/*
 * NEWHOPE reason codes.
 */
# define NEWHOPE_R_KDF_FAILED                             100

#endif
