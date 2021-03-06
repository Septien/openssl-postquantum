/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/round5err.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA ROUND5_str_reasons[] = {
    {ERR_PACK(ERR_LIB_ROUND5, 0, ROUND5_R_KDF_FAILED), "kdf failed"},
    {0, NULL}
};

#endif

int ERR_load_ROUND5_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(ROUND5_str_reasons[0].error) == NULL)
        ERR_load_strings_const(ROUND5_str_reasons);
#endif
    return 1;
}
