#ifndef HEADER_FRODOKEM_H
#define HEADER_FRODOKEM_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_FRODOKEM
#error FRODOKEM is disabled
#endif

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/frodokemerr.h>
#include "rfrodokem_locl.h"

#include <stdio.h>

#ifdef _cplusplus
extern "C" {
#endif

typedef struct frodokem_pub_st FRODOKEM_PUB;
typedef struct frodokem_pair_st FRODOKEM_PAIR;
typedef struct frodokem_ctx_st FRODOKEM_CTX;
typedef struct frodokem_param_data FRODOKEM_DATA;

/* Concerning public key */
FRODOKEM_PUB *FRODOKEM_PUB_new(const FRODOKEM_CTX *ctx);
FRODOKEM_PUB *FRODOKEM_PUB_dup(const FRODOKEM_PUB *src);
void FRODOKEM_PUB_free(FRODOKEM_PUB *pub);

/* Concerning key pair */
FRODOKEM_PAIR *FRODOKEM_PAIR_new(FRODOKEM_CTX *ctx);
FRODOKEM_PAIR *FRODOKEM_PAIR_dup(FRODOKEM_PAIR *pair);
void FRODOKEM_PAIR_free(FRODOKEM_PAIR *pair);

/* Create/destroy context */
FRODOKEM_CTX *FRODOKEM_CTX_new(const int nid);
void FRODOKEM_CTX_free(FRODOKEM_CTX *ctx);

/* Generate key pair */
int FRODOKEM_PAIR_generate_key(FRODOKEM_PAIR *keypair);
FRODOKEM_PUB *FRODOKEM_PAIR_get_publickey(FRODOKEM_PAIR *keypair);
int FRODOKEM_PAIR_has_privatekey(FRODOKEM_PAIR *keypair);

/* Compute the shared secret for alice and bob */
size_t FRODOKEM_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const FRODOKEM_PAIR *alice_keypair, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
size_t FRODOKEM_compute_key_bob(unsigned char *out, size_t outlen, const FRODOKEM_PUB *pub_bob, unsigned char *ct, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

#ifdef _cplusplus
}
#endif

#endif //   HEADER_FRODOKEM_H