/*c crypto/nround5/round5.h */
#ifndef HEADER_ROUND5_H
#define HEADER_ROUND5_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_ROUND5
#error ROUND5 is disabled
#endif

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/round5err.h>
#include "round5_locl.h"

#include <stdio.h>

#ifdef _cplusplus
extern "C" {
#endif

typedef struct round5_pub_st ROUND5_PUB;
typedef struct round5_pair_st ROUND5_PAIR;
typedef struct round5_ctx_st ROUND5_CTX;
typedef struct round5_param_data ROUND5_DATA;

/* Concerning public key */
ROUND5_PUB *ROUND5_PUB_new(const ROUND5_CTX *ctx);
ROUND5_PUB *ROUND5_PUB_dup(const ROUND5_PUB *src);
void ROUND5_PUB_free(ROUND5_PUB *pub);

/* Concerning key pair */
ROUND5_PAIR *ROUND5_PAIR_new(ROUND5_CTX *ctx);
ROUND5_PAIR *ROUND5_PAIR_dup(ROUND5_PAIR *pair);
void ROUND5_PAIR_free(ROUND5_PAIR *pair);

/* Create/destroy context */
ROUND5_CTX *ROUND5_CTX_new(const int nid);
void ROUND5_CTX_free(ROUND5_CTX *ctx);

/* Generate key pair */
int ROUND5_PAIR_generate_key(ROUND5_PAIR *keypair);
ROUND5_PUB *ROUND5_PAIR_get_publickey(ROUND5_PAIR *keypair);
int ROUND5_PAIR_has_privatekey(ROUND5_PAIR *keypair);

/* Compute the shared secret for alice and bob */
size_t ROUND5_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const ROUND5_PAIR *alice_keypair, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
size_t ROUND5_compute_key_bob(unsigned char *out, size_t outlen, const ROUND5_PUB *pub_bob, unsigned char *ct, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

#ifdef _cplusplus
}
#endif

#endif // HEADER_ROUND5_H