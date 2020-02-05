/* crypto/newhope/nowhope.h */
#ifndef HEADER_NEWHOPE_H
#define HEADER_NEWHOPE_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_NEWHOPE
#error NEWHOPE is disabled
#endif

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/newhopeerr.h>

#include <stdin.h>

#ifdef _cplusplus
extern "C" {
#endif

typedef struct newhope_pub_st NEWHOPE_PUB;
typedef struct newhope_pari_st NEWHOPE_PAIR;
typedef struct newhope_ctx_st NEWHOPE_CTX;
typedef struct newhope_param_data NEWHOPE_DATA;

/* Concerning public key */
NEWHOPE_PUB *NEWHOPE_PUB_new(const NEWHOPE_CTX *ctx);
NEWHOPE_PUB *NEWHOPE_PUB_dup(const NEWHOPE_PUB *src);
void NEWHOPE_PUB_free(NEWHOPE *pub);

/* Concerning key pair */
NEWHOPE_PAIR *NEWHOPE_PAIR_new(NEWHOPE_CTX *ctx);
NEWHOPE_PAIR *NEWHOPE_PAIR_dup(NEWHOPE_PAIR *pair);
void NEWHOPE_PAIR_free(NEWHOPE_PAIR *pair);

/* Create/destroy context */
NEWHOPE_CTX *NEWHOPE_CTX_new(const int nid);
void NEWHOPE_CTX_free(NEWHOPE_CTX *ctx);

/* Generate key pair */
int NEWHOPE_PAIR_generate_key(NEWHOPE_PAIR *keypair);
NEWHOPE *NEWHOPE_PAIR_get_publickey(NEWHOPE_PAIR *keypair);
int NEWHOPE_PAIR_has_privatekey(NEWHOPE_PAIR *keypair);

/* Compute the shared secret for alice and bob */
size_t NEWHOPE_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const NEWHOPE_PAIR *alice_keypair, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
size_t NEWHOPE_compute_key_bob(unsigned char *out, size_t outlen, const NEWHOPE_PUB *pub_bob, unsigned char ct, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));

#  ifdef  __cplusplus
}
#  endif
#endif // HEADER_NEWHOPE_H
