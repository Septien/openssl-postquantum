#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "testutil.h"

#ifdef OPENSSL_NO_NEWHOPE
int main(int argc, char **argv)
{
    print("No NEWHOPE support\n");
    return 0;
}
#else
#include <openssl/newhope.h>

static const int KDF_SHA1_len = 128;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)
{
#ifndef OPENSSL_NO_SHA
    if (*outlen < SHA_DIGEST_LENGTH)
        return NULL;
    else
        *outlen = SHA_DIGEST_LENGTH;
        return SHA1(in, inlen, out);
#else
    retrun NULL;
#endif
}

static int test_newhope(void)
{
    /* Necessary data structures for key exchange */
    NEWHOPE_CTX  *ctx   = NULL;
    NEWHOPE_PAIR *alice = NULL;
    NEWHOPE_PUB  *bob   = NULL;

    /* Necessary buffers for storing generated data */
    unsigned char *apubbuf = NULL, *bpubbuf = NULL;
    unsigned char *assbuf = NULL, *bssbuf = NULL;
    unsigned char *ct = NULL;

    int bsslen = 0, asslen = 0;

    int ret = 0;
    if (!TEST_ptr(ctx = NEWHOPE_CTX_new(1))) goto err;

    if (!TEST_ptr(alice = NEWHOPE_PAIR_new(ctx)) || !TEST_ptr(bob = NEWHOPE_PUB_new(ctx))) goto err;

    /* Generate the pair of keys for alice */
    if (!TEST_int_eq(NEWHOPE_PAIR_generate_key(alice), 1)) goto err;

    /* Get Bob's public key from alice key pair */
    if (!TEST_ptr(bob = NEWHOPE_PAIR_get_publickey(alice))) goto err;

    /* Generate the ciphertext and the shared secret from the public key */
    bsslen = KDF_SHA1_len;
    if (!TEST_ptr(bssbuf = (unsigned char *)OPENSSL_malloc(bsslen * sizeof(unsigned char)))) goto err;
    if (!TEST_int_eq(bsslen = NEWHOPE_compute_key_bob(bssbuf, bsslen, bob, ct, KDF1_SHA1), 128)) goto err;

    /* Generate the shared secret for alice, using its private key and the ciphertext */
    asslen = KDF_SHA1_len;
    if (!TEST_ptr(assbuf = (unsigned char *)OPENSSL_malloc(asslen * sizeof(unsigned char)))) goto err;
    if (!TEST_int_eq(asslen = NEWHOPE_compute_key_alice(assbuf, asslen, ct, alice, KDF1_SHA1), 128)) goto err;
    if (!TEST_int_eq(asslen, bsslen)) goto err;

    ret = 1;
err:
    OPENSSL_free(bssbuf);
    OPENSSL_free(assbuf);
    OPENSSL_free(apubbuf);
    OPENSSL_free(bpubbuf);
    OPENSSL_free(bob);
    OPENSSL_free(alice);
    OPENSSL_free(ctx);

    return (ret);
}

int setup_tests(void)
{
#ifdef OPENSSL_NO_NEWHOPE
    TEST_note("No NEWHOPE support");
#else
    ADD_TEST(test_newhope);
#endif
    return 1;
}

#endif
