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

static const char rnd_seed[] = "Some random string, for the random number generator";
static const int KDF_SHA1_len = 20;
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

static int test_newhope(BIO *out, int single)
{
    NEWHOPE_PAIR *alice = NULL, *bob = NULL;
    NEWHOPE_PUB *bobp = NULL;
    NEWHOPE_CTX *ctx = NULL;

    unsigned char *apubbuf = NULL, *bpubbuf = NULL;
    size_t apublen, bpublen;

    unsigned char *assbuf = NULL, *bssbuf = NULL;
    size_t asslen, bsslen;

    unsigned char *ct = NULL;

    int i, ret = 0;

    ctx = NEWHOPE_CTX_new(1);
    alice = NEWHOPE_PAIR_new(ctx);
    bob = NEWHOPE_PAIR_new(ctx);
    

    if ( (alice == NULL) || (bob == NULL) || (ctx == NULL) )
    {
        goto err;
    }

    if (single) BIO_puts(out, "Testing key generation");

    if (!NEWHOPE_PAIR_generate_key(alice)) goto err;
    apublen = sizeof(alice->pub->pu);
    if (single) BIO_printf(out, "\tpub_A (%i bytes) = ", (int) apublen);
    if (apublen < 0)
    {
        fprintf(stderr, "Error in NEWHOPE routines");
        ret = 0;
        goto err;
    }
    if (single)
    {
        for (i = 0; i < apublen; i++)
        {
            BIO_printf(out, "%02X", alice->pk[i]);
        }
        BIO_puts(out, "\n");
    }

    if ((bobp = NEWHOPE_PAIR_get_publickey(bob)) == NULL) goto err;
    bpublen = sizeof(bob->pub->pu);
    if (single)
    {
        BIO_printf(out, "\n\t pub_B (%i bytes) = ", (int) bpublen);
        for (i = 0; i < bpublen; i++)
        {
            BIO_printf(out, "%02X", bobp->pu[i]);
        }
        BIO_puts(out, "\n");
    }

    if (single) BIO_puts(out, "Testing Bob shared secret generation\n");

    bsslen = KDF_SHA1_len;
    bssbuf = (unsigned char *)OPENSSL_malloc(bsslen);
    bsslen = NEWHOPE_compute_key_bob(bssbuf, bsslen, bob, ct, KDF1_SHA1);

    if (single) BIO_puts(out, "Testing Alice shared secret generation\n");
    asslen = KDF_SHA1_len;
    asslen = NEWHOPE_compute_key_alice(assbuf, asslen, ct, alice, KDF1_SHA1);

    if (single)
    {
        BIO_printf(out, "\t key_A (%i bytes) = ", (int) asslen);
        for (i = 0; i < asslen; i++)
        {
            BIO_printf(out, "%02X", assbuf[i]);
        }
        BIO_puts(out, "\n");
    }

    if (bsslen != asslen)
    {
        BIO_printf(out, " failed\n\n");
        fprintf(stderr, "Error un NEWHOPE routines (mismatched shared secrets) \n");
        ret = 0;
    }
    else
    {
        if (single) BIO_printf(out, "ok!\n");
        ret = 1;
    }

err:
    ERR_print_errors_fp(stderr);

    OPENSSL_free(bssbuf);
    OPENSSL_free(assbuf);
    OPENSSL_free(apubbuf);
    OPENSSL_free(bpubbuf);
    OPENSSL_free(bob);
    OPENSSL_free(alice);
    OPENSSL_free(ctx);

    return (ret);
}

int setup_test(void)
{
#ifdef OPENSSL_NO_NEWHOPE
    TEST_note("No NEWHOPE support");
#else
    ADD_TEST(test_newhope);
#endif
    return 1;
}

#endif
