#include <string.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/frodokemerr.h>
#include "frodokem_locl.h"
#include "frodokem_kex.c"

FRODOKEM_CTX *FRODOKEM_CTX_new(const int nid)
{
    FRODOKEM_CTX *ctx;
    ctx = (FRODOKEM_CTX *) OPENSSL_malloc(sizeof(FRODOKEM_CTX));
    if (ctx == NULL) {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ctx->pd = (FRODOKEM_DATA *) OPENSSL_malloc(sizeof(FRODOKEM_DATA));
    if (ctx->pd == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    ctx->nid = nid;
    ctx->pd->pub_key_size = CRYPTO_PUBLICKEYBYTES;
    ctx->pd->pr_key_size = CRYPTO_SECRETKEYBYTES;
    ctx->pd->sym_key_size = 128;

    return (ctx);
}

void FRODOKEM_CTX_free(FRODOKEM_CTX *ctx)
{
    if (ctx == NULL) return;

    if (ctx->pd == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_CTX_FREE, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }

    OPENSSL_cleanse((void *) ctx->pd, sizeof(FRODOKEM_DATA));
    OPENSSL_cleanse((void *) ctx, sizeof(FRODOKEM_CTX));
    OPENSSL_free(ctx->pd);
    OPENSSL_free(ctx);
}


FRODOKEM_PUB *FRODOKEM_PUB_new(const FRODOKEM_CTX *ctx)
{
    FRODOKEM_PUB *pub;

    if (ctx == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub = (FRODOKEM_PUB *)OPENSSL_malloc(sizeof(FRODOKEM_PUB));
    if (pub == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    pub->pm = (FRODOKEM_DATA *)OPENSSL_malloc(sizeof(FRODOKEM_DATA));
    if (pub->pm == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (ctx->pd == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub->pm->pub_key_size = ctx->pd->pub_key_size;
    pub->pm->pr_key_size = ctx->pd->pr_key_size;
    pub->pm->sym_key_size = ctx->pd->sym_key_size;
    pub->pu = (unsigned char *)OPENSSL_malloc(pub->pm->sym_key_size * sizeof(unsigned char));
    if (pub->pu == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    return (pub);
}

FRODOKEM_PUB *FRODOKEM_PUB_dup(const FRODOKEM_PUB *src)
{
    FRODOKEM_PUB *dst;
    
    if (src == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    dst = (FRODOKEM_PUB *) OPENSSL_malloc(sizeof(FRODOKEM_PUB));
    if (dst == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    dst->pm = (FRODOKEM_DATA *)OPENSSL_malloc(sizeof(FRODOKEM_DATA));
    if (dst->pm == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (src->pm == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    dst->pm->pub_key_size = src->pm->pub_key_size;
    dst->pm->pr_key_size = src->pm->pr_key_size;
    dst->pm->sym_key_size = src->pm->sym_key_size;

    if (src->pu)
    {
        dst->pu = (unsigned char *)OPENSSL_malloc(dst->pm->pub_key_size * sizeof(unsigned char));
        if (dst->pu == NULL)
        {
            FRODOKEMerr(FRODOKEM_F_FRODOKEM_PUB_DUP, ERR_R_MALLOC_FAILURE);
            FRODOKEM_PUB_free(dst);
            return (NULL);
        }
        memcpy(dst->pu, src->pu, src->pm->pub_key_size * sizeof(unsigned char));        
    }

    return (dst);
}

void FRODOKEM_PUB_free(FRODOKEM_PUB *pub)
{
    if (pub == NULL) return;

    if (pub->pu && pub->pm)
    {
        OPENSSL_cleanse(pub->pu, pub->pm->pub_key_size * sizeof(unsigned char));
        OPENSSL_cleanse(pub->pm, sizeof(FRODOKEM_DATA));
        OPENSSL_free(pub->pm);
    }

    if (pub->pu)
    {
        OPENSSL_free(pub->pu);
    }

    OPENSSL_cleanse((void *)pub, sizeof(FRODOKEM_PUB));
    OPENSSL_free(pub);
}

FRODOKEM_PAIR *FRODOKEM_PAIR_new(FRODOKEM_CTX *ctx)
{
    if (ctx == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    FRODOKEM_PAIR *pair;
    pair = (FRODOKEM_PAIR *)OPENSSL_malloc(sizeof(FRODOKEM_PAIR));
    if (pair == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    /* Keys not set yet */
    pair->keys_set = 0;

    pair->pub = FRODOKEM_PUB_new(ctx);
    pair->pk = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pr_key_size * sizeof(unsigned char));
    if ((pair->pub == NULL) || (pair->pk == NULL))
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        FRODOKEM_PAIR_free(pair);
        return (NULL);
    }

    pair->pub->pu = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pub_key_size * sizeof(unsigned char));
    if (pair->pub->pu == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    return (pair);
}

FRODOKEM_PAIR *FRODOKEM_PAIR_dup(FRODOKEM_PAIR *pair)
{
    if (pair == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    FRODOKEM_PAIR *newPair;
    newPair = (FRODOKEM_PAIR *)OPENSSL_malloc(sizeof(FRODOKEM_PAIR));
    if (newPair == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    newPair->pub = FRODOKEM_PUB_dup(pair->pub);
    if (newPair->pub == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (pair->pk == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    newPair->pk = (unsigned char *)OPENSSL_malloc(newPair->pub->pm->pr_key_size * sizeof(unsigned char));
    if (newPair->pk == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memcpy(newPair->pk, pair->pk, pair->pub->pm->pr_key_size * sizeof(unsigned char));
    newPair->keys_set = pair->keys_set;

    return (newPair);
}

void FRODOKEM_PAIR_free(FRODOKEM_PAIR *pair)
{
    if (pair == NULL) return;

    if (pair->pk && pair->pub->pm)
    {
        OPENSSL_cleanse(pair->pk, pair->pub->pm->pr_key_size * sizeof(unsigned char));
    }
    if (pair->pk)
    {
        OPENSSL_free(pair->pk);
    }
    FRODOKEM_PUB_free(pair->pub);

    OPENSSL_cleanse((void *)pair, sizeof(FRODOKEM_PUB));
    OPENSSL_free(pair);
}


int FRODOKEM_PAIR_generate_key(FRODOKEM_PAIR *keypair)
{
    if (keypair == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (keypair->pub == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    crypto_kem_keypair(keypair->pk, keypair->pub->pu);
    keypair->keys_set = 1;
    return 1;
}

FRODOKEM_PUB *FRODOKEM_PAIR_get_publickey(FRODOKEM_PAIR *keypair)
{
    if (keypair == NULL)
    {
        return (NULL);
    }
    if (keypair->keys_set == 0)
        return (NULL);
    return keypair->pub;
}

size_t FRODOKEM_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const FRODOKEM_PAIR *alice_keypair, 
                                    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;

    if ((alice_keypair == NULL) || (ct == NULL))
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_ALICE, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }

    unsigned char *ssa = (unsigned char *)OPENSSL_malloc(FRODOKEM_CPAKEM_SECRETKEYBYTES * sizeof(unsigned char));
    if (ssa == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset(ssa, 0, CRYPTO_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for alice, using the ciphertext recieved and alice's private key */
    crypto_kem_dec(ssa, ct, alice_keypair->pk);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssa, 128, out, &outlen) == NULL)
        {
            FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_ALICE, FRODOKEM_R_KDF_FAILED);
            goto err;
        }
        ret = outlen;
    }
    else
    {
        if (outlen > 128)
            outlen = 128;
        memcpy(out, (unsigned char *) ssa, outlen);
        ret = outlen;
    }

err:
    if (ssa) OPENSSL_free(ssa);

    return (ret);
}

size_t FRODOKEM_compute_key_bob(unsigned char *out, size_t outlen, const FRODOKEM_PUB *pub_bob, unsigned char *ct, 
                                void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;
    if (pub_bob == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }
    unsigned char *ssb = (unsigned char *)OPENSSL_malloc(CRYPTO_CIPHERTEXTBYTES * sizeof(unsigned char));
    if (ssb == NULL)
    {
        FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_BOB, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset (ssb, 0, CRYPTO_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for bob, using bob's private key*/
    crypto_kem_enc(ct, ssb, pub_bob->pu);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssb, FRODOKEM_CPAKEM_CIPHERTEXTBYTES * sizeof(unsigned char), out, &outlen) == NULL)
        {
            FRODOKEMerr(FRODOKEM_F_FRODOKEM_COMPUTE_KEY_BOB, FRODOKEM_R_KDF_FAILED);
            goto err;
        }
        ret = outlen;
    }
    else
    {
        if (outlen > 128)
            outlen = 128;
        memcpy(out, (unsigned char *) ssb, outlen);
        ret = outlen;
    }

err:
    if (ssb) OPENSSL_free(ssb);

    return (ret);
}
