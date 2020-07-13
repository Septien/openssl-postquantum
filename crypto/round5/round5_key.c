#include <string.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/round5err.h>
#include "round5_locl.h"
#include "kem.h"

ROUND5_CTX *ROUND5_CTX_new(const int nid)
{
    ROUND5_CTX *ctx;
    ctx = (ROUND5_CTX *) OPENSSL_malloc(sizeof(ROUND5_CTX));
    if (ctx == NULL) {
        ROUND5err(ROUND5_F_ROUND5_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ctx->pd = (ROUND5_DATA *) OPENSSL_malloc(sizeof(ROUND5_DATA));
    if (ctx->pd == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    ctx->nid = nid;
    ctx->pd->pub_key_size = CRYPTO_PUBLICKEYBYTES;
    ctx->pd->pr_key_size = CRYPTO_SECRETKEYBYTES;
    ctx->pd->sym_key_size = 128;

    return (ctx);
}

void ROUND5_CTX_free(ROUND5_CTX *ctx)
{
    if (ctx == NULL) return;

    if (ctx->pd == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_CTX_FREE, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }

    OPENSSL_cleanse((void *) ctx->pd, sizeof(ROUND5_DATA));
    OPENSSL_cleanse((void *) ctx, sizeof(ROUND5_CTX));
    OPENSSL_free(ctx->pd);
    OPENSSL_free(ctx);
}


ROUND5_PUB *ROUND5_PUB_new(const ROUND5_CTX *ctx)
{
    ROUND5_PUB *pub;

    if (ctx == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub = (ROUND5_PUB *)OPENSSL_malloc(sizeof(ROUND5_PUB));
    if (pub == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    pub->pm = (ROUND5_DATA *)OPENSSL_malloc(sizeof(ROUND5_DATA));
    if (pub->pm == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (ctx->pd == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub->pm->pub_key_size = ctx->pd->pub_key_size;
    pub->pm->pr_key_size = ctx->pd->pr_key_size;
    pub->pm->sym_key_size = ctx->pd->sym_key_size;
    pub->pu = (unsigned char *)OPENSSL_malloc(pub->pm->sym_key_size * sizeof(unsigned char));
    if (pub->pu == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    return (pub);
}

ROUND5_PUB *ROUND5_PUB_dup(const ROUND5_PUB *src)
{
    ROUND5_PUB *dst;
    
    if (src == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    dst = (ROUND5_PUB *) OPENSSL_malloc(sizeof(ROUND5_PUB));
    if (dst == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    dst->pm = (ROUND5_DATA *)OPENSSL_malloc(sizeof(ROUND5_DATA));
    if (dst->pm == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (src->pm == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
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
            ROUND5err(ROUND5_F_ROUND5_PUB_DUP, ERR_R_MALLOC_FAILURE);
            ROUND5_PUB_free(dst);
            return (NULL);
        }
        memcpy(dst->pu, src->pu, src->pm->pub_key_size * sizeof(unsigned char));        
    }

    return (dst);
}

void ROUND5_PUB_free(ROUND5_PUB *pub)
{
    if (pub == NULL) return;

    if (pub->pu && pub->pm)
    {
        OPENSSL_cleanse(pub->pu, pub->pm->pub_key_size * sizeof(unsigned char));
        OPENSSL_cleanse(pub->pm, sizeof(ROUND5_DATA));
        OPENSSL_free(pub->pm);
    }

    if (pub->pu)
    {
        OPENSSL_free(pub->pu);
    }

    OPENSSL_cleanse((void *)pub, sizeof(ROUND5_PUB));
    OPENSSL_free(pub);
}

ROUND5_PAIR *ROUND5_PAIR_new(ROUND5_CTX *ctx)
{
    if (ctx == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    ROUND5_PAIR *pair;
    pair = (ROUND5_PAIR *)OPENSSL_malloc(sizeof(ROUND5_PAIR));
    if (pair == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    /* Keys not set yet */
    pair->keys_set = 0;

    pair->pub = ROUND5_PUB_new(ctx);
    pair->pk = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pr_key_size * sizeof(unsigned char));
    if ((pair->pub == NULL) || (pair->pk == NULL))
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        ROUND5_PAIR_free(pair);
        return (NULL);
    }

    pair->pub->pu = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pub_key_size * sizeof(unsigned char));
    if (pair->pub->pu == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    return (pair);
}

ROUND5_PAIR *ROUND5_PAIR_dup(ROUND5_PAIR *pair)
{
    if (pair == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    ROUND5_PAIR *newPair;
    newPair = (ROUND5_PAIR *)OPENSSL_malloc(sizeof(ROUND5_PAIR));
    if (newPair == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    newPair->pub = ROUND5_PUB_dup(pair->pub);
    if (newPair->pub == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (pair->pk == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    newPair->pk = (unsigned char *)OPENSSL_malloc(newPair->pub->pm->pr_key_size * sizeof(unsigned char));
    if (newPair->pk == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memcpy(newPair->pk, pair->pk, pair->pub->pm->pr_key_size * sizeof(unsigned char));
    newPair->keys_set = pair->keys_set;

    return (newPair);
}

void ROUND5_PAIR_free(ROUND5_PAIR *pair)
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
    ROUND5_PUB_free(pair->pub);

    OPENSSL_cleanse((void *)pair, sizeof(ROUND5_PUB));
    OPENSSL_free(pair);
}


int ROUND5_PAIR_generate_key(ROUND5_PAIR *keypair)
{
    if (keypair == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (keypair->pub == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    crypto_kem_keypair(keypair->pk, keypair->pub->pu);
    keypair->keys_set = 1;
    return 1;
}

ROUND5_PUB *ROUND5_PAIR_get_publickey(ROUND5_PAIR *keypair)
{
    if (keypair == NULL)
    {
        return (NULL);
    }
    if (keypair->keys_set == 0)
        return (NULL);
    return keypair->pub;
}

size_t ROUND5_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const ROUND5_PAIR *alice_keypair, 
                                    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;

    if ((alice_keypair == NULL) || (ct == NULL))
    {
        ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_ALICE, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }

    unsigned char *ssa = (unsigned char *)OPENSSL_malloc(CRYPTO_SECRETKEYBYTES * sizeof(unsigned char));
    if (ssa == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset(ssa, 0, CRYPTO_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for alice, using the ciphertext recieved and alice's private key */
    crypto_kem_dec(ssa, ct, alice_keypair->pk);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssa, 128, out, &outlen) == NULL)
        {
            ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_ALICE, ROUND5_R_KDF_FAILED);
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

size_t ROUND5_compute_key_bob(unsigned char *out, size_t outlen, const ROUND5_PUB *pub_bob, unsigned char *ct, 
                                void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;
    if (pub_bob == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }
    unsigned char *ssb = (unsigned char *)OPENSSL_malloc(CRYPTO_CIPHERTEXTBYTES * sizeof(unsigned char));
    if (ssb == NULL)
    {
        ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_BOB, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset (ssb, 0, CRYPTO_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for bob, using bob's private key*/
    crypto_kem_enc(ct, ssb, pub_bob->pu);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssb, CRYPTO_SECRETKEYBYTES * sizeof(unsigned char), out, &outlen) == NULL)
        {
            ROUND5err(ROUND5_F_ROUND5_COMPUTE_KEY_BOB, ROUND5_R_KDF_FAILED);
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
