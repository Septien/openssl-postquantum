#include <string.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/newhopeerr.h>
#include "newhope_locl.h"
#include "api.h"

NEWHOPE_CTX *NEWHOPE_CTX_new(const int nid)
{
    NEWHOPE_CTX *ctx;
    ctx = (NEWHOPE_CTX *) OPENSSL_malloc(sizeof(NEWHOPE_CTX));
    if (ctx == NULL) {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ctx->pd = (NEWHOPE_DATA *) OPENSSL_malloc(sizeof(NEWHOPE_DATA));
    if (ctx->pd == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    ctx->nid = nid;
    ctx->pd->pub_key_size = CRYPTO_PUBLICKEYBYTES;
    ctx->pd->pr_key_size = CRYPTO_SECRETKEYBYTES;
    ctx->pd->sym_key_size = 128;

    return (ctx);
}

void NEWHOPE_CTX_free(NEWHOPE_CTX *ctx)
{
    if (ctx == NULL) return;

    if (ctx->pd == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_CTX_FREE, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }

    OPENSSL_cleanse((void *) ctx->pd, sizeof(NEWHOPE_DATA));
    OPENSSL_cleanse((void *) ctx, sizeof(NEWHOPE_CTX));
    OPENSSL_free(ctx->pd);
    OPENSSL_free(ctx);
}


NEWHOPE_PUB *NEWHOPE_PUB_new(const NEWHOPE_CTX *ctx)
{
    NEWHOPE_PUB *pub;

    if (ctx == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub = (NEWHOPE_PUB *)OPENSSL_malloc(sizeof(NEWHOPE_PUB));
    if (pub == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    pub->pm = (NEWHOPE_DATA *)OPENSSL_malloc(sizeof(NEWHOPE_DATA));
    if (pub->pm == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (ctx->pd == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    pub->pm->pub_key_size = ctx->pd->pub_key_size;
    pub->pm->pr_key_size = ctx->pd->pr_key_size;
    pub->pm->sym_key_size = ctx->pd->sym_key_size;
    pub->pu = (unsigned char *)OPENSSL_malloc(pub->pm->sym_key_size * sizeof(unsigned char));
    if (pub->pu == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    return (pub);
}

NEWHOPE_PUB *NEWHOPE_PUB_dup(const NEWHOPE_PUB *src)
{
    NEWHOPE_PUB *dst;
    
    if (src == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    dst = (NEWHOPE_PUB *) OPENSSL_malloc(sizeof(NEWHOPE_PUB));
    if (dst == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    dst->pm = (NEWHOPE_DATA *)OPENSSL_malloc(sizeof(NEWHOPE_DATA));
    if (dst->pm == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (src->pm == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_DUP, ERR_R_PASSED_NULL_PARAMETER);
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
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_PUB_DUP, ERR_R_MALLOC_FAILURE);
            NEWHOPE_PUB_free(dst);
            return (NULL);
        }
        memcpy(dst->pu, src->pu, src->pm->pub_key_size * sizeof(unsigned char));        
    }

    return (dst);
}

void NEWHOPE_PUB_free(NEWHOPE_PUB *pub)
{
    if (pub == NULL) return;

    if (pub->pu && pub->pm)
    {
        OPENSSL_cleanse(pub->pu, pub->pm->pub_key_size * sizeof(unsigned char));
        OPENSSL_cleanse(pub->pm, sizeof(NEWHOPE_DATA));
        OPENSSL_free(pub->pm);
    }

    if (pub->pu)
    {
        OPENSSL_free(pub->pu);
    }

    OPENSSL_cleanse((void *)pub, sizeof(NEWHOPE_PUB));
    OPENSSL_free(pub);
}

NEWHOPE_PAIR *NEWHOPE_PAIR_new(NEWHOPE_CTX *ctx)
{
    if (ctx == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    NEWHOPE_PAIR *pair;
    pair = (NEWHOPE_PAIR *)OPENSSL_malloc(sizeof(NEWHOPE_PAIR));
    if (pair == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    /* Keys not set yet */
    pair->keys_set = 0;

    pair->pub = NEWHOPE_PUB_new(ctx);
    pair->pk = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pr_key_size * sizeof(unsigned char));
    if ((pair->pub == NULL) || (pair->pk == NULL))
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        NEWHOPE_PAIR_free(pair);
        return (NULL);
    }

    pair->pub->pu = (unsigned char *)OPENSSL_malloc(pair->pub->pm->pub_key_size * sizeof(unsigned char));
    if (pair->pub->pu == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    return (pair);
}

NEWHOPE_PAIR *NEWHOPE_PAIR_dup(NEWHOPE_PAIR *pair)
{
    if (pair == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }

    NEWHOPE_PAIR *newPair;
    newPair = (NEWHOPE_PAIR *)OPENSSL_malloc(sizeof(NEWHOPE_PAIR));
    if (newPair == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    
    newPair->pub = NEWHOPE_PUB_dup(pair->pub);
    if (newPair->pub == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    if (pair->pk == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_DUP, ERR_R_PASSED_NULL_PARAMETER);
        return (NULL);
    }
    newPair->pk = (unsigned char *)OPENSSL_malloc(newPair->pub->pm->pr_key_size * sizeof(unsigned char));
    if (newPair->pk == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    memcpy(newPair->pk, pair->pk, pair->pub->pm->pr_key_size * sizeof(unsigned char));
    newPair->keys_set = pair->keys_set;

    return (newPair);
}

void NEWHOPE_PAIR_free(NEWHOPE_PAIR *pair)
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
    NEWHOPE_PUB_free(pair->pub);

    OPENSSL_cleanse((void *)pair, sizeof(NEWHOPE_PUB));
    OPENSSL_free(pair);
}


int NEWHOPE_PAIR_generate_key(NEWHOPE_PAIR *keypair)
{
    if (keypair == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (keypair->pub == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_PAIR_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    crypto_kem_keypair(keypair->pk, keypair->pub->pu);
    keypair->keys_set = 1;
    return 1;
}

NEWHOPE_PUB *NEWHOPE_PAIR_get_publickey(NEWHOPE_PAIR *keypair)
{
    if (keypair == NULL)
    {
        return (NULL);
    }
    if (keypair->keys_set == 0)
        return (NULL);
    return keypair->pub;
}

size_t NEWHOPE_compute_key_alice(unsigned char *out, size_t outlen, const unsigned char *ct, const NEWHOPE_PAIR *alice_keypair, 
                                    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;

    if ((alice_keypair == NULL) || (ct == NULL))
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_ALICE, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }

    unsigned char *ssa = (unsigned char *)OPENSSL_malloc(NEWHOPE_CPAKEM_SECRETKEYBYTES * sizeof(unsigned char));
    if (ssa == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_ALICE, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset(ssa, 0, NEWHOPE_CPAKEM_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for alice, using the ciphertext recieved and alice's private key */
    crypto_kem_dec(ssa, ct, alice_keypair->pk);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssa, 128, out, &outlen) == NULL)
        {
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_ALICE, NEWHOPE_R_KDF_FAILED);
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

size_t NEWHOPE_compute_key_bob(unsigned char *out, size_t outlen, const NEWHOPE_PUB *pub_bob, unsigned char *ct, 
                                void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    size_t ret = 0;
    if (pub_bob == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_BOB, ERR_R_PASSED_NULL_PARAMETER);
        return (ret);
    }
    unsigned char *ssb = (unsigned char *)OPENSSL_malloc(NEWHOPE_CPAKEM_CIPHERTEXTBYTES * sizeof(unsigned char));
    if (ssb == NULL)
    {
        NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_BOB, ERR_R_MALLOC_FAILURE);
        return (ret);
    }

    memset(ssb, 0, NEWHOPE_CPAKEM_SECRETKEYBYTES * sizeof(unsigned char));
    /* Compute the shared secret for bob, using bob's private key*/
    crypto_kem_enc(ct, ssb, pub_bob->pu);

    if (KDF != 0)
    {
        if (KDF((unsigned char *) ssb, NEWHOPE_CPAKEM_CIPHERTEXTBYTES * sizeof(unsigned char), out, &outlen) == NULL)
        {
            NEWHOPEerr(NEWHOPE_F_NEWHOPE_COMPUTE_KEY_BOB, NEWHOPE_R_KDF_FAILED);
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
