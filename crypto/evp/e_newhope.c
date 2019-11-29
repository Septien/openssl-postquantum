#include "../newhope/api.h"

/* NewHope subkey structure */
typedef struct {
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
} EVP_NEWHOPE_KEYS;

/* Initialize the keys */
static int newhope_init_keys(EVP_CIPHER_CTX *ctx, const unsigned char *sk, const unsigned char *pk)
{
    int ret;
    NEWHOPE_KeyGen(pk, sk);
}
