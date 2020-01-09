#include "../newhope/api.h"

/* Public key data structure */
struct newhope_pub_st {
    unsigned char pu[CRYPTO_PUBLICKEYBYTES];
};

/* Key pair data structure (private and public) */
struct newhope_pair_st {
    NEWHOPE_PUB *pub;
    unsigned char *pk;
    int keys_set;
};

/* Context structure */
struct newhope_ctx_st {
    int nid;
};


static const EVP_CIPHER newhope {
    NID_newhope,
    1, CRYPTO_PUBLICKEYBYTES, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    NEWHOPE_PAIR_generate_key,
    crypto_kem_enc,
    NULL,
    CRYPTO_PUBLICKEYBYTES,
    NULL,
    NULL,
    NULL,
    NULL
};
