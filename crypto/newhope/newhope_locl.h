#ifndef NEWHOPE_CS
#define NEWHOPE_CS

#include <openssl/newhope.h>
#include "newhope_kex.h"

#ifdef _cpluplus
extern "C" { 
#endif

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

#ifdef _cplusplus
}
#endif

#endif // NEWHOPE_CS