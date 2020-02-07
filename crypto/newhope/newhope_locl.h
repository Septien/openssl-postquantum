#ifndef NEWHOPE_CS
#define NEWHOPE_CS

#include <openssl/newhope.h>

#ifdef _cpluplus
extern "C" { 
#endif

struct newhope_param_data {
    size_t pub_key_size;
    size_t pr_key_size;
    size_t sym_key_size;
};

/* Public key data structure */
struct newhope_pub_st {
    unsigned char *pu;
    NEWHOPE_DATA *pm;
};

/* Key pair data structure (private and public) */
struct newhope_pair_st {
    NEWHOPE_PUB *pub;
    unsigned char *pk;
    int keys_set;           // Is there a private and public key?
};

/* Context structure */
struct newhope_ctx_st {
    int nid;
    NEWHOPE_DATA *pd;
};

#ifdef _cplusplus
}
#endif

#endif // NEWHOPE_CS