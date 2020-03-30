#ifndef FRODOKEM_CS
#define FRODOKEM_CS

#include <openssl/frodokem.h>

#ifdef _cpluplus
extern "C" { 
#endif

struct frodokem_param_data {
    size_t pub_key_size;
    size_t pr_key_size;
    size_t sym_key_size;
};

/* Public key data structure */
struct frodokem_pub_st {
    unsigned char *pu;
    struct frodokem_param_data *pm;
};

/* Key pair data structure (private and public) */
struct frodokem_pair_st {
    struct frodokem_pub_st *pub;
    unsigned char *pk;
    int keys_set;           // Is there a private and public key?
};

/* Context structure */
struct frodokem_ctx_st {
    int nid;
    struct frodokem_param_data *pd;
};

#ifdef _cplusplus
}
#endif

#endif // FRODOKEM_CS
