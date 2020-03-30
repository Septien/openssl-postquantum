#ifndef ROUND5_CS
#define ROUND5_CS

#include <openssl/round5.h>

#ifdef _cpluplus
extern "C" { 
#endif

struct round5_param_data {
    size_t pub_key_size;
    size_t pr_key_size;
    size_t sym_key_size;
};

/* Public key data structure */
struct round5_pub_st {
    unsigned char *pu;
    struct round5_param_data *pm;
};

/* Key pair data structure (private and public) */
struct round5_pair_st {
    struct round5_pub_st *pub;
    unsigned char *pk;
    int keys_set;           // Is there a private and public key?
};

/* Context structure */
struct round5_ctx_st {
    int nid;
    struct round5_param_data *pd;
};

#ifdef _cplusplus
}
#endif

#endif // ROUND5_CS
