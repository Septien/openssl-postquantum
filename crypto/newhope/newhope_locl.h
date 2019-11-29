#ifndef NEWHOPE_CS
#define NEWHOPE_CS

#include "api.h"

extern void KeyGen(unsigned char *pk,
                    unsigned char *sk);

extern void encrypt(unsigned char *ct,
                    unsigned char *m,
                    unsigned char *pk);

extern void decrypt(unsigned char *m,
                    unsigned char *ct,
                    unsigned char *sk);

#endif // NEWHOPE_CS