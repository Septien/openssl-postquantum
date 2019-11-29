#include <time.h>
#include <stdlib.h>

#include "newhope.h"
#include "api.h"
#include "rng.h"
#include "cpapke.h"

void NEWHOPE_KeyGen(unsigned char *pk, unsigned char *sk)
{
    cpapke_keypair(pk, sk);
}

void NEWHOPE_encrypt(unsigned char *ct, unsigned char *m, unsigned char *pk)
{
    // Generate a random sequence of bytes each time
    srand(time(NULL));
    unsigned int n = (unsigned int) (rand() % 65535);
    unsigned char z[n];
    randombytes(z, n);
    cpapke_enc(ct, m, pk, z);
}

void NEWHOPE_decrypt(unsigned char *m, unsigned char *ct, unsigned char *sk)
{
    cpapke_dec(m, ct, sk);
}
