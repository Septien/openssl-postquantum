/* Reduction on the public domain implementation in
 * crypto_hash/keccakc512/simple/ 
 * from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 **/

#include "keccakf1600.h"

#include "chooseparameters.h"

#define NROUNDS 24
#define ROL(X, Y) (((X) << (Y)) ^ ((X) >> (64-(Y))))

static const uint64_t KeccakF_RoundConstants[NROUNDS] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

inline uint64_t load64(const uint8_t *x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *((const uint64_t *)(x));
#else
	return (((uint64_t) (x[0]))       ) | (((uint64_t) (x[1])) <<  8 )
	     | (((uint64_t) (x[2])) << 16 ) | (((uint64_t) (x[3])) << 24 )
	     | (((uint64_t) (x[4])) << 32 ) | (((uint64_t) (x[5])) << 40 )
	     | (((uint64_t) (x[6])) << 48 ) | (((uint64_t) (x[7])) << 56 ) );
#endif
}


inline void store64(uint8_t *x, uint64_t u)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	*((uint64_t *)(x)) = u;
#else
	x[0] = u      ; x[1] = u >>  8;
	x[2] = u >> 16; x[3] = u >> 24;
	x[4] = u >> 32; x[5] = u >> 40;
	x[6] = u >> 48; x[7] = u >> 56;
#endif
}

void KeccakF1600_StateExtractBytes(uint64_t *state, uint8_t *data Parameters )
{
	size_t i;       
	for (i = 0; i < RATE / 8; i++) {
		store64(data+8*i, state[i]);
	}
}

void KeccakF1600_StateXORBytes(uint64_t *state, const uint8_t *data Parameters )
{
	size_t i;

	for (i = 0; i < RATE / 8; ++i) {
		state[i] ^= load64(data + 8 * i);
	}
}

