CC = 	gcc
LDFLAGS = -lcrypto

CFLAGS += -I $(srcdir) -std=c99 -pedantic -Wall -Wextra -Wconversion -Wcast-qual -Wcast-align
CFLAGS += -g -DDEBUG -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv
HEADERS = aesdrbg.h a_fixed.h a_random.h chooseparameters.h drbg.h keccakf1600.h kem.h little_endian.h misc.h pack.h r5_cca_kem.h r5_cca_pke.h r5_cpa_kem.h r5_cpa_pke.h r5_dem.h r5_hash.h r5_memory.h r5_parameter_sets.h r5_secretkeygen.h ringmul.h rng.h xef.h 
SOURCES = aesdrbg.c a_fixed.c a_random.c keccakf1600.c kem.c little_endian.c matmul_avx2.c matmul.c matmul_ct.c misc.c pack.c pke.c r5_cca_kem.c r5_cca_pke.c r5_cpa_kem.c r5_cpa_pke_n1.c r5_cpa_pke_nd.c r5_dem.c r5_hash.c r5_memory.c r5_secretkeygen.c ringmul_avx2.c ringmul.c ringmul_cm.c ringmul_ct.c xe2_c16.c xe4_c64.c xe5_c64.c xef_ref.c
FLAGSPIC = -c
FLAGSLIB = -shared

.PHONY: clean, libround5

libround5: round5lib
	$(CC) $(FLAGSLIB) -fvisibility=hidden -o libround5.so *.o $(LDFLAGS)

round5lib : $(SOURCES) $(HEADERS)
	$(CC) $(FLAGSPIC) $(SOURCES) -fpic

clean:
	-rm *.o