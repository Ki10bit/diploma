CC 		  = /usr/bin/gcc
CFLAGS  = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native
CFLAGS_D = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-d1
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99
NISTFLAGS_D  = -Wno-unused-result -d1 -fomit-frame-pointer -march=native -std=c99
CLANG   = clang -march=native -O3 -fomit-frame-pointer -fwrapv -Qunused-arguments
RM 		  = /bin/rm
INC     = -I /usr/bin

all: test/test_kex \
     test/kem \
	 demo/demo_gen \
	 demo/demo_enc \
	 demo/demo_dec \

SOURCES = pack_unpack.c poly.c verify.c cbd.c SABER_indcpa.c kem.c \
			fips202.c sha256.c sha512.c aes256ctr.c symmetric-aes.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h verify.h cbd.h SABER_indcpa.h \
			fips202.h aes256ctr.h sha2.h symmetric.h

test/test_kex: $(SOURCES) $(HEADERS) rng.o test/test_kex.c
	$(CC) $(CFLAGS_D) -o $@ $(SOURCES) rng.o test/test_kex.c -lcrypto

test/PQCgenKAT_kem: $(SOURCES) $(HEADERS) rng.o test/PQCgenKAT_kem.c
	$(CC) $(NISTFLAGS_D) -o $@ $(SOURCES) rng.o test/PQCgenKAT_kem.c -lcrypto

test/kem: $(SOURCES) $(HEADERS) rng.o test/kem.c
	$(CC) $(CFLAGS_D) -o $@ $(SOURCES) rng.o test/kem.c -lcrypto

demo/demo_gen: $(SOURCES) $(HEADERS) rng.o demo/gen_keypair_pem.c
	$(CC) $(CFLAGS_D) -o $@ $(SOURCES) rng.o demo/gen_keypair_pem.c -lcrypto

demo/demo_enc: $(SOURCES) $(HEADERS) rng.o demo/enc_pem.c
	$(CC) $(CFLAGS_D) -o $@ $(SOURCES) rng.o demo/enc_pem.c -lcrypto

demo/demo_dec: $(SOURCES) $(HEADERS) rng.o demo/dec_pem.c
	$(CC) $(CFLAGS_D) -o $@ $(SOURCES) rng.o demo/dec_pem.c -lcrypto

rng.o: rng.c
	$(CC) $(NISTFLAGS_D) $(INC) -c rng.c -lcrypto -o $@

.PHONY: clean test

test:
	./test/test_kex
	./test/kem

clean:
	-$(RM) -f *.o
	-$(RM) -rf test/test_kex
	-$(RM) -rf test/kem
	-$(RM) -rf demo/gen_keypair_pem
	-$(RM) -rf demo/enc_pem
	-$(RM) -rf demo/dec_pem
	-$(RM) -f *.req
	-$(RM) -f *.rsp
