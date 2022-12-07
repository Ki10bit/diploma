#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../pack_unpack.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "test_tools.c"

void pol_ut() {
    uint8_t bytes[SABER_SCALEBYTES_KEM];
    uint16_t data[SABER_N];
    randombytes(bytes, SABER_SCALEBYTES_KEM);

    uint8_t bytes_cp[SABER_SCALEBYTES_KEM];
    memcpy(bytes_cp, bytes, SABER_SCALEBYTES_KEM);

    BS2POLT(bytes, data);
    POLT2BS(bytes, data);

    if (verify(bytes, bytes_cp)) {
        printf("pol_ut ERROR\n");
		return;
    }
}

void pol_vec_q_ut() {
    uint8_t bytes[SABER_POLYVECBYTES];
    uint16_t data[SABER_L][SABER_N];
    randombytes(bytes, SABER_POLYVECBYTES);

    uint8_t bytes_cp[SABER_POLYVECBYTES];
    memcpy(bytes_cp, bytes, SABER_POLYVECBYTES);

    BS2POLVECq(bytes, data);
    POLVECq2BS(bytes, data);

    if (verify(bytes, bytes_cp)) {
        printf("pol_ut ERROR\n");
		return;
    }
}

void pol_vec_p_ut() {
    uint8_t bytes[SABER_POLYVECCOMPRESSEDBYTES];
    uint16_t data[SABER_L][SABER_N];
    randombytes(bytes, SABER_POLYVECCOMPRESSEDBYTES);

    uint8_t bytes_cp[SABER_POLYVECCOMPRESSEDBYTES];
    memcpy(bytes_cp, bytes, SABER_POLYVECCOMPRESSEDBYTES);

    BS2POLVECp(bytes, data);
    POLVECp2BS(bytes, data);

    if (verify(bytes, bytes_cp)) {
        printf("pol_ut ERROR\n");
		return;
    }
}



int main(int argc, char **argv) {
    pol_ut();
    pol_vec_q_ut();
    pol_vec_p_ut();

	return 0;
}
