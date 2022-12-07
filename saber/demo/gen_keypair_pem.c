#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "test_tools.c"

#define PUBLIC_KEY_FULL_ARG "--public-key"
#define PUBLIC_KEY_ARG "-pk"

#define SECRET_KEY_FULL_ARG "--secret-key"
#define SECRET_KEY_ARG "-sk"

#define HELP_FULL_ARG "--help"
#define HELP_ARG "-h"

const char* pk_file;
const char* sk_file;

void parse_args(const int argc, char **argv) {
    for(int i = 1; i < argc; ++i) {
        if (
            !verify(argv[i], PUBLIC_KEY_FULL_ARG, MIN(strlen(argv[i]), strlen(PUBLIC_KEY_FULL_ARG))) ||
            !verify(argv[i], PUBLIC_KEY_ARG, MIN(strlen(argv[i]), strlen(PUBLIC_KEY_ARG)))
        ) {
            pk_file = argv[++i];
        } else if (
            !verify(argv[i], SECRET_KEY_FULL_ARG, MIN(strlen(argv[i]), strlen(SECRET_KEY_FULL_ARG))) ||
            !verify(argv[i], SECRET_KEY_ARG, MIN(strlen(argv[i]), strlen(SECRET_KEY_ARG)))
        ) {
            sk_file = argv[++i];
        } else if (
            !verify(argv[i], HELP_FULL_ARG, MIN(strlen(argv[i]), strlen(HELP_FULL_ARG))) ||
            !verify(argv[i], HELP_ARG, MIN(strlen(argv[i]), strlen(HELP_ARG)))
        ) {
            printf("Hello! You can generate public and secret key.\n");
            printf("You shoud config it:\n");
            printf("\t--public-key(-pk): Output file for generated public key\n");
            printf("\t--secret-key(-sk): Output file for generated secret key\n");
            exit(0);
        } else {
            printf("Unknow param: %s\n", argv[i]);
            printf("Use --help(-h) for more information\n");
            exit(0);
        }
    }
    int successfull_params = 1;
    if (pk_file) {
        printf("PublicKey file: %s\n", pk_file);
    } else {
        printf("Need file for writing PublicKey\n");
        successfull_params = 0;
    }

    if (sk_file) {
        printf("SecretKey file: %s\n", sk_file);
    } else {
        printf("Need file for writing SecretKey\n");
        successfull_params = 0;
    }

    if (!successfull_params) {
        printf("\nNot correct encoding params\nPlease restart programm with reconfiguring\n");
        exit(1);
    }
}

void gen_keypair(uint8_t pk[SABER_PUBLICKEYBYTES], uint8_t sk[SABER_SECRETKEYBYTES]) {
    indcpa_kem_keypair(pk, sk);
}


int main(const int argc, char **argv) {
    parse_args(argc, argv);

    clear_file(pk_file);
    clear_file(sk_file);

    uint8_t pk[SABER_PUBLICKEYBYTES];
	uint8_t sk[SABER_SECRETKEYBYTES];
	gen_keypair(pk, sk);

    write_file(pk_file, pk, SABER_PUBLICKEYBYTES);
    write_file(sk_file, sk, SABER_SECRETKEYBYTES);
	return 0;
}