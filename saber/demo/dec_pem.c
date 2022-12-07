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

#define CIPHERTEXT_FULL_ARG "--ciphertext"
#define CIPHERTEXT_ARG "-c"

#define SECRET_KEY_FULL_ARG "--secret-key"
#define SECRET_KEY_ARG "-sk"

#define HELP_FULL_ARG "--help"
#define HELP_ARG "-h"

const char* c_file;
const char* sk_file;

void parse_args(const int argc, char **argv) {
    for(int i = 1; i < argc; ++i) {
        if (
            !verify(argv[i], CIPHERTEXT_FULL_ARG, MIN(strlen(argv[i]), strlen(CIPHERTEXT_FULL_ARG))) ||
            !verify(argv[i], CIPHERTEXT_ARG, MIN(strlen(argv[i]), strlen(CIPHERTEXT_ARG)))
        ) {
            c_file = argv[++i];
        } else if (
            !verify(argv[i], SECRET_KEY_FULL_ARG, MIN(strlen(argv[i]), strlen(SECRET_KEY_FULL_ARG))) ||
            !verify(argv[i], SECRET_KEY_ARG, MIN(strlen(argv[i]), strlen(SECRET_KEY_ARG)))
        ) {
            sk_file = argv[++i];
        } else if (
            !verify(argv[i], HELP_FULL_ARG, MIN(strlen(argv[i]), strlen(HELP_FULL_ARG))) ||
            !verify(argv[i], HELP_ARG, MIN(strlen(argv[i]), strlen(HELP_ARG)))
        ) {
            printf("Hello! You can decrypt message.\n");
            printf("You shoud config it:\n");
			printf("\t--chiphertext(-c): Input file with generated encrypted message\n");
            printf("\t--secret-key(-sk): Input file with SABER secret key\n");
            exit(0);
        } else {
            printf("Unknow param: %s\n", argv[i]);
            printf("Use --help(-h) for more information\n");
            exit(0);
        }
    }
    int successfull_params = 1;
    if (c_file) {
        printf("Chiphertext file: %s\n", c_file);
    } else {
        printf("Need file for reading chiphertext\n");
        successfull_params = 0;
    }

    if (sk_file) {
        printf("SecretKey file: %s\n", sk_file);
    } else {
        printf("Need file for reading SecretKey\n");
        successfull_params = 0;
    }

    if (!successfull_params) {
        printf("\nNot correct encoding params\nPlease restart programm with reconfiguring\n");
        exit(1);
    }
}

void decrypt_message(uint8_t sk[SABER_SECRETKEYBYTES], uint8_t c[SABER_BYTES_CCA_DEC], uint8_t* m) {
	indcpa_kem_dec(sk, c, m);
}

int main(const int argc, char **argv)
{
	parse_args(argc, argv);

	uint8_t sk[SABER_SECRETKEYBYTES];
	read_file(sk_file, sk, SABER_SECRETKEYBYTES);

	uint8_t c[SABER_BYTES_CCA_DEC];
	read_file(c_file, c, SABER_BYTES_CCA_DEC);

	uint8_t m[SABER_KEYBYTES];
	decrypt_message(sk, c, m);

	printf("\nYour original message: %s\n", m);


	return 0;
}