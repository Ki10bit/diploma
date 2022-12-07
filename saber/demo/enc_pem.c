#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "test_tools.c"

#define HELP_FULL_ARG "--help"
#define HELP_ARG "-h"

#define PUBLIC_KEY_FULL_ARG "--public-key"
#define PUBLIC_KEY_ARG "-pk"

#define MESSAGE_FULL_ARG "--message"
#define MESSAGE_ARG "-m"

#define CIPHERTEXT_FULL_ARG "--ciphertext"
#define CIPHERTEXT_ARG "-c"

const char* pk_file;
char* m;
const char* c_file;

void parse_args(const int argc, char **argv) {
    for(int i = 1; i < argc; ++i) {
        if (
            !verify(argv[i], PUBLIC_KEY_FULL_ARG, MIN(strlen(argv[i]), strlen(PUBLIC_KEY_FULL_ARG))) ||
            !verify(argv[i], PUBLIC_KEY_ARG, MIN(strlen(argv[i]), strlen(PUBLIC_KEY_ARG)))
        ) {
            pk_file = argv[++i];
        } else if (
            !verify(argv[i], MESSAGE_FULL_ARG, MIN(strlen(argv[i]), strlen(MESSAGE_FULL_ARG))) ||
            !verify(argv[i], MESSAGE_ARG, MIN(strlen(argv[i]), strlen(MESSAGE_ARG)))
        ) {
            ++i;
            size_t m_size = 0;
            int m_words_count = 0;
            while (i + m_words_count < argc && argv[i + m_words_count][0] != '-') {
                if (m_words_count != 0) {
                    ++m_size;
                }
                m_size += strlen(argv[i + m_words_count]);
                ++m_words_count;
            }
            m = (char*) malloc(m_size * sizeof(char) + 1);
            for (int w_counter = 0, j = 0; w_counter < m_words_count; ++w_counter) {
                if (w_counter != 0) {
                    m[j++] = ' ';
                }
                size_t cur_w_len = strlen(argv[i + w_counter]);
                memcpy(m + j, argv[i + w_counter], cur_w_len);
                j += cur_w_len;
            }
            m[m_size + 1] = '\0';

            i += m_words_count - 1;
        } else if (
            !verify(argv[i], CIPHERTEXT_FULL_ARG, MIN(strlen(argv[i]), strlen(CIPHERTEXT_FULL_ARG))) ||
            !verify(argv[i], CIPHERTEXT_ARG, MIN(strlen(argv[i]), strlen(CIPHERTEXT_ARG)))
        ) {
            c_file = argv[++i];
        } else if (
            !verify(argv[i], HELP_FULL_ARG, MIN(strlen(argv[i]), strlen(HELP_FULL_ARG))) ||
            !verify(argv[i], HELP_ARG, MIN(strlen(argv[i]), strlen(HELP_ARG)))
        ) {
            printf("Hello! You can encrypt your message.\n");
            printf("You shoud config it:\n");
            printf("\t--public-key(-pk): Input file with SABER public key\n");
            printf("\t--chiphertext(-c): Output file for generated encrypted message\n");
            printf("\t--message(-m): Encrypted message\n");
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
        printf("Need file with PublicKey for encoding\n");
        successfull_params = 0;
    }

    if (c_file) {
        printf("Chiphertext file: %s\n", c_file);
    } else {
        printf("Need file for writing chiphertext\n");
        successfull_params = 0;
    }

    if (m) {
        printf("Message for encoding: %s\n", m);
    } else {
        printf("Need message for encoding\n");
        successfull_params = 0;
    }

    if (!successfull_params) {
        printf("\nNot correct encoding params\nPlease restart programm with reconfiguring\n");
        exit(1);
    }
}

void encrypt_message(char* pk, uint8_t* c) {
    // char* pk;
    read_file(pk_file, pk, SABER_PUBLICKEYBYTES);

    uint8_t seed_sp[SABER_NOISE_SEEDBYTES];
	randombytes(seed_sp, SABER_KEYBYTES);

    // char* c;
    indcpa_kem_enc(m, seed_sp, pk, c);
}


int main(int argc, char **argv) {
    parse_args(argc, argv);

    uint8_t pk[SABER_PUBLICKEYBYTES];
    read_file(pk_file, pk, SABER_PUBLICKEYBYTES);

    uint8_t c[SABER_BYTES_CCA_DEC];
    encrypt_message(pk, c);

    clear_file(c_file);
    write_file(c_file, c, SABER_BYTES_CCA_DEC);

    free(m);

	return 0;
}