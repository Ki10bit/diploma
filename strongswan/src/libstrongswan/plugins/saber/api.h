#ifndef API_H
#define API_H

#include "SABER_params.h"


#define CRYPTO_ALGNAME SABER_PREFIX SABER_VARIANT SABER_POSTFIX
#define CRYPTO_SECRETKEYBYTES SABER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES SABER_PUBLICKEYBYTES
#define CRYPTO_BYTES SABER_KEYBYTES
#define CRYPTO_CIPHERTEXTBYTES SABER_BYTES_CCA_DEC

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
