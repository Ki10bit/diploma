#include "SABER_params.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "SABER_indcpa.h"
#include "api.h"
#include "verify.h"
#include "rng.h"
#include "fips202.h"
#include "symmetric.h"



int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  int i;

  indcpa_kem_keypair(pk, sk);
  for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++)
    sk[i + SABER_INDCPA_SECRETKEYBYTES] = pk[i];

  hash_h(sk + SABER_SECRETKEYBYTES - 64, pk, SABER_INDCPA_PUBLICKEYBYTES);

  randombytes(sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES);
  return (0);
}

int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk)
{
  unsigned char kr[64];
  unsigned char buf[64];

  randombytes(buf, 32);

  hash_h(buf, buf, 32);

  hash_h(buf + 32, pk, SABER_INDCPA_PUBLICKEYBYTES);

  hash_g(kr, buf, 64);

  indcpa_kem_enc(buf, kr + 32, pk, c);

  hash_h(kr + 32, c, SABER_BYTES_CCA_DEC);

  hash_h(k, kr, 64);

  return (0);
}

int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  int i, fail;
  unsigned char cmp[SABER_BYTES_CCA_DEC];
  unsigned char buf[64];
  unsigned char kr[64];
  const unsigned char *pk = sk + SABER_INDCPA_SECRETKEYBYTES;

  indcpa_kem_dec(sk, c, buf);

  for (i = 0; i < 32; i++)
    buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];

  hash_g(kr, buf, 64);

  indcpa_kem_enc(buf, kr + 32, pk, cmp);

  fail = verify(c, cmp, SABER_BYTES_CCA_DEC);

  hash_h(kr + 32, c, SABER_BYTES_CCA_DEC);

  cmov(kr, sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES, fail);

  hash_h(k, kr, 64);

  return (0);
}
