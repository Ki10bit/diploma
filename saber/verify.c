#include <string.h>
#include <stdint.h>
#include "verify.h"

int verify(const unsigned char *a, const unsigned char *b, size_t len)
{
  uint64_t r;
  size_t i;
  r = 0;

  for (i = 0; i < len; i++)
    r |= a[i] ^ b[i];

  r = (-r) >> 63;

  return r;
}

void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b)
{
  size_t i;

  b = -b;
  for (i = 0; i < len; i++)
    r[i] ^= b & (x[i] ^ r[i]);
}
