#ifndef SAber_H_
#define SAber_H_

typedef struct saber_t saber_t;

#include <library.h>

struct saber_t {

	/**
	 * Implements key_exchange_t interface.
	 */
	key_exchange_t ke;
};

saber_t *saber_create(key_exchange_method_t method);

#endif /* SABER_H_ */
