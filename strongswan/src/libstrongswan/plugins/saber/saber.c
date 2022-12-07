#include "saber.h"
#include "SABER_params.h"
#include "saber_utils.h"

#include <utils/debug.h>

typedef struct private_saber_t private_saber_t;


struct private_saber_t {

	/**
	 * Public saber_t interface.
	 */
	saber_t public;

	/**
	 * key exchange method
	 */
	key_exchange_method_t method;

	/**
	 * Saber parameters
	 */
	const saber_params_t *params;

	/**
	 * Public Key
	 */
	uint8_t *public_key;

	/**
	 * Secret Key
	 */
	uint8_t *secret_key;

	/**
	 * Ciphertext
	 */
	uint8_t *ciphertext;

	/**
	 * Shared secret
	 */
	uint8_t *shared_secret;

	/**
	 * NIST CTR DRBG
	 */
	drbg_t *drbg;

	/**
	 * SHAKE-128 or SHAKE-256 eXtended Output Function
	 */
	xof_t *xof;

};



static bool generate(private_saber_t *this)
{
	int i;

	indcpa_kem_keypair(pk, sk);
	for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++)
		this->secret_key[i + SABER_INDCPA_SECRETKEYBYTES] = this->public_key[i];

	hash_h(this->secret_key + SABER_SECRETKEYBYTES - 64, this->public_key, SABER_INDCPA_PUBLICKEYBYTES);

	randombytes(this->secret_key + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES);
	return TRUE;
}


static bool encaps_shared_secret(private_saber_t *this)
{
	unsigned char kr[64];
	unsigned char buf[64];

	randombytes(buf, 32);

	hash_h(buf, buf, 32);

	hash_h(buf + 32, this->public_key, SABER_INDCPA_PUBLICKEYBYTES);

	hash_g(kr, buf, 64);

	indcpa_kem_enc(buf, kr + 32, this->public_key, this->ciphertext);

	hash_h(kr + 32, c, SABER_BYTES_CCA_DEC);

	hash_h(k, kr, 64);

	return TRUE;
}


static bool decaps_shared_secret(private_saber_t *this)
{
	 int i, fail;
	unsigned char cmp[SABER_BYTES_CCA_DEC];
	unsigned char buf[64];
	unsigned char kr[64];
	const unsigned char *pk = this->sk + SABER_INDCPA_SECRETKEYBYTES;

	indcpa_kem_dec(sk, c, buf);

	for (i = 0; i < 32; i++)
		buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];

	hash_g(kr, buf, 64);

	indcpa_kem_enc(buf, kr + 32, this->pk, cmp);

	fail = verify(c, cmp, SABER_BYTES_CCA_DEC);

	hash_h(kr + 32, c, SABER_BYTES_CCA_DEC);

	cmov(kr, sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES, fail);

	hash_h(k, kr, 64);
	memwipe((uint8_t *)W, nb_x_nb * sizeof(uint16_t));

	return TRUE;
}


static bool set_ciphertext(private_saber_t *this, chunk_t value)
{
	if (value.len != this->params->ct_len)
	{
		DBG1(DBG_LIB, "wrong %N ciphertext size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->params->ct_len);
		return FALSE;
	}
	this->ciphertext = malloc(value.len);
	memcpy(this->ciphertext, value.ptr, value.len);

	return decaps_shared_secret(this);
}

METHOD(key_exchange_t, get_public_key, bool,
	private_saber_t *this, chunk_t *value)
{
	if (this->ciphertext)
	{
		*value = chunk_clone(
					chunk_create(this->ciphertext, this->params->ct_len));
		return TRUE;
	}

	if (!this->secret_key)
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
	}
	*value = chunk_clone(chunk_create(this->public_key, this->params->pk_len));

	return TRUE;
}


METHOD(key_exchange_t, get_shared_secret, bool,
	private_saber_t *this, chunk_t *secret)
{
	*secret = chunk_clone(
				chunk_create(this->shared_secret, this->params->ss_len));
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_saber_t *this, chunk_t value)
{
	if (this->secret_key)
	{
		return set_ciphertext(this, value);
	}

	if (value.len != this->params->pk_len)
	{
		DBG1(DBG_LIB, "wrong %N public key size of %u bytes, %u bytes expected",
			 key_exchange_method_names, this->method, value.len,
			 this->params->pk_len);
		return FALSE;
	}
	memcpy(this->public_key, value.ptr, value.len);

	return need_drbg(this) && encaps_shared_secret(this);
}


METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_saber_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, set_seed, bool,
	private_saber_t *this, chunk_t value, drbg_t *drbg)
{
	DESTROY_IF(this->drbg);
	this->drbg = drbg->get_ref(drbg);

	return TRUE;
}

METHOD(key_exchange_t, destroy, void,
	private_saber_t *this)
{
	DESTROY_IF(this->drbg);
	this->xof->destroy(this->xof);

	memwipe(this->secret_key, this->params->sk_len);
	free(this->secret_key);
	memwipe(this->shared_secret, this->params->ss_len);
	free(this->shared_secret);
	free(this->public_key);
	free(this->ciphertext);
	free(this);
}


saber_t *saber_create(key_exchange_method_t method)
{
	private_saber_t *this;
	const saber_params_t *params;
	saber_kem_type_t id;
	bool use_aes;
	xof_t *xof;

	switch (method)
	{
		case KE_SABER_L1:
			id = SABER_KEM_L1;
			use_aes = TRUE;
			break;
		case KE_SABER_L3:
			id = SABER_KEM_L3;
			use_aes = TRUE;
			break;
		case KE_SABER_L5:
			id = SABER_KEM_L5;
			use_aes = TRUE;
			break;
		default:
			return NULL;
	}
	params = saber_params_get_by_id(id);
	crypto_kem_keypair(this->public_key, this->secret_key)

	xof = lib->crypto->create_xof(lib->crypto, params->xof_type);
	if (!xof)
	{
		DBG1(DBG_LIB, "could not instantiate %N", ext_out_function_names,
					   params->xof_type);
		return NULL;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_method = _get_method,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_shared_secret = _get_shared_secret,
				.set_seed = _set_seed,
				.destroy = _destroy,
			},
		},
		.method = method,
		.use_aes = use_aes,
		.params = params,
		.xof = xof,
		.public_key = malloc(params->pk_len),
		.shared_secret = malloc(params->ss_len),
	);

	return &this->public;
}
