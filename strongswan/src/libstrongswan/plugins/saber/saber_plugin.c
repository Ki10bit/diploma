#include "saber_plugin.h"
#include "saber.h"

#include <library.h>

typedef struct private_saber_plugin_t private_saber_plugin_t;

struct private_saber_plugin_t {

	saber_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_saber_plugin_t *this)
{
	return "saber";
}

METHOD(plugin_t, get_features, int,
	private_saber_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, saber_create),
			PLUGIN_PROVIDE(KE, KE_SABER_L1),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_SABER_L3),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_SABER_L5),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
	};
	*features = f;

	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_saber_plugin_t *this)
{
	free(this);
}

plugin_t *saber_plugin_create()
{
	private_saber_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
