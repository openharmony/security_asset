#include "hks_key.h"
#include "hks_param.h"
#include "asset_log.h"

static struct HksParam g_genParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }
};

int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    if (paramSet == NULL || params == NULL || paramcount == 0) {
        LOGE("bad params\n");
        return HKS_FAILURE;
    }

    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        LOGE("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        LOGE("HksAddParams failed");
        HksFreeParamSet(paramSet);
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        LOGE("HksBuildParamSet failed!");
        HksFreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

int32_t GenerateKey(uint32_t keyLen, const uint8_t *keyData)
{
    struct HksBlob keyAlias = { keyLen, (uint8_t *)keyData };
    struct HksParamSet *paramSetIn = NULL;
    int32_t ret = InitParamSet(&paramSetIn, g_genParams, sizeof(g_genParams) / sizeof(HksParam));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HksGenerateKey(&keyAlias, paramSetIn, nullptr);
}

int32_t DeleteKey(uint32_t keyLen, const uint8_t *keyData)
{
    struct HksBlob keyAlias = { keyLen, (uint8_t *)keyData };
    return HksDeleteKey(&keyAlias, nullptr);
}

int32_t KeyExist(uint32_t keyLen, const uint8_t *keyData)
{
    struct HksBlob keyAlias = { keyLen, (uint8_t *)keyData };
    return HksKeyExist(&keyAlias, nullptr);
}