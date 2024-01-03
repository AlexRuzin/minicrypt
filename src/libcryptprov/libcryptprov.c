#include "libcryptprov.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int32_t crypt_alloc_context(struct crypt_context **ctx_out, const void *key, uint8_t key_size)
{
    if (!ctx_out || !key || key_size >= CRYPT_MAX_KEY_LEN) {
        return CRYPT_ERROR_PARAMETER;
    }

    struct crypt_context *ctx = calloc(1, sizeof(struct crypt_context));
    if (!ctx) {
        return CRYPT_ERROR_NO_MEMORY;
    }

    memset(ctx, 0x00, sizeof(struct crypt_context));

    ctx->version = crypt_get_version_long();
    ctx->version_string = crypt_get_version_string();

    ctx->key = malloc(key_size);
    if (!ctx->key) {
        free(ctx);
        return CRYPT_ERROR_NO_MEMORY;
    }

    memcpy(ctx->key, key, key_size);
    ctx->key_size = key_size;
    ctx->key_state = 0;

    *ctx_out = ctx;
    return CRYPT_ERROR_OK;
}

void crypt_free_context(struct crypt_context *ctx)
{
    if (!ctx) {
        return;
    }

    // zero out the key state just in case
    memset(ctx->key, 0x00, ctx->key_size);
    free(ctx->key);
    memset(ctx, 0x00, sizeof(struct crypt_context));
    free(ctx);

    return;
}

uint32_t crypt_buffer(
    struct crypt_context *ctx,
    uint8_t *output,
    const uint8_t *input,
    uint32_t inputLen)
{
    // Sanity check
    if (!ctx || !output || !input || inputLen == 0 || !ctx->key || ctx->key_size == 0) {
        return CRYPT_ERROR_PARAMETER;
    }

    if (inputLen > CRYPT_MAX_BUFFER_SIZE || ctx->key_size >= CRYPT_MAX_KEY_LEN) {
        return CRYPT_ERROR_NO_MEMORY;
    }

    const uint8_t key_size = ctx->key_size;
    
    // Key state is preserved in crypt_context
    uint8_t *key_ptr = (uint8_t *)ctx->key;  
    uint8_t i = ctx->key_state;

    for (uint32_t pos = 0; pos < inputLen; pos++) {
        key_ptr[i] = (key_ptr[i] + i) % 256;
        output[pos] = input[pos] ^ key_ptr[i];
        i = (i + 1) % key_size;
    }

    ctx->key_state = i;

    return inputLen;
}

unsigned long crypt_get_version_long(void)
{
    return CRYPT_VERSION;
}

const char *crypt_get_version_string(void)
{
    return CRYPT_VERSION_STRING;
}

//EOF