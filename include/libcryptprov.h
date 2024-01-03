#include <stdint.h>

#define CRYPT_VERSION                   0x00000001
#define CRYPT_VERSION_STRING            "v0.1"

// Maximum key length
#define CRYPT_MAX_KEY_LEN               (uint8_t)(255)

// Maximum size of buffer provided to crypt_buffer()
//  Max size is 16-bits, but the buffer len itself is 32-bit
#define CRYPT_MAX_BUFFER_SIZE           (uint32_t)(65535)

enum {
    CRYPT_ERROR_OK,
    CRYPT_ERROR_NO_MEMORY,
    CRYPT_ERROR_PARAMETER,
    CRYPT_ERROR_ALREADY_RUNNING
};

// Cryptographic context, contains key state
struct crypt_context {
    unsigned long                       version;
    const char                          *version_string;
    
    // Key
    void                                *key;
    uint16_t                            key_size;
    uint8_t                             key_state; // Holds the symmetric key state
};

// Creates a crypt_context structure. Caller must free using crypt_free_context(). 
int32_t crypt_alloc_context(struct crypt_context **ctx_out, const void *key, uint8_t key_size);

// Free up key and context
void crypt_free_context(struct crypt_context *ctx);

// Primary cryptographic function 
// Returns inputLen if all bytes were encrypted
// Returns 0 if failure
// output and input buffers can be the same
uint32_t crypt_buffer(
    struct crypt_context *ctx,
    uint8_t *output,
    const uint8_t *input,
    uint32_t inputLen
);

unsigned long crypt_get_version_long(void);
const char *crypt_get_version_string(void);