#include <stdint.h>

#define CRYPT_MAIN_VERSION          "1.0"

// Stdin buffer size maximum
#define CRYPT_STDIN_BUF_SIZE        0x10

struct crypt_params {
    // Key
    uint8_t                         *key;
    uint16_t                        key_size;

    // Input buffer
    uint8_t                         *input_buffer; // if NULL, use stdi
    uint32_t                        input_buffer_size;

    // Output buffer, pointer originates from args to main() and 
    //  must not be deallocated
    char                            *output_buffer_path;
};
