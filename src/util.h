#include <stdbool.h>

#define MAX_FILE_BUF_SIZE                           65535

// This will be MAX_PATH on Win32
#define MAX_FILE_PATH                               255

#define DEBUG_ERR(fmt, ...) debug(true, fmt, ##__VA_ARGS__);
#define DEBUG_INFO(fmt, ...) debug(false, fmt, ##__VA_ARGS__);

// Debugging function
void debug(bool is_error, const char *format, ...);

// Validate path sanity
bool is_path_valid(const char *p);

// Reads a file, allocates memory, and returns the total bytes read. 0 is returned
//  if there is a failure
// Caller must free()
uint32_t read_file_into_memory(const char *path, uint8_t **out);

// Custom implementation of strnlen, but it is POSIX-compliant
uint32_t strnlen(const char *s, uint32_t n);

// Ask user for input via stdin
//  Return the stdin buffer, must be free()'d
//  Return the out_size
//  If return is NULL, then error
// Used for grabbing the key via stdin
//  stdin for input buffer is handled by cryptmain.c
const char *get_stdin_user(uint16_t *out_size, uint32_t max_size);

// Write target buffer to file, create file if it does not exist
//  Return number of bytes written, or -1 if failed
uint32_t write_to_file(const char *filename, const void *buf, uint32_t buf_size);

// Read from stdin until a max buffer count is reached
//  If the return value is less than the input_buffer, then the EOF has been reached
uint32_t read_from_stdin(uint8_t *buf, uint32_t buf_max_size);