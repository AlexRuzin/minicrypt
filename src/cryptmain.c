#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptprov.h"
#include "cryptmain.h"
#include "util.h"

// Parse the command line arguments into crypt_params
//  This function will validate CLI parameters
//  This function will read from target files and load them into memory
//  This function will populate the key
//  This function will block for stdin (i.e. key)
//  stdin on the input file will not block
static struct crypt_params *parse_cli_and_load(int32_t argc, char *argv[]);

// Mode when there is a specified input file
static int32_t mode_input_file(struct crypt_context *ctx, const struct crypt_params *params);

// Mode when there is no specified input file, and so block on stdin until EOF
static int32_t mode_input_stdin(struct crypt_context *ctx, const struct crypt_params *params);

// Write output buffer to either file or stdout
//  0 returns an error
static uint32_t write_output_buffer(const struct crypt_params *params, void *buf, uint32_t buf_size);

// Free up all i/o buffers and parameters
static void free_cli_params(struct crypt_params *p);

// Debugging: print the values of crypt_params
static void print_cli_params(const struct crypt_params *p);

// Generic print help
static void print_help(void);

int32_t main(int32_t argc, char **argv)
{
    DEBUG_INFO(" [crypt] (v%s)", CRYPT_MAIN_VERSION);
    DEBUG_INFO("libcryptprov version: %s (0x%08x)\n", crypt_get_version_string(), crypt_get_version_long());

    //
    // Parse command line parameters into params structure
    //
    struct crypt_params *params = parse_cli_and_load(argc, argv);
    if (!params || !params->key) {
        print_help();
        return -1;
    }
    print_cli_params(params);

    //
    // Initialize crypt context, provided key from cli input
    //
    struct crypt_context *crypt_ctx = NULL;
    int32_t res = crypt_alloc_context(&crypt_ctx, params->key, params->key_size);
    if (res != CRYPT_ERROR_OK) {
        DEBUG_ERR("Failed to initialize cryptographic context: 0x%08x", res);
        free_cli_params(params);
        return res;
    }

    //
    // Enter one of two modes
    //  1) An input file was provided, therefore encrypt the entire file in one go and write
    //      it to either stdout or a specified file
    //  2) No input file was specified, therefore assume stdin, block on stdin unti EOF.
    //      Write from stdin to the cipher function in blocks until EOF is reached, preserving
    //      the context of the key and re-entering the function as data is received.
    //
    if (params->input_buffer) {
        res = mode_input_file(crypt_ctx, params);
    } else {
        res = mode_input_stdin(crypt_ctx, params);
    }

    if (res) {
        DEBUG_ERR("Failed to process I/O: 0x%08x", res);
    }

    //
    // Cleanup
    //
    DEBUG_INFO("Cleanup...");
    crypt_free_context(crypt_ctx);
    free_cli_params(params);
    return 0;
}

static int32_t mode_input_file(struct crypt_context *ctx, const struct crypt_params *params)
{
    if (!ctx || !params || !params->input_buffer) {
        return -1;
    }

    uint8_t *out_buf = (uint8_t *)calloc(params->input_buffer_size, sizeof(uint8_t));
    if (!out_buf) {
        DEBUG_ERR("mode_input_file: out of memory");
        return -1;
    }

    uint32_t res = crypt_buffer(ctx, out_buf, params->input_buffer, params->input_buffer_size);
    if (res != params->input_buffer_size) {
        return res;
    }

    res = write_output_buffer(params, out_buf, params->input_buffer_size);
    if (res != params->input_buffer_size) {
        DEBUG_ERR("mode_input_file: failed to write file to: %s", 
            params->output_buffer_path ? params->output_buffer_path : "stdout");
        free(out_buf);
        return res;
    }

    free(out_buf);
    return 0;
}

static int32_t mode_input_stdin(struct crypt_context *ctx, const struct crypt_params *params)
{
    if (!ctx || !params) {
        return -1;
    }

    uint8_t stdin_buf[CRYPT_STDIN_BUF_SIZE];
    uint32_t total_read = 0;

    fflush(stdin);
    fflush(stdout);
    for (;;) {
        memset(stdin_buf, 0x00, CRYPT_STDIN_BUF_SIZE);
        uint32_t stdin_buf_read = read_from_stdin(stdin_buf, CRYPT_STDIN_BUF_SIZE);
        total_read += stdin_buf_read;

        // Just write to the same buffer
        crypt_buffer(ctx, stdin_buf, stdin_buf, stdin_buf_read);

        uint32_t res = write_output_buffer(params, stdin_buf, stdin_buf_read);
        if (res != stdin_buf_read) {
            DEBUG_ERR("Failed to write to stream: 0x%08x", res);
        }

        // Have we reached an EOF?
        if (stdin_buf_read < CRYPT_STDIN_BUF_SIZE) {
            break;
        }
    }
    
    DEBUG_INFO("mode_input_stdin: total read: %d", total_read);
    return 0;
}

static uint32_t write_output_buffer(const struct crypt_params *params, void *buf, uint32_t buf_size)
{
    if (!params || !buf || buf_size == 0) {
        return 0;
    }

    if (params->output_buffer_path) {
        // Write the output buffer to a file path specified by CLI
        // Default behaviour is to append to a file if it exists,
        // or create it if it does not        
        const uint32_t bytes_written = write_to_file(params->output_buffer_path, buf, buf_size);
        if (bytes_written != buf_size) {
            DEBUG_ERR("Failed to write file: %d written (%d expected)", bytes_written, buf_size);
            return bytes_written;
        }
        DEBUG_INFO("Written output to file %s (size: %d)", params->output_buffer_path, buf_size);
    } else {
        // Otherwise, write to stdout
        fflush(stdout);
        fwrite(buf, 1, buf_size, stdout);
    }

    return buf_size;
}

static void print_cli_params(const struct crypt_params *p)
{
    if (!p) {
        return;
    }

    DEBUG_INFO("key: %s (size: %d)", p->key, p->key_size);

    if (p->input_buffer) {
        DEBUG_INFO("input_buf: %s (size: %d)", p->input_buffer, p->input_buffer_size);
    } else {
        DEBUG_INFO("input_buf: stdin");
    }

    if (p->output_buffer_path) {
        DEBUG_INFO("output_buf_path: %s", p->output_buffer_path);
    } else {
        DEBUG_INFO("output_buf_path: stdout");
    }
}

// Careful parsing input (i.e. stack overrun via command line)
static struct crypt_params *parse_cli_and_load(int32_t argc, char *argv[])
{
    if (argc <= 1) {
        return NULL;
    }

    struct crypt_params *params = (struct crypt_params *)calloc(sizeof(struct crypt_params), sizeof(uint8_t));

    uint8_t *buf = NULL;
    uint32_t buf_size = 0;

    for (uint8_t curr_arg = 1; curr_arg < argc; curr_arg++) {
        if (!strncmp("-h", argv[curr_arg], 2)) {
            DEBUG_INFO("Printing help...");
            goto params_fail;

        } else if (!strncmp("-k", argv[curr_arg], 2)) {
            // Read key from command line arg

            if (params->key) {
                DEBUG_ERR("Key parameter already set, exiting");
                goto params_fail;
            }

            buf_size = strnlen(argv[curr_arg + 1], CRYPT_MAX_KEY_LEN);

            if ((curr_arg + 1) >= argc || buf_size >= CRYPT_MAX_KEY_LEN) {
                DEBUG_ERR("Invalid parameter for -k");
                goto params_fail;
            }

            // We need to allocate a buffer for the key, since key might come from a file 
            //  and a crash will happen trying to free() an element of argv[]
            params->key = (uint8_t *)malloc(buf_size);
            memcpy(params->key, argv[curr_arg + 1], buf_size);
            params->key_size = buf_size;

            curr_arg++;
            continue;

        } else if (!strncmp("-f", argv[curr_arg], 2)) {
            // Read key from file

            // If the params->key buffer already exists, then -k and -f were used together, return help output
            if (params->key) {
                DEBUG_ERR("Key parameter already set, exiting");
                goto params_fail;
            }

            // Validate file path for "-f"
            if ((curr_arg + 1) >= argc || !is_path_valid(argv[curr_arg + 1])) {
                DEBUG_ERR("Invalid parameter for -f, or path not valid: %s", argv[curr_arg + 1]);
                goto params_fail;
            }

            // Read file specified for -f into heap
            buf_size = read_file_into_memory(argv[curr_arg + 1], &buf);
            if (!buf_size) {
                DEBUG_ERR("Invalid path for -f: %s", argv[curr_arg + 1]);
                goto params_fail;
            }

            params->key = buf;
            params->key_size = buf_size;

            curr_arg++;
            continue;

        } else if (!strncmp("-o", argv[curr_arg], 2)) {
            // The output file must be specified, doesn't need to exist at this point, however

            const uint32_t path_len = strnlen(argv[curr_arg + 1], MAX_FILE_PATH);
            if ((curr_arg + 1) >= argc || path_len >= MAX_FILE_PATH) {
                DEBUG_ERR("Invalid specifier for -o");
                goto params_fail;
            }

            // `-o -` is provided, then used stdout is to be used
            if (argv[curr_arg + 1][0] == '-') {
                curr_arg++;
                continue;
            }    
            
            params->output_buffer_path = (char *)calloc(path_len + sizeof('\0'), sizeof(char));
            memcpy(params->output_buffer_path, argv[curr_arg + 1], path_len);

            curr_arg++;
            continue;

        } else {
            if (params->input_buffer) {
                goto params_fail;
            }

            // This may be a path, if it is, then it must be a path for the input buffer
            if (!is_path_valid(argv[curr_arg])) {
                DEBUG_ERR("Input file %s does not exist", argv[curr_arg]);
                goto params_fail;
            }

            // Read file specified for -f into heap
            buf_size = read_file_into_memory(argv[curr_arg], &buf);
            if (!buf_size) {
                DEBUG_ERR("Invalid path for -f: %s", argv[curr_arg + 1]);
                goto params_fail;
            }

            params->input_buffer = buf;
            params->input_buffer_size = buf_size;

            curr_arg++;
            continue;
        }

        DEBUG_ERR("Invalid parameter");
        goto params_fail;
    }

    if (!params->key) {
        // Key was not specified in command line, ask through stdin
        DEBUG_INFO("Enter symmetric key: ");
        uint8_t *key = (uint8_t *)get_stdin_user(&params->key_size, CRYPT_MAX_KEY_LEN);
        if (!key) {
            DEBUG_ERR("Failed to get symmetric key");
            goto params_fail;
        }

        params->key = key;
    }

    return params;

params_fail:
    if (params) {
        if (params->input_buffer) {
            memset(params->input_buffer, 0x00, params->input_buffer_size);
            free(params->input_buffer);
        }

        if (params->output_buffer_path) {
            free(params->output_buffer_path);
        }

        free(params);        
    }

    return NULL;
}

static void print_help(void)
{
    DEBUG_INFO("Help: ");
    DEBUG_INFO("crypt [-h] -k <key> | -f <key_file> [-o <output_file>] [<input_file>]");
    DEBUG_INFO("-h\t\t\t\tPrint this help");
    DEBUG_INFO("-k <key>\t\t\tSupply a key via command line. -k and -f are mutually exclusive");
    DEBUG_INFO("-f <key_path>\t\tSupply a key file via standard path");
    DEBUG_INFO("-o <out_path>\t\tEncryption output sent to a file rather than stdout");
    DEBUG_INFO("[<input_file>]\t\tOptional parameter that specifies the input buffer as a file, otherwise stdin will be used\n");

    DEBUG_INFO("Exiting cleanly.\n");
}


static void free_cli_params(struct crypt_params *p)
{
    if (!p) {
        return;
    }

    if (p->key) {
        memset(p->key, 0x00, p->key_size);
        free(p->key);
    }

    if (p->input_buffer) {
        memset(p->input_buffer, 0x00, p->input_buffer_size);
        free(p->input_buffer);
    }

    if (p->output_buffer_path) {
        free(p->output_buffer_path);
    }

    free(p);
}

//EOF