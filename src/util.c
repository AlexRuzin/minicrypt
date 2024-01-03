#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

void debug(bool is_error, const char *format, ...) 
{
    fflush(stdout);

    va_list args;
    va_start(args, format);

    if (is_error) {
        printf("[crypt!]: ");
    } else {
        printf("[crypt+]: ");
    }

    vprintf(format, args);

    printf("\n");

    va_end(args);
}

// todo: use _stat on Win32
bool is_path_valid(const char *p)
{
    if (!p || p[0] == '\0' || p[0] == '-' || strnlen(p, MAX_FILE_PATH) >= MAX_FILE_PATH) {
        return false;
    }

    struct stat stat_buf = { 0 };

    if (stat(p, &stat_buf) != 0) {
        return false;
    }

    return true;
}

uint32_t read_file_into_memory(const char *path, uint8_t **out)
{
    if (!path || !out) {
        return 0;
    }

    *out = NULL;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        DEBUG_ERR("read_file: Failed to open file: %s", path);
        return 0;
    }

    // File size
    fseek(fp, 0, SEEK_END);
    uint32_t file_size = ftell(fp);
    rewind(fp);

    if (file_size >= MAX_FILE_BUF_SIZE) {
        DEBUG_ERR("read_file: File exceeds max size: %d", file_size);
        fclose(fp);
        return 0;
    }

    uint8_t *buf = (uint8_t *)malloc(file_size * sizeof(uint8_t));
    if (!buf) {
        DEBUG_ERR("read_file: Failed to allocate memory (size: %d)", file_size);
        fclose(fp);
        return 0;
    }

    const size_t res = fread(buf, 1, file_size, fp);
    if (res != file_size) {
        DEBUG_ERR("read_file: Failed to read file: %s (%d)", path, res);
        free(buf);
        fclose(fp);
        return 0;
    }

    DEBUG_INFO("read_file: Successfully read file %s size: %d", path, res);

    fclose(fp);
    *out = buf;
    return file_size;
}

// Custom implementation of strnlen, but it is POSIX-compliant
uint32_t strnlen(const char *s, uint32_t n) 
{
    if (!s) {
        return 0;
    }

    uint32_t i = 0;

    for (; i < n && s[i] != '\0'; i++) {
        continue;
    }

    return i;
}

const char *get_stdin_user(uint16_t *out_size, uint32_t max_size)
{
    fflush(stdin);

    *out_size = 0;

    char *buf = (char *)calloc(max_size, sizeof(uint8_t));
    if (!buf) {
        return NULL;
    }

    char c = '\0';
    char *buf_ptr = buf;

    for (;;) {
        c = getc(stdin);

        if (c == EOF || c == '\n') {
            *buf_ptr = '\0';
            *out_size = buf_ptr - buf;
            return buf;
        } else {
            *buf_ptr = c;
        }

        if ((buf_ptr - buf) >= max_size) {
            DEBUG_ERR("get_stdin_user: max buffersize reached");
            free(buf);
            fflush(stdin);
            return NULL;
        }
    }
}

uint32_t write_to_file(const char *filename, const void *buf, uint32_t buf_size)
{
    if (!filename || !buf || buf_size == 0) {
        return 0;
    }

    FILE *fp = fopen(filename, "ab");
    if (fp == NULL) {
        return 0;
    }

    const uint32_t bytes_written = fwrite(buf, 1, buf_size, fp);
    
    fclose(fp);
    return bytes_written;
}

uint32_t read_from_stdin(uint8_t *buf, uint32_t buf_max_size)
{
    if (!buf || !buf_max_size) {
        return 0;
    }

    uint32_t total_read = 0;
    int8_t ch;

    while (total_read < buf_max_size) {
        ch = fgetc(stdin);
        if (ch == EOF || feof(stdin)) {
            DEBUG_INFO("read_from_stdin: Received EOF");
            break;
        }

        if (ferror(stdin)) {
            DEBUG_ERR("I/O error reading from stdin");
            break;
        }

        buf[total_read] = ch;
        total_read++;
    }

    return total_read;
}
