#include <stdlib.h>
#include <string.h>

#include "buf.h"

void sshe_buf_init(sshe_buf *b)
{
    b->data = NULL;
    b->len = b->cap = b->pos = 0;
}

void sshe_buf_free(sshe_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = b->pos = 0;
}

int sshe_buf_reserve(sshe_buf *b, size_t need)
{
    size_t ncap;
    unsigned char *nd;
    if (b->len + need <= b->cap) return 0;
    ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + need) ncap <<= 1;
    nd = (unsigned char *)realloc(b->data, ncap);
    if (!nd) return -1;
    b->data = nd;
    b->cap = ncap;
    return 0;
}

int sshe_buf_raw(sshe_buf *b, const void *p, size_t n)
{
    if (sshe_buf_reserve(b, n) != 0) return -1;
    if (n) memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int sshe_buf_u8(sshe_buf *b, uint8_t v)
{
    return sshe_buf_raw(b, &v, 1);
}

int sshe_buf_u32(sshe_buf *b, uint32_t v)
{
    unsigned char x[4];
    x[0] = (unsigned char)(v >> 24);
    x[1] = (unsigned char)(v >> 16);
    x[2] = (unsigned char)(v >> 8);
    x[3] = (unsigned char)v;
    return sshe_buf_raw(b, x, 4);
}

int sshe_buf_str(sshe_buf *b, const void *p, size_t n)
{
    if (sshe_buf_u32(b, (uint32_t)n) != 0) return -1;
    return sshe_buf_raw(b, p, n);
}

int sshe_buf_get_u8(sshe_buf *b, uint8_t *v)
{
    if (b->pos + 1 > b->len) return -1;
    *v = b->data[b->pos++];
    return 0;
}

int sshe_buf_get_u32(sshe_buf *b, uint32_t *v)
{
    if (b->pos + 4 > b->len) return -1;
    *v = ((uint32_t)b->data[b->pos] << 24) |
         ((uint32_t)b->data[b->pos + 1] << 16) |
         ((uint32_t)b->data[b->pos + 2] << 8) |
         ((uint32_t)b->data[b->pos + 3]);
    b->pos += 4;
    return 0;
}

int sshe_buf_get_len(sshe_buf *b, size_t *n)
{
    uint32_t v;
    if (sshe_buf_get_u32(b, &v) != 0) return -1;
    *n = v;
    return 0;
}

int sshe_buf_get_str(sshe_buf *b, const unsigned char **p, size_t *n)
{
    if (sshe_buf_get_len(b, n) != 0) return -1;
    if (b->pos + *n > b->len) return -1;
    *p = b->data + b->pos;
    b->pos += *n;
    return 0;
}

int sshe_buf_name_list_has(sshe_buf *b, const char *want)
{
    unsigned char *nl;
    size_t nl_len;
    size_t i, wl = strlen(want);
    if (sshe_buf_get_len(b, &nl_len) != 0) return 0;
    nl = b->data + b->pos;
    if (b->pos + nl_len > b->len) return 0;
    /* parse comma-separated list; we take the FIRST candidate that
     * matches OUR preference — caller passes want = our preferred alg */
    i = 0;
    while (i < nl_len) {
        size_t j = i;
        while (j < nl_len && nl[j] != ',') j++;
        if (j - i == wl && memcmp(nl + i, want, wl) == 0) return 1;
        i = j + 1;
    }
    return 0;
}