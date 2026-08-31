/*
 * buf.h — growable byte buffer + SSH wire primitives (RFC 4251 §5)
 */
#ifndef SSH_BUF_H
#define SSH_BUF_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    size_t pos;   /* read cursor */
} sshe_buf;

void  sshe_buf_init(sshe_buf *b);
void  sshe_buf_free(sshe_buf *b);
int   sshe_buf_reserve(sshe_buf *b, size_t need);

/* append: raw bytes / u8 / u32 / string(BOM) / name-list */
int   sshe_buf_raw(sshe_buf *b, const void *p, size_t n);
int   sshe_buf_u8(sshe_buf *b, uint8_t v);
int   sshe_buf_u32(sshe_buf *b, uint32_t v);
int   sshe_buf_str(sshe_buf *b, const void *p, size_t n);

/* read: returns 0 ok, -1 if exhausted/truncated */
int   sshe_buf_get_u8(sshe_buf *b, uint8_t *v);
int   sshe_buf_get_u32(sshe_buf *b, uint32_t *v);
int   sshe_buf_get_len(sshe_buf *b, size_t *n);       /* peek string len only */
int   sshe_buf_get_str(sshe_buf *b, const unsigned char **p, size_t *n);

int   sshe_buf_name_list_has(sshe_buf *b, const char *want); /* consumes */

#endif