#ifndef CBUF_H_
#define CBUF_H_

#include "stddef.h"

/* A circular buffer allocator. */

typedef struct cbuf_t_ cbuf_t;
struct cbuf_t_ {
    size_t head;
    size_t tail;
    size_t nelem;
    size_t buf_size;
    void *buffer;
};

void cbuf_init(cbuf_t *c, void *buffer, size_t buf_size);
void cbuf_alloc(cbuf_t *c, size_t size,void **zones, size_t *zone_sizes);
size_t cbuf_popN(cbuf_t *c, void *out, size_t N);

#endif