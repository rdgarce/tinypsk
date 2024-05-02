#include "cbuf.h"
#include "host.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void cbuf_init(cbuf_t *c, void *buffer, size_t buf_size) {
    
    c->head = 0;
    c->tail = 0;
    c->nelem = 0;
    c->buffer = buffer;
    c->buf_size = buf_size;
}

void cbuf_alloc(cbuf_t *c, size_t size, void **zones, size_t *zone_sizes) {

    zones[0] = zones[1] = NULL;
    zone_sizes[0] = zone_sizes[1] = 0;
    
    if (c->nelem + size > c->buf_size)
        return;

    size_t tail_end_size = c->buf_size - c->tail;
    zones[0] = (unsigned char *)c->buffer + c->tail;

    if (size > tail_end_size) {
        zone_sizes[0] = tail_end_size;
        zones[1] = c->buffer;
        zone_sizes[1] = size - tail_end_size;
    }
    else zone_sizes[0] = size;

    c->nelem += size;
    c->tail = (c->tail + size) % c->buf_size;
}

size_t cbuf_popN(cbuf_t *c, void *out, size_t N) {

    size_t pops = MIN(c->nelem, N);
    size_t head_end_size = c->buf_size - c->head;

    if (pops <= head_end_size) {
        host_memcpy(out, (unsigned char *)c->buffer + c->head, pops);
    }
    else {
        host_memcpy(out, (unsigned char *)c->buffer + c->head, head_end_size);
        host_memcpy((unsigned char *)out + head_end_size, c->buffer, pops - head_end_size);
    }
    
    c->nelem -= pops;
    c->head = (c->head + pops) % c->buf_size;

    return pops;
}