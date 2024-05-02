#ifndef APPLICATION_H_
#define APPLICATION_H_

#include "cbuf.h"

typedef struct app_layer_ app_layer;
struct app_layer_ {
    cbuf_t allocator;
};

#include "tinypsk.h"
#include "stddef.h"

void application_init(app_layer *a, void *buffer, size_t buf_size);
void application_cbuf_alloc(app_layer *a, size_t size, void **zones, size_t *zone_sizes);
size_t application_receiveN(tp_sock_t *s, void *out, size_t N);
int application_send(tp_sock_t *s, const void *data, size_t size);
int application_handle(tp_sock_t *s, const void **zones, const size_t *zone_sizes);

#endif