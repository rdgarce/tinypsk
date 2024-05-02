#include "application.h"
#include "record.h"
#include "tp_defines.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void application_init(app_layer *a, void *buffer, size_t buf_size) {

    cbuf_init(&a->allocator, buffer, buf_size);
}

void application_cbuf_alloc(app_layer *a, size_t size, void **zones,
                                                size_t *zone_sizes) {

    cbuf_alloc(&a->allocator, size, zones, zone_sizes);
}

size_t application_receiveN(tp_sock_t *s, void *out, size_t N) {

    size_t pops = cbuf_popN(&s->a.allocator, out, N);
    if (s->a.allocator.nelem == 0)
        s->sock_state = s->sock_state & ~SOCK_APPL_RD;

    return pops;
}

int application_send(tp_sock_t *s, const void *data, size_t size) {

    if (!(s->sock_state & SOCK_HS_DONE))
    /* Not allowed to send application data until handshake is done */
        return TP_NOT_ALLOWED;
    
    int res;
    uint16_t bytes_to_send;
    uint8_t *data_ptr = (uint8_t *)data;
    size_t num_iters_ceil = (size + (1 << 14) - 1) / (1 << 14);

    TLSPlaintext_t record = {
        .header.type = ContentType_application_data,
        .header.version = ProtocolVersion_TLS_1_2,
    };

    for (size_t i = 0; i < num_iters_ceil; i++) {
        bytes_to_send = MIN(size, (1 << 14));
        record.header.length = bytes_to_send;
        record.fragment = data_ptr;
        res = record_send_plain(s, &record);
        if (res < 0)
            return res;
        size -= bytes_to_send;
        data_ptr += bytes_to_send;
    }

    return 0;
}

int application_handle(tp_sock_t *s, const void **zones, const size_t *zone_sizes) {

    s->sock_state = s->sock_state | SOCK_APPL_RD;
    
    return 0;
}