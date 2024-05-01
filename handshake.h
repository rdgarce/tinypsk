/* ------------------------------ [handshake_] functions ----------------------------- */
/*
*  These structures and functions handles the TLS handshake protocol for the client
*  and server mode.
*/
#ifndef HANDSHAKE_H_
#define HANDSHAKE_H_

#include "tinypsk.h"
#include "lin.h"
#include "sha256_prim.h"
#include "tp_types.h"

typedef struct Handshake_H_p_t_ Handshake_H_p_t;
struct Handshake_H_p_t_ {
    HandshakeType_t msg_type;
    uint32_t length;
};

typedef struct hds_layer_ hds_layer;
struct hds_layer_ {
    int16_t psk_identity;
    uint8_t master_secret[48];
    Random_t S_C_randoms[2];
    struct sha256_state hash;
    lin alloc;
    int (*get_ms)(uint16_t, Random_t *, uint8_t *);
};

void handshake_init(hds_layer *h, void *buffer, size_t buf_size);
void *handshake_lin_alloc(hds_layer *h, size_t size);
Handshake_H_p_t handshake_parse_header(const void *header);
int handshake_do_C(tp_sock_t *s);
int handshake_do_S(tp_sock_t *s);
int handshake_handle(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv);

#endif