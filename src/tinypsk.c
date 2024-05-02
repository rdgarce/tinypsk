#include "tinypsk.h"
#include "tp_defines.h"
#include "alert.h"
#include "record.h"

#define HANDSHAKE_MEM_SIZE 256
static char handshake_mem[HANDSHAKE_MEM_SIZE];
#define APPLICATION_MEM_SIZE 512
static char application_mem[APPLICATION_MEM_SIZE];

int tp_initC(tp_sock_t *s, uint16_t psk_identity, void *tl_structure,
             int (*tl_send)(void *, const void *, size_t),
             int (*tl_recv)(void *, void *, size_t),
             int (*get_ms)(uint16_t, Random_t *, uint8_t *)) {
    
    if (!s || !tl_structure || !tl_send || !tl_recv || !get_ms)
        return TP_FATAL;
    
    s->sock_state = SOCK_MD_CLIENT;
    s->tl_structure = tl_structure;
    s->tl_send = tl_send;
    s->tl_recv = tl_recv;
    
    s->curr_read = conn_state_t_INIT;
    s->curr_write = conn_state_t_INIT;

    s->pend_read = conn_state_t_INIT;
    s->pend_write = conn_state_t_INIT;

    handshake_init(&s->h, get_ms,psk_identity, handshake_mem, HANDSHAKE_MEM_SIZE);
    application_init(&s->a, application_mem, APPLICATION_MEM_SIZE);

    return 0;
}

int tp_initS(tp_sock_t *s, void *tl_structure,
             int (*tl_send)(void *, const void *, size_t),
             int (*tl_recv)(void *, void *, size_t),
             int (*get_ms)(uint16_t, Random_t *, uint8_t *)) {
    
    if (!s || !tl_structure || !tl_send || !tl_recv || !get_ms)
        return TP_FATAL;
    
    s->sock_state = SOCK_MD_SERVER;
    s->tl_structure = tl_structure;
    s->tl_send = tl_send;
    s->tl_recv = tl_recv;

    s->curr_read = conn_state_t_INIT;
    s->curr_write = conn_state_t_INIT;

    s->pend_read = conn_state_t_INIT;
    s->pend_write = conn_state_t_INIT;
    
    handshake_init(&s->h,get_ms, 0, handshake_mem, HANDSHAKE_MEM_SIZE);
    application_init(&s->a, application_mem, APPLICATION_MEM_SIZE);

    return 0;
}

int tp_handshake(tp_sock_t *s) {
    
    switch (s->sock_state & SOCK_MD_MASK) {
    case SOCK_MD_CLIENT: return handshake_do_C(s);
    case SOCK_MD_SERVER: return handshake_do_S(s);
    default: return TP_FATAL;
    }
}

int tp_send(tp_sock_t *s, const void *buff, size_t len) {

    return application_send(s, buff, len);
}

int tp_rcv(tp_sock_t *s, void *buff, size_t len) {

    int res = 0;
    while ( !(s->sock_state & SOCK_APPL_RD) &&
            !(s->sock_state & SOCK_CLOSED) &&
            res == 0)
        res = record_recv_one(s);
    
    if (s->sock_state & SOCK_APPL_RD && res == 0)
        return application_receiveN(s, buff, len);
    else return res;
}

int tp_close(tp_sock_t *s) {

    Alert_t alert = {
        .level = AlertLevel_fatal,
        .description = AlertDescription_close_notify
    };
    int res;
    res = alert_send(s, alert);
    if (res < 0)
        return res;
    
    while (!(s->sock_state & SOCK_CLOSED))
        res = record_recv_one(s);
    
    return res;
}