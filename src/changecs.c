#include "changecs.h"
#include "tp_defines.h"
#include "record.h"
#include "alert.h"

int changecs_send(tp_sock_t *s) {

    ChangeCipherSpec_t message = change_cipher_spec;
    TLSPlaintext_t record = {
        .header.type = ContentType_change_cipher_spec,
        .header.version = ProtocolVersion_TLS_1_2,
        .header.length = sizeof(ChangeCipherSpec_t),
        .fragment = &message
    };

    return record_send_plain(s, &record);
}

int changecs_handle(tp_sock_t *s, ChangeCipherSpec_t message) {
    
    switch (message) {
    case change_cipher_spec:
        s->curr_read = s->pend_read;
        s->pend_read = conn_state_t_INIT;
        return 0;
    
    default:
    {
        Alert_t decode_alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_decode_error
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, decode_alert);
        return TP_RCV_DECODE_ERROR;
    }
    }

    return TP_FATAL; /* We should never get here */
}