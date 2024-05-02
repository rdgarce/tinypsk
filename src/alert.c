#include "alert.h"
#include "tp_defines.h"
#include "record.h"

int alert_send(tp_sock_t *s, Alert_t message) {

    TLSPlaintext_t record = {
        .header.type = ContentType_alert,
        .header.version = ProtocolVersion_TLS_1_2,
        .header.length = sizeof(Alert_t),
        .fragment = &message
    };
    return record_send_plain(s, &record);
}

int alert_handle(tp_sock_t *s, Alert_t message) {

    if (message.description == AlertDescription_close_notify) {
        s->sock_state = SOCK_CLOSED;
        alert_send(s, message); /* Echo of the close_notify */
        return TP_CLOSED;
    }

    switch (message.level) {
    case AlertLevel_fatal:
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    case AlertLevel_warning:
        break; /* No support at the moment. Do nothing */
    
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

    return 0;
}