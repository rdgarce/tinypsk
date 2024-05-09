#include "record.h"
#include "host.h"
#include "tp_defines.h"
#include "tp_sha256.h"
#include "alert.h"
#include "handshake.h"
#include "changecs.h"
#include "application.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* --------------------------------- helper functions -------------------------------- */

static int set_mac(const uint8_t *write_MAC_key, uint64_t seq_num, ContentType_t type,
                    ProtocolVersion_t version, uint16_t length, const void **zones,
                                            const size_t *zone_sizes , uint8_t * mac) {
    
    uint64_t BE_seq_num = host_htobe64(seq_num);
    uint16_t BE_length = host_htobe16(length);

    const uint8_t *addr[] = {   
                                (uint8_t *)&BE_seq_num,
                                &type,
                                (uint8_t *)&version,
                                (uint8_t *)&BE_length,
                                (uint8_t *)zones[0],
                                (uint8_t *)zones[1]
                            };
    const size_t len[] = {      
                                sizeof(BE_seq_num),
                                sizeof(type),
                                sizeof(version),
                                sizeof(BE_length),
                                zone_sizes[0],
                                zone_sizes[1]
                            };

    size_t num_elem = zones[1] ? 6 : 5;

    return hmac_sha256_vector(write_MAC_key, 32, num_elem, addr, len, mac) == 0 ?
        0 : TP_FATAL;
}
/* ----------------------------------------------------------------------------------- */

/* -------------------------------- cipher functions --------------------------------- */

static inline uint16_t cipher_null_sha_len(uint16_t plain_m_len) {
    
    return plain_m_len + 32;
}

static inline uint16_t decipher_null_sha_len(uint16_t ciphered_m_len) {

    return ciphered_m_len - 32;
}

static int cipher_null_sha(const tp_sock_t *s, const void **zones,
                                const size_t *zone_sizes, uint8_t *out_MAC,
                                const TLS_Plain_H_t *plain_h) {
    // Setted to 0 or TP_FATAL
    int setMACres = 0;

    switch (s->sock_state & SOCK_MD_MASK) {
    
    case SOCK_MD_CLIENT:
        setMACres = set_mac(s->C_S_write_MAC_key[0], s->curr_write.seq_num,
                                   plain_h->type, plain_h->version,
                                   plain_h->length, zones, zone_sizes, out_MAC);
        break;
    
    case SOCK_MD_SERVER:
        setMACres = set_mac(s->C_S_write_MAC_key[1], s->curr_write.seq_num,
                                   plain_h->type, plain_h->version,
                                   plain_h->length, zones, zone_sizes, out_MAC);
        break;

    default: return TP_FATAL; /* If a bit is neither 0 or 1 the world is ending */
    }

    return setMACres;
}

static int decipher_null_sha(const tp_sock_t *s, const void **zones,
                                const size_t *zone_sizes, const uint8_t *check_MAC,
                                const TLS_Plain_H_t *plain_h) {
    // Setted to 0 or TP_FATAL
    int setMACres = 0;
    uint8_t local_MAC[32];

    switch (s->sock_state & SOCK_MD_MASK) {
    
    case SOCK_MD_CLIENT:
        setMACres = set_mac(s->C_S_write_MAC_key[1], s->curr_read.seq_num,
                            plain_h->type, plain_h->version, plain_h->length,
                            zones, zone_sizes, local_MAC);
        break;
    
    case SOCK_MD_SERVER:
        setMACres = set_mac(s->C_S_write_MAC_key[0], s->curr_read.seq_num,
                            plain_h->type, plain_h->version, plain_h->length,
                            zones, zone_sizes, local_MAC);
        break;

    default: return TP_FATAL; /* If a bit is neither 0 or 1 the world is ending */
    }

    if (host_memcmp(local_MAC, check_MAC, 32))
        return TP_RCV_BAD_RECORD_MAC;

    return setMACres;
}
/* ----------------------------------------------------------------------------------- */

/* -------------------------------- send/recv function ------------------------------- */

static int send_bytes(const tp_sock_t *s, const void *buf, size_t len) {

    check(s && buf);
    print_debug("*** send_bytes ***\n");
    print_debug("  Sending out this bytes\n");
    print_debug_arr(buf, len);

    size_t sent_bytes = 0;
    int res = 0;
    while (sent_bytes < len) {
        buf = (uint8_t *)buf + res;
        res = s->tl_send(s->tl_structure, buf, len - sent_bytes);
        switch (res) {
        case -1: return TP_FATAL;
        default: sent_bytes += res; break;
        }
    }

    print_debug("All bytes are sent, returning 0\n");
    return 0;
}

static int recv_bytes(const tp_sock_t *s, void *buf, size_t len) {

    check(s && buf);
    print_debug("*** recv_bytes ***\n");
    print_debug("  Starting reception of %ld bytes\n", len);

    size_t recvd_bytes = 0;
    int res = 0;
    while (recvd_bytes < len) {
        buf = (uint8_t *)buf + res;
        res = s->tl_recv(s->tl_structure, buf, len - recvd_bytes);
        switch (res) {
        case -1: return TP_FATAL;
        default: recvd_bytes += res; break;
        }
    }

    print_debug("  These bytes are received\n");
    print_debug_arr(buf, len);
    print_debug("All bytes are received, returning 0\n");
    return 0;
}

static int send_cipher(const tp_sock_t *s, TLSCiphertext_t *ciphered_m) {

    check(s && ciphered_m);
    print_debug("*** send_cipher ***\n");

    uint16_t ciphered_m_len = ciphered_m->header.length;
    ciphered_m->header.length = host_htobe16(ciphered_m_len);
    
    print_debug(
        "  Sending a cipher message:\n"
        "  type: %d\n"
        "  version: %d.%d\n"
        "  length: %d\n",
        ciphered_m->header.type,
        ciphered_m->header.version.major,
        ciphered_m->header.version.minor,
        ciphered_m_len
    );
    
    /* Send the header of TLS Record protocol */
    if (send_bytes(s, &ciphered_m->header, sizeof(TLS_Ciph_H_t)) < 0)
        return TP_FATAL;
    
    uint8_t b1 = s->curr_write.cipher_suite.b1;
    uint8_t b2 = s->curr_write.cipher_suite.b2;
    if (b1 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b1 &&
        b2 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b2) {
        if (send_bytes(s, ciphered_m->fragment.content, ciphered_m_len) < 0)
            return TP_FATAL;
        }
    else if (b1 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b1 &&
             b2 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b2) {
        if (send_bytes(s, ciphered_m->fragment.content,
                decipher_null_sha_len(ciphered_m_len)) < 0)
            return TP_FATAL;
        if (send_bytes(s, ciphered_m->fragment.MAC, 32) < 0)
            return TP_FATAL;
        }
    else
        return TP_FATAL; /* CipherSuite not available */

    return 0;
}

static int recv_cipher_header(const tp_sock_t *s, TLS_Ciph_H_t *ciphered_h) {

    if (recv_bytes(s, ciphered_h, sizeof(TLS_Ciph_H_t)) < 0)
        return TP_FATAL;
    
    ciphered_h->length = host_be16toh(ciphered_h->length);
    
    return 0;
}

static int recv_headers(const tp_sock_t *s, TLS_Plain_H_t *plain_h,
                               TLS_Ciph_H_t *ciphered_h) {

    if (recv_cipher_header(s, ciphered_h) < 0)
        return TP_FATAL;

    if (ciphered_h->length > (1 << 14) + 2048)
    /* Max length is 2^14 + 2048 */
        return TP_RCV_RECORD_OVERFLOW;

    plain_h->type = ciphered_h->type;
    plain_h->version = ciphered_h->version;

    uint8_t b1 = s->curr_read.cipher_suite.b1;
    uint8_t b2 = s->curr_read.cipher_suite.b2;
    if (b1 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b1 &&
        b2 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b2)
        plain_h->length = ciphered_h->length;
    else if (b1 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b1 &&
             b2 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b2)
        plain_h->length = decipher_null_sha_len(ciphered_h->length);
    else
        return TP_FATAL; /* CipherSuite not available */

    return 0;
}

static int recv_fragment_vector(tp_sock_t *s, void **zones, size_t *zone_sizes,
                                            const TLS_Plain_H_t *plain_h,
                                            const TLS_Ciph_H_t *ciphered_h) {
    /*
    *  First plain_h->length bytes are the fragment itself (no compression).
    *  Here we assume that zones is an array of two pointers to two memory
    *  areas with a cumulative size of PRECISELY plain_h->length.
    *  zone_sizes[i] is the size of area pointed by zones[i], i = 1,2
    */
    check(plain_h->length == zone_sizes[0] + zone_sizes[1]);

    size_t remaining_length = plain_h->length;
    size_t first_recv_num = MIN(zone_sizes[0], remaining_length);
    
    if (!zones[0] || recv_bytes(s, zones[0], first_recv_num) < 0)
        return TP_FATAL;

    remaining_length = remaining_length - first_recv_num;
    
    if (remaining_length > 0 &&
        (!zones[1] || recv_bytes(s, zones[1], remaining_length) < 0))
        return TP_FATAL;

    int res;
    uint8_t b1 = s->curr_read.cipher_suite.b1;
    uint8_t b2 = s->curr_read.cipher_suite.b2;
    if (b1 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b1 &&
        b2 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b2)
    {
        res = 0; /* Nothing to do */
    }
    else if (b1 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b1 &&
             b2 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b2)
    {
        /* 32 bytes for the MAC have to be received and checked */
        uint8_t MAC[32];
        if (recv_bytes(s, MAC, 32) < 0)
            return TP_FATAL;
        res = decipher_null_sha(s, (const void **)zones, zone_sizes, MAC, plain_h);
    }
    else
        return TP_FATAL;  /* CipherSuite not available */
    
    if (res < 0)
    /* TP_FATAL or TP_RCV_BAD_RECORD_MAC */
        return res;

    /* Increment the curr_read.seq_num */
    s->curr_read.seq_num++;

    return 0;
}

static int recv_fragment(tp_sock_t *s, void *fragment, const TLS_Plain_H_t *plain_h,
                                            const TLS_Ciph_H_t *ciphered_h) {
    
    void *zones[] = {fragment, NULL};
    size_t zone_sizes[] = {plain_h->length, 0};

    return recv_fragment_vector(s, zones, zone_sizes, plain_h, ciphered_h);
}
/* ----------------------------------------------------------------------------------- */

/* ---------------------------- upper protocols handlers ----------------------------- */

static int handle_alert(tp_sock_t *s, const TLS_Plain_H_t *plain_h,
                                    const TLS_Ciph_H_t *ciphered_h) {

    Alert_t alert;
    int res;
    if (plain_h->length != sizeof(Alert_t)) {
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_decode_error;
        alert_send(s, alert);
        return TP_RCV_DECODE_ERROR;
    }
    else if (plain_h->version.major != ProtocolVersion_TLS_1_2.major ||
             plain_h->version.minor != ProtocolVersion_TLS_1_2.minor) {
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_unexpected_message;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    else {
        res = recv_fragment(s, &alert, plain_h, ciphered_h);
        switch (res) {
        case TP_FATAL:
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        
        case TP_RCV_BAD_RECORD_MAC:
            s->sock_state = SOCK_CLOSED;
            alert.level = AlertLevel_fatal;
            alert.description = AlertDescription_bad_record_mac;
            alert_send(s, alert);
            return TP_RCV_BAD_RECORD_MAC;
        default:
            break;
        }
    }
    
    return alert_handle(s, alert);
}

static int handle_changecs(tp_sock_t *s, const TLS_Plain_H_t *plain_h,
                                    const TLS_Ciph_H_t *ciphered_h) {

    Alert_t alert;
    ChangeCipherSpec_t changecs;
    int res;
    
    if (plain_h->length != sizeof(ChangeCipherSpec_t)) {
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_decode_error;
        alert_send(s, alert);
        return TP_RCV_DECODE_ERROR;
    }
    else if (plain_h->version.major != ProtocolVersion_TLS_1_2.major ||
             plain_h->version.minor != ProtocolVersion_TLS_1_2.minor) {
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_unexpected_message;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    else {
        res = recv_fragment(s, &changecs, plain_h, ciphered_h);
        switch (res) {
        case TP_FATAL:
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        
        case TP_RCV_BAD_RECORD_MAC:
            s->sock_state = SOCK_CLOSED;
            alert.level = AlertLevel_fatal;
            alert.description = AlertDescription_bad_record_mac;
            alert_send(s, alert);
            return TP_RCV_BAD_RECORD_MAC;
        default:
            break;
        }
    }
    
    return changecs_handle(s, changecs);
}

static int handle_application_data(tp_sock_t *s, const TLS_Plain_H_t *plain_h,
                                    const TLS_Ciph_H_t *ciphered_h) {
    
    Alert_t alert;
    if (plain_h->version.major != ProtocolVersion_TLS_1_2.major ||
        plain_h->version.minor != ProtocolVersion_TLS_1_2.minor) {
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_unexpected_message;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }

    int res;
    void *zones[2];
    size_t zone_sizes[2];
    application_cbuf_alloc(&s->a, plain_h->length, zones, zone_sizes);
    
    res = recv_fragment_vector(s, zones, zone_sizes, plain_h, ciphered_h);
    
    switch (res) {
    case TP_FATAL:
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    
    case TP_RCV_BAD_RECORD_MAC:
        s->sock_state = SOCK_CLOSED;
        alert.level = AlertLevel_fatal;
        alert.description = AlertDescription_bad_record_mac;
        alert_send(s, alert);
        return TP_RCV_BAD_RECORD_MAC;
    default:
        break;
    }

    return application_handle(s, (const void **)zones, zone_sizes);
}

static int handle_handshake(tp_sock_t *s, const TLS_Plain_H_t *plain_h,
                                    const TLS_Ciph_H_t *ciphered_h) {
    /* Need to handle reception of multiple record that compose the same
       handshake message */
    void *handshake_first_m = handshake_lin_alloc(&s->h, plain_h->length);
    if (!handshake_first_m) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    int res;
    res = recv_fragment(s, handshake_first_m, plain_h, ciphered_h);
    switch (res) {
        case TP_FATAL:
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        
        case TP_RCV_BAD_RECORD_MAC:
        {
            Alert_t alert;
            s->sock_state = SOCK_CLOSED;
            alert.level = AlertLevel_fatal;
            alert.description = AlertDescription_bad_record_mac;
            alert_send(s, alert);
            return TP_RCV_BAD_RECORD_MAC;
        }

        default:
            break;
    }

    Handshake_H_p_t handshake_first_h = handshake_parse_header(handshake_first_m);
    ProtocolVersion_t record_prtcv = plain_h->version;
    /* 4 bytes is the size of the Handshake header */
    uint32_t handshake_len = handshake_first_h.length + 4;
    /* floor division since we already received one record layer message.
       Must be zero if handshake message is all contained in one record layer one. */
    size_t num_iters_floor = handshake_len / (1 << 14);

    for (size_t i = 0; i < num_iters_floor; i++) {
        TLS_Plain_H_t plain_h;
        TLS_Ciph_H_t ciphered_h;

        res = recv_headers(s, &plain_h, &ciphered_h);
        switch (res) {
        case TP_FATAL:
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        
        case TP_RCV_RECORD_OVERFLOW:
        {
            s->sock_state = SOCK_CLOSED;
            Alert_t rec_ovrfl = {
                .level = AlertLevel_fatal,
                .description = AlertDescription_record_overflow,
            };
            alert_send(s, rec_ovrfl);
            return TP_RCV_RECORD_OVERFLOW;
        }
        default:
            break;
        }

        /* The allocator used by the handshake protocol is linear so
           subsequent allocation receive contiguous regions (LIN_ALIGNMENT_POW = 0) */
        void *handshake_other_m = handshake_lin_alloc(&s->h, plain_h.length);
        if (!handshake_other_m) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }

        res = recv_fragment(s, handshake_other_m, &plain_h, &ciphered_h);
        switch (res) {
            case TP_FATAL:
                s->sock_state = SOCK_CLOSED;
                return TP_FATAL;
            
            case TP_RCV_BAD_RECORD_MAC:
            {
                Alert_t alert;
                s->sock_state = SOCK_CLOSED;
                alert.level = AlertLevel_fatal;
                alert.description = AlertDescription_bad_record_mac;
                alert_send(s, alert);
                return TP_RCV_BAD_RECORD_MAC;
            }

            default:
                break;
        }
    }

    return handshake_handle(s, handshake_first_m, handshake_len, record_prtcv);
}
/* ----------------------------------------------------------------------------------- */

/* ---------------------------------- API functions ---------------------------------- */

int record_send_plain(tp_sock_t *s, const TLSPlaintext_t *plain_m) {

    check(s && plain_m);
    print_debug("*** record_send_plain ***\n");

    if (plain_m->header.length > (1 << 14)) {
    /* Max length is 2^14 */
        print_debug("  returning TP_NOT_ALLOWED\n");
        return TP_NOT_ALLOWED;
    }

    print_debug(
        "  type: %d\n"
        "  version: %d.%d\n"
        "  length: %d\n",
        plain_m->header.type,
        plain_m->header.version.major,
        plain_m->header.version.minor,
        plain_m->header.length
    );
    print_debug("fragment: ");
    print_debug_arr(plain_m->fragment, plain_m->header.length);

    TLSCiphertext_t ciphered_m = {
        .header.type = plain_m->header.type,
        .header.version = plain_m->header.version,
        .fragment.content = plain_m->fragment
    };

    void *zones[2] = {plain_m->fragment, NULL};
    size_t zone_sizes[2] = {plain_m->header.length, 0};

    int res;
    uint8_t b1 = s->curr_write.cipher_suite.b1;
    uint8_t b2 = s->curr_write.cipher_suite.b2;
    if (b1 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b1 &&
        b2 == CipherSuite_TLS_NULL_WITH_NULL_NULL.b2) {
            ciphered_m.header.length = plain_m->header.length;
            res = 0;
        }
    else if (b1 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b1 &&
             b2 == CipherSuite_TLS_PSK_WITH_NULL_SHA.b2) {
            ciphered_m.header.length =
                cipher_null_sha_len(plain_m->header.length);
            res = cipher_null_sha(s, (const void **)zones, zone_sizes,
                                ciphered_m.fragment.MAC, &plain_m->header);
        }
    else
        return TP_FATAL; /* CipherSuite not available */

    if (res < 0)
    /* Unrecognized cipher method or hmac_sha256 error */
        return res;

    if (ciphered_m.header.length > (1 << 14) + 2048) {
    /* Max length is 2^14 + 2048 */
        return TP_NOT_ALLOWED;
    }


    if (send_cipher(s, &ciphered_m) < 0)
        return TP_FATAL;

    /* Increment the curr_write.seq_num */
    s->curr_write.seq_num++;

    return 0;
}

int record_recv_one(tp_sock_t *s) {

    TLS_Plain_H_t plain_h;
    TLS_Ciph_H_t ciphered_h;
    int res;

    res = recv_headers(s, &plain_h, &ciphered_h);
    
    switch (res) {
    case TP_FATAL:
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    
    case TP_RCV_RECORD_OVERFLOW:
    {
        s->sock_state = SOCK_CLOSED;
        Alert_t rec_ovrfl = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_record_overflow,
        };
        alert_send(s, rec_ovrfl);
        return TP_RCV_RECORD_OVERFLOW;
    }
    default:
        break;
    }

    switch (plain_h.type) {
    case ContentType_alert:
        return handle_alert(s, &plain_h, &ciphered_h);
    case ContentType_application_data:
        return handle_application_data(s, &plain_h, &ciphered_h);
    case ContentType_change_cipher_spec:
        return handle_changecs(s, &plain_h, &ciphered_h);
    case ContentType_handshake:
        return handle_handshake(s, &plain_h, &ciphered_h);

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
/* ----------------------------------------------------------------------------------- */
