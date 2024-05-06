#include "handshake.h"
#include "host.h"
#include "tp_defines.h"
#include "record.h"
#include "alert.h"
#include "changecs.h"
#include "tp_sha256.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define SET_HS_STATE(x, state)  do {                                                             \
                                    (x) = ((x) & SOCK_HS_DONE) | (state) | ((x) & SOCK_MD_MASK); \
                                } while (0)
#define GET_HS_STATE(x) (((x) & SOCK_HS_MASK) >> 1)

/* ---------------- Handshake protocol parsing structures declaration ---------------- */

typedef struct ClientHello_p_t_ ClientHello_p_t;
struct ClientHello_p_t_ {
    ProtocolVersion_t client_version;
    Random_t *random;
    /* 
    *  The implementation has no support for session resumption.
    *  In client and server mode, session_id_len is set always to zero
    *  and *session_id = NULL.
    *  In server mode, session_id_len and session_id is ignored.
    */
    uint8_t session_id_len;
    uint8_t *session_id;
    /*
    *  Only two cipher suites are supported:
    *  - TLS_NULL_WITH_NULL_NULL
    *  - TLS_PSK_WITH_NULL_SHA
    *  
    *  In client mode only these two will be used in the ClientHello message.
    *  In server mode the hanshake will fail if none of the above are presented
    *  by the client.
    */
    uint16_t cipher_suites_len;
    CipherSuite_t *cipher_suites;
    /*
    *  Our implementation has no support for compression (only null compression).
    *  In client mode only 1 compression method proposal will be sent in the
    *  ClientHello message:
    *  - CompressionMethod.null
    *  
    *  In server mode the hanshake will be aborted if CompressionMethod.null is not
    *  presented by the client.
    */
    uint8_t compression_methods_len;
    CompressionMethod_t *compression_methods;
    /* No extension support. Maybe we will need that? */
};

typedef struct ServerHello_p_t_ ServerHello_p_t;
struct ServerHello_p_t_ {
    ProtocolVersion_t server_version;
    Random_t *random;
    uint8_t session_id_len;
    uint8_t *session_id;
    CipherSuite_t cipher_suite;
    CompressionMethod_t compression_method;
    /* No extension support. Maybe we will need that? */
};

typedef struct ClientKeyExchange_p_t_ ClientKeyExchange_p_t;
struct ClientKeyExchange_p_t_{
    uint16_t psk_identity_len;
    uint8_t *psk_identity;
};

typedef struct ServerKeyExchange_p_t_ ServerKeyExchange_p_t;
struct ServerKeyExchange_p_t_{
    uint16_t psk_identity_hint_len;
    uint8_t *psk_identity_hint;
};

typedef struct Finished_p_t_ Finished_p_t;
struct Finished_p_t_{
    uint8_t verify_data[12];
};
/* ----------------------------------------------------------------------------------- */

/* ---------------------------------- send function ---------------------------------- */

static int send_handshake(tp_sock_t *s, const void *handshake_m, uint32_t handshake_len) {

    print_debug("*** send_handshake ***\n");
    print_debug_arr(handshake_m, handshake_len);

    int res;
    uint16_t bytes_to_send;
    uint8_t *handshake_ptr = (uint8_t *)handshake_m;
    size_t num_iters_ceil = (handshake_len + (1 << 14) - 1) / (1 << 14);

    TLSPlaintext_t record = {
        .header.type = ContentType_handshake,
        .header.version = ProtocolVersion_TLS_1_2,
    };

    for (size_t i = 0; i < num_iters_ceil; i++) {
        bytes_to_send = MIN(handshake_len, (1 << 14));
        record.header.length = bytes_to_send;
        record.fragment = handshake_ptr;
        res = record_send_plain(s, &record);
        if (res < 0)
            return res;
        handshake_len -= bytes_to_send;
        handshake_ptr += bytes_to_send;
    }

    return 0;
}
/* ----------------------------------------------------------------------------------- */

/* --------------------------------- helper functions -------------------------------- */

static void free_all(hds_layer *h) {

    lin_freeAll(&h->alloc);
}

static void set_random(Random_t *r) {

    r->BE_gmt_unix_time = host_htobe32((uint32_t)host_time(NULL));
    for (size_t i = 0; i < 28; i++)
        r->random_bytes[i] = (uint8_t)(host_rand() % UINT8_MAX);
}

static inline int set_key_block(const uint8_t *ms, const Random_t *S_C_randoms,
                            uint8_t *key_block, size_t key_block_size) {
    
    if (tls_prf_sha256(ms, 48, "key expansion", (uint8_t *)S_C_randoms, 2*sizeof(Random_t),
                   key_block, key_block_size) < 0)
        return TP_FATAL;
    else
        return 0;
}
/* ----------------------------------------------------------------------------------- */

/* --------------------------------- parsing/writing --------------------------------- */

static void *new_raw_ch(tp_sock_t *s, const ClientHello_p_t *ch, uint32_t *ch_size) {

    print_debug("*** new_raw_ch ***\n");

    uint8_t session_id_len = ch->session_id_len;
    uint16_t cipher_suites_len = ch->cipher_suites_len;
    uint8_t compression_methods_len = ch->compression_methods_len;
    
    if (session_id_len > 32 || compression_methods_len < 1 ||
        cipher_suites_len < 2 || cipher_suites_len > (1 << 16) - 2)
        return NULL;

    uint32_t handshake_h_size = sizeof(HandshakeType_t) +
                                3*sizeof(uint8_t);

    uint32_t client_m_size = sizeof(ProtocolVersion_t)       +
                             sizeof(Random_t)                +
                             sizeof(session_id_len)          +
                             session_id_len                  +
                             sizeof(cipher_suites_len)       +
                             cipher_suites_len               +
                             sizeof(compression_methods_len) +
                             compression_methods_len;

    uint32_t tot_size = handshake_h_size + client_m_size;

    print_debug(
        "  handshake_h_size: %d\n"
        "  client_m_size: %d\n"
        "  tot_size: %d\n",
        handshake_h_size,
        client_m_size,
        tot_size
    );

    uint8_t *h = handshake_lin_alloc(&s->h, tot_size);

    if (!h)
        return NULL;
    
    uint8_t *r = h;
    *ch_size = tot_size;

    *(HandshakeType_t *)h = HandshakeType_client_hello;
    print_debug("Handshake Type: %02X\n", *(HandshakeType_t *)h);
    h = h + sizeof(HandshakeType_t);

    uint32_t BE_client_size = host_htobe32(client_m_size);
    uint8_t *cs_p = (uint8_t *)&BE_client_size;
    host_memcpy(h, cs_p + 1, 3 * sizeof(uint8_t));
    print_debug("Length: ");
    print_debug_arr(h, 3);
    h = h + 3 * sizeof(uint8_t);

    *(ProtocolVersion_t *)h = ch->client_version;
    h = h + sizeof(ProtocolVersion_t);

    host_memcpy(h, ch->random, sizeof(Random_t));
    h = h + sizeof(Random_t);

    *h = session_id_len;
    h = h + sizeof(uint8_t);

    host_memcpy(h, ch->session_id, session_id_len * sizeof(uint8_t));
    h = h + session_id_len * sizeof(uint8_t);

    *(uint16_t *)h = host_htobe16(cipher_suites_len);
    h = h + sizeof(uint16_t);

    host_memcpy(h, ch->cipher_suites, cipher_suites_len * sizeof(CipherSuite_t));
    h = h + cipher_suites_len * sizeof(CipherSuite_t);

    *h = compression_methods_len;
    h = h + sizeof(uint8_t);

    host_memcpy(h, ch->compression_methods, compression_methods_len *
                                            sizeof(CompressionMethod_t));

    return r;
}

static void parse_raw_ch(ClientHello_p_t *ch, const void *raw_ch) {

    uint8_t *r = (uint8_t *)raw_ch;

    /* Skip the Handshake header */
    r = r + sizeof(HandshakeType_t) + 3 * sizeof(uint8_t);

    ch->client_version = *(ProtocolVersion_t *)r;
    r = r + sizeof(ProtocolVersion_t);

    ch->random = (Random_t *)r;
    r = r + sizeof(Random_t);

    ch->session_id_len = *r;
    r = r + sizeof(uint8_t);

    ch->session_id = r;
    r = r + ch->session_id_len * sizeof(uint8_t);

    ch->cipher_suites_len = host_be16toh(*(uint16_t *)r);
    r = r + sizeof(uint16_t);

    ch->cipher_suites = (CipherSuite_t *)r;
    r = r + ch->cipher_suites_len * sizeof(CipherSuite_t);

    ch->compression_methods_len = *r;
    r = r + sizeof(uint8_t);
    ch->compression_methods = (CompressionMethod_t *)r;
}

static void *new_raw_sh(tp_sock_t *s, const ServerHello_p_t *sh, uint32_t *sh_size) {

    uint8_t session_id_len = sh->session_id_len;
    if (session_id_len > 32)
        return NULL;
    
    uint32_t handshake_h_size = sizeof(HandshakeType_t) +
                                3*sizeof(uint8_t);

    uint32_t server_m_size = sizeof(ProtocolVersion_t)       +
                             sizeof(Random_t)                +
                             sizeof(uint8_t)                 +
                             session_id_len                  +
                             sizeof(CipherSuite_t)           +
                             sizeof(CompressionMethod_t);

    uint32_t tot_size = handshake_h_size + server_m_size;
    uint8_t *h = handshake_lin_alloc(&s->h, tot_size);
    if (!h)
        return NULL;
    
    uint8_t *r = h;
    *sh_size = tot_size;

    *(HandshakeType_t *)h = HandshakeType_server_hello;
    h = h + sizeof(HandshakeType_t);

    uint32_t BE_server_size = host_htobe32(server_m_size);
    uint8_t *ss_p = (uint8_t *)&BE_server_size;
    host_memcpy(h, ss_p + 1, 3 * sizeof(uint8_t));
    h = h + 3 * sizeof(uint8_t);

    *(ProtocolVersion_t *)h = sh->server_version;
    h = h + sizeof(ProtocolVersion_t);

    host_memcpy(h, sh->random, sizeof(Random_t));
    h = h + sizeof(Random_t);

    *h = session_id_len; /* Should be zero */
    h = h + sizeof(uint8_t);

    host_memcpy(h, sh->session_id, session_id_len * sizeof(uint8_t));
    h = h + session_id_len * sizeof(uint8_t);

    *(CipherSuite_t *)h = sh->cipher_suite;
    h = h + sizeof(CipherSuite_t);

    *(CompressionMethod_t *)h = sh->compression_method;

    return r;
}

static void parse_raw_sh(ServerHello_p_t *sh, const void *raw_sh) {

    uint8_t *r = (uint8_t *)raw_sh;

    /* Skip the Handshake header */
    r = r + sizeof(HandshakeType_t) + 3 * sizeof(uint8_t);

    sh->server_version = *(ProtocolVersion_t *)r;
    r = r + sizeof(ProtocolVersion_t);

    sh->random = (Random_t *)r;
    r = r + sizeof(Random_t);

    sh->session_id_len = *r;
    r = r + sizeof(uint8_t);

    sh->session_id = r;
    r = r + sh->session_id_len * sizeof(uint8_t);

    sh->cipher_suite = *(CipherSuite_t *)r;
    r = r + sizeof(CipherSuite_t);

    sh->compression_method = *(CompressionMethod_t *)r;
}

static void *new_raw_shd(tp_sock_t *s, uint32_t *shd_size) {

    uint32_t handshake_h_size = sizeof(HandshakeType_t) +
                                3*sizeof(uint8_t);
    
    uint8_t *h = handshake_lin_alloc(&s->h, handshake_h_size);

    if (!h)
        return NULL;

    uint8_t *r = h;
    *shd_size = handshake_h_size;

    *(HandshakeType_t *)h = HandshakeType_server_hello_done;
    h = h + sizeof(HandshakeType_t);

    uint32_t zero = 0;
    uint8_t *zero_p = (uint8_t *)&zero;
    host_memcpy(h, zero_p, 3 * sizeof(uint8_t));

    return r;
}

static void parse_raw_ske(ServerKeyExchange_p_t *ske, const void *raw_ske) {

    uint8_t *r = (uint8_t *)raw_ske;

    /* Skip the Handshake header */
    r = r + sizeof(HandshakeType_t) + 3 * sizeof(uint8_t);
    
    ske->psk_identity_hint_len = host_be16toh(*(uint16_t *)r);
    r = r + sizeof(uint16_t);
    ske->psk_identity_hint = r;
}

static void *new_raw_cke(tp_sock_t *s, const ClientKeyExchange_p_t *cke,
                                                    uint32_t *cke_size) {
    
    uint32_t handshake_h_size = sizeof(HandshakeType_t) + 3*sizeof(uint8_t);
    uint32_t mess_size = sizeof(uint16_t) + cke->psk_identity_len;
    uint32_t tot_size = handshake_h_size + mess_size;

    uint8_t *h = handshake_lin_alloc(&s->h, tot_size);
    if (!h)
        return NULL;
    
    uint8_t *r = h;
    *cke_size = tot_size;

    *(HandshakeType_t *)h = HandshakeType_client_key_exchange;
    h = h + sizeof(HandshakeType_t);

    uint32_t BE_mess_size = host_htobe32(mess_size);
    uint8_t *ms_p = (uint8_t *)&BE_mess_size;
    host_memcpy(h, ms_p + 1, 3 * sizeof(uint8_t));
    h = h + 3 * sizeof(uint8_t);

    *(uint16_t *)h = host_htobe16(cke->psk_identity_len);
    h = h + sizeof(uint16_t);

    host_memcpy(h, cke->psk_identity, cke->psk_identity_len * sizeof(uint8_t));

    return r;
}

static void parse_raw_cke(ClientKeyExchange_p_t *cke, const void *raw_cke) {

    uint8_t *r = (uint8_t *)raw_cke;

    /* Skip the Handshake header */
    r = r + sizeof(HandshakeType_t) + 3 * sizeof(uint8_t);

    cke->psk_identity_len = host_be16toh(*(uint16_t *)r);
    r = r + sizeof(uint16_t);
    cke->psk_identity = r;
}

static void *new_raw_f(tp_sock_t *s, const Finished_p_t *f, uint32_t *f_size) {

    uint32_t handshake_h_size = sizeof(HandshakeType_t) + 3*sizeof(uint8_t);
    uint32_t mess_size = 12*sizeof(uint8_t);
    uint32_t tot_size = handshake_h_size + mess_size;

    uint8_t *h = handshake_lin_alloc(&s->h, tot_size);
    if (!h)
        return NULL;
    
    uint8_t *r = h;
    *f_size = tot_size;

    *(HandshakeType_t *)h = HandshakeType_finished;
    h = h + sizeof(HandshakeType_t);

    uint32_t BE_mess_size = host_htobe32(mess_size);
    uint8_t *ms_p = (uint8_t *)&BE_mess_size;
    host_memcpy(h, ms_p + 1, 3 * sizeof(uint8_t));
    h = h + 3 * sizeof(uint8_t);

    host_memcpy(h, f->verify_data, 12*sizeof(uint8_t));

    return r;
}

static void parse_raw_f(Finished_p_t *f, const void *raw_f) {

    uint8_t *r = (uint8_t *)raw_f;

    /* Skip the Handshake header */
    r = r + sizeof(HandshakeType_t) + 3 * sizeof(uint8_t);

    host_memcpy(f->verify_data, r, 12*sizeof(uint8_t));
}
/* ----------------------------------------------------------------------------------- */

/* --------------------------------- message handlers -------------------------------- */

static int handle_hr(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {
    
    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_SERVER) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    /* No action on HelloRequest */
    return 0;
}

static int handle_ch(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {
    
    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_CLIENT ||
        GET_HS_STATE(s->sock_state) != 0) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }

    ClientHello_p_t chp;
    parse_raw_ch(&chp, handshake_m);

    /* First we check the protocol version of the record layer.
       For the ClientHello we check only the major version being the same as TLS 1.2.
       We ignore Handshake layer protocol version because our server only works with
       TLS 1.2 so it will be client responsibility to abort the handshake if it is not
       happy with our proposed version */
    if (record_prtcv.major != ProtocolVersion_TLS_1_2.major) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }
    
    /* Check for the cipher methods */
    CipherSuite_t available_cs[] = cipher_suites_default;
    size_t cs_len = sizeof(available_cs) / sizeof(available_cs[0]);
    
    size_t idx_cs = 0;
    unsigned char found = 0;
    while (idx_cs < chp.cipher_suites_len && !found) {
        for (size_t i = 0; i < cs_len; i++)
            if (chp.cipher_suites[idx_cs].b1 == available_cs[i].b1 &&
                chp.cipher_suites[idx_cs].b2 == available_cs[i].b2)
                found = 1;
        idx_cs++;
    }
    if (idx_cs >= chp.cipher_suites_len) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    /* Check for the compression methods */
    CompressionMethod_t available_cm[] = compression_methods_default;
    size_t cm_len = sizeof(available_cm) / sizeof(available_cm[0]);

    size_t idx_cm = 0;
    found = 0;
    while (idx_cm < chp.compression_methods_len && !found) {
        for (size_t i = 0; i < cm_len; i++)
            if (chp.compression_methods[idx_cm] == available_cm[i])
                found = 1;
        idx_cm++;
    }
    if (idx_cm >= chp.compression_methods_len) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    /* If we are here it means the ClientHello it's ok.
       Now we copy the client random and hash the message */
    host_memcpy(&s->h.S_C_randoms[1], chp.random, sizeof(Random_t));
    if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    /* Client hello is received */
    SET_HS_STATE(s->sock_state, SOCK_HS_CH);

    /* Let's proceed with sending the Server Hello */
    set_random(&s->h.S_C_randoms[0]);

    ServerHello_p_t shp = {
        .server_version = ProtocolVersion_TLS_1_2,
        .random = &s->h.S_C_randoms[0],
        .session_id_len = 0,
        .session_id = NULL,
        .cipher_suite = chp.cipher_suites[idx_cs],
        .compression_method = chp.compression_methods[idx_cm]
    };

    uint32_t sh_size;
    void *raw_sh = new_raw_sh(s, &shp, &sh_size);
    if (!raw_sh) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (send_handshake(s, raw_sh, sh_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (sha256_process(&s->h.hash, raw_sh, sh_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    /* Compression and Cipher algorithms are found so we set them in pend conn states */
    s->pend_read.cipher_suite = chp.cipher_suites[idx_cs];
    s->pend_read.compression_method = chp.compression_methods[idx_cm];
    
    s->pend_write.cipher_suite = chp.cipher_suites[idx_cs];
    s->pend_write.compression_method = chp.compression_methods[idx_cm];

    SET_HS_STATE(s->sock_state, SOCK_HS_SH);

    uint32_t shd_size;
    void *raw_shd = new_raw_shd(s, &shd_size);
    if (!raw_shd) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (send_handshake(s, raw_shd, shd_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (sha256_process(&s->h.hash, raw_shd, shd_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_SHD);
    
    return 0;
}

static int handle_sh(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {
    
    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_SERVER ||
        GET_HS_STATE(s->sock_state) != SOCK_HS_CH) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }

    ServerHello_p_t shp;
    parse_raw_sh(&shp, handshake_m);
    /* For any message other than ClientHello the protocol version must match TLS 1.2
       both at Record and Handshake level */
    if (record_prtcv.major       != ProtocolVersion_TLS_1_2.major ||
        record_prtcv.minor       != ProtocolVersion_TLS_1_2.minor ||
        shp.server_version.major != ProtocolVersion_TLS_1_2.major ||
        shp.server_version.minor != ProtocolVersion_TLS_1_2.minor) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    /* Save the server random and hash the message */
    host_memcpy(&s->h.S_C_randoms[0], shp.random, sizeof(Random_t));
    if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    s->pend_read.cipher_suite = shp.cipher_suite;
    s->pend_read.compression_method = shp.compression_method;
    
    s->pend_write.cipher_suite = shp.cipher_suite;
    s->pend_write.compression_method = shp.compression_method;

    SET_HS_STATE(s->sock_state, SOCK_HS_SH);

    return 0;
}

static int handle_ske(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {

    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_SERVER ||
        GET_HS_STATE(s->sock_state) != SOCK_HS_SH) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    /* For any message other than ClientHello the protocol version must match TLS 1.2
       both at Record and Handshake level */
    if (record_prtcv.major       != ProtocolVersion_TLS_1_2.major ||
        record_prtcv.minor       != ProtocolVersion_TLS_1_2.minor) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    ServerKeyExchange_p_t skep;
    parse_raw_ske(&skep, handshake_m);
    /* For now we just ignore the hint, if received. We just hash the message */
    if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_SKE);

    return 0;
}

static int handle_shd(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {

    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_SERVER ||
        (GET_HS_STATE(s->sock_state) != SOCK_HS_CH && 
         GET_HS_STATE(s->sock_state) != SOCK_HS_SKE)) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    /* For any message other than ClientHello the protocol version must match TLS 1.2
       both at Record and Handshake level */
    if (record_prtcv.major       != ProtocolVersion_TLS_1_2.major ||
        record_prtcv.minor       != ProtocolVersion_TLS_1_2.minor) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_SHD);

    /* Proceed with sending the ClientKeyExchange message */
    ClientKeyExchange_p_t ckep = {
        .psk_identity_len = sizeof(uint16_t),
        .psk_identity = (uint8_t *)&s->h.psk_identity
    };

    /* Generate the master secret. If we can't generate the master secret we abort */
    if (s->h.get_ms(*(uint16_t *)ckep.psk_identity, s->h.S_C_randoms,
        s->h.master_secret) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    /* Generate Client and Server Write keys */
    if (set_key_block(s->h.master_secret, s->h.S_C_randoms,
        (uint8_t *)s->C_S_write_MAC_key, 64) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    uint32_t cke_size;
    void *raw_cke = new_raw_cke(s, &ckep, &cke_size);
    if (!raw_cke) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (send_handshake(s, raw_cke, cke_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (sha256_process(&s->h.hash, raw_cke, cke_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_CKE);

    /* Send the ChangeCipherSpec message */
    if (changecs_send(s) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    /* These actions have effect on the record layer.
       From now on the record layer will apply the
       pend_write security measures */
    s->curr_write = s->pend_write;
    s->pend_write = conn_state_t_INIT;

    /* The hash of all the handshake message (Client side).
       Should contain, in order:
       - ClientHello
       - ServerHello
       - ServerKeyExchange (only if the server sent one)
       - ServerHelloDone
       - ClientKeyExchange */
    uint8_t client_hash[32];
    struct sha256_state temp = s->h.hash; /* temp copy */
    if (sha256_done(&temp, client_hash) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    /* Calculate the verify_data */
    Finished_p_t fp;
    if (tls_prf_sha256(s->h.master_secret, 48, "client finished", client_hash, 32,
                   fp.verify_data, 12) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    uint32_t f_size;
    void *raw_f = new_raw_f(s, &fp, &f_size);
    if (!raw_f) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    if (send_handshake(s, raw_f, f_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    /* Continuing the hash process to verify_data of the Finished message from
       the server */
    if (sha256_process(&s->h.hash, raw_f, f_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    
    SET_HS_STATE(s->sock_state, SOCK_HS_FC);

    return 0;
}

static int handle_cke(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {

    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_CLIENT ||
        GET_HS_STATE(s->sock_state) != SOCK_HS_SHD) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
    }
    /* For any message other than ClientHello the protocol version must match TLS 1.2
       both at Record and Handshake level */
    if (record_prtcv.major       != ProtocolVersion_TLS_1_2.major ||
        record_prtcv.minor       != ProtocolVersion_TLS_1_2.minor) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    ClientKeyExchange_p_t ckep;
    parse_raw_cke(&ckep, handshake_m);

    /* Generate the master secret. If we can't generate the master secret we abort */
    if (s->h.get_ms(*(uint16_t *)ckep.psk_identity, s->h.S_C_randoms,
        s->h.master_secret) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    /* Generate Client and Server Write keys */
    if (set_key_block(s->h.master_secret, s->h.S_C_randoms,
        (uint8_t *)s->C_S_write_MAC_key, 64) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    /* If we are here we hash the ClientKeyExchange message */
    if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_CKE);

    return 0;
}

static int handle_f(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {
    /* For any message other than ClientHello the protocol version must match TLS 1.2
       both at Record and Handshake level */
    if (record_prtcv.major       != ProtocolVersion_TLS_1_2.major ||
        record_prtcv.minor       != ProtocolVersion_TLS_1_2.minor) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_handshake_failure
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_HANDSHAKE_FAIL;
    }

    if ((s->sock_state & SOCK_MD_MASK) == SOCK_MD_CLIENT) {
        /* Received a Finished message as a Client. We need to check */
        if (GET_HS_STATE(s->sock_state) != SOCK_HS_SHD) {
        Alert_t alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_unexpected_message
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, alert);
        return TP_RCV_UNEXPECTED_MSG;
        }

        Finished_p_t server_f;
        parse_raw_f(&server_f, handshake_m);
        uint8_t client_verify_data[12]; /* Here our calculated verify_data */

        /* Now we check the server verify_data */
        uint8_t server_hash[32];
        if (sha256_done(&s->h.hash, server_hash) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (tls_prf_sha256(s->h.master_secret, 48, "server finished", server_hash, 32,
                           client_verify_data, 12) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (host_memcmp(server_f.verify_data, client_verify_data, 12)) {
            Alert_t alert = {
                .level = AlertLevel_fatal,
                .description = AlertDescription_decrypt_error
            };
            s->sock_state = SOCK_CLOSED;
            alert_send(s, alert);
            return TP_HANDSHAKE_FAIL;
        }

        SET_HS_STATE(s->sock_state, 0);
        s->sock_state = s->sock_state | SOCK_HS_DONE;
        
        return 0;
    }
    else {
        /* Received a Finished message as a Server. We need to check */
        if (GET_HS_STATE(s->sock_state) != SOCK_HS_CKE) {
            Alert_t alert = {
                .level = AlertLevel_fatal,
                .description = AlertDescription_unexpected_message
            };
            s->sock_state = SOCK_CLOSED;
            alert_send(s, alert);
            return TP_RCV_UNEXPECTED_MSG;
        }

        Finished_p_t client_f;
        parse_raw_f(&client_f, handshake_m);
        uint8_t server_verify_data[12]; /* Here our calculated verify_data */

        /* Now we check the client verify_data */
        uint8_t client_hash[32];
        struct sha256_state temp = s->h.hash; /* temp copy */
        if (sha256_done(&temp, client_hash) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (tls_prf_sha256(s->h.master_secret, 48, "client finished", client_hash, 32,
                           server_verify_data, 12) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (host_memcmp(client_f.verify_data, server_verify_data, 12)) {
            Alert_t alert = {
                .level = AlertLevel_fatal,
                .description = AlertDescription_decrypt_error
            };
            s->sock_state = SOCK_CLOSED;
            alert_send(s, alert);
            return TP_HANDSHAKE_FAIL;
        }
        /* verify_data from client matches ours. Proceed with hashing client
           Finished message, sending a ChangeCipherSpec message and a Finished message */
        if (sha256_process(&s->h.hash, handshake_m, handshake_m_len) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (changecs_send(s) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
        }
        /* These actions have effect on the record layer.
        From now on the record layer will apply the
        pend_write security measures */
        s->curr_write = s->pend_write;
        s->pend_write = conn_state_t_INIT;
        
        Finished_p_t fp;
        uint8_t hash[32];
        if (sha256_done(&s->h.hash, hash) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        if (tls_prf_sha256(s->h.master_secret, 48, "server finished", hash, 32,
                           fp.verify_data, 12) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }

        uint32_t f_size;
        void *raw_f = new_raw_f(s, &fp, &f_size);
        if (send_handshake(s, raw_f, f_size) < 0) {
            s->sock_state = SOCK_CLOSED;
            return TP_FATAL;
        }
        
        SET_HS_STATE(s->sock_state, 0);
        s->sock_state = s->sock_state | SOCK_HS_DONE;
        
        return 0;
    }
}
/* ----------------------------------------------------------------------------------- */

/* ---------------------------------- API functions ---------------------------------- */

void handshake_init(hds_layer *h, int (*get_ms)(uint16_t, Random_t *, uint8_t *),
                            uint16_t psk_identity, void *buffer, size_t buf_size) {

    h->get_ms = get_ms;
    h->psk_identity = psk_identity;                           
    lin_init(&h->alloc, buffer, buf_size);
}

void *handshake_lin_alloc(hds_layer *h, size_t size) {

    return lin_alloc(&h->alloc, size);
}

Handshake_H_p_t handshake_parse_header(const void *header) {

    const uint8_t *h = header;
    Handshake_H_p_t parsed_header = {
        .msg_type = *h,
        .length = 0
    };

    h = h + sizeof(HandshakeType_t);
    uint8_t *p = (uint8_t *)&parsed_header.length;
    
    host_memcpy(p+1, h, 3*sizeof(uint8_t));
    parsed_header.length = host_be32toh(parsed_header.length);

    return parsed_header;
}

int handshake_do_C(tp_sock_t *s) {

    /* Init the handshake FSM and the sha256 hash structure */
    SET_HS_STATE(s->sock_state, 0);
    sha256_init(&s->h.hash);

    set_random(&s->h.S_C_randoms[1]);
    CipherSuite_t cipher_suites[] = cipher_suites_default;
    CompressionMethod_t cmprss_methods[] = compression_methods_default;
    
    /* Default ClientHello message */
    ClientHello_p_t chp = {
        .client_version = ProtocolVersion_TLS_1_2,
        .random = &s->h.S_C_randoms[1],
        .session_id_len = 0,
        .session_id = NULL,
        .cipher_suites_len = sizeof(cipher_suites)/sizeof(cipher_suites[0]),
        .cipher_suites = cipher_suites,
        .compression_methods_len = sizeof(cmprss_methods)/sizeof(cmprss_methods[0]),
        .compression_methods = cmprss_methods
    };

    uint32_t ch_size;
    void *raw_ch = new_raw_ch(s, &chp, &ch_size);
    if (!raw_ch) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }
    int res = send_handshake(s, raw_ch, ch_size);
    if (res < 0) {
        s->sock_state = SOCK_CLOSED;
        return res;
    }
    if (sha256_process(&s->h.hash, raw_ch, ch_size) < 0) {
        s->sock_state = SOCK_CLOSED;
        return TP_FATAL;
    }

    SET_HS_STATE(s->sock_state, SOCK_HS_CH);

    do
        res = record_recv_one(s);
    while (res == 0 && !(s->sock_state & SOCK_HS_DONE));
    
    return res;
}

int handshake_do_S(tp_sock_t *s) {

    /* Init the handshake FSM and the sha256 hash structure */
    SET_HS_STATE(s->sock_state, 0);
    sha256_init(&s->h.hash);

    int res;
    do
        res = record_recv_one(s);
    while (res == 0 && !(s->sock_state & SOCK_HS_DONE));
    
    return res;
}

int handshake_handle(tp_sock_t *s, const void *handshake_m, uint32_t handshake_m_len,
                                                    ProtocolVersion_t record_prtcv) {

    Handshake_H_p_t handshake_h = handshake_parse_header(handshake_m);
    int res;

    switch (handshake_h.msg_type) {
    case HandshakeType_hello_request:
        res = handle_hr(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_client_hello:
        res = handle_ch(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_server_hello:
        res = handle_sh(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_server_key_exchange:
        res = handle_ske(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_server_hello_done:
        res = handle_shd(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_client_key_exchange:
        res = handle_cke(s, handshake_m, handshake_m_len, record_prtcv);
        break;
    case HandshakeType_finished:
        res = handle_f(s, handshake_m, handshake_m_len, record_prtcv);
        break;

    default:
    {
        Alert_t decode_alert = {
            .level = AlertLevel_fatal,
            .description = AlertDescription_decode_error
        };
        s->sock_state = SOCK_CLOSED;
        alert_send(s, decode_alert);
        res = TP_RCV_DECODE_ERROR;
    }
    }

    /* handshake level is responsible for its memory freeing */
    free_all(&s->h);
    return res;
}
/* ----------------------------------------------------------------------------------- */