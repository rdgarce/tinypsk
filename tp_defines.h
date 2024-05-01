#ifndef TP_DEFINES_H_
#define TP_DEFINES_H_

#include "tp_types.h"

/*
*********************
*   Protocol version
*********************
*/
// TLS v1.2
#define ProtocolVersion_TLS_1_2 ((ProtocolVersion_t) {3, 3})

/***********************
*   Compression Methods
************************
*/
// No compression
#define CompressionMethod_NULL ((CompressionMethod_t) 0)

/*
******************
*   Cipher suites
******************
*/
// TLS_NULL_WITH_NULL_NULL
#define CipherSuite_TLS_NULL_WITH_NULL_NULL ((CipherSuite_t){0x00, 0x00})
// TLS_PSK_WITH_NULL_SHA
#define CipherSuite_TLS_PSK_WITH_NULL_SHA   ((CipherSuite_t){0x00, 0x2C})

/*
*******************************
*   TLSPlaintext content types
*******************************
*/

#define ContentType_change_cipher_spec ((ContentType_t) 20)
#define ContentType_alert              ((ContentType_t) 21)
#define ContentType_handshake          ((ContentType_t) 22)
#define ContentType_application_data   ((ContentType_t) 23)

/*
********************
*   Handshake types
********************
*/

#define HandshakeType_hello_request       ((HandshakeType_t) 0)
#define HandshakeType_client_hello        ((HandshakeType_t) 1)
#define HandshakeType_server_hello        ((HandshakeType_t) 2)
#define HandshakeType_server_key_exchange ((HandshakeType_t) 12)
#define HandshakeType_server_hello_done   ((HandshakeType_t) 14)
#define HandshakeType_client_key_exchange ((HandshakeType_t) 16)
#define HandshakeType_finished            ((HandshakeType_t) 20)

/*
****************
*   Alert level
****************   
*/

#define AlertLevel_warning ((AlertLevel_t) 1)
#define AlertLevel_fatal   ((AlertLevel_t) 2)

/*
**********************
*   Alert description
**********************
*/

#define AlertDescription_close_notify                ((AlertDescription_t) 0)
#define AlertDescription_unexpected_message          ((AlertDescription_t) 10)
#define AlertDescription_bad_record_mac              ((AlertDescription_t) 20)
#define AlertDescription_decryption_failed_RESERVED  ((AlertDescription_t) 21)
#define AlertDescription_record_overflow             ((AlertDescription_t) 22)
#define AlertDescription_decompression_failure       ((AlertDescription_t) 30)
#define AlertDescription_handshake_failure           ((AlertDescription_t) 40)
#define AlertDescription_no_certificate_RESERVED     ((AlertDescription_t) 41)
#define AlertDescription_bad_certificate             ((AlertDescription_t) 42)
#define AlertDescription_unsupported_certificate     ((AlertDescription_t) 43)
#define AlertDescription_certificate_revoked         ((AlertDescription_t) 44)
#define AlertDescription_certificate_expired         ((AlertDescription_t) 45)
#define AlertDescription_certificate_unknown         ((AlertDescription_t) 46)
#define AlertDescription_illegal_parameter           ((AlertDescription_t) 47)
#define AlertDescription_unknown_ca                  ((AlertDescription_t) 48)
#define AlertDescription_access_denied               ((AlertDescription_t) 49)
#define AlertDescription_decode_error                ((AlertDescription_t) 50)
#define AlertDescription_decrypt_error               ((AlertDescription_t) 51)
#define AlertDescription_export_restriction_RESERVED ((AlertDescription_t) 60)
#define AlertDescription_protocol_version            ((AlertDescription_t) 70)
#define AlertDescription_insufficient_security       ((AlertDescription_t) 71)
#define AlertDescription_internal_error              ((AlertDescription_t) 80)
#define AlertDescription_user_canceled               ((AlertDescription_t) 90)
#define AlertDescription_no_renegotiation            ((AlertDescription_t) 100)
#define AlertDescription_unsupported_extension       ((AlertDescription_t) 110)
#define AlertDescription_unknown_psk_identity        ((AlertDescription_t) 115)

/*
*
*   Predefined objects
*/
// cipher_suites default conf
#define cipher_suites_default {CipherSuite_TLS_PSK_WITH_NULL_SHA, CipherSuite_TLS_NULL_WITH_NULL_NULL}
// compression_methods default conf
#define compression_methods_default {CompressionMethod_NULL}
// conn_state_t default conf
#define conn_state_t_INIT ((conn_state_t){                \
    .seq_num = 0,                                         \
    .compression_method = CompressionMethod_NULL,         \
    .cipher_suite = CipherSuite_TLS_NULL_WITH_NULL_NULL})                                        


#endif