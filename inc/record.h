/* ------------------------------- [record_] functions ------------------------------- */
/*
*  This functions handle the message payloads produced by uppers protocols:
*  - the handshake protocol
*  - the alert protocol
*  - the change cipher spec protocol
*  - the application data protocol.
*
*  They assume that the payload (fragment) is already in network order (Big endian)
*/
#ifndef RECORD_H_
#define RECORD_H_

typedef struct TLSPlaintext_t_ TLSPlaintext_t;
/*
*  You can get the length of this part of the message by sizeof
*/
typedef struct TLS_Plain_H_t_ TLS_Plain_H_t;
typedef struct TLSCiphertext_t_ TLSCiphertext_t;
/*
*  You can get the length of this part of the message by sizeof
*/
typedef struct TLS_Ciph_H_t_ TLS_Ciph_H_t;

#include "tinypsk.h"
#include "tp_types.h"


struct TLSPlaintext_t_{
    struct __attribute__ ((__packed__)) TLS_Plain_H_t_ {
        ContentType_t type;
        ProtocolVersion_t version;
        uint16_t length;             /* Max length is 2^14 */
    } header;
    void *fragment;
};

struct TLSCiphertext_t_{
    struct __attribute__ ((__packed__)) TLS_Ciph_H_t_ {
        ContentType_t type;             /* same as TLSPlaintext_t.type */
        ProtocolVersion_t version;      /* same as TLSPlaintext_t.version */
        uint16_t length;                /* Max length is 2^14 + 2048 */
    } header;
    GenericStreamCipher_t fragment;
};

int record_send_plain(tp_sock_t *s, const TLSPlaintext_t *plain_m);
int record_recv_one(tp_sock_t *s);

#endif