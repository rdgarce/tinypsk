#ifndef TP_TYPES_H_
#define TP_TYPES_H_

#include "stdint.h"

typedef struct ProtocolVersion_t_ ProtocolVersion_t;
struct __attribute__ ((__packed__)) ProtocolVersion_t_{
    uint8_t major;
    uint8_t minor;
};

typedef struct Random_t_ Random_t;
struct __attribute__ ((__packed__)) Random_t_{
    // Subject to Big Endian conversion
    uint32_t BE_gmt_unix_time;
    uint8_t random_bytes[28];
};

typedef struct CipherSuite_t_ CipherSuite_t;
struct __attribute__ ((__packed__)) CipherSuite_t_{
    uint8_t b1;
    uint8_t b2;
};

typedef struct GenericStreamCipher_t_ GenericStreamCipher_t;
struct GenericStreamCipher_t_{
    void *content;
    uint8_t MAC[32]; /* Fixed at 32 byte because sha256 produces 32 bytes results */
};

typedef uint8_t CompressionMethod_t;
typedef uint8_t HandshakeType_t;

typedef uint8_t ContentType_t;

typedef uint8_t AlertLevel_t;
typedef uint8_t AlertDescription_t;

typedef struct conn_state_t_ conn_state_t;
struct conn_state_t_ {
    uint64_t seq_num;
    CompressionMethod_t compression_method;
    CipherSuite_t cipher_suite;
};

#endif