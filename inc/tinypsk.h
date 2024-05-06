#ifndef TINYPSK_H_
#define TINYPSK_H_

/* Define TP_NO_OS to build a bare metal version */

/* ------------------------------- Error return codes  ------------------------------- */

/* A fatal error was generated. The TLS protocol is interrupted immediately
   and no more messages can be sent or received */
#define TP_FATAL -1
/* The requested action is not allowed by the TLS protocol in the current state */
#define TP_NOT_ALLOWED -2
/* A TLSCiphertext record was received that had a length more than 2^14+2048 bytes.
   This error is fatal */
#define TP_RCV_RECORD_OVERFLOW -3
/* This alert is returned if a record is received with an incorrect MAC */
#define TP_RCV_BAD_RECORD_MAC -4
/* A message was received but the decoding failed. This error is fatal */
#define TP_RCV_DECODE_ERROR -5
/* The connection is closed due to the reception of a close_notify */
#define TP_CLOSED -6
/* An unexpected message was received. This error is fatal */
#define TP_RCV_UNEXPECTED_MSG -7
/* The handshake is aborted */
#define TP_HANDSHAKE_FAIL -8
/* ----------------------------------------------------------------------------------- */

/* ---------------------------- Sock state FSM bitmasks  ----------------------------- */

/* Sock in closed state. No other actions are permitted */
#define SOCK_CLOSED    ((unsigned char) 1 << 7)
/* Application data is available to be received */
#define SOCK_APPL_RD   ((unsigned char) 1 << 6)
/* Connection end Mode [MD] bitmask */
#define SOCK_MD_MASK   ((unsigned char) 1)
/* Init in Client mode */
#define SOCK_MD_CLIENT ((unsigned char) 0)
/* Init in Server mode */
#define SOCK_MD_SERVER ((unsigned char) 1)
/* Handshake states [HS] bitmask */
#define SOCK_HS_MASK   ((unsigned char) 15 << 1)
/* ClientHello message is sent (Client mode) or received (Server mode) */
#define SOCK_HS_CH     ((unsigned char) 1 << 1)
/* ServerHello message is sent (Server mode) or received (Client mode) */
#define SOCK_HS_SH     ((unsigned char) 2 << 1)
/* ServerKeyExchange is sent (Server mode) or received (Client mode) */
#define SOCK_HS_SKE    ((unsigned char) 3 << 1)
/* ServerHelloDone is sent (Server mode) or received (Client mode) */
#define SOCK_HS_SHD    ((unsigned char) 4 << 1)
/* ClientKeyExchange is sent (Client mode) or received (Server mode) */
#define SOCK_HS_CKE    ((unsigned char) 5 << 1)
/* ChangeCipherSpec from client is sent (Client mode) or received (Server mode) */
#define SOCK_HS_CCSC   ((unsigned char) 6 << 1)
/* Finished from client is sent (Client mode) or received (Server mode) */
#define SOCK_HS_FC     ((unsigned char) 7 << 1)
/* ChangeCipherSpec from server is sent (Server mode) or received (Client mode) */
#define SOCK_HS_CCSS   ((unsigned char) 8 << 1)
/* Finished from server is sent (Server mode) or received (Client mode) */
#define SOCK_HS_FS     ((unsigned char) 9 << 1)
/* Handshake completed. master_secret and client/server_write_MAC_key available */
#define SOCK_HS_DONE   ((unsigned char) 1 << 5)
/* ----------------------------------------------------------------------------------- */

#ifdef DEBUG
#include "assert.h"
#include "stdio.h"
#define check(x) assert((x))
#define print_debug(...) fprintf(stderr, __VA_ARGS__)
#define print_debug_arr(arr, len)   do {                                             \
                                       for (size_t i = 0; i < len; i++)              \
                                          print_debug("%02X ", *((uint8_t *)arr + i)); \
                                       print_debug("\n");                            \
                                    }while(0)
#else
#define check(x)
#define print_debug(...)
#define print_debug_arr(arr, len)
#endif

typedef struct tp_sock_t_ tp_sock_t;

#include "stddef.h"
#include "stdint.h"
#include "application.h"
#include "handshake.h"
#include "tp_types.h"

struct tp_sock_t_ {
   unsigned char sock_state;
   /* Handshake layer support structure */
   hds_layer h;
   /* Application layer support structure */
   app_layer a;
   /* Common structures */
   uint8_t C_S_write_MAC_key[2][32];
   conn_state_t curr_read, curr_write;
   conn_state_t pend_read, pend_write;
   void *tl_structure;
   /*
   *  Pointer to a socket-like send function.
   *  Must return the number of byte sent or
   *  (-1) on error.
   */
   int (*tl_send)(void *, const void *, size_t);
   /*
   *  Pointer to a socket-like recv function.
   *  Must return the number of byte received or
   *  (-1) on error.
   */
   int (*tl_recv)(void *, void *, size_t);
};

int tp_initC(tp_sock_t *s, uint16_t psk_identity, void *tl_structure,
            int (*tl_send)(void *, const void *, size_t),
            int (*tl_recv)(void *, void *, size_t),
            int (*get_ms)(uint16_t, Random_t *, uint8_t *));
int tp_initS(tp_sock_t *s, void *tl_structure,
            int (*tl_send)(void *, const void *, size_t),
            int (*tl_recv)(void *, void *, size_t),
            int (*get_ms)(uint16_t, Random_t *, uint8_t *));
int tp_handshake(tp_sock_t *s);
int tp_send(tp_sock_t *s, const void *buff, size_t len);
int tp_rcv(tp_sock_t *s, void *buff, size_t len);
int tp_close(tp_sock_t *s);

#endif