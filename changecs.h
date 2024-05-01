#ifndef CHANGECS_H_
#define CHANGECS_H_

#include "tinypsk.h"
#include "stdint.h"

typedef uint8_t ChangeCipherSpec_t;

/* change_cipher_spec message */
#define change_cipher_spec ((ChangeCipherSpec_t) 1)

static int changecs_send(tp_sock_t *s);
int changecs_handle(tp_sock_t *s, ChangeCipherSpec_t message);

#endif