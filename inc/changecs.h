#ifndef CHANGECS_H_
#define CHANGECS_H_

#include "stdint.h"

typedef uint8_t ChangeCipherSpec_t;

#include "tinypsk.h"

/* change_cipher_spec message */
#define change_cipher_spec ((ChangeCipherSpec_t) 1)

int changecs_send(tp_sock_t *s);
int changecs_handle(tp_sock_t *s, ChangeCipherSpec_t message);

#endif