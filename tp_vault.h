#ifndef TP_VAULT_H_
#define TP_VAULT_H_

#include "stddef.h"
#include "stdint.h"
#include "tp_types.h"

// Max PSK len is 32 bytes
#define MAX_PSK_LEN 32

/**
 * TP_CRED(ID, PSK) - Initialize a tp_cred_t type
 */
#define TP_CRED(ID, PSK) { .identity = (ID), .psk = (PSK), .psk_len = PSK_LEN_((PSK)) }
#define PSK_LEN_(psk) ( (sizeof((psk))-1) < MAX_PSK_LEN ? (sizeof((psk))-1) : MAX_PSK_LEN )

typedef struct tp_cred{
    const uint16_t identity; /* NON-Compliant: TLS v1.2 prescribes a len of 65535 bytes for identity */
    const char psk[MAX_PSK_LEN];
    const uint16_t psk_len;
}tp_cred_t;

int tp_vault_set(tp_cred_t *credentials, size_t creds_size);
int tp_vault_get_ms(uint16_t identity, Random_t *S_C_randoms, uint8_t *ms);

#endif