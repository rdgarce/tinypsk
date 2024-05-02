/*
 * TLS v1.2 hmac_sha256 and tls_prf_sha256 implementation
 */

#ifndef TP_SHA256_H_
#define TP_SHA256_H_

#include "stddef.h"
#include "stdint.h"

#define SHA256_MAC_LEN 32

int hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t *len, uint8_t *mac);

int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
		size_t data_len, uint8_t *mac);

int tls_prf_sha256(const uint8_t *secret, size_t secret_len,
		   const char *label, const uint8_t *seed, size_t seed_len,
		   uint8_t *out, size_t outlen);

#endif
