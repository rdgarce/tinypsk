#include "tp_sha256.h"
#include "sha256_prim.h"
#include "host.h"

/**
 * sha256_vector - SHA256 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
static int sha256_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
		  uint8_t *mac)
{
	struct sha256_state ctx;
	size_t i;

	sha256_init(&ctx);
	for (i = 0; i < num_elem; i++)
		if (sha256_process(&ctx, addr[i], len[i]))
			return -1;
	if (sha256_done(&ctx, mac))
		return -1;
	return 0;
}

/**
 * hmac_sha256_vector - HMAC-SHA256 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (32 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[32];
	const uint8_t *_addr[11];
	size_t _len[11], i;

	if (num_elem > 10) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = SHA256(key) */
        if (key_len > 64) {
		if (sha256_vector(1, &key, &key_len, tk) < 0)
			return -1;
		key = tk;
		key_len = 32;
        }

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	host_memset(k_pad, 0, sizeof(k_pad));
	host_memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (sha256_vector(1 + num_elem, _addr, _len, mac) < 0)
		return -1;

	host_memset(k_pad, 0, sizeof(k_pad));
	host_memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	return sha256_vector(2, _addr, _len, mac);
}


/**
 * hmac_sha256 - HMAC-SHA256 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (32 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
		size_t data_len, uint8_t *mac)
{
	return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}

/**
 * tls_prf_sha256 - Pseudo-Random Function for TLS v1.2 (P_SHA256, RFC 5246)
 * @secret: Key for PRF
 * @secret_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @seed: Seed value to bind into the key
 * @seed_len: Length of the seed
 * @out: Buffer for the generated pseudo-random key
 * @outlen: Number of bytes of key to generate
 * Returns: 0 on success, -1 on failure.
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key in TLS. This PRF is defined in RFC 2246, Chapter 5.
 */
int tls_prf_sha256(const uint8_t *secret, size_t secret_len, const char *label,
		   const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
	size_t clen;
	uint8_t A[SHA256_MAC_LEN];
	uint8_t P[SHA256_MAC_LEN];
	size_t pos;
	const unsigned char *addr[3];
	size_t len[3];

	addr[0] = A;
	len[0] = SHA256_MAC_LEN;
	addr[1] = (unsigned char *) label;
	len[1] = host_strlen(label);
	addr[2] = seed;
	len[2] = seed_len;

	/*
	 * RFC 5246, Chapter 5
	 * A(0) = seed, A(i) = HMAC(secret, A(i-1))
	 * P_hash = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ..
	 * PRF(secret, label, seed) = P_SHA256(secret, label + seed)
	 */

	if (hmac_sha256_vector(secret, secret_len, 2, &addr[1], &len[1], A) < 0)
		return -1;

	pos = 0;
	while (pos < outlen) {
		if (hmac_sha256_vector(secret, secret_len, 3, addr, len, P) <
		    0 ||
		    hmac_sha256(secret, secret_len, A, SHA256_MAC_LEN, A) < 0)
			return -1;

		clen = outlen - pos;
		if (clen > SHA256_MAC_LEN)
			clen = SHA256_MAC_LEN;
		host_memcpy(out + pos, P, clen);
		pos += clen;
	}

	return 0;
}