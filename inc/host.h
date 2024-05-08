/*
*   Here we redefine used library functions names with libc ones if
*   you compile with OS support
*/
#ifndef HOST_H_
#define HOST_H_

#ifdef TP_NO_OS

#include <stddef.h>
#include <stdint.h>
void *host_memset(void *dest, int c, size_t n);
int host_memcmp(const void *vl, const void *vr, size_t n);
void *host_memcpy(void *restrict dest, const void *restrict src, size_t n);
size_t host_strlen(const char *s);
uint16_t host_htobe16(uint16_t host_16bits);
uint16_t host_be16toh(uint16_t big_endian_16bits);
uint32_t host_htobe32(uint32_t host_32bits);
uint32_t host_be32toh(uint32_t big_endian_32bits);
uint64_t host_htobe64(uint64_t host_64bits);
uint64_t host_be64toh(uint64_t big_endian_64bits);
long host_time(long * tloc);
int host_rand(void);

#else

#include <string.h>
#include <endian.h>
#include <time.h>
#include <stdlib.h>
#define host_memcpy  memcpy
#define host_memset  memset
#define host_memcmp  memcmp
#define host_strlen  strlen
#define host_htobe16 htobe16
#define host_be16toh be16toh
#define host_htobe32 htobe32
#define host_be32toh be32toh
#define host_htobe64 htobe64
#define host_be64toh be64toh
#define host_time    time
#define host_rand    rand

#endif

#endif