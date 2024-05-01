/*
*   Here we redefine used library functions names with libc ones if
*   you compile with OS support
*/

#ifndef HOST_H_
#define HOST_H_

#ifndef TP_NO_OS
#include "string.h"
#include "endian.h"
#include "time.h"
#include "stdlib.h"
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