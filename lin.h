#ifndef LIN_H_
#define LIN_H_

/* Single header Linear Allocator */

#include "stddef.h"

/*
*  Every allocation size is aligned at 2^(LIN_ALIGNMENT_POW) bytes
*/
#define LIN_ALIGNMENT_POW 0

/* Private definitions */
#ifdef DEBUG
#include "assert.h"
#include "stdio.h"
#define check(x) assert((x))
#define print_debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define check(x)
#define print_debug(...)
#endif

#define ALIGNMENT_ (1 << LIN_ALIGNMENT_POW)
#if LIN_ALIGNMENT_POW == 0
#define ALIGNMENT_MASK_ 0
#else
#define ALIGNMENT_MASK_ (ALIGNMENT_-1)
#endif

typedef struct lin_ lin;
struct lin_ {
    size_t used_size;
    size_t buf_size;
    void *buffer;
};

void lin_init(lin *a, void *buffer, size_t buf_size);
void *lin_alloc(lin *a, size_t size);
void lin_freeAll(lin *a);

#endif