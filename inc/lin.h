#ifndef LIN_H_
#define LIN_H_

/* Linear Allocator */

#include "stddef.h"

/*
*  Every allocation size is aligned at 2^(LIN_ALIGNMENT_POW) bytes
*/
#ifndef LIN_ALIGNMENT_POW
#define LIN_ALIGNMENT_POW 0
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