#include "lin.h"

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

void lin_init(lin *a, void *buffer, size_t buf_size) {

    check(a);
    a->used_size = 0;
    a->buf_size = buf_size;
    a->buffer = buffer;
}

void *lin_alloc(lin *a, size_t size) {

    check(a);
    size_t offset = -size & ALIGNMENT_MASK_;
    size_t aligned_size = size + offset;    
    size_t old_used_size = a->used_size;
    char enough_space = (a->buf_size - old_used_size) >= aligned_size;

    print_debug("*** lin_alloc *** \n  size = %ld, aligned_size = %ld\n",
                size, aligned_size);
    check((aligned_size % ALIGNMENT_) == 0);

    switch (enough_space)
    {
    case 0:
        print_debug("  Insufficient space for allocation\n");
        return NULL;
    default:
        a->used_size += aligned_size;
        print_debug("  Allocating memory: old_used_size: %ld, new_used_size: %ld, "
                    "buf_size: %ld \n", old_used_size, a->used_size, a->buf_size);
        return ((char *)(a->buffer) + old_used_size);
    }
}

void lin_freeAll(lin *a) {

    check(a);
    print_debug("*** lin_freeAll *** \n  old_used_size: %ld, new_used_size: 0\n",
                a->used_size);
    a->used_size = 0;
}