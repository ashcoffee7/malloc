#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the implicit list
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        // If the block is free and large enough for the allocation, return it
        if (!is_allocated(curr) && get_size(curr) >= size) {
            return curr;
        }
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    return true;
}

void coalesce() {
    if (mm_heap_first != NULL) {
        size_t total_size = get_size(mm_heap_first);
        for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr < mm_heap_last;
             curr = (void *) curr + get_size(curr)) {
            total_size = get_size(curr);
            block_t *next = (block_t *) ((void *) curr + get_size(curr));
            if ((next != NULL) && (curr != NULL)) {
                if ((!(is_allocated(curr))) && (!(is_allocated(next)))) {
                    total_size += get_size(next); // + sizeof(curr->header);
                    set_header(curr, total_size, false);
                }
            }
            if (next == mm_heap_last) {
                mm_heap_last = curr;
            }
        }
    }
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size, ALIGNMENT);
    coalesce();

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        size_t found_size = get_size(block);

        if ((found_size - size) >= ALIGNMENT) {
            // block_t *new = (void *)(get_size(block) - size);
            set_header(block, size, true);
            block_t *new = (block_t *) ((void *) block + size);
            set_header(new, found_size - size, false);

            if (mm_heap_last == block) {
                mm_heap_last = new;
            }
        }
        else {
            set_header(block, get_size(block), true);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;
    // Initialize the block with the allocated size
    set_header(block, size, true);

    // coalesce

    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header(block, get_size(block), false);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    else if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    else {
        block_t *old = block_from_payload(old_ptr);
        void *new_ptr = mm_malloc(size);
        block_t *new = block_from_payload(new_ptr);
        size_t old_size = get_size(old);
        size_t header_size = sizeof(new->header);
        size_t needed = old_size - header_size;
        if (size < needed) {
            needed = size;
        }
        memcpy(new->payload, old->payload, needed);
        mm_free(old_ptr);
        return new_ptr;
    }
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    if ((nmemb != 0) && (size != 0)) {
        size_t arr_size = nmemb * size;
        void *curr_ptr = mm_malloc(arr_size);
        // set mem to 0?
        memset(curr_ptr, 0, arr_size);
        return curr_ptr;
    }
    return NULL;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        if ((get_size(curr) == 0)) {
            fprintf(stderr, "%s\n", "this block is as empty as my brain");
            exit(0);
        }
    }
    // all free blocks are in the list. count how many free blocks in heap then
    // every free block has next and prev
    //
}
