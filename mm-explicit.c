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

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}


static size_t get_size_from_hf(size_t *hf) {
    return *hf & ~1;
}

static size_t get_allocated_from_hf(size_t *hf) {
    return *hf & 1;
}


static block_t *get_block_from_hf(size_t *hf, block_t *start) {
    return (block_t *)((void*)start - get_size_from_hf(hf));
}
typedef struct {
    size_t header;
    block_t *next;
    block_t *prev;
} free_block_t;

static free_block_t *head = NULL;
static free_block_t *tail = NULL;

/** Set's a block's header with the given size and allocation state */
/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    // Calculate the address of the footer and set its value
    size_t *footer = (size_t *) ((void *) block + size - sizeof(size_t));
    // fprintf(stderr, "%p\n", block);
    // fprintf(stderr, "%zu\n", size);
    *footer = size | is_allocated;
}

free_block_t *free_init(block_t *block, size_t size) {
    free_block_t *freed = (free_block_t *) block;
    freed->next = NULL;
    freed->prev = NULL;
    set_header(block, size, false);
    return freed;
}

size_t len_free() {
    free_block_t *start = head;
    size_t lennn = 0;
    if (head != NULL) {
        lennn += 1;
        free_block_t *next = (free_block_t *) start->next;
        if (next != NULL) {
            while (next != NULL) {
                lennn += 1;
                next = (free_block_t *) ((free_block_t *) (next))->next;
            }
            return lennn;
        }
        else {
            return 1;
        }
    }
    return 0;
}

void static add_free(free_block_t *block) {
    /*
    fprintf(stderr, "%s\n", "add"); 
    fprintf(stderr, "%d\n", add_count);
    */
    assert(block != NULL);
    if (head == NULL) {
        head = block;
        tail = block;
        // because it's the head
        block->next = NULL;
        block->prev = NULL;
    }
    else {
        block_t *old_head = (block_t *) head;
        head->prev = (block_t *) block;
        block->next = old_head;
        block->prev = NULL;
        head = block;
    }
}

block_t *remove_free(free_block_t *block) {
    //size_t curr_len = len_free();
    block_t *curr = (block_t *) block;
    if (head == tail){
        head = NULL;
        tail = NULL;
    }
    else if (block == head) {
        head = (free_block_t *) block->next;
        // for a one item list, only consisting of the head
        if (head != NULL) {
            head->prev = NULL;
        }
    }
    else if (block == tail) {
        tail = (free_block_t *) block->prev;
        if (tail != NULL) {
            tail->next = NULL;
        }
    }
    else {
        free_block_t *prev = (free_block_t *) block->prev;
        free_block_t *nxt = (free_block_t *) block->next;
        if (prev != NULL) {
            prev->next = (block_t *) nxt;
        }
        if (nxt != NULL) {
            nxt->prev = (block_t *) prev;
        }
    }
    return curr;
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    if (head == NULL) {
        return NULL;
    }
    free_block_t *next = (free_block_t *) head;
    while (next != NULL) {
        if (get_size((block_t *) next) >= size) {
            return (block_t *) next;
        }
        next = (free_block_t *) ((free_block_t *) (next))->next;
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
    head = NULL;
    tail = NULL;
    return true;
}

/*
void new_coalesce() {
    if (mm_heap_last != NULL) {
        for (block_t *curr = mm_heap_last; curr > mm_heap_first;
            curr = (void *) curr - get_size(curr)) {
            size_t curr_size = get_size(curr);
            size_t *prev_footer = (size_t *) ((uint8_t *) curr - sizeof(size_t));
            if ((*prev_footer & 1) == true) {
                remove_free((free_block_t *)prev_footer);
                size_t total_size = curr_size + (*prev_footer & ~1);
                free_block_t *free_new = free_init(curr, total_size + sizeof(size_t));
                add_free(free_new);
                if (curr == mm_heap_first) {
                    block_t *prev = (block_t *)()
                    mm_heap_last = prev;
                }
                curr = prev;
            }
        }
    }
}
*/

block_t *new_coalesce_left(block_t *freed) {
    if (freed != mm_heap_first) {
        size_t *left_footer = (size_t *)((void *)freed - sizeof(size_t));
        block_t *left = get_block_from_hf(left_footer, freed);
        if ((left != NULL) && (!get_allocated_from_hf(left_footer))) {
            size_t total_size = get_size_from_hf(left_footer) + get_size(freed);
            remove_free((free_block_t *)freed);
            set_header(left, total_size, false);
            if (freed == mm_heap_last) {
                mm_heap_last = left;
            }
            return left;

        }
        else { 
            return freed;
        }
    }
    else {
        return freed;
    }
}

void new_coalesce_right(block_t *freed) {
    if (freed != mm_heap_last) {
        size_t *right_header = (size_t *)((void *) freed + get_size(freed));
        block_t *right = (block_t *)right_header;
        if ((right != NULL) && (!(is_allocated(right)))) {
            size_t total_size = get_size(right) + get_size(freed); // space for two footers
            remove_free((free_block_t *)right);
            set_header(freed, total_size, false);
            if (mm_heap_last == right) {
                mm_heap_last = freed;
            }
        }
    }
    else {
        return;
    }
}

/*
block_t *new_coalesce_left(block_t *freed) {
    if (freed != mm_heap_first) {
        size_t *left_footer = (size_t *) ((size_t *) freed - sizeof(size_t));
        block_t *left = (block_t *) ((void *) (freed - (*left_footer & ~1) - sizeof(size_t)));
        if ((left != NULL) && (*left_footer & 1) == false) {
            remove_free((free_block_t *) freed);
            size_t total_size = (*left_footer & ~1) + get_size(freed);
            free_block_t *free_new = free_init(left, total_size);
            remove_free((free_block_t *) left);
            add_free(free_new);
            if (freed == mm_heap_last) {
                mm_heap_last = left;
            }
            freed = (block_t *) free_new;
            return freed;
        }
        else {
            return NULL;
        }
    }
    else {
        return NULL;
    }
}
*/

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    if (size < 16) {
        size = 16;
    }
    size = round_up((sizeof(block_t) + size + sizeof(size_t)), ALIGNMENT); // add size of footer, ALIGNMENT);
    
    block_t *block = find_fit(size);
    if (block != NULL) {
        
        size_t found_size = get_size(block);
        if ((found_size - size) >= (2 * ALIGNMENT)) {
            set_header(block, size, true);
            block_t *new = (block_t *) ((void *) block + size);
            free_block_t *new_freed = free_init(new, found_size - size);
            add_free(new_freed);
            remove_free((free_block_t *) block);
            if (mm_heap_last == block) {
                mm_heap_last = new;
            }
        }
        else {
            
            set_header(block, get_size(block), true);
            remove_free((free_block_t *) block);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

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
    // handles the setting of the footer
    size_t size = get_size(block);
    free_block_t *new_free = free_init(block, size);
    add_free(new_free);
    
    block_t *freed = new_coalesce_left((block_t *)new_free);
    new_coalesce_right(freed);
    
    
    
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
        size_t needed = old_size - (2 * header_size); // accounting for footer
        if (size < needed) {
            needed = size;
        }
        memcpy(new_ptr, old_ptr, needed);
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
    size_t len_free_1 = 0;
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        // 1. check if any block size is 0
        if ((get_size(curr) == 0)) {
            fprintf(stderr, "%s\n", "this block is as empty as my brain");
            exit(0);
        }
        // counting free blocks
        if (!is_allocated(curr)) {
            len_free_1 += 1;
        }
        // mm_heap_last is greater than every other block in heap
        if (mm_heap_last < curr) {
            fprintf(stderr, "%s\n",
                    "im higher than mm_heap_last...? what if i just die.");
            exit(0);
        }
    }
    size_t free_len = len_free();
    if (free_len != len_free_1) {
        if (free_len > len_free_1) {
            fprintf(stderr, "%s\n", "im explicit. i hold too much!!");
            exit(0);
        }

        else if (len_free_1 > free_len) {
            fprintf(stderr, "%s\n", "im explicit. gimme gimme more!!");
            exit(0);
        }
    }

    // all free blocks are in the list. count how many free blocks in heap then
    // every free block has next and prev
    //
}
