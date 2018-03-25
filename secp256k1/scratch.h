/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _ARES_SECP256K1_SCRATCH_
#define _ARES_SECP256K1_SCRATCH_

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct ares_secp256k1_scratch_space_struct {
    void *data;
    size_t offset;
    size_t init_size;
    size_t max_size;
    const ares_secp256k1_callback* error_callback;
} ares_secp256k1_scratch;

static ares_secp256k1_scratch* ares_secp256k1_scratch_create(const ares_secp256k1_callback* error_callback, size_t init_size, size_t max_size);
static void ares_secp256k1_scratch_destroy(ares_secp256k1_scratch* scratch);

/** Returns the maximum allocation the scratch space will allow */
static size_t ares_secp256k1_scratch_max_allocation(const ares_secp256k1_scratch* scratch, size_t n_objects);

/** Attempts to allocate so that there are `n` available bytes. Returns 1 on success, 0 on failure */
static int ares_secp256k1_scratch_resize(ares_secp256k1_scratch* scratch, size_t n, size_t n_objects);

/** Returns a pointer into the scratch space or NULL if there is insufficient available space */
static void *ares_secp256k1_scratch_alloc(ares_secp256k1_scratch* scratch, size_t n);

/** Resets the returned pointer to the beginning of space */
static void ares_secp256k1_scratch_reset(ares_secp256k1_scratch* scratch);

#endif
