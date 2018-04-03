/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _HNS_SECP256K1_SCRATCH_
#define _HNS_SECP256K1_SCRATCH_

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct hns_secp256k1_scratch_space_struct {
    void *data;
    size_t offset;
    size_t init_size;
    size_t max_size;
    const hns_secp256k1_callback* error_callback;
} hns_secp256k1_scratch;

static hns_secp256k1_scratch* hns_secp256k1_scratch_create(const hns_secp256k1_callback* error_callback, size_t init_size, size_t max_size);
static void hns_secp256k1_scratch_destroy(hns_secp256k1_scratch* scratch);

/** Returns the maximum allocation the scratch space will allow */
static size_t hns_secp256k1_scratch_max_allocation(const hns_secp256k1_scratch* scratch, size_t n_objects);

/** Attempts to allocate so that there are `n` available bytes. Returns 1 on success, 0 on failure */
static int hns_secp256k1_scratch_resize(hns_secp256k1_scratch* scratch, size_t n, size_t n_objects);

/** Returns a pointer into the scratch space or NULL if there is insufficient available space */
static void *hns_secp256k1_scratch_alloc(hns_secp256k1_scratch* scratch, size_t n);

/** Resets the returned pointer to the beginning of space */
static void hns_secp256k1_scratch_reset(hns_secp256k1_scratch* scratch);

#endif
