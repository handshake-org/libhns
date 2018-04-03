/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "secp256k1.h"

#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        ares_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

static void default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}

static const ares_secp256k1_callback default_illegal_callback = {
    default_illegal_callback_fn,
    NULL
};

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const ares_secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};


struct ares_secp256k1_context_struct {
    ares_secp256k1_ecmult_context ecmult_ctx;
    ares_secp256k1_ecmult_gen_context ecmult_gen_ctx;
    ares_secp256k1_callback illegal_callback;
    ares_secp256k1_callback error_callback;
};

ares_secp256k1_context* ares_secp256k1_context_create(unsigned int flags) {
    ares_secp256k1_context* ret = (ares_secp256k1_context*)checked_malloc(&default_error_callback, sizeof(ares_secp256k1_context));
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    if (EXPECT((flags & ARES_SECP256K1_FLAGS_TYPE_MASK) != ARES_SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            ares_secp256k1_callback_call(&ret->illegal_callback,
                                    "Invalid flags");
            free(ret);
            return NULL;
    }

    ares_secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    ares_secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    if (flags & ARES_SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        ares_secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &ret->error_callback);
    }
    if (flags & ARES_SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        ares_secp256k1_ecmult_context_build(&ret->ecmult_ctx, &ret->error_callback);
    }

    return ret;
}

ares_secp256k1_context* ares_secp256k1_context_clone(const ares_secp256k1_context* ctx) {
    ares_secp256k1_context* ret = (ares_secp256k1_context*)checked_malloc(&ctx->error_callback, sizeof(ares_secp256k1_context));
    ret->illegal_callback = ctx->illegal_callback;
    ret->error_callback = ctx->error_callback;
    ares_secp256k1_ecmult_context_clone(&ret->ecmult_ctx, &ctx->ecmult_ctx, &ctx->error_callback);
    ares_secp256k1_ecmult_gen_context_clone(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx, &ctx->error_callback);
    return ret;
}

void ares_secp256k1_context_destroy(ares_secp256k1_context* ctx) {
    if (ctx != NULL) {
        ares_secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        ares_secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);

        free(ctx);
    }
}

void ares_secp256k1_context_set_illegal_callback(ares_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void ares_secp256k1_context_set_error_callback(ares_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

ares_secp256k1_scratch_space* ares_secp256k1_scratch_space_create(const ares_secp256k1_context* ctx, size_t init_size, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(max_size >= init_size);

    return ares_secp256k1_scratch_create(&ctx->error_callback, init_size, max_size);
}

void ares_secp256k1_scratch_space_destroy(ares_secp256k1_scratch_space* scratch) {
    ares_secp256k1_scratch_destroy(scratch);
}

static int ares_secp256k1_pubkey_load(const ares_secp256k1_context* ctx, ares_secp256k1_ge* ge, const ares_secp256k1_pubkey* pubkey) {
    if (sizeof(ares_secp256k1_ge_storage) == 64) {
        /* When the ares_secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside ares_secp256k1_pubkey, as conversion is very fast.
         * Note that ares_secp256k1_pubkey_save must use the same representation. */
        ares_secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        ares_secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        ares_secp256k1_fe x, y;
        ares_secp256k1_fe_set_b32(&x, pubkey->data);
        ares_secp256k1_fe_set_b32(&y, pubkey->data + 32);
        ares_secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!ares_secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void ares_secp256k1_pubkey_save(ares_secp256k1_pubkey* pubkey, ares_secp256k1_ge* ge) {
    if (sizeof(ares_secp256k1_ge_storage) == 64) {
        ares_secp256k1_ge_storage s;
        ares_secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!ares_secp256k1_ge_is_infinity(ge));
        ares_secp256k1_fe_normalize_var(&ge->x);
        ares_secp256k1_fe_normalize_var(&ge->y);
        ares_secp256k1_fe_get_b32(pubkey->data, &ge->x);
        ares_secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int ares_secp256k1_ec_pubkey_parse(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    ares_secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!ares_secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    ares_secp256k1_pubkey_save(pubkey, &Q);
    ares_secp256k1_ge_clear(&Q);
    return 1;
}

int ares_secp256k1_ec_pubkey_serialize(const ares_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const ares_secp256k1_pubkey* pubkey, unsigned int flags) {
    ares_secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & ARES_SECP256K1_FLAGS_BIT_COMPRESSION) ? 33 : 65));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & ARES_SECP256K1_FLAGS_TYPE_MASK) == ARES_SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (ares_secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = ares_secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & ARES_SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void ares_secp256k1_ecdsa_signature_load(const ares_secp256k1_context* ctx, ares_secp256k1_scalar* r, ares_secp256k1_scalar* s, const ares_secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(ares_secp256k1_scalar) == 32) {
        /* When the ares_secp256k1_scalar type is exactly 32 byte, use its
         * representation inside ares_secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that ares_secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        ares_secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        ares_secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void ares_secp256k1_ecdsa_signature_save(ares_secp256k1_ecdsa_signature* sig, const ares_secp256k1_scalar* r, const ares_secp256k1_scalar* s) {
    if (sizeof(ares_secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        ares_secp256k1_scalar_get_b32(&sig->data[0], r);
        ares_secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int ares_secp256k1_ecdsa_signature_parse_der(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    ares_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (ares_secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        ares_secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int ares_secp256k1_ecdsa_signature_parse_compact(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    ares_secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    ares_secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    ares_secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        ares_secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int ares_secp256k1_ecdsa_signature_serialize_der(const ares_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const ares_secp256k1_ecdsa_signature* sig) {
    ares_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    ares_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return ares_secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int ares_secp256k1_ecdsa_signature_serialize_compact(const ares_secp256k1_context* ctx, unsigned char *output64, const ares_secp256k1_ecdsa_signature* sig) {
    ares_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    ares_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    ares_secp256k1_scalar_get_b32(&output64[0], &r);
    ares_secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int ares_secp256k1_ecdsa_signature_normalize(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_signature *sigout, const ares_secp256k1_ecdsa_signature *sigin) {
    ares_secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    ares_secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = ares_secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            ares_secp256k1_scalar_negate(&s, &s);
        }
        ares_secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int ares_secp256k1_ecdsa_verify(const ares_secp256k1_context* ctx, const ares_secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const ares_secp256k1_pubkey *pubkey) {
    ares_secp256k1_ge q;
    ares_secp256k1_scalar r, s;
    ares_secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    ares_secp256k1_scalar_set_b32(&m, msg32, NULL);
    ares_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!ares_secp256k1_scalar_is_high(&s) &&
            ares_secp256k1_pubkey_load(ctx, &q, pubkey) &&
            ares_secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
}

static ARES_SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   ares_secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   ares_secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       ares_secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   ares_secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const ares_secp256k1_nonce_function ares_secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const ares_secp256k1_nonce_function ares_secp256k1_nonce_function_default = nonce_function_rfc6979;

int ares_secp256k1_ecdsa_sign(const ares_secp256k1_context* ctx, ares_secp256k1_ecdsa_signature *signature, const unsigned char *msg32, const unsigned char *seckey, ares_secp256k1_nonce_function noncefp, const void* noncedata) {
    ares_secp256k1_scalar r, s;
    ares_secp256k1_scalar sec, non, msg;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = ares_secp256k1_nonce_function_default;
    }

    ares_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !ares_secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        ares_secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            ares_secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !ares_secp256k1_scalar_is_zero(&non)) {
                if (ares_secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        ares_secp256k1_scalar_clear(&msg);
        ares_secp256k1_scalar_clear(&non);
        ares_secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        ares_secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int ares_secp256k1_ec_seckey_verify(const ares_secp256k1_context* ctx, const unsigned char *seckey) {
    ares_secp256k1_scalar sec;
    int ret;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ares_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !ares_secp256k1_scalar_is_zero(&sec);
    ares_secp256k1_scalar_clear(&sec);
    return ret;
}

int ares_secp256k1_ec_pubkey_create(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    ares_secp256k1_gej pj;
    ares_secp256k1_ge p;
    ares_secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(ares_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    ares_secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = (!overflow) & (!ares_secp256k1_scalar_is_zero(&sec));
    if (ret) {
        ares_secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &sec);
        ares_secp256k1_ge_set_gej(&p, &pj);
        ares_secp256k1_pubkey_save(pubkey, &p);
    }
    ares_secp256k1_scalar_clear(&sec);
    return ret;
}

int ares_secp256k1_ec_privkey_negate(const ares_secp256k1_context* ctx, unsigned char *seckey) {
    ares_secp256k1_scalar sec;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ares_secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ares_secp256k1_scalar_negate(&sec, &sec);
    ares_secp256k1_scalar_get_b32(seckey, &sec);

    return 1;
}

int ares_secp256k1_ec_pubkey_negate(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubkey) {
    int ret = 0;
    ares_secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = ares_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        ares_secp256k1_ge_neg(&p, &p);
        ares_secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}

int ares_secp256k1_ec_privkey_tweak_add(const ares_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    ares_secp256k1_scalar term;
    ares_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    ares_secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ares_secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && ares_secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        ares_secp256k1_scalar_get_b32(seckey, &sec);
    }

    ares_secp256k1_scalar_clear(&sec);
    ares_secp256k1_scalar_clear(&term);
    return ret;
}

int ares_secp256k1_ec_pubkey_tweak_add(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    ares_secp256k1_ge p;
    ares_secp256k1_scalar term;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    ares_secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = !overflow && ares_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (ares_secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &p, &term)) {
            ares_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int ares_secp256k1_ec_privkey_tweak_mul(const ares_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    ares_secp256k1_scalar factor;
    ares_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    ares_secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ares_secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ret = !overflow && ares_secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    memset(seckey, 0, 32);
    if (ret) {
        ares_secp256k1_scalar_get_b32(seckey, &sec);
    }

    ares_secp256k1_scalar_clear(&sec);
    ares_secp256k1_scalar_clear(&factor);
    return ret;
}

int ares_secp256k1_ec_pubkey_tweak_mul(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    ares_secp256k1_ge p;
    ares_secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    ares_secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ret = !overflow && ares_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (ares_secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            ares_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int ares_secp256k1_context_randomize(ares_secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(ares_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ares_secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    return 1;
}

int ares_secp256k1_ec_pubkey_combine(const ares_secp256k1_context* ctx, ares_secp256k1_pubkey *pubnonce, const ares_secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    ares_secp256k1_gej Qj;
    ares_secp256k1_ge Q;

    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    ares_secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        ares_secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        ares_secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (ares_secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    ares_secp256k1_ge_set_gej(&Q, &Qj);
    ares_secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}
