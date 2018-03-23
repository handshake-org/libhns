#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"

#include "ares_ec.h"

ares_ec_t *
ares_ec_alloc(void) {
  return secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

ares_ec_t *
ares_ec_clone(ares_ec_t *ec) {
  assert(ec);
  return secp256k1_context_clone(ec);
}

void
ares_ec_free(ares_ec_t *ec) {
  assert(ec);
  secp256k1_context_destroy(ec);
}

int
ares_ec_randomize(ares_ec_t *ec, unsigned char *seed) {
  assert(ec && seed);
  return secp256k1_context_randomize(ec, seed) != 0;
}

int
ares_ec_verify_privkey(ares_ec_t *ec, unsigned char *key) {
  assert(ec && key);
  return secp256k1_ec_seckey_verify(ec, key) != 0;
}

int
ares_ec_verify_pubkey(ares_ec_t *ec, unsigned char *key) {
  assert(ec && key);
  secp256k1_pubkey pub;
  return secp256k1_ec_pubkey_parse(ec, &pub, key, 33) != 0;
}

int
ares_ec_create_pubkey(
  ares_ec_t *ec,
  unsigned char *key,
  unsigned char *pubkey
) {
  assert(ec && key && pubkey);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_create(ec, &pub, key))
    return 0;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return 0;

  assert(len == 33);

  return 1;
}

int
ares_ec_sign_msg(
  ares_ec_t *ec,
  unsigned char *key,
  unsigned char *msg,
  unsigned char *sig,
  int *rec
) {
  assert(ec && key && sig);

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;

  secp256k1_ecdsa_recoverable_signature s;

  int result = secp256k1_ecdsa_sign_recoverable(
    ec,
    &s,
    msg,
    key,
    noncefn,
    NULL
  );

  if (result == 0)
    return 0;

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ec, sig, rec, &s);

  return 1;
}

int
ares_ec_verify_msg(
  ares_ec_t *ec,
  unsigned char *pubkey,
  unsigned char *msg,
  unsigned char *sig
) {
  assert(ec && pubkey && msg && sig);

  secp256k1_ecdsa_signature s;

  if (!secp256k1_ecdsa_signature_parse_compact(ec, &s, sig))
    return 0;

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return 0;

  if (!secp256k1_ecdsa_verify(ec, &s, msg, &pub))
    return 0;

  return 1;
}

int
ares_ec_recover(
  ares_ec_t *ec,
  unsigned char *msg,
  unsigned char *sig,
  int rec,
  unsigned char *pubkey
) {
  assert(ec && msg && sig && pubkey);

  secp256k1_ecdsa_recoverable_signature s;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ec, &s, sig, rec))
    return 0;

  secp256k1_pubkey pub;

  if (!secp256k1_ecdsa_recover(ec, &pub, &s, msg))
    return 0;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return 0;

  assert(len == 33);

  return 1;
}
