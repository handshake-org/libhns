#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"

#include "ares_ec.h"

ares_ec_t *
ares_ec_alloc(void) {
  return ares_secp256k1_context_create(ARES_SECP256K1_CONTEXT_VERIFY);
}

ares_ec_t *
ares_ec_clone(ares_ec_t *ec) {
  assert(ec);
  return ares_secp256k1_context_clone(ec);
}

void
ares_ec_free(ares_ec_t *ec) {
  assert(ec);
  ares_secp256k1_context_destroy(ec);
}

int
ares_ec_randomize(ares_ec_t *ec, unsigned char *seed) {
  assert(ec && seed);
  return ares_secp256k1_context_randomize(ec, seed) != 0;
}

int
ares_ec_verify_pubkey(ares_ec_t *ec, unsigned char *key) {
  assert(ec && key);
  ares_secp256k1_pubkey pub;
  return ares_secp256k1_ec_pubkey_parse(ec, &pub, key, 33) != 0;
}

int
ares_ec_verify_msg(
  ares_ec_t *ec,
  unsigned char *pubkey,
  unsigned char *msg,
  unsigned char *sig
) {
  assert(ec && pubkey && msg && sig);

  ares_secp256k1_ecdsa_signature s;

  if (!ares_secp256k1_ecdsa_signature_parse_compact(ec, &s, sig))
    return 0;

  ares_secp256k1_pubkey pub;

  if (!ares_secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return 0;

  if (!ares_secp256k1_ecdsa_verify(ec, &s, msg, &pub))
    return 0;

  return 1;
}
