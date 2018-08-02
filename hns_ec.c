#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"

#include "hns_ec.h"

hns_ec_t *
hns_ec_alloc(void) {
  return hns_secp256k1_context_create(HNS_SECP256K1_CONTEXT_VERIFY);
}

hns_ec_t *
hns_ec_clone(hns_ec_t *ec) {
  assert(ec);
  return hns_secp256k1_context_clone(ec);
}

void
hns_ec_free(hns_ec_t *ec) {
  assert(ec);
  hns_secp256k1_context_destroy(ec);
}

int
hns_ec_randomize(hns_ec_t *ec, const unsigned char *seed) {
  assert(ec && seed);
  return hns_secp256k1_context_randomize(ec, seed) != 0;
}

int
hns_ec_verify_pubkey(hns_ec_t *ec, const unsigned char *key) {
  assert(ec && key);
  hns_secp256k1_pubkey pub;
  return hns_secp256k1_ec_pubkey_parse(ec, &pub, key, 33) != 0;
}

int
hns_ec_verify_msg(
  hns_ec_t *ec,
  const unsigned char *pubkey,
  const unsigned char *msg,
  const unsigned char *sig
) {
  assert(ec && pubkey && msg && sig);

  hns_secp256k1_ecdsa_signature s;

  if (!hns_secp256k1_ecdsa_signature_parse_compact(ec, &s, sig))
    return 0;

  hns_secp256k1_pubkey pub;

  if (!hns_secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return 0;

  if (!hns_secp256k1_ecdsa_verify(ec, &s, msg, &pub))
    return 0;

  return 1;
}
