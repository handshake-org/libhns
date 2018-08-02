#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "hns_ec.h"
#include "hns_blake2b.h"
#include "hns_sig0.h"

static unsigned char
get_u8(const unsigned char *data) {
  return data[0];
}

static unsigned int
get_u16be(const unsigned char *data) {
  unsigned int out;
#ifdef HNS_BIG_ENDIAN
  memcpy(&out, data, 2);
#else
  out = 0;
  out |= ((unsigned int)data[0]) << 8;
  out |= (unsigned int)data[1];
#endif
  return out;
}

static unsigned long
get_u32be(const unsigned char *data) {
  unsigned long out;
#ifdef HNS_BIG_ENDIAN
  memcpy(&out, data, 4);
#else
  out = 0;
  out |= ((unsigned long)data[0]) << 24;
  out |= ((unsigned long)data[1]) << 16;
  out |= ((unsigned long)data[2]) << 8;
  out |= (unsigned long)data[3];
#endif
  return out;
}

static void
set_u8(unsigned char *data, unsigned char out) {
  data[0] = out;
}

static void
set_u16be(unsigned char *data, unsigned int out) {
#ifdef HNS_BIG_ENDIAN
  memcpy(data, &out, 2);
#else
  data[1] = (unsigned char)out;
  data[0] = (unsigned char)(out >> 8);
#endif
}

static void
set_u32be(unsigned char *data, unsigned long out) {
#ifdef HNS_BIG_ENDIAN
  memcpy(data, &out, 4);
#else
  data[3] = (unsigned char)out;
  data[2] = (unsigned char)(out >> 8);
  data[1] = (unsigned char)(out >> 16);
  data[0] = (unsigned char)(out >> 24);
#endif
}

int
hns_sig0_has_sig(const unsigned char *wire, size_t wire_len) {
  if (wire_len < HNS_SIG0_RR_SIZE + 12)
    return 0;

  unsigned int arcount = get_u16be(&wire[10]);

  if (arcount < 1)
    return 0;

  const unsigned char *rr = &wire[wire_len - HNS_SIG0_RR_SIZE];

  // Name should be `.`.
  if (rr[0] != 0)
    return 0;

  unsigned int type = get_u16be(&rr[1]);
  unsigned int class = get_u16be(&rr[3]);
  unsigned long ttl = get_u32be(&rr[5]);
  unsigned int size = get_u16be(&rr[9]);
  const unsigned char *rd = &rr[11];

  // Type
  if (type != HNS_SIG0_TYPE)
    return 0;

  // Class (ANY)
  if (class != HNS_SIG0_CLASS)
    return 0;

  // TTL
  if (ttl != 0)
    return 0;

  // RD size
  if (size != HNS_SIG0_RD_SIZE)
    return 0;

  unsigned int type_covered = get_u16be(&rd[0]);

  // Must be SIG(0).
  if (type_covered != HNS_SIG0_ZERO)
    return 0;

  return 1;
}

int
hns_sig0_get_sig(
  const unsigned char *wire,
  size_t wire_len,
  unsigned char *sig,
  unsigned int *tag
) {
  if (!hns_sig0_has_sig(wire, wire_len))
    return 0;

  const unsigned char *rr = &wire[wire_len - HNS_SIG0_RR_SIZE];
  const unsigned char *rd = &rr[11];

  unsigned int type_covered = get_u16be(&rd[0]);
  unsigned char algorithm = get_u8(&rd[2]);
  unsigned char labels = get_u8(&rd[3]);
  unsigned long orig_ttl = get_u32be(&rd[4]);
  unsigned long expiration = get_u32be(&rd[8]);
  unsigned long inception = get_u32be(&rd[12]);
  unsigned int key_tag = get_u16be(&rd[16]);
  unsigned int signer_name = get_u8(&rd[18]);

  // Must be SIG(0).
  if (type_covered != HNS_SIG0_ZERO)
    return 0;

  // Must be PRIVATEDNS.
  if (algorithm != HNS_SIG0_ALG)
    return 0;

  // Unused.
  if (labels != 0 || orig_ttl != 0)
    return 0;

  // Must be `.`.
  if (signer_name != 0)
    return 0;

  // Must match time.
#if 0
  unsigned long now = (unsigned long)hns_now();

  if (now < inception)
    return 0;

  if (now > expiration)
    return 0;
#endif

  // Copy sig.
  if (sig)
    memcpy(sig, &rd[19], 64);

  // Copy key tag.
  if (tag)
    *tag = key_tag;

  return 1;
}

int
hns_sig0_sighash(
  const unsigned char *wire,
  size_t wire_len,
  unsigned char *hash
) {
  if (!hns_sig0_has_sig(wire, wire_len))
    return 0;

  unsigned int arcount = get_u16be(&wire[10]);
  const unsigned char *rr = &wire[wire_len - HNS_SIG0_RR_SIZE];
  const unsigned char *rd = &rr[11];

  // Decrement arcount.
  unsigned char count[2];
  set_u16be(&count[0], arcount - 1);

  hns_blake2b_ctx ctx;
  assert(hns_blake2b_init(&ctx, 32) == 0);

  // SIG rdata (without signature bytes).
  hns_blake2b_update(&ctx, &rd[0], 19);

  // Message header with decremented arcount.
  hns_blake2b_update(&ctx, &wire[0], 10);
  hns_blake2b_update(&ctx, &count[0], 2);

  // Message body, stopping just before SIG record.
  hns_blake2b_update(&ctx, &wire[12], wire_len - 12 - HNS_SIG0_RR_SIZE);

  assert(hns_blake2b_final(&ctx, hash, 32) == 0);

  return 1;
}

int
hns_sig0_verify(
  hns_ec_t *ec,
  const unsigned char *pubkey,
  const unsigned char *wire,
  size_t wire_len
) {
  unsigned char sig[64];
  unsigned int tag;

  if (!hns_sig0_get_sig(wire, wire_len, sig, &tag))
    return 0;

  unsigned char hash[32];
  assert(hns_sig0_sighash(wire, wire_len, hash));

  return hns_ec_verify_msg(ec, pubkey, hash, sig);
}
