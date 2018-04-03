#include "hns-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace hns {
namespace test {

TEST_F(LibraryTest, ParseOpenpgpkeyReplyOK) {
  std::string key_hex("7037807198c22a7d2b0807371d763779a84fdfcf");

  DNSPacket pkt;

  pkt.set_qid(0x1234)
    .set_response()
    .set_rd()
    .set_ra()
    .set_ad()
    .add_question(new DNSQuestion("example.com", ns_t_openpgpkey))
    .add_answer(new DNSOpenpgpkeyRR("example.com", 1500, key_hex));

  std::vector<byte> data = pkt.data();

  struct hns_openpgpkey_reply *openpgpkey = nullptr;

  EXPECT_EQ(HNS_SUCCESS,
    hns_parse_openpgpkey_reply(data.data(), data.size(), &openpgpkey));
  ASSERT_NE(nullptr, openpgpkey);

  ASSERT_NE(openpgpkey->pubkey, nullptr);
  ASSERT_EQ(openpgpkey->pubkey_len, 20);

  size_t len = key_hex.length();
  std::vector<uint8_t> key;

  for (size_t i = 0; i < len; i += 2) {
    std::string byte = key_hex.substr(i, 2);
    unsigned char chr = (unsigned char)strtol(byte.c_str(), nullptr, 16);
    key.push_back(chr);
  }

  ASSERT_EQ(memcmp(openpgpkey->pubkey, key.data(), 20), 0);

  hns_free_data(openpgpkey);
}

}  // namespace test
}  // namespace hns
