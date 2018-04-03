#include "hns-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace hns {
namespace test {

TEST_F(LibraryTest, ParseSshfpReplyOK) {
  std::string fp_hex("7037807198c22a7d2b0807371d763779a84fdfcf");

  DNSPacket pkt;

  pkt.set_qid(0x1234)
    .set_response()
    .set_rd()
    .set_ra()
    .set_ad()
    .add_question(new DNSQuestion("example.com", ns_t_sshfp))
    .add_answer(new DNSSshfpRR("example.com", 1500, 1, 1, fp_hex));

  std::vector<byte> data = pkt.data();

  struct hns_sshfp_reply *sshfp = nullptr;
  EXPECT_EQ(HNS_SUCCESS,
    hns_parse_sshfp_reply(data.data(), data.size(), &sshfp));
  ASSERT_NE(nullptr, sshfp);

  ASSERT_EQ(sshfp->algorithm, 1);
  ASSERT_EQ(sshfp->digest_type, 1);
  ASSERT_NE(sshfp->fingerprint, nullptr);

  std::string key_hex(
    "010203"
  );

  size_t len = key_hex.length();
  std::vector<uint8_t> key;

  for (size_t i = 0; i < len; i += 2) {
    std::string byte = key_hex.substr(i, 2);
    unsigned char chr = (unsigned char)strtol(byte.c_str(), nullptr, 16);
    key.push_back(chr);
  }

  ASSERT_EQ(hns_sshfp_verify(sshfp, key.data(), key.size()), 1);

  hns_free_data(sshfp);
}

}  // namespace test
}  // namespace hns
