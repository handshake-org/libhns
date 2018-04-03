#include "hns-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

using testing::InvokeWithoutArgs;
using testing::DoAll;

namespace hns {
namespace test {

TEST_P(MockChannelTest, Basic) {
  std::vector<byte> reply = {
    0x00, 0x00,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // 1 question
    0x00, 0x01,  // 1 answer RRs
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x01, 0x00,  // TTL
    0x00, 0x04,  // rdata length
    0x01, 0x02, 0x03, 0x04
  };

  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReplyData(&server_, reply));

  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

// UDP only so mock server doesn't get confused by concatenated requests
TEST_P(MockUDPChannelTest, ParallelLookups) {
  DNSPacket rsp1;
  rsp1.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp1));
  DNSPacket rsp2;
  rsp2.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", ns_t_a))
    .add_answer(new DNSARR("www.example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("www.example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp2));

  HostResult result1;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result1);
  HostResult result2;
  hns_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result2);
  HostResult result3;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result3);
  Process();
  EXPECT_TRUE(result1.done_);
  EXPECT_TRUE(result2.done_);
  EXPECT_TRUE(result3.done_);
  std::stringstream ss1;
  ss1 << result1.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss1.str());
  std::stringstream ss2;
  ss2 << result2.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[1.2.3.4]}", ss2.str());
  std::stringstream ss3;
  ss3 << result3.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss3.str());
}

// UDP to TCP specific test
TEST_P(MockUDPChannelTest, TruncationRetry) {
  DNSPacket rsptruncated;
  rsptruncated.set_response().set_aa().set_tc()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  DNSPacket rspok;
  rspok.set_response()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {1, 2, 3, 4}));
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsptruncated))
    .WillOnce(SetReply(&server_, &rspok));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

static int sock_cb_count = 0;
static int SocketConnectCallback(hns_socket_t fd, int type, void *data) {
  int rc = *(int*)data;
  if (verbose) std::cerr << "SocketConnectCallback(" << fd << ") invoked" << std::endl;
  sock_cb_count++;
  return rc;
}

TEST_P(MockChannelTest, SockCallback) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));

  // Get notified of new sockets
  int rc = HNS_SUCCESS;
  hns_set_socket_callback(channel_, SocketConnectCallback, &rc);

  HostResult result;
  sock_cb_count = 0;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_EQ(1, sock_cb_count);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SockFailCallback) {
  // Notification of new sockets gives an error.
  int rc = -1;
  hns_set_socket_callback(channel_, SocketConnectCallback, &rc);

  HostResult result;
  sock_cb_count = 0;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_LT(1, sock_cb_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ECONNREFUSED, result.status_);
}

static int sock_config_cb_count = 0;
static int SocketConfigureCallback(hns_socket_t fd, int type, void *data) {
  int rc = *(int*)data;
  if (verbose) std::cerr << "SocketConfigureCallback(" << fd << ") invoked" << std::endl;
  sock_config_cb_count++;
  return rc;
}

TEST_P(MockChannelTest, SockConfigureCallback) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));

  // Get notified of new sockets
  int rc = HNS_SUCCESS;
  hns_set_socket_configure_callback(channel_, SocketConfigureCallback, &rc);

  HostResult result;
  sock_config_cb_count = 0;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_EQ(1, sock_config_cb_count);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SockConfigureFailCallback) {
  // Notification of new sockets gives an error.
  int rc = -1;
  hns_set_socket_configure_callback(channel_, SocketConfigureCallback, &rc);

  HostResult result;
  sock_config_cb_count = 0;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_LT(1, sock_config_cb_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ECONNREFUSED, result.status_);
}

// TCP only to prevent retries
TEST_P(MockTCPChannelTest, MalformedResponse) {
  std::vector<byte> one = {0x01};
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, one));

  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ETIMEOUT, result.status_);
}

TEST_P(MockTCPChannelTest, FormErrResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_formerr);
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_EFORMERR, result.status_);
}

TEST_P(MockTCPChannelTest, ServFailResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_servfail);
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  // HNS_FLAG_NOCHECKRESP not set, so SERVFAIL consumed
  EXPECT_EQ(HNS_ECONNREFUSED, result.status_);
}

TEST_P(MockTCPChannelTest, NotImplResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_notimpl);
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  // HNS_FLAG_NOCHECKRESP not set, so NOTIMPL consumed
  EXPECT_EQ(HNS_ECONNREFUSED, result.status_);
}

TEST_P(MockTCPChannelTest, RefusedResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_refused);
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  // HNS_FLAG_NOCHECKRESP not set, so REFUSED consumed
  EXPECT_EQ(HNS_ECONNREFUSED, result.status_);
}

TEST_P(MockTCPChannelTest, YXDomainResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_yxdomain);
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ENODATA, result.status_);
}

class MockExtraOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockExtraOptsTest()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second,
                          FillOptions(&opts_),
                          HNS_OPT_SOCK_SNDBUF|HNS_OPT_SOCK_RCVBUF) {}
  static struct hns_options* FillOptions(struct hns_options * opts) {
    memset(opts, 0, sizeof(struct hns_options));
    // Set a few options that affect socket communications
    opts->socket_send_buffer_size = 514;
    opts->socket_receive_buffer_size = 514;
    return opts;
  }
 private:
  struct hns_options opts_;
};

TEST_P(MockExtraOptsTest, SimpleQuery) {
  hns_set_local_ip4(channel_, 0x7F000001);
  byte addr6[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  hns_set_local_ip6(channel_, addr6);
  hns_set_local_dev(channel_, "dummy");

  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));

  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

class MockFlagsChannelOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockFlagsChannelOptsTest(int flags)
    : MockChannelOptsTest(1, GetParam().first, GetParam().second,
                          FillOptions(&opts_, flags), HNS_OPT_FLAGS) {}
  static struct hns_options* FillOptions(struct hns_options * opts, int flags) {
    memset(opts, 0, sizeof(struct hns_options));
    opts->flags = flags;
    return opts;
  }
 private:
  struct hns_options opts_;
};

class MockNoCheckRespChannelTest : public MockFlagsChannelOptsTest {
 public:
  MockNoCheckRespChannelTest() : MockFlagsChannelOptsTest(HNS_FLAG_NOCHECKRESP) {}
};

TEST_P(MockNoCheckRespChannelTest, ServFailResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_servfail);
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ESERVFAIL, result.status_);
}

TEST_P(MockNoCheckRespChannelTest, NotImplResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_notimpl);
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ENOTIMP, result.status_);
}

TEST_P(MockNoCheckRespChannelTest, RefusedResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  rsp.set_rcode(ns_r_refused);
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_EREFUSED, result.status_);
}

class MockEDNSChannelTest : public MockFlagsChannelOptsTest {
 public:
  MockEDNSChannelTest() : MockFlagsChannelOptsTest(HNS_FLAG_EDNS) {}
};

TEST_P(MockEDNSChannelTest, RetryWithoutEDNS) {
  DNSPacket rspfail;
  rspfail.set_response().set_aa().set_rcode(ns_r_servfail)
    .add_question(new DNSQuestion("www.google.com", ns_t_a));
  DNSPacket rspok;
  rspok.set_response()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 100, {1, 2, 3, 4}));
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReply(&server_, &rspfail))
    .WillOnce(SetReply(&server_, &rspok));
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomains) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesthird));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, SearchDomainsWithResentReply) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  EXPECT_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  // Before sending the real answer, resend an earlier reply
  EXPECT_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillOnce(DoAll(SetReply(&server_, &nofirst),
                    SetReplyQID(&server_, 123)))
    .WillOnce(DoAll(SetReply(&server_, &yesthird),
                    SetReplyQID(&server_, -1)));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomainsBare) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket yesbare;
  yesbare.set_response().set_aa()
    .add_question(new DNSQuestion("www", ns_t_a))
    .add_answer(new DNSARR("www", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesbare));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenSuccess) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesthird));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenNoDataBare) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket nobare;
  nobare.set_response().set_aa()
    .add_question(new DNSQuestion("www", ns_t_a));
  ON_CALL(server_, OnRequest("www", ns_t_a))
    .WillByDefault(SetReply(&server_, &nobare));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ENODATA, result.status_);
}

TEST_P(MockChannelTest, SearchNoDataThenFail) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket nobare;
  nobare.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www", ns_t_a));
  ON_CALL(server_, OnRequest("www", ns_t_a))
    .WillByDefault(SetReply(&server_, &nobare));

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ENODATA, result.status_);
}

TEST_P(MockChannelTest, SearchAllocFailure) {
  SearchResult result;
  SetAllocFail(1);
  hns_search(channel_, "fully.qualified.", ns_c_in, ns_t_a, SearchCallback, &result);
  /* Already done */
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SearchHighNdots) {
  DNSPacket nobare;
  nobare.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("a.b.c.w.w.w", ns_t_a));
  ON_CALL(server_, OnRequest("a.b.c.w.w.w", ns_t_a))
    .WillByDefault(SetReply(&server_, &nobare));
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("a.b.c.w.w.w.first.com", ns_t_a))
    .add_answer(new DNSARR("a.b.c.w.w.w.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("a.b.c.w.w.w.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesfirst));

  SearchResult result;
  hns_search(channel_, "a.b.c.w.w.w", ns_c_in, ns_t_a, SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_SUCCESS, result.status_);
  std::stringstream ss;
  ss << PacketToString(result.data_);
  EXPECT_EQ("RSP QRY AA NOERROR Q:{'a.b.c.w.w.w.first.com' IN A} "
            "A:{'a.b.c.w.w.w.first.com' IN A TTL=512 2.3.4.5}",
            ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyV6) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));

  HostResult result;
  hns_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  // Default to IPv6 when both are available.
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyV4) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  hns_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyNoData) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSCnameRR("example.com", 100, "elsewhere.com"));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  hns_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'' aliases=[] addrs=[]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyCname6A4) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSCnameRR("example.com", 100, "elsewhere.com"));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  hns_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'example.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIP) {
  HostResult result;
  hns_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(HNS_SUCCESS, result.status_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'1.2.3.4' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIPAllocFail) {
  HostResult result;
  SetAllocSizeFail(strlen("1.2.3.4") + 1);
  hns_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(HNS_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SortListV4) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {22, 23, 24, 25}))
    .add_answer(new DNSARR("example.com", 100, {12, 13, 14, 15}))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "12.13.0.0/255.255.0.0 1234::5678"));
    HostResult result;
    hns_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[12.13.14.15, 22.23.24.25, 2.3.4.5]}", ss.str());
  }
  {
    EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "2.3.0.0/16 130.140.150.160/26"));
    HostResult result;
    hns_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5, 22.23.24.25, 12.13.14.15]}", ss.str());
  }
  struct hns_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;
  EXPECT_EQ(HNS_SUCCESS, hns_save_options(channel_, &options, &optmask));
  EXPECT_TRUE((optmask & HNS_OPT_SORTLIST) == HNS_OPT_SORTLIST);
  hns_destroy_options(&options);
}

TEST_P(MockChannelTest, SortListV6) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_aaaa))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02}))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", ns_t_aaaa))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    hns_set_sortlist(channel_, "1111::/16 2.3.0.0/255.255.0.0");
    HostResult result;
    hns_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[1111:0000:0000:0000:0000:0000:0000:0202, "
              "2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
  }
  {
    hns_set_sortlist(channel_, "2121::/8");
    HostResult result;
    hns_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303, "
              "1111:0000:0000:0000:0000:0000:0000:0202]}", ss.str());
  }
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, SearchDomainsAllocFail) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.first.com", ns_t_a));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(ns_r_nxdomain)
    .add_question(new DNSQuestion("www.second.org", ns_t_a));
  ON_CALL(server_, OnRequest("www.second.org", ns_t_a))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", ns_t_a))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesthird));

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  HostResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    HostResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    hns_gethostbyname(channel_, "www", AF_INET, HostCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ == HNS_SUCCESS) {
      std::stringstream ss;
      ss << result->host_;
      EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }

  // Explicitly destroy the channel now, so that the HostResult objects
  // are still valid (in case any pending work refers to them).
  hns_destroy(channel_);
  channel_ = nullptr;
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, Resend) {
  std::vector<byte> nothing;
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReply(&server_, &reply));

  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(2, result.timeouts_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, CancelImmediate) {
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  hns_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, CancelImmediateGetHostByAddr) {
  HostResult result;
  struct in_addr addr;
  addr.s_addr = htonl(0x08080808);
  
  hns_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET, HostCallback, &result);
  hns_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, CancelLater) {
  std::vector<byte> nothing;

  // On second request, cancel the channel.
  EXPECT_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(CancelChannel(&server_, channel_));

  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameDestroyAbsolute) {
  HostResult result;
  hns_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);

  hns_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(HNS_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameDestroyRelative) {
  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);

  hns_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(HNS_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByAddrDestroy) {
  unsigned char gdns_addr4[4] = {0x08, 0x08, 0x08, 0x08};
  HostResult result;
  hns_gethostbyaddr(channel_, gdns_addr4, sizeof(gdns_addr4), AF_INET, HostCallback, &result);

  hns_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(HNS_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

#ifndef WIN32
TEST_P(MockChannelTest, HostAlias) {
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", ns_t_a))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));
  ON_CALL(server_, OnRequest("www.google.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &reply));

  TempFile aliases("\n\n# www commentedout\nwww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissing) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesfirst));

  TempFile aliases("\n\n# www commentedout\nww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());
  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissingFile) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", ns_t_a))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.first.com", ns_t_a))
    .WillByDefault(SetReply(&server_, &yesfirst));

  EnvValue with_env("HOSTALIASES", "bogus.mcfile");
  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasUnreadable) {
  TempFile aliases("www www.google.com\n");
  chmod(aliases.filename(), 0);
  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  hns_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(HNS_EFILE, result.status_);
  chmod(aliases.filename(), 0777);
}
#endif

class MockMultiServerChannelTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockMultiServerChannelTest(bool rotate)
    : MockChannelOptsTest(3, GetParam().first, GetParam().second, nullptr, rotate ? HNS_OPT_ROTATE : HNS_OPT_NOROTATE) {}
  void CheckExample() {
    HostResult result;
    hns_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  }
};

class RotateMultiMockTest : public MockMultiServerChannelTest {
 public:
  RotateMultiMockTest() : MockMultiServerChannelTest(true) {}
};

class NoRotateMultiMockTest : public MockMultiServerChannelTest {
 public:
  NoRotateMultiMockTest() : MockMultiServerChannelTest(false) {}
};


TEST_P(RotateMultiMockTest, ThirdServer) {
  struct hns_options opts = {0};
  int optmask = 0;
  EXPECT_EQ(HNS_SUCCESS, hns_save_options(channel_, &opts, &optmask));
  EXPECT_EQ(0, (optmask & HNS_OPT_NOROTATE));
  hns_destroy_options(&opts);

  DNSPacket servfailrsp;
  servfailrsp.set_response().set_aa().set_rcode(ns_r_servfail)
    .add_question(new DNSQuestion("www.example.com", ns_t_a));
  DNSPacket notimplrsp;
  notimplrsp.set_response().set_aa().set_rcode(ns_r_notimpl)
    .add_question(new DNSQuestion("www.example.com", ns_t_a));
  DNSPacket okrsp;
  okrsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", ns_t_a))
    .add_answer(new DNSARR("www.example.com", 100, {2,3,4,5}));

  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &okrsp));
  CheckExample();

  // Second time around, starts from server [1].
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &servfailrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &notimplrsp));
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));
  CheckExample();

  // Third time around, starts from server [2].
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &servfailrsp));
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &notimplrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  CheckExample();
}

TEST_P(NoRotateMultiMockTest, ThirdServer) {
  struct hns_options opts = {0};
  int optmask = 0;
  EXPECT_EQ(HNS_SUCCESS, hns_save_options(channel_, &opts, &optmask));
  EXPECT_EQ(HNS_OPT_NOROTATE, (optmask & HNS_OPT_NOROTATE));
  hns_destroy_options(&opts);

  DNSPacket servfailrsp;
  servfailrsp.set_response().set_aa().set_rcode(ns_r_servfail)
    .add_question(new DNSQuestion("www.example.com", ns_t_a));
  DNSPacket notimplrsp;
  notimplrsp.set_response().set_aa().set_rcode(ns_r_notimpl)
    .add_question(new DNSQuestion("www.example.com", ns_t_a));
  DNSPacket okrsp;
  okrsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", ns_t_a))
    .add_answer(new DNSARR("www.example.com", 100, {2,3,4,5}));

  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &okrsp));
  CheckExample();

  // Second time around, still starts from server [0].
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &okrsp));
  CheckExample();

  // Third time around, still starts from server [0].
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", ns_t_a))
    .WillOnce(SetReply(servers_[2].get(), &okrsp));
  CheckExample();
}

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockChannelTest, ::testing::ValuesIn(hns::test::families_modes));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockUDPChannelTest, ::testing::ValuesIn(hns::test::families));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockTCPChannelTest, ::testing::ValuesIn(hns::test::families));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockExtraOptsTest, ::testing::ValuesIn(hns::test::families_modes));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockNoCheckRespChannelTest, ::testing::ValuesIn(hns::test::families_modes));

INSTANTIATE_TEST_CASE_P(AddressFamilies, MockEDNSChannelTest, ::testing::ValuesIn(hns::test::families_modes));

INSTANTIATE_TEST_CASE_P(TransportModes, RotateMultiMockTest, ::testing::ValuesIn(hns::test::families_modes));

INSTANTIATE_TEST_CASE_P(TransportModes, NoRotateMultiMockTest, ::testing::ValuesIn(hns::test::families_modes));

}  // namespace test
}  // namespace hns
