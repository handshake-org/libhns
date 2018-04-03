#include "hns-test.h"

// library initialization is only needed for windows builds
#ifdef WIN32
#define EXPECTED_NONINIT HNS_ENOTINITIALIZED
#else
#define EXPECTED_NONINIT HNS_SUCCESS
#endif

namespace hns {
namespace test {

TEST(LibraryInit, Basic) {
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
  EXPECT_EQ(HNS_SUCCESS, hns_library_init(HNS_LIB_INIT_ALL));
  EXPECT_EQ(HNS_SUCCESS, hns_library_initialized());
  hns_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
}

TEST(LibraryInit, UnexpectedCleanup) {
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
  hns_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
}

TEST(LibraryInit, DISABLED_InvalidParam) {
  // TODO: police flags argument to hns_library_init()
  EXPECT_EQ(HNS_EBADQUERY, hns_library_init(HNS_LIB_INIT_ALL << 2));
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
  hns_library_cleanup();
}

TEST(LibraryInit, Nested) {
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
  EXPECT_EQ(HNS_SUCCESS, hns_library_init(HNS_LIB_INIT_ALL));
  EXPECT_EQ(HNS_SUCCESS, hns_library_initialized());
  EXPECT_EQ(HNS_SUCCESS, hns_library_init(HNS_LIB_INIT_ALL));
  EXPECT_EQ(HNS_SUCCESS, hns_library_initialized());
  hns_library_cleanup();
  EXPECT_EQ(HNS_SUCCESS, hns_library_initialized());
  hns_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, hns_library_initialized());
}

TEST(LibraryInit, BasicChannelInit) {
  EXPECT_EQ(HNS_SUCCESS, hns_library_init(HNS_LIB_INIT_ALL));
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  EXPECT_NE(nullptr, channel);
  hns_destroy(channel);
  hns_library_cleanup();
}

TEST_F(LibraryTest, OptionsChannelInit) {
  struct hns_options opts = {0};
  int optmask = 0;
  opts.flags = HNS_FLAG_USEVC | HNS_FLAG_PRIMARY;
  optmask |= HNS_OPT_FLAGS;
  opts.timeout = 2000;
  optmask |= HNS_OPT_TIMEOUTMS;
  opts.tries = 2;
  optmask |= HNS_OPT_TRIES;
  opts.ndots = 4;
  optmask |= HNS_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= HNS_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= HNS_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= HNS_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= HNS_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= HNS_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc(opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= HNS_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc(opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= HNS_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= HNS_OPT_LOOKUPS;
  optmask |= HNS_OPT_ROTATE;

  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  hns_channel channel2 = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_dup(&channel2, channel));

  struct hns_options opts2 = {0};
  int optmask2 = 0;
  EXPECT_EQ(HNS_SUCCESS, hns_save_options(channel2, &opts2, &optmask2));

  // Note that not all opts-settable fields are saved (e.g.
  // ednspsz, socket_{send,receive}_buffer_size).
  EXPECT_EQ(opts.flags, opts2.flags);
  EXPECT_EQ(opts.timeout, opts2.timeout);
  EXPECT_EQ(opts.tries, opts2.tries);
  EXPECT_EQ(opts.ndots, opts2.ndots);
  EXPECT_EQ(opts.udp_port, opts2.udp_port);
  EXPECT_EQ(opts.tcp_port, opts2.tcp_port);
  EXPECT_EQ(1, opts2.nservers);  // Truncated by HNS_FLAG_PRIMARY
  EXPECT_EQ(opts.servers[0].s_addr, opts2.servers[0].s_addr);
  EXPECT_EQ(opts.ndomains, opts2.ndomains);
  EXPECT_EQ(std::string(opts.domains[0]), std::string(opts2.domains[0]));
  EXPECT_EQ(std::string(opts.domains[1]), std::string(opts2.domains[1]));
  EXPECT_EQ(std::string(opts.lookups), std::string(opts2.lookups));

  hns_destroy_options(&opts);
  hns_destroy_options(&opts2);
  hns_destroy(channel);
  hns_destroy(channel2);
}

TEST_F(LibraryTest, ChannelAllocFail) {
  hns_channel channel;
  for (int ii = 1; ii <= 25; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = hns_init(&channel);
    // The number of allocations depends on local environment, so don't expect ENOMEM.
    if (rc == HNS_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      hns_destroy(channel);
    }
  }
}

TEST_F(LibraryTest, OptionsChannelAllocFail) {
  struct hns_options opts = {0};
  int optmask = 0;
  opts.flags = HNS_FLAG_USEVC;
  optmask |= HNS_OPT_FLAGS;
  opts.timeout = 2;
  optmask |= HNS_OPT_TIMEOUT;
  opts.tries = 2;
  optmask |= HNS_OPT_TRIES;
  opts.ndots = 4;
  optmask |= HNS_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= HNS_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= HNS_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= HNS_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= HNS_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= HNS_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc(opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= HNS_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc(opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= HNS_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= HNS_OPT_LOOKUPS;
  optmask |= HNS_OPT_ROTATE;

  hns_channel channel = nullptr;
  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    int rc = hns_init_options(&channel, &opts, optmask);
    if (rc == HNS_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      EXPECT_EQ(HNS_SUCCESS, rc);
      hns_destroy(channel);
      channel = nullptr;
    }
  }
  ClearFails();

  EXPECT_EQ(HNS_SUCCESS, hns_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  // Add some servers and a sortlist for flavour.
  EXPECT_EQ(HNS_SUCCESS,
            hns_set_servers_csv(channel, "1.2.3.4,0102:0304:0506:0708:0910:1112:1314:1516,2.3.4.5"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel, "1.2.3.4 2.3.4.5"));

  hns_channel channel2 = nullptr;
  for (int ii = 1; ii <= 18; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(HNS_ENOMEM, hns_dup(&channel2, channel)) << ii;
    EXPECT_EQ(nullptr, channel2) << ii;
  }

  struct hns_options opts2;
  int optmask2 = 0;
  for (int ii = 1; ii <= 6; ii++) {
    memset(&opts2, 0, sizeof(opts2));
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(HNS_ENOMEM, hns_save_options(channel, &opts2, &optmask2)) << ii;
    // May still have allocations even after HNS_ENOMEM return code.
    hns_destroy_options(&opts2);
  }
  hns_destroy_options(&opts);
  hns_destroy(channel);
}

TEST_F(LibraryTest, FailChannelInit) {
  EXPECT_EQ(HNS_SUCCESS,
            hns_library_init_mem(HNS_LIB_INIT_ALL,
                                  &LibraryTest::amalloc,
                                  &LibraryTest::afree,
                                  &LibraryTest::arealloc));
  SetAllocFail(1);
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_ENOMEM, hns_init(&channel));
  EXPECT_EQ(nullptr, channel);
  hns_library_cleanup();
}

#ifndef WIN32
TEST_F(LibraryTest, EnvInit) {
  hns_channel channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  hns_destroy(channel);
}

TEST_F(LibraryTest, EnvInitAllocFail) {
  hns_channel channel;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  for (int ii = 1; ii <= 10; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = hns_init(&channel);
    if (rc == HNS_SUCCESS) {
      hns_destroy(channel);
    } else {
      EXPECT_EQ(HNS_ENOMEM, rc);
    }
  }
}
#endif

TEST_F(DefaultChannelTest, SetAddresses) {
  hns_set_local_ip4(channel_, 0x01020304);
  byte addr6[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  hns_set_local_ip6(channel_, addr6);
  hns_set_local_dev(channel_, "dummy");
}

TEST_F(DefaultChannelTest, SetSortlistFailures) {
  EXPECT_EQ(HNS_ENODATA, hns_set_sortlist(nullptr, "1.2.3.4"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "xyzzy ; lwk"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "xyzzy ; 0x123"));
}

TEST_F(DefaultChannelTest, SetSortlistVariants) {
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "1.2.3.4"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "1.2.3.4 ; 2.3.4.5"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "129.1.1.1"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "192.1.1.1"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "224.1.1.1"));
  EXPECT_EQ(HNS_SUCCESS, hns_set_sortlist(channel_, "225.1.1.1"));
}

TEST_F(DefaultChannelTest, SetSortlistAllocFail) {
  for (int ii = 1; ii <= 3; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(HNS_ENOMEM, hns_set_sortlist(channel_, "12.13.0.0/16 1234::5678/40 1.2.3.4")) << ii;
  }
}

#ifdef USE_WINSOCK
TEST(Init, NoLibraryInit) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_ENOTINITIALIZED, hns_init(&channel));
}
#endif

#ifdef HAVE_CONTAINER
// These tests rely on the ability of non-root users to create a chroot
// using Linux namespaces.


// The library uses a variety of information sources to initialize a channel,
// in particular to determine:
//  - search: the search domains to use
//  - servers: the name servers to use
//  - lookup: whether to check files or DNS or both (e.g. "fb")
//  - options: various resolver options
//  - sortlist: the order of preference for IP addresses
//
// The first source from the following list is used:
//  - init_by_options(): explicitly specified values in struct hns_options
//  - init_by_environment(): values from the environment:
//     - LOCALDOMAIN -> search (single value)
//     - RES_OPTIONS -> options
//  - init_by_resolv_conf(): values from various config files:
//     - /etc/resolv.conf -> search, lookup, servers, sortlist, options
//     - /etc/nsswitch.conf -> lookup
//     - /etc/host.conf -> lookup
//     - /etc/svc.conf -> lookup
//  - init_by_defaults(): fallback values:
//     - gethostname(3) -> domain
//     - "fb" -> lookup

NameContentList filelist = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"
                       "search first.com second.com\n"},
  {"/etc/hosts", "3.4.5.6 hhostname.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerChannelInit,
                 "myhostname", "mydomainname.org", filelist) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  std::vector<std::string> actual = GetNameServers(channel);
  std::vector<std::string> expected = {"1.2.3.4"};
  EXPECT_EQ(expected, actual);

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(2, opts.ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(opts.domains[0]));
  EXPECT_EQ(std::string("second.com"), std::string(opts.domains[1]));
  hns_destroy_options(&opts);

  HostResult result;
  hns_gethostbyname(channel, "hhostname.com", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'hhostname.com' aliases=[] addrs=[3.4.5.6]}", ss.str());

  hns_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerSortlistOptionInit,
                 "myhostname", "mydomainname.org", filelist) {
  hns_channel channel = nullptr;
  struct hns_options opts = {0};
  int optmask = 0;
  optmask |= HNS_OPT_SORTLIST;
  opts.nsort = 0;
  // Explicitly specifying an empty sortlist in the options should override the
  // environment.
  EXPECT_EQ(HNS_SUCCESS, hns_init_options(&channel, &opts, optmask));
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(0, opts.nsort);
  EXPECT_EQ(nullptr, opts.sortlist);
  EXPECT_EQ(HNS_OPT_SORTLIST, (optmask & HNS_OPT_SORTLIST));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList fullresolv = {
  {"/etc/resolv.conf", " nameserver   1.2.3.4 \n"
                       "search   first.com second.com\n"
                       "lookup bind\n"
                       "options debug ndots:5\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerFullResolvInit,
                 "myhostname", "mydomainname.org", fullresolv) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(std::string("b"), std::string(opts.lookups));
  EXPECT_EQ(5, opts.ndots);
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList hostconf = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "sortlist1.2.3.4\n"  // malformed line
                       "search first.com second.com\n"},
  {"/etc/host.conf", "order bind hosts\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerHostConfInit,
                 "myhostname", "mydomainname.org", hostconf) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(std::string("bf"), std::string(opts.lookups));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList svcconf = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"},
  {"/etc/svc.conf", "hosts= bind\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSvcConfInit,
                 "myhostname", "mydomainname.org", svcconf) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(std::string("b"), std::string(opts.lookups));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

// Failures when expected config filenames are inaccessible.
class MakeUnreadable {
 public:
  explicit MakeUnreadable(const std::string& filename)
    : filename_(filename) {
    chmod(filename_.c_str(), 0000);
  }
  ~MakeUnreadable() { chmod(filename_.c_str(), 0644); }
 private:
  std::string filename_;
};

CONTAINED_TEST_F(LibraryTest, ContainerResolvConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  hns_channel channel = nullptr;
  MakeUnreadable hide("/etc/resolv.conf");
  // Unavailable /etc/resolv.conf falls back to defaults
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerNsswitchConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  hns_channel channel = nullptr;
  // Unavailable /etc/nsswitch.conf falls back to defaults.
  MakeUnreadable hide("/etc/nsswitch.conf");
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(std::string("fb"), std::string(opts.lookups));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerHostConfNotReadable,
                 "myhostname", "mydomainname.org", hostconf) {
  hns_channel channel = nullptr;
  // Unavailable /etc/host.conf falls back to defaults.
  MakeUnreadable hide("/etc/host.conf");
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  hns_destroy(channel);
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerSvcConfNotReadable,
                 "myhostname", "mydomainname.org", svcconf) {
  hns_channel channel = nullptr;
  // Unavailable /etc/svc.conf falls back to defaults.
  MakeUnreadable hide("/etc/svc.conf");
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  hns_destroy(channel);
  return HasFailure();
}

NameContentList rotateenv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"
                       "options rotate\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerRotateInit,
                 "myhostname", "mydomainname.org", rotateenv) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(HNS_OPT_ROTATE, (optmask & HNS_OPT_ROTATE));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerRotateOverride,
                 "myhostname", "mydomainname.org", rotateenv) {
  hns_channel channel = nullptr;
  struct hns_options opts = {0};
  int optmask = HNS_OPT_NOROTATE;
  EXPECT_EQ(HNS_SUCCESS, hns_init_options(&channel, &opts, optmask));

  optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(HNS_OPT_NOROTATE, (optmask & HNS_OPT_NOROTATE));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList multiresolv = {
  {"/etc/resolv.conf", " nameserver 1::2 ;  ;;\n"
                       " domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMultiResolvInit,
                 "myhostname", "mydomainname.org", multiresolv) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  std::vector<std::string> actual = GetNameServers(channel);
  std::vector<std::string> expected = {"0001:0000:0000:0000:0000:0000:0000:0002"};
  EXPECT_EQ(expected, actual);

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(1, opts.ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(opts.domains[0]));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList systemdresolv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: junk resolve files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSystemdResolvInit,
                 "myhostname", "mydomainname.org", systemdresolv) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(std::string("bf"), std::string(opts.lookups));
  hns_destroy_options(&opts);

  hns_destroy(channel);
  return HasFailure();
}

NameContentList empty = {};  // no files
CONTAINED_TEST_F(LibraryTest, ContainerEmptyInit,
                 "host.domain.org", "domain.org", empty) {
  hns_channel channel = nullptr;
  EXPECT_EQ(HNS_SUCCESS, hns_init(&channel));
  std::vector<std::string> actual = GetNameServers(channel);
  std::vector<std::string> expected = {"127.0.0.1"};
  EXPECT_EQ(expected, actual);

  struct hns_options opts;
  int optmask = 0;
  hns_save_options(channel, &opts, &optmask);
  EXPECT_EQ(1, opts.ndomains);
  EXPECT_EQ(std::string("domain.org"), std::string(opts.domains[0]));
  EXPECT_EQ(std::string("fb"), std::string(opts.lookups));
  hns_destroy_options(&opts);


  hns_destroy(channel);
  return HasFailure();
}

#endif

}  // namespace test
}  // namespace hns
