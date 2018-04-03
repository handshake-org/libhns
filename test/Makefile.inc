TESTSOURCES = hns-test-main.cc	\
  hns-test-init.cc			\
  hns-test.cc				\
  hns-test-ns.cc			\
  hns-test-parse.cc			\
  hns-test-parse-a.cc			\
  hns-test-parse-aaaa.cc		\
  hns-test-parse-mx.cc		\
  hns-test-parse-naptr.cc		\
  hns-test-parse-ns.cc		\
  hns-test-parse-ptr.cc		\
  hns-test-parse-soa.cc		\
  hns-test-parse-srv.cc		\
  hns-test-parse-txt.cc		\
  hns-test-parse-smimea.cc		\
  hns-test-parse-sshfp.cc		\
  hns-test-parse-tlsa.cc		\
  hns-test-parse-openpgpkey.cc		\
  hns-test-misc.cc			\
  hns-test-live.cc			\
  hns-test-mock.cc			\
  hns-test-internal.cc		\
  dns-proto.cc				\
  dns-proto-test.cc

TESTHEADERS = hns-test.h		\
  dns-proto.h

FUZZSOURCES = hns-test-fuzz.c		\
  hns-fuzz.c

FUZZNAMESOURCES = hns-test-fuzz-name.c	\
  hns-fuzz.c

DUMPSOURCES = dns-proto.cc		\
  dns-dump.cc
