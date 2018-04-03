# Where to find the hns source code; needed because the tests use library-internal headers
HNS_SRC_DIR = ..
# Where to find the built hns static library
HNS_BLD_DIR = ..
AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I ../m4
GMOCK_DIR = gmock-1.8.0
# Note use of -isystem to force use of local gMock/gTest even if there's an installed version.
CPPFLAGS += -I$(HNS_SRC_DIR) -I$(HNS_SRC_DIR)/secp256k1 -isystem $(GMOCK_DIR)
CXXFLAGS += -Wall $(PTHREAD_CFLAGS)

# Makefile.inc provides the various *SOURCES and *HEADERS defines
include Makefile.inc

TESTS = hnstest fuzzcheck.sh

noinst_PROGRAMS = hnstest hnsfuzz hnsfuzzname dnsdump
EXTRA_DIST = fuzzcheck.sh CMakeLists.txt
hnstest_SOURCES = $(TESTSOURCES) $(TESTHEADERS)
hnstest_LDADD = libgmock.la $(HNS_BLD_DIR)/libhns.la $(PTHREAD_LIBS)

# Not interested in coverage of test code, but linking the test binary needs the coverage option
@CODE_COVERAGE_RULES@
hnstest_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

noinst_LTLIBRARIES = libgmock.la

libgmock_la_SOURCES = \
  $(GMOCK_DIR)/gmock-gtest-all.cc	\
  $(GMOCK_DIR)/gmock/gmock.h		\
  $(GMOCK_DIR)/gtest/gtest.h

libgmock_la_CPPFLAGS = -isystem $(GMOCK_DIR)

hnsfuzz_SOURCES = $(FUZZSOURCES)
hnsfuzz_LDADD = $(HNS_BLD_DIR)/libhns.la

hnsfuzzname_SOURCES = $(FUZZNAMESOURCES)
hnsfuzzname_LDADD = $(HNS_BLD_DIR)/libhns.la

dnsdump_SOURCES = $(DUMPSOURCES)
dnsdump_LDADD = $(HNS_BLD_DIR)/libhns.la

test: check
