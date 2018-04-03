AUTOMAKE_OPTIONS = foreign nostdinc

ACLOCAL_AMFLAGS = -I m4

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# When using the low-level hard-hacking memory leak tracking code from
# libcurl the generated curl/curlbuild.h file must also be reachable.
# Using the libcurl lowlevel code from within hns library is ugly and
# only works when hns is built and linked with a similarly debug-build
# libcurl, but we do this anyway for convenience.
#
# $(top_builddir)/../include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/../include is for libcurl's generated curl/curlbuild.h file
# $(top_srcdir)/../include is for libcurl's external include files
# $(top_builddir)/../lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/../lib is for libcurl's lib/setup.h and other "private" files
# $(top_builddir) is for hns's generated hns_config.h file
# $(top_srcdir) is for hns's hns_setup.h and other "hns-private" files

if CURLDEBUG
AM_CPPFLAGS = -I$(top_builddir)/../include/curl \
              -I$(top_builddir)/../include      \
              -I$(top_srcdir)/../include        \
              -I$(top_builddir)/../lib          \
              -I$(top_srcdir)/../lib            \
              -I$(top_builddir)                 \
              -I$(top_srcdir)
else
AM_CPPFLAGS = -I$(top_builddir) \
              -I$(top_srcdir) \
              -I$(top_srcdir)/secp256k1
endif

lib_LTLIBRARIES = libhns.la

man_MANS = $(MANPAGES)

MSVCFILES = vc/vc6aws.dsw vc/hcountry/vc6hcountry.dsp vc/hdig/vc6hdig.dsp	\
 vc/hhost/vc6hhost.dsp vc/hns/vc6hns.dsp vc/hns/vc6hns.dsw		\
 msvc_ver.inc

if CURLDEBUG
PROGS =
else
PROGS = hhost hdig hcountry
endif

noinst_PROGRAMS =$(PROGS)

# hdig and hhost are just sample programs and thus not mentioned with the
# regular sources and headers
EXTRA_DIST = AUTHORS CHANGES README.hns Makefile.inc Makefile.dj	   \
 Makefile.m32 Makefile.netware Makefile.msvc Makefile.Watcom $(man_MANS)   \
 config-win32.h RELEASE-NOTES libhns.pc.in buildconf get_ver.awk maketgz \
 TODO hns_build.h.in hns.rc README.msvc $(MSVCFILES)	   \
 $(CSOURCES) $(HHEADERS) config-dos.h hcountry.1 hdig.1 hhost.1 INSTALL.md	   \
 CMakeLists.txt hns_build.h.cmake hns_config.h.cmake hns-config.cmake.in \
 libhns.pc.cmake README.md LICENSE.md RELEASE-PROCEDURE.md

CLEANFILES = $(PDFPAGES) $(HTMLPAGES)

DISTCLEANFILES = hns_build.h

DIST_SUBDIRS = test

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhns.pc

HNS_VERSION_INFO = -version-info 4:0:2
# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information:
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r+1:a)
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0. (c+1:r=0:a)
#
# 5.If any interfaces have been added since the last public release, then
# increment age. (c:r:a+1)
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0. (c:r:a=0)
#

AM_LDFLAGS =

#
# Secp256k1
#

if USE_EXTERNAL_ASM
COMMON_LIB = libhns_common.la
noinst_LTLIBRARIES = $(COMMON_LIB)
else
COMMON_LIB =
endif

if USE_EXTERNAL_ASM
if USE_ASM_ARM
libhns_common_la_SOURCES = src/asm/field_10x26_arm.s
endif
endif

libhns_la_LIBADD = $(COMMON_LIB)

#
# /Secp256k1
#

libhns_la_LDFLAGS_EXTRA =

if HNS_LT_SHLIB_USE_VERSION_INFO
libhns_la_LDFLAGS_EXTRA += $(HNS_VERSION_INFO)
endif

if HNS_LT_SHLIB_USE_NO_UNDEFINED
libhns_la_LDFLAGS_EXTRA += -no-undefined
endif

if HNS_LT_SHLIB_USE_MIMPURE_TEXT
libhns_la_LDFLAGS_EXTRA += -mimpure-text
endif

libhns_la_LDFLAGS = $(AM_LDFLAGS) $(libhns_la_LDFLAGS_EXTRA)

# Add -Werror if defined
CFLAGS += @HNS_CFLAG_EXTRAS@

if USE_CPPFLAG_HNS_STATICLIB
AM_CPPFLAGS += $(CPPFLAG_HNS_STATICLIB)
endif

libhns_la_CFLAGS_EXTRA =

libhns_la_CPPFLAGS_EXTRA = -DHNS_BUILDING_LIBRARY

if DOING_HNS_SYMBOL_HIDING
libhns_la_CFLAGS_EXTRA += $(CFLAG_HNS_SYMBOL_HIDING)
libhns_la_CPPFLAGS_EXTRA += -DHNS_SYMBOL_HIDING
endif

@CODE_COVERAGE_RULES@
libhns_la_LDFLAGS += $(CODE_COVERAGE_LDFLAGS)
libhns_la_CFLAGS_EXTRA += $(CODE_COVERAGE_CFLAGS)

libhns_la_CFLAGS = $(AM_CFLAGS) $(libhns_la_CFLAGS_EXTRA)

libhns_la_CPPFLAGS = $(AM_CPPFLAGS) $(libhns_la_CPPFLAGS_EXTRA)

# Makefile.inc provides the CSOURCES and HHEADERS defines
include Makefile.inc

libhns_la_SOURCES = $(CSOURCES) $(HHEADERS)

# where to install the hns headers
libhns_ladir = $(includedir)
# what headers to install on 'make install':
libhns_la_HEADERS = hns.h hns_version.h hns_dns.h \
	hns_build.h hns_rules.h

hhost_SOURCES = hhost.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
hhost_LDADD = $(top_builddir)/libhns.la
hhost_CFLAGS = $(AM_CFLAGS)
hhost_CPPFLAGS = $(AM_CPPFLAGS)

hdig_SOURCES = hdig.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
hdig_LDADD = $(top_builddir)/libhns.la
hdig_CFLAGS = $(AM_CFLAGS)
hdig_CPPFLAGS = $(AM_CPPFLAGS)

hcountry_SOURCES = hcountry.c $(SAMPLESOURCES) $(SAMPLEHEADERS)
hcountry_LDADD = $(top_builddir)/libhns.la
hcountry_CFLAGS = $(AM_CFLAGS)
hcountry_CPPFLAGS = $(AM_CPPFLAGS)

SOURCEDMANDIR = man3
SOURCEDMANPAGES = hns_init.3

clean-local: clean-sourced-manpages

clean-sourced-manpages:
	@srcdmandir='$(SOURCEDMANDIR)'; \
	echo "rm -rf $(top_builddir)/$$srcdmandir"; \
	rm -rf $(top_builddir)/$$srcdmandir

sourced-manpages: clean-sourced-manpages
	@srcdmandir='$(SOURCEDMANDIR)'; \
	srcdmanfiles='$(SOURCEDMANPAGES)'; \
	mkdir $(top_builddir)/$$srcdmandir; \
	for file in $$srcdmanfiles; do \
	  if test -f $(top_srcdir)/$$file; then \
	    echo "cp $(top_srcdir)/$$file $(top_builddir)/$$srcdmandir/$$file"; \
	    cp $(top_srcdir)/$$file $(top_builddir)/$$srcdmandir/$$file; \
	  fi; \
	done

MAN2HTML = roffit --mandir=. < $< >$@

SUFFIXES = .3 .html

html: sourced-manpages $(HTMLPAGES)

.3.html:
	$(MAN2HTML)

pdf: sourced-manpages $(PDFPAGES)

.3.pdf:
	@(foo=`echo $@ | sed -e 's/\.[0-9]$$//g'`; \
	groff -Tps -man $< >$$foo.ps; \
	ps2pdf $$foo.ps $@; \
	rm $$foo.ps; \
	echo "converted $< to $@")

# Make files named *.dist replace the file without .dist extension
dist-hook:
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
