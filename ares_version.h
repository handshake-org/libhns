
#ifndef HNS__VERSION_H
#define HNS__VERSION_H

/* This is the global package copyright */
#define HNS_COPYRIGHT "2004 - 2017 Daniel Stenberg, <daniel@haxx.se>."

#define HNS_VERSION_MAJOR 1
#define HNS_VERSION_MINOR 14
#define HNS_VERSION_PATCH 0
#define HNS_VERSION ((HNS_VERSION_MAJOR<<16)|\
                       (HNS_VERSION_MINOR<<8)|\
                       (HNS_VERSION_PATCH))
#define HNS_VERSION_STR "1.14.0"

#if (HNS_VERSION >= 0x010700)
#  define HNS_HAVE_HNS_LIBRARY_INIT 1
#  define HNS_HAVE_HNS_LIBRARY_CLEANUP 1
#else
#  undef HNS_HAVE_HNS_LIBRARY_INIT
#  undef HNS_HAVE_HNS_LIBRARY_CLEANUP
#endif

#endif
