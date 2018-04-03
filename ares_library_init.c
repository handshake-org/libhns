
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2004-2009 by Daniel Stenberg
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "hns_setup.h"

#include "hns.h"
#include "hns_library_init.h"
#include "hns_private.h"

/* library-private global and unique instance vars */

#ifdef USE_WINSOCK
fpGetNetworkParams_t hns_fpGetNetworkParams = ZERO_NULL;
fpSystemFunction036_t hns_fpSystemFunction036 = ZERO_NULL;
fpGetAdaptersAddresses_t hns_fpGetAdaptersAddresses = ZERO_NULL;
fpGetBestRoute2_t hns_fpGetBestRoute2 = ZERO_NULL;
#endif

#if defined(ANDROID) || defined(__ANDROID__)
#include "hns_android.h"
#endif

/* library-private global vars with source visibility restricted to this file */

static unsigned int hns_initialized;
static int          hns_init_flags;

/* library-private global vars with visibility across the whole library */
void *(*hns_malloc)(size_t size) = malloc;
void *(*hns_realloc)(void *ptr, size_t size) = realloc;
void (*hns_free)(void *ptr) = free;
hns_ec_t *hns_ec = NULL;

#ifdef USE_WINSOCK
static HMODULE hnd_iphlpapi;
static HMODULE hnd_advapi32;
#endif


static int hns_win32_init(void)
{
#ifdef USE_WINSOCK

  hnd_iphlpapi = 0;
  hnd_iphlpapi = LoadLibraryW(L"iphlpapi.dll");
  if (!hnd_iphlpapi)
    return HNS_ELOADIPHLPAPI;

  hns_fpGetNetworkParams = (fpGetNetworkParams_t)
    GetProcAddress(hnd_iphlpapi, "GetNetworkParams");
  if (!hns_fpGetNetworkParams)
    {
      FreeLibrary(hnd_iphlpapi);
      return HNS_EADDRGETNETWORKPARAMS;
    }

  hns_fpGetAdaptersAddresses = (fpGetAdaptersAddresses_t)
    GetProcAddress(hnd_iphlpapi, "GetAdaptersAddresses");
  if (!hns_fpGetAdaptersAddresses)
    {
      /* This can happen on clients before WinXP, I don't
         think it should be an error, unless we don't want to
         support Windows 2000 anymore */
    }

  hns_fpGetBestRoute2 = (fpGetBestRoute2_t)
    GetProcAddress(hnd_iphlpapi, "GetBestRoute2");
  if (!hns_fpGetBestRoute2)
    {
      /* This can happen on clients before Vista, I don't
         think it should be an error, unless we don't want to
         support Windows XP anymore */
    }

  /*
   * When advapi32.dll is unavailable or advapi32.dll has no SystemFunction036,
   * also known as RtlGenRandom, which is the case for Windows versions prior
   * to WinXP then hns uses portable rand() function. Then don't error here.
   */

  hnd_advapi32 = 0;
  hnd_advapi32 = LoadLibraryW(L"advapi32.dll");
  if (hnd_advapi32)
    {
      hns_fpSystemFunction036 = (fpSystemFunction036_t)
        GetProcAddress(hnd_advapi32, "SystemFunction036");
    }

#endif
  return HNS_SUCCESS;
}


static void hns_win32_cleanup(void)
{
#ifdef USE_WINSOCK
  if (hnd_advapi32)
    FreeLibrary(hnd_advapi32);
  if (hnd_iphlpapi)
    FreeLibrary(hnd_iphlpapi);
#endif
}


int hns_library_init(int flags)
{
  int res;

  if (hns_initialized)
    {
      hns_initialized++;
      return HNS_SUCCESS;
    }
  hns_initialized++;

  if (flags & HNS_LIB_INIT_WIN32)
    {
      res = hns_win32_init();
      if (res != HNS_SUCCESS)
        return res;  /* LCOV_EXCL_LINE: can't test Win32 init failure */
    }

  hns_ec = hns_ec_alloc();
  hns_init_flags = flags;

  return HNS_SUCCESS;
}

int hns_library_init_mem(int flags,
                          void *(*amalloc)(size_t size),
                          void (*afree)(void *ptr),
                          void *(*arealloc)(void *ptr, size_t size))
{
  if (amalloc)
    hns_malloc = amalloc;
  if (arealloc)
    hns_realloc = arealloc;
  if (afree)
    hns_free = afree;
  return hns_library_init(flags);
}


void hns_library_cleanup(void)
{
  if (!hns_initialized)
    return;
  hns_initialized--;
  if (hns_initialized)
    return;

  if (hns_init_flags & HNS_LIB_INIT_WIN32)
    hns_win32_cleanup();

#if defined(ANDROID) || defined(__ANDROID__)
  hns_library_cleanup_android();
#endif

  hns_init_flags = HNS_LIB_INIT_NONE;
  hns_ec_free(hns_ec);
  hns_ec = NULL;
  hns_malloc = malloc;
  hns_realloc = realloc;
  hns_free = free;
}


int hns_library_initialized(void)
{
#ifdef USE_WINSOCK
  if (!hns_initialized)
    return HNS_ENOTINITIALIZED;
#endif
  return HNS_SUCCESS;
}
