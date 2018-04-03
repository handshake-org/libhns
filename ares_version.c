
#include "hns_setup.h"
#include "hns.h"

const char *hns_version(int *version)
{
  if(version)
    *version = HNS_VERSION;

  return HNS_VERSION_STR;
}
