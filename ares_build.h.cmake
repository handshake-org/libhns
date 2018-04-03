#ifndef __HNS_BUILD_H
#define __HNS_BUILD_H

#define HNS_TYPEOF_HNS_SOCKLEN_T @HNS_TYPEOF_HNS_SOCKLEN_T@
#define HNS_TYPEOF_HNS_SSIZE_T @HNS_TYPEOF_HNS_SSIZE_T@

/* Prefix names with HNS_ to make sure they don't conflict with other config.h
 * files.  We need to include some dependent headers that may be system specific
 * for HNS */
#cmakedefine HNS_HAVE_SYS_TYPES_H
#cmakedefine HNS_HAVE_SYS_SOCKET_H
#cmakedefine HNS_HAVE_WINDOWS_H
#cmakedefine HNS_HAVE_WS2TCPIP_H
#cmakedefine HNS_HAVE_WINSOCK2_H
#cmakedefine HNS_HAVE_WINDOWS_H

#ifdef HNS_HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HNS_HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

#ifdef HNS_HAVE_WINSOCK2_H
#  include <winsock2.h>
#endif

#ifdef HNS_HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
#endif

#ifdef HNS_HAVE_WINDOWS_H
#  include <windows.h>
#endif


typedef HNS_TYPEOF_HNS_SOCKLEN_T hns_socklen_t;
typedef HNS_TYPEOF_HNS_SSIZE_T hns_ssize_t;

#endif /* __HNS_BUILD_H */
