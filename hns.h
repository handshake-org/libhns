
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2007-2013 by Daniel Stenberg
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

#ifndef HNS__H
#define HNS__H

#include "hns_version.h"  /* hns version defines   */
#include "hns_build.h"    /* hns build definitions */
#include "hns_rules.h"    /* hns rules enforcement */

/*
 * Define WIN32 when build target is Win32 API
 */

#if (defined(_WIN32) || defined(__WIN32__)) && \
   !defined(WIN32) && !defined(__SYMBIAN32__)
#  define WIN32
#endif

#include <sys/types.h>

/* HP-UX systems version 9, 10 and 11 lack sys/select.h and so does oldish
   libc5-based Linux systems. Only include it on system that are known to
   require it! */
#if defined(_AIX) || defined(__NOVELL_LIBC__) || defined(__NetBSD__) || \
    defined(__minix) || defined(__SYMBIAN32__) || defined(__INTEGRITY) || \
    defined(ANDROID) || defined(__ANDROID__) || defined(__OpenBSD__) || \
    defined(__QNXNTO__)
#include <sys/select.h>
#endif
#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
#include <sys/bsdskt.h>
#endif

#if defined(WATT32)
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <tcp.h>
#elif defined(_WIN32_WCE)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock.h>
#elif defined(WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#if defined(ANDROID) || defined(__ANDROID__)
#include <jni.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/*
** hns external API function linkage decorations.
*/

#ifdef HNS_STATICLIB
#  define HNS_EXTERN
#elif defined(WIN32) || defined(_WIN32) || defined(__SYMBIAN32__)
#  if defined(HNS_BUILDING_LIBRARY)
#    define HNS_EXTERN  __declspec(dllexport)
#  else
#    define HNS_EXTERN  __declspec(dllimport)
#  endif
#elif defined(HNS_BUILDING_LIBRARY) && defined(HNS_SYMBOL_HIDING)
#  define HNS_EXTERN HNS_SYMBOL_SCOPE_EXTERN
#else
#  define HNS_EXTERN
#endif


#define HNS_SUCCESS            0

/* Server error codes (HNS_ENODATA indicates no relevant answer) */
#define HNS_ENODATA            1
#define HNS_EFORMERR           2
#define HNS_ESERVFAIL          3
#define HNS_ENOTFOUND          4
#define HNS_ENOTIMP            5
#define HNS_EREFUSED           6

/* Locally generated error codes */
#define HNS_EBADQUERY          7
#define HNS_EBADNAME           8
#define HNS_EBADFAMILY         9
#define HNS_EBADRESP           10
#define HNS_ECONNREFUSED       11
#define HNS_ETIMEOUT           12
#define HNS_EOF                13
#define HNS_EFILE              14
#define HNS_ENOMEM             15
#define HNS_EDESTRUCTION       16
#define HNS_EBADSTR            17

/* hns_getnameinfo error codes */
#define HNS_EBADFLAGS          18

/* hns_getaddrinfo error codes */
#define HNS_ENONAME            19
#define HNS_EBADHINTS          20

/* Uninitialized library error code */
#define HNS_ENOTINITIALIZED    21          /* introduced in 1.7.0 */

/* hns_library_init error codes */
#define HNS_ELOADIPHLPAPI           22     /* introduced in 1.7.0 */
#define HNS_EADDRGETNETWORKPARAMS   23     /* introduced in 1.7.0 */

/* More error codes */
#define HNS_ECANCELLED         24          /* introduced in 1.7.0 */

/* Even more error codes */
#define HNS_EBADSIGNATURE      25
#define HNS_EINSECURE          26

/* Flag values */
#define HNS_FLAG_USEVC         (1 << 0)
#define HNS_FLAG_PRIMARY       (1 << 1)
#define HNS_FLAG_IGNTC         (1 << 2)
#define HNS_FLAG_NORECURSE     (1 << 3)
#define HNS_FLAG_STAYOPEN      (1 << 4)
#define HNS_FLAG_NOSEARCH      (1 << 5)
#define HNS_FLAG_NOALIASES     (1 << 6)
#define HNS_FLAG_NOCHECKRESP   (1 << 7)
#define HNS_FLAG_EDNS          (1 << 8)

/* Option mask values */
#define HNS_OPT_FLAGS          (1 << 0)
#define HNS_OPT_TIMEOUT        (1 << 1)
#define HNS_OPT_TRIES          (1 << 2)
#define HNS_OPT_NDOTS          (1 << 3)
#define HNS_OPT_UDP_PORT       (1 << 4)
#define HNS_OPT_TCP_PORT       (1 << 5)
#define HNS_OPT_SERVERS        (1 << 6)
#define HNS_OPT_DOMAINS        (1 << 7)
#define HNS_OPT_LOOKUPS        (1 << 8)
#define HNS_OPT_SOCK_STATE_CB  (1 << 9)
#define HNS_OPT_SORTLIST       (1 << 10)
#define HNS_OPT_SOCK_SNDBUF    (1 << 11)
#define HNS_OPT_SOCK_RCVBUF    (1 << 12)
#define HNS_OPT_TIMEOUTMS      (1 << 13)
#define HNS_OPT_ROTATE         (1 << 14)
#define HNS_OPT_EDNSPSZ        (1 << 15)
#define HNS_OPT_NOROTATE       (1 << 16)

/* Nameinfo flag values */
#define HNS_NI_NOFQDN                  (1 << 0)
#define HNS_NI_NUMERICHOST             (1 << 1)
#define HNS_NI_NAMEREQD                (1 << 2)
#define HNS_NI_NUMERICSERV             (1 << 3)
#define HNS_NI_DGRAM                   (1 << 4)
#define HNS_NI_TCP                     0
#define HNS_NI_UDP                     HNS_NI_DGRAM
#define HNS_NI_SCTP                    (1 << 5)
#define HNS_NI_DCCP                    (1 << 6)
#define HNS_NI_NUMERICSCOPE            (1 << 7)
#define HNS_NI_LOOKUPHOST              (1 << 8)
#define HNS_NI_LOOKUPSERVICE           (1 << 9)
/* Reserved for future use */
#define HNS_NI_IDN                     (1 << 10)
#define HNS_NI_IDN_ALLOW_UNASSIGNED    (1 << 11)
#define HNS_NI_IDN_USE_STD3_ASCII_RULES (1 << 12)

/* Addrinfo flag values */
#define HNS_AI_CANONNAME               (1 << 0)
#define HNS_AI_NUMERICHOST             (1 << 1)
#define HNS_AI_PASSIVE                 (1 << 2)
#define HNS_AI_NUMERICSERV             (1 << 3)
#define HNS_AI_V4MAPPED                (1 << 4)
#define HNS_AI_ALL                     (1 << 5)
#define HNS_AI_ADDRCONFIG              (1 << 6)
/* Reserved for future use */
#define HNS_AI_IDN                     (1 << 10)
#define HNS_AI_IDN_ALLOW_UNASSIGNED    (1 << 11)
#define HNS_AI_IDN_USE_STD3_ASCII_RULES (1 << 12)
#define HNS_AI_CANONIDN                (1 << 13)

#define HNS_AI_MASK (HNS_AI_CANONNAME|HNS_AI_NUMERICHOST|HNS_AI_PASSIVE| \
                      HNS_AI_NUMERICSERV|HNS_AI_V4MAPPED|HNS_AI_ALL| \
                      HNS_AI_ADDRCONFIG)
#define HNS_GETSOCK_MAXNUM 16 /* hns_getsock() can return info about this
                                  many sockets */
#define HNS_GETSOCK_READABLE(bits,num) (bits & (1<< (num)))
#define HNS_GETSOCK_WRITABLE(bits,num) (bits & (1 << ((num) + \
                                         HNS_GETSOCK_MAXNUM)))

/* hns library initialization flag values */
#define HNS_LIB_INIT_NONE   (0)
#define HNS_LIB_INIT_WIN32  (1 << 0)
#define HNS_LIB_INIT_ALL    (HNS_LIB_INIT_WIN32)


/*
 * Typedef our socket type
 */

#ifndef hns_socket_typedef
#ifdef WIN32
typedef SOCKET hns_socket_t;
#define HNS_SOCKET_BAD INVALID_SOCKET
#else
typedef int hns_socket_t;
#define HNS_SOCKET_BAD -1
#endif
#define hns_socket_typedef
#endif /* hns_socket_typedef */

typedef void (*hns_sock_state_cb)(void *data,
                                   hns_socket_t socket_fd,
                                   int readable,
                                   int writable);

struct apattern;

/* NOTE about the hns_options struct to users and developers.

   This struct will remain looking like this. It will not be extended nor
   shrunk in future releases, but all new options will be set by hns_set_*()
   options instead of with the hns_init_options() function.

   Eventually (in a galaxy far far away), all options will be settable by
   hns_set_*() options and the hns_init_options() function will become
   deprecated.

   When new options are added to hns, they are not added to this
   struct. And they are not "saved" with the hns_save_options() function but
   instead we encourage the use of the hns_dup() function. Needless to say,
   if you add config options to hns you need to make sure hns_dup()
   duplicates this new option.

 */
struct hns_options {
  int flags;
  int timeout; /* in seconds or milliseconds, depending on options */
  int tries;
  int ndots;
  unsigned short udp_port;
  unsigned short tcp_port;
  int socket_send_buffer_size;
  int socket_receive_buffer_size;
  struct in_addr *servers;
  int nservers;
  char **domains;
  int ndomains;
  char *lookups;
  hns_sock_state_cb sock_state_cb;
  void *sock_state_cb_data;
  struct apattern *sortlist;
  int nsort;
  int ednspsz;
};

struct hostent;
struct timeval;
struct sockaddr;
struct hns_channeldata;

typedef struct hns_channeldata *hns_channel;

typedef void (*hns_callback)(void *arg,
                              int status,
                              int timeouts,
                              unsigned char *abuf,
                              int alen);

typedef void (*hns_host_callback)(void *arg,
                                   int status,
                                   int timeouts,
                                   struct hostent *hostent);

typedef void (*hns_nameinfo_callback)(void *arg,
                                       int status,
                                       int timeouts,
                                       char *node,
                                       char *service);

typedef int  (*hns_sock_create_callback)(hns_socket_t socket_fd,
                                          int type,
                                          void *data);

typedef int  (*hns_sock_config_callback)(hns_socket_t socket_fd,
                                          int type,
                                          void *data);

HNS_EXTERN int hns_library_init(int flags);

HNS_EXTERN int hns_library_init_mem(int flags,
                                       void *(*amalloc)(size_t size),
                                       void (*afree)(void *ptr),
                                       void *(*arealloc)(void *ptr, size_t size));

#if defined(ANDROID) || defined(__ANDROID__)
HNS_EXTERN void hns_library_init_jvm(JavaVM *jvm);
HNS_EXTERN int hns_library_init_android(jobject connectivity_manager);
HNS_EXTERN int hns_library_android_initialized(void);
#endif

HNS_EXTERN int hns_library_initialized(void);

HNS_EXTERN void hns_library_cleanup(void);

HNS_EXTERN const char *hns_version(int *version);

HNS_EXTERN int hns_init(hns_channel *channelptr);

HNS_EXTERN int hns_init_options(hns_channel *channelptr,
                                   struct hns_options *options,
                                   int optmask);

HNS_EXTERN int hns_save_options(hns_channel channel,
                                   struct hns_options *options,
                                   int *optmask);

HNS_EXTERN void hns_destroy_options(struct hns_options *options);

HNS_EXTERN int hns_dup(hns_channel *dest,
                          hns_channel src);

HNS_EXTERN void hns_destroy(hns_channel channel);

HNS_EXTERN void hns_cancel(hns_channel channel);

/* These next 3 configure local binding for the out-going socket
 * connection.  Use these to specify source IP and/or network device
 * on multi-homed systems.
 */
HNS_EXTERN void hns_set_local_ip4(hns_channel channel, unsigned int local_ip);

/* local_ip6 should be 16 bytes in length */
HNS_EXTERN void hns_set_local_ip6(hns_channel channel,
                                     const unsigned char* local_ip6);

/* local_dev_name should be null terminated. */
HNS_EXTERN void hns_set_local_dev(hns_channel channel,
                                     const char* local_dev_name);

HNS_EXTERN void hns_set_socket_callback(hns_channel channel,
                                           hns_sock_create_callback callback,
                                           void *user_data);

HNS_EXTERN void hns_set_socket_configure_callback(hns_channel channel,
                                                     hns_sock_config_callback callback,
                                                     void *user_data);

HNS_EXTERN int hns_set_sortlist(hns_channel channel,
                                   const char *sortstr);

/*
 * Virtual function set to have user-managed socket IO.
 * Note that all functions need to be defined, and when
 * set, the library will not do any bind nor set any
 * socket options, assuming the client handles these
 * through either socket creation or the
 * hns_sock_config_callback call.
 */
struct iovec;
struct hns_socket_functions {
   hns_socket_t(*asocket)(int, int, int, void *);
   int(*aclose)(hns_socket_t, void *);
   int(*aconnect)(hns_socket_t, const struct sockaddr *, hns_socklen_t, void *);
   hns_ssize_t(*arecvfrom)(hns_socket_t, void *, size_t, int, struct sockaddr *, hns_socklen_t *, void *);
   hns_ssize_t(*asendv)(hns_socket_t, const struct iovec *, int, void *);
};

HNS_EXTERN void hns_set_socket_functions(hns_channel channel,
					    const struct hns_socket_functions * funcs,
					    void *user_data);

HNS_EXTERN void hns_send(hns_channel channel,
                            const unsigned char *qbuf,
                            int qlen,
                            hns_callback callback,
                            void *arg);

HNS_EXTERN void hns_query(hns_channel channel,
                             const char *name,
                             int dnsclass,
                             int type,
                             hns_callback callback,
                             void *arg);

HNS_EXTERN void hns_search(hns_channel channel,
                              const char *name,
                              int dnsclass,
                              int type,
                              hns_callback callback,
                              void *arg);

HNS_EXTERN void hns_gethostbyname(hns_channel channel,
                                     const char *name,
                                     int family,
                                     hns_host_callback callback,
                                     void *arg);

HNS_EXTERN int hns_gethostbyname_file(hns_channel channel,
                                         const char *name,
                                         int family,
                                         struct hostent **host);

HNS_EXTERN void hns_gethostbyaddr(hns_channel channel,
                                     const void *addr,
                                     int addrlen,
                                     int family,
                                     hns_host_callback callback,
                                     void *arg);

HNS_EXTERN void hns_getnameinfo(hns_channel channel,
                                   const struct sockaddr *sa,
                                   hns_socklen_t salen,
                                   int flags,
                                   hns_nameinfo_callback callback,
                                   void *arg);

HNS_EXTERN int hns_fds(hns_channel channel,
                          fd_set *read_fds,
                          fd_set *write_fds);

HNS_EXTERN int hns_getsock(hns_channel channel,
                              hns_socket_t *socks,
                              int numsocks);

HNS_EXTERN struct timeval *hns_timeout(hns_channel channel,
                                          struct timeval *maxtv,
                                          struct timeval *tv);

HNS_EXTERN void hns_process(hns_channel channel,
                               fd_set *read_fds,
                               fd_set *write_fds);

HNS_EXTERN void hns_process_fd(hns_channel channel,
                                  hns_socket_t read_fd,
                                  hns_socket_t write_fd);

HNS_EXTERN int hns_create_query(const char *name,
                                   int dnsclass,
                                   int type,
                                   unsigned short id,
                                   int rd,
                                   unsigned char **buf,
                                   int *buflen,
                                   int max_udp_size);

HNS_EXTERN int hns_mkquery(const char *name,
                              int dnsclass,
                              int type,
                              unsigned short id,
                              int rd,
                              unsigned char **buf,
                              int *buflen);

HNS_EXTERN int hns_expand_name(const unsigned char *encoded,
                                  const unsigned char *abuf,
                                  int alen,
                                  char **s,
                                  long *enclen);

HNS_EXTERN int hns_expand_string(const unsigned char *encoded,
                                    const unsigned char *abuf,
                                    int alen,
                                    unsigned char **s,
                                    long *enclen);

/*
 * NOTE: before hns 1.7.0 we would most often use the system in6_addr
 * struct below when hns itself was built, but many apps would use this
 * private version since the header checked a HAVE_* define for it. Starting
 * with 1.7.0 we always declare and use our own to stop relying on the
 * system's one.
 */
struct hns_in6_addr {
  union {
    unsigned char _S6_u8[16];
  } _S6_un;
};

struct hns_addrttl {
  struct in_addr ipaddr;
  int            ttl;
};

struct hns_addr6ttl {
  struct hns_in6_addr ip6addr;
  int             ttl;
};

struct hns_srv_reply {
  struct hns_srv_reply  *next;
  char                   *host;
  unsigned short          priority;
  unsigned short          weight;
  unsigned short          port;
};

struct hns_mx_reply {
  struct hns_mx_reply   *next;
  char                   *host;
  unsigned short          priority;
};

struct hns_txt_reply {
  struct hns_txt_reply  *next;
  unsigned char          *txt;
  size_t                  length;  /* length excludes null termination */
};

/* NOTE: This structure is a superset of hns_txt_reply
 */
struct hns_txt_ext {
  struct hns_txt_ext      *next;
  unsigned char            *txt;
  size_t                   length;
  /* 1 - if start of new record
   * 0 - if a chunk in the same record */
  unsigned char            record_start;
};

struct hns_naptr_reply {
  struct hns_naptr_reply *next;
  unsigned char           *flags;
  unsigned char           *service;
  unsigned char           *regexp;
  char                    *replacement;
  unsigned short           order;
  unsigned short           preference;
};

struct hns_soa_reply {
  char        *nsname;
  char        *hostmaster;
  unsigned int serial;
  unsigned int refresh;
  unsigned int retry;
  unsigned int expire;
  unsigned int minttl;
};

struct hns_sshfp_reply {
  struct hns_sshfp_reply *next;
  unsigned short           algorithm;
  unsigned short           digest_type;
  unsigned char           *fingerprint;
  size_t                   fingerprint_len;
};

struct hns_dane_reply {
  struct hns_dane_reply *next;
  unsigned short          usage;
  unsigned short          selector;
  unsigned short          matching_type;
  unsigned char          *certificate;
  size_t                  certificate_len;
};

#define hns_tlsa_reply hns_dane_reply
#define hns_smimea_reply hns_dane_reply

struct hns_openpgpkey_reply {
  struct hns_openpgpkey_reply *next;
  unsigned char                *pubkey;
  size_t                        pubkey_len;
};

/*
 * DANE functions
 */

HNS_EXTERN int
hns_tlsa_encode_name(
  const char *name,
  const char *protocol,
  unsigned int port,
  char *out,
  size_t out_len
);

HNS_EXTERN size_t
hns_tlsa_name_size(const char *name, const char *protocol, unsigned int port);

HNS_EXTERN int
hns_tlsa_verify(
  struct hns_tlsa_reply *tlsa_reply,
  const unsigned char *cert,
  size_t cert_len
);

HNS_EXTERN int
hns_smimea_encode_email(
  const char *email,
  char *out,
  size_t out_len
);

HNS_EXTERN int
hns_smimea_encode_name(
  const char *name,
  const char *local,
  char *out,
  size_t out_len
);

HNS_EXTERN size_t
hns_smimea_email_size(const char *email);

HNS_EXTERN size_t
hns_smimea_name_size(const char *name);

HNS_EXTERN int
hns_smimea_verify(
  struct hns_smimea_reply *smimea_reply,
  const unsigned char *cert,
  size_t cert_len
);

HNS_EXTERN int
hns_openpgpkey_encode_email(
  const char *email,
  char *out,
  size_t out_len
);

HNS_EXTERN int
hns_openpgpkey_encode_name(
  const char *name,
  const char *local,
  char *out,
  size_t out_len
);

HNS_EXTERN size_t
hns_openpgpkey_email_size(const char *email);

HNS_EXTERN size_t
hns_openpgpkey_name_size(const char *name);

/*
 * SSHFP functions
 */

HNS_EXTERN int
hns_sshfp_verify(
  struct hns_sshfp_reply *sshfp_reply,
  const unsigned char *key,
  size_t key_len
);

/*
** Parse the buffer, starting at *abuf and of length alen bytes, previously
** obtained from an hns_search call.  Put the results in *host, if nonnull.
** Also, if addrttls is nonnull, put up to *naddrttls IPv4 addresses along with
** their TTLs in that array, and set *naddrttls to the number of addresses
** so written.
*/

HNS_EXTERN int hns_parse_a_reply(const unsigned char *abuf,
                                    int alen,
                                    struct hostent **host,
                                    struct hns_addrttl *addrttls,
                                    int *naddrttls);

HNS_EXTERN int hns_parse_aaaa_reply(const unsigned char *abuf,
                                       int alen,
                                       struct hostent **host,
                                       struct hns_addr6ttl *addrttls,
                                       int *naddrttls);

HNS_EXTERN int hns_parse_ptr_reply(const unsigned char *abuf,
                                      int alen,
                                      const void *addr,
                                      int addrlen,
                                      int family,
                                      struct hostent **host);

HNS_EXTERN int hns_parse_ns_reply(const unsigned char *abuf,
                                     int alen,
                                     struct hostent **host);

HNS_EXTERN int hns_parse_srv_reply(const unsigned char* abuf,
                                      int alen,
                                      struct hns_srv_reply** srv_out);

HNS_EXTERN int hns_parse_mx_reply(const unsigned char* abuf,
                                      int alen,
                                      struct hns_mx_reply** mx_out);

HNS_EXTERN int hns_parse_txt_reply(const unsigned char* abuf,
                                      int alen,
                                      struct hns_txt_reply** txt_out);

HNS_EXTERN int hns_parse_txt_reply_ext(const unsigned char* abuf,
                                          int alen,
                                          struct hns_txt_ext** txt_out);

HNS_EXTERN int hns_parse_naptr_reply(const unsigned char* abuf,
                                        int alen,
                                        struct hns_naptr_reply** naptr_out);

HNS_EXTERN int hns_parse_soa_reply(const unsigned char* abuf,
				      int alen,
				      struct hns_soa_reply** soa_out);

HNS_EXTERN int hns_parse_sshfp_reply(const unsigned char* abuf,
				      int alen,
				      struct hns_sshfp_reply** sshfp_out);

HNS_EXTERN int hns_parse_tlsa_reply(const unsigned char* abuf,
				      int alen,
				      struct hns_tlsa_reply** tlsa_out);

HNS_EXTERN int hns_parse_smimea_reply(const unsigned char* abuf,
				      int alen,
				      struct hns_smimea_reply** smimea_out);

HNS_EXTERN int hns_parse_openpgpkey_reply(const unsigned char* abuf,
				      int alen,
				      struct hns_openpgpkey_reply** openpgpkey_out);

HNS_EXTERN void hns_free_string(void *str);

HNS_EXTERN void hns_free_hostent(struct hostent *host);

HNS_EXTERN void hns_free_data(void *dataptr);

HNS_EXTERN const char *hns_strerror(int code);

struct hns_addr_node {
  struct hns_addr_node *next;
  int family;
  union {
    struct in_addr       addr4;
    struct hns_in6_addr addr6;
  } addr;
};

struct hns_addr_port_node {
  struct hns_addr_port_node *next;
  int family;
  union {
    struct in_addr       addr4;
    struct hns_in6_addr addr6;
  } addr;
  int udp_port;
  int tcp_port;
};

HNS_EXTERN int hns_set_servers(hns_channel channel,
                                  struct hns_addr_node *servers);
HNS_EXTERN int hns_set_servers_ports(hns_channel channel,
                                        struct hns_addr_port_node *servers);

/* Incomming string format: host[:port][,host[:port]]... */
HNS_EXTERN int hns_set_servers_csv(hns_channel channel,
                                      const char* servers);
HNS_EXTERN int hns_set_servers_ports_csv(hns_channel channel,
                                            const char* servers);

HNS_EXTERN int hns_get_servers(hns_channel channel,
                                  struct hns_addr_node **servers);
HNS_EXTERN int hns_get_servers_ports(hns_channel channel,
                                        struct hns_addr_port_node **servers);

HNS_EXTERN const char *hns_inet_ntop(int af, const void *src, char *dst,
                                        hns_socklen_t size);

HNS_EXTERN int hns_inet_pton(int af, const char *src, void *dst);


#ifdef  __cplusplus
}
#endif

#endif /* HNS__H */
