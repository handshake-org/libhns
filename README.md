# libhns

An HNS-capable fork of [c-ares]. Currently unstable, but adds a few features
which are useful for authenticated DNS, such as [DANE][dane]. See [hdns] for
a similar node.js implementation.

## Added Features

- [TLSA][tlsa] certificate verification.
- [SMIMEA][smimea] certificate verification.
- [OPENPGPKEY][pgp] verification.
- [SSHFP][sshfp] verification.
- [SIG(0)][sig0] verification.
- [hns.conf][conf] parsing.

## License

### c-ares

- Copyright (c) 2007 - 2018, Daniel Stenberg with many contributors, see
  AUTHORS file.
- Copyright 1998 by the Massachusetts Institute of Technology.

### libhns

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided that
the above copyright notice appear in all copies and that both that copyright
notice and this permission notice appear in supporting documentation, and that
the name of M.I.T. not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.
M.I.T. makes no representations about the suitability of this software for any
purpose.  It is provided "as is" without express or implied warranty.

[c-ares]: https://c-ares.haxx.se/
[dane]: https://tools.ietf.org/html/rfc6698
[hdns]: https://github.com/handshake-org/hdns
[tlsa]: https://tools.ietf.org/html/rfc6698
[smimea]: https://tools.ietf.org/html/rfc8162
[pgp]: https://tools.ietf.org/html/rfc7929
[sshfp]: https://tools.ietf.org/html/rfc4255
[sig0]: https://tools.ietf.org/html/rfc2931
[conf]: https://handshake.org/files/handshake.txt
