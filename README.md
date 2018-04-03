hns
======

[![Build Status](https://travis-ci.org/hns/hns.svg?branch=master)](https://travis-ci.org/hns/hns)
[![Windows Build Status](https://ci.appveyor.com/api/projects/status/03i7151772eq3wn3/branch/master?svg=true)](https://ci.appveyor.com/project/hns/hns)
[![Coverage Status](https://coveralls.io/repos/hns/hns/badge.svg?branch=master&service=github)](https://coveralls.io/github/hns/hns?branch=master)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/291/badge)](https://bestpractices.coreinfrastructure.org/projects/291)
[![Releases](https://coderelease.io/badge/hns/hns)](https://coderelease.io/github/repository/hns/hns)

This is hns, an asynchronous resolver library.  It is intended for
applications which need to perform DNS queries without blocking, or need to
perform multiple DNS queries in parallel.  The primary examples of such
applications are servers which communicate with multiple clients and programs
with graphical user interfaces.

The full source code is available in the ['hns' release archives](https://c-ares.haxx.se/download/),
and in a git repository: http://github.com/hns/hns.  See the
[INSTALL.md](INSTALL.md) file for build information.

If you find bugs, correct flaws, have questions or have comments in general in
regard to hns (or by all means the original hns too), get in touch with us
on the hns mailing list: http://cool.haxx.se/mailman/listinfo/c-ares

hns is of course distributed under the same MIT-style license as the
original hns.

You'll find all hns details and news here:
        https://c-ares.haxx.se/


Notes for hns hackers
------------------------

* The distributed `hns_build.h` file is only intended to be used on systems
  which can not run the also distributed configure script.

* The distributed `hns_build.h` file is generated as a copy of `hns_build.h.dist`
  when the hns source code distribution archive file is originally created.

* If you check out from git on a non-configure platform, you must run the
  appropriate `buildconf*` script to set up `hns_build.h` and other local files
  before being able to compile the library.

* On systems capable of running the `configure` script, the `configure` process
  will overwrite the distributed `hns_build.h` file with one that is suitable
  and specific to the library being configured and built, this new file is
  generated from the `hns_build.h.in` template file.

* If you intend to distribute an already compiled hns library you **MUST**
  also distribute along with it the generated `hns_build.h` which has been
  used to compile it. Otherwise the library will be of no use for the users of
  the library that you have built. It is **your** responsibility to provide this
  file. No one at the hns project can know how you have built the library.

* File `hns_build.h` includes platform and configuration dependent info,
  and must not be modified by anyone. Configure script generates it for you.

* We cannot assume anything else but very basic compiler features being
  present. While hns requires an ANSI C compiler to build, some of the
  earlier ANSI compilers clearly can't deal with some preprocessor operators.

* Newlines must remain unix-style for older compilers' sake.

* Comments must be written in the old-style /* unnested C-fashion */

* Try to keep line lengths below 80 columns.
