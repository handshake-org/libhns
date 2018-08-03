prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}/@CMAKE_INSTALL_BINDIR@
libdir=${prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: hns
URL: https://github.com/handshake-org/libhns
Description: asynchronous HNS lookup library
Version: @HNS_VERSION@
Requires:
Requires.private:
Cflags: -I${includedir} @CPPFLAG_HNS_STATICLIB@
Libs: -L${libdir} -lhns
Libs.private: @HNS_PRIVATE_LIBS@
