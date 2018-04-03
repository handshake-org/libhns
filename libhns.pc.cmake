#***************************************************************************
# Project        ___       __ _ _ __ ___  ___ 
#               / __|____ / _` | '__/ _ \/ __|
#              | (_|_____| (_| | | |  __/\__ \
#               \___|     \__,_|_|  \___||___/
#
prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}/@CMAKE_INSTALL_BINDIR@
libdir=${prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: hns
URL: https://c-ares.haxx.se/
Description: asynchronous DNS lookup library
Version: @HNS_VERSION@
Requires: 
Requires.private: 
Cflags: -I${includedir} @CPPFLAG_HNS_STATICLIB@
Libs: -L${libdir} -lhns
Libs.private: @HNS_PRIVATE_LIBS@
