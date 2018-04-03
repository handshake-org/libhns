#!/bin/sh
set -e

if [ "$BUILD_TYPE" != "cmake" ]; then
    ./buildconf
    $SCAN_WRAP ./configure --disable-symbol-hiding --enable-expose-statics --enable-maintainer-mode --enable-debug $CONFIG_OPTS
    $SCAN_WRAP make
else
    mkdir cmakebld
    cd cmakebld
    cmake -DCMAKE_BUILD_TYPE=DEBUG -DHNS_STATIC=ON -DHNS_STATIC_PIC=ON -DHNS_BUILD_TESTS=ON ..
    make
fi
