#!/bin/sh
set -e
if [ "$BUILD_TYPE" != "ios" -a "$BUILD_TYPE" != "analyse" -a "$BUILD_TYPE" != "cmake" ]; then
    $TEST_WRAP ./hdig www.google.com
    $TEST_WRAP ./hcountry www.google.com
    $TEST_WRAP ./hhost www.google.com
    cd test
    make
    $TEST_WRAP ./hnstest -4 -v $TEST_FILTER
    ./fuzzcheck.sh
    ./dnsdump  fuzzinput/answer_a fuzzinput/answer_aaaa
    cd ..
elif [ "$BUILD_TYPE" = "cmake" ] ; then
    TESTDIR=../../test/
    cd cmakebld/bin
    $TEST_WRAP ./hdig www.google.com
    $TEST_WRAP ./hcountry www.google.com
    $TEST_WRAP ./hhost www.google.com
    $TEST_WRAP ./hnstest -4 -v $TEST_FILTER
    ./hnsfuzz $TESTDIR/fuzzinput/*
    ./hnsfuzzname $TESTDIR/fuzznames/*
    ./dnsdump $TESTDIR/fuzzinput/answer_a $TESTDIR/fuzzinput/answer_aaaa
    cd ../..
fi
