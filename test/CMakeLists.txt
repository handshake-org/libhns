set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

enable_language(CXX)

find_package(Threads)

# create target to access and use internal hns library
set(HNS_SRC_DIR ${hns_SOURCE_DIR})
add_library(hnsinternal INTERFACE)
target_compile_definitions(hnsinternal INTERFACE HAVE_CONFIG_H=1)
target_include_directories(hnsinternal INTERFACE ${HNS_SRC_DIR})
target_link_libraries(hnsinternal INTERFACE ${PROJECT_NAME})

# Google Test and Mock
set(GMOCK_DIR gmock-1.8.0)
add_library(gmock STATIC
  ${GMOCK_DIR}/gmock-gtest-all.cc
  ${GMOCK_DIR}/gmock/gmock.h
  ${GMOCK_DIR}/gtest/gtest.h
)
target_include_directories(gmock PUBLIC SYSTEM ${GMOCK_DIR})
target_link_libraries(gmock PRIVATE ${CMAKE_THREAD_LIBS_INIT})

# test targets

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

configure_file(${HNS_SRC_DIR}/hns_config.h.cmake config.h)

add_executable(hnstest ${TESTSOURCES} ${TESTHEADERS})
target_include_directories(hnstest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hnstest PRIVATE hnsinternal gmock)

add_executable(hnsfuzz ${FUZZSOURCES})
target_link_libraries(hnsfuzz PRIVATE hnsinternal)

add_executable(hnsfuzzname ${FUZZNAMESOURCES})
target_link_libraries(hnsfuzzname PRIVATE hnsinternal)

add_executable(dnsdump ${DUMPSOURCES})
target_link_libraries(dnsdump PRIVATE hnsinternal)

# register tests

add_test(NAME hnstest COMMAND $<TARGET_FILE:hnstest>)

file(GLOB_RECURSE FUZZINPUT_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput" "fuzzinput/*")
add_test(
  NAME hnsfuzz
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput"
  COMMAND $<TARGET_FILE:hnsfuzz> ${FUZZINPUT_FILES}
)

file(GLOB_RECURSE FUZZNAMES_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames" "fuzznames/*")
add_test(
  NAME hnsfuzzname
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames"
  COMMAND $<TARGET_FILE:hnsfuzzname> ${FUZZNAMES_FILES}
)
