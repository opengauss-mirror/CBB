# CMakeLists.txt for CBB MES RTT performance verification tool

# Add mes_rtt_perf executable
add_executable(mes_rtt_perf mes_rtt_perf.c)
target_include_directories(mes_rtt_perf PRIVATE
    ${CMAKE_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/../..
    ${CMAKE_SOURCE_DIR}/../../cm_defines
    ${CMAKE_SOURCE_DIR}/../../cm_concurrency
    ${CMAKE_SOURCE_DIR}/../../cm_struct
    ${CMAKE_SOURCE_DIR}/../../cm_time
    ${CMAKE_SOURCE_DIR}/../../cm_types
    ${CMAKE_SOURCE_DIR}/../../cm_utils
    ${CMAKE_SOURCE_DIR}/../../cm_security
    ${CMAKE_SOURCE_DIR}/../../cm_protocol
    ${CMAKE_SOURCE_DIR}/../../../library/huawei_security/include
    ${CMAKE_SOURCE_DIR}/../../../library/openssl/include
    ${CMAKE_SOURCE_DIR}/../../../library/zlib/include
    ${CMAKE_SOURCE_DIR}/../../../library/lz4/include
)
target_link_directories(mes_rtt_perf PRIVATE
    ${CMAKE_SOURCE_DIR}/../../output/lib
    ${CMAKE_SOURCE_DIR}/../../../library/openssl/lib
    ${CMAKE_SOURCE_DIR}/../../../library/zlib/lib
    ${CMAKE_SOURCE_DIR}/../../../library/lz4/lib
    ${CMAKE_SOURCE_DIR}/../../../library/huawei_security/lib
)
target_link_libraries(mes_rtt_perf
    cbb ssl crypto z lz4 securec pthread dl rt m
    -Wl,--whole-archive -Wl,-Bstatic ${vpp_libsecurec} ${zlib} -Wl,-Bdynamic -Wl,--no-whole-archive
)
target_compile_options(mes_rtt_perf PRIVATE -std=c99 -D_POSIX_C_SOURCE=199309L -Wall -Wno-error -g -ggdb -O0)
