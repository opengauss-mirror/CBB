# Copyright (c) 2026 Huawei Technologies Co.,Ltd.
#
# CBB is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# -------------------------------------------------------------------------
#
# CMakeLists.txt
#
#
# IDENTIFICATION
#    src/cm_mes/benchmark/CMakeLists.txt
#
# -------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.14.1)

set(benchmark_SRCS
    mes_benchmark.c
)

add_executable(mes_benchmark ${benchmark_SRCS})

# Include directories
target_include_directories(mes_benchmark PRIVATE
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

# Library directories
target_link_directories(mes_benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/../../../output/lib
    ${CMAKE_SOURCE_DIR}/../../../library/openssl/lib
    ${CMAKE_SOURCE_DIR}/../../../library/zlib/lib
    ${CMAKE_SOURCE_DIR}/../../../library/lz4/lib
    ${CMAKE_SOURCE_DIR}/../../../library/huawei_security/lib
)

# Link against the CBB library and its dependencies
target_link_libraries(mes_benchmark
    cbb
    ssl
    crypto
    z
    lz4
    securec
    pthread
    dl
    rt
)

# Compile options
target_compile_options(mes_benchmark PRIVATE
    -std=c99
    -D_POSIX_C_SOURCE=199309L
    -Wall
    -Wno-error
    -g
    -ggdb
    -O0
)
