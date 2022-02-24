cmake_minimum_required(VERSION 3.14.1)
project(cbb)

set(CMAKE_INSTALL_PREFIX $ENV{cbb_install_prefix})

message(STATUS "BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
     OR ${CMAKE_BUILD_TYPE} STREQUAL "")
    message(STATUS "CMAKE_BUILD_TYPE is Debug")
    set(CMAKE_BUILD_TYPE Debug)
    set(CMAKE_CXX_FLAGS_DEBUG -DDB_DEBUG_VERSION)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    message(STATUS "CMAKE_BUILD_TYPE is Release")
    set(CMAKE_BUILD_TYPE Release)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
else ()
    message(FATAL_ERROR "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
endif ()

set(CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS}")

add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -lpthread)
add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT __PERF_STAT__)
add_link_options(-pie)
add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)

# Secure Compilation Options
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ldl -pthread -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-freg-struct-return)
add_compile_options(-pipe)
add_compile_options(-Wl,-Bsymbolic)
add_compile_options(-rdynamic)


OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_GCOV = ${ENABLE_GCOV}")
IF (ENABLE_GCOV AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable gcov (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
ENDIF()

OPTION(ENABLE_EXPORT_API "Enable hidden internal api" OFF)
message(STATUS "ENABLE_EXPORT_API = ${ENABLE_EXPORT_API}")
IF (ENABLE_EXPORT_API)
    message(STATUS "Enable only dcf_interface.h file's api to external systems.")
    add_compile_options(-fvisibility=hidden)
ENDIF()

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE OS_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})
if (OS_ARCH STREQUAL "aarch64")
    option(USE_H1620 OFF)
    if (USE_H1620)
        add_compile_options(-march=armv8-a+crc+lse)
        message(STATUS "Toolchain: Build aarch64 USE_H1620")
    else ()
        add_compile_options(-march=armv8-a+crc)
    endif (USE_H1620)

    add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
else ()
    add_compile_options(-msse4.2 )
endif ()
Add_Definitions(-DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110 -DWSEC_COMPILE_SDP)

## CBB include
set(CBB_CONCURRENCY_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_concurrency)
set(CBB_DEFINE_PATH             ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_defines)
set(CBB_NETWORK_PATH            ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_network)
set(CBB_SECURITY_PATH           ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_security)
set(CBB_STRUCT_PATH             ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_struct)
set(CBB_TIME_PATH               ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_time)
set(CBB_TYPE_PATH               ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_types)
set(CBB_UTIL_PATH               ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_utils)
set(CBB_MES_PATH                ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_mes)
set(CBB_PROTOCOL_PATH           ${CMAKE_CURRENT_SOURCE_DIR}/src/cm_protocol)

## other dependency include
set(CBB_SECUREC_INC_PATH        "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/include/")
set(CBB_OPENSSL_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/include/")

## lib
set(SECUREC_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/lib/")
set(OPENSSL_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/lib/")

## output path
set (LIBRARY_OUTPUT_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/output/lib)
set (EXECUTABLE_OUTPUT_PATH     ${CMAKE_CURRENT_SOURCE_DIR}/output/bin)

link_directories(${LIBRARY_OUTPUT_PATH} ${SECUREC_LIB_PATH} ${OPENSSL_LIB_PATH})

set(vpp_libsecurec "securec")
set(3rd_libssl "ssl")
set(sdp "sdp")

add_subdirectory(src)