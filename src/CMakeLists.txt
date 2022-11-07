## include
include_directories(${CBB_CONCURRENCY_PATH})
include_directories(${CBB_DEFINE_PATH})
include_directories(${CBB_NETWORK_PATH})
include_directories(${CBB_SECURITY_PATH})
include_directories(${CBB_STRUCT_PATH})
include_directories(${CBB_TIME_PATH})
include_directories(${CBB_TYPE_PATH})
include_directories(${CBB_UTIL_PATH})
include_directories(${CBB_MES_PATH})
include_directories(${CBB_PROTOCOL_PATH})
include_directories(${CBB_JSON_PATH})
include_directories(${CBB_LEXER_PATH})
include_directories(${CBB_INTERFACE_PATH})
include_directories(${CBB_SERVICE_PATH})

include_directories(.)

## other dependency include 
include_directories(${CBB_SECUREC_INC_PATH})
include_directories(${CBB_OPENSSL_PATH})

## source
aux_source_directory(./ COMMON_SRC)
aux_source_directory(./cm_concurrency CM_CONCURRENCY_SRC)
aux_source_directory(./cm_defines CM_DEFINES_SRC)
aux_source_directory(./cm_network CM_NETWORK_SRC)
aux_source_directory(./cm_struct CM_STRUCT_SRC)
aux_source_directory(./cm_time CM_TIME_SRC)
aux_source_directory(./cm_types CM_TYPE_SRC)
aux_source_directory(./cm_utils CM_UTILS_SRC)
aux_source_directory(./cm_security CM_SECURITY_SRC)
aux_source_directory(./cm_mes CM_MES_SRC)
aux_source_directory(./cm_protocol CM_PROTOCOL_SRC)
aux_source_directory(./cm_res CM_RES_SRC)
aux_source_directory(./ddes_json CM_JSON_SRC)
aux_source_directory(./ddes_lexer CM_LEXER_SRC)
aux_source_directory(./ddes_perctrl/interface CM_INTERFACE_SRC)
aux_source_directory(./ddes_perctrl/service CM_SERVICE_SRC)

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${CM_DEFINES_SRC}
        ${CM_CONCURRENCY_SRC}
        ${CM_NETWORK_SRC}
        ${CM_STRUCT_SRC}
        ${CM_TIME_SRC}
        ${CM_TYPE_SRC}
        ${CM_UTILS_SRC}
        ${CM_SECURITY_SRC}
        ${CM_MES_SRC}
        ${CM_PROTOCOL_SRC}
        ${CM_RES_SRC}
        ${CM_JSON_SRC}
        ${CM_LEXER_SRC}
        ${CM_INTERFACE_SRC}
        )

add_library(cbb SHARED ${COMMON_ALL_SRC})
target_link_libraries(cbb ${3rd_libssl} pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} -Wl,--no-whole-archive)

add_library(cbb_static STATIC ${COMMON_ALL_SRC})
set_property(TARGET cbb_static PROPERTY OUTPUT_NAME "cbb")
target_link_libraries(cbb_static ${3rd_libssl} pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} -Wl,--no-whole-archive)

add_library(cbb_static_master STATIC ${COMMON_ALL_SRC})
set_property(TARGET cbb_static_master PROPERTY OUTPUT_NAME "cbb_static")
target_link_libraries(cbb_static_master ${3rd_libssl} pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} -Wl,--no-whole-archive)

set(PERSIST_SRC
        ${CM_STRUCT_SRC}
        ${CM_TIME_SRC}
        ${CM_TYPE_SRC}
        ${CM_UTILS_SRC}
        ${CM_CONCURRENCY_SRC}
        ${CM_DEFINES_SRC}
        ${CM_INTERFACE_SRC}
        ${CM_SERVICE_SRC}
        )

ADD_EXECUTABLE(perctrl ${PERSIST_SRC})
target_link_libraries(perctrl pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} -Wl,--no-whole-archive)