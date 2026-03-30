# CMakeLists.txt for UBS Memory Mock Library

add_library(ubsm_sdk SHARED ubs_mem_mock.c)

target_include_directories(ubsm_sdk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_options(ubsm_sdk PRIVATE
    -Wno-error
    -g
    -O0
)

set_target_properties(ubsm_sdk PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "ubsm_sdk"
    VERSION 1.0.0
    SOVERSION 1
)

install(TARGETS ubsm_sdk
    LIBRARY DESTINATION lib
)
