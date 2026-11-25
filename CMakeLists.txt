cmake_minimum_required(VERSION 3.20)

if(NOT PROJECT_NAME)
    project(spudec LANGUAGES CXX)
    enable_testing()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SPUDEC_CORE_SOURCES
    src/core/ir.cpp
    src/core/sem.cpp
    src/core/abi.cpp
    src/core/lifter.cpp
    src/core/cfg.cpp
)

# Incrementally attach later-phase core sources as they are created
foreach(_extra_src
    src/core/ssa.cpp
    src/core/opt.cpp
    src/core/lanes.cpp
    src/core/scalarize.cpp
    src/core/outssa.cpp
    src/core/structure.cpp
    src/core/frame.cpp
    src/core/types.cpp
    src/core/ctree.cpp
    src/core/cgen.cpp
    src/core/highlight.cpp
    src/core/user_data.cpp
    src/core/pipeline.cpp
)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_extra_src}")
        list(APPEND SPUDEC_CORE_SOURCES "${_extra_src}")
    endif()
endforeach()

add_library(spudec_core STATIC ${SPUDEC_CORE_SOURCES})

target_include_directories(spudec_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if(WIN32)
    target_compile_definitions(spudec_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

if(MSVC)
    target_compile_options(spudec_core PRIVATE /W3 /EHsc /MP)
    target_compile_options(spudec_core PRIVATE $<$<CONFIG:Release>:/O2 /Oi /Ot>)
else()
    target_compile_options(spudec_core PRIVATE -Wall -Wextra -O3)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ctests/spudec_tests.cpp")
    add_executable(spudec_tests ctests/spudec_tests.cpp)
    target_link_libraries(spudec_tests PRIVATE spudec_core)
    add_test(NAME spudec_tests COMMAND spudec_tests)
endif()

# Resolve IDA SDK root from IDASDK, IDA_SDK_DIR, or integrated ida-sdk tree
set(_DEFAULT_IDA_SDK_DIR "")
if(DEFINED IDASDK AND EXISTS "${IDASDK}/include/ida.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${IDASDK}")
elseif(DEFINED ENV{IDASDK} AND EXISTS "$ENV{IDASDK}/include/ida.hpp")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDASDK}")
elseif(DEFINED IDA_SDK_DIR AND EXISTS "${IDA_SDK_DIR}/include/ida.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/ida.hpp")
    get_filename_component(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ida/plugin.cpp" AND
   (TARGET idasdk::plugin OR (EXISTS "${IDA_SDK_DIR}/include/ida.hpp" AND _IDA_LIB_PATH)))
    set(SPUDEC_IDA_SOURCES
        src/ida/plugin.cpp
    )
    foreach(_ida_src
        src/ida/ida_provider.cpp
        src/ida/summary_cache.cpp
        src/ida/db.cpp
        src/ida/merge.cpp
        src/ida/api_dispatch.cpp
        src/ida/idc_funcs.cpp
        src/ida/view.cpp
    )
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_ida_src}")
            list(APPEND SPUDEC_IDA_SOURCES "${_ida_src}")
        endif()
    endforeach()

    if(COMMAND ida_add_plugin)
        ida_add_plugin(spudec
            SOURCES
                ${SPUDEC_IDA_SOURCES}
            LIBRARIES
                spudec_core
        )
    else()
        add_library(spudec SHARED ${SPUDEC_IDA_SOURCES})
        set_target_properties(spudec PROPERTIES
            PREFIX ""
            OUTPUT_NAME "spudec"
        )
        if(TARGET idasdk::plugin)
            target_link_libraries(spudec PRIVATE spudec_core idasdk::plugin)
        else()
            target_include_directories(spudec PRIVATE "${IDA_SDK_DIR}/include")
            target_compile_definitions(spudec PRIVATE
                __NT__ __EA64__ __X64__ __IDP__
                USE_DANGEROUS_FUNCTIONS USE_STANDARD_FILE_FUNCTIONS
                _CRT_SECURE_NO_WARNINGS NOMINMAX
            )
            target_link_libraries(spudec PRIVATE spudec_core "${_IDA_LIB_PATH}")
        endif()
    endif()

    if(MSVC)
        target_compile_options(spudec PRIVATE /EHsc /MP $<$<CONFIG:Release>:/O2 /Oi /Ot>)
        target_link_options(spudec PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    endif()

    if(WIN32 AND DEFINED ENV{APPDATA})
        set(_IDA_USER_PLUGINS "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins")
        add_custom_target(spudec_deploy
            DEPENDS spudec
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${_IDA_USER_PLUGINS}"
            COMMAND "${CMAKE_COMMAND}" -E rm -f "${_IDA_USER_PLUGINS}/spudec_plugin.py"
            COMMAND "${CMAKE_COMMAND}" -E rm -rf "${_IDA_USER_PLUGINS}/spudec"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:spudec>" "${_IDA_USER_PLUGINS}/spudec.dll"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/python_sdk/spudec_hexrays_bridge.py" "${_IDA_USER_PLUGINS}/spudec_hexrays_bridge.py"
            COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/python_sdk/spudec" "${_IDA_USER_PLUGINS}/spudec"
            COMMENT "Deploying native spudec.dll + Python SDK to ${_IDA_USER_PLUGINS}"
        )
    endif()
endif()
