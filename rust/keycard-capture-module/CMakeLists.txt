cmake_minimum_required(VERSION 3.14)
project(KeycardCaptureModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

logos_module(NAME keycard_capture_module)

# The Rust keycard client talks to the reader through the macOS PC/SC API (the
# `pcsc` crate). Its `-framework PCSC` link directive lives in the Rust staticlib
# metadata and is not propagated to this C++ plugin link, so add it explicitly.
if(APPLE)
    target_link_libraries(keycard_capture_module_module_plugin PRIVATE "-framework PCSC")
endif()
