if(COMMAND idf_component_register)
    # This directory can be placed directly in ESP-IDF's
    # EXTRA_COMPONENT_DIRS. Keep this branch free of host-test machinery.
    idf_component_register(
        SRCS
            "src/glyph.c"
            "src/temporal.c"
        INCLUDE_DIRS
            "include")
    target_compile_features(${COMPONENT_LIB} PUBLIC c_std_11)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    return()
endif()

cmake_minimum_required(VERSION 3.20)

project(fractonica_embedded_c VERSION 0.1.0 LANGUAGES C)

add_library(fractonica_embedded_glyph STATIC src/glyph.c)
add_library(fractonica::embedded_glyph ALIAS fractonica_embedded_glyph)

add_library(fractonica_embedded_temporal STATIC src/temporal.c)
add_library(fractonica::embedded_temporal ALIAS fractonica_embedded_temporal)

add_library(fractonica_embedded INTERFACE)
add_library(fractonica::embedded ALIAS fractonica_embedded)
target_link_libraries(
    fractonica_embedded
    INTERFACE
        fractonica_embedded_glyph
        fractonica_embedded_temporal)

target_compile_features(fractonica_embedded_glyph PUBLIC c_std_11)
set_target_properties(fractonica_embedded_glyph PROPERTIES
    C_EXTENSIONS OFF
    C_STANDARD_REQUIRED YES)
target_include_directories(fractonica_embedded_glyph
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

if(MSVC)
    target_compile_options(fractonica_embedded_glyph PRIVATE /W4 /WX)
else()
    target_compile_options(fractonica_embedded_glyph PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

target_compile_features(fractonica_embedded_temporal PUBLIC c_std_11)
set_target_properties(fractonica_embedded_temporal PROPERTIES
    C_EXTENSIONS OFF
    C_STANDARD_REQUIRED YES)
target_include_directories(fractonica_embedded_temporal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
if(MSVC)
    target_compile_options(fractonica_embedded_temporal PRIVATE /W4 /WX)
else()
    target_compile_options(fractonica_embedded_temporal PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# cosf/sinf live in libm on Unix-like host toolchains. ESP-IDF and many
# embedded toolchains provide them through their standard C runtime instead.
if(UNIX AND NOT APPLE)
    target_link_libraries(fractonica_embedded_glyph PUBLIC m)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(fractonica_embedded_glyph_tests tests/glyph_test.c)
    target_compile_features(fractonica_embedded_glyph_tests PRIVATE c_std_11)
    target_link_libraries(fractonica_embedded_glyph_tests PRIVATE fractonica_embedded_glyph)
    if(MSVC)
        target_compile_options(fractonica_embedded_glyph_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(fractonica_embedded_glyph_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME fractonica_embedded_glyph_tests COMMAND fractonica_embedded_glyph_tests)

    add_executable(fractonica_embedded_temporal_tests tests/temporal_test.c)
    target_compile_features(fractonica_embedded_temporal_tests PRIVATE c_std_11)
    target_link_libraries(fractonica_embedded_temporal_tests PRIVATE fractonica_embedded_temporal)
    if(MSVC)
        target_compile_options(fractonica_embedded_temporal_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(fractonica_embedded_temporal_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME fractonica_embedded_temporal_tests COMMAND fractonica_embedded_temporal_tests)

    enable_language(CXX)
    add_executable(
        fractonica_embedded_glyph_cpp_consumer_test
        tests/glyph_cpp_consumer_test.cpp)
    target_compile_features(
        fractonica_embedded_glyph_cpp_consumer_test
        PRIVATE
            cxx_std_17)
    target_link_libraries(
        fractonica_embedded_glyph_cpp_consumer_test
        PRIVATE
            fractonica_embedded)
    if(MSVC)
        target_compile_options(fractonica_embedded_glyph_cpp_consumer_test PRIVATE /W4 /WX)
    else()
        target_compile_options(
            fractonica_embedded_glyph_cpp_consumer_test
            PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Werror)
    endif()
    add_test(
        NAME fractonica_embedded_glyph_cpp_consumer_test
        COMMAND fractonica_embedded_glyph_cpp_consumer_test)
endif()
