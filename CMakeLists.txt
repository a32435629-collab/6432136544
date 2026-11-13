
cmake_minimum_required(VERSION 3.20)

project(DLL_LULZ_AI VERSION 0.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DLL_LULZ_BUILD_TESTS "Build unit tests" ON)

# Full x86/x64 instruction decoding for control-flow analysis.
include(FetchContent)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_FORMATTER OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG v4.1.1
    GIT_SHALLOW TRUE
    GIT_SUBMODULES_RECURSE TRUE
)
FetchContent_MakeAvailable(zydis)

# ==========================================
# Core library
# ==========================================

add_library(lulz_core

    # Core
    src/core/Logger.cpp

    # Loaders
    src/loaders/FileLoader.cpp

    # Binary
    src/binary/BinaryReader.cpp
    src/binary/BinaryWriter.cpp

    # HEX
    src/hex/HexParser.cpp
    src/hex/HexFormatter.cpp

    # Format detection
    src/formats/common/FormatDetector.cpp

    # PE
    src/formats/pe/PEParser.cpp
    src/formats/pe/UnwindInfo.cpp

    # Analysis
    src/analysis/EntropyAnalyzer.cpp
    src/analysis/FunctionFinder.cpp
    src/analysis/FunctionAnalysis.cpp

    # ASM
    src/asm/x86/X86Decoder.cpp
    src/asm/x86/X86Encoder.cpp

    # AI Core
    src/ai/core/AIEngine.cpp
    src/ai/core/AIContext.cpp
    src/ai/core/AIConfig.cpp

    # AI Analysis
    src/ai/analysis/AIAnalyzer.cpp
    src/ai/analysis/AnalysisReport.cpp

    # AI Features
    src/ai/features/FeatureExtractor.cpp
    src/ai/features/ImportFeatures.cpp
    src/ai/features/FunctionFeatures.cpp
    src/ai/features/InstructionFeatures.cpp
)

# ==========================================
# Include directories
# ==========================================

target_include_directories(lulz_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(lulz_core PUBLIC cxx_std_20)
target_link_libraries(lulz_core PRIVATE Zydis)

# ==========================================
# Compiler options
# ==========================================

if(MSVC)

    target_compile_options(lulz_core PRIVATE
        /W4
        /permissive-
        /EHsc
        /utf-8
    )

else()

    target_compile_options(lulz_core PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )

endif()

# ==========================================
# Main executable
# ==========================================

add_executable(dll_lulz
    app/main.cpp
)

target_link_libraries(dll_lulz
    PRIVATE lulz_core
)

# ==========================================
# Unit tests
# ==========================================

if(DLL_LULZ_BUILD_TESTS)

    enable_testing()

    add_executable(lulz_tests
        tests/test_main.cpp
    )

    target_link_libraries(lulz_tests
        PRIVATE lulz_core
    )

    # Keep assert-based checks active in Release configurations.
    if(MSVC)
        target_compile_options(lulz_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(lulz_tests PRIVATE -UNDEBUG)
    endif()

    add_test(
        NAME lulz_tests
        COMMAND lulz_tests
    )

endif()

# ==========================================
# Build information
# ==========================================

message(STATUS "================================")
message(STATUS " DLL_LULZ_AI ${PROJECT_VERSION}")
message(STATUS " AI Core: 0.1.0")
message(STATUS " AI Analysis: 0.1.0")
message(STATUS " AI Features: 0.1.0")
message(STATUS " C++ Standard: 20")
message(STATUS " Unit Tests: ${DLL_LULZ_BUILD_TESTS}")
message(STATUS "================================")
