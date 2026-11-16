cmake_minimum_required(VERSION 3.20)

project(DLL_LULZ_AI VERSION 0.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DLL_LULZ_BUILD_TESTS "Build unit tests" ON)
option(DLL_LULZ_BUILD_BENCHMARKS "Build opt-in microbenchmarks" OFF)

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

add_library(lulz_core
    src/core/Logger.cpp
    src/loaders/FileLoader.cpp
    src/binary/BinaryReader.cpp
    src/binary/BinaryWriter.cpp
    src/hex/HexParser.cpp
    src/hex/HexFormatter.cpp
    src/formats/common/FormatDetector.cpp
    src/formats/pe/PEParser.cpp
    src/formats/pe/PEExtendedParser.cpp
    src/formats/elf/ELFParser.cpp
    src/formats/dotnet/DotNetParser.cpp
    src/formats/macho/MachOParser.cpp
    src/formats/pe/UnwindInfo.cpp
    src/analysis/EntropyAnalyzer.cpp
    src/analysis/FunctionFinder.cpp
    src/analysis/FunctionAnalysis.cpp
    src/asm/x86/X86Decoder.cpp
    src/asm/x86/X86Encoder.cpp
    src/ai/core/AIEngine.cpp
    src/ai/core/AIContext.cpp
    src/ai/core/AIConfig.cpp
    src/ai/analysis/AIAnalyzer.cpp
    src/ai/analysis/AnalysisReport.cpp
    src/ai/features/FeatureExtractor.cpp
    src/ai/features/ImportFeatures.cpp
    src/ai/features/FunctionFeatures.cpp
    src/ai/features/InstructionFeatures.cpp
    src/ai/neural/NeuralNetwork.cpp
    src/ai/builder/Json.cpp
    src/ai/builder/BuilderAI.cpp
    src/ai/providers/OpenAIClient.cpp
    src/ai/providers/DeepSeekClient.cpp
)

target_include_directories(lulz_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(lulz_core PUBLIC cxx_std_20)
target_link_libraries(lulz_core PRIVATE Zydis)
if(WIN32)
    target_link_libraries(lulz_core PRIVATE winhttp)
endif()

if(MSVC)
    target_compile_options(lulz_core PRIVATE /W4 /permissive- /EHsc /utf-8)
else()
    target_compile_options(lulz_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(dll_lulz app/main.cpp)
target_link_libraries(dll_lulz PRIVATE lulz_core)

if(WIN32)
    add_executable(lulz_gui WIN32 app/gui_main.cpp)
    target_link_libraries(lulz_gui PRIVATE lulz_core comctl32 comdlg32 user32 gdi32)
    target_compile_definitions(lulz_gui PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(lulz_gui PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
endif()

add_executable(lulz_trainer app/trainer.cpp)
target_link_libraries(lulz_trainer PRIVATE lulz_core)

add_executable(lulz_dataset app/dataset_builder.cpp)
target_link_libraries(lulz_dataset PRIVATE lulz_core)

add_executable(lulz_builder app/builder.cpp)
target_link_libraries(lulz_builder PRIVATE lulz_core)

if(DLL_LULZ_BUILD_TESTS)
    enable_testing()
    add_executable(lulz_tests tests/test_main.cpp)
    target_link_libraries(lulz_tests PRIVATE lulz_core)
    if(MSVC)
        target_compile_options(lulz_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(lulz_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME lulz_tests COMMAND lulz_tests)

    add_executable(lulz_builder_tests tests/builder_test.cpp)
    target_link_libraries(lulz_builder_tests PRIVATE lulz_core)
    if(MSVC)
        target_compile_options(lulz_builder_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(lulz_builder_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME lulz_builder_tests COMMAND lulz_builder_tests)

    add_executable(lulz_neural_tests tests/neural_test.cpp)
    target_link_libraries(lulz_neural_tests PRIVATE lulz_core)
    add_test(NAME lulz_neural_tests COMMAND lulz_neural_tests)
    add_test(NAME lulz_trainer_smoke
        COMMAND lulz_trainer
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/synthetic_pe_training.csv
            ${CMAKE_CURRENT_BINARY_DIR}/trainer_smoke.lznn)

    add_executable(lulz_subsystem_tests tests/subsystems_test.cpp)
    target_link_libraries(lulz_subsystem_tests PRIVATE lulz_core)
    if(MSVC)
        target_compile_options(lulz_subsystem_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(lulz_subsystem_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME lulz_subsystem_tests COMMAND lulz_subsystem_tests)

    add_executable(lulz_ai_tests tests/ai_test.cpp)
    target_link_libraries(lulz_ai_tests PRIVATE lulz_core)
    if(MSVC)
        target_compile_options(lulz_ai_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(lulz_ai_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME lulz_ai_tests COMMAND lulz_ai_tests)
endif()

if(DLL_LULZ_BUILD_BENCHMARKS)
    add_executable(lulz_neural_benchmark benchmarks/neural_benchmark.cpp)
    target_link_libraries(lulz_neural_benchmark PRIVATE lulz_core)
endif()

message(STATUS "================================")
message(STATUS " DLL_LULZ_AI ${PROJECT_VERSION}")
message(STATUS " AI Architecture: Dual AI (Analyzer + Builder)")
message(STATUS " AI Core: 0.8.0")
message(STATUS " AI Analysis: 0.8.0")
message(STATUS " AI Features: 0.8.0")
message(STATUS " AI Neural: 0.8.0")
message(STATUS " C++ Standard: 20")
message(STATUS " Unit Tests: ${DLL_LULZ_BUILD_TESTS}")
message(STATUS "================================")
