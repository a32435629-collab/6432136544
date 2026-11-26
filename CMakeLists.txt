cmake_minimum_required(VERSION 3.20)

project(DLL_LULZ_AI VERSION 0.9.0 LANGUAGES CXX)

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

    # Binary Intelligence Foundation
    src/binary/BinaryImage.cpp
    src/binary/BinaryView.cpp
    src/binary/BinaryValidation.cpp
    src/binary/BinaryFormats.cpp
    src/binary/BinaryReader.cpp
    src/binary/BinaryWriter.cpp

    # Hex and format parsers
    src/hex/HexParser.cpp
    src/hex/HexFormatter.cpp
    src/formats/common/FormatDetector.cpp
    src/formats/pe/PEParser.cpp
    src/formats/pe/PEExtendedParser.cpp
    src/formats/pe/PEWindowsMetadata.cpp
    src/formats/elf/ELFParser.cpp
    src/formats/dotnet/DotNetParser.cpp
    src/formats/macho/MachOParser.cpp
    src/formats/pe/UnwindInfo.cpp

    # Analysis and disassembly
    src/analysis/EntropyAnalyzer.cpp
    src/analysis/FunctionFinder.cpp
    src/analysis/FunctionAnalysis.cpp
    src/analysis/InstructionIR.cpp
    src/asm/x86/X86Decoder.cpp
    src/asm/x86/X86Encoder.cpp

    # AI Core
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
    src/ai/builder/BuilderLearning.cpp
    src/ai/providers/OpenAIClient.cpp
    src/ai/providers/DeepSeekClient.cpp
)

target_include_directories(lulz_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

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

# Main CLI
add_executable(dll_lulz app/main.cpp)
target_link_libraries(dll_lulz PRIVATE lulz_core)

# Windows GUI
if(WIN32)
    add_executable(lulz_gui WIN32 app/gui_main.cpp)
    target_link_libraries(lulz_gui PRIVATE
        lulz_core
        comctl32
        comdlg32
        shell32
        user32
        gdi32
    )
    target_compile_definitions(lulz_gui PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    if(MSVC)
        target_compile_options(lulz_gui PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
endif()

# AI applications
add_executable(lulz_trainer app/trainer.cpp)
target_link_libraries(lulz_trainer PRIVATE lulz_core)

add_executable(lulz_dataset app/dataset_builder.cpp)
target_link_libraries(lulz_dataset PRIVATE lulz_core)

add_executable(lulz_builder app/builder.cpp)
target_link_libraries(lulz_builder PRIVATE lulz_core)

add_executable(lulz_builder_trainer app/builder_trainer.cpp)
target_link_libraries(lulz_builder_trainer PRIVATE lulz_core)

# Tests
if(DLL_LULZ_BUILD_TESTS)
    enable_testing()

    add_executable(lulz_tests tests/test_main.cpp)
    target_link_libraries(lulz_tests PRIVATE lulz_core)

    add_executable(lulz_builder_learning_tests tests/builder_learning_test.cpp)
    target_link_libraries(lulz_builder_learning_tests PRIVATE lulz_core)

    add_executable(lulz_builder_tests tests/builder_test.cpp)
    target_link_libraries(lulz_builder_tests PRIVATE lulz_core)

    add_executable(lulz_neural_tests tests/neural_test.cpp)
    target_link_libraries(lulz_neural_tests PRIVATE lulz_core)

    add_executable(lulz_subsystem_tests tests/subsystems_test.cpp)
    target_link_libraries(lulz_subsystem_tests PRIVATE lulz_core)

    add_executable(lulz_ai_tests tests/ai_test.cpp)
    target_link_libraries(lulz_ai_tests PRIVATE lulz_core)

    add_executable(lulz_binary_foundation_tests tests/binary_foundation_test.cpp)
    target_link_libraries(lulz_binary_foundation_tests PRIVATE lulz_core)

    add_executable(lulz_pe_windows_metadata_tests tests/pe_windows_metadata_test.cpp)
    add_executable(lulz_instruction_ir_tests tests/instruction_ir_test.cpp)
    add_executable(lulz_macho_dyld_rebase_tests tests/macho_dyld_rebase_test.cpp)
    target_link_libraries(lulz_macho_dyld_rebase_tests PRIVATE lulz_core)
    target_link_libraries(lulz_instruction_ir_tests PRIVATE lulz_core)
    target_link_libraries(lulz_pe_windows_metadata_tests PRIVATE lulz_core)

    if(MSVC)
        foreach(test_target
            lulz_tests
            lulz_builder_learning_tests
            lulz_builder_tests
            lulz_subsystem_tests
            lulz_ai_tests
            lulz_pe_windows_metadata_tests
            lulz_macho_dyld_rebase_tests
            lulz_instruction_ir_tests
            lulz_macho_dyld_rebase_tests
        )
            target_compile_options(${test_target} PRIVATE /UNDEBUG)
        endforeach()
    else()
        foreach(test_target
            lulz_tests
            lulz_builder_learning_tests
            lulz_builder_tests
            lulz_subsystem_tests
            lulz_ai_tests
            lulz_pe_windows_metadata_tests
        )
            target_compile_options(${test_target} PRIVATE -UNDEBUG)
        endforeach()
    endif()

    add_test(NAME lulz_tests COMMAND lulz_tests)
    add_test(NAME lulz_builder_learning_tests COMMAND lulz_builder_learning_tests)
    add_test(NAME lulz_builder_tests COMMAND lulz_builder_tests)
    add_test(NAME lulz_neural_tests COMMAND lulz_neural_tests)

    add_test(
        NAME lulz_trainer_smoke
        COMMAND lulz_trainer
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/synthetic_pe_training.csv
            ${CMAKE_CURRENT_BINARY_DIR}/trainer_smoke.lznn
    )

    add_test(NAME lulz_subsystem_tests COMMAND lulz_subsystem_tests)
    add_test(NAME lulz_ai_tests COMMAND lulz_ai_tests)
    add_test(NAME lulz_binary_foundation_tests COMMAND lulz_binary_foundation_tests)
    add_test(NAME lulz_pe_windows_metadata_tests COMMAND lulz_pe_windows_metadata_tests)
    add_test(NAME lulz_instruction_ir_tests COMMAND lulz_instruction_ir_tests)
    add_test(NAME lulz_macho_dyld_rebase_tests COMMAND lulz_macho_dyld_rebase_tests)
endif()

# Optional benchmarks
if(DLL_LULZ_BUILD_BENCHMARKS)
    add_executable(lulz_neural_benchmark benchmarks/neural_benchmark.cpp)
    target_link_libraries(lulz_neural_benchmark PRIVATE lulz_core)
endif()

message(STATUS "================================")
message(STATUS " DLL_LULZ_AI ${PROJECT_VERSION}")
message(STATUS " AI Architecture: Dual AI (Analyzer + Builder)")
message(STATUS " AI Core: 0.9.0 Binary Intelligence Foundation")
message(STATUS " AI Analysis: 0.8.0")
message(STATUS " AI Features: 0.8.0")
message(STATUS " AI Neural: 0.8.0")
message(STATUS " C++ Standard: 20")
message(STATUS " Unit Tests: ${DLL_LULZ_BUILD_TESTS}")
message(STATUS "================================")
