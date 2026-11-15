#include "ai/builder/BuilderAI.hpp"
#include "ai/builder/Json.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main() {
    using namespace lulz::ai::builder;

    const auto valid = JsonParser(R"({"project":"TestApp","files":[{"path":"src/main.cpp","content":"int main(){return 0;}"}]})").parse();
    assert(valid.success);
    assert(valid.value.get("project") != nullptr);

    assert(!JsonParser(R"({"x":1,"x":2})").parse().success);
    assert(!JsonParser(R"({"x":[1,2,]})").parse().success);
    assert(!JsonParser(R"({"x":"unterminated})").parse().success);

    const auto base = std::filesystem::temp_directory_path() / "lulz_builder_ai_test";
    std::error_code ec;
    std::filesystem::remove_all(base, ec);

    BuilderOptions options;
    options.outputDirectory = base;

    const std::string project =
        R"({"project":"GeneratedSample","files":[)"
        R"({"path":"src/main.cpp","content":"#include <iostream>\nint main(){std::cout << \"ok\";}\n"},)"
        R"({"path":"CMakeLists.txt","content":"cmake_minimum_required(VERSION 3.20)\nproject(GeneratedSample)\n"})"
        R"(]})";

    const auto report = BuilderAI{}.buildFromJson(project, options);
    assert(report.success);
    assert(report.createdFiles.size() == 2);
    assert(std::filesystem::exists(base / "GeneratedSample" / "src" / "main.cpp"));
    assert(std::filesystem::exists(base / "GeneratedSample" / "CMakeLists.txt"));

    const std::string traversal =
        R"({"project":"BadProject","files":[{"path":"../outside.txt","content":"bad"}]})";
    const auto rejected = BuilderAI{}.buildFromJson(traversal, options);
    assert(!rejected.success);

    const auto duplicate =
        R"({"project":"BadProject","files":[{"path":"a.txt","content":"1"},{"path":"a.txt","content":"2"}]})";
    assert(!BuilderAI{}.buildFromJson(duplicate, options).success);

    const auto noOverwrite = BuilderAI{}.buildFromJson(project, options);
    assert(!noOverwrite.success);

    std::filesystem::remove_all(base, ec);

    // Analyzer JSON is accepted directly and converted into typed C++ source files.
    const std::string analyzerReport = R"({
      "format":"PE32+ x64",
      "image_base":"0x140000000",
      "pe_metadata":{
        "exports":[{"name":"ExampleExport","ordinal":7,"rva":"0x2100","forwarded":false,"forwarder":""}],
        "certificates":[{"length":8,"revision":512,"certificate_type":2,"file_offset":1024}],
        "base_relocations":[{"page_rva":"0x1000","target_rva":"0x1010","type":10}],
        "debug_entries":[{"timestamp":1,"type":2,"size":8,"raw_pointer":2048}],
        "tls":{"callbacks":["0x1100"]}
      },
      "imports":[{"module":"KERNEL32.dll","name":"CreateFileW","iat_rva":"0x3000"}],
      "functions":[{"begin_rva":"0x1000","end_rva":"0x1020","unwind_rva":"0x4000","size":32,"stack_consumed":40,
        "calls":[{"instruction_rva":"0x1008","kind":"call_rel32","target_rva":"0x2000","target":"function 0x2000","resolved":true}]}]
    })";
    BuilderOptions analysisOptions;
    analysisOptions.outputDirectory = base / "analysis-output";
    const auto generated = BuilderAI{}.buildFromJson(analyzerReport, analysisOptions);
    assert(generated.success);
    assert(std::filesystem::exists(generated.projectDirectory / "include" / "analysis" / "AnalysisData.hpp"));
    assert(std::filesystem::exists(generated.projectDirectory / "src" / "AnalysisData.cpp"));
    assert(std::filesystem::exists(generated.projectDirectory / "src" / "main.cpp"));
    assert(std::filesystem::exists(generated.projectDirectory / "analysis" / "source.json"));
    std::ifstream generatedCpp(generated.projectDirectory / "src" / "AnalysisData.cpp", std::ios::binary);
    const std::string generatedText((std::istreambuf_iterator<char>(generatedCpp)), std::istreambuf_iterator<char>());
    assert(generatedText.find("ExampleExport") != std::string::npos);
    assert(generatedText.find("0x1100") != std::string::npos);

    std::filesystem::remove_all(base, ec);
    std::cout << "Builder AI tests passed\n";
    return 0;
}
