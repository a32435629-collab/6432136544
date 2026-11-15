#include "ai/builder/BuilderAI.hpp"
#include "ai/builder/Json.hpp"

#include <fstream>
#include <cctype>
#include <set>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <utility>
#include <system_error>

namespace lulz::ai::builder {
namespace {

bool readTextFile(const std::filesystem::path& path, std::string& output, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) { error = "cannot open JSON input: " + path.string(); return false; }
    std::ostringstream stream;
    stream << input.rdbuf();
    if (!input.good() && !input.eof()) { error = "failed while reading JSON input"; return false; }
    output = stream.str();
    return true;
}

bool validProjectName(const std::string& name) {
    if (name.empty() || name.size() > 80 || name == "." || name == "..") return false;
    for (unsigned char c : name) {
        if (!(std::isalnum(c) || c == '-' || c == '_' || c == '.')) return false;
    }
    return true;
}

bool safeRelativePath(const std::string& text, std::filesystem::path& result) {
    if (text.empty() || text.size() > 240) return false;
    std::filesystem::path path = std::filesystem::u8path(text);
    if (path.is_absolute() || path.has_root_name() || path.has_root_directory()) return false;
    for (const auto& part : path) {
        const std::string component = part.string();
        if (component.empty() || component == "." || component == ".." ||
            component.find(':') != std::string::npos) return false;
    }
    result = path.lexically_normal();
    return !result.empty();
}

const std::string* getString(const JsonValue& value, const std::string& key) {
    const auto* field = value.get(key);
    return field ? field->string() : nullptr;
}


std::string jsonEscape(const std::string& value) {
    std::string out;
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                static constexpr char digits[] = "0123456789abcdef";
                out += "\\u00";
                out += digits[ch >> 4];
                out += digits[ch & 0x0f];
            } else out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

std::string cppEscape(const std::string& value) {
    std::string out;
    for (char ch : value) {
        if (ch == '\\' || ch == '"') { out.push_back('\\'); out.push_back(ch); }
        else if (ch == '\n') out += "\\n";
        else if (ch == '\r') out += "\\r";
        else if (ch == '\t') out += "\\t";
        else out.push_back(ch);
    }
    return out;
}

std::string scalarText(const JsonValue* value, const std::string& fallback = {}) {
    if (!value) return fallback;
    if (const auto* text = value->string()) return *text;
    if (const auto* number = std::get_if<double>(&value->value)) {
        std::ostringstream out;
        out.precision(17);
        out << *number;
        return out.str();
    }
    if (const auto* boolean = std::get_if<bool>(&value->value)) return *boolean ? "true" : "false";
    return fallback;
}

std::string numberLiteral(const JsonValue* value, const std::string& fallback = "0") {
    if (!value || !value->isNumber()) return fallback;
    const auto* number = std::get_if<double>(&value->value);
    if (!number || *number < 0.0 || *number > 9007199254740991.0) return fallback;
    std::ostringstream out;
    out << std::fixed << std::setprecision(0) << *number;
    return out.str();
}

std::string makeAnalysisProjectManifest(const JsonValue& root, const std::string& originalJson) {
    const auto* importsValue = root.get("imports");
    const auto* functionsValue = root.get("functions");
    const auto* imports = importsValue ? importsValue->array() : nullptr;
    const auto* functions = functionsValue ? functionsValue->array() : nullptr;
    if (!imports || !functions) return {};

    const JsonValue* metadata = root.get("pe_metadata");
    const JsonValue* tls = metadata ? metadata->get("tls") : nullptr;
    const auto* exportsValue = metadata ? metadata->get("exports") : nullptr;
    const auto* relocationsValue = metadata ? metadata->get("base_relocations") : nullptr;
    const auto* debugValue = metadata ? metadata->get("debug_entries") : nullptr;
    const auto* certificatesValue = metadata ? metadata->get("certificates") : nullptr;
    const auto* callbacksValue = tls ? tls->get("callbacks") : nullptr;
    const auto* exports = exportsValue ? exportsValue->array() : nullptr;
    const auto* relocations = relocationsValue ? relocationsValue->array() : nullptr;
    const auto* debugEntries = debugValue ? debugValue->array() : nullptr;
    const auto* certificates = certificatesValue ? certificatesValue->array() : nullptr;
    const auto* callbacks = callbacksValue ? callbacksValue->array() : nullptr;

    std::ostringstream header;
    header << "#pragma once\n\n#include <cstdint>\n#include <string>\n#include <vector>\n\n"
           << "namespace lulz_generated {\n"
           << "struct Import { std::string module; std::string name; std::string iatRva; };\n"
           << "struct Call { std::string instructionRva; std::string kind; std::string targetRva; std::string target; bool resolved; };\n"
           << "struct Function { std::string beginRva; std::string endRva; std::string unwindRva; std::uint64_t size; std::uint32_t stackConsumed; std::vector<Call> calls; };\n"
           << "struct Export { std::string name; std::uint32_t ordinal; std::string rva; bool forwarded; std::string forwarder; };\n"
           << "struct Relocation { std::string pageRva; std::string targetRva; std::uint8_t type; };\n"
           << "struct DebugEntry { std::uint32_t timestamp; std::uint32_t type; std::uint32_t size; std::uint32_t rawPointer; };\n"
           << "struct Certificate { std::uint32_t length; std::uint16_t revision; std::uint16_t type; std::uint32_t fileOffset; };\n"
           << "extern const std::string imageBase;\n"
           << "extern const std::vector<Import> imports;\n"
           << "extern const std::vector<Function> functions;\n"
           << "extern const std::vector<Export> exports;\n"
           << "extern const std::vector<Relocation> relocations;\n"
           << "extern const std::vector<DebugEntry> debugEntries;\n"
           << "extern const std::vector<Certificate> certificates;\n"
           << "extern const std::vector<std::string> tlsCallbacks;\n"
           << "} // namespace lulz_generated\n";

    std::ostringstream source;
    source << "#include \"analysis/AnalysisData.hpp\"\n\nnamespace lulz_generated {\n";
    source << "const std::string imageBase = \"" << cppEscape(scalarText(root.get("image_base"), "unknown")) << "\";\n";
    source << "const std::vector<Import> imports = {\n";
    for (const auto& item : *imports) {
        if (!item.isObject()) continue;
        source << "    {\"" << cppEscape(scalarText(item.get("module"))) << "\", \""
               << cppEscape(scalarText(item.get("name"))) << "\", \""
               << cppEscape(scalarText(item.get("iat_rva"))) << "\"},\n";
    }
    source << "};\nconst std::vector<Function> functions = {\n";
    for (const auto& item : *functions) {
        if (!item.isObject()) continue;
        const auto* callsValue = item.get("calls");
        const auto* calls = callsValue ? callsValue->array() : nullptr;
        source << "    {\"" << cppEscape(scalarText(item.get("begin_rva"))) << "\", \""
               << cppEscape(scalarText(item.get("end_rva"))) << "\", \""
               << cppEscape(scalarText(item.get("unwind_rva"))) << "\", "
               << numberLiteral(item.get("size")) << "ULL, "
               << numberLiteral(item.get("stack_consumed")) << "U, {";
        if (calls) {
            for (const auto& call : *calls) {
                if (!call.isObject()) continue;
                const auto* resolved = call.get("resolved");
                const bool isResolved = resolved && std::get_if<bool>(&resolved->value) &&
                    *std::get_if<bool>(&resolved->value);
                source << "{\"" << cppEscape(scalarText(call.get("instruction_rva"))) << "\", \""
                       << cppEscape(scalarText(call.get("kind"))) << "\", \""
                       << cppEscape(scalarText(call.get("target_rva"))) << "\", \""
                       << cppEscape(scalarText(call.get("target"))) << "\", "
                       << (isResolved ? "true" : "false") << "},";
            }
        }
        source << "}},\n";
    }

    source << "};\nconst std::vector<Export> exports = {\n";
    if (exports) {
        for (const auto& item : *exports) {
            if (!item.isObject()) continue;
            const auto* forwarded = item.get("forwarded");
            const bool isForwarded = forwarded && std::get_if<bool>(&forwarded->value) &&
                *std::get_if<bool>(&forwarded->value);
            source << "    {\"" << cppEscape(scalarText(item.get("name"))) << "\", "
                   << numberLiteral(item.get("ordinal")) << "U, \""
                   << cppEscape(scalarText(item.get("rva"))) << "\", "
                   << (isForwarded ? "true" : "false") << ", \""
                   << cppEscape(scalarText(item.get("forwarder"))) << "\"},\n";
        }
    }

    source << "};\nconst std::vector<Relocation> relocations = {\n";
    if (relocations) {
        for (const auto& item : *relocations) {
            if (!item.isObject()) continue;
            source << "    {\"" << cppEscape(scalarText(item.get("page_rva"))) << "\", \""
                   << cppEscape(scalarText(item.get("target_rva"))) << "\", "
                   << numberLiteral(item.get("type")) << "U},\n";
        }
    }

    source << "};\nconst std::vector<DebugEntry> debugEntries = {\n";
    if (debugEntries) {
        for (const auto& item : *debugEntries) {
            if (!item.isObject()) continue;
            source << "    {" << numberLiteral(item.get("timestamp")) << "U, "
                   << numberLiteral(item.get("type")) << "U, "
                   << numberLiteral(item.get("size")) << "U, "
                   << numberLiteral(item.get("raw_pointer")) << "U},\n";
        }
    }

    source << "};\nconst std::vector<Certificate> certificates = {\n";
    if (certificates) {
        for (const auto& item : *certificates) {
            if (!item.isObject()) continue;
            source << "    {" << numberLiteral(item.get("length")) << "U, "
                   << numberLiteral(item.get("revision")) << "U, "
                   << numberLiteral(item.get("certificate_type")) << "U, "
                   << numberLiteral(item.get("file_offset")) << "U},\n";
        }
    }

    source << "};\nconst std::vector<std::string> tlsCallbacks = {\n";
    if (callbacks) {
        for (const auto& item : *callbacks)
            source << "    \"" << cppEscape(scalarText(&item)) << "\",\n";
    }
    source << "};\n} // namespace lulz_generated\n";

    const std::string mainSource =
        "#include \"analysis/AnalysisData.hpp\"\n"
        "#include <iostream>\n"
        "int main() {\n"
        "    std::cout << \"PE analysis project\\nImage base: \" << lulz_generated::imageBase << \"\\n\";\n"
        "    std::cout << \"Imports: \" << lulz_generated::imports.size() << \"\\n\";\n"
        "    std::cout << \"Functions: \" << lulz_generated::functions.size() << \"\\n\";\n"
        "    std::cout << \"Exports: \" << lulz_generated::exports.size() << \"\\n\";\n"
        "    std::cout << \"Relocations: \" << lulz_generated::relocations.size() << \"\\n\";\n"
        "    std::cout << \"Certificates: \" << lulz_generated::certificates.size() << \"\\n\";\n"
        "    std::cout << \"Debug entries: \" << lulz_generated::debugEntries.size() << \"\\n\";\n"
        "    std::cout << \"TLS callbacks: \" << lulz_generated::tlsCallbacks.size() << \"\\n\";\n"
        "    for (const auto& function : lulz_generated::functions)\n"
        "        std::cout << function.beginRva << \" - \" << function.endRva << \" calls=\" << function.calls.size() << \"\\n\";\n"
        "    return 0;\n"
        "}\n";

    const std::string cmake =
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(LulzAnalysisExport LANGUAGES CXX)\n"
        "set(CMAKE_CXX_STANDARD 20)\n"
        "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n"
        "add_executable(LulzAnalysisExport src/main.cpp src/AnalysisData.cpp)\n"
        "target_include_directories(LulzAnalysisExport PRIVATE include)\n";

    std::ostringstream manifest;
    manifest << "{\"project\":\"LulzAnalysisExport\",\"files\":[";
    const std::pair<std::string, std::string> generated[] = {
        {"include/analysis/AnalysisData.hpp", header.str()},
        {"src/AnalysisData.cpp", source.str()},
        {"src/main.cpp", mainSource},
        {"CMakeLists.txt", cmake},
        {"analysis/source.json", originalJson}
    };
    for (std::size_t i = 0; i < std::size(generated); ++i) {
        if (i) manifest << ',';
        manifest << "{\"path\":\"" << jsonEscape(generated[i].first)
                 << "\",\"content\":\"" << jsonEscape(generated[i].second) << "\"}";
    }
    manifest << "]}";
    return manifest.str();
}

bool hasSymlinkComponent(const std::filesystem::path& root, const std::filesystem::path& relative) {
    std::error_code ec;
    std::filesystem::path current = root;
    auto inspect = [&](const std::filesystem::path& candidate) {
        const auto status = std::filesystem::symlink_status(candidate, ec);
        if (ec == std::errc::no_such_file_or_directory) { ec.clear(); return false; }
        if (ec) return true;
        return std::filesystem::is_symlink(status);
    };
    if (inspect(current)) return true;
    for (const auto& component : relative) {
        current /= component;
        if (inspect(current)) return true;
    }
    return false;
}

BuildReport failure(std::string message) {
    BuildReport report;
    report.error = std::move(message);
    return report;
}

} // namespace

BuildReport BuilderAI::buildFromJsonFile(
    const std::filesystem::path& jsonFile,
    const BuilderOptions& options
) const {
    std::string json;
    std::string error;
    if (!readTextFile(jsonFile, json, error)) return failure(error);
    return buildFromJson(json, options);
}

BuildReport BuilderAI::buildFromJson(
    const std::string& json,
    const BuilderOptions& options
) const {
    JsonParser parser(json);
    const JsonParseResult parsed = parser.parse();
    if (!parsed.success) {
        return failure("JSON parse error at byte " +
            std::to_string(parsed.errorOffset) + ": " + parsed.error);
    }
    if (!parsed.value.isObject()) return failure("root JSON value must be an object");

    // Analyzer reports are accepted directly and converted into a typed C++ model project.
    if (!parsed.value.get("project") && parsed.value.get("format") &&
        parsed.value.get("functions") && parsed.value.get("imports")) {
        const std::string generatedManifest = makeAnalysisProjectManifest(parsed.value, json);
        if (generatedManifest.empty()) return failure("analysis JSON is missing imports or functions arrays");
        return buildFromJson(generatedManifest, options);
    }

    const std::string* projectName = getString(parsed.value, "project");
    if (!projectName || !validProjectName(*projectName))
        return failure("field 'project' must be a safe project name (letters, digits, '.', '_' or '-')");

    const JsonValue* filesValue = parsed.value.get("files");
    const auto* files = filesValue ? filesValue->array() : nullptr;
    if (!files || files->empty()) return failure("field 'files' must be a non-empty array");
    if (files->size() > options.maximumFiles) return failure("project exceeds configured file-count limit");

    struct PendingFile { std::filesystem::path path; std::string content; };
    std::vector<PendingFile> pending;
    std::set<std::string> uniquePaths;
    std::size_t totalBytes = 0;

    for (std::size_t i = 0; i < files->size(); ++i) {
        const JsonValue& item = (*files)[i];
        if (!item.isObject()) return failure("files[" + std::to_string(i) + "] must be an object");
        const std::string* pathText = getString(item, "path");
        const std::string* content = getString(item, "content");
        if (!pathText || !content) return failure("each file requires string fields 'path' and 'content'");

        std::filesystem::path relative;
        if (!safeRelativePath(*pathText, relative))
            return failure("unsafe or invalid output path: " + *pathText);
        const std::string normalized = relative.generic_string();
        if (!uniquePaths.insert(normalized).second)
            return failure("duplicate output path: " + normalized);
        if (content->size() > options.maximumFileBytes)
            return failure("file exceeds size limit: " + normalized);
        if (content->size() > options.maximumTotalBytes - totalBytes)
            return failure("project exceeds total output size limit");
        totalBytes += content->size();
        pending.push_back({std::move(relative), *content});
    }

    const std::filesystem::path root =
        (options.outputDirectory / *projectName).lexically_normal();
    std::error_code ec;
    if (std::filesystem::exists(root, ec)) {
        if (!options.overwrite) return failure("output already exists; use --force to replace generated files");
        if (!std::filesystem::is_directory(root, ec))
            return failure("output path exists and is not a directory");
    }
    std::filesystem::create_directories(root, ec);
    if (ec) return failure("cannot create output directory: " + ec.message());

    BuildReport report;
    report.projectName = *projectName;
    report.projectDirectory = root;

    for (const auto& file : pending) {
        const auto destination = root / file.path;
        if (hasSymlinkComponent(root, file.path)) {
            report.error = "refusing to follow a symbolic link in output path: " + file.path.string();
            return report;
        }
        std::filesystem::create_directories(destination.parent_path(), ec);
        if (ec) { report.error = "cannot create directory for " + file.path.string() + ": " + ec.message(); return report; }

        if (std::filesystem::exists(destination, ec) && !options.overwrite) {
            report.error = "refusing to overwrite existing file: " + destination.string();
            return report;
        }

        const auto temporary = destination.string() + ".lulz-tmp";
        {
            std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
            if (!output) { report.error = "cannot create file: " + temporary; return report; }
            output.write(file.content.data(), static_cast<std::streamsize>(file.content.size()));
            output.flush();
            if (!output) { report.error = "failed writing file: " + temporary; return report; }
        }
        if (options.overwrite && std::filesystem::exists(destination, ec)) {
            std::filesystem::remove(destination, ec);
            if (ec) {
                std::filesystem::remove(temporary);
                report.error = "cannot replace existing file " + destination.string() + ": " + ec.message();
                return report;
            }
        }
        std::filesystem::rename(temporary, destination, ec);
        if (ec) {
            std::filesystem::remove(temporary);
            report.error = "cannot finalize file " + destination.string() + ": " + ec.message();
            return report;
        }
        report.createdFiles.push_back(destination);
    }

    report.success = true;
    return report;
}

} // namespace lulz::ai::builder
