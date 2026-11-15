#include "ai/builder/BuilderAI.hpp"
#include "ai/builder/Json.hpp"

#include <fstream>
#include <set>
#include <sstream>
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
