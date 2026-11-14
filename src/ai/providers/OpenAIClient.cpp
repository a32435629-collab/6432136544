#include "OpenAIClient.hpp"
#include <cstddef>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

namespace lulz::ai::providers {
namespace {
std::wstring widenAscii(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}
std::string jsonEscape(const std::string& value) {
    std::string out;
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch >= 0x20) out.push_back(static_cast<char>(ch));
                break;
        }
    }
    return out;
}
bool extractContent(const std::string& json, std::string& content) {
    const auto key = json.find("\"content\"");
    if (key == std::string::npos) return false;
    auto pos = json.find(':', key + 9);
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size()) {
        const char ch = json[pos++];
        if (ch == '"') return true;
        if (ch != '\\') { content.push_back(ch); continue; }
        if (pos >= json.size()) return false;
        const char escaped = json[pos++];
        switch (escaped) {
            case '"': content.push_back('"'); break;
            case '\\': content.push_back('\\'); break;
            case '/': content.push_back('/'); break;
            case 'n': content.push_back('\n'); break;
            case 'r': content.push_back('\r'); break;
            case 't': content.push_back('\t'); break;
            case 'b': content.push_back('\b'); break;
            case 'f': content.push_back('\f'); break;
            default: return false;
        }
    }
    return false;
}
void setError(std::string* error, const char* message) { if (error) *error = message; }
}
bool analyzeWithOpenAI(const std::string& endpoint, const std::string& apiKey,
    const std::string& model, const std::string& prompt,
    std::string& response, std::string* error) {
    if (apiKey.empty()) { setError(error, "OPENAI_API_KEY environment variable is not set"); return false; }
    const std::wstring url = widenAscii(endpoint);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) {
        setError(error, "Invalid OpenAI endpoint URL"); return false;
    }
    if (parts.nScheme != INTERNET_SCHEME_HTTPS) {
        setError(error, "OpenAI endpoint must use HTTPS to protect the API key"); return false;
    }
    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.dwExtraInfoLength) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    if (path.empty()) path = L"/";
    HINTERNET session = WinHttpOpen(L"DLL-LULZ-AI/0.6.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { setError(error, "WinHTTP session initialization failed"); return false; }
    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);
    HINTERNET connection = WinHttpConnect(session, host.c_str(), parts.nPort, 0);
    if (!connection) { WinHttpCloseHandle(session); setError(error, "OpenAI connection initialization failed"); return false; }
    const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, L"POST", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
        setError(error, "OpenAI request initialization failed"); return false;
    }
    const std::string body = "{\"model\":\"" + jsonEscape(model) +
        "\",\"messages\":[{\"role\":\"system\",\"content\":\"You are a careful static binary-analysis assistant. Do not claim a malware verdict from heuristics alone.\"},{\"role\":\"user\",\"content\":\"" +
        jsonEscape(prompt) + "\"}],\"temperature\":0.1}";
    const std::wstring headers = L"Content-Type: application/json\r\nAuthorization: Bearer " +
        widenAscii(apiKey) + L"\r\n";
    bool ok = WinHttpSendRequest(request, headers.c_str(),
        static_cast<DWORD>(headers.size()), const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) &&
        WinHttpReceiveResponse(request, nullptr);
    DWORD status = 0, statusSize = sizeof(status);
    if (ok) ok = WinHttpQueryHeaders(request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
        WINHTTP_NO_HEADER_INDEX) && status >= 200 && status < 300;
    std::string payload;
    if (ok) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available) {
            if (payload.size() + available > 1024 * 1024) { ok = false; break; }
            const auto oldSize = payload.size();
            payload.resize(oldSize + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, payload.data() + oldSize, available, &read)) { ok = false; break; }
            payload.resize(oldSize + read);
            if (read == 0) break;
        }
    }
    WinHttpCloseHandle(request); WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
    if (!ok) { setError(error, status >= 400 ? "OpenAI HTTP request failed (check key, quota and endpoint)" : "OpenAI response read failed or exceeded 1 MiB"); return false; }
    if (!extractContent(payload, response)) { setError(error, "OpenAI response did not contain a supported message content field"); return false; }
    if (error) error->clear();
    return true;
}
} // namespace lulz::ai::providers
#else
namespace lulz::ai::providers {
bool analyzeWithOpenAI(const std::string&, const std::string&, const std::string&,
    const std::string&, std::string&, std::string* error) {
    if (error) *error = "OpenAI HTTP transport is currently supported on Windows builds only";
    return false;
}
}
#endif
