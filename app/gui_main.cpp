#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>

#include "lulz/analysis/FunctionAnalysis.hpp"
#include "lulz/analysis/EntropyAnalyzer.hpp"
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/formats/pe/PEExtendedParser.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Comdlg32.lib")

namespace {
constexpr int ID_OPEN = 1001;
constexpr int ID_NAV_SUMMARY = 1101;
constexpr int ID_NAV_DIAGNOSTICS = 1102;
constexpr int ID_NAV_SECTIONS = 1103;
constexpr int ID_NAV_IMPORTS = 1104;
constexpr int ID_NAV_FUNCTIONS = 1105;
constexpr int ID_CONTENT = 1201;
constexpr COLORREF BG = RGB(17, 22, 31);
constexpr COLORREF PANEL = RGB(25, 32, 44);
constexpr COLORREF TEXT = RGB(232, 238, 247);
constexpr COLORREF MUTED = RGB(151, 164, 183);
constexpr COLORREF ACCENT = RGB(79, 145, 255);

HWND g_window{}, g_content{}, g_title{}, g_subtitle{}, g_file{}, g_status{};
HWND g_nav[5]{};
HFONT g_font{}, g_fontBold{};
std::wstring g_path;
std::wstring g_page = L"Обзор";
int g_activePage = 0;
std::vector<std::uint8_t> g_bytes;
std::unique_ptr<lulz::PEInfo> g_pe;
std::unique_ptr<lulz::FunctionAnalysis> g_analysis;
std::unique_ptr<lulz::PEExtendedInfo> g_extended;
std::wstring g_error;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"(текст недоступен)";
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}
std::wstring number(std::size_t n) {
    std::wostringstream s; s << n; return s.str();
}
std::wstring hex32(std::uint32_t n) {
    std::wostringstream s; s << L"0x" << std::uppercase << std::hex << n; return s.str();
}
std::wstring hex64(std::uint64_t n) {
    std::wostringstream s; s << L"0x" << std::uppercase << std::hex << n; return s.str();
}
void setContent(const std::wstring& value) {
    SetWindowTextW(g_content, value.c_str());
    SendMessageW(g_content, EM_SETSEL, 0, 0);
}
void clearAnalysis() {
    g_bytes.clear(); g_pe.reset(); g_analysis.reset(); g_extended.reset(); g_error.clear();
}
void analyzeFile(const std::wstring& path) {
    clearAnalysis();
    g_path = path;
    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    if (!in) { g_error = L"Не удалось открыть файл."; return; }
    in.seekg(0, std::ios::end);
    const auto length = static_cast<std::streamoff>(in.tellg());
    if (length <= 0 || length > static_cast<std::streamoff>(512ull * 1024 * 1024)) {
        g_error = L"Файл пустой или превышает лимит GUI (512 МиБ)."; return;
    }
    in.seekg(0, std::ios::beg);
    g_bytes.resize(static_cast<std::size_t>(length));
    if (!in.read(reinterpret_cast<char*>(g_bytes.data()), static_cast<std::streamsize>(length))) {
        clearAnalysis(); g_error = L"Ошибка чтения файла."; return;
    }
    auto pe = lulz::parsePE(g_bytes);
    if (!pe) { g_error = L"Это не поддерживаемый PE-файл.\r\n\r\nПодробности: " + widen(pe.error()); return; }
    g_pe = std::make_unique<lulz::PEInfo>(std::move(pe.value()));
    auto a = lulz::analyzePEFunctions(g_bytes, *g_pe);
    if (a) g_analysis = std::make_unique<lulz::FunctionAnalysis>(std::move(a.value()));
    else g_error = L"Заголовки PE прочитаны, но анализ функций завершился ошибкой:\r\n" + widen(a.error());
    auto x = lulz::parsePEExtended(g_bytes);
    if (x) g_extended = std::make_unique<lulz::PEExtendedInfo>(std::move(x.value()));
}
std::wstring fileName() {
    if (g_path.empty()) return L"Файл не выбран";
    return std::filesystem::path(g_path).filename().wstring();
}
void showPage(int page) {
    static const wchar_t* names[] = {L"Обзор", L"Диагностика", L"Секции PE", L"Импорты", L"Функции"};
    if (page < 0 || page >= 5) return;
    g_page = names[page];
    g_activePage = page;
    for (int i=0;i<5;++i) {
        SendMessageW(g_nav[i], BM_SETSTATE, i==page, TRUE);
        InvalidateRect(g_nav[i], nullptr, TRUE);
    }
    SetWindowTextW(g_title, g_page.c_str());
    if (!g_pe) {
        std::wostringstream out;
        if (g_path.empty()) {
            out << L"Откройте EXE или DLL, чтобы начать анализ.\\r\\n\\r\\n"
                << L"LULZ-AI читает файл как данные и не запускает его.";
        } else {
            out << L"ВЫБРАННЫЙ ФАЙЛ\\r\\n\\r\\n"
                << L"Файл: " << fileName() << L"\\r\\n"
                << L"Путь: " << g_path << L"\\r\\n\\r\\n"
                << L"Не удалось построить PE-отчёт.\\r\\n"
                << (g_error.empty() ? L"Причина не указана." : g_error)
                << L"\\r\\n\\r\\nПроверьте, что выбран корректный EXE/DLL, а файл не повреждён и доступен для чтения.";
        }
        setContent(out.str());
        return;
    }
    std::wostringstream out;
    if (page == 0) {
        out << L"РЕЗУЛЬТАТ АНАЛИЗА\r\n\r\n"
            << L"Файл: " << fileName() << L"\r\n"
            << L"Формат: Portable Executable (PE" << (g_pe->is64 ? L"32+" : L"32") << L")\r\n"
            << L"Архитектура: " << (g_pe->is64 ? L"x64" : L"x86") << L"\r\n"
            << L"Размер: " << number(g_bytes.size()) << L" байт\r\n"
            << L"Точка входа (RVA): " << hex32(g_pe->entryPoint) << L"\r\n"
            << L"Image Base: " << hex64(g_pe->imageBase) << L"\r\n"
            << L"Секций: " << g_pe->sections.size() << L"\r\n"
            << L"Функций: " << (g_analysis ? number(g_analysis->functions.size()) : L"не определено") << L"\r\n"
            << L"Импортов: " << (g_analysis ? number(g_analysis->imports.size()) : L"не определено") << L"\r\n"
            << L"Неразрешённых вызовов: " << (g_analysis ? number(g_analysis->unresolvedCalls) : L"не определено") << L"\r\n"
            << L"Предупреждений: " << (g_analysis ? number(g_analysis->warnings.size()) : L"не определено") << L"\r\n\r\n"
            << L"Что это значит\r\n"
            << L"Файл успешно распознан как PE. Счётчики показывают объём найденных структур, а не оценку безопасности файла.\r\n"
            << L"Статический анализ не запускает файл и сам по себе не выносит вердикт о вредоносности.";
    } else if (page == 1) {
        out << L"ПРОБЛЕМЫ И ПРЕДУПРЕЖДЕНИЯ\r\n\r\n";
        std::size_t count=0;
        if (g_analysis) for (const auto& w : g_analysis->warnings) { out << L"• " << widen(w) << L"\r\n"; ++count; }
        if (g_extended) for (const auto& w : g_extended->warnings) { out << L"• " << widen(w) << L"\r\n"; ++count; }
        if (count==0) out << L"Предупреждений не обнаружено.\r\n\r\nЭто означает, что текущие проверки не нашли известных им проблем. Это не гарантия корректности или безопасности файла.";
        else out << L"\r\nВсего сообщений: " << count << L"\r\n\r\nПредупреждение означает, что конкретная проверка обнаружила необычную или некорректную структуру. Оно не обязательно означает, что файл повреждён.";
    } else if (page == 2) {
        out << L"СЕКЦИИ PE\r\n\r\nИмя\tRVA\tРазмер в памяти\tСмещение в файле\tРазмер в файле\r\n";
        for (const auto& s : g_pe->sections)
            out << widen(s.name) << L"\t" << hex32(s.virtualAddress) << L"\t" << number(std::max(s.virtualSize,s.rawSize))
                << L"\t" << hex32(s.rawOffset) << L"\t" << number(s.rawSize) << L"\r\n";
        out << L"\r\nRVA — адрес относительно начала образа в памяти. Смещение в файле указывает положение данных на диске.";
    } else if (page == 3) {
        out << L"ИМПОРТИРУЕМЫЕ ФУНКЦИИ\r\n\r\n";
        if (g_analysis) for (const auto& i : g_analysis->imports)
            out << widen(i.module) << L"  →  " << widen(i.name) << L"    IAT " << hex32(i.iatRva) << L"\r\n";
        if (!g_analysis || g_analysis->imports.empty()) out << L"Импорты не найдены или таблица не поддерживается.";
        out << L"\r\nИмпорт — функция или символ, который файл ожидает получить из другой библиотеки.";
    } else {
        out << L"ОБНАРУЖЕННЫЕ ФУНКЦИИ\r\n\r\nНачальный RVA\tКонечный RVA\tИнструкций\tВызовов\tСтек\r\n";
        if (g_analysis) for (const auto& f : g_analysis->functions)
            out << hex32(f.range.beginRva) << L"\t" << hex32(f.range.endRva) << L"\t"
                << number(f.instructions.size()) << L"\t" << number(f.calls.size()) << L"\t"
                << number(f.unwind.stackAllocation) << L" байт\r\n";
        if (!g_analysis || g_analysis->functions.empty()) out << L"Функции не найдены. Для некоторых архитектур и форматов этот этап анализа ограничен.";
    }
    setContent(out.str());
}
void openFile() {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW ofn{sizeof(ofn)};
    ofn.hwndOwner = g_window; ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Исполняемые файлы\0EXE и DLL (*.exe;*.dll)\0*.exe;*.dll\0Все файлы (*.*)\0*.*\0\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = L"Выберите файл для статического анализа";
    if (GetOpenFileNameW(&ofn)) {
        analyzeFile(path);
        SetWindowTextW(g_file, fileName().c_str());
        SetWindowTextW(g_status, g_error.empty() ? L"Анализ завершён" : L"Анализ завершился с сообщением");
        showPage(0);
    }
}
HWND makeControl(DWORD ex, const wchar_t* cls, const wchar_t* text, DWORD style, int id, HWND parent) {
    return CreateWindowExW(ex, cls, text, style, 0,0,100,30,parent,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
}
void layout(HWND w) {
    RECT r{}; GetClientRect(w,&r); const int width=r.right, height=r.bottom;
    MoveWindow(g_title, 260, 24, width-290, 38, TRUE);
    MoveWindow(g_subtitle, 260, 64, width-290, 24, TRUE);
    MoveWindow(g_file, 260, 104, width-450, 34, TRUE);
    MoveWindow(GetDlgItem(w,ID_OPEN), width-170, 101, 140, 40, TRUE);
    MoveWindow(g_content, 260, 160, std::max(200,width-290), std::max(120,height-215), TRUE);
    MoveWindow(g_status, 260, height-38, width-290, 24, TRUE);
    for(int i=0;i<5;++i) MoveWindow(g_nav[i], 20, 145+i*52, 210, 42, TRUE);
}
LRESULT CALLBACK wndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        g_window=w;
        g_font=CreateFontW(17,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_fontBold=CreateFontW(25,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_title=makeControl(0,L"STATIC",L"Обзор",WS_CHILD|WS_VISIBLE,0,w);
        g_subtitle=makeControl(0,L"STATIC",L"Статический анализ исполняемых файлов Windows",WS_CHILD|WS_VISIBLE,0,w);
        g_file=makeControl(0,L"STATIC",L"Файл не выбран",WS_CHILD|WS_VISIBLE|SS_LEFT,0,w);
        makeControl(0,L"BUTTON",L"Открыть файл",WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,ID_OPEN,w);
        g_content=makeControl(WS_EX_CLIENTEDGE,L"EDIT",L"Откройте EXE или DLL, чтобы начать анализ.",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|ES_WANTRETURN,ID_CONTENT,w);
        g_status=makeControl(0,L"STATIC",L"Готов к работе · файлы не запускаются",WS_CHILD|WS_VISIBLE,0,w);
        const int ids[]={ID_NAV_SUMMARY,ID_NAV_DIAGNOSTICS,ID_NAV_SECTIONS,ID_NAV_IMPORTS,ID_NAV_FUNCTIONS};
        const wchar_t* labels[]={L"Обзор",L"Диагностика",L"Секции PE",L"Импорты",L"Функции"};
        for(int i=0;i<5;++i) g_nav[i]=makeControl(0,L"BUTTON",labels[i],WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,ids[i],w);
        for(HWND h:{g_title,g_subtitle,g_file,g_content,g_status}) SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(g_font),TRUE);
        SendMessageW(g_title,WM_SETFONT,reinterpret_cast<WPARAM>(g_fontBold),TRUE);
        for(HWND h:g_nav) SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(g_font),TRUE);
        SendMessageW(GetDlgItem(w,ID_OPEN),WM_SETFONT,reinterpret_cast<WPARAM>(g_font),TRUE);
        SendMessageW(g_content,EM_SETLIMITTEXT,16*1024*1024,0);
        layout(w); return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{}; HDC dc=BeginPaint(w,&ps); RECT r{}; GetClientRect(w,&r);
        HBRUSH bg=CreateSolidBrush(BG); FillRect(dc,&r,bg); DeleteObject(bg);
        RECT side{0,0,250,r.bottom}; HBRUSH panel=CreateSolidBrush(PANEL); FillRect(dc,&side,panel); DeleteObject(panel);
        HPEN pen=CreatePen(PS_SOLID,1,RGB(43,54,72)); HPEN old=(HPEN)SelectObject(dc,pen);
        MoveToEx(dc,249,0,nullptr); LineTo(dc,249,r.bottom); SelectObject(dc,old); DeleteObject(pen);
        SetBkMode(dc,TRANSPARENT); SetTextColor(dc,TEXT);
        HFONT oldFont=(HFONT)SelectObject(dc,g_fontBold); RECT brand{24,34,225,78}; DrawTextW(dc,L"LULZ-AI", -1,&brand,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc,g_font); SetTextColor(dc,MUTED); RECT tagline{24,78,225,112}; DrawTextW(dc,L"PE ANALYSIS STUDIO",-1,&tagline,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc,oldFont); EndPaint(w,&ps); return 0;
    }
    case WM_DRAWITEM: {
        auto* dis=reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if(dis && (dis->CtlID==ID_OPEN || (dis->CtlID>=ID_NAV_SUMMARY && dis->CtlID<=ID_NAV_FUNCTIONS))) {
            const bool open=dis->CtlID==ID_OPEN;
            const int index=open?-1:static_cast<int>(dis->CtlID-ID_NAV_SUMMARY);
            const bool selected=!open && index==g_activePage;
            const COLORREF fill=open?ACCENT:(selected?RGB(42,76,124):PANEL);
            HBRUSH b=CreateSolidBrush(fill); FillRect(dis->hDC,&dis->rcItem,b); DeleteObject(b);
            SetBkMode(dis->hDC,TRANSPARENT); SetTextColor(dis->hDC,open?RGB(255,255,255):(selected?RGB(255,255,255):TEXT));
            RECT tr=dis->rcItem; InflateRect(&tr,-12,0);
            DrawTextW(dis->hDC,open?L"Открыть файл":(index==0?L"Обзор":index==1?L"Диагностика":index==2?L"Секции PE":index==3?L"Импорты":L"Функции"),-1,&tr,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            if(dis->itemState & ODS_FOCUS) DrawFocusRect(dis->hDC,&dis->rcItem);
            return TRUE;
        } break;
    }
    case WM_SIZE: layout(w); return 0;
    case WM_COMMAND:
        switch(LOWORD(wp)) {
        case ID_OPEN: openFile(); return 0;
        case ID_NAV_SUMMARY: showPage(0); return 0;
        case ID_NAV_DIAGNOSTICS: showPage(1); return 0;
        case ID_NAV_SECTIONS: showPage(2); return 0;
        case ID_NAV_IMPORTS: showPage(3); return 0;
        case ID_NAV_FUNCTIONS: showPage(4); return 0;
        } break;
    case WM_CTLCOLOREDIT: {
        HDC dc=reinterpret_cast<HDC>(wp); SetTextColor(dc,TEXT); SetBkColor(dc,PANEL);
        static HBRUSH brush=CreateSolidBrush(PANEL); return reinterpret_cast<LRESULT>(brush);
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc=reinterpret_cast<HDC>(wp); SetTextColor(dc,GetDlgCtrlID(reinterpret_cast<HWND>(lp))==0?TEXT:MUTED); SetBkColor(dc,BG);
        static HBRUSH brush=CreateSolidBrush(BG); return reinterpret_cast<LRESULT>(brush);
    }
    case WM_DESTROY:
        if(g_font) DeleteObject(g_font); if(g_fontBold) DeleteObject(g_fontBold);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(w,msg,wp,lp);
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    INITCOMMONCONTROLSEX icc{sizeof(icc),ICC_STANDARD_CLASSES|ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSW wc{}; wc.lpfnWndProc=wndProc; wc.hInstance=instance; wc.lpszClassName=L"LULZAI_MAIN_WINDOW";
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW); wc.hbrBackground=CreateSolidBrush(BG);
    wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION);
    if(!RegisterClassW(&wc)) return 1;
    HWND w=CreateWindowExW(0,wc.lpszClassName,L"LULZ-AI Desktop",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
        CW_USEDEFAULT,CW_USEDEFAULT,1180,780,nullptr,nullptr,instance,nullptr);
    if(!w) return 1;
    ShowWindow(w,show); UpdateWindow(w);
    MSG msg{}; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    return static_cast<int>(msg.wParam);
}
