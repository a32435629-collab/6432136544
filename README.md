# DLL LULZ AI v0.8.0 — Dual AI Architecture

**DLL LULZ AI** — модульный C++20-инструмент для статического анализа исполняемых файлов, исследования бинарных форматов и экспериментов с нейросетевыми моделями.

Проект находится в активной разработке. Часть компонентов реализована и покрыта тестами, другие являются ограниченными foundation-модулями. Этот документ отделяет текущие возможности от незавершённых направлений.

## Возможности

### Загрузка и базовый анализ
- Чтение файлов и безопасные операции с бинарными диапазонами.
- Парсинг и форматирование hex-данных.
- Определение поддерживаемого формата файла.
- Оценка энтропии по распределению байтов.
- Поиск кандидатов на точки входа функций.
- CLI для основных операций с файлами.

### Форматы исполняемых файлов
- **PE32 / PE32+**: заголовки, секции, импорты и связанные структуры.
- **PE x64 unwind**: разбор exception directory, RUNTIME_FUNCTION, UNWIND_INFO, распространённых UWOP_*, chained records и handler metadata.
- **ELF32 / ELF64**: обе endian-модели, заголовки, program/section headers, имена секций, PT_INTERP, DT_NEEDED и extended numbering.
- **Mach-O thin**: 32/64-bit заголовки, load commands, segments/sections, dylib references и LC_MAIN.
- **.NET / CLR metadata foundation**: CLR directory/header, BSJB metadata root, streams и IDs/row counts таблиц.

Поддержка форматов имеет ограничения. Например, Mach-O Universal/Fat, полное декодирование ELF symbol/relocation tables и декодирование строк таблиц CLR пока не реализованы.

### Анализ кода
- Ограниченный встроенный x86/x64 decoder и encoder для базовых операций.
- Использование Zydis 4.1.1 для декодирования инструкций в x64 PE call-site analysis.
- Анализ PE x64 функций с использованием .pdata и UNWIND_INFO.
- Построение best-effort call graph по распознанным прямым и поддерживаемым косвенным вызовам.

Call graph не является полным CFG: косвенные переходы, исключительные рёбра и неподдерживаемые формы адресации могут остаться неразрешёнными. Это не полноценный дизассемблер или декомпилятор.

### AI и нейросеть
- AI configuration/context и извлечение признаков импортов, функций и декодированных инструкций.
- Лёгкая CPU feed-forward neural network (MLP): configurable topology, ReLU/tanh/sigmoid/linear activations, inference и SGD training.\n- Neural Evolution 0.7 foundation: momentum SGD, L2 weight decay, global gradient-norm clipping и проверки non-finite значений во время обучения.
- Сохранение и загрузка модели в версионированном little-endian формате с проверками размеров и параметров.
- `lulz_dataset`: статическое извлечение 28 числовых PE-признаков из размеченного manifest CSV.
- `lulz_trainer`: локальное обучение MLP, stratified train/validation/test split, метрики и сохранение `.lznn` вместе с `.norm` нормализацией.
- JSON presets в каталоге config/ и отдельный opt-in microbenchmark в benchmarks/.

**Важно:** JSON presets пока не загружаются автоматически в AIConfig. Наличие MLP не означает, что приложение содержит обученный malware detector. Текущий AI pipeline — экспериментальная основа; качество обнаружения на реальных файлах не заявляется.

### Дополнительные foundation-модули
В src/ также находятся начальные реализации:
- bounded PackBits-like RLE compression;
- byte-frequency, Shannon entropy и простые crypto-oriented heuristics;
- in-memory analysis metadata store;
- debugger state/breakpoint/event model без подключения к процессу;
- небольшое промежуточное представление (IR) и генератор псевдокода;
- byte-span binary diff;
- модели memory regions, network indicators, plugin registry, reports, CFG, scripting и workspace UI.

Эти компоненты не следует считать полноценными production-подсистемами. Например, database foundation пока не является persistent SQLite storage, debugger model не управляет ОС-процессом, а IR emitter не декомпилирует произвольный машинный код.

## Структура проекта

| Каталог | Назначение |
|---|---|
| app/ | CLI application |
| include/, src/core/ | Общие типы, результаты и инфраструктура |
| src/formats/ | PE, ELF, Mach-O и .NET/CLR parsers |
| src/analysis/ | Анализ бинарных данных и функций |
| src/asm/ | Низкоуровневые x86 helpers |
| src/ai/ | AI pipeline, features и neural network |
| src/*/ | Дополнительные subsystem foundations |
| tests/ | Unit и subsystem tests |
| datasets/ | Небольшие starter datasets |
| config/ | AI JSON presets и schema |
| benchmarks/ | Opt-in neural microbenchmark |

## Сборка

Требования:
- CMake 3.20 или новее;
- компилятор с поддержкой C++20 (Visual Studio 2022 / MSVC или совместимый GCC/Clang);
- доступ к GitHub во время первой конфигурации CMake для получения Zydis v4.1.1 через FetchContent.

### Windows Desktop GUI (Win32 API)

The native desktop interface is built as a separate `lulz_gui` target. It uses the existing `lulz_core` analysis engine; the CLI and test targets remain available.

    cmake -S . -B build-msvc -A x64
    cmake --build build-msvc --config Release --target lulz_gui

Launch `build-msvc\\Release\\lulz_gui.exe`. Choose **Открыть файл** to inspect an EXE or DLL. The first GUI iteration includes an overview, PE section table, imports, discovered functions and diagnostic messages. It performs static parsing only and does not execute the selected file.

### Windows (Visual Studio 2022)

    cmake -S . -B build
    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure

Запуск CLI:

    .\build\Release\dll_lulz.exe info .\sample.exe
    .\build\Release\dll_lulz.exe hex .\sample.dll
    .\build\Release\dll_lulz.exe disasm 4889D84883C001C3
    .\build\Release\dll_lulz.exe pe .\sample.exe
    .\build\Release\dll_lulz.exe unwind .\sample.exe
    .\build\Release\dll_lulz.exe unwind .\sample.exe --json
    .\build\Release\dll_lulz.exe analyze .\sample.exe

Для single-config генераторов (например, MinGW Makefiles) исполняемый файл обычно находится в build/dll_lulz.exe.

### Локальное обучение PE-модели

Инструкция по формату manifest, извлечению датасета и запуску trainer находится в [datasets/README.md](datasets/README.md).

Краткий workflow после сборки:

    .\\build\\Release\\lulz_dataset.exe .\\datasets\\pe_manifest.csv .\\datasets\\pe_training.csv
    .\\build\\Release\\lulz_trainer.exe .\\datasets\\pe_training.csv .\\models\\lulz_pe_0.7.lznn

Для локального inference используйте полученный checkpoint через `dll_lulz ai <file> --model <checkpoint.lznn>`. Файл `<checkpoint.lznn>.norm` должен оставаться рядом с checkpoint. Текущая random stratified split не исключает утечку близких/родственных образцов между выборками; см. ограничения в datasets/README.md.

## Отдельный neural benchmark

Бенчмарки отключены по умолчанию:

    cmake -S . -B build-bench -DDLL_LULZ_BUILD_TESTS=OFF -DDLL_LULZ_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
    cmake --build build-bench --config Release --target lulz_neural_benchmark
    .\build-bench\Release\lulz_neural_benchmark.exe

Бенчмарк измеряет время обучения и inference на синтетических данных. Он не измеряет качество malware detection, полный pipeline анализа бинарных файлов или производительность GPU.

## Тесты и datasets

Тестовые цели:
- lulz_tests;
- lulz_neural_tests;
- lulz_subsystem_tests.

Запуск всех зарегистрированных тестов выполняется через ctest, как показано выше.

Данные в datasets/functions/ и datasets/assembly/ — небольшие hand-authored synthetic examples. Они предназначены для проверки формата и экспериментов с обработкой данных, а не для оценки точности классификатора. Не используйте их как доказательство качества обнаружения вредоносного ПО.

## Безопасность

- Рассматривайте неизвестные бинарные файлы как недоверенные данные.
- Статические парсеры проекта не должны запускать анализируемый файл.
- Сохраняйте оригиналы образцов неизменными и работайте с копиями.
- Для динамического анализа используйте изолированную виртуальную машину.
- Не помещайте API keys, пароли и другие секреты в JSON-конфиги или репозиторий.

## Текущее состояние и дальнейшая работа

Проект развивается поэтапно. Основные направления:
1. Расширение тестов и fuzzing для парсеров форматов.
2. Дальнейшая реализация и интеграция subsystem foundations.
3. JSON config loader и CLI selection для AI presets.
4. Подготовка репрезентативных датасетов и воспроизводимого training/evaluation pipeline.
5. Расширение декодирования, CFG и анализа функций.
6. Реализация persistent storage, plugin loading и OS debugger adapters.

См. README в соответствующих каталогах для точного описания API и ограничений каждого модуля.

## License

Проверьте файлы лицензий и зависимости проекта перед распространением сборок. Не добавляйте сторонние компоненты без соответствующего license notice.


## Version 0.7.0 — Neural Evolution (work in progress)\n\nThe local MLP trainer now supports optional momentum, L2 weight decay and\nglobal per-sample gradient-norm clipping. Defaults preserve the previous SGD\nbehaviour. Training options are range-checked and non-finite gradients,\nparameters and final losses are rejected. This is a training-engine improvement,\nnot evidence of a trained general-purpose assistant or malware classifier.\n\n## Version 0.6.0 — decoded instruction pipeline

The x64 PE function-analysis pass now retains each successfully decoded Zydis
instruction mnemonic and RVA. The AI context receives those instructions, and
the feature extractor derives instruction and per-function statistics from the
decoded stream rather than synthetic metadata lines. Undecodable bytes are
counted separately by the PE analysis layer.

A local neural checkpoint can be selected with
`dll_lulz.exe ai <file> --model <checkpoint.lznn>`. The model must match the
numeric feature-vector schema and order of this build. No pretrained malware
classifier is shipped; a forward pass is reported as inference only, not as a
malware verdict. The OpenAI provider uses Windows WinHTTP and reads OPENAI_API_KEY from the environment. The --openai CLI option sends extracted feature metadata, not executable bytes. The DeepSeek provider uses the compatible Chat Completions API, reads DEEPSEEK_API_KEY from the environment, and is selected with --deepseek (default model: deepseek-flash). The Groq provider uses Groq's OpenAI-compatible Chat Completions endpoint, reads GROQ_API_KEY from the environment, and is selected with --groq (default model: openai/gpt-oss-20b). Both providers send extracted feature metadata only, not executable bytes.

Groq CLI example (Windows PowerShell):

    $env:GROQ_API_KEY = "YOUR_GROQ_API_KEY"
    .\\build\\Release\\dll_lulz.exe ai .\\sample.exe --groq

Groq endpoint: https://api.groq.com/openai/v1/chat/completions. Model IDs and free-tier limits are controlled by Groq and can change; check the Groq console for current availability.


## Version 0.8.0 — Dual AI Architecture

Version 0.8.0 introduces two independent processing roles:

- **Analyzer AI** collects static binary metadata, parses executable structures, extracts features and produces analysis data. It does not execute the inspected file.
- **Builder AI** consumes a JSON project manifest and materializes a C++ project under `dist/<project>/`.

### Builder AI JSON format

The input JSON has a project name and a list of relative output paths with UTF-8 file contents:

```json
{
  "project": "ExampleProject",
  "files": [
    {
      "path": "CMakeLists.txt",
      "content": "cmake_minimum_required(VERSION 3.20)\nproject(ExampleProject)\n"
    },
    {
      "path": "src/main.cpp",
      "content": "#include <iostream>\nint main(){ std::cout << \"hello\\n\"; }\n"
    }
  ]
}
```

Generate the sample project:

    .\build\Release\lulz_builder.exe .\examples\builder\hello_project.json

The Builder also recognizes Analyzer JSON produced by `dll_lulz analyze <file> --json report.json`. Passing that report directly generates a typed C++ data model for imports, exports, functions, call edges, base relocations, debug records and TLS callbacks, preserves the source JSON, and creates a small executable that prints the collected summary:

    .\build\Release\dll_lulz.exe analyze .\sample.exe --json .\analysis.json
    .\build\Release\lulz_builder.exe .\analysis.json

Choose a different output directory:

    .\build\Release\lulz_builder.exe .\examples\builder\hello_project.json --out .\dist

Use `--force` only when intentionally replacing files in an existing generated project. The builder rejects absolute paths, parent-directory traversal, duplicate output paths, oversized files and excessive file counts. It does not invoke a compiler automatically; build the generated project with CMake after reviewing its source.

The JSON schema is available at `config/builder_project.schema.json`.

### Extended PE inspection

The new `pe-deep` command reports all available data-directory entries and parses export symbols, base relocations, TLS callback addresses, debug directory records and Authenticode WIN_CERTIFICATE table entries:

    .\build\Release\dll_lulz.exe pe-deep .\sample.exe

The parser is best-effort: malformed or unsupported substructures are reported as warnings where possible. Resource trees, delay-import decoding, load-config internals and certificate-table contents are not yet fully decoded. Static parsing is not a malware verdict.
