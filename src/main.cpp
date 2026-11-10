#include "datastego/CLIController.hpp"
#include "datastego/Types.hpp"
#include <iostream>
#ifdef DATASTEGO_GUI
#include "datastego/GUIController.hpp"
#include <cstdio>
#endif
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <cwchar>
#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif
#endif

static int runApplication(int argc, char** argv, int showCommand) {
    bool graphical = false;
    try {
        std::vector<std::string> arguments;
#ifdef _WIN32
        (void)argc; (void)argv;
        SetConsoleOutputCP(CP_UTF8);
        int wideCount = 0;
        auto* wideArguments = CommandLineToArgvW(GetCommandLineW(), &wideCount);
        if (!wideArguments) throw datastego::Error("Cannot read command line");
        struct Guard { wchar_t** p; ~Guard() { LocalFree(p); } } guard{wideArguments};
        for (int i = 1; i < wideCount; ++i) {
            const auto length = static_cast<int>(std::wcslen(wideArguments[i]));
            const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wideArguments[i], length, nullptr, 0, nullptr, nullptr);
            if (!size && length) throw datastego::Error("Invalid command line text");
            std::string value(static_cast<std::size_t>(size), '\0');
            if (size) WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wideArguments[i], length, &value[0], size, nullptr, nullptr);
            arguments.push_back(std::move(value));
        }
#else
        for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);
#endif
#ifdef DATASTEGO_GUI
        if (arguments.empty() || (arguments.size() == 1 && arguments[0] == "--gui")) {
            graphical = true;
            return datastego::GUIController{}.run(showCommand);
        }


        const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!output || output == INVALID_HANDLE_VALUE || GetFileType(output) == FILE_TYPE_UNKNOWN) {
            if (!AttachConsole(ATTACH_PARENT_PROCESS) && !AllocConsole())
                throw datastego::Error("Cannot open console for CLI command");
            std::freopen("CONOUT$", "w", stdout);
            std::freopen("CONOUT$", "w", stderr);
            const auto input = GetStdHandle(STD_INPUT_HANDLE);
            if (input && input != INVALID_HANDLE_VALUE && GetFileType(input) == FILE_TYPE_CHAR)
                std::freopen("CONIN$", "r", stdin);
            std::ios::sync_with_stdio(true);
        }
#else
        (void)showCommand;
#endif
        return datastego::CLIController{}.run(arguments);
    } catch (const std::exception& error) {
#ifdef DATASTEGO_GUI
        if (graphical) {
            MessageBoxA(nullptr, error.what(), "DataStego", MB_OK | MB_ICONERROR);
            return 1;
        }
#else
        (void)graphical;
#endif
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}

#ifdef DATASTEGO_GUI
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int showCommand) {
    return runApplication(0, nullptr, showCommand);
}
#else
int main(int argc, char** argv) { return runApplication(argc, argv, 0); }
#endif
