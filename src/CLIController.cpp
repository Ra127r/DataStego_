#include "datastego/CLIController.hpp"
#include "datastego/ContainerFormat.hpp"
#include "datastego/FileIO.hpp"
#include "datastego/ImageHandler.hpp"
#include "datastego/StegoEngine.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace datastego {
namespace {
using Options = std::map<std::string, std::string>;
void help() {
    std::cout <<
        "DataStego 1.1 - AES-256-GCM + RGB LSB (self-contained C++17)\n\n"
        "Usage:\n"
        "  datastego hide --in FILE --cover IMAGE --out STEGO.png [options]\n"
        "  datastego extract --in STEGO.png --out FILE [options]\n"
        "  datastego info --in IMAGE\n"
        "  datastego compare --original IMAGE --stego IMAGE\n\n"
        "  datastego --interactive   Open the console menu\n\n"
        "  datastego --gui           Open the Windows GUI (also the default)\n\n"
        "Options for hide/extract:\n"
        "  --password-file FILE  Read one UTF-8 password line from FILE\n"
        "                        Otherwise prompt without terminal echo\n"
        "  --force               Allow replacing an existing output file\n"
        "Option for hide:\n"
        "  --iterations N        PBKDF2 rounds: 100000..2000000 (default 600000)\n\n"
        "Input images: PNG; uncompressed 24/32-bit BMP. Output image: PNG.\n"
        "The output path for extract is explicit; stored names never choose a path.\n"
        "See README.md and obyasneniya/README.md for the project walkthrough.\n";
}
Options parse(const std::vector<std::string>& arguments, const std::set<std::string>& allowed) {
    Options options;
    for (std::size_t i = 1; i < arguments.size(); ++i) {
        const auto& name = arguments[i];
        if (!allowed.count(name)) throw Error("Unknown option: " + name);
        if (options.count(name)) throw Error("Duplicate option: " + name);
        if (name == "--force") options[name] = "1";
        else {
            if (i + 1 == arguments.size() || arguments[i+1].rfind("--", 0) == 0)
                throw Error("Missing value for " + name);
            options[name] = arguments[++i];
        }
    }
    return options;
}
const std::string& requireOption(const Options& options, const std::string& name) {
    const auto found = options.find(name);
    if (found == options.end() || found->second.empty()) throw Error("Required option: " + name);
    return found->second;
}
std::filesystem::path pathOption(const Options& options, const std::string& name) {
    return std::filesystem::u8path(requireOption(options, name));
}
std::uint32_t iterationsOption(const Options& options) {
    const auto found = options.find("--iterations");
    if (found == options.end()) return CryptoEngine::DefaultIterations;
    const auto& text = found->second;
    if (text.empty() || text.size() > 7 || !std::all_of(text.begin(), text.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
        throw Error("Invalid PBKDF2 iteration count");
    const auto value = std::stoul(text);
    if (value < CryptoEngine::MinContainerIterations || value > CryptoEngine::MaxContainerIterations)
        throw Error("PBKDF2 iterations must be between 100000 and 2000000");
    return static_cast<std::uint32_t>(value);
}
void validateOutput(const Options& options, const std::filesystem::path& out,
                    const std::vector<std::filesystem::path>& inputs) {
    for (const auto& input : inputs) if (sameFile(input, out)) throw Error("Output must differ from every input file");
    const auto password = options.find("--password-file");
    if (password != options.end() && sameFile(std::filesystem::u8path(password->second), out))
        throw Error("Output must differ from the password file");
    if (!options.count("--force") && std::filesystem::exists(out))
        throw Error("Output already exists; choose another name or use --force");
}

class EchoGuard {
public:
    EchoGuard() {
#ifdef _WIN32
        handle_ = GetStdHandle(STD_INPUT_HANDLE);
        if (GetConsoleMode(handle_, &mode_)) {
            if (!SetConsoleMode(handle_, mode_ & ~ENABLE_ECHO_INPUT)) throw Error("Cannot disable password echo");
            changed_ = true;
        }
#else
        if (::isatty(STDIN_FILENO)) {
            if (::tcgetattr(STDIN_FILENO, &mode_) != 0) throw Error("Cannot read terminal mode");
            auto hidden = mode_; hidden.c_lflag &= ~ECHO;
            if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) throw Error("Cannot disable password echo");
            changed_ = true;
        }
#endif
    }
    ~EchoGuard() {
        if (!changed_) return;
#ifdef _WIN32
        SetConsoleMode(handle_, mode_);
#else
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &mode_);
#endif
        std::cerr << '\n';
    }
    bool isConsole() const { return changed_; }
private:
    bool changed_ = false;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    DWORD mode_ = 0;
#else
    termios mode_{};
#endif
};
Bytes readPassword(const Options& options) {
    Bytes password;
    const auto file = options.find("--password-file");
    if (file != options.end()) {
        password = readFile(std::filesystem::u8path(file->second), 4096);
    } else {
        std::cerr << "Password: " << std::flush;
        EchoGuard echo;
#ifdef _WIN32
        if (echo.isConsole()) {
            std::array<wchar_t, 4098> wide{};
            DWORD count = 0;
            if (!ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), wide.data(), static_cast<DWORD>(wide.size()), &count, nullptr))
                throw Error("Cannot read password");
            const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(count), nullptr, 0, nullptr, nullptr);
            if (length <= 0 || length > 4096) { secureErase(wide.data(), sizeof(wide)); throw Error("Password is too long or invalid"); }
            password.resize(static_cast<std::size_t>(length));
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(count),
                                reinterpret_cast<char*>(password.data()), length, nullptr, nullptr);
            secureErase(wide.data(), sizeof(wide));
        } else
#endif
        {
            password.reserve(4096);
            char c = 0;
            while (std::cin.get(c)) {
                if (c == '\n') break;
                if (password.size() == 4096) { secureErase(password.data(), password.size()); throw Error("Password exceeds 4096 bytes"); }
                password.push_back(static_cast<std::uint8_t>(c));
            }
        }
    }
    if (!password.empty() && password.back() == '\n') password.pop_back();
    if (!password.empty() && password.back() == '\r') password.pop_back();
    if (password.empty() || std::find(password.begin(), password.end(), '\n') != password.end() ||
        std::find(password.begin(), password.end(), '\r') != password.end()) {
        secureErase(password.data(), password.size());
        throw Error("Password must be one nonempty UTF-8 line");
    }
    return password;
}
std::string_view passwordView(const SecretBytes& password) {
    return {reinterpret_cast<const char*>(password.bytes.data()), password.bytes.size()};
}

bool interactiveTerminal() {
#ifdef _WIN32
    DWORD mode = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

std::optional<std::string> menuLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
#ifdef _WIN32
    if (interactiveTerminal()) {

        std::wstring wide;
        std::array<wchar_t, 1024> buffer{};
        for (;;) {
            DWORD count = 0;
            if (!ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buffer.data(),
                              static_cast<DWORD>(buffer.size()), &count, nullptr) || !count)
                return std::nullopt;
            wide.append(buffer.data(), count);
            if (wide.size() > 32768) throw Error("Input line is too long");
            if (wide.back() == L'\n') break;
        }
        while (!wide.empty() && (wide.back() == L'\n' || wide.back() == L'\r')) wide.pop_back();
        if (!wide.empty()) {
            const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
            if (size <= 0) throw Error("Invalid input text");
            line.resize(static_cast<std::size_t>(size));
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                static_cast<int>(wide.size()), &line[0], size, nullptr, nullptr);
        }
    } else
#endif
    {
        if (!std::getline(std::cin, line)) return std::nullopt;
        if (line.size() > 131072) throw Error("Input line is too long");
        if (!line.empty() && line.back() == '\r') line.pop_back();
    }
    const auto first = line.find_first_not_of(" \t");
    if (first == std::string::npos) return std::string{};
    const auto last = line.find_last_not_of(" \t");
    line = line.substr(first, last - first + 1);

    if (line.size() >= 2 && line.front() == '"' && line.back() == '"')
        line = line.substr(1, line.size() - 2);
    return line;
}
}

int CLIController::run(const std::vector<std::string>& arguments) const {
    if (arguments.empty()) {
        if (interactiveTerminal()) return runInteractive();
        help(); return 0;
    }
    if (arguments.size() == 1 && arguments[0] == "--interactive") return runInteractive();
    if (arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h") { help(); return 0; }
    if (arguments.size() == 1 && arguments[0] == "--version") { std::cout << "DataStego 1.1.0\n"; return 0; }
    const auto& command = arguments[0];
    if (command == "hide") {
        const auto options = parse(arguments, {"--in","--cover","--out","--password-file","--iterations","--force"});
        const auto input = pathOption(options, "--in"), cover = pathOption(options, "--cover"), out = pathOption(options, "--out");
        validateOutput(options, out, {input, cover});
        auto extension = out.extension().u8string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); });
        if (extension != ".png") throw Error("Stego output must use the .png extension");
        const auto iterations = iterationsOption(options);
        auto image = ImageHandler::load(cover);
        SecretBytes file(readFile(input));
        const auto name = input.filename().u8string();
        const auto size = ContainerFormat::packedSize(file.bytes.size(), name.size());
        if (size > image.capacityBytes()) throw Error("Image capacity is " + std::to_string(image.capacityBytes()) +
            " bytes, but the encrypted container needs " + std::to_string(size) + " bytes");
        SecretBytes password(readPassword(options));
        std::cout << "Deriving key and encrypting...\n" << std::flush;
        const auto container = ContainerFormat::pack(file.bytes, name, passwordView(password), iterations);
        StegoEngine::embed(image, container);
        ImageHandler::savePng(image, out, options.count("--force") != 0);
        std::cout << "Saved PNG. File: " << file.bytes.size() << " bytes; container: " << container.size()
                  << " / " << image.capacityBytes() << " bytes.\n";
        return 0;
    }
    if (command == "extract") {
        const auto options = parse(arguments, {"--in","--out","--password-file","--force"});
        const auto input = pathOption(options, "--in"), out = pathOption(options, "--out");
        validateOutput(options, out, {input});
        const auto image = ImageHandler::load(input);
        const auto header = StegoEngine::extract(image, ContainerFormat::HeaderSize);
        const auto info = ContainerFormat::inspect(header, image.capacityBytes());
        const auto container = StegoEngine::extract(image, ContainerFormat::HeaderSize + static_cast<std::size_t>(info.ciphertextSize));
        SecretBytes password(readPassword(options));
        std::cout << "Deriving key and checking authentication...\n" << std::flush;
        const auto recovered = ContainerFormat::unpack(container, passwordView(password));
        writeFile(out, recovered.data, options.count("--force") != 0);
        std::cout << "Recovered " << recovered.data.size() << " bytes. Stored filename: " << recovered.name << "\n";
        return 0;
    }
    if (command == "info") {
        const auto options = parse(arguments, {"--in"});
        const auto image = ImageHandler::load(pathOption(options, "--in"));
        std::cout << "Image: " << image.width << " x " << image.height << " (RGBA8)\n"
                  << "RGB LSB capacity: " << image.capacityBytes() << " bytes\n"
                  << "Container overhead: 82 bytes + UTF-8 filename length\n";
        if (image.capacityBytes() < ContainerFormat::HeaderSize) { std::cout << "No space for a container header.\n"; return 0; }
        const auto header = StegoEngine::extract(image, ContainerFormat::HeaderSize);
        const std::string magic(header.begin(), header.begin()+8);
        if (magic != "DSTEG001") { std::cout << "No DataStego signature found.\n"; return 0; }
        const auto info = ContainerFormat::inspect(header, image.capacityBytes());
        std::cout << "Container signature found (not authenticated without password).\n"
                  << "Ciphertext: " << info.ciphertextSize << " bytes\n"
                  << "PBKDF2 iterations: " << info.iterations << '\n';
        return 0;
    }
    if (command == "compare") {
        const auto options = parse(arguments, {"--original","--stego"});
        const auto a = ImageHandler::load(pathOption(options, "--original"));
        const auto b = ImageHandler::load(pathOption(options, "--stego"));
        const auto psnr = ImageHandler::psnr(a, b);
        std::size_t changed = 0, alphaChanged = 0;
        unsigned maxDifference = 0;
        for (std::size_t i = 0; i < a.rgba.size(); ++i) {
            const auto difference = static_cast<unsigned>(std::abs(int(a.rgba[i])-int(b.rgba[i])));
            if (i % 4 == 3) alphaChanged += difference != 0;
            else { changed += difference != 0; maxDifference = std::max(maxDifference, difference); }
        }
        if (std::isinf(psnr)) std::cout << "RGB PSNR: infinity (RGB samples are identical)\n";
        else std::cout << "RGB PSNR: " << std::fixed << std::setprecision(4) << psnr << " dB\n";
        std::cout << "Changed RGB channels: " << changed << "\nMaximum RGB difference: " << maxDifference
                  << "\nChanged alpha channels: " << alphaChanged << '\n';
        return 0;
    }
    throw Error("Unknown command: " + command + "; use --help");
}

int CLIController::runInteractive() const {
    std::cout << "DataStego: шифрование файлов и LSB-стеганография\n"
                 "Указывайте полный путь к файлу или путь относительно текущей папки.\n"
                 "Путь можно вставить в кавычках. Для отмены операции оставьте строку пустой.\n";
    for (;;) {
        try {
            std::cout << "\n1. Спрятать файл в изображении\n"
                         "2. Извлечь файл из изображения\n"
                         "3. Узнать вместимость изображения\n"
                         "4. Сравнить изображения (PSNR)\n"
                         "5. Показать справку по командам\n"
                         "0. Выход\n";
            const auto choice = menuLine("Выберите действие: ");
            if (!choice || *choice == "0") return 0;
            if (*choice == "5") { help(); continue; }
            std::vector<std::string> arguments;
            std::vector<std::pair<std::string, std::string>> fields;
            if (*choice == "1") {
                arguments = {"hide"};
                fields = {{"--in", "Файл, который нужно спрятать: "},
                          {"--cover", "Исходное изображение PNG/BMP: "},
                          {"--out", "Путь нового PNG-контейнера: "}};
            } else if (*choice == "2") {
                arguments = {"extract"};
                fields = {{"--in", "PNG-контейнер: "},
                          {"--out", "Куда сохранить восстановленный файл: "}};
            } else if (*choice == "3") {
                arguments = {"info"};
                fields = {{"--in", "Изображение PNG/BMP: "}};
            } else if (*choice == "4") {
                arguments = {"compare"};
                fields = {{"--original", "Исходное изображение: "},
                          {"--stego", "Изображение с данными: "}};
            } else {
                std::cout << "Введите номер от 0 до 5.\n";
                continue;
            }
            bool cancelled = false;
            for (const auto& field : fields) {
                const auto value = menuLine(field.second);
                if (!value) return 0;
                if (value->empty()) { cancelled = true; break; }
                arguments.push_back(field.first);
                arguments.push_back(*value);
            }
            if (cancelled) { std::cout << "Операция отменена.\n"; continue; }
            if (*choice == "1" || *choice == "2")
                std::cout << "Введите пароль по запросу и нажмите Enter. Символы пароля не отображаются в терминале.\n";
            run(arguments);
            std::cout << "Готово.\n";
        } catch (const std::exception& error) {
            std::cerr << "Ошибка: " << error.what() << '\n';
        }
    }
}
}
