#include "datastego/FileIO.hpp"
#include <algorithm>
#include <fstream>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace datastego {
#ifdef _WIN32
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
}
#endif
Bytes readFile(const std::filesystem::path& path, std::size_t maximum) {
#ifdef _WIN32
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) throw Error("Cannot open input file");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum) throw Error("Input exceeds the file size limit");
    Bytes out(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < out.size()) {
        DWORD got = 0;
        const auto n = static_cast<DWORD>(std::min<std::size_t>(out.size() - offset, 1024 * 1024));
        if (!ReadFile(file.value, out.data() + offset, n, &got, nullptr) || got == 0)
            throw Error("Cannot read input file completely");
        offset += got;
    }
    return out;
#else
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw Error("Cannot open input file");
    const auto size = file.tellg();
    if (size < 0 || static_cast<std::uintmax_t>(size) > maximum) throw Error("Input exceeds the file size limit");
    Bytes out(static_cast<std::size_t>(size));
    file.seekg(0);
    if (!out.empty() && !file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size())))
        throw Error("Cannot read input file completely");
    return out;
#endif
}
void writeFile(const std::filesystem::path& path, const Bytes& bytes, bool overwrite) {
#ifdef _WIN32
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            overwrite ? CREATE_ALWAYS : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE)
        throw Error("Cannot create output file (it may already exist; use --force to replace it)");
    std::size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        DWORD written = 0;
        const auto n = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1024 * 1024));
        if (!WriteFile(file.value, bytes.data() + offset, n, &written, nullptr) || written == 0) { ok = false; break; }
        offset += written;
    }
    if (ok) ok = FlushFileBuffers(file.value) != 0;
    if (!ok) {
        CloseHandle(file.value); file.value = INVALID_HANDLE_VALUE;
        DeleteFileW(path.c_str());
        throw Error("Cannot write output file completely");
    }
#else
    const int flags = O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL);
    const int file = ::open(path.c_str(), flags, 0600);
    if (file < 0) throw Error("Cannot create output file (it may already exist; use --force to replace it)");
    std::size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        const auto n = ::write(file, bytes.data() + offset, std::min<std::size_t>(bytes.size() - offset, 1024 * 1024));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        offset += static_cast<std::size_t>(n);
    }
    if (ok) ok = ::fsync(file) == 0;
    if (::close(file) != 0) ok = false;
    if (!ok) { ::unlink(path.c_str()); throw Error("Cannot write output file completely"); }
#endif
}
bool sameFile(const std::filesystem::path& first, const std::filesystem::path& second) {
    std::error_code error;
    if (std::filesystem::equivalent(first, second, error) && !error) return true;
    error.clear();
    const auto a = std::filesystem::weakly_canonical(first, error);
    if (error) return false;
    const auto b = std::filesystem::weakly_canonical(second, error);
    return !error && a == b;
}
}
