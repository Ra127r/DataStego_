#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace datastego {
using Bytes = std::vector<std::uint8_t>;


constexpr std::size_t MaxFileBytes = 128u * 1024u * 1024u;
constexpr std::size_t MaxImageBytes = 256u * 1024u * 1024u;

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

void secureErase(void* data, std::size_t size) noexcept;


class SecretBytes {
public:
    Bytes bytes;
    SecretBytes() = default;
    explicit SecretBytes(Bytes value) : bytes(std::move(value)) {}
    ~SecretBytes() { secureErase(bytes.data(), bytes.size()); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
};

namespace binary {
inline void append16(Bytes& out, std::uint16_t n) {
    out.push_back(static_cast<std::uint8_t>(n >> 8));
    out.push_back(static_cast<std::uint8_t>(n));
}
inline void append32(Bytes& out, std::uint32_t n) {
    for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
}
inline void append64(Bytes& out, std::uint64_t n) {
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
}
inline void require(const Bytes& data, std::size_t offset, std::size_t size) {
    if (offset > data.size() || size > data.size() - offset) throw Error("Truncated binary data");
}
inline std::uint16_t read16(const Bytes& data, std::size_t at) {
    require(data, at, 2);
    return static_cast<std::uint16_t>((std::uint16_t(data[at]) << 8) | data[at + 1]);
}
inline std::uint32_t read32(const Bytes& data, std::size_t at) {
    require(data, at, 4);
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n = (n << 8) | data[at + i];
    return n;
}
inline std::uint64_t read64(const Bytes& data, std::size_t at) {
    require(data, at, 8);
    std::uint64_t n = 0;
    for (std::size_t i = 0; i < 8; ++i) n = (n << 8) | data[at + i];
    return n;
}
}
}
