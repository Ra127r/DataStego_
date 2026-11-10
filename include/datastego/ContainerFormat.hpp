#pragma once

#include "datastego/CryptoEngine.hpp"

namespace datastego {
struct ContainerInfo {
    std::uint32_t iterations = 0;
    std::uint64_t ciphertextSize = 0;
};
struct RecoveredFile {
    std::string name;
    Bytes data;
    ~RecoveredFile() { secureErase(data.data(), data.size()); }
    RecoveredFile() = default;
    RecoveredFile(const RecoveredFile&) = delete;
    RecoveredFile& operator=(const RecoveredFile&) = delete;
    RecoveredFile(RecoveredFile&&) noexcept = default;
    RecoveredFile& operator=(RecoveredFile&&) noexcept = default;
};

class ContainerFormat {
public:
    static constexpr std::size_t HeaderSize = 68;
    static constexpr std::size_t InnerHeaderSize = 14;
    static constexpr std::size_t MaxNameBytes = 255;
    static std::size_t packedSize(std::size_t fileSize, std::size_t nameSize);
    static ContainerInfo inspect(const Bytes& header, std::size_t availableBytes);
    static Bytes pack(const Bytes& file, const std::string& filename, std::string_view password,
                      std::uint32_t iterations = CryptoEngine::DefaultIterations);
    static RecoveredFile unpack(const Bytes& container, std::string_view password);
};
}
