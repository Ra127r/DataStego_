#include "datastego/ContainerFormat.hpp"
#include <algorithm>
#include <array>

namespace datastego {
namespace {
constexpr std::array<std::uint8_t, 8> Magic = {'D','S','T','E','G','0','0','1'};
struct SecretKey {
    Key256 bytes{};
    ~SecretKey() { secureErase(bytes.data(), bytes.size()); }
};
bool safeName(const std::string& name) {
    if (name.empty() || name.size() > ContainerFormat::MaxNameBytes || name == "." || name == "..") return false;
    return std::none_of(name.begin(), name.end(), [](unsigned char c) {
        return c < 32 || c == 127 || c == '/' || c == '\\' || c == ':';
    });
}
}
std::size_t ContainerFormat::packedSize(std::size_t fileSize, std::size_t nameSize) {
    if (fileSize > MaxFileBytes || nameSize > MaxNameBytes) throw Error("File or filename exceeds the limit");
    return HeaderSize + InnerHeaderSize + nameSize + fileSize;
}
ContainerInfo ContainerFormat::inspect(const Bytes& header, std::size_t availableBytes) {
    if (header.size() < HeaderSize || !std::equal(Magic.begin(), Magic.end(), header.begin()))
        throw Error("No DataStego container found");
    if (header[8] != 1 || header[9] != 1 || binary::read16(header, 10) != HeaderSize)
        throw Error("Unsupported container version or algorithm");
    ContainerInfo info;
    info.iterations = binary::read32(header, 12);
    info.ciphertextSize = binary::read64(header, 16);
    if (info.iterations < CryptoEngine::MinContainerIterations || info.iterations > CryptoEngine::MaxContainerIterations)
        throw Error("Invalid PBKDF2 iteration count in container");
    if (info.ciphertextSize < InnerHeaderSize || info.ciphertextSize > MaxFileBytes + InnerHeaderSize + MaxNameBytes ||
        availableBytes < HeaderSize || info.ciphertextSize > availableBytes - HeaderSize)
        throw Error("Invalid payload length in container");
    return info;
}
Bytes ContainerFormat::pack(const Bytes& file, const std::string& filename,
                            std::string_view password, std::uint32_t iterations) {
    if (password.empty()) throw Error("Password must not be empty");
    if (!safeName(filename)) throw Error("Invalid filename for container metadata");
    if (iterations < CryptoEngine::MinContainerIterations || iterations > CryptoEngine::MaxContainerIterations)
        throw Error("PBKDF2 iterations must be between 100000 and 2000000");
    const auto size = packedSize(file.size(), filename.size());
    SecretBytes plaintext;
    plaintext.bytes.reserve(size - HeaderSize);
    binary::append64(plaintext.bytes, file.size());
    binary::append32(plaintext.bytes, crc32(file));
    binary::append16(plaintext.bytes, static_cast<std::uint16_t>(filename.size()));
    plaintext.bytes.insert(plaintext.bytes.end(), filename.begin(), filename.end());
    plaintext.bytes.insert(plaintext.bytes.end(), file.begin(), file.end());

    const auto salt = randomBytes(16);
    const auto nonceBytes = randomBytes(12);
    Nonce96 nonce{};
    std::copy(nonceBytes.begin(), nonceBytes.end(), nonce.begin());
    Bytes aad(Magic.begin(), Magic.end());
    aad.push_back(1);
    aad.push_back(1);
    binary::append16(aad, HeaderSize);
    binary::append32(aad, iterations);
    binary::append64(aad, plaintext.bytes.size());
    aad.insert(aad.end(), salt.begin(), salt.end());
    aad.insert(aad.end(), nonce.begin(), nonce.end());
    SecretKey key;
    key.bytes = pbkdf2Sha256(password, salt, iterations);
    auto encrypted = CryptoEngine::encrypt(plaintext.bytes, key.bytes, nonce, aad);
    Bytes out = aad;
    out.reserve(size);
    out.insert(out.end(), encrypted.tag.begin(), encrypted.tag.end());
    out.insert(out.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());
    return out;
}
RecoveredFile ContainerFormat::unpack(const Bytes& container, std::string_view password) {
    const auto info = inspect(container, container.size());
    if (container.size() != HeaderSize + info.ciphertextSize) throw Error("Unexpected bytes after container payload");
    Bytes salt(container.begin() + 24, container.begin() + 40);
    Nonce96 nonce{};
    std::copy_n(container.begin() + 40, 12, nonce.begin());
    Block128 tag{};
    std::copy_n(container.begin() + 52, 16, tag.begin());
    Bytes aad(container.begin(), container.begin() + 52);
    Bytes ciphertext(container.begin() + HeaderSize, container.end());
    SecretKey key;
    key.bytes = pbkdf2Sha256(password, salt, info.iterations);
    SecretBytes plaintext(CryptoEngine::decrypt(ciphertext, key.bytes, nonce, aad, tag));
    const auto fileSize = binary::read64(plaintext.bytes, 0);
    const auto checksum = binary::read32(plaintext.bytes, 8);
    const auto nameSize = binary::read16(plaintext.bytes, 12);
    if (nameSize == 0 || nameSize > MaxNameBytes || nameSize > plaintext.bytes.size() - InnerHeaderSize ||
        fileSize != plaintext.bytes.size() - InnerHeaderSize - nameSize)
        throw Error("Invalid encrypted file metadata");
    RecoveredFile out;
    out.name.assign(plaintext.bytes.begin() + InnerHeaderSize, plaintext.bytes.begin() + InnerHeaderSize + nameSize);
    if (!safeName(out.name)) throw Error("Unsafe filename in container metadata");
    out.data.assign(plaintext.bytes.begin() + InnerHeaderSize + nameSize, plaintext.bytes.end());
    if (crc32(out.data) != checksum) throw Error("File CRC32 mismatch");
    return out;
}
}
