#pragma once

#include "datastego/Types.hpp"
#include <array>
#include <string_view>

namespace datastego {
using Digest256 = std::array<std::uint8_t, 32>;
using Key256 = std::array<std::uint8_t, 32>;
using Block128 = std::array<std::uint8_t, 16>;
using Nonce96 = std::array<std::uint8_t, 12>;

class Sha256 {
public:
    Sha256();
    ~Sha256();
    void update(const std::uint8_t* data, std::size_t size);
    Digest256 finish();
private:
    void compress(const std::uint8_t* block);
    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t total_ = 0;
    std::size_t used_ = 0;
    bool finished_ = false;
};

Digest256 sha256(const Bytes& data);
Digest256 hmacSha256(const Bytes& key, const Bytes& message);
Key256 pbkdf2Sha256(std::string_view password, const Bytes& salt, std::uint32_t iterations);
Bytes randomBytes(std::size_t count);
std::uint32_t crc32(const std::uint8_t* data, std::size_t size);
inline std::uint32_t crc32(const Bytes& data) { return crc32(data.data(), data.size()); }

class Aes256 {
public:
    explicit Aes256(const Key256& key);
    ~Aes256();
    Aes256(const Aes256&) = delete;
    Aes256& operator=(const Aes256&) = delete;
    Block128 encryptBlock(const Block128& input) const;
private:
    std::array<std::uint8_t, 240> roundKeys_{};
};

struct GcmResult {
    Bytes ciphertext;
    Block128 tag{};
};

class CryptoEngine {
public:
    static constexpr std::uint32_t DefaultIterations = 600000;
    static constexpr std::uint32_t MinContainerIterations = 100000;
    static constexpr std::uint32_t MaxContainerIterations = 2000000;

    static GcmResult encrypt(const Bytes& plaintext, const Key256& key,
                             const Nonce96& nonce, const Bytes& aad);

    static Bytes decrypt(const Bytes& ciphertext, const Key256& key,
                         const Nonce96& nonce, const Bytes& aad, const Block128& tag);
};
}
