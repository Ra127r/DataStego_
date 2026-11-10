#include "datastego/CryptoEngine.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

namespace datastego {
void secureErase(void* data, std::size_t size) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(data);
    while (size--) *p++ = 0;
}

namespace {
constexpr std::array<std::uint32_t, 64> ShaConstants = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
constexpr std::array<std::uint8_t, 256> Sbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
std::uint32_t rotateRight(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
std::uint8_t xtime(std::uint8_t x) {
    return static_cast<std::uint8_t>((x << 1) ^ (0x1b & (0u - (x >> 7))));
}

class PreparedHmac {
public:
    PreparedHmac(const std::uint8_t* key, std::size_t size) {
        std::array<std::uint8_t, 64> block{};
        if (size > block.size()) {
            Sha256 hash;
            hash.update(key, size);
            auto digest = hash.finish();
            std::copy(digest.begin(), digest.end(), block.begin());
            secureErase(digest.data(), digest.size());
        } else if (size) std::copy_n(key, size, block.begin());
        for (auto& b : block) b ^= 0x36;
        inner_.update(block.data(), block.size());
        for (auto& b : block) b ^= 0x36 ^ 0x5c;
        outer_.update(block.data(), block.size());
        secureErase(block.data(), block.size());
    }
    Digest256 calculate(const std::uint8_t* data, std::size_t size) const {
        auto inner = inner_;
        inner.update(data, size);
        auto digest = inner.finish();
        auto outer = outer_;
        outer.update(digest.data(), digest.size());
        secureErase(digest.data(), digest.size());
        return outer.finish();
    }
private:
    Sha256 inner_, outer_;
};

Block128 multiplyGf128(const Block128& x, const Block128& y) {


    Block128 result{}, v = y;
    for (unsigned bit = 0; bit < 128; ++bit) {
        const auto mask = static_cast<std::uint8_t>(0u - ((x[bit / 8] >> (7 - bit % 8)) & 1));
        for (unsigned i = 0; i < 16; ++i) result[i] ^= v[i] & mask;
        const auto reduction = static_cast<std::uint8_t>(0xe1 & (0u - (v[15] & 1)));
        for (int i = 15; i > 0; --i) v[i] = static_cast<std::uint8_t>((v[i] >> 1) | (v[i - 1] << 7));
        v[0] = static_cast<std::uint8_t>((v[0] >> 1) ^ reduction);
    }
    secureErase(v.data(), v.size());
    return result;
}
void hashGcmBytes(Block128& state, const Block128& h, const Bytes& data) {
    for (std::size_t offset = 0; offset < data.size(); offset += 16) {
        const auto n = std::min<std::size_t>(16, data.size() - offset);
        for (std::size_t i = 0; i < n; ++i) state[i] ^= data[offset + i];
        state = multiplyGf128(state, h);
    }
}
void checkGcmLengths(const Bytes& data, const Bytes& aad) {
    if (static_cast<std::uint64_t>(data.size()) > (std::uint64_t{1} << 36) - 32 ||
        static_cast<std::uint64_t>(aad.size()) > std::numeric_limits<std::uint64_t>::max() / 8)
        throw Error("GCM input is too large");
}
Block128 initialCounter(const Nonce96& nonce) {
    Block128 block{};
    std::copy(nonce.begin(), nonce.end(), block.begin());
    block[15] = 1;
    return block;
}
Block128 authenticationTag(const Aes256& aes, const Nonce96& nonce,
                           const Bytes& aad, const Bytes& ciphertext) {
    const Block128 zero{};
    auto h = aes.encryptBlock(zero);
    Block128 state{};
    hashGcmBytes(state, h, aad);
    hashGcmBytes(state, h, ciphertext);
    const auto aBits = static_cast<std::uint64_t>(aad.size()) * 8;
    const auto cBits = static_cast<std::uint64_t>(ciphertext.size()) * 8;
    for (unsigned i = 0; i < 8; ++i) {
        state[7 - i] ^= static_cast<std::uint8_t>(aBits >> (8 * i));
        state[15 - i] ^= static_cast<std::uint8_t>(cBits >> (8 * i));
    }
    state = multiplyGf128(state, h);
    auto mask = aes.encryptBlock(initialCounter(nonce));
    for (unsigned i = 0; i < 16; ++i) state[i] ^= mask[i];
    secureErase(h.data(), h.size());
    secureErase(mask.data(), mask.size());
    return state;
}
Bytes counterTransform(const Aes256& aes, const Nonce96& nonce, const Bytes& data) {
    Bytes out(data.size());
    auto counter = initialCounter(nonce);
    for (std::size_t offset = 0; offset < data.size(); offset += 16) {
        for (int i = 15; i >= 12; --i) if (++counter[i]) break;
        auto stream = aes.encryptBlock(counter);
        const auto n = std::min<std::size_t>(16, data.size() - offset);
        for (std::size_t i = 0; i < n; ++i) out[offset + i] = data[offset + i] ^ stream[i];
        secureErase(stream.data(), stream.size());
    }
    return out;
}
}

Sha256::Sha256() : state_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19} {}
Sha256::~Sha256() {
    secureErase(state_.data(), sizeof(state_));
    secureErase(buffer_.data(), buffer_.size());
}
void Sha256::compress(const std::uint8_t* block) {
    std::array<std::uint32_t, 64> w{};
    for (unsigned i = 0; i < 16; ++i)
        for (unsigned j = 0; j < 4; ++j) w[i] = (w[i] << 8) | block[i * 4 + j];
    for (unsigned i = 16; i < 64; ++i) {
        const auto s0 = rotateRight(w[i-15],7) ^ rotateRight(w[i-15],18) ^ (w[i-15] >> 3);
        const auto s1 = rotateRight(w[i-2],17) ^ rotateRight(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    auto a=state_[0], b=state_[1], c=state_[2], d=state_[3];
    auto e=state_[4], f=state_[5], g=state_[6], h=state_[7];
    for (unsigned i = 0; i < 64; ++i) {
        const auto s1 = rotateRight(e,6) ^ rotateRight(e,11) ^ rotateRight(e,25);
        const auto choose = (e & f) ^ (~e & g);
        const auto t1 = h + s1 + choose + ShaConstants[i] + w[i];
        const auto s0 = rotateRight(a,2) ^ rotateRight(a,13) ^ rotateRight(a,22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto t2 = s0 + majority;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
    state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    secureErase(w.data(), sizeof(w));
}
void Sha256::update(const std::uint8_t* data, std::size_t size) {
    if (finished_) throw Error("SHA-256 is already finalized");
    if (size > std::numeric_limits<std::uint64_t>::max() / 8 - total_)
        throw Error("SHA-256 input is too large");
    total_ += size;
    while (size) {
        if (used_ == 0 && size >= 64) {
            compress(data); data += 64; size -= 64;
        } else {
            const auto n = std::min<std::size_t>(64 - used_, size);
            std::copy_n(data, n, buffer_.begin() + static_cast<std::ptrdiff_t>(used_));
            data += n; size -= n; used_ += n;
            if (used_ == 64) { compress(buffer_.data()); used_ = 0; }
        }
    }
}
Digest256 Sha256::finish() {
    if (finished_) throw Error("SHA-256 is already finalized");
    const auto bitLength = total_ * 8;
    buffer_[used_++] = 0x80;
    if (used_ > 56) {
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(used_), buffer_.end(), 0);
        compress(buffer_.data()); used_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(used_), buffer_.begin() + 56, 0);
    for (unsigned i = 0; i < 8; ++i) buffer_[63 - i] = static_cast<std::uint8_t>(bitLength >> (8 * i));
    compress(buffer_.data());
    Digest256 result{};
    for (unsigned i = 0; i < 32; ++i) result[i] = static_cast<std::uint8_t>(state_[i/4] >> (24 - 8 * (i%4)));
    finished_ = true;
    return result;
}
Digest256 sha256(const Bytes& data) {
    Sha256 hash; hash.update(data.data(), data.size()); return hash.finish();
}
Digest256 hmacSha256(const Bytes& key, const Bytes& message) {
    PreparedHmac hmac(key.data(), key.size());
    return hmac.calculate(message.data(), message.size());
}
Key256 pbkdf2Sha256(std::string_view password, const Bytes& salt, std::uint32_t iterations) {
    if (!iterations) throw Error("PBKDF2 iteration count must be positive");
    PreparedHmac hmac(reinterpret_cast<const std::uint8_t*>(password.data()), password.size());
    Bytes first = salt;
    binary::append32(first, 1);
    auto u = hmac.calculate(first.data(), first.size());
    auto result = u;
    for (std::uint32_t i = 1; i < iterations; ++i) {
        u = hmac.calculate(u.data(), u.size());
        for (unsigned j = 0; j < 32; ++j) result[j] ^= u[j];
    }
    secureErase(u.data(), u.size());
    return result;
}
Bytes randomBytes(std::size_t count) {
    Bytes result(count);
#ifdef _WIN32
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        throw Error("Cannot access the operating system random generator");
    std::size_t offset = 0;
    while (offset < count) {
        const auto n = static_cast<DWORD>(std::min<std::size_t>(count - offset, 1024 * 1024));
        if (!CryptGenRandom(provider, n, result.data() + offset)) {
            CryptReleaseContext(provider, 0);
            throw Error("Operating system random generator failed");
        }
        offset += n;
    }
    CryptReleaseContext(provider, 0);
#else
    std::ifstream source("/dev/urandom", std::ios::binary);
    if (!source || !source.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(count)))
        throw Error("Cannot read the operating system random generator");
#endif
    return result;
}
std::uint32_t crc32(const std::uint8_t* data, std::size_t size) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            auto n = i;
            for (unsigned bit = 0; bit < 8; ++bit) n = (n >> 1) ^ (0xedb88320u & (0u - (n & 1u)));
            t[i] = n;
        }
        return t;
    }();
    std::uint32_t result = 0xffffffffu;
    for (std::size_t i = 0; i < size; ++i) result = (result >> 8) ^ table[(result ^ data[i]) & 255];
    return result ^ 0xffffffffu;
}

Aes256::Aes256(const Key256& key) {
    std::copy(key.begin(), key.end(), roundKeys_.begin());
    std::size_t generated = 32;
    std::uint8_t rcon = 1;
    std::array<std::uint8_t, 4> temp{};
    while (generated < roundKeys_.size()) {
        std::copy_n(roundKeys_.begin() + static_cast<std::ptrdiff_t>(generated - 4), 4, temp.begin());
        if (generated % 32 == 0) {
            std::rotate(temp.begin(), temp.begin() + 1, temp.end());
            for (auto& b : temp) b = Sbox[b];
            temp[0] ^= rcon; rcon = xtime(rcon);
        } else if (generated % 32 == 16) {
            for (auto& b : temp) b = Sbox[b];
        }
        for (auto b : temp) {
            roundKeys_[generated] = roundKeys_[generated - 32] ^ b;
            ++generated;
        }
    }
    secureErase(temp.data(), temp.size());
}
Aes256::~Aes256() { secureErase(roundKeys_.data(), roundKeys_.size()); }
Block128 Aes256::encryptBlock(const Block128& input) const {

    auto state = input;
    for (unsigned i = 0; i < 16; ++i) state[i] ^= roundKeys_[i];
    for (unsigned round = 1; round <= 14; ++round) {
        for (auto& b : state) b = Sbox[b];
        auto shifted = state;
        for (unsigned row = 0; row < 4; ++row)
            for (unsigned col = 0; col < 4; ++col) shifted[4*col+row] = state[4*((col+row)%4)+row];
        state = shifted;
        secureErase(shifted.data(), shifted.size());
        if (round != 14) {
            for (unsigned col = 0; col < 4; ++col) {
                auto* p = state.data() + 4 * col;
                const auto a=p[0], b=p[1], c=p[2], d=p[3];
                p[0]=xtime(a) ^ xtime(b) ^ b ^ c ^ d;
                p[1]=a ^ xtime(b) ^ xtime(c) ^ c ^ d;
                p[2]=a ^ b ^ xtime(c) ^ xtime(d) ^ d;
                p[3]=xtime(a) ^ a ^ b ^ c ^ xtime(d);
            }
        }
        for (unsigned i = 0; i < 16; ++i) state[i] ^= roundKeys_[round*16+i];
    }
    return state;
}
GcmResult CryptoEngine::encrypt(const Bytes& plaintext, const Key256& key,
                                const Nonce96& nonce, const Bytes& aad) {
    checkGcmLengths(plaintext, aad);
    Aes256 aes(key);
    GcmResult result;
    result.ciphertext = counterTransform(aes, nonce, plaintext);
    result.tag = authenticationTag(aes, nonce, aad, result.ciphertext);
    return result;
}
Bytes CryptoEngine::decrypt(const Bytes& ciphertext, const Key256& key,
                            const Nonce96& nonce, const Bytes& aad, const Block128& tag) {
    checkGcmLengths(ciphertext, aad);
    Aes256 aes(key);
    auto expected = authenticationTag(aes, nonce, aad, ciphertext);
    std::uint8_t difference = 0;
    for (unsigned i = 0; i < 16; ++i) difference |= expected[i] ^ tag[i];
    secureErase(expected.data(), expected.size());
    if (difference) throw Error("Authentication failed: wrong password or damaged container");
    return counterTransform(aes, nonce, ciphertext);
}
}
