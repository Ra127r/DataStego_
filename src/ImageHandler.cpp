#include "datastego/ImageHandler.hpp"
#include "datastego/CryptoEngine.hpp"
#include "datastego/FileIO.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <string>

namespace datastego {
namespace {
constexpr std::array<std::uint8_t, 8> PngSignature = {137,80,78,71,13,10,26,10};

std::size_t checkedImageSize(std::uint32_t width, std::uint32_t height) {
    if (!width || !height || std::uint64_t(width) * height > MaxImageBytes / 4)
        throw Error("Invalid image dimensions or image exceeds the 256 MiB decoded limit");
    return static_cast<std::size_t>(std::uint64_t(width) * height * 4);
}
std::uint32_t adler32(const Bytes& data) {
    std::uint32_t a = 1, b = 0;
    for (std::size_t offset = 0; offset < data.size();) {
        const auto end = std::min(data.size(), offset + 5552);
        for (; offset < end; ++offset) { a += data[offset]; b += a; }
        a %= 65521; b %= 65521;
    }
    return (b << 16) | a;
}


class BitReader {
public:
    BitReader(const Bytes& data, std::size_t begin, std::size_t end)
        : data_(data), bit_(begin * 8), end_(end * 8) {}
    unsigned read(unsigned count) {
        if (count > 24 || count > end_ - bit_) throw Error("Truncated DEFLATE stream");
        unsigned result = 0;
        for (unsigned i = 0; i < count; ++i, ++bit_)
            result |= ((data_[bit_ / 8] >> (bit_ % 8)) & 1u) << i;
        return result;
    }
    void align() { bit_ = (bit_ + 7) & ~std::size_t{7}; }
    std::size_t endByte() const { return (bit_ + 7) / 8; }
private:
    const Bytes& data_;
    std::size_t bit_, end_;
};

class Huffman {
public:
    explicit Huffman(const std::vector<unsigned>& lengths) {
        for (auto length : lengths) {
            if (length > 15) throw Error("Invalid DEFLATE Huffman code length");
            if (length) ++counts_[length];
        }
        int space = 1;
        unsigned code = 0, offset = 0;
        for (unsigned len = 1; len <= 15; ++len) {
            space = space * 2 - static_cast<int>(counts_[len]);
            if (space < 0) throw Error("Oversubscribed DEFLATE Huffman tree");
            code = (code + counts_[len - 1]) << 1;
            firstCode_[len] = code;
            firstSymbol_[len] = offset;
            offset += counts_[len];
        }
        symbols_.resize(offset);
        auto position = firstSymbol_;
        for (unsigned symbol = 0; symbol < lengths.size(); ++symbol)
            if (lengths[symbol]) symbols_[position[lengths[symbol]]++] = symbol;
    }
    unsigned decode(BitReader& reader) const {
        unsigned code = 0;
        for (unsigned len = 1; len <= 15; ++len) {

            code = (code << 1) | reader.read(1);
            if (code >= firstCode_[len] && code - firstCode_[len] < counts_[len])
                return symbols_[firstSymbol_[len] + code - firstCode_[len]];
        }
        throw Error("Invalid DEFLATE Huffman symbol");
    }
private:
    std::array<unsigned, 16> counts_{}, firstCode_{}, firstSymbol_{};
    std::vector<unsigned> symbols_;
};

Bytes inflateZlib(const Bytes& input, std::size_t expected) {
    if (input.size() < 6 || (input[0] & 15) != 8 || (input[0] >> 4) > 7 ||
        ((unsigned(input[0]) << 8) | input[1]) % 31 || (input[1] & 0x20))
        throw Error("Invalid or unsupported PNG zlib header");
    if (expected > MaxImageBytes) throw Error("PNG decompression exceeds memory limit");
    BitReader reader(input, 2, input.size() - 4);
    Bytes out;
    out.reserve(expected);
    bool last = false;
    constexpr std::array<unsigned, 29> LengthBase = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    constexpr std::array<unsigned, 29> LengthExtra = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    constexpr std::array<unsigned, 30> DistanceBase = {
        1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,
        2049,3073,4097,6145,8193,12289,16385,24577};
    constexpr std::array<unsigned, 30> DistanceExtra = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    std::size_t blocks = 0;
    while (!last) {
        if (++blocks > 1000000) throw Error("Too many DEFLATE blocks");
        last = reader.read(1) != 0;
        const auto type = reader.read(2);
        if (type == 0) {
            reader.align();
            const auto length = reader.read(16), inverse = reader.read(16);
            if ((length ^ inverse) != 65535 || length > expected - out.size())
                throw Error("Invalid uncompressed DEFLATE block");
            for (unsigned i = 0; i < length; ++i) out.push_back(static_cast<std::uint8_t>(reader.read(8)));
            continue;
        }
        if (type == 3) throw Error("Reserved DEFLATE block type");
        std::vector<unsigned> literalLengths, distanceLengths;
        if (type == 1) {
            literalLengths.resize(288);
            for (unsigned i = 0; i < 288; ++i) literalLengths[i] = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
            distanceLengths.assign(32, 5);
        } else {
            const auto literalCount = reader.read(5) + 257;
            const auto distanceCount = reader.read(5) + 1;
            const auto codeCount = reader.read(4) + 4;
            if (literalCount > 286) throw Error("Too many DEFLATE literal codes");
            constexpr std::array<unsigned, 19> CodeOrder = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            std::vector<unsigned> codeLengths(19, 0);
            for (unsigned i = 0; i < codeCount; ++i) codeLengths[CodeOrder[i]] = reader.read(3);
            Huffman codeTree(codeLengths);
            std::vector<unsigned> lengths;
            const auto total = literalCount + distanceCount;
            while (lengths.size() < total) {
                const auto symbol = codeTree.decode(reader);
                if (symbol <= 15) lengths.push_back(symbol);
                else {
                    unsigned count = 0, value = 0;
                    if (symbol == 16) {
                        if (lengths.empty()) throw Error("DEFLATE repeat without previous length");
                        count = reader.read(2) + 3; value = lengths.back();
                    } else if (symbol == 17) count = reader.read(3) + 3;
                    else if (symbol == 18) count = reader.read(7) + 11;
                    else throw Error("Invalid DEFLATE code length symbol");
                    if (count > total - lengths.size()) throw Error("DEFLATE code length repeat exceeds tree");
                    lengths.insert(lengths.end(), count, value);
                }
            }
            literalLengths.assign(lengths.begin(), lengths.begin() + literalCount);
            distanceLengths.assign(lengths.begin() + literalCount, lengths.end());
            if (!literalLengths[256]) throw Error("DEFLATE tree has no end marker");
        }
        Huffman literals(literalLengths), distances(distanceLengths);
        for (;;) {
            const auto symbol = literals.decode(reader);
            if (symbol < 256) {
                if (out.size() == expected) throw Error("PNG decompression exceeds declared dimensions");
                out.push_back(static_cast<std::uint8_t>(symbol));
            } else if (symbol == 256) break;
            else {
                if (symbol > 285) throw Error("Invalid DEFLATE length symbol");
                const auto lengthIndex = symbol - 257;
                const auto length = LengthBase[lengthIndex] + reader.read(LengthExtra[lengthIndex]);
                const auto distanceSymbol = distances.decode(reader);
                if (distanceSymbol >= 30) throw Error("Invalid DEFLATE distance symbol");
                const auto distance = DistanceBase[distanceSymbol] + reader.read(DistanceExtra[distanceSymbol]);
                if (distance > out.size() || length > expected - out.size()) throw Error("Invalid DEFLATE back reference");
                for (unsigned i = 0; i < length; ++i) out.push_back(out[out.size() - distance]);
            }
        }
    }
    if (reader.endByte() != input.size() - 4 || out.size() != expected ||
        adler32(out) != binary::read32(input, input.size() - 4)) throw Error("PNG zlib length or Adler32 mismatch");
    return out;
}

std::uint8_t paeth(unsigned left, unsigned up, unsigned corner) {
    const int p = static_cast<int>(left + up) - static_cast<int>(corner);
    const auto a = std::abs(p - static_cast<int>(left));
    const auto b = std::abs(p - static_cast<int>(up));
    const auto c = std::abs(p - static_cast<int>(corner));
    return static_cast<std::uint8_t>(a <= b && a <= c ? left : b <= c ? up : corner);
}
unsigned sampleAt(const Bytes& row, std::size_t index, unsigned depth) {
    if (depth == 16) return (unsigned(row[index*2]) << 8) | row[index*2+1];
    if (depth == 8) return row[index];
    const auto bit = index * depth;
    return (row[bit / 8] >> (8 - depth - bit % 8)) & ((1u << depth) - 1);
}
std::uint8_t sampleTo8(unsigned value, unsigned depth) {
    return static_cast<std::uint8_t>(depth == 16 ? value >> 8 : value * 255 / ((1u << depth) - 1));
}

Image decodePng(const Bytes& file) {
    std::uint32_t width = 0, height = 0;
    unsigned depth = 0, color = 0, interlace = 0;
    Bytes compressed, palette, transparency;
    bool haveHeader = false, haveData = false, dataEnded = false, haveEnd = false;
    bool havePalette = false, haveTransparency = false;
    std::size_t offset = 8;
    while (offset < file.size()) {
        binary::require(file, offset, 12);
        const auto length = binary::read32(file, offset);
        if (length > file.size() - offset - 12) throw Error("Truncated PNG chunk");
        const auto data = offset + 8;
        const std::string type(file.begin() + offset + 4, file.begin() + offset + 8);
        if (crc32(file.data() + offset + 4, static_cast<std::size_t>(length) + 4) != binary::read32(file, data + length))
            throw Error("PNG chunk CRC32 mismatch");
        if (!haveHeader && type != "IHDR") throw Error("PNG must start with IHDR");
        if (haveData && type != "IDAT") dataEnded = true;
        if (type == "IHDR") {
            if (haveHeader || length != 13) throw Error("Invalid PNG IHDR");
            width = binary::read32(file, data); height = binary::read32(file, data + 4);
            checkedImageSize(width, height);
            depth = file[data+8]; color = file[data+9]; interlace = file[data+12];
            bool validDepth = false;
            if (color == 0) validDepth = depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16;
            if (color == 2 || color == 4 || color == 6) validDepth = depth == 8 || depth == 16;
            if (color == 3) validDepth = depth == 1 || depth == 2 || depth == 4 || depth == 8;
            if (!validDepth || file[data+10] || file[data+11] || interlace > 1) throw Error("Unsupported PNG format");
            haveHeader = true;
        } else if (type == "PLTE") {
            if (havePalette || haveData || !length || length > 768 || length % 3 || color == 0 || color == 4)
                throw Error("Invalid PNG palette");
            palette.assign(file.begin() + data, file.begin() + data + length);
            havePalette = true;
        } else if (type == "tRNS") {
            if (haveTransparency || haveData || color == 4 || color == 6 ||
                (color == 0 && length != 2) || (color == 2 && length != 6) ||
                (color == 3 && (!havePalette || !length || length > palette.size() / 3)))
                throw Error("Invalid PNG transparency");
            transparency.assign(file.begin() + data, file.begin() + data + length);
            haveTransparency = true;
        } else if (type == "IDAT") {
            if (dataEnded || (color == 3 && !havePalette) || length > MaxImageBytes - compressed.size())
                throw Error("Invalid or excessive PNG IDAT data");
            compressed.insert(compressed.end(), file.begin() + data, file.begin() + data + length);
            haveData = true;
        } else if (type == "IEND") {
            if (length || !haveData) throw Error("Invalid PNG IEND");
            offset += static_cast<std::size_t>(length) + 12;
            haveEnd = true; break;
        } else if ((static_cast<unsigned char>(type[0]) & 32) == 0) throw Error("Unknown critical PNG chunk");
        offset += static_cast<std::size_t>(length) + 12;
    }
    if (!haveEnd || offset != file.size()) throw Error("PNG is incomplete or has trailing data");
    if (color == 3 && palette.size() / 3 > (1u << depth)) throw Error("PNG palette exceeds bit depth");
    const unsigned channels = color == 0 || color == 3 ? 1 : color == 2 ? 3 : color == 4 ? 2 : 4;
    const auto bytesPerPixel = std::max(1u, (channels * depth + 7) / 8);
    constexpr std::array<unsigned, 7> X = {0,4,0,2,0,1,0}, Y = {0,0,4,0,2,0,1};
    constexpr std::array<unsigned, 7> DX = {8,8,4,4,2,2,1}, DY = {8,8,8,4,4,2,2};
    struct Pass { unsigned x,y,dx,dy; std::size_t w,h,rowBytes; };
    std::vector<Pass> passes;
    std::uint64_t expected = 0;
    for (unsigned p = 0; p < (interlace ? 7u : 1u); ++p) {
        const unsigned x = interlace ? X[p] : 0, y = interlace ? Y[p] : 0;
        const unsigned dx = interlace ? DX[p] : 1, dy = interlace ? DY[p] : 1;
        const std::size_t w = width <= x ? 0 : (width - x + dx - 1) / dx;
        const std::size_t h = height <= y ? 0 : (height - y + dy - 1) / dy;
        if (!w || !h) continue;
        const auto rowBytes = (std::uint64_t(w) * channels * depth + 7) / 8;
        expected += std::uint64_t(h) * (rowBytes + 1);
        if (expected > MaxImageBytes) throw Error("PNG scanlines exceed the memory limit");
        passes.push_back({x,y,dx,dy,w,h,static_cast<std::size_t>(rowBytes)});
    }
    if (expected > MaxImageBytes) throw Error("PNG scanlines exceed the memory limit");
    auto raw = inflateZlib(compressed, static_cast<std::size_t>(expected));
    Image image{width, height, Bytes(checkedImageSize(width, height), 255)};
    std::size_t rawOffset = 0;
    for (const auto& pass : passes) {
        Bytes previous(pass.rowBytes, 0), row(pass.rowBytes, 0);
        for (std::size_t y = 0; y < pass.h; ++y) {
            const auto filter = raw[rawOffset++];
            if (filter > 4) throw Error("Invalid PNG scanline filter");
            for (std::size_t i = 0; i < row.size(); ++i) {
                const unsigned left = i < bytesPerPixel ? 0 : row[i - bytesPerPixel];
                const unsigned up = previous[i], corner = i < bytesPerPixel ? 0 : previous[i - bytesPerPixel];
                unsigned predictor = 0;
                if (filter == 1) predictor = left;
                if (filter == 2) predictor = up;
                if (filter == 3) predictor = (left + up) / 2;
                if (filter == 4) predictor = paeth(left, up, corner);
                row[i] = static_cast<std::uint8_t>(raw[rawOffset++] + predictor);
            }
            for (std::size_t x = 0; x < pass.w; ++x) {
                const auto pixel = ((pass.y + y * pass.dy) * width + pass.x + x * pass.dx) * 4;
                std::array<unsigned, 4> s{};
                for (unsigned c = 0; c < channels; ++c) s[c] = sampleAt(row, x * channels + c, depth);
                if (color == 3) {
                    if (s[0] >= palette.size() / 3) throw Error("PNG palette index is out of range");
                    for (unsigned c = 0; c < 3; ++c) image.rgba[pixel+c] = palette[s[0]*3+c];
                    if (s[0] < transparency.size()) image.rgba[pixel+3] = transparency[s[0]];
                } else if (color == 0 || color == 4) {
                    for (unsigned c = 0; c < 3; ++c) image.rgba[pixel+c] = sampleTo8(s[0], depth);
                    if (color == 4) image.rgba[pixel+3] = sampleTo8(s[1], depth);
                    if (color == 0 && !transparency.empty() && s[0] == binary::read16(transparency, 0)) image.rgba[pixel+3] = 0;
                } else {
                    for (unsigned c = 0; c < 3; ++c) image.rgba[pixel+c] = sampleTo8(s[c], depth);
                    if (color == 6) image.rgba[pixel+3] = sampleTo8(s[3], depth);
                    if (color == 2 && !transparency.empty() && s[0] == binary::read16(transparency,0) &&
                        s[1] == binary::read16(transparency,2) && s[2] == binary::read16(transparency,4)) image.rgba[pixel+3] = 0;
                }
            }
            previous.swap(row);
        }
    }
    return image;
}

std::uint16_t little16(const Bytes& b, std::size_t p) {
    binary::require(b, p, 2); return static_cast<std::uint16_t>(b[p] | (unsigned(b[p+1]) << 8));
}
std::uint32_t little32(const Bytes& b, std::size_t p) {
    binary::require(b, p, 4);
    return std::uint32_t(b[p]) | (std::uint32_t(b[p+1]) << 8) | (std::uint32_t(b[p+2]) << 16) | (std::uint32_t(b[p+3]) << 24);
}
Image decodeBmp(const Bytes& file) {
    binary::require(file, 0, 54);
    const auto dataOffset = little32(file, 10), dibSize = little32(file, 14);
    if (dibSize < 40 || dibSize > file.size() - 14 || dataOffset < 14u + std::uint64_t(dibSize))
        throw Error("Unsupported BMP header");
    const auto signedWidth = static_cast<std::int32_t>(little32(file, 18));
    const auto signedHeight = static_cast<std::int32_t>(little32(file, 22));
    const auto bpp = little16(file, 28);
    if (signedWidth <= 0 || !signedHeight || little16(file, 26) != 1 || (bpp != 24 && bpp != 32) || little32(file, 30) != 0)
        throw Error("BMP must be uncompressed 24-bit or 32-bit BI_RGB");
    const auto width = static_cast<std::uint32_t>(signedWidth);
    const auto height = static_cast<std::uint32_t>(signedHeight < 0 ? -std::int64_t(signedHeight) : signedHeight);
    Image image{width, height, Bytes(checkedImageSize(width, height), 255)};
    const auto stride = ((std::uint64_t(width) * bpp + 31) / 32) * 4;
    if (dataOffset > file.size() || stride * height > file.size() - dataOffset) throw Error("Truncated BMP pixels");
    bool anyAlpha = false;
    for (std::uint32_t y = 0; y < height; ++y) {
        const auto sourceY = signedHeight < 0 ? y : height - y - 1;
        for (std::uint32_t x = 0; x < width; ++x) {
            const auto from = static_cast<std::size_t>(dataOffset + stride * sourceY + x * (bpp / 8));
            const auto to = (std::size_t(y) * width + x) * 4;
            image.rgba[to] = file[from+2]; image.rgba[to+1] = file[from+1]; image.rgba[to+2] = file[from];
            if (bpp == 32) { image.rgba[to+3] = file[from+3]; anyAlpha |= file[from+3] != 0; }
        }
    }

    if (bpp == 32 && !anyAlpha) for (std::size_t i = 3; i < image.rgba.size(); i += 4) image.rgba[i] = 255;
    return image;
}
void appendChunk(Bytes& file, const char* name, const Bytes& data) {
    binary::append32(file, static_cast<std::uint32_t>(data.size()));
    const auto start = file.size();
    file.insert(file.end(), name, name + 4);
    file.insert(file.end(), data.begin(), data.end());
    binary::append32(file, crc32(file.data() + start, data.size() + 4));
}
}

void Image::validate() const {
    if (rgba.size() != checkedImageSize(width, height)) throw Error("Image buffer size does not match dimensions");
}
std::size_t Image::capacityBytes() const { validate(); return (std::size_t(width) * height * 3) / 8; }
Image ImageHandler::load(const std::filesystem::path& path) { return decode(readFile(path, MaxImageBytes)); }
Image ImageHandler::decode(const Bytes& file) {
    if (file.size() > MaxImageBytes) throw Error("Image file exceeds the 256 MiB limit");
    if (file.size() >= PngSignature.size() && std::equal(PngSignature.begin(), PngSignature.end(), file.begin())) return decodePng(file);
    if (file.size() >= 2 && file[0] == 'B' && file[1] == 'M') return decodeBmp(file);
    throw Error("Expected a PNG or BMP image");
}
Bytes ImageHandler::encodePng(const Image& image) {
    image.validate();
    const auto stride = std::size_t(image.width) * 4;
    if (image.rgba.size() > MaxImageBytes - image.height) throw Error("PNG scanlines exceed memory limit");
    Bytes raw;
    raw.reserve(image.rgba.size() + image.height);
    for (std::uint32_t y = 0; y < image.height; ++y) {
        raw.push_back(0);
        raw.insert(raw.end(), image.rgba.begin() + y * stride, image.rgba.begin() + (y + 1) * stride);
    }


    Bytes zlib{0x78, 0x01};
    zlib.reserve(raw.size() + raw.size() / 65535 * 5 + 16);
    for (std::size_t offset = 0; offset < raw.size();) {
        const auto n = static_cast<std::uint16_t>(std::min<std::size_t>(65535, raw.size() - offset));
        const bool last = offset + n == raw.size();
        zlib.push_back(last ? 1 : 0);
        zlib.push_back(static_cast<std::uint8_t>(n)); zlib.push_back(static_cast<std::uint8_t>(n >> 8));
        const auto inverse = static_cast<std::uint16_t>(~n);
        zlib.push_back(static_cast<std::uint8_t>(inverse)); zlib.push_back(static_cast<std::uint8_t>(inverse >> 8));
        zlib.insert(zlib.end(), raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(offset + n));
        offset += n;
    }
    binary::append32(zlib, adler32(raw));
    Bytes file(PngSignature.begin(), PngSignature.end()), ihdr;
    binary::append32(ihdr, image.width); binary::append32(ihdr, image.height);
    ihdr.insert(ihdr.end(), {8,6,0,0,0});
    appendChunk(file, "IHDR", ihdr);

    for (std::size_t offset = 0; offset < zlib.size(); offset += 1024 * 1024) {
        const auto n = std::min<std::size_t>(1024 * 1024, zlib.size() - offset);
        appendChunk(file, "IDAT", Bytes(zlib.begin() + static_cast<std::ptrdiff_t>(offset), zlib.begin() + static_cast<std::ptrdiff_t>(offset+n)));
    }
    appendChunk(file, "IEND", {});
    if (file.size() > MaxImageBytes) throw Error("Encoded PNG exceeds the 256 MiB file limit");
    return file;
}
void ImageHandler::savePng(const Image& image, const std::filesystem::path& path, bool overwrite) {
    writeFile(path, encodePng(image), overwrite);
}
double ImageHandler::psnr(const Image& first, const Image& second) {
    first.validate(); second.validate();
    if (first.width != second.width || first.height != second.height) throw Error("PSNR requires equal image dimensions");
    long double sum = 0;
    for (std::size_t i = 0; i < first.rgba.size(); i += 4)
        for (unsigned c = 0; c < 3; ++c) {
            const int difference = int(first.rgba[i+c]) - int(second.rgba[i+c]);
            sum += difference * difference;
        }
    if (sum == 0) return std::numeric_limits<double>::infinity();
    const auto mse = sum / (std::uint64_t(first.width) * first.height * 3);
    return 10 * std::log10(255.0 * 255.0 / static_cast<double>(mse));
}
}
