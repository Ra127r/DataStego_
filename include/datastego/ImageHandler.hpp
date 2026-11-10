#pragma once

#include "datastego/Types.hpp"
#include <filesystem>

namespace datastego {
struct Image {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    Bytes rgba;
    void validate() const;
    std::size_t capacityBytes() const;
};

class ImageHandler {
public:
    static Image load(const std::filesystem::path& path);
    static Image decode(const Bytes& file);
    static Bytes encodePng(const Image& image);
    static void savePng(const Image& image, const std::filesystem::path& path, bool overwrite = false);
    static double psnr(const Image& first, const Image& second);
};
}
