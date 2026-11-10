#pragma once

#include "datastego/ImageHandler.hpp"

namespace datastego {
class StegoEngine {
public:

    static void embed(Image& image, const Bytes& payload);
    static Bytes extract(const Image& image, std::size_t count);
};
}
