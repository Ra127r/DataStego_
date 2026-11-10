#include "datastego/StegoEngine.hpp"

namespace datastego {
void StegoEngine::embed(Image& image, const Bytes& payload) {
    image.validate();
    if (payload.size() > image.capacityBytes()) throw Error("Image is too small for this payload");
    std::size_t channel = 0;
    for (auto byte : payload) {
        for (int bit = 7; bit >= 0; --bit, ++channel) {
            const auto index = (channel / 3) * 4 + channel % 3;
            image.rgba[index] = static_cast<std::uint8_t>((image.rgba[index] & 0xfe) | ((byte >> bit) & 1));
        }
    }
}
Bytes StegoEngine::extract(const Image& image, std::size_t count) {
    image.validate();
    if (count > image.capacityBytes()) throw Error("Payload length exceeds image capacity");
    Bytes out(count, 0);
    std::size_t channel = 0;
    for (auto& byte : out) {
        for (unsigned bit = 0; bit < 8; ++bit, ++channel) {
            const auto index = (channel / 3) * 4 + channel % 3;
            byte = static_cast<std::uint8_t>((byte << 1) | (image.rgba[index] & 1));
        }
    }
    return out;
}
}
