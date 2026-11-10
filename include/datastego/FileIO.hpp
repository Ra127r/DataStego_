#pragma once

#include "datastego/Types.hpp"
#include <filesystem>

namespace datastego {
Bytes readFile(const std::filesystem::path& path, std::size_t maximum = MaxFileBytes);
void writeFile(const std::filesystem::path& path, const Bytes& bytes, bool overwrite = false);
bool sameFile(const std::filesystem::path& first, const std::filesystem::path& second);
}
