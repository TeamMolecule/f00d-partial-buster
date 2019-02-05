#pragma once

#include <string>
#include <vector>

namespace hex
{
    std::string encode(const std::vector<std::uint8_t>& binary);
    std::vector<std::uint8_t> decode(const std::string& str);
}
