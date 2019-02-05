#include "hex.h"

#include <string>

namespace
{
    void encodeByte(std::uint8_t byte, char str[2])
    {
        const char digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        str[0] = digits[(byte >> 4) & 0xF];
        str[1] = digits[byte & 0xF];
    }
}

namespace hex
{

std::string encode(const std::vector<std::uint8_t>& binary)
{
    std::string str;
    str.reserve(binary.size()*2);

    for (auto byte : binary)
    {
        char bytes[2];
        encodeByte(byte, bytes);
        str.push_back(bytes[0]);
        str.push_back(bytes[1]);
    }

    return str;
}

std::vector<std::uint8_t> decode(const std::string& str)
{
    std::vector<uint8_t> binary;

    for (auto it = str.begin(); it != str.end(); it += 2)
    {
        std::string byte(it, it+2);
        binary.push_back(std::stoul(byte, nullptr, 16) & 0xFF);
    }

    return binary;
}

} // namespace hex
