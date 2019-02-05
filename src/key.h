#pragma once

#include <cstdint>
#include <cstring>

struct Key
{
    Key()
    {
        std::memset(data.bytes, 0, sizeof(data.bytes));
    }

    union
    {
        std::uint8_t bytes[0x10];
        std::uint32_t dwords[4];
    } data;
};
