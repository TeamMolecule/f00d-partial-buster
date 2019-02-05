#pragma once

#include "key.h"

#include <cstdint>
#include <vector>

class AESImpl;

class AES
{
public:
    AES();

    void setKey(const Key *key);

    void decrypt(std::vector<std::uint8_t>& data);
    void decrypt(std::vector<std::uint8_t>& dst, const std::vector<std::uint8_t>& src);
    void decrypt(std::uint8_t *dst, const std::vector<std::uint8_t>& src);
    void decrypt(std::uint8_t *dst, const std::uint8_t *src, std::size_t size);
    void encrypt(std::vector<std::uint8_t>& data);
    void encrypt(std::vector<std::uint8_t>& dst, const std::vector<std::uint8_t>& src);
    void encrypt(std::uint8_t *dst, const std::vector<std::uint8_t>& src);
    void encrypt(std::uint8_t *dst, const std::uint8_t *src, std::size_t size);

private:
    AESImpl *m_impl = nullptr;
};
