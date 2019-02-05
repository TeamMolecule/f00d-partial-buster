#include "aes.h"

#ifdef OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#else
#include "aesni128.h"
#endif

namespace
{
    enum CurrentMode
    {
        MODE_UNASSIGNED,
        MODE_DECRYPT,
        MODE_ENCRYPT
    };
}

class AESImpl
{
public:
    AESImpl()
#ifdef OPENSSL
        : ctx(EVP_CIPHER_CTX_new())
#endif
    {
    }

#ifdef OPENSSL
    EVP_CIPHER_CTX *ctx = nullptr;
#else
    __m128i ctx[20];
#endif
    CurrentMode mode = MODE_UNASSIGNED;
    const Key *key = nullptr;
};

AES::AES()
    : m_impl(new AESImpl)
{
}

void AES::setKey(const Key *key)
{
    m_impl->key = key;
    m_impl->mode = MODE_UNASSIGNED;
}

void AES::decrypt(std::vector<std::uint8_t>& data)
{
    decrypt(data, data);
}

void AES::decrypt(std::vector<std::uint8_t>& dst, const std::vector<std::uint8_t>& src)
{
    decrypt(dst.data(), src.data(), src.size());
}

void AES::decrypt(uint8_t *dst, const std::vector<uint8_t> &src)
{
    decrypt(dst, src.data(), src.size());
}

void AES::decrypt(std::uint8_t *dst, const std::uint8_t *src, std::size_t size)
{
#ifdef OPENSSL
    if (m_impl->mode != MODE_DECRYPT)
    {
        EVP_DecryptInit_ex(m_impl->ctx, EVP_aes_128_ecb(), NULL, m_impl->key->data.bytes, NULL);
        EVP_CIPHER_CTX_set_padding(m_impl->ctx, 0);
        m_impl->mode = MODE_DECRYPT;
    }

    // TODO: check casts
    int outLength1 = static_cast<int>(0x10);
    if (1 != EVP_DecryptUpdate(m_impl->ctx, dst, &outLength1, src, static_cast<int>(size)))
    {
        // TODO: error handling
    }

    // TODO: check casts
    int outLength2 = static_cast<int>(0x10) - outLength1;
    if (1 != EVP_DecryptFinal_ex(m_impl->ctx, dst+outLength1, &outLength2))
    {
        // TODO: error handling
    }
#else
    if (m_impl->mode != MODE_DECRYPT)
    {
        aesni128::schedule_dec(m_impl->ctx, m_impl->key->data.bytes);
        m_impl->mode = MODE_DECRYPT;
    }

    for (auto i = 0u; i < size; i += 0x10)
    {
        aesni128::dec(m_impl->ctx, dst + i, src + i);
    }
#endif
}

void AES::encrypt(std::vector<std::uint8_t>& data)
{
    encrypt(data, data);
}

void AES::encrypt(std::vector<std::uint8_t>& dst, const std::vector<std::uint8_t>& src)
{
    encrypt(dst.data(), src.data(), src.size());
}

void AES::encrypt(uint8_t *dst, const std::vector<uint8_t> &src)
{
    encrypt(dst, src.data(), src.size());
}

void AES::encrypt(std::uint8_t *dst, const std::uint8_t *src, std::size_t size)
{
#ifdef OPENSSL
    if (m_impl->mode != MODE_ENCRYPT)
    {
        EVP_EncryptInit_ex(m_impl->ctx, EVP_aes_128_ecb(), NULL, m_impl->key->data.bytes, NULL);
        EVP_CIPHER_CTX_set_padding(m_impl->ctx, 0);
        m_impl->mode = MODE_ENCRYPT;
    }

    // TODO: check casts
    int outLength1 = static_cast<int>(0x10);
    if (1 != EVP_EncryptUpdate(m_impl->ctx, dst, &outLength1, src, static_cast<int>(size)))
    {
        // TODO: error handling
    }

    // TODO: check casts
    int outLength2 = static_cast<int>(0x10) - outLength1;
    if (1 != EVP_EncryptFinal_ex(m_impl->ctx, dst+outLength1, &outLength2))
    {
        // TODO: error handling
    }
#else
    if (m_impl->mode != MODE_ENCRYPT)
    {
        aesni128::schedule_enc(m_impl->ctx, m_impl->key->data.bytes);
        m_impl->mode = MODE_ENCRYPT;
    }

    for (auto i = 0u; i < size; i += 0x10)
    {
        aesni128::enc(m_impl->ctx, dst + i, src + i);
    }
#endif
}
