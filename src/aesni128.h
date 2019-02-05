#pragma once

#include <cstdint>
#include <wmmintrin.h>

namespace aesni128
{
    namespace 
    {
        static inline __m128i round_expansion(__m128i key, int rcon)
        {
            auto rconxor = _mm_aeskeygenassist_si128(key, rcon);
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            return _mm_xor_si128(key, _mm_shuffle_epi32(rconxor, _MM_SHUFFLE(3,3,3,3)));
        }
    }

    static inline void schedule_enc(__m128i *schedule, const std::uint8_t *key)
    {
        schedule[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
        schedule[1] = round_expansion(schedule[0], 0x01);
        schedule[2] = round_expansion(schedule[1], 0x02);
        schedule[3] = round_expansion(schedule[2], 0x04);
        schedule[4] = round_expansion(schedule[3], 0x08);
        schedule[5] = round_expansion(schedule[4], 0x10);
        schedule[6] = round_expansion(schedule[5], 0x20);
        schedule[7] = round_expansion(schedule[6], 0x40);
        schedule[8] = round_expansion(schedule[7], 0x80);
        schedule[9] = round_expansion(schedule[8], 0x1B);
        schedule[10] = round_expansion(schedule[9], 0x36);
    }

    static inline void schedule_dec(__m128i *schedule, const std::uint8_t *key)
    {
        schedule_enc(schedule, key);

        schedule[11] = _mm_aesimc_si128(schedule[9]);
        schedule[12] = _mm_aesimc_si128(schedule[8]);
        schedule[13] = _mm_aesimc_si128(schedule[7]);
        schedule[14] = _mm_aesimc_si128(schedule[6]);
        schedule[15] = _mm_aesimc_si128(schedule[5]);
        schedule[16] = _mm_aesimc_si128(schedule[4]);
        schedule[17] = _mm_aesimc_si128(schedule[3]);
        schedule[18] = _mm_aesimc_si128(schedule[2]);
        schedule[19] = _mm_aesimc_si128(schedule[1]);
    }

    static inline void enc(const __m128i *schedule, std::uint8_t *enc, const std::uint8_t *dec)
    {
        auto blk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(dec));

        blk = _mm_xor_si128(blk, schedule[0]);
        blk = _mm_aesenc_si128(blk, schedule[1]);
        blk = _mm_aesenc_si128(blk, schedule[2]);
        blk = _mm_aesenc_si128(blk, schedule[3]);
        blk = _mm_aesenc_si128(blk, schedule[4]);
        blk = _mm_aesenc_si128(blk, schedule[5]);
        blk = _mm_aesenc_si128(blk, schedule[6]);
        blk = _mm_aesenc_si128(blk, schedule[7]);
        blk = _mm_aesenc_si128(blk, schedule[8]);
        blk = _mm_aesenc_si128(blk, schedule[9]);
        blk = _mm_aesenclast_si128(blk, schedule[10]);

        _mm_storeu_si128(reinterpret_cast<__m128i *>(enc), blk);
    }

    static inline void dec(const __m128i *schedule, std::uint8_t *dec, const std::uint8_t *enc)
    {
        auto blk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));

        blk = _mm_xor_si128(blk, schedule[10]);
        blk = _mm_aesdec_si128(blk, schedule[11]);
        blk = _mm_aesdec_si128(blk, schedule[12]);
        blk = _mm_aesdec_si128(blk, schedule[13]);
        blk = _mm_aesdec_si128(blk, schedule[14]);
        blk = _mm_aesdec_si128(blk, schedule[15]);
        blk = _mm_aesdec_si128(blk, schedule[16]);
        blk = _mm_aesdec_si128(blk, schedule[17]);
        blk = _mm_aesdec_si128(blk, schedule[18]);
        blk = _mm_aesdec_si128(blk, schedule[19]);
        blk = _mm_aesdeclast_si128(blk, schedule[0]);

        _mm_storeu_si128(reinterpret_cast<__m128i *>(dec), blk);
    }
} // namespace aesni128
