#pragma once
#include "crypto/common/types.hpp"
#include <array>
#include <algorithm>
namespace crypto::utils {
    class BitUtils {
    public:
        template<size_t N>
        static uint64_t permute(uint64_t input, const std::array<uint8_t, N>& table) {
            uint64_t output = 0;
            for (size_t i = 0; i < N; ++i) {
                if ((input >> (64 - table[i])) & 1) {
                    output |= (1ULL << (N - 1 - i));
                }
            }
            return output;
        }
        static uint32_t rol28(uint32_t value, int shifts) {
            return ((value << shifts) | (value >> (28 - shifts))) & 0x0FFFFFFF;
        }
        static uint64_t bytesToUInt64(ConstBytesSpan bytes) {
            uint64_t res = 0;
            for (size_t i = 0; i < 8; ++i) {
                res = (res << 8) | static_cast<uint8_t>(bytes[i]);
            }
            return res;
        }
        static void uint64ToBytes(uint64_t val, BytesSpan out) {
            for (int i = 7; i >= 0; --i) {
                out[7 - i] = static_cast<Byte>(val & 0xFF);
                val >>= 8;
            }
        }
    };
}