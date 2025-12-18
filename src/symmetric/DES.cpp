#include <crypto/symmetric/DES.hpp>
#include <crypto/utils/BitUtils.hpp>
#include <vector>
#include <stdexcept>
namespace crypto::symmetric {
    using utils::BitUtils;
    static constexpr std::array<uint8_t, 64> IP_TABLE = {
        58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7
    };
    static constexpr std::array<uint8_t, 64> FP_TABLE = {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25
    };
    static constexpr std::array<uint8_t, 48> E_TABLE = {
        32, 1, 2, 3, 4, 5,   4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };
    static constexpr std::array<uint8_t, 32> P_TABLE = {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    };
    static constexpr std::array<uint8_t, 56> PC1 = {  };
    static constexpr std::array<uint8_t, 48> PC2 = {  };
    static constexpr std::array<uint8_t, 16> SHIFTS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    static constexpr uint8_t S_BOX[8][64] = {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
         4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    };
    DES::DES(ConstBytesSpan key) {
        if (key.size() != 8) throw std::invalid_argument("DES Key must be 8 bytes");
        generateSubKeys(BitUtils::bytesToUInt64(key));
    }
    void DES::generateSubKeys(uint64_t key64) {
        uint64_t k56 = BitUtils::permute<56>(key64, PC1);
        uint32_t c = (k56 >> 28) & 0x0FFFFFFF;
        uint32_t d = k56 & 0x0FFFFFFF;
        for (int i = 0; i < 16; ++i) {
            c = BitUtils::rol28(c, SHIFTS[i]);
            d = BitUtils::rol28(d, SHIFTS[i]);
            uint64_t cd = (static_cast<uint64_t>(c) << 28) | d;
            subKeys[i] = BitUtils::permute<48>(cd, PC2);
        }
    }
    uint32_t feistel(uint32_t r, uint64_t k) {
        uint64_t er = BitUtils::permute<48>(r, E_TABLE);
        uint64_t x = er ^ k;
        uint32_t output = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t block = (x >> ((7 - i) * 6)) & 0x3F;
            int row = ((block >> 5) & 1) * 2 + (block & 1);
            int col = (block >> 1) & 0x0F;
            uint32_t s_val = S_BOX[i][row * 16 + col];
            output = (output << 4) | s_val;
        }
        return static_cast<uint32_t>(BitUtils::permute<32>(output, P_TABLE));
    }
    void DES::encryptBlock(ConstBytesSpan src, BytesSpan dst) {
        uint64_t m = BitUtils::bytesToUInt64(src);
        m = BitUtils::permute<64>(m, IP_TABLE);
        uint32_t left = (m >> 32) & 0xFFFFFFFF;
        uint32_t right = m & 0xFFFFFFFF;
        for (int i = 0; i < 16; ++i) {
            uint32_t temp = right;
            right = left ^ feistel(right, subKeys[i]);
            left = temp;
        }
        uint64_t res = (static_cast<uint64_t>(right) << 32) | left;
        res = BitUtils::permute<64>(res, FP_TABLE);
        BitUtils::uint64ToBytes(res, dst);
    }
    void DES::decryptBlock(ConstBytesSpan src, BytesSpan dst) {
        uint64_t m = BitUtils::bytesToUInt64(src);
        m = BitUtils::permute<64>(m, IP_TABLE);
        uint32_t left = (m >> 32) & 0xFFFFFFFF;
        uint32_t right = m & 0xFFFFFFFF;
        for (int i = 15; i >= 0; --i) {
            uint32_t temp = right;
            right = left ^ feistel(right, subKeys[i]);
            left = temp;
        }
        uint64_t res = (static_cast<uint64_t>(right) << 32) | left;
        res = BitUtils::permute<64>(res, FP_TABLE);
        BitUtils::uint64ToBytes(res, dst);
    }
}