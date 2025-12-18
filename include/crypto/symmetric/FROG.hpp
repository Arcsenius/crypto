#pragma once
#include "crypto/interfaces/IBlockCipher.hpp"
#include <vector>
#include <array>
namespace crypto::symmetric {
    class FROG : public IBlockCipher {
    public:
        explicit FROG(ConstBytesSpan key);
        size_t getBlockSize() const override { return 16; }
        size_t getKeySize() const override { return 16; }
        void encryptBlock(ConstBytesSpan src, BytesSpan dst) override;
        void decryptBlock(ConstBytesSpan src, BytesSpan dst) override;
    private:
        static constexpr size_t BLOCK_SIZE = 16;
        static constexpr size_t NUM_ROUNDS = 8;
        static constexpr size_t INTERNAL_KEY_SIZE = 2304;
        struct RoundKey {
            std::array<uint8_t, 16>  xorBu;
            std::array<uint8_t, 256> subst;
            std::array<uint8_t, 16>  bombPerm;
        };
        std::vector<RoundKey> encryptKeys;
        std::vector<RoundKey> decryptKeys;
        void makeInternalKey(ConstBytesSpan userKey);

        void invertKeys();
    };
}