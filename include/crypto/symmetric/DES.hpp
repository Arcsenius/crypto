#pragma once
#include "crypto/interfaces/IBlockCipher.hpp"
#include <array>
namespace crypto::symmetric {
    class DES : public IBlockCipher {
    public:
        explicit DES(ConstBytesSpan key);
        size_t getBlockSize() const override { return 8; }
        size_t getKeySize() const override { return 8; }
        void encryptBlock(ConstBytesSpan src, BytesSpan dst) override;
        void decryptBlock(ConstBytesSpan src, BytesSpan dst) override;
    private:
        std::array<uint64_t, 16> subKeys;
        void generateSubKeys(uint64_t key64);
    };
}