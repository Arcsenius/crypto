#pragma once
#include "crypto/symmetric/DES.hpp"
#include <memory>
namespace crypto::symmetric {
    class TripleDES : public IBlockCipher {
        DES des1, des2, des3;
    public:

        explicit TripleDES(ConstBytesSpan key)
            : des1(key.subspan(0, 8)),
              des2(key.subspan(8, 8)),
              des3(key.subspan(16, 8))
        {
            if (key.size() != 24) throw std::invalid_argument("3DES key must be 24 bytes");
        }
        size_t getBlockSize() const override { return 8; }
        size_t getKeySize() const override { return 24; }
        void encryptBlock(ConstBytesSpan src, BytesSpan dst) override {
            std::array<Byte, 8> temp1, temp2;
            des1.encryptBlock(src, temp1);
            des2.decryptBlock(temp1, temp2);
            des3.encryptBlock(temp2, dst);
        }
        void decryptBlock(ConstBytesSpan src, BytesSpan dst) override {
            std::array<Byte, 8> temp1, temp2;
            des3.decryptBlock(src, temp1);
            des2.encryptBlock(temp1, temp2);
            des1.decryptBlock(temp2, dst);
        }
    };
}