#pragma once
#include "crypto/symmetric/DES.hpp"
#include "crypto/utils/BitUtils.hpp"
#include <vector>
#include <memory>
namespace crypto::symmetric {
    class DEAL : public IBlockCipher {
        std::vector<std::unique_ptr<DES>> roundDes;
    public:
        explicit DEAL(ConstBytesSpan key);
        size_t getBlockSize() const override { return 16; }
        size_t getKeySize() const override { return 16; }
        void encryptBlock(ConstBytesSpan src, BytesSpan dst) override;
        void decryptBlock(ConstBytesSpan src, BytesSpan dst) override;
    };
}