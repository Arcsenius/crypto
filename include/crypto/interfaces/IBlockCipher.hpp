#pragma once
#include "crypto/common/types.hpp"
#include <vector>
namespace crypto {
    class IBlockCipher {
    public:
        virtual ~IBlockCipher() = default;
        [[nodiscard]] virtual size_t getBlockSize() const = 0;
        [[nodiscard]] virtual size_t getKeySize() const = 0;
        virtual void encryptBlock(ConstBytesSpan src, BytesSpan dst) = 0;
        virtual void decryptBlock(ConstBytesSpan src, BytesSpan dst) = 0;
    };
}