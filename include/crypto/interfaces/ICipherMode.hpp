#pragma once
#include "crypto/interfaces/IBlockCipher.hpp"
#include "crypto/interfaces/IPadding.hpp"
#include <memory>
namespace crypto {
    class ICipherMode {
    protected:
        std::unique_ptr<IBlockCipher> cipher;
        std::unique_ptr<IPadding> padding;
    public:
        ICipherMode(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p)
            : cipher(std::move(c)), padding(std::move(p)) {}
        virtual ~ICipherMode() = default;
        virtual Bytes encrypt(ConstBytesSpan data) = 0;
        virtual Bytes decrypt(ConstBytesSpan data) = 0;
    };
}