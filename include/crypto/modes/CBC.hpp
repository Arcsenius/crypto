#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include <vector>
namespace crypto::modes {
    class CBC : public ICipherMode {
        Bytes iv;
    public:
        CBC(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), std::move(p)), iv(iv_.begin(), iv_.end())
        {
            if (iv.size() != cipher->getBlockSize()) throw std::invalid_argument("Invalid IV size");
        }
        Bytes encrypt(ConstBytesSpan input) override {
            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            padding->addPadding(data, bs);
            Bytes result(data.size());
            size_t blockCount = data.size() / bs;


            Bytes prevBlock = iv;

            for(size_t i = 0; i < blockCount; ++i) {
                size_t offset = i * bs;


                Bytes block(bs);
                for(size_t j = 0; j < bs; ++j) {
                    block[j] = data[offset + j] ^ prevBlock[j];
                }


                cipher->encryptBlock(block, std::span{result.data() + offset, bs});


                std::copy(result.begin() + offset, result.begin() + offset + bs, prevBlock.begin());
            }
            return result;
        }
        Bytes decrypt(ConstBytesSpan input) override {


            size_t bs = cipher->getBlockSize();
            if (input.size() % bs != 0) throw std::invalid_argument("Bad size");
            Bytes result(input.size());
            size_t blockCount = input.size() / bs;
            std::vector<size_t> indices(blockCount);
            std::iota(indices.begin(), indices.end(), 0);

            std::for_each(std::execution::par, indices.begin(), indices.end(), [&](size_t i) {
                size_t offset = i * bs;

                cipher->decryptBlock(input.subspan(offset, bs), std::span{result.data() + offset, bs});


                ConstBytesSpan xorBlock = (i == 0) ? std::span{iv} : input.subspan(offset - bs, bs);
                for(size_t j=0; j<bs; ++j) {
                    result[offset + j] ^= xorBlock[j];
                }
            });
            size_t validSize = padding->removePadding(result, bs);
            result.resize(validSize);
            return result;
        }
    };
}