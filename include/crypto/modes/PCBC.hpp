#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include <vector>
namespace crypto::modes {
    class PCBC : public ICipherMode {
        Bytes iv;
    public:
        PCBC(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), std::move(p)), iv(iv_.begin(), iv_.end())
        {
            if (iv.size() != cipher->getBlockSize()) throw std::invalid_argument("Invalid IV size");
        }
        Bytes encrypt(ConstBytesSpan input) override {
            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            padding->addPadding(data, bs);
            Bytes result(data.size());
            size_t blocks = data.size() / bs;
            Bytes prevP = iv;
            Bytes prevC(bs, Byte{0});





            Bytes state = iv;
            for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;
                Bytes block(bs);

                for(size_t j=0; j<bs; ++j) {
                    block[j] = data[offset + j] ^ state[j];
                }

                cipher->encryptBlock(block, std::span{result.data() + offset, bs});

                for(size_t j=0; j<bs; ++j) {
                    state[j] = data[offset + j] ^ result[offset + j];
                }
            }
            return result;
        }
        Bytes decrypt(ConstBytesSpan input) override {
            size_t bs = cipher->getBlockSize();
            if (input.size() % bs != 0) throw std::invalid_argument("Invalid size");
            Bytes result(input.size());
            size_t blocks = input.size() / bs;
            Bytes state = iv;
            for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;

                Bytes decBlock(bs);
                cipher->decryptBlock(input.subspan(offset, bs), decBlock);

                for(size_t j=0; j<bs; ++j) {
                    result[offset + j] = decBlock[j] ^ state[j];
                }


                for(size_t j=0; j<bs; ++j) {
                    state[j] = result[offset + j] ^ input[offset + j];
                }
            }
            size_t valid = padding->removePadding(result, bs);
            result.resize(valid);
            return result;
        }
    };
}