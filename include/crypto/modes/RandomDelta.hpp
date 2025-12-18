#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include <random>
#include <cstring>
namespace crypto::modes {
    class RandomDelta : public ICipherMode {
        uint32_t seed;
    public:

        RandomDelta(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p, ConstBytesSpan iv)
            : ICipherMode(std::move(c), std::move(p))
        {
            if (iv.size() < 4) throw std::invalid_argument("RandomDelta needs at least 4 bytes IV for seed");
            std::memcpy(&seed, iv.data(), 4);
        }
        Bytes encrypt(ConstBytesSpan input) override {



            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            padding->addPadding(data, bs);

            Bytes result(data.size());
            size_t blocks = data.size() / bs;

            std::mt19937 gen(seed);
            std::uniform_int_distribution<uint16_t> dist(0, 255);
            for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;
                Bytes block(bs);


                for(size_t j=0; j<bs; ++j) {
                    Byte delta = static_cast<Byte>(dist(gen));
                    block[j] = data[offset + j] ^ delta;
                }


                cipher->encryptBlock(block, std::span{result.data() + offset, bs});
            }
            return result;
        }
        Bytes decrypt(ConstBytesSpan input) override {
             size_t bs = cipher->getBlockSize();
             Bytes result(input.size());
             size_t blocks = input.size() / bs;




             std::mt19937 gen(seed);
             std::uniform_int_distribution<uint16_t> dist(0, 255);
             for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;
                Bytes decryptedBlock(bs);

                cipher->decryptBlock(input.subspan(offset, bs), decryptedBlock);


                for(size_t j=0; j<bs; ++j) {
                    Byte delta = static_cast<Byte>(dist(gen));
                    result[offset + j] = decryptedBlock[j] ^ delta;
                }
             }
             size_t valid = padding->removePadding(result, bs);
             result.resize(valid);
             return result;
        }
    };
}