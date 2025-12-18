#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include <execution>
#include <algorithm>
#include <stdexcept>
namespace crypto::modes {
    class ECB : public ICipherMode {
    public:
        using ICipherMode::ICipherMode;
        Bytes encrypt(ConstBytesSpan input) override {
            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();

            padding->addPadding(data, bs);
            Bytes result(data.size());
            size_t blockCount = data.size() / bs;


            std::vector<size_t> indices(blockCount);
            std::iota(indices.begin(), indices.end(), 0);

            std::for_each(std::execution::par, indices.begin(), indices.end(),
                [&](size_t i) {
                    size_t offset = i * bs;
                    cipher->encryptBlock(
                        std::span{data.data() + offset, bs},
                        std::span{result.data() + offset, bs}
                    );
                });
            return result;
        }
        Bytes decrypt(ConstBytesSpan input) override {
             size_t bs = cipher->getBlockSize();
             if (input.size() % bs != 0) throw std::invalid_argument("Invalid data size for decryption");
             Bytes result(input.size());
             size_t blockCount = input.size() / bs;

             std::vector<size_t> indices(blockCount);
             std::iota(indices.begin(), indices.end(), 0);
             std::for_each(std::execution::par, indices.begin(), indices.end(),
                [&](size_t i) {
                    size_t offset = i * bs;
                    cipher->decryptBlock(
                        input.subspan(offset, bs),
                        std::span{result.data() + offset, bs}
                    );
                });

             size_t validSize = padding->removePadding(result, bs);
             result.resize(validSize);
             return result;
        }
    };
}