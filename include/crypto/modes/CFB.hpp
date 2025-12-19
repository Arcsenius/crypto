#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
namespace crypto::modes {
    class CFB : public ICipherMode {
        Bytes iv;
    public:



        CFB(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), std::move(p)), iv(iv_.begin(), iv_.end()) {}
        Bytes encrypt(ConstBytesSpan input) override {
            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            if (padding) padding->addPadding(data, bs);
            Bytes result(data.size());
            Bytes feedback = iv;
            for (size_t i = 0; i < data.size(); i += bs) {

                Bytes output(bs);
                cipher->encryptBlock(feedback, output);
                size_t len = std::min(bs, data.size() - i);
                for (size_t j = 0; j < len; ++j) {
                    result[i + j] = data[i + j] ^ output[j];

                    if (j < bs) feedback[j] = result[i + j];
                }
            }
            return result;
        }
        Bytes decrypt(ConstBytesSpan input) override {
            Bytes result(input.size());
            size_t bs = cipher->getBlockSize();
            Bytes feedback = iv;
            for (size_t i = 0; i < input.size(); i += bs) {
                Bytes output(bs);
                cipher->encryptBlock(feedback, output);
                size_t len = std::min(bs, input.size() - i);
                for (size_t j = 0; j < len; ++j) {
                    Byte c = input[i + j];
                    result[i + j] = c ^ output[j];

                    if (j < bs) feedback[j] = c;
                }
            }
            if (padding) {
                size_t valid = padding->removePadding(result, bs);
                result.resize(valid);
            }
            return result;
        }
    };
}