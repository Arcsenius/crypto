#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
namespace crypto::modes {
    class OFB : public ICipherMode {
        Bytes iv;
    public:
        OFB(std::unique_ptr<IBlockCipher> c, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), nullptr), iv(iv_.begin(), iv_.end()) {}

        Bytes process(ConstBytesSpan input) {
            Bytes result(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            Bytes currentIV = iv;
            size_t blocks = (input.size() + bs - 1) / bs;

            for (size_t i = 0; i < blocks; ++i) {
                Bytes keystream(bs);
                cipher->encryptBlock(currentIV, keystream);
                currentIV = keystream;
                size_t offset = i * bs;
                size_t len = std::min(bs, input.size() - offset);
                for(size_t j=0; j < len; ++j) {
                    result[offset + j] ^= keystream[j];
                }
            }
            return result;
        }
        Bytes encrypt(ConstBytesSpan input) override { return process(input); }
        Bytes decrypt(ConstBytesSpan input) override { return process(input); }
    };
}