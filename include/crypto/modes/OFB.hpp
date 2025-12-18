#pragma once
#include "crypto/interfaces/ICipherMode.hpp"

namespace crypto::modes {
    class OFB : public ICipherMode {
        Bytes iv;
    public:
        OFB(std::unique_ptr<IBlockCipher> c, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), nullptr), iv(iv_.begin(), iv_.end()) {}

        // OFB симметричен: Encrypt == Decrypt (XOR с одной и той же гаммой)
        Bytes process(ConstBytesSpan input) {
            Bytes result(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            Bytes currentIV = iv;

            size_t blocks = (input.size() + bs - 1) / bs;

            // В OFB нельзя параллелить генерацию IV, так как IV_i зависит от IV_{i-1}
            for (size_t i = 0; i < blocks; ++i) {
                Bytes keystream(bs);
                cipher->encryptBlock(currentIV, keystream);
                currentIV = keystream; // Update IV for next round

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