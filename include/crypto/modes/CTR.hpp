#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include "crypto/utils/BitUtils.hpp"
namespace crypto::modes {
    class CTR : public ICipherMode {
        Bytes iv;
    public:
        CTR(std::unique_ptr<IBlockCipher> c, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), nullptr), iv(iv_.begin(), iv_.end())
        {
             if (iv.size() != cipher->getBlockSize()) throw std::invalid_argument("IV size mismatch");
        }
        Bytes process(ConstBytesSpan input) {
            Bytes result(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            size_t blockCount = (input.size() + bs - 1) / bs;
            std::vector<size_t> indices(blockCount);
            std::iota(indices.begin(), indices.end(), 0);
            std::for_each(std::execution::par, indices.begin(), indices.end(), [&](size_t i) {
                uint64_t counterVal = utils::BitUtils::bytesToUInt64(iv);
                counterVal += i;
                Bytes ctrBlock(bs);
                utils::BitUtils::uint64ToBytes(counterVal, ctrBlock);
                Bytes encryptedCtr(bs);
                cipher->encryptBlock(ctrBlock, encryptedCtr);
                size_t offset = i * bs;
                size_t len = std::min(bs, result.size() - offset);
                for(size_t j=0; j<len; ++j) {
                    result[offset + j] ^= encryptedCtr[j];
                }
            });
            return result;
        }
        Bytes encrypt(ConstBytesSpan input) override { return process(input); }
        Bytes decrypt(ConstBytesSpan input) override { return process(input); }
    };
}