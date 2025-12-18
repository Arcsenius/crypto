#pragma once
#include "crypto/interfaces/IPadding.hpp"
namespace crypto::padding {
    class Zeros : public IPadding {
    public:
        void addPadding(Bytes& data, size_t blockSize) override {
            size_t paddingSize = blockSize - (data.size() % blockSize);
            if (paddingSize == blockSize) return;
            if (paddingSize == 0) return;
            data.insert(data.end(), paddingSize, Byte{0});
        }
        size_t removePadding(ConstBytesSpan data, size_t blockSize) override {
            size_t newSize = data.size();
            while (newSize > 0 && data[newSize - 1] == Byte{0}) {
                newSize--;
            }
            return newSize;
        }
    };
}