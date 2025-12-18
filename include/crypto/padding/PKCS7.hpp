#pragma once
#include "crypto/interfaces/IPadding.hpp"
#include <stdexcept>
namespace crypto::padding {
    class PKCS7 : public IPadding {
    public:
        void addPadding(Bytes& data, size_t blockSize) override {
            size_t paddingSize = blockSize - (data.size() % blockSize);
            Byte padByte = static_cast<Byte>(paddingSize);
            data.insert(data.end(), paddingSize, padByte);
        }
        size_t removePadding(ConstBytesSpan data, size_t blockSize) override {
            if (data.empty()) throw std::runtime_error("Empty data");

            Byte lastByte = data.back();
            size_t paddingSize = static_cast<size_t>(lastByte);
            if (paddingSize == 0 || paddingSize > blockSize) {
                throw std::runtime_error("Invalid PKCS7 padding size");
            }

            size_t dataSize = data.size();
            for (size_t i = 0; i < paddingSize; ++i) {
                if (data[dataSize - 1 - i] != lastByte) {
                    throw std::runtime_error("Invalid PKCS7 padding bytes");
                }
            }
            return dataSize - paddingSize;
        }
    };
}