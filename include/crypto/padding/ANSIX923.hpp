#pragma once
#include "crypto/interfaces/IPadding.hpp"
namespace crypto::padding {
    class ANSIX923 : public IPadding {
    public:
        void addPadding(Bytes& data, size_t blockSize) override {
            size_t paddingSize = blockSize - (data.size() % blockSize);

            for (size_t i = 0; i < paddingSize - 1; ++i) {
                data.push_back(Byte{0});
            }

            data.push_back(static_cast<Byte>(paddingSize));
        }
        size_t removePadding(ConstBytesSpan data, size_t blockSize) override {
            if (data.empty()) throw std::runtime_error("Empty data");
            size_t paddingSize = static_cast<size_t>(data.back());
            if (paddingSize == 0 || paddingSize > blockSize || paddingSize > data.size()) {
                throw std::runtime_error("Invalid ANSI X9.23 padding length");
            }


            size_t paddingStart = data.size() - paddingSize;
            for (size_t i = 0; i < paddingSize - 1; ++i) {
                if (data[paddingStart + i] != Byte{0})
                    throw std::runtime_error("Invalid ANSI X9.23 padding bytes");
            }
            return data.size() - paddingSize;
        }
    };
}