#pragma once
#include "crypto/interfaces/IPadding.hpp"
#include <random>
namespace crypto::padding {
    class ISO10126 : public IPadding {
    public:
        void addPadding(Bytes& data, size_t blockSize) override {
            size_t paddingSize = blockSize - (data.size() % blockSize);

            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (size_t i = 0; i < paddingSize - 1; ++i) {
                data.push_back(static_cast<Byte>(dis(gen)));
            }

            data.push_back(static_cast<Byte>(paddingSize));
        }
        size_t removePadding(ConstBytesSpan data, size_t blockSize) override {
            if (data.empty()) throw std::runtime_error("Empty data");
            size_t paddingSize = static_cast<size_t>(data.back());
            if (paddingSize == 0 || paddingSize > blockSize || paddingSize > data.size()) {
                throw std::runtime_error("Invalid ISO10126 padding");
            }
            return data.size() - paddingSize;
        }
    };
}