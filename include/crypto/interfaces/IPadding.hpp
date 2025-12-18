#pragma once
#include "crypto/common/types.hpp"
namespace crypto {
    class IPadding {
    public:
        virtual ~IPadding() = default;
        virtual void addPadding(Bytes& data, size_t blockSize) = 0;
        virtual size_t removePadding(ConstBytesSpan data, size_t blockSize) = 0;
    };
}