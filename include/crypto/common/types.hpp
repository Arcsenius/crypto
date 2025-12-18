#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>
#include <span>
namespace crypto {
    using Byte = std::byte;
    using Bytes = std::vector<Byte>;
    using ConstBytesSpan = std::span<const Byte>;
    using BytesSpan = std::span<Byte>;
    enum class CipherType { DES, TripleDES, DEAL };
    enum class ModeType { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };
    enum class PaddingType { Zeros, ANSI_X9_23, PKCS7, ISO_10126 };
}