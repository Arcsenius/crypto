#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"

namespace crypto::asymmetric {

    struct RSAKeyPair {
        PublicKey pub;
        PrivateKey priv;
    };

    class RSAKeyGenerator {
    public:
        // keySizeBits - размер модуля n (например, 2048)
        static RSAKeyPair generate(size_t keySizeBits = 2048);
    };
}