#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"
namespace crypto::asymmetric {
    struct RSAKeyPair {
        PublicKey pub;
        PrivateKey priv;
    };
    class RSAKeyGenerator {
    public:
        static RSAKeyPair generate(size_t keySizeBits = 2048);
    };
}