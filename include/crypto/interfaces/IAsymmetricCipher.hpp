#pragma once
#include "crypto/common/BigInt.hpp"
#include <vector>
namespace crypto {

    struct PublicKey {
        BigInt e;
        BigInt n;
    };
    struct PrivateKey {
        BigInt d;
        BigInt n;
    };
    class IAsymmetricCipher {
    public:
        virtual ~IAsymmetricCipher() = default;

        virtual BigInt encrypt(const BigInt& plaintext, const PublicKey& pubKey) = 0;
        virtual BigInt decrypt(const BigInt& ciphertext, const PrivateKey& privKey) = 0;

    };
}