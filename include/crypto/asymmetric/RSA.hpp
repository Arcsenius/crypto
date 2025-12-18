#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"

namespace crypto::asymmetric {
    class RSA : public IAsymmetricCipher {
    public:
        // C = M^e mod n
        BigInt encrypt(const BigInt& plaintext, const PublicKey& pubKey) override;

        // M = C^d mod n
        BigInt decrypt(const BigInt& ciphertext, const PrivateKey& privKey) override;
    };
}