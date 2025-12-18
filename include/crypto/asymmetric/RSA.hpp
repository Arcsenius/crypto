#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"
namespace crypto::asymmetric {
    class RSA : public IAsymmetricCipher {
    public:

        BigInt encrypt(const BigInt& plaintext, const PublicKey& pubKey) override;

        BigInt decrypt(const BigInt& ciphertext, const PrivateKey& privKey) override;
    };
}