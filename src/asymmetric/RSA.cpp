#include "crypto/asymmetric/RSA.hpp"
#include "crypto/math/MathUtils.hpp"

namespace crypto::asymmetric {

    BigInt RSA::encrypt(const BigInt& plaintext, const PublicKey& pubKey) {
        if (plaintext >= pubKey.n) {
            throw std::invalid_argument("RSA: Plaintext too large for modulus n");
        }
        return math::MathUtils::modPow(plaintext, pubKey.e, pubKey.n);
    }

    BigInt RSA::decrypt(const BigInt& ciphertext, const PrivateKey& privKey) {
        if (ciphertext >= privKey.n) {
            throw std::invalid_argument("RSA: Ciphertext too large for modulus n");
        }
        return math::MathUtils::modPow(ciphertext, privKey.d, privKey.n);
    }
}