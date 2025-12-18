#pragma once
#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/math/MathUtils.hpp"
namespace crypto::asymmetric {
    class WeakKeyGenerator {
    public:

        static RSAKeyPair generateWeak(size_t keySizeBits = 1024) {
            using math::MathUtils;
            while (true) {
                BigInt p = MathUtils::generatePrime(keySizeBits / 2);
                BigInt q = MathUtils::generatePrime(keySizeBits / 2);
                if (p == q) continue;
                if (p < q) std::swap(p, q);
                BigInt n = p * q;
                BigInt phi = (p - 1) * (q - 1);




                BigInt d = MathUtils::generatePrime(keySizeBits / 5);

                if (MathUtils::gcd(d, phi) != 1) continue;

                BigInt e = MathUtils::modInverse(d, phi);
                return RSAKeyPair{ {e, n}, {d, n} };
            }
        }
    };
}