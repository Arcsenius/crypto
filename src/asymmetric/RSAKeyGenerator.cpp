#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/math/MathUtils.hpp"
#include <iostream>
namespace crypto::asymmetric {
    using math::MathUtils;
    RSAKeyPair RSAKeyGenerator::generate(size_t keySizeBits) {
        size_t primeBits = keySizeBits / 2;
        BigInt p, q, n, phi, e, d;
        e = 65537;
        while (true) {
            p = MathUtils::generatePrime(primeBits);
            q = MathUtils::generatePrime(primeBits);
            if (p == q) continue;
            n = p * q;
            phi = (p - 1) * (q - 1);
            if (MathUtils::gcd(e, phi) != 1) {
                continue;
            }
            d = MathUtils::modInverse(e, phi);
            BigInt wienerBound = boost::multiprecision::pow(n, 1);
            if (boost::multiprecision::msb(d) < (keySizeBits / 4)) {
                std::cerr << "[WARNING] Generated weak d (Wiener Attack risk). Regenerating...\n";
                continue;
            }
            break;
        }
        return RSAKeyPair{ {e, n}, {d, n} };
    }
}