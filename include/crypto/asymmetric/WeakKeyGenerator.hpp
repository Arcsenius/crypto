#pragma once
#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/math/MathUtils.hpp"

namespace crypto::asymmetric {

    class WeakKeyGenerator {
    public:
        // Генерирует ключи, уязвимые для атаки Винера (малое d)
        static RSAKeyPair generateWeak(size_t keySizeBits = 1024) {
            using math::MathUtils;

            while (true) {
                BigInt p = MathUtils::generatePrime(keySizeBits / 2);
                BigInt q = MathUtils::generatePrime(keySizeBits / 2);
                if (p == q) continue;
                if (p < q) std::swap(p, q); // p > q

                BigInt n = p * q;
                BigInt phi = (p - 1) * (q - 1);

                // Выбираем МАЛЕНЬКОЕ d
                // d должно быть < 1/3 * n^(1/4)
                // Для 1024 бит n^(1/4) ~ 256 бит.
                // Возьмем d размером около 100 бит.

                BigInt d = MathUtils::generatePrime(keySizeBits / 5);

                // Проверяем gcd(d, phi) == 1
                if (MathUtils::gcd(d, phi) != 1) continue;

                // Вычисляем e = d^(-1) mod phi
                BigInt e = MathUtils::modInverse(d, phi);

                return RSAKeyPair{ {e, n}, {d, n} };
            }
        }
    };
}