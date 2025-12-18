#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/math/MathUtils.hpp"
#include <iostream>

namespace crypto::asymmetric {

    using math::MathUtils;

    RSAKeyPair RSAKeyGenerator::generate(size_t keySizeBits) {
        // p и q должны быть примерно половина от n
        size_t primeBits = keySizeBits / 2;

        BigInt p, q, n, phi, e, d;

        // Стандартное значение e (эффективное шифрование)
        e = 65537;

        while (true) {
            // 1. Генерируем простые числа
            p = MathUtils::generatePrime(primeBits);
            q = MathUtils::generatePrime(primeBits);

            // p и q не должны быть равны
            if (p == q) continue;

            n = p * q;

            // Проверка длины модуля (иногда произведение меньше ожидаемого на 1 бит)
            // if (msb(n) != keySizeBits) continue; // (можно добавить позже)

            phi = (p - 1) * (q - 1);

            // 2. Проверяем GCD(e, phi) == 1
            if (MathUtils::gcd(e, phi) != 1) {
                // Если 65537 не подходит (крайне редко), берем другое e или новые p,q
                // Проще сгенерировать новые p,q
                continue;
            }

            // 3. Вычисляем d
            d = MathUtils::modInverse(e, phi);

            // 4. ЗАЩИТА ОТ АТАКИ ВИНЕРА
            // d должно быть достаточно большим.
            // Граница Винера: d < (1/3) * n^(1/4)
            // У нас n ~ 2^keySizeBits. Значит n^(1/4) ~ 2^(keySizeBits/4).
            // Для 2048 бит: граница ~ 2^512.
            // При e=65537, d обычно ~ phi ~ 2^2048, так что это безопасно.
            // Но добавим явную проверку.

            BigInt wienerBound = boost::multiprecision::pow(n, 1);
            // К сожалению, корень 4-й степени из BigInt в boost извлекать неудобно напрямую (нужен float conversion).
            // Сделаем грубую проверку по битам.
            // d должно быть больше чем 1/3 * n^(1/4).
            // Если d имеет размер более чем keySizeBits / 4, то все ок.

            // Метод msb() возвращает индекс старшего бита
            if (boost::multiprecision::msb(d) < (keySizeBits / 4)) {
                std::cerr << "[WARNING] Generated weak d (Wiener Attack risk). Regenerating...\n";
                continue;
            }

            break; // Все проверки пройдены
        }

        return RSAKeyPair{ {e, n}, {d, n} };
    }
}