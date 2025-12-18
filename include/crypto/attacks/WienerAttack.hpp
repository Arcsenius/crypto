#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"
#include "crypto/asymmetric/RSA.hpp"
#include "crypto/math/MathUtils.hpp"
#include <vector>
#include <iostream>

namespace crypto::attacks {

    class WienerAttack {
    public:
        // Пытается восстановить приватный ключ d по (e, n)
        // Возвращает найденный d или 0, если атака не удалась
        static BigInt recoverPrivateKey(const PublicKey& pubKey) {
            BigInt e = pubKey.e;
            BigInt n = pubKey.n;

            // 1. Генерация коэффициентов цепной дроби e/n
            // Мы не храним все коэффициенты, а генерируем конвергенты на лету
            // Алгоритм Евклида для поиска коэффициентов a_i

            std::vector<BigInt> q_coeffs;
            BigInt r0 = e, r1 = n;

            // Предыдущие значения числителей (k) и знаменателей (d_candidate) конвергентов
            // k_prev = numerator, d_prev = denominator (это и есть наш кандидат на d)
            // p0/q0, p1/q1 ...
            // В нотации Винера это k/d.

            BigInt k_prev = 0, k_curr = 1;      // Числители
            BigInt d_prev = 1, d_curr = 0;      // Знаменатели (кандидаты на приватный ключ)

            // Первая итерация (a0 = 0, т.к. e < n)
            // e/n = 0 + ...
            // Конвергент 0: 0/1 -> k=0, d=1. Это не подходит.

            // Будем итерироваться пока d_curr * d_curr < n (или чуть больше)
            while (r1 != 0) {
                BigInt quotient = r0 / r1;
                BigInt remainder = r0 % r1;

                // Обновляем r
                r0 = r1;
                r1 = remainder;

                // Считаем следующий конвергент (числитель k, знаменатель d)
                // next = quotient * curr + prev
                BigInt k_next = quotient * k_curr + k_prev;
                BigInt d_next = quotient * d_curr + d_prev;

                // Сдвигаем
                k_prev = k_curr; k_curr = k_next;
                d_prev = d_curr; d_curr = d_next;

                // d_curr - это наш кандидат на секретную экспоненту d
                // k_curr - это k

                // Пропускаем тривиальные случаи
                if (d_curr == 0 || k_curr == 0) continue;

                // Проверка кандидата:
                // ed - 1 = k * phi
                // phi = (ed - 1) / k

                BigInt ed_minus_1 = e * d_curr - 1;
                if (ed_minus_1 % k_curr != 0) continue;

                BigInt phi = ed_minus_1 / k_curr;

                // Теперь решаем квадратное уравнение: x^2 - ((n - phi) + 1)x + n = 0
                // Корни этого уравнения - это p и q.
                // Если корни целые, то мы нашли разложение!

                BigInt b = n - phi + 1;
                // Дискриминант D = b^2 - 4n
                BigInt D = b * b - 4 * n;

                if (D >= 0) {
                    BigInt sqrtD = boost::multiprecision::sqrt(D);
                    // Проверка, что корень целый
                    if (sqrtD * sqrtD == D) {
                        // Проверяем корни
                        BigInt p = (b + sqrtD) / 2;
                        BigInt q = (b - sqrtD) / 2;

                        if (p * q == n) {
                            std::cout << "[Wiener] Success! Found d = " << d_curr << "\n";
                            return d_curr;
                        }
                    }
                }
            }

            return 0; // Fail
        }
    };
}