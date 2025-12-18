#pragma once
#include "crypto/common/BigInt.hpp"
#include <boost/multiprecision/miller_rabin.hpp>
#include <random>

namespace crypto::math {

    class MathUtils {
    public:
        // a^b mod m
        static BigInt modPow(BigInt base, BigInt exp, const BigInt& mod) {
            return boost::multiprecision::powm(base, exp, mod);
        }

        // Обратный элемент: a * x = 1 (mod m)
        static BigInt modInverse(BigInt a, BigInt m) {
            // Boost integer module имеет gcd, но для inverse иногда нужно extended_euclidean
            // Однако, boost::multiprecision обычно считает inverse через powm(a, m-2, m) для простых m,
            // но для RSA m не простое. Нужен Extended Euclidean.
            
            BigInt m0 = m, t, q;
            BigInt x0 = 0, x1 = 1;

            if (m == 1) return 0;

            // Алгоритм Евклида расширенный
            while (a > 1) {
                if (m == 0) throw std::runtime_error("MathUtils: Inverse doesn't exist (gcd != 1)");
                
                q = a / m;
                t = m;
                m = a % m; a = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0) x1 += m0;
            return x1;
        }

        // НОД
        static BigInt gcd(const BigInt& a, const BigInt& b) {
            return boost::multiprecision::gcd(a, b);
        }

        // Проверка на простоту (Miller-Rabin)
        // iterations: 25 достаточно для высокой надежности
        static bool isPrime(const BigInt& n, unsigned iterations = 25) {
            return boost::multiprecision::miller_rabin_test(n, iterations);
        }

        // Генерация случайного числа заданной битности
        static BigInt randomBigInt(size_t bits) {
            boost::random::independent_bits_engine<
                boost::random::mt19937, 
                256, // chunk size
                boost::multiprecision::cpp_int
            > gen;
            
            // Получаем рандом, обрезаем по битам
            // Для простоты используем встроенный random Boost MP
            // Важно: нужно инициализировать сид
             static boost::random::mt19937 rng(std::random_device{}());
             boost::random::uniform_int_distribution<BigInt> dist(
                 (BigInt(1) << (bits - 1)), 
                 (BigInt(1) << bits) - 1
             );
             return dist(rng);
        }
        
        // Генерация простого числа
        static BigInt generatePrime(size_t bits) {
            while (true) {
                BigInt candidate = randomBigInt(bits);
                // Делаем нечетным
                if (candidate % 2 == 0) candidate += 1;
                
                if (isPrime(candidate)) return candidate;
            }
        }
    };
}