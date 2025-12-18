#pragma once
#include "crypto/common/BigInt.hpp"
#include <boost/multiprecision/miller_rabin.hpp>
#include <random>
namespace crypto::math {
    class MathUtils {
    public:
        static BigInt modPow(BigInt base, BigInt exp, const BigInt& mod) {
            return boost::multiprecision::powm(base, exp, mod);
        }
        static BigInt modInverse(BigInt a, BigInt m) {
            BigInt m0 = m, t, q;
            BigInt x0 = 0, x1 = 1;
            if (m == 1) return 0;
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
        static BigInt gcd(const BigInt& a, const BigInt& b) {
            return boost::multiprecision::gcd(a, b);
        }
        static bool isPrime(const BigInt& n, unsigned iterations = 25) {
            return boost::multiprecision::miller_rabin_test(n, iterations);
        }
        static BigInt randomBigInt(size_t bits) {
            boost::random::independent_bits_engine<
                boost::random::mt19937,
                256,
                boost::multiprecision::cpp_int
            > gen;
             static boost::random::mt19937 rng(std::random_device{}());
             boost::random::uniform_int_distribution<BigInt> dist(
                 (BigInt(1) << (bits - 1)),
                 (BigInt(1) << bits) - 1
             );
             return dist(rng);
        }
        static BigInt generatePrime(size_t bits) {
            while (true) {
                BigInt candidate = randomBigInt(bits);
                if (candidate % 2 == 0) candidate += 1;
                if (isPrime(candidate)) return candidate;
            }
        }
    };
}