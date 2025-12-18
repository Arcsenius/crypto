#pragma once
#include "crypto/interfaces/IAsymmetricCipher.hpp"
#include "crypto/asymmetric/RSA.hpp"
#include "crypto/math/MathUtils.hpp"
#include <vector>
#include <iostream>
namespace crypto::attacks {
    class WienerAttack {
    public:
        static BigInt recoverPrivateKey(const PublicKey& pubKey) {
            BigInt e = pubKey.e;
            BigInt n = pubKey.n;
            std::vector<BigInt> q_coeffs;
            BigInt r0 = e, r1 = n;
            BigInt k_prev = 0, k_curr = 1;
            BigInt d_prev = 1, d_curr = 0;
            while (r1 != 0) {
                BigInt quotient = r0 / r1;
                BigInt remainder = r0 % r1;
                r0 = r1;
                r1 = remainder;
                BigInt k_next = quotient * k_curr + k_prev;
                BigInt d_next = quotient * d_curr + d_prev;
                k_prev = k_curr; k_curr = k_next;
                d_prev = d_curr; d_curr = d_next;
                if (d_curr == 0 || k_curr == 0) continue;
                BigInt ed_minus_1 = e * d_curr - 1;
                if (ed_minus_1 % k_curr != 0) continue;
                BigInt phi = ed_minus_1 / k_curr;
                BigInt b = n - phi + 1;
                BigInt D = b * b - 4 * n;
                if (D >= 0) {
                    BigInt sqrtD = boost::multiprecision::sqrt(D);
                    if (sqrtD * sqrtD == D) {
                        BigInt p = (b + sqrtD) / 2;
                        BigInt q = (b - sqrtD) / 2;
                        if (p * q == n) {
                            std::cout << "[Wiener] Success! Found d = " << d_curr << "\n";
                            return d_curr;
                        }
                    }
                }
            }
            return 0;
        }
    };
}