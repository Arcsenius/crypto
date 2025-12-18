#pragma once
#include "crypto/common/BigInt.hpp"
#include <vector>

namespace crypto {
    // Структуры ключей
    struct PublicKey {
        BigInt e; // Экспонента
        BigInt n; // Модуль
    };

    struct PrivateKey {
        BigInt d; // Секретная экспонента
        BigInt n; // Модуль
    };

    class IAsymmetricCipher {
    public:
        virtual ~IAsymmetricCipher() = default;

        // Шифрование/Дешифрование сырых чисел (Raw RSA)
        virtual BigInt encrypt(const BigInt& plaintext, const PublicKey& pubKey) = 0;
        virtual BigInt decrypt(const BigInt& ciphertext, const PrivateKey& privKey) = 0;

        // В будущем сюда добавим методы для Bytes и паддинга
    };
}