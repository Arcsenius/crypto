#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <random>

// Подключаем модули RSA
#include "crypto/common/BigInt.hpp"
#include "crypto/math/MathUtils.hpp"
#include "crypto/asymmetric/RSA.hpp"
#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/asymmetric/WeakKeyGenerator.hpp"
#include "crypto/padding/RSA_PKCS1.hpp"
#include "crypto/attacks/WienerAttack.hpp"

using namespace crypto;

// === 1. Тест Математики ===
TEST(RSA_Math, ModInverseAndPow) {
    // Проверка a^b mod n
    BigInt base = 4;
    BigInt exp = 13;
    BigInt mod = 497;
    // 4^13 mod 497 = 445
    EXPECT_EQ(math::MathUtils::modPow(base, exp, mod), 445);

    // Проверка Inverse: a*x = 1 (mod m)
    // 3 * x = 1 (mod 11) -> x = 4 (3*4 = 12 = 1 mod 11)
    EXPECT_EQ(math::MathUtils::modInverse(3, 11), 4);
}

// === 2. Тест Ядра RSA (Raw) ===
TEST(RSA_Core, EncryptDecryptRaw) {
    auto keys = asymmetric::RSAKeyGenerator::generate(512); // 512 бит для скорости
    asymmetric::RSA rsa;

    BigInt original = 123456789;
    BigInt encrypted = rsa.encrypt(original, keys.pub);
    BigInt decrypted = rsa.decrypt(encrypted, keys.priv);

    EXPECT_EQ(original, decrypted);
    EXPECT_NE(original, encrypted);
}

// === 3. Тест Паддинга PKCS#1 v1.5 ===
TEST(RSA_Padding, PadUnpad) {
    size_t keySizeBytes = 128; // 1024 бита
    std::string msg = "Test Padding Message";

    // ИСПРАВЛЕНИЕ: Явная конвертация char -> Byte
    Bytes data;
    data.reserve(msg.size());
    for(char c : msg) {
        data.push_back(static_cast<Byte>(c));
    }

    // 1. Pad
    BigInt paddedBlock = padding::RSA_PKCS1::pad(data, keySizeBytes);

    // Убедимся, что число большое (почти размером с ключ)
    EXPECT_GT(paddedBlock, BigInt(1) << (keySizeBytes * 8 - 20));

    // 2. Unpad
    Bytes restoredData = padding::RSA_PKCS1::unpad(paddedBlock, keySizeBytes);

    EXPECT_EQ(data, restoredData);
}

TEST(RSA_Padding, ThrowsOnTooLargeData) {
    size_t keySizeBytes = 64; // 512 бит
    // Максимум данных: 64 - 11 = 53 байта.
    // Создаем вектор 60 байт (0xFF)
    Bytes hugeData(60, Byte{0xFF});

    EXPECT_THROW(padding::RSA_PKCS1::pad(hugeData, keySizeBytes), std::runtime_error);
}

// === 4. Тест Атаки Винера ===
TEST(RSA_Attack, WienerAttackSuccess) {
    // 1. Генерируем специально СЛАБЫЙ ключ
    auto weakKeys = asymmetric::WeakKeyGenerator::generateWeak(1024);

    // Убедимся, что ключ валиден
    asymmetric::RSA rsa;
    BigInt msg = 555;
    BigInt enc = rsa.encrypt(msg, weakKeys.pub);
    BigInt dec = rsa.decrypt(enc, weakKeys.priv);
    ASSERT_EQ(msg, dec) << "Generated weak key is invalid!";

    // 2. Запускаем атаку
    BigInt recoveredD = attacks::WienerAttack::recoverPrivateKey(weakKeys.pub);

    // 3. Проверяем
    EXPECT_EQ(recoveredD, weakKeys.priv.d) << "Wiener attack failed to recover d";
}

// === 5. Тест Защиты обычного генератора ===
TEST(RSA_KeyGen, NormalGeneratorResistsWiener) {
    // Генерируем НОРМАЛЬНЫЙ ключ
    auto strongKeys = asymmetric::RSAKeyGenerator::generate(512);

    // Пытаемся атаковать
    BigInt result = attacks::WienerAttack::recoverPrivateKey(strongKeys.pub);

    // Либо атака вернула 0, либо неправильное число
    if (result != 0) {
        EXPECT_NE(result, strongKeys.priv.d) << "Normal generator created a WEAK key! Security breach.";
    }
}