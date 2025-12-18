#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <random>
#include "crypto/common/BigInt.hpp"
#include "crypto/math/MathUtils.hpp"
#include "crypto/asymmetric/RSA.hpp"
#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/asymmetric/WeakKeyGenerator.hpp"
#include "crypto/padding/RSA_PKCS1.hpp"
#include "crypto/attacks/WienerAttack.hpp"
using namespace crypto;
TEST(RSA_Math, ModInverseAndPow) {
    BigInt base = 4;
    BigInt exp = 13;
    BigInt mod = 497;
    EXPECT_EQ(math::MathUtils::modPow(base, exp, mod), 445);
    EXPECT_EQ(math::MathUtils::modInverse(3, 11), 4);
}
TEST(RSA_Core, EncryptDecryptRaw) {
    auto keys = asymmetric::RSAKeyGenerator::generate(512);
    asymmetric::RSA rsa;
    BigInt original = 123456789;
    BigInt encrypted = rsa.encrypt(original, keys.pub);
    BigInt decrypted = rsa.decrypt(encrypted, keys.priv);
    EXPECT_EQ(original, decrypted);
    EXPECT_NE(original, encrypted);
}
TEST(RSA_Padding, PadUnpad) {
    size_t keySizeBytes = 128;
    std::string msg = "Test Padding Message";
    Bytes data;
    data.reserve(msg.size());
    for(char c : msg) {
        data.push_back(static_cast<Byte>(c));
    }
    BigInt paddedBlock = padding::RSA_PKCS1::pad(data, keySizeBytes);
    EXPECT_GT(paddedBlock, BigInt(1) << (keySizeBytes * 8 - 20));
    Bytes restoredData = padding::RSA_PKCS1::unpad(paddedBlock, keySizeBytes);
    EXPECT_EQ(data, restoredData);
}
TEST(RSA_Padding, ThrowsOnTooLargeData) {
    size_t keySizeBytes = 64;
    Bytes hugeData(60, Byte{0xFF});
    EXPECT_THROW(padding::RSA_PKCS1::pad(hugeData, keySizeBytes), std::runtime_error);
}
TEST(RSA_Attack, WienerAttackSuccess) {
    auto weakKeys = asymmetric::WeakKeyGenerator::generateWeak(1024);
    asymmetric::RSA rsa;
    BigInt msg = 555;
    BigInt enc = rsa.encrypt(msg, weakKeys.pub);
    BigInt dec = rsa.decrypt(enc, weakKeys.priv);
    ASSERT_EQ(msg, dec) << "Generated weak key is invalid!";
    BigInt recoveredD = attacks::WienerAttack::recoverPrivateKey(weakKeys.pub);
    EXPECT_EQ(recoveredD, weakKeys.priv.d) << "Wiener attack failed to recover d";
}
TEST(RSA_KeyGen, NormalGeneratorResistsWiener) {
    auto strongKeys = asymmetric::RSAKeyGenerator::generate(512);
    BigInt result = attacks::WienerAttack::recoverPrivateKey(strongKeys.pub);
    if (result != 0) {
        EXPECT_NE(result, strongKeys.priv.d) << "Normal generator created a WEAK key! Security breach.";
    }
}