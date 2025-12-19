#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <random>
#include "crypto/symmetric/FROG.hpp"
#include "crypto/modes/ECB.hpp"
#include "crypto/modes/OFB.hpp"
#include "crypto/modes/PCBC.hpp"
#include "crypto/padding/PKCS7.hpp"
using namespace crypto;
TEST(FROG_Core, KeySizes) {

    std::vector<Byte> k5(5, Byte{1});
    EXPECT_NO_THROW(symmetric::FROG f(k5));

    std::vector<Byte> k125(125, Byte{2});
    EXPECT_NO_THROW(symmetric::FROG f(k125));

    std::vector<Byte> kSmall(4);
    EXPECT_THROW(symmetric::FROG f(kSmall), std::invalid_argument);
    std::vector<Byte> kBig(126);
    EXPECT_THROW(symmetric::FROG f(kBig), std::invalid_argument);
}
TEST(FROG_Core, BlockEncryptDecrypt) {
    std::vector<Byte> key(16, Byte{0x55});
    symmetric::FROG frog(key);
    std::vector<Byte> original(16);
    for(int i=0; i<16; ++i) original[i] = static_cast<Byte>(i);
    std::vector<Byte> encrypted(16);
    frog.encryptBlock(original, encrypted);

    EXPECT_NE(original, encrypted);
    std::vector<Byte> decrypted(16);
    frog.decryptBlock(encrypted, decrypted);
    EXPECT_EQ(original, decrypted);
}
TEST(FROG_Integration, ECB_PKCS7) {
    std::vector<Byte> key(16, Byte{0xAA});
    auto cipher = std::make_unique<symmetric::FROG>(key);
    auto padding = std::make_unique<padding::PKCS7>();
    modes::ECB ecb(std::move(cipher), std::move(padding));
    std::string msg = "Hello FROG Cipher!";

    Bytes data;
    for(char c : msg) data.push_back(static_cast<Byte>(c));
    Bytes enc = ecb.encrypt(data);
    Bytes dec = ecb.decrypt(enc);
    EXPECT_EQ(data, dec);
}
TEST(FROG_Integration, OFB_Stream) {
    std::vector<Byte> key(16, Byte{0x12});
    auto cipher = std::make_unique<symmetric::FROG>(key);
    std::vector<Byte> iv(16, Byte{0x00});
    modes::OFB ofb(std::move(cipher), iv);
    std::string msg = "Stream cipher mode test";

    Bytes data;
    for(char c : msg) data.push_back(static_cast<Byte>(c));
    Bytes enc = ofb.encrypt(data);
    Bytes dec = ofb.decrypt(enc);
    EXPECT_EQ(data, dec);
    EXPECT_NE(data, enc);
}
TEST(FROG_Integration, PCBC_Propagating) {
    std::vector<Byte> key(16, Byte{0x34});
    auto cipher = std::make_unique<symmetric::FROG>(key);
    auto padding = std::make_unique<padding::PKCS7>();
    std::vector<Byte> iv(16, Byte{0xFF});
    modes::PCBC pcbc(std::move(cipher), std::move(padding), iv);

    Bytes data(32, Byte{0xAA});
    Bytes enc = pcbc.encrypt(data);
    Bytes dec = pcbc.decrypt(enc);
    EXPECT_EQ(data, dec);
}