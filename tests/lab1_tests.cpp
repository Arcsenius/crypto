#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <memory>
#include <random>
#include <algorithm>

// Подключаем библиотеку
#include "crypto/symmetric/DES.hpp"
#include "crypto/symmetric/TripleDES.hpp"
#include "crypto/symmetric/DEAL.hpp"

#include "crypto/modes/ECB.hpp"
#include "crypto/modes/CBC.hpp"
#include "crypto/modes/CTR.hpp"
#include "crypto/modes/RandomDelta.hpp"

#include "crypto/padding/PKCS7.hpp"
#include "crypto/padding/ANSIX923.hpp"
#include "crypto/padding/ISO10126.hpp"
#include "crypto/padding/Zeros.hpp"

using namespace crypto;

// === 1. Структура параметров теста ===
struct CryptoParams {
    std::string algoName;
    std::string modeName;
    std::string paddingName;
    size_t keySize;
};

// Для красивого вывода имени теста в логах
std::ostream& operator<<(std::ostream& os, const CryptoParams& p) {
    return os << p.algoName << "_" << p.modeName << "_" << p.paddingName;
}

// === 2. Тестовый класс (Fixture) ===
class CryptoRoundTripTest : public ::testing::TestWithParam<CryptoParams> {
protected:
    // Генератор случайных данных
    Bytes generateRandomBytes(size_t size) {
        Bytes res(size);
        std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < size; ++i) res[i] = static_cast<Byte>(dis(gen));
        return res;
    }

    // Фабрика (упрощенная копия из main.cpp)
    std::unique_ptr<ICipherMode> createStack(const CryptoParams& p, const Bytes& key) {
        // 1. Algo
        std::unique_ptr<IBlockCipher> cipher;
        Bytes adjustedKey = key;
        adjustedKey.resize(p.keySize, Byte{0}); // Подгонка размера

        if (p.algoName == "DES") cipher = std::make_unique<symmetric::DES>(adjustedKey);
        else if (p.algoName == "3DES") cipher = std::make_unique<symmetric::TripleDES>(adjustedKey);
        else if (p.algoName == "DEAL") cipher = std::make_unique<symmetric::DEAL>(adjustedKey);
        else throw std::runtime_error("Unknown algo");

        size_t bs = cipher->getBlockSize();

        // 2. Padding
        std::unique_ptr<IPadding> padding;
        if (p.paddingName == "PKCS7") padding = std::make_unique<padding::PKCS7>();
        else if (p.paddingName == "ANSI") padding = std::make_unique<padding::ANSIX923>();
        else if (p.paddingName == "ISO") padding = std::make_unique<padding::ISO10126>();
        else if (p.paddingName == "Zeros") padding = std::make_unique<padding::Zeros>();
        else if (p.paddingName == "None") padding = nullptr;

        // 3. Mode
        // Генерируем IV (нули для детерминированности теста, в реальности нужен рандом)
        Bytes iv(bs, Byte{0});

        if (p.modeName == "ECB") {
            return std::make_unique<modes::ECB>(std::move(cipher), std::move(padding));
        } else if (p.modeName == "CBC") {
            return std::make_unique<modes::CBC>(std::move(cipher), std::move(padding), iv);
        } else if (p.modeName == "CTR") {
            return std::make_unique<modes::CTR>(std::move(cipher), iv);
        } else if (p.modeName == "RD") {
            Bytes seedIv(4, Byte{0}); // Seed для RD
            return std::make_unique<modes::RandomDelta>(std::move(cipher), std::move(padding), seedIv);
        }
        throw std::runtime_error("Unknown mode");
    }
};

// === 3. Сам Тест ===
TEST_P(CryptoRoundTripTest, EncryptDecryptMatchesOriginal) {
    CryptoParams params = GetParam();

    // Подготовка данных
    // Размер данных берем случайный, чтобы проверить работу паддинга (не кратный блоку)
    size_t dataSize = 1024 + 5; // 1029 байт
    Bytes original = generateRandomBytes(dataSize);
    Bytes key = generateRandomBytes(params.keySize);

    // Создаем стек для шифрования
    auto encryptor = createStack(params, key);

    // Шифруем
    Bytes encrypted;
    ASSERT_NO_THROW({
        encrypted = encryptor->encrypt(original);
    }) << "Encryption failed for " << params;

    ASSERT_FALSE(encrypted.empty());
    if (params.modeName != "CTR") {
        // Для блочных режимов размер должен измениться из-за паддинга (кроме Zeros/None в редких случаях)
        // Но точно должен быть кратен блоку (обычно 8 или 16)
        // Для CTR размер равен исходному.
        ASSERT_GE(encrypted.size(), original.size());
    }

    // Создаем стек для дешифрования (новый объект, чтобы сбросить состояние)
    auto decryptor = createStack(params, key);

    // Расшифровываем
    Bytes decrypted;
    ASSERT_NO_THROW({
        decrypted = decryptor->decrypt(encrypted);
    }) << "Decryption failed for " << params;

    // Сверяем
    ASSERT_EQ(original, decrypted) << "Decrypted data mismatch for " << params;
}

// === 4. Генерация параметров (Combinatorial) ===

// Список алгоритмов: {Название, Размер ключа}
const std::vector<std::pair<std::string, size_t>> ALGOS = {
    {"DES", 8},
    {"3DES", 24},
    {"DEAL", 16}
};

// Режимы, требующие паддинга
const std::vector<std::string> BLOCK_MODES = {"ECB", "CBC", "RD"};
// Паддинги
const std::vector<std::string> PADDINGS = {"PKCS7", "ANSI", "ISO", "Zeros"};

// Потоковые режимы (паддинг None)
const std::vector<std::string> STREAM_MODES = {"CTR"};

// Функция для создания всех комбинаций
std::vector<CryptoParams> GenerateParams() {
    std::vector<CryptoParams> combinations;

    for (const auto& algo : ALGOS) {
        // Комбинации: Block Mode + Padding
        for (const auto& mode : BLOCK_MODES) {
            for (const auto& pad : PADDINGS) {
                combinations.push_back({algo.first, mode, pad, algo.second});
            }
        }
        // Комбинации: Stream Mode + None Padding
        for (const auto& mode : STREAM_MODES) {
            combinations.push_back({algo.first, mode, "None", algo.second});
        }
    }
    return combinations;
}

// === 5. Регистрация тестов ===
INSTANTIATE_TEST_SUITE_P(
    AllCombinations,
    CryptoRoundTripTest,
    ::testing::ValuesIn(GenerateParams()),
    [](const testing::TestParamInfo<CryptoParams>& info) {
        return info.param.algoName + "_" + info.param.modeName + "_" + info.param.paddingName;
    }
);

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}