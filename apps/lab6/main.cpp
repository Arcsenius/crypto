#include <iostream>
#include <string>
#include <filesystem>
#include <memory>
#include <vector>

// Алгоритм
#include "crypto/symmetric/FROG.hpp"

// Режимы
#include "crypto/modes/ECB.hpp"
#include "crypto/modes/CBC.hpp"
#include "crypto/modes/CTR.hpp"
#include "crypto/modes/RandomDelta.hpp"

// Паддинги
#include "crypto/padding/PKCS7.hpp"
#include "crypto/padding/ANSIX923.hpp"
#include "crypto/padding/ISO10126.hpp"
#include "crypto/padding/Zeros.hpp"

// Утилиты
#include "crypto/utils/FileProcessor.hpp"

using namespace crypto;

void printUsage() {
    std::cout << "Usage: lab6 <mode> <padding> <key> <input_file> <output_file> [enc|dec]\n";
    std::cout << "Algo is always FROG.\n";
    std::cout << "Modes: ECB, CBC, CTR, RD\n";
    std::cout << "Paddings: PKCS7, ANSI, ISO, Zeros\n";
}

Bytes prepareKey(const Bytes& rawKey, size_t size) {
    Bytes key = rawKey;
    if (key.size() < size) key.resize(size, Byte{0});
    else if (key.size() > size) key.resize(size);
    return key;
}

Bytes generateIV(size_t size) {
    return Bytes(size, Byte{0}); // Для лабы нули, в продакшене рандом
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 7) {
            printUsage();
            return 1;
        }

        std::string modeStr = argv[1];
        std::string padStr = argv[2];
        std::string keyStr = argv[3];
        std::filesystem::path inFile = argv[4];
        std::filesystem::path outFile = argv[5];
        bool encrypt = (std::string(argv[6]) == "enc");

        // 1. Ключ
        Bytes rawKey;
        for(char c : keyStr) rawKey.push_back(static_cast<Byte>(c));

        // FROG принимает ключи от 5 до 125 байт. Возьмем 16 байт как стандарт, но можно и больше.
        // Если пользователь ввел короткий пароль, добьем до 16.
        Bytes key = prepareKey(rawKey, 16);

        // 2. Алгоритм (Только FROG)
        auto cipher = std::make_unique<symmetric::FROG>(key);
        size_t bs = cipher->getBlockSize();

        // 3. Padding
        std::unique_ptr<IPadding> padding;
        if (padStr == "PKCS7") padding = std::make_unique<padding::PKCS7>();
        else if (padStr == "ANSI") padding = std::make_unique<padding::ANSIX923>();
        else if (padStr == "ISO") padding = std::make_unique<padding::ISO10126>();
        else if (padStr == "Zeros") padding = std::make_unique<padding::Zeros>();
        else if (padStr == "None") padding = nullptr;
        else throw std::invalid_argument("Unknown padding");

        // 4. Mode
        std::unique_ptr<ICipherMode> mode;
        if (modeStr == "ECB") {
            mode = std::make_unique<modes::ECB>(std::move(cipher), std::move(padding));
        } else if (modeStr == "CBC") {
            mode = std::make_unique<modes::CBC>(std::move(cipher), std::move(padding), generateIV(bs));
        } else if (modeStr == "CTR") {
            mode = std::make_unique<modes::CTR>(std::move(cipher), generateIV(bs));
        } else if (modeStr == "RD") {
            mode = std::make_unique<modes::RandomDelta>(std::move(cipher), std::move(padding), generateIV(4));
        } else {
            throw std::invalid_argument("Unknown mode");
        }

        // 5. Run
        std::cout << "Running FROG " << modeStr << "...\n";
        utils::FileProcessor::process(inFile, outFile, *mode, encrypt);
        std::cout << "Done.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}