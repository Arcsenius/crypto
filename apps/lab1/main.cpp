#include <iostream>
#include <string>
#include <filesystem>
#include <memory>

// Подключаем наши хедеры
#include "crypto/symmetric/DES.hpp"
#include "crypto/symmetric/TripleDES.hpp"
// #include "crypto/symmetric/DEAL.hpp" 
#include "crypto/padding/PKCS7.hpp"
// #include "crypto/modes/CBC.hpp"
#include "crypto/modes/ECB.hpp"
#include "crypto/utils/FileProcessor.hpp"

using namespace crypto;

void printUsage() {
    std::cout << "Usage: lab1 <mode> <algo> <padding> <key> <input_file> <output_file> [enc|dec]\n";
    std::cout << "Example: lab1 ECB DES PKCS7 mysecretkey data.bin out.bin enc\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 8) {
            printUsage();
            return 1;
        }

        std::string modeStr = argv[1];
        std::string algoStr = argv[2];
        std::string padStr = argv[3];
        std::string keyStr = argv[4];
        std::filesystem::path inFile = argv[5];
        std::filesystem::path outFile = argv[6];
        bool encrypt = (std::string(argv[7]) == "enc");

        // 1. Создаем ключ (простая конвертация строки в байты)
        // В реальности нужен KDF (Key Derivation Function), но для лабы сойдет обрезка/дополнение
        Bytes keyData;
        for (char c : keyStr) keyData.push_back(static_cast<Byte>(c));

        // 2. Фабрика алгоритма
        std::unique_ptr<IBlockCipher> cipher;
        if (algoStr == "DES") {
            // DES требует 8 байт
            keyData.resize(8, Byte{0}); 
            cipher = std::make_unique<symmetric::DES>(keyData);
        } else if (algoStr == "3DES") {
             // ...
             throw std::logic_error("3DES not implemented in this snippet");
        } else {
            throw std::invalid_argument("Unknown algorithm");
        }

        // 3. Фабрика паддинга
        std::unique_ptr<IPadding> padding;
        if (padStr == "PKCS7") {
             padding = std::make_unique<padding::PKCS7>();
        } else {
             // Default or error
             throw std::invalid_argument("Unknown padding");
        }

        // 4. Фабрика режима
        std::unique_ptr<ICipherMode> mode;
        if (modeStr == "ECB") {
            mode = std::make_unique<modes::ECB>(std::move(cipher), std::move(padding));
        } else {
            throw std::invalid_argument("Unknown mode");
        }

        // 5. Запуск
        std::cout << "Starting processing...\n";
        utils::FileProcessor::process(inFile, outFile, *mode, encrypt);
        std::cout << "Done! Output saved to " << outFile << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return -1;
    }

    return 0;
}