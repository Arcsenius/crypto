#include <iostream>
#include <string>
#include <filesystem>
#include <memory>
#include <vector>
#include <cstring>
#include <algorithm>
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
#include "crypto/utils/FileProcessor.hpp"
using namespace crypto;
void printUsage() {
    std::cout << "Usage: lab1 <mode> <algo> <padding> <key> <input_file> <output_file> [enc|dec]\n";
    std::cout << "Options:\n";
    std::cout << "  Modes:   ECB, CBC, CTR, RD (RandomDelta)\n";
    std::cout << "  Algos:   DES, 3DES, DEAL\n";
    std::cout << "  Padding: PKCS7, ANSI, ISO, Zeros\n";
    std::cout << "Example: lab1 CBC DES PKCS7 mysecretkey data.bin out.bin enc\n";
}
Bytes prepareKey(const Bytes& rawKey, size_t requiredSize) {
    Bytes key = rawKey;
    if (key.size() < requiredSize) {
        key.resize(requiredSize, Byte{0});
    } else if (key.size() > requiredSize) {
        key.resize(requiredSize);
    }
    return key;
}
Bytes generateIV(size_t size) {


    return Bytes(size, Byte{0});
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

        Bytes rawKey;
        rawKey.reserve(keyStr.size());
        for (char c : keyStr) rawKey.push_back(static_cast<Byte>(c));

        std::unique_ptr<IBlockCipher> cipher;
        if (algoStr == "DES") {

            cipher = std::make_unique<symmetric::DES>(prepareKey(rawKey, 8));
        } else if (algoStr == "3DES") {

            cipher = std::make_unique<symmetric::TripleDES>(prepareKey(rawKey, 24));
        } else if (algoStr == "DEAL") {

            cipher = std::make_unique<symmetric::DEAL>(prepareKey(rawKey, 16));
        } else {
            throw std::invalid_argument("Unknown algorithm: " + algoStr);
        }

        std::unique_ptr<IPadding> padding;
        if (padStr == "PKCS7") {
            padding = std::make_unique<padding::PKCS7>();
        } else if (padStr == "ANSI") {
            padding = std::make_unique<padding::ANSIX923>();
        } else if (padStr == "ISO") {
            padding = std::make_unique<padding::ISO10126>();
        } else if (padStr == "Zeros") {
            padding = std::make_unique<padding::Zeros>();
        } else if (padStr == "None") {
            padding = nullptr;
        } else {
            throw std::invalid_argument("Unknown padding: " + padStr);
        }

        std::unique_ptr<ICipherMode> mode;
        size_t blockSize = cipher->getBlockSize();
        if (modeStr == "ECB") {
            if (!padding) throw std::invalid_argument("ECB requires padding");
            mode = std::make_unique<modes::ECB>(std::move(cipher), std::move(padding));
        }
        else if (modeStr == "CBC") {
            if (!padding) throw std::invalid_argument("CBC requires padding");

            Bytes iv = generateIV(blockSize);
            mode = std::make_unique<modes::CBC>(std::move(cipher), std::move(padding), iv);
        }
        else if (modeStr == "CTR") {



            Bytes iv = generateIV(blockSize);
            mode = std::make_unique<modes::CTR>(std::move(cipher), iv);
        }
        else if (modeStr == "RD") {
            if (!padding) throw std::invalid_argument("RandomDelta requires padding");

            Bytes iv = generateIV(4);
            mode = std::make_unique<modes::RandomDelta>(std::move(cipher), std::move(padding), iv);
        }
        else {
            throw std::invalid_argument("Unknown mode: " + modeStr);
        }

        std::cout << "Config: " << algoStr << "/" << modeStr << "/" << padStr << "\n";
        std::cout << "Operation: " << (encrypt ? "Encrypting" : "Decrypting") << "...\n";
        utils::FileProcessor::process(inFile, outFile, *mode, encrypt);
        std::cout << "Success! Result written to " << outFile << "\n";
    } catch (const std::exception& e) {
        std::cerr << "\n[ERROR] " << e.what() << "\n";
        return -1;
    }
    return 0;
}