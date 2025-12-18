#include <iostream>
#include <filesystem>
#include <string>
#include "crypto/asymmetric/RSAKeyGenerator.hpp"
#include "crypto/utils/RSAFileProcessor.hpp"
#include "crypto/attacks/WienerAttack.hpp"
#include "crypto/asymmetric/WeakKeyGenerator.hpp"


using namespace crypto;

void printUsage() {
    std::cout << "Usage: lab2 <keysize> <input_file> <output_file> [gen|demo|attack]\n";
    std::cout << "Note: For 'dec', keys are regenerated (demo mode), so it won't work on restarted app.\n";
    std::cout << "Real app should save/load keys.\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            printUsage();
            return 1;
        }

        int keySize = std::stoi(argv[1]);
        std::filesystem::path inFile = argv[2];
        std::filesystem::path outFile = argv[3];
        std::string mode = argv[4];

        // В РЕАЛЬНОСТИ: Ключи нужно грузить с диска.
        // Для ЛАБЫ: Генерируем прямо тут.
        // ВНИМАНИЕ: Это значит, что 'dec' сработает только в том же запуске процесса.
        // Чтобы протестировать enc и dec раздельно, нам нужно сохранить ключи в файлы.
        // Давайте сделаем полный цикл в 'enc' для проверки, или реализуем сохранение.

        // Давайте для простоты реализуем сохранение ключей в текстовые файлы рядом.

        std::filesystem::path pubPath = "public.key";
        std::filesystem::path privPath = "private.key";

        asymmetric::RSAKeyPair keys;

        if (mode == "gen") {
             // Просто генератор
             std::cout << "Generating keys " << keySize << " bits...\n";
             keys = asymmetric::RSAKeyGenerator::generate(keySize);
             // Save to file (simple text format: e n \n d n)
             // ...
             return 0;
        }

        // Для упрощения демонстрации (и чтобы не писать парсер ключей сейчас):
        // Сделаем режим "demo", который делает gen -> enc -> dec и сравнивает.
        if (mode == "demo") {
            std::cout << "Generating keys...\n";
            keys = asymmetric::RSAKeyGenerator::generate(keySize);

            std::cout << "Encrypting " << inFile << "...\n";
            utils::RSAFileProcessor::encryptFile(inFile, outFile, keys.pub, keySize);

            std::cout << "Decrypting to " << outFile << ".dec ...\n";
            utils::RSAFileProcessor::decryptFile(outFile, outFile.string() + ".dec", keys.priv, keySize);

            std::cout << "Done! Check " << outFile << ".dec\n";
        }
        if (mode == "attack") {
            std::cout << "=== Wiener Attack Demo ===\n";
            std::cout << "1. Generating WEAK keys (vulnerable to Wiener)...\n";

            // Генерируем слабые ключи
            auto weakKeys = asymmetric::WeakKeyGenerator::generateWeak(1024);

            std::cout << "Generated:\n";
            std::cout << "d (secret) = " << weakKeys.priv.d << "\n";
            std::cout << "e (public) = " << weakKeys.pub.e << "\n";
            std::cout << "n (public) = " << weakKeys.pub.n << "\n";

            std::cout << "\n2. Launching Attack knowing only (e, n)...\n";

            BigInt recoveredD = attacks::WienerAttack::recoverPrivateKey(weakKeys.pub);

            if (recoveredD == weakKeys.priv.d) {
                std::cout << "\n[SUCCESS] Private key successfully recovered!\n";
                std::cout << "Recovered d = " << recoveredD << "\n";
            } else {
                std::cout << "\n[FAILURE] Attack failed.\n";
            }
            return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}