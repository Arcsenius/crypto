#pragma once
#include "crypto/common/BigInt.hpp"
#include <vector>
#include <random>
#include <stdexcept>

namespace crypto::padding {

    class RSA_PKCS1 {
    public:
        // Упаковка данных в BigInt
        // keySizeBytes: размер модуля n в байтах (например, 256 для 2048 бит)
        static BigInt pad(const Bytes& data, size_t keySizeBytes) {
            if (data.size() > keySizeBytes - 11) {
                throw std::runtime_error("RSA PKCS1: Data too long for key size");
            }

            // Мы используем Bytes (std::vector<byte>), но для генерации паддинга нужны числа
            // Сформируем блок в Bytes
            Bytes block;
            block.reserve(keySizeBytes);

            // 1. Start byte 0x00 (пропускаем в векторе, т.к. BigInt съест ведущий ноль)
            // 2. Block Type 0x02
            block.push_back(Byte{0x02});

            // 3. Padding String (PS) - random non-zero
            size_t psLen = keySizeBytes - data.size() - 3;

            static std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<> dis(1, 255); // Non-zero!

            for (size_t i = 0; i < psLen; ++i) {
                block.push_back(static_cast<Byte>(dis(gen)));
            }

            // 4. Separator 0x00
            block.push_back(Byte{0x00});

            // 5. Data
            block.insert(block.end(), data.begin(), data.end());

            // Convert Bytes -> BigInt
            return bytesToBigInt(block);
        }

        // Распаковка BigInt в данные
        static Bytes unpad(const BigInt& paddedInt, size_t keySizeBytes) {
            Bytes block = bigIntToBytes(paddedInt, keySizeBytes);

            size_t cursor = 0;
            // Пропускаем возможный ведущий ноль
            if (!block.empty() && block[0] == Byte{0x00}) cursor++;

            if (cursor >= block.size() || block[cursor] != Byte{0x02}) {
                throw std::runtime_error("RSA PKCS1: Invalid block type");
            }
            cursor++;

            // Ищем разделитель 0x00
            while (cursor < block.size() && block[cursor] != Byte{0x00}) {
                cursor++;
            }

            if (cursor >= block.size()) {
                throw std::runtime_error("RSA PKCS1: Separator 0x00 not found");
            }
            cursor++; // Пропускаем сам разделитель

            // Всё остальное - данные
            return Bytes(block.begin() + cursor, block.end());
        }

    private:
        static BigInt bytesToBigInt(const Bytes& bytes) {
            // КОНВЕРТАЦИЯ: std::byte -> uint8_t для Boost
            std::vector<uint8_t> temp;
            temp.reserve(bytes.size());
            for(auto b : bytes) temp.push_back(static_cast<uint8_t>(b));

            using boost::multiprecision::cpp_int;
            using boost::multiprecision::import_bits;
            BigInt res;
            // import_bits ожидает числовой контейнер
            import_bits(res, temp.begin(), temp.end(), 8, true);
            return res;
        }

        static Bytes bigIntToBytes(const BigInt& num, size_t expectedSize) {
            using boost::multiprecision::export_bits;

            // ВРЕМЕННЫЙ БУФЕР: uint8_t
            std::vector<uint8_t> tempBuffer;
            export_bits(num, std::back_inserter(tempBuffer), 8);

            // КОНВЕРТАЦИЯ: uint8_t -> std::byte
            Bytes res;
            res.reserve(tempBuffer.size());
            for(auto val : tempBuffer) res.push_back(static_cast<Byte>(val));

            // Дополняем нулями слева до размера ключа (BigInt обрезает ведущие нули)
            if (res.size() < expectedSize) {
                Bytes padded(expectedSize - res.size(), Byte{0});
                padded.insert(padded.end(), res.begin(), res.end());
                return padded;
            }
            return res;
        }
    };
}