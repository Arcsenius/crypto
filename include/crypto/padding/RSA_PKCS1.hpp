#pragma once
#include "crypto/common/BigInt.hpp"
#include <vector>
#include <random>
#include <stdexcept>
namespace crypto::padding {
    class RSA_PKCS1 {
    public:


        static BigInt pad(const Bytes& data, size_t keySizeBytes) {
            if (data.size() > keySizeBytes - 11) {
                throw std::runtime_error("RSA PKCS1: Data too long for key size");
            }


            Bytes block;
            block.reserve(keySizeBytes);


            block.push_back(Byte{0x02});

            size_t psLen = keySizeBytes - data.size() - 3;
            static std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<> dis(1, 255);
            for (size_t i = 0; i < psLen; ++i) {
                block.push_back(static_cast<Byte>(dis(gen)));
            }

            block.push_back(Byte{0x00});

            block.insert(block.end(), data.begin(), data.end());

            return bytesToBigInt(block);
        }

        static Bytes unpad(const BigInt& paddedInt, size_t keySizeBytes) {
            Bytes block = bigIntToBytes(paddedInt, keySizeBytes);
            size_t cursor = 0;

            if (!block.empty() && block[0] == Byte{0x00}) cursor++;
            if (cursor >= block.size() || block[cursor] != Byte{0x02}) {
                throw std::runtime_error("RSA PKCS1: Invalid block type");
            }
            cursor++;

            while (cursor < block.size() && block[cursor] != Byte{0x00}) {
                cursor++;
            }
            if (cursor >= block.size()) {
                throw std::runtime_error("RSA PKCS1: Separator 0x00 not found");
            }
            cursor++;

            return Bytes(block.begin() + cursor, block.end());
        }
    private:
        static BigInt bytesToBigInt(const Bytes& bytes) {

            std::vector<uint8_t> temp;
            temp.reserve(bytes.size());
            for(auto b : bytes) temp.push_back(static_cast<uint8_t>(b));
            using boost::multiprecision::cpp_int;
            using boost::multiprecision::import_bits;
            BigInt res;

            import_bits(res, temp.begin(), temp.end(), 8, true);
            return res;
        }
        static Bytes bigIntToBytes(const BigInt& num, size_t expectedSize) {
            using boost::multiprecision::export_bits;

            std::vector<uint8_t> tempBuffer;
            export_bits(num, std::back_inserter(tempBuffer), 8);

            Bytes res;
            res.reserve(tempBuffer.size());
            for(auto val : tempBuffer) res.push_back(static_cast<Byte>(val));

            if (res.size() < expectedSize) {
                Bytes padded(expectedSize - res.size(), Byte{0});
                padded.insert(padded.end(), res.begin(), res.end());
                return padded;
            }
            return res;
        }
    };
}