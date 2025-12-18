#include "crypto/utils/RSAFileProcessor.hpp"
#include <fstream>
#include <vector>
#include <execution>
#include <algorithm>
namespace crypto::utils {

    Bytes readFile(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) throw std::runtime_error("Cannot open file: " + path.string());
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        Bytes buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
             throw std::runtime_error("Read error");
        return buffer;
    }
    void writeFile(const std::filesystem::path& path, const Bytes& data) {
        std::ofstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open file: " + path.string());
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    void RSAFileProcessor::encryptFile(const std::filesystem::path& inPath, const std::filesystem::path& outPath, const PublicKey& pubKey, size_t keySizeBits) {
        size_t keySizeBytes = keySizeBits / 8;
        size_t maxDataSize = keySizeBytes - 11;
        Bytes input = readFile(inPath);

        size_t blockCount = (input.size() + maxDataSize - 1) / maxDataSize;
        std::vector<Bytes> outputBlocks(blockCount);
        std::vector<size_t> indices(blockCount);
        std::iota(indices.begin(), indices.end(), 0);
        asymmetric::RSA rsa;

        std::for_each(std::execution::par, indices.begin(), indices.end(), [&](size_t i) {
            size_t offset = i * maxDataSize;
            size_t len = std::min(maxDataSize, input.size() - offset);

            Bytes chunk(input.begin() + offset, input.begin() + offset + len);

            BigInt padded = padding::RSA_PKCS1::pad(chunk, keySizeBytes);

            BigInt encrypted = rsa.encrypt(padded, pubKey);

            using boost::multiprecision::export_bits;

            std::vector<uint8_t> tempBuffer;
            export_bits(encrypted, std::back_inserter(tempBuffer), 8);

            Bytes outChunk;
            outChunk.reserve(tempBuffer.size());
            for(auto val : tempBuffer) outChunk.push_back(static_cast<Byte>(val));

            if (outChunk.size() < keySizeBytes) {
                Bytes aligned(keySizeBytes - outChunk.size(), Byte{0});
                aligned.insert(aligned.end(), outChunk.begin(), outChunk.end());
                outputBlocks[i] = aligned;
            } else {
                outputBlocks[i] = outChunk;
            }
        });

        std::ofstream outFile(outPath, std::ios::binary);
        for (const auto& block : outputBlocks) {
            outFile.write(reinterpret_cast<const char*>(block.data()), block.size());
        }
    }
    void RSAFileProcessor::decryptFile(const std::filesystem::path& inPath, const std::filesystem::path& outPath, const PrivateKey& privKey, size_t keySizeBits) {
        size_t keySizeBytes = keySizeBits / 8;
        Bytes input = readFile(inPath);
        if (input.size() % keySizeBytes != 0) {
            throw std::runtime_error("Encrypted file corrupted (size not multiple of key size)");
        }
        size_t blockCount = input.size() / keySizeBytes;
        std::vector<Bytes> outputBlocks(blockCount);
        std::vector<size_t> indices(blockCount);
        std::iota(indices.begin(), indices.end(), 0);
        asymmetric::RSA rsa;

        std::for_each(std::execution::par, indices.begin(), indices.end(), [&](size_t i) {
            size_t offset = i * keySizeBytes;
            Bytes chunk(input.begin() + offset, input.begin() + offset + keySizeBytes);


            std::vector<uint8_t> tempChunk;
            tempChunk.reserve(chunk.size());
            for(auto b : chunk) tempChunk.push_back(static_cast<uint8_t>(b));
            using boost::multiprecision::import_bits;
            BigInt encrypted;
            import_bits(encrypted, tempChunk.begin(), tempChunk.end(), 8);

            BigInt decrypted = rsa.decrypt(encrypted, privKey);

            outputBlocks[i] = padding::RSA_PKCS1::unpad(decrypted, keySizeBytes);
        });

        std::ofstream outFile(outPath, std::ios::binary);
        for (const auto& block : outputBlocks) {
            outFile.write(reinterpret_cast<const char*>(block.data()), block.size());
        }
    }
}