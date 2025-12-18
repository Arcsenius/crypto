#include "crypto/utils/FileProcessor.hpp"
#include <fstream>
#include <vector>
#include <stdexcept>
namespace crypto::utils {
    void FileProcessor::process(const std::filesystem::path& inPath,
                                const std::filesystem::path& outPath,
                                ICipherMode& mode,
                                bool encrypt)
    {
        if (!std::filesystem::exists(inPath)) {
            throw std::runtime_error("Input file not found: " + inPath.string());
        }
        std::ifstream inFile(inPath, std::ios::binary | std::ios::ate);
        if (!inFile) throw std::runtime_error("Cannot open input file");
        std::streamsize size = inFile.tellg();
        inFile.seekg(0, std::ios::beg);
        Bytes buffer(size);
        if (!inFile.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw std::runtime_error("Error reading file");
        }
        Bytes result;
        if (encrypt) {
            result = mode.encrypt(buffer);
        } else {
            result = mode.decrypt(buffer);
        }
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile) throw std::runtime_error("Cannot open output file");
        outFile.write(reinterpret_cast<const char*>(result.data()), result.size());
    }
}