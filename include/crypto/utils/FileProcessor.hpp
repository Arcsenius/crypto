#pragma once
#include <string>
#include <filesystem>
#include "crypto/interfaces/ICipherMode.hpp"
namespace crypto::utils {
    class FileProcessor {
    public:
        static void process(
            const std::filesystem::path& inputFile,
            const std::filesystem::path& outputFile,
            ICipherMode& mode,
            bool encrypt
        );
    };
}