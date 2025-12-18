#pragma once
#include <filesystem>
#include <string>
#include "crypto/asymmetric/RSA.hpp"
#include "crypto/interfaces/IAsymmetricCipher.hpp"
#include "crypto/padding/RSA_PKCS1.hpp"
namespace crypto::utils {
    class RSAFileProcessor {
    public:
        static void encryptFile(
            const std::filesystem::path& inPath,
            const std::filesystem::path& outPath,
            const PublicKey& pubKey,
            size_t keySizeBits
        );
        static void decryptFile(
            const std::filesystem::path& inPath,
            const std::filesystem::path& outPath,
            const PrivateKey& privKey,
            size_t keySizeBits
        );
    };
}