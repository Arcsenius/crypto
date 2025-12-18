#pragma once
#include "crypto/interfaces/ICipherMode.hpp"
#include <vector>

namespace crypto::modes {

    class PCBC : public ICipherMode {
        Bytes iv;
    public:
        PCBC(std::unique_ptr<IBlockCipher> c, std::unique_ptr<IPadding> p, ConstBytesSpan iv_)
            : ICipherMode(std::move(c), std::move(p)), iv(iv_.begin(), iv_.end())
        {
            if (iv.size() != cipher->getBlockSize()) throw std::invalid_argument("Invalid IV size");
        }

        Bytes encrypt(ConstBytesSpan input) override {
            Bytes data(input.begin(), input.end());
            size_t bs = cipher->getBlockSize();
            padding->addPadding(data, bs);

            Bytes result(data.size());
            size_t blocks = data.size() / bs;

            Bytes prevP = iv; // В начале IV играет роль (P_{i-1} ^ C_{i-1})
            Bytes prevC(bs, Byte{0}); // Не используется в первой итерации напрямую так как IV заменяет пару

            // В классическом PCBC: Input XOR IV.
            // Далее: Input XOR (PrevPlain XOR PrevCipher)
            // Упростим: state = IV.
            // C_i = Enc(P_i ^ state)
            // state = P_i ^ C_i

            Bytes state = iv;

            for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;
                Bytes block(bs);

                // XOR с state
                for(size_t j=0; j<bs; ++j) {
                    block[j] = data[offset + j] ^ state[j];
                }

                // Encrypt
                cipher->encryptBlock(block, std::span{result.data() + offset, bs});

                // Update state: P_i ^ C_i
                for(size_t j=0; j<bs; ++j) {
                    state[j] = data[offset + j] ^ result[offset + j];
                }
            }
            return result;
        }

        Bytes decrypt(ConstBytesSpan input) override {
            size_t bs = cipher->getBlockSize();
            if (input.size() % bs != 0) throw std::invalid_argument("Invalid size");

            Bytes result(input.size());
            size_t blocks = input.size() / bs;

            Bytes state = iv;

            for(size_t i=0; i<blocks; ++i) {
                size_t offset = i * bs;

                // Decrypt
                Bytes decBlock(bs);
                cipher->decryptBlock(input.subspan(offset, bs), decBlock);

                // XOR with state to get P_i
                for(size_t j=0; j<bs; ++j) {
                    result[offset + j] = decBlock[j] ^ state[j];
                }

                // Update state: P_i ^ C_i
                // P_i мы только что получили, C_i это input block
                for(size_t j=0; j<bs; ++j) {
                    state[j] = result[offset + j] ^ input[offset + j];
                }
            }

            size_t valid = padding->removePadding(result, bs);
            result.resize(valid);
            return result;
        }
    };
}