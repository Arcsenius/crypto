#include "crypto/symmetric/FROG.hpp"
#include <stdexcept>
#include <cstring>
#include <vector>
namespace crypto::symmetric {
    FROG::FROG(ConstBytesSpan key) {
        if (key.size() < 5 || key.size() > 125) {
            throw std::invalid_argument("FROG key must be between 5 and 125 bytes");
        }
        encryptKeys.resize(NUM_ROUNDS);
        decryptKeys.resize(NUM_ROUNDS);
        makeInternalKey(key);
        invertKeys();
    }
    void FROG::makeInternalKey(ConstBytesSpan userKey) {
        std::vector<uint8_t> simpleKey(INTERNAL_KEY_SIZE);
        size_t keyLen = userKey.size();
        for (size_t i = 0; i < INTERNAL_KEY_SIZE; ++i) {
            simpleKey[i] = 0;
        }
        size_t current = 0;
        size_t processed = 0;
        while (processed < INTERNAL_KEY_SIZE) {
            for (size_t i = 0; i < keyLen; ++i) {
                if (processed >= INTERNAL_KEY_SIZE) break;
                simpleKey[processed] ^= static_cast<uint8_t>(userKey[i]);
                processed++;
            }
        }
        uint8_t buf[BLOCK_SIZE];
        for(size_t i=0; i<BLOCK_SIZE; ++i) buf[i] = 0;
        buf[0] = static_cast<uint8_t>(keyLen);
        size_t last = INTERNAL_KEY_SIZE - 16;
        for (size_t chunk = 0; chunk < INTERNAL_KEY_SIZE; chunk += 16) {
             for(size_t i=0; i<16; ++i) {
                 simpleKey[chunk + i] ^= buf[i];
                 buf[i] = simpleKey[chunk + i];
             }
        }
        size_t cursor = 0;
        for (int r = 0; r < NUM_ROUNDS; ++r) {
            for (int i = 0; i < 16; ++i) encryptKeys[r].xorBu[i] = simpleKey[cursor++];
            std::array<bool, 256> used = {false};
            for (int i = 0; i < 256; ++i) {
                uint8_t val = simpleKey[cursor++];
                encryptKeys[r].subst[i] = val;
                used[val] = true;
            }
            size_t missingIdx = 0;
            std::vector<uint8_t> missing;
            for (int i = 0; i < 256; ++i) if (!used[i]) missing.push_back(i);
            std::fill(used.begin(), used.end(), false);
            size_t m_ptr = 0;
            for (int i = 0; i < 256; ++i) {
                uint8_t val = encryptKeys[r].subst[i];
                if (used[val]) {
                    if (m_ptr < missing.size()) {
                        encryptKeys[r].subst[i] = missing[m_ptr++];
                        used[encryptKeys[r].subst[i]] = true;
                    }
                } else {
                    used[val] = true;
                }
            }
            for (int i = 0; i < 16; ++i) encryptKeys[r].bombPerm[i] = simpleKey[cursor++];
        }
    }
    void FROG::invertKeys() {
        for (int r = 0; r < NUM_ROUNDS; ++r) {
            int srcR = NUM_ROUNDS - 1 - r;
            const auto& ek = encryptKeys[srcR];
            auto& dk = decryptKeys[r];
            dk.xorBu = ek.xorBu;
            for (int i = 0; i < 256; ++i) {
                dk.subst[ek.subst[i]] = static_cast<uint8_t>(i);
            }
            dk.bombPerm = ek.bombPerm;
        }
    }
    void FROG::encryptBlock(ConstBytesSpan src, BytesSpan dst) {
        if (src.size() != BLOCK_SIZE || dst.size() != BLOCK_SIZE)
             throw std::invalid_argument("Size error");
        std::memcpy(dst.data(), src.data(), BLOCK_SIZE);
        uint8_t* block = reinterpret_cast<uint8_t*>(dst.data());
        for (int r = 0; r < NUM_ROUNDS; ++r) {
            const auto& key = encryptKeys[r];
            for (int i = 0; i < 16; ++i) block[i] ^= key.xorBu[i];
            for (int i = 0; i < 16; ++i) block[i] = key.subst[block[i]];
            for (int i = 0; i < 15; ++i) {
                block[i+1] ^= block[i];
            }
             block[0] ^= block[15];
        }
    }
    void FROG::decryptBlock(ConstBytesSpan src, BytesSpan dst) {
        if (src.size() != BLOCK_SIZE || dst.size() != BLOCK_SIZE)
             throw std::invalid_argument("Size error");
        std::memcpy(dst.data(), src.data(), BLOCK_SIZE);
        uint8_t* block = reinterpret_cast<uint8_t*>(dst.data());
        for (int r = 0; r < NUM_ROUNDS; ++r) {
            const auto& key = decryptKeys[r];
            block[0] ^= block[15];
            for (int i = 14; i >= 0; --i) {
                block[i+1] ^= block[i];
            }
            for (int i = 0; i < 16; ++i) block[i] = key.subst[block[i]];
            for (int i = 0; i < 16; ++i) block[i] ^= key.xorBu[i];
        }
    }
}