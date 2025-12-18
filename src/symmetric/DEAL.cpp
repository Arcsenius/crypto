#include "crypto/symmetric/DEAL.hpp"
#include <stdexcept>
#include <algorithm> // для std::swap

namespace crypto::symmetric {

    DEAL::DEAL(ConstBytesSpan key) {
        if (key.size() != 16) throw std::invalid_argument("DEAL-128 requires 16 bytes key");

        // Простая схема ключей: K1, K2, K3... повторяем 128 битный ключ
        // K = (K_A, K_B)
        // RK1 = K_A, RK2 = K_B, RK3 = K_A ...

        for(int i=0; i<6; ++i) {
             size_t offset = (i % 2) * 8;
             roundDes.push_back(std::make_unique<DES>(key.subspan(offset, 8)));
        }
    }

    void DEAL::encryptBlock(ConstBytesSpan src, BytesSpan dst) {
        if (src.size() != 16 || dst.size() != 16) throw std::invalid_argument("DEAL block size is 16");

        Bytes left(src.begin(), src.begin() + 8);
        Bytes right(src.begin() + 8, src.begin() + 16);

        for (int i = 0; i < 6; ++i) {
            // Feistel Round:
            // temp = R
            // R = L ^ f(R, K)
            // L = temp

            Bytes temp = right; // Сохраняем R_old

            // F(R, K) -> DES(R)
            Bytes f_out(8);
            roundDes[i]->encryptBlock(right, f_out);

            // R_new = L_old ^ F_out
            for(int j=0; j<8; ++j) right[j] = left[j] ^ f_out[j];

            // L_new = R_old
            left = temp;
        }

        // В конце классической сети Фейстеля (DES) делается Undo Swap (L и R меняются местами обратно),
        // чтобы дешифрование было симметричным.
        // То есть после цикла у нас (L=R_old, R=New), а мы записываем в выход (R, L).
        // Это эквивалентно swap(left, right) перед записью.

        std::swap(left, right);

        // Запись Left | Right
        std::copy(left.begin(), left.end(), dst.begin());
        std::copy(right.begin(), right.end(), dst.begin() + 8);
    }

    void DEAL::decryptBlock(ConstBytesSpan src, BytesSpan dst) {
        if (src.size() != 16 || dst.size() != 16) throw std::invalid_argument("DEAL block size is 16");

        Bytes left(src.begin(), src.begin() + 8);
        Bytes right(src.begin() + 8, src.begin() + 16);

        // Для дешифрования в сети Фейстеля:
        // Входные данные те же (L, R) - но так как мы сделали swap в конце encrypt,
        // то на вход decrypt приходят уже "правильные" половины.
        // Нам нужно просто применить ключи в обратном порядке.

        for (int i = 5; i >= 0; --i) {
             // Обратный раунд (абсолютно такой же, как прямой, только ключи наоборот)
             // L_i, R_i -> L_{i-1}, R_{i-1}
             // Но благодаря свойству Фейстеля:
             // L_new = R_old
             // R_new = L_old ^ f(R_old, K)

             Bytes temp = right;

             Bytes f_out(8);
             roundDes[i]->encryptBlock(right, f_out); // Функция раунда всегда одна и та же!

             for(int j=0; j<8; ++j) right[j] = left[j] ^ f_out[j];

             left = temp;
        }

        // Финальный свап (так же как в шифровании)
        std::swap(left, right);

        std::copy(left.begin(), left.end(), dst.begin());
        std::copy(right.begin(), right.end(), dst.begin() + 8);
    }
}