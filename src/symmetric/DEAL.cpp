#include "crypto/symmetric/DEAL.hpp"
#include <stdexcept>
#include <algorithm>
namespace crypto::symmetric {
    DEAL::DEAL(ConstBytesSpan key) {
        if (key.size() != 16) throw std::invalid_argument("DEAL-128 requires 16 bytes key");



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




            Bytes temp = right;

            Bytes f_out(8);
            roundDes[i]->encryptBlock(right, f_out);

            for(int j=0; j<8; ++j) right[j] = left[j] ^ f_out[j];

            left = temp;
        }




        std::swap(left, right);

        std::copy(left.begin(), left.end(), dst.begin());
        std::copy(right.begin(), right.end(), dst.begin() + 8);
    }
    void DEAL::decryptBlock(ConstBytesSpan src, BytesSpan dst) {
        if (src.size() != 16 || dst.size() != 16) throw std::invalid_argument("DEAL block size is 16");
        Bytes left(src.begin(), src.begin() + 8);
        Bytes right(src.begin() + 8, src.begin() + 16);




        for (int i = 5; i >= 0; --i) {





             Bytes temp = right;
             Bytes f_out(8);
             roundDes[i]->encryptBlock(right, f_out);
             for(int j=0; j<8; ++j) right[j] = left[j] ^ f_out[j];
             left = temp;
        }

        std::swap(left, right);
        std::copy(left.begin(), left.end(), dst.begin());
        std::copy(right.begin(), right.end(), dst.begin() + 8);
    }
}