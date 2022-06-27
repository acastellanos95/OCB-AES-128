#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include "aes_lib.h"

int main() {
    std::vector<unsigned char> in(320);
    std::vector<unsigned char> key{15,65,84,23,15,97,156,100,3,213,82,16,73,235,15,16};
    int nBlocks = 20;
    std::random_device rd;
    std::mt19937 mersenne_engine(rd());
    std::uniform_int_distribution<unsigned char> distribution(std::numeric_limits<unsigned char>::min(), std::numeric_limits<unsigned char>::max());
    auto gen = [&distribution, &mersenne_engine](){
        return distribution(mersenne_engine);
    };
    std::generate(in.begin(), in.end(), gen);

    std::vector<unsigned char> keySchedule(11);

    AES_128_Key_Expansion(key.data(), keySchedule.data());

    std::vector<unsigned char> outEncrypted(320);
    AES_ECB_encrypt(in.data(), outEncrypted.data(), 320, reinterpret_cast<const char *>(keySchedule.data()));

    std::vector<unsigned char>outDecrypted(320);
    AES_ECB_decrypt(outEncrypted.data(), outDecrypted.data(), 320, reinterpret_cast<const char *>(keySchedule.data()));
//    alignas(16) std::vector<__m128i> ptext(nBlocks);
//    size_t indexPtext = 0;
//    for(size_t i = 0; i < text.size(); i += 16){
//        ptext[indexPtext] = _mm_loadu_si128((__m128i*) &text[i]);
//        ++indexPtext;
//    }
//
//    AES_128_ECB_Encrypt(ptext.data(), nBlocks, keySchedule.data());
//    AES_128_ECB_Decrypt(ptext.data(), nBlocks, keySchedule.data());
//
//    alignas(16) std::vector<unsigned char> final(320);
//    size_t indexFinal = 0;
//    for(size_t i = 0; i < ptext.size(); ++i){
//        _mm_store_si128((__m128i *)&final[indexFinal], ptext[i]);
//        indexFinal += 16;
//    }

    std::cout << "text: (";
    for(size_t i = 0; i < in.size(); ++i){
        std::cout << (int) in[i] << ", "[i == (in.size() - 1)];
    }
    std::cout << ")\n";

    std::cout << "final deciphered text: (";
    for(size_t i = 0; i < outDecrypted.size(); ++i){
        std::cout << (int) outDecrypted[i] << ", "[i == (outDecrypted.size() - 1)];
    }
    std::cout << ")";

    return 0;
}
