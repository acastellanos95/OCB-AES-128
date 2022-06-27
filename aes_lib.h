//
// Created by andre on 27/06/2022.
//

#ifndef PROJECT_AES_LIB_H
#define PROJECT_AES_LIB_H

#include<wmmintrin.h>
#include<xmmintrin.h>
#include<smmintrin.h>
#include<emmintrin.h>
#include<tmmintrin.h>
#include<malloc.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <stdint.h>



inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

void AES_128_Key_Expansion (const unsigned char *userkey, unsigned char *key) {
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

static inline void AES_128_set_decrypt_keys(const __m128i *roundkey, __m128i *dkey){
    __m128i *tmp_dkey =(__m128i*)dkey;

    dkey[10]= roundkey[0];
    dkey[9] = _mm_aesimc_si128(roundkey[1]);
    dkey[8] = _mm_aesimc_si128(roundkey[2]);
    dkey[7] = _mm_aesimc_si128(roundkey[3]);
    dkey[6] = _mm_aesimc_si128(roundkey[4]);
    dkey[5] = _mm_aesimc_si128(roundkey[5]);
    dkey[4] = _mm_aesimc_si128(roundkey[6]);
    dkey[3] = _mm_aesimc_si128(roundkey[7]);
    dkey[2] = _mm_aesimc_si128(roundkey[8]);
    dkey[1] = _mm_aesimc_si128(roundkey[9]);
    dkey[0] = roundkey[10];
}

__m128i  AES_128_Encrypt(__m128i ptext, __m128i *keySchedule){
    int j;
    __m128i tmp;

    tmp = _mm_xor_si128 (ptext,keySchedule[0]);
    for(j=1; j <10; j++){
        tmp = _mm_aesenc_si128 (tmp,keySchedule[j]);
    }
    tmp = _mm_aesenclast_si128 (tmp,keySchedule[j]);
    /*_mm_storeu_si128 (&((__m128i*)out)[0],tmp);*/
    return(tmp);

}

__m128i AES_128_Decrypt(__m128i ptext, __m128i *keySchedule)
{      int j;
    __m128i tmp;

    tmp = _mm_xor_si128 (ptext,keySchedule[0]);
    for(j=1; j <10; j++){
        tmp = _mm_aesdec_si128 (tmp,keySchedule[j]);
    }
    tmp = _mm_aesdeclast_si128 (tmp,keySchedule[j]);
    /*_mm_storeu_si128 (&((__m128i*)out)[0],tmp);*/
    return(tmp);

}

void AES_128_ECB_Encrypt(__m128i *text, int nBlocks, __m128i *keySchedule)
{   int i,j;
    // __m128i tmp;

    for(i=0; i< nBlocks; i++)
        text[i] = _mm_xor_si128(text[i], keySchedule[0]);

    for(j=1; j<10 ; j++)
        for(i=0; i< nBlocks; i++)
            text[i] = _mm_aesenc_si128 (text[i],keySchedule[j]);

    for(i=0; i< nBlocks; i++)
        text[i] = _mm_aesenclast_si128 (text[i],keySchedule[j]);
}

void AES_128_ECB_Decrypt(__m128i *text, int nBlocks, __m128i *keySchedule)
{   int i,j;
    // __m128i tmp;

    for(i=0; i< nBlocks; i++)
        text[i] = _mm_xor_si128(text[i], keySchedule[0]);

    for(j=1; j<10 ; j++) {
        for(i=0; i< nBlocks; i++) {
            text[i] = _mm_aesdec_si128 (text[i],keySchedule[j]);
        }
    }

    for(i=0; i< nBlocks; i++) {
        text[i] = _mm_aesdeclast_si128 (text[i],keySchedule[j]);
    }
}

void AES_ECB_encrypt(const unsigned char *in, //pointer to the PLAINTEXT
                            unsigned char *out, //pointer to the CIPHERTEXT buffer
                            unsigned long length, //text length in bytes
                            const char *key) //pointer to the expanded key schedule
{
    int number_of_rounds = 10;
    __m128i tmp;
    int i,j;
    if(length%16)
        length = length/16+1;
    else
        length = length/16;

    for(i=0; i < length; i++){
        tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
        tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++){
            tmp = _mm_aesenc_si128 (tmp,((__m128i*)key)[j]);
        }
        tmp = _mm_aesenclast_si128 (tmp,((__m128i*)key)[j]);
        _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
    }
}

void AES_ECB_decrypt(const unsigned char *in, //pointer to the PLAINTEXT
                     unsigned char *out, //pointer to the CIPHERTEXT buffer
                     unsigned long length, //text length in bytes
                     const char *key) //pointer to the expanded key schedule
{
    int number_of_rounds = 10;
    __m128i tmp;
    int i,j;
    if(length%16)
        length = length/16+1;
    else
        length = length/16;

    for(i=0; i < length; i++){
        tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
        tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++){
            tmp = _mm_aesdec_si128 (tmp,((__m128i*)key)[j]);
        }
        tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)key)[j]);
        _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
    }
}

static inline void gfmulby2(__m128i a,__m128i* res){
    *res = _mm_srai_epi32(a,31);
    *res = _mm_shuffle_epi32(*res,0x57);
    *res = _mm_and_si128(*res,_mm_set_epi32(0x00,0x01,0x00,0x87));
    *res = _mm_xor_si128(*res,_mm_slli_epi64(a,0x01));
}

static inline void gfmulby2inv(__m128i a,__m128i* res){
    *res = _mm_srli_epi32(a,31);
    *res = _mm_shuffle_epi32(*res,0x57);
    *res = _mm_andnot_si128(*res,_mm_set_epi32(0x00,0x00,0x80000000,0x43));
    *res = _mm_xor_si128(*res,_mm_slli_epi64(a,0x01));
}

static inline void gfmulby3(__m128i a,__m128i* res){
    __m128i x2;

    gfmulby2(a,&x2);
    *res = _mm_xor_si128(x2,a);
}

static inline void gfmulby5(__m128i a,__m128i* res){
    __m128i x2,x4;
    gfmulby2(a,&x2);
    gfmulby2(x2,&x4);
    *res = _mm_xor_si128(x4,a);
}

///**********************************/
void print_m128i_with_string(char* string,__m128i data) {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<16; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
}

void print_byte_array(unsigned char *data,int len) {
    int i;
    printf("\n");
    for (i=0; i<len;i++){
        if(i%16==0){
            printf("\n");
            printf("%d ",i);
        }
        printf("%02x",data[i]);

    }
}

void rand_gen(unsigned char *ax, int len)
{
    int  i;
    srand ( time(NULL) );
    for(i=0;i<len;i++){
        ax[i] = rand();
    }
}

static inline unsigned ntz(unsigned x) {
    static const unsigned char tz_table[32] =
            { 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
              31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
    return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
}


#endif //PROJECT_AES_LIB_H
