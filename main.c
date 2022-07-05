//
// Created by andre on 7/3/22.
//
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>


# define ALIGN16 __attribute__ ( (aligned (16)))
# define ALIGN32 __attribute__ ( (aligned (32)))

typedef struct KEY_SCHEDULE {
  ALIGN16 unsigned char KEY[16 * 15];
  unsigned int nr;
} AES_KEY;

__m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32 (temp2, 0xff);
  temp3 = _mm_slli_si128 (temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128 (temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

void AES_128_Key_Expansion_Ten_Rounds(const unsigned char *userkey,
                           unsigned char *key) {
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

void AES_128_Key_Expansion_Two_Rounds(const unsigned char *userkey,
                                      unsigned char *key) {
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
}

int AES_set_decrypt_key_Ten_Rounds (const unsigned char *userKey,
                         AES_KEY *key)
{
  int i,nr;;
  AES_KEY temp_key;
  __m128i *Key_Schedule = (__m128i*)key->KEY;
  __m128i *Temp_Key_Schedule = (__m128i*)temp_key.KEY;
  AES_128_Key_Expansion_Ten_Rounds(userKey, &temp_key);
  temp_key.nr = 10;
  nr = temp_key.nr;
  key->nr = nr;
  Key_Schedule[nr] = Temp_Key_Schedule[0];
  Key_Schedule[nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
  Key_Schedule[nr-2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
  Key_Schedule[nr-3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
  Key_Schedule[nr-4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
  Key_Schedule[nr-5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
  Key_Schedule[nr-6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
  Key_Schedule[nr-7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
  Key_Schedule[nr-8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
  Key_Schedule[nr-9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
  Key_Schedule[0] = Temp_Key_Schedule[nr];
  return 0;
}

int AES_set_decrypt_key_Two_Rounds (const unsigned char *userKey,
                                    AES_KEY *key)
{
  int i,nr;;
  AES_KEY temp_key;
  __m128i *Key_Schedule = (__m128i*)key->KEY;
  __m128i *Temp_Key_Schedule = (__m128i*)temp_key.KEY;
  AES_128_Key_Expansion_Two_Rounds(userKey, &temp_key);
  temp_key.nr = 2;
  nr = temp_key.nr;
  key->nr = nr;
  Key_Schedule[nr] = Temp_Key_Schedule[0];
  Key_Schedule[nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
  Key_Schedule[0] = Temp_Key_Schedule[nr];
  return 0;
}

ALIGN16 uint8_t AES_128_TEST_KEY1[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
ALIGN16 uint8_t AES_128_TEST_KEY2[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x34};
ALIGN16 uint8_t AES_128_TEST_NONCE[] = {0x2b, 0x71, 0x15, 0x15, 0x28, 0xae, 0xd2, 0xa6,
                                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x34};

ALIGN16 uint8_t GOCB_TEST_PLAINTEXT[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
ALIGN16 uint8_t GOCB_TEST_ASSOCIATED_DATA[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
/*****************************************************************************/
void print_m128i_with_string(char *string, __m128i data) {
  unsigned char *pointer = (unsigned char *) &data;
  int i;
  printf("%-40s[0x", string);
  for (i = 0; i < 16; i++)
    printf("%02x", pointer[i]);
  printf("]\n");
}
void print_m128i_with_string_short(char *string, __m128i data, int length) {
  unsigned char *pointer = (unsigned char *) &data;
  int i;
  printf("%-40s[0x", string);
  for (i = 0; i < length; i++)
    printf("%02x", pointer[i]);
  printf("]\n");
}
/*****************************************************************************/
int main() {
  int length_key_in_bits = 128;
  int length_plaintext_in_bytes = 64;
  int length_associated_data_in_bytes = 64;
  AES_KEY key1;
  AES_KEY decrypt_key1;
  AES_KEY key2;
  AES_KEY decrypt_key2;
  uint8_t *PLAINTEXT;
  uint8_t *ASSOCIATEDDATA;
  uint8_t *TAG;
  uint8_t *CIPHERTEXT;
//  uint8_t *DECRYPTEDTEXT;
  uint8_t *CIPHER_KEY1;
  uint8_t *CIPHER_KEY2;
  uint8_t *NONCE;
  CIPHER_KEY1 = AES_128_TEST_KEY1;
  CIPHER_KEY2 = AES_128_TEST_KEY2;
  NONCE = AES_128_TEST_NONCE;
  PLAINTEXT = GOCB_TEST_PLAINTEXT;
  ASSOCIATEDDATA = GOCB_TEST_ASSOCIATED_DATA;
  CIPHERTEXT = (uint8_t *) malloc(length_plaintext_in_bytes);
  TAG = (uint8_t *) malloc(length_associated_data_in_bytes);
  AES_128_Key_Expansion_Ten_Rounds(CIPHER_KEY1, &key1);
  key1.nr = 10;
  AES_set_decrypt_key_Ten_Rounds(CIPHER_KEY1, &decrypt_key1);
  AES_128_Key_Expansion_Two_Rounds(CIPHER_KEY2, &key2);
  key1.nr = 2;
  AES_set_decrypt_key_Two_Rounds(CIPHER_KEY2, &decrypt_key2);

  /* ------------------------------------ Hashing ------------------------------------ */
  int complete_blocks = (length_associated_data_in_bytes - length_associated_data_in_bytes % 16)/16;
  int not_complete_bytes = length_associated_data_in_bytes % 16;
  int indexBlock;
  for(indexBlock = 1; indexBlock <= complete_blocks; indexBlock += 16){
    __m128i A_i;
    A_i = _mm_loadu_si128 (&((__m128i*)ASSOCIATEDDATA)[indexBlock-1]);
  }
  // Initialize ctr
  int ctr = 0;
  // Initialize L with nonce
  __m128i L = _mm_loadu_si128((__m128i*) NONCE);
  // normal cipher nonce (10 rounds)
  L = _mm_xor_si128 (L,((__m128i*)key1.KEY)[0]);
  int j;
  for(j=1; j < 10; j++){
    L = _mm_aesenc_si128 (L,((__m128i*)key1.KEY)[j]);
  }
  L = _mm_aesenclast_si128 (L,((__m128i*)key1.KEY)[j]);

  // Create alpha and delta with key 2
  __m128i alpha, delta;
  ctr++;
  alpha = _mm_set_epi32(ctr,ctr,ctr,ctr);
  alpha = _mm_xor_si128 (alpha,L);
  // cipher alpha (2 rounds)
  alpha = _mm_xor_si128 (alpha,((__m128i*)key2.KEY)[0]);
  for(j=1; j < 2; j++){
    alpha = _mm_aesenc_si128 (alpha,((__m128i*)key2.KEY)[j]);
  }
  delta = _mm_aesenclast_si128 (alpha,((__m128i*)key2.KEY)[j]);

  AES_ECB_encrypt(PLAINTEXT,
                  CIPHERTEXT,
                  LENGTH,
                  key.KEY,
                  key.nr);
  AES_ECB_decrypt(CIPHERTEXT,
                  DECRYPTEDTEXT,
                  LENGTH,
                  decrypt_key.KEY,
                  decrypt_key.nr);
  printf("%s\n", STR);
  printf("The Cipher Key:\n");
  print_m128i_with_string("", ((__m128i *) CIPHER_KEY)[0]);
  if (key_length > 128)
    print_m128i_with_string_short("", ((__m128i *) CIPHER_KEY)[1], (key_length / 8) - 16);
  printf("The Key Schedule:\n");
  for (i = 0; i < key.nr; i++)
    print_m128i_with_string("", ((__m128i *) key.KEY)[i]);
  printf("The PLAINTEXT:\n");
  for (i = 0; i < LENGTH / 16; i++)
    print_m128i_with_string("", ((__m128i *) PLAINTEXT)[i]);
  if (LENGTH % 16)
    print_m128i_with_string_short("", ((__m128i *) PLAINTEXT)[i], LENGTH % 16);
  printf("\n\nThe CIPHERTEXT:\n");
  for (i = 0; i < LENGTH / 16; i++)
    print_m128i_with_string("", ((__m128i *) CIPHERTEXT)[i]);
  if (LENGTH % 16)
    print_m128i_with_string_short("", ((__m128i *) CIPHERTEXT)[i], LENGTH % 16);
  for (i = 0; i < LENGTH; i++) {
    if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i % (16 * 4)]) {
      printf("The CIPHERTEXT is not equal to the EXPECTED CIHERTEXT.\n\n");
      return 1;
    }
  }
  printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT.\n\n");
  for (i = 0; i < LENGTH; i++) {
    if (DECRYPTEDTEXT[i] != PLAINTEXT[i % (16 * 4)]) {
      printf("The DECRYPTED TEXT isn't equal to the original PLAINTEXT!");
      printf("\n\n");
      return 1;
    }
  }
  printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n");
}
