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
  __m128i *Key_Schedule = (__m128i *) key;
  temp1 = _mm_loadu_si128((__m128i *) userkey);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
}

void AES_128_Key_Expansion_Two_Rounds(const unsigned char *userkey,
                                      unsigned char *key) {
  __m128i temp1, temp2;
  __m128i *Key_Schedule = (__m128i *) key;
  temp1 = _mm_loadu_si128((__m128i *) userkey);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128 (temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
}

int AES_set_decrypt_key_Ten_Rounds(const unsigned char *userKey,
                                   AES_KEY *key) {
  int i, nr;;
  AES_KEY temp_key;
  __m128i *Key_Schedule = (__m128i *) key->KEY;
  __m128i *Temp_Key_Schedule = (__m128i *) temp_key.KEY;
  AES_128_Key_Expansion_Ten_Rounds(userKey, &temp_key);
  temp_key.nr = 10;
  nr = temp_key.nr;
  key->nr = nr;
  Key_Schedule[nr] = Temp_Key_Schedule[0];
  Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
  Key_Schedule[nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
  Key_Schedule[nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
  Key_Schedule[nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
  Key_Schedule[nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
  Key_Schedule[nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
  Key_Schedule[nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
  Key_Schedule[nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
  Key_Schedule[nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
  Key_Schedule[0] = Temp_Key_Schedule[nr];
  return 0;
}

int AES_set_decrypt_key_Two_Rounds(const unsigned char *userKey,
                                   AES_KEY *key) {
  int i, nr;;
  AES_KEY temp_key;
  __m128i *Key_Schedule = (__m128i *) key->KEY;
  __m128i *Temp_Key_Schedule = (__m128i *) temp_key.KEY;
  AES_128_Key_Expansion_Two_Rounds(userKey, &temp_key);
  temp_key.nr = 2;
  nr = temp_key.nr;
  key->nr = nr;
  Key_Schedule[nr] = Temp_Key_Schedule[0];
  Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
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
ALIGN16 uint8_t GOCB_TEST_ASSOCIATED_DATA[] = {0x64, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                               0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                               0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                               0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                               0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                               0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                                               0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                               0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x11};

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
  uint8_t *DECRYPTEDTEXT;
  uint8_t *CIPHER_KEY1;
  uint8_t *CIPHER_KEY2;
  uint8_t *NONCE;
  CIPHER_KEY1 = AES_128_TEST_KEY1;
  CIPHER_KEY2 = AES_128_TEST_KEY2;
  NONCE = AES_128_TEST_NONCE;
  PLAINTEXT = GOCB_TEST_PLAINTEXT;
  ASSOCIATEDDATA = GOCB_TEST_ASSOCIATED_DATA;
  CIPHERTEXT = (uint8_t *) malloc(length_plaintext_in_bytes);
  DECRYPTEDTEXT = (uint8_t *) malloc(length_plaintext_in_bytes);
  TAG = (uint8_t *) malloc(16);
  AES_128_Key_Expansion_Ten_Rounds(CIPHER_KEY1, &key1);
  key1.nr = 10;
  AES_set_decrypt_key_Ten_Rounds(CIPHER_KEY1, &decrypt_key1);
  AES_128_Key_Expansion_Two_Rounds(CIPHER_KEY2, &key2);
  key2.nr = 2;
  AES_set_decrypt_key_Two_Rounds(CIPHER_KEY2, &decrypt_key2);

  /* ------------------------------------ Initializing L ------------------------------------ */
  // Initialize L with nonce
  __m128i L = _mm_loadu_si128((__m128i *) NONCE);
  // normal cipher nonce (10 rounds)
  L = _mm_xor_si128(L, ((__m128i *) key1.KEY)[0]);
  int j;
  for (j = 1; j < 10; j++) {
    L = _mm_aesenc_si128(L, ((__m128i *) key1.KEY)[j]);
  }
  L = _mm_aesenclast_si128(L, ((__m128i *) key1.KEY)[j]);

  /* ------------------------------------ Hashing ------------------------------------ */
  // Assuming complete blocks only
  int complete_blocks = (length_associated_data_in_bytes - length_associated_data_in_bytes % 16) / 16;
  int indexBlock;
  int ctr = 1;
  __m128i S = _mm_set_epi32(0, 0, 0, 0);
  for (indexBlock = 0; indexBlock < complete_blocks; indexBlock++) {
    // Load A_i 16 * 16 bits of A
    __m128i A_i, U_i, V_i;
    A_i = _mm_loadu_si128(&((__m128i *) ASSOCIATEDDATA)[indexBlock]);
    // Create alpha and delta5 with key 2
    __m128i alpha, delta5;
    alpha = _mm_set_epi32(ctr, ctr, ctr, ctr);
    alpha = _mm_xor_si128(alpha, L);
    // cipher alpha (2 rounds)
    alpha = _mm_xor_si128(alpha, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      alpha = _mm_aesenc_si128(alpha, ((__m128i *) key2.KEY)[j]);
    }
    delta5 = alpha;
    ctr += 5;

    // Calculate U_i
    U_i = _mm_xor_si128(A_i, delta5);

    // Cipher U_i with two rounds AES. Calculate V_i
    V_i = _mm_xor_si128(U_i, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      V_i = _mm_aesenc_si128(V_i, ((__m128i *) key2.KEY)[j]);
    }

    // Calculate S
    S = _mm_xor_si128(S, V_i);
  }

  /* ------------------------------------ Encryption ------------------------------------ */
  // Assuming complete blocks only
  complete_blocks = (length_plaintext_in_bytes - length_plaintext_in_bytes % 16) / 16;
  ctr = 1;
  __m128i M_xor = _mm_set_epi32(0, 0, 0, 0);
  for (indexBlock = 0; indexBlock < complete_blocks; indexBlock++) {
    // Load M_i 16 * 16 bits of M
    __m128i M_i, X_i, Y_i, C_i;
    M_i = _mm_loadu_si128(&((__m128i *) PLAINTEXT)[indexBlock]);

    // Create alpha and delta1_i with key 2
    __m128i alpha, delta1;
    alpha = _mm_set_epi32(ctr, ctr, ctr, ctr);
    alpha = _mm_xor_si128(alpha, L);
    // cipher alpha (2 rounds)
    alpha = _mm_xor_si128(alpha, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      alpha = _mm_aesenc_si128(alpha, ((__m128i *) key2.KEY)[j]);
    }
    delta1 = alpha;
    ctr++;

    // Calculate M_xor
    M_xor = _mm_xor_si128(M_xor, M_i);

    // Calculate X_i
    X_i = _mm_xor_si128(M_i, delta1);

    // Cipher X_i to Y_i
    Y_i = _mm_xor_si128(X_i, ((__m128i *) key1.KEY)[0]);
    for (j = 1; j < 10; j++) {
      Y_i = _mm_aesenc_si128(Y_i, ((__m128i *) key1.KEY)[j]);
    }
    Y_i = _mm_aesenclast_si128(Y_i, ((__m128i *) key1.KEY)[j]);

    // Calculate C_i
    C_i = _mm_xor_si128(Y_i, delta1);
    _mm_storeu_si128(&((__m128i*)CIPHERTEXT)[indexBlock],C_i);
  }

  // Create alpha and delta3_l with key 2
  __m128i alpha, delta3_l;
  alpha = _mm_set_epi32(3*complete_blocks + 1, 3*complete_blocks + 1, 3*complete_blocks + 1, 3*complete_blocks + 1);
  alpha = _mm_xor_si128(alpha, L);
  // cipher alpha (2 rounds)
  alpha = _mm_xor_si128(alpha, ((__m128i *) key2.KEY)[0]);
  for (j = 1; j <= 2; j++) {
    alpha = _mm_aesenc_si128(alpha, ((__m128i *) key2.KEY)[j]);
  }
  delta3_l = alpha;

  // Calculate X_xor
  __m128i X_xor = _mm_xor_si128(M_xor, delta3_l);

  // Calculate Y_xor ciphering X_xor (two rounds)
  __m128i Y_xor = _mm_xor_si128(X_xor, ((__m128i *) key2.KEY)[0]);
  for (j = 1; j <= 2; j++) {
    Y_xor = _mm_aesenc_si128(Y_xor, ((__m128i *) key2.KEY)[j]);
  }

  // Calculate tag
  __m128i T;
  T = _mm_xor_si128(S, delta3_l);
  T = _mm_xor_si128(T, Y_xor);

  _mm_storeu_si128 (&((__m128i*)TAG)[0],T);

  // Print encrypt part
  printf("The Cipher Key 1:\n");
  print_m128i_with_string("", ((__m128i *) CIPHER_KEY1)[0]);
  printf("The Cipher Key 2:\n");
  print_m128i_with_string("", ((__m128i *) CIPHER_KEY2)[0]);
  printf("The Key 1 Schedule:\n");
  int i;
  for (i = 0; i < key1.nr; i++)
    print_m128i_with_string("", ((__m128i *) key1.KEY)[i]);
  printf("The Key 2 Schedule:\n");
  for (i = 0; i < key2.nr; i++)
    print_m128i_with_string("", ((__m128i *) key2.KEY)[i]);
  printf("The decrypt Key 1 Schedule:\n");
  for (i = 0; i < key1.nr; i++)
    print_m128i_with_string("", ((__m128i *) decrypt_key1.KEY)[i]);
  printf("The decrypt Key 2 Schedule:\n");
  for (i = 0; i < key2.nr; i++)
    print_m128i_with_string("", ((__m128i *) decrypt_key2.KEY)[i]);
  printf("The PLAINTEXT:\n");
  for (i = 0; i < length_plaintext_in_bytes / 16; i++)
    print_m128i_with_string("", ((__m128i *) PLAINTEXT)[i]);
  if (length_plaintext_in_bytes % 16)
    print_m128i_with_string_short("", ((__m128i *) PLAINTEXT)[i], length_plaintext_in_bytes % 16);
  printf("The ASSOCIATEDDATA:\n");
  for (i = 0; i < length_associated_data_in_bytes / 16; i++)
    print_m128i_with_string("", ((__m128i *) ASSOCIATEDDATA)[i]);
  if (length_associated_data_in_bytes % 16)
    print_m128i_with_string_short("", ((__m128i *) ASSOCIATEDDATA)[i], length_associated_data_in_bytes % 16);
  printf("\n\nThe CIPHERTEXT:\n");
  for (i = 0; i < length_plaintext_in_bytes / 16; i++)
    print_m128i_with_string("", ((__m128i *) CIPHERTEXT)[i]);
  if (length_plaintext_in_bytes % 16)
    print_m128i_with_string_short("", ((__m128i *) CIPHERTEXT)[i], length_plaintext_in_bytes % 16);
  printf("TAG:\n");
  print_m128i_with_string("", ((__m128i *) TAG)[0]);

  /* ------------------------------------ Decryption part ------------------------------------ */
  /* ------------------------------------ Hashing ------------------------------------ */
  // Assuming complete blocks only
  complete_blocks = (length_associated_data_in_bytes - length_associated_data_in_bytes % 16) / 16;
  ctr = 1;
  S = _mm_set_epi32(0, 0, 0, 0);
  for (indexBlock = 0; indexBlock < complete_blocks; indexBlock++) {
    // Load A_i 16 * 16 bits of A
    __m128i A_i, U_i, V_i;
    A_i = _mm_loadu_si128(&((__m128i *) ASSOCIATEDDATA)[indexBlock]);
    // Create alpha and delta5 with key 2
    __m128i alpha, delta5;
    alpha = _mm_set_epi32(ctr, ctr, ctr, ctr);
    alpha = _mm_xor_si128(alpha, L);
    // cipher alpha (2 rounds)
    alpha = _mm_xor_si128(alpha, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      alpha = _mm_aesenc_si128(alpha, ((__m128i *) key2.KEY)[j]);
    }
    delta5 = alpha;
    ctr += 5;

    // Calculate U_i
    U_i = _mm_xor_si128(A_i, delta5);

    // Cipher U_i with two rounds AES. Calculate V_i
    V_i = _mm_xor_si128(U_i, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      V_i = _mm_aesenc_si128(V_i, ((__m128i *) key2.KEY)[j]);
    }

    // Calculate S
    S = _mm_xor_si128(S, V_i);
  }

  /* ------------------------------------ Decryption ------------------------------------ */
  // Assuming complete blocks only
  complete_blocks = (length_plaintext_in_bytes - length_plaintext_in_bytes % 16) / 16;
  ctr = 1;
  M_xor = _mm_set_epi32(0, 0, 0, 0);
  for (indexBlock = 0; indexBlock < complete_blocks; indexBlock++) {
    // Load M_i 16 * 16 bits of M
    __m128i M_i, X_i, Y_i, C_i;
    C_i = _mm_loadu_si128(&((__m128i *) CIPHERTEXT)[indexBlock]);
    // Create alpha and delta1_i with key 2
    __m128i delta1;
    alpha = _mm_set_epi32(ctr, ctr, ctr, ctr);
    alpha = _mm_xor_si128(alpha, L);
    // cipher alpha (2 rounds)
    alpha = _mm_xor_si128(alpha, ((__m128i *) key2.KEY)[0]);
    for (j = 1; j <= 2; j++) {
      alpha = _mm_aesenc_si128(alpha, ((__m128i *) key2.KEY)[j]);
    }
    delta1 = alpha;
    ctr++;

    // Calculate Y_i
    Y_i = _mm_xor_si128(C_i, delta1);

    // Decipher Y_i to X_i
    X_i = _mm_xor_si128(Y_i, ((__m128i *) decrypt_key1.KEY)[0]);
    for (j = 1; j < 10; j++) {
      X_i = _mm_aesdec_si128(X_i, ((__m128i *) decrypt_key1.KEY)[j]);
    }
    X_i = _mm_aesdeclast_si128(X_i, ((__m128i *) decrypt_key1.KEY)[j]);

    // Calculate M_i
    M_i = _mm_xor_si128(X_i, delta1);
    _mm_storeu_si128(&((__m128i*)DECRYPTEDTEXT)[indexBlock],M_i);

    // Calculate M_xor
    M_xor = _mm_xor_si128(M_xor, M_i);
  }

  // Calculate X_xor
  X_xor = _mm_xor_si128(M_xor, delta3_l);

  // Calculate Y_xor ciphering X_xor (two rounds)
  Y_xor = _mm_xor_si128(X_xor, ((__m128i *) key2.KEY)[0]);
  for (j = 1; j <= 2; j++) {
    Y_xor = _mm_aesenc_si128(Y_xor, ((__m128i *) key2.KEY)[j]);
  }

  // Calculate tag
  T = _mm_xor_si128(S, delta3_l);
  T = _mm_xor_si128(T, Y_xor);

  _mm_storeu_si128 (&((__m128i*)TAG)[0],T);

  printf("\n\nThe DECIPHERTEXT:\n");
  for (i = 0; i < length_plaintext_in_bytes / 16; i++)
    print_m128i_with_string("", ((__m128i *) DECRYPTEDTEXT)[i]);
  if (length_plaintext_in_bytes % 16)
    print_m128i_with_string_short("", ((__m128i *) DECRYPTEDTEXT)[i], length_plaintext_in_bytes % 16);
  printf("TAG:\n");
  print_m128i_with_string("", ((__m128i *) TAG)[0]);
}
