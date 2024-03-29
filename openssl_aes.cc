// Most of this code is borrowed from Saju Pillai.  Do not assert copyright.

/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code.

  Saju Pillai (saju.pillai@gmail.com)
**/

#include "openssl_aes.h"

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];

  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  if (EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv) == 0)
    return -1;
  EVP_CIPHER_CTX_init(d_ctx);
  if (EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv) == 0)
    return -1;

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  if (EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL) == 0)
    return nullptr;

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  if (EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len) == 0)
    return nullptr;

  /* update ciphertext with the final remaining bytes */
  if (EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len) == 0)
    return nullptr;

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

  if (EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL) == 0)
    return nullptr;

  if (EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len) == 0)
    return nullptr;

  if (EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len) == 0)
    return nullptr;

  *len = p_len + f_len;
  return plaintext;
}
