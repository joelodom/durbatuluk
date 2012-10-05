//
// Durbatuluk is Copyright (c) 2012 Joel Odom
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "gtest/gtest.h"
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include "openssl_aes.h"

TEST(crypto_tests, test_gtest)
{
  EXPECT_TRUE(true) << "law of non-contradiction failed";
}

TEST(crypto_tests, test_digital_signature_good)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(2048, 65537, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay";

  std::string message("One ring to rule them all, one ring to find them");
  unsigned char* sigret = new unsigned char[rsa_size];
  unsigned int siglen;

  i = RSA_sign(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, &siglen, rsa);
  ASSERT_EQ(i, 1) << "RSA_sign failed";

  i = RSA_verify(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, siglen, rsa);
  EXPECT_EQ(i, 1) << "RSA_verify failed";

  RSA_free(rsa);
  delete[] sigret;
}

TEST(crypto_tests, test_digital_signature_bad)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(2048, 65537, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay";

  std::string message("One ring to rule them all, one ring to find them");
  unsigned char* sigret = new unsigned char[rsa_size];
  unsigned int siglen;

  i = RSA_sign(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, &siglen, rsa);
  ASSERT_EQ(i, 1) << "RSA_sign failed";

  message.append("One ring to bring them all and in the darkness bind them");

  i = RSA_verify(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, siglen, rsa);
  EXPECT_NE(i, 1) << "RSA_verify should have failed";

  RSA_free(rsa);
  delete[] sigret;
}

TEST(crypto_tests, test_encrypt_decrypt_session_key)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(2048, 65537, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay";

  std::string session_key("One ring to rule them all, one ring to find them");
  ASSERT_LT(session_key.size(), (size_t)(RSA_size(rsa) - 41))
    << "required condition for RSA_PKCS1_OAEP_PADDING";

  unsigned char* ciphertext = new unsigned char[rsa_size];
  i = RSA_public_encrypt(session_key.size(),
    (unsigned char *)session_key.c_str(),
    ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
  ASSERT_EQ(i, rsa_size) << "RSA_public_encrypt failed";

  unsigned char* plaintext = new unsigned char[rsa_size];
  i = RSA_private_decrypt(rsa_size, ciphertext,
     plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
  EXPECT_EQ((size_t)i, session_key.size()) << "RSA_private_decrypt failed";

  EXPECT_STREQ((const char*)plaintext, session_key.c_str());

  RSA_free(rsa);
  delete[] ciphertext;
  delete[] plaintext;
}

TEST(crypto_tests, DISABLED_test_aes_sample) // thanks Saju Pillai
{
  int i; // for etc.

  // "opaque" encryption, decryption ctx structures that libcrypto uses to
  // record status of enc/dec operations

  EVP_CIPHER_CTX en, de;

  // 8 bytes to salt the key_data during key generation. This is an example of
  // compiled in salt. We just read the bit pattern created by these two 4 byte
  // integers on the stack as 64 bits of contigous salt material -
  // ofcourse this only works if sizeof(int) >= 4

  unsigned int salt[] = {12345, 54321};
  const char *key_data = "joel key";
  int key_data_len = strlen(key_data);
  const char *input[] = {"a", "abcd", "this is a test", "this is a bigger test",
    "\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
    NULL};

  /* gen key and iv. init the cipher ctx object */
  i = aes_init((unsigned char *)key_data, key_data_len,
    (unsigned char *)&salt, &en, &de);
  ASSERT_EQ(i, 0) << "couldn't initialize AES cipher";

  /* encrypt and decrypt each input string and compare with the original */
  for (i = 0; input[i]; i++)
  {
    int len;

    // The enc/dec functions deal with binary data and not C strings. strlen()
    // will return length of the string without counting the '\0' string marker.
    // We always pass in the marker byte to the encrypt/decrypt functions so
    // that after decryption we end up with a legal C string

    unsigned char *ciphertext
      = aes_encrypt(&en, (unsigned char *)input[i], &len);
    ASSERT_TRUE(ciphertext != nullptr);

    char *plaintext = (char *)aes_decrypt(&de, ciphertext, &len);
    ASSERT_TRUE(plaintext != nullptr);

    EXPECT_STREQ(plaintext, input[i]);

    free(ciphertext);
    free(plaintext);
  }

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);
}
