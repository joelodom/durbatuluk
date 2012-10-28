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

#include "crypto.h"
#include "gtest/gtest.h"
#include "openssl_aes.h"
#include <openssl/engine.h>

TEST(crypto_test, test_rsa_f4)
{
  EXPECT_EQ(RSA_F4, 65537);
}

TEST(crypto_tests, test_rsa_check_key)
{
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  EXPECT_EQ(RSA_check_key(rsa), 1);

  // flip a bit
  if (BN_is_bit_set(rsa->n, 3))
    BN_clear_bit(rsa->n, 3);
  else
    BN_set_bit(rsa->n, 3);

  EXPECT_EQ(RSA_check_key(rsa), 0);

  RSA_free(rsa);
}

TEST(crypto_tests, test_digital_signature_good)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay if RSA_BITS ever changes";

  std::string message("One ring to rule them all, one ring to find them");
  unsigned char sigret[rsa_size];
  unsigned int siglen;

  i = RSA_sign(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, &siglen, rsa);
  ASSERT_EQ(i, 1) << "RSA_sign failed";

  i = RSA_verify(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, siglen, rsa);
  EXPECT_EQ(i, 1) << "RSA_verify failed";

  RSA_free(rsa);
}

TEST(crypto_tests, test_digital_signature_bad)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay";

  std::string message("One ring to rule them all, one ring to find them");
  unsigned char sigret[rsa_size];
  unsigned int siglen;

  i = RSA_sign(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, &siglen, rsa);
  ASSERT_EQ(i, 1) << "RSA_sign failed";

  message.append("One ring to bring them all and in the darkness bind them");

  i = RSA_verify(NID_sha1, (const unsigned char*)message.c_str(),
    message.size(), sigret, siglen, rsa);
  EXPECT_NE(i, 1) << "RSA_verify should have failed";

  RSA_free(rsa);
}

TEST(crypto_tests, test_encrypt_decrypt_session_key)
{
  int i; // for checking return values

  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  i = RSA_check_key(rsa);
  ASSERT_EQ(i, 1) << "RSA_check_key failed";

  int rsa_size = RSA_size(rsa);
  EXPECT_EQ(rsa_size, 256) << "this may be okay";

  std::string session_key("One ring to rule them all, one ring to find them");
  ASSERT_LT(session_key.size(), (size_t)(RSA_size(rsa) - 41))
    << "required condition for RSA_PKCS1_OAEP_PADDING";

  unsigned char ciphertext[rsa_size];
  i = RSA_public_encrypt(session_key.length(),
    (unsigned char *)session_key.c_str(),
    ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
  ASSERT_EQ(i, rsa_size) << "RSA_public_encrypt failed";

  unsigned char plaintext[rsa_size];
  i = RSA_private_decrypt(rsa_size, ciphertext,
     plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
  EXPECT_EQ((size_t)i, session_key.length()) << "RSA_private_decrypt failed";

  EXPECT_TRUE(
    (memcmp(plaintext, session_key.c_str(), session_key.length()) == 0));

  RSA_free(rsa);
}

TEST(crypto_tests, test_bignum_conversion)
{
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  int len = BN_num_bytes(rsa->n);
  unsigned char buf[len];
  len = BN_bn2bin(rsa->n, buf);

  BIGNUM* bn = BN_bin2bn(buf, len, nullptr);
  ASSERT_NE(bn, nullptr);
  EXPECT_EQ(BN_cmp(rsa->n, bn), 0);

  BN_free(bn);
  RSA_free(rsa);
}

TEST(crypto_tests, test_aes_sample) // thanks Saju Pillai
{
  int i; // for etc.

  // "opaque" encryption, decryption ctx structures that libcrypto uses to
  // record status of enc/dec operations

  EVP_CIPHER_CTX en, de;

  // 8 bytes to salt the key_data during key generation. This is an example of
  // compiled in salt. We just read the bit pattern created by these two 4 byte
  // integers on the stack as 64 bits of contigous salt material -
  // of course this only works if sizeof(int) >= 4

  unsigned int salt[] = {12345, 54321};
  const char *key_data = "joel key";
  int key_data_len = strlen(key_data);
  const char* input[] = {"a", "abcd", "this is a test", "this is a bigger test",
    "\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
    NULL};

  /* gen key and iv. init the cipher ctx object */
  i = aes_init((unsigned char *)key_data, key_data_len,
    (unsigned char *)&salt, &en, &de);
  ASSERT_EQ(i, 0) << "couldn't initialize AES cipher";

  /* encrypt and decrypt each input string and compare with the original */
  for (i = 0; input[i]; i++)
  {
    int len = strlen(input[i])+1;

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

TEST(crypto_tests, test_extract_import_public_rsa_key)
{
  // generate a key
  RSA* rsa_before = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa_before != nullptr);

  // extract the public key
  RSAKey extracted;
  ASSERT_TRUE(Crypto::ExtractPublicRSAKey(rsa_before, extracted));

  // import the public key
  RSA* rsa_after = RSA_new();
  ASSERT_TRUE(rsa_after != nullptr);
  ASSERT_TRUE(Crypto::ImportRSAKey(extracted, rsa_after));

  // check the imported key
  EXPECT_EQ(BN_cmp(rsa_before->n, rsa_after->n), 0);
  EXPECT_EQ(BN_cmp(rsa_before->e, rsa_after->e), 0);
  EXPECT_EQ(rsa_after->d, nullptr);
  EXPECT_EQ(rsa_after->p, nullptr);
  EXPECT_EQ(rsa_after->q, nullptr);
  EXPECT_EQ(rsa_after->dmp1, nullptr);
  EXPECT_EQ(rsa_after->dmq1, nullptr);
  EXPECT_EQ(rsa_after->iqmp, nullptr);

  RSA_free(rsa_before);
  RSA_free(rsa_after);
}

TEST(crypto_tests, test_extract_import_private_rsa_key)
{
  // generate a key
  RSA* rsa_before = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa_before != nullptr);

  // extract the private key
  RSAKey extracted;
  ASSERT_TRUE(Crypto::ExtractPrivateRSAKey(rsa_before, extracted));

  // import the public key
  RSA* rsa_after = RSA_new();
  ASSERT_TRUE(rsa_after != nullptr);
  ASSERT_TRUE(Crypto::ImportRSAKey(extracted, rsa_after));

  // check the imported key
  EXPECT_EQ(BN_cmp(rsa_before->n, rsa_after->n), 0);
  EXPECT_EQ(BN_cmp(rsa_before->e, rsa_after->e), 0);
  EXPECT_EQ(BN_cmp(rsa_before->d, rsa_after->d), 0);
  EXPECT_EQ(BN_cmp(rsa_before->p, rsa_after->p), 0);
  EXPECT_EQ(BN_cmp(rsa_before->q, rsa_after->q), 0);
  EXPECT_EQ(BN_cmp(rsa_before->dmp1, rsa_after->dmp1), 0);
  EXPECT_EQ(BN_cmp(rsa_before->dmq1, rsa_after->dmq1), 0);
  EXPECT_EQ(BN_cmp(rsa_before->iqmp, rsa_after->iqmp), 0);

  RSA_free(rsa_before);
  RSA_free(rsa_after);
}

TEST(crypto_tests, test_sha1)
{
  std::string message("Let me go.  I don't want to be a hero.  "
    "I don't want to be a big man.  "
    "I just want to fight like everyone else.  "
    "Your masquerade!  I don't want to be a part of your parade.  "
    "Everyone deserves a chance to walk with everyone else.");

  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)message.c_str(), message.length(), digest);
  EXPECT_TRUE(memcmp(digest, "\x7a\x52\x85\xd1\x7e\x53\xae\x21\x30\x07"
    "\x27\xb3\xe4\x6e\x59\x9e\x7c\x06\x46\xca", SHA_DIGEST_LENGTH) == 0);
}

TEST(crypto_tests, test_create_and_verify_signed_message)
{
  std::string contents("Arbitrary message contents...");

  // generate a key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  // generate a SignedMessage and throw away the key
  SignedMessage signed_message;
  ASSERT_TRUE(Crypto::CreateSignedMessage(contents, rsa, signed_message));
  RSA_free(rsa); // cleans the key from memory

  // verify the SignedMessage
  EXPECT_STREQ(signed_message.contents().c_str(), contents.c_str());
  EXPECT_TRUE(Crypto::VerifySignedMessage(signed_message));
}

TEST(crypto_tests, test_encrypt_and_decrypt_encrypted_message)
{
  std::string message("Arbitrary message to encrypt...");

  // generate recipient key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);
  RSAKey public_key;
  ASSERT_TRUE(Crypto::ExtractPublicRSAKey(rsa, public_key));

  // encrypt the message
  EncryptedMessage encrypted_message;
  ASSERT_TRUE(Crypto::EncryptMessage(public_key, message, encrypted_message));

  // decrypt the message
  std::string decrypted;
  ASSERT_TRUE(Crypto::DecryptMessage(rsa, encrypted_message, decrypted));
  RSA_free(rsa);

  EXPECT_TRUE(
    memcmp(decrypted.c_str(), message.c_str(), message.length()) == 0);
  EXPECT_EQ(message.length(), decrypted.length());
}
