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

#include "keyfile.h"
#include "gtest/gtest.h"
#include <fstream>

TEST(keyfile_tests, test_keyfiles)
{
  // generate an RSA key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_F4, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  // generate the key files
  std::string key_name("__test_keyfiles__");
  ASSERT_TRUE(KeyFile::WriteKeyFiles(key_name, rsa));

  // check and delete the public key file

  RSAKey public_key;
  ASSERT_TRUE(KeyFile::ReadPublicKeyFile(key_name, &public_key));

  RSA* rsa_public_after = RSA_new();
  ASSERT_TRUE(rsa_public_after != nullptr);
  ASSERT_TRUE(Crypto::ImportRSAKey(public_key, rsa_public_after));

  EXPECT_EQ(BN_cmp(rsa->n, rsa_public_after->n), 0);
  EXPECT_EQ(BN_cmp(rsa->e, rsa_public_after->e), 0);
  EXPECT_EQ(rsa_public_after->d, nullptr);
  EXPECT_EQ(rsa_public_after->p, nullptr);
  EXPECT_EQ(rsa_public_after->q, nullptr);
  EXPECT_EQ(rsa_public_after->dmp1, nullptr);
  EXPECT_EQ(rsa_public_after->dmq1, nullptr);
  EXPECT_EQ(rsa_public_after->iqmp, nullptr);

  RSA_free(rsa_public_after);

  EXPECT_TRUE(remove((key_name + ".public").c_str()) == 0);

  // check and delete the private key file

  RSAKey private_key;
  ASSERT_TRUE(KeyFile::ReadPrivateKeyFile(key_name, &private_key));

  RSA* rsa_private_after = RSA_new();
  ASSERT_TRUE(rsa_private_after != nullptr);
  ASSERT_TRUE(Crypto::ImportRSAKey(private_key, rsa_private_after));

  EXPECT_EQ(BN_cmp(rsa->n, rsa_private_after->n), 0);
  EXPECT_EQ(BN_cmp(rsa->e, rsa_private_after->e), 0);
  EXPECT_EQ(BN_cmp(rsa->d, rsa_private_after->d), 0);
  EXPECT_EQ(BN_cmp(rsa->p, rsa_private_after->p), 0);
  EXPECT_EQ(BN_cmp(rsa->q, rsa_private_after->q), 0);
  EXPECT_EQ(BN_cmp(rsa->dmp1, rsa_private_after->dmp1), 0);
  EXPECT_EQ(BN_cmp(rsa->dmq1, rsa_private_after->dmq1), 0);
  EXPECT_EQ(BN_cmp(rsa->iqmp, rsa_private_after->iqmp), 0);

  RSA_free(rsa_private_after);

  EXPECT_TRUE(remove((key_name + ".private").c_str()) == 0);

  RSA_free(rsa);
}
