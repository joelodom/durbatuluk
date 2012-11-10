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

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "durbatuluk.pb.h"
#include <openssl/rsa.h>

#define RSA_BITS 2048
#define SESSION_KEY_LEN 32

class Crypto
{
public:
  // methods to convert between OpenSSL and protocol buffers
  static bool ExtractPublicRSAKey(const RSA* rsa, RSAKey* public_key);
  static bool ExtractPrivateRSAKey(const RSA* rsa, RSAKey* private_key);
  static bool ImportRSAKey(const RSAKey& rsa_key, RSA* rsa);

  // methods to create and to verify a protocol buffers SignedMessage
  static bool CreateSignedMessage(
    const std::string& contents, RSA* rsa, SignedMessage* signed_message);
  static bool VerifySignedMessage(const SignedMessage& signed_message);

  // methods to encrypt and to decrypt a protocol buffers EncryptedMessage
  static bool EncryptMessage(const RSAKey& recipient_public_key,
    const std::string& contents, EncryptedMessage* encrypted_message);
  static bool DecryptMessage(RSA* rsa,
    const EncryptedMessage& encrypted_message, std::string* decrypted);

  // method to extract a hash of a public key
  static bool HashRSAKey(const RSAKey& key, std::string* encoded_hash);
private:
  static unsigned char* AllocateForRSAExtraction(const RSA* rsa);
  static void ExtractBIGNUM(const std::string s, BIGNUM** bn);
};

#endif // #ifndef CRYPTO_H_
