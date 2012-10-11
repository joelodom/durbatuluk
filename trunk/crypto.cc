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
#include <openssl/engine.h>
#include "openssl_aes.h"

/*static*/ bool Crypto::ExtractPublicRSAKey(RSA* rsa, RSAKey& public_key)
{
  unsigned char* buf = AllocateForRSAExtraction(rsa);
  if (buf == nullptr)
    return false; // failure

  int len = BN_bn2bin(rsa->n, buf);
  public_key.set_n(buf, len);

  len = BN_bn2bin(rsa->e, buf);
  public_key.set_e(buf, len);

  delete[] buf;
  return true; // success
}

/*static*/ bool Crypto::ExtractPrivateRSAKey(RSA* rsa, RSAKey& private_key)
{
  unsigned char* buf = AllocateForRSAExtraction(rsa);
  if (buf == nullptr)
    return false; // failure

  int len = BN_bn2bin(rsa->n, buf);
  private_key.set_n(buf, len);

  len = BN_bn2bin(rsa->e, buf);
  private_key.set_e(buf, len);

  len = BN_bn2bin(rsa->d, buf);
  private_key.set_d(buf, len);

  len = BN_bn2bin(rsa->p, buf);
  private_key.set_p(buf, len);

  len = BN_bn2bin(rsa->q, buf);
  private_key.set_q(buf, len);

  len = BN_bn2bin(rsa->dmp1, buf);
  private_key.set_dmp1(buf, len);

  len = BN_bn2bin(rsa->dmq1, buf);
  private_key.set_dmq1(buf, len);

  len = BN_bn2bin(rsa->iqmp, buf);
  private_key.set_iqmp(buf, len);

  delete[] buf;
  return true; // success
}

/*static*/ bool Crypto::ImportRSAKey(const RSAKey& rsa_key, RSA* rsa)
{
  ExtractBIGNUM(rsa_key.n(), &rsa->n);
  if (rsa->n == nullptr)
    return false; // failure

  ExtractBIGNUM(rsa_key.e(), &rsa->e);
  if (rsa->e == nullptr)
    return false; // failure

  if (rsa_key.has_d())
  {
    ExtractBIGNUM(rsa_key.d(), &rsa->d);
    if (rsa->d == nullptr)
      return false; // failure
  }

  if (rsa_key.has_p())
  {
    ExtractBIGNUM(rsa_key.p(), &rsa->p);
    if (rsa->p == nullptr)
      return false; // failure
  }

  if (rsa_key.has_q())
  {
    ExtractBIGNUM(rsa_key.q(), &rsa->q);
    if (rsa->q == nullptr)
      return false; // failure
  }

  if (rsa_key.has_dmp1())
  {
    ExtractBIGNUM(rsa_key.dmp1(), &rsa->dmp1);
    if (rsa->dmp1 == nullptr)
      return false; // failure
  }

  if (rsa_key.has_dmq1())
  {
    ExtractBIGNUM(rsa_key.dmq1(), &rsa->dmq1);
    if (rsa->dmq1 == nullptr)
      return false; // failure
  }

  if (rsa_key.has_iqmp())
  {
    ExtractBIGNUM(rsa_key.iqmp(), &rsa->iqmp);
    if (rsa->iqmp == nullptr)
      return false; // failure
  }

  return true; // success
}

/*static*/ unsigned char* Crypto::AllocateForRSAExtraction(RSA* rsa)
{
  if (rsa->n == nullptr || rsa->e == nullptr)
    return nullptr;

  int bytes_needed = BN_num_bytes(rsa->n);
  int i = BN_num_bytes(rsa->e);
  if (i > bytes_needed)
    bytes_needed = i;

  if (rsa->d != nullptr)
  {
    i = BN_num_bytes(rsa->d);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  if (rsa->p != nullptr)
  {
    i = BN_num_bytes(rsa->p);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  if (rsa->q != nullptr)
  {
    i = BN_num_bytes(rsa->q);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  if (rsa->dmp1 != nullptr)
  {
    i = BN_num_bytes(rsa->dmp1);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  if (rsa->dmq1 != nullptr)
  {
    i = BN_num_bytes(rsa->dmq1);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  if (rsa->iqmp != nullptr)
  {
    i = BN_num_bytes(rsa->iqmp);
    if (i > bytes_needed)
      bytes_needed = i;
  }

  return new unsigned char[bytes_needed];
}

/*static*/ void Crypto::ExtractBIGNUM(std::string s, BIGNUM** bn)
{
  *bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.c_str()),
    s.length(), nullptr);
}

/*static*/ bool Crypto::CreateSignedMessage(
    std::string& contents, RSA* rsa, SignedMessage& signed_message)
{
  // set up variables and buffers
  int rsa_size = RSA_size(rsa);
  unsigned char* sigret = new unsigned char[rsa_size];
  if (sigret == nullptr)
    return false; // failure
  unsigned int siglen;

  // sign the contents
  if (RSA_sign(NID_sha1, (const unsigned char*)contents.c_str(),
    contents.size(), sigret, &siglen, rsa) != 1)
    return false; // failure

  // build the SignedMessage
  RSAKey public_key;
  if (!ExtractPublicRSAKey(rsa, public_key))
    return false;
  signed_message.mutable_sender()->set_n(public_key.n());
  signed_message.mutable_sender()->set_e(public_key.e());
  signed_message.set_contents(contents);
  signed_message.set_signature(sigret, siglen);

  delete[] sigret;
  return true; // failure
}

/*static*/ bool Crypto::VerifySignedMessage(SignedMessage& signed_message)
{
  // import the public signing key

  RSA* rsa = RSA_new();
  if (!ImportRSAKey(signed_message.sender(), rsa))
  {
    RSA_free(rsa);
    return false; // failure
  }

  int rsa_size = RSA_size(rsa);
  unsigned char* sigret = new unsigned char[rsa_size];
  if (sigret == nullptr)
  {
    RSA_free(rsa);
    return false; // failure
  }

  // verify the digital signature

  bool signature_passed = RSA_verify(NID_sha1,
    reinterpret_cast<const unsigned char*>(signed_message.contents().c_str()),
    signed_message.contents().size(),
    reinterpret_cast<const unsigned char*>(signed_message.signature().c_str()),
    signed_message.signature().length(), rsa);

  delete[] sigret;
  RSA_free(rsa);

  return signature_passed;
}

/*static*/ bool Crypto::EncryptMessage(RSAKey& recipient_public_key,
    std::string& contents, EncryptedMessage& encrypted_message)
{
  // set up for encryption early so that the session key stays in memory
  // for as short a time as possible
  RSA* rsa = RSA_new();
  ImportRSAKey(recipient_public_key, rsa);
  int rsa_size = RSA_size(rsa);
  EVP_CIPHER_CTX en, de;
  unsigned char* ciphertext = nullptr;
  int len = (int)contents.length() + 1; // capture terminating null
  unsigned char* encrypted_session_key = new unsigned char[rsa_size];

  // generate a random session key
  // CRITICAL!  generate cryptographically secure session keys
  char* session_key = new char[16];
  strcpy(session_key, "JVO TODO");
  size_t session_key_len = strlen(session_key);
  unsigned int salt[] = {12345, 54321};

  while (true) // break out when finished
  {
    // encrypt the session key
    int i = RSA_public_encrypt(session_key_len + 1, // capture terminating null
      (unsigned char*)session_key,
      encrypted_session_key, rsa, RSA_PKCS1_OAEP_PADDING);
      
    if (i != rsa_size)
      break; // something went wrong

    // encrypt the message contents with the session key
    i = aes_init((unsigned char*)session_key, session_key_len,
      (unsigned char*)&salt, &en, &de);
    if (i != 0)
      break; // couldn't initialize AES cipher
    ciphertext = aes_encrypt(&en, (unsigned char*)contents.c_str(), &len);

    break;
  }

  // dispose of session key as quickly as possible
  memset((char*)session_key, 0, session_key_len);
  session_key_len = 0;
  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);
  delete[] session_key;
  RSA_free(rsa); // remember this is only the receiver public key

  bool success = false;

  if (ciphertext != nullptr)
  {
    // populate the encrypted message
    encrypted_message.mutable_recipient()->set_n(recipient_public_key.n());
    encrypted_message.mutable_recipient()->set_e(recipient_public_key.e());
    encrypted_message.set_encrypted_key(encrypted_session_key, rsa_size);
    encrypted_message.set_encrypted_contents(ciphertext, len);

    free(ciphertext); // (safe to free nullptr)
    success = true;
  }

  delete[] encrypted_session_key;
  return success;
}

/*static*/ bool Crypto::DecryptMessage(RSA* rsa,
  EncryptedMessage& encrypted_message, std::string& decrypted)
{
  size_t session_key_len;
  EVP_CIPHER_CTX en, de;

  decrypted.erase(); // length used to check for error condition below

  // verify that RSA key parameter is that of recipient of message
  RSAKey private_key;
  if (!ExtractPrivateRSAKey(rsa, private_key))
    return false; // failure
  if (encrypted_message.recipient().e() != private_key.e() // e usually smaller
    || encrypted_message.recipient().n() != private_key.n())
    return false; // recipient key mismatch / not intended for this recipient

  // decrypt the message contents

  int rsa_size = RSA_size(rsa);
  unsigned char* session_key = new unsigned char[rsa_size];
  if (session_key == nullptr)
    return false; // memory allocation failure

  while (true) // break out when finished
  {
    // decrypt the session key

    if (RSA_private_decrypt(rsa_size,
      reinterpret_cast<const unsigned char*>(
      encrypted_message.encrypted_key().c_str()),
      session_key, rsa, RSA_PKCS1_OAEP_PADDING) < 0)
      break; // failure

    unsigned int salt[] = {12345, 54321};

    session_key_len = strlen((char*)session_key);
    if (session_key_len > 10)
      break; // TODO: set max length above

    // decrypt the contents

    int i = aes_init((unsigned char*)session_key, session_key_len,
      (unsigned char*)&salt, &en, &de);
    if (i != 0)
      break; // couldn't initialize AES cipher

    int len = encrypted_message.encrypted_contents().length();

    char* plaintext = (char*)aes_decrypt(&de,
      (unsigned char*)encrypted_message.encrypted_contents().c_str(), &len);

    if (plaintext == nullptr)
      break; // something went wrong with encryption

    decrypted = plaintext;
    free(plaintext);

    break;
  }

  // clean the session key from memory
  memset((char*)session_key, 0, session_key_len);
  session_key_len = 0;
  delete[] session_key;
  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  return decrypted.length() > 0;
}
