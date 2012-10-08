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

  if (!RSA_verify(NID_sha1,
    reinterpret_cast<const unsigned char*>(signed_message.contents().c_str()),
    signed_message.contents().size(),
    reinterpret_cast<const unsigned char*>(signed_message.signature().c_str()),
    signed_message.signature().length(), rsa))
  {
    // signature verification failed -- this is important
    delete[] sigret;
    RSA_free(rsa);
    return false;
  }

  delete[] sigret;
  RSA_free(rsa);

  return true; // success
}
