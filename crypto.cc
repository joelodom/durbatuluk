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

/*static*/ bool Crypto::ImportRSAKey(RSAKey& rsa_key, RSA* rsa)
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
