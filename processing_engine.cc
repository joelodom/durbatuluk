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

#include "processing_engine.h"
#include "base64.h"

/*static*/ bool ProcessingEngine::EncryptSignAndEncode(std::string& message,
    RSAKey& recipient_public_key, RSA* sender_signing_key,
    std::string& encoded)
{
  // generate the encrypted message
  EncryptedMessage encrypted_message;
  if (!Crypto::EncryptMessage(recipient_public_key, message, encrypted_message))
    return false; // failure
  std::string encrypted_str;
  if (!encrypted_message.SerializeToString(&encrypted_str))
    return false; // failure

  // generate the signed message
  SignedMessage signed_message;
  if (!Crypto::CreateSignedMessage(
    encrypted_str, sender_signing_key, signed_message))
    return false; // failure
  std::string signed_str;
  if (!signed_message.SerializeToString(&signed_str))
    return false; // failure

  // encode the signed message
  encoded = base64_encode(reinterpret_cast<const unsigned char*>(
    signed_str.c_str()), signed_str.length());

  return true; // success
}

/*static*/ bool ProcessingEngine::DecodeVerifyAndDecrypt(std::string& encoded,
    RSA* recipient_private_encryption_key, std::string& message)
{
  return false; // under construction
}
