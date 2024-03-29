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

#ifndef PROCESSING_ENGINE_H_
#define PROCESSING_ENGINE_H_

#include "crypto.h"
#include "message_handler.h"

class ProcessingEngine
{
public:
  // method to generate a DurbatulukMessage
  static bool GenerateEncodedDurbatulukMessage(const std::string& type,
    const std::string& contents, const RSAKey& recipient_public_key,
    RSA* sender_signing_key, std::string* encoded_message,
    unsigned long long* sequence_number);

  // method to handle an encoded message with message handler
  // (doesn't generate encoded response, but passes on message handler output
  // and callback)
  static bool HandleIncomingEncodedMessage(const std::string& encoded_incoming,
    RSA* recipient_private_encryption_key,
    DurbatulukMessage* output, MessageHandlerCallback callback = nullptr);

  // methods to perform a full Durbatuluk circle of encryption and encoding
  static bool EncryptSignAndEncode(const std::string& message,
    const RSAKey& recipient_public_key, RSA* sender_signing_key,
    std::string* encoded);
  static bool DecodeVerifyAndDecrypt(const std::string& encoded,
    RSA* recipient_private_encryption_key, DurbatulukMessage* message);
};

#endif // #ifndef PROCESSING_ENGINE_H_
