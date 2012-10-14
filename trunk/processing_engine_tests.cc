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
#include "gtest/gtest.h"
#include "message_handler.h"

TEST(processing_engine_tests, test_full_circle_of_string_message)
{
  std::string message("this tests the full circle message");

  // generate sender key
  RSA* rsa_sender_signing
    = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  ASSERT_TRUE(rsa_sender_signing != nullptr);

  // generate recipient key
  RSA* rsa_recipient_encryption
    = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  ASSERT_TRUE(rsa_recipient_encryption != nullptr);
  RSAKey rsa_recipient_encryption_public_key;
  ASSERT_TRUE(Crypto::ExtractPublicRSAKey(
    rsa_recipient_encryption, rsa_recipient_encryption_public_key));

  // encrypt, sign and encode the message
  std::string encoded;
  ASSERT_TRUE(ProcessingEngine::EncryptSignAndEncode(
    message, rsa_recipient_encryption_public_key, rsa_sender_signing, encoded));
  RSA_free(rsa_sender_signing);

  // decode, verify and decrypt the encoded message
  std::string message2;
  ASSERT_TRUE(ProcessingEngine::DecodeVerifyAndDecrypt(
    encoded, rsa_recipient_encryption, message2));
  RSA_free(rsa_recipient_encryption);

  EXPECT_STREQ(message.c_str(), message2.c_str());
}

TEST(processing_engine_tests, test_full_circle_of_shell_command)
{
  // generate sender key
  RSA* rsa_sender_signing
    = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  ASSERT_TRUE(rsa_sender_signing != nullptr);

  // generate recipient key
  RSA* rsa_recipient_encryption
    = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  ASSERT_TRUE(rsa_recipient_encryption != nullptr);
  RSAKey rsa_recipient_encryption_public_key;
  ASSERT_TRUE(Crypto::ExtractPublicRSAKey(
    rsa_recipient_encryption, rsa_recipient_encryption_public_key));

  // generate the message as if I am a commander
  std::string encoded_message;
  ASSERT_TRUE(ProcessingEngine::GenerateEncodedDurbatulukMessage(
    MESSAGE_TYPE_SHELL_EXEC, "echo durbatuluk",
    rsa_recipient_encryption_public_key, rsa_sender_signing, encoded_message));

  // process the message as if I am a client
  DurbatulukMessage output;
  ASSERT_TRUE(ProcessingEngine::HandleIncomingEncodedMessage(
    encoded_message, rsa_recipient_encryption, output));

  // send the output to myself as a message (for testing)
  // (since we already have output as a Durbatuluk message, we only need
  // to encrypt, sign and encode)
  std::string output_str;
  ASSERT_TRUE(output.SerializeToString(&output_str));
  ASSERT_TRUE(ProcessingEngine::EncryptSignAndEncode(output_str,
    rsa_recipient_encryption_public_key, rsa_sender_signing, encoded_message));
  RSA_free(rsa_sender_signing);

  // a lambda function for handling the callback from the message handler
  MessageHandlerCallback callback
    = [](const std::string& type, const std::string& contents)
    {
      return type == MESSAGE_TYPE_SHELL_EXEC_OUTPUT
        && contents.find("durbatuluk") == 0;
    };

  // process the response as if I am the commander getting the response
  ASSERT_TRUE(ProcessingEngine::HandleIncomingEncodedMessage(
    encoded_message, rsa_recipient_encryption, output, callback));
  RSA_free(rsa_recipient_encryption);
}
