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
#include "encoding.h"
#include "message_handler.h"
#include "logger.h"
#include "sequence_manager.h"

/*static*/ bool ProcessingEngine::GenerateEncodedDurbatulukMessage(
  const std::string& type, const std::string& contents,
  RSAKey& recipient_public_key,
  RSA* sender_signing_key, std::string& encoded_message,
  unsigned long long& sequence_number)
{
  sequence_number = SequenceManager::GetNextSequenceNumber();

  DurbatulukMessage durbatuluk_message;
  durbatuluk_message.set_type(type);
  durbatuluk_message.set_contents(contents);
  durbatuluk_message.set_sequence_number(sequence_number);

  std::string serialized;
  if (!durbatuluk_message.SerializeToString(&serialized))
    return false; // failure

  return EncryptSignAndEncode(serialized, recipient_public_key,
    sender_signing_key, encoded_message);
}

/*static*/ bool ProcessingEngine::HandleIncomingEncodedMessage(
  std::string& encoded_incoming, RSA* recipient_private_encryption_key,
  DurbatulukMessage& output, MessageHandlerCallback callback /*= nullptr*/)
{
  std::string decoded_message;
  if (!DecodeVerifyAndDecrypt(
    encoded_incoming, recipient_private_encryption_key, decoded_message))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine",
      "DecodeVerifyAndDecrypt failed");
    return false; // failure
  }

  DurbatulukMessage input;
  if (!input.ParseFromString(decoded_message))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine",
      "ParseFromString failed");
    return false; // failure
  }

  if (!MessageHandler::HandleMessage(input, output, callback))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine",
      "HandleMessage failed");
    return false; // failure
  }

  return true; // success
}

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
  if (!Encoding::EncodeMessage(signed_str, encoded))
    return false; // failure

  return true; // success
}

/*static*/ bool ProcessingEngine::DecodeVerifyAndDecrypt(std::string& encoded,
    RSA* recipient_private_encryption_key, std::string& message)
{
  // decode the message

  std::string decoded;
  if (!Encoding::DecodeMessage(encoded, decoded))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine", "DecodeMessage failed");
    return false; // failure
  }

  SignedMessage signed_message;
  if (!signed_message.ParseFromString(decoded))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine",
      "ParseFromString for signed_message failed");
    return false; // failure
  }

  // TODO: verify here that the sender is authorized

  // verify the message signature

  if (!Crypto::VerifySignedMessage(signed_message))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine", "VerifySignedMessage failed");
    return false; // failure
  }

  EncryptedMessage encrypted_message;
  if (!encrypted_message.ParseFromString(signed_message.contents()))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine",
      "ParseFromString for encrypted_message failed");
    return false; // failure
  }

  // decrypt the message
  std::string decrypted;
  if (!Crypto::DecryptMessage(
    recipient_private_encryption_key, encrypted_message, message))
  {
    Logger::LogMessage(ERROR, "ProcessingEngine", "DecryptMessage failed");
    return false; // failure
  }

  return true; // success
}
