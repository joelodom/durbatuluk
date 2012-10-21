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

#include "durbatuluk.h"
#include "gtest/gtest.h"
#include "durbatuluk.pb.h"
#include "logger.h"
#include "crypto.h"
#include "keyfile.h"
#include "message_handler.h"
#include "processing_engine.h"
#include "net_fetcher.h"
#include "sequence_manager.h"
#include "configuration_manager.h"
#include "base64.h"
#include <openssl/engine.h>

// leave as EXIT_FAILURE until handler function is sure of success
int final_return_value = EXIT_FAILURE;

void usage()
{
  std::cout << std::endl << "Durbatuluk " << MAJOR_VERSION << "."
    << MINOR_VERSION << "." << MICRO_VERSION << " " << DEVELOPMENT_PHASE
    << std::endl << std::endl;

  std::cout << "Durbatuluk is Copyright (c) 2012 Joel Odom Marietta, GA"
    << std::endl;
  std::cout << "See legal.txt for license details" << std::endl;
  std::cout << "http://durbatuluk.googlecode.com/" << std::endl;
  std::cout << std::endl;

  std::cout << "Usage:" << std::endl;
  std::cout << "  durbatuluk --tests" << std::endl;
  std::cout << "  durbatuluk --generate-keyfiles key_name" << std::endl;
  std::cout << "  durbatuluk --extract-public key_name" << std::endl;
  std::cout << "  durbatuluk --generate-command recipient_encryption_key "
    "sender_signing_key (command text read from stdin)" << std::endl;
  std::cout << "  durbatuluk --process-command recipient_encryption_key "
    "(encoded command read from stdin)" << std::endl;
  std::cout << "  durbatuluk --fetch-commands-from-url url "
    "recipient_encryption_key" << std::endl;
  std::cout << "  durbatuluk --reset-sequence-numbers" << std::endl;

  std::cout << std::endl;

  final_return_value = EXIT_SUCCESS;
}

bool tests(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--tests") == 0)
  {
    if (SequenceManager::ResetSequenceNumberFile())
    {
      std::cout << "Sequence number file reset." << std::endl;
      ::testing::InitGoogleTest(&argc, argv);
      final_return_value = RUN_ALL_TESTS();
      return true; // handled
    }
    else
    {
      std::cout << "Failed to reset sequence number file." << std::endl;
    }
  }

  return false; // not handled
}

bool generate_keyfiles(int argc, char **argv)
{
  if (argc != 3 || strcmp(argv[1], "--generate-keyfiles") != 0)
  {
    std::stringstream ss;
    ss << "argc: " << argc << " argv[1]: " << argv[1];
    Logger::LogMessage(DEBUG, "generate_keyfiles", ss);
    return false; // not handled
  }

  // generate an RSA key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  if (rsa == nullptr)
  {
    Logger::LogMessage(ERROR, "generate_keyfiles", "RSA_generate_key failed");
    return true; // handled
  }

  // write the key files
  if (!KeyFile::WriteKeyFiles(argv[2], rsa))
  {
    Logger::LogMessage(ERROR, "generate_keyfiles", "WriteKeyFiles failed");
    return true; // handled
  }

  RSA_free(rsa);
  std::cout << "Key files generated." << std::endl << std::endl;
  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

bool extract_public(int argc, char **argv)
{
  if (argc != 3 || strcmp(argv[1], "--extract-public") != 0)
    return false; // not handled

  // read the key
  RSAKey public_key;
  if (!KeyFile::ReadPublicKeyFile(argv[2], public_key))
  {
    Logger::LogMessage(ERROR, "extract_public", "ReadPublicKeyFile failed");
    return true; // handled
  }

  // hash and encode
  std::string encoded;
  if (!Crypto::HashRSAKey(public_key, encoded))
  {
    Logger::LogMessage(ERROR, "extract_public", "HashRSAKey failed");
    return true; // handled
  }

  std::cout << encoded;
  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

bool generate_command(int argc, char **argv)
{
  if (argc != 4 || strcmp(argv[1], "--generate-command") != 0)
    return false; // not handled

  // read the command from stdin

  std::string command;
  std::getline(std::cin, command);

  std::stringstream ss;
  ss << "command: " << command;
  Logger::LogMessage(DEBUG, "generate_command", ss);

  // read the recipient encryption key
  RSAKey recipient_public_key;
  if (!KeyFile::ReadPublicKeyFile(argv[2], recipient_public_key))
  {
    Logger::LogMessage(ERROR, "generate_command", "ReadPublicKeyFile failed");
    return true; // handled
  }

  // read the sender signing key

  RSAKey sender_signing_rsa;
  if (!KeyFile::ReadPrivateKeyFile(argv[3], sender_signing_rsa))
  {
    Logger::LogMessage(ERROR, "generate_command", "ReadPrivateKeyFile failed");
    return true; // handled
  }

  RSA* rsa = RSA_new();
  if (rsa == nullptr)
  {
    Logger::LogMessage(ERROR, "generate_command", "RSA_new failed");
    return true; // handled
  }

  if (!Crypto::ImportRSAKey(sender_signing_rsa, rsa))
  {
    Logger::LogMessage(ERROR, "generate_command", "ImportRSAKey failed");
    RSA_free(rsa);
    return true; // handled
  }

  // generate the message

  std::string encoded_message;
  unsigned long long sequence_number;
  bool rv = ProcessingEngine::GenerateEncodedDurbatulukMessage(
    MESSAGE_TYPE_SHELL_EXEC, command,
    recipient_public_key, rsa, encoded_message, sequence_number);
  RSA_free(rsa);

  if (!rv)
  {
    Logger::LogMessage(
      ERROR, "generate_command", "GenerateEncodedDurbatulukMessage failed");
    return true; // handled
  }

  // save the sequence number so that we can process the response
  if (!SequenceManager::AddToAllowedSequenceNumbers(sequence_number))
  {
    Logger::LogMessage(
      ERROR, "generate_command", "AddToAllowedSequenceNumbers failed");
    return true; // handled
  }

  std::cout << encoded_message;
  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

bool process_command(int argc, char **argv)
{
  if (argc != 3 || strcmp(argv[1], "--process-command") != 0)
    return false; // not handled

  // read the encoded command from stdin
  std::string encoded;
  std::cin >> encoded;

  // read the recipient encryption key

  RSAKey recipient_private_key;
  if (!KeyFile::ReadPrivateKeyFile(argv[2], recipient_private_key))
  {
    Logger::LogMessage(ERROR, "process_command", "ReadPrivateKeyFile failed");
    return true; // handled
  }

  RSA* rsa = RSA_new();
  if (rsa == nullptr)
  {
    Logger::LogMessage(ERROR, "process_command", "RSA_new failed");
    return true; // handled
  }

  if (!Crypto::ImportRSAKey(recipient_private_key, rsa))
  {
    Logger::LogMessage(ERROR, "process_command", "ImportRSAKey failed");
    RSA_free(rsa);
    return true; // handled
  }

  // handle the message
  DurbatulukMessage output;
  if (!ProcessingEngine::HandleIncomingEncodedMessage(encoded, rsa, output))
  {
    Logger::LogMessage(ERROR, "process_command",
      "HandleIncomingEncodedMessage failed");
    RSA_free(rsa);
    return true; // handled
  }

  RSA_free(rsa);
  std::cout << output.contents() << std::endl;
  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

bool fetch_commands_from_url(int argc, char **argv)
{
  if (argc != 4 || strcmp(argv[1], "--fetch-commands-from-url") != 0)
    return false; // not handled

  // read the recipient encryption key

  RSAKey recipient_private_key;
  if (!KeyFile::ReadPrivateKeyFile(argv[3], recipient_private_key))
  {
    Logger::LogMessage(ERROR, "fetch_commands_from_url",
      "ReadPrivateKeyFile failed");
    return true; // handled
  }

  RSA* rsa = RSA_new();
  if (rsa == nullptr)
  {
    Logger::LogMessage(ERROR, "fetch_commands_from_url", "RSA_new failed");
    return true; // handled
  }

  if (!Crypto::ImportRSAKey(recipient_private_key, rsa))
  {
    Logger::LogMessage(ERROR, "fetch_commands_from_url", "ImportRSAKey failed");
    RSA_free(rsa);
    return true; // handled
  }

  // fetch the URL

  std::stringstream ss;
  std::string url_contents;

  ss << "Attempting to fetch " << argv[2];
  Logger::LogMessage(DEBUG, "fetch_commands_from_url", ss);

  if (!NetFetcher::FetchURL(argv[2], url_contents))
  {
    Logger::LogMessage(ERROR, "fetch_commands_from_url", "FetchURL failed");
    RSA_free(rsa);
    return true; // handled
  }

  // process each commind in the URL, one by one

  size_t start_tag_pos = url_contents.find("<durbatuluk>");
  int message_num = 0;
  int messages_successfully_processed = 0;

  while (start_tag_pos != url_contents.npos)
  {
    ++message_num; // one indexed

    // find the next <durbatuluk>...</durbatuluk>
    size_t end_tag_pos = url_contents.find("</durbatuluk>", start_tag_pos + 11);
    if (end_tag_pos == url_contents.npos)
      break; // done processing (no end tag found)
    size_t len = end_tag_pos - start_tag_pos + 13;

    // process the encoded command

    std::string encoded(url_contents, start_tag_pos, len);
    DurbatulukMessage output;

    if (ProcessingEngine::HandleIncomingEncodedMessage(encoded, rsa, output))
    {
      messages_successfully_processed++;
      ss << "message #" << message_num << " processed successfully";
      Logger::LogMessage(INFO, "fetch_commands_from_url", ss);
    }
    else
    {
      ss << "could not process message #" << message_num;
      Logger::LogMessage(INFO, "fetch_commands_from_url", ss);
    }

    std::cout << output.contents() << std::endl;

    start_tag_pos = url_contents.find("<durbatuluk>", end_tag_pos + 12);
  }

  ss << messages_successfully_processed << " of " << message_num
    << " messages processed successfully";
  Logger::LogMessage(INFO, "fetch_commands_from_url", ss);

  RSA_free(rsa);
  std::cout << "Processed " << messages_successfully_processed << " commands."
    << std::endl;
  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

bool reset_sequence_numbers(int argc, char **argv)
{
  if (argc != 2 || strcmp(argv[1], "--reset-sequence-numbers") != 0)
    return false; // not handled

  if (SequenceManager::ResetSequenceNumberFile())
    std::cout << "Sequence number file reset." << std::endl;
  else
    std::cout << "Failed to reset sequence number file." << std::endl;

  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

int main(int argc, char **argv)
{
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::string config_file_name;

  if (!ConfigurationManager::GetConfigurationFileName(config_file_name))
  {
    Logger::LogMessage(ERROR, "main", "GetConfigurationFileName failed");
  }
  else if (!ConfigurationManager::ReadConfigurationFile(config_file_name))
  {
    std::stringstream ss;
    ss << "Failed to read " << config_file_name;
    Logger::LogMessage(ERROR, "main", ss);
  }
  else if (RAND_status() != 1)
  {
    // This could happen on systems without OS-provided randomness,
    // in which case additional features are required to initialize
    // the PRNG.

    Logger::LogMessage(ERROR, "main", "PRNG not initialized.");
  }
  else if (!(
    tests(argc, argv) ||
    generate_keyfiles(argc, argv) ||
    extract_public(argc, argv) ||
    generate_command(argc, argv) ||
    process_command(argc, argv) ||
    fetch_commands_from_url(argc, argv) ||
    reset_sequence_numbers(argc, argv)
    ))
    usage();

  RAND_cleanup();
  google::protobuf::ShutdownProtobufLibrary();

  return final_return_value;
}
