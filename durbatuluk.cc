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
#include <fstream>

// leave as EXIT_FAILURE until handler function is sure of success
int final_return_value = EXIT_FAILURE;

void usage()
{
  std::cout << "Durbatuluk is Copyright (c) 2012 Joel Odom" << std::endl;
  std::cout << "See legal.txt for license details" << std::endl;
  std::cout << "http://durbatuluk.googlecode.com/" << std::endl;
  std::cout << std::endl;

  std::cout << "Usage:" << std::endl;
  std::cout << "  durbatuluk --tests" << std::endl;
  std::cout << "  durbatuluk --generate-keyfiles key_name" << std::endl;

  std::cout << std::endl;

  final_return_value = EXIT_SUCCESS;
}

bool tests(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--tests") == 0)
  {
    ::testing::InitGoogleTest(&argc, argv);
    final_return_value = RUN_ALL_TESTS();
    return true; // handled
  }

  return false; // not handled
}

bool write_to_file(const std::string& filename, const std::string& data)
{
  std::ofstream out_file;

  out_file.open(filename);
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "write_to_file", "failed to open output file");
    return false; // failure
  }

  out_file << data;
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "write_to_file", "failed to write to output file");
    return false; // failure
  }

  out_file.close();
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "write_to_file", "failed to close output file");
    return false; // failure
  }

  return true; // success
}

bool generate_keyfiles(int argc, char **argv)
{
  if (argc != 3 || strcmp(argv[1], "--generate-keyfiles") != 0)
  {
    std::stringstream ss;
    ss << "argc: " << argc << " argv[1]: " << argv[1];
    Logger::LogMessage(DEBUG, "generate_keyfiles", ss.str());
    return false; // not handled
  }

  RSAKey public_key, private_key;
  std::string filename_base(argv[2]), serialized;

  // generate an RSA key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  if (rsa == nullptr)
  {
    Logger::LogMessage(ERROR, "generate_keyfiles", "RSA_generate_key failed");
    return true; // handled
  }

  // extract the public key
  if (!Crypto::ExtractPublicRSAKey(rsa, public_key))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "ExtractPublicRSAKey failed");
    return true; // handled
  }

  // extract the private key
  if (!Crypto::ExtractPrivateRSAKey(rsa, private_key))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "ExtractPrivateRSAKey failed");
    return true; // handled
  }

  // write the public key to a file

  if (!public_key.SerializeToString(&serialized))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "SerializeToString failed");
    return true; // handled
  }

  if (!write_to_file(filename_base + ".public", serialized))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "write_to_file failed");
    return true; // handled
  }

  // write the private key to a file

  if (!private_key.SerializeToString(&serialized))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "SerializeToString failed");
    return true; // handled
  }

  if (!write_to_file(filename_base + ".private", serialized))
  {
    Logger::LogMessage(
      ERROR, "generate_keyfiles", "write_to_file failed");
    return true; // handled
  }

  //TODO: output a success message here...  Also, it's not removing test keyfiles...

  final_return_value = EXIT_SUCCESS;
  return true; // handled
}

int main(int argc, char **argv)
{
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (!(
    tests(argc, argv) ||
    generate_keyfiles(argc, argv)
    ))
    usage();

  google::protobuf::ShutdownProtobufLibrary();
  return final_return_value;
}
