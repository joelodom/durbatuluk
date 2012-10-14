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

#include "keyfile.h"
#include "logger.h"
#include <fstream>

/*static*/ bool KeyFile::WriteKeyFiles(const std::string& key_name, RSA* rsa)
{
  RSAKey public_key, private_key;
  std::string public_serialized, private_serialized;

  // extract the public key

  if (!Crypto::ExtractPublicRSAKey(rsa, public_key))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "ExtractPublicRSAKey failed");
    return false; // failure
  }

  if (!public_key.SerializeToString(&public_serialized))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "SerializeToString failed");
    return false; // failure
  }

  // extract the private key

  if (!Crypto::ExtractPrivateRSAKey(rsa, private_key))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "ExtractPrivateRSAKey failed");
    return false; // failure
  }

  if (!private_key.SerializeToString(&private_serialized))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "SerializeToString failed");
    return false; // failure
  }

  // write the public key to a file

  if (!WriteToFile(key_name + ".public", public_serialized))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "WriteToFile failed");
    return false; // failure
  }

  // write the private key to a file

  if (!WriteToFile(key_name + ".private", private_serialized))
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "WriteToFile failed");
    return false; // failure
  }

  return true; // success
}

/*static*/ bool KeyFile::WriteToFile(
  const std::string& filename, const std::string& data)
{
  std::ofstream out_file;

  out_file.open(filename);
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "failed to open output file");
    return false; // failure
  }

  out_file << data;
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "failed to write to output file");
    return false; // failure
  }

  out_file.close();
  if (out_file.fail())
  {
    Logger::LogMessage(
      ERROR, "KeyFile", "failed to close output file");
    return false; // failure
  }

  return true; // success
}
