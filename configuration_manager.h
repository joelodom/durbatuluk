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

#ifndef CONFIGURATION_MANAGER_H_
#define CONFIGURATION_MANAGER_H_

#include "durbatuluk.pb.h"
#include <openssl/rsa.h>
#include <string>
#include <map>

class ConfigurationManager
{
public:
  static bool ReadConfigurationFile(std::string& config_file_name);

  static bool GetSequenceNumberFileName(std::string& file_name)
  {
    // TODO: make configurable
    file_name = "sequence_file";
    return true; // success
  }

  static bool GetConfigurationFileName(std::string& file_name)
  {
    file_name = configuration_file_name_;
    return true; // success
  }

  static bool SetConfigurationFileName(std::string& file_name)
  {
    configuration_file_name_ = file_name;
    return true; // success
  }

  static bool GetPostMessageURL(std::string& url)
  {
    url = post_message_url_;
    return true; // success
  }

  static bool GetFetchMessageURL(std::string& url)
  {
    url = fetch_message_url_;
    return true; // success
  }

  static bool GetMySigningKeyName(std::string& name)
  {
    name = my_signing_key_name_;
    return true; // success
  }

  static bool GetMyEncryptionKeyName(std::string& name)
  {
    name = my_encryption_key_name_;
    return true; // success
  }

  // The idea is to allow an initial check of the sender, followed
  // by a check of the sender and message type pair.  This double
  // check reduces attack surface.
  static bool IsSenderAllowed(const RSAKey& sender);
  static bool IsSenderAllowedToSendMessageType(
    const RSAKey& sender, const std::string& type);

  // AllowSender is mostly for testing purposes
  static bool AllowSender(RSA* rsa, const std::string& type);

private:
  // The map key is the hash of the sender public key.  The map value
  // is the message type allowed.  See the sample configuration file.
  static std::map<std::string, std::string> allowed_messages_;

  // etc...
  static std::string configuration_file_name_;
  static std::string post_message_url_;
  static std::string fetch_message_url_;
  static std::string my_signing_key_name_;
  static std::string my_encryption_key_name_;
};

#endif // #ifndef CONFIGURATION_MANAGER_H_
