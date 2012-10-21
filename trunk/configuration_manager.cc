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

#include "configuration_manager.h"
#include "logger.h"
#include "crypto.h"
#include <fstream>

/*static*/ std::map<std::string, std::string>
  ConfigurationManager::allowed_messages;

/*static*/ bool ConfigurationManager::ReadConfigurationFile(
  std::string& config_file_name)
{
  std::ifstream config_file;
  config_file.exceptions(std::ios::failbit); // throw on failure

  try
  {
    config_file.open(config_file_name, std::ios_base::in);

    std::string line;
    while (!config_file.eof() && std::getline(config_file, line))
    {
      // amateurish parsing algorithm will do for now

      if (line.length() < 17 || line[0] == '#')
        continue;

      if (line.find("allow_message ") == 0)
      {
        size_t second_space = line.rfind(" ");
        if (second_space == line.npos)
          continue;

        std::string type = line.substr(14, second_space - 14);
        std::string sender = line.substr(second_space + 1);

        std::stringstream ss;
        ss << "Type: " << type << " Sender: " << sender;
        Logger::LogMessage(DEBUG, "ConfigurationManager", ss);

        allowed_messages[sender] = type;
      }
    }

    config_file.close();
    return true; // success
  }
  catch (const std::exception& ex)
  {
    std::stringstream ss;
    ss << "Failed to read configuration file (" << ex.what() << ").";
    Logger::LogMessage(ERROR, "ConfigurationManager", ss);
  }

  return false; // failure
}

/*static*/ bool ConfigurationManager::IsSenderAllowed(const RSAKey& sender)
{
  std::string hashed;
  if (!Crypto::HashRSAKey(sender, hashed))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager", "HashRSAKey failed");
    return false;
  }

  return allowed_messages.find(hashed) != allowed_messages.end();
}

/*static*/ bool ConfigurationManager::IsSenderAllowedToSendMessageType(
  const RSAKey& sender, const std::string& type)
{
  return false; // under construction
}

/*static*/ bool ConfigurationManager::AllowSender(
  RSA* rsa, const std::string& type)
{
  // extract the public key from
  RSAKey public_key;
  if (!Crypto::ExtractPublicRSAKey(rsa, public_key))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager",
      "ExtractPublicRSAKey failed");
    return false;
  }

  // hash the key
  std::string hashed;
  if (!Crypto::HashRSAKey(public_key, hashed))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager", "HashRSAKey failed");
    return false;
  }

  // add it
  allowed_messages[hashed] = type;

  return true;
}
