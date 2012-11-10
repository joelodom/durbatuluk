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

// TODO: make configurable at run-time
/*static*/ std::string
  ConfigurationManager::configuration_file_name_("durbatuluk.conf");

/*static*/ std::map<std::string, std::string>
  ConfigurationManager::allowed_messages_;
/*static*/ std::string ConfigurationManager::post_message_url_;
/*static*/ std::string ConfigurationManager::fetch_message_url_;
/*static*/ std::string ConfigurationManager::my_signing_key_name_;
/*static*/ std::string ConfigurationManager::my_encryption_key_name_;

/*static*/ bool ConfigurationManager::ReadConfigurationFile(
  const std::string& config_file_name)
{
  // amateurish parsing algorithm will do for now
  // need to add error checking and lots more...

  std::ifstream config_file;
    config_file.open(config_file_name, std::ios_base::in);
  if (config_file.fail())
  {
    Logger::LogMessage(ERROR, "ConfigurationManager",
      "failed to read configuration file");
    return false;
  }

  std::string line;
  while (!config_file.eof())
  {
    if (!std::getline(config_file, line))
    {
      // may just be blank line
      continue;
    }

    if (line.length() < 17 || line[0] == '#')
      continue;

    if (line.rfind("\r") == line.length() - 1)
    {
      // trim DOS line endings
      line = line.substr(0, line.length() - 1);
    }

    if (line.find("allow_message ") == 0)
    {
      size_t second_space = line.rfind(" ");
      if (second_space == line.npos)
        continue;

      std::string type = line.substr(14, second_space - 14);
      std::string sender = line.substr(second_space + 1);

      std::stringstream ss;
      ss << "Type: " << type << " Sender: " << sender;
      Logger::LogMessage(DEBUG, "ConfigurationManager", &ss);

      allowed_messages_[sender] = type;
    }
    else if (line.find("logging_severity ") == 0)
    {
      std::string severity_str = line.substr(17);
      if (severity_str == "DEBUG")
        Logger::SetMinLoggingSeverity(DEBUG);
      else if (severity_str == "INFO")
        Logger::SetMinLoggingSeverity(INFO);
      else if (severity_str == "NONE")
        Logger::SetMinLoggingSeverity(NONE);
      else
        Logger::SetMinLoggingSeverity(ERROR);
    }
    else if (line.find("post_message_url ") == 0)
    {
      post_message_url_ = line.substr(17);
    }
    else if (line.find("fetch_message_url ") == 0)
    {
      fetch_message_url_ = line.substr(18);
    }
    else if (line.find("my_signing_key_name ") == 0)
    {
      my_signing_key_name_ = line.substr(20);
    }
    else if (line.find("my_encryption_key_name ") == 0)
    {
      my_encryption_key_name_ = line.substr(23);
    }
  }

  config_file.close();
  return true; // success
}

/*static*/ bool ConfigurationManager::IsSenderAllowed(const RSAKey& sender)
{
  std::string hashed;
  if (!Crypto::HashRSAKey(sender, &hashed))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager", "HashRSAKey failed");
    return false;
  }

  return allowed_messages_.find(hashed) != allowed_messages_.end();
}

/*static*/ bool ConfigurationManager::IsSenderAllowedToSendMessageType(
  const RSAKey& sender, const std::string& type)
{
  std::string hashed;
  if (!Crypto::HashRSAKey(sender, &hashed))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager", "HashRSAKey failed");
    return false;
  }

  auto it = allowed_messages_.find(hashed);
  return (it != allowed_messages_.end()) && ((*it).second == type);
}

/*static*/ bool ConfigurationManager::AllowSender(
  const RSA* rsa, const std::string& type)
{
  // extract the public key from
  RSAKey public_key;
  if (!Crypto::ExtractPublicRSAKey(rsa, &public_key))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager",
      "ExtractPublicRSAKey failed");
    return false;
  }

  // hash the key
  std::string hashed;
  if (!Crypto::HashRSAKey(public_key, &hashed))
  {
    Logger::LogMessage(ERROR, "ConfigurationManager", "HashRSAKey failed");
    return false;
  }

  // add it
  allowed_messages_[hashed] = type;

  return true;
}
