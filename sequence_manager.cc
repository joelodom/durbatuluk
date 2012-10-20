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

#include "utils.h"
#include "durbatuluk.pb.h"
#include "sequence_manager.h"
#include "configuration_manager.h"
#include "logger.h"
#include <fstream>

/*static*/ bool SequenceManager::IsSequenceNumberAllowed(unsigned long long n)
{
  unsigned long long minimum;
  std::set<unsigned long long> allowed_numbers;

  // read the sequence number file
  if (!ReadSequenceNumberFile(minimum, allowed_numbers))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "ReadSequenceNumberFile failed");
    return false; // disallowed
  }

  // logging
  std::stringstream ss;
  ss << "N: " << n << "  minimum: " << minimum;
  Logger::LogMessage(DEBUG, "SequenceManager", ss);

  // check the set of explicitly allowed numbers
  if (allowed_numbers.find(n) != allowed_numbers.end())
    return true; // allowed

  return n >= minimum;
}

/*static*/ bool SequenceManager::SetMinimumAllowedSequenceNumber(
  unsigned long long n)
{
  unsigned long long minimum;
  std::set<unsigned long long> allowed_numbers;

  // read the sequence number file
  if (!ReadSequenceNumberFile(minimum, allowed_numbers))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "ReadSequenceNumberFile failed");
    return false; // failure
  }

  // write the new sequence number file with the new minimum
  if (!SequenceManager::WriteSequenceNumberFile(n, allowed_numbers))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "WriteSequenceNumberFile failed");
    return false; // failure
  }

  return true; // success
}

/*static*/ bool SequenceManager::AddToAllowedSequenceNumbers(
  unsigned long long n)
{
  unsigned long long minimum;
  std::set<unsigned long long> allowed_numbers;

  // read the sequence number file
  if (!ReadSequenceNumberFile(minimum, allowed_numbers))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "ReadSequenceNumberFile failed");
    return false; // failure
  }

  // add the new number
  std::pair<std::set<unsigned long long>::iterator, bool> pair
    = allowed_numbers.insert(n);

  // write the new sequence number file if it changed
  if (pair.second)
  {
    if (!SequenceManager::WriteSequenceNumberFile(minimum, allowed_numbers))
    {
      Logger::LogMessage(ERROR,
        "SequenceManager", "WriteSequenceNumberFile failed");
      return false; // failure
    }
  }

  return true; // success
}

/*static*/ bool SequenceManager::RemoveFromAllowedSequenceNumbers(
  unsigned long long n)
{
  unsigned long long minimum;
  std::set<unsigned long long> allowed_numbers;

  // read the sequence number file
  if (!ReadSequenceNumberFile(minimum, allowed_numbers))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "ReadSequenceNumberFile failed");
    return false; // failure
  }

  // remove the disallowed number
  if (allowed_numbers.erase(n) == 1)
  {
    // write the new sequence number file if it changed
    if (!SequenceManager::WriteSequenceNumberFile(minimum, allowed_numbers))
    {
      Logger::LogMessage(ERROR,
        "SequenceManager", "WriteSequenceNumberFile failed");
      return false; // failure
    }
  }

  return true; // success
}

/*static*/ bool SequenceManager::ReadSequenceNumberFile(
    unsigned long long& minimum,
    std::set<unsigned long long>& allowed_numbers)
{
  // defaults for failure or for writing new file
  minimum = SEQUENCE_NUMBER_MAX;
  allowed_numbers.clear();

  // get the sequence file name
  std::string sequence_file_name;
  if (!ConfigurationManager::GetSequenceNumberFileName(sequence_file_name))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "GetSequenceNumberFileName failed");
    return false; // failure
  }

  // attempt to read the sequence file

  std::ifstream in_file;
  AllowedSequenceNumbers allowed_numbers_message;

  std::ios_base::iostate state_before = in_file.exceptions();
  in_file.exceptions(std::ios::failbit); // throw on failure

  try
  {
    in_file.open(sequence_file_name);
  }
  catch (const std::exception& ex)
  {
    std::stringstream ss;
    ss << "Failed to open sequence number file (message " << ex.what()
      << ").  Creating new file.";
    Logger::LogMessage(INFO, "SequenceManager", ss);

    // writes using defaults
    if (!SequenceManager::WriteSequenceNumberFile(
      minimum, allowed_numbers))
    {
      Logger::LogMessage(ERROR,
        "SequenceManager", "WriteSequenceNumberFile failed");
      return false; // failure
    }

    Logger::LogMessage(DEBUG, "SequenceManager",
      "New sequence file created.");

    return true; // success
  }

  in_file.exceptions(state_before); // reset to no throw

  if (!allowed_numbers_message.ParseFromIstream(&in_file))
  {
    Logger::LogMessage(DEBUG, "SequenceManager", "ParseFromIstream failed");
    return false; // failure
  }

  in_file.close(); // does ParseFromIstream close in_file?

  // set returns

  minimum = allowed_numbers_message.has_minimum()
    ? allowed_numbers_message.minimum() : SEQUENCE_NUMBER_MAX;

  for (int i = 0; i < allowed_numbers_message.allowed_size(); i++)
    allowed_numbers.insert(allowed_numbers_message.allowed(i));

  return true; // success
}

/*static*/ bool SequenceManager::WriteSequenceNumberFile(
    unsigned long long minimum,
    std::set<unsigned long long>& allowed_numbers)
{
  // get the sequence file name
  std::string sequence_file_name;
  if (!ConfigurationManager::GetSequenceNumberFileName(sequence_file_name))
  {
    Logger::LogMessage(ERROR,
      "SequenceManager", "GetSequenceNumberFileName failed");
    return false; // failure
  }

  // build the message to save
  AllowedSequenceNumbers allowed_numbers_message;
  allowed_numbers_message.set_minimum(minimum);
  for (auto it = allowed_numbers.begin(); it != allowed_numbers.end(); it++)
    allowed_numbers_message.add_allowed(*it);

  // serialize the message to save
  std::string serialized;
  if (!allowed_numbers_message.SerializeToString(&serialized))
  {
    Logger::LogMessage(ERROR, "SequenceManager", "SerializeToString failed");
    return false; // failure
  }

  // save
  if (!Utils::WriteToFile(sequence_file_name, serialized))
  {
    Logger::LogMessage(ERROR, "SequenceManager", "WriteToFile failed");
    return false; // failure
  }

  return true; // success
}
