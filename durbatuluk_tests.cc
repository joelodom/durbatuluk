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
#include "message_handler.h"
#include "encoding.h"
#include "sequence_manager.h"
#include "configuration_manager.h"
#include "utils.h"

TEST(durbatuluk_tests, test_gtest)
{
  EXPECT_TRUE(true) << "law of non-contradiction failed";
}

TEST(durbatuluk_tests, test_command_from_encoded)
{
  std::string serialized, encoded, decoded;

  // This test is mainly a proof-of-concept / integration test that shows
  // that we can take an encoded string, decode it, and run it through the
  // message handler.

  // build the shell command message
  DurbatulukMessage input, parsed, output;
  input.set_type(MESSAGE_TYPE_SHELL_EXEC);
  input.set_contents("echo durbatuluk");
  input.set_sequence_number(SequenceManager::GetNextSequenceNumber());

  // encode the message
  input.SerializeToString(&serialized);
  ASSERT_TRUE(Encoding::EncodeMessage(serialized, encoded));

  // decode & parse the message
  ASSERT_TRUE(Encoding::DecodeMessage(encoded, decoded));
  ASSERT_TRUE(parsed.ParseFromString(decoded));

  // send the message to the message handler
  bool rv = MessageHandler::HandleMessage(parsed, output);
  ASSERT_TRUE(rv) << "HandleMessage failed";

  // check the result
  EXPECT_STREQ(output.type().c_str(), MESSAGE_TYPE_SHELL_EXEC_OUTPUT);
  EXPECT_EQ(output.contents().find("durbatuluk"), (size_t)0);
}

TEST(durbatuluk_tests, test_usage)
{
  std::stringstream ss;
  usage(ss);
  EXPECT_GT(ss.str().length(), (size_t)200);
}

TEST(durbatuluk_tests, test_command_line_processing)
{
  std::stringstream ss; // used for key name then as fake for std::cout

  // generate key name
  ss << time(nullptr);
  std::string key_name("test_");
  key_name += ss.str();

  // set a test configuration file name

  std::string conf_file_name("test_");
  conf_file_name += ss.str();
  conf_file_name += ".conf";
  ASSERT_TRUE(ConfigurationManager::SetConfigurationFileName(conf_file_name));

  std::string safety_check;
  ASSERT_TRUE(ConfigurationManager::GetConfigurationFileName(safety_check));
  ASSERT_STREQ(conf_file_name.c_str(), safety_check.c_str());

  // generate the keyfiles

  const char* argv0 = "./durbatuluk";
  const char* argv1 = "--generate-keyfiles";

  const int ARGC = 3;
  const char* argv[ARGC];
  argv[0] = argv0;
  argv[1] = argv1;
  argv[2] = key_name.c_str();

  ASSERT_TRUE(generate_keyfiles(ARGC, (char**)argv, ss));

  // extract the public key

  // TODO: under construction

  // write the test configuration file

  ASSERT_TRUE(Utils::WriteToFile(
    conf_file_name, std::string("under construction")));

  // remove the test files

  EXPECT_TRUE(remove((key_name + ".public").c_str()) == 0);
  EXPECT_TRUE(remove((key_name + ".private").c_str()) == 0);
  EXPECT_TRUE(remove(conf_file_name.c_str()) == 0);
}
