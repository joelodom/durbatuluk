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

#include "message_handler.h"
#include "gtest/gtest.h"
#include "sequence_manager.h"

TEST(message_handler_tests, test_shell_exec)
{
  std::string input("echo durbatuluk"), output;
  bool rv = MessageHandler::ShellExec(input, output);
  ASSERT_TRUE(rv) << "ShellExec failed";
  EXPECT_EQ(output.find("durbatuluk"), (size_t)0);
}

TEST(message_handler_tests, test_handle_message_bad_message)
{
  DurbatulukMessage input, output;
  bool rv = MessageHandler::HandleMessage(input, output);
  EXPECT_FALSE(rv);
}

TEST(message_handler_tests, test_shell_command_message)
{
  // build the shell command message
  DurbatulukMessage input, output;
  input.set_type(MESSAGE_TYPE_SHELL_EXEC);
  input.set_contents("echo durbatuluk");
  input.set_sequence_number(SequenceManager::GetNextSequenceNumber());

  // send the message to the message handler
  bool rv = MessageHandler::HandleMessage(input, output);
  ASSERT_TRUE(rv) << "HandleMessage failed";

  // check the result
  EXPECT_STREQ(output.type().c_str(), MESSAGE_TYPE_SHELL_EXEC_OUTPUT);
  EXPECT_EQ(output.contents().find("durbatuluk"), (size_t)0);
}

TEST(message_handler_tests, test_shell_command_message_missing_sequence_number)
{
  // build the shell command message
  DurbatulukMessage input, output;
  input.set_type(MESSAGE_TYPE_SHELL_EXEC);
  input.set_contents("echo durbatuluk");

  // send the message to the message handler
  bool rv = MessageHandler::HandleMessage(input, output);
  EXPECT_FALSE(rv) << "HandleMessage should have failed";
}

TEST(message_handler_tests, test_shell_command_message_low_sequence_number)
{
  ASSERT_TRUE(SequenceManager::SetMinimumAllowedSequenceNumber(314));

  // build the shell command message
  DurbatulukMessage input, output;
  input.set_type(MESSAGE_TYPE_SHELL_EXEC);
  input.set_contents("echo durbatuluk");
  input.set_sequence_number(31);

  // send the message to the message handler
  bool rv = MessageHandler::HandleMessage(input, output);
  EXPECT_FALSE(rv) << "HandleMessage should have failed";
}
