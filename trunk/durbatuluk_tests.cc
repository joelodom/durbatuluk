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

#include "gtest/gtest.h"
#include "message_handler.h"
#include "base64.h"

TEST(durbatuluk_tests, test_gtest)
{
  EXPECT_TRUE(true) << "law of non-contradiction failed";
}

TEST(durbatuluk_tests, test_command_from_base64)
{
  // This test is mainly a proof-of-concept / integration test that shows
  // that we can take an encoded string, decode it, and run it through the
  // message handler.

  // build the shell command message
  DurbatulukMessage input, parsed, output;
  input.set_type(MESSAGE_TYPE_SHELL_EXEC);
  input.set_contents("echo durbatuluk");

  // encode the message
  std::string serialized;
  input.SerializeToString(&serialized);
  std::string encoded = base64_encode(
    reinterpret_cast<const unsigned char*>(
    serialized.c_str()), serialized.length());

  // decode & parse the message
  std::string decoded = base64_decode(encoded);
  ASSERT_TRUE(parsed.ParseFromString(decoded));

  // send the message to the message handler
  bool rv = MessageHandler::HandleMessage(parsed, output);
  ASSERT_TRUE(rv) << "HandleMessage failed";

  // check the result
  EXPECT_STREQ(output.type().c_str(), MESSAGE_TYPE_SHELL_EXEC_OUTPUT);
  EXPECT_EQ(output.contents().find("durbatuluk"), (size_t)0);
}
