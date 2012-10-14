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
#include "gtest/gtest.h"
#include <fstream>

TEST(keyfile_tests, test_write_keyfiles)
{
  // generate an RSA key
  RSA* rsa = RSA_generate_key(RSA_BITS, RSA_G, nullptr, nullptr);
  ASSERT_TRUE(rsa != nullptr);

  // generate the key files
  std::string key_name("__test_keyfiles__");
  ASSERT_TRUE(KeyFile::WriteKeyFiles(key_name, rsa));

  // check and delete the test key files

  {
    std::string file_name(key_name);
    file_name += ".public";
    std::ifstream file(file_name);
    ASSERT_TRUE(file.good());
    EXPECT_TRUE(remove(file_name.c_str()) == 0);
  }

  {
    std::string file_name(key_name);
    file_name += ".private";
    std::ifstream file(file_name);
    ASSERT_TRUE(file.good());
    EXPECT_TRUE(remove(file_name.c_str()) == 0);
  }
}
