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

#include "net_fetcher.h"
#include "gtest/gtest.h"
#include <sstream>

TEST(net_fetcher_tests, test_fetch_url)
{
  std::string url("http://durbatuluk-server.appspot.com/"), contents;
  ASSERT_TRUE(NetFetcher::FetchURL(url, contents));
  EXPECT_TRUE(contents.find("<html>") != contents.npos);
}

TEST(net_fetcher_tests, test_post_command_to_url)
{
  std::string url("http://durbatuluk-server.appspot.com/post");

  std::stringstream ss;
  ss << time(nullptr);
  std::string time_str(ss.str());

  // stringstream giving strange results, so use inefficient string handling
  std::string command("<durbatuluk>joelwashere");
  command += time_str;
  command += "/+=</durbatuluk>";

  // post
  ASSERT_TRUE(NetFetcher::PostCommandToURL(url, command));

  // check log that post went through
  std::string contents;
  ASSERT_TRUE(NetFetcher::FetchURL("http://durbatuluk-server.appspot.com/log",
    contents));
  EXPECT_TRUE(contents.find(time_str) != contents.npos);
}
