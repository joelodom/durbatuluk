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

#ifndef NET_FETCHER_H_
#define NET_FETCHER_H_

#include <string>

class NetFetcher
{
public:
  static bool FetchURL(const std::string& url, std::string& contents);

  // Input command should not be escaped.  For example,
  // <durbatuluk>Cog/5+8/sFo==</durbatuluk> as input command
  // will be posted as
  // message=%3Cdurbatuluk%3ECog%2F5%2B8%2FsFo%3D%3D%3C%2Fdurbatuluk%3E
  static bool PostMessageToURL(
    const std::string& url, const std::string& message);

private:
  static size_t FetchToString(void* ptr, size_t size, size_t nmemb, void* user);
};

#endif // #ifndef NET_FETCHER_H_
