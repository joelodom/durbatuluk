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

#include "encoding.h"
#include "base64.h"

/*static*/ bool Encoding::EncodeMessage(
  const std::string& input, std::string& output)
{
  std::string encoded = base64_encode(
    reinterpret_cast<const unsigned char*>(
    input.c_str()), input.length());

  output = "<durbatuluk>";
  output.append(encoded);
  output.append("</durbatuluk>");

  return true; // success
}

/*static*/ bool Encoding::DecodeMessage(
  const std::string& input, std::string& output)
{
  if (input.length() < ENCODING_OVERHEAD + 1)
    return false; // failure
  if (input.find("<durbatuluk>") != 0)
    return false; // failure
  if (input.find("</durbatuluk>") != input.length() - 13)
    return false; // failure

  output = base64_decode(input.substr(12, input.length() - ENCODING_OVERHEAD));

  return true; // success
}
