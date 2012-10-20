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

#ifndef SEQUENCE_MANAGER_H_
#define SEQUENCE_MANAGER_H_

// There are two ways to get and to set sequence numbers.  The first way is to
// set the minimum allowed sequence number.  This typically would be used
// in a scenario where a client is only allowed to process numbers greater
// than the last number processed to prevent replays.  The second way is to
// set allowed sequence numbers explicitly.  This would be used for
// a commander to remember which sequence numbers are outstanding in waiting
// for responses.  If EITHER condition matches (sequence number is greater
// than minimum or sequence number is explicitly allowed), the sequence
// number should be allowed.  For this reason, commanders will probably want
// to set the minimum allowed sequence number to 2^64 - 1.

#define SEQUENCE_NUMBER_MAX 0Xffffffffffffffff

#include <set>
#include <string>

class SequenceManager
{
public:
  static bool IsSequenceNumberAllowed(unsigned long long n);
  static bool SetMinimumAllowedSequenceNumber(unsigned long long n);
  static bool AddToAllowedSequenceNumbers(unsigned long long n);
  static bool RemoveFromAllowedSequenceNumbers(unsigned long long n);

private:
  static bool ReadSequenceNumberFile(
    std::string& filename, unsigned long long& minimum,
    std::set<unsigned long long>& allowed_numbers);
  static bool WriteSequenceNumberFile(
    std::string& filename, unsigned long long minimum,
    std::set<unsigned long long>& allowed_numbers);
};

#endif // #ifndef SEQUENCE_MANAGER_H_

