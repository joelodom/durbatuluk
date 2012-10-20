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

#include "sequence_manager.h"
#include "gtest/gtest.h"

TEST(sequence_manager_tests, test_set_get_minimum_allowed_sequence_number)
{
  const int N = 31415;

  ASSERT_TRUE(SequenceManager::SetMinimumAllowedSequenceNumber(N));
  EXPECT_TRUE(SequenceManager::IsSequenceNumberAllowed(N));
  EXPECT_FALSE(SequenceManager::IsSequenceNumberAllowed(N - 1));

  ASSERT_TRUE(SequenceManager::SetMinimumAllowedSequenceNumber(
    SEQUENCE_NUMBER_MAX));
  EXPECT_FALSE(SequenceManager::IsSequenceNumberAllowed(N));
}

