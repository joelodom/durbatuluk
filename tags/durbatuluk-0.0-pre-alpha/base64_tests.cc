// This file may be modified from its original version -- JVO

/*
   base64.cpp and base64.h

   Copyright (C) 2004-2008 Ren� Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   Ren� Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

#include "base64.h"
#include <iostream>
#include "gtest/gtest.h"

TEST(base64_tests, test_base64)
{
  const std::string s = "ADP GmbH\nAnalyse Design & Programmierung\n"
    "Gesellschaft mit beschr�nkter Haftung";
  std::string encoded = base64_encode(
    reinterpret_cast<const unsigned char*>(s.c_str()), s.length());
  std::string decoded = base64_decode(encoded);
  EXPECT_STREQ(s.c_str(), decoded.c_str());
}

TEST(base64_tests, test_base64_with_whitespace)
{
  const std::string s = "ADP GmbH\nAnalyse Design & Programmierung\n"
    "Gesellschaft mit beschr�nkter Haftung";
  const std::string encoded("QURQIEdtYkgKQW5hbHlzZSBEZXNpZ24g   JiBQcm9ncm"
    "FtbWllcnVuZwpH\r\nZXNl\tbGxzY2hhZnQgbWl0IGJlc2NocuRua3RlciBIYWZ0dW5n");
  std::string decoded = base64_decode(encoded);
  EXPECT_STREQ(s.c_str(), decoded.c_str());
}
