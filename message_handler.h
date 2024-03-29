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

#ifndef MESSAGE_HANDLER_H_
#define MESSAGE_HANDLER_H_

#include "durbatuluk.pb.h"
#include <string>

#define MESSAGE_TYPE_SHELL_EXEC "ShellExec"
#define MESSAGE_TYPE_SHELL_EXEC_OUTPUT "ShellExecOutput"

//
// The message handler is the main class that does the work.  This is the class
// to change in order to implement custom message handling.
//

typedef bool (*MessageHandlerCallback)(
  const std::string& type, const std::string& contents);

class MessageHandler
{
public:
  static bool HandleMessage(const DurbatulukMessage& input,
    DurbatulukMessage* output, MessageHandlerCallback callback = nullptr);
  static bool ShellExec(const std::string& input, std::string* output);
};

#endif // #ifndef MESSAGE_HANDLER_H_
