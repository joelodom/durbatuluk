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

#include "logger.h"
#include "message_handler.h"
#include <sstream>

/*static*/ bool MessageHandler::HandleMessage(
  const DurbatulukMessage& input, DurbatulukMessage& output,
  MessageHandlerCallback callback /*= nullptr*/)
{
  std::stringstream ss;
  ss << "Entering HandleMessage (type " << input.type() << ")";
  Logger::LogMessage(INFO, "MessageHandler", ss.str());

  if (input.type() == MESSAGE_TYPE_SHELL_EXEC)
  {
    std::string shell_exec_output;
    if (ShellExec(input.contents(), shell_exec_output))
    {
      ss.str("");
      ss << "ShellExec output begins " << shell_exec_output.substr(0, 20);
      Logger::LogMessage(DEBUG, "MessageHandler", ss.str());

      output.set_type(MESSAGE_TYPE_SHELL_EXEC_OUTPUT);
      output.set_contents(shell_exec_output);
      return true; // success
    }

    return false; // ShellExec failed
  }

  if (input.type() == MESSAGE_TYPE_SHELL_EXEC_OUTPUT)
  {
    ss.str("");
    ss << MESSAGE_TYPE_SHELL_EXEC_OUTPUT << " contents begins "
      << input.contents().substr(0, 20);
    Logger::LogMessage(DEBUG, "MessageHandler", ss.str());

    ss.str("");
    ss << "Attempting to callback (callback IS "
      << (callback != nullptr ? "NOT " : "") << "NULL)";
    Logger::LogMessage(DEBUG, "MessageHandler", ss.str());

    // kick back to caller

    bool rv = callback == nullptr ? false
      : callback(input.type(), input.contents());

    ss.str("");
    ss << "Callback returned " << rv;
    Logger::LogMessage(DEBUG, "MessageHandler", ss.str());

    return rv;
  }

  return false; // problem
}

/*static*/ bool MessageHandler::ShellExec(
  const std::string& input, std::string& output)
{
  FILE* fp = popen(input.c_str(), "r");
  if (fp == NULL)
    return false;

  char buf[1024];
  while (fgets(buf, sizeof(buf), fp) != nullptr)
    output.append(buf);

  pclose(fp);

  return true; // success
}
