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
#include <iostream>

/*static*/ LoggerSeverity Logger::min_logging_severity_ = ERROR;

/*static*/ void Logger::LogMessage(LoggerSeverity severity,
  const std::string& component, const std::string& message)
{
  // TODO: make stream a static object so that we don't recreate every time,
  // set run-time logging level changes, etc...

  if (severity < min_logging_severity_)
    return;

  std::ostream stream(std::cerr.rdbuf());

  switch (severity)
  {
    case DEBUG:
      stream << "DEBUG: ";
      break;
    case INFO:
      stream << "INFO: ";
      break;
    case ERROR:
      stream << "ERROR: ";
      break;
  }

  stream << component << ": " << message << std::endl;
}

/*static*/ void Logger::LogMessage(LoggerSeverity severity,
    const std::string& component, std::stringstream& message)
{
  LogMessage(severity, component, message.str());
  message.str("");
}
