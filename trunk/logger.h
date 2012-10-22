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

#ifndef LOGGER_H_
#define LOGGER_H_

#include <string>
#include <sstream>

enum LoggerSeverity { DEBUG, INFO, ERROR };

class Logger
{
public:
  static void LogMessage(LoggerSeverity severity,
    const std::string& component, const std::string& message);

  // this version empties the stringstream so that it can be reused
  static void LogMessage(LoggerSeverity severity,
    const std::string& component, std::stringstream& message);

  static void SetMinLoggingSeverity(LoggerSeverity severity)
  {
    min_logging_severity_ = severity;
  }

private:
  static LoggerSeverity min_logging_severity_;
};

#endif // #ifndef LOGGER_H_
