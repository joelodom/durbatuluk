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
#include "logger.h"
#include <curl/curl.h>

/*static*/ bool NetFetcher::FetchURL(
  const std::string& url, std::string& contents)
{
  CURLcode error;
  std::stringstream ss;

  // initialize cURL

  CURL *curl = curl_easy_init();
  if (curl == nullptr)
  {
    Logger::LogMessage(ERROR, "NetFetcher", "curl_easy_init failed");
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting URL";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, FetchToString);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting callback";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &contents);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting user data";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  // perform the fetch
  error = curl_easy_perform(curl);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_perform returned " << error;
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  curl_easy_cleanup(curl);
  return true; // success
}

/*static*/ bool NetFetcher::PostCommandToURL(
  const std::string& url, const std::string& command)
{
  CURLcode error;
  std::stringstream ss;

  // initialize cURL

  CURL *curl = curl_easy_init();
  if (curl == nullptr)
  {
    Logger::LogMessage(ERROR, "NetFetcher", "curl_easy_init failed");
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting URL";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, FetchToString);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting callback";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  error = curl_easy_setopt(curl, CURLOPT_POST, 1);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting callback";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  char* escaped = curl_easy_escape(curl, command.c_str(), command.length());
  if (escaped == nullptr)
  {
    Logger::LogMessage(ERROR, "NetFetcher", "curl_easy_escape failed");
    return false; // failure
  }

  std::string postdata("command=");
  postdata += escaped;
  curl_free(escaped);

  error = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str());
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting user data";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  error = curl_easy_setopt(
    curl, CURLOPT_POSTFIELDSIZE, postdata.length());
  if (error != CURLE_OK)
  {
    ss << "curl_easy_setopt returned " << error << " setting user data";
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  // perform the fetch
  error = curl_easy_perform(curl);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_perform returned " << error;
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  long http_code = 0;
  error = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (error != CURLE_OK)
  {
    ss << "curl_easy_getinfo returned " << error;
    Logger::LogMessage(ERROR, "NetFetcher", ss);
    return false; // failure
  }

  curl_easy_cleanup(curl);

  if (http_code != 200)
  {
    ss << "curl status code: " << http_code;
    Logger::LogMessage(ERROR, "NetFetcher", ss);
  }

  return true; // success
}

// thanks ...libkml/source/browse/trunk/examples/hellonet/curlfetch.cc
/*static*/ size_t NetFetcher::FetchToString(
  void* ptr, size_t size, size_t nmemb, void* user)
{
  size_t nbytes = size * nmemb;
  std::string *output_buffer = reinterpret_cast<std::string*>(user);
  output_buffer->append(reinterpret_cast<char*>(ptr), nbytes);
  return nbytes;
}
