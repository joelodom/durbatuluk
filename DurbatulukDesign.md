# Protocol Design #

The following diagram depicts how Durbatulûk commands are encapsulated in various layers of overhead used in message handling and to provide security.

'<img width='40%' src='http://durbatuluk.googlecode.com/svn/images/Durbatuluk%20Protocol%20Diagram.png'>'<br>
<br>
The fundamental unit of the Durbatulûk protocol is the <code>DurbatulukMessage</code>, defined as<br>
<br>
<pre><code>message DurbatulukMessage {<br>
  required string type = 1;<br>
  required string contents = 2;<br>
  required uint64 sequence_number = 3;<br>
}<br>
</code></pre>

The only currently implemented message type is <code>ShellExec</code>, though future message types are likely.  The contents field of a <code>DurbatulukMessage</code> contains the message contents as a string.  In the case of a <code>ShellExec</code> message, this is a command to pass to the command interpreter.<br>
<br>
The sequence number is used to prevent replay attacks.  Sequence numbers need not be strictly sequential (they could be based on the number of seconds since some epoch).  A Durbatulûk client will drop <code>ShellExec</code> messages if the sequence number of the message is not greater than the last sequence number processed.  (Commanders should set their last sequence number processed to <code>2^64^ - 1</code> as a safety precaution against accidentally processing <code>ShellExec</code> messages.  There is a provision to allow commanders to allow specific sequence numbers in order to process replies from clients, but this feature is under development.)  Sequence number information is saved in a sequence file so that it persists between Durbatulûk executions.<br>
<br>
Durbatulûk messages are encapsulated in an <code>EncryptedMessage</code>, defined as<br>
<br>
<pre><code>message EncryptedMessage {<br>
  required RSAKey recipient = 1;<br>
  required bytes encrypted_key = 2;<br>
  required bytes encrypted_contents = 3;<br>
}<br>
</code></pre>

The recipient's public RSA key is included in the encrypted message so that recipients can identify messaged intended for them.  The <code>RSAKey</code> message type, used in <code>EncryptedMessage</code>, will be explained below.<br>
<br>
When a Durbatulûk client verifies that an encrypted message is intended for it, the client uses the RSA decryption algorithm to decrypt the encrypted symmetric key, which in turn is used to decrypt the encrypted contents of the encrypted message.  These encrypted contents are the serialized form of the encapsulated <code>DurbatulukMessage</code>.<br>
<br>
Encrypted messages are encapsulated in a <code>SignedMessage</code>, defined as<br>
<br>
<pre><code>message SignedMessage {<br>
  required RSAKey sender = 1;<br>
  required bytes contents = 2;<br>
  required bytes signature = 3;<br>
}<br>
</code></pre>

The sender field of the signed message is the public signing key of the sender of the message.  This allows clients to verify that the contents of the message are authentic.<br>
<br>
When a client first receives a message, it verifies that the sender of the message is an authorized sender by checking the sender public key against the allowed senders in the client's Durbatulûk configuration file.  If this is true, signature verification and decryption take place.  After this process, the client verifies that the sender of the message is allowed to send the particular message type in the encapsulated <code>DurbatulukMessage</code>.<br>
<br>
After a commander generates a signed message, the message is encoded using base64 for convenience.  There is a large amount of overhead after encapsulation of a single command as described above, but most of this is due to the inclusion of public keys in the messages and does not grow faster than the size of the message.  Encryption algorithm randomization notwithstanding, the <code>ShellExec</code> command "echo hello" grows to:<br>
<br>
<pre><code>&lt;durbatuluk&gt;CogCCoAC9bKbkyo+sKhlu5HPHZYpIZVntKY6YesnXDWsjbyMnEYCnqkCjBVAPKYLCGvUln560alF/Ax0DwI24gl0rda8CsdeYkldHbhYIKVJsE3wcKBo04iIjeR/Bco7MkTWI+cEeM8z0zU6MO4YcNm2r2/lOuVHoYO/IPQlt4XYtlodE7xwVduAd3viSN2ZTV2RwDMp39pWju9WxfZVHrFN5ELkCiRQl/CXFzsz8MnCA7sdvk7cRIjYKLpnY9d2wgjWETC3CBBEI6AIjAx6fmF8TPw1v5NXO5WW+fjNOruMvjgqe0syuC56SMpggFaBFNYH3b4bFL9/m2aUA29rUldpMzZElxIDAQABErAECogCCoACwMIeIgNzjr8QILQ+RDVCm8WztSvOOVzN8ULYwqYu/Gm/MqD4HL8A2D8vtd8lNFlklyvO+HHT8gRhldccBh5vQop3aIHIyx0sL4eu8dFDpBqziYPZKis0OUAE61+ahMY+31rKnxUqjn6wbVFcIziSC3fxUp506S9eBD5+ioe7yaecNIsiC+6AB75UT/GUVm+ysa1o1kXZoquBBUf9c3fp9QgRvGhMxWh+q8FaRV8HM8VEmlzr0OHpokgjSqFV8XcgicfQKlxC1kCQ2RzrxDp95cVnXADgSOEzR1566m28fV/tbQ0o1V9BVunJaT6S7Dm9itd2nsL7P6enDhmfs+N2/xIDAQABEoACUWFL5fGphKdwSccZMhHahl+ppTqbO0yaWAmMJ8EdJRY5lkIvcNhtjorJZAJuyYfqGsC/OLpgRFMVL5d9E6tl1na0Db093DBbwtNhknlD1z6ofKoPmY1vqB5Hcne1xmF/6Uo4l2u5HyZm5toygJ7ajN+8XeJ/5RybYy0UsY/VIMZR+SvO7r5A4qFRhKbLoVkASOYdfMcjGvqLgrDeKSNkdHzhOFoklINAfIyC9oC0esVL77no24svpmLt/YFBncyotER3JAUIg6LqENY/lyvMxlWGWTddXUeGmrjvTEtwJDOjjRYxUWfILrDE9Ejx0cKw/bbi0HxT6VGgQS1RvK7OKBogVXpeAo+LRnK/3ZNO9yVgE8Zymamj14nK+YxFdqPPe6wagAJwBZ3HSvVeZ+a60CuV5Gg6A4KBuJ2DieS8LjVFZaMQrRjU7VPeZFbj8h2tpcTefVvaS1+1Zbb0S8wPN4D25YodCsbsoJnrHNwwLZmNFnRKp2SBHk6KFuTze/DG6Wjpynwap1ETqRM/XyExYsVEsi7ZH6J4mp3gK58H3Hoeh+dFgjnVHZVN2WhsHKRAlAFLELVADMHEHRfaqI1GhSqQJULIcuU0mfqxdvhLCgIolGkE8p3E0uIZsX9//yB3qCTVHLdqtIj9Tp+XhQbE9dLKmPdZjfEaYN/vIDP6AIl6GsGGOyca0x8D5xjikn24lZIhGgCrfsdRg2BSpdrfj85W2Wq4&lt;/durbatuluk&gt;<br>
</code></pre>

The inclusion of the XML-like starting and ending tags are for convenience in embedding messages in XML, should the need arise.<br>
<br>
The <code>RSAKey</code> message, used for storing public and private RSA keys for encryption and signing  is defined as<br>
<br>
<pre><code>message RSAKey {<br>
  // public parameters<br>
  required bytes n = 1;<br>
  required bytes e = 2;<br>
<br>
  // private parameters<br>
  optional bytes d = 3;<br>
  optional bytes p = 4;<br>
  optional bytes q = 5;<br>
  optional bytes dmp1 = 6;<br>
  optional bytes dmq1 = 7;<br>
  optional bytes iqmp = 8;<br>
}<br>
</code></pre>

RSA keys in signed messages and in encrypted messages do not include the optional parameters, but these are included when the structure is serialized to private key files.<br>
<br>
For more information on Durbatulûk security, see SecurityFeatures.<br>
<br>
<h1>Modular Architecture</h1>

As of the time of this writing, Durbatulûk is broken into one main file (durbatuluk.cc) and ten modules.  Each module is coded as a separate C++ static class. <i>The implementations below may have changed slightly since the writing of this document, so please consult the source code for the latest versions.</i>

<h2>Message Handler Module</h2>

The message handler handles Durbatulûk messages after they have been decrypted.  There is one main function on this module, <code>HandleMessage</code>, which processes an incoming message and generates an output message.  An optional callback function allows users of the message handler to process separately the type and contents of a message.  This is the module to change to make simple Durbatulûk customizations.  See CustomizingDurbatuluk.<br>
<br>
<pre><code>typedef bool (*MessageHandlerCallback)(<br>
  const std::string&amp; type, const std::string&amp; contents);<br>
<br>
static bool HandleMessage(const DurbatulukMessage&amp; input,<br>
  DurbatulukMessage&amp; output, MessageHandlerCallback callback = nullptr);<br>
</code></pre>

<h2>Cryptographic Module</h2>

The cryptographic module is the main module for performing cryptographic functions.  It is used by the main functions and other modules to perform the functions noted in the comments below.<br>
<br>
<pre><code>// methods to convert between OpenSSL and protocol buffers<br>
static bool ExtractPublicRSAKey(RSA* rsa, RSAKey&amp; public_key);<br>
static bool ExtractPrivateRSAKey(RSA* rsa, RSAKey&amp; private_key);<br>
static bool ImportRSAKey(const RSAKey&amp; rsa_key, RSA* rsa);<br>
<br>
// methods to create and to verify a protocol buffers SignedMessage<br>
static bool CreateSignedMessage(<br>
  std::string&amp; contents, RSA* rsa, SignedMessage&amp; signed_message);<br>
static bool VerifySignedMessage(SignedMessage&amp; signed_message);<br>
<br>
// methods to encrypt and to decrypt a protocol buffers EncryptedMessage<br>
static bool EncryptMessage(RSAKey&amp; recipient_public_key,<br>
  std::string&amp; contents, EncryptedMessage&amp; encrypted_message);<br>
static bool DecryptMessage(RSA* rsa, EncryptedMessage&amp; encrypted_message,<br>
  std::string&amp; decrypted);<br>
<br>
// method to extract a hash of a public key<br>
static bool HashRSAKey(const RSAKey&amp; key, std::string&amp; encoded_hash);<br>
</code></pre>

<h2>Processing Engine</h2>

The processing engine provides methods to bundle common Durbatulûk patterns into individual methods.<br>
<br>
<pre><code>// method to generate a DurbatulukMessage<br>
static bool GenerateEncodedDurbatulukMessage(const std::string&amp; type,<br>
  const std::string&amp; contents, RSAKey&amp; recipient_public_key,<br>
  RSA* sender_signing_key, std::string&amp; encoded_message,<br>
  unsigned long long&amp; sequence_number);<br>
<br>
// method to handle an encoded message with message handler<br>
// (doesn't generate encoded response, but passes on message handler output<br>
// and callback)<br>
static bool HandleIncomingEncodedMessage(<br>
  std::string&amp; encoded_incoming, RSA* recipient_private_encryption_key,<br>
  DurbatulukMessage&amp; output, MessageHandlerCallback callback = nullptr);<br>
<br>
// methods to perform a full Durbatuluk circle of encryption and encoding<br>
static bool EncryptSignAndEncode(std::string&amp; message,<br>
  RSAKey&amp; recipient_public_key, RSA* sender_signing_key,<br>
  std::string&amp; encoded);<br>
static bool DecodeVerifyAndDecrypt(std::string&amp; encoded,<br>
  RSA* recipient_private_encryption_key, DurbatulukMessage&amp; message);<br>
</code></pre>

<h2>Encoding Module</h2>

The encoding module performs base64 encoding and decoding.<br>
<br>
<pre><code>static bool EncodeMessage(const std::string&amp; input, std::string&amp; output);<br>
static bool DecodeMessage(const std::string&amp; input, std::string&amp; output);<br>
</code></pre>

<h2>Sequence Manager Module</h2>

The sequence manager encapsulates handling of sequence numbers, which are used to prevent replay attacks.  This module interacts with the sequence number file to persist sequence numbers between Durbatulûk sessions.<br>
<br>
<pre><code>static unsigned long long GetNextSequenceNumber();<br>
<br>
// returns true if allowed, false if disallowed or error<br>
static bool IsSequenceNumberAllowed(unsigned long long n);<br>
<br>
static bool SetMinimumAllowedSequenceNumber(unsigned long long n);<br>
static bool AddToAllowedSequenceNumbers(unsigned long long n);<br>
static bool RemoveFromAllowedSequenceNumbers(unsigned long long n);<br>
<br>
static bool ResetSequenceNumberFile();<br>
</code></pre>

<h2>Configuration Manager</h2>

The configuration manager parses the configuration file and provides an interface to the parameters in the configuration file.<br>
<br>
<pre><code>static bool ReadConfigurationFile(std::string&amp; config_file_name);<br>
<br>
static bool GetSequenceNumberFileName(std::string&amp; file_name);<br>
<br>
static bool GetConfigurationFileName(std::string&amp; file_name);<br>
static bool SetConfigurationFileName(std::string&amp; file_name);<br>
<br>
static bool GetPostMessageURL(std::string&amp; url);<br>
static bool GetFetchMessageURL(std::string&amp; url);<br>
static bool GetMySigningKeyName(std::string&amp; name);<br>
static bool GetMyEncryptionKeyName(std::string&amp; name);<br>
<br>
// The idea is to allow an initial check of the sender, followed<br>
// by a check of the sender and message type pair.  This double<br>
// check reduces attack surface.<br>
static bool IsSenderAllowed(const RSAKey&amp; sender);<br>
static bool IsSenderAllowedToSendMessageType(<br>
  const RSAKey&amp; sender, const std::string&amp; type);<br>
<br>
// AllowSender is mostly for testing purposes<br>
static bool AllowSender(RSA* rsa, const std::string&amp; type);<br>
</code></pre>

<h2>KeyFile Module</h2>

The key file module reads and writes Durbatulûk key files.<br>
<br>
<pre><code>static bool WriteKeyFiles(const std::string&amp; key_name, RSA* rsa);<br>
static bool ReadPublicKeyFile(const std::string&amp; key_name, RSAKey&amp; key);<br>
static bool ReadPrivateKeyFile(const std::string&amp; key_name, RSAKey&amp; key);<br>
</code></pre>

<h2>NetFetcher Module</h2>

The net fetcher module wraps <code>libcurl</code> to allow for easy HTTP gets and puts so that Durbatulûk clients and commanders can interact with Durbatulûk servers.<br>
<br>
<pre><code>static bool FetchURL(const std::string&amp; url, std::string&amp; contents);<br>
<br>
// Input command should not be escaped.  For example,<br>
// &lt;durbatuluk&gt;Cog/5+8/sFo==&lt;/durbatuluk&gt; as input command<br>
// will be posted as<br>
// message=%3Cdurbatuluk%3ECog%2F5%2B8%2FsFo%3D%3D%3C%2Fdurbatuluk%3E<br>
static bool PostMessageToURL(<br>
  const std::string&amp; url, const std::string&amp; message);<br>
</code></pre>

<h2>Logger Module</h2>

The logger module is for logging different types messages.  The minimum severity of log messages may be set via the configuration file.<br>
<br>
<pre><code>enum LoggerSeverity { DEBUG, INFO, ERROR, NONE };<br>
<br>
static void LogMessage(LoggerSeverity severity,<br>
  const std::string&amp; component, const std::string&amp; message);<br>
<br>
// this version empties the stringstream so that it can be reused<br>
static void LogMessage(LoggerSeverity severity,<br>
  const std::string&amp; component, std::stringstream&amp; message);<br>
<br>
static void SetMinLoggingSeverity(LoggerSeverity severity);<br>
</code></pre>

<h2>Utility Module</h2>

Miscellaneous utility methods should be placed here.<br>
<br>
<pre><code>static bool WriteToFile(<br>
  const std::string&amp; file_name, const std::string&amp; data);<br>
</code></pre>

<h1>Command Line Parameters & Configuration File</h1>

In the current implementation of Durbatulûk, commanders use a combination of command line parameters and <code>stdio</code> to specify inputs to the system that are likely to change for each run of Durbatulûk.  Parameters that are static for a particular commander or client are stored in a configuration file, which is currently always named <code>durbatuluk.conf</code>.<br>
<br>
For details of the command line parameters and configuration file, see GettingStarted.  The <a href='http://durbatuluk.googlecode.com/svn/trunk/durbatuluk.conf'>default configuration file that ships with Durbatulûk</a> also contains comments that explain the configuration options.  Running Durbatulûk with no command line parameters will list the available parameters and their usage.<br>
<br>
The configuration file, which may contain comments, is always read by Durbatulûk at startup.  If reading or parsing the configuration file fails, Durbatulûk will exit with an error.<br>
<br>
<h1>Extensibility</h1>

See CustomizingDurbatuluk.