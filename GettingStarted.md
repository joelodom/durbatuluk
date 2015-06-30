# Introduction #

Durbatulûk is currently in a development phase.  This means that you are welcome to experiment with it -- and it does function now at a very basic level -- but you'll have to know how to build a binary from source code and how to deal with a Linux shell terminal to use it from the command line.

The following instructions are fairly technical, and are really meant to be a tutorial on how Durbatulûk works.  Be on the lookout for packaged installers for Linux and Windows with more user-friendly interfaces.  Durbatulûk needs some more development spit-and-polish before I feel ready to post a downloadable installer.  For now, use the "Source" link above to fetch the trunk via Subversion.

# Building Durbatulûk #

The current version of Durbatulûk under development on Ubuntu Linux with portability a primary consideration in the research and development process.  In theory you should be able to build the software on a number of different systems, but this document assumes that you are using Ubuntu.

First, install the prerequisite Ubuntu libraries using your package manager:

  * `libprotobuf-dev`
  * `libssl-dev`
  * `libcurl4-openssl-dev`

After installing the above libraries, speak `make` and enter.

# Testing Durbatulûk Basic Functionality #

After you have a Durbatulûk binary, run the binary with no parameters.  You should get a usage message that looks something like this:

```
 = Durbatuluk 0.0.0 Pre-Alpha =

Durbatuluk is Copyright (c) 2012 Joel Odom, Marietta, GA
See LEGAL.txt for license details.
http://durbatuluk.googlecode.com/

Usage:
  durbatuluk --tests (running this will reset sequence file)
  durbatuluk --generate-keyfiles <key_name>
  durbatuluk --extract-public-key <key_name>
  durbatuluk --generate-shell-command <recipient_encryption_key> (command text read from stdin)
  durbatuluk --post-shell-command <recipient_encryption_key> (command text read from stdin)
  durbatuluk --process-message (encoded command read from stdin)
  durbatuluk --process-messages-from-url
  durbatuluk --reset-sequence-numbers
```

If you get an error message, let me know.  Next, try the suite of self tests using the `--tests` parameter.  The testing procedure will end with something like this:

```
[----------] Global test environment tear-down
[==========] 27 tests from 9 test cases ran. (11914 ms total)
[  PASSED  ] 27 tests.
```

If Durbatulûk reports failure of any tests, let me know.  (You may see some ERROR messages during the testing process.  This is normal as the testing process tests for proper functioning under certain error conditions, but the end of the test script should report no failures.)

# Configuring a Durbatulûk Commander #

Once you have verified that Durbatulûk passes the self-tests, you need to configure your Durbatulûk commander.  (This is where you could branch away from these instructions to try different configurations.  This guide will explain how to configure Durbatulûk for a single client and a single commander.)

## Generating Key Files ##

In this example, I will be making key files named `commander.signing` and `commander.encryption`.  When you use the `--generate-keyfiles` parameter to generate a key pair, you will get two files, one ending in .public and one ending in .private.  You should obviously keep the .private key files private.  The .public key files will be used by other members of the system and need not be kept secret.

First, generate your signing key pair:

```
./durbatuluk --generate-keyfiles commander.signing
```

Next, generate your encryption key pair:

```
./durbatuluk --generate-keyfiles commander.encryption
```

It is possible to use the same key pair for signing and encryption, but not recommended.  Just to reinforce the point, let's lock down the private key files:

```
chmod 400 *.private
```

In your folder, you should see something like this:

```
-rw-rw-r--  1 joelodom joelodom    264 Oct 26 07:03 commander.signing.public
-r--------  1 joelodom joelodom   1178 Oct 26 07:03 commander.signing.private
-rw-rw-r--  1 joelodom joelodom    264 Oct 26 07:04 commander.encryption.public
-r--------  1 joelodom joelodom   1176 Oct 26 07:04 commander.encryption.private
```

Now we need to extract a digest of the commander's signing key from the public signing key.  Use this command:

```
./durbatuluk --extract-public-key commander.signing
```

The output from this function is a bit ugly because there is purposefully no whitespace in the output written to `std::cout`.  Here's what it looks like on my system:

```
joelodom@ubuntu:~/Dropbox/InfoSecLab/durbatuluk$ ./durbatuluk --extract-public-key commander.signing
Pa/YE5f3zefx1KunIEhtVPlNZ00=joelodom@ubuntu:~/Dropbox/InfoSecLab/durbatuluk$
```

The part that matters is the hash that, for my commander, came out to `Pa/YE5f3zefx1KunIEhtVPlNZ00=`.  These 28 byte, which will be used in the configuration files of your clients, must be copied _exactly_ as you see them, with no spaces.

## Editing the Commander Configuration File ##

Edit your `durbatuluk.conf` file so that it has lines in it that look something like this:

```
allow_message ShellExec Pa/YE5f3zefx1KunIEhtVPlNZ00=
logging_severity ERROR
post_message_url http://durbatuluk-server.appspot.com/post
fetch_message_url http://durbatuluk-server.appspot.com/fetch
my_signing_key_name commander.signing
my_encryption_key_name commander.encryption
```

The current configuration file parser is overly strict about whitespace, so make sure that you don't put any extra spaces in the lines above.  The second `allow_message` parameter should be the digest of your public signing key that we just generated.  Normally we would not include an allowance for `ShellExec` in a commander's configuration, but we're going to demonstrate Durbatulûk by having our commander send itself commands.

## Reset Your Sequence Number File ##

The sequence number file is used by Durbatulûk to prevent busybodies from trying to fool with your clients (and commander) by sending replays of old Durbatulûk messages.  Every time you run Durbatulûk tests, your sequence number file is going to get goofed, so you must reset it as follows:

```
./durbatuluk --reset-sequence-numbers
```

Do this now for your commander.

## Sending Yourself a Command via the Command Line ##

Durbatulûk normally processes by posting and fetching from a web server, but we can also do this using the command line.  This section demonstrates how to send yourself a command over the command line.

First, understand that Durbatulûk uses `std::cin` to read the content of commands.  In Linux, we use a pipe to make this happen.

```
echo "echo Hello, World" | ./durbatuluk --generate-shell-command commander.encryption >hello_world.message
```

If you type the above, Durbatulûk does the following:

  1. Reads the command `echo Hello, World` from `std::cin`.
  1. Generates a Durbatulûk message intended for `commander.encryption`
  1. Writes the message to the file `hello_world.message`

Take a peek at the message format by typing `cat hellow_world.message`.  This gibberish is your original command with encapsulation, encryption, signing and encoding.

Now, let's process your command.  Again, Durbatulûk uses `std::cin` for receiving the command, so we will use `cat` to pipe the message to Durbatulûk.

```
cat hello_world.message | ./durbatuluk --process-message
```

If all goes as expected, you will see "Hello, world" echoed to your screen.

(Just for kicks, try processing the same command again.  You should get some errors indicating that there is a sequence number problem.  This is expected as it is part of the replay prevention feature.)

Since the Durbatulûk `--generate-shell-command` and `--process-message` commands both use stdio, you can chain your commands as follows (though it doesn't seem very useful).

```
echo "echo Hello, World" | ./durbatuluk --generate-shell-command commander.encryption | ./durbatuluk --process-message
```

## Sending Yourself a Command via a Server ##

Normally you will want to use a server to send messages between commanders and clients.  For Durbatulûk testing and demonstration purposes, I have established a lightweight server at http://durbatuluk-server.appspot.com/.  If you visit that link you will see a text area where you can manually paste a Durbatulûk message.  For five minutes after posting the message, the message will persist at http://durbatuluk-server.appspot.com/fetch.

For kicks, enter `<durbatuluk>foo</durbatuluk>` in the text area and then view it on the fetch link (the server is very picky about what you type, so don't include any whitespace).  This message is completely invalid, but it demonstrates what the server does.

Let's send our "Hello, World" message from our commander back to itself via the server.  Enter the following:

```
echo "echo Hello, World" | ./durbatuluk --post-shell-command commander.encryption
```

If all goes well, your message will appear on the fetch link above (take a look!) for about five minutes.  You must process the message within that time window, or it will disappear.

To process the message enter:

```
./durbatuluk --process-messages-from-url
```

You may see some error messages that go along with this command.  These just indicate that Durbatulûk is skipping commands that it can't process such as your "foo" command above or commands intended for other clients.  You have success if you see "Hello, World" echoed to your terminal along with a message saying how many commands were processed.  It looks something like this:

```
Hello, World

Processed 1 commands.
```

# Configuring a Durbatulûk Client #

(As of the writing of this page, clients don't actually send responses back to their commander.  This will be added in the near future.  This means that you really don't need a client signing key at the moment.  This also means that you don't need to modify the commander configuration file until the full circle of command and response is implemented.)

## Setting up Your Client and Your Commander ##

Sending yourself commands isn't very interesting.  Configuring a client is much like configuring a commander.  On your client, do the following:

  1. Build Durbatulûk as above.
  1. Generate keys as above, but name them `client.signing` and `client.encryption`.
  1. Reuse the same `durbatuluk.conf` file as you used on your commander, but change the key names.
  1. Reset your sequence number file on your client.

At this point, your client is ready to receive messages from your commander.  Copy your `client.encryption.public` file over to your commander and place it in the same folder as your Durbatulûk binary.  This sets up your commander to send commands to your client.

## Sending a Command from Commander to Client ##

Once you have configured your commander and your client, you can start sending commands.  On your commander, enter:

```
echo "echo Hello, client" | ./durbatuluk --post-shell-command client.encryption
```

On your client, enter:

```
./durbatuluk --process-messages-from-url
```

If all works as expected, you will see something like this on your client:

```
Hello, client

Processed 1 commands.
```

For kicks, repeat the `--post-shell-command` on your commander three or four times before you run `--process-messages-from-url`.  You should see your client process each of the messages in turn.

# What Now? #

Durbatulûk is coming along, and I expect to have it in a "less techie" state in the future.  See the RoadMap. For now, you can try the following.

  * Put Durbatulûk as a cron job in your client until I have running as a service implemented.
  * Have your cron job e-mail you the output of your client, or perhaps hack your client to use Durbatulûk in a sneaky way to send your output back to your commander as a command to the commander.
  * Try setting up two or three clients with the same encryption key.  Notice how they will all process the commander commands as if the commands were written only for them.

Keep in tune with this project page to stay abreast of Durbatulûk development, which will simplify the bullet ideas above and provide additional features.  If you want to contact me, you will find information at CustomizingDurbatuluk.  You may also be interested in DurbatulukDesign.