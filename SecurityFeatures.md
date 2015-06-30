# Message Integrity & Sender Authentication #

The most important security guarantee offered by Durbatulûk is the guarantee against forgery of messages.  If an attacker learns how to forge a message, the security of the entire system is broken because that attacker can control clients or send spoofed messages to commanders.

Durbatulûk provides protection against message forgery using digital signatures.  Once an encrypted message is generated (see the sections on message confidentiality and protocol design), the message is serialized to a string of bytes and is then hashed using the SHA-1 algorithm.  This hash is signed using the RSA algorithm under PKCS#1 with 2048-bit signing keys.  The following code snippet shows how we do this using OpenSSL.

```
// sign the contents
unsigned char digest[SHA_DIGEST_LENGTH];
SHA1((const unsigned char*)contents.c_str(), contents.length(), digest);
if (RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sigret, &siglen, rsa) != 1)
  return false; // failure
```

After generating the signature, Durbatulûk packs the message contents, signature, and signer public key into a `SignedMessage` protocol buffers message, as described in DurbatulukDesign.

Clients are configured only to accept messages from certain senders.  Senders are identified by a SHA-1 digest of their public key.  If a client does not recognize the hash of the public key of the sender, the message is dropped.

The Durbatulûk program provides command line options for generating key pairs and far generating hashes of public keys.  When a user generates a key, separate public and private key files are written.  As is standard practice in public key cryptography, we allow and encourage the use of separate keys for encryption and signing.  Keys currently must be managed manually, and will typically be generated and installed when a particular node is initially configured.  See GettingStarted for details on the key management process.

# Message Confidentiality #

After message integrity, the second most important security goal of Durbatulûk is the confidentiality of messages.  This is guaranteed by using hybrid encryption.  For each message, Durbatulûk generates a new random "session key" that is used to encrypt messages using 256-bit AES encryption in CBC mode.  Session keys are encrypted for the intended recipient using 2048-bit RSA encryption with OAEP.  The recipient's public key serves as the identifier for the particular recipient, and Durbatulûk drops messages for which the public key does not match its public key.

Each Durbatulûk node may use its own private key, or, if confidentiality is less important in a specific instance of a Durbatulûk system, nodes may share private keys.  The capability to share private keys between nodes or between groups of nodes is a powerful feature of Durbatulûk.  This means that a command can configure groups with shared private keys so that a single command will be processed by every node sharing a private key.  This feature provides great gains in efficiency, but this should not be used in a setting where confidentiality is important since the compromise of a single client implies the compromise of the confidentiality of every client sharing the compromised private key.  Compromise of confidentiality does not imply compromise of message integrity and sender authentication.

# Client Stability #

The last security feature of Durbatulûk is reasonable client stability.  An attacker should not be able to create Durbatulûk inputs (messages or command line inputs) that crash a client, nor should denial-of-service types attacks be easy.  The worst case of a denial of service attack should require an attacker to do about as much work as the client(s) under attack.  This means that a powerful adversary with strong computational power could overwhelm a Durbatulûk network with less computational power.  We consider protection against this class of adversary impractical to implement, thus we qualify this security guarantee by ensuring _reasonable_ client stability.

_There is currently an exception to this.  A known attack using the current demonstration / test server would be to copy a legitimate message from the public test server and repost that message many times to the test server.  This is a deficiency in the test server and not in the Durbatulûk protocol.  The test server that we currently implement is for testing and demonstration, and does not verify who is posting messages to the server.  Production implementations of Durbatulûk servers should use server security to prevent attackers from performing this type of attack.  For example, production servers could use SSL to authenticate posters to the server._

To help guard against denial-of-service, we perform several checks on messages and drop messages at the first failure of a check.  This reduces client workload and reduces attack surface.  Before performing an expensive digital signature verification, we first simply check that the signer of a message is a legitimate sender.  This ensures that an attacker trying to forge a message has to perform about as much computational work as the client verifying the signature (with the exception of the known replay attack mentioned above).  We only decrypt a message once the signature and recipient pass verification.  We only process a message if the sender is allowed to send the message type and if the sequence number passes validation.

# Assumptions #

We assume the integrity of commander and client systems: if attackers can read the private key files of Durbatulûk nodes, no security guarantees hold.  We assume the difficulty of the RSA problem; we assume that AES is indistinguishable from a true random permutation; we assume the strong collision resistance of SHA-1.  We assume that the correct functioning and overall security of OpenSSL, including its internal PRNG seeding process using `/dev/urandom`.

# Security-Focused Development Process #

We performed the research and development process for Durbatulûk with a focus on security from the beginning.  Using a test-driven development process, we first coded tests for the expected behaviors of Durbatulûk processes, including cryptographic failures.  Even in production mode, the `--tests` parameter may be used to run a series of Durbatulûk tests.  The failure of any tests may imply insecurity in the system.  We also developed Durbatulûk using standard security paradigms.  For example, we sign messages _after_ encryption, and we use cryptographic primitives in modes that are known to be secure.