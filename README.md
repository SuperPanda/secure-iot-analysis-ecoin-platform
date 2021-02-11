# Secure IoT analysis ecoin platform (Proof of concept)
## Topic: Security

Bank must require connections are from authorised clients only by requiring there key to be stored in the banks truststore

Coins are 256 bit random value generated on demand and stored in the Bank's ledger until redeemed

Coins act as both an authorisation token and as the Symmetric Key for communication between the analyst and the collector

The 256-bit Symmetric key (ecoin) and a random 128-bit IV is encrypted using the Bank's public key in the initial service operation request

The analyst sends the Encrypted Payload Header to the bank for decryption of content (since bank only connects to authorised client), and validation of the coin

The bank returns the Symmetric key and IV back to the analyst to decrypt data payload, and encryption of result

No symmetric key (ecoin) or IV is sent back to the collector, since it is awaiting the reply and has the IV and SK in memory to decrypt

The collected data and result is encrypted because how creepy would it be if eavesdropper could know what is happening in your IOT house

256-bit ecoin was chosen in order to make it intractable to randomly guess the ecoin, since the director can craft encrypted header packets
using the banks public key... but the director doesn't have an ecoin, and can't get one from the bank, unless it had an account, then it 
would use its own credit... and sending it to an analyst would be just giving credit away (one use ecoin)

When a coin is invalid, the bank notifies the analyst, but the analyst gives a non-specific operation error to the collector 

The Service Operation data is encrypted using an AES256-CBC cipher with PKCS1Padding (openssl says this is the most common)

Director cannot replay results to Collector because each Service operation is encrypted with a different IV each time

Collector stores bad ecoins in a seperate directory if it failed, so maybe the bank could return credit in case of a horrible fraud-like 
situation where the director kept faking service operation errors


## Topic: Weakness

Director can in effect destroy ecoins from the collector, however, the director still cannot 'misuse', 'reuse' or 'duplicate' ecoins.

## Topic: Design rationale
### Bank storage requirements
Bank storage requirements with 10^9 devices with 1000 ecoins allocated:
Assume 10^9 devices with 10^3 keys = 10^12 keys in use
10^12 * 256 bit key = approx. 2.5*10^14 bits
250Tbits at max capacity required to be held at a given time by the bank (feasible) for the ledger
### IoT Storage Requirements
Storage requirement for microcomputer:
1000 keys x 256bit = 32 bytes for microcomputer (feasible)

### ecoin guessability
2^256 is about 10^64
with 10^12 keys in use...
10^12 / 10^64 = 1/10^52
a guess is one in 1 in 10^52 
including birthday attack (half the bit size) 10^26
Running @ 1 billion guesses a second: 10^9 / 10^26 seconds
10^15 seconds = 3 years to guess 1 ecent @ a billion guesses a second :) (if my rough maths works out)

## Topic: Infrastructure

See [analyst/README.md](analyst/README.md) and [collector/README.md](collector/README.md)
