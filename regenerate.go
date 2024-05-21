package main

import (
//	"crypto/cipher"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
  "strconv"
  "strings"
  "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
  inputFile   string
  outputFile  string
  password    string
  uuidKey     string
  verbose     bool
)

const chunkSize = 63


type AppData struct {
	App string `json:"app"`
}

type AppDetails struct { 
    Data []DataChunk `json:"data"`
 }

type DataChunk struct {
    FullId string `json:"full-id"`
}

type ChunkData struct {
  TotalChunks     int
  ReceivedChunks  map[int]string
}

func init() {
	flag.StringVar(&inputFile, "i", "", "Input JSON file exported from InteractSh client")
	flag.StringVar(&outputFile, "o", "output.txt", "Output file of decrypted data")
	flag.StringVar(&password, "p", "", "Password for encrypted data")
  flag.StringVar(&uuidKey, "u", "", "Expected UUID to verify correct data")
  flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.Parse()

	// Validate required arguments
	if inputFile == "" || password == "" || uuidKey == "" || outputFile == "" {
		fmt.Println("Missing required arguments. -i, -o, -p and -u must be specified.")
		flag.Usage()
		os.Exit(1)
	}
}

func readInputFile(filename string) ([]DataChunk, error) {
  data, err := ioutil.ReadFile(filename)
  if err != nil {
    return nil, fmt.Errorf("error reading input file: %v", err)
  }
  var appData AppData
  if err := json.Unmarshal(data, &appData); err != nil {
    return nil, fmt.Errorf("error parsing JSON data: %v", err)
  }
  var appDetails AppDetails
	if err := json.Unmarshal([]byte(appData.App), &appDetails); err != nil {
		return nil, fmt.Errorf("error parsing app field: %v", err)
	}

	return appDetails.Data, nil
}

// ProcessDataChunks handles the reassembly and decryption of ProcessDataChunks
func processDataChunks(chunks []DataChunk) ([]byte, error) {
  chunkData := make(map[string]*ChunkData)
  for _, chunk := range chunks {
      fullId := chunk.FullId 
      if !strings.HasPrefix(fullId, uuidKey) {
			  continue
      }
      parts := strings.Split(fullId, ".")
		  if len(parts) != 6 {
			  if verbose {
				  log.Printf("Wrong format for full-id data: %s\n", fullId)
			  }
		    continue
		  }

		  randomHex, position, totalChunks, encodedData := parts[0], parts[2], parts[3], parts[4]
		  posInt, err := strconv.Atoi(position)
		  if err != nil {
			    log.Printf("Unexpected formatting of position value in DNS record: %v\n", err)
			    continue
		  }
		  totalInt, err := strconv.Atoi(totalChunks)
		  if err != nil {
			    log.Printf("Unexpected formatting of total chunks value in DNS record: %v\n", err)
			    continue
		  }
   
    // Caps Base32 encoded string
    encodedData = strings.ToUpper(encodedData)

    // Log the raw encoded data for each chunk
    if verbose {
      log.Printf("Encoded data for chunk %d: %s", posInt, encodedData)
    }

    // Validate if the encodedData contains only valid Base32 characters
    if !isValidBase32(encodedData) {
      log.Printf("Invalid characters in Base32 encoded data in chunk %d: %s", posInt, encodedData)
      continue
    }
      
    // Allow the last chunk to be smaller than the predefined chunk size
		if posInt != totalInt-1 && len(encodedData) != chunkSize {
			log.Printf("Chunk size mismatch for chunk %d, expected %d bytes, got %d bytes\n", posInt, chunkSize, len(encodedData))
			continue

    }
    if verbose {
        log.Printf("Processing chunk: %s, Position: %d, Total Chunks: %d\n", fullId, posInt, totalInt)
    }
 
  //Ensure encodedData is a valid Base32 string before proceeding
   //   if _, err := base32.StdEncoding.DecodeString(encodedDataPadded); err != nil {
    //    log.Printf("Invalid Base32 encoded data in chunk %d: %v\n", posInt, err)
    //    continue
     // }

		  if _, exists := chunkData[randomHex]; !exists {
			    chunkData[randomHex] = &ChunkData{
				      TotalChunks:    totalInt,
				      ReceivedChunks: make(map[int]string),
			    }
		  }
		  chunkData[randomHex].ReceivedChunks[posInt] = encodedData

      receivedCount := len(chunkData[randomHex].ReceivedChunks)
		  if verbose {
			log.Printf("Received %d/%d chunks for %s\n", receivedCount, chunkData[randomHex].TotalChunks, randomHex)
	  	}

		  if receivedCount == chunkData[randomHex].TotalChunks {
			  if verbose {
				  log.Println("All chunks received. Reconstructing data.")
			  }

			  fullData, err := reconstructData(chunkData[randomHex])
			  if err != nil {
				  return nil, fmt.Errorf("failed to reconstruct data: %v", err)
			  }

			  decryptedData, err := decryptData(fullData, password)
			  if err != nil {
				  return nil, fmt.Errorf("failed to decrypt data: %v", err)
			  }

			  return decryptedData, nil
		  }
	  }

  if verbose {
		for hex, data := range chunkData {
			missingChunks := make([]int, 0)
			for i := 0; i < data.TotalChunks; i++ { // Position is zero-based
				if _, exists := data.ReceivedChunks[i]; !exists {
					missingChunks = append(missingChunks, i)
				}
			}
			log.Printf("Missing chunks for %s: %d/%d received, missing chunks: %v\n", hex, len(data.ReceivedChunks), data.TotalChunks, missingChunks)
		}
	}
	  return nil, fmt.Errorf("not all chunks received")
  }

//func extractFullId(chunk DataChunk) string {
	// Extract full-id from the raw-request or raw-response field
//	if idx := strings.Index(chunk.RawRequest, ";"); idx != -1 {
//		return chunk.RawRequest[:idx]
//	}
//	if idx := strings.Index(chunk.RawResponse, ";"); idx != -1 {
//		return chunk.RawResponse[:idx]
//	}
//	return ""
//}

func addBase32Padding(encodedData string) string {
  padLength := (8 - (len(encodedData) % 8)) % 8
  return encodedData + strings.Repeat("=", padLength)
}

func reconstructData(chunkData *ChunkData) ([]byte, error) {
	var reconstructed strings.Builder
	for i := 0; i < chunkData.TotalChunks; i++ { 
    if chunk, exists := chunkData.ReceivedChunks[i]; exists {
        reconstructed.WriteString(chunk)
    } else {
		    return nil, fmt.Errorf("missing chunk at position %d", i)
    }
  }
  // Log the reconstructed string for debugging
  reconstructedStr := reconstructed.String()
  if verbose {
    log.Printf("Reconstructed String: %s", reconstructedStr)
  }

	// Add padding to the final reconstructed string before decoding
	reconstructedStrPadded := addBase32Padding(reconstructedStr)
	decodedData, err := base32.StdEncoding.DecodeString(reconstructedStrPadded)
	if err != nil {
		return nil, fmt.Errorf("error decoding base32 data: %v", err)
	}
	
	return decodedData, nil
}

// Utility function to derive a key from the password and saltSize
func deriveKey(password string, salt []byte) []byte { 
  return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32) // 32 bytes key for XChaCha20Poly1305
}

func decryptData(encryptedData []byte, password string) ([]byte, error) {
	// Assuming the salt is prepended to the encrypted data
	saltSize := 16
	salt := encryptedData[:saltSize]
	nonce := encryptedData[saltSize : saltSize+chacha20poly1305.NonceSizeX]
	ciphertext := encryptedData[saltSize+chacha20poly1305.NonceSizeX:]

	key := deriveKey(password, salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead: %v", err)
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

func isValidBase32(s string) bool {
  for _, c := range s {
    if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
      return false
    }
  }
  return true
}

func main() { 
// Read and parse input file
	chunks, err := readInputFile(inputFile)
	if err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}

	// Process data chunks
	fullData, err := processDataChunks(chunks)
	if err != nil {
		log.Fatalf("Failed to process data: %v", err)
	}

	// Write output file
	if err := ioutil.WriteFile(outputFile, fullData, 0644); err != nil {
		log.Fatalf("Error writing to output file: %v", err)
	}

	fmt.Println("Decryption and processing completed successfully, output written to", outputFile)
}
  
