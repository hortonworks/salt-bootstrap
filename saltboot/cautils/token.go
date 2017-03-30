package cautils

import (
  "math/rand"
  "time"
  "strconv"
  "strings"
  "errors"
  "os"
)
var Now = time.Now

type Token struct {
	ExpiresAt   int64
	RandomHash  string
}

func RandomString(strlen int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func NewToken(lifetime int64, strlen int) (*Token) {
  randomHash := RandomString(strlen)
  expiresAt := Now().Unix() + lifetime

	newToken := &Token{
		ExpiresAt:     expiresAt,
		RandomHash:    randomHash,
	}

  return newToken
}


func(t *Token) Serialize() (string) {
   serialized :=  t.RandomHash + ":" + strconv.FormatInt(t.ExpiresAt, 10)
   return serialized
}

func DeserializeToken(serialized string) (*Token, error) {
   parts := strings.Split(serialized, ":")
   if len(parts) < 2 {
     return nil, errors.New("Minimum match not found")
   }
   expires, err := strconv.ParseInt(parts[1], 10, 64)
   if err != nil {
     return nil, err
   }
   loadedToken := &Token {
    ExpiresAt: expires,
    RandomHash: parts[0],
  }
  return loadedToken, nil
}

func(t *Token) IsValid() bool {
  return t.ExpiresAt > Now().Unix()
}

func Store(filename string, content interface{Serialize() string}) error {
  f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
  if err != nil {
    return err
  }
  _, err = f.WriteString(content.Serialize())
  f.Close()
  if err != nil {
    return err
  }
  return nil
}

func ValidateToken(filename string, token string,
  readFile func(filename string) ([]byte, error),
	writeFile func(filename string, data []byte, perm os.FileMode) error) (bool) {
  b, err := readFile(filename)
	if err != nil {
		panic(err)
	}
  valid := false
	loadedString := string(b)
  loadedTokens := strings.Split(loadedString, "\n")
  var filteredLines = make([]string, 0)

  for _, serializedToken := range loadedTokens {
      if serializedToken == "" {
        continue;
      }
  		loadedToken, err := DeserializeToken(serializedToken)
      if err != nil {
        panic(err)
      }
      if loadedToken.IsValid() {
        if loadedToken.RandomHash == token {
          valid = true
        } else {
          filteredLines = append(filteredLines, serializedToken)
        }
      }
  	}
    tokensToKeep := strings.Join(filteredLines, "\n")
    if len(tokensToKeep) > 0 {
      tokensToKeep = tokensToKeep + "\n"
    }
    err = writeFile(filename, []byte(tokensToKeep), 0644)
  	if err != nil {
  		panic(err)
  	}

  return valid
}
