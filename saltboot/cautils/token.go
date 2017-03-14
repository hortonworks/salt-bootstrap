package cautils

import (
  "math/rand"
  "time"
  "strconv"
  "strings"
  "errors"
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
  return  t.ExpiresAt > Now().Unix()
}
