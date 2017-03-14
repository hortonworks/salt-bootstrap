package cautils

import (
	"testing"
	"sort"
	"time"
)


func TestTokenGeneratorLength(t *testing.T) {
	a := RandomString(12)
	if len(a) != 12 {
		t.Errorf("a.length %d == %d", 12, len(a))
	}
}

func StringInSlice(needle string, haystack []string)(found bool) {
	sort.Strings(haystack)
	i := sort.SearchStrings(haystack, needle)
	if i < len(haystack) && haystack[i] == needle {
	   return true
	}
	return false
}

func TestTokensAreUnique(t *testing.T) {
  hashes := []string{}
  for i := 1; i <= 1000; i++ {
    a := RandomString(10)
		if StringInSlice(a, hashes) {
		  t.Errorf("Token is not unique")
		} else {
			hashes = append(hashes, a)
		}
  }
}

func TestTokenExpiryTimeIsCorrect(t *testing.T) {
	Now = func() time.Time { return time.Unix(1515151123, 0)}
	var then = Now().Unix() + 10
  tkn := NewToken(10, 1)
	if (tkn.ExpiresAt != then) {
		t.Errorf("Token expiration time is incorrect %d, %d", then, tkn.ExpiresAt)
	}
}

func TestTokenSerialize(t *testing.T) {
	testTkn := &Token{
		ExpiresAt:     123,
		RandomHash:    "sorandom",
	}
	actual := testTkn.Serialize()
	if (actual != "sorandom:123") {
		t.Errorf("Token serialization is incorrect %d, %d", actual, "sorandom:123")
	}
}

func TestTokenDeSerialize(t *testing.T) {
	actual, err := DeserializeToken("sorandom:123")
  if err != nil {
		t.Error(err)
	}
	if actual.RandomHash != "sorandom" {
		t.Errorf("Token serialization is incorrect %d, %d", actual, "sorandom:123")
	}
	if actual.ExpiresAt != 123 {
		t.Errorf("Token serialization is incorrect %d, %d", 123, actual.ExpiresAt)
	}
}

func TestTokenIsValid(t *testing.T) {
	expired, err := DeserializeToken("sorandom:123")
  if err != nil {
		t.Error(err)
	}
	if expired.IsValid()  {
		t.Errorf("Expired token detected as still in date")
	}
	Now = func() time.Time { return time.Unix(1515151123, 0)}
	tkn := NewToken(10, 1)
	if (tkn.IsValid() != true) {
		t.Errorf("Valid token detected as expired: %d, %d", Now().Unix(), tkn.ExpiresAt)
	}
}
