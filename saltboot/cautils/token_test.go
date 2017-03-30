package cautils

import (
	"testing"
	"sort"
	"time"
	"io/ioutil"
	"os"
	"strconv"
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

func TestTokenStore(t *testing.T) {
	ioutil.WriteFile("../testdata/ca.tkn", []byte(""), 0644)
	defer os.Remove("../testdata/test_tokens/*")
	tkn1, _ := DeserializeToken("tkn1:123")
	Store("../testdata/test_tokens/" + tkn1.RandomHash, tkn1)

	tkn2, _ := DeserializeToken("tkn2:1515151123")
	Store("../testdata/test_tokens/" + tkn2.RandomHash, tkn2)

	result, _ := ioutil.ReadFile("../testdata/test_tokens/tkn1")
	expected := "tkn1:123\n"
	if string(result) != expected {
  	t.Errorf("Persist token failed %s != %s ", string(result), expected)
	}

	result, _ = ioutil.ReadFile("../testdata/test_tokens/tkn2")
	expected = "tkn2:1515151123\n"
	if string(result) != expected {
  	t.Errorf("Persist token failed %s != %s ", result, expected)
	}
}



func TestTokenValidatorRemovesExpiredTokens(t *testing.T) {

	readFile := func(filename string) ([]byte, error) {
		hostsFile :="tkn1:123\ntkn2:1515151123\n"
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	valid := ValidateToken("/not/used/in/tests", "tktk", readFile, writeFile)

	expected := ""

	if expected != result {
		t.Errorf("Token store content does not match desired state, %s != %s", expected, result)
	}

	if valid != false {
		t.Errorf("True returned for valid, when token is not found.")
	}
}



func TestTokenValidatorAcceptsValidTokens(t *testing.T) {
	time1 := Now().Unix() + 30
	time2 := time1 + 10

	readFile := func(filename string) ([]byte, error) {
		hostsFile := "tkn1:" + strconv.FormatInt(time1,
			 10) + "\ntkn2:" + strconv.FormatInt(time2, 10) + "\n"
		return []byte(hostsFile), nil
	}

	var result string
	writeFile := func(filename string, data []byte, perm os.FileMode) error {
		result = string(data)
		return nil
	}

	valid := ValidateToken("/not/used/in/tests", "tkn2", readFile, writeFile)

	expected := "tkn1:" +  strconv.FormatInt(time1, 10)+ "\n"

	if expected != result {
		t.Errorf("Invalid hostname replacement, %s != %s", expected, result)
	}

	if valid != true {
		t.Errorf("False returned for found, when no token is valid and found.")
	}
}
