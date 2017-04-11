package cautils

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"
)

type FakeFile struct {
	name string
}

func (f FakeFile) Name() string {
	return f.name
}
func (f FakeFile) IsDir() bool {
	return false
}
func (f FakeFile) Size() int64 {
	return 0
}
func (f FakeFile) Mode() os.FileMode {
	return 0
}
func (f FakeFile) ModTime() time.Time {
	return time.Now()
}
func (f FakeFile) Sys() interface{} {
	return nil
}

func TestTokenGeneratorLength(t *testing.T) {
	a := RandomString(12)
	if len(a) != 12 {
		t.Errorf("a.length %d == %d", 12, len(a))
	}
}

func StringInSlice(needle string, haystack []string) (found bool) {
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
	Now = func() time.Time { return time.Unix(1515151123, 0) }
	var then = Now().Unix() + 10
	tkn := NewToken(10, 1)
	if tkn.ExpiresAt != then {
		t.Errorf("Token expiration time is incorrect %d, %d", then, tkn.ExpiresAt)
	}
}

func TestTokenSerialize(t *testing.T) {
	testTkn := &Token{
		ExpiresAt:  123,
		RandomHash: "sorandom",
	}
	actual := testTkn.Serialize()
	if actual != "sorandom:123" {
		t.Errorf("Token serialization is incorrect %s, %s", actual, "sorandom:123")
	}
}

func TestTokenDeSerialize(t *testing.T) {
	actual, err := DeserializeToken("sorandom:123")
	if err != nil {
		t.Error(err)
	}
	if actual.RandomHash != "sorandom" {
		t.Errorf("Token serialization is incorrect %s, %s", actual.RandomHash, "sorandom:123")
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
	if expired.IsValid() {
		t.Errorf("Expired token detected as still in date")
	}
	Now = func() time.Time { return time.Unix(1515151123, 0) }
	tkn := NewToken(10, 1)
	if tkn.IsValid() != true {
		t.Errorf("Valid token detected as expired: %d, %d", Now().Unix(), tkn.ExpiresAt)
	}
}

func TestTokenStore(t *testing.T) {
	defer os.Remove("../testdata/test_tokens/*")
	tkn1, _ := DeserializeToken("tkn1:123")
	Store("../testdata/test_tokens/"+tkn1.RandomHash, tkn1)

	tkn2, _ := DeserializeToken("tkn2:1515151123")
	Store("../testdata/test_tokens/"+tkn2.RandomHash, tkn2)

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

	var files = []os.FileInfo{FakeFile{name: "tkn1"}, FakeFile{name: "tkn2"},
		FakeFile{name: "tkn3"}}

	readDir := func(dirname string) ([]os.FileInfo, error) {
		return files, nil
	}

	readFile := func(filename string) ([]byte, error) {
		if filename == "mock/tkn1" {
			return []byte("tkn1:123"), nil
		}
		if filename == "mock/tkn2" {
			return []byte("tkn2:123"), nil
		}
		if filename == "mock/tkn3" {
			time1 := Now().Unix() + 30
			return []byte("tkn3:" + strconv.FormatInt(time1, 10)), nil
		}
		return nil, errors.New("Bad filename requested :" + filename)
	}
	Remove := func(filename string) error {
		var tmp = []os.FileInfo{}
		for _, file := range files {
			if filename != filepath.Join("mock", file.Name()) {
				tmp = append(tmp, file)
			}
		}
		files = tmp
		return nil
	}

	valid := ValidateToken("mock", "tkn1", readDir, readFile, Remove)
	if valid {
		t.Errorf("Invalid token detected as valid token %b != %b ", valid, false)

	}
	if len(files) > 1 {
		t.Errorf("Invalid token detected as valid token %d != %d", len(files), 1)
	}

}

func TestTokenValidatorAcceptsValidTokens(t *testing.T) {
	var files = []os.FileInfo{FakeFile{name: "tkn1"}, FakeFile{name: "tkn2"},
		FakeFile{name: "tkn3"}}

	readDir := func(dirname string) ([]os.FileInfo, error) {
		return files, nil
	}

	readFile := func(filename string) ([]byte, error) {
		if filename == "mock/tkn1" {
			return []byte("tkn1:123\n"), nil
		}
		if filename == "mock/tkn2" {
			return []byte("tkn2:123\n"), nil
		}
		if filename == "mock/tkn3" {
			time1 := Now().Unix() + 30
			return []byte("tkn3:" + strconv.FormatInt(time1, 10) + "\n"), nil
		}
		return nil, errors.New("Bad filename requested :" + filename)
	}
	Remove := func(filename string) error {
		var tmp = []os.FileInfo{}
		for _, file := range files {
			if filename != filepath.Join("mock", file.Name()) {
				tmp = append(tmp, file)
			}
		}
		files = tmp
		return nil
	}

	valid := ValidateToken("mock", "tkn3", readDir, readFile, Remove)
	if !valid {
		t.Errorf("Valid token detected as invalid token %s != %s ", valid, true)

	}
	if len(files) != 0 {
		t.Errorf("Invalid token detected as valid token %d != %d", len(files), 0)
	}
}
