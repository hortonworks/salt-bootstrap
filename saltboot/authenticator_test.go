package saltboot

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

type TestWriter struct {
	header  http.Header
	status  int
	message string
}

func (w *TestWriter) Header() http.Header {
	return w.header
}

func (w *TestWriter) Write(b []byte) (int, error) {
	w.message = string(b)
	return len(b), nil
}

func (w *TestWriter) WriteHeader(s int) {
	w.status = s
}

func TestWrapUserPassNotValid(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	invalidAuth := base64.StdEncoding.EncodeToString([]byte("user-pass"))
	req.Header.Add("Authorization", "Basic "+invalidAuth)
	writer := new(TestWriter)
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, []byte{})
	handler.ServeHTTP(writer, req)
	if writer.status != 401 {
		t.Errorf("writer.status %d == %d", 401, writer.status)
	}
}

func TestWrapMissingSignature(t *testing.T) {
	body := bytes.NewBufferString("body")
	req, _ := http.NewRequest("GET", "http://google.com", body)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	writer := new(TestWriter)
	writer.header = req.Header
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, []byte{})
	handler.ServeHTTP(writer, req)
	if writer.status != 406 {
		t.Errorf("writer.status %d == %d", 406, writer.status)
	}
}

func TestWrapInvalidSignature(t *testing.T) {
	body := bytes.NewBufferString("body")
	req, _ := http.NewRequest("GET", "http://google.com", body)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	req.Header.Add("signature", base64.StdEncoding.EncodeToString([]byte("sign")))
	writer := new(TestWriter)
	writer.header = req.Header
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, []byte("sign"))
	handler.ServeHTTP(writer, req)
	if writer.status != 406 {
		t.Errorf("writer.status %d == %d", 406, writer.status)
	}
}

func TestWrapAllValid(t *testing.T) {
	pk, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubDer, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: pubDer})

	content := "body"
	newHash := crypto.SHA256.New()
	newHash.Write([]byte(content))
	opts := rsa.PSSOptions{SaltLength: 20}
	sign, _ := rsa.SignPSS(rand.Reader, pk, crypto.SHA256, newHash.Sum(nil), &opts)

	body := bytes.NewBufferString(content)
	req, _ := http.NewRequest("GET", "http://google.com", body)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	req.Header.Add("signature", base64.StdEncoding.EncodeToString(sign))
	writer := new(TestWriter)
	writer.header = req.Header
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, pubPem)
	handler.ServeHTTP(writer, req)
	if writer.status != 0 {
		t.Errorf("writer.status %d == %d", 0, writer.status)
	}
}

func TestWrapUploadAllValid(t *testing.T) {
	pk, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubDer, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: pubDer})

	expected := []byte("content")
	newHash := crypto.SHA256.New()
	newHash.Write(expected)
	opts := rsa.PSSOptions{SaltLength: 20}
	sign, _ := rsa.SignPSS(rand.Reader, pk, crypto.SHA256, newHash.Sum(nil), &opts)

	body := &bytes.Buffer{}
	multiWriter := multipart.NewWriter(body)
	part, _ := multiWriter.CreateFormFile("file", "test.txt")

	part.Write(expected)
	multiWriter.Close()

	req, _ := http.NewRequest("GET", "http://google.com", body)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	req.Header.Add("signature", base64.StdEncoding.EncodeToString(sign))
	req.Header.Set("Content-Type", multiWriter.FormDataContentType())
	writer := httptest.NewRecorder()
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, pubPem)
	handler.ServeHTTP(writer, req)
	if writer.Code != 200 {
		t.Errorf("writer.status %d == %d", 200, writer.Code)
	}
}

func TestWrapSignedByJava(t *testing.T) {
	getEnv := func(key string) string {
		switch key {
		case "SALTBOOT_CONFIG":
			return "testdata/security-config-java.yml"
		default:
			return ""
		}
	}

	securityConfig, _ := DetermineSecurityDetails(getEnv, nil)

	body := bytes.NewBufferString("content")
	req, _ := http.NewRequest("GET", "http://google.com/asd", body)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	req.Header.Add("signature",
		"SsLHxVfUQYFHDEsZxEhjWEtN40UNC604nFw9wSNqE0x5H2Ey8UqaPB8g/I+LAK9e1ty7IBE0c4d+ZQcyNWBrxjpH+rUwgHJr9X8XE9irz8E5HiDN5wTkLap1zWmzWSwzAc2fuO5kN61lZlZnKyI3+qTLZ2G6gypl3a7HLq858zU083AoQ2NcAWYAGUubsRcUdJyhJwyg7b9w009FDBAj9DO+GSYPp6TkYW1E1ghDsQPHKoQU+qNRvL45xO9217DBzJlF3OOUusTUkpyXSg9X5sw0Eng1Tvyp8phr0q9o+pIixxZdoZGcnZtWhQBe1KNmH2yBQVZehit1iRt9DxHPoQ==")
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {}, []byte(securityConfig.SignVerifyKey))
	writer := new(TestWriter)
	writer.header = make(map[string][]string)

	handler.ServeHTTP(writer, req)
	if writer.status != 0 {
		t.Errorf("writer.status %d == %d", 0, writer.status)
	}
}

func TestGetAuthUserPassShortOrNotBasic(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	user, pass := GetAuthUserPass(req)
	if user != "" || pass != "" {
		t.Error("User and password must be empty")
	}
}

func TestGetAuthUserPassBasicButNotBase64(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	req.Header.Add("Authorization", "Basic not-base64-string")
	user, pass := GetAuthUserPass(req)
	if user != "" || pass != "" {
		t.Error("User and password must be empty")
	}
}

func TestGetAuthUserPassBasicBase64ButNotUserPass(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	invalidAuth := base64.StdEncoding.EncodeToString([]byte("user-pass"))
	req.Header.Add("Authorization", "Basic "+invalidAuth)
	user, pass := GetAuthUserPass(req)
	if user != "" || pass != "" {
		t.Error("User and password must be empty")
	}
}

func TestGetAuthUserPassBasicBase64UserPass(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	user, pass := GetAuthUserPass(req)
	if user != "user" || pass != "pass" {
		t.Error("User and password not decrypted well")
	}
}
