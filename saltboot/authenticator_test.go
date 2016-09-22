package saltboot

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
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
	pk, _ := rsa.GenerateKey(rand.Reader, 2014)
	pubDer, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: pubDer})

	content := "body"
	newHash := crypto.SHA256.New()
	newHash.Write([]byte(content))
	sign, _ := rsa.SignPSS(rand.Reader, pk, crypto.SHA256, newHash.Sum(nil), nil)

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
