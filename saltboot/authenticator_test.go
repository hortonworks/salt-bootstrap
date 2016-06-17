package saltboot

import (
	"encoding/base64"
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
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {})
	handler.ServeHTTP(writer, req)
	if writer.status != 401 {
		t.Errorf("writer.status %d == %d", 401, writer.status)
	} else if writer.message != "401 Unauthorized" {
		t.Errorf("writer.message %s == %s", "401 Unauthorized", writer.message)
	}
}

func TestWrapUserPassValid(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://google.com", nil)
	validAuth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+validAuth)
	writer := new(TestWriter)
	writer.header = req.Header
	auth := Authenticator{Username: "user", Password: "pass"}
	handler := auth.Wrap(func(w http.ResponseWriter, req *http.Request) {})
	handler.ServeHTTP(writer, req)
	if writer.header.Get("Content-Type") != "application/json" {
		t.Errorf("header.Get('Content-Type') %s == %s", "application/json", writer.header.Get("Content-Type"))
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
