package saltboot

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

type ReadSeekCloser struct {
	*bytes.Reader
}

func (r *ReadSeekCloser) Close() error {
	return nil
}

func TestDistributeRequest(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
	}))
	defer server1.Close()
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
	}))
	defer server2.Close()

	clients := []string{server1.Listener.Addr().String(), server2.Listener.Addr().String()}
	reqBody := RequestBody{PlainPayload: []byte(`{"key": "value"}`)}

	results := DistributeRequest(clients, "/test-endpoint", "user", "pass", reqBody)
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}

	validAddresses := map[string]bool{
		server1.Listener.Addr().String(): true,
		server2.Listener.Addr().String(): true,
	}

	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
	}
}

func TestDistributeRequest_WithSignature(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get(SIGNATURE) == "test-signature" {
			json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server1.Close()
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get(SIGNATURE) == "test-signature" {
			json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server2.Close()

	clients := []string{server1.Listener.Addr().String(), server2.Listener.Addr().String()}
	reqBody := RequestBody{
		SignedPayload: `{"key": "value"}`,
		Signature:     "test-signature",
	}

	results := DistributeRequest(clients, "/test-endpoint", "user", "pass", reqBody)
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		server1.Listener.Addr().String(): true,
		server2.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
	}
}

func TestDistributeRequest_HttpsEnabled(t *testing.T) {
	os.Setenv("SALTBOOT_HTTPS_ENABLED", "true")
	defer os.Unsetenv("SALTBOOT_HTTPS_ENABLED")
	server1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
	}))
	defer server1.Close()
	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
	}))
	defer server2.Close()

	clients := []string{server1.Listener.Addr().String(), server2.Listener.Addr().String()}
	reqBody := RequestBody{PlainPayload: []byte(`{"key": "value"}`)}

	results := DistributeRequest(clients, "/test-endpoint", "user", "pass", reqBody)
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		server1.Listener.Addr().String(): true,
		server2.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
	}
}

func TestDistributeRequest_HttpsEnabled_FallbackToHTTP(t *testing.T) {
	os.Setenv("SALTBOOT_HTTPS_ENABLED", "true")
	defer os.Unsetenv("SALTBOOT_HTTPS_ENABLED")
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"StatusCode": http.StatusOK, "Address": r.Host})
	}))
	defer httpServer.Close()
	os.Setenv("SALTBOOT_PORT", strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port))
	defer os.Unsetenv("SALTBOOT_PORT")
	clients := []string{"127.0.0.1:7071"} //Uses default HTTPS port
	reqBody := RequestBody{PlainPayload: []byte(`{"key": "value"}`)}

	results := DistributeRequest(clients, "/test-endpoint", "user", "pass", reqBody)
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 1 {
		t.Errorf("Expected 1 response, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		httpServer.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
	}
}

func TestDistributeFileUploadRequest(t *testing.T) {
	sampleFileContent := []byte("test file content")
	sampleFileName := "testfile.txt"
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		w.WriteHeader(http.StatusCreated)
	}))
	defer server1.Close()
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		w.WriteHeader(http.StatusCreated)
	}))
	defer server2.Close()
	targets := []string{server1.Listener.Addr().String(), server2.Listener.Addr().String()}
	file := &ReadSeekCloser{Reader: bytes.NewReader(sampleFileContent)}
	header := &multipart.FileHeader{Filename: sampleFileName}

	results := DistributeFileUploadRequest("/upload", "user", "pass", targets, "/path", "0644", file, header, "test-signature")
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		server1.Listener.Addr().String(): true,
		server2.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
		if res["StatusCode"] != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", res["StatusCode"])
		}
	}
}

func TestDistributeFileUploadRequest_HttpsEnabled(t *testing.T) {
	os.Setenv("SALTBOOT_HTTPS_ENABLED", "true")
	defer os.Unsetenv("SALTBOOT_HTTPS_ENABLED")
	sampleFileContent := []byte("test file content")
	sampleFileName := "testfile.txt"
	server1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		w.WriteHeader(http.StatusCreated)
	}))
	defer server1.Close()
	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		w.WriteHeader(http.StatusCreated)
	}))
	defer server2.Close()
	targets := []string{server1.Listener.Addr().String(), server2.Listener.Addr().String()}
	file := &ReadSeekCloser{Reader: bytes.NewReader(sampleFileContent)}
	header := &multipart.FileHeader{Filename: sampleFileName}

	results := DistributeFileUploadRequest("/upload", "user", "pass", targets, "/path", "0644", file, header, "test-signature")
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		server1.Listener.Addr().String(): true,
		server2.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
		if res["StatusCode"] != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", res["StatusCode"])
		}
	}
}

func TestDistributeFileUploadRequest_HttpsEnabled_FallbackToHttp(t *testing.T) {
	os.Setenv("SALTBOOT_HTTPS_ENABLED", "true")
	defer os.Unsetenv("SALTBOOT_HTTPS_ENABLED")
	sampleFileContent := []byte("test file content")
	sampleFileName := "testfile.txt"
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		w.WriteHeader(http.StatusCreated)
	}))
	defer httpServer.Close()
	os.Setenv("SALTBOOT_PORT", strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port))
	defer os.Unsetenv("SALTBOOT_PORT")
	targets := []string{httpServer.Listener.Addr().String()}
	file := &ReadSeekCloser{Reader: bytes.NewReader(sampleFileContent)}
	header := &multipart.FileHeader{Filename: sampleFileName}

	results := DistributeFileUploadRequest("/upload", "user", "pass", targets, "/path", "0644", file, header, "test-signature")
	var responses []map[string]interface{}
	for res := range results {
		responses = append(responses, map[string]interface{}{"StatusCode": res.StatusCode, "Address": res.Address})
	}

	if len(responses) != 1 {
		t.Errorf("Expected 1 response, got %d", len(responses))
	}
	validAddresses := map[string]bool{
		httpServer.Listener.Addr().String(): true,
	}
	for _, res := range responses {
		addr := res["Address"].(string)
		if !validAddresses[addr] {
			t.Errorf("Unexpected address in response: %s", addr)
		}
		if res["StatusCode"] != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", res["StatusCode"])
		}
	}
}
