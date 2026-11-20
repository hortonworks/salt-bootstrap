package saltboot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestDistributeRawRequest_HttpsFallbackSharesTheTimeout(t *testing.T) {
	os.Setenv("SALTBOOT_HTTPS_ENABLED", "true")
	defer os.Unsetenv("SALTBOOT_HTTPS_ENABLED")
	release := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer httpServer.Close()
	defer close(release)
	os.Setenv("SALTBOOT_PORT", strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port))
	defer os.Unsetenv("SALTBOOT_PORT")
	clients := []string{"127.0.0.1:7071"} // nothing listens on the HTTPS port, so the request falls back to HTTP
	const timeout = 300 * time.Millisecond

	start := time.Now()
	results := DistributeRawRequest(clients, "/test-endpoint", "user", "pass", RequestBody{PlainPayload: []byte(`{}`)}, timeout, 1)
	var responses []RawResponse
	for res := range results {
		responses = append(responses, res)
	}

	if len(responses) != 1 || responses[0].Err == nil || !errors.Is(responses[0].Err, context.DeadlineExceeded) {
		t.Fatalf("expected one deadline error, got %+v", responses)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the fallback attempt ignored the timeout, took %s", elapsed)
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

func TestDistributeRawRequestTimesOutSlowTargets(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"statusCode":200}`))
	}))
	defer fast.Close()
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer slow.Close()
	defer close(release)

	clients := []string{fast.Listener.Addr().String(), slow.Listener.Addr().String()}
	start := time.Now()
	results := DistributeRawRequest(clients, "/test-endpoint", "user", "pass", RequestBody{PlainPayload: []byte(`{}`)}, 300*time.Millisecond, 10)

	byAddress := make(map[string]RawResponse)
	for res := range results {
		byAddress[res.Address] = res
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fan-out took %s, the timeout was not applied", elapsed)
	}
	if res := byAddress[clients[0]]; res.Err != nil || res.StatusCode != http.StatusOK || string(res.Body) != `{"statusCode":200}` {
		t.Errorf("unexpected fast response: %+v", res)
	}
	if res := byAddress[clients[1]]; res.Err == nil || res.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected a timeout for the slow target, got %+v", res)
	}
}

func TestDistributeRawRequestLimitsTheParallelTargets(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		maxActive = max(maxActive, active)
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	clients := make([]string, 12)
	for i := range clients {
		clients[i] = server.Listener.Addr().String()
	}

	answered := 0
	for res := range DistributeRawRequest(clients, "/test-endpoint", "user", "pass", RequestBody{PlainPayload: []byte(`{}`)}, 5*time.Second, 3) {
		if res.Err != nil || res.StatusCode != http.StatusOK {
			t.Errorf("unexpected response: %+v", res)
		}
		answered++
	}

	if answered != 12 || maxActive != 3 {
		t.Errorf("expected 12 answers with at most 3 targets at a time, got %d answers and %d at a time", answered, maxActive)
	}
}

func TestDistributeRawRequestContactsTheTargetsInOrderAndTimesOnlyTheContact(t *testing.T) {
	var mu sync.Mutex
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.URL.Query().Get("index"))
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	clients := []string{server.Listener.Addr().String(), server.Listener.Addr().String(), server.Listener.Addr().String()}
	signed := RequestBody{SignedPayload: `{}`, Signature: "signature"}

	// one at a time, the last target waits 300ms for its turn, longer than the 250ms timeout of its own request
	for res := range DistributeRawRequest(clients, "/test-endpoint", "user", "pass", signed, 250*time.Millisecond, 1) {
		if res.Err != nil {
			t.Errorf("waiting for a slot must not count against the timeout: %v", res.Err)
		}
	}

	if strings.Join(order, ",") != "0,1,2" {
		t.Errorf("expected the targets in request order, got %v", order)
	}
}

func TestDistributeRawRequestWithoutALimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer server.Close()

	for _, maxParallel := range []int{0, 100} {
		answered := 0
		for range DistributeRawRequest([]string{server.Listener.Addr().String(), server.Listener.Addr().String()}, "/x", "u", "p",
			RequestBody{PlainPayload: []byte(`{}`)}, time.Second, maxParallel) {
			answered++
		}
		if answered != 2 {
			t.Errorf("maxParallel %d: expected 2 answers, got %d", maxParallel, answered)
		}
	}
	if len(DistributeRawRequest(nil, "/x", "u", "p", RequestBody{}, time.Second, 5)) != 0 {
		t.Errorf("expected no answers without targets")
	}
}
