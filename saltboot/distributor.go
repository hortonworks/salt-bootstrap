package saltboot

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fmt"
	"io"
	"mime/multipart"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func determineProtocol(httpsEnabled bool) string {
	if httpsEnabled {
		return "https://"
	} else {
		return "http://"
	}
}

func getHttpClient(httpsEnabled bool) *http.Client {
	if httpsEnabled {
		httpsConfig := GetHttpsConfig()
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
		transport.TLSClientConfig.MinVersion = httpsConfig.MinTlsVersion
		transport.TLSClientConfig.MaxVersion = httpsConfig.MaxTlsVersion
		transport.TLSClientConfig.CipherSuites = httpsConfig.CipherSuites

		return &http.Client{
			Transport: transport,
		}
	} else {
		return &http.Client{}
	}
}

func sendRequestWithFallback(httpClient *http.Client, request *http.Request, httpsEnabled bool) (string, *http.Response, error) {
	resp, err := httpClient.Do(request)
	if httpsEnabled && err != nil && errors.Is(err, syscall.ECONNREFUSED) {
		log.Printf("[sendRequestWithFallback] Could not reach the target using HTTPS. Falling back to HTTP.")
		newRequest := request.Clone(request.Context())
		newRequest.URL.Scheme = "http"
		newRequest.URL.Host = newRequest.URL.Hostname() + ":" + strconv.Itoa(DetermineHttpPort())
		resp, err = httpClient.Do(newRequest)
		return newRequest.URL.Host, resp, err
	}
	return request.URL.Host, resp, err
}

// sendDistributedRequest sends one fan-out request to client, signed with the client's index when the
// request body carries a signature.
func sendDistributedRequest(ctx context.Context, httpClient *http.Client, client string, index int, protocol, endpoint, user, pass string,
	requestBody RequestBody, httpsEnabled bool) (string, *http.Response, error) {
	log.Printf("[DistributeRequest] Send request to client: %s", client)

	var clientAddr string
	if strings.Contains(client, ":") {
		clientAddr = client
	} else {
		clientAddr = client + ":" + strconv.Itoa(DetermineBootstrapPort(httpsEnabled))
	}

	var req *http.Request
	if len(requestBody.Signature) > 0 {
		indexString := strconv.Itoa(index)
		log.Printf("[DistributeRequest] Send signed request to client: %s with index: %s", client, indexString)
		req, _ = http.NewRequestWithContext(ctx, "POST", protocol+clientAddr+endpoint+"?index="+indexString, bytes.NewBufferString(requestBody.SignedPayload))
		req.Header.Set(SIGNATURE, requestBody.Signature)
	} else {
		log.Printf("[DistributeRequest] Send plain request to client: %s", client)
		req, _ = http.NewRequestWithContext(ctx, "POST", protocol+clientAddr+endpoint, bytes.NewBuffer(requestBody.PlainPayload))
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)

	return sendRequestWithFallback(httpClient, req, httpsEnabled)
}

// RawResponse is the undecoded result of one fan-out request. Err is set when the target could not be reached
// or did not answer within the timeout. ContactedAt is when the request was about to be sent, which with a limit on
// the parallel targets is later for the targets that waited for a free slot.
type RawResponse struct {
	Address     string
	StatusCode  int
	Body        []byte
	Err         error
	ContactedAt time.Time
}

// DistributeRawRequest works like DistributeRequest, but bounds each target with timeout, contacts at most
// maxParallel targets at a time and leaves the response body to the caller to decode. The targets are started in the
// order given; the timeout of a target only starts once it is contacted, so waiting for a free slot does not count.
func DistributeRawRequest(clients []string, endpoint, user, pass string, requestBody RequestBody, timeout time.Duration, maxParallel int) <-chan RawResponse {
	httpsEnabled := HttpsEnabled()
	protocol := determineProtocol(httpsEnabled)
	c := make(chan RawResponse, len(clients))
	if maxParallel <= 0 || maxParallel > len(clients) {
		maxParallel = len(clients)
	}

	type target struct {
		client string
		index  int
	}
	targets := make(chan target, len(clients))
	for idx, client := range clients {
		targets <- target{client, idx}
	}
	close(targets)

	var wg sync.WaitGroup
	wg.Add(maxParallel)
	for worker := 0; worker < maxParallel; worker++ {
		go func() {
			defer wg.Done()
			for t := range targets {
				c <- sendRawRequest(t.client, t.index, protocol, endpoint, user, pass, requestBody, httpsEnabled, timeout)
			}
		}()
	}

	wg.Wait()
	close(c)

	return c
}

func sendRawRequest(client string, index int, protocol, endpoint, user, pass string, requestBody RequestBody, httpsEnabled bool,
	timeout time.Duration) RawResponse {
	httpClient := getHttpClient(httpsEnabled)
	// one deadline for the whole target, so the HTTP fallback after a refused HTTPS attempt cannot double it
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	contactedAt := time.Now()
	respHost, resp, err := sendDistributedRequest(ctx, httpClient, client, index, protocol, endpoint, user, pass, requestBody, httpsEnabled)
	if err != nil {
		log.Printf("[DistributeRawRequest] [ERROR] Failed to send request to: %s, error: %s", client, err.Error())
		return RawResponse{Address: respHost, StatusCode: http.StatusInternalServerError, Err: err, ContactedAt: contactedAt}
	}
	defer closeIt(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[DistributeRawRequest] [ERROR] Failed to read response from: %s, error: %s", client, err.Error())
		return RawResponse{Address: respHost, StatusCode: http.StatusInternalServerError, Err: err, ContactedAt: contactedAt}
	}
	return RawResponse{Address: respHost, StatusCode: resp.StatusCode, Body: body, ContactedAt: contactedAt}
}

func DistributeRequest(clients []string, endpoint, user, pass string, requestBody RequestBody) <-chan model.Response {
	httpsEnabled := HttpsEnabled()
	protocol := determineProtocol(httpsEnabled)
	var wg sync.WaitGroup
	wg.Add(len(clients))
	c := make(chan model.Response, len(clients))

	for idx, client := range clients {
		go func(client string, index int) {
			defer wg.Done()
			httpClient := getHttpClient(httpsEnabled)
			respHost, resp, err := sendDistributedRequest(context.Background(), httpClient, client, index, protocol, endpoint, user, pass, requestBody, httpsEnabled)
			if err != nil {
				log.Printf("[DistributeRequest] [ERROR] Failed to send request to: %s, error: %s", client, err.Error())
				c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: respHost}
				return
			}

			body, _ := io.ReadAll(resp.Body)
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			var response model.Response
			if err := decoder.Decode(&response); err != nil {
				log.Printf("[DistributeRequest] [ERROR] Failed to decode response, error: %s", err.Error())
			}
			response.Address = respHost

			if response.StatusCode == 0 {
				response.StatusCode = resp.StatusCode
			}
			log.Printf("[DistributeRequest] Request to: %s result: %s", client, response.String())
			c <- response
			defer closeIt(resp.Body)
		}(client, idx)
	}

	wg.Wait()
	close(c)

	return c
}

func DistributeFileUploadRequest(endpoint string, user string, pass string, targets []string, path string,
	permissions string, file multipart.File, header *multipart.FileHeader, signature string) <-chan model.Response {

	httpsEnabled := HttpsEnabled()
	protocol := determineProtocol(httpsEnabled)
	var wg sync.WaitGroup
	wg.Add(len(targets))
	c := make(chan model.Response, len(targets))

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	_ = bodyWriter.WriteField("path", path)
	_ = bodyWriter.WriteField("permissions", permissions)

	fileWriter, err := bodyWriter.CreateFormFile("file", header.Filename)
	if err != nil {
		log.Println("[DistributeFileUploadRequest] error writing file header to buffer")
		for _, target := range targets {
			c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: target}
		}
		return c
	}

	_, err = io.Copy(fileWriter, file)
	if err != nil {
		fmt.Println("[DistributeFileUploadRequest] error writing file content to buffer")
		for _, target := range targets {
			c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: target}
		}
		return c
	}

	closeIt(bodyWriter)
	fileContent := bodyBuf.Bytes()

	for i, target := range targets {
		go func(target string, index int) {
			defer wg.Done()
			log.Printf("[DistributeFileUploadRequest] Send file upload request to target: %s", target)

			var targetAddress string
			if strings.Contains(target, ":") {
				targetAddress = target
			} else {
				targetAddress = target + ":" + strconv.Itoa(DetermineBootstrapPort(httpsEnabled))
			}

			req, err := http.NewRequest("POST", protocol+targetAddress+endpoint, bytes.NewReader(fileContent))
			req.Header.Set(SIGNATURE, signature)
			req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
			req.SetBasicAuth(user, pass)

			httpClient := getHttpClient(httpsEnabled)
			respHost, resp, err := sendRequestWithFallback(httpClient, req, httpsEnabled)
			if err != nil {
				log.Printf("[DistributeFileUploadRequest] [ERROR] Failed to send request to: %s, error: %s", respHost, err.Error())
				c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: respHost}
				return
			}

			body, _ := io.ReadAll(resp.Body)
			defer closeIt(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				log.Printf("[DistributeFileUploadRequest] Error response from: %s, error: %s", respHost, body)
				c <- model.Response{StatusCode: resp.StatusCode, ErrorText: string(body), Address: respHost}
				return
			} else {
				log.Printf("[DistributeFileUploadRequest] Request to: %s result: %s", respHost, body)
				c <- model.Response{StatusCode: http.StatusCreated, Status: string(body), Address: respHost}
			}
		}(target, i)
	}
	wg.Wait()
	close(c)

	return c
}
