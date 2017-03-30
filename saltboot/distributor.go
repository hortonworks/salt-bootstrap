package saltboot

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
	"io"
	"mime/multipart"
)

func DistributeRequest(clients []string, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
	var wg sync.WaitGroup
	wg.Add(len(clients))
	c := make(chan model.Response, len(clients))
	for idx, client := range clients {

		go func(client string, index int) {
			defer wg.Done()
			log.Printf("[distribute] Send request to client: %s", client)

			var clientAddr string
			if strings.Contains(client, ":") {
				clientAddr = client
			} else {
				clientAddr = client + ":" + strconv.Itoa(DetermineBootstrapPort())
			}

			req, err := http.NewRequest("POST", "http://"+clientAddr+endpoint+"?index="+strconv.Itoa(index), bytes.NewBufferString(signed))
			req.Header.Set(SIGNATURE, signature)
			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(user, pass)

			httpClient := &http.Client{}
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("[distribute] Failed to send request to: %s, error: %s", client, err.Error())
				c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: client}
				return
			}

			body, _ := ioutil.ReadAll(resp.Body)
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			var response model.Response
			decoder.Decode(&response)
			response.Address = client

			if response.StatusCode == 0 {
				response.StatusCode = resp.StatusCode
			}
			log.Printf("[distribute] Request to: %s result: %s", client, response.String())
			c <- response
			defer resp.Body.Close()
		}(client, idx)
	}
	wg.Wait()
	close(c)

	return c
}

func Distribute(clients []string, payload []byte, endpoint string, user string, pass string) <-chan model.Response {
	var wg sync.WaitGroup
	wg.Add(len(clients))
	c := make(chan model.Response, len(clients))

	for _, client := range clients {
		go func(client string) {
			defer wg.Done()
			log.Printf("[distribute] Send request to client: %s", client)

			var clientAddr string
			if strings.Contains(client, ":") {
				clientAddr = client
			} else {
				clientAddr = client + ":" + strconv.Itoa(DetermineBootstrapPort())
			}

			req, err := http.NewRequest("POST", "http://"+clientAddr+endpoint, bytes.NewBuffer(payload))
			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(user, pass)

			httpClient := &http.Client{}
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("[distribute] Failed to send request to: %s, error: %s", client, err.Error())
				c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: client}
				return
			}

			body, _ := ioutil.ReadAll(resp.Body)
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			var response model.Response
			decoder.Decode(&response)
			response.Address = client

			if response.StatusCode == 0 {
				response.StatusCode = resp.StatusCode
			}
			log.Printf("[distribute] Request to: %s result: %s", client, response.String())
			c <- response
			defer resp.Body.Close()
		}(client)
	}
	wg.Wait()
	close(c)

	return c
}

func DistributeFileUploadRequest(endpoint string, user string, pass string, targets []string, path string,
	permissions string, file multipart.File, header *multipart.FileHeader, signature string) <-chan model.Response {

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

	bodyWriter.Close()
	fileContent := bodyBuf.Bytes()

	for i, target := range targets {
		go func(target string, index int) {
			defer wg.Done()
			log.Printf("[DistributeFileUploadRequest] Send file upload request to target: %s", target)

			var targetAddress string
			if strings.Contains(target, ":") {
				targetAddress = target
			} else {
				targetAddress = target + ":" + strconv.Itoa(DetermineBootstrapPort())
			}

			req, err := http.NewRequest("POST", "http://"+targetAddress+endpoint, bytes.NewReader(fileContent))
			req.Header.Set(SIGNATURE, signature)
			req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
			req.SetBasicAuth(user, pass)

			httpClient := &http.Client{}
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("[DistributeFileUploadRequest] Failed to send request to: %s, error: %s", target, err.Error())
				c <- model.Response{StatusCode: http.StatusInternalServerError, ErrorText: err.Error(), Address: target}
				return
			}

			body, _ := ioutil.ReadAll(resp.Body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				log.Printf("[DistributeFileUploadRequest] Error response from: %s, error: %s", target, body)
				c <- model.Response{StatusCode: resp.StatusCode, ErrorText: string(body), Address: target}
				return
			} else {
				log.Printf("[DistributeFileUploadRequest] Request to: %s result: %s", target, body)
				c <- model.Response{StatusCode: http.StatusCreated, Status: string(body), Address: target}
			}
		}(target, i)
	}
	wg.Wait()
	close(c)

	return c
}
