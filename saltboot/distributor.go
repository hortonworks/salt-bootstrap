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

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func DistributeActionRequest(clients []string, request SaltActionRequest, endpoint string, user string, pass string, signature string, signed string) <-chan model.Response {
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
