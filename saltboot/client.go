package saltboot

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/sequenceiq/salt-bootstrap/saltboot/model"
)

type Clients struct {
	Clients []string `json:"clients,omitempty"`
	Servers []Server `json:"servers,omitempty"`
	Path    string   `json:"path"`
}

func (clients *Clients) DistributeAddress(user string, pass string) (result []model.Response) {
	log.Printf("[Clients.distributeAddress] Request: %s", clients)
	json, _ := json.Marshal(Servers{Servers: clients.Servers, Path: clients.Path})
	responses := Distribute(clients.Clients, json, ServerSaveEP, user, pass)
	for resp := range responses {
		result = append(result, resp)
	}
	return result
}

func (clients *Clients) DistributeHostnameRequest(user string, pass string) (result []model.Response) {
	log.Printf("[Clients.distributeHostnameRequest] Request: %s", clients)
	responses := Distribute(clients.Clients, nil, HostnameEP, user, pass)
	for resp := range responses {
		result = append(result, resp)
	}
	return result
}

func ClientHostnameHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[ClientHostnameHandler] get FQDN")
	fqdn, err := getHostName()
	if err != nil {
		log.Printf("[ClientHostnameHandler] failed to retrieve FQDN")
		model.Response{Status: err.Error(), StatusCode: http.StatusInternalServerError}.WriteHttp(w)
		return
	}
	log.Printf("[ClientHostnameHandler] FQDN: %s", fqdn)
	model.Response{Status: fqdn}.WriteHttp(w)
}

func ClientHostnameDistributionHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[ClientHostnameRequestHandler] execute distribute hostname request")

	decoder := json.NewDecoder(req.Body)
	var clients Clients
	err := decoder.Decode(&clients)
	if err != nil {
		log.Printf("[ClientHostnameRequestHandler] [ERROR] couldn't decode json: %s", err)
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	responses := clients.DistributeHostnameRequest(user, pass)
	cResp := model.Responses{Responses: responses}
	log.Printf("[ClientHostnameRequestHandler] distribute request executed: %s" + cResp.String())
	json.NewEncoder(w).Encode(cResp)
}

func ClientDistributionHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[clientDistributionHandler] execute distribute request")

	decoder := json.NewDecoder(req.Body)
	var clients Clients
	err := decoder.Decode(&clients)
	if err != nil {
		log.Printf("[clientDistributionHandler] [ERROR] couldn't decode json: %s", err)
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	responses := clients.DistributeAddress(user, pass)
	cResp := model.Responses{Responses: responses}
	log.Printf("[clientDistributionHandler] distribute request executed: %s" + cResp.String())
	json.NewEncoder(w).Encode(cResp)
}
