package saltboot

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

type Clients struct {
	Clients []string `json:"clients,omitempty"`
	Servers []Server `json:"servers,omitempty"`
	Path    string   `json:"path"`
}

func (clients *Clients) DistributeAddress(user string, pass string) (result []model.Response) {
	log.Printf("[Clients.distributeAddress] Request: %s", clients)
	jsonString, _ := json.Marshal(Servers{Servers: clients.Servers, Path: clients.Path})
	return distributeImpl(DistributeRequest, clients.Clients, ServerSaveEP, user, pass, RequestBody{PlainPayload: jsonString})
}

func distributeImpl(distribute func(clients []string, endpoint, user, pass string, requestBody RequestBody) <-chan model.Response,
	c []string, endpoint string, user string, pass string, requestBody RequestBody) (result []model.Response) {
	responses := distribute(c, endpoint, user, pass, requestBody)
	for resp := range responses {
		result = append(result, resp)
	}
	return result
}

func (clients *Clients) DistributeHostnameRequest(user string, pass string) (result []model.Response) {
	log.Printf("[Clients.distributeHostnameRequest] Request: %s", clients)
	return distributeImpl(DistributeRequest, clients.Clients, HostnameEP, user, pass, RequestBody{})
}

func ClientHostnameHandler(w http.ResponseWriter, req *http.Request) {
	clientHostnameHandlerImpl(w, req, getFQDN)
}

func clientHostnameHandlerImpl(w http.ResponseWriter, req *http.Request, resolver func() (string, error)) {
	log.Println("[ClientHostnameHandler] get FQDN")
	fqdn, err := resolver()
	if err != nil {
		log.Println("[ClientHostnameHandler] failed to retrieve FQDN")
		model.Response{Status: err.Error(), StatusCode: http.StatusInternalServerError}.WriteHttp(w)
		return
	}
	log.Printf("[ClientHostnameHandler] FQDN: %s", fqdn)
	model.Response{Status: fqdn}.WriteHttp(w)
}

func ClientHostnameDistributionHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[ClientHostnameRequestHandler] execute distribute hostname request")

	decoder := json.NewDecoder(req.Body)
	var clients Clients
	err := decoder.Decode(&clients)
	if err != nil {
		log.Printf("[ClientHostnameRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	responses := clients.DistributeHostnameRequest(user, pass)
	cResp := model.Responses{Responses: responses}
	log.Printf("[ClientHostnameRequestHandler] distribute request executed: %s" + cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[ClientHostnameRequestHandler] [ERROR] couldn't encode json: %s", err.Error())
	}
}

func ClientDistributionHandler(w http.ResponseWriter, req *http.Request) {
	log.Println("[clientDistributionHandler] execute distribute request")

	decoder := json.NewDecoder(req.Body)
	var clients Clients
	err := decoder.Decode(&clients)
	if err != nil {
		log.Printf("[clientDistributionHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	user, pass := GetAuthUserPass(req)
	responses := clients.DistributeAddress(user, pass)
	cResp := model.Responses{Responses: responses}
	log.Printf("[clientDistributionHandler] distribute request executed: %s" + cResp.String())
	if err := json.NewEncoder(w).Encode(cResp); err != nil {
		log.Printf("[ClientHostnameRequestHandler] [ERROR] couldn't encode json: %s", err.Error())
	}
}
