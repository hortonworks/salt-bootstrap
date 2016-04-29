package cbboot

import (
    "log"
    "encoding/json"
    "net/http"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
)

type Clients struct {
    Clients []string   `json:"clients,omitempty"`
    Servers []Server   `json:"servers,omitempty"`
    Path    string     `json:"path"`
}

func (clients *Clients) distributeAddress(user string, pass string) (result []model.Response) {
    log.Printf("[Clients.distributeAddress] Request: %s", clients)
    json, _ := json.Marshal(Servers{Servers:clients.Servers, Path:clients.Path})
    responses := distribute(clients.Clients, json, ServerSaveEP, user, pass)
    for resp := range responses {
        result = append(result, resp)
    }
    return result
}

func (clients *Clients) distributeHostnameRequest(user string, pass string) (result []model.Response) {
    log.Printf("[Clients.distributeHostnameRequest] Request: %s", clients)
    responses := distribute(clients.Clients, nil, HostnameEP, user, pass)
    for resp := range responses {
        result = append(result, resp)
    }
    return result
}

func ClientHostnameHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ClientHostnameHandler] get FQDN")
    fqdn, err := execCmd("hostname", "-f")
    if err != nil {
        log.Printf("[ClientHostnameHandler] failed to retrieve FQDN")
        model.Response{Status: err.Error(), StatusCode:http.StatusInternalServerError}.WriteHttp(w)
        return
    }
    log.Printf("[ClientHostnameHandler] FQDN: %s", fqdn)
    model.Response{Status:fqdn}.WriteHttp(w)
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

    user, pass := getAuthUserPass(req)
    responses := clients.distributeHostnameRequest(user, pass)
    cResp := model.Responses{Responses:responses}
    log.Printf("[ClientHostnameRequestHandler] distribute request executed: %s" + cResp.String())
    json.NewEncoder(w).Encode(cResp)
}

func clientDistributionHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[clientDistributionHandler] execute distribute request")

    decoder := json.NewDecoder(req.Body)
    var clients Clients
    err := decoder.Decode(&clients)
    if err != nil {
        log.Printf("[clientDistributionHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    user, pass := getAuthUserPass(req)
    responses := clients.distributeAddress(user, pass)
    cResp := model.Responses{Responses:responses}
    log.Printf("[clientDistributionHandler] distribute request executed: %s" + cResp.String())
    json.NewEncoder(w).Encode(cResp)
}
