package cbboot

import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "encoding/json"
    "fmt"
)

type SaltServerSetupRequest struct {
    Password string     `json:"password,omitempty"`
}

type SaltRunRequest struct {
    Minions []string   `json:"minions,omitempty"`
    Server  string     `json:"server,omitempty"`
}

func (r SaltRunRequest) String() string {
    b, _ := json.Marshal(r)
    return fmt.Sprintf(string(b))
}

func (salt SaltRunRequest) distributeRun(user string, pass string) (result []model.Response) {
    log.Printf("[distributeRun] distribute salt run command to targets: %s", salt.String())
    for res := range distribute(salt.Minions, nil, SaltMinionRunEP, user, pass) {
        result = append(result, res)
    }
    result = append(result, <-distribute([]string{salt.Server}, nil, SaltServerRunEP, user, pass))
    return result
}

func SaltMinionRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltAgentRunRequestHandler] execute salt run request")
    resp, _ := LaunchService("salt-minion")
    resp.WriteHttp(w)
}

func SaltServerRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltServerRunRequestHandler] execute salt run request")
    resp, err := LaunchService("salt-master")
    resp.WriteHttp(w)
    if err != nil {
        return
    }
    resp, _ = LaunchService("salt-api")
    resp.WriteHttp(w)

}

func SaltServerSetupRequestHandler(w http.ResponseWriter, req *http.Request) {

}

func SaltRunDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltRunDistributeRequestHandler] execute SaltRun run distribute request")

    decoder := json.NewDecoder(req.Body)
    var run SaltRunRequest
    err := decoder.Decode(&run)
    if err != nil {
        log.Printf("[SaltRunDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        cResp := model.Response{Status: err.Error()}
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(cResp)
        return
    }

    user, pass := getAuthUserPass(req)
    result := run.distributeRun(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[SaltRunDistributeRequestHandler] distribute salt run command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}
