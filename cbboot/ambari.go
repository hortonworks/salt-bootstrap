package cbboot

import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "encoding/json"
    "fmt"
)

type AmbariRunRequest struct {
    Agents []string   `json:"agents,omitempty"`
    Server string     `json:"server,omitempty"`
}

func (r AmbariRunRequest) String() string {
    b, _ := json.Marshal(r)
    return fmt.Sprintf(string(b))
}

func ambariAgentRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariAgentRunRequestHandler] execute consul run request")
    StartService(w, req, "ambari-agent")
}

func ambariServerRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariAgentRunRequestHandler] execute consul run request")
    StartService(w, req, "ambari-server")
}

func (amb AmbariRunRequest) distributeRun(user string, pass string) (result []model.Response) {
    log.Printf("[distributeRun] distribute ambari run command to targets: %s", amb.String())
    for res := range distribute(amb.Agents, nil, AmbariAgentRunEP, user, pass) {
        result = append(result, res)
    }
    result = append(result, <-distribute([]string{amb.Server}, nil, AmbariServerRunEP, user, pass))
    return result
}

func ambariRunDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariRunDistributeRequestHandler] execute consul run distribute request")

    decoder := json.NewDecoder(req.Body)
    var run AmbariRunRequest
    err := decoder.Decode(&run)
    if err != nil {
        log.Printf("[ambariRunDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        cResp := model.Response{Status: err.Error()}
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(cResp)
        return
    }

    user, pass := getAuthUserPass(req)
    result := run.distributeRun(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[ambariRunDistributeRequestHandler] distribute consul run command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}
