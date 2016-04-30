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

func AmbariAgentRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariAgentRunRequestHandler] execute ambari-agent run request")
    resp, err := LaunchService("ambari-agent")
    if err != nil {
        log.Printf("[ambariAgentRunRequestHandler] failed to start ambari-agent: %s", err.Error())
    }
    resp.WriteHttp(w)
}

func AmbariServerRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariAgentRunRequestHandler] execute ambari-server run request")
    resp, err := LaunchService("ambari-server")
    if err != nil {
        log.Printf("[ambariAgentRunRequestHandler] failed to start ambari-server: %s", err.Error())
    }
    resp.WriteHttp(w)
}

func (amb AmbariRunRequest) DistributeRun(user string, pass string) (result []model.Response) {
    log.Printf("[distributeRun] distribute ambari run command to targets: %s", amb.String())
    for res := range Distribute(amb.Agents, nil, AmbariAgentRunEP, user, pass) {
        result = append(result, res)
    }
    result = append(result, <-Distribute([]string{amb.Server}, nil, AmbariServerRunEP, user, pass))
    return result
}

func AmbariRunDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[ambariRunDistributeRequestHandler] execute consul run distribute request")

    decoder := json.NewDecoder(req.Body)
    var run AmbariRunRequest
    err := decoder.Decode(&run)
    if err != nil {
        log.Printf("[ambariRunDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    user, pass := GetAuthUserPass(req)
    result := run.DistributeRun(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[ambariRunDistributeRequestHandler] distribute consul run command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}
