package cbboot

import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "encoding/json"
    "fmt"
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "os"
)

type SaltServerSetupRequest struct {
    Password string     `json:"password,omitempty"`
}

type SaltRunRequest struct {
    Minions []SaltMinion   `json:"minions,omitempty"`
    Server  string         `json:"server,omitempty"`
}

type SaltMinion struct {
    Address string     `json:"address"`
    Roles   []string   `json:"roles"`
    Server  string     `json:"server,omitempty"`
}

func (saltMinion SaltMinion) AsByteArray() []byte {
    b, _ := json.Marshal(saltMinion)
    return b
}

//consul:
//    advertise_addr: 10.0.0.24
//    recursors:
//        - 10.0.0.2
//        - 8.8.8.8
//hostgroup: hostgroup_3
//roles:
//    - ambari_server
//    - ambari_agent


type ConsulGrainConfig struct {
    AdvertiseAddr string     `json:"advertise_addr" yaml:"advertise_addr"`
    DNSRecursors  []string   `json:"recursors" yaml:"recursors"`
}

type GrainConfig struct {
    Consul ConsulGrainConfig       `json:"consul" yaml:"consul"`
    //    HostGroup           string                  `json:"hostgroup yaml:"hostgroup"`
    Roles  []string                `json:"roles" yaml:"roles"`
}

func (r SaltRunRequest) String() string {
    b, _ := json.Marshal(r)
    return fmt.Sprintf(string(b))
}

func (saltRunRequest SaltRunRequest) distributeRun(user string, pass string) (result []model.Response) {
    log.Printf("[distributeRun] distribute salt run command to targets: %s", saltRunRequest.String())
    var targets []string
    var payloads []Payload
    for _, minion := range saltRunRequest.Minions {
        targets = append(targets, minion.Address)
        if minion.Server == "" {
            minion.Server = saltRunRequest.Server
        }
        payloads = append(payloads, minion)
    }

    for res := range DistributePayload(targets, payloads, SaltMinionRunEP, user, pass) {
        result = append(result, res)
    }
    result = append(result, <-Distribute([]string{saltRunRequest.Server}, nil, SaltServerRunEP, user, pass))
    return result
}

func SaltMinionRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltMinionRunRequestHandler] execute salt run request")

    decoder := json.NewDecoder(req.Body)
    var saltMinion SaltMinion
    err := decoder.Decode(&saltMinion)
    if err != nil {
        log.Printf("[SaltMinionRunRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    recursors := DetermineDNSRecursors([]string{})

    grainConfig := GrainConfig{
        Consul:            ConsulGrainConfig{
            AdvertiseAddr:      saltMinion.Address,
            DNSRecursors:       recursors,
        },
        Roles:             saltMinion.Roles,
    }

    grainYaml, err := yaml.Marshal(grainConfig)
    var resp model.Response;
    if err != nil {
        resp = model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}
        resp.WriteHttp(w)
        return
    }

    err = os.MkdirAll("/etc/salt/minion.d", 0755)
    if err != nil {
        resp = model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}
        resp.WriteHttp(w)
        return
    }

    masterConf := []byte("master: " + saltMinion.Server)
    err = ioutil.WriteFile("/etc/salt/minion.d/master.conf", masterConf, 0644)
    if err != nil {
        resp = model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}
        resp.WriteHttp(w)
        return
    }

    err = ioutil.WriteFile("/etc/salt/grains", grainYaml, 0644)
    if err != nil {
        resp = model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}
        resp.WriteHttp(w)
        return
    }
    resp, _ = LaunchService("salt-minion")
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
    var saltRunRequest SaltRunRequest
    err := decoder.Decode(&saltRunRequest)
    if err != nil {
        log.Printf("[SaltRunDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    user, pass := GetAuthUserPass(req)
    result := saltRunRequest.distributeRun(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[SaltRunDistributeRequestHandler] distribute salt run command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}
