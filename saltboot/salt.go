package saltboot

import (
    "log"
    "github.com/sequenceiq/salt-bootstrap/saltboot/model"
    "net/http"
    "encoding/json"
    "fmt"
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "os"
    "strings"
)

type SaltServerSetupRequest struct {
    Password string     `json:"password,omitempty"`
}

type SaltActionRequest struct {
    Minions []SaltMinion   `json:"minions,omitempty"`
    Server  string         `json:"server,omitempty"`
    Action  string         `json:"action"`
}

type SaltMinion struct {
    Address string     `json:"address"`
    Roles   []string   `json:"roles,omitempty"`
    Server  string     `json:"server,omitempty"`
}

type SaltPillar struct {
    Path string                 `json:"path"`
    Json map[string]interface{} `json:"json"`
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

func (r SaltActionRequest) String() string {
    b, _ := json.Marshal(r)
    return fmt.Sprintf(string(b))
}

func (r SaltActionRequest) distributeAction(user string, pass string) (result []model.Response) {
    log.Printf("[distributeAction] distribute salt state command to targets: %s", r.String())
    var targets []string
    var payloads []Payload
    for _, minion := range r.Minions {
        targets = append(targets, minion.Address)
        if minion.Server == "" {
            minion.Server = r.Server
        }
        payloads = append(payloads, minion)
    }

    for res := range DistributePayload(targets, payloads, SaltMinionEp + "/" + r.Action, user, pass) {
        result = append(result, res)
    }
    if len(r.Server) > 0 {
        result = append(result, <-Distribute([]string{r.Server}, nil, SaltServerEp + "/" + r.Action, user, pass))
    }
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

func SaltMinionStopRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltMinionStopRequestHandler] execute salt minion stop request")

    decoder := json.NewDecoder(req.Body)
    var saltMinion SaltMinion
    err := decoder.Decode(&saltMinion)
    if err != nil {
        log.Printf("[SaltMinionRunRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    resp, _ := StopService("salt-minion")
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

func SaltServerStopRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltServerStopRequestHandler] execute salt master stop request")
    resp, err := StopService("salt-master")
    resp.WriteHttp(w)
    if err != nil {
        return
    }
    resp, _ = StopService("salt-api")
    resp.WriteHttp(w)
}

func SaltServerSetupRequestHandler(w http.ResponseWriter, req *http.Request) {

}

func (pillar SaltPillar) WritePillar() (outStr string, err error) {
    file := "/srv/pillar" + pillar.Path
    dir := file[0:strings.LastIndex(file, "/")]

    log.Printf("[SaltPillar.WritePillar] mkdir %s", dir)
    err = os.MkdirAll(dir, 0644)
    if err != nil {
        return "Failed to create dir " + dir, err
    }

    yml, _ := yaml.Marshal(pillar.Json)
    log.Printf("[SaltPillarRequestHandler] generated yaml from json %s", string(yml))
    err = ioutil.WriteFile(file, yml, 0644)
    if err != nil {
        return "Failed to write to " + file, err
    }
    return "Salt pillar successfully written to " + file, err
}

func SaltPillarRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltPillarRequestHandler] execute salt pillar save request")
    decoder := json.NewDecoder(req.Body)
    var saltPillar SaltPillar
    err := decoder.Decode(&saltPillar)
    if err != nil {
        log.Printf("[SaltPillarRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    if !strings.HasSuffix(saltPillar.Path, ".sls") {
        log.Printf("[SaltPillarRequestHandler] [ERROR] path is not ending with '.sls' suffix %s", saltPillar.Path)
        model.Response{Status: "path is not ending with '.sls' suffix"}.WriteBadRequestHttp(w)
        return
    }
    if !strings.HasPrefix(saltPillar.Path, "/") {
        log.Printf("[SaltPillarRequestHandler] [ERROR] path is not starting with '/' %s", saltPillar.Path)
        model.Response{Status: "path is not starting with '/'"}.WriteBadRequestHttp(w)
        return
    }
    if strings.Contains(saltPillar.Path, "..") {
        log.Printf("[SaltPillarRequestHandler] [ERROR] path cannot contain '..' charachters %s", saltPillar.Path)
        model.Response{Status: "path cannot contain '..' charachters"}.WriteBadRequestHttp(w)
        return
    }

    jsonString, _ := json.Marshal(saltPillar.Json)
    log.Printf("[SaltPillarRequestHandler] Recieved arbitrary json: %s", jsonString)

    outStr, err := saltPillar.WritePillar()
    if err != nil {
        log.Printf("[SaltPillarRequestHandler] failed to execute salt pillar save config: %s", err.Error())
        model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}.WriteHttp(w)
    } else {
        cResp := model.Response{Status: outStr}.WriteHttp(w)
        log.Printf("[SaltPillarRequestHandler] save salt pillar request executed: %s", cResp.String())
    }
}

func SaltActionDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[SaltActionDistributeRequestHandler] execute Salt state distribute request")

    decoder := json.NewDecoder(req.Body)
    var saltActionRequest SaltActionRequest
    err := decoder.Decode(&saltActionRequest)
    if err != nil {
        log.Printf("[SaltActionDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
        return
    }

    user, pass := GetAuthUserPass(req)
    result := saltActionRequest.distributeAction(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[SaltActionDistributeRequestHandler] distribute salt state command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}