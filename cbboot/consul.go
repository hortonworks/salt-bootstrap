package cbboot

import (
    "fmt"
    "encoding/json"
    "log"
    "strings"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "io/ioutil"
    "regexp"
    "os"
    "sync"
)

type ConsulConfigRequest struct {
    DataDir string     `json:"data_dir"`
    Servers []string   `json:"servers"`
    Targets []string   `json:"targets,omitempty"`
}

type ConsulRunRequest struct {
    Targets []string   `json:"targets,omitempty"`
}

type ConsulConfig struct {
    BootstrapExpect    int        `json:"bootstrap_expect"`
    Server             bool       `json:"server"`
    AdvertiseAddr      string     `json:"advertise_addr,omitempty"`
    DataDir            string     `json:"data_dir"`
    Ui                 bool       `json:"ui"`
    ClientAddr         string     `json:"client_addr"`
    DNSRecursors       []string   `json:"recursors"`
    DisableUpdateCheck bool       `json:"disable_update_check"`
    RetryJoin          []string   `json:"retry_join"`
    EncryptKey         string     `json:"encrypt,omitempty"`
    VerifyIncoming     bool       `json:"verify_incoming,omitempty"`
    VerifyOutgoing     bool       `json:"verify_outgoing,omitempty"`
    CAFile             string     `json:"ca_file,omitempty"`
    CertFile           string     `json:"cert_file,omitempty"`
    KeyFile            string     `json:"key_file,omitempty"`
    Ports              PortConfig `json:"ports"`
    DNS                DNSConfig  `json:"dns_config"`
    NodeName           string     `json:"node_name"`
}

type PortConfig struct {
    DNS   int
    HTTP  int
    HTTPS int
}

type DNSConfig struct {
    AllowStale bool   `json:"allow_stale"`
    MaxStale   string `json:"max_stale"`
    NodeTTL    string `json:"node_ttl"`
}

func (cr *ConsulConfigRequest) distributeConfig(user string, pass string) (result []model.Response) {

    var wg sync.WaitGroup
    wg.Add(len(cr.Targets))

    recursors := determineDNSRecursors([]string{"8.8.8.8"})
    for _, target := range cr.Targets {
        go func(target string) {
            defer wg.Done()
            consulConfig := ConsulConfig{
                DataDir:            cr.DataDir,
                Ui:                 true,
                ClientAddr:         "0.0.0.0",
                DNSRecursors:       recursors,
                DisableUpdateCheck: true,
                RetryJoin:          cr.Servers,
                Ports: PortConfig{
                    DNS:   53,
                    HTTP:  8500,
                    HTTPS: -1,
                },
                DNS: DNSConfig{
                    AllowStale: true,
                    MaxStale:   "5m",
                    NodeTTL:    "1m",
                },
            }

            if (strings.Contains(target, ":")) {
                consulConfig.AdvertiseAddr = strings.Split(target, ":")[0]
            } else {
                consulConfig.AdvertiseAddr = target
            }

            if (IsServer(consulConfig.AdvertiseAddr, cr.Servers)) {
                consulConfig.RetryJoin = GetRetryIps(target, cr.Servers)
                consulConfig.Server = true
                consulConfig.BootstrapExpect = len(cr.Servers)
            }

            json, _ := json.Marshal(consulConfig)
            for resp := range distribute([]string{target}, json, ConsulConfigSaveEP, user, pass) {
                result = append(result, resp)
            }
        }(target)
    }
    wg.Wait()

    return result
}

func GetRetryIps(target string, servers []string) []string {
    result := make([]string, 0)
    if (strings.Contains(target, ":")) {
        target = strings.Split(target, ":")[0]
    }
    for _, server := range servers {
        if (target != server) {
            result = append(result, server)
        }
    }
    return result
}

func IsServer(candidate string, servers[] string) bool {
    for _, server := range servers {
        if (server == candidate) {
            return true
        }
    }
    return false
}

func (c *ConsulConfig) writeToFile() (outStr string, err error) {
    log.Printf("[ConsulConfig.writeToFile] %s", c)

    file := c.DataDir + "/consul.json"
    err = os.MkdirAll(c.DataDir, 0644)
    if err != nil {
        return "Failed to create dir " + c.DataDir, err
    }

    j, _ := json.Marshal(c)
    err = ioutil.WriteFile(file, j, 0644)
    if err != nil {
        return "Failed to write to " + file, err
    }
    return "Consul config successfully written to " + file, err
}

func (cr ConsulRunRequest) distributeRun(user string, pass string) (result []model.Response) {
    log.Printf("[distributeRun] distribute consul run command to targets: %s", strings.Join(cr.Targets, ","))
    for res := range distribute(cr.Targets, nil, ConsulRunEP, user, pass) {
        result = append(result, res)
    }
    return result
}

func determineDNSRecursors(fallbackDNSRecursors []string) []string {
    var dnsRecursors []string
    if dat, err := ioutil.ReadFile("/etc/resolv.conf"); err == nil {
        resolvContent := string(dat)
        log.Printf("[determineDNSRecursors] Loaded /etc/resolv.conf file: %s.", resolvContent)
        r, _ := regexp.Compile("nameserver .*")
        if nameserverLines := r.FindAllString(resolvContent, -1); nameserverLines != nil {
            for _, nameserverLine := range nameserverLines {
                log.Printf("[determineDNSRecursors] Found nameserverline: %s.", nameserverLine)
                dnsRecursor := strings.TrimSpace(strings.Split(nameserverLine, " ")[1])
                log.Printf("[determineDNSRecursors] Parsed DNS recursor: %s.", dnsRecursor)
                if !strings.Contains(dnsRecursor, "127.0.0.1") {
                    dnsRecursors = append(dnsRecursors, dnsRecursor)
                }
            }
        }
    } else {
        log.Printf("[containerhandler] Failed to load /etc/resolv.conf")
    }
    if fallbackDNSRecursors != nil {
        dnsRecursors = append(dnsRecursors, fallbackDNSRecursors...)
    }
    return dnsRecursors
}

func consulConfigDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[consulConfigRequestHandler] execute distribute request")

    decoder := json.NewDecoder(req.Body)
    var config ConsulConfigRequest
    err := decoder.Decode(&config)
    if err != nil {
        log.Printf("[consulConfigRequestHandler] [ERROR] couldn't decode json: %s", err)
        cResp := model.Response{Status: err.Error()}
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(cResp)
        return
    }

    user, pass := getAuthUserPass(req)
    result := config.distributeConfig(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[consulConfigRequestHandler] distribute request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}

func consulConfigSaveRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[consulConfigSaveRequestHandler] execute save consul config")

    decoder := json.NewDecoder(req.Body)
    var config ConsulConfig
    err := decoder.Decode(&config)
    if err != nil {
        log.Printf("[consulConfigSaveRequestHandler] [ERROR] couldn't decode json: %s", err)
        cResp := model.Response{Status: err.Error()}
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(cResp)
        return
    }
    hostname, _ := os.Hostname()
    config.NodeName = hostname
    outStr, err := config.writeToFile()
    if err != nil {
        log.Printf("[consulConfigSaveRequestHandler] failed to execute consul save config: %s", err.Error())
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(model.Response{ErrorText: err.Error()})
    } else {
        cResp := model.Response{Status: outStr}
        log.Printf("[consulConfigSaveRequestHandler] save consul request executed: %s", cResp.String())
        json.NewEncoder(w).Encode(cResp)
    }
}

func consulRunRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[consulRunRequestHandler] execute consul run request")
    startService(w, req, "consul")
}

func consulRunDistributeRequestHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[consulRunDistributeRequestHandler] execute consul run distribute request")

    decoder := json.NewDecoder(req.Body)
    var run ConsulRunRequest
    err := decoder.Decode(&run)
    if err != nil {
        log.Printf("[consulRunDistributeRequestHandler] [ERROR] couldn't decode json: %s", err)
        cResp := model.Response{Status: err.Error()}
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(cResp)
        return
    }

    user, pass := getAuthUserPass(req)
    result := run.distributeRun(user, pass)
    cResp := model.Responses{Responses:result}
    log.Printf("[consulRunDistributeRequestHandler] distribute consul run command request executed: %s", cResp.String())
    json.NewEncoder(w).Encode(cResp)
}

func (r ConsulConfig) String() string {
    b, _ := json.Marshal(r)
    return fmt.Sprintf(string(b))
}
